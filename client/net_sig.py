# -*- coding: utf-8 -*-
"""Signalling: connect to the server, keep the link alive, exchange rooms.

This is the half that speaks to the signalling server over WebSocket.
Splitting it out of the 1100-line NetworkManager keeps the peer-transport
and proxy code from having to live in the same file.
"""
import atexit
import hashlib
import json
import os
import socket
import threading
import time
import uuid as uuidmod

from wsproto import WSClient, WSError

from protocol import (MODE_AUTO, MODE_DIRECT, MODE_RELAY, PING_INTERVAL_S,
                      STATE_CONNECTING, STATE_WAITING, STATE_ONLINE,
                      STATE_ERROR, STATE_IDLE,
                      RECONNECT_MIN_S, RECONNECT_MAX_S, RECONNECT_FACTOR,
                      describe_error,
                      NAT_UNKNOWN, NAT_CONE, NAT_SYMMETRIC, SYM_SPRAY_PORTS,
                      STUN_SERVERS, STUN_HANDSHAKE_WAIT_S,
                      NAT_SUB_EASY_INC, NAT_SUB_EASY_DEC, NAT_SUB_CONE,
                      PUNCH_START_MAX_WAIT_S, FILTER_PROBE_BUDGET_S,
                      NAT_RECHECK_S, TCP_PUNCH_PORT, PUNCH_PORT,
                      INBOUND_PROBE_PACKET, INBOUND_PROBE_TIMEOUT_S,
                      INBOUND_PROBE_WARM_PACKET, INBOUND_PROBE_WARM_COUNT,
                      INBOUND_PROBE_WARM_GAP_S, INBOUND_PROBE_RETRY_S,
                      TCP_PROBE_TIMEOUT_S)
from common import (log_to_file, tune, build_manual_address,
                    stun_mapped_address, stun_probe, stun_probe2,
                    stun_filtering,
                    local_endpoints, ipv6_endpoints,
                    order_candidates, predicted_ports)
from udptunnel import UdpHub
from natpunch import (SOCKETS_FOR_SYM_TO_CONE, subtype_regressed,
                      effective_filter)
from natpunch import (FILTER_EIF, FILTER_ADF, FILTER_APDF,
                      FILTER_UNKNOWN)


def nat_changed(prev, cur):
    """Did our own signature actually move?

    A pure function so the decision can be tested without a session.

    "No previous measurement" counts as unchanged on purpose: during
    startup there is nothing to compare against, and calling that a change
    would make every first re-check re-publish and clear a backoff that was
    never earned.
    """
    if prev is None:
        return False
    # Compare the ADDRESS and the CLASS -- not the step.
    #
    # `delta` is the gap between the ports two different STUN servers saw.
    # Every unrelated UDP flow the machine opens while we ask widens it, so
    # it is noise: measured on one box, 1 and 11 and 350 and 760 in the
    # same session. Treating that noise as "the network changed" made the
    # client fire every 90 seconds:
    #
    #   10:53:56  network changed: 220.178.180.180:44635 ->
    #             220.178.180.180:44635            <- same address!
    #   10:53:56  cleared direct-connection backoff after the change
    #
    # ...which silently abolished both the backoff and the blacklist. A
    # peer that should have been parked for 12s was retried forever, and
    # the log looked like it was doing something useful.
    #
    # The step is still PUBLISHED (peers use it to predict), it just is not
    # evidence that we moved.
    return (prev[0], prev[1], prev[3]) != (cur[0], cur[1], cur[3])


class SignalingMixin:
    def log(self, msg):
        try:
            self.log_cb("[%s] %s" % (time.strftime("%H:%M:%S"), msg))
        except Exception:
            pass
        # persist: the window can be closed, a crash can happen, and the
        # question "what did it say yesterday" is otherwise unanswerable
        log_to_file(msg)

    def status(self, msg):
        self._status_text = msg
        try:
            self.status_cb(msg)
        except Exception:
            pass

    def _note_members(self, members):
        self.members_snapshot = list(members or [])
        if self.members_cb:
            self.members_cb(members)

    # ---------------------------------------------------------- connect

    def connect(self, url, name, manual_ip, mode):
        self.my_name = name
        self.manual_ip = manual_ip
        self.mode = mode
        self._stop.clear()
        self._conn_dead.clear()
        self._conn_params = (url, name, manual_ip, mode)
        self.set_state(STATE_CONNECTING)

        # A reconnect must release the previous punch socket, otherwise the
        # old one still holds port 30000 and every retry logs "port busy"
        # and silently falls back to a random port.
        self._gen += 1
        self._release_punch_socket()

        # One punch socket for ALL peers. Deliberately no SO_REUSEADDR:
        # the port must be exclusively ours, or two clients on one machine
        # could both "bind" 30000 and silently steal each other's packets.
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        port = self.punch_port
        try:
            self.udp.bind(("", port))
        except OSError as e:
            # Never silently fall back to a random port when punching is
            # actually needed: a random port means the peer can never
            # reach us, so direct mode would fail forever. Say so.
            self.udp.bind(("", 0))
            self.log("port %d busy (%s), using a random port" % (port, e))
            if self.mode in (MODE_AUTO, MODE_DIRECT):
                self.log("WARNING: direct/auto needs a fixed port - "
                         "punching will NOT work. Change 'UDP 打洞端口'.")
                self.status("打洞端口被占用，直连不可用")
            else:
                self.log("using a random port - fine for relay mode")
        self.udp_port = self.udp.getsockname()[1]
        self._resolve_tcp_port()
        self.hub = UdpHub(self.udp, self.log)
        self.hub.start()
        self.log("UDP local port: %d" % self.udp_port)

        self.ws = WSClient(timeout=30)
        self.log("connect: %s" % url)
        try:
            self.ws.connect(url)
        except Exception:
            # Critical for the reconnect supervisor: it waits for
            # _conn_dead. If a failed connect leaves the flag clear, the
            # supervisor waits forever and only ever retries ONCE.
            self._conn_dead.set()
            self.set_state(STATE_ERROR, "无法连接服务器")
            raise
        tune(self.ws.sock)
        self.log("websocket connected")
        self.status("signal connected")

        gen = self._gen
        self._spawn(lambda: self._recv_loop(gen))
        self._spawn(lambda: self._ping_loop(gen))
        self._start_watchdog()


        # one supervisor for the lifetime of the object
        if not self._reconnect_thread or not self._reconnect_thread.is_alive():
            self._reconnect_thread = self._spawn(self._reconnect_loop)

        # A new session may be a different server with different STUN, so
        # last session's answer must not satisfy this session's wait.
        self._stun_ready.clear()
        self._registered.clear()
        self._published_once = False
        self._have_public_addr = False

        self.send({"action": "register", "name": name, "clientId": self._client_id()})
        self.send({"action": "list_rooms"})
        # Restoring the room has to wait for `registered`, and it must NOT
        # wait for STUN.
        #
        # Publishing used to run first, and it blocks: on a network where
        # the STUN servers are unreachable it burns its whole budget before
        # returning. The room is what decides whether two players are
        # actually playing together, and it does not depend on the public
        # address at all -- so reconnecting put everyone in "connected but
        # in no room" for several extra seconds for no reason. Restore
        # first, then measure.
        self._registered.wait(5.0)
        self._restore_room()
        self.set_state(STATE_WAITING, "等待房间")
        self._publish_address()
        self._start_upnp()

    def _clear_room_state(self):
        """Forget the room after the link died.

        The restore info is captured HERE, while the room state is still
        intact. Capturing it later (in the reconnect loop) is too late --
        by then room_code is already empty and there is nothing to save.
        """
        if self.room_code:
            self._room_to_restore = (self.room_code,
                                     self.room_name or self.my_name,
                                     self.is_host)
        self.room_code = ""
        self.is_host = False

    def _find_room_by_name(self, rname, owner_id=None):
        """Find a room by NAME; returns its code, or "" if it is not up yet.

        Room codes are random per creation, so a host that reconnects gets
        a new one and any remembered code is stale. Looking the room up by
        name is what makes a reconnect actually restore the session instead
        of leaving both sides in different rooms.

        `owner_id` is not optional in spirit: the default room name is
        shared by everyone, so name alone is NOT identity. A host that
        reconnected and joined someone else's same-named room would silently
        become a guest -- and in this topology only the host side is wired
        to the local Minecraft, so the world would end up running on a
        stranger's machine. Only ever accept a room we own.

        Looks FIRST and sleeps never: the caller owns the retry cadence.
        """
        self.refresh_rooms()
        time.sleep(0.6)
        for r in self.rooms_snapshot or []:
            if r.get("roomName") != rname:
                continue
            if owner_id is not None and r.get("ownerId") != owner_id:
                continue
            return r.get("roomCode", "")
        return ""

    def _release_punch_socket(self):
        """Close the punch socket + hub so a reconnect can rebind the port."""
        try:
            if self.hub:
                self.hub.close()
        except Exception:
            pass
        try:
            if self.udp:
                self.udp.close()
        except Exception:
            pass
        self.hub = None
        self.udp = None
        self.udp_port = 0

    def _restore_room(self):
        """Re-create / re-join the room we were in before a drop.

        Without this, auto-reconnect would just leave you connected but
        sitting in no room -- which looks almost identical to being broken.
        """
        room = self._room_to_restore
        if not room:
            return
        code, rname, was_host = room
        try:
            if was_host:
                self.log("重连后重建房间：%s" % rname)
                self.create_room(rname)
            else:
                self.log("重连后重新加入房间：%s" % code)
                self.join_room(code)
                # _retry_restore below also looks the room up by name (the
                # host comes back with a NEW random code, so the remembered
                # one is usually dead). It used to spawn a second, nearly
                # identical fallback loop here -- two threads racing to
                # join_room, the loser getting ALREADY_IN_ROOM. One retry
                # path is enough.
        except Exception as e:
            # keep it: a failed attempt must not throw away the only record
            # of where the user was, or the next retry has nothing to restore
            self.log("恢复房间失败：%s" % e)
            return
        self._room_to_restore = None
        # Sending the request is not the same as getting the room back.
        #
        # The reply can be lost to exactly the race we just guarded against
        # (the server had not finished registering us), or the host may not
        # be back yet. Nothing retried, so the user ended up connected and
        # in no room -- which looks like a broken connection. Keep trying
        # for a while; the loop exits the moment we are actually in a room.
        self._spawn(lambda: self._retry_restore(rname, was_host))

    def _retry_restore(self, rname, was_host):
        """Keep trying to get back into the room for a bounded while.

        Exits as soon as `room_code` is set, so in the normal case this does
        nothing at all. It only fires when the first attempt went nowhere --
        and "connected but in no room" is the single most confusing state
        this program can be in.
        """
        # Front-loaded retries.
        #
        # The most likely outcome of a reconnect is that BOTH sides come
        # back within a few seconds of each other, so the room is usually
        # there almost immediately if it is going to be there at all. A flat
        # 4s cadence spent most of the first half minute doing nothing: it
        # only got ~6 attempts into a 30s window, and a pair that missed
        # each other by a couple of seconds sat in "connected but in no
        # room" -- the most confusing state this program has.
        for i in range(14):
            time.sleep(1.5 if i < 5 else 4.0)
            if self._stop.is_set() or self.room_code:
                return
            # the server cannot place us in a room before it knows who we are
            if not self._registered.is_set():
                continue
            try:
                if was_host:
                    # Look before creating. The server does not dedupe room
                    # names, so if the first create succeeded but its reply
                    # was lost, retrying blindly would leave a second
                    # same-named room in the list -- and a guest reconnecting
                    # would join the wrong one.
                    # Only a room WE own. Joining someone else's same-named
                    # room would demote us to guest and move the world to
                    # their machine.
                    existing = self._find_room_by_name(rname,
                                                       owner_id=self.my_id)
                    if existing:
                        self.log("我的房间已存在，直接回到：%s -> %s"
                                 % (rname, existing))
                        self.join_room(existing)
                        continue
                    self.log("重试重建房间：%s" % rname)
                    self.create_room(rname)
                else:
                    # The host comes back with a NEW random code, so the
                    # remembered one is dead -- look it up by name. Single
                    # source of truth: _find_room_by_name().
                    code = self._find_room_by_name(rname)
                    if code:
                        self.log("按房间名重新找到房间：%s -> %s"
                                 % (rname, code))
                        self.join_room(code)
            except Exception:
                pass

    def _reconnect_loop(self):
        """Bring the signalling link back when it drops.

        Exponential backoff, and it gives up entirely once disconnect()
        is called -- otherwise closing the window would leave a thread
        quietly reconnecting behind your back.
        """
        delay = RECONNECT_MIN_S
        while not self._stop.is_set():
            # wait for the link to be marked dead
            while not self._conn_dead.is_set() and not self._stop.is_set():
                time.sleep(0.4)
            if self._stop.is_set() or not self.auto_reconnect:
                return
            if not self._conn_params:
                return

            self.set_state(STATE_WAITING, "%.0f 秒后重连" % delay)
            self.log("连接断开，%.0f 秒后自动重连 ..." % delay)

            # sleep, but wake immediately on stop
            if self._stop.wait(timeout=delay):
                return
            if not self.auto_reconnect:
                return

            url, name, manual_ip, mode = self._conn_params
            self._clear_room_state()
            try:
                self._reset_p2p()
                self.connect(url, name, manual_ip, mode)
                delay = RECONNECT_MIN_S
            except Exception as e:
                self.log("重连失败：%s：%s" % (type(e).__name__, e))
                delay = min(delay * RECONNECT_FACTOR, RECONNECT_MAX_S)

    @staticmethod

    def _machine_tag():
        """A coarse fingerprint of this machine.

        The device id used to be a bare random UUID stored in a file. Copy
        the folder to a second PC (or ship it inside a packaged build) and
        both clients would send the SAME id -- the server then treats the
        second login as a reconnect and kicks the first one offline.

        Binding the id to this machine means a copied file is detected and
        regenerated instead.
        """
        try:
            import uuid as _u
            mac = _u.getnode()
        except Exception:
            mac = 0
        try:
            host = socket.gethostname()
        except Exception:
            host = "?"
        raw = "%s|%012x" % (host, mac & 0xFFFFFFFFFFFF)
        return hashlib.sha1(raw.encode("utf-8", "ignore")).hexdigest()[:16]

    def _client_id(self):
        if not self.my_id:
            path = os.path.join(self.home, ".device_id")
            tag = self._machine_tag()
            stored_id, stored_tag = "", None
            try:
                if os.path.exists(path):
                    txt = open(path, encoding="utf-8").read().strip()
                    # new format: "<id> <machinetag>"; old format: bare id
                    parts = txt.split()
                    stored_id = parts[0] if parts else ""
                    stored_tag = parts[1] if len(parts) > 1 else None
            except Exception:
                pass

            if stored_id and stored_tag == tag:
                self.my_id = stored_id
            else:
                import uuid
                self.my_id = str(uuid.uuid4())
                if stored_id:
                    self.log("device id was copied from another machine "
                             "- generating a fresh one")
                try:
                    open(path, "w", encoding="utf-8").write(
                        "%s %s" % (self.my_id, tag))
                except Exception:
                    pass
        return self.my_id

    def _spawn(self, fn):
        # Reap finished threads first. This list only ever grew before, so
        # a session with many reconnects accumulated Thread objects (and
        # the frames their stacks once referenced) for the life of the
        # process.
        with self._threads_lock:
            self._threads = [t for t in self._threads if t.is_alive()]
        t = threading.Thread(target=fn, daemon=True)
        with self._threads_lock:
            self._threads.append(t)
        t.start()
        return t

    def send(self, obj):
        if not self.ws or self._conn_dead.is_set():
            return
        try:
            with self._send_lock:
                self.ws.send_text(json.dumps(obj, ensure_ascii=False))
            self.log("-> " + json.dumps(obj, ensure_ascii=False)[:200])
        except Exception as e:
            self.log("send failed: %s" % e)

    def send_binary(self, data):
        if not self.ws or self._conn_dead.is_set():
            return
        try:
            with self._send_lock:
                self.ws.send_binary(data)
        except Exception as e:
            self.log("binary send failed: %s" % e)

    # ---------------------------------------------------------- address

    def _adopt_server_stun(self, servers):
        """Prefer the STUN server the signalling server is running.

        Public STUN servers are unreliable (blocked, throttled, or just
        far away), and the client degrading to its LAN address was enough
        to make direct P2P fail outright. The signalling server is a host
        we have already reached, so its STUN is the dependable choice --
        our own list stays as a fallback.
        """
        if not servers:
            return
        picked = []
        for item in servers:
            host = (item.get("host") or "").strip() if isinstance(item, dict) else ""
            try:
                port = int(item.get("port", 3478))
            except (TypeError, ValueError):
                continue
            if host and 0 < port < 65536:
                picked.append((host, port))
        if not picked:
            return
        # server first, then our own list (deduped) as backup
        merged = picked + [e for e in STUN_SERVERS if e not in picked]
        self._stun_servers = merged
        self.log("STUN: %s" % ", ".join("%s:%d" % e for e in picked[:3]))

    def _stun_list(self):
        return getattr(self, "_stun_servers", None) or STUN_SERVERS

    def _wait_for_server_stun(self):
        """Block (briefly) until the server has said where its STUN is.

        `registered` carries stunServers, and until it lands _stun_list()
        hands back the PUBLIC list. register and publish_offer are sent
        back to back from the same thread, but the reply is handled by the
        recv thread one full RTT later -- so without this wait the publish
        always won the race: the built-in STUN (the one host we know is
        reachable, and the reason deploy-server.sh opens two UDP ports)
        was never asked, and a LAN-only address was published for the whole
        session. Direct P2P then had no chance at all.

        Bounded on purpose: a server that never sends stunServers must not
        stall startup. If the wait times out, _maybe_republish() takes the
        second chance once `registered` does arrive.
        """
        if self.ws is None or self._stun_ready.is_set():
            return
        self._stun_ready.wait(STUN_HANDSHAKE_WAIT_S)

    def _maybe_republish(self):
        """Re-publish, but ONLY if we never got a real endpoint.

        The gate is the whole point. Re-probing on a symmetric NAT consumes
        an allocation slot per destination and shifts the very mapping the
        peer is trying to hit -- so refreshing an endpoint we already know
        is actively harmful. Refreshing one we never had is the only way
        out of "published a link-local address forever".

        Runs on its own thread: a STUN probe can take seconds and the
        caller is usually the recv thread.
        """
        if self._have_public_addr:
            return False
        if self.hub is None or self.udp is None:
            return False
        # One at a time: a room that is created and joined in quick
        # succession must not pile up probe threads.
        with self._refresh_lock:
            if self._refresh_inflight:
                return False
            self._refresh_inflight = True

        def _run():
            try:
                self._refresh_own_endpoint()
            finally:
                self._refresh_inflight = False

        try:
            self._spawn(_run)
            return True
        except Exception:
            self._refresh_inflight = False
            return False

    def _start_upnp(self):
        """Ask the router for a port mapping, in the background.

        Deliberately after publishing, not before: UPnP involves a couple of
        seconds of SSDP, and a router with UPnP turned off must not delay
        anyone's connection. If it works we re-publish with the real public
        port, which turns "maybe we can punch" into "the peer just connects".
        """
        if self.manual_ip.strip():
            return
        try:
            import upnp
        except Exception:
            return
        if self.upnp is not None:
            return

        port = self.udp_port or self.punch_port

        # A mapping is a hole in the router. If the process is
        # killed -- crash, force-quit, power loss -- disconnect() never runs
        # and the hole stays open until the lease expires. atexit covers the
        # ordinary exits; nothing can cover a SIGKILL, but that is exactly
        # why the lease is short.
        atexit.register(self._release_upnp)

        def run():
            try:
                m = upnp.Mapping(port, port, "UDP", log=self.log)
                if not m.start():
                    self.log("[UPnP] no mapping available (normal: UPnP "
                             "off or filtered) -- relying on punching")
                    return
                self.upnp = m
                self.upnp_endpoint = m.endpoint
                self._do_publish_address()
            except Exception as e:
                self.log("[UPnP] skipped: %s" % e)

        self._spawn(run)

    def _release_upnp(self):
        """Give the router's port back. Safe to call twice."""
        try:
            m = self.upnp
            if m is not None:
                m.stop()
        except Exception:
            pass
        self.upnp = None
        self.upnp_endpoint = ""

    def _publish_address(self):
        """Endpoint discovery: publish public + LAN endpoints and NAT type.

        STUN runs on the PUNCH socket on purpose -- a symmetric NAT issues a
        different mapping per destination, so a port learned on any other
        socket would be worthless for punching.
        """
        self._wait_for_server_stun()
        self._do_publish_address()
        self._start_nat_recheck()
        self._probe_inbound()
        # Whether the NAT preserves the TCP punch port is measured here,
        # once, so the TCP path is judged on evidence instead of on what
        # the UDP mapping happened to do. Cheap (one connection the server
        # closes) and it decides a whole fallback mechanism.
        self._probe_tcp_preservation()

    def _probe_inbound(self):
        """Is inbound UDP reachable at all -- and if not, whose fault?

        Every other diagnostic in the punch path is ambiguous. "No packet
        from <peer> reached any of our mappings" is printed both when the
        peer's packets are being dropped before they arrive, and when our
        scan is simply aimed at the wrong ports -- and those two need
        opposite responses, one of which is not a code change at all.

        So ask the server to send one UDP packet from a brand new socket:
        a host and port we have never spoken to.

        WHAT A MISS ACTUALLY MEANS (and this is where the old code was
        wrong). It used to conclude "no amount of punching can help". But
        the packet comes from a
        host we have never sent a UDP packet to, so a NAT that filters per
        address -- ADF, which is what most home routers and every CGNAT
        does -- drops it by design. That is not a blocked host, it is a
        NAT doing its job, and the pair is perfectly punchable: having
        sent to the peer, the peer's packets are accepted from any port.

        Real log, both ends of one pair, two different ISPs:

            [NAT] inbound UDP is BLOCKED: ... at 220.178.180.6:48520
            [NAT] inbound UDP is BLOCKED: ... at 39.144.154.160:23653

        Both "blocked" at once, while both had just measured their
        filtering as eif. Two separate measurements disagreeing is the
        signal: a host that is genuinely open to anyone (eif) would have
        received that packet. So a miss only rules out eif -- it does not
        rule out punching.

        The verdict therefore has three states, not two:

          open      the packet arrived: anyone can reach us
          punchable the packet did not arrive, but a host we send to
                    still can (adf) -- this is the ordinary case and the
                    punch must be attempted
          blocked   nothing unsolicited can ever arrive (apdf), so the
                    punch is a wall

        Deciding between the last two is the filtering measurement's job.
        There is deliberately no third branch for "a desktop firewall is
        blocking us": see the note at the miss.
        """
        if self.hub is None or not getattr(self, "p2p_addr", None):
            return
        # One probe at a time: two threads would fight over the catch-all
        # and each would read the other's packet as its own answer.
        if getattr(self, "_inbound_probe_running", False):
            return
        self._inbound_probe_running = True
        got = threading.Event()
        sent_ok = threading.Event()
        asked = threading.Event()
        self._inbound_probe_sent = sent_ok

        def _on_probe(data, addr):
            if data.startswith(INBOUND_PROBE_PACKET):
                got.set()

        try:
            self.hub.set_catch_all(_on_probe, key=None)
        except Exception:
            self._inbound_probe_running = False
            return
        def _warm_and_ask():
            # Aim the probe at a mapping that CAN admit the server.
            #
            # A NAT that filters per address only lets in packets from a
            # host we have sent to -- and the signalling server is a host we
            # speak TCP to and UDP never. So on a restricted-cone NAT (cone
            # mapping, address-dependent filtering: the most common home
            # router there is) the probe was dropped for no reason at all
            # and the host was reported as unreachable.
            #
            # Done here rather than inline: the warm-up is a STUN query
            # (up to a couple of seconds) and this runs on the connect path,
            # where the room restore has only just happened.
            #
            # Runs on its own thread, so it can outlive the session that
            # started it. Everything below therefore has to tolerate the
            # session being torn down underneath it -- see the notes.
            warmed = None
            try:
                if self._stop.is_set():
                    return
                warmed = self._warm_server_mapping()
                if not warmed:
                    # No STUN on the server: still send a few packets its
                    # way, so a NAT that shares one mapping between
                    # destinations admits it.
                    tgt = self._server_udp_target()
                    # Take a LOCAL reference before testing it.
                    #
                    # Checking `self.udp is not None` and then using
                    # `self.udp` is a race: a disconnect on another thread
                    # sets it to None in between, and the send raised
                    # AttributeError -- which is not an OSError, so the
                    # handler below did not catch it and the thread died
                    # with a traceback. Seen in local_test.py, where
                    # clients connect and disconnect in quick succession.
                    udp = self.udp
                    if tgt and udp is not None:
                        for _ in range(INBOUND_PROBE_WARM_COUNT):
                            try:
                                udp.sendto(INBOUND_PROBE_WARM_PACKET, tgt)
                            except (OSError, AttributeError, ValueError):
                                # closed underneath us -- nothing to warm
                                break
                            time.sleep(INBOUND_PROBE_WARM_GAP_S)
            except Exception:
                # A warm-up that fails must not become a traceback in the
                # user's log, and must not stop us asking for the probe:
                # the probe is still worth running, it just loses the
                # guarantee that the server's packet can get in.
                pass
            finally:
                self._inbound_probe_warmed = bool(warmed)
                try:
                    msg = {"action": "inbound_probe"}
                    if warmed:
                        msg["addr"] = warmed
                    self.send(msg)
                except Exception:
                    pass
                finally:
                    asked.set()

        self._spawn(_warm_and_ask)

        def _wait():
            try:
                # Only start the clock once the packet has actually gone
                # out: the warm-up is a STUN query and can take a couple of
                # seconds, and timing that against the probe's own timeout
                # would leave the answer no time to arrive.
                asked.wait(INBOUND_PROBE_TIMEOUT_S)
                if got.wait(INBOUND_PROBE_TIMEOUT_S):
                    self._inbound_blocked = False
                    if self._inbound_probe_warmed:
                        # It reached a mapping we opened towards the server,
                        # from a port we never wrote to: address-dependent
                        # filtering, i.e. exactly what a peer looks like the
                        # moment we start sending to it.
                        self._inbound_state = "punchable"
                        self.log("[NAT] inbound UDP works from a host we "
                                 "sent to (address-dependent filtering): "
                                 "the peer can reach us once the punch "
                                 "starts, so direct is worth attempting.")
                    else:
                        self._inbound_state = "open"
                        self.log("[NAT] inbound UDP works: an unrelated host "
                                 "reached us at %s, so a failed punch is "
                                 "ours to fix" % self.p2p_addr)
                    self._publish_offer()
                    return
                # Did the server even send it? An older server does not
                # know this action and answers nothing, and reporting
                # "BLOCKED" for that blames the host for our own
                # un-upgraded deployment. Seen on two machines at once, on
                # two different ISPs -- a coincidence far less likely than
                # one stale server.
                if not sent_ok.wait(INBOUND_PROBE_TIMEOUT_S):
                    self._inbound_state = "unknown"
                    self._inbound_blocked = False
                    self.log("[NAT] inbound probe inconclusive: the server "
                             "never confirmed sending it, so this tells us "
                             "nothing. Upgrade the server, or ignore this "
                             "line.")
                    return
                # It missed. That rules out endpoint-independent filtering
                # and nothing else -- see the docstring.
                measured = getattr(self, "nat_filter", FILTER_UNKNOWN)
                if measured == FILTER_EIF:
                    # Two measurements cannot both be right. The probe is
                    # the stronger evidence -- it is a packet that did not
                    # arrive, not an inference from a STUN server that may
                    # not even have honoured CHANGE-REQUEST -- so the
                    # filter is the thing that gets corrected.
                    self.log("[NAT] filtering was measured as eif but an "
                             "unrelated host could not reach us, so eif is "
                             "wrong (the server ignored CHANGE-REQUEST); "
                             "treating it as address-dependent")
                if measured == FILTER_APDF:
                    self._on_inbound_blocked(
                        "this NAT filters per address+port (apdf)")
                    return
                # Unknown or address-dependent: both are punchable, so the
                # punch must still run.
                #
                # Nothing here concludes anything about a desktop firewall.
                # A program that is allowed to SEND is also allowed to
                # receive replies, so a host firewall is not what a
                # hole-punching peer looks like -- and blaming it sent two
                # machines on two different ISPs chasing a setting that was
                # already off. The only thing a miss rules out is
                # endpoint-independent filtering.
                self._inbound_state = "punchable"
                self._inbound_blocked = False
                self.log("[NAT] no unsolicited inbound UDP at %s: filtering "
                         "is %s, so a host we send to CAN still reach us "
                         "and the punch is worth running. Only apdf would "
                         "make direct impossible."
                         % (self.p2p_addr, measured))
                self._publish_offer()
            finally:
                self._inbound_probe_running = False
                try:
                    # Only take back OUR slot. clear_catch_all(None) wipes
                    # every key, including the per-peer ones a concurrent
                    # punch is using, and this probe re-runs periodically
                    # mid-session.
                    with self.hub._catch_lock:
                        if self.hub._catch_all.get(None) is _on_probe:
                            self.hub._catch_all.pop(None, None)
                except Exception:
                    try:
                        self.hub.clear_catch_all(None)
                    except Exception:
                        pass

        self._spawn(_wait)

    def _server_udp_target(self):
        """(ip, port) of the signalling server, for the warm packet.

        Taken from the live WebSocket socket rather than parsed out of the
        URL: the URL may be a hostname or go through a proxy, and it is the
        connected socket's peer whose address the NAT actually sees.
        """
        try:
            peer = self.ws.sock.getpeername()
            if peer and peer[0]:
                return peer[0], int(peer[1])
        except Exception:
            pass
        return None

    def _warm_server_mapping(self):
        """Our public endpoint for traffic towards the SIGNALLING server.

        Returns "ip:port", or None when the server runs no STUN (an older
        build) or the query fails.

        Why this is the address the probe must be aimed at:

        A NAT that filters per address only lets in packets from a host we
        have already sent to -- and the signalling server is a host we
        speak TCP to and UDP never. So the probe, arriving from the server
        at the endpoint we published (a mapping opened towards a STUN
        server), is dropped by design on every restricted-cone and every
        symmetric NAT. That miss was then reported as "inbound UDP is
        BLOCKED, no amount of punching can help", which is wrong: the peer
        is a host we DO send to, and its packets get in fine.

        Asking the server's own STUN gives us a real, named mapping towards
        the server, so a probe that reaches it means exactly what matters:
        a host we send to can reach us from a port we never wrote to. That
        is address-dependent filtering, and it is punchable.
        """
        srv = self._server_udp_target()
        if not srv or self.udp is None or self.hub is None:
            return None
        srv_ip = srv[0]
        cands = []
        for host, port in (getattr(self, "_stun_servers", None) or []):
            try:
                if socket.gethostbyname(host) == srv_ip:
                    cands.append((host, port))
            except Exception:
                continue
        if not cands:
            # Real log: `registered` carried no stunServers, so nothing
            # matched and the probe went out with no `addr` at all -- i.e.
            # it was aimed at the mapping we opened towards a PUBLIC stun
            # server, which an address-filtering NAT drops on sight.
            #
            # The server advertises its endpoints on a background probe
            # (detect_public_host) that usually finishes AFTER we have
            # registered, so "not advertised yet" is the normal case, not
            # an error. The built-in STUN is on the same host we are
            # already talking TCP to, on these ports, so ask it directly.
            for p in (3478, 3479, srv[1]):
                if p and (srv_ip, p) not in cands:
                    cands.append((srv_ip, p))
        got = stun_mapped_address(self.udp, timeout=2.0, servers=cands,
                                  hub=self.hub)
        if not got:
            return None
        return "%s:%d" % got

    def _on_inbound_blocked(self, why):
        """Recorded, not just logged: once this is proven, every further
        punch is pure waste -- spraying, a backoff, then the same again.
        """
        self._inbound_state = "blocked"
        self._inbound_blocked = True
        self.log("[NAT] inbound UDP is BLOCKED (%s): the server sent us a "
                 "packet at %s from a fresh source port and it never "
                 "arrived, so no hole can be punched with UDP. Use relay "
                 "mode; TCP simultaneous open is tried first because it "
                 "needs a different mapping."
                 % (why, getattr(self, "p2p_addr", "?")))

    def _on_inbound_probe_sent(self, msg):
        """The server confirms it actually sent the probe packet."""
        ev = getattr(self, "_inbound_probe_sent", None)
        if ev is not None:
            ev.set()

    # ------------------------------------------------- TCP reachability

    def _probe_tcp_preservation(self):
        """Does the NAT keep our TCP punch port, or rewrite it?

        This decides whether a TCP simultaneous open can cross, and it is
        NOT the same question as the UDP one -- which is what the old code
        answered:

            [TCP] skipped: this NAT does not preserve ports (local 30000
                  maps to public 48520) and there is no UPnP mapping, so a
                  simultaneous open cannot cross

        48520 is the UDP mapping. NATs keep the TCP and UDP port pools
        separate, and a great many of them -- CGNAT included -- hand out the
        port the client asked for on TCP while allocating a fresh one per
        destination on UDP. So "UDP is symmetric" was used to switch off the
        one mechanism that survives a symmetric UDP NAT: with the port
        preserved on both ends, each side's SYN leaves from the port the
        other is dialling, and the two meet.

        Measured by asking the server what source port it saw on a TCP
        connection we opened from the punch port. No inference involved.
        """
        port = int(getattr(self, "tcp_punch_port", TCP_PUNCH_PORT) or 0)
        srv = self._server_udp_target()
        if not port or not srv:
            self._tcp_preserves = None
            return
        self._tcp_preserves = None
        try:
            self.send({"action": "tcp_probe", "port": port})
        except Exception:
            self._tcp_preserves = None

    def _run_tcp_probe(self, port):
        """Open one TCP connection from the punch port so the server sees it."""
        try:
            port = int(port or 0)
        except (TypeError, ValueError):
            return
        srv = self._server_udp_target()
        if not port or not srv:
            return
        try:
            from tcppunch import open_bound_connection
        except Exception:
            return
        sock = open_bound_connection(port, srv[0], int(srv[1]),
                                     timeout=TCP_PROBE_TIMEOUT_S)
        if sock is None:
            # Could not bind or could not connect: no verdict, and no
            # reason to disable TCP punching on the strength of it.
            self.log("[TCP] port-preservation probe could not run (port %d "
                     "busy or the server unreachable)" % port)
            return
        try:
            # Hold it open long enough for the server to look at it.
            time.sleep(1.0)
        finally:
            try:
                sock.close()
            except Exception:
                pass

    def _on_tcp_probe_result(self, msg):
        try:
            asked = int(msg.get("port") or 0)
            seen = int(msg.get("seenPort") or 0)
        except (TypeError, ValueError):
            self._tcp_preserves = None
            return
        if not asked or not seen:
            self._tcp_preserves = None
            return
        self._tcp_preserves = (asked == seen)
        if self._tcp_preserves:
            self.log("[TCP] this NAT preserves the punch port (asked %d, the "
                     "server saw %d): a simultaneous open can cross even "
                     "though UDP is symmetric" % (asked, seen))
        else:
            self.log("[TCP] the punch port is rewritten (asked %d, the "
                     "server saw %d): a simultaneous open cannot cross"
                     % (asked, seen))

    def tcp_preserves_port(self):
        """True / False / None (not measured yet or could not be)."""
        return getattr(self, "_tcp_preserves", None)

    def _do_publish_address(self):
        self.my_locals = local_endpoints(self.udp_port)
        # IPv6 first: it needs no punching at all, so if the peer also has
        # a global address this is a plain direct connection.
        try:
            self.my_locals = ipv6_endpoints(self.udp_port) + self.my_locals
        except Exception:
            pass
        nat, delta = NAT_UNKNOWN, 1
        got_public = False

        if self.manual_ip.strip():
            addr = build_manual_address(self.manual_ip, self.udp_port, self.log)
            self.log("manual addr: %s" % addr)
            # a hand-entered public IP is the one case where we know there
            # is nothing to discover, so no later retry is wanted
            got_public = True
        elif self.upnp_endpoint:
            # A router we asked directly gave us a real public port. This is
            # not a guess (unlike every STUN-derived endpoint) and it does
            # not change per destination, so the peer can simply connect.
            addr = self.upnp_endpoint
            nat, delta = NAT_CONE, 0
            self.nat_subtype = NAT_SUB_CONE
            # We asked the router for this mapping, so inbound
            # traffic to it is expected by construction.
            self.nat_filter = FILTER_EIF
            got_public = True
            self.log("using UPnP-mapped address %s (direct, no punching "
                     "needed)" % addr)
        else:
            self.log("STUN querying...")
            # hub= matters: the hub is the ONLY reader of the punch socket.
            # Without it STUN calls recvfrom() itself and races the hub for
            # every datagram -- and the hub drops what it cannot route (a
            # STUN server is not a peer), so replies vanished and every
            # probe looked like a timeout.
            _extra = {}
            probe = stun_probe2(self.udp, timeout=2.0,
                                servers=self._stun_list(),
                                hub=self.hub, log=self.log,
                                extra=_extra)
            self._per_ip_pool = bool(_extra.get("per_ip_pool"))
            if probe:
                ip, port, nat, delta, sub = probe
                addr = "%s:%d" % (ip, port)
                got_public = True
                self.nat_subtype = sub
                self.log("STUN ok: %s" % addr)
                # Second axis: what does the NAT let back IN?
                # Mapping behaviour alone cannot answer that, and
                # it is what decides who has to speak first.
                self._probe_filtering()
                if nat == NAT_SYMMETRIC:
                    if sub in (NAT_SUB_EASY_INC, NAT_SUB_EASY_DEC):
                        self.log("[NAT] symmetric but SEQUENTIAL (%s): the "
                                 "next port is predictable, punching with a "
                                 "contiguous window and %d sockets"
                                 % (sub, SOCKETS_FOR_SYM_TO_CONE))
                    else:
                        self.log("[NAT] symmetric, allocation looks random "
                                 "(%s): falling back to random collision"
                                 % sub)
                elif nat == NAT_CONE:
                    self.log("[NAT] cone: single mapping, plain punch")
            else:
                self.log("STUN failed, falling back to LAN address")
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    s.connect(("8.8.8.8", 80))
                    local = s.getsockname()[0]
                    s.close()
                except Exception:
                    local = "127.0.0.1"
                addr = "%s:%d" % (local, self.udp_port)
                self.log("using LAN addr %s (peer must be on the same LAN)" % addr)
                # Not a public endpoint, so it is worth asking again later:
                # publishing this for the whole session makes direct P2P
                # impossible, and a late-arriving server STUN would fix it.
                self.log("[NAT] no public endpoint yet -- will retry")

        self.nat_type = nat
        self.nat_delta = delta
        self.p2p_addr = addr          # what the peer will be told to reach
        self._have_public_addr = got_public
        self._published_once = True
        # Record what we just measured so the periodic re-check has
        # something to compare against. Only a real public endpoint counts
        # as a baseline: comparing against a LAN fallback would make every
        # later measurement look like a change.
        if got_public:
            self._nat_snapshot = (addr, nat, delta, self.nat_subtype)
        self._publish_offer()
        self.status("address published")

    def _publish_offer(self):
        """Publish our endpoint and NAT signature -- always the FULL set.

        Never hand-build a partial publish_offer. A message carrying only
        some of these fields makes the server fall back to "unknown" for
        the rest, which is how natType came to be reported as "unknown" in
        the room list even though it had been measured correctly: the
        filtering probe re-published with nothing but natFilter and
        silently overwrote the mapping result from a second earlier.

        Every field is read from self, so all three publish sites agree by
        construction.
        """
        self.send({"action": "publish_offer", "p2pAddr": self.p2p_addr,
                   "localAddrs": self.my_locals, "natType": self.nat_type,
                   "natDelta": self.nat_delta, "natSubtype": self.nat_subtype,
                   # Not the raw STUN verdict: the inbound probe is a
                   # packet that either arrived or did not, and when the
                   # two disagree the probe wins. See
                   # natpunch.effective_filter. Both inputs are read with
                   # getattr so a partially-built publisher still emits
                   # something sane instead of raising.
                   "natFilter": effective_filter(
                       getattr(self, "nat_filter", FILTER_UNKNOWN)
                       or FILTER_UNKNOWN,
                       getattr(self, "_inbound_state", "unknown")),
                   "tcpPort": self.tcp_punch_port,
                   # separate port region per destination IP -- see
                   # protocol.PER_IP_POOL_GAP. Without it the peer aims a
                   # contiguous window at a region we will never be in.
                   "perIpPool": bool(getattr(self, "_per_ip_pool", False))})
        # Stamp it HERE, every time, not only when the address changes.
        #
        # It used to be set in _refresh_punch_anchor only after a change,
        # and that path returns early when the address is unchanged -- which
        # for a hub socket is always, because socket 30000 -> the stun
        # server is one long-lived flow whose mapping never moves. So the
        # stamp stayed 0 forever, the age printed as the raw epoch
        # ("anchor is 1789693310s old"), and every punch re-ran a full
        # probe believing the anchor was ancient.
        self._p2p_published_at = time.time()

    def _start_nat_recheck(self):
        """Re-measure our own NAT periodically, not just once at connect.

        The measurement taken at connect time describes the network we were
        on THEN. Routers redial, laptops change Wi-Fi, CGNAT reassigns
        ports -- and a signature recorded hours ago then actively misleads:
        we keep punching at an endpoint that no longer exists, and we keep
        applying a strategy chosen for a NAT that is no longer in the path.
        """
        if getattr(self, "_nat_recheck_started", False):
            return
        self._nat_recheck_started = True
        try:
            self._spawn(self._nat_recheck_loop)
        except Exception:
            self._nat_recheck_started = False

    def _nat_recheck_loop(self):
        # A first sleep, not a first immediate check: connect() has only
        # just measured, so re-measuring now would be pure duplication.
        time.sleep(NAT_RECHECK_S)
        while not self._stop.is_set():
            try:
                self._recheck_nat()
            except Exception:
                pass
            self._stop.wait(NAT_RECHECK_S)

    def _recheck_nat(self):
        """One re-measurement. Re-publishes only when something changed.

        Skipped while a punch is in flight on purpose: the probe uses the
        same socket (it has to -- a mapping learned on another socket is
        worthless on a symmetric NAT), and stealing the hub's attention
        mid-punch is a good way to lose the very packet we were waiting
        for. Missing one 90s tick costs nothing; disturbing a punch costs
        the connection.
        """
        if self.udp is None or self.hub is None or self._stop.is_set():
            return
        try:
            busy = getattr(self, "_direct_loops", None)
            if busy:
                return
        except Exception:
            pass
        try:
            # More samples than the connect path uses: nothing is waiting
            # on this, and a downgrade to "random" is the one verdict we
            # should not reach on thin evidence.
            _extra2 = {}
            got = stun_probe2(self.udp, timeout=2.0,
                              servers=self._stun_list(), hub=self.hub,
                              third_n=5, extra=_extra2)
            self._per_ip_pool = bool(_extra2.get("per_ip_pool"))
        except Exception:
            return
        if not got or self._stop.is_set():
            return
        ip, port, nat, delta, sub = got
        addr = "%s:%d" % (ip, port)

        # A WORSE verdict has to be confirmed before we believe it.
        #
        # The two errors are not equally costly. Guessing "predictable"
        # when the NAT is actually random costs one failed punch, a
        # backoff, and a retry -- and then relaying, which works. Guessing
        # "random" when it is actually predictable costs the direct
        # connection outright, because hard x hard is the one combination
        # punch_plan refuses to try.
        #
        # And a bad reading is easy to get: this runs every 90s, i.e.
        # usually while a game is running, and the probe measures "where
        # the next port lands" -- a question whose answer is skewed by
        # every unrelated UDP flow the machine opens while we are asking.
        # A few of those and a sequential allocator looks random.
        #
        # So: trust improvements immediately, require two agreeing
        # re-checks before accepting a downgrade. The endpoint is still
        # updated right away -- that is a fact, not an inference.
        believed = sub
        if subtype_regressed(sub, self.nat_subtype):
            pending = getattr(self, "_nat_downgrade_pending", 0) + 1
            self._nat_downgrade_pending = pending
            if pending < 2:
                self.log("[NAT] re-check says %s (was %s) -- not "
                         "downgrading yet, one bad sample can be a busy "
                         "machine rather than a new NAT" % (sub,
                                                            self.nat_subtype))
                believed = self.nat_subtype
            else:
                self._nat_downgrade_pending = 0
                self.log("[NAT] %s confirmed on a second re-check -- "
                         "downgrading" % sub)
        else:
            self._nat_downgrade_pending = 0

        prev = getattr(self, "_nat_snapshot", None)
        if not nat_changed(prev, (addr, nat, delta, believed)):
            return                      # nothing moved; stay quiet

        old_desc = prev[0] if prev else "(none)"
        self._nat_snapshot = (addr, nat, delta, believed)
        self.p2p_addr = addr
        self.nat_type = nat
        self.nat_delta = delta
        # `believed`, not `sub`: assigning the raw reading here undid the
        # whole confirmation rule above, so the room list showed the
        # downgraded class on the very first bad sample while the log said
        # it was being held back.
        self.nat_subtype = believed
        self._have_public_addr = True
        self.log("[NAT] network changed: %s -> %s (type %s/%s)"
                 % (old_desc, addr, nat, believed))

        # Peers must hear the new endpoint, and -- just as important --
        # must be allowed to try again. Failures recorded against the OLD
        # address say nothing about the new one, so leaving the backoff and
        # the blacklist in place would keep us relaying on a network where
        # direct would now work.
        # Re-measure FILTERING too, not just mapping.
        #
        # _recheck_nat exists because the NAT can change -- and filtering is
        # the sole input to must_open_first(), i.e. to deciding which end
        # opens the door. Reusing the value measured on the old network
        # means that decision keeps being made about a network we are no
        # longer on. The probe is one-shot, so allow it to run again.
        self._filter_probe_started = False
        self._probe_filtering()

        self._publish_offer()
        self._on_nat_changed()

    def _resolve_tcp_port(self):
        """Pick the TCP punch port: configured, else UDP port + 1.

        Two things have to hold. It must not equal the UDP punch port (both
        are bound for the lifetime of the session), and it must be stable,
        because the peer is aiming at it.

        An explicit setting wins when present (the "TCP 打洞" field, blank by
        default); otherwise offset from the UDP port so the two can never
        collide no matter what the user typed there.
        """
        cfg = 0
        try:
            cfg = int(getattr(self, "tcp_punch_port_cfg", 0) or 0)
        except (TypeError, ValueError):
            cfg = 0
        if 0 < cfg < 65536:
            self.tcp_punch_port = cfg
            return
        base = int(self.udp_port or self.punch_port or PUNCH_PORT)
        # Clamped: 65535 + 1 is not a port, and an out-of-range bind raised
        # somewhere the caller only logged as a mystery failure.
        self.tcp_punch_port = base + 1 if base < 65535 else base - 1

    def _probe_filtering(self):
        """RFC 5780: discover what the NAT lets back in.

        Runs only after a public endpoint is known, so a failure here costs
        two short timeouts and nothing else -- we fall back to
        FILTER_UNKNOWN and every decision that used it falls back with it.

        Deliberately NOT part of stun_probe2: that call is on the startup
        path where every extra second is felt by the user, while this only
        decides strategy, not whether we can connect at all.
        """
        # Off the startup path, on purpose.
        #
        # This used to run inline right after a successful mapping probe. On
        # a network where the STUN servers are unreachable that added three
        # more timeouts to a path the user is already waiting on, and the
        # result only refines STRATEGY -- it never decides whether we can
        # connect at all. In the background a slow or dead server costs
        # nothing, and a late answer simply arrives after the first punch,
        # which falls back to FILTER_UNKNOWN and behaves as before.
        if getattr(self, "_filter_probe_started", False):
            return
        servers = self._stun_list() or None
        if not servers or self.udp is None:
            return
        self._filter_probe_started = True
        udp, hub = self.udp, self.hub
        try:
            self._spawn(lambda: self._probe_filtering_bg(udp, hub,
                                                         list(servers[:2])))
        except Exception:
            self._filter_probe_started = False

    def _probe_filtering_bg(self, udp, hub, servers):
        names = {FILTER_EIF: "endpoint-independent (anything may come in)",
                 FILTER_ADF: "address-dependent (only hosts we wrote to)",
                 FILTER_APDF: "address+port dependent (only the exact "
                              "address we wrote to)"}
        deadline = time.monotonic() + FILTER_PROBE_BUDGET_S
        try:
            for host, port in servers:
                left = deadline - time.monotonic()
                if left <= 0.1 or self._stop.is_set():
                    break
                got = stun_filtering(udp, host, port, timeout=1.0, hub=hub,
                                     log=self.log, deadline=deadline)
                if got != FILTER_UNKNOWN:
                    self.nat_filter = got
                    self.log("[NAT] filtering: %s" % names.get(got, got))
                    # Re-publish so peers learn it; they may already be
                    # punching, in which case they just see unknown.
                    #
                    # The FULL offer, not just the filter: this used to
                    # send p2pAddr + natFilter only, and the server's
                    # "missing means unknown" fallback then overwrote a
                    # natType/natSubtype that had been measured correctly
                    # one second earlier.
                    try:
                        self._publish_offer()
                    except Exception:
                        pass
                    return
        except Exception as e:
            self.log("[NAT] filtering probe failed: %s" % e)


    # ---------------------------------------------------------- rooms

    def _recv_loop(self, gen=None):
        try:
            while not self._stop.is_set():
                if gen is not None and gen != self._gen:
                    return
                opcode, payload = self.ws.recv_frame()
                if opcode == 0x8:
                    break
                if opcode == 0x2:
                    self._on_relay_frame(payload)
                    continue
                if opcode != 0x1:
                    continue
                self._on_text(payload.decode("utf-8", "ignore"))
        except (WSError, OSError) as e:
            if not self._stop.is_set():
                self.log("connection lost: %s" % e)
            self._conn_dead.set()
            # the room we were in is gone with the link; keeping the stale
            # code would make the reconnect fallback think we are still in
            self._clear_room_state()
        except Exception as e:
            if not self._stop.is_set():
                self.log("recv error: %s: %s" % (type(e).__name__, e))
            self._conn_dead.set()
            self._clear_room_state()

    def _on_text(self, text):
        self.log("<- " + text[:300])
        try:
            msg = json.loads(text)
        except Exception:
            return
        action = msg.get("action", "")

        if action == "pong":
            self._on_pong(msg)
            return
        if action == "registered":
            self.my_id = msg.get("peerId", self.my_id)
            self.log("registered ID: %s" % self.my_id)
            # Room actions are only valid once the server knows who we are.
            self._registered.set()
            self._adopt_server_stun(msg.get("stunServers"))
            # Unblock endpoint discovery either way: a server with no STUN
            # to advertise must not cost us the full wait.
            self._stun_ready.set()
            # If discovery already ran and came back empty, the server's
            # STUN just gave us a second chance we did not have before.
            if self._published_once:
                self._maybe_republish()
            return
        if action == "room_list":
            self.rooms_snapshot = msg.get("rooms", [])
            if self.rooms_cb:
                self.rooms_cb(msg.get("rooms", []))
            return
        if action == "room_created":
            self.room_name = msg.get("roomName") or self.room_name
            self.room_code = msg.get("roomCode", "")
            if msg.get("maxPlayers"):
                self.max_players = int(msg["maxPlayers"])
            self.is_host = True
            self.log("room created: %s (%s)" % (msg.get("roomName"), self.room_code))
            self.refresh_rooms()
            return
        if action == "inbound_probe_sent":
            self._on_inbound_probe_sent(msg)
            return
        if action == "tcp_probe_go":
            self._spawn(lambda: self._run_tcp_probe(msg.get("port")))
            return
        if action == "tcp_probe_result":
            self._on_tcp_probe_result(msg)
            return
        if action == "room_update":
            self.room_name = msg.get("roomName") or self.room_name
            # capacity comes from the host's room; an old server omits it
            if msg.get("maxPlayers"):
                self.max_players = int(msg["maxPlayers"])
            members = msg.get("members", [])
            if msg.get("roomCode"):
                self.room_code = msg["roomCode"]
            self._note_members(members)
            for m in members:
                if m.get("id") == self.my_id:
                    self.is_host = bool(m.get("isHost"))
                if m.get("isHost"):
                    self.host_id = m.get("id", "")
            return
        if action == "room_closed":
            reason = msg.get("reason") or "deleted"
            # Remember the room BEFORE clearing it: a "host left" is often
            # just the host reconnecting (server restart, brief drop), and it
            # will rebuild a room with the same NAME but a new random code.
            # Without capturing it here the guest would have nothing to look
            # for and would sit idle after the host came back.
            self._clear_room_state()
            self._reset_p2p()
            if reason == "host_left":
                self.log("房主已离开，房间解散")
                self.status("房主已离开，房间解散")
            else:
                self.log("房间已关闭")
                self.status("房间已关闭")
            # the world is gone, so drop the stale host too
            self.host_id = ""
            self.refresh_rooms()
            return
        if action == "error":
            # The server sends a code; show Chinese and keep the code so it
            # can be quoted verbatim when reporting a problem.
            code = msg.get("code") or ""
            # remembered so callers (and tests) can react to a specific
            # failure instead of scraping the log text
            self.last_error_code = code or None
            text = describe_error(code, msg.get("message") or "")
            self.log("服务器错误：%s" % text)
            self.status(text)
            return
        if action == "peer_signal":
            src = msg.get("fromId", "")
            sig = msg.get("signal") or {}
            ch = self._get_channel(src)
            if ch is None:
                return
            try:
                sid = int(sig.get("sid") or 0)
            except (TypeError, ValueError):
                return
            kind = sig.get("t")
            if kind == "open":
                st, created = ch.alloc_stream(sid)
                if created and self.is_host:
                    self._spawn(lambda x=st: self._host_stream(ch, x))
            elif kind == "close":
                st = ch.get_stream(sid)
                if st is not None:
                    st.stop.set()
            return
        if action == "start_punch":
            addr = msg.get("targetAddr", "")
            peer_id = msg.get("targetId", "")
            ep = None
            if addr and ":" in addr:
                host, _, port = addr.rpartition(":")
                try:
                    ep = (host, int(port))
                except ValueError:
                    return
            self.target_id = peer_id
            self.target_addr = ep

            # Coordinated start, as a RELATIVE delay from ARRIVAL.
            #
            # Deliberately not an absolute timestamp: that would require
            # our clock to agree with the server's and with the peer's,
            # and a peer-to-peer link is the last place to assume that.
            #
            # And the deadline is anchored to the moment this message
            # arrived, not to whenever the punch loop gets round to it:
            # candidates are tried in order, so v6/LAN attempts run first
            # and their cost differs between the two peers. Anchoring
            # leaves only the difference in RTT.
            delay = 0.0
            try:
                delay = float(msg.get("startIn") or 0)
            except (TypeError, ValueError):
                delay = 0.0
            # A fresh start_punch is a fresh round: the previous wait has
            # been spent, so let this one wait again. Without this a
            # rebuilt link never synchronises -- the peer stays in the
            # "already waited" set forever.
            self._punch_synced.discard(peer_id)
            if delay > 0:
                self._punch_start_in[peer_id] = delay
                self._punch_recv_at[peer_id] = time.monotonic()
                # invalidate any wait already in flight: it is sleeping
                # against the previous deadline
                self._punch_gen[peer_id] = self._punch_gen.get(peer_id, 0) + 1
                self.log("start_punch: %s @ %s (begin in %.1fs)"
                         % (peer_id, addr, delay))
            else:
                self._punch_start_in.pop(peer_id, None)
                self._punch_recv_at.pop(peer_id, None)
                self.log("start_punch: %s @ %s" % (peer_id, addr))

            # candidate list: LAN first, public last
            peer_public = ep
            peer_locals = msg.get("targetAddrs") or []
            peer_nat = msg.get("targetNat") or NAT_UNKNOWN
            try:
                peer_delta = int(msg.get("targetDelta") or 0)
            except (TypeError, ValueError):
                peer_delta = 0
            self._peer_candidates[peer_id] = order_candidates(
                peer_public, peer_locals, self.my_locals, self.log)
            self._peer_nat[peer_id] = peer_nat
            # The PEER's step, not ours. Using our own delta was plain wrong:
            # two different NATs allocate differently, so our number says
            # nothing about the port their NAT will pick.
            self._peer_delta[peer_id] = peer_delta
            peer_sub = (msg.get("targetSubtype") or "").strip().lower()
            if peer_sub:
                self._peer_sub[peer_id] = peer_sub
            # Whether the peer's port for US is near the one it published.
            # Absent means "no" (an older peer, or the ordinary sequential
            # allocator), which keeps the window for everyone who needs it.
            try:
                self._peer_per_ip[peer_id] = bool(msg.get("targetPerIpPool"))
            except AttributeError:
                # A session built without the punch attributes: the flag is
                # an optimisation, and losing it must not break the link.
                pass
            # The peer's TCP punch port. Without it there is nothing to aim
            # a simultaneous open at, so TCP is skipped rather than tried
            # blind -- see net_transport._try_tcp_punch.
            try:
                tp = int(msg.get("targetTcpPort") or 0)
            except (TypeError, ValueError):
                tp = 0
            if tp:
                self._peer_tcp[peer_id] = tp
            peer_filter = (msg.get("targetFilter") or "").strip().lower()
            if peer_filter:
                self._peer_filter[peer_id] = peer_filter
            if peer_nat == NAT_SYMMETRIC:
                self.log("[NAT] peer is behind symmetric NAT (%s, step=%d)"
                         % (peer_sub or "class unknown", peer_delta))

            # A peer that switched back to direct asks the server to
            # re-coordinate, which lands here. If we already have a channel
            # we used to ignore it entirely -- and the common case is
            # exactly that: we gave up and went to the relay long ago, so
            # our peer would punch alone forever. Honour the request by
            # dropping what we have and coming back.
            force = bool(msg.get("force"))
            if force:
                # Remember that this rebuild is an ANSWER, so we do not
                # ask the server for another one and start a loop -- see
                # _request_punch_coordination.
                seen = getattr(self, "_force_seen", None)
                if seen is None:
                    seen = self._force_seen = {}
                seen[peer_id] = time.time()
                self._teardown_peer(peer_id)
            self._dispatch_mode(peer_id, ep)
            return
    # ---------------------------------------------------------- channels

    def snapshot(self):
        """Everything the GUI status panel needs.

        Deliberately a plain dict: the GUI must never reach into live
        network objects from its own thread.
        """
        with self._stat_lock:
            up, down = self.bytes_up, self.bytes_down
        # live speed, not just a cumulative total -- sample() smooths the
        # delta since the previous call so the number is readable
        self._up_meter.update(up)
        self._down_meter.update(down)
        with self._chan_lock:
            chans = [c for c in self.channels.values() if not c.stop.is_set()]
            streams = sum(len(c.streams) for c in chans)
        return {
            "connected": bool(self.ws) and not self._conn_dead.is_set(),
            "state": self._status_text,
            "mode": self.mode,
            "is_host": self.is_host,
            "room": self.room_code,
            "members": len(self.members_snapshot),
            "max_players": self.max_players,
            "channels": len(chans),
            "streams": streams,
            "udp_port": self.udp_port,
            "proxy_port": self.proxy_port if not self.is_host else None,
            "mc_port": self.mc_port,
            "bytes_up": up,
            "bytes_down": down,
            "rate_up": self._up_meter.sample(),
            "rate_down": self._down_meter.sample(),
            "latency_ms": self.latency_ms,
            # "state" used to be written twice -- first the free-form text,
            # then the state-machine value. The dict silently kept the
            # second, and the GUI only worked because it happened to read
            # that one. Both are now explicit.
            "state": self._state,
            "state_text": self._status_text,
            "peer_id": self.my_id,
        }

    # ---------------------------------------------------------- misc

    def _ping_loop(self, gen=None):
        """Measure and report round-trip latency.

        Two jobs, and previously BOTH were missing:
          1. time the ping/pong round trip (the old loop sent a ping but
             threw the reply away, so latency stayed 0 forever)
          2. push the result to the server so every member sees it

        Also stops once the link is gone, otherwise every tick produced a
        "send failed" error on an already-closed socket.
        """
        while not self._stop.is_set() and not self._conn_dead.is_set():
            # a stale loop from a previous connection must exit, or every
            # reconnect would add another pinger
            if gen is not None and gen != self._gen:
                return
            time.sleep(PING_INTERVAL_S)
            if self._conn_dead.is_set() or self._stop.is_set():
                return
            if gen is not None and gen != self._gen:
                return
            try:
                with self._ping_lock:
                    self._ping_seq += 1
                    seq = self._ping_seq
                    self._pending_pings[seq] = time.monotonic()
                # older servers ignore the extra field and just reply "pong"
                self.send({"action": "ping", "seq": seq})
            except Exception:
                return

    def _on_pong(self, msg):
        """Handle a pong: compute RTT and report it when it moves."""
        with self._ping_lock:
            seq = msg.get("seq")
            sent = self._pending_pings.pop(seq, None)
            if sent is None and len(self._pending_pings) == 1:
                # server does not echo seq: take the single outstanding one
                sent = self._pending_pings.pop(
                    next(iter(self._pending_pings)), None)
        if sent is None:
            return

        rtt = (time.monotonic() - sent) * 1000.0
        # exponential moving average: a single spike should not flip the
        # number around, but a real change should show up within a few ticks
        if self.latency_ms <= 0:
            self.latency_ms = rtt
        else:
            self.latency_ms = self.latency_ms * 0.7 + rtt * 0.3

        # only push upstream when it actually changed, so we are not
        # spamming room_update to everyone every few seconds
        rounded = int(round(self.latency_ms))
        if rounded <= 0:
            # loopback really can be sub-millisecond; report 1 rather than
            # 0, which is indistinguishable from "not measured yet"
            rounded = 1
        if abs(rounded - self._last_reported) >= 1:
            self._last_reported = rounded
            try:
                self.send({"action": "update_latency", "latency": rounded})
            except Exception:
                pass

    def disconnect(self):
        # give the router's port back; leaving it would be a stray hole
        self._release_upnp()
        self._stop.set()
        self._conn_dead.set()
        self.auto_reconnect = False
        self._room_to_restore = None
        self.set_state(STATE_IDLE)
        self._reset_p2p()
        self._gen += 1
        self._release_punch_socket()
        try:
            if self.ws:
                self.ws.close()
        except Exception:
            pass
        self.log("disconnected")
