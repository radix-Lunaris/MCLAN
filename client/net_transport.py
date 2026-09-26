# -*- coding: utf-8 -*-
"""Peer transport: UDP hole punching and server relay.

Owns the per-peer channels and the two ways bytes can reach a peer.
Which one is used is decided by _dispatch_mode() according to the mode
the user picked.
"""
import json
import socket
import struct
import threading
import random
import time

from udptunnel import UdpTunnel, fmt_addr, UdpHub

from protocol import (frame, MODE_AUTO, MODE_DIRECT, MODE_RELAY,
                      AUTO_DIRECT_ATTEMPTS, DIRECT_RETRY_S, RELAY_RETRY_S,
                      PUNCH_TIMEOUT_S, RELAY_DATA, control_frame,
                      LINK_CHECK_S, LINK_DEAD_S,
                      NAT_UNKNOWN, NAT_CONE, NAT_SYMMETRIC, SYM_SPRAY_PORTS,
                      SPRAY_BUDGET, JITTER_SPRAY, JITTER_MAX_SKIP,
                      UNKNOWN_SPRAY_PORTS,
                      AUTO_PUNCH_TIMEOUT_S, LAN_PUNCH_TIMEOUT_S,
                      NO_MECHANISM_TIMEOUT_S, ANCHOR_STALE_S,
                      ANCHOR_REFRESH_TIMEOUT_S, FORCE_ANSWER_QUIET_S,
                      IPV6_CONNECT_SLACK_S,
                      HANDSHAKE_AFTER_HIT_S, IPV6_PUNCH_TIMEOUT_S,
                      ROUND_WALL_CLOCK_S,
                      SYM_TO_CONE_SPRAY_S,
                      PUNCH_START_MAX_WAIT_S,
                      DIRECT_FAIL_BLACKLIST_S, DIRECT_FAIL_LIMIT,
                      DIRECT_BACKOFF_S, DIRECT_BACKOFF_MAX_S,
                      RELAY_UPGRADE_EVERY_S, RELAY_UPGRADE_BUDGET_S,
                      NAT_SUB_CONE, NAT_SUB_EASY_INC, NAT_SUB_EASY_DEC,
                      NAT_SUB_HARD, NAT_SUB_UNKNOWN,
                      FILTER_EIF, FILTER_ADF, FILTER_APDF, FILTER_UNKNOWN,
                      TCP_PUNCH_PORT, TCP_PUNCH_TIMEOUT_S)
from common import (predicted_ports, stun_probe, stun_probe2,
                    is_ipv6, is_public_ipv4)
from channel import PeerChannel
from natpunch import (punch_plan, run_punch, should_lead, port_window,
                      METHOD_NONE, METHOD_CONE, METHOD_SYM_TO_CONE,
                      METHOD_OPENP2P, must_open_first, effective_filter)
from tcppunch import simultaneous_open as tcp_simultaneous_open, enabled as tcp_enabled


class TransportMixin:
    def _get_channel(self, peer_id):
        with self._chan_lock:
            return self.channels.get(peer_id)

    def _new_channel(self, peer_id, label, send_fn=None):
        with self._chan_lock:
            old = self.channels.get(peer_id)
            if old and not old.stop.is_set():
                return old
            ch = PeerChannel(peer_id, label, send_fn, self.log)
            self.channels[peer_id] = ch
            return ch

    def _dispatch_mode(self, peer_id, ep):
        if not peer_id:
            return
        if self._get_channel(peer_id) is not None:
            return
        if self.mode == MODE_RELAY:
            self._start_server_relay(peer_id)
            return
        # Proven-unreachable inbound: do not burn the budget proving it
        # again. The server sent us a packet from a fresh source port --
        # exactly what a peer looks like -- and it never arrived, so every
        # punch from here is 12s of spraying at a wall, then a backoff,
        # then the same again.
        if getattr(self, "_inbound_blocked", False) and \
                self.mode == MODE_AUTO:
            # Proven-unreachable inbound UDP: no scan can succeed. But that
            # verdict is about UDP -- the TCP path opens its own mapping,
            # and a NAT that rewrites or filters one protocol says nothing
            # certain about the other. One simultaneous open is cheaper
            # than relaying forever, so it is tried before the relay.
            self.log("inbound UDP was measured as blocked on this host, so "
                     "no UDP hole can be punched to %s; trying TCP "
                     "simultaneous open first." % peer_id)
            try:
                cands = self._peer_candidates.get(peer_id) or []
                for cand in cands:
                    if is_ipv6(cand[0]):
                        continue
                    if self._try_tcp_punch(peer_id, cand):
                        return
            except Exception as e:
                self.log("[TCP] punch error: %s" % e)
            self._start_server_relay(peer_id)
            return
        self._start_direct(peer_id, ep)

    # ---- direct: UDP hole punch, one tunnel per peer ----

    def _start_direct(self, peer_id, ep):
        if self.hub is None:
            return
        cands = self._peer_candidates.get(peer_id) or ([tuple(ep)] if ep else [])
        if not cands:
            return
        self._warn_if_same_public_ip(peer_id, cands)
        # REFUSE to start a second loop for a peer that already has one.
        #
        # See the comment on _direct_loops: without this, each start_punch
        # and each "link died" adds another concurrent loop for the same
        # peer. The new loop is not a fresh attempt, it is a duplicate --
        # same channel, same candidates, separate failure counter.
        with self._direct_loop_lock:
            if peer_id in self._direct_loops:
                self.log("direct to %s is already running; not starting "
                         "another" % peer_id)
                return
            self._direct_loops.add(peer_id)
        self._spawn(lambda: self._direct_loop(peer_id, cands))

    @property
    def _v6_failed(self):
        """IPv6 addresses already tried and proved unusable, per session."""
        got = getattr(self, "_v6_failed_set", None)
        if got is None:
            got = self._v6_failed_set = set()
        return got

    def _have_ipv6(self):
        """Do WE have a globally routable IPv6 address?

        Not "does the peer publish one". A v6-capable peer happily offers
        its address to a v4-only host, and that host then tries to reach it
        with no way out -- see the note in _direct_loop.
        """
        for m in getattr(self, "my_locals", None) or []:
            ip = m.rpartition(":")[0] if isinstance(m, str) else ""
            if ip and is_ipv6(ip):
                return True
        return False

    def _warn_if_same_public_ip(self, peer_id, cands):
        """Say so when both ends are behind the SAME public IP.

        That is the host + VM case, and also two machines on one router.
        A packet to the peer's public endpoint then has to leave the router
        and come straight back -- hairpinning / NAT loopback -- which a lot
        of home routers simply drop.

        Without this the symptom is silent and misleading: "no packet from
        <peer> reached any of our mappings", which reads like the peer is
        not punching, when in fact every packet was thrown away by the
        router before it could arrive. It also cannot be fixed by tuning
        the window or the socket count, so it is worth saying out loud.
        """
        mine = getattr(self, "p2p_addr", None) or ""
        my_ip = mine.rpartition(":")[0] if mine else ""
        if not my_ip:
            return
        for c in cands:
            ip = c[0] if isinstance(c, (tuple, list)) else str(c).rpartition(":")[0]
            if ip and ip == my_ip:
                self.log("[NAT] peer has the same public IP as us (%s): "
                         "packets must hairpin through the router, which "
                         "many routers drop -- test from two separate "
                         "networks (e.g. one on a phone hotspot)" % ip)
                return

    def _end_direct_loop(self, peer_id):
        with self._direct_loop_lock:
            self._direct_loops.discard(peer_id)

    def _refresh_punch_anchor(self, peer_id, budget):
        """Re-measure and re-publish our endpoint right before punching.

        The peer scans a window around the port we PUBLISHED. That port was
        measured when we connected, and on a NAT whose allocation cursor
        keeps moving it is already wrong by the time the peer starts
        looking -- it is stale by however long we have been connected.

        Measured on a real CGNAT, same socket, same LAN address:

            23:20:23  published 220.178.180.180:22116
            23:21:53  published 220.178.180.180:28745

        Roughly 73 ports a second. A punch that began 140s after the last
        publish anchored its scan about 10,000 ports away from where the
        socket array actually opened -- so every packet went to ports the
        peer had never been allocated, and widening the window cannot fix
        an error of that size.

        Re-measuring here makes the anchor seconds old instead of minutes.
        It is not free (one STUN round trip), so it is only worth doing
        when we would otherwise be idle waiting for the coordinated start.
        """
        if self.udp is None or budget <= 0.2:
            return
        try:
            got = stun_probe2(self.udp, timeout=budget,
                              servers=self._stun_list(), hub=self.hub)
        except Exception:
            return
        if not got:
            return
        ip, port = got[0], got[1]
        if not ip or not port:
            return
        addr = "%s:%d" % (ip, port)
        if addr == self.p2p_addr:
            return
        old = self.p2p_addr
        self.p2p_addr = addr
        self._p2p_published_at = time.time()
        self._publish_offer()
        self.log("[NAT] anchor refreshed for the punch: %s -> %s"
                 % (old or "(none)", addr))

    def _refresh_anchor_if_stale(self, peer_id):
        """Re-measure the anchor before a scan that depends on it, if old.

        Both plans scan a window around the port we PUBLISHED. That port
        was measured when we connected, and on a NAT whose allocation
        cursor keeps moving it is wrong by the time anyone looks -- it is
        stale by however long ago we last measured.

        Same socket, same LAN address, measured 90s apart on a real CGNAT:

            23:20:23  published 220.178.180.180:22116
            23:21:53  published 220.178.180.180:28745

        ~73 ports a second. A punch that starts 140s after the last
        publish anchors its scan about 10,000 ports from where the socket
        array actually opens, so every packet goes to ports the peer was
        never allocated -- and no window width covers an error that big
        (bench: at drift 300 both_easy measures 0% even at max reach 2000).

        Throttled on purpose. Each probe is a new destination, which on a
        symmetric NAT costs an allocation slot and nudges the cursor -- so
        re-probing every round would shift the mapping the peer is
        scanning for. Only refresh when the anchor is old enough that the
        drift has already dwarfed that cost.
        """
        if self.udp is None or self.hub is None:
            return
        last = getattr(self, "_p2p_published_at", 0) or 0
        if time.time() - last < ANCHOR_STALE_S:
            return
        if last:
            self.log("[NAT] anchor is %.0fs old; re-measuring before the "
                     "scan" % (time.time() - last))
        else:
            self.log("[NAT] anchor age unknown; re-measuring before the "
                     "scan")
        self._refresh_punch_anchor(peer_id, ANCHOR_REFRESH_TIMEOUT_S)

    def _await_punch_start(self, peer_id, cand, plan):
        """Hold off so both ends spray at the same time.

        The wait must happen on the candidate that actually needs
        coordination. Keying it on `attempt == 1` was a mistake: candidates
        are tried in order and the first one is now IPv6 (or a LAN address),
        so the wait was spent there, and by the time the public v4
        candidate came round the moment had already passed -- silently
        disabling the whole mechanism in exactly the case it was built for.

        So: wait once, on the first candidate that is a public IPv4 address
        and whose punch plan is more than a simple cone-to-cone exchange.
        """
        synced = getattr(self, "_punch_synced", None)
        if synced is None:
            synced = self._punch_synced = set()
        if peer_id in synced:
            return
        ip = str(cand[0])
        if is_ipv6(ip) or ip.startswith("127.") or ip.startswith("169.254."):
            return
        # A plain exchange has nothing to synchronise, and "no mechanism"
        # is a decision already made -- waiting only delays the relay we
        # are about to fall back to.
        if plan in (METHOD_CONE, METHOD_NONE):
            return
        synced.add(peer_id)

        # Anchor the deadline to when the message ARRIVED, not to now.
        #
        # "sleep(start_in)" is wrong: by the time we get here we may have
        # already spent 3s on an IPv6 candidate and 2s on a LAN one, and
        # the peer may have spent a different amount. The two ends then
        # start at (recv + own prefix + start_in), and whenever the
        # prefixes differ the overlap degrades -- to zero in the common
        # "one side has v6/LAN candidates, the other does not" case.
        #
        # Anchoring to recv_at leaves only the difference in RTT.
        start_in = getattr(self, "_punch_start_in", {}).get(peer_id, 0)
        recv_at = getattr(self, "_punch_recv_at", {}).get(peer_id)
        if start_in <= 0 or recv_at is None:
            return
        deadline = recv_at + min(start_in, PUNCH_START_MAX_WAIT_S)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            # already past it -- start immediately rather than sleeping for
            # a moment that has gone, which is how the old code could miss
            # the overlap entirely
            return
        gen = getattr(self, "_punch_gen", {}).get(peer_id, 0)
        self.log("waiting %.1fs for the coordinated start" % remaining)
        self.status("等待同步起跑")
        # We are idle for `remaining` anyway, so spend part of it making
        # the anchor the peer will scan around as fresh as possible. See
        # _refresh_punch_anchor: a stale anchor is an error measured in
        # thousands of ports, not in window widths.
        try:
            self._refresh_punch_anchor(peer_id, min(remaining * 0.6, 1.2))
        except Exception:
            pass
        while time.monotonic() < deadline:
            if self._stop.is_set():
                return
            # a newer start_punch arrived: re-read the deadline instead of
            # finishing against the one we started with
            if getattr(self, "_punch_gen", {}).get(peer_id, 0) != gen:
                recv_at = getattr(self, "_punch_recv_at", {}).get(peer_id)
                start_in = getattr(self, "_punch_start_in", {}).get(peer_id, 0)
                if recv_at is None or start_in <= 0:
                    return
                deadline = recv_at + min(start_in, PUNCH_START_MAX_WAIT_S)
                gen = getattr(self, "_punch_gen", {}).get(peer_id, 0)
            time.sleep(min(0.05, max(0.0, deadline - time.monotonic())))

    def _run_multi_socket(self, ch, peer_id, cand, plan, budget,
                          anchor_age_s=None):
        """Open a bank of sockets and punch. True if the channel is up."""
        hit = self._try_multi_socket_punch(peer_id, cand, plan,
                                           anchor_age_s=anchor_age_s)
        if not hit:
            return False
        sock, addr = hit
        # sock is None when the reply landed on the punch socket itself --
        # the hole is open there, so keep using it under the hub rather
        # than moving to a socket we do not own.
        if sock is None:
            if self.udp is None:
                return False
            t2 = UdpTunnel(self.udp, addr, self.log, hub=self.hub)
            owned = False
        else:
            t2 = UdpTunnel(sock, addr, self.log, hub=None, owns_socket=True)
            owned = True
        ch.tunnel = t2
        try:
            # The hole is already half open: we have heard the peer on this
            # exact socket, so a full punch timeout is the wrong thing to
            # spend. A short handshake is enough to exchange HELLO/ACK --
            # and waiting longer risks the peer's socket array expiring
            # before we finish, which turns a hit into a miss.
            t2.connect(min(budget, HANDSHAKE_AFTER_HIT_S))
            ch.send_fn = t2.send
            self._note_direct_success(peer_id)
            self.log("direct UDP tunnel ready (multi-socket %s, %s), peer %s"
                     % (plan, "own socket" if owned else "punch socket",
                        t2.remote))
            self._spawn(lambda: self._tunnel_reader(ch, t2))
            self._start_forward(ch)
            return True
        except Exception as e:
            self.log("multi-socket punch %s did not settle: %s" % (plan, e))
            try:
                t2.close()
            except Exception:
                pass
            ch.tunnel = None
        return False

    def _multi_socket_first(self, peer_id, plan, cand=None):
        """Should the socket array run BEFORE the ordinary punch?

        Only when we actually know somebody here is behind a symmetric NAT.
        Running it first for everyone meant every ordinary connection -- LAN,
        loopback, two machines on one router -- paid for a barrage it did
        not need. Running it never (after the plain attempt) is worse in the
        case that matters: a confirmed NAT4 peer then sits through a full
        punch timeout on a mechanism that cannot work for it, before the one
        that can.

        "unknown" is deliberately NOT enough: that is the state for every
        same-network peer too, and it is what keeps the common case fast.
        """
        if plan == METHOD_OPENP2P:
            # An openp2p handshake applies, so it must run -- including
            # for cone x cone, which METHOD_CONE would otherwise skip.
            #
            # This is the check that kept the ported handshakes from ever
            # executing: punch_plan used to be decided entirely by the
            # home-grown policy, and its two common verdicts (CONE: "no
            # array needed", NONE: "no mechanism") both bypassed run_punch
            # entirely. The policy now returns METHOD_OPENP2P whenever one
            # of the three handshakes applies, and this is what makes
            # "openp2p first" true on the real path rather than only in
            # the unit tests.
            pass
        elif plan in (METHOD_CONE, METHOD_NONE):
            return False
        # There is no NAT to punch through on loopback or link-local, and
        # none on a LAN candidate either. Spraying there is pure cost: it
        # delays the connection that was about to succeed anyway.
        if cand is not None:
            ip = str(cand[0])
            if (ip.startswith("127.") or ip == "::1"
                    or ip.lower().startswith("fe80:")
                    or ip.startswith("169.254.")):
                return False
        peer_sub = self._peer_subtype(peer_id)
        if peer_sub in (NAT_SUB_EASY_INC, NAT_SUB_EASY_DEC, NAT_SUB_HARD):
            return True
        if getattr(self, "_peer_nat", {}).get(peer_id) == NAT_SYMMETRIC:
            return True
        mine = getattr(self, "nat_subtype", NAT_SUB_UNKNOWN)
        return mine in (NAT_SUB_EASY_INC, NAT_SUB_EASY_DEC, NAT_SUB_HARD)

    def _close_v6(self, tunnel, sock):
        """Tear down a v6 attempt. The thread may still be inside it."""
        if tunnel is not None:
            try:
                tunnel.close()
            except Exception:
                pass
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass

    def _try_ipv6(self, peer_id, cand, budget):
        """Connect straight to a peer's global IPv6 address.

        A separate AF_INET6 socket, not the v4 punch socket: the hub owns
        that one and it cannot carry v6 traffic at all. No alt ports and no
        spray -- there is no NAT to predict, so there is nothing to guess.

        Returns None unless the tunnel is actually CONNECTED.

        Returning the tunnel whenever connect() returned -- regardless of
        whether it connected -- is what stalled a real session: the caller
        installed it as a working link, the v4 candidate queued behind it
        was never tried, and for 51 seconds the only log line was

            === direct #1: [240e:...]:30000 (IPv6, no NAT) ===

        On a host whose inbound v6 is firewalled -- the ordinary home
        router default, and "has a global address" says nothing about it --
        connect() simply runs to its deadline and returns. That is the
        common case, not an error path, so it has to be reported as what it
        is.
        """
        sock = None
        try:
            sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            # V6ONLY is mandatory here, not an optimisation.
            #
            # Linux defaults to net.ipv6.bindv6only=0, so a wildcard
            # AF_INET6 bind on port 30000 collides with the v4 socket
            # already holding 0.0.0.0:30000 -- errno 98, every time. It
            # "works" on Windows/macOS (they default to v6only=1), which is
            # exactly why this shipped: the bug only shows up on the
            # platform every server actually runs.
            try:
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            except Exception:
                # Not OSError: a socket that is not v6-capable can raise
                # anything, and refusing to set the option must not stop us
                # from trying -- it only risks a port collision.
                pass
            sock.bind(("", self.udp_port or 0))
        except OSError as e:
            self.log("IPv6 socket unavailable: %s" % e)
            self._close_v6(None, sock)
            return None

        # Everything from here, including the tunnel construction, happens
        # on a thread the caller abandons on a wall clock. Not because
        # connect() is untrustworthy in principle, but because a real
        # session sat on this line for 51s while the v4 address -- the one
        # that could have worked -- waited behind it.
        box = {}
        started = time.monotonic()

        def _go():
            try:
                t = UdpTunnel(sock, (cand[0], cand[1]), self.log,
                              hub=None, owns_socket=True)
                box["t"] = t
                t.connect(budget)
            except Exception as exc:
                box["exc"] = exc

        th = threading.Thread(target=_go, daemon=True)
        th.start()
        th.join(budget + IPV6_CONNECT_SLACK_S)
        t = box.get("t")

        if th.is_alive():
            self.log("IPv6 to [%s]:%d exceeded %.0fs; abandoning it"
                     % (cand[0], cand[1], budget + IPV6_CONNECT_SLACK_S))
            self._close_v6(t, sock)
            return None
        if box.get("exc") is not None:
            self.log("IPv6 direct failed: %s" % box["exc"])
            self._close_v6(t, sock)
            return None
        if t is None:
            self.log("IPv6 to [%s]:%d could not be started" % (cand[0],
                                                               cand[1]))
            self._close_v6(None, sock)
            return None
        if not getattr(t, "connected", False):
            # Ran to its deadline and never connected. Firewalled inbound
            # v6 looks exactly like this, and it is the normal case.
            self.log("IPv6 [%s]:%d did not answer in %.0fs -- inbound IPv6 "
                     "is blocked on many home routers even when outbound "
                     "works. Trying IPv4 next."
                     % (cand[0], cand[1], time.monotonic() - started))
            self._close_v6(t, sock)
            return None
        return t

    def _peer_subtype(self, peer_id):
        """The peer's refined NAT subtype, or a guess from its coarse type.

        A peer running an older build only reports cone/symmetric. Downgrading
        "symmetric" to "hard" would abandon exactly the users we are trying
        to reach, so unknown is treated as *predictable*: we try the window
        first and fall back. Being wrong here costs a few hundred packets;
        being pessimistic costs the whole direct connection.
        """
        sub = getattr(self, "_peer_sub", {}).get(peer_id)
        if sub:
            return sub
        nat = getattr(self, "_peer_nat", {}).get(peer_id)
        if nat == NAT_SYMMETRIC:
            return NAT_SUB_EASY_INC      # direction unknown, try anyway
        if nat == NAT_CONE:
            return NAT_SUB_CONE
        return NAT_SUB_UNKNOWN

    def _peer_per_ip_pool(self, peer_id):
        """Does the PEER allocate a separate port region per destination IP?

        Published by the peer alongside its subtype (see common.stun_probe2's
        `extra`). When it does, a contiguous window around its published
        port is aimed at the wrong region, and the scan has to spend part
        of every round on random ports instead.

        Unknown is treated as "no": the window is right for the ordinary
        sequential allocator, and only a measured gap that no amount of
        background traffic can explain flags it.
        """
        return bool(getattr(self, "_peer_per_ip", {}).get(peer_id, False))

    def _peer_filtering(self, peer_id):
        """The peer's RFC 5780 filtering behaviour."""
        return (getattr(self, "_peer_filter", {}).get(peer_id)
                or FILTER_UNKNOWN)

    def _my_filtering(self):
        """The verdict the policy acts on -- reconciled, not raw.

        nat_filter is what the STUN tests concluded, which a server that
        ignores CHANGE-REQUEST can get confidently wrong. The inbound probe
        is the stronger evidence, so the two are combined; see
        natpunch.effective_filter.
        """
        raw = getattr(self, "nat_filter", FILTER_UNKNOWN) or FILTER_UNKNOWN
        try:
            return effective_filter(raw, getattr(self, "_inbound_state",
                                                 "unknown"))
        except NameError:
            return raw

    def _on_nat_changed(self):
        """Our own endpoint or NAT type moved: give direct another chance.

        Two things have to happen, and the second is the one that is easy
        to forget.

        Peers learn the new address from publish_offer, so that part is
        automatic. But every failure recorded against the OLD address --
        the backoff counter, and worse, the blacklist -- is still sitting
        there, and a blacklist entry is measured in tens of seconds of
        doing nothing. Clearing them is not generosity: those failures were
        evidence about a network we are no longer on.
        """
        try:
            self._direct_fails = {}
        except Exception:
            pass
        try:
            self._direct_blacklist = {}
        except Exception:
            pass
        self.log("[NAT] cleared direct-connection backoff after the change")

    def _peer_tcp_port(self, peer_id):
        return getattr(self, "_peer_tcp", {}).get(peer_id, 0)

    def _try_tcp_punch(self, peer_id, cand, budget=None,
                       after_udp_failure=False):
        """TCP simultaneous open, as a last attempt before relaying.

        Why it is last: on a network where UDP works at all, UDP punching
        is faster to establish and better suited to the traffic. TCP is the
        path for when UDP is blocked outright -- the case where the
        alternative is relaying forever.

        Both ends bind a fixed local port and dial each other; the SYNs
        cross. See client/tcppunch.py.
        """
        if not tcp_enabled():
            return False
        peer_port = self._peer_tcp_port(peer_id)
        if not peer_port:
            self.log("[TCP] peer did not publish a TCP port; skipping")
            return False
        ip = str(cand[0])
        if is_ipv6(ip):
            return False                 # v4 only for now
        local = getattr(self, "tcp_punch_port", TCP_PUNCH_PORT)
        # A simultaneous open only crosses if each side's PUBLIC port is
        # the port the other dials -- and what we publish to the peer is
        # our LOCAL port. So it needs port preservation on both ends, or a
        # real mapped port from UPnP.
        #
        # WHETHER THE PORT IS PRESERVED IS MEASURED, NOT INFERRED.
        #
        # This used to be decided from the UDP mapping:
        #
        #   [TCP] skipped: this NAT does not preserve ports (local 30000
        #         maps to public 48520) and there is no UPnP mapping, so a
        #         simultaneous open cannot cross
        #
        # 48520 is the UDP mapping, and the two protocols are allocated
        # separately -- a NAT that hands out a fresh UDP port per
        # destination very often gives TCP the port the client asked for.
        # So the check disabled the one mechanism that survives a symmetric
        # UDP NAT on exactly the networks that need it, and it did so
        # silently, before a single SYN was sent. See
        # SignalingMixin._probe_tcp_preservation: the server reports the
        # source port it saw on a connection we opened from this port.
        try:
            preserved = self.tcp_preserves_port()
        except AttributeError:
            # An older/stubbed session without the signalling mixin: no
            # measurement is available, which must not disable the path.
            preserved = None
        if preserved is None and not getattr(self, "_upnp_tcp_port", 0):
            # Not measured: an older server, or a punch port that was busy
            # at startup. Do not disable the path on absence of evidence --
            # but do not spend 8s per round on it either. It runs only when
            # UDP has no mechanism at all, i.e. when the alternative is
            # relaying forever.
            if self._punch_plan_for(peer_id) != METHOD_NONE \
                    and not after_udp_failure:
                # Skipped only while UDP is still fresh.
                #
                # Real log, both ends of a pair:
                #
                #   direct #1 ... failed: udp punch timeout
                #   [TCP] skipped: port preservation is unmeasured (the
                #         server does not support tcp_probe ...) and UDP
                #         still has a mechanism for this pair
                #
                # and then straight to the relay. "UDP still has a
                # mechanism" is a statement about the PLAN, not about what
                # just happened -- the mechanism it names had already spent
                # a full round sending 11,000 packets and hearing nothing.
                #
                # OpenP2P makes TCP the path for exactly this shape
                # (connectUnderlayTCPSymmetric runs when either side is
                # symmetric), and being wrong here costs one 8s round
                # against relaying forever.
                self.log("[TCP] skipped: port preservation is unmeasured "
                         "(the server does not support tcp_probe, or the "
                         "port was busy at startup) and UDP still has a "
                         "mechanism for this pair")
                return False
            self.log("[TCP] port preservation unmeasured; trying anyway "
                     "because UDP has no mechanism for this pair")
        elif preserved is False and not getattr(self, "_upnp_tcp_port", 0):
            self.log("[TCP] skipped: the public port for TCP %s is not the "
                     "port we bound (measured by the server), and there is "
                     "no UPnP mapping, so the SYNs cannot meet" % local)
            return False
        self.log("[TCP] trying simultaneous open with %s:%s (from local %s)"
                 % (ip, peer_port, local))
        t = tcp_simultaneous_open(local, ip, peer_port,
                                 timeout=TCP_PUNCH_TIMEOUT_S, log=self.log)
        if t is None:
            self.log("[TCP] simultaneous open did not cross")
            return False
        ch = self._new_channel(peer_id, "direct-tcp")
        ch.tunnel = t
        ch.send_fn = t.send
        self._note_direct_success(peer_id)
        self.log("direct TCP tunnel ready, peer endpoint %s" % t.remote)
        self._spawn(lambda: self._tunnel_reader(ch, t))
        self._start_forward(ch)
        return True

    def _punch_plan_for(self, peer_id):
        mine = getattr(self, "nat_subtype", NAT_SUB_UNKNOWN)
        plan = punch_plan(mine, self._peer_subtype(peer_id),
                          self.my_id, peer_id,
                          my_filter=self._my_filtering(),
                          peer_filter=self._peer_filtering(peer_id))
        if mine == NAT_SUB_UNKNOWN:
            # Never measured ourselves -- either no STUN answered, or only
            # one IP was reachable to ask.
            if plan == METHOD_NONE:
                # "No mechanism" is not a verdict we are entitled to give
                # about a NAT we never characterised.
                return METHOD_CONE
            if plan == METHOD_CONE:
                # plain cone-to-cone is exactly the wrong default here: an
                # unmeasured NAT is more likely symmetric than a tidy cone,
                # and cone_to_cone means one socket and one guess. Escalate
                # to the multi-socket path, which costs a few hundred local
                # packets and covers both cases.
                return METHOD_SYM_TO_CONE
        return plan

    def _try_multi_socket_punch(self, peer_id, cand, plan,
                                anchor_age_s=None):
        """Open a socket array and punch. Returns (sock, addr) or None."""
        try:
            # Who has to speak first is a question about FILTERING, not
            # about ids. The stricter end must open the door before the
            # other end's packets can get in at all; picking the leader by
            # id alone left a coin flip deciding whether a perfectly
            # punchable pair ever exchanged a packet.
            lead = must_open_first(self._my_filtering(),
                                   self._peer_filtering(peer_id),
                                   self.my_id, peer_id)
            # Only spend PART of the punch budget here. The multi-socket
            # attempt is an extra chance, not the whole attempt -- if it
            # fails we still want time left for the ordinary single-socket
            # punch rather than handing the peer straight to the relay.
            budget = (AUTO_PUNCH_TIMEOUT_S if self.mode == MODE_AUTO
                      else PUNCH_TIMEOUT_S)
            # sym_to_cone needs the peer to walk a window of our ports, and
            # that only works if we are still there when it gets to ours.
            # Six seconds was not enough: the peer burns its own budget on
            # its single-socket attempt first, so by the time it starts
            # scanning we have already closed our array. Give it the same
            # floor both_easy gets.
            timeout = max(2.0, min(8.0, budget * 0.5))
            if plan == METHOD_SYM_TO_CONE:
                timeout = max(timeout, SYM_TO_CONE_SPRAY_S)
            return run_punch(cand[0], int(cand[1]),
                             self._peer_subtype(peer_id),
                             getattr(self, "nat_subtype", NAT_SUB_UNKNOWN),
                             plan, log=self.log, lead=lead, hub=self.hub,
                             timeout=timeout,
                             my_filter=self._my_filtering(),
                             peer_filter=self._peer_filtering(peer_id),
                             anchor_age_s=anchor_age_s,
                             per_ip_pool=self._peer_per_ip_pool(peer_id))
        except Exception as e:
            self.log("multi-socket punch failed: %s: %s"
                     % (type(e).__name__, e))
            return None

    def _candidate_ports(self, peer_id, cand):
        """Ports to try for one candidate.

        Uses the PEER's allocation step, not ours -- two NATs of different
        models allocate differently, so our own number is meaningless here.

        The spray is capped and jittered. An uncapped burst at a stale
        address is indistinguishable from a port scan of whoever now owns
        that IP, so we keep the total small and vary the start slightly.
        """
        ip, port = cand[0], int(cand[1])
        nat = self._peer_nat.get(peer_id) or self.nat_type
        # Only a CONFIRMED cone NAT gets the single-port treatment.
        #
        # This used to be `if nat != NAT_SYMMETRIC`, which silently demoted
        # "unknown" to a single guess. Unknown is the common case in exactly
        # the networks this project exists for: one built-in STUN on one IP
        # answers, so there is no second destination to compare against and
        # the type stays unknown -- and an unmeasured NAT is far more likely
        # to be symmetric than to be a well-behaved cone. Demoting it threw
        # away prediction for the users who most need it.
        if nat == NAT_CONE:
            return [port]

        # Prefer the peer's own step; fall back to ours only if theirs is
        # unknown (an old server that does not forward it).
        delta = self._peer_delta.get(peer_id)
        if not delta:
            delta = self.nat_delta
        if not delta:
            delta = 1       # unknown direction, but a window is still worth it

        # SYM_SPRAY_PORTS is the TOTAL number of targets, base included.
        # A confirmed symmetric NAT earns the full window; an unmeasured one
        # gets a narrower probe, because we are guessing either way.
        budget = (SYM_SPRAY_PORTS if nat == NAT_SYMMETRIC
                  else UNKNOWN_SPRAY_PORTS)
        count = max(1, min(budget, SPRAY_BUDGET) - 1)
        # contiguous, not base+k*delta, and already shuffled -- see
        # natpunch.port_window for why the stride is 1 and not the delta
        ports = port_window(port, self._peer_subtype(peer_id), count)
        if JITTER_SPRAY and len(ports) > 2:
            # Rotate the START of the window, do not truncate it.
            #
            # Slicing [rand:] dropped up to 3 ports -- and it dropped them
            # from the FRONT, i.e. base+1..base+3, which on a sequential
            # allocator are the single most likely targets in the whole
            # list. The jitter was deleting the best guesses. Rotating
            # changes the order two peers march in without losing any.
            k = random.randint(0, min(JITTER_MAX_SKIP, len(ports) - 1))
            if k:
                ports = ports[k:] + ports[:k]
        return [port] + ports

    def _direct_loop(self, peer_id, cands):
        """Try every candidate in order, and keep retrying forever.

        Candidates are LAN-then-public (see order_candidates). Trying all of
        them matters: a candidate that "should" work can still be blocked,
        and one that looks odd may be the only reachable path.
        """
        attempt = 0
        ch = self._new_channel(peer_id, "direct UDP")
        idx = 0
        round_start = time.monotonic()
        last_cand = None
        try:
            while not self._stop.is_set() and ch.send_fn is None:
                # Re-read the candidate list EVERY round.
                #
                # It used to be captured once by the caller, so a peer that
                # re-published was punched at its STALE address for the rest
                # of the session. Seen in the wild: the server kept sending
                # start_punch with a fresh public address while the client
                # hammered an old one -- different IP entirely -- and the
                # new one was never tried because the loop was holding a
                # snapshot from before it arrived.
                fresh = self._peer_candidates.get(peer_id)
                if fresh:
                    if fresh != cands:
                        # the peer re-published: start from the top so the
                        # new address is not left behind an index that
                        # pointed into the old list
                        idx = 0
                    cands = fresh
                # Never restart on an address we already proved unusable.
                # The list is re-read every round and idx resets to 0 on
                # every change, so a v6 candidate that fails comes straight
                # back to the top -- with the v4 address queued behind it,
                # forever.
                if self._v6_failed:
                    cands = [c for c in cands
                             if not (is_ipv6(c[0]) and c[0] in self._v6_failed)]
                    if not cands:
                        break
                if not cands:
                    break
                # Re-checked EVERY round, not just on entry.
                #
                # Checking once before the loop meant the blacklist was a
                # single 60s pause followed by a return to the 3s retry
                # cadence: the loop came straight back round and started
                # again from zero. The point of a blacklist is that the
                # peer stays parked until it expires.
                left = self._direct_blacklisted(peer_id)
                if left > 0 and self.mode == MODE_DIRECT:
                    self.log("direct to %s is blacklisted for %.0fs more"
                             % (peer_id, left))
                    self.status("直连暂停中（%.0fs），可切换中转" % left)
                    self._sleep_or_stop(left)
                    continue

                pos = idx % len(cands)
                cand = cands[pos]
                idx += 1

                # A wall clock on the ROUND, not just on each candidate.
                #
                # One candidate that never returns is enough to hide every
                # candidate behind it for the rest of the session. Seen in a
                # real log: the loop printed the IPv6 attempt and then
                # nothing at all for 51 seconds while the IPv4 address --
                # tried second, and the only one with a chance -- was never
                # reached. Per-candidate timeouts are not enough; something
                # has to notice that the round itself has stopped making
                # progress.
                #
                # On expiry, drop the candidate that was being worked on AND
                # every sibling of the same kind. Two IPv6 addresses are
                # usually one host's stable and temporary address, so
                # blacklisting only the first just repeats the same stall.
                now = time.monotonic()
                if now - round_start > ROUND_WALL_CLOCK_S \
                        and last_cand is not None:
                    self.log("candidate [%s]:%d has not finished after "
                             "%.0fs; skipping it and its siblings"
                             % (last_cand[0], last_cand[1],
                                now - round_start))
                    if is_ipv6(last_cand[0]):
                        for c in cands:
                            if is_ipv6(c[0]):
                                self._v6_failed.add(c[0])
                    round_start = now
                    continue
                last_cand = cand
                # order_candidates always appends the public endpoint LAST,
                # so anything before it is a LAN candidate
                kind = "public" if pos == len(cands) - 1 else "LAN"
                # Only a public IPv4 attempt counts -- see is_round_candidate.
                is_public = self.is_round_candidate(cand[0])

                # --- IPv6: no NAT, so no punching -----------------------
                #
                # If both ends have a global v6 address this is a plain
                # connection, and every bit of the machinery below is
                # unnecessary. Try it before anything else.
                if is_ipv6(cand[0]) and not self._have_ipv6():
                    # We have no global v6 address of our own, so there is
                    # no way out to theirs -- yet this was tried anyway, and
                    # it STALLED: from a real log, the host sat on
                    # "direct #1: [240e:...]:30000 (IPv6, no NAT)" for the
                    # rest of the session while its peer punched the v4
                    # address alone and reported "no packet from <peer>
                    # reached any of our mappings".
                    #
                    # Publishing a v6 address is not evidence that we have
                    # one: the peer's list is what we are reading here, and
                    # a v6-capable peer happily offers an address to a
                    # v4-only one.
                    self.log("=== direct #%d: skipping [%s]:%d (IPv6) -- "
                             "this host has no global IPv6 address ==="
                             % (attempt + 1, cand[0], cand[1]))
                    self._v6_failed.add(cand[0])
                    continue

                if is_ipv6(cand[0]):
                    kind = "IPv6"
                    self.log("=== direct #%d: [%s]:%d (IPv6, no NAT) ==="
                             % (attempt + 1, cand[0], cand[1]))
                    # Short leash for v6. No NAT means it either answers
                    # straight away or never -- and home routers very
                    # commonly allow v6 OUT but block it IN, so "has a
                    # global address" is not the same as "accepts inbound".
                    # Giving it the full budget just made every such peer
                    # wait 10s to be told no, with the v4 path queued
                    # behind it.
                    t6 = self._try_ipv6(peer_id, cand,
                                        min(budget, IPV6_PUNCH_TIMEOUT_S))
                    if t6 is not None:
                        ch.tunnel = t6
                        ch.send_fn = t6.send
                        self._note_direct_success(peer_id)
                        self.log("direct IPv6 tunnel ready, peer %s"
                                 % t6.remote)
                        self._spawn(lambda: self._tunnel_reader(ch, t6))
                        self._start_forward(ch)
                        return
                    self.log("direct #%d via IPv6 failed, falling back"
                             % (attempt + 1))
                    self._v6_failed.add(cand[0])
                    # When IPv6 is the ONLY candidate there is no punch to
                    # fall back to, so this failure IS the round. Counting
                    # it is what lets auto mode reach "give up and relay";
                    # without it a peer published as a bare v6 address spun
                    # in "connecting" forever -- a worse failure than
                    # failing outright.
                    if all(is_ipv6(c[0]) for c in cands):
                        attempt += 1
                        action, wait = self._on_round_failed(peer_id, attempt)
                        if action == "relay":
                            self._start_server_relay(peer_id)
                            return
                        if action == "blacklist":
                            self.status("直连反复失败，暂停 %d 秒；可用中转模式"
                                        % int(wait))
                        self._sleep_or_stop(wait)
                    continue

                # Count the round HERE, where a punch is actually started --
                # not before the cheap candidates (LAN/IPv6) bail out with
                # `continue`, which inflated the counter and made auto mode
                # give up on the public address after a single real try.
                if is_public:
                    attempt += 1

                ports = self._candidate_ports(peer_id, cand)
                self.log("=== direct #%d: %s:%d (%s, %d port(s)) ==="
                         % (attempt, cand[0], cand[1], kind, len(ports)))
                self.status("direct punch #%d (%s)" % (attempt, kind))



                # NOTE: deliberately no STUN refresh in here.
                #
                # It used to re-probe every round, which is actively
                # harmful: on a symmetric NAT every new destination consumes
                # an allocation slot, so probing shifts the very mapping the
                # peer is trying to hit. Any unrelated UDP flow the machine
                # opens (QUIC, DNS, a game) shifts it too, which is why the
                # prediction is best treated as a hint and not chased.

                # auto must not burn 2 x 25s before giving the user a
                # working connection; direct mode can afford to be patient
                # because it retries forever anyway
                budget = (AUTO_PUNCH_TIMEOUT_S if self.mode == MODE_AUTO
                          else PUNCH_TIMEOUT_S)
                # A LAN candidate either answers at once or never: the peer
                # is on the same wire, so there is no NAT to punch and no
                # reason to wait 10-25s. Giving LAN the full budget was
                # spending most of the first attempt on an address that
                # cannot work, before even reaching the public candidate.
                if kind == "LAN":
                    budget = min(budget, LAN_PUNCH_TIMEOUT_S)

                # --- NAT4: decide HOW before trying ------------------------
                #
                # One socket is one target. If either side is a symmetric
                # NAT the peer cannot know which port we will be on, so a
                # single-socket spray mostly just burns the punch budget.
                # The policy picks a real algorithm (open many sockets /
                # walk a contiguous window / random collision) or says
                # "no mechanism -- relay now" instead of failing slowly.
                plan = self._punch_plan_for(peer_id)

                # Refresh the anchor BEFORE the coordinated wait, not
                # after it.
                #
                # It used to sit after, so the refreshed port was measured
                # once both ends were already spraying around the value
                # from start_punch -- which is the value the peer was
                # holding, and it does not change just because we
                # re-measured. Refreshing during the wait at least gives
                # the server a chance to re-issue start_punch with the
                # fresh address before the first packet goes out.
                # Wait for the coordinated start -- but only here, on the
                # candidate that actually needs it. See _await_punch_start.
                self._await_punch_start(peer_id, cand, plan)

                # Confirmed NAT4 somewhere: go straight to the mechanism
                # that can work, instead of spending the whole budget on
                # the one that cannot.
                if self._multi_socket_first(peer_id, plan, cand):
                    # A scan is only as good as the anchor it scans
                    # around. See _refresh_anchor_if_stale: on a NAT that
                    # moves ~73 ports/second, a two-minute-old anchor is
                    # off by thousands of ports, and widening the window
                    # cannot make up for that.
                    self._refresh_anchor_if_stale(peer_id)
                    # How stale is the port we are about to scan around?
                    # Passed down so the failure line can say "STALE:
                    # measured 50s ago" instead of just "no packet from
                    # the peer", which points at the peer for what is
                    # usually OUR stale measurement.
                    # Age of the PEER's anchor, not ours.
                    #
                    # The scan is built around the port the PEER published,
                    # so the number that matters is how long ago we heard
                    # it. This used to report `now - our own last publish`,
                    # which is a different clock entirely -- it printed
                    # "STALE: measured 34s ago" next to the peer's port for
                    # a reason that had nothing to do with that port, and
                    # sent the reading of the log the wrong way.
                    # MONOTONIC, matching what _punch_recv_at stores.
                    #
                    # It was time.time() - monotonic, i.e. epoch minus
                    # uptime, which printed "STALE: measured 1789726890s
                    # ago" in a real log. A wrong unit is worse than no
                    # number: that line is what tells you whether the
                    # anchor or the scan is to blame.
                    _recv = getattr(self, "_punch_recv_at", None) or {}
                    _t = _recv.get(peer_id)
                    _age = (time.monotonic() - _t) if _t else None
                    self.log("=== direct #%d: multi-socket %s ==="
                             % (attempt, plan))
                    if self._run_multi_socket(ch, peer_id, cand, plan, budget,
                                              anchor_age_s=_age):
                        return
                if plan == METHOD_NONE:
                    # Say what actually happens. This used to log "going
                    # straight to relay" and then fall through into a full
                    # single-socket punch, so a 25s attempt was spent on
                    # the one combination the policy had already given up
                    # on -- and the log claimed the opposite.
                    if self.mode == MODE_AUTO:
                        self.log("=== no UDP mechanism for this pair "
                                 "(filtering too strict) -> relaying ===")
                        self._start_server_relay(peer_id)
                        return
                    # DIRECT: the user asked for direct, so still try --
                    # but briefly. There is no mechanism, so a long budget
                    # only delays them finding out.
                    self.log("=== no UDP mechanism for this pair "
                             "(filtering too strict); trying anyway "
                             "because direct mode was requested ===")
                    self.status("对称型 NAT 无法直连，请用中转")
                    budget = min(budget, NO_MECHANISM_TIMEOUT_S)
                # The ordinary single-socket punch goes FIRST, even when
                # the policy says a bigger hammer exists.
                #
                # Running the socket array first was measurably worse: it
                # burns several seconds of the punch budget on a path that
                # only helps when the peer's port is genuinely unknown, and
                # it made every ordinary LAN/loopback connection slower for
                # no gain. The array is a fallback for "the simple way did
                # not work", which is exactly when it is worth paying for.
                t = UdpTunnel(self.udp, (cand[0], ports[0]), self.log,
                              hub=self.hub, alt_ports=ports[1:])
                ch.tunnel = t
                try:
                    t.connect(budget)
                    ch.send_fn = t.send
                    self._note_direct_success(peer_id)
                    self.log("direct UDP tunnel ready, peer endpoint %s" % t.remote)
                    self._spawn(lambda: self._tunnel_reader(ch, t))
                    self._start_forward(ch)
                    return
                except Exception as e:
                    self.log("direct #%d to %s:%s failed: %s"
                             % (attempt, cand[0], ports[0], e))
                    if self.hub:
                        self.hub.unregister(t)
                    ch.tunnel = None

                    # Second chance: the single-socket spray only reaches
                    # the port we were told about, which on a symmetric NAT
                    # is never the one the peer is using. Open a bank of
                    # sockets so the peer has many targets to hit, or walk
                    # a contiguous window around the published port.
                    # the plain attempt failed -- now it is worth the
                    # barrage, because the cheap answer did not work
                    if (plan not in (METHOD_CONE, METHOD_NONE)
                            and not self._multi_socket_first(peer_id, plan,
                                                             cand)):
                        if self._run_multi_socket(ch, peer_id, cand, plan,
                                                  budget):
                            return

                if not is_public:
                    # a LAN candidate failing is not a round: trying the
                    # next candidate is the right response, and charging it
                    # to the failure counter would blacklist a peer whose
                    # public address was never even attempted
                    continue

                # First round failed: put the link we set aside BACK now,
                # rather than at the end of the loop.
                #
                # make-before-break keeps the old channel running, but it
                # is parked outside `self.channels` while we try -- and
                # anything looking for a link (a player reconnecting to the
                # Minecraft port) waits and is then refused. Waiting for the
                # whole loop to finish meant ~20s of that: two 10s punch
                # budgets plus backoff. Restore after the first failure and
                # let the remaining retries happen with a working link in
                # place, which is the state we promised anyway.
                if attempt == 1:
                    self._restore_replaced_link(peer_id)
                    # TCP simultaneous open, once, after the first full
                    # UDP round has failed.
                    #
                    # After the first round rather than after every one:
                    # this is a different path, not a stronger version of
                    # the same one, so it is either going to cross or not.
                    # Retrying it every round would spend the whole budget
                    # on a second UDP-shaped attempt while adding nothing.
                    #
                    # And before giving up entirely, because the whole point
                    # is to avoid relaying on networks where UDP is blocked.
                    try:
                        if self._try_tcp_punch(peer_id, cand,
                                               after_udp_failure=True):
                            return
                    except Exception as e:
                        self.log("[TCP] punch error: %s" % e)

                    # Ask the server to re-issue start_punch to BOTH ends.
                    #
                    # A hole needs traffic from both sides, so if the peer
                    # is not sending at all -- it missed the first
                    # start_punch, gave up early, or has already fallen
                    # back to relaying -- nothing we do here can open one.
                    # Re-coordinating makes the peer tear down and try
                    # again on a shared start, which is the only way to
                    # recover that case without asking the user anything.
                    self._request_punch_coordination(peer_id)

                # One round = one failed attempt at the public endpoint.
                action, wait = self._on_round_failed(peer_id, attempt)
                if action == "relay":
                    self._start_server_relay(peer_id)
                    return
                if action == "blacklist":
                    self.status("直连反复失败，暂停 %d 秒；可用中转模式"
                                % int(wait))
                    self._sleep_or_stop(wait)
                    continue
                if self.mode == MODE_DIRECT:
                    self.status("direct failed, retry in %ds (#%d)"
                                % (wait, attempt + 1))
                self._sleep_or_stop(wait)
        finally:
            # Only remove OUR channel. A blanket pop(peer_id) could delete
            # a relay channel that _start_server_relay installed after we
            # gave up -- tearing down the working fallback we just built.
            if ch.send_fn is None:
                with self._chan_lock:
                    if self.channels.get(peer_id) is ch:
                        self.channels.pop(peer_id, None)
                # We never got a link, so the one we set aside is still the
                # best one we have. Put it back rather than leaving the peer
                # with nothing.
                self._restore_replaced_link(peer_id)
            # free the slot so a later start_punch can start a real attempt
            self._end_direct_loop(peer_id)

    def _on_round_failed(self, peer_id, attempt):
        """One full round of candidates failed. Returns (action, seconds).

        action is "retry" (sleep `seconds`), "blacklist" (sleep `seconds`,
        then start over) or "relay" (give up on direct, use the server).

        Retrying an unreachable address every few seconds forever is not
        persistence, it is a loop with no exit: the user watches a spinner
        while a relay would have worked the whole time. So the delay grows,
        and after enough consecutive failures direct mode stops entirely.
        """
        fails = self._direct_fails.get(peer_id, 0) + 1
        self._direct_fails[peer_id] = fails

        if self.mode == MODE_AUTO and attempt >= AUTO_DIRECT_ATTEMPTS:
            self.log("auto: direct punch failed -> server relay")
            return "relay", 0

        if fails >= DIRECT_FAIL_LIMIT:
            self.log("direct to %s failed %d rounds in a row"
                     % (peer_id, fails))
            if self.mode == MODE_AUTO:
                # auto already has a fallback; use it instead of making the
                # user wait out a blacklist they did not ask for
                return "relay", 0
            self._direct_blacklist[peer_id] = (
                time.monotonic() + DIRECT_FAIL_BLACKLIST_S)
            self.log("direct: backing off %ds before retrying"
                     % DIRECT_FAIL_BLACKLIST_S)
            # drop the count so the next attempt starts from a clean slate
            self._direct_fails.pop(peer_id, None)
            return "blacklist", DIRECT_FAIL_BLACKLIST_S

        wait = DIRECT_BACKOFF_S[min(fails - 1, len(DIRECT_BACKOFF_S) - 1)]
        return "retry", min(wait, DIRECT_BACKOFF_MAX_S)

    def set_mode(self, mode):
        """Apply a new connection mode to a LIVE session.

        Changing the radio button used to do nothing but update the hint
        text: `self.mode` is only read when a link is being set up, so a
        user who was told "you can switch to relay" switched, and then
        watched the direct loop keep spinning with no way out short of
        disconnecting. So rebuild -- and rebuild every peer, not one.
        """
        if mode == self.mode:
            return
        self.mode = mode

        # EVERY peer, not just the last one.
        #
        # `target_id` is overwritten by each start_punch, so it holds only
        # the most recent peer. In the star topology that is the host's last
        # guest -- and the host is exactly the side that holds several
        # channels and is the one being told "you can switch to relay".
        # Rebuilding a single channel left the rest spinning in the direct
        # loop, which looks like the switch did nothing at all.
        with self._chan_lock:
            peers = [p for p in self.channels.keys() if p]
        if not peers:
            peers = [getattr(self, "target_id", "") or ""]
        for peer_id in peers:
            if not peer_id:
                continue
            self._rebuild_peer_link(peer_id, mode)

    def _teardown_peer(self, peer_id):
        """Make room for a new link WITHOUT breaking the old one.

        The old channel is moved aside and left RUNNING, not closed. Only
        once the new link is actually carrying traffic do we drop it -- and
        if the new one never comes up, the old one is put back.

        Breaking first was the obvious way to write this and it is wrong.
        The peer that asked for the re-punch is trying to improve things;
        the peer being asked did not consent, and tearing its channel down
        immediately costs it a hole-punch round plus backoff -- around 23s
        with no link at all -- for an attempt that may well fail anyway.
        Game traffic must not stop because someone else pressed a button.
        """
        pending = getattr(self, "_pending_replace", None)
        if pending is None:
            pending = self._pending_replace = {}
        with self._chan_lock:
            ch = self.channels.pop(peer_id, None)
        if ch is not None:
            pending[peer_id] = ch
        # a forced retry is a fresh start, not a continuation of failures
        self._note_direct_success(peer_id)
        self._punch_synced.discard(peer_id)

    def _drop_replaced_link(self, peer_id):
        """The new link is up: now it is safe to close the old one."""
        pending = getattr(self, "_pending_replace", None) or {}
        ch = pending.pop(peer_id, None)
        if ch is None:
            return
        try:
            if self.hub and ch.tunnel:
                self.hub.unregister(ch.tunnel)
            if ch.tunnel:
                ch.tunnel.close()
            ch.close()
        except Exception:
            pass

    def _restore_replaced_link(self, peer_id):
        """The new link did not come up: put the old one back."""
        pending = getattr(self, "_pending_replace", None) or {}
        ch = pending.pop(peer_id, None)
        if ch is None:
            return
        with self._chan_lock:
            cur = self.channels.get(peer_id)
            if cur is not None and not cur.stop.is_set():
                # something else already got there; do not clobber it
                try:
                    if self.hub and ch.tunnel:
                        self.hub.unregister(ch.tunnel)
                    if ch.tunnel:
                        ch.tunnel.close()
                    ch.close()
                except Exception:
                    pass
                return
            self.channels[peer_id] = ch

    def _rebuild_peer_link(self, peer_id, mode):
        """Tear down one peer's link and set it up again under `mode`."""
        self._note_direct_success(peer_id)
        with self._chan_lock:
            ch = self.channels.get(peer_id)
        if ch is not None:
            try:
                if self.hub and ch.tunnel:
                    self.hub.unregister(ch.tunnel)
                # Close the TUNNEL, not just the channel. ch.close() only
                # sets the stop event, and a tunnel from a multi-socket hit
                # or from IPv6 owns its socket -- so every mode switch
                # leaked a UDP port. The link-rebuild path closes it; this
                # one must too.
                if ch.tunnel:
                    ch.tunnel.close()
                ch.close()
            except Exception:
                pass
            with self._chan_lock:
                if self.channels.get(peer_id) is ch:
                    self.channels.pop(peer_id, None)

        if mode == MODE_RELAY or self.hub is None:
            self._start_server_relay(peer_id)
            return

        # Going (back) to direct: the coordinated start we already spent is
        # stale, and the server will not resend one just because we changed
        # a setting. Ask it to re-coordinate so both ends start together;
        # if it cannot, drop the stale sync state so we do not wait on a
        # deadline that has already passed.
        self._punch_synced.discard(peer_id)
        self._punch_start_in.pop(peer_id, None)
        self._punch_recv_at.pop(peer_id, None)
        self._request_punch_coordination(peer_id)

        # _start_direct, not a bare spawn: that skipped the per-peer
        # single-loop guard and started a SECOND concurrent punch for a
        # peer that already had one -- two 100-socket arrays spraying at
        # once, sharing one rate bucket and halving each other's coverage.
        # Log evidence: "[punch] both_easy_sym: 100 sockets, 901 ports"
        # twice, two seconds apart, for the same peer.
        ep = getattr(self, "target_addr", None)
        self._start_direct(peer_id, ep)

    def _request_punch_coordination(self, peer_id):
        """Ask the server to re-issue start_punch for this peer.

        A manual switch to direct has no coordination: both ends would
        spray on their own schedules. The server already knows how to send
        a matched pair with a shared startIn, so just ask for one -- but
        only when WE are the one who changed something.

        Answering a peer's `force` with another `force` is a feedback loop.
        Seen in a real log, one second apart:

            08:08:02  A -> punch_target(force)
            08:08:03  B <- start_punch(force)
            08:08:04  B -> punch_target(force)      <- answers a force
            08:08:04  A <- start_punch(force)

        Each side's answer re-triggers the other's, so both spend the whole
        session tearing down and re-punching instead of punching. The
        teardown is also not free: it drops the link the other end is
        using, so this loop is what turns a slow punch into no link at all.
        """
        seen = getattr(self, "_force_seen", None) or {}
        if time.time() - seen.get(peer_id, 0.0) < FORCE_ANSWER_QUIET_S:
            return
        try:
            self.send({"action": "punch_target", "targetId": peer_id,
                       "force": True})
        except Exception:
            pass

    @staticmethod
    def is_round_candidate(ip):
        """Does failing THIS candidate count as a failed round?

        Only a public IPv4 endpoint counts. LAN and IPv6 failures are cheap
        and expected, and letting them advance the counter meant
        AUTO_DIRECT_ATTEMPTS=2 gave the public candidate exactly ONE try
        before falling back to the relay. That is too early for NAT4, which
        often needs the second or third round: the first spray primes the
        mapping, the second gets through.

        Judging by the ADDRESS rather than by the slot is deliberate.
        "The last candidate is the public one" holds for the normal list,
        but order_candidates also produces a one-element list when the peer
        is only reachable over the LAN -- and charging a LAN miss as a
        failed hole punch burns the retry budget for nothing.
        """
        return is_public_ipv4(ip)

    def _note_direct_success(self, peer_id):
        """A direct link came up: forget the failures that led here."""
        self._direct_fails.pop(peer_id, None)
        self._direct_blacklist.pop(peer_id, None)

    def _sleep_or_stop(self, seconds):
        """Sleep in small slices so disconnect() is still responsive."""
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            if self._stop.is_set():
                return
            time.sleep(min(0.25, end - time.monotonic()))

    def _direct_blacklisted(self, peer_id):
        """Seconds left on this peer's blacklist, 0 if it may be tried."""
        until = self._direct_blacklist.get(peer_id)
        if not until:
            return 0.0
        left = until - time.monotonic()
        if left <= 0:
            self._direct_blacklist.pop(peer_id, None)
            return 0.0
        return left

    def _refresh_own_endpoint(self, force=False):
        """Re-run STUN and republish -- only while we have no public address.

        This used to be called from _direct_loop on every punch round, which
        was correctly removed (re-probing on a symmetric NAT burns an
        allocation slot and shifts the mapping the peer is aiming at). But
        no caller replaced it, so the method was dead and the client
        published whatever its very first discovery produced for the whole
        session -- including the link-local fallback.

        So it is now gated rather than periodic:
          * already have a public endpoint -> do nothing (probing would
            only move the mapping);
          * never got one -> ask again, because a server-supplied STUN that
            arrived late, or a network that came up slowly, is exactly the
            case where a retry is the difference between direct P2P and
            none at all.
        """
        if self._have_public_addr and not force:
            return
        if self.udp is None or self.hub is None:
            return
        try:
            # hub= for the same reason as in _publish_address: STUN must
            # not recvfrom() on the hub's socket.
            probe = stun_probe(self.udp, timeout=2.0,
                               servers=self._stun_list(),
                               hub=self.hub, log=self.log)
        except Exception:
            return
        if not probe:
            return
        ip, port, nat, delta = probe
        self.nat_type = nat
        self.nat_delta = delta
        self._have_public_addr = True
        try:
            self.send({"action": "publish_offer", "p2pAddr": "%s:%d" % (ip, port),
                       "localAddrs": self.my_locals, "natType": nat,
                       "natDelta": delta})
            self.log("[NAT] refreshed endpoint %s:%d" % (ip, port))
        except Exception:
            pass

    def _tunnel_reader(self, ch, t):
        while not ch.stop.is_set() and not self._stop.is_set():
            try:
                data = t.recv(1.0)
            except Exception:
                break
            if data:
                ch.put(data)

    # ---- link liveness: a dead hole must not look "connected" ----

    def _start_watchdog(self):
        """One thread for the whole session; started on connect.

        Previously a direct tunnel that died (NAT mapping expired, peer
        restarted) was never noticed: _direct_loop had already returned, the
        channel stayed in the table with a send_fn pointing at a dead
        socket, and the UI kept saying 运行中 while the game sat frozen.
        """
        if getattr(self, "_watchdog_started", False):
            return
        self._watchdog_started = True
        self._spawn(self._link_watchdog)

    def _link_watchdog(self):
        while not self._stop.is_set():
            try:
                time.sleep(LINK_CHECK_S)
                self._check_links()
            except Exception:
                pass

    def _check_links(self):
        """Kill silent direct tunnels and rebuild them."""
        with self._chan_lock:
            pairs = [(pid, c) for pid, c in self.channels.items()
                     if c.tunnel is not None and not c.stop.is_set()]
        for pid, ch in pairs:
            t = ch.tunnel
            if t is None or ch.stop.is_set():
                continue
            # Never declare a link dead while a punch for that peer is
            # still running.
            #
            # Real log, one attempt:
            #
            #   12:32:09  start_punch (begin in 1.5s)
            #   12:32:42  直连链路中断（20 秒无数据），正在重建...
            #   12:32:42  重建直连：220.178.180.180:57492
            #   12:32:42  direct to ... is already running; not starting
            #             another
            #   12:32:43  direct #1 ... failed: udp punch timeout after 25s
            #
            # The watchdog (20s) is shorter than the punch budget (25s), so
            # it always fires mid-attempt: it tears down the link, logs a
            # rebuild it then refuses to start, and the punch it interrupted
            # reports failure a second later. Three log lines that describe
            # one event, none of which say what actually happened.
            if pid in getattr(self, "_direct_loops", ()):
                continue
            try:
                idle = t.idle_for()
            except Exception:
                continue
            if idle < LINK_DEAD_S:
                continue
            ep = tuple(t.send_to)
            self._on_link_dead(pid, ch, ep, idle)

    def _on_link_dead(self, peer_id, ch, ep, idle):
        """Tear down a dead link, then rebuild it the same way.

        Streams are stopped on purpose: killing them closes the local
        Minecraft connections, so the player sees "connection lost" and
        reconnects into the fresh link. Leaving them open would give a
        world that looks connected but never moves again.
        """
        self.log("直连链路中断（%.0f 秒无数据），正在重建..." % idle)
        self.status("直连中断，重建中")

        ch.stop_streams()
        ch.stop.set()
        with self._chan_lock:
            self.channels.pop(peer_id, None)
        if self.hub is not None:
            try:
                self.hub.unregister(ch.tunnel)
            except Exception:
                pass
        try:
            ch.tunnel.close()
        except Exception:
            pass
        ch.tunnel = None

        if self.mode == MODE_DIRECT:
            self.log("重建直连：%s" % fmt_addr(ep))
            self._start_direct(peer_id, ep)
        else:
            # auto: fall back to the relay instead of punching forever
            self.log("直连不可用，改用服务器中转")
            self._start_server_relay(peer_id)

    # ---- relay: game data over the signaling websocket ----

    def _start_server_relay(self, peer_id):
        ch = self._new_channel(peer_id, "server relay",
                               lambda d: self._relay_send(peer_id, d))
        self._start_forward(ch)
        self._start_relay_upgrade_loop(peer_id)

    def _start_relay_upgrade_loop(self, peer_id):
        """Keep trying direct while the relay is carrying the traffic.

        Giving up after two timed attempts is a statement about those two
        attempts, not about the pair. Port allocation on both ends keeps
        moving, the peer's anchor gets refreshed, a phone switches towers,
        and a punch that missed at 19:26 can land at 19:31 with nothing
        having been "fixed". EasyTier keeps punching in the background for
        exactly this reason and shows a direct link where a single timed
        attempt shows a relay.

        Only in auto mode: direct mode already retries forever, and a user
        who asked for direct has not asked for a relay underneath it.
        """
        if self.mode != MODE_AUTO:
            return
        with self._direct_loop_lock:
            loops = getattr(self, "_upgrade_loops", None)
            if loops is None:
                loops = self._upgrade_loops = set()
            if peer_id in loops:
                return
            loops.add(peer_id)
        self._spawn(lambda: self._relay_upgrade_loop(peer_id))

    def _relay_upgrade_loop(self, peer_id):
        try:
            while not self._stop.is_set():
                self._sleep_or_stop(RELAY_UPGRADE_EVERY_S)
                if self._stop.is_set():
                    return
                ch = self._get_channel(peer_id)
                # Only upgrade a live RELAY. If the channel is gone the
                # peer disconnected; if it is not a relay any more we
                # already have something better.
                if ch is None or ch.label != "server relay":
                    return
                if self._direct_blacklisted(peer_id) > 0:
                    continue
                if getattr(self, "_inbound_blocked", False):
                    # Proven unreachable inbound: a background punch is
                    # just noise. (Auto mode only ever reaches here with
                    # the verdict unknown.)
                    continue
                cands = self._peer_candidates.get(peer_id) or []
                if not cands:
                    continue
                try:
                    if self._try_relay_upgrade(peer_id, cands):
                        return
                except Exception as e:
                    self.log("relay upgrade attempt failed: %s: %s"
                             % (type(e).__name__, e))
        finally:
            with self._direct_loop_lock:
                try:
                    self._upgrade_loops.discard(peer_id)
                except Exception:
                    pass

    def _try_relay_upgrade(self, peer_id, cands):
        """One short punch. On success the relay channel is upgraded in place.

        In place, not make-before-break: the relay stays the channel's
        transport until a tunnel has actually completed its handshake, so a
        failed attempt costs nothing and the game never notices.
        """
        plan = self._punch_plan_for(peer_id)
        if plan == METHOD_NONE:
            return False
        for cand in cands:
            if is_ipv6(cand[0]) and not self._have_ipv6():
                continue
            if not is_public_ipv4(cand[0]) and not is_ipv6(cand[0]):
                continue          # LAN candidates were tried already
            ports = self._candidate_ports(peer_id, cand)
            t = UdpTunnel(self.udp, (cand[0], ports[0]), self.log,
                          hub=self.hub, alt_ports=ports[1:])
            try:
                t.connect(RELAY_UPGRADE_BUDGET_S)
            except Exception:
                try:
                    if self.hub:
                        self.hub.unregister(t)
                except Exception:
                    pass
                continue
            ch = self._get_channel(peer_id)
            if ch is None:
                try:
                    t.close()
                except Exception:
                    pass
                return True
            old = ch.tunnel
            ch.tunnel = t
            ch.send_fn = t.send
            ch.label = "direct UDP"
            if old is not None and old is not t:
                try:
                    old.close()
                except Exception:
                    pass
            self._note_direct_success(peer_id)
            self.log("upgraded to a direct UDP tunnel (was relaying), peer "
                     "endpoint %s" % t.remote)
            self.status("已升级为直连")
            self._spawn(lambda: self._tunnel_reader(ch, t))
            return True
        return False

    def _count(self, up=0, down=0):
        with self._stat_lock:
            self.bytes_up += up
            self.bytes_down += down

    def _relay_send(self, peer_id, data):
        if not peer_id:
            return
        tid = peer_id.encode("ascii", "ignore")[:255]
        self._count(up=len(data))
        self.send_binary(bytes([0x01, len(tid)]) + tid + data)

    def _on_relay_frame(self, data):
        if len(data) < 3 or data[0] != 0x01:
            return
        id_len = data[1]
        if len(data) < 2 + id_len:
            return
        body = data[2 + id_len:]
        if not body:
            return
        sender = data[2:2 + id_len].decode("ascii", "ignore")
        ch = self._get_channel(sender)
        if ch is None:
            # relay needs no handshake, so create the channel on demand —
            # this is what lets a third player join without a punch round
            ch = self._new_channel(sender, "server relay",
                                   lambda d, s=sender: self._relay_send(s, d))
            self._start_forward(ch)
        self._count(down=len(body))
        ch.put(body)

    # ---------------------------------------------------------- forward

    def _reset_p2p(self):
        with self._chan_lock:
            chs = list(self.channels.values())
            self.channels.clear()
        for ch in chs:
            try:
                if self.hub and ch.tunnel:
                    self.hub.unregister(ch.tunnel)
                ch.close()
            except Exception:
                pass

    def _wait_channel(self, timeout):
        """Wait for any live channel to appear (bounded)."""
        end = time.time() + timeout
        while time.time() < end:
            with self._chan_lock:
                live = [c for c in self.channels.values() if not c.stop.is_set()]
                if live:
                    ch = next((c for c in live if c.peer_id == self.host_id), None)
                    return ch or live[0]
            time.sleep(0.2)
        return None

    # ---------------------------------------------------------- snapshot
