# -*- coding: utf-8 -*-
"""Reliable UDP tunnel — the core of the direct-connection path.

Why UDP and not TCP (the old implementation's fatal mistake):

    s = socket(); s.connect(peer)          # no local port bound!

TCP hole punching only works if the outgoing SYN leaves *from the punch port*
(30000), because a NAT only creates a mapping when a packet is actually sent
from that local port. A listening socket sends nothing, so no mapping exists
and the peer's inbound SYN is dropped. The old code never bound the local
port, so TCP punching had a 0% success rate — not "occasionally failing".

Also: NATs keep UDP and TCP mappings separate. The 120 UDP punch packets the
old code sent did nothing for the TCP tunnel.

So we do what openP2P / ZeroTier / WireGuard all do:
  1. UDP only — both sides send to each other, both NATs create mappings
  2. keepalive every few seconds, otherwise the mapping expires and the hole closes
  3. reliability implemented by us: sequence numbers, cumulative ACK, NAK,
     retransmit, reorder buffer
"""
import queue
import socket
import struct
import threading
import time

MAGIC = 0x4D50  # 'MP'
T_HELLO, T_HELLO_ACK, T_DATA = 1, 2, 3


def fmt_addr(addr):
    """Render an endpoint without assuming it is IPv4.

    recvfrom() on an AF_INET6 socket returns a 4-tuple, so `"%s:%d" % addr`
    raises "not all arguments converted" the moment a peer connects over
    IPv6 -- inside the receive loop, which is exactly where a formatting
    bug does the most damage. Take the first two fields and stop there.
    """
    try:
        host, port = addr[0], addr[1]
    except (TypeError, IndexError):
        return str(addr)
    if ":" in str(host):
        return "[%s]:%d" % (host, port)
    return "%s:%d" % (host, port)
T_ACK, T_NAK, T_PING, T_PONG = 4, 5, 6, 7

HDR = 12
MTU = 1300          # stay well under 1500 so we never get IP-fragmented
WINDOW = 64
# Congestion control (AIMD-ish). Start small, grow on ACKs, halve on loss.
WINDOW_INIT = 8        # not 64: a 64-packet burst into an unmeasured link
WINDOW_MIN = 4         # is pure loss on a slow uplink
SEND_WAIT_S = 0.25     # bounded wait instead of a 30s block
CONGEST_WAIT_S = 3.0   # ... but waiting for the window is NOT a stall
REORDER_MAX = 512
RTO_MS = 300
RTO_MAX_MS = 4000
KEEPALIVE_S = 5.0
HELLO_S = 0.2
NAK_THROTTLE_S = 0.06


# Process-wide error budget for "the socket is gone" messages.
_send_err_lock = threading.Lock()
_send_err_count = 0
_send_err_reset = 0.0
SEND_ERR_LOG_LIMIT = 3          # per process, per minute
SEND_ERR_LOG_WINDOW = 60.0


def _log_send_error(log_fn, exc):
    global _send_err_count, _send_err_reset
    with _send_err_lock:
        now = time.time()
        if now - _send_err_reset > SEND_ERR_LOG_WINDOW:
            _send_err_reset = now
            _send_err_count = 0
        if _send_err_count >= SEND_ERR_LOG_LIMIT:
            return
        _send_err_count += 1
        n = _send_err_count
    try:
        log_fn("send failed: %s%s"
               % (exc,
                  " (further errors suppressed for 60s)" if n ==
                  SEND_ERR_LOG_LIMIT else ""))
    except Exception:
        pass


class UdpTunnel:
    def __init__(self, sock, peer, log=print, hub=None, alt_ports=None,
                 owns_socket=False):
        self.sock = sock
        self._peer = tuple(peer)
        # True when this socket came from a punch array and nobody else will
        # close it. Sockets handed to us by the hub belong to the hub.
        self.owns_socket = bool(owns_socket)
        self.peer_ip = peer[0]
        self.hub = hub
        self.log = log
        self.send_to = tuple(peer)
        # extra ports to spray at -- see connect() for why this exists
        self.alt_ports = list(alt_ports or [])
        if hub is not None:
            hub.register(self)

        self.connected = False
        self._stop = threading.Event()

        # Last time ANY packet arrived from the peer. Both ends send a
        # keepalive every few seconds, so a long silence means the hole has
        # closed (NAT mapping expired, peer restarted, ...) even though
        # nothing "failed" locally -- there is no error to catch.
        self.last_rx_at = time.monotonic()

        self._tx_lock = threading.Lock()
        self._next_seq = 1
        self._inflight = {}          # seq -> [payload, sent_at, rto]
        # Congestion window, adaptive instead of a fixed 64.
        #
        # Two problems with the fixed window: it is opened fully on a link
        # whose capacity we have never measured (a 64-packet burst into a
        # slow uplink is pure loss), and _send_chunk blocked up to 30s on a
        # semaphore -- on the Minecraft forwarding thread, so the whole game
        # stream stalled.
        self._window = threading.Semaphore(WINDOW)
        self._cwnd = float(WINDOW_INIT)
        self._win_lock = threading.Lock()
        self._space_cv = threading.Condition(threading.Lock())
        self._acked_since = 0

        self._rx_lock = threading.Lock()
        self._expected = 1
        self._reorder = {}
        self._last_nak = 0.0

        self.inbox = queue.Queue(maxsize=4096)
        self._loops_started = False
        self._lock = threading.Lock()

    # ---------------------------------------------------------- helpers

    def _log(self, msg):
        try:
            self.log("[UDP] " + msg)
        except Exception:
            pass

    @property
    def remote(self):
        return fmt_addr(self.send_to)

    def _build(self, typ, seq, ack, payload=b""):
        return (struct.pack(">HBBII", MAGIC, typ, 0, seq, ack) + payload)

    def _sendto(self, data, addr):
        # Sending on a released socket is the normal state of a tunnel
        # whose socket has gone away, so it is not worth reporting often.
        #
        # Rate-limited PROCESS-WIDE, not per tunnel.
        #
        # A real log: after disconnect, thousands of "[WinError 10038]
        # operation on a non-socket" lines -- several megabytes, filling the
        # file and burying the one line that would have explained the
        # disconnect. Per-tunnel dedup was not enough, because there were
        # thousands of tunnels (one per failed punch / rebuild), each
        # entitled to its own single line.
        if self._stop.is_set():
            return
        try:
            self.sock.sendto(data, addr)
        except Exception as e:
            if self._stop.is_set():
                return
            _log_send_error(self._log, e)

    # ---------------------------------------------------------- connect

    def _start_loops(self):
        with self._lock:
            if self._loops_started:
                return
            self._loops_started = True
        # 有 hub 时 socket 归 hub 独占读取，这里不能再起读循环，
        # 否则多个隧道会互相偷走对方的数据包。
        if self.hub is None:
            threading.Thread(target=self._read_loop, daemon=True).start()
        threading.Thread(target=self._retransmit_loop, daemon=True).start()
        threading.Thread(target=self._keepalive_loop, daemon=True).start()

    def connect(self, timeout=25.0):
        """Punch + handshake. Both sides blindly send HELLO — that's what
        actually opens the hole.

        Symmetric NAT (NAT4) support
        ----------------------------
        A symmetric NAT allocates a FRESH external port per destination, so
        the endpoint a peer learned from STUN is not the one it will use to
        talk to us -- and vice versa. Sending HELLO to that single port
        therefore never gets through.

        Fortunately most such NATs allocate sequentially, so the reachable
        port is within a small offset of the published one. We spray HELLO
        at the published port plus a handful of predicted offsets; one of
        them lands in the mapping the peer's NAT created, and that packet
        opens the hole. `_handle` accepts any source port from the peer's
        IP, so whichever guess hits simply becomes the connection.
        """
        self._log("punching %s ...%s" % (self.remote,
                  " (+%d predicted ports)" % len(self.alt_ports)
                  if self.alt_ports else ""))
        self._start_loops()

        hello = self._build(T_HELLO, 0, 0)
        targets = [tuple(self.send_to)]
        for p in self.alt_ports:
            targets.append((self.send_to[0], p))

        deadline = time.time() + timeout
        next_log = time.time() + 3
        sent = 0
        while not self.connected and time.time() < deadline and not self._stop.is_set():
            for tgt in targets:
                if self.connected or self._stop.is_set():
                    break
                self._sendto(hello, tgt)
                sent += 1
            now = time.time()
            if now >= next_log:
                self._log("still punching... %ds (sent %d, targets %d)"
                          % (int(now - (deadline - timeout)), sent, len(targets)))
                next_log = now + 5
            time.sleep(HELLO_S)

        if not self.connected:
            raise TimeoutError(
                "udp punch timeout after %ds (sent %d packets to %d ports; "
                "is UDP %d blocked by a firewall?)"
                % (timeout, sent, len(targets), self._peer[1]))
        # self.remote is ALREADY a formatted string -- wrapping it again
        # would try to %d a piece of it
        self._log("connected, peer endpoint %s" % self.remote)
        return True

    # ---------------------------------------------------------- reading

    def feed(self, data, addr):
        """Called by the UdpHub when it owns the socket."""
        self._handle(data, addr)

    def idle_for(self):
        """Seconds since the peer was last heard from."""
        return time.monotonic() - self.last_rx_at

    def _read_loop(self):
        while not self._stop.is_set():
            try:
                data, addr = self.sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                if self._stop.is_set():
                    break
                continue
            except Exception:
                break
            try:
                self._handle(data, addr)
            except Exception as e:
                self._log("handle error: %s" % e)

    def _handle(self, buf, addr):
        if len(buf) < HDR:
            return
        magic, typ, _flags, seq, ack = struct.unpack(">HBBII", buf[:HDR])
        if magic != MAGIC:
            return
        # NAT may change the port but never the IP — only accept the peer's IP
        if addr[0] != self._peer[0]:
            return

        # any well-formed packet from the peer proves the hole is alive
        self.last_rx_at = time.monotonic()

        if not self.connected:
            self.connected = True
            self.send_to = addr
        elif addr != self.send_to:
            self.send_to = addr

        if typ == T_HELLO:
            self._log("HELLO from %s, reply HELLO_ACK" % fmt_addr(addr))
            self._sendto(self._build(T_HELLO_ACK, 0, 0), addr)
            return
        if typ == T_HELLO_ACK:
            self._log("HELLO_ACK received")
            return

        if ack:
            self._ack_upto(ack)

        if typ == T_DATA:
            self._on_data(seq, buf[HDR:], addr)
        elif typ == T_NAK:
            self._retransmit(seq, addr)
        elif typ == T_PING:
            self._sendto(self._build(T_PONG, 0, self._expected - 1), addr)
        # T_ACK / T_PONG: nothing to do (ack already processed)

    def _on_data(self, seq, payload, addr):
        with self._rx_lock:
            if seq == self._expected:
                self._deliver(payload)
                self._expected += 1
                while self._expected in self._reorder:
                    nxt = self._reorder.pop(self._expected)
                    self._deliver(nxt)
                    self._expected += 1
            elif seq > self._expected:
                if len(self._reorder) < REORDER_MAX and seq not in self._reorder:
                    self._reorder[seq] = payload
                now = time.time()
                if now - self._last_nak >= NAK_THROTTLE_S:
                    self._last_nak = now
                    self._sendto(self._build(T_NAK, self._expected, self._expected - 1), addr)
            exp_minus = self._expected - 1
        self._sendto(self._build(T_ACK, 0, exp_minus), addr)

    def _deliver(self, payload):
        try:
            self.inbox.put_nowait(payload)
        except queue.Full:
            self._log("inbox full, dropped %d bytes (TCP will retransmit)" % len(payload))

    # ---------------------------------------------------------- writing

    def _ack_upto(self, ack):
        done = []
        with self._tx_lock:
            for k in list(self._inflight):
                if k <= ack:
                    done.append(k)
            for k in done:
                del self._inflight[k]
                try:
                    self._window.release()
                except ValueError:
                    pass
            if done:
                self._on_ack(len(done))
                # Wake a sender that is waiting for the window, instead of
                # letting it sleep out a fixed pacing slice.
                with self._space_cv:
                    self._space_cv.notify_all()

    def _retransmit(self, seq, addr):
        with self._tx_lock:
            pkt = self._inflight.get(seq)
            if not pkt:
                return
            pkt[1] = time.time()
            payload = pkt[0]
        self._sendto(self._build(T_DATA, seq, self._expected - 1, payload), addr)

    def send(self, data):
        """Reliable send. Splits into MTU-sized chunks."""
        if not data:
            return
        offset = 0
        while offset < len(data):
            chunk = data[offset:offset + MTU - HDR]
            offset += len(chunk)
            self._send_chunk(chunk)

    # ------------------------------------------------------- congestion

    def _on_ack(self, count=1):
        """Grow the window gradually (AIMD: additive increase)."""
        with self._win_lock:
            self._acked_since += count
            if self._acked_since >= max(2, int(self._cwnd)):
                self._acked_since = 0
                if self._cwnd < WINDOW:
                    self._cwnd = min(WINDOW, self._cwnd + 1.0)

    def _on_loss(self):
        """Shrink the window fast (AIMD: multiplicative decrease).

        Loss is the only congestion signal available on this link, and
        halving is what keeps a burst from turning into a loss spiral.
        """
        with self._win_lock:
            self._cwnd = max(WINDOW_MIN, self._cwnd * 0.5)

    def _current_window(self):
        with self._win_lock:
            return self._cwnd

    def _backoff(self):
        """Wait a little when the window is full, instead of blocking.

        Called from the Minecraft forwarding thread. Blocking it for 30
        seconds stalled the entire game stream; waiting a bounded slice and
        then applying back-pressure (dropping) keeps the thread responsive.
        """
        time.sleep(min(0.02, MTU / max(1.0, self._current_window()) * 0.5))

    def _send_chunk(self, chunk):
        # Wait a bounded time, then apply back-pressure.
        #
        # Blocking for tens of seconds here stalled the whole game stream,
        # because the caller is the Minecraft forwarding thread. A short
        # wait plus pacing keeps it responsive; dropping after that lets
        # TCP's own retransmit deal with it, which is far better than a
        # frozen stream.
        #
        # The gate is min(cwnd, WINDOW), not the semaphore alone: the
        # semaphore is a fixed 64 permits, so on its own it let the very
        # first burst go out 64 packets wide -- the "start at 8, slow start"
        # comment was a lie, and _cwnd only ever paced the backoff sleep.
        #
        # Waiting for the window needs a DIFFERENT bound than waiting for a
        # stuck link, and conflating them is what broke this once: a lost
        # packet holds the cumulative ACK back for a whole retransmit cycle,
        # so with a small cwnd a healthy link is "window full" for 100s of
        # milliseconds at a time. Dropping after the old 0.25s back-pressure
        # bound turned ordinary loss into permanent data loss.
        deadline = time.monotonic() + SEND_WAIT_S
        congest_deadline = time.monotonic() + CONGEST_WAIT_S
        while not self._stop.is_set():
            limit = max(1, int(min(self._current_window(), WINDOW)))
            with self._tx_lock:
                inflight = len(self._inflight)
            if inflight < limit:
                if self._window.acquire(timeout=0.02):
                    break
                # Room by cwnd but no permit: everything we sent is still
                # out and nothing is coming back -- that is a stuck link,
                # not congestion, so give up fast.
                if time.monotonic() >= deadline:
                    self._log("send window full, dropping chunk (back-pressure)")
                    return
            else:
                # Congestion window full: waiting here is normal operation.
                # Only give up if nothing has moved at all.
                if time.monotonic() >= congest_deadline:
                    self._log("congestion window stuck (inflight=%d, cwnd=%.0f), "
                              "dropping chunk" % (inflight, self._current_window()))
                    return
                # Wait to be woken by an ACK rather than sleeping out a
                # fixed slice: a blind 20ms pacing sleep spread a 60KB
                # burst over six rounds, and the peer (which reassembles
                # per read) then saw it as several separate messages.
                with self._space_cv:
                    self._space_cv.wait(0.05)
                continue
            self._backoff()
        else:
            return
        with self._tx_lock:
            seq = self._next_seq
            self._next_seq += 1
            self._inflight[seq] = [chunk, time.time(), RTO_MS]
        self._sendto(self._build(T_DATA, seq, self._expected - 1, chunk), self.send_to)

    def _retransmit_loop(self):
        while not self._stop.is_set():
            time.sleep(0.03)
            now = time.time()
            with self._tx_lock:
                due = [s for s, p in self._inflight.items()
                       if (now - p[1]) * 1000 >= p[2]]
            for s in due:
                with self._tx_lock:
                    pkt = self._inflight.get(s)
                    if not pkt:
                        continue
                    pkt[1] = now
                    pkt[2] = min(pkt[2] * 2, RTO_MAX_MS)
                    payload = pkt[0]
                self._on_loss()
                self._sendto(self._build(T_DATA, s, self._expected - 1, payload),
                             self.send_to)

    def _keepalive_loop(self):
        """Without this the NAT mapping expires and the hole silently closes."""
        while not self._stop.is_set():
            time.sleep(KEEPALIVE_S)
            if not self.connected:
                continue
            self._sendto(self._build(T_PING, 0, self._expected - 1), self.send_to)

    # ---------------------------------------------------------- api

    def recv(self, timeout=None):
        try:
            return self.inbox.get(timeout=timeout)
        except queue.Empty:
            return None

    def close(self):
        self._stop.set()
        # A punched socket from the array has no other owner: if we do not
        # close it, every failed punch -- and every link rebuild, which
        # discards the old tunnel -- leaks one UDP port for the life of the
        # process.
        if self.owns_socket:
            try:
                self.sock.close()
            except Exception:
                pass
            self.owns_socket = False


class UdpHub:
    """One socket, many tunnels.

    Every direct-peer tunnel must share the single punch socket (30000),
    but only ONE reader may own a socket - otherwise the tunnels steal each
    other's packets and nobody's handshake ever completes.

    The hub is that single reader and routes each datagram by source
    address. Two peers behind the same NAT share a public IP, so match on
    (ip, port) first and only fall back to IP when unambiguous.
    """

    def __init__(self, sock, log=print):
        self.sock = sock
        self.log = log
        self.tunnels = {}          # ip -> [UdpTunnel]
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.thread = None

        # Hub-mediated request/response.
        #
        # STUN must run on the punch socket (a symmetric NAT hands out a
        # different mapping per socket), but the hub is that socket's sole
        # reader. If STUN called recvfrom() itself, the two would race for
        # every datagram: the hub would swallow STUN responses (it routes by
        # peer IP, and a STUN server is not a peer) and STUN would swallow
        # tunnel traffic.
        #
        # So instead of racing, STUN registers a matcher and lets the hub
        # hand the reply back.
        self._pending = []         # [(match_fn, queue)]
        self._pend_lock = threading.Lock()
        self._catch_all = {}       # peer_ip -> fn(data, addr) while punching
        self._catch_lock = threading.Lock()

    def start(self):
        if self.thread is None:
            self.thread = threading.Thread(target=self._run, daemon=True)
            self.thread.start()

    def exchange(self, payload, addr, timeout, match):
        """Send `payload` to `addr` and wait for a packet `match` accepts.

        Returns the datagram, or None on timeout. Used for STUN so the hub
        stays the only reader of the socket.

        The socket is set non-blocking ONLY around the send, and the
        previous timeout is always restored -- leaving a timeout behind
        here would silently kill this very loop (see _run).
        """
        box = queue.Queue(maxsize=1)
        entry = (match, box)
        with self._pend_lock:
            self._pending.append(entry)
        try:
            prev = self.sock.gettimeout()
            try:
                self.sock.settimeout(None)
                self.sock.sendto(payload, addr)
            except Exception:
                return None
            finally:
                try:
                    self.sock.settimeout(prev)
                except Exception:
                    pass
            try:
                return box.get(timeout=timeout)
            except Exception:
                return None
        finally:
            with self._pend_lock:
                try:
                    self._pending.remove(entry)
                except ValueError:
                    pass

    def _match_pending(self, data, addr):
        with self._pend_lock:
            pend = list(self._pending)
        for match, box in pend:
            try:
                if match(data, addr):
                    try:
                        box.put_nowait(data)
                    except Exception:
                        pass
                    return True
            except Exception:
                continue
        return False

    def set_catch_all(self, fn, key=None):
        """Hand unroutable packets to `fn(data, addr)` while punching.

        During a multi-socket punch the punch port (30000) has NO tunnel
        registered -- the ordinary single-socket attempt just failed and
        unregistered itself -- so anything the peer sends to our published
        endpoint arrives at the hub, matches nothing, and is dropped. The
        peer is meanwhile spraying at exactly that port for its whole
        budget, and we never answer.

        A catch-all lets the punch array hear those packets without giving
        up hub ownership of the socket (two readers would steal each
        other's datagrams).

        Slots are per-key (the peer's IP), because this is a star topology:
        the host punches to several guests at once, and a single slot meant
        whichever punch started last silently deafened all the others --
        and any one of them finishing cleared the slot for everybody.
        """
        with self._catch_lock:
            self._catch_all[key] = fn

    def clear_catch_all(self, key=None):
        with self._catch_lock:
            if key is None:
                self._catch_all.clear()
            else:
                self._catch_all.pop(key, None)

    def register(self, tunnel):
        with self.lock:
            self.tunnels.setdefault(tunnel.peer_ip, []).append(tunnel)

    def unregister(self, tunnel):
        with self.lock:
            lst = self.tunnels.get(tunnel.peer_ip)
            if lst and tunnel in lst:
                lst.remove(tunnel)
                if not lst:
                    self.tunnels.pop(tunnel.peer_ip, None)

    def _pick(self, addr):
        cands = self.tunnels.get(addr[0]) or []
        if not cands:
            return None
        if len(cands) == 1:
            return cands[0]
        for t in cands:
            if t.send_to == tuple(addr):
                return t
        try:
            self.log("[UDP] ambiguous packet from %s:%d "
                     "(two peers behind one NAT) - dropped"
                     % fmt_addr(addr))
        except Exception:
            pass
        return None

    def _run(self):
        # This loop must NEVER exit on a timeout.
        #
        # socket.timeout IS an OSError, so a bare `except OSError: break`
        # means any leftover socket timeout kills the reader permanently --
        # no error surfaces, tunnels just stop receiving and the link is
        # declared dead 20s later by the watchdog. Keepalives every 5s with
        # a 3s timeout made that dead certain.
        while not self.stop.is_set():
            try:
                data, addr = self.sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            except Exception:
                continue
            # a STUN reply (or anything else waiting) gets first look
            try:
                if self._match_pending(data, addr):
                    continue
            except Exception:
                pass
            t = self._pick(addr)
            if t is None:
                # nobody claims it -- but a punch in progress might
                with self._catch_lock:
                    cands = [self._catch_all.get(addr[0]),
                             self._catch_all.get(None)]
                for catch in cands:
                    if catch is None:
                        continue
                    try:
                        catch(data, addr)
                    except Exception:
                        pass
                continue
            try:
                t.feed(data, addr)
            except Exception:
                pass

    def close(self):
        """Stop the reader AND every tunnel still using this socket.

        Setting only `stop` left every registered tunnel running. Their
        socket is this hub's, so the moment the caller closes it (see
        _release_punch_socket) their keepalive and retransmit loops start
        failing on every tick -- hundreds of "operation on a non-socket"
        lines a second, forever.

        The tunnels do not own the socket, so they cannot know it went
        away; the hub is the one object that does.
        """
        self.stop.set()
        with self.lock:
            tuns = [t for lst in self.tunnels.values() for t in lst]
        for t in tuns:
            try:
                t.close()
            except Exception:
                pass
