# -*- coding: utf-8 -*-
"""TCP simultaneous open: a second path when UDP cannot get through.

Why this exists
---------------
UDP punching is the right first choice, but it is not always available:
some networks and firewalls block UDP almost entirely while leaving TCP
alone, and on those a UDP-only client can only relay. TCP's simultaneous
open is a genuinely different path -- not a variant of the UDP trick.

How it works
------------
Both ends bind to a KNOWN local port and connect to each other at the same
time. The two SYNs cross in the middle and both kernels complete the
handshake. No listen() is needed and no server is involved.

The detail that makes it work with a single socket: the socket is bound to
the port the peer is aiming at. When the peer's SYN arrives, the kernel
finds a socket in SYN-SENT on exactly that port, receives a SYN (not the
SYN-ACK it expected), moves to SYN-RECEIVED and answers -- that IS the
simultaneous open, handled by the TCP state machine.

Timing
------
Strictly simultaneous is not required. The first SYN is dropped by the
peer's NAT (no mapping exists yet) and then RETRANSMITTED, so a window of
a second or two is plenty. We retry a few rounds anyway, re-binding the
same local port each time, because a retry is cheap and the alternative is
relaying.
"""
import os
import random
import select
import socket
import struct
import threading
import time

# Frame: 4-byte length prefix + payload. TCP is a byte stream, so without
# a boundary the peer cannot tell one frame from the next -- and the
# channel parser above us expects whole frames.
_LEN = struct.Struct(">I")


def enabled():
    """Off switch, like DISABLE_SYM_PUNCH.

    Some networks treat a burst of outbound SYNs as scanning. Give the
    operator a way to turn this off without a rebuild.
    """
    return os.environ.get("DISABLE_TCP_PUNCH", "").strip() not in ("1", "true",
                                                                   "yes")


class TcpTunnel:
    """A connected TCP socket dressed as a tunnel.

    Deliberately NOT a copy of UdpTunnel: TCP already provides ordering,
    retransmission and loss detection, so re-implementing sequence numbers
    and ACKs on top of it would add latency and bugs for nothing. All this
    has to do is frame.
    """

    def __init__(self, sock, peer, log=print):
        self.sock = sock
        self.peer_ip = peer[0]
        self.send_to = tuple(peer)
        self.remote = "%s:%s" % (peer[0], peer[1])
        self.log = log
        self.connected = True
        self.owns_socket = True
        self.last_rx_at = time.monotonic()
        self._stop = threading.Event()
        self._tx_lock = threading.Lock()
        self._rx_buf = bytearray()
        self._rx_lock = threading.Lock()
        try:
            sock.settimeout(None)
        except Exception:
            pass

    # -- link liveness uses this; same contract as UdpTunnel.idle_for --
    def idle_for(self):
        return time.monotonic() - self.last_rx_at

    def send(self, data):
        if self._stop.is_set():
            return
        try:
            with self._tx_lock:
                self.sock.sendall(_LEN.pack(len(data)) + bytes(data))
        except Exception:
            self.close()

    def recv(self, timeout=1.0):
        """One frame, or b'' on timeout, or None when the link is gone.

        None (not b'') signals EOF: the reader loop above us stops on an
        exception, so it breaks either way, but the distinction keeps the
        log honest.
        """
        if self._stop.is_set():
            return None
        try:
            self.sock.settimeout(timeout)
        except Exception:
            return None
        try:
            with self._rx_lock:
                if len(self._rx_buf) >= _LEN.size:
                    n = _LEN.unpack_from(self._rx_buf, 0)[0]
                    if len(self._rx_buf) >= _LEN.size + n:
                        out = bytes(self._rx_buf[_LEN.size:_LEN.size + n])
                        del self._rx_buf[:_LEN.size + n]
                        self.last_rx_at = time.monotonic()
                        return out
            chunk = self.sock.recv(65536)
            if not chunk:
                return None
            with self._rx_lock:
                self._rx_buf += chunk
                if len(self._rx_buf) >= _LEN.size:
                    n = _LEN.unpack_from(self._rx_buf, 0)[0]
                    if len(self._rx_buf) >= _LEN.size + n:
                        out = bytes(self._rx_buf[_LEN.size:_LEN.size + n])
                        del self._rx_buf[:_LEN.size + n]
                        self.last_rx_at = time.monotonic()
                        return out
            return b""
        except socket.timeout:
            return b""
        except Exception:
            return None

    def close(self):
        self._stop.set()
        self.connected = False
        try:
            self.sock.close()
        except Exception:
            pass


def _open_socket(local_port):
    """Bind to `local_port` -- the port the peer is aiming at.

    NO SO_REUSEADDR here, deliberately.

    On the UDP side the same rule already applies and is documented: two
    clients on one machine binding the same punch port steal each other's
    packets. TCP obeys the same logic -- with REUSEADDR a second client
    binds 30001 happily and then absorbs SYNs the first one was waiting
    for, so a two-instance test on one box (or on a LAN where both picked
    the same port) fails in a way that looks like "TCP punching does not
    work".

    Failing loudly on a busy port is the right outcome: the port is
    configurable, and a silent steal is far harder to diagnose than an
    error.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("", int(local_port)))
    except OSError as e:
        s.close()
        raise OSError(e.errno, "TCP punch port %s is busy (another client "
                               "on this machine, or change it in settings)"
                      % local_port)
    s.setblocking(False)
    return s


def open_bound_connection(local_port, host, port, timeout=4.0):
    """One plain TCP connection opened FROM the punch port.

    The point is not the connection, it is the source port: a server on the
    other end sees which port the NAT actually gave us, which is the only
    way to learn whether this NAT preserves it. Returns the socket (caller
    holds it open while the server looks, then closes it) or None.

    Never raises: this runs on the startup path, and a port that happens to
    be busy must not cost the user a connection.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.bind(("", int(local_port)))
        s.connect((host, int(port)))
        return s
    except Exception:
        try:
            s.close()
        except Exception:
            pass
        return None


def simultaneous_open(local_port, peer_ip, peer_port, timeout=8.0,
                      log=None, rounds=6, on_bound=None):
    """Try to establish a TCP connection by both ends dialling at once.

    Returns a connected TcpTunnel, or None.

    One connect per round, then wait out the whole window.
    -----------------------------------------------------
    Within a round the kernel retransmits the SYN on its own
    (tcp_syn_retries), so there is no reason to tear the socket down and
    redial -- and doing so mid-flight IS harmful: between rounds the local
    port has no socket on it, so the peer's crossing SYN gets an RST and
    its attempt fails instantly. So each round keeps one socket bound and
    in SYN-SENT for as long as the budget allows.

    Across rounds, redialing is exactly right, because a round ends only on
    a DEFINITE failure. The common one is ECONNREFUSED: on loopback (and
    from some firewalls) an unanswered SYN is answered with RST rather than
    dropped, and an RST is final -- the kernel will not retransmit past it.
    That happens whenever the peer had not bound its port yet. Retrying
    with jitter gives the two ends a chance to be bound at the same time,
    which is the only thing the crossing needs.
    """
    if not enabled():
        return None
    try:
        peer_ip = socket.gethostbyname(peer_ip)
        peer_port = int(peer_port)
    except Exception:
        return None
    if peer_port <= 0 or not peer_ip:
        return None

    deadline = time.monotonic() + max(0.5, timeout)
    for r in range(max(1, rounds)):
        left_total = deadline - time.monotonic()
        left = left_total
        if left <= 0.3:
            break
        try:
            s = _open_socket(local_port)
        except OSError as e:
            # Fatal for this attempt, not worth retrying: the port is what
            # the peer aims at, so "try another" is not an option.
            if log:
                log("[TCP] %s" % e)
            return None
        try:
            # Test seam.
            #
            # The crossing needs BOTH ends in SYN-SENT before either SYN is
            # processed: a bound-but-not-connecting socket answers an
            # incoming SYN with RST. On loopback there is no NAT to drop the
            # first SYN and no retransmit window to speak of, so two ends
            # started independently almost never line up -- the test was
            # flaky for that reason alone. Real deployments do not need
            # this; they have a NAT absorbing the early SYNs.
            if on_bound is not None:
                try:
                    on_bound()
                except Exception:
                    pass
            err = None
            try:
                # Connected immediately: same host, or no NAT in between.
                s.connect((peer_ip, peer_port))
                return TcpTunnel(s, (peer_ip, peer_port), log=log)
            except (BlockingIOError, InterruptedError):
                err = None                  # EINPROGRESS: the normal case
            except OSError as e:
                # A refusal means a peer IS there and is not listening on
                # that port. Retrying is still worth it -- the peer may
                # still be starting up.
                err = e.errno
                if log:
                    log("[TCP] connect to %s:%s -> %s"
                        % (peer_ip, peer_port, e))

            # Poll until the handshake completes or this ROUND's slice runs
            # out.
            #
            # A per-round slice, not the whole budget: an RST is final, so a
            # round that has failed will never recover by waiting longer.
            # Giving round 1 the entire budget meant the retry loop could
            # never run at all.
            rounds_left = max(1, max(1, rounds) - r)
            slice_end = min(deadline, time.monotonic()
                            + max(0.8, left_total / rounds_left))
            while time.monotonic() < slice_end:
                rest = slice_end - time.monotonic()
                try:
                    _, w, _ = select.select([], [s], [], min(rest, 0.25))
                except (OSError, ValueError):
                    break
                if not w:
                    continue
                so_err = s.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                if so_err == 0:
                    return TcpTunnel(s, (peer_ip, peer_port), log=log)
                # Writable but with an error: this attempt is over. Break
                # out of the poll; the outer loop may redial.
                err = so_err
                break
        except Exception as e:
            if log:
                log("[TCP] attempt %d failed: %s" % (r + 1, e))
            try:
                s.close()
            except Exception:
                pass
            continue
        # Only reached when this round failed for good; the tunnel owns the
        # socket on every success path above, so closing here cannot kill a
        # live link.
        try:
            s.close()
        except Exception:
            pass
        # Jitter matters: without it two ends that both failed can settle
        # into lockstep and keep missing each other.
        left = deadline - time.monotonic()
        if left <= 0.3:
            break
        time.sleep(min(0.05 + random.random() * 0.25, left))
    return None
