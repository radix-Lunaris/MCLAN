# -*- coding: utf-8 -*-
"""Small helpers shared by every layer: sockets, settings, rate meter.

Nothing in here imports the network layer, so the GUI and the tests can use
it without pulling in the whole stack.
"""
import json
import logging
import logging.handlers
import os
import socket
import struct
import sys
import time

from protocol import (STUN_SERVERS, NAT_UNKNOWN, NAT_CONE, NAT_SYMMETRIC,
                      SYM_SPRAY_PORTS, SYM_MAX_DELTA, STUN_BUDGET_S,
                      NAT_SUB_CONE, NAT_SUB_HARD, NAT_SUB_UNKNOWN,
                      THIRD_PROBE_SAMPLES, THIRD_PROBE_MIN_SAMPLES,
                      PER_IP_POOL_GAP)


# ============================================================
# Sockets
# ============================================================

def tune(sock):
    """TCP_NODELAY, plus do not linger on close.

    Minecraft is latency sensitive: without NODELAY, Nagle batches the many
    small packets the game sends and adds a round trip to each one.
    """
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except Exception:
        pass
    return sock


def close_sock(sock):
    """Close a socket and never raise (used from cleanup paths)."""
    if sock is None:
        return
    try:
        sock.close()
    except Exception:
        pass


def listen_backlog():
    """Several MC connections can queue up at once (probe + real join)."""
    return 8


# ============================================================
# Locations
# ============================================================

APP_NAME = "MCLanP2P"
CONFIG_FILENAME = "settings.json"

# device id lives in the config dir too, so it follows the same rules
DEVICE_ID_NAME = ".device_id"


def is_frozen():
    """True when running as a PyInstaller one-file exe."""
    return bool(getattr(sys, "frozen", False))


def exe_dir():
    """The directory the program actually lives in.

    Under PyInstaller onefile, __file__ points into the temp extraction dir
    (_MEIxxxx) which is deleted on exit -- so never derive a persistent
    path from __file__ when frozen.
    """
    if is_frozen():
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.abspath(__file__))


def config_dir():
    """Per-user config directory -- NOT the program directory.

    Storing settings next to the exe means they are lost whenever the exe is
    moved, and writes fail outright when the program sits in Program Files
    or on a read-only share. The OS gives every platform a per-user place:

        Windows  %APPDATA%\\MCLanP2P
        macOS    ~/Library/Application Support/MCLanP2P
        Linux    $XDG_CONFIG_HOME/mclanp2p  (default ~/.config/mclanp2p)

    Override with MCLANP2P_HOME for tests and for running several copies.
    """
    env = os.environ.get("MCLANP2P_HOME")
    if env:
        return env

    if sys.platform.startswith("win"):
        base = os.environ.get("APPDATA") or os.path.expanduser("~")
        return os.path.join(base, APP_NAME)

    if sys.platform == "darwin":
        return os.path.join(os.path.expanduser("~"), "Library",
                            "Application Support", APP_NAME)

    base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(
        os.path.expanduser("~"), ".config")
    return os.path.join(base, "mclanp2p")


def fallback_dir():
    """Used only when the per-user dir is not writable.

    A locked-down machine or a read-only roaming profile should not stop the
    client from running; it just means settings may not survive a move.
    """
    return exe_dir()


def _writable(path):
    try:
        os.makedirs(path, exist_ok=True)
        probe = os.path.join(path, ".write_test")
        with open(probe, "w") as f:
            f.write("x")
        os.remove(probe)
        return True
    except Exception:
        return False


def app_dir():
    """The directory settings.json and .device_id actually live in."""
    if os.environ.get("MCLANP2P_HOME"):
        return os.environ["MCLANP2P_HOME"]

    preferred = config_dir()
    if _writable(preferred):
        _migrate_legacy(preferred)
        return preferred

    return fallback_dir()


def _migrate_legacy(dest):
    """Move settings created by older versions out of the program folder.

    Before this change everything lived next to the exe. Without a migration
    every existing user would silently lose their nickname, server address
    and device id on upgrade -- and would get handed a fresh device id,
    which (see the DUPLICATE_DEVICE handling) can look like a weird bug.

    Only copies what is missing at the destination, and never raises.
    """
    legacy = exe_dir()
    if os.path.abspath(legacy) == os.path.abspath(dest):
        return

    for name in (CONFIG_FILENAME, DEVICE_ID_NAME):
        src = os.path.join(legacy, name)
        dst = os.path.join(dest, name)
        if not os.path.isfile(src) or os.path.exists(dst):
            continue
        try:
            with open(src, "rb") as f:
                data = f.read()
            tmp = dst + ".tmp"
            with open(tmp, "wb") as f:
                f.write(data)
            os.replace(tmp, dst)
        except Exception:
            pass


def settings_path():
    return os.path.join(app_dir(), CONFIG_FILENAME)


def log_dir():
    """Rotating logs; keeps the config dir clean by using a sibling."""
    base = app_dir()
    try:
        path = os.path.join(base, "logs")
        os.makedirs(path, exist_ok=True)
        return path
    except Exception:
        return base


# ============================================================
# Settings
# ============================================================

def load_settings():
    try:
        with open(settings_path(), "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def save_settings(**kw):
    data = load_settings()
    data.update(kw)
    tmp = settings_path() + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        os.replace(tmp, settings_path())
    except Exception:
        pass


# ============================================================
# Logging to disk
# ============================================================

_FILE_LOGGER = None


def file_logger():
    """A logger that writes a rotating log file next to the app.

    Why: the client used to show logs only in the window. Close the window
    and every clue about what went wrong was gone.
    """
    global _FILE_LOGGER
    if _FILE_LOGGER is not None:
        return _FILE_LOGGER

    logger = logging.getLogger("mclanp2p")
    logger.setLevel(logging.INFO)
    logger.propagate = False

    try:
        path = os.path.join(log_dir(), "mclanp2p.log")
        handler = logging.handlers.TimedRotatingFileHandler(
            path, when="midnight", backupCount=5, encoding="utf-8")
        handler.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
        logger.addHandler(handler)
    except Exception:
        # A read-only install must not stop the client from running.
        logger.addHandler(logging.NullHandler())

    _FILE_LOGGER = logger
    return logger


def log_to_file(text):
    try:
        file_logger().info(text)
    except Exception:
        pass


# ============================================================
# Endpoint discovery / candidate ordering
# ============================================================

def ipv6_endpoints(port):
    """This host's globally-routable IPv6 endpoints as "ip:port" strings.

    IPv6 does not go through NAT at all, so if both ends have a global v6
    address they can simply connect -- no prediction, no socket array, no
    birthday attack, none of the probability machinery below. It is the
    cleanest bypass there is, which is why EasyTier listens dual-stack by
    default.

    Only GLOBAL addresses count: link-local (fe80::) is no more routable
    than 169.254, and a temporary/privacy address is fine but pointless to
    enumerate alongside its stable sibling.
    """
    out, seen = [], set()

    def add(ip):
        if not ip:
            return
        ip = ip.split("%")[0]      # scope id is only meaningful locally
        low = ip.lower()
        if low.startswith("fe80:") or low == "::1":
            return                 # not routable
        if low in seen:
            return
        seen.add(low)
        out.append("%s:%d" % (ip, port))

    # The trick the v4 path already uses and this one was missing: ask the
    # kernel which source address it would actually pick. Resolving the
    # hostname only works when the name resolves to a global address at
    # all -- on most Linux boxes it resolves to ::1 and nothing else, so
    # the v6 list came back empty even though the machine had a perfectly
    # good global address.
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        s.connect(("2001:4860:4860::8888", 80))
        add(s.getsockname()[0])
        s.close()
    except Exception:
        pass

    try:
        for info in socket.getaddrinfo(socket.gethostname(), None,
                                       socket.AF_INET6):
            add(info[4][0])
    except Exception:
        pass
    return out


def is_ipv6(text):
    """True for a literal IPv6 address (the parser needs to know)."""
    return ":" in (text or "") and not text.replace(".", "").isdigit()


def is_public_ipv4(text):
    """Routable public IPv4 -- i.e. worth counting as a punch attempt.

    Loopback, link-local, RFC1918 and CGNAT space are all "somewhere we can
    reach without punching", so failing against them says nothing about
    whether a hole is achievable and must not advance the retry budget.
    """
    ip = (text or "").strip()
    if not ip or is_ipv6(ip):
        return False
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        a, b = int(parts[0]), int(parts[1])
    except ValueError:
        return False
    if a in (0, 10, 127) or a >= 224:
        return False
    if a == 169 and b == 254:
        return False
    if a == 172 and 16 <= b <= 31:
        return False
    if a == 192 and b == 168:
        return False
    if a == 100 and 64 <= b <= 127:      # CGNAT
        return False
    return True


def local_endpoints(port):
    """This host's LAN IPv4 endpoints as "ip:port" strings.

    Matters because two players on the same LAN must NOT be sent out to the
    public internet and back -- that needs hairpinning on the router, which
    is widely unsupported, and it needlessly burns the VPS relay.
    """
    ips = []
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ips.append(s.getsockname()[0])
        s.close()
    except Exception:
        pass
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None,
                                       socket.AF_INET):
            ips.append(info[4][0])
    except Exception:
        pass

    out, seen = [], set()
    for ip in ips:
        # link-local is never routable, not even inside the LAN
        if ip.startswith("169.254.") or ip in seen:
            continue
        # Loopback is published to every room member, so offering
        # "127.0.0.1:30000" tells peers to dial themselves. Seen in a real
        # log: a peer's localAddrs were ["240e:...", "100.167.x.x",
        # "127.0.0.1"] -- and getaddrinfo(gethostname()) is the source,
        # which resolves to ::1 / 127.0.0.1 on plenty of machines.
        if ip.startswith("127."):
            continue
        seen.add(ip)
        out.append("%s:%d" % (ip, port))
    return out


def _same_subnet(a, b):
    """True only for a same-/24 pair.

    A /16 match was also accepted before, which is far too loose: CGNAT
    ranges (10.x, 100.64/10) and large corporate networks would make
    complete strangers look like LAN neighbours. Worse, LAN endpoints are
    published to every room member, so being wrong also leaks internal
    addresses to unrelated peers.

    /24 covers the overwhelming majority of home routers. Anything larger
    is treated as public, which is the safe failure direction.
    """
    try:
        pa = [int(x) for x in a.split(".")]
        pb = [int(x) for x in b.split(".")]
    except (ValueError, AttributeError):
        return False
    if len(pa) != 4 or len(pb) != 4:
        return False
    # never treat a loopback or link-local address as a LAN peer
    if pa[0] == 127 or pa[0] == 169 or pb[0] == 127 or pb[0] == 169:
        return False
    return pa[:3] == pb[:3]


def order_candidates(peer_public, peer_locals, my_locals, log=None):
    """Connection attempts in priority order.

    LAN first (cheap, always works if it applies), then the public endpoint.
    Everything is still ATTEMPTED -- a candidate that looks right on paper
    can be blocked, so a wrong-but-reachable one is better than none.
    """
    def split(x):
        if isinstance(x, (tuple, list)):
            return str(x[0]), int(x[1])
        ip, _, p = str(x).rpartition(":")
        try:
            return ip, int(p)
        except ValueError:
            return None, None

    mine = [split(m)[0] for m in my_locals or []]
    mine = [m for m in mine if m]

    out, seen = [], set()

    if log is not None:
        try:
            log("[NAT] peer locals=%s public=%s" % (list(peer_locals or []),
                                                    peer_public))
        except Exception:
            pass

    # LAN IPv4 first.
    #
    # Two players in the same dorm should talk over the LAN, not out to a
    # global address and back. IPv6 used to be sorted ahead of everything,
    # which sent same-room traffic out through v6 first.
    saw_lan = False
    for pl in peer_locals or []:
        pip, pport = split(pl)
        if pip is None:
            continue
        if is_ipv6(pip):
            continue      # handled below
        if any(_same_subnet(pip, m) for m in mine):
            key = (pip, pport)
            if key not in seen:
                seen.add(key)
                out.append(key)
                saw_lan = True

    # IPv6 next -- but after the LAN, and only when it is routable.
    #
    # _same_subnet() only understands IPv4, so a global v6 address would
    # otherwise never match "LAN" and would be dropped from the list
    # entirely, making the one path that needs no NAT unreachable.
    for pl in peer_locals or []:
        pip, pport = split(pl)
        if pip is None or not is_ipv6(pip):
            continue
        # link-local is not routable; a peer can publish anything, so this
        # is filtered here too and not only when collecting our own
        if pip.lower().startswith("fe80:") or pip == "::1":
            continue
        key = (pip, pport)
        if key not in seen:
            seen.add(key)
            out.append(key)

    if peer_public:
        pip, pport = split(peer_public)
        if pip is not None and (pip, pport) not in seen:
            seen.add((pip, pport))
            out.append((pip, pport))
    return out


# ============================================================
# Formatting
# ============================================================

def human_bytes(value):
    """12345 -> '12.1 KB'"""
    try:
        value = float(value)
    except (TypeError, ValueError):
        return "0 B"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{int(value)} B" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024


def human_rate(value):
    """12345 -> '12.1 KB/s'"""
    return human_bytes(value) + "/s"


# ============================================================
# RateMeter
# ============================================================

class RateMeter:
    """Turn an ever growing byte counter into a live bytes/second figure.

    `sample()` must be called regularly (the GUI calls it once a second).
    The rate is smoothed over the window since the previous call, which is
    what a "speed" display should show -- a raw delta just jitters.

    When no bytes move the rate decays to 0 instead of holding the last
    value, so an idle connection reads 0 B/s rather than a stale number.
    """
    __slots__ = ("_count", "_last_count", "_last_time", "_rate", "_idle")

    # number of consecutive empty windows before the rate is forced to 0
    IDLE_WINDOWS = 2

    def __init__(self):
        self._count = 0
        self._last_count = 0
        self._last_time = time.monotonic()
        self._rate = 0.0
        self._idle = 0

    def update(self, total_bytes):
        """Feed the absolute counter (bytes since the session started)."""
        try:
            self._count = int(total_bytes or 0)
        except (TypeError, ValueError):
            self._count = 0

    def sample(self):
        """Recompute and return the current rate in bytes/second."""
        now = time.monotonic()
        elapsed = now - self._last_time

        # ignore absurdly short windows (clock resolution, double calls)
        if elapsed >= 0.25:
            delta = self._count - self._last_count
            instant = delta / elapsed if elapsed > 0 else 0.0

            # blend: 70% old + 30% new keeps the number readable
            self._rate = self._rate * 0.7 + instant * 0.3

            # Stop showing movement once traffic really stops.
            #
            # The EMA alone is not enough: 0.7^n only reaches ~1% after 13
            # windows, so a burst would keep displaying a stale figure for
            # ~13 seconds after the transfer ended. Count empty windows
            # instead and hard-zero after a couple of them.
            if delta == 0:
                self._idle += 1
                if self._idle >= self.IDLE_WINDOWS:
                    self._rate = 0.0
            else:
                self._idle = 0

            self._last_time = now
            self._last_count = self._count

        return max(0.0, self._rate)


# ============================================================
# STUN / reachability
# ============================================================

STUN_MAGIC = b"\x21\x12\xa4\x42"
STUN_MAGIC_INT = 0x2112A442

# --- RFC 5780: NAT behaviour discovery ---------------------------------
#
# Everything above tells us how the NAT MAPS outbound flows. It says
# nothing about what it lets back IN -- and that is the other half of the
# problem. Two NATs with identical mapping behaviour need completely
# different handling if one filters per-destination and the other does not.
#
# The attribute that makes this measurable is CHANGE-REQUEST: ask the
# server to answer from a different IP and/or port. If that answer arrives,
# the NAT is letting in traffic from somewhere we never contacted, which is
# exactly the question.
CHANGE_REQUEST = 0x0003
CHANGE_PORT = 0x00000001       # RFC 5780 flag "B"
CHANGE_IP = 0x00000002         # RFC 5780 flag "A"
OTHER_ADDRESS = 0x802C         # where the server WOULD answer from
RESPONSE_ORIGIN = 0x802B       # where this answer actually came from

# Filtering behaviour. Ordered by how strict they are -- see filter_rank.
FILTER_EIF = "eif"             # endpoint-independent: anything may come in
FILTER_ADF = "adf"             # address-dependent: only hosts we wrote to
FILTER_APDF = "apdf"           # address AND port dependent
FILTER_UNKNOWN = "unknown"


def _stun_parse(data, txid, out=None):
    """Extract (ip, port) from a binding response, validating it first.

    Both checks matter. Without them ANY datagram that happens to arrive
    first -- the peer's HELLO, a keepalive, another app entirely -- would be
    parsed as a STUN reply and an unrelated address published to the peer,
    which is worse than failing outright.
    """
    if len(data) < 20:
        return None
    kind, length = struct.unpack(">HH", data[:4])
    if kind != 0x0101:                       # binding response
        return None
    if data[4:8] != STUN_MAGIC:              # magic cookie
        return None
    if data[8:20] != txid:                   # our transaction
        return None
    if 20 + length != len(data):
        return None
    # Scan EVERY attribute before returning.
    #
    # Returning as soon as the mapped address was found -- which is what
    # this did -- means anything positioned after it is never seen. For
    # RFC 5780 that is fatal: RESPONSE-ORIGIN is the only way to tell a
    # server that honoured CHANGE-REQUEST from one that ignored it, and
    # servers are free to put the attributes in any order. Reading it as
    # absent made every such server look permissive.
    attrs = data[20:]
    p = 0
    best = None
    xored = None
    while p + 4 <= len(attrs):
        a, l = struct.unpack_from(">HH", attrs, p)
        v = attrs[p + 4:p + 4 + l]
        if out is not None and a in (RESPONSE_ORIGIN, OTHER_ADDRESS) \
                and len(v) >= 8:
            # family byte is v[1]: 1 = v4. Anything else we cannot use.
            if v[1] == 1:
                o_port = struct.unpack_from(">H", v, 2)[0]
                o_ip = ".".join(str(b) for b in v[4:8])
                key = ("origin" if a == RESPONSE_ORIGIN else "other")
                out[key] = (o_ip, o_port)
        if a == 0x0020 and len(v) >= 8:      # XOR-MAPPED, preferred
            port = struct.unpack_from(">H", v, 2)[0] ^ (STUN_MAGIC_INT >> 16)
            ip = ".".join(str(v[4 + i] ^ STUN_MAGIC[i]) for i in range(4))
            xored = (ip, port)
            if out is not None:
                out["mapped"] = xored
        elif a == 0x0001 and len(v) >= 8 and best is None:
            port = struct.unpack_from(">H", v, 2)[0]
            best = (".".join(str(b) for b in v[4:8]), port)
            if out is not None and "mapped" not in out:
                out["mapped"] = best
        p += 4 + ((l + 3) & ~3)
    return xored or best


def _stun_once(sock, host, port, timeout, hub=None, change=0, info=None):
    """One STUN binding request from `sock`. Returns (ip, port) or None.

    `sock` MUST be the punch socket: a symmetric NAT hands out a different
    mapping per destination, so a mapping learned elsewhere is useless.

    When `hub` is given the reply is collected by the hub thread instead of
    by a second recvfrom() on the same socket (see UdpHub.exchange).

    `change` is an RFC 5780 CHANGE-REQUEST: ask the server to answer from a
    different port and/or IP. When it is set the reply no longer comes from
    `addr`, so matching by source address would drop the very answer we
    asked for -- the transaction id is then the only thing we can match on,
    which is safe because it is 12 random bytes.

    `info` (a dict) receives RESPONSE-ORIGIN / OTHER-ADDRESS when present,
    which is how we tell a server that honoured CHANGE-REQUEST from one
    that silently ignored it.

    Never leaves a socket timeout behind: this socket is shared with the
    tunnel reader, and a stray timeout silently kills it.
    """
    try:
        txid = os.urandom(12)
        body = b""
        if change:
            body = struct.pack(">HHI", CHANGE_REQUEST, 4, change)
        msg = (struct.pack(">HH", 0x0001, len(body)) + STUN_MAGIC + txid
               + body)
        addr = (socket.gethostbyname(host), port)

        # With CHANGE-REQUEST the answer may legitimately arrive from
        # anywhere, so match on the transaction alone.
        strict_src = not change

        if hub is not None:
            # Where the answer really came from is recorded too, not just
            # what the server claims about it -- see _answered_from_elsewhere
            # for why an unverifiable answer must not count as permission.
            seen = {}

            def _match(d, a, _t=txid, _s=strict_src, _addr=addr):
                if len(d) < 20 or d[8:20] != _t or d[4:8] != STUN_MAGIC:
                    return False
                ok = (a[0] == _addr[0]) if _s else True
                if ok:
                    seen["src"] = (a[0], a[1])
                return ok

            data = hub.exchange(msg, addr, timeout, _match)
            if not data:
                return None
            if info is not None and seen.get("src"):
                info["src"] = seen["src"]
            return _stun_parse(data, txid, info)

        prev = sock.gettimeout()
        try:
            sock.settimeout(timeout)
            sock.sendto(msg, addr)
            deadline = time.monotonic() + timeout
            while True:
                left = deadline - time.monotonic()
                if left <= 0:
                    return None
                sock.settimeout(left)
                data, src = sock.recvfrom(2048)
                if strict_src and src[0] != addr[0]:
                    continue            # not our server; ignore
                got = _stun_parse(data, txid, info)
                if got:
                    if info is not None:
                        try:
                            info["src"] = (src[0], src[1])
                        except Exception:
                            pass
                    return got
        except socket.timeout:
            return None
        except Exception:
            return None
        finally:
            try:
                sock.settimeout(prev)
            except Exception:
                pass
    except Exception:
        return None
    return None


def stun_mapped_address(sock, timeout=3.0, servers=None, hub=None):
    """Tiny STUN binding request. Returns (ip, port) or None."""
    for host, port in (servers if servers is not None else STUN_SERVERS):
        got = _stun_once(sock, host, port, timeout, hub=hub)
        if got:
            return got
    return None


def _answered_from_elsewhere(info, server, want_ip, want_port):
    """Did the server really answer from a different place?

    A server that does not implement RFC 5780 simply IGNORES
    CHANGE-REQUEST and answers from where it always answers. That answer
    gets through any NAT -- we just sent there -- so it would be read as
    proof of a permissive NAT when it proves nothing at all.

    RESPONSE-ORIGIN tells us where the answer actually came from, so we can
    tell the two apart, and so does the source address of the datagram we
    received -- which every server gives us, whether it speaks RFC 5780 or
    not.

    When NEITHER is available there is no evidence, and an unverifiable
    answer must not be counted as permission. This is how a real log came
    to say, about a host that drops every unsolicited packet:

        [NAT] stun.miwifi.com ignored CHANGE-REQUEST; filtering unknown
        [NAT] filtering: endpoint-independent (anything may come in)

    i.e. one server honestly reported "I ignored that", and the next one
    was believed without evidence. "The door is already open" then decided
    the whole punch strategy -- the side that should have been sending to
    the peer first sat still and waited to be found instead.

    Being wrong towards "unknown" costs a little optimism; being wrong
    towards "eif" costs the connection.
    """
    origin = info.get("origin") or info.get("src")
    if not origin:
        return False         # no evidence -> not evidence of permissiveness
    if want_ip and origin[0] == server[0]:
        return False         # did not change IP
    if want_port and origin[1] == server[1]:
        return False         # did not change port
    return True


def stun_filtering(sock, host, port, timeout=1.5, hub=None, log=None,
                   deadline=None):
    """RFC 5780 filtering behaviour: what does the NAT let back IN?

    Mapping behaviour (what everything else here measures) tells us which
    external port a flow gets. It says NOTHING about which inbound packets
    survive -- and that is the other half of whether a hole can be punched
    at all.

    Three tests, in order:
      I   plain binding request          -> proves the server is reachable
      II  CHANGE-REQUEST ip+port         -> answer means traffic from a host
                                            we never contacted gets through
      III CHANGE-REQUEST port only       -> answer means traffic from a host
                                            we DID contact gets through,
                                            from any port

    Why this is worth three more packets: it decides who has to speak first.
    A NAT that filters per-destination drops the peer's packets until we
    have sent to that exact address ourselves. If both ends wait for the
    other, nothing ever arrives. Knowing which end is stricter tells us
    which one must open the door.
    """
    try:
        server_ip = socket.gethostbyname(host)
    except Exception:
        return FILTER_UNKNOWN
    server = (server_ip, port)

    # One budget for all three tests. Each has its own timeout, but three
    # unreachable servers in a row used to stack into ~14s of dead time on
    # the startup path -- and on a network where UDP is blocked entirely,
    # that is time spent measuring nothing.
    if deadline is None:
        deadline = time.monotonic() + timeout * 4

    def _left():
        return max(0.05, deadline - time.monotonic())

    # Test I
    info = {}
    if not _stun_once(sock, host, port, min(timeout, _left()), hub=hub,
                      info=info):
        return FILTER_UNKNOWN

    # No translation at all: nothing is being filtered.
    mapped = info.get("mapped")
    if mapped and mapped[0] == server_ip and mapped[1] == port:
        return FILTER_EIF

    # Test II -- change IP *and* port
    i2 = {}
    got2 = _stun_once(sock, host, port, min(timeout, _left()), hub=hub,
                      change=(CHANGE_IP | CHANGE_PORT), info=i2)
    if got2 and _answered_from_elsewhere(i2, server, True, True):
        return FILTER_EIF

    # Test III -- change port only
    i3 = {}
    got3 = _stun_once(sock, host, port, min(timeout, _left()), hub=hub,
                      change=CHANGE_PORT, info=i3)
    if got3 and _answered_from_elsewhere(i3, server, False, True):
        return FILTER_ADF

    if got2 or got3:
        # Something answered but did not actually change, so the server
        # ignored us: this is not evidence of strict filtering, just of a
        # server that does not speak RFC 5780.
        if log:
            try:
                log("[NAT] %s ignored CHANGE-REQUEST; filtering unknown"
                    % host)
            except Exception:
                pass
        return FILTER_UNKNOWN
    return FILTER_APDF


def stun_order(servers):
    """Order candidates so the first two ANSWERS are likely different IPs.

    NAT typing compares the mapped port seen by two destinations. If both
    destinations share an IP -- e.g. the built-in STUN on 3478/3479 -- a NAT
    that allocates per destination *IP* reports the same port for both, and
    gets misclassified as cone. That is the common CGNAT case, and the
    misclassification silently disables port prediction for exactly the
    users who need it.

    The whole list comes back, NOT just a pair of endpoints: stun_probe
    keeps asking until two servers have answered, because a pair chosen up
    front left nothing to fall back on when one of the two was unreachable
    -- one sample means NAT_UNKNOWN and no prediction at all, which is
    exactly what happened with a reachable built-in STUN plus a blocked
    public one.

    Order: EVERY entry of the first IP first, then round-robin across the
    remaining IPs (one each, then a second each, ...).

    Strict round-robin used to interleave the first entry of every IP
    before the second entry of ANY, which put the operator's second
    built-in port behind every public server on the list. When those are
    unreachable -- the normal case in mainland China, and the exact reason
    the built-in STUN exists -- the budget ran out before that second port
    was ever asked, so the client got one sample, reported NAT_UNKNOWN, and
    switched port prediction off for precisely the deployment it was built
    for.

    Asking two ports on the SAME IP is still a real measurement: it does
    not separate per-IP allocation from cone, but it does detect the common
    case, per-destination-port allocation. Two samples from one reachable
    server beat one sample plus a timeout.
    """
    by_ip = {}
    order = []
    for entry in servers:
        if entry[0] not in by_ip:
            by_ip[entry[0]] = []
            order.append(entry[0])
        by_ip[entry[0]].append(entry)
    if not order:
        return []
    out = list(by_ip[order[0]])          # the operator's own server, all of it
    rest = [by_ip[ip] for ip in order[1:]]
    idx = 0
    while True:
        rung = [lst[idx] for lst in rest if idx < len(lst)]
        if not rung:
            return out
        out.extend(rung)
        idx += 1


def _third_probe(host, port, timeout):
    """What mapping does a brand NEW socket get from a server we asked?

    This is the measurement that separates "predictable NAT4" from "hopeless
    NAT4", and it is the one that is almost always missing. Comparing two
    servers on ONE socket only tells you the mapping depends on the
    destination. Asking the same server from a SECOND socket tells you where
    the next mapping lands -- and "next" is precisely what the peer has to
    guess when it punches.

    A throwaway socket is correct here: we are measuring the NAT's
    allocation behaviour, not a mapping we intend to use.
    """
    return _third_probes(host, port, timeout, 1)[0]


def _third_probes(host, port, timeout, n=3, want=None):
    """Several samples of "what does the NEXT mapping look like".

    One sample is not trustworthy. Between two probes the machine may open
    any number of unrelated UDP flows (DNS, QUIC, a game, a browser), and
    every one of them consumes an allocation slot -- so a single reading
    can be arbitrarily far from the real step, and a far reading means
    "hopeless NAT4", i.e. we give up on the connection.

    Extra slots can only make the observed gap LARGER, never smaller, so the
    smallest gap across samples is the best estimate of the true step.

    `n` is how many to gather, and it governs both the attempt count and
    the early exit. There used to be a separate `want` that only moved the
    exit point, so asking for 4 while attempting 3 still yielded 3 -- the
    background re-check asked for more samples than the connect path and
    quietly got the same number.

    Small n on the connect path (the user is watching), larger off it
    (nothing is waiting, and every extra sample is another chance to see
    the true step behind the machine's other traffic).
    """
    if want is None:
        want = n
    out = []
    # Total budget for the whole sampling run, not per sample. When the
    # server is unreachable every probe runs to its full timeout, so three
    # samples meant 4.5s of dead time on every connect -- and on a
    # reconnect, where the user is already waiting, that is very visible.
    deadline = time.monotonic() + max(0.5, min(timeout, 3.0))
    for _ in range(max(1, n)):
        left = deadline - time.monotonic()
        if left <= 0:
            break
        tmp = None
        try:
            tmp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            tmp.bind(("", 0))
            got = _stun_once(tmp, host, port, min(1.5, left))
            if got:
                out.append(got[1])
        except Exception:
            pass
        finally:
            if tmp is not None:
                try:
                    tmp.close()
                except Exception:
                    pass
        if len(out) >= max(2, want):
            # Enough samples to trust the step. Two is right on the
            # connect path, where asking more costs latency the user can
            # see; a background re-check has time to spare and should take
            # more, because every extra sample is another chance to catch
            # the true step behind the noise of the machine's other flows.
            break
    return out


def stun_probe(sock, timeout=3.0, servers=None, hub=None, want=2, log=None):
    got = stun_probe2(sock, timeout=timeout, servers=servers, hub=hub,
                      want=want, log=log)
    if not got:
        return None
    return got[0], got[1], got[2], got[3]


def stun_probe2(sock, timeout=3.0, servers=None, hub=None, want=2, log=None,
                third_n=None, extra=None):
    """stun_probe plus a NAT subtype. Returns (ip, port, nat, delta, subtype).

    The 4-tuple form is kept for every existing caller; this one exists
    because "symmetric" is not an answer, it is a question. See
    natpunch.refine_nat_subtype.

    `third_n`: how many "where does the next port land" samples to gather
    before deciding. More samples make a downgrade to "random" less likely
    to be a fluke, at the cost of time -- so it is worth it off the connect
    path, and not worth it on it.
    """
    return _stun_probe_full(sock, timeout, servers, hub, want, log,
                            third_n=third_n, extra=extra)


def _stun_probe_full(sock, timeout, servers, hub, want, log, third_n=None,
                     extra=None):
    """Endpoint discovery + NAT type. Returns (ip, port, nat_type, delta).

    Asks two DIFFERENT STUN destinations from the SAME socket:
      * same mapped port for both  -> cone NAT (one mapping, every peer sees
        the same endpoint, so a single target port is enough)
      * different ports            -> symmetric NAT (a fresh mapping per
        destination), and the difference is the allocation increment.

    The port reported is the LAST one: on a symmetric NAT it is the closest
    to whatever the next allocation will be.

    It keeps going down the list until `want` servers have ANSWERED (or the
    budget runs out) rather than committing to two endpoints up front: a
    silent server must not cost us the second sample.
    """
    pool = stun_order(list(servers if servers is not None else STUN_SERVERS))
    if not pool:
        return None

    results = []      # [(mapped_ip, mapped_port), server_host, server_port]
    # Hard budget: 16 servers x 3s would be ~48s of apparent hang on a
    # network that blocks UDP. Two answers are all we need -- but they have
    # to be two real answers, hence the retry loop above.
    deadline = time.monotonic() + STUN_BUDGET_S
    for host, port in pool:
        if len(results) >= want:
            break
        left = deadline - time.monotonic()
        if left <= 0.05:
            break
        got = _stun_once(sock, host, port, min(timeout, left), hub=hub)
        if got:
            # got is the MAPPED (public) endpoint; (host, port) is the
            # SERVER we asked. Keep both -- conflating them is what sent the
            # third probe to the mapped port instead of the server, where
            # nothing listens, so it always timed out and every symmetric
            # NAT was mis-classified as unsolvable.
            results.append((got, host, port))
    if not results:
        return None

    ip, port = results[-1][0]
    if len(results) < 2:
        # Only one server ever answered, so there is nothing to compare
        # against: the NAT type is genuinely unknown and prediction stays
        # off. Say so, because "unknown" here usually means "one of your
        # STUN servers is unreachable", which is fixable.
        if log:
            try:
                log("[NAT] only %d STUN server answered (%s) -> unknown type"
                    % (len(results), ", ".join(sorted(r[1] for r in results))))
            except Exception:
                pass
        return ip, port, NAT_UNKNOWN, 1, NAT_SUB_UNKNOWN

    hosts = {r[1] for r in results}
    ports = [r[0][1] for r in results]   # mapped ports
    delta = ports[-1] - ports[0]

    # Separate port region per destination IP?
    #
    # Real log, one machine: two DIFFERENT STUN IPs reported 47524 and
    # 41105 -- 6419 apart. That is not a step, it is two pools, so the
    # port this NAT will use for the peer (an address we have never sent
    # to) is in a region nothing we measured points at. A contiguous
    # window around its published port then cannot hit, no matter how
    # wide: it is aimed at the STUN pool.
    #
    # Flagged rather than folded into the subtype, because the subtype
    # describes the allocator WITHIN one destination (which really is
    # sequential -- "+35" per flow) and that is still useful. What is
    # unusable is the window, so the scan mixes in random ports instead.
    if isinstance(extra, dict):
        extra["per_ip_pool"] = bool(abs(delta) > PER_IP_POOL_GAP)
        extra["sample_ports"] = list(ports)
        extra["sample_hosts"] = sorted(hosts)
    if abs(delta) > PER_IP_POOL_GAP and log:
        try:
            log("[NAT] two different STUN IPs gave ports %s (%d apart): "
                "this NAT allocates a separate port region per destination "
                "IP, so the port it will use for the peer is NOT near the "
                "one it published. Mixing random ports into the scan."
                % (ports, abs(delta)))
        except Exception:
            pass

    # WHAT KIND of gap is `delta`? It decides whether prediction applies
    # to the peer at all, and getting this wrong silently disables every
    # mechanism.
    #
    # Punching needs to predict the port we get for a brand NEW
    # destination -- the peer's IP, which we have never sent to. So the
    # only relevant measurement is the gap between two DIFFERENT server
    # IPs. A gap between two ports of the SAME IP says "consecutive flows
    # to one host differ by this much", which tells us nothing about a new
    # host.
    #
    # Real log, one machine, seconds apart:
    #
    #   09:01:24  two ports of ONE ip -> 44019, 44020   (gap 1)
    #   09:01:27  two DIFFERENT ips   -> 44020, 7647    (gap -36373)
    #
    # Same NAT. Reading the first as "sequential, therefore predictable"
    # is what made the scan aim at 44020..49940 while the array actually
    # opened in a completely different region -- 10,600 packets, none of
    # which could ever arrive.
    same_ip_gap = len(hosts) < 2
    if same_ip_gap and log:
        try:
            log("[NAT] both samples came from one IP (%s): the step "
                "between them describes consecutive flows to ONE host, "
                "not what a brand-new destination gets -- the peer's "
                "address is a brand-new destination"
                % ",".join(sorted(hosts)))
        except Exception:
            pass

    # Diagnosed but not treated, which is worse than either: the log line
    # above says the step is meaningless for a new destination, and then
    # the code went ahead and published it anyway.
    #
    # Real log, one machine:
    #
    #   09:01:24  two ports of ONE ip -> 44019, 44020   (step 1)
    #   09:01:27  two DIFFERENT ips   -> 44020, 7647    (a different region)
    #
    # Publishing "sym_easy_inc, delta 1" from the first line sends every
    # peer to walk 44020, 44021, 44022... while our array opens somewhere
    # else entirely. Measured: 10600 packets, none of which could arrive.
    #
    # With one IP there is no way to tell "sequential overall" from
    # "sequential within one host", so the honest answer is UNKNOWN --
    # and that is not a downgrade, because _punch_plan_for upgrades
    # unknown to a real mechanism (the array still runs), whereas a wrong
    # subtype sends the array to the wrong place.
    if same_ip_gap:
        # One IP, two ports: this is exactly openp2p's test, and it is
        # enough to tell cone from symmetric.
        #
        #   nat.go:  port1 == port2  ->  NATCone   else NATSymmetric
        #
        # It asks one question only: does changing the DESTINATION PORT
        # change the mapping? If not, every peer sees the same endpoint,
        # which is the definition of cone. If it does, the mapping is
        # per-flow and the peer's port is not the one we published.
        #
        # Returning UNKNOWN here was the wrong call, and it is why a cone
        # peer behind a server with only one STUN endpoint could never be
        # recognised as cone: the openp2p handshakes are chosen purely on
        # cone-vs-symmetric, so "unknown" silently disabled all three.
        if delta == 0:
            if log:
                try:
                    log("[NAT] cone: the same mapped port %s answered for "
                        "two destination ports of one IP, so every peer "
                        "sees this endpoint" % (port,))
                except Exception:
                    pass
            return ip, port, NAT_CONE, 0, NAT_SUB_CONE
        # Different port per destination port: symmetric. The STEP is
        # still not generalisable (see above) -- only the class is.
        if log:
            try:
                log("[NAT] symmetric: two destination ports of one IP got "
                    "mapped ports %s, so the mapping is per-flow"
                    % (ports,))
            except Exception:
                pass
        return ip, port, NAT_SYMMETRIC, 0, NAT_SUB_HARD

    # Only worth spending a round trip on when the first two disagree --
    # otherwise there is nothing to refine.
    #
    # Imported here, not at module scope: natpunch pulls in udptunnel, and a
    # top-level import would make common <-> natpunch circular.
    from natpunch import refine_nat_subtype, nat_step

    p3 = None
    p3s = []
    if delta != 0:
        # Ask a server we ALREADY reached, from a brand new socket. The
        # server's own (host, port) -- not the mapped port from its reply.
        first_host, first_port = pool[0]
        for r in results:
            if r[1] == first_host:
                first_host, first_port = r[1], r[2]
                break
        p3s = _third_probes(first_host, first_port, timeout,
                            n=(third_n or THIRD_PROBE_MIN_SAMPLES))
        p3 = p3s[0] if p3s else None
    sub = refine_nat_subtype(ports[0], ports[-1], p3s)
    # The step comes from p3, not from the two-destination gap. Publishing
    # the gap (measured: 167 for a NAT whose step was 1) tells every peer
    # to walk the wrong distance.
    step = nat_step(ports[0], ports[-1], p3s)
    if step:
        delta = step
    if log:
        try:
            log("[NAT] %s (ports %s, next from a new socket: %s)"
                % (sub, ports, p3))
        except Exception:
            pass

    if delta == 0:
        # "Same port for two ports of the same host" is consistent with a
        # cone NAT AND with a NAT that allocates per destination IP -- and
        # with only ONE server to ask, the two are indistinguishable.
        #
        # It used to return cone here. That is the single most damaging
        # verdict in the whole program, because cone switches the entire
        # NAT4 mechanism off:
        #
        #   punch_plan(cone, *)      -> METHOD_CONE
        #   _multi_socket_first()    -> False   (no array, no window)
        #   _await_punch_start()     -> returns without waiting
        #   _refresh_anchor_if_stale -> never called
        #   _should_scan_window()    -> False
        #
        # leaving one socket aimed at the port the peer published for ITS
        # STUN server -- which a per-destination NAT drops on sight. The
        # user sees "cannot connect" and no punch ever ran.
        #
        # With several distinct IPs answering, delta == 0 really does mean
        # cone: a per-destination-IP allocator would have given different
        # ports to different IPs. Only the single-IP case is ambiguous, and
        # there UNKNOWN is right -- _punch_plan_for upgrades unknown to a
        # real mechanism, so the array still runs, whereas cone does not.
        if len(hosts) < 2:
            if log:
                try:
                    log("[NAT] both STUN answers came from one IP (%s): a "
                        "NAT that allocates per destination IP looks "
                        "identical to a cone NAT here -- reporting UNKNOWN "
                        "so punching still runs"
                        % ",".join(sorted(hosts)))
                except Exception:
                    pass
            return ip, port, NAT_UNKNOWN, 0, NAT_SUB_UNKNOWN
        return ip, port, NAT_CONE, 0, NAT_SUB_CONE
    if abs(delta) > SYM_MAX_DELTA:
        # allocation is not sequential -- prediction is pointless
        return ip, port, NAT_SYMMETRIC, 0, NAT_SUB_HARD
    return ip, port, NAT_SYMMETRIC, delta, sub


def predicted_ports(base_port, delta, count):
    """Contiguous ports to spray, one direction, starting one step out.

    CONTIGUOUS, not "base + k*delta". Stepping by the measured delta was the
    reason symmetric NATs never punched: with a measured step of 7 it tried
    +7 +14 +21 ..., while a sequential allocator's very next mapping is +1.
    The step tells us the DIRECTION, not the stride -- so we walk every port
    in between and let the direction decide which way.

    A negative delta simply walks downwards, so the sign is preserved
    rather than folded away with abs().
    """
    step = 1 if (delta or 1) > 0 else -1
    if abs(delta or 0) > SYM_MAX_DELTA:
        step = 1 if delta > 0 else -1
    out, seen = [], set()
    for k in range(1, count + 1):
        cand = base_port + k * step
        if 1024 <= cand <= 65535 and cand not in seen:
            seen.add(cand)
            out.append(cand)
    return out


def test_server(url, timeout=6.0):
    """TCP-connect to the signalling server and report the round trip.

    Returns (ok, message, rtt_ms). Only proves the port is reachable —
    it does not do a WebSocket handshake.
    """
    import re as _re
    m = _re.match(r"(?:ws|wss|http|https)://([^:/]+)(?::(\d+))?", (url or "").strip())
    if not m:
        return False, "服务器地址格式不对（示例：ws://1.2.3.4:5000/ws）", None
    host = m.group(1)
    port = int(m.group(2)) if m.group(2) else 80
    t0 = time.time()
    try:
        s = socket.create_connection((host, port), timeout=timeout)
    except Exception as e:
        return False, "无法连接 %s:%d（%s）" % (host, port, type(e).__name__), None
    rtt = (time.time() - t0) * 1000.0
    try:
        s.close()
    except Exception:
        pass
    return True, "服务器可达 %s:%d" % (host, port), rtt


def build_manual_address(text, bound_port, log=print):
    """'1.2.3.4' -> '1.2.3.4:bound'; '1.2.3.4:30000' -> unchanged."""
    s = (text or "").strip()
    if not s:
        return ""
    for pfx in ("ws://", "wss://", "http://", "https://"):
        if s.lower().startswith(pfx):
            s = s[len(pfx):]
            break
    s = s.strip().rstrip("/")
    if ":" in s:
        host, _, port = s.rpartition(":")
        if host and port.isdigit() and 0 < int(port) < 65536:
            if int(port) != bound_port:
                try:
                    log("[warn] manual port %s differs from bound port %d; "
                        "unless your router forwards %s->%d the peer cannot reach you"
                        % (port, bound_port, port, bound_port))
                except Exception:
                    pass
            return "%s:%s" % (host, port)
    return "%s:%d" % (s, bound_port)
