#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MCLanP2P signaling server — pure Python standard library, zero pip install.

Why stdlib only: the previous .NET version burned a lot of time on SDK /
NuGet / build issues. Python 3 is present on virtually every Linux box, so
this server runs the moment it's copied over.

What it does
  * WebSocket signaling (rooms, members, punch coordination)
  * Binary-frame game data relay (the always-works fallback path)

Protocol is kept identical to the previous C# server so old clients still work.
"""
import asyncio
import base64
import hashlib
import json
import logging
import os
import random
import signal
import socket
import struct
import sys

# The client defines its constants in protocol.py; import it rather than
# restating any of them, so a probe packet cannot drift out of sync between
# the two ends.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "client"))
try:
    from protocol import INBOUND_PROBE_PACKET
except Exception:                                    # pragma: no cover
    INBOUND_PROBE_PACKET = b"MCLANP2P-INBOUND-PROBE"
import sys
import time

# ---------------------------------------------------------------- config

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "client"))

PORT = int(os.environ.get("PORT") or 5000)

# Built-in STUN. Two ports on purpose: NAT-type detection needs two
# DIFFERENT destinations to tell a cone NAT (same mapped port for both)
# from a symmetric one (a fresh port per destination, and the difference is
# the allocation step we later use to predict ports).
#
# Set STUN_PORT=0 to disable (e.g. UDP is not allowed on this host).
STUN_PORT = int(os.environ.get("STUN_PORT") or 3478)
STUN_PORT2 = int(os.environ.get("STUN_PORT2") or (STUN_PORT + 1 if STUN_PORT else 0))

# How this server tells clients where its STUN lives. Auto-detected from
# the environment, overridable for odd setups (port-forwarded box, ...).
STUN_HOST = os.environ.get("STUN_HOST") or ""

# Reverse-proxy support (nginx + Let's Encrypt, which the README recommends
# for TLS).
#
# Behind a proxy every connection's peername is the proxy itself, so the
# per-IP join limiter would be shared by EVERY player -- one room's normal
# reconnects could lock complete strangers out. So we honour
# X-Forwarded-For, but only from proxies listed here.
#
# Trusting the header unconditionally would be worse than ignoring it:
# X-Forwarded-For is client-supplied text, and an attacker would simply
# invent a new address per connection to get a fresh quota. Set this to the
# proxy's address (e.g. TRUSTED_PROXIES=127.0.0.1) and nothing else.
TRUSTED_PROXIES = tuple(
    p.strip() for p in (os.environ.get("TRUSTED_PROXIES") or "").split(",")
    if p.strip())


def _default_log_file():
    """Where to put the log file, per platform.

    /var/log is the right answer on the Linux box this is meant to be
    deployed to, and the wrong one everywhere else: on Windows the same
    string resolves to `E:\\var\\log\\mc-p2p.log`, which does not exist,
    so every single-machine run printed

        cannot write /var/log/mc-p2p.log: [Errno 2] No such file or
        directory: 'E:\\var\\log\\mc-p2p.log' (logging to stdout only)

    as the first line of its output -- harmless, but it reads like a
    fault and it is the first thing anyone asks about.

    Set LOG_FILE to override either way, or LOG_FILE= to disable the
    file handler entirely and keep stdout only.
    """
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or os.path.dirname(
            os.path.abspath(__file__))
        return os.path.join(base, "MCLanP2P", "server.log")
    return "/var/log/mc-p2p.log"


_env_log = os.environ.get("LOG_FILE")
LOG_FILE = (_env_log if _env_log is not None else _default_log_file())

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s.%(msecs)03d] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("mc-p2p")
if LOG_FILE:
    try:
        _dir = os.path.dirname(LOG_FILE)
        if _dir:
            os.makedirs(_dir, exist_ok=True)
        _fh = logging.FileHandler(LOG_FILE, encoding="utf-8")
        _fh.setFormatter(
            logging.Formatter("[%(asctime)s.%(msecs)03d] %(message)s",
                              "%Y-%m-%d %H:%M:%S"))
        log.addHandler(_fh)
    except Exception as e:
        log.warning("cannot write %s: %s (logging to stdout only)",
                    LOG_FILE, e)

# ------------------------------------------------------- WebSocket (RFC 6455)

WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
OP_CONT, OP_TEXT, OP_BINARY = 0x0, 0x1, 0x2
OP_CLOSE, OP_PING, OP_PONG = 0x8, 0x9, 0xA


class WSError(Exception):
    pass


async def read_http_headers(reader):
    """Read request line + headers up to the blank line."""
    request_line = await reader.readline()
    if not request_line:
        return None, {}
    headers = {}
    while True:
        line = await reader.readline()
        if not line or line in (b"\r\n", b"\n"):
            break
        try:
            k, _, v = line.decode("latin1").partition(":")
            headers[k.strip().lower()] = v.strip()
        except Exception:
            break
    return request_line, headers


def ws_accept_key(key):
    return base64.b64encode(hashlib.sha1((key + WS_GUID).encode()).digest()).decode()


def is_ip(text):
    """True for a literal IPv4/IPv6 address. Used to validate a header."""
    if not text or len(text) > 45:
        return False
    for fam in (socket.AF_INET, socket.AF_INET6):
        try:
            socket.inet_pton(fam, text)
            return True
        except (OSError, ValueError):
            continue
    return False


def client_ip_for(writer, headers):
    """The address to rate-limit on.

    Direct deployment: the socket's peer. Behind a TRUSTED proxy: the
    left-most X-Forwarded-For entry, because everything else sees only the
    proxy. Anything unrecognised falls back to the socket address -- never
    to a header we do not trust.
    """
    peer = writer.get_extra_info("peername")
    # never empty: the caller treats "" as "handshake failed"
    sock_ip = str(peer[0]) if peer else "unknown"
    if not TRUSTED_PROXIES or sock_ip not in TRUSTED_PROXIES:
        return sock_ip
    raw = headers.get("x-forwarded-for") or ""
    first = raw.split(",")[0].strip() if raw else ""
    if not first:
        return sock_ip
    # strip an optional port: "1.2.3.4:5678" or "[2001:db8::1]:5678"
    if first.startswith("["):
        host = first[1:].split("]")[0]
    elif first.count(":") == 1:
        host = first.split(":")[0]
    else:
        host = first
    if not is_ip(host):
        log.warning("ignoring malformed X-Forwarded-For %r", raw[:80])
        return sock_ip
    return host


async def ws_handshake(reader, writer):
    """Returns the client IP to rate-limit on, or "" if the upgrade failed.

    Returning the address rather than a bool keeps the caller's
    `if not await ws_handshake(...)` check working while carrying out the
    one thing only the handshake knows: the request headers.
    """
    req, headers = await read_http_headers(reader)
    if not req:
        return ""
    key = headers.get("sec-websocket-key")
    if not key:
        writer.write(b"HTTP/1.1 400 Bad Request\r\n\r\n")
        await writer.drain()
        return ""
    body = (
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Accept: {ws_accept_key(key)}\r\n\r\n"
    )
    writer.write(body.encode())
    await writer.drain()
    return client_ip_for(writer, headers)


# Size caps.
#
# What matters is the TOTAL assembled message, not each fragment: capping
# fragments individually lets 1000 x 8MB continuations accumulate into 8GB
# of resident memory before anything is ever checked.
# How far in the future the shared punch deadline is set. Long enough that
# a slow peer still receives its start_punch before the deadline passes,
# short enough not to be noticed by the user.
PUNCH_START_DELAY_S = 1.5

ZERO_MASK = b"\x00\x00\x00\x00"
MAX_MESSAGE = 8 * 1024 * 1024      # 8 MB per assembled message
MAX_CONTROL = 125                  # RFC 6455: control frames are <= 125
MAX_FRAGMENTS = 1024               # no unbounded fragment chains


async def read_frame(reader, max_payload=MAX_MESSAGE):
    """Read one frame. Returns (opcode, payload_bytes). Handles fragmentation."""
    opcode, payload = None, bytearray()
    total = 0
    fragments = 0
    while True:
        try:
            hdr = await reader.readexactly(2)
        except asyncio.IncompleteReadError:
            raise WSError("closed")
        b0, b1 = hdr[0], hdr[1]
        fin = bool(b0 & 0x80)
        rsv = b0 & 0x70
        op = b0 & 0x0F
        if rsv:
            # No extension is negotiated, so an RSV bit means a protocol
            # error -- or that we have lost sync. Either way, stop.
            raise WSError("RSV bits set")
        masked = bool(b1 & 0x80)
        length = b1 & 0x7F
        if length == 126:
            length = struct.unpack(">H", await reader.readexactly(2))[0]
        elif length == 127:
            length = struct.unpack(">Q", await reader.readexactly(8))[0]
        if length > max_payload:
            raise WSError("frame too large")
        if op in (OP_PING, OP_PONG, OP_CLOSE) and length > MAX_CONTROL:
            raise WSError("control frame too large")
        mask = await reader.readexactly(4) if masked else ZERO_MASK
        data = await reader.readexactly(length) if length else b""
        if masked:
            data = bytes(b ^ mask[i & 3] for i, b in enumerate(data))

        if op in (OP_TEXT, OP_BINARY):
            opcode = op
        elif op == OP_CONT:
            if opcode is None:
                raise WSError("continuation without start")
            fragments += 1
            if fragments > MAX_FRAGMENTS:
                raise WSError("too many fragments")
        else:
            return op, data  # control frames are never fragmented

        total += len(data)
        if total > max_payload:
            raise WSError("message too large")
        payload += data
        if fin:
            return opcode, bytes(payload)


def encode_frame(opcode, payload, mask=False):
    """Encode a frame. Server->client must NOT mask; clients MUST mask."""
    header = bytearray([0x80 | opcode])
    n = len(payload)
    mask_bit = 0x80 if mask else 0
    if n < 126:
        header.append(mask_bit | n)
    elif n < 65536:
        header.append(mask_bit | 126)
        header += struct.pack(">H", n)
    else:
        header.append(mask_bit | 127)
        header += struct.pack(">Q", n)
    if mask:
        key = os.urandom(4)
        body = bytes(b ^ key[i & 3] for i, b in enumerate(payload))
        return bytes(header) + key + body
    return bytes(header) + payload


# ---------------------------------------------------------------- state


# ============================================================
# STUN (RFC 5389 binding request, server side)
# ============================================================
#
# Why the signalling server also runs STUN:
#
# Public STUN servers are unreliable from China, and a client that cannot
# reach ANY of them falls back to its LAN address -- which no peer outside
# that LAN can ever connect to. That single failure made direct P2P look
# "broken" even on networks where a hole punch would have worked.
#
# Running our own on the VPS makes endpoint discovery depend only on the
# one host the client is already talking to.
#
# Only the binding request is implemented -- that is all endpoint discovery
# needs. No CHANGE_REQUEST, so no RFC 3489 NAT classification; the client
# infers what it needs by comparing two bindings instead.

STUN_MAGIC = b"\x21\x12\xa4\x42"
STUN_BINDING_REQUEST = 0x0001
STUN_BINDING_RESPONSE = 0x0101
STUN_BINDING_ERROR = 0x0111
STUN_ATTR_MAPPED_ADDRESS = 0x0001
STUN_ATTR_XOR_MAPPED_ADDRESS = 0x0020
STUN_ATTR_SOFTWARE = 0x8022


def _stun_attr(kind, value):
    return struct.pack(">HH", kind, len(value)) + value


def stun_binding_response(txid, addr):
    """Build a success response carrying the peer's public endpoint."""
    ip, port = addr[0], addr[1]
    try:
        packed = socket.inet_pton(socket.AF_INET, ip)
        family = 0x01
    except (OSError, ValueError):
        # IPv6 client: report it back verbatim
        try:
            packed = socket.inet_pton(socket.AF_INET6, ip)
            family = 0x02
        except (OSError, ValueError):
            return _stun_error(txid, 400)
    mapped = struct.pack(">BBH", 0, family, port) + packed

    # XOR-MAPPED-ADDRESS: obfuscated so a NAT that rewrites the payload
    # cannot mangle it. Port XORs with the top half of the cookie.
    xport = port ^ 0x2112
    xpacked = bytes(packed[i] ^ STUN_MAGIC[i] for i in range(len(packed)))
    xmapped = struct.pack(">BBH", 0, family, xport) + xpacked

    body = (_stun_attr(STUN_ATTR_MAPPED_ADDRESS, mapped)
            + _stun_attr(STUN_ATTR_XOR_MAPPED_ADDRESS, xmapped)
            + _stun_attr(STUN_ATTR_SOFTWARE, b"mclanp2p"))
    return (struct.pack(">HH", STUN_BINDING_RESPONSE, len(body))
            + STUN_MAGIC + txid + body)


def _stun_error(txid, code):
    reason = b"bad request"
    body = struct.pack(">HHI", 0, code, 0)[:4] + reason
    body = struct.pack(">HH", 0x0009, len(body)) + body
    return (struct.pack(">HH", STUN_BINDING_ERROR, len(body))
            + STUN_MAGIC + txid + body)


class StunServerProtocol(asyncio.DatagramProtocol):
    """Answers STUN binding requests with the observed source address.

    Rate limited per source IP.
    ---------------------------
    A 20-byte binding request produces a ~56-byte response, so an
    unauthenticated STUN port is a ~2.8x amplification reflector. It needs
    a valid magic cookie, which raises the bar, but that is not a defence --
    it is a minor inconvenience. Capping per-source traffic keeps this port
    from being useful in a reflection attack.
    """

    # generous for real clients (a handful of probes per session), tiny for
    # an amplifier that needs sustained throughput
    REFILL_PER_SEC = 5.0
    BURST = 20.0

    def __init__(self, name=""):
        self.name = name
        self.transport = None
        self._budget = {}          # ip -> [tokens, last_update]
        self._last_gc = 0.0

    def _allow(self, ip):
        now = time.monotonic()
        tok, last = self._budget.get(ip, (self.BURST, now))
        tok = min(self.BURST, tok + (now - last) * self.REFILL_PER_SEC)
        self._budget[ip] = [tok, now]
        if tok < 1.0:
            return False
        self._budget[ip][0] = tok - 1.0
        # keep the table bounded
        if len(self._budget) > 4096 and now - self._last_gc > 60.0:
            self._last_gc = now
            self._budget = {k: v for k, v in self._budget.items()
                            if v[0] > 0 or now - v[1] < 60.0}
            if len(self._budget) > 4096:
                self._budget.clear()
        return True

    def connection_made(self, transport):
        self.transport = transport
        sock = transport.get_extra_info("socket")
        try:
            log.info("STUN listening on udp %s (via %s)",
                     sock.getsockname(), self.name)
        except Exception:
            log.info("STUN socket ready (%s)", self.name)

    def datagram_received(self, data, addr):
        # 20-byte header: type(2) length(2) cookie(4) txid(12)
        if len(data) < 20:
            return
        kind, length = struct.unpack(">HH", data[:4])
        if kind != STUN_BINDING_REQUEST:
            return
        if data[4:8] != STUN_MAGIC:
            return
        if length != len(data) - 20:
            # A length mismatch means we cannot trust the framing; replying
            # to a malformed packet is how you build an amplification vector.
            return
        if not self._allow(addr[0]):
            return
        try:
            self.transport.sendto(stun_binding_response(data[8:20], addr), addr)
        except Exception:
            pass

    def error_received(self, exc):
        log.info("STUN error: %s", exc)


async def start_stun():
    """Bind the STUN sockets. Returns (transports, [host, port], [host, port2]).

    Failure here must never stop the signalling server -- STUN is an
    optimisation, not a dependency.
    """
    if not STUN_PORT:
        log.info("built-in STUN disabled (STUN_PORT=0)")
        return [], None, None

    loop = asyncio.get_running_loop()
    transports = []
    for port in (STUN_PORT, STUN_PORT2):
        if not port:
            continue
        try:
            tr, _pr = await loop.create_datagram_endpoint(
                lambda p=port: StunServerProtocol("udp/%d" % p),
                local_addr=("0.0.0.0", port))
            transports.append(tr)
        except OSError as e:
            log.warning("cannot bind STUN udp/%d: %s "
                        "(another STUN server? run with STUN_PORT=0)", port, e)
        except Exception as e:
            log.warning("STUN udp/%d failed: %s", port, e)

    if not transports:
        log.info("built-in STUN unavailable")
        return [], None, None
    return transports, STUN_PORT, STUN_PORT2


def _stun_self_query(timeout=1.5):
    """Ask our own STUN listener what address it sees. Returns "" on failure.

    Loopback only sees 127.0.0.1, which is useless to a remote client, so
    that result is rejected rather than advertised.
    """
    if not STUN_PORT:
        return ""
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.bind(("0.0.0.0", 0))
        txid = os.urandom(12)
        msg = (struct.pack(">HH", STUN_BINDING_REQUEST, 0)
               + STUN_MAGIC + txid)
        sock.sendto(msg, ("127.0.0.1", STUN_PORT))
        data, _ = sock.recvfrom(2048)
        if len(data) < 20 or data[8:20] != txid or data[4:8] != STUN_MAGIC:
            return ""
        body = data[20:]
        p = 0
        while p + 4 <= len(body):
            a, l = struct.unpack_from(">HH", body, p)
            v = body[p + 4:p + 4 + l]
            if a == STUN_ATTR_MAPPED_ADDRESS and len(v) >= 8:
                ip = ".".join(str(b) for b in v[4:8])
                if not ip.startswith("127."):
                    return ip
                return ""
            p += 4 + ((l + 3) & ~3)
    except Exception:
        return ""
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass
    return ""


def detect_public_host(timeout=1.5):
    """Best-effort PUBLIC IP of this box, via a real STUN exchange.

    Note it must be a real request/response: `socket.connect()` on a UDP
    socket sends nothing, so getsockname() would just return our own
    INTERNAL address -- useless for telling a client how to reach us.

    Never fatal: an empty result just means we cannot advertise our STUN
    and clients keep using their built-in list.
    """
    if STUN_HOST:
        return STUN_HOST

    from common import stun_probe
    servers = [("stun.miwifi.com", 3478), ("stun.voipbuster.com", 3478),
               ("stun.schlund.de", 3478), ("stun.l.google.com", 19302)]
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("0.0.0.0", 0))
        got = stun_probe(sock, timeout=timeout, servers=servers)
        if got and got[0] and not got[0].startswith("127."):
            return got[0]
    except Exception:
        pass
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass
    return ""


class Conn:
    def __init__(self, reader, writer, client_ip=""):
        self.reader = reader
        self.writer = writer
        self.id = ""
        self.name = ""
        # Source IP of the TCP connection. Room codes are short enough to
        # enumerate, so every limiter is keyed on this -- a key the client
        # cannot choose. conn.id does not qualify: it is whatever the client
        # puts in the register message, and re-registering with a new one
        # used to hand out a fresh quota.
        #
        # Behind a trusted reverse proxy this is the forwarded address; see
        # client_ip_for(). Everything else sees only the proxy, which would
        # make one shared quota for all players.
        self.peer_ip = client_ip
        if not self.peer_ip:
            try:
                peer = writer.get_extra_info("peername")
                if peer:
                    self.peer_ip = str(peer[0])
            except Exception:
                self.peer_ip = "unknown"
        self.registered = False
        self.room = ""
        self.p2p = ""
        self.local_addrs = []   # LAN endpoints, tried before the public one
        self.nat = "unknown"
        self.nat_subtype = "unknown"   # refined class; the PEER picks a method
        self.nat_filter = "unknown"    # RFC 5780 filtering; peers it with the above
        self.tcp_port = 0              # TCP punch port for simultaneous open
        self.nat_delta = 0      # port allocation step; the PEER needs it
        self.latency = 0
        self.lock = asyncio.Lock()
        self.alive = True

    async def send_frame(self, opcode, payload):
        if not self.alive:
            return
        try:
            async with self.lock:
                self.writer.write(encode_frame(opcode, payload))
                await self.writer.drain()
        except Exception:
            self.alive = False

    async def send(self, obj):
        await self.send_frame(OP_TEXT, json.dumps(obj, ensure_ascii=False).encode("utf-8"))

    def __repr__(self):
        return f"<Conn {self.name or '?'} {self.id[:8]}>"


# Capacity rules are mirrored in client/protocol.py (MIN/MAX/LIMIT).
MIN_PLAYERS = 2
DEFAULT_PLAYERS = 10
MAX_PLAYERS_LIMIT = 64

# Brute-force resistance.
#
# A room code is 4 characters from a 32-char alphabet (~1M combinations),
# which is trivially enumerable unless joining is rate limited AND the room
# can require a password. Both were missing.
#
# The limiters are keyed on the SOURCE IP, not on conn.id: conn.id is
# whatever the client sends in `register`, so re-registering with a new id
# used to reset the quota and made the whole limit a no-op. The per-IP
# allowance is deliberately looser than the per-connection one -- several
# players routinely share one public IP (a dorm, a CGNAT) and must not lock
# each other out.
MAX_JOIN_ATTEMPTS = 8         # failed joins per window, per connection
MAX_JOIN_PER_IP = 30          # ... and per source IP
MAX_REGISTER_PER_IP = 120     # registers per minute, per source IP
RATE_WINDOW_S = 30.0
MAX_CREATE_PER_MIN = 20
MAX_CREATE_PER_IP = 60
MAX_PASSWORD_LEN = 64


def _env_int(name, default, low=1, high=100000):
    """Tunable limit; a self-hosted lobby under one NAT may need more.

    env value of 0 means OFF, not "one attempt" -- behind a reverse proxy
    where every player shares one address the per-IP budget is not a
    signal, and an operator must be able to switch it off rather than have
    a whole lobby locked out by somebody else's reconnects.
    """
    try:
        n = int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default
    if n <= 0:
        return 0
    return max(low, min(high, n))


def _make_limiter(name, default, window):
    n = _env_int(name, default)
    if n == 0:
        log.warning("%s=0: per-IP limit for %s is DISABLED", name, name)
        n = 10 ** 9      # effectively off; keeps every call site simple
    return RateLimiter(n, window)


# Per-process salt; a restart invalidates stored hashes, which is fine
# because rooms do not survive a restart either.
ROOM_SALT = os.urandom(16).hex()


def clamp_capacity(value):
    """Coerce any incoming capacity into a sane range. Never raises."""
    try:
        n = int(value)
    except (TypeError, ValueError):
        return DEFAULT_PLAYERS
    return max(MIN_PLAYERS, min(MAX_PLAYERS_LIMIT, n))


def room_password_hash(room_code, password):
    """Derive a stored hash from a room password.

    Stored as a salted hash rather than plaintext so a leaked server file
    does not hand over every room's password. Deliberately NOT a slow KDF:
    it is checked per join attempt and this is a game lobby, not a vault.
    """
    if not password:
        return ""
    return hashlib.sha256(("%s|%s|%s" % (ROOM_SALT, room_code, password))
                          .encode("utf-8")).hexdigest()


class RateLimiter:
    """Sliding-window limiter. Keyed by whatever the caller passes.

    Always pass a key the CLIENT CANNOT CHOOSE for the quota that matters.
    Keying on conn.id alone was pointless: the id arrives in the register
    message, so sending register again with a different clientId handed out
    a brand new quota (see handle_register).

    Why it exists: room codes are short (4 chars of a 32-char alphabet,
    ~1M combinations) and joining needed no secret at all, so anyone could
    enumerate their way into somebody else's room. ERR_RATE_LIMIT was
    declared in the protocol and never enforced anywhere.
    """

    def __init__(self, limit, window):
        self.limit = limit
        self.window = window
        self.hits = {}          # key -> [timestamps]

    def _prune(self):
        # keep the table from growing without bound
        if len(self.hits) > 512:
            for k in [k for k, v in self.hits.items() if not v]:
                self.hits.pop(k, None)
            if len(self.hits) > 512:
                self.hits.clear()

    def peek(self, key):
        """Would this key be allowed right now? Does not consume quota."""
        now = time.monotonic()
        hits = [t for t in self.hits.get(key, []) if now - t < self.window]
        self.hits[key] = hits
        # Prune here too, not only in hit(): a key that is refused is never
        # written to again, so without this it sat in the table forever.
        self._prune()
        return len(hits) < self.limit

    def hit(self, key):
        """Consume one unit of quota (unconditional)."""
        self.hits.setdefault(key, []).append(time.monotonic())
        self._prune()

    def allow(self, key):
        """Consume one unit if -- and only if -- the key is under the limit."""
        if not self.peek(key):
            return False
        self.hit(key)
        return True


JOIN_LIMITER = RateLimiter(_env_int("MAX_JOIN_ATTEMPTS", MAX_JOIN_ATTEMPTS),
                           RATE_WINDOW_S)
JOIN_IP_LIMITER = _make_limiter("MAX_JOIN_PER_IP", MAX_JOIN_PER_IP,
                                RATE_WINDOW_S)
CREATE_LIMITER = RateLimiter(_env_int("MAX_CREATE_PER_MIN", MAX_CREATE_PER_MIN),
                             60.0)
CREATE_IP_LIMITER = _make_limiter("MAX_CREATE_PER_IP", MAX_CREATE_PER_IP, 60.0)
REGISTER_LIMITER = _make_limiter("MAX_REGISTER_PER_IP", MAX_REGISTER_PER_IP,
                                 60.0)
# A punch_target makes the OTHER side tear down a working link, so it is an
# action with a cost someone else pays. Rate it per connection and per IP
# like every other cross-client action, and cool it down per peer pair so a
# buggy or hostile client cannot keep a room permanently reconnecting.
PUNCH_LIMITER = _make_limiter("MAX_PUNCH_PER_IP", 20, RATE_WINDOW_S)
PUNCH_COOLDOWN_S = _env_int("PUNCH_COOLDOWN_S", 10)
PUNCH_LAST = {}                   # (from_id, to_id) -> last coordination


def conn_key(conn):
    """Per-connection quota key.

    Safe to use now that a connection can only register once: conn.id is
    fixed at that point and can no longer be rotated by the client.
    """
    return conn.id or str(id(conn))


def ip_key(conn):
    """Per-source-IP quota key -- the one the client cannot influence."""
    return conn.peer_ip or conn_key(conn)


class Room:
    def __init__(self, code, name, owner, max_players=DEFAULT_PLAYERS):
        self.code = code
        self.name = name
        self.owner = owner
        self.members = []  # list[Conn]
        self.max_players = clamp_capacity(max_players)
        self.password_hash = ""    # empty = open room


# Error codes. The client maps these to Chinese (see client/protocol.py);
# keeping them here means the wire only ever carries a stable token.
ERR_ROOM_NOT_FOUND = "ROOM_NOT_FOUND"
ERR_NOT_HOST = "NOT_HOST"
ERR_ROOM_FULL = "ROOM_FULL"
ERR_ROOM_BUSY = "ROOM_BUSY"
ERR_BAD_ROOM = "BAD_ROOM"
ERR_DUPLICATE_DEVICE = "DUPLICATE_DEVICE"
ERR_RATE_LIMIT = "RATE_LIMIT"
ERR_BAD_PASSWORD = "BAD_PASSWORD"


async def send_error(conn, code):
    await conn.send({"action": "error", "code": code})


ROOM_CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

rooms = {}          # code -> Room
conns = set()       # set[Conn]
state_lock = asyncio.Lock()


def new_room_code():
    while True:
        code = "".join(random.choice(ROOM_CODE_ALPHABET) for _ in range(4))
        if code not in rooms:
            return code


def room_info(r):
    return {
        "roomCode": r.code,
        "roomName": r.name,
        "ownerId": r.owner.id if r.owner else "",
        "ownerName": r.owner.name if r.owner else "",
        "memberCount": len(r.members),
        "maxPlayers": r.max_players,
    }


def member_info(c):
    return {
        "id": c.id,
        "name": c.name,
        "p2pAddr": c.p2p,
        "latency": c.latency,
        "isHost": bool(c.room and rooms.get(c.room) and rooms[c.room].owner is c),
        # NAT details for every member, not just the punch target.
        #
        # "Why can't I connect to them" is the single most common support
        # question, and until now the only way to answer it was to ask the
        # other player to read their own log. Showing both ends' NAT in the
        # room lets the host see at a glance whether a problem is theirs,
        # the peer's, or the pair's.
        # `nat`, not `nat_type` -- the Connection attribute is `self.nat`.
        # getattr() with a default silently swallowed the typo and every
        # member was published as "unknown", so the room list showed the
        # coarse fallback ("未知") for cone users -- the largest group this
        # display exists to serve.
        "natType": getattr(c, "nat", "unknown"),
        "natSubtype": getattr(c, "nat_subtype", "unknown"),
        "natFilter": getattr(c, "nat_filter", "unknown"),
    }


async def send_room_list(conn=None):
    payload = {"action": "room_list", "rooms": [room_info(r) for r in rooms.values()]}
    targets = [conn] if conn else list(conns)
    for t in targets:
        await t.send(payload)


async def send_room_update(code):
    r = rooms.get(code)
    if not r:
        return
    payload = {
        "action": "room_update",
        "roomCode": r.code,
        "roomName": r.name,
        "maxPlayers": r.max_players,
        "members": [member_info(m) for m in r.members],
    }
    for m in list(r.members):
        await m.send(payload)


async def dissolve_room(r, reason):
    """Close a room and tell everybody in it why.

    `reason` reaches the player: "host_left" (the world is gone) versus
    "deleted" (the host closed it on purpose).
    """
    members = list(r.members)
    for m in members:
        m.room = ""
        try:
            await m.send({"action": "room_closed", "roomCode": r.code,
                          "reason": reason})
        except Exception:
            pass
    rooms.pop(r.code, None)
    log.info("room %s closed (%s), %d member(s) notified",
             r.code, reason, len(members))


async def remove_from_room(conn):
    """Leave current room; delete room if empty. Returns True if changed.

    If the departing member is the HOST the whole room is dissolved.

    Why: the topology is a star -- every guest tunnels to the host, and the
    host is the one running the world. Just dropping the host from the
    member list left an orphan room: guests sat in it with nobody to talk
    to, the UI still showed a host that no longer existed, and new players
    could still see and join that dead room from the list.
    """
    if not conn.room:
        return False
    r = rooms.get(conn.room)
    conn.room = ""
    if not r:
        return True
    if conn in r.members:
        r.members.remove(conn)

    if r.owner is conn:
        log.info("host %s left room %s - dissolving it",
                 conn.name or conn.id[:8], r.code)
        await dissolve_room(r, "host_left")
        return True

    log.info("%s left room %s, %d remaining",
             conn.name or conn.id[:8], r.code, len(r.members))
    if not r.members:
        rooms.pop(r.code, None)
        log.info("room %s empty, deleted", r.code)
    return True


async def maybe_coordinate(room_code):
    """Tell everyone to punch to the HOST — and only to the host.

    Star topology: the host is the one that owns the Minecraft world, so
    guests only ever need a link to it. Pairing guests with each other
    wasted a tunnel per guest and, worse, gave each guest more than one
    channel to pick from when its local MC client connected.
    """
    r = rooms.get(room_code)
    if not r:
        return
    host = r.owner
    if host is None or not host.p2p:
        return
    for m in r.members:
        if m is host or not m.p2p:
            continue
        log.info("punch coord: %s <-> host %s (%s)", m.name, host.name, host.p2p)
        # A shared start is the difference between "both sides spray at the
        # same moment" and "each side sprays on a schedule nobody agreed
        # to".
        #
        # It is sent as a RELATIVE delay, not an absolute timestamp. An
        # absolute epoch requires both peers' clocks to agree with the
        # server's -- and clock agreement is the last thing to assume in a
        # peer-to-peer setting. With a relative delay each peer starts
        # `startIn` seconds after it RECEIVES the message, so the two
        # starts differ only by the difference in their round-trip times:
        # tens of milliseconds, regardless of how wrong either clock is.
        start_in = PUNCH_START_DELAY_S
        await m.send({
            "action": "start_punch",
            "targetAddr": host.p2p,
            "targetAddrs": host.local_addrs,
            "targetNat": host.nat,
            "targetSubtype": host.nat_subtype,
            "targetPerIpPool": bool(getattr(host, "per_ip_pool", False)),
                "targetFilter": host.nat_filter,
                "targetTcpPort": host.tcp_port,
            "targetDelta": host.nat_delta,
            "targetId": host.id,
            "isHost": True,
            "startIn": start_in,
        })
        await host.send({
            "action": "start_punch",
            "targetAddr": m.p2p,
            "targetAddrs": m.local_addrs,
            "targetNat": m.nat,
            "targetSubtype": m.nat_subtype,
            "targetPerIpPool": bool(getattr(m, "per_ip_pool", False)),
                "targetFilter": m.nat_filter,
                "targetTcpPort": m.tcp_port,
            "targetDelta": m.nat_delta,
            "targetId": m.id,
            "isHost": False,
            "startIn": start_in,
        })


# ---------------------------------------------------------------- handlers


async def handle_register(conn, msg):
    # One register per connection, ever.
    #
    # conn.id used to be re-writable at will, and every per-connection
    # quota is keyed on it: send register again with a different clientId
    # and the join/create limiters handed out a fresh allowance. Room codes
    # are ~1M combinations, so that alone made brute-forcing a room code
    # trivial. The identity a connection presents is now fixed on its first
    # register; getting a new identity requires a new connection, which the
    # per-IP limiter does count.
    if conn.registered:
        log.warning("%s tried to re-register as '%s' (was %s) -- ignored",
                    conn.name or conn.peer_ip,
                    str(msg.get("clientId") or "")[:8], conn.id[:8])
        await send_error(conn, ERR_RATE_LIMIT)
        return
    if not REGISTER_LIMITER.allow(ip_key(conn)):
        log.warning("%s hit the register limit", conn.peer_ip)
        await send_error(conn, ERR_RATE_LIMIT)
        return
    conn.registered = True

    conn.id = (msg.get("clientId") or "").strip()
    conn.name = (msg.get("name") or "").strip() or "player"

    # A reconnecting device replaces its old connection.
    #
    # If this fires for two DIFFERENT machines, their .device_id files are
    # identical (usually because the folder was copied). The client now
    # binds the id to a machine fingerprint, so a copied file is
    # regenerated -- but a stale build can still collide.
    for old in [c for c in conns if c is not conn and c.id and c.id == conn.id]:
        log.warning("DUPLICATE device id %s: '%s' is kicking '%s'. "
                    "If these are different machines, delete .device_id on "
                    "one of them (or upgrade the client).",
                    conn.id[:8], conn.name, old.name)
        await remove_from_room(old)
        conns.discard(old)
        old.alive = False
        try:
            await old.send({"action": "error",
                            "message": "another client with the same device id "
                                       "connected from %s" % conn.name})
        except Exception:
            pass
        try:
            old.writer.close()
        except Exception:
            pass

    if not conn.id:
        conn.id = os.urandom(16).hex()

    log.info("register: %s (%s)", conn.name, conn.id)
    payload = {"action": "registered", "peerId": conn.id}
    # Tell the client where our STUN lives. Preferred over its built-in
    # list because this host is one it provably can reach.
    if STUN_ENDPOINTS:
        payload["stunServers"] = [
            {"host": h, "port": p} for h, p in STUN_ENDPOINTS]
    await conn.send(payload)
    await send_room_list(conn)


async def handle_create_room(conn, msg):
    await remove_from_room(conn)
    if not (CREATE_LIMITER.allow(conn_key(conn))
            and CREATE_IP_LIMITER.allow(ip_key(conn))):
        await send_error(conn, ERR_RATE_LIMIT)
        log.warning("%s hit the create limit", conn.name)
        return
    code = new_room_code()
    name = (msg.get("roomName") or "").strip() or "room"
    pwd = str(msg.get("password") or "")[:MAX_PASSWORD_LEN]
    # the host chooses the capacity; an old client that never sends the
    # field simply gets the default
    capacity = clamp_capacity(msg.get("maxPlayers", DEFAULT_PLAYERS))
    r = Room(code, name, conn, capacity)
    r.password_hash = room_password_hash(code, pwd)
    r.members.append(conn)
    rooms[code] = r
    conn.room = code
    log.info("room created: %s (%s) by %s, capacity %d%s",
             name, code, conn.name, capacity,
             " [password]" if r.password_hash else "")
    await conn.send({"action": "room_created", "roomCode": code,
                     "roomName": name, "maxPlayers": capacity})
    await send_room_update(code)
    await send_room_list()


async def handle_join_room(conn, msg):
    code = (msg.get("roomCode") or "").strip().upper()

    # Rate limit BEFORE telling the caller whether the room exists.
    # Checking existence first would turn this into a free oracle for
    # enumerating codes.
    #
    # Two keys on purpose: the per-connection one keeps a single client
    # honest, the per-IP one is what actually stops an attacker -- the
    # client cannot pick its source IP the way it used to pick its id.
    #
    # Quota is consumed only by FAILED attempts (peek now, hit below):
    # brute-forcing a code or a password is nothing but failures, while a
    # lobby full of real players behind one NAT never trips it.
    if not (JOIN_LIMITER.peek(conn_key(conn))
            and JOIN_IP_LIMITER.peek(ip_key(conn))):
        await send_error(conn, ERR_RATE_LIMIT)
        log.warning("%s hit the join limit", conn.name)
        return

    r = rooms.get(code)
    if not r:
        JOIN_LIMITER.hit(conn_key(conn))
        JOIN_IP_LIMITER.hit(ip_key(conn))
        await send_error(conn, ERR_ROOM_NOT_FOUND)
        return
    if len(r.members) >= r.max_players:
        await send_error(conn, ERR_ROOM_FULL)
        log.info("%s rejected from %s: full (%d/%d)",
                 conn.name, code, len(r.members), r.max_players)
        return
    if r.password_hash:
        given = str(msg.get("password") or "")[:MAX_PASSWORD_LEN]
        if room_password_hash(code, given) != r.password_hash:
            JOIN_LIMITER.hit(conn_key(conn))
            JOIN_IP_LIMITER.hit(ip_key(conn))
            await send_error(conn, ERR_BAD_PASSWORD)
            log.info("%s rejected from %s: wrong password", conn.name, code)
            return
    await remove_from_room(conn)
    conn.room = code
    if conn not in r.members:
        r.members.append(conn)
    log.info("%s joined %s (%s)", conn.name, r.name, code)
    await send_room_update(code)
    await send_room_list()
    await maybe_coordinate(code)


def _addr_list(value, limit=8):
    """Sanitise a list of "ip:port" strings coming from the network."""
    out = []
    for item in (value or [])[:limit]:
        text = str(item).strip()
        if text and ":" in text:
            out.append(text)
    return out


def _str_field(msg, key, limit=16, default=""):
    """A string field, or "" when it is ABSENT. Callers decide the default.

    Deliberately does not collapse missing into "unknown": that made a
    partial update overwrite a value we already had with a worse one, and
    silently -- the room list showed natType "unknown" for a peer whose NAT
    had been measured correctly.
    """
    return str(msg.get(key) or "").strip().lower()[:limit]


async def handle_publish_offer(conn, msg):
    # Same rule for every field: only overwrite what the message actually
    # carries. A client that reports just its filter must not wipe the
    # endpoint we already know -- a partial update silently downgraded
    # natType to "unknown" for a peer whose NAT had been measured
    # correctly, and the same hole on p2p would be worse still (the peer
    # becomes unreachable rather than merely mislabelled).
    if "p2pAddr" in msg:
        conn.p2p = (msg["p2pAddr"] or "").strip()
    if "localAddrs" in msg:
        conn.local_addrs = _addr_list(msg["localAddrs"])
    if "tcpPort" in msg:
        try:
            conn.tcp_port = max(0, min(65535, int(msg["tcpPort"] or 0)))
        except (TypeError, ValueError):
            pass
    conn.nat = _str_field(msg, "natType") or conn.nat
    conn.nat_filter = _str_field(msg, "natFilter") or conn.nat_filter
    conn.nat_subtype = _str_field(msg, "natSubtype") or conn.nat_subtype
    # "this peer allocates a separate port region per destination IP":
    # forwarded so the other end knows a window around the published port
    # will not hit. Unknown/absent means "no", which is the ordinary case.
    conn.per_ip_pool = bool(msg.get("perIpPool"))
    # Presence, not truthiness: 0 is a meaningful delta (a cone does not
    # step its ports), so `or 0` would both mask a real 0 and turn an
    # absent field into one.
    if "natDelta" in msg:
        try:
            conn.nat_delta = int(msg["natDelta"] or 0)
        except (TypeError, ValueError):
            pass
    log.info("%s published: %s (lan=%s nat=%s/%s delta=%d)",
             conn.name, conn.p2p, conn.local_addrs, conn.nat,
             conn.nat_subtype, conn.nat_delta)
    if conn.room:
        await send_room_update(conn.room)
        await maybe_coordinate(conn.room)


async def handle_inbound_probe(conn, msg):
    """Send one UDP packet from an unrelated port to the peer's mapping.

    This is the single most useful diagnostic in the whole program, because
    it separates two failures that look identical in every other log line:

        * the peer cannot reach us   (firewall, ISP, strict filtering)
        * our punching is wrong      (window, anchor, timing)

    Both present as "no packet from <peer> reached any of our mappings".
    Nothing in the punch path can tell them apart, and the difference
    decides everything: one is fixable in code, the other is not.

    So send from a BRAND NEW socket -- a source port and a source host the
    client has never spoken to, exactly like a peer it is trying to punch
    with. If that arrives, inbound UDP works, and a punch that fails is a
    bug in our scan. If it does not arrive, no scan can ever succeed and
    the only honest answer is to relay.
    """
    addr = (msg.get("addr") or conn.p2p or "").strip()
    if not addr:
        return
    ip, _, port_s = addr.rpartition(":")
    try:
        port = int(port_s)
    except (TypeError, ValueError):
        return
    if not ip or not (0 < port < 65536):
        return
    # An explicit address may only be another port on the SAME host the
    # client published. Otherwise this handler is an open UDP reflector,
    # which is not a thing to ship: anyone could point it at anyone.
    #
    # The client asks for its own mapping towards this very server (learned
    # from the STUN we run), so restricting it to the published IP costs
    # nothing and removes the abuse case.
    own_ip = (conn.p2p or "").rpartition(":")[0]
    if msg.get("addr") and own_ip and ip != own_ip:
        log.info("inbound probe addr %s rejected: not the client's own IP",
                 addr)
        return
    sent_from = None
    try:
        import socket as _s
        s = _s.socket(_s.AF_INET, _s.SOCK_DGRAM)
        try:
            s.bind(("", 0))          # a fresh, unrelated source port
            sent_from = s.getsockname()[1]
            s.sendto(INBOUND_PROBE_PACKET, (ip, port))
        finally:
            s.close()
        log.info("inbound probe -> %s (from a fresh source port %s)",
                 addr, sent_from)
    except Exception as e:
        log.warning("inbound probe to %s failed: %s", addr, e)

    # Confirm that we actually sent it.
    #
    # Without this the client cannot tell "inbound UDP is blocked" from
    # "this server is an older build that ignored the request", and it
    # reported BLOCKED for both -- which on two machines at once, on two
    # different ISPs, is far more likely to be the second. Telling a user
    # their firewall is at fault when the real cause is an un-upgraded
    # server is worse than saying nothing.
    try:
        await conn.send({"action": "inbound_probe_sent",
                         "addr": addr, "fromPort": sent_from})
    except Exception:
        pass


# TCP port-preservation probe: "I am about to connect to you from local
# port P -- tell me which port you actually saw."
#
# Whether a NAT preserves the TCP punch port decides whether a simultaneous
# open can cross, and it is a DIFFERENT question from the UDP one: NATs keep
# separate port pools, and plenty of them rewrite UDP per destination while
# handing out the port the client asked for on TCP. Clients used to answer
# it from the UDP mapping and switched TCP punching off on networks where it
# was the only mechanism left.
#
# One pending request per port, expired on a timer: this is a diagnostic,
# not state.
TCP_PROBE_WAIT = {}
TCP_PROBE_TTL_S = 20.0


async def handle_tcp_probe(conn, msg):
    try:
        port = int(msg.get("port") or 0)
    except (TypeError, ValueError):
        return
    if not (0 < port < 65536):
        return
    now = time.time()
    for key, (_c, exp) in list(TCP_PROBE_WAIT.items()):
        if exp < now:
            TCP_PROBE_WAIT.pop(key, None)
    TCP_PROBE_WAIT[port] = (conn, now + TCP_PROBE_TTL_S)
    await conn.send({"action": "tcp_probe_go", "port": port})


async def maybe_report_tcp_probe(peer_ip, peer_port):
    """Called for EVERY inbound TCP connection, before the handshake.

    Matches the connection to a pending request by SOURCE IP, not by port.

    Matching by port was backwards, and it was backwards in the one case
    the measurement exists for. The key was the port the client said it
    bound (30001); the lookup used the port we actually observed. So:

      * the port IS preserved   -> key == observed, matches, and the answer
        is one we could have guessed
      * the port IS rewritten   -> observed != 30001, no match, no answer

    i.e. it could only ever report the case where nothing was learned. Real
    log: both ends sent `tcp_probe`, both got `tcp_probe_go`, and neither
    ever saw a `tcp_probe_result`.

    The IP is the stable part: a NAT may rewrite the port but it does not
    rewrite the address. So match on the address and report the observed
    port against the one that was declared.
    """
    if not peer_port or not peer_ip:
        return
    now = time.time()
    for key, (conn, exp) in list(TCP_PROBE_WAIT.items()):
        if exp < now:
            TCP_PROBE_WAIT.pop(key, None)
            continue
        own_ip = (conn.p2p or "").rpartition(":")[0]
        if not own_ip or own_ip != peer_ip:
            continue
        TCP_PROBE_WAIT.pop(key, None)
        asked, seen = int(key), int(peer_port)
        try:
            await conn.send({"action": "tcp_probe_result",
                             "port": asked, "seenPort": seen})
        except Exception:
            pass
        log.info("tcp probe: asked %s, observed %s -> %s",
                 asked, seen, "preserved" if asked == seen else "rewritten")
        return


async def handle_punch_target(conn, msg):
    target_id = (msg.get("targetId") or "").strip()
    if not target_id or not conn.room:
        return
    # This asks us to interrupt someone else's connection, so it is not
    # free: rate-limit the asker and cool the pair down.
    if not PUNCH_LIMITER.allow(ip_key(conn)):
        log.warning("%s hit the punch coordination limit", conn.name)
        return
    pair = (conn.id, target_id)
    now = time.time()
    last = PUNCH_LAST.get(pair, 0.0)
    if now - last < PUNCH_COOLDOWN_S:
        log.info("punch coordination for %s -> %s still cooling down",
                 conn.name, target_id)
        return
    PUNCH_LAST[pair] = now
    r = rooms.get(conn.room)
    if not r:
        return
    for m in r.members:
        if m.id == target_id and m.p2p:
            # Same fields as the coordinated path. This route is unused in
            # the star topology, but a start_punch missing targetSubtype /
            # targetDelta / targetAddrs silently downgraded the peer to
            # "unknown NAT, single guess" -- a trap for whoever uses it.
            start_in = PUNCH_START_DELAY_S
            # This path is used by "I switched back to direct, try again".
            # The peer may already be on the relay, in which case an
            # ordinary start_punch is ignored -- its channel exists, so
            # there is nothing to do. force=True tells it to tear the relay
            # down and come back, so one side switching modes does not
            # leave the other side behind.
            force = bool(msg.get("force"))
            await conn.send({
                "action": "start_punch",
                "targetAddr": m.p2p,
                "targetAddrs": m.local_addrs,
                "targetNat": m.nat,
                "targetSubtype": m.nat_subtype,
                "targetPerIpPool": bool(getattr(m, "per_ip_pool", False)),
                "targetDelta": m.nat_delta,
                "targetId": m.id,
                "isHost": bool(r.owner is m),
                "startIn": start_in,
                "force": force,
            })
            await m.send({
                "action": "start_punch",
                "targetAddr": conn.p2p,
                "targetAddrs": conn.local_addrs,
                "targetNat": conn.nat,
                "targetSubtype": conn.nat_subtype,
                "targetPerIpPool": bool(getattr(conn, "per_ip_pool", False)),
                "targetDelta": conn.nat_delta,
                "targetId": conn.id,
                "isHost": bool(r.owner is conn),
                "startIn": start_in,
                "force": force,
            })
            log.info("punch coord: %s <-> %s (forced)", conn.name, m.name)
            return


async def handle_delete_room(conn, msg):
    code = (msg.get("roomCode") or conn.room or "").strip()
    r = rooms.get(code)
    if not r:
        log.info("delete failed: no such room (code=%r)", code)
        await send_error(conn, ERR_ROOM_NOT_FOUND)
        return
    if r.owner is not conn:
        await send_error(conn, ERR_NOT_HOST)
        return
    await dissolve_room(r, "deleted")
    log.info("room %s deleted by %s", code, conn.name)
    await send_room_list()


async def handle_peer_signal(conn, msg):
    """Forward a small control message to one peer in the same room.

    Used for per-connection stream open/close: each Minecraft connection
    is a separate stream so the host can give it its own backend socket.
    """
    target_id = (msg.get("targetId") or "").strip()
    if not target_id:
        return
    for c in conns:
        if c.id == target_id and c.room and c.room == conn.room:
            await c.send({"action": "peer_signal", "fromId": conn.id,
                          "signal": msg.get("signal") or {}})
            return


async def handle_relay_binary(conn, data):
    """Binary game-data relay: [0x01][id_len][target_id ascii][payload]."""
    if len(data) < 3 or data[0] != 0x01:
        return
    id_len = data[1]
    if len(data) < 2 + id_len:
        return
    target_id = data[2:2 + id_len].decode("ascii", "ignore")
    body = data[2 + id_len:]
    if not body:
        return

    target = None
    for c in conns:
        if c is not conn and c.id == target_id and c.room and c.room == conn.room:
            target = c
            break
    if target is None:
        return

    my_id = conn.id.encode("ascii", "ignore")[:255]
    frame = bytes([0x01, len(my_id)]) + my_id + body
    await target.send_frame(OP_BINARY, frame)


HANDLERS = {
    "register": handle_register,
    "create_room": handle_create_room,
    "join_room": handle_join_room,
    "publish_offer": handle_publish_offer,
    "punch_target": handle_punch_target,
    "inbound_probe": handle_inbound_probe,
    "tcp_probe": handle_tcp_probe,
    "delete_room": handle_delete_room,
    "peer_signal": handle_peer_signal,
}


async def handle_text(conn, raw):
    text = raw.decode("utf-8", "ignore")
    stripped = text.strip().strip('"')
    if stripped in ("ping", "pong"):
        await conn.send({"action": "pong"})
        return
    try:
        msg = json.loads(text)
    except Exception:
        log.info("invalid json: %s", text[:100])
        return
    if not isinstance(msg, dict):
        return
    action = msg.get("action", "")

    if action == "ping":
        # echo the seq so the client can time the exact round trip
        reply = {"action": "pong"}
        if isinstance(msg, dict) and "seq" in msg:
            reply["seq"] = msg["seq"]
        await conn.send(reply)
        return
    if action == "update_latency":
        try:
            conn.latency = int(msg.get("latency") or 0)
        except Exception:
            pass
        if conn.room:
            await send_room_update(conn.room)
        return
    if action == "list_rooms":
        await send_room_list(conn)
        return
    if action == "leave":
        # Capture the code BEFORE leaving: remove_from_room clears
        # conn.room, so the old `send_room_update(conn.room) if conn.room`
        # always took the empty branch and the remaining members never saw
        # the list refresh until some unrelated event came along.
        code = conn.room
        if await remove_from_room(conn):
            if code and code in rooms:
                await send_room_update(code)
            await send_room_list()
            await send_room_list(conn)
        return

    fn = HANDLERS.get(action)
    if fn:
        await fn(conn, msg)
    else:
        log.info("unknown action: %s", action)


async def client_loop(reader, writer):
    # Before the handshake: a TCP port-preservation probe arrives as a
    # plain connection with no WebSocket key, so it never gets that far.
    peer = writer.get_extra_info("peername")
    if peer:
        await maybe_report_tcp_probe(str(peer[0]), peer[1])
    client_ip = await ws_handshake(reader, writer)
    if not client_ip:
        writer.close()
        return
    conn = Conn(reader, writer, client_ip=client_ip)
    conns.add(conn)
    peer_addr = writer.get_extra_info("peername")
    log.info("connected: %s (rate-limit key %s, total %d)",
             peer_addr, client_ip, len(conns))
    try:
        while True:
            opcode, payload = await read_frame(reader)
            if opcode == OP_CLOSE:
                break
            if opcode == OP_PING:
                await conn.send_frame(OP_PONG, payload)
                continue
            if opcode == OP_PONG:
                continue
            if opcode == OP_BINARY:
                await handle_relay_binary(conn, payload)
                continue
            if opcode == OP_TEXT:
                await handle_text(conn, payload)
    except WSError:
        pass
    except (ConnectionResetError, BrokenPipeError):
        pass
    except Exception as e:
        log.info("connection error: %s: %s", type(e).__name__, e)
    finally:
        conn.alive = False
        conns.discard(conn)
        had_room = await remove_from_room(conn)
        if had_room:
            await send_room_list()
        try:
            writer.close()
        except Exception:
            pass
        log.info("disconnected: %s (total %d)", conn.name or conn.id[:8], len(conns))


# Filled in by main(): the STUN endpoints advertised to clients.
STUN_ENDPOINTS = []


def _advertise_stun(host, p1, p2):
    global STUN_ENDPOINTS
    STUN_ENDPOINTS = [(host, p1)] + ([(host, p2)] if p2 else [])
    log.info("built-in STUN advertised: %s",
             ", ".join("%s:%d" % e for e in STUN_ENDPOINTS))


async def main():
    global STUN_ENDPOINTS
    log.info("=== MCLanP2P signaling server (python) start, port %d ===", PORT)

    transports, p1, p2 = await start_stun()
    if transports:
        if STUN_HOST:
            _advertise_stun(STUN_HOST, p1, p2)
        else:
            # Probe in the background: this talks to an external STUN
            # server and must not delay startup (a slow or firewalled host
            # would otherwise hold up every client, and a reconnecting
            # client could time out waiting for a server that is still
            # "starting"). Endpoints are published as soon as we know them.
            async def _probe():
                host = await asyncio.get_running_loop().run_in_executor(
                    None, detect_public_host)
                if host:
                    _advertise_stun(host, p1, p2)
                else:
                    log.info("built-in STUN running but public IP unknown - "
                             "set STUN_HOST to advertise it")

            asyncio.create_task(_probe())
    server = await asyncio.start_server(client_loop, "0.0.0.0", PORT)
    addrs = ", ".join(str(s.getsockname()) for s in server.sockets or [])
    log.info("listening on %s", addrs)

    stop = asyncio.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            asyncio.get_running_loop().add_signal_handler(sig, stop.set)
        except NotImplementedError:
            pass
    try:
        async with server:
            await stop.wait()
    finally:
        for tr in transports:
            try:
                tr.close()
            except Exception:
                pass


def run():
    """Synchronous entry point — what packaged builds call."""
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        log.info("shutting down")


if __name__ == "__main__":
    run()
