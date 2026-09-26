# -*- coding: utf-8 -*-
"""Minimal WebSocket *client* (RFC 6455) on top of the standard library.

Client frames MUST be masked; the server replies unmasked.

Everything is read through ONE buffer (`self._buf`).

That is not a style choice. The handshake has to read until "\\r\\n\\r\\n",
which usually over-reads past the end of the response -- and the 101 reply
is frequently followed immediately by the first frame in the same TCP
segment (nginx buffering, TCP coalescing, a server greeting). The previous
version stashed those extra bytes in `_rest`, then read only the 2-byte
header from it and went back to the socket for the extended length, mask
and payload -- silently discarding everything else. One coalesced segment
and the stream was permanently misaligned.

Now every read goes through `_read(n)`, which serves from the buffer first
and only touches the socket when the buffer is short.
"""
import base64
import hashlib
import os
import socket
import struct

WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
OP_CONT, OP_TEXT, OP_BINARY = 0x0, 0x1, 0x2
OP_CLOSE, OP_PING, OP_PONG = 0x8, 0x9, 0xA

# A single logical message may span fragments; the TOTAL is capped, not each
# fragment. Checking fragments individually lets 1000 x 8MB continuations
# accumulate into 8GB of resident memory.
MAX_MESSAGE = 8 * 1024 * 1024        # 8 MB per message
MAX_CONTROL = 125                    # RFC 6455: control frames are <= 125
MAX_FRAGMENTS = 1024                 # no unbounded fragment chains


class WSError(Exception):
    pass


class WSClient:
    def __init__(self, timeout=30.0, max_message=MAX_MESSAGE):
        self.sock = None
        self.timeout = timeout
        self.max_message = max_message
        self._buf = bytearray()

    # ------------------------------------------------------------ io

    def _fill(self):
        """Pull one chunk from the socket into the buffer."""
        chunk = self.sock.recv(65536)
        if not chunk:
            raise WSError("connection closed")
        self._buf += chunk

    def _read(self, n):
        """Take exactly n bytes, buffer first. Never reads past them."""
        while len(self._buf) < n:
            self._fill()
        out = bytes(self._buf[:n])
        del self._buf[:n]
        return out

    def _read_available(self, n):
        """Take up to n bytes that are ALREADY buffered (no blocking)."""
        out = bytes(self._buf[:n])
        del self._buf[:n]
        return out

    # -------------------------------------------------------- connect

    def connect(self, url):
        """url: ws://host:port/path  (wss:// is not supported)"""
        if not url.startswith("ws://"):
            raise WSError("only ws:// is supported: %s" % url)
        rest = url[5:]
        path = "/"
        if "/" in rest:
            hostport, path = rest.split("/", 1)
            path = "/" + path
        else:
            hostport = rest
        if ":" in hostport:
            host, port = hostport.split(":", 1)
            port = int(port)
        else:
            host, port = hostport, 80

        self.sock = socket.create_connection((host, port), timeout=self.timeout)
        self.sock.settimeout(self.timeout)
        key = base64.b64encode(os.urandom(16)).decode()
        req = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {hostport}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n"
        )
        self.sock.sendall(req.encode())

        # Read until the header terminator. Whatever follows stays in
        # self._buf -- it is the start of the first frame.
        while b"\r\n\r\n" not in self._buf:
            self._fill()
        raw = bytes(self._buf)
        head = raw.partition(b"\r\n\r\n")[0]
        del self._buf[:len(head) + 4]

        lines = head.decode("latin1").split("\r\n")
        if "101" not in lines[0]:
            raise WSError("handshake failed: %s" % lines[0])

        # Verify Sec-WebSocket-Accept. Without this we would happily treat
        # any 101 response as a WebSocket -- including an HTTP proxy or a
        # captive portal answering "101" -- and then misparse its body as
        # frames.
        hdrs = {}
        for line in lines[1:]:
            if ":" in line:
                k, _, v = line.partition(":")
                hdrs[k.strip().lower()] = v.strip()
        want = base64.b64encode(
            hashlib.sha1((key + WS_GUID).encode()).digest()).decode()
        got = hdrs.get("sec-websocket-accept", "")
        if got != want:
            raise WSError("bad Sec-WebSocket-Accept (not a websocket?)")
        return True

    # ---------------------------------------------------------- send

    def send_text(self, text):
        self._send_frame(OP_TEXT, text.encode("utf-8"))

    def send_binary(self, data):
        self._send_frame(OP_BINARY, data)

    def _send_frame(self, opcode, payload):
        header = bytearray([0x80 | opcode])
        n = len(payload)
        mask_bit = 0x80  # clients must mask
        if n < 126:
            header.append(mask_bit | n)
        elif n < 65536:
            header.append(mask_bit | 126)
            header += struct.pack(">H", n)
        else:
            header.append(mask_bit | 127)
            header += struct.pack(">Q", n)
        key = os.urandom(4)
        body = bytes(b ^ key[i & 3] for i, b in enumerate(payload))
        self.sock.sendall(bytes(header) + key + body)

    # ---------------------------------------------------------- recv

    def recv_frame(self):
        """Returns (opcode, payload). Raises WSError on close."""
        opcode, payload = None, bytearray()
        total = 0
        fragments = 0
        while True:
            b0, b1 = self._read(2)
            fin = bool(b0 & 0x80)
            rsv = b0 & 0x70
            op = b0 & 0x0F
            if rsv:
                # no extension is negotiated, so any RSV bit is a protocol
                # error -- and a hint that we are misaligned
                raise WSError("RSV bits set (0x%02x)" % b0)
            masked = bool(b1 & 0x80)
            length = b1 & 0x7F
            if length == 126:
                length = struct.unpack(">H", self._read(2))[0]
            elif length == 127:
                length = struct.unpack(">Q", self._read(8))[0]
                # a 63-bit length is not a frame, it is an OOM: _read would
                # happily concatenate chunks until the process died
                if length > self.max_message:
                    raise WSError("frame too large: %d" % length)

            if op in (OP_PING, OP_PONG, OP_CLOSE) and length > MAX_CONTROL:
                raise WSError("control frame too large: %d" % length)

            mask = self._read(4) if masked else b"\x00\x00\x00\x00"
            data = self._read(length) if length else b""
            if masked:
                data = bytes(b ^ mask[i & 3] for i, b in enumerate(data))

            if op in (OP_TEXT, OP_BINARY):
                if opcode is not None:
                    raise WSError("unexpected new frame")
                opcode = op
            elif op == OP_CONT:
                if opcode is None:
                    raise WSError("continuation without start")
                fragments += 1
                if fragments > MAX_FRAGMENTS:
                    raise WSError("too many fragments")
            else:
                # Control frame. Only hand it back when no message is being
                # assembled: returning mid-message threw away everything
                # accumulated so far (payload was dropped on the floor and
                # the caller saw an unrelated opcode). The server does not
                # fragment today, but a proxy that interleaves PING must not
                # corrupt a large frame.
                if opcode is None:
                    return op, data
                continue

            total += len(data)
            if total > self.max_message:
                raise WSError("message too large: %d > %d"
                              % (total, self.max_message))
            payload += data
            if fin:
                return opcode, bytes(payload)

    def close(self):
        try:
            self._send_frame(OP_CLOSE, b"")
        except Exception:
            pass
        try:
            self.sock.close()
        except Exception:
            pass
