# -*- coding: utf-8 -*-
"""Peer channels and the streams carried inside them.

A PeerChannel is one remote peer: its own transport, its own inbound
buffer, and (on the host side) its own connection to the local Minecraft
server.

Why per-peer isolation matters
------------------------------
Sharing one stream would interleave two players' protocol data into a
single MC connection and corrupt both sessions. This mirrors how a
multi-tunnel relay client works: N tunnels, each with its own local
backend connection, instead of one shared pipe.

Why per-stream isolation matters
--------------------------------
One peer link carries MANY Minecraft connections (a server-list probe,
then the real join). Each needs its own backend socket, because the MC
protocol is stateful and the server closes the socket after answering a
status request.
"""
import queue
import struct
import threading

from protocol import STREAM_DATA, SID_HDR, MAX_FRAME


class Stream:
    """One Minecraft connection carried over a peer channel."""

    def __init__(self, sid):
        self.sid = sid
        self.q = queue.Queue(maxsize=8192)
        self.stop = threading.Event()
        self.up = 0        # bytes sent to the peer
        self.down = 0      # bytes received from the peer

    def put(self, data):
        if self.stop.is_set():
            return
        try:
            self.q.put_nowait(data)
        except queue.Full:
            pass


class PeerChannel:
    """One remote peer: its own transport, inbox, and local MC socket.

    The inbox buffers peer data from the moment the link comes up. The
    host only starts pumping after its local MC connection succeeds, so
    nothing is lost in between — same effect as a READY handshake.
    """

    def __init__(self, peer_id, label, send_fn=None, log=print):
        self.peer_id = peer_id
        self.label = label
        self.send_fn = send_fn
        self.log = log
        self.inbox = queue.Queue(maxsize=8192)
        self.stop = threading.Event()
        self.tunnel = None
        self.streams = {}          # sid -> Stream
        self._stream_lock = threading.Lock()
        self._next_sid = 0
        self._rx = bytearray()     # inbound byte stream awaiting framing
        self._rx_lock = threading.Lock()

    def feed(self, data):
        """Parse a byte stream into (sid, payload) frames.

        Transport-agnostic: a WebSocket relay frame arrives whole, while a
        UDP tunnel delivers MTU-sized slices. Both are handled by
        buffering and only emitting once the declared length is present.
        """
        out = []
        with self._rx_lock:
            buf = self._rx
            buf += data
            while True:
                if not buf:
                    break
                if buf[0] != STREAM_DATA:
                    # Not a stream frame. Emitting it as sid=0 made the host
                    # open a REAL connection to its local Minecraft and push
                    # the garbage into it -- a stray byte could reach the
                    # world socket. Skip one byte and resync instead; the
                    # control messages this used to carry (STREAM_OPEN and
                    # friends) are dead code now that they go over the
                    # signalling channel.
                    del buf[:1]
                    continue
                if len(buf) < SID_HDR:
                    break
                sid, ln = struct.unpack(">II", bytes(buf[1:SID_HDR]))
                if ln > MAX_FRAME:          # corrupt: resync
                    del buf[:1]
                    continue
                if len(buf) < SID_HDR + ln:
                    break                   # partial, wait for more
                out.append((sid, bytes(buf[SID_HDR:SID_HDR + ln])))
                del buf[:SID_HDR + ln]
        return out

    def get_stream(self, sid):
        with self._stream_lock:
            return self.streams.get(sid)

    def alloc_stream(self, sid):
        """Returns (stream, created). Idempotent for the same sid."""
        with self._stream_lock:
            st = self.streams.get(sid)
            if st is not None:
                return st, False
            st = Stream(sid)
            self.streams[sid] = st
            return st, True

    def next_stream(self):
        with self._stream_lock:
            self._next_sid += 1
            sid = self._next_sid
            st = Stream(sid)
            self.streams[sid] = st
            return st

    def drop_stream(self, sid):
        with self._stream_lock:
            self.streams.pop(sid, None)

    def stop_streams(self):
        with self._stream_lock:
            sts = list(self.streams.values())
            self.streams.clear()
        for st in sts:
            st.stop.set()

    def put(self, data):
        if self.stop.is_set():
            return
        try:
            self.inbox.put_nowait(data)
        except queue.Full:
            try:
                self.log("%s: inbox full, dropped %d bytes (TCP retransmits)"
                         % (self.label, len(data)))
            except Exception:
                pass

    def send(self, data):
        if self.send_fn and not self.stop.is_set():
            try:
                self.send_fn(data)
            except Exception:
                pass

    def close(self):
        self.stop.set()
        self.stop_streams()
