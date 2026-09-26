# -*- coding: utf-8 -*-
"""Local forwarding between Minecraft and the peer link.

Host side: accept a local MC connection, open a fresh stream on the peer
channel, and pump both ways.
Guest side: listen on a local port, and for each MC connection that comes
in open a stream toward the host.
"""
import queue
import socket
import struct
import threading
import time

from protocol import (BUFFER_SIZE, STREAM_DATA, SID_HDR, MAX_FRAME,
                      STREAM_OPEN, STREAM_CLOSE, frame, control_frame)
from common import tune, close_sock, listen_backlog


class ProxyMixin:
    def _start_forward(self, ch):
        self.log("=== game traffic via %s ===" % ch.label)
        self.status("P2P connected (%s)" % ch.label)
        # The new link is carrying traffic, so the one it replaces can go.
        # See _teardown_peer: we keep the old one alive until here.
        try:
            self._drop_replaced_link(ch.peer_id)
        except Exception:
            pass
        self._spawn(lambda: self._demux(ch))
        if not self.is_host:
            self._ensure_guest_proxy()

    # ---- stream demux: route inbound frames by stream id ----

    def _demux(self, ch):
        while not ch.stop.is_set() and not self._stop.is_set():
            try:
                data = ch.inbox.get(timeout=1.0)
            except queue.Empty:
                continue
            except Exception:
                break
            for sid, payload in ch.feed(data):
                st = ch.get_stream(sid)
                if st is None:
                    # control message lost or not yet arrived: create on demand
                    st, created = ch.alloc_stream(sid)
                    if created and self.is_host:
                        self._spawn(lambda x=st: self._host_stream(ch, x))
                if payload:
                    st.put(payload)

    def _host_stream(self, ch, st):
        """Host: open ONE dedicated connection to the local MC server for
        this stream, and only this stream.

        The Minecraft server closes the socket after answering a server-list
        probe. With a single shared backend connection, that close would
        kill every subsequent connection from that player -- which is why
        "connect to 127.0.0.1:25566" failed right after the list ping.
        """
        while not st.stop.is_set() and not ch.stop.is_set() and not self._stop.is_set():
            try:
                sock = socket.create_connection(("127.0.0.1", self.mc_port), timeout=5)
            except Exception as e:
                if st.stop.is_set() or ch.stop.is_set() or self._stop.is_set():
                    break
                self.log("流 %d：本地 MC 未就绪（%s），2 秒后重试"
                         % (st.sid, type(e).__name__))
                self.status("等待本地世界 %d ..." % self.mc_port)
                time.sleep(2)
                continue
            tune(sock)
            self.log("流 %d -> 本地 MC 127.0.0.1:%d" % (st.sid, self.mc_port))
            self.status("世界已连接 (%d)" % self.mc_port)
            self._pump_stream(ch, st, sock)
            break   # MC closed it; this stream is finished

    def _ensure_guest_proxy(self):
        if self._proxy_started:
            return
        self._proxy_started = True
        self._spawn(self._guest_proxy_loop)

    def _guest_proxy_loop(self):
        """Bind the local proxy, scanning upward if the port is taken.

        Two clients on one machine (or another程序 on 25566) would
        otherwise fail outright with 'port busy'.
        """
        srv = None
        port = self.proxy_port
        wanted = self.proxy_port
        for cand in range(self.proxy_port, self.proxy_port + 25):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.bind(("127.0.0.1", cand))
                # backlog > 1: a client probing the server list opens and
                # drops a connection while the real join is still queued
                sock.listen(listen_backlog())
                srv, port = sock, cand
                break
            except OSError:
                try:
                    sock.close()
                except Exception:
                    pass
        if srv is None:
            self.log("cannot bind any proxy port near %d" % wanted)
            self.status("代理端口 %d 被占用" % wanted)
            self._proxy_started = False
            return
        if port != wanted:
            self.log("port %d busy, using %d instead" % (wanted, port))
        self.proxy_port = port
        srv.settimeout(1.0)
        self.log("代理就绪：MC 请连接 127.0.0.1:%d" % port)
        self.status("MC 请连接 127.0.0.1:%d" % port)
        try:
            while not self._stop.is_set():
                try:
                    mc, _ = srv.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break
                tune(mc)
                self.log("MC client connected to proxy")
                with self._chan_lock:
                    live = [c for c in self.channels.values() if not c.stop.is_set()]
                    # prefer the link to the host; a guest may also hold
                    # stale channels from before a host change
                    ch = next((c for c in live if c.peer_id == self.host_id), None)
                    if ch is None:
                        ch = live[0] if live else None
                if ch is None:
                    # the peer link may be a second away (MC is often opened
                    # before everyone has joined) - wait briefly rather than
                    # dropping the client immediately
                    ch = self._wait_channel(5.0)
                if ch is None:
                    self.log("no peer link yet, closing MC client")
                    try:
                        mc.close()
                    except Exception:
                        pass
                    continue
                # each accepted connection is its own stream, so the host
                # gives it its own backend connection to the MC server
                st = ch.next_stream()
                self._send_stream_open(ch, st.sid)
                self._spawn(lambda m=mc, c=ch, x=st: self._pump_stream(c, x, m))
        finally:
            try:
                srv.close()
            except Exception:
                pass
            self._proxy_started = False

    def _send_stream_open(self, ch, sid):
        self.send({"action": "peer_signal", "targetId": ch.peer_id,
                   "signal": {"t": "open", "sid": sid}})

    def _send_stream_close(self, ch, sid):
        self.send({"action": "peer_signal", "targetId": ch.peer_id,
                   "signal": {"t": "close", "sid": sid}})

    def _pump_stream(self, ch, st, sock):
        """Bidirectional pump for ONE stream.

        Runs on both sides: on the guest it is the accepted MC client; on
        the host it is this stream's own connection to the local MC server.
        """
        try:
            sock.settimeout(None)
        except Exception:
            pass

        def up():
            try:
                while not st.stop.is_set():
                    d = sock.recv(BUFFER_SIZE)
                    if not d:
                        break
                    st.up += len(d)
                    self._count(up=len(d))
                    ch.send(frame(st.sid, d))
            except Exception:
                pass
            st.stop.set()

        def down():
            while not st.stop.is_set() and not ch.stop.is_set():
                try:
                    d = st.q.get(timeout=0.5)
                except queue.Empty:
                    continue
                try:
                    sock.sendall(d)
                    st.down += len(d)
                    self._count(down=len(d))
                except Exception:
                    break
            st.stop.set()

        t1 = threading.Thread(target=up, daemon=True)
        t2 = threading.Thread(target=down, daemon=True)
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        try:
            sock.close()
        except Exception:
            pass
        ch.drop_stream(st.sid)
        self._send_stream_close(ch, st.sid)
        self.log("stream %d closed" % st.sid)
