# -*- coding: utf-8 -*-
"""NetworkManager: the object the GUI talks to.

This class used to be 1100+ lines doing signalling, hole punching, relay,
and local forwarding all at once. It is now assembled from four
mixins, each in its own module:

    net_sig.py        signalling link, ping/pong, reconnect supervision
    net_room.py       room create / join / leave / delete / list
    net_transport.py  per-peer channels: direct / relay
    net_proxy.py      local Minecraft forwarding

Mixins keep ONE object (self) holding all the state, so the split is purely
about where the code lives, not about how it shares data.

Everything from `protocol` and `common` is re-exported here on purpose:
older code and the tests import these names from `net`.
"""
import os
import queue
import socket
import struct
import threading
import time

from protocol import *            # noqa: F401,F403  (re-export)
from protocol import (MODE_AUTO, MODE_DIRECT, MODE_RELAY,
                      PUNCH_PORT, MC_SERVER_PORT, MC_PROXY_PORT,
                      BUFFER_SIZE, STREAM_DATA, SID_HDR, MAX_FRAME, MAX_PLAYERS,
                      NAT_UNKNOWN, NAT_CONE, NAT_SYMMETRIC, SYM_SPRAY_PORTS,
                      NAT_SUB_CONE, NAT_SUB_EASY_INC, NAT_SUB_EASY_DEC,
                      NAT_SUB_HARD, NAT_SUB_UNKNOWN,
                      FILTER_UNKNOWN,
                      STATE_IDLE, STATE_CONNECTING, STATE_WAITING,
                      STATE_ONLINE, STATE_ERROR, STATE_TEXT,
                      RECONNECT_MIN_S, RECONNECT_MAX_S, RECONNECT_FACTOR,
                      NAT_RECHECK_S, TCP_PUNCH_PORT,)
from common import (app_dir, settings_path, load_settings, save_settings,
                    log_to_file, tune, close_sock, human_bytes, human_rate,
                    RateMeter, stun_mapped_address, test_server,
                    stun_probe, local_endpoints, order_candidates,
                    predicted_ports,
                    build_manual_address)
from channel import PeerChannel, Stream
from net_sig import SignalingMixin
from net_room import RoomsMixin
from net_transport import TransportMixin
from net_proxy import ProxyMixin


class NetworkManager(SignalingMixin, RoomsMixin, TransportMixin, ProxyMixin):
    """Facade over the four mixins. Nothing else should live here."""

    def __init__(self, log_cb=print, status_cb=print,
                 rooms_cb=None, members_cb=None, home=None, mc_port=None,
                 proxy_port=None):
        self.home = home or app_dir()
        self.mc_port = int(mc_port) if mc_port else MC_SERVER_PORT
        # port a guest's Minecraft connects to; configurable so several
        # clients on one PC (or a port clash) can each pick their own
        self.proxy_port = int(proxy_port) if proxy_port else MC_PROXY_PORT
        self.log_cb = log_cb
        self.status_cb = status_cb
        self.rooms_cb = rooms_cb
        self.members_cb = members_cb

        self.mode = MODE_AUTO
        self.manual_ip = ""
        self.my_id = ""
        self.my_name = ""
        self.room_code = ""
        self.room_name = ""      # remembered so a reconnect can re-create it
        self.is_host = False
        self.max_players = MAX_PLAYERS   # capacity of the room we are in

        self.ws = None
        self.udp = None
        self.udp_port = 0
        self.hub = None            # owns the punch socket, routes by address

        self.channels = {}         # peer_id -> PeerChannel
        self._chan_lock = threading.Lock()
        self._proxy_started = False
        self.members_snapshot = []
        self.rooms_snapshot = []   # last room_list, for reconnect fallback
        self.punch_port = PUNCH_PORT   # overridable per instance

        # endpoint discovery results
        self.my_locals = []            # LAN endpoints of THIS host
        self.p2p_addr = ""             # endpoint published to the peer
        self.last_error_code = None    # last server error code, if any
        self.room_password = ""        # used when re-creating after a drop
        self.nat_type = NAT_UNKNOWN
        self.nat_delta = 1
        # Refined NAT4 class (cone / easy_inc / easy_dec / hard). Coarse
        # "symmetric" is not actionable: most such NATs allocate
        # sequentially and are perfectly punchable. See client/natpunch.py.
        self.nat_subtype = NAT_SUB_UNKNOWN
        # RFC 5780 filtering behaviour: what the NAT lets back IN.
        # Independent of mapping -- see natpunch.must_open_first.
        self.nat_filter = FILTER_UNKNOWN
        # Last measured values, so a periodic re-measure can tell "changed"
        # from "same". Without this the client cannot notice that it moved
        # to a different network, and keeps punching at an endpoint that no
        # longer exists.
        self._nat_snapshot = None
        self._nat_recheck_started = False
        # Consecutive re-checks that came back WORSE than what we already
        # believed. A downgrade needs confirming; see net_sig._recheck_nat.
        self._nat_downgrade_pending = 0
        # Derived from the UDP punch port unless set explicitly.
        #
        # A hardcoded 30001 collides with a user who moved the UDP port to
        # 30001 in settings (it is configurable there), and a collision here
        # is silent: the TCP attempt just never crosses. Offsetting from the
        # UDP port keeps the two apart by construction.
        self.tcp_punch_port = 0        # resolved in _resolve_tcp_port()
        # 0 = derive it from the UDP punch port. Settable from the UI
        # ("TCP 打洞" field); blank means derive.
        self.tcp_punch_port_cfg = 0
        # UPnP: a router-agreed port mapping beats every probabilistic
        # trick -- it gives us a REAL public port, so the peer just
        # connects. Tried in the background; usually absent, which is fine.
        self.upnp = None
        self.upnp_endpoint = ""
        # Has the server told us where its STUN is? Endpoint discovery waits
        # on this: publishing before `registered` lands means the built-in
        # STUN is never asked (see _wait_for_server_stun).
        self._stun_ready = threading.Event()
        # Set once the server has answered our register. Anything that has
        # to be identified to the server (join/create a room) must wait for
        # it: sending join_room before register has been processed is
        # rejected, and a reconnect that restores its room in connect()
        # sends exactly that, too early.
        self._registered = threading.Event()
        # Did STUN ever succeed? Endpoint discovery is only safe to REPEAT
        # while this is False -- on a symmetric NAT every probe burns an
        # allocation slot and shifts the mapping the peer is aiming at.
        self._have_public_addr = False
        self._published_once = False
        self._refresh_lock = threading.Lock()
        self._refresh_inflight = False
        self._peer_candidates = {}     # peer_id -> [(ip, port), ...]
        # Only ONE direct loop per peer, ever.
        #
        # Every start_punch, every "link died, rebuilding" and every mode
        # switch used to spawn another loop, and nothing stopped them: the
        # loops shared one channel but each kept its own `attempt` counter,
        # so a log would show direct #1 through #10 all running at once -- a
        # thousand UDP sockets, ten independent failure counters each
        # reaching the limit on its own, and a blacklist that expired into
        # nine more loops already mid-punch.
        self._direct_loops = set()
        self._direct_loop_lock = threading.Lock()
        self._peer_nat = {}            # peer_id -> nat type string
        # Coordinated punch start: `start_in` is a relative delay (seconds
        # to wait) and `recv_at` is the monotonic clock reading when the
        # start_punch arrived. The deadline is recv_at + start_in, so it is
        # independent of both the wall clock and of how long the earlier
        # candidates took on this side.
        self._punch_start_in = {}      # peer_id -> seconds to wait
        self._punch_recv_at = {}       # peer_id -> monotonic arrival time
        self._punch_synced = set()     # peers whose wait has been spent
        # Bumped on every start_punch for a peer. A coordinated wait that is
        # already sleeping checks it: if both ends switch to direct at once
        # the server sends each of them two start_punch messages, and the
        # second deadline replaces the first -- so the sleep must restart
        # against the new one rather than finish against the stale one.
        self._punch_gen = {}           # peer_id -> counter
        self._direct_fails = {}        # peer_id -> consecutive failed rounds
        self._direct_blacklist = {}    # peer_id -> monotonic time to retry
        self._peer_delta = {}          # peer_id -> that peer's port step
        self._peer_sub = {}            # peer_id -> refined NAT subtype
        self._peer_filter = {}         # peer_id -> RFC 5780 filtering
        self._peer_tcp = {}            # peer_id -> TCP punch port
        self._peer_per_ip = {}         # peer_id -> separate port region
                                       # per destination IP (see
                                       # protocol.PER_IP_POOL_GAP)
        self._filter_probe_started = False

        self._stop = threading.Event()
        self._conn_dead = threading.Event()   # signalling link is gone
        self._send_lock = threading.Lock()
        self._threads = []
        self._threads_lock = threading.Lock()

        self.target_id = ""
        self.target_addr = None
        self.host_id = ""          # star topology: guests only talk to the host

        # traffic counters, surfaced in the GUI status panel
        self.bytes_up = 0
        self.bytes_down = 0
        self._stat_lock = threading.Lock()
        self._up_meter = RateMeter()
        self._down_meter = RateMeter()

        # latency: measured from ping/pong round trip, reported upstream so
        # the member list shows something real instead of a constant 0
        self.latency_ms = 0
        self._ping_lock = threading.Lock()
        self._pending_pings = {}      # seq -> monotonic send time
        self._ping_seq = 0
        self._last_reported = -1

        # ---- session state machine ----
        self._state = STATE_IDLE
        self._status_text = STATE_TEXT[STATE_IDLE]

        # ---- auto reconnect ----
        self.auto_reconnect = True
        self._gen = 0          # bumped per connect; stale loops exit
        self._conn_params = None    # (url, name, manual_ip, mode)
        self._room_to_restore = None   # (code, name, was_host)
        self._reconnect_thread = None

    # ---------------------------------------------------------- state

    @property
    def state(self):
        return self._state

    def set_state(self, state, reason=""):
        """Drive the UI from a small fixed set of states.

        Before this, status() was called with ~14 free-form strings, some
        Chinese and some English, so the GUI could not reason about
        "can the user press connect right now".
        """
        if state == self._state:
            return
        self._state = state
        text = STATE_TEXT.get(state, state)
        if reason:
            text = "%s（%s）" % (text, reason)
        self.status(text)

    def _set_online_state(self):
        """ONLINE once a peer link exists, WAITING while we still wait."""
        with self._chan_lock:
            live = [c for c in self.channels.values() if not c.stop.is_set()]
        if live:
            self.set_state(STATE_ONLINE)
        elif self.room_code:
            self.set_state(STATE_WAITING, "等待连接")


# ------------------------------------------------------------------
# keep the old public names importable from here
# ------------------------------------------------------------------

__all__ = [
    "NetworkManager", "PeerChannel", "Stream",
    "load_settings", "save_settings", "test_server", "build_manual_address",
    "stun_mapped_address", "stun_probe", "local_endpoints",
    "order_candidates", "predicted_ports", "settings_path", "app_dir",
    "human_bytes", "human_rate", "RateMeter",
    "MODE_AUTO", "MODE_DIRECT", "MODE_RELAY",
    "PUNCH_PORT", "MC_SERVER_PORT", "MC_PROXY_PORT",
    "STATE_IDLE", "STATE_CONNECTING", "STATE_WAITING",
    "STATE_ONLINE", "STATE_ERROR", "STATE_TEXT",
]
