# -*- coding: utf-8 -*-
"""Wire constants, frame format and error codes.

Everything the client and the server agree on lives here. Keeping the
framing and the error table in one module means the transport code never
hard-codes a magic byte or an English error string.

Additive-change rule
--------------------
New OPTIONAL fields may be appended to messages, but existing fields must
never change meaning. A newer client talking to an older server must
degrade, not crash.
"""
import struct

# --------------------------------------------------------------- ports

PUNCH_PORT = 30000
MC_SERVER_PORT = 25565
MC_PROXY_PORT = 25566

# MC sends many small packets (moves, block updates are a few dozen bytes).
# 64K reads + TCP_NODELAY: Nagle would otherwise batch them and add a
# round-trip of latency to every single one.
BUFFER_SIZE = 64 * 1024

# --------------------------------------------------------------- framing

# One peer link carries MANY Minecraft connections (a server-list probe,
# then the real join, then maybe a second player), and each needs its OWN
# backend connection to the local MC server -- the MC protocol is stateful
# and the server closes the socket after answering a status request.
STREAM_DATA = 0x02
RELAY_DATA = 0x01          # server-relay: [0x01][id_len][id][payload]
SID_HDR = 9                # 1 type + 4 stream id + 4 payload length
MAX_FRAME = 8 * 1024 * 1024

# control messages that travel on a peer link (not MC payload)
STREAM_OPEN = 0x10
STREAM_CLOSE = 0x11


def frame(sid, data):
    """[0x02][sid:4][len:4][payload] — self-delimiting.

    The length is essential: a UDP tunnel hands back a large message in
    MTU-sized pieces, so the reader cannot rely on one recv() being one
    logical message. With an explicit length the receiver can reassemble
    across an arbitrary split.
    """
    return (bytes([STREAM_DATA]) + struct.pack(">I", sid)
            + struct.pack(">I", len(data)) + data)


def relay_frame(peer_id, data):
    """[0x01][id_len][peer_id][payload] — send via the signalling server."""
    tid = peer_id.encode("ascii", "ignore")[:255]
    return bytes([RELAY_DATA, len(tid)]) + tid + data


def control_frame(kind, sid):
    """A tiny out-of-band note about a stream (open / close)."""
    return bytes([kind]) + struct.pack(">I", sid)


# --------------------------------------------------------------- modes

MODE_AUTO = "auto"
MODE_DIRECT = "direct"
MODE_RELAY = "relay"

MODE_KEYS = (MODE_AUTO, MODE_DIRECT, MODE_RELAY)

# --------------------------------------------------------------- timings

PING_INTERVAL_S = 4.0     # latency sample rate
DIRECT_RETRY_S = 3
RELAY_RETRY_S = 4
AUTO_DIRECT_ATTEMPTS = 2
PUNCH_TIMEOUT_S = 25
# AUTO mode must reach a working link quickly; two long punch windows meant
# ~50s of "connecting" before the relay kicked in.
AUTO_PUNCH_TIMEOUT_S = 10

# Link liveness: how long a direct tunnel may stay silent before we call it
# dead and rebuild.
#
# A UDP hole is not a connection -- nothing "fails" when a NAT mapping
# expires or the peer restarts. The peer simply stops answering, and without
# this check the client would keep pushing game data into a dead tunnel
# while the UI still said "运行中".
#
# Both ends send a keepalive, so silence longer than a few keepalive
# intervals means the hole is gone. Must be well above the keepalive period
# (and above a couple of lost packets), but short enough that a player
# notices a reconnect rather than a frozen world.
LINK_CHECK_S = 5          # how often to poll
LINK_DEAD_S = 20          # silence that counts as a dead link

# How often to re-measure our own NAT.
#
# The type is not a constant: a laptop moved to another network, a router
# that redialled, a CGNAT that reassigned us -- all of these change the
# endpoint or the allocation behaviour, and a measurement taken at connect
# time describes a network we may no longer be on. Long enough that the
# probe is not a nuisance, short enough that a change is noticed before the
# link has been dead for minutes.
NAT_RECHECK_S = 90.0

# TCP simultaneous open: the port both ends bind to locally.
#
# It has to be a FIXED number rather than an ephemeral one, because the
# peer aims at it -- see client/tcppunch.py. Distinct from the UDP punch
# port so the two never fight over the same bind, and so a router that
# forwards one does not silently affect the other.
TCP_PUNCH_PORT = 30001
# How long one crossing attempt waits for the SYNs to meet.
TCP_PUNCH_TIMEOUT_S = 8.0

# auto reconnect (the old client just stopped and waited for a manual click)
RECONNECT_MIN_S = 2.0
RECONNECT_MAX_S = 30.0
RECONNECT_FACTOR = 1.6

# --------------------------------------------------------------- limits

# Room capacity. The host picks it; the server enforces it.
# Lower bound 2: a "1 player" room is a singleplayer world with extra steps.
# Upper bound 64: beyond that the star topology (every guest tunnels to the
# host) makes the host the bottleneck long before the protocol does.
MIN_PLAYERS = 2
MAX_PLAYERS = 10          # default capacity, user configurable
MAX_PLAYERS_LIMIT = 64

# --------------------------------------------------------------- states
#
# The GUI needs to answer "can the user press connect right now". With
# free-form status strings it could not, so the session drives a small
# fixed state machine and the GUI looks at the state, not the text.

STATE_IDLE = "IDLE"
STATE_CONNECTING = "CONNECTING"
STATE_WAITING = "WAITING"
STATE_ONLINE = "ONLINE"
STATE_ERROR = "ERROR"

STATE_TEXT = {
    STATE_IDLE: "未连接",
    STATE_CONNECTING: "连接中",
    STATE_WAITING: "等待中",
    STATE_ONLINE: "运行中",
    STATE_ERROR: "出错",
}

# --------------------------------------------------------------- nat
#
# NAT type is INFORMATIONAL ONLY. It must never be used to declare "P2P
# impossible" -- plenty of NATs misreport, and the only reliable verdict is
# an actual punch attempt. It only decides how hard we try:
# a symmetric NAT gets a port-predicted spray, a cone NAT does not need one.

NAT_UNKNOWN = "unknown"
NAT_CONE = "cone"          # one mapping for every destination
NAT_SYMMETRIC = "symmetric"  # a new mapping per destination (a.k.a. NAT4)

# NAT4 is not one thing -- it is a spectrum of "how predictable is the next
# port". Treating every symmetric NAT as "hopeless" is what made NAT4 direct
# connections fail: the majority of real NAT4s allocate SEQUENTIALLY, so the
# next mapping is guessable, and only a minority are truly random.
#
# Refined by asking one extra question (see natpunch.refine_nat_subtype):
# what mapping does a brand NEW socket get from a server we already asked?
#
#   sym_easy_inc  next mapping is a little ABOVE this one (port + k)
#   sym_easy_dec  next mapping is a little BELOW this one
#   sym_hard      no usable pattern -- needs a birthday attack, or a relay
NAT_SUB_CONE = "cone"
NAT_SUB_EASY_INC = "sym_easy_inc"
NAT_SUB_EASY_DEC = "sym_easy_dec"
NAT_SUB_HARD = "sym_hard"
NAT_SUB_UNKNOWN = "unknown"

# RFC 5780 FILTERING behaviour -- the other axis.
#
# The subtypes above describe how a NAT MAPS outbound flows. They say
# nothing about what it lets back IN, and the two are independent: a NAT can
# hand out a fresh port per destination and still accept inbound packets
# from anywhere. That combination is far easier to punch than "symmetric"
# suggests, because the door is already open and only the port has to be
# guessed.
#
#   eif   endpoint-independent: any host may reach the mapping
#   adf   address-dependent:    only hosts we have written to
#   apdf  address+port dep.:    only the exact address we have written to
#
# Which of these applies decides who has to speak first -- see
# natpunch.must_open_first.
FILTER_EIF = "eif"
FILTER_ADF = "adf"
FILTER_APDF = "apdf"
FILTER_UNKNOWN = "unknown"

# Human-readable labels. Shown IN THE ROOM next to every player's name --
# see ui.nat_label. Kept here because these strings are protocol values,
# not presentation.
NAT_LABEL = {
    NAT_UNKNOWN: "未知",
    NAT_CONE: "锥型 (NAT1-3)",
    NAT_SYMMETRIC: "对称型 (NAT4)",
}
NAT_SUB_LABEL = {
    NAT_SUB_CONE: "锥型",
    NAT_SUB_EASY_INC: "对称·递增（可预测）",
    NAT_SUB_EASY_DEC: "对称·递减（可预测）",
    NAT_SUB_HARD: "对称·随机（难）",
    NAT_SUB_UNKNOWN: "未测出",
}
NAT_FILTER_LABEL = {
    FILTER_EIF: "入站宽松",
    FILTER_ADF: "入站中等",
    FILTER_APDF: "入站严格",
    FILTER_UNKNOWN: "入站未测",
}


def nat_label(nat, sub=None, filt=None):
    """One short line describing a member's NAT, for the room list.

    Deliberately verbose over terse: the people reading this are trying to
    work out why a connection is not working, and "NAT4" alone does not
    tell them whether that is fatal. "对称·递增（可预测）" and
    "对称·随机（难）" are both symmetric, and they are not the same problem.
    """
    # The subtype already implies the coarse type -- "对称·递增" IS
    # symmetric -- so printing both was redundant and made the room list
    # row too long to read. Only fall back to the coarse label when there
    # is nothing more specific.
    if sub and sub in (NAT_SUB_EASY_INC, NAT_SUB_EASY_DEC, NAT_SUB_HARD):
        parts = [NAT_SUB_LABEL[sub]]
    else:
        parts = [NAT_LABEL.get(nat, NAT_LABEL[NAT_UNKNOWN])]
    if filt and filt != FILTER_UNKNOWN:
        parts.append(NAT_FILTER_LABEL.get(filt, filt))
    return " · ".join(parts)

# How far apart two mappings may be and still count as "sequential".
# Beyond this the allocation is not a small step, so prediction is a waste.
NAT_EASY_MAX_STEP = 100
# Gap between two DIFFERENT server IPs that means "each destination IP gets
# its own port region".
#
# Two different IPs reporting 47524 and 41105 (real log) is not a step, it
# is two separate pools: this NAT hands out a fresh region per destination
# IP. The port it will use for the peer -- an address we have never sent to
# -- is therefore somewhere we cannot predict, and a contiguous window
# around the port it published for a STUN server is aimed at the wrong
# region entirely.
#
# It is deliberately much larger than NAT_EASY_MAX_STEP, because a SMALL
# gap between two IPs is not evidence of separate pools: consecutive flows
# to one host drift with whatever else the machine is doing (measured 167
# where the true step was 1), and the same drift shows up between two IPs.
# Only a gap no amount of background traffic explains means separate pools.
PER_IP_POOL_GAP = 512
# Share of every scan round spent on uniformly random ports when the peer's
# allocation is per-destination-IP, i.e. when a window cannot possibly be
# aimed correctly. See natpunch._run_punch_inner.
WINDOW_RANDOM_MIX_PER_IP = 0.35
# How spread out the mappings seen from one socket may be before we call it
# hard-symmetric (EasyTier uses 15).
# EasyTier uses 15. That is too tight for a real desktop: the two probes
# are seconds apart, and anything the machine does in between (QUIC, a DNS
# lookup, a game) consumes an allocation slot too -- 16 concurrent flows is
# ordinary, not exotic. At 15 such a NAT is mis-read as "random", which is
# the one verdict that switches off every mechanism we have.
# A LAN candidate either answers immediately or never -- there is no NAT to
# punch. Giving it the full punch budget spent most of the first attempt on
# an address that could not work.
# How many times to sample "what does the next mapping look like". One
# reading is not trustworthy (see common._third_probes); two agreeing ones
# are, and three is the point of diminishing returns.
THIRD_PROBE_SAMPLES = 3
# Stop as soon as this many samples agree -- the connect path is
# user-visible, so it takes the minimum and no more.
THIRD_PROBE_MIN_SAMPLES = 2

# IPv6 either answers immediately or never: no NAT, but home routers often
# allow v6 out and block v6 in, so a global address is not proof that the
# peer accepts inbound. A full budget here just delays the v4 attempt.
IPV6_PUNCH_TIMEOUT_S = 3.0
# Wall clock for one whole round of candidates. A single candidate that
# never returns otherwise hides every candidate behind it forever -- in a
# real log the IPv6 attempt printed once and then nothing for 51s, while
# the IPv4 address that could have worked waited behind it, untried.
ROUND_WALL_CLOCK_S = 30.0

# Cap on how long we will wait for the server's coordinated start, so a
# badly skewed clock on the server cannot stall a punch indefinitely.
PUNCH_START_MAX_WAIT_S = 5.0

# Failure blacklist / backoff.
#
# Retrying the same unreachable address every 3s forever is not persistence,
# it is a loop with no exit: the user watches "connecting" and nothing ever
# changes. EasyTier blacklists a failed peer for an hour; these are much
# gentler because a peer that reconnects should come back quickly.
# These used to be 60s / 4 / (3, 6, 12, 24): a full cycle was 45s of
# backoff plus a 60s blacklist, i.e. nearly two minutes before the peer got
# another real try. For a network that came back after a blip that is
# punitive, and NAT4 in particular often succeeds on a later round.
#
# A short cycle is not the same as hammering: each round still costs a
# punch attempt, and the blacklist is still a real pause. 7s of growing
# backoff then a 12s park keeps the retry pressure low while returning to
# a working link in seconds rather than minutes.
# Auto mode: keep punching in the BACKGROUND while the relay carries the
# traffic.
#
# A punch is a collision between two moving port allocations, so the first
# attempt failing says very little about the tenth: the peer may have been
# mid-restart, its anchor may have been stale, or its NAT may have been
# re-allocating at that moment. EasyTier never stops trying and upgrades the
# link when it lands, which is why it shows "direct" on pairs a single
# timed attempt gives up on.
#
# Cheap on purpose: one short punch per minute, while the user is already
# playing over the relay.
RELAY_UPGRADE_EVERY_S = 60.0
RELAY_UPGRADE_BUDGET_S = 8.0

DIRECT_FAIL_BLACKLIST_S = 12.0    # park this peer for this long, then retry
DIRECT_FAIL_LIMIT = 3             # consecutive full failures to trigger it
DIRECT_BACKOFF_S = (1, 2, 4)      # sleep between attempts, then park
DIRECT_BACKOFF_MAX_S = 8.0

LAN_PUNCH_TIMEOUT_S = 2.0
# When the policy says there is NO mechanism for this pair, a full punch
# budget only delays the outcome. Direct mode still tries -- the user
# asked for direct -- but briefly.
NO_MECHANISM_TIMEOUT_S = 5.0
# How old the published endpoint may be before we re-measure it prior to a
# scan that depends on it. See _refresh_anchor_if_stale: on a fast-moving
# NAT the anchor drifts far enough in this long to put the whole scan in
# the wrong place.
ANCHOR_STALE_S = 15.0
# How long after RECEIVING a forced re-punch we refuse to send one back.
# See _request_punch_coordination: answering a force with a force is a loop.
FORCE_ANSWER_QUIET_S = 30.0
# The server's inbound probe: one packet, and how long to wait for it.
INBOUND_PROBE_TIMEOUT_S = 4.0
# One UDP packet the server sends from a fresh socket to see whether ANY
# unrelated host can reach us. See NetSession._probe_inbound: it is the
# only diagnostic that separates "our scan is wrong" from "inbound UDP is
# blocked", which look identical everywhere else.
INBOUND_PROBE_PACKET = b"MCLANP2P-INBOUND-PROBE"
# The packet WE send to the server to open a mapping towards it before
# asking for the probe.
#
# Without it the probe is unanswerable-by-design on the most common NATs:
# the server's packet arrives from a host we have never sent a UDP packet
# to, and a NAT that filters per address (or per address+port) drops it on
# arrival. That is not a blocked firewall, it is a NAT doing its job -- and
# reading it as "no amount of punching can help" gave up on every pair that
# was perfectly punchable.
INBOUND_PROBE_WARM_PACKET = b"MCLANP2P-INBOUND-WARM"
# How many warm packets, and how far apart. One can be lost; a burst of
# three spread over ~0.6s is still cheaper than mistaking ADF for a wall.
INBOUND_PROBE_WARM_COUNT = 3
INBOUND_PROBE_WARM_GAP_S = 0.2
# A second probe round after the OS firewall has been opened: the rule only
# takes effect for packets that arrive later, so the result has to be
# re-measured, never assumed.
INBOUND_PROBE_RETRY_S = 1.0
# How long to wait for the server to report the source port it saw on our
# TCP probe connection. See tcppunch.probe_preserved_port: whether the NAT
# preserves the TCP punch port decides whether a simultaneous open can
# cross, and it CANNOT be inferred from the UDP mapping.
TCP_PROBE_TIMEOUT_S = 4.0
# Extra wall-clock grace over the IPv6 handshake budget before the caller
# gives up on it and closes the socket. See _try_ipv6: connect() is handed
# a budget and must still be leashed, because a stalled v6 attempt blocks
# the v4 candidate queued behind it.
IPV6_CONNECT_SLACK_S = 2.0
ANCHOR_REFRESH_TIMEOUT_S = 1.2

# After a punch HIT the hole is already open, so the handshake should be
# quick. Waiting a full budget risks the peer's socket array expiring first.
HANDSHAKE_AFTER_HIT_S = 3.0
# sym_to_cone: the symmetric side opens a bank of ports and the cone side
# walks them. The cone side usually spends its own single-socket budget
# first, so the bank must still be open when it starts scanning. 6s was not
# enough -- give it the same floor both_easy gets.
SYM_TO_CONE_MIN_S = 8.0
SYM_TO_CONE_SPRAY_S = 12.0
# Total time the RFC 5780 filtering probe may spend, across all servers.
FILTER_PROBE_BUDGET_S = 4.0
# The cone side walks WINDOW_SYM_TO_CONE ports with its own socket count.
# Give it long enough to finish at least one full pass AFTER its own
# single-socket attempt has failed -- the two used to be the same budget,
# so the array closed before the peer had even started walking it.

# (removed) NAT_HARD_SPREAD used to decide the subtype, checked BEFORE the
# third probe: |p2 - p1| > 128 returned sym_hard outright. But p1 and p2
# are mappings for two DIFFERENT destinations, so their gap is not a step
# -- it is the step plus however many unrelated flows the machine opened
# while we were asking. Measured on a sequential NAT: p1=60225, p2=60392
# (gap 167) while the real step, from the third probe, was +1. The verdict
# was "random" for a NAT that had not changed, and hard x hard is the one
# pair punch_plan refuses, so it cost the direct connection outright.
#
# Deleted rather than kept: an unused threshold that still reads like part
# of the decision invites someone to "tune" it back into use.

# Symmetric-NAT hole punching (this is what lets EasyTier/Astral connect
# through NAT4).
#
# A symmetric NAT picks a fresh external port per destination, so both ends
# send to a port the other side can never know. But most such NATs allocate
# ports SEQUENTIALLY, so a small number of guesses covers a large share of
# real cases: we measure the increment by asking two different STUN servers
# from the same socket, then spray HELLO at port, port±delta, port±2·delta…
#
# Both sides spray at once, so what matters is that ONE our guesses lands on
# the mapping the peer actually created. Bounded on purpose -- an unbounded
# spray is indistinguishable from a DoS.
SYM_SPRAY_PORTS = 50       # how many extra ports to try (EasyTier uses 50)
SYM_MAX_DELTA = 1000       # ignore absurd increments (not sequential)

# Safety cap on the whole spray.
#
# A wider window is a higher hit rate -- that is the whole point of
# prediction -- but it is also more datagrams aimed at one host. Two things
# keep that honest: the order is shuffled (a sequential walk is exactly what
# an IDS calls a port scan) and the mode is switchable off entirely.
SPRAY_BUDGET = 50
# An UNMEASURED NAT gets a narrower window than a confirmed symmetric one:
# we are guessing about a NAT we never characterised, so a big spray is not
# justified. 50 is reserved for the case we are confident about.
UNKNOWN_SPRAY_PORTS = 24
JITTER_SPRAY = True
# How many predicted ports may be skipped before the spray starts. Jitter
# exists so two peers do not synchronise their bursts; skipping 0-or-1
# entries (the old code) was not jitter at all, just an off-by-one.
JITTER_MAX_SKIP = 3

# --------------------------------------------------------------- stun

# Ordering matters: the first two that ANSWER decide the NAT type, so the
# ones most likely to be reachable from China come first. Everything here is
# best-effort -- the reliable source is the STUN server the signalling
# server runs itself (see STUN_SERVERS_FROM_SERVER below), which is why the
# server advertises its own and the client prefers that.
# Ordering matters: the first two that ANSWER decide the NAT type, so the
# reachable ones come first.
#
# Public STUN, most-likely-to-answer first.
#
# Honest caveat: NONE of these is guaranteed. Public STUN servers go away,
# get rate-limited, or are blocked by particular ISPs -- stun.qq.com is a
# well-known example that still resolves but stopped answering. They are only
# a BACKUP: the signalling server runs its own STUN and the client always
# tries that first (see STUN_PORT / stun_probe's `preferred` argument).
#
# China-mainland servers lead because stun.l.google.com is unreachable there,
# which is why endpoint discovery used to time out for CN users.
STUN_SERVERS = [
    ("stun.miwifi.com", 3478),           # Xiaomi, Beijing
    ("stun.chat.bilibili.com", 3478),    # Bilibili, Beijing
    ("stun.douyucdn.cn", 18000),         # Douyu
    ("stun.hitv.com", 3478),             # Mango TV
    ("stun.cdnbye.com", 3478),           # CDNBye
    ("stun.yy.com", 3478),               # YY
    ("stun.cloudflare.com", 3478),       # global, usually reachable
    ("stun.voipbuster.com", 3478),
    ("stun.schlund.de", 3478),
    ("global.stun.twilio.com", 3478),
    ("stun.voipstunt.com", 3478),
    ("stun.internetcalls.com", 3478),
    ("stun.hot-chilli.net", 3478),
    ("stun.nextcloud.com", 3478),
    ("stun.l.google.com", 19302),        # blocked in mainland China
    ("stun1.l.google.com", 19302),
]

# A STUN server that ships WITH the signalling server (see server/server.py).
#
# Two ports on purpose: detecting a symmetric NAT needs two DIFFERENT
# destinations, and a single-IP vps can only offer that by varying the port.
STUN_PORT = 3478
STUN_ALT_PORT = 3479
# Enough for two round trips to a reachable server (which answers in tens
# of milliseconds), while stopping a blocked network from stalling startup.
STUN_BUDGET_S = 6.0      # total time allowed for endpoint discovery

# How long endpoint discovery waits for the server to say "here is my STUN"
# before publishing anyway.
#
# `registered` (which carries stunServers) and our own publish_offer are
# sent back to back, but the reply is handled by the recv thread -- one
# full RTT later. Without a synchronisation point the publish always won
# the race, so the built-in STUN was never asked and the client published a
# LAN address for the entire session. Wait for it; do not wait forever.
STUN_HANDSHAKE_WAIT_S = 3.0

# --------------------------------------------------------------- errors
#
# The server sends {"action":"error","code":...}. The client maps the code
# to Chinese and keeps the raw code in brackets so it can be quoted when
# reporting a problem.

ERR_ROOM_NOT_FOUND = "ROOM_NOT_FOUND"
ERR_NOT_HOST = "NOT_HOST"
ERR_ROOM_FULL = "ROOM_FULL"
ERR_ROOM_BUSY = "ROOM_BUSY"
ERR_BAD_ROOM = "BAD_ROOM"
ERR_ALREADY_IN_ROOM = "ALREADY_IN_ROOM"
ERR_NOT_IN_ROOM = "NOT_IN_ROOM"
ERR_DUPLICATE_DEVICE = "DUPLICATE_DEVICE"
ERR_RATE_LIMIT = "RATE_LIMIT"
ERR_BAD_PASSWORD = "BAD_PASSWORD"
ERR_BAD_REQUEST = "BAD_REQUEST"
ERR_UNKNOWN = "UNKNOWN"

ERROR_TEXT = {
    ERR_ROOM_NOT_FOUND: "房间不存在（可能已经关闭）",
    ERR_NOT_HOST: "你不是这个房间的房主",
    ERR_ROOM_FULL: "房间已满",
    ERR_ROOM_BUSY: "房间里还有玩家，不能删除",
    ERR_BAD_ROOM: "房间号不合法",
    ERR_ALREADY_IN_ROOM: "你已经在房间里了",
    ERR_NOT_IN_ROOM: "你不在任何房间里",
    ERR_DUPLICATE_DEVICE: "另一台设备用了相同的设备 ID，你被挤下线了",
    ERR_RATE_LIMIT: "操作过于频繁，请稍后再试",
    ERR_BAD_PASSWORD: "房间密码不正确",
    ERR_BAD_REQUEST: "请求格式不正确",
    ERR_UNKNOWN: "服务器返回未知错误",
}


def describe_error(code, fallback=""):
    """Turn a raw error code into a friendly Chinese message. Never raises."""
    if not code:
        return fallback or "未知错误"
    key = str(code).strip().upper()
    text = ERROR_TEXT.get(key)
    if text is None:
        return fallback or "服务器返回错误：%s" % code
    return "%s [%s]" % (text, key)
