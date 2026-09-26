# -*- coding: utf-8 -*-
"""NAT4 hole punching: subtyping, a socket array, and a policy matrix.

Why this file exists
--------------------
"My NAT is symmetric" used to be treated as a verdict: prediction off, punch
fails, everyone falls back to the relay. That is wrong, and it is wrong in a
way that costs the most common NAT4 users their direct connection.

Two ideas from EasyTier (and from the DCUtR measurements behind it):

1. Most NAT4s allocate ports SEQUENTIALLY. The next mapping is port+k for a
   small k -- it is not random, it is just different every time. Those NATs
   are predictable, and a small contiguous window of guesses covers them.
   Only a minority are genuinely random.

2. For the random ones, open MANY sockets locally. Each one is another
   mapping, i.e. another target the peer can hit by chance. Hit probability
   is 1-(1-K/65535)^N: with K=84 open ports, ~700 random guesses lands
   around 80%. That is a birthday attack, and it is why "open more sockets"
   is not a hack but the actual mechanism.

The spray is also a port scan of somebody's IP from the outside, so it is
capped, rate limited, shuffled, and switchable off. See SYM_PUNCH_ENABLED.
"""
import os
import random
import selectors
import socket
import struct
import threading
import time

from udptunnel import MAGIC, HDR, T_HELLO, T_HELLO_ACK

from protocol import (NAT_SUB_CONE, NAT_SUB_EASY_INC, NAT_SUB_EASY_DEC,
                      FILTER_EIF, FILTER_ADF, FILTER_APDF, FILTER_UNKNOWN,
                      NAT_SUB_HARD, NAT_SUB_UNKNOWN,
                      NAT_EASY_MAX_STEP, ANCHOR_STALE_S,
)

# --- filtering behaviour (RFC 5780) -------------------------------------
# See common.stun_filtering for how these are measured. Kept here as the
# canonical names because this is where the policy that uses them lives.
FILTER_RANK = {FILTER_EIF: 0, FILTER_ADF: 1, FILTER_APDF: 2,
               FILTER_UNKNOWN: 1}


def filter_rank(f):
    """How strict a filter is. Unknown sits in the middle.

    Unknown deliberately does NOT rank as strict. Treating it as strict made
    every undiagnosed network look like the worst case, and undiagnosed is
    the common case -- most servers silently ignore CHANGE-REQUEST. The
    failure mode of ranking it loosely is optimism; the failure mode of
    ranking it strictly is giving up on networks that would have worked.
    """
    return FILTER_RANK.get(f, 1)


def effective_filter(measured, inbound="unknown"):
    """The filtering verdict to act on, given BOTH measurements.

    Two independent measurements of the same property, and they can
    disagree -- in a real log they did, on both ends of one pair:

        [NAT] filtering: endpoint-independent (anything may come in)
        [NAT] inbound UDP is BLOCKED: ... it never arrived

    If anyone could reach us, the server's packet would have arrived. So a
    miss disproves eif and nothing else: a NAT that filters per address
    (adf) also drops a packet from a host we never wrote to, and it is the
    ordinary case -- the peer's packets are accepted from the moment we
    send to it, which is what punching is.

    Old behaviour: a miss was reported as "no amount of punching can help",
    which vetoed the punch for every adf host -- i.e. for most of the
    users this project exists for.

      measured   what the STUN tests concluded
      inbound    "open" | "punchable" | "blocked" | "unknown"
    """
    measured = measured or FILTER_UNKNOWN
    if inbound == "open":
        # An unrelated host got in: either genuinely open, or the server's
        # address was warmed first (adf). Trust the STUN verdict when it
        # has one; eif is the only thing a cold miss would have ruled out.
        return measured if measured != FILTER_UNKNOWN else FILTER_EIF
    if inbound == "blocked":
        # Nothing unsolicited arrives, so eif is impossible. adf would have
        # been classified as "punchable" by the probe path; here the filter
        # says apdf, or the measurement is missing entirely.
        if measured == FILTER_EIF:
            return FILTER_ADF
        return measured
    if inbound == "punchable":
        # A miss that adf explains: never claim eif, it was disproved.
        if measured == FILTER_EIF:
            return FILTER_ADF
        return measured
    return measured


def must_open_first(my_filter, peer_filter, my_id="", peer_id=""):
    """True if WE have to send before the peer's packets can get in.

    This is the question RFC 5780 exists to answer.

    A NAT that filters per destination drops the peer's packets until we
    have sent to that address ourselves. If BOTH ends are like that and
    both wait for the other, nothing ever arrives -- not because the hole
    cannot be punched but because neither side opened the door. The
    stricter end has to go first.

    Ties fall back to the id comparison so both sides still agree without a
    round trip.
    """
    a, b = filter_rank(my_filter), filter_rank(peer_filter)
    if a != b:
        return a > b
    return should_lead(my_id, peer_id)


# --- policy outcomes -----------------------------------------------------
# NONE means "do not even try": hard-symmetric on both ends has no mechanism
# left, and pretending otherwise just burns 25s before the relay anyway.
METHOD_NONE = "none"
METHOD_CONE = "cone_to_cone"
METHOD_SYM_TO_CONE = "sym_to_cone"      # I am NAT4, peer is cone: I open many
METHOD_BOTH_EASY = "both_easy_sym"      # both predictable: both open, both spray
METHOD_BIRTHDAY = "birthday"            # hard-sym vs cone: random collision

# --- parameters (EasyTier's constants, tuned down where a game lobby does
# --- not need the full barrage) ------------------------------------------
# Two knobs, and both were being throttled by something else entirely.
#
# They were sized against the old 800pps cap, which halved the round rate
# and so halved what these numbers actually bought. With the cap lifted the
# same window and socket count deliver twice the coverage, and raising them
# further is now affordable: 120 sockets x 2 packets = 240/round, which at
# 2000pps still fits ~8 rounds a second.
# 100 sockets x 64 ports. Both numbers were raised on a hunch and then
# measured -- see bench_punch.py, which replays this exact algorithm
# against a per-flow NAT. The result was not what "more is better" predicts:
#
#   sockets  window   clean   noisy allocator
#      84      50      70%         52%
#     100      50      70%         58%
#     100      64      72%         60%     <- chosen
#     100      80      60%         42%
#     120      64      70%         50%
#
# Widening the window PAST ~64 makes it worse, which is the opposite of
# intuition. The reason is that a hit needs both ends to line up at once:
# not only must we aim at a port the peer owns, the peer must have sent to
# the port we are sending from. A wider window spreads the same packets over
# more targets, so per round we cover a smaller share of it -- while our own
# source ports keep marching away from the range the peer is aiming at.
#
# Sockets are also the expensive dimension (an fd and an ephemeral port
# each, times every concurrent peer; 120 x 5 guests is most of the 1024 fd
# default on a Windows desktop), so they stay moderate and the window does
# the covering.
# Measured, and the answer was not "fewer":
#
#   drift (a,b)    n=25     n=50     n=100
#   0, 0           100%     100%     100%
#   30, 31           0%      95%     100%
#   60, 61           0%       0%      75%
#
# Fewer sockets means fewer mappings, i.e. a smaller TARGET -- and a
# smaller target hurts more than the extra rounds help, because the peer
# must hit one of our mappings while we must hit one of theirs. 25 is
# EasyTier's number for a different shape (it holds still rather than
# spraying from every socket), not a free win here.
# How far the outward walk may go before giving up. Bounded only so a
# peer that is not there at all does not walk into someone else's port
# range forever; a real punch is over long before this.
PORT_WALK_LIMIT = 20000
SOCKETS_FOR_SYM_TO_CONE = 100    # mappings I open for the peer to hit
SOCKETS_FOR_BOTH_EASY = 100      # ... when both ends are predictable
# A collision attack is a bet on OUR side having many targets, so 100
# mappings wastes most of the peer's guesses: with 100 targets a random
# port has a 100/65535 chance of landing on one of them.
#
# OpenP2P opens 800 (`SymmetricHandshakeNum = 800 // 0.992379`) and sprays
# 800, which is where that 0.99 comes from -- the product of the two, not
# either alone. Opening 800 UDP sockets from one process is fine on every
# platform we ship to, so a pure collision attack uses that.
SOCKETS_FOR_COLLISION = 800
# Guesses per round when they all go out from the ONE published source
# port. Capped on purpose: several thousand packets to consecutive ports
# of one host is the signature of a port scan, and getting an unrelated
# host flagged is not an acceptable side effect of playing Minecraft.
#
# 400 halved the coverage of an 800-port spray for no safety benefit --
# the ports are random, not consecutive, so the cap does nothing a
# reader would expect it to. Aligned to the spray size: the cap is about
# not hammering one host, and it is honoured by the round budget, not by
# silently dropping half the guesses.
HUB_SPRAY_PER_ROUND = 800
# sym_to_cone is a DIFFERENT shape from both_easy and must not share its
# number. Here only ONE end is spraying: the symmetric side opens 100
# mappings and then holds still, and the cone side walks them. Widening the
# window costs nothing -- the targets are already there, fixed, so more
# ports means strictly more of them get hit.
#
# both_easy is the opposite: BOTH ends move, so a wider window spreads the
# same packets thinner while our own source ports march out of the peer's
# range. That is why bench_punch.py finds 64 best there and worse above it.
#
# 160 here covers the 100 sockets plus room for drift: the peer's window is
# anchored on the mapping we published at connect time, and by the time the
# array is opened this machine has usually created other UDP flows (DNS,
# STUN retries, QUIC), each of which pushes the next allocation further
# along. At 64 the scan missed most of the array.
WINDOW_SYM_TO_CONE = 160         # contiguous ports the peer walks
# How far out the walk may reach if those all miss. Ports are tried
# nearest-first, so a peer whose allocator barely drifted is found in the
# first rounds and this costs nothing; it only matters when the peer's
# allocations have moved a long way between publishing its mapping and
# opening its array, which bench_punch.py shows is routine -- and which was
# previously simply unreachable, the scan rotating over the same 160 ports
# for the whole budget.
WINDOW_SYM_TO_CONE_MAX = 900
# The window has to be wide enough for TWO independent incrementing
# allocations to line up: at 25 sockets / +/-20 the two sequences rarely
# overlap (measured 1/4); 84 / +/-50 gave 3/4. EasyTier's 25/20 assumes a
# tighter allocator than real home routers actually have.
# Share of every window round spent on uniformly random ports instead.
#
# Not a fallback that kicks in after the window fails -- it runs from the
# first round, because on a per-destination NAT the window is wrong from
# the start and waiting to discover that just spends the budget confirming
# it. See the note at the scan site.
WINDOW_RANDOM_MIX = 0.0
# How far around a LEARNED address to spray.
#
# Learning beats predicting: a heard address is a real mapping in the
# region that applies to us, so its neighbours are worth more than any
# window built around the port we published to a stun server. This is what
# EasyTier does and it is why it succeeds where a predicted window does
# not -- see spray_learned_neighborhood.
LEARN_NEIGHBOR_WINDOW = 64
WINDOW_BOTH_EASY = 160           # contiguous ports the peer walks
# Where the walk may reach if those miss. See WINDOW_SYM_TO_CONE_MAX; the
# measured numbers for this plan are in _run_punch_inner.
WINDOW_BOTH_EASY_MAX = 900
# both_easy needs BOTH ends spraying simultaneously, so it must not be
# starved by a budget meant for one-sided punching. 8s rather than 5s: the
# two allocators take time to drift into each other, and cutting the window
# short is the difference between "almost aligned" and connected.
BOTH_EASY_MIN_S = 8.0
SPRAY_INTERVAL_S = 0.1           # one round per 100ms
BIRTHDAY_PROBES = 600            # random ports per round (EasyTier: 600-800)
# Floor for the per-round batch: late rounds get fewer fresh ports, because
# by then the marginal value of another guess is lower than the cost of
# another few thousand packets at somebody's IP.
BIRTHDAY_MIN_PROBES = 180
BIRTHDAY_DECAY = 0.75            # each round asks for this x the previous

# Compliance: an unbounded spray at somebody's IP is indistinguishable from
# a port scan, and some ISPs treat it as one. Everything below is a hard cap.
#
# 800 pps was too tight to be neutral: one round is 84 sockets x 2 = 168
# packets, and at 100ms/round that is 1680pps of natural demand -- so the
# cap halved the round rate and quietly halved the number of rounds that
# fit in a 5s both_easy window (23 instead of 50). Since the whole point of
# the window width and the socket count is coverage, losing half the rounds
# loses half the coverage.
#
# 2400 is sized against the natural rate of ONE punch: 100 sockets x 2
# packets = 200 per round, and a round is 100ms, so a single attempt wants
# 2000pps. The old 800 throttled it to 0.21s/round, halving the rounds that
# fit in a window -- and rounds are what the coverage is made of.
#
# It stays a PROCESS-wide ceiling (see RateGuard.shared), which is the
# number an ISP actually sees, and it is now divided among the punches
# running at once rather than being grabbed by whoever asks first.
MAX_PUNCH_PPS = 2400             # packets/second across the whole spray
# Floor for a single attempt when several share the ceiling. Without it,
# five concurrent punches would each be squeezed to 480pps -- enough to
# function, but not enough to keep a round at its 100ms design rate.
MIN_PUNCH_PPS_PER_ATTEMPT = 600
# How many punches may run at once.
#
# This is what makes the two numbers above compatible. A floor per attempt
# and a ceiling for the process pull in opposite directions: five attempts
# at a 900 floor is 4500pps, which quietly abolishes the ceiling the
# compliance argument depends on. Capping concurrency resolves it -- four
# attempts at the 600 floor is exactly 2400, the ceiling.
#
# A fifth guest waits for a slot instead of slowing the first four to a
# fifth of the rate each. Same total work, and the ones already running
# finish at a usable speed rather than all five crawling.
MAX_CONCURRENT_PUNCHES = 4
MAX_PUNCH_PACKETS = 40000        # ... and per punch attempt
PUNCH_TIMEOUT_CAP_S = 12.0


def sym_punch_enabled():
    """Master switch.

    EasyTier ships --disable-sym-hole-punching for exactly this reason: the
    spray can be identified and blocked by an ISP. Anyone who does not want
    it must be able to turn it off without patching code.
    """
    return os.environ.get("DISABLE_SYM_PUNCH", "").strip().lower() not in (
        "1", "true", "yes", "on")


def refine_nat_subtype(p1, p2, p3):
    """Split "symmetric" into predictable and hopeless.

    p1  mapping seen by server A from socket 1
    p2  mapping seen by server B from socket 1   (same socket, other server)
    p3  mapping(s) seen by server A from socket 2 (new socket, same server)

    p3 may be a single port or a LIST of samples. A single reading is not
    trustworthy: between two probes the machine can open any number of
    unrelated UDP flows, and each consumes an allocation slot, inflating the
    observed gap. Extra slots can only make the gap LARGER, never smaller,
    so with several samples the smallest one is the best estimate.

    The third probe is the one that matters and the one everybody omits.
    p1 vs p2 tells you the mapping depends on the destination; only p3 tells
    you WHERE THE NEXT ONE LANDS, and "next" is what the peer has to guess.

    Returns one of NAT_SUB_*.
    """
    if not p1 or not p2:
        return NAT_SUB_UNKNOWN
    if p1 == p2:
        # one mapping for every destination
        return NAT_SUB_CONE

    # p3 is the primary evidence and it is judged FIRST.
    #
    # |p2 - p1| used to be checked here and returned sym_hard outright.
    # That is wrong, and it is how a perfectly predictable NAT came to be
    # reported as random: p1 and p2 are mappings for two DIFFERENT
    # destinations, so their gap is not a step -- it is the sum of the
    # step and however many unrelated flows the machine opened in between.
    # Observed: p1=60225, p2=60392 (gap 167) while p3=60393, i.e. the real
    # step was +1. The NAT had not changed at all; the reading was busy.
    #
    # p3 answers the actual question -- "where does the NEXT mapping land"
    # -- by asking a server we already reached from a fresh socket, so the
    # two allocations are consecutive.
    samples = p3 if isinstance(p3, (list, tuple, set)) else ([p3] if p3 else [])
    samples = [x for x in samples if x]
    if samples:
        hi = max(p1, p2)
        lo = min(p1, p2)
        # Only POSITIVE gaps are evidence. Two samples landing on opposite
        # sides of [lo, hi] is a perfectly ordinary sequential allocator
        # (one slot before, one after) -- but taking a signed min over both
        # directions yields a negative "gap" in one and discards the other,
        # so the pair was read as unpredictable and the connection was
        # abandoned. Judge each direction on its own positive evidence.
        ups = [s - hi for s in samples if 0 < s - hi < NAT_EASY_MAX_STEP]
        downs = [lo - s for s in samples if 0 < lo - s < NAT_EASY_MAX_STEP]
        if ups:
            return NAT_SUB_EASY_INC
        if downs:
            return NAT_SUB_EASY_DEC
        # We DID get samples and every one of them landed far away. That
        # is real evidence of randomness -- not an absence of evidence --
        # so it must not fall through to the optimistic branch below,
        # which is only for when the probe never answered at all.
        return NAT_SUB_HARD

    # No p3 AT ALL (the probe failed or was never run), so fall back to
    # the gap between destinations.
    # Asymmetric costs decide this: calling a random NAT predictable costs
    # one failed punch and then relaying, while calling a predictable NAT
    # random gives up on the direct connection outright. So a small gap is
    # read optimistically; only a large one, with nothing better to go on,
    # is called random.
    if abs(p2 - p1) <= NAT_EASY_MAX_STEP:
        return NAT_SUB_EASY_INC if p2 > p1 else NAT_SUB_EASY_DEC
    return NAT_SUB_HARD


def nat_step(p1, p2, p3):
    """The port-allocation step we actually believe, signed.

    NOT `p2 - p1`. Same reason as in refine_nat_subtype: those are two
    different destinations, and their gap is mostly "how busy was the
    machine". Measured 167 where the true step was 1 -- and that number is
    published as natDelta, so the peer strides by it.

    p3 gives two consecutive allocations, which is what a step is.
    """
    samples = p3 if isinstance(p3, (list, tuple, set)) else ([p3] if p3 else [])
    samples = [x for x in samples if x]
    if p1 and p2 and samples:
        hi = max(p1, p2)
        lo = min(p1, p2)
        ups = [s - hi for s in samples if 0 < s - hi < NAT_EASY_MAX_STEP]
        downs = [lo - s for s in samples if 0 < lo - s < NAT_EASY_MAX_STEP]
        if ups:
            return min(ups)
        if downs:
            return -min(downs)
    return (p2 - p1) if (p1 and p2) else 0


def subtype_rank(sub):
    """How pessimistic a subtype is. Higher = worse.

    Ordering is by CONSEQUENCE, not by how "symmetric" the NAT is.
    hard is last because hard x hard is the one combination that gives up
    on punching entirely (see punch_plan); everything else still tries.
    """
    return {NAT_SUB_CONE: 0,
            NAT_SUB_EASY_INC: 1,
            NAT_SUB_EASY_DEC: 1,
            NAT_SUB_UNKNOWN: 2,
            NAT_SUB_HARD: 3}.get(sub, 2)


def subtype_regressed(new, old):
    """Is `new` a worse verdict than `old`?"""
    return subtype_rank(new) > subtype_rank(old)


def punch_plan(my_sub, peer_sub, my_id="", peer_id="",
               my_filter=FILTER_UNKNOWN, peer_filter=FILTER_UNKNOWN):
    """Which algorithm to use. Pure function, so it can be tested directly.

    Two rules are deliberate:

      * hard-sym against anything but a cone NAT is METHOD_NONE. There is no
        mechanism left -- spraying into a random allocation on both sides is
        not a strategy, and "NAT4 to NAT4 always works" is marketing, not
        engineering. Say so up front instead of failing 25 seconds later.

      * when both ends are predictable, BOTH sides still have to send --
        a hole needs traffic in both directions. What the id comparison
        decides is who leads, so the two do not open 25 sockets each in the
        same millisecond. See should_lead().

    `my_filter` / `peer_filter` come from RFC 5780 and refine the mapping
    behaviour above. Mapping and filtering are independent axes: a NAT can
    allocate a fresh port per destination (symmetric) and still accept
    inbound traffic from anywhere (endpoint-independent filtering). That
    combination is much easier than it sounds from "symmetric", because the
    only hard part is guessing the port -- the door is already open. So
    hard-sym + EIF is worth an attempt where hard-sym + APDF is not.
    """
    if not sym_punch_enabled():
        return METHOD_NONE

    # OPENP2P FIRST.
    #
    # Everything below is this program's own policy, and it is a voter,
    # not a gate: openp2p's three handshakes are selected on cone vs
    # symmetric alone, so whenever one of them applies it decides.
    #
    # The old code let this policy go first and the ported handshakes only
    # ran if it happened to allow them -- so a single "no mechanism" line
    # here (or a cone verdict, which skips the array entirely) meant the
    # handshakes were dead code on every real pair. They are now the
    # primary decision and this function only handles what openp2p does
    # not (symmetric x symmetric, and the mechanisms it deliberately has
    # no answer for).
    if openp2p_plan(my_sub, peer_sub) is not None:
        return METHOD_OPENP2P

    eif_pair = (my_filter == FILTER_EIF and peer_filter == FILTER_EIF)
    if not eif_pair:
        if my_sub == NAT_SUB_HARD and peer_sub == NAT_SUB_HARD:
            # Both cursors are unpredictable. Nothing to aim at on either
            # side, so this really is the one hopeless pair -- but even
            # here, only when filtering is strict. With EIF on both ends
            # the door is already open and the port is the only obstacle,
            # so it falls through to BIRTHDAY below.
            return METHOD_NONE
        # hard x easy (either way round) used to return METHOD_NONE too.
        # It is not hopeless: the easy side's ports are PREDICTABLE, so
        # there is a window worth scanning -- the hard side just cannot be
        # predicted at, which only removes half the mechanisms, not all of
        # them. And METHOD_NONE skips everything, including the
        # coordinated start, so the pair never even tried.

    both_easy = (my_sub in (NAT_SUB_EASY_INC, NAT_SUB_EASY_DEC)
                 and peer_sub in (NAT_SUB_EASY_INC, NAT_SUB_EASY_DEC))
    if both_easy:
        return METHOD_BOTH_EASY

    if my_sub in (NAT_SUB_EASY_INC, NAT_SUB_EASY_DEC):
        return METHOD_SYM_TO_CONE
    if peer_sub in (NAT_SUB_EASY_INC, NAT_SUB_EASY_DEC):
        return METHOD_SYM_TO_CONE
    if my_sub == NAT_SUB_HARD or peer_sub == NAT_SUB_HARD:
        return METHOD_BIRTHDAY
    return METHOD_CONE


def _anchor_age_text(seconds):
    """How stale the anchor this scan was built around is."""
    try:
        seconds = float(seconds)
    except (TypeError, ValueError):
        return "age unknown"
    if seconds < 0:
        return "age unknown"
    if seconds < ANCHOR_STALE_S:
        return "measured %.0fs ago" % seconds
    return "STALE: measured %.0fs ago" % seconds


def _unpredictable(sub):
    """A port allocation we cannot aim a window at.

    HARD (measured random) and UNKNOWN (never characterised) are the same
    problem for a scan: the published port tells us nothing about where the
    next mapping lands, so a contiguous window around it is a guess about
    a number that was never related to the answer.
    """
    return sub in (NAT_SUB_HARD, NAT_SUB_UNKNOWN)


def _should_scan_window(plan, my_sub, peer_sub):
    """Should we also walk a window of predicted ports?

    Only a CONE peer is exempt: its port never changes, so a window around
    it is 50 targets that cannot possibly answer -- that was the whole of
    sym_to_cone's wasted round.

    A random peer is the opposite case and used to fall into the same
    branch, which is the bug: with the peer's allocation unpredictable the
    scan was switched off entirely and every socket hammered the ONE port
    the peer published for its STUN server. Real log, 100 sockets and
    13 seconds:

        [punch] sent 8989 packets to 23653 (anchor measured 2s ago)

    One port, 8989 times. On a per-destination NAT the peer is not on
    23653 when talking to us, so those packets had nothing to hit -- while
    its own array sat somewhere in the 64k space, unguessed.
    """
    if plan == METHOD_BOTH_EASY:
        return True          # both allocations move
    if plan == METHOD_SYM_TO_CONE:
        if peer_sub == NAT_SUB_CONE:
            return False     # cannot move; a window buys nothing
        # predictable -> a contiguous window; unpredictable -> a wide
        # random spray, which is the only thing that can find it
        return True
    return False


def _mix_random(batch, tried, frac):
    """Replace `frac` of `batch` with uniformly random ports.

    See the note at the scan site: on a per-destination NAT the window can
    be aimed at a region the peer was never allocated in, and then only the
    random guesses can land. Ports are drawn from the whole range and
    de-duplicated against everything already tried.
    """
    if frac <= 0 or not batch:
        return batch
    n_rand = max(1, int(len(batch) * frac))
    out = list(batch[:len(batch) - n_rand])
    for _ in range(n_rand * 4):
        if len(out) >= len(batch):
            break
        p = random.randint(1024, 65535)
        if p not in tried and p not in out:
            out.append(p)
    random.shuffle(out)
    return out


def _wrap_port(p):
    """Fold a port into the usable range instead of dropping it.

    The walk used to discard anything outside 1024..65535, which meant "run
    out of ports" the moment it reached the top of the range. Real log, the
    anchor at 57492, walking upward:

        [punch] window exhausted at 19999 ports
        [punch] covered 8043 ports 57493..65535

    A 19999-port window covered 8043 ports -- and the 56,000 ports BELOW
    the anchor were never tried, because the code read 65535 as the end of
    the world. The port space is circular; there is plenty further to go.

    Wrapping is not a re-run of the same ports: it only happens after every
    port on the near side of the anchor has been tried, so nothing is
    repeated. And it is worth doing even for a peer judged "sequential",
    because the same peer measured 1 apart on one sample and 350 and 760
    apart on others -- its allocator is not a pure +1 walk, so the far side
    of the space is not the lost cause a strict reading would make it.
    """
    lo, hi = 1024, 65535
    span = hi - lo + 1
    return lo + ((int(p) - lo) % span)


def _next_ports(state, want):
    """The next `want` ports to try: near-first, outward, never repeated.

    An unbounded walk rather than a fixed list, because the target moves
    (see the note at the scan site). Banded like port_window -- shuffle
    within a band so it does not read as a sequential port scan, never
    shuffle across bands, so a peer that barely drifted is still found in
    the first rounds.

    Wraps around the port range instead of stopping at it -- see
    _wrap_port. Stopping at 65535 silently cost a real session 60% of the
    window it had asked for.
    """
    out = []
    while len(out) < want:
        if not state["pre"]:
            band = state["next"] // state["width"]
            if band * state["width"] >= PORT_WALK_LIMIT:
                break
            lo = band * state["width"] + 1
            hi = lo + state["width"]
            sub = state["sub"]
            if sub in (NAT_SUB_EASY_INC, NAT_SUB_EASY_DEC):
                signs = (-1,) if sub == NAT_SUB_EASY_DEC else (1,)
            else:
                # Unknown: walk BOTH ways.
                #
                # _peer_subtype defaults a peer that only reported the
                # coarse "symmetric" to EASY_INC, and an older build does
                # exactly that. If such a peer decrements, walking only
                # upward covers half the space and misses every time --
                # port_window used to cover both directions, so this was a
                # regression, not a new limitation.
                signs = (1, -1) if (band % 2 == 0) else (-1, 1)
            pre = []
            for sign in signs:
                for k in range(lo, hi):
                    pre.append(_wrap_port(state["base"] + sign * k))
            state["pre"] = pre
            random.shuffle(state["pre"])     # inside the band only
            state["next"] = hi - 1
        take = min(want - len(out), len(state["pre"]))
        out.extend(state["pre"][:take])
        state["pre"] = state["pre"][take:]
    return out


def _should_spray_random(my_sub, peer_sub):
    """In a birthday attack, should THIS end spray at random ports?

    One end has to spray and one end has to open mappings, and which is
    which depends on the pair:

      * cone x hard  -> the CONE side sprays (its own NAT accepts
        anything, so whichever mapping it hits answers). The hard side
        only opens mappings.
      * hard x hard  -> NEITHER side is a cone, so the old "only the non-
        hard side sprays" rule left nobody spraying at all. With EIF on
        both ends the door is already open and the port is the only
        obstacle, so both spray.
    """
    if my_sub != NAT_SUB_HARD:
        return True              # I am the cone side: I spray
    return peer_sub == NAT_SUB_HARD   # both hard -> both spray


def should_lead(my_id, peer_id):
    """True if this side starts first when both ends spray at once.

    Both sides compute the same answer without a round trip. The follower is
    only delayed, never silent: it still has to send, or no hole opens.
    """
    if not my_id or not peer_id:
        return True
    return str(my_id) <= str(peer_id)


def port_window(base_port, subtype, width, max_width=None):
    """The contiguous ports worth trying, in the order to try them.

    Contiguous, NOT "base + k*delta". That was the actual bug: with a
    measured step of 7 the old code tried +7 +14 +21 ... and missed a peer
    whose next allocation was +1. A sequential allocator's next port is one
    step along, whatever the step size we happened to measure, so the window
    has to be every port in the range.

    Shuffled WITHIN each distance band on purpose: walking 5000,5001,5002...
    is the signature of a port scan, and getting an unrelated host flagged
    is not an acceptable side effect of someone trying to play Minecraft.

    `max_width` extends the reach. The first `width` ports are tried first,
    and the caller only walks further out if those miss -- so a peer whose
    allocator has barely drifted is found immediately, while one that has
    drifted past the initial window is still reachable. The banding is what
    keeps that cheap: near-first ordering means a wide search costs nothing
    when a narrow one would have worked.

    Ordered by distance from `base_port`, NOT globally shuffled. A global
    shuffle would interleave port +3 with port +900, and a scan that has
    only budget for 200 packets would then spend it on 200 distant, mostly
    hopeless ports instead of the 200 nearest ones.
    """
    if not base_port:
        return []
    span = max(width, max_width or width)
    if subtype == NAT_SUB_EASY_DEC:
        signed = [-1]
    elif subtype == NAT_SUB_EASY_INC:
        signed = [1]
    else:
        signed = [-1, 1]
        # `width` is a budget for the TOTAL number of targets, not per
        # direction. Two directions at full span would double it -- which
        # is not just a cost, it breaks the "never look like a port scan"
        # cap the caller relies on.
        span = max(1, span // 2)
    out = []
    # Bands of `width`, walking outward. Shuffle inside a band so the scan
    # does not read as sequential; never shuffle across bands.
    start = 1
    while start <= span:
        stop = min(start + width, span + 1)
        band = []
        for k in range(start, stop):
            for sg in signed:
                p = base_port + sg * k
                if 1024 <= p <= 65535:
                    band.append(p)
        random.shuffle(band)
        out.extend(band)
        start = stop
    return out


def random_ports(count):
    """Random distinct ports for the birthday branch."""
    return _fresh_ports(count, set())


def _fresh_ports(count, tried):
    """`count` random ports we have not tried yet.

    Sampling against a shared `tried` set is what makes the birthday
    attack actually work: re-guessing a port we already missed adds
    nothing, and the whole point is to spread guesses as widely as
    possible across rounds.
    """
    out = []
    # bound the search: once we have tried most of the usable space there
    # is no point spinning
    space = 65535 - 1024
    if len(tried) >= space:
        return out
    attempts = 0
    while len(out) < count and attempts < count * 20:
        attempts += 1
        p = random.randint(1024, 65535)
        if p in tried:
            continue
        tried.add(p)
        out.append(p)
    return out


class PunchSocketArray:
    """Many UDP sockets, each one another mapping the peer can hit.

    One socket means one target. Against a NAT whose port allocation is
    random there is nothing to predict, so the only lever left is having
    more targets -- each socket we open is a fresh mapping, and the peer
    only has to collide with one of them.

    Every socket is read by ONE selector thread, so we can tell which
    socket the peer's packet arrived on; that socket is the punched one.
    """

    def __init__(self, count, log=print):
        self.count = max(1, int(count))
        self.log = log
        self.socks = []
        self._stop = threading.Event()
        self._hit = None          # (sock, addr)
        self._lock = threading.Lock()
        self._reader = None
        self.sent = 0
        # Source endpoints we have actually HEARD the peer from.
        #
        # This is the "learn" half of learn-then-reply, and it is the single
        # most valuable piece of information in the whole punch: a packet
        # that arrived proves the peer's NAT created THAT mapping, and that
        # the mapping is willing to talk to us. No amount of prediction is
        # as good as an address we have already been reached from.
        self.learned = set()
        # Which socket each learned address was HEARD on. Filtering on a
        # symmetric NAT is per-destination, so the only reply that can get
        # through is one sent from the same endpoint the peer spoke to.
        # Guessing an address right and answering from the wrong socket is
        # no better than not having guessed at all.
        self.learned_on = {}      # addr -> sock (None = the hub socket)
        self.hub_sock = None      # for addresses learned via the hub
        self.hello_ack = None     # bytes to answer a HELLO with
        self._peer_ip = None      # set by start_reader

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, *exc):
        self.close()

    def open(self):
        """Bind every socket. Fewer than asked is fine; zero is not."""
        for _ in range(self.count):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.bind(("", 0))
                s.setblocking(False)
                self.socks.append(s)
            except OSError as e:
                self.log("[punch] socket array stopped at %d: %s"
                         % (len(self.socks), e))
                break
        return len(self.socks)

    def local_ports(self):
        return [s.getsockname()[1] for s in self.socks]

    def send_all(self, data, addr):
        """One packet from every socket -- opens one mapping per socket.

        The HUB socket goes too, and it matters more than the rest.

        On a NAT that allocates per destination IP, the published port --
        the one the peer is told -- is the hub socket's mapping towards the
        stun server, and the array's mappings are in a different region
        entirely. A packet from an array socket therefore opens a mapping
        the peer has no way to guess, and its reply lands nowhere.

        A packet from the hub socket opens a mapping in the region the
        peer IS looking at (it is the same socket the published port came
        from), and the hub is also the socket with the catch-all, so the
        reply has somewhere to land. This is the first hop of the only
        chain that works without prediction:

            us -> peer's published port   (they hear us if filtering is EIF)
            peer -> our source port       (they learned it from that packet)
            us -> that port               (tunnel up)

        Skipping it when the peer's filtering is strict is still right --
        under APDF even a learned source address is refused.
        """
        socks = list(self.socks)
        if self.hub_sock is not None:
            socks.insert(0, self.hub_sock)
        for s in socks:
            try:
                s.sendto(data, addr)
                self.sent += 1
            except OSError:
                pass

    def send_round_robin(self, data, ip, ports, offset=0):
        """Spread one round across the port window.

        Socket i takes port (i + offset) % len(ports): with N sockets and a
        window of W, N rounds cover every (socket, port) pair instead of
        every socket hammering the same port.
        """
        if not ports:
            return
        for i, s in enumerate(self.socks):
            p = ports[(i + offset) % len(ports)]
            try:
                s.sendto(data, (ip, p))
                self.sent += 1
            except OSError:
                pass

    def send_from_hub(self, data, ip, ports, limit=0):
        """Guess the peer's port from ONE source port: the published one.

        This is the whole of OpenP2P's `handshakeC2S`, and it is the
        difference between the two sides of a cone x symmetric pair:

            conn, _ := net.ListenUDP("udp", t.localHoleAddr)   // ONE socket
            for i := 0; i < SymmetricHandshakeNum; i++         // 800 guesses
                UDPWrite(conn, peerIP:randPorts[i]+2, ...)

        Many destination ports, ONE source port. Our scan did the opposite
        -- `send_scatter` gives every guess a DIFFERENT source port, one per
        array socket -- and on a peer that filters per address AND port that
        is fatal in a way no window width can fix:

            the peer sent to (our IP, our published port), so per-port
            filtering admits packets from that one source endpoint and
            drops every other. 8100 guesses from 8100 different source
            ports, all discarded before they were ever routed.

        Real log, the cone side of exactly this pair:

            [NAT] cone (ports [30000, 30000])      <- published 30000
            [punch] covered 8043 ports 57493..65535; sent 8100 packets
            [punch] no packet from 220.178.180.180 reached any of our
                    mappings.

        The scan is only worth running from the socket whose mapping IS the
        published port -- the hub socket -- which is also the socket the
        reply can arrive on. So this is used when OUR mapping is stable
        (cone): then one source port is enough, and it is the only one the
        peer will accept.
        """
        if not ports or self.hub_sock is None:
            return 0
        if limit and len(ports) > limit:
            ports = ports[:limit]
        n = 0
        for p in ports:
            try:
                self.hub_sock.sendto(data, (ip, p))
                self.sent += 1
                n += 1
            except OSError:
                pass
        return n

    def send_scatter(self, data, ip, ports):
        """One round, socket index DECOUPLED from port index.

        send_round_robin ties socket i to port i (shifted by the round
        number). Under a per-flow NAT that coupling creates a congruence
        the scan then has to satisfy:

            hit requires  target == peer's mapping
                     AND  that mapping's recorded dest == my source port

        which, with both cursors drifting by d_a and d_b, reduces to

            2r == d_a + d_b  (mod N)

        Since 2r is always even, an ODD drift sum has NO solution at any
        window width -- about half of real sessions were unwinnable before
        they started, and widening the window did not help because r, not
        the span, is what the condition constrains.

        Assigning each socket a RANDOM port from the batch breaks the
        coupling: source port and target port become independent, so the
        congruence disappears.
        """
        if not ports:
            return
        socks = list(self.socks)
        random.shuffle(socks)
        for i, s in enumerate(socks):
            p = ports[i % len(ports)]
            try:
                s.sendto(data, (ip, p))
                self.sent += 1
            except OSError:
                pass

    def note_peer(self, data, addr, sock=None):
        """Record a source endpoint the peer actually reached us from.

        Returns True if this was a usable tunnel packet. Called for packets
        arriving on the array's sockets AND (via the hub catch-all) on the
        punch socket, because the peer may be answering either.
        """
        if not data or addr[0] != self._peer_ip:
            return False
        # only our own tunnel packets; a stray NAT reply to somebody else's
        # flow is not a punch
        if len(data) < HDR or struct.unpack(">H", data[:2])[0] != MAGIC:
            return False
        with self._lock:
            self.learned.add(tuple(addr))
            self.learned_on.setdefault(tuple(addr), sock)
            if self._hit is None:
                self._hit = (sock, tuple(addr))
        # Answer immediately. Knowing the peer's mapping is worthless unless
        # we send something back through it -- that reply is what opens the
        # hole from OUR side, and it tells the peer its guess landed.
        if self.hello_ack is not None and sock is not None:
            try:
                sock.sendto(self.hello_ack, addr)
            except OSError:
                pass
        return True

    def start_reader(self, peer_ip):
        """Listen on every socket, and keep listening.

        Two deliberate departures from the obvious implementation:

        * It does NOT stop at the first packet. A NAT can deliver one stray
          datagram from an unrelated flow, and a reader that returns on the
          first thing it sees has no second chance -- the punch then fails
          even though the real reply arrives a moment later.

        * Every packet is a LEARNING opportunity, not just a possible hit.
          The source port is the mapping the peer's NAT actually created --
          precisely the number we could not predict -- so we record it and
          answer it. That is what turns a blind spray into a conversation.
        """
        self._peer_ip = peer_ip
        if self._reader is not None:
            return

        def run():
            sel = selectors.DefaultSelector()
            for s in self.socks:
                try:
                    sel.register(s, selectors.EVENT_READ)
                except Exception:
                    return
            while not self._stop.is_set():
                try:
                    events = sel.select(timeout=0.1)
                except Exception:
                    return
                for key, _mask in events:
                    s = key.fileobj
                    try:
                        data, addr = s.recvfrom(2048)
                    except (BlockingIOError, InterruptedError):
                        continue
                    except OSError:
                        continue
                    self.note_peer(data, addr, s)

        self._reader = threading.Thread(target=run, daemon=True)
        self._reader.start()

    def reply_learned(self, data):
        """Answer every source endpoint we have heard the peer from.

        Cheap and high-value: these addresses are known-good. The peer's
        mapping already carried a packet to us, so a reply stands a real
        chance of getting back -- unlike the blind window spray.
        """
        with self._lock:
            pairs = [(a, self.learned_on.get(a)) for a in self.learned]
        if not pairs:
            return 0
        n = 0
        for addr, sock in pairs:
            s = sock if sock is not None else self.hub_sock
            if s is None:
                continue        # heard via the hub and we do not own it
            try:
                s.sendto(data, addr)
                n += 1
                self.sent += 1
            except OSError:
                pass
        return n

    def spray_learned_neighborhood(self, data, window=LEARN_NEIGHBOR_WINDOW):
        """Spray AROUND an address we actually heard the peer from.

        This is the mechanism EasyTier leans on, and it is the only one
        that survives a NAT which allocates per destination IP.

        Why a window around the PUBLISHED port is worthless there, and
        this is not:

            published (to the stun server)   44020
            allocated for us (a new host)     7647

        Two unrelated regions -- measured on one machine, three seconds
        apart. But once a packet FROM the peer actually arrives, we know
        a real mapping in the region that applies to us, and the peer's
        allocations there are as consecutive as anywhere else (they only
        restart when the destination changes, and the destination is now
        us). So the ports next to it are the ports its other sockets got.

        Crucially each socket sprays a DIFFERENT port from a different
        source port, because a hit needs both:

            target == a mapping the peer owns
            that mapping's recorded destination == my source port

        Having heard one mapping tells us the first half is soluble nearby;
        using every socket for the neighbourhood covers the second half.
        """
        with self._lock:
            heard = list(self.learned)
        if not heard or not self.socks:
            return 0
        n = 0
        for (ip, port) in heard:
            for s in self.socks:
                # one port per socket, spread over the neighbourhood
                off = (self._nbr_cursor % (2 * window + 1)) - window
                self._nbr_cursor += 1
                target = port + off
                if target == port or not (1024 <= target <= 65535):
                    continue
                try:
                    s.sendto(data, (ip, target))
                    n += 1
                    self.sent += 1
                except OSError:
                    pass
        return n

    def wait_hit(self, timeout):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            with self._lock:
                if self._hit is not None:
                    return self._hit
            if not (self._reader and self._reader.is_alive()):
                with self._lock:
                    if self._hit is not None:
                        return self._hit
                return None
            time.sleep(0.05)
        with self._lock:
            return self._hit

    def detach(self, sock):
        """Hand a punched socket over to the tunnel without closing it."""
        if sock in self.socks:
            self.socks.remove(sock)
        try:
            sock.setblocking(True)
        except OSError:
            pass
        return sock

    def close(self):
        self._stop.set()
        if self._reader is not None:
            self._reader.join(timeout=1.0)
            self._reader = None
        for s in self.socks:
            try:
                s.close()
            except OSError:
                pass
        self.socks = []


class AttemptBudget:
    """Per-attempt packet allowance, rate-limited by a shared RateGuard.

    Registers itself with the guard while it is live, which is how the
    guard knows how many punches it is dividing its ceiling between.
    """

    def __init__(self, guard, total, log=print):
        self.guard = guard
        self.total = total
        # Enter() logs when it cannot get a concurrency slot. Without this
        # the attribute did not exist and the log call raised
        # AttributeError -- inside run_punch, before the try block, so it
        # escaped as "multi-socket punch failed", and every NAT4 guest past
        # the fourth relayed forever.
        self.log = log or print
        self.used = 0
        # Each attempt keeps its OWN rate window.
        #
        # The window COUNTER used to be a single shared one compared against
        # THIS attempt's slice of the ceiling. That caps the AGGREGATE at one
        # slice, not at the sum of the slices: measured 2467pps with one
        # punch but only 733 with four, i.e. 183pps each against a design of
        # 600 -- a round of 200 packets took 1.1s, so the 8s window held 7
        # rounds instead of 24. That is worse than the single shared bucket
        # this replaced (about 2000pps), and four concurrent punches is the
        # normal case: it is the host side of a star.
        #
        # Sum of slices still cannot exceed the ceiling, because the number
        # of live attempts is capped and each slice is pps // n_live -- so
        # per-attempt windows plus the shared backstop bound both ends.
        self._in_window = 0
        self._window_start = time.monotonic()
        self._win_lock = threading.Lock()
        self.ok = True
        self._live = False
        self.enter()

    def enter(self):
        if self._live:
            return
        # Respect the slot result.
        #
        # Ignoring it meant an attempt that FAILED to get a slot still
        # registered itself as active -- inflating the divisor and so
        # shrinking the share of the attempts that were actually running,
        # while itself being unable to send anything at full rate. And it
        # released a slot it never held, letting total concurrency drift
        # above the intended maximum.
        if not self.guard._acquire_slot():
            # Do not run at all.
            #
            # Running anyway would consume bandwidth that is not accounted
            # for anywhere: this attempt is not in the divisor, so it gets
            # no slice, yet it still sends -- pushing the aggregate past the
            # ceiling the floor x concurrency arithmetic exists to keep.
            # And with every slot taken, the ceiling is already fully
            # divided; a fifth punch can only make the other four slower.
            self.log("[punch] all %d punch slots are busy; skipping this "
                     "attempt rather than exceeding the rate ceiling"
                     % MAX_CONCURRENT_PUNCHES)
            self.ok = False
            self._live = True
            return
        self.guard._add_attempt()
        self._live = True

    def close(self):
        if self._live:
            # Only undo what enter() actually did: an attempt that never got
            # a slot must not release one, or total concurrency drifts above
            # the cap and the ceiling arithmetic stops holding.
            if self.ok:
                self.guard._remove_attempt()
                self.guard._release_slot()
            self._live = False

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False

    def allow(self, n=1):
        if self.used + n > self.total:
            return False
        if not self.ok:
            return False
        # Own slice first, then the shared backstop.
        #
        # The shared one is asked LAST and with no sleeping: the two limits
        # normally add up to exactly the ceiling, so if the per-attempt
        # window already slept, the aggregate has by definition drained and
        # the backstop will not sleep again. Sleeping twice would mean up to
        # two seconds of dead time in one round.
        share = self.guard.share()
        with self._win_lock:
            now = time.monotonic()
            if now - self._window_start >= 1.0:
                self._window_start = now
                self._in_window = 0
            if self._in_window + n > share:
                gap = 1.0 - (now - self._window_start)
                if gap > 0:
                    time.sleep(gap)
                self._window_start = time.monotonic()
                self._in_window = 0
            self._in_window += n
        self.guard._take_nosleep(n)
        self.used += n
        return True


class RateGuard:
    """Hard ceiling on the spray: packets/second and packets/attempt.

    This is the compliance control, not an optimisation. A birthday attack
    is a port scan of the peer's public IP; without a ceiling a retry loop
    turns into thousands of packets aimed at a host that may not even be
    ours any more.

    The budget is PROCESS-WIDE, not per attempt. A host punching to five
    guests at once used to get five independent 800pps allowances -- the
    "global rate limit" was never global, and the one number that actually
    matters to an ISP is the aggregate leaving this machine.
    """

    _shared_lock = threading.Lock()
    _shared = None

    @classmethod
    def shared(cls):
        """The process-wide RATE ceiling.

        Shared so that a host punching to five guests at once still emits
        one allowance's worth of packets, not five. The number an ISP sees
        is the aggregate leaving this machine.
        """
        with cls._shared_lock:
            if cls._shared is None:
                cls._shared = RateGuard()
            return cls._shared

    def __init__(self, pps=MAX_PUNCH_PPS, min_pps=MIN_PUNCH_PPS_PER_ATTEMPT):
        # Only a RATE ceiling. The per-attempt packet cap lives in
        # AttemptBudget: it used to live here too, and every new attempt
        # reset a counter that all concurrent attempts shared.
        self.pps = pps
        self.min_pps = min_pps
        self._slots = threading.Semaphore(MAX_CONCURRENT_PUNCHES)
        self._window_start = time.monotonic()
        self._in_window = 0
        self._active = 0
        self._lock = threading.Lock()

    # -- active-attempt bookkeeping --------------------------------

    def _acquire_slot(self, timeout=5.0):
        """Wait for a concurrency slot. False if we gave up waiting.

        Giving up rather than queueing forever matters: a punch that waits
        two minutes for its turn is worse than one that runs immediately at
        a smaller share, because the peer's window has long closed.

        5s, not 30s. The punch budget itself is ~12s, so a slot that
        arrives after 30s is useless -- the attempt would start with the
        window already gone, having also spent those 30s counted as an
        active attempt (diluting everyone else's share). Waiting longer
        than the attempt can use is strictly worse than not starting.
        """
        return self._slots.acquire(timeout=timeout)

    def _release_slot(self):
        try:
            self._slots.release()
        except ValueError:
            pass

    def _add_attempt(self):
        with self._lock:
            self._active += 1

    def _remove_attempt(self):
        with self._lock:
            self._active = max(0, self._active - 1)

    def _share_locked(self):
        return max(self.min_pps, self.pps // max(1, self._active))

    def share(self):
        """This attempt's slice of the ceiling, in packets/second.

        One shared bucket is right in principle -- the number an ISP sees
        is the aggregate. But first-come-first-served inside a shared
        bucket means, in the star topology, the host's five concurrent
        punches fight over 2400pps and each gets whatever it can grab:
        measured ~400pps each, i.e. 0.6s per round instead of 0.1s, so the
        8s window held 13 rounds instead of 66. The host is exactly the
        side punching to several peers at once, so it is the side that
        degrades.

        Dividing the ceiling instead gives each attempt a predictable
        slice, with a floor so a single attempt is never squeezed below the
        point where a round fits -- and the number of slices is capped
        (MAX_CONCURRENT_PUNCHES) so "floor x slices" can never exceed the
        ceiling.
        """
        # NOTE: takes the lock itself. It MUST NOT be called while the lock
        # is already held -- allow() holds it and used to call this, which
        # deadlocked instantly (threading.Lock is not reentrant). Hence the
        # split between share() and _share_locked().
        with self._lock:
            return self._share_locked()

    def allow(self, n=1):
        """The AGGREGATE backstop: never more than `pps` per second.

        Per-attempt windows (AttemptBudget) are what normally limit each
        punch; this is the second line, and it is what makes "sum of shares
        <= ceiling" true even while attempts are starting and finishing.
        """
        with self._lock:
            return self._take(self.pps, n)

    def _take_nosleep(self, n):
        """The aggregate counter, WITHOUT sleeping.

        Used by AttemptBudget after it has already slept for its own
        slice; see AttemptBudget.allow for why sleeping twice is wrong.
        """
        with self._lock:
            now = time.monotonic()
            if now - self._window_start >= 1.0:
                self._window_start = now
                self._in_window = 0
            if self._in_window + n > self.pps:
                self._window_start = now
                self._in_window = 0
            self._in_window += n
            return True

    def _take(self, limit, n):
        """Caller holds the lock. Sleeps only the REMAINDER of a second."""
        now = time.monotonic()
        if now - self._window_start >= 1.0:
            self._window_start = now
            self._in_window = 0
        if self._in_window + n > limit:
            # Sleep only the REMAINDER of this second. Sleeping a whole
            # second on every overshoot halved throughput at the exact
            # moment the spray was finally working.
            gap = 1.0 - (now - self._window_start)
            if gap > 0:
                time.sleep(gap)
            # Re-read the clock AFTER sleeping: using the pre-sleep `now`
            # drifted the window start backwards by the sleep duration on
            # every overshoot.
            self._window_start = time.monotonic()
            self._in_window = 0
        self._in_window += n
        return True

    def budget(self, total, log=print):
        """A PER-ATTEMPT packet allowance drawn against the shared rate.

        Kept separate from the rate ceiling on purpose. They were the same
        counter, and resetting it for each new attempt meant five
        concurrent punches each reset a counter they all shared -- so the
        per-attempt cap never held for anyone, while the (intended to be
        persistent) rate window was also being cleared.
        """
        return AttemptBudget(self, total, log=log)


# ============================================================
# OpenP2P's three handshakes, ported from openp2p/core/holepunch.go
#
# The whole strategy is four lines of openp2p:
#
#   cone x cone          -> handshakeC2C
#   symmetric x sym      -> ErrorS2S  (no UDP punch; TCP or relay)
#   peer sym, me cone    -> handshakeC2S
#   peer cone, me sym    -> handshakeS2C
#
# and the two asymmetric ones are mirror images:
#
#   C2S (I am cone):      ONE socket, bound to the fixed punch port,
#                         sprays 800 RANDOM destination ports.
#   S2C (I am symmetric): 800 SOCKETS, each sending one packet to the
#                         peer's KNOWN port. No guessing at all.
#
# That last line is the one this program had backwards. The symmetric side
# used to run a window scan -- thousands of guesses aimed at the peer's
# port -- while the cone side's port does not move, so there was nothing
# to guess. The symmetric side's job is to OPEN TARGETS, not to aim at
# them: every socket it opens is another mapping the cone side might hit.
# Real log, 8100 guesses against a port that never moved, zero replies.
# ============================================================

# The plan value that means "an openp2p handshake applies". It is a real
# plan and not a sentinel: every call site that gates on METHOD_CONE or
# METHOD_NONE (the coordinated start, "should the array run first", the
# second-chance branch) must see it as a mechanism that exists, or the
# handshake never runs.
METHOD_OPENP2P = "openp2p"

METHOD_C2C = "c2c"
METHOD_C2S = "c2s"
METHOD_S2C = "s2c"

# SymmetricHandshakeNum in openp2p (protocol.go), with its own comment:
# `800 // 0.992379`.
#
# The two sides do NOT cost the same thing, so they do not both get 800:
#
#   SPRAY_PORTS (the cone side's guesses) -- 800 packets from ONE socket.
#       One mapping. Guessing more ports is free.
#   SOCKETS (the symmetric side's targets) -- 800 would be 800 mappings.
#
# openp2p runs on servers and soft routers; this runs on a Windows desktop
# behind a home router, whose UDP mapping table is often 512-1024 entries.
# 800 mappings in one punch, times MAX_CONCURRENT_PUNCHES, evicts the
# OLDEST entry -- which is the hub socket's published port, the one thing
# the whole handshake depends on. It then reads as "zero replies for no
# reason". 250 keeps a single punch well inside that table and is paid
# back by re-spraying (see OPENP2P_ROUNDS).
OPENP2P_SPRAY_PORTS = 800
OPENP2P_SOCKETS = 250
# HandshakeTimeout in openp2p: it fires everything at once and waits once.
#
# Not ported as one shot. The two sides' preparation differs by an order
# of magnitude -- the cone side is done in milliseconds, the symmetric
# side has to bind SOCKETS sockets -- and startIn only aligns the two to
# tens of milliseconds. One shot therefore means the 800 guesses can all
# land on mappings that do not exist yet, with no second chance.
#
# Several rounds inside the same window fix that for free, and they are
# what actually makes the pair work: the symmetric side's packets reach
# the cone side's published port, get recorded by note_peer, and are
# answered. The spray is the backup; the learning is the mechanism.
OPENP2P_TIMEOUT_S = 7.0
OPENP2P_ROUNDS = 5


def openp2p_plan(my_sub, peer_sub):
    """Which handshake applies, or None. Mirrors core/p2ptunnel.go.

    Only the coarse cone/symmetric distinction matters here -- openp2p
    does not subdivide symmetric into "sequential" and "random", and does
    not predict anything. An unknown subtype is treated as symmetric
    (NATSymmetric is openp2p's default too), which still leaves the pair
    punchable whenever the other end is a cone.
    """
    if not my_sub or not peer_sub:
        return None
    me_cone = (my_sub == NAT_SUB_CONE)
    peer_cone = (peer_sub == NAT_SUB_CONE)
    if me_cone and peer_cone:
        return METHOD_C2C
    if not me_cone and not peer_cone:
        # ErrorS2S: openp2p does not even try UDP for this pair.
        return None
    return METHOD_C2S if me_cone else METHOD_S2C


def openp2p_punch(peer_ip, peer_port, plan, log=print, hub=None,
                  timeout=OPENP2P_TIMEOUT_S):
    """Run one of the three handshakes. Returns (sock, addr) or None."""
    hello = struct.pack(">HBBII", MAGIC, T_HELLO, 0, 0, 0)
    hello_ack = struct.pack(">HBBII", MAGIC, T_HELLO_ACK, 0, 0, 0)

    if plan == METHOD_S2C:
        # One packet per mapping, all aimed at the port we were TOLD.
        n = OPENP2P_SOCKETS
    else:
        # C2C and C2S both run on the fixed punch port: it is the port we
        # published, so it is the one a peer that filters per address+port
        # will accept, and the one its replies can land on.
        n = 1

    array = PunchSocketArray(n, log=log)
    array.hello_ack = hello_ack
    array.hub_sock = getattr(hub, "sock", None) if hub is not None else None
    opened = array.open()
    if not opened and array.hub_sock is None:
        log("[punch] no socket to punch with")
        array.close()
        return None
    array.start_reader(peer_ip)

    # Take over the published port for the duration.
    #
    # C2C and C2S both leave from the fixed punch port, so that is where
    # the peer answers -- and a hub with no tunnel registered on that port
    # drops the reply as unroutable. Without this the cone side of a pair
    # sprays 800 ports and is structurally deaf to every answer: the
    # packets arrive at the hub, match nothing, and are discarded.
    if hub is not None:
        def _on_hub_packet(data, addr):
            if array.note_peer(data, addr, None):
                # Answer from THIS socket: on a NAT that filters per
                # destination, only a reply sent from the endpoint the
                # peer spoke to is accepted. Replying from an array socket
                # is the right message delivered by the wrong messenger.
                try:
                    array.hub_sock.sendto(hello_ack, addr)
                except OSError:
                    pass

        hub.set_catch_all(_on_hub_packet, key=peer_ip)

    try:
        if plan == METHOD_C2C:
            array.send_all(hello, (peer_ip, peer_port))
        elif plan == METHOD_C2S:
            # ONE source port, 800 destination ports. rand.Perm(65532)+2
            # in openp2p; random_ports() is the same idea (distinct,
            # uniformly spread over the usable range).
            ports = random_ports(OPENP2P_SPRAY_PORTS)
            if peer_port and peer_port not in ports:
                # openp2p starts at randPorts[i]+2, i.e. it never tries 0/1
                # but does cover the rest. The published port is the one
                # address we know for certain, so try it first.
                ports.insert(0, peer_port)
            sent = array.send_from_hub(hello, peer_ip, ports)
            if not sent:
                # Never fall back silently.
                #
                # send_scatter sends from a freshly bound socket, whose
                # source port is NOT the published one -- and a peer that
                # filters per address AND port drops every packet from an
                # endpoint it has not spoken to. So the fallback is not a
                # weaker version of the same attempt, it is 800 packets
                # that cannot arrive, and the log still reads as if the
                # handshake ran. Say so instead.
                log("[punch] c2s cannot run: there is no hub socket bound "
                    "to the published port, so the spray would leave from "
                    "an address the peer will refuse. Skipping c2s -- a "
                    "silent fallback would send 800 packets that cannot "
                    "arrive.")
                return None
            log("[punch] c2s: spraying %d ports from the published port "
                "(the peer is symmetric: it opens %d mappings and we have "
                "to hit one)" % (len(ports), OPENP2P_SPRAY_PORTS))
        else:                                            # METHOD_S2C
            array.send_all(hello, (peer_ip, peer_port))
            log("[punch] s2c: opened %d mappings, one packet each to the "
                "peer's fixed port %d (the peer sprays our ports)"
                % (opened, peer_port))

        # Re-spray inside the window instead of firing once and sleeping.
        #
        # openp2p does send once, but it also does not have to: it starts
        # both ends from the same server signal and its two sides' setup
        # costs are symmetric. Here the cone side finishes in milliseconds
        # while the symmetric side binds hundreds of sockets, so a single
        # volley can be entirely wasted on targets that do not exist yet.
        # Rounds also give the learn-then-reply path repeated chances,
        # which is the part that actually closes these pairs.
        rounds = max(1, int(OPENP2P_ROUNDS))
        per = max(0.3, timeout / rounds)
        for r in range(1, rounds):
            hit = array.wait_hit(per)
            if hit:
                sock, addr = hit
                if sock is not None:
                    array.detach(sock)
                log("[punch] %s ok: punched via port %d" % (plan, addr[1]))
                return sock, addr
            if plan == METHOD_C2C:
                array.send_all(hello, (peer_ip, peer_port))
            elif plan == METHOD_C2S:
                # Continue the permutation: fresh ports, not the same 800
                # again, so a round is new information.
                more = random_ports(OPENP2P_SPRAY_PORTS)
                if array.hub_sock is not None:
                    array.send_from_hub(hello, peer_ip, more)
                else:
                    array.send_scatter(hello, peer_ip, more)
            else:
                array.send_all(hello, (peer_ip, peer_port))

        hit = array.wait_hit(max(0.5, timeout / rounds))
        if hit:
            sock, addr = hit
            if sock is not None:
                array.detach(sock)
            log("[punch] %s ok: punched via port %d" % (plan, addr[1]))
            return sock, addr
        return None
    finally:
        if hub is not None:
            try:
                hub.clear_catch_all(key=peer_ip)
            except Exception:
                pass
        array.close()


def run_punch(peer_ip, peer_port, peer_sub, my_sub, plan,
              log=print, timeout=PUNCH_TIMEOUT_CAP_S, lead=True, hub=None,
              my_filter=FILTER_UNKNOWN, peer_filter=FILTER_UNKNOWN,
              anchor_age_s=None, per_ip_pool=False):
    """Execute one multi-socket punch. Returns (sock, addr) or None.

    The socket handed back is the one the peer's packet arrived on, already
    detached from the array; the caller owns it from here.

    `hub` is the UdpHub owning the punch socket (30000). Pass it in and the
    punch also LISTENS there: during a multi-socket attempt no tunnel is
    registered on 30000 (the plain attempt just failed and unregistered),
    so packets the peer sends to our published endpoint would otherwise be
    dropped -- while the peer is spraying exactly that port for its whole
    budget. A hit on that socket comes back as (None, addr), meaning "use
    the hub's socket"; the caller must not take ownership of it.
    """
    hello = struct.pack(">HBBII", MAGIC, T_HELLO, 0, 0, 0)
    hello_ack = struct.pack(">HBBII", MAGIC, T_HELLO_ACK, 0, 0, 0)
    guard = RateGuard.shared()
    budget = guard.budget(MAX_PUNCH_PACKETS, log=log)
    if not budget.ok:
        # No free slot: see AttemptBudget.enter(). Returning None means
        # "this attempt did not happen", which the caller treats exactly
        # like any other failed round -- it will back off and retry, by
        # which time a slot is likely free. Silently spraying without a
        # slice would have been the only worse option.
        budget.close()
        return None
    if not lead:
        # Tiny stagger, never a skip: both directions need traffic.
        #
        # This used to be 400ms, which made sense when it was the ONLY
        # coordination we had -- but the server now sends a shared start
        # (startIn), so the job of separating the two ends is already done
        # there. What is left is only "do not emit into the same millisecond",
        # and 400ms of a 5s both_easy window is an 8% loss of the very
        # overlap we just synchronised.
        time.sleep(0.05)

    # Everything below runs inside a try/finally that releases the budget.
    #
    # The budget registers itself for a share of the rate ceiling and takes
    # one of a small number of concurrency slots. Releasing it used to be
    # done by hand at each `return`, and one missed path was enough to leak
    # a slot permanently: after four such leaks every later punch waited
    # the full 30s acquire timeout and then ran out of its own budget
    # without sending a single packet. try/finally, not discipline.
    try:
        return _run_punch_inner(peer_ip, peer_port, peer_sub, my_sub, plan,
                                log, timeout, lead, hub, budget,
                                my_filter, peer_filter, anchor_age_s,
                                per_ip_pool=per_ip_pool)
    finally:
        budget.close()


def _run_punch_inner(peer_ip, peer_port, peer_sub, my_sub, plan, log,
                     timeout, lead, hub, budget,
                     my_filter=FILTER_UNKNOWN, peer_filter=FILTER_UNKNOWN,
                     anchor_age_s=None, per_ip_pool=False):
    # Is the port we PUBLISH also the port we will send from?
    #
    # On a cone NAT it is: one mapping, every destination sees the same
    # endpoint, so the hub socket's source port is exactly the port the
    # peer was told -- and, crucially, exactly the port a peer that filters
    # per address AND port will accept a packet from. Every other socket we
    # open is a source port the peer has never heard of and will drop.
    #
    # On a symmetric NAT it is not, so there is no single "right" source
    # port and the array's many mappings are the only lever.
    stable_source = (my_sub == NAT_SUB_CONE)
    hello = struct.pack(">HBBII", MAGIC, T_HELLO, 0, 0, 0)
    hello_ack = struct.pack(">HBBII", MAGIC, T_HELLO_ACK, 0, 0, 0)

    # OpenP2P's handshakes run first, whenever they apply.
    #
    # Everything below this -- the window walk, the delta prediction, the
    # birthday collision -- is this program's own invention, and it is
    # aimed the wrong way round for the one pair that keeps failing: the
    # symmetric end scans thousands of ports, while the cone end's port
    # never moves. openp2p inverts it (the symmetric end opens targets,
    # the cone end sprays) and does it in one 7s shot, so try that first
    # and fall through only if it does not close.
    op = openp2p_plan(my_sub, peer_sub)
    if op is not None:
        shot = min(float(timeout), OPENP2P_TIMEOUT_S)
        got = openp2p_punch(peer_ip, peer_port, op, log=log, hub=hub,
                            timeout=shot)
        if got:
            return got
        log("[punch] %s did not close in %.0fs; falling back to the "
            "window scan" % (op, shot))

    if plan == METHOD_BOTH_EASY:
        n, window = SOCKETS_FOR_BOTH_EASY, WINDOW_BOTH_EASY
        # Same reach-out as sym_to_cone, for the same reason -- and
        # measured, not assumed:
        #
        #   window/max   drift 0   drift 60   drift 300
        #   64 / 64        70%         0%          0%
        #   64 / 900      100%         5%          0%
        #   160 / 900     100%        85%          0%
        #
        # The first band has to cover drift + n_sockets: the peer's array
        # occupies `n` consecutive allocations starting wherever its cursor
        # has drifted to, so a band narrower than that only clips the near
        # edge of the array no matter how far out the scan eventually goes.
        #
        # Above drift ~300 no window helps, because both cursors are
        # moving while we scan -- which is why the anchor is refreshed
        # before punching instead (see _refresh_punch_anchor).
        if per_ip_pool:
            # A contiguous window is provably wrong here, so do not use
            # one at all -- and open far more mappings, because with no
            # window the only thing working for us is the collision.
            n = SOCKETS_FOR_COLLISION
            #
            # Real log, one peer: two different STUN IPs gave 47524 and
            # 41105 -- 6419 apart -- while the port it published for the
            # punch was 56719. Three different regions for three
            # destinations. A window around the anchor covers 5400 ports
            # and cannot contain the port the peer actually has.
            #
            # This is what OpenP2P does for a symmetric peer: forget the
            # window and send to `rand.Perm(65532)` -- a random
            # permutation of the whole space, no repeats. 800 of those
            # against 800 peer mappings is the 0.99 hit rate in its
            # comment (SymmetricHandshakeNum = 800 // 0.992379).
            window = 0
            ports = random_ports(WINDOW_BOTH_EASY_MAX)
        else:
            ports = port_window(peer_port, peer_sub, window,
                                max_width=WINDOW_BOTH_EASY_MAX)
    elif plan == METHOD_SYM_TO_CONE:
        n, window = SOCKETS_FOR_SYM_TO_CONE, WINDOW_SYM_TO_CONE
        # Reach further than `window` if the near ports all miss. The peer
        # publishes a mapping at connect time and opens its array some
        # seconds later; every unrelated UDP flow its machine creates in
        # between pushes the next allocation further along, and that drift
        # has no upper bound we can rely on. Ordered near-first, so a peer
        # that barely drifted is still found in the first rounds.
        if per_ip_pool:
            n = SOCKETS_FOR_COLLISION
            window = 0
            ports = random_ports(WINDOW_SYM_TO_CONE_MAX)
        else:
            ports = port_window(peer_port, peer_sub, window,
                                max_width=WINDOW_SYM_TO_CONE_MAX)
    elif plan == METHOD_BIRTHDAY:
        n = SOCKETS_FOR_SYM_TO_CONE
        window = WINDOW_SYM_TO_CONE
        ports = random_ports(BIRTHDAY_PROBES)
    else:
        return None

    if not ports:
        return None

    # The published port goes FIRST, and stays in the list.
    #
    # A window of [base+1 .. base+50] does not contain base, so if the peer
    # really is on the port we were told -- no NAT at all, loopback, or a
    # cone NAT we mistyped -- we would spray 50 wrong ports and burn the
    # whole budget before ever trying the right one. Trying the known-good
    # answer first costs one round and fails fast when it does not work.
    if peer_port:
        if peer_port in ports:
            ports.remove(peer_port)
        ports.insert(0, peer_port)

    # both_easy only works if BOTH ends are spraying at the same time, so
    # it needs a floor: a 2s budget (what auto mode hands the fallback)
    # would see one side stop before the other had started.
    if plan == METHOD_BOTH_EASY:
        timeout = max(timeout, BOTH_EASY_MIN_S)

    log("[punch] %s: %d sockets, %d ports, %.0fs budget"
        % (plan, n, len(ports), timeout))

    array = PunchSocketArray(n, log=log)
    array.tried_ports = set()
    array._nbr_cursor = 0
    array.hello_ack = hello_ack
    array.hub_sock = getattr(hub, "sock", None) if hub is not None else None
    opened = array.open()
    if not opened:
        array.close()
        return None
    array.start_reader(peer_ip)

    # Listen on the punch socket too -- see run_punch's docstring. Without
    # this the 30000 port is deaf for the entire multi-socket attempt while
    # the peer spends its whole budget talking to it.
    if hub is not None:
        def _on_hub_packet(data, addr):
            # Same learning path as the array's own sockets -- a packet
            # arriving here proves the peer's mapping just as well, and it
            # is typically the FIRST one we ever see, because the published
            # port is the only address the peer knows about.
            if array.note_peer(data, addr, None):
                # Answer from THIS socket, not from one of the array's.
                #
                # The peer reached us at our published endpoint, so on any
                # NAT that filters per-destination only a reply FROM that
                # endpoint is accepted. Replying from a random array socket
                # would be the right message delivered by the wrong
                # messenger: known-good address, packet dropped anyway.
                try:
                    array.hub_sock.sendto(hello_ack, addr)
                except OSError:
                    pass
        hub.set_catch_all(_on_hub_packet, key=peer_ip)

    # A generator, not a list: see the note at the scan site. `ports` is
    # still built up front (its length is logged and it seeds the walk),
    # but the walk continues past it instead of wrapping.
    # Bands are generated on demand, so do NOT pre-seed with the whole
    # window: that would hand out the near band repeatedly. `ports` stays
    # for the log line and as the documented first band.
    ports_state = {"base": peer_port, "next": 0,
                   "sub": peer_sub, "width": window, "pre": []}
    # How stale is the port we are scanning around? Passed in by the
    # caller; if it never was, say so rather than printing a fake 0.
    anchor_age = anchor_age_s
    tried = set()          # birthday keeps its own exhausted-pool set
    try:
        end = time.monotonic() + timeout
        rnd = 0
        while time.monotonic() < end:
            if not budget.allow(opened * 2):
                # Out of allowance for THIS SECOND -- wait it out rather
                # than giving up on the whole punch.
                #
                # This was a `break`. Hitting the per-second rate ceiling is
                # normal and transient (it is the point of the ceiling), but
                # one overshoot ended the attempt outright, so a punch could
                # die in the first few rounds having sprayed almost nothing
                # -- and on a loaded machine, where the whole round lands in
                # one rate window, that is exactly what happened.
                time.sleep(SPRAY_INTERVAL_S)
                continue

            # LEARNED ADDRESSES FIRST.
            #
            # If the peer has already reached us from somewhere, that
            # address is worth more than any guess: the mapping exists and
            # it is willing to talk to us. Replying is also what actually
            # opens the hole from our side.
            if array.reply_learned(hello):
                # Heard something: answer it AND spray around it.
                #
                # Answering alone is not enough. One heard address means
                # one of our sockets is reachable from the peer; the other
                # 99 still are not, and the tunnel needs the handshake on
                # a socket that can carry it both ways. Spraying the
                # neighbourhood of a REAL mapping is the highest-value
                # packets this loop will ever send -- see
                # spray_learned_neighborhood.
                array.spray_learned_neighborhood(hello)
            elif my_sub == NAT_SUB_CONE and plan == METHOD_SYM_TO_CONE:
                # I am the CONE side, so my mapping is the same for every
                # destination and every socket: opening "more mappings" is
                # not something I can do, and send_all to the peer's
                # published port is a packet we already know is wrong (it
                # is the port they had at connect time, not the one their
                # array is on now).
                #
                # Spending half of every round on it halved the scan. Skip
                # it and put the whole allowance into the window.
                pass
            elif peer_filter == FILTER_APDF:
                # Opening mappings the peer can never answer.
                #
                # send_all writes to (peer_ip, peer_port). A mapping opened
                # that way only accepts a packet back from exactly that
                # address -- but the peer answers from one of its own array
                # ports, which is a different port. Under APDF every reply
                # is dropped on arrival, so this is half of every round
                # spent on mappings that cannot ever be reached.
                #
                # It is also why "learn then reply" has never fired in a
                # real log: our published mapping was opened towards the
                # STUN server, so only EIF ever lets the peer's first
                # packet through at all.
                pass
            else:
                # Nothing heard yet, so fall back to sending out.
                #
                # On a port-symmetric NAT filtering is per-destination:
                # having sent to X, only a packet FROM X is accepted back.
                # So every socket must send to the peer's real address --
                # that is what opens a mapping we can be reached on.
                # Guessing at random ports does nothing but burn budget:
                # even a perfect guess is dropped, because we never sent
                # there.
                if peer_port:
                    array.send_all(hello, (peer_ip, peer_port))

            if plan == METHOD_BIRTHDAY and _should_spray_random(
                    my_sub, peer_sub) or (
                    plan == METHOD_SYM_TO_CONE
                    and _unpredictable(peer_sub)):
                # Guess the peer's port.
                #
                # The old condition was `my_sub != NAT_SUB_HARD`, which
                # meant the cone side of a hard peer sprayed and the hard
                # side only opened mappings -- right for cone x hard.
                #
                # But BIRTHDAY is also produced by hard x hard (with EIF on
                # both ends), and there BOTH sides fail that test, so
                # neither ever sprayed and the attack never happened: the
                # branch was dead in the only case v14 had just opened it
                # for. With both ends hard, both must spray.
                #
                # RESAMPLE every round. Walking one fixed pool by an offset
                # covers only (n_sockets + R) distinct ports -- 17% hit
                # rate. Fresh ports each round cover thousands.
                want = max(BIRTHDAY_MIN_PROBES,
                           int(BIRTHDAY_PROBES * (BIRTHDAY_DECAY ** rnd)))
                # Never draw more than we can actually send.
                #
                # Each socket sends one packet per pass, so a round covers
                # `opened` ports per pass -- and the round's allowance is
                # opened*2. Drawing 600 and sending 100 did not just waste
                # the other 500, it poisoned the pool: _fresh_ports marks
                # everything it draws as tried, so five sixths of the port
                # space was written off without a single packet ever being
                # aimed at it. After ~110 rounds the pool read as
                # "exhausted" having covered about a sixth of it.
                want = min(want, max(BIRTHDAY_MIN_PROBES, opened * 2))
                batch = _fresh_ports(want, tried)
                if not batch:
                    log("[punch] birthday: port pool exhausted")
                    break
                try:
                    array.tried_ports.update(batch)
                except Exception:
                    pass
                array.send_scatter(hello, peer_ip, batch)
                if len(batch) > opened:
                    # The allowance is opened*2 packets, so spend it: a
                    # second pass doubles the ground covered per round,
                    # which is the only thing a collision attack has going
                    # for it when the peer's allocation is random.
                    array.send_scatter(hello, peer_ip, batch[opened:])
            elif _should_scan_window(plan, my_sub, peer_sub):
                # The PEER's port moves and is predictable, so its mappings
                # lie in a contiguous window around the one it published.
                #
                # Take a FRESH slice each round rather than rotating over
                # one fixed list. Rotating meant every round covered the
                # same `n` ports shifted by one, so after R rounds only
                # n+R distinct ports had been tried -- the far end of a
                # wide window was never reached inside the budget, no
                # matter how long the punch ran.
                # Walk OUTWARD and never repeat a port.
                #
                # Both ends consume `n` new mappings per round, so once the
                # peer's cursor has moved past the ports we already tried,
                # re-trying them cannot hit: the mapping is gone from under
                # that port. Wrapping around after span/n rounds therefore
                # spent the rest of the budget on packets that were
                # mathematically unable to succeed -- measured, with the
                # model below, identical hit rate at 9 rounds and at 120.
                #
                #   rounds     1     3     5     9    15    40   120
                #   hit rate  70%   95%  100%  100%  100%  100%  100%
                #
                # So the window is generated on demand instead: near-first
                # (a peer that barely drifted is found immediately) and
                # unbounded outward, which also means a stale anchor is
                # recoverable rather than fatal.
                batch = _next_ports(ports_state, opened)
                # Mix in random ports from the very first round.
                #
                # A window only helps if the peer's mapping for US lies
                # near the port it published for its STUN server. On a NAT
                # that allocates per destination that is simply false:
                # measured on one machine, two ports of one IP came back
                # as 44019/44020 while a second IP came back as 7647 --
                # a different region entirely. The array's mappings open
                # in whichever region a brand-new destination gets, so a
                # window around the STUN port can be aimed thousands of
                # ports away no matter how wide it is.
                #
                # So every round spends part of its allowance on uniformly
                # random ports. If the peer really is sequential the window
                # still finds it in the first rounds; if it is not, the
                # random half is the only thing that can.
                # A window is only right if the peer's mapping for US lies
                # near the port it published. When it allocates a separate
                # region per destination IP (measured: two STUN IPs 6419
                # apart) the window is aimed at the wrong region from the
                # first round, so part of every round goes to uniformly
                # random ports -- the only guesses that can land. The
                # window still runs: if the peer does turn out to be
                # sequential it is found in the first rounds and the
                # random share costs nothing but budget.
                mix = (WINDOW_RANDOM_MIX_PER_IP if per_ip_pool
                       else WINDOW_RANDOM_MIX)
                batch = _mix_random(batch, array.tried_ports, mix)
                array.tried_ports.update(batch)
                if not batch:
                    log("[punch] window exhausted at %d ports"
                        % (ports_state["next"] - 1))
                    break
                # Decoupled, not (i+r) % N -- see send_scatter.
                if stable_source:
                    # ONE source port: the published one. See
                    # send_from_hub -- every other source port is dropped
                    # by a peer that filters per address AND port, which is
                    # what made 8100 guesses arrive at nothing.
                    array.send_from_hub(hello, peer_ip, batch,
                                        HUB_SPRAY_PER_ROUND)
                else:
                    array.send_scatter(hello, peer_ip, batch)
            # else: the peer's port does not move (cone), so a window scan
            # would be 84 packets at 83 addresses that cannot answer.

            rnd += 1
            hit = array.wait_hit(SPRAY_INTERVAL_S)
            if hit:
                sock, addr = hit
                if sock is not None:
                    array.detach(sock)
                else:
                    log("[punch] punched on the punch socket itself")
                log("[punch] punched via port %d" % addr[1])
                return sock, addr
        hit = array.wait_hit(0.5)
        if hit:
            sock, addr = hit
            if sock is not None:
                array.detach(sock)
            return sock, addr

        # Say WHY nothing happened, because "punch failed" is not
        # actionable and the two causes need opposite responses.
        #
        # If we never saw a single packet from the peer, no amount of
        # spraying here can help: a hole needs traffic from both ends. The
        # peer may be in relay mode, running an older build, or simply not
        # have received start_punch -- all of which are fixed on the OTHER
        # machine. If we did hear from them, the problem is ours (window
        # drift, filtering) and belongs in this log.
        # WHAT we actually did, in numbers.
        #
        # "no packet from the peer" is two very different failures and the
        # old wording pointed at the peer for both:
        #
        #   * we sent thousands of packets and nothing came back -> the
        #     inbound direction is filtered or blocked (our NAT, their NAT,
        #     or an ISP in between)
        #   * we sent (almost) nothing -> the punch never ran, and it is
        #     our own budget/rate limiter to blame
        #
        # So report the sent count, the span actually covered and the age
        # of the anchor the span was built around. A 50-second-old anchor
        # on a NAT that moves tens of ports a second puts the whole window
        # thousands of ports away from where the peer's array opened, and
        # no window width covers that.
        try:
            span = (min(array.tried_ports), max(array.tried_ports)) \
                if getattr(array, "tried_ports", None) else None
        except Exception:
            span = None
        if span:
            if per_ip_pool:
                # "a..b" would be meaningless: uniformly random ports span
                # nearly the whole space, and printing that invites reading
                # it as "we covered everything", which we did not.
                log("[punch] tried %d ports spread uniformly at random "
                    "(no window: this peer allocates a separate port "
                    "region per destination IP, so a window around %s "
                    "cannot contain it); sent %d packets"
                    % (len(array.tried_ports), peer_port, array.sent))
            else:
                log("[punch] covered %d ports %d..%d around anchor %s "
                    "(%s); sent %d packets"
                    % (len(array.tried_ports), span[0], span[1], peer_port,
                       _anchor_age_text(anchor_age), array.sent))
        else:
            log("[punch] sent %d packets to %s (anchor %s)"
                % (array.sent, peer_port, _anchor_age_text(anchor_age)))

        if not getattr(array, "learned_on", None):
            log("[punch] no packet from %s reached any of our mappings. "
                "A hole needs traffic from BOTH ends -- check that the "
                "peer is punching too (not relaying, same version)."
                % peer_ip)
            # If we really did send, and really did cover ground, then
            # nothing about the scan can explain a total absence of
            # replies: something INBOUND is dropping them.
            #
            # What it does NOT mean is "a firewall is blocking us". A host
            # firewall that allows the program to SEND also allows replies
            # to what it sent, so it is not what a punching peer looks
            # like -- blaming it sent users to a setting that was already
            # off. A desktop firewall that allows the program
            # to SEND (so STUN works, so the NAT type looks fine, so
            # filtering reports eif) can still refuse unsolicited inbound
            # UDP, and then every packet the peer sends is discarded
            # before the program ever sees it.
            if array.sent > 500:
                            log("[punch] we sent %d packets and heard nothing back: the "
                "guesses did not land on a mapping the peer could answer, "
                "or the peer is not punching. Note that a NAT type measured "
                "from outbound STUN says nothing about which source port a "
                "peer that filters per address+port will accept."
                % array.sent)
        else:
            log("[punch] heard %d endpoint(s) from %s but never completed "
                "the handshake" % (len(array.learned_on), peer_ip))
    finally:
        if hub is not None:
            hub.clear_catch_all(key=peer_ip)
        array.close()
    return None
