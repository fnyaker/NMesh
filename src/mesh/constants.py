"""
Every bound the core holds itself to.

Queue depths, rate-limit windows, timeouts, retry ceilings, keepalive
cadences, the direct/routable split of the type table. ``CLAUDE.md``
is blunt that "every queue, cache, buffer and counter has a hard
limit" — this is where each one is written down, beside what it
protects.
"""

import re
import socket
import struct

from ..core_release import PUBLISHER_ID_LEN as _RELEASE_ID_LEN
from .messages import *  # noqa: F401,F403


_HEADER_BYTES = 79  # fixed packet header size, for byte accounting


def _is_ip_address(s: str) -> bool:
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            socket.inet_pton(family, s)
            return True
        except OSError:
            continue
    return False


_ACK_ACCEPTED = 0x00
_ACK_REJECTED = 0x01

# HANDSHAKE: kem_len(H) | dsa_len(H) | chain_bytes_len(H)
_HS_HEADER   = struct.Struct('!HHH')
# HANDSHAKE_ACK: ct_len(H) | dsa_len(H) | chain_bytes_len(H) | issued_cert_len(H)
_ACK_HEADER  = struct.Struct('!HHHH')
# FOUND_NODE entry: node_id(20) | addr_count(B) | chain_len in pool indices(B)
_ENTRY_HEADER = struct.Struct('!20sBB')
# FOUND_NODE cert pool: pool_count(H) then per-cert length prefixes; entries
# reference certs by index (H) instead of repeating them.
_POOL_COUNT   = struct.Struct('!H')
_POOL_INDEX   = struct.Struct('!H')
_ENTRY_POOL_MAX  = 32   # distinct certs one FOUND_NODE may carry (bounds verify work)
# A pooled certificate may travel as a fingerprint instead of as ~7 kB, when the
# querier said it already holds it. `cert_len == 0` is free as the marker: a
# certificate shorter than its own header cannot be parsed, so no real one is
# ever zero-length.
_CERT_REF        = 0
_CERT_HINT_MAX   = 32   # fingerprints a FIND_NODE may carry
# One byte on the end of a FOUND_NODE saying "you may send me fingerprints".
# Trailing bytes are what a build without this reads it as, and `_decode_entries`
# has always stopped at the last entry — so this is how the two ends find out
# about each other without a link-level negotiation they cannot have: a lookup
# is routed, and the node that answers it may be several hops away.
_HINTS_OK        = b"\x01"
_HINT_PEERS_MAX  = 256  # nodes we remember as understanding fingerprints
_ENTRY_CHAIN_MAX = 6    # certs in one entry's chain — longer is nonsense
_ENTRY_COUNT_MAX = 20   # Kademlia k; the receiver would drop a longer answer
# Certificate renewal. A membership certificate lasts a year
# (`CryptoIdentity.issue_cert`) and nothing renewed it: at T+365 days a node went
# on presenting a chain every peer refuses, dropped out of the mesh with no
# diagnostic anywhere, and only a fresh invitation could bring it back.
# The two windows differ on purpose. A node starts asking a month out; the
# issuer will act on anything within three, so clock skew, a slow relayed path
# and a few missed sweeps can never turn a request made in time into a refusal.
_CERT_RENEW_WINDOW  = 30 * 86400    # we start asking this long before expiry
_CERT_RENEW_ACCEPT  = 90 * 86400    # we serve a request this close to expiry
_CERT_RENEW_TICK    = 6 * 3600.0    # seconds between renewal sweeps
_CERT_RENEW_FIRST   = 30.0          # first sweep, shortly after start
_CERT_RENEW_MIN_GAP = 3600.0        # one renewal served per subject per hour
_CERT_RENEW_TRACKED = 512           # subjects whose last renewal we remember
_CERT_RENEW_MAX     = 16 * 1024     # bytes of a renewal payload, before any parse
# Per-cert length prefix inside a chain blob
_CERT_LEN    = struct.Struct('!H')
# Address length prefix inside address lists
_ADDR_LEN    = struct.Struct('!H')
# E2E handshake: nonce(32) || var1_len(H) || var2_len(H) || chain_bytes_len(H)
_E2E_HEADER  = struct.Struct('!32sHHH')

# PUNCH_REQUEST payload: target_id(20) | my_udp_port(H)
_PUNCH_REQ = struct.Struct('!20sH')
# PUNCH_RELAY payload: peer_id(20) | peer_addr_len(H) | peer_addr | my_observed_addr_len(H) | my_observed_addr
# PUNCH_PROBE (raw UDP datagram, not a mesh Packet): magic(4) | node_id(20) | nonce(16) | signature(64)
_PUNCH_PROBE_MAGIC = b"NPPB"
_PUNCH_PROBE = struct.Struct('!4s20s16s')
# ML-DSA-65 signatures are 3309 bytes; keep a generous upper bound so a
# malformed/oversized datagram is rejected before we hand it to verify().
_PUNCH_SIG_MAX = 5000
# PUNCH_ACK (raw UDP datagram): magic(4) | node_id(20) | nonce(16) | signature(64)
_PUNCH_ACK_MAGIC = b"NPAK"

# Direct types travel one authenticated hop (src must be the immediate peer):
# per-link liveness, NAT punch signalling, and the catalog gossip (re-stamped
# each hop). Everything else that addresses a *node id* is routable — forwarded
# multi-hop across any transport toward its dst — so the DHT, the pseudo
# directory and Kademlia discovery all work when the target is only reachable
# through relays (A→…→X), not just a direct peer.
_DIRECT_TYPES    = {PING, PONG, OBSERVED_ADDR, PUNCH_REQUEST, PUNCH_RELAY,
                    REACH_PROBE, REACH_PROBE_ACK, CATALOG_ANNOUNCE,
                    RELEASE_ANNOUNCE, PSEUDO_ANNOUNCE, PKG_ANNOUNCE,
                    CERT_REVOKE, ABUSE_REPORT,
                    # The keepalive accord is about *this link* and nothing
                    # else: a cadence is a property of the pair, so it can only
                    # ever be stated by the peer at the other end of it.
                    KA_PROPOSE, KA_REQUEST}
_CATALOG_RATE_WINDOW = 10.0     # seconds
_CATALOG_RATE_MAX    = 128      # announces one link may push at us per window
_RELEASE_RATE_WINDOW = 10.0     # seconds
_RELEASE_RATE_MAX    = 32       # release announces one link may push per window
# "Never go looking" (`update_check_minutes = 0`). Not an infinite wait: the
# loop must still come round to notice the setting changed, and a day is far
# enough away to be "never" while staying a number the loop can survive.
_RELEASE_NEVER_TICK  = 86400.0
# A release that arrives wakes the pass instead of waiting out a whole sweep,
# and the first pass runs shortly after start rather than five minutes in — a
# node that reboots into an update it was told to take should not spend the
# next tick running the version it was meant to leave behind. The settle is
# what keeps a burst of announces (a peer catching us up) to one pass.
_RELEASE_FIRST_TICK  = 20.0     # seconds before the first pass after start
_RELEASE_SETTLE      = 3.0      # seconds an announce waits for its neighbours
_AUTO_PUBLISH_RETRY  = 3600.0   # before re-attempting a version that failed
_RELEASE_TRIED_MAX   = 32       # release ids we remember failing to install
_RELEASE_SLICE       = 48 * 1024   # bytes of package per RELEASE_DATA packet
_RELEASE_SLICE_TIMEOUT = 20.0   # waiting for one slice before trying elsewhere
_RELEASE_SERVE_WINDOW  = 10.0   # seconds
_RELEASE_SERVE_MAX     = 64     # slices one link may pull from us per window
_RELEASE_SOURCES_MAX   = 8      # nodes remembered as holding a given release
_RELEASE_SOURCES_TRACKED = 64   # releases we remember any sources for at all
_RELEASE_ASK_MAX       = 12     # nodes one fetch may ask before giving up
_PUBLISH_CONCURRENCY   = 8      # DHT stores in flight while publishing an app
_HEX_RELEASE = re.compile(r"[0-9a-f]{%d}" % (_RELEASE_ID_LEN * 2))
_HEX_PKG = re.compile(r"[0-9a-f]{40}")     # a package-directory entry id
_DIR_RATE_WINDOW     = 10.0     # seconds
_DIR_RATE_MAX        = 128      # DIR_STORE claims one link may push per window
_DIR_K               = 6        # replicate/query the pseudo directory across K
_DIR_PUBLISH_MAX     = 24       # nodes one directory publish may reach in total
# How often a node re-files what it publishes into the directory. Not "once, at
# startup": the K nodes closest to a key change as the mesh does, a directory
# holder may restart, and a node that published before it had any peer published
# to nobody. Cheap — a claim is one packet to a bounded set of nodes.
_DIR_REPUBLISH       = 900.0    # seconds between directory publishes
_DIR_FIRST_PUBLISH   = 20.0     # …and how long after start the first one waits
# The whole "ask the network" round: a Kademlia lookup plus one query to every
# target. Bounded, and it returns what it has: a caller behind a 10-second
# bridge must get a partial answer rather than a timeout, which is what turned
# a slow directory lookup into "the search does not work".
_DIR_LOOKUP_BUDGET   = 6.0      # seconds one directory lookup may take
_DIR_LOOKUP_ROUNDS   = 3        # Kademlia rounds a directory lookup may spend
_PSEUDO_RATE_WINDOW  = 10.0     # seconds
_PSEUDO_RATE_MAX     = 64       # pseudo claims one link may gossip at us per window
_PSEUDO_SEARCH_MAX   = 50       # results one search may return
_PKG_RATE_WINDOW     = 10.0     # seconds
_PKG_RATE_MAX        = 64       # package records one link may push at us per window
_PKG_SEARCH_MAX      = 50       # results one package search may return
_PKG_SYNC_MAX        = 64       # records pushed at a peer when it authenticates
_PKG_OWN_MAX         = 32       # records this node signs and keeps re-filing
_KEY_SHARE_WINDOW    = 60.0     # seconds
_KEY_SHARE_MAX       = 8        # key-share messages one link may push per window
# Offers held at once, in each direction. Small: each is a decision waiting for
# a human, and an outgoing one holds an unlocked secret until it is answered.
_MAX_KEY_OFFERS      = 8
_PSEUDO_SYNC_MAX     = 128      # claims pushed at a peer when it authenticates
_REVOKE_RATE_WINDOW  = 10.0     # seconds
_REVOKE_RATE_MAX     = 64       # revocations one link may gossip at us per window
_REVOKE_SYNC_MAX     = 256      # revocations pushed at a peer when it authenticates
_ABUSE_RATE_WINDOW   = 10.0     # seconds
_ABUSE_RATE_MAX      = 32       # accusations one link may gossip at us per window
# How long traffic from a peer we hold as suspect is dropped before the link is
# quietly let go. Randomised per link so the delay itself is not a signal an
# attacker can time — a fixed one is a message, just a slower one.
_TARPIT_MIN          = 45.0
_TARPIT_MAX          = 180.0
# We say something about a node at most this often, however much it does. An
# accusation is a broadcast: a node under attack must not answer by becoming the
# flood itself.
_ACCUSE_MIN_GAP      = 300.0
_ACCUSE_TRACKED      = 256
_ACCUSE_SEEN_MAX     = 4096     # accusation digests remembered (epidemic dedup)
# How much of a quorum may descend from one issuer before it stops being a
# quorum. Above half is the honest line: at half, two families disagree and a
# human decides; above it, one family decides alone while looking like several.
_FAMILY_SHARE        = 0.5
_BEHAVIOUR_NOTICES   = 64       # findings held for the operator, never scored
# Subjects whose arrival under an issuer we remember between two sweeps (rule
# A1). A bound and not a target: a real window holds a handful, and a peer
# pushing certificates at us must not be able to grow this one.
_CERT_ARRIVALS_MAX   = 4096
_MAX_DETACHED        = 64       # fire-and-forget tasks alive at once
_MAX_EXTRA_ADDRS = 8
_ROUTABLE_TYPES  = {DATA, E2E_HANDSHAKE, E2E_HANDSHAKE_ACK, ECHO_REQUEST, ECHO_REPLY,
                    FIND_NODE, FOUND_NODE, FIND_VALUE, FOUND_VALUE, STORE,
                    DIR_STORE, DIR_FIND, DIR_FOUND,
                    PKG_STORE, PKG_FIND, PKG_FOUND,
                    # Handing a publisher key to somebody is a conversation
                    # between two operators who may be several hops apart.
                    KEY_OFFER, KEY_ACCEPT, KEY_GRANT,
                    # A package comes from whoever has it, which may be several
                    # hops away — the publisher, or any node that kept a copy.
                    RELEASE_FETCH, RELEASE_DATA,
                    # The issuer of a membership is rarely still a neighbour by
                    # the time it needs renewing.
                    CERT_RENEW, CERT_RENEWED}
_DHT_K              = 6      # replication: store/fetch across this many closest nodes
_DHT_QUERY_TIMEOUT  = 5.0
_POST_AUTH_TYPES = _DIRECT_TYPES | _ROUTABLE_TYPES
_BROADCAST_ID    = b"\xff" * 20
_MSG_DEDUP_MAX         = 10_000
_MAX_PEERS             = 128    # open links, not distinct nodes: a node may hold several
# Of those, how many may be links that have not authenticated yet. They must
# never be able to crowd out the ones that have: a full `_peers` also stops
# `_dial_uri` dialling, so the node cannot re-join the mesh it was pushed out of.
_MAX_UNAUTH_PEERS      = 32
# How long a link has to finish its handshake before the sweep above cuts it.
# Generous: a relayed join crosses the mesh, and a slow medium is the normal
# case here, not the exception.
_HANDSHAKE_DEADLINE    = 60.0
_MAX_MALFORMED         = 32     # bad frames from one peer before we cut it (node rejection)
_MAX_HANDSHAKE_ATTEMPTS = 8     # handshakes one link may make us verify
_MAX_PENDING_PER_TARGET = 128   # buffered payloads awaiting an E2E session, per target
_MAX_PENDING_TARGETS    = 256   # distinct half-open destinations kept in RAM
# Decrypted application payloads waiting for whoever calls receive_data(). A
# node relaying with no app attached has no consumer at all, so without a
# ceiling any peer holding an E2E session grows this until the node dies. The
# E2E plane offers no delivery guarantee, so overflow drops rather than blocks —
# awaiting a full queue inside _handle_data would freeze the ingress link.
_MAX_DATA_QUEUE         = 512
# Live E2E sessions. `src_id` is checked against the key inside the payload, not
# against the link, so an adversary mints a fresh identity per handshake and
# each one used to add a permanent entry — and re-wrote the whole session store
# on the way (see _persist_state). Bounded and LRU, with anything that still has
# data queued for it held back from eviction.
_MAX_E2E_SESSIONS       = 512
_ON_DEMAND_TIMEOUT     = 5.0    # transport open + handshake
_KAD_LOOKUP_TIMEOUT    = 3.0    # per FIND_NODE round
_KAD_LOOKUP_MAX_ROUNDS = 4
_AUTH_POLL_INTERVAL    = 0.05
_QID_LEN               = 8     # query_id bytes appended to FIND_NODE / prefix of FOUND_NODE
_PUBLIC_IP_TIMEOUT     = 8.0   # hard cap on the (threaded) public-IP HTTP probe
_DIRECT_PING_TIMEOUT   = 3.0   # console PING→PONG wait before the ECHO fallback
# Measuring a link by loading it. Every figure here is a *refusal* first and a
# measurement second, because this is the one plane whose purpose is to spend
# somebody else's bandwidth.
#
#   * one chunk is well under what a packet carries (`packet.py`, 60 000), so a
#     probe is a probe and never a way to find the framing's edge;
#   * an echo is the same size as its probe — **one for one**. A reflector that
#     answered more than it was sent is an amplifier, which is the single worst
#     thing this pair could be, so the handler copies the payload rather than
#     generating one;
#   * a test is bounded by bytes *and* by seconds, whichever ends first, so a
#     fast link cannot be asked for an unbounded amount and a dead one cannot
#     hold the caller;
#   * and the answering side rate-limits per identity, so a peer cannot make us
#     echo without end however politely it asks.
_SPEED_CHUNK           = 16 * 1024
_SPEED_MAX_BYTES       = 8 * 1024 * 1024   # one test, in one direction
_SPEED_MAX_SECONDS     = 10.0
_SPEED_WINDOW          = 60.0              # what the *answering* side allows…
_SPEED_MAX_PER_WINDOW  = 1200              # …in echoes, per identity, per window
_SPEED_INFLIGHT        = 8                 # probes outstanding at once
# A transport reaps an idle link once no data arrives for its read timeout
# (TCP: 60s). A healthy but quiet link would die on its own, so ping every
# established peer well inside that window — both sides do it, so each link
# carries a packet each way and a few misses still leave margin.
_LINK_KEEPALIVE_INTERVAL = 20.0
# When probes stop coming back, the link is gone whatever the socket believes.
# A half-open TCP connection and a UDP mapping a NAT has forgotten both look
# alive from here — nothing errors, nothing closes — so the only evidence is
# silence, and the only honest reading of it is to cut the link and dial again.
# Counted as a run rather than a share: a link that carried traffic for an hour
# and then died never shows a high lifetime loss, because a thousand good
# probes outvote the dead ones. Four in a row is over a minute of one-way
# silence on a link whose own transport reaps at sixty seconds.
_DEAD_LINK_PROBES = 4
# …and the time that run always stood for. A probe count answers "is this link
# still a link" only while every link is probed on one interval; once a link can
# negotiate its own cadence (below), four probes is four hundred milliseconds on
# a bundle member and a minute and a half on a sleeping one. A link has to fail
# both tests, so the verdict means the same thing at any cadence.
_DEAD_LINK_SILENCE = _DEAD_LINK_PROBES * _LINK_KEEPALIVE_INTERVAL
# -- multi-link operation and the keepalive accord (see mlo.py) -------------
# The sweep the keepalive loop has always done — reap the silent, expire the
# tarpits, judge behaviour — still runs on `_LINK_KEEPALIVE_INTERVAL`. What
# changed is that each *link* now has its own due time, because a bundle
# member needs a probe ten times a second and everything else must go on
# costing exactly one wake-up every twenty seconds.
#
# A due-time loop with no floor is a busy loop (gotchas): a pass that finds
# nothing due still waits this long, so nothing here can spin however the
# arithmetic comes out.
_KA_TICK_FLOOR = 0.02
# The floor under "a probe with no answer is lost". The deadline itself is
# three times *that link's* cadence (see `_link_keepalive_loop`) — a constant
# would call every probe on a slow medium lost while the link works — and this
# is what keeps a fast-probed link from giving up in three hundred
# milliseconds. `LinkQuality.answered` keeps the late ones honest either way;
# this only decides when to stop waiting.
_KA_PROBE_DEADLINE = 3.0
# How long after an accord changes nothing is held against a peer for speaking
# under the old one. A proposal crosses the link at the speed of the link, and
# both ends re-propose *before* their first probe at a new cadence — so this is
# the width of the crossing, not a tolerance for being wrong.
_KA_GRACE = 10.0
# Cadence requests one link may make of us per window. A request costs us a
# change of behaviour, which makes it the cheapest thing on this plane to send
# and one of the more annoying to receive.
_KA_REQUEST_WINDOW = 60.0
_KA_REQUEST_MAX = 8
# How long a cadence request holds before it lapses. A request is a "go quiet
# for now", not a setting: the durable way for a node not to be probed hard is
# the fast range it *declares*, which no request can override. Long enough that
# repeating it costs nothing against the meter above, short enough that a peer
# that went away does not leave a link sleeping for ever.
_KA_TOLD_TTL = 300.0
# How often a probe re-carries this node's advertised addresses to one peer,
# whether or not they changed. The address gossip rides the probe; it is not
# what a probe is *for*, and at ten probes a second re-sending an unchanged
# list is 71% of the packet and half of what answering it costs.
#
# A duration and not a probe count, for the reason `_DEAD_LINK_SILENCE` exists:
# "every Nth probe" means one cadence at rest and another while striping. At
# the classic interval this is every probe, which is exactly what the node did
# before — so nothing changes for a link nobody is bundling. It is also the net
# under a lost PING: a peer that missed the update is told again within it,
# rather than never.
_ADDR_GOSSIP_INTERVAL = _LINK_KEEPALIVE_INTERVAL
# How long a sign of somebody actually using this node keeps it awake for MLO.
# Long enough that a console left open on a dashboard does not flap, short
# enough that a laptop shut at six is back to one probe per link per twenty
# seconds by ten past.
_MLO_AWAKE_TTL = 120.0
_MLO_SOURCES_MAX = 16       # distinct things that can say "somebody is here"
# Asking for the second link a bundle is made of. Nothing else in this node
# ever opens it: `_ensure_route_to` stops at the first address that answers and
# the retry loop skips a node it is already linked to — neither is wrong, one
# link is all routing needs. So a bundle only ever formed when the pair
# happened to dial each other over two media, or when an operator pressed
# "retry every address" by hand.
_MLO_DIAL_MIN = 60.0        # backoff after an address that did not answer…
_MLO_DIAL_MAX = 900.0       # …doubling to here, so a dead address costs little
_MLO_DIAL_TRACKED = 64      # identities remembered, in either book
_MLO_DIAL_PER_PASS = 1      # dials one pass may make…
_MLO_DIAL_FLOOR = 5.0       # …and the shortest gap between two passes
_MLO_DIAL_IDLE_MAX = 300.0  # ceiling on a wait nothing is expected to end
# Re-drive a stalled E2E handshake: if data is queued for a peer we still have no
# session with, re-initiate on this cadence. Without it, a single lost handshake
# (peer offline at send time, an ACK dropped in transit) stranded the queued data
# until a reboot or until the peer happened to initiate to us (CLAUDE.md: retry /
# self-repair / delay tolerance).
_E2E_RETRY_INTERVAL = 5.0
# How often the persisted snapshot is written at most. A handshake marks the
# state dirty; one task writes. Anything shorter and a burst of handshakes is
# back to one full serialise-and-fsync each.
_STATE_WRITE_INTERVAL = 2.0
# Responder-side E2E re-key candidates (see _handle_e2e_handshake): when a valid
# handshake arrives for a peer we ALREADY have a session with, answering naively
# would overwrite the live session while the initiator (which keeps no matching
# pending state for a stale/duplicate handshake) ignores our ACK — both ends
# then hold different keys and every DATA packet is dropped on GCM failure,
# silently and permanently. So a re-key is derived as a *candidate* only: it is
# promoted to the live session exclusively by a DATA packet that successfully
# decrypts under it (proof the peer actually completed that handshake). Bounded
# and short-lived so a flood of valid-but-useless handshakes can't grow it.
_E2E_REKEY_TTL = 30.0        # seconds a candidate session awaits proof
_E2E_REKEY_MAX = 64          # distinct peers with a pending re-key candidate
# Initiator side of the same problem. A retry generates a fresh nonce and ML-KEM
# keypair — it has to, an identical packet would be dropped by the receiver's
# msg_id dedup — and used to overwrite the attempt it was retrying. The answer to
# that first attempt then had nothing left to decapsulate with and was refused,
# while the far end had already installed that session and flushed everything it
# had queued for us under it. Nothing in the E2E plane retransmits, so those
# payloads were lost for good, in one direction only, on a link both ends
# considered healthy. A replaced attempt therefore stays answerable for a while,
# bounded and short-lived like the candidate table above.
_E2E_ATTEMPT_TTL = 30.0      # seconds a replaced attempt can still be answered
_E2E_ATTEMPT_MAX = 64        # replaced attempts kept, across all peers
# When our advertised address set changes, push it to this many most-recently
# seen peers (targeted Kademlia-style gossip). Bounded → no storm.
_ANNOUNCE_FANOUT       = 5
# Peers one gossip hop reaches. An epidemic still covers a connected mesh at
# this width; sending to *every* peer instead made one accepted claim cost
# (peers − 1) transmissions of ~5.3 kB, and an adversary that mints identities
# offline can make every claim it sends genuinely new.
_GOSSIP_FANOUT         = 6
# A bounded XOR-nearest link set is recovered at startup and refreshed while
# the node runs. Failed identities back off independently so dead addresses do
# not turn maintenance into a dial storm.
_NEIGHBOR_TARGET          = 5
# Floor of live maintained links. Below it the node is *searching*: it runs a
# discovery cycle every _NEIGHBOR_REFRESH. At or above it the neighbourhood is
# considered joined and the cycle stays quiet — a node that keeps looking up its
# own id forever is pure traffic, and a mesh that never settles is a mesh an
# adversary can keep busy. The floor is also what the keepalive guarantees.
_NEIGHBOR_FLOOR           = 3
# Identities seen carrying traffic that are XOR-closer to us than the least
# interesting slot we hold. Bounded: a peer relaying for the whole network must
# never grow our state (src ids in routed packets are not authenticated).
_NEIGHBOR_WATCH_TRACKED   = 64
_NEIGHBOR_REFRESH         = 30.0
# A wake may shorten the wait, never remove it. Without this floor a cycle whose
# own replies wake it runs flat out: FIND_NODE → FOUND_NODE → wake → FIND_NODE,
# and since a FOUND_NODE carries certificate chains (~15 kB) that loop fills a
# link entirely. **No loop driven by what a peer sends us may run unbounded.**
_NEIGHBOR_MIN_INTERVAL    = 5.0
# A mesh smaller than the floor can never reach it, so "searching" would stay
# true for the life of the node. Cycles that discover nothing back off to here.
_NEIGHBOR_IDLE_MAX        = 300.0
_NEIGHBOR_RETRY_MIN       = 2.0
_NEIGHBOR_RETRY_MAX       = 60.0
_NEIGHBOR_RETRY_TRACKED   = 128
# Getting a node back after its link died under us. Neighbourhood maintenance
# does not cover this and is not meant to: it dials to hold `_NEIGHBOR_FLOOR`
# links and to promote an XOR-nearer identity, so the node a person was
# actually talking to — usually neither — produced no dial at all when its link
# went, and the address-retry loop below only runs on media that declared a
# `retry_interval` (0, off, by default). The link went away and nothing went
# looking for it until an app happened to send again.
# So an established link lost involuntarily enrols its identity here and is
# chased hard for a short while: the first attempt within a second, doubling
# from there, and after `_RECONNECT_WINDOW` the ordinary machinery has it back.
# Everything about it is bounded — this is a loop that a peer disconnecting can
# start, and no such loop may run flat out (see gotchas §12).
_RECONNECT_FIRST_DELAY    = 0.5    # a socket still closing is not dialled
_RECONNECT_BACKOFF_MAX    = 15.0
_RECONNECT_WINDOW         = 120.0  # how long one identity is chased at this rate
_RECONNECT_NODES_TRACKED  = 16
_RECONNECT_MAX_IN_FLIGHT  = 4      # dials this loop may hold open at once
# A pass leaves whatever the in-flight cap did not reach still due, so the wait
# it computes can be zero. The floor is what keeps that from spinning.
_RECONNECT_MIN_TICK       = 0.25
# …and what happens when that window runs out. It used to be: nothing. The
# identity left the book, and the only thing left that could dial it was the
# address-retry loop below — which no stock node runs, because `retry_interval`
# ships at 0 on every transport. So a peer that came back four minutes later
# stayed unreached until somebody pressed "retry every address" by hand, which
# is not self-repair, it is an operator standing in for it.
# The chase therefore does not end; it slows down. Same ladder, second ceiling:
# hard for `_RECONNECT_WINDOW`, then patiently, for as long as we still hold an
# address to dial. One dial per identity per five minutes, against a book of
# sixteen, is a cost that does not move — and it is the difference between a
# node that comes back on its own and one that waits for a human.
_RECONNECT_PATIENT_MAX    = 300.0
# Losing several nodes at once says something none of the losses says alone.
# They cannot all have gone down together, so the thing that moved is *us*: a
# DHCP lease renewed, a VPN dropped, a laptop resumed on another network, an
# interface that changed under the process. Every address this node advertises
# and every address it dials out of is then suspect, and the reconnect ladder
# above is patiently dialling from a hole. So a burst re-verifies our own
# addressing at once instead of waiting out the monitor's ordinary rate limit.
# Bounded twice, because a peer flapping its link is what can trigger it: a
# cooldown here, and a floor of its own inside `NetMonitor`.
_LOSS_BURST_NODES         = 3      # distinct identities…
_LOSS_BURST_WINDOW        = 20.0   # …lost within this of each other
_LOSS_BURST_TRACKED       = 16
_LOSS_BURST_COOLDOWN      = 60.0
_ROUTE_SEND_FANOUT        = 5
_ROUTE_HINT_MAX           = 256
_ROUTE_HINT_TTL           = 120.0
# Measuring a routed path instead of assuming it (see `routed.py`).
#
# A direct link is probed and a routed one was not, so the send path could not
# tell a relay that delivers from one that accepts and drops: `peer.send()`
# returns either way. The first hop was whichever peer traffic last arrived
# through, then XOR distance — two guesses about topology, neither of which can
# notice a path that stopped working. A node that had been reachable a minute
# ago simply stopped answering, and the fix was to make a direct link by hand.
#
# So a path is probed end to end, on the same terms as a link: an ECHO to the
# target forced down one chosen neighbour, charged as lost when nothing comes
# back. Bounded like everything a peer's behaviour can drive — the book is
# bounded on both axes in `routed.py`, and this is what a pass may cost.
# Echo probes in flight, across the console's reachability check and the path
# prober below. Named because two callers share it, and a literal in one of
# them is a bound the other can silently exceed.
_PENDING_ECHO_MAX         = 128
_PATH_PROBE_INTERVAL      = 10.0   # per path, at rest
# …and the cadence of a path kept warm *behind a working direct link*. That is
# the hybrid: one physical link and one routed path measured at the same time,
# so losing the physical one costs a turn of the send order rather than a
# reconnect. It has to cost a great deal less than the link it stands behind —
# nothing is riding on it — so it gets its own, slower clock, and only one such
# path is opened per identity.
_PATH_STANDBY_INTERVAL    = 60.0
_PATH_PROBE_TIMEOUT       = 6.0    # …and when a probe is charged as lost
_PATH_PROBES_PER_PASS     = 4
_PATH_FLOOR               = 1.0    # shortest gap between two passes
_PATH_IDLE_MAX            = 300.0  # ceiling on a wait nothing is expected to end
_DIAL_LOG_NODES           = 128    # nodes whose address outcomes we remember
_DIAL_LOG_ADDRESSES       = 8      # addresses remembered per node
# Re-dialling addresses that went quiet. The *interval* is a per-transport
# setting (`retry_interval`, 0 = off) — a medium that costs a coin cell per dial
# and one that costs a TCP SYN have no business sharing a number. What is fixed
# here is the shape of the loop, so an operator's setting can never turn it into
# a flood: a slow tick, and a hard cap of dials per pass however many nodes are
# waiting.
_RETRY_TICK               = 5.0
_RETRY_MAX_PER_PASS       = 4
_RETRY_NODES_SCANNED      = 64
_RETRY_IDLE_MAX           = 300.0  # ceiling on a wait nothing is expected to end
_RETRY_DIAL_TIMEOUT       = 8.0
# What a dial **nobody is waiting on** may take, all addresses together.
#
# This is the difference the console's button had over every automatic path,
# and it was not a better idea about which address to try. `_ON_DEMAND_TIMEOUT`
# is five seconds because a packet is queued behind it — right for that — and
# `_connect_routing` splits whatever it is given across *every* address of the
# node. A peer advertising four of them therefore got 1.25 s each, which is
# less than opening a socket and completing a post-quantum handshake takes on
# any real WAN link: the recovery loops dialled, failed on time rather than on
# merit, and the operator pressed "retry every address" — where each address
# gets `_RETRY_DIAL_TIMEOUT` to itself — and watched it connect first go.
#
# Recovery is background work, so it is given what the button gives: a full
# per-address budget for a whole walk. Nothing is blocked meanwhile —
# `_pending_connections` makes a concurrent on-demand caller wait on its *own*
# timeout, not on this one.
_RECOVERY_TIMEOUT         = _RETRY_DIAL_TIMEOUT * _DIAL_LOG_ADDRESSES
# Proving our own public address instead of guessing it.
#
# `_extra_addrs` holds IPs somebody reported seeing us at — an HTTPS probe, a
# peer's `OBSERVED_ADDR`, a STUN reflexive address — and `advertised_uris`
# paired each of them with the **local listener port**. That is not an address.
# It is a claim that the NAT in front of this machine forwards that port, made
# from no evidence at all, and the mesh carried it to everybody.
#
# Two nodes behind one household or office IP therefore announced the *same
# URI*, and took turns being wrong about it: whoever the router forwards to
# answers, so the other one's entry is struck off ("dropped an address of … —
# it answers as somebody else"), and a node whose own router forwards back to
# itself dials its own public address and refuses its own handshake ("the
# challenge presents our own identity"). Both were read as bugs in the mesh.
# Neither was: the mesh was doing exactly the right thing with a false claim.
#
# `public_endpoints()` — what a join ticket carries — already held the rule:
# *we think this address is public* is not the same as *an inbound connection
# arrived on it*. The gossip path simply never applied it. It does now, and
# what counts as proof is one thing: somebody **out on the open internet**
# opened this transport to us. A peer on our own LAN reaching our LAN address
# proves the listener works and says nothing whatever about the NAT.
#
# That proof has to be *produced*, not waited for. AutoNAT existed and was
# reachable from one console button and from nothing else (gotchas: "a feature
# whose precondition nothing produces"), so a node with a correctly forwarded
# port could sit for ever with no confirmation. It is asked for on a timer now,
# backed off per failure, and only while there is somebody off our networks to
# ask — a probe costs that peer a dial back, so it is not free to them either.
_AUTONAT_FIRST            = 5.0    # after start, once there is somebody to ask
_AUTONAT_RETRY_MIN        = 30.0   # …then backing off per round that proved nothing
_AUTONAT_RETRY_MAX        = 900.0
_AUTONAT_REFRESH          = 1800.0 # a confirmation is re-proved this often
_AUTONAT_IDLE_MAX         = 300.0  # ceiling on a wait nothing is expected to end
# Distinct refusal reasons remembered. The vocabulary is this file's own, so
# the bound is a formality — it is here so that adding a reason can never turn
# a counter into a leak.
_REFUSALS_KEPT            = 24
# Moving a live link to a better address. Off by default: switching costs a
# dial, a handshake and a moment with two links to the same node, which is only
# worth it when the gain is real and lasting.
_ADDR_STEER_INTERVAL      = 60.0   # one candidate examined per pass, at most
_ADDR_STEER_COOLDOWN      = 300.0  # per address, after it has been measured
_ADDR_STEER_PROBES        = 3      # pings averaged before believing a number
# Steering compares *scores*, not milliseconds, so "this medium is preferred"
# and "this address is faster" are weighed on one scale (see `_address_score`).
_ADDR_STEER_MIN_GAIN      = 0.05   # below this, the difference is noise
# How hard losing probes counts against a link. Loss is not "a slower link" —
# it is a link that does not work — so it *multiplies* the score rather than
# shifting it: at this exponent one probe in ten lost costs more than any
# latency difference a real network produces (0.9^4 ≈ 0.66), and a link nothing
# comes back from scores exactly zero, so it is never chosen while anything
# else exists. It stays listed, and stays connected: probes lost is not proof
# that data is, and an operator who can see "100% loss" can act on it.
_LOSS_PENALTY_EXP         = 4.0
# Replacing a link that is losing too much to still be one.
#
# The score above keeps a rotten link out of the traffic, and
# `_reap_silent_links` cuts one that answers *nothing*. Between the two sits
# the link an operator actually complains about: it answers four probes in
# five, so it is never cut — and when it is the only link to that node, a score
# has nothing to prefer over it. Nothing dialled anything, and getting a
# working link back meant pressing "retry every address" by hand.
#
# So the keepalive sweep names it and a bounded pass does by itself what that
# button does: work down that identity's addresses, open a link, and keep
# whichever of the two `_link_score` prefers. Dialling the address already in
# use is not a mistake here and is often the whole fix — a half-open TCP
# connection and a NAT mapping that expired both need a *new* connection, not a
# different address.
#
# Every bound is one the second-link dial already uses, because it is the same
# risk: a loop a peer's behaviour can start. One identity per pass, a floor
# between passes, a backoff per identity, a book that cannot grow.
_LOSS_RESCUE_SHARE        = 0.20   # of the recent window, above which a link is failing
_LOSS_RESCUE_PROBES       = 10     # …judged over at least this many outcomes
_RESCUE_TRACKED           = 16     # identities remembered, in either book
_RESCUE_MIN               = 60.0   # backoff after a rescue that changed nothing…
_RESCUE_MAX               = 900.0  # …doubling to here
_RESCUE_DIALS_PER_PASS    = 4      # addresses one rescue may try before giving up
_RESCUE_FLOOR             = 5.0    # shortest gap between two passes
_RESCUE_IDLE_MAX          = 300.0  # ceiling on a wait nothing is expected to end

# Choosing between the addresses of one node. Two things matter and they are not
# the same kind of thing: what the *medium* is worth (a priority the operator
# sets per transport, e.g. never prefer a USB spool over Wi-Fi) and what the
# *address* measures. The balance between them is the operator's to set, because
# only they know whether a slow preferred link beats a fast unwanted one.
_PRIORITY_SPAN            = 254    # a priority runs -254..254
_LATENCY_HALF_MS          = 25.0   # the latency worth exactly half a point
_BALANCE_DEFAULT          = 50     # 0 = latency alone, 100 = priority alone
# Acquiring a route (Kademlia lookup + dial + hole punch) takes seconds. It must
# never run inside a peer's receive loop: that link would process nothing else
# meanwhile — and the FOUND_NODE the lookup waits for often has to come back
# over that very link, so an inline lookup can only time out. Handlers hand the
# slow path to a bounded set of background tasks instead.
_MAX_DEFERRED_ROUTES      = 64
# Cap on waiting for one peer's cancelled receive task to actually exit. Never
# unbounded: shutdown must always finish (see _Peer.stop).
_PEER_STOP_TIMEOUT        = 2.0
# A post-quantum certificate is ~7 KB (ML-DSA-65 subject + issuer key +
# signature), so a chain to a root is ~15 KB. Packing Kademlia's k=20 entries
# into one FOUND_NODE therefore blows the 60 000-byte packet cap: Packet.create
# raised, the reply was never sent, and *every* lookup in a mesh holding more
# than four certified nodes silently timed out. Entries are packed closest-first
# under a hard byte budget instead (certs shared through a pool, see
# _EntryPacker) — fewer per reply, but the lookup converges over its rounds
# instead of dying. Also caps the CPU one FIND_NODE can buy (one chain-to-root
# BFS per packed entry) and the reflection an attacker gets out of a 28-byte
# query addressed with someone else's src_id.
_FOUND_NODE_MAX_BYTES     = 32_000
# Candidates scanned to fill that budget. Only entries with a chain to a root
# are usable (the receiver drops the rest), and those are scattered through the
# table — scanning exactly k left replies empty whenever the k nearest happened
# to be chain-less. Kademlia's k bounds what we *return*, not what we look at.
_FIND_NODE_SCAN           = 64
# Answering FIND_NODE/FIND_VALUE is the most expensive thing a single small
# packet can ask of us (chain building, a DHT value up to the packet cap), and
# the reply is routed to an *unverified* src_id — so it is also a reflection
# lever. Bound it per ingress link, like the seek/catalog/directory planes.
# This is a flood valve, NOT traffic shaping: one peer's legitimate peak is a
# lookup's alpha × rounds plus a few concurrent lookups — measured at ~66 per
# window on a relay star, and flat as the mesh grows, since it is bounded by one
# node's lookup behaviour rather than by how many nodes exist. Set it well above
# that; a cap near the legitimate peak silently kills real lookups, which is the
# very failure mode this file is trying to remove.
_QUERY_RATE_WINDOW        = 10.0
_QUERY_RATE_MAX           = 512
# Storing is cheap for us and cheap for the sender, but the store it fills is
# where app chunks and release content live and eviction is one global LRU — so
# a peer that can spray STOREs can evict the distribution layer. Well above any
# legitimate publish (`dht_put_many` sends `_PUBLISH_CONCURRENCY` at a time).
_STORE_RATE_WINDOW        = 10.0
_STORE_RATE_MAX           = 256
# One PUNCH_REQUEST costs us two packets, one of them on a link the requester
# does not pay for. A punch is a handful of requests, never a stream.
_PUNCH_REQ_WINDOW         = 10.0
_PUNCH_REQ_MAX            = 32
# Raw punch datagrams, per source address. A punch is `_PUNCH_PROBE_COUNT`
# probes and an ack, repeated at most `_PUNCH_MAX_RETRIES` times, so this is far
# above anything legitimate and still far below what an unmetered verification
# flood would cost.
_PUNCH_DGRAM_WINDOW       = 10.0
_PUNCH_DGRAM_MAX          = 64
_PUNCH_DGRAM_TRACKED      = 256

# Invite blocks (base64 join bundles: advertised URIs + invite code)
_JOIN_BLOCK_MAX_LEN  = 8192   # base64 length cap before decode
_JOIN_BLOCK_MAX_URIS = 16     # candidate addresses tried per block
_JOIN_TRY_TIMEOUT    = 6.0    # per-URI connect + session wait

# Relayed invitation (INVITE_SEEK): a joiner routes a signed seek toward the
# inviter through the mesh. Everything here is bounded and rate-limited — a
# pre-auth packet crossing the mesh is a sensitive surface.
_SEEK_TAG          = b"NMESH-INVITE-SEEK-v1"  # domain separation for the token
_SEEK_MAX_PAYLOAD  = 8192      # cert + token, bounded before any parse
_SEEK_MAX_FUTURE   = 3600.0    # exp accepted at most this far ahead (replay window)
_SEEK_TTL          = 16        # max hops a seek travels
# …and what an *unauthenticated* link's seek is worth. One packet handed to the
# edge of the mesh was carried by up to _SEEK_TTL authenticated links, by
# somebody who had not joined it; a joiner needs enough hops to find an inviter,
# not the diameter of the network.
_SEEK_TTL_PREAUTH  = 6
# Neighbours one seek is handed to at each hop. One was greedy XOR, which fails
# precisely when that neighbour has no path — and a seek has no reply, no retry
# and no second attempt. Two, because a node forwards a given seek at most once
# (node-wide dedup), so this is a factor on the packets a join costs and never
# an exponent.
_SEEK_FANOUT       = 2
_RDV_MAX           = 512       # bounded reverse-path (rendezvous) table
_RDV_TTL           = 120.0     # rendezvous entry lifetime, seconds
_SEEK_RATE_MAX     = 20        # max seeks accepted per ingress link per window
_SEEK_RATE_WINDOW  = 10.0      # rate-limit window, seconds
_MAX_PENDING_SEEKS = 128       # bounded record of seeks addressed to us
_CARRY_RATE_MAX    = 256       # max relay-carry packets per ingress link per window
# AutoNAT: confirm reachability by having a peer dial us back at the address it
# observed us come from (never an arbitrary address → no amplification).
_REACH_DIAL_TIMEOUT   = 3.0    # per dial-back attempt
# Opening packets a dial-back will look through for the challenge. Small: a node
# answering a fresh connection says a couple of things and one of them is the
# challenge. What this bounds is a peer answering with an endless dribble.
_REACH_DIAL_PACKETS   = 4
_REACH_PROBE_RATE_MAX = 5      # dial-backs we perform per requesting peer / window
_REACH_DIALS_MAX      = 8      # concurrent dial-backs across all peers (bounded)
# How long an answer to a probe we sent is still worth believing, and how many
# outstanding probes we track. A dial-back is bounded by _REACH_DIAL_TIMEOUT
# twice over, so anything much later than this is not an answer to our question.
_REACH_PENDING_TTL    = 30.0
_REACH_PENDING_MAX    = 64
# A rendezvous an inviter left with a relay: "a joiner will come asking for
# this code; here is the proof I authorised it". It is what lets an invitation
# reach a node with no address of its own from a string short enough to put in a
# QR code — the heavy part (an ML-DSA key and a signature, five kilobytes) stays
# with the relay, and the ticket carries an identity and a seed.
_SHORT_SEEK_LEN    = 40        # exp(8) | h_code(32) — nothing else fits in it
_OFFER_MAX         = 256       # rendezvous offers one node holds for others
_OFFER_RATE_MAX    = 8         # offers one peer may leave us per window
_SHORT_SEEK_GAP    = 2.0       # seconds between two forwards of one rendezvous
_RELAY_INVITE_TTL  = 300       # relay-invite block lifetime, seconds (== code TTL)
_RELAY_BLOCK_MAX_LEN = 32768   # v3 block cap (carries an ML-DSA key + signature)
_RELAY_JOIN_TIMEOUT = 12.0     # per-relay attempt: seek + tunnelled handshake
_RELAY_TRIES       = 3         # relays a ticket's rendezvous is offered to
_MAX_RELAY_PEERS   = 64        # bounded virtual (relayed) peer table
_RELAY_QUEUE_MAX   = 32        # packets a relayed tunnel may hold undelivered

# Hole punching
_PUNCH_PROBE_COUNT     = 5     # probes sent in rapid succession
_PUNCH_PROBE_INTERVAL  = 0.1   # seconds between probes
_PUNCH_TIMEOUT         = 10.0  # overall hole-punch attempt timeout
_PUNCH_MAX_PENDING     = 16    # max concurrent hole-punch attempts
_PUNCH_MAX_RETRIES     = 3     # max retries per target
_PUNCH_MAX_RELAYS      = 3     # relays asked per punch attempt
# The initiator opens the punched link by sending a keepalive frame the
# responder's accept path turns into a challenge. UDP can drop that datagram
# (a loaded receiver's buffer overflows), and a single loss strands the whole
# punch — the responder never challenges and the initiator's link self-closes
# on its keepalive timeout. Kick in a bounded, spaced burst instead so a few
# consecutive drops can't sink the handshake (CLAUDE.md: retry, self-repair).
_PUNCH_KICK_COUNT      = 8     # keepalive kicks to open the punched link
_PUNCH_KICK_INTERVAL   = 0.3   # seconds between kicks (burst spans ~2.4s)
_PUNCH_KEEPALIVE_INTERVAL = 20.0  # NAT mapping refresh for the UDP listener
# STUN requests we remember having sent. A binding response arrives in
# milliseconds; anything much later is not an answer to our question.
_STUN_PENDING_TTL         = 15.0
_STUN_PENDING_MAX         = 8
# Manual (out-of-band) hole punching: open a NAT mapping toward a peer whose
# public UDP endpoint an operator supplies by hand — no relay needed.
_HOLE_OPEN_MAGIC    = b"NHOL"  # ignored by the receiver; only opens our mapping
_HOLE_OPEN_INTERVAL = 2.0      # cadence for keeping a hole fresh (< NAT timeout)
_HOLE_OPEN_DEFAULT  = 30.0     # default sustain for a bare manual open
# The two-step connect exchange has a human copy-paste round-trip between the
# accept and the complete, so the host must hold its hole open long enough to
# span it — kept under the 5-min invite-code TTL.
_CONN_HOLE_SUSTAIN  = 180.0
_MANUAL_HOLE_MAX    = 32       # bounded table of manual-punch targets
_UPGRADE_COOLDOWN      = 60.0  # min seconds between direct-link attempts per target
_UPGRADE_MAX_TRACKED   = 256   # bounded per-target cooldown table

# Two-step connect exchange blocks
_CONN_BLOCK_VERSION = 2


__all__ = [
    "_ABUSE_RATE_MAX",
    "_ABUSE_RATE_WINDOW",
    "_ACCUSE_MIN_GAP",
    "_ACCUSE_SEEN_MAX",
    "_ACCUSE_TRACKED",
    "_ACK_ACCEPTED",
    "_ACK_HEADER",
    "_ACK_REJECTED",
    "_ADDR_GOSSIP_INTERVAL",
    "_ADDR_LEN",
    "_ADDR_STEER_COOLDOWN",
    "_ADDR_STEER_INTERVAL",
    "_ADDR_STEER_MIN_GAIN",
    "_ADDR_STEER_PROBES",
    "_ANNOUNCE_FANOUT",
    "_AUTH_POLL_INTERVAL",
    "_AUTONAT_FIRST",
    "_AUTONAT_IDLE_MAX",
    "_AUTONAT_REFRESH",
    "_AUTONAT_RETRY_MAX",
    "_AUTONAT_RETRY_MIN",
    "_AUTO_PUBLISH_RETRY",
    "_BALANCE_DEFAULT",
    "_BEHAVIOUR_NOTICES",
    "_BROADCAST_ID",
    "_CARRY_RATE_MAX",
    "_CATALOG_RATE_MAX",
    "_CATALOG_RATE_WINDOW",
    "_CERT_ARRIVALS_MAX",
    "_CERT_HINT_MAX",
    "_CERT_LEN",
    "_CERT_REF",
    "_CERT_RENEW_ACCEPT",
    "_CERT_RENEW_FIRST",
    "_CERT_RENEW_MAX",
    "_CERT_RENEW_MIN_GAP",
    "_CERT_RENEW_TICK",
    "_CERT_RENEW_TRACKED",
    "_CERT_RENEW_WINDOW",
    "_CONN_BLOCK_VERSION",
    "_CONN_HOLE_SUSTAIN",
    "_DEAD_LINK_PROBES",
    "_DEAD_LINK_SILENCE",
    "_DHT_K",
    "_DHT_QUERY_TIMEOUT",
    "_DIAL_LOG_ADDRESSES",
    "_DIAL_LOG_NODES",
    "_DIRECT_PING_TIMEOUT",
    "_DIRECT_TYPES",
    "_DIR_FIRST_PUBLISH",
    "_DIR_K",
    "_DIR_LOOKUP_BUDGET",
    "_DIR_LOOKUP_ROUNDS",
    "_DIR_PUBLISH_MAX",
    "_DIR_RATE_MAX",
    "_DIR_RATE_WINDOW",
    "_DIR_REPUBLISH",
    "_E2E_ATTEMPT_MAX",
    "_E2E_ATTEMPT_TTL",
    "_E2E_HEADER",
    "_E2E_REKEY_MAX",
    "_E2E_REKEY_TTL",
    "_E2E_RETRY_INTERVAL",
    "_ENTRY_CHAIN_MAX",
    "_ENTRY_COUNT_MAX",
    "_ENTRY_HEADER",
    "_ENTRY_POOL_MAX",
    "_FAMILY_SHARE",
    "_FIND_NODE_SCAN",
    "_FOUND_NODE_MAX_BYTES",
    "_GOSSIP_FANOUT",
    "_HANDSHAKE_DEADLINE",
    "_HEADER_BYTES",
    "_HEX_PKG",
    "_HEX_RELEASE",
    "_HINTS_OK",
    "_HINT_PEERS_MAX",
    "_HOLE_OPEN_DEFAULT",
    "_HOLE_OPEN_INTERVAL",
    "_HOLE_OPEN_MAGIC",
    "_HS_HEADER",
    "_JOIN_BLOCK_MAX_LEN",
    "_JOIN_BLOCK_MAX_URIS",
    "_JOIN_TRY_TIMEOUT",
    "_KAD_LOOKUP_MAX_ROUNDS",
    "_KAD_LOOKUP_TIMEOUT",
    "_KA_GRACE",
    "_KA_PROBE_DEADLINE",
    "_KA_REQUEST_MAX",
    "_KA_REQUEST_WINDOW",
    "_KA_TICK_FLOOR",
    "_KA_TOLD_TTL",
    "_KEY_SHARE_MAX",
    "_KEY_SHARE_WINDOW",
    "_LATENCY_HALF_MS",
    "_LINK_KEEPALIVE_INTERVAL",
    "_LOSS_BURST_COOLDOWN",
    "_LOSS_BURST_NODES",
    "_LOSS_BURST_TRACKED",
    "_LOSS_BURST_WINDOW",
    "_LOSS_PENALTY_EXP",
    "_LOSS_RESCUE_PROBES",
    "_LOSS_RESCUE_SHARE",
    "_MANUAL_HOLE_MAX",
    "_MAX_DATA_QUEUE",
    "_MAX_DEFERRED_ROUTES",
    "_MAX_DETACHED",
    "_MAX_E2E_SESSIONS",
    "_MAX_EXTRA_ADDRS",
    "_MAX_HANDSHAKE_ATTEMPTS",
    "_MAX_KEY_OFFERS",
    "_MAX_MALFORMED",
    "_MAX_PEERS",
    "_MAX_PENDING_PER_TARGET",
    "_MAX_PENDING_SEEKS",
    "_MAX_PENDING_TARGETS",
    "_MAX_RELAY_PEERS",
    "_MAX_UNAUTH_PEERS",
    "_MLO_AWAKE_TTL",
    "_MLO_DIAL_FLOOR",
    "_MLO_DIAL_IDLE_MAX",
    "_MLO_DIAL_MAX",
    "_MLO_DIAL_MIN",
    "_MLO_DIAL_PER_PASS",
    "_MLO_DIAL_TRACKED",
    "_MLO_SOURCES_MAX",
    "_MSG_DEDUP_MAX",
    "_NEIGHBOR_FLOOR",
    "_NEIGHBOR_IDLE_MAX",
    "_NEIGHBOR_MIN_INTERVAL",
    "_NEIGHBOR_REFRESH",
    "_NEIGHBOR_RETRY_MAX",
    "_NEIGHBOR_RETRY_MIN",
    "_NEIGHBOR_RETRY_TRACKED",
    "_NEIGHBOR_TARGET",
    "_NEIGHBOR_WATCH_TRACKED",
    "_OFFER_MAX",
    "_OFFER_RATE_MAX",
    "_ON_DEMAND_TIMEOUT",
    "_PATH_FLOOR",
    "_PATH_IDLE_MAX",
    "_PATH_PROBES_PER_PASS",
    "_PATH_PROBE_INTERVAL",
    "_PATH_PROBE_TIMEOUT",
    "_PATH_STANDBY_INTERVAL",
    "_PEER_STOP_TIMEOUT",
    "_PENDING_ECHO_MAX",
    "_PKG_OWN_MAX",
    "_PKG_RATE_MAX",
    "_PKG_RATE_WINDOW",
    "_PKG_SEARCH_MAX",
    "_PKG_SYNC_MAX",
    "_POOL_COUNT",
    "_POOL_INDEX",
    "_POST_AUTH_TYPES",
    "_PRIORITY_SPAN",
    "_PSEUDO_RATE_MAX",
    "_PSEUDO_RATE_WINDOW",
    "_PSEUDO_SEARCH_MAX",
    "_PSEUDO_SYNC_MAX",
    "_PUBLIC_IP_TIMEOUT",
    "_PUBLISH_CONCURRENCY",
    "_PUNCH_ACK_MAGIC",
    "_PUNCH_DGRAM_MAX",
    "_PUNCH_DGRAM_TRACKED",
    "_PUNCH_DGRAM_WINDOW",
    "_PUNCH_KEEPALIVE_INTERVAL",
    "_PUNCH_KICK_COUNT",
    "_PUNCH_KICK_INTERVAL",
    "_PUNCH_MAX_PENDING",
    "_PUNCH_MAX_RELAYS",
    "_PUNCH_MAX_RETRIES",
    "_PUNCH_PROBE",
    "_PUNCH_PROBE_COUNT",
    "_PUNCH_PROBE_INTERVAL",
    "_PUNCH_PROBE_MAGIC",
    "_PUNCH_REQ",
    "_PUNCH_REQ_MAX",
    "_PUNCH_REQ_WINDOW",
    "_PUNCH_SIG_MAX",
    "_PUNCH_TIMEOUT",
    "_QID_LEN",
    "_QUERY_RATE_MAX",
    "_QUERY_RATE_WINDOW",
    "_RDV_MAX",
    "_RDV_TTL",
    "_REACH_DIALS_MAX",
    "_REACH_DIAL_PACKETS",
    "_REACH_DIAL_TIMEOUT",
    "_REACH_PENDING_MAX",
    "_REACH_PENDING_TTL",
    "_REACH_PROBE_RATE_MAX",
    "_RECONNECT_BACKOFF_MAX",
    "_RECONNECT_FIRST_DELAY",
    "_RECONNECT_MAX_IN_FLIGHT",
    "_RECONNECT_MIN_TICK",
    "_RECONNECT_NODES_TRACKED",
    "_RECONNECT_PATIENT_MAX",
    "_RECONNECT_WINDOW",
    "_RECOVERY_TIMEOUT",
    "_REFUSALS_KEPT",
    "_RELAY_BLOCK_MAX_LEN",
    "_RELAY_INVITE_TTL",
    "_RELAY_JOIN_TIMEOUT",
    "_RELAY_QUEUE_MAX",
    "_RELAY_TRIES",
    "_RELEASE_ASK_MAX",
    "_RELEASE_FIRST_TICK",
    "_RELEASE_NEVER_TICK",
    "_RELEASE_RATE_MAX",
    "_RELEASE_RATE_WINDOW",
    "_RELEASE_SERVE_MAX",
    "_RELEASE_SERVE_WINDOW",
    "_RELEASE_SETTLE",
    "_RELEASE_SLICE",
    "_RELEASE_SLICE_TIMEOUT",
    "_RELEASE_SOURCES_MAX",
    "_RELEASE_SOURCES_TRACKED",
    "_RELEASE_TRIED_MAX",
    "_RESCUE_DIALS_PER_PASS",
    "_RESCUE_FLOOR",
    "_RESCUE_IDLE_MAX",
    "_RESCUE_MAX",
    "_RESCUE_MIN",
    "_RESCUE_TRACKED",
    "_RETRY_DIAL_TIMEOUT",
    "_RETRY_IDLE_MAX",
    "_RETRY_MAX_PER_PASS",
    "_RETRY_NODES_SCANNED",
    "_RETRY_TICK",
    "_REVOKE_RATE_MAX",
    "_REVOKE_RATE_WINDOW",
    "_REVOKE_SYNC_MAX",
    "_ROUTABLE_TYPES",
    "_ROUTE_HINT_MAX",
    "_ROUTE_HINT_TTL",
    "_ROUTE_SEND_FANOUT",
    "_SEEK_FANOUT",
    "_SEEK_MAX_FUTURE",
    "_SEEK_MAX_PAYLOAD",
    "_SEEK_RATE_MAX",
    "_SEEK_RATE_WINDOW",
    "_SEEK_TAG",
    "_SEEK_TTL",
    "_SEEK_TTL_PREAUTH",
    "_SHORT_SEEK_GAP",
    "_SHORT_SEEK_LEN",
    "_SPEED_CHUNK",
    "_SPEED_INFLIGHT",
    "_SPEED_MAX_BYTES",
    "_SPEED_MAX_PER_WINDOW",
    "_SPEED_MAX_SECONDS",
    "_SPEED_WINDOW",
    "_STATE_WRITE_INTERVAL",
    "_STORE_RATE_MAX",
    "_STORE_RATE_WINDOW",
    "_STUN_PENDING_MAX",
    "_STUN_PENDING_TTL",
    "_TARPIT_MAX",
    "_TARPIT_MIN",
    "_UPGRADE_COOLDOWN",
    "_UPGRADE_MAX_TRACKED",
    "_is_ip_address",
]
