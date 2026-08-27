import asyncio
import base64
import hashlib
import heapq
import hmac
import json
import os
import random
import re
import socket
import ssl
import struct
import threading
import time
from collections import OrderedDict
from .app_auth import AppAuth
from .trace import Trace
from .node_id import NodeID
from .routing import RoutingTable, NodeEntry
from .transport import BaseTransport
from .packet import Packet
from .crypto import CryptoIdentity, SessionKey
from .invite import InviteManager, compute_response
from .cert import Certificate
from .cert_store import CertStore
from .transport_manager import TransportManager
from .metrics import NodeMetrics, Counters, LinkQuality
from .dht import ContentStore
from .ip_utils import local_ip_addresses, expand_listen_uri, split_host_port
from .net_monitor import NetMonitor
from .app_package import (
    build as _app_build, parse_manifest as _app_parse_manifest,
    reassemble as _app_reassemble, chunk_keys as _app_chunk_keys,
    content_key as _content_key, AppPackageError,
    pack_root as _app_pack_root, parse_root as _app_parse_root,
    reassemble_bytes as _app_reassemble_bytes,
    build_release as _app_build_release, parse_release as _app_parse_release,
)
from .app_dht import frame as _app_dht_frame, read as _app_dht_read, AppDHTError
from .app_catalog import AppCatalog, InstalledApps
from .version import is_newer as _is_newer
from .core_release import (ReleaseCatalog, ReleaseStore, TrustedPublishers,
                           ReleaseError, PUBLISHER_ID_LEN as _RELEASE_ID_LEN,
                           build_package as _core_build_package,
                           build_release as _core_build_release,
                           check_tree as _core_check_tree,
                           open_package as _core_open_package,
                           parse_release as _core_parse_release,
                           publisher_id as _core_publisher_id,
                           read_tree as _core_read_tree,
                           release_id as _core_release_id,
                           version_of as _core_version_of)
from .pseudo import canonical as _pseudo_canonical
from .pseudo_dir import (PseudoBook, MAX_CLAIM as _MAX_CLAIM, dir_key as _dir_key,
                         build_claim as _dir_build_claim,
                         parse_claim as _dir_parse_claim,
                         encode_claims as _dir_encode, decode_claims as _dir_decode,
                         PseudoDirError)
from .uri import _validate_uri, _MAX_URI_LEN, _MAX_ADDRESSES

_HEADER_BYTES = 79  # fixed packet header size, for byte accounting


def _is_ip_address(s: str) -> bool:
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            socket.inet_pton(family, s)
            return True
        except OSError:
            continue
    return False

DATA          = 0x00
PING          = 0x01
PONG          = 0x02
FIND_NODE     = 0x03
FOUND_NODE    = 0x04
FIND_VALUE    = 0x05
FOUND_VALUE   = 0x06
STORE         = 0x07
HANDSHAKE     = 0x08
HANDSHAKE_ACK = 0x09
INVITE        = 0x0A
INVITE_ACK    = 0x0B
CHALLENGE         = 0x0C
E2E_HANDSHAKE     = 0x0D
E2E_HANDSHAKE_ACK = 0x0E
OBSERVED_ADDR     = 0x0F
PUNCH_REQUEST     = 0x10
PUNCH_RELAY       = 0x11
PUNCH_PROBE       = 0x12
PUNCH_ACK         = 0x13
INVITE_SEEK       = 0x14   # relayed invitation seek — routable PRE-auth, token-gated
RELAY_CARRY       = 0x15   # carries a handshake packet between two nodes via a relay
REACH_PROBE       = 0x16   # ask a peer to dial us back and confirm we're reachable
REACH_PROBE_ACK   = 0x17   # reply: did the dial-back succeed?
CATALOG_ANNOUNCE  = 0x18   # gossip a signed app-store release descriptor
DIR_STORE         = 0x19   # store a signed pseudo-directory claim
DIR_FIND          = 0x1A   # look up pseudo-directory claims by key
DIR_FOUND         = 0x1B   # reply: the claims held for a pseudo key
ECHO_REQUEST      = 0x1C   # routed liveness probe to a node id (multi-hop)
ECHO_REPLY        = 0x1D   # routed reply to an ECHO_REQUEST
RELEASE_ANNOUNCE  = 0x1E   # gossip a signed descriptor for the node's own code
RELEASE_FETCH     = 0x1F   # "send me this release's package, from here"
RELEASE_DATA      = 0x20   # a slice of a package, answering a fetch
PSEUDO_ANNOUNCE   = 0x21   # gossip a signed claim binding a pseudo to its node

# Built from this module's own constants so a message type added above can never
# be missing here — a trace showing "0x1e" for a type the code knows the name of
# is exactly the moment a trace stops being useful.
MESSAGE_NAMES = {
    value: name for name, value in list(globals().items())
    if isinstance(value, int) and name.isupper() and not name.startswith("_")
    and 0x00 <= value <= 0xFF
}

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
_ENTRY_CHAIN_MAX = 6    # certs in one entry's chain — longer is nonsense
_ENTRY_COUNT_MAX = 20   # Kademlia k; the receiver would drop a longer answer
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
                    RELEASE_ANNOUNCE, PSEUDO_ANNOUNCE}
_CATALOG_RATE_WINDOW = 10.0     # seconds
_CATALOG_RATE_MAX    = 128      # announces one link may push at us per window
_RELEASE_RATE_WINDOW = 10.0     # seconds
_RELEASE_RATE_MAX    = 32       # release announces one link may push per window
_RELEASE_TICK        = 300.0    # seconds between auto-install passes
_RELEASE_TRIED_MAX   = 32       # release ids we remember failing to install
_RELEASE_SLICE       = 48 * 1024   # bytes of package per RELEASE_DATA packet
_RELEASE_SLICE_TIMEOUT = 20.0   # waiting for one slice before trying elsewhere
_RELEASE_SERVE_WINDOW  = 10.0   # seconds
_RELEASE_SERVE_MAX     = 64     # slices one link may pull from us per window
_RELEASE_SOURCES_MAX   = 8      # nodes remembered as holding a given release
_RELEASE_SOURCES_TRACKED = 64   # releases we remember any sources for at all
_PUBLISH_CONCURRENCY   = 8      # DHT stores in flight while publishing an app
_HEX_RELEASE = re.compile(r"[0-9a-f]{%d}" % (_RELEASE_ID_LEN * 2))
_DIR_RATE_WINDOW     = 10.0     # seconds
_DIR_RATE_MAX        = 128      # DIR_STORE claims one link may push per window
_DIR_K               = 6        # replicate/query the pseudo directory across K
_PSEUDO_RATE_WINDOW  = 10.0     # seconds
_PSEUDO_RATE_MAX     = 64       # pseudo claims one link may gossip at us per window
_PSEUDO_SEARCH_MAX   = 50       # results one search may return
_PSEUDO_SYNC_MAX     = 128      # claims pushed at a peer when it authenticates
_MAX_DETACHED        = 64       # fire-and-forget tasks alive at once
_MAX_EXTRA_ADDRS = 8
_ROUTABLE_TYPES  = {DATA, E2E_HANDSHAKE, E2E_HANDSHAKE_ACK, ECHO_REQUEST, ECHO_REPLY,
                    FIND_NODE, FOUND_NODE, FIND_VALUE, FOUND_VALUE, STORE,
                    DIR_STORE, DIR_FIND, DIR_FOUND,
                    # A package comes from whoever has it, which may be several
                    # hops away — the publisher, or any node that kept a copy.
                    RELEASE_FETCH, RELEASE_DATA}
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
# A transport reaps an idle link once no data arrives for its read timeout
# (TCP: 60s). A healthy but quiet link would die on its own, so ping every
# established peer well inside that window — both sides do it, so each link
# carries a packet each way and a few misses still leave margin.
_LINK_KEEPALIVE_INTERVAL = 20.0
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
_ROUTE_SEND_FANOUT        = 5
_ROUTE_HINT_MAX           = 256
_ROUTE_HINT_TTL           = 120.0
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
_RETRY_DIAL_TIMEOUT       = 8.0
# Moving a live link to a better address. Off by default: switching costs a
# dial, a handshake and a moment with two links to the same node, which is only
# worth it when the gain is real and lasting.
_ADDR_STEER_INTERVAL      = 60.0   # one candidate examined per pass, at most
_ADDR_STEER_COOLDOWN      = 300.0  # per address, after it has been measured
_ADDR_STEER_PROBES        = 3      # pings averaged before believing a number
# Steering compares *scores*, not milliseconds, so "this medium is preferred"
# and "this address is faster" are weighed on one scale (see `_address_score`).
_ADDR_STEER_MIN_GAIN      = 0.05   # below this, the difference is noise

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
_RDV_MAX           = 512       # bounded reverse-path (rendezvous) table
_RDV_TTL           = 120.0     # rendezvous entry lifetime, seconds
_SEEK_RATE_MAX     = 20        # max seeks accepted per ingress link per window
_SEEK_RATE_WINDOW  = 10.0      # rate-limit window, seconds
_MAX_PENDING_SEEKS = 128       # bounded record of seeks addressed to us
_CARRY_RATE_MAX    = 256       # max relay-carry packets per ingress link per window
# AutoNAT: confirm reachability by having a peer dial us back at the address it
# observed us come from (never an arbitrary address → no amplification).
_REACH_DIAL_TIMEOUT   = 3.0    # per dial-back attempt
_REACH_PROBE_RATE_MAX = 5      # dial-backs we perform per requesting peer / window
_REACH_DIALS_MAX      = 8      # concurrent dial-backs across all peers (bounded)
# How long an answer to a probe we sent is still worth believing, and how many
# outstanding probes we track. A dial-back is bounded by _REACH_DIAL_TIMEOUT
# twice over, so anything much later than this is not an answer to our question.
_REACH_PENDING_TTL    = 30.0
_REACH_PENDING_MAX    = 64
_RELAY_INVITE_TTL  = 300       # relay-invite block lifetime, seconds (== code TTL)
_RELAY_BLOCK_MAX_LEN = 32768   # v3 block cap (carries an ML-DSA key + signature)
_RELAY_JOIN_TIMEOUT = 12.0     # per-relay attempt: seek + tunnelled handshake
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


def _encode_conn_block(kind: str, **fields) -> str:
    """base64(JSON) block for the two-step connect exchange."""
    payload = {"v": _CONN_BLOCK_VERSION, "kind": kind, **fields}
    return base64.b64encode(
        json.dumps(payload, separators=(",", ":")).encode("utf-8")
    ).decode("ascii")


def _decode_conn_block(block: str, expect_kind: str) -> dict:
    """Decode + validate a connect block (hostile input). Raises ValueError."""
    if not isinstance(block, str) or not (0 < len(block) <= _JOIN_BLOCK_MAX_LEN):
        raise ValueError("invalid block")
    try:
        data = json.loads(base64.b64decode("".join(block.split()), validate=True))
    except Exception:
        raise ValueError("invalid or corrupt block") from None
    if not isinstance(data, dict) or data.get("v") != _CONN_BLOCK_VERSION:
        raise ValueError("unsupported block version")
    if data.get("kind") != expect_kind:
        what = {"req": "a connection request", "inv": "an invite"}.get(expect_kind, expect_kind)
        raise ValueError(f"that block is not {what} block")
    return data


# ---------------------------------------------------------------------------
# INVITE_SEEK codec (relayed invitation)
# ---------------------------------------------------------------------------
#
# Payload: exp(uint64) | h_code(32) | pub_len(H) | inviter_pub | token_len(H) | token
# Routing uses the packet header: src_id = seeker (B), dst_id = inviter (A). We
# carry the inviter's raw ML-DSA public key (not a full cert — leaner): any node
# checks NodeID(inviter_pub) == dst_id and that the token is the inviter's
# signature over TAG||h_code||exp. So a seek is verifiably authorised by the key
# whose hash is the inviter id — no shared secret, no impersonation.

def _uri_preference(uri: str) -> int:
    """Connect-order key: 0 = global IPv6 (no NAT, prefer), 1 = anything else.
    A global IPv6 endpoint is directly reachable end-to-end, so trying it first
    lets two IPv6-capable nodes skip NAT punching / relaying entirely."""
    parsed = _validate_uri(uri)
    if parsed is None:
        return 1
    hp = split_host_port(parsed[1])
    if hp is None:
        return 1
    try:
        import ipaddress
        ip = ipaddress.ip_address(hp[0])
    except ValueError:
        return 1
    return 0 if (ip.version == 6 and ip.is_global) else 1


def _order_by_preference(uris: list[str]) -> list[str]:
    """Stable sort putting global-IPv6 endpoints first."""
    return sorted(uris, key=_uri_preference)


def _h_code(code: str) -> bytes:
    """Recogniser tag for an invite code (only the inviter resolves it)."""
    return hashlib.sha256(code.encode("utf-8")).digest()


def _seek_signed_blob(h_code: bytes, exp: int) -> bytes:
    return _SEEK_TAG + h_code + struct.pack("!Q", exp)


def _encode_seek(exp: int, h_code: bytes, inviter_pub: bytes, token: bytes) -> bytes:
    return (struct.pack("!Q", exp) + h_code
            + struct.pack("!H", len(inviter_pub)) + inviter_pub
            + struct.pack("!H", len(token)) + token)


def _decode_seek(payload: bytes):
    """Parse an INVITE_SEEK payload (hostile input). Returns
    (exp, h_code, inviter_pub, token) or None. Fully bounds-checked."""
    if not (40 < len(payload) <= _SEEK_MAX_PAYLOAD):
        return None
    try:
        off = 0
        exp = struct.unpack_from("!Q", payload, off)[0]; off += 8
        h_code = payload[off:off + 32]; off += 32
        if len(h_code) != 32:
            return None
        plen = struct.unpack_from("!H", payload, off)[0]; off += 2
        inviter_pub = payload[off:off + plen]; off += plen
        if len(inviter_pub) != plen or plen == 0:
            return None
        tlen = struct.unpack_from("!H", payload, off)[0]; off += 2
        token = payload[off:off + tlen]; off += tlen
        if len(token) != tlen or tlen == 0:
            return None
    except struct.error:
        return None
    return exp, h_code, inviter_pub, token


def _make_invite_seek(inviter_identity, seeker_id, code: str, exp: int,
                      ttl: int = _SEEK_TTL) -> 'Packet':
    """Build a signed INVITE_SEEK from the inviter's own identity (used by the
    inviter's block generator and by tests). Routed toward the inviter id."""
    pub = inviter_identity.dsa_public_key
    inviter_id = NodeID.from_public_key(pub)
    h = _h_code(code)
    token = inviter_identity.sign(_seek_signed_blob(h, exp))
    payload = _encode_seek(exp, h, pub, token)
    return Packet.create(INVITE_SEEK, seeker_id.raw, inviter_id.raw,
                         payload, ttl=ttl)


# ---------------------------------------------------------------------------
# Chain codec
# ---------------------------------------------------------------------------

def _encode_chain(chain: list[Certificate]) -> bytes:
    """count(B) || [cert_len(H) || cert_bytes]*count"""
    parts: list[bytes] = [bytes([len(chain)])]
    for cert in chain:
        cert_bytes = cert.serialize()
        parts.append(_CERT_LEN.pack(len(cert_bytes)))
        parts.append(cert_bytes)
    return b"".join(parts)


def _decode_chain(data: bytes) -> list[Certificate]:
    """Parse a certificate chain. Every certificate is verified as it is built
    (``Certificate._build``), so this is the expensive half of a handshake —
    hence the explicit ceiling. It used to be bounded only by the packet size,
    which is a bound by accident: it moves the day a smaller signature scheme
    is added, and every other decoder in this file states its own."""
    if not data:
        return []
    count = data[0]
    if count > _ENTRY_CHAIN_MAX:
        raise ValueError(f"chain too long: {count}")
    offset = 1
    certs: list[Certificate] = []
    for _ in range(count):
        if offset + 2 > len(data):
            raise ValueError("chain truncated at length field")
        cert_len = _CERT_LEN.unpack_from(data, offset)[0]
        offset += 2
        if offset + cert_len > len(data):
            raise ValueError("chain truncated at cert data")
        certs.append(Certificate.deserialize(data[offset:offset + cert_len]))
        offset += cert_len
    return certs


# ---------------------------------------------------------------------------
# Handshake codec
# ---------------------------------------------------------------------------

def _encode_handshake(kem_pub: bytes, dsa_pub: bytes,
                      chain: list[Certificate], signature: bytes) -> bytes:
    chain_bytes = _encode_chain(chain)
    return (_HS_HEADER.pack(len(kem_pub), len(dsa_pub), len(chain_bytes))
            + kem_pub + dsa_pub + chain_bytes + signature)


def _split_handshake(data: bytes) -> tuple[bytes, bytes, bytes, bytes]:
    """Slice a HANDSHAKE into its four fields, **without** parsing the chain.

    Parsing a chain verifies every certificate in it, which is the most
    expensive thing in the packet — and `_handle_handshake` can rule the packet
    out with two SHA-256s before spending any of it. Keeping the slice and the
    verification apart is what lets the cheap test come first."""
    if len(data) < _HS_HEADER.size:
        raise ValueError("handshake payload too short")
    kem_len, dsa_len, chain_len = _HS_HEADER.unpack_from(data, 0)
    offset = _HS_HEADER.size
    if offset + kem_len + dsa_len + chain_len > len(data):
        raise ValueError("handshake payload truncated")
    kem_pub     = data[offset:offset + kem_len];   offset += kem_len
    dsa_pub     = data[offset:offset + dsa_len];   offset += dsa_len
    chain_bytes = data[offset:offset + chain_len]; offset += chain_len
    return kem_pub, dsa_pub, chain_bytes, data[offset:]


def _decode_handshake(data: bytes) -> tuple[bytes, bytes, list[Certificate], bytes]:
    kem_pub, dsa_pub, chain_bytes, signature = _split_handshake(data)
    return kem_pub, dsa_pub, _decode_chain(chain_bytes), signature


def _encode_handshake_ack(ciphertext: bytes, dsa_pub: bytes,
                          chain: list[Certificate],
                          issued_cert: Certificate | None,
                          signature: bytes) -> bytes:
    chain_bytes  = _encode_chain(chain)
    issued_bytes = issued_cert.serialize() if issued_cert is not None else b""
    return (_ACK_HEADER.pack(len(ciphertext), len(dsa_pub),
                             len(chain_bytes), len(issued_bytes))
            + ciphertext + dsa_pub + chain_bytes + issued_bytes + signature)


def _decode_handshake_ack(data: bytes) -> tuple[bytes, bytes, list[Certificate],
                                                 Certificate | None, bytes]:
    if len(data) < _ACK_HEADER.size:
        raise ValueError("handshake_ack payload too short")
    ct_len, dsa_len, chain_len, issued_len = _ACK_HEADER.unpack_from(data, 0)
    offset = _ACK_HEADER.size
    if offset + ct_len + dsa_len + chain_len + issued_len > len(data):
        raise ValueError("handshake_ack payload truncated")
    ciphertext   = data[offset:offset + ct_len];     offset += ct_len
    dsa_pub      = data[offset:offset + dsa_len];    offset += dsa_len
    chain_bytes  = data[offset:offset + chain_len];  offset += chain_len
    issued_bytes = data[offset:offset + issued_len]; offset += issued_len
    chain       = _decode_chain(chain_bytes)
    issued_cert = Certificate.deserialize(issued_bytes) if issued_bytes else None
    return ciphertext, dsa_pub, chain, issued_cert, data[offset:]


# ---------------------------------------------------------------------------
# Address list codec
# addr_count(B) || [addr_len(H) || addr_bytes]*addr_count
# ---------------------------------------------------------------------------

def _encode_addresses(addresses: list[str]) -> bytes:
    count = min(len(addresses), _MAX_ADDRESSES)
    parts: list[bytes] = [bytes([count])]
    for addr in addresses[:count]:
        b = addr.encode('utf-8')
        parts.append(_ADDR_LEN.pack(len(b)))
        parts.append(b)
    return b"".join(parts)


def _decode_addresses(data: bytes) -> list[str]:
    """Decode a packed address list. Raises ValueError on structural errors or count > _MAX_ADDRESSES."""
    if not data:
        raise ValueError("empty address payload")
    count = data[0]
    if count > _MAX_ADDRESSES:
        raise ValueError(f"too many addresses: {count}")
    offset = 1
    addresses: list[str] = []
    for _ in range(count):
        if offset + 2 > len(data):
            raise ValueError("truncated addr_len")
        addr_len = _ADDR_LEN.unpack_from(data, offset)[0]
        offset += 2
        if addr_len > _MAX_URI_LEN:
            raise ValueError(f"addr_len too large: {addr_len}")
        if offset + addr_len > len(data):
            raise ValueError("truncated addr_bytes")
        addr = data[offset:offset + addr_len].decode('utf-8')
        addresses.append(addr)
        offset += addr_len
    return addresses


# ---------------------------------------------------------------------------
# E2E handshake codecs
# E2E_HANDSHAKE payload:  nonce(32) || kem_pub_len(H) || dsa_pub_len(H) || chain_len(H)
#                          || kem_pub || dsa_pub || chain_bytes || signature
# E2E_HANDSHAKE_ACK payload: same struct, fields are ct_len / dsa_len / chain_len
#                          || ciphertext || dsa_pub || chain_bytes || signature
# ---------------------------------------------------------------------------

def _encode_e2e_handshake(nonce: bytes, kem_pub: bytes, dsa_pub: bytes,
                           chain: list[Certificate], signature: bytes) -> bytes:
    chain_bytes = _encode_chain(chain)
    return (_E2E_HEADER.pack(nonce, len(kem_pub), len(dsa_pub), len(chain_bytes))
            + kem_pub + dsa_pub + chain_bytes + signature)


def _decode_e2e_handshake(data: bytes) -> tuple[bytes, bytes, bytes, list[Certificate], bytes]:
    if len(data) < _E2E_HEADER.size:
        raise ValueError("e2e_handshake payload too short")
    nonce, kem_len, dsa_len, chain_len = _E2E_HEADER.unpack_from(data, 0)
    offset = _E2E_HEADER.size
    if offset + kem_len + dsa_len + chain_len > len(data):
        raise ValueError("e2e_handshake payload truncated")
    kem_pub     = data[offset:offset + kem_len];   offset += kem_len
    dsa_pub     = data[offset:offset + dsa_len];   offset += dsa_len
    chain_bytes = data[offset:offset + chain_len]; offset += chain_len
    return nonce, kem_pub, dsa_pub, _decode_chain(chain_bytes), data[offset:]


def _encode_e2e_handshake_ack(nonce: bytes, ciphertext: bytes, dsa_pub: bytes,
                               chain: list[Certificate], signature: bytes) -> bytes:
    chain_bytes = _encode_chain(chain)
    return (_E2E_HEADER.pack(nonce, len(ciphertext), len(dsa_pub), len(chain_bytes))
            + ciphertext + dsa_pub + chain_bytes + signature)


def _decode_e2e_handshake_ack(data: bytes) -> tuple[bytes, bytes, bytes, list[Certificate], bytes]:
    if len(data) < _E2E_HEADER.size:
        raise ValueError("e2e_handshake_ack payload too short")
    nonce, ct_len, dsa_len, chain_len = _E2E_HEADER.unpack_from(data, 0)
    offset = _E2E_HEADER.size
    if offset + ct_len + dsa_len + chain_len > len(data):
        raise ValueError("e2e_handshake_ack payload truncated")
    ciphertext  = data[offset:offset + ct_len];    offset += ct_len
    dsa_pub     = data[offset:offset + dsa_len];   offset += dsa_len
    chain_bytes = data[offset:offset + chain_len]; offset += chain_len
    return nonce, ciphertext, dsa_pub, _decode_chain(chain_bytes), data[offset:]


# ---------------------------------------------------------------------------
# Hole-punching codecs
# ---------------------------------------------------------------------------

def _encode_punch_request(target_id: bytes, my_udp_port: int) -> bytes:
    return _PUNCH_REQ.pack(target_id, my_udp_port)


def _decode_punch_request(data: bytes) -> tuple[bytes, int] | None:
    if len(data) < _PUNCH_REQ.size:
        return None
    target_id, port = _PUNCH_REQ.unpack_from(data, 0)
    return target_id, port


def _encode_punch_relay(peer_id: bytes, peer_addr: str,
                        observed_addr: str) -> bytes:
    pa = peer_addr.encode('utf-8')
    oa = observed_addr.encode('utf-8')
    return (peer_id + _ADDR_LEN.pack(len(pa)) + pa
            + _ADDR_LEN.pack(len(oa)) + oa)


def _decode_punch_relay(data: bytes) -> tuple[bytes, str, str] | None:
    if len(data) < 20 + 2:
        return None
    peer_id = data[:20]
    offset = 20
    if offset + 2 > len(data):
        return None
    pa_len = _ADDR_LEN.unpack_from(data, offset)[0]
    offset += 2
    if offset + pa_len > len(data):
        return None
    peer_addr = data[offset:offset + pa_len].decode('utf-8')
    offset += pa_len
    if offset + 2 > len(data):
        return None
    oa_len = _ADDR_LEN.unpack_from(data, offset)[0]
    offset += 2
    if offset + oa_len > len(data):
        return None
    observed_addr = data[offset:offset + oa_len].decode('utf-8')
    return peer_id, peer_addr, observed_addr


def _punch_signed_blob(magic: bytes, src: bytes, dst: bytes, nonce: bytes,
                       minute: int) -> bytes:
    """What a punch probe or ack actually signs.

    It names the **recipient** and the minute it was made. Signing only
    ``magic ‖ src ‖ nonce`` made every probe a token valid anywhere, for ever:
    one captured datagram could be replayed at any node that knew the sender,
    and each replay bought a signature and a ~3.4 kB answer sent to whatever
    source address the replayer forged."""
    return magic + src + dst + nonce + struct.pack("!Q", minute)


def _punch_minutes(now: float | None = None) -> tuple[int, ...]:
    """The minute stamps a fresh probe may carry: this one and the last.

    Two, not one, because a probe crossing a minute boundary is not a replay —
    and not more, because the window is the whole freshness guarantee."""
    minute = int((now if now is not None else time.time()) // 60)
    return (minute, minute - 1)


def _build_punch_probe(node_id: bytes, nonce: bytes, signature: bytes) -> bytes:
    """Build a raw UDP probe datagram (not a mesh Packet)."""
    return _PUNCH_PROBE.pack(_PUNCH_PROBE_MAGIC, node_id, nonce) + signature


def _parse_punch_probe(data: bytes) -> tuple[bytes, bytes, bytes] | None:
    """Parse a raw UDP probe datagram. Returns (node_id, nonce, signature) or None."""
    return _parse_punch_frame(data, _PUNCH_PROBE_MAGIC)


def _parse_punch_frame(data: bytes, expect_magic: bytes
                       ) -> tuple[bytes, bytes, bytes] | None:
    """Shared probe/ack parse. The signature is the variable-length tail after
    the fixed header (ML-DSA-65 = 3309 bytes), bounded by _PUNCH_SIG_MAX."""
    sig_len = len(data) - _PUNCH_PROBE.size
    if sig_len <= 0 or sig_len > _PUNCH_SIG_MAX:
        return None
    magic, node_id, nonce = _PUNCH_PROBE.unpack_from(data, 0)
    if magic != expect_magic:
        return None
    signature = data[_PUNCH_PROBE.size:]
    return node_id, nonce, signature


def _build_punch_ack(node_id: bytes, nonce: bytes, signature: bytes) -> bytes:
    """Build a raw UDP punch-ack datagram."""
    return _PUNCH_PROBE.pack(_PUNCH_ACK_MAGIC, node_id, nonce) + signature


def _parse_punch_ack(data: bytes) -> tuple[bytes, bytes, bytes] | None:
    """Parse a raw UDP punch-ack datagram. Returns (node_id, nonce, signature) or None."""
    return _parse_punch_frame(data, _PUNCH_ACK_MAGIC)


# ---------------------------------------------------------------------------
# FOUND_NODE entry codec
# pool_count(H) | [cert_len(H) | cert_bytes]*pool_count
#   | entry_count(B)
#   | [ node_id(20) | addr_count(B) | chain_len(B)
#       | [addr_len(H) | addr_bytes]*addr_count
#       | pool_index(H)*chain_len ]*entry_count
# ---------------------------------------------------------------------------

class _EntryPacker:
    """Packs NodeEntry records for a FOUND_NODE under a byte budget.

    Certificates are shared through a pool the entries index into. Chains
    overwhelmingly end on the same network root and a post-quantum certificate
    is ~7 KB, so repeating each chain per entry made the root alone half the
    packet — and pushed the answer past the packet cap (see
    ``_FOUND_NODE_MAX_BYTES``). Pooling also bounds how many signatures one
    hostile FOUND_NODE can make a receiver verify.
    """

    def __init__(self, budget: int) -> None:
        self._budget = budget
        self._pool: list[bytes] = []
        self._index: dict[bytes, int] = {}
        self._entries: list[bytes] = []
        # pool_count(H) + entry_count(B)
        self._used = _POOL_COUNT.size + 1

    def add(self, entry: NodeEntry) -> bool:
        """Append ``entry``; False (and nothing added) if it wouldn't fit."""
        if (len(self._entries) >= _ENTRY_COUNT_MAX
                or len(entry.cert_chain) > _ENTRY_CHAIN_MAX):
            return False
        addrs = entry.addresses[:_MAX_ADDRESSES]
        blob = _ENTRY_HEADER.pack(entry.node_id.raw, len(addrs),
                                  len(entry.cert_chain))
        for addr in addrs:
            b = addr.encode('utf-8')
            blob += _ADDR_LEN.pack(len(b)) + b
        added: list[bytes] = []
        cost = len(blob) + _POOL_INDEX.size * len(entry.cert_chain)
        # Serialised once each. `serialize()` rebuilds a ~7 kB blob every call,
        # and this ran it twice per certificate — the second time only to use it
        # as a dictionary key — for up to `_FIND_NODE_SCAN` candidates a query.
        raws = [cert.serialize() for cert in entry.cert_chain]
        for raw in raws:
            if raw not in self._index and raw not in added:
                if len(self._pool) + len(added) >= _ENTRY_POOL_MAX:
                    return False
                added.append(raw)
                cost += _CERT_LEN.size + len(raw)
        if self._used + cost > self._budget:
            return False
        for raw in added:
            self._index[raw] = len(self._pool)
            self._pool.append(raw)
        for raw in raws:
            blob += _POOL_INDEX.pack(self._index[raw])
        self._entries.append(blob)
        self._used += cost
        return True

    def encode(self) -> bytes:
        pool = _POOL_COUNT.pack(len(self._pool))
        for raw in self._pool:
            pool += _CERT_LEN.pack(len(raw)) + raw
        return pool + bytes([len(self._entries)]) + b"".join(self._entries)


def _encode_entries(entries: list[NodeEntry]) -> bytes:
    packer = _EntryPacker(1 << 30)
    for entry in entries:
        packer.add(entry)
    return packer.encode()


def _decode_entries(data: bytes) -> list[NodeEntry]:
    if len(data) < _POOL_COUNT.size:
        raise ValueError("empty payload")
    pool_count = _POOL_COUNT.unpack_from(data, 0)[0]
    if pool_count > _ENTRY_POOL_MAX:
        raise ValueError(f"too many pooled certs: {pool_count}")
    offset = _POOL_COUNT.size
    pool: list[Certificate | None] = []
    for _ in range(pool_count):
        if offset + _CERT_LEN.size > len(data):
            raise ValueError("truncated pooled cert length")
        cert_len = _CERT_LEN.unpack_from(data, offset)[0]
        offset += _CERT_LEN.size
        if offset + cert_len > len(data):
            raise ValueError("truncated pooled cert")
        try:
            pool.append(Certificate.deserialize(data[offset:offset + cert_len]))
        except Exception:
            pool.append(None)   # unusable cert: entries referencing it lose their chain
        offset += cert_len
    if offset >= len(data):
        raise ValueError("missing entry count")
    count = data[offset]
    offset += 1
    if count > _ENTRY_COUNT_MAX:
        raise ValueError(f"too many entries: {count}")
    entries: list[NodeEntry] = []
    for _ in range(count):
        if offset + _ENTRY_HEADER.size > len(data):
            raise ValueError("truncated entry header")
        raw_id, addr_count, chain_len = _ENTRY_HEADER.unpack_from(data, offset)
        offset += _ENTRY_HEADER.size
        if addr_count > _MAX_ADDRESSES:
            raise ValueError(f"too many addresses in entry: {addr_count}")
        if chain_len > _ENTRY_CHAIN_MAX:
            raise ValueError(f"chain too long in entry: {chain_len}")
        addresses: list[str] = []
        valid = True
        for _ in range(addr_count):
            if offset + 2 > len(data):
                raise ValueError("truncated addr_len in entry")
            addr_len = _ADDR_LEN.unpack_from(data, offset)[0]
            offset += 2
            if addr_len > _MAX_URI_LEN:
                valid = False
            if offset + addr_len > len(data):
                raise ValueError("truncated addr_bytes in entry")
            try:
                addr = data[offset:offset + addr_len].decode('utf-8')
            except UnicodeDecodeError:
                valid = False
                addr = ""
            offset += addr_len
            if _validate_uri(addr) is None:
                valid = False
            addresses.append(addr)
        chain: list[Certificate] = []
        chain_ok = True
        for _ in range(chain_len):
            if offset + _POOL_INDEX.size > len(data):
                raise ValueError("truncated chain index in entry")
            idx = _POOL_INDEX.unpack_from(data, offset)[0]
            offset += _POOL_INDEX.size
            if idx >= len(pool):
                raise ValueError("chain index out of range")
            cert = pool[idx]
            if cert is None:
                chain_ok = False   # one unusable cert voids the whole chain
            elif chain_ok:
                chain.append(cert)
        if not chain_ok:
            chain = []
        if not valid:
            continue  # drop entry with any malformed URI
        entries.append(NodeEntry(NodeID(raw_id), addresses, b"", chain))
    return entries


# ---------------------------------------------------------------------------
# Peer state
# ---------------------------------------------------------------------------

class _Peer:

    def __init__(self, transport: BaseTransport, is_client_side: bool = False) -> None:
        self.transport = transport
        self.session: SessionKey | None = None
        self.pending_kem_secret: bytes | None = None
        self.join_code: str | None = None
        self.pending_challenge: bytes | None = None
        self.received_challenge: bytes | None = None
        self.authenticated_id: NodeID | None = None
        self.invite_accepted: bool = False
        self.invite_sent: bool = False
        # We presented an invitation code on THIS link and it was accepted.
        # Only then may the answer's issued certificate make its self-signed
        # root a root of ours: the alternative — believing whoever we happen to
        # have dialled — is a trust anchor anybody we contact can plant. See
        # `_handle_handshake_ack`, and Docs/Architecture/security.md.
        self.joined_by_invite: bool = False
        self.is_client_side: bool = is_client_side
        # A link used only to relay for others (SEEK / RELAY_CARRY) — we do not
        # try to authenticate to it, so its unsolicited CHALLENGE is ignored.
        self.relay_only: bool = False
        self.remote_addr: str | None = None   # dialled URI, for routing/reconnect
        self._invite_failures: int = 0
        self._invite_lockout_ts: float = 0.0
        # Handshakes this link has been allowed to make us verify. A joiner
        # legitimately needs more than one (the invite exchange re-drives it,
        # and a lost packet is retried), but not without end: the work is a
        # post-quantum verification per certificate plus one for the handshake
        # itself, and nothing above this handler is authenticated.
        self._handshake_attempts: int = 0
        self.dsa_pub: bytes = b""
        self._malformed: int = 0
        # Liveness / round-trip: set when we PING, cleared+measured on the PONG.
        self.ping_sent_at: float | None = None
        self.last_rtt: float | None = None
        self.quality = LinkQuality()  # latency spread and probe loss
        self.connected_at: float = time.monotonic()
        self.counters = Counters()   # per-link throughput
        self.total = None            # node-wide Counters, set by the node
        # Node-wide Trace, set by the node alongside `total`. None (or disabled)
        # costs one attribute test per packet, which is the point: this sits on
        # the hot path of every packet in and out.
        self.trace = None
        # Invoked when the receive loop exits on its own (dead link or abuse),
        # so the node can prune this peer. Cleared on intentional stop().
        self.on_dead = None
        self._task: asyncio.Task | None = None

    async def start(self, on_packet) -> None:
        self._task = asyncio.create_task(self._run(on_packet))

    async def _run(self, on_packet) -> None:
        try:
            await self._loop(on_packet)
        finally:
            cb = self.on_dead
            if cb is not None:
                self.on_dead = None
                try:
                    await cb(self)
                except Exception:
                    pass

    async def _loop(self, on_packet) -> None:
        while True:
            try:
                packet = await self.transport.receive()
            except asyncio.CancelledError:
                raise
            except (asyncio.IncompleteReadError, ConnectionError, OSError, EOFError):
                return  # link is dead — exit so the node reaps this peer
            except Exception:
                # Malformed frame on a still-live link (e.g. bad length prefix,
                # oversized payload). One bad packet must never kill the link:
                # drop it, count the abuse, and keep serving. Persistent garbage
                # is treated as hostile and the peer is cut.
                if self.note_abuse():
                    return
                continue
            nbytes = _HEADER_BYTES + len(packet.payload)
            self.counters.on_in(nbytes)
            if self.total is not None:
                self.total.on_in(nbytes)
            if self.trace is not None:
                self.trace.record("in", packet, nbytes, self.authenticated_id)
            try:
                await on_packet(self, packet)
            except asyncio.CancelledError:
                raise
            except Exception:
                pass  # malformed payload or handler bug — drop, loop continues

    def note_handshake_attempt(self) -> bool:
        """Claim one handshake attempt on this link. False once they run out."""
        self._handshake_attempts += 1
        return self._handshake_attempts <= _MAX_HANDSHAKE_ATTEMPTS

    def note_abuse(self) -> bool:
        """Count one thing this peer did that a correct node never does, and say
        whether it has now earned being cut.

        The receive loop counts frames it could not even decode; handlers count
        what decoded but was a lie — a claim signed by nobody, a name in a form
        the protocol forbids. Both are the same judgement ("this peer is not
        playing the protocol") so both feed the same counter, and the console
        shows it under one heading."""
        self._malformed += 1
        return self._malformed > _MAX_MALFORMED

    async def send(self, packet: Packet) -> None:
        await self.transport.send(packet)
        nbytes = _HEADER_BYTES + len(packet.payload)
        self.counters.on_out(nbytes)
        if self.total is not None:
            self.total.on_out(nbytes)
        if self.trace is not None:
            self.trace.record("out", packet, nbytes, self.authenticated_id)

    async def stop(self) -> None:
        self.on_dead = None  # intentional shutdown — do not trigger reaping
        if self._task:
            self._task.cancel()
            # Bounded. A cancelled receive task normally dies at once, but when
            # the cancellation lands on a read future that was already cancelled
            # the task is left flagged "cancelling", waiting for a wake-up that
            # never comes — and stop() waited with it, forever (seen roughly one
            # teardown in three with several peers). Closing the transport below
            # tears the link down regardless, so give up waiting and finish.
            try:
                async with asyncio.timeout(_PEER_STOP_TIMEOUT):
                    await self._task
            except (asyncio.CancelledError, TimeoutError, Exception):
                pass
        await self.transport.close()


# ---------------------------------------------------------------------------
# Relayed transport — a virtual link tunnelled through a relay
# ---------------------------------------------------------------------------

class RelayedTransport(BaseTransport):
    """A BaseTransport that carries mesh packets to a *remote* node through a
    *relay* link, by wrapping each outgoing packet in a RELAY_CARRY and letting
    the relay route it. Incoming packets are fed by the node when a RELAY_CARRY
    addressed to us and originating from ``remote`` is unwrapped.

    This lets the entire existing invite/handshake run, unchanged, between two
    nodes that share no direct link — the relay only sees signed ciphertext."""

    def __init__(self, node: 'MeshNode', remote: NodeID, via: '_Peer') -> None:
        super().__init__()
        self._node = node
        self._remote = remote
        self._via = via
        # Bounded: `feed` is reached from `_handle_relay_carry`, which runs
        # *before* the authentication gates, so an unauthenticated peer that
        # knows the seeker's id can push into this. A relayed handshake is a
        # handful of packets; anything past that is not a handshake.
        self._queue: asyncio.Queue = asyncio.Queue(_RELAY_QUEUE_MAX)
        self._closed = False

    async def connect(self, address: str) -> None:  # never dialled directly
        ...

    async def listen(self, address: str) -> None:
        ...

    async def send(self, packet: Packet) -> None:
        if self._closed:
            raise ConnectionError("relayed transport closed")
        carrier = Packet.create(RELAY_CARRY, self._node.id.raw,
                                self._remote.raw, packet.pack(), ttl=_SEEK_TTL)
        await self._via.send(carrier)

    def feed(self, inner: Packet) -> None:
        if self._closed:
            return
        try:
            self._queue.put_nowait(inner)
        except asyncio.QueueFull:
            pass       # the tunnel is not a buffer — drop, the join retries

    async def receive(self) -> Packet:
        while True:
            if self._closed:
                raise ConnectionError("relayed transport closed")
            # asyncio.timeout, not wait_for: on a path that must stay
            # cancellable, wait_for can swallow the outer cancellation when the
            # inner get completes in the same loop step, and the receive task
            # then never dies (gotchas.md §3b).
            try:
                async with asyncio.timeout(1.0):
                    return await self._queue.get()
            except asyncio.TimeoutError:
                continue

    def remote_ip(self) -> str | None:
        return None

    async def close(self) -> None:
        self._closed = True


# ---------------------------------------------------------------------------
# Hole-punching state
# ---------------------------------------------------------------------------

class _PunchState:
    """Tracks an in-progress NAT hole-punch attempt."""

    def __init__(self, target: NodeID, remote_udp_addr: str,
                 my_udp_addr: str) -> None:
        self.target = target
        self.remote_udp_addr = remote_udp_addr   # peer's public UDP addr (from relay)
        self.my_udp_addr = my_udp_addr           # our public UDP addr (observed by relay)
        self.probes_sent: int = 0
        self.probes_received: int = 0
        self.ack_received: bool = False
        self.deadline: float = 0.0
        self.completed: bool = False   # hole open, mesh handshake handed off
        self.nonce: bytes = os.urandom(16)
        self.peer_nonce: bytes | None = None



def _running_version() -> str:
    """The version this process is running.

    Read through the module rather than captured at import: a test (and an
    operator reading the console after an install) needs "what am I running"
    to be one lookup, not a constant copied at startup."""
    from .version import __version__
    return __version__

# ---------------------------------------------------------------------------
# MeshNode
# ---------------------------------------------------------------------------

class MeshNode:

    def __init__(self,
                 transport_manager: TransportManager,
                 identity_path: str | None = None,
                 cert_store_path: str | None = None,
                 session_store_path: str | None = None,
                 app_storage_path: str | None = None,
                 app_store_dir: str | None = None,
                 release_dir: str | None = None,
                 pseudo: str | None = None,
                 dht_max_bytes: int | None = None) -> None:
        if identity_path:
            self._identity = CryptoIdentity.load(identity_path)
            self._identity.save(identity_path)
        else:
            self._identity = CryptoIdentity()
        self._id = NodeID.from_public_key(self._identity.dsa_public_key)
        self._routing = RoutingTable(self._id)
        self._addresses: list[str] = []      # configured listen URIs (may be wildcard)
        self._local_ips: list[str] = []      # cached host addresses (for expansion)
        self._extra_addrs: list[str] = []    # externally-discovered (e.g. public IP)
        # Transports on which we have accepted an inbound authenticated
        # connection — passive, zero-cost proof of reachability (relay-capable).
        self._inbound_schemes: set[str] = set()
        # Relayed-invitation state (INVITE_SEEK). All bounded.
        self._rdv: OrderedDict[bytes, tuple] = OrderedDict()      # seeker_id -> (peer, exp)
        self._seek_rate: OrderedDict[bytes, tuple] = OrderedDict()  # _rate_key(peer) -> (count, window)
        self._pending_seeks: OrderedDict[bytes, dict] = OrderedDict()  # seeker_id -> record
        self._carry_rate: OrderedDict[bytes, tuple] = OrderedDict()     # _rate_key(peer) -> (count, window)
        self._relay_peers: dict[bytes, _Peer] = {}   # remote_id -> virtual peer (tunnelled)
        self._lan_discovery = None                    # LanDiscovery answerer (opt-in)
        self._reach_probe_rate: OrderedDict[bytes, tuple] = OrderedDict()  # _rate_key(peer)->(n,win)
        self._reach_dials_active = 0                   # concurrent dial-backs (bounded)
        # (peer id, scheme) -> expiry: probes we sent and are still willing to
        # believe an answer to. See _note_reach_probe.
        self._reach_pending: OrderedDict[tuple, float] = OrderedDict()
        self._running = False
        self._peers: list[_Peer] = []
        self._invite = InviteManager()
        self._cert_store_path = cert_store_path
        self._cert_store = (CertStore.load(cert_store_path, self._id)
                            if cert_store_path else CertStore(self._id))
        self._cert_store.add(self._identity.self_signed_cert())
        self._seen_msgs: OrderedDict[int, None] = OrderedDict()
        self._data_queue: asyncio.Queue[tuple[NodeID, bytes]] = asyncio.Queue(
            _MAX_DATA_QUEUE)
        self._e2e_sessions: dict[NodeID, SessionKey] = {}
        self._e2e_pending_kem: dict[NodeID, bytes] = {}
        self._e2e_pending_nonce: dict[NodeID, bytes] = {}
        self._e2e_pending_data: dict[NodeID, list[bytes]] = {}
        self._e2e_attempt: dict[NodeID, float] = {}   # target -> last handshake attempt (monotonic)
        # Responder-side re-key candidates: peer -> (candidate session, expiry).
        # Promoted only by a DATA packet that decrypts under the candidate.
        # Never persisted: a candidate is proof-of-completion awaited *now*;
        # across a restart the peer re-handshakes anyway.
        self._e2e_rekey: dict[NodeID, tuple[SessionKey, float]] = {}
        self._e2e_retry_task: asyncio.Task | None = None
        # Persisted state is written by one background task, not by whoever
        # happened to change it — see _persist_state.
        self._state_dirty: bool = False
        self._certs_dirty: bool = False
        self._state_task: asyncio.Task | None = None
        self._pending_connections: dict[NodeID, asyncio.Event] = {}
        self._pending_lookups: dict[NodeID, asyncio.Event] = {}
        self._pending_finds: dict[bytes, asyncio.Future] = {}
        # What this node caches for the network. Filled entirely by what peers
        # STORE, so it is memory given away — the operator decides how much
        # (`dht_max_mb`), and the default is what a small machine can lose.
        self._dht_store = (ContentStore(max_bytes=dht_max_bytes)
                           if dht_max_bytes else ContentStore())
        self._pending_values: dict[bytes, asyncio.Future] = {}
        # Per-app local secure store ("drawers"). Encryption keys derive from the
        # identity; persistence is opt-in (RAM-only without a path).
        from .app_storage import AppStorage
        self._app_storage = AppStorage(app_storage_path, self._identity)
        # App store: the network catalog (gossiped, in-memory) and the local
        # installed set (persisted). Rate-limit catalog gossip per ingress link.
        self._catalog = AppCatalog()
        installed_path = (os.path.join(app_store_dir, "installed.json")
                          if app_store_dir else None)
        apps_dir = os.path.join(app_store_dir, "apps") if app_store_dir else None
        self._installed = InstalledApps(installed_path, apps_dir)
        self._catalog_rate: OrderedDict[bytes, tuple] = OrderedDict()  # _rate_key(peer)->(n,win)
        # Mesh-native releases: what the network offers (gossiped, in-memory)
        # and whose signature this operator accepts (pinned, persisted). The
        # pins are the only thing that decides what may replace this node's own
        # code, so nothing arriving from the network writes to them.
        self._publishers = TrustedPublishers(
            os.path.join(release_dir, "publishers.json") if release_dir else None)
        self._releases = ReleaseCatalog()
        # The packages we hold and can serve, and who else said they hold one.
        self._packages = ReleaseStore(
            os.path.join(release_dir, "packages") if release_dir else None)
        self._release_sources: OrderedDict[str, list] = OrderedDict()
        self._pending_slices: dict[tuple, asyncio.Future] = {}
        self._release_rate: OrderedDict[bytes, tuple] = OrderedDict()
        self._release_serve_rate: OrderedDict[bytes, tuple] = OrderedDict()
        self._release_task: asyncio.Task | None = None
        self._release_tried: OrderedDict[bytes, str] = OrderedDict()
        self._release_log: list[dict] = []
        self._pending_echo: OrderedDict[bytes, tuple[NodeID, asyncio.Future]] = OrderedDict()
        # Pseudos: the changeable name beside the unchangeable id. One book
        # holds every claim we have verified — our own included — and answers
        # both "what is this node called?" and "who is called this?".
        self._pseudo_book = PseudoBook()
        self._pseudo = ""
        self._pseudo_claim: bytes | None = None
        self._pending_dir: dict[bytes, asyncio.Future] = {}   # query_id -> future
        self._dir_rate: OrderedDict[bytes, tuple] = OrderedDict()      # _rate_key(peer)->(n,win)
        self._pseudo_rate: OrderedDict[bytes, tuple] = OrderedDict()   # _rate_key(peer)->(n,win)
        self._detached: set = set()   # fire-and-forget tasks, bounded
        self._transport_manager = transport_manager
        self._metrics = NodeMetrics()
        # Off until an operator turns it on. Handed to every peer so the two
        # packet funnels (_Peer.send and _Peer._loop) can record without the
        # node having to know anything about tracing.
        self.trace = Trace()
        # Opt-in E2E session persistence (encrypted at rest). Off by default:
        # keys stay in RAM only. When enabled, resume prior sessions on start.
        self._session_store = None
        if session_store_path:
            from .session_store import SessionStore
            self._session_store = SessionStore(session_store_path, self._identity)
            restored = self._session_store.load()
            self._e2e_sessions.update(restored.e2e_sessions)
            self._e2e_pending_kem.update(restored.pending_kem)
            self._e2e_pending_nonce.update(restored.pending_nonce)
            self._e2e_pending_data.update(restored.pending_data)
            # Restore known peers so links can be rebuilt on demand after a
            # restart — re-authenticated via the persisted cert store, so no
            # re-invitation is needed.
            self._routing.import_entries(restored.routing)
        transport_manager.on_new_connection = self._on_new_transport
        # UDP hole-punching state
        self._udp_server: 'UDPServer | None' = None
        self._udp_listen_uri: str | None = None
        self._punch_pending: dict[NodeID, _PunchState] = {}
        self._punch_stats = {"attempted": 0, "completed": 0,
                             "failed": 0, "keepalives": 0}
        self._punch_enabled: bool = True   # hole punching on by default
        # Continuous mode: keep the UDP listener's NAT mapping open so the node
        # stays reachable (and can relay for others) even behind NAT. Opt-in.
        self._punch_keepalive: bool = False
        self._punch_keepalive_task: asyncio.Task | None = None
        # Periodic PING that keeps idle authenticated links from timing out.
        self._keepalive_task: asyncio.Task | None = None
        self._neighbor_task: asyncio.Task | None = None
        self._neighbor_wakeup = asyncio.Event()
        # Consecutive maintenance cycles that discovered nothing. Drives the
        # backoff, and tells the keepalive loop to stop nudging a search that
        # has nothing left to find.
        self._neighbor_idle_cycles = 0
        self._neighbor_retry: OrderedDict[NodeID, tuple[int, float]] = OrderedDict()
        # Candidate neighbours spotted in transit (node_id -> observation time).
        self._neighbor_watch: OrderedDict[NodeID, float] = OrderedDict()
        # Source node id -> (authenticated local first hop it reached us over,
        # observation time). Learned from inbound traffic only, so it records a
        # path that provably carried a packet; no remote relay identities are
        # inferred from this local observation.
        self._route_hints: OrderedDict[NodeID, tuple[NodeID, float]] = OrderedDict()
        # node hex -> {uri: {outcome, detail, at, ms}} — what each address did
        # last time it was dialled. Bounded on both axes.
        self._dial_log: OrderedDict[str, OrderedDict] = OrderedDict()
        self._retry_task: asyncio.Task | None = None
        self._steer_task: asyncio.Task | None = None
        # Moving a link to a lower-latency address is off unless someone asks
        # for it: it is a trade (a dial and a handshake against a few
        # milliseconds), and only the operator knows whether it is worth it.
        self._dynamic_address: bool = False
        # node hex -> {uri: measured at} — so a candidate that turned out no
        # better is not measured again on the next pass.
        self._steer_seen: OrderedDict[str, OrderedDict] = OrderedDict()
        self._transport_balance: int = _BALANCE_DEFAULT
        # Background route acquisitions started from a receive loop (bounded).
        self._deferred_routes: set = set()
        self._query_rate: OrderedDict[bytes, tuple] = OrderedDict()  # _rate_key(peer)->(n,win)
        self._store_rate: OrderedDict[bytes, tuple] = OrderedDict()
        self._punch_req_rate: OrderedDict[bytes, tuple] = OrderedDict()
        # Raw UDP punch datagrams, keyed by source address: they arrive with no
        # link, no session and no handshake, so there is no peer to key on.
        self._punch_dgram_rate: OrderedDict[bytes, tuple] = OrderedDict()
        self._last_announced: tuple[str, ...] | None = None
        self._announce_tasks: set = set()
        self._observed_udp_addr: tuple[str, int] | None = None  # from keepalive STUN
        # STUN transaction id -> (server ip, expiry). Requests we sent and are
        # still willing to believe an answer to. See _note_stun_request.
        self._stun_pending: OrderedDict[bytes, tuple] = OrderedDict()
        # Manual hole-punch targets → {"sent": int, "started": float, "task": Task}
        self._manual_holes: OrderedDict[tuple[str, int], dict] = OrderedDict()
        self._stun_enabled: bool = False
        # Per-target cooldown for relayed→direct path upgrade attempts
        self._upgrade_last: OrderedDict[NodeID, float] = OrderedDict()
        # Invite-block join state (driven from the console)
        self._join_task: asyncio.Task | None = None
        self._join_status: dict | None = None
        self._join_try_timeout: float = _JOIN_TRY_TIMEOUT
        self._relay_join_timeout: float = _RELAY_JOIN_TIMEOUT
        # Keeps local/public addressing fresh (created on start(), needs a loop)
        self._net_monitor: NetMonitor | None = None
        if pseudo:
            # Raises on a name that cannot be one, rather than quietly running
            # unnamed: the configuration layer validates first (see
            # ``config.SETTINGS``), so reaching here with a bad one is a caller
            # bug and deserves to be visible.
            self.set_pseudo(pseudo)

    @property
    def id(self) -> NodeID:
        return self._id

    @property
    def session(self) -> SessionKey | None:
        return next((p.session for p in self._peers if p.session is not None), None)

    def generate_invite(self, ttl_seconds: float | None = None) -> str:
        """Issue an invitation code. ``ttl_seconds`` widens the window (bounded
        by `invite._MAX_TTL`) for invitations that are not typed by hand —
        typically the one left on a machine being provisioned, which will not
        use it until the install is done."""
        return self._invite.generate_code(ttl_seconds)

    async def start(self, addresses: list[str]) -> None:
        self._running = True
        for uri in addresses:
            try:
                await self._transport_manager.listen(uri)
                self._addresses.append(uri)
            except Exception:
                pass
        self._local_ips = local_ip_addresses()
        # Background monitor: re-verifies local/public IPs on triggers
        # (interface change, suspend/resume, peer events) and periodically.
        if self._net_monitor is None:
            self._net_monitor = NetMonitor(
                probe_local_ips=local_ip_addresses,
                probe_public_ip=self.discover_public_ip,
                probe_stun=self._probe_stun_if_udp,
                on_change=self._on_network_change,
            )
            self._net_monitor.start()
        self._ensure_link_keepalive()
        self._ensure_e2e_retry()
        self._ensure_neighbor_maintenance()
        self._ensure_address_retry()
        self._ensure_address_steering()
        self._ensure_release_watch()
        self._announce_own_pseudo()   # peers that were already up learn our name

    def _on_network_change(self, status: dict, changes: dict) -> None:
        """Applied when the monitor sees our addressing move: refresh the
        addresses we advertise and drop a stale public IP."""
        if "local_ips" in changes:
            self._local_ips = list(status["local_ips"])
        if "public_ip" in changes:
            old, new = changes["public_ip"]
            if old in self._extra_addrs:
                self._extra_addrs.remove(old)
            if (new and new not in self._extra_addrs
                    and new not in self._local_ips
                    and len(self._extra_addrs) < _MAX_EXTRA_ADDRS):
                self._extra_addrs.append(new)
        self._announce_addresses_soon("network-change")

    def _poke_net(self, reason: str) -> None:
        if self._net_monitor is not None:
            self._net_monitor.poke(reason)

    async def _probe_stun_if_udp(self) -> tuple[str, int] | None:
        """STUN only makes sense (and is only worth the observable traffic)
        when a UDP listener is up for hole punching."""
        if self._udp_server is None:
            return None
        return await self.discover_public_udp_addr()

    async def add_listen(self, uri: str) -> None:
        """Start listening on another address at runtime (e.g. add a port)."""
        await self._transport_manager.listen(uri)
        if uri not in self._addresses:
            self._addresses.append(uri)
        self._running = True
        self._local_ips = local_ip_addresses()
        self._poke_net("listener-added")
        await self._announce_addresses("listener-added")

    async def remove_listen(self, uri: str) -> bool:
        """Stop listening on an address at runtime."""
        ok = await self._transport_manager.stop_listen(uri)
        if uri in self._addresses:
            self._addresses.remove(uri)
        if ok:
            await self._announce_addresses("listener-removed")
        return ok

    async def start_udp(self, port: int, host: str = "0.0.0.0") -> None:
        """Start a UDP listener for hole-punching and direct UDP links."""
        from .udp_transport import UDPServer
        uri = f"udp://{host}:{port}"
        if self._udp_server is not None:
            return  # already listening
        self._udp_server = UDPServer()
        self._udp_server.on_new_connection = self._on_new_transport
        self._udp_server.on_raw_datagram = self.handle_udp_datagram
        await self._udp_server.listen(f"{host}:{port}")
        self._udp_listen_uri = uri
        if uri not in self._addresses:
            self._addresses.append(uri)
        self._poke_net("udp-listener-added")
        # Resume continuous keepalive if it was requested while UDP was down.
        if self._punch_keepalive:
            self._start_punch_keepalive()

    async def stop_udp(self) -> None:
        """Stop the UDP listener."""
        await self._stop_punch_keepalive()
        self._cancel_manual_holes()
        self._observed_udp_addr = None
        if self._udp_server is None:
            return
        await self._udp_server.close()
        self._udp_server = None
        if self._udp_listen_uri and self._udp_listen_uri in self._addresses:
            self._addresses.remove(self._udp_listen_uri)
        self._udp_listen_uri = None

    # -- continuous hole-punch keepalive ------------------------------------

    def console_set_punch_keepalive(self, enabled: bool) -> bool:
        """Continuous mode: keep the UDP NAT mapping open so this node stays
        reachable behind NAT and can act as a relay. Requires a UDP listener
        and hole punching enabled to actually emit traffic."""
        self._punch_keepalive = bool(enabled)
        if self._punch_keepalive:
            self._start_punch_keepalive()
        else:
            asyncio.ensure_future(self._stop_punch_keepalive())
        return self._punch_keepalive

    def _start_punch_keepalive(self) -> None:
        if (self._punch_keepalive_task is None
                or self._punch_keepalive_task.done()):
            self._punch_keepalive_task = asyncio.create_task(
                self._punch_keepalive_loop())

    async def _stop_punch_keepalive(self) -> None:
        task = self._punch_keepalive_task
        self._punch_keepalive_task = None
        if task is not None:
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass

    async def _punch_keepalive_loop(self) -> None:
        """Refresh the listener's NAT mapping on a timer while continuous mode
        is on. Never raises out — a broken probe must not kill the loop."""
        while self._punch_keepalive and self._running:
            try:
                await self._send_nat_keepalive()
            except Exception:
                pass
            await asyncio.sleep(_PUNCH_KEEPALIVE_INTERVAL)

    async def _send_nat_keepalive(self) -> None:
        """Send a STUN Binding Request from the *listener* socket. The outbound
        packet keeps the NAT mapping alive; the response (dispatched back to
        handle_udp_datagram) tells us the listener's public reflexive address.

        Uses the listener socket itself — not a fresh socket like the net
        monitor — because only that socket's mapping is the one peers reach."""
        if not self._punch_enabled or self._udp_server is None:
            return
        sock = self._udp_server._sock
        if sock is None:
            return
        from .stun import _build_binding_request, DEFAULT_STUN_SERVERS
        from .ip_utils import bounded_getaddrinfo
        for host, port in DEFAULT_STUN_SERVERS:
            try:
                # Not `loop.getaddrinfo`: that runs on asyncio's default
                # executor, which is *joined* at shutdown, so a lookup that
                # hangs on a restricted network wedges interpreter exit
                # (gotchas §2). This was the one call site in the tree still
                # doing it.
                infos = await bounded_getaddrinfo(
                    host, port, family=socket.AF_INET, type=socket.SOCK_DGRAM)
            except (OSError, socket.gaierror, asyncio.TimeoutError):
                continue
            if not infos:
                continue
            request = _build_binding_request()
            try:
                sock.sendto(request, infos[0][4])
                self._punch_stats["keepalives"] += 1
            except (OSError, ConnectionError):
                continue
            # Remember what we asked, and who we asked. Without this the
            # response check compares the datagram's transaction id against
            # itself, so any datagram carrying the STUN magic cookie set our
            # believed public address — which we then advertise to the mesh.
            self._note_stun_request(request[8:20], infos[0][4][0])
            return  # one server is enough per interval

    def _note_stun_request(self, txn_id: bytes, server_ip: str) -> None:
        now = time.monotonic()
        for key in [k for k, (_, exp) in self._stun_pending.items() if exp <= now]:
            del self._stun_pending[key]
        while len(self._stun_pending) >= _STUN_PENDING_MAX:
            self._stun_pending.popitem(last=False)
        self._stun_pending[bytes(txn_id)] = (server_ip, now + _STUN_PENDING_TTL)

    def udp_port(self) -> int | None:
        """The port our UDP server is listening on, if any."""
        if self._udp_server is None or self._udp_server._sock is None:
            return None
        sock = self._udp_server._sock.get_extra_info("socket")
        if sock is None:
            return None
        try:
            return sock.getsockname()[1]
        except (OSError, IndexError):
            return None

    async def discover_public_udp_addr(self) -> tuple[str, int] | None:
        """Use STUN to discover our public UDP reflexive address (fallback)."""
        from .stun import discover_public_addr
        return await discover_public_addr()

    async def discover_public_ip(self) -> str | None:
        """Discover our public IP address via HTTP services (ip.me, etc.).

        The probe is blocking stdlib socket I/O (DNS + TLS connect), so it runs
        in a *daemon* thread we abandon on timeout — never blocking the event
        loop, and never joined at shutdown. A restricted network (CI, air-gapped)
        where DNS or egress hangs would otherwise either freeze the loop or wedge
        interpreter shutdown on the executor join — the real cause of a node
        (or test run) that appears to hang forever. run_in_executor is unsafe
        here precisely because asyncio joins the default executor on shutdown.
        On success the IP is added to ``_extra_addrs`` so it appears in the
        advertised URIs for all transports.
        """
        loop = asyncio.get_running_loop()
        fut: asyncio.Future = loop.create_future()

        def _worker() -> None:
            try:
                result = self._blocking_public_ip_probe()
            except Exception:
                result = None
            if not loop.is_closed():
                loop.call_soon_threadsafe(
                    lambda: fut.done() or fut.set_result(result))

        threading.Thread(target=_worker, name="nmesh-pubip", daemon=True).start()
        try:
            ip = await asyncio.wait_for(fut, timeout=_PUBLIC_IP_TIMEOUT)
        except (asyncio.TimeoutError, Exception):
            return None
        if ip and _is_ip_address(ip):
            if ip not in self._local_ips and ip not in self._extra_addrs:
                if len(self._extra_addrs) < _MAX_EXTRA_ADDRS:
                    self._extra_addrs.append(ip)
            return ip
        return None

    def _blocking_public_ip_probe(self) -> str | None:
        """Synchronous public-IP probe — always called inside an executor.

        Each service gets a per-socket timeout AND we cap the DNS lookup, so a
        single stuck host can't consume the whole overall budget."""
        import http.client
        services = [
            ("ip.me", "/"),
            ("ifconfig.me", "/"),
            ("icanhazip.com", "/"),
        ]
        for host, path in services:
            try:
                # Force IPv4: resolve A record only, connect on AF_INET
                infos = socket.getaddrinfo(
                    host, 443, socket.AF_INET, socket.SOCK_STREAM)
                if not infos:
                    continue
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                ctx = ssl.create_default_context()
                sock = ctx.wrap_socket(sock, server_hostname=host)
                sock.connect(infos[0][4])
                conn = http.client.HTTPSConnection(host, timeout=3)
                conn.sock = sock
                try:
                    conn.request("GET", path, headers={"User-Agent": "curl/8"})
                    resp = conn.getresponse()
                    ip = resp.read().decode("ascii").strip()
                finally:
                    conn.close()
                if _is_ip_address(ip):
                    return ip
            except Exception:
                continue
        return None

    async def request_hole_punch(self, relay_peer: '_Peer',
                                  target: NodeID) -> None:
        """Request a relay to coordinate a UDP hole punch to *target*.

        Sends PUNCH_REQUEST to the relay peer (over the existing TCP link).
        The relay will respond with PUNCH_RELAY to both us and the target,
        after which both sides send UDP probes simultaneously.
        """
        if not self._punch_enabled:
            return
        if relay_peer.authenticated_id is None or relay_peer.session is None:
            return
        if len(self._punch_pending) >= _PUNCH_MAX_PENDING:
            return
        udp_port = self.udp_port()
        if udp_port is None:
            return  # no UDP listener — can't punch
        payload = _encode_punch_request(target.raw, udp_port)
        pkt = Packet.create(PUNCH_REQUEST, self._id.raw,
                            relay_peer.authenticated_id.raw, payload)
        await relay_peer.send(pkt)

    def advertised_uris(self) -> list[str]:
        """Concrete, connectable URIs a peer can reach us at — each configured
        listen URI expanded over the host's addresses (and any discovered
        external address). Wildcards like 0.0.0.0 become one URI per address."""
        out: list[str] = []
        seen: set[str] = set()
        for uri in self._addresses:
            for u in expand_listen_uri(uri, self._local_ips, self._extra_addrs):
                if u not in seen:
                    seen.add(u)
                    out.append(u)
        return out

    async def join(self, address: str, code: str) -> '_Peer':
        transport = await self._connect_for_join(address)
        peer = _Peer(transport, is_client_side=True)
        peer.on_dead = self._reap_peer
        peer.total = self._metrics.total
        peer.trace = self.trace
        peer.remote_addr = address
        peer.join_code = code
        self._peers.append(peer)
        self._running = True
        self._ensure_link_keepalive()
        self._ensure_e2e_retry()
        await peer.start(self._handle_packet)
        return peer

    async def _connect_for_join(self, address: str) -> BaseTransport:
        """Open a transport for a join. A ``udp://`` target reuses the shared
        listener socket (not a fresh one) so it traverses any NAT hole already
        opened toward the peer — the whole point of manual hole punching. Other
        schemes go through the normal transport manager."""
        parsed = _validate_uri(address)
        if (parsed is not None and parsed[0] == "udp"
                and self._udp_server is not None
                and self._udp_server._sock is not None):
            hp = split_host_port(parsed[1])
            if hp is not None:
                try:
                    host, port = hp[0], int(hp[1])
                except ValueError:
                    host = None
                if host is not None and 0 < port < 65536:
                    return self._udp_listener_transport(host, port)
        return await self._transport_manager.connect(address)

    def _udp_listener_transport(self, host: str, port: int) -> BaseTransport:
        """Create a UDP transport bound to (host, port) on the *listener* socket
        and register it so the peer's replies route to it. Sends an initial
        keepalive burst to open our mapping and prod the peer to accept."""
        from .udp_transport import UDPTransport
        addr = (host, port)
        transport = UDPTransport._from_server(self._udp_server._sock, addr,
                                              self._udp_server)
        self._udp_server._transports[addr] = transport
        transport._start_tasks()
        asyncio.create_task(self._udp_join_bridge(transport))
        return transport

    async def _udp_join_bridge(self, transport) -> None:
        """Send a short burst of keepalives so the peer accepts even if the two
        operators didn't open their holes at exactly the same instant."""
        for _ in range(10):
            if transport._closed:
                return
            try:
                transport._send_raw(transport._link.build_keepalive())
            except Exception:
                return
            await asyncio.sleep(0.5)

    def console_open_hole(self, host: str, port: int,
                          duration: float = _HOLE_OPEN_DEFAULT) -> dict:
        """Manually punch a NAT hole toward a peer's public UDP endpoint.

        No relay: two operators exchange their public UDP addresses out of
        band, each opens a hole toward the other, then one joins. This side
        only opens *our* mapping — the peer must do the same. Datagrams keep
        flowing at a low cadence for ``duration`` seconds (or until a link to
        the endpoint appears) so the hole survives the copy-paste round-trip."""
        if self._udp_server is None:
            raise ValueError("start UDP first")
        if not isinstance(host, str) or not _is_ip_address(host):
            raise ValueError("invalid IP address — expected ip:port")
        if not isinstance(port, int) or not (0 < port < 65536):
            raise ValueError("invalid port")
        key = (host, port)
        existing = self._manual_holes.pop(key, None)
        if existing is not None and not existing["task"].done():
            existing["task"].cancel()
        while len(self._manual_holes) >= _MANUAL_HOLE_MAX:
            _, old = self._manual_holes.popitem(last=False)
            if not old["task"].done():
                old["task"].cancel()
        deadline = time.monotonic() + max(0.0, float(duration))
        task = asyncio.create_task(self._open_hole_task(host, port, deadline))
        self._manual_holes[key] = {"sent": 0, "started": time.monotonic(),
                                   "task": task}
        return {"host": host, "port": port}

    async def _open_hole_task(self, host: str, port: int, deadline: float) -> None:
        """Keep a NAT hole open by sending hole-open datagrams from the listener
        socket until the deadline — or until a transport to this endpoint
        exists (the connection is happening). The receiver ignores them; they
        only open *our* mapping."""
        key = (host, port)
        while time.monotonic() < deadline:
            server = self._udp_server
            if server is None or server._sock is None:
                break
            if key in server._transports:
                break  # a link to this endpoint is forming — stop opening
            try:
                server._sock.sendto(_HOLE_OPEN_MAGIC, (host, port))
            except (OSError, ConnectionError):
                break
            entry = self._manual_holes.get(key)
            if entry is not None:
                entry["sent"] += 1
            await asyncio.sleep(_HOLE_OPEN_INTERVAL)

    def _cancel_manual_holes(self) -> None:
        for entry in self._manual_holes.values():
            if not entry["task"].done():
                entry["task"].cancel()
        self._manual_holes.clear()

    async def stop(self) -> None:
        self._running = False
        self._persist_state()
        # Cancel any in-flight address-gossip tasks before tearing down links.
        tasks = list(self._announce_tasks)
        self._announce_tasks.clear()
        for t in tasks:
            t.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        await self._stop_link_keepalive()
        await self._stop_e2e_retry()
        await self._stop_neighbor_maintenance()
        await self._stop_address_retry()
        await self._stop_address_steering()
        await self._stop_release_watch()
        await self._stop_deferred_routes()
        await self._stop_state_writer()
        # Concurrently: each peer.stop() is individually bounded, and stopping
        # 128 links one after another would stack those bounds into minutes.
        await asyncio.gather(*(peer.stop() for peer in list(self._peers)),
                             return_exceptions=True)
        self._peers.clear()
        await self._transport_manager.close_all()
        await self._stop_punch_keepalive()
        self._cancel_manual_holes()
        await self.stop_lan_discovery()
        if self._udp_server is not None:
            await self._udp_server.close()
            self._udp_server = None
        self._punch_pending.clear()
        if self._net_monitor is not None:
            await self._net_monitor.stop()
            self._net_monitor = None

    async def wait_for_session(self, timeout: float = 10.0) -> None:
        deadline = asyncio.get_event_loop().time() + timeout
        while not any(p.session is not None for p in self._peers):
            if asyncio.get_event_loop().time() >= deadline:
                raise TimeoutError("session not established in time")
            await asyncio.sleep(0.05)

    async def send_data(self, target: NodeID, payload: bytes) -> None:
        if target == self._id:
            raise ValueError("cannot send to self")
        if target not in self._e2e_sessions:
            pending = self._e2e_pending_data
            # Cap half-open destinations so an app flooding unreachable targets
            # can't exhaust memory; evict the oldest destination if needed.
            if target not in pending and len(pending) >= _MAX_PENDING_TARGETS:
                self._forget_e2e(next(iter(pending)))
            queue = pending.setdefault(target, [])
            queue.append(payload)
            if len(queue) > _MAX_PENDING_PER_TARGET:
                del queue[0]  # drop oldest — bounded backlog per target
            if self._should_initiate_e2e(target):
                await self._initiate_e2e_handshake(target)
            self._persist_state()
            return
        session = self._e2e_sessions[target]
        packet = Packet.create_encrypted(DATA, self._id.raw, target.raw, payload, session)
        await self._route_outbound(packet)

    async def receive_data(self) -> tuple[NodeID, bytes]:
        return await self._data_queue.get()

    async def ping(self, peer: _Peer) -> None:
        payload = _encode_addresses(self.advertised_uris())
        packet = Packet.create(PING, self._id.raw, NodeID(b"\xff" * 20).raw, payload)
        peer.ping_sent_at = time.monotonic()   # for RTT measurement on the PONG
        peer.quality.on_ping()
        await peer.send(packet)

    def _recent_authed_peers(self, limit: int) -> list['_Peer']:
        peers = [p for p in self._peers
                 if p.authenticated_id is not None and p.session is not None]
        def seen(p):
            e = self._routing.get(p.authenticated_id)
            return e.last_seen if e is not None else 0.0
        peers.sort(key=seen, reverse=True)
        return peers[:limit]

    async def _announce_addresses(self, reason: str) -> None:
        """Push our advertised address set to the most-recently-seen peers when
        it changes (targeted Kademlia-style gossip). A PING already carries
        advertised_uris. Skips an unchanged set (no storm); never raises."""
        current = tuple(self.advertised_uris())
        if current == self._last_announced:
            return
        self._last_announced = current
        for peer in self._recent_authed_peers(_ANNOUNCE_FANOUT):
            try:
                await self.ping(peer)
            except Exception:
                pass

    def _announce_addresses_soon(self, reason: str) -> None:
        """Fire-and-forget address announce for sync contexts (the network-change
        callback). The task is tracked so stop() can cancel it — an untracked
        announce awaiting a PING write would otherwise wedge teardown."""
        if not self._running:
            return
        task = asyncio.ensure_future(self._announce_addresses(reason))
        self._announce_tasks.add(task)
        task.add_done_callback(self._announce_tasks.discard)

    async def console_ping_peers(self) -> dict:
        """Console action: PING every authenticated peer now (refreshes RTT and
        liveness). Returns how many pings were sent; per-peer RTT surfaces in the
        next snapshot."""
        sent = 0
        for peer in list(self._peers):
            if peer.authenticated_id is None or peer.session is None:
                continue
            try:
                await self.ping(peer)
                sent += 1
            except Exception:
                pass
        return {"sent": sent}

    async def console_ping_node(self, node_id_hex: str) -> dict:
        """Console action: ping one known node by id and measure the round-trip.

        If it isn't a direct peer, establish a link on demand first (bounded).
        Returns reachability + RTT so the console can show liveness per node."""
        try:
            nid = NodeID(bytes.fromhex(node_id_hex))
        except (ValueError, TypeError):
            return {"ok": False, "error": "bad id"}
        if nid == self._id:
            return {"ok": False, "error": "self"}
        peer = next((p for p in self._peers
                     if p.authenticated_id == nid and p.session is not None), None)
        if peer is not None:
            await self.ping(peer)
            deadline = time.monotonic() + _DIRECT_PING_TIMEOUT
            while peer.ping_sent_at is not None and time.monotonic() < deadline:
                await asyncio.sleep(0.02)
            if peer.ping_sent_at is None:
                # PONG received inside the window — the link provably works.
                rtt = (round(peer.last_rtt * 1000, 1)
                       if peer.last_rtt is not None else None)
                return {"ok": True, "reachable": True, "rtt_ms": rtt, "via": "direct"}
            # No PONG: the direct link is suspect (half-dead punched link, or a
            # peer that never answers PINGs). Don't claim reachability on
            # suspicion — fall through to the routed ECHO probe, which always
            # gets a reply from a live node wherever the answer comes from.
        # Not a direct peer: probe over the mesh (multi-hop, relayed) rather than
        # only trying to form a direct link. This is what makes reaching a node by
        # id work when it's only reachable through a relay (remote / behind NAT).
        rtt = await self._routed_ping(nid)
        if rtt is None:
            # Last resort: try to form a direct/punched link, then ping it.
            peer = await self._ensure_route_to(nid)
            if peer is not None and peer.authenticated_id == nid and peer.session is not None:
                rtt = await self._routed_ping(nid)
        if rtt is None:
            return {"ok": True, "reachable": False}
        return {"ok": True, "reachable": True, "rtt_ms": rtt, "via": "route"}

    async def console_forget_node(self, node_id_hex: str) -> bool:
        """Console action: forget a known node — drop its routing-table (address
        book) entry and any E2E/session state, and close a live link to it if one
        exists. Persists so the deletion survives restart.

        Not a permanent ban: gossip/PONG merge (any authenticated contact) and
        neighbour maintenance can re-learn the node later if it's still
        reachable — see gotchas.md."""
        try:
            nid = NodeID(bytes.fromhex(node_id_hex))
        except (ValueError, TypeError):
            return False
        if nid == self._id:
            return False
        existed = self._routing.contains(nid)
        self._routing.remove(nid)
        self._e2e_sessions.pop(nid, None)
        self._e2e_pending_kem.pop(nid, None)
        self._e2e_pending_nonce.pop(nid, None)
        self._e2e_pending_data.pop(nid, None)
        self._route_hints.pop(nid, None)
        for peer in list(self._peers):
            if peer.authenticated_id == nid:
                existed = True
                try:
                    await peer.stop()
                except Exception:
                    pass
                if peer in self._peers:
                    self._peers.remove(peer)
        self._persist_state()
        return existed

    async def _routed_ping(self, target: NodeID, timeout: float = 5.0) -> float | None:
        """Liveness probe that travels the mesh multi-hop: an ECHO_REQUEST routed
        to ``target`` (forwarded hop by hop, across any transport), which replies
        with an ECHO_REPLY routed back. Returns the round-trip in ms, or None."""
        qid = os.urandom(_QID_LEN)
        fut: asyncio.Future = asyncio.get_event_loop().create_future()
        while len(self._pending_echo) >= 128:
            _, (_, old) = self._pending_echo.popitem(last=False)
            if not old.done():
                old.cancel()
        self._pending_echo[qid] = (target, fut)
        t0 = time.monotonic()
        try:
            await self._route_outbound(
                Packet.create(ECHO_REQUEST, self._id.raw, target.raw, qid))
            await asyncio.wait_for(asyncio.shield(fut), timeout)
            return round((time.monotonic() - t0) * 1000, 1)
        except Exception:
            self._forget_route_hint(target)   # unanswered — re-pick next time
            return None
        finally:
            self._pending_echo.pop(qid, None)
            if not fut.done():
                fut.cancel()

    async def _handle_echo_request(self, peer: _Peer, packet: Packet) -> None:
        # Delivered here because dst==self (forwarding routed it to us). Reply
        # routed back to the origin so the round-trip crosses the same mesh path.
        if len(packet.payload) != _QID_LEN:
            return
        await self._route_outbound(
            Packet.create(ECHO_REPLY, self._id.raw, packet.src_id, packet.payload),
            blocking=False)   # we are in a receive loop — never acquire inline

    async def _handle_echo_reply(self, peer: _Peer, packet: Packet) -> None:
        if len(packet.payload) != _QID_LEN:
            return
        pending = self._pending_echo.get(packet.payload)
        if pending is None:
            return
        target, fut = pending
        if packet.src_id != target.raw or packet.dst_id != self._id.raw:
            return
        self._pending_echo.pop(packet.payload, None)
        if not fut.done():
            fut.set_result(True)

    def _ensure_link_keepalive(self) -> None:
        """Start the link-keepalive loop if it isn't already running."""
        if self._keepalive_task is None or self._keepalive_task.done():
            self._keepalive_task = asyncio.create_task(self._link_keepalive_loop())

    async def _link_keepalive_loop(self) -> None:
        """Ping every established peer on an interval so a healthy but idle link
        isn't torn down by the transport's read timeout. Both sides run this, so
        each link sees inbound traffic in both directions. Never raises: a link
        that is genuinely dead is reaped by its own receive loop.

        The maintained set (`_neighbor_slots`) is pinged first: those are the
        links the node commits to, so they must never be the ones starved by a
        slow or dead peer earlier in the list. Dropping below the floor puts
        maintenance back into its searching regime immediately."""
        while self._running:
            await asyncio.sleep(_LINK_KEEPALIVE_INTERVAL)
            slots = self._neighbor_slots()
            peers = sorted(self._peers,
                           key=lambda p: 0 if p.authenticated_id in slots else 1)
            for peer in peers:
                if peer.authenticated_id is None or peer.session is None:
                    continue
                try:
                    await self.ping(peer)
                except Exception:
                    pass
            # Only nudge maintenance while it is still finding things. A mesh
            # smaller than the floor is below it permanently, and nudging every
            # keepalive there means a certificate-carrying lookup every 20 s
            # that can only ever learn what we already know. Real events (a peer
            # lost or gained, an identity we had not seen) wake the loop
            # directly and reset its backoff, so nothing is missed by staying
            # quiet here.
            if (len(self._live_neighbors()) < _NEIGHBOR_FLOOR
                    and self._neighbor_idle_cycles == 0):
                self._wake_neighbor_maintenance()

    async def _stop_link_keepalive(self) -> None:
        task = self._keepalive_task
        self._keepalive_task = None
        if task is not None:
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass

    def _authenticated_peers(self, *, exclude: _Peer | None = None) -> list[_Peer]:
        """Return one live authenticated link per identity."""
        seen: set[NodeID] = set()
        out: list[_Peer] = []
        for peer in self._peers:
            if (peer is exclude or peer.authenticated_id is None
                    or peer.session is None or peer.authenticated_id in seen):
                continue
            seen.add(peer.authenticated_id)
            out.append(peer)
        return out

    def _live_neighbors(self) -> list[NodeID]:
        """Identities we hold a live authenticated link with, nearest first."""
        ids = [p.authenticated_id for p in self._authenticated_peers()
               if p.authenticated_id is not None]
        ids.sort(key=self._id.distance)
        return ids

    def _neighbor_slots(self) -> list[NodeID]:
        """The maintained set: the `_NEIGHBOR_FLOOR` XOR-nearest live links.

        These are the links the node insists on: they get the keepalive first
        and losing one puts maintenance back into its searching regime.
        """
        return self._live_neighbors()[:_NEIGHBOR_FLOOR]

    def _neighbor_cutoff(self) -> int | None:
        """Distance of the least interesting maintained slot, or None while the
        set is not full — below the floor every identity is worth having."""
        slots = self._neighbor_slots()
        if len(slots) < _NEIGHBOR_FLOOR:
            return None
        return self._id.distance(slots[-1])

    def _note_neighbor_candidate(self, node_id: NodeID) -> None:
        """A packet from ``node_id`` just came through. Remember it when it is a
        better neighbour than the worst slot we maintain, so the next
        maintenance cycle dials it and it takes that slot.

        Deliberately does *not* wake maintenance: the loop already runs every
        `_NEIGHBOR_REFRESH`, and dialling on a packet's arrival would let anyone
        who picks a source id close to ours set our dialling pace. The src id of
        a routed packet is unauthenticated — it can only ever cost one
        backed-off dial to an identity that then has to prove itself in the
        handshake (NodeID = hash of its DSA key).
        """
        if node_id == self._id:
            return
        if any(p.authenticated_id == node_id and p.session is not None
               for p in self._peers):
            return
        cutoff = self._neighbor_cutoff()
        if cutoff is not None and self._id.distance(node_id) >= cutoff:
            return
        self._neighbor_watch[node_id] = time.monotonic()
        self._neighbor_watch.move_to_end(node_id)
        while len(self._neighbor_watch) > _NEIGHBOR_WATCH_TRACKED:
            self._neighbor_watch.popitem(last=False)

    def _neighbor_promotions(self) -> list[NodeID]:
        """Watched candidates still worth dialling, nearest first. Entries that
        became live, or that a closer slot has since made uninteresting, are
        dropped here — the watch list never keeps stale work."""
        cutoff = self._neighbor_cutoff()
        live = set(self._live_neighbors())
        out: list[NodeID] = []
        for node_id in list(self._neighbor_watch):
            if node_id in live or (cutoff is not None
                                   and self._id.distance(node_id) >= cutoff):
                del self._neighbor_watch[node_id]
                continue
            out.append(node_id)
        out.sort(key=self._id.distance)
        return out[:_NEIGHBOR_TARGET]

    def _wake_neighbor_maintenance(self) -> None:
        """Something changed — look again soon, and from a clean backoff.

        Resetting here is the half that makes the backoff safe: it may grow to
        five minutes while nothing is happening, but any real event brings it
        straight back to the normal cadence."""
        if self._running:
            self._neighbor_idle_cycles = 0
            self._neighbor_wakeup.set()

    def _ensure_neighbor_maintenance(self) -> None:
        if self._neighbor_task is None or self._neighbor_task.done():
            self._neighbor_task = asyncio.create_task(
                self._neighbor_maintenance_loop())

    async def _stop_neighbor_maintenance(self) -> None:
        task = self._neighbor_task
        self._neighbor_task = None
        self._neighbor_wakeup.set()
        if task is not None:
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass

    async def _neighbor_maintenance_loop(self) -> None:
        """Recover an empty node and maintain its five XOR-nearest known links.

        Two bounds sit on this loop, and both exist because of the same failure:
        a cycle asks FIND_NODE, the answer wakes the loop, and the next cycle
        starts with no delay at all — a two-node mesh sat at ~3 Mbit/s of
        certificate chains doing nothing.

        `_NEIGHBOR_MIN_INTERVAL` is the floor a wake cannot go below. The
        backoff is for the other half: a mesh smaller than `_NEIGHBOR_FLOOR`
        can never reach it, so searching never ends on its own. Cycles that
        turn up nothing new stretch the wait out to `_NEIGHBOR_IDLE_MAX`; a
        real change — a peer gained or lost, an identity we had not seen —
        wakes the loop and resets it."""
        while self._running:
            self._neighbor_wakeup.clear()
            before = len(self._live_neighbors())
            known_before = len(self._routing.all_entries())
            try:
                await self._maintain_neighbors()
            except asyncio.CancelledError:
                raise
            except Exception:
                pass
            productive = (len(self._live_neighbors()) != before
                          or len(self._routing.all_entries()) != known_before)
            self._neighbor_idle_cycles = (
                0 if productive else min(self._neighbor_idle_cycles + 1, 8))
            wait = min(_NEIGHBOR_IDLE_MAX,
                       _NEIGHBOR_REFRESH * (2 ** self._neighbor_idle_cycles))
            try:
                async with asyncio.timeout(wait):
                    await self._neighbor_wakeup.wait()
                # Woken early. Honour the floor anyway: the wake says there is
                # something to do, not that it must be done this instant.
                await asyncio.sleep(_NEIGHBOR_MIN_INTERVAL)
            except TimeoutError:
                pass

    async def _maintain_neighbors(self, *, force: bool = False) -> None:
        """Run one bounded discovery/reconnect cycle.

        Two regimes. Below `_NEIGHBOR_FLOOR` live links the node is *searching*:
        an iterative lookup refreshes its own neighborhood, then it dials the
        XOR-nearest identities it knows (with no known or discoverable identity
        there is intentionally nothing to dial). At or above the floor it is
        joined and stays quiet — no lookup, no dial — except for *promotions*:
        identities seen carrying traffic that are closer to us than the least
        interesting slot we hold. Dialling one makes it a maintained neighbour
        and pushes that worst slot out of the set.

        ``force`` runs a full searching cycle whatever we hold; join/bootstrap
        use it to populate a fresh table.
        """
        live = self._live_neighbors()
        searching = force or len(live) < _NEIGHBOR_FLOOR
        promotions = self._neighbor_promotions()
        if not searching and not promotions:
            return

        if searching and self._authenticated_peers():
            try:
                async with asyncio.timeout(_KAD_LOOKUP_TIMEOUT * 2):
                    await self.kad_lookup(self._id, k=20, alpha=3,
                                          max_rounds=_KAD_LOOKUP_MAX_ROUNDS)
            except (TimeoutError, Exception):
                pass

        now = time.monotonic()
        live_ids = {p.authenticated_id for p in self._authenticated_peers()}
        desired = list(promotions)
        if searching:
            desired += [entry.node_id for entry in
                        self._routing.get_closest(self._id, _NEIGHBOR_TARGET)]
        attempts = []
        seen: set[NodeID] = set()
        for node_id in desired:
            if node_id in live_ids:
                self._neighbor_retry.pop(node_id, None)
                continue
            if node_id in seen:
                continue
            seen.add(node_id)
            _, next_try = self._neighbor_retry.get(node_id, (0, 0.0))
            if now >= next_try:
                attempts.append(node_id)
        if not attempts:
            return

        results = await asyncio.gather(
            *(self._ensure_route_to(node_id) for node_id in attempts),
            return_exceptions=True,
        )
        now = time.monotonic()
        for node_id, result in zip(attempts, results):
            if isinstance(result, _Peer) and result.session is not None:
                self._neighbor_retry.pop(node_id, None)
                continue
            failures = self._neighbor_retry.get(node_id, (0, 0.0))[0] + 1
            delay = min(_NEIGHBOR_RETRY_MAX,
                        _NEIGHBOR_RETRY_MIN * (2 ** min(failures - 1, 5)))
            self._neighbor_retry[node_id] = (failures, now + delay)
            self._neighbor_retry.move_to_end(node_id)
            while len(self._neighbor_retry) > _NEIGHBOR_RETRY_TRACKED:
                self._neighbor_retry.popitem(last=False)

    async def find_node(self, target: NodeID) -> None:
        qid = os.urandom(_QID_LEN)
        for peer in self._peers:
            packet = Packet.create(FIND_NODE, self._id.raw,
                                   NodeID(b"\xff" * 20).raw, target.raw + qid)
            await peer.send(packet)

    async def initiate_handshake(self, peer: _Peer) -> None:
        kem_pub, kem_secret = self._identity.generate_kem_keypair()
        peer.pending_kem_secret = kem_secret
        dsa_pub   = self._identity.dsa_public_key
        challenge = peer.received_challenge if peer.received_challenge is not None else os.urandom(32)
        chain     = self._cert_store.get_chain_to_root(self._id) or []
        signature = self._identity.sign(challenge + kem_pub + dsa_pub)
        payload   = _encode_handshake(kem_pub, dsa_pub, chain, signature)
        packet    = Packet.create(HANDSHAKE, self._id.raw,
                                  NodeID(b"\xff" * 20).raw, payload)
        await peer.send(packet)

    async def _wait_for_peer_authenticated(self, peer: _Peer,
                                            target: NodeID,
                                            timeout: float) -> bool:
        deadline = asyncio.get_event_loop().time() + timeout
        while True:
            if peer not in self._peers:
                return False
            if peer.authenticated_id == target and peer.session is not None:
                return True
            if asyncio.get_event_loop().time() >= deadline:
                return False
            await asyncio.sleep(_AUTH_POLL_INTERVAL)

    async def _kademlia_lookup(self, target: NodeID, timeout: float) -> bool:
        deadline = time.monotonic() + timeout
        existing = self._pending_lookups.get(target)
        if existing is not None:
            try:
                await asyncio.wait_for(existing.wait(), timeout=timeout)
            except asyncio.TimeoutError:
                return self._routing.contains(target)
            if self._routing.contains(target):
                return True
            # That lookup answered a different question: it started from another
            # shortlist, at another time. Reporting its failure as ours would
            # give up on an id we never actually asked about — run our own with
            # what is left of the budget. Only once: if someone else has taken
            # the slot again meanwhile we stop, so two nodes can never chain
            # lookups into each other indefinitely.
            timeout = deadline - time.monotonic()
            if timeout <= 0 or self._pending_lookups.get(target) is not None:
                return False

        event = asyncio.Event()
        self._pending_lookups[target] = event
        try:
            try:
                async with asyncio.timeout(timeout):
                    await self.kad_lookup(target, k=20, alpha=3,
                                          max_rounds=_KAD_LOOKUP_MAX_ROUNDS)
            except TimeoutError:
                pass
            return self._routing.contains(target)
        finally:
            event.set()
            self._pending_lookups.pop(target, None)

    async def _ensure_route_to(self, target: NodeID,
                                timeout: float = _ON_DEMAND_TIMEOUT) -> _Peer | None:
        if target == self._id:
            return None
        existing = next(
            (p for p in self._peers
             if p.authenticated_id == target and p.session is not None),
            None,
        )
        if existing is not None:
            return existing
        pending = self._pending_connections.get(target)
        if pending is not None:
            try:
                await asyncio.wait_for(pending.wait(), timeout=timeout)
            except asyncio.TimeoutError:
                return None
            return next(
                (p for p in self._peers
                 if p.authenticated_id == target and p.session is not None),
                None,
            )
        event = asyncio.Event()
        self._pending_connections[target] = event
        deadline = asyncio.get_event_loop().time() + timeout
        try:
            if not self._routing.contains(target):
                remaining = deadline - asyncio.get_event_loop().time()
                if remaining <= 0:
                    return None
                await self._kademlia_lookup(target, remaining)
                if not self._routing.contains(target):
                    return None
            peer = await self._connect_routing(target, deadline)
            if peer is not None:
                return peer
            # Use only the remaining whole-operation budget for NAT traversal.
            remaining = deadline - asyncio.get_event_loop().time()
            if remaining <= 0:
                return None
            return await self._punch_route_to(target, remaining)
        finally:
            event.set()
            self._pending_connections.pop(target, None)

    async def _punch_route_to(self, target: NodeID,
                              timeout: float = _ON_DEMAND_TIMEOUT) -> _Peer | None:
        """NAT traversal fallback: ask shared relays to coordinate a UDP hole
        punch to *target*, then wait for the punched link to authenticate.

        Requires an active UDP listener and punching enabled. Relays tried are
        bounded; a hostile or ignorant relay just wastes one wait slot."""
        if not self._punch_enabled or self._udp_server is None:
            return None
        if self.udp_port() is None:
            return None
        relays = [p for p in self._peers
                  if p.session is not None and p.authenticated_id is not None
                  and p.authenticated_id != target]
        sent = 0
        for relay in relays[:_PUNCH_MAX_RELAYS]:
            try:
                await self.request_hole_punch(relay, target)
                sent += 1
            except Exception:
                pass
        if sent == 0:
            return None
        # All requests are in flight; concurrent PUNCH_RELAY answers dedupe
        # on _punch_pending. One bounded wait covers them all.
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            peer = next(
                (p for p in self._peers
                 if p.authenticated_id == target and p.session is not None),
                None,
            )
            if peer is not None:
                return peer
            await asyncio.sleep(_AUTH_POLL_INTERVAL)
        return None

    def _maybe_upgrade_path(self, target: NodeID) -> None:
        """Fire-and-forget attempt to turn a relayed path into a direct link
        (direct connect first, hole punch as fallback — both inside
        _ensure_route_to). Rate-limited per target so a chatty flow doesn't
        turn into a connect/punch storm."""
        if target == self._id or target in self._pending_connections:
            return
        now = time.monotonic()
        last = self._upgrade_last.get(target)
        if last is not None and now - last < _UPGRADE_COOLDOWN:
            return
        if len(self._upgrade_last) >= _UPGRADE_MAX_TRACKED:
            self._upgrade_last.popitem(last=False)
        self._upgrade_last[target] = now
        self._track_route_task(self._ensure_route_to(target))

    async def _kad_query_node(self, node_id: NodeID, target: NodeID,
                               timeout: float = 5.0) -> list[NodeEntry]:
        query_id = os.urandom(_QID_LEN)
        future: asyncio.Future = asyncio.get_event_loop().create_future()
        self._pending_finds[query_id] = future
        # Addressed to node_id and routed: a direct peer gets it in one hop, an
        # id reachable only through relays gets it multi-hop. The FOUND_NODE
        # reply routes back to us the same way.
        packet = Packet.create(FIND_NODE, self._id.raw, node_id.raw,
                               target.raw + query_id)
        try:
            await self._route_outbound(packet)
            return await asyncio.wait_for(asyncio.shield(future), timeout)
        except (asyncio.TimeoutError, Exception):
            # Unanswered: whatever first hop we used is not carrying traffic to
            # this id any more. Forget it so the next try re-picks by proximity.
            self._forget_route_hint(node_id)
            return []
        finally:
            self._pending_finds.pop(query_id, None)
            if not future.done():
                future.cancel()

    async def kad_lookup(self, target: NodeID, k: int = 20, alpha: int = 3,
                         max_rounds: int = 10) -> list[NodeID]:
        shortlist: set[NodeID] = {e.node_id for e in self._routing.get_closest(target, k)}
        for p in self._peers:
            if p.authenticated_id is not None and p.session is not None:
                shortlist.add(p.authenticated_id)
        queried: set[NodeID] = set()
        closest_seen: NodeID | None = None
        for _ in range(max_rounds):
            candidates = sorted(
                (nid for nid in shortlist if nid not in queried),
                key=lambda n: target.distance(n),
            )[:alpha]
            if not candidates:
                break
            queried.update(candidates)
            results = await asyncio.gather(
                *[self._kad_query_node(nid, target) for nid in candidates],
                return_exceptions=True,
            )
            for r in results:
                if isinstance(r, list):
                    for entry in r:
                        if entry.node_id != self._id:
                            shortlist.add(entry.node_id)
            sorted_ids = sorted(shortlist, key=lambda n: target.distance(n))[:k]
            shortlist = set(sorted_ids)
            new_closest = sorted_ids[0] if sorted_ids else None
            if new_closest == closest_seen:
                break
            closest_seen = new_closest
        return sorted(shortlist, key=lambda n: target.distance(n))

    async def bootstrap(self) -> None:
        """Kademlia join: advertise own addresses then iteratively populate routing table."""
        if not self._authenticated_peers():
            await self._maintain_neighbors(force=True)
        if not self._authenticated_peers():
            return
        for peer in list(self._peers):
            if peer.session is not None and self._addresses:
                await self.ping(peer)
        await self._maintain_neighbors(force=True)

    def _learn_reverse_path(self, peer: _Peer, packet: Packet) -> None:
        """A routable packet just arrived from ``packet.src_id`` over ``peer``:
        that link is a path back to that node id which *demonstrably carries
        traffic*. XOR proximity is only a guess about an overlay we may not have
        finished learning, so replies (FOUND_NODE, ECHO_REPLY, the E2E ack, DATA)
        used to be routed by a fresh guess that could walk into a dead end while
        the request's own path sat unused. Remember the ingress link instead.

        Only ever *reorders* peers we have already authenticated, so it can
        never introduce an unauthenticated next hop; bounded and TTL'd, and
        dropped again as soon as a query through it goes unanswered."""
        if peer.authenticated_id is None or packet.dst_id == _BROADCAST_ID:
            return
        src = NodeID(packet.src_id)
        if src == self._id:
            return
        if peer.authenticated_id == src:
            # We have the link ourselves; any hint could only be a longer path.
            self._route_hints.pop(src, None)
            return
        # Traffic from a node we have no link to: it may be a better neighbour
        # than the worst slot we maintain (see _note_neighbor_candidate).
        self._note_neighbor_candidate(src)
        self._route_hints[src] = (peer.authenticated_id, time.monotonic())
        self._route_hints.move_to_end(src)
        while len(self._route_hints) > _ROUTE_HINT_MAX:
            self._route_hints.popitem(last=False)

    def _forget_route_hint(self, target: NodeID) -> None:
        """Drop the learned first hop for ``target``. Called when a routed query
        through it goes unanswered, so the next attempt falls back to XOR
        proximity instead of retrying a hop that went dark (or is lying)."""
        self._route_hints.pop(target, None)

    def _forget_hints_via(self, node_id: NodeID | None) -> None:
        """Forget every hint whose first hop was ``node_id`` — that link is gone,
        so the paths behind it are no longer known to work."""
        if node_id is None:
            return
        for target in [t for t, (via, _) in self._route_hints.items()
                       if via == node_id]:
            del self._route_hints[target]

    def _route_hint_peer(self, target: NodeID,
                         exclude: _Peer | None = None) -> _Peer | None:
        """The live peer a packet from ``target`` last reached us through."""
        hint = self._route_hints.get(target)
        if hint is None:
            return None
        via, seen_at = hint
        if time.monotonic() - seen_at > _ROUTE_HINT_TTL:
            del self._route_hints[target]
            return None
        return next((p for p in self._peers
                     if p is not exclude and p.authenticated_id == via
                     and p.session is not None), None)

    def _route_candidates(self, target: NodeID,
                          exclude: _Peer | None = None) -> list[_Peer]:
        # nsmallest, not a full sort: this runs per forwarded packet, and the
        # ordering rules below are what matter — a direct link to the target
        # leads, then observed traffic, then XOR proximity (gotchas §11).
        peers = heapq.nsmallest(
            _ROUTE_SEND_FANOUT, self._authenticated_peers(exclude=exclude),
            key=lambda peer: (
                0 if peer.authenticated_id == target else 1,
                target.distance(peer.authenticated_id),
            ))
        # A direct link to the target is the shortest path that exists and keeps
        # the lead; otherwise observed traffic beats XOR proximity.
        if not peers or peers[0].authenticated_id != target:
            hint = self._route_hint_peer(target, exclude=exclude)
            if hint is not None:
                peers = [hint] + [p for p in peers
                                  if p.authenticated_id != hint.authenticated_id]
        return peers[:_ROUTE_SEND_FANOUT]

    def _drop_failed_peer(self, peer: _Peer) -> None:
        """A send to this peer failed: take it out of routing *now*, tear the
        link down in the background.

        Called from `_send_to_candidates`, which runs in some *other* peer's
        receive loop. `peer.stop()` waits up to `_PEER_STOP_TIMEOUT` and then
        closes the transport, and a forward tries up to `_ROUTE_SEND_FANOUT`
        candidates — so doing it inline let one packet freeze an unrelated link
        for ten seconds (gotchas §10). Removing it from `self._peers`
        synchronously is what matters for correctness: the next
        `_route_candidates` must not pick it again."""
        if peer in self._peers:
            self._peers.remove(peer)
        self._forget_hints_via(peer.authenticated_id)
        self._wake_neighbor_maintenance()
        self._spawn_bounded(self._safe_stop_peer(peer))

    async def _send_to_candidates(self, packet: Packet, candidates: list[_Peer],
                                  *, decrement: bool = False) -> _Peer | None:
        outgoing = packet.with_decremented_ttl() if decrement else packet
        for peer in candidates:
            try:
                await peer.send(outgoing)
                return peer
            except Exception:
                self._drop_failed_peer(peer)
        return None

    def _track_route_task(self, coro) -> bool:
        """Run background route work under a hard cap, tracked so stop() can
        cancel it — an untracked task awaiting a dial outlives teardown."""
        if not self._running or len(self._deferred_routes) >= _MAX_DEFERRED_ROUTES:
            coro.close()
            return False
        task = asyncio.ensure_future(coro)
        self._deferred_routes.add(task)
        task.add_done_callback(self._deferred_routes.discard)
        return True

    def _defer_route(self, packet: Packet, *, decrement: bool = False,
                     exclude: _Peer | None = None) -> None:
        """Acquire a route for ``packet`` in the background, then send it.

        Called from a peer's receive loop, where awaiting ``_ensure_route_to``
        inline stalls the link for the whole on-demand budget — and deadlocks
        outright when the lookup it starts can only be answered over that same
        link. Bounded: past ``_MAX_DEFERRED_ROUTES`` in flight the packet is
        dropped, exactly as an unroutable packet always was."""
        self._track_route_task(
            self._deferred_route_task(packet, decrement, exclude))

    async def _deferred_route_task(self, packet: Packet, decrement: bool,
                                   exclude: _Peer | None) -> None:
        target = NodeID(packet.dst_id)
        try:
            peer = await self._ensure_route_to(target)
        except asyncio.CancelledError:
            raise
        except Exception:
            peer = None
        if not self._running:
            return
        # Acquisition may also have exposed a new relay even when the target
        # itself stayed undiallable, so fall back to the refreshed neighbor set.
        candidates = ([peer] if peer is not None and peer is not exclude
                      else self._route_candidates(target, exclude=exclude))
        await self._send_to_candidates(packet, candidates, decrement=decrement)

    async def _stop_deferred_routes(self) -> None:
        tasks = list(self._deferred_routes)
        self._deferred_routes.clear()
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _route_outbound(self, packet: Packet, *,
                              blocking: bool = True) -> _Peer | None:
        """Send a packet toward its dst_id. ``blocking=False`` is mandatory for
        callers running inside a peer's receive loop: it keeps the fast path
        (send to a live candidate) and defers only the slow acquisition."""
        target = NodeID(packet.dst_id)
        peer = await self._send_to_candidates(
            packet, self._route_candidates(target))
        if peer is not None:
            # Relayed path — try to upgrade to a direct link in the
            # background (direct connect, then UDP hole punch).
            if peer.authenticated_id != target:
                self._maybe_upgrade_path(target)
            return peer
        if not blocking:
            self._defer_route(packet)
            return None
        peer = await self._ensure_route_to(target)
        if peer is not None:
            return await self._send_to_candidates(packet, [peer])
        # Lookup/direct acquisition may expose a new relay even if the target
        # itself remains undiallable. Try the refreshed neighbor set once.
        return await self._send_to_candidates(
            packet, self._route_candidates(target))

    def _forget_e2e(self, target: NodeID) -> None:
        """Drop everything we hold for one destination, in one place.

        The four tables describe one relationship, so they have to be forgotten
        together: evicting only the queued data left an ML-KEM secret, a nonce
        and an attempt timestamp behind for a target nothing would ever mention
        again, and those three had no bound of their own."""
        self._e2e_sessions.pop(target, None)
        self._e2e_pending_kem.pop(target, None)
        self._e2e_pending_nonce.pop(target, None)
        self._e2e_pending_data.pop(target, None)
        self._e2e_attempt.pop(target, None)
        self._e2e_rekey.pop(target, None)

    def _keep_e2e_session(self, src: NodeID, session: SessionKey) -> None:
        """File a live E2E session, evicting the least recently used if needed.

        `src` is proven against the key inside the handshake, not against the
        link it arrived on, so an adversary mints a fresh identity per handshake
        and every one of them wants an entry. A destination with data still
        queued is never the one evicted: dropping it would strand the backlog
        and the retry loop would re-handshake for it immediately."""
        if src in self._e2e_sessions:
            self._e2e_sessions[src] = session
            return
        while len(self._e2e_sessions) >= _MAX_E2E_SESSIONS:
            victim = next((nid for nid in self._e2e_sessions
                           if nid not in self._e2e_pending_data), None)
            if victim is None:
                # Every session is backing a queue. Take the oldest anyway —
                # a bound that can be switched off is not a bound.
                victim = next(iter(self._e2e_sessions))
            self._forget_e2e(victim)
        self._e2e_sessions[src] = session

    def _should_initiate_e2e(self, target: NodeID) -> bool:
        """True if we should (re)send an E2E handshake to ``target``: no session
        yet, and either none in flight or the last attempt is stale enough to
        retry. This is what makes a lost handshake self-heal instead of stranding
        queued data forever."""
        if target in self._e2e_sessions:
            return False
        last = self._e2e_attempt.get(target)
        return last is None or (time.monotonic() - last) >= _E2E_RETRY_INTERVAL

    async def _initiate_e2e_handshake(self, target: NodeID) -> None:
        nonce = os.urandom(32)
        kem_pub, kem_secret = self._identity.generate_kem_keypair()
        dsa_pub = self._identity.dsa_public_key
        cert_chain = self._cert_store.get_chain_to_root(self._id)
        if cert_chain is None:
            return
        signature = self._identity.sign(nonce + kem_pub + dsa_pub)
        payload = _encode_e2e_handshake(nonce, kem_pub, dsa_pub, cert_chain, signature)
        self._e2e_pending_kem[target] = kem_secret
        self._e2e_pending_nonce[target] = nonce
        self._e2e_attempt[target] = time.monotonic()
        self._persist_state()
        packet = Packet.create(E2E_HANDSHAKE, self._id.raw, target.raw, payload)
        await self._route_outbound(packet)

    def _ensure_e2e_retry(self) -> None:
        if self._e2e_retry_task is None or self._e2e_retry_task.done():
            self._e2e_retry_task = asyncio.create_task(self._e2e_retry_loop())

    async def _e2e_retry_loop(self) -> None:
        """Re-drive stalled E2E handshakes: any target with data still queued but
        no session gets its handshake re-sent on a bounded cadence. Re-initiating
        also nudges ``_route_outbound`` to look for a (possibly newly-available)
        path to the peer. Never raises."""
        while self._running:
            await asyncio.sleep(_E2E_RETRY_INTERVAL)
            # Prune bookkeeping for targets that are done (session up / no backlog).
            for t in [t for t in self._e2e_attempt
                      if t in self._e2e_sessions or t not in self._e2e_pending_data]:
                self._e2e_attempt.pop(t, None)
            for target in list(self._e2e_pending_data.keys()):
                if self._should_initiate_e2e(target):
                    try:
                        await self._initiate_e2e_handshake(target)
                    except Exception:
                        pass

    async def _stop_e2e_retry(self) -> None:
        task = self._e2e_retry_task
        self._e2e_retry_task = None
        if task is not None:
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass

    async def _on_new_transport(self, transport: BaseTransport) -> None:
        if len(self._peers) >= _MAX_PEERS:
            await transport.close()
            return
        # Unauthenticated links get their own, smaller ceiling. Without it, 128
        # sockets that never finish a handshake take every slot — and `_dial_uri`
        # refuses to dial at all once `_peers` is full, so the node cannot even
        # re-join the mesh. The transport read timeout is no defence: any packet
        # resets it, including one the gates drop at the first test.
        if self._unauthenticated_peers() >= _MAX_UNAUTH_PEERS:
            self._reap_stale_unauthenticated()
            if self._unauthenticated_peers() >= _MAX_UNAUTH_PEERS:
                await transport.close()
                return
        peer = _Peer(transport, is_client_side=False)
        peer.on_dead = self._reap_peer
        peer.total = self._metrics.total
        peer.trace = self.trace
        self._peers.append(peer)
        self._poke_net("peer-connected")
        await peer.start(self._handle_packet)
        challenge = self._invite.generate_challenge()
        peer.pending_challenge = challenge
        packet = Packet.create(CHALLENGE, self._id.raw,
                               NodeID(b"\xff" * 20).raw, challenge)
        await peer.send(packet)

    def _unauthenticated_peers(self) -> int:
        """Links that have not proved who they are yet — virtual relay peers
        excluded, because a relayed invitation legitimately sits here for the
        length of a join."""
        return sum(1 for p in self._peers
                   if p.authenticated_id is None
                   and not isinstance(p.transport, RelayedTransport))

    def _reap_stale_unauthenticated(self) -> None:
        """Cut links that have had long enough to authenticate and have not.

        A sweep rather than a timer per peer: one bounded pass when the pressure
        is felt costs nothing at rest, and there is nothing to cancel."""
        now = time.monotonic()
        for peer in list(self._peers):
            if peer.authenticated_id is not None:
                continue
            if isinstance(peer.transport, RelayedTransport):
                continue
            if now - peer.connected_at < _HANDSHAKE_DEADLINE:
                continue
            if peer in self._peers:
                self._peers.remove(peer)
            self._spawn_bounded(self._safe_stop_peer(peer))

    async def _dial_uri(self, node_id: NodeID, uri: str,
                        timeout: float) -> _Peer | None:
        """Dial one address of one node and require it to prove who it is.

        The single place an outgoing link is opened: the routing walk, the
        console's manual retry, the periodic retry and the latency probe all
        come through here, so they all apply the same timeout, tear a failed
        attempt down the same way, and — the reason it matters to an operator —
        record the same outcome against the same address.

        Returns the authenticated peer, or ``None``. Never raises: a dial that
        fails is the normal case on a real network, not an error."""
        node_hex = node_id.raw.hex() if node_id is not None else ""
        # These three are answers too, and an operator staring at an address
        # that never connects deserves to be told which one it is rather than
        # being left with a blank row.
        result = _validate_uri(uri)
        if result is None:
            self._note_dial(node_hex, uri, "invalid")
            return None
        scheme, _ = result
        if not self._transport_manager.is_supported(scheme):
            self._note_dial(node_hex, uri, "no transport", scheme)
            return None
        if len(self._peers) >= _MAX_PEERS:
            self._note_dial(node_hex, uri, "peer limit")
            return None
        peer = None
        authenticated = False
        started = time.monotonic()
        try:
            async with asyncio.timeout(timeout):
                transport = await self._transport_manager.connect(uri)
                peer = _Peer(transport, is_client_side=True)
                peer.on_dead = self._reap_peer
                peer.total = self._metrics.total
                peer.trace = self.trace
                peer.remote_addr = uri
                self._peers.append(peer)
                await peer.start(self._handle_packet)
                if await self._wait_for_peer_authenticated(peer, node_id, timeout):
                    authenticated = True
                    self._note_dial(node_hex, uri, "connected",
                                    elapsed=time.monotonic() - started)
                    return peer
                self._note_dial(node_hex, uri, "no-answer",
                                "connected but never authenticated",
                                time.monotonic() - started)
        except asyncio.TimeoutError:
            self._note_dial(node_hex, uri, "timeout", "",
                            time.monotonic() - started)
        except Exception as exc:
            self._note_dial(node_hex, uri, "refused",
                            type(exc).__name__, time.monotonic() - started)
        finally:
            if peer is not None and not authenticated:
                try:
                    await peer.stop()
                except Exception:
                    pass
                if peer in self._peers:
                    self._peers.remove(peer)
        return None

    async def _connect_routing(self, node_id: NodeID,
                               deadline: float) -> _Peer | None:
        entry = self._routing.get(node_id)
        if entry is None:
            return None
        uris = self._preferred(list(entry.addresses), node_id.raw.hex())
        for index, uri in enumerate(uris):
            remaining = deadline - asyncio.get_event_loop().time()
            if remaining <= 0:
                return None
            # Reserve a fair share for every remaining endpoint. A transport
            # that accepts but never authenticates cannot hide fresher URIs.
            peer = await self._dial_uri(node_id, uri,
                                        remaining / max(1, len(uris) - index))
            if peer is not None:
                return peer
        return None

    async def _inject_peer(self, transport: BaseTransport) -> _Peer:
        """For testing only — injects a fake transport as a client-side peer."""
        peer = _Peer(transport, is_client_side=True)
        peer.on_dead = self._reap_peer
        peer.total = self._metrics.total
        peer.trace = self.trace
        self._peers.append(peer)
        self._running = True
        await peer.start(self._handle_packet)
        return peer

    async def _reap_peer(self, peer: _Peer) -> None:
        """Prune a peer whose link died or which was cut for abuse.

        Called from the peer's own receive task, so it must not cancel that
        task (that is stop()'s job) — it just drops the peer from routing and
        releases the transport. On-demand routing re-establishes any link that
        is needed again, so the mesh self-heals without explicit reconnect.
        """
        try:
            self._peers.remove(peer)
        except ValueError:
            pass
        try:
            await peer.transport.close()
        except Exception:
            pass
        self._forget_hints_via(peer.authenticated_id)
        self._poke_net("peer-lost")
        self._wake_neighbor_maintenance()

    def _persist_state(self) -> None:
        """Mark the persisted state dirty; a background task does the writing.

        `SessionStore.save` serialises every session, every pending handshake
        and the whole routing export, encrypts it, writes it and calls
        `os.fsync` — synchronously. It is called from `_handle_handshake`,
        both E2E handlers, `_handle_data` and `send_data`, all of which run on
        the event loop, so every handshake stopped the entire node for the
        length of a serialise-and-fsync, and the cost grew with the state.

        Never raises: a disk problem must not take the node down."""
        if self._session_store is None:
            return
        self._state_dirty = True
        self._ensure_state_writer()

    def _ensure_state_writer(self) -> None:
        if self._session_store is None and not self._cert_store_path:
            return
        if self._state_task is None or self._state_task.done():
            try:
                self._state_task = asyncio.create_task(self._state_writer_loop())
            except RuntimeError:
                # No running loop (construction, teardown). Write inline: this
                # is the one place where there is nothing to block.
                self._state_task = None
                self._write_state_now()
                self._write_certs_now()

    async def _state_writer_loop(self) -> None:
        """Write what has changed, at most every `_STATE_WRITE_INTERVAL`.

        Off the loop thread (`to_thread`): both writes end in an `fsync`, and
        the medium may be a slow one."""
        while self._running or self._state_dirty or self._certs_dirty:
            await asyncio.sleep(_STATE_WRITE_INTERVAL)
            if self._state_dirty:
                await asyncio.to_thread(self._write_state_now)
            if self._certs_dirty:
                await asyncio.to_thread(self._write_certs_now)

    def _write_state_now(self) -> None:
        if self._session_store is None:
            return
        self._state_dirty = False
        try:
            self._session_store.save(
                self._e2e_sessions, self._e2e_pending_kem,
                self._e2e_pending_nonce, self._e2e_pending_data,
                self._routing.export_entries(),
            )
        except Exception:
            pass

    async def _stop_state_writer(self) -> None:
        task = self._state_task
        self._state_task = None
        if task is not None:
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass
        # Whatever is still pending goes to disk before we go: a snapshot the
        # node never wrote is a restart that re-handshakes everything, and a
        # certificate never written is a peer that can no longer be verified.
        if self._state_dirty:
            self._write_state_now()
        if self._certs_dirty:
            self._write_certs_now()

    # -- console / management surface -------------------------------------
    # These read or mutate node state and are meant to be driven from the web
    # console. Async ones run on the event loop; the console marshals into it.

    async def console_snapshot(self) -> dict:
        """A JSON-serialisable view of the node. Built on the event loop, so it
        reads live state atomically (no awaits mid-iteration)."""
        peers = []
        link_now = time.monotonic()
        for p in self._peers:
            peers.append({
                "authenticated_id": p.authenticated_id.raw.hex() if p.authenticated_id else None,
                "pseudo": self.pseudo_of(p.authenticated_id) if p.authenticated_id else "",
                "is_client_side": p.is_client_side,
                "has_session": p.session is not None,
                "malformed": p._malformed,
                "rtt_ms": (round(p.last_rtt * 1000, 1)
                           if p.last_rtt is not None else None),
                "counters": p.counters.as_dict(),
                "transport": self._peer_scheme(p),
                "link": self._link_view(p, link_now),
            })
        # Known nodes, most recently seen first, so the console can show the
        # latest N. seen_ago is seconds since we last added/refreshed the entry.
        now = time.monotonic()
        entries = sorted(self._routing.all_entries(),
                         key=lambda e: e.last_seen, reverse=True)
        authed = {p.authenticated_id.raw.hex(): p for p in self._peers
                  if p.authenticated_id is not None and p.session is not None}
        routing = []
        for e in entries:
            hexid = e.node_id.raw.hex()
            p = authed.get(hexid)
            routing.append({
                "id": hexid,
                "addresses": list(e.addresses),
                "pseudo": self.pseudo_of(hexid),
                "address_status": self._address_status(hexid, e.addresses, p),
                "seen_ago": max(0.0, now - e.last_seen),
                "connected": p is not None,
                "rtt_ms": (round(p.last_rtt * 1000, 1)
                           if p is not None and p.last_rtt is not None else None),
                "has_key": bool(e.dsa_pub),
                "link": self._link_view(p, now) if p is not None else None,
            })
        return {
            "id": self._id.raw.hex(),
            "pseudo": self._pseudo,
            "addresses": list(self._addresses),
            "listen": list(self._addresses),
            "advertised": self.advertised_uris(),
            "local_ips": list(self._local_ips),
            "transports": self._transport_manager.schemes(),
            "listening": self._transport_manager.listening_uris()
                         + ([self._udp_listen_uri] if self._udp_listen_uri else []),
            "running": self._running,
            "uptime": self._metrics.uptime(),
            # Two different quantities, named so they cannot be confused again.
            # A node may hold several links at once (a LAN address and a punched
            # UDP path, say), so these are not the same number — and a console
            # that printed the link count under the word "nodes" is exactly what
            # one ambiguous name costs.
            "link_count": sum(1 for p in self._peers
                              if p.authenticated_id and p.session),
            "node_count": len(self._authenticated_peers()),
            "peers": peers,
            "routing": routing,
            "routing_size": len(routing),
            "e2e_sessions": [nid.raw.hex() for nid in self._e2e_sessions],
            "topology": self._console_topology(now),
            "total": self._metrics.total.as_dict(),
            "load": self._metrics.load(),
            "network": (self._net_monitor.status()
                        if self._net_monitor is not None else None),
            "transport_details": self._transport_details(),
            "reachability": self.reachability(),
            "relay_capable": self.relay_capable(),
            "pending_seeks": len(self._pending_seeks),
            "lan_discovery": self._lan_discovery is not None,
            "dynamic_address": self._dynamic_address,
            "transport_balance": self._transport_balance,
            "transport_preference": self.transport_preference(),
            "punch_enabled": self._punch_enabled,
            "punch_keepalive": self._punch_keepalive,
            "join_status": self._join_status,
        }

    def _console_topology(self, now: float) -> dict:
        direct = []
        direct_ids: set[NodeID] = set()
        for peer in self._authenticated_peers():
            direct_ids.add(peer.authenticated_id)
            direct.append({
                "id": peer.authenticated_id.raw.hex(),
                "pseudo": self.pseudo_of(peer.authenticated_id),
                "transport": self._peer_scheme(peer),
                "rtt_ms": (round(peer.last_rtt * 1000, 1)
                           if peer.last_rtt is not None else None),
                "quality": peer.quality.as_dict(),
                "counters": peer.counters.as_dict(),
                "since": max(0.0, now - peer.connected_at),
                "remote": (peer.remote_addr
                           or self._link_view(peer, now).get("remote")),
                "evidence": "authenticated-direct-link",
            })
        routed = []
        for target in self._e2e_sessions:
            if target in direct_ids:
                continue
            hint = self._route_hints.get(target)
            if hint is None:
                continue
            via, seen_at = hint
            if now - seen_at > _ROUTE_HINT_TTL or via not in direct_ids:
                continue
            routed.append({
                "id": target.raw.hex(),
                "pseudo": self.pseudo_of(target),
                "via": via.raw.hex(),
                "seen_ago": max(0.0, now - seen_at),
                "evidence": "locally-observed-first-hop",
                "path_visibility": "first-hop-only",
            })
        return {"direct": direct, "routed": routed}

    def console_nodes(self, scope: str) -> list[dict]:
        """A focused console view of direct or routing-table nodes."""
        now = time.monotonic()
        authed = {p.authenticated_id.raw.hex(): p for p in self._peers
                  if p.authenticated_id is not None and p.session is not None}
        if scope == "known":
            known = []
            for e in self._routing.all_entries():
                node_id = e.node_id.raw.hex()
                peer = authed.get(node_id)
                known.append({
                    "id": node_id,
                    "pseudo": self.pseudo_of(node_id),
                    "addresses": sorted(e.addresses),
                    "address_status": self._address_status(
                        node_id, sorted(e.addresses), peer),
                    "seen_ago": max(0.0, now - e.last_seen),
                    "connected": peer is not None,
                    "rtt_ms": (round(peer.last_rtt * 1000, 1)
                               if peer is not None and peer.last_rtt is not None
                               else None),
                    "has_key": bool(e.dsa_pub),
                    "link": self._link_view(peer, now) if peer is not None else None,
                })
            return known
        if scope != "active":
            raise ValueError("invalid node scope")

        out = []
        for p in self._peers:
            if p.authenticated_id is None or p.session is None:
                continue
            node_id = p.authenticated_id.raw.hex()
            route = self._routing.get(p.authenticated_id)
            addresses = list(route.addresses) if route is not None else []
            if p.remote_addr and p.remote_addr not in addresses:
                addresses.append(p.remote_addr)
            out.append({
                "id": node_id,
                "pseudo": self.pseudo_of(node_id),
                "authenticated_id": node_id,
                "addresses": sorted(addresses),
                "seen_ago": (max(0.0, now - route.last_seen)
                             if route is not None else None),
                "connected": True,
                "has_key": bool((route.dsa_pub if route is not None else b"")
                                or p.dsa_pub),
                "is_client_side": p.is_client_side,
                "has_session": True,
                "malformed": p._malformed,
                "rtt_ms": (round(p.last_rtt * 1000, 1)
                           if p.last_rtt is not None else None),
                "counters": p.counters.as_dict(),
                "transport": self._peer_scheme(p),
                "address_status": self._address_status(node_id, sorted(addresses), p),
                "link": self._link_view(p, now),
            })
        return out

    def _reachability_ctx(self) -> dict:
        """Node-level facts a transport needs to classify its reachability:
        our host addresses, discovered public addresses, and the transports on
        which someone has already reached us (passive confirmation)."""
        return {
            "local_ips": list(self._local_ips),
            "public_addrs": list(self._extra_addrs),
            "inbound_schemes": set(self._inbound_schemes),
        }

    def reachability(self) -> list[dict]:
        """Aggregated reachability descriptors across every active transport.
        Transport-agnostic: each transport classifies its own addresses."""
        ctx = self._reachability_ctx()
        out = list(self._transport_manager.reachability(ctx))
        if self._udp_server is not None and self._udp_listen_uri is not None:
            try:
                out.extend(self._udp_server.reachability(self._udp_listen_uri, ctx))
            except Exception:
                pass
        return out

    def public_endpoints(self) -> list[str]:
        """Addresses a stranger on the open internet can actually dial.

        Confirmed world-scope descriptors only: "we think this address is
        public" is not the same as "an inbound connection arrived on it", and a
        join ticket that points at an address nobody can reach is worse than no
        ticket at all — it fails after the operator has already shared it."""
        out: list[str] = []
        for descriptor in self.reachability():
            if descriptor.get("scope") != "world" or not descriptor.get("confirmed"):
                continue
            address = descriptor.get("address")
            # Tickets carry a TCP endpoint: it is the transport a scanner on an
            # arbitrary network can open without hole punching.
            if isinstance(address, str) and address.startswith("tcp://"):
                if address not in out:
                    out.append(address)
        return out

    def issue_join_ticket(self, ttl: float | None = None) -> dict:
        """Mint a compact join ticket. Raises ``ValueError`` if we are not
        publicly reachable — the whole point of this shape of invitation is that
        the scanner needs nothing but the string."""
        from . import join_ticket
        endpoints = self.public_endpoints()
        if not endpoints:
            raise ValueError(
                "this node has no confirmed public address — a scanned ticket "
                "would have nowhere to connect. Use the full join instead.")
        parsed = _validate_uri(endpoints[0])
        hostport = split_host_port(parsed[1]) if parsed else None
        if hostport is None:
            raise ValueError("could not read our own public address")
        host, port = hostport
        window = join_ticket.clamp_ttl(ttl)
        code, seed = self._invite.generate_seeded_code(window)
        text = join_ticket.encode(host.strip("[]"), port, seed,
                                  time.time() + window)
        return {
            "ticket": text,
            "uri": f"tcp://{host}:{port}",
            "code": code,
            "expires_at": time.time() + window,
            "ttl": window,
            "endpoints": endpoints,
        }

    def relay_capable(self) -> bool:
        """True if we are confirmed reachable by a broad audience — i.e. we can
        serve as a rendezvous/relay for others. Any transport may qualify."""
        return any(d.get("scope") == "world" and d.get("confirmed")
                   for d in self.reachability())

    def _note_dial(self, node_hex: str, uri: str, outcome: str,
                   detail: str = "", elapsed: float | None = None) -> None:
        """Remember how one address behaved.

        A node advertising four addresses of which one works is the normal case
        on a real network, and "which one, and why not the others" is the first
        question an operator asks. Bounded twice over: a fixed number of nodes,
        a fixed number of addresses each."""
        if not node_hex:
            return
        book = self._dial_log.get(node_hex)
        if book is None:
            while len(self._dial_log) >= _DIAL_LOG_NODES:
                self._dial_log.pop(next(iter(self._dial_log)))
            book = self._dial_log[node_hex] = OrderedDict()
        book.pop(uri, None)
        while len(book) >= _DIAL_LOG_ADDRESSES:
            book.pop(next(iter(book)))
        book[uri] = {"outcome": outcome, "detail": detail[:80],
                     "at": time.monotonic(),
                     "ms": None if elapsed is None else round(elapsed * 1000, 1)}

    # -- retrying addresses ------------------------------------------------

    def _known_addresses(self, node_id: NodeID) -> list[str]:
        """Addresses we hold for a node, in the order we would try them."""
        entry = self._routing.get(node_id)
        if entry is None:
            return []
        return self._preferred(list(entry.addresses),
                               node_id.raw.hex())[:_DIAL_LOG_ADDRESSES]

    # -- choosing between a node's addresses --------------------------------

    def _transport_priority(self, uri: str) -> int:
        """What the medium behind this address is worth, as its own setting.

        A number the operator sets per transport, not a ranking the core
        invents: only the person running the node knows whether their LoRa link
        is the precious one or the last resort."""
        result = _validate_uri(uri)
        if result is None:
            return -_PRIORITY_SPAN
        try:
            value = int(self._transport_manager.setting(result[0], "priority") or 0)
        except Exception:
            # A medium that cannot answer is not a reason to stop dialling: it
            # scores neutral, exactly like one that never declared a priority.
            return 0
        return max(-_PRIORITY_SPAN, min(_PRIORITY_SPAN, value))

    def _address_score(self, uri: str, ms: float | None) -> float:
        """One number, 0..1, higher is better — priority and latency weighed.

        Both halves are mapped onto 0..1 *absolutely* rather than against the
        other candidates, so a score means the same thing on every pass: two
        addresses compared today and tomorrow give the same answer, and the
        steering loop can use a fixed margin.

        Latency curves rather than scales: 0 ms scores 1, `_LATENCY_HALF_MS`
        scores .5, and 400 ms still scores something. A linear map would make
        one absurd measurement flatten every real difference. An address never
        measured scores the middle — neither rewarded nor punished for being
        untried."""
        priority = (self._transport_priority(uri) + _PRIORITY_SPAN) / (2 * _PRIORITY_SPAN)
        if ms is None or ms < 0:
            latency = _LATENCY_HALF_MS / (_LATENCY_HALF_MS + _LATENCY_HALF_MS)
        else:
            latency = _LATENCY_HALF_MS / (_LATENCY_HALF_MS + ms)
        weight = max(0.0, min(100, self._transport_balance)) / 100.0
        return weight * priority + (1.0 - weight) * latency

    def _measured_ms(self, node_hex: str, uri: str) -> float | None:
        """What this address measured last time it was dialled, if ever."""
        record = (self._dial_log.get(node_hex) or {}).get(uri)
        return None if record is None else record.get("ms")

    def _preferred(self, uris: list[str], node_hex: str = "") -> list[str]:
        """A node's addresses, best first.

        Score decides; a global-IPv6 endpoint breaks a tie, because it is
        reachable end-to-end and lets two IPv6 nodes skip NAT entirely. Sorting
        is stable, so equal addresses keep the order they were learned in."""
        scored = _order_by_preference(uris)
        return sorted(scored,
                      key=lambda uri: -self._address_score(
                          uri, self._measured_ms(node_hex, uri)))

    def transport_preference(self) -> list[dict]:
        """The order the schemes themselves come in right now, for the console.

        Computed here and not in the page: the balance is a single rule, and a
        second implementation of it in JavaScript would disagree the day the
        rule changes."""
        out = []
        try:
            schemes = self._transport_manager.schemes()
        except Exception:
            return out
        for scheme in schemes:
            uri = scheme + "://placeholder:1"
            out.append({"scheme": scheme,
                        "priority": self._transport_priority(uri),
                        "score": round(self._address_score(uri, None), 3)})
        out.sort(key=lambda entry: (-entry["score"], entry["scheme"]))
        return out

    def set_transport_balance(self, value: int) -> int:
        """0 = decide on latency alone, 100 = on priority alone."""
        try:
            value = int(value)
        except (TypeError, ValueError):
            raise ValueError("balance must be a whole number") from None
        if not 0 <= value <= 100:
            raise ValueError("balance must be between 0 and 100")
        self._transport_balance = value
        return value

    @property
    def transport_balance(self) -> int:
        return self._transport_balance

    def _retry_interval(self, uri: str) -> float:
        """What the medium behind this address says about re-dialling it.

        Zero — the default — means "never on a timer". The core has no opinion:
        a link over a radio that costs power per attempt and one over Ethernet
        cannot share a number, so the number belongs to the medium."""
        result = _validate_uri(uri)
        if result is None:
            return 0.0
        try:
            value = self._transport_manager.setting(result[0], "retry_interval")
        except Exception:
            return 0.0
        try:
            return max(0.0, float(value or 0.0))
        except (TypeError, ValueError):
            return 0.0

    def _ensure_address_retry(self) -> None:
        if self._retry_task is None or self._retry_task.done():
            self._retry_task = asyncio.create_task(self._address_retry_loop())

    async def _stop_address_retry(self) -> None:
        task = self._retry_task
        self._retry_task = None
        if task is not None:
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass

    async def _address_retry_loop(self) -> None:
        """Re-dial the addresses of nodes we know but are not linked to.

        A node that dropped off because its ISP bounced, its laptop slept, or a
        switch rebooted comes back on its own address; without this, nothing
        tries again until something else needs a route. What each medium
        considers a reasonable cadence is its own setting; what is fixed here is
        that a pass costs at most `_RETRY_MAX_PER_PASS` dials however many nodes
        are waiting, and that a node already linked is never dialled again.

        Never raises: this loop dying would be a silent loss of recovery."""
        while self._running:
            await asyncio.sleep(_RETRY_TICK)
            try:
                await self._retry_pass()
            except asyncio.CancelledError:
                raise
            except Exception:
                pass

    async def _retry_pass(self) -> int:
        """One bounded round of re-dialling. Returns how many dials it made."""
        linked = {peer.authenticated_id for peer in self._peers
                  if peer.authenticated_id is not None and peer.session is not None}
        now = time.monotonic()
        budget = _RETRY_MAX_PER_PASS
        for entry in self._routing.all_entries()[:_RETRY_NODES_SCANNED]:
            if budget <= 0:
                break
            node_id = entry.node_id
            if node_id == self._id or node_id in linked:
                continue
            node_hex = node_id.raw.hex()
            book = self._dial_log.get(node_hex) or {}
            for uri in self._known_addresses(node_id):
                if budget <= 0:
                    break
                interval = self._retry_interval(uri)
                if interval <= 0:
                    continue
                record = book.get(uri)
                if record is not None and now - record["at"] < interval:
                    continue
                budget -= 1
                peer = await self._dial_uri(node_id, uri, _RETRY_DIAL_TIMEOUT)
                if peer is not None:
                    self._wake_neighbor_maintenance()
                    break               # linked again; the other addresses can wait
        return _RETRY_MAX_PER_PASS - budget

    async def console_retry_addresses(self, node_id_hex: str,
                                      uri: str = "") -> dict:
        """Console action: dial a node's addresses now — one, or all of them.

        Only addresses this node already knows for that identity are dialled.
        The console is authenticated, but "type a host and the node connects to
        it" is a different feature with a different threat model; adding a peer
        goes through the join and listener paths, which say what they are.

        Reports what every address did, in the same words the address table
        uses, because the point of pressing the button is to find out."""
        try:
            node_id = NodeID(bytes.fromhex(node_id_hex))
        except (ValueError, TypeError):
            return {"ok": False, "error": "bad id"}
        if node_id == self._id:
            return {"ok": False, "error": "self"}
        known = self._known_addresses(node_id)
        if not known:
            return {"ok": False, "error": "no known address for that node"}
        if uri:
            if uri not in known:
                return {"ok": False, "error": "not an address of that node"}
            targets = [uri]
        else:
            targets = known
        peer = next((p for p in self._peers if p.authenticated_id == node_id
                     and p.session is not None), None)
        in_use = peer.remote_addr if peer is not None else None
        results = []
        for target in targets:
            if target == in_use:
                results.append({"uri": target, "outcome": "in-use", "detail": "",
                                "ms": None})
                continue
            linked = await self._dial_uri(node_id, target, _RETRY_DIAL_TIMEOUT)
            record = (self._dial_log.get(node_id.raw.hex()) or {}).get(target) or {}
            results.append({"uri": target,
                            "outcome": record.get("outcome", "no-answer"),
                            "detail": record.get("detail", ""),
                            "ms": record.get("ms")})
            if linked is not None:
                in_use = target
                self._wake_neighbor_maintenance()
                if not uri:
                    break               # linked; stop working down the list
        return {"ok": True, "connected": in_use is not None, "results": results}

    # -- steering a link onto a better address ------------------------------

    def _ensure_address_steering(self) -> None:
        if self._steer_task is None or self._steer_task.done():
            self._steer_task = asyncio.create_task(self._address_steering_loop())

    async def _stop_address_steering(self) -> None:
        task = self._steer_task
        self._steer_task = None
        if task is not None:
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass

    def set_dynamic_address(self, enabled: bool) -> None:
        """Turn latency-based address steering on or off on a running node."""
        self._dynamic_address = bool(enabled)
        if not self._dynamic_address:
            self._steer_seen.clear()

    @property
    def dynamic_address(self) -> bool:
        return self._dynamic_address

    async def _address_steering_loop(self) -> None:
        """Move a link onto a better address of the same node, if there is one.

        A node reachable at several addresses is usually reachable at several
        *qualities* — a LAN address and the same machine's public one, IPv4 and
        IPv6 through different paths. Whichever was dialled first is the one in
        use, and it is chosen by order, not by how it performs.

        One candidate per pass, at most, and only when the operator asked for
        it. The measurement is a real link: the candidate is dialled and pinged,
        because an address that looks fast and cannot complete a handshake is
        not a better address. The loser is closed either way, so the node never
        keeps two links to one peer beyond the measurement."""
        while self._running:
            await asyncio.sleep(_ADDR_STEER_INTERVAL)
            if not self._dynamic_address:
                continue
            try:
                await self._steer_pass()
            except asyncio.CancelledError:
                raise
            except Exception:
                pass

    def _steer_candidate(self) -> tuple:
        """The one link worth examining this pass, and the address to try.

        Returns ``(peer, uri)`` or ``(None, "")``. Skips anything we cannot
        judge: a link with no measured latency, an address already in use, and
        one measured recently enough that the answer would be the same."""
        now = time.monotonic()
        for peer in list(self._peers):
            node_id = peer.authenticated_id
            if node_id is None or peer.session is None:
                continue
            if peer.last_rtt is None:
                continue        # never measured: nothing to compare against
            node_hex = node_id.raw.hex()
            seen = self._steer_seen.get(node_hex) or {}
            for uri in self._known_addresses(node_id):
                if uri == peer.remote_addr:
                    continue
                at = seen.get(uri)
                if at is not None and now - at < _ADDR_STEER_COOLDOWN:
                    continue
                return peer, uri
        return None, ""

    def _note_steer(self, node_hex: str, uri: str) -> None:
        """Remember that an address was measured. Bounded on both axes, like
        every other table keyed by something a peer can influence."""
        seen = self._steer_seen.get(node_hex)
        if seen is None:
            while len(self._steer_seen) >= _DIAL_LOG_NODES:
                self._steer_seen.pop(next(iter(self._steer_seen)))
            seen = self._steer_seen[node_hex] = OrderedDict()
        seen.pop(uri, None)
        while len(seen) >= _DIAL_LOG_ADDRESSES:
            seen.pop(next(iter(seen)))
        seen[uri] = time.monotonic()

    async def _measure_peer(self, peer: '_Peer') -> float | None:
        """Average round-trip of a few pings, in milliseconds, or None."""
        samples = []
        for _ in range(_ADDR_STEER_PROBES):
            if peer.session is None:
                break
            try:
                await self.ping(peer)
            except Exception:
                break
            deadline = time.monotonic() + _DIRECT_PING_TIMEOUT
            while peer.ping_sent_at is not None and time.monotonic() < deadline:
                await asyncio.sleep(0.02)
            if peer.ping_sent_at is not None or peer.last_rtt is None:
                break
            samples.append(peer.last_rtt * 1000.0)
        if not samples:
            return None
        return round(sum(samples) / len(samples), 1)

    async def _steer_pass(self) -> str:
        """Examine one candidate address. Returns what happened, for the tests
        and the trace — never raises, and never leaves two links standing."""
        peer, uri = self._steer_candidate()
        if peer is None:
            return "nothing to examine"
        node_id = peer.authenticated_id
        node_hex = node_id.raw.hex()
        self._note_steer(node_hex, uri)
        current = await self._measure_peer(peer)
        if current is None:
            return "current link did not answer"
        candidate = await self._dial_uri(node_id, uri, _RETRY_DIAL_TIMEOUT)
        if candidate is None:
            return "candidate did not connect"
        better = False
        try:
            measured = await self._measure_peer(candidate)
            # The same score the dial order uses, so "prefer this medium" and
            # "this address is faster" are settled by one rule rather than two
            # that can disagree.
            better = (measured is not None
                      and self._address_score(uri, measured)
                      - self._address_score(peer.remote_addr or uri, current)
                      >= _ADDR_STEER_MIN_GAIN)
        finally:
            loser = peer if better else candidate
            try:
                await loser.stop()
            except Exception:
                pass
            if loser in self._peers:
                self._peers.remove(loser)
        if better:
            return "moved to " + uri
        return "kept the current address"

    def _address_status(self, node_hex: str, addresses, peer) -> list[dict]:
        """Every address we know for a node, and what happened at each.

        The live link wins over the log: an address carrying traffic right now
        is "in use" whatever it did last week."""
        now = time.monotonic()
        in_use = None
        if peer is not None:
            in_use = peer.remote_addr
            if in_use is None:
                try:
                    in_use = (peer.transport.endpoints() or {}).get("remote")
                except Exception:
                    in_use = None
        book = self._dial_log.get(node_hex) or {}
        rows = []
        for uri in list(addresses)[:_DIAL_LOG_ADDRESSES]:
            record = book.get(uri)
            if uri == in_use:
                outcome, detail, ago, took = "in-use", "", None, None
            elif record is None:
                outcome, detail, ago, took = "untried", "", None, None
            else:
                outcome = record["outcome"]
                detail = record["detail"]
                ago = max(0.0, now - record["at"])
                took = record["ms"]
            rows.append({"uri": uri, "outcome": outcome, "detail": detail,
                         "ago": ago, "ms": took})
        # An address we are connected to but never advertised (an accepted link)
        # still belongs in the list — it is the one actually carrying traffic.
        if in_use and all(row["uri"] != in_use for row in rows):
            rows.insert(0, {"uri": in_use, "outcome": "in-use", "detail": "",
                            "ago": None, "ms": None})
        return rows

    def _link_view(self, peer: '_Peer', now: float) -> dict:
        """One link, as an operator needs to see it.

        The endpoints and the extra counters come from the transport itself
        (``BaseTransport.endpoints`` / ``stats``), so a medium this file has
        never heard of describes itself and shows up in the console with no
        change here."""
        endpoints = {"local": None, "remote": None}
        stats: dict = {}
        transport = peer.transport
        try:
            endpoints = transport.endpoints() or endpoints
        except Exception:
            pass          # a transport that cannot describe itself is not a fault
        try:
            stats = {str(key)[:32]: value
                     for key, value in (transport.stats() or {}).items()
                     if isinstance(value, (int, float, str, bool)) or value is None}
        except Exception:
            stats = {}
        return {
            "scheme": self._peer_scheme(peer),
            "dialled": peer.remote_addr,
            "local": endpoints.get("local"),
            "remote": endpoints.get("remote"),
            "direction": "outbound" if peer.is_client_side else "inbound",
            "since": max(0.0, now - peer.connected_at),
            "quality": peer.quality.as_dict(),
            "counters": peer.counters.as_dict(),
            "malformed": peer._malformed,
            "stats": dict(list(stats.items())[:16]),
        }

    def _peer_scheme(self, peer: '_Peer') -> str | None:
        """Best-effort transport scheme of a peer's link, for the console."""
        addr = peer.remote_addr
        if addr and "://" in addr:
            return addr.split("://", 1)[0]
        scheme_of = getattr(self._transport_manager, "scheme_of", None)
        scheme = scheme_of(peer.transport) if scheme_of is not None else None
        if scheme is not None:
            return scheme
        from .udp_transport import UDPTransport
        if isinstance(peer.transport, UDPTransport):
            return "udp"
        return None

    def _transport_details(self) -> list[dict]:
        """Per-scheme view of the transport layer for the console: listeners,
        ports, open links — plus hole-punching state for udp://.

        `links` counts links and not nodes on purpose: a transport carries
        links, and one node reached over both tcp and udp is one link on each.
        The console labels it "Links" for the same reason."""
        listening = (self._transport_manager.listening_uris()
                     + ([self._udp_listen_uri] if self._udp_listen_uri else []))
        by_scheme: dict[str, list[str]] = {}
        for uri in listening:
            parsed = _validate_uri(uri)
            if parsed is not None:
                by_scheme.setdefault(parsed[0], []).append(uri)

        links_by_scheme: dict[str, int] = {}
        for p in self._peers:
            scheme = self._peer_scheme(p)
            if scheme is not None:
                links_by_scheme[scheme] = links_by_scheme.get(scheme, 0) + 1

        self._prune_punch_pending()
        details: list[dict] = []
        schemes = set(self._transport_manager.schemes()) | set(by_scheme)
        if self._udp_server is not None:
            schemes.add("udp")
        for scheme in sorted(schemes):
            uris = by_scheme.get(scheme, [])
            ports: list[int] = []
            for uri in uris:
                hp = split_host_port(_validate_uri(uri)[1])
                if hp is not None:
                    try:
                        ports.append(int(hp[1]))
                    except ValueError:
                        pass
            entry: dict = {
                "scheme": scheme,
                "listening": uris,
                "ports": sorted(set(ports)),
                "links": links_by_scheme.get(scheme, 0),
            }
            if scheme == "udp":
                now = time.monotonic()
                ready, reason = self._punch_readiness()
                entry["hole_punch"] = {
                    "udp_port": self.udp_port(),
                    "keepalive": self._punch_keepalive,
                    "public_udp": (f"{self._observed_udp_addr[0]}:"
                                   f"{self._observed_udp_addr[1]}"
                                   if self._observed_udp_addr else None),
                    "ready": ready,
                    "reason": reason,
                    "relay_nodes": self._relay_node_count(),
                    "manual_holes": [{
                        "addr": f"{h}:{p}",
                        "sent": e["sent"],
                        "active": not e["task"].done(),
                        "age": now - e["started"],
                    } for (h, p), e in self._manual_holes.items()],
                    "stats": dict(self._punch_stats),
                    "pending": [{
                        "target": s.target.raw.hex(),
                        "remote_addr": s.remote_udp_addr,
                        "probes_sent": s.probes_sent,
                        "probes_received": s.probes_received,
                        "ack_received": s.ack_received,
                        "expires_in": max(0.0, s.deadline - now),
                    } for s in self._punch_pending.values()],
                }
            details.append(entry)
        return details

    def _relay_node_count(self) -> int:
        """How many *nodes* could coordinate a punch (or be relayed between).
        Hole punching is impossible without at least one.

        Nodes, not links: two links to the same node are still one coordinator,
        and counting links here would have told the operator they had two ways
        through when they had one."""
        return len(self._authenticated_peers())

    def _punch_readiness(self) -> tuple[bool, str]:
        """Explain, for the console, whether a punch can happen right now.

        Punching is on-demand: it only fires when this node tries to reach a
        peer it can't connect to directly AND shares a relay with. This tells
        the operator why nothing is punching — the top question behind NAT."""
        if not self._punch_enabled:
            return False, "hole punching is off"
        if self._udp_server is None:
            return False, "no UDP listener — start UDP first"
        relays = self._relay_node_count()
        if relays == 0:
            return False, ("no connected node to coordinate through — join a "
                           "reachable node (a public rendezvous) first")
        return True, (f"ready — {relays} node(s) can coordinate a punch; it "
                      "fires on demand when you reach an unreachable node")

    def console_set_punch_enabled(self, enabled: bool) -> bool:
        """Enable/disable UDP hole punching at runtime (default: enabled).
        Disabling also drops in-flight punch attempts."""
        self._punch_enabled = bool(enabled)
        if not self._punch_enabled:
            self._punch_pending.clear()
        return self._punch_enabled

    async def console_start_udp(self, port: int) -> None:
        if not isinstance(port, int) or not (0 < port < 65536):
            raise ValueError("invalid port")
        await self.start_udp(port)

    async def console_stop_udp(self) -> None:
        await self.stop_udp()

    def console_recheck_net(self) -> bool:
        """Force an immediate network re-check (rate-limited by the monitor)."""
        if self._net_monitor is None:
            return False
        self._net_monitor.poke("manual")
        return True

    async def console_add_listen(self, uri: str) -> None:
        if not isinstance(uri, str) or not (0 < len(uri) <= _MAX_URI_LEN):
            raise ValueError("invalid URI")
        parsed = _validate_uri(uri)
        if parsed is None:
            raise ValueError("invalid URI")
        if not self._transport_manager.is_supported(parsed[0]):
            raise ValueError(f"unsupported scheme: {parsed[0]}")
        await self.add_listen(uri)

    async def console_remove_listen(self, uri: str) -> bool:
        return await self.remove_listen(uri)

    # -- two-step connect exchange ----------------------------------------
    # The simple way to link two nodes with no shared relay: B (joiner) makes
    # a request block → paste into A (host) → A returns an invite block →
    # paste into B → B connects. Each side opens a NAT hole toward the other's
    # UDP endpoints during the exchange, so the join traverses both NATs.

    def console_connect_request(self) -> str:
        """Step 1 (joiner): a base64 block listing the endpoints we can be
        reached at. Hand it to the node you want to join."""
        return _encode_conn_block("req",
                                  uris=self.advertised_uris()[:_JOIN_BLOCK_MAX_URIS])

    def console_connect_accept(self, block: str) -> str:
        """Step 2 (host): ingest the joiner's request, open NAT holes toward
        its UDP endpoints, mint a one-time code, and return an invite block to
        send back. The block is hostile input — fully validated."""
        data = _decode_conn_block(block, "req")
        peer_uris = self._valid_candidate_uris(data.get("uris"))
        self._open_holes_from_uris(peer_uris, _CONN_HOLE_SUSTAIN)
        code = self._invite.generate_code()
        return _encode_conn_block("inv", code=code,
                                  uris=self.advertised_uris()[:_JOIN_BLOCK_MAX_URIS])

    def console_connect_complete(self, block: str) -> dict:
        """Step 3 (joiner): ingest the host's invite, open NAT holes toward its
        UDP endpoints, and join it over every advertised address."""
        data = _decode_conn_block(block, "inv")
        code = data.get("code")
        if not isinstance(code, str) or not (0 < len(code) <= 64):
            raise ValueError("invalid code in block")
        candidates = self._valid_candidate_uris(data.get("uris"))
        self._open_holes_from_uris(candidates, _CONN_HOLE_SUSTAIN)
        return self._start_join(candidates, code)

    def _valid_candidate_uris(self, uris) -> list[str]:
        """Validate a pasted URI list (hostile input): bounded, well-formed,
        and only schemes this node actually has a transport for. Ordered to try
        a global IPv6 address first — no NAT there, so a direct link often
        works where IPv4 would need punching or a relay."""
        if not isinstance(uris, list) or not uris:
            raise ValueError("no addresses in block")
        out: list[str] = []
        for uri in uris[:_JOIN_BLOCK_MAX_URIS]:
            if not isinstance(uri, str) or len(uri) > _MAX_URI_LEN:
                continue
            parsed = _validate_uri(uri)
            if parsed is None or not self._transport_manager.is_supported(parsed[0]):
                continue
            if uri not in out:
                out.append(uri)
        if not out:
            raise ValueError("no address uses a transport this node supports")
        return self._preferred(out)

    def _open_holes_from_uris(self, uris: list[str], duration: float) -> int:
        """Open a NAT hole toward every udp:// endpoint in *uris*. No-op without
        a UDP listener. Bounded by the manual-hole table."""
        if self._udp_server is None:
            return 0
        opened = 0
        for uri in uris:
            parsed = _validate_uri(uri)
            if parsed is None or parsed[0] != "udp":
                continue
            hp = split_host_port(parsed[1])
            if hp is None:
                continue
            try:
                self.console_open_hole(hp[0], int(hp[1]), duration)
                opened += 1
            except ValueError:
                continue
        return opened

    def _start_join(self, candidates: list[str], code: str) -> dict:
        if self._join_task is not None and not self._join_task.done():
            raise ValueError("a join is already in progress")
        self._join_status = {"running": True, "current": None,
                             "tried": [], "connected": None}
        self._join_task = asyncio.create_task(
            self._join_block_task(candidates, code))
        return {"candidates": len(candidates)}

    # -- relayed invitation (single block, no direct link needed) -----------

    def _select_relays(self, limit: int = 5) -> list[str]:
        """Addresses of nodes that can bridge an invitation to us. We pick the
        reachable peers we dialled (we reached them, so a joiner likely can
        too), preferring the freshest. Bounded."""
        out: list[str] = []
        seen: set[str] = set()
        for p in self._peers:
            if (p.authenticated_id is not None and p.session is not None
                    and p.is_client_side and p.remote_addr
                    and _validate_uri(p.remote_addr) is not None
                    and p.remote_addr not in seen):
                seen.add(p.remote_addr)
                out.append(p.remote_addr)
            if len(out) >= limit:
                break
        return out

    def console_relay_invite(self) -> str:
        """Generate a single invite block for a node we want to bring in, even
        with no direct link: it carries a signed rendezvous token plus a list
        of relays the joiner can reach us through."""
        code = self._invite.generate_code()
        exp = int(time.time()) + _RELAY_INVITE_TTL
        token = self._identity.sign(_seek_signed_blob(_h_code(code), exp))
        payload = {
            "v": 3, "kind": "relay-inv", "code": code, "exp": exp,
            "pub": self._identity.dsa_public_key.hex(),
            "token": token.hex(), "relays": self._select_relays(),
        }
        return base64.b64encode(
            json.dumps(payload, separators=(",", ":")).encode("utf-8")
        ).decode("ascii")

    def console_relay_join(self, block: str) -> dict:
        """Ingest a relay-invite block and join in the background: route a
        signed seek toward the inviter through each relay until the tunnelled
        handshake yields a session. Hostile input — fully validated."""
        # relay-inv is v3 (not the v2 connect exchange) — parse explicitly
        if not isinstance(block, str) or not (0 < len(block) <= _RELAY_BLOCK_MAX_LEN):
            raise ValueError("invalid block")
        try:
            data = json.loads(base64.b64decode("".join(block.split()), validate=True))
        except Exception:
            raise ValueError("invalid or corrupt block") from None
        if not isinstance(data, dict) or data.get("v") != 3 or data.get("kind") != "relay-inv":
            raise ValueError("not a relay-invite block")
        code = data.get("code")
        if not isinstance(code, str) or not (0 < len(code) <= 64):
            raise ValueError("invalid code in block")
        exp = data.get("exp")
        if not isinstance(exp, int) or exp < time.time():
            raise ValueError("invite block expired")
        try:
            inviter_pub = bytes.fromhex(data.get("pub", ""))
            token = bytes.fromhex(data.get("token", ""))
        except (ValueError, TypeError):
            raise ValueError("malformed block fields") from None
        if not inviter_pub or not token:
            raise ValueError("malformed block fields")
        try:
            inviter_id = NodeID.from_public_key(inviter_pub)
        except Exception:
            raise ValueError("bad inviter key") from None
        if inviter_id == self._id:
            raise ValueError("that is our own invite")
        relays = data.get("relays")
        candidates: list[str] = []
        if isinstance(relays, list):
            for uri in relays[:_JOIN_BLOCK_MAX_URIS]:
                if (isinstance(uri, str) and len(uri) <= _MAX_URI_LEN
                        and _validate_uri(uri) is not None
                        and uri not in candidates):
                    parsed = _validate_uri(uri)
                    if self._transport_manager.is_supported(parsed[0]):
                        candidates.append(uri)
        candidates = self._preferred(candidates)
        # No relay in the block is not fatal if we can look for one on the LAN
        # (a broadcast-capable transport is up).
        can_discover = self._udp_server is not None
        if not candidates and not can_discover:
            raise ValueError("no reachable relay in block")
        if self._join_task is not None and not self._join_task.done():
            raise ValueError("a join is already in progress")
        self._join_status = {"running": True, "current": None,
                             "tried": [], "connected": None}
        self._join_task = asyncio.create_task(
            self._relay_join_task(inviter_id, inviter_pub, code, exp, token,
                                  candidates, discover=can_discover))
        return {"relays": len(candidates)}

    # -- LAN relay discovery (broadcast) ------------------------------------

    def _lan_relay_addrs(self) -> list[str]:
        """Addresses a LAN peer can reach us at to relay through — our own
        reachable addresses. Answered to discovery beacons."""
        out: list[str] = []
        seen: set[str] = set()
        for d in self.reachability():
            a = d.get("address")
            if a and a not in seen:
                seen.add(a)
                out.append(a)
        return out[:8]

    async def start_lan_discovery(self) -> None:
        """Answer LAN discovery beacons so joiners on our medium can find us as
        a relay. Opt-in — it exposes our addresses to the local broadcast domain."""
        if self._lan_discovery is not None:
            return
        from .lan_discovery import LanDiscovery
        disc = LanDiscovery(self._id.raw, self._lan_relay_addrs)
        try:
            await disc.start()
        except Exception:
            return
        self._lan_discovery = disc

    async def stop_lan_discovery(self) -> None:
        if self._lan_discovery is not None:
            await self._lan_discovery.stop()
            self._lan_discovery = None

    async def discover_lan_relays(self, timeout: float = 1.5,
                                  targets: tuple = ("255.255.255.255",)) -> list[str]:
        """Broadcast a beacon and collect relay addresses from LAN members.
        Only URIs whose scheme we support are returned. Bounded."""
        from .lan_discovery import LanDiscovery
        try:
            found = await LanDiscovery(self._id.raw, lambda: []).discover(
                timeout=timeout, targets=targets)
        except Exception:
            return []
        out: list[str] = []
        for uri in found[:_JOIN_BLOCK_MAX_URIS]:
            parsed = _validate_uri(uri)
            if (parsed is not None and len(uri) <= _MAX_URI_LEN
                    and self._transport_manager.is_supported(parsed[0])
                    and uri not in out):
                out.append(uri)
        return out

    def _seek_from_block(self, inviter_id: NodeID, inviter_pub: bytes,
                         code: str, exp: int, token: bytes) -> Packet:
        payload = _encode_seek(exp, _h_code(code), inviter_pub, token)
        return Packet.create(INVITE_SEEK, self._id.raw, inviter_id.raw,
                             payload, ttl=_SEEK_TTL)

    async def _relay_join_task(self, inviter_id, inviter_pub, code, exp, token,
                               relays: list[str], discover: bool = False) -> None:
        status = self._join_status
        try:
            candidates = list(relays)
            # Opportunistic: ask the LAN if a member can relay us, and append
            # any answers we don't already have.
            if discover:
                status["current"] = "discovering relays on LAN…"
                for uri in await self.discover_lan_relays():
                    if uri not in candidates:
                        candidates.append(uri)
            if not candidates:
                status["tried"].append({"uri": "-", "error": "no relay found"})
                return
            for uri in candidates:
                status["current"] = uri
                try:
                    if await self._relay_join_one(uri, inviter_id, inviter_pub,
                                                  code, exp, token):
                        status["connected"] = uri
                        return
                    status["tried"].append({"uri": uri, "error": "no session"})
                except Exception as exc:
                    status["tried"].append(
                        {"uri": uri, "error": (str(exc) or type(exc).__name__)[:80]})
        finally:
            status["running"] = False
            status["current"] = None

    async def _relay_join_one(self, relay_uri: str, inviter_id: NodeID,
                              inviter_pub: bytes, code: str, exp: int,
                              token: bytes) -> bool:
        """Open a relay link, launch a tunnelled invite handshake toward the
        inviter, and wait for a session. Cleans up on failure."""
        rlink = None
        vpa = None
        try:
            transport = await self._transport_manager.connect(relay_uri)
            rlink = _Peer(transport, is_client_side=True)
            rlink.relay_only = True
            rlink.on_dead = self._reap_peer
            rlink.total = self._metrics.total
            rlink.remote_addr = relay_uri
            self._peers.append(rlink)
            self._running = True
            await rlink.start(self._handle_packet)

            vpa = _Peer(RelayedTransport(self, inviter_id, rlink), is_client_side=True)
            vpa.join_code = code
            vpa.on_dead = self._relay_on_dead(inviter_id.raw)
            vpa.total = self._metrics.total
            self._relay_peers[inviter_id.raw] = vpa
            self._peers.append(vpa)
            await vpa.start(self._handle_packet)

            await rlink.send(self._seek_from_block(inviter_id, inviter_pub,
                                                   code, exp, token))

            deadline = time.monotonic() + self._relay_join_timeout
            while time.monotonic() < deadline:
                if vpa.session is not None and vpa.authenticated_id == inviter_id:
                    return True
                if vpa not in self._peers or rlink not in self._peers:
                    break
                await asyncio.sleep(0.05)
            return False
        finally:
            if (vpa is not None and
                    (vpa.session is None or vpa.authenticated_id != inviter_id)):
                self._relay_peers.pop(inviter_id.raw, None)
                if vpa is not None:
                    await self._safe_stop_peer(vpa)
                if rlink is not None:
                    await self._safe_stop_peer(rlink)

    async def _safe_stop_peer(self, peer: '_Peer') -> None:
        try:
            await peer.stop()
        except Exception:
            pass
        if peer in self._peers:
            self._peers.remove(peer)

    def console_invite_block(self) -> str:
        """A shareable join bundle: base64 JSON with a fresh invite code and
        every URI we advertise. The receiving node tries them all."""
        code = self._invite.generate_code()
        payload = {"v": 1, "code": code,
                   "uris": self.advertised_uris()[:_JOIN_BLOCK_MAX_URIS]}
        return base64.b64encode(
            json.dumps(payload, separators=(",", ":")).encode("utf-8")
        ).decode("ascii")

    def console_join_block(self, block: str) -> dict:
        """Validate a one-shot invite block and start joining in the background.

        The block is attacker-supplied input (pasted by the operator, but
        crafted by whoever produced it): every field is type- and size-checked,
        addresses are capped and URI-validated, and only schemes with a
        registered transport are kept.
        """
        if not isinstance(block, str) or not (0 < len(block) <= _JOIN_BLOCK_MAX_LEN):
            raise ValueError("invalid block")
        try:
            data = json.loads(base64.b64decode("".join(block.split()), validate=True))
        except Exception:
            raise ValueError("invalid block") from None
        if not isinstance(data, dict) or data.get("v") != 1:
            raise ValueError("unsupported block version")
        code = data.get("code")
        if not isinstance(code, str) or not (0 < len(code) <= 64):
            raise ValueError("invalid code in block")
        candidates = self._valid_candidate_uris(data.get("uris"))
        return self._start_join(candidates, code)

    async def _join_block_task(self, uris: list[str], code: str) -> None:
        """Try each candidate URI until one yields an authenticated session."""
        status = self._join_status
        try:
            for uri in uris:
                status["current"] = uri
                peer = None
                try:
                    peer = await asyncio.wait_for(
                        self.join(uri, code), self._join_try_timeout)
                    deadline = time.monotonic() + self._join_try_timeout
                    while peer.session is None:
                        if time.monotonic() >= deadline:
                            raise TimeoutError("no session established")
                        if peer not in self._peers:
                            raise ConnectionError("link died")
                        await asyncio.sleep(0.05)
                    status["connected"] = uri
                    return
                except Exception as exc:
                    if peer is not None:
                        try:
                            await peer.stop()
                        except Exception:
                            pass
                        if peer in self._peers:
                            self._peers.remove(peer)
                    status["tried"].append(
                        {"uri": uri,
                         "error": (str(exc) or type(exc).__name__)[:80]})
        finally:
            status["running"] = False
            status["current"] = None

    def console_root_cert_hex(self) -> str:
        """Our self-signed root cert, hex-encoded — paste it into another node's
        console to have that node trust ours."""
        return self._identity.self_signed_cert().serialize().hex()

    def console_add_root(self, cert_hex: str) -> bool:
        """Trust another node's self-signed root cert (hex). Returns success."""
        try:
            cert = Certificate.deserialize(bytes.fromhex(cert_hex))
        except Exception:
            return False
        if not cert.is_self_signed:
            return False
        self._cert_add(cert)
        self._cert_store.add_root(cert.subject_id)
        return True

    def _cert_add(self, cert: Certificate) -> bool:
        """Take one certificate and mark the store for writing.

        `CertStore.save` serialises the *whole* store to hex JSON and writes it,
        synchronously. Doing that per certificate meant absorbing one chain of
        six re-wrote a multi-megabyte file six times, inside a receive loop.
        Same shape as `_persist_state`: mark dirty, let one task write."""
        ok = self._cert_store.add(cert)
        if ok and self._cert_store_path:
            self._certs_dirty = True
            self._ensure_state_writer()
            if self._state_task is None:
                self._write_certs_now()   # no loop to write on
        return ok

    def _write_certs_now(self) -> None:
        if not self._cert_store_path:
            return
        self._certs_dirty = False
        try:
            self._cert_store.save(self._cert_store_path)
        except Exception:
            pass          # a disk problem must not take the node down

    def _is_seen(self, msg_id: int) -> bool:
        """Have we handled this exact packet already? Records it if not.

        A set of ids, FIFO-evicted. It used to store `time.monotonic()` against
        each one — a value nothing ever read, paid for on every routable packet."""
        if msg_id in self._seen_msgs:
            return True
        if len(self._seen_msgs) >= _MSG_DEDUP_MAX:
            self._seen_msgs.popitem(last=False)
        self._seen_msgs[msg_id] = None
        return False

    async def _forward_packet(self, from_peer: _Peer, packet: Packet) -> None:
        if packet.ttl <= 1:
            return
        target = NodeID(packet.dst_id)
        # Each hop repeats the ordered neighbor fallback. If the closest link
        # fails during send, the packet still gets every other bounded candidate
        # before it is dropped; TTL and msg_id dedup stop loops and flooding.
        peer = await self._send_to_candidates(
            packet, self._route_candidates(target, exclude=from_peer),
            decrement=True)
        if peer is not None:
            return
        # No live relay. Acquiring one takes seconds and must not happen here:
        # this runs in from_peer's receive loop, so an inline lookup/dial froze
        # that link — and the FOUND_NODE it waits for often has to arrive over
        # that very link, which made the wait unwinnable. Defer it.
        self._defer_route(packet, decrement=True, exclude=from_peer)

    async def _handle_packet(self, peer: _Peer, packet: Packet) -> None:
        if packet.type == INVITE_SEEK:
            # Pre-auth, token-gated, bounded — handled entirely on its own.
            await self._handle_invite_seek(peer, packet)
            return
        if packet.type == RELAY_CARRY:
            await self._handle_relay_carry(peer, packet)
            return
        if packet.type in _DIRECT_TYPES:
            if peer.authenticated_id is None:
                return
            if packet.src_id != peer.authenticated_id.raw:
                return
        if packet.type in _ROUTABLE_TYPES:
            if peer.authenticated_id is None:
                return
            # msg_id must commit to the packet's content. This stops a relay from
            # minting fresh msg_ids for the same payload to slip past dedup and
            # amplify a flood — any tampering to change the id also breaks it.
            if packet.msg_id != packet.compute_msg_id():
                return
            if self._is_seen(packet.msg_id):
                return
            # Past the gates the packet is well-formed, fresh, and came off an
            # authenticated link: record that link as a path back to its source
            # so the reply follows the way the request came.
            self._learn_reverse_path(peer, packet)
            if packet.dst_id != self._id.raw and packet.dst_id != _BROADCAST_ID:
                await self._forward_packet(peer, packet)
                return
        handler = _HANDLERS.get(packet.type)
        if handler:
            await handler(self, peer, packet)

    # -----------------------------------------------------------------------
    # Relayed invitation (INVITE_SEEK)
    # -----------------------------------------------------------------------

    @staticmethod
    def _rate_key(peer: '_Peer') -> bytes:
        """What a rate-limit table counts against.

        The authenticated identity where there is one, the remote address
        otherwise (the pre-auth planes have nothing better). Never ``id(peer)``:
        that is the object's address, CPython reuses it as soon as the object is
        collected, and the tables are pruned by window expiry rather than by
        peer lifetime — so an entry outlived the peer it described and a fresh
        `_Peer` landing on a freed address inherited its count. Both directions
        were wrong: an honest peer born already throttled, and an adversary
        shedding an exhausted budget by reconnecting, which made every one of
        these a per-connection limit rather than a per-peer one."""
        if peer.authenticated_id is not None:
            return peer.authenticated_id.raw
        try:
            remote = peer.transport.remote_ip()
        except Exception:
            remote = None
        return (b"ip:" + remote.encode("utf-8", "replace")) if remote \
            else b"anon:%d" % id(peer)

    def _seek_allowed(self, peer: '_Peer') -> bool:
        """Per-ingress-link rate limit: bound how many seeks one link can make
        us process (and verify) in a window. Table is bounded and pruned."""
        now = time.monotonic()
        for k in [k for k, (_, ws) in self._seek_rate.items()
                  if now - ws > _SEEK_RATE_WINDOW]:
            del self._seek_rate[k]
        while len(self._seek_rate) > _RDV_MAX:
            self._seek_rate.popitem(last=False)
        key = self._rate_key(peer)
        cnt, ws = self._seek_rate.get(key, (0, now))
        if now - ws > _SEEK_RATE_WINDOW:
            cnt, ws = 0, now
        if cnt >= _SEEK_RATE_MAX:
            self._seek_rate[key] = (cnt, ws)
            return False
        self._seek_rate[key] = (cnt + 1, ws)
        return True

    def _rdv_record(self, seeker_raw: bytes, peer: '_Peer') -> None:
        """Remember the reverse path for a seeker (bounded, short-lived) so the
        inviter's reply can be routed back on the link the seek arrived on."""
        self._rdv.pop(seeker_raw, None)
        while len(self._rdv) >= _RDV_MAX:
            self._rdv.popitem(last=False)
        self._rdv[seeker_raw] = (peer, time.monotonic() + _RDV_TTL)

    def _rdv_lookup(self, seeker_raw: bytes) -> '_Peer | None':
        entry = self._rdv.get(seeker_raw)
        if entry is None:
            return None
        peer, exp = entry
        if time.monotonic() > exp or peer not in self._peers:
            self._rdv.pop(seeker_raw, None)
            return None
        return peer

    def _recognize_seek(self, h_code: bytes) -> str | None:
        """The live invite code whose hash matches, if any (constant-time).

        *Live*: an expired code is not one. Matching on the hash alone meant an
        expired code still looked recognised and still started a relayed invite,
        allocating a virtual peer against `_MAX_RELAY_PEERS` and `_MAX_PEERS`
        for something that could never be redeemed."""
        for code in self._invite.live_codes():
            if hmac.compare_digest(_h_code(code), h_code):
                return code
        return None

    async def _handle_invite_seek(self, peer: '_Peer', packet: Packet) -> None:
        """Process a relayed invitation seek. Cheap, bounded checks run before
        the expensive signature verification; nothing here can crash the loop."""
        # 1. cheap structural / bound checks first
        if packet.ttl <= 0:
            return
        # The rate limit comes BEFORE the dedup table, because `_is_seen` is not
        # a query — it inserts. This handler runs pre-auth, so any socket that
        # connects reached it; with the order the other way round an
        # unauthenticated peer flushed the whole node-wide replay window
        # (`_MSG_DEDUP_MAX` entries, FIFO) at line rate, and dedup is what stops
        # a routed packet looping and a relay re-injecting the same payload.
        if not self._seek_allowed(peer):
            return
        if packet.msg_id != packet.compute_msg_id():
            return  # msg_id must commit to content (anti-amplification)
        if self._is_seen(packet.msg_id):
            return
        decoded = _decode_seek(packet.payload)
        if decoded is None:
            return
        exp, h_code, inviter_pub, token = decoded
        now = time.time()
        if exp < now or exp > now + _SEEK_MAX_FUTURE:
            return  # expired or absurdly far ahead
        inviter = NodeID(packet.dst_id)
        seeker = NodeID(packet.src_id)
        if seeker == self._id:
            return  # our own seek looped back
        # 2. expensive verification last: key↔id binding + token signature
        try:
            if NodeID.from_public_key(inviter_pub) != inviter:
                return  # a NodeID not derivable from the presented key is a lie
            if not self._identity.verify(_seek_signed_blob(h_code, exp), token,
                                         inviter_pub):
                return  # not authorised by the inviter's key — drop
        except Exception:
            return
        # 3. legit seek: remember the reverse path (bounded)
        self._rdv_record(packet.src_id, peer)
        if inviter == self._id:
            self._on_seek_for_self(seeker, h_code, inviter_pub, peer)
            return
        # 4. relay toward the inviter over authenticated member links only
        await self._forward_seek(peer, packet)

    def _on_seek_for_self(self, seeker: NodeID, h_code: bytes,
                          inviter_pub: bytes, peer: '_Peer') -> None:
        """A valid seek addressed to us. If it names a live invite code we
        answer it: open a relayed virtual peer for the seeker and drive the
        invite handshake through the relay it arrived on."""
        recognized = self._recognize_seek(h_code) is not None
        while len(self._pending_seeks) >= _MAX_PENDING_SEEKS:
            self._pending_seeks.popitem(last=False)
        self._pending_seeks[seeker.raw] = {
            "h_code": h_code, "recognized": recognized,
            "peer": peer, "at": time.monotonic(),
        }
        if recognized and seeker.raw not in self._relay_peers:
            self._spawn_bounded(self._start_relay_invite(seeker, peer))

    async def _start_relay_invite(self, seeker: NodeID, via: '_Peer') -> None:
        """Inviter side: challenge the seeker over a relayed virtual peer,
        mirroring _on_new_transport but tunnelled through *via*."""
        if seeker.raw in self._relay_peers or seeker == self._id:
            return
        if len(self._relay_peers) >= _MAX_RELAY_PEERS or len(self._peers) >= _MAX_PEERS:
            return
        vp = _Peer(RelayedTransport(self, seeker, via), is_client_side=False)
        vp.on_dead = self._relay_on_dead(seeker.raw)
        vp.total = self._metrics.total
        self._relay_peers[seeker.raw] = vp
        self._peers.append(vp)
        await vp.start(self._handle_packet)
        challenge = self._invite.generate_challenge()
        vp.pending_challenge = challenge
        pkt = Packet.create(CHALLENGE, self._id.raw, _BROADCAST_ID, challenge)
        try:
            await vp.send(pkt)
        except Exception:
            pass

    def _relay_on_dead(self, remote_raw: bytes):
        async def _cb(peer: '_Peer') -> None:
            if self._relay_peers.get(remote_raw) is peer:
                self._relay_peers.pop(remote_raw, None)
            await self._reap_peer(peer)
        return _cb

    def _carry_allowed(self, peer: '_Peer') -> bool:
        """Per-ingress-link rate limit for relay-carry packets (bounded table)."""
        now = time.monotonic()
        for k in [k for k, (_, ws) in self._carry_rate.items()
                  if now - ws > _SEEK_RATE_WINDOW]:
            del self._carry_rate[k]
        while len(self._carry_rate) > _RDV_MAX:
            self._carry_rate.popitem(last=False)
        key = self._rate_key(peer)
        cnt, ws = self._carry_rate.get(key, (0, now))
        if now - ws > _SEEK_RATE_WINDOW:
            cnt, ws = 0, now
        if cnt >= _CARRY_RATE_MAX:
            self._carry_rate[key] = (cnt, ws)
            return False
        self._carry_rate[key] = (cnt + 1, ws)
        return True

    async def _handle_relay_carry(self, peer: '_Peer', packet: Packet) -> None:
        """Route a RELAY_CARRY toward its destination, or — if it is for us —
        unwrap the inner handshake packet and feed the matching virtual peer.
        Bounded: TTL, dedup, per-link rate limit."""
        if packet.ttl <= 0:
            return
        # Same order as the seek handler, and for the same reason: this is
        # pre-auth, and `_is_seen` mutates a node-wide table.
        if not self._carry_allowed(peer):
            return
        if packet.msg_id != packet.compute_msg_id():
            return
        if self._is_seen(packet.msg_id):
            return
        if packet.dst_id == self._id.raw:
            vp = self._relay_peers.get(packet.src_id)
            if vp is None:
                return  # no active rendezvous with this endpoint
            try:
                inner = Packet.unpack(packet.payload)
            except Exception:
                return
            vp.transport.feed(inner)
            return
        # route onward: reverse path (a seeker we bridged) first, else forward
        rp = self._rdv_lookup(packet.dst_id)
        if rp is not None and rp is not peer:
            if packet.ttl > 1:
                await rp.send(packet.with_decremented_ttl())
            return
        await self._forward_seek(peer, packet)

    async def _forward_seek(self, from_peer: '_Peer', packet: Packet) -> None:
        """Greedy XOR routing of a seek toward its inviter id, over authenticated
        peers only. TTL-bounded; no on-demand connects (stays cheap pre-auth).

        A seek from a link that has **not** authenticated gets a shorter budget.
        This plane exists so a joiner with no link yet can be heard, which is
        exactly why any socket that connects reaches it — and each packet it
        hands us is then carried by up to `_SEEK_TTL` authenticated links. The
        joiner needs enough hops to reach an inviter, not the full diameter."""
        if packet.ttl <= 1:
            return
        if (from_peer.authenticated_id is None
                and packet.ttl > _SEEK_TTL_PREAUTH):
            packet = packet.with_ttl(_SEEK_TTL_PREAUTH)
        target = NodeID(packet.dst_id)
        direct = next(
            (p for p in self._peers
             if p is not from_peer and p.authenticated_id == target
             and p.session is not None),
            None,
        )
        if direct is not None:
            await direct.send(packet.with_decremented_ttl())
            return
        candidates = [
            p for p in self._peers
            if p is not from_peer and p.authenticated_id is not None
            and p.session is not None
        ]
        if candidates:
            best = min(candidates,
                       key=lambda p: target.distance(p.authenticated_id))
            await best.send(packet.with_decremented_ttl())

    # -----------------------------------------------------------------------
    # AutoNAT — active reachability confirmation
    # -----------------------------------------------------------------------

    async def probe_reachability(self) -> int:
        """Ask an authenticated peer to dial each scheme we listen on and tell
        us whether it worked — proactive confirmation (beyond the passive
        'someone reached us' signal). Returns how many probes were sent."""
        peer = next((p for p in self._peers
                     if p.authenticated_id is not None and p.session is not None
                     and not isinstance(p.transport, RelayedTransport)), None)
        if peer is None:
            return 0
        sent = 0
        for uri in self._transport_manager.listening_uris():
            parsed = _validate_uri(uri)
            if parsed is None:
                continue
            hp = split_host_port(parsed[1])
            if hp is None:
                continue
            try:
                port = int(hp[1])
            except ValueError:
                continue
            scheme = parsed[0].encode("utf-8")[:16]
            payload = struct.pack("!BH", len(scheme), port) + scheme
            try:
                await peer.send(Packet.create(REACH_PROBE, self._id.raw,
                                              peer.authenticated_id.raw, payload))
                self._note_reach_probe(peer.authenticated_id, parsed[0])
                sent += 1
            except Exception:
                pass
        return sent

    def _note_reach_probe(self, asked: NodeID, scheme: str) -> None:
        """Remember that we asked *this* peer about *this* scheme.

        Without it the ACK is an unsolicited claim any authenticated peer can
        make at any time — and `_inbound_schemes` decides what we advertise and
        whether we offer ourselves as a relay, so one peer could make a NATted
        node announce itself as reachable and become a black hole for everyone
        routing through it."""
        now = time.monotonic()
        for key in [k for k, exp in self._reach_pending.items() if exp <= now]:
            del self._reach_pending[key]
        while len(self._reach_pending) >= _REACH_PENDING_MAX:
            self._reach_pending.popitem(last=False)
        self._reach_pending[(asked.raw, scheme)] = now + _REACH_PENDING_TTL

    def _reach_probe_allowed(self, peer: '_Peer') -> bool:
        now = time.monotonic()
        for k in [k for k, (_, ws) in self._reach_probe_rate.items()
                  if now - ws > _SEEK_RATE_WINDOW]:
            del self._reach_probe_rate[k]
        while len(self._reach_probe_rate) > _RDV_MAX:
            self._reach_probe_rate.popitem(last=False)
        key = self._rate_key(peer)
        cnt, ws = self._reach_probe_rate.get(key, (0, now))
        if now - ws > _SEEK_RATE_WINDOW:
            cnt, ws = 0, now
        if cnt >= _REACH_PROBE_RATE_MAX:
            self._reach_probe_rate[key] = (cnt, ws)
            return False
        self._reach_probe_rate[key] = (cnt + 1, ws)
        return True

    async def _handle_reach_probe(self, peer: _Peer, packet: Packet) -> None:
        """A peer asks us to confirm it is reachable. We dial back the address
        we OBSERVED it come from (never an arbitrary one → no amplification)
        and report whether an NMesh node answered."""
        try:
            slen, port = struct.unpack_from("!BH", packet.payload, 0)
            scheme = packet.payload[3:3 + slen].decode("ascii")
        except Exception:
            return
        if not scheme or port <= 0 or port >= 65536:
            return
        if not self._transport_manager.is_supported(scheme):
            return
        if not self._reach_probe_allowed(peer):
            return
        if self._reach_dials_active >= _REACH_DIALS_MAX:
            return
        # Dial ONLY the address we observed this peer at — never a value it
        # supplied — so it can never make us dial an arbitrary victim.
        observed = peer.transport.remote_ip()
        if observed is None:
            return
        # …and never inline. A dial-back is two bounded waits of
        # _REACH_DIAL_TIMEOUT, and the rate limit allows five per window: awaited
        # here they hold this peer's receive loop for longer than the window
        # lasts, so it never catches up (gotchas §10).
        self._spawn_bounded(self._reach_probe_answer(peer, packet.src_id,
                                                     scheme, observed, port))

    async def _reach_probe_answer(self, peer: '_Peer', dst: bytes, scheme: str,
                                  observed: str, port: int) -> None:
        """Dial the peer back and tell it what happened. Off the receive loop."""
        self._reach_dials_active += 1
        try:
            ok = await self._dial_back(scheme, observed, port)
        finally:
            self._reach_dials_active -= 1
        reply = struct.pack("!BB", len(scheme.encode()), 1 if ok else 0) + scheme.encode()
        try:
            await peer.send(Packet.create(REACH_PROBE_ACK, self._id.raw,
                                          dst, reply))
        except Exception:
            pass

    async def _dial_back(self, scheme: str, ip: str, port: int) -> bool:
        """Open a connection to ip:port and confirm an NMesh node answers (it
        challenges on accept). Bounded by a timeout; always cleaned up."""
        from .ip_utils import _fmt_host
        addr = f"{scheme}://{_fmt_host(ip)}:{port}"
        transport = None
        try:
            transport = await asyncio.wait_for(
                self._transport_manager.connect(addr), _REACH_DIAL_TIMEOUT)
            pkt = await asyncio.wait_for(transport.receive(), _REACH_DIAL_TIMEOUT)
            return pkt.type == CHALLENGE
        except Exception:
            return False
        finally:
            if transport is not None:
                try:
                    await transport.close()
                except Exception:
                    pass

    async def _handle_reach_probe_ack(self, peer: _Peer, packet: Packet) -> None:
        try:
            slen, ok = struct.unpack_from("!BB", packet.payload, 0)
            scheme = packet.payload[2:2 + slen].decode("ascii")
        except Exception:
            return
        if not ok or not scheme or peer.authenticated_id is None:
            return
        # Only from the peer we asked, only about the scheme we asked about, and
        # only inside the window. An answer nobody asked for says nothing.
        key = (peer.authenticated_id.raw, scheme)
        expiry = self._reach_pending.pop(key, None)
        if expiry is None or expiry <= time.monotonic():
            return
        if self._transport_manager.is_supported(scheme):
            if scheme not in self._inbound_schemes:
                self._inbound_schemes.add(scheme)   # confirmed reachable → relay-capable
                self._poke_net("autonat-confirmed")

    async def _handle_data(self, peer: _Peer, packet: Packet) -> None:
        src = NodeID(packet.src_id)
        session = self._e2e_sessions.get(src)
        if session is None:
            return
        try:
            plaintext = packet.decrypt_payload(session)
        except Exception:
            # The live key rejected it. If a re-key candidate is parked for this
            # peer (they re-handshaked from scratch), this packet is the proof
            # they completed it: a successful candidate decrypt promotes the
            # candidate to the live session, healing the link. Anything else is
            # hostile or corrupt and stays dropped, revealing nothing.
            candidate = self._e2e_rekey_get(src)
            if candidate is None:
                return
            try:
                plaintext = packet.decrypt_payload(candidate)
            except Exception:
                return
            self._keep_e2e_session(src, candidate)
            del self._e2e_rekey[src]
            self._persist_state()
        try:
            self._data_queue.put_nowait((src, plaintext))
        except asyncio.QueueFull:
            # Dropped on purpose. We are inside this peer's receive loop, so
            # awaiting a full queue would freeze the link — and a node with no
            # app attached never drains it at all. The E2E plane promises no
            # delivery; the app layer already tolerates loss.
            self._metrics.total.on_drop()

    async def _handle_ping(self, peer: _Peer, packet: Packet) -> None:
        if not packet.payload:
            return
        src = NodeID(packet.src_id)
        if peer.authenticated_id != src:
            return
        try:
            raw_addrs = _decode_addresses(packet.payload)
        except (ValueError, UnicodeDecodeError):
            return
        valid_uris = [a for a in raw_addrs if _validate_uri(a) is not None]
        # An authenticated PING proves recency even when the peer currently has
        # no announceable address. Existing addresses remain as reconnect hints.
        self._routing.add(src, valid_uris, peer.dsa_pub)
        # The PONG is unconditional: a node with nothing to advertise (a pure
        # client, or a NATted node whose addresses are all unreachable) still
        # deserves its liveness reply — withholding it leaves the sender's RTT
        # bookkeeping stuck forever and makes a healthy link look dead.
        pong = Packet.create(PONG, self._id.raw, packet.src_id, b"")
        await peer.send(pong)

    async def _handle_pong(self, peer: _Peer, packet: Packet) -> None:
        if peer.ping_sent_at is not None:
            peer.last_rtt = max(0.0, time.monotonic() - peer.ping_sent_at)
            peer.quality.on_pong(peer.last_rtt)
            peer.ping_sent_at = None

    def _query_allowed(self, peer: '_Peer') -> bool:
        """Per-ingress-link rate limit for the expensive query replies
        (FIND_NODE, FIND_VALUE): each buys a chain-building sweep or a DHT value
        many times the size of the question, sent to an unverified src_id."""
        now = time.monotonic()
        for k in [k for k, (_, ws) in self._query_rate.items()
                  if now - ws > _QUERY_RATE_WINDOW]:
            del self._query_rate[k]
        while len(self._query_rate) > _MAX_PEERS:
            self._query_rate.popitem(last=False)
        key = self._rate_key(peer)
        cnt, ws = self._query_rate.get(key, (0, now))
        if now - ws > _QUERY_RATE_WINDOW:
            cnt, ws = 0, now
        if cnt >= _QUERY_RATE_MAX:
            self._query_rate[key] = (cnt, ws)
            return False
        self._query_rate[key] = (cnt + 1, ws)
        return True

    async def _handle_find_node(self, peer: _Peer, packet: Packet) -> None:
        if len(packet.payload) != 20 + _QID_LEN:
            return
        if not self._query_allowed(peer):
            return
        target = NodeID(packet.payload[:20])
        query_id = packet.payload[20:]
        # Closest-first under a hard byte budget: one PQ chain is ~15 KB, so a
        # full k=20 answer would exceed the packet cap and never be sent at all
        # (see _FOUND_NODE_MAX_BYTES). Chains are built lazily so the budget
        # also caps the work one query can ask of us.
        packer = _EntryPacker(_FOUND_NODE_MAX_BYTES)
        # Kademlia's answer classically excludes the responder — but here a
        # querier can only reach us *through* a relay, so leaving ourselves out
        # means it never learns our entry. A lookup routed to the very id it is
        # looking for then comes back with that node's neighbours, the shortlist
        # stops improving, and the lookup ends one hop short of an id it had
        # actually reached. So rank ourselves among the candidates like any other
        # entry: the receiver still verifies the chain and that its first cert
        # subject *is* the entry's node id, so a relay cannot forge this.
        candidates = [(e.node_id, e.addresses, e.dsa_pub)
                      for e in self._routing.get_closest(target, _FIND_NODE_SCAN)]
        candidates.append((self._id, self.advertised_uris(),
                           self._identity.dsa_public_key))
        candidates.sort(key=lambda c: target.distance(c[0]))
        for node_id, addresses, dsa_pub in candidates:
            if not dsa_pub:
                continue
            chain = self._cert_store.get_chain_to_root(node_id)
            if not chain:
                continue   # the receiver drops chain-less entries — don't spend budget
            if not packer.add(NodeEntry(node_id, addresses, dsa_pub, chain)):
                break
        response = Packet.create(FOUND_NODE, self._id.raw, packet.src_id,
                                 query_id + packer.encode())
        # routes back to the querier — never inline, we are in a receive loop
        await self._route_outbound(response, blocking=False)

    async def _handle_found_node(self, peer: _Peer, packet: Packet) -> None:
        if len(packet.payload) < _QID_LEN:
            return
        query_id = packet.payload[:_QID_LEN]
        future = self._pending_finds.get(query_id)
        if future is None:
            return  # unsolicited routing data never mutates local state
        try:
            entries = _decode_entries(packet.payload[_QID_LEN:])
        except Exception:
            entries = []
        if len(entries) > 20:
            return
        valid_entries: list[NodeEntry] = []
        learned_new = False
        for entry in entries:
            if not entry.cert_chain:
                continue
            anchor = self._cert_store.verify_chain(entry.cert_chain)
            if anchor is None:
                continue
            first = entry.cert_chain[0]
            if first.subject_id != entry.node_id:
                continue
            dsa_pub = first.subject_pub
            for cert in entry.cert_chain:
                self._cert_add(cert)
            # Whether this is news has to be asked *before* adding it, and it
            # decides whether maintenance is worth waking: a reply that only
            # restates identities we already hold is not a reason to go looking
            # again — that is a question answered by its own answer.
            #
            # Our own id is excluded, and not as a detail: the table refuses to
            # store it, so `contains` is false for it forever and every reply
            # that mentions us back would look like a discovery. That alone kept
            # the loop running.
            if (entry.node_id != self._id
                    and not self._routing.contains(entry.node_id)):
                learned_new = True
            self._routing.add(entry.node_id, entry.addresses, dsa_pub)
            valid_entries.append(entry)
        self._pending_finds.pop(query_id, None)
        if not future.done():
            future.set_result(valid_entries)
        if learned_new:
            self._wake_neighbor_maintenance()

    # -- DHT (content-addressed value store) ------------------------------

    async def _handle_store(self, peer: _Peer, packet: Packet) -> None:
        # payload: key(20) || value ; stored only if key == hash(value)
        if len(packet.payload) < 20:
            return
        # Content addressing stops a peer *choosing* a key, which is what closes
        # the poisoning vector — but it does not stop them filling the store:
        # random bytes hash to random keys and every one is accepted. Eviction
        # is a single global LRU over the app chunks and release content that
        # actually matter, so an unmetered STORE is an eviction lever.
        if not self._store_allowed(peer):
            return
        key = packet.payload[:20]
        value = packet.payload[20:]
        self._dht_store.put(key, value)  # put() rejects non-content-addressed data

    def _store_allowed(self, peer: '_Peer') -> bool:
        return self._gossip_allowed(self._store_rate, peer,
                                    _STORE_RATE_WINDOW, _STORE_RATE_MAX)

    async def _handle_observed_addr(self, peer: _Peer, packet: Packet) -> None:
        # A peer that accepted our connection tells us the source IP it saw —
        # that's our public address as seen from there. Record it (validated,
        # bounded) so we can advertise it alongside our local ones.
        try:
            ip = packet.payload.decode("ascii")
        except UnicodeDecodeError:
            return
        if not _is_ip_address(ip):
            return
        if ip in self._local_ips or ip in self._extra_addrs:
            return
        if len(self._extra_addrs) < _MAX_EXTRA_ADDRS:
            self._extra_addrs.append(ip)
        # A peer sees us at an address we didn't know — our public IP may
        # have just changed. Re-verify.
        self._poke_net("observed-addr")
        self._announce_addresses_soon("observed-addr")

    async def _handle_find_value(self, peer: _Peer, packet: Packet) -> None:
        # payload: key(20) || query_id(8) ; reply carries the value or empty
        if len(packet.payload) != 20 + _QID_LEN:
            return
        if not self._query_allowed(peer):
            return
        key = packet.payload[:20]
        query_id = packet.payload[20:]
        value = self._dht_store.get(key) or b""
        reply = Packet.create(FOUND_VALUE, self._id.raw, packet.src_id,
                              query_id + value)
        # routes back to the querier — never inline, we are in a receive loop
        await self._route_outbound(reply, blocking=False)

    async def _handle_found_value(self, peer: _Peer, packet: Packet) -> None:
        if len(packet.payload) < _QID_LEN:
            return
        query_id = packet.payload[:_QID_LEN]
        value = packet.payload[_QID_LEN:]
        future = self._pending_values.pop(query_id, None)
        if future is not None and not future.done():
            future.set_result(value if value else None)

    async def _dht_store_at(self, node_id: NodeID, key: bytes, value: bytes) -> None:
        # Addressed to node_id and routed (direct if adjacent, multi-hop if not).
        try:
            await self._route_outbound(
                Packet.create(STORE, self._id.raw, node_id.raw, key + value))
        except Exception:
            pass

    async def _dht_find_value_at(self, node_id: NodeID, key: bytes) -> bytes | None:
        query_id = os.urandom(_QID_LEN)
        future: asyncio.Future = asyncio.get_event_loop().create_future()
        self._pending_values[query_id] = future
        try:
            await self._route_outbound(
                Packet.create(FIND_VALUE, self._id.raw, node_id.raw, key + query_id))
            return await asyncio.wait_for(asyncio.shield(future), _DHT_QUERY_TIMEOUT)
        except Exception:
            self._forget_route_hint(node_id)   # unanswered — re-pick next time
            return None
        finally:
            self._pending_values.pop(query_id, None)
            if not future.done():
                future.cancel()

    async def dht_put(self, value: bytes) -> bytes:
        """Store a value in the DHT, addressed by its own hash. Returns the key."""
        key = _content_key(value)
        self._dht_store.put(key, value)  # keep a local copy (and re-share)
        targets = await self.kad_lookup(NodeID(key))
        await asyncio.gather(
            *(self._dht_store_at(nid, key, value)
              for nid in targets[:_DHT_K] if nid != self._id),
            return_exceptions=True,
        )
        return key

    async def dht_put_many(self, values: list[bytes]) -> list[bytes]:
        """Store many values, a bounded number of lookups at a time.

        A release is ~120 values, and :meth:`dht_put` is a full Kademlia lookup
        each: one after another, that is a hundred round trips with an operator
        watching a spinner. Bounded rather than all at once, because "publish
        everything simultaneously" is how a publish becomes a flood.

        Replication is **best effort**: every value is in our own store before
        its lookup even starts, so a peer we cannot reach costs reach, never the
        publish. Whoever fetches the release finds the chunks here."""
        keys: list[bytes] = []
        for start in range(0, len(values), _PUBLISH_CONCURRENCY):
            batch = values[start:start + _PUBLISH_CONCURRENCY]
            await asyncio.gather(*(self.dht_put(value) for value in batch),
                                 return_exceptions=True)
            keys.extend(_content_key(value) for value in batch)
        return keys

    async def dht_get(self, key: bytes) -> bytes | None:
        """Fetch a value by key, verifying it hashes to the key. Caches locally."""
        local = self._dht_store.get(key)
        if local is not None:
            return local
        for nid in (await self.kad_lookup(NodeID(key)))[:_DHT_K]:
            if nid == self._id:
                continue
            value = await self._dht_find_value_at(nid, key)
            if value is not None and _content_key(value) == key:
                self._dht_store.put(key, value)  # cache → this node now re-shares it
                return value
        return None

    # -- per-app DHT (namespaced overlay on the content-addressed store) ---
    #
    # The caller passes the app_id bound to the authenticated session; the app
    # never declares it. Public entries are stored in the clear, private ones
    # encrypted by the node under an app-supplied key. See :mod:`src.app_dht`.

    async def app_dht_put(self, app_id: bytes, content: bytes,
                          enc_key: bytes | None = None) -> bytes:
        """Publish an app entry on the DHT; returns its content key. ``enc_key``
        present → private (node-encrypted). Raises ``AppDHTError`` on bad input."""
        value = _app_dht_frame(app_id, content, enc_key)
        return await self.dht_put(value)

    async def app_dht_get(self, app_id: bytes, key: bytes,
                          dec_key: bytes | None = None) -> bytes | None:
        """Fetch an app entry by content key. Returns its content, or None if
        absent, from another app's namespace, or private without the right key."""
        value = await self.dht_get(key)
        if value is None:
            return None
        return _app_dht_read(value, app_id, dec_key)

    # -- app store: shared catalog (gossiped) + installed set -------------

    def _gossip_allowed(self, table: 'OrderedDict[bytes, tuple]', peer: '_Peer',
                        window: float, maximum: int) -> bool:
        """Per-ingress-link rate limit for a gossip plane (bounded, pruned) — a
        peer cannot make us verify signatures without end. One implementation:
        a second one would be a second place to get a bound wrong."""
        now = time.monotonic()
        for k in [k for k, (_, ws) in table.items() if now - ws > window]:
            del table[k]
        while len(table) > _MAX_PEERS:
            table.popitem(last=False)
        key = self._rate_key(peer)
        cnt, ws = table.get(key, (0, now))
        if now - ws > window:
            cnt, ws = 0, now
        if cnt >= maximum:
            table[key] = (cnt, ws)
            return False
        table[key] = (cnt + 1, ws)
        return True

    def _catalog_allowed(self, peer: '_Peer') -> bool:
        return self._gossip_allowed(self._catalog_rate, peer,
                                    _CATALOG_RATE_WINDOW, _CATALOG_RATE_MAX)

    async def _handle_catalog_announce(self, peer: '_Peer', packet: Packet) -> None:
        from .dht import MAX_VALUE
        if not self._catalog_allowed(peer):
            return
        release_bytes = packet.payload
        if not release_bytes or len(release_bytes) > MAX_VALUE:
            return
        # offer() verifies the signature and rejects stale/duplicate entries;
        # it returns a truthy outcome only when our view actually changed, which
        # is exactly when we re-gossip — so the epidemic terminates on its own.
        outcome = self._catalog.offer(release_bytes, self._identity.verify)
        if outcome:
            # Off the receive loop: the fan-out awaits a send to every peer, so
            # one peer whose send buffer is full stalls *this* peer's link.
            self._spawn_bounded(self._gossip_catalog(release_bytes, exclude=peer))

    async def _gossip_catalog(self, release_bytes: bytes,
                              exclude: '_Peer | None' = None) -> None:
        # Re-stamp src_id to us at each hop so the next node's direct-type gate
        # (src_id must equal the immediate sender) accepts it.
        pkt = Packet.create(CATALOG_ANNOUNCE, self._id.raw, _BROADCAST_ID, release_bytes)
        for p in self._gossip_targets(exclude, _GOSSIP_FANOUT):
            try:
                await p.send(pkt)
            except Exception:
                pass

    async def _sync_catalog_to(self, peer: '_Peer') -> None:
        """Push our whole catalog view to a freshly authenticated peer so a
        joining node catches up on apps published before it arrived."""
        for release_bytes in self._catalog.releases():
            if peer.authenticated_id is None or peer.session is None:
                return
            try:
                await peer.send(Packet.create(CATALOG_ANNOUNCE, self._id.raw,
                                              _BROADCAST_ID, release_bytes))
            except Exception:
                return

    def _schedule_catalog_sync(self, peer: '_Peer') -> None:
        if not self._catalog.releases():
            return
        try:
            self._spawn_bounded(self._sync_catalog_to(peer))
        except RuntimeError:
            pass  # no running loop (e.g. teardown) — nothing to sync

    async def publish_store_app(self, name: str, version: str,
                                files: dict[str, bytes],
                                ts: int | None = None) -> dict:
        """Publish a signed app and announce it to the network catalog. Returns
        ``{"release_id", "app_id"}``. Every node that hears the announce (and
        re-gossips it) can then discover and install the app. A later ``ts`` (or
        just publishing again later) supersedes the previous version network-wide."""
        info = await self.publish_signed_app(name, version, files, ts)
        release_bytes = await self.dht_get(bytes.fromhex(info["release_id"]))
        if release_bytes is not None:
            if self._catalog.offer(release_bytes, self._identity.verify):
                await self._gossip_catalog(release_bytes)
        return info

    def catalog_list(self) -> list[dict]:
        return self._catalog.list()

    def installed_list(self) -> list[dict]:
        return self._installed.list()

    def store_overview(self) -> dict:
        """The full store view for a UI, with all decisions made here (Python):
        each catalog app is annotated with its ``state`` (``install`` /
        ``update`` / ``installed``) and the ``action`` verb to POST (or None when
        it is already up to date). The front-end only renders this."""
        installed = {m["app_id"]: m for m in self._installed.list()}
        catalog = []
        for e in self._catalog.list():
            cur = installed.get(e["app_id"])
            if cur is None:
                state, action = "install", "install"
            elif e["ts"] > cur.get("ts", 0):
                state, action = "update", "update"
            else:
                state, action = "installed", None
            catalog.append({**e, "state": state, "action": action})
        return {"catalog": catalog, "installed": self._installed.list()}

    async def install_app(self, app_id_hex: str) -> dict | None:
        """Fetch and install an app known in the catalog. Content is verified
        against the signed release's root before anything touches disk. Returns
        the installed record, or None if unknown/unfetchable/at the cap."""
        try:
            app_id = bytes.fromhex(app_id_hex)
        except (ValueError, TypeError):
            return None
        entry = self._catalog.get(app_id)
        if entry is None:
            return None
        result = await self.fetch_app(entry["root_key"])  # content-verified
        if result is None:
            return None
        _, files = result
        self._installed.write_files(app_id_hex, files)
        meta = {
            "app_id": app_id_hex,
            "name": entry["name"],
            "version": entry["version"],
            "author": entry["author"].hex(),
            "release_id": entry["release_id"].hex(),
            "ts": entry["ts"],
            "installed_ts": int(time.time()),
        }
        if not self._installed.record(meta):
            return None
        return meta

    def uninstall_app(self, app_id_hex: str) -> bool:
        return self._installed.remove(app_id_hex)

    async def update_app(self, app_id_hex: str) -> dict | None:
        """Re-install an app if the catalog holds a newer signed release
        (strictly higher ``ts``). Returns the new record, or None if nothing
        newer / not installed."""
        inst = self._installed.get(app_id_hex)
        if inst is None:
            return None
        try:
            entry = self._catalog.get(bytes.fromhex(app_id_hex))
        except (ValueError, TypeError):
            return None
        if entry is None or entry["ts"] <= inst.get("ts", 0):
            return None
        return await self.install_app(app_id_hex)

    # -- mesh-native releases: the node's own code, published and signed ---
    #
    # Same shape as the app catalog above, and deliberately so: a signed
    # descriptor gossiped between direct peers, kept only when it changes our
    # view, so the epidemic terminates. What differs is what it authorises — an
    # app is installed into its own directory, a release *replaces this node's
    # code* — so nothing here acts on a signature its operator has not pinned.

    def _release_allowed(self, peer: '_Peer') -> bool:
        """Per-ingress-link rate limit on release announces. Verifying an
        ML-DSA signature is work; a peer does not get to ask for it without
        end."""
        return self._gossip_allowed(self._release_rate, peer,
                                    _RELEASE_RATE_WINDOW, _RELEASE_RATE_MAX)

    def _trusts_publisher(self, public_key: bytes) -> bool:
        return self._publishers.trusts(public_key)

    async def _handle_release_announce(self, peer: '_Peer', packet: Packet) -> None:
        from .dht import MAX_VALUE
        if not self._release_allowed(peer):
            return
        payload = packet.payload
        # `have(1) ‖ descriptor`: the sender says whether it holds the package
        # too, so the next node to want it has somewhere nearer to ask than the
        # publisher. A hint only — the hash is what decides.
        if not payload:
            return
        holder, release_bytes = payload[0] == 1, payload[1:]
        if not release_bytes or len(release_bytes) > MAX_VALUE:
            return
        # Parsed once. Verifying an ML-DSA signature is the cost here, and the
        # same bytes used to be parsed three times per announce: for the holder
        # hint, inside `offer`, and again in `_release_have_byte` on the way
        # out.
        try:
            doc = _core_parse_release(release_bytes, self._identity.verify)
        except Exception:
            return
        if holder and peer.authenticated_id is not None:
            self._note_release_source(
                bytes.fromhex(doc["sha256"])[:_RELEASE_ID_LEN].hex(),
                peer.authenticated_id)
        # An untrusted publisher's release is still carried and re-gossiped:
        # refusing to relay what we would not install ourselves would break
        # discovery for every other operator. It is flagged, never acted on.
        outcome = self._releases.offer(release_bytes, self._identity.verify,
                                       self._trusts_publisher)
        if outcome:
            held = self._packages.has(
                bytes.fromhex(doc["sha256"])[:_RELEASE_ID_LEN].hex())
            self._spawn_bounded(self._gossip_release(
                release_bytes, exclude=peer, have=held))

    def _release_have_byte(self, release_bytes: bytes) -> bytes:
        """Do we hold this release's package? Re-answered at every hop, because
        the answer is about the node doing the sending, not about the release."""
        try:
            doc = _core_parse_release(release_bytes, self._identity.verify)
        except Exception:
            return b"\x00"
        held = self._packages.has(
            bytes.fromhex(doc["sha256"])[:_RELEASE_ID_LEN].hex())
        return b"\x01" if held else b"\x00"

    async def _gossip_release(self, release_bytes: bytes,
                              exclude: '_Peer | None' = None,
                              have: bool | None = None) -> None:
        # `have` lets a caller that has already parsed the descriptor say so,
        # rather than making `_release_have_byte` verify the signature again.
        flag = (b"\x01" if have else b"\x00") if have is not None \
            else self._release_have_byte(release_bytes)
        pkt = Packet.create(RELEASE_ANNOUNCE, self._id.raw, _BROADCAST_ID,
                            flag + release_bytes)
        for p in self._gossip_targets(exclude, _GOSSIP_FANOUT):
            try:
                await p.send(pkt)
            except Exception:
                pass

    async def _sync_releases_to(self, peer: '_Peer') -> None:
        """Catch a freshly authenticated peer up on the releases we know."""
        for release_bytes in self._releases.releases():
            if peer.authenticated_id is None or peer.session is None:
                return
            try:
                await peer.send(Packet.create(
                    RELEASE_ANNOUNCE, self._id.raw, _BROADCAST_ID,
                    self._release_have_byte(release_bytes) + release_bytes))
            except Exception:
                return

    def _schedule_release_sync(self, peer: '_Peer') -> None:
        if not self._releases.releases():
            return
        try:
            self._spawn_bounded(self._sync_releases_to(peer))
        except RuntimeError:
            pass  # no running loop (e.g. teardown) — nothing to sync

    async def publish_release(self, root: str | None = None, notes: str = "",
                              ts: int | None = None) -> dict:
        """Publish this node's own code as a signed release, and announce it.

        The tree is read, content-addressed onto the DHT, and a descriptor
        signed with **this node's identity** binds that content to us. Whoever
        has pinned our key can then fetch and install it. Raises
        :class:`ReleaseError` if the tree is not something we can publish."""
        from .dht import MAX_VALUE
        from . import updater
        files = _core_read_tree(root or updater.install_root())
        version = _core_version_of(files)
        _core_check_tree(files, version)          # what we sign is what we carry
        package = _core_build_package(files)
        release_bytes = _core_build_release(
            package, version, self._identity.dsa_public_key,
            self._identity.sign, ts, notes)
        if len(release_bytes) > MAX_VALUE:
            raise ReleaseError("release descriptor too large")
        release_id = _core_release_id(package)
        if not self._packages.put(release_id.hex(), package,
                                  hashlib.sha256(package).hexdigest()):
            raise ReleaseError("could not keep the package to serve it")
        # Publishing is signing and announcing. Nothing is pushed anywhere: the
        # bytes move when somebody actually wants them, from us or from anyone
        # who kept a copy. A publisher with no peers still publishes.
        if self._releases.offer(release_bytes, self._identity.verify,
                                self._trusts_publisher):
            await self._gossip_release(release_bytes)
        return {
            "version": version,
            "release_id": release_id.hex(),
            "publisher_id": _core_publisher_id(
                self._identity.dsa_public_key).hex(),
            "files": len(files),
            "bytes": sum(len(value) for value in files.values()),
            "package_bytes": len(package),
        }

    # -- moving the package: ask whoever has it, then be one of them -------

    def _release_serve_allowed(self, peer: '_Peer') -> bool:
        return self._gossip_allowed(self._release_serve_rate, peer,
                                    _RELEASE_SERVE_WINDOW, _RELEASE_SERVE_MAX)

    def _note_release_source(self, release_id_hex: str, node_id: NodeID) -> None:
        """Remember that this node said it holds that release.

        Bounded on both axes, and it is only ever a hint: a node that claims to
        have a package and does not simply wastes one request, because what
        decides the bytes are good is the hash the publisher signed."""
        if not _HEX_RELEASE.fullmatch(release_id_hex or ""):
            return
        sources = self._release_sources.setdefault(release_id_hex, [])
        if node_id in sources:
            sources.remove(node_id)
        sources.append(node_id)
        del sources[:-_RELEASE_SOURCES_MAX]
        while len(self._release_sources) > _RELEASE_SOURCES_TRACKED:
            self._release_sources.popitem(last=False)

    async def _handle_release_fetch(self, peer: '_Peer', packet: Packet) -> None:
        """Hand a slice of a package to whoever asked, if we have it.

        A release is public code, signed: there is nothing here to authorise
        beyond not letting one peer pull without end, which the rate limit
        does. If we do not hold it, we say nothing — an empty answer would be
        one more thing to forge."""
        if not self._release_serve_allowed(peer):
            return
        payload = packet.payload
        if len(payload) != _RELEASE_ID_LEN + 4:
            return
        release_id_hex = payload[:_RELEASE_ID_LEN].hex()
        offset = int.from_bytes(payload[_RELEASE_ID_LEN:], "big")
        package = self._packages.get(release_id_hex)
        if package is None or offset >= len(package):
            return
        slice_ = package[offset:offset + _RELEASE_SLICE]
        # blocking=False, like every other handler: we are in a receive loop,
        # and `_route_outbound` with no live candidate awaits `_ensure_route_to`
        # — a lookup, a dial and a hole punch, seconds of it — while this link
        # processes nothing else (gotchas §10). `src_id` is not authenticated,
        # so a stranger's unroutable id is exactly the packet that costs most.
        await self._route_outbound(Packet.create(
            RELEASE_DATA, self._id.raw, packet.src_id,
            payload[:_RELEASE_ID_LEN] + offset.to_bytes(4, "big") + slice_),
            blocking=False)

    async def _handle_release_data(self, peer: '_Peer', packet: Packet) -> None:
        payload = packet.payload
        if len(payload) <= _RELEASE_ID_LEN + 4:
            return
        # Keyed on the source too. The release id is public gossip and the
        # offsets are 0, _RELEASE_SLICE, 2×… — so without this any authenticated
        # peer could race the real answer with rubbish. The final SHA-256 still
        # catches it, which is why this was denial rather than corruption: every
        # download of a given release could be made to fail, for ever, at one
        # packet per slice. Updates are a security mechanism.
        key = (NodeID(packet.src_id), payload[:_RELEASE_ID_LEN].hex(),
               int.from_bytes(payload[_RELEASE_ID_LEN:_RELEASE_ID_LEN + 4], "big"))
        future = self._pending_slices.get(key)
        if future is None:
            self._charge_abuse(peer)   # answering a question we did not ask
            return
        if not future.done():
            future.set_result(payload[_RELEASE_ID_LEN + 4:])

    async def _pull_slice(self, source: NodeID, release_id: bytes,
                          offset: int) -> bytes | None:
        key = (source, release_id.hex(), offset)
        future: asyncio.Future = asyncio.get_event_loop().create_future()
        self._pending_slices[key] = future
        try:
            await self._route_outbound(Packet.create(
                RELEASE_FETCH, self._id.raw, source.raw,
                release_id + offset.to_bytes(4, "big")))
            return await asyncio.wait_for(asyncio.shield(future),
                                          _RELEASE_SLICE_TIMEOUT)
        except Exception:
            return None
        finally:
            self._pending_slices.pop(key, None)
            if not future.done():
                future.cancel()

    async def _pull_package(self, source: NodeID, entry: dict) -> bytes | None:
        """Pull a whole package from one node, slice by slice."""
        release_id = entry["release_id"]
        size = entry["size"]
        parts, offset = bytearray(), 0
        while offset < size:
            slice_ = await self._pull_slice(source, release_id, offset)
            if not slice_:
                return None                    # this source stopped answering
            parts.extend(slice_)
            offset += len(slice_)
            if len(parts) > size:
                return None                    # more than was signed for
        return bytes(parts)

    def _release_sources_for(self, entry: dict) -> list[NodeID]:
        """Who to ask, nearest hint first, the publisher last.

        Neighbours that said they hold it are tried before the publisher: that
        is what makes this a swarm rather than one machine serving everybody."""
        sources = list(reversed(
            self._release_sources.get(entry["release_id"].hex(), [])))
        publisher = NodeID(_core_publisher_id(entry["publisher"]))
        if publisher not in sources:
            sources.append(publisher)
        return [node_id for node_id in sources if node_id != self._id]

    async def fetch_release(self, publisher_id_hex: str):
        """Get a release's package and open it, verified end to end.

        Returns ``(entry, files)`` or None. The bytes are checked against the
        SHA-256 the publisher signed before anything is unpacked, and the
        version the descriptor announces against the one the tree carries — so
        what comes back is what was signed, or nothing at all.

        Whatever we end up holding, we keep: the next node to want this release
        can ask us instead of the publisher."""
        entry = self._releases.get(publisher_id_hex)
        if entry is None:
            return None
        release_id_hex = entry["release_id"].hex()
        package = self._packages.get(release_id_hex)
        if package is None:
            for source in self._release_sources_for(entry):
                package = await self._pull_package(source, entry)
                if package is None:
                    continue
                if not self._packages.put(release_id_hex, package,
                                          entry["sha256"]):
                    package = None     # not what was signed — try someone else
                    continue
                break
        if package is None:
            return None
        files = _core_open_package(package)
        _core_check_tree(files, entry["version"])
        return entry, files

    def _release_state(self, entry: dict) -> tuple[str, str | None]:
        """What this node can do with a release, decided here rather than in a
        page: unpinned publisher → nothing, older or equal version → nothing.

        Takes a **catalogue entry** (`publisher` as bytes), never the hex-ified
        row `ReleaseCatalog.list()` renders for a UI.

        Trust is read from the pins **now**, not from the flag cached on the
        entry when it arrived: that flag exists to be displayed, and a stale one
        must never be what authorises an install."""
        if not self._trusts_publisher(entry["publisher"]):
            return "untrusted", None
        if entry["version"] == _running_version():
            return "running", None
        if not _is_newer(entry["version"], _running_version()):
            return "older", None
        return "available", "install"

    def release_overview(self) -> dict:
        """Everything a UI needs, with every decision already made here."""
        releases = []
        for listed in self._releases.list():
            entry = self._releases.get(listed["publisher_id"])
            if entry is None:
                continue
            state, action = self._release_state(entry)
            releases.append({**listed, "state": state, "action": action,
                             "trusted": state != "untrusted"})
        from . import updater
        ok, reason = updater.updatable()
        return {
            "current": _running_version(),
            "publisher_id": _core_publisher_id(
                self._identity.dsa_public_key).hex(),
            "publisher_key": self._identity.dsa_public_key.hex(),
            "publishers": self._publishers.list(),
            "releases": releases,
            "log": list(self._release_log),
            "updatable": ok,
            "reason": reason,
        }

    def trust_publisher(self, key_hex: str, name: str = "",
                        auto: bool = False) -> dict:
        """Pin a publisher key. The only way a key enters this list is here —
        an operator acting locally, never a packet."""
        try:
            public_key = bytes.fromhex(key_hex)
        except (ValueError, TypeError) as exc:
            raise ReleaseError("that is not a public key") from exc
        entry = self._publishers.add(public_key, name, auto)
        self._releases.retrust(self._trusts_publisher)
        return entry

    def untrust_publisher(self, publisher_id_hex: str) -> bool:
        removed = self._publishers.remove(publisher_id_hex)
        if removed:
            self._releases.retrust(self._trusts_publisher)
        return removed

    def set_publisher_auto(self, publisher_id_hex: str, auto: bool) -> bool:
        return self._publishers.set_auto(publisher_id_hex, auto)

    def _note_release(self, version: str, outcome: str, detail: str = "") -> None:
        self._release_log.append({"ts": int(time.time()), "version": version,
                                  "outcome": outcome, "detail": detail[:200]})
        del self._release_log[:-16]

    async def install_release(self, publisher_id_hex: str) -> dict:
        """Install a release from a pinned publisher.

        Three gates, in this order: the publisher is pinned, the version is
        strictly newer than the one running, and every byte verifies against the
        signed root. Only then does anything touch disk — and even then the
        previous tree is kept and restored if the swap fails."""
        from . import updater
        entry = self._releases.get(publisher_id_hex)
        if entry is None:
            raise ReleaseError("no such release")
        state, _action = self._release_state(entry)
        if state == "untrusted":
            raise ReleaseError("that publisher is not trusted here")
        if state != "available":
            raise ReleaseError(f"version {entry['version']} is not newer than "
                               f"{_running_version()}")
        fetched = await self.fetch_release(publisher_id_hex)
        if fetched is None:
            raise ReleaseError("the release content could not be fetched")
        _entry, files = fetched
        result = await updater.apply_files(files, entry["version"])
        self._note_release(entry["version"], "installed",
                           f"from {publisher_id_hex[:12]}")
        return {**result, "version": entry["version"],
                "publisher_id": publisher_id_hex}

    def _ensure_release_watch(self) -> None:
        if self._release_task is None or self._release_task.done():
            self._release_task = asyncio.create_task(self._release_loop())

    async def _stop_release_watch(self) -> None:
        task = self._release_task
        self._release_task = None
        if task is not None:
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass

    async def _release_loop(self) -> None:
        """Install what pinned publishers marked for automatic installation.

        Installing is not restarting: the node keeps running the code it
        started with until something restarts it. That is deliberate — a node
        that swaps its own code and immediately exits turns one bad release
        into a restart loop nobody is present to break.

        Never raises: this loop dying would silently stop the updates an
        operator asked for."""
        while self._running:
            await asyncio.sleep(_RELEASE_TICK)
            try:
                await self._release_pass()
            except asyncio.CancelledError:
                raise
            except Exception:
                pass

    async def _release_pass(self) -> str | None:
        """One pass: install at most one release, and never the same failing
        one twice. Returns the version installed, or None."""
        for listed in self._releases.list():
            entry = self._releases.get(listed["publisher_id"])
            if entry is None:
                continue
            state, _action = self._release_state(entry)
            if state != "available":
                continue
            if not self._publishers.auto_for(entry["publisher"]):
                continue
            release_id = entry["release_id"]
            if release_id in self._release_tried:
                continue        # already tried this one — don't loop on it
            self._release_tried[release_id] = entry["version"]
            while len(self._release_tried) > _RELEASE_TRIED_MAX:
                self._release_tried.popitem(last=False)
            try:
                await self.install_release(listed["publisher_id"])
                return entry["version"]
            except Exception as exc:
                self._note_release(entry["version"], "failed", str(exc))
                return None
        return None

    # -- pseudos (the changeable name beside the unchangeable id) ---------
    #
    # Two planes, one book. Gossip (PSEUDO_ANNOUNCE) spreads a node's signed
    # claim to everyone it can reach, which is what makes a *partial* search
    # possible at all: you cannot hash half a name into a DHT key, but you can
    # rank the names you already hold. The keyed directory (DIR_*) covers the
    # rest — an exact pseudo whose owner sits beyond our gossip horizon.
    #
    # Claims are self-authenticating (see :mod:`src.pseudo_dir`), so accepting
    # them from strangers and re-serving them is safe; and a peer that sends one
    # we cannot verify, or a name in a form the protocol forbids, is not making
    # a mistake we should absorb — it is counted and eventually cut.

    @property
    def pseudo(self) -> str:
        """This node's own pseudo, or "" if it has none."""
        return self._pseudo

    def set_pseudo(self, pseudo: str) -> str:
        """Adopt ``pseudo`` as this node's name and sign a fresh claim for it.

        Returns the canonical form actually adopted; raises
        :class:`~src.pseudo.PseudoError` if it cannot be one. An empty string
        drops the pseudo — the node keeps its id and simply stops offering a
        name. The new claim is announced to the mesh if the node is running."""
        if isinstance(pseudo, str) and not pseudo.strip():
            # Local only. A claim says "this node is called X"; there is no
            # signed way to say "called nothing", so peers keep the last name
            # they were told until they forget it. Renaming propagates, clearing
            # does not — see Docs/Pseudos/guide.
            self._pseudo, self._pseudo_claim = "", None
            self._pseudo_book.forget(self._id.raw)
            return ""
        wanted = _pseudo_canonical(pseudo)
        # Strictly forward, even when two renames land in the same second:
        # peers keep the newest claim per node and drop the rest, so a
        # timestamp that failed to move would leave them on the old name.
        previous = self._pseudo_book.ts_of(self._id.raw)
        ts = int(time.time())
        if previous is not None and ts <= previous:
            ts = previous + 1
        claim = _dir_build_claim(wanted, self._identity.dsa_public_key,
                                 self._identity.sign, ts)
        parsed = _dir_parse_claim(claim, self._identity.verify)
        if parsed is None:                       # never seen; a signed claim we
            raise PseudoDirError("could not verify our own claim")   # cannot read
        self._pseudo, self._pseudo_claim = wanted, claim
        self._pseudo_book.offer(parsed, claim)
        self._announce_own_pseudo()
        return wanted

    def _announce_own_pseudo(self) -> None:
        """Gossip our claim, if there is one and a loop to do it on."""
        if self._pseudo_claim is None or not self._running:
            return
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return
        self._spawn_bounded(self._gossip_pseudo(self._pseudo_claim))

    def pseudo_of(self, node_id) -> str:
        """What a node is called, or "" when we have never seen a claim for it.
        Display only — never a substitute for the id."""
        raw = node_id.raw if isinstance(node_id, NodeID) else node_id
        if isinstance(raw, str):
            try:
                raw = bytes.fromhex(raw)
            except ValueError:
                return ""
        if not isinstance(raw, (bytes, bytearray)):
            return ""
        return self._pseudo_book.pseudo_of(bytes(raw)) or ""

    def _pseudo_allowed(self, peer: '_Peer') -> bool:
        return self._gossip_allowed(self._pseudo_rate, peer,
                                    _PSEUDO_RATE_WINDOW, _PSEUDO_RATE_MAX)

    def _absorb_claim(self, peer: '_Peer', raw: bytes):
        """Verify a claim that arrived from ``peer`` and file it.

        Returns the claim if our view changed (so gossip should continue), None
        otherwise. A claim that does not verify is charged to the peer that sent
        it: an honest relay verifies before re-sending, so whoever handed us a
        bad one either forged it or forwarded without checking."""
        if not raw or len(raw) > _MAX_CLAIM:
            self._charge_abuse(peer)
            return None
        claim = _dir_parse_claim(raw, self._identity.verify)
        if claim is None:
            self._charge_abuse(peer)
            return None
        return claim if self._pseudo_book.offer(claim, bytes(raw)) else None

    def _spawn_bounded(self, coro) -> None:
        """Run a coroutine detached from the caller.

        Two things a bare ``create_task`` does not give: a reference, without
        which the loop may collect the task mid-flight, and a ceiling, without
        which fire-and-forget work piles up under pressure exactly when the node
        can least afford it."""
        if len(self._detached) >= _MAX_DETACHED:
            coro.close()
            return
        try:
            task = asyncio.create_task(coro)
        except RuntimeError:
            coro.close()       # no running loop (teardown) — nothing to run on
            return
        self._detached.add(task)
        task.add_done_callback(self._detached.discard)

    def _charge_abuse(self, peer: '_Peer') -> None:
        """Count a protocol violation and cut the peer once they pile up. Never
        inline: we are inside that peer's own receive task, which must not be
        cancelled from here (see :meth:`_reap_peer`)."""
        if peer.note_abuse():
            self._spawn_bounded(self._reap_peer(peer))

    async def _handle_pseudo_announce(self, peer: '_Peer', packet: Packet) -> None:
        if not self._pseudo_allowed(peer):
            return
        # Re-gossip only when our view actually changed, so the epidemic dies
        # out instead of circulating forever (same shape as the catalog).
        if self._absorb_claim(peer, packet.payload) is not None:
            self._spawn_bounded(self._gossip_pseudo(packet.payload, exclude=peer))

    def _gossip_targets(self, exclude: '_Peer | None', fanout: int) -> list['_Peer']:
        """Which peers an epidemic goes to next — a bounded sample, not all.

        Sending to every peer turns one accepted claim into (peers − 1)
        transmissions, and a claim is ~5.3 kB. The terminating rule ("only
        re-gossip when our view changed") stops it circulating for ever, but it
        does not stop the *width*: an adversary mints identities offline, so
        every one of its claims is genuinely new. A bounded fan-out keeps the
        epidemic reaching everyone — that is what an epidemic does — while
        costing a fixed amount per hop."""
        live = [p for p in self._peers
                if p is not exclude and p.authenticated_id is not None
                and p.session is not None]
        if len(live) <= fanout:
            return live
        return random.sample(live, fanout)

    async def _gossip_pseudo(self, raw: bytes,
                             exclude: '_Peer | None' = None) -> None:
        # Re-stamp src_id to us at each hop so the next node's direct-type gate
        # (src_id must equal the immediate sender) accepts it.
        pkt = Packet.create(PSEUDO_ANNOUNCE, self._id.raw, _BROADCAST_ID, raw)
        for p in self._gossip_targets(exclude, _GOSSIP_FANOUT):
            try:
                await p.send(pkt)
            except Exception:
                pass

    async def _sync_pseudos_to(self, peer: '_Peer') -> None:
        """Catch a freshly authenticated peer up on the names we know.

        Ours first — it is the one thing this peer certainly wants — then the
        most recently learned, bounded: the book holds far more than belongs in
        a burst at connection time, and the rest arrives by gossip anyway."""
        claims = self._pseudo_book.recent(_PSEUDO_SYNC_MAX)
        if self._pseudo_claim is not None:
            claims = [self._pseudo_claim] + [c for c in claims
                                             if c != self._pseudo_claim]
        for raw in claims:
            if peer.authenticated_id is None or peer.session is None:
                return
            try:
                await peer.send(Packet.create(PSEUDO_ANNOUNCE, self._id.raw,
                                              _BROADCAST_ID, raw))
            except Exception:
                return

    def _schedule_pseudo_sync(self, peer: '_Peer') -> None:
        if not len(self._pseudo_book):
            return
        try:
            self._spawn_bounded(self._sync_pseudos_to(peer))
        except RuntimeError:
            pass  # no running loop (e.g. teardown) — nothing to sync

    def _dir_allowed(self, peer: '_Peer') -> bool:
        now = time.monotonic()
        for k in [k for k, (_, ws) in self._dir_rate.items()
                  if now - ws > _DIR_RATE_WINDOW]:
            del self._dir_rate[k]
        while len(self._dir_rate) > _MAX_PEERS:
            self._dir_rate.popitem(last=False)
        key = self._rate_key(peer)
        cnt, ws = self._dir_rate.get(key, (0, now))
        if now - ws > _DIR_RATE_WINDOW:
            cnt, ws = 0, now
        if cnt >= _DIR_RATE_MAX:
            self._dir_rate[key] = (cnt, ws)
            return False
        self._dir_rate[key] = (cnt + 1, ws)
        return True

    async def _handle_dir_store(self, peer: '_Peer', packet: Packet) -> None:
        if not self._dir_allowed(peer):
            return
        # Same gate as the gossip plane: only a self-consistent, canonically
        # named claim is stored, and a bad one is charged to its sender.
        self._absorb_claim(peer, packet.payload)

    async def _handle_dir_find(self, peer: '_Peer', packet: Packet) -> None:
        if len(packet.payload) != 20 + _QID_LEN:
            return
        # Same valve as FIND_NODE / FIND_VALUE, and for the same reason: 28
        # bytes of question buy up to `_FOUND_BUDGET` of signed claims, routed
        # to a src_id nothing has verified. `_dir_allowed` covered DIR_STORE
        # only, so this plane had no ceiling at all.
        if not self._query_allowed(peer):
            return
        key = packet.payload[:20]
        query_id = packet.payload[20:]
        body = query_id + _dir_encode(self._pseudo_book.get(key))
        # routes back to the querier — never inline, we are in a receive loop
        await self._route_outbound(
            Packet.create(DIR_FOUND, self._id.raw, packet.src_id, body),
            blocking=False)

    async def _handle_dir_found(self, peer: '_Peer', packet: Packet) -> None:
        if len(packet.payload) < _QID_LEN:
            return
        query_id = packet.payload[:_QID_LEN]
        future = self._pending_dir.pop(query_id, None)
        if future is not None and not future.done():
            future.set_result(packet.payload[_QID_LEN:])

    async def _dir_store_at(self, node_id: NodeID, claim: bytes) -> None:
        # Addressed to node_id and routed (direct if adjacent, multi-hop if not).
        try:
            await self._route_outbound(
                Packet.create(DIR_STORE, self._id.raw, node_id.raw, claim))
        except Exception:
            pass

    async def _dir_find_at(self, node_id: NodeID, key: bytes) -> bytes | None:
        query_id = os.urandom(_QID_LEN)
        future: asyncio.Future = asyncio.get_event_loop().create_future()
        self._pending_dir[query_id] = future
        try:
            await self._route_outbound(
                Packet.create(DIR_FIND, self._id.raw, node_id.raw, key + query_id))
            return await asyncio.wait_for(asyncio.shield(future), _DHT_QUERY_TIMEOUT)
        except Exception:
            self._forget_route_hint(node_id)   # unanswered — re-pick next time
            return None
        finally:
            self._pending_dir.pop(query_id, None)
            if not future.done():
                future.cancel()

    def _direct_peer_ids(self) -> list[NodeID]:
        """Node ids of our directly-connected authenticated peers. The directory
        (like the DHT) can only exchange FIND/STORE with peers we have a live link
        to, so in a hub/NAT topology these — not the abstract K-closest — are who
        actually holds and answers. Including them makes lookup work when the
        closest-to-key nodes aren't directly reachable."""
        out, seen = [], set()
        for p in self._peers:
            nid = p.authenticated_id
            if nid is not None and p.session is not None and nid.raw not in seen:
                seen.add(nid.raw)
                out.append(nid)
        return out

    async def _dir_targets(self, key: bytes) -> list[NodeID]:
        """Union of the K nodes closest to ``key`` and our direct peers — bounded,
        deduplicated, self excluded."""
        targets, seen = [], set()
        for nid in (await self.kad_lookup(NodeID(key)))[:_DIR_K] + self._direct_peer_ids():
            if nid != self._id and nid.raw not in seen:
                seen.add(nid.raw)
                targets.append(nid)
        return targets

    async def publish_pseudo(self) -> str:
        """Replicate our claim into the keyed directory and gossip it.

        Gossip alone reaches everyone we can talk to; the directory copy is what
        makes us findable by exact name from a node that has never heard of us.
        Returns the directory key, or "" when this node has no pseudo."""
        if self._pseudo_claim is None:
            return ""
        claim = self._pseudo_claim
        key = _dir_key(self._pseudo)
        await self._gossip_pseudo(claim)
        await asyncio.gather(
            *(self._dir_store_at(nid, claim) for nid in await self._dir_targets(key)),
            return_exceptions=True,
        )
        return key.hex()

    async def lookup_pseudo(self, pseudo: str) -> list[dict]:
        """Every node claiming exactly ``pseudo``, network-wide.

        Pseudos are not unique, so this returns a list; the node id in each row
        is the real identity. Queries the nodes closest to the key and our
        direct peers **in parallel**, so one slow or unreachable peer cannot
        stall the whole lookup."""
        key = _dir_key(pseudo)
        found: dict[str, dict] = {}

        def absorb(raw: bytes) -> None:
            claim = _dir_parse_claim(raw, self._identity.verify)
            if claim is None or claim["key"] != key:
                return
            self._pseudo_book.offer(claim, raw)     # cache → this node re-serves it
            found[claim["node_id"].hex()] = {"id": claim["node_id"].hex(),
                                             "pseudo": claim["pseudo"],
                                             "ts": claim["ts"], "match": 0}

        for raw in self._pseudo_book.get(key):
            absorb(raw)
        blobs = await asyncio.gather(
            *(self._dir_find_at(nid, key) for nid in await self._dir_targets(key)),
            return_exceptions=True,
        )
        for blob in blobs:
            if isinstance(blob, (bytes, bytearray)):
                for raw in _dir_decode(blob):
                    absorb(raw)
        return list(found.values())

    def find_pseudo(self, query: str, limit: int = 20) -> list[dict]:
        """Nodes whose pseudo matches ``query``, whole or partial, best first.

        Answered entirely from what this node already holds, so it costs nothing
        and returns instantly — which is what lets a console field search as
        somebody types."""
        return self._pseudo_book.search(query, min(int(limit), _PSEUDO_SEARCH_MAX))

    async def search_pseudo(self, query: str, limit: int = 20) -> list[dict]:
        """:meth:`find_pseudo`, widened by one exact directory lookup.

        The local book only knows names that reached us by gossip. Asking the
        directory for the query *as typed* is what finds somebody whose node we
        have never met — and costs one round of parallel queries, so it stays a
        deliberate act rather than something a keystroke triggers."""
        limit = min(int(limit), _PSEUDO_SEARCH_MAX)
        try:
            await self.lookup_pseudo(query)
        except Exception:
            pass          # the local answer is still worth returning
        return self.find_pseudo(query, limit)

    # -- application packages ---------------------------------------------

    async def publish_app(self, name: str, version: str,
                          files: dict[str, bytes]) -> bytes:
        """Publish an app on the DHT. Returns the app id (= hash of the root).

        Content chunks, the manifest (itself chunked), and a small root that
        lists the manifest chunks are all stored content-addressed — so an app
        can have arbitrarily many files."""
        _, manifest, chunks = _app_build(name, version, files)
        from .dht import MAX_VALUE
        await self.dht_put_many(list(chunks.values()))
        root_bytes, manifest_chunks = _app_pack_root(manifest)
        if len(root_bytes) > MAX_VALUE:
            raise AppPackageError("app has too many files even after chunking")
        await self.dht_put_many(list(manifest_chunks.values()))
        return await self.dht_put(root_bytes)

    async def publish_signed_app(self, name: str, version: str,
                                 files: dict[str, bytes],
                                 ts: int | None = None) -> dict:
        """Publish a signed, deployable app. Returns ``{"release_id", "app_id"}``.

        The content (chunks + manifest + root) is published as with
        :meth:`publish_app`; on top, a release descriptor signed by this node's
        identity binds the content root to us as author, and is published too.
        ``ts`` (defaults to now) is the signed publish time that orders versions.
        Installers fetch it by ``release_id`` and verify the signature."""
        _, manifest, chunks = _app_build(name, version, files)
        from .dht import MAX_VALUE
        for value in chunks.values():
            await self.dht_put(value)
        root_bytes, manifest_chunks = _app_pack_root(manifest)
        if len(root_bytes) > MAX_VALUE:
            raise AppPackageError("app has too many files even after chunking")
        for value in manifest_chunks.values():
            await self.dht_put(value)
        root_key = await self.dht_put(root_bytes)
        release_bytes, app_id = _app_build_release(
            root_key, hashlib.sha256(root_bytes).hexdigest(), name, version,
            self._identity.dsa_public_key, self._identity.sign, ts)
        if len(release_bytes) > MAX_VALUE:
            raise AppPackageError("release descriptor too large")
        release_id = await self.dht_put(release_bytes)
        return {"release_id": release_id.hex(), "app_id": app_id.hex()}

    async def fetch_signed_app(self, release_id: bytes):
        """Fetch a signed app by its release id, verifying the author signature
        before any content. Returns ``(meta, files)`` where ``meta`` has
        ``app_id`` / ``name`` / ``version`` / ``author`` (hex), or None if the
        release is absent. Raises ``AppPackageError`` on any verification
        failure — a bad signature yields nothing (reject by default)."""
        release_bytes = await self.dht_get(release_id)
        if release_bytes is None:
            return None
        doc = _app_parse_release(release_bytes, self._identity.verify)
        result = await self.fetch_app(doc["root_key"])  # content-verified
        if result is None:
            return None
        manifest, files = result
        meta = {"app_id": doc["app_id"].hex(), "name": doc["name"],
                "version": doc["version"], "author": doc["author"].hex()}
        return meta, files

    async def fetch_app(self, app_id: bytes) -> tuple[dict, dict[str, bytes]] | None:
        """Fetch and verify an app by id. Returns (manifest, files) or None."""
        root_bytes = await self.dht_get(app_id)
        if root_bytes is None:
            return None
        root = _app_parse_root(root_bytes)
        mchunks: dict[bytes, bytes] = {}
        for h in root["chunks"]:
            value = await self.dht_get(bytes.fromhex(h))
            if value is not None:
                mchunks[bytes.fromhex(h)] = value
        manifest_bytes = _app_reassemble_bytes(
            root["size"], root["sha256"], root["chunks"], mchunks.get)
        manifest = _app_parse_manifest(manifest_bytes)
        fetched: dict[bytes, bytes] = {}
        for ck in _app_chunk_keys(manifest):
            value = await self.dht_get(ck)
            if value is not None:
                fetched[ck] = value
        files = _app_reassemble(manifest, fetched.get)  # verifies every hash
        return manifest, files

    # -- per-app local secure store ("drawers") ---------------------------
    #
    # The node holds the app id; callers pass the id bound to the authenticated
    # session, never one an app chose for itself. See :mod:`src.app_storage`.

    @property
    def app_storage(self):
        return self._app_storage

    def app_auth(self, app_id: bytes) -> AppAuth:
        """Hand an app an authentication service scoped to its section.

        This is how an app uses the node's mesh identity as a login (see
        ``Docs/AppAuth/guide``): it can mint assertions naming *this* node and
        verify a peer's, but it never touches the signing key, and every
        signature it can cause is confined to the app-auth domain and to its own
        ``app_id``. An app therefore cannot mint an assertion for another app's
        section, nor steer the signer at a certificate or a handshake."""
        return AppAuth(self._identity, app_id, self._id)

    def app_store_put(self, app_id: bytes, key: str, value: bytes) -> bool:
        return self._app_storage.put(app_id, key, value)

    def app_store_get(self, app_id: bytes, key: str) -> bytes | None:
        return self._app_storage.get(app_id, key)

    def app_store_delete(self, app_id: bytes, key: str) -> bool:
        return self._app_storage.delete(app_id, key)

    def app_store_list(self, app_id: bytes) -> list[str]:
        return self._app_storage.list_keys(app_id)

    async def _handle_challenge(self, peer: _Peer, packet: Packet) -> None:
        if len(packet.payload) != 32:
            return
        peer.received_challenge = packet.payload
        if peer.relay_only:
            return  # we only use this link to relay — don't authenticate to it
        if not peer.is_client_side:
            return  # Unsolicited challenge — ignore
        if peer.join_code is None:
            # Reconnecting routing peer — present our chain directly
            await self.initiate_handshake(peer)
            return
        response    = compute_response(peer.join_code, packet.payload)
        invite_pkt  = Packet.create(INVITE, self._id.raw, packet.src_id, response)
        peer.invite_sent = True
        await peer.send(invite_pkt)

    async def _handle_invite(self, peer: _Peer, packet: Packet) -> None:
        if peer.pending_challenge is None:
            return
        if peer._invite_failures >= 3 and time.monotonic() - peer._invite_lockout_ts < 60:
            return
        if not self._invite.verify_response(peer.pending_challenge, packet.payload):
            # Both counters. The per-link one cuts an abusive link without
            # locking out an honest joiner; the manager's is node-wide, and it
            # is the one `Docs/Architecture/security.md` describes — it existed
            # and nothing ever called it, so dropping the connection bought
            # three fresh attempts at no cost.
            peer._invite_failures += 1
            self._invite.record_failure()
            if peer._invite_failures >= 3:
                peer._invite_lockout_ts = time.monotonic()
            ack = Packet.create(INVITE_ACK, self._id.raw, packet.src_id,
                                bytes([_ACK_REJECTED]))
            await peer.send(ack)
            return
        self._invite.consume(peer.pending_challenge, packet.payload)
        peer.invite_accepted = True
        ack = Packet.create(INVITE_ACK, self._id.raw, packet.src_id,
                            bytes([_ACK_ACCEPTED]))
        await peer.send(ack)

    async def _handle_invite_ack(self, peer: _Peer, packet: Packet) -> None:
        if len(packet.payload) < 1:
            return
        if not peer.invite_sent:
            return
        peer.invite_sent = False
        if packet.payload[0] == _ACK_ACCEPTED:
            # The code is spent, but the fact that we presented one is not: it
            # is the only reason this link may hand us a trust root.
            peer.join_code = None
            peer.joined_by_invite = True
            await self.initiate_handshake(peer)

    async def _handle_e2e_handshake(self, peer: _Peer, packet: Packet) -> None:
        try:
            nonce, kem_pub, dsa_pub, cert_chain, signature = _decode_e2e_handshake(packet.payload)
        except Exception:
            return
        src = NodeID(packet.src_id)
        if NodeID.from_public_key(dsa_pub) != src:
            return
        if self._cert_store.verify_chain(cert_chain) is None:
            return
        if not self._identity.verify(nonce + kem_pub + dsa_pub, signature, dsa_pub):
            return
        # Simultaneous-open (glare) resolution: if we also have a handshake
        # in flight to this peer, only one may win or the two ends settle on
        # different keys and deadlock. The lower NodeID is the canonical
        # initiator; if that's us, ignore their handshake and let ours win.
        if src in self._e2e_pending_nonce and self._id.raw < src.raw:
            return
        self._e2e_pending_nonce.pop(src, None)
        self._e2e_pending_kem.pop(src, None)
        my_cert_chain = self._cert_store.get_chain_to_root(self._id)
        if my_cert_chain is None:
            return
        ciphertext, shared_secret = self._identity.kem_encapsulate(kem_pub)
        if src in self._e2e_sessions:
            # We already hold a live session with this peer, so this handshake
            # is either a stale/late duplicate (our retry loop, a slow relay)
            # or the peer re-keying from scratch (it lost its session, e.g. a
            # restart without persistence). Overwriting the live session right
            # now would poison the link in the stale case: the initiator has no
            # pending state for a duplicate, ignores our ACK, and keeps the OLD
            # key while we would hold the NEW one — every DATA packet then
            # fails GCM on both sides, silently, forever. Instead park the new
            # key as a *candidate* and still ACK: a peer that truly re-keyed
            # completes the handshake and its next DATA packet decrypts under
            # the candidate, which promotes it; a stale duplicate never
            # produces such a packet, so the candidate just expires.
            self._e2e_rekey_store(src, SessionKey(shared_secret))
        else:
            self._keep_e2e_session(src, SessionKey(shared_secret))
            if src not in self._e2e_sessions:
                return          # evicted on the way in — nothing to ACK under
        ack_sig = self._identity.sign(nonce + ciphertext + self._identity.dsa_public_key)
        ack_payload = _encode_e2e_handshake_ack(
            nonce, ciphertext, self._identity.dsa_public_key, my_cert_chain, ack_sig
        )
        ack = Packet.create(E2E_HANDSHAKE_ACK, self._id.raw, packet.src_id, ack_payload)
        await self._route_outbound(ack, blocking=False)   # in a receive loop
        # We became the responder — flush anything we had queued for this peer,
        # otherwise data sent before the session existed is stranded forever.
        # Always under the LIVE session (with a candidate pending, the old key
        # is still the only one the peer provably holds).
        for payload in self._e2e_pending_data.pop(src, []):
            pkt = Packet.create_encrypted(DATA, self._id.raw, src.raw, payload,
                                          self._e2e_sessions[src])
            await self._route_outbound(pkt, blocking=False)
        self._persist_state()

    def _e2e_rekey_store(self, src: NodeID, candidate: SessionKey) -> None:
        """Park a responder-side re-key candidate, bounded and TTL'd."""
        now = time.monotonic()
        for nid in [n for n, (_, exp) in self._e2e_rekey.items() if exp <= now]:
            del self._e2e_rekey[nid]
        if src in self._e2e_rekey:
            self._e2e_rekey[src] = (candidate, now + _E2E_REKEY_TTL)
            return
        if len(self._e2e_rekey) >= _E2E_REKEY_MAX:
            oldest = min(self._e2e_rekey, key=lambda n: self._e2e_rekey[n][1])
            del self._e2e_rekey[oldest]
        self._e2e_rekey[src] = (candidate, now + _E2E_REKEY_TTL)

    def _e2e_rekey_get(self, src: NodeID) -> SessionKey | None:
        """Fetch a live (unexpired) re-key candidate for ``src``, if any."""
        entry = self._e2e_rekey.get(src)
        if entry is None:
            return None
        session, exp = entry
        if exp <= time.monotonic():
            del self._e2e_rekey[src]
            return None
        return session

    async def _handle_e2e_handshake_ack(self, peer: _Peer, packet: Packet) -> None:
        try:
            nonce, ciphertext, dsa_pub, cert_chain, signature = _decode_e2e_handshake_ack(packet.payload)
        except Exception:
            return
        src = NodeID(packet.src_id)
        expected_nonce = self._e2e_pending_nonce.get(src)
        if expected_nonce is None or nonce != expected_nonce:
            return
        if NodeID.from_public_key(dsa_pub) != src:
            return
        if self._cert_store.verify_chain(cert_chain) is None:
            return
        if not self._identity.verify(nonce + ciphertext + dsa_pub, signature, dsa_pub):
            return
        kem_secret = self._e2e_pending_kem.pop(src, None)
        if kem_secret is None:
            return
        self._e2e_pending_nonce.pop(src, None)
        shared_secret = self._identity.kem_decapsulate(ciphertext, kem_secret)
        self._keep_e2e_session(src, SessionKey(shared_secret))
        pending = self._e2e_pending_data.pop(src, [])
        for payload in pending:
            pkt = Packet.create_encrypted(DATA, self._id.raw, src.raw, payload,
                                          self._e2e_sessions[src])
            await self._route_outbound(pkt, blocking=False)   # in a receive loop
        self._persist_state()

    async def _handle_handshake(self, peer: _Peer, packet: Packet) -> None:
        if peer.authenticated_id is not None:
            return
        if peer.pending_challenge is None:
            return
        # This handler is reachable on an *unauthenticated* link, and a failed
        # attempt clears neither guard above, so the same connection may try
        # again. Order the work accordingly: slice the payload, rule it out
        # with two SHA-256s, verify the one signature that binds it to our
        # challenge, and only then parse the chain — which verifies a
        # post-quantum signature per certificate in it.
        try:
            kem_pub, bob_dsa_pub, chain_bytes, signature = _split_handshake(
                packet.payload)
        except Exception:
            return
        claimed_id = NodeID.from_public_key(bob_dsa_pub)
        if claimed_id != NodeID(packet.src_id):
            return
        if not peer.note_handshake_attempt():
            return          # this link has had its tries
        if not self._identity.verify(peer.pending_challenge + kem_pub + bob_dsa_pub,
                                     signature, bob_dsa_pub):
            return
        try:
            chain = _decode_chain(chain_bytes)
        except Exception:
            return

        issued_cert: Certificate | None = None
        if peer.invite_accepted:
            issued_cert = self._identity.issue_cert(claimed_id, bob_dsa_pub)
            self._cert_add(issued_cert)
        else:
            if not chain:
                return
            anchor = self._cert_store.verify_chain(chain)
            if anchor is None:
                return
            for cert in chain:
                self._cert_add(cert)

        peer.authenticated_id = claimed_id
        peer.dsa_pub = bob_dsa_pub
        self._note_punch_link_up(peer)
        self._routing.add(claimed_id, [], bob_dsa_pub)
        ciphertext, shared_secret = self._identity.kem_encapsulate(kem_pub)
        peer.session = SessionKey(shared_secret)
        self._wake_neighbor_maintenance()
        self._schedule_catalog_sync(peer)  # catch this peer up on known apps
        self._schedule_release_sync(peer)  # …and on known releases
        self._schedule_pseudo_sync(peer)   # …and on who is called what
        # This peer connected to us (server side) and authenticated → positive,
        # zero-cost evidence that we are reachable on this transport. Never let
        # this observability bookkeeping break the handshake (zero crash).
        if not peer.is_client_side:
            try:
                scheme = self._peer_scheme(peer)
                if scheme is not None:
                    self._inbound_schemes.add(scheme)
            except Exception:
                pass
        dsa_pub      = self._identity.dsa_public_key
        server_chain = self._cert_store.get_chain_to_root(self._id) or []
        signature    = self._identity.sign(peer.pending_challenge + ciphertext + dsa_pub)
        payload      = _encode_handshake_ack(ciphertext, dsa_pub, server_chain,
                                             issued_cert, signature)
        peer.pending_challenge = None
        ack = Packet.create(HANDSHAKE_ACK, self._id.raw, packet.src_id, payload)
        await peer.send(ack)
        self._persist_state()  # persist the newly-known peer for restart recovery
        # Tell the peer the source IP we saw — that's their public address.
        observed = peer.transport.remote_ip()
        if observed and _is_ip_address(observed):
            try:
                await peer.send(Packet.create(OBSERVED_ADDR, self._id.raw,
                                              packet.src_id, observed.encode("ascii")))
            except Exception:
                pass

    async def _handle_handshake_ack(self, peer: _Peer, packet: Packet) -> None:
        if peer.pending_kem_secret is None:
            return
        if peer.received_challenge is None:
            return
        try:
            ciphertext, alice_dsa_pub, server_chain, issued_cert, signature = (
                _decode_handshake_ack(packet.payload)
            )
        except Exception:
            return
        if not self._identity.verify(peer.received_challenge + ciphertext + alice_dsa_pub,
                                     signature, alice_dsa_pub):
            return
        if NodeID.from_public_key(alice_dsa_pub) != NodeID(packet.src_id):
            return
        server_id = NodeID(packet.src_id)

        # Adopting a root is the one irreversible thing a handshake can do to
        # this node: from then on every chain anchored there authenticates. So
        # the branch is chosen by OUR record of having presented a code, never
        # by the answer carrying a certificate — the peer writes that field, and
        # it knows our public key (we just sent it), so it can always forge one.
        # Without this test, every address we dial — and we dial addresses
        # learned from gossip — could plant a trust anchor.
        if issued_cert is not None and peer.joined_by_invite:
            if issued_cert.issuer_id != server_id:
                return
            if issued_cert.subject_id != self._id:
                return
            for cert in server_chain:
                self._cert_add(cert)
            if server_chain:
                last = server_chain[-1]
                if last.is_self_signed:
                    self._cert_store.add_root(last.subject_id)
            self._cert_add(issued_cert)
        else:
            if not server_chain:
                return
            anchor = self._cert_store.verify_chain(server_chain)
            if anchor is None:
                return
            for cert in server_chain:
                self._cert_add(cert)

        peer.authenticated_id = server_id
        peer.dsa_pub = alice_dsa_pub
        self._note_punch_link_up(peer)
        # Record the address we dialled so this peer is reconnectable after a
        # restart (validated before advertising it to anyone else).
        addrs = ([peer.remote_addr]
                 if peer.remote_addr and _validate_uri(peer.remote_addr) else [])
        self._routing.add(server_id, addrs, alice_dsa_pub)
        shared_secret         = self._identity.kem_decapsulate(ciphertext,
                                                                peer.pending_kem_secret)
        peer.session          = SessionKey(shared_secret)
        peer.pending_kem_secret = None
        self._wake_neighbor_maintenance()
        self._schedule_catalog_sync(peer)  # catch this peer up on known apps
        self._schedule_release_sync(peer)  # …and on known releases
        self._schedule_pseudo_sync(peer)   # …and on who is called what
        self._persist_state()  # persist the newly-known peer for restart recovery

    # -----------------------------------------------------------------------
    # Hole-punching handlers
    # -----------------------------------------------------------------------

    async def _handle_punch_request(self, peer: '_Peer', packet: Packet) -> None:
        """Relay role: a peer asks us to coordinate a hole punch to *target*.

        We look up the target among our authenticated peers and send
        PUNCH_RELAY to both sides, telling each the other's public UDP
        address (as we observed it) and the UDP port they're listening on.
        """
        if not self._punch_enabled:
            return
        # Every request makes us emit two packets, one of them over a *different*
        # link than the one that paid for it. Every other plane that spends our
        # bandwidth on a peer's say-so has a valve; this one had none.
        if not self._punch_request_allowed(peer):
            return
        decoded = _decode_punch_request(packet.payload)
        if decoded is None:
            return
        target_id_raw, requester_udp_port = decoded
        target_id = NodeID(target_id_raw)

        # Find the target among our authenticated peers
        target_peer = next(
            (p for p in self._peers
             if p.authenticated_id == target_id and p.session is not None),
            None,
        )
        if target_peer is None:
            return  # can't relay if we don't have a link to the target

        # Observe the requester's source IP
        requester_ip = peer.transport.remote_ip()
        if requester_ip is None or not _is_ip_address(requester_ip):
            return
        requester_udp_addr = f"{requester_ip}:{requester_udp_port}"

        # Observe the target's source IP (from its TCP connection to us)
        target_ip = target_peer.transport.remote_ip()
        if target_ip is None or not _is_ip_address(target_ip):
            return
        # We don't know the target's UDP port yet — ask it by sending a
        # PUNCH_RELAY with the requester's info. The target will respond
        # with its own PUNCH_REQUEST if it wants to punch back.
        # For now, send the target the requester's UDP address.
        target_payload = _encode_punch_relay(
            packet.src_id, requester_udp_addr, requester_ip,
        )
        target_pkt = Packet.create(PUNCH_RELAY, self._id.raw,
                                   target_id.raw, target_payload)
        await target_peer.send(target_pkt)

        # Send the requester the target's known TCP address as a starting
        # point. The target will send its own probes once it receives the
        # relay. We include the target's observed IP.
        target_tcp_addr = target_peer.remote_addr or ""
        requester_payload = _encode_punch_relay(
            target_id.raw, target_tcp_addr, target_ip,
        )
        requester_pkt = Packet.create(PUNCH_RELAY, self._id.raw,
                                      packet.src_id, requester_payload)
        await peer.send(requester_pkt)

    def _punch_request_allowed(self, peer: '_Peer') -> bool:
        return self._gossip_allowed(self._punch_req_rate, peer,
                                    _PUNCH_REQ_WINDOW, _PUNCH_REQ_MAX)

    async def _handle_punch_relay(self, peer: '_Peer', packet: Packet) -> None:
        """We received relay info about a peer we want to punch to.

        Start sending UDP probes to the peer's address. The peer will be
        doing the same simultaneously, creating NAT mappings on both sides.
        """
        if not self._punch_enabled:
            return
        decoded = _decode_punch_relay(packet.payload)
        if decoded is None:
            return
        peer_id_raw, peer_addr_str, observed_ip = decoded
        peer_id = NodeID(peer_id_raw)

        if peer_id == self._id:
            return
        self._prune_punch_pending()
        if len(self._punch_pending) >= _PUNCH_MAX_PENDING:
            return
        if peer_id in self._punch_pending:
            return  # already punching to this target

        # We need a UDP listener to punch
        if self._udp_server is None:
            return

        # The relay told us the peer's address. If it's a TCP address, we
        # can't punch to it directly — we need the peer's UDP address.
        # The peer will send us its UDP probes, and we'll learn its UDP
        # address from the datagram source. For now, parse what we can.
        # If the peer_addr is host:port format, use it as the UDP target.
        udp_addr = peer_addr_str
        if "://" in udp_addr:
            # It's a URI like tcp://host:port — extract host:port
            result = _validate_uri(udp_addr)
            if result is None:
                return
            _, opaque = result
            udp_addr = opaque

        # Record our observed address from the relay
        if _is_ip_address(observed_ip) and observed_ip not in self._extra_addrs:
            if len(self._extra_addrs) < _MAX_EXTRA_ADDRS:
                self._extra_addrs.append(observed_ip)

        state = _PunchState(peer_id, udp_addr, observed_ip)
        state.deadline = time.monotonic() + _PUNCH_TIMEOUT
        self._punch_pending[peer_id] = state
        self._punch_stats["attempted"] += 1

        # Start sending probes
        # Bounded and tracked, like every other detached task — but the punch
        # state stays whatever happens: `gotchas.md` warns that deleting
        # `_punch_pending` early blocks the punch deterministically, and a task
        # the ceiling refuses must not take that state with it.
        self._spawn_bounded(self._send_punch_probes(state))

    def _prune_punch_pending(self) -> None:
        """Drop hole-punch attempts past their deadline (counted as failed)."""
        now = time.monotonic()
        for target in [t for t, s in self._punch_pending.items()
                       if not s.completed and now > s.deadline]:
            del self._punch_pending[target]
            self._punch_stats["failed"] += 1

    async def _send_punch_probes(self, state: '_PunchState') -> None:
        """Send a burst of UDP probe datagrams to punch the NAT hole."""
        from .udp_transport import _host_port

        # No UDP listener → we can't punch at all.
        if self._udp_server is None or self._udp_server._sock is None:
            self._punch_pending.pop(state.target, None)
            return

        # Without the peer's DSA key we can neither sign our probes nor verify
        # theirs — the punch can never complete, so drop it now.
        entry = self._routing.get(state.target)
        if entry is None or not entry.dsa_pub:
            self._punch_pending.pop(state.target, None)
            return

        # The relay often can't tell us the peer's UDP address: it only sees the
        # peer's TCP link, whose server-side remote_addr is None, so the address
        # relayed to us is empty. We then can't probe proactively — but the peer
        # DID get our address (the relay knows our UDP port from the request) and
        # is probing us. Keep the pending state so an incoming probe completes
        # the punch from its source address; dropping it here strands the punch
        # exactly on the side (larger NodeID) that must drive the handshake.
        try:
            host, port = _host_port(state.remote_udp_addr)
        except ValueError:
            return

        sock = self._udp_server._sock
        target_addr = (host, port)

        for i in range(_PUNCH_PROBE_COUNT):
            if time.monotonic() > state.deadline:
                break
            nonce = os.urandom(16)
            signature = self._identity.sign(_punch_signed_blob(
                _PUNCH_PROBE_MAGIC, self._id.raw, state.target.raw, nonce,
                _punch_minutes()[0]))
            probe = _build_punch_probe(self._id.raw, nonce, signature)
            try:
                sock.sendto(probe, target_addr)
            except (OSError, ConnectionError):
                break
            state.probes_sent += 1
            if i < _PUNCH_PROBE_COUNT - 1:
                await asyncio.sleep(_PUNCH_PROBE_INTERVAL)

    def handle_udp_datagram(self, data: bytes, addr: tuple[str, int]) -> None:
        """Called by the UDP server when a raw datagram arrives that is not
        a reliable transport frame (i.e. a punch probe or punch ack).

        This runs on the event loop via the datagram protocol callback.
        """
        # STUN binding response to our keepalive (magic cookie at bytes 4:8) —
        # handled regardless of punch state so continuous mode keeps learning
        # our public UDP mapping.
        if len(data) >= 20 and data[4:8] == b"\x21\x12\xa4\x42":
            self._handle_stun_keepalive_response(data, addr)
            return
        if not self._punch_enabled:
            return  # punching disabled — ignore probes and acks entirely
        # Before any crypto. These datagrams arrive with no link, no session and
        # no handshake — the cheapest thing an attacker can send — and each one
        # that names a node we know buys a full ML-DSA verification, plus a
        # *signature* if it verifies. Every other expensive plane in this file
        # has a valve; this was the only one reachable with no link at all.
        if not self._punch_datagram_allowed(addr):
            return
        # Try to parse as a punch probe
        probe = _parse_punch_probe(data)
        if probe is not None:
            node_id_raw, nonce, signature = probe
            self._handle_punch_probe_datagram(node_id_raw, nonce, signature, addr)
            return

        # Try to parse as a punch ack
        ack = _parse_punch_ack(data)
        if ack is not None:
            node_id_raw, nonce, signature = ack
            self._handle_punch_ack_datagram(node_id_raw, nonce, signature, addr)
            return

        # Not a probe or ack — could be a reliable transport frame or garbage.
        # The UDPTransport handles reliable frames via its own feed_datagram.
        # This method is only called for datagrams that don't match any
        # known transport in the server's dispatch table.

    def _punch_datagram_allowed(self, addr: tuple[str, int]) -> bool:
        """Per-source-address ceiling on raw punch datagrams.

        Keyed on the address because there is nothing else: no peer, no
        identity, nothing authenticated. A spoofed source therefore only spends
        the budget of the address it forged, which is the honest bound — and the
        table itself is bounded and pruned, so spraying addresses costs memory
        that is capped rather than memory that grows."""
        now = time.monotonic()
        table = self._punch_dgram_rate
        for k in [k for k, (_, ws) in table.items()
                  if now - ws > _PUNCH_DGRAM_WINDOW]:
            del table[k]
        while len(table) > _PUNCH_DGRAM_TRACKED:
            table.popitem(last=False)
        key = f"{addr[0]}:{addr[1]}".encode("utf-8", "replace")
        cnt, ws = table.get(key, (0, now))
        if now - ws > _PUNCH_DGRAM_WINDOW:
            cnt, ws = 0, now
        if cnt >= _PUNCH_DGRAM_MAX:
            table[key] = (cnt, ws)
            return False
        table[key] = (cnt + 1, ws)
        return True

    def _handle_stun_keepalive_response(self, data: bytes,
                                        addr: tuple[str, int] | None = None) -> None:
        """Parse a STUN Binding Response received on the listener socket and
        record the public UDP address peers actually reach us at.

        Only for a request we actually sent. `_parse_binding_response` does
        compare the transaction id — but it was handed `data[8:20]`, the id out
        of the datagram being checked, which makes the comparison a tautology.
        The listener socket is unconnected, so that left any host able to set
        the address this node believes it has, and then advertises to the mesh."""
        from .stun import _parse_binding_response
        if len(data) < 20:
            return
        txn_id = bytes(data[8:20])
        pending = self._stun_pending.pop(txn_id, None)
        if pending is None:
            return
        server_ip, expiry = pending
        if expiry <= time.monotonic():
            return
        if addr is not None and addr[0] != server_ip:
            return          # answered by somebody we did not ask
        result = _parse_binding_response(data, txn_id)
        if result is None:
            return
        ip, port = result
        self._observed_udp_addr = (ip, port)
        if (_is_ip_address(ip) and ip not in self._extra_addrs
                and ip not in self._local_ips
                and len(self._extra_addrs) < _MAX_EXTRA_ADDRS):
            self._extra_addrs.append(ip)
            self._poke_net("stun-keepalive")

    def _handle_punch_probe_datagram(self, node_id_raw: bytes, nonce: bytes,
                                      signature: bytes,
                                      addr: tuple[str, int]) -> None:
        """Handle a raw UDP punch probe from a peer."""
        src_id = NodeID(node_id_raw)
        if src_id == self._id:
            return

        # Look up the peer's DSA key to verify the signature
        entry = self._routing.get(src_id)
        if entry is None or not entry.dsa_pub:
            return

        # Verify the probe signature. It has to name *us* and a recent minute,
        # or a probe captured once is a token good at every node for ever.
        if not any(self._identity.verify(
                _punch_signed_blob(_PUNCH_PROBE_MAGIC, node_id_raw,
                                   self._id.raw, nonce, minute),
                signature, entry.dsa_pub)
                for minute in _punch_minutes()):
            return  # invalid, stale, or addressed elsewhere — ignore

        # Send a punch ACK back via UDP to confirm the hole is punched
        ack_nonce = os.urandom(16)
        ack_sig = self._identity.sign(_punch_signed_blob(
            _PUNCH_ACK_MAGIC, self._id.raw, node_id_raw, ack_nonce,
            _punch_minutes()[0]))
        ack = _build_punch_ack(self._id.raw, ack_nonce, ack_sig)
        if self._udp_server is not None and self._udp_server._sock is not None:
            try:
                self._udp_server._sock.sendto(ack, addr)
            except (OSError, ConnectionError):
                pass

        # If we have a pending punch to this peer, complete it
        state = self._punch_pending.get(src_id)
        if state is not None:
            state.probes_received += 1
            state.peer_nonce = nonce
            # The hole is punched — we can now create a UDP transport
            # to this peer. We'll do this once we also receive a PUNCH_ACK
            # (or after enough probes, optimistically).
            if not state.ack_received:
                # Optimistically create the transport after receiving a probe
                self._complete_punch(state, addr)

    def _handle_punch_ack_datagram(self, node_id_raw: bytes, nonce: bytes,
                                    signature: bytes,
                                    addr: tuple[str, int]) -> None:
        """Handle a raw UDP punch ack from a peer."""
        src_id = NodeID(node_id_raw)
        if src_id == self._id:
            return

        entry = self._routing.get(src_id)
        if entry is None or not entry.dsa_pub:
            return

        if not any(self._identity.verify(
                _punch_signed_blob(_PUNCH_ACK_MAGIC, node_id_raw,
                                   self._id.raw, nonce, minute),
                signature, entry.dsa_pub)
                for minute in _punch_minutes()):
            return

        state = self._punch_pending.get(src_id)
        if state is not None:
            state.ack_received = True
            self._complete_punch(state, addr)

    def _note_punch_link_up(self, peer: '_Peer') -> None:
        """A newly authenticated peer just came up over UDP. If we had a
        hole-punch attempt pending toward it, the authenticated link is proof
        the hole is open — count the completion here.

        The responder side (smaller NodeID) never drives _complete_punch: its
        link is created by the UDP accept path when the initiator's frames
        arrive. Its probe/ack exchange can also race ahead of the pending state
        set up from PUNCH_RELAY. Anchoring the completion to the handshake makes
        the counter reflect reality on both sides regardless of that race."""
        from .udp_transport import UDPTransport
        target = peer.authenticated_id
        if target is None or not isinstance(peer.transport, UDPTransport):
            return
        state = self._punch_pending.get(target)
        if state is None or state.completed:
            return  # no attempt, or _complete_punch already counted it
        state.completed = True
        self._punch_pending.pop(target, None)
        self._punch_stats["completed"] += 1

    def _complete_punch(self, state: '_PunchState',
                        addr: tuple[str, int]) -> None:
        """Finish a punched attempt once the hole is open.

        Both sides reach here (each got the other's probe), so the roles must
        be deterministic and only ONE side may drive the mesh handshake — else
        each side's UDP server would also auto-accept the other's frames and a
        duplicate peer would race the handshake to a dead link.

        The node with the larger NodeID is the *initiator*: it opens the UDP
        transport, registers it, and sends the first frame (acting like a
        client connecting). The other side does nothing here — its UDP server
        accept loop creates the peer and challenges when the initiator's frames
        arrive, exactly as for any inbound UDP connection."""
        from .udp_transport import UDPTransport

        if state.completed:
            return  # already handled (probe and ack both landed)
        if self._udp_server is None or self._udp_server._sock is None:
            return

        state.completed = True  # guards re-entry from probe+ack
        self._punch_pending.pop(state.target, None)
        self._punch_stats["completed"] += 1

        if self._id.raw <= state.target.raw:
            # Responder: let the standard UDP accept path handle it.
            return
        if len(self._peers) >= _MAX_PEERS:
            return

        # Both peers may punch at once (each upgrades its own relayed traffic),
        # so several attempts can complete toward the same endpoint. The server
        # dispatch table is the one link per source address: if it already holds
        # a live transport for this addr — a prior attempt, or the accept path —
        # a second one here would race the first to a dead, never-authenticated
        # link. Reuse the existing one instead of duplicating it.
        existing_t = self._udp_server._transports.get(addr)
        if existing_t is not None and not existing_t._closed:
            return

        # Initiator: open the transport, register it in the server dispatch
        # table so the peer's frames route to it, and send an initial keepalive
        # to trigger the responder's accept + challenge.
        transport = UDPTransport._from_server(self._udp_server._sock, addr,
                                              self._udp_server)
        self._udp_server._transports[addr] = transport
        transport._start_tasks()
        peer = _Peer(transport, is_client_side=True)
        peer.on_dead = self._reap_peer
        peer.total = self._metrics.total
        peer.trace = self.trace
        host, port = addr
        peer.remote_addr = f"udp://{host}:{port}"
        self._peers.append(peer)
        existing = self._routing.get(state.target)
        self._routing.add(state.target, [peer.remote_addr],
                          existing.dsa_pub if existing else b"")
        self._spawn_bounded(peer.start(self._handle_packet))
        self._spawn_bounded(self._kick_punched_link(peer, transport))

    async def _kick_punched_link(self, peer: '_Peer',
                                 transport: 'UDPTransport') -> None:
        """Open the punched link with a bounded burst of keepalive kicks.

        The responder challenges only once it sees a frame from us; a single
        lost datagram would otherwise strand the punch. Stop as soon as the
        link authenticates (further kicks are harmless dedup'd keepalives) or
        the transport dies — bounded so a dead peer can't loop us forever."""
        for i in range(_PUNCH_KICK_COUNT):
            if peer.authenticated_id is not None or transport._closed:
                return
            transport._send_raw(transport._link.build_keepalive())
            if i < _PUNCH_KICK_COUNT - 1:
                await asyncio.sleep(_PUNCH_KICK_INTERVAL)


# ---------------------------------------------------------------------------
# Packet dispatch
# ---------------------------------------------------------------------------
# Built once, from the unbound methods, rather than as a dict literal inside
# `_handle_packet`. That literal allocated a thirty-entry dict and thirty bound
# methods for **every packet the node received** — the hottest path there is —
# and threw them away again. Nothing about the dispatch changes; only the moment
# the table is built.

_HANDLERS = {
    DATA:              MeshNode._handle_data,
    PING:              MeshNode._handle_ping,
    PONG:              MeshNode._handle_pong,
    FIND_NODE:         MeshNode._handle_find_node,
    FOUND_NODE:        MeshNode._handle_found_node,
    FIND_VALUE:        MeshNode._handle_find_value,
    FOUND_VALUE:       MeshNode._handle_found_value,
    STORE:             MeshNode._handle_store,
    OBSERVED_ADDR:     MeshNode._handle_observed_addr,
    HANDSHAKE:         MeshNode._handle_handshake,
    HANDSHAKE_ACK:     MeshNode._handle_handshake_ack,
    CHALLENGE:         MeshNode._handle_challenge,
    INVITE:            MeshNode._handle_invite,
    INVITE_ACK:        MeshNode._handle_invite_ack,
    E2E_HANDSHAKE:     MeshNode._handle_e2e_handshake,
    E2E_HANDSHAKE_ACK: MeshNode._handle_e2e_handshake_ack,
    PUNCH_REQUEST:     MeshNode._handle_punch_request,
    PUNCH_RELAY:       MeshNode._handle_punch_relay,
    REACH_PROBE:       MeshNode._handle_reach_probe,
    REACH_PROBE_ACK:   MeshNode._handle_reach_probe_ack,
    CATALOG_ANNOUNCE:  MeshNode._handle_catalog_announce,
    PSEUDO_ANNOUNCE:   MeshNode._handle_pseudo_announce,
    RELEASE_ANNOUNCE:  MeshNode._handle_release_announce,
    RELEASE_FETCH:     MeshNode._handle_release_fetch,
    RELEASE_DATA:      MeshNode._handle_release_data,
    DIR_STORE:         MeshNode._handle_dir_store,
    DIR_FIND:          MeshNode._handle_dir_find,
    DIR_FOUND:         MeshNode._handle_dir_found,
    ECHO_REQUEST:      MeshNode._handle_echo_request,
    ECHO_REPLY:        MeshNode._handle_echo_reply,
}
