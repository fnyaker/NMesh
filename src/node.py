import asyncio
import base64
import hashlib
import hmac
import json
import os
import socket
import ssl
import struct
import time
from collections import OrderedDict
from .node_id import NodeID
from .routing import RoutingTable, NodeEntry
from .transport import BaseTransport
from .packet import Packet
from .crypto import CryptoIdentity, SessionKey
from .invite import InviteManager, compute_response
from .cert import Certificate
from .cert_store import CertStore
from .transport_manager import TransportManager
from .metrics import NodeMetrics, Counters
from .dht import ContentStore
from .ip_utils import local_ip_addresses, expand_listen_uri, split_host_port
from .net_monitor import NetMonitor
from .app_package import (
    build as _app_build, parse_manifest as _app_parse_manifest,
    reassemble as _app_reassemble, chunk_keys as _app_chunk_keys,
    content_key as _content_key, AppPackageError,
    pack_root as _app_pack_root, parse_root as _app_parse_root,
    reassemble_bytes as _app_reassemble_bytes,
)
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

_ACK_ACCEPTED = 0x00
_ACK_REJECTED = 0x01

# HANDSHAKE: kem_len(H) | dsa_len(H) | chain_bytes_len(H)
_HS_HEADER   = struct.Struct('!HHH')
# HANDSHAKE_ACK: ct_len(H) | dsa_len(H) | chain_bytes_len(H) | issued_cert_len(H)
_ACK_HEADER  = struct.Struct('!HHHH')
# FOUND_NODE entry: node_id(20) | addr_count(B) | chain_bytes_len(H)
_ENTRY_HEADER = struct.Struct('!20sBH')
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

_DIRECT_TYPES    = {PING, PONG, FIND_NODE, FOUND_NODE, FIND_VALUE, FOUND_VALUE,
                    STORE, OBSERVED_ADDR, PUNCH_REQUEST, PUNCH_RELAY,
                    REACH_PROBE, REACH_PROBE_ACK}
_MAX_EXTRA_ADDRS = 8
_ROUTABLE_TYPES  = {DATA, E2E_HANDSHAKE, E2E_HANDSHAKE_ACK}
_DHT_K              = 6      # replication: store/fetch across this many closest nodes
_DHT_QUERY_TIMEOUT  = 5.0
_POST_AUTH_TYPES = _DIRECT_TYPES | _ROUTABLE_TYPES
_BROADCAST_ID    = b"\xff" * 20
_MSG_DEDUP_MAX         = 10_000
_MAX_PEERS             = 128
_MAX_MALFORMED         = 32     # bad frames from one peer before we cut it (node rejection)
_MAX_PENDING_PER_TARGET = 128   # buffered payloads awaiting an E2E session, per target
_MAX_PENDING_TARGETS    = 256   # distinct half-open destinations kept in RAM
_ON_DEMAND_TIMEOUT     = 5.0    # transport open + handshake
_KAD_LOOKUP_TIMEOUT    = 3.0    # per FIND_NODE round
_KAD_LOOKUP_MAX_ROUNDS = 2
_AUTH_POLL_INTERVAL    = 0.05
_QID_LEN               = 8     # query_id bytes appended to FIND_NODE / prefix of FOUND_NODE

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
_RELAY_INVITE_TTL  = 300       # relay-invite block lifetime, seconds (== code TTL)
_RELAY_BLOCK_MAX_LEN = 32768   # v3 block cap (carries an ML-DSA key + signature)
_RELAY_JOIN_TIMEOUT = 12.0     # per-relay attempt: seek + tunnelled handshake
_MAX_RELAY_PEERS   = 64        # bounded virtual (relayed) peer table

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
    if not data:
        return []
    count = data[0]
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


def _decode_handshake(data: bytes) -> tuple[bytes, bytes, list[Certificate], bytes]:
    if len(data) < _HS_HEADER.size:
        raise ValueError("handshake payload too short")
    kem_len, dsa_len, chain_len = _HS_HEADER.unpack_from(data, 0)
    offset = _HS_HEADER.size
    if offset + kem_len + dsa_len + chain_len > len(data):
        raise ValueError("handshake payload truncated")
    kem_pub     = data[offset:offset + kem_len];   offset += kem_len
    dsa_pub     = data[offset:offset + dsa_len];   offset += dsa_len
    chain_bytes = data[offset:offset + chain_len]; offset += chain_len
    return kem_pub, dsa_pub, _decode_chain(chain_bytes), data[offset:]


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
# node_id(20) | addr_count(B) | chain_bytes_len(H)
#   | [addr_len(H) | addr_bytes]*addr_count
#   | chain_bytes
# ---------------------------------------------------------------------------

def _encode_entries(entries: list[NodeEntry]) -> bytes:
    out = bytes([len(entries)])
    for e in entries:
        chain_bytes = _encode_chain(e.cert_chain)
        addrs = e.addresses[:_MAX_ADDRESSES]
        out += _ENTRY_HEADER.pack(e.node_id.raw, len(addrs), len(chain_bytes))
        for addr in addrs:
            b = addr.encode('utf-8')
            out += _ADDR_LEN.pack(len(b)) + b
        out += chain_bytes
    return out


def _decode_entries(data: bytes) -> list[NodeEntry]:
    if len(data) < 1:
        raise ValueError("empty payload")
    count = data[0]
    offset = 1
    entries: list[NodeEntry] = []
    for _ in range(count):
        if offset + _ENTRY_HEADER.size > len(data):
            raise ValueError("truncated entry header")
        raw_id, addr_count, chain_bytes_len = _ENTRY_HEADER.unpack_from(data, offset)
        offset += _ENTRY_HEADER.size
        if addr_count > _MAX_ADDRESSES:
            raise ValueError(f"too many addresses in entry: {addr_count}")
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
        if offset + chain_bytes_len > len(data):
            raise ValueError("truncated chain in entry")
        chain_bytes = data[offset:offset + chain_bytes_len]
        offset += chain_bytes_len
        if not valid:
            continue  # drop entry with any malformed URI
        try:
            chain = _decode_chain(chain_bytes)
        except Exception:
            chain = []
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
        self.is_client_side: bool = is_client_side
        # A link used only to relay for others (SEEK / RELAY_CARRY) — we do not
        # try to authenticate to it, so its unsolicited CHALLENGE is ignored.
        self.relay_only: bool = False
        self.remote_addr: str | None = None   # dialled URI, for routing/reconnect
        self._invite_failures: int = 0
        self._invite_lockout_ts: float = 0.0
        self.dsa_pub: bytes = b""
        self._malformed: int = 0
        self.counters = Counters()   # per-link throughput
        self.total = None            # node-wide Counters, set by the node
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
                self._malformed += 1
                if self._malformed > _MAX_MALFORMED:
                    return
                continue
            nbytes = _HEADER_BYTES + len(packet.payload)
            self.counters.on_in(nbytes)
            if self.total is not None:
                self.total.on_in(nbytes)
            try:
                await on_packet(self, packet)
            except asyncio.CancelledError:
                raise
            except Exception:
                pass  # malformed payload or handler bug — drop, loop continues

    async def send(self, packet: Packet) -> None:
        await self.transport.send(packet)
        nbytes = _HEADER_BYTES + len(packet.payload)
        self.counters.on_out(nbytes)
        if self.total is not None:
            self.total.on_out(nbytes)

    async def stop(self) -> None:
        self.on_dead = None  # intentional shutdown — do not trigger reaping
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
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
        self._queue: asyncio.Queue = asyncio.Queue()
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
        if not self._closed:
            self._queue.put_nowait(inner)

    async def receive(self) -> Packet:
        while True:
            if self._closed:
                raise ConnectionError("relayed transport closed")
            try:
                return await asyncio.wait_for(self._queue.get(), timeout=1.0)
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


# ---------------------------------------------------------------------------
# MeshNode
# ---------------------------------------------------------------------------

class MeshNode:

    def __init__(self,
                 transport_manager: TransportManager,
                 identity_path: str | None = None,
                 cert_store_path: str | None = None,
                 session_store_path: str | None = None) -> None:
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
        self._seek_rate: OrderedDict[int, tuple] = OrderedDict()  # id(peer) -> (count, window)
        self._pending_seeks: OrderedDict[bytes, dict] = OrderedDict()  # seeker_id -> record
        self._carry_rate: OrderedDict[int, tuple] = OrderedDict()     # id(peer) -> (count, window)
        self._relay_peers: dict[bytes, _Peer] = {}   # remote_id -> virtual peer (tunnelled)
        self._lan_discovery = None                    # LanDiscovery answerer (opt-in)
        self._reach_probe_rate: OrderedDict[int, tuple] = OrderedDict()  # id(peer)->(n,win)
        self._reach_dials_active = 0                   # concurrent dial-backs (bounded)
        self._running = False
        self._peers: list[_Peer] = []
        self._invite = InviteManager()
        self._cert_store_path = cert_store_path
        self._cert_store = (CertStore.load(cert_store_path, self._id)
                            if cert_store_path else CertStore(self._id))
        self._cert_store.add(self._identity.self_signed_cert())
        self._seen_msgs: OrderedDict[int, float] = OrderedDict()
        self._data_queue: asyncio.Queue[tuple[NodeID, bytes]] = asyncio.Queue()
        self._e2e_sessions: dict[NodeID, SessionKey] = {}
        self._e2e_pending_kem: dict[NodeID, bytes] = {}
        self._e2e_pending_nonce: dict[NodeID, bytes] = {}
        self._e2e_pending_data: dict[NodeID, list[bytes]] = {}
        self._pending_connections: dict[NodeID, asyncio.Event] = {}
        self._pending_lookups: dict[NodeID, asyncio.Event] = {}
        self._pending_finds: dict[bytes, asyncio.Future] = {}
        self._dht_store = ContentStore()
        self._pending_values: dict[bytes, asyncio.Future] = {}
        self._transport_manager = transport_manager
        self._metrics = NodeMetrics()
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
        self._observed_udp_addr: tuple[str, int] | None = None  # from keepalive STUN
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

    @property
    def id(self) -> NodeID:
        return self._id

    @property
    def session(self) -> SessionKey | None:
        return next((p.session for p in self._peers if p.session is not None), None)

    def generate_invite(self) -> str:
        return self._invite.generate_code()

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

    async def remove_listen(self, uri: str) -> bool:
        """Stop listening on an address at runtime."""
        ok = await self._transport_manager.stop_listen(uri)
        if uri in self._addresses:
            self._addresses.remove(uri)
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
        loop = asyncio.get_running_loop()
        for host, port in DEFAULT_STUN_SERVERS:
            try:
                infos = await loop.getaddrinfo(
                    host, port, family=socket.AF_INET, type=socket.SOCK_DGRAM)
            except (OSError, socket.gaierror):
                continue
            if not infos:
                continue
            try:
                sock.sendto(_build_binding_request(), infos[0][4])
                self._punch_stats["keepalives"] += 1
            except (OSError, ConnectionError):
                continue
            return  # one server is enough per interval

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

        Uses stdlib only — no new dependency. Tries multiple services in
        order with a short timeout. Forces IPv4 connectivity so we learn
        our public IPv4 (behind NAT) rather than our already-known IPv6.
        On success, the IP is added to ``_extra_addrs`` so it appears in
        advertised URIs for all transports.
        """
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
                sock.settimeout(5)
                ctx = ssl.create_default_context()
                sock = ctx.wrap_socket(sock, server_hostname=host)
                sock.connect(infos[0][4])
                conn = http.client.HTTPSConnection(host, timeout=5)
                conn.sock = sock
                try:
                    conn.request("GET", path, headers={"User-Agent": "curl/8"})
                    resp = conn.getresponse()
                    ip = resp.read().decode("ascii").strip()
                finally:
                    conn.close()
                if _is_ip_address(ip):
                    if ip not in self._local_ips and ip not in self._extra_addrs:
                        if len(self._extra_addrs) < _MAX_EXTRA_ADDRS:
                            self._extra_addrs.append(ip)
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
        peer.remote_addr = address
        peer.join_code = code
        self._peers.append(peer)
        self._running = True
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
        transport = UDPTransport._from_server(self._udp_server._sock, addr)
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
        for peer in list(self._peers):
            await peer.stop()
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
                del pending[next(iter(pending))]
            queue = pending.setdefault(target, [])
            queue.append(payload)
            if len(queue) > _MAX_PENDING_PER_TARGET:
                del queue[0]  # drop oldest — bounded backlog per target
            if target not in self._e2e_pending_kem:
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
        await peer.send(packet)

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
        existing = self._pending_lookups.get(target)
        if existing is not None:
            try:
                await asyncio.wait_for(existing.wait(), timeout=timeout)
            except asyncio.TimeoutError:
                pass
            return self._routing.contains(target)

        event = asyncio.Event()
        self._pending_lookups[target] = event
        try:
            seen_peers: set[bytes] = set()
            deadline = asyncio.get_event_loop().time() + timeout
            for _ in range(_KAD_LOOKUP_MAX_ROUNDS):
                if self._routing.contains(target):
                    return True
                queried = 0
                for p in list(self._peers):
                    if p.authenticated_id is None or p.session is None:
                        continue
                    if p.authenticated_id.raw in seen_peers:
                        continue
                    seen_peers.add(p.authenticated_id.raw)
                    pkt = Packet.create(FIND_NODE, self._id.raw,
                                        NodeID(b"\xff" * 20).raw,
                                        target.raw + os.urandom(_QID_LEN))
                    try:
                        await p.send(pkt)
                        queried += 1
                    except Exception:
                        pass
                if queried == 0:
                    break
                sub_deadline = min(deadline,
                                   asyncio.get_event_loop().time() + _KAD_LOOKUP_TIMEOUT)
                while asyncio.get_event_loop().time() < sub_deadline:
                    if self._routing.contains(target):
                        return True
                    await asyncio.sleep(_AUTH_POLL_INTERVAL)
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
        try:
            if not self._routing.contains(target):
                await self._kademlia_lookup(
                    target, _KAD_LOOKUP_TIMEOUT * _KAD_LOOKUP_MAX_ROUNDS
                )
                if not self._routing.contains(target):
                    return None
            peer = await self._connect_routing(target)
            if peer is None:
                # No advertised address is directly connectable (typically
                # both sides behind NAT) — fall back to a UDP hole punch
                # coordinated by a shared relay.
                return await self._punch_route_to(target, timeout)
            ok = await self._wait_for_peer_authenticated(peer, target, timeout)
            if not ok:
                try:
                    await peer.stop()
                except Exception:
                    pass
                if peer in self._peers:
                    self._peers.remove(peer)
                return await self._punch_route_to(target, timeout)
            return peer
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
        asyncio.create_task(self._ensure_route_to(target))

    async def _kad_query_node(self, node_id: NodeID, target: NodeID,
                               timeout: float = 5.0) -> list[NodeEntry]:
        peer = next(
            (p for p in self._peers
             if p.authenticated_id == node_id and p.session is not None),
            None,
        )
        if peer is None:
            peer = await self._ensure_route_to(node_id, timeout)
            if peer is None:
                return []
        query_id = os.urandom(_QID_LEN)
        future: asyncio.Future = asyncio.get_event_loop().create_future()
        self._pending_finds[query_id] = future
        packet = Packet.create(FIND_NODE, self._id.raw,
                               NodeID(b"\xff" * 20).raw,
                               target.raw + query_id)
        try:
            await peer.send(packet)
            return await asyncio.wait_for(asyncio.shield(future), timeout)
        except (asyncio.TimeoutError, Exception):
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
        if not self._peers:
            return
        for peer in list(self._peers):
            if peer.session is not None and self._addresses:
                await self.ping(peer)
        discovered = await self.kad_lookup(self._id)
        tasks = []
        for nid in discovered:
            if nid == self._id:
                continue
            if any(p.authenticated_id == nid for p in self._peers):
                continue
            tasks.append(asyncio.create_task(self._ensure_route_to(nid)))
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _route_outbound(self, packet: Packet) -> None:
        target = NodeID(packet.dst_id)
        direct = next(
            (p for p in self._peers
             if p.authenticated_id == target and p.session is not None),
            None,
        )
        if direct is not None:
            await direct.send(packet)
            return
        candidates = [p for p in self._peers
                      if p.authenticated_id is not None and p.session is not None]
        if candidates:
            best = min(candidates, key=lambda p: target.distance(p.authenticated_id))
            await best.send(packet)
            # Relayed path — try to upgrade to a direct link in the
            # background (direct connect, then UDP hole punch).
            self._maybe_upgrade_path(target)
            return
        peer = await self._ensure_route_to(target)
        if peer is not None:
            await peer.send(packet)

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
        self._persist_state()
        packet = Packet.create(E2E_HANDSHAKE, self._id.raw, target.raw, payload)
        await self._route_outbound(packet)

    async def _on_new_transport(self, transport: BaseTransport) -> None:
        if len(self._peers) >= _MAX_PEERS:
            await transport.close()
            return
        peer = _Peer(transport, is_client_side=False)
        peer.on_dead = self._reap_peer
        peer.total = self._metrics.total
        self._peers.append(peer)
        self._poke_net("peer-connected")
        await peer.start(self._handle_packet)
        challenge = self._invite.generate_challenge()
        peer.pending_challenge = challenge
        packet = Packet.create(CHALLENGE, self._id.raw,
                               NodeID(b"\xff" * 20).raw, challenge)
        await peer.send(packet)

    async def _connect_routing(self, node_id: NodeID) -> _Peer | None:
        entry = self._routing.get(node_id)
        if entry is None:
            return None
        for uri in _order_by_preference(list(entry.addresses)):  # prefer global IPv6
            result = _validate_uri(uri)
            if result is None:
                continue
            scheme, _ = result
            if not self._transport_manager.is_supported(scheme):
                continue
            try:
                transport = await self._transport_manager.connect(uri)
            except Exception:
                continue
            peer = _Peer(transport, is_client_side=True)
            peer.on_dead = self._reap_peer
            peer.total = self._metrics.total
            peer.remote_addr = uri
            self._peers.append(peer)
            await peer.start(self._handle_packet)
            return peer
        return None

    async def _inject_peer(self, transport: BaseTransport) -> _Peer:
        """For testing only — injects a fake transport as a client-side peer."""
        peer = _Peer(transport, is_client_side=True)
        peer.on_dead = self._reap_peer
        peer.total = self._metrics.total
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
        self._poke_net("peer-lost")

    def _persist_state(self) -> None:
        """Snapshot E2E + routing state to the encrypted store, if persistence
        is on. Never raises — a disk problem must not take the node down."""
        if self._session_store is None:
            return
        try:
            self._session_store.save(
                self._e2e_sessions, self._e2e_pending_kem,
                self._e2e_pending_nonce, self._e2e_pending_data,
                self._routing.export_entries(),
            )
        except Exception:
            pass

    # -- console / management surface -------------------------------------
    # These read or mutate node state and are meant to be driven from the web
    # console. Async ones run on the event loop; the console marshals into it.

    async def console_snapshot(self) -> dict:
        """A JSON-serialisable view of the node. Built on the event loop, so it
        reads live state atomically (no awaits mid-iteration)."""
        peers = []
        for p in self._peers:
            peers.append({
                "authenticated_id": p.authenticated_id.raw.hex() if p.authenticated_id else None,
                "is_client_side": p.is_client_side,
                "has_session": p.session is not None,
                "malformed": p._malformed,
                "counters": p.counters.as_dict(),
                "transport": self._peer_scheme(p),
            })
        routing = [
            {"id": e.node_id.raw.hex(), "addresses": list(e.addresses)}
            for e in self._routing.all_entries()
        ]
        return {
            "id": self._id.raw.hex(),
            "addresses": list(self._addresses),
            "listen": list(self._addresses),
            "advertised": self.advertised_uris(),
            "local_ips": list(self._local_ips),
            "transports": self._transport_manager.schemes(),
            "listening": self._transport_manager.listening_uris()
                         + ([self._udp_listen_uri] if self._udp_listen_uri else []),
            "running": self._running,
            "uptime": self._metrics.uptime(),
            "peer_count": len(self._peers),
            "authenticated_peers": sum(
                1 for p in self._peers if p.authenticated_id and p.session
            ),
            "peers": peers,
            "routing": routing,
            "routing_size": len(routing),
            "e2e_sessions": [nid.raw.hex() for nid in self._e2e_sessions],
            "total": self._metrics.total.as_dict(),
            "load": self._metrics.load(),
            "network": (self._net_monitor.status()
                        if self._net_monitor is not None else None),
            "transport_details": self._transport_details(),
            "reachability": self.reachability(),
            "relay_capable": self.relay_capable(),
            "pending_seeks": len(self._pending_seeks),
            "lan_discovery": self._lan_discovery is not None,
            "punch_enabled": self._punch_enabled,
            "punch_keepalive": self._punch_keepalive,
            "join_status": self._join_status,
        }

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

    def relay_capable(self) -> bool:
        """True if we are confirmed reachable by a broad audience — i.e. we can
        serve as a rendezvous/relay for others. Any transport may qualify."""
        return any(d.get("scope") == "world" and d.get("confirmed")
                   for d in self.reachability())

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
        ports, connected peers — plus hole-punching state for udp://."""
        listening = (self._transport_manager.listening_uris()
                     + ([self._udp_listen_uri] if self._udp_listen_uri else []))
        by_scheme: dict[str, list[str]] = {}
        for uri in listening:
            parsed = _validate_uri(uri)
            if parsed is not None:
                by_scheme.setdefault(parsed[0], []).append(uri)

        peer_schemes: dict[str, int] = {}
        for p in self._peers:
            scheme = self._peer_scheme(p)
            if scheme is not None:
                peer_schemes[scheme] = peer_schemes.get(scheme, 0) + 1

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
                "peers": peer_schemes.get(scheme, 0),
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
                    "relay_peers": self._relay_peer_count(),
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

    def _relay_peer_count(self) -> int:
        """Authenticated peers that could coordinate a punch (or that we could
        relay between). Hole punching is impossible without at least one."""
        return sum(1 for p in self._peers
                   if p.authenticated_id is not None and p.session is not None)

    def _punch_readiness(self) -> tuple[bool, str]:
        """Explain, for the console, whether a punch can happen right now.

        Punching is on-demand: it only fires when this node tries to reach a
        peer it can't connect to directly AND shares a relay with. This tells
        the operator why nothing is punching — the top question behind NAT."""
        if not self._punch_enabled:
            return False, "hole punching is off"
        if self._udp_server is None:
            return False, "no UDP listener — start UDP first"
        relays = self._relay_peer_count()
        if relays == 0:
            return False, ("no connected peer to coordinate through — join a "
                           "reachable node (a public rendezvous) first")
        return True, (f"ready — {relays} peer(s) can coordinate a punch; it "
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
        return _order_by_preference(out)

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
        candidates = _order_by_preference(candidates)   # prefer global IPv6
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
        ok = self._cert_store.add(cert)
        if ok and self._cert_store_path:
            self._cert_store.save(self._cert_store_path)
        return ok

    def _is_seen(self, msg_id: int) -> bool:
        if msg_id in self._seen_msgs:
            return True
        if len(self._seen_msgs) >= _MSG_DEDUP_MAX:
            self._seen_msgs.popitem(last=False)
        self._seen_msgs[msg_id] = time.monotonic()
        return False

    async def _forward_packet(self, from_peer: _Peer, packet: Packet) -> None:
        if packet.ttl <= 1:
            return
        target = NodeID(packet.dst_id)
        # Direct peer is always preferred
        direct = next(
            (p for p in self._peers
             if p is not from_peer
             and p.authenticated_id == target
             and p.session is not None),
            None,
        )
        if direct is not None:
            await direct.send(packet.with_decremented_ttl())
            return
        # Routing table entry → on-demand is more reliable than random XOR hop,
        # especially across network boundaries where only certain nodes have reachability.
        if self._routing.contains(target):
            peer = await self._ensure_route_to(target)
            if peer is not None and peer is not from_peer:
                await peer.send(packet.with_decremented_ttl())
                return
        candidates = [
            p for p in self._peers
            if p is not from_peer
            and p.authenticated_id is not None
            and p.session is not None
        ]
        if candidates:
            best = min(candidates, key=lambda p: target.distance(p.authenticated_id))
            await best.send(packet.with_decremented_ttl())
            return
        # Last resort: Kademlia lookup + on-demand
        peer = await self._ensure_route_to(target)
        if peer is not None and peer is not from_peer:
            await peer.send(packet.with_decremented_ttl())

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
            if packet.dst_id != self._id.raw and packet.dst_id != _BROADCAST_ID:
                await self._forward_packet(peer, packet)
                return
        handlers = {
            DATA:              self._handle_data,
            PING:              self._handle_ping,
            PONG:              self._handle_pong,
            FIND_NODE:         self._handle_find_node,
            FOUND_NODE:        self._handle_found_node,
            FIND_VALUE:        self._handle_find_value,
            FOUND_VALUE:       self._handle_found_value,
            STORE:             self._handle_store,
            OBSERVED_ADDR:     self._handle_observed_addr,
            HANDSHAKE:         self._handle_handshake,
            HANDSHAKE_ACK:     self._handle_handshake_ack,
            CHALLENGE:         self._handle_challenge,
            INVITE:            self._handle_invite,
            INVITE_ACK:        self._handle_invite_ack,
            E2E_HANDSHAKE:     self._handle_e2e_handshake,
            E2E_HANDSHAKE_ACK: self._handle_e2e_handshake_ack,
            PUNCH_REQUEST:     self._handle_punch_request,
            PUNCH_RELAY:       self._handle_punch_relay,
            REACH_PROBE:       self._handle_reach_probe,
            REACH_PROBE_ACK:   self._handle_reach_probe_ack,
        }
        handler = handlers.get(packet.type)
        if handler:
            await handler(peer, packet)

    # -----------------------------------------------------------------------
    # Relayed invitation (INVITE_SEEK)
    # -----------------------------------------------------------------------

    def _seek_allowed(self, peer: '_Peer') -> bool:
        """Per-ingress-link rate limit: bound how many seeks one link can make
        us process (and verify) in a window. Table is bounded and pruned."""
        now = time.monotonic()
        for k in [k for k, (_, ws) in self._seek_rate.items()
                  if now - ws > _SEEK_RATE_WINDOW]:
            del self._seek_rate[k]
        while len(self._seek_rate) > _RDV_MAX:
            self._seek_rate.popitem(last=False)
        key = id(peer)
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
        """The live invite code whose hash matches, if any (constant-time)."""
        for code in list(self._invite._codes.keys()):
            if hmac.compare_digest(_h_code(code), h_code):
                return code
        return None

    async def _handle_invite_seek(self, peer: '_Peer', packet: Packet) -> None:
        """Process a relayed invitation seek. Cheap, bounded checks run before
        the expensive signature verification; nothing here can crash the loop."""
        # 1. cheap structural / bound checks first
        if packet.ttl <= 0:
            return
        if packet.msg_id != packet.compute_msg_id():
            return  # msg_id must commit to content (anti-amplification)
        if self._is_seen(packet.msg_id):
            return
        if not self._seek_allowed(peer):
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
            asyncio.ensure_future(self._start_relay_invite(seeker, peer))

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
        key = id(peer)
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
        if packet.msg_id != packet.compute_msg_id():
            return
        if self._is_seen(packet.msg_id):
            return
        if not self._carry_allowed(peer):
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
        peers only. TTL-bounded; no on-demand connects (stays cheap pre-auth)."""
        if packet.ttl <= 1:
            return
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
                sent += 1
            except Exception:
                pass
        return sent

    def _reach_probe_allowed(self, peer: '_Peer') -> bool:
        now = time.monotonic()
        for k in [k for k, (_, ws) in self._reach_probe_rate.items()
                  if now - ws > _SEEK_RATE_WINDOW]:
            del self._reach_probe_rate[k]
        while len(self._reach_probe_rate) > _RDV_MAX:
            self._reach_probe_rate.popitem(last=False)
        key = id(peer)
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
        ok = False
        if observed is not None:
            self._reach_dials_active += 1
            try:
                ok = await self._dial_back(scheme, observed, port)
            finally:
                self._reach_dials_active -= 1
        reply = struct.pack("!BB", len(scheme.encode()), 1 if ok else 0) + scheme.encode()
        try:
            await peer.send(Packet.create(REACH_PROBE_ACK, self._id.raw,
                                          packet.src_id, reply))
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
        if ok and scheme and self._transport_manager.is_supported(scheme):
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
            return
        await self._data_queue.put((src, plaintext))

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
        if not valid_uris:
            return
        self._routing.add(src, valid_uris, peer.dsa_pub)
        pong = Packet.create(PONG, self._id.raw, packet.src_id, b"")
        await peer.send(pong)

    async def _handle_pong(self, peer: _Peer, packet: Packet) -> None:
        pass

    async def _handle_find_node(self, peer: _Peer, packet: Packet) -> None:
        if len(packet.payload) != 20 + _QID_LEN:
            return
        target = NodeID(packet.payload[:20])
        query_id = packet.payload[20:]
        closest: list[NodeEntry] = []
        for e in self._routing.get_closest(target):
            if not e.dsa_pub:
                continue
            chain = self._cert_store.get_chain_to_root(e.node_id) or []
            closest.append(NodeEntry(e.node_id, e.addresses, e.dsa_pub, chain))
        response = Packet.create(FOUND_NODE, self._id.raw, packet.src_id,
                                 query_id + _encode_entries(closest))
        await peer.send(response)

    async def _handle_found_node(self, peer: _Peer, packet: Packet) -> None:
        if len(packet.payload) < _QID_LEN:
            return
        query_id = packet.payload[:_QID_LEN]
        try:
            entries = _decode_entries(packet.payload[_QID_LEN:])
        except Exception:
            entries = []
        valid_entries: list[NodeEntry] = []
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
            self._routing.add(entry.node_id, entry.addresses, dsa_pub)
            valid_entries.append(entry)
        future = self._pending_finds.pop(query_id, None)
        if future is not None and not future.done():
            future.set_result(valid_entries)

    # -- DHT (content-addressed value store) ------------------------------

    async def _handle_store(self, peer: _Peer, packet: Packet) -> None:
        # payload: key(20) || value ; stored only if key == hash(value)
        if len(packet.payload) < 20:
            return
        key = packet.payload[:20]
        value = packet.payload[20:]
        self._dht_store.put(key, value)  # put() rejects non-content-addressed data

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

    async def _handle_find_value(self, peer: _Peer, packet: Packet) -> None:
        # payload: key(20) || query_id(8) ; reply carries the value or empty
        if len(packet.payload) != 20 + _QID_LEN:
            return
        key = packet.payload[:20]
        query_id = packet.payload[20:]
        value = self._dht_store.get(key) or b""
        reply = Packet.create(FOUND_VALUE, self._id.raw, packet.src_id,
                              query_id + value)
        await peer.send(reply)

    async def _handle_found_value(self, peer: _Peer, packet: Packet) -> None:
        if len(packet.payload) < _QID_LEN:
            return
        query_id = packet.payload[:_QID_LEN]
        value = packet.payload[_QID_LEN:]
        future = self._pending_values.pop(query_id, None)
        if future is not None and not future.done():
            future.set_result(value if value else None)

    async def _dht_store_at(self, node_id: NodeID, key: bytes, value: bytes) -> None:
        peer = await self._ensure_route_to(node_id, _DHT_QUERY_TIMEOUT)
        if peer is None:
            return
        try:
            await peer.send(Packet.create(STORE, self._id.raw,
                                          NodeID(b"\xff" * 20).raw, key + value))
        except Exception:
            pass

    async def _dht_find_value_at(self, node_id: NodeID, key: bytes) -> bytes | None:
        peer = await self._ensure_route_to(node_id, _DHT_QUERY_TIMEOUT)
        if peer is None:
            return None
        query_id = os.urandom(_QID_LEN)
        future: asyncio.Future = asyncio.get_event_loop().create_future()
        self._pending_values[query_id] = future
        try:
            await peer.send(Packet.create(FIND_VALUE, self._id.raw,
                                          NodeID(b"\xff" * 20).raw, key + query_id))
            return await asyncio.wait_for(asyncio.shield(future), _DHT_QUERY_TIMEOUT)
        except Exception:
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

    # -- application packages ---------------------------------------------

    async def publish_app(self, name: str, version: str,
                          files: dict[str, bytes]) -> bytes:
        """Publish an app on the DHT. Returns the app id (= hash of the root).

        Content chunks, the manifest (itself chunked), and a small root that
        lists the manifest chunks are all stored content-addressed — so an app
        can have arbitrarily many files."""
        _, manifest, chunks = _app_build(name, version, files)
        from .dht import MAX_VALUE
        for value in chunks.values():
            await self.dht_put(value)
        root_bytes, manifest_chunks = _app_pack_root(manifest)
        if len(root_bytes) > MAX_VALUE:
            raise AppPackageError("app has too many files even after chunking")
        for value in manifest_chunks.values():
            await self.dht_put(value)
        return await self.dht_put(root_bytes)

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
            peer._invite_failures += 1
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
            peer.join_code = None
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
        self._e2e_sessions[src] = SessionKey(shared_secret)
        ack_sig = self._identity.sign(nonce + ciphertext + self._identity.dsa_public_key)
        ack_payload = _encode_e2e_handshake_ack(
            nonce, ciphertext, self._identity.dsa_public_key, my_cert_chain, ack_sig
        )
        ack = Packet.create(E2E_HANDSHAKE_ACK, self._id.raw, packet.src_id, ack_payload)
        await self._route_outbound(ack)
        # We became the responder — flush anything we had queued for this peer,
        # otherwise data sent before the session existed is stranded forever.
        for payload in self._e2e_pending_data.pop(src, []):
            pkt = Packet.create_encrypted(DATA, self._id.raw, src.raw, payload,
                                          self._e2e_sessions[src])
            await self._route_outbound(pkt)
        self._persist_state()

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
        self._e2e_sessions[src] = SessionKey(shared_secret)
        pending = self._e2e_pending_data.pop(src, [])
        for payload in pending:
            pkt = Packet.create_encrypted(DATA, self._id.raw, src.raw, payload,
                                          self._e2e_sessions[src])
            await self._route_outbound(pkt)
        self._persist_state()

    async def _handle_handshake(self, peer: _Peer, packet: Packet) -> None:
        if peer.authenticated_id is not None:
            return
        if peer.pending_challenge is None:
            return
        try:
            kem_pub, bob_dsa_pub, chain, signature = _decode_handshake(packet.payload)
        except Exception:
            return
        if not self._identity.verify(peer.pending_challenge + kem_pub + bob_dsa_pub,
                                     signature, bob_dsa_pub):
            return
        claimed_id = NodeID.from_public_key(bob_dsa_pub)
        if claimed_id != NodeID(packet.src_id):
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
        # This peer connected to us (server side) and authenticated → positive,
        # zero-cost evidence that we are reachable on this transport. Never let
        # this observability bookkeeping break the handshake (zéro crash).
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

        if issued_cert is not None:
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
        asyncio.create_task(self._send_punch_probes(state))

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

        try:
            host, port = _host_port(state.remote_udp_addr)
        except ValueError:
            self._punch_pending.pop(state.target, None)
            return

        # Get the raw socket from our UDP server
        if self._udp_server is None or self._udp_server._sock is None:
            self._punch_pending.pop(state.target, None)
            return

        sock = self._udp_server._sock
        target_addr = (host, port)

        # Look up the peer's DSA public key for signing the probe
        entry = self._routing.get(state.target)
        if entry is None or not entry.dsa_pub:
            self._punch_pending.pop(state.target, None)
            return

        for i in range(_PUNCH_PROBE_COUNT):
            if time.monotonic() > state.deadline:
                break
            nonce = os.urandom(16)
            signature = self._identity.sign(
                _PUNCH_PROBE_MAGIC + self._id.raw + nonce
            )
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
            self._handle_stun_keepalive_response(data)
            return
        if not self._punch_enabled:
            return  # punching disabled — ignore probes and acks entirely
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

    def _handle_stun_keepalive_response(self, data: bytes) -> None:
        """Parse a STUN Binding Response received on the listener socket and
        record the public UDP address peers actually reach us at."""
        from .stun import _parse_binding_response
        # The response echoes our transaction id; use it directly so the
        # XOR-MAPPED-ADDRESS de-XORs correctly without our tracking it.
        result = _parse_binding_response(data, data[8:20])
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

        # Verify the probe signature
        if not self._identity.verify(
            _PUNCH_PROBE_MAGIC + node_id_raw + nonce, signature, entry.dsa_pub
        ):
            return  # invalid signature — hostile probe, ignore

        # Send a punch ACK back via UDP to confirm the hole is punched
        ack_nonce = os.urandom(16)
        ack_sig = self._identity.sign(
            _PUNCH_ACK_MAGIC + self._id.raw + ack_nonce
        )
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

        if not self._identity.verify(
            _PUNCH_ACK_MAGIC + node_id_raw + nonce, signature, entry.dsa_pub
        ):
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

        # Initiator: open the transport, register it in the server dispatch
        # table so the peer's frames route to it, and send an initial keepalive
        # to trigger the responder's accept + challenge.
        transport = UDPTransport._from_server(self._udp_server._sock, addr)
        self._udp_server._transports[addr] = transport
        transport._start_tasks()
        peer = _Peer(transport, is_client_side=True)
        peer.on_dead = self._reap_peer
        peer.total = self._metrics.total
        host, port = addr
        peer.remote_addr = f"udp://{host}:{port}"
        self._peers.append(peer)
        existing = self._routing.get(state.target)
        self._routing.add(state.target, [peer.remote_addr],
                          existing.dsa_pub if existing else b"")
        asyncio.create_task(peer.start(self._handle_packet))
        asyncio.create_task(self._kick_punched_link(peer, transport))

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
