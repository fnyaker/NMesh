"""
The wire: encode and decode every payload the core understands.

Handshake, certificate chain, addresses, FOUND_NODE entries, ping
trailers, E2E handshakes, punch signalling, invitation seeks and the
connect blocks. Every decoder here is a parsing surface reachable
from the network, so each one bounds what it will read before it
reads it — this is the module `tests/test_fuzz.py` exists for.
"""

import base64
import hashlib
import json
import struct
import time

from ..cert import Certificate, FINGERPRINT_LEN
from ..ip_utils import split_host_port
from .constants import *  # noqa: F401,F403
from ..node_id import NodeID
from .messages import INVITE_SEEK
from ..packet import Packet
from ..routing import NodeEntry
from ..uri import _validate_uri, _MAX_URI_LEN, _MAX_ADDRESSES


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


def _decode_addresses_at(data: bytes) -> tuple[list[str], int]:
    """Decode a packed address list and say where it ended.

    The offset is what lets a PING carry something *after* its addresses (see
    :data:`_KA_TAIL`). Split out rather than duplicated: two walks over one
    encoding is two chances for them to disagree about where it stops."""
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
    return addresses, offset


def _decode_addresses(data: bytes) -> list[str]:
    """Decode a packed address list. Raises ValueError on structural errors or count > _MAX_ADDRESSES."""
    return _decode_addresses_at(data)[0]


# What a PING carries after its addresses: how long until the next one, and a
# token the answer echoes so a probe can be matched to *its own* answer.
#
# It is a trailer, and that is the whole compatibility story: `_decode_addresses`
# has always stopped at the last address and ignored whatever followed, so a
# build without this reads a tailed PING as exactly the PING it always read.
# The same trick as the `_HINTS_OK` byte on a FOUND_NODE, for the same reason —
# there is no version to bump and nothing to negotiate for the *reader*.
#
# The tail is only ever *sent* to a peer that announced the `keepalive` feature,
# which is a different question: a peer that cannot echo the token would have
# every probe charged as a loss. See `MeshNode.peer_announces`.
_KA_TAIL = struct.Struct("!IQ")          # next_ms, token
_KA_TOKEN = struct.Struct("!Q")
# fast_min, fast_max, slow_min, slow_max — a KA_PROPOSE body. Four numbers,
# not two: see `mlo.Bounds` for why a single range leaves the ceiling as a
# lever anybody can pull.
_KA_BOUNDS = struct.Struct("!IIII")
_KA_WANTED = struct.Struct("!I")         # a KA_REQUEST body


#: A probe carrying no addresses — the one byte `_encode_addresses([])` builds,
#: hoisted because it is now the common case and a probe should not allocate to
#: say "nothing new". Exactly what a node with no announceable address has
#: always sent, so no build anywhere reads it as anything unusual.
_NO_ADDRESSES = _encode_addresses([])


def _encode_ping_tail(next_ms: int, token: int) -> bytes:
    return _KA_TAIL.pack(max(0, min(0xFFFFFFFF, int(next_ms))), token)


def _decode_ping_tail(data: bytes, offset: int):
    """``(next_ms, token)`` from a PING's trailer, or ``None`` when there is
    none.

    Anything that is not exactly this trailer is *ignored*, never charged: a
    longer tail is what a build newer than this one looks like, and the one
    thing the negotiation exists to stop is treating that as misbehaviour."""
    if len(data) - offset != _KA_TAIL.size:
        return None
    try:
        return _KA_TAIL.unpack_from(data, offset)
    except struct.error:
        return None


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

    def __init__(self, budget: int, known: frozenset = frozenset()) -> None:
        self._budget = budget
        self._known = known
        # Keyed on the fingerprint rather than on the serialised bytes: it is
        # what the store already treats as a certificate's identity, it is
        # computed once per certificate, and it is what a reference names.
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
        added: list[tuple[bytes, bytes]] = []
        cost = len(blob) + _POOL_INDEX.size * len(entry.cert_chain)
        prints = [cert.fingerprint() for cert in entry.cert_chain]
        for cert, digest in zip(entry.cert_chain, prints):
            if digest in self._index or any(digest == d for d, _ in added):
                continue
            if len(self._pool) + len(added) >= _ENTRY_POOL_MAX:
                return False
            if digest in self._known:
                # The querier told us it holds this one. Ten bytes instead of
                # seven thousand, and no `serialize()` at all — which is the
                # other half of the saving: rebuilding a chain used to cost the
                # responder a ~7 kB blob per certificate per query.
                body = _CERT_LEN.pack(_CERT_REF) + digest
            else:
                raw = cert.serialize()
                body = _CERT_LEN.pack(len(raw)) + raw
            added.append((digest, body))
            cost += len(body)
        if self._used + cost > self._budget:
            return False
        for digest, body in added:
            self._index[digest] = len(self._pool)
            self._pool.append(body)
        for digest in prints:
            blob += _POOL_INDEX.pack(self._index[digest])
        self._entries.append(blob)
        self._used += cost
        return True

    def encode(self) -> bytes:
        return (_POOL_COUNT.pack(len(self._pool)) + b"".join(self._pool)
                + bytes([len(self._entries)]) + b"".join(self._entries))


def _encode_cert_hints(prints: list[bytes]) -> bytes:
    """The tail of a FIND_NODE: fingerprints of certificates we already hold."""
    return b"".join(prints[:_CERT_HINT_MAX])


def _decode_cert_hints(tail: bytes) -> frozenset | None:
    """Read that tail. ``None`` means the payload is not a FIND_NODE at all.

    An empty tail is the classic question and must stay valid for ever: a node
    that has never heard of fingerprints asks exactly that, and refusing it
    would cut every older build out of the lookup."""
    if not tail:
        return frozenset()
    if len(tail) % FINGERPRINT_LEN or len(tail) > _CERT_HINT_MAX * FINGERPRINT_LEN:
        return None
    return frozenset(tail[i:i + FINGERPRINT_LEN]
                     for i in range(0, len(tail), FINGERPRINT_LEN))


def _encode_entries(entries: list[NodeEntry], known: frozenset = frozenset()) -> bytes:
    packer = _EntryPacker(1 << 30, known)
    for entry in entries:
        packer.add(entry)
    return packer.encode()


def _decode_entries(data: bytes, resolve=None) -> tuple[list[NodeEntry], int]:
    """Parse a FOUND_NODE body. Returns the entries and how many bytes they took.

    ``resolve(fingerprint) -> Certificate | None`` looks up a certificate the
    sender referred to instead of sending. It can only ever find one this node
    already holds and verified, so a reference adds no authority: naming one we
    do not have voids that chain exactly as an unparseable certificate does.

    The consumed length is returned because what follows the entries is how the
    two ends discover each other (see ``_HINTS_OK``) — and because a build
    without that marker has always simply stopped reading here."""
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
        if cert_len == _CERT_REF:
            if offset + FINGERPRINT_LEN > len(data):
                raise ValueError("truncated cert reference")
            digest = data[offset:offset + FINGERPRINT_LEN]
            offset += FINGERPRINT_LEN
            pool.append(resolve(digest) if resolve is not None else None)
            continue
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
    return entries, offset


__all__ = [
    "_EntryPacker",
    "_KA_BOUNDS",
    "_KA_TAIL",
    "_KA_TOKEN",
    "_KA_WANTED",
    "_NO_ADDRESSES",
    "_build_punch_ack",
    "_build_punch_probe",
    "_decode_addresses",
    "_decode_addresses_at",
    "_decode_cert_hints",
    "_decode_chain",
    "_decode_conn_block",
    "_decode_e2e_handshake",
    "_decode_e2e_handshake_ack",
    "_decode_entries",
    "_decode_handshake",
    "_decode_handshake_ack",
    "_decode_ping_tail",
    "_decode_punch_relay",
    "_decode_punch_request",
    "_decode_seek",
    "_encode_addresses",
    "_encode_cert_hints",
    "_encode_chain",
    "_encode_conn_block",
    "_encode_e2e_handshake",
    "_encode_e2e_handshake_ack",
    "_encode_entries",
    "_encode_handshake",
    "_encode_handshake_ack",
    "_encode_ping_tail",
    "_encode_punch_relay",
    "_encode_punch_request",
    "_encode_seek",
    "_h_code",
    "_make_invite_seek",
    "_order_by_preference",
    "_parse_punch_ack",
    "_parse_punch_frame",
    "_parse_punch_probe",
    "_punch_minutes",
    "_punch_signed_blob",
    "_seek_signed_blob",
    "_split_handshake",
    "_uri_preference",
]
