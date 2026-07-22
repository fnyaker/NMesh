"""
Pseudo directory — find people by pseudo across the whole network.

The mesh DHT is content-addressed (key = hash of value), which is perfect for
immutable blobs but cannot answer "who is <pseudo>?": that needs a key derived
from the *pseudo*, not from the value. This module adds a **keyed directory**
that maps a pseudo to the node ids that claim it, without weakening anything.

The trick is that a directory record is **self-authenticating**, so storing it
under an attacker-chosen key buys the attacker nothing:

    key   = sha256(DOMAIN : app_id : normalise(pseudo))[:20]
    claim = app_id ‖ ts ‖ pubkey ‖ pseudo ‖ ML-DSA signature

  - the claimed **node id is derived from the pubkey** in the claim
    (``NodeID.from_public_key``), and the signature is verified under that
    pubkey. So a claim can only ever bind a pseudo to the *claimant's own* node
    id — it can never map "alice" onto a victim's id (the classic poisoning /
    impersonation vector is closed, exactly as for the content-addressed store).
  - the receiver recomputes the key from the claim's own ``app_id`` + pseudo, so
    a claim cannot be filed under an unrelated key.

Pseudos are not unique: several people may claim "alice". The directory keeps a
**bounded set of claims per key** (newest ``ts`` per node id wins), and a lookup
returns them all — the caller decides. The node id, not the pseudo, stays the
real identity. Everything is bounded (per key, and total keys) so a flood of
signed claims cannot exhaust memory.
"""
from __future__ import annotations

import hashlib
import struct
import time
from collections import OrderedDict

from .node_id import NodeID
from .app_channel import APP_ID_LEN

_DOMAIN = b"nmesh-pseudo-dir-v1"
KEY_LEN = 20
# claim = app_id(8) ‖ ts(Q) ‖ pubkey_len(H) ‖ pseudo_len(H) ‖ sig_len(H)
#         ‖ pubkey ‖ pseudo ‖ sig
_HDR = struct.Struct("!QHHH")
_MAX_PSEUDO = 256
_MAX_PUBKEY = 4096          # ML-DSA-65 public key ~1952 B — generous ceiling
_MAX_SIG = 5000             # ML-DSA-65 signature ~3309 B
_MAX_CLAIM = APP_ID_LEN + _HDR.size + _MAX_PUBKEY + _MAX_PSEUDO + _MAX_SIG

_MAX_KEYS = 4096            # distinct pseudo keys held
# Claims are large (ML-DSA pubkey ~1952 B + signature ~3309 B ≈ 5.3 KB each), so
# keep few per pseudo — a DIR_FOUND reply must fit one packet payload.
_MAX_PER_KEY = 8


class PseudoDirError(Exception):
    pass


def _normalise(pseudo: str) -> bytes:
    return pseudo.strip().casefold().encode("utf-8")[:_MAX_PSEUDO]


def dir_key(app_id: bytes, pseudo: str) -> bytes:
    """Deterministic DHT key a lookup can compute from the pseudo alone."""
    h = hashlib.sha256()
    h.update(_DOMAIN)
    h.update(b":")
    h.update(app_id)
    h.update(b":")
    h.update(_normalise(pseudo))
    return h.digest()[:KEY_LEN]


def _signing_input(app_id: bytes, node_id: bytes, pseudo: str, ts: int) -> bytes:
    return (_DOMAIN + app_id + node_id
            + struct.pack("!Q", ts)
            + pseudo.encode("utf-8")[:_MAX_PSEUDO])


def build_claim(app_id: bytes, pseudo: str, pubkey: bytes, sign,
                ts: int | None = None) -> bytes:
    """Build a signed pseudo claim for this node. ``sign(msg) -> signature`` uses
    the node's ML-DSA identity; ``pubkey`` is that identity's public key."""
    if len(app_id) != APP_ID_LEN:
        raise PseudoDirError("bad app id")
    ts = int(ts if ts is not None else time.time())
    node_id = NodeID.from_public_key(pubkey).raw
    p = pseudo.encode("utf-8")[:_MAX_PSEUDO]
    sig = sign(_signing_input(app_id, node_id, pseudo, ts))
    if len(pubkey) > _MAX_PUBKEY or len(sig) > _MAX_SIG:
        raise PseudoDirError("claim field too large")
    return app_id + _HDR.pack(ts, len(pubkey), len(p), len(sig)) + pubkey + p + sig


def parse_claim(data: bytes, verify) -> dict | None:
    """Parse and cryptographically verify a claim. ``verify(msg, sig, pubkey)``.
    Returns ``{app_id, node_id, pubkey, pseudo, ts, key}`` (node_id/key as bytes),
    or ``None`` on anything malformed, oversized, or with a bad signature — never
    raises on hostile input (reject by default)."""
    if not isinstance(data, (bytes, bytearray)) or len(data) > _MAX_CLAIM:
        return None
    if len(data) < APP_ID_LEN + _HDR.size:
        return None
    data = bytes(data)
    app_id = data[:APP_ID_LEN]
    ts, pk_len, ps_len, sig_len = _HDR.unpack_from(data, APP_ID_LEN)
    if pk_len > _MAX_PUBKEY or ps_len > _MAX_PSEUDO or sig_len > _MAX_SIG:
        return None
    off = APP_ID_LEN + _HDR.size
    if len(data) != off + pk_len + ps_len + sig_len:
        return None
    pubkey = data[off:off + pk_len]
    pseudo_b = data[off + pk_len:off + pk_len + ps_len]
    sig = data[off + pk_len + ps_len:]
    try:
        pseudo = pseudo_b.decode("utf-8")
    except UnicodeDecodeError:
        return None
    node_id = NodeID.from_public_key(pubkey).raw
    try:
        if not verify(_signing_input(app_id, node_id, pseudo, ts), sig, pubkey):
            return None
    except Exception:
        return None
    return {"app_id": app_id, "node_id": node_id, "pubkey": pubkey,
            "pseudo": pseudo, "ts": ts, "key": dir_key(app_id, pseudo)}


# Wire encoding of a claim list in a DIR_FOUND reply: length-prefixed claims,
# capped to a byte budget so the reply always fits one packet payload.
_CLAIM_LEN = struct.Struct("!H")
_FOUND_BUDGET = 56 * 1024


def encode_claims(claims: list[bytes]) -> bytes:
    out = bytearray()
    for c in claims:
        if len(c) > _MAX_CLAIM:
            continue
        if len(out) + _CLAIM_LEN.size + len(c) > _FOUND_BUDGET:
            break
        out += _CLAIM_LEN.pack(len(c)) + c
    return bytes(out)


def decode_claims(blob: bytes) -> list[bytes]:
    out: list[bytes] = []
    off = 0
    n = len(blob)
    while off + _CLAIM_LEN.size <= n and len(out) < _MAX_PER_KEY:
        (ln,) = _CLAIM_LEN.unpack_from(blob, off)
        off += _CLAIM_LEN.size
        if ln == 0 or ln > _MAX_CLAIM or off + ln > n:
            break
        out.append(blob[off:off + ln])
        off += ln
    return out


class PseudoStore:
    """Bounded set of verified claims, keyed by pseudo key; per key, the newest
    claim per node id is kept. LRU eviction on both dimensions."""

    def __init__(self, max_keys: int = _MAX_KEYS, max_per_key: int = _MAX_PER_KEY) -> None:
        self._max_keys = max_keys
        self._max_per_key = max_per_key
        # key -> OrderedDict[node_id -> (ts, claim_bytes)]
        self._d: "OrderedDict[bytes, OrderedDict[bytes, tuple[int, bytes]]]" = OrderedDict()

    def put(self, claim: dict, raw: bytes) -> bool:
        """Insert an already-verified claim (from :func:`parse_claim`). Returns
        True if it changed the store (new or newer than what we held)."""
        key, node_id, ts = claim["key"], claim["node_id"], claim["ts"]
        bucket = self._d.get(key)
        if bucket is None:
            if len(self._d) >= self._max_keys:
                self._d.popitem(last=False)   # evict least-recently-used key
            bucket = self._d[key] = OrderedDict()
        existing = bucket.get(node_id)
        if existing is not None and ts <= existing[0]:
            return False                      # older or same — ignore
        bucket[node_id] = (ts, raw)
        bucket.move_to_end(node_id)
        self._d.move_to_end(key)
        while len(bucket) > self._max_per_key:
            bucket.popitem(last=False)
        return True

    def get(self, key: bytes) -> list[bytes]:
        bucket = self._d.get(key)
        if not bucket:
            return []
        self._d.move_to_end(key)
        return [raw for _, raw in bucket.values()]

    def __len__(self) -> int:
        return len(self._d)
