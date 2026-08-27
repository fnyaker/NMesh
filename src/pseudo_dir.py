"""
The pseudo directory — who is called what, network-wide.

A pseudo is chosen by whoever runs the node, so it cannot be trusted the way an
id can. What makes it usable anyway is that it never travels bare: it travels as
a **claim**, signed by the very identity it names.

    claim = version ‖ ts ‖ pubkey ‖ pseudo ‖ ML-DSA signature
    signed over  DOMAIN ‖ node_id ‖ ts ‖ pseudo

Three properties fall out of that shape, and together they are the whole
security argument:

  - the **node id is derived from the pubkey inside the claim**
    (:meth:`NodeID.from_public_key`), and the signature is checked under that
    same pubkey — so a claim can only ever bind a pseudo to the *claimant's own*
    id. Nobody can file "alice" against a victim's id, which is what makes it
    safe to accept claims from strangers and re-serve them.
  - the **pseudo must already be canonical** (:mod:`src.pseudo`). The sender
    does not get to send a name we then tidy up: a receiver re-derives the form
    and refuses anything else, because the difference between what was sent and
    what renders is precisely where impersonation lives.
  - the **timestamp only moves forward** for a given id, so an old claim
    replayed by a relay cannot roll somebody's name back to one they abandoned.

Pseudos are **not unique** and are **not identities**: several nodes may claim
"alice", and a lookup returns them all with their ids. The caller — a human
reading the console, or an app — picks; the id is what it then talks to.

:class:`PseudoBook` holds what we have learned. It is bounded twice over, in
entries and in bytes, because claims are large (an ML-DSA-65 pubkey and
signature are ~5.3 kB together) and arrive from anyone: without a byte budget a
flood of signed claims is a memory-exhaustion vector, which is the same bug as
an unbounded queue.
"""
from __future__ import annotations

import hashlib
import struct
import time
from collections import OrderedDict

from .node_id import NodeID
from .pseudo import MAX_PSEUDO, fold, is_canonical, rank_folded

_DOMAIN = b"nmesh-pseudo-v2"
KEY_LEN = 20
CLAIM_VERSION = 2

# claim = version(B) ‖ ts(Q) ‖ pubkey_len(H) ‖ pseudo_len(H) ‖ sig_len(H)
#         ‖ pubkey ‖ pseudo ‖ sig
_HDR = struct.Struct("!BQHHH")
_MAX_PSEUDO_BYTES = MAX_PSEUDO * 4   # 50 characters, worst case in UTF-8
_MAX_PUBKEY = 4096                   # ML-DSA-65 public key ~1952 B — generous ceiling
_MAX_SIG = 5000                      # ML-DSA-65 signature ~3309 B
MAX_CLAIM = _HDR.size + _MAX_PUBKEY + _MAX_PSEUDO_BYTES + _MAX_SIG

_MAX_NODES = 1024              # distinct nodes we remember a pseudo for
_MAX_BOOK_BYTES = 4 * 1024 * 1024
# Claims are large, so few per pseudo — a DIR_FOUND reply must fit one packet.
_MAX_PER_KEY = 8


class PseudoDirError(Exception):
    pass


def dir_key(pseudo: str) -> bytes:
    """The directory key a lookup can compute from the pseudo alone. Derived
    from the *folded* pseudo, so ``José`` and ``jose`` land on the same key."""
    h = hashlib.sha256()
    h.update(_DOMAIN)
    h.update(b":")
    h.update(fold(pseudo).encode("utf-8"))
    return h.digest()[:KEY_LEN]


def _signing_input(node_id: bytes, pseudo: str, ts: int) -> bytes:
    return _DOMAIN + node_id + struct.pack("!Q", ts) + pseudo.encode("utf-8")


def build_claim(pseudo: str, pubkey: bytes, sign, ts: int | None = None) -> bytes:
    """Sign a claim that ``pseudo`` names this node. ``sign(msg) -> signature``
    uses the node's ML-DSA identity, of which ``pubkey`` is the public half.

    The pseudo is checked here too: signing a name we would refuse on receipt
    would only produce a claim the whole network drops."""
    if not is_canonical(pseudo):
        raise PseudoDirError("pseudo is not in canonical form")
    ts = int(ts if ts is not None else time.time())
    if ts < 0 or ts > 0xFFFFFFFFFFFFFFFF:
        raise PseudoDirError("bad timestamp")
    node_id = NodeID.from_public_key(pubkey).raw
    encoded = pseudo.encode("utf-8")
    sig = sign(_signing_input(node_id, pseudo, ts))
    if len(pubkey) > _MAX_PUBKEY or len(sig) > _MAX_SIG:
        raise PseudoDirError("claim field too large")
    return (_HDR.pack(CLAIM_VERSION, ts, len(pubkey), len(encoded), len(sig))
            + pubkey + encoded + sig)


def parse_claim(data: bytes, verify) -> dict | None:
    """Parse and cryptographically verify a claim. ``verify(msg, sig, pubkey)``.

    Returns ``{node_id, pubkey, pseudo, ts, key}`` (``node_id`` and ``key`` as
    bytes), or ``None`` for anything malformed, oversized, non-canonical or
    badly signed. Never raises on hostile input: this is the gate, and a gate
    that can throw is a gate that can be used to kill a receive loop."""
    if not isinstance(data, (bytes, bytearray)) or not (_HDR.size <= len(data) <= MAX_CLAIM):
        return None
    data = bytes(data)
    version, ts, pk_len, ps_len, sig_len = _HDR.unpack_from(data, 0)
    if version != CLAIM_VERSION:
        return None
    if pk_len > _MAX_PUBKEY or ps_len > _MAX_PSEUDO_BYTES or sig_len > _MAX_SIG:
        return None
    off = _HDR.size
    if len(data) != off + pk_len + ps_len + sig_len:
        return None
    pubkey = data[off:off + pk_len]
    pseudo_bytes = data[off + pk_len:off + pk_len + ps_len]
    sig = data[off + pk_len + ps_len:]
    try:
        pseudo = pseudo_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return None
    # Before spending an ML-DSA verification on it: a name that is not in the
    # canonical form is refused outright, however well it is signed.
    if not is_canonical(pseudo):
        return None
    try:
        node_id = NodeID.from_public_key(pubkey).raw
        if not verify(_signing_input(node_id, pseudo, ts), sig, pubkey):
            return None
    except Exception:
        return None
    return {"node_id": node_id, "pubkey": pubkey, "pseudo": pseudo, "ts": ts,
            "key": dir_key(pseudo)}


# Wire encoding of a claim list in a DIR_FOUND reply: length-prefixed claims,
# capped to a byte budget so the reply always fits one packet payload.
_CLAIM_LEN = struct.Struct("!H")
_FOUND_BUDGET = 56 * 1024


def encode_claims(claims: list[bytes]) -> bytes:
    out = bytearray()
    for c in claims:
        if len(c) > MAX_CLAIM:
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
        if ln == 0 or ln > MAX_CLAIM or off + ln > n:
            break
        out.append(blob[off:off + ln])
        off += ln
    return out


class PseudoBook:
    """Every pseudo we have learned, one entry per node id.

    Indexed twice from a single set of entries: by node id (to answer "what is
    this node called?" and to keep the newest claim per node), and by directory
    key (to answer a ``DIR_FIND`` for an exact pseudo). Bounded in entries *and*
    in bytes, LRU on both."""

    def __init__(self, max_nodes: int = _MAX_NODES,
                 max_bytes: int = _MAX_BOOK_BYTES,
                 max_per_key: int = _MAX_PER_KEY) -> None:
        self._max_nodes = max_nodes
        self._max_bytes = max_bytes
        self._max_per_key = max_per_key
        # node_id -> {ts, pseudo, key, raw}
        self._by_node: "OrderedDict[bytes, dict]" = OrderedDict()
        self._by_key: dict[bytes, list[bytes]] = {}
        self._bytes = 0

    # -- mutation ---------------------------------------------------------

    def offer(self, claim: dict, raw: bytes) -> bool:
        """Take an already-verified claim (from :func:`parse_claim`). Returns
        True only when it **changed our view** — new node, or a strictly newer
        timestamp for one we knew. That answer is what makes gossip terminate,
        so it must stay exact."""
        node_id, ts = claim["node_id"], claim["ts"]
        raw = bytes(raw)
        if len(raw) > MAX_CLAIM:
            return False
        current = self._by_node.get(node_id)
        if current is not None:
            if ts <= current["ts"]:
                return False          # older or replayed — the name stands
            self._unindex(node_id, current)
        # `folded` is computed here, once, because `search` runs `rank` over
        # every entry and `rank` folds both sides — NFC, casefold, NFD, filter,
        # NFC — so a console field searching as somebody types was ~2 000
        # Unicode normalisations a keystroke.
        entry = {"ts": ts, "pseudo": claim["pseudo"], "key": claim["key"],
                 "raw": raw, "folded": fold(claim["pseudo"])}
        self._by_node[node_id] = entry
        self._by_node.move_to_end(node_id)
        self._bytes += len(raw)
        bucket = self._by_key.setdefault(claim["key"], [])
        bucket.append(node_id)
        # Pop first, then forget. `forget` shrinks the bucket only through
        # `_unindex`, which removes from `self._by_key[entry["key"]]` — the
        # *entry's* key, not this list. The two are the same today because
        # `offer` always unindexes before re-indexing, so the loop terminated;
        # but a `while` whose progress depends on an invariant maintained three
        # methods away, on the path that absorbs claims from strangers, is not
        # a loop to leave standing.
        while len(bucket) > self._max_per_key:
            self.forget(bucket.pop(0))
        self._enforce_bounds()
        # Whether it *survived* the bounds, not merely whether it was accepted:
        # a claim evicted on the way in is one we do not hold, and saying we
        # changed our view would have us re-gossip it every time it arrives —
        # an epidemic that never terminates, exactly under memory pressure.
        return node_id in self._by_node

    def forget(self, node_id: bytes) -> None:
        entry = self._by_node.pop(node_id, None)
        if entry is not None:
            self._unindex(node_id, entry)

    def _unindex(self, node_id: bytes, entry: dict) -> None:
        self._bytes -= len(entry["raw"])
        bucket = self._by_key.get(entry["key"])
        if bucket is not None:
            try:
                bucket.remove(node_id)
            except ValueError:
                pass
            if not bucket:
                del self._by_key[entry["key"]]

    def _enforce_bounds(self) -> None:
        while self._by_node and (len(self._by_node) > self._max_nodes
                                 or self._bytes > self._max_bytes):
            oldest, entry = next(iter(self._by_node.items()))
            self._by_node.pop(oldest)
            self._unindex(oldest, entry)

    # -- reading ----------------------------------------------------------

    def get(self, key: bytes) -> list[bytes]:
        """Raw claims filed under a directory key (for a ``DIR_FIND`` reply)."""
        out = []
        for node_id in self._by_key.get(key, []):
            entry = self._by_node.get(node_id)
            if entry is not None:
                out.append(entry["raw"])
        return out

    def pseudo_of(self, node_id: bytes):
        entry = self._by_node.get(bytes(node_id))
        return entry["pseudo"] if entry is not None else None

    def ts_of(self, node_id: bytes):
        entry = self._by_node.get(bytes(node_id))
        return entry["ts"] if entry is not None else None

    def recent(self, limit: int) -> list[bytes]:
        """The most recently learned claims, newest first — what a peer joining
        now is told before gossip fills in the rest."""
        claims = self.claims()
        claims.reverse()
        return claims[:max(0, int(limit))]

    def claim_of(self, node_id: bytes):
        entry = self._by_node.get(bytes(node_id))
        return entry["raw"] if entry is not None else None

    def claims(self) -> list[bytes]:
        """Every claim we hold, newest-touched last — what a freshly connected
        peer is caught up with."""
        return [entry["raw"] for entry in self._by_node.values()]

    def search(self, query: str, limit: int = 20) -> list[dict]:
        """Nodes whose pseudo matches ``query``, whole or partial, best first.

        Ranked by how the match was found (exact, then prefix, then a word
        inside the pseudo, then anywhere), and within a rank by the shortest
        pseudo — the closest thing to what was typed."""
        folded_query = fold(query)
        if not folded_query:
            return []
        hits = []
        for node_id, entry in self._by_node.items():
            score = rank_folded(folded_query, entry["folded"])
            if score is None:
                continue
            hits.append((score, len(entry["pseudo"]), entry["pseudo"],
                         {"id": node_id.hex(), "pseudo": entry["pseudo"],
                          "ts": entry["ts"], "match": score}))
        hits.sort(key=lambda h: h[:3])
        return [h[3] for h in hits[:max(0, int(limit))]]

    def __len__(self) -> int:
        return len(self._by_node)

    @property
    def nbytes(self) -> int:
        return self._bytes
