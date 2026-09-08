"""
The package directory — who publishes what, findable by name and by node.

A node's own code and a third-party app are the same problem twice: somebody
signed some bytes, and somebody else has to find them, judge them and install
them. This module is the *finding* half.

    record = version ‖ kind ‖ flags ‖ ts ‖ pubkey ‖ name ‖ pkg_version
             ‖ notes ‖ ref ‖ src ‖ ML-DSA signature
    signed over  DOMAIN ‖ publisher_id ‖ kind ‖ flags ‖ ts ‖ name
                 ‖ pkg_version ‖ notes ‖ ref ‖ src

It is deliberately the same shape as :mod:`src.pseudo_dir`, and for the same
reason: a record is **self-authenticating**, so it is safe to accept from a
stranger, cache, and re-serve.

  - the **publisher id is derived from the pubkey inside the record**, and the
    signature is checked under that same key — so a record can only ever say
    what its own author publishes. Nobody can file a package against somebody
    else's identity, which is what makes a directory of strangers usable.
  - the **name is canonical** (:mod:`src.pseudo`, the same form a pseudo takes)
    and the keys it is filed under are **derived from it**, never declared. A
    publisher cannot file itself under a name it did not sign.
  - the **timestamp only moves forward** per (publisher, kind, name), so a relay
    replaying an old record cannot walk anybody back to a stale version.

What a record is not
--------------------
It is **not authority to install anything**. It names a publisher, a version and
a content reference; what the bytes are is decided by hashes, and whether they
may replace this node's code is decided by the pins the operator holds. A record
from an unpinned publisher is carried, displayed and never acted on. This is the
charter's "hearsay is never authority", applied to the one payload that replaces
a program.

Two things a publisher can say
------------------------------
``KIND_CORE`` / ``KIND_APP`` say *what* is being published. ``FLAG_RECOMMEND``
says the signer is not the author: "I run this release id", pointing at somebody
else's bytes. That is worth exactly as much as the operator decides — it counts
towards corroboration when they subscribed to that node, and towards nothing
otherwise.

The source digest
-----------------
``src`` is a digest over the package's **code**, with documentation left out
(:func:`source_digest`). Two publishers who build the same source with different
release notes produce different packages and the same ``src``, so "do these
parties agree on the code?" can be answered *before* anything is downloaded.
It never replaces the content hash: what gets installed is still verified byte
for byte against the descriptor the operator chose.
"""
from __future__ import annotations

import hashlib
import json
import struct
import time
from collections import OrderedDict

from .pseudo import MAX_PSEUDO, canonical, fold, is_canonical, key_terms, rank_folded

_DOMAIN = b"nmesh-package-dir-v1"
KEY_LEN = 20
PUBLISHER_ID_LEN = 20
RECORD_VERSION = 1

KIND_CORE = 1          # the node's own code (see src/core_release.py)
KIND_APP = 2           # a third-party application (see src/app_package.py)
KINDS = (KIND_CORE, KIND_APP)

# The signer is not the author: it points at a release id somebody else signed
# and says "this is the one I run". Corroboration, never authority.
FLAG_RECOMMEND = 0x01
_KNOWN_FLAGS = FLAG_RECOMMEND

MAX_NAME = MAX_PSEUDO              # one definition of what a displayed name is
MAX_VERSION = 64
MAX_NOTES = 600                    # the few lines shown before anything is fetched
REF_LEN = 20                       # a DHT content key
SRC_LEN = 32                       # a SHA-256

# record = version(B) ‖ kind(B) ‖ flags(B) ‖ ts(Q) ‖ pubkey_len(H) ‖ name_len(H)
#          ‖ version_len(H) ‖ notes_len(H) ‖ sig_len(H)
_HDR = struct.Struct("!BBBQHHHHH")
_MAX_PUBKEY = 4096                 # ML-DSA-65 public key ~1952 B
_MAX_SIG = 5000                    # ML-DSA-65 signature ~3309 B
_MAX_NAME_BYTES = MAX_NAME * 4     # 50 characters, worst case in UTF-8
MAX_RECORD = (_HDR.size + _MAX_PUBKEY + _MAX_NAME_BYTES + MAX_VERSION
              + MAX_NOTES * 4 + REF_LEN + SRC_LEN + _MAX_SIG)

_MAX_ENTRIES = 512                 # packages this node remembers at all
_MAX_BOOK_BYTES = 4 * 1024 * 1024
_MAX_PER_KEY = 8                   # a PKG_FOUND reply must fit one packet
_MAX_EQUIVOCATIONS = 8

# Documentation a source digest deliberately ignores. Nothing here is executed
# by anything — which is the whole test for what may be excluded. A file that
# runs must change the digest, or "the parties agree on the code" would be a
# sentence about nothing.
_DOC_PREFIXES = ("docs/", "doc/", ".github/")
_DOC_NAMES = ("readme", "readme.md", "readme.txt", "readme.rst", "changelog",
              "changelog.md", "license", "licence", "license.md", "licence.md",
              "notice", "claude.md", "contributing.md", "code_of_conduct.md")


class PackageDirError(Exception):
    pass


# ---------------------------------------------------------------------------
# Keys: one derivation, two questions
# ---------------------------------------------------------------------------

def _key(prefix: bytes, material: bytes) -> bytes:
    h = hashlib.sha256()
    h.update(_DOMAIN)
    h.update(prefix)
    h.update(material)
    return h.digest()[:KEY_LEN]


def publisher_key(publisher_id: bytes) -> bytes:
    """The directory key holding what this publisher publishes.

    Takes the publisher id — which is derived exactly like a ``NodeID``, so for
    a node signing with its own identity it *is* its node id. That is what lets
    a node's details page ask "what does this machine publish?" with nothing but
    the id already on the screen."""
    if not isinstance(publisher_id, (bytes, bytearray)):
        raise PackageDirError("publisher id must be bytes")
    return _key(b":pub:", bytes(publisher_id))


def name_key(name) -> bytes:
    """The directory key a lookup computes from what was typed — the query
    side. Folded, so ``Chat`` and ``chat`` land together."""
    return _key(b":name:", fold(name).encode("utf-8"))


def name_keys(name) -> list[bytes]:
    """Every key a record is filed under by name — the publishing side.

    The whole folded name and each word's prefixes, so typing three letters
    finds a package on a node that has never heard of it. Derived from the name
    inside the signed record, never from anything the sender says."""
    return [_key(b":name:", term.encode("utf-8")) for term in key_terms(name)]


def publisher_id(public_key: bytes) -> bytes:
    """A publisher is named by the hash of its key, like a NodeID: there is no
    id to lie about, only a key that does or does not produce it."""
    return hashlib.sha256(public_key).digest()[:PUBLISHER_ID_LEN]


# ---------------------------------------------------------------------------
# The source digest — "do these two publish the same code?"
# ---------------------------------------------------------------------------

def is_documentation(path: str) -> bool:
    """Is this file documentation, and therefore outside the source digest?

    Narrow on purpose: only files nothing executes. Widening this is widening
    what two publishers may differ on while still counting as agreeing."""
    if not isinstance(path, str) or not path:
        return False
    lowered = path.replace("\\", "/").lstrip("./").lower()
    if lowered.startswith(_DOC_PREFIXES):
        return True
    return lowered.rsplit("/", 1)[-1] in _DOC_NAMES


def source_digest(files: dict) -> bytes:
    """A digest over a package's code, ignoring its documentation.

    Two publishers building the same tree with different release notes ship
    different bytes and the same digest, so an operator can ask whether several
    parties agree on the *code* without downloading anything from any of them.

    This is a comparison key, never a trust decision: an install still verifies
    every byte against the content hash the chosen publisher signed."""
    parts = {}
    for path, content in files.items():
        if not isinstance(path, str) or is_documentation(path):
            continue
        parts[path] = hashlib.sha256(bytes(content)).hexdigest()
    material = json.dumps(parts, sort_keys=True).encode("utf-8")
    return hashlib.sha256(_DOMAIN + b":src:" + material).digest()


# ---------------------------------------------------------------------------
# The record
# ---------------------------------------------------------------------------

def _signing_input(pub_id: bytes, kind: int, flags: int, ts: int, name: str,
                   version: str, notes: str, ref: bytes, src: bytes) -> bytes:
    return (_DOMAIN + pub_id + bytes([kind, flags]) + struct.pack("!Q", ts)
            + name.encode("utf-8") + b"\x00" + version.encode("utf-8") + b"\x00"
            + notes.encode("utf-8") + b"\x00" + ref + src)


def build_record(kind: int, name: str, version: str, ref: bytes, src: bytes,
                 pubkey: bytes, sign, *, notes: str = "", ts: int | None = None,
                 recommend: bool = False) -> bytes:
    """Sign a record saying what this key publishes.

    ``ref`` is the DHT content key of the signed descriptor the record points
    at — a core release descriptor or an app release descriptor. ``src`` is
    :func:`source_digest` over the package's code, or 32 zero bytes when the
    signer has not read the package (a recommendation of somebody else's bytes
    may honestly have nothing to say about them).

    The name is checked here too: signing a form we would refuse on receipt only
    produces a record the whole network drops."""
    if kind not in KINDS:
        raise PackageDirError("unknown package kind")
    if not is_canonical(name):
        raise PackageDirError("package name is not in canonical form")
    if not isinstance(version, str) or not 0 < len(version) <= MAX_VERSION:
        raise PackageDirError("package version invalid")
    if not isinstance(ref, (bytes, bytearray)) or len(ref) != REF_LEN:
        raise PackageDirError("package reference invalid")
    if not isinstance(src, (bytes, bytearray)) or len(src) != SRC_LEN:
        raise PackageDirError("source digest invalid")
    notes = str(notes or "")[:MAX_NOTES]
    ts = int(ts if ts is not None else time.time())
    if ts < 0 or ts > 0xFFFFFFFFFFFFFFFF:
        raise PackageDirError("bad timestamp")
    flags = FLAG_RECOMMEND if recommend else 0
    pub_id = publisher_id(pubkey)
    ref, src = bytes(ref), bytes(src)
    sig = sign(_signing_input(pub_id, kind, flags, ts, name, version, notes,
                              ref, src))
    encoded_name = name.encode("utf-8")
    encoded_version = version.encode("utf-8")
    encoded_notes = notes.encode("utf-8")
    if (len(pubkey) > _MAX_PUBKEY or len(sig) > _MAX_SIG
            or len(encoded_name) > _MAX_NAME_BYTES
            or len(encoded_notes) > MAX_NOTES * 4):
        raise PackageDirError("record field too large")
    return (_HDR.pack(RECORD_VERSION, kind, flags, ts, len(pubkey),
                      len(encoded_name), len(encoded_version),
                      len(encoded_notes), len(sig))
            + pubkey + encoded_name + encoded_version + encoded_notes
            + ref + src + sig)


def parse_record(data: bytes, verify) -> dict | None:
    """Parse and cryptographically verify a record.

    Returns the record, or ``None`` for anything malformed, oversized,
    non-canonical, carrying a flag we do not know, or badly signed. Never raises
    on hostile input: this is the gate, and a gate that can throw is a gate that
    can be used to kill a receive loop."""
    if not isinstance(data, (bytes, bytearray)):
        return None
    if not (_HDR.size <= len(data) <= MAX_RECORD):
        return None
    data = bytes(data)
    (version, kind, flags, ts, pk_len, name_len, ver_len, notes_len,
     sig_len) = _HDR.unpack_from(data, 0)
    if version != RECORD_VERSION or kind not in KINDS:
        return None
    if flags & ~_KNOWN_FLAGS:
        return None            # a flag we do not know is a meaning we cannot honour
    if (pk_len > _MAX_PUBKEY or sig_len > _MAX_SIG
            or name_len > _MAX_NAME_BYTES or ver_len > MAX_VERSION
            or notes_len > MAX_NOTES * 4):
        return None
    off = _HDR.size
    expected = off + pk_len + name_len + ver_len + notes_len + REF_LEN + SRC_LEN + sig_len
    if len(data) != expected:
        return None
    pubkey = data[off:off + pk_len]
    off += pk_len
    name_bytes = data[off:off + name_len]
    off += name_len
    version_bytes = data[off:off + ver_len]
    off += ver_len
    notes_bytes = data[off:off + notes_len]
    off += notes_len
    ref = data[off:off + REF_LEN]
    off += REF_LEN
    src = data[off:off + SRC_LEN]
    off += SRC_LEN
    sig = data[off:]
    try:
        name = name_bytes.decode("utf-8")
        pkg_version = version_bytes.decode("utf-8")
        notes = notes_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return None
    # Before spending an ML-DSA verification on it: a name in any form other
    # than the canonical one is refused outright, however well it is signed.
    if not is_canonical(name) or not pkg_version:
        return None
    if len(notes) > MAX_NOTES:
        return None
    try:
        pub_id = publisher_id(pubkey)
        if not verify(_signing_input(pub_id, kind, flags, ts, name, pkg_version,
                                     notes, ref, src), sig, pubkey):
            return None
    except Exception:
        return None
    return {
        "publisher_id": pub_id,
        "publisher": pubkey,
        "kind": kind,
        "flags": flags,
        "recommend": bool(flags & FLAG_RECOMMEND),
        "name": name,
        "version": pkg_version,
        "notes": notes,
        "ref": ref,
        "src": src,
        "ts": ts,
        "keys": [publisher_key(pub_id)] + name_keys(name),
    }


def entry_key(record: dict) -> bytes:
    """What one record supersedes: this publisher, this kind, this name.

    One publisher may offer several apps, and both a core release and an app —
    so the identity of an entry is the three together, never the publisher
    alone."""
    return hashlib.sha256(
        record["publisher_id"] + bytes([record["kind"]])
        + fold(record["name"]).encode("utf-8")).digest()[:KEY_LEN]


# Wire encoding of a record list in a PKG_FOUND reply: length-prefixed records,
# capped to a byte budget so the reply always fits one packet payload.
_REC_LEN = struct.Struct("!H")
_FOUND_BUDGET = 56 * 1024


def encode_records(records: list[bytes]) -> bytes:
    out = bytearray()
    for record in records:
        if len(record) > MAX_RECORD:
            continue
        if len(out) + _REC_LEN.size + len(record) > _FOUND_BUDGET:
            break
        out += _REC_LEN.pack(len(record)) + record
    return bytes(out)


def decode_records(blob: bytes) -> list[bytes]:
    out: list[bytes] = []
    off = 0
    total = len(blob)
    while off + _REC_LEN.size <= total and len(out) < _MAX_PER_KEY:
        (length,) = _REC_LEN.unpack_from(blob, off)
        off += _REC_LEN.size
        if length == 0 or length > MAX_RECORD or off + length > total:
            break
        out.append(blob[off:off + length])
        off += length
    return out


class PackageBook:
    """Every package record we have learned, one entry per publisher-kind-name.

    Indexed from a single set of entries: by publisher key (to answer "what does
    this node publish?"), and by name key — the whole name and each of its
    prefixes — to answer a search for a package nobody here has installed.
    Bounded in entries *and* in bytes, LRU on both."""

    def __init__(self, max_entries: int = _MAX_ENTRIES,
                 max_bytes: int = _MAX_BOOK_BYTES,
                 max_per_key: int = _MAX_PER_KEY) -> None:
        self._max_entries = max_entries
        self._max_bytes = max_bytes
        self._max_per_key = max_per_key
        self._entries: "OrderedDict[bytes, dict]" = OrderedDict()
        self._by_key: dict[bytes, list[bytes]] = {}
        self._bytes = 0
        # Publishers caught signing two different packages as one version at one
        # instant. One proof per publisher, bounded like everything an outsider
        # can grow.
        self._equivocations: dict[bytes, bytes] = {}

    # -- mutation ---------------------------------------------------------

    def offer(self, record: dict, raw: bytes) -> bool:
        """Take an already-verified record (from :func:`parse_record`).

        Returns True only when it **changed our view** — new, or a strictly
        newer timestamp for one we knew. That answer is what makes gossip
        terminate, so it must stay exact."""
        raw = bytes(raw)
        if len(raw) > MAX_RECORD:
            return False
        ident = entry_key(record)
        current = self._entries.get(ident)
        if current is not None:
            # Before the rollback check, deliberately: an attacker replaying the
            # older half second is exactly how a contradiction slips past a
            # check that ran after. Same shape as the pseudo book.
            if (record["ts"] == current["ts"]
                    and (record["ref"] != current["ref"]
                         or record["version"] != current["version"])):
                self._note_equivocation(record["publisher_id"], current["raw"], raw)
            if record["ts"] <= current["ts"]:
                return False
            self._unindex(ident, current)
        entry = {
            "id": ident,
            "publisher_id": record["publisher_id"],
            "publisher": record["publisher"],
            "kind": record["kind"],
            "recommend": record["recommend"],
            "name": record["name"],
            "folded": fold(record["name"]),
            "version": record["version"],
            "notes": record["notes"],
            "ref": record["ref"],
            "src": record["src"],
            "ts": record["ts"],
            "raw": raw,
            "keys": list(record["keys"]),
        }
        self._entries[ident] = entry
        self._entries.move_to_end(ident)
        self._bytes += len(raw)
        for key in entry["keys"]:
            bucket = self._by_key.setdefault(key, [])
            bucket.append(ident)
            # The pointer goes, never the record: a hot prefix bucket must not
            # be able to evict a package that is still the only answer to its
            # own exact name. Memory is bounded by `_enforce_bounds`.
            del bucket[:-self._max_per_key]
        self._enforce_bounds()
        # Whether it *survived* the bounds: a record evicted on the way in is
        # one we do not hold, and saying we changed our view would re-gossip it
        # every time it arrives — an epidemic that never terminates, exactly
        # under memory pressure.
        return ident in self._entries

    def _note_equivocation(self, pub_id: bytes, held: bytes,
                           incoming: bytes) -> None:
        if pub_id in self._equivocations or len(self._equivocations) >= _MAX_EQUIVOCATIONS:
            return
        from . import equivocation
        try:
            self._equivocations[pub_id] = equivocation.build(
                equivocation.KIND_RELEASE, held, incoming)
        except Exception:
            pass          # a proof we cannot frame is not a reason to fail the offer

    def equivocated(self, pub_id) -> bytes | None:
        if not isinstance(pub_id, (bytes, bytearray)):
            return None
        return self._equivocations.get(bytes(pub_id))

    def forget(self, ident: bytes) -> None:
        entry = self._entries.pop(ident, None)
        if entry is not None:
            self._unindex(ident, entry)

    def _unindex(self, ident: bytes, entry: dict) -> None:
        self._bytes -= len(entry["raw"])
        for key in entry["keys"]:
            bucket = self._by_key.get(key)
            if bucket is None:
                continue
            try:
                bucket.remove(ident)
            except ValueError:
                pass          # a full bucket drops its oldest pointer, not the record
            if not bucket:
                del self._by_key[key]

    def _enforce_bounds(self) -> None:
        while self._entries and (len(self._entries) > self._max_entries
                                 or self._bytes > self._max_bytes):
            oldest, entry = next(iter(self._entries.items()))
            self._entries.pop(oldest)
            self._unindex(oldest, entry)

    # -- reading ----------------------------------------------------------

    def get(self, key: bytes) -> list[bytes]:
        """Raw records filed under a directory key (for a ``PKG_FIND`` reply)."""
        out = []
        for ident in self._by_key.get(key, []):
            entry = self._entries.get(ident)
            if entry is not None:
                out.append(entry["raw"])
        return out

    def entry(self, ident: bytes) -> dict | None:
        return self._entries.get(bytes(ident))

    def by_source(self, src: bytes) -> list[dict]:
        """Every entry whose package carries the same code, whatever its
        documentation or who built it. This is what corroboration counts."""
        src = bytes(src)
        if src == b"\x00" * SRC_LEN:
            return []        # "I did not read the package" is not agreement
        return [entry for entry in self._entries.values() if entry["src"] == src]

    def of_publisher(self, pub_id: bytes) -> list[dict]:
        pub_id = bytes(pub_id)
        return [entry for entry in self._entries.values()
                if entry["publisher_id"] == pub_id]

    def records(self) -> list[bytes]:
        """Every record we hold, oldest-touched first — what a freshly connected
        peer is caught up with."""
        return [entry["raw"] for entry in self._entries.values()]

    def recent(self, limit: int) -> list[bytes]:
        records = self.records()
        records.reverse()
        return records[:max(0, int(limit))]

    def search(self, query: str, limit: int = 20) -> list[dict]:
        """Packages whose name matches ``query``, whole or partial, best first.

        Ranked exactly like a pseudo search — exact, then prefix, then a word
        inside the name — because it is the same question about a different
        thing, and two rankings would disagree the moment one changed."""
        folded_query = fold(query)
        if not folded_query:
            return []
        hits = []
        for entry in self._entries.values():
            score = rank_folded(folded_query, entry["folded"])
            if score is None:
                continue
            hits.append((score, len(entry["name"]), entry["name"], entry))
        hits.sort(key=lambda hit: hit[:3])
        return [hit[3] for hit in hits[:max(0, int(limit))]]

    def __len__(self) -> int:
        return len(self._entries)

    @property
    def nbytes(self) -> int:
        return self._bytes


def canonical_name(name) -> str:
    """The one accepted form of a package name — the same rule a pseudo takes,
    because it is displayed in the same places and impersonation lives in the
    same difference between what was sent and what renders."""
    return canonical(name)

