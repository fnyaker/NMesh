"""
The package directory — what a node holds, findable by name, by node, by release.

A node's own code and a third-party app are the same problem twice: somebody
signed some bytes, and somebody else has to find them, judge them and install
them. This module is the *finding* half.

One statement, and only one
---------------------------
A node says exactly one thing here, about itself::

    "I hold release R, and I serve it."

    record = version ‖ kind ‖ flags ‖ ts ‖ node_pub ‖ name ‖ pkg_version
             ‖ notes ‖ release_key ‖ src ‖ node_sig
             [‖ signer_pub ‖ signer_sig]     when FLAG_PUBLISHED is set

Everything else follows from that sentence. **Recommending is holding**: a node
files a record only for a release whose bytes it actually has, so the set of
records under a release is the set of machines that can serve it. There is no
separate "who has this" mechanism, and no node to fall back on when nobody does.

The record is **self-authenticating**, so it is safe to accept from a stranger,
cache and re-serve:

  - the **node id is derived from the pubkey inside the record**, and the
    signature is checked under that same key — so a record can only ever say
    what its own author holds. Nobody can file a package against somebody
    else's identity, which is what makes a directory of strangers usable.
  - the **name is canonical** (:mod:`src.pseudo`, the same form a pseudo takes)
    and the keys it is filed under are **derived from it**, never declared.
  - the **timestamp only moves forward** per (node, kind, name), so a relay
    replaying an old record cannot walk anybody back to a stale version.

Publishing is holding, plus a proof
-----------------------------------
There is no separate kind of record for "I published this". A publication is a
node holding a release *and* being able to prove it holds the key that signed
the descriptor — ``FLAG_PUBLISHED``, carrying a second signature by that key::

    node   signs   DOMAIN ‖ ":hold:" ‖ node_id ‖ kind ‖ flags ‖ ts ‖ name
                   ‖ version ‖ notes ‖ release_key ‖ src
    signer signs   DOMAIN ‖ ":sign:" ‖ node_id ‖ signer_id ‖ release_key

The second statement names **the node**, which is what makes it non-transferable:
lifting somebody else's proof onto your own record produces a signature over a
node id that is not yours, and it fails. A record whose flag is set and whose
proof does not verify is **refused entirely** — a claim that comes with its own
broken evidence is not a weaker claim, it is a malformed one.

This is deliberately the only place a package and a node are joined. A release
is bytes and a signature; who *serves* it is a separate, local, revocable fact
that each node states about itself and nobody states about anybody else.

What a record is not
--------------------
It is **not authority to install anything**. It names a release, a version and a
content reference; what the bytes are is decided by hashes, and whether they may
replace this node's code is decided by the pinned signing keys the operator
holds. A record from an unpinned signer is carried, displayed and never acted
on. This is the charter's "hearsay is never authority", applied to the one
payload that replaces a program.

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

# Version 2 of this plane. Version 1 filed records under a *publisher key* and
# needed a second artefact (a two-halved pairing) to get from a node to the code
# it published. Both are gone: the record is signed by the node, so the link is
# in the thing itself. Old records are refused rather than translated — a format
# that means two things is worse than one nobody can read.
_DOMAIN = b"nmesh-package-dir-v2"
KEY_LEN = 20
ID_LEN = 20
RECORD_VERSION = 2

KIND_CORE = 1          # the node's own code (see src/core_release.py)
KIND_APP = 2           # a third-party application (see src/app_package.py)
KINDS = (KIND_CORE, KIND_APP)

# "…and the key that signed this release is one I hold." Proved, never asserted:
# see the second signature above.
FLAG_PUBLISHED = 0x01
_KNOWN_FLAGS = FLAG_PUBLISHED

MAX_NAME = MAX_PSEUDO              # one definition of what a displayed name is
MAX_VERSION = 64
MAX_NOTES = 600                    # the few lines shown before anything is fetched
RELEASE_KEY_LEN = 20               # a DHT content key: the signed descriptor
SRC_LEN = 32                       # a SHA-256

# record = version(B) ‖ kind(B) ‖ flags(B) ‖ ts(Q) ‖ node_len(H) ‖ name_len(H)
#          ‖ version_len(H) ‖ notes_len(H) ‖ node_sig_len(H) ‖ signer_len(H)
#          ‖ signer_sig_len(H)
_HDR = struct.Struct("!BBBQHHHHHHH")
_MAX_PUBKEY = 4096                 # ML-DSA-65 public key ~1952 B
_MAX_SIG = 5000                    # ML-DSA-65 signature ~3309 B
_MAX_NAME_BYTES = MAX_NAME * 4     # 50 characters, worst case in UTF-8
MAX_RECORD = (_HDR.size + 2 * _MAX_PUBKEY + _MAX_NAME_BYTES + MAX_VERSION
              + MAX_NOTES * 4 + RELEASE_KEY_LEN + SRC_LEN + 2 * _MAX_SIG)

_MAX_ENTRIES = 512                 # records this node remembers at all
_MAX_BOOK_BYTES = 8 * 1024 * 1024  # two keys and two signatures fit in a record
_MAX_PER_KEY = 8                   # pointers per directory key
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
# Keys: one derivation, three questions
# ---------------------------------------------------------------------------

def _key(prefix: bytes, material: bytes) -> bytes:
    h = hashlib.sha256()
    h.update(_DOMAIN)
    h.update(prefix)
    h.update(material)
    return h.digest()[:KEY_LEN]


def node_key(node_id: bytes) -> bytes:
    """The directory key holding what this node offers.

    Takes a **node id**, which is what the details page for a machine already
    has on screen. It used to be a publisher id — a key hash that names a
    machine only by coincidence, and names nothing at all once the key is
    detached or shared."""
    if not isinstance(node_id, (bytes, bytearray)):
        raise PackageDirError("node id must be bytes")
    return _key(b":node:", bytes(node_id))


def release_key(release: bytes) -> bytes:
    """The directory key holding **who can serve this release**.

    Derived from the release's own content key, so every node computes the same
    one from the thing itself. This is what makes a fetch work through routing
    with nobody to fall back on: ask the directory who holds it, then ask
    them."""
    if (not isinstance(release, (bytes, bytearray))
            or len(release) != RELEASE_KEY_LEN):
        raise PackageDirError("release key must be 20 bytes")
    return _key(b":rel:", bytes(release))


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


def identity_id(public_key: bytes) -> bytes:
    """The id of any ML-DSA identity: the hash of its key, like a ``NodeID``.

    One function for both ids a record carries — the node that signed it and the
    key that signed the release — because they are the same derivation, and two
    spellings of one quantity is two chances to disagree. What each *means* is
    carried by the field name (``node_id``, ``signer_id``), never by a second
    copy of this."""
    return hashlib.sha256(public_key).digest()[:ID_LEN]


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
    every byte against the content hash the chosen key signed."""
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

def _hold_input(node_id: bytes, kind: int, flags: int, ts: int, name: str,
                version: str, notes: str, release: bytes, src: bytes) -> bytes:
    """What the **node** signs: everything it is saying, bound to itself."""
    return (_DOMAIN + b":hold:" + node_id + bytes([kind, flags])
            + struct.pack("!Q", ts)
            + name.encode("utf-8") + b"\x00" + version.encode("utf-8") + b"\x00"
            + notes.encode("utf-8") + b"\x00" + release + src)


def _publisher_input(node_id: bytes, signer_id: bytes, release: bytes) -> bytes:
    """What the **release's signing key** signs to let one node claim it
    published: this node, this key, this release.

    Deliberately short, and deliberately naming the node. It says nothing about
    the version, the name or the notes — those are the node's own words, and a
    signing key that had to re-sign them would be re-signing a sentence it did
    not write. What it does say cannot be lifted: a proof carries the node id it
    was made for, so copying it onto another record verifies a different node
    id and fails."""
    return _DOMAIN + b":sign:" + node_id + signer_id + release


def build_record(kind: int, name: str, version: str, release: bytes,
                 src: bytes, node_pub: bytes, sign, *, notes: str = "",
                 ts: int | None = None, signer_pub: bytes | None = None,
                 signer_sign=None) -> bytes:
    """Sign a record saying this node holds and serves a release.

    ``release`` is the DHT content key of the signed descriptor — a core release
    descriptor or an app release descriptor. ``src`` is :func:`source_digest`
    over the package's code, or 32 zero bytes when the signer has not read it
    (holding somebody else's bytes may honestly say nothing about them).

    Pass ``signer_pub`` **and** ``signer_sign`` to add the proof that this node
    also holds the key which signed that descriptor; the record then carries
    ``FLAG_PUBLISHED``. Passing one without the other is refused rather than
    silently downgraded — half a proof is a mistake, not an intention.

    The name is checked here too: signing a form we would refuse on receipt only
    produces a record the whole network drops."""
    if kind not in KINDS:
        raise PackageDirError("unknown package kind")
    if not is_canonical(name):
        raise PackageDirError("package name is not in canonical form")
    if not isinstance(version, str) or not 0 < len(version) <= MAX_VERSION:
        raise PackageDirError("package version invalid")
    if (not isinstance(release, (bytes, bytearray))
            or len(release) != RELEASE_KEY_LEN):
        raise PackageDirError("release key invalid")
    if not isinstance(src, (bytes, bytearray)) or len(src) != SRC_LEN:
        raise PackageDirError("source digest invalid")
    if (signer_pub is None) != (signer_sign is None):
        raise PackageDirError("a publication proof needs both key and signer")
    notes = str(notes or "")[:MAX_NOTES]
    ts = int(ts if ts is not None else time.time())
    if ts < 0 or ts > 0xFFFFFFFFFFFFFFFF:
        raise PackageDirError("bad timestamp")
    flags = FLAG_PUBLISHED if signer_pub is not None else 0
    node_id = identity_id(node_pub)
    release, src = bytes(release), bytes(src)
    node_sig = sign(_hold_input(node_id, kind, flags, ts, name, version, notes,
                                release, src))
    if signer_pub is not None:
        signer_pub = bytes(signer_pub)
        signer_sig = signer_sign(_publisher_input(
            node_id, identity_id(signer_pub), release))
    else:
        signer_pub = signer_sig = b""
    encoded_name = name.encode("utf-8")
    encoded_version = version.encode("utf-8")
    encoded_notes = notes.encode("utf-8")
    if (len(node_pub) > _MAX_PUBKEY or len(node_sig) > _MAX_SIG
            or len(signer_pub) > _MAX_PUBKEY or len(signer_sig) > _MAX_SIG
            or len(encoded_name) > _MAX_NAME_BYTES
            or len(encoded_notes) > MAX_NOTES * 4):
        raise PackageDirError("record field too large")
    return (_HDR.pack(RECORD_VERSION, kind, flags, ts, len(node_pub),
                      len(encoded_name), len(encoded_version),
                      len(encoded_notes), len(node_sig), len(signer_pub),
                      len(signer_sig))
            + node_pub + encoded_name + encoded_version + encoded_notes
            + release + src + node_sig + signer_pub + signer_sig)


def parse_record(data: bytes, verify) -> dict | None:
    """Parse and cryptographically verify a record.

    Returns the record, or ``None`` for anything malformed, oversized,
    non-canonical, carrying a flag we do not know, or badly signed — including a
    ``FLAG_PUBLISHED`` whose proof does not check. Never raises on hostile
    input: this is the gate, and a gate that can throw is a gate that can be
    used to kill a receive loop."""
    if not isinstance(data, (bytes, bytearray)):
        return None
    if not (_HDR.size <= len(data) <= MAX_RECORD):
        return None
    data = bytes(data)
    (version, kind, flags, ts, node_len, name_len, ver_len, notes_len,
     nsig_len, signer_len, ssig_len) = _HDR.unpack_from(data, 0)
    if version != RECORD_VERSION or kind not in KINDS:
        return None
    if flags & ~_KNOWN_FLAGS:
        return None            # a flag we do not know is a meaning we cannot honour
    published = bool(flags & FLAG_PUBLISHED)
    # The proof and the flag are one statement: a proof nobody claimed is as
    # wrong as a claim with no proof, and letting either through would leave two
    # spellings of "published" for a reader to disagree about.
    if published == (signer_len == 0 or ssig_len == 0):
        return None
    if (node_len > _MAX_PUBKEY or nsig_len > _MAX_SIG
            or signer_len > _MAX_PUBKEY or ssig_len > _MAX_SIG
            or name_len > _MAX_NAME_BYTES or ver_len > MAX_VERSION
            or notes_len > MAX_NOTES * 4):
        return None
    off = _HDR.size
    expected = (off + node_len + name_len + ver_len + notes_len
                + RELEASE_KEY_LEN + SRC_LEN + nsig_len + signer_len + ssig_len)
    if len(data) != expected:
        return None
    node_pub = data[off:off + node_len]
    off += node_len
    name_bytes = data[off:off + name_len]
    off += name_len
    version_bytes = data[off:off + ver_len]
    off += ver_len
    notes_bytes = data[off:off + notes_len]
    off += notes_len
    release = data[off:off + RELEASE_KEY_LEN]
    off += RELEASE_KEY_LEN
    src = data[off:off + SRC_LEN]
    off += SRC_LEN
    node_sig = data[off:off + nsig_len]
    off += nsig_len
    signer_pub = data[off:off + signer_len]
    off += signer_len
    signer_sig = data[off:off + ssig_len]
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
        node_id = identity_id(node_pub)
        if not verify(_hold_input(node_id, kind, flags, ts, name, pkg_version,
                                  notes, release, src), node_sig, node_pub):
            return None
        signer_id = None
        if published:
            signer_id = identity_id(signer_pub)
            if not verify(_publisher_input(node_id, signer_id, release),
                          signer_sig, signer_pub):
                return None
    except Exception:
        return None
    return {
        "node_id": node_id,
        "node": node_pub,
        "kind": kind,
        "flags": flags,
        "published": published,
        "signer_id": signer_id,
        "signer": signer_pub if published else None,
        "name": name,
        "version": pkg_version,
        "notes": notes,
        "release": release,
        "src": src,
        "ts": ts,
        "keys": ([node_key(node_id), release_key(release)] + name_keys(name)),
    }


def entry_key(record: dict) -> bytes:
    """What one record supersedes: this node, this kind, this name.

    A node may hold several apps, and both a core release and an app — so the
    identity of an entry is the three together, never the node alone. One
    statement per package per node is also what "recommending is holding" means
    in practice: a node says which version of a thing it runs, not every version
    it has ever seen."""
    return hashlib.sha256(
        record["node_id"] + bytes([record["kind"]])
        + fold(record["name"]).encode("utf-8")).digest()[:KEY_LEN]


# Wire encoding of a record list in a PKG_FOUND reply: length-prefixed records,
# capped to a byte budget so the reply always fits one packet payload. The
# budget matters more than the count now that a record may carry two keys and
# two signatures.
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
    """Every record we have learned, one entry per node-kind-name.

    Indexed from a single set of entries: by node key (to answer "what does this
    machine offer?"), by release key (to answer "who can serve this?" — the
    swarm, which is what makes a fetch work through routing), and by name key —
    the whole name and each of its prefixes — to answer a search for a package
    nobody here has installed. Bounded in entries *and* in bytes, LRU on both."""

    def __init__(self, max_entries: int = _MAX_ENTRIES,
                 max_bytes: int = _MAX_BOOK_BYTES,
                 max_per_key: int = _MAX_PER_KEY) -> None:
        self._max_entries = max_entries
        self._max_bytes = max_bytes
        self._max_per_key = max_per_key
        self._entries: "OrderedDict[bytes, dict]" = OrderedDict()
        self._by_key: dict[bytes, list[bytes]] = {}
        self._bytes = 0
        # Nodes caught saying they hold two different releases of one package at
        # one instant. One proof per node, bounded like everything an outsider
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
                    and (record["release"] != current["release"]
                         or record["version"] != current["version"])):
                self._note_equivocation(record["node_id"], current["raw"], raw)
            if record["ts"] <= current["ts"]:
                return False
            self._unindex(ident, current)
        entry = {
            "id": ident,
            "node_id": record["node_id"],
            "node": record["node"],
            "kind": record["kind"],
            "published": record["published"],
            "signer_id": record["signer_id"],
            "signer": record["signer"],
            "name": record["name"],
            "folded": fold(record["name"]),
            "version": record["version"],
            "notes": record["notes"],
            "release": record["release"],
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

    def _note_equivocation(self, node_id: bytes, held: bytes,
                           incoming: bytes) -> None:
        if node_id in self._equivocations or len(self._equivocations) >= _MAX_EQUIVOCATIONS:
            return
        from . import equivocation
        try:
            self._equivocations[node_id] = equivocation.build(
                equivocation.KIND_RELEASE, held, incoming)
        except Exception:
            pass          # a proof we cannot frame is not a reason to fail the offer

    def equivocated(self, node_id) -> bytes | None:
        if not isinstance(node_id, (bytes, bytearray)):
            return None
        return self._equivocations.get(bytes(node_id))

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

    def of_node(self, node_id: bytes) -> list[dict]:
        """What one machine says it holds — the only join between a package and
        a node, and one the node makes about itself."""
        node_id = bytes(node_id)
        return [entry for entry in self._entries.values()
                if entry["node_id"] == node_id]

    def holders(self, release: bytes) -> list[dict]:
        """Every node that says it holds these bytes and will serve them.

        A recommendation *is* the offer to serve, so this is the swarm. It is a
        claim, not a fact: a node that lies costs the asker one round trip,
        because the hash decides what the bytes are."""
        release = bytes(release)
        return [entry for entry in self._entries.values()
                if entry["release"] == release]

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
