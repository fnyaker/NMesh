"""
Proving that one identity said two contradictory things.

Everything else a node hears about another node is an *opinion*, and
`reputation.py` is careful about that for a good reason: if hearsay alone could
get a node cut off, anybody able to speak could cut anybody off. So an
accusation counts as one voice, capped strictly below the threshold that cuts
anybody, and it has to be — the accuser could simply be lying.

This is the one report that is not like that. An equivocation proof is two
records **signed by the same key** that cannot both have been meant: the same
publisher signing two different programs under one version number, the same node
signing two different names as of the same instant. Forging one needs the
accused's private key, so the messenger contributes nothing but transport and
there is nothing to trust them about. It is the only shape of report a stranger
can hand over that a receiver can act on without the stranger's honesty entering
into it at all.

What is here is the **format** and the two places that build one. Passing a
proof to a neighbour is deliberately not part of it yet: a 20 kB record
re-broadcast on the say-so of one arrival is an amplifier, and that gossip wants
the same bounding, deduplication and rate limiting as every other flood on this
mesh. The format had to exist first, because it is what makes the report
checkable at all.

Two things this is **not**:

- It is not "two publishers disagree". `ReleaseCatalog.contradicts` answers that
  one, and it is right to treat it as a reason to stop rather than to blame:
  honest publishers fork by accident. Equivocation is one key contradicting
  *itself*, which no accident produces.
- It is not a new signing plane. Nothing here signs anything. It carries two
  records that were already signed, for their own reasons, on paths that already
  existed — so it costs no key material, no new domain, and nothing on any hot
  path.

Hostile input
-------------
`verify` never raises and never returns a half-checked answer. It re-parses both
records through their own parsers — the ones that already refuse everything
malformed — and then asks the only question this file owns: do these two
genuinely contradict, and are they genuinely from one key?
"""
from __future__ import annotations

import struct

from .node_id import NodeID

VERSION = 1

# What kind of record the pair is made of. A verifier that does not know a kind
# refuses the proof rather than guessing at it.
KIND_RELEASE = 1        # one publisher, one version, two different programs
KIND_PSEUDO = 2         # one node, one instant, two different names

KIND_NAMES = {
    KIND_RELEASE: "release",
    KIND_PSEUDO: "name claim",
}

# version(B) | kind(B) | len_a(H) | len_b(H)
_HDR = struct.Struct("!BBHH")
_MAX_RECORD = 64 * 1024
MAX_PROOF = _HDR.size + 2 * _MAX_RECORD


class EquivocationError(Exception):
    pass


def build(kind: int, first: bytes, second: bytes) -> bytes:
    """Wrap two already-signed records as one proof.

    Order is not meaningful and is not made so: which of the two arrived first
    says something about the network, never about the signer, and a proof that
    depended on it would be a proof somebody could argue with."""
    if kind not in KIND_NAMES:
        raise EquivocationError("unknown kind")
    for record in (first, second):
        if not isinstance(record, (bytes, bytearray)) or not record:
            raise EquivocationError("record invalid")
        if len(record) > _MAX_RECORD:
            raise EquivocationError("record too large")
    return (_HDR.pack(VERSION, kind, len(first), len(second))
            + bytes(first) + bytes(second))


def _split(data) -> tuple[int, bytes, bytes] | None:
    if not isinstance(data, (bytes, bytearray)):
        return None
    if not (_HDR.size <= len(data) <= MAX_PROOF):
        return None
    data = bytes(data)
    version, kind, len_a, len_b = _HDR.unpack_from(data, 0)
    if version != VERSION or kind not in KIND_NAMES:
        return None
    off = _HDR.size
    if len(data) != off + len_a + len_b or not len_a or not len_b:
        return None
    return kind, data[off:off + len_a], data[off + len_a:]


def _release_pair(first: bytes, second: bytes, verify) -> dict | None:
    """Same publisher, same version, different bytes."""
    from .core_release import parse_release
    one = parse_release(first, verify)
    two = parse_release(second, verify)
    if one["publisher"] != two["publisher"]:
        return None
    if one["version"] != two["version"]:
        return None
    if one["sha256"] == two["sha256"]:
        return None
    return {
        "subject_id": NodeID.from_public_key(one["publisher"]),
        "subject_pub": one["publisher"],
        "about": (f"signed two different programs as version "
                  f"{one['version']}"),
    }


def _pseudo_pair(first: bytes, second: bytes, verify) -> dict | None:
    """Same node, same instant, different names.

    The timestamp has to match: a node is entitled to change its name, and the
    book keeps the newest claim per node precisely so it can. Two names carrying
    the *same* instant is the case no honest sequence produces — it is one node
    telling two halves of the network different things and leaving whichever
    arrived first to decide."""
    from .pseudo_dir import parse_claim
    one = parse_claim(first, verify)
    two = parse_claim(second, verify)
    if one is None or two is None:
        return None
    if one["pubkey"] != two["pubkey"]:
        return None
    if one["ts"] != two["ts"]:
        return None
    if one["pseudo"] == two["pseudo"]:
        return None
    return {
        "subject_id": NodeID(one["node_id"]),
        "subject_pub": one["pubkey"],
        "about": "signed two different names for one instant",
    }


_PAIRS = {KIND_RELEASE: _release_pair, KIND_PSEUDO: _pseudo_pair}


def verify(data, verify_signature) -> dict | None:
    """Check a proof. Returns ``{kind, subject_id, subject_pub, about}`` or
    ``None``.

    ``verify_signature(message, signature, public_key) -> bool``. Both records
    go back through their own parser, so every check those already make is made
    again here — this file adds only the question they cannot ask on their own,
    which is whether two records contradict each other."""
    split = _split(data)
    if split is None:
        return None
    kind, first, second = split
    if first == second:
        return None          # one record twice is not two statements
    try:
        found = _PAIRS[kind](first, second, verify_signature)
    except Exception:
        return None          # a parser that throws is a parser, not a verdict
    if found is None:
        return None
    return {"kind": kind, "kind_name": KIND_NAMES[kind], **found}
