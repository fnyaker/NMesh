"""
Telling the network that a node is misbehaving.

A revocation is an issuer withdrawing something it granted; it is authoritative
because only one node could have said it. An accusation is nothing of the kind.
It is one node's opinion, and the whole difficulty is that opinions are cheap:
anybody on the mesh can form one, about anybody, at no cost.

So the record is deliberately weak by design. It carries no authority at all and
is not meant to. It says "I, this identity, saw this node do this", and what
happens next is entirely the receiver's business — see `reputation.py`, where an
accusation from an ordinary member counts as *one accuser*, is capped strictly
below the threshold that cuts anybody off, and is ignored outright if we already
hold the accuser itself as suspect.

That asymmetry is the point. If hearsay could get a node cut off, then anybody
able to speak could cut anybody off, and this file would be a censorship
primitive with a reputation label on it. What it is instead is a way for a node
that has not yet been attacked to be wary of one that is attacking its
neighbours.

The signature does one job: it binds the opinion to an identity, so that "how
many distinct members say this" is a question with an answer. Without it a
single node would be an unbounded crowd.

Hostile input
-------------
`parse` never raises and never returns a half-checked record. It is a gate, and
a gate that can throw is a gate that can be used to kill a receive loop.
"""
from __future__ import annotations

import struct
import time

from .node_id import NodeID

_DOMAIN = b"nmesh-accusation-v1"
VERSION = 1

# version(B) ‖ issued_at(Q) ‖ subject_id(20) ‖ severity(B) ‖ kind(B)
# ‖ pub_len(H) ‖ sig_len(H)
_HDR = struct.Struct("!BQ20sBBHH")
_MAX_PUBKEY = 4096
_MAX_SIG = 5000
MAX_RECORD = _HDR.size + _MAX_PUBKEY + _MAX_SIG

# How stale an accusation may be and still be worth absorbing. Old ones are not
# evidence, they are a replay: the whole value of a report is that it is about
# what is happening now, and `reputation` decays it away in an hour or so
# anyway. Also bounds how far ahead of us a clock may claim to be.
MAX_AGE = 3600
MAX_SKEW = 300

MAX_SEVERITY = 8

# What was seen. Advisory — shown to an operator, decides nothing. A receiver
# acts on the accusation, never on the label attached to it.
KIND_UNSPECIFIED = 0
KIND_FLOOD = 1              # more traffic than the app's threshold allows
KIND_MALFORMED = 2          # input that does not parse, repeatedly
KIND_UNAUTHORISED = 3       # asking for what it has no right to, repeatedly
KIND_NAMES = {
    KIND_UNSPECIFIED: "unspecified",
    KIND_FLOOD: "flooding",
    KIND_MALFORMED: "malformed input",
    KIND_UNAUTHORISED: "unauthorised requests",
}


def _signing_input(issued_at: int, subject_id: bytes, severity: int,
                   kind: int) -> bytes:
    return (_DOMAIN + struct.pack("!BQ", VERSION, issued_at)
            + subject_id + bytes([severity, kind]))


def build(subject_id: NodeID, accuser_pub: bytes, sign, *,
          severity: int = 1, kind: int = KIND_UNSPECIFIED,
          issued_at: int | None = None) -> bytes:
    """Sign an accusation against ``subject_id``.

    ``sign(message) -> signature`` signs with the accuser's ML-DSA identity, of
    which ``accuser_pub`` is the public half."""
    stamp = int(time.time() if issued_at is None else issued_at)
    if not 0 <= stamp <= 0xFFFFFFFFFFFFFFFF:
        raise ValueError("bad timestamp")
    severity = max(1, min(int(severity), MAX_SEVERITY))
    if kind not in KIND_NAMES:
        kind = KIND_UNSPECIFIED
    signature = sign(_signing_input(stamp, subject_id.raw, severity, kind))
    if len(accuser_pub) > _MAX_PUBKEY or len(signature) > _MAX_SIG:
        raise ValueError("accusation field too large")
    return (_HDR.pack(VERSION, stamp, subject_id.raw, severity, kind,
                      len(accuser_pub), len(signature))
            + accuser_pub + signature)


def parse(data, verify, *, now: float | None = None) -> dict | None:
    """Parse and cryptographically verify an accusation.

    Returns ``{accuser_id, accuser_pub, subject_id, issued_at, severity,
    kind}`` — ids as :class:`NodeID` — or ``None`` for anything that does not
    check out, is stale, or claims to come from the future."""
    if not isinstance(data, (bytes, bytearray)):
        return None
    if not (_HDR.size <= len(data) <= MAX_RECORD):
        return None
    data = bytes(data)
    (version, issued_at, subject_raw, severity, kind,
     pub_len, sig_len) = _HDR.unpack_from(data, 0)
    if version != VERSION:
        return None
    if not 1 <= severity <= MAX_SEVERITY:
        return None
    if pub_len > _MAX_PUBKEY or sig_len > _MAX_SIG or not pub_len or not sig_len:
        return None
    offset = _HDR.size
    if len(data) != offset + pub_len + sig_len:
        return None
    stamp = int(time.time() if now is None else now)
    if issued_at > stamp + MAX_SKEW or stamp - issued_at > MAX_AGE:
        return None          # not evidence any more, or not evidence yet
    accuser_pub = data[offset:offset + pub_len]
    signature = data[offset + pub_len:]
    try:
        if not verify(_signing_input(issued_at, subject_raw, severity, kind),
                      signature, accuser_pub):
            return None
    except Exception:
        return None      # a broken key blob must not raise into a receive loop
    accuser_id = NodeID.from_public_key(accuser_pub)
    subject_id = NodeID(subject_raw)
    if accuser_id == subject_id:
        return None      # an identity accusing itself is noise, not a report
    return {
        "accuser_id": accuser_id,
        "accuser_pub": accuser_pub,
        "subject_id": subject_id,
        "issued_at": int(issued_at),
        "severity": int(severity),
        "kind": int(kind),
    }
