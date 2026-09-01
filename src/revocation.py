"""
Taking a membership back.

Expiry is the slow way out of a network: a certificate lasts a year, and a node
that stops being renewed stops being a member. That is far too slow for the case
this module exists for — a key that leaked this morning. Until now there was no
fast way at all: once a certificate was signed, nothing in the tree could undo
it, and the compromised node stayed a full member until the following year.

A revocation is one signed sentence: **"I, the issuer, no longer vouch for this
subject, as of this moment."**

Who may say it
--------------
Only the node that issued the certificate. That is not a new authority — it is
exactly the one it already exercised by signing in the first place — and it is
the only one that needs no arbiter: the signature proves the claim, and the
issuer id derives from the key that made it, so there is no id to lie about.
Nobody can revoke anybody else's members, which is what keeps this from being a
way to cut nodes off the network.

What it voids
-------------
Every certificate that issuer signed for that subject **at or before** the
revocation's own timestamp. Naming a moment rather than one certificate is what
makes it hold: a subject may hold several certificates from one issuer, and
revoking them one at a time would leave whichever the attacker kept quiet. An
issuer that later changes its mind issues a *newer* certificate, which the
revocation does not reach — readmission stays a deliberate act.

A **root** cannot be revoked this way. A root's certificate is self-signed, so
the only node entitled to revoke it is itself, which is no use when the point is
that it has gone bad. Distrusting an anchor is a local decision by whoever runs
the node (`CertStore.remove_root`, exposed in the console), and it has to be:
there is nobody above a root to appeal to.

Hostile input
-------------
`parse` never raises and never returns a half-checked record: anything
oversized, truncated, malformed or badly signed is ``None``. It is a gate, and a
gate that can throw is a gate that can be used to kill a receive loop.
"""
from __future__ import annotations

import struct
import time

from .node_id import NodeID

_DOMAIN = b"nmesh-revocation-v1"
VERSION = 1

# version(B) ‖ issued_at(Q) ‖ subject_id(20) ‖ reason(B) ‖ pub_len(H) ‖ sig_len(H)
_HDR = struct.Struct("!BQ20sBHH")
_MAX_PUBKEY = 4096            # ML-DSA-65 public key ~1952 B — generous ceiling
_MAX_SIG = 5000               # ML-DSA-65 signature ~3309 B
MAX_RECORD = _HDR.size + _MAX_PUBKEY + _MAX_SIG

# Reasons are advisory: they are shown to an operator and decide nothing. A
# receiver acts on the revocation itself, never on why it says it happened.
REASON_UNSPECIFIED = 0
REASON_COMPROMISED = 1
REASON_SUPERSEDED = 2
REASON_DEPARTED = 3
REASON_NAMES = {
    REASON_UNSPECIFIED: "unspecified",
    REASON_COMPROMISED: "key compromised",
    REASON_SUPERSEDED: "superseded",
    REASON_DEPARTED: "left the network",
}


def _signing_input(issued_at: int, subject_id: bytes, reason: int) -> bytes:
    return (_DOMAIN + struct.pack("!BQ", VERSION, issued_at)
            + subject_id + bytes([reason]))


def build(subject_id: NodeID, issuer_pub: bytes, sign, *,
          reason: int = REASON_UNSPECIFIED,
          issued_at: int | None = None) -> bytes:
    """Sign a revocation of every certificate we issued for ``subject_id``.

    ``sign(message) -> signature`` signs with the issuer's ML-DSA identity, of
    which ``issuer_pub`` is the public half."""
    stamp = int(time.time() if issued_at is None else issued_at)
    if not 0 <= stamp <= 0xFFFFFFFFFFFFFFFF:
        raise ValueError("bad timestamp")
    if reason not in REASON_NAMES:
        reason = REASON_UNSPECIFIED
    signature = sign(_signing_input(stamp, subject_id.raw, reason))
    if len(issuer_pub) > _MAX_PUBKEY or len(signature) > _MAX_SIG:
        raise ValueError("revocation field too large")
    return (_HDR.pack(VERSION, stamp, subject_id.raw, reason,
                      len(issuer_pub), len(signature))
            + issuer_pub + signature)


def parse(data, verify) -> dict | None:
    """Parse and cryptographically verify a revocation.

    ``verify(message, signature, public_key) -> bool``. Returns
    ``{issuer_id, issuer_pub, subject_id, issued_at, reason}`` — ids as
    :class:`NodeID` — or ``None`` for anything that does not check out."""
    if not isinstance(data, (bytes, bytearray)):
        return None
    if not (_HDR.size <= len(data) <= MAX_RECORD):
        return None
    data = bytes(data)
    version, issued_at, subject_raw, reason, pub_len, sig_len = _HDR.unpack_from(data, 0)
    if version != VERSION:
        return None
    if pub_len > _MAX_PUBKEY or sig_len > _MAX_SIG or not pub_len or not sig_len:
        return None
    offset = _HDR.size
    # Exact length, not "at least": trailing bytes nobody reads are room for two
    # encodings of one record, and a record is what a bound is keyed on.
    if len(data) != offset + pub_len + sig_len:
        return None
    issuer_pub = data[offset:offset + pub_len]
    signature = data[offset + pub_len:]
    try:
        if not verify(_signing_input(issued_at, subject_raw, reason),
                      signature, issuer_pub):
            return None
    except Exception:
        return None      # a broken key blob must not raise into a receive loop
    issuer_id = NodeID.from_public_key(issuer_pub)
    subject_id = NodeID(subject_raw)
    # An issuer revoking itself is either a root trying to disown its own anchor
    # — which only whoever runs the node can decide — or noise. Neither is
    # something to store.
    if issuer_id == subject_id:
        return None
    return {
        "issuer_id": issuer_id,
        "issuer_pub": issuer_pub,
        "subject_id": subject_id,
        "issued_at": int(issued_at),
        "reason": int(reason),
    }
