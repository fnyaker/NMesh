"""
Handing a publisher key to somebody else — the one secret we deliberately copy.

Everything else in this project moves public halves around. This moves a
**private signing key**: the key that decides what code every node pinning it
will run. So the shape of the exchange is not "encrypt and send", it is a
handshake whose every step refuses by default.

Say it plainly first
--------------------
Sharing a signing key is a real cost and the alternative exists: each person
keeps their own key, and consumers pin several
(``release_quorum``/``endorsed``). That way a compromise is one signer, not the
project. Sharing is right when a *team* publishes one thing under one identity
and does not want every consumer to track who is on the team this year — and
wrong the moment "share it with one more person" becomes routine. Nothing here
can tell those apart; what it can do is make each act deliberate on both sides,
and leave a record of who handed what to whom.

Three messages, and why it takes three
--------------------------------------
::

    OFFER    sender    → recipient   "I hold key P and I offer it to you"
    ACCEPT   recipient → sender      "I want it — seal it to this KEM key"
    GRANT    sender    → recipient   the secret, sealed so only they can open it

The middle message is the whole design. There is no long-term encryption key to
seal a secret to — a node's identity is ML-DSA (a *signing* key), and the ML-KEM
keys it uses are ephemeral per link. So the recipient has to produce one, and it
produces one **only when a human accepted**. Consent is therefore structural
rather than checked: with no acceptance there is nothing to seal to, and the
secret cannot leave the sender's machine even by mistake.

What each signature is for
--------------------------
- The **offer is signed by the publisher key itself**. That proves the sender
  actually holds what they are offering; without it anybody could offer a key
  they do not have and harvest acceptances. It also carries the sender's node
  id *inside the signature*, so the reply goes where the signer said rather than
  to whatever ``src_id`` a relay wrote on the packet.
- The **acceptance is signed by the recipient's node identity**, over the KEM
  public key. That is what stops a relay substituting its own KEM key and
  reading the grant: only the node the offer named can produce an acceptance the
  sender will act on.
- The **grant needs no signature**. It is sealed to the accepted KEM key, and
  what proves it is genuine is arithmetic: the recipient checks the delivered
  secret against the public key **from the offer** (``CryptoIdentity.from_pair``).
  A forged or tampered grant yields a pair that does not match itself, and is
  refused — the same check ``publisher_key.load`` already makes.

What this does not hide
-----------------------
The sender must unlock the key to sign the offer and to seal the grant, so the
secret is in that process's memory for the length of the handshake. That is
unavoidable: you cannot send what you have not unlocked. It is bounded instead —
the sender forgets it when the grant goes out, or when the offer expires
unanswered (:data:`OFFER_TTL`), whichever comes first.

The recipient chooses **its own** passphrase. A shared passphrase would make the
weaker of the two machines the security of both, and the whole point of
``publisher_key.py`` is that the file is useless to whoever copies it.
"""
from __future__ import annotations

import os
import struct
import time

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

_DOMAIN = b"nmesh-publisher-share-v1"
VERSION = 1
OFFER_ID_LEN = 16
NODE_ID_LEN = 20

# How long an offer stands. Short on purpose: it is the window in which the
# sender holds an unlocked secret waiting for an answer.
OFFER_TTL = 300.0

MAX_LABEL = 64                 # what the sender calls this key, for a human
_MAX_PUBKEY = 4096             # ML-DSA-65 public ~1952 B
_MAX_SECRET = 8192             # ML-DSA-65 secret ~4032 B
_MAX_KEM_PUBLIC = 4096         # ML-KEM-768 public ~1184 B
_MAX_KEM_CIPHERTEXT = 4096     # ~1088 B
_MAX_SIG = 5000                # ML-DSA-65 signature ~3309 B
_NONCE_LEN = 12
_TAG_LEN = 16

# offer = version(B) ‖ ts(Q) ‖ offer_id(16) ‖ pub_len(H) ‖ label_len(H) ‖ sig_len(H)
_OFFER_HDR = struct.Struct("!BQ16sHHH")
MAX_OFFER = _OFFER_HDR.size + _MAX_PUBKEY + MAX_LABEL * 4 + _MAX_SIG

# accept = version(B) ‖ ts(Q) ‖ offer_id(16) ‖ kem_len(H) ‖ pub_len(H) ‖ sig_len(H)
_ACCEPT_HDR = struct.Struct("!BQ16sHHH")
MAX_ACCEPT = _ACCEPT_HDR.size + _MAX_KEM_PUBLIC + _MAX_PUBKEY + _MAX_SIG

# grant = version(B) ‖ offer_id(16) ‖ ct_len(H) ‖ nonce(12) ‖ kem_ct ‖ sealed
_GRANT_HDR = struct.Struct("!B16sH12s")
MAX_GRANT = (_GRANT_HDR.size + _MAX_KEM_CIPHERTEXT + _MAX_SECRET + _TAG_LEN)


class KeyShareError(Exception):
    """A share that cannot be built or accepted, phrased for whoever asked."""


def new_offer_id() -> bytes:
    return os.urandom(OFFER_ID_LEN)


def _label(text) -> str:
    return str(text or "")[:MAX_LABEL]


# ---------------------------------------------------------------------------
# 1. The offer — signed by the key being offered
# ---------------------------------------------------------------------------

def _offer_input(offer_id: bytes, from_id: bytes, to_id: bytes, ts: int,
                 publisher_pub: bytes, label: str) -> bytes:
    return (_DOMAIN + b":offer:" + offer_id + from_id + to_id
            + struct.pack("!Q", ts) + publisher_pub + label.encode("utf-8"))


def build_offer(offer_id: bytes, from_id: bytes, to_id: bytes,
                publisher_pub: bytes, sign, *, label: str = "",
                ts: int | None = None) -> bytes:
    """Offer a publisher key to one node. ``sign`` is **the offered key's**.

    Signing with the key being offered is what makes the offer worth reading:
    it proves the sender holds it. Both node ids are inside the signature, so
    the recipient replies to the node the signer named rather than to whatever
    a relay wrote on the packet."""
    _check_ids(from_id, to_id)
    if not isinstance(publisher_pub, (bytes, bytearray)) or not publisher_pub:
        raise KeyShareError("publisher key invalid")
    if len(publisher_pub) > _MAX_PUBKEY:
        raise KeyShareError("publisher key too large")
    if len(offer_id) != OFFER_ID_LEN:
        raise KeyShareError("offer id invalid")
    label = _label(label)
    ts = int(ts if ts is not None else time.time())
    signature = sign(_offer_input(offer_id, bytes(from_id), bytes(to_id), ts,
                                  bytes(publisher_pub), label))
    encoded = label.encode("utf-8")
    if len(signature) > _MAX_SIG or len(encoded) > MAX_LABEL * 4:
        raise KeyShareError("offer field too large")
    return (_OFFER_HDR.pack(VERSION, ts, bytes(offer_id), len(publisher_pub),
                            len(encoded), len(signature))
            + bytes(publisher_pub) + encoded + signature)


def parse_offer(data: bytes, from_id: bytes, to_id: bytes, verify) -> dict | None:
    """Parse and verify an offer addressed to ``to_id``.

    ``None`` for anything malformed, oversized, or not signed by the key it
    names — never raises, because this arrives from the network."""
    if not isinstance(data, (bytes, bytearray)):
        return None
    if not (_OFFER_HDR.size <= len(data) <= MAX_OFFER):
        return None
    data = bytes(data)
    version, ts, offer_id, pub_len, label_len, sig_len = \
        _OFFER_HDR.unpack_from(data, 0)
    if version != VERSION:
        return None
    if (pub_len > _MAX_PUBKEY or label_len > MAX_LABEL * 4
            or sig_len > _MAX_SIG or not pub_len or not sig_len):
        return None
    off = _OFFER_HDR.size
    if len(data) != off + pub_len + label_len + sig_len:
        return None
    publisher_pub = data[off:off + pub_len]
    raw_label = data[off + pub_len:off + pub_len + label_len]
    signature = data[off + pub_len + label_len:]
    try:
        label = raw_label.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if len(label) > MAX_LABEL or not label.isprintable():
        return None
    try:
        if not verify(_offer_input(offer_id, bytes(from_id), bytes(to_id), ts,
                                   publisher_pub, label),
                      signature, publisher_pub):
            return None
    except Exception:
        return None
    return {"offer_id": offer_id, "publisher": publisher_pub, "label": label,
            "ts": ts}


# ---------------------------------------------------------------------------
# 2. The acceptance — the only thing that makes a grant possible
# ---------------------------------------------------------------------------

def _accept_input(offer_id: bytes, from_id: bytes, to_id: bytes, ts: int,
                  kem_public: bytes) -> bytes:
    return (_DOMAIN + b":accept:" + offer_id + from_id + to_id
            + struct.pack("!Q", ts) + kem_public)


def build_accept(offer_id: bytes, from_id: bytes, to_id: bytes,
                 kem_public: bytes, node_pub: bytes, sign,
                 ts: int | None = None) -> bytes:
    """Accept an offer, naming the key the grant must be sealed to.

    Signed by the accepting node's **identity**, over the KEM public key: that
    binding is what stops a relay putting its own KEM key here and reading the
    secret. ``sign`` is the recipient node's."""
    _check_ids(from_id, to_id)
    if len(offer_id) != OFFER_ID_LEN:
        raise KeyShareError("offer id invalid")
    if not kem_public or len(kem_public) > _MAX_KEM_PUBLIC:
        raise KeyShareError("KEM key invalid")
    if not node_pub or len(node_pub) > _MAX_PUBKEY:
        raise KeyShareError("node key invalid")
    ts = int(ts if ts is not None else time.time())
    signature = sign(_accept_input(bytes(offer_id), bytes(from_id),
                                   bytes(to_id), ts, bytes(kem_public)))
    if len(signature) > _MAX_SIG:
        raise KeyShareError("accept field too large")
    return (_ACCEPT_HDR.pack(VERSION, ts, bytes(offer_id), len(kem_public),
                             len(node_pub), len(signature))
            + bytes(kem_public) + bytes(node_pub) + signature)


def parse_accept(data: bytes, from_id: bytes, to_id: bytes, verify,
                 node_id_of) -> dict | None:
    """Parse and verify an acceptance said to come from ``from_id``.

    ``node_id_of(pubkey) -> bytes`` derives a node id from a public key; the
    acceptance is refused unless the key inside it produces the very id the
    offer was addressed to. That is the check the MITM has to beat and cannot:
    it would need the recipient's signing key."""
    if not isinstance(data, (bytes, bytearray)):
        return None
    if not (_ACCEPT_HDR.size <= len(data) <= MAX_ACCEPT):
        return None
    data = bytes(data)
    version, ts, offer_id, kem_len, pub_len, sig_len = \
        _ACCEPT_HDR.unpack_from(data, 0)
    if version != VERSION:
        return None
    if (kem_len > _MAX_KEM_PUBLIC or pub_len > _MAX_PUBKEY
            or sig_len > _MAX_SIG or not kem_len or not pub_len or not sig_len):
        return None
    off = _ACCEPT_HDR.size
    if len(data) != off + kem_len + pub_len + sig_len:
        return None
    kem_public = data[off:off + kem_len]
    node_pub = data[off + kem_len:off + kem_len + pub_len]
    signature = data[off + kem_len + pub_len:]
    try:
        if node_id_of(node_pub) != bytes(from_id):
            return None          # not the node the offer named
        if not verify(_accept_input(offer_id, bytes(from_id), bytes(to_id), ts,
                                    kem_public), signature, node_pub):
            return None
    except Exception:
        return None
    return {"offer_id": offer_id, "kem_public": kem_public,
            "node_public": node_pub, "ts": ts}


# ---------------------------------------------------------------------------
# 3. The grant — sealed to the accepted key, and checkable without a signature
# ---------------------------------------------------------------------------

def _grant_key(shared_secret: bytes, offer_id: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=_DOMAIN + b":grant:" + offer_id).derive(shared_secret)


def _grant_aad(offer_id: bytes, from_id: bytes, to_id: bytes,
               publisher_pub: bytes) -> bytes:
    return (_DOMAIN + b":grant:" + offer_id + from_id + to_id + publisher_pub)


def seal_grant(offer_id: bytes, from_id: bytes, to_id: bytes,
               publisher_pub: bytes, secret_key: bytes, kem_public: bytes,
               encapsulate) -> bytes:
    """Seal the secret to the KEM key the recipient signed for.

    ``encapsulate(kem_public) -> (ciphertext, shared_secret)``. The offer id,
    both node ids and the public half are the AEAD's associated data, so a
    grant cannot be lifted into another exchange even by whoever relayed it."""
    _check_ids(from_id, to_id)
    if not secret_key or len(secret_key) > _MAX_SECRET:
        raise KeyShareError("secret key invalid")
    ciphertext, shared = encapsulate(bytes(kem_public))
    if len(ciphertext) > _MAX_KEM_CIPHERTEXT:
        raise KeyShareError("KEM ciphertext too large")
    nonce = os.urandom(_NONCE_LEN)
    sealed = AESGCM(_grant_key(shared, bytes(offer_id))).encrypt(
        nonce, bytes(secret_key),
        _grant_aad(bytes(offer_id), bytes(from_id), bytes(to_id),
                   bytes(publisher_pub)))
    return (_GRANT_HDR.pack(VERSION, bytes(offer_id), len(ciphertext), nonce)
            + ciphertext + sealed)


def open_grant(data: bytes, from_id: bytes, to_id: bytes, publisher_pub: bytes,
               kem_secret: bytes, decapsulate) -> bytes | None:
    """Recover the secret key from a grant. ``None`` if it is not for us.

    ``decapsulate(ciphertext, kem_secret) -> shared_secret``. What this does
    **not** do is decide the secret is genuine: the caller checks it against
    ``publisher_pub`` (``CryptoIdentity.from_pair``), because a key pair that
    does not match itself is the one failure a signature would not catch."""
    if not isinstance(data, (bytes, bytearray)):
        return None
    if not (_GRANT_HDR.size <= len(data) <= MAX_GRANT):
        return None
    data = bytes(data)
    version, offer_id, ct_len, nonce = _GRANT_HDR.unpack_from(data, 0)
    if version != VERSION or not ct_len or ct_len > _MAX_KEM_CIPHERTEXT:
        return None
    off = _GRANT_HDR.size
    if len(data) < off + ct_len + _TAG_LEN:
        return None
    ciphertext = data[off:off + ct_len]
    sealed = data[off + ct_len:]
    if len(sealed) > _MAX_SECRET + _TAG_LEN:
        return None
    try:
        shared = decapsulate(ciphertext, bytes(kem_secret))
        return AESGCM(_grant_key(shared, offer_id)).decrypt(
            nonce, sealed,
            _grant_aad(offer_id, bytes(from_id), bytes(to_id),
                       bytes(publisher_pub)))
    except Exception:
        return None              # wrong key, wrong exchange, tampered — silent


# Which exchange a message claims to belong to, read before it is verified.
#
# A label, not a fact: it says which pending row to try, and the signature (or
# the seal) is what decides whether it was the right one. Both live here rather
# than as an offset written out at the call site — the format is this module's
# business, and an offset copied into a handler is an offset that goes stale
# silently. It did: the first cut read `payload[:16]` for an acceptance, which
# is the version and most of the timestamp, so every acceptance looked like an
# answer to a question nobody had asked.

def accept_offer_id(data: bytes) -> bytes | None:
    if not isinstance(data, (bytes, bytearray)):
        return None
    if not (_ACCEPT_HDR.size <= len(data) <= MAX_ACCEPT):
        return None
    version, _ts, offer_id, _kem, _pub, _sig = _ACCEPT_HDR.unpack_from(
        bytes(data), 0)
    return offer_id if version == VERSION else None


def grant_offer_id(data: bytes) -> bytes | None:
    if not isinstance(data, (bytes, bytearray)):
        return None
    if not (_GRANT_HDR.size <= len(data) <= MAX_GRANT):
        return None
    version, offer_id, _ct_len, _nonce = _GRANT_HDR.unpack_from(bytes(data), 0)
    return offer_id if version == VERSION else None


def _check_ids(from_id, to_id) -> None:
    for value in (from_id, to_id):
        if not isinstance(value, (bytes, bytearray)) or len(value) != NODE_ID_LEN:
            raise KeyShareError("node id invalid")
