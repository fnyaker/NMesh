"""
Application identity & authentication — the mesh identity used as a login.

The mesh already authenticates *transport*: a DATA payload handed to an app
carries a ``src_id`` proven by the E2E session (ML-DSA signature + certificate
chain, see ``Docs/Architecture/security.md``). That is a strong property, but it
is confined to one live session on one node: an app cannot re-check it later,
cannot hand it to a third party, and cannot tell *what* the peer meant to
authorise. This module adds the missing layer — the app-level equivalent of a
single sign-on backed by the node's long-term identity:

  - an **assertion** is a short signed statement "node *S* asserts, inside app
    *A*, to audience *B*, for purpose *P*, over context *C*, at time *T*";
  - it is **self-verifying and portable**: anyone holding the bytes can check it
    offline, after a restart, without the session that carried it;
  - it is **scoped**: an assertion minted for one app / audience / purpose is
    cryptographically useless anywhere else;
  - it is **single-use**: a bounded nonce cache makes a replay fail.

Why this is not a signing oracle
--------------------------------
Handing an app a "sign these bytes with the node key" primitive would be fatal:
the same ML-DSA key signs certificates, handshakes, release descriptors and
directory claims, so an app could have the node sign a *certificate body* and
mint itself membership. Nothing here signs app-supplied bytes. The signed input
is always ``_DOMAIN ‖ <fixed, bounded, structured fields>``, the app's free-form
context enters only as a **32-byte hash**, and ``_DOMAIN`` is distinct from every
other signing domain in the tree (``nmesh-pseudo-v2``,
``nmesh-app-release-v1``, the certificate body, the handshake input). An app
therefore cannot steer the signer outside the app-auth namespace.

Reject by default
-----------------
Every field is length-checked before use, every parse failure returns ``None``
rather than raising into a caller, and the replay cache, the session table and
the pending-challenge table are all hard-bounded — a hostile peer cannot grow
memory through us, and a malformed assertion never reaches the verifier.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import struct
import time
from dataclasses import dataclass

from .app_channel import APP_ID_LEN
from .node_id import NodeID

_DOMAIN = b"nmesh-app-auth-v1"
_VERSION = 1

NONCE_LEN = 16
CTX_LEN = 32                      # sha256 of the caller's context
ANY_AUDIENCE = b"\x00" * 20       # an assertion addressed to no node in particular

# Bounds. A hostile assertion is rejected before anything is allocated for it.
MAX_PUB_LEN = 8192                # ML-DSA-65 public key is ~1.9 KiB
MAX_SIG_LEN = 8192                # ML-DSA-65 signature is ~3.3 KiB
MAX_PURPOSE_LEN = 64
MAX_ASSERTION_LEN = 32 * 1024
DEFAULT_TTL = 120                 # seconds an assertion stays valid
MAX_TTL = 86400
MAX_SKEW = 60                     # tolerated clock skew, seconds

# Replay cache / session table ceilings (anti-exhaustion).
MAX_NONCES = 8192
MAX_SESSIONS = 512
MAX_PENDING = 512
SESSION_TTL = 3600.0

_HEAD = struct.Struct("!BB8sH")          # version, flags(reserved), app_id, pub_len
_MID = struct.Struct("!20sB")            # audience, purpose_len
_TAIL = struct.Struct("!16sQI32sH")      # nonce, issued_at, ttl, ctx_hash, sig_len


class AppAuthError(Exception):
    """Raised only by the *minting* side, on caller misuse (never on parsing)."""


def ctx_hash(*parts: bytes) -> bytes:
    """Bind arbitrary app context into an assertion as one 32-byte digest.

    Length-prefixed so ``(b"ab", b"c")`` and ``(b"a", b"bc")`` never collide —
    an attacker must not be able to re-cut a context into a different meaning."""
    h = hashlib.sha256()
    h.update(_DOMAIN)
    for part in parts:
        h.update(struct.pack("!I", len(part)))
        h.update(part)
    return h.digest()


# ---------------------------------------------------------------------------
# The assertion itself
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Assertion:
    """A parsed, *not yet verified* app-auth statement. Only
    :func:`verify_assertion` may be trusted to hand one to application logic."""

    app_id: bytes
    subject_pub: bytes
    audience: bytes            # 20-byte node id, or ANY_AUDIENCE
    purpose: str
    nonce: bytes
    issued_at: int
    ttl: int
    ctx: bytes                 # 32-byte digest (see ctx_hash)
    signature: bytes

    @property
    def subject(self) -> NodeID:
        """The asserting node's id, *derived from the key it signed with* — an
        id that does not derive from the presented key is a lie, so there is no
        separate claimed-id field to disagree with."""
        return NodeID.from_public_key(self.subject_pub)

    @property
    def expires_at(self) -> int:
        return self.issued_at + self.ttl

    def signed_body(self) -> bytes:
        """Exactly what the ML-DSA signature covers. Always starts with the
        app-auth domain tag, so this input can never be read as a certificate
        body, a handshake input, or any other signed structure in the tree."""
        purpose = self.purpose.encode("utf-8")
        return (
            _DOMAIN
            + _HEAD.pack(_VERSION, 0, self.app_id, len(self.subject_pub))
            + self.subject_pub
            + _MID.pack(self.audience, len(purpose))
            + purpose
            + struct.pack("!16sQI32s", self.nonce, self.issued_at, self.ttl, self.ctx)
        )

    def serialize(self) -> bytes:
        purpose = self.purpose.encode("utf-8")
        return (
            _HEAD.pack(_VERSION, 0, self.app_id, len(self.subject_pub))
            + self.subject_pub
            + _MID.pack(self.audience, len(purpose))
            + purpose
            + _TAIL.pack(self.nonce, self.issued_at, self.ttl, self.ctx,
                         len(self.signature))
            + self.signature
        )


def parse_assertion(blob: bytes) -> Assertion | None:
    """Decode an assertion from hostile bytes. Returns None on anything
    malformed, truncated, oversized or out of bounds — never raises."""
    if not isinstance(blob, (bytes, bytearray)) or len(blob) > MAX_ASSERTION_LEN:
        return None
    blob = bytes(blob)
    try:
        if len(blob) < _HEAD.size:
            return None
        version, _flags, app_id, pub_len = _HEAD.unpack_from(blob, 0)
        if version != _VERSION or not 0 < pub_len <= MAX_PUB_LEN:
            return None
        off = _HEAD.size
        if len(blob) < off + pub_len + _MID.size:
            return None
        subject_pub = blob[off:off + pub_len]
        off += pub_len
        audience, purpose_len = _MID.unpack_from(blob, off)
        off += _MID.size
        if purpose_len > MAX_PURPOSE_LEN or len(blob) < off + purpose_len + _TAIL.size:
            return None
        purpose = blob[off:off + purpose_len].decode("utf-8")
        off += purpose_len
        nonce, issued_at, ttl, ctx, sig_len = _TAIL.unpack_from(blob, off)
        off += _TAIL.size
        if not 0 < sig_len <= MAX_SIG_LEN or len(blob) != off + sig_len:
            return None
        if ttl == 0 or ttl > MAX_TTL:
            return None
        signature = blob[off:off + sig_len]
    except (struct.error, UnicodeDecodeError, ValueError):
        return None
    return Assertion(app_id, subject_pub, audience, purpose, nonce,
                     issued_at, ttl, ctx, signature)


def make_assertion(identity, app_id: bytes, *, audience: bytes | NodeID,
                   purpose: str, ctx: bytes = b"\x00" * CTX_LEN,
                   ttl: int = DEFAULT_TTL, now: float | None = None) -> Assertion:
    """Mint an assertion signed by ``identity`` (a :class:`~src.crypto.CryptoIdentity`).

    ``audience`` is the node the statement is *for*; use :data:`ANY_AUDIENCE`
    only for a statement genuinely addressed to no one in particular (it can
    then be relayed to any verifier — the caller owns that consequence)."""
    if len(app_id) != APP_ID_LEN:
        raise AppAuthError("app_id must be APP_ID_LEN bytes")
    aud = audience.raw if isinstance(audience, NodeID) else bytes(audience)
    if len(aud) != 20:
        raise AppAuthError("audience must be a 20-byte node id")
    if len(ctx) != CTX_LEN:
        raise AppAuthError("ctx must be a 32-byte digest (see ctx_hash)")
    encoded_purpose = purpose.encode("utf-8")
    if not 0 < len(encoded_purpose) <= MAX_PURPOSE_LEN:
        raise AppAuthError("purpose out of bounds")
    if not 0 < ttl <= MAX_TTL:
        raise AppAuthError("ttl out of bounds")
    unsigned = Assertion(app_id, identity.dsa_public_key, aud, purpose,
                         os.urandom(NONCE_LEN), int(now or time.time()), ttl,
                         ctx, b"")
    return Assertion(unsigned.app_id, unsigned.subject_pub, unsigned.audience,
                     unsigned.purpose, unsigned.nonce, unsigned.issued_at,
                     unsigned.ttl, unsigned.ctx,
                     identity.sign(unsigned.signed_body()))


@dataclass(frozen=True)
class Principal:
    """The result of a *successful* verification: who proved what, until when."""

    node_id: NodeID
    public_key: bytes
    app_id: bytes
    purpose: str
    ctx: bytes
    issued_at: int
    expires_at: int


def verify_assertion(blob: bytes, verifier, *, app_id: bytes,
                     audience: bytes | NodeID, purpose: str | None = None,
                     ctx: bytes | None = None, nonces: "NonceCache | None" = None,
                     trust=None, now: float | None = None) -> Principal | None:
    """Verify an assertion end to end. Returns a :class:`Principal`, or ``None``
    if *anything* fails to check out (reject by default — the caller never has
    to distinguish "invalid" from "malformed").

    Checks, in order (cheapest and most discriminating first, signature last
    because ML-DSA verification is the expensive step):

    1. parses within bounds;
    2. names *our* app section — an assertion for another app is not ours to use;
    3. is addressed to us (or to :data:`ANY_AUDIENCE`);
    4. states the ``purpose`` we asked about, and the ``ctx`` we expected;
    5. is fresh: issued no further ahead than ``MAX_SKEW`` and not expired;
    6. its nonce has not been seen before (single use);
    7. its signature verifies under the presented key;
    8. that key is consistent with what we already knew of the subject (TOFU).
    """
    parsed = parse_assertion(blob)
    if parsed is None:
        return None
    if not hmac.compare_digest(parsed.app_id, bytes(app_id)):
        return None
    aud = audience.raw if isinstance(audience, NodeID) else bytes(audience)
    if (not hmac.compare_digest(parsed.audience, aud)
            and not hmac.compare_digest(parsed.audience, ANY_AUDIENCE)):
        return None
    if purpose is not None and not hmac.compare_digest(
            parsed.purpose.encode("utf-8"), purpose.encode("utf-8")):
        return None
    if ctx is not None and not hmac.compare_digest(parsed.ctx, bytes(ctx)):
        return None
    stamp = int(now if now is not None else time.time())
    if parsed.issued_at > stamp + MAX_SKEW or parsed.expires_at <= stamp:
        return None
    # Burn the nonce only once everything cheap has passed, so a flood of
    # rubbish cannot evict live entries from a bounded cache.
    if nonces is not None and not nonces.claim(parsed.nonce, parsed.expires_at,
                                               now=stamp):
        return None
    try:
        if not verifier(parsed.signed_body(), parsed.signature, parsed.subject_pub):
            return None
    except Exception:
        return None  # a broken key blob must not raise into the caller
    subject = parsed.subject
    if trust is not None and not trust.add(subject, parsed.subject_pub):
        return None  # same id, different key — impersonation or compromise
    return Principal(subject, parsed.subject_pub, parsed.app_id, parsed.purpose,
                     parsed.ctx, parsed.issued_at, parsed.expires_at)


# ---------------------------------------------------------------------------
# Replay protection
# ---------------------------------------------------------------------------

class NonceCache:
    """Bounded single-use nonce set. Entries drop when the assertion that used
    them expires; under pressure the oldest go first, so the cache degrades into
    a shorter replay window rather than growing without end."""

    def __init__(self, max_entries: int = MAX_NONCES) -> None:
        self._max = max(1, max_entries)
        self._seen: dict[bytes, int] = {}   # nonce -> expiry (unix seconds)

    def claim(self, nonce: bytes, expires_at: int, *, now: float | None = None) -> bool:
        """Consume ``nonce``. True the first time, False on every replay."""
        if not isinstance(nonce, (bytes, bytearray)) or len(nonce) != NONCE_LEN:
            return False
        nonce = bytes(nonce)
        stamp = int(now if now is not None else time.time())
        self._expire(stamp)
        if nonce in self._seen:
            return False
        while len(self._seen) >= self._max:
            self._seen.pop(next(iter(self._seen)), None)
        self._seen[nonce] = expires_at
        return True

    def _expire(self, stamp: int) -> None:
        if len(self._seen) < self._max // 2:
            return  # sweeping a mostly-empty cache is wasted work
        for key in [k for k, exp in self._seen.items() if exp <= stamp]:
            self._seen.pop(key, None)

    def __len__(self) -> int:
        return len(self._seen)


# ---------------------------------------------------------------------------
# Mutual app-level sessions (the "sign-on" itself)
# ---------------------------------------------------------------------------
#
# Three messages, each side proving liveness on a nonce the *other* chose, so
# neither can be replayed and neither side authenticates alone:
#
#   A → B   HELLO      nonce_a
#   B → A   CHALLENGE  nonce_b ‖ assertion_b(audience=A, ctx=H(nonce_a‖nonce_b))
#   A → B   PROVE      assertion_a(audience=B, ctx=H(nonce_a‖nonce_b))
#
# Both ends then hold the same session id = H(nonce_a ‖ nonce_b), bound to two
# proven identities. This is defence in depth on top of the E2E session, not a
# replacement: it survives a restart as an auditable record, and it states what
# the peer meant to authorise.

PURPOSE_LOGIN = "auth.login"

_HELLO = 0x01
_CHALLENGE = 0x02
_PROVE = 0x03


def session_id(nonce_a: bytes, nonce_b: bytes) -> bytes:
    return ctx_hash(b"session", nonce_a, nonce_b)[:16]


@dataclass
class AuthSession:
    """A mutually authenticated app-level session between two nodes."""

    sid: bytes
    peer: NodeID
    peer_key: bytes
    established_at: float
    expires_at: float

    def alive(self, now: float | None = None) -> bool:
        return (now if now is not None else time.monotonic()) < self.expires_at


class AppAuth:
    """Per-app authentication service: mints our assertions, verifies peers',
    and drives the three-message mutual login.

    One instance per app section. ``identity`` is the node's
    :class:`~src.crypto.CryptoIdentity`; the app never touches it directly, and
    every signature it can cause is confined to the app-auth domain.
    """

    def __init__(self, identity, app_id: bytes, node_id: NodeID, *,
                 trust=None, session_ttl: float = SESSION_TTL,
                 max_sessions: int = MAX_SESSIONS) -> None:
        if len(app_id) != APP_ID_LEN:
            raise AppAuthError("app_id must be APP_ID_LEN bytes")
        self._identity = identity
        self._app_id = bytes(app_id)
        self._node_id = node_id
        self._trust = trust
        self._ttl = session_ttl
        self._max_sessions = max(1, max_sessions)
        self._nonces = NonceCache()
        self._sessions: dict[bytes, AuthSession] = {}       # sid -> session
        self._pending: dict[bytes, tuple[NodeID, bytes, float]] = {}  # nonce_a -> …

    @property
    def app_id(self) -> bytes:
        return self._app_id

    @property
    def node_id(self) -> NodeID:
        return self._node_id

    @property
    def public_key(self) -> bytes:
        """Our own ML-DSA public key — the thing a peer needs to verify us. It
        is public by definition; the private half never leaves the identity."""
        return self._identity.dsa_public_key

    # -- assertions -------------------------------------------------------

    def assert_to(self, audience: bytes | NodeID, purpose: str,
                  ctx: bytes = b"\x00" * CTX_LEN, ttl: int = DEFAULT_TTL) -> bytes:
        """Mint a serialized assertion of *ours* for ``audience``."""
        return make_assertion(self._identity, self._app_id, audience=audience,
                              purpose=purpose, ctx=ctx, ttl=ttl).serialize()

    def verify(self, blob: bytes, *, purpose: str | None = None,
               ctx: bytes | None = None,
               audience: bytes | NodeID | None = None) -> Principal | None:
        """Verify a peer's assertion addressed to us. ``None`` on any failure."""
        return verify_assertion(
            blob, self._identity.verify, app_id=self._app_id,
            audience=self._node_id if audience is None else audience,
            purpose=purpose, ctx=ctx, nonces=self._nonces, trust=self._trust)

    # -- mutual login -----------------------------------------------------

    def start_login(self, peer: NodeID) -> bytes:
        """Step 1 (initiator). Returns the HELLO frame to send to ``peer``."""
        nonce_a = os.urandom(NONCE_LEN)
        self._prune_pending()
        self._pending[nonce_a] = (peer, b"", time.monotonic() + self._ttl)
        return bytes([_HELLO]) + nonce_a

    def answer_login(self, peer: NodeID, frame: bytes) -> bytes | None:
        """Step 2 (responder). Consumes a HELLO, returns the CHALLENGE frame."""
        if len(frame) != 1 + NONCE_LEN or frame[0] != _HELLO:
            return None
        nonce_a = frame[1:]
        nonce_b = os.urandom(NONCE_LEN)
        self._prune_pending()
        if len(self._pending) >= MAX_PENDING:
            return None
        proof = self.assert_to(peer, PURPOSE_LOGIN,
                               ctx_hash(b"login", nonce_a, nonce_b))
        self._pending[nonce_b] = (peer, nonce_a, time.monotonic() + self._ttl)
        return bytes([_CHALLENGE]) + nonce_b + proof

    def complete_login(self, peer: NodeID, frame: bytes) -> tuple[bytes, AuthSession] | None:
        """Step 3 (initiator). Verifies the responder's proof and returns the
        PROVE frame plus *our* established session. ``None`` if it fails."""
        if len(frame) < 1 + NONCE_LEN or frame[0] != _CHALLENGE:
            return None
        nonce_b, proof = frame[1:1 + NONCE_LEN], frame[1 + NONCE_LEN:]
        # The HELLO nonce we are still waiting on for this peer.
        nonce_a = next((n for n, (p, prior, _) in self._pending.items()
                        if p == peer and not prior), None)
        if nonce_a is None:
            return None
        principal = self.verify(proof, purpose=PURPOSE_LOGIN,
                                ctx=ctx_hash(b"login", nonce_a, nonce_b))
        if principal is None or principal.node_id != peer:
            return None
        self._pending.pop(nonce_a, None)
        reply = self.assert_to(peer, PURPOSE_LOGIN,
                               ctx_hash(b"login", nonce_a, nonce_b))
        session = self._store_session(session_id(nonce_a, nonce_b), principal)
        return bytes([_PROVE]) + reply, session

    def accept_login(self, peer: NodeID, frame: bytes) -> AuthSession | None:
        """Step 4 (responder). Verifies the initiator's proof, returns the
        established session."""
        if len(frame) < 1 or frame[0] != _PROVE:
            return None
        entry = next(((n, prior) for n, (p, prior, _) in self._pending.items()
                      if p == peer and prior), None)
        if entry is None:
            return None
        nonce_b, nonce_a = entry
        principal = self.verify(frame[1:], purpose=PURPOSE_LOGIN,
                                ctx=ctx_hash(b"login", nonce_a, nonce_b))
        if principal is None or principal.node_id != peer:
            return None
        self._pending.pop(nonce_b, None)
        return self._store_session(session_id(nonce_a, nonce_b), principal)

    # -- session table ----------------------------------------------------

    def _store_session(self, sid: bytes, principal: Principal) -> AuthSession:
        now = time.monotonic()
        self._prune_sessions(now)
        while len(self._sessions) >= self._max_sessions:
            self._sessions.pop(next(iter(self._sessions)), None)
        session = AuthSession(sid, principal.node_id, principal.public_key,
                              now, now + self._ttl)
        self._sessions[sid] = session
        return session

    def session(self, sid: bytes) -> AuthSession | None:
        session = self._sessions.get(bytes(sid))
        if session is None:
            return None
        if not session.alive():
            self._sessions.pop(bytes(sid), None)
            return None
        return session

    def drop_session(self, sid: bytes) -> None:
        self._sessions.pop(bytes(sid), None)

    def _prune_sessions(self, now: float) -> None:
        for sid in [s for s, sess in self._sessions.items() if sess.expires_at <= now]:
            self._sessions.pop(sid, None)

    def _prune_pending(self) -> None:
        now = time.monotonic()
        for nonce in [n for n, (_, _, deadline) in self._pending.items()
                      if deadline <= now]:
            self._pending.pop(nonce, None)
        while len(self._pending) > MAX_PENDING:
            self._pending.pop(next(iter(self._pending)), None)

    def __len__(self) -> int:
        return len(self._sessions)
