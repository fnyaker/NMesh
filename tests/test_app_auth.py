"""
Application identity & authentication tests.

This layer is the app-level login: a compromise here lets one node speak as
another inside an app. So the tests are mostly *negative* — every scoping field
(app, audience, purpose, context, freshness, nonce, key binding) must be load
bearing, and no hostile byte string may crash a parser.
"""
import os
import struct
import time

import pytest

from src.app_auth import (
    ANY_AUDIENCE, AppAuth, AppAuthError, Assertion, CTX_LEN, MAX_ASSERTION_LEN,
    MAX_PURPOSE_LEN, MAX_TTL, MAX_SKEW, NONCE_LEN, NonceCache, PURPOSE_LOGIN,
    ctx_hash, make_assertion, parse_assertion, verify_assertion,
)
from src.app_channel import builtin_id
from src.crypto import CryptoIdentity
from src.node_id import NodeID
from src.trust import TrustTable

APP = builtin_id("test-auth")
OTHER_APP = builtin_id("test-auth-other")


@pytest.fixture(scope="module")
def alice():
    identity = CryptoIdentity()
    return identity, NodeID.from_public_key(identity.dsa_public_key)


@pytest.fixture(scope="module")
def bob():
    identity = CryptoIdentity()
    return identity, NodeID.from_public_key(identity.dsa_public_key)


def _verify(blob, alice_identity, **kwargs):
    kwargs.setdefault("app_id", APP)
    return verify_assertion(blob, alice_identity.verify, **kwargs)


class TestRoundTrip:
    def test_mint_and_verify(self, alice, bob):
        a_id, _ = alice
        b_id, b_node = bob
        blob = make_assertion(a_id, APP, audience=b_node,
                              purpose="test.hello").serialize()
        principal = _verify(blob, b_id, audience=b_node, purpose="test.hello")
        assert principal is not None
        assert principal.node_id == NodeID.from_public_key(a_id.dsa_public_key)
        assert principal.app_id == APP
        assert principal.purpose == "test.hello"

    def test_serialize_parse_roundtrip(self, alice, bob):
        a_id, _ = alice
        _, b_node = bob
        original = make_assertion(a_id, APP, audience=b_node, purpose="p",
                                  ctx=ctx_hash(b"x"))
        again = parse_assertion(original.serialize())
        assert again == original

    def test_subject_derives_from_key(self, alice, bob):
        a_id, a_node = alice
        _, b_node = bob
        parsed = parse_assertion(
            make_assertion(a_id, APP, audience=b_node, purpose="p").serialize())
        assert parsed.subject == a_node

    def test_any_audience_verifies_anywhere(self, alice, bob):
        a_id, _ = alice
        b_id, b_node = bob
        blob = make_assertion(a_id, APP, audience=ANY_AUDIENCE,
                              purpose="broadcast").serialize()
        assert _verify(blob, b_id, audience=b_node, purpose="broadcast") is not None


class TestScoping:
    """Every scoping field must actually gate. If one of these passes, an
    assertion minted for one context is usable in another."""

    def test_wrong_app_rejected(self, alice, bob):
        a_id, _ = alice
        b_id, b_node = bob
        blob = make_assertion(a_id, APP, audience=b_node, purpose="p").serialize()
        assert _verify(blob, b_id, app_id=OTHER_APP, audience=b_node) is None

    def test_wrong_audience_rejected(self, alice, bob):
        a_id, _ = alice
        b_id, _ = bob
        someone_else = NodeID(b"\x07" * 20)
        blob = make_assertion(a_id, APP, audience=someone_else,
                              purpose="p").serialize()
        assert _verify(blob, b_id, audience=NodeID(b"\x08" * 20)) is None

    def test_wrong_purpose_rejected(self, alice, bob):
        a_id, _ = alice
        b_id, b_node = bob
        blob = make_assertion(a_id, APP, audience=b_node,
                              purpose="fleet.status").serialize()
        assert _verify(blob, b_id, audience=b_node, purpose="fleet.shell") is None

    def test_wrong_ctx_rejected(self, alice, bob):
        a_id, _ = alice
        b_id, b_node = bob
        blob = make_assertion(a_id, APP, audience=b_node, purpose="p",
                              ctx=ctx_hash(b"reboot")).serialize()
        assert _verify(blob, b_id, audience=b_node,
                       ctx=ctx_hash(b"rm -rf /")) is None

    def test_ctx_hash_is_unambiguous(self):
        # Length-prefixed: re-cutting the same bytes must not collide, or an
        # attacker could re-interpret a signed context.
        assert ctx_hash(b"ab", b"c") != ctx_hash(b"a", b"bc")
        assert ctx_hash(b"a") == ctx_hash(b"a")


class TestFreshness:
    def test_expired_rejected(self, alice, bob):
        a_id, _ = alice
        b_id, b_node = bob
        past = time.time() - 10_000
        blob = make_assertion(a_id, APP, audience=b_node, purpose="p",
                              ttl=60, now=past).serialize()
        assert _verify(blob, b_id, audience=b_node) is None

    def test_far_future_rejected(self, alice, bob):
        a_id, _ = alice
        b_id, b_node = bob
        blob = make_assertion(a_id, APP, audience=b_node, purpose="p",
                              now=time.time() + MAX_SKEW + 600).serialize()
        assert _verify(blob, b_id, audience=b_node) is None

    def test_small_skew_tolerated(self, alice, bob):
        a_id, _ = alice
        b_id, b_node = bob
        blob = make_assertion(a_id, APP, audience=b_node, purpose="p",
                              now=time.time() + MAX_SKEW // 2).serialize()
        assert _verify(blob, b_id, audience=b_node) is not None


class TestReplay:
    def test_nonce_is_single_use(self, alice, bob):
        a_id, _ = alice
        b_id, b_node = bob
        cache = NonceCache()
        blob = make_assertion(a_id, APP, audience=b_node, purpose="p").serialize()
        assert _verify(blob, b_id, audience=b_node, nonces=cache) is not None
        assert _verify(blob, b_id, audience=b_node, nonces=cache) is None

    def test_cache_is_bounded(self):
        cache = NonceCache(max_entries=8)
        for _ in range(100):
            cache.claim(os.urandom(NONCE_LEN), int(time.time()) + 60)
        assert len(cache) <= 8

    def test_bad_nonce_length_refused(self):
        cache = NonceCache()
        assert cache.claim(b"short", int(time.time()) + 60) is False

    def test_nonce_not_burned_by_a_failing_assertion(self, alice, bob):
        """A flood of assertions that fail a cheap check must not evict live
        entries — the nonce is only claimed once the cheap checks pass."""
        a_id, _ = alice
        b_id, b_node = bob
        cache = NonceCache()
        parsed = parse_assertion(
            make_assertion(a_id, APP, audience=b_node, purpose="p").serialize())
        # Rejected on purpose, so its nonce stays unspent…
        assert _verify(parsed.serialize(), b_id, audience=b_node,
                       purpose="other", nonces=cache) is None
        assert len(cache) == 0
        # …and the very same assertion still verifies for its real purpose.
        assert _verify(parsed.serialize(), b_id, audience=b_node,
                       purpose="p", nonces=cache) is not None


class TestKeyBinding:
    def test_tampered_signature_rejected(self, alice, bob):
        a_id, _ = alice
        b_id, b_node = bob
        parsed = parse_assertion(
            make_assertion(a_id, APP, audience=b_node, purpose="p").serialize())
        forged = Assertion(parsed.app_id, parsed.subject_pub, parsed.audience,
                           parsed.purpose, parsed.nonce, parsed.issued_at,
                           parsed.ttl, parsed.ctx,
                           bytes(parsed.signature[:-1]) + bytes([parsed.signature[-1] ^ 1]))
        assert _verify(forged.serialize(), b_id, audience=b_node) is None

    def test_swapped_key_rejected(self, alice, bob):
        """Presenting someone else's public key does not make the signature
        check out — and the subject id derives from the key, so there is no
        identity to steal by editing a field."""
        a_id, _ = alice
        b_id, b_node = bob
        parsed = parse_assertion(
            make_assertion(a_id, APP, audience=b_node, purpose="p").serialize())
        swapped = Assertion(parsed.app_id, b_id.dsa_public_key, parsed.audience,
                            parsed.purpose, parsed.nonce, parsed.issued_at,
                            parsed.ttl, parsed.ctx, parsed.signature)
        assert _verify(swapped.serialize(), b_id, audience=b_node) is None

    def test_tofu_conflict_rejected(self, alice, bob):
        """Same node id, different key → impersonation or compromise."""
        a_id, a_node = alice
        b_id, b_node = bob
        trust = TrustTable()
        trust.add(a_node, b"a-completely-different-key")
        blob = make_assertion(a_id, APP, audience=b_node, purpose="p").serialize()
        assert _verify(blob, b_id, audience=b_node, trust=trust) is None

    def test_tofu_records_first_sight(self, alice, bob):
        a_id, a_node = alice
        b_id, b_node = bob
        trust = TrustTable()
        blob = make_assertion(a_id, APP, audience=b_node, purpose="p").serialize()
        assert _verify(blob, b_id, audience=b_node, trust=trust) is not None
        assert trust.get_key(a_node) == a_id.dsa_public_key


class TestMintingBounds:
    def test_bad_app_id(self, alice, bob):
        a_id, _ = alice
        _, b_node = bob
        with pytest.raises(AppAuthError):
            make_assertion(a_id, b"short", audience=b_node, purpose="p")

    def test_bad_audience(self, alice):
        a_id, _ = alice
        with pytest.raises(AppAuthError):
            make_assertion(a_id, APP, audience=b"\x00" * 8, purpose="p")

    def test_bad_ctx(self, alice, bob):
        a_id, _ = alice
        _, b_node = bob
        with pytest.raises(AppAuthError):
            make_assertion(a_id, APP, audience=b_node, purpose="p", ctx=b"short")

    def test_bad_purpose(self, alice, bob):
        a_id, _ = alice
        _, b_node = bob
        with pytest.raises(AppAuthError):
            make_assertion(a_id, APP, audience=b_node, purpose="")
        with pytest.raises(AppAuthError):
            make_assertion(a_id, APP, audience=b_node,
                           purpose="x" * (MAX_PURPOSE_LEN + 1))

    def test_bad_ttl(self, alice, bob):
        a_id, _ = alice
        _, b_node = bob
        with pytest.raises(AppAuthError):
            make_assertion(a_id, APP, audience=b_node, purpose="p", ttl=0)
        with pytest.raises(AppAuthError):
            make_assertion(a_id, APP, audience=b_node, purpose="p", ttl=MAX_TTL + 1)


class TestHostileParsing:
    """No byte string may raise out of the parser (charter: zero crash)."""

    def test_garbage_never_raises(self):
        for _ in range(400):
            assert parse_assertion(os.urandom(int.from_bytes(os.urandom(1), "big"))) is None

    def test_truncations_never_raise(self, alice, bob):
        a_id, _ = alice
        _, b_node = bob
        blob = make_assertion(a_id, APP, audience=b_node, purpose="p").serialize()
        for cut in range(len(blob)):
            assert parse_assertion(blob[:cut]) is None
        # Trailing junk is a length mismatch, not a signature to check.
        assert parse_assertion(blob + b"\x00") is None

    def test_wrong_types_rejected(self):
        for junk in (None, 42, "string", [], {}):
            assert parse_assertion(junk) is None

    def test_oversized_rejected(self):
        assert parse_assertion(b"\x01" * (MAX_ASSERTION_LEN + 1)) is None

    def test_declared_lengths_are_bounded(self):
        # pub_len claiming far more than the buffer holds must not allocate.
        blob = struct.pack("!BB8sH", 1, 0, APP, 0xFFFF) + b"\x00" * 4
        assert parse_assertion(blob) is None

    def test_bad_version_rejected(self, alice, bob):
        a_id, _ = alice
        _, b_node = bob
        blob = bytearray(make_assertion(a_id, APP, audience=b_node,
                                        purpose="p").serialize())
        blob[0] = 2
        assert parse_assertion(bytes(blob)) is None

    def test_verify_survives_garbage(self, bob):
        b_id, b_node = bob
        for _ in range(200):
            assert _verify(os.urandom(64), b_id, audience=b_node) is None


class TestMutualLogin:
    """The three-message login: both sides prove liveness on a nonce the other
    chose, and both end up on the same session id."""

    def _pair(self, alice, bob):
        a_id, a_node = alice
        b_id, b_node = bob
        return (AppAuth(a_id, APP, a_node), AppAuth(b_id, APP, b_node),
                a_node, b_node)

    def test_full_handshake(self, alice, bob):
        a_auth, b_auth, a_node, b_node = self._pair(alice, bob)
        hello = a_auth.start_login(b_node)
        challenge = b_auth.answer_login(a_node, hello)
        assert challenge is not None
        prove, a_session = a_auth.complete_login(b_node, challenge)
        b_session = b_auth.accept_login(a_node, prove)
        assert b_session is not None
        assert a_session.sid == b_session.sid       # same session, both ends
        assert a_session.peer == b_node
        assert b_session.peer == a_node
        assert a_auth.session(a_session.sid) is not None

    def test_replayed_challenge_fails(self, alice, bob):
        a_auth, b_auth, a_node, b_node = self._pair(alice, bob)
        hello = a_auth.start_login(b_node)
        challenge = b_auth.answer_login(a_node, hello)
        assert a_auth.complete_login(b_node, challenge) is not None
        # The pending HELLO is consumed; the same challenge is now worthless.
        assert a_auth.complete_login(b_node, challenge) is None

    def test_third_party_cannot_answer(self, alice, bob):
        """A proof signed by C does not complete A's login to B."""
        a_auth, _b_auth, _a_node, b_node = self._pair(alice, bob)
        mallory_identity = CryptoIdentity()
        mallory_node = NodeID.from_public_key(mallory_identity.dsa_public_key)
        m_auth = AppAuth(mallory_identity, APP, mallory_node)
        hello = a_auth.start_login(b_node)
        forged = m_auth.answer_login(NodeID.from_public_key(
            _b_auth._identity.dsa_public_key), hello)
        assert a_auth.complete_login(b_node, forged) is None

    def test_garbage_frames_rejected(self, alice, bob):
        a_auth, b_auth, a_node, b_node = self._pair(alice, bob)
        a_auth.start_login(b_node)
        for _ in range(100):
            assert b_auth.answer_login(a_node, os.urandom(20)) is None
            assert a_auth.complete_login(b_node, os.urandom(40)) is None
            assert b_auth.accept_login(a_node, os.urandom(40)) is None

    def test_login_assertions_are_scoped_to_login(self, alice, bob):
        """The login proof must not be reusable as an authorisation for some
        other purpose in the same app."""
        a_auth, b_auth, a_node, b_node = self._pair(alice, bob)
        hello = a_auth.start_login(b_node)
        challenge = b_auth.answer_login(a_node, hello)
        proof = challenge[1 + NONCE_LEN:]
        assert a_auth.verify(proof, purpose="fleet.shell") is None

    def test_session_table_bounded(self, alice, bob):
        a_id, a_node = alice
        auth = AppAuth(a_id, APP, a_node, max_sessions=4)
        for i in range(20):
            auth._store_session(bytes([i]) * 16, _principal(a_node, a_id))
        assert len(auth) <= 4

    def test_expired_session_not_returned(self, alice):
        a_id, a_node = alice
        auth = AppAuth(a_id, APP, a_node, session_ttl=-1.0)
        session = auth._store_session(b"\x01" * 16, _principal(a_node, a_id))
        assert auth.session(session.sid) is None


def _principal(node, identity):
    from src.app_auth import Principal
    return Principal(node, identity.dsa_public_key, APP, PURPOSE_LOGIN,
                     b"\x00" * CTX_LEN, int(time.time()), int(time.time()) + 60)


class TestNonceIsClaimedAfterTheSignature:
    """Everything ahead of the signature is structural — an attacker copies the
    app id, the audience, the purpose and the ctx off a legitimate assertion and
    picks a fresh timestamp. Claiming the nonce there let unsigned rubbish evict
    live entries from a bounded cache, which reopens the replay window."""

    def test_a_badly_signed_assertion_burns_nothing(self):
        idn = CryptoIdentity()
        app = builtin_id("chat")
        audience = NodeID(os.urandom(20))
        nonces = NonceCache()

        blob = make_assertion(idn, app, audience=audience,
                              purpose="p", ttl=60).serialize()
        # Same fields, signature replaced with rubbish.
        forged = bytearray(blob)
        forged[-1] ^= 0xFF
        assert verify_assertion(bytes(forged), idn.verify, app_id=app,
                                audience=audience, nonces=nonces) is None
        assert len(nonces) == 0, "a forged assertion consumed a cache slot"

        # …and the genuine one still works afterwards.
        assert verify_assertion(blob, idn.verify, app_id=app,
                                audience=audience, nonces=nonces) is not None

    def test_the_genuine_assertion_is_still_single_use(self):
        idn = CryptoIdentity()
        app = builtin_id("chat")
        audience = NodeID(os.urandom(20))
        nonces = NonceCache()
        blob = make_assertion(idn, app, audience=audience,
                              purpose="p", ttl=60).serialize()
        assert verify_assertion(blob, idn.verify, app_id=app,
                                audience=audience, nonces=nonces) is not None
        assert verify_assertion(blob, idn.verify, app_id=app,
                                audience=audience, nonces=nonces) is None
