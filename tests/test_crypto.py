import os
import pytest
from src.crypto import CryptoIdentity, SessionKey, CryptoError
from src.packet import Packet


SRC     = bytes(range(20))
DST     = bytes(range(20, 40))
NONCE   = bytes(range(12))
GCM_TAG = bytes(range(16))


def make_packet(payload: bytes = b"hello") -> Packet:
    return Packet(
        version=1, type=0x01, ttl=64,
        src_id=SRC, dst_id=DST, msg_id=0,
        nonce=NONCE, gcm_tag=GCM_TAG,
        payload=payload,
    )


class TestCryptoIdentity:
    def test_dsa_public_key_is_bytes(self):
        identity = CryptoIdentity()
        assert isinstance(identity.dsa_public_key, bytes)
        assert len(identity.dsa_public_key) > 0

    def test_sign_and_verify(self):
        identity = CryptoIdentity()
        message = b"hello mesh"
        sig = identity.sign(message)
        assert identity.verify(message, sig, identity.dsa_public_key)

    def test_verify_wrong_message_fails(self):
        identity = CryptoIdentity()
        sig = identity.sign(b"correct message")
        assert not identity.verify(b"wrong message", sig, identity.dsa_public_key)

    def test_verify_wrong_key_fails(self):
        identity1 = CryptoIdentity()
        identity2 = CryptoIdentity()
        sig = identity1.sign(b"message")
        assert not identity1.verify(b"message", sig, identity2.dsa_public_key)

    def test_kem_keypair_returns_two_nonempty_bytes(self):
        identity = CryptoIdentity()
        pub, sec = identity.generate_kem_keypair()
        assert isinstance(pub, bytes) and len(pub) > 0
        assert isinstance(sec, bytes) and len(sec) > 0

    def test_kem_roundtrip(self):
        identity = CryptoIdentity()
        pub, sec = identity.generate_kem_keypair()
        ciphertext, shared_secret_alice = identity.kem_encapsulate(pub)
        shared_secret_bob = identity.kem_decapsulate(ciphertext, sec)
        assert shared_secret_alice == shared_secret_bob

    def test_two_identities_different_keys(self):
        i1 = CryptoIdentity()
        i2 = CryptoIdentity()
        assert i1.dsa_public_key != i2.dsa_public_key


class TestSessionKey:
    def setup_method(self):
        self.key = SessionKey(os.urandom(32))
        self.nonce = os.urandom(12)
        self.aad = b"test-aad"

    def test_encrypt_returns_ciphertext_and_tag(self):
        ciphertext, tag = self.key.encrypt(b"hello", self.nonce, self.aad)
        assert isinstance(ciphertext, bytes)
        assert len(tag) == 16

    def test_encrypt_decrypt_roundtrip(self):
        plaintext = b"secret message"
        ciphertext, tag = self.key.encrypt(plaintext, self.nonce, self.aad)
        result = self.key.decrypt(ciphertext, self.nonce, tag, self.aad)
        assert result == plaintext

    def test_decrypt_wrong_tag_raises(self):
        ciphertext, tag = self.key.encrypt(b"hello", self.nonce, self.aad)
        bad_tag = bytes(16)
        with pytest.raises(CryptoError):
            self.key.decrypt(ciphertext, self.nonce, bad_tag, self.aad)

    def test_decrypt_wrong_aad_raises(self):
        ciphertext, tag = self.key.encrypt(b"hello", self.nonce, self.aad)
        with pytest.raises(CryptoError):
            self.key.decrypt(ciphertext, self.nonce, tag, b"wrong-aad")

    def test_same_secret_same_key(self):
        secret = os.urandom(32)
        k1 = SessionKey(secret)
        k2 = SessionKey(secret)
        nonce = os.urandom(12)
        ciphertext, tag = k1.encrypt(b"hello", nonce, b"aad")
        assert k2.decrypt(ciphertext, nonce, tag, b"aad") == b"hello"

    def test_encrypt_empty_payload(self):
        ciphertext, tag = self.key.encrypt(b"", self.nonce, self.aad)
        assert self.key.decrypt(ciphertext, self.nonce, tag, self.aad) == b""


class TestPacketAad:
    def test_aad_is_bytes(self):
        p = make_packet()
        assert isinstance(p.aad(), bytes)

    def test_aad_excludes_ttl(self):
        p1 = Packet(version=1, type=0x01, ttl=10, src_id=SRC, dst_id=DST,
                    msg_id=0, nonce=NONCE, gcm_tag=GCM_TAG, payload=b"")
        p2 = Packet(version=1, type=0x01, ttl=64, src_id=SRC, dst_id=DST,
                    msg_id=0, nonce=NONCE, gcm_tag=GCM_TAG, payload=b"")
        assert p1.aad() == p2.aad()

    def test_aad_changes_with_src_id(self):
        p1 = make_packet()
        p2 = Packet(version=1, type=0x01, ttl=64, src_id=bytes(range(1, 21)),
                    dst_id=DST, msg_id=0, nonce=NONCE, gcm_tag=GCM_TAG, payload=b"")
        assert p1.aad() != p2.aad()


class TestIdentityOnDisk:
    """The private key *is* the node's identity on the mesh: on disk it must be
    readable only by the account running the node."""

    def test_saved_identity_is_owner_only(self, tmp_path):
        path = str(tmp_path / "node.key")
        CryptoIdentity().save(path)
        assert (os.stat(path).st_mode & 0o777) == 0o600

    def test_a_permissive_file_from_an_older_version_is_tightened(self, tmp_path):
        path = str(tmp_path / "node.key")
        identity = CryptoIdentity()
        identity.save(path)
        os.chmod(path, 0o644)
        identity.save(path)
        assert (os.stat(path).st_mode & 0o777) == 0o600

    def test_the_umask_cannot_loosen_it(self, tmp_path):
        path = str(tmp_path / "node.key")
        previous = os.umask(0)
        try:
            CryptoIdentity().save(path)
        finally:
            os.umask(previous)
        assert (os.stat(path).st_mode & 0o777) == 0o600

    def test_it_still_round_trips(self, tmp_path):
        path = str(tmp_path / "node.key")
        identity = CryptoIdentity()
        identity.save(path)
        assert CryptoIdentity.load(path).dsa_public_key == identity.dsa_public_key

    def test_no_temporary_file_is_left_behind(self, tmp_path):
        path = str(tmp_path / "node.key")
        CryptoIdentity().save(path)
        assert not os.path.exists(path + ".tmp")


class TestIdentityLoad:
    """The node's private key *is* its identity on the mesh: its certificates,
    its memberships, its place in every peer's routing table. Losing it is not
    recoverable, and the caller writes back whatever `load` returns.

    Named apart from ``TestIdentityOnDisk`` above deliberately: this class was
    added carrying that same name, and a second class of the same name does not
    fail — it *replaces* the first in the module namespace, so pytest never sees
    it. Five permission tests, including the two that guard 0600 on the key
    file, silently stopped running and the suite stayed green throughout."""

    def test_a_missing_file_makes_a_new_identity(self, tmp_path):
        path = str(tmp_path / "node.key")
        identity = CryptoIdentity.load(path)
        assert identity.dsa_public_key

    def test_a_truncated_file_is_refused_not_replaced(self, tmp_path):
        path = tmp_path / "node.key"
        CryptoIdentity().save(str(path))
        original = path.read_bytes()
        path.write_bytes(original[:len(original) // 2])
        with pytest.raises(CryptoError):
            CryptoIdentity.load(str(path))
        # …and the file is still there, untouched.
        assert path.read_bytes() == original[:len(original) // 2]

    def test_garbage_is_refused(self, tmp_path):
        path = tmp_path / "node.key"
        path.write_bytes(b"not an identity")
        with pytest.raises(CryptoError):
            CryptoIdentity.load(str(path))

    def test_a_mismatched_pair_is_refused(self, tmp_path):
        """Nothing checked that the stored public half belonged to the stored
        secret, so a mismatched file produced a node whose signatures nobody
        could verify — with no diagnostic anywhere."""
        import struct
        mine, theirs = CryptoIdentity(), CryptoIdentity()
        secret = mine._signer.export_secret_key()
        pub = theirs.dsa_public_key                      # somebody else's
        path = tmp_path / "node.key"
        path.write_bytes(struct.pack("!HH", len(pub), len(secret)) + pub + secret)
        with pytest.raises(CryptoError):
            CryptoIdentity.load(str(path))

    def test_a_good_file_round_trips(self, tmp_path):
        path = str(tmp_path / "node.key")
        original = CryptoIdentity()
        original.save(path)
        again = CryptoIdentity.load(path)
        assert again.dsa_public_key == original.dsa_public_key


class TestLiboqsLifecycle:
    """liboqs-python frees nothing on garbage collection.

    `Signature` and `KeyEncapsulation` offer `free()` and a context manager, and
    define no `__del__` at all — so a context dropped without one of those is
    native memory gone for the life of the process. Measured against liboqs
    0.16.0: 85 bytes per abandoned `Signature`, 268 per abandoned KEM keypair.
    The KEM one runs once per handshake, and a peer chooses how often to ask for
    a handshake, so "small" is not the same as "bounded". `free()` is also what
    cleanses the secret key buffer, which is the reason the library offers it.
    """

    def test_a_kem_keypair_hands_its_context_back(self, monkeypatch):
        import src.crypto as crypto
        real, events = crypto.oqs.KeyEncapsulation, []

        class Watched:
            def __init__(self, *args, **kwargs):
                self._inner = real(*args, **kwargs)

            def __enter__(self):
                events.append("enter")
                self._inner.__enter__()
                return self

            def __exit__(self, *exc):
                events.append("exit")
                return self._inner.__exit__(*exc)

            def generate_keypair(self):
                return self._inner.generate_keypair()

            def export_secret_key(self):
                return self._inner.export_secret_key()

        monkeypatch.setattr(crypto.oqs, "KeyEncapsulation", Watched)
        public, secret = CryptoIdentity().generate_kem_keypair()
        assert public and secret
        assert events == ["enter", "exit"]

    def test_the_verifier_pool_stays_bounded_under_more_threads(self):
        """More concurrent verifiers than the pool holds: the extra ones are
        freed on the way back, not stacked up."""
        import threading
        from src.crypto import (verify_signature, _verifier_pool,
                                _VERIFIER_POOL_MAX)
        identity = CryptoIdentity()
        message = b"a message worth signing"
        signature = identity.sign(message)
        threads_wanted = _VERIFIER_POOL_MAX * 2
        start = threading.Barrier(threads_wanted)
        failures = []

        def work():
            start.wait()
            for _ in range(10):
                if not verify_signature(message, signature,
                                        identity.dsa_public_key):
                    failures.append(True)

        threads = [threading.Thread(target=work) for _ in range(threads_wanted)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        assert not failures
        assert len(_verifier_pool) <= _VERIFIER_POOL_MAX

    def test_a_refused_identity_does_not_strand_its_signer(self, tmp_path):
        """`load` builds the signer before it can know the pair is wrong, so the
        failure path is one that has something to give back."""
        path = tmp_path / "node.key"
        path.write_bytes(b"not an identity at all")
        with pytest.raises(CryptoError):
            CryptoIdentity.load(str(path))
