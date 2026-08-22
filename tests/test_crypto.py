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
    """La clé privée *est* l'identité du nœud sur le mesh : sur disque, elle ne
    doit être lisible que par le compte qui fait tourner le nœud."""

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
