import os
import threading
import time
import oqs
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from .node_id import NodeID
from .cert import Certificate

KEM_ALG = "ML-KEM-768"
DSA_ALG = "ML-DSA-65"
_HKDF_INFO = b"nmesh-session-key"


class CryptoError(Exception):
    pass


# One verifier per thread, reused. Constructing an `oqs.Signature` allocates
# liboqs state, and a verification happens per certificate parsed, per pseudo
# claim, per release descriptor, per app-auth assertion — decoding one
# FOUND_NODE with a full pool is 32 of them. The context holds no per-call
# state for a *public-key* verification, but it is not documented as
# re-entrant, so it is thread-local rather than shared.
_verifiers = threading.local()


def verify_signature(message: bytes, signature: bytes, public_key: bytes) -> bool:
    """Verify an ML-DSA signature, reusing this thread's verifier."""
    verifier = getattr(_verifiers, "dsa", None)
    if verifier is None:
        verifier = oqs.Signature(DSA_ALG)
        _verifiers.dsa = verifier
    return verifier.verify(message, signature, public_key)


class CryptoIdentity:

    def __init__(self) -> None:
        self._signer = oqs.Signature(DSA_ALG)
        self._dsa_public: bytes = self._signer.generate_keypair()

    @property
    def dsa_public_key(self) -> bytes:
        return self._dsa_public

    def sign(self, message: bytes) -> bytes:
        return self._signer.sign(message)

    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        return verify_signature(message, signature, public_key)

    def generate_kem_keypair(self) -> tuple[bytes, bytes]:
        kem = oqs.KeyEncapsulation(KEM_ALG)
        public_key = kem.generate_keypair()
        return public_key, kem.export_secret_key()

    def kem_encapsulate(self, their_public_key: bytes) -> tuple[bytes, bytes]:
        with oqs.KeyEncapsulation(KEM_ALG) as kem:
            ciphertext, shared_secret = kem.encap_secret(their_public_key)
        return ciphertext, shared_secret

    def kem_decapsulate(self, ciphertext: bytes, secret_key: bytes) -> bytes:
        with oqs.KeyEncapsulation(KEM_ALG, secret_key) as kem:
            return kem.decap_secret(ciphertext)

    def derive_secret(self, info: bytes, length: int = 32) -> bytes:
        """Derive an independent symmetric subkey from the long-term identity
        secret (HKDF). Used to encrypt at-rest state under the same trust
        boundary as the identity file. One-way: never exposes the signing key."""
        return HKDF(
            algorithm=hashes.SHA256(),
            length=length,
            salt=None,
            info=info,
        ).derive(self._signer.export_secret_key())

    def save(self, path: str) -> None:
        """Persist the DSA key pair on disk (raw binary format)."""
        import struct, os
        pub = self._dsa_public
        secret = self._signer.export_secret_key()
        data = struct.pack('!HH', len(pub), len(secret)) + pub + secret
        tmp = path + ".tmp"
        # The node's private key *is* its identity on the mesh. It is created
        # 0600 at open time — not by a chmod afterwards, which would leave a
        # window where anyone on the machine could read it.
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(fd, 'wb') as f:
                f.write(data)
        except BaseException:
            os.unlink(tmp)
            raise
        # A file already present in 0644 (an identity written by an earlier
        # version) keeps its mode across the replace: fix it.
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)

    @classmethod
    def load(cls, path: str) -> 'CryptoIdentity':
        """Load an identity from disk, or make one if there is none.

        A file that is **there and unreadable** raises. It used to generate a
        fresh key pair instead — and the caller writes what it gets straight
        back over the file, so one truncated write, one bad sector, one
        half-restored backup destroyed the node's identity permanently: its
        certificates, its memberships, its place in every peer's routing table,
        all gone, and the symptom looks like a network fault. It is also a
        destruction primitive for anyone who can touch the state directory.

        The pair is checked against itself before it is trusted. Nothing
        verified that the stored public half belonged to the stored secret, so a
        mismatched file produced a node whose signatures nobody could verify and
        whose id nobody would accept — with no diagnostic anywhere."""
        import struct
        identity = cls.__new__(cls)
        if not os.path.exists(path):
            identity._signer = oqs.Signature(DSA_ALG)
            identity._dsa_public = identity._signer.generate_keypair()
            return identity
        try:
            with open(path, 'rb') as f:
                data = f.read()
            if len(data) < 4:
                raise ValueError("identity file too short")
            pub_len, secret_len = struct.unpack_from('!HH', data, 0)
            if not pub_len or not secret_len:
                raise ValueError("identity file has an empty key")
            if 4 + pub_len + secret_len > len(data):
                raise ValueError("identity file truncated")
            pub    = data[4:4 + pub_len]
            secret = data[4 + pub_len:4 + pub_len + secret_len]
            identity._signer = oqs.Signature(DSA_ALG, secret)
            identity._dsa_public = pub
            probe = identity.sign(b"nmesh-identity-self-test")
            if not identity.verify(b"nmesh-identity-self-test", probe, pub):
                raise ValueError("the stored public key does not match the secret")
        except Exception as exc:
            raise CryptoError(
                f"{path} exists but is not a usable identity ({exc}). Refusing "
                f"to replace it — move it aside deliberately to start fresh."
            ) from None
        return identity

    def self_signed_cert(self) -> Certificate:
        """Issue a self-signed certificate (a root identity)."""
        own_id = NodeID.from_public_key(self._dsa_public)
        now = int(time.time())
        cert = Certificate(own_id, self._dsa_public,
                           own_id, self._dsa_public,
                           now, 0, b"")
        sig = self._signer.sign(cert.signed_body())
        return Certificate(own_id, self._dsa_public,
                           own_id, self._dsa_public,
                           now, 0, sig)

    def issue_cert(self, subject_id: NodeID, subject_pub: bytes,
                   ttl_seconds: int = 365 * 86400) -> Certificate:
        """Issue a certificate for a subject, signed by this identity."""
        own_id = NodeID.from_public_key(self._dsa_public)
        now = int(time.time())
        expires = now + ttl_seconds
        cert = Certificate(subject_id, subject_pub,
                           own_id, self._dsa_public,
                           now, expires, b"")
        sig = self._signer.sign(cert.signed_body())
        return Certificate(subject_id, subject_pub,
                           own_id, self._dsa_public,
                           now, expires, sig)


class SessionKey:
    """An AES-256-GCM key, and the cipher built from it.

    The cipher is built **once**. It used to be constructed per call, so the key
    schedule was rebuilt for every packet in and out — on a link whose key is
    fixed for its whole life."""

    __slots__ = ("_key", "_aead")

    def __init__(self, shared_secret: bytes) -> None:
        self._key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=_HKDF_INFO,
        ).derive(shared_secret)
        self._aead = AESGCM(self._key)

    @classmethod
    def from_key(cls, key: bytes) -> "SessionKey":
        """Rebuild a session from its already-derived 32-byte key (for
        persistence). Bypasses HKDF — the key is stored, not the raw secret."""
        if len(key) != 32:
            raise ValueError("session key must be 32 bytes")
        obj = cls.__new__(cls)
        obj._key = key
        obj._aead = AESGCM(key)
        return obj

    @property
    def key_bytes(self) -> bytes:
        return self._key

    def encrypt(self, plaintext: bytes, nonce: bytes, aad: bytes) -> tuple[bytes, bytes]:
        raw = self._aead.encrypt(nonce, plaintext, aad)
        return raw[:-16], raw[-16:]

    def decrypt(self, ciphertext: bytes, nonce: bytes, gcm_tag: bytes, aad: bytes) -> bytes:
        try:
            return self._aead.decrypt(nonce, ciphertext + gcm_tag, aad)
        except Exception as e:
            raise CryptoError("decryption failed") from e
