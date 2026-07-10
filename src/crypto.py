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
        with oqs.Signature(DSA_ALG) as verifier:
            return verifier.verify(message, signature, public_key)

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
        """Persiste la paire de clés DSA sur disque (format binaire brut)."""
        import struct, os
        pub = self._dsa_public
        secret = self._signer.export_secret_key()
        data = struct.pack('!HH', len(pub), len(secret)) + pub + secret
        tmp = path + ".tmp"
        with open(tmp, 'wb') as f:
            f.write(data)
        os.replace(tmp, path)

    @classmethod
    def load(cls, path: str) -> 'CryptoIdentity':
        """Charge une identité depuis le disque. Crée une nouvelle si introuvable."""
        import struct
        identity = cls.__new__(cls)
        try:
            with open(path, 'rb') as f:
                data = f.read()
            if len(data) < 4:
                raise ValueError("identity file too short")
            pub_len, secret_len = struct.unpack_from('!HH', data, 0)
            if 4 + pub_len + secret_len > len(data):
                raise ValueError("identity file truncated")
            pub    = data[4:4 + pub_len]
            secret = data[4 + pub_len:4 + pub_len + secret_len]
            identity._signer = oqs.Signature(DSA_ALG, secret)
            identity._dsa_public = pub
        except (FileNotFoundError, Exception):
            identity._signer = oqs.Signature(DSA_ALG)
            identity._dsa_public = identity._signer.generate_keypair()
        return identity

    def self_signed_cert(self) -> Certificate:
        """Émet un certificat auto-signé (identité racine)."""
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
        """Émet un certificat pour un sujet, signé par cette identité."""
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

    def __init__(self, shared_secret: bytes) -> None:
        self._key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=_HKDF_INFO,
        ).derive(shared_secret)

    @classmethod
    def from_key(cls, key: bytes) -> "SessionKey":
        """Rebuild a session from its already-derived 32-byte key (for
        persistence). Bypasses HKDF — the key is stored, not the raw secret."""
        if len(key) != 32:
            raise ValueError("session key must be 32 bytes")
        obj = cls.__new__(cls)
        obj._key = key
        return obj

    @property
    def key_bytes(self) -> bytes:
        return self._key

    def encrypt(self, plaintext: bytes, nonce: bytes, aad: bytes) -> tuple[bytes, bytes]:
        raw = AESGCM(self._key).encrypt(nonce, plaintext, aad)
        return raw[:-16], raw[-16:]

    def decrypt(self, ciphertext: bytes, nonce: bytes, gcm_tag: bytes, aad: bytes) -> bytes:
        try:
            return AESGCM(self._key).decrypt(nonce, ciphertext + gcm_tag, aad)
        except Exception as e:
            raise CryptoError("decryption failed") from e
