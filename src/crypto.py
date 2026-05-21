import oqs
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

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


class SessionKey:

    def __init__(self, shared_secret: bytes) -> None:
        self._key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=_HKDF_INFO,
        ).derive(shared_secret)

    def encrypt(self, plaintext: bytes, nonce: bytes, aad: bytes) -> tuple[bytes, bytes]:
        raw = AESGCM(self._key).encrypt(nonce, plaintext, aad)
        return raw[:-16], raw[-16:]

    def decrypt(self, ciphertext: bytes, nonce: bytes, gcm_tag: bytes, aad: bytes) -> bytes:
        try:
            return AESGCM(self._key).decrypt(nonce, ciphertext + gcm_tag, aad)
        except Exception as e:
            raise CryptoError("decryption failed") from e
