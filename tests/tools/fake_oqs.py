"""A stand-in for `oqs` with the sizes of ML-DSA-65 and ML-KEM-768 and none of
their cost, so a simulation measures routing and not lattice arithmetic.

    from tests.tools import fake_oqs; fake_oqs.install()      # before `import src`

Nothing here is secure: a signature is a hash anyone can compute from the public
key. It exists to carry the right number of bytes through the right code paths.
"""
import hashlib
import os
import sys
import types

_DSA_PK, _DSA_SK, _DSA_SIG = 1952, 4032, 3309
_KEM_PK, _KEM_SK, _KEM_CT, _KEM_SS = 1184, 2400, 1088, 32


def _h(data: bytes, size: int = 32) -> bytes:
    return hashlib.blake2b(data, digest_size=size).digest()


def _pad(data: bytes, size: int) -> bytes:
    return data + b"\0" * (size - len(data))


class Signature:
    def __init__(self, alg, secret_key=None):
        self._sk = bytes(secret_key) if secret_key is not None else None

    @staticmethod
    def _pk(sk: bytes) -> bytes:
        return _pad(_h(sk[:32], 64), _DSA_PK)

    def generate_keypair(self) -> bytes:
        self._sk = _pad(os.urandom(32), _DSA_SK)
        return self._pk(self._sk)

    def export_secret_key(self) -> bytes:
        return self._sk

    def sign(self, message: bytes) -> bytes:
        return _pad(_h(self._pk(self._sk) + bytes(message), 64), _DSA_SIG)

    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        return len(signature) == _DSA_SIG and bytes(signature[:64]) == _h(bytes(public_key) + bytes(message), 64)

    def free(self):
        pass


class KeyEncapsulation:
    def __init__(self, alg, secret_key=None):
        self._sk = bytes(secret_key) if secret_key is not None else None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    @staticmethod
    def _pk(sk: bytes) -> bytes:
        return _pad(_h(sk[:32], 64), _KEM_PK)

    def generate_keypair(self) -> bytes:
        self._sk = _pad(os.urandom(32), _KEM_SK)
        return self._pk(self._sk)

    def export_secret_key(self) -> bytes:
        return self._sk

    def encap_secret(self, public_key: bytes):
        secret = os.urandom(_KEM_SS)
        mask = _h(bytes(public_key), _KEM_SS)
        return _pad(bytes(a ^ b for a, b in zip(secret, mask)), _KEM_CT), secret

    def decap_secret(self, ciphertext: bytes) -> bytes:
        mask = _h(self._pk(self._sk), _KEM_SS)
        return bytes(a ^ b for a, b in zip(bytes(ciphertext[:_KEM_SS]), mask))

    def free(self):
        pass


def install() -> None:
    module = types.ModuleType("oqs")
    module.Signature = Signature
    module.KeyEncapsulation = KeyEncapsulation
    sys.modules["oqs"] = module
