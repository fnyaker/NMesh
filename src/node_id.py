import hashlib
import os


class NodeID:

    def __init__(self, raw: bytes) -> None:
        if len(raw) != 20:
            raise ValueError("NodeID must be 20 bytes")
        self._raw = raw

    @classmethod
    def generate(cls) -> 'NodeID':
        return cls(os.urandom(20))

    @classmethod
    def from_public_key(cls, dsa_pub: bytes) -> 'NodeID':
        return cls(hashlib.sha256(dsa_pub).digest()[:20])

    @classmethod
    def from_hex(cls, hex_str: str) -> 'NodeID':
        return cls(bytes.fromhex(hex_str))

    def distance(self, other: 'NodeID') -> int:
        result = 0
        for a, b in zip(self._raw, other._raw):
            result = (result << 8) | (a ^ b)
        return result

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, NodeID):
            return NotImplemented
        return self._raw == other._raw

    def __hash__(self) -> int:
        return hash(self._raw)

    def __repr__(self) -> str:
        return f"NodeID({self._raw.hex()[:8]}…)"

    @property
    def raw(self) -> bytes:
        return self._raw
