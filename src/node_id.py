import hashlib
import os


class NodeID:

    __slots__ = ("_raw", "_int")

    def __init__(self, raw: bytes) -> None:
        if len(raw) != 20:
            raise ValueError("NodeID must be 20 bytes")
        self._raw = raw
        # The id as one 160-bit integer, computed once. `distance` is the sort
        # key of every routing decision — `get_closest`, `_route_candidates`,
        # `kad_lookup`, `_handle_find_node` — so it runs thousands of times per
        # lookup, and it used to be a twenty-iteration Python loop of
        # shift-and-or per call. A NodeID is immutable, so this is free after
        # the first read.
        self._int = int.from_bytes(raw, "big")

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
        return self._int ^ other._int

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
