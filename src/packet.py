from __future__ import annotations
import hashlib
import os
import struct
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .crypto import SessionKey

HEADER_FORMAT = '!BBB20s20sQ12s16s'   # msg_id is now a uint64 (8 bytes)
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)
MSG_ID_FORMAT = '!BB20s20s12s16s'

class PacketError(Exception):
    pass


# Every packet carries twelve random bytes, and `os.urandom` is a system call.
# One per packet was invisible while a link was probed every twenty seconds; it
# is a syscall ten times a second per bundled link now, on both sides, and the
# node makes one for every packet it sends besides. So the entropy is drawn in
# blocks and handed out twelve bytes at a time.
#
# **Identical unpredictability.** A slice of a CSPRNG draw is CSPRNG output —
# this buys a syscall, never a shortcut — and the nonce has to stay
# unpredictable: it feeds `msg_id`, and a guessable `msg_id` is a way to seed a
# relay's dedup window so a *later* legitimate packet is dropped as a replay.
#
# The buffer is dropped in the child after a fork, or both sides of it would
# hand out the same bytes to two processes that each believe them fresh.
_NONCE_BLOCK = 4096
_NONCE_SIZE = 12
_EMPTY_TAG = bytes(16)
_nonce_pool = b""
_nonce_at = 0


def _nonce() -> bytes:
    global _nonce_pool, _nonce_at
    if _nonce_at + _NONCE_SIZE > len(_nonce_pool):
        _nonce_pool, _nonce_at = os.urandom(_NONCE_BLOCK), 0
    out = _nonce_pool[_nonce_at:_nonce_at + _NONCE_SIZE]
    _nonce_at += _NONCE_SIZE
    return out


def _reset_nonce_pool() -> None:
    global _nonce_pool, _nonce_at
    _nonce_pool, _nonce_at = b"", 0


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_reset_nonce_pool)

class Packet:
    def __init__(self, version: int, type: int, ttl: int, src_id: bytes,
                 dst_id: bytes, msg_id: int, nonce: bytes, gcm_tag: bytes,
                 payload: bytes) -> None:
        self.__version = version
        self.__type = type
        self.__ttl = ttl
        if len(src_id) != 20:
            raise PacketError("src_id must be 20 bytes")
        self.__src_id = src_id
        if len(dst_id) != 20:
            raise PacketError("dst_id must be 20 bytes")
        self.__dst_id = dst_id
        self.__msg_id = msg_id
        if len(nonce) != 12:
            raise PacketError("nonce must be 12 bytes")
        self.__nonce = nonce
        if len(gcm_tag) != 16:
            raise PacketError("gcm_tag must be 16 bytes")
        self.__gcm_tag = gcm_tag
        if len(payload) > 60000:
            raise PacketError("payload too big")
        self.__payload = payload

    def pack(self) -> bytes:
        header = struct.pack(
            HEADER_FORMAT,
            self.__version,
            self.__type,
            self.__ttl,
            self.__src_id,
            self.__dst_id,
            self.__msg_id,
            self.__nonce,
            self.__gcm_tag,
        )
        return header + self.__payload

    @classmethod
    def unpack(cls, data: bytes) -> 'Packet':
        if len(data) < HEADER_SIZE:
            raise PacketError("data too short")
        version, type_, ttl, src_id, dst_id, msg_id, nonce, gcm_tag = struct.unpack(
            HEADER_FORMAT, data[:HEADER_SIZE]
        )
        payload = data[HEADER_SIZE:]
        return cls(version, type_, ttl, src_id, dst_id, msg_id, nonce, gcm_tag, payload)

    @staticmethod
    def msg_id_over(version: int, type: int, src_id: bytes, dst_id: bytes,
                    nonce: bytes, gcm_tag: bytes, payload: bytes) -> int:
        """The id of a packet with these fields, without needing the packet.

        `create` used to build one `Packet` purely to ask it for its own id and
        then build a second one to keep — two constructions, and eight length
        checks, for one packet. Neither the id nor the checks changed; only the
        instance nobody kept."""
        data = struct.pack(MSG_ID_FORMAT, version, type, src_id, dst_id,
                           nonce, gcm_tag) + payload
        return int.from_bytes(hashlib.sha256(data).digest()[:8], 'big')

    def compute_msg_id(self) -> int:
        return self.msg_id_over(self.__version, self.__type, self.__src_id,
                                self.__dst_id, self.__nonce, self.__gcm_tag,
                                self.__payload)

    @classmethod
    def create(cls, type: int, src_id: bytes, dst_id: bytes,
               payload: bytes, ttl: int = 64, version: int = 1) -> 'Packet':
        nonce = _nonce()
        gcm_tag = _EMPTY_TAG
        return cls(version, type, ttl, src_id, dst_id,
                   cls.msg_id_over(version, type, src_id, dst_id, nonce,
                                   gcm_tag, payload),
                   nonce, gcm_tag, payload)

    @property
    def type(self) -> int:
        return self.__type

    @property
    def src_id(self) -> bytes:
        return self.__src_id

    @property
    def dst_id(self) -> bytes:
        return self.__dst_id

    @property
    def ttl(self) -> int:
        return self.__ttl

    @property
    def payload(self) -> bytes:
        return self.__payload

    @property
    def msg_id(self) -> int:
        return self.__msg_id

    @property
    def nonce(self) -> bytes:
        return self.__nonce

    def aad(self) -> bytes:
        return struct.pack(
            '!BB20s20s12s',
            self.__version,
            self.__type,
            self.__src_id,
            self.__dst_id,
            self.__nonce,
        )

    @classmethod
    def create_encrypted(cls, type: int, src_id: bytes, dst_id: bytes,
                         plaintext: bytes, session: SessionKey,
                         ttl: int = 64, version: int = 1) -> Packet:
        import os
        nonce = os.urandom(12)
        partial_aad = struct.pack('!BB20s20s12s', version, type, src_id, dst_id, nonce)
        ciphertext, gcm_tag = session.encrypt(plaintext, nonce, partial_aad)
        p = cls(version, type, ttl, src_id, dst_id, 0, nonce, gcm_tag, ciphertext)
        return cls(version, type, ttl, src_id, dst_id, p.compute_msg_id(), nonce, gcm_tag, ciphertext)

    def decrypt_payload(self, session: SessionKey) -> bytes:
        return session.decrypt(self.__payload, self.__nonce, self.__gcm_tag, self.aad())

    def with_decremented_ttl(self) -> 'Packet':
        return self.with_ttl(self.__ttl - 1)

    def with_ttl(self, ttl: int) -> 'Packet':
        """The same packet with a different hop budget.

        Only the TTL changes, and the TTL is outside both the AAD and the
        `msg_id` pre-image — so the packet stays exactly as authentic as it
        was, and dedup still recognises it. That is the whole reason those two
        exclusions exist."""
        return Packet(self.__version, self.__type, ttl,
                      self.__src_id, self.__dst_id, self.__msg_id,
                      self.__nonce, self.__gcm_tag, self.__payload)
        
    




