from __future__ import annotations
import struct
import zlib
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .crypto import SessionKey

HEADER_FORMAT = '!BBB20s20sI12s16s'
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)
MSG_ID_FORMAT = '!BB20s20s12s16s'

class PacketError(Exception):
    pass

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

    def compute_msg_id(self) -> int:
        data = struct.pack(
            MSG_ID_FORMAT,
            self.__version,
            self.__type,
            self.__src_id,
            self.__dst_id,
            self.__nonce,
            self.__gcm_tag,
        ) + self.__payload
        return zlib.crc32(data) & 0xFFFFFFFF

    @classmethod
    def create(cls, type: int, src_id: bytes, dst_id: bytes,
               payload: bytes, ttl: int = 64, version: int = 1) -> 'Packet':
        import os
        nonce = os.urandom(12)
        gcm_tag = bytes(16)
        p = cls(version, type, ttl, src_id, dst_id, 0, nonce, gcm_tag, payload)
        return cls(version, type, ttl, src_id, dst_id, p.compute_msg_id(), nonce, gcm_tag, payload)

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
        return Packet(self.__version, self.__type, self.__ttl - 1,
                      self.__src_id, self.__dst_id, self.__msg_id,
                      self.__nonce, self.__gcm_tag, self.__payload)
        
    




