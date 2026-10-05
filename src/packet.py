from __future__ import annotations
import hashlib
import os
import struct
import threading
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .crypto import SessionKey

HEADER_FORMAT = '!BBB20s20sQ12s16s'   # msg_id is now a uint64 (8 bytes)
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)
MSG_ID_FORMAT = '!BB20s20s12s16s'

# The two hashes a `msg_id` may be computed with — the same 64-bit commitment to
# the same bytes, so neither is weaker than the other. SHA-256 is the one every
# build has always spoken and the only one a link that agreed nothing may carry.
# BLAKE2b is the one a link carries once both ends announced it
# (`features.BLAKE2B_IDS`): it hashes 60 kB in about half the time of SHA-256 on
# a CPU without SHA instructions, and the hash was over half of what a large
# packet cost a node. See `Docs/Architecture/protocol.md`.
MSG_ID_SHA256 = 0
MSG_ID_BLAKE2B = 1
_BLAKE2B_PERSON = b"nmesh-msg-id"


def _sha256_id(prefix: bytes, payload: bytes) -> int:
    digest = hashlib.sha256(prefix)
    digest.update(payload)
    return int.from_bytes(digest.digest()[:8], 'big')


def _blake2b_id(prefix: bytes, payload: bytes) -> int:
    digest = hashlib.blake2b(prefix, digest_size=8, person=_BLAKE2B_PERSON)
    digest.update(payload)
    return int.from_bytes(digest.digest(), 'big')


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
#
# **Taking a lock, and not because a race was observed.** Every caller today is
# on the event loop — checked — but handing out a slice is a read-modify-write
# on module state, and CPython promises nothing about that. The cost of being
# wrong is not a crash: it is two packets sharing a nonce, therefore a `msg_id`,
# therefore a legitimate packet dropped somewhere down the mesh as a replay,
# silently and unreproducibly. "Nothing calls this off the loop" is exactly the
# kind of invariant nobody re-checks when they add a thread, and this project
# has a file full of what that costs. The lock is still cheaper than the
# `getrandom` syscall it replaced (0.51 us against 0.62), so correctness here
# is not even a trade.
#
# A lock-free version measured twice as fast again — an `itertools.count` per
# pool, whose `__next__` is a single C call — and is **not** taken. Its safety
# rests on that call being atomic, which CPython does not promise and a
# free-threaded build need not provide; that is the same unstated assumption
# the lock exists to remove, wearing a faster suit. A quarter of a microsecond
# on a 2.5 us path is not worth buying it back.
_NONCE_BLOCK = 4096
_NONCE_SIZE = 12
_EMPTY_TAG = bytes(16)
_nonce_lock = threading.Lock()
_nonce_pool = b""
_nonce_at = 0


def _nonce() -> bytes:
    global _nonce_pool, _nonce_at
    with _nonce_lock:
        if _nonce_at + _NONCE_SIZE > len(_nonce_pool):
            _nonce_pool, _nonce_at = os.urandom(_NONCE_BLOCK), 0
        out = _nonce_pool[_nonce_at:_nonce_at + _NONCE_SIZE]
        _nonce_at += _NONCE_SIZE
    return out


def _reset_nonce_pool() -> None:
    """Drop the pool. Called in a forked child, where the lock may also have
    been left held by a thread that does not exist here any more — so it is
    replaced rather than acquired."""
    global _nonce_pool, _nonce_at, _nonce_lock
    _nonce_lock = threading.Lock()
    _nonce_pool, _nonce_at = b"", 0


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_reset_nonce_pool)

class Packet:
    """One mesh packet.

    ``msg_id`` is the header *as one link carries it*: the id of the content
    under the hash that link agreed, rewritten per hop exactly like the TTL and
    outside the AAD for the same reason. ``None`` means no link has carried it
    yet; reading it then gives the SHA-256 id, which every build accepts. The
    id under each hash is computed at most once per packet and travels with its
    TTL-decremented and per-link copies, so a relay that tries five candidates
    hashes once, not five times."""

    def __init__(self, version: int, type: int, ttl: int, src_id: bytes,
                 dst_id: bytes, msg_id: int | None, nonce: bytes, gcm_tag: bytes,
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
        self.__sha256_id: int | None = None
        self.__blake2b_id: int | None = None

    def pack(self) -> bytes:
        header = struct.pack(
            HEADER_FORMAT,
            self.__version,
            self.__type,
            self.__ttl,
            self.__src_id,
            self.__dst_id,
            self.msg_id,
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
                    nonce: bytes, gcm_tag: bytes, payload: bytes,
                    algorithm: int = MSG_ID_SHA256) -> int:
        """The id of a packet with these fields, without needing the packet."""
        prefix = struct.pack(MSG_ID_FORMAT, version, type, src_id, dst_id,
                             nonce, gcm_tag)
        if algorithm == MSG_ID_BLAKE2B:
            return _blake2b_id(prefix, payload)
        return _sha256_id(prefix, payload)

    def id_under(self, algorithm: int) -> int:
        """This packet's id under one hash, computed at most once."""
        if algorithm == MSG_ID_BLAKE2B:
            if self.__blake2b_id is None:
                self.__blake2b_id = self.msg_id_over(
                    self.__version, self.__type, self.__src_id, self.__dst_id,
                    self.__nonce, self.__gcm_tag, self.__payload, MSG_ID_BLAKE2B)
            return self.__blake2b_id
        if self.__sha256_id is None:
            self.__sha256_id = self.msg_id_over(
                self.__version, self.__type, self.__src_id, self.__dst_id,
                self.__nonce, self.__gcm_tag, self.__payload, MSG_ID_SHA256)
        return self.__sha256_id

    def compute_msg_id(self) -> int:
        """The SHA-256 id: the one every build, old or new, accepts."""
        return self.id_under(MSG_ID_SHA256)

    def replay_key(self) -> int | None:
        """What a replay window files this packet under, or ``None`` when the
        header ``msg_id`` does not commit to the content.

        **Either hash is accepted, whatever the link agreed.** The two ends of a
        link learn each other's features at different moments, so a receiver
        that held the sender to the agreement would drop everything sent in the
        gap. Accepting both costs nothing in safety: neither is a secret, both
        bind the same bytes, and anyone could compute either.

        **The key is always the BLAKE2b id, never the header.** One packet can
        reach a node down a link speaking SHA-256 and again down one speaking
        BLAKE2b; filed under the header it would be two packets, and a relay
        holding one link of each kind could replay anything once more. So a
        packet from a SHA-256 link costs both hashes — the price of a mesh that
        is not all on one build yet, and only for as long as it is not."""
        key = self.id_under(MSG_ID_BLAKE2B)
        header = self.msg_id
        if header == key or header == self.id_under(MSG_ID_SHA256):
            return key
        return None

    def for_link(self, algorithm: int) -> 'Packet':
        """This packet as a link carrying ``algorithm`` sends it."""
        msg_id = self.id_under(algorithm)
        if self.__msg_id is None and algorithm == MSG_ID_SHA256:
            self.__msg_id = msg_id          # what `msg_id` would have read
        if msg_id == self.__msg_id:
            return self
        return self._twin(self.__ttl, msg_id)

    def _twin(self, ttl: int, msg_id: int | None) -> 'Packet':
        twin = Packet(self.__version, self.__type, ttl, self.__src_id,
                      self.__dst_id, msg_id, self.__nonce, self.__gcm_tag,
                      self.__payload)
        twin.__sha256_id = self.__sha256_id
        twin.__blake2b_id = self.__blake2b_id
        return twin

    @classmethod
    def create(cls, type: int, src_id: bytes, dst_id: bytes,
               payload: bytes, ttl: int = 64, version: int = 1) -> 'Packet':
        """A new packet. No id yet: which hash it is sent under is the link's
        to say, and hashing it here would be a hash the first link may throw
        away."""
        return cls(version, type, ttl, src_id, dst_id, None, _nonce(),
                   _EMPTY_TAG, payload)

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
        if self.__msg_id is None:
            self.__msg_id = self.id_under(MSG_ID_SHA256)
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
        return cls(version, type, ttl, src_id, dst_id, None, nonce, gcm_tag,
                   ciphertext)

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
        return self._twin(ttl, self.__msg_id)
