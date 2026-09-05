"""
Remembering which packets we have already handled, cheaply and exactly.

``_is_seen`` is asked once per routable packet, so what this costs is paid on
the hot path, and how much it can hold decides how far back the anti-replay
window reaches. It was an ``OrderedDict[int, None]``: exact, correct, and about
a hundred bytes an entry — almost all of it CPython object overhead wrapped
around eight bytes of actual information. That overhead is the reason the window
was capped at ten thousand ids.

A ``msg_id`` is already 64 bits (``Packet.compute_msg_id``), so it fits a flat
table with no boxing at all: one ``bytearray`` of 8-byte slots, open addressing,
linear probing. Sixteen bytes an entry at half load — six times smaller for the
same answers, which is the same memory buying a window six times longer.

**Exact on purpose.** A Bloom filter would be six times smaller again, and this
is not where to spend a false positive. Not because dropping a packet would hurt
— the protocol tolerates that — but because this is the structure anything else
bounded by identity will be modelled on, and a false positive on anything
punitive is an innocent node cut off with no way to tell. Keeping the pattern
exact means nothing downstream has to remember which kind it was looking at.

Expiry is generational, not LRU. Two tables: everything new goes into the young
one, a lookup asks both, and when the young one fills it becomes the old one and
a fresh table takes its place. An id therefore survives between ``capacity`` and
``2 * capacity`` further insertions — the same "roughly the last N" the FIFO
gave, without paying to order them.

**The bucket is seeded.** The obvious index is the id's own low bits, and they
are uniform: it is a SHA-256 truncation. But the attacker chooses the payload
the digest is taken over, so they can grind ids that land in one bucket — a few
thousand hashes each — and turn every lookup into a walk. The index is therefore
derived through a per-process random seed they cannot see. The stored value is
still the whole id, so exactness is untouched; only *where* it lands is
unpredictable.
"""
from __future__ import annotations

import os
import struct

_Q = struct.Struct("!Q")
_SLOT = _Q.size
_MASK64 = 0xFFFFFFFFFFFFFFFF
# Fractional part of the golden ratio, the usual odd multiplier: it is coprime
# with 2**64, so multiplying is a bijection and no id is mapped away.
_MIX = 0x9E3779B97F4A7C15


class SeenSet:
    """A bounded, exact set of 64-bit ids. ``add`` says whether it was new."""

    __slots__ = ("_slots", "_mask", "_limit", "_seed", "_young", "_old",
                 "_young_count", "_old_count", "_zero_young", "_zero_old")

    def __init__(self, capacity: int = 10_000) -> None:
        if capacity < 1:
            raise ValueError("capacity must be positive")
        # Half load. Linear probing degrades sharply past that, and this table
        # is read once per routable packet.
        slots = 1
        while slots < capacity * 2:
            slots <<= 1
        self._slots = slots
        self._mask = slots - 1
        self._limit = slots // 2
        self._seed = int.from_bytes(os.urandom(8), "big")
        self._young = bytearray(slots * _SLOT)
        self._old = bytearray(slots * _SLOT)
        self._young_count = 0
        self._old_count = 0
        # Zero is a legal id and is also the empty-slot sentinel, so it is held
        # apart rather than stored. One flag against a 1-in-2**64 case costs
        # less than a second sentinel byte in every slot.
        self._zero_young = False
        self._zero_old = False

    # -- internals ---------------------------------------------------------

    def _index(self, value: int) -> int:
        """Where ``value`` starts probing. Seeded — see the module docstring."""
        return ((((value ^ self._seed) * _MIX) & _MASK64) >> 24) & self._mask

    def _slot_of(self, table: bytearray, value: int) -> int:
        """The slot holding ``value``, or the first free one on its path.

        Always terminates: neither table is ever more than half full, so a free
        slot always exists."""
        mask = self._mask
        index = self._index(value)
        while True:
            held = _Q.unpack_from(table, index * _SLOT)[0]
            if held == 0 or held == value:
                return index
            index = (index + 1) & mask

    def _rotate(self) -> None:
        self._old = self._young
        self._old_count = self._young_count
        self._zero_old = self._zero_young
        self._young = bytearray(self._slots * _SLOT)
        self._young_count = 0
        self._zero_young = False

    # -- the two operations ------------------------------------------------

    def __contains__(self, value: int) -> bool:
        if value == 0:
            return self._zero_young or self._zero_old
        if _Q.unpack_from(self._young,
                          self._slot_of(self._young, value) * _SLOT)[0] == value:
            return True
        return _Q.unpack_from(self._old,
                              self._slot_of(self._old, value) * _SLOT)[0] == value

    def add(self, value: int) -> bool:
        """Record ``value``; return whether it was **already** there.

        The return is the question the caller actually asks — "have I handled
        this packet?" — so the lookup and the insert are one pass over the table
        rather than two."""
        if not 0 <= value <= _MASK64:
            raise ValueError("id must fit in 64 bits")
        if value == 0:
            if self._zero_young or self._zero_old:
                return True
            self._zero_young = True
            self._young_count += 1
        else:
            if _Q.unpack_from(self._old,
                              self._slot_of(self._old, value) * _SLOT)[0] == value:
                return True
            index = self._slot_of(self._young, value)
            offset = index * _SLOT
            if _Q.unpack_from(self._young, offset)[0] == value:
                return True
            _Q.pack_into(self._young, offset, value)
            self._young_count += 1
        if self._young_count >= self._limit:
            self._rotate()
        return False

    # -- for the console and the tests --------------------------------------

    def __len__(self) -> int:
        """Ids currently remembered, across both generations."""
        return self._young_count + self._old_count

    @property
    def capacity(self) -> int:
        """Ids guaranteed to be remembered before the oldest start to go."""
        return self._limit

    def nbytes(self) -> int:
        """What the two tables cost, for anyone reporting on memory."""
        return 2 * self._slots * _SLOT

    def clear(self) -> None:
        self._young = bytearray(self._slots * _SLOT)
        self._old = bytearray(self._slots * _SLOT)
        self._young_count = self._old_count = 0
        self._zero_young = self._zero_old = False
