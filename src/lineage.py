"""
Who vouched for whom before a root shortened the chain.

A member's certificate is signed by the node that invited it, so every
generation of invitations adds one certificate to the chain — about 7 kB each —
and a mesh that grows by members inviting members outgrows what a handshake and
a routing answer can carry (`Docs/Architecture/scale.md`). The root fixes that
by signing members directly once their chain proves they belong
(`CERT_RENEW` with a chain, see `node._serve_chain_compaction`).

Signing directly loses one thing the long chain gave for free: revoking a
member used to void every chain running through it, so everyone it had invited
went with it. A certificate the root signed itself does not run through
anybody. This is what keeps that property — for every member it compacted, the
root remembers the issuers its original chain ran through, and a revocation of
any of them is passed on to the members below it.

Nothing here is trusted from the network: the root records what it verified
itself, and a file read back is checked for shape like any other input.

Bounded, and **full refuses rather than evicts**: forgetting a member's lineage
would silently make it unrevocable by its inviter, which is worse than leaving
its chain long. A refused member keeps the chain it has.
"""
from __future__ import annotations

MAX_ENTRIES = 65_536          # members a root keeps the lineage of
MAX_ANCESTORS = 8             # issuers between a member and the root
_ID_LEN = 20


class Lineage:
    """``subject id -> the issuers its chain ran through``, nearest first."""

    def __init__(self, max_entries: int = MAX_ENTRIES) -> None:
        self._by_subject: dict[bytes, tuple[bytes, ...]] = {}
        self._max = max_entries

    def __len__(self) -> int:
        return len(self._by_subject)

    def record(self, subject: bytes, ancestors) -> bool:
        """Remember that ``subject``'s chain ran through ``ancestors``. False
        when refused: the book is full, or the input is not a lineage."""
        ancestors = tuple(ancestors)
        if (len(subject) != _ID_LEN or not ancestors
                or len(ancestors) > MAX_ANCESTORS
                or any(len(a) != _ID_LEN for a in ancestors)
                or subject in ancestors):
            return False
        if subject not in self._by_subject and len(self._by_subject) >= self._max:
            return False
        self._by_subject[subject] = ancestors
        return True

    def ancestors(self, subject: bytes) -> tuple[bytes, ...]:
        return self._by_subject.get(subject, ())

    def descendants(self, ancestor: bytes) -> list[bytes]:
        """Every member whose original chain ran through ``ancestor``. A scan:
        asked once per revocation, which is rare, and kept off every hot path."""
        return [subject for subject, chain in self._by_subject.items()
                if ancestor in chain]

    def forget(self, subject: bytes) -> None:
        self._by_subject.pop(subject, None)

    def to_json(self) -> dict:
        return {subject.hex(): [a.hex() for a in chain]
                for subject, chain in self._by_subject.items()}

    @classmethod
    def from_json(cls, data, max_entries: int = MAX_ENTRIES) -> 'Lineage':
        """Read back defensively: anything that is not a lineage is skipped."""
        book = cls(max_entries)
        if not isinstance(data, dict):
            return book
        for subject_hex, chain in data.items():
            if not isinstance(subject_hex, str) or not isinstance(chain, list):
                continue
            try:
                subject = bytes.fromhex(subject_hex)
                ancestors = [bytes.fromhex(a) for a in chain if isinstance(a, str)]
            except ValueError:
                continue
            if len(ancestors) == len(chain):
                book.record(subject, ancestors)
        return book
