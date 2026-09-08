import heapq
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from .node_id import NodeID
from .uri import _MAX_ADDRESSES, _validate_uri

# How long an address that answered as somebody else is held against the node it
# was filed under. Not for ever: an address is a lease, and the node that owns
# it today may be the one we were looking for tomorrow. Long enough that the
# gossip which taught it to us has stopped repeating itself, short enough that a
# machine changing hands heals on its own.
WRONG_ADDRESS_TTL = 600.0
# Bounded like everything an outsider can grow: the pairs come from what peers
# advertise, so a flood of invented (node, address) pairs must not be a way to
# grow this table.
MAX_WRONG_ADDRESSES = 256

# A node we have asked this many times, and which has never once answered, stops
# being asked every round. Five is deliberately patient: a node reachable only
# through a relay that is having a bad minute must not be written off, and the
# cost of asking is one small packet.
SILENT_AFTER = 5
# It is then asked again at this interval instead of at every lookup — so a node
# that comes back is found within five minutes, and one that never does costs
# one packet per five minutes instead of one per ten seconds.
SILENT_RETRY = 300.0


@dataclass
class NodeEntry:
    node_id: NodeID
    addresses: list[str] = field(default_factory=list)
    dsa_pub: bytes = b""
    cert_chain: list = field(default_factory=list)
    # Monotonic timestamp of when this entry was last added/refreshed — used to
    # surface the most recently seen nodes. A fresh entry is created on every
    # add(), so this tracks recency of contact without a separate update path.
    last_seen: float = field(default_factory=time.monotonic)
    # Whether this id has ever answered a lookup of ours, how many times running
    # it has not, and when we last asked. Carried across `add`, which is the
    # whole point: an id re-advertised by somebody else must not arrive with a
    # clean sheet, or the count never reaches anything.
    answered_at: float | None = None
    unanswered: int = 0
    asked_at: float = 0.0


class KBucket:
    K = 20

    def __init__(self) -> None:
        self._entries: list[NodeEntry] = []

    def add(self, entry: NodeEntry) -> NodeEntry | None:
        existing = self.get(entry.node_id)
        if existing is not None:
            self._entries.remove(existing)
            self._entries.append(entry)
            return None
        if len(self._entries) < self.K:
            self._entries.append(entry)
            return None
        return self._entries[0]

    def evict_oldest(self, replacement: NodeEntry) -> None:
        self._entries.pop(0)
        self._entries.append(replacement)

    def remove(self, node_id: NodeID) -> None:
        self._entries = [e for e in self._entries if e.node_id != node_id]

    def get(self, node_id: NodeID) -> NodeEntry | None:
        for e in self._entries:
            if e.node_id == node_id:
                return e
        return None

    @property
    def oldest(self) -> NodeEntry | None:
        return self._entries[0] if self._entries else None

    @property
    def entries(self) -> list[NodeEntry]:
        return list(self._entries)

    def __len__(self) -> int:
        return len(self._entries)


class RoutingTable:

    def __init__(self, own_id: NodeID) -> None:
        self._own_id = own_id
        self._buckets: list[KBucket] = [KBucket() for _ in range(160)]
        # (node_id, address) -> (what it answered as, when we stop believing it).
        # Oldest first, so the bound evicts what we have believed longest.
        self._wrong: "OrderedDict[tuple[bytes, str], tuple[bytes, float]]" = OrderedDict()

    def _bucket_index(self, node_id: NodeID) -> int:
        """Which bucket an id belongs in, or -1 for our own.

        Our own id is at distance 0, whose `bit_length()` is 0 — so the naive
        expression yielded -1, which Python resolves to the *last* bucket.
        `add` guarded against it, `get`/`remove`/`contains` did not, so they
        silently interrogated bucket 159. Harmless only because `add` refuses
        to store us; an accident, not a decision."""
        distance = self._own_id.distance(node_id)
        return distance.bit_length() - 1 if distance else -1

    def add(self, node_id: NodeID, addresses: list[str], dsa_pub: bytes = b"") -> NodeEntry | None:
        if node_id == self._own_id:
            return None
        existing = self.get(node_id)
        # Prefer fresh observations and cap address churn from authenticated
        # peers so a single route can never grow without bound.
        merged_addrs = list(dict.fromkeys(
            addresses + (existing.addresses if existing else [])))
        # Filtered here, at the one door every address comes through. Dropping a
        # bad address without remembering it was a treadmill: the next answer
        # from anybody put it straight back, at the *head* of the list because
        # fresh observations are preferred, and the next pass paid another
        # post-quantum handshake to learn the same thing. That loop is what a
        # real trace showed, once every ten seconds, for as long as the node ran.
        merged_addrs = [a for a in merged_addrs
                        if self.wrong_address(node_id, a) is None][:_MAX_ADDRESSES]
        merged_pub = dsa_pub if dsa_pub else (existing.dsa_pub if existing else b"")
        entry = NodeEntry(node_id, merged_addrs, merged_pub)
        if existing is not None:
            entry.answered_at = existing.answered_at
            entry.unanswered = existing.unanswered
            entry.asked_at = existing.asked_at
        return self._buckets[self._bucket_index(node_id)].add(entry)

    def touch(self, node_id: NodeID) -> bool:
        """This node is alive; it told us nothing new about where it is.

        `add` is how recency has always been refreshed, and it does far more
        than that: it merges the addresses it was handed with the ones already
        held, filters every one of them through `wrong_address`, builds a fresh
        entry and re-inserts it. That is right when addresses arrive and pure
        waste when none did — and since a link can be probed ten times a
        second, "none did" is now the overwhelming majority of the calls.

        Returns whether the id was known. An unknown one is *not* created here:
        recency about a node we have never heard of is not an entry, and
        inventing one from a bare liveness signal is how a table fills with ids
        nobody can reach."""
        entry = self.get(node_id)
        if entry is None:
            return False
        entry.last_seen = time.monotonic()
        return True

    # -- ids that never answer ---------------------------------------------

    def note_answered(self, node_id: NodeID) -> None:
        """This id answered a lookup of ours. Nothing else counts as an answer:
        being mentioned by a peer is what put it here in the first place."""
        entry = self.get(node_id)
        if entry is not None:
            entry.answered_at = entry.asked_at = time.monotonic()
            entry.unanswered = 0

    def note_unanswered(self, node_id: NodeID) -> None:
        entry = self.get(node_id)
        if entry is not None:
            entry.asked_at = time.monotonic()
            entry.unanswered += 1

    def is_silent(self, entry: NodeEntry, now: float | None = None) -> bool:
        """Has this id never once answered, often enough that we should stop
        asking for a while?

        Never once, not lately: an id that has answered before is a node having
        a bad minute, and the answer to that is patience. An id that has answered
        *nothing*, ever, through every path we have, is what a routing table
        looks like when it is still carrying somebody's previous identity —
        re-advertised by everyone, asked after by everyone, for ever."""
        if entry.answered_at is not None or entry.unanswered < SILENT_AFTER:
            return False
        return (time.monotonic() if now is None else now) - entry.asked_at < SILENT_RETRY

    # -- addresses that answered as somebody else --------------------------

    def note_wrong_address(self, node_id: NodeID, address: str,
                           answered_as: NodeID) -> None:
        """This address is not this node's. Drop it, and remember why.

        Only ever called on something we established ourselves — the identity a
        handshake proved against our own challenge, or our own list of the
        addresses we answer on. A *claim* on an unauthenticated link is not
        enough to strike an address off; if it were, saying "I am somebody else"
        would be a way to have a third party's address forgotten."""
        self.drop_address(node_id, address)
        now = time.monotonic()
        self._prune_wrong(now)
        key = (node_id.raw, address)
        self._wrong.pop(key, None)
        while len(self._wrong) >= MAX_WRONG_ADDRESSES:
            self._wrong.popitem(last=False)
        self._wrong[key] = (answered_as.raw, now + WRONG_ADDRESS_TTL)

    def wrong_address(self, node_id: NodeID, address: str) -> bytes | None:
        """Who this address answered as, while we still believe it. ``None``
        once the record has expired — the entry is left to the next prune."""
        found = self._wrong.get((node_id.raw, address))
        if found is None:
            return None
        answered_as, until = found
        return answered_as if time.monotonic() < until else None

    def wrong_addresses(self) -> list[dict]:
        """What we are currently refusing to dial, for a console to show."""
        now = time.monotonic()
        return [{"node": node_raw.hex(), "address": address,
                 "answered_as": answered_as.hex(),
                 "for_seconds": round(until - now, 1)}
                for (node_raw, address), (answered_as, until)
                in self._wrong.items() if now < until]

    def _prune_wrong(self, now: float) -> None:
        for key in [k for k, (_who, until) in self._wrong.items() if now >= until]:
            self._wrong.pop(key, None)

    def evict_and_add(self, node_id: NodeID, addresses: list[str], dsa_pub: bytes = b"") -> None:
        index = self._bucket_index(node_id)
        if index < 0:
            return
        self._buckets[index].evict_oldest(NodeEntry(node_id, addresses, dsa_pub))

    def remove(self, node_id: NodeID) -> None:
        index = self._bucket_index(node_id)
        if index >= 0:
            self._buckets[index].remove(node_id)

    def drop_address(self, node_id: NodeID, address: str) -> bool:
        """Forget one address of a node, keeping the node. Returns whether it
        was there.

        The removal half of :meth:`note_wrong_address`, and on its own not
        enough: forgetting an address that anybody is still advertising means
        learning it again on the next answer. Call this directly only where
        there is nothing to remember. The entry stays either way — the node is
        real, its other addresses may be good, and a punch can still reach it.

        The entry is edited rather than re-added: ``add`` builds a fresh
        ``NodeEntry``, whose ``last_seen`` defaults to now, so re-adding would
        report a node we have just failed to reach as the most recently seen
        one."""
        entry = self.get(node_id)
        if entry is None or address not in entry.addresses:
            return False
        entry.addresses = [a for a in entry.addresses if a != address]
        return True

    def all_entries(self) -> list[NodeEntry]:
        entries: list[NodeEntry] = []
        for bucket in self._buckets:
            entries.extend(bucket.entries)
        return entries

    def get_closest(self, target: NodeID, count: int = 20) -> list[NodeEntry]:
        """The ``count`` entries nearest ``target`` by XOR distance.

        `nsmallest`, not a full sort of a materialised copy of the table:
        `_handle_find_node` calls this for every FIND_NODE, which an
        authenticated peer may send `_QUERY_RATE_MAX` times a window, and the
        table can hold 160 × K entries. Same answer, same order.

        Silent ids are left out — of what we ask, of what we dial, and of what
        we tell others. Not an accusation and nothing is held against the node:
        we simply stop naming an id that answers nobody, which is how a dead one
        leaves the network instead of being handed round it for ever. Anyone who
        *can* reach it goes on naming it, and we ask again ourselves every
        `SILENT_RETRY`."""
        now = time.monotonic()
        return heapq.nsmallest(
            count, (e for e in self._iter_entries() if not self.is_silent(e, now)),
            key=lambda e: target.distance(e.node_id))

    def silent_ids(self) -> list[str]:
        """The ids we have stopped asking after, for a console to show."""
        now = time.monotonic()
        return [e.node_id.raw.hex() for e in self._iter_entries()
                if self.is_silent(e, now)]

    def _iter_entries(self):
        for bucket in self._buckets:
            yield from bucket.entries

    def get(self, node_id: NodeID) -> NodeEntry | None:
        index = self._bucket_index(node_id)
        # Our own id is never stored (see `add`), so `contains(self._id)` is
        # false for ever — which `_handle_found_node` relies on (gotchas §12).
        # It is stated here now rather than falling out of a negative index.
        if index < 0:
            return None
        return self._buckets[index].get(node_id)

    def contains(self, node_id: NodeID) -> bool:
        return self.get(node_id) is not None

    def export_entries(self) -> list[dict]:
        """Reconnectable peers as JSON-safe dicts (node id, addresses, pubkey).
        Only public information — no secrets."""
        out: list[dict] = []
        for e in self.all_entries():
            if not e.dsa_pub:
                continue  # can't re-authenticate without the peer's key
            out.append({
                "id": e.node_id.raw.hex(),
                "addresses": list(e.addresses),
                "dsa_pub": e.dsa_pub.hex(),
            })
        return out

    def import_entries(self, entries: list) -> None:
        """Restore peers exported by :meth:`export_entries`, defensively."""
        if not isinstance(entries, list):
            return
        for e in entries:
            if not isinstance(e, dict):
                continue
            try:
                raw = bytes.fromhex(e["id"])
                dsa_pub = bytes.fromhex(e["dsa_pub"])
            except (KeyError, TypeError, ValueError):
                continue
            if len(raw) != 20 or not dsa_pub:
                continue
            node_id = NodeID(raw)
            if NodeID.from_public_key(dsa_pub) != node_id:
                continue
            raw_addresses = e.get("addresses", [])
            if not isinstance(raw_addresses, list):
                continue
            addresses = [a for a in raw_addresses[:_MAX_ADDRESSES]
                         if isinstance(a, str) and _validate_uri(a) is not None]
            self.add(node_id, addresses, dsa_pub)
