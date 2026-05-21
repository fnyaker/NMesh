from dataclasses import dataclass
from .node_id import NodeID


@dataclass
class NodeEntry:
    node_id: NodeID
    address: str


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

    def _bucket_index(self, node_id: NodeID) -> int:
        return self._own_id.distance(node_id).bit_length() - 1

    def add(self, node_id: NodeID, address: str) -> NodeEntry | None:
        if node_id == self._own_id:
            return None
        return self._buckets[self._bucket_index(node_id)].add(NodeEntry(node_id, address))

    def evict_and_add(self, node_id: NodeID, address: str) -> None:
        idx = self._bucket_index(node_id)
        self._buckets[idx].evict_oldest(NodeEntry(node_id, address))

    def remove(self, node_id: NodeID) -> None:
        self._buckets[self._bucket_index(node_id)].remove(node_id)

    def get_closest(self, target: NodeID, count: int = 20) -> list[NodeEntry]:
        all_entries: list[NodeEntry] = []
        for bucket in self._buckets:
            all_entries.extend(bucket.entries)
        all_entries.sort(key=lambda e: target.distance(e.node_id))
        return all_entries[:count]

    def get(self, node_id: NodeID) -> NodeEntry | None:
        idx = self._bucket_index(node_id)
        return self._buckets[idx].get(node_id)

    def contains(self, node_id: NodeID) -> bool:
        return self.get(node_id) is not None
