from dataclasses import dataclass, field
from .node_id import NodeID


@dataclass
class NodeEntry:
    node_id: NodeID
    addresses: list[str] = field(default_factory=list)
    dsa_pub: bytes = b""
    cert_chain: list = field(default_factory=list)


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

    def add(self, node_id: NodeID, addresses: list[str], dsa_pub: bytes = b"") -> NodeEntry | None:
        if node_id == self._own_id:
            return None
        existing = self.get(node_id)
        merged_addrs = list(dict.fromkeys((existing.addresses if existing else []) + addresses))
        merged_pub = dsa_pub if dsa_pub else (existing.dsa_pub if existing else b"")
        return self._buckets[self._bucket_index(node_id)].add(
            NodeEntry(node_id, merged_addrs, merged_pub)
        )

    def evict_and_add(self, node_id: NodeID, addresses: list[str], dsa_pub: bytes = b"") -> None:
        idx = self._bucket_index(node_id)
        self._buckets[idx].evict_oldest(NodeEntry(node_id, addresses, dsa_pub))

    def remove(self, node_id: NodeID) -> None:
        self._buckets[self._bucket_index(node_id)].remove(node_id)

    def all_entries(self) -> list[NodeEntry]:
        entries: list[NodeEntry] = []
        for bucket in self._buckets:
            entries.extend(bucket.entries)
        return entries

    def get_closest(self, target: NodeID, count: int = 20) -> list[NodeEntry]:
        all_entries = self.all_entries()
        all_entries.sort(key=lambda e: target.distance(e.node_id))
        return all_entries[:count]

    def get(self, node_id: NodeID) -> NodeEntry | None:
        idx = self._bucket_index(node_id)
        return self._buckets[idx].get(node_id)

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
            if len(raw) != 20:
                continue
            addresses = [a for a in e.get("addresses", []) if isinstance(a, str)]
            self.add(NodeID(raw), addresses, dsa_pub)
