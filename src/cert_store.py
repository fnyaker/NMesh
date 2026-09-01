import json
import os
import time
from collections import deque
from .node_id import NodeID
from .cert import Certificate


# Bounds. Certificates arrive from the network — three handlers absorb them
# (`_handle_handshake`, `_handle_handshake_ack`, `_handle_found_node`) — and a
# post-quantum certificate is ~7 kB. Unbounded, the store grew on demand, and
# `get_chain_to_root` is a BFS over it called once per candidate entry of every
# FIND_NODE: a 28-byte packet buying an unbounded graph walk.
MAX_SUBJECTS = 4096          # distinct subjects we keep certificates for
MAX_PER_SUBJECT = 8          # certificates kept for one subject


class CertStore:
    """
    Holds the known certificates and the trusted roots.
    Replaces TrustTable in a self-rooted P2P PKI model.
    """

    def __init__(self, own_id: NodeID,
                 max_subjects: int = MAX_SUBJECTS,
                 max_per_subject: int = MAX_PER_SUBJECT) -> None:
        self._own_id = own_id
        # Insertion-ordered, oldest first: eviction takes the subject nobody has
        # mentioned for longest. Roots and every subject our own chain runs
        # through are pinned (see `_pinned`) — a bound that can make us unable
        # to authenticate is not a bound, it is an outage.
        self._certs: dict[bytes, list[Certificate]] = {}  # subject_id.raw → [Certificate]
        self._roots: set[bytes] = {own_id.raw}
        self._max_subjects = max_subjects
        self._max_per_subject = max_per_subject
        # `get_chain_to_root` memoised per subject. Cleared on any change: a
        # stale chain is a chain that no longer verifies, which is worse than
        # recomputing one.
        self._chains: dict[bytes, list[Certificate] | None] = {}

    def add_root(self, node_id: NodeID) -> None:
        self._roots.add(node_id.raw)
        self._chains.clear()

    def is_root(self, node_id: NodeID) -> bool:
        return node_id.raw in self._roots

    def add(self, cert: Certificate) -> bool:
        key = cert.subject_id.raw
        existing = self._certs.setdefault(key, [])
        for e in existing:
            if e.signature == cert.signature:
                self._touch(key)
                return True  # already present
        existing.append(cert)
        # Cleared before the bounds run, not after: both of them ask what our
        # own chain is made of, and a chain computed from the graph as it was a
        # certificate ago can name the wrong certificates to keep.
        self._chains.clear()
        # Oldest first within a subject: a peer presenting chain after chain
        # cannot make one subject's list grow without end. The one certificate
        # our own chain runs through is not a candidate — a chain visits a
        # subject once, so there is always something else to drop.
        if len(existing) > self._max_per_subject:
            load_bearing = self._chain_signatures()
            while len(existing) > self._max_per_subject:
                victim = next((c for c in existing
                               if c.signature not in load_bearing), existing[0])
                existing.remove(victim)
        self._touch(key)
        self._enforce_bounds()
        return True

    def _touch(self, key: bytes) -> None:
        entry = self._certs.pop(key, None)
        if entry is not None:
            self._certs[key] = entry

    def _chain_signatures(self) -> set[bytes]:
        """The certificates our own chain is made of. Memoised with the chain."""
        return {c.signature for c in (self.get_chain_to_root(self._own_id) or [])}

    def _own_chain_subjects(self) -> set[bytes]:
        """Every subject our own chain runs through.

        Not just us and the root: the issuers in between are what joins the two.
        Losing one leaves us presenting a chain that stops short of a root,
        which no peer can verify — we would go on authenticating everyone else
        while nobody could authenticate us, and no error would be raised
        anywhere. Memoised with the chain, so this costs a lookup."""
        chain = self.get_chain_to_root(self._own_id) or []
        subjects = {c.subject_id.raw for c in chain}
        subjects.update(c.issuer_id.raw for c in chain)
        subjects.add(self._own_id.raw)
        return subjects

    def _pinned(self, key: bytes) -> bool:
        """Subjects eviction may never take: the roots, and our own chain.

        Losing a root means every chain anchored there stops verifying; losing
        any link of our own chain means we can no longer present one at all."""
        return key in self._roots or key in self._own_chain_subjects()

    def _enforce_bounds(self) -> None:
        while len(self._certs) > self._max_subjects:
            victim = next((k for k in self._certs if not self._pinned(k)), None)
            if victim is None:
                return          # everything left is load-bearing
            del self._certs[victim]

    def add_all(self, certs) -> None:
        """Absorb a chain in one go — one bound check, one cache clear."""
        for cert in certs:
            self.add(cert)

    def get_chain_to_root(self, target: NodeID) -> list[Certificate] | None:
        """
        A BFS over the issuance graph, looking for a path from target up to a
        known root.

        We prefer a chain anchored on an **external** root (the network): a node
        that joined a network is also its own self-signed root, but presenting
        ``[own_self_signed_cert]`` authenticates nothing to peers (nobody trusts
        that root). The network chain (through the issuer that invited us) is
        the only one others can verify; the self-root is kept only as a
        fallback.

        Returns [cert_target, ..., cert_root_self_signed] or None.

        Memoised per subject: this is a BFS over the issuance graph and
        `_handle_find_node` runs it once per candidate it considers (up to
        `_FIND_NODE_SCAN`), so recomputing it per query made one small packet
        buy a great deal of walking. The cache is dropped whenever the graph or
        the root set changes.
        """
        if target.raw in self._chains:
            return self._chains[target.raw]
        chain = self._build_chain_to_root(target)
        self._chains[target.raw] = chain
        return chain

    def _build_chain_to_root(self, target: NodeID) -> list[Certificate] | None:
        target_certs = self._certs.get(target.raw)
        if not target_certs:
            return None

        visited: set[bytes] = {target.raw}
        # Prefer certs with external issuer so we find the network-wide chain
        sorted_certs = sorted(target_certs, key=lambda c: 1 if c.is_self_signed else 0)
        queue: deque[tuple[bytes, list[Certificate]]] = deque(
            (c.issuer_id.raw, [c]) for c in sorted_certs
        )
        self_anchored: list[Certificate] | None = None  # fallback: our own root

        while queue:
            current_raw, path = queue.popleft()

            if current_raw in self._roots:
                last = path[-1]
                if last.is_self_signed:
                    chain = path
                else:
                    chain = None
                    for rc in self._certs.get(current_raw, []):
                        if rc.is_self_signed:
                            chain = path + [rc]
                            break
                    if chain is None:
                        # Root known but no self-signed cert yet — keep BFS going
                        if current_raw not in visited:
                            visited.add(current_raw)
                            for cert in self._certs.get(current_raw, []):
                                queue.append((cert.issuer_id.raw, path + [cert]))
                        continue
                if current_raw != self._own_id.raw:
                    return chain            # anchored on the network root — best
                if self_anchored is None:
                    self_anchored = chain   # only good if nothing external exists
                continue

            if current_raw in visited:
                continue
            visited.add(current_raw)

            for cert in self._certs.get(current_raw, []):
                queue.append((cert.issuer_id.raw, path + [cert]))

        return self_anchored

    def verify_chain(self, chain: list[Certificate]) -> NodeID | None:
        """
        Verify a chain presented by a peer.
        Returns the anchor (the root's NodeID) if it is valid, None otherwise.

        Invariants:
          1. Every cert holds its own invariants (already checked at parse time).
          2. Unbroken issuance links.
          3. The last cert is self-signed.
          4. The last cert.subject_id is in roots.
          5. No expired cert.
        """
        if not chain:
            return None

        now = int(time.time())
        for cert in chain:
            if cert.expires_at != 0 and now > cert.expires_at:
                return None

        for i in range(len(chain) - 1):
            if chain[i].issuer_id != chain[i + 1].subject_id:
                return None
            if chain[i].issuer_pub != chain[i + 1].subject_pub:
                return None

        last = chain[-1]
        if not last.is_self_signed:
            return None
        if last.subject_id.raw not in self._roots:
            return None

        return last.subject_id

    def save(self, path: str) -> None:
        roots = [r.hex() for r in self._roots]
        certs_json: dict[str, list[dict]] = {
            raw.hex(): [c.to_json() for c in cert_list]
            for raw, cert_list in self._certs.items()
        }
        tmp = path + ".tmp"
        with open(tmp, 'w') as f:
            json.dump({"roots": roots, "certs": certs_json}, f)
        os.replace(tmp, path)

    @classmethod
    def load(cls, path: str, own_id: NodeID) -> 'CertStore':
        store = cls(own_id)
        try:
            with open(path) as f:
                data = json.load(f)
            for root_hex in data.get("roots", []):
                try:
                    store._roots.add(bytes.fromhex(root_hex))
                except ValueError:
                    pass
            for subject_hex, cert_list in data.get("certs", {}).items():
                for cert_data in cert_list:
                    try:
                        cert = Certificate.from_json(subject_hex, cert_data)
                        store.add(cert)
                    except (ValueError, KeyError):
                        pass
        except FileNotFoundError:
            pass
        return store
