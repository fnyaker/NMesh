import json
import os
import time
from collections import deque
from .node_id import NodeID
from .cert import Certificate


class CertStore:
    """
    Holds the known certificates and the trusted roots.
    Replaces TrustTable in a self-rooted P2P PKI model.
    """

    def __init__(self, own_id: NodeID) -> None:
        self._own_id = own_id
        self._certs: dict[bytes, list[Certificate]] = {}  # subject_id.raw → [Certificate]
        self._roots: set[bytes] = {own_id.raw}

    def add_root(self, node_id: NodeID) -> None:
        self._roots.add(node_id.raw)

    def is_root(self, node_id: NodeID) -> bool:
        return node_id.raw in self._roots

    def add(self, cert: Certificate) -> bool:
        key = cert.subject_id.raw
        existing = self._certs.setdefault(key, [])
        for e in existing:
            if e.signature == cert.signature:
                return True  # already present
        existing.append(cert)
        return True

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
        """
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
