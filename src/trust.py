from .node_id import NodeID


class TrustTable:
    """
    Stocke l'identité cryptographique des nœuds connus : NodeID → DSA public key.

    Modèle TOFU (Trust On First Use) :
    - Premier contact : clé inconnue → stockée, retourne True.
    - Contact suivant : clé connue et identique → retourne True.
    - Contact suivant : clé DIFFÉRENTE → retourne False (attaque ou compromission).
    """

    def __init__(self) -> None:
        self._keys: dict[bytes, bytes] = {}  # node_id.raw → dsa_pub

    def add(self, node_id: NodeID, dsa_pub: bytes) -> bool:
        stored = self._keys.get(node_id.raw)
        if stored is None:
            self._keys[node_id.raw] = dsa_pub
            return True
        return stored == dsa_pub

    def contains(self, node_id: NodeID) -> bool:
        return node_id.raw in self._keys

    def get_key(self, node_id: NodeID) -> bytes | None:
        return self._keys.get(node_id.raw)

    def remove(self, node_id: NodeID) -> None:
        self._keys.pop(node_id.raw, None)

    def __len__(self) -> int:
        return len(self._keys)
