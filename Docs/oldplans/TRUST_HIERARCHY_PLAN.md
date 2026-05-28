# NMesh — Refonte du modèle de confiance

## 1. Principe directeur

**Plus de TOFU.** Plus de connexion à un inconnu. Avant toute session, on doit pouvoir **vérifier une chaîne de signatures** qui remonte jusqu'à une identité que l'on connaît déjà comme source de confiance (initialement : soi-même).

Modèle : **PKI P2P à auto-racines** — chaque nœud est l'autorité de certification des nœuds qu'il invite. La confiance se propage par signature, jamais par convention.

---

## 2. Concept central : `Certificate`

Un certificat lie cryptographiquement une identité (NodeID + DSA public key) à un émetteur, signé par lui.

```
Certificate {
  subject_id:    NodeID   (20 bytes)
  subject_pub:   bytes    (DSA pub, longueur variable)
  issuer_id:     NodeID   (20 bytes)
  issuer_pub:    bytes    (DSA pub de l'émetteur — pour pratique de vérification)
  issued_at:     uint64   (timestamp unix)
  expires_at:    uint64   (timestamp unix ; 0 = jamais)
  signature:     bytes    (DSA signature de l'émetteur sur tout ce qui précède)
}
```

**Cas self-signed (root identity)** : `subject_id == issuer_id`, `subject_pub == issuer_pub`. Une seule signature, par sa propre clé privée.

**Invariants vérifiés à toute désérialisation** :
- `NodeID.from_public_key(subject_pub) == subject_id`
- `NodeID.from_public_key(issuer_pub) == issuer_id`
- `signature` valide sur `(subject_id || subject_pub || issuer_id || issuer_pub || issued_at || expires_at)`

Si un seul invariant casse → rejet.

---

## 3. Stockage : `CertStore` (remplace `TrustTable`)

```
CertStore {
  certs: dict[NodeID, list[Certificate]]   # tous les certs reçus, indexés par subject
  roots: set[NodeID]                       # identités à la racine de la confiance
  
  add(cert: Certificate) -> bool           # vérifie invariants + ajoute
  get_chain_to_root(target: NodeID) -> list[Certificate] | None
                                            # BFS dans le graphe d'émission
  verify_chain(chain: list[Certificate]) -> NodeID | None
                                            # retourne l'ancre si valide, None sinon
  save(path) / load(path)                  # JSON, schéma à définir
}
```

**Roots initiaux** : `{self_node_id}`. L'utilisateur peut ajouter manuellement d'autres roots (config) — par exemple si l'on veut faire confiance à un nœud "ami" sans en avoir reçu d'invitation.

**Algorithme de vérification de chaîne** (chain = `[cert_0, cert_1, ..., cert_n]` où `cert_0` est le cert de l'identité cible) :

```
1. Pour chaque cert dans la chaîne : valider les invariants (binding ID↔pub, signature).
2. Pour i de 0 à n-1 :
   - cert[i].issuer_id doit == cert[i+1].subject_id
   - cert[i].issuer_pub doit == cert[i+1].subject_pub
3. cert[n] doit être self-signed (subject == issuer)
4. cert[n].subject_id doit ∈ roots
5. Aucun cert expiré.
→ Si tout OK, retourner cert[n].subject_id (l'ancre utilisée). Sinon None.
```

---

## 4. Émission d'un certificat

Méthode sur `CryptoIdentity` :
```
issue_cert(subject_id: NodeID, subject_pub: bytes, ttl_seconds: int = 365 * 86400) -> Certificate
```

Quand un nœud **A invite B** et que B complète le handshake :
- A émet un cert pour B : `issuer = A`, `subject = B`, durée 1 an par défaut
- Ce cert est envoyé à B dans **HANDSHAKE_ACK** (extension du payload)
- B le stocke dans son CertStore comme **son propre cert de bootstrap**

À l'inverse, B peut aussi vouloir émettre un cert pour A — symétrique. Mais on garde unidirectionnel pour la v1 : seul l'inviter émet.

---

## 5. Changements dans les flux existants

### 5.1 INVITE flow (inchangé sur la forme, étendu sur la sémantique)
- CHALLENGE / INVITE / INVITE_ACK comme avant.
- À la place de "TOFU" : sur réception d'un INVITE valide, l'invitant **note** qu'il devra émettre un cert lors du HANDSHAKE_ACK.
- `peer.invite_accepted = True` reste, mais devient juste un signal interne.

### 5.2 HANDSHAKE flow (refondu)

**Payload HANDSHAKE** :
```
kem_pub_len(H) || dsa_pub_len(H) || cert_chain_len(H)
  || kem_pub || dsa_pub || cert_chain_bytes || signature
```
où `cert_chain_bytes` = encodage de la liste de certs présentés.

**Pour un client qui vient d'être invité** : `cert_chain` peut être vide (l'invite code prouve l'autorisation, le cert sera émis dans le ACK).

**Pour un client qui se reconnecte ou routing peer** : `cert_chain` doit être présenté.

**Vérification côté serveur** (`_handle_handshake`) :
1. Vérifier signature (challenge + kem_pub + dsa_pub) comme avant.
2. Vérifier `hash(dsa_pub) == src_id`.
3. **Si `peer.invite_accepted`** : pas de chaîne requise → accepter, émettre cert pour le client dans le ACK.
4. **Sinon** : exiger chaîne non vide ; `cert_store.verify_chain(chain)` doit retourner un ancrage valide → accepter. Sinon drop.
5. Ajouter le subject (et toute la chaîne) au CertStore.

### 5.3 HANDSHAKE_ACK (refondu)

**Payload** :
```
ct_len(H) || dsa_pub_len(H) || cert_chain_len(H) || optional_issued_cert_len(H)
  || ciphertext || dsa_pub || cert_chain_bytes || optional_issued_cert_bytes
  || signature
```

- `optional_issued_cert_bytes` : présent si le serveur émet un cert pour le client (suite à invite). Sinon vide.
- `cert_chain_bytes` : chaîne du serveur (sa propre identité prouvable).

**Vérification client** :
1. Signature comme avant.
2. Vérifier chaîne du serveur → ancrage dans `roots`.
3. Si `issued_cert` présent : le stocker comme son propre cert de bootstrap. Vérifier qu'il a bien été émis par ce serveur (`issuer == server`).

### 5.4 FOUND_NODE (refondu)

Chaque entry inclut désormais la **chaîne complète** vers une racine connue de l'émetteur. Format d'entry :
```
node_id(20) || addr_len(B) || cert_chain_len(H) || address || cert_chain_bytes
```

À réception, le récepteur :
1. Vérifie la chaîne avec son propre CertStore.
2. Si elle remonte à une racine connue → ajoute à la routing table + ajoute au CertStore.
3. Sinon → drop entry (n'a aucune valeur pour ce nœud).

Conséquence : un nœud ne peut pas être "annoncé" sans preuve. Anti-poisoning fort.

### 5.5 Routing connections (simplifiées)

Plus besoin de `is_routing_peer` comme bypass. Tout client présente sa chaîne. La distinction n'existe plus.

→ Supprimer `is_routing_peer`, `_handle_challenge` ne saute plus le INVITE flow.
→ Pour qu'une connexion sans code passe, il faut **simplement** que le client présente une chaîne valide.

---

## 6. Persistance

`CertStore.save(path)` : JSON
```json
{
  "roots": ["nodeid_hex", ...],
  "certs": {
    "subject_id_hex": [
      {
        "subject_pub": "hex",
        "issuer_id": "hex",
        "issuer_pub": "hex",
        "issued_at": 12345,
        "expires_at": 678901,
        "signature": "hex"
      },
      ...
    ]
  }
}
```

Atomique via `os.replace`.

Sauvegarder après chaque `add()` réussi.

---

## 7. Migration depuis l'état actuel

1. Supprimer `src/trust.py` ou le remplacer par `src/cert_store.py`.
2. Tous les sites de `self._trust.add(...)` deviennent `self._cert_store.add(cert)`.
3. `_handle_handshake` et `_handle_handshake_ack` réécrits comme décrit.
4. `_handle_found_node` réécrit.
5. Suppression de `_handle_challenge` du branch `is_routing_peer`.
6. Suppression de `_connect_routing` ou refonte pour exiger une chaîne dès la connexion.

---

## 8. Tests à ajouter

- `test_cert_self_signed_valid` : un cert self-signed correct est accepté.
- `test_cert_binding_violation_rejected` : `hash(pub) != id` → rejet.
- `test_cert_chain_verifies_to_root` : chaîne A→B→C avec roots={A} → ancre A retournée.
- `test_cert_chain_no_root_rejected` : chaîne valide mais qui n'aboutit pas à une racine → rejet.
- `test_cert_expired_rejected`
- `test_invite_flow_issues_cert` : après invite réussi, le serveur émet un cert au client, qui le stocke.
- `test_routing_handshake_requires_chain` : connexion sans cert → drop.
- `test_routing_handshake_with_valid_chain_accepted`.
- `test_found_node_with_invalid_chain_dropped`.
- `test_cert_store_save_load_roundtrip`.

---

## 9. Risques / décisions à prendre

- **Taille des paquets** : un cert ML-DSA-65 fait ~2KB (signature). Une chaîne de 5 certs = 10KB. Header TCP frame est `!H` (uint16, max 65KB), donc OK, mais à surveiller.
- **Expiration des certs** : si un cert root expire → toute la chaîne casse. Stratégie de renouvellement à concevoir.
- **Révocation** : pas dans la v1. Si A veut "untrust" B après l'avoir invité, il doit retirer B des roots ET retirer son cert du CertStore (manuel pour l'instant).
- **Boucles dans le graphe** : éviter en interdisant `subject == issuer` sauf pour self-signed.

---

## 10. Ordre d'exécution recommandé

1. Créer `src/cert.py` (classe `Certificate`, serialize/deserialize).
2. Créer `src/cert_store.py` (replacement de `trust.py`).
3. Tests unitaires des deux ci-dessus (sans intégration node).
4. Modifier `CryptoIdentity` pour `issue_cert()` et `self_signed_cert()`.
5. Modifier `MeshNode.__init__` : remplacer `_trust` par `_cert_store`.
6. Refondre `_handle_handshake` / `_handle_handshake_ack` + `initiate_handshake`.
7. Refondre `_handle_found_node` / `_handle_find_node` + `NodeEntry`.
8. Supprimer `is_routing_peer` et tout son code branché.
9. Mettre à jour les tests existants (la plupart vont casser).
10. Ajouter les nouveaux tests de la section 8.

---

## 11. Compatibilité

Aucune. Le format des paquets HANDSHAKE / HANDSHAKE_ACK / FOUND_NODE change. Le réseau actuel (non déployé) sera incompatible avec le code post-refonte. Acceptable.
