# NMesh — Implémentation E2E (option A) — Plan détaillé pour Sonnet

**Objectif** : DATA chiffré de bout en bout entre `src` et `dst`, illisible par les relais. La session est entre `(source, destination)` finales, pas entre voisins directs.

**Prérequis** : la refonte de la confiance (cf. [TRUST_HIERARCHY_PLAN.md](TRUST_HIERARCHY_PLAN.md)) doit avoir été appliquée. Le `CertStore` est utilisé pour valider les identités. Cette implémentation E2E **suppose** que la validation de chaîne est disponible.

**Ce plan ne décrit pas la refonte trust**. Il décrit uniquement le mécanisme E2E qui s'appuie dessus.

---

## 1. Vue d'ensemble

- Chaque nœud maintient `self._e2e_sessions: dict[NodeID, SessionKey]` — sessions chiffrées par destinataire final.
- Avant d'envoyer une `DATA` à `target`, vérifier qu'une session existe avec `target`. Sinon, déclencher un **E2E handshake routé**.
- Le handshake utilise les paquets `E2E_HANDSHAKE` / `E2E_HANDSHAKE_ACK` qui transitent comme `DATA` (forwarding Kademlia, TTL, dedup msg_id).
- Les relais ne peuvent rien lire — `_handle_data` n'est appelé que si `dst_id == self._id`.

---

## 2. Nouveaux types de paquets

Dans [src/node.py](src/node.py), après `INVITE_ACK = 0x0B` :
```
E2E_HANDSHAKE      = 0x0D
E2E_HANDSHAKE_ACK  = 0x0E
```

**Ajouter à `_ROUTABLE_TYPES`** :
```
_ROUTABLE_TYPES = {DATA, E2E_HANDSHAKE, E2E_HANDSHAKE_ACK}
```

Ces paquets sont donc routés/forwardés exactement comme `DATA` (Kademlia, TTL, dedup), et leur `dst_id` désigne la destination finale.

---

## 3. État ajouté à `MeshNode`

Dans `MeshNode.__init__` :
```
self._e2e_sessions: dict[NodeID, SessionKey] = {}
self._e2e_pending_kem: dict[NodeID, bytes] = {}      # target → kem_secret en attente
self._e2e_pending_nonce: dict[NodeID, bytes] = {}    # target → nonce envoyé (pour binding)
self._e2e_pending_data: dict[NodeID, list[bytes]] = {}  # buffer si handshake en cours
```

---

## 4. Format des payloads E2E

### `E2E_HANDSHAKE` (initiateur → cible, via relais)
```
nonce(32) || kem_pub_len(H) || dsa_pub_len(H) || cert_chain_len(H)
  || kem_pub || dsa_pub || cert_chain_bytes || signature
```
- `nonce` : 32 octets aléatoires fraîchement générés (binding anti-replay).
- `signature` : `sign(nonce || kem_pub || dsa_pub)` par la clé privée de l'initiateur.
- `cert_chain_bytes` : chaîne de l'initiateur (sérialisée comme dans le trust plan).

### `E2E_HANDSHAKE_ACK` (cible → initiateur, via relais)
```
nonce(32) || ct_len(H) || dsa_pub_len(H) || cert_chain_len(H)
  || ciphertext || dsa_pub || cert_chain_bytes || signature
```
- `nonce` : **le même nonce reçu dans le E2E_HANDSHAKE** — lien explicite vers la requête.
- `signature` : `sign(nonce || ciphertext || dsa_pub)` par la clé privée de la cible.
- `ciphertext` : sortie de `kem_encapsulate(kem_pub)`.

Helpers à créer dans [src/node.py](src/node.py) :
```python
_E2E_HEADER = struct.Struct('!32sHHH')  # nonce || kem_pub_len || dsa_pub_len || cert_chain_len

def _encode_e2e_handshake(nonce, kem_pub, dsa_pub, cert_chain, signature) -> bytes
def _decode_e2e_handshake(data) -> tuple[nonce, kem_pub, dsa_pub, cert_chain, signature]
def _encode_e2e_handshake_ack(nonce, ciphertext, dsa_pub, cert_chain, signature) -> bytes
def _decode_e2e_handshake_ack(data) -> tuple[nonce, ciphertext, dsa_pub, cert_chain, signature]
```

Validations strictes dans chaque `_decode_*` (longueurs, bornes), comme déjà fait dans `_decode_entries`.

---

## 5. Modifications de `send_data`

### Nouvelle signature
```python
async def send_data(self, target: NodeID, payload: bytes) -> None:
    if target == self._id:
        raise ValueError("cannot send to self")
    
    if target not in self._e2e_sessions:
        # bufferiser et déclencher handshake
        self._e2e_pending_data.setdefault(target, []).append(payload)
        if target not in self._e2e_pending_kem:
            await self._initiate_e2e_handshake(target)
        return
    
    session = self._e2e_sessions[target]
    packet = Packet.create_encrypted(DATA, self._id.raw, target.raw, payload, session)
    await self._route_outbound(packet)
```

`_route_outbound(packet)` : utilise la logique de routage existante (peer authentifié dont `authenticated_id` est le plus proche de `dst_id` en XOR). Si aucun peer routant connaissant la cible → erreur ou drop.

### Ancien comportement broadcast
Conserver sous nouveau nom `broadcast_data(payload)` si besoin (envoi non chiffré E2E à tous les peers directs — utile pour discovery, hello, etc.). Si pas utilisé → supprimer.

---

## 6. `_initiate_e2e_handshake`

```python
async def _initiate_e2e_handshake(self, target: NodeID) -> None:
    import os
    nonce = os.urandom(32)
    kem_pub, kem_secret = self._identity.generate_kem_keypair()
    dsa_pub = self._identity.dsa_public_key
    cert_chain = self._cert_store.get_chain_to_root(self._id)  # ma propre chaîne
    if cert_chain is None:
        return  # ne peut pas prouver son identité — abort
    signature = self._identity.sign(nonce + kem_pub + dsa_pub)
    payload = _encode_e2e_handshake(nonce, kem_pub, dsa_pub, cert_chain, signature)
    
    self._e2e_pending_kem[target] = kem_secret
    self._e2e_pending_nonce[target] = nonce
    
    packet = Packet.create(E2E_HANDSHAKE, self._id.raw, target.raw, payload)
    await self._route_outbound(packet)
```

---

## 7. `_handle_e2e_handshake` (côté cible)

```python
async def _handle_e2e_handshake(self, peer: _Peer, packet: Packet) -> None:
    # NOTE : ce handler est appelé seulement si dst_id == self._id (cf. dispatch dans _handle_packet)
    try:
        nonce, kem_pub, dsa_pub, cert_chain, signature = _decode_e2e_handshake(packet.payload)
    except Exception:
        return
    
    # 1. Vérifier l'identité revendiquée
    if NodeID.from_public_key(dsa_pub) != NodeID(packet.src_id):
        return
    
    # 2. Vérifier la chaîne → doit aboutir à une racine de confiance
    if self._cert_store.verify_chain(cert_chain) is None:
        return
    
    # 3. Vérifier la signature
    if not self._identity.verify(nonce + kem_pub + dsa_pub, signature, dsa_pub):
        return
    
    # 4. Encapsuler, établir session côté cible
    ciphertext, shared_secret = self._identity.kem_encapsulate(kem_pub)
    self._e2e_sessions[NodeID(packet.src_id)] = SessionKey(shared_secret)
    
    # 5. Préparer et envoyer l'ACK
    my_cert_chain = self._cert_store.get_chain_to_root(self._id)
    if my_cert_chain is None:
        return
    ack_signature = self._identity.sign(nonce + ciphertext + self._identity.dsa_public_key)
    ack_payload = _encode_e2e_handshake_ack(
        nonce, ciphertext, self._identity.dsa_public_key, my_cert_chain, ack_signature
    )
    ack_packet = Packet.create(E2E_HANDSHAKE_ACK, self._id.raw, packet.src_id, ack_payload)
    await self._route_outbound(ack_packet)
```

---

## 8. `_handle_e2e_handshake_ack` (côté initiateur)

```python
async def _handle_e2e_handshake_ack(self, peer: _Peer, packet: Packet) -> None:
    try:
        nonce, ciphertext, dsa_pub, cert_chain, signature = _decode_e2e_handshake_ack(packet.payload)
    except Exception:
        return
    
    src = NodeID(packet.src_id)
    
    # 1. Vérifier que le nonce correspond à un handshake qu'on a initié
    expected_nonce = self._e2e_pending_nonce.get(src)
    if expected_nonce is None or nonce != expected_nonce:
        return
    
    # 2. Identité revendiquée
    if NodeID.from_public_key(dsa_pub) != src:
        return
    
    # 3. Chaîne de l'autre → ancrage de confiance
    if self._cert_store.verify_chain(cert_chain) is None:
        return
    
    # 4. Signature
    if not self._identity.verify(nonce + ciphertext + dsa_pub, signature, dsa_pub):
        return
    
    # 5. Décapsuler, établir session
    kem_secret = self._e2e_pending_kem.pop(src, None)
    if kem_secret is None:
        return
    self._e2e_pending_nonce.pop(src, None)
    shared_secret = self._identity.kem_decapsulate(ciphertext, kem_secret)
    self._e2e_sessions[src] = SessionKey(shared_secret)
    
    # 6. Flush les data en attente
    pending = self._e2e_pending_data.pop(src, [])
    for payload in pending:
        pkt = Packet.create_encrypted(DATA, self._id.raw, src.raw, payload, self._e2e_sessions[src])
        await self._route_outbound(pkt)
```

---

## 9. Modifications dans `_handle_packet` (dispatch)

Dans le bloc `_ROUTABLE_TYPES`, après le check dédup et avant le forwarding :

```python
if packet.type in _ROUTABLE_TYPES:
    if peer.authenticated_id is None:
        return
    if self._is_seen(packet.msg_id):
        return
    if packet.dst_id != self._id.raw and packet.dst_id != _BROADCAST_ID:
        await self._forward_packet(peer, packet)
        return
    # paquet pour moi — tomber dans le dispatch standard
```

Ajouter les handlers dans la table :
```python
handlers = {
    ...
    DATA:              self._handle_data,
    E2E_HANDSHAKE:     self._handle_e2e_handshake,
    E2E_HANDSHAKE_ACK: self._handle_e2e_handshake_ack,
    ...
}
```

---

## 10. Modifications de `_handle_data` (déchiffrement E2E)

```python
async def _handle_data(self, peer: _Peer, packet: Packet) -> None:
    src = NodeID(packet.src_id)
    session = self._e2e_sessions.get(src)
    if session is None:
        return  # aucune session E2E avec cette source — drop
    try:
        plaintext = packet.decrypt_payload(session)
    except Exception:
        return
    await self._data_queue.put((src, plaintext))
```

**Important** : `receive_data` retourne maintenant `(src_id, payload)`. C'est un changement d'API.

```python
async def receive_data(self) -> tuple[NodeID, bytes]:
    return await self._data_queue.get()
```

---

## 11. Helper `_route_outbound`

Refactorisation du choix de peer pour un paquet sortant (DATA, E2E_HANDSHAKE, E2E_HANDSHAKE_ACK) :
```python
async def _route_outbound(self, packet: Packet) -> None:
    target = NodeID(packet.dst_id)
    # peer direct ?
    direct = next(
        (p for p in self._peers
         if p.authenticated_id == target and p.session is not None),
        None
    )
    if direct is not None:
        await direct.send(packet)
        return
    # sinon, peer le plus proche en XOR (forwarding initial)
    candidates = [p for p in self._peers
                  if p.authenticated_id is not None and p.session is not None]
    if not candidates:
        return
    best = min(candidates, key=lambda p: target.distance(p.authenticated_id))
    await best.send(packet)
```

**Note** : `_forward_packet` (pour les paquets transitant) reste séparé car il fait TTL-1 et exclut le peer d'origine. `_route_outbound` est pour les paquets qu'on émet soi-même.

---

## 12. Tests à ajouter (à créer dans `tests/test_e2e.py`)

Architecture : utiliser des `MeshNode` reliés par `FakeTransport` en chaîne A→B→C avec routing tables et cert stores pré-peuplés (assume trust hierarchy déjà migrée).

### 12.1 Tests handshake E2E
- `test_e2e_handshake_establishes_session` : A→C via B, après E2E handshake, les deux ont une session pour l'autre.
- `test_e2e_handshake_invalid_signature_dropped`
- `test_e2e_handshake_no_chain_dropped` : pas de chaîne valide → drop.
- `test_e2e_handshake_replay_nonce_rejected` : injecter un ACK avec un nonce non-en-attente → drop.

### 12.2 Tests data E2E
- `test_send_data_buffers_until_handshake` : envoyer DATA avant que la session existe → bufferisée.
- `test_send_data_uses_session_after_handshake` : après handshake, DATA chiffré avec la bonne session.
- `test_relay_cannot_decrypt_data` : intercepter sur B le paquet DATA → B ne peut pas le déchiffrer.
- `test_target_decrypts_data` : C reçoit DATA, déchiffre avec la session.
- `test_receive_data_returns_src_id` : `receive_data()` retourne `(src, payload)`.

### 12.3 Tests de routage / TTL
- `test_e2e_handshake_ttl_decremented` : à chaque hop, TTL diminue.
- `test_e2e_handshake_ttl_zero_dropped`.
- `test_e2e_handshake_msg_id_dedup`.

### 12.4 Tests d'erreur
- `test_send_to_self_raises`.
- `test_handshake_to_unknown_target_no_session`.

---

## 13. Régressions à anticiper

Tous les tests existants qui appellent `node.send_data(b"...")` (sans `target`) doivent être mis à jour. Liste à grep avant d'exécuter le plan :
```
grep -rn "send_data" tests/
grep -rn "receive_data" tests/
```

`test_data.py` est concerné — toute la suite à réécrire avec :
1. Setup `CertStore` pré-peuplé sur les deux nœuds (chacun reconnaît l'autre comme racine, ou via cert mutuels).
2. Forcer l'établissement E2E avant l'assertion sur la DATA.

---

## 14. Ordre d'exécution pour Sonnet

1. **Pré-condition** : avoir terminé la refonte trust hierarchy ([TRUST_HIERARCHY_PLAN.md](TRUST_HIERARCHY_PLAN.md)).
2. Ajouter les constantes `E2E_HANDSHAKE` et `E2E_HANDSHAKE_ACK` et les inclure dans `_ROUTABLE_TYPES`.
3. Créer les helpers `_encode_e2e_*` / `_decode_e2e_*`.
4. Ajouter l'état E2E dans `MeshNode.__init__`.
5. Implémenter `_route_outbound`.
6. Implémenter `_initiate_e2e_handshake`.
7. Implémenter `_handle_e2e_handshake` + ajouter au dispatch.
8. Implémenter `_handle_e2e_handshake_ack` + ajouter au dispatch.
9. Modifier `_handle_data` pour utiliser `_e2e_sessions[src]`.
10. Modifier `send_data` (signature + logique de buffer).
11. Modifier `receive_data` (retour tuple).
12. Mettre à jour `tests/test_data.py`.
13. Créer `tests/test_e2e.py` avec les tests listés.
14. Faire passer la suite complète.

---

## 15. Points de vigilance pour Sonnet

- **Ne pas appeler `_route_outbound` depuis un handler async sans peer source identifié** — risque de boucle si on renvoie au même peer.
- **Toujours valider la longueur de payload AVANT de slicer** dans les `_decode_*` (cf. règles C5).
- **`_e2e_pending_nonce`** : critique pour le binding anti-replay. Ne jamais accepter un ACK sans nonce match.
- **Expiration** : ne pas oublier de prévoir un timeout sur les handshakes E2E en attente (sinon fuite mémoire si jamais la cible est injoignable). Implémenter avec une tâche périodique ou via un timestamp dans `_e2e_pending_*`.
- **Concurrence** : si deux `send_data(target)` arrivent simultanément avant la session, ne déclencher **qu'un seul** handshake (le check `if target not in self._e2e_pending_kem` le garantit, à condition que ce soit atomique en asyncio — c'est le cas car pas de `await` entre le check et le set).
- **Ne pas implémenter** : forwarding optimisé (cache de routes), heartbeat E2E, rekey périodique. Ce sont des extensions futures.

---

## 16. Ce qui sort du scope

- Routage adaptatif (changement de route en cas de panne d'un relais).
- Multipath.
- Onion (chiffrement par hop) — explicitement écarté au profit de E2E.
- Sender anonymity (l'identifiant `src_id` est en clair dans le header).
- Forward secrecy par message (la session reste valable jusqu'à rekey explicite).

Ces points sont à traiter dans des itérations ultérieures, séparément.
