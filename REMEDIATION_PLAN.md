# NMesh — Plan de remédiation détaillé

Pour chaque faille : **plan d'attaque**, **risques de régression**, **tests de vérification**.
Ordre = par sévérité décroissante (audit).

---

## C1 — Forwarding DATA cassé

### Décision d'architecture nécessaire
Deux options exclusives :
- **A. End-to-end** : la session est entre `(src, dst)`, pas `(peer, peer)`. Les relais transportent en aveugle. Préféré pour la confidentialité.
- **B. Onion routing** : N couches, une par hop. Complexe, latence élevée.

**Recommandation : A**. Plus simple, plus sûr, et le routage Kademlia s'y prête.

### Plan (option A)

1. **Court terme (immédiat — anti-zombie)** :
   - Dans [src/node.py:_loop](src/node.py#L102) : élargir le `except` pour catcher `Exception` (avec log) — empêche un peer de mourir sur exception.
   - Dans [src/node.py:_handle_data](src/node.py#L303) : try/except autour de `decrypt_payload` ; sur échec → drop silencieux.
   - **Le forwarding DATA fonctionnera mais le destinataire dropperont les paquets** (au lieu de crasher). C'est acceptable temporairement.

2. **Moyen terme (E2E)** :
   - Nouveau dict `MeshNode._sessions: dict[NodeID, SessionKey]` (E2E sessions par destinataire)
   - Nouveau type de paquet : `E2E_HANDSHAKE` / `E2E_HANDSHAKE_ACK` — routés comme DATA (msg_id, TTL, forward) mais avec payload `(kem_pub, dsa_pub, signature)`
   - `send_data(payload, target: NodeID)` : si pas de session E2E avec `target`, déclencher `_initiate_e2e_handshake(target)` qui envoie un E2E_HANDSHAKE routé
   - `_handle_data` : utilise `self._sessions[NodeID(packet.src_id)]` et non `peer.session`

### Risques de régression
- Casse `send_data` (broadcast actuel). Garder un mode `send_broadcast` séparé pour les paquets non-E2E.
- Tests `test_data.py` : adapter pour le nouveau modèle.

### Tests de vérification
- `test_forward_data_no_zombie` : injecter DATA non-déchiffrable → boucle peer survit
- `test_e2e_session_setup` : A↔C via relai B → session E2E établie
- `test_e2e_data_decrypts_at_target` : A envoie à C via B → C déchiffre

---

## C2 — INVITE_ACK non sollicité (bypass invitation)

### Plan
1. Ajouter `peer.invite_sent: bool = False` dans `_Peer.__init__`
2. Dans [_handle_challenge](src/node.py#L331), après `await peer.send(invite_pkt)`, **set `peer.invite_sent = True`** (uniquement dans la branche `join_code` — pas pour les routing peers)
3. Dans [_handle_invite_ack](src/node.py#L357) : **drop si `not peer.invite_sent`**
4. Reset `peer.invite_sent = False` après consommation (anti-replay)

### Risques de régression
- Aucun, c'est un ajout strict.

### Tests de vérification
- `test_unsolicited_invite_ack_dropped` : connecter, ignorer CHALLENGE, envoyer INVITE_ACK(ACCEPTED) → aucun HANDSHAKE émis
- `test_normal_invite_flow_still_works` : flow complet existant passe toujours

---

## C3 — HANDSHAKE non lié à la connexion (replay)

### Plan
La CHALLENGE de 32 octets envoyée à l'ouverture devient le nonce de binding.
1. Stocker `peer.received_challenge: bytes | None = None` dans `_Peer`
2. Dans [_handle_challenge](src/node.py#L331) : avant tout traitement, **set `peer.received_challenge = packet.payload`**
3. Dans [initiate_handshake](src/node.py#L209) : signer `received_challenge + kem_pub + dsa_pub` (au lieu de juste `kem_pub + dsa_pub`)
   - Si `received_challenge is None` (client n'a pas reçu de CHALLENGE) → générer un nonce aléatoire local et l'inclure dans le payload du HANDSHAKE
4. Dans [_handle_handshake](src/node.py#L362) : vérifier la signature sur `peer.pending_challenge + kem_pub + dsa_pub`
   - Le serveur a stocké `pending_challenge` dans `_on_new_transport`
5. Idem pour HANDSHAKE_ACK : signer `peer.pending_challenge + ciphertext + dsa_pub`

### Pour les routing peers (pas de CHALLENGE comme binding HMAC)
- Le serveur envoie quand même un CHALLENGE à la connexion
- Le routing peer le stocke (étape 2 ci-dessus) et l'inclut dans sa signature
- Le serveur connaît son propre challenge — il vérifie

→ Pas de cas spécial à traiter.

### Risques de régression
- Casse tous les tests handshake (signature change). Mettre à jour `test_handshake.py`.
- Changement de format du payload HANDSHAKE → incompatibilité avec versions précédentes (non-déployé, donc OK).

### Tests de vérification
- `test_replay_handshake_on_new_connection_rejected` : capturer un HANDSHAKE, l'injecter sur nouvelle connexion → drop
- `test_handshake_with_wrong_challenge_rejected` : signature sur mauvaise challenge → drop

---

## C4 — Routing connections impossibles à bootstrap

### Plan
1. **Modifier `NodeEntry`** ([src/routing.py:5](src/routing.py#L5)) :
   ```python
   @dataclass
   class NodeEntry:
       node_id: NodeID
       address: str
       dsa_pub: bytes
   ```
2. **Modifier `_encode_entries` / `_decode_entries`** dans [src/node.py:33](src/node.py#L33) :
   - Ajouter un `H` (uint16) pour `len(dsa_pub)` après `len(addr)`
   - Inclure les octets `dsa_pub`
3. **Dans [_handle_found_node](src/node.py#L326)** :
   ```python
   for entry in entries:
       if NodeID.from_public_key(entry.dsa_pub) != entry.node_id:
           continue  # binding ID↔clé invalide
       if not self._trust.add(entry.node_id, entry.dsa_pub):
           continue  # clé déjà connue mais différente — attaque
       self._routing.add(entry.node_id, entry.address)
   ```
4. **Quand on ajoute un peer à routing** (post-handshake) : aussi écrire en routing table avec sa `dsa_pub` connue
5. **`_handle_find_node`** : inclure les `dsa_pub` dans les entries renvoyées (déjà dans NodeEntry après le pt 1)
6. **`MeshNode._connect_routing`** : avant de dial, vérifier que `self._trust.contains(node_id)` — sinon abort

### Risques de régression
- Format de paquet FOUND_NODE change → casse les tests `test_node.py` (TestHandleFoundNode, TestFindNode)
- Routing table init plus stricte → entries existantes (PING sans dsa_pub) doivent être traitées différemment

### Tests de vérification
- `test_found_node_populates_trust_table` : A reçoit FOUND_NODE de B avec entry (C, addr, C_pub) → A.trust contient C
- `test_found_node_with_bad_binding_rejected` : entry avec `hash(dsa_pub) != node_id` → drop
- `test_routing_peer_handshake_after_found_node` : A connecte routing à C après FOUND_NODE → handshake accepté

---

## C5 — Exceptions non catchées (DoS par paquet malformé)

### Plan (deux couches de défense)

**1. Catch-all dans `_loop`** ([src/node.py:102](src/node.py#L102)) :
```python
async def _loop(self, on_packet) -> None:
    while True:
        try:
            packet = await self.transport.receive()
        except (asyncio.IncompleteReadError, ConnectionError, asyncio.CancelledError):
            return  # vraie fin de connexion
        try:
            await on_packet(self, packet)
        except Exception:
            pass  # paquet malformé — drop, continuer la boucle
```

**2. Validation stricte dans chaque handler** :
- `_handle_ping` : `try: address = packet.payload.decode(); except: return`
- `_handle_find_node` : `if len(packet.payload) != 20: return`
- `_handle_invite_ack` : `if len(packet.payload) < 1: return`
- `_decode_entries` : try/except + bounds checking sur chaque slice
- `_decode_handshake` / `_decode_handshake_ack` : idem
- `_handle_data` : try/except autour de `decrypt_payload`

### Risques de régression
- Le catch-all peut masquer de vrais bugs en dev. Acceptable — mais log.
- Aucun changement de logique métier.

### Tests de vérification
- `test_malformed_ping_does_not_kill_peer` : payload PING non-UTF8 → boucle survit
- `test_short_find_node_payload_dropped` : FIND_NODE avec 5 octets → drop, boucle vivante
- `test_empty_invite_ack_dropped` : INVITE_ACK avec payload vide → drop
- `test_truncated_found_node_dropped` : FOUND_NODE avec entries tronquées → drop

---

## H1 — Address poisoning via PING

### Plan
1. Ajouter une méthode (ou propriété optionnelle) sur `BaseTransport` :
   ```python
   def peer_address(self) -> str | None: return None
   ```
2. Implémenter sur `TCPTransport` :
   ```python
   def peer_address(self) -> str | None:
       if self._writer is None: return None
       host, port = self._writer.get_extra_info('peername')[:2]
       return f"{host}:{port}"
   ```
3. Dans `_handle_ping` :
   ```python
   address = peer.transport.peer_address() or packet.payload.decode()
   # transport-vérifié si disponible, fallback sur payload sinon
   ```
4. Pour les transports non-TCP : ils retournent `None` → on accepte le payload (mais le payload n'est plus considéré comme une source d'autorité)

### Risques de régression
- L'adresse stockée pour TCP devient le `peername` (ex: `192.168.1.5:43210`) — pas l'adresse de listen du peer. Le peer écoute sur un autre port. **Bug potentiel** : on stocke l'adresse de connexion sortante, pas l'adresse d'écoute.
- **Mitigation** : le peer doit annoncer son adresse d'écoute dans PING, **signée** avec sa clé DSA. Le binding identité↔clé garantit l'intégrité.
- **Plan révisé** : exiger que le payload PING contienne `address || signature(challenge + address)` où challenge est connexion-bound (cf C3).

### Tests de vérification
- `test_ping_address_must_be_signed` : PING avec adresse non-signée → drop
- `test_ping_signed_address_accepted` : adresse signée correctement → routing table mise à jour

---

## H2 — FOUND_NODE poisoning

### Plan
Couplé à C4 (qui ajoute `dsa_pub` à `NodeEntry`).

**Étape 1** (déjà dans C4) : vérifier `hash(dsa_pub) == node_id` à la réception. Élimine l'invention de NodeID.

**Étape 2** (additionnel) : pour empêcher un peer authentifié de **mentir sur l'adresse** :
- Chaque entry est signée par le peer qui l'a vouchée à l'origine
- `NodeEntry` devient `(node_id, address, dsa_pub, signature)` où `signature = sign(address)` par le node lui-même
- À la réception : vérifier `verify(address, signature, dsa_pub)` — le node a auto-déclaré son adresse, vérifiable indépendamment

**Étape 3** : ne pas blindly remplacer une entry existante. Si on a déjà `(C, addr1)` dans la routing table et qu'on reçoit `(C, addr2)` via FOUND_NODE, **ne pas écraser** sans validation supplémentaire (ex: tentative de connect à addr2 + handshake réussi).

### Risques de régression
- Format paquet change encore → mais on aligne avec C4
- Auto-signature de l'adresse : chaque nœud doit signer son adresse au démarrage et la stocker

### Tests de vérification
- `test_found_node_unsigned_address_rejected`
- `test_found_node_signed_by_wrong_key_rejected`
- `test_existing_address_not_overwritten_by_found_node`

---

## H3 — msg_id CRC32 → cryptographique

### Plan
1. Dans [src/packet.py:64](src/packet.py#L64) :
   ```python
   def compute_msg_id(self) -> int:
       data = struct.pack(MSG_ID_FORMAT, ...) + self.__payload
       digest = hashlib.sha256(data).digest()
       return int.from_bytes(digest[:8], 'big')
   ```
2. Changer `HEADER_FORMAT` : `msg_id` passe de `I` (uint32, 4 octets) à `Q` (uint64, 8 octets)
3. Header passe de 75 à 79 octets

### Risques de régression
- Tous les tests qui comparent des `msg_id` ou parsent l'header doivent être revérifiés
- Compat ascendante perdue (mais non-déployé)

### Tests de vérification
- `test_msg_id_is_sha256_truncated`
- `test_msg_id_collision_resistance` (statistique — pas faisable en unit, mais documenter)
- `test_header_size_is_79`

---

## H4 — Slow Loris (timeout TCP)

### Plan
1. Dans [src/tcp_transport.py](src/tcp_transport.py) ajouter constante `_READ_TIMEOUT = 30.0`
2. Dans `receive()` :
   ```python
   async def receive(self) -> Packet:
       try:
           length = _FRAME.unpack(
               await asyncio.wait_for(self._reader.readexactly(_FRAME.size), _READ_TIMEOUT)
           )[0]
           data = await asyncio.wait_for(self._reader.readexactly(length), _READ_TIMEOUT)
           return Packet.unpack(data)
       except asyncio.TimeoutError:
           raise ConnectionError("read timeout")
   ```

### Risques de régression
- Si une vraie connexion lente (mauvais réseau) dépasse 30s entre paquets → fermée. Augmenter à 60s ou 120s si nécessaire.
- Tests qui injectent des paquets manuellement (`fake_transport`) ne sont pas affectés (pas de TCP réel).

### Tests de vérification
- Test d'intégration : ouvrir socket TCP, envoyer length=10, ne rien envoyer → connexion fermée après 30s

---

## H5 — Limite de connexions

### Plan
1. Constante `MAX_PEERS = 100` dans node.py
2. Dans `_on_new_transport` :
   ```python
   if len(self._peers) >= MAX_PEERS:
       await transport.close()
       return
   ```

### Risques de régression
- Limite arbitraire. Configurable via constructor `MeshNode(max_peers=...)`.

### Tests de vérification
- `test_max_peers_enforced` : ouvrir 101 transports → 101e fermé immédiatement

---

## H6 — Rate limit invitation par peer

### Plan
1. Sortir le rate limit de `InviteManager` (logique réseau, pas crypto)
2. Ajouter à `_Peer` : `failed_invites: int = 0`, `lockout_ts: float = 0.0`
3. Dans `_handle_invite` : si `peer.failed_invites >= 3 and time() - peer.lockout_ts < 60` → drop
4. Incrémenter `peer.failed_invites` sur échec ; set `lockout_ts` à 3
5. `_invite._failures` peut rester pour stats mais ne déclenche plus le lockout global

### Risques de régression
- Tests `test_invite.py::TestRateLimit` testent le rate limit global → adapter pour test au niveau peer dans `test_invite_flow.py`

### Tests de vérification
- `test_peer_a_lockout_does_not_affect_peer_b` : A échoue 3 fois → A bloqué, B fonctionne
- `test_peer_lockout_expires` : après 60s, A peut réessayer

---

## H7 — Persistance trust table

### Plan
1. Dans [src/trust.py](src/trust.py) :
   ```python
   def save(self, path: str) -> None:
       data = {nid.hex(): pub.hex() for nid, pub in self._keys.items()}
       with open(path, 'w') as f:
           json.dump(data, f)

   @classmethod
   def load(cls, path: str) -> 'TrustTable':
       tt = cls()
       try:
           with open(path) as f:
               data = json.load(f)
           tt._keys = {bytes.fromhex(k): bytes.fromhex(v) for k, v in data.items()}
       except FileNotFoundError:
           pass
       return tt
   ```
2. `MeshNode(__init__, trust_path: str | None = None)` : si fourni, load au démarrage
3. Hook : sauvegarder après chaque `_trust.add` réussi (ou périodique)

### Risques de régression
- Aucune si le path est optionnel.
- Atomicité de l'écriture : utiliser `os.replace(tmp_path, path)` pour éviter les fichiers corrompus.

### Tests de vérification
- `test_trust_save_load_roundtrip`
- `test_trust_load_missing_file_returns_empty`
- `test_node_loads_trust_at_startup`

---

## H8 — Dedup local des DATA

### Plan
Dans [_handle_packet](src/node.py#L275), avant la branche `_ROUTABLE_TYPES`, ajouter :
```python
if packet.type in _ROUTABLE_TYPES:
    if self._is_seen(packet.msg_id):
        return
    # puis la suite (forward ou local)
```
Le check est unique, couvre forward ET local.

### Risques de régression
- Si un paquet légitime est dropé par collision msg_id → dépend de H3 (msg_id crypto).
- Si même paquet DATA légitime envoyé deux fois (ex: retry app-level) → 2e drop. Acceptable.

### Tests de vérification
- `test_duplicate_data_dropped_locally` : injecter même DATA deux fois → 1 seule dans la queue
- `test_distinct_data_passes` : 2 DATA différentes → 2 dans la queue

---

## Ordre d'exécution recommandé

Toujours par bloc cohérent avec tests avant/après :

1. **C5** d'abord (catch large) — protège tout le reste
2. **C2** (1 ligne de code) — ferme un bypass évident
3. **H8** (1 ligne) — bonne hygiène
4. **C3** (lie handshake au challenge)
5. **C4** (NodeEntry étendu — gros changement)
6. **H1, H2** (adresse signée — cohérent avec C4)
7. **H3** (msg_id crypto)
8. **H4, H5, H6** (DoS hardening)
9. **H7** (persistance)
10. **C1** (E2E — gros travail, à isoler)
