# Plan de correction Docker routing test — analyse + plan détaillé pour Sonnet

## Symptômes observés

Au lancement de `docker compose -f docker-compose-routing.yml up --build` :
- bridge1 démarre, génère ses invites, voit "All 9 nodes online ✓" en 0s (tous les `.id` sont écrits avant les join)
- 4 secondes plus tard : `discovery: 0/9 targets in routing table` puis `Bridge1 ready — backbone running`
- **Aucun** nœud ne log "Session established ✓"
- L'output s'arrête là (les nœuds restent bloqués jusqu'au timeout à 60s)

Conclusion : **le handshake INVITE→HANDSHAKE échoue silencieusement pour tous les nœuds**.

---

## Bugs identifiés

### 🔴 BUG #1 (CRITIQUE) — `_handle_invite` casse le flow INVITE→HANDSHAKE

**Fichier** : [src/node.py:806-824](src/node.py#L806-L824)

```python
async def _handle_invite(self, peer: _Peer, packet: Packet) -> None:
    if peer.pending_challenge is None:
        return
    ...
    self._invite.consume(peer.pending_challenge, packet.payload)
    peer.pending_challenge = None   # ← BUG : effacé trop tôt
    peer.invite_accepted = True
    ack = Packet.create(INVITE_ACK, ..., bytes([_ACK_ACCEPTED]))
    await peer.send(ack)
```

Puis dans [`_handle_handshake`](src/node.py#L886-L890) :

```python
async def _handle_handshake(self, peer: _Peer, packet: Packet) -> None:
    if peer.authenticated_id is not None:
        return
    if peer.pending_challenge is None:   # ← rejette ici
        return
```

**Conséquence** : après INVITE valide, `pending_challenge` est `None`. Le HANDSHAKE qui arrive ensuite est rejeté immédiatement. Aucun ACK envoyé. Session jamais établie.

**Pourquoi les tests ne l'ont pas détecté** : tous les tests handshake utilisent `_setup_challenge_pair()` ([tests/test_handshake.py:13-18](tests/test_handshake.py#L13-L18)) qui set `pending_challenge` manuellement, court-circuitant complètement le flow INVITE. **Aucun test ne couvre INVITE→INVITE_ACK→HANDSHAKE en bout-en-bout**.

**Fix** : supprimer `peer.pending_challenge = None` ligne 820. `_handle_handshake` ligne 925 efface déjà le challenge à la fin du handshake (qui est le bon endroit).

---

### 🔴 BUG #2 — `_handle_handshake` pollue la routing table

**Fichier** : [src/node.py:915-917](src/node.py#L915-L917)

```python
peer.authenticated_id = claimed_id
if self._addresses:
    self._routing.add(peer.authenticated_id, self._addresses, bob_dsa_pub)
```

Le serveur (bridge1) ajoute le **joiner's NodeID** avec **ses propres adresses** (self._addresses = bridge1's listening addresses). Quand quelqu'un demandera FIND_NODE pour n1, bridge1 répondra avec bridge1's addresses au lieu de n1's.

**Conséquence** : routing table corrompue. Les FOUND_NODE responses propagent de fausses adresses.

**Fix** : supprimer les lignes 916-917. La routing table doit être peuplée par PING (qui a les vraies adresses du sender).

---

### 🟠 BUG #3 — Couverture de test insuffisante

**Fichier** : [tests/](tests/)

Le flow complet INVITE → INVITE_ACK → HANDSHAKE → HANDSHAKE_ACK → session bilatérale n'est testé nulle part. Les classes existantes testent les étapes isolément.

**Fix** : ajouter `tests/test_invite_to_handshake.py` qui orchestre les deux nœuds via FakeTransport et vérifie le flow complet sans contournement manuel de `pending_challenge`.

---

### 🟠 BUG #4 — Les membres ne s'annoncent pas

**Fichier** : [scripts/run_node.py](scripts/run_node.py)

Les membres (`run_member`) appellent `node.join()` mais jamais `node.start([...])`. Conséquences :
- `self._addresses == []` côté membre
- Ils ne PING jamais après handshake
- Le bridge n'apprend jamais leurs adresses via PING
- Donc routing table du bridge n'a pas leurs adresses → impossible de les recontacter on-demand

**Fix** : chaque membre listen sur `tcp://0.0.0.0:9100` (même port pour tous, hostname différent par container). Après `wait_for_session`, appeler `await node.ping(peer)` pour annoncer son adresse.

---

### 🟠 BUG #5 — Discovery prématurée chez les bridges

**Fichier** : [scripts/run_node.py](scripts/run_node.py) (`run_bridge1`, `run_bridge2`)

```python
all_ids = await all_ids_ready(all_names)   # ← retourne instantanément
await do_ping(node, name)                   # ← aucun peer authentifié encore
await discovery_phase(node, name, ...)      # ← envoie FIND_NODE à 0 peers
```

`all_ids_ready` retourne dès que les fichiers `.id` existent, ce qui arrive **avant** que les nœuds aient fini de se connecter. À ce moment, bridge1 n'a aucun peer authentifié. Le `do_ping` et le `discovery_phase` sont des no-ops.

**Fix** : attendre que les sessions soient établies avant de PING / discover. Boucle d'attente sur `len([p for p in self._peers if p.session is not None]) == expected_count`.

---

### 🟠 BUG #6 — Pas de discovery périodique

Une seule passe de discovery au démarrage. Si bridge2 connecte 3s après bridge1 a fini, bridge1 ne refait pas FIND_NODE et ne découvre jamais n5-n8.

**Fix** : tâche de fond `asyncio.create_task` qui retourne la discovery toutes les ~10s tant que des targets manquent.

---

### 🟡 BUG #7 (mineur) — TransportManager limité à un serveur par scheme

**Fichier** : [src/transport_manager.py:55-56](src/transport_manager.py#L55-L56)

```python
if scheme in self._servers:
    raise TransportError(f"already listening on scheme: {scheme!r}")
```

Empêche bridge1 d'écouter sur plusieurs ports TCP en parallèle. **Non bloquant** : on contourne en écoutant sur `0.0.0.0:9000` (couvre toutes les interfaces). Mais à noter pour le futur (`self._servers: dict[str, list[BaseServer]]`).

---

## Plan d'exécution pour Sonnet

### 1. Fixes critiques dans `src/node.py`

#### 1.a — Supprimer le clear prématuré (Bug #1)

[src/node.py:806-824](src/node.py#L806-L824) — dans `_handle_invite`, supprimer la ligne :
```python
peer.pending_challenge = None
```
Le challenge sera effacé proprement à la fin de `_handle_handshake` (l. 925) après que la signature ait été vérifiée.

#### 1.b — Supprimer la pollution de routing table (Bug #2)

[src/node.py:915-917](src/node.py#L915-L917) — dans `_handle_handshake`, supprimer :
```python
if self._addresses:
    self._routing.add(peer.authenticated_id, self._addresses, bob_dsa_pub)
```
La routing table sera peuplée correctement quand le joiner enverra un PING.

### 2. Nouveau test d'intégration `tests/test_invite_to_handshake.py`

Doit tester le flow complet **sans** contournement de `pending_challenge`. Architecture : deux nœuds reliés par deux FakeTransports croisés (`t_a` sur node_a, `t_b` sur node_b). Step-by-step :

```python
async def test_full_invite_to_handshake():
    node_a, fake_a = await make_node()   # joiner
    node_b, fake_b = await make_node()   # host

    # 1. Host génère invite, joiner reçoit le code
    code = node_b.generate_invite()
    node_a._peers[0].join_code = code
    node_a._peers[0].is_client_side = True

    # 2. Host envoie CHALLENGE comme dans _on_new_transport
    challenge = node_b._invite.generate_challenge()
    node_b._peers[0].pending_challenge = challenge
    chal_pkt = Packet.create(CHALLENGE, node_b.id.raw,
                              NodeID(b"\xff"*20).raw, challenge)
    fake_a.inject(chal_pkt)
    await asyncio.sleep(0.1)

    # 3. Joiner doit avoir envoyé INVITE
    invite_pkt = next(p for p in fake_a.sent if p.type == INVITE)
    fake_b.inject(invite_pkt)
    await asyncio.sleep(0.1)

    # 4. Host doit avoir envoyé INVITE_ACK(accepted)
    ack_pkt = next(p for p in fake_b.sent if p.type == INVITE_ACK)
    assert ack_pkt.payload[0] == _ACK_ACCEPTED
    fake_a.inject(ack_pkt)
    await asyncio.sleep(0.1)

    # 5. Joiner doit avoir envoyé HANDSHAKE
    hs_pkt = next(p for p in fake_a.sent if p.type == HANDSHAKE)
    fake_b.inject(hs_pkt)
    await asyncio.sleep(0.1)

    # 6. Host doit avoir envoyé HANDSHAKE_ACK → ⚠ ICI le bug actuel rejette
    hs_ack = next((p for p in fake_b.sent if p.type == HANDSHAKE_ACK), None)
    assert hs_ack is not None, "HANDSHAKE_ACK manquant — bug #1"
    fake_a.inject(hs_ack)
    await asyncio.sleep(0.1)

    # 7. Sessions établies des deux côtés
    assert node_a._peers[0].session is not None
    assert node_b._peers[0].session is not None
    assert node_a._peers[0].authenticated_id == node_b.id
    assert node_b._peers[0].authenticated_id == node_a.id
```

Ajouter aussi : `test_handshake_signature_verified_after_invite` qui vérifie que la signature du HANDSHAKE valide bien (la signature porte sur le challenge — donc effacer le challenge cassait la vérification).

### 3. Réécriture partielle de `scripts/run_node.py`

#### 3.a — Tous les nœuds écoutent

Ajouter à `run_member` :
```python
LISTEN = _env("LISTEN_ADDR", "0.0.0.0:9100")
# ...
node = make_node(name)
await node.start([f"tcp://{LISTEN}"])   # ← nouveau
write_id(name, node)
```

L'advertise hostname est `{name}:9100` (resolved par Docker DNS).

#### 3.b — PING après wait_for_session

Après `await node.wait_for_session(...)` et `_log(name, "Session established ✓")` :
```python
await asyncio.sleep(0.5)   # laisse l'event loop souffler
for peer in list(node._peers):
    if peer.session is not None:
        await node.ping(peer)
_log(name, "Advertised addresses via PING")
```

#### 3.c — Discovery côté bridges après wait_sessions

Remplacer la séquence actuelle dans `run_bridge1` :
```python
all_ids = await all_ids_ready(all_names)
await do_ping(node, name)
await discovery_phase(...)
```

par :
```python
all_ids = await all_ids_ready(all_names)
_log(name, "All ID files present — waiting for sessions to establish…")
await wait_for_n_sessions(node, expected=5, timeout=90.0)   # bridge2 + n1..n4
_log(name, "All expected sessions established ✓")
await do_ping(node, name)
asyncio.create_task(periodic_discovery(node, name, list(all_ids.values())))
```

Idem dans `run_bridge2` (expected=5 : bridge1 + n5..n8).

Nouvelles helpers à ajouter en haut de `scripts/run_node.py` :
```python
async def wait_for_n_sessions(node, expected: int, timeout: float):
    deadline = asyncio.get_event_loop().time() + timeout
    while asyncio.get_event_loop().time() < deadline:
        n = sum(1 for p in node._peers if p.session is not None
                and p.authenticated_id is not None)
        if n >= expected:
            return
        await asyncio.sleep(0.2)
    raise TimeoutError(f"only {n}/{expected} sessions established")

async def periodic_discovery(node, name, target_ids, interval=10.0):
    while True:
        missing = [t for t in target_ids if not node._routing.contains(t)]
        if missing:
            for t in missing:
                await node.find_node(t)
        await asyncio.sleep(interval)
```

#### 3.d — Sender attend la stabilisation

Dans `run_member`, branche `is_sender`, augmenter le sleep avant le speed test à 10s et faire une boucle d'attente jusqu'à ce que `target_id` apparaisse dans la routing table :
```python
_log(name, "Waiting for target to be discovered in routing table…")
deadline = asyncio.get_event_loop().time() + 60
while asyncio.get_event_loop().time() < deadline:
    if node._routing.contains(target_id):
        break
    await node.find_node(target_id)   # force discovery
    await asyncio.sleep(2)
else:
    _log(name, "WARNING: target not in routing table — proceeding anyway")
```

### 4. Update `docker/docker-compose-routing.yml`

Ajouter `LISTEN_ADDR` env var pour tous les membres :

```yaml
n1:
  environment:
    MODE:        member
    NAME:        n1
    HOST_ADDR:   "bridge1:9000"
    LISTEN_ADDR: "0.0.0.0:9100"   # ← nouveau
    IS_SENDER:   "1"
    SENDER_TARGET: "n8"
    MSG_COUNT:   "300"
    MSG_SIZE:    "512"
```

Idem pour n2..n8, avec advertise déduit (hostname est `n2`, port 9100).

---

## Ordre d'exécution

1. **Fix Bug #1** ([src/node.py:820](src/node.py#L820)) — 1 ligne supprimée
2. **Fix Bug #2** ([src/node.py:916-917](src/node.py#L916-L917)) — 2 lignes supprimées
3. **Run pytest** — les 210 tests existants doivent rester verts (le bug #1 n'avait pas de test, donc pas de régression)
4. **Créer `tests/test_invite_to_handshake.py`** avec 2-3 tests d'intégration du flow complet
5. **Run pytest** — les nouveaux tests doivent passer (sinon le fix #1 est incomplet)
6. **Update `scripts/run_node.py`** (sections 3.a-3.d ci-dessus)
7. **Update `docker/docker-compose-routing.yml`** (LISTEN_ADDR par membre)
8. **Run Docker** : `docker compose -f docker/docker-compose-routing.yml up --build`
9. **Observer** : chaque nœud doit logger "Session established ✓", puis le speed test n1→n8 doit produire un block de stats

---

## Critères de succès

Le test Docker doit montrer dans les logs :
- ✅ Tous les 10 nœuds "Session established ✓"
- ✅ bridge1 logge "Routing table: 9/9 remote nodes reachable" (après periodic_discovery)
- ✅ n1 logge "E2E session established ✓" avec n8 comme target
- ✅ Block de stats final n8 (receiver) avec `received: 300/301 (≥99%)` et latencies p50/p95/p99

Si la perte est >5% → vérifier que `_forward_packet` utilise bien la priority routing-table avant XOR ([src/node.py:670-678](src/node.py#L670-L678)).

---

## Points de vigilance

- **Ne pas ajouter de TimeoutError dans `_handle_invite`** : si le challenge devient None par d'autres mécanismes (timeout / disconnect), la fonction doit retourner proprement sans crash.
- **Persistance des cert stores** : chaque nœud sauvegarde son `cert_store` sur `/data/{name}.certs`. Si un container redémarre, il charge l'ancien store. Pour rebuilds répétés, faire `docker compose down -v` pour vider le volume `shared_data`.
- **Race condition sur PING** : si le membre PING juste après `wait_for_session`, le bridge pourrait encore avoir des paquets HANDSHAKE_ACK en queue. Le `await asyncio.sleep(0.5)` avant PING donne du jeu.
- **Ne pas changer `TransportManager`** dans ce passage — la limitation à un serveur par scheme n'est pas bloquante, l'écoute sur 0.0.0.0 suffit.
