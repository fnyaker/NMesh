# NMesh — Connexion à la demande (Roadmap point 3) — Plan détaillé pour Sonnet

## Context

La roadmap demande, point 3 : « Quand on doit forwarder vers un nœud non directement connecté → chercher l'adresse dans la routing table, ouvrir un nouveau transport, attendre l'établissement de session, puis forwarder le paquet ».

Aujourd'hui, [src/node.py](src/node.py) :
- `_route_outbound` (l.456) et `_forward_packet` (l.544) sélectionnent le peer authentifié le plus proche du `dst_id` en XOR puis envoient. Si aucun peer authentifié n'existe → **drop silencieux**.
- `_connect_routing` (l.501) sait ouvrir un transport vers un `node_id` connu de la routing table — mais **n'est jamais appelé**. Il retourne le `_Peer` immédiatement après `peer.start()`, sans attendre l'auth.
- `find_node` (l.437) est fire-and-forget : broadcast FIND_NODE, pas de mécanisme pour attendre les FOUND_NODE.

Décisions validées avec l'utilisateur :
1. **Trigger** : mix policy — direct si peer existe, sinon forwarding multi-hop classique, sinon on-demand.
2. **Portée** : à câbler dans `_route_outbound` ET `_forward_packet`.
3. **Lookup miss** : si la cible n'est pas dans la routing table, déclencher un FIND_NODE Kademlia puis retry.

Le résultat attendu : un nœud peut envoyer/forwarder vers n'importe quel pair connu transitivement, sans dépendance à une connaissance préalable du réseau.

---

## 1. Vue d'ensemble

Le cœur est un nouveau helper `_ensure_route_to(target, timeout) -> _Peer | None` qui :
1. Retourne un peer direct `authenticated_id == target` si existant.
2. Sinon, déclenche au besoin une connexion on-demand vers `target` et attend qu'elle soit authentifiée.
3. Si `target` n'est pas dans la routing table, déclenche d'abord un `_kademlia_lookup` Kademlia (broadcast FIND_NODE + petite attente) pour la peupler, puis re-tente l'on-demand.
4. Garantit qu'une seule tentative concurrente existe pour un `target` donné (via `asyncio.Event` partagé).

`_route_outbound` et `_forward_packet` conservent leur logique actuelle (direct / forwarding par peer le plus proche) ET, dans la branche « pas de candidat → drop », appellent désormais `_ensure_route_to` avant d'abandonner.

---

## 2. État ajouté à `MeshNode.__init__`

Après les `self._e2e_*` :
```python
self._pending_connections: dict[NodeID, asyncio.Event] = {}
self._pending_lookups: dict[NodeID, asyncio.Event] = {}
```

Constantes à ajouter en haut du fichier (à côté de `_MSG_DEDUP_MAX`) :
```python
_ON_DEMAND_TIMEOUT     = 5.0   # ouverture transport + handshake
_KAD_LOOKUP_TIMEOUT    = 3.0   # un round de FIND_NODE
_KAD_LOOKUP_MAX_ROUNDS = 2     # iterations max du lookup
_AUTH_POLL_INTERVAL    = 0.05  # cadence de polling pour wait_for_*
```

---

## 3. Helper `_wait_for_peer_authenticated`

Polling sur un peer spécifique (pas tous comme `wait_for_session`) :

```python
async def _wait_for_peer_authenticated(self, peer: _Peer,
                                        target: NodeID,
                                        timeout: float) -> bool:
    """Returns True once peer.authenticated_id == target AND peer.session is set,
    False if timeout elapses or the peer disappears."""
    deadline = asyncio.get_event_loop().time() + timeout
    while True:
        if peer not in self._peers:
            return False
        if peer.authenticated_id == target and peer.session is not None:
            return True
        if asyncio.get_event_loop().time() >= deadline:
            return False
        await asyncio.sleep(_AUTH_POLL_INTERVAL)
```

Cohérent avec le style existant (`wait_for_session` l.410, polling 50ms).

---

## 4. Helper `_kademlia_lookup`

Demande aux peers actuellement authentifiés de chercher `target`, attend que la routing table se peuple. Retourne True si `target` apparaît dans la routing table dans le délai.

```python
async def _kademlia_lookup(self, target: NodeID, timeout: float) -> bool:
    """Iterative-ish FIND_NODE. Returns True if target appears in routing table."""
    # Coalesce concurrent lookups
    existing = self._pending_lookups.get(target)
    if existing is not None:
        try:
            await asyncio.wait_for(existing.wait(), timeout=timeout)
        except asyncio.TimeoutError:
            pass
        return self._routing.contains(target)

    event = asyncio.Event()
    self._pending_lookups[target] = event
    try:
        seen_peers: set[bytes] = set()
        deadline = asyncio.get_event_loop().time() + timeout
        for _ in range(_KAD_LOOKUP_MAX_ROUNDS):
            if self._routing.contains(target):
                return True
            # Send FIND_NODE to authenticated peers we haven't queried this round
            queried = 0
            for p in list(self._peers):
                if p.authenticated_id is None or p.session is None:
                    continue
                if p.authenticated_id.raw in seen_peers:
                    continue
                seen_peers.add(p.authenticated_id.raw)
                pkt = Packet.create(FIND_NODE, self._id.raw,
                                    NodeID(b"\xff" * 20).raw, target.raw)
                try:
                    await p.send(pkt)
                    queried += 1
                except Exception:
                    pass
            if queried == 0:
                break
            # Wait for routing table to grow (or timeout)
            sub_deadline = min(deadline,
                               asyncio.get_event_loop().time() + _KAD_LOOKUP_TIMEOUT)
            while asyncio.get_event_loop().time() < sub_deadline:
                if self._routing.contains(target):
                    return True
                await asyncio.sleep(_AUTH_POLL_INTERVAL)
        return self._routing.contains(target)
    finally:
        event.set()
        self._pending_lookups.pop(target, None)
```

Détails :
- 2 rounds maximum : (1) interroger peers connus, (2) interroger peers nouvellement découverts.
- Coalesce : si un lookup pour `target` est déjà en cours, on attend son résultat plutôt que d'en relancer un.
- `_handle_found_node` (déjà existant l.634) peuple la routing table automatiquement à la réception → pas de modif nécessaire de ce handler.

---

## 5. Helper principal `_ensure_route_to`

C'est l'API qu'utilisent `_route_outbound` / `_forward_packet` quand leur logique standard n'a pas trouvé de chemin.

```python
async def _ensure_route_to(self, target: NodeID,
                            timeout: float = _ON_DEMAND_TIMEOUT) -> _Peer | None:
    """Open or reuse a direct peer to `target`. Returns the authenticated peer
    or None if no route can be established within `timeout`."""
    if target == self._id:
        return None

    # 1. Already directly connected?
    existing = next(
        (p for p in self._peers
         if p.authenticated_id == target and p.session is not None),
        None,
    )
    if existing is not None:
        return existing

    # 2. Coalesce concurrent attempts
    pending = self._pending_connections.get(target)
    if pending is not None:
        try:
            await asyncio.wait_for(pending.wait(), timeout=timeout)
        except asyncio.TimeoutError:
            return None
        return next(
            (p for p in self._peers
             if p.authenticated_id == target and p.session is not None),
            None,
        )

    event = asyncio.Event()
    self._pending_connections[target] = event
    try:
        # 3. Routing table miss → Kademlia lookup
        if not self._routing.contains(target):
            await self._kademlia_lookup(target, _KAD_LOOKUP_TIMEOUT * _KAD_LOOKUP_MAX_ROUNDS)
            if not self._routing.contains(target):
                return None

        # 4. Open transport
        peer = await self._connect_routing(target)
        if peer is None:
            return None

        # 5. Wait for handshake to complete
        ok = await self._wait_for_peer_authenticated(peer, target, timeout)
        if not ok:
            # Best-effort cleanup
            try:
                await peer.stop()
            except Exception:
                pass
            if peer in self._peers:
                self._peers.remove(peer)
            return None

        return peer
    finally:
        event.set()
        self._pending_connections.pop(target, None)
```

Notes :
- L'ordre `lookup → connect → wait` est important : sans entrée dans la routing table, `_connect_routing` renvoie None immédiatement.
- En cas d'échec d'auth (chain pas vérifiable, transport mort), on retire le peer et on retourne None.
- Le timeout total approximatif : `lookup (≤ 6s)` + `connect + auth (≤ 5s)` ≈ 11s. Acceptable pour un cold-start ; les appels suivants ré-utilisent le peer.

---

## 6. Modifications de `_route_outbound`

```python
async def _route_outbound(self, packet: Packet) -> None:
    target = NodeID(packet.dst_id)
    direct = next(
        (p for p in self._peers
         if p.authenticated_id == target and p.session is not None),
        None,
    )
    if direct is not None:
        await direct.send(packet)
        return
    candidates = [p for p in self._peers
                  if p.authenticated_id is not None and p.session is not None]
    if candidates:
        best = min(candidates, key=lambda p: target.distance(p.authenticated_id))
        await best.send(packet)
        return
    # No forwarding candidate → on-demand
    peer = await self._ensure_route_to(target)
    if peer is not None:
        await peer.send(packet)
```

---

## 7. Modifications de `_forward_packet`

```python
async def _forward_packet(self, from_peer: _Peer, packet: Packet) -> None:
    if packet.ttl <= 1:
        return
    target = NodeID(packet.dst_id)
    candidates = [
        p for p in self._peers
        if p is not from_peer
        and p.authenticated_id is not None
        and p.session is not None
    ]
    if candidates:
        best = min(candidates, key=lambda p: target.distance(p.authenticated_id))
        await best.send(packet.with_decremented_ttl())
        return
    # No forwarding candidate → on-demand to target
    peer = await self._ensure_route_to(target)
    if peer is not None and peer is not from_peer:
        await peer.send(packet.with_decremented_ttl())
```

Remarque : ce changement transforme `_forward_packet` en opération potentiellement longue (jusqu'à 11s). Comme il est `await`-é depuis `_handle_packet`, ça peut ralentir le traitement de paquets suivants sur le même peer. Pour cette première itération c'est acceptable — chaque peer a sa propre task (`_Peer._loop`), donc seule cette task est bloquée.

---

## 8. Fichiers modifiés

- **[src/node.py](src/node.py)** — toutes les modifications ci-dessus (constantes, état `__init__`, 3 nouveaux helpers, modif `_route_outbound`, `_forward_packet`).

Aucun changement requis dans :
- [src/routing.py](src/routing.py) — `RoutingTable.contains()` existe déjà.
- [src/cert_store.py](src/cert_store.py) — la chaîne du peer cible est validée par le flux handshake standard.
- Codecs / packet — FIND_NODE existe déjà.

---

## 9. Tests à ajouter

Nouveau fichier [tests/test_on_demand_routing.py](tests/test_on_demand_routing.py).

Pour simuler des `transport_manager.connect()` qui aboutissent à un peer authentifié, on étend le pattern de [tests/conftest.py](tests/conftest.py) : un `FakeTransportManager` ou un fixture qui, lors d'un `connect("fake://target")`, crée une paire de `FakeTransport` et la branche sur un `MeshNode` cible (jouant le rôle de serveur).

### 9.1 `_ensure_route_to`
- `test_ensure_route_returns_existing_peer` : peer déjà authentifié → retourné direct sans `_connect_routing`.
- `test_ensure_route_opens_connection_when_in_routing` : routing table contient target, pas de peer → connect + auth complet → peer retourné.
- `test_ensure_route_triggers_lookup_when_target_unknown` : routing table vide pour target → FIND_NODE déclenché, FOUND_NODE injecté, target apparaît → connect réussit.
- `test_ensure_route_returns_none_on_lookup_miss` : target inconnu et FIND_NODE ne ramène rien → None.
- `test_ensure_route_coalesces_concurrent_calls` : deux appels parallèles pour le même target → un seul `_connect_routing`.
- `test_ensure_route_cleans_up_on_handshake_timeout` : transport s'ouvre mais le serveur ne répond pas → peer retiré, None retourné.

### 9.2 Intégration `_route_outbound`
- `test_route_outbound_falls_back_to_on_demand` : aucun peer authentifié, target dans routing table → on-demand → DATA envoyé via le nouveau peer.

### 9.3 Intégration `_forward_packet`
- `test_forward_packet_falls_back_to_on_demand` : un peer A connecté à B, B reçoit un paquet pour C, n'a pas de peer pour C, mais a C dans sa routing table → B ouvre transport vers C, forward.

### 9.4 Kademlia lookup
- `test_kademlia_lookup_populates_routing_table` : seed une chaîne d'entries via FOUND_NODE, vérifie que `_kademlia_lookup` ramène target.
- `test_kademlia_lookup_max_rounds_respected` : si target jamais retourné → s'arrête après 2 rounds, retourne False.

---

## 10. Ordre d'exécution pour Sonnet

1. Ajouter les constantes `_ON_DEMAND_TIMEOUT`, `_KAD_LOOKUP_*`, `_AUTH_POLL_INTERVAL`.
2. Ajouter l'état `_pending_connections` / `_pending_lookups` dans `__init__`.
3. Implémenter `_wait_for_peer_authenticated`.
4. Implémenter `_kademlia_lookup`.
5. Implémenter `_ensure_route_to`.
6. Modifier `_route_outbound` (ajout du fallback final).
7. Modifier `_forward_packet` (ajout du fallback final).
8. Créer le fixture de test (FakeTransportManager bidirectionnel) — modifier [tests/conftest.py](tests/conftest.py).
9. Créer [tests/test_on_demand_routing.py](tests/test_on_demand_routing.py) avec les tests listés.
10. Vérifier que la suite complète (`pytest tests/ -q`) passe sans régression.

---

## 11. Points de vigilance

- **Re-entrance** : `_ensure_route_to` peut être appelé depuis `_forward_packet` qui tourne dans la task d'un peer. Bien vérifier qu'on ne se ré-appelle pas via `_route_outbound` (qui appellerait à son tour `_ensure_route_to`) — possible boucle si la cible est nous-mêmes. Le check `if target == self._id: return None` au début prévient ça.
- **Peer self-removed** : si un peer disparaît pendant le polling, `_wait_for_peer_authenticated` doit retourner False (check `peer not in self._peers`).
- **Auth réussit mais sur la mauvaise identité** : le check `peer.authenticated_id == target` après l'auth garantit qu'on a bien atteint la cible. Si le serveur s'annonce avec une autre identité (chain valide mais ID différent), on rejette.
- **Concurrence** : `_pending_connections[target]` et `_pending_lookups[target]` doivent toujours être nettoyés dans un `finally` — sinon les appelants suivants s'attendent indéfiniment.
- **Limite `_MAX_PEERS`** : `_connect_routing` peut potentiellement faire dépasser 128 peers. On ne fait rien de spécial cette itération — `_on_new_transport` a un cap côté serveur mais pas côté client. À surveiller pour une future itération (eviction LRU).
- **Cert store cohérence** : on suppose que si target est dans la routing table, sa chaîne y a été validée à la réception (déjà fait dans `_handle_found_node` l.634). Donc l'auth de la connexion on-demand a toutes les chances de réussir.
- **Pas dans le scope** : retry/backoff, healthcheck des peers, eviction adaptative, multipath, optimisation du choix d'adresse (latence).

---

## 12. Vérification end-to-end

Après implémentation :
1. `python -m pytest tests/ -q` → tous les tests passent (anciens + nouveaux on-demand).
2. Test manuel scénario 3 nœuds (modèle [tests/test_e2e.py](tests/test_e2e.py) `_make_chain`) : A connaît B et C dans sa routing table, **pas** de peer authentifié, envoi DATA vers C → A ouvre transport on-demand, handshake, E2E handshake (cf. plan E2E), data décodé chez C.
3. Pour valider la branche FIND_NODE : 4 nœuds A↔B↔C, A connaît B mais pas D ; C connaît D ; A doit pouvoir envoyer à D (FIND_NODE via B remonte D dans la routing table de A, puis on-demand vers D).
