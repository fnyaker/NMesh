# NMesh — Audit de sécurité

Date : 2026-05-21
Relecture indépendante de tout le code source avec mentalité "une armée essaie de casser chaque ligne".

---

## CRITIQUES — bloquant, à corriger avant tout autre développement

### C1. Le forwarding DATA est cassé (crypto incompatible)

**Localisation :** [src/node.py:258-273](src/node.py#L258-L273), [src/node.py:303-307](src/node.py#L303-L307)

Le `_forward_packet` retransmet le paquet DATA chiffré tel quel (juste TTL-1). Mais :

- A chiffre DATA avec la session `(A↔B)`
- B forward à C
- C tente de déchiffrer avec la session `(B↔C)`
- **Le GCM tag ne correspond pas** → `CryptoError` jeté

C ne peut **pas** lire des DATA chiffrés par A. Le multi-hop ne fonctionne pas.

**Pire :** `_handle_data` ne catch pas `CryptoError`. La boucle `_loop` ne catch que `IncompleteReadError`/`ConnectionError`/`CancelledError`. **L'exception remonte et tue silencieusement la boucle de réception du peer.** Le peer devient un zombie.

**Fix nécessaire :** soit
- chiffrement de bout en bout (session A↔C via KEM handshake routé) — préférable
- soit onion routing

Et catch `CryptoError` dans `_loop` ou `_handle_data`.

---

### C2. Bypass total de l'invitation via INVITE_ACK non sollicité

**Localisation :** [src/node.py:357-360](src/node.py#L357-L360)

```python
async def _handle_invite_ack(self, peer: _Peer, packet: Packet) -> None:
    if packet.payload[0] == _ACK_ACCEPTED:
        peer.join_code = None
        await self.initiate_handshake(peer)
```

Aucune vérification qu'on a réellement envoyé un INVITE. Un attaquant peut :

1. Se connecter au serveur
2. Recevoir CHALLENGE (qu'il ignore)
3. **Envoyer directement INVITE_ACK avec payload = `\x00`**
4. Le serveur appelle `initiate_handshake(peer)` → envoie HANDSHAKE
5. L'attaquant répond avec un HANDSHAKE_ACK valide (sa propre identité)
6. Trust table ajoute l'attaquant comme premier-contact TOFU
7. Session établie — **l'attaquant a rejoint le réseau sans aucun code**

**Fix :** ajouter `peer.invite_sent: bool` mis à `True` uniquement par `_handle_challenge` côté client, vérifier dans `_handle_invite_ack`.

---

### C3. HANDSHAKE non lié à la connexion — relay/replay possible

**Localisation :** [src/node.py:362-382](src/node.py#L362-L382)

Le HANDSHAKE signe `kem_pub + dsa_pub`. Aucune partie de la signature n'est liée à la connexion TCP actuelle.

**Attaque :** Eve capture une HANDSHAKE légitime émise par Alice (sur n'importe quelle connexion historique). Eve ouvre une nouvelle connexion à Bob et rejoue ce HANDSHAKE. Bob :
- Vérifie signature ✓ (c'est bien la signature d'Alice)
- Vérifie `hash(dsa_pub) == src_id` ✓
- Pour un routing peer, trust table contient déjà Alice → accepte
- Établit une session avec Eve, **croyant parler à Alice**

Eve ne peut pas lire (KEM secret est à Alice), mais elle peut :
- Faire trou noir sur le trafic vers Alice
- Recevoir des paquets destinés à Alice et les drop
- Polluer la routing table de Bob avec une fausse adresse pour Alice (via PING — voir H1)

**Fix :** le CHALLENGE envoyé à l'ouverture doit être inclus dans la signature du HANDSHAKE. Pour les routing peers, il faut un challenge symétrique au moment de la connexion.

---

### C4. Routing connections impossibles à bootstrap

**Localisation :** [src/node.py:371](src/node.py#L371)

```python
if not peer.invite_accepted and not self._trust.contains(claimed_id):
    return
```

Pour qu'un routing peer (sans invite) soit accepté, il faut que son ID soit déjà dans la trust table. Or la trust table ne grandit que via des handshakes réussis. **Si A et C n'ont jamais fait de handshake direct, C rejettera toujours la connexion routing de A**, même si A et C connaissent tous les deux B.

→ Le mode "routing peer" est en pratique inutilisable. La trust table doit être peuplée par un autre canal (FOUND_NODE devrait inclure la clé publique DSA, pas juste NodeID+adresse).

**Fix :** `NodeEntry` doit inclure `dsa_pub`. FOUND_NODE inclut les clés publiques signées. On peuple trust table à partir d'entrées FOUND_NODE provenant de pairs déjà authentifiés (transitivité de confiance).

---

### C5. `CryptoError`, `UnicodeDecodeError`, `IndexError` et `ValueError` ne sont pas catchés

**Localisation :** [src/node.py:102-108](src/node.py#L102-L108)

```python
async def _loop(self, on_packet) -> None:
    try:
        while True:
            packet = await self.transport.receive()
            await on_packet(self, packet)
    except (asyncio.IncompleteReadError, ConnectionError, asyncio.CancelledError):
        pass
```

Beaucoup d'exceptions remontent et tuent la boucle :

- `CryptoError` dans `_handle_data` (déchiffrement)
- `UnicodeDecodeError` dans `_handle_ping` (`packet.payload.decode()`)
- `UnicodeDecodeError` dans `_decode_entries` (`address.decode()`)
- `IndexError` dans `_decode_entries` (`data[0]` si payload vide)
- `IndexError` dans `_handle_invite_ack` (`packet.payload[0]` si payload vide)
- `ValueError` dans `NodeID(packet.payload)` dans `_handle_find_node` (taille ≠ 20)
- `struct.error` dans tous les `unpack_from` si data trop court
- `PacketError` si un paquet est invalide à la désérialisation

**Un attaquant authentifié peut tuer la boucle de chacun de ses peers en envoyant un paquet malformé.**

**Fix :** catch large dans `_loop`, ou validation stricte à l'entrée de chaque handler.

---

## HAUTES — exploitables, à corriger rapidement

### H1. Address poisoning via PING

**Localisation :** [src/node.py:309-314](src/node.py#L309-L314)

```python
async def _handle_ping(self, peer: _Peer, packet: Packet) -> None:
    src = NodeID(packet.src_id)
    address = packet.payload.decode()
    self._routing.add(src, address)
```

L'adresse stockée vient du payload du peer, pas du socket réel. **Un peer authentifié peut s'enregistrer avec n'importe quelle adresse** — par exemple celle d'un autre nœud légitime pour rediriger le trafic ou créer du chaos.

**Fix :** utiliser l'adresse réelle du socket TCP. Ou exiger que l'adresse annoncée soit signée et corresponde à un challenge connexion-bound.

---

### H2. Routing table poisoning via FOUND_NODE

**Localisation :** [src/node.py:326-329](src/node.py#L326-L329)

```python
async def _handle_found_node(self, peer: _Peer, packet: Packet) -> None:
    entries = _decode_entries(packet.payload)
    for entry in entries:
        self._routing.add(entry.node_id, entry.address)
```

Aucune validation. Un pair authentifié peut envoyer des entrées `(NodeID_X, attacker_address)` arbitraires. La routing table est polluée. Quand on tente `_connect_routing(NodeID_X)`, on dial l'attaquant.

L'attaquant ne peut pas passer le handshake (pas de clé privée), donc pas de breach de session, mais :
- DoS sur la disponibilité de NodeID_X
- Possibilité combinée avec C3 (relay handshake)

**Fix :** FOUND_NODE doit transporter `(NodeID, address, dsa_pub, signature_from_vouching_node)` — chaque entrée est signée par le pair authentifié qui la transmet.

---

### H3. msg_id est un CRC32 — collisions possibles

**Localisation :** [src/packet.py:64-74](src/packet.py#L64-L74)

```python
def compute_msg_id(self) -> int:
    ...
    return zlib.crc32(data) & 0xFFFFFFFF
```

CRC32 n'est pas cryptographique. Collisions calculables par construction. Un attaquant peut :
- Forger un paquet ayant le **même msg_id** qu'un paquet à venir → le forwarding va dropper le paquet légitime (le paquet attaquant est "vu" en premier)
- **Censure ciblée** d'un message dans le réseau

**Fix :** utiliser SHA-256[:8] ou BLAKE2b — résistant aux collisions, 64 bits suffisent largement.

---

### H4. Pas de timeout sur la lecture TCP — Slow Loris

**Localisation :** [src/tcp_transport.py:50-54](src/tcp_transport.py#L50-L54)

```python
async def receive(self) -> Packet:
    length = _FRAME.unpack(await self._reader.readexactly(_FRAME.size))[0]
    return Packet.unpack(await self._reader.readexactly(length))
```

Si un attaquant envoie le préfixe `length=65535` mais n'envoie jamais les données, `readexactly` bloque indéfiniment. Chaque connexion → un fd + une coroutine + 65 KB de buffer alloués. Multiplier par N connexions → épuisement des ressources.

**Fix :** `asyncio.wait_for(..., timeout=N)` autour des reads, fermer la connexion sur timeout.

---

### H5. Pas de limite sur le nombre de connexions

**Localisation :** [src/node.py:219-227](src/node.py#L219-L227)

`_on_new_transport` accepte sans bornes — chaque connexion alloue un `_Peer`, une tâche asyncio, un challenge, un buffer.

**Fix :** limite `max_peers` configurable, rejet par DROP/RST des nouvelles connexions au-delà.

---

### H6. Rate limit d'invitation est GLOBAL

**Localisation :** [src/invite.py:56-64](src/invite.py#L56-L64), [src/node.py:341-355](src/node.py#L341-L355)

```python
if not self._invite.verify_response(peer.pending_challenge, packet.payload):
    self._invite.record_failure()
```

3 échecs → lockout 60s **pour tout le monde**. Un attaquant fait 3 essais foireux → tous les guests légitimes sont bloqués pendant 60s.

**Fix :** rate limit par adresse source (IP) ou par `_Peer`, pas global.

---

### H7. Trust table non persistée

**Localisation :** [src/trust.py](src/trust.py)

Toute la trust table est en mémoire. Au redémarrage du nœud, **toutes les preuves d'identité sont perdues** — le TOFU recommence à zéro. Un attaquant qui s'aligne avec un redémarrage peut substituer l'identité de n'importe quel pair (premier contact = lui).

**Fix :** persister sur disque (JSON ou SQLite), charger au démarrage.

---

### H8. Pas de dédup pour les DATA reçues localement

**Localisation :** [src/node.py:281-286](src/node.py#L281-L286)

Le `_is_seen` n'est consulté que dans `_forward_packet`. Si je suis le destinataire final (`dst_id == my_id`), le paquet n'est pas dédupliqué localement. **Replay attack possible** : un attaquant ré-injecte une DATA chiffrée capturée → je la traite deux fois.

GCM n'est pas un anti-replay, juste une intégrité+confidentialité.

**Fix :** consulter `_is_seen` aussi pour les paquets locaux dans `_handle_packet`.

---

## MOYENNES — à traiter dans les itérations suivantes

### M1. KEM secret non zéroïsé après usage

[src/node.py:209-217](src/node.py#L209-L217), [src/node.py:399](src/node.py#L399)

`peer.pending_kem_secret = None` ne wipe pas la mémoire — l'octet reste en heap Python. Faible impact (process Python n'est pas un environnement secure de toute façon) mais bonne hygiène.

### M2. Eclipse attack possible

Pas de stratégie spécifique de diversification de buckets. Un attaquant qui contrôle suffisamment de nœuds proches d'un ID cible peut le couper du reste.

### M3. Pas de heartbeat / detection de peer mort

Pas de PING périodique. Un peer dont la connexion meurt (sans FIN) reste dans `_peers` indéfiniment. `_handle_pong` est vide — aucune mise à jour de liveness.

### M4. Validation des champs version et type des paquets manquante

[src/packet.py:54-62](src/packet.py#L54-L62)

`unpack` ne valide pas `version` ni `type`. Type inconnu silencieusement drop (OK), mais version inconnue → décodages potentiellement bogués sans erreur.

### M5. Le challenge n'est pas binaire-aléatoire si attaquant a accès au PRNG

`os.urandom(32)` est cryptographiquement sûr sur Linux/macOS. OK en pratique mais à documenter.

### M6. Aucune protection contre l'amplification

Un peer authentifié envoie un FIND_NODE → on répond avec jusqu'à 20 entrées (gros payload). Pas de rate limit. Amplification possible si on imagine un futur transport UDP.

---

## BASSES — annotations, pas de fix urgent

### L1. `_handle_pong` est vide — devrait au moins toucher un timestamp peer

### L2. `_handle_invite_ack` ne valide pas la taille du payload avant `payload[0]` → IndexError (déjà couvert par C5)

### L3. `_handle_data` ne valide pas que `peer.session is not None` *avant* de chercher à décoder — c'est OK puisqu'on retourne immédiatement, mais documenter

### L4. La gestion d'erreur dans `_loop` swallow `CancelledError` — peut masquer des bugs lors du shutdown

### L5. Le constructeur de `Packet` valide la taille du payload (`> 60000`) mais TCP `_FRAME` est `!H` (max 65535) — peut être un mismatch silencieux

---

## Récapitulatif — ordre d'attaque recommandé

1. **C2** : ferme le trou béant de bypass d'invitation (état `invite_sent`)
2. **C5** : catch les exceptions dans `_loop` ou valide les entrées strictement
3. **C1** : décide du modèle de chiffrement multi-hop (E2E ou hop-by-hop) et implémente
4. **C3** : lie la signature HANDSHAKE au challenge de connexion
5. **C4** : redessine FOUND_NODE pour transporter les clés publiques signées, peupler trust table par transitivité
6. **H1, H2** : poisoning fixes
7. **H3** : msg_id cryptographique
8. **H4, H5, H6** : DoS hardening
9. **H7** : persistance trust table
10. **H8** : dedup local
11. **Mediums et lows**
