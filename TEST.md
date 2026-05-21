# Guide de test — NMesh

## Tests unitaires

Tests rapides, sans réseau réel ni Docker. Couvrent toute la logique interne.

```bash
pip install -r requirements.txt
pytest
```

Résultat attendu : ~100 tests en < 10 secondes.

---

## Tests d'intégration locaux

Tests avec deux nœuds TCP réels sur localhost. Crypto réelle, réseau réel.
Plus lents que les tests unitaires (~30 secondes).

```bash
pytest tests/integration/
```

Ces tests vérifient :
- Le flow complet invitation → handshake → session AES-256-GCM
- L'envoi/réception de données chiffrées
- Le rejet d'un mauvais code d'invitation
- L'usage unique du code d'invitation

---

## Tests Docker (réseau multi-containers)

Simule un vrai réseau maillé avec 3 nœuds distincts dans des containers isolés.

### Prérequis

- Docker
- Docker Compose

### Lancer les tests

```bash
cd docker
docker-compose up --build --abort-on-container-exit
```

`--abort-on-container-exit` arrête tout dès qu'un container se termine.
Le code de sortie global reflète le succès ou l'échec.

### Ce qui se passe

1. `node_a` démarre, génère un code d'invitation, l'écrit dans `/data/invite_code`
2. `node_b` et `node_c` lisent le code et rejoignent `node_a`
3. Chaque guest envoie un message à `node_a`
4. `node_a` affiche les messages reçus dans ses logs

### Lire les logs

```bash
docker-compose logs node_a
docker-compose logs node_b
docker-compose logs node_c
```

### Nettoyer

```bash
cd docker
docker-compose down -v
```

---

## Structure des tests

```
tests/
├── test_packet.py          — sérialisation / validation des paquets
├── test_tcp_transport.py   — transport TCP (framing, send/receive)
├── test_transport_manager.py — gestion du transport
├── test_node_id.py         — ID Kademlia (génération, distance XOR)
├── test_routing.py         — k-buckets, routing table
├── test_node.py            — MeshNode (PING, FIND_NODE, bootstrap)
├── test_crypto.py          — ML-KEM, ML-DSA, AES-256-GCM
├── test_handshake.py       — handshake complet entre deux nœuds
├── test_data.py            — envoi/réception de données chiffrées
├── test_invite.py          — InviteManager (HMAC, expiration, rate limiting)
├── test_invite_flow.py     — flow invitation dans MeshNode
└── integration/
    └── test_local.py       — tests end-to-end sur TCP localhost
```
