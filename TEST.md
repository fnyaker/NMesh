# Guide de test — NMesh

## Tests unitaires

Rapides, sans réseau réel. Couvrent toute la logique interne, y compris le
fuzzing (aucun octet hostile ne crashe un parseur).

```bash
pip install -r requirements.txt
pytest
```

Environ 280 tests en ~20 secondes.

---

## Tests d'intégration

Nœuds réels, crypto post-quantique réelle, vraie pile réseau. Exclus par défaut
(voir `pyproject.toml`) ; à lancer explicitement :

```bash
pytest tests/integration
```

Ils vérifient notamment :
- Le flow complet invitation → handshake → session → data E2E, sur **TCP** et
  sur le transport **spool** (répertoire/fichier, sans socket).
- Le routage **multi-hop A→B→C** (les extrémités ne se parlent qu'à travers le
  relais), y compris sur deux médias fichier distincts.
- La reprise **après redémarrage** sans ré-invitation (routage + sessions E2E
  restaurés depuis le disque).
- L'**auto-réparation** (purge d'un pair mort) et le trajet **app→mesh→app** via
  les connecteurs de données.

---

## CI

La CI GitHub (`.github/workflows/ci.yml`) exécute les tests unitaires puis
d'intégration à chaque push sur `main` et à chaque pull request.

---

## Où sont les tests

```
tests/
├── test_packet.py / test_crypto.py / test_cert.py   — primitives
├── test_node.py / test_routing.py / test_handshake.py — nœud & routage
├── test_e2e.py / test_data.py                        — chiffrement E2E
├── test_invite*.py / test_trust.py                   — invitations & confiance
├── test_fuzz.py                                       — entrées hostiles
├── test_spool.py                                      — bundle & transport fichier
├── test_webconsole.py / test_data_connector.py       — console & connecteur
├── test_session_store.py                             — persistance (chiffrée)
└── integration/                                       — nœuds réels (TCP + spool)
```
</content>
