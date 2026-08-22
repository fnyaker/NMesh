# Guide de test — NMesh

## Tests unitaires

Rapides, sans réseau réel. Couvrent toute la logique interne, y compris le
fuzzing (aucun octet hostile ne crashe un parseur).

```bash
NMESH_SETUP_ONLY=1 ./start.sh   # installe tout, ne lance pas de nœud
. .venv/bin/activate
pytest
```

(`start.sh` installe aussi les dépendances de test ; il gère les distros qui
livrent `pip`/`venv` à part — voir [`Docs/Setup/guide`](Docs/Setup/guide).
À la main : `python3 -m venv .venv && . .venv/bin/activate &&
pip install -r requirements.txt`.)

Environ 1000 tests en ~20 secondes.

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
- Le routage **au-delà de la poignée de nœuds** (`test_routing_scale.py`) : un
  relais dont la table dépasse la falaise historique des 5 nœuds certifiés doit
  toujours répondre aux lookups, relayer ping/données/annuaire, apprendre le
  chemin retour sur une chaîne, et rester réactif sous des paquets adressés à
  des ids injoignables.
- La reprise **après redémarrage** sans ré-invitation (routage + sessions E2E
  restaurés depuis le disque).
- L'**auto-réparation** (purge d'un pair mort) et le trajet **app→mesh→app** via
  les connecteurs de données.
- L'**app de gestion sur mesh réel** (`tests/integration/test_fleet.py`) :
  enrôlement complet avec décision humaine puis commande autorisée, opérateur non
  enrôlé qui n'obtient rien, capability non accordée refusée, révocation qui
  coupe l'accès, et isolation de section (une autre app ne voit rien du trafic).

---

## CI

La CI GitHub (`.github/workflows/ci.yml`) exécute les tests unitaires puis
d'intégration à chaque push sur `main` et à chaque pull request.

Les tests tournent **dans l'image de base** (`docker/Dockerfile.base`, publiée
par `base-image.yml`), qui embarque déjà un **liboqs compilé** et toutes les
dépendances. On ne recompile donc plus la lourde bibliothèque C à chaque run, et
on teste sur le runtime exact que l'app embarque (Python 3.13). Si l'image de
base n'est pas joignable (premier bootstrap, ou PR de fork sans accès aux
paquets), la CI la construit une fois localement pour rester verte — même repli
que le job `docker`.

---

## Où sont les tests

```
tests/
├── test_packet.py / test_crypto.py / test_cert.py   — primitives
├── test_node.py / test_routing.py / test_handshake.py — nœud & routage
├── test_routing_stability.py                          — régressions de routage :
│     taille d'un FOUND_NODE, acquisition de route hors boucle de réception,
│     chemin retour appris du trafic, démontage borné
├── test_e2e.py / test_data.py                        — chiffrement E2E
├── test_invite*.py / test_trust.py                   — invitations & confiance
├── test_fuzz.py                                       — entrées hostiles
├── test_spool.py                                      — bundle & transport fichier
├── test_webconsole.py / test_data_connector.py       — console & connecteur
├── test_app_auth.py                                  — identité applicative :
│     scoping (app/audience/purpose/ctx), fraîcheur, anti-rejeu, liaison de clé,
│     parsing hostile, login mutuel
├── test_fleet*.py / test_console_fleet.py            — app de gestion : les trois
│     portes d'autorisation prises isolément (signature absente/modifiée/rejouée/
│     émise pour un autre nœud ou un autre purpose, émetteur non enrôlé,
│     capability absente), non-fuite des identifiants SSH, ledger qui échoue fermé
├── test_session_store.py                             — persistance (chiffrée)
├── test_start_script.py / test_install_script.py     — les deux scripts, sourcés
│     dont : environnement nu façon systemd (HOME absent, home inexistant ou non
│     inscriptible) et réutilisation de liboqs (cache, candidat inchargeable
│     jamais adopté, vérification à destination)
│     en mode bibliothèque (rien n'est installé) : distro, sudo, sonde venv pour
│     l'un ; détection d'init (systemctl sans systemd), privilèges, chemins,
│     création du compte système dédié, répertoires jamais donnés à root par
│     erreur, unités générées, copie d'arbre pour l'autre
├── test_updater.py                                    — mise à jour GitHub :
│     comparaison de versions, champs hostiles bornés, archive piégée (chemin
│     absolu, traversée, lien symbolique, fichier spécial), état et venv jamais
│     touchés, restauration après échec, dépôt épinglé
├── test_config.py                                     — fichier de configuration :
│     analyse hostile (ligne cassée, clé inconnue, fichier géant, octets
│     aléatoires, valeur qui tente d'ouvrir une seconde ligne), précédence,
│     réglages non éditables depuis la console, mode 0600, fusion installeur
├── test_docker_image_tree.py                          — l'image embarque ce que
│     le provisioning fleet exige (« no NMesh tree at /app »)
└── integration/                                       — nœuds réels (TCP + spool)
```
</content>
