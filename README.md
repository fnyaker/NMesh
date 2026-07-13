# NMesh

**Réseau mesh décentralisé, agnostique du transport, chiffré de bout en bout —
conçu pour fonctionner en territoire hostile.**

NMesh fait transiter des données entre nœuds sur *n'importe quel medium capable
de porter des octets* — TCP/IP, et aussi un répertoire partagé sur clé USB
(store-and-forward). Le routage est agnostique du transport : si A parle à B en
Bluetooth et B à C en Wi-Fi, A atteint C en passant par B. Tout est chiffré de
bout en bout avec de la cryptographie **post-quantique** ; les relais ne voient
jamais le contenu.

> Les principes directeurs (sécurité > solidité > flexibilité > rapidité,
> dépendances minimales) sont dans [`CLAUDE.md`](CLAUDE.md). L'état d'avancement
> est dans [`ROADMAP.md`](ROADMAP.md).

## Points clés

- **Post-quantique de bout en bout** — ML-KEM-768, ML-DSA-65, AES-256-GCM.
- **Agnostique du transport** — n'importe qui implémente un transport
  (`BaseTransport` / `BaseServer`) et l'enregistre par schéma d'URL.
- **Store-and-forward** — le mesh tourne aussi sur un répertoire/fichier
  (`spool://`), pour les liens hors-ligne ou à très forte latence.
- **Zéro crash / auto-réparation** — aucun paquet hostile ne fait tomber un
  nœud ; les pairs abusifs sont coupés, les liens morts purgés, les liens
  reconstruits à la demande.
- **PKI P2P auto-racinée** — invitations, chaînes de certificats, racines de
  confiance ; pas d'autorité centrale.
- **Persistance opt-in** — sessions et pairs survivent au redémarrage
  (chiffrés au repos).
- **Console web de gestion** + **connecteur de données** pour brancher des apps.
- **Dépendances minimales** — stdlib Python + `liboqs-python` + `cryptography`.

## Démarrage rapide

```bash
./start.sh                         # crée un venv, installe les deps, lance un nœud + console
```

Au premier lancement, le mot de passe de la console est **généré et affiché une
fois** — notez-le. Puis ouvrez l'URL affichée (console web en HTTPS).

Options utiles (tout argument est transmis au lanceur) :

```bash
./start.sh --connector-port 8790          # expose un connecteur pour brancher des apps
./start.sh --spool /mnt/usb/mesh          # ajoute un lien store-and-forward (clé USB)
./start.sh --console-host 0.0.0.0         # console accessible depuis le LAN
```

Sans le script, à la main :

```bash
pip install -r requirements.txt
python scripts/console_demo.py --data ./data
```

## Console web

Plan de **gestion** : graphe réseau, liste des pairs, débit temps réel, charge
du nœud, et actions (générer une invitation, rejoindre un réseau, faire
confiance à un certificat). HTTPS auto-signé, mot de passe haché (scrypt),
jetons Bearer, lockout anti-bruteforce, bind loopback par défaut.
→ [`Docs/WebConsole/guide`](Docs/WebConsole/guide)

## Brancher une application

Plan de **données** : une app (même hôte ou conteneur) se connecte au connecteur
et envoie/reçoit des messages E2E du mesh. Le nœud devient son pont réseau.
→ [`Docs/DataConnector/guide`](Docs/DataConnector/guide)

## Transports

Un transport = tout ce qui déplace des octets. Fournis :

| Schéma     | Medium                         | Usage                         |
|------------|--------------------------------|-------------------------------|
| `tcp://`   | TCP/IP                         | liens réseau classiques       |
| `udp://`   | UDP/IP (fiabilité + hole punch NAT) | liens directs derrière NAT |
| `spool://` | répertoire partagé / fichier   | store-and-forward, clé USB    |

Écrire le vôtre : [`Docs/Transports/guide`](Docs/Transports/guide) +
[`template.py`](Docs/Transports/template.py). Spool :
[`Docs/Transports/spool`](Docs/Transports/spool).

## Déploiements

### Docker (héberger un nœud-relais)

```bash
docker compose -f docker/docker-compose.yml up -d --build
```

Ouvre le port mesh `9000` (relais) ; la console reste sur le loopback de l'hôte
par défaut (voir les commentaires du compose pour l'exposer). L'état (identité,
certificats, sessions, mot de passe console) persiste dans le volume `/data`.
Image publiée sur GHCR à chaque tag (`ghcr.io/<owner>/nmesh`).

### Zipapp (`.pyz`)

```bash
python scripts/build_pyz.py          # produit nmesh.pyz
python nmesh.pyz --data ./data       # nécessite liboqs-python + cryptography installés
```

Un fichier unique embarquant le code NMesh. Note : la crypto native
(`liboqs-python`, `cryptography`) doit être installée dans l'interpréteur —
pour un artefact totalement autonome, préférez l'image Docker.

## Tests

```bash
pytest                     # tests unitaires (rapides, sans réseau)
pytest tests/integration   # intégration : nœuds réels (TCP + spool), crypto réelle
```

La CI GitHub lance les deux à chaque push/PR. Voir [`TEST.md`](TEST.md).

## Sécurité

Le modèle de menace : *dès qu'une donnée quitte le nœud, elle est en territoire
hostile*. Rien de ce qui arrive du réseau ou du disque n'est présumé fiable ;
tout est validé, borné, et rejeté par défaut. Le fuzzing prouve qu'aucun octet
hostile ne crashe un parseur. Détails et priorités : [`CLAUDE.md`](CLAUDE.md).

## Structure du projet

```
src/              cœur : nœud, crypto, paquets, routage, transports, console, connecteur
scripts/          console_demo.py (lanceur), build_pyz.py
docker/           image et compose du nœud-relais
Docs/             guides (transports, console, connecteur, format des paquets)
tests/            unitaires + tests/integration (nœuds réels)
```
</content>
