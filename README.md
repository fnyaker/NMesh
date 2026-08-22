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
- **Identité applicative (SSO)** — une app se sert de l'identité mesh du nœud pour
  authentifier ses pairs : assertions signées, scopées, fraîches, à usage unique.
- **Gestion de parc & déploiement** — app *Fleet* : enrôler des nodes avec
  capabilities, lire leur status, les mettre à jour, ouvrir un shell, découvrir
  le LAN et y installer NMesh par SSH.
- **Dépendances minimales** — stdlib Python + `liboqs-python` + `cryptography`.

## Démarrage rapide

```bash
./start.sh                         # crée un venv, installe les deps, lance un nœud + console
```

Sur une machine neuve, le script se débrouille seul : il détecte la distribution
(apt, dnf/yum, pacman, zypper, apk, xbps, Homebrew, FreeBSD, Termux), installe
ce qui manque — **y compris `pip`/`venv` quand la distro les livre à part
(Ubuntu, Debian, Alpine, Arch)** — et compile liboqs. La liste complète des cas
traités est dans [`Docs/Setup/guide`](Docs/Setup/guide).

Au premier lancement, le mot de passe de la console est **généré et affiché une
fois** — notez-le. Puis ouvrez l'URL affichée (console web en HTTPS).

Options utiles (tout argument est transmis au lanceur) :

```bash
./start.sh --connector-port 8790          # expose un connecteur pour brancher des apps
./start.sh --spool /mnt/usb/mesh          # ajoute un lien store-and-forward (clé USB)
./start.sh --console-host 0.0.0.0         # console accessible depuis le LAN
./start.sh --fleet                        # active l'app de gestion de parc (/fleet)
```

Vérifier une installation sans démarrer de nœud (utile en CI) :

```bash
NMESH_SETUP_ONLY=1 ./start.sh
```

Sans le script, à la main (dans un venv — depuis PEP 668, la plupart des distros
refusent d'installer dans le Python système) :

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
python scripts/nmesh_node.py --data ./data
```

## Installer durablement (méthode recommandée)

Pour une machine qui doit **héberger** un nœud, `install.sh` copie l'arbre dans
un emplacement durable, active le démarrage au boot (systemd, OpenRC ou
launchd) puis lance le nœud :

```bash
./install.sh                       # installe, active au boot, lance
./install.sh --fleet               # …et active l'app de gestion de parc
./install.sh --uninstall           # retire le service et les fichiers
```

Il ne réimplémente rien de `start.sh` : il lui délègue les dépendances et le
service qu'il écrit pointe sur `start.sh`, si bien qu'un nœud qui redémarre
revérifie et répare son installation. Relancer `install.sh` met à jour sur
place — **l'état du nœud n'est jamais touché**.

En root, le nœud reçoit un **compte système à lui** (`nmesh`, sans shell ni mot
de passe) qui possède seul l'installation et l'état, en mode 700 : la clé
d'identité n'est lisible par aucun autre compte de la machine. `--run-as root`
ou `--run-as quelquun` pour en décider autrement.

Le nœud sait aussi se mettre à jour depuis GitHub : console web →
**Settings → Updates**. La vérification est manuelle, l'installation demande
une confirmation qui nomme la version, et rien n'est jamais installé sans ce
clic. Détails : [`Docs/Setup/guide`](Docs/Setup/guide).

Docker reste possible (`docker/`), mais ce n'est plus la voie conseillée pour
une machine dédiée.

## Console web

Interface de gestion **responsive** (4 onglets : Vue d'ensemble, Apps, Connectivité,
Paramètres) :

- Vue d'ensemble : statut local, débit temps réel (graphique), **carte réseau
  cliquable** (cliquer sur un nœud ouvre une pop-up avec son ID complète),
  tableau des pairs actifs (direction, session, RTT, octets), topologie.
- Apps : apps installées + **store scalable** (catalogue paginé côté serveur,
  recherche, actions d'installation/désinstallation).
- Connectivité : nœuds actifs + connus/recherchables, affichage par défaut des
  20 plus récents (jusqu'à 100), clic pour détails.
- Paramètres : écouteurs, punch NAT, keepalive, AutoNAT, vérification réseau.

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

### Service système (recommandé)

`./install.sh` — voir [Installer durablement](#installer-durablement-méthode-recommandée)
ci-dessus.

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
scripts/          nmesh_node.py (lanceur), build_pyz.py
start.sh          installe les dépendances et lance un nœud depuis l'arbre courant
install.sh        installe l'arbre à demeure + service de démarrage, puis lance
docker/           image et compose du nœud-relais
Docs/             guides (installation, transports, console, connecteur, paquets)
tests/            unitaires + tests/integration (nœuds réels)
```
</content>
