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
│     capability absente), non-fuite des identifiants SSH, ledger qui échoue fermé,
│     et le relais console `manage` : chemins refusés (fleet, remote, chat, hors
│     API), découpage/réassemblage d'une réponse, réponse trop grande expliquée
│     plutôt que tronquée, réponse forgée par un tiers ignorée, appels bornés
├── test_fleet_deploy.py                               — déploiement distant et
│     droit d'update : le script autorisé n'est pas dans le préfixe du nœud, la
│     règle ne nomme qu'un chemin sans joker, le wrapper refuse tout argument,
│     le plan préfère le droit quand il existe, `NoNewPrivileges` est vu **avant**
│     de lancer sudo (et un nœud déjà root n'est pas concerné), et l'unité
│     systemd suit le droit accordé au lieu de le défaire ; plus, pour le déploiement :
│     install.sh voyage dans le payload et rien ne le réimplémente, aucun mot de
│     passe écrit dans un script, élévation dite et non sondée, ordre des
│     prompts (connexion puis élévation, jamais rejoué), refus d'un install
│     système sans route vers root
├── test_join_ticket.py / test_qr.py                   — ticket compact et QR :
│     aller-retour, casse et espaces indifférents, faute de frappe attrapée,
│     octets aléatoires qui ne lèvent que TicketError, nom d'hôte refusé ;
│     pour le QR, structure et bornes, plus — si l'outillage optionnel est
│     installé — égalité module par module avec un encodeur indépendant et
│     décodage réel du SVG rendu
├── test_console_auth.py                               — credential console :
│     mot de passe jamais stocké, sel par credential, fichier corrompu ou
│     algorithme inconnu refusés, entrée démesurée rejetée avant le hachage,
│     mode 0600 même sous umask permissif
├── test_trace.py                                      — trace protocolaire :
│     jamais de payload dans ce qui est gardé, anneau borné, arrêt automatique,
│     paquet malformé qui ne lève pas, débit calculé sur la fenêtre d'
│     enregistrement (pas sur la rafale), fichier en 0600
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
├── test_webassets.py                                  — les assets web, vérifiés
│     à la construction : le JS parse (une erreur de syntaxe = page blanche, pas
│     un test rouge), aucun `$("id")` ne vise un élément absent, aucune ressource
│     externe, aucun attribut `style=` (la CSP l'ignore en silence), et
│     l'émulateur de terminal relit ce qu'un vrai shell écrit
│     (`term_emulator_test.js`, exécuté sous node)
├── test_transport_options.py                          — configurer un transport
│     sans savoir ce qu'est un transport : coercition et bornes de chaque type
│     (bool/int/float/text/choice/multi), application partielle (un champ mauvais
│     ne jette pas les bons), SETTINGS remplacé et non muté, le fichier porte les
│     clés `schéma.option` sans les valider, section bornée, aller-retour
│     render/parse, et un réglage mal tapé est signalé au démarrage, jamais fatal
├── test_link_stats.py                                 — ce que le mesh donne à
│     voir : gigue qui distingue un lien stable d'un lien qui oscille, perte non
│     déduite d'une seule sonde, historique borné, statut par adresse (en service
│     > journal, « jamais essayée » ≠ « en panne »), journal borné sur deux axes,
│     et un transport qui lève ou rend n'importe quoi ne casse pas le snapshot
├── test_app_api.py                                    — la surface d'API des apps :
│     une opération non déclarée n'existe pas (même si la méthode est là), un
│     argument non déclaré est refusé et non ignoré, chaque valeur est coercée et
│     bornée, une app arrêtée n'est plus joignable, une app qui lève ne rend pas
│     ses internes — et ce que chat et fleet exposent est épinglé (élargir est un
│     changement de sécurité)
├── test_address_retry.py                              — redialer une adresse : à
│     la main (un `proto://addr` ou toutes, et on dit ce que chacune a fait ; une
│     adresse qui n'est pas celle de cette node est refusée sans composer), la
│     boucle périodique (la cadence appartient au medium, la passe est plafonnée
│     quel que soit le nombre de nodes en attente, une node déjà liée n'est jamais
│     redialée, et la boucle survit à un medium qui lève), et le pilotage par
│     latence (off tant qu'on ne l'a pas demandé, un gain marginal ne déplace
│     rien, un vrai gain déplace et ferme l'ancien lien, jamais deux liens vers
│     une même node après la mesure), et le système de priorités : bornes d'une
│     priorité, curseur latence↔priorité aux deux extrêmes, une adresse jamais
│     mesurée vaut le milieu, la latence courbe (une mesure absurde n'écrase pas
│     les écarts réels), l'ordre montré à l'opérateur est celui qui compose, et
│     un gestionnaire de transports qui ne sait pas répondre n'arrête rien
├── test_ui_contrast.py                                — jetons de couleur : ratio
│     WCAG de chaque paire texte/fond dans les deux thèmes, et aucune page ne
│     redéfinit un jeton du système
└── integration/                                       — nœuds réels (TCP + spool)
      dont test_idle_chatter.py : deux nœuds joints et inactifs restent
      silencieux (la boucle FIND_NODE/FOUND_NODE qui saturait le lien), et la
      découverte fonctionne toujours quand il y a vraiment quelque chose à
      trouver ; et test_join_ticket.py : join réel avec le seul ticket, usage
      unique, ticket expiré, code forgé, porte « adresse publique confirmée » ;
      et test_fleet.py qui fait traverser un vrai mesh à un appel console relayé
      (réponse de 90 Ko, donc plusieurs frames) et vérifie qu'il est refusé sans
      le grant `manage`
```
</content>
