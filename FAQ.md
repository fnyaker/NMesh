# FAQ — les pannes qu'on rencontre vraiment

Les symptômes exacts, ce qu'ils veulent dire, et la commande qui les répare.
Chaque entrée part du message que vous avez sous les yeux.

Pour le reste : [`Docs/Setup/guide`](Docs/Setup/guide) (installation),
[`Docs/WebConsole/guide`](Docs/WebConsole/guide) (console),
[`Docs/Apps/fleet`](Docs/Apps/fleet) (gestion à distance),
[`Docs/Architecture/gotchas.md`](Docs/Architecture/gotchas.md) (pièges internes).

---

## Mises à jour

### `sudo: The "no new privileges" flag is set, which prevents sudo from running as root`

**Quand :** vous cliquez **Update** sur une node gérée (capability `update`).

**Ce qui se passe.** L'unité systemd que `install.sh` écrit est durcie, et une
des directives est `NoNewPrivileges=yes`. Le noyau refuse alors **tout binaire
setuid** pour ce processus et tous ses enfants, pour toujours — `sudo` en fait
partie. Le droit d'update existe bien (le wrapper root, la règle sudoers), il
est simplement inutilisable depuis ce processus-là. Deux durcissements du même
projet se contredisaient.

**Le correctif.** Sur la machine concernée :

```bash
cd /opt/nmesh            # ou votre préfixe d'installation
sudo ./install.sh --allow-update
```

L'unité est réécrite avec une confinement compatible avec le droit accordé, et
le service redémarre. Vérifier :

```bash
systemctl cat nmesh | grep -E 'NoNewPrivileges|ProtectSystem'
#   NoNewPrivileges=no
#   ProtectSystem=no
```

Depuis ce correctif, la confinement **suit le droit** : durcissement complet par
défaut, relâché uniquement pour une node dont l'opérateur a explicitement demandé
les mises à jour système. Repasser `./install.sh` **sans** `--allow-update`
retire la règle sudoers *et* remet l'unité durcie — les deux choix ne peuvent
plus être faits séparément.

**Pourquoi trois directives et pas une.** `NoNewPrivileges=yes` bloque `sudo` ;
`ProtectSystem=full` monte `/usr` en lecture seule, donc un gestionnaire de
paquets ne pourrait rien écrire même si `sudo` marchait ; `PrivateDevices=yes`
cache des périphériques dont certains scripts post-installation ont besoin.
`PrivateTmp=yes` reste, il ne gêne rien.

**Sans redémarrer maintenant ?** Il n'y a pas de contournement : le drapeau est
posé au démarrage du processus et le noyau ne le retire jamais. Une mise à jour
lancée à la main sur la machine (`sudo apt update && sudo apt dist-upgrade`)
marche toujours — c'est votre shell, pas le processus du nœud.

**En conteneur.** Le même message apparaît avec
`--security-opt no-new-privileges` (parfois posé par défaut). Retirez-le, ou
mettez à jour l'image plutôt que le conteneur : un nœud qui tourne depuis une
image se met à jour en tirant une image plus récente, et la console le dit.

### « cannot self-update » sur la carte d'une node

La node a répondu qu'elle ne peut pas se mettre à jour. La raison exacte est
dans le refus affiché quand vous cliquez Update. Les trois cas :

| Message | Cause | Correctif |
|---|---|---|
| `no package manager this node knows how to drive` | distribution non reconnue (ou image minimale sans `apt`/`dnf`/`apk`…) | mettre à jour la machine autrement ; NMesh ne devine pas un gestionnaire |
| `no sudo or doas on this machine, and the node is not root` | le nœud tourne sous un compte non privilégié et rien ne permet d'élever | `sudo ./install.sh --allow-update` sur la machine |
| `NoNewPrivileges` | voir l'entrée ci-dessus | `sudo ./install.sh --allow-update` |

### La node se met à jour, puis ne revient pas

Après une mise à jour **de NMesh** (Settings → Updates), le nœud remplace ses
propres fichiers et redémarre. S'il est géré par un service (`systemd`, OpenRC,
launchd), il revient tout seul et la console le dit. Sinon, l'ancienne version
est conservée : le message d'après-mise-à-jour donne le chemin de sauvegarde.

---

## Installation & démarrage

### `PermissionError: [Errno 13] … '/…/node.key.tmp'`

Le répertoire d'état appartient à root alors que le nœud tourne sous un autre
compte — typiquement une installation faite en `sudo` avant que le nœud n'ait son
propre compte de service. Relancer `./install.sh` : il répare les
appartenances au passage.

### `start.sh: ligne …: HOME : variable sans liaison`

Un service systemd démarre sans `HOME`. Corrigé : `start.sh` déduit désormais le
répertoire personnel de l'entrée passwd du compte. Si vous voyez encore ce
message, votre arbre est antérieur au correctif — mettez à jour, ou ajoutez
`Environment=HOME=<préfixe>` à l'unité.

### liboqs se recompile à chaque installation

Il ne devrait plus : le résultat est mis en cache par version d'enveloppe
(`/var/cache/nmesh/liboqs-<v>` en root). Si la compilation recommence,
c'est que le cache n'est pas accessible en écriture ou que la version du
wrapper a changé. Le message de `start.sh` le dit.

### J'ai perdu le mot de passe de la console

Sur la machine :

```bash
cd /opt/nmesh && sudo ./install.sh --reset-password
```

Un nouveau mot de passe est généré et affiché **une seule fois**. C'est
volontairement le seul chemin : il exige un accès au répertoire d'état, c'est-à-dire
exactement le niveau de privilège qu'un tel pouvoir mérite.

---

## Réseau & joignabilité

### `this node has no confirmed public address` en créant un ticket de join

Un ticket ne contient qu'une adresse et un code : le scanner n'a rien d'autre.
Émettre exige donc une adresse **`world` confirmée** — une connexion entrante y
est réellement arrivée —, pas une adresse qu'on croit publique. Sur une node
derrière un NAT sans redirection, utilisez le join complet (échange de blocs) ou
un relais.

### Deux nodes ne se voient pas alors que les adresses sont bonnes

Ouvrez la fiche du pair (**Network → Peers → Details**) : la table
**Addresses** dit ce qu'a fait chaque adresse — `in-use`, `timeout`, `refused`,
`untried` — avec le motif et la durée. C'est presque toujours suffisant pour
trancher entre « pare-feu », « mauvaise adresse » et « jamais essayée ».

### Un lien a une bonne latence mais le trafic est mauvais

Regardez **gigue** et **perte** dans la même fiche, et les compteurs du
transport en dessous : sur UDP, des *retransmits* qui montent alors que le RTT
a l'air bon est la signature d'un chemin qui perd des paquets. La carte étendue
(clic sur la carte de l'Overview) passe ces liens en ambre.

### La console dit « Offline » alors que la machine a internet

`internet` vient d'une sonde sortante bornée. Sur un réseau qui filtre les
sondes, elle échoue sans que le mesh soit en cause. **Re-check network** la
relance ; la joignabilité réelle est l'affaire de la ligne
**Reachability** juste au-dessus.

---

## Console

### Le sélecteur de contexte n'apparaît pas

Il n'apparaît que si l'app **fleet** tourne **et** qu'au moins une node vous a
accordé la capability `manage`. Sinon il n'y a rien à sélectionner. Voir
[`Docs/Apps/fleet`](Docs/Apps/fleet).

### « no session on that node — connect to it again »

La session distante a expiré (une heure d'inactivité), la node distante a
redémarré, ou son mot de passe console a changé. Re-sélectionnez-la : elle
redemandera le mot de passe. C'est volontaire — le grant ouvre le canal, le mot
de passe ouvre la session.

### Une barre de progression ou de mémoire reste vide

Corrigé. La CSP de la console (`default-src 'self'`, sans `unsafe-inline`) fait
ignorer **en silence** tout attribut `style=`, donc les barres écrites ainsi ne
se remplissaient jamais. Elles sont désormais des `<progress>`. Si vous le voyez
encore, votre arbre est antérieur au correctif.

### Le navigateur refuse le certificat de la console

Il est auto-signé, c'est attendu. Son empreinte SHA-256 est affichée au
démarrage du nœud : comparez-la, puis acceptez-la. En loopback, `--no-tls` est
une option raisonnable.

---

## Fleet & déploiement

### `dependency setup failed` en déployant sur une machine

Le déploiement distant ne pose rien lui-même : il livre l'arbre et appelle son
`install.sh`. En cas d'échec, la console garde les **dernières lignes de sortie
de la machine cible** — la vraie cause y est presque toujours (paquet manquant,
disque plein, pas de compilateur pour liboqs).

### `sudo: a terminal is required`

Corrigé : le déploiement alloue un pty et répond aux invites sans jamais écrire
le secret sur disque ni sur une ligne de commande. Si vous le voyez encore,
mettez à jour la node **opératrice** (c'est elle qui pilote le SSH).

### Une machine déployée n'apparaît pas dans la liste

Elle rejoint après avoir installé ses dépendances, ce qui peut prendre plusieurs
minutes sur une petite machine (compilation de liboqs). Son invitation est
valable bien plus longtemps qu'un code tapé à la main, précisément pour ça.
L'onglet **Activity** montre où en est le déploiement.

---

## Divers

### Deux nodes inactives échangeaient des mégaoctets

Corrigé (boucle `FIND_NODE`/`FOUND_NODE`) : ~3 Mbit/s au repos sont devenus
~2 kbit/s. Pour vérifier chez vous : **Settings → Diagnostics → Protocol
trace**, qui donne le volume par type de message sans jamais enregistrer de
contenu.

### Où sont les fichiers ?

| Quoi | Où (installation système) |
|---|---|
| l'arbre | `/opt/nmesh` |
| l'état (identité, sessions, certificats) | `/var/lib/nmesh`, mode 700 |
| la configuration | `<préfixe>/nmesh.conf` |
| le wrapper d'update | `/usr/local/lib/nmesh/nmesh-update` (root) |
| la règle sudoers | `/etc/sudoers.d/nmesh` |
