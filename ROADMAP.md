# NMesh — Roadmap

Priorités directrices : voir `CLAUDE.md`. Ordre non-négociable :
**sécurité > solidité > flexibilité > rapidité**, dépendances minimales.

## Fait

### Socle cryptographique et réseau
- Crypto post-quantique E2E (ML-KEM-768 / ML-DSA-65 / AES-256-GCM).
- PKI P2P auto-racinée (chaînes de certificats, racines de confiance).
- Invitation → handshake → session, Kademlia + routage on-demand multi-hop.
- Transport enfichable par schéma d'URL (`BaseTransport` / `BaseServer`).

### Durcissement sécurité / solidité (session en cours)
- **Zéro-crash sur input hostile** : un paquet mal formé ne tue plus la boucle
  de réception ; il est compté et jeté.
- **Rejet de nœud** : au-delà d'un seuil de trames invalides, le pair est coupé.
- **Auto-recovery** : les pairs morts (lien fermé / abus) sont purgés
  automatiquement ; le routage on-demand reconstruit les liens au besoin.
- **Anti-amplification** : `msg_id` vérifié à la réception (il commite le
  contenu) — un relais ne peut plus forger des `msg_id` pour échapper à la
  déduplication.
- **Bornes mémoire** : buffers E2E plafonnés par cible et au global.
- **Glare E2E** : les ouvertures simultanées convergent sur une clé unique
  (tie-break par NodeID) au lieu de deadlocker ; flush des données en attente
  côté répondeur.
- **Fuzzing** : `tests/test_fuzz.py` prouve qu'aucun octet hostile ne crashe
  (Packet, tous les codecs, certificats, nœud vivant sous flot aléatoire).
- **Intégration réelle** : `tests/integration/test_local.py` remis à niveau —
  invite/handshake, data E2E, gros payloads, routage A→B→C, self-healing.

### Console web de gestion (`src/webconsole.py`)
- Plan de gestion local : graphe réseau, liste des pairs, débit temps réel,
  charge de la node ; actions invite / join / trust cert.
- Sécurité : HTTPS auto-signé (empreinte affichée), mot de passe généré +
  haché scrypt, session par jeton Bearer **ou cookie** (`HttpOnly` +
  `SameSite=Strict` → pas de surface CSRF ; survit au refresh), lockout
  anti-bruteforce, bind loopback par défaut, CSP stricte, assets same-origin,
  **zéro dépendance externe** (stdlib + `cryptography`).
- Métriques nœud (`src/metrics.py`) : compteurs débit + charge process.
- Exemple : `scripts/nmesh_node.py`. Doc : `Docs/WebConsole/guide`.

## En cours / à valider
- Test Docker multi-nœuds (10) : rebuild `--build`, valider invitation →
  handshake → data sur les 9 guests.
- Topologie chaîne A→B→C→D pour le forwarding multi-hop en conditions réelles.

### Store-and-forward — medium fichier (`src/spool_transport.py`, `src/spool.py`)
- Transport `spool://` : tout le mesh (invite/handshake/routage/E2E) tourne sur
  un **répertoire partagé**, sans socket. Journaux append durables (fsync),
  framing CRC par enregistrement, resync sur corruption, multi-client.
- Conteneur portable `Bundle` : lot de paquets en un fichier intégrité SHA-256
  (le « fichier de la clé USB »), troncature/altération rejetées.
- Testé : session + data E2E via fichiers, routage multi-hop en étoile,
  sneakernet (livraison offline via Bundle), fuzzing du conteneur et du framing.
- Doc : `Docs/Transports/spool`. Exemple : `nmesh_node.py --spool DIR`.

### Persistance de session (`src/session_store.py`) — opt-in
- Survit au redémarrage et à l'aller-retour offline : sessions E2E, handshakes
  en vol (kem/nonce), et données en attente sont persistés.
- **Chiffré au repos** (AES-256-GCM) sous une clé HKDF dérivée de l'identité —
  même frontière de confiance que le fichier d'identité déjà sur disque.
  Par défaut désactivé (clés en RAM). Activé via `session_store_path`.
- Chargement bulletproof (fichier hostile → repart à vide, jamais de crash).

### Multi-écouteurs par schéma (`TransportManager`) — fait
- Un nœud peut écouter plusieurs `spool://` distincts → topologie
  A—clé1—B—clé2—C débloquée.

### Persistance des liens directs (table de routage) — fait
- La table de routage (pairs connus, adresses, clés publiques) est persistée
  chiffrée au repos. Au redémarrage, le nœud retrouve ses pairs et reconstruit
  les liens à la demande, **ré-authentifiés via le cert store persisté** (chemin
  cert-chain existant, sans ré-invitation). Les sessions E2E survivent déjà.
- Le client mémorise l'adresse composée et l'enregistre dans le routage, ce qui
  rend le pair reconnectable après redémarrage.
- Testé : redémarrage sur lien TCP réel, reprise sans ré-invitation.

### Adressage IP complet + vue expert (`src/ip_utils.py`) — fait
- Énumération des IP locales, parsing host:port IPv6-safe, expansion des URI
  d'écoute wildcard (`0.0.0.0` → chaque IP concrète) → URIs annoncées
  connectables (le ping annonce désormais des adresses joignables).
- Écoute multi-ports + ajout/retrait d'écoute à chaud (`add_listen` /
  `remove_listen`). Snapshot enrichi (advertised, listen, local_ips,
  transports, listening).
- Vue expert dans la console web (URIs diffusées, écoutes, IP locales,
  transports actifs).

## Prochaines étapes (vision « Jarvis / Edith »)

### Détection d'IP publique (mesh-native) — fait
- Un pair qui accepte notre connexion nous renvoie l'IP source qu'il a vue
  (message `OBSERVED_ADDR`) → on apprend notre adresse publique sans serveur
  externe (activé par défaut, à chaque handshake). Validé, borné ; alimente
  les URIs annoncées.

### Transport IP — suite — fait
- **Client STUN** (`src/stun.py`) : Binding Request RFC 5389 sur UDP, parse
  XOR-MAPPED-ADDRESS (IPv4/IPv6). Fallback quand aucun pair n'est disponible
  pour observer notre adresse. stdlib only, opt-in (`--stun`).
- **Transport UDP** (`src/udp_transport.py`) : `UDPTransport` / `UDPServer`
  implémentant `BaseTransport` / `BaseServer` sur sockets datagramme asyncio.
  Couche de fiabilité : numéros de séquence, ACK cumulatif + SACK,
  retransmission avec backoff exponentiel, tampon de réordonnancement borné,
  keepalive 25 s pour maintenir les mappings NAT. Framing avec magic `NUDP`.
  Tout le mesh (invite/handshake/routage/E2E) tourne sur UDP inchangé.
- **Hole punching NAT** signalé sur le mesh : messages `PUNCH_REQUEST` /
  `PUNCH_RELAY` (coordination via relais TCP), `PUNCH_PROBE` / `PUNCH_ACK`
  (datagrammes UDP bruts signés ML-DSA-65). Deux nœuds derrière NAT
  s'envoient des sondes simultanées via un relais public ; le trou est
  percé et un lien UDP direct remplace le relais. Fallback automatique :
  si le punch échoue (NAT symétrique), le trafic continue via le relais.
- Testé : transport UDP loopback (send/receive, ordre, bidirectionnel),
  invite/handshake/E2E sur UDP, hole-punching coordination via relais,
  résistance aux datagrammes hostiles (garbage → ignoré, pas de crash).
  385 tests unitaires + 6 tests d'intégration, zéro régression.


### Store-and-forward — approfondissement delay-tolerant
- Mode drop unidirectionnel (bundle déposé sans round-trip interactif).
- File d'émission persistante par pair + reprise après coupure.

### Connecteur de données (`src/data_connector.py`) — fait
- Socket local (TCP loopback ou Unix 0600, TLS optionnel) par lequel une app
  envoie/reçoit des messages E2E du mesh. Auth par jeton (compare_digest),
  trames bornées, clients plafonnés. Plan de *données* (distinct de la console).
- Testé app→mesh→app de bout en bout. Doc : `Docs/DataConnector/guide`.
  Exemple : `nmesh_node.py --connector-port N`.

### Lanceur de sous-processus (`src/process_launcher.py`) — fait
- Le nœud lance des apps déclarées et injecte les coordonnées du connecteur
  (hôte/port/jeton) dans leur environnement ; l'app rejoint le mesh via
  `ConnectorClient`. Exec sans shell (pas d'injection), enfants bornés et
  terminés à l'arrêt. Exemple : `nmesh_node.py --launch "..."`,
  `scripts/example_app.py`. Doc : `Docs/ProcessLauncher/guide`.

### Partage d'apps via DHT (`src/dht.py`, `src/app_package.py`) — fait
- Paquets d'app **adressés par contenu** (chunks + manifeste, clé = hash) :
  publication, récupération vérifiée, re-partage automatique en cache.
- DHT Kademlia : `STORE` / `FIND_VALUE` / `FOUND_VALUE`, magasin borné
  anti-empoisonnement/anti-OOM. API `node.publish_app` / `node.fetch_app`.
- Doc : `Docs/AppSharing/guide`.

### Store local par app + DHT par-app (`src/app_storage.py`, `src/app_dht.py`) — fait
- **Tiroir** chiffré par app : clé→valeur AES-256-GCM (clé par app dérivée de
  l'identité), isolé par `app_id`, borné, robuste aux fichiers hostiles.
  `node.app_store_*` et frames connecteur `STORE_*`. Doc : `Docs/AppStorage/guide`.
- **DHT par-app** publique/privée au-dessus du store adressé-contenu : namespace
  par `app_id` (que le nœud connaît, l'app ne le déclare pas), chiffrement
  node-side sous clé fournie par l'app pour le privé. `node.app_dht_*` et frames
  connecteur `APP_DHT_*`. Doc : `Docs/Architecture/routing.md`.

### Annuaire de pseudos DHT (`src/pseudo_dir.py`) — fait
- Find-by-pseudo **réseau** : annuaire à clé sur Kademlia (`DIR_STORE`/`FIND`/
  `FOUND`), réclamations **signées auto-authentifiées** (pseudo→node_id lié à la
  clé pub → pas d'usurpation), bornées/rate-limitées, réclamations multiples par
  pseudo. `node.publish_pseudo`/`lookup_pseudo`, frames connecteur `PSEUDO_*`. Le
  chat publie au `set_pseudo` et cherche le réseau au `search`.

### App store : catalogue partagé (`src/app_catalog.py`) — fait
- Catalogue réseau de **releases signées** (auteur ML-DSA + `ts` signé), gossipé
  (`CATALOG_ANNOUNCE`), anti-forge / anti-rollback / borné, rattrapage au
  handshake. Registre local d'apps installées (install vérifie le contenu avant
  d'écrire, chemins assainis). Page **App Store** de la console (logique de
  décision en Python via `store_overview`). Doc : `Docs/AppStore/guide`.

### App de démo chat (`src/apps/chat.py`) — fait
- Texte, partage de fichiers (chunké, intégrité SHA-256) et flux temps réel
  (primitive d'appel : trames horodatées, latence mesurée) sur le connecteur.
- Démo auto-contenue `scripts/chat_demo.py` (~37 Mo/s fichier, ~0,5 ms de
  latence médiane en local), client interactif `scripts/chat_app.py`.
  Doc : `Docs/Apps/chat`.

### Partage d'apps depuis la console web — fait
- Section « Apps (DHT) » de l'interface : publier une app (sélection de
  fichiers → app_id partagé sur le mesh) et en récupérer une par identifiant
  (fichiers vérifiés, téléchargeables). Endpoints `/api/app/publish` et
  `/api/app/fetch`.

### Web app du chat (`src/apps/chat_web.py`) — fait
- Option de l'app de chat : quand activée, l'app fait remonter ses messages vers
  une web UI et route les envois via elle (fan-out interne à l'app via
  `ChatApp.add_listener`). Le nœud et la console de gestion ne sont pas touchés.
  Loopback + jeton, CSP stricte. `chat_app.py --web PORT`.

### Manifestes chunkés (grosses apps) — fait
- Le manifeste est lui-même chunké et adressé par contenu ; l'app_id pointe
  vers un petit root listant les chunks du manifeste. Plus de limite ~59 Ko
  sur le nombre de fichiers d'une app.

### Appels audio (`src/apps/call.py`) — fait
- Transport audio temps réel sur le flux de trames : PCM framé, latence mesurée.
  Backend WAV en stdlib (`wave`) → appel testé de bout en bout avec de vrais
  échantillons, sans matériel ni dépendance. Interface `AudioSource`/`AudioSink`
  pour brancher un micro/HP live côté app sans polluer les deps de NMesh.
  Démo `scripts/call_demo.py` (audio identique bit-à-bit, ~0,5 ms de latence).

### Écosystème d'applications — suite
- Backend périphérique live (micro/HP, ex. sounddevice) implémentant
  `AudioSource`/`AudioSink`, côté application.
- Vidéo au-dessus du même flux temps réel.
- Envoi de fichiers depuis la web UI du chat (aujourd'hui : texte + affichage
  des fichiers reçus).

### Identité applicative (`src/app_auth.py`) — fait
- Le mesh authentifiait le transport ; une app n'avait rien de **portable** ni de
  **lié à une intention**. Assertions signées ML-DSA scopées
  `(app, audience, purpose, ctx)`, fraîches, à usage unique, vérifiables
  hors-ligne après redémarrage.
- **Jamais un oracle de signature** : l'entrée signée est toujours
  `domaine ‖ champs structurés bornés`, le contexte libre n'entre que par un hash
  32 o, et le domaine est distinct de tous les autres du dépôt — une app ne peut
  pas faire signer un corps de certificat par la clé du nœud. L'`app_id` vient de
  la session, jamais de la trame.
- Exposé aux apps intégrées par `node.app_auth(app_id)` (l'app ne touche jamais
  la clé) et aux apps externes par les trames `AUTH_*` du connecteur.
- Doc : `Docs/AppAuth/guide`.

### App de gestion de parc « Fleet » (`src/apps/fleet*.py`) — fait
- Enrôlement avec **notification et décision humaine** sur la node cible ;
  approuver peut restreindre, jamais élargir. Grant signé conservé côté opérateur
  comme preuve auditable du consentement.
- **Capabilities par action** (`status`, `update`, `scan`, `provision`, `shell`).
- Trois portes indépendantes avant exécution : mesh authentifié, enrôlé avec la
  capability, signature fraîche sur les octets exacts de la commande.
- Status (disque/RAM/charge/uptime), update (plan dérivé par la node elle-même
  depuis ses propres faits — apt/dnf/pacman/zypper/apk/xbps/brew/pkg, argv jamais
  une chaîne shell), shell interactif sur pty borné.
- Découverte LAN SSH sur **tous les réseaux attachés**, au préfixe réellement en
  usage (`/proc/net/route`, ioctl, `ip`/`ifconfig`, repli) — un `/22` n'est plus
  balayé comme un `/24`, et une seconde carte ou un VPN ne sont plus manqués.
  Bornée, réseaux trop grands rétrécis autour de notre adresse et signalés comme
  tels. Le champ de cible accepte aussi une **machine précise** (`10.0.0.5`,
  `nas.lan:2222`, `[fd00::5]:22`) : nommer une machine n'est pas balayer, donc
  c'est permis hors des plages privées, alors qu'un **préfixe** public reste
  refusé. Ce qui n'est pas compris revient nommé, jamais avalé. Empreintes de
  clés d'hôte présentées à l'opérateur, puis provisioning : bootstrap auto-extractible en une
  session SSH, intégrité SHA-256 vérifiée avant d'écrire, service de démarrage
  installé, et **reprise de confiance** par pré-autorisation à jeton unique.
- Identifiants SSH : OpenSSH piloté par **pty**, jamais sur disque, jamais dans
  `argv`, jamais dans l'environnement. Clés d'hôte épinglées après confirmation
  humaine (`StrictHostKeyChecking=yes`), pas d'`accept-new`.
- **Intégration au réseau automatisée** : la node qui lance le scan émet une
  invitation fraîche et à usage unique **par machine**, la dépose dans la
  pré-autorisation avec ses propres URI, et la machine neuve rejoint le mesh à
  son premier démarrage — flux ordinaire invitation → handshake → `issue_cert`,
  donc **son certificat est signé par la node qui l'a installée** et chaîne
  jusqu'à la racine du réseau. C'est aussi la node joignable : elle est sur le
  même LAN, là où l'opérateur peut être derrière un NAT.
- `generate_invite(ttl)` : TTL par code (borné 6 h). Un code tapé à la main vit
  5 minutes ; celui déposé sur une machine en cours d'installation n'est redeemé
  qu'après le build des dépendances. Usage unique et lockout inchangés.
- Doc : `Docs/Apps/fleet`.

### Cycle de vie des apps intégrées (`src/app_registry.py`) — fait
- `installed` / `enabled` distincts et persistés ; désinstaller **purge le tiroir
  chiffré** de l'app. Bascule à chaud depuis la console, sans redémarrer le nœud.
- Fleet est **désactivée par défaut** (elle peut ouvrir un shell).

### Installation à demeure et mise à jour (`install.sh`, `src/updater.py`) — fait
- `install.sh` : copie l'arbre dans un emplacement durable (`/opt/nmesh` en root,
  `~/.local/share/nmesh` sinon), pose un service systemd / OpenRC / launchd,
  puis lance. Il **délègue tout** à `start.sh` (dépendances, distro, liboqs) et
  le service pointe sur `start.sh` : un nœud qui redémarre se répare seul.
- Compte système dédié en installation root (`nmesh`, sans login ni mot de
  passe) : il possède seul l'arbre et l'état, en mode 700, et l'unité systemd
  ajoute `NoNewPrivileges` / `PrivateTmp` / `PrivateDevices` / `ProtectSystem`.
  Installation autonome sous le préfixe (`HOME` épinglé → liboqs dans
  `<prefix>/_oqs`). Repli documenté quand aucun compte ne peut être créé.
- liboqs compilé une seule fois par machine : cache
  `/var/cache/nmesh/liboqs-<version>` réutilisé par toute install ultérieure,
  réutilisation validée fonctionnellement (le wrapper charge la bibliothèque),
  pas sur un numéro de version.
- Réinstallation = mise à jour sur place, **l'état n'est jamais touché**.
  `--uninstall` retire service et fichiers, `--purge` va jusqu'à l'identité.
- Mise à jour depuis GitHub (console → Settings → Updates) : vérification
  manuelle, confirmation qui **nomme la version**, version rappelée dans la
  requête et revérifiée côté nœud. Seuls les répertoires de code/doc sont
  remplacés ; l'arbre précédent est gardé et restauré en cas d'échec. Refus
  explicite sur image de conteneur ou répertoire non inscriptible.
- Limite connue : **pas encore de signature de release vérifiée par le nœud**
  (confiance TLS + GitHub + publieurs). C'est la prochaine étape de ce chantier.
- Doc : `Docs/Setup/guide`, `Docs/WebConsole/guide`.

### Configuration du nœud (`src/config.py`) — fait
- Toutes les options de lancement dans `<prefix>/nmesh.conf`, écrit par
  `install.sh` et éditable depuis la console (Settings → Configuration).
- Priorité ligne de commande > fichier > défaut : une unité existante qui passe
  des arguments ne change pas de comportement.
- Lecture défensive et bornée ; un fichier incompréhensible est signalé puis
  écarté, jamais fatal. Une valeur refusée par la console n'écrit rien.
- `launch` et `data` affichés mais non éditables depuis le web ; le mot de passe
  console n'est pas un réglage.
- Doc : `Docs/Setup/guide`, `Docs/WebConsole/guide`.

### Long terme
- **Signer les releases** (ML-DSA) et vérifier la signature avant d'appliquer une
  mise à jour, pour sortir de la confiance en GitHub seul.
- Trust score par nœud + révocation en cas de trahison.
- Persistance de la trust/cert table sur disque.
- meshnet-daemon : embarque la lib, écoute sur socket, multi-clients.
</content>
