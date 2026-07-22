# NMesh — Charte d'ingénierie

Réseau mesh décentralisé, agnostique du transport, conçu pour faire transiter
des données sensibles dans un environnement **hostile**. Ce fichier fixe les
principes non-négociables. Toute contribution doit les respecter.

## ⚑ Documentation d'architecture — OBLIGATOIRE

`Docs/Architecture/` décrit **comment le code fonctionne réellement** (protocole,
sécurité, routage, transports, et surtout `gotchas.md` : les pièges de blocage /
flakiness durement appris).

- **AVANT toute modification ou débogage**, lis les documents pertinents. Pour un
  blocage ou une flakiness, **commence par `Docs/Architecture/gotchas.md`**.
- **APRÈS tout changement de comportement décrit là**, mets le document à jour
  **dans le même commit**. Une doc fausse est pire qu'absente.
- Un nouveau mécanisme non trivial → une entrée dans le bon document (ou un
  nouveau fichier + lien dans `Docs/Architecture/README.md`).

Index : [`Docs/Architecture/README.md`](Docs/Architecture/README.md).

## Modèle de menace (l'hypothèse de base)

> Dès qu'une donnée quitte le nœud, elle entre en **territoire hostile**.
> On ne fait confiance ni au réseau, ni aux pairs, ni au transport, ni même —
> autant que possible — à la machine locale.

- Tout ce qui arrive d'un pair est **présumé malveillant** jusqu'à validation.
- Un pair authentifié peut se comporter en adversaire (relais qui altère,
  rejoue, amplifie, ou inonde). L'authentification n'est pas de la confiance.
- On se protège de l'appareil : clés sensibles gardées en mémoire quand
  possible, surface d'attaque minimale, aucun secret en clair sur disque sans
  raison.
- On imagine un adversaire à ressources d'État qui veut casser le réseau.
  La question à se poser à chaque ligne : « qu'est-ce qu'il en ferait ? ».

## Les principes, par ordre de priorité

### 1. Sécurité — jamais négociable
- Cryptographie **post-quantique** de bout en bout : ML-KEM-768 (échange de
  clés), ML-DSA-65 (signatures), AES-256-GCM (chiffrement authentifié).
- **Rejeter par défaut.** Tout paquet mal formé, non autorisé, non
  authentifié, ou de type inattendu est jeté sans effet de bord. Une entrée
  valide doit prouver sa validité ; ce n'est pas au récepteur de prouver
  l'invalidité.
- Toute donnée applicative est chiffrée E2E : les relais ne voient que des
  métadonnées de routage, jamais le contenu.
- L'identité d'un nœud = hash de sa clé publique DSA. Un `NodeID` non dérivable
  de la clé présentée est un mensonge → rejet.
- Comparaisons de secrets en temps constant (`hmac.compare_digest`).

### 2. Solidité — le réseau ne tombe jamais
- **Zéro crash. Un crash est un bug de sécurité.** Aucune entrée réseau, aussi
  hostile soit-elle, ne doit faire tomber un nœud ni tuer une boucle de
  réception. Si l'impensable arrive, le nœud doit **se réparer seul**
  (auto-recovery) : purge de l'état corrompu, reconnexion à la demande,
  reprise du service.
- **Rejet de nœud actif.** Un pair qui envoie du bruit, des paquets invalides
  ou abuse du protocole est compté puis déconnecté. On ne subit pas un
  adversaire ; on le coupe.
- **Bornes partout.** Toute file, tout cache, tout buffer, tout compteur a une
  limite dure. Rien qui puisse grandir sans fin sous la pression d'un attaquant
  (pas d'épuisement mémoire, pas d'amplification).
- Fonctionne en **conditions dégradées** : pertes, latences énormes,
  partitions, transports asynchrones (store-and-forward type « clé USB portée
  à pied »). Correction d'erreur, retry, tolérance au délai.

### 3. Flexibilité — agnostique du transport
- Le cœur ne connaît **aucun** transport concret. N'importe qui implémente
  `BaseTransport` + `BaseServer` et l'enregistre par schéma d'URL
  (`tcp://`, `ble://`, `lora://`, `usb://`…). Objectif « Jarvis » : passer sur
  n'importe quel medium capable de transporter des octets.
- Le routage est agnostique du medium : si A↔B est en Bluetooth et B↔C en
  Wi-Fi, A parle à C en routant par B, en choisissant le meilleur lien.
- Les nœuds s'annoncent par des URL listant leurs transports ; chaque nœud
  n'utilise que les schémas qu'il connaît.

### 4. Rapidité — proche du temps réel
- Objectif : dépasser largement les ~4 Mo/s déjà atteints (TCP + routage).
- Optimiser **sans jamais rien perdre** en sécurité, solidité ou flexibilité.
  Un gain de perf qui affaiblit un des trois points précédents est refusé.
- Chemins chauds sans allocation superflue, sans copie inutile, sans
  crypto redondante.

## Chaîne d'approvisionnement (supply chain)

- **Dépendances externes minimales.** Chaque dépendance est une surface
  d'attaque (cf. paquets NPM/PyPI vérolés). Par défaut : **stdlib Python**.
- Une dépendance externe n'est admise que si elle est indispensable, très
  répandue et auditée. Aujourd'hui, strictement :
  - `liboqs-python` — crypto post-quantique (pas d'équivalent stdlib).
  - `cryptography` — AES-GCM/HKDF (référence de l'écosystème Python).
  - `pytest` / `pytest-asyncio` / `pytest-xdist` / `pytest-timeout` — tests
    uniquement, hors runtime (`pytest-xdist` parallélise la suite sur tous les
    cœurs ; `pytest-timeout` borne chaque test pour qu'un blocage échoue vite
    au lieu de faire tourner le job des heures).
- Ajouter une dépendance runtime = justification explicite dans la PR + mise à
  jour de cette liste. Dans le doute : réimplémenter sur stdlib.

## Discipline de contribution

- **Tout changement est prouvé par des tests**, y compris des tests d'entrée
  hostile (fuzzing, paquets aléatoires/mal formés). « Ça marche » ne suffit
  pas : il faut « ça résiste ».
- On ne merge jamais avec la suite rouge.
- Le code lisible prime sur le code malin. On code comme le voisin :
  mêmes idiomes, même densité de commentaires.
- Un commentaire n'explique qu'une **contrainte** que le code ne peut pas
  montrer, jamais le « quoi » ni le « d'où ça vient ».

## Invariants réseau (rappels rapides)

- Header en clair mais **authentifié** (AAD du GCM) ; payload chiffré.
- `msg_id` lie le contenu du paquet (anti-rejeu, anti-amplification) ; il est
  vérifié à la réception, pas seulement à l'émission.
- TTL décrémenté à chaque hop, exclu de l'authentification et du `msg_id`.
- Déduplication bornée des messages routés (anti-boucle, anti-flood).
</content>
</invoke>
