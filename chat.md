
NMesh
/
Salut salut. Alors j'ai une idée de projet. En gros, ce sera un système, ce sera un projet à plusieurs blocs. Donc il y aura d'abord une première partie où j'étable la communication entre ces différents, on va dire différents appareils. Donc l'idéal ce serait d'avoir je ne sais pas un ensemble gestion de communication qui est capable de prendre entre guillemets n'importe quelle voie. Tu vois n'importe qui peut dire, je vais le ajouter une manière de nouvelle manière de communiquer. Juste du coup je peux vous donner un bout de code par exemple qui va juste établir un lien entre c'est un peu comme le réseau de niveau deux, établir un lien base pour qu'après les deux on va dire les deux parties en application puissent envoyer des échanger des données entre elles. Alors ça peut être n'importe quel moyen, ça on s'en fout, il faut que notre manière de faire soit complètement amnésique on va dire, enfin indépendante de ce moyen de communication tu vois. Donc déjà on aurait ça. Alors déjà pour ça est-ce qu'il y a des solutions qui existent déjà toutes faites open source ou c'est un petit peu un monde pas trop certain ?

Show more
15 mai

Inventoried transport-agnostic middleware solutions for modular communication architecture
Inventoried transport-agnostic middleware solutions for modular communication architecture
Salut ! Ouais l'idée est claire : une couche d'abstraction transport — le reste du système ne sait pas (et s'en fout) si en dessous c'est du TCP, du serial, du Bluetooth, du CAN, etc. C'est un pattern bien connu, et oui il existe des solutions solides.

Les candidates principales :

ZeroMQ (libzmq) — la classique

Abstraction sur TCP, IPC, inproc, PGM...
Tu envoies/reçois des messages, le transport est configuré par URI (tcp://..., ipc://...)
Très mature, bindings dans quasiment tous les langages
Limite : les transports supportés sont fixés, ajouter un transport custom (ex: serial, BLE) demande de patcher ou de faire un bridge
Zenoh — la plus intéressante pour ton cas

Pensé dès le départ pour être multi-transport pluggable (TCP, UDP, serial, Bluetooth, shared memory, CAN...)
Architecture en plugins : tu peux écrire un plugin transport tiers
Open source (Eclipse Foundation), très actif, conçu pour l'embarqué/IoT jusqu'au cloud
C'est probablement ce qui ressemble le plus à ce que tu décris
libp2p — plus orienté P2P réseau

Utilisé dans IPFS/Ethereum, très modulaire
Supports de transports pluggables, multiplexing, etc.
Peut-être overkill si tu ne fais pas du P2P distribué
DDS (ex: Cyclone DDS, FastDDS) — middleware temps-réel

Standard industriel (utilisé dans ROS2, aéro, défense)
Très robuste, QoS poussé
Plus lourd à mettre en place
Mon avis rapide : si tu veux vraiment le côté "n'importe qui peut brancher un nouveau transport en fournissant juste un bout de code", Zenoh est probablement le mieux aligné. ZeroMQ si tu veux quelque chose de battle-tested et simple mais tu seras limité aux transports natifs ou tu devras bricoler des bridges.

Tu vises quel(s) langages/plateformes ? Et les appareils en question c'est du Linux embarqué, du micro-contrôleur, du desktop ? Ça m'aiderait à affiner.

Alors concrètement, j'aimerais bien faire ce projet en python, je pense parce que comment dire, en fait c'est une sorte de projet qui a la finalité. L'idée c'est de comment dire d'avoir un agent sur plein d'appareils différents, que ce soit un smartphone, un ordinateur, un serveur, un objet iouti connecté. En fait tout ce qui est capable d'exécuter du python et se connecter à internet ou même un réseau. Et en fait donc l'idéal c'est qu'en gros, l'idée donc c'est de les mettre en lien, déjà de faire en sorte donc son peer to peer qui n'est pas de serveur central et que en gros on est un système vraiment de robustesse, on va dire à la perte de lien très très puissante par exemple, je ne sais pas si j'ai, on va dire j'ai a b c, tu as trois appareils. Imaginons donc que b arrive à joindre a et c et que a arrive aussi à joindre c. Tu vois, tout monde arrive à se joindre en gros. Et là, imaginons pour x ou y raison, a arrive toujours à joindre b, mais par contre, il est incapable de joindre directement c, et bien il va passer par b pour aller à c, tu as une sorte de réseau maillet. Donc en fait, j'aimerais déjà établir ça, donc un système de réseau maillet en python, Ils sont capables donc d'évoluer et c'est au travers de différentes technologies. Par exemple a et b peuvent communiquer entre via du Bluetooth et par un réseau TCP IP, mais par contre B et C peuvent uniquement communiquer par du TCP IP, tu vois. Et donc si par exemple la communication TCP IP de a est perdue, en fait a va passer par le Bluetooth pour aller communiquer avec le b et le c. Je ne sais pas ce que tu as compris le concept, dis-le-moi.

Show more
15 mai

Architected decentralized mesh network with multi-transport resilience
Architected decentralized mesh network with multi-transport resilience
Oui, très clair. Ce que tu décris c'est un réseau maillé P2P multi-transport avec routage dynamique. Je te résume ce que j'ai compris pour qu'on soit alignés :

Ce que tu veux :

Chaque appareil est un nœud avec un identifiant unique
Pas de serveur central — full P2P
Un nœud peut avoir plusieurs liens simultanés vers d'autres nœuds, sur des transports différents (TCP, Bluetooth, serial, peu importe)
Si le chemin direct A→C tombe, A route automatiquement via B (A→B→C)
Si plusieurs chemins existent vers la même destination, il choisit le meilleur / bascule sur l'autre en cas de panne
Le tout est indépendant du transport — la couche applicative au-dessus s'en fout complètement
Les briques qu'il faut construire :

┌─────────────────────────────┐
│        Application          │  ← envoie à "node_id", point final
├─────────────────────────────┤
│      Couche Routage         │  ← table de routage, next-hop, TTL
├─────────────────────────────┤
│      Couche Maillage        │  ← découverte de pairs, topologie
├─────────────────────────────┤
│   Couche Abstraction        │  ← interface commune à tous les transports
├────────┬────────┬───────────┤
│  TCP   │  BLE  │  Serial…  │  ← implémentations concrètes
└────────┴────────┴───────────┘
Le point le plus délicat : le protocole de routage

Il faut choisir entre :

AODV — réactif, ne calcule une route que quand on en a besoin. Bien pour les réseaux peu denses ou peu actifs
OLSR — proactif, chaque nœud connaît toute la topologie en permanence. Plus de trafic de contrôle mais routes immédiates
Babel — hybride, très bien conçu, tourne sur des liens hétérogènes, c'est probablement le plus adapté à ton cas
Côté Python, il y a des briques qui existent :

python-libp2p — existe mais peu mature, pas super maintenu
asyncio — indispensable, tout ton stack devra être async
Pour le Bluetooth : bleak (BLE, cross-platform)
Pour TCP : natif asyncio
Honnêtement pour la couche routage/maillage en Python pur, tu vas devoir construire, y'a pas de lib clé en main qui fasse exactement ça proprement.

Question clé avant d'aller plus loin : est-ce que les nœuds se connaissent à l'avance (config statique) ou faut-il aussi de la découverte automatique de nouveaux nœuds sur le réseau ? Parce que ça change pas mal la complexité de la couche maillage.

Ok, donc il n'y a rien qui le fasse actuellement. Donc ça, c'est un intéressant. Ça veut dire que déjà, juste le fait c'est d'avoir, comment dire, un réseau que soit capable de communiquer entre eux, enfin, comment dire ça, juste cette partie-là, je vais en faire donc un projet GitHub bien à part, comme ça d'autres personnes pour éventuellement s'en servir. Au moins, je pourrais m'en resservir. Donc déjà ça, ça va être je pense une librairie bien à part, bien distincte du reste. Ok. Donc ensuite, alors comme j'ai dit, en fait, je serai amnésique du moins de communication, tu vois, je m'en fous en fait. Genre moi, je veux juste savoir à qui je peux parler, même si je ne sais pas par un câble jack, mais que ça me permet d'échanger des données à peu près c'est la faute c'est la sous-couche derrière on s'en fout tu vois. Moi en gros je vais développer, enfin je vais commencer par développer on va dire peut-être TCPIP tu vois parce que c'est le plus simple. Donc un plugin TCPIP et puis ensuite d'autres gens pourront développer des plugins même moi en python toujours, mais qui vont juste donc recevoir de ma brique centrale des zéro et des un, enfin tu sais des données binaires et derrière ils vous, donc ce plugin va juste faire en sorte que ces données binaires arrivent à l'autre bout, que ce soit par un câble jack, que ce soit par de la lumière, que ce soit par du Bluetooth, du de Laura, tout ce que tu veux, je n'en ai rien à foutre, que du MQTT, du HTTPS. Vraiment tout tout ce que tu peux imaginer qui permet d'échanger des infos même par un pigeon voyageur, je n'en ai rien à foutre. Moi, tout ce que je veux, c'est que ces données arrivent intactes à l'autre de l'autre côté. Donc il faut aussi peut-être un système de check-som et de de correction d'erreur intégré dans ma brique centrale peut-être. Tu as une double sécurité au cas où. Donc comme dit, moi je vais commencer par juste développer un truc en IP parce que sinon je ne vais pas réussir, enfin juste pour les tests au début, tu vois je vais faire du pur IP avec des machines virtuelles qui sont chacun un sous-réseau, je couperais les comme comme ça, enfin je ferai joue de cette manière et ce sera comment dire, ce sera très simple avec des VMs, tu vois. Je vais faire vraiment ça au début en IP avec des VMs et une fois que ce concept marche en IP des VM. Normalement, ça devrait marcher pour tout ensuite. Tu vois, et d'après si je le plug-in derrière. Donc déjà oui, je pense faire un projet GitHub bien à part. Et effectivement, donc alors tu m'as dit qu'il y a des briques qui existent, mais en fait, c'est-à-dire que dépendre d'un truc externe, ça fait un peu chier, tu vois. Surtout un truc qui n'est pas officiel python. Parce qu'à tout moment, ce truc il saute. C'est-à-dire que c'est un truc officiel python, bon d'ici à ce que ça saute ou qu'il y a une faille de sécurité dedans, il faut le faire, tu vois. C'est des quelque chose assez solide. Moi j'ai quelque chose de solide. Tu as un truc qui marche vraiment, même en cas de doomdail entre guillemets, enfin j'exagère un peu, mais tu as compris. Donc déjà piton, lit, p toupet, c'est mort, on oublie parce que voilà tu m'as dit peu mature, pas super maintenu, ça vire, c'est mort, je je ferai pas non non du coup. Je ferai, tu m'expliquera, tu m'aideras et moi je coderai le protocole pour faire du peer to peer un truc vraiment solide, je veux quelque chose de puissant. Bon après pour la partie Bluetooth tu m'as dit, je m'en fous en fait, enfin genre ce sera pour plus tard tu vois, pas pour tout de suite. Asinkayo, oui, alors je ne sais pas en fait, j'ai pensé plutôt à peut-être essayer des threads tu vois. Alors soit de l'asinkio, soit des systèmes de multithreading, multiprocess, il faut que tu me dises et je t'avoue que je ne suis pas hyper  m'aider du coup à prendre asyncio pour que ça soit plus à l'aise parce que je ne sais pas, j'ai du mal en fait avec le fait de créer des fonctions async et de les exécuter depuis des fonctions qui ne le sont pas tu vois, c'est ça le concept. Je n'arrive pas à comprendre comment on mélange ces deux mondes. J'ai l'impression jusqu'à maintenant à chaque fois que je fais les applications que tout doit être asynchrone. Alors peut-être que c'est la bonne manière de faire, que tout doit être asynchrone parce qu'il faut juste que je mette que je m'y fasse tout simplement. Mais oui, ça syncoupe assez flou et je ne sais pas, j'ai un peu de mal avec ça. Pour l'instant j'ai fait beaucoup sur des threads tout ça, mais c'est que ce n'est pas très propre. Donc peut-être que la sync ce serait mieux. Donc ça j'aurais sûrement besoin de toi, c'est pour ça que je paie un abonnement de vingt-et-un euros par mois. Et donc oui, effectivement, donc comme tu as dit, pas de serveur central, plusieurs liens simultanés exactement. Et ça pourra me faire de l'agrégation de liens. Alors ça, c'est pour plus tard. D'abord, on va se concentrer sur la base, peut-être pour plus tard de l'agrégation de liens. Ou bon au début, voilà, sera juste y choisir peut-être la meilleure ou même une aléatoire, tu vois tout au début, sera vraiment commencer par un truc simple pour que ça se met simple mais solide, tu vois. Et on va ensuite l'améliorer.

Show more
15 mai

Architected modular mesh network library avec asyncio guidance
Architected modular mesh network library avec asyncio guidance
Ok, tout est clair. Laisse-moi te donner les grandes décisions avec mon avis tranché, et ensuite on attaque.

asyncio vs threads — tranche ici
Prends asyncio, c'est le bon choix, et je vais t'expliquer pourquoi le "mélange" te faisait peur :

Le problème que tu as eu c'est que tu pensais asyncio comme un outil optionnel qu'on branche sur du code normal. C'est pas ça. La bonne façon de voir :

ton programme = une boucle d'événements asyncio
                qui tourne du début à la fin
                et tout vit dedans
Donc il n'y a pas de mélange — tout est async. Le seul endroit non-async c'est le point d'entrée :

python
async def main():
    node = MeshNode(...)
    await node.start()
    await node.run_forever()

asyncio.run(main())  # ← seule ligne sync de tout le projet
Les threads c'est bien pour du CPU-bound. Pour du réseau (I/O-bound pur), asyncio gère des milliers de connexions sans overhead, sans GIL, sans locks partout. Ça tombe bien.

Architecture de la lib — ce qu'on va construire
meshnet/
├── node.py          ← MeshNode, point d'entrée public
├── router.py        ← table de routage, next-hop
├── packet.py        ← format, framing, checksum
├── peer.py          ← état d'un pair connu
├── transports/
│   ├── base.py      ← interface abstraite
│   └── tcp.py       ← premier plugin
└── discovery.py     ← comment on trouve les autres noeuds
Interface transport — le contrat que tout plugin doit respecter
python
class BaseTransport(ABC):
    @abstractmethod
    async def start(self): ...
    
    @abstractmethod
    async def stop(self): ...

    @abstractmethod
    async def send(self, addr: str, data: bytes) -> bool: ...

    # Le transport appelle ce callback quand il reçoit quelque chose
    def set_receive_callback(self, cb): 
        self._on_receive = cb  # cb(data: bytes, from_addr: str)
C'est tout. Un plugin TCP, BLE, MQTT, peu importe — il implémente juste ça. Le reste il s'en fout.

Format paquet — simple mais solide
[ version:1 | type:1 | src_id:16 | dst_id:16 | msg_id:4 | ttl:1 | flags:1 | len:2 | CRC32:4 | payload:N ]
src_id / dst_id : UUID tronqué à 16 bytes — identifiant de nœud, indépendant du transport
msg_id : pour déduplication (évite les boucles de routage)
ttl : decrementé à chaque hop, paquet droppé à 0
CRC32 : checksum du header + payload, paquet droppé si invalide
type : DATA / HELLO / ROUTE_UPDATE / ACK...
Plan d'attaque concret
Phase 1 (on commence là) — le squelette qui marche en TCP entre 2 VMs :

packet.py — sérialisation/désérialisation + CRC32
transports/tcp.py — listen + connect + send en asyncio
node.py — envoie/reçoit des paquets bruts entre 2 nœuds
Phase 2 — routage basique :

Table de routage simple (dst → next_hop)
Flooding pour découverte initiale (simple et ça marche)
A→B→C fonctionnel
Phase 3 — robustesse :

Détection de panne de lien
Reroutage automatique
Déduplication des paquets
On commence par quoi ? Je te propose qu'on attaque packet.py d'abord — c'est la fondation de tout, et ça ne dépend de rien.

Bon attends juste là tu commences à me faire du code, tu vas trop loin, tu vas trop vite. Là on commence vraiment par la base, tu vois quand on crée un projet d'abord, on fait du brainstorming, on ne fait pas du code, on s'en fout, c'est juste on définit qu'est-ce qu'on va faire. Parce que donc ok, on va essayer de la synchrone, ok. Mais ensuite comment est-ce que je vais m'en servir depuis une autre application qui ne sera peut-être pas en tu vois ? Si par exemple je fais un système, je ne sais pas donc avec ce donc une fois que différents appareils sont en lien pour qu'ils puissent, je ne sais pas se synchroniser tous ensemble, c'est-à-dire je ne sais pas, j'ouvre par exemple une appui sur mon tel et je vois l'état de tous mes ordinateurs, tu vois, je ne joue pas le niveau de batterie, s'ils ont de batterie, niveau du gestion CPU, les process qui tout, tourne ce genre de choses. Tu as peut-être même les contrôler, je ne sais pas, exécuter des commandes prédéfinies, ce genre de choses. Comment est-ce que je m'interface avec d'autres blocs ? Comment j'interface de la avec d'autres blocs ? Est-ce que je ne sais pas, je peux appeler des fonctions et ça va déclencher des événements à mais genre déclencher des fonctions depuis un programme qui n'est pas à ça marche en fait ? Comment on fait concrètement ?

Show more
15 mai

Architectured integration patterns for async library across heterogeneous applications
Architectured integration patterns for async library across heterogeneous applications
Ok t'as raison, on reste en brainstorming. Et c'est une très bonne question — c'est même LA question d'architecture centrale.

Le problème que tu soulèves
Si la lib est full asyncio, et que quelqu'un veut l'utiliser depuis une appli Django, une GUI Tkinter, un script bash via subprocess, ou même un programme en Go — comment il fait ?

Tu as deux grandes philosophies :

Option A — La lib s'importe directement
Le consommateur importe ta lib Python, et c'est lui qui gère asyncio. Si il est lui-même async, parfait. Sinon il fait tourner la boucle asyncio dans un thread de fond et tu lui exposes une API sync propre.

Avantage : simple, pas de processus en plus Inconvénient : couplé à Python, et si le consommateur plante, ton nœud réseau meurt avec lui

Option B — La lib tourne comme un daemon/processus séparé
Ton nœud réseau tourne tout seul en arrière-plan, comme un service système. Il expose une API locale sur la machine — typiquement une socket Unix ou un port TCP local — et n'importe qui peut lui parler : Python, Go, Rust, un script bash, une appli mobile, peu importe.

┌─────────────────────────────────────┐
│           ta machine                │
│                                     │
│  [App monitoring]  [App contrôle]   │
│         ↕                ↕          │
│    (socket unix / localhost)        │
│         ↕                ↕          │
│      [ meshnet daemon ]             │
│         ↕                           │
│    [ réseau maillé ]                │
└─────────────────────────────────────┘
Avantage : totalement découplé, n'importe quel langage, le daemon survit aux plantages des applis Inconvénient : tu dois définir un protocole de communication local

Mon avis
Option B est clairement la bonne pour ce que tu décris. Tes exemples — voir l'état des machines depuis le tel, exécuter des commandes — c'est exactement le modèle daemon. C'est d'ailleurs comme ça que fonctionnent tous les vrais services système (bluetoothd, Docker, etc.).

Et du coup ça répond à ta question sur asyncio : le daemon est full async en interne, ça le regarde lui. Les autres applis ne savent même pas que c'est du Python.

Ce que ça implique comme décisions à prendre
Quel format pour l'API locale ? (JSON simple, Protocol Buffers, MessagePack...)
Quel mécanisme de transport local ? (socket Unix sur Linux/Mac, TCP localhost pour la portabilité Windows aussi)
Est-ce que tu fournis un SDK Python qui cache tout ça pour les consommateurs Python ?
Tu veux qu'on creuse ces questions là ?

Ah alors l'option biais, je l'aime bien en fait. Est-ce que finalement, on ne va pas créer carrément mon sexe ça fait un petit peu ambitieux dire ça ? Est-ce qu'on ne va pas directement, enfin carrément créer une sorte de protocole de VPN ? C'est un, au fait on va recréer une sorte de tel scale, mais plus résilient tu vois. Du coup on va peut-être, est-ce qu'on va échanger du TCP IP ? C'est une bonne question, peut-être en vrai, peut-être qu'on pourrait effectivement faire une API locale comme tu as dit et en fait on lui envoie des paquets ou carrément de ceux qui créent une interface virtuelle vois comme ça ça s'intègre bien en fait dans l'ouest tu vois j'en crée une interface virtuelle en Linux par exemple la tune zéro, mais en fait ce que je suis en train de penser en te disant ça, c'est que du coup on va enfin cette pulsion pour le porter sur multiples enfin plusieurs OS en gros plusieurs systèmes d'exploitation, ça va être plus casse-pieds. Parce que la manière de créer l'interface virtuelle sous Windows, imagine que ce n'est pas la même que pour Linux. Donc si maintenant on n'échange pas du TCP IP effectivement une API locale où il importe TCP local oui en fait c'est ce que tu viens de m'écrire, je suis  Donc en gros, tu m'as dit, attends je je lis deux secondes. Ok, en fait comment ? C'est ok, donc je veux bien créer un socket unique, mais ensuite, est-ce que ce socket unique, je peux, je ne sais pas, l'imbriquer dans une application Android, tu vois ? Parce que par exemple, j'aimerais bien voir que mon tel se fasse partie d'une node, et du coup, j'aimerais aussi une application Android qui fasse tourner ce code Python. J'imagine que faire tourner du Python sur Android, c'est possible, mais j'aimerais bien savoir comment, parce que donc là, tu, si tant qu'on est sur un PC standard, on n'a pas ce problème. Mais il faut qu'on arrive sur des environnements conteneurisés ou qui s'éloignent un peu du monde Unix, par exemple la Windows, alors même si je ne compte pas honnêtement le mettre sur du Windows, ça pourrait arriver. Donc tu vois j'aimerais vraiment un truc sur multiplateforme. Multiplateforme maximum, tu vois vraiment le truc universel qui peut tourner comme j'ai dit surtout tu vois tout ce qui est tout ce qui est capable de faire tourner du python, je veux que ça puisse tourner dessus. Tu vois le le concept pur python en gros, indépendant de l'OS.

Show more
15 mai

Arbitré entre interface virtuelle et socket local pour portabilité multiplateforme
Arbitré entre interface virtuelle et socket local pour portabilité multiplateforme
Bonne réflexion, et tu as toi-même trouvé le problème : l'interface TUN c'est mort pour le multiplateforme. TUN/TAP c'est Linux/Mac avec des droits root, Windows c'est une galère avec des drivers, Android c'est le VpnService API de Java... tu passes ton temps à gérer des cas OS au lieu de construire ton truc. On oublie.

La vraie question : c'est quoi ton protocole local ?
Socket Unix → Linux/Mac seulement, Android non standard TCP localhost → partout, Android inclus, Windows inclus, MicroPython presque

→ TCP localhost gagne, c'est le plus universel. Port fixe, genre localhost:52525. N'importe quoi peut s'y connecter.

Python sur Android
C'est possible, plusieurs approches :

Termux — terminal Linux sur Android, Python natif, mais c'est pas une vraie appli
Kivy / BeeWare — frameworks pour faire de vraies applis Android en Python
Chaquopy — embarque Python dans une appli Android native Java/Kotlin
Pour ton daemon mesh, Termux c'est parfait pour commencer, et BeeWare pour plus tard si tu veux une vraie appli packagée.

Ce que ça donne comme vision globale
┌─────────────────────────────────────────┐
│  N'importe quelle appli, n'importe où   │
│  (Python, Go, JS, Java, bash...)        │
└──────────────┬──────────────────────────┘
               │  TCP localhost:52525
               │  (protocole simple, JSON ou binaire)
┌──────────────▼──────────────────────────┐
│         meshnet daemon                  │
│         (pur Python, asyncio)           │
│         tourne partout où y'a Python    │
└──────────────┬──────────────────────────┘
               │  réseau maillé
         ┌─────┴──────┐
       [TCP]  [BLE]  [...]
La vraie décision restante
Le protocole entre l'appli et le daemon local — c'est quoi le format des messages ?

JSON sur TCP → lisible, debuggable, universel, un peu verbeux
MessagePack → JSON binaire, compact, toujours universel
Protobuf → très solide mais dépendance externe et génération de code
Mon instinct pour un projet qui vise le maximum de portabilité et de simplicité : JSON sur TCP localhost. Debuggable avec netcat, pas de dépendance, tout le monde sait le parser.

T'es d'accord avec cette direction ou tu veux challenger quelque chose ?

Euh, ce que tu viens de me dire, ça c'est intéressant. Donc effectivement, l'idée du localos, donc ce serait quelque chose, on écoute, on ouvre un socket en gros. Je j'essaie de redire de ma même manière. On ouvre un socket donc sur localos, c'est un peu comme un service, je ne sais pas comme un serveur web. Et donc à partir de là, des clients pourraient se connecter dessus, pour échanger donc par exemple une application de monitoring, de monitoring d'appareils se connecterait dessus. Et donc, il faudrait pouvoir contrôler en gros cette node, mais je donc en gros, le projet GitHub où j'ai dit beaucoup de fois en gros, désolé. Il faut que je corrige ça. Mais donc le projet GitHub, ce serait un serveur, enfin du coup non, un serveur, une node, un mesh, une sorte de diamond si on puisse dire de, oui de process qui donc écoute et se contrôle via via du coup des appels à localhost, un certain port, enfin via en gros des connexions TCP via un certain port du localhost. Donc en gros ce que tu es en train de me dire c'est presque sorte d'API, c'est ça ? Enfin peut-être pas du coup de la ChatGPT tout ça, mais donc enfin la manière d'un serveur web, on envoie des des des connexions créent un socket sur le local. C'est ça, c'est créer un socket sur le local si j'ai bien compris. Donc si c'est ça dont tu me diras si oui non. Si oui, effectivement le JSON me plaît. Le JSON me plaît maintenant effectivement un peu verbeux, oui, j'imagine que c'est un peu lourd. Ce qui serait intéressant, c'est effectivement de faire en sorte que ce soit, comment dire, que ce soit le plus léger possible. Alors je ne sais pas est-ce qu'il y a moyen alors ne message pas que c'est quoi mes gisons binaires, c'est-à-dire tu en gros on fait un un gison point n code quelque chose comme ça ou gison point tout je ne sais pas point l'audace enfin tu sais il y a les la librairie gison python fait gison point load l o a d s à la fin et donc j'imagine que ça décode du gison. Est-ce que c'est un système comme ça qui ressemble à ça ? Dans ce cas-là ça me plaît vraiment beaucoup parce que ça pour le coup je m'en suis déjà servi une perte de foi et je trouve ça vraiment bien. Voilà dit moi

Show more
15 mai

Clarified local socket API architecture et arbitrated JSON versus MessagePack tradeoffs
Clarified local socket API architecture et arbitrated JSON versus MessagePack tradeoffs
Oui t'as tout compris. C'est exactement ça — un socket TCP local, c'est conceptuellement la même chose qu'un serveur web, sauf que c'est sur 127.0.0.1 donc seule ta machine peut s'y connecter. Et oui, json.loads / json.dumps, c'est exactement l'API Python que t'utiliserais.

JSON vs MessagePack — soyons honnêtes
MessagePack c'est du JSON binaire — même structure, même concept, juste plus compact. Mais concrètement sur un socket local, tu transferts des données entre deux process sur la même machine. La "lourdeur" du JSON elle est quasi invisible — on parle de microsecondes.

La vraie lourdeur du JSON c'est sur des millions de messages par seconde ou sur des liens radio très contraints (LoRa, par exemple). Pour une API de contrôle locale, c'est négligeable.

Mon avis tranché : commence avec JSON. Pourquoi :

Tu débogues avec n'importe quoi, même netcat ou telnet
Zéro dépendance externe
Si un jour t'as un vrai besoin de perf, tu swappes MessagePack en une heure
Ce que t'as en tête, reformulé proprement
[ application cliente ]
        ↓
  connexion TCP sur 127.0.0.1:52525
        ↓
  envoie  → {"action": "send", "to": "node_abc", "data": "..."}
  reçoit  ← {"event": "message", "from": "node_xyz", "data": "..."}
        ↓
[ daemon meshnet ]
        ↓
  [ réseau maillé P2P ]
C'est vraiment propre comme architecture. Le daemon c'est une boîte noire — tu lui parles en JSON, il fait son boulot sur le réseau.

On est bien alignés sur la vision globale maintenant. Tu veux qu'on continue le brainstorming sur quoi — la structure des messages JSON de l'API locale, ou plutôt les concepts internes du maillage ?

J'aimerais revenir sur ce gise, donc ok pour le socket, ça j'ai bien compris. Maintenant donc message pack. Tu me dis c'est du giseau binaire, même structure, même concept, juste plus compact. Concrètement, fais-moi juste un exemple de code pour que je joue un peu sous les yeux que je comprenne en fait ce que c'est. Je prends un exemple python en fait qui génère entre guillemets un blob giseau qui envoie du giseau à quelque chose et un bloc de code qui envoie du message pack à quelque chose juste pour que je comprenne la différence.

15 mai

Préparé exemples de code Python comparant sérialisation binaire et MessagePack
Préparé exemples de code Python comparant sérialisation binaire et MessagePack
python
import json
import msgpack  # pip install msgpack

message = {
    "action": "send",
    "to": "node_abc",
    "data": "hello world",
    "ttl": 5
}

# ── JSON ──────────────────────────────────────────
json_bytes = json.dumps(message).encode("utf-8")
print(json_bytes)
# b'{"action": "send", "to": "node_abc", "data": "hello world", "ttl": 5}'
print(len(json_bytes), "octets")  # 68 octets

# pour décoder :
recu_json = json.loads(json_bytes.decode("utf-8"))
print(recu_json["action"])  # "send"


# ── MessagePack ───────────────────────────────────
mp_bytes = msgpack.packb(message)
print(mp_bytes)
# b'\x84\xa6action\xa4send\xa2to\xa8node_abc\xa4data\xabhello world\xa3ttl\x05'
print(len(mp_bytes), "octets")  # 48 octets

# pour décoder :
recu_mp = msgpack.unpackb(mp_bytes, raw=False)
print(recu_mp["action"])  # "send"
La différence visible : JSON c'est du texte lisible à l'œil nu, MessagePack c'est du binaire. Même données, même dict Python des deux côtés, juste la représentation intermédiaire change.

30% plus compact sur cet exemple. Sur un message avec beaucoup de texte la différence diminue, sur un message avec des nombres elle augmente (un entier 5 en JSON c'est 1 octet de texte, en msgpack c'est 1 octet binaire — pareil. Mais un entier 123456 en JSON c'est 6 octets, en msgpack c'est 3).

Conclusion concrète pour toi : la seule vraie différence c'est que JSON tu peux le lire dans ton terminal quand tu débogues, MessagePack tu vois des caractères bizarres. Pour démarrer, JSON c'est clairement plus confortable.

En fait, ne message pas que ça me plaît beaucoup parce que le truc, c'est que j'aimerais bien, comment dire, pour faire du temps réel en fait et que c'est moche. Tu vois, selon les capacités du lien, ça aussi c'est quelque chose qu'il va faire plus tard, analyser la capacité du lien et si oui, pouvoir faire du temps réel par exemple échanger de la voix, tu vois. Genre je ne peux pas écouter un son, en temps réel fait passer de l'audio, voir de la vidéo selon les capacités des des liens encore une fois, tout ça faire du temps réel. C'est pour ça je veux vraiment un code aussi que soit plutôt optimisé, tu vois. Alors je ne devrais pas faire, je ne sais pas, du cent mégasseconde, mais si on arrive déjà à atteindre quelque chose comme cinq mégas par seconde par exemple de de vitesse de transmission, tu vois tout en ayant du code qui soit parfaitement memory safe, multi plateformes. Donc en fait, je pense à Python, c'est pour ça parce que concrètement Python, ça peut tourner sur une s p trente deux, comme ça peut tourner sur un ordinateur, un téléphone, enfin ça tourne à peu près partout, surtout en s b r i p r o s. E s p trente deux, c'est le micro Python, c'est vrai. Un petit raspberry pi, l'épi zéro w à ce que je sache, on peut faire tourner un vrai Python dessus et ça ne coûte pas cher. Donc le message pack me plaît parce qu'effectivement ça m'aide à être plus léger maintenant, ce que ça peut permettre de faire du temps réel, même si on envoie de la voix que je ne sais pas, genre soixante quatre kilos secondes, est-ce que ça c'est faisable

Show more
15 mai

Évalué la faisabilité du temps réel audio et architecture optimisée
Évalué la faisabilité du temps réel audio et architecture optimisée
Oui 64 kbps voix c'est totalement faisable, c'est rien — un codec Opus à 64 kbps c'est 8 Ko/s, même un lien bas débit le gère.

Mais tu viens de soulever un truc important qui change l'architecture.

Le vrai problème : deux types de données très différents
Pour du temps réel (voix, vidéo), t'as deux mondes qui n'ont pas du tout les mêmes contraintes :

Messages de contrôle — "envoie ça à node_abc", "quelle est la topologie", "quel est ton CPU" → faible débit, latence pas critique, JSON/MessagePack parfait

Flux temps réel — audio, vidéo → débit continu, latence ultra critique, le moindre overhead de sérialisation ça se sent

Si tu fais passer un flux audio de 64 kbps à travers ton API JSON localhost, tu vas te battre avec la sérialisation, les copies mémoire, le parsing. C'est pas fait pour ça.

Ce que ça implique
Il faut probablement deux canaux distincts sur le daemon :

App cliente
  ├── socket JSON  localhost:52525  → contrôle, commandes, événements
  └── socket binaire localhost:52526 → flux temps réel brut
Le canal temps réel c'est du binaire pur — header minimal, payload raw, zéro parsing. Là MessagePack ne sert même plus à rien, c'est trop de overhead encore. Tu veux juste :

[ taille:2 | type:1 | timestamp:4 | payload brut ]
ESP32 — soyons honnêtes
MicroPython sur ESP32 c'est un sous-ensemble très limité de Python. Ton daemon complet ne tournera pas dessus tel quel. Il faudra une version "nano" allégée pour ce type de cible. Raspberry Pi Zero W par contre, Python complet, aucun problème.

En résumé : l'architecture à deux canaux (contrôle + temps réel) c'est une décision importante à prendre maintenant avant de coder quoi que ce soit. T'es partant pour ça ?

Alors l'architecture de canot ça me plaît. Par contre comment est-ce que tu sécurises ça ? Parce que moi j'aimerais aussi que pas n'importe quelle application qui tourne sur cet appareil puisse y accéder. C'est-à-dire qu'en gros, il faut un peu qu'on authentifie ses clients, il faut qu'on authentifie qui puisse parler tu vois ? Parce que donc l'idée de base c'était de faire quasiment une sorte de librairie. Enfin comment dire, mon idée c'était oui voilà faire quelque chose qu'on puisse imbriquer dans un logiciel pour que justement on limite vraiment ce qui passe au travers de ces notes. Tu ne vas pas qu'une application malveillante puisse envoyer des messages sur ce réseau mèche. C'est pour ça qu'au début je pensais une librairie, comme ça je t'appelle une fonction, c'est, ce n'est pas, je ne sais pas, depuis ton programme classique, t'appelle une fonction send m s g qui envoie des données enfin ou send data qui envoie des données et du coup on limite en fait finalement l'utilisation de cette librairie de de ce réseau mesh à l'application

Show more
15 mai

Pesé sécurité daemon versus approche bibliothèque pour authentification
Pesé sécurité daemon versus approche bibliothèque pour authentification
Très bonne question, et tu viens de toucher un vrai dilemme architectural.

Le problème fondamental
Les deux approches ont des compromis opposés :

Daemon + socket local

Pratique, universel, n'importe quel langage
Mais : n'importe quel process sur la machine peut se connecter à localhost:52525. Tu peux mettre un mot de passe, mais si une appli malveillante tourne avec le même utilisateur système, elle peut lire ce mot de passe en mémoire ou sniffer le socket.
Librairie importée

Sécurité naturelle — c'est ton process, ta mémoire, ton contexte
Mais : couplé à Python, et si l'appli plante le nœud réseau meurt avec
La vraie réponse : ça dépend de ton modèle de menace
La question c'est : tu te protèges contre quoi exactement ?

Une appli malveillante installée par l'utilisateur → les deux approches sont vulnérables si elle tourne avec les mêmes droits
Un processus qui tourne sous un autre utilisateur système → le daemon avec permissions OS suffit, seul ton user peut se connecter
Un attaquant réseau externe → le socket localhost est inaccessible depuis l'extérieur par définition
Ce que font les vrais systèmes
Docker, par exemple, utilise une socket Unix avec des permissions fichier — seul root ou le groupe docker peut y accéder. C'est l'OS qui gère l'autorisation, pas le protocole.

Bluetooth sur Linux c'est bluetoothd — un daemon, accès contrôlé par D-Bus avec un système de capabilities.

Ma suggestion pour toi
Les deux, en fait. Une architecture hybride :

┌─────────────────────────────┐
│     ta lib Python           │  ← ce que tu distribues sur GitHub
│                             │
│  - importe directement      │
│  - OU se connecte au daemon │
│  - même API dans les deux   │
└─────────────────────────────┘
Tu fournis une lib avec une interface propre. En interne, elle peut soit tourner le nœud mesh directement dans le process, soit se connecter à un daemon existant si il tourne déjà. Le choix appartient au développeur qui utilise ta lib.

La sécurité du daemon c'est alors une question de déploiement — permissions système, pas ton problème à toi.

Tu veux qu'on décide ça maintenant ou tu préfères d'abord définir ce que la lib expose comme interface publique ?

Bon alors cependant je ne suis pas sûr de ce que je vais dire là, mais je crois que sous Linux tant que tu n'es pas route, tu ne peux pas signifier la mémoire d'une autre appli ou du moins sur des systèmes basés sur le carnet Linux. Est-ce que tu peux me confirmer ça s'il te plaît

15 mai

Corroborated la théorie d'isolation mémoire Linux
Corroborated la théorie d'isolation mémoire Linux
Oui, tu as raison. Sur Linux, chaque processus a son propre espace mémoire virtuel isolé par le noyau. Un processus non-root ne peut pas lire la mémoire d'un autre processus.

Plus précisément :

/proc/<pid>/mem — le fichier qui permet d'accéder à la mémoire d'un process, est protégé par les permissions Unix. Tu ne peux y accéder qu'avec ptrace, qui requiert soit d'être root, soit d'être le process parent.
ptrace — l'appel système utilisé par les debuggers comme gdb. Bloqué entre process non liés sans privilèges.
Sur les systèmes avec Yama LSM activé (la plupart des distros modernes), même un process parent ne peut pas ptrace un enfant par défaut sans config explicite.
Donc ton raisonnement tient : si le daemon tourne sous un utilisateur dédié et que le socket Unix a les bonnes permissions, une appli malveillante qui tourne sous un autre utilisateur ne peut ni lire ta mémoire, ni se connecter à ton socket.

Ce qui veut dire que l'approche daemon avec socket Unix + permissions fichier OS est en réalité plus robuste que ce que tu pensais. Android c'est aussi un noyau Linux, donc les mêmes garanties s'appliquent — c'est d'ailleurs pour ça qu'Android isole si bien les applis entre elles.

Ça change ton ressenti sur l'architecture daemon ?

Alors en fait non, ce que je pensais, c'est que le fait qu'on ne puisse pas lire les mémoires d'une autre application, est-ce que du coup ça veut dire que même deux applis qui tournent sur le même user, est-ce qu'une appli peut interagir avec l'autre, avec la mémoire de l'autre ?

15 mai

Démêlé les nuances entre isolation mémoire et communication inter-processus
Démêlé les nuances entre isolation mémoire et communication inter-processus
Non, même deux process sous le même user ne peuvent pas accéder à la mémoire l'un de l'autre. L'isolation mémoire c'est par process, pas par user. C'est le noyau qui impose ça, peu importe qui tu es.

La nuance c'est ptrace — un process peut débugger un autre process du même user avec ptrace. Mais c'est un appel système explicite, pas un accès mémoire direct. Et sur les distros modernes avec Yama activé, même ça c'est restreint aux relations parent-enfant.

Ce que ça change pour ton architecture
Donc la vraie surface d'attaque du daemon c'est pas la mémoire — c'est le socket. Une appli malveillante sous le même user ne peut pas lire ta mémoire, mais elle peut se connecter à localhost:52525 parce que le réseau local ne distingue pas les users.

D'où l'intérêt de la socket Unix avec permissions fichier plutôt que TCP localhost :

/var/run/meshnet/control.sock  → permissions 660, groupe meshnet
Seuls les process qui appartiennent au groupe meshnet peuvent s'y connecter. C'est l'OS qui gère, c'est solide.

En résumé :

Mémoire → isolée par process, tu es tranquille
Socket TCP localhost → accessible à tout process du système
Socket Unix + permissions → accessible uniquement aux process autorisés par l'OS
Ok, donc moi comme j'ai dit, je n'en a pas forcément fait en fait me baser sur l'architecture d'avoir un socket et d'écouter ce socket, une x par exemple comme tu as dit avec slash contrôle point soc parce que le problème c'est que ça va le porter en fait, enfin c'est faisable, le porter sur un sur un Android je pense, mais quelque chose me dit que imbriquait ça dans une application Android totalement autonome, ça doit être un peu chiant tu vois, enfin ça ne doit pas être simple à mon avis. Donc c'est ce n'est pas forcément la solution que je rechercherai, tu vois je pense que se limiter à une librairie à ce limité à la librairie, tu vois, ce serait bien. Donc juste je fais importe, enfin un, j'importe donc ma librairie et depuis on programme, je ne sais pas de supervision par exemple, j'utilise les fonctions pour échanger des données. C'est ce qui me semble en tout cas, comment dire, niveau simplicité, pas trop mal et niveau sécurité très correct. À toi de me dire maintenant ou peut-être que le le socket est c'est aussi faisable sous Android, le le socket Unix, le contrôle pour un soc. mais là encore en fait, je n'ai pas envie en fait de devoir faire de la gestion multi utilisateurs, tu vois, je veux que tu puisses le et ton propre utilisateur, mais que seules les applis qui sont autorisées, aient le droit de l'exécuter en gros. Parce que si on commence à devoir demander aux gens qui utilisaient alors oui, il faut que vous fassiez un utilisateur à part pour sécuriser, personne ne va le faire, ce ne sera jamais sécurisé, ce sera de la grosse merde. voilà en fait il faut que ce soit un peu full proof, enfin c'est de l'anglais, mais tu as compris je pense. Donc vraiment il faut aller au simple. Si le fait de faire une librairie que tu imblies un un brique dans un programme c'edt fesable, on  le fait

Show more
15 mai

Évalué les avantages d'une approche bibliothèque pour la simplicité et la sécurité
Évalué les avantages d'une approche bibliothèque pour la simplicité et la sécurité
Oui, la librairie pure c'est la bonne décision pour toi. Et les raisons sont simples :

Sécurité — c'est ton process, ta mémoire, zéro surface d'attaque externe. Pas de socket à exposer, pas de gestion de permissions à expliquer aux gens.

Portabilité — Android, ESP32 avec MicroPython lite, Windows, Linux, Mac — tu importes, ça tourne. Zéro config système.

Simplicité d'usage — un développeur fait from meshnet import MeshNode et c'est parti. C'est le niveau de friction zéro que tu veux.

La seule vraie limite de ce choix
Si tu veux que plusieurs applis sur la même machine partagent le même nœud mesh — par exemple une appli monitoring ET une appli voix qui utilisent toutes les deux la même connexion réseau mesh — là la librairie seule ne suffit plus, il faut un daemon.

Mais pour commencer, et pour la majorité des cas d'usage que tu décris, une appli = un nœud, et c'est parfaitement cohérent.

Ce que ça veut dire concrètement
python
from meshnet import MeshNode

node = MeshNode(node_id="mon_tel")
node.add_transport(TCPTransport(port=5000))
node.on_message(lambda msg: print(msg))
node.start()
node.send(to="node_pc", data=b"hello")
Propre, lisible, portable, sécurisé par nature. On brainstorme quoi maintenant — l'API publique de la lib, ou les concepts internes du routage ?

En fait, je pense commencer justement par une appli à un noeud, donc une simple librairie et au pire, plus tard, je pourrais développer une vraie application, enfin une application qui écoute sur un socket sur la machine, tu vois. Donc en gros d'abord je développe une librairie meshnet, comme ça on peut avoir tout type de notes qui se connectent et puis si plus tard j'ai le besoin de me faire plusieurs applications qui passent par là, alors je crée un autre projet GitHub qui va s'appeler meshnet node serveur quelque chose en tout cas qui va écouter sur du socket, qui va implémenter une tonne de mécanismes de sécurité et qui va permettre donc de faire passer plusieurs applications par une seule node.

15 mai

Synthétisé l'architecture logicielle en deux phases progressives
Synthétisé l'architecture logicielle en deux phases progressives
Parfait, c'est une décision très propre. Tu as exactement le bon raisonnement — d'abord la fondation, ensuite les surcouches.

Ce que t'as décidé ce soir :

Projet 1 — meshnet (la lib)

Librairie Python pure
Une appli = un nœud
Multiplateforme maximum
Sécurité par isolation naturelle du process
Transports pluggables (TCP d'abord)
Routage maillé résilient, P2P, pas de serveur central
Projet 2 — meshnet-daemon (plus tard, si besoin)

Embarque la lib meshnet
Écoute sur socket Unix ou TCP local
Gestion auth, multi-clients sur une même node
C'est un projet séparé qui dépend du projet 1
C'est vraiment une bonne architecture parce que le projet 2 ne sera jamais bloquant — si quelqu'un en a besoin il le fait, sinon la lib seule suffit. Et la lib reste propre et indépendante.

On continue le brainstorming sur quoi maintenant ? Je vois deux sujets encore ouverts :

L'API publique de la lib — ce que le développeur voit et utilise
Le protocole interne — comment les nœuds se parlent entre eux sur le réseau
Alors l'API publique de la librairie, ça c'est une très bonne question. Comment est-ce qu'on va faire ? Je pense que oui, ça appartient en fait on appelle on appelle de fonction quoi. Maintenant pour définir les méthodes, je pense qu'on doit d'abord définir le protocole interne. Non ensuite pour voir comment est-ce qu'on appelle depuis l'extérieur, il faut voir comment est-ce que ça marche à l'intérieur. En tout cas, c'est ce qui me semblerait logique, non ?

15 mai

Endorsed bottom-up design strategy for internal protocol definition
Endorsed bottom-up design strategy for internal protocol definition
Oui, totalement logique. L'API publique c'est juste la façade de ce qui se passe en dessous — si tu ne sais pas ce qui se passe en dessous, tu ne peux pas concevoir une façade cohérente.

Donc protocole interne d'abord. Et là il y a plusieurs sous-sujets, dans l'ordre logique :

Format des paquets — ce qui circule sur le réseau entre les nœuds
Découverte — comment un nœud sait que les autres existent
Routage — comment un paquet trouve son chemin dans le maillage
Gestion des liens — détection de panne, bascule automatique
Tu veux qu'on attaque dans cet ordre ou t'as une autre priorité ?

Alors donc pour le format des paquets, pour le format des paquets, oui donc on a dit on doit être amnésique de la manière dont ça dont ça circule de dont ça se transporte. C'est une très bonne question, donc ça on va peut-être, donc je ne vais pas l'aborder tout de suite parce que là on est vraiment dans du protocole pur. Je pense qu'on peut définir d'autres choses avant de définir ça. Donc pour la découverte, en gros comment comment ne sait que les autres existent et comment on rejoint ce réseau. Alors là ce sera intéressant de voir comment font d'autres parce qu'en fait la question que je pose c'est si je suis par exemple sur mon téléphone en quatre g ou derrière un réseau NAT. Par défaut on d'accord que Je ne peux pas avoir de connexion entrante. Alors comment ça marche dans les réseaux pire tout pire enfin dans dans le torrent, je sais que ça ne fonctionne pas. Ah oui dans le torrent ça peut fonctionner en quatre g. Donc là je serai intéressé de voir comment est-ce que ça marche pour le torrent ou pour mettre tous les autres types de réseaux décentralisés en fait. Ça faut faut s'y intéresser. Je pense qu'on va commencer par ça en fait. Tu pourras tiens d'ailleurs rechercher comment est-ce que font les autres réseaux décentralisés pour que les notes se joignent entre eux malgré le fait qu'on puisse avoir du NAT en fait ce genre de choses.

Show more
15 mai

Synthesized decentralized network NAT traversal and peer discovery techniques
Synthesized decentralized network NAT traversal and peer discovery techniques
Ok, très intéressant. Voilà ce que font les vrais réseaux décentralisés.

Le problème du NAT — pourquoi c'est chiant
Quand t'es derrière un NAT (4G, box Internet, réseau d'entreprise), ton IP publique est partagée avec plein d'autres. Personne ne peut initier une connexion vers toi de l'extérieur — ton routeur ne sait pas à qui la transmettre.

Les techniques qui existent
1. UDP Hole Punching — la plus utilisée
Chaque hôte envoie un paquet UDP à travers son NAT, ce qui crée un "trou" — un mapping dans la table NAT. Quand les deux pairs connaissent l'IP:port externe de l'autre, ils peuvent s'envoyer des paquets directement à travers ces trous. 
OneUptime

Environ 82% des NATs supportent le hole punching UDP. C'est la fondation de WebRTC, WireGuard, et plein de jeux en ligne. 
arxiv

2. STUN — comment tu trouves ta propre IP publique
T'as un petit serveur STUN quelque part sur Internet. Tu lui demandes "c'est quoi mon IP publique et mon port ?" Il te répond. Maintenant tu peux communiquer cette info à tes pairs.

3. TURN — le fallback quand rien d'autre ne marche
TURN c'est le fallback quand le hole punching échoue — contrairement à STUN, TURN relaie réellement les données. Dans les déploiements WebRTC typiques, TURN est nécessaire pour environ 10-15% des connexions, surtout sur les réseaux cellulaires et les Wi-Fi d'entreprise restrictifs. 
Pinggy

4. DHT (Distributed Hash Table) — comment BitTorrent découvre les pairs sans serveur central
Pour bootstrapper dans le réseau, on se connecte d'abord à quelques nœuds connus. Ces nœuds envoient des adresses IP de pairs, qui elles-mêmes donnent d'autres adresses, et ainsi de suite — comme suivre un arbre des racines aux branches. 
Make Tech Easier

La leçon clé pour ton projet
Aucun réseau P2P n'est vraiment 100% sans serveur central au démarrage. Même BitTorrent a ses nœuds DHT de bootstrap connus à l'avance. La différence c'est que ces serveurs ne font que mettre en relation — ils ne relaient pas les données. Après le handshake, c'est du vrai P2P direct.

Pour toi ça veut dire qu'il faut décider : est-ce que tu veux des nœuds bootstrap quelque part, ou est-ce que la découverte se fait uniquement sur le réseau local (mDNS/broadcast) et par configuration manuelle ?

Ce que je suggère pour ton cas
Phase 1 — réseau local : mDNS/broadcast UDP
           (les nœuds sur le même subnet se trouvent tout seuls)

Phase 2 — Internet : quelques nœuds bootstrap connus
           + UDP hole punching pour connexion directe
           + TURN minimal en fallback si le hole punching échoue
Le STUN c'est gratuit et public (Google en fournit), le TURN c'est le seul truc qui coûte vraiment quelque chose à opérer.

Tu veux qu'on creuse l'un de ces mécanismes en particulier ?

Ok, alors désolé, je n'ai pas trop lu, faites suggestions, enfin là, je je l'ai lu juste maintenant. Donc donc donc donc, alors on ne va pas faire de ou de turn, enfin ce qui m'embête, c'est de dépendre d'un autre, tu vois. Alors peut-être que par la suite, on pourrait peut-être mettre aussi un plugin pour ça ou une nouvelle fonctionnalité, tu vois, mais ne sera pas pour tout de suite. En fait au début, ce que j'ai juste pensé, c'est effectivement faire un peu notre entre guillemets notre serveur turn et de l'u d p enfin le la la première solution tiens à proposer avec l'u d p, c'est rentrer sympathique, ça j'aime bien, ça faut à l'implémenter clairement. Alors il faudra, enfin je ne sais pas du tout comment ça marche. Là, je viens de découvrir, donc c'est comme ça que marche des gens en ligne tout ça. Tu viens de me l'apprendre, je ne savais pas jusque maintenant. Donc ça en fait, il va falloir donc voilà que tu m'expliques comment implémenter ça, mais plus tard, pas tout de suite. Et donc pour le Stone, effectivement ça, enfin Stone et surtout Turn, donc la solution numéro trois, en fait je pense qu'en fait vu que notre architecture t'aura un, il y aura un système de node qui peuvent comment dire, qui peuvent relayer des informations, je pense qu'on donnera comment dire un un rôle à des notes, tu vois quelque chose comme par exemple la note téléphone, on ne peut pas la joindre par son IP publique parce qu'elle est sur un réseau bizarre d'entreprise ou je ne sais pas quoi. Par contre la note serveur numéro quatre, bon lui il a une IP publique directe ou la note ordinateur perso, lui il est une box standard qui supporte le la solution numéro un. Du coup lui on peut aussi le joindre. En fait tu vois faire une sorte de de partage justement d'un formation de qui est-ce qu'on peut joindre et comment pour s'intégrer au réseau et avoir une sorte de table de routage en fait qui se construit. Alors maintenant si je tends la question numéro deux, il va falloir qu'on s'intéresse au système de routage en fait. Alors il faudrait qu'on voit déjà qu'est-ce qui existe actuellement comme protocole de routage et est-ce qu'on ne pourrait pas s'en inspirer pour faire quelque chose d'intéressant.

Show more
15 mai

Synthesized routing protocol options and formulated tailored recommendation
Synthesized routing protocol options and formulated tailored recommendation
Ok, voilà le panorama des protocoles existants. Je te l'explique clairement.

Les trois familles de protocoles de routage
Proactif — chaque nœud connaît toute la topologie en permanence
Exemple : OLSR, BATMAN

Chaque nœud envoie régulièrement des messages "je suis là, voici mes voisins". Tout le monde maintient une carte complète du réseau. Quand t'as besoin d'envoyer un paquet, la route est déjà connue — réponse immédiate.

Avantage : latence très faible, route immédiate Inconvénient : trafic de contrôle permanent, même si personne n'envoie rien

Réactif — on calcule la route seulement quand on en a besoin
Exemple : AODV, DSR

Quand A veut parler à C et ne connaît pas la route, il flood le réseau "quelqu'un connaît C ?". C répond, la route est mémorisée temporairement.

Avantage : zéro trafic de contrôle au repos, léger Inconvénient : délai à la première connexion, mauvais si le réseau change souvent

Hybride — un mix des deux
Exemple : Babel, ZRP

Babel est un protocole de routage à vecteur de distance avancé — il combine des éléments proactifs et réactifs. En tests indoor, Babel obtient la meilleure bande passante initiale (57 Mb/s) mais souffre de problèmes de scalabilité sur de nombreux nœuds. 
ResearchGate
MDPI

Ce qui est intéressant pour ton cas
Ton réseau il est particulier — il n'est pas un réseau WiFi mesh classique. Il est multi-transport, hétérogène, et les liens peuvent avoir des qualités très différentes (Bluetooth vs fibre vs 4G). Ce que les protocoles existants ne gèrent pas bien.

Ce qui t'intéresse à prendre de chacun :

D'OLSR → le concept de "hello packets" périodiques pour détecter les voisins et l'état des liens

De Babel → la gestion de métriques de lien (qualité, latence, débit) pour choisir la meilleure route

De BATMAN → l'idée simple : au lieu de calculer des routes complètes, chaque nœud sait juste "pour atteindre X, mon meilleur voisin suivant c'est Y"

Mon avis pour toi
Tu n'as pas besoin d'implémenter un de ces protocoles à la lettre. Tu peux t'en inspirer et faire quelque chose de plus simple et adapté à ton contexte. Concrètement :

Chaque nœud diffuse périodiquement un hello à ses voisins directs avec son ID et ses capacités
Chaque nœud maintient uniquement une table next-hop — pas besoin de connaître toute la topologie
La métrique de choix de route prend en compte : latence mesurée, type de transport, stabilité du lien
C'est proche de BATMAN dans l'esprit — simple, robuste, pas besoin de carte globale. Et ça scale bien.

Tu veux qu'on définisse maintenant comment cette table de routage se construit et se met à jour ?

Alors le système réactif m'intéresse parce qu'en fait j'aimerais bien que ma libre soit vraiment scalable au maximum, qu'elle puisse évoluer, qu'elle puisse fonctionner autant avec quatre appareils ou même trois que avec je ne sais pas deux-mille appareils. Bon je ne pense pas que ça arrivera très prochainement, ni serait-ce que même un jour. Mais dans l'éventualité, j'aimerais bien voilà qu'elle puisse fonctionner avec deux-mille appareils comme trois. Et donc ce qui pourrait effectivement être intéressant, c'est qu'on dise chaque node doit connaître le chemin vers je ne sais pas trois nodes Osoir tu vois. Et donc donc chacune des notes connaît le chemin vers trois autres notes, c'est-à-dire qu'elle peut avoir une chute de deux de ces liens ou qu'elle doit connaître en tout cas un nombre x de chemin, elle peut avoir un nombre un nombre du coup de chute de x moins un de chemin et toujours réussir à réintégrer les réseaux et réapprendre potentiellement de nouveaux chemins. Je ne sais pas si tu vois un peu l'idée en fait, c'est réactif, comment dire, réactif. Donc là par exemple tu dis quand a veut parler assez et que quelqu'un, enfin que l'on ne connaît pas, qui ne connaît pas la route, il floute le réseau quelqu'un connaissait. Et donc Et donc la même route et mémoriser temporairement, ok. Et donc j'irai jusque dire, donc il connaît cette route temporairement pour parler assez, mais les autres s'ils ne connaissent pas, ils vont aussi flouder le réseau à leur tour, sauf celui qui a émis pour comment dire, pour apprendre la route en fait tu vois, jusqu'à ce qu'il y ait au minimum un nombre x de personnes. Alors ça pareil, il faudrait définir en fait comment est-ce qu'on dit de combien de personnes doivent connaître le chemin vers chaque node. L'idéalement, c'est que trois personnes par exemple, le chemin vers une node ou ça je ne sais pas exactement comment est-ce qu'on pourra le définir justement parce qu'en fait le problème c'est que sinon si par exemple une aide a trois manières de sortir ou alors elle l'annonce son chemin sur être honnête oui mais du coup ça veut dire qu'en fait on arrive sur un proactif en fait où chaque noeud connaît toute la topologie en permanence. Donc quelque chose d'hybride en fait ce sera intéressant. J'aimerais que tu me parles un peu plus de de Babel, mais le problème c'est comme tu as dit, c'est qu'il y a un problème de scalabilité. Mais le réactif, voilà le réactif ce qui m'embête c'est que du coup si tu perds la connexion à une node, En fait, tu es perdue, genre tu sors du réseau, tu es fini. Tu vois, si tu peux tester un node qui tombe, que tu connais juste le choix vers un node, tu tombes, c'est fini. Donc en fait, il faudrait quand même avoir un certain nombre de connaissances, on va dire de manière de sortir, enfin une manière voilà de sortir ou alors peut-être définir ou alors peut-être définir des groupes finalement, faire une architecture semi centralisée, un peu comme le BGP. Je ne sais pas si tu vois, donc c'est-à-dire que par exemple, je ne sais pas, je vais dire voilà, alors j'ai les notes on va dire qui sont dans, imaginons entreprise a, et entreprise b et c. Et donc je vais dire en fait entreprise a et là, je ne sais pas quatre liens de sortie. Entreprise b, on a aussi quatre et c aussi. Et donc en fait, quand je vais vouloir joindre un appareil, je vais dire, enfin je ne sais pas, j'ai une note, un des milliers d'ordinateurs qui est dans l'entreprise a, vouloir joindre un des milliers d'ordinateurs qui est entreprise c, mais il ne connaît pas tous en fait. Et tout ce qu'il sait, c'est juste que c'est quelque part. Et donc en fait, je suis en train de m'apercevoir que je suis en train de réinventer les protocoles de routage TCPIP. En fait on n'a pas prendre rente la roue. C'est un peu con, mais donc je pense qu'on va peut-être faire du BGP. Ça pourrait être intéressant, tu vois, de faire quelque chose qui ressemble au BGP. Dis-moi ce que tu en penses encore une fois, j'aimerais toujours rester en histoire d'architecture décentralisée, donc dans tous les cas, il ne faut pas qu'il y ait un noeud central. Il faut que les noeuds puissent comme parler entre eux. Donc peut-être juste en fait ce que les serveurs de sortie ne servent pas à relier les communications, mais seulement à échanger les routes, tu vois de, c'est-à-dire qu'en gros il y ait des noeuds savants pour chaque qui connaissent, on va dire un groupe de notes, tu vois. Par exemple, imaginons que je connaisse un groupe d'amis. J'ai un autre ami qui en connaît un autre groupe ami et j'ai dit tiens, est-ce que tu n'aurais pas un ami qui sait faire de la soudure ? Tu vois, moi j'ai demandé ça et puis il va me donner le contact de cette personne. Un peu une idée comme ça, tu vois. En gros, on est des notes qui connaissent une liste d'autres notes. Une liste définie, tu vois un groupe et qu'on s'intègre en fait que pour rejoindre le réseau, que pour rejoindre ce ce réseau décentralisé ou voilà. En fait, on s'inscrive, on rejoigne un groupe de notes, donc un groupe d'amis, donc par exemple j'ai rejoindre, je ne sais pas, j'ai j'ai un ami qui va rejoindre un groupe d'amis, mais du coup donc, comment dire ça, je vais dire j'ai un groupe d'amis a, connais quelqu'un qui a un groupe d'amis b. Donc quelqu'un va venir dans ce groupe d'amis a, donc moi je le connais, mais les gens du groupe d'amis b ne le connaissent pas. Et donc à un moment ils vont faire, tiens est-ce que tu n'aurais pas quelqu'un qui sait faire de la soudure ? On va reprendre cet exemple. Et là je fais ah oui, j'ai quelqu'un qui a rejoint à sa moment groupe d'amis, hop voilà. Et donc dans l'idée des notes, ce serait tiens, j'aimerais joindre tel node, je ne sais pas trop où elle est. On va demander à tous les connaisseurs de groupe tu vois. Et du coup voilà en fait on va envoyer un, on va qu'on a ça envoyé en fait une sorte de broadcast on va dire allez gars, est-ce que quelqu'un ne connaîtrait pas a b six y deux? Enfin tu vois enfin un nom de note unique, en tout cas un ID, tu vois juste un ID. Et donc là il y aurait quelque part un serveur, enfin un serveur une node en fait parce qu'on peut avoir plusieurs nodes qui connaissent ce groupe, je crois qu'ils gèrent pas dire ce groupe d'amis, tu vois il y a par exemple, il y aura deux personnes dans le groupe d'amis qui connaissent tout le groupe qui feraient, ah bah oui, moi je le connais en fait. Je je connais cette personne. Et là encore je me me percevoir en te disant ça que comment dire qu'on retourne dans une décentralisation, qu'on est plus vraiment sur VGP parce que donc chaque personne finalement de ce groupe d'amis connaît son groupe d'amis. Donc en fait c'est ça, je pense qu'il faudrait s'inspirer de cette architecture, c'est j'ai un groupe d'amis que je connais, ces groupes d'amis ont chacun leur groupe d'amis et ainsi de suite tu vois, c'est-à-dire enfin ces groupes d'amis dans chaque ami qui est dans ces groupes d'amis connaît des groupes d'amis et à chaque fois je pense ça pourrait fonctionner comme ça, tu vois. Et si moi par exemple qu'on me dit est-ce que tu ne connaîtrais pas Jean-Pierre, je suis non je ne connais pas Jean-Pierre, mais je lui demande à tous mes amis qui connaît Jean-Pierre. Et du coup, je pense qu'on arrive sur un système un peu réactif finalement.

Show more
15 mai

Reconnaissait l'invention involontaire de protocoles de routage décentralisés existants
Reconnaissait l'invention involontaire de protocoles de routage décentralisés existants
Stop. Tu viens de réinventer Kademlia. Et c'est une très bonne nouvelle.

Ce que tu as décrit, c'est exactement Kademlia
Ton analogie des groupes d'amis, c'est mot pour mot le principe :

Chaque nœud connaît un nombre limité d'autres nœuds, organisés par "proximité" (pas géographique, mais par ID)
Quand tu cherches quelqu'un que tu ne connais pas, tu demandes à tes voisins les plus proches de cet ID
Eux demandent à leurs voisins, etc.
En O(log N) étapes tu trouves n'importe qui dans un réseau de N nœuds
Donc 2000 nœuds → ~11 sauts maximum. 1 million de nœuds → ~20 sauts. C'est extrêmement scalable.

C'est ce qu'utilisent BitTorrent, Ethereum, IPFS. C'est éprouvé depuis 20 ans.

Pourquoi c'est parfait pour toi
Décentralisé pur — pas de nœud central, pas de groupe "spécial"
Réactif — on ne cherche que quand on a besoin
Résilient — chaque nœud connaît plusieurs voisins, la perte d'un lien ne tue rien
Scalable — fonctionne avec 3 nœuds comme avec 2 millions
La seule vraie question maintenant
Kademlia c'est conçu pour trouver des ressources (comme dans BitTorrent — "qui a ce fichier ?"). Toi tu veux trouver des nœuds pour leur parler en temps réel.

C'est une légère adaptation mais le cœur reste identique. Tu veux qu'on rentre dans comment Kademlia fonctionne concrètement ?

oui j'aimerais bien que tu m'expliques comment fonctionne k d m l i a, je ne sais pas comment le prononcer, mais j'aimerais bien que tu me l'expliques un peu oui,

15 mai

Orchestrated clear French explanation of distributed algorithm
Orchestrated clear French explanation of distributed algorithm
Kademlia, ça se prononce "ka-deh-MEE-lia". Laisse-moi t'expliquer le concept pur, sans code.

L'idée de base — la distance entre IDs
Chaque nœud a un ID unique, par exemple sur 160 bits. Et Kademlia définit une notion de distance entre deux IDs — pas une distance géographique, mais une distance mathématique : le XOR des deux IDs.

Exemple simplifié avec des IDs sur 4 bits :

Nœud A  : 0110
Nœud B  : 0100
Distance : 0010  = 2
Ce qui est contre-intuitif mais génial avec XOR : plus deux IDs commencent par les mêmes bits, plus ils sont "proches". C'est ça qui organise tout le réseau.

La table de routage — les "groupes d'amis"
Chaque nœud maintient une table de routage appelée k-buckets. L'idée :

Tu divises l'espace des IDs possibles en tranches, selon la distance à toi
Pour chaque tranche, tu gardes en mémoire k nœuds (en général k=20)
Les tranches proches de toi sont très fines — tu connais plein de gens près de toi
Les tranches loin de toi sont larges — tu connais juste quelques représentants
Visuellement :

Toi (ID = 0110)
│
├── Distance 1  → tu connais tous tes voisins immédiats
├── Distance 2-3  → tu connais quelques nœuds
├── Distance 4-7  → tu connais quelques nœuds
├── Distance 8-15  → tu connais quelques nœuds
└── Distance 16-∞  → tu connais quelques représentants lointains
C'est exactement ton analogie — tu connais bien ton groupe proche, et tu as juste quelques contacts dans des groupes de plus en plus lointains.

La recherche — "tu connais Jean-Pierre ?"
Quand tu veux trouver un nœud avec un ID cible :

Tu regardes dans ta table — qui sont les nœuds que je connais qui sont les plus proches de cet ID ?
Tu leur demandes en parallèle : "toi, qui connais-tu qui est encore plus proche de cet ID ?"
Chacun répond avec ses propres voisins proches de cet ID
Tu recommences avec les nouveaux nœuds trouvés, en te rapprochant à chaque fois
Tu t'arrêtes quand tu ne trouves plus personne de plus proche
À chaque étape tu te rapproches mathématiquement de la cible. C'est pour ça que c'est O(log N) — le nombre de bits de différence diminue à chaque étape.

Ce que ça donne en pratique
Sur un réseau de 1000 nœuds, tu trouves n'importe qui en 3 à 5 échanges maximum. Et chaque nœud ne stocke que quelques dizaines de contacts. Pas besoin de connaître tout le monde.

Le bootstrap — comment tu rejoins le réseau
C'est le seul moment où tu as besoin d'un point de départ connu. Tu contactes un seul nœud que tu connais déjà (un ami qui t'a filé son adresse, un nœud public, peu importe). Tu lui demandes "qui est proche de mon propre ID ?". Il te répond, tu remplis ta table, et tu es intégré.

C'est ça Kademlia. Simple dans le concept, redoutablement efficace en pratique. Tu vois comment ça s'applique à ton projet ?

Ok, j'adore. C'est vraiment top. L'explication était en plus bien claire, ça, c'est vraiment bien. C'est pour ça que je paye vingt euros par mois d'ailleurs. C'est vraiment parce que tu as cette capacité à comprendre, enfin à faire en semblant que tu as compris, donner cette impression et à réexpliquer très bien. C'est vraiment top, j'adore. Donc le bout de strap, en fait j'aurais pensé, c'est-à-dire qu'en fait, je vais pouvoir faire rejoindre facilement n'importe quoi pour le contrôler, tu vois. C'est un peu cette finalité comme si je crée un réseau mesh, mais là, j'aimerais aussi avoir cette idée de jouir je vais pouvoir contrôler n'importe quoi avec ça à distance, tu vois. Genre je ramène un un EPC, une VM, alors meilleur exemple, la machine virtuelle virtuelle. Dans une machine virtuelle, je ne vais pas avoir envie de taper un ID très long, tu vois. Dans une machine virtuelle, ce que je je vais va dire avoir envie de taper tout au grand maximum, ça va être une adresse IP ou une adresse DNS et peut-être, je ne sais pas, un code un code, je ne sais pas, allez on va dire dix caractères grand max. Dix caractères, c'est déjà beaucoup, tu vois. Mais en gros, voilà, un code à dix caractères et une adresse. C'est ce que j'aimerais avoir envie de taper au grand maximum. Et donc il faudra trouver un système qui avec ces deux informations, donc alors l'adresse ça permet de joindre le noeud, mais le code AD caractère, en fait ce qui m'embête un peu, comment dire, c'est que ce n'est pas très secure, tu vois. C'est-à-dire qu'en gros si je si je dis un noeud prépare-toi à avoir quelqu'un qui va te rejoindre, en fait s'il y a quand même une certaine probabilité que quelqu'un d'autre qui brut force risque de se connecter avant moi, tu vois. Donc en fait ce sera intéressant, comment dire, de trouver un système pour lutter contre ça. Alors j'aurais pensé à combiner les deux informations, c'est-à-dire générer ce code donc depuis depuis un noeu aux gens qui est déjà dans le réseau, ils génèrent un code où il attend un code du moins, comment dire, s'il te propose un code, tu es un peu comme si je me connecte à une application en deux f a et j'ai un one time password d'entrée, tu vois un code un code unique, un code à usage unique. Et donc il faudrait voir qu'est-ce que tu aurais à proposer comme système pour lutter donc contre les personnes qui vont essayer de brut forcer pour entrer dans le réseau. Donc d'attendre en gros qu'il y a un autre qui passe en mode, qui accepte des nouveaux arrivants et qui se fasse brut forcer ou qui se brut forcer constamment et si par hasard, il y a le bon code au bon moment, quelqu'un donc de non pour entrer dans le réseau et foutre la merde. Ce que je n'ai pas envie. Il faudra plus tard implémenter plus de mécanismes de sécurité, mais déjà là, je le fais de limiter qui peut rejoindre le réseau. Ça, il faut il faut s'y pencher

Show more
15 mai

Architected brute-force resistant bootstrap mechanism combining rate limiting and time-limited codes
Architected brute-force resistant bootstrap mechanism combining rate limiting and time-limited codes
Bonne question, et c'est un vrai sujet de sécurité. Laisse-moi décomposer le problème.

Le vrai risque — quantifions-le d'abord
Un code de 10 caractères alphanumériques (a-z, 0-9) c'est 36^10 = 3700 milliards de combinaisons. Même à 1000 tentatives par seconde, c'est 117 ans pour tout tester. Le brute force pur n'est pas réaliste.

Le vrai risque c'est autre chose — un attaquant qui écoute le réseau et intercepte le code pendant l'échange. Là c'est un autre problème.

La solution — trois couches combinées
Couche 1 : code à usage unique + durée limitée
Le nœud qui invite génère un token aléatoire, valable une seule fois et 5 minutes maximum. Après utilisation ou expiration, il est détruit. Même si quelqu'un intercepte le code, il est déjà mort.

Couche 2 : rate limiting agressif
Après 3 tentatives échouées, le nœud qui invite ferme la porte et attend 60 secondes. Un brute force devient mathématiquement impossible — 3 tentatives toutes les 60 secondes, le code expire en 5 minutes, donc 15 tentatives maximum par invitation.

Couche 3 : le code ne circule jamais en clair sur le réseau
C'est là que c'est élégant. Au lieu d'envoyer le code directement :

Nœud A génère un token secret T
Nœud B connaît T (via un canal hors-bande — tu l'as tapé à la main)

Connexion :
1. A envoie un challenge aléatoire C à B
2. B répond avec HMAC(T, C) — une signature du challenge avec le token
3. A vérifie la signature — si correct, B prouve qu'il connaît T sans jamais l'envoyer
Même si quelqu'un sniffe la connexion, il ne voit jamais T — juste une signature qui ne sert qu'une fois.

Ce que l'utilisateur tape concrètement
Adresse : 192.168.1.42  (ou monserveur.dns.com)
Code    : K7X2-MNP4-QR   (généré par le nœud qui invite, affiché à l'écran)
Le nœud invitant affiche le code, l'utilisateur le tape sur le nouveau nœud. Simple, court, sécurisé.

Après le bootstrap — clés permanentes
Une fois que le nouveau nœud a rejoint, on oublie le code. Chaque nœud génère une paire de clés publique/privée à sa création. Dès la première connexion validée, les deux nœuds s'échangent leurs clés publiques et toute communication future est chiffrée et authentifiée par ces clés. Le code à 10 caractères n'a servi qu'à ce premier moment de confiance.

C'est exactement comme ça que fonctionne SSH — la première connexion demande une vérification humaine, ensuite les clés font tout.

On continue le brainstorming sur quoi — le chiffrement des communications entre nœuds, ou autre chose ?

Oui, je pense qu'il faut devoir parler du chiffrement des communications. Donc on m'a dit que les publics, que les privés, ça, ça me va, ça me paraît une solution tout à fait valable. Maintenant, donc est-ce qu'il y aurait des algorithmes qui soient résistants aux potentielles attaques quantiques qui existent déjà en Python, qui sont déjà bien implémentées et surtout assez rapides à utiliser pour du quasi-temps réel.

15 mai

Rassemblé connaissances pour répondre sur cryptographie post-quantique
Rassemblé connaissances pour répondre sur cryptographie post-quantique
Ok, bonne nouvelle — l'écosystème est là et il est solide. Voilà ce que tu dois savoir.

Ce que le NIST a standardisé
Le NIST a sélectionné CRYSTALS-Kyber pour le chiffrement/échange de clés, et CRYSTALS-Dilithium, FALCON et SPHINCS+ pour les signatures numériques. Kyber et Dilithium sont basés sur des problèmes mathématiques sur les réseaux euclidiens — petites clés, excellentes performances. 
arxiv

Pour toi concrètement, t'as besoin de deux choses distinctes :

Kyber — pour établir une clé de session chiffrée entre deux nœuds
Dilithium — pour signer et authentifier qui parle à qui
La lib Python qui existe — et elle est solide
liboqs-python — projet Open Quantum Safe, soutenu par Amazon AWS et le gouvernement canadien. C'est un wrapper Python pour la bibliothèque C liboqs, testé extensivement sur Linux, macOS et Windows, avec intégration continue. Il couvre tous les algorithmes standardisés par le NIST. 
GitHub

Il existe même des wheels précompilés pour Raspberry Pi sur piwheels — donc ça tourne sur ton Pi Zero W sans compiler quoi que ce soit. 
piwheels

La nuance importante : c'est un wrapper C sous le capot. La crypto lourde est exécutée en C compilé, Python ne fait que l'appeler. Donc les performances sont celles du C, pas du Python pur.

Ce que ça change pour ton architecture de chiffrement
Le schéma classique pour du temps réel c'est :

Établissement de session (une seule fois par connexion)
  → Kyber négocie une clé symétrique entre les deux nœuds
  → Dilithium signe pour prouver l'identité

Données en temps réel (tous les paquets)
  → AES-256-GCM avec la clé symétrique négociée
  → ultra rapide, quasi zéro overhead
La crypto post-quantique coûteuse n'intervient qu'une fois à l'établissement du lien. Ensuite tout tourne en AES symétrique qui lui est natif dans le CPU — des Gbps possibles.

La seule vraie limite
liboqs-python nécessite de compiler liboqs en C au moment de l'installation. Sur un PC ou un Raspberry Pi, c'est transparent. Sur MicroPython/ESP32, c'est mort — mais tu avais déjà dit que l'ESP32 serait une version allégée de toute façon.

Résumé des décisions crypto pour ton projet
Kyber (ML-KEM) → échange de clé de session, résistant quantique
Dilithium (ML-DSA) → authentification des nœuds, résistant quantique
AES-256-GCM → chiffrement des données en temps réel, symétrique, ultra rapide
liboqs-python → la lib, MIT license, active, multiplateforme
On continue sur quoi ? Il reste à définir le format des paquets ou tu veux aborder autre chose d'abord ?

Bon, au cas où on oublie le SP trente-deux, non, c'est mort en fait et on ne fera pas non plus de micropitons. Oubliez-les, genre vraiment oubliez-les. Mais ok, ta solution me plaît, c'est intéressant. Oui, oui, tout à fait, tout à fait, ça me plaît.

15 mai

Acknowledged user's preferences and affirmed proposed solution
Acknowledged user's preferences and affirmed proposed solution
Ok, ESP32 et MicroPython rayés définitivement. La cible c'est tout ce qui tourne un Python standard — Linux, macOS, Windows, Android (Termux/BeeWare), Raspberry Pi. Point.

Donc la stack crypto est validée :

Kyber + Dilithium via liboqs-python pour l'établissement de session
AES-256-GCM pour les données en temps réel
Récap de ce qu'on a décidé ce soir pour le projet meshnet :

Librairie Python pure, pas de daemon
Transports pluggables, TCP d'abord
Routage inspiré de Kademlia
Bootstrap par adresse + code à usage unique
Chiffrement post-quantique sur l'établissement, AES sur les données
Deux canaux : contrôle (JSON) + temps réel (binaire brut)
Il reste deux sujets de brainstorming ouverts :

Format des paquets — ce qui circule concrètement sur le réseau
API publique — ce que le développeur qui importe ta lib voit et utilise
Tu veux attaquer lequel ?

Alors pour le multicanal de base, on avait évoqué cette idée, c'était pour la connexion avec justement la node, mais entre la node et des programmes qui voulaient l'utiliser. Je te rappelle que maintenant on a oublié ça parce que et bien on on donc on passe sur une librairie piton pure. Donc en fait non, le multicanal non non pas du tout au parent, on va échanger effectivement des paquets entre les nodes. Ça il va falloir le définir. Je vais sur mon ordi comme ça je pourrais enfin, je vais essayer attribué cette conversation dans un projet pour pouvoir centraliser un peu les informations et on va définir on va définir ensemble le format des paquets. Ce sera intéressant. il

15 mai
Parfait, bonne idée de centraliser dans un projet Claude — comme ça on perd rien.

Et oui t'as raison, le multicanal contrôle/temps réel c'était pour l'API locale qu'on a abandonnée. Dans l'architecture librairie pure, il n'y a qu'un seul type d'échange : des paquets entre nœuds sur le réseau. Point.

Donc le sujet suivant c'est : qu'est-ce qui circule exactement entre deux nœuds ? Header, payload, chiffrement, tout ça.

On s'y met quand t'es sur ton ordi.

fait moi un claude.md pour claude code

15 mai

Orchestrated comprehensive Claude Code documentation framework
Orchestrated comprehensive Claude Code documentation framework
Voilà. Tu mets ce fichier à la racine de ton repo et Claude Code aura tout le contexte — les décisions prises, ce qui est exclu et pourquoi, la stack technique, et l'ordre de développement.

Quand tu seras prêt à définir le format des paquets, on continue ici ou dans le projet Claude.


Claude
Document · MD 
ajoute autre, chose, il ne doit pas me macher tout le travail, je veut etre celui qui code ce projet, copier coller de petits blocs, ook, mais surtout pas tout faire a ma place, je ne veut pas vibecoder, je vut realiser ce projet de mes mains

15 mai

Reconnu le désir d'autonomie du développeur
Reconnu le désir d'autonomie du développeur
Ajouté. Claude Code saura qu'il est là pour t'accompagner, pas pour coder à ta place.
