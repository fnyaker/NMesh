# Pièges & leçons (à lire AVANT de déboguer un blocage ou une flakiness)

Bugs réels rencontrés et corrigés. Chacun a coûté cher à diagnostiquer. Si tu
retouches la zone, garde le correctif — et si tu en ajoutes un, documente-le ici.

## Blocages (le job/nœud « ne finit jamais »)

### 1. asyncio 3.12 : `Server.wait_closed()` attend les connexions clientes
Python 3.12 a changé la sémantique : `wait_closed()` bloque jusqu'à la fermeture
de **toutes les connexions acceptées**, plus seulement la socket d'écoute.
Fermer un serveur (`remove_listen`, `close`) pendant qu'un pair reste connecté
**ne revenait jamais** → hang infini (5 h en CI avant kill).
→ Correctif : `_wait_closed_bounded()` (`tcp_transport.py`) borne l'attente.
**Ne jamais `await server.wait_closed()` nu** sur un serveur qui peut avoir des
clients vivants.

### 2. Sondes réseau bloquantes → boucle/shutdown figés
`discover_public_ip` faisait du socket **bloquant** (`getaddrinfo` sans timeout,
`connect`) directement sur la boucle asyncio. Sur réseau restreint (CI) → gel.
Piège subtil : `loop.run_in_executor(None, …)` **ne résout pas** le problème —
asyncio **joint l'executor par défaut au shutdown**, donc un thread coincé dans
`getaddrinfo` fige `asyncio.run()` à la sortie.
→ Correctif : sonde dans un **thread daemon abandonné au timeout** (jamais
joint), bornée (`_PUBLIC_IP_TIMEOUT`). Idem DNS STUN (`_bounded_getaddrinfo`).
**Toute I/O réseau bloquante potentiellement lente doit être bornée ET hors de
la boucle ET non-jointe au shutdown.**

### 3b. `asyncio.wait_for` peut *perdre* une annulation (Python 3.11)
`TCPTransport.receive` utilisait `asyncio.wait_for(readexactly, timeout)`. Si la
lecture interne se termine dans le même pas de boucle que l'annulation de la
tâche englobante, `wait_for` peut **avaler** le `CancelledError` : la boucle de
réception ne sort pas et se **re-bloque** sur le `receive()` suivant → `peer.stop()`
(qui fait `await self._task`) attend une tâche qui ne meurt jamais. Symptôme :
un `stop()` qui fige, révélé par du trafic concurrent (le gossip d'adresses
générant un PING/PONG juste avant l'arrêt).
→ Correctif : `async with asyncio.timeout(...)` au lieu de `wait_for` — il
propage l'annulation proprement. **Ne pas réintroduire `wait_for` sur un chemin
qui doit rester annulable.**

### 3. Un lien TCP inactif meurt tout seul
`receive()` TCP lève au `_READ_TIMEOUT` (60 s) sans données → lien reapé. Sans
keepalive, un lien sain mais silencieux tombe. → `_link_keepalive_loop` (PING
toutes les 20 s). Si tu vois des liens qui « tombent au bout d'un moment »,
regarde le keepalive avant tout.

### 4. Un `connect()` TCP sans timeout pend des minutes
Dialer une adresse injoignable (IP privée d'un pair NATté apprise par gossip,
hôte mort) sans borne laisse l'OS épuiser son timeout SYN (~2 min) **dans**
`_ensure_route_to` — qui est awaité par `_forward_packet` (ça gèle la boucle de
réception du lien entrant) et par le fallback de `console_ping_node`.
→ Correctif : `_CONNECT_TIMEOUT` (4 s) via `async with asyncio.timeout(...)`
(cancellable, cf. 3b) dans `TCPTransport.connect`. **Toute ouverture de
connexion vers une adresse non prouvée doit être bornée.**

### 4b. `peer.stop()` attendait sans borne une tâche annulée qui ne meurt pas
`_Peer.stop()` faisait `task.cancel()` puis `await task` **sans borne**. Quand
l'annulation tombe sur une lecture dont le future était déjà annulé, la tâche
reste marquée « cancelling » et attend un réveil qui n'arrive jamais → `stop()`
n'en revient pas. Observé sur ~1 démontage sur 3 dès qu'un nœud a plusieurs
pairs (le hang existait avant les correctifs de routage, il était juste rare).
→ Attente bornée (`_PEER_STOP_TIMEOUT`) : la fermeture du transport qui suit
détruit le lien de toute façon. `MeshNode.stop()` arrête aussi ses pairs **en
parallèle** (`gather`), sinon 128 liens empilent 128 bornes.
**Aucune attente de tâche au démontage ne doit être non bornée.**

## Routage : les bugs « ça marche à 3 nœuds, plus à 6 »

### 9. Un `FOUND_NODE` qui ne rentre pas dans un paquet — Kademlia meurt en silence
Un certificat ML-DSA-65 pèse ~7,3 ko, donc une chaîne jusqu'à une racine ~14,6 ko.
`_handle_find_node` empaquetait les `k = 20` entrées de Kademlia → ~292 ko, très
au-delà du plafond de 60 000 octets. `Packet.create` levait `PacketError`,
`_Peer._loop` avalait l'exception (« un paquet malformé ne tue pas le lien »), et
**aucune réponse ne partait**. Dès la **5ᵉ** node certifiée dans la table, tous
les `FIND_NODE` du réseau restaient sans réponse : plus de lookup, donc plus
d'`_ensure_route_to` vers un id inconnu, donc un mesh qui « marchait au début »
et se dégradait aux seuls pairs directs en grandissant. Aucun log, aucun test
rouge — les topologies de test avaient 2-5 nœuds, juste sous la falaise.
→ Réponse **budgétée** (`_FOUND_NODE_MAX_BYTES`) et certificats mutualisés dans
un pool (`_EntryPacker`) ; entrées sans chaîne sautées. Voir `routing.md`.
**Tout ce qui empaquette N certificats dans un paquet doit être borné en octets,
et vérifié par un test à N > 5.**

### 10. Acquérir une route depuis une boucle de réception : gel + interblocage
`_forward_packet` et les handlers de réponse (`_handle_find_node`,
`_handle_find_value`, `_handle_dir_find`, `_handle_echo_request`, E2E) awaitaient
`_ensure_route_to` — lookup + dial + hole punch, plusieurs secondes — **dans**
`_Peer._loop`. Deux conséquences :
1. le lien entrant ne traite plus rien pendant tout le budget (un pair qui envoie
   des paquets vers des ids injoignables gèle le lien à volonté : PING/PONG
   perdus, RTT en vrac, « le ping ne répond plus ») ;
2. le lookup lancé attend un `FOUND_NODE` qui doit souvent revenir **par ce
   lien-là** — quand c'est notre seul pair, l'attente est perdue d'avance.
Mesuré : un unique paquet non routable gelait le lien 4,95 s.
→ `_defer_route` / `_route_outbound(blocking=False)` : chemin rapide en ligne,
acquisition en tâche de fond bornée (`_MAX_DEFERRED_ROUTES`, annulée par
`stop()`). **Ne jamais awaiter `_ensure_route_to` depuis un handler de paquet.**

### 11. Les réponses étaient routées par une nouvelle supposition XOR
Une réponse (`FOUND_NODE`, `ECHO_REPLY`, ACK E2E, `DATA`) repartait par un choix
glouton recalculé de zéro, alors que le chemin que la requête venait d'emprunter
était la seule information *prouvée* disponible. Sur une chaîne ça marche par
accident ; dès qu'un nœud a plusieurs voisins, la réponse peut partir dans une
impasse et le demandeur ne voit qu'un timeout.
→ `_learn_reverse_path` / `_route_hints` (borné, daté, oublié au premier
silence), consulté par `_route_candidates`. Détail et surface d'attaque assumée
dans `routing.md`. **Un lien direct vers la cible garde toujours la priorité.**

### 12. Une limite de débit calée sur le trafic normal casse le trafic normal
Le garde-fou anti-réflexion sur `FIND_NODE`/`FIND_VALUE` a d'abord été posé à
64 requêtes / 10 s par lien. Le pic **légitime** mesuré est ~66 (α × rounds d'un
lookup, plus quelques lookups concurrents) : la limite refusait donc de vraies
requêtes et rendait les lookups aléatoires — exactement la panne qu'on corrigeait.
→ `_QUERY_RATE_MAX = 512` : une soupape anti-flood, pas du shaping.
**Mesurer le pic légitime avant de fixer une borne de débit ; le pic ne grandit
pas forcément avec le réseau (ici il est plat, borné par le comportement d'un
lookup, pas par le nombre de nœuds).**

## Sessions E2E & vivacité (les bugs « ça ne livre plus jamais »)

### 5. Répondre à un E2E_HANDSHAKE en écrasant la session empoisonne le lien
Le retry E2E réémet un handshake toutes les 5 s tant que de la data est en
file. Sur un chemin lent (relais), un doublon arrive **après** l'établissement.
Répondre naïvement = écraser la session côté répondeur avec une nouvelle clé,
alors que l'initiateur n'a plus d'état pending pour ce doublon, **ignore l'ACK**
et garde l'ancienne clé → les deux bouts chiffrent avec des clés différentes →
chaque DATA échoue au GCM → **drop silencieux et permanent** (aucun des deux
ne ré-initie : chacun « a » une session). Même effet en glare quand l'ACK
double le handshake perdant en chemin.
→ Correctif : avec une session déjà vivante, le répondeur dérive une clé
**candidate** (bornée `_E2E_REKEY_MAX`, TTL `_E2E_REKEY_TTL`) et ACK quand même,
mais ne la promeut que si un DATA **déchiffre** sous elle (preuve que le pair a
réellement complété ce handshake — cas du pair qui a perdu sa session). Un
doublon ne produit jamais un tel paquet → le candidat expire. Tests :
`tests/test_nat_relay_fixes.py`, `tests/integration/test_nat_relay_e2e.py`.
**Ne jamais réinstaller une session E2E sans preuve que le pair détient la clé.**

### 6. Le PONG est inconditionnel
`_handle_ping` ne répondait que si le PING portait des URI valides. Un nœud
NATté sans listeners (ou sans adresses annonçables) ne recevait donc **jamais**
de PONG : son `ping_sent_at` restait armé à vie (RTT jamais résolu) et le ping
console d'un pair direct semblait mort. → Le PONG suit toujours les gates
(payload non vide, src = pair authentifié, adresses décodables).
La fusion dans la table de routage, elle, se fait **toujours** pour l'émetteur
authentifié (un PING prouve sa fraîcheur même sans adresse annonçable — sinon
un pair NATté vivant se fait purger de la table faute d'adresse), mais **seules
les URI valides** sont ajoutées à `addresses` : une entrée peut donc exister
avec `addresses == []` (recency sans adresse exploitable), jamais avec une URI
mal formée dedans.

### 7. Le timeout keepalive UDP était plus court que la cadence du trafic
`_KEEPALIVE_TIMEOUT = 15 s` avec un keepalive toutes les 25 s et des PING mesh
toutes les 20 s (commentaire : « 3 missed keepalives ») → dès que les phases
s'alignaient, un lien punché **sain** était déclaré mort → flapping de route :
`_route_outbound` préfère le pair direct mourant → ECHO/DATA aspirés dans un
trou noir → « ping ne marche plus » intermittent dans les deux sens.
→ `_KEEPALIVE_TIMEOUT = 75 s` (3 × intervalle). **Un timeout de mort doit
toujours être ≥ 3 × la plus grande cadence de trafic légitime.**

### 8. Fenêtre de séquence UDP : comparaison modulaire, pas de set infini
La dédup receveur utilisait un `_recv_seen` **non borné** (spray de seq →
mémoire) et cassait le lien au wrap 2³² (tout seq post-wrap déjà « vu »).
→ `process_incoming` raisonne en distance modulaire (RFC 1982) autour du
curseur de délivrance : en-ordre → livrer ; en-avant → buffer borné
(`_MAX_REORDER`) ; en-arrière → duplicata, re-ACK. Aucun set, état borné par
construction.

## Hole punching (voir aussi `transports.md`)

- **Ne pas supprimer `_punch_pending` quand l'adresse UDP du pair est inconnue**
  (relais qui ne connaît que le lien TCP → adresse vide). L'initiateur (plus
  grand NodeID) doit garder son état pour compléter le punch depuis le PROBE
  entrant. Le supprimer bloquait le punch de façon déterministe (surtout 3.12).
- **Dé-dupliquer les transports initiateur** : les deux pairs punchent souvent
  en même temps → risque de deux `UDPTransport` vers la même adresse qui se
  courent après (aucun ne s'authentifie).
- **Kick en rafale** : ouvrir le lien punché avec UN seul keepalive était fragile
  (une perte UDP = punch perdu). `_kick_punched_link` envoie une rafale bornée.

## Tests : parallélisation & non-blocage

La suite tourne en parallèle (`pytest-xdist`, `-n auto`, config dans
`pyproject.toml`). Pièges quand tu ajoutes/déplaces un test :

- **Ports fixes = collision entre workers.** Une *fixture* partagée par plusieurs
  tests doit binder un port **éphémère** (`:0`) puis relire le port
  (cf. fixtures TCP/UDP dans `tests/test_*_transport.py`). Un port fixe unique
  par test unique est OK ; un port fixe partagé ne l'est pas.
- **Broadcast LAN = diaphonie entre workers.** Les tests qui émettent/écoutent
  sur `DISCOVERY_PORT` s'entendent entre eux. Ils sont épinglés à un seul worker
  via `pytestmark = pytest.mark.xdist_group("lan_discovery")` (+ `--dist
  loadgroup`). Tout nouveau test de broadcast doit rejoindre ce groupe.
- **Pas de réseau réel en test.** Fixture autouse `_no_public_network_probes`
  (`tests/conftest.py`) neutralise `discover_public_ip` et la sonde STUN → aucune
  dépendance Internet, aucun risque de gel. Ne pas la contourner sans raison.
- **Filet anti-hang** : `--timeout=120 --timeout-method=thread` — tout test qui
  dépasse 120 s échoue avec une trace (au lieu de 5 h). Si un test légitime
  approche cette limite, il y a un vrai problème, pas une limite trop basse.
- **Attendre une condition, pas dormir.** Remplacer `await asyncio.sleep(0.1)`
  « pour laisser propager » par un poll sur l'état observable (les transports en
  mémoire propagent en ~ms). Les tests négatifs (« rien ne se passe ») gardent un
  timeout court, mais borné.

## Divers

- `console.stop()` bloquait 0,5 s : `ThreadingHTTPServer.serve_forever()` sonde
  le drapeau d'arrêt toutes les 0,5 s par défaut. On passe `poll_interval`
  serré (`webconsole.py`, `chat_web.py`).
- Docker : liboqs est **compilé** (image de base séparée `Dockerfile.base`,
  publiée seulement aux MAJ de deps ; l'image applicative build FROM elle). Le
  build de base a besoin de `make` → `build-essential`, pas `gcc` seul (sinon
  CMake : « CMAKE_MAKE_PROGRAM is not set »).

## Maintenance de voisinage

- Le scan par bucket éloigné utilise `routing.get_closest(target, k)` trié par
  XOR : si le bucket courant est saturé, le plus ancien candidat remonte et est
  tenté d'abord — ça peut cibler un nœud déjà connecté. `_connect_routing`
  déduplique donc les sessions existantes avant de dialer.
- Les identités en échec accumulent un back-off indépendant ; sans borne
  (`_NEIGHBOR_RETRY_TRACKED`), une table de routage énorme peut faire grandir
  ce suivi sans fin. Cette table est une simple `dict` bornée en taille.
- **Au-dessus de `_NEIGHBOR_FLOOR = 3` liens vivants, un cycle de maintenance ne
  fait plus rien** (ni `kad_lookup`, ni dial) — c'est voulu (voir
  `routing.md`). Un test qui attend un dial doit donc soit rester sous le
  plancher, soit appeler `_maintain_neighbors(force=True)` ; sinon il constate
  un silence parfaitement normal et conclut à tort à une régression.
- La **promotion** (une node vue en transit, plus proche que notre pire
  créneau) dial *même en régime silencieux* : c'est un second chemin, en plus du
  scan par bucket, qui peut créer un raccourci dans un test de topologie en
  chaîne. Même parade : `_stop_neighbor_maintenance()` après le join.
- Observer une candidate ne **réveille jamais** la boucle de maintenance. C'est
  délibéré : le `src_id` d'un paquet routé n'est pas authentifié, et réveiller
  sur réception laisserait n'importe qui choisir un id proche du nôtre pour
  fixer notre cadence de dial (amplification). La candidate est traitée au
  cycle suivant, au plus 30 s après.
- Le dial multi-peer partage un deadline commun : on évite d'« attendre le plus
  lent » quand la cible est simplement injoignable. Un échec collectif est
  distingué d'un échec partiel (certains pairs répondent, d'autres non) pour
  que le fallback Kademlia ne « double-dial » pas des candidats déjà valides.
- **Un test de topologie en chaîne (A-B-C-D-E, sans raccourci) doit désactiver
  la maintenance de voisinage**, pas seulement `_punch_enabled`. Dès que les
  nœuds ont chacun une adresse TCP écoutable, `_maintain_neighbors` les
  connecte directement dès qu'ils s'apprennent via le routage (c'est le but :
  résilience par liens XOR-proches). Ça casse l'hypothèse « pas de raccourci »
  d'un test qui vérifie le multi-hop pur. `await nd._stop_neighbor_maintenance()`
  après le join. Les topologies relais (pairs NATtés sans listener, ex.
  `test_routed_ping.py`, `test_nat_relay_e2e.py`) n'ont pas ce problème : sans
  adresse dialable, la maintenance ne peut pas créer de raccourci.
- **« Forget node » (console web, `console_forget_node`) n'est pas un
  bannissement.** Il retire l'entrée de `RoutingTable` et coupe la session live
  éventuelle, mais la fusion PONG (tout émetteur authentifié est réinséré dans
  la table — voir plus haut) et le scan de maintenance de voisinage ci-dessus
  peuvent réapprendre le même nœud dès qu'il recontacte la node. Un vrai
  bannissement demanderait une liste d'exclusion persistante consultée par
  `RoutingTable.add`/PONG, qui n'existe pas aujourd'hui.
</content>
