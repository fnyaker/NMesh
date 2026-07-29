# Routage, DHT & propagation des adresses

Source : `routing.py`, `dht.py`, et dans `node.py` : `_ensure_route_to`,
`_connect_routing`, `_kademlia_lookup`, `_forward_packet`, `ping`/`_handle_ping`,
`_handle_found_node`, keepalive.

## Table de routage (`routing.py`)

Kademlia à 160 buckets. `NodeEntry` = `node_id`, `addresses`, `dsa_pub`,
`cert_chain`, **`last_seen`** (monotonic, posé à chaque `add`).

- `KBucket.K = 20`. Un bucket plein renvoie son plus ancien (candidat éviction).
  Un nœud re-`add`é est déplacé en fin de bucket (LRU → on garde les actifs).
- `RoutingTable.add(id, addresses, dsa_pub)` : **fusionne** les adresses
  (`dict.fromkeys(existing + new)`) et la clé DSA ; crée un `NodeEntry` neuf →
  `last_seen` rafraîchi. Ignore l'auto-ajout.
- `all_entries()`, `get_closest(target, k)` (tri par distance XOR),
  `export_entries`/`import_entries` (persistance ; seules les entrées avec clé
  DSA sont exportables — sans clé on ne peut pas ré-authentifier).
- `last_seen` alimente la console (« Known nodes », N plus récentes) et **doit**
  alimenter la propagation d'adresses ciblée (voir plus bas).

## Kademlia « en mieux » (routage à la demande)

Le concept de base est Kademlia, mais le routage est **agnostique du medium** et
**à la demande** plutôt qu'un simple saut XOR aveugle :

- `_forward_packet` (cf. `protocol.md`) : pair direct > **chemin retour observé**
  (`_route_hints`, voir plus bas) > plus proche voisin XOR > acquisition de route
  **en tâche de fond**. On préfère une route réellement joignable à un saut XOR
  théorique — crucial à travers des frontières réseau où seuls certains nœuds ont
  de la joignabilité.
- `_ensure_route_to(target)` : renvoie un pair authentifié vers `target`, en
  l'établissant si besoin. Ordre : pair existant → si absent de la table,
  `_kademlia_lookup` → `_connect_routing` (essaie les adresses connues, IPv6
  d'abord) → si aucune adresse joignable, `_punch_route_to` (NAT hole punch
  coordonné par un relais, cf. `transports.md`).
- `_kademlia_lookup(target)` : `FIND_NODE` itératif borné (`_KAD_LOOKUP_TIMEOUT`,
  `_KAD_LOOKUP_MAX_ROUNDS`), agrège les `FOUND_NODE` jusqu'à stabilisation.

### ⚑ L'acquisition de route ne bloque **jamais** une boucle de réception

`_ensure_route_to` dure des secondes (lookup, dial, punch). L'appeler depuis un
handler — donc depuis `_Peer._loop` — gèle le lien entrant pendant tout ce
budget, **et ne peut pas aboutir** quand le `FOUND_NODE` attendu doit justement
revenir par ce lien-là (cas du nœud qui n'a qu'un seul pair : blocage garanti).

→ `_route_outbound(packet, blocking=False)` et `_forward_packet` ne font que le
chemin rapide (envoi à un candidat vivant) ; s'il n'y a pas de candidat, le
paquet part dans `_defer_route` : une **tâche de fond bornée**
(`_MAX_DEFERRED_ROUTES`, suivie et annulée par `stop()`) qui acquiert la route
puis réémet. Tout handler appelé depuis la boucle de réception
(`_handle_find_node`, `_handle_find_value`, `_handle_dir_find`,
`_handle_echo_request`, les deux handlers E2E) utilise `blocking=False`.
`_maybe_upgrade_path` passe par la même réserve de tâches.
**Ne jamais awaiter `_ensure_route_to` depuis un handler de paquet.**

### Joindre un id **à distance** (multi-hop) — pas seulement un pair direct

**Tout ce qui adresse un `node id` est routable** et relayé de saut en saut
(`_forward_packet`, glouton vers la cible en excluant le pair d'où vient le
paquet — sur une chaîne cela dégénère en « passe à l'autre voisin ») jusqu'au
destinataire, à travers **n'importe quel medium**. Sont routables : `DATA`,
`E2E_HANDSHAKE`/`_ACK`, `ECHO_REQUEST`/`_REPLY`, **et tout le plan de contrôle
Kademlia/DHT** — `FIND_NODE`/`FOUND_NODE`, `STORE`/`FIND_VALUE`/`FOUND_VALUE`,
`DIR_STORE`/`DIR_FIND`/`DIR_FOUND`. Restent **directs** (un saut authentifié) :
`PING`/`PONG` (keepalive par lien), la signalisation de punch, et le gossip du
catalogue (re-stampé à chaque saut).

### Chemin retour appris du trafic (`_route_hints`) ⚑

La proximité XOR n'est qu'une **hypothèse** sur un overlay qu'on n'a pas fini
d'apprendre ; le lien par lequel un paquet vient d'arriver est une **preuve**
qu'il porte du trafic depuis cette source. Router une réponse par une nouvelle
supposition gloutonne, alors que le chemin de la requête est là, envoyait des
`FOUND_NODE`/`ECHO_REPLY`/ACK E2E dans une impasse.

- `_learn_reverse_path(peer, packet)` : après les portes de validation
  (`msg_id` vérifié, non-doublon, lien authentifié), on note
  `packet.src_id → pair d'entrée`. Un pair joignable en **direct** n'a pas
  d'entrée (le lien direct est déjà le plus court).
- `_route_candidates` place ce premier saut **en tête**, sauf si un lien direct
  vers la cible existe — celui-là garde toujours la main. Le reste de la liste
  (voisins triés par XOR) suit, donc un envoi qui échoue continue de descendre
  la liste.
- Borné (`_ROUTE_HINT_MAX = 256`, éviction FIFO) et daté (`_ROUTE_HINT_TTL`).
- **Auto-réparation** : `_forget_route_hint(cible)` dès qu'une requête routée
  reste sans réponse (`_kad_query_node`, `_dht_find_value_at`, `_dir_find_at`,
  `_routed_ping`) ; `_forget_hints_via(pair)` quand un lien meurt. Un premier
  saut qui cesse de porter — ou qui ment pour attirer le trafic — coûte une
  requête en timeout, puis disparaît.

Surface d'attaque assumée : un pair authentifié peut forger `src_id` pour
attirer notre trafic vers une cible et le jeter. Il ne gagne rien qu'il n'ait
déjà : le hint ne fait que **réordonner des pairs déjà authentifiés** (jamais
de saut non authentifié), il n'écrase pas un lien direct, il est borné, daté,
et effacé au premier silence. Un relais choisi par XOR pouvait déjà jeter le
trafic de la même façon.

Conséquence : `A → X en passant par tout l'alphabet` fonctionne pour **tout** —
messages, ping, DHT adressé-contenu, annuaire de pseudos — même si A et X ne
peuvent pas se connecter en direct (distant / NAT). Les requêtes (`_kad_query_node`,
`_dht_store_at`/`_dht_find_value_at`, `_dir_store_at`/`_dir_find_at`) adressent le
paquet au `node id` cible et passent par `_route_outbound` (direct si adjacent,
multi-hop sinon) ; les réponses (`FOUND_*`) sont routées en retour vers le
demandeur. Pour la **vivacité**, `console_ping_node` envoie un `ECHO_REQUEST`
routé et mesure le RTT (`_routed_ping`) ; le champ `via` vaut `direct` ou `route`.
E2E exige en plus une **racine de confiance commune** entre les extrémités (le
routage atteint la cible, l'authentification demande une ancre partagée).

## DHT adressé par contenu (`dht.py`)

- `ContentStore.put(key, value)` **refuse** si `key != sha256(value)[:20]`
  (`content_key`). → un pair ne peut jamais stocker de données arbitraires sous
  une clé choisie : l'empoisonnement DHT classique est fermé par construction.
- Borné : `_MAX_ENTRIES = 8192`, `_MAX_BYTES = 128 MiB`, éviction LRU.
- Réplication : `_DHT_K = 6` nœuds les plus proches (STORE/FIND_VALUE).
- Usage : partage d'applications (`app_package.py`, cf. `Docs/AppSharing/guide`).

## DHT par-app publique/privée (`app_dht.py`)

Overlay applicatif au-dessus du store adressé par contenu, sans en affaiblir
l'anti-empoisonnement (c'est toujours la valeur *cadrée* qui est hashée et
stockée). Chaque valeur est `app_id(8) ‖ flag(1) ‖ body` :

- **Namespace par app.** L'`app_id` est celui que le nœud tient pour la session
  authentifiée — **l'app ne le déclare pas**. Un lecteur n'accepte qu'une valeur
  dont l'`app_id` cadré correspond au sien : deux apps ne se lisent jamais, même
  en connaissant la clé de contenu de l'autre.
- **Publique** (`flag=0`) : `body = contenu` en clair → toute instance de la
  *même* app, sur n'importe quel nœud, la lit (« toutes les nodes »).
- **Privée** (`flag=1`) : `body = nonce(12) ‖ AES-256-GCM(contenu)` chiffré par
  le **nœud** sous une clé fournie par **l'app** (16/24/32 octets ; AAD =
  `app_id ‖ flag`). Seules les instances qui détiennent aussi la clé lisent.
  Le nœud fait la crypto DHT ; l'app possède le contenu, la clé, et sa
  distribution entre nœuds. AES-GCM symétrique = post-quantique.

API nœud : `app_dht_put(app_id, contenu, enc_key?) -> clé` /
`app_dht_get(app_id, clé, dec_key?) -> contenu | None`. Côté app externe, mêmes
opérations via le connecteur (`ConnectorClient.dht_put/dht_get`, l'`app_id` venant
de la session — cf. `Docs/DataConnector/guide`). Contenu borné à `MAX_CONTENT`
(≈ une valeur DHT). L'app gère son propre index de clés de contenu.

## Annuaire de pseudos (`pseudo_dir.py`)

Trouver un node_id **par pseudo**, à l'échelle du réseau — ce que l'adressage
par contenu ne permet pas (la clé y est le hash de la valeur, pas du pseudo).
C'est un **annuaire à clé** au-dessus de Kademlia, sans rien affaiblir grâce à
des enregistrements **auto-authentifiés** :

```
clé         = sha256(DOMAIN : app_id : normalise(pseudo))[:20]
réclamation = app_id ‖ ts ‖ pubkey ‖ pseudo ‖ signature ML-DSA
```

- Le **node_id réclamé est dérivé de la `pubkey`** de la réclamation
  (`NodeID.from_public_key`), et la signature est vérifiée sous cette pubkey.
  Une réclamation ne peut donc lier un pseudo qu'au node_id **de son propre
  auteur** — impossible de mapper « alice » sur le node_id d'une victime (même
  fermeture de l'empoisonnement/usurpation que le store adressé-contenu).
- Le récepteur **recalcule la clé** depuis l'`app_id` + pseudo de la réclamation
  → impossible de la déposer sous une clé sans rapport.
- Les pseudos ne sont **pas uniques** : plusieurs peuvent réclamer « alice ».
  L'annuaire garde un **ensemble borné de réclamations par clé** (la plus récente
  par node_id l'emporte) ; un lookup les renvoie toutes — le node_id reste
  l'identité réelle.

Paquets `DIR_STORE` / `DIR_FIND` / `DIR_FOUND`, répliqués/interrogés sur les
`_DIR_K` nœuds les plus proches de la clé, bornés et rate-limités par lien. API
nœud : `publish_pseudo(app_id, pseudo)` / `lookup_pseudo(app_id, pseudo)`. Côté
app : `ConnectorClient.publish_pseudo/lookup_pseudo` (app_id de la session). Le
chat publie automatiquement au `set_pseudo` et cherche le réseau au `search`.

## Maintenance de voisinage cible et recovery au démarrage

Un nœud ne survit pas à un voisinage éparse : il entretient activement un
**groupe cible de 5 voisins** choisis par distance XOR, et peut atteindre n'importe quel
node-id en relayant à travers ses voisins et la DHT même sans pair direct
commun.

- Cible `_NEIGHBOR_TARGET = 5` : au démarrage (`start()`) et à chaud toutes les
  `_NEIGHBOR_REFRESH = 30 s`, le nœud cherche les entrées XOR-les-plus-proches
  dont il n'a pas encore de session authentifiée, privilégie les buckets
  éloignés, puis tente `_connect_routing` sur les adresses connues (IPv6 puis
  IPv4). C'est un dial dirigé, pas un broadcast.
- Back-off par identité : chaque identité en échec retarde ses prochaines
  tentatives (`_neighbor_retry_until`, minimum `2 s`, plafond `60 s`) ; le
  nombre d'identités suivies est borné (`_NEIGHBOR_RETRY_TRACKED = 128`) pour
  qu'un scan large ne crée pas d'état sans fin. Une fois la session établie,
  `_add_authed_peer` efface la pénalité.
- Réseaux sans pairs directs : si nous n'avons aucune entrée voisine joignable,
  on retombe sur `_kademlia_lookup` puis un envoi multi-peer ordonné vers
  jusqu'à `_ROUTE_SEND_FANOUT = 5` candidats choisis par distance XOR, avec un
  deadline commun. Un pair qui échoue n'entraîne pas la chute du message : on
  essaie le suivant. L'échec total est repris par l'acquisition de route en
  tâche de fond (`_defer_route`), jamais en bloquant le lien entrant.
- Dernier recours : `_kademlia_lookup(target)` itératif borné (`_KAD_LOOKUP_MAX_ROUNDS = 4`,
  `_KAD_LOOKUP_TIMEOUT = 3.0 s`) agrège `FOUND_NODE` jusqu'à stabilisation ;
  les résultats alimentent `_connect_routing` et la table de routage.

## ⚑ Taille d'un `FOUND_NODE` (contrainte post-quantique)

Un certificat ML-DSA-65 pèse **~7,3 ko** (clé sujet + clé émetteur + signature),
donc une chaîne jusqu'à une racine ~**14,6 ko**. Répondre à un `FIND_NODE` avec
les `k = 20` entrées de Kademlia ferait ~292 ko : bien au-delà du plafond de
60 000 octets d'un paquet. `Packet.create` levait, l'exception était avalée par
la boucle de réception, **aucun** `FOUND_NODE` ne partait — dès la 5ᵉ node
certifiée connue, tous les lookups du réseau expiraient en silence.

La réponse est donc **budgétée** :

- `_EntryPacker(budget)` empile les entrées les plus proches tant qu'elles
  tiennent dans `_FOUND_NODE_MAX_BYTES = 32 000`, et **mutualise les
  certificats** dans un pool indexé (toutes les chaînes finissent sur la même
  racine réseau : l'envoyer une fois par entrée doublait le paquet). En
  pratique ≈ 3 entrées par réponse au lieu de rien du tout.
- Les entrées **sans chaîne** sont sautées : le récepteur les jette de toute
  façon (`_handle_found_node` exige une chaîne vérifiable), autant ne pas
  dépenser le budget. Les chaînes sont construites au fur et à mesure, donc le
  budget plafonne aussi le coût CPU d'un `FIND_NODE`.
- On **balaie plus large que k** (`_FIND_NODE_SCAN = 64`) pour remplir ce
  budget : `k` borne ce qu'on **renvoie**, pas ce qu'on **regarde**. Les entrées
  utilisables sont dispersées dans la table (une table apprise par gossip en
  contient beaucoup sans chaîne) ; se limiter aux k plus proches renvoyait une
  réponse **vide** dès que ces k-là n'avaient pas de chaîne.
- Moins d'entrées par réponse = quelques rounds de plus, jamais un lookup mort.
- `_query_allowed` limite `FIND_NODE`/`FIND_VALUE` par lien entrant
  (`_QUERY_RATE_MAX` par `_QUERY_RATE_WINDOW`) : ce sont les seules requêtes
  minuscules dont la réponse est énorme **et** routée vers un `src_id` non
  vérifié (levier de réflexion). C'est une **soupape anti-flood, pas du
  shaping** : le pic légitime d'un pair est de l'ordre de 66 par fenêtre
  (α × rounds d'un lookup, plat quand le réseau grandit), la borne est très
  au-dessus. Une borne proche du trafic normal tue des lookups réels.

## Propagation des adresses  ⚑ invariant central

**But visé** : *connaître une node ⟹ connaître l'ensemble de ses adresses
annoncées*, afin que le routage puisse choisir le meilleur medium (« si A↔B est
en Bluetooth et B↔C en Wi-Fi… »).

### Ce qui existe aujourd'hui

- `advertised_uris()` = chaque URI d'écoute étendue sur `_local_ips` +
  `_extra_addrs` (IP publique découverte, adresses observées).
- Le **PING transporte `advertised_uris`** ; `_handle_ping` fait
  `_routing.add(src, uris_valides, dsa_pub)` (fusion) et répond PONG.
  `_validate_uri` filtre avant ajout (« rejeter par défaut »).
- PING émis : au `bootstrap()`, par la **boucle de keepalive** (~20 s,
  `_link_keepalive_loop`), **et sur changement d'adresse** (gossip ciblé, voir
  ci-dessous). `FOUND_NODE` propage aussi les adresses connues. Le PING sert
  aussi de mesure **RTT** (voir `_handle_pong`, exposé dans la console).
- Découverte d'adresse : `OBSERVED_ADDR` (un pair nous dit l'IP d'où il nous
  voit), STUN, IP publique HTTP → alimentent `_extra_addrs`, puis `_poke_net`.

### Gossip d'adresses sur changement (implémenté)

Quand l'ensemble annoncé change, on l'annonce **immédiatement** aux pairs
récents, sans attendre le keepalive périodique :

- `_announce_addresses(reason)` : recalcule `advertised_uris()`, **saute si
  inchangé** (`_last_announced` → pas de tempête), sinon envoie un PING (qui
  porte déjà `advertised_uris`) aux **≤ `_ANNOUNCE_FANOUT` = 5** pairs
  authentifiés triés par `last_seen` décroissant (`_recent_authed_peers`). Gossip
  Kademlia ciblé : peu de trafic, convergence rapide. Ne lève jamais.
- Déclencheurs (`_announce_addresses_soon`, fire-and-forget depuis un contexte
  sync) : `_on_network_change` (IP publique/locale), `_handle_observed_addr`
  (nouvelle adresse observée), `add_listen` / `remove_listen`.
- Le pair receveur, via `_handle_ping`, fait `_routing.add(src, advertised_uris)`
  → il connaît la nouvelle adresse. Les nœuds plus lointains l'apprennent
  paresseusement par lookup Kademlia (`FIND_NODE`) — modèle Kademlia normal.

Limite assumée : on pousse à ses **pairs directs** les plus récents (un PING est
un message direct). La diffusion large reste lazy via Kademlia. Un pair
fraîchement authentifié n'a donc pas *instantanément* toutes nos adresses ;
elles arrivent au premier gossip/keepalive. Ne pas coder de dépendance dure sur
« pair authentifié ⟹ toutes ses adresses connues à l'instant T ».
</content>
