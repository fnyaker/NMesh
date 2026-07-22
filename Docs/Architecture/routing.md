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

- `_forward_packet` (cf. `protocol.md`) : pair direct > entrée de routage +
  `_ensure_route_to` > plus proche voisin XOR > lookup Kademlia. On préfère une
  route réellement joignable à un saut XOR théorique — crucial à travers des
  frontières réseau où seuls certains nœuds ont de la joignabilité.
- `_ensure_route_to(target)` : renvoie un pair authentifié vers `target`, en
  l'établissant si besoin. Ordre : pair existant → si absent de la table,
  `_kademlia_lookup` → `_connect_routing` (essaie les adresses connues, IPv6
  d'abord) → si aucune adresse joignable, `_punch_route_to` (NAT hole punch
  coordonné par un relais, cf. `transports.md`).
- `_kademlia_lookup(target)` : `FIND_NODE` itératif borné (`_KAD_LOOKUP_TIMEOUT`,
  `_KAD_LOOKUP_MAX_ROUNDS`), agrège les `FOUND_NODE` jusqu'à stabilisation.

## DHT adressé par contenu (`dht.py`)

- `ContentStore.put(key, value)` **refuse** si `key != sha256(value)[:20]`
  (`content_key`). → un pair ne peut jamais stocker de données arbitraires sous
  une clé choisie : l'empoisonnement DHT classique est fermé par construction.
- Borné : `_MAX_ENTRIES = 8192`, `_MAX_BYTES = 128 MiB`, éviction LRU.
- Réplication : `_DHT_K = 6` nœuds les plus proches (STORE/FIND_VALUE).
- Usage : partage d'applications (`app_package.py`, cf. `Docs/AppSharing/guide`).

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
