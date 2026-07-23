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
