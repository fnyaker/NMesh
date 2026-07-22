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
- PING émis : au `bootstrap()`, et par la **boucle de keepalive** (~20 s,
  `_link_keepalive_loop`). `FOUND_NODE` propage aussi les adresses connues.
- Découverte d'adresse : `OBSERVED_ADDR` (un pair nous dit l'IP d'où il nous
  voit), STUN, IP publique HTTP → alimentent `_extra_addrs`, puis `_poke_net`.

### Le trou (⚠ à implémenter — comportement voulu, pas encore codé)

Aujourd'hui, **un changement d'adresse ne pousse rien immédiatement** :
`_on_network_change` et `_handle_observed_addr` mettent à jour `_extra_addrs`
localement mais **n'annoncent pas** aux pairs. Les autres nœuds n'apprennent la
nouvelle adresse qu'au prochain keepalive (jusqu'à ~20 s) ou par gossip indirect.

**Invariant voulu** : quand une node change d'adresse, elle **annonce** son
nouvel ensemble d'adresses à **si possible 5 nodes — les plus récemment vues**
(`last_seen` de la table de routage), en plus du keepalive périodique. C'est du
gossip Kademlia ciblé : peu de trafic, convergence rapide.

Piste d'implémentation (à valider) : sur `_on_network_change` /
`_handle_observed_addr`, si l'ensemble annoncé a réellement changé, envoyer un
PING (qui porte déjà `advertised_uris`) aux ≤ 5 pairs authentifiés triés par
`last_seen` décroissant ; router vers ceux qui ne sont pas des pairs directs.
Borné (≤ 5), idempotent, sans tempête (dé-dupliquer sur « ensemble inchangé »).

> Tant que ce trou existe, ne pas *supposer* dans le code qu'un pair fraîchement
> authentifié connaît toutes nos adresses. Si tu combles le trou, **mets ce
> document à jour** (retire la section « à implémenter »).
</content>
