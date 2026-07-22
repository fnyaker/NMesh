# Protocole inter-nœuds

Source de vérité : `src/packet.py`, `src/node.py` (constantes + `_handle_packet`).

## Format du paquet

`HEADER_FORMAT = '!BBB20s20sQ12s16s'` → **header de 79 octets**, suivi du payload.

| Champ | Taille | Notes |
|---|---|---|
| version | 1 | protocole (=1) |
| type | 1 | voir table des types |
| ttl | 1 | décrémenté à chaque hop ; **exclu de l'AAD et du `msg_id`** |
| src_id | 20 | NodeID émetteur |
| dst_id | 20 | NodeID destinataire (`0xff…ff` = broadcast) |
| msg_id | 8 | uint64, voir ci-dessous |
| nonce | 12 | `os.urandom(12)`, unique par paquet (AES-GCM) |
| gcm_tag | 16 | tag d'authenticité AES-256-GCM |
| payload | ≤ 60000 | clair pour le contrôle, chiffré pour DATA/E2E |

> ⚠️ La vieille note « 75 octets / CRC32 » est **fausse** : c'est 79 octets et
> un `msg_id` uint64 dérivé de sha256.

### `msg_id` (anti-rejeu / anti-amplification)

`msg_id = int(sha256(version‖type‖src‖dst‖nonce‖gcm_tag‖payload)[:8])`
(`Packet.compute_msg_id`). **TTL et msg_id exclus** du calcul.

Il *engage le contenu* du paquet : un relais ne peut pas forger un nouvel
`msg_id` pour le même payload afin de contourner la déduplication et amplifier
un flood. Vérifié à la réception pour les types routables (voir portes).

### AAD et chiffrement (`Packet.aad`, `create_encrypted`, `decrypt_payload`)

- **AAD** (authentifié, non chiffré) = `version‖type‖src‖dst‖nonce` — **le TTL
  n'y est pas** (il change à chaque hop).
- Le payload DATA/E2E est chiffré AES-256-GCM sous la clé de session ; le
  `gcm_tag` couvre AAD + payload.
- Le header est donc *en clair mais authentifié*.

## Table des types (`src/node.py`)

| Type | Val | Rôle |
|---|---|---|
| DATA | 0x00 | données applicatives (chiffrées E2E) |
| PING / PONG | 0x01 / 0x02 | vivacité + **gossip d'adresses** (le PING porte `advertised_uris`) |
| FIND_NODE / FOUND_NODE | 0x03 / 0x04 | lookup Kademlia (nœuds proches) |
| FIND_VALUE / FOUND_VALUE | 0x05 / 0x06 | lookup DHT par clé |
| STORE | 0x07 | stocker une valeur DHT (adressée par contenu) |
| HANDSHAKE / HANDSHAKE_ACK | 0x08 / 0x09 | session par-saut (ML-KEM + ML-DSA + cert) |
| INVITE / INVITE_ACK | 0x0A / 0x0B | (legacy) présentation de code d'invitation |
| CHALLENGE | 0x0C | challenge d'authentification |
| E2E_HANDSHAKE / _ACK | 0x0D / 0x0E | session de bout en bout |
| OBSERVED_ADDR | 0x0F | « voici l'IP d'où je te vois » (découverte d'adresse publique) |
| PUNCH_REQUEST / _RELAY | 0x10 / 0x11 | coordination de NAT hole punch via relais |
| PUNCH_PROBE / _ACK | 0x12 / 0x13 | **datagrammes UDP bruts** (pas des Packet mesh), signés ML-DSA |
| INVITE_SEEK | 0x14 | invitation relayée, **routable AVANT auth**, token-gated |
| RELAY_CARRY | 0x15 | transporte un paquet de handshake entre 2 nœuds via un relais |
| REACH_PROBE / _ACK | 0x16 / 0x17 | AutoNAT : « rappelle-moi pour confirmer que je suis joignable » |
| CATALOG_ANNOUNCE | 0x18 | gossip d'une **release signée** pour le catalogue de l'app store |
| DIR_STORE / _FIND / _FOUND | 0x19 / 0x1A / 0x1B | annuaire de pseudos : stocke/cherche/répond une **réclamation signée** pseudo→node_id |

Regroupements (constantes) :
- `_DIRECT_TYPES` : messages de contrôle entre pairs directs → **exigent un pair
  authentifié et `src_id == pair authentifié`** (inclut `CATALOG_ANNOUNCE`, re-
  stampé à chaque saut lors du gossip épidémique, et `DIR_STORE`/`DIR_FIND`/
  `DIR_FOUND`).
- `_ROUTABLE_TYPES` = {DATA, E2E_HANDSHAKE, E2E_HANDSHAKE_ACK} : peuvent traverser
  le mesh.
- `INVITE_SEEK` et `RELAY_CARRY` sont traités **avant** les portes (pré-auth,
  strictement bornés/token-gated).

### Sections d'application (dans la payload DATA)

Le **management** (tout le reste du tableau : PING, routage, DHT, handshakes…)
vit dans des **types de paquets distincts** — jamais dans DATA. Les **données
applicatives** vivent, elles, uniquement dans `DATA`, et sont sous-divisées en
**sections par app** : la payload DATA déchiffrée E2E est `app_id(8) ‖ payload`
(voir `src/app_channel.py`). Le nœud traite la payload comme opaque ; c'est le
**connecteur** qui pose/retire le cadre et démultiplexe par `app_id`, de sorte
qu'une app ne voit que sa section. Une payload trop courte pour porter un
`app_id` est jetée. `app_id` réservé pour les apps intégrées (`builtin_id`),
lié à la clé auteur pour les apps déployées (`deployed_id`, package signé).

## Portes de validation (`_handle_packet`) — le cœur sécurité

Ordre exact appliqué à chaque paquet reçu :

1. `INVITE_SEEK` → handler dédié pré-auth (rate-limité par lien, borné). Return.
2. `RELAY_CARRY` → handler dédié. Return.
3. Si `type ∈ _DIRECT_TYPES` : rejeter si le pair n'est pas authentifié, ou si
   `src_id != authenticated_id`. (« rejeter par défaut ».)
4. Si `type ∈ _ROUTABLE_TYPES` :
   - pair authentifié requis ;
   - `msg_id == compute_msg_id()` sinon rejet (anti-amplification) ;
   - `_is_seen(msg_id)` → déjà vu → rejet (déduplication bornée, `_MSG_DEDUP_MAX
     = 10 000`, éviction FIFO) ;
   - si `dst_id` n'est ni nous ni broadcast → `_forward_packet` puis return.
5. Sinon, dispatch vers le handler du type.

## Forwarding (`_forward_packet`) — routage glouton

Pour un paquet dont on n'est pas la destination (TTL > 1) :
1. **Pair direct** vers `dst` (authentifié, session) → envoyer (TTL-1).
2. Sinon si `dst` est dans la table de routage → `_ensure_route_to` (à la
   demande) puis envoyer.
3. Sinon **plus proche voisin** par distance XOR (`min(distance(dst, peer))`).
4. Dernier recours : lookup Kademlia + route à la demande.

`with_decremented_ttl()` à chaque saut ; TTL ≤ 1 → on ne relaie pas (anti-boucle,
en complément de la déduplication `msg_id`).

## Invariants (rappel, cf. CLAUDE.md)

- Header en clair mais **authentifié** (AAD). Payload applicatif chiffré E2E.
- `msg_id` engage le contenu, **vérifié à la réception**.
- TTL décrémenté par hop, hors AAD et hors `msg_id`.
- Déduplication bornée. Rejet par défaut de tout paquet mal formé/non autorisé.
</content>
