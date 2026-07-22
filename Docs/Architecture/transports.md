# Transports, NAT & joignabilité

Source : `transport.py`, `transport_manager.py`, `tcp_transport.py`,
`udp_transport.py`, `spool_transport.py`, `stun.py`, `net_monitor.py`, et dans
`node.py` : hole punching, reachability, keepalive.

## Abstraction

- `BaseTransport` : `connect / send / receive / close` (un lien bidirectionnel).
- `BaseServer` : `listen / close` + callback `on_new_connection(transport)`.
- `TransportManager` : registre **par schéma d'URL** (`tcp`, `udp`, `spool`, …).
  N'importe qui implémente les deux interfaces et `register("scheme", T, S)`.
  Le cœur ne connaît aucun transport concret. Écoute clée par URI exacte (un
  nœud peut écouter sur plusieurs adresses ; refuse un doublon d'URI).

## TCP (`tcp_transport.py`)

- Framing : préfixe **2 octets** (uint16 big-endian) = taille du `Packet` suivant.
- `_READ_TIMEOUT = 60 s` : un `receive()` sans données pendant 60 s lève →
  le lien est considéré mort et reapé. **Un lien inactif meurt donc s'il n'y a
  pas de keepalive** (cf. §keepalive).
- **`_wait_closed_bounded`** : Python 3.12 a changé `Server.wait_closed()` — il
  bloque jusqu'à la fermeture de **toutes les connexions clientes acceptées**,
  plus seulement la socket d'écoute. Fermer un port pendant qu'un pair y reste
  connecté ne revenait jamais (hang). On borne l'attente (la socket d'écoute est
  déjà fermée par `close()`, c'est l'essentiel). Voir `gotchas.md`.

## UDP (`udp_transport.py`)

UDP est sans connexion et non fiable → une **couche de fiabilité** :
- Frame : `NUDP`(magic 4o) + seq(4) + ack(4) + sack(4) + flags(1) + payload_len(2)
  + payload. ACK cumulatif + SACK, retransmission avec backoff (`_RTO_*`),
  réordonnancement borné, keepalive (25 s), tout borné.
- `UDPServer` : **une socket partagée**, multiplexée par `(ip, port)` source.
  Un datagramme d'une source inconnue crée un `UDPTransport` + `on_new_connection`
  — comme un accept TCP. Datagrammes `NPPB`/`NPAK`/STUN routés vers
  `on_raw_datagram` (hole punch), pas vers un transport fiable.

## Store-and-forward (`spool_transport.py`)

Le mesh tourne aussi sur un **répertoire/fichier** (`spool://DIR`) : chaque nœud
écrit ses paquets sortants dans un fichier et sonde (poll `_POLL = 0.02 s`) le
fichier du pair. Pour liens hors-ligne / très haute latence (« clé USB portée à
pied »). Même invite/handshake/E2E, sans socket.

## NAT hole punching (dans `node.py`)

But : établir un lien **UDP direct** entre deux nœuds derrière NAT, coordonné par
un relais commun. Machinerie (constantes `_PUNCH_*`) :

1. A envoie `PUNCH_REQUEST(target, my_udp_port)` au relais (TCP).
2. Le relais envoie `PUNCH_RELAY` **aux deux** : à la cible C (avec l'adresse
   UDP réelle de A) et au demandeur A (avec l'adresse **TCP** de C — souvent
   vide, car côté serveur du relais `remote_addr` est `None`).
3. Chacun crée un état `_punch_pending` et envoie une **rafale de PROBE** UDP
   bruts, signés ML-DSA (`_send_punch_probes`).
   - ⚠ Si l'adresse UDP du pair est inconnue (vide), **on garde l'état** et on
     ne sonde pas : le pair, lui, a notre adresse et nous sonde ; un PROBE
     entrant complète le punch depuis son adresse source. (Bug historique :
     supprimer l'état bloquait l'initiateur — cf. `gotchas.md`.)
4. À réception d'un PROBE valide → ACK + `_complete_punch`. Le nœud au **plus
   grand NodeID** est l'initiateur : il ouvre le `UDPTransport`, l'enregistre, et
   **kicke** le répondeur (rafale de keepalives, `_kick_punched_link`, pour
   survivre à une perte de datagramme). Le répondeur accepte via la voie UDP
   normale. Puis handshake standard → lien authentifié.
   - Dé-dup : un seul transport initiateur par adresse (les deux pairs punchent
     souvent en même temps).
5. `_maybe_upgrade_path` : envoyer des données à un pair joignable seulement par
   relais déclenche automatiquement un essai de lien direct (rate-limité par
   cible, `_UPGRADE_COOLDOWN`).

## Découverte d'adresse & joignabilité

- `OBSERVED_ADDR` : un pair qui accepte notre connexion nous renvoie l'IP source
  qu'il voit → notre adresse publique vue de là (ajout borné à `_extra_addrs`).
- STUN (`stun.py`) : adresse UDP réflexive publique. Résolution DNS bornée
  (`_bounded_getaddrinfo`, thread daemon abandonné au timeout — sinon un DNS
  bloqué fige le shutdown, cf. `gotchas.md`).
- **AutoNAT** : `REACH_PROBE`/`REACH_PROBE_ACK` — demander à un pair de nous
  rappeler pour **confirmer activement** qu'on est joignable (avant de se
  déclarer relais public).
- `NetMonitor` (`net_monitor.py`) : re-vérifie l'adressage local sur timer court
  et relance les sondes réseau (IP publique HTTP, STUN) sur *trigger* (IP locale
  changée, saut d'horloge = suspend/resume, `poke` du nœud, refresh périodique).
  Sondes bornées, échec silencieux, **ne bloque jamais la boucle**
  (`discover_public_ip` en thread daemon, cf. `gotchas.md`).

## Keepalive de lien (`_link_keepalive_loop`)

Un lien sain mais **inactif** est reapé au `_READ_TIMEOUT` (TCP 60 s). Le nœud
PING donc chaque pair établi toutes les **20 s** (`_LINK_KEEPALIVE_INTERVAL`),
bien en deçà. Les deux extrémités le font → trafic dans les deux sens ; toute
trame entrante réarme le timeout. Démarré dans `start()`/`join()`, arrêté dans
`stop()`. Ne lève jamais. (Ce PING porte aussi `advertised_uris` → gossip
d'adresses, cf. `routing.md`.)
</content>
