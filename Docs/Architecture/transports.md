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

## Se configurer : `OPTIONS` / `configure()`

Même principe que l'observabilité : **le medium déclare, le reste est écrit une
fois.** Un transport pose deux attributs de classe et n'écrit aucune validation :

```python
class TCPTransport(BaseTransport):
    OPTIONS = (
        option("connect_timeout", "float", 4.0, "…", minimum=0.5, maximum=60.0, unit="s"),
        option("families", "multi", ["ipv4", "ipv6"], "…",
               choices=[{"value": "ipv4", "label": "IPv4"},
                        {"value": "ipv6", "label": "IPv6"}]),
        option("source_address", "text", "", "…", placeholder="192.168.1.20"),
    )
    SETTINGS: dict = {}          # valeurs en vigueur, au niveau de la classe
```

Types : `bool`, `int`, `float`, `text`, `choice`, `multi` — soit exactement les
cases à cocher, listes multi-choix et champs libres qu'une interface sait
rendre. `restart=True` marque une valeur que le processus vivant ne peut pas
reprendre : le dire est la différence entre un réglage cassé et un réglage pas
encore actif.

- `coerce()` traduit et **borne** (min/max, longueur, valeur d'une liste de
  choix, ligne unique) avec un message qu'un humain peut suivre. Écrit une fois :
  un medium qui validerait lui-même validerait légèrement différemment.
- `configure()` applique **partiellement** : un champ mauvais ne jette pas les
  quatre bons tapés avec lui, et rend `{"applied": …, "rejected": {nom: raison}}`.
  `SETTINGS` est **remplacé**, jamais muté — un dictionnaire de classe partagé
  n'est pas un endroit qu'on édite sous un lien vivant.
- `TransportManager.options() / configure() / settings()` ne fait que passer les
  choses : il sait quelle classe répond pour un schéma, rien de plus.

### Persistance

Le fichier de configuration accepte des clés **namespacées** `schéma.option` et
les porte **en texte, sans les valider** : c'est le medium qui sait. Au
démarrage, `_apply_transport_settings()` les distribue avant que quoi que ce
soit n'écoute ou ne compose ; une valeur refusée est signalée sur la bannière et
laissée à son défaut — un nœud qui refuse de démarrer parce qu'un délai est mal
tapé est un pire résultat qu'un nœud qui tourne sur son défaut.

La console (Network → Reachability) rend le formulaire **à partir de la
déclaration**, applique d'abord et écrit ensuite : une valeur que le transport
refuse n'atteint jamais le fichier, sinon le prochain démarrage la refuserait à
son tour avec personne devant le clavier pour lire pourquoi.

Réglages actuels : TCP (délai de connexion, délai de lecture, `TCP_NODELAY`,
familles d'adresses, adresse source), UDP (intervalle et délai de keepalive,
profondeur du buffer de réordonnancement), spool (intervalle de scrutation).

## S'observer soi-même : `endpoints()` et `stats()`

Deux crochets optionnels sur `BaseTransport`, de la même forme que
`reachability()` : **le medium se décrit, le cœur n'interprète rien.**

```python
def endpoints(self) -> dict:      # {"local": uri|None, "remote": uri|None}
def stats(self) -> dict:          # {"retransmits": 12, "rto ms": 50.0, …}
```

- `endpoints()` n'est **pas** l'URI qu'on a composée : c'est le point de
  terminaison tel que le medium le voit maintenant. Sur un lien *accepté* c'est
  la seule adresse qui existe, et c'est celle qui dit à l'opérateur laquelle des
  adresses d'un pair porte réellement le trafic.
- `stats()` est libre par construction : un lien UDP a des retransmissions et un
  buffer de réordonnancement, un lien série a un débit, une liaison LoRa a un
  SNR. La console **affiche les noms qu'on lui donne**, donc un transport que la
  console n'a jamais vu devient observable sans une ligne de code côté console.

Deux règles, parce que c'est *pollé* : les valeurs sont des scalaires
JSON-compatibles, et la lecture ne bloque jamais. Le cœur se protège quand même
— un transport qui lève, qui rend un objet imbriqué ou cinquante clés ne casse
pas le snapshot : il est ignoré, filtré, borné à 16 entrées
(`tests/test_link_stats.py`).

Implémentations actuelles : TCP rend le remplissage du buffer d'écriture (un
nombre qui reste haut = ce pair ne draine pas, ce qu'aucun compteur de paquets
ne montre) et `TCP_NODELAY` ; UDP rend retransmissions, réordonnancements,
frames non acquittées, RTO courant et keepalives manqués.

## Qualité d'un lien (`metrics.LinkQuality`)

Un RTT unique ne distingue pas un lien stable à 40 ms d'un lien qui oscille
entre 5 et 400 ms. Chaque lien garde donc les **32 derniers échantillons**
(borné, minuscule) réduits aux quatre chiffres qu'on lit vraiment : dernier,
meilleur, pire, **gigue** (moyenne des écarts consécutifs). La **perte** est
comptée à part — une sonde qui ne revient jamais n'a pas d'aller-retour à
moyenner — et vaut `None` tant qu'une seule sonde est en vol : une sonde en
attente n'est pas 100 % de perte.

## Statut de chaque adresse (`node._dial_log`)

Un nœud qui annonce quatre adresses dont une marche est le cas normal sur un
vrai réseau, et « laquelle, et pourquoi pas les autres » est la première
question qu'on se pose. Chaque tentative est donc notée : `connected`,
`no-answer`, `timeout`, `refused`, avec le motif et la durée. Le lien vivant
gagne sur le journal (une adresse qui porte du trafic est `in-use`, quoi qu'elle
ait fait la semaine dernière), et une adresse jamais essayée est `untried`, pas
en panne. Borné deux fois : 128 nœuds, 8 adresses chacun.

## TCP (`tcp_transport.py`)

- Framing : préfixe **2 octets** (uint16 big-endian) = taille du `Packet` suivant.
- `_CONNECT_TIMEOUT = 4 s` : un `connect()` sans réponse échoue vite (au lieu de
  pendre sur le timeout SYN de l'OS) — indispensable quand on diale des adresses
  non prouvées (IP privées d'un pair NATté apprises par gossip). Via
  `asyncio.timeout`, jamais `wait_for` (annulation, cf. `gotchas.md` §3b).
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
- Fenêtre de réception **modulaire** (RFC 1982) autour du curseur de délivrance :
  en-ordre → livré ; en-avant → buffer borné (`_MAX_REORDER`) ; en-arrière →
  duplicata, re-ACK. Pas de set de seq vus (état borné quoi qu'envoie un pair
  hostile ; le wrap 2³² ne fige plus le lien).
- Mort d'un lien : `_KEEPALIVE_TIMEOUT = 75 s` (3 × l'intervalle de 25 s, et
  au-dessus de la cadence PING mesh de 20 s) — en dessous, un lien punché sain
  mais silencieux était tué quand les phases s'alignaient (flapping de route).
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
bien en deçà. Les liens du **set maintenu** (`_neighbor_slots`, les
`_NEIGHBOR_FLOOR = 3` plus proches — cf. `routing.md`) sont pingés **en
premier** : ce sont ceux que le nœud s'engage à tenir, ils ne doivent jamais
être affamés par un pair lent ou mort placé plus tôt dans la liste. Si le
compte de liens vivants passe sous le plancher à la fin d'un cycle, la
maintenance de voisinage est réveillée immédiatement. Les deux extrémités le font → trafic dans les deux sens ; toute
trame entrante réarme le timeout. Démarré dans `start()`/`join()`, arrêté dans
`stop()`. Ne lève jamais. (Ce PING porte aussi `advertised_uris` → gossip
d'adresses, cf. `routing.md`.)
</content>
