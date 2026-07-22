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
</content>
