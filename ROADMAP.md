# NMesh — Roadmap

Guiding priorities: see `CLAUDE.md`. The order is non-negotiable:
**security > solidity > flexibility > speed**, with minimal dependencies.

## Done

### Cryptographic and network foundation
- Post-quantum E2E crypto (ML-KEM-768 / ML-DSA-65 / AES-256-GCM).
- A self-rooted P2P PKI (certificate chains, trusted roots).
- Invitation → handshake → session, Kademlia + multi-hop on-demand routing.
- A pluggable transport per URL scheme (`BaseTransport` / `BaseServer`).

### Security / solidity hardening
- **Zero crash on hostile input**: a malformed packet no longer kills the
  receive loop; it is counted and dropped.
- **Peer rejection**: past a threshold of invalid frames, the peer is cut off.
- **Auto-recovery**: dead peers (a closed link, abuse) are purged automatically;
  on-demand routing rebuilds the links when needed.
- **Anti-amplification**: `msg_id` verified on receipt (it commits the content) —
  a relay can no longer forge `msg_id`s to escape deduplication.
- **Memory bounds**: E2E buffers capped per target and globally.
- **E2E glare**: simultaneous opens converge on a single key (tie-broken by
  NodeID) instead of deadlocking; the responder flushes the pending data.
- **Fuzzing**: `tests/test_fuzz.py` proves no hostile byte crashes anything
  (Packet, every codec, certificates, a live node under a random flood).
- **Real integration**: `tests/integration/test_local.py` brought up to date —
  invite/handshake, E2E data, large payloads, A→B→C routing, self-healing.

### The web management console (`src/webconsole.py`)
- A local management plane: the network graph, the peer list, live throughput,
  the node's load; the invite / join / trust-cert actions.
- Security: self-signed HTTPS (fingerprint printed), a generated password hashed
  with scrypt, a session by Bearer token **or cookie** (`HttpOnly` +
  `SameSite=Strict` → no CSRF surface; survives a refresh), an anti-bruteforce
  lockout, a loopback bind by default, a strict CSP, same-origin assets, **zero
  external dependency** (stdlib + `cryptography`).
- Node metrics (`src/metrics.py`): throughput counters + process load.
- Example: `scripts/nmesh_node.py`. Docs: `Docs/WebConsole/guide`.

## In progress / to validate
- The multi-node Docker test (10): rebuild with `--build`, validate
  invitation → handshake → data on the 9 guests.
- An A→B→C→D chain topology for multi-hop forwarding in real conditions.

### Store-and-forward — a file medium (`src/spool_transport.py`, `src/spool.py`)
- The `spool://` transport: the whole mesh (invite/handshake/routing/E2E) runs
  over a **shared directory**, with no socket. Durable append journals (fsync),
  per-record CRC framing, resync on corruption, multi-client.
- The portable `Bundle` container: a batch of packets in one file with SHA-256
  integrity (the "USB stick file"), truncation/alteration rejected.
- Tested: a session + E2E data through files, multi-hop routing in a star,
  sneakernet (offline delivery through a Bundle), fuzzing of the container and
  the framing.
- Docs: `Docs/Transports/spool`. Example: `nmesh_node.py --spool DIR`.

### Session persistence (`src/session_store.py`) — opt-in
- Survives a restart and an offline round trip: E2E sessions, in-flight
  handshakes (kem/nonce) and pending data are persisted.
- **Encrypted at rest** (AES-256-GCM) under an HKDF key derived from the
  identity — the same trust boundary as the identity file already on disk. Off
  by default (keys in RAM). Turned on with `session_store_path`.
- Bulletproof loading (a hostile file → start empty, never a crash).

### Multiple listeners per scheme (`TransportManager`) — done
- A node can listen on several distinct `spool://` directories → the
  A—stick1—B—stick2—C topology is unblocked.

### Persistence of direct links (the routing table) — done
- The routing table (known peers, addresses, public keys) is persisted encrypted
  at rest. On restart the node finds its peers again and rebuilds the links on
  demand, **re-authenticated through the persisted cert store** (the existing
  cert-chain path, with no re-invitation). E2E sessions already survived.
- The client remembers the address it dialled and records it in routing, which
  makes the peer reconnectable after a restart.
- Tested: a restart on a real TCP link, resuming with no re-invitation.

### Full IP addressing + the expert view (`src/ip_utils.py`) — done
- Enumerating local IPs, IPv6-safe host:port parsing, expanding wildcard listen
  URIs (`0.0.0.0` → each concrete IP) → connectable advertised URIs (the ping now
  advertises reachable addresses).
- Multi-port listening + adding/removing a listener live (`add_listen` /
  `remove_listen`). An enriched snapshot (advertised, listen, local_ips,
  transports, listening).
- The expert view in the web console (advertised URIs, listeners, local IPs,
  active transports).

## Next steps (the "Jarvis / Edith" vision)

### Public IP detection (mesh-native) — done
- A peer that accepts our connection sends back the source IP it saw (the
  `OBSERVED_ADDR` message) → we learn our public address with no external server
  (on by default, at every handshake). Validated, bounded; it feeds the
  advertised URIs.

### The IP transport — continued — done
- **A STUN client** (`src/stun.py`): an RFC 5389 Binding Request over UDP,
  parsing XOR-MAPPED-ADDRESS (IPv4/IPv6). A fallback when no peer is available to
  observe our address. Stdlib only, opt-in (`--stun`).
- **A UDP transport** (`src/udp_transport.py`): `UDPTransport` / `UDPServer`
  implementing `BaseTransport` / `BaseServer` over asyncio datagram sockets. A
  reliability layer: sequence numbers, cumulative ACK + SACK, retransmission with
  exponential backoff, a bounded reordering buffer, a 25 s keepalive to hold NAT
  mappings. Framing with the `NUDP` magic. The whole mesh
  (invite/handshake/routing/E2E) runs over UDP unchanged.
- **NAT hole punching** signalled over the mesh: `PUNCH_REQUEST` /
  `PUNCH_RELAY` (coordination through a TCP relay), `PUNCH_PROBE` / `PUNCH_ACK`
  (raw UDP datagrams signed with ML-DSA-65). Two nodes behind NAT send
  simultaneous probes through a public relay; the hole is punched and a direct
  UDP link replaces the relay. Automatic fallback: if the punch fails (symmetric
  NAT), traffic keeps flowing through the relay.
- Tested: the UDP transport on loopback (send/receive, ordering,
  bidirectional), invite/handshake/E2E over UDP, hole-punch coordination through
  a relay, resistance to hostile datagrams (garbage → ignored, no crash).

### Store-and-forward — going further with delay tolerance
- A one-way drop mode (a bundle left with no interactive round trip).
- A persistent send queue per peer + resuming after a cut.

### The data connector (`src/data_connector.py`) — done
- A local socket (loopback TCP or a 0600 Unix socket, TLS optional) through
  which an app sends and receives E2E messages over the mesh. Token auth
  (compare_digest), bounded frames, a cap on clients. The *data* plane (distinct
  from the console).
- Tested app→mesh→app end to end. Docs: `Docs/DataConnector/guide`. Example:
  `nmesh_node.py --connector-port N`.

### The subprocess launcher (`src/process_launcher.py`) — done
- The node launches declared apps and injects the connector's coordinates
  (host/port/token) into their environment; the app joins the mesh through
  `ConnectorClient`. Exec with no shell (no injection), children bounded and
  terminated at shutdown. Example: `nmesh_node.py --launch "..."`,
  `scripts/example_app.py`. Docs: `Docs/ProcessLauncher/guide`.

### Sharing apps over the DHT (`src/dht.py`, `src/app_package.py`) — done
- **Content-addressed** app packages (chunks + manifest, key = hash):
  publishing, verified fetching, automatic re-sharing from the cache.
- A Kademlia DHT: `STORE` / `FIND_VALUE` / `FOUND_VALUE`, a bounded store
  against poisoning and OOM. The `node.publish_app` / `node.fetch_app` API.
- Docs: `Docs/AppSharing/guide`.

### A per-app local store + a per-app DHT (`src/app_storage.py`, `src/app_dht.py`) — done
- An encrypted **drawer** per app: key→value in AES-256-GCM (a per-app key
  derived from the identity), isolated by `app_id`, bounded, robust against
  hostile files. `node.app_store_*` and the connector's `STORE_*` frames. Docs:
  `Docs/AppStorage/guide`.
- A **per-app DHT**, public or private, on top of the content-addressed store: a
  namespace per `app_id` (which the node knows, and the app does not declare),
  node-side encryption under a key the app supplies for private entries.
  `node.app_dht_*` and the connector's `APP_DHT_*` frames. Docs:
  `Docs/Architecture/routing.md`.

### A DHT pseudo directory (`src/pseudo_dir.py`) — done
- **Network-wide** find-by-pseudo: a keyed directory over Kademlia
  (`DIR_STORE`/`FIND`/`FOUND`), **self-authenticating signed** claims
  (pseudo→node_id bound to the public key → no impersonation), bounded and
  rate-limited, several claims per pseudo. `node.publish_pseudo`/`lookup_pseudo`,
  the connector's `PSEUDO_*` frames. Chat publishes on `set_pseudo` and queries
  the network on `search`.

### App store: a shared catalogue (`src/app_catalog.py`) — done
- A network catalogue of **signed releases** (an ML-DSA author + a signed `ts`),
  gossiped (`CATALOG_ANNOUNCE`), anti-forge / anti-rollback / bounded, with a
  catch-up at the handshake. A local registry of installed apps (install verifies
  the content before writing, paths sanitised). The console's **App Store** page
  (the decision logic in Python, through `store_overview`). Docs:
  `Docs/AppStore/guide`.

### The demo chat app (`src/apps/chat.py`) — done
- Text, file sharing (chunked, SHA-256 integrity) and a real-time stream (a
  call's primitive: timestamped frames, measured latency) over the connector.
- The self-contained demo `scripts/chat_demo.py` (~37 MB/s on a file, ~0.5 ms
  median latency locally), the interactive client `scripts/chat_app.py`. Docs:
  `Docs/Apps/chat`.

### Sharing apps from the web console — done
- The interface's "Apps (DHT)" section: publishing an app (pick files → an
  app_id shared over the mesh) and fetching one by identifier (files verified,
  downloadable). The `/api/app/publish` and `/api/app/fetch` endpoints.

### The chat web app (`src/apps/chat_web.py`) — done
- An option of the chat app: when it is on, the app pushes its messages to a web
  UI and routes what you send through it (fan-out inside the app through
  `ChatApp.add_listener`). The node and the management console are untouched.
  Loopback + token, a strict CSP. `chat_app.py --web PORT`.

### Chunked manifests (large apps) — done
- The manifest is itself chunked and content-addressed; the app_id points at a
  small root listing the manifest's chunks. No more ~59 KB limit on how many
  files an app can have.

### Audio calls (`src/apps/call.py`) — done
- Real-time audio transport over the frame stream: framed PCM, measured latency.
  A WAV backend in the stdlib (`wave`) → a call tested end to end with real
  samples, no hardware and no dependency. An `AudioSource`/`AudioSink` interface
  to plug a live mic/speaker in on the app side without polluting NMesh's
  dependencies. The `scripts/call_demo.py` demo (audio identical bit for bit,
  ~0.5 ms latency).

### The application ecosystem — continued
- A live device backend (mic/speaker, sounddevice say) implementing
  `AudioSource`/`AudioSink`, on the application side.
- Video over the same real-time stream.
- Sending files from chat's web UI (today: text + displaying received files).

### Application identity (`src/app_auth.py`) — done
- The mesh authenticated the transport; an app had nothing **portable** nor
  **bound to an intent**. ML-DSA-signed assertions scoped
  `(app, audience, purpose, ctx)`, fresh, single-use, verifiable offline after a
  restart.
- **Never a signing oracle**: the signed input is always
  `domain ‖ bounded structured fields`, free-form context enters only as a 32-byte
  hash, and the domain is distinct from every other in the repository — an app
  cannot have a certificate body signed by the node's key. The `app_id` comes
  from the session, never from the frame.
- Exposed to built-in apps through `node.app_auth(app_id)` (the app never
  touches the key) and to external apps through the connector's `AUTH_*` frames.
- Docs: `Docs/AppAuth/guide`.

### The "Fleet" fleet-management app (`src/apps/fleet*.py`) — done
- Enrolment with **a notification and a human decision** on the target node;
  approving can narrow, never widen. The signed grant is kept on the operator's
  side as auditable proof of consent.
- **Capabilities per action** (`status`, `invite`, `update`, `scan`, `provision`,
  `shell`, `manage`, `passwordless`). `manage` relays the console and still
  wants the target's password; `passwordless` replaces that password with the
  grant itself, for the machine that has no password anybody ever typed — one
  this operator provisioned. Taking either back ends the sessions it opened.
- Three independent gates before execution: the mesh authenticated, enrolled
  with the capability, a fresh signature over the command's exact bytes.
- Status (disk/RAM/load/uptime), update (a plan the node derives itself from its
  own facts — apt/dnf/pacman/zypper/apk/xbps/brew/pkg, argv never a shell
  string), an interactive shell on a bounded pty.
- SSH LAN discovery over **every attached network**, at the prefix actually in
  use (`/proc/net/route`, ioctl, `ip`/`ifconfig`, a fallback) — a `/22` is no
  longer scanned as a `/24`, and a second card or a VPN is no longer missed.
  Bounded, with over-large networks narrowed around our address and reported as
  such. The target field also accepts a **precise machine** (`10.0.0.5`,
  `nas.lan:2222`, `[fd00::5]:22`): naming a machine is not scanning, so it is
  allowed outside the private ranges, while a public **prefix** stays refused.
  What is not understood comes back named, never swallowed. Host key
  fingerprints presented to the operator, then provisioning: a self-extracting
  bootstrap in one SSH session, SHA-256 integrity verified before writing, the
  startup service installed, and **trust taken over** through a single-token
  pre-authorisation — which also carries the release publishers the new machine
  should accept, since it is the only moment a box with no screen can be told.
- SSH credentials: OpenSSH driven through a **pty**, never on disk, never in
  `argv`, never in the environment. Host keys pinned after human confirmation
  (`StrictHostKeyChecking=yes`), no `accept-new`.
- **Automated network integration**: the node running the scan issues a fresh,
  single-use invitation **per machine**, puts it in the pre-authorisation with
  its own URIs, and the new machine joins the mesh on its first start — the
  ordinary invitation → handshake → `issue_cert` flow, so **its certificate is
  signed by the node that installed it** and chains up to the network's root. It
  is also the reachable node: it is on the same LAN, where the operator may be
  behind a NAT.
- `generate_invite(ttl)`: a per-code TTL (bounded at 6 h). A code typed by hand
  lives 5 minutes; the one left on a machine mid-installation is only redeemed
  after the dependencies are built. Single use and lockout unchanged.
- Docs: `Docs/Apps/fleet`.

### The built-in apps' life cycle (`src/app_registry.py`) — done
- `installed` / `enabled` distinct and persisted; uninstalling **purges the
  app's encrypted drawer**. Toggled live from the console, with no node restart.
- Fleet is **off by default** (it can open a shell).

### Permanent installation and updating (`install.sh`, `src/updater.py`) — done
- `install.sh`: copies the tree somewhere durable (`/opt/nmesh` as root,
  `~/.local/share/nmesh` otherwise), lays down a systemd / OpenRC / launchd
  service, then runs it. It **delegates everything** to `start.sh` (dependencies,
  distro, liboqs) and the service points at `start.sh`: a node that restarts
  repairs itself.
- A dedicated system account for a root installation (`nmesh`, no login, no
  password): it alone owns the tree and the state, in mode 700, and the systemd
  unit adds `NoNewPrivileges` / `PrivateTmp` / `PrivateDevices` /
  `ProtectSystem`. A self-contained installation under the prefix (`HOME` pinned
  → liboqs in `<prefix>/_oqs`). A documented fallback when no account can be
  created.
- liboqs compiled once per machine: the `/var/cache/nmesh/liboqs-<version>`
  cache reused by any later install, reuse validated functionally (the wrapper
  loads the library), not on a version number.
- Reinstalling = updating in place, **the state is never touched**.
  `--uninstall` removes the service and the files, `--purge` goes as far as the
  identity.
- Updating from GitHub (console → Settings → Updates): a manual check, a
  confirmation that **names the version**, that version repeated in the request
  and re-checked on the node. Only the code/docs directories are replaced; the
  previous tree is kept and restored on failure. An explicit refusal on a
  container image or a non-writable directory.
- A known limitation: **no release signature verified by the node yet** (trust in
  TLS + GitHub + the publishers). That is this area's next step.
- Docs: `Docs/Setup/guide`, `Docs/WebConsole/guide`.

### Node configuration (`src/config.py`) — done
- Every launch option in `<prefix>/nmesh.conf`, written by `install.sh` and
  editable from the console (Settings → Configuration).
- Precedence command line > file > default: an existing unit that passes
  arguments does not change behaviour.
- Defensive, bounded reading; an incomprehensible file is reported and set
  aside, never fatal. A value the console refuses writes nothing.
- `launch` and `data` shown but not editable from the web; the console password
  is not a setting.
- The defaults live only in `src/config.py`: `start.sh` no longer injects
  `--udp/--stun`, which used to cancel the file's matching settings.
- Docs: `Docs/Setup/guide`, `Docs/WebConsole/guide`.

### `update` and `shell`: two separate routes to root — done
- No "root" capability. `update` (unattended) gets a **narrow** right through
  `install.sh --allow-update`: a root-owned script outside the prefix, with no
  argument, a fixed sequence, a sudoers rule validated by `visudo`, removable.
- `shell` becomes a real terminal (`TIOCSCTTY`): `sudo` there asks a human for
  their password, so there is no permanent credential-free root access. Raw
  keystrokes in the browser + a small emulator written in stdlib JS, with no
  dependency.
- Update progress announced step by step, before each step, with a bar and the
  last outcome in the node list.
- Docs: `Docs/Apps/fleet`, `Docs/Setup/guide`, `Docs/Architecture/gotchas.md`.

### Remote deployment aligned with `install.sh` — done
- The bootstrap no longer lays anything down itself: it delivers the tree and
  calls its `install.sh`. The dedicated service account, mode 700, a service
  pointing at `start.sh`, the liboqs cache, the config file — all of it comes
  from there.
- Two SSH sessions: delivery (piped, unprivileged) then installation **with a
  remote terminal**, so `sudo`/`su` ask for their password on a terminal and the
  local pty answers. The elevation secret never enters a script.
- The interface asks for: the login account, "can sudo" (a checkbox), otherwise
  an account that can, and where NMesh goes (system `/opt` recommended, or user).
- On failure, the last lines the machine actually wrote go into the log.
- Docs: `Docs/Apps/fleet`, `Docs/Architecture/gotchas.md`.

### Fast join by ticket + QR (`src/join_ticket.py`, `src/qr.py`) — done
- A 34-character string (IPv4) carrying an address and a single-use code; the
  lifetime chosen by the operator, bounded at 6 h.
- Issuing reserved to nodes with a **confirmed** `world` address.
- The QR rendered as SVG by the node, the encoder written in pure stdlib (no new
  dependency), verified against an independent encoder and a real decoder.
- Camera scanning through the browser's `BarcodeDetector`, with no library; a
  fallback to pasting where it does not exist.
- Docs: `Docs/WebConsole/guide`, `Docs/Architecture/security.md`.

### The console password (`src/console_auth.py`) — done
- Changing it from the console (`POST /api/password`): **the current password is
  required** even with a valid session — otherwise a stolen session would become
  permanent control. A wrong attempt counts towards the login's lockout. The
  other sessions are closed, not the one making the change.
- `./install.sh --reset-password` on the machine: rewrites the credential,
  prints the new password once, restarts the service, touches nothing else. The
  hashing is delegated to the node's code, not reimplemented in shell.
- Docs: `Docs/WebConsole/guide`, `Docs/Setup/guide`.

### The protocol trace (`src/trace.py`) — done
- A bounded record of what the node sends and receives, per message type.
  Routing metadata only: **never a payload**.
- Off by default, bounded in memory and in time, it stops on its own; requested
  bounds are capped. Console → Settings → Protocol trace, JSON export.
- It paid off immediately: a `FIND_NODE`/`FOUND_NODE` loop between two idle
  nodes, 3036 kbit/s → 2.1 kbit/s (see `Docs/Architecture/gotchas.md` §12).

### Choosing between a node's addresses (`src/node.py`) — done
- A **priority** per transport (−254..254, shipped `udp` 10, `tcp` 0,
  `spool` −50) combined with measured latency through a user-set
  **balance** (`transport_balance`, 0..100). The node computes the resulting
  order; the console renders it and never reimplements the rule.
- **Retry**: one precise address or all of a node's known addresses, on demand
  from the node card, plus a per-transport `retry_interval` (off by default).
- **Dynamic addressing** (off by default): a live link moves to a better-scoring
  address of the same node, after the candidate has really been dialled and
  probed, and only on a clear gain.
- Docs: `Docs/WebConsole/guide`, `Docs/Architecture/transports.md`.

### The app API surface (`src/app_api.py`) — done
- An app declares its operations (`API` + `api_<name>`) and everything else —
  another app, the core, a page — calls them the same way. Reject by default:
  nothing undeclared, every argument coerced and bounded, and no new authority
  granted.
- It carries the cross-app journeys: messaging a node from its card, opening a
  node's card from a conversation, asking for fleet rights from either. One
  shared node view (`src/webassets/nodeview.py`), mounted rather than framed, so
  every page keeps `frame-ancestors 'none'`.
- Docs: `Docs/AppAPI/guide`, `Docs/WebConsole/design`.

### Mesh-native releases (`src/core_release.py`) — done
- A node publishes **its own code**: one deterministic archive plus a descriptor
  naming its hash, signed with its ML-DSA identity, on a signing domain of its
  own so it cannot be confused with an app release, a certificate or a
  handshake. Publishing touches **no network** — it signs and announces.
- The package moves on demand (`RELEASE_FETCH`/`RELEASE_DATA`, routable and
  sliced) from the publisher or from any node that kept a copy; receiving one
  makes a node a source, so one publisher becomes a swarm and a publisher that
  goes offline stops being necessary.
- Gossiped as `RELEASE_ANNOUNCE` with the app catalogue's rules — verify, keep
  only what is newer (signed `ts`), re-gossip only when the view changed, catch a
  new peer up at the handshake. A release from an unpinned publisher is relayed
  and displayed, never installed, and the catalogue reserves room so a flood of
  strangers cannot evict a pinned publisher.
- Three gates before anything touches disk: the publisher is pinned by the
  operator (nothing from the network can add a pin), the version is strictly
  newer than the running one, and every byte verifies against the signed root —
  including the version the tree itself declares, so a release cannot announce
  one version and carry another.
- Installing ends in a **restart**, because a tree written and never started is
  an update that did not happen — and only where a service manager will bring
  the node back. What keeps that from looping is a journal written *before* the
  node leaves: a release that installs and never becomes the running version is
  retried once and then abandoned. Automatic installation stays a second
  decision per publisher, taken after the pin; the console ticks it by default,
  and a machine provisioned from the fleet page is handed its operator's
  publishers so a headless box is not left accepting nothing for ever.
- An announce from a publisher marked for automatic installation **wakes** the
  pass; a stranger's announce does not. The periodic sweep is the net under a
  missed wake-up, not the schedule.
- GitHub remains as the first-run route only. Docs: `Docs/Updates/guide`.

### Long term
- **Signing GitHub releases too** (or dropping that route once a node can always
  reach a publisher it trusts on the mesh).
- A trust score per node + revocation on betrayal.
- Persisting the trust/cert table on disk.
- meshnet-daemon: embeds the library, listens on a socket, multi-client.
