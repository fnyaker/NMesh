# NMesh — Architecture (how it actually works)

> **Read this BEFORE any change or debugging session.** These documents
> describe how the code really behaves (not an ideal target). If you change a
> behaviour described here, **update the document in the same commit**.
> Documentation that lies is worse than none.

The usage guides (how to plug an app in, how to write a transport…) stay in the
other folders of `Docs/`. Here we describe the **internal mechanics**. Two
guides sit next to security and deserve to be read alongside `security.md`:
[`Docs/AppAuth/guide`](../AppAuth/guide) (the mesh identity as authentication
for apps) and [`Docs/Apps/fleet`](../Apps/fleet) (the app that uses it to
authorise remote execution). [`Docs/Updates/guide`](../Updates/guide) is the
third: the mesh identity signing the node's **own code**. And
[`Docs/Pseudos/guide`](../Pseudos/guide) is the fourth: the same identity
signing the **name** a node is shown under — a label that decides nothing, and
is therefore safe to accept from strangers.

## Map of the code (`src/`)

| File | Role |
|---|---|
| `node.py` | The node itself (`MeshNode`): receive loop, dispatch, handshake, routing (learned return path, route acquisition outside the receive loop), DHT, E2E, hole punching, keepalive (a **due time per link**, not one interval for all), reachability, **maintaining a target neighbourhood and multi-hop recovery**, **chasing back a node whose link just died — hard, then patiently, never giving up on it**, **replacing a link that is up and losing a fifth of its probes**, **re-verifying our own addressing when several nodes go at once**, **spreading one node's traffic over two links**. Its parts that are *not* the node are pulled out into the modules below, and re-exported here so `src.node` stays the one door onto the core for everything that already imports it. |
| `mesh/messages.py` | The message vocabulary: one number per kind of packet, and the name each carries in a trace, built from this module's own constants so a type added below can never be missing above. Its own module because it is the one thing a transport, an app and a console all need to name a message, and none of them should have to import the node to do it. |
| `mesh/constants.py` | Every bound the core holds itself to: queue depths, rate-limit windows, timeouts, retry ceilings, keepalive cadences, and the direct/routable split of the type table. `CLAUDE.md` is blunt that *every queue, cache, buffer and counter has a hard limit* — this is where each one is written down, beside what it protects. |
| `mesh/codecs.py` | The wire: handshake, certificate chain, addresses, `FOUND_NODE` entries (with the certificate pool that keeps a post-quantum chain from filling the packet), ping trailers, E2E handshakes, punch signalling, invitation seeks and the two-step connect blocks. Every decoder here parses bytes that arrived from the network, so each bounds what it will read before it reads it — this is the module `tests/test_fuzz.py` exists for. |
| `mesh/peers.py` | A link, not a node: `_Peer` (a node may hold several links at once, which is why every counter it keeps is named for the link), `RelayedTransport` (the core's own transport — a link that is another node carrying frames), and `_PunchState` (one hole-punch in flight). |
| `packet.py` | Packet format, `msg_id`, GCM AAD, (de)encrypting a packet. Building one is on the send path of everything the node emits, so it constructs the packet once rather than twice and draws its nonce in blocks — a slice of a CSPRNG draw, never a cheaper source. |
| `activity.py` | Who is doing what: every background loop declares a name, what it does and **what wakes it**, and counts its own passes. Nothing on the packet path. |
| `seen.py` | The replay window: a bounded, **exact** set of 64-bit ids in a flat table, generational eviction, seeded buckets. Sixteen bytes an id where boxing them cost a hundred. |
| `node_id.py` | `NodeID` = sha256(DSA public key)[:20]; Kademlia XOR distance. |
| `crypto.py` | `CryptoIdentity` (ML-DSA sign, ML-KEM), `SessionKey` (AES-256-GCM + HKDF). |
| `cert.py` / `cert_store.py` | Certificates + self-rooted P2P PKI (chains, verification, roots, expiry, revocation). |
| `revocation.py` | A signed "I no longer vouch for this node", from its issuer and nobody else. |
| `reputation.py` | What this node thinks of the nodes it talks to: a bounded, decaying score fed by the core and by the apps, plus `RateGate`. |
| `app_guard.py` | An app's per-kind allowances per sender, and the one place a breach is reported to the node. |
| `features.py` | What two nodes agree they can say to each other: a set of names, not a version number. Silence means yes for every name older than the negotiation, and no for the ones added since (`SINCE_NEGOTIATION`) — the same sentence, "exactly what it received before", read in both directions. |
| `behaviour.py` | Named rules over counters the links already keep, swept on the keepalive timer. Compares a peer to its transport class, never to a constant; a rule that fires on everyone disarms itself. |
| `routed.py` | **Routed paths**: reaching a node *through* another node, as something measured rather than assumed — a first hop is probed end to end, a run of silence gives up on it, and giving up is remembered so the next pass does not re-open it. What `mlo.py` bundles over links, this makes available over paths (MRLO), and over a mix of the two (HMLO): losing a direct link then costs a turn of the send order rather than a reconnect. Over identities and measurements only, so none of it needs a mesh to be tested. |
| `mlo.py` | **Multi-link operation**: two links to one node carrying its traffic together, and the keepalive **accord** that makes measuring them possible. Which links are close enough to bundle, what that costs in reordering, and which one is losing enough to be benched — over opaque keys, so none of it needs a mesh to be tested. |
| `publisher_key.py` | A release-signing key kept encrypted at rest, unlocked only to sign, plus the `KeyStore` holding the ones a node may sign with. Each id is **re-derived from the file's own public half** on read, so a tampered index can lose a key but never make the node sign under an identity the file does not carry. |
| `key_share.py` | Handing that key to somebody else — the one secret this project deliberately copies. Three messages, and the middle one is the design: there is no long-term encryption key to seal a secret to, so the recipient produces an ML-KEM key **only when a human accepted**, and consent becomes structural rather than checked. |
| `accusation.py` | A signed "I saw this node misbehave". Carries no authority on purpose — the receiver weighs it. |
| `equivocation.py` | The one report that is **not** an opinion: two records signed by the same key that cannot both have been meant. Forging one needs the key it accuses, so the messenger's honesty is not in it. |
| `invite.py` | Invitation codes (HMAC challenge/response, single use, lockout). The relayed half lives in `node.py`: an inviter leaves a **rendezvous** with a relay (`INVITE_OFFER`) so the heavy part of a relayed invitation — a post-quantum key and a signature — never has to fit in the string somebody scans. |
| `routing.py` | Kademlia routing table (k-buckets keyed by id so a refresh is a `move_to_end` rather than a scan under dataclass equality, `last_seen`, and a `touch` that refreshes recency without the merge `add` does — most probes now carry no addresses at all), plus the two things it needed to stop chasing ghosts: addresses that answered as somebody else are **remembered**, not merely dropped, and an id that has never once answered a lookup stops being asked after, dialled, or named to others. |
| `dht.py` | Content-addressed DHT store (`key = sha256(value)[:20]`). |
| `pkg_dir.py` | **The package directory**: one signed sentence a node says about itself — *I hold this release and I serve it* — filed under the node id, under the release, and under the package name's prefixes. So "what does this machine offer?", "who can serve this release?" and "who offers something called this?" are one lookup with three keys, and **recommending is holding**: the records under a release are the machines that can hand it over. A second signature by the key that signed the release turns holding into publishing, and it names the node, so it cannot be lifted. Also the source digest that answers "do these publishers agree on the *code*?" without downloading anything. |
| `subscriptions.py` | What this node watches for a new version — **a package**, never a publisher — and how many signing keys the operator chose (endorsed, or the pin a release sits under) must agree on the code before one installs itself. A subscription is named by the package, which is why nothing may look one up by the id of a record. Local, deliberate, never writable from the network — like the pins beside it. |
| `app_dht.py` | Per-app DHT (overlay): a namespace per `app_id`, entries public (in the clear) or private (AES-256-GCM under a key the app supplies). |
| `pseudo.py` | The one canonical form of a pseudo (NFC, no invisible or directional characters, at most 50). Deterministic, so a receiver can re-derive it and call a mismatch a lie. Also `key_terms`: the terms a name is filed under, so a directory can answer half a name — shared with the package directory, because a name is a name. |
| `pseudo_dir.py` | Signed name claims (bound to the public key, so a claim can only name its own author) and the bounded book that holds them — indexed by node id *and* by every key the name is filed under (the whole name and each word's prefixes), so it answers "what is this called?", "who is called this?" and "who is called something starting with this?". Keeps the proof when one node signs two names for one instant. |
| `transport.py` / `transport_manager.py` | The `BaseTransport`/`BaseServer` interfaces + a registry by URL scheme. |
| `tcp_transport.py` / `udp_transport.py` / `spool_transport.py` | Concrete transports. |
| `net_monitor.py` / `stun.py` / `ip_utils.py` | Address tracking (on a timer, on a trigger, and **urgently** when the node has evidence its own addressing moved rather than a suspicion), STUN, local IPs, **enumerating the attached networks** (interface + real mask, via `/proc/net/route`, ioctl, `ip`/`ifconfig`, then a fallback), a bounded DNS resolver outside the executor. |
| `control/` | **The control plane**: what a node can be asked to do about itself, declared once and reached over a channel. A module (`node`, `config`, `transports`, `trace`, `pseudo`, `jobs`, `control`) declares its operations, their arguments, their ceiling and how far they travel — nothing by default, which is what replaced a denylist of URL prefixes. **Everything now travels**, by one of three mechanisms: what outlasts the relay runs as a *job* (`jobs.py` — a bounded book, a ticket, a thread that is never joined), what is a *decision* rather than an operation needs the fleet's `govern` capability beside `manage`, and **files** are a named set of byte streams carried a chunk per frame (`transfer.py`) — so a download follows the node being driven instead of quietly fetching from the machine serving the page. One frame carries a request either way: `LocalChannel` answers it here, `RemoteChannel` points the same channel at a node somebody manages. See [`control-plane.md`](control-plane.md). |
| `webconsole.py` / `webassets/` | The web management console (HTTPS, stdlib). The node reports what moved (`set_change_listener`) and the console coalesces it into a `text/event-stream`, so a link appears the moment it does instead of on a timer. `POST /api/control` is the plane's one route — everything else beside it is a route that has not moved onto it yet, and a migrated one is a thin adapter over the same operation rather than a second implementation. The assets are a package: `ui.py` carries the design system, `channel.py` the browser's half of the plane, one module per page, `nodeview.py` carries the **node view** — mounted by the console's dialog, by chat, by fleet, *and* served at `/node` — and `terminal.py` carries the **terminal**: the emulator — the alternate screen, scroll regions, 24-bit colour and mouse reporting, because a program that *draws* needs a terminal rather than a log pane, and a parser that matches in place because slicing the buffer at every escape is quadratic in the size of a frame — the **canvas** it is drawn on, where a cell is placed at `col * cw` rather than laid out (a box-drawing glyph the font lacks falls back at another width, and the whole line drifts), the session driver, whose read is held by the console until the pty speaks rather than fired on a timer, and the full-screen page at `/term` that fleet's panel shares them with. See [`Docs/WebConsole/design`](../WebConsole/design). |
| `app_channel.py` | App sections: `app_id ‖ payload` framing inside the DATA payload, built-in/deployed ids (connector demultiplexing). |
| `data_connector.py` / `process_launcher.py` / `apps/` | Plugging apps into the mesh (one section per app). |
| `apps/fleet_links.py` | The mesh map past one node's own eyes: what the machines an operator manages say they are connected to, held **while it is still true**. A freshness book rather than a history — a machine that has not confirmed in 45 seconds has no links on the map, not old ones — replacing rather than merging, bounded on every axis, and in memory only. |
| `apps/fleet_logs.py` | The logs of the machines an operator manages, kept on the operator's node: one bounded, compressed ring **per machine** (never one pool — a chatty machine must not push out a quiet one's log), a bounded number of them, and a collection policy per node with a fleet-wide default. Ordered by *our* clock, never by the time the far machine supplied. |
| `apps/chat*.py` | The built-in chat app: messages/files/stream (`chat.py`), the social layer of contacts/groups (`chat_state.py`), the console UI (`chat_web.py`). Names are mirrored from the node, never carried in a chat message. |
| `app_package.py` | Content-addressed packages + a **signed release** (deployment: app_id bound to the ML-DSA author, a signed `ts` for version ordering). |
| `app_catalog.py` | App store: the network catalogue (signed releases, gossiped, anti-rollback) + a local registry of installed apps. |
| `app_storage.py` | A local per-app store (the "drawer"): key→value encrypted at rest (AES-256-GCM, a per-app key derived from the identity), isolated by `app_id`, bounded. |
| `app_auth.py` | **Application identity** (SSO): ML-DSA-signed assertions scoped to `(app, audience, purpose, ctx)`, freshness, anti-replay, mutual login. A separate signing domain — never an oracle. |
| `app_api.py` | **The app API surface**: an app declares its operations (`API` + `api_<name>`), and everything else — another app, the core, a page — calls them the same way. Reject by default: nothing that is not declared, every argument coerced and bounded. See [`../AppAPI/guide`](../AppAPI/guide). |
| `app_registry.py` | The registry of **built-in** apps (installed / enabled, persisted) + `AppHost`, which starts and stops them live. |
| `apps/fleet*.py` | The management/deployment app: protocol and roles (`fleet.py`), the capability ledger (`fleet_state.py` — grants, the groups an operator names, and the credentials this node holds for something else), machine facts and the update plan (`fleet_host.py`), LAN scan + SSH over a pty (`fleet_ssh.py`), provisioning bootstrap (`fleet_provision.py`), files under the `shell` right (`fleet_files.py`), **docker** (`fleet_docker.py`: the Engine API over the machine's own socket, and stacks recovered from the labels compose writes — no second source of truth) and the **Portainer** in front of it (`fleet_portainer.py`: a stack it owns is updated through it, or the next thing it does undoes the update), the relay to the local console (`fleet_console.py`), the console bridge (`fleet_web.py`). |
| `session_store.py` | Encrypted persistence: E2E sessions + peers (`SessionStore`), and the **names this node has learned** (`PseudoStore`, its own file and cadence — the session blob is rewritten every couple of seconds and a book of 5 kB claims has no business on that path). |
| `join_ticket.py` | **One invitation, both ways round**: the inviter's own endpoint *and* a relay to reach it through, plus the code's seed, an expiry and a checksum, in unpadded base32 (34 characters for a direct IPv4 one, 76 for both routes). That is what removes the second exchange — a ticket used to be the direct case and a block of base64 the other, and an operator had to know which they were in first. Defensive decoding: bounded, everything validated, never anything but a `TicketError`. |
| `qr.py` | A QR encoder (ISO/IEC 18004) in pure stdlib: versions 1–10, levels M/L, alphanumeric and byte modes, Reed-Solomon and mask selection. Verified against an independent encoder and a real decoder. |
| `console_feed.py` | **What the console sends a page, and how the two stay in step.** A read carries who is speaking (`proto`, `build`), what changed (named sections, by revision), and what to do when the two cannot agree. The revision is a checksum of the **section itself**, never a counter — a counter has to be bumped from every place that writes, and the one that forgets is a section that silently stops updating. `proto=1` is the flat snapshot every earlier page sent and understood and is still answered exactly as it was; `proto=2` is the sectioned one. That is what lets a page from before an update keep working against a node from after one. |
| `console_auth.py` | The console credential: scrypt hashing + salt, atomic 0600 write, constant-time comparison, bounds on the password. Shared by the console and by the installer's reset — one implementation. |
| `trace.py` | **Protocol trace**: a bounded ring of packet events (type, size, TTL, ids) + totals per message type. Never a payload. Off by default, bounded in memory *and* in time, stops on its own. See [`../WebConsole/guide`](../WebConsole/guide). |
| `logbook.py` | **The log**: what the node and its apps *said*, beside what `trace.py` says they sent. Off until an operator asks, bounded in **megabytes** rather than in lines, compressed a block at a time, and dropped when it stops. Read by sequence number, so a console four hops away follows it exactly as a page on the machine does. See [`logging.md`](logging.md). |
| `alerts.py` | **The notice board**: what wants a person's attention, one entry per problem with a count rather than one per occurrence. Always on — the conditions worth telling somebody about are the ones nobody knew to start a log for — bounded so the worst survives, and never a reason to act on its own. See [`alerts.md`](alerts.md). |
| `faults.py` | Where a swallowed failure goes: stderr, bounded, named — plus one sink, so a node keeping a log gets the failures that have no other reader at all. |
| `config.py` | The node's configuration file (`nmesh.conf`): bounded, defensive parsing, per-setting validation, commented rendering, atomic 0600 write. Precedence command line > file > default. See [`../Setup/guide`](../Setup/guide). |
| `version.py` / `updater.py` | The current version and tag comparison; obtaining a release (from GitHub — the published releases, or `src/version.py` at a branch when `update_branch` names one — or from the mesh) and replacing the installed tree — the node's state is untouched, the previous tree is kept and restored on failure. See [`../Setup/guide`](../Setup/guide). |
| `core_release.py` | **Mesh-native releases**: a node packs its own code into one deterministic archive and signs a descriptor naming its hash. Publishing touches no network; the package moves when someone asks, and whoever received it serves the next node. An operator pins the signing keys they accept, and **what each is accepted for** — a key pinned from an app's record is a party to that app, never somebody who may replace this program; nothing arriving from the network can add one. Also the journal that keeps an automatic install — which ends in a restart — from becoming a restart loop, and the proof kept when one publisher signs two different programs under one version. A release is named by its **descriptor's own content key** (`descriptor_key`), never by its publisher: `ReleaseBook` holds one entry per release and several per signing key, because a key is not a name for a release — indexing that way meant clicking one release installed whatever that key had signed since. See [`../Updates/guide`](../Updates/guide). |

## The documents

1. **[protocol.md](protocol.md)** — packet, `msg_id`, AAD, message types, the
   dispatch validation gates, TTL, deduplication, forwarding.
2. **[security.md](security.md)** — identity, post-quantum crypto, certificates
   & trust chains, invitation, handshake, E2E session.
3. **[routing.md](routing.md)** — routing table, `last_seen`, on-demand
   routing, Kademlia lookup, DHT, **address propagation**.
4. **[transports.md](transports.md)** — the transport abstraction, TCP/UDP/spool,
   NAT hole punching, STUN, reachability/AutoNAT, net monitor, keepalive, the
   **keepalive accord** and **multi-link operation**.
5. **[gotchas.md](gotchas.md)** — the traps learned the hard way (asyncio 3.12,
   blocking network probes, hole-punch races, parallelising the tests).
   **Start here before debugging a hang or a flaky test.**
6. **[control-plane.md](control-plane.md)** — the management plane: one frame
   between a front end and a node, the declaration that decides what an
   operator at another console may ask for, the two mechanisms that let *all*
   of it be asked from a distance (jobs, and the `govern` capability), the
   channels, and the ledger of what has moved onto it. **Read it before adding
   a console route.**
7. **[logging.md](logging.md)** — the log engine: why nothing is kept by
   default, why the bound is in megabytes, how a subscriber catches up after a
   gap, and the two unequal halves of an app's access to it.
8. **[alerts.md](alerts.md)** — the notice board: one entry per problem, what
   an app may put on it, and why nothing on it ever acts.
9. **[behaviour-rules.md](behaviour-rules.md)** — what a node measures to
   notice one that is not playing the protocol. Partly implemented
   (`behaviour.py`), mostly still a catalogue. Chain-of-trust genealogy, signature correlation, protocol
   conformance, traffic shape, routing, gossip, the update chain — with the
   anti-rules that must never become signals, and why.

## The four layers (bottom to top)

```
   Apps (chat, call, data connector)          ── application payload
   ────────────────────────────────
   E2E (E2E_HANDSHAKE / encrypted DATA)       ── end-to-end secrecy, blind relays
   ────────────────────────────────
   Mesh (Kademlia routing, DHT, hole punch)   ── reach a NodeID over any medium
   ────────────────────────────────
   Link (per-hop handshake + AES session)     ── an authenticated peer on a transport
   ────────────────────────────────
   Transport (tcp/udp/spool/…)                ── carry bytes
```

Two levels of encryption: **per-hop** (a session negotiated at the handshake
between two direct peers) and **end to end** (E2E, between the source and the
final destination; relays see only routing metadata).
