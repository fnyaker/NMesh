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
| `node.py` | The core (~5000 lines): receive loop, dispatch, handshake, routing (learned return path, route acquisition outside the receive loop), DHT, E2E, hole punching, keepalive, reachability, **maintaining a target neighbourhood and multi-hop recovery**, **chasing back a node whose link just died**. |
| `packet.py` | Packet format, `msg_id`, GCM AAD, (de)encrypting a packet. |
| `seen.py` | The replay window: a bounded, **exact** set of 64-bit ids in a flat table, generational eviction, seeded buckets. Sixteen bytes an id where boxing them cost a hundred. |
| `node_id.py` | `NodeID` = sha256(DSA public key)[:20]; Kademlia XOR distance. |
| `crypto.py` | `CryptoIdentity` (ML-DSA sign, ML-KEM), `SessionKey` (AES-256-GCM + HKDF). |
| `cert.py` / `cert_store.py` | Certificates + self-rooted P2P PKI (chains, verification, roots, expiry, revocation). |
| `revocation.py` | A signed "I no longer vouch for this node", from its issuer and nobody else. |
| `reputation.py` | What this node thinks of the nodes it talks to: a bounded, decaying score fed by the core and by the apps, plus `RateGate`. |
| `app_guard.py` | An app's per-kind allowances per sender, and the one place a breach is reported to the node. |
| `features.py` | What two nodes agree they can say to each other: a set of names, not a version number. |
| `behaviour.py` | Named rules over counters the links already keep, swept on the keepalive timer. Compares a peer to its transport class, never to a constant; a rule that fires on everyone disarms itself. |
| `publisher_key.py` | A release-signing key kept encrypted at rest, unlocked only to sign. |
| `accusation.py` | A signed "I saw this node misbehave". Carries no authority on purpose — the receiver weighs it. |
| `invite.py` | Invitation codes (HMAC challenge/response, single use, lockout). |
| `routing.py` | Kademlia routing table (k-buckets, `last_seen`). |
| `dht.py` | Content-addressed DHT store (`key = sha256(value)[:20]`). |
| `app_dht.py` | Per-app DHT (overlay): a namespace per `app_id`, entries public (in the clear) or private (AES-256-GCM under a key the app supplies). |
| `pseudo.py` | The one canonical form of a pseudo (NFC, no invisible or directional characters, at most 50). Deterministic, so a receiver can re-derive it and call a mismatch a lie. |
| `pseudo_dir.py` | Signed name claims (bound to the public key, so a claim can only name its own author) and the bounded book that holds them — indexed by node id *and* by directory key, so it answers both "what is this called?" and "who is called this?". |
| `transport.py` / `transport_manager.py` | The `BaseTransport`/`BaseServer` interfaces + a registry by URL scheme. |
| `tcp_transport.py` / `udp_transport.py` / `spool_transport.py` | Concrete transports. |
| `net_monitor.py` / `stun.py` / `ip_utils.py` | Address tracking, STUN, local IPs, **enumerating the attached networks** (interface + real mask, via `/proc/net/route`, ioctl, `ip`/`ifconfig`, then a fallback), a bounded DNS resolver outside the executor. |
| `webconsole.py` / `webassets/` | The web management console (HTTPS, stdlib). The node reports what moved (`set_change_listener`) and the console coalesces it into a `text/event-stream`, so a link appears the moment it does instead of on a timer. The assets are a package: `ui.py` carries the design system, one module per page, `nodeview.py` carries the **node view** — mounted by the console's dialog, by chat, by fleet, *and* served at `/node` — and `terminal.py` carries the **terminal**: the emulator, the session driver, and the full-screen page at `/term` that fleet's panel shares them with. See [`Docs/WebConsole/design`](../WebConsole/design). |
| `app_channel.py` | App sections: `app_id ‖ payload` framing inside the DATA payload, built-in/deployed ids (connector demultiplexing). |
| `data_connector.py` / `process_launcher.py` / `apps/` | Plugging apps into the mesh (one section per app). |
| `apps/chat*.py` | The built-in chat app: messages/files/stream (`chat.py`), the social layer of contacts/groups (`chat_state.py`), the console UI (`chat_web.py`). Names are mirrored from the node, never carried in a chat message. |
| `app_package.py` | Content-addressed packages + a **signed release** (deployment: app_id bound to the ML-DSA author, a signed `ts` for version ordering). |
| `app_catalog.py` | App store: the network catalogue (signed releases, gossiped, anti-rollback) + a local registry of installed apps. |
| `app_storage.py` | A local per-app store (the "drawer"): key→value encrypted at rest (AES-256-GCM, a per-app key derived from the identity), isolated by `app_id`, bounded. |
| `app_auth.py` | **Application identity** (SSO): ML-DSA-signed assertions scoped to `(app, audience, purpose, ctx)`, freshness, anti-replay, mutual login. A separate signing domain — never an oracle. |
| `app_api.py` | **The app API surface**: an app declares its operations (`API` + `api_<name>`), and everything else — another app, the core, a page — calls them the same way. Reject by default: nothing that is not declared, every argument coerced and bounded. See [`../AppAPI/guide`](../AppAPI/guide). |
| `app_registry.py` | The registry of **built-in** apps (installed / enabled, persisted) + `AppHost`, which starts and stops them live. |
| `apps/fleet*.py` | The management/deployment app: protocol and roles (`fleet.py`), the capability ledger (`fleet_state.py`), machine facts and the update plan (`fleet_host.py`), LAN scan + SSH over a pty (`fleet_ssh.py`), provisioning bootstrap (`fleet_provision.py`), files under the `shell` right (`fleet_files.py`), the relay to the local console (`fleet_console.py`), the console bridge (`fleet_web.py`). |
| `session_store.py` | Encrypted persistence: E2E sessions + peers (`SessionStore`), and the **names this node has learned** (`PseudoStore`, its own file and cadence — the session blob is rewritten every couple of seconds and a book of 5 kB claims has no business on that path). |
| `join_ticket.py` | **A compact join ticket**: address + port + the code's seed + expiry + checksum, in unpadded base32 (34 characters for IPv4). Defensive decoding: bounded, everything validated, never anything but a `TicketError`. |
| `qr.py` | A QR encoder (ISO/IEC 18004) in pure stdlib: versions 1–10, levels M/L, alphanumeric and byte modes, Reed-Solomon and mask selection. Verified against an independent encoder and a real decoder. |
| `console_auth.py` | The console credential: scrypt hashing + salt, atomic 0600 write, constant-time comparison, bounds on the password. Shared by the console and by the installer's reset — one implementation. |
| `trace.py` | **Protocol trace**: a bounded ring of packet events (type, size, TTL, ids) + totals per message type. Never a payload. Off by default, bounded in memory *and* in time, stops on its own. See [`../WebConsole/guide`](../WebConsole/guide). |
| `config.py` | The node's configuration file (`nmesh.conf`): bounded, defensive parsing, per-setting validation, commented rendering, atomic 0600 write. Precedence command line > file > default. See [`../Setup/guide`](../Setup/guide). |
| `version.py` / `updater.py` | The current version and tag comparison; obtaining a release (from GitHub, or from the mesh) and replacing the installed tree — the node's state is untouched, the previous tree is kept and restored on failure. See [`../Setup/guide`](../Setup/guide). |
| `core_release.py` | **Mesh-native releases**: a node packs its own code into one deterministic archive and signs a descriptor naming its hash. Publishing touches no network; the package moves when someone asks, and whoever received it serves the next node. An operator pins the publisher keys they accept; nothing arriving from the network can add one. Also the journal that keeps an automatic install — which ends in a restart — from becoming a restart loop. See [`../Updates/guide`](../Updates/guide). |

## The documents

1. **[protocol.md](protocol.md)** — packet, `msg_id`, AAD, message types, the
   dispatch validation gates, TTL, deduplication, forwarding.
2. **[security.md](security.md)** — identity, post-quantum crypto, certificates
   & trust chains, invitation, handshake, E2E session.
3. **[routing.md](routing.md)** — routing table, `last_seen`, on-demand
   routing, Kademlia lookup, DHT, **address propagation**.
4. **[transports.md](transports.md)** — the transport abstraction, TCP/UDP/spool,
   NAT hole punching, STUN, reachability/AutoNAT, net monitor, keepalive.
5. **[gotchas.md](gotchas.md)** — the traps learned the hard way (asyncio 3.12,
   blocking network probes, hole-punch races, parallelising the tests).
   **Start here before debugging a hang or a flaky test.**
6. **[behaviour-rules.md](behaviour-rules.md)** — what a node measures to
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
