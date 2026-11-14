# NMesh documentation

This is the map. Each folder has one job; start from the row that matches what
you are doing.

## Start by role

| You are… | Read, in this order |
|---|---|
| New to the code | [`../AGENTS.md`](../AGENTS.md) → [`Architecture/README.md`](Architecture/README.md) → [`Architecture/protocol.md`](Architecture/protocol.md) → [`../TEST.md`](../TEST.md) |
| Debugging a hang or a flaky test | [`Architecture/gotchas.md`](Architecture/gotchas.md) (its *Start here* section) → [`../TEST.md`](../TEST.md) |
| Installing or operating a node | [`../README.md`](../README.md) → [`Setup/guide`](Setup/guide) → [`../FAQ.md`](../FAQ.md) |
| Writing an app | [`DataConnector/guide`](DataConnector/guide) → [`AppAPI/guide`](AppAPI/guide) → [`AppPermissions/guide`](AppPermissions/guide) → [`AppStorage/guide`](AppStorage/guide) |
| Writing a transport | [`Transports/guide`](Transports/guide) → [`Transports/template.py`](Transports/template.py) → [`Architecture/transports.md`](Architecture/transports.md) |
| Working on the console | [`WebConsole/guide`](WebConsole/guide) → [`WebConsole/design`](WebConsole/design) → [`Architecture/control-plane.md`](Architecture/control-plane.md) |
| Reviewing security | [`../AGENTS.md`](../AGENTS.md) threat model → [`Architecture/security.md`](Architecture/security.md) → [`../BUGSVULNS.MD`](../BUGSVULNS.MD) → [`../SECURITY.md`](../SECURITY.md) |
| Publishing or updating | [`Updates/guide`](Updates/guide) → [`Architecture/security.md`](Architecture/security.md) |

## Internal mechanics — `Architecture/`

How the code actually works. A change to a behaviour described here updates the
document **in the same commit**.

- [`Architecture/README.md`](Architecture/README.md) — index, reading order, the
  four layers, and the map of `src/`.
- [`Architecture/protocol.md`](Architecture/protocol.md) — wire format, `msg_id`,
  AAD, message types, validation gates, forwarding.
- [`Architecture/security.md`](Architecture/security.md) — identity, crypto,
  certificates and trust, renewal/compaction/revocation, invitations,
  handshakes, E2E, app identity and permissions.
- [`Architecture/routing.md`](Architecture/routing.md) — routing table,
  Kademlia, DHT, pseudo and package directories, neighbourhood maintenance,
  routed paths, address propagation.
- [`Architecture/transports.md`](Architecture/transports.md) — the transport
  contract, TCP/UDP/veil/spool, NAT/STUN, keepalive, traffic profiles,
  multi-link operation.
- [`Architecture/control-plane.md`](Architecture/control-plane.md) — the frame,
  operation declarations, origins and grants, jobs, transfers, the operation
  ledger.
- [`Architecture/logging.md`](Architecture/logging.md) — the log engine: what is
  kept, when, and by whom.
- [`Architecture/alerts.md`](Architecture/alerts.md) — the notice board.
- [`Architecture/behaviour-rules.md`](Architecture/behaviour-rules.md) — the
  detection catalogue: what is measured, what is implemented, and the rules that
  must never become signals.
- [`Architecture/scale.md`](Architecture/scale.md) — what grows with the mesh,
  and what must not.
- [`Architecture/gotchas.md`](Architecture/gotchas.md) — the traps, with a
  diagnosis-first index. **Start here before debugging a hang.**

## Guides — by area

Each is a usage guide, not a description of internals.

| Folder | Covers |
|---|---|
| [`Setup/guide`](Setup/guide) | `install.sh`, `start.sh`, the service, the configuration file, liboqs. |
| [`CLI/guide`](CLI/guide) | `nmeshctl`, signing in, managing another node from a terminal. |
| [`WebConsole/guide`](WebConsole/guide) | Every page and route of the console. |
| [`WebConsole/design`](WebConsole/design) | The design system, tokens, components, shell, shared runtime. |
| [`DataConnector/guide`](DataConnector/guide) | Plugging an external app into the mesh, and launching a child app with the node. |
| [`AppAPI/guide`](AppAPI/guide) | An app declaring operations other apps, pages and the core can call. |
| [`AppAuth/guide`](AppAuth/guide) | The mesh identity as an authentication system for apps. |
| [`AppPermissions/guide`](AppPermissions/guide) | The permission tree, manifests, mods, who an app is. |
| [`AppStorage/guide`](AppStorage/guide) | The encrypted per-app drawer. |
| [`AppStore/guide`](AppStore/guide) | Finding, installing and updating an app by name, plus the raw DHT package path. |
| [`Apps/chat`](Apps/chat) | The chat app, voice messages, the social layer, calls. |
| [`Apps/contacts`](Apps/contacts) | The contacts app and its permission. |
| [`Apps/fleet`](Apps/fleet) | Remote management, grants, SSH, Docker, files, terminal. |
| [`Apps/mcp`](Apps/mcp) | The node's operations as MCP tools. |
| [`I18n/guide`](I18n/guide) | Languages, catalogues, `t()`, adding a language. |
| [`Pseudos/guide`](Pseudos/guide) | Names: what a pseudo is, and what it is not. |
| [`Transports/guide`](Transports/guide) | Writing a transport, with spool as the store-and-forward example. |
| [`Updates/guide`](Updates/guide) | Releases published by nodes, signed, and how they install. |

## History, ideas and process

- [`History/`](History/README.md) — frozen records: the full security audit, a
  live field report, and an implemented design. Read for context, never as a
  statement about today.
- [`Ideas/`](Ideas/README.md) — research notes, nothing implemented.
- [`Contributing/agent-mistakes.md`](Contributing/agent-mistakes.md) — every
  mistake an agent has made here, with the rule that would have prevented it.
  Read it before you start.

## Conventions

- Guides are extensionless Markdown files; architecture documents use `.md`.
- Every relative link resolves. There is no external asset in a page or a doc.
- English, no emoji, structure over decoration — see
  [`../AGENTS.md`](../AGENTS.md).
- A document that no longer describes the code is a bug: fix it in the same
  change, or move it to `History/` with a dated banner.
