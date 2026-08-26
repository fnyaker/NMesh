# NMesh — engineering charter

A decentralised, transport-agnostic mesh network, built to carry sensitive data
through a **hostile** environment. This file sets the non-negotiable
principles. Every contribution must respect them.

## Architecture documentation — MANDATORY

`Docs/Architecture/` describes **how the code actually works** (protocol,
security, routing, transports, and above all `gotchas.md`: the hard-won traps
around hangs and flakiness).

- **BEFORE any change or debugging session**, read the relevant documents. For a
  hang or a flaky test, **start with `Docs/Architecture/gotchas.md`**.
- **AFTER any change to behaviour described there**, update the document **in
  the same commit**. Documentation that lies is worse than none.
- A new non-trivial mechanism → an entry in the right document (or a new file
  plus a link in `Docs/Architecture/README.md`).

Index: [`Docs/Architecture/README.md`](Docs/Architecture/README.md).

## Threat model (the founding assumption)

> The moment data leaves the node, it enters **hostile territory**.
> We trust neither the network, nor the peers, nor the transport, nor — as far
> as possible — the local machine.

- Anything arriving from a peer is **presumed malicious** until validated.
- An authenticated peer may behave as an adversary (a relay that alters,
  replays, amplifies or floods). Authentication is not trust.
- We defend against the device itself: sensitive keys kept in memory where
  possible, minimal attack surface, no secret in the clear on disk without a
  reason.
- We assume a state-resourced adversary who wants to break the network. The
  question to ask on every line: "what would they do with this?".

## The principles, in priority order

### 1. Security — never negotiable
- **Post-quantum** cryptography end to end: ML-KEM-768 (key exchange), ML-DSA-65
  (signatures), AES-256-GCM (authenticated encryption).
- **Reject by default.** Any packet that is malformed, unauthorised,
  unauthenticated or of an unexpected type is dropped with no side effect. A
  valid input must prove its validity; it is not the receiver's job to prove
  invalidity.
- All application data is E2E encrypted: relays see routing metadata only, never
  the content.
- A node's identity = the hash of its DSA public key. A `NodeID` that cannot be
  derived from the key presented is a lie → reject.
- Secrets compared in constant time (`hmac.compare_digest`).

### 2. Solidity — the network never goes down
- **Zero crash. A crash is a security bug.** No network input, however hostile,
  may bring a node down or kill a receive loop. If the unthinkable happens, the
  node must **repair itself** (auto-recovery): purge the corrupted state,
  reconnect on demand, resume service.
- **Active peer rejection.** A peer that sends noise, invalid packets or abuses
  the protocol is counted and then disconnected. We do not endure an adversary;
  we cut them off.
- **Bounds everywhere.** Every queue, cache, buffer and counter has a hard
  limit. Nothing that can grow without end under an attacker's pressure (no
  memory exhaustion, no amplification).
- Works in **degraded conditions**: loss, enormous latency, partitions,
  asynchronous transports (store-and-forward of the "USB stick carried on foot"
  kind). Error correction, retry, delay tolerance.

### 3. Flexibility — transport-agnostic
- The core knows **no** concrete transport. Anyone implements `BaseTransport` +
  `BaseServer` and registers it by URL scheme (`tcp://`, `ble://`, `lora://`,
  `usb://`…). The "Jarvis" goal: run over any medium capable of carrying bytes.
- Routing is medium-agnostic: if A↔B is Bluetooth and B↔C is Wi-Fi, A talks to
  C by routing through B, choosing the best link.
- Nodes announce themselves with URLs listing their transports; each node only
  uses the schemes it knows.

### 4. Speed — close to real time
- Goal: comfortably beat the ~4 MB/s already reached (TCP + routing).
- Optimise **without ever losing** security, solidity or flexibility. A
  performance gain that weakens any of the three above is refused.
- Hot paths with no superfluous allocation, no needless copy, no redundant
  crypto.

## Supply chain

- **Minimal external dependencies.** Every dependency is an attack surface (see
  the poisoned NPM/PyPI packages). By default: **the Python stdlib**.
- An external dependency is admitted only if it is indispensable, very widely
  used and audited. Today, strictly:
  - `liboqs-python` — post-quantum crypto (no stdlib equivalent).
  - `cryptography` — AES-GCM/HKDF (the Python ecosystem's reference).
  - `pytest` / `pytest-asyncio` / `pytest-xdist` / `pytest-timeout` — tests
    only, outside the runtime (`pytest-xdist` spreads the suite over every core;
    `pytest-timeout` bounds each test so a hang fails fast instead of running
    the job for hours).
- Adding a runtime dependency = an explicit justification in the PR + an update
  to this list. When in doubt: reimplement on the stdlib.

## Contribution discipline

- **Documentation follows the code, in the same commit — always, no
  exception.** This rule generalises the section above to **all** the
  documentation, not only `Docs/Architecture/`.
  - **BEFORE coding: read the documents concerned.** `Docs/Architecture/` first
    (internal mechanics), then the usage guides affected
    (`Docs/DataConnector/`, `Docs/Apps/`, `Docs/WebConsole/`,
    `Docs/AppSharing/`…), and `TEST.md` / `README.md` if the change touches
    them. Never code a documented mechanism blind.
  - **AFTER coding: update EVERY document the change touches, in the same
    commit** — the protocol, an app's guide, the console's API table, CI, the
    map of the code, the message table… A feature shipped without its
    documentation is **incomplete**, never "to be documented later".
    Documentation that is wrong or missing is a bug exactly like a red test.
- **Every change is proved by tests**, including hostile-input tests (fuzzing,
  random/malformed packets). "It works" is not enough: it has to "hold up".
- We never merge with the suite red.
- Readable code beats clever code. Write like the neighbour: same idioms, same
  comment density.
- A comment explains only a **constraint** the code cannot show, never the
  "what" nor where it came from.

### Name the thing, then count the thing

Most of the bugs that reach a user are not hard: they are a name that lies. A
`_Peer` in this codebase is a **link**, and a node may hold several at once — so
`authenticated_peers` counted links while the console printed "Connected to N
**nodes**". One number, four labels, right for two of them, and it survived a
whole pass that grouped those very links by node.

- **The name carries the unit.** `link_count` and `node_count`, never `peers`.
  If a reader has to open the definition to know what a number counts, rename it
  rather than comment it.
- **Derive, do not re-derive.** There was already a helper returning one link per
  identity; the snapshot re-implemented the count inline and got a different
  meaning. Two expressions for one quantity is two chances to be wrong.
- **Read the label out loud against the value.** Before shipping a number to a
  screen, say the sentence it will render: "Connected to 3 nodes" — is it three
  *nodes*? A label and its value are one claim, and the claim has to be true.
- **Ask who else uses this.** Every change: what reads this field, this
  function, this row — and what will? A count consumed under two labels is a
  count that will be wrong under one of them.
- Change the *cause*, not the symptom: a wrong number on a page is fixed in the
  thing that computes it, once, not corrected at each place it is displayed.

### No emoji in an interface

Emoji make a product look cheap, render differently on every platform, and carry
no meaning to a screen reader. They are also the lazy way out of drawing
something.

- **Graphical interfaces use SVG icons** — `icon()` in
  [`src/webassets/ui.py`](src/webassets/ui.py), one set, shared by every page,
  inheriting `currentColor` and sized in `em`. A page never inlines its own
  glyph.
- **Terminal output uses words**, aligned: `ok`, `warning:`, `failed`. A dingbat
  is not guaranteed to render in a minimal console, and a word always is.
- **Documentation uses structure** — a heading, a table, an admonition line in
  prose. Not a green tick.
- The one exception is content that *is* an emoji: the chat reaction palette,
  and what a person types. Those are the user's, not the interface's.
- **Every finished piece of work bumps the version**, in the same commit. One
  step on the patch number per task (or per block of tasks landing together):
  `0.1.3` → `0.1.4`. The patch number is **not capped at 9** — it counts up
  freely, `0.1.99` → `0.1.100`, and keeps going. A **minor** bump (`0.2.0`) is a
  deliberate act, marking a body of work worth naming, never something a patch
  count rolls over into.
  Two files carry it and a test holds them together:
  [`src/version.py`](src/version.py) and `pyproject.toml`.

## Network invariants (quick reminders)

- The header is in the clear but **authenticated** (as the GCM AAD); the payload
  is encrypted.
- `msg_id` binds the packet's content (anti-replay, anti-amplification); it is
  verified on receipt, not only when sending.
- TTL is decremented at every hop, excluded from authentication and from
  `msg_id`.
- Bounded deduplication of routed messages (anti-loop, anti-flood).

## Language

The project — code, comments, documentation, commit messages — is written in
**English**.
