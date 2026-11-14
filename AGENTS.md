# NMesh — engineering charter

NMesh is a decentralised, transport-agnostic mesh network that carries
sensitive data through a **hostile** environment. This file is the
non-negotiable contract for every contribution. It is short on purpose: the
mechanics live in [`Docs/Architecture/`](Docs/Architecture/README.md), the
commands in [`TEST.md`](TEST.md), and the traps in
[`Docs/Architecture/gotchas.md`](Docs/Architecture/gotchas.md).

## Working with several agents

This project is developed by a team of specialised agents. Parallelism is the
default, not a last resort.

- **Split before you start.** Decompose a task into independent workstreams and
  launch the matching agents from [`opencode.json`](opencode.json) together.
  Read-only exploration can always be parallel. Writes may be parallel only
  when no two agents touch the same file or directory.
- **Background everything.** Every subagent call and every shell command runs
  in the background. A short blocking command is the exception only when the
  next step literally needs its output, and then it must be bounded. Do not sit
  waiting on one result while another workstream could advance; collect results
  when they report. Never sleep or poll a background job.
- **One writer per file set.** Partition work by ownership
  (`src/transports/`, `src/control/`, `Docs/`, the seven locales…). The lead
  serialises shared files: `AGENTS.md`, `README.md`, `ROADMAP.md`, `TEST.md`,
  `BUGSVULNS.MD`, `Docs/Architecture/README.md`, `opencode.json`,
  `src/version.py`, `pyproject.toml`, the control-plane ledger and all seven
  `src/locales/*.json`.
- **`src/node.py` is shared ground.** An edit there needs the core owner and
  every affected domain; run the full suite, not only the focused files.
- **Integrate, then verify.** A subagent's report is a claim, not a result.
  The lead reads the diff, runs the tests, and owns the final tree.
- **Report outside your scope; do not fix it.** A cross-domain bug goes back
  to the lead with the reproduction. Reverting or rewriting another agent's
  work is never how a conflict is resolved.
- **One version bump per landed block.** Specialists do not touch
  `src/version.py`; the lead bumps it once when the block is complete.

## Architecture documentation — mandatory

`Docs/Architecture/` describes **how the code actually works**. It is not a
design wish: it is the map a change has to agree with.

- **Before any change or debugging session**, read the documents concerned.
  For a hang or a flaky test, start with
  [`gotchas.md`](Docs/Architecture/gotchas.md).
- **After any change to behaviour described there**, update the document in
  the same commit. Documentation that lies is worse than none.
- A new non-trivial mechanism gets an entry in the right document, and a link
  in [`Docs/Architecture/README.md`](Docs/Architecture/README.md).

## Threat model (the founding assumption)

> The moment data leaves the node, it enters **hostile territory**.
> We trust neither the network, nor the peers, nor the transport, nor — as far
> as possible — the local machine.

- Anything arriving from a peer is **presumed malicious** until validated.
- An authenticated peer may behave as an adversary. **Authentication is not
  trust, and joining a network is not being trusted.** Nothing is trusted by
  default; what trust exists is named, local and revocable — the anchors an
  operator pinned, the capabilities a human granted in Fleet, the witnesses
  they designated, the permissions a human granted an app.
- **Hearsay is never authority.** A node's opinion of another node travels and
  is weighed by whoever receives it — never obeyed. Only what we saw
  ourselves, or what a witness the operator named saw, is decisive.
- We defend against the device itself: sensitive keys in memory where
  possible, minimal attack surface, no secret in the clear on disk without a
  reason.
- We assume a state-resourced adversary who wants to break the network. The
  question on every line is: **what would they do with this?**

## The principles, in priority order

### 1. Security — never negotiable

- **Post-quantum** end to end: ML-KEM-768 (key exchange), ML-DSA-65
  (signatures), AES-256-GCM (authenticated encryption).
- **Reject by default.** A packet that is malformed, unauthorised,
  unauthenticated or of an unexpected type is dropped with no side effect. A
  valid input must prove its validity.
- Application data is E2E encrypted: relays see routing metadata only, never
  the content.
- A node's identity is the hash of its DSA public key. A `NodeID` that cannot
  be derived from the key presented is a lie: reject.
- Secrets are compared in constant time (`hmac.compare_digest`).

### 2. Solidity — the network never goes down

- **Zero crash. A crash is a security bug.** No input may kill a receive loop.
  If the unthinkable happens, the node repairs itself: purge the corrupted
  state, reconnect on demand, resume service.
- **Active peer rejection.** Noise is counted **per identity**, not per link,
  then the peer is cut off silently. A peer told it was detected changes
  identity and starts again.
- **Every app judges, the node decides.** An app sets its own thresholds and
  reports the sender; what the reports add up to belongs to the node, and an
  app never reads the standing back.
- **Bounds everywhere.** Every queue, cache, buffer and counter has a hard
  limit in [`src/mesh/constants.py`](src/mesh/constants.py).
- Works in degraded conditions: loss, enormous latency, partitions,
  store-and-forward.

### 3. Flexibility — transport-agnostic

- Anyone implements `BaseTransport` + `BaseServer` and registers it by URL
  scheme (`tcp://`, `ble://`, `lora://`, `usb://`…). The goal is to run over
  any medium that can carry bytes.
- **Every module of the core is medium-agnostic except two, and each exception
  is bounded and named.**
  - **UDP, for NAT traversal**, known to `src/node.py` alone. A hole is
    punched through a stateful datagram NAT by sending from the very socket
    the listener owns; there is no medium-agnostic spelling of that. What the
    punch path needs is declared on the contract — `BaseServer.bound_endpoint`,
    `holds`, `adopt`, `send_raw`, and `BaseTransport.scheme`, `is_closed`,
    `keepalive` — never read from a medium's privates. The capability list is
    [`src/transports/contract.py`](src/transports/contract.py).
  - **`RelayedTransport`**, defined by `src/mesh/peers.py`: a link that is not
    a socket but another node carrying frames. That is core routing wearing
    the transport interface, not a medium. `node.py` also names it to ask
    whether a link is relayed when counting physical links.
  A third would be something else entirely, so the list is checked:
  `tests/test_medium_agnostic.py` fails if a medium spreads to a module that
  did not own one, or if the punch path reaches into a medium.
- Whatever a medium answers is checked on the way back, never trusted for its
  annotated type ([`src/transports/medium.py`](src/transports/medium.py)).
- Routing is medium-agnostic. Nodes announce URLs; each uses the schemes it
  knows.

### 4. Speed — close to real time

- **The last measured figure is the one to beat**, not a number chosen in a
  planning document. A speed claim without the tool, the conditions and the
  date that produced it is not a result.
- **And measure it.** `node.speedtest` and `SPEED_PROBE`/`SPEED_ECHO` load one
  link and report what it carries; `tests/tools/mesh_sim.py` measures routing
  at scale and reports its own event-loop lateness. The link measurement is
  bounded, refused without a direct authenticated link, and negotiated under
  its own feature name.
- Optimise without ever losing security, solidity or flexibility. A gain that
  weakens one of the three is refused.
- Hot paths: no superfluous allocation, no needless copy, no redundant crypto.

## Supply chain

- **Minimal external dependencies.** Every dependency is an attack surface.
  By default: **the Python stdlib**.
- The runtime admits, strictly:
  - `liboqs-python` — post-quantum crypto (no stdlib equivalent).
  - `cryptography` — AES-GCM/HKDF.
  - Test-only: `pytest`, `pytest-asyncio`, `pytest-xdist`, `pytest-timeout`.
- Adding a runtime dependency means an explicit justification in the PR and an
  update to this list. When in doubt, reimplement on the stdlib.
- **What is fetched is proven, not named.** liboqs is built from the commit and
  archive digest in `scripts/liboqs.lock`; the wrapper never fetches it
  itself. The base image installs `docker/requirements.lock` under
  `--require-hashes`. A version bump moves the lock, its hashes and its digest
  together.
- **CI tools are dependencies too.** Actions are pinned by commit, tool images
  by digest, none gets the Docker socket, and an image this repository
  published is used only after its provenance attestation checks out.

## Contribution discipline

### Documentation follows the code

Documentation is updated in the **same commit** as the behaviour it describes.
A feature shipped without its documentation is incomplete, never “to be
documented later”. Before coding, read the documents concerned; after coding,
update every one the change touches.

### Every change is proved by tests

- A change is proved by tests, including hostile-input tests (fuzzing,
  malformed packets). “It works” is not enough; it has to hold up.
- We never merge with the suite red.
- Every parser of peer input gets a fuzz target in the same commit
  (`tests/fuzz/targets.py`).
- A test must be able to fail. Mutate the mechanism it names and watch it go
  red before trusting it.

### Language and interfaces

- The project — code, comments, documentation, commit messages — is written in
  **English**.
- Every interface string is a key in all seven `src/locales/*.json` catalogues,
  asked for with `t()`. A sentence in a page is the key's English fallback for
  the moment before `/i18n.js` answers (and for scripts off), held to the
  catalogue word for word by `tests/test_i18n.py` — never a second source. A
  new key goes into all seven files in the same commit, plural forms included.
- **No emoji in an interface.** Graphical interfaces use the shared SVG set
  (`icon()` in [`src/webassets/ui.py`](src/webassets/ui.py)); terminal output
  uses aligned words; documentation uses structure. The one exception is
  content that is an emoji: the chat reaction palette, and what a person types.

### Report every bug — always

- A bug found is a bug reported, every time: one outside the task, one you
  worked around, one you are not going to fix.
- Tell the person you work for, in the same turn, in plain words: what fails,
  how to reproduce it, how bad it is, and whether you fixed it.
- **Never with the live network's details.** Write “relay A”, “node C”, an
  address from 192.0.2.0/24, 198.51.100.0/24 or 203.0.113.0/24 — never a real
  address, node name, hostname, account or path.
  `tests/test_no_live_addresses.py` refuses a real IPv4 literal; names are on
  you.
- A fixed trap goes in [`Docs/Architecture/gotchas.md`](Docs/Architecture/gotchas.md);
  one still open goes in [`BUGSVULNS.MD`](BUGSVULNS.MD), with the reproduction.
- Never “flaky”, never “unrelated”, never silent without a root cause: those
  are the words a bug hides behind.

### Name the thing, then count the thing

Most bugs that reach a user are not hard: they are a name that lies.

- **The name carries the unit.** `link_count` and `node_count`, never `peers`.
  If a reader has to open the definition to know what a number counts, rename
  it.
- **Derive, do not re-derive.** One quantity has one producer.
- **Read the label out loud against the value.** A label and its value are one
  claim; the claim has to be true.
- **Ask who else uses this** before changing a field, a function or a row.
- Fix the cause, once, not the symptom at each place it is displayed.

### Version

Every finished piece of work bumps the patch version in the same commit: one
step per task, or per block of tasks landing together (`0.1.3` → `0.1.4`). The
patch number is not capped at nine (`0.1.99` → `0.1.100`). A minor bump
(`0.2.0`) is a deliberate act marking a body of work, never a rollover. Two
files carry it and a test holds them together:
[`src/version.py`](src/version.py) and `pyproject.toml`.

## Network invariants (quick reminders)

- The header is in the clear but **authenticated** as the GCM AAD; the payload
  is encrypted.
- `msg_id` binds the content and is verified on receipt, not only when sending.
  Its hash is negotiated per link and rewritten per hop; a receiver accepts
  either, and dedup keys on the node's own id of the content.
- TTL is decremented at every hop, excluded from authentication and from
  `msg_id`.
- Deduplication of routed messages is bounded (anti-loop, anti-flood).

## Cross-domain hazard rules

- **New top-level directory:** add it to `boot_guard.REPLACE_ENTRIES` or it
  will never ship to nodes updating themselves.
- **New transport:** one entry in `src/transports/registry.py:BUILT_IN`; old
  flat paths stay aliases; assert it arrives in `test_transport_registry.py`.
- **New control operation:** declare it in a `control/modules/` module with
  arguments, a ceiling and a travel scope; update the ledger table in
  `control-plane.md`; never add a raw `/api` route.
- **New locale key:** all seven files, matching `{params}`, CLDR plurals.
- **New UI:** no emoji, no inline style or external asset; the page's script
  must parse under `node --check`.
- **No new runtime dependency.** `tests/test_charter.py` enforces it.

## Where the knowledge lives

| Question | Read |
|---|---|
| How does the protocol / routing / security actually work? | [`Docs/Architecture/`](Docs/Architecture/README.md) |
| Something hangs, a test is flaky, a link flaps | [`Docs/Architecture/gotchas.md`](Docs/Architecture/gotchas.md) |
| How do I run the suite, fuzz, or measure? | [`TEST.md`](TEST.md) |
| What did agents get wrong before? | [`Docs/Contributing/agent-mistakes.md`](Docs/Contributing/agent-mistakes.md) |
| What is still open, security-wise? | [`BUGSVULNS.MD`](BUGSVULNS.MD) |
| What is shipped and what comes next? | [`ROADMAP.md`](ROADMAP.md) |
| How do I install, configure or deploy? | [`Docs/Setup/guide`](Docs/Setup/guide) |
| What are the actual failure messages? | [`FAQ.md`](FAQ.md) |
| What is the public documentation map? | [`Docs/README.md`](Docs/README.md) |
