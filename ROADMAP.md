# NMesh — roadmap

The order is non-negotiable: **security > solidity > flexibility > speed**,
with minimal dependencies. This file is a map of what is left, not a changelog;
what shipped is described in [`README.md`](README.md) and specified in
[`Docs/Architecture/`](Docs/Architecture/README.md), and the security register
is [`BUGSVULNS.MD`](BUGSVULNS.MD).

## Where the project stands

A node runs on TCP, UDP (with NAT hole punching), a keyed TCP medium (`veil`) and
a shared directory or file (`spool`), with post-quantum E2E encryption, a
self-rooted certificate PKI, Kademlia routing, multi-link operation, a web
console and control plane, a data connector, built-in chat, contacts, Fleet and
MCP apps, and two independent update routes (GitHub and signed releases over the
mesh itself). The suite is unit + integration + guided fuzzing on every change.

The tree is at `0.4.x`; the exact version is in [`src/version.py`](src/version.py).
It is the only place to read it.

## Open work

### Security and robustness

The audit register tracks nine findings open or partly open
([`BUGSVULNS.MD`](BUGSVULNS.MD)):

- Receive loops still await their sends (52) — the one that needs a per-link
  outbound queue rather than a spawn or a shorter bound.
- Every new link costs a ~360 kB catch-up burst each way (53).
- `test_spool_transport` lost one message, once, in CI (81).
- A liboqs built before the lock, or left in a cache, is reused unproven (93).
- liboqs 0.16.0 carries two advisories in code a node never calls; fixed for
  new builds, open for libraries already built (115).
- The container runs as root (116).
- Partly open: the E2E session table's persistence half (2), the release fetch
  reflection path (9), and the default DHT/session-store sizes (P20).

Separately, finding 121 leaves one remainder: a node's descriptor count is on
no page, so the next shortage is again found by its symptom.

### Scale

[`Docs/Architecture/scale.md`](Docs/Architecture/scale.md) is the audit of what
grows with the mesh. Still open there: gossip planes, distributed storage,
relaying and routed paths, post-quantum verification CPU, persistence, and the
console/app/metrics cost at size. Membership chains and probing budgets are the
two that have been fixed and measured; use them as the pattern.

### Reliability and features

- **Store-and-forward, one-way**: a drop mode with no interactive round trip, a
  persistent send queue per peer, and resuming after a cut.
- **Live audio and video** on the real-time stream: a device backend
  (`AudioSource`/`AudioSink`) on the app side, video over the same frames.
- **Chat web UI**: sending files, today only text and received files.
- **A trust score per node**, fed by what each app judges abusive — already
  bounded and decaying; the open part is turning app reports into a score the
  node can act on without letting one app decide.
- **Integration suite stability**: group the fixed-port tests by port (or
  serialise integration in CI) so a loaded machine stops producing failures
  that read as mesh bugs. `tests/test_integration_ports.py` is the guard; the
  grouping is the missing half.

### Releases

- **Sign GitHub releases too** (or drop that route once a node can always reach
  a trusted publisher on the mesh).
- **meshnet-daemon**: embed the library, listen on a socket, multi-client.

### Ideas, not commitments

[`Docs/Ideas/peer-integrity.md`](Docs/Ideas/peer-integrity.md) is a research
note on making a lying peer expensive and an inconsistency indelible, without a
hardware root. Nothing there is implemented; read its honest limits first.

## What we deliberately do not do

- No central server, store or directory. A store is a list, and a list is a
  thing to flood; finding is a question, not a catalogue.
- No new runtime dependency when the standard library can do the job.
- No feature that buys speed or convenience by weakening authentication,
  bounds or end-to-end encryption.
- No “verified peer” badge: the product shows what it observed, not a promise.
