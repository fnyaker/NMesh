# TODO — Integrity / health verification between peers (core & apps)

> **Status: a brainstorm, nothing is implemented.** This document lists leads
> for peers to reassure each other that the code they run has not been altered
> (a machine compromised by an adversary, a poisoned app, the supply chain). It
> does not describe how the code behaves today: it therefore has no place in
> `Docs/Architecture/`. Any mechanism chosen and implemented will have to be
> documented there, in the same commit as the code.

## The honest starting point

**Pure software attestation proves nothing against an adversary who owns the
machine.** If they control the process, they replay the "right" hash. That is
the *lying endpoint* problem, and it has no solution without a hardware root
(TPM / Secure Enclave).

The goal is therefore not "proving integrity" but:

1. **making lying expensive** — the attacker has to keep a pristine copy of the
   code, answer within a bounded time, and stay consistent in front of N
   verifiers;
2. **making inconsistency indelible** — signed proofs of fraud that anyone can
   verify offline;
3. **degrading a suspect peer** rather than deciding with a boolean.

The sections below run from "real value, cheap" to "expensive, decreasing
value".

---

## 1. Build attestation (static) — the base

- **`build_root`**: a Merkle tree over the core's source/bytecode files (exactly
  the mechanism of `app_package.build`: content-addressed chunking + a manifest).
  One root hash identifies "which code is running".
- **Announced at the handshake**: `build_root` + version carried in
  `HANDSHAKE`/`HANDSHAKE_ACK`, and therefore **signed** by the ML-DSA identity.
  Free, no extra round trip.
- **A signed release of the core**: reuse `build_release` / `app_catalog`'s
  anti-rollback for the core itself. A `build_root` not covered by a signed
  release from a known author = unknown code → an "unattested" peer.
- **A version floor**: refusing (or degrading) peers below a signed minimum
  version → kills the downgrade attack towards a known bug.
- **Statistical consensus**: gossip the `(build_root, version)` pairs observed.
  A `build_root` unique in the whole mesh is a strong signal (either a developer
  or a patched node). Never ban on that — feed a score.

## 2. Challenge/response resistant to precomputation

- **A nonce'd Merkle-path challenge**: "give me `H(nonce ‖ chunk[i])` + the
  Merkle path to `build_root`", with `i` drawn at random. A tiny answer, an
  O(log n) verification. The attacker has to keep **a complete intact copy** of
  the code, permanently.
- **A nonce + a random range**: never the same question twice → no cache of
  answers.
- **Attest memory, not disk**: hash the bytecode actually loaded (`co_code` of
  the imported modules), not the files. A live patch never touches the disk.
- **Instrumentation detection**: audit hooks, `sys.settrace`, an abnormal
  `sys.path`, monkey-patched functions (a fingerprint of `__code__` compared
  against the manifest), modules imported off the list. These are **signals**,
  not proofs.
- **Timed attestation** (SWATT-like: a pseudo-random walk over the code with a
  strict deadline): to be treated as theatre in pure Python — the gap the
  attacker introduces drowns in GC and network noise. To be kept for a possible
  native shim, or it is complexity for nothing.

## 3. *Behavioural* attestation — the most effective layer in practice

It fits the charter: "authentication is not trust". We test what the peer
**does**, not what it **says**.

- **Trap probes (negative)**: send packets a correct implementation **must drop
  silently** — an inconsistent `msg_id`, an exhausted TTL, an unexpected type, an
  expired certificate, an unknown app section. A modified node (a relay that
  logs, a proxy that rewrites) reacts where it should stay quiet. The attacker
  cannot tell a trap from a genuinely corrupt packet.
- **Signed E2E receipts**: the destination signs the `H(ciphertext)` it
  received. The source detects a relay that alters, selectively drops or
  duplicates — without ever trusting it.
- **A health scorecard**: generalise the existing invalid-frame counter into a
  vector (invalid rate, deduplication violations, a tampered TTL, routing lies,
  latency outside its profile, refusing attestation, a `build_root` that changes
  without a restart).
- **A timing profile**: a baseline RTT / response time per peer; an
  interposition layer drifts. A weak signal → a score only, never a decision on
  its own.

## 4. Distributed verification & proofs of fraud

- **Multiple verifiers**: several peers challenge independently and compare the
  answers through the DHT/gossip. An attacker can no longer lie "made to
  measure" to a single verifier.
- **Gossip only verifiable proofs, never accusations.** A bare accusation is a
  Sybil DoS weapon. On the other hand, **two contradictory signed statements from
  the same key** (two `build_root`s for the same epoch, two uses of the same
  epoch counter, two incompatible certificates) form a **self-contained proof of
  fraud**: anyone verifies it offline, so it is safe to propagate and archive.
- **Identity-clone detection**: a signed monotonic epoch counter. Two uses of
  the same counter = a duplicated key = a proof of fraud → a network alert and
  revocation.
- **Quarantine by local quorum** (the k-bucket), never on a single accuser.

## 5. A chained log + witnesses (the best value/complexity ratio)

- A local **append-only, hash-chained** log (integrity state, restarts,
  versions, anomalies). Rewriting history requires recomputing the chain.
- **Cross-witnessing**: periodically publish `sign(epoch, chain_head,
  build_root)` into the DHT; peers keep the heads they have seen. An attacker
  who rewrites the past **contradicts witnesses** → detection *after the fact*,
  even if they were undetectable at the time. The same logic as transparency
  logs, and it works without a TPM.
- **An integrity lease**: a successful attestation is worth N minutes. An
  expired lease → the peer automatically falls back to "unattested". No
  permanent state of trust.

## 6. The apps side

The foundation is already there: `app_package` (content-addressed packages + a
signed release binding `app_id` to the ML-DSA author) and `app_catalog`
(anti-rollback).

- **Attestation at the app-section level**: each app declares
  `(app_id, version, package_root)`. A peer refuses traffic from a section whose
  root does not match a signed release known to the catalogue.
- **A per-app Merkle challenge**, in the app channel: the same mechanics as §2,
  but over the package — and over the modules loaded in memory, not only the
  package at rest.
- **A signed capability manifest**: the release declares what the app is allowed
  to do (paths, storage, network, transports). The runtime observes; anything
  beyond is a violation attributable to a precise signed version.
- **Drawer integrity** (`app_storage`): a Merkle root or a MAC chain + an
  anti-rollback counter in the encrypted header → it detects the restoration of
  an old state, not only tampering.
- **A signed revocation** of a compromised version by its author, gossiped with
  the existing anti-rollback → nodes refuse or uninstall it.
- **N-version cross-validation**: two nodes on the same app version compare a
  deterministic canary computation. A divergence = one of the two is modified.
- **Isolation**: the more an app is isolated (a separate process, see
  `process_launcher`), the more its attestation means; a compromised core lies
  for every app it hosts.

## 7. A graduated reaction (never binary)

Levels, with an automatic way back after a successful re-attestation:

| Level | Effect |
|---|---|
| Attested | everything allowed |
| Unattested | no certificate issued, no app installed from it |
| Suspect | no more relaying of sensitive traffic, no more route sharing |
| Quarantined | the link kept, data refused |
| Rejected | disconnection (the existing peer-rejection mechanism) |

Locally, on a self-check failure: **panic mode** — wipe the session keys, stop
relaying, send a signed alert to the contacts. A node that goes quiet is better
than a node that leaks.

## 8. Traps not to create

- **Amplification**: a short challenge must never produce a long answer. A
  capped answer, a budget per peer, a rate limit — or attestation becomes a DoS
  vector itself.
- **A read oracle**: never allow hashing an arbitrary file; only the chunks of
  the signed manifest. Otherwise we are offering a remote disk reader.
- **Banning on accusation**: see §4 — local observations and proofs of fraud
  only.
- **False assurance**: never display "peer verified ✅", but "known code,
  attested 40 s ago" — that is, the real information.
- **Network fingerprinting**: a `build_root` in the clear at the handshake tells
  an observer who runs what. To be considered under link encryption, or as a
  commitment revealed only after authentication.

## 9. A proposed build order

1. A signed `build_root` + version at the handshake, a version floor, display in
   the console. *(little code, immediate value against a careless peer and the
   supply chain)*
2. Verifying apps' `package_root` against the signed catalogue + revocation.
3. A health scorecard + trap probes + signed E2E receipts.
4. A chained log + witnessed heads in the DHT.
5. Nonce'd Merkle challenges (the core, then apps).
6. Multiple verifiers, proofs of fraud, quarantine by quorum.
7. Timed attestation / a hardware root — only if a native shim ever enters the
   project.

Points 1→4 cover most of what is achievable; 5→6 raise the cost for the
attacker; 7 is the only one that would aim at a real proof, and it falls outside
the stdlib-only perimeter set by `CLAUDE.md`.
