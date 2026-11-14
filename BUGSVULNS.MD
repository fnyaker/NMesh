# BUGSVULNS — open findings and audit index

> This file is the **living register**: what is still open, and an index of
> every finding ever recorded. The full audit — each entry's context, reach,
> reproduction and the invariant a fix must not break — is archived in
> [`Docs/History/audit-execution-flow.md`](Docs/History/audit-execution-flow.md).
> Code comments cite findings by number (`BUGSVULNS 73`); the index below is
> the map. A closed finding is closed because its Status line in the archive
> says so, with the tests that hold it.

Severity is what an adversary gains, in the threat model of `AGENTS.md`:
the network, peers and transports are hostile, and an authenticated peer
may still be an adversary.

## Open findings

- **2 — high — `_e2e_sessions` is unbounded, and each new entry re-writes the store** — partly fixed
- **9 — high — `RELEASE_FETCH` blocks the receive loop and reflects 48 KB to an unverified id** — partly fixed
- **52 — medium — Receive loops still await their sends (open)** — open
- **53 — low — Every new link costs a ~360 kB catch-up burst each way (open)** — open
- **81 — low — `test_spool_transport::test_bidirectional_over_directory` lost one message, once** — open
- **93 — medium — A liboqs built before the lock, or left in a cache, is reused unproven** — open
- **115 — medium — liboqs 0.16.0 carries two advisories, in code a node never calls** — fixed for new builds; open for libraries already built
- **116 — low — The container runs as root** — open
- **P20 — 128 MiB of DHT and 16 MiB of session store are large defaults** — partly fixed

9 of 141 findings are open or partly open.

## Open findings in full

The body of each entry is the audit text, written against the tree *before* its
fix; its **Status** line is the current statement. Read the status first, then
the invariant and reproduction.

## 2 — high — `_e2e_sessions` is unbounded, and each new entry re-writes the store

> **Status — partly fixed.** `_keep_e2e_session` bounds the table
> (`_MAX_E2E_SESSIONS`, LRU, never evicting a target with data queued) and
> `_forget_e2e` drops all four tables together. The persistence half — the
> synchronous fsync per handshake — is **P8**, in the receive-loop pass.

**Where** — `src/node.py`, `MeshNode._handle_e2e_handshake` /
`_handle_e2e_handshake_ack` / `_handle_data`, and `MeshNode._persist_state`.

**Reach** — `_handle_packet` → `_ROUTABLE_TYPES` gate (needs *a* live
authenticated link, not that `src_id` is that link) → `_handle_e2e_handshake`.

**What happens** — `self._e2e_sessions: dict[NodeID, SessionKey]` has no
ceiling and no expiry. `_handle_e2e_handshake` writes one entry per distinct
`src_id` that presents a chain to a root. `src_id` is *not* the authenticated
peer — it is whatever the packet claims, checked only against the DSA key
inside the payload (`NodeID.from_public_key(dsa_pub) != src`), so an adversary
generates a fresh key pair per handshake and gets a fresh entry every time.
`_e2e_pending_kem`, `_e2e_pending_nonce` and `_e2e_attempt` are equally
unbounded (see **36**). `_e2e_pending_data` is the one table that *is* bounded, by
`send_data`.

Every one of those handshakes also calls `_persist_state()`, which is
`SessionStore.save(...)` — a synchronous serialise-encrypt-write of the
*entire* session table plus `self._routing.export_entries()`, on the event
loop. Cost per handshake is therefore O(number of sessions), so N handshakes
cost O(N²) of blocking disk I/O.

**Impact** — memory exhaustion plus a self-amplifying event-loop stall. It also
degrades before it exhausts: once the store is a few megabytes, every E2E
handshake freezes the loop for the duration of a full encrypt-and-write.

Note the asymmetry with the code right beside it: `_e2e_rekey` *is* bounded
(`_E2E_REKEY_MAX`, `_E2E_REKEY_TTL`) precisely because the comment there
reasons about "a flood of valid-but-useless handshakes". The primary table has
the same exposure and none of the bound.

**Fixing it without breaking something** — bound `_e2e_sessions` (LRU with a
ceiling, and an idle TTL), and evict the companion tables with it —
`_MAX_PENDING_TARGETS` already exists and already governs
`_e2e_pending_data`; the other three ignore it (**36**). Two traps:

- eviction must not be able to drop a session that has data queued for it, or
  `_e2e_retry_loop` will re-handshake in a loop; evict by last use and skip
  targets present in `_e2e_pending_data`.
- do **not** make `_persist_state` async-with-await inside the handlers: they
  run in a receive loop (see gotcha §10). The right shape is to mark the state
  dirty and let one bounded background task write at most every N seconds —
  `_release_loop` is the pattern already in the file.

---


---

## 9 — high — `RELEASE_FETCH` blocks the receive loop and reflects 48 KB to an unverified id

> **Status — partly fixed.** `blocking=False`, as every sibling handler does,
> so the link no longer freezes. The reflection half is in the rate-limit pass.

**Where** — `src/node.py`, `MeshNode._handle_release_fetch`.

**Reach** — `_handle_packet` → `_ROUTABLE_TYPES` → `_handle_release_fetch`
(any authenticated peer; `src_id` inside the packet is *not* authenticated).

**What happens** — two defects in the same three lines:

```python
await self._route_outbound(Packet.create(
    RELEASE_DATA, self._id.raw, packet.src_id,
    payload[:_RELEASE_ID_LEN] + offset.to_bytes(4, "big") + slice_))
```

- `_route_outbound` is called **without `blocking=False`**. Every other handler
  in the file passes it (`_handle_find_node`, `_handle_find_value`,
  `_handle_dir_find`, `_handle_e2e_handshake`, `_handle_echo_request`) with the
  comment "never inline, we are in a receive loop". Here it is missing, so when
  no route exists the handler awaits `_ensure_route_to` — a Kademlia lookup plus
  a dial plus a hole punch, up to `_ON_DEMAND_TIMEOUT` — inside `_Peer._loop`.
  This is precisely the failure documented in `gotchas.md` §10 (measured there
  at 4.95 s of frozen link per unroutable packet).
- the reply is addressed to `packet.src_id`, which no gate verifies, and
  carries `_RELEASE_SLICE = 48 KiB`. The request is 79 + 24 = 103 bytes.

**Impact** — a ~475× reflection amplifier aimed at any node id the attacker
names, rate-limited only by `_RELEASE_SERVE_MAX = 64` per 10 s **per ingress
link** (≈ 307 kB/s per link, and an attacker may hold many links); and, with a
src_id that has no route, a permanent freeze of the attacker-chosen ingress
link — 64 requests × up to 5 s each, in a 10 s window.

**Fixing it without breaking something** — pass `blocking=False`, as the sibling
handlers do. Keep serving to `packet.src_id`: a release fetch legitimately
arrives from a node several hops away, and the reply has to route back (that is
why `RELEASE_FETCH`/`RELEASE_DATA` are in `_ROUTABLE_TYPES`). To close the
reflection, prefer answering back down the link the request arrived on (the
`_route_hints` reverse path already records it) and, failing that, drop rather
than acquire a route for a stranger's slice.

---


---

## 52 — medium — Receive loops still await their sends (open)

> **Status — open.** Recorded, not fixed. The link is no longer dropped for it
> (**50**), and a stall of a second or more is now written to the log
> (`a handler held the receive loop`, `_SLOW_HANDLER`), so it can be seen.

**Where** — `src/node.py`: `_handle_ping` (the `PONG`), `_forward_packet` →
`_send_to_candidates`, `_handle_find_node`, `_handle_speed_probe`, and every
handler that answers inline.

**Reach** — a packet arriving on link A whose handling sends on link B, while B
is full.

**What happens** — the handler awaits the send, up to `_SEND_WAIT`, and link A's
receive loop reads nothing meanwhile — its own probes go unanswered, so to A's
far end this is loss.

**Reproduce** — two links, B's medium blocking on `send`; inject on A a packet
routed through B followed by a `PING`; the `PONG` leaves `_SEND_WAIT` later.

**Fixing it without breaking something** — a forward could be spawned
(`_spawn_bounded`) or sent with a short bound, but spawning loses the ordering a
link gives its packets and a short bound drops traffic a slower path would have
carried. A per-link outbound queue with its own task is the shape that keeps
both, and it is a design change to every send path.

---


---

## 53 — low — Every new link costs a ~360 kB catch-up burst each way (open)

> **Status — open.** Recorded, not fixed.

**Where** — `src/node.py`, what a link is owed when it authenticates (the
capability record and the catch-up syncs: release, pseudo and package
announces).

**What happens** — the field trace shows each new link sending 26
`RELEASE_ANNOUNCE` (~10.8 kB each), 8 `PSEUDO_ANNOUNCE` (~5.4 kB) and 5
`PKG_ANNOUNCE` (5.4–10.7 kB) in the first 50 ms, both ways: roughly 360 kB per
direction before the link has carried anything it was opened for.

**Impact** — on a link that flaps, the reconnect cost dominates what the link
carries, and the burst arrives exactly when the link is being judged: a fresh
UDP link starts with a 64 kB window. Receivers rate-limit releases at 32 per
10 s, so a node holding more than that drops the rest and the sender re-sends
them next time.

**Fixing it without breaking something** — announce a digest (ids and versions)
and let the far end pull what it lacks, instead of pushing everything. That is a
new message on a plane every build speaks, so it needs the capability
negotiation (`features.py`); a node that has not announced it must keep getting
the push.


# Verified by running it

Three of the findings were not only read but executed, on this tree, with a
test-only stand-in for `liboqs` (the machine had no build of it). The stand-in
replaces ML-DSA with deterministic HMACs whose verification is exact — a
tampered signature or a wrong key fails — which is all the node's *logic*
depends on. Nothing about the post-quantum primitives themselves is being
claimed here; what is claimed is the control flow around them.

## Finding 1 — the victim adopts the attacker's root

The victim dials out holding no invite code (`peer.join_code is None`, the
ordinary reconnect / routing-walk path). The attacker challenges as any
accepting server does, reads the victim's public key out of its `HANDSHAKE`,
forges an `issued_cert` naming the victim as subject, and answers with its own
self-signed certificate as the chain.

```
victim trusts attacker root before: False
victim trusts attacker root after : True
link authenticated as             : NodeID(c4338863…)
stranger's minted chain verifies  : True (anchor NodeID(c4338863…) )
```

The last line is the consequence: with that root in place, a certificate the
attacker mints for a **brand-new identity it has just generated** passes
`CertStore.verify_chain` on the victim. The invitation gate is gone for every
identity the attacker cares to create.

## Finding 27 — a one-byte file buffers gigabytes

The offer declares `size = 1` and `total = _MAX_CHUNKS`, then sends chunks far
larger than the sender would ever produce:

```
FILE_CHUNK_SIZE the sender uses : 48000
_MAX_CHUNKS the receiver allows : 262144
chunks a legitimate 256 MiB file needs: 5593
transfer accepted               : True
declared file size              : 1 bytes
buffered after 200 chunks       : 11800000 bytes
projected at the declared total : 15.5 GB
```

11.8 MB held for a declared one-byte file after 200 packets, and the ceiling the
code actually enforces is 15.5 GB — per transfer, with 64 concurrent transfers
allowed.

## Finding 5 — 128 datagrams close the UDP door for good

128 distinct source addresses each send one keepalive frame; every transport is
then marked closed (the peers went away); a new peer arrives, and one of the old
peers reconnects from its original address:

```
transports held        : 128
all closed             : True
new peer accepted      : False
dead transport replaced: False
remove_transport called anywhere in src/: src/udp_transport.py:691:    def remove_transport(...)
```

Neither the new peer nor the returning one can be served, and the only mention
of `remove_transport` in the whole tree is its own definition.

## Reproducing them

The three scripts are short enough to belong in `tests/` once the fixes land, as
the regression tests for each finding. They need only the existing
`tests/conftest.py` helpers (`FakeTransport`, `make_manager`) plus, for finding
27, nothing at all beyond `src.apps.chat`. Sketches:

- **1** — `MeshNode._inject_peer(FakeTransport())`, inject a `CHALLENGE`, read
  the `HANDSHAKE` back out of `fake.sent`, `_decode_handshake` it, build the
  ACK with `_encode_handshake_ack(ct, attacker_pub, [attacker_root],
  forged_cert, sig)`, inject it, then assert
  `victim._cert_store.is_root(attacker_id) is False`.
- **27** — `ChatApp(_NullClient())`, call `_on_offer` with `size=1,
  total=_MAX_CHUNKS`, then `_on_chunk` with oversized bodies, and assert the sum
  of buffered chunk lengths never exceeds the declared `size`.
- **5** — a `UDPServer` with a stub socket, 128 `_dispatch_datagram` calls from
  distinct addresses, close them all, then assert a new address is still
  accepted.


# Suggested order of work

> **This is what was followed.** The order below was written before any fix
> landed; the commits match it, with the additions noted in *Where this
> stands*. It is kept here because the reasoning — "what does fixing this
> unlock" — is what made the sequence work.

Not a priority ranking by severity alone — by "what does fixing this unlock".

1. **Finding 1** on its own, first. It is the only one that breaks the trust
   model outright, and the fix is small and local (carry "we presented a code"
   forward on the `_Peer`). It wants its own commit and its own test.
2. **The bounds pass**: **27**, **6**, **7**, **2**, **36**, **43**. These are
   one idea applied six times, they are independently testable, and several of
   them are what make the other DoS levers actually dangerous.
3. **The ordering pass**: **3**, **33**, **34**. Three call sites, each a
   two-line move, each restoring a property the surrounding comment already
   claims.
4. **The receive-loop pass**: **9**, **14**, **16**, **P17**, then **P8** and
   **P9**. All of them are the same rule from `gotchas.md` §10, and fixing them
   together keeps the rule visible.
5. **The rate-limit pass**: **10**, **20**, **28**, **42**, **44**, plus keying
   the tables on identity rather than `id(peer)` (**15**). `_gossip_allowed` is
   already the one implementation to extend.
6. **The fleet pass**: **30** and **31** together — both are "a string from the
   network decides where a credential goes".
7. **Then the hot path**: **P1**, **P2**, **P3**, **P6**, **P7**, **P14**. These
   are pure wins with no behaviour change, and **P2**/**P3**/**P6** also cut the
   cost of the query-plane DoS levers by a large factor.

Each of these touches behaviour described in `Docs/Architecture/`. Per
`AGENTS.md`, the document changes in the same commit as the code — in
particular `protocol.md`'s gate order (for **3**), `security.md`'s invitation
lockout (for **32**) and its handshake section (for **1**), `transports.md` for
the UDP findings, and a new `gotchas.md` entry for anything that turns out to
have been load-bearing.

---


---

## 81 — low — `test_spool_transport::test_bidirectional_over_directory` lost one message, once

> **Status — open.** Seen twice in CI: run 37657786505 (PR #111), on a commit
> that touched only the MCP bridge, and run 38392590031 (PR #127), on one that
> touched only the fuzzer, a release parser and the punch codec. Both times
> the same direction was lost, the second message of the pair, after 25 s.

**What happens** — after both sessions came up, `host` received `g2h` and
`guest` never received `h2g` within 25 s.

**Tried, without reproducing it** — 8 serial runs; 12 runs beside 14 busy CPU
loops; 96 runs, 24 at a time; the whole integration suite under `-n auto` ten
times; 45 runs of the scenario with every spool write delayed by a random
0–150 ms. All passed.

**Noticed on the way, not shown to matter** — `SpoolTransport.send` writes each
record from its own `asyncio.to_thread` call, so two sends in flight on one link
can reach the file in either order. A link is expected to keep order (TCP and
the UDP layer do). The delayed-write runs above reorder records and still lost
nothing — the E2E retry recovers — so this is not offered as the cause.


---

## 93 — medium — A liboqs built before the lock, or left in a cache, is reused unproven

> **Status — open.**

**Where** — `start.sh`: `adopt_liboqs`, `liboqs_candidates`, `cache_liboqs`.

**What happens** — a node that already has a working liboqs keeps it: the
check is functional (the wrapper loads it, both algorithms answer), so a
library built from an unchecked source before 92 was fixed stays in use, and
so does one copied from a cache or a prefix another install left — including
`~/.cache/nmesh`, which the account running the installer can write and a later
system install may adopt.

**What it would take** — a stamp next to each build naming the lock it was
built from (commit and digest), written only by `build_liboqs.sh`, and refusal to
adopt anything without the current one; existing nodes would then rebuild once,
which on a small machine is minutes of downtime at the next start, so when that
happens is a decision.


---

## 115 — medium — liboqs 0.16.0 carries two advisories, in code a node never calls

> **Status — fixed for new builds; open for libraries already built.** Tests:
> `tests/test_liboqs_lock.py` (`TestWhatIsCompiled`),
> `tests/test_liboqs_advisories.py`.

**Where** — `scripts/build_liboqs.sh`, `scripts/liboqs.lock`.

**What happens** — GHSA-wh5q-mpc8-67wf (an out-of-bounds read in LMS/HSS
verification) and GHSA-xv6c-h66p-6mfq (LM-OTS key reuse and further memory
errors in LMS signing) affect liboqs 0.11.0 to 0.16.0, built with
`OQS_ENABLE_SIG_STFL_LMS` — and the build turned on LMS, XMSS and
`OQS_HAZARDOUS_EXPERIMENTAL_ENABLE_SIG_STFL_KEY_SIG_GEN`, on the belief that the
wrapper would not load without them. No node calls a stateful signature, so the
code was linked and unreachable. Nothing reported it either: liboqs is compiled
from source, so it is in no package index, and none of Dependabot, pip-audit or
Trivy can see it. The fix is in 0.17.0, not released when this was written.

**Fixed** — the wrapper loads without them (0.16.0 compiles the stateful
signature API with no scheme behind it), so the build now compiles only
ML-KEM-768 and ML-DSA-65 (`OQS_MINIMAL_BUILD`), with LMS, XMSS and the hazardous
signing off by name: 26 MB of library becomes 600 KB, and the unit suite passes
on it. `audit.yml` now reads liboqs's advisories against the lock every week;
these two are listed in `scripts/liboqs.accepted` with that reason.

**Still open** — a library a host built before this change (`start.sh` reuses
one whose stamp matches the lock) keeps its LMS code until the lock moves; it
stays unreachable from a node. Moving the lock to 0.17.0 rebuilds it, and the
audit will then report both exceptions as stale.


---

## 116 — low — The container runs as root

> **Status — open.**

**Where** — `docker/Dockerfile`, `docker/entrypoint.sh`.

**What happens** — no `USER` is set, so the node, and any shell the fleet app
opens, run as root inside the container. That is not root on the host under
Docker's defaults, but it is one kernel bug or one careless mount (the Docker
socket, which the fleet app can use) away from it, where an unprivileged user
would also need a privilege escalation. A host install already runs as its own
account (`install.sh`).

**Why it is not one line** — three things a deployment relies on assume root:
the `/data` volume of every existing node is owned by root; the documented key
mount is `/root/.ssh`, and a key kept `0600` by the host's user cannot be read
by another account in the container; and the fleet app's Docker management talks to a
mounted socket owned by the host's `docker` group. Dropping privileges in the
entrypoint (take ownership of `/data`, then `setpriv` to an `nmesh` account
with the socket's group) has to move all three without breaking a node that
updates. Trivy's rule DS-0002 is set aside in `.trivyignore` until it does.


---

## P20 — 128 MiB of DHT and 16 MiB of session store are large defaults

**Status — partly fixed.** The DHT default is 32 MiB and settable (`dht_max_mb`, 1–4096). The session store and the drawer ceilings are unchanged.


**Where** — `src/dht.py` (`_MAX_BYTES = 128 * 1024 * 1024`),
`src/session_store.py` (`_MAX_FILE = 16 MiB`), `src/app_storage.py`
(`MAX_DRAWER_BYTES = 8 MiB × MAX_DRAWERS = 256` → 2 GiB of drawers).

These are bounds, so nothing is unbounded — but they are bounds sized for a
server, in a project whose stated goal is to run over BLE, LoRa and a USB stick.
The DHT ceiling in particular is filled entirely by peers (see **20**).

**Fix** — make them configurable (`config.py` already has the shape for it) and
default them far lower; a node that wants to be a big cache can say so.

---

# What was checked and found sound

Recording this matters as much as the findings: it says where an attacker's
effort is wasted, and it stops a later change from quietly removing a property
nobody knew was load-bearing.

- **`Packet` framing and `msg_id`.** Fixed-width fields, so the `msg_id`
  pre-image is unambiguous; TTL is correctly outside both the AAD and the id;
  `with_decremented_ttl` is only reachable behind a `ttl > 1` test.
- **Content addressing in the DHT.** `ContentStore.put` refusing
  `content_key(value) != key` closes the poisoning vector by construction, and
  `dht_get` re-checks the hash before caching. `app_dht` frames the app id into
  the hashed value, so a namespace cannot be crossed even with a known key.
- **The pseudo claim format.** The node id is derived from the key inside the
  claim and the signature is checked under that same key, so a claim can only
  ever name its author. Canonicalisation is checked *before* the signature, so a
  hostile name costs no verification. Timestamps are strictly increasing per id.
- **`app_auth`'s signing-domain separation.** Nothing signs app-supplied bytes;
  free-form context enters only as a 32-byte hash; `app_id` comes from the
  session, never the frame. (The one defect is the nonce ordering — **33**.)
- **The release install gates.** Pinned publisher, strictly newer version, and
  the package checked against the signed SHA-256 in `ReleaseStore.put` before
  `open_package` is even called. `open_package` refuses links, devices and
  unusable paths rather than sanitising them, and bounds the unpacked size while
  reading rather than after.
- **`updater.safe_relative` and `_refuse_unsafe_members`.** Absolute paths,
  `..`, NUL and links out of the tree are refused, not trimmed; the `data`
  filter is used where available and the pre-check makes the fallback safe.
- **Fleet's three gates.** `_open_signed` binds the assertion to the exact body
  bytes and to a per-message-kind purpose, and requires `principal.node_id ==
  src`; replies are matched against `_inflight` with a sender check; shell input
  is session-bound to the owner. `ENROL_NARROW` intersects rather than widens.
- **Subprocess use.** Everything goes through `create_subprocess_exec` with an
  argv list — there is no shell string anywhere in the tree. (The defect is argv
  *parsing*, not quoting — **30**.)
- **`fleet_console`'s loopback pin.** The certificate fingerprint is compared on
  the live socket *before* the request is sent, so the caller's token never
  reaches an impostor; `console_path_refusal` is applied on both the proxy side
  and the agent side, and the console's own routing matches the same prefixes,
  so there is no `/api/fleet` vs `/api/fleet/` gap.
- **`config.py`.** Bounded in bytes, lines, value length and list length, with
  per-setting coercion and no way for a value to become a path outside what the
  setting means.
- **The console's session handling.** `HttpOnly` + `SameSite=Strict` + `Secure`
  removes the CSRF surface; tokens are 32 random bytes with a sliding idle TTL
  under a lock; a password change revokes every other session but keeps the
  caller's.
- **HTML escaping in the pages.** `esc()` is a correct escaper and is applied
  consistently — `linkify` escapes *before* linkifying, and the URL pattern
  cannot re-introduce a raw delimiter. The one gap is **35**.

---

# Addendum — findings 41 to 45

These came out of the last pass over the app store, the relay tunnel and the
fleet ledger. They are listed after the performance section only because that is
the order they were found in; severity is stated per entry as above.


---

## Index of every finding

| # | Severity | Finding | Status |
|---|---|---|---|
| 1 | critical | A dialled peer can install itself as a trust root | fixed |
| 2 | high | `_e2e_sessions` is unbounded, and each new entry re-writes the store | partly fixed |
| 3 | high | Pre-auth packets poison the replay-dedup cache before any rate limit | fixed |
| 4 | high | Unauthenticated links hold every peer slot for ever | fixed |
| 5 | high | `UDPServer._transports` is never pruned | fixed |
| 6 | high | UDP decode queue unbounded; reorder buffer bounded in frames, not bytes | fixed |
| 7 | high | `MeshNode._data_queue` is unbounded | fixed |
| 8 | high | `CertStore` is unbounded and re-writes its whole file per certificate | fixed |
| 9 | high | `RELEASE_FETCH` blocks the receive loop and reflects 48 KB to an unverified id | partly fixed |
| 10 | high | `DIR_FIND` has no rate limit and reflects up to 56 KB | fixed |
| 11 | high | A stranger's pseudo claim is re-gossiped to every peer | fixed |
| 12 | medium | A corrupt identity file is silently replaced, then overwritten | fixed |
| 13 | medium | The UDP reliability layer is unauthenticated | mitigated, not closed |
| 14 | medium | `_handle_reach_probe` dials back inside the receive loop | fixed |
| 15 | medium | Rate-limit tables are keyed by `id(peer)` | fixed |
| 16 | medium | A failed forward tears the target peer down inside the ingress loop | fixed |
| 17 | medium | Pre-auth `HANDSHAKE` may be retried without limit on one connection | fixed |
| 18 | medium | `RELAY_CARRY` / `INVITE_SEEK` give an unauthenticated peer a mesh injector | mitigated |
| 19 | medium | One peer's word sets `_inbound_schemes` | fixed |
| 20 | medium | `_handle_store` has no rate limit, and 128 MiB of LRU is an eviction lever | fixed |
| 21 | medium | `RELEASE_DATA` slices are accepted from anyone | fixed |
| 22 | low | `_decode_chain` does not bound the certificate count | fixed |
| 23 | low | `RoutingTable._bucket_index(own_id)` indexes bucket `-1` | fixed |
| 24 | low | `SpoolServer` has no peer cap and an unbounded `_seen` set | fixed |
| 25 | low | `_note_release_source` bounds the outer table with the inner constant | fixed |
| 26 | low | `PseudoBook.offer` drains a bucket with an unbounded `while` | fixed |
| 27 | critical | A chat file transfer can buffer gigabytes per peer | fixed |
| 28 | high | Raw UDP punch probes buy an ML-DSA verify *and* a signature, unmetered | fixed |
| 29 | high | Any datagram with the STUN magic cookie rewrites our public address | fixed |
| 30 | high | Argument injection into `ssh` from a fleet provisioning request | fixed |
| 31 | medium | Scan results choose where the operator's SSH password goes | fixed |
| 32 | medium | The invitation lockout is per connection, not per node | fixed |
| 33 | medium | `verify_assertion` burns the anti-replay nonce before checking the signature | fixed |
| 34 | medium | The console reads an unauthenticated body of up to 64 MiB | fixed |
| 35 | medium | HTML injection into the node view from a remote console | fixed |
| 36 | medium | `_e2e_pending_kem` / `_e2e_pending_nonce` / `_e2e_attempt` are unbounded | fixed |
| 37 | medium | `DataConnector` counts only authenticated clients | fixed |
| 38 | low | A corrupt console credential silently resets the password | fixed |
| 39 | low | `_build_ssl_context` can pair a stale certificate with a fresh key | fixed |
| 40 | low | A signed app release can declare a million chunks | fixed |
| 41 | high | The app-store catalogue can be filled and held for ever | fixed |
| 42 | medium | Enrolment requests are unmetered and can fill the pending table | fixed |
| 43 | medium | `RelayedTransport`'s inbox is unbounded and its `receive` uses `wait_for` | fixed |
| 44 | low | `PUNCH_REQUEST` is unmetered and sends two packets per request | fixed |
| 45 | low | Fire-and-forget tasks that are neither tracked nor bounded | fixed |
| 46 | high | `DataConnector.stop()` deadlocks on Python 3.12+ while an app is attached | fixed |
| 47 | medium | liboqs contexts are never freed, and one of them is per handshake | fixed |
| 48 | low | Two test classes shared a name, and five permission tests stopped running | fixed |
| 49 | medium | A UDP FIN refreshed the link it closed | fixed |
| 50 | medium | A full send queue was read as a dead link | fixed |
| 51 | high | A peer that stops reading its TCP socket froze the keepalive loop | fixed |
| 52 | medium | Receive loops still await their sends (open) | open |
| 53 | low | Every new link costs a ~360 kB catch-up burst each way (open) | open |
| 54 | high | The UDP SACK was one bit off | fixed |
| 55 | medium | A UDP link both ends accepted held a slot for ever | fixed |
| 56 | low | Link-local addresses were advertised | fixed |
| 57 | low | The reachability descriptors still carried link-local addresses | fixed |
| 58 | medium | Local addresses sorted alphabetically | fixed |
| 59 | low | A bundle member opened by the far end showed `remote: null` | fixed |
| 60 | medium | `govern` reached every operation an app declared | fixed |
| 61 | high | A UDP timer that could only learn that the path was fast | fixed |
| 62 | medium | A machine that slept kept links its peers had dropped | fixed |
| 63 | medium | One UDP frame per mesh packet, fragmented by IP | fixed |
| 64 | medium | An address shared by two nodes cost a whole link every ten minutes | fixed |
| 65 | low | A link closed by a dial's clean-up left no line in the log | fixed |
| 66 | low | An accepted UDP link that never spoke was held for ever | fixed |
| 67 | low | A log could not be filtered by time, nor followed past a million | fixed |
| 68 | medium | The speed test could not read the speed the charter names | fixed |
| 69 | low | Three small ones from the live test | fixed |
| 70 | medium | Two UDP listeners accepting each other, without end | fixed, not yet re-seen live |
| 71 | medium | A dial refused as the wrong node still costs the far end's link | fixed |
| 72 | low | A speed test run past the far end's echo ceiling read it as loss | fixed |
| 73 | low | The MLO second link was not opened in time, once | fixed |
| 74 | low | An idle UDP link resent one frame in nine for nothing | fixed |
| 75 | low | The console's layout, undone by its own rules | fixed (src/webassets/ui.py, src/webassets/console.py) |
| 76 | medium | Lookups dialled the gone, and routes changed every packet | fixed |
| 77 | low | Two loops dialled the same address at once | fixed |
| 78 | medium | A node with many interfaces announced no UDP address | fixed |
| 79 | low | The map said "measuring" for links it had refused to bundle | fixed |
| 80 | low | Every GET page route failed through MCP | fixed |
| 81 | low | `test_spool_transport::test_bidirectional_over_directory` lost one message, once | open |
| 82 | low | A needless fast retransmit was counted as a spurious timeout | fixed |
| 83 | high | A mesh grown by invitations stopped working after a few generations | fixed (chain compaction) |
| 84 | high | Compaction made every compacted member depend on the root | fixed before any node ran it (introduced by the fix for 83 in |
| 85 | medium | Lookups gave up early in a sparse mesh with offline nodes | fixed |
| 86 | medium | A relay's probe load grew with every awake peer | fixed |
| 87 | medium | Uploading over a file through Fleet made it world-readable | fixed |
| 88 | low | `NMESH_UPDATE_REPO` was spliced into URLs unchecked | fixed |
| 89 | low | The MCP stdio bridge followed any URL scheme with the token | fixed |
| 90 | low | Three TLS clients relied on the library's default floor | fixed |
| 91 | medium | The first-run console password stays in the service log | fixed |
| 92 | high | liboqs was compiled from a tag nobody checked, or from `main` | fixed |
| 93 | medium | A liboqs built before the lock, or left in a cache, is reused unproven | open |
| 94 | high | The published image shipped 260 fixable HIGH/CRITICAL vulnerabilities | fixed |
| 95 | low | A core release descriptor without `notes` raised `KeyError` before its signature was checked | fixed |
| 96 | low | `PUNCH_RELAY` with an address that is not UTF-8 raised instead of being refused | fixed |
| 97 | medium | An authenticated flooder was told it had been detected | fixed |
| 98 | low | The console told every visitor its exact Python version | fixed |
| 99 | low | Dependabot moved one image to Python 3.14 and not the other | fixed |
| 100 | high | A routed packet that went round a cycle was dropped with its only copy | mitigated |
| 101 | low | An accepted link closed before the greeting raised out of the accept callback | fixed |
| 102 | medium | Relays that take packets and drop them cost a fifth of first contacts at 20 % | mitigated |
| 103 | low | A fleet route given a `node` that was not text answered with the interpreter's own words | fixed |
| 104 | high | One silent connection stopped the console for everybody | fixed |
| 105 | medium | The first invitation of a network could not be a short one | fixed |
| 106 | medium | A listener bound to one address announced every address on the machine | fixed |
| 107 | medium | The TCP link opens with a fixed, recognisable pattern | mitigated |
| 108 | high | Every lookup answered through a relay ended in a direct link, so the mesh became a full mesh | fixed (soft limit, and links spread over distance) |
| 109 | high | A node was linked to its true nearest neighbour about one time in two, and the others could not be found | fixed (leaf set) |
| 110 | medium | Every link stayed open for ever, and keeping them open was the whole traffic of an idle node | fixed |
| 111 | medium | Two builds raced to publish the base image, and the older won | fixed |
| 112 | medium | The image scanner held the Docker socket on a runner about to push | fixed |
| 113 | medium | A release published an image no test and no scan had seen | fixed |
| 114 | low | The base image every test ran in was never traced to a build | fixed |
| 115 | medium | liboqs 0.16.0 carries two advisories, in code a node never calls | fixed for new builds; open for libraries already built |
| 116 | low | The container runs as root | open |
| 117 | high | Fleet never recognised a Portainer stack, and updating one through Portainer erased its environment | fixed |
| 118 | medium | A stack update was reported failed after 25 seconds while it went on running | fixed |
| 119 | low | The Docker and Logs panels did not load when opened | fixed |
| 120 | low | A Portainer token could be configured over plain HTTP to any host, and compose was assumed from a `docker` binary | fixed |
| 121 | high | Descriptors were given back late, and swallowed failures were written without limit | fixed |
| P1 | perf | The packet dispatch table is rebuilt for every packet | fixed |
| P2 | perf | `NodeID.distance` is a Python loop over 20 bytes | fixed |
| P3 | perf | `get_closest` materialises and sorts the whole routing table | fixed |
| P4 | perf | Every UDP link polls at 100 Hz and pops from the front of a list | fixed with 6: an asyncio.Event and a deque |
| P5 | perf | The reliability layer does O(window) work per received frame | fixed |
| P6 | perf | A fresh liboqs context per signature verification | fixed |
| P7 | perf | A fresh AES-GCM object per packet | fixed |
| P8 | perf | Persisting session state is a synchronous fsync on the event loop | fixed |
| P9 | perf | The certificate store is rewritten in full for every certificate | fixed |
| P10 | perf | `_EntryPacker.add` re-serialises every certificate up to three times | fixed |
| P11 | perf | A release announce verifies the same signature three times | fixed |
| P12 | perf | Pseudo search re-folds the whole book on every keystroke | fixed |
| P13 | perf | The spool transport blocks the event loop on file I/O | fixed |
| P14 | perf | TCP framing copies the whole packet on every send | fixed |
| P15 | perf | `transport.setting()` walks the option list on every call | fixed |
| P16 | perf | `_route_candidates` sorts every authenticated peer per forwarded packet | fixed |
| P17 | perf | Gossip fan-out runs inside the ingress receive loop | fixed |
| P18 | perf | Small change, small win: the dedup cache stores a timestamp nobody reads | fixed |
| P19 | perf | `app_storage` fsyncs on the event loop | fixed |
| P20 | perf | 128 MiB of DHT and 16 MiB of session store are large defaults | partly fixed |
