# Traps & lessons (read BEFORE debugging a hang or a flaky test)

Real bugs, hit and fixed. Each one was expensive to diagnose. If you touch the
area, keep the fix — and if you add one, document it here.

## Hangs (the job/node "never finishes")

### 1. asyncio 3.12: `Server.wait_closed()` waits for client connections
Python 3.12 changed the semantics: `wait_closed()` blocks until **every accepted
connection** is closed, not only the listening socket. Closing a server
(`remove_listen`, `close`) while a peer stayed connected **never returned** → an
infinite hang (5 h in CI before the kill).
→ Fix: `_wait_closed_bounded()` (`tcp_transport.py`) bounds the wait. **Never
`await server.wait_closed()` bare** on a server that may have live clients.

### 2. Blocking network probes → a frozen loop/shutdown
`discover_public_ip` did **blocking** socket work (`getaddrinfo` with no
timeout, `connect`) directly on the asyncio loop. On a restricted network (CI) →
a freeze. The subtle trap: `loop.run_in_executor(None, …)` **does not solve** the
problem — asyncio **joins the default executor at shutdown**, so a thread stuck
in `getaddrinfo` freezes `asyncio.run()` on the way out.
→ Fix: the probe runs in a **daemon thread abandoned on timeout** (never
joined), bounded (`_PUBLIC_IP_TIMEOUT`). Same for STUN DNS
(`_bounded_getaddrinfo`).
**Any potentially slow blocking network I/O must be bounded AND off the loop AND
not joined at shutdown.**

### 3b. `asyncio.wait_for` can *lose* a cancellation (Python 3.11)
`TCPTransport.receive` used `asyncio.wait_for(readexactly, timeout)`. If the
inner read completes in the same loop step as the cancellation of the enclosing
task, `wait_for` can **swallow** the `CancelledError`: the receive loop does not
exit and **blocks again** on the next `receive()` → `peer.stop()` (which does
`await self._task`) waits for a task that never dies. Symptom: a `stop()` that
freezes, revealed by concurrent traffic (address gossip producing a PING/PONG
just before shutdown).
→ Fix: `async with asyncio.timeout(...)` instead of `wait_for` — it propagates
the cancellation cleanly. **Do not reintroduce `wait_for` on a path that must
stay cancellable.**

### 2b. Reading a pty in a thread freezes shutdown again (the same trap as 2)
The Fleet app's remote shell and its driving of OpenSSH both read a **pty
master**. The temptation is `loop.run_in_executor(None, os.read, fd, n)` — and
that is exactly trap 2 wearing another face: reading a pty whose peer never
closes **never returns**, the thread stays in the default executor, and asyncio
**joins that executor at shutdown** → `stop()` never comes back.
→ Fix: `fleet_ssh.watch_pty()` — `os.set_blocking(fd, False)` +
`loop.add_reader(fd, …)`. No thread to join, no read to get stuck in, and EOF
(EIO on Linux when the child hangs up) removes the reader cleanly.
**Any fd that may never return is read with `add_reader`, never in a thread.**

A corollary in the same area: the task pumping a pty closes its own session at
the end of the stream. If `close()` cancels that task without a guard, it
cancels itself mid-teardown and never finishes its cleanup — hence the
`task is not asyncio.current_task()` in `_Shell.close()`.

### 3. An idle TCP link dies on its own
TCP `receive()` raises at `_READ_TIMEOUT` (60 s) with no data → the link is
reaped. Without a keepalive, a healthy but silent link goes down. →
`_link_keepalive_loop` (a PING every 20 s). If you see links "dropping after a
while", look at the keepalive first.

### 4. A TCP `connect()` with no timeout hangs for minutes
Dialling an unreachable address (a NATted peer's private IP learned by gossip, a
dead host) with no bound lets the OS exhaust its SYN timeout (~2 min) **inside**
`_ensure_route_to` — which is awaited by `_forward_packet` (freezing the
incoming link's receive loop) and by `console_ping_node`'s fallback.
→ Fix: `_CONNECT_TIMEOUT` (4 s) through `async with asyncio.timeout(...)`
(cancellable, see 3b) in `TCPTransport.connect`. **Every connection opened
towards an unproven address must be bounded.**

### 4b. `peer.stop()` waited without a bound for a cancelled task that never dies
`_Peer.stop()` did `task.cancel()` then `await task` **with no bound**. When the
cancellation lands on a read whose future was already cancelled, the task stays
marked "cancelling" and waits for a wake-up that never comes → `stop()` never
returns. Observed on roughly one teardown in three as soon as a node has several
peers (the hang predated the routing fixes, it was simply rare).
→ A bounded wait (`_PEER_STOP_TIMEOUT`): closing the transport afterwards
destroys the link anyway. `MeshNode.stop()` also stops its peers **in parallel**
(`gather`), or 128 links stack 128 bounds.
**No task wait at teardown may be unbounded.**

### 12. An answer that triggers the next question — the link saturated at rest
`_maintain_neighbors` sent a `FIND_NODE`; `_handle_found_node` woke maintenance
as soon as the answer held valid entries; the `await self._neighbor_wakeup.wait()`
therefore returned **immediately** and started again. Since a `FOUND_NODE`
carries certificate chains (~15 kB, see §9), two joined and **idle** nodes
exchanged 3 Mbit/s measured over loopback — on a real link, everything the link
can carry, permanently.

Three stacked causes, all three fixed:
1. **Our own id counted as a discovery.** The routing table refuses to store
   `self._id`, so `contains(self._id)` is false *forever*: every answer that
   mentioned us back looked like news and woke maintenance. We now only wake on
   a genuinely new id, and never on our own.
2. **No floor between two cycles.** `_NEIGHBOR_MIN_INTERVAL`: a wake-up may
   shorten the wait, never remove it. **No loop driven by what a peer sends us
   may run unbounded** — that is as much about amplification as about
   throughput.
3. **A search that cannot succeed never stopped.** A mesh smaller than
   `_NEIGHBOR_FLOOR` (3) is below the floor forever, so `searching` stayed true.
   Unproductive cycles now back off exponentially up to `_NEIGHBOR_IDLE_MAX`
   (5 min), and the keepalive stops pushing a search with nothing left to find.
   Any real event (a peer lost or gained, an unknown identity) wakes it and
   resets the backoff.

Before/after on two joined nodes at rest: **3036 kbit/s → 2.1 kbit/s**. Found
with `src/trace.py` (Settings → Protocol trace), locked down by
`tests/integration/test_idle_chatter.py` — which includes a "discovery still
works" test, because a bound must not switch off what it protects.

### 8b. Two readers on one socket — the connector request that never answers
`ConnectorClient` let `recv()` and `_roundtrip()` both read `self._reader`
directly. An app parked in `recv()` (which every app is, always) read the
**reply to somebody else's request** and, seeing it was not a `RECV` frame,
**threw it away**. The requester then waited for a frame that no longer existed.

It stayed invisible while every request happened to run before the receive loop
started. The moment one ran on a timer — chat re-reading the node's pseudo every
30 s — the app's name silently stayed empty forever. No error, no traceback: a
hang inside a coroutine nobody was awaiting with a timeout.
→ Fix: **one reader**. `_pump()` is the only coroutine that touches the stream;
`RECV` frames go to the inbox and wake `recv()`, everything else is handed to
the future a `_roundtrip` registered. Replies carry no request id, so
`_roundtrip` also takes a lock to keep one question in flight at a time, and a
dead link fails every waiter instead of leaving them parked.
**Never add a second `await _read_frame(self._reader)` to that class.**
Locked down by `TestOneReader` in `tests/test_data_connector.py`.

## Routing: the "works at 3 nodes, not at 6" bugs

### 9. A `FOUND_NODE` that does not fit in a packet — Kademlia dies silently
An ML-DSA-65 certificate weighs ~7.3 kB, so a chain up to a root ~14.6 kB.
`_handle_find_node` packed Kademlia's `k = 20` entries → ~292 kB, far beyond the
60 000-byte ceiling. `Packet.create` raised `PacketError`, `_Peer._loop`
swallowed the exception ("a malformed packet does not kill the link"), and **no
reply ever left**. From the **fifth** certified node in the table onwards, every
`FIND_NODE` on the network went unanswered: no more lookups, so no more
`_ensure_route_to` towards an unknown id, so a mesh that "worked at first" and
degraded to direct peers only as it grew. No log, no red test — the test
topologies had 2-5 nodes, just under the cliff.
→ A **budgeted** reply (`_FOUND_NODE_MAX_BYTES`) and certificates shared through
a pool (`_EntryPacker`); entries with no chain skipped. See `routing.md`.
**Anything packing N certificates into a packet must be bounded in bytes, and
checked by a test with N > 5.**

### 10. Acquiring a route from a receive loop: a freeze plus a deadlock
`_forward_packet` and the reply handlers (`_handle_find_node`,
`_handle_find_value`, `_handle_dir_find`, `_handle_echo_request`, E2E) awaited
`_ensure_route_to` — lookup + dial + hole punch, several seconds — **inside**
`_Peer._loop`. Two consequences:
1. the incoming link processes nothing for that whole budget (a peer sending
   packets towards unreachable ids can freeze the link at will: PINGs/PONGs
   lost, RTT ruined, "the ping stopped answering");
2. the lookup started waits for a `FOUND_NODE` that often has to come back **over
   that very link** — when it is our only peer, the wait is lost before it
   begins.
Measured: a single unroutable packet froze the link for 4.95 s.
→ `_defer_route` / `_route_outbound(blocking=False)`: the fast path inline,
acquisition in a bounded background task (`_MAX_DEFERRED_ROUTES`, cancelled by
`stop()`). **Never await `_ensure_route_to` from a packet handler.**

### 10b. Four more handlers were still doing the slow thing inline

§10 named the rule — **never await `_ensure_route_to` from a packet handler** —
and four places still broke it, each in its own way, long after the rule was
written:

- `_handle_release_fetch` called `_route_outbound` **without `blocking=False`**,
  the one sibling handler that did not pass it. `src_id` is not authenticated,
  so a stranger's unroutable id was exactly the packet that cost most: up to
  `_ON_DEMAND_TIMEOUT` of frozen link, `_RELEASE_SERVE_MAX` times per window.
- `_handle_reach_probe` awaited the AutoNAT dial-back: two bounded waits of
  `_REACH_DIAL_TIMEOUT` each, five allowed per window — so the peer's link was
  held busy for longer than its own rate window lasts, and never caught up.
- `_send_to_candidates` awaited `_drop_failed_peer`, which awaited
  `peer.stop()` (bounded at `_PEER_STOP_TIMEOUT`) and then closed the
  transport. A forward tries up to `_ROUTE_SEND_FANOUT` candidates, so one
  packet could spend ~10 s tearing links down *inside an unrelated peer's*
  receive loop. It removes the peer from routing synchronously now — which is
  what correctness needs — and stops it in the background.
- the three gossip handlers fanned out with `await p.send(...)` over every peer,
  so one peer's full send buffer stalled the link the announce arrived on.

**The rule generalises: a handler's job is to decide, not to wait.** Anything
that dials, stops a link, writes to disk or talks to every peer goes through
`_spawn_bounded` / `_track_route_task`.

Two of those were also `fsync`s. `_persist_state` (every handshake, both E2E
handlers, `_handle_data`, `send_data`) and `_cert_add` (per certificate, so six
times for one chain) each serialised their whole store and wrote it
synchronously on the loop — and the cost grew with the state, so a node that
had been up a while stalled longer per handshake. Both mark a dirty flag now;
one bounded task writes at most every `_STATE_WRITE_INTERVAL`, off the loop
thread, and `stop()` flushes whatever is pending. **A snapshot the node never
wrote is a restart that re-handshakes everything, so the flush at teardown is
not optional.**

### 11. Replies were routed by a fresh XOR guess
A reply (`FOUND_NODE`, `ECHO_REPLY`, an E2E ACK, `DATA`) left again by a greedy
choice recomputed from scratch, while the path the request had just taken was
the only *proven* information available. On a chain that works by accident; as
soon as a node has several neighbours, the reply can go into a dead end and the
seeker sees only a timeout.
→ `_learn_reverse_path` / `_route_hints` (bounded, dated, forgotten at the first
silence), consulted by `_route_candidates`. Detail and the accepted attack
surface in `routing.md`. **A direct link to the target always keeps priority.**

### 12. A rate limit set at normal traffic breaks normal traffic
The anti-reflection guard on `FIND_NODE`/`FIND_VALUE` was first set at
64 requests / 10 s per link. The measured **legitimate** peak is ~66 (α × a
lookup's rounds, plus a few concurrent lookups): the limit therefore refused
real requests and made lookups random — exactly the failure we were fixing.
→ `_QUERY_RATE_MAX = 512`: an anti-flood valve, not shaping.
**Measure the legitimate peak before setting a rate bound; the peak does not
necessarily grow with the network (here it is flat, bounded by a lookup's
behaviour, not by the number of nodes).**

## E2E sessions & liveness (the "it never delivers again" bugs)

### 5. Answering an E2E_HANDSHAKE by overwriting the session poisons the link
The E2E retry re-sends a handshake every 5 s while data is queued. On a slow
path (a relay), a duplicate arrives **after** establishment. Answering naively =
overwriting the responder's session with a new key, while the initiator has no
pending state for that duplicate, **ignores the ACK** and keeps the old key →
the two ends encrypt with different keys → every DATA fails at the GCM → a
**silent, permanent drop** (neither re-initiates: each one "has" a session). The
same effect in a glare when the ACK doubles the losing handshake in flight.
→ Fix: with a session already live, the responder derives a **candidate** key
(bounded by `_E2E_REKEY_MAX`, TTL `_E2E_REKEY_TTL`) and ACKs anyway, but only
promotes it if a DATA **decrypts** under it (proof that the peer really
completed that handshake — the case of a peer that lost its session). A
duplicate never produces such a packet → the candidate expires. Tests:
`tests/test_nat_relay_fixes.py`, `tests/integration/test_nat_relay_e2e.py`.
**Never reinstall an E2E session without proof that the peer holds the key.**

### 6. The PONG is unconditional
`_handle_ping` only answered if the PING carried valid URIs. A NATted node with
no listeners (or with no announceable address) therefore **never** got a PONG:
its `ping_sent_at` stayed armed forever (the RTT never resolved) and a direct
peer's console ping looked dead. → The PONG always follows the gates (a non-empty
payload, src = an authenticated peer, decodable addresses).
The merge into the routing table, on the other hand, **always** happens for the
authenticated sender (a PING proves its freshness even with no announceable
address — otherwise a live NATted peer is purged from the table for lack of one),
but **only valid URIs** are added to `addresses`: an entry may therefore exist
with `addresses == []` (recency with no usable address), never with a malformed
URI inside it.

### 7. The UDP keepalive timeout was shorter than the traffic cadence
`_KEEPALIVE_TIMEOUT = 15 s` with a keepalive every 25 s and mesh PINGs every 20 s
(the comment said "3 missed keepalives") → as soon as the phases lined up, a
**healthy** punched link was declared dead → route flapping: `_route_outbound`
prefers the dying direct peer → ECHO/DATA sucked into a black hole → an
intermittent "ping stopped working" in both directions.
→ `_KEEPALIVE_TIMEOUT = 75 s` (3 × the interval). **A death timeout must always
be ≥ 3 × the largest legitimate traffic cadence.**

### 8. UDP sequence window: modular comparison, not an infinite set
Receiver deduplication used an **unbounded** `_recv_seen` (a spray of sequence
numbers → memory) and broke the link at the 2³² wrap (every post-wrap sequence
already "seen").
→ `process_incoming` reasons in modular distance (RFC 1982) around the delivery
cursor: in order → deliver; ahead → a bounded buffer (`_MAX_REORDER`); behind →
a duplicate, re-ACK. No set, bounded state by construction.

## Hole punching (see also `transports.md`)

- **Do not delete `_punch_pending` when the peer's UDP address is unknown** (a
  relay that only knows the TCP link → an empty address). The initiator (the
  larger NodeID) must keep its state to complete the punch from the incoming
  PROBE. Deleting it blocked the punch deterministically (especially on 3.12).
- **De-duplicate initiator transports**: both peers often punch at the same time
  → a risk of two `UDPTransport`s to the same address racing each other (neither
  authenticates).
- **Kick in a burst**: opening the punched link with ONE keepalive was fragile
  (one lost UDP datagram = a lost punch). `_kick_punched_link` sends a bounded
  burst.

## Tests: parallelism & not blocking

The suite runs in parallel (`pytest-xdist`, `-n auto`, configured in
`pyproject.toml`). Traps when you add or move a test:

- **Fixed ports = a collision between workers.** A *fixture* shared by several
  tests must bind an **ephemeral** port (`:0`) and then read the port back (see
  the TCP/UDP fixtures in `tests/test_*_transport.py`). One fixed port for one
  unique test is fine; a shared fixed port is not.
- **LAN broadcast = crosstalk between workers.** Tests that send or listen on
  `DISCOVERY_PORT` hear each other. They are pinned to a single worker with
  `pytestmark = pytest.mark.xdist_group("lan_discovery")` (+ `--dist loadgroup`).
  Any new broadcast test must join that group.
- **No real network in tests.** The autouse fixture `_no_public_network_probes`
  (`tests/conftest.py`) neutralises `discover_public_ip` and the STUN probe → no
  Internet dependency, no risk of a freeze. Do not work around it without a
  reason.
- **A hang net**: `--timeout=120 --timeout-method=thread` — any test exceeding
  120 s fails with a traceback (instead of 5 h). If a legitimate test approaches
  that limit, there is a real problem, not a limit set too low.
- **The console holds the loop: do not call it from the loop.** The HTTP server
  runs in a thread and marshals every action onto the asyncio loop
  (`run_coroutine_threadsafe(...).result()`). A test (or a script) making a
  **synchronous HTTP call from the loop** blocks it while the server thread waits
  for it to run its coroutine → a hard deadlock that looks like a network
  timeout. Every console test goes through
  `await asyncio.to_thread(_request, …)`; keep that pattern.
- **Wait for a condition, do not sleep.** Replace `await asyncio.sleep(0.1)` "to
  let it propagate" with a poll on the observable state (in-memory transports
  propagate in milliseconds). Negative tests ("nothing happens") keep a short
  timeout, but a bounded one.

## The app layer: a reply's silent failures

- **Never cut JSON at a byte offset.** The Fleet app's `_dump_json` truncated at
  `MAX_BODY` to fit a DATA frame. The result is not a short reply: it is invalid
  JSON, which the recipient drops silently. From the operator's side, the command
  "does nothing". We now remove **entries** (named lists) until it fits, with a
  `truncated` counter. **Any variable-size reply must be trimmed by elements,
  never by bytes.**
- **An asynchronous action must have an observable state.** A scan asked of a
  remote node did come back over the wire, but the interface never redrew the
  tab concerned: the result landed in the state and was never shown. A polling
  loop must redraw *everything* that can change, not only what the user just
  triggered.
- **A completion can precede its own registration.** The bridge records the
  operation after the call returns; a nearby peer answers before that. Closing
  must be idempotent and order-independent, or the operation stays "running"
  forever. (Symptom: a test green on its own, red in parallel.)

## Miscellaneous

- `console.stop()` blocked for 0.5 s: `ThreadingHTTPServer.serve_forever()` polls
  its shutdown flag every 0.5 s by default. We pass a tight `poll_interval`
  (`webconsole.py`, `chat_web.py`).
- Docker: liboqs is **compiled** (a separate base image `Dockerfile.base`,
  published only on dependency updates; the application image builds FROM it).
  The base build needs `make` → `build-essential`, not `gcc` alone (otherwise
  CMake: "CMAKE_MAKE_PROGRAM is not set").
- Docker: the application image must copy **`start.sh` and `pyproject.toml`** as
  well as `src/` and `scripts/`. Without them the fleet app fails at runtime with
  "no NMesh tree at /app" — `build_payload` requires `src` **and** `start.sh` to
  push an installable tree. Nothing breaks at build time, hence
  `tests/test_docker_image_tree.py`.
- `systemctl` being present does **not** prove systemd is running: many container
  images ship it with no init behind, and every call dies on "Failed to connect
  to bus". The real test for a running systemd is the existence of
  `/run/systemd/system` — `install.sh` requires both.
- `sudo mkdir -p` on a path **inside the user's home** gives the directory to
  root. `install.sh` used to create `~/.local/share/nmesh/data` root-owned for a
  user installation, and the node — running under that account — died on its very
  first write: *"PermissionError: … /data/node.key.tmp"*. `ensure_dir` therefore
  creates the directory **without escalating** where it can, escalates only as a
  last resort, and always restores the expected owner (which also repairs an
  earlier installation).
- A system account has no usable home, yet `start.sh` looks for liboqs under
  `$HOME/_oqs`. The node started as `nmesh` therefore could not find its crypto.
  `install.sh` pins `HOME` to the installation directory — at install time **and**
  in the unit — so the library that was built is exactly the one the service
  loads.
- A service does not inherit a session environment: systemd passes neither `HOME`
  nor `USER`. Under `set -u`, `start.sh`'s bare `$HOME` killed the script before
  anything started — *"HOME: unbound variable"* — and systemd restarted it in a
  loop. `node_home()` resolves a directory that is actually writable
  (environment → passwd entry → installation directory).
  **No script launched by a service may dereference a session environment
  variable without a fallback.**
- liboqs is compiled once per machine: the result is cached under
  `/var/cache/nmesh/liboqs-<wrapper version>` and reused by any later install (a
  different prefix, a second node). Reuse is decided **functionally** — the
  wrapper loads the candidate library and ML-KEM-768 / ML-DSA-65 answer — never
  on a filename or a version number, and the check is redone at the destination
  after the copy.
- `install.sh` writes `nmesh.conf` **before** locking permissions down, not
  after. The file is created 0600 by whoever runs the installer: written after
  the `chown -R` to the node's account it stayed `root:root` and the node could
  not read it at all. Symptom: a node coming back on **all** its defaults while
  the file says otherwise (the console on 127.0.0.1, no fleet app).
  `tests/test_install_script.py` locks the order down.
- A default injected by the launcher beats the configuration file, and therefore
  cancels it. `start.sh` used to prefix `--udp 9001 --stun` on every launch:
  `udp`, `no_udp` and `stun` were settable in `nmesh.conf` and silently had no
  effect. **A default is only allowed to exist in one place** — here
  `src/config.py`. A corollary: at startup the node announces which settings from
  the file the command line overrode.
- A pty on a shell's descriptors is **not** enough: it must be made the session's
  **controlling terminal** (the `TIOCSCTTY` ioctl). Without it `/dev/tty` will not
  open, `sudo` refuses to ask for a password and job control is off — a pty with a
  prompt in it, not a terminal. `start_new_session=True` has already done the
  `setsid()` by the time `preexec_fn` runs: the session exists, it simply owns no
  terminal.
- `sudo` and `su` refuse to ask for a password with no terminal. An `ssh` without
  `-tt` gives the remote shell no tty: "sudo: a terminal is required". And with
  `-tt`, the remote prompt comes back on ssh's **stdout** and the answer must go
  into its **stdin** — not onto the local pty, which serves only OpenSSH's own
  prompts. Hence, for the escalating phase: stdin, stdout and stderr all wired to
  the pty, **tty echo off** (or the typed password comes back out in the collected
  output, which goes into the operator's log), and no piped data — with a remote
  terminal, stdin *is* the terminal.
- A password prompt cannot be told apart by its wording: `sudo` writes "password
  for", `su` a bare "password:", OpenSSH both. What separates them is the
  **moment**: the first is the login, the following ones an escalation — and only
  runs that asked for a remote terminal can face one. Elsewhere, a second prompt
  is OpenSSH asking again, and answering it burns an attempt against the target's
  lockout.
- `install.sh` never fails an installation because a service manager refused the
  service: under `set -euo pipefail`, a `systemctl` exiting with an error killed
  the whole script after the tree had been copied. It is a warning now, and the
  installation stays usable by hand.

## Neighbourhood maintenance

- The distant-bucket scan uses `routing.get_closest(target, k)` sorted by XOR: if
  the current bucket is saturated, the oldest candidate rises and is tried first
  — which may target a node that is already connected. `_connect_routing`
  therefore de-duplicates existing sessions before dialling.
- Failing identities accumulate an independent back-off; without a bound
  (`_NEIGHBOR_RETRY_TRACKED`), an enormous routing table could grow that tracking
  endlessly. That table is a plain `dict`, bounded in size.
- **Above `_NEIGHBOR_FLOOR = 3` live links, a maintenance cycle does nothing**
  (no `kad_lookup`, no dial) — that is intended (see `routing.md`). A test
  expecting a dial must therefore either stay below the floor or call
  `_maintain_neighbors(force=True)`; otherwise it observes a perfectly normal
  silence and wrongly concludes a regression.
- **Promotion** (a node seen in transit, nearer than our worst slot) dials *even
  in the quiet regime*: it is a second path, on top of the bucket scan, which can
  create a shortcut in a chain-topology test. The same guard applies:
  `_stop_neighbor_maintenance()` after the join.
- Observing a candidate **never wakes** the maintenance loop. This is
  deliberate: the `src_id` of a routed packet is not authenticated, and waking on
  receipt would let anyone pick an id near ours to set our dial cadence
  (amplification). The candidate is handled on the next cycle, at most 30 s later.
- The multi-peer dial shares a common deadline: we avoid "waiting for the
  slowest" when the target is simply unreachable. A collective failure is
  distinguished from a partial one (some peers answer, others do not) so that the
  Kademlia fallback does not "double-dial" candidates that are already valid.
- **A lookup for an id we already know as a peer of the network does not put it
  in the table.** Observed in CI (~1 run in 8, long before it was understood):
  `_kademlia_lookup(z)` returns `False` in 50 ms in a relay star, while the relay
  knows `z` perfectly well. Two stacked causes, fixed together:
  1. the shortlist contained `z` (distance 0) → the `FIND_NODE` went **to `z`
     itself**, which answered with its neighbours and **never included itself**;
     the shortlist stopped progressing, the lookup stopped at the first round and
     `routing.contains(z)` stayed false. The responder now includes itself in its
     reply (`_handle_find_node`, see `routing.md`);
  2. `_kademlia_lookup` returned the verdict of a lookup **already in flight**
     for the same target (`_pending_lookups`) — started from a different
     shortlist, at a different moment. It now restarts its own with the remaining
     budget.
  The debugging moral: a lookup that fails in a few tens of milliseconds asked
  the network nothing. Look at `_pending_lookups` **before** suspecting the
  transport.
- **A chain-topology test (A-B-C-D-E, no shortcut) must disable neighbourhood
  maintenance**, not only `_punch_enabled`. As soon as the nodes each have a
  listenable TCP address, `_maintain_neighbors` connects them directly the moment
  they learn about each other through routing (that is the point: resilience
  through XOR-near links). It breaks the "no shortcut" assumption of a test
  checking pure multi-hop. `await nd._stop_neighbor_maintenance()` after the
  join. Relay topologies (NATted peers with no listener, e.g.
  `test_routed_ping.py`, `test_nat_relay_e2e.py`) do not have this problem:
  with no dialable address, maintenance cannot create a shortcut.
- **"Forget node" (web console, `console_forget_node`) is not a ban.** It removes
  the entry from `RoutingTable` and cuts any live session, but the PONG merge
  (every authenticated sender is reinserted into the table — see above) and the
  neighbourhood maintenance scan above can relearn the same node as soon as it
  contacts this one again. A real ban would need a persistent exclusion list
  consulted by `RoutingTable.add`/PONG, which does not exist today.
