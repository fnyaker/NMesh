# Transports, NAT & reachability

Source: `transport.py`, `transport_manager.py`, `tcp_transport.py`,
`udp_transport.py`, `spool_transport.py`, `stun.py`, `net_monitor.py`, and
inside `node.py`: hole punching, reachability, keepalive.

## The abstraction

- `BaseTransport`: `connect / send / receive / close` (one bidirectional link).
- `BaseServer`: `listen / close` + an `on_new_connection(transport)` callback.
- `TransportManager`: a registry **by URL scheme** (`tcp`, `udp`, `spool`, …).
  Anyone implements the two interfaces and calls `register("scheme", T, S)`. The
  core knows no concrete transport. Listeners are keyed by exact URI (a node may
  listen on several addresses; a duplicate URI is refused).

## Configuring itself: `OPTIONS` / `configure()`

The same principle as observability: **the medium declares, everything else is
written once.** A transport sets two class attributes and writes no validation:

```python
class TCPTransport(BaseTransport):
    OPTIONS = (
        option("connect_timeout", "float", 4.0, "…", minimum=0.5, maximum=60.0, unit="s"),
        option("families", "multi", ["ipv4", "ipv6"], "…",
               choices=[{"value": "ipv4", "label": "IPv4"},
                        {"value": "ipv6", "label": "IPv6"}]),
        option("source_address", "text", "", "…", placeholder="192.168.1.20"),
    )
    SETTINGS: dict = {}          # the values in force, at class level
```

Kinds: `bool`, `int`, `float`, `text`, `choice`, `multi` — exactly the
checkboxes, multi-choice lists and free fields an interface knows how to render.
`restart=True` marks a value the live process cannot pick up: saying so is the
difference between a broken setting and one that is simply not live yet.

- `coerce()` translates and **bounds** (min/max, length, membership of a choice
  list, single line) with a message a human can act on. Written once: a medium
  validating for itself would validate slightly differently.
- `configure()` applies **partially**: one bad field does not throw away the four
  good ones typed with it, and it returns
  `{"applied": …, "rejected": {name: reason}}`. `SETTINGS` is **replaced**, never
  mutated — a class dictionary shared by instances is not a place to edit under a
  live link.
- `TransportManager.options() / configure() / setting() / settings()` is pure
  pass-through: it knows which class answers for a scheme, and nothing more.
  `setting(scheme, name)` is what the core calls when it needs a value from a
  medium (the re-dial cadence, say) without knowing which class serves it.

### Persistence

The configuration file accepts **namespaced** `scheme.option` keys and carries
them **as text, without validating them**: the medium is what knows. At startup
`_apply_transport_settings()` distributes them before anything listens or dials;
a refused value is reported on the banner and left at its default — a node that
refuses to start because a timeout was mistyped is a worse outcome than a node
running on its default.

The console (Network → Reachability) renders the form **from the declaration**,
applies first and writes afterwards: a value the transport refuses never reaches
the file, or the next startup would refuse it in turn with nobody at the
keyboard to read why.

Current settings: TCP (connect timeout, read timeout, `TCP_NODELAY`, address
families, source address), UDP (keepalive interval and timeout, reorder buffer
depth), spool (poll interval).

## Observing itself: `endpoints()` and `stats()`

Two optional hooks on `BaseTransport`, shaped like `reachability()`: **the
medium describes itself, the core interprets nothing.**

```python
def endpoints(self) -> dict:      # {"local": uri|None, "remote": uri|None}
def stats(self) -> dict:          # {"retransmits": 12, "rto ms": 50.0, …}
```

- `endpoints()` is **not** the URI we dialled: it is the endpoint as the medium
  sees it now. On an *accepted* link it is the only address there is, and it is
  what tells an operator which of a peer's addresses actually carries the
  traffic.
- `stats()` is free-form by construction: a UDP link has retransmits and a
  reorder buffer, a serial link has a baud rate, a LoRa link has an SNR. The
  console **renders the names it is given**, so a transport the console has never
  seen becomes observable with no console-side code.

Two rules, because this is *polled*: the values are JSON-safe scalars, and
reading them never blocks. The core protects itself anyway — a transport that
raises, returns a nested object or fifty keys does not break the snapshot: it is
ignored, filtered, bounded to 16 entries (`tests/test_link_stats.py`).

Current implementations: TCP reports the write buffer's fill (a number that
stays high means that peer is not draining, which no packet counter shows) and
`TCP_NODELAY`; UDP reports retransmits, reorderings, unacknowledged frames, the
current RTO and missed keepalives.

## Link quality (`metrics.LinkQuality`)

A single RTT cannot tell a steady 40 ms link from one oscillating between 5 and
400 ms. Every link therefore keeps the **last 32 samples** (bounded, tiny)
reduced to the four numbers people actually read: last, best, worst, **jitter**
(the mean of consecutive differences). **Loss** is counted separately — a probe
that never comes back has no round trip to average — and is `None` while only
one probe is in flight: a pending probe is not 100% loss.

## The status of each address (`node._dial_log`)

A node advertising four addresses of which one works is the normal case on a
real network, and "which one, and why not the others" is the first question
anybody asks. Every attempt is therefore recorded: `connected`, `no-answer`,
`timeout`, `refused`, with the reason and the duration. A live link beats the
log (an address carrying traffic is `in-use`, whatever it did last week), and an
address never tried is `untried`, not broken. Bounded twice over: 128 nodes,
8 addresses each.

Three further outcomes never reach the medium and are recorded anyway, because
a blank line next to an address that does not work teaches nothing: `invalid`
(the URI is not one), `no transport` (no registered transport serves that
scheme — the reason carries the scheme) and `peer limit` (`_MAX_PEERS` reached
— a ceiling on open **links**, not on distinct nodes; one node may hold several).

**A single dialling path.** `node._dial_uri(node_id, uri, timeout)` is the only
place an outgoing link is opened: the routing-table walk, the console's *Retry*
button, the periodic loop and the latency probe all go through it. They
therefore apply the same timeout, tear a failed attempt down the same way, and —
the part that matters to an operator — record the same outcome against the same
address. It never raises: a dial that fails is the normal case, not an error.

## Re-dialling an address

Three mechanisms, one dial function (above).

**By hand** — `console_retry_addresses(node_hex, uri="")` replays one specific
address, or all of them (stopping at the first that works: "give me back a
link", not "open four"). It only dials **addresses already known for that
identity**: the console is authenticated, but "type an address and the node
connects to it" is a different feature with a different threat model. The reply
says what each address did, in the words of the table above.

**Periodically** — `_address_retry_loop`. A node that dropped because its ISP
hiccuped, its laptop slept or a switch rebooted comes back on its own address;
without this, nothing tries again until something needs a route. The **cadence
belongs to the medium**: `retry_interval` is an option declared by the transport
(0 = never, the default), because a radio that costs a battery per attempt and
an Ethernet have no business sharing a number. What is fixed in the core is the
**shape** of the loop, so that an operator's setting cannot turn it into a
flood:

| bound | value | what it prevents |
|---|---|---|
| `_RETRY_TICK` | 5 s | a loop running flat out |
| `_RETRY_MAX_PER_PASS` | 4 dials | a node with 200 known peers dialling 200 times |
| `_RETRY_NODES_SCANNED` | 64 | the pass growing with the table |
| `_RETRY_DIAL_TIMEOUT` | 8 s | a dead address holding the pass |

A node already linked is never re-dialled, and the loop dies on nothing: a
recovery loop that stops is a silent loss of recovery.

## Choosing between a node's addresses: priority × latency

Two things decide, and they are not the same kind of thing.

- **What the medium is worth** — `priority`, an option declared by every
  transport, from −254 to 254. Shipped defaults: `udp` **10**, `tcp` **0**,
  `spool` **−50**. The core has no opinion here: only the operator knows whether
  their LoRa link is the precious one or the last resort.
- **What the address measures** — the last duration recorded for that URI in
  `_dial_log`.

The `transport_balance` slider (0..100, default 50) says how much each half
weighs: `0` = latency alone decides, `100` = priority alone.

```
score(uri) = w · (priority + 254) / 508  +  (1 − w) · 25 / (25 + ms)
                                                          w = balance / 100
```

Two intended properties:

- **Both halves are mapped onto 0..1 absolutely**, not against each other. A
  score therefore means the same thing on every pass: two addresses compared
  today and tomorrow give the same answer, and the steering loop can use a fixed
  margin.
- **Latency *curves*, it does not scale.** 0 ms is worth 1, 25 ms 0.5, 4 s still
  something. A linear scale would let one absurd measurement flatten every real
  difference between 5 and 50 ms.

An address **never measured** is worth the middle: neither rewarded nor punished
for being new. A medium that cannot answer (no `setting()`) is worth neutral —
that is no reason to stop dialling.

`node._preferred(uris, node_hex)` sorts by descending score; a **global IPv6**
address breaks a tie (reachable end to end, it avoids NAT entirely). That is the
sort *every* path choosing an address uses: the routing-table walk, the re-dial,
the join block, the hole punch. `node.transport_preference()` returns the order
of the schemes alone, so the console can show it without reimplementing the rule
in JavaScript.

## Steering an address on latency (`dynamic_address`, off by default)

A node reachable at several addresses is usually reachable at several
**qualities** — a LAN address and the same machine's public one, IPv4 and IPv6
over different paths. The one in use is the one dialled first: chosen by order,
not by what it is worth.

`_address_steering_loop` fixes that when the operator asks
(`--dynamic-address`, the `dynamic_address` key, or the console's button).
**One** candidate per pass:

1. a live link whose latency we have measured, and an address of the same node
   that is neither the one in use nor measured recently
   (`_ADDR_STEER_COOLDOWN`);
2. the current latency is measured with real probes (`_ADDR_STEER_PROBES`);
3. the candidate is **dialled** and measured the same way — an address that
   looks fast but cannot finish a handshake is not a better address;
4. we only move if the **score** (above, so priority *and* latency) wins by at
   least `_ADDR_STEER_MIN_GAIN`. Deliberately the same score as the dial order:
   "this medium is preferred" and "this address is faster" are settled by one
   rule, not by two that can contradict each other. Two milliseconds is noise;
   at equal latency, the preferred medium wins.

The loser is closed either way: the node never keeps two links to one peer
beyond the measurement. It is off by default because it is a trade — a dial and
a handshake against a few milliseconds — and only the operator knows whether it
is worth it.

## TCP (`tcp_transport.py`)

- Framing: a **2-byte** prefix (uint16 big-endian) = the size of the `Packet`
  that follows.
- `_CONNECT_TIMEOUT = 4 s`: a `connect()` with no answer fails fast (instead of
  hanging on the OS SYN timeout) — indispensable when dialling unproven
  addresses (the private IPs of a NATted peer learned by gossip). Through
  `asyncio.timeout`, never `wait_for` (cancellation, see `gotchas.md` §3b).
- `_READ_TIMEOUT = 60 s`: a `receive()` with no data for 60 s raises → the link
  is treated as dead and reaped. **An idle link therefore dies without a
  keepalive** (see §keepalive).
- **`_wait_closed_bounded`**: Python 3.12 changed `Server.wait_closed()` — it
  now blocks until **every accepted client connection** is closed, not only the
  listening socket. Closing a port while a peer stayed connected never returned
  (a hang). We bound the wait (the listening socket is already closed by
  `close()`, which is what matters). See `gotchas.md`.

## UDP (`udp_transport.py`)

UDP is connectionless and unreliable → a **reliability layer**:
- Frame: `NUDP` (4-byte magic) + seq(4) + ack(4) + sack(4) + flags(1) +
  payload_len(2) + payload. Cumulative ACK + SACK, retransmission with backoff
  (`_RTO_*`), bounded reordering, keepalive (25 s), all bounded.
- A **modular** receive window (RFC 1982) around the delivery cursor: in order →
  delivered; ahead → a bounded buffer (`_MAX_REORDER`); behind → a duplicate,
  re-ACK. No set of seen sequence numbers (bounded state whatever a hostile peer
  sends; the 2³² wrap no longer freezes the link).
- **Both buffers are bounded in bytes as well as in entries**, whichever binds
  first: `_MAX_REORDER_BYTES` for the out-of-order buffer and
  `_MAX_DECODED_BYTES` for the decoded packets waiting on `receive()`. A frame
  count is not a memory bound — a frame carries up to 60 000 bytes, so 256 of
  them is 15 MB per link, and the sender chooses every byte by sending sequence
  numbers ahead of the cursor and never filling the gap. The decode queue has
  the same shape from the other side: nothing couples arrival to consumption, so
  a sender faster than `_Peer._loop` — or a transport whose consumer has not
  started yet — grew it without limit. Overflow **drops**: `_process_frame` runs
  inside `datagram_received`, a synchronous callback that must never block, and
  UDP promises no delivery anyway.
- `receive()` waits on an `asyncio.Event`, not on a poll. The poll cost up to
  10 ms of latency per packet and 100 timer wakeups a second **per link** at
  complete rest; with `_MAX_PEERS_UDP` links that is 12 800 wakeups a second
  doing nothing. `close()` and the keepalive's death verdict both set the event,
  so a parked `receive()` is never left waiting for a link that has gone.
- Link death: `_KEEPALIVE_TIMEOUT = 75 s` (3 × the 25 s interval, and above the
  20 s mesh PING cadence) — below that, a healthy but silent punched link was
  killed when the phases lined up (route flapping).
- `UDPServer`: **one shared socket**, multiplexed by source `(ip, port)`. A
  datagram from an unknown source creates a `UDPTransport` +
  `on_new_connection` — like a TCP accept. `NPPB`/`NPAK`/STUN datagrams are
  routed to `on_raw_datagram` (hole punch), not to a reliable transport. The
  dispatch table counts **live** transports: a closed one releases its slot
  (`remove_transport` on close and on the keepalive's death verdict,
  `_reap_closed` when the table is read), because counting the dead meant 128
  datagrams from 128 source ports disabled UDP for the life of the process,
  including for a known peer whose link had died and wanted to come back.
- **Sequence numbers start random**, and the receiver learns the peer's starting
  point from the first frame of any kind — which is the keepalive `connect()`
  sends before any data, so the cursor is set before a data frame can arrive.
  The frame header is *not* authenticated (only the mesh Packet inside it is)
  and a link's endpoints are public gossip, so a cursor starting at zero was a
  free target: one spoofed frame at the next expected sequence advanced it, and
  the real peer's next frame was then dropped as a duplicate. Randomising does
  not make the header authentic — that would be a design change — it removes the
  guess. A delivered payload that is not a decodable packet is counted
  (`undecodable`, visible in `stats()`): a real peer's frames decode, so it is a
  fault worth seeing rather than silence.

## Store-and-forward (`spool_transport.py`)

The mesh also runs over a **directory/file** (`spool://DIR`): each node writes
its outgoing packets to a file and polls (`_POLL = 0.02 s`) the peer's file. For
offline / very high latency links ("a USB stick carried on foot"). The same
invite/handshake/E2E, with no socket.

Whoever can write to that directory decides how many sessions appear, so
`SpoolServer` bounds both: `_MAX_SESSIONS` live links at once, `_MAX_SEEN`
remembered names, and a directory whose name is not exactly what `connect`
writes (`sess-` + 16 hex characters, `_SESSION_RE`) is not a session at all.

## NAT hole punching (in `node.py`)

The goal: establish a **direct UDP** link between two nodes behind NAT,
coordinated by a shared relay. The machinery (`_PUNCH_*` constants):

1. A sends `PUNCH_REQUEST(target, my_udp_port)` to the relay (over TCP).
2. The relay sends `PUNCH_RELAY` **to both**: to the target C (with A's real UDP
   address) and to the requester A (with C's **TCP** address — often empty,
   because on the relay's server side `remote_addr` is `None`).
3. Each creates a `_punch_pending` state and sends a **burst of raw UDP PROBEs**,
   ML-DSA signed (`_send_punch_probes`).
   - **Careful:** if the peer's UDP address is unknown (empty), **we keep the state** and do
     not probe: the peer has our address and is probing us; an incoming PROBE
     completes the punch from its source address. (A historical bug: deleting the
     state blocked the initiator — see `gotchas.md`.)
4. On receiving a valid PROBE → ACK + `_complete_punch`. The node with the
   **larger NodeID** is the initiator: it opens the `UDPTransport`, registers it,
   and **kicks** the responder (a burst of keepalives, `_kick_punched_link`, to
   survive a lost datagram). The responder accepts through the normal UDP path.
   Then the standard handshake → an authenticated link.
   - De-duplication: one initiator transport per address (both peers often punch
     at the same time).
5. `_maybe_upgrade_path`: sending data to a peer only reachable through a relay
   automatically triggers an attempt at a direct link (rate-limited per target,
   `_UPGRADE_COOLDOWN`).

### What a punch probe signs

`magic ‖ src_id ‖ dst_id ‖ nonce ‖ minute` — the **recipient** and the minute,
not just the sender. Signing `magic ‖ src ‖ nonce` alone made every probe a
bearer token: captured once, it verified at any node that knew the sender, for
ever, and each replay bought a signature and a ~3.4 kB ack sent to whatever
source address the replayer forged. The receiver accepts the current minute or
the previous one, so a probe crossing a boundary is not treated as a replay.

Raw punch datagrams are also metered per **source address**
(`_punch_datagram_allowed`) before any verification — there is no peer and no
identity to key on, and they are the only expensive thing reachable with no link
at all. A spoofed source therefore spends only the budget of the address it
forged.

## Address discovery & reachability

**An AutoNAT answer is only believed if we asked the question.** `probe_reachability`
records `(peer id, scheme)` with a short TTL (`_note_reach_probe`), and
`_handle_reach_probe_ack` requires a match, consumes it, and ignores anything
else. `_inbound_schemes` decides what the node advertises and whether it offers
itself as a relay, so an unsolicited "yes" from one peer could make a NATted node
announce itself as reachable — a black hole for everyone who then routes through
it. Contrast the *passive* signal in `_handle_handshake`: an inbound connection
that authenticated is proof, not a claim.


- `OBSERVED_ADDR`: a peer accepting our connection sends back the source IP it
  sees → our public address as seen from there (bounded addition to
  `_extra_addrs`).
- STUN (`stun.py`): the public reflexive UDP address. Bounded DNS resolution
  (`_bounded_getaddrinfo`, a daemon thread abandoned on timeout — otherwise a
  stuck DNS freezes shutdown, see `gotchas.md`).
- **AutoNAT**: `REACH_PROBE`/`REACH_PROBE_ACK` — asking a peer to call us back to
  **actively confirm** that we are reachable (before declaring ourselves a public
  relay).
- `NetMonitor` (`net_monitor.py`): re-checks local addressing on a short timer
  and re-runs the network probes (public IP over HTTP, STUN) on a *trigger* (a
  changed local IP, a clock jump = suspend/resume, a `poke` from the node, a
  periodic refresh). Bounded probes, silent failure, **never blocks the loop**
  (`discover_public_ip` in a daemon thread, see `gotchas.md`).

## Link keepalive (`_link_keepalive_loop`)

A healthy but **idle** link is reaped at `_READ_TIMEOUT` (TCP 60 s). The node
therefore PINGs every established peer every **20 s**
(`_LINK_KEEPALIVE_INTERVAL`), well below it. The links of the **maintained set**
(`_neighbor_slots`, the `_NEIGHBOR_FLOOR = 3` nearest — see `routing.md`) are
pinged **first**: those are the ones the node commits to holding, and they must
never be starved by a slow or dead peer placed earlier in the list. If the count
of live links falls below the floor at the end of a cycle, neighbourhood
maintenance is woken immediately. Both ends do this → traffic in both
directions; any incoming frame rearms the timeout. Started in `start()`/`join()`,
stopped in `stop()`. Never raises. (That PING also carries `advertised_uris` →
address gossip, see `routing.md`.)
