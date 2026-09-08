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
`wrong node`, `timeout`, `refused`, with the reason and the duration. A live link beats the
log (an address carrying traffic is `in-use`, whatever it did last week), and an
address never tried is `untried`, not broken. Bounded twice over: 128 nodes,
8 addresses each.

`wrong node` is the one that used to hide: an address that connects, completes
the handshake and turns out to belong to somebody else — or to this node itself
— failed in a way `no-answer` describes as its opposite. The reason names the
identity actually reached, and the address is dropped from the entry **and
remembered** (`note_wrong_address`), because that entry is wrong rather than
slow and forgetting it only lasts until the next answer re-advertises it (see
`gotchas.md` and `routing.md`).

Three of its reasons say three different things, and the difference is what may
be held against the address:

| Reason | What proved it | Address struck off |
|---|---|---|
| `answered as <id>` | a signature over our own challenge | yes |
| `this address is this node itself` | our own advertised address list | yes |
| `answered claiming our own identity` | nothing — a `CHALLENGE` on a link that has authenticated nothing | **no** |

The third is the net for a self-dial at an address we did not recognise as ours:
it ends the link before a 21 kB handshake is built for it, but a *claim* must
never be what strikes an address off — otherwise saying "I am somebody else"
would be how you get a third party's address forgotten.

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

### Choosing between the links a node already holds

An address score answers "which of these would I dial?". A node reached over
`tcp` **and** `udp` at once needs the other question — "which of these do I
send down?" — and every place that asked it wrote
`next(p for p in self._peers if p.authenticated_id == …)`: *the first link
opened*, which with two links is a coin toss. One of the two may be losing every
probe, and half the traffic went down it.

`node._link_to(target)` answers it once, by `_link_score`: the address score,
**multiplied** by what the link is losing.

```
_link_score(peer) = _address_score(uri, rtt) × (1 − loss) ** _LOSS_PENALTY_EXP
```

Multiplied, not shifted, because loss is not "a slower link" — it is a link that
does not work. At `_LOSS_PENALTY_EXP = 4`, one probe in ten lost costs about a
third of the score (0.9⁴ ≈ 0.66), which is more than any latency difference a
real network produces; and a link nothing comes back from scores **exactly
zero**, so it is never chosen while anything else exists. Loss below two probes
is `None` — unknown, not zero — and an unproven link is neither rewarded nor
punished for being new.

`_authenticated_peers()` returns the **best** link per identity by the same
score (identities keep the order they were first seen in, so a list on a screen
does not reshuffle when two links swap rank), which puts routing, gossip
fan-out and the neighbourhood on it too. Address steering multiplies by the same
factor on both sides of its comparison — a lossy incumbent is precisely what
steering exists to leave, so it has to count there or it never gets left.

### Cutting a link that answers nothing (`_reap_silent_links`)

Scoring a dead link at zero keeps it out of the traffic; it does not get rid of
it. A half-open TCP connection and a UDP mapping the NAT has forgotten both look
alive from here — nothing errors, nothing closes — so the link stays listed,
stays counted, and stays in the way. Worse, the far end has no such link and is
dialling us to get one, and until this one goes the two ends disagree about
what exists between them.

The link keepalive (every `_LINK_KEEPALIVE_INTERVAL`, 20 s) cuts any established
link that has gone `_DEAD_LINK_PROBES` probes with no answer — four in a row,
over a minute of one-way silence. The evidence is a **run**, not the lifetime
share:

| | what it answers | what it misses |
|---|---|---|
| `loss()` | what an operator reads: how good has this link been | a link that worked for an hour and then died — a thousand good probes outvote the dead ones, so the share never rises |
| `since_pong` | is this link still a link | nothing; it is reset by any answer |

Three things keep it from cutting something that works:

- **any answer resets the run**, including one that arrived too late to be
  timed. Only the latest probe is kept for the round-trip measurement, so a
  link slower than the keepalive interval has its answers arrive unmatched —
  counting those as silence is how a slow medium gets cut for being slow
  (`LinkQuality.on_answer`).
- **each link is judged on its own probes**, so a node reached over `tcp` and
  `udp` loses only the medium that stopped answering.
- **relayed and `probation` links are left alone** — the first carries no probes
  of its own, the second belongs to the steering pass.

Cutting heals the link rather than losing the node: the identity, its addresses
and the routes through it are untouched (`_safe_stop_peer`, not `_reap_peer`),
maintenance is woken, and the next pass dials it again.

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

The candidate is dialled with `_dial_uri(..., probe=True)`, which marks it
`probation` **before** its handshake can complete. That is what keeps the
duplicate reaper below out of the measurement: a second link opened on purpose,
whose loser this pass closes itself.

## One link per node per medium (`_collapse_redundant_links`)

Two nodes that dial each other at the same moment end up with **two** links
each: same pair, same transport, both authenticated. Nothing used to look, so
both stayed — the console showed one node twice on one port, the keepalive paid
for both, and half the traffic went down a link the far end was not using.

Which of the two survives cannot be decided locally: if each end drops the
other's, the pair is left with none. So it is decided from the two identities,
which both ends already know:

> **The canonical link is the one dialled by the larger node id.**

The same rule as the hole punch's initiator (`_complete_punch`), for the same
reason: one comparison, one answer, no exchange. Each end runs it at the moment
a link authenticates (both handshake handlers) and closes what the new link
supersedes — with `_safe_stop_peer`, not `_reap_peer`, because the *node* is
still reachable and forgetting the routes through it would cost real traffic.

Two guards keep it from eating something legitimate:

- **only the same scheme**. A node reached over both `tcp://` and `udp://` holds
  one link on each and that is the design; two `tcp://` links to one node is the
  accident.
- **never a `probation` link** (address steering, above) and never a relayed
  virtual peer — a tunnelled link has no medium and no port to duplicate.

When both links run the same way round (we dialled twice, or were dialled
twice), direction cannot choose, and the **older** one wins: the far end sees
the same pair in the same order.

### The rule only holds while both ends see both links

The canonical rule settles a **simultaneous dial**, and that is bounded in time:
two dials cross within one open-and-authenticate, which this node already
bounds at `_HANDSHAKE_DEADLINE` (60 s). A link much older than that when a new
one authenticates is not the other half of anything — it is a link the far end
no longer has (it restarted, its address moved, its TCP went half-open), and it
is dialling us again precisely because it has none.

Applying the rule there was an outage, not a tidy-up. The far end dialled, we
answered its `CHALLENGE`, it sent its `HANDSHAKE` — and the rule kept the ghost
and closed the link that had just proved itself. From the dialler, over two
minutes: eleven `HANDSHAKE` out, eleven `CHALLENGE` in, **no `HANDSHAKE_ACK`
at all**, for ever.

So when the keeper the rule chooses is more than `_HANDSHAKE_DEADLINE` older
than the newest link, the newest one is kept instead: it is the one that has
just been proved, and the other is the one nobody on the far side has. A pair
that really did cross is seconds apart and is still settled by the two ids.

The `_reap_silent_links` sweep above is the other half of this: the ghost that
made the rule misfire is exactly a link that stopped answering, and it now goes
on its own within a couple of minutes rather than waiting for a dial to trip
over it.

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
- **`wait_closed_bounded`** (`ip_utils.py`, shared with the data connector):
  Python 3.12 changed `Server.wait_closed()` — it now blocks until **every
  accepted client connection** is closed, not only the listening socket.
  Closing a port while a peer stayed connected never returned (a hang). We bound
  the wait (the listening socket is already closed by `close()`, which is what
  matters). It lived here as `_wait_closed_bounded` until a second caller needed
  it and the connector was found still awaiting bare — see `gotchas.md` §1.

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

**A STUN response is only believed if we sent that request.**
`_send_nat_keepalive` records the transaction id it generated and the server it
went to (`_note_stun_request`); `_handle_stun_keepalive_response` requires both
to match and consumes the entry. `stun._parse_binding_response` *does* compare
the transaction id — but it was handed `data[8:20]`, the id out of the datagram
being checked, which makes the comparison a tautology. The listener socket is
unconnected, so that left any host able to set the address this node believes it
has, and then advertises to the mesh. The lookup also goes through
`ip_utils.bounded_getaddrinfo`, not `loop.getaddrinfo`: this was the one call
site in the tree still using the executor asyncio joins at shutdown (gotchas §2).

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

**Two clocks, not one.** Since multi-link operation (below) a link may need a
probe every hundred millisecond, and every other link must go on costing one
wake-up every twenty seconds. So the loop is a **due-time** loop: each link
carries its own `ka_due`, the loop sleeps until the soonest of them (never less
than `_KA_TICK_FLOOR`, and woken early by `_keepalive_wakeup`), and the *sweep*
— reaping the silent, expiring tarpits, re-forming the bundles, judging
behaviour — stays on `_LINK_KEEPALIVE_INTERVAL`, because none of that is
per-link work.

At rest nothing changed: every link is due in twenty seconds, so the loop
sleeps twenty seconds. The gotchas' "timers that exist to find nothing" budget
is unaffected.

### A probe count stopped being a duration

`_reap_silent_links` cut a link after `_DEAD_LINK_PROBES = 4` unanswered
probes, and the comment explaining the number said "over a minute of one-way
silence" — true only while every link was probed on one interval. On a bundle
member probed ten times a second, four probes is **four hundred milliseconds**,
and cutting a link for a hiccup is exactly the thing benching exists to avoid.

So the run is joined by the time it always stood for
(`_DEAD_LINK_SILENCE = _DEAD_LINK_PROBES × _LINK_KEEPALIVE_INTERVAL`, read off
`LinkQuality.answered_at`) and a link has to fail **both** tests. The verdict
then means the same thing at any cadence — which is the point, and neither half
alone gets there: the run alone cuts a fast-probed link for a hiccup, and the
silence alone cuts a link on a very slow medium that nobody has probed yet.

## The keepalive accord (`mlo.accord`, `KA_PROPOSE` / `KA_REQUEST`)

A cadence is a cost, and it is paid by **both** ends: the prober spends the
packet, the answerer spends the answer. So neither may simply choose it, and
neither may be made to spend more than it offered to.

Each node declares **four** numbers — a range per mode — in a `KA_PROPOSE` sent
once the link authenticates, beside the capability record:

| | what it says | default |
|---|---|---|
| `keepalive_fast_min_ms` | the fastest I will ever be probed, striping or not | 100 ms |
| `keepalive_fast_max_ms` | the slowest that is still worth calling *fast* to me | 1 s |
| `keepalive_slow_min_ms` | the fastest I want to be probed when nothing is happening | 15 s |
| `keepalive_slow_max_ms` | the slowest I can be probed before I stop believing the link | 20 s |

Both ends then apply `mlo.accord` to the two declarations and get the same
answer, so **nothing is exchanged to settle it** and there is no state where one
end thinks something was agreed and the other does not (the same trick as the
canonical link and the punch initiator).

```
fast = max(the two fast floors)          … and a fast mode exists only if
                                           fast ≤ min(the two fast ceilings)
slow = max(the two slow floors, min(the two slow ceilings))
```

### Why four and not two

One range was the obvious shape and it is short by half. With a single
`[min, max]` only the **floor** protects anybody: it is a `max` across the two
nodes, so nobody can be dragged below what they declared. The ceiling is a
`min` — and a `min` is a lever anybody can pull. A peer proposing `(100, 150)`
pulled the shared ceiling to 150 ms, and this node, which clamps its cadence
into the accord, would have probed that link six times a second for as long as
it stayed open. Eight bytes, once, per link an adversary opens.

There is no way to write the two-number model where the ceiling is not either a
lever or ignored. Four numbers give each *mode* its own floor and ceiling, and
then **both agreed cadences are a `max` over something each node declared**:

> There is no expression in `accord` a peer's number enters where being smaller
> helps it. **Nothing a peer sends lowers this node's own probe interval** — not
> bounded by a constant, not clamped afterwards; it is the shape of the
> arithmetic. `test_no_declaration_at_all_can_lower_either_cadence` sweeps every
> corner of the hard range against a node on defaults and says so.

The two ceilings still do real work, and it is the honest kind:

- **`fast_max` decides whether striping happens at all.** A phone offering
  `fast = [2 s, 5 s]` and a server offering `[100 ms, 500 ms]` have no cadence
  both would call fast, so `fast_ok` is false and the pair is **not bundled** —
  rather than one of them paying for the other's idea of it. That is the whole
  of "do not drain the other's battery for something neither of us gets
  anything from", and it is a node's strongest opt-out: raising `fast_min` past
  a peer's `fast_max` ends the question, and no request can override it.
- **`slow_max` is how a node says a link has gone too quiet to believe.** It
  loses to a peer's `slow_min` when the two disagree, because at rest the
  cheaper answer is the right one — but see the medium's own timeout below,
  which is the constraint that actually binds.

### The medium has the last word on going quiet

Two nodes can agree to idle at five minutes over a transport that reaps a
silent link at sixty seconds, and neither can see that from the accord: it is a
fact about the wire, not about the pair. So the medium declares
(`BaseTransport.idle_timeout` — TCP reports its `read_timeout`, UDP its
`keepalive_timeout`, a spool directory reports nothing) and the core keeps the
idle cadence to `mlo.IDLE_TIMEOUT_SHARE` of it: the same three-to-one margin the
UDP keepalive already holds itself to, read backwards.

Applied **locally**, not folded into the accord, because the two ends may run
different transport settings and each is right about its own — and it may only
ever take back what the medium cannot afford, never push the cadence below what
the pair agreed. Which is why a node wanting a genuinely deep sleep raises
`tcp.read_timeout` as well as its own `slow_max`.

Everything the pair does afterwards sits inside that accord, and three things
follow from it.

- **Every PING says when the next one is due.** The tail is
  `next_ms(4) ‖ token(8)`, appended after the address list — a trailer, which is
  the whole compatibility story: `_decode_addresses` has always stopped at the
  last address, so a build without this reads a tailed PING as the PING it
  always read. The tail is only *sent* to a peer that announced the `keepalive`
  feature, which is a different question — see **What silence means** below.
- **…and carries the addresses only when the peer might not have them.** See
  *What a probe weighs* below: at ten a second, an unchanged address list is
  most of the packet and most of the work.
- **The answer echoes the token.** `on_ping`/`on_pong` keep only the latest
  probe, which is right at twenty seconds and useless at a hundred
  milliseconds: with several probes in flight, every answer but one arrives
  unmatched. `LinkQuality.sent`/`answered`/`expire` resolve each probe
  individually, which is what makes the recent window honest.
- **A `next_ms` outside the accord is a finding** (rule K1), not an error. The
  two agreed cadences *are* the two ends of the window it is judged against —
  nothing between striping and idling is out of bounds, nothing outside them is
  in — and that window is what makes "faster than we agreed" a thing that can be
  *said* about a peer at all. Nothing is counted for `_KA_GRACE` after an accord
  moves: a proposal crosses the link at the speed of the link.

### Asking a peer to slow down (`KA_REQUEST`)

`request_keepalive(target, wanted_ms)` asks the far end to probe this link less
often — "I am going to sleep". It is **deliberate, never automatic**, and that
is a decision rather than an omission: a node that asked automatically would
meet a node that automatically takes the fast lane back, and the pair would
spend the link arguing about how often to probe it.

> **A request can only ever ask for less.** One that asks for more is dropped.
> Granting it would make a four-byte packet a way to spend somebody else's
> battery and bandwidth, on the one plane that exists to stop exactly that.

It is clamped into the accord in both directions, so a peer can neither speed
this node up nor slow it past the idle cadence the two of them already agreed.

> **A request is a "go quiet for now", never a setting.** It is honoured in
> *both* modes — "stop probing me so hard" is worth nothing if striping ignores
> it — and it lapses at `_KA_TOLD_TTL`; a peer that still wants the quiet says
> so again. The **durable** way not to be probed hard is the declared fast
> range, which no request can override and which a peer cannot ask us to widen.
> Keeping those two apart is what stops a four-byte packet becoming a
> configuration change somebody else made.

Once the request has lapsed, the next probe carries the fast cadence again —
which is the announcement that legitimately refuses it.

The peer has two correct answers, and only two:

| what it announces | what it means | finding |
|---|---|---|
| `next_ms ≥ what was asked` | honoured | none; the request is cleared |
| `next_ms = the accord's floor` | "I want the fast lane back" | none; the request is cancelled |
| anything else, after the grace | a third cadence | **K2** |

The floor announcement is what keeps a refusal from looking like silence: the
peer is entitled to want the fast lane, it is only not entitled to say nothing.

A proposed window whose floor sits above its own ceiling is **K3** — a claim
that cannot be true — and the proposal is dropped rather than adopted: believing
a window we have just called impossible would be the accusation and the
compliance in one breath. See `behaviour-rules.md`.

### What silence means, in both directions

`peer_speaks` answers "may we use this plane with a peer that has said
nothing?", and the answer is **yes**: every name in the classic set predates the
negotiation, and a node from before it must keep receiving exactly what it
received before (`features.py`, rule 2).

A name added *after* the negotiation is the opposite case, and reading it the
same way is a bug with no error message. Silence about `keepalive` is a peer
that will not echo the token — so every probe would be unmatched and `expire`
would charge every one of them as a **loss on a link answering perfectly**.
Those names are listed in `features.SINCE_NEGOTIATION` and asked through
`peer_announces`, which requires the name to have been said.

## What a probe weighs

The PING carries `advertised_uris` because liveness and address gossip happened
to want the same packet. That was free at one probe per link per twenty seconds.
At ten a second it is the packet — measured on a node advertising five
addresses:

| | before | after |
|---|---|---|
| PING on the wire | 312 B | **92 B** |
| PONG on the wire | 87 B | 87 B |
| `_handle_ping`, receiving one | 30.2 µs | **6.4 µs** |
| `ping()`, sending one | 22.1 µs | **6.3 µs** |

Three changes, and none of them touches the wire format.

**The addresses go out when the peer might not have them** — our set changed,
or `_ADDR_GOSSIP_INTERVAL` has passed for that link — and the rest of the time
the probe is a probe. The interval is a *duration*, not "every Nth probe", for
the same reason `_DEAD_LINK_SILENCE` is: a probe count means one thing at rest
and another while striping. It equals `_LINK_KEEPALIVE_INTERVAL`, so a link
nobody is bundling carries them on every probe exactly as before, and it is
also the net under a lost PING — a peer that missed an update is told again
within it rather than never.

Sending none is **not a new kind of packet**: a node with nothing announceable
has always sent exactly this, so there is nothing to negotiate and no build
anywhere that reads it as unusual. On the receiving side an empty list takes
`RoutingTable.touch` instead of `add` — `add` merges and re-filters everything
already held, which is four microseconds of work to learn nothing — and falls
back to `add` for an id we have never heard of, because `touch` will not invent
an entry and this is the one path that may create one.

Both are cheap because the bucket is keyed by id rather than held as a list:
refreshing an entry is a `move_to_end`, not a scan under dataclass equality.
Restoring the second of the two below cost 11.7 µs a probe until that changed —
a security fix that ate the whole optimisation, which is its own lesson
(`gotchas.md`).

Two things `add` did are kept, and both are load-bearing rather than
bookkeeping. **An authenticated PING still proves recency**, which is what
keeps a live NATted peer with nothing to announce from being purged for having
nothing to say. And **`touch` re-appends the entry to its k-bucket**: bucket
position is the eviction order, so being heard from is what keeps a node out of
the firing line. Refreshing `last_seen` alone — which is what the first version
of this did — left the peer we probe ten times a second first in line to be
evicted while an id a stranger merely mentioned was promoted past it. See
`gotchas.md`.

**`advertised_uris()` is memoised on the three lists it derives from.** It was
15 µs of regex and per-character work per call, recomputed on every probe,
every `FIND_NODE` answer and every announce, to produce the same five strings.
The key is the whole of the input, so there is no fourth thing to forget to
invalidate — the failure a cache normally buys.

**`Packet.create` builds the packet once and draws its nonce in blocks.** It
used to construct one `Packet` purely to ask it for its own id and then a
second one to keep, and to make a `getrandom` syscall for every packet. Neither
is a property, both were on the send path of *every* packet this node emits:
3.34 µs → 2.40 µs each. A slice of a CSPRNG draw is CSPRNG output, so the block
buys a syscall and never a shortcut — and the nonce has to stay unpredictable,
because it feeds `msg_id` and a guessable `msg_id` is a way to seed a relay's
dedup window so a *later* legitimate packet is dropped as a replay. The pool is
dropped in a forked child, or both sides would hand out the same bytes.

## Multi-link operation (`mlo.py`, off by default)

A node holds several links to one peer as a matter of course — a LAN address
and a punched UDP path, IPv4 and IPv6. Exactly one of them carried anything:
`_link_to` picked the best by score, `_authenticated_peers` reduced each
identity to that one, and the other sat there being kept alive at our expense.

MLO spends both. Packets go down the members in turn, so the pair carries what
neither carries alone, and a link that starts losing is left behind in seconds
instead of at the next reap.

### Who may be bundled

Six tests, and each one is a way this could otherwise break a mesh.

| test | why |
|---|---|
| the **medium** declares `mlo` | `tcp.mlo` / `udp.mlo`, off by default. Only the operator knows whether a probe ten times a second is cheap on that medium — a transport that does not declare the option at all (spool) can never be bundled, and that absence is the right answer rather than a gap |
| the **node** is awake | `mlo_active()`: somebody is using it, or `mlo_always` |
| the **peer announced** `mlo` **and** `keepalive` | one end missing is no MLO — which is the backward-compatibility story, and it is the negotiation's, not a special case |
| the accord has a **fast mode** (`fast_ok`) | a cadence *both* call fast. Without one the pair would be measured at whatever the slower tolerates and called multi-link operation: fifty probes at twenty seconds is seventeen minutes of history. Either end declaring a fast range that does not reach the other's is how a node opts out, and that opt-out has to work |
| the link is **direct** | not relayed, not `probation`, not tarpitted: a tunnelled link has no medium of its own to be a second one |
| there are **two of them** to one identity | one link is not a bundle and must not pay for one — and the node opens the second one itself, see [below](#where-the-second-link-comes-from) |

A link that passes is a **candidate**, and candidacy is what buys the fast
probe — not membership. A link only earns its place by being *measured* at that
cadence, so waiting for membership first waits for something that can never
happen. `_update_bundles` decides this once per sweep and writes the answer onto
the link (`ka_wanted_ms`), because `_keepalive_interval` runs per probe and must
stay O(1).

### What a bundle decides

Every number comes from the last `LinkQuality.WINDOW` (50) probes of *that*
link — the window the request named, stated once so the console and the bundle
cannot read two different ones.

- **Skew.** Members must measure within `mlo_skew_ms` (default 30 ms) of the
  fastest. Striping across 5 ms and 300 ms does not double anything: it delivers
  half the packets a third of a second late, which every consumer above reads as
  loss.
- **Reordering budget** = `2 × skew`. Deliberately generous: the skew is a
  difference of *round trips*, so the one-way spread it stands for is about half
  of it, and doubling again leaves the budget at roughly four times what a
  healthy pair produces. A budget that is too small is a consumer dropping
  packets that did arrive. Readable per node as `reorder_budget_ms(target)`.
- **Benching.** A member losing `mlo_drop_percent` (default 10%) of its window
  carries nothing — and **keeps its keepalive**, which is how it measures its
  way back in.
- **…and coming back needs half that.** One number in both directions is a link
  that flaps: with a fifty-probe window, one answer moves the share by 2%, so a
  link at the threshold would rejoin, drop, leave and rejoin about ten times a
  second — spraying traffic down the one link known to be losing it. The window
  damps nothing on its own; the margin (`mlo.RECOVER_SHARE`) is what does.
- **Two members**, `mlo.MAX_MEMBERS`. A third adds a second skew that nothing
  measures against the first.

An **unmeasured** link (fewer than `mlo.MIN_PROBES` outcomes) is never eligible:
unproven is not good, and handing half the traffic to a link nothing has come
back from yet is the failure the whole mechanism exists to avoid.

### Where the second link comes from

MLO worked, and *started* by accident.

A bundle is two links to one identity, and a node holds one. `_ensure_route_to`
stops at the first address that answers; the address-retry loop skips a node it
is already linked to. Neither is wrong — one link is all routing needs — so the
second one existed only when the pair happened to dial each other over two
media, or when an operator pressed **Retry every address** by hand. A node could
sit next to a perfectly bundleable peer for a week and never bundle.

So MLO asks for it (`_mlo_dial_loop`). `_update_bundles` is already the one
place that decides who could be bundled, so it is the one place that notices an
identity **one link short** and writes it down (`_mlo_short`); the loop spends
that book, one dial at a time.

Two rules pick the address (`_mlo_second_address`), and neither is a preference:

- **Another scheme.** Two links to one identity over one medium are collapsed as
  redundant the moment the second authenticates (`_redundant_links`), so dialling
  one is asking for the link we already hold to be closed. This is why a bundle
  is a LAN address *and* a punched UDP path, never two addresses of one
  transport.
- **A medium that declares `mlo`.** Exactly what the link we hold had to prove:
  the second link is probed ten times a second too.

And the bounds are the ones every other dial in the node obeys: it dials only
addresses **already known for that identity** (like the retry loop and the
console's button — "type a host and the node connects to it" is a different
feature with a different threat model), the far end must still prove it is that
identity, one dial per pass, `_MLO_DIAL_FLOOR` between passes, an exponential
backoff per identity from `_MLO_DIAL_MIN` to `_MLO_DIAL_MAX`, and both books
bounded at `_MLO_DIAL_TRACKED`. It asks for nothing at all while the node is
asleep: the link it would open exists to be probed ten times a second.

What it does not do is close one. A link opened is a link the node has, and MLO
never takes one away — a node that goes back to sleep keeps both, at one probe
per link every twenty seconds.

> A peer only reachable through a hole punch is the one case this cannot serve:
> a punch is coordinated when there is **no** route, and by then there is one.
> Such a pair bundles when the punched path arrives on its own.

`mlo_status()["waiting"]` is the same book, for an operator: what is one link
short, and the address MLO would open it on — which is what the console's
multi-link table says when it is empty.

### Where the traffic is actually spread

One place: `_route_candidates`, through `_stripe`, which swaps the **head** of
the candidate list for whichever member's turn it is. That puts app data,
routed traffic and everything else on one rule, and `_authenticated_peers` has
already reduced each identity to its best link — which is exactly the list a
bundle exists to widen again. The loser of a turn stays in the list as a
fallback, so a send that fails still has somewhere to go. When nothing is
bundled the cost is one truthiness test on an empty dict.

Round robin rather than weighted: the members are inside one skew of each other
by construction, so there is nothing left to weigh, and a rule recomputed per
packet is a rule on the hot path.

**The turn is filtered by `exclude` too**, and that is not tidiness. A forward
excludes the link the packet arrived on; a bundle knows which links reach an
identity and knows nothing about where a packet came from. Without the filter
the turn could land on exactly that link and send the packet straight back the
way it came — a loop, added by the one thing in the path that *adds* a
candidate rather than removing one.

### Being awake

MLO is a trade, and it is only worth making while somebody is using the node —
which cannot be read off traffic, since a relay carries plenty and wants none of
this. Two shapes say so, because "somebody is here" arrives as two different
facts:

- `note_awake(source)` — a **moment**. The console calls it for **every**
  authenticated request it serves (`WebConsole._authed`), because a page asking
  for anything is what a page being open *is*. Not `/api/state` alone, which is
  where it used to be: the chat and fleet pages never read the node's state, so
  a console open on chat looked like an empty room. It wears off after
  `_MLO_AWAKE_TTL`.
- `hold_awake(source, probe)` — a **state**. Two are registered. The console
  holds one over the change streams it is serving (`open_streams`): a page with
  its refresh interval turned off asks for nothing until something moves, and
  the connection it is holding open is what says it is still there. The data
  connector holds one over its **attended** clients: an app somebody is at,
  with nobody typing, is still a window open, and a timestamp would have been
  the wrong shape for it.

### …and what is not somebody

Two things look exactly like a person and are not. Both were counted once, and
each one on its own is enough to keep a node bundling for ever.

- **A socket this node opened for itself.** The node attaches its own built-in
  apps to the connector at boot — chat is enabled by default — so "a client is
  attached" is true on a machine nobody has touched in a week. Those clients
  declare themselves unattended (`ConnectorClient(attended=False)`, the
  `ATTENDED` frame in [`Docs/DataConnector/guide`](../DataConnector/guide)) and
  `DataConnector.attended_clients` counts what is left. What says a person is
  at chat is the chat *page*, and the console sees that.
- **A page on somebody else's machine.** A peer holding the fleet's `manage`
  right drives this console by replaying HTTP calls against it
  (`fleet_console.LocalConsole`), which is authorised and is still not somebody
  *here*: waking this node must not be something the network can do to it. Each
  replayed call carries `fleet_console.REPLAY_HEADER` and the console does not
  count it. The marker can only ever ask for less, so nothing that can set it
  gains anything by lying.

An operator who wants a node bundling regardless of any of this says so:
`mlo_always`.

### The contract this puts on apps

> **An app must tolerate receiving out of order**, and this is not new — a mesh
> routes, and a routed reply has never been obliged to arrive after the one
> before it. MLO makes the overtaking *deliberate* and gives it a number.

Each app decides how. The built-ins: `call` orders audio frames by `seq`, chat's
file transfer is indexed by chunk, and chat's edits, deletions and reactions
now **wait** for the message they name rather than being dropped when it has not
arrived yet (`chat_web._park` / `_release`, bounded in number and in time).
