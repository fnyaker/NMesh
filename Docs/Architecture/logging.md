# The log — what a node says about itself

`trace.py` records **what crossed the wire**: type, size, TTL, ids. This records
**what the node was thinking while it crossed** — the line a loop wrote when it
gave up on an address, the gate that refused a handshake, whatever an app chose
to say. Two different questions, and neither answers the other: a trace shows a
handshake that never completed, a log says which gate refused it.

Implemented in [`src/logbook.py`](../../src/logbook.py), reached from a console
through `logs.*` on the control plane, and from an app through the data
connector.

## Three refusals decide the shape

**Nothing is kept by default.** Not a truncated ring, not "just the errors" —
nothing. `LogBook.record` off is one attribute test and a return. A node keeping
a log of itself is a node carrying evidence about who it talked to and when,
which is exactly the material the threat model says to hold as little of as
possible. So it is off, it is kept while somebody is looking, and **when the last
one keeping it lets go, what was kept is dropped** rather than left in memory.
That is the opposite of `Trace.stop`, deliberately: a trace is a recording
somebody asked for and then reads; a log ring is a by-product.

**The bound is in megabytes**, because that is the question an operator actually
has. "How many lines" is a number nobody can convert into "how much of this
machine", and a ring bounded by records is a ring whose real size depends on how
chatty the code happened to be that day.

**It is compressed**, and that is what makes the bound generous. Log lines are
the most repetitive text a program produces — the same twenty messages, the same
node ids, the same field names. Whole *blocks* are compressed once each
(`BLOCK_RECORDS` lines at a time, `zlib` level 6): per line would pay the header
cost on every one and find nothing to repeat, and re-compressing the ring on
every write would be quadratic. Measured: lines carrying a node id each compress
about eight to one and repetitive ones far more, so eight megabytes holds
somewhere between one and several million of them. `logs.status` reports the **measured**
ratio — what the blocks held before deflate over what they hold now — rather
than a claim, because an operator sizing a ring deserves the real number.

## Who keeps it on

Three different things want lines kept, and none may switch off what another
asked for. Each **holds** the ring under its own name (`LogBook.hold` /
`release`), the ring records while anybody holds it, and it drops what it kept
when the last hold goes:

| Hold | Taken by | Let go by |
|---|---|---|
| `operator` | *Start recording*, `logs.set start` | *Stop*, `logs.set stop` |
| `trace` | `trace.set start` | `trace.set stop`, **and the trace running out on its own** (`Trace.on_stop`) |
| `watch` | the first app subscribing over the connector (`_LOG_WATCH`) — which is how a fleet console following this machine reads it | the last subscriber leaving, or its socket dying |

**No hold survives a restart, the operator's included — on purpose.** The
ring and its holds live in memory, and a node restarts every time it updates,
so an operator who started recording finds it stopped after the next update
(`running: false`, `held_by: []`). That is the decision, not an oversight:
keeping the log is a thing somebody chooses to do now, and a choice written to
disk would keep every line of a machine for as long as nobody remembered to
take it back. Start it again after a restart if you still want it.

Every status says who holds it (`held_by`), so a *Stop* that leaves the ring
running says why instead of looking broken. Three things went wrong before this,
and each was one switch doing another's job: stopping a trace stopped a log an
operator had started on purpose; a trace that ran out on its own left the log
running for ever; and a fleet console following a machine received nothing at
all, because recording was off there and nobody had happened to start it.
`LogBook.stop` still exists for what really means "everybody": the node
stopping, and the operator's own copy of somebody else's ring.

## Writing

```python
node.log("link dropped", source="peers", topic="link", node=short_id)
```

`MeshNode.log` is the one door, and `LogBook.record` **never raises**: it is
called from receive loops and handlers, where an exception is a dropped packet
or a dead loop. Every axis is bounded (`MAX_MESSAGE`, `MAX_TOPIC`, `MAX_FIELDS`,
`MAX_FIELD_TEXT`) because an app writes these too, and an app is not trusted to
be brief.

A **source** is refused rather than repaired when it is not a name —
*including when it is merely too long*. Truncating would be the obvious repair
and it is the wrong one: the source is what every filter in the product groups
by, and two long names cut to the same sixty-four characters become one source
that neither of them is. Anything unrecognisable is recorded as `unknown`.

A **level** is the other way round: an unknown one is recorded as `info` rather
than dropped, because losing a diagnostic to a typo is the wrong trade.

Every failure a guard swallows lands here as well as on stderr —
[`src/faults.py`](../../src/faults.py) carries one sink, set by the node. Those
are the failures with no other reader at all, which makes them the lines an
operator turning a log on is most often looking for.

## What the core writes

The ring held two lines from the core for a long time — "link dropped", with an
id and an address, and "protocol violation charged to a peer" — and a node whose
links came and went over the internet produced a log that said exactly that,
six times, and nothing about why. A trace beside it showed one link answering
nothing for a quarter of a minute and then ten seconds in which no probe left
for anybody; nothing on the node's side could say what it had been doing.

So every decision about a link is now written where it is taken, under a name
that ties the log to the trace: each link is numbered when it is made
(`_Peer.label`, ``L17/udp`` — a process-local number and the medium, naming no
one), and the same label is on every trace event that crossed it.

| source / topic | line | level | what it carries |
|---|---|---|---|
| `peers` / `link` | `link up` | info | node, link, address, dialled or accepted |
| `peers` / `link` | `link dropped` | **warn** if it died on its own, info if we closed it | node, link, address, **reason**, age, seconds since it last answered, recent loss %, the medium's counters (zeros left out). Every path that takes a link out of the list writes it — a dial that reached somebody else, a node the operator forgot and a failed join included (`unauthenticated link ended`, debug, for a link that never proved an identity) |
| `transport` / `link` | whatever the medium says (`BaseTransport.note`) | the medium's | the peer closed the link; the peer went silent; a retransmit timeout dropped the window; a send was refused — each with the medium's figures |
| `peers` / `link` | `a probe could not be sent` | warn | why, and the link's figures — once a minute per link |
| `peers` / `link` | `link failing: it loses too many probes` / `link recovered` | warn / info | on the crossing only, with the figures |
| `peers` / `link` | `a link was too busy to take a packet` | warn | the message type; the packet went to the next route and the link was kept |
| `peers` / `link` | `a handler held the receive loop` | warn | the message type and for how long (≥ `_SLOW_HANDLER`) — nothing else on that link was read meanwhile |
| `node` / `load` | `the event loop ran late` | warn | by how much, and how many links waited |
| `peers` / `rescue` | `every link to a node is failing…`, `rescue: no address answered` | warn | which links |
| `peers` / `reconnect` | `node lost: it will be dialled again`, `reconnect attempt failed`, `reconnected` | info / warn | attempts, when the next one is |
| `peers` / `dial` | `dial connected` (info) and every other outcome (debug) | — | address, outcome, detail, milliseconds |
| `peers` / `handshake` | `handshake refused` | warn | the refusal's reason |
| `peers` / `keepalive` | `keepalive accord`; `a peer announced a cadence outside the accord`; `…window refused` | info / warn | the agreed fast and slow cadences |
| `mlo` / `mlo` | `bundle changed` | info | members, benched, skew — on a change only |
| `peers` / `abuse` | `behaviour rule … fired`, `a peer's standing crossed to …`, `link tarpitted…` | warn | rule, weight, score, how long the tarpit holds |
| `peers` / `rate` | `a peer went over a rate limit: dropped` | info | which plane, its allowance |

Three rules keep this from becoming the problem it diagnoses:

- **Free while nothing is kept.** `LogBook.record` off is one attribute test,
  and every line that builds anything (figures, labels, a join) tests
  `logs.enabled` first.
- **What can happen per packet is written once per `_LOG_THROTTLE` per key**
  (`_log_throttled`), and the next line for that key says how many it `folded`.
  A rate limit or a busy link under load is otherwise a flood that pushes every
  other line out of the ring.
- **A diagnostic never raises on the path it describes.** Every one of these is
  reached from a receive loop, a sweep or a teardown, and reads the link with
  `getattr` where a stand-in might not be a `_Peer`.

## Reading

A reader holds a **sequence number** and asks what has happened since. That is
the same shape as `control.changes`, and it is deliberate: it works over a
channel that carries one bounded question and its answer, so a console four hops
away follows a log exactly as a page on the machine does.

Two details make the cursor trustworthy, and both were missing:

- **The number that comes back is where to ask from next** — the last line the
  answer *looked at*, matched or not — with `more` when a page was cut at its
  limit. It used to be the newest line *returned*, so a filter that matched
  nothing answered 0, and a reader that followed it asked for the whole ring
  again, every time.
- **A number belongs to a run.** Sequence numbers start again from one when the
  process does, and a node restarts every time it updates. Every answer names
  its `run` (random, per process); a reader that comes back with a number and
  the run it came from is answered from the start of this run if that run is
  over (`restarted`), instead of "nothing after 5000" from a ring at 3.

| Operation | The question it answers |
|---|---|
| `logs.status` | Is anything kept, how much, how well does it compress |
| `logs.set` | `start` / `stop` (the operator's hold) / `clear` / `resize` (`megabytes`, applied at once) |
| `logs.query` | The ring, newest first, through filters — what a person asks. Stops at a page (`more`); `before_seq` asks for the page before; `head` is where to follow from |
| `logs.since` | Everything after a sequence number (and its `run`), oldest first — what a subscriber asks |
| `logs.sources` | The names a filter can offer |

Filters, the same for both readers: `level` (a **floor**, not an equality),
`source` (substring), `topic` (exact), `contains` (message *and* fields — a field
must not be a place to put something a search can never find), `since_time`,
`until_time` (unix seconds — declared with their own ceiling, since the shared
one on a count is a million and refused every real time), `limit` (bounded by
`MAX_QUERY` whoever asks).

Blocks carry their own sequence and time range. A query reads **from the newest
block backwards and stops once it has a page** — a person reads the end of a
log, and it used to unpack the whole ring to show them its last screen —
skipping blocks outside the asked time range unopened. `matched` is therefore
what this page found, with `more` saying there is older material; it is not a
count of the ring. The lock is held to copy the block list and released before
any decompression: a query must never stall a loop that is writing.

The **source** names a filter offers (`logs.sources`) are counted as lines are
written, bounded by `MAX_SOURCES`, for as long as the ring runs. They used to be
read off the open block, which empties every few hundred lines.

## What the size counts

`used_bytes` is everything held: the packed blocks **and** the open one. It was
the packed blocks alone, so a fresh ring read "0 B of 8 MB" over lines it was
plainly holding — and the open block, up to 512 uncompressed lines, sat outside
the bound entirely, so a 64 kB ring could hold a few hundred kB. The open block
is now packed early once it weighs an eighth of the ring (never below 16 kB),
and room for it is kept free: the packed blocks may use the size less that. The
compression `ratio` is measured over packed blocks only.

Nothing is buffered per subscriber. **The ring is the buffer**: a reader that
was away comes back with the number it last saw, and `since` answers `lost` —
how many lines went past while it was gone — rather than handing back a gap it
cannot see.

## One switch for two recordings

`trace.set` drives the log ring with it: starting a trace takes the `trace` hold,
and the trace ending — pressed or run out — lets it go. "Turn the trace on" is
one thing an operator does, and finding out afterwards that half of it was off
is the failure worth designing out. It does not reach past its own hold: a log
an operator started is still running when the trace stops. `logs.set` remains
for what that cannot express — sizing the ring, or keeping the lines of a node
whose packet headers you have no business recording.

## Looking at it

Console → **Settings → Logs** ([`../WebConsole/guide`](../WebConsole/guide)).
The ring had a control plane and no page: the only log anybody could look at in
the product was the copy a fleet console collected from somebody else. The page
has two halves — the recording (start, stop, size, clear, and who is keeping
it) and a live view that reads the end of the log and then follows it — and
both go through the channel, so they work the same on a node being driven from
another console.

## An app's half

Two unequal halves, over the data connector
([`Docs/DataConnector/guide`](../DataConnector/guide)):

* **Writing needs no grant.** The *node* stamps the source as
  `app:<app id[:16]>`, so an app can only ever be quoted as itself. An app able
  to set its own source could write lines that read as the core's, and a log an
  operator cannot attribute is worse than no log.
* **Reading needs `readstate.logs`** (the `logs` grant — `Docs/AppPermissions/guide`), given per app in the console's Apps page
  (`apps.grant`, stored by `AppRegistry`, off until an operator turns it on, and
  dropped when the app is uninstalled). Without it every read is **answered**
  with `{"refused": true}` rather than dropped — a silent drop leaves the app
  waiting on a reply that is never coming, which is indistinguishable from a
  node that has wedged.

A subscribing app is pushed lines as they are recorded (`_LOG_LINE`). The push
is synchronous and non-blocking on the node's side, because the caller is a
receive loop: a line is queued on the client's own bounded outbox and a client
that has stopped reading loses pushes, alone, then catches up with `_LOG_SINCE`.
Watchers are forgotten when the socket goes, and the table is bounded like every
other one here. **While any app watches, the ring is held** (`watch`): a
subscriber is somebody looking, which is exactly when a node keeps a log. The
watch answer names the `run` the pushed lines are numbered in
(`ConnectorClient.log_run`), since a line does not carry it.

## A fleet's half

One node's ring answers "what is happening here, now". An operator managing forty
machines has a different question — *what happened on any of them while nobody
was looking* — and a ring on a node that has since rebooted cannot answer it.

So the fleet app collects: a machine grants `logs` by name, the operator's node
follows it (always, only while a page is open on it, or never), and what arrives
is kept in **one bounded ring per machine** on the operator's node. A follow
expires unless renewed, carries the sequence number the operator already holds
**and the run it belongs to**, and is answered from the far ring — so a
partition costs a gap that is reported (`lost`) rather than a silence that is
not, and a machine that restarted is collected from the start of its new run.
Before the run travelled, the operator's copy dropped every line numbered at or
below the highest it had seen, and after the first restart of a managed machine
nothing it said was ever kept again. Details, bounds and the two grants it
needs: [`Docs/Apps/fleet`](../Apps/fleet).

The per-machine decision — always, only while its page is open, never — is
offered wherever that machine appears: on its node card, in Fleet → Logs, and on
the shared node card the console's map opens (`fleet.relation` carries it,
`fleet.logs_policy` changes it).

## What this is not

* **Not a file.** Nothing is written to disk, by design. A ring in memory dies
  with the process, which is the property that makes it safe to offer.
* **Not a reply.** What travels to a caller is what the reader asked for and
  bounded; the plane still carries nothing of this machine in a refusal
  (`src/faults.py`).
* **Not free to read.** Reading a log is reading routing metadata — who this
  node talked to, when, and what it thought about it. That is why both readers
  are `remote=True` **and** behind the fleet's capabilities, never one without
  the other.
