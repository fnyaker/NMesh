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
possible. So it is off, an operator turns it on for as long as they are looking,
and **stopping drops what was kept** rather than leaving it in memory. That is
the opposite of `Trace.stop`, deliberately: a trace is a recording somebody asked
for and then reads; a log ring is a by-product.

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

## Reading

A reader holds a **sequence number** and asks what has happened since. That is
the same shape as `control.changes`, and it is deliberate: it works over a
channel that carries one bounded question and its answer, so a console four hops
away follows a log exactly as a page on the machine does.

| Operation | The question it answers |
|---|---|
| `logs.status` | Is anything kept, how much, how well does it compress |
| `logs.set` | `start` / `stop` / `clear` / `resize` (`megabytes`) |
| `logs.query` | The ring, newest first, through filters — what a person asks |
| `logs.since` | Everything after a sequence number, oldest first — what a subscriber asks |
| `logs.sources` | The names a filter can offer |

Filters: `level` (a **floor**, not an equality), `source` (substring), `topic`
(exact), `contains` (message *and* fields — a field must not be a place to put
something a search can never find), `since_time`, `until_time`, `limit`
(bounded by `MAX_QUERY` whoever asks).

Blocks carry their own sequence and time range, so a query decompresses only the
blocks that can hold an answer and leaves the rest packed. The lock is held to
copy the block list and released before any decompression: a query must never
stall a loop that is writing.

Nothing is buffered per subscriber. **The ring is the buffer**: a reader that
was away comes back with the number it last saw, and `since` answers `lost` —
how many lines went past while it was gone — rather than handing back a gap it
cannot see.

## One switch for two recordings

`trace.set` drives the log ring with it: starting a trace starts the log,
stopping stops both. "Turn the trace on" is one thing an operator does, and
finding out afterwards that half of it was off is the failure worth designing
out. `logs.set` remains for what that cannot express — sizing the ring, or
keeping the lines of a node whose packet headers you have no business recording.

## An app's half

Two unequal halves, over the data connector
([`Docs/DataConnector/guide`](../DataConnector/guide)):

* **Writing needs no grant.** The *node* stamps the source as
  `app:<app id[:16]>`, so an app can only ever be quoted as itself. An app able
  to set its own source could write lines that read as the core's, and a log an
  operator cannot attribute is worse than no log.
* **Reading needs the `logs` grant**, given per app in the console's Apps page
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
other one here.

## A fleet's half

One node's ring answers "what is happening here, now". An operator managing forty
machines has a different question — *what happened on any of them while nobody
was looking* — and a ring on a node that has since rebooted cannot answer it.

So the fleet app collects: a machine grants `logs` by name, the operator's node
follows it (always, only while a page is open on it, or never), and what arrives
is kept in **one bounded ring per machine** on the operator's node. A follow
expires unless renewed, carries the sequence number the operator already holds,
and is answered from the far ring — so a partition costs a gap that is reported
(`lost`) rather than a silence that is not. Details, bounds and the two grants it
needs: [`Docs/Apps/fleet`](../Apps/fleet).

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
