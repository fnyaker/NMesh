# Alerts — what wants a person's attention

A log says everything; an alert says *this one matters*. They are not the same
thing and one is not a filter over the other: the log is **off** until an
operator turns it on ([`logging.md`](logging.md)), and the conditions worth
telling somebody about are exactly the ones nobody had the foresight to start
recording.

So the notice board ([`src/alerts.py`](../../src/alerts.py)) is small, always on,
and deliberately poorer than the ring beside it.

## One entry per problem, not per occurrence

Entries are **keyed**. A repeat bumps a count and a timestamp rather than adding
a row, so three hundred refused handshakes are one line reading "300 times" —
the sentence an operator can act on, rather than a wall whose contents somebody
else chose. That is a readability decision and a safety one: a board that grew a
row per event would be a page an attacker writes.

`first` is kept beside `at`, because "since when" and "most recently" are
different questions and both get asked.

## Bounded, and the worst survives

`MAX_ALERTS` entries. When it is full the **least severe, oldest, already-seen**
entry goes first. Evicting by age alone is the obvious implementation and the
wrong one — a chatty warning would empty the board of exactly what it exists for.

Every axis a caller supplies is bounded (`MAX_SUMMARY`, `MAX_DETAIL`,
`MAX_SOURCE`, `MAX_KEY`), and `raise_alert` **never raises**: it is called from
receive loops and handlers, where an exception is a dropped packet or a dead
loop.

## Seen is not gone

`acknowledge` marks an entry read and leaves it on the board. "Is it still
happening?" is a question about the count, not about whether somebody dismissed
it. A problem that comes back is unread again, whatever was decided about it
last time. `drop` forgets one or all; whatever raised it raises it again if it
is still true, which is what makes forgetting safe to offer.

## Never a reason to act

Nothing here cuts a peer off, changes a setting, or writes to disk. What acts on
a peer is the reputation book, fed by what this node **saw itself**
(`src/reputation.py`); this is the notice board beside it, and
`tests/test_alerts.py` reads the module's own call graph to hold it to that.

## Who raises one

* **The node**, for the few conditions it is certain about — a peer whose
  standing crossed (so a peer this node has stopped enduring is a sentence an
  operator gets without having started a recording), and every failure a guard
  swallows (`src/faults.py`), keyed by where it happened.
* **An app**, over the connector (`_NOTIFY`, and `ConnectorClient.notify`). Only
  chat knows what "too many failed uploads" means for chat, exactly as only chat
  knows what abuse means for chat. The node attributes the notice — the key is
  namespaced `app:<id>:<key>` here, so one app can never overwrite another's
  entry or post as the core — and, like an abuse report, **nothing is answered**:
  a reply would let an app read the node's board back, and what else is wrong
  with this machine is the operator's business.

## Reading it

The board rides `node.state` (`alerts`: the rows, a count, how many are unread,
and the worst level), so every page that already reads the snapshot has it. The
control plane carries `alerts.list`, `alerts.ack` and `alerts.drop`, all
remotely reachable — a node that has a problem is exactly the node an operator is
not sitting in front of.

The console renders it as one card on the overview, above everything else, with
the count of *problems* and "N times" on the row that repeated.
