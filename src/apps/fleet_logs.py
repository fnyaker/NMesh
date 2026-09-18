"""
The logs of the machines an operator looks after, kept on the operator's node.

Each managed node already keeps its own bounded ring (`src/logbook.py`), and a
console can read one over the plane. That answers "what is happening on that
machine *now*, while I am looking at it". It does not answer the question a
fleet actually has, which is "what happened on any of them while nobody was
looking" — a ring on a node that has since rebooted is gone, and a node that was
unreachable at the time had nobody to tell.

So the operator keeps a copy: one ring per managed node, on this machine.

**The same three refusals as the node's own ring**, for the same reasons — off
until an operator asks, bounded in megabytes, compressed a block at a time — and
two more that only exist because this one holds *other people's* logs:

**A budget per node, not one pool.** A node that says a great deal must not
push out the log of a node that says little, which is exactly what a shared ring
does and exactly what an adversary among the managed nodes would aim for. Each
node gets its own ring, sized by a fleet-wide default an operator may override
per node.

**A bounded number of rings.** `MAX_NODES` of them, and the one that has been
silent longest is dropped first. A fleet is 4096 nodes by `MAX_MANAGED`, and
4096 rings of the default size is not memory this process has.

Receiving is a policy per node, because collecting is not free and not always
wanted:

``always``
    Follow this node's log whenever we can reach it. For the handful of machines
    an operator actually watches.
``active``
    Follow it only while somebody is looking at it — a fleet page open on that
    node. The default, and the one that costs nothing in an empty room.
``never``
    Do not follow it at all. Its log is still readable on demand, by asking; it
    is simply never pushed here. For a node whose log is none of our business,
    or one on a metered link.

**And one ring more, which is not one of those.** The rings above answer "what
happened on that machine"; a console watching the whole network asks "what is
happening, anywhere, right now", and that is a different question with a
different shape. Answering it by merging N rings on every tick needs a cursor
per ring — a map the operator's page would have to carry and every layer between
would have to be widened for. So arrivals are written a second time, in order,
into one small ring of their own: :meth:`LogArchive.stream` is then
``LogBook.since`` on that ring, which is the subscriber shape the rest of this
product already speaks (`Docs/Architecture/logging.md`).

It is a second copy and that is the cost. It buys a single integer cursor, a
`lost` count a reader can act on, and the one property a live tail must have and
a fair merge must not: **the loudest machine wins**. A per-node budget exists so
that a node saying a great deal cannot push out a node saying little — that is
right for history and wrong for a tail, where a machine screaming *is* the news.
The two rules live in two rings rather than fighting over one.
"""
from __future__ import annotations

import threading
import time

from .. import logbook
from ..logbook import LogBook

# What one managed node's ring holds here by default, and what an operator may
# set it to. Smaller than a node's own default: this machine holds many.
DEFAULT_MEGABYTES = 2.0
MIN_MEGABYTES = round(logbook.MIN_BYTES / 1024 / 1024, 3)
MAX_MEGABYTES = 64.0

# Rings held at once. A fleet may hold `MAX_MANAGED` nodes; their logs may not.
MAX_NODES = 128

# The live tail, shared by every machine. Small on purpose: it is what a page
# has missed since it last asked, never a history — that is what the per-node
# rings above are, and a tail sized like one would be a second copy of them.
TAIL_MEGABYTES = 1.0


def _tagged(fields, **ours) -> dict:
    """One line's fields, under ours, bounded where the ring bounds them.

    ``ours`` goes on **first** and nothing that arrived may displace it or
    overwrite it. `clean_fields` keeps the first `MAX_FIELDS` entries, so a
    machine sending eight fields of its own — or one called ``node`` — could
    otherwise push out, or rewrite, who said the line and when. A machine we
    manage is an adversary that happens to hold a grant, and a line whose
    attribution its sender can set is a line that can be read as somebody
    else's."""
    out = dict(ours)
    room = max(0, logbook.MAX_FIELDS - len(out))
    if isinstance(fields, dict):
        for key, value in list(fields.items())[:room]:
            if key not in out:
                out[key] = value
    return out


ALWAYS, ACTIVE, NEVER = "always", "active", "never"
POLICIES = (ALWAYS, ACTIVE, NEVER)
DEFAULT_POLICY = ACTIVE

# How long "somebody is looking at this node" lasts after the last sign of it.
# A page says so as it polls; one that was closed simply stops saying it.
ACTIVE_TTL = 120.0


def clean_policy(raw) -> str:
    text = str(raw or "").strip().lower()
    return text if text in POLICIES else DEFAULT_POLICY


def clean_megabytes(raw, default: float = DEFAULT_MEGABYTES) -> float:
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return default
    if value <= 0:
        return default
    return round(min(max(value, MIN_MEGABYTES), MAX_MEGABYTES), 3)


class LogArchive:
    """One ring per managed node, bounded in size and in number.

    Holds no policy of its own: what to collect from whom is a decision an
    operator made and the ledger persists (`FleetState`), and a second copy here
    would be a second answer to one question.

    **Written from one thread and read from another.** Lines arrive on the
    node's loop (`FleetBridge._drain`) and every reader here is a console
    thread, so the table of rings is mutated under whoever is iterating it —
    which in CPython is a `RuntimeError`, not a stale answer, and a reader that
    can be made to raise by a machine speaking at the right moment is a crash
    somebody else can time. The lock is held to take a snapshot of *which*
    rings there are and released before any of them is read or written: each
    `LogBook` has its own lock for its own contents, and holding this one across
    a compression would put a page's poll in front of the loop that is
    writing."""

    def __init__(self) -> None:
        self._books: dict[str, LogBook] = {}
        self._seen: dict[str, int] = {}        # node -> last sequence absorbed
        self._touched: dict[str, float] = {}   # node -> when it last said anything
        self._active: dict[str, float] = {}    # node -> when a page last looked
        self._sizes: dict[str, float] = {}     # node -> megabytes, when set
        self._default = DEFAULT_MEGABYTES
        # Re-entrant: making room for a ring forgets one, and both take it.
        self._lock = threading.RLock()
        # Every arrival, once more, in the order this machine received them.
        # Started here rather than on demand: it is what a page subscribes to,
        # and a subscription that only begins working after the first line is a
        # page that shows nothing until something happens.
        self._tail = LogBook()
        self._tail.start(megabytes=TAIL_MEGABYTES)

    # -- sizing ------------------------------------------------------------

    @property
    def default_megabytes(self) -> float:
        return self._default

    def set_default_megabytes(self, megabytes) -> float:
        """Resize every ring that has no size of its own."""
        self._default = clean_megabytes(megabytes)
        with self._lock:
            rings = list(self._books.items())
        for node, book in rings:
            if node not in self._sizes:
                book.start(megabytes=self._default)
        return self._default

    def set_megabytes(self, node: str, megabytes) -> float:
        """Size one node's ring, or hand it back to the default (``0``)."""
        try:
            asked = float(megabytes)
        except (TypeError, ValueError):
            asked = 0.0
        if asked <= 0:
            self._sizes.pop(node, None)
            size = self._default
        else:
            size = self._sizes[node] = clean_megabytes(asked)
        book = self._books.get(node)
        if book is not None:
            book.start(megabytes=size)
        return size

    def megabytes_for(self, node: str) -> float:
        return self._sizes.get(node, self._default)

    # -- who is being looked at -------------------------------------------

    def note_active(self, node: str, now: float | None = None) -> None:
        """A page is open on this node. Said as it happens, never stored: a
        page that was closed stops saying it, and a process that died says
        nothing at all — both of which have to mean the same thing."""
        self._active[node] = now if now is not None else time.monotonic()
        while len(self._active) > MAX_NODES:
            self._active.pop(min(self._active, key=self._active.get), None)

    def is_active(self, node: str, now: float | None = None) -> bool:
        last = self._active.get(node)
        if last is None:
            return False
        moment = now if now is not None else time.monotonic()
        return (moment - last) <= ACTIVE_TTL

    def wants(self, node: str, policy: str, now: float | None = None) -> bool:
        """Should we be following this node's log right now?"""
        policy = clean_policy(policy)
        if policy == ALWAYS:
            return True
        if policy == NEVER:
            return False
        return self.is_active(node, now)

    # -- the rings ---------------------------------------------------------

    def book(self, node: str) -> LogBook:
        with self._lock:
            book = self._books.get(node)
            if book is None:
                while len(self._books) >= MAX_NODES:
                    self._drop_quietest()
                book = LogBook()
                book.start(megabytes=self.megabytes_for(node))
                self._books[node] = book
            self._touched[node] = time.monotonic()
            return book

    def _drop_quietest(self) -> None:
        """The ring nobody has heard from for longest. Dropping the *largest*
        would be the other option and it is the wrong one: it rewards a node
        for flooding by keeping its log and throwing away a quiet neighbour's.

        Called with the lock held. Making room is **not** forgetting: it is this
        machine running out of rings, not an operator saying they want a log
        gone, so the live tail is left alone. Clearing it here would mean a
        fleet at `MAX_NODES` wiping everybody's tail every time a new machine
        spoke."""
        if not self._touched:
            self._books.clear()
            return
        self._drop(min(self._touched, key=self._touched.get))

    def _drop(self, node: str) -> None:
        """Stop holding this node's ring. The table only."""
        with self._lock:
            book = self._books.pop(node, None)
            self._touched.pop(node, None)
            self._seen.pop(node, None)
            self._active.pop(node, None)
        if book is not None:
            book.stop()

    def forget(self, node: str) -> None:
        """An operator saying they want this machine's log gone.

        The tail goes with it. It holds one node's lines mixed into every
        other's and cannot drop a part, so the choice is between dropping all of
        it and going on answering with lines from a machine somebody asked us to
        forget — including handing them back the moment that machine speaks
        again and its ring is recreated. A reader loses the last few seconds of
        tail, which `since` reports as nothing lost, because nothing was lost
        that this console still holds."""
        self._drop(node)
        self._tail.clear()

    def clear(self) -> None:
        with self._lock:
            held = list(self._books)
        for node in held:
            self._drop(node)
        self._tail.clear()

    def seen(self, node: str) -> int:
        """The last sequence number we hold from this node — what a reconnecting
        follower asks from, so the node hands back only what we missed."""
        return self._seen.get(node, 0)

    def absorb(self, node: str, lines, *, lost: int = 0) -> int:
        """Take lines from one managed node. Returns how many were kept.

        Their sequence numbers are **that node's**, and they are kept as a field
        rather than re-used here: two nodes number their lines independently, so
        one ring numbered by whoever spoke last would answer `since` with
        somebody else's history."""
        if not isinstance(lines, (list, tuple)):
            return 0
        book = self.book(node)
        kept, highest = 0, self._seen.get(node, 0)
        if lost:
            gap = f"{int(lost)} lines were lost before this one"
            for ring in (book, self._tail):
                ring.record("fleet", gap, level=logbook.WARN, topic="gap",
                            fields={"node": node})
        for line in lines[:logbook.MAX_QUERY]:
            if not isinstance(line, dict):
                continue
            try:
                seq = int(line.get("seq") or 0)
            except (TypeError, ValueError):
                seq = 0
            if seq and seq <= highest:
                continue          # already held; a replayed page is not new news
            fields = line.get("fields")
            # Two times, and they are not the same claim. ``at`` is **ours**:
            # when this line reached this machine, which is what a merged view
            # is ordered by. ``said_at`` is the sending node's own word for
            # when it happened, kept because it is what an operator wants to
            # read and ordered by nothing, because a machine we manage is an
            # adversary that happens to hold a grant — one ordering by a time
            # it supplied could pin its lines to the top of the page for ever.
            tagged = _tagged(fields, node=node, seq=seq,
                             said_at=line.get("at"))
            book.record(line.get("source"), line.get("message"),
                        level=line.get("level"), topic=line.get("topic"),
                        fields=tagged)
            # The same line, in the order it arrived here, for whoever is
            # watching the whole network rather than one machine.
            self._tail.record(line.get("source"), line.get("message"),
                              level=line.get("level"), topic=line.get("topic"),
                              fields=tagged)
            highest = max(highest, seq)
            kept += 1
        self._seen[node] = highest
        self._touched[node] = time.monotonic()
        return kept

    # -- reading -----------------------------------------------------------

    def query(self, *, node: str = "", limit: int = logbook.MAX_QUERY,
              **filters) -> dict:
        """One node's lines, or every node's, newest first.

        Across nodes this is a merge rather than a scan of one ring, and the
        node is carried on each line: a fleet page filtering by node, by level
        and by text is asking one question, and answering it three times over
        three rings is how the three answers come back disagreeing."""
        with self._lock:
            # Name *and* ring together: looking the name up again afterwards is
            # a second chance for it to have gone.
            wanted = ([(node, self._books.get(node))] if node
                      else list(self._books.items()))
            held = sorted(self._books)
        rows = []
        for name, book in wanted:
            if book is None:
                continue
            for line in book.query(limit=logbook.MAX_QUERY, **filters)["lines"]:
                line["node"] = name
                rows.append(line)
        # By **our** clock: see `absorb`. Ties keep the order they were
        # absorbed in, which on one machine is the order they arrived.
        rows.sort(key=lambda line: line.get("at") or 0, reverse=True)
        bound = max(1, min(int(limit or logbook.MAX_QUERY), logbook.MAX_QUERY))
        return {"lines": rows[:bound], "matched": len(rows),
                "returned": min(len(rows), bound),
                "nodes": held}

    def stream(self, seq: int = 0, *,
               limit: int = logbook.MAX_QUERY) -> dict:
        """Everything that has arrived since ``seq``, from every machine.

        Oldest first, which is the order a tail is read in, and bounded like
        every other read here. A reader that fell behind the ring is told how
        much went past (``lost``) rather than handed a gap it cannot see.

        Lines from a machine whose ring we no longer hold are dropped on the
        way out, not left for the cursor: a node forgotten and then heard from
        again gets a new ring, and the tail must not answer for it with what it
        said before somebody pressed forget."""
        answer = self._tail.since(seq, limit=limit)
        with self._lock:
            held = set(self._books)
        lines = []
        for line in answer["lines"]:
            node = str((line.get("fields") or {}).get("node") or "")
            if node not in held:
                continue
            # On the line rather than only in its fields: every other reader
            # here is handed `node` that way, and one shape for one thing is
            # what keeps a page from having to know which reader answered it.
            line["node"] = node
            lines.append(line)
        return {"lines": lines,
                # What was *consumed*, not what was returned: a line dropped
                # above has still gone past, and a cursor that did not move
                # over it would hand it back for ever.
                "seq": answer["seq"] or seq,
                "lost": answer["lost"],
                "nodes": sorted(held)}


    def status(self) -> dict:
        nodes = {}
        with self._lock:
            rings = list(self._books.items())
        for name, book in rings:
            state = book.status()
            nodes[name] = {"records": state["records"],
                           "used_bytes": state["used_bytes"],
                           "dropped": state["dropped"],
                           "megabytes": state["megabytes"],
                           "seen": self._seen.get(name, 0),
                           "active": self.is_active(name)}
        tail = self._tail.status()
        return {"default_megabytes": self._default,
                "max_nodes": MAX_NODES,
                "used_bytes": sum(n["used_bytes"] for n in nodes.values()),
                "records": sum(n["records"] for n in nodes.values()),
                "nodes": nodes,
                # Counted apart, because it is a second copy and an operator
                # reading "how much of this machine is this costing" is owed
                # both halves rather than one of them quietly folded into the
                # other.
                "tail": {"records": tail["records"],
                         "used_bytes": tail["used_bytes"],
                         "megabytes": tail["megabytes"],
                         "seq": tail["seq"]}}
