"""
What this node *said*, kept only when somebody asked for it.

`trace.py` records what crosses the wire. This records what the node and its
apps were thinking while it did — the line a loop wrote when it gave up on an
address, the reason a handler dropped a packet, whatever an app chose to say.
Two different questions, and neither answers the other: a trace shows a
handshake that never completed, and a log says which gate refused it.

Three properties decide the whole shape of this file, and every one of them is a
refusal:

**Nothing is kept by default.** Not a truncated ring, not "just the errors" —
nothing. `record()` off is one attribute test and a return. A node that keeps
a log of itself is a node carrying evidence about who it talked to and when,
which is precisely the material the threat model says to hold as little of as
possible. So it is off, an operator turns it on for as long as they are looking,
and it stops being kept the moment they stop.

**The bound is in megabytes, because that is the question an operator actually
has.** "How many lines" is a number nobody can convert into "how much of this
machine". A ring bounded by records is a ring whose real size depends on how
chatty the code happened to be that day.

**It is compressed, and that is what makes the bound generous.** Log lines are
the most repetitive text a program produces — the same twenty messages, the same
node ids, the same field names. Whole *blocks* are compressed once each
(`BLOCK_RECORDS` at a time) rather than line by line: compression per line pays
the header cost on every one and finds nothing to repeat, and compressing the
whole ring on every write would be quadratic. So the cost is one deflate per few
hundred lines, and eight megabytes of ring holds on the order of a hundred
thousand of them.

Reading
-------
A reader holds a **sequence number** and asks what has happened since. That is
the same shape as ``control.changes`` and it is deliberate: it works over a
channel that carries one bounded question and its answer, so a console four hops
away follows a log exactly as a page on the machine does — and a subscriber that
loses its connection catches up by asking from the number it last saw, rather
than by anybody having to buffer for it.

Blocks carry their own sequence and time range, so a query decompresses only the
blocks that can contain an answer — and a person's question, newest first,
stops decompressing as soon as it has a page of them. A search over eight
megabytes touches the handful of blocks it needs and leaves the rest packed.

Who keeps it on
---------------
Three different things want a log kept, and none of them may switch off what
another asked for: an operator who pressed *Start*, a trace that is running, and
somebody following the log as it is written (an app, a fleet console). Each one
**holds** the ring under its own name and releases only its own hold; the ring
records while anybody holds it, and drops what it kept when the last one lets
go. A trace that stopped used to stop a log an operator had started on purpose,
and a follower was handed nothing at all, because nobody had happened to start
the ring on that machine.

A run, not only a number
------------------------
Sequence numbers start again from one when the process does — and a node
restarts every time it updates. So every answer names the **run** its numbers
belong to, and a reader that comes back with a number from another run is
answered from the start of this one instead of being told nothing moved.
"""
from __future__ import annotations

import json
import re
import secrets
import threading
import time
import zlib

# What one ring may hold, compressed, and what an operator may ask for. The
# ceiling is high because the whole point is that an operator sizes this to the
# machine; the default is what a laptop will not notice.
DEFAULT_BYTES = 8 * 1024 * 1024
MAX_BYTES = 512 * 1024 * 1024
MIN_BYTES = 64 * 1024

# Records compressed together. Small enough that what is still readable is
# always recent, large enough that deflate has something to find.
BLOCK_RECORDS = 512

# One line, bounded like every other thing a caller supplies. An app writes
# these, and an app is not trusted to be brief.
MAX_MESSAGE = 512
MAX_TOPIC = 48
MAX_SOURCE = 64
MAX_FIELDS = 8
MAX_FIELD_KEY = 32
MAX_FIELD_TEXT = 128
# What one query may answer with, whoever asks and however wide the filter.
MAX_QUERY = 500
# Names a filter can offer, remembered for as long as the ring runs. Bounded:
# a source is chosen by whoever writes, and an app is a writer.
MAX_SOURCES = 256
# The names a hold is taken under. Short and closed in spirit; bounded anyway,
# since a hold is the one thing that keeps lines being written.
MAX_HOLDER = 16
MAX_HOLDERS = 8
OPERATOR, TRACE, WATCH = "operator", "trace", "watch"

DEBUG, INFO, WARN, ERROR = "debug", "info", "warn", "error"
LEVELS = (DEBUG, INFO, WARN, ERROR)
_RANK = {name: number for number, name in enumerate(LEVELS)}


def rank(level) -> int:
    """How severe a level is, for a floor to compare against.

    Public because a *reader* needs it as much as this file does — a subscriber
    asks for "warn and above" and something has to decide what is above. An
    unknown name ranks as ``info``, the same repair `clean_level` makes, so one
    spelling mistake never silently filters everything out."""
    return _RANK.get(str(level or "").strip().lower(), _RANK[INFO])

_SOURCE_RE = re.compile(r"^[A-Za-z0-9_.:@-]{1,%d}$" % MAX_SOURCE)


def clean_level(raw) -> str:
    """A level, or ``info``. Never a refusal: a log line with a level nobody
    recognises is still a line worth keeping, and losing it to a typo in a
    diagnostic is the wrong trade."""
    text = str(raw or "").strip().lower()
    return text if text in _RANK else INFO


def clean_source(raw) -> str:
    """Who is speaking — a module name, or ``app:<id>``.

    Refused rather than repaired when it is not a name at all — **including
    when it is merely too long**. Truncating would have been the obvious repair
    and it is the wrong one: a source is what every filter in the product
    groups by, and two long names cut to the same sixty-four characters become
    one source that neither of them is."""
    text = str(raw or "").strip()
    return text if _SOURCE_RE.match(text) else "unknown"


def clean_fields(raw) -> dict:
    """The structured half of a line, bounded on every axis."""
    if not isinstance(raw, dict):
        return {}
    out = {}
    for key, value in list(raw.items())[:MAX_FIELDS]:
        name = str(key)[:MAX_FIELD_KEY]
        if isinstance(value, bool) or value is None or isinstance(value, int):
            out[name] = value
        elif isinstance(value, float):
            out[name] = value if value == value else None
        else:
            out[name] = str(value)[:MAX_FIELD_TEXT]
    return out


def as_line(entry) -> dict:
    """One record, as everything outside this file reads it.

    A record is a tuple in the ring (smaller to keep, faster to compress) and a
    dict everywhere else. One function makes the second from the first, so a
    line pushed to a subscriber and a line returned by a query cannot have
    different keys — which is the sort of difference a reader finds in
    production."""
    seq, at, level, source, topic, message, fields = entry
    return {"seq": seq, "at": at, "level": level, "source": source,
            "topic": topic, "message": message, "fields": fields}


class LogBook:
    """A bounded, compressed ring of what this node said. Off until held.

    Touched from the node's loop, from the console's threads and from whatever
    thread an app's connector runs on, so everything here takes the lock. The
    lock is held for a dict append and, once every few hundred lines, one
    deflate — never for a query's decompression, which works on a snapshot taken
    under it and released."""

    def __init__(self, *, clock=time.time) -> None:
        self.enabled = False
        # Handed each line as it is recorded, for whoever wants them *now*
        # rather than by asking. One sink, not a list: fanning out to several
        # subscribers is the job of the thing on the other end of it, which
        # already has to bound its own readers. Never allowed to raise —
        # `record()` is called from receive loops.
        self.sink = None
        # Which run of this process the sequence numbers belong to. They start
        # again from one when the process does, so a number alone cannot tell
        # a reader whether it is behind or from another life of this node.
        self.run = secrets.token_hex(8)
        self._clock = clock
        self._lock = threading.Lock()
        self._limit = DEFAULT_BYTES
        self._seq = 0
        self._open: list = []          # the newest records, still readable raw
        self._open_bytes = 0           # …and about how much memory they take
        self._blocks: list = []   # [(first, last, at_first, at_last, n, gz, raw)]
        self._packed = 0               # bytes held by those blocks
        self._raw = 0                  # what those blocks held before deflate
        self._dropped = 0              # lines lost to eviction, ever
        self._started_at = 0.0
        self._holders: set = set()     # who asked for lines to be kept
        self._sources: dict = {}       # every source heard since it started

    # -- lifecycle ---------------------------------------------------------

    def hold(self, holder: str = OPERATOR, *,
             megabytes: float | None = None) -> dict:
        """Keep lines on behalf of ``holder``, in a ring of this many
        megabytes if given. Holding twice under one name is holding once."""
        name = str(holder or OPERATOR)[:MAX_HOLDER]
        with self._lock:
            if megabytes is not None:
                self._resize(megabytes)
            if name not in self._holders and len(self._holders) >= MAX_HOLDERS:
                return self._status()
            if not self.enabled:
                self._started_at = self._clock()
            self._holders.add(name)
            self.enabled = True
            return self._status()

    def start(self, *, megabytes: float | None = None,
              holder: str = OPERATOR) -> dict:
        """Begin keeping lines — an operator's hold unless another is named."""
        return self.hold(holder, megabytes=megabytes)

    def release(self, holder: str = OPERATOR) -> dict:
        """Let go of one hold. When it was the last, **what was kept is
        dropped**, not left to read.

        The opposite of `Trace.stop`, and on purpose: a trace is a recording an
        operator asked for and then reads. A log ring is a by-product, and one
        left sitting in memory after everybody stopped looking is exactly the
        record this node should not be holding. Releasing a hold somebody else
        took is not possible: an operator's *Stop* must not take the lines from
        under a trace, nor a trace ending from under an operator."""
        with self._lock:
            self._holders.discard(str(holder or OPERATOR)[:MAX_HOLDER])
            if not self._holders:
                self._drop()
            return self._status()

    def stop(self) -> dict:
        """Every hold at once, and everything kept with them. What a node
        stopping does, and a ring that is somebody else's copy."""
        with self._lock:
            self._holders.clear()
            self._drop()
            return self._status()

    def resize(self, megabytes) -> dict:
        """A new size, applied now — the oldest blocks go at once rather than
        at the next write — whether or not anything is being kept."""
        with self._lock:
            self._resize(megabytes)
            return self._status()

    def clear(self) -> None:
        """Drop what is kept and go on keeping."""
        with self._lock:
            self._open = []
            self._open_bytes = 0
            self._blocks = []
            self._packed = self._raw = 0
            self._dropped = 0
            self._sources = {}

    def _drop(self) -> None:
        """Under the lock: stop, and keep nothing."""
        self.enabled = False
        self._open = []
        self._open_bytes = 0
        self._blocks = []
        self._packed = self._raw = 0
        self._sources = {}

    def _resize(self, megabytes) -> None:
        """Under the lock."""
        try:
            asked = float(megabytes)
        except (TypeError, ValueError):
            return
        self._limit = max(MIN_BYTES, min(int(asked * 1024 * 1024), MAX_BYTES))
        self._evict()

    def _open_cap(self) -> int:
        """How much the open block may weigh before it is packed."""
        return max(_MIN_OPEN, self._limit // 8)

    def _evict(self) -> None:
        """Under the lock. Whole blocks, oldest first. A ring that dropped
        single lines would have to decompress a block to do it, which is the
        one thing this shape exists to avoid.

        The open block counts against the size like the packed ones: it is
        memory this node holds, and leaving it out let a small ring hold a few
        hundred kilobytes it said it did not. So room for a whole open block is
        kept free: the packed ones may use the size less that."""
        while self._packed > max(0, self._limit - self._open_cap()) and self._blocks:
            _first, _last, _af, _al, count, gz, raw_size = self._blocks.pop(0)
            self._packed -= len(gz)
            self._raw -= raw_size
            self._dropped += count

    # -- writing -----------------------------------------------------------

    def record(self, source: str, message: str, *, level: str = INFO,
               topic: str = "", fields=None) -> None:
        """One line. **Never raises.**

        Called from loops, from handlers and from apps, which means it is called
        from places where an exception is a dropped packet or a dead loop. A
        diagnostic that can break what it is diagnosing is worse than none."""
        if not self.enabled:
            return
        try:
            entry = (
                self._seq + 1,
                round(self._clock(), 3),
                clean_level(level),
                clean_source(source),
                str(topic or "")[:MAX_TOPIC],
                str(message or "")[:MAX_MESSAGE],
                clean_fields(fields),
            )
            with self._lock:
                if not self.enabled:
                    return
                self._seq += 1
                entry = (self._seq,) + entry[1:]
                self._open.append(entry)
                self._open_bytes += _weight(entry)
                said = self._sources.get(entry[3])
                if said is not None or len(self._sources) < MAX_SOURCES:
                    self._sources[entry[3]] = (said or 0) + 1
                # By count, and by size: a block of long lines in a small ring
                # would otherwise be most of the ring before it was compressed.
                if (len(self._open) >= BLOCK_RECORDS
                        or self._open_bytes >= self._open_cap()):
                    self._pack()
                sink = self.sink
        except Exception:               # noqa: BLE001 — never the reason
            self._dropped += 1
            return
        if sink is None:
            return
        # Outside the lock: a subscriber is not allowed to hold up the loop
        # that is writing, and a sink that blocks or raises costs one line and
        # nothing else.
        try:
            sink(as_line(entry))
        except Exception:               # noqa: BLE001 — a reader, never a risk
            pass

    def _pack(self) -> None:
        """Compress the open block and make room for it. Under the lock."""
        raw = json.dumps(self._open, separators=(",", ":")).encode("utf-8")
        packed = zlib.compress(raw, 6)
        self._blocks.append((self._open[0][0], self._open[-1][0],
                             self._open[0][1], self._open[-1][1],
                             len(self._open), packed, len(raw)))
        self._packed += len(packed)
        self._raw += len(raw)
        self._open = []
        self._open_bytes = 0
        self._evict()

    # -- reading -----------------------------------------------------------

    def status(self) -> dict:
        with self._lock:
            return self._status()

    def _status(self) -> dict:
        """Under the lock."""
        held = len(self._open) + sum(b[4] for b in self._blocks)
        return {
            "running": self.enabled,
            # Who is keeping it on. A ring that goes on recording after an
            # operator pressed Stop has to say whose it is, or *Stop* reads as
            # broken.
            "held_by": sorted(self._holders),
            "megabytes": round(self._limit / 1024 / 1024, 2),
            # Everything held: the packed blocks and the open one. It was the
            # packed blocks alone, so a fresh ring read "0 B of 8 MB" over
            # lines it was plainly holding.
            "used_bytes": self._packed + self._open_bytes,
            "records": held,
            "blocks": len(self._blocks),
            "dropped": self._dropped,
            "seq": self._seq,
            "run": self.run,
            "oldest_seq": self._oldest(),
            "started_at": self._started_at or None,
            # What the compression is actually buying, measured rather than
            # claimed: what the packed blocks held before deflate over what
            # they hold now. Dividing the compressed size by itself read 1.0
            # on a ring compressing forty to one; counting the open block's raw
            # bytes on top read better than it was.
            "ratio": round(self._raw / self._packed, 1) if self._packed else None,
        }

    def _oldest(self) -> int:
        """Under the lock."""
        if self._blocks:
            return self._blocks[0][0]
        return self._open[0][0] if self._open else 0

    def since(self, seq: int, *, run: str = "", limit: int = MAX_QUERY,
              **filters) -> dict:
        """Everything after ``seq``, oldest first — the subscriber's question.

        A reader that was away comes back with the number it last saw and gets
        what it missed, or is told plainly that some of it is gone (`lost`).
        Nothing is buffered per subscriber: the ring is the buffer, and a reader
        too slow for it learns so rather than being lied to.

        The ``seq`` that comes back is **where to ask from next**: the last
        line this answer looked at, matched or not. It used to be the newest
        line *returned*, so a filter that matched nothing in the window
        answered 0 — and a reader that took that at its word asked for the
        whole ring again, every time. ``more`` says a page was cut at ``limit``
        and the next question will have more to give.

        ``run`` is the run the reader's number came from. A different one means
        this node restarted since: the number is from another life, and the
        answer starts from the beginning of this one (``restarted``)."""
        try:
            after = max(0, int(seq))
        except (TypeError, ValueError):
            after = 0
        restarted = bool(run) and str(run) != self.run
        if restarted:
            after = 0
        bound = _bound(limit)
        keep = _matcher(**filters)
        with self._lock:
            blocks = [b for b in self._blocks if b[1] > after]
            open_rows = [e for e in self._open if e[0] > after]
            oldest = self._oldest()
            newest = self._seq
        out, cursor, more = [], max(after, newest), False

        def rows():
            for block in blocks:
                yield from _unpack(block)
            yield from open_rows

        for entry in rows():
            if entry[0] <= after:
                continue
            if len(out) >= bound:
                more = True
                break
            cursor = entry[0]
            if keep(entry):
                out.append(as_line(entry))
        if more:
            cursor = out[-1]["seq"] if out else after
        return {"lines": out, "matched": len(out), "returned": len(out),
                "seq": cursor, "more": more, "run": self.run,
                "restarted": restarted,
                "lost": max(0, oldest - after - 1) if after and oldest else 0}

    def query(self, *, limit: int = MAX_QUERY, before_seq: int = 0,
              **filters) -> dict:
        """The ring, newest first, through filters — the question a person asks.

        Decompresses from the newest block backwards and **stops once it has a
        page**: a person reading a log reads its end, and a query used to
        unpack the whole ring to show them its last screen. ``more`` says there
        is older matching material than this page holds; ``before_seq`` asks
        for the page before it (lines numbered below that). Blocks entirely
        outside the asked time range are skipped without being opened."""
        bound = _bound(limit)
        keep = _matcher(**filters)
        try:
            below = max(0, int(before_seq or 0))
        except (TypeError, ValueError):
            below = 0
        after_at, before_at = _times(filters)
        with self._lock:
            blocks = list(self._blocks)
            open_rows = list(self._open)
            head = self._seq
        out, more = [], False

        def newest_first():
            yield from reversed(open_rows)
            for block in reversed(blocks):
                first, _last, at_first, at_last = block[:4]
                if below and first >= below:
                    continue
                if before_at and at_first > before_at:
                    continue
                if after_at and at_last < after_at:
                    break       # every older block ends earlier still
                yield from reversed(_unpack(block))

        for entry in newest_first():
            if below and entry[0] >= below:
                continue
            if not keep(entry):
                continue
            if len(out) >= bound:
                more = True
                break
            out.append(as_line(entry))
        # `head` is the newest line the ring held when this answer was taken:
        # where a reader that has just painted the end of the log follows
        # from with `since`, so nothing written meanwhile is lost and nothing
        # shown is shown twice — whatever the filter matched.
        return {"lines": out, "matched": len(out), "returned": len(out),
                "more": more, "run": self.run, "head": head,
                "seq": max((row["seq"] for row in out), default=0)}

    # -- what a filter can offer ------------------------------------------

    def sources(self) -> list:
        """Every source that has said something since the ring started, for a
        filter to offer.

        Counted as lines are written rather than read off the ring: the open
        block is emptied every few hundred lines, so reading it offered almost
        nothing just after a pack, and reading the packed blocks would cost a
        decompression of the whole ring to fill a drop-down."""
        with self._lock:
            return sorted(self._sources)


# The open block is packed early once it weighs an eighth of the ring, but
# never below this: compressing every handful of lines finds nothing to repeat.
_MIN_OPEN = 16 * 1024


def _weight(entry) -> int:
    """About what one record costs to hold, without serialising it: the text
    it carries plus a tuple's worth of overhead. A bound, not an invoice."""
    _seq, _at, level, source, topic, message, fields = entry
    extra = sum(len(str(key)) + len(str(value)) + 8
                for key, value in fields.items())
    return 64 + len(level) + len(source) + len(topic) + len(message) + extra


def _bound(limit) -> int:
    try:
        return max(1, min(int(limit or MAX_QUERY), MAX_QUERY))
    except (TypeError, ValueError):
        # A limit that is not a number is a caller mistake, and the answer
        # to it is the ceiling rather than an exception: every reader here
        # is a socket, and a reply that never comes reads as a hung node.
        return MAX_QUERY


def _times(filters) -> tuple:
    try:
        return (float(filters.get("since_time") or 0.0),
                float(filters.get("until_time") or 0.0))
    except (TypeError, ValueError):
        return 0.0, 0.0


def _unpack(block) -> list:
    """One block's records, or none: a lost block is not a crash."""
    try:
        return [tuple(entry) for entry in
                json.loads(zlib.decompress(block[5]).decode("utf-8"))]
    except Exception:                   # noqa: BLE001
        return []


def _matcher(*, level: str = "", source: str = "", topic: str = "",
             contains: str = "", since_time: float = 0.0,
             until_time: float = 0.0):
    """One predicate over a record, from the filters every reader shares."""
    floor = _RANK.get(str(level or "").strip().lower(), 0)
    want_source = str(source or "").strip().lower()
    want_topic = str(topic or "").strip().lower()
    needle = str(contains or "").strip().lower()
    after_at, before_at = _times({"since_time": since_time,
                                  "until_time": until_time})

    def keep(entry) -> bool:
        _seq, at, lvl, src, top, message, fields = entry
        if _RANK.get(lvl, 1) < floor:
            return False
        if want_source and want_source not in src.lower():
            return False
        if want_topic and want_topic != top.lower():
            return False
        if after_at and at < after_at:
            return False
        if before_at and at > before_at:
            return False
        # Message *and* fields: a field must not be a place to put something a
        # search can never find.
        if needle and needle not in message.lower() \
                and needle not in json.dumps(fields).lower():
            return False
        return True

    return keep
