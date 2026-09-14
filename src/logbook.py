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
blocks that can contain an answer. A search over eight megabytes touches the
handful of blocks whose range overlaps and leaves the rest packed.
"""
from __future__ import annotations

import json
import re
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
    """A bounded, compressed ring of what this node said. Off until started.

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
        self._clock = clock
        self._lock = threading.Lock()
        self._limit = DEFAULT_BYTES
        self._seq = 0
        self._open: list = []          # the newest records, still readable raw
        self._blocks: list = []   # [(first, last, at_first, at_last, n, gz, raw)]
        self._packed = 0               # bytes held by those blocks
        self._raw = 0                  # what those blocks held before deflate
        self._dropped = 0              # lines lost to eviction, ever
        self._started_at = 0.0

    # -- lifecycle ---------------------------------------------------------

    def start(self, *, megabytes: float | None = None) -> dict:
        """Begin keeping lines, in a ring of this many megabytes."""
        with self._lock:
            if megabytes is not None:
                self._limit = max(MIN_BYTES,
                                  min(int(float(megabytes) * 1024 * 1024),
                                      MAX_BYTES))
            self._started_at = self._clock()
            self.enabled = True
        return self.status()

    def stop(self) -> dict:
        """Stop keeping lines. **What was kept is dropped**, not left to read.

        The opposite of `Trace.stop`, and on purpose: a trace is a recording an
        operator asked for and then reads. A log ring is a by-product, and one
        left sitting in memory after somebody stopped looking is exactly the
        record this node should not be holding."""
        with self._lock:
            self.enabled = False
            self._open = []
            self._blocks = []
            self._packed = self._raw = 0
        return self.status()

    def clear(self) -> None:
        with self._lock:
            self._open = []
            self._blocks = []
            self._packed = self._raw = 0
            self._dropped = 0

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
                self._open.append(entry)
                if len(self._open) >= BLOCK_RECORDS:
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
        # Evict whole blocks, oldest first. A ring that dropped single lines
        # would have to decompress a block to do it, which is the one thing
        # this shape exists to avoid.
        while self._packed > self._limit and self._blocks:
            _first, _last, _af, _al, count, gz, raw_size = self._blocks.pop(0)
            self._packed -= len(gz)
            self._raw -= raw_size
            self._dropped += count

    # -- reading -----------------------------------------------------------

    def status(self) -> dict:
        with self._lock:
            held = len(self._open) + sum(b[4] for b in self._blocks)
            # What the blocks held **before** deflate, measured at the moment
            # each was packed. Adding up the compressed sizes instead made the
            # ratio read 1.0 on a ring compressing forty to one — a number with
            # a label that was not true of it.
            raw = self._raw + len(json.dumps(self._open, separators=(",", ":")))
            oldest = (self._blocks[0][0] if self._blocks
                      else (self._open[0][0] if self._open else 0))
            return {
                "running": self.enabled,
                "megabytes": round(self._limit / 1024 / 1024, 2),
                "used_bytes": self._packed,
                "records": held,
                "blocks": len(self._blocks),
                "dropped": self._dropped,
                "seq": self._seq,
                "oldest_seq": oldest,
                "started_at": self._started_at or None,
                # What the compression is actually buying, measured rather than
                # claimed. An operator sizing a ring deserves the real number.
                "ratio": round(raw / self._packed, 1) if self._packed else None,
            }

    def since(self, seq: int, *, limit: int = MAX_QUERY, **filters) -> dict:
        """Everything after ``seq``, oldest first — the subscriber's question.

        A reader that was away comes back with the number it last saw and gets
        what it missed, or is told plainly that some of it is gone (`lost`).
        Nothing is buffered per subscriber: the ring is the buffer, and a reader
        too slow for it learns so rather than being lied to."""
        try:
            after = max(0, int(seq))
        except (TypeError, ValueError):
            after = 0
        rows, oldest = self._rows(after)
        answer = self._filter(rows, limit=limit, **filters)
        answer["lost"] = max(0, oldest - after - 1) if after and oldest else 0
        return answer

    def query(self, *, limit: int = MAX_QUERY, **filters) -> dict:
        """The whole ring, newest first — the question a person asks."""
        rows, _oldest = self._rows(0)
        answer = self._filter(rows, limit=limit, newest_first=True, **filters)
        return answer

    def _rows(self, after: int) -> tuple:
        """Every kept record after ``after``, decompressing only what can hold
        one. The lock is held to copy the block list and released before any
        deflate work: a query must never stall a loop that is writing."""
        with self._lock:
            blocks = [b for b in self._blocks if b[1] > after]
            open_rows = [e for e in self._open if e[0] > after]
            oldest = (self._blocks[0][0] if self._blocks
                      else (self._open[0][0] if self._open else 0))
        rows = []
        for _first, _last, _af, _al, _count, gz, _raw in blocks:
            try:
                for entry in json.loads(zlib.decompress(gz).decode("utf-8")):
                    if entry[0] > after:
                        rows.append(tuple(entry))
            except Exception:           # noqa: BLE001 — a lost block is not a crash
                continue
        rows.extend(open_rows)
        return rows, oldest

    @staticmethod
    def _filter(rows, *, limit: int = MAX_QUERY, newest_first: bool = False,
                level: str = "", source: str = "", topic: str = "",
                contains: str = "", since_time: float = 0.0,
                until_time: float = 0.0) -> dict:
        floor = _RANK.get(str(level or "").strip().lower(), 0)
        want_source = str(source or "").strip().lower()
        want_topic = str(topic or "").strip().lower()
        needle = str(contains or "").strip().lower()
        try:
            after_at = float(since_time or 0.0)
            before_at = float(until_time or 0.0)
        except (TypeError, ValueError):
            after_at = before_at = 0.0
        out = []
        for entry in rows:
            seq, at, lvl, src, top, message, fields = entry
            if _RANK.get(lvl, 1) < floor:
                continue
            if want_source and want_source not in src.lower():
                continue
            if want_topic and want_topic != top.lower():
                continue
            if after_at and at < after_at:
                continue
            if before_at and at > before_at:
                continue
            if needle and needle not in message.lower() \
                    and needle not in json.dumps(fields).lower():
                continue
            out.append(as_line(entry))
        total = len(out)
        try:
            bound = max(1, min(int(limit or MAX_QUERY), MAX_QUERY))
        except (TypeError, ValueError):
            # A limit that is not a number is a caller mistake, and the answer
            # to it is the ceiling rather than an exception: every reader here
            # is a socket, and a reply that never comes reads as a hung node.
            bound = MAX_QUERY
        if newest_first:
            out.reverse()
        cut = out[:bound]
        return {"lines": cut, "matched": total, "returned": len(cut),
                "seq": max((row["seq"] for row in cut), default=0)}

    # -- what a filter can offer ------------------------------------------

    def sources(self) -> list:
        """Every source that has said something, for a filter to offer.

        Read off the *open* block only. A filter listing names from a ring that
        may be an hour old would offer choices that match nothing, and finding
        that out costs a decompression of the whole ring."""
        with self._lock:
            return sorted({entry[3] for entry in self._open})
