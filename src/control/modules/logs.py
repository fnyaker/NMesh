"""
The ``logs`` module: what this node said, for whoever is allowed to read it.

Four operations, and the shape of them is the whole design.

``logs.status``
    Is anything being kept, how much, and how well it is compressing. An
    operator sizing a ring deserves the measured ratio rather than a claim.

``logs.set``
    Start, stop, resize, clear. **Nothing is kept until this says so**, and
    stopping drops what was kept rather than leaving it in memory — a log ring
    outliving the person reading it is a record this node has no business
    holding (`src/logbook.py`).

``logs.query``
    The question a person asks: the ring, newest first, through filters.

``logs.since``
    The question a *subscriber* asks: everything after a sequence number. Same
    shape as ``control.changes``, and for the same reason — it works over a
    channel that carries one bounded question and its answer, so a console four
    hops away follows a log exactly as a page on the machine does. A reader that
    lost its connection comes back with the number it last saw and is told
    plainly how much, if any, went past while it was away.

Reading a log is reading routing metadata — who this node talked to, when, and
what it thought about it — so both readers travel only as far as the console
that is allowed to see them. That is `remote=True` here and the fleet's `logs`
capability behind it, never one without the other.
"""
from __future__ import annotations

from ... import logbook
from ..params import param
from ..plane import operation

# Everything here reads or writes a structure this process already holds. The
# only one that does real work is a query, which decompresses the blocks whose
# range can hold an answer — a handful, not the ring.
_QUICK = 5.0
_READ = 10.0


class LogsModule:
    """What the node said, bounded, compressed, and kept only on request."""

    NAME = "logs"

    OPERATIONS = (
        operation("status", "Whether anything is kept, how much, and how well "
                            "it compresses",
                  remote=True, timeout=_QUICK),
        operation("set", "Start, stop, resize or clear what is kept",
                  [param("action", "choice",
                         choices=("start", "stop", "clear", "resize")),
                   param("megabytes", "count", required=False, default=0,
                         limit=logbook.MAX_BYTES // 1024 // 1024)],
                  changes=True, remote=True, timeout=_QUICK),
        operation("query", "The ring, newest first, through filters",
                  [param("level", "choice", required=False, default="",
                         choices=("",) + logbook.LEVELS),
                   param("source", "text", required=False, default=""),
                   param("topic", "text", required=False, default=""),
                   param("contains", "text", required=False, default=""),
                   param("since_time", "count", required=False, default=0),
                   param("until_time", "count", required=False, default=0),
                   param("limit", "count", required=False, default=0,
                         limit=logbook.MAX_QUERY)],
                  remote=True, timeout=_READ),
        operation("since", "Everything after a sequence number, oldest first",
                  [param("seq", "count", required=False, default=0),
                   param("level", "choice", required=False, default="",
                         choices=("",) + logbook.LEVELS),
                   param("source", "text", required=False, default=""),
                   param("limit", "count", required=False, default=0,
                         limit=logbook.MAX_QUERY)],
                  remote=True, timeout=_READ),
        operation("sources", "The names a filter can offer",
                  remote=True, timeout=_QUICK),
    )

    def __init__(self, context) -> None:
        self._context = context

    @property
    def _book(self):
        return self._context.node.logs

    def op_status(self) -> dict:
        return self._book.status()

    def op_set(self, action: str, megabytes: int) -> dict:
        book = self._book
        if action == "start":
            # Zero means "leave the size alone", which is what a caller who
            # only wanted it on has said. Inventing a number here would resize
            # a ring somebody had already sized on purpose.
            return book.start(megabytes=megabytes or None)
        if action == "resize":
            # Resizing a stopped ring is how an operator sets the size *before*
            # turning it on, which is the order anybody would use.
            was = book.status()["running"]
            book.start(megabytes=megabytes or None)
            return book.status() if was else book.stop()
        if action == "stop":
            return book.stop()
        book.clear()
        return book.status()

    def op_query(self, level, source, topic, contains, since_time, until_time,
                 limit) -> dict:
        return self._book.query(level=level, source=source, topic=topic,
                                contains=contains, since_time=since_time,
                                until_time=until_time, limit=limit)

    def op_since(self, seq, level, source, limit) -> dict:
        return self._book.since(seq, level=level, source=source, limit=limit)

    def op_sources(self) -> dict:
        return {"sources": self._book.sources()}
