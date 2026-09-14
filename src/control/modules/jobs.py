"""
The ``jobs`` module: how an operation that cannot fit in one call travels.

Four operations, all of them small, all of them reachable from a console at a
distance — because the whole point is that the *long* thing stays here and only
the question about it crosses the mesh.

``jobs.start``
    Run a declared operation in the background. Refuses anything the caller
    could not have called directly, binds its arguments before a thread exists,
    and answers with a ticket.

``jobs.poll``
    What became of one ticket: still running, its answer, or its refusal — in
    the plane's own vocabulary, so a job that was refused reads exactly like a
    call that was refused.

``jobs.list``
    The tickets this console can see, so an operator who reloaded a page can
    find the install they started before it.

``jobs.forget``
    Drop a finished one. Not a cancellation: nothing here can un-install half a
    release, and a ticket dropped while its work continues is how somebody ends
    up running it twice.

The rules about reach, bounds and who may read a ticket are in
:mod:`src.control.jobs`, next to the book that enforces them.
"""
from __future__ import annotations

from ..jobs import JobBook
from ..params import param
from ..plane import operation

# Every one of these answers about state this process already holds — a
# dictionary and a lock, no loop, no file, no network. They are the smallest
# ceilings in the plane, and they have to be: a poll on a cadence is the cost of
# watching a four-minute install from the other side of a mesh.
_QUICK = 5.0


class JobsModule:
    """Long operations, started and watched from wherever the operator is."""

    NAME = "jobs"

    OPERATIONS = (
        operation("start", "Run a long operation in the background",
                  [param("op", "line"),
                   param("params", "payload", required=False, default=None)],
                  changes=True, remote=True, timeout=_QUICK,
                  wants_origin=True),
        operation("poll", "What became of one job",
                  [param("job", "line")],
                  remote=True, timeout=_QUICK, wants_origin=True),
        operation("list", "The jobs this console can see",
                  remote=True, timeout=_QUICK, wants_origin=True),
        operation("forget", "Drop a finished job",
                  [param("job", "line")],
                  changes=True, remote=True, timeout=_QUICK,
                  wants_origin=True),
    )

    def __init__(self, plane, context) -> None:
        self._book = JobBook(plane)
        self._context = context

    def op_start(self, op, params, origin) -> dict:
        return self._book.start(op, params or {}, origin)

    def op_poll(self, job, origin) -> dict:
        return self._book.poll(job, origin)

    def op_list(self, origin) -> dict:
        return self._book.listing(origin)

    def op_forget(self, job, origin) -> dict:
        return self._book.forget(job, origin)
