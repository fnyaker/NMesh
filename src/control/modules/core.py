"""
The ``control`` module: what this node exposes, and what has moved.

Two operations, and both exist so that a page does not have to guess.

``control.catalogue``
    Every operation reachable **right now, by whoever is asking**. A console
    driving another node reads that node's catalogue and draws only what it
    answers: a button for a module the far node does not run, or for one it
    will not expose to a remote console, is not drawn at all rather than drawn
    and then refused on the press. It is filtered by origin here, in the plane,
    because a page must never be the thing that decides what it may do.

``control.changes``
    The sequence number of what has moved, and the topic names since a caller's
    last one. This is the *pull* half of the change stream, and it is the half
    that works on every channel: the console can hold a ``text/event-stream``
    open for a page on this machine, but the relay to a managed node moves one
    bounded request and its answer — so a remote console used to fall back to a
    blind timer and be told nothing. Now it asks this on its cadence and
    repaints when something actually moved.
"""
from __future__ import annotations

from ..plane import Origin, operation
from ..params import param

# Both are answers about state this process already holds — no loop, no file, no
# network — so their ceilings are the smallest thing in the plane.
_QUICK = 5.0


class ControlModule:
    """Introspection over the plane it belongs to."""

    NAME = "control"

    OPERATIONS = (
        operation("catalogue", "Every operation reachable from here",
                  remote=True, timeout=_QUICK, wants_origin=True),
        operation("changes", "What has moved since a sequence number",
                  [param("since", "count", required=False, default=0)],
                  remote=True, timeout=_QUICK),
    )

    def __init__(self, plane, context) -> None:
        self._plane = plane
        self._context = context

    def op_catalogue(self, origin: str) -> dict:
        return {"modules": self._plane.catalogue(origin),
                "remote_ok": origin == Origin.REMOTE}

    def op_changes(self, since: int) -> dict:
        book = self._context.changes
        if book is None:
            # Nothing is watching for changes on this node, which is a real
            # answer: a caller then knows to stay on its cadence rather than
            # waiting for a sequence number that will never move.
            return {"available": False, "seq": 0, "topics": []}
        # Never waits. A relayed call must not hold a mesh handler open for a
        # tenth of a second longer than the answer needs, and a page that wants
        # to be woken rather than to ask has the stream for that.
        topics, seq = book.since(int(since), 0.0)
        return {"available": True, "seq": seq, "topics": topics}
