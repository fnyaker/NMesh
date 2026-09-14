"""
The ``alerts`` module: what is wrong with this node, in one sentence each.

The log answers "what happened"; this answers "what should somebody look at".
They are separate on purpose (`src/alerts.py`): a log is off until an operator
turns it on, and the conditions worth telling a person about are exactly the
ones nobody had the foresight to start recording.

``alerts.list``
    Worst first, then newest — the order a person reads them in.

``alerts.ack``
    A person has seen this one. It stays on the board, because "is it still
    happening?" is a question about its count rather than about whether somebody
    dismissed it; it stops being *unread*.

``alerts.drop``
    Forget one, or all. Whatever raised it raises it again if it is still true,
    which is what makes forgetting safe to offer.

All three travel, because a node that has a problem is exactly the node an
operator is not sitting in front of.
"""
from __future__ import annotations

from ..params import param
from ..plane import operation

# Everything here reads or writes a bounded dict this process already holds.
_QUICK = 5.0


class AlertsModule:
    """The notice board: always on, bounded, and never a reason to act."""

    NAME = "alerts"

    OPERATIONS = (
        operation("list", "What is wrong here, worst first",
                  [param("unread", "flag", required=False, default=False)],
                  remote=True, timeout=_QUICK),
        operation("ack", "Mark one as seen, without taking it off the board",
                  [param("key", "text")],
                  changes=True, remote=True, timeout=_QUICK),
        operation("drop", "Forget one alert, or all of them",
                  [param("key", "text", required=False, default="")],
                  changes=True, remote=True, timeout=_QUICK),
    )

    def __init__(self, context) -> None:
        self._context = context

    @property
    def _book(self):
        return self._context.node.alerts

    def op_list(self, unread: bool) -> dict:
        book = self._book
        return dict(book.status(), alerts=book.alerts(unacknowledged=unread))

    def op_ack(self, key: str) -> dict:
        return {"ok": self._book.acknowledge(key), **self._book.status()}

    def op_drop(self, key: str) -> dict:
        return {"dropped": self._book.drop(key), **self._book.status()}
