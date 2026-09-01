"""
What an application uses to hold a peer to its own thresholds.

The node decides what reports add up to; the app decides what "too much" means,
because only it can. But every app that has needed this wrote the same loop
slightly differently — fleet counted signed requests per window, the core counts
gossip per link, chat counted nothing at all — and each one had to remember, on
its own, to tell the node afterwards. Two of the three forgot.

An :class:`AppGuard` is that loop, once, with the reporting attached:

.. code-block:: python

    guard = AppGuard(client, {
        "text":  Limit(40, 10.0),
        "offer": Limit(8, 10.0, weight=2),
    })
    ...
    if not guard.allow("text", src):
        return          # drop it; the node has been told

Why the limits are **per kind and not one bucket**
--------------------------------------------------
This is the whole reason this file exists rather than a single rate gate per
app. The messages an app receives are not comparable: a typing notice is a byte
and arrives constantly, a file offer allocates a reassembly buffer and should
arrive rarely, a media frame is the highest-rate thing on the mesh and
throttling it breaks a call. One shared bucket has to be set for the loudest of
them, which means the expensive ones get that same allowance — so "too many file
offers" and "too many group invitations", the two that actually cost something,
become unreachable in practice. Sized per kind, each ceiling can sit just above
what its own message legitimately does.

The weights follow the same reasoning. Flooding text is rude and might be a
stuck client; flooding profile updates or group invitations is not something a
correct client does at all, so it says more about the sender and is worth more.

Reporting, not blocking
-----------------------
`allow` returning False means *this app* drops the message. It is not a
sanction: the same sender walks straight on to the next app. What makes it cost
anything is the report, and the report is deliberately sent **once per spent
window** rather than per refused message — a peer flooding at ten thousand
messages a second must not make us call the node ten thousand times.
"""
from __future__ import annotations

from dataclasses import dataclass

from .node_id import NodeID
from .reputation import RateGate


@dataclass(frozen=True)
class Limit:
    """How much of one kind of message a single sender may send.

    ``weight`` is what a breach is worth to the node — see the module note: the
    messages a correct client never floods are worth more than the ones a stuck
    one might."""

    max_events: int
    window: float
    weight: int = 1
    max_senders: int = 512


class AppGuard:
    """One app's allowances, and the one place it reports a breach."""

    __slots__ = ("_client", "_limits", "_gates", "_spent", "_kind", "_spawn")

    def __init__(self, client, limits: dict, *, kind: int = 0,
                 spawn=None) -> None:
        self._client = client
        self._spawn = spawn
        self._limits = dict(limits)
        self._gates = {name: RateGate(limit.max_events, limit.window,
                                      limit.max_senders)
                       for name, limit in self._limits.items()}
        # (kind, sender) whose window is already spent and already reported.
        # Cleared when the gate lets that sender through again, which is how
        # "once per spent window" is expressed without a second timer.
        self._spent: set[tuple[str, bytes]] = set()
        self._kind = kind

    def allow(self, kind: str, sender: NodeID, *, now: float | None = None) -> bool:
        """Claim one message of ``kind`` from ``sender``.

        ``True`` to go on handling it. ``False`` means the app drops it — and,
        the first time in a window, that the node has been told."""
        gate = self._gates.get(kind)
        if gate is None:
            return True          # a kind with no declared limit is not gated
        if gate.allow(sender, now=now):
            self._spent.discard((kind, sender.raw))
            return True
        if (kind, sender.raw) not in self._spent:
            self._spent.add((kind, sender.raw))
            self._report(sender, kind)
        return False

    def forget(self, sender: NodeID) -> None:
        """Drop what we hold for one sender — a peer that has gone."""
        for kind, gate in self._gates.items():
            gate.forget(sender)
            self._spent.discard((kind, sender.raw))

    def _report(self, sender: NodeID, kind: str) -> None:
        """Hand the breach to the node. Never fatal, never awaited inline: an
        app that noticed a problem must not become one."""
        report = getattr(self._client, "report_abuse", None)
        if report is None:
            return
        weight = self._limits[kind].weight
        try:
            coro = report(sender, weight=weight, kind=self._kind,
                          reason=f"too many {kind}")
        except Exception:
            return
        if self._spawn is not None:
            try:
                self._spawn(coro)
                return
            except Exception:
                pass
        # Nowhere to run it: give the coroutine back rather than leave one
        # nobody awaits — that is a warning at collection time, from a line
        # with nothing to do with it.
        close = getattr(coro, "close", None)
        if close is not None:
            close()
