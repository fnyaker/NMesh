"""
The ``trace`` module: the protocol trace, started and read.

The trace itself is bounded in memory *and* in time and stops on its own
(:mod:`src.trace`); what this adds is the same bound on the way **in**. An
operator asking for a week-long trace of a million packets gets the largest one
the node is willing to hold, not the one they typed — and the numbers are
clamped by the trace, not here, so there is one opinion about what "too much"
means.

Reachable from a remote console, deliberately: "what is this machine actually
sending?" is the question a distant node is hardest to answer without. It
carries routing metadata only — never a payload — which is what makes that safe
to hand to whoever the ledger already trusts to manage the node.
"""
from __future__ import annotations

from ...node import MESSAGE_NAMES
from ...trace import MAX_EVENTS, MAX_SECONDS
from ..params import param
from ..plane import operation

_READ = 5.0             # the trace is in this process; nothing to wait for
_EVENT_PAGE = 400       # events one status read may carry


class TraceModule:
    """Start it, stop it, read it, export it."""

    NAME = "trace"

    OPERATIONS = (
        operation("status", "The trace's state, totals and recent events",
                  [param("events", "flag", required=False, default=False)],
                  remote=True, timeout=_READ),
        operation("set", "Start, stop or clear the trace",
                  [param("action", "choice", choices=("start", "stop", "clear")),
                   # The trace's own ceilings, not a second opinion about them:
                   # an operator asking for a week-long trace of a million
                   # packets gets the largest one the node is willing to hold.
                   param("seconds", "count", required=False, default=0,
                         limit=int(MAX_SECONDS)),
                   param("events", "count", required=False, default=0,
                         limit=int(MAX_EVENTS))],
                  changes=True, remote=True, timeout=_READ),
        operation("export", "Everything held, as one document",
                  remote=True, timeout=_READ),
    )

    def __init__(self, context) -> None:
        self._context = context

    @property
    def _trace(self):
        return self._context.node.trace

    def op_status(self, events: bool) -> dict:
        trace = self._trace
        payload = {"status": trace.status(), "summary": trace.summary()}
        if events:
            payload["events"] = trace.events(limit=_EVENT_PAGE)
        return payload

    def op_set(self, action: str, seconds: int, events: int) -> dict:
        trace = self._trace
        if action == "start":
            # Zero means "whatever the trace's own default is": the caller left
            # the field alone, and this is not the place to invent a number.
            return trace.start(seconds=seconds, events=events,
                               names=MESSAGE_NAMES)
        if action == "stop":
            return trace.stop()
        trace.clear()
        return trace.status()

    def op_export(self) -> dict:
        return self._trace.export()
