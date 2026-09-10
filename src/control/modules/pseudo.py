"""
The ``pseudo`` module: what this node is called, and who else is called what.

Two writes when a node is renamed, deliberately: the node signs a fresh claim
and announces it, and the configuration file records it so a restart keeps the
name. If the file cannot be written the rename still stands for this run and the
problem is reported — losing the name on the next start is worth saying, not
worth refusing the rename over.

Searching is **two operations, not one flag**, and that is the interesting part.
``search`` answers from the book this node already holds: instant, free, and
what a field searches as somebody types. ``lookup`` asks the directory, which is
a Kademlia round plus a query to every target it finds. They were one route with
a ``wide=1`` in the query string, and one route with two costs is a route whose
ceiling has to be the larger one — so the cheap question inherited the expensive
question's timeout, and neither could be given a ceiling that fitted the relay.
Named apart, each gets its own: the cheap one is reachable from a remote console
and the expensive one is not, because thirty seconds does not fit in what the
relay carries there and back.
"""
from __future__ import annotations

from ...pseudo import MAX_PSEUDO, PseudoError
from ..context import on_loop
from ..errors import ControlError
from ..params import param
from ..plane import operation
from .settings import write_settings

_LOCAL = 10.0           # this node's own name, or its own book
_WIDE = 30.0            # a directory round: bounded by the node, not by us
_SEARCH_MAX = 20


class PseudoModule:
    """This node's name, and the names it has learned."""

    NAME = "pseudo"

    OPERATIONS = (
        operation("get", "What this node is called",
                  remote=True, timeout=_LOCAL),
        operation("search", "Names this node already knows",
                  [param("query", "text"),
                   param("limit", "count", required=False, default=_SEARCH_MAX)],
                  remote=True, timeout=_LOCAL),
        operation("save", "Rename this node and sign a fresh claim",
                  [param("pseudo", "text", required=False, default="")],
                  changes=True, remote=True, timeout=_LOCAL),
        operation("lookup", "Ask the directory for a name",
                  [param("query", "text")], timeout=_WIDE),
    )

    def __init__(self, context) -> None:
        self._context = context

    @property
    def _node(self):
        return self._context.node

    def op_get(self) -> dict:
        return {"pseudo": self._node.pseudo,
                "id": self._node.id.raw.hex(),
                "max": MAX_PSEUDO}

    def op_search(self, query: str, limit: int) -> dict:
        results = self._context.ask(
            on_loop(self._node.find_pseudo, query,
                    min(int(limit) or _SEARCH_MAX, _SEARCH_MAX)), _LOCAL)
        return {"results": results, "wide": False}

    def op_lookup(self, query: str) -> dict:
        return {"results": self._context.ask(
            self._node.search_pseudo(query), _WIDE), "wide": True}

    def op_save(self, pseudo: str) -> dict:
        try:
            adopted = self._context.ask(
                on_loop(self._node.set_pseudo, pseudo), _LOCAL)
        except PseudoError as exc:
            raise ControlError("bad_request", str(exc)) from None
        # The name already survives a restart on its own — the node signed a
        # claim and its name store keeps it. What the file adds is that the
        # *declared* value agrees: a configuration still naming the old one
        # wins at startup, so leaving it stale is how a rename comes undone.
        saved, problem = (True, "")
        if self._context.config_path:
            saved, problem = write_settings(self._context.config_path,
                                            {"pseudo": adopted})
        else:
            saved = False   # nothing declares a name here; the store keeps it
        return {"ok": True, "pseudo": adopted, "saved": saved,
                "error": problem or None}
