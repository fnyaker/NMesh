"""
The ``packages`` module: the directory, and what this node does with a record.

**Nothing is listed, which is the point** — an unlisted directory is one nobody
can flood with entries nobody asked for. You ask it a question (this name, or
this node) and signed records come back.

The same split as names, for the same reason: *what this node already knows* is
instant and free, and *asking the network* is a Kademlia round plus a query to
every target it finds. They were one route with a `wide=1`, which meant one
ceiling for both — the cheap question inherited the expensive one's, and neither
could be given one that fits the relay. Apart, `search` and `held` answer a
console managing this node, and `lookup` does not travel at all.

Acting on a record — installing it, pinning the key that signed it, watching the
package it names — stays local for the reason spelled out in
:mod:`src.control.modules.releases`: what a node accepts for replacing its own
programs is pinned by a human at that node, and installing is minutes of work
rather than a call.
"""
from __future__ import annotations

from ..context import on_loop
from ..errors import ControlError
from ..params import MAX_ID_HEX, param
from ..plane import operation

_READ = 10.0
_WIDE = 30.0             # a directory round: bounded by the node, not by us
_FETCH = 60.0            # pulling a descriptor the record points at
_INSTALL = 400.0         # fetch, verify, unpack — a release, not a call


class PackagesModule:
    """Ask the directory, then decide what to do with what came back."""

    NAME = "packages"

    OPERATIONS = (
        operation("search", "Packages this node already knows, by name",
                  [param("query", "text")], remote=True, timeout=_READ),
        operation("held", "What this node knows one machine holds and serves",
                  [param("node", "node")], remote=True, timeout=_READ),
        operation("entry", "One signed record, as this node holds it",
                  [param("record", "hex", limit=MAX_ID_HEX)],
                  remote=True, timeout=_READ),
        operation("lookup", "Ask the network — by name, or about one node",
                  [param("query", "text", required=False, default=""),
                   param("node", "node", required=False, default="")],
                  timeout=_WIDE),
        operation("describe", "Pull the descriptor a record points at",
                  [param("record", "hex", limit=MAX_ID_HEX)],
                  timeout=_FETCH),
        operation("install", "Fetch, verify and install what a record names",
                  [param("record", "hex", limit=MAX_ID_HEX),
                   param("confirm", "flag")],
                  changes=True, timeout=_INSTALL),
        operation("trust", "Pin the key that signed this record's release",
                  [param("record", "hex", limit=MAX_ID_HEX),
                   param("confirm", "flag"),
                   param("auto", "flag", required=False, default=False),
                   param("endorsed", "flag", required=False, default=False)],
                  changes=True, timeout=_READ),
        operation("subscribe", "Watch the package a record names, or stop",
                  [param("record", "hex", limit=MAX_ID_HEX),
                   param("on", "flag", required=False, default=True),
                   param("auto", "flag", required=False, default=False),
                   param("quorum", "count", required=False, default=1)],
                  changes=True, timeout=_READ),
    )

    def __init__(self, context) -> None:
        self._context = context

    @property
    def _node(self):
        return self._context.node

    def _ask(self, coro, timeout: float):
        try:
            return self._context.ask(coro, timeout)
        except ControlError:
            raise
        except (TypeError, ValueError) as exc:
            raise ControlError("bad_request", str(exc)[:200]) from None
        except Exception as exc:
            raise ControlError("failed", f"{type(exc).__name__}") from None

    # -- asking ------------------------------------------------------------

    def op_search(self, query: str) -> dict:
        return {"results": self._ask(
            on_loop(self._node.find_packages, query), _READ), "wide": False}

    def op_held(self, node: str) -> dict:
        return {"results": self._ask(
            self._node.packages_of(node, wide=False), _READ), "wide": False}

    def op_lookup(self, query: str, node: str) -> dict:
        """One question, asked of the network. Exactly one of the two."""
        if bool(query) == bool(node):
            raise ControlError("bad_request",
                               "ask by name or about one node, not both")
        if node:
            found = self._ask(self._node.packages_of(node, wide=True), _WIDE)
        else:
            found = self._ask(self._node.search_packages(query), _WIDE)
        return {"results": found, "wide": True}

    def op_entry(self, record: str) -> dict:
        entry = self._ask(on_loop(self._node.package_entry, record), _READ)
        if entry is None:
            raise ControlError("not_found", "this node holds no such record")
        return {**entry, "descriptor": None}

    def op_describe(self, record: str) -> dict:
        entry = self._ask(on_loop(self._node.package_entry, record), _READ)
        if entry is None:
            raise ControlError("not_found", "this node holds no such record")
        # The descriptor is fetched from whoever serves it, so it may simply
        # not arrive. That is not a failure of the record, and the page still
        # has the record to draw.
        try:
            described = self._ask(self._node.package_descriptor(record), _FETCH)
        except ControlError:
            described = None
        return {**entry, "descriptor": described}

    # -- acting ------------------------------------------------------------

    def op_install(self, record: str, confirm: bool) -> dict:
        if confirm is not True:
            raise ControlError("bad_request", "confirmation required")
        result = self._ask(self._node.install_package(record), _INSTALL)
        # A node release only takes effect when the node comes back on the tree
        # just written; an app is live where it stands.
        restarting = (self._context.restart()
                      if result.get("restart_required") else False)
        return {"ok": True, **result, "restarting": restarting}

    def op_trust(self, record: str, confirm: bool, auto: bool,
                 endorsed: bool) -> dict:
        """Pin the key **inside** the record, never a hex string pasted in.

        It arrived with the signature it made, checked against it, so this is a
        confirmation of a record rather than a key copied out of a channel
        nobody could vouch for."""
        if confirm is not True:
            raise ControlError("bad_request", "confirmation required")
        return {"ok": True, "publisher": self._ask(
            on_loop(self._node.trust_package_signer, record,
                    auto=auto, endorsed=endorsed), _READ)}

    def op_subscribe(self, record: str, on: bool, auto: bool,
                     quorum: int) -> dict:
        if on is False:
            if not self._ask(on_loop(self._node.unsubscribe_package, record),
                             _READ):
                raise ControlError("not_found", "this node watches no such thing")
            return {"ok": True}
        return {"ok": True, "subscription": self._ask(
            on_loop(self._node.subscribe_package, record, auto=auto,
                    quorum=max(1, int(quorum or 1))), _READ)}
