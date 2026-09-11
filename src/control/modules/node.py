"""
The ``node`` module: this machine, as an operator acts on it.

The state snapshot, a ping, forgetting a node, dialling one back. What used to
be six routes in the console with their argument checks written inline, six
times, slightly differently.

Two of them are **not** reachable from a remote console, and the reason is a
ceiling rather than a secret:

* ``node.retry`` walks every address a node is known at, one dial each, and the
  node bounds the walk — not this. On a machine with several dead addresses that
  is a minute, and the relay to a managed node cannot carry a minute. Declaring
  it remote would mean an operator waiting for the pipe to give up and being
  told nothing about why (``Docs/Architecture/gotchas.md``, "a bound at one
  layer is not a bound"); refusing it says what happened.
"""
from __future__ import annotations

import time

from ... import updater
from ...pseudo import PseudoError
from .. import listing
from ..context import on_loop
from ..errors import ControlError
from ..params import param
from ..plane import operation

_READ = 10.0            # a snapshot, a certificate: state this node holds
_PING_NODE = 15.0       # may have to establish a link first, bounded by the node
_RETRY = 60.0           # one dial per known address, bounded by the node


class NodeModule:
    """The core's own management surface."""

    NAME = "node"

    OPERATIONS = (
        operation("state", "Everything the console draws about this node",
                  remote=True, timeout=_READ),
        operation("list", "The nodes this one is linked to, or has heard of",
                  [param("scope", "choice", choices=("active", "known")),
                   param("query", "text", required=False, default=""),
                   param("limit", "count", required=False,
                         default=listing.DEFAULT_LIMIT,
                         limit=listing.MAX_LIMIT),
                   param("offset", "count", required=False, default=0)],
                  remote=True, timeout=_READ),
        operation("ping", "Ping every authenticated peer now",
                  changes=True, remote=True, timeout=_READ),
        operation("ping_node", "Ping one known node and measure the round trip",
                  [param("node", "node")], remote=True, timeout=_PING_NODE),
        operation("forget", "Drop a node's addresses, sessions and live link",
                  [param("node", "node")], changes=True, remote=True,
                  timeout=_READ),
        operation("rootcert", "This node's self-signed root certificate, hex",
                  remote=True, timeout=_READ),
        operation("restart", "Stop this node properly and come back",
                  [param("confirm", "flag")],
                  changes=True, remote=True, timeout=_READ),
        operation("retry", "Dial a node's known addresses now",
                  [param("node", "node"),
                   param("uri", "line", required=False, default="")],
                  changes=True, timeout=_RETRY),
    )

    def __init__(self, context) -> None:
        self._context = context

    @property
    def _node(self):
        return self._context.node

    def _ask(self, coro, timeout: float):
        """Run something on the node's loop, and phrase its refusals.

        The node being stopped or slow is already ``unavailable``
        (:meth:`Context.ask`). What is added here is the other half: a value
        the node itself rejected is the *caller's* mistake, and telling an
        operator "the node did not answer" about an id they mistyped sends them
        looking at the wrong thing."""
        try:
            return self._context.ask(coro, timeout)
        except ControlError:
            raise
        except (PseudoError, ValueError) as exc:
            raise ControlError("bad_request", str(exc)) from None

    # -- reading ----------------------------------------------------------

    def op_state(self) -> dict:
        snapshot = self._ask(self._node.console_snapshot(), _READ)
        if not isinstance(snapshot, dict):
            raise ControlError("unavailable", "the node did not answer")
        snapshot["server_time"] = time.time()
        snapshot["apps"] = self._context.apps()
        snapshot["version"] = updater.__version__
        # Whether a restart would come back. The page needs it to decide
        # between offering the action and saying why not — so it is that
        # question, asked of `restart_plan`, not the narrower "is a service
        # manager watching?" it once was.
        can, why = updater.restart_possible()
        snapshot["can_restart"] = can
        snapshot["restart_blocked"] = why
        return snapshot

    def op_list(self, scope: str, query: str, limit: int, offset: int) -> dict:
        """One page of the table, sorted, filtered and counted here.

        The **active** scope answers one row per *link*, and a node may hold
        several — so it is paged by node. Paging by link would show one node
        twice across a boundary, once with each half, and would count links
        under a heading that says nodes."""
        if len(query or "") > listing.MAX_QUERY:
            # The `text` kind's own ceiling is wider than a search box needs,
            # and `listing.MAX_QUERY` is the figure the HTTP door already
            # enforces — one bound for the question, wherever it is asked.
            raise ControlError("bad_request",
                               f"a query is at most {listing.MAX_QUERY} characters")
        rows = self._ask(on_loop(self._node.console_nodes, scope), _READ)
        if scope == "known":
            rows.sort(key=lambda item: (item["seen_ago"], item["id"]))
        else:
            rows.sort(key=lambda item: (
                item["id"], item.get("transport") or "",
                item.get("is_client_side", False),
                tuple(item.get("addresses", ()))))
        matched = [item for item in rows
                   if listing.matches(item, (query or "").casefold())]
        limit = limit or listing.DEFAULT_LIMIT
        if scope == "active":
            page, total = listing.page_by_node(matched, offset, limit)
        else:
            page, total = matched[offset:offset + limit], len(matched)
        return {"items": page, "total": total, "limit": limit, "offset": offset}

    def op_rootcert(self) -> dict:
        return {"cert_hex": self._ask(
            on_loop(self._node.console_root_cert_hex), _READ)}

    # -- acting -----------------------------------------------------------

    def op_ping(self) -> dict:
        return {"ok": True, **self._ask(self._node.console_ping_peers(), _READ)}

    def op_ping_node(self, node: str) -> dict:
        return self._ask(self._node.console_ping_node(node), _PING_NODE)

    def op_forget(self, node: str) -> dict:
        forgotten = self._ask(self._node.console_forget_node(node), _READ)
        if not forgotten:
            # Not an error worth a code of its own: the node is not known here,
            # which is the state the caller was asking for.
            raise ControlError("not_found", "this node is not known here")
        return {"ok": True}

    def op_restart(self, confirm: bool) -> dict:
        """Restart this node, if something will bring it back.

        The gate is not the point of interest — the answer is. A console that
        says "restarting" and leaves the operator with a stopped node is worse
        than one that refuses, so the refusal is explicit and names the reason
        it came back with.

        Driven from another console this arrives at the *managed* node, which
        is exactly right: the operator asked to restart that machine, and it is
        that machine's service manager that answers for it."""
        if confirm is not True:
            raise ControlError("bad_request", "confirmation required")
        can, why = updater.restart_possible()
        if not can:
            raise ControlError("conflict",
                               "nothing would start this node again — " + why)
        return {"ok": True, "restarting": self._context.restart()}

    def op_retry(self, node: str, uri: str) -> dict:
        result = self._ask(
            self._node.console_retry_addresses(node, uri or ""), _RETRY)
        if isinstance(result, dict) and not result.get("ok"):
            # The node refuses this for reasons that are all the caller's: an
            # id it does not know, an address that belongs to somebody else,
            # ourselves. So it is `bad_request` and it carries the node's own
            # sentence — the operator needs to read which of the three it was.
            raise ControlError("bad_request", str(result.get("error") or
                                                  "nothing to dial")[:200])
        return result if isinstance(result, dict) else {"ok": True}
