"""
The ``store`` module: deployed apps — what the network offers, what is here.

An **app** rather than the node's own program, and the difference decides what
travels. Installing a node release replaces the code this process is running;
installing an app writes a directory and starts something beside it. So an
operator managing a machine may install, update and remove apps on it — that is
what managing a machine is — while what may replace its *program* stays pinned
by a human at that machine (:mod:`src.control.modules.releases`).

The store decides nothing here either. Which apps may be installed at all is
the signed catalogue and the keys this node has pinned; this is the door an
operator knocks on, not a second opinion about what is behind it. And the
*answers* are the node's: ``store_overview`` already annotates each row with the
state it is in and the verb to press, so a page renders rather than re-derives
(``CLAUDE.md``: derive, do not re-derive).

Publishing an app is not here, and will not be: it carries the files
themselves, which is bytes rather than a sentence, and a control frame is
capped to what the relay carries.
"""
from __future__ import annotations

from .. import listing
from ..context import on_loop
from ..errors import ControlError
from ..params import param
from ..plane import operation

_READ = 10.0
# Installing an app fetches it from whoever serves it and writes it down —
# bounded by the node, and short enough to fit what the relay carries so a
# managed machine's apps can be managed from the console that manages it.
_WORK = 15.0


class StoreModule:
    """The catalogue, the installed set, and the three verbs between them."""

    NAME = "store"

    OPERATIONS = (
        operation("overview", "The catalogue and what is installed, annotated",
                  remote=True, timeout=_READ),
        operation("list", "One page of the catalogue, or of what is installed",
                  [param("scope", "choice", choices=("catalog", "installed")),
                   param("query", "text", required=False, default=""),
                   param("limit", "count", required=False,
                         default=listing.DEFAULT_LIMIT,
                         limit=listing.MAX_LIMIT),
                   param("offset", "count", required=False, default=0)],
                  remote=True, timeout=_READ),
        operation("install", "Install an app from the catalogue",
                  [param("app", "text")], changes=True, remote=True,
                  timeout=_WORK),
        operation("update", "Install the newer version of an installed app",
                  [param("app", "text")], changes=True, remote=True,
                  timeout=_WORK),
        operation("uninstall", "Remove an installed app",
                  [param("app", "text")], changes=True, remote=True,
                  timeout=_READ),
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

    # -- reading -----------------------------------------------------------

    def op_overview(self) -> dict:
        return self._ask(on_loop(self._node.store_overview), _READ)

    def op_list(self, scope: str, query: str, limit: int, offset: int) -> dict:
        if len(query or "") > listing.MAX_QUERY:
            raise ControlError("bad_request",
                               f"a query is at most {listing.MAX_QUERY} characters")
        if scope == "catalog":
            rows = self._ask(on_loop(self._node.store_overview), _READ)["catalog"]
            rows.sort(key=lambda item: (-item["ts"], item["app_id"]))
        else:
            rows = self._ask(on_loop(self._node.installed_list), _READ)
            rows.sort(key=lambda item: (str(item.get("name", "")).casefold(),
                                        str(item.get("app_id", ""))))
        matched = [row for row in rows
                   if listing.matches(row, (query or "").casefold())]
        limit = limit or listing.DEFAULT_LIMIT
        return {"items": matched[offset:offset + limit], "total": len(matched),
                "limit": limit, "offset": offset}

    # -- acting ------------------------------------------------------------

    def op_install(self, app: str) -> dict:
        return self._one(self._node.install_app(self._named(app)), "install")

    def op_update(self, app: str) -> dict:
        return self._one(self._node.update_app(self._named(app)), "update")

    def op_uninstall(self, app: str) -> dict:
        if not self._ask(on_loop(self._node.uninstall_app, self._named(app)),
                         _READ):
            raise ControlError("not_found", "no such app is installed")
        return {"ok": True}

    @staticmethod
    def _named(app: str) -> str:
        """Naming nothing is a malformed call, not a call for something that
        does not exist — and an operator reading a 404 would go looking for a
        missing app rather than at what their client sent."""
        if not app:
            raise ControlError("bad_request", "an app is required")
        return app

    def _one(self, coro, what: str) -> dict:
        result = self._ask(coro, _WORK)
        if result is None:
            # The node says no by answering with nothing: an app id nobody
            # offers, or a version that is not there any more.
            raise ControlError("not_found", f"there is nothing to {what}")
        return {"ok": True, "app": result}
