"""
The ``apps`` module: what the apps running on this node can be asked to do.

An app already declares its operations (:mod:`src.app_api`) — the node view
asks chat whether it has a conversation with a node, and fleet whether it
manages it, without either of them owning a route. This puts that surface on
the same channel as everything else, which is what lets an app be driven on a
node somebody manages instead of only on the one serving the page.

**Two gates, and they are not the same gate.**

The plane's own ``remote`` decides whether a *remote console may reach the app
surface at all*; the app's per-operation ``remote`` decides which of its
operations that console may then call. Both default to no, so an app added
tomorrow is unreachable from a distance until its author writes down which of
its operations may travel — and the two built-in apps take that default on
purpose. Chat's conversations were never part of managing somebody's machine,
and fleet's own operations would turn a node one operator manages into a way to
reach the nodes *it* manages (``Docs/Apps/fleet``).

The enforcement is here rather than in the app API, because this is the layer
that knows who is asking. An app must not have to.
"""
from __future__ import annotations

from ... import app_api
from ..errors import ControlError
from ..params import param
from ..plane import Origin, operation

_READ = 10.0
# Enabling an app writes the registry and starts its loops; disabling stops
# them and uninstalling purges its drawer. All local work — the ceiling is
# there for the app that hangs on the way up, and it fits what the relay
# carries so a node's apps can be managed from the console that manages it.
_LIFECYCLE = 15.0


class AppsModule:
    """The app surface, and the built-in apps' on/off switch."""

    NAME = "apps"

    OPERATIONS = (
        operation("catalogue", "Every app operation reachable from here",
                  remote=True, timeout=_READ, wants_origin=True),
        operation("call", "Invoke one operation an app declared",
                  [param("app", "text"), param("op", "text"),
                   param("args", "document", required=False, default=None)],
                  changes=True, remote=True, timeout=_READ, wants_origin=True),
        operation("list", "The built-in apps and their state",
                  remote=True, timeout=_READ),
        operation("set", "Install, enable, disable or uninstall a built-in app",
                  [param("app", "text"),
                   param("action", "choice",
                         choices=("install", "enable", "disable", "uninstall"))],
                  changes=True, remote=True, timeout=_LIFECYCLE),
    )

    def __init__(self, context) -> None:
        self._context = context

    # -- what the apps offer ----------------------------------------------

    def _surface(self):
        surface = self._context.api()
        if surface is None:
            raise ControlError("conflict", "this node hosts no apps")
        return surface

    def op_catalogue(self, origin: str) -> dict:
        catalogue = []
        for entry in self._surface().catalogue():
            operations = [dict(row) for row in entry.get("operations", ())
                          if origin != Origin.REMOTE or row.get("remote")]
            if operations:
                catalogue.append({"app": entry["app"], "operations": operations})
        return {"apps": catalogue}

    def op_call(self, app: str, op: str, args, origin: str) -> dict:
        if not app or not op:
            # Naming nothing is a malformed call, not a call for something that
            # does not exist — and an operator reading a 404 would go looking
            # for a missing app rather than at what their client sent.
            raise ControlError("bad_request", "app and op are required")
        surface = self._surface()
        declared = surface.find(app, op)
        if declared is None:
            # An app that is not running exposes nothing, which is the honest
            # answer rather than an error to work around: the operation does
            # not exist here, now.
            raise ControlError("not_found", "no such operation")
        if origin == Origin.REMOTE and not declared.get("remote"):
            raise ControlError(
                "refused", f"{app}.{op} cannot be driven from a remote console")
        try:
            result = surface.call(app, op, args if isinstance(args, dict) else {})
        except app_api.AppAPIError as exc:
            # The app's own refusal, in this plane's vocabulary. It is the
            # caller's mistake by construction: the app API refuses exactly
            # what was not declared, or what would not coerce.
            raise ControlError("bad_request", str(exc)) from None
        except Exception:
            raise ControlError("unavailable", "the app is unavailable") from None
        return {"ok": True, "result": result}

    # -- the built-in apps -------------------------------------------------

    def op_list(self) -> dict:
        return {"apps": self._context.apps()}

    def op_set(self, app: str, action: str) -> dict:
        host = self._context.host()
        if host is None:
            raise ControlError("conflict", "this node hosts no built-in apps")
        try:
            done = self._context.ask(getattr(host, action)(app), _LIFECYCLE)
        except ControlError:
            raise
        except Exception as exc:
            raise ControlError("failed", str(exc)[:200]) from None
        if not done:
            raise ControlError("bad_request", f"no app called {app[:32]!r}")
        # The list comes back with the answer: a page that just toggled an app
        # must not have to ask a second question to know what it now looks
        # like, and the two answers could disagree.
        return {"ok": True, "apps": self._context.apps()}
