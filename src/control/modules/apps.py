"""
The ``apps`` module: what the apps running on this node can be asked to do, and
what each of them may do in return.

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

**And the other way round: what an app may do here.** Each app asks for
permissions in its manifest and a human grants them (:mod:`src.app_perms`).
``permissions`` is the page's view of that, ``permit`` is the switch, and
``api`` is every operation this node exposes — the console's and the apps' —
with the permission each one needs, which is what the Apps page lists as the
node's internal API and what the MCP app turns into tools. None of the three
that decide anything is reachable by an app (``app_perms.OPERATOR_ONLY``).

The enforcement is here rather than in the app API, because this is the layer
that knows who is asking. An app must not have to.
"""
from __future__ import annotations

import json
import os

from ... import app_api
from ... import app_perms
from ...app_registry import GRANTS
from ..errors import ControlError
from ..params import param
from ..plane import Origin, app_of, carries_apps, operation

_READ = 10.0
# Enabling an app writes the registry and starts its loops; disabling stops
# them and uninstalling purges its drawer. All local work — the ceiling is
# there for the app that hangs on the way up, and it fits what the relay
# carries so a node's apps can be managed from the console that manages it.
_LIFECYCLE = 15.0
# An installed package's manifest, read off disk to show what it will ask for
# before it ever runs. Bounded like a manifest that arrives over the connector.
_MANIFEST_FILE = "nmesh.json"


class AppsModule:
    """The app surface, the built-in apps' on/off switch, and permissions."""

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
        operation("grant", "Give or take back one grant from a built-in app",
                  [param("app", "text"),
                   param("capability", "choice",
                         choices=tuple(grant["name"] for grant in GRANTS)),
                   param("granted", "flag")],
                  changes=True, remote=True, timeout=_LIFECYCLE),
        operation("permissions", "What each app asked for, and what it holds",
                  remote=True, timeout=_READ),
        # What an app may do on this node is a decision about trust, like a
        # pinned key: a console managing this node needs `govern` to make it.
        operation("permit", "Give or take back one permission from one app",
                  [param("app", "text"), param("permission", "text"),
                   param("granted", "flag")],
                  changes=True, govern=True, timeout=_READ),
        operation("forget", "Forget an app that is not built in",
                  [param("app", "text")],
                  changes=True, govern=True, timeout=_READ),
        # The credential an app connects with. It proves an app *is* that app
        # to the connector, which only listens on this machine — so it is this
        # machine's to hand out, and never travels.
        operation("token", "The connector token one app authenticates with",
                  [param("app", "text")], timeout=_READ),
        operation("api", "Every operation this node exposes, and what each needs",
                  remote=True, timeout=_READ),
    )

    def __init__(self, context) -> None:
        self._context = context

    # -- what the apps offer ----------------------------------------------

    def _surface(self):
        surface = self._context.api()
        if surface is None:
            raise ControlError("conflict", "this node hosts no apps")
        return surface

    def _reachable(self, origin: str, app: str, row: dict) -> bool:
        app_hex = app_of(origin)
        if app_hex:
            if row.get("operator"):
                return False            # a person's to call, never an app's
            perms = self._context.provided("perms")
            need = "control.apps" if row.get("changes") else "readstate.apps"
            return perms is not None and perms.allows(app_hex, need)
        if carries_apps(origin):
            return True
        # Every other console is at a distance and holds no `apps` grant —
        # `govern` included: deciding what a node trusts says nothing about
        # its apps. So the test is "is it one of those that carry apps?", and
        # never "is it the plain remote one?", whose `else` is everybody else.
        return bool(row.get("remote"))

    def op_catalogue(self, origin: str) -> dict:
        catalogue = []
        for entry in self._surface().catalogue():
            operations = [dict(row) for row in entry.get("operations", ())
                          if self._reachable(origin, entry["app"], row)]
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
        if not self._reachable(origin, app, declared):
            raise ControlError(
                "refused", f"{app}.{op} cannot be driven from a remote console"
                if not app_of(origin) else f"{app}.{op} is not open to this app")
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

    def op_grant(self, app: str, capability: str, granted: bool) -> dict:
        """What an app may ask of the node beyond running — the two grants that
        came before permissions, kept so a console from before them still has
        something to tick. Each one *is* a permission now (``logs`` is
        ``readstate.logs``); this is a second name for the same switch."""
        host = self._context.host()
        if host is None:
            raise ControlError("conflict", "this node hosts no built-in apps")
        if not host.registry.set_grant(app, capability, granted):
            raise ControlError("bad_request",
                               f"no app called {app[:32]!r}, or no such grant")
        return {"ok": True, "apps": self._context.apps()}

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

    # -- permissions --------------------------------------------------------

    def _perms(self):
        perms = self._context.provided("perms")
        if perms is None:
            raise ControlError("conflict", "this node keeps no app permissions")
        return perms

    def _app_hex(self, app: str) -> str:
        """An app named the way a page names it — a built-in's name, or the
        16-hex id an attached app authenticates as."""
        text = str(app or "").strip().lower()
        for entry in self._context.apps():
            if entry.get("id") == text and entry.get("app_id"):
                return entry["app_id"]
        if len(text) == 16 and all(ch in "0123456789abcdef" for ch in text):
            return text
        raise ControlError("bad_request", f"no app called {text[:32]!r}")

    def _installed_manifests(self, perms) -> None:
        """Read what installed packages will ask for, before they ever run.

        An operator can then grant before the first start, rather than finding
        an app that started and was refused everything. A package without a
        manifest asks for nothing beyond what every app has."""
        node = self._context.node
        listing = getattr(node, "installed_list", None)
        app_dir = getattr(node, "installed_app_dir", None)
        if listing is None or app_dir is None:
            return
        try:
            installed = listing()
        except Exception:
            return
        known = set(perms.known_apps())
        for record in installed[:app_perms.MAX_APPS]:
            app_hex = str(record.get("app_id") or "")
            if app_hex in known:
                continue
            try:
                directory = app_dir(app_hex)
                path = os.path.join(directory, _MANIFEST_FILE) if directory else ""
                if not path or os.path.getsize(path) > app_perms.MAX_MANIFEST:
                    continue
                with open(path, "rb") as handle:
                    perms.declare(app_hex, handle.read(app_perms.MAX_MANIFEST),
                                  source="installed")
            except (OSError, app_perms.ManifestError, ValueError):
                continue

    def op_permissions(self) -> dict:
        perms = self._perms()
        self._installed_manifests(perms)
        connector = self._context.provided("connector")
        live = {}
        if connector is not None:
            try:
                live = connector.attached()
            except Exception:
                live = {}
        apps = []
        for view in perms.overview():
            row = dict(view)
            row["attached"] = live.get(view["app_id"], {})
            apps.append(row)
        return {"apps": apps, "tree": app_perms.catalogue()}

    def op_permit(self, app: str, permission: str, granted: bool) -> dict:
        perms = self._perms()
        app_hex = self._app_hex(app)
        if not app_perms.known(permission):
            raise ControlError("bad_request", f"no permission called {permission[:40]!r}")
        if not perms.set_grant(app_hex, permission, granted):
            raise ControlError("bad_request",
                               f"that app did not ask for {permission}")
        return {"ok": True, "app": perms.view(app_hex)}

    def op_forget(self, app: str) -> dict:
        perms = self._perms()
        if not perms.forget(self._app_hex(app)):
            raise ControlError("bad_request", "a built-in app is not forgotten")
        return {"ok": True}

    def op_token(self, app: str) -> dict:
        connector = self._context.provided("connector")
        if connector is None or not hasattr(connector, "token_for"):
            raise ControlError("conflict", "this node has no data connector")
        app_hex = self._app_hex(app)
        return {"app_id": app_hex, "token": connector.token_for(bytes.fromhex(app_hex)),
                "host": getattr(connector, "host", ""),
                "port": getattr(connector, "port", 0)}

    # -- the internal API ----------------------------------------------------

    def op_api(self) -> dict:
        """Every operation this node exposes, in one list, with how it is
        reached and what an app needs to reach it.

        The same derivation the MCP app's tools come from, so the list on the
        page and the tools a client sees cannot disagree."""
        rows = endpoint_rows(self._context)
        return {"endpoints": rows,
                "connector": _connector_info(self._context.provided("connector")),
                "count": len(rows)}


def tool_name(op: str) -> str:
    """The MCP tool an operation becomes: ``node.state`` → ``node_state``,
    ``chat.peer`` (an app's) → ``app_chat_peer``."""
    return op.replace(".", "_")


def endpoint_rows(context) -> list:
    """The internal API, as rows: the plane's operations, then the apps'."""
    plane = context.provided("plane")
    rows = []
    connector = context.provided("connector")
    modded = {}
    hooks = getattr(connector, "hooks", None)
    if hooks is not None:
        try:
            modded = hooks.listing()
        except Exception:
            modded = {}
    if plane is not None:
        for module in plane.catalogue(Origin.LOCAL):
            for entry in module["operations"]:
                op = module["module"] + "." + entry["name"]
                need = app_perms.required(op, entry)
                if op in ("jobs.start", "apps.call"):
                    need = "the operation it carries"
                rows.append({
                    "kind": "node", "op": op, "summary": entry["summary"],
                    "params": entry["params"], "changes": entry["changes"],
                    "reach": entry["reach"], "background": entry["background"],
                    "permission": need if need is not None else None,
                    "apps": need is not None,
                    "tool": tool_name(op) if need is not None else "",
                    "modded_by": modded.get(op, ""),
                })
    api = context.api()
    if api is not None:
        try:
            listing = api.catalogue()
        except Exception:
            listing = []
        for entry in listing:
            for row in entry.get("operations", ()):
                op = entry["app"] + "." + row["name"]
                rows.append({
                    "kind": "app", "op": op, "summary": row.get("summary", ""),
                    "params": row.get("params", []), "changes": row.get("changes", False),
                    "reach": "remote" if row.get("remote") else "local",
                    "background": False,
                    "permission": "control.apps" if row.get("changes") else "readstate.apps",
                    "apps": True, "tool": "app_" + tool_name(op), "modded_by": "",
                })
    web = context.provided("web")
    if web is not None:
        try:
            pages = web.routes()
        except Exception:
            pages = []
        for page in pages:
            for route in page.get("routes", ()):
                rows.append({
                    "kind": "web", "op": route["method"] + " " + route["path"],
                    "summary": f"what {page.get('title') or page['app']}'s page calls",
                    "params": [], "changes": route["method"] != "GET",
                    "reach": "local", "background": False,
                    "permission": "control.appweb", "apps": True,
                    "tool": "web_request", "modded_by": "",
                })
    return rows


def _connector_info(connector) -> dict:
    if connector is None:
        return {"available": False}
    return {"available": True, "host": getattr(connector, "host", ""),
            "port": getattr(connector, "port", 0),
            "frame": "CONTROL", "http": "POST /api/control"}
