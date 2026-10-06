"""
Built-in app registry & host — installing, enabling and disabling the apps that
ship with the node.

The app store (:mod:`src.app_catalog`) already covers apps *deployed* from the
mesh. The apps shipped in-tree — chat, fleet — had no such control: they were
either wired at startup or not, decided by a command-line flag. That is the
wrong granularity for an app like fleet, which grants remote execution: whether
it runs has to be a deliberate, persisted, revocable choice, visible in the
console next to everything else.

Two independent states, because they mean different things:

  - **installed** — this node keeps state for the app. Uninstalling *purges the
    app's encrypted drawer*: its ledger, its history, its keys-in-the-drawer.
    That is a real, irreversible action, not a cosmetic flag.
  - **enabled** — the app is wired to the mesh right now. Disabling stops it and
    closes its connector section; its state survives, so re-enabling picks up
    where it left off.

Defaults are chosen by blast radius: chat is on, **fleet is off**. An app that
can open a shell does not enable itself because it was shipped.

The registry file holds no secret (names and two booleans), so it is plain JSON
alongside the other state. A corrupt or absent file yields the defaults, never a
crash and never an app enabled that the operator did not enable.
"""
from __future__ import annotations

from . import faults

import asyncio
import json
import os
import threading

from . import app_perms
from .app_channel import CHAT_APP_ID, builtin_id

FLEET_APP_ID = builtin_id("fleet")
MCP_APP_ID = builtin_id("mcp")

# What every built-in app does through the connector anyway — its own section,
# names, reports, a log line. Asked for like any other app asks, so the Apps
# page shows the same thing for a built-in as for an app somebody installed.
_BASE = [
    {"name": "network", "why": "Its messages travel over the mesh."},
    {"name": "storage", "why": "It keeps its own state on this node."},
    {"name": "names", "why": "It shows nodes by name."},
    {"name": "identity", "why": "It proves who is speaking to the node at the other end."},
    {"name": "report", "why": "It reports a node that floods it."},
    {"name": "log", "why": "It says what it is doing."},
    {"name": "notify", "why": "It tells you when something needs you."},
]

# The apps shipped with the node. ``page`` is where the console surfaces the
# app; ``default_enabled`` is the shipped-off/shipped-on decision above.
BUILTIN_APPS = (
    {
        "name": "chat",
        "title": "Chat",
        "page": "/chat",
        "app_id": CHAT_APP_ID,
        "default_enabled": True,
        "description": "Messaging, files and calls across the mesh.",
        "permissions": _BASE,
    },
    {
        "name": "fleet",
        "title": "Fleet",
        "page": "/fleet",
        "app_id": FLEET_APP_ID,
        "default_enabled": False,
        "description": ("Remote management and automated deployment: enrol "
                        "nodes, read their status, update them, open a shell, "
                        "discover and provision machines over SSH."),
        "permissions": _BASE + [
            {"name": "readstate.links",
             "why": "An operator managing this node sees its links on their map."},
            {"name": "readstate.logs",
             "why": "An operator managing this node can follow its log."},
        ],
    },
    {
        "name": "mcp",
        "title": "MCP",
        # Its settings live with the internal API it exposes, not on a page of
        # their own: what it serves is that list.
        "page": "/#apps/api",
        "app_id": MCP_APP_ID,
        "default_enabled": False,
        "description": ("A Model Context Protocol server: every operation this "
                        "node's console can perform, as tools an AI client can "
                        "call — within the permissions you grant it here. "
                        "Loopback only unless you say otherwise."),
        "permissions": [
            {"name": "readstate",
             "why": "Answering questions about this node is reading its state."},
            {"name": "control",
             "why": "Every console operation it exposes as a tool needs the "
                    "matching part of this, and nothing more."},
            {"name": "log", "why": "It says which tools were called."},
        ],
    },
)

# What an app may be *granted*, beyond running. Installing and enabling say
# whether an app runs; a grant says what the node will answer when it asks for
# something that is not its own. Off for every app until an operator turns it
# on, and listed here rather than invented per app so the console has one place
# to render and one word to render it with.
#
# ``logs`` — read the node's log ring: every other app's lines and the core's.
#   Writing a line needs no grant (the connector stamps the source, so an app
#   can only ever speak as itself); reading is the node's whole diary, which is
#   a different question with a different answer.
# ``links`` — read which nodes this one is connected to. Who a machine keeps
#   company with, which is the same kind of thing as its log and is why it is
#   asked for separately: an app that shows a mesh map needs it, and an app
#   that sends messages does not.
#
# These two are the first permissions there were, and they are permissions now
# (`src/app_perms.py`): `logs` is `readstate.logs`, `links` is `readstate.links`.
# The names stay so a console from before the change still has something to
# tick, and so the `apps.grant` operation it calls still answers.
GRANTS = (
    {
        "name": "logs",
        "permission": "readstate.logs",
        "title": "Read the node's log",
        "description": ("Query and follow every line this node keeps — the "
                        "core's and every other app's, not only its own."),
    },
    {
        "name": "links",
        "permission": "readstate.links",
        "title": "Read this node's links",
        "description": ("See which nodes this one is connected to right now, "
                        "over which medium and at what latency."),
    },
)
_GRANT_NAMES = tuple(grant["name"] for grant in GRANTS)
_GRANT_PERMISSION = {grant["name"]: grant["permission"] for grant in GRANTS}

_BY_NAME = {app["name"]: app for app in BUILTIN_APPS}
_BY_APP_ID = {app["app_id"]: app["name"] for app in BUILTIN_APPS}
_FILENAME = "apps.json"


class AppRegistry:
    """Persisted install/enable state for the built-in apps."""

    def __init__(self, state_dir: str | None = None) -> None:
        self._path = os.path.join(state_dir, _FILENAME) if state_dir else None
        self._lock = threading.RLock()
        self._state: dict[str, dict] = {}
        # What each app asked for and what a human gave it — the built-ins
        # here, and every app that ever connected with a manifest.
        self.perms = app_perms.PermissionBook(state_dir)
        self._load()
        for app in BUILTIN_APPS:
            self.perms.declare(app["app_id"].hex(), {
                "name": app["name"], "title": app["title"],
                "description": app["description"],
                "permissions": app.get("permissions", [])},
                source="builtin", fixed=True)
        self._migrate_grants()

    # -- persistence ------------------------------------------------------

    def _load(self) -> None:
        document = {}
        if self._path:
            try:
                if os.path.getsize(self._path) <= 64 * 1024:
                    with open(self._path, encoding="utf-8") as handle:
                        document = json.load(handle)
            except (OSError, ValueError):
                document = {}       # corrupt/absent → defaults, never a crash
        if not isinstance(document, dict):
            document = {}
        for app in BUILTIN_APPS:
            stored = document.get(app["name"])
            stored = stored if isinstance(stored, dict) else {}
            granted = stored.get("grants")
            granted = granted if isinstance(granted, dict) else {}
            self._state[app["name"]] = {
                "installed": _flag(stored.get("installed"), True),
                "enabled": _flag(stored.get("enabled"), app["default_enabled"]),
                # Never defaulted to true by anything a file can say: an
                # unreadable or hostile state file must not be a way to grant.
                "grants": {name: _flag(granted.get(name), False)
                           for name in _GRANT_NAMES},
            }

    def _migrate_grants(self) -> None:
        """Carry the grants of `apps.json` over to the permission book, once.

        A node that had given fleet its log must not lose that on upgrade, and
        must not have it given back after an operator takes it away again — so
        only a grant the book has never heard of moves, and it moves as it was."""
        for app in BUILTIN_APPS:
            app_hex = app["app_id"].hex()
            old = self._state.get(app["name"], {}).get("grants") or {}
            explicit = {row["name"]: row["explicit"]
                        for row in self.perms.view(app_hex)["permissions"]}
            for name, value in old.items():
                permission = _GRANT_PERMISSION.get(name)
                if value and permission in explicit and explicit[permission] is None:
                    self.perms.set_grant(app_hex, permission, True)

    def _save(self) -> None:
        if not self._path:
            return
        try:
            blob = json.dumps(self._state, separators=(",", ":")).encode("utf-8")
            tmp = f"{self._path}.tmp.{os.getpid()}"
            descriptor = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            try:
                os.write(descriptor, blob)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            os.replace(tmp, self._path)
        except OSError:
            pass          # a read-only state dir must not break a live node

    # -- queries ----------------------------------------------------------

    def known(self, name: str) -> bool:
        return name in _BY_NAME

    def is_installed(self, name: str) -> bool:
        with self._lock:
            return bool(self._state.get(name, {}).get("installed"))

    def is_enabled(self, name: str) -> bool:
        """Enabled *and* installed — an uninstalled app never runs."""
        with self._lock:
            entry = self._state.get(name, {})
            return bool(entry.get("installed") and entry.get("enabled"))

    def overview(self, running: set | None = None) -> list[dict]:
        """The Apps view: every built-in with its state and available action."""
        running = running or set()
        with self._lock:
            out = []
            for app in BUILTIN_APPS:
                entry = self._state.get(app["name"], {})
                app_hex = app["app_id"].hex()
                # Field names follow what /api/state already published for
                # apps (id / name / path); the state flags are the new part.
                out.append({
                    "id": app["name"],
                    "name": app["title"],
                    "path": app["page"],
                    "description": app["description"],
                    "app_id": app["app_id"].hex(),
                    "installed": bool(entry.get("installed")),
                    "enabled": self.is_enabled(app["name"]),
                    "running": app["name"] in running,
                    # Self-describing, like a transport's options: the page
                    # renders what the node declares rather than holding its
                    # own copy of what a grant is called. Read from the
                    # permission book — the one place a grant is held.
                    "grants": [dict(grant, granted=self.perms.allows(app_hex, grant["permission"]))
                               for grant in GRANTS
                               if grant["permission"] in self.perms.requested(app_hex)],
                    "permissions": self.perms.view(app_hex)["permissions"],
                })
            return out

    def granted(self, name: str, capability: str) -> bool:
        """Does this app hold this grant? **No** for anything not recognised.

        The one question the connector asks, and it is asked on a path an app
        controls the arguments of, so every unknown app, unknown capability and
        missing entry is a refusal rather than a lookup that happens to fail."""
        entry = _BY_NAME.get(name)
        if entry is None or capability not in _GRANT_NAMES:
            return False
        return self.perms.allows(entry["app_id"].hex(),
                                 _GRANT_PERMISSION[capability])

    def granted_to_id(self, app_id: bytes, capability: str) -> bool:
        """The same question, asked with the identifier a connector has.

        An app the mesh deployed is not in this registry and is therefore
        refused, which is the right answer: nothing here has granted it
        anything."""
        return self.granted(_BY_APP_ID.get(bytes(app_id) if app_id else b"", ""),
                            capability)

    # -- mutations --------------------------------------------------------

    def set_enabled(self, name: str, enabled: bool) -> bool:
        with self._lock:
            entry = self._state.get(name)
            if entry is None or (enabled and not entry["installed"]):
                return False
            entry["enabled"] = bool(enabled)
            self._save()
            return True

    def set_grant(self, name: str, capability: str, granted: bool) -> bool:
        """Give or take back one grant. Refused for anything not declared."""
        entry = _BY_NAME.get(name)
        if entry is None or capability not in _GRANT_NAMES:
            return False
        return self.perms.set_grant(entry["app_id"].hex(),
                                    _GRANT_PERMISSION[capability], bool(granted))

    def set_installed(self, name: str, installed: bool) -> bool:
        """Uninstalling also disables **and drops every grant**: an app must
        never keep running once the operator has asked for its state to be
        purged, and one reinstalled later starts from nothing rather than from
        what somebody allowed the app that used to have that name."""
        with self._lock:
            entry = self._state.get(name)
            if entry is None:
                return False
            entry["installed"] = bool(installed)
            if not installed:
                entry["enabled"] = False
                entry["grants"] = {key: False for key in _GRANT_NAMES}
                # …and every permission above the ordinary ones: an app
                # reinstalled later starts from nothing, not from what somebody
                # allowed the app that used to have that name.
                app_hex = _BY_NAME[name]["app_id"].hex()
                for permission in self.perms.requested(app_hex):
                    if app_perms.level(permission) != app_perms.NORMAL:
                        self.perms.set_grant(app_hex, permission, False)
            self._save()
            return True


def _flag(value, default: bool) -> bool:
    return bool(value) if isinstance(value, bool) else default


class AppHost:
    """Starts and stops built-in apps on a live node.

    A *factory* per app builds it (connector client, state, web bridge) and is
    registered by the launcher, so this module never imports the apps themselves
    — the node core stays ignorant of what any app does.

    Every method is a coroutine driven from the event loop; the console
    marshals its calls onto that loop like every other node interaction."""

    def __init__(self, registry: AppRegistry, *, app_storage=None) -> None:
        self._registry = registry
        self._storage = app_storage
        self._factories: dict[str, object] = {}
        self._running: dict[str, tuple] = {}      # name -> (app, bridge)
        self._loop: asyncio.AbstractEventLoop | None = None

    @property
    def registry(self) -> AppRegistry:
        return self._registry

    def register(self, name: str, factory) -> None:
        """``factory()`` is an async callable returning ``(app, bridge|None)``.
        ``app`` must expose ``start()`` and ``stop()`` coroutines."""
        if self._registry.known(name):
            self._factories[name] = factory

    def bridge(self, name: str):
        entry = self._running.get(name)
        return entry[1] if entry else None

    def app(self, name: str):
        entry = self._running.get(name)
        return entry[0] if entry else None

    def running(self) -> set:
        return set(self._running)

    def overview(self) -> list[dict]:
        return self._registry.overview(self.running())

    # -- lifecycle --------------------------------------------------------

    async def apply(self) -> None:
        """Reconcile what runs with what the registry says should run."""
        for name in list(self._running):
            if not self._registry.is_enabled(name):
                await self._stop(name)
        for name, _factory in self._factories.items():
            if self._registry.is_enabled(name) and name not in self._running:
                await self._start(name)

    async def _start(self, name: str) -> bool:
        factory = self._factories.get(name)
        if factory is None or name in self._running:
            return False
        try:
            built = await factory()
        except Exception as exc:  # noqa: BLE001
            faults.note(f"app {name} factory", exc)
            return False          # a failing app must not take the node with it
        # The sentence above was true of the *call* and not of what it handed
        # back: `app, bridge = built` is an unpack, and a factory answering one
        # value, or three, or a number, raised here — outside every guard — and
        # took `apply()` with it, which on start-up is the node. What a factory
        # must return is written down in `register`; this is where that is held
        # to rather than assumed.
        if not isinstance(built, (tuple, list)) or len(built) != 2:
            faults.note(f"app {name} factory",
                        TypeError("a factory answers (app, bridge|None)"))
            return False
        app, bridge = built
        if not hasattr(app, "start") or not hasattr(app, "stop"):
            faults.note(f"app {name} factory",
                        TypeError("an app needs start() and stop()"))
            return False
        try:
            await app.start()
        except Exception as exc:  # noqa: BLE001
            faults.note(f"app {name} start", exc)
            return False
        if bridge is not None and self._loop is not None:
            try:
                bridge.start(self._loop)
            except Exception as exc:  # noqa: BLE001
                faults.note(f"app {name} bridge", exc)
        self._running[name] = (app, bridge)
        return True

    async def _stop(self, name: str) -> bool:
        entry = self._running.pop(name, None)
        if entry is None:
            return False
        app, bridge = entry
        if bridge is not None:
            try:
                bridge.stop()
            except Exception as exc:  # noqa: BLE001
                faults.note(f"app {name} bridge stop", exc)
        try:
            await app.stop()
        except Exception as exc:  # noqa: BLE001
            faults.note(f"app {name} stop", exc)
            # A wedged app must not block the toggle. It is still let go of
            # below — an app that will not stop is not an app that keeps
            # running.
        return True

    def bind_console(self, loop: asyncio.AbstractEventLoop) -> None:
        """Hand the host the loop its bridges marshal onto (the console's)."""
        self._loop = loop
        for _name, (_app, bridge) in self._running.items():
            if bridge is not None:
                try:
                    bridge.start(loop)
                except Exception:
                    pass

    async def enable(self, name: str) -> bool:
        if not self._registry.set_enabled(name, True):
            return False
        return await self._start(name)

    async def disable(self, name: str) -> bool:
        if not self._registry.known(name):
            return False
        self._registry.set_enabled(name, False)
        await self._stop(name)
        return True

    async def install(self, name: str) -> bool:
        return self._registry.set_installed(name, True)

    async def uninstall(self, name: str) -> bool:
        """Stop the app and **purge its drawer** — the honest meaning of
        uninstalling something whose code ships with the node."""
        if not self._registry.known(name):
            return False
        await self._stop(name)
        self._registry.set_installed(name, False)
        app_id = _BY_NAME[name]["app_id"]
        if self._storage is not None:
            try:
                for key in self._storage.list_keys(app_id):
                    self._storage.delete(app_id, key)
            except Exception:
                pass
        return True

    async def stop_all(self) -> None:
        for name in list(self._running):
            await self._stop(name)
