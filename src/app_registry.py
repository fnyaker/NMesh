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

import asyncio
import json
import os
import threading

from .app_channel import CHAT_APP_ID, builtin_id

FLEET_APP_ID = builtin_id("fleet")

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
    },
)

_BY_NAME = {app["name"]: app for app in BUILTIN_APPS}
_FILENAME = "apps.json"


class AppRegistry:
    """Persisted install/enable state for the built-in apps."""

    def __init__(self, state_dir: str | None = None) -> None:
        self._path = os.path.join(state_dir, _FILENAME) if state_dir else None
        self._lock = threading.RLock()
        self._state: dict[str, dict] = {}
        self._load()

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
            self._state[app["name"]] = {
                "installed": _flag(stored.get("installed"), True),
                "enabled": _flag(stored.get("enabled"), app["default_enabled"]),
            }

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
                })
            return out

    # -- mutations --------------------------------------------------------

    def set_enabled(self, name: str, enabled: bool) -> bool:
        with self._lock:
            entry = self._state.get(name)
            if entry is None or (enabled and not entry["installed"]):
                return False
            entry["enabled"] = bool(enabled)
            self._save()
            return True

    def set_installed(self, name: str, installed: bool) -> bool:
        """Uninstalling also disables: an app must never keep running once the
        operator has asked for its state to be purged."""
        with self._lock:
            entry = self._state.get(name)
            if entry is None:
                return False
            entry["installed"] = bool(installed)
            if not installed:
                entry["enabled"] = False
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
        except Exception:
            return False          # a failing app must not take the node with it
        if not built:
            return False
        app, bridge = built
        try:
            await app.start()
        except Exception:
            return False
        if bridge is not None and self._loop is not None:
            try:
                bridge.start(self._loop)
            except Exception:
                pass
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
            except Exception:
                pass
        try:
            await app.stop()
        except Exception:
            pass          # a wedged app must not block the toggle
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
