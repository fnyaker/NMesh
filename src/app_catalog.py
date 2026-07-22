"""
App store — the shared catalog of published apps, and the local installed set.

Two pieces, both deliberately small and defensive:

  - :class:`AppCatalog` — a bounded, network-wide directory of *published* apps.
    Each entry is a **signed release descriptor** (see :mod:`src.app_package`):
    self-verifying, bound to its author's ML-DSA key, and carrying a signed
    publish time (``ts``). Nodes gossip these descriptors to each other; a node
    keeps the highest ``ts`` per app id, so a relay can neither forge an entry
    (signature) nor roll a node back to a stale one (``ts`` never goes down).
    This is what lets one node publish an app and every node discover it.

  - :class:`InstalledApps` — the local, persisted record of which apps *this*
    node has installed (fetched + written to disk), separate from what merely
    exists on the network. Install / uninstall / update act here.

Everything is bounded (entry counts) and every parse rejects by default: a bad
descriptor, a wrong signature, a stale ``ts``, or a corrupt registry file is
dropped without effect and never crashes the node.
"""
from __future__ import annotations

import json
import os
import shutil

from .app_package import parse_release, content_key, AppPackageError
from .app_channel import APP_ID_LEN

MAX_APPS = 1024          # catalog entries (distinct app ids)
MAX_INSTALLED = 256      # locally installed apps


class AppCatalog:
    """Bounded, signature-verified directory of published apps, keyed by app id.

    Kept in memory (it is reconstructed from gossip); the source of truth for a
    given app is the highest-``ts`` signed release the node has seen.
    """

    def __init__(self, max_apps: int = MAX_APPS) -> None:
        self._max = max_apps
        self._apps: dict[bytes, dict] = {}   # app_id -> entry

    def offer(self, release_bytes: bytes, verify) -> str | None:
        """Consider a signed release for the catalog.

        Returns ``"new"`` / ``"updated"`` if it changed our view (the caller
        should then re-gossip it), or ``None`` if it was invalid, a duplicate, or
        older than what we hold (in which case it must NOT be re-gossiped — that
        is what terminates the epidemic)."""
        try:
            doc = parse_release(release_bytes, verify)
        except AppPackageError:
            return None
        app_id = doc["app_id"]
        existing = self._apps.get(app_id)
        if existing is not None:
            if doc["ts"] <= existing["ts"]:
                return None            # older or same — ignore (anti-rollback)
            outcome = "updated"
        else:
            if len(self._apps) >= self._max:
                return None            # catalog full — reject new app ids
            outcome = "new"
        self._apps[app_id] = {
            "app_id": app_id,
            "release": bytes(release_bytes),
            "release_id": content_key(release_bytes),
            "name": doc["name"],
            "version": doc["version"],
            "author": doc["author"],
            "root_key": doc["root_key"],
            "ts": doc["ts"],
        }
        return outcome

    def get(self, app_id: bytes) -> dict | None:
        return self._apps.get(app_id)

    def releases(self) -> list[bytes]:
        """Every stored release blob — for syncing our whole view to a peer."""
        return [e["release"] for e in self._apps.values()]

    def list(self) -> list[dict]:
        """UI-facing metadata (no raw bytes), newest first."""
        out = [{
            "app_id": e["app_id"].hex(),
            "name": e["name"],
            "version": e["version"],
            "author": e["author"].hex(),
            "release_id": e["release_id"].hex(),
            "ts": e["ts"],
        } for e in self._apps.values()]
        out.sort(key=lambda d: d["ts"], reverse=True)
        return out

    def __len__(self) -> int:
        return len(self._apps)


class InstalledApps:
    """Local record of installed apps, persisted as plain JSON (metadata only —
    no secrets). Any corruption yields an empty registry, never a crash."""

    def __init__(self, path: str | None, apps_dir: str | None = None,
                 max_installed: int = MAX_INSTALLED) -> None:
        self._path = path
        self._apps_dir = apps_dir
        self._max = max_installed
        self._apps: dict[str, dict] = self._load()

    def _load(self) -> dict[str, dict]:
        if not self._path:
            return {}
        try:
            with open(self._path) as f:
                doc = json.load(f)
        except (FileNotFoundError, OSError, ValueError):
            return {}
        if not isinstance(doc, dict):
            return {}
        out: dict[str, dict] = {}
        for k, v in doc.items():
            if (isinstance(k, str) and len(k) == APP_ID_LEN * 2
                    and isinstance(v, dict) and len(out) < self._max):
                out[k] = v
        return out

    def _save(self) -> None:
        if not self._path:
            return
        tmp = f"{self._path}.tmp.{os.getpid()}"
        with open(tmp, "w") as f:
            json.dump(self._apps, f)
        os.replace(tmp, self._path)

    def app_dir(self, app_id_hex: str) -> str | None:
        if not self._apps_dir:
            return None
        return os.path.join(self._apps_dir, app_id_hex)

    def is_installed(self, app_id_hex: str) -> bool:
        return app_id_hex in self._apps

    def record(self, meta: dict) -> bool:
        """Insert/replace an installed-app record. Refuses a *new* app once the
        cap is reached (an update to an existing one always goes through)."""
        app_id = meta["app_id"]
        if app_id not in self._apps and len(self._apps) >= self._max:
            return False
        self._apps[app_id] = meta
        self._save()
        return True

    def remove(self, app_id_hex: str) -> bool:
        if app_id_hex not in self._apps:
            return False
        del self._apps[app_id_hex]
        self._save()
        d = self.app_dir(app_id_hex)
        if d and os.path.isdir(d):
            shutil.rmtree(d, ignore_errors=True)
        return True

    def get(self, app_id_hex: str) -> dict | None:
        return self._apps.get(app_id_hex)

    def list(self) -> list[dict]:
        return sorted(self._apps.values(), key=lambda m: m.get("name", ""))

    def write_files(self, app_id_hex: str, files: dict[str, bytes]) -> None:
        """Persist an installed app's verified files under its own directory.
        Path components are sanitised so a manifest path can't escape the dir."""
        d = self.app_dir(app_id_hex)
        if not d:
            return
        if os.path.isdir(d):
            shutil.rmtree(d, ignore_errors=True)
        for path, content in files.items():
            safe = _safe_rel(path)
            if safe is None:
                continue
            dest = os.path.join(d, safe)
            os.makedirs(os.path.dirname(dest) or d, exist_ok=True)
            with open(dest, "wb") as f:
                f.write(content)


def _safe_rel(path: str) -> str | None:
    """A relative path with no absolute root, no ``..`` escape, no NUL. Anything
    else is dropped (reject by default) — a hostile manifest can't write outside
    its app directory."""
    if not isinstance(path, str) or not path or "\x00" in path:
        return None
    norm = os.path.normpath(path)
    if os.path.isabs(norm) or norm.startswith("..") or norm == ".":
        return None
    parts = norm.split(os.sep)
    if ".." in parts:
        return None
    return norm
