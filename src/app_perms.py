"""
What an app may do on this node, asked for in a manifest and granted by a human.

An app used to get one of two answers: everything the data connector offers —
sending, a drawer, a DHT namespace, names, the node's signature on an assertion
— for holding the token, and two grants beside it (``logs``, ``links``) that an
operator ticked on the Apps page. That was enough while the apps were the two
that ship with the node. It stops being enough the moment an app can *drive*
the node — call the operations the console calls, or replace one of them —
because "it holds the token" is then the whole of the answer to "may it restart
this machine?".

So permissions are named, arranged in a tree, and asked for:

* An app **declares** what it wants in a manifest — at install time from its
  package (``nmesh.json``), or at run time over the connector — and says *why*
  for each one. Declaring asks; it grants nothing.
* A human **grants**, per app, on the Apps page. Only what the app asked for is
  shown: an app that wants nothing beyond messaging gets no panel full of
  switches it never needed.
* A parent covers its children. ``readstate`` is the whole of the node's state;
  ``readstate.logs`` is its log and nothing else. An operator can give either.

Three levels, by blast radius:

==============  ================================================================
``normal``      what every connector client always had — its own section, its
                own drawer, names, saying things. Allowed when asked for (and
                for an app with no manifest at all, which is every app written
                before this existed); an operator can still take one back.
``sensitive``   reading this node's state. Off until granted.
``dangerous``   driving the node, or replacing what it does. Off until granted,
                and the page says what it means before the switch moves.
==============  ================================================================

**Authentication is not trust**, here as everywhere. A grant is held by an app
*identity* — the app id a client authenticated as with its own per-app token
(:mod:`src.data_connector`) — and nothing above ``normal`` is ever answered to a
client that only holds the connector's shared token: that token says "a local
process", never "this app".

**Permissions never move themselves.** Nothing an app can call changes what any
app may do: the operations that grant are refused to every app origin, whatever
it holds (:data:`OPERATOR_ONLY`). An app with ``control.apps`` can enable
another app; it cannot give itself, or anybody, ``modding``.
"""
from __future__ import annotations

import json
import os
import re
import threading
import time

from . import faults

NORMAL = "normal"
SENSITIVE = "sensitive"
DANGEROUS = "dangerous"
LEVELS = (NORMAL, SENSITIVE, DANGEROUS)

# Bounds. A manifest arrives from an app, which is a local process and still not
# a trusted one: every list and string in it is capped before it is kept.
MAX_APPS = 64                 # apps whose manifest and grants are remembered
MAX_MANIFEST = 32 * 1024      # bytes of one manifest, before it is parsed
MAX_REQUESTS = 32             # permissions one manifest may ask for
MAX_WHY = 200                 # characters of the reason given for one
MAX_TITLE = 60
MAX_DESCRIPTION = 400
MAX_API = 32                  # operations an app may declare it exposes
_FILENAME = "app_perms.json"
_FILE_MAX = 512 * 1024

_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{0,31}$")
_PERM_RE = re.compile(r"^[a-z][a-z0-9_]{0,31}(\.[a-z][a-z0-9_]{0,31})?$")
_HEX_RE = re.compile(r"^[0-9a-f]{16}$")
_VERSION_RE = re.compile(r"^[0-9A-Za-z.+_-]{1,32}$")


def _perm(name, title, level, description, children=()):
    return {"name": name, "title": title, "level": level,
            "description": description, "children": tuple(children)}


# The tree. Every name an app can ask for is written here and nowhere else: a
# permission that is not on this list does not exist, and a manifest asking for
# one is told so rather than recorded.
PERMISSIONS = (
    # -- what every connector client already had ---------------------------
    _perm("network", "Exchange messages with other nodes", NORMAL,
          "End-to-end messages on this app's own section of the mesh."),
    _perm("storage", "Keep data on this node", NORMAL,
          "This app's own encrypted drawer, and nobody else's."),
    _perm("dht", "Publish on its own DHT namespace", NORMAL,
          "Public or private entries under this app's id."),
    _perm("names", "Read node names", NORMAL,
          "What nodes are called, and finding a node by name."),
    _perm("identity", "Prove this node's identity to its peers", NORMAL,
          "Signed assertions scoped to this app, an audience and a purpose — "
          "never a signature over bytes the app chose."),
    _perm("log", "Write to the node's log", NORMAL,
          "Lines attributed to this app, never to the core."),
    _perm("notify", "Post on the notice board", NORMAL,
          "A problem worth a person's attention, filed under this app."),
    _perm("report", "Report a node that abuses it", NORMAL,
          "A complaint the node weighs; never an answer about the outcome."),
    # -- reading the node's own state --------------------------------------
    _perm("readstate", "Read this node's state", SENSITIVE,
          "Everything below: what the console shows, without changing any of it.",
          children=(
              _perm("readstate.node", "Identity, addresses and peers", SENSITIVE,
                    "Version, uptime, addresses, links, known nodes and names."),
              _perm("readstate.links", "Who this node is connected to", SENSITIVE,
                    "The links alone — a medium, a latency and an age each."),
              _perm("readstate.logs", "The node's log", SENSITIVE,
                    "Every line kept: the core's and every other app's."),
              _perm("readstate.alerts", "The notice board", SENSITIVE,
                    "What wants a person's attention on this machine."),
              _perm("readstate.trace", "The protocol trace", SENSITIVE,
                    "Packet events and totals, never a payload."),
              _perm("readstate.config", "The configuration", SENSITIVE,
                    "Settings and transport options."),
              _perm("readstate.trust", "Trust and membership", SENSITIVE,
                    "Trust anchors, witnesses, the network joined, signing keys "
                    "held (never the keys)."),
              _perm("readstate.updates", "Releases and packages", SENSITIVE,
                    "Releases, packages, the installed set and transfers."),
              _perm("readstate.apps", "Apps and their operations", SENSITIVE,
                    "Apps, their state, and the read-only operations they "
                    "declare."),
          )),
    # -- driving it ---------------------------------------------------------
    _perm("control", "Drive this node", DANGEROUS,
          "Everything below: what an operator at the console can do.",
          children=(
              _perm("control.node", "Ping, retry, restart, rename", DANGEROUS,
                    "Including restarting the node and changing its name."),
              _perm("control.network", "Reachability and links", DANGEROUS,
                    "Probing, punching, listening, discovery, multi-link."),
              _perm("control.config", "Change the configuration", DANGEROUS,
                    "Settings and transports — how this node runs."),
              _perm("control.diagnostics", "Trace, log and alerts", DANGEROUS,
                    "Start and stop the trace, keep the log, clear alerts."),
              _perm("control.trust", "Trust, invitations, joining", DANGEROUS,
                    "Who this node trusts and which network it belongs to."),
              _perm("control.updates", "Install and publish", DANGEROUS,
                    "Releases, packages, the store, signing keys — what program "
                    "this machine runs."),
              _perm("control.apps", "Run apps and call them", DANGEROUS,
                    "Enable and disable apps, and call the operations they "
                    "declare. Never their permissions."),
              _perm("control.appweb", "Drive apps that declare nothing", DANGEROUS,
                    "The routes an app's own page calls, for an app that "
                    "declares no operations — whatever that page can do."),
          )),
    _perm("modding", "Replace what this node does", DANGEROUS,
          "Intercept the node's own operations — before, after or instead of "
          "them. Whatever the node answers, this app can change."),
)


def _index():
    flat = {}

    def walk(entries, parent):
        for entry in entries:
            flat[entry["name"]] = dict(entry, parent=parent)
            walk(entry["children"], entry["name"])
    walk(PERMISSIONS, None)
    return flat


_BY_NAME = _index()
NAMES = tuple(_BY_NAME)


def known(name) -> bool:
    return isinstance(name, str) and name in _BY_NAME


def level(name: str) -> str:
    entry = _BY_NAME.get(name)
    return entry["level"] if entry else DANGEROUS


def parent(name: str):
    entry = _BY_NAME.get(name)
    return entry["parent"] if entry else None


def children(name: str) -> tuple:
    entry = _BY_NAME.get(name)
    return tuple(child["name"] for child in entry["children"]) if entry else ()


def closure(names) -> set:
    """Every permission ``names`` covers: each one, and all of its children."""
    out = set()
    for name in names:
        if name in _BY_NAME:
            out.add(name)
            out.update(children(name))
    return out


def describe(name: str) -> dict:
    entry = _BY_NAME[name]
    return {"name": name, "title": entry["title"], "level": entry["level"],
            "description": entry["description"], "parent": entry["parent"]}


def catalogue() -> list:
    """The whole tree, as a page or a test reads it."""
    def render(entries):
        return [dict(describe(entry["name"]),
                     children=render(entry["children"])) for entry in entries]
    return render(PERMISSIONS)


# ---------------------------------------------------------------------------
# What a control-plane operation needs
# ---------------------------------------------------------------------------

# Each module's subject, as a scope under `readstate.` and `control.`. A read
# (an operation that does not declare `changes`) needs the first, anything else
# the second. A module that is not on this list is reachable by no app at all —
# `tests/test_app_perms.py` fails if the plane grows one that is not mapped.
MODULE_SCOPE = {
    "node": ("readstate.node", "control.node"),
    "pseudo": ("readstate.node", "control.node"),
    "network": ("readstate.node", "control.network"),
    "config": ("readstate.config", "control.config"),
    "transports": ("readstate.config", "control.config"),
    "trace": ("readstate.trace", "control.diagnostics"),
    "logs": ("readstate.logs", "control.diagnostics"),
    "alerts": ("readstate.alerts", "control.diagnostics"),
    "trust": ("readstate.trust", "control.trust"),
    "join": ("readstate.trust", "control.trust"),
    "keys": ("readstate.trust", "control.updates"),
    "releases": ("readstate.updates", "control.updates"),
    "packages": ("readstate.updates", "control.updates"),
    "store": ("readstate.updates", "control.updates"),
    "transfer": ("readstate.updates", "control.updates"),
    "apps": ("readstate.apps", "control.apps"),
    "web": ("readstate.apps", "control.appweb"),
}

# Answerable to any app that may reach the plane at all: what the plane is, and
# the app's own jobs. The catalogue is filtered to what the asker may call, and
# a job is visible to the origin that started it and to nobody else.
OPEN_TO_APPS = frozenset({"control.catalogue", "control.changes", "jobs.poll",
                          "jobs.list", "jobs.forget"})

# Never answerable to an app, whatever it holds. These decide what apps may do,
# or hand out what proves an app is an app; an app that could call them would
# turn any grant into every grant.
OPERATOR_ONLY = frozenset({"apps.grant", "apps.permit", "apps.token",
                           "apps.forget"})

# Operations nobody may mod: the ones that say what the node is and who may do
# what. A mod that could rewrite the catalogue or a grant could hide itself from
# the page that exists to show it.
NOT_MODDABLE_MODULES = frozenset({"apps", "control", "jobs", "web"})


def required(op: str, entry: dict) -> str | None:
    """The permission one operation needs from an app, or ``None`` for one no
    app may call. ``op`` is ``"module.operation"``.

    ``apps.call`` and ``jobs.start`` are not answered here: what they need
    depends on what they carry, and :meth:`PermissionBook.allows_call` asks
    again with the target."""
    if op in OPERATOR_ONLY:
        return None
    if op in OPEN_TO_APPS:
        return ""
    module = op.split(".", 1)[0]
    scope = MODULE_SCOPE.get(module)
    if scope is None:
        return None
    return scope[1] if entry.get("changes") else scope[0]


def moddable(op: str) -> bool:
    return (isinstance(op, str) and op.count(".") == 1
            and op.split(".", 1)[0] not in NOT_MODDABLE_MODULES
            and op not in OPERATOR_ONLY)


# ---------------------------------------------------------------------------
# The manifest
# ---------------------------------------------------------------------------

class ManifestError(ValueError):
    """A manifest that will not be kept, phrased for whoever wrote it."""


def _text(value, limit: int) -> str:
    if not isinstance(value, str):
        return ""
    # One line, bounded, nothing that is not printable: this is shown on a page
    # and read by a person deciding whether to trust the app that wrote it.
    clean = "".join(ch for ch in value if ch.isprintable())
    return clean.strip()[:limit]


def parse_manifest(raw) -> dict:
    """A manifest — bytes, text or an already-parsed mapping — brought inside
    what is kept. Raises :class:`ManifestError`.

    Lenient where leniency is harmless and strict where it is not: an unknown
    *field* is ignored (a newer app talking to an older node), an unknown
    *permission* is refused by name rather than silently dropped, because an
    app that asked for something and was granted something else should hear
    which."""
    if isinstance(raw, (bytes, bytearray)):
        if len(raw) > MAX_MANIFEST:
            raise ManifestError("manifest too large")
        try:
            raw = json.loads(bytes(raw).decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise ManifestError("manifest is not JSON") from None
    elif isinstance(raw, str):
        if len(raw) > MAX_MANIFEST:
            raise ManifestError("manifest too large")
        try:
            raw = json.loads(raw)
        except ValueError:
            raise ManifestError("manifest is not JSON") from None
    if not isinstance(raw, dict):
        raise ManifestError("a manifest is an object")
    name = raw.get("name")
    if not isinstance(name, str) or not _NAME_RE.match(name):
        raise ManifestError("name: lowercase letters, digits and _, at most 32")
    version = raw.get("version", "")
    version = version if isinstance(version, str) and _VERSION_RE.match(version) else ""
    requested = raw.get("permissions", [])
    if not isinstance(requested, list):
        raise ManifestError("permissions: a list")
    if len(requested) > MAX_REQUESTS:
        raise ManifestError(f"permissions: at most {MAX_REQUESTS}")
    permissions, unknown, seen = [], [], set()
    for item in requested:
        if isinstance(item, str):
            item = {"name": item}
        if not isinstance(item, dict):
            raise ManifestError("permissions: each is a name or {name, why}")
        perm = item.get("name")
        if not isinstance(perm, str) or not _PERM_RE.match(perm):
            raise ManifestError("permissions: not a permission name")
        if perm not in _BY_NAME:
            unknown.append(perm)
            continue
        if perm in seen:
            continue
        seen.add(perm)
        permissions.append({"name": perm, "why": _text(item.get("why"), MAX_WHY)})
    if unknown:
        raise ManifestError("unknown permission: " + ", ".join(sorted(unknown))[:200])
    api = raw.get("api", [])
    if not isinstance(api, list) or len(api) > MAX_API:
        raise ManifestError(f"api: a list of at most {MAX_API}")
    return {"name": name,
            "title": _text(raw.get("title"), MAX_TITLE) or name,
            "version": version,
            "description": _text(raw.get("description"), MAX_DESCRIPTION),
            "permissions": permissions,
            "api": [entry for entry in api if isinstance(entry, dict)]}


# ---------------------------------------------------------------------------
# The book: who asked for what, and what a human gave
# ---------------------------------------------------------------------------

class PermissionBook:
    """Manifests and grants, per app id, persisted.

    Keyed by the app id (hex) a connector client authenticates as — the thing
    a grant is actually held by. A corrupt or absent file yields nothing
    granted, never a crash and never a grant nobody made."""

    def __init__(self, state_dir: str | None = None) -> None:
        self._path = os.path.join(state_dir, _FILENAME) if state_dir else None
        self._lock = threading.RLock()
        self._apps: dict[str, dict] = {}
        # Built-in apps are declared on every start rather than read back: what
        # chat asks for is in this build's source, not in a file.
        self._fixed: set[str] = set()
        self._load()

    # -- persistence ------------------------------------------------------

    def _load(self) -> None:
        if not self._path:
            return
        try:
            if os.path.getsize(self._path) > _FILE_MAX:
                return
            with open(self._path, encoding="utf-8") as handle:
                document = json.load(handle)
        except (OSError, ValueError):
            return
        apps = document.get("apps") if isinstance(document, dict) else None
        if not isinstance(apps, dict):
            return
        for app_hex, stored in list(apps.items())[:MAX_APPS]:
            if not isinstance(app_hex, str) or not _HEX_RE.match(app_hex):
                continue
            if not isinstance(stored, dict):
                continue
            try:
                manifest = parse_manifest(stored.get("manifest"))
            except ManifestError:
                manifest = None
            grants = stored.get("grants")
            grants = grants if isinstance(grants, dict) else {}
            self._apps[app_hex] = {
                "manifest": manifest,
                # Only a literal true grants. Anything else a file can say —
                # a string, a number, a list — is a refusal.
                "grants": {name: value for name, value in grants.items()
                           if name in _BY_NAME and isinstance(value, bool)},
                "source": _text(stored.get("source"), 16) or "connector",
                "seen": float(stored.get("seen") or 0)
                        if isinstance(stored.get("seen"), (int, float)) else 0.0,
            }

    def _save(self) -> None:
        if not self._path:
            return
        try:
            blob = json.dumps({"apps": self._apps},
                              separators=(",", ":")).encode("utf-8")
            tmp = f"{self._path}.tmp.{os.getpid()}"
            descriptor = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            try:
                os.write(descriptor, blob)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            os.replace(tmp, self._path)
        except OSError as exc:
            faults.note("app permissions save", exc)

    # -- declaring --------------------------------------------------------

    def declare(self, app_hex: str, manifest, *, source: str = "connector",
                fixed: bool = False) -> dict:
        """Record what an app asks for. Raises :class:`ManifestError`.

        Asking grants nothing above ``normal``. A grant the new manifest no
        longer asks for is dropped: least privilege is what an app asks for
        *now*, not the widest thing it ever asked."""
        if not isinstance(app_hex, str) or not _HEX_RE.match(app_hex):
            raise ManifestError("not an app id")
        manifest = parse_manifest(manifest)
        with self._lock:
            entry = self._apps.get(app_hex)
            if entry is None:
                self._make_room()
                entry = {"manifest": None, "grants": {}, "source": source,
                         "seen": 0.0}
                self._apps[app_hex] = entry
            if app_hex in self._fixed and not fixed:
                # A built-in's manifest is this build's, and a client claiming
                # the same id does not get to rewrite what it asks for.
                return self.view(app_hex)
            changed = entry.get("manifest") != manifest
            entry["manifest"] = manifest
            entry["source"] = source
            entry["seen"] = time.time()
            if fixed:
                self._fixed.add(app_hex)
            wanted = closure(item["name"] for item in manifest["permissions"])
            for name in list(entry["grants"]):
                if name not in wanted:
                    del entry["grants"][name]
                    changed = True
            if changed:
                self._save()
            return self.view(app_hex)

    def _make_room(self) -> None:
        """Forget the app least worth remembering when the book is full: one
        that holds no grant and was seen longest ago. A built-in never goes."""
        if len(self._apps) < MAX_APPS:
            return
        candidates = [(any(entry["grants"].values()), entry["seen"], app_hex)
                      for app_hex, entry in self._apps.items()
                      if app_hex not in self._fixed]
        if candidates:
            del self._apps[min(candidates)[2]]

    def forget(self, app_hex: str) -> bool:
        with self._lock:
            if app_hex in self._fixed or app_hex not in self._apps:
                return False
            del self._apps[app_hex]
            self._save()
            return True

    # -- granting ---------------------------------------------------------

    def requested(self, app_hex: str) -> set:
        with self._lock:
            entry = self._apps.get(app_hex)
            manifest = entry.get("manifest") if entry else None
            if not manifest:
                return set()
            return closure(item["name"] for item in manifest["permissions"])

    def set_grant(self, app_hex: str, name: str, granted: bool) -> bool:
        """Give or take back one permission. Refused for anything the app did
        not ask for — the page shows only what was asked, and a grant made
        around the page is a grant nobody saw."""
        with self._lock:
            entry = self._apps.get(app_hex)
            if entry is None or name not in self.requested(app_hex):
                return False
            entry["grants"][name] = bool(granted)
            # Taking back a parent takes back what it covered: a page that
            # unticks `readstate` and leaves `readstate.logs` ticked has said
            # two contradictory things, and the narrower is the one to keep.
            if not granted:
                for child in children(name):
                    if entry["grants"].get(child):
                        entry["grants"][child] = False
            self._save()
            return True

    def allows(self, app_hex: str, name: str, *, identified: bool = True) -> bool:
        """May this app do this? **No** for anything not recognised.

        ``identified`` is whether the asker authenticated *as* this app: a
        client holding only the connector's shared token gets the ``normal``
        set and never more, whatever was granted to the id it claims."""
        if name not in _BY_NAME:
            return False
        with self._lock:
            entry = self._apps.get(app_hex)
            grants = entry["grants"] if entry else {}
            manifest = entry.get("manifest") if entry else None
            if level(name) == NORMAL:
                if grants.get(name) is False:
                    return False
                if manifest is None:
                    # Every app written before manifests existed: it had these,
                    # and an upgrade must not take them away.
                    return True
                return name in self.requested(app_hex)
            if not identified:
                return False
            if grants.get(name) is True:
                return True
            up = parent(name)
            return up is not None and grants.get(up) is True

    def allows_any(self, app_hex: str, names, *, identified: bool = True) -> bool:
        return any(self.allows(app_hex, name, identified=identified)
                   for name in names)

    def granted(self, app_hex: str) -> list:
        """Every permission this app may use right now, sorted."""
        return sorted(name for name in _BY_NAME if self.allows(app_hex, name))

    # -- reading ----------------------------------------------------------

    def manifest(self, app_hex: str):
        with self._lock:
            entry = self._apps.get(app_hex)
            return dict(entry["manifest"]) if entry and entry.get("manifest") else None

    def known_apps(self) -> list:
        with self._lock:
            return sorted(self._apps)

    def view(self, app_hex: str) -> dict:
        """One app as the Apps page draws it: what it asked for, in the tree's
        order, each with its reason and whether it is granted now."""
        with self._lock:
            entry = self._apps.get(app_hex) or {}
            manifest = entry.get("manifest") or {}
            reasons = {item["name"]: item["why"]
                       for item in manifest.get("permissions", [])}
            asked = self.requested(app_hex)
            rows = []
            for name in NAMES:
                if name not in asked:
                    continue
                rows.append(dict(describe(name),
                                 why=reasons.get(name, ""),
                                 asked=name in reasons,
                                 granted=self.allows(app_hex, name),
                                 explicit=entry.get("grants", {}).get(name)))
            return {"app_id": app_hex,
                    "name": manifest.get("name", ""),
                    "title": manifest.get("title", ""),
                    "version": manifest.get("version", ""),
                    "description": manifest.get("description", ""),
                    "source": entry.get("source", ""),
                    "manifest": bool(manifest),
                    "permissions": rows}

    def overview(self) -> list:
        with self._lock:
            return [self.view(app_hex) for app_hex in sorted(self._apps)]


# ---------------------------------------------------------------------------
# The gate the control plane asks
# ---------------------------------------------------------------------------

# Anything here makes the plane worth reaching at all: an app holding none of
# it is shown an empty catalogue, and its jobs and app calls are refused.
_DRIVING = ("readstate", "control") + tuple(
    child for root in ("readstate", "control") for child in children(root))


class ControlGate:
    """``gate(app_hex, op, entry, params)`` → a refusal, or ``None``.

    What one app may call on the control plane, answered from the permissions
    a human granted it. Two operations carry another one inside them and are
    answered for what they carry: ``jobs.start`` (the job's operation, as if it
    had been called) and ``apps.call`` (the app operation — a read needs
    ``readstate.apps``, anything that changes state ``control.apps``).

    ``find_app_op(app, op)`` is the app API's own lookup; with ``params`` absent
    — a catalogue being drawn — the two carriers are offered to any app that
    could use them for something."""

    def __init__(self, book: PermissionBook, plane=None, find_app_op=None) -> None:
        self._book = book
        self._plane = plane
        self._find_app_op = find_app_op

    def bind(self, plane=None, find_app_op=None) -> None:
        if plane is not None:
            self._plane = plane
        if find_app_op is not None:
            self._find_app_op = find_app_op

    def __call__(self, app_hex: str, op: str, entry: dict, params=None):
        return self._refusal(app_hex, op, entry, params, depth=0)

    def _refusal(self, app_hex, op, entry, params, *, depth):
        if op in OPERATOR_ONLY:
            return f"{op} is a decision for a person at this node, never an app"
        if op == "jobs.start":
            return self._carried_job(app_hex, params, depth)
        if op == "apps.call":
            return self._carried_app_call(app_hex, params)
        need = required(op, entry)
        if need is None:
            return f"{op} is not open to apps"
        if need == "" or self._book.allows(app_hex, need):
            return None
        return f"{op} needs the {need} permission"

    def _carried_job(self, app_hex, params, depth):
        if not isinstance(params, dict) or "op" not in params:
            return (None if self._book.allows_any(app_hex, _DRIVING)
                    else "this app may not drive this node")
        if depth or self._plane is None:
            return "a job cannot start a job"
        target = params.get("op")
        found = self._plane.find(target) if isinstance(target, str) else None
        if found is None:
            return None              # the plane says "no such operation" itself
        inner = params.get("params")
        return self._refusal(app_hex, target, found[1],
                             inner if isinstance(inner, dict) else {}, depth=1)

    def _carried_app_call(self, app_hex, params):
        if not isinstance(params, dict) or "app" not in params:
            return (None if self._book.allows_any(
                        app_hex, ("readstate.apps", "control.apps"))
                    else "this app may not call other apps")
        declared = None
        if self._find_app_op is not None:
            try:
                declared = self._find_app_op(str(params.get("app") or ""),
                                             str(params.get("op") or ""))
            except Exception:           # noqa: BLE001 — a refusal, never a crash
                declared = None
        if declared is None:
            return None              # "no such operation", said by the module
        need = "control.apps" if declared.get("changes") else "readstate.apps"
        if self._book.allows(app_hex, need):
            return None
        return f"that operation needs the {need} permission"
