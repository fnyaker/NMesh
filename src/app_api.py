"""
What an app lets the rest of the product ask of it.

The console already talks to chat and to fleet, but through routes written by
hand in :mod:`src.webconsole` — one ``elif`` per action, in a file that has no
business knowing what a capability or a conversation is. That works while there
are two apps and one caller. It stops working the moment a *page* wants
something from an app it does not own: the node details view wants to know
whether chat has a conversation with this node and whether fleet manages it,
and neither of those belongs in the console's routing table.

So an app declares what it exposes, once, next to itself:

.. code-block:: python

    class ChatBridge:
        API = (
            operation("peer", "What chat knows about a node",
                      [param("node", "node")]),
            operation("contact", "Add a node to the address book",
                      [param("node", "node")], changes=True),
        )

        def api_peer(self, node):
            ...

and every caller — another app, the core, a page in the browser — reaches it the
same way: ``AppAPI.call("chat", "peer", {"node": ...})``.

**Reject by default, everywhere.** An operation that is not declared does not
exist, whatever the bridge happens to have as an attribute: dispatch never looks
up a name the caller supplied, only a name the app itself wrote down. A
parameter that is not declared is refused rather than passed through. Every
declared parameter is coerced and bounded before the app sees it, so an app
never has to write the same three lines of validation a fourth time — and never
writes them slightly differently.

**No new authority.** This is a way to *reach* what an app already does, not a
way around the checks it already makes. A capability that fleet refuses to a
node is still refused when the request arrives through here; the ledger is the
authority, not the caller. What this adds is one door instead of five, with the
lock in one place.

Parameters are deliberately a short, closed list. A generic type system was the
other option and it would have been the wrong one: the values that actually
cross this boundary are node identities, short strings, flags, counts and
capability tokens, and giving ``node`` its own kind means the shape of a NodeID
is checked once here instead of in every operation that takes one.
"""
from __future__ import annotations

import re

# Bounds. Every one of these exists so that a caller cannot turn an argument
# into a payload; none of them is a guess about what an app "should" need.
MAX_OPERATIONS = 32          # per app, so a declaration cannot itself be an attack
MAX_ARGS = 16                # per call
MAX_TEXT = 200               # a label, a pseudo, a short note — never a document
MAX_TOKENS = 16              # entries in a token list (capabilities, say)
MAX_TOKEN = 32               # length of one token
MAX_COUNT = 10 ** 6

KINDS = ("node", "text", "flag", "count", "tokens")

_NODE_RE = re.compile(r"^[0-9a-f]{40}$")
_TOKEN_RE = re.compile(r"^[a-z0-9_-]{1,%d}$" % MAX_TOKEN)
_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{0,31}$")


class AppAPIError(Exception):
    """A call an app will not take, phrased for whoever made it."""


def param(name: str, kind: str, *, required: bool = True, default=None,
          help: str = "") -> dict:
    """Declare one argument of one operation."""
    if kind not in KINDS:
        raise AppAPIError(f"unknown kind {kind!r}")
    if not _NAME_RE.match(name):
        raise AppAPIError(f"bad parameter name {name!r}")
    return {"name": name, "kind": kind, "required": bool(required),
            "default": default, "help": help}


def operation(name: str, summary: str, params=(), *, changes: bool = False) -> dict:
    """Declare one operation.

    ``changes`` marks an operation that alters state. It is not a permission —
    the app still decides — but it lets a caller present a confirmation, and it
    keeps read-only calls distinguishable from the rest at a glance."""
    if not _NAME_RE.match(name):
        raise AppAPIError(f"bad operation name {name!r}")
    fields = list(params)
    if len(fields) > MAX_ARGS:
        raise AppAPIError("too many parameters")
    return {"name": name, "summary": summary, "params": fields,
            "changes": bool(changes)}


def coerce(field: dict, raw):
    """One submitted value, turned into what the field declares.

    Raises :class:`AppAPIError` with a sentence a human can act on."""
    kind = field["kind"]
    if kind == "node":
        text = "" if raw is None else str(raw).strip().lower()
        if not _NODE_RE.match(text):
            raise AppAPIError("not a node identity")
        return text
    if kind == "text":
        text = "" if raw is None else str(raw).strip()
        if len(text) > MAX_TEXT:
            raise AppAPIError(f"longer than {MAX_TEXT} characters")
        if "\n" in text or "\r" in text:
            raise AppAPIError("must be a single line")
        return text
    if kind == "flag":
        if isinstance(raw, bool):
            return raw
        text = str(raw).strip().lower()
        if text in ("1", "true", "yes", "on"):
            return True
        if text in ("0", "false", "no", "off", ""):
            return False
        raise AppAPIError("expected yes or no")
    if kind == "count":
        try:
            value = int(raw)
        except (TypeError, ValueError):
            raise AppAPIError("expected a whole number") from None
        if not 0 <= value <= MAX_COUNT:
            raise AppAPIError(f"must be between 0 and {MAX_COUNT}")
        return value
    if kind == "tokens":
        if isinstance(raw, str):
            raw = [part.strip() for part in raw.split(",") if part.strip()]
        if not isinstance(raw, (list, tuple)):
            raise AppAPIError("expected a list")
        if len(raw) > MAX_TOKENS:
            raise AppAPIError(f"more than {MAX_TOKENS} entries")
        out = []
        for entry in raw:
            token = str(entry).strip().lower()
            if not _TOKEN_RE.match(token):
                raise AppAPIError("not a valid token")
            if token not in out:
                out.append(token)
        return out
    raise AppAPIError("unsupported parameter")


def declared(bridge) -> list[dict]:
    """The operations one bridge declares, bounded and de-duplicated."""
    out, seen = [], set()
    for entry in getattr(bridge, "API", ())[:MAX_OPERATIONS]:
        if not isinstance(entry, dict) or entry.get("name") in seen:
            continue
        seen.add(entry["name"])
        out.append(entry)
    return out


class AppAPI:
    """Dispatch to whatever is running, and nothing else.

    Holds no state of its own: an app that is stopped between the catalogue
    being read and a call being made simply is not there any more, and the call
    is refused — which is the honest answer, not an error to work around."""

    def __init__(self, app_host) -> None:
        self._host = app_host

    # -- what exists ------------------------------------------------------

    def _bridge(self, app: str):
        if self._host is None or not _NAME_RE.match(str(app or "")):
            return None
        try:
            return self._host.bridge(app)
        except Exception:
            return None

    def catalogue(self) -> list[dict]:
        """Every operation reachable right now, app by app.

        A page uses this to decide what to *offer*: a button that calls an app
        which is not installed should not be drawn at all, rather than drawn and
        then failing when pressed."""
        out = []
        try:
            names = sorted(self._host.running()) if self._host is not None else []
        except Exception:
            return out
        for app in names:
            bridge = self._bridge(app)
            if bridge is None:
                continue
            operations = declared(bridge)
            if operations:
                out.append({"app": app, "operations": operations})
        return out

    def find(self, app: str, name: str) -> dict | None:
        """The declaration for one operation, or ``None`` if there is none.

        The only lookup path there is. Nothing dispatches on a name that did not
        come back from here."""
        bridge = self._bridge(app)
        if bridge is None:
            return None
        for entry in declared(bridge):
            if entry["name"] == name:
                return entry
        return None

    # -- calling ----------------------------------------------------------

    def call(self, app: str, name: str, args: dict | None = None) -> dict:
        """Invoke a declared operation. Raises :class:`AppAPIError`.

        The handler is ``api_<name>`` on the bridge — but only ever for a
        ``name`` the app itself declared, so a caller cannot reach a method by
        guessing what it is called."""
        entry = self.find(app, name)
        if entry is None:
            raise AppAPIError("no such operation")
        args = args if isinstance(args, dict) else {}
        if len(args) > MAX_ARGS:
            raise AppAPIError("too many arguments")
        declared_names = {field["name"] for field in entry["params"]}
        for supplied in args:
            if str(supplied) not in declared_names:
                raise AppAPIError(f"unknown argument {str(supplied)[:32]!r}")
        call_args = {}
        for field in entry["params"]:
            if field["name"] not in args:
                if field["required"]:
                    raise AppAPIError(f"{field['name']} is required")
                call_args[field["name"]] = field["default"]
                continue
            try:
                call_args[field["name"]] = coerce(field, args[field["name"]])
            except AppAPIError as exc:
                raise AppAPIError(f"{field['name']}: {exc}") from None
        handler = getattr(self._bridge(app), "api_" + name, None)
        if not callable(handler):
            # Declared but not implemented: a bug in the app, not in the call.
            raise AppAPIError("operation is unavailable")
        try:
            result = handler(**call_args)
        except AppAPIError:
            raise
        except Exception as exc:
            # An app that throws must not hand its internals to the caller.
            raise AppAPIError(f"{app}.{name} failed: {type(exc).__name__}") from None
        return result if isinstance(result, dict) else {"result": result}
