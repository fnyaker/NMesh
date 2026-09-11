"""
What an argument of a control operation may be.

The kinds an app already declares (:mod:`src.app_api` — ``node``, ``text``,
``flag``, ``count``, ``tokens``) are exactly the kinds a management operation
needs most of the time, and they are **reused rather than restated**: the shape
of a ``NodeID`` is checked in one place in this project, and adding a second
place is how the two come to disagree.

The management plane needs three more, and only three:

``line``
    A path, a URI, a search query. Longer than ``text`` (a filesystem path is
    not a label) and still one line: a newline in a value that ends up in a
    header or a configuration file starts a second one.
``document``
    A bounded mapping — the settings of a form, one transport's fields. Values
    are scalars, or one further level of scalars (``{scheme: {field: value}}``),
    and **that is the end of it**: no recursion, so a caller cannot spend our
    stack describing an object nobody asked for. The *meaning* of the values is
    not decided here — ``config.apply_edits`` and ``TransportManager.configure``
    each validate their own, and they are the authority.
``choice``
    One name out of a closed list the operation itself writes down. Cheaper to
    read than a ``text`` the handler then compares three times.
``hex``
    Bytes written as hex, with a ``limit`` on how many characters. A
    certificate is the case: 14 kB of it, which is neither a label nor a line,
    and which the node must not be handed until it *is* hex — the check is one
    regular expression here rather than an exception from a parser three
    frames down.
``secret``
    A passphrase, and the one kind that is **not** trimmed. Every other text
    field strips what surrounds it, which is right for a label and wrong here:
    a space at the end of a passphrase *is* the passphrase, and quietly
    removing it would unlock nothing and explain nothing. Bounded and checked
    for a null byte, and that is the whole of what may be done to it.

A ``count`` may also carry a ``limit``, and it is the one value in this module
that is **clamped rather than refused**. The reason is ownership: the thing
being bounded owns the bound — the trace decides how long it may run and how
many events it may hold — so a declaration here is the *outer copy* of that
decision and must not disagree with it. It is written as
``param("seconds", "count", limit=trace.MAX_SECONDS)``: the same constant, not
a second guess at it. Without a ``limit`` a count is refused above the app
API's ceiling, because then nothing downstream has an opinion to defer to.

Every kind is a refusal, not a repair: a value that is not what was declared is
refused with a sentence naming the field, never trimmed into something that
looks valid. Truncating a path gives you a different file and tells nobody, and
reading the string "no" as a yes would move links and bind sockets on the
strength of a guess. ``text`` and ``flag`` are therefore narrower here than in
the app API, whose callers are HTML forms where everything is a string.
"""
from __future__ import annotations

import re

from .. import app_api
from .errors import ControlError

# Bounds. None of them is a guess about what an operator "should" need; each is
# there so an argument cannot become a payload.
MAX_LINE = 1024          # a path, a URI, a query — never a document
MAX_KEYS = 64            # entries in one `document`, per level
MAX_KEY = 64             # length of one of its keys
MAX_VALUE = 512          # length of one of its scalar values
MAX_CHOICES = 32

KINDS = app_api.KINDS + ("line", "document", "choice", "hex", "secret")

# The largest `hex` a declaration may allow. A self-signed certificate is about
# 14 kB of hex; the ceiling leaves room for a longer key without ever
# approaching what one frame carries (`frame.MAX_FRAME`).
MAX_HEX = 20000
# A passphrase. Long enough for anything a person types or a manager generates,
# short enough that it is an argument rather than a payload.
MAX_SECRET = 512
# An identifier written as hex — a record, an offer, a signing key's id. They
# are hashes, so the real ones are 40 or 64 characters; the ceiling is well
# above that because its job is to refuse a payload, not to police a length the
# hash already decides.
MAX_ID_HEX = 256

_HEX_RE = re.compile(r"^[0-9a-f]*$")
_KEY_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.:-]{0,%d}$" % (MAX_KEY - 1))
_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{0,31}$")


def param(name: str, kind: str, *, required: bool = True, default=None,
          help: str = "", choices=(), limit=None) -> dict:
    """Declare one argument. Raises :class:`ControlError` on a bad declaration.

    Raised at import time, which is where a bad declaration belongs: an
    operation whose parameters do not make sense must never be reachable, and
    finding that out when somebody presses the button is finding out too late."""
    if kind in app_api.KINDS:
        # One implementation of the shared kinds, and it is the app API's.
        try:
            field = app_api.param(name, kind, required=required,
                                  default=default, help=help)
        except app_api.AppAPIError as exc:
            raise ControlError("bad_request", str(exc)) from None
        if limit is not None:
            if kind != "count":
                raise ControlError("bad_request",
                                   f"{name}: only a count takes a limit")
            field["limit"] = max(0, int(limit))
        return field
    if kind not in KINDS:
        raise ControlError("bad_request", f"unknown kind {kind!r}")
    if not _NAME_RE.match(name or ""):
        raise ControlError("bad_request", f"bad parameter name {name!r}")
    field = {"name": name, "kind": kind, "required": bool(required),
             "default": default, "help": help}
    if kind == "choice":
        allowed = [str(entry) for entry in choices][:MAX_CHOICES]
        if not allowed:
            raise ControlError("bad_request", f"{name}: a choice needs choices")
        field["choices"] = allowed
    if kind == "hex":
        if limit is None:
            raise ControlError("bad_request", f"{name}: hex needs a limit")
        field["limit"] = min(max(0, int(limit)), MAX_HEX)
    return field


def _scalar(raw, where: str):
    """One value inside a ``document``: text, a number, a flag, or nothing."""
    if raw is None or isinstance(raw, bool) or isinstance(raw, int):
        return raw
    if isinstance(raw, float):
        return raw
    if isinstance(raw, str):
        if len(raw) > MAX_VALUE:
            raise ControlError(
                "bad_request", f"{where} is longer than {MAX_VALUE} characters")
        if "\x00" in raw:
            raise ControlError("bad_request", f"{where} contains a null byte")
        if "\n" in raw or "\r" in raw:
            # The same refusal `line` makes, and for the sharper version of the
            # same reason: these values are written into a configuration file,
            # one `name = value` per line, so a newline in one does not make a
            # longer value — it makes a second *setting*. The file layer refuses
            # it too (`config.validate`); this is the half that belongs to
            # whoever declared the field.
            raise ControlError("bad_request", f"{where} must be a single line")
        return raw
    if isinstance(raw, (list, tuple)):
        # A list of scalars is how a setting spelled as several values arrives
        # (`bootstrap`, `transports`). Bounded like everything else.
        if len(raw) > MAX_KEYS:
            raise ControlError("bad_request", f"{where} has too many entries")
        return [_scalar(entry, where) for entry in raw]
    raise ControlError("bad_request", f"{where} is not a value")


def _document(raw, where: str, depth: int) -> dict:
    if not isinstance(raw, dict):
        raise ControlError("bad_request", f"{where} must be a mapping")
    if len(raw) > MAX_KEYS:
        raise ControlError("bad_request", f"{where} has too many entries")
    out: dict = {}
    for key, value in raw.items():
        if not isinstance(key, str) or not _KEY_RE.match(key):
            raise ControlError("bad_request", f"{where}: bad name {str(key)[:32]!r}")
        if isinstance(value, dict):
            if depth <= 0:
                # The one place recursion could have crept in. Two levels is
                # what the deepest real caller needs (a transport's fields under
                # its scheme); anything deeper is refused rather than walked.
                raise ControlError("bad_request", f"{where}.{key} is nested too deep")
            out[key] = _document(value, f"{where}.{key}", depth - 1)
            continue
        out[key] = _scalar(value, f"{where}.{key}")
    return out


def coerce(field: dict, raw):
    """One submitted value, turned into what the field declares.

    Raises :class:`ControlError` (``bad_request``) with a sentence a human can
    act on. The shared kinds are the app API's implementation, its refusals
    re-worded into this plane's vocabulary and nothing else."""
    kind = field.get("kind")
    if kind == "count" and field.get("limit") is not None:
        try:
            value = int(raw)
        except (TypeError, ValueError):
            raise ControlError("bad_request", "expected a whole number") from None
        # Clamped, because whatever this bounds already decided the ceiling.
        return max(0, min(value, int(field["limit"])))
    if kind == "flag" and raw is not None and not isinstance(raw, bool):
        # Same reason as text below: a form sends "on", a frame sends `true`.
        # A toggle that accepted the string "no" as a yes would be a repair
        # with consequences — this one binds sockets and moves links.
        raise ControlError("bad_request", "expected true or false")
    if kind == "text" and raw is not None and not isinstance(raw, str):
        # The app API coerces a number into its digits, and it is right to: its
        # callers are HTML forms, where every field is a string on the wire. A
        # control frame is JSON, so a value declared as text either arrived as
        # text or the caller made a mistake — and renaming a node to "42"
        # because somebody sent the number is a repair, which this plane does
        # not do.
        raise ControlError("bad_request", "must be text")
    if kind in app_api.KINDS:
        try:
            return app_api.coerce(field, raw)
        except app_api.AppAPIError as exc:
            raise ControlError("bad_request", str(exc)) from None
    name = field.get("name", "value")
    if kind == "line":
        text = "" if raw is None else str(raw)
        if len(text) > MAX_LINE:
            raise ControlError("bad_request",
                               f"longer than {MAX_LINE} characters")
        if "\n" in text or "\r" in text or "\x00" in text:
            raise ControlError("bad_request", "must be a single line")
        return text
    if kind == "document":
        return _document(raw, name, depth=1)
    if kind == "choice":
        text = "" if raw is None else str(raw).strip()
        if text not in field.get("choices", ()):
            allowed = ", ".join(field.get("choices", ()))
            raise ControlError("bad_request", f"must be one of {allowed}")
        return text
    if kind == "secret":
        if not isinstance(raw, str):
            raise ControlError("bad_request", "must be text")
        if len(raw) > MAX_SECRET:
            raise ControlError("bad_request",
                               f"longer than {MAX_SECRET} characters")
        if "\x00" in raw:
            raise ControlError("bad_request", "contains a null byte")
        return raw            # not stripped, deliberately
    if kind == "hex":
        if not isinstance(raw, str):
            raise ControlError("bad_request", "must be hex text")
        text = raw.strip().lower()
        if len(text) > int(field.get("limit", MAX_HEX)):
            raise ControlError("bad_request", "longer than this field allows")
        # Empty is not a value: a field declared as bytes means *these* bytes,
        # and an empty one reaches the node as a key nobody has.
        if not text or len(text) % 2 or not _HEX_RE.match(text):
            raise ControlError("bad_request", "not hex")
        return text
    raise ControlError("bad_request", "unsupported parameter")


def bind(fields, params: dict) -> dict:
    """Declared fields + what the caller sent → the arguments to call with.

    Reject by default, in both directions: an argument nobody declared is a
    refusal rather than something passed through to a handler that might read
    it, and a declared argument that is missing and required is a refusal rather
    than a ``None`` the handler discovers halfway down."""
    declared = {field["name"]: field for field in fields}
    for supplied in params:
        if supplied not in declared:
            raise ControlError("bad_request",
                               f"unknown argument {str(supplied)[:32]!r}")
    out = {}
    for name, field in declared.items():
        if name not in params:
            if field["required"]:
                raise ControlError("bad_request", f"{name} is required")
            out[name] = field["default"]
            continue
        try:
            out[name] = coerce(field, params[name])
        except ControlError as exc:
            raise ControlError(exc.code, f"{name}: {exc.message}") from None
    return out
