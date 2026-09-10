"""
The registry: what this node can be asked to do about itself, declared once.

The console used to *be* the management plane. Every action an operator could
take was an ``if path == "/api/…"`` in :mod:`src.webconsole`, its arguments
validated inline, its answer written as a status code — and driving another node
meant replaying the whole HTTP request over the mesh, where the only thing that
could be checked about it was the **prefix of its path**. Three consequences,
all of them structural rather than bad luck:

* what an operator may do to a node they manage was decided by a denylist of
  strings, so a route added anywhere became remotely reachable by default —
  precisely backwards from "reject by default";
* the page and the node agreed on paths and status codes, so the front end was
  pinned to HTTP and nothing else could ever drive the node;
* nothing could answer "what can this node do?", so a page could only offer
  every button and find out on the press.

So the operations move here, next to nothing at all. A **module** groups the
operations of one subject (``node``, ``config``, ``trace``…) and declares them:

.. code-block:: python

    class TraceModule:
        NAME = "trace"
        OPERATIONS = (
            operation("status", "The trace's state and totals",
                      [param("events", "flag", required=False, default=False)],
                      remote=True),
            operation("set", "Start, stop or clear the trace",
                      [param("action", "choice", choices=("start", "stop", "clear"))],
                      changes=True, remote=True),
        )

        def op_status(self, events):
            ...

and every caller reaches them the same way, over whatever channel it has:
``plane.dispatch(Request("trace.status"), origin=Origin.LOCAL)``.

**Reject by default, three times over.** An operation that is not declared does
not exist (dispatch never looks up a name a caller supplied — only a name a
module wrote down). An argument that is not declared is refused rather than
passed on. And an operation is **local-only unless it says otherwise**:
``remote=True`` is the whole of what a peer holding the fleet's ``manage`` right
may ask of this node, which turns that permission from a path denylist into a
list this node maintains about itself.

**A declared ceiling, and it has to fit.** Every operation says how long it may
take. An operation that may be driven remotely must fit inside
:data:`REMOTE_BUDGET` — what the fleet relay can carry there and back — and one
that declares more is refused **at declaration**, not on the call. That is the
gotchas' rule about layered bounds turned into something a reader cannot get
wrong: an operator asking a distant machine to walk six dead addresses would
otherwise wait for the relay to give up and be told nothing about why.
"""
from __future__ import annotations

import re

from .errors import ControlError
from .frame import Reply, Request
from .params import bind

# Bounds on the declaration itself, so a module cannot be the attack.
MAX_MODULES = 32
MAX_OPERATIONS = 32          # per module
MAX_PARAMS = 12              # per operation

# The default ceiling on one operation, and the largest one a remotely-driven
# operation may declare. The remote figure is smaller than what the fleet relay
# allows a replayed call (``fleet_console.CALL_TIMEOUT``) so the far node gives
# up before the pipe does — the caller then hears *why* it failed instead of
# hearing nothing. `tests/test_control_plane.py` holds the two together.
DEFAULT_TIMEOUT = 10.0
REMOTE_BUDGET = 15.0

_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{0,31}$")


class Origin:
    """Who is asking — never *what* they are allowed, only where they are.

    ``LOCAL`` is a page on this machine, holding a session this console issued.
    ``REMOTE`` is a peer driving us through the fleet's ``manage`` capability:
    an operator at another console, whose right to be here was decided by the
    ledger long before the frame arrived. The distinction is not authorisation
    — both are authenticated — it is *reach*: an operator at a remote console
    is not somebody at this node, and what this node spends on itself must not
    be something the network can turn on."""

    LOCAL = "local"
    REMOTE = "remote"
    ALL = (LOCAL, REMOTE)


def operation(name: str, summary: str, params=(), *, changes: bool = False,
              remote: bool = False, timeout: float = DEFAULT_TIMEOUT,
              wants_origin: bool = False) -> dict:
    """Declare one operation.

    ``changes`` marks one that alters state: not a permission — the module
    still decides — but it lets a page ask for confirmation, and it keeps a
    read apart from a write at a glance.

    ``remote`` is the permission, and its default is the point.

    ``wants_origin`` is for the one kind of operation whose *answer* depends on
    who is asking rather than on what they sent: the catalogue, which must list
    what this origin can reach and not what some other origin could. It arrives
    as an extra keyword the caller cannot forge — nothing in a frame can set
    it, and an operation that declares a parameter of that name is refused here
    rather than being quietly shadowed.
    """
    if not _NAME_RE.match(name or ""):
        raise ControlError("bad_request", f"bad operation name {name!r}")
    fields = list(params)
    if len(fields) > MAX_PARAMS:
        raise ControlError("bad_request", f"{name}: too many parameters")
    seen = set()
    for field in fields:
        if not isinstance(field, dict) or "name" not in field:
            raise ControlError("bad_request", f"{name}: not a parameter")
        if field["name"] in seen:
            raise ControlError("bad_request",
                               f"{name}: {field['name']} declared twice")
        seen.add(field["name"])
    if wants_origin and "origin" in seen:
        raise ControlError("bad_request",
                           f"{name}: origin is injected, not declared")
    ceiling = float(timeout)
    if ceiling <= 0:
        raise ControlError("bad_request", f"{name}: a ceiling must be positive")
    if remote and ceiling > REMOTE_BUDGET:
        raise ControlError(
            "bad_request",
            f"{name}: {ceiling:g}s does not fit the relay's {REMOTE_BUDGET:g}s")
    return {"name": name, "summary": str(summary)[:200], "params": fields,
            "changes": bool(changes), "remote": bool(remote),
            "timeout": ceiling, "wants_origin": bool(wants_origin)}


def declared(module) -> list:
    """The operations one module declares, bounded and de-duplicated."""
    out, seen = [], set()
    for entry in getattr(module, "OPERATIONS", ())[:MAX_OPERATIONS]:
        if not isinstance(entry, dict) or entry.get("name") in seen:
            continue
        seen.add(entry["name"])
        out.append(entry)
    return out


class ControlPlane:
    """Every module registered here, and the one way to reach any of them.

    Holds no state beyond the registry: an operation acts on the node, and the
    node is reached through the context each module was given. Two planes over
    one node would therefore be two doors onto the same house — which is why
    there is one, built by whoever owns the node, and handed to the channels."""

    def __init__(self) -> None:
        self._modules: dict = {}

    # -- what exists ------------------------------------------------------

    def register(self, module) -> None:
        """Add one module. Raises :class:`ControlError` on a bad one."""
        name = getattr(module, "NAME", "")
        if not _NAME_RE.match(str(name)):
            raise ControlError("bad_request", f"bad module name {name!r}")
        if name in self._modules:
            raise ControlError("conflict", f"{name} is already registered")
        if len(self._modules) >= MAX_MODULES:
            raise ControlError("conflict", "too many modules")
        operations = declared(module)
        if not operations:
            raise ControlError("bad_request", f"{name} declares no operations")
        for entry in operations:
            if not callable(getattr(module, "op_" + entry["name"], None)):
                # Declared and not implemented is a bug in the module, and it
                # is found here rather than by the operator who pressed it.
                raise ControlError(
                    "bad_request", f"{name}.{entry['name']} has no handler")
        self._modules[name] = module

    def modules(self) -> list:
        return sorted(self._modules)

    def find(self, op: str):
        """``(module, declaration)`` for ``"module.operation"``, or ``None``.

        The only lookup path there is. Nothing dispatches on a name that did
        not come back from here, and nothing here is derived from the caller's
        string beyond splitting it once."""
        if not isinstance(op, str) or op.count(".") != 1:
            return None
        module_name, operation_name = op.split(".", 1)
        module = self._modules.get(module_name)
        if module is None:
            return None
        for entry in declared(module):
            if entry["name"] == operation_name:
                return module, entry
        return None

    def catalogue(self, origin: str = Origin.LOCAL) -> list:
        """What this node exposes, as the given origin can reach it.

        A page uses this to decide what to *offer*: a button that calls an
        operation this node does not have — an app that is not installed, a
        module a remote console cannot reach — should not be drawn at all
        rather than drawn and then refused when pressed. Which is also why the
        remote view is filtered here: an operator driving another node is shown
        what that node lets them do, not what their own would."""
        out = []
        for name in sorted(self._modules):
            entries = [{key: value for key, value in entry.items()
                        if key != "wants_origin"}
                       for entry in declared(self._modules[name])
                       if origin != Origin.REMOTE or entry["remote"]]
            if entries:
                out.append({"module": name, "operations": entries})
        return out

    # -- calling ----------------------------------------------------------

    def dispatch(self, request: Request, origin: str = Origin.LOCAL) -> Reply:
        """Answer one request. **Never raises, never crashes the caller.**

        A management plane that can be made to throw is a management plane an
        adversary can silence, so every path out of here is a :class:`Reply` —
        including the ones that are this code's own fault."""
        ident = getattr(request, "id", "") or ""
        try:
            return Reply.of(self.call(request.op, request.params, origin=origin),
                            ident=ident)
        except ControlError as exc:
            return Reply.refusal(exc, ident=ident)
        except Exception:                       # noqa: BLE001 — never propagate
            return Reply.refusal(
                ControlError("failed", "the operation could not be answered"),
                ident=ident)

    def call(self, op: str, params=None, *, origin: str = Origin.LOCAL) -> dict:
        """Invoke a declared operation, raising :class:`ControlError`.

        The Python-side door — used by :class:`~src.control.channel.LocalChannel`
        and by anything in this process that wants the same answer a page gets,
        rather than a second implementation of it."""
        if origin not in Origin.ALL:
            raise ControlError("bad_request", "unknown origin")
        found = self.find(op)
        if found is None:
            raise ControlError("not_found", "no such operation")
        module, entry = found
        if origin == Origin.REMOTE and not entry["remote"]:
            raise ControlError(
                "refused", f"{op} cannot be driven from a remote console")
        arguments = bind(entry["params"],
                         params if isinstance(params, dict) else {})
        if entry.get("wants_origin"):
            arguments["origin"] = origin
        handler = getattr(module, "op_" + entry["name"], None)
        if not callable(handler):
            raise ControlError("not_found", "operation is unavailable")
        try:
            result = handler(**arguments)
        except ControlError:
            raise
        except Exception as exc:                # noqa: BLE001 — never leak
            # A module that throws must not hand its internals to whoever
            # called: on some channels that is a peer, and an exception's text
            # is a description of this machine.
            raise ControlError(
                "failed", f"{op} failed: {type(exc).__name__}") from None
        return result if isinstance(result, dict) else {"result": result}
