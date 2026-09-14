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
passed on. And an operation is **local-only unless it says otherwise**.

**Everything a node can do, an operator can do at a distance.** That is the
goal, and reaching it took two mechanisms rather than a wider permission,
because the two things standing in the way were not one thing:

* *a ceiling* — the fleet relay carries one bounded call and its answer, so an
  operation that takes four hundred seconds could never be one of them. It now
  travels as a **job**: ``background=True``, started through ``jobs.start`` and
  polled through ``jobs.poll``, both of which are small calls. What crosses the
  mesh is a ticket and a question about it, never the wait.
* *a decision* — pinning a publisher key, minting an invitation, holding a
  private key. Those are not "drive this console", they are "decide what this
  node trusts", and folding them into ``manage`` would have made one grant mean
  two things. They declare ``govern=True`` and need the fleet capability of
  that name, which a human at the target grants separately and takes back the
  same way.

So an operation declares **how far it travels**:

==================  ====================================================
``remote=True``     any console holding the fleet's ``manage`` right
``govern=True``     a console holding ``manage`` *and* ``govern``
neither             this machine only — and nothing declares that now
==================  ====================================================

**A declared ceiling, and it has to fit.** Every operation says how long it may
take. One that travels and declares more than :data:`REMOTE_BUDGET` must say
``background=True``, and one that does neither is refused **at declaration**,
not on the call. That is the gotchas' rule about layered bounds turned into
something a reader cannot get wrong: an operator asking a distant machine to
walk six dead addresses would otherwise wait for the relay to give up and be
told nothing about why.
"""
from __future__ import annotations

import re
import sys
import traceback

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

# How much of a failed operation's traceback is written down. Bounded because
# a management plane must not become a way to fill somebody's disk, and because
# a log line nobody can read past is a log line nobody reads.
MAX_TRACE_FRAMES = 12


def _note_failure(op: str, exc: BaseException) -> None:
    """Write a failed operation down, on the machine it failed on.

Nothing else in this project prints a traceback, and that was right up to
    the moment a module could throw: an exception's text is a description of
    this machine and must never reach a peer, so the plane replaces it with a
    type name. Which left a bug inside an operation invisible **everywhere** —
    the console said ``node.state failed: AttributeError`` and the node's own
    log said nothing at all, so the one machine that could have fixed it was
    the one machine not told.

    A **reply** is still not where it goes, even to a page on this machine:
    replies are relayed, pasted and read by scripts, and
    ``tests/test_control_plane.py`` holds the plane to carrying nothing of this
    machine in one whoever asked. A log is the machine's own, so that is where
    it goes, and the refusal says to look there."""
    try:
        lines = traceback.format_exception(type(exc), exc, exc.__traceback__,
                                           limit=MAX_TRACE_FRAMES)
        sys.stderr.write(f"nmesh: control operation {op} failed\n")
        sys.stderr.write("".join(lines))
        sys.stderr.flush()
    except Exception:                       # noqa: BLE001 — never the reason
        pass                                # a failed report is not a failure


class Origin:
    """Who is asking — never *what* they are allowed, only where they are.

    ``LOCAL`` is a page on this machine, holding a session this console issued.
    ``REMOTE`` is a peer driving us through the fleet's ``manage`` capability:
    an operator at another console, whose right to be here was decided by the
    ledger long before the frame arrived. ``GOVERN`` is that same peer holding
    the fleet's ``govern`` capability as well — a second grant, given by a human
    at *this* node and taken back the same way.

    The distinction is not authentication — all three are authenticated — it is
    **reach**: an operator at a remote console is not somebody at this node, and
    a node's own trust decisions are not something the network gets to make
    because it was let in to drive a console."""

    LOCAL = "local"
    GOVERN = "govern"
    REMOTE = "remote"
    ALL = (LOCAL, GOVERN, REMOTE)


# What each origin may call, by the reach an operation declares. Written out
# rather than computed from an ordering: a table a reader can check against the
# sentence above beats a comparison they have to reason about, and this is the
# one place in the plane where being wrong is being open.
REACHED_BY = {
    Origin.LOCAL: ("local", "govern", "remote"),
    Origin.GOVERN: ("govern", "remote"),
    Origin.REMOTE: ("remote",),
}


def reaches(origin: str, entry: dict) -> bool:
    """May ``origin`` call an operation declared like ``entry``?"""
    return entry.get("reach") in REACHED_BY.get(origin, ())


def operation(name: str, summary: str, params=(), *, changes: bool = False,
              remote: bool = False, govern: bool = False,
              background: bool = False, timeout: float = DEFAULT_TIMEOUT,
              wants_origin: bool = False) -> dict:
    """Declare one operation.

    ``changes`` marks one that alters state: not a permission — the module
    still decides — but it lets a page ask for confirmation, and it keeps a
    read apart from a write at a glance.

    ``remote`` and ``govern`` are how far it travels, and the default — neither
    — is the point. They are not two permissions to add up: ``remote`` is every
    console holding ``manage``, which already includes the ones holding
    ``govern`` too, so declaring both is a contradiction and is refused here.

    ``background`` says the operation is run as a **job** rather than inside the
    call. An operation that travels and takes longer than :data:`REMOTE_BUDGET`
    has to, because the relay cannot hold a call open that long; one that fits
    the budget must not, because a ticket for something that could simply have
    been answered is a second mechanism for nothing.

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
    if remote and govern:
        raise ControlError(
            "bad_request",
            f"{name}: remote already includes govern — declare one")
    reach = "remote" if remote else "govern" if govern else "local"
    travels = reach != "local"
    # The two halves of one rule, so neither can be declared alone and be
    # quietly wrong: what does not fit the relay is a job, and what fits it is
    # not. A caller then never has to ask which of two mechanisms an operation
    # uses — its ceiling already says.
    if travels and ceiling > REMOTE_BUDGET and not background:
        raise ControlError(
            "bad_request",
            f"{name}: {ceiling:g}s does not fit the relay's {REMOTE_BUDGET:g}s "
            f"— declare background=True")
    if background and ceiling <= REMOTE_BUDGET:
        raise ControlError(
            "bad_request",
            f"{name}: {ceiling:g}s fits the relay; answer it rather than "
            f"handing back a ticket")
    if background and not travels:
        raise ControlError(
            "bad_request", f"{name}: a job is how an operation travels")
    return {"name": name, "summary": str(summary)[:200], "params": fields,
            "changes": bool(changes), "reach": reach,
            "background": bool(background),
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
        module this console cannot reach — should not be drawn at all rather
        than drawn and then refused when pressed. Which is also why it is
        filtered here: an operator driving another node is shown what that node
        lets *them* do, not what their own would, and an operator who was never
        granted ``govern`` is not shown the buttons it opens."""
        out = []
        for name in sorted(self._modules):
            entries = [{key: value for key, value in entry.items()
                        if key != "wants_origin"}
                       for entry in declared(self._modules[name])
                       if reaches(origin, entry)]
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
        except Exception as exc:                # noqa: BLE001 — never propagate
            # This one is the plane's own fault rather than a module's, which
            # makes writing it down more important, not less: nothing above
            # here will ever see it again.
            _note_failure(getattr(request, "op", "?"), exc)
            return Reply.refusal(
                ControlError("failed", "the operation could not be answered"),
                ident=ident)

    def check(self, op: str, params=None, *, origin: str = Origin.LOCAL):
        """Everything that decides whether a call happens, and nothing that
        happens. ``(module, declaration, arguments)``, or a refusal.

        Its own step because a job needs it *twice over*: once in the caller's
        own call, so a bad argument is a refusal they can read rather than a
        ticket that fails a minute later, and once again in the thread that
        runs it, because between the two the answer is allowed to have
        changed."""
        if origin not in Origin.ALL:
            raise ControlError("bad_request", "unknown origin")
        found = self.find(op)
        if found is None:
            raise ControlError("not_found", "no such operation")
        module, entry = found
        if not reaches(origin, entry):
            raise ControlError(
                "refused", f"{op} needs the govern capability"
                if entry["reach"] == "govern"
                else f"{op} cannot be driven from a remote console")
        arguments = bind(entry["params"],
                         params if isinstance(params, dict) else {})
        if entry.get("wants_origin"):
            arguments["origin"] = origin
        return module, entry, arguments

    def invoke(self, op: str, params=None, *, origin: str = Origin.LOCAL) -> dict:
        """Run a declared operation here and now, whatever it costs.

        The door a **job** comes through, and the only caller that may hold a
        four-hundred-second operation open: it is already off the channel that
        could not have carried it. Everything else calls :meth:`call`."""
        module, entry, arguments = self.check(op, params, origin=origin)
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
            # is a description of this machine. So it is written down here
            # instead — on the machine that owns the node, which is the one
            # able to do anything about it.
            _note_failure(op, exc)
            # The sentence names where the rest of it is. Not an internal —
            # an instruction, and the difference between an operator who can
            # act and one reading the word "AttributeError" about their own
            # node with nowhere to go.
            raise ControlError(
                "failed",
                f"{op} failed: {type(exc).__name__} — this node's log says "
                f"where") from None
        return result if isinstance(result, dict) else {"result": result}

    def call(self, op: str, params=None, *, origin: str = Origin.LOCAL) -> dict:
        """Invoke a declared operation, raising :class:`ControlError`.

        The Python-side door — used by :class:`~src.control.channel.LocalChannel`
        and by anything in this process that wants the same answer a page gets,
        rather than a second implementation of it."""
        found = self.find(op)
        # A job is not a slower call: the relay cannot hold one open, so a
        # console at a distance is handed a ticket instead of a timeout. Said
        # as a refusal with a shape, so a caller re-asks through `jobs.start`
        # rather than having to have read the catalogue first. Checked before
        # `check` binds anything, because the answer does not depend on the
        # arguments and an operator should hear the one thing that is wrong.
        if (found is not None and found[1]["background"]
                and origin != Origin.LOCAL and reaches(origin, found[1])):
            raise ControlError(
                "refused", f"{op} takes longer than one call across the mesh — "
                f"start it as a job", {"background": True, "job": op})
        return self.invoke(op, params, origin=origin)
