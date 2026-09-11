"""
The wire format of the control channel: one request, one reply.

Everything the management plane carries is one of these two documents, and they
are the same document whichever channel moves them — a page's HTTPS request to
this node's console, that request relayed over the mesh to a node somebody
manages, a test calling the plane with no socket at all. That is the whole point
of naming a format: *what* is being asked stops depending on *how* it arrived.

    request   {"v": 1, "id": "7f3a", "op": "node.state", "params": {...}}
    reply     {"v": 1, "id": "7f3a", "ok": true,  "result": {...}}
              {"v": 1, "id": "7f3a", "ok": false, "code": "refused",
               "error": "not reachable from a remote console"}

The ``id`` is the caller's own, echoed back untouched: a channel that multiplexes
(a page with three panels open) matches answers to questions by it, and a channel
that does not simply ignores it. It is never used to look anything up here — an
identifier a caller chooses must not become a key into our state.

**Decoding is hostile-input first.** These bytes reach us from a browser this
node authenticated *and* from a peer replaying a frame through the fleet relay,
which the threat model says is an adversary. So: a size cap before parsing, a
type check on every field, a bound on every string, and no recursion of our own
— a frame is exactly two levels deep, and ``params`` is validated by the
operation that declared them (:mod:`src.control.params`), never trusted for
having arrived. The parser *does* recurse, so a frame of nothing but brackets
is counted, not parsed (``_shallow_enough``), and refused before ``json`` ever
sees it — depending on the interpreter to refuse it by exhausting its own
recursion limit stopped being reliable the day Python 3.13 raised how deep
that tolerates within one frame (``Docs/Architecture/gotchas.md``).

There is no event frame. Events travel as an ordinary operation
(``control.changes``, "what has moved since sequence N"), because a channel that
relays one bounded request and its answer — which the mesh relay is — cannot
carry a stream, and one mechanism that works on every channel beats two that
each work on one. The console's ``text/event-stream`` is a push optimisation of
that same information over the one channel that can hold a socket open, not a
second vocabulary (see ``Docs/Architecture/control-plane.md``).
"""
from __future__ import annotations

import json

from .errors import ControlError, FrameError

VERSION = 1
# One *request* on the wire. Deliberately far smaller than the console's body
# cap: a management call carries names, identities and settings — never a file.
# What does carry bytes (an upload, an avatar) has its own route and its own,
# larger ceiling, and is not a control frame. Sized to exactly what the fleet
# relay will carry to another node (``fleet.CONSOLE_REQ_MAX``): a frame this
# side accepts and the pipe then drops is a request that fails for a reason the
# operator cannot see. The largest real one is a certificate on its way to
# being trusted — 14 kB of hex — which is why this is not smaller.
MAX_FRAME = 24 * 1024
# One *reply*. Larger, because a question is a sentence and an answer is a
# table: the node's snapshot, a page of the trace, the whole catalogue. Sized to
# what the fleet relay will reassemble (``fleet.CONSOLE_RESP_MAX``) so a reply
# this side would accept is never one the pipe drops —
# ``tests/test_control_plane.py`` holds the two figures together.
MAX_REPLY = 512 * 1024
MAX_OP = 64          # "module.operation", both halves bounded by params.py
MAX_ID = 64          # the caller's correlation id, echoed and never read
MAX_PARAMS = 24      # keys in one request, before the operation is consulted
# How deep `{`/`[` may nest before a document is refused unparsed. A request
# nests at most a handful of levels (`params` → a `document` kind's own one
# permitted level, `control.params.MAX_KEYS`-many keys wide rather than deep).
# The deepest legitimate *reply* is `control.catalogue` — every module, every
# operation, every declared param, down to a `choice` param's own list of
# names — nine levels from the envelope down. `MAX_NESTING` leaves that room
# to grow and is still nowhere near what an attack needs — see `decode_request`
# for why it exists at all.
MAX_NESTING = 24


def _text(value, limit: int, what: str) -> str:
    if not isinstance(value, str):
        raise FrameError(f"{what} must be text")
    if len(value) > limit:
        raise FrameError(f"{what} is too long")
    return value


def _shallow_enough(raw: bytes) -> bool:
    """A bracket count over the *bytes*, never a parse: no recursion of our own.

    `json` recurses once per nesting level, so a frame of nothing but opening
    brackets used to be refused as a side effect of it hitting the
    interpreter's own recursion limit — until Python 3.13 raised how many
    levels the C decoder tolerates well past what fits in a frame, and the
    same 5 000-bracket document that used to raise `RecursionError` before any
    check here ran instead parsed clean (`Docs/Architecture/gotchas.md`). A
    limit this function enforces itself cannot move out from under it again.

    Structural characters only count outside a string, so a label or a value
    that happens to contain ``{`` does not; nothing here needs to know what a
    string *means*, only where one ends, which needs no recursion either."""
    depth = 0
    in_string = False
    escaped = False
    for byte in raw:
        if in_string:
            if escaped:
                escaped = False
            elif byte == 0x5C:            # \
                escaped = True
            elif byte == 0x22:            # "
                in_string = False
            continue
        if byte == 0x22:                  # "
            in_string = True
        elif byte == 0x7B or byte == 0x5B:  # { [
            depth += 1
            if depth > MAX_NESTING:
                return False
        elif byte == 0x7D or byte == 0x5D:  # } ]
            depth -= 1
    return True


class Request:
    """One question, decoded and shaped, with nothing validated beyond shape.

    ``params`` is still whatever the caller sent — a dict, bounded in size, of
    values nobody has looked at. The operation's own declaration is what turns
    it into arguments, and it is the only thing allowed to."""

    __slots__ = ("op", "params", "id")

    def __init__(self, op: str, params=None, ident: str = "") -> None:
        self.op = op
        self.params = params if isinstance(params, dict) else {}
        self.id = ident

    def __repr__(self) -> str:      # pragma: no cover - debugging aid
        return f"<Request {self.op} {sorted(self.params)}>"


class Reply:
    """One answer. ``ok`` decides which half of it is meaningful."""

    __slots__ = ("ok", "result", "code", "error", "detail", "id")

    def __init__(self, ok: bool, result=None, code: str = "",
                 error: str = "", ident: str = "", detail=None) -> None:
        self.ok = bool(ok)
        self.result = result if isinstance(result, dict) else {}
        self.code = code
        self.error = error
        self.detail = detail if isinstance(detail, dict) else {}
        self.id = ident

    @classmethod
    def of(cls, result, ident: str = "") -> "Reply":
        return cls(True, result if isinstance(result, dict) else {"result": result},
                   ident=ident)

    @classmethod
    def refusal(cls, error: ControlError, ident: str = "") -> "Reply":
        return cls(False, None, error.code, error.message, ident=ident,
                   detail=getattr(error, "detail", None))

    def document(self) -> dict:
        base = {"v": VERSION, "id": self.id, "ok": self.ok}
        if self.ok:
            base["result"] = self.result
        else:
            base["code"] = self.code
            base["error"] = self.error
            if self.detail:
                base["detail"] = self.detail
        return base

    def raise_for_refusal(self) -> dict:
        """The result, or the refusal as an exception.

        For a caller that would only write the same three lines: a channel used
        from Python wants a value or a raise, not a document to inspect."""
        if not self.ok:
            raise ControlError(self.code, self.error, self.detail)
        return self.result


def decode_request(raw) -> Request:
    """Bytes off a channel → a :class:`Request`, or :class:`FrameError`.

    The size check comes first and on the *bytes*: parsing a 40 MB document to
    then decide it was too big is the work an attacker was hoping for."""
    if isinstance(raw, str):
        raw = raw.encode("utf-8", "replace")
    if not isinstance(raw, (bytes, bytearray)):
        raise FrameError("no frame")
    if not raw:
        raise FrameError("empty frame")
    if len(raw) > MAX_FRAME:
        raise FrameError("frame too large")
    if not _shallow_enough(raw):
        raise FrameError("not a frame")
    try:
        document = json.loads(bytes(raw).decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise FrameError("not a frame") from None
    except RecursionError:                # pragma: no cover - belt and braces
        # `_shallow_enough` is the real guard; this is what stood alone before
        # Python 3.13 moved the interpreter's own limit out of reach of a
        # frame (`Docs/Architecture/gotchas.md`) and stays as a second layer.
        raise FrameError("not a frame") from None
    if not isinstance(document, dict):
        raise FrameError("not a frame")
    version = document.get("v", VERSION)
    if version != VERSION:
        # A version we do not speak is refused, never guessed at. `features.py`
        # makes the same choice for the mesh: silence about a name is "no".
        raise FrameError("unsupported frame version")
    op = _text(document.get("op"), MAX_OP, "the operation")
    ident = _text(document.get("id", ""), MAX_ID, "the request id")
    params = document.get("params", {})
    if params is None:
        params = {}
    if not isinstance(params, dict):
        raise FrameError("params must be a mapping")
    if len(params) > MAX_PARAMS:
        raise FrameError("too many params")
    for name in params:
        if not isinstance(name, str) or len(name) > MAX_OP:
            raise FrameError("a param name that is not text")
    return Request(op, params, ident)


def decode_reply(raw) -> Reply:
    """The answer side, decoded with the same suspicion.

    Used by the channel that speaks to *another node's* plane: what comes back
    is a document a machine we do not run composed, so "it is our own format"
    is not a reason to trust its shape."""
    if isinstance(raw, str):
        raw = raw.encode("utf-8", "replace")
    if not isinstance(raw, (bytes, bytearray)) or not raw:
        raise FrameError("no reply")
    if len(raw) > MAX_REPLY:
        raise FrameError("reply too large")
    if not _shallow_enough(raw):
        raise FrameError("not a reply")
    try:
        document = json.loads(bytes(raw).decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise FrameError("not a reply") from None
    except RecursionError:                # pragma: no cover - belt and braces
        raise FrameError("not a reply") from None
    if not isinstance(document, dict):
        raise FrameError("not a reply")
    ident = document.get("id", "")
    ident = ident if isinstance(ident, str) and len(ident) <= MAX_ID else ""
    if document.get("ok") is True:
        result = document.get("result")
        return Reply(True, result if isinstance(result, dict) else {}, ident=ident)
    code = document.get("code")
    error = document.get("error")
    detail = document.get("detail")
    return Reply(False, None,
                 code if isinstance(code, str) else "failed",
                 error[:200] if isinstance(error, str) else "",
                 ident=ident,
                 # Bounded on the way in as well as out: this half of a refusal
                 # may have been composed by a node we do not run.
                 detail=detail if isinstance(detail, dict) and len(detail) <= 8
                 else None)


def encode(document) -> bytes:
    """A frame on its way out. Never raises on unserialisable content.

    A handler that returns something ``json`` cannot write is a bug here, and
    the shape it must not take is a socket that closes with nothing on it: that
    reads to the operator as "it loads for ever", which says nothing about
    where the fault is (``WebConsole._answering`` learned this the hard way)."""
    try:
        return json.dumps(document).encode("utf-8")
    except (TypeError, ValueError):
        return json.dumps({"v": VERSION, "id": "", "ok": False,
                           "code": "failed",
                           "error": "the answer could not be encoded"}).encode("utf-8")
