"""
The two ends of the management link, and the one thing they have in common.

A **channel** carries a frame and brings back its answer. That is all it is,
and everything else about it — a socket, a thread bridge, a mesh route, three
hops and a base32 chunking — is the channel's own business.

Two exist:

:class:`LocalChannel`
    The plane in this process. The console's request handler decodes a frame,
    hands it here, and writes back what comes out.
:class:`RemoteChannel`
    **The same channel, pointed at another node.** The frame is handed to a
    relay that puts it on the mesh; the node at the other end feeds it to *its*
    plane, as an operation from a remote origin, and its reply comes back as
    the reply to this call.

Which one a request uses is one decision in one place, and nothing above it
changes: a page asks the console for ``node.state``, and whether that means
"this machine" or "the machine I am managing" is a channel, not a route, not a
second front end, and not a different set of buttons.

The relay is **injected, never imported**. This package knows nothing about the
fleet app, about HTTP or about how a frame reaches another node — that keeps the
one file that decides "reject by default" free of everything that could make it
depend on the transport it was reached over.

The bound is the caller's here, and it is the *outer* one: the relay's own
ceiling, the far node's console call, and the operation's declared ceiling all
sit inside it (``Docs/Architecture/gotchas.md``, "a bound at one layer is not a
bound").
"""
from __future__ import annotations

from .errors import ControlError, FrameError
from .frame import Reply, Request, decode_reply, decode_request, encode
from .plane import Origin


class BaseChannel:
    """One end of the management link.

    Subclasses implement :meth:`send`; :meth:`call` is written once here so
    that a caller in Python and a caller behind a socket take exactly the same
    path through the same validation."""

    #: What this channel is pointed at — "" for this node, else a node id hex.
    target = ""

    def send(self, raw) -> bytes:
        """A request frame in, a reply frame out. Never raises."""
        raise NotImplementedError

    def call(self, op: str, params=None, ident: str = "") -> Reply:
        """Ask for one operation and get a :class:`~src.control.frame.Reply`.

        Goes through the frame rather than around it — a Python caller that
        skipped encoding would be exercising a path no page ever takes, and the
        first thing to rot is the path only one caller uses.

        A :class:`Reply` whatever happens, including when what came back was
        not a frame at all. This is the promise the whole plane rests on: a
        caller drives another machine through here, and "the far side answered
        with something I could not read" has to be an answer rather than an
        exception in the middle of a page's repaint."""
        document = {"v": 1, "id": ident, "op": str(op), "params": params or {}}
        try:
            return decode_reply(self.send(encode(document)))
        except ControlError as exc:
            return Reply.refusal(exc, ident=ident)


class LocalChannel(BaseChannel):
    """The plane in this process.

    ``origin`` is not the caller's to choose: a channel is built by whoever
    knows where the frame came from — the console's own request handler builds
    a local one, the fleet relay's replay arrives with the marker that makes it
    remote — and the plane refuses anything the origin may not reach."""

    def __init__(self, plane, origin: str = Origin.LOCAL) -> None:
        self._plane = plane
        self._origin = origin if origin in Origin.ALL else Origin.REMOTE

    def send(self, raw) -> bytes:
        try:
            request = decode_request(raw)
        except FrameError as exc:
            return encode(Reply.refusal(exc).document())
        return encode(self._plane.dispatch(request, self._origin).document())

    def call(self, op: str, params=None, ident: str = "") -> Reply:
        # The one shortcut, and it skips only the JSON: same plane, same
        # binding, same refusals. It exists because the console's own routes
        # call the plane a hundred times a page and re-encoding their arguments
        # to immediately decode them would be work with no reader.
        return self._plane.dispatch(Request(str(op), params, ident), self._origin)


class RemoteChannel(BaseChannel):
    """The channel, pointed at a node this operator manages.

    ``relay(node_hex, frame_bytes) -> reply_frame_bytes`` is whatever can move
    a bounded request to that node and bring its answer back; today it is the
    fleet app's ``manage`` capability replaying it against the far console.
    Anything that can do that — a serial line, a courier with a USB stick —
    is a relay, and this class cannot tell the difference."""

    def __init__(self, node_hex: str, relay) -> None:
        self.target = str(node_hex or "").lower()
        self._relay = relay

    def send(self, raw) -> bytes:
        try:
            answer = self._relay(self.target, bytes(raw))
        except ControlError as exc:
            return encode(Reply.refusal(exc).document())
        except Exception:                       # noqa: BLE001 — never propagate
            # The relay failing is not the far node refusing, and an operator
            # has to be able to tell them apart: this is "the message did not
            # get there", which is `unavailable`, not a refusal.
            return encode(Reply.refusal(ControlError(
                "unavailable", "that node could not be reached")).document())
        if not isinstance(answer, (bytes, bytearray)):
            return encode(Reply.refusal(ControlError(
                "failed", "the relay answered with nothing")).document())
        return bytes(answer)
