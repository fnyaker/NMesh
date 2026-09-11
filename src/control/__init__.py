"""
The control plane: one channel between whatever manages a node and the node.

Read this before touching the console or the fleet relay —
``Docs/Architecture/control-plane.md`` is the long version.

The shape
---------

::

    a page in a browser        another operator's console
            │                            │
            │  frame (JSON)              │  the same frame
            ▼                            ▼
    ┌───────────────────┐        ┌────────────────────┐
    │ LocalChannel      │        │ RemoteChannel      │  ── points the channel
    │  origin = local   │        │  relay → the mesh  │     at another node
    └────────┬──────────┘        └─────────┬──────────┘
             │                             │  (fleet `manage`, replayed
             ▼                             ▼   against that node's console)
      ┌────────────────────────────────────────────┐
      │ ControlPlane — the modules, and only them  │
      │  node · config · transports · trace ·      │
      │  pseudo · control                          │
      └────────────────────────────────────────────┘

One vocabulary, three properties that came out of naming it:

**Reject by default, per operation.** What a peer holding the fleet's ``manage``
right may ask of this node is a list this node keeps about *itself* — one
``remote=True`` per operation — instead of a denylist of URL prefixes that every
new route joined by default.

**The front end stops speaking HTTP.** A page asks for ``node.state``; whether
that reaches this machine or the machine it is managing is which channel carried
it. Nothing above the channel changes, so there is no second front end for
remote management, and no route that works locally and quietly does not remotely.

**A node can say what it can do.** ``control.catalogue`` answers with the
operations reachable *by whoever is asking*, so a page draws what exists rather
than everything and finding out on the press.

Using it
--------

.. code-block:: python

    context = Context(node=node, config_path=path, apps=host.overview,
                      changes=book)
    plane = build(context)                     # every built-in module
    channel = LocalChannel(plane)
    channel.call("node.state").raise_for_refusal()

Nothing in here imports the console, the fleet app or HTTP: the plane is the
node's management surface, and a channel is how somebody reached it.
"""
from __future__ import annotations

from .channel import (BaseChannel, LocalChannel, RefusedChannel,
                      RemoteChannel)
from .context import Context, on_loop
from .errors import CODES, ControlError, FrameError
from .frame import (MAX_FRAME, MAX_REPLY, Reply, Request, decode_reply,
                    decode_request, encode)
from .modules import install
from .params import coerce, param
from .plane import ControlPlane, Origin, operation

__all__ = [
    "BaseChannel", "CODES", "Context", "ControlError", "ControlPlane",
    "FrameError", "LocalChannel", "MAX_FRAME", "MAX_REPLY", "Origin",
    "RefusedChannel", "RemoteChannel", "Reply", "Request", "build", "coerce",
    "decode_reply",
    "decode_request", "encode", "install", "on_loop", "operation", "param",
]


def build(context) -> ControlPlane:
    """A plane with every built-in module on it.

    The one constructor anything outside this package should need: a caller
    that assembled its own would be a caller that can forget one."""
    return install(ControlPlane(), context)
