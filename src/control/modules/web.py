"""
The ``web`` module: driving an app that declares no operations.

An app that declares its operations (:mod:`src.app_api`) is reached through
``apps.call``, argument by argument. Chat and fleet declare a handful; most of
what they do lives behind the routes their own pages call — sending a message,
opening a shell, deploying a stack. Writing every one of those again as an
operation would be a second implementation of each, and the next app with a
page would start the list over.

So the routes are **read from what the page is sent**: the script bundle the
console serves for an app is scanned for the calls it makes —
``api("/api/chat/send", "POST", …)`` — and that list is what this module
offers. A route the page does not call is not offered, a route it does call
appears the moment the page does, and nobody keeps a list.

Two gates, and both are narrow on purpose:

* ``request`` is **this machine's only** (no ``remote``, no ``govern``). Chat's
  and fleet's page surfaces were never part of managing a node from somewhere
  else — a managed node is not a jump host — and an operation that reached them
  from a distance would undo exactly that (``Docs/Architecture/control-plane.md``).
* an app reaches it only with ``control.appweb``, which says on the Apps page
  what it is: whatever that app's page can do.

The call itself is the console's own: replayed over the loopback against this
node's console, under a session minted in-process, so every check a page's
request meets — body caps, every refusal — is the one a page meets.
"""
from __future__ import annotations

import json
import re

from ..errors import ControlError
from ..params import param
from ..plane import operation

_READ = 5.0
# A replayed console call is a local HTTP request; the ceiling is the relay's
# own, so a route that waits on the mesh is answered or refused inside it.
_CALL = 15.0
# What an answer may carry back, before it is parsed.
MAX_ANSWER = 512 * 1024

_PATH_RE = re.compile(r"^/api/[a-z][a-z0-9_]{0,31}/[a-z0-9_\-/]{0,96}$")
_QUERY_RE = re.compile(r"^[A-Za-z0-9_\-.=&%:+,]{0,512}$")


class WebModule:
    """The routes an app's page calls, and a way to call them."""

    NAME = "web"

    OPERATIONS = (
        operation("routes", "The routes each app's own page calls",
                  remote=True, timeout=_READ),
        operation("request", "Call one route an app's own page calls",
                  [param("app", "text"), param("method", "choice",
                                               choices=("GET", "POST")),
                   param("path", "line"),
                   param("query", "text", required=False, default=""),
                   param("body", "document", required=False, default=None)],
                  changes=True, timeout=_CALL),
    )

    def __init__(self, context) -> None:
        self._context = context

    def _surface(self):
        surface = self._context.provided("web")
        if surface is None:
            raise ControlError("conflict", "this node serves no app pages")
        return surface

    def op_routes(self) -> dict:
        return {"apps": self._surface().routes()}

    def op_request(self, app: str, method: str, path: str, query: str,
                   body) -> dict:
        surface = self._surface()
        offered = {entry["app"]: entry for entry in surface.routes()}
        if app not in offered:
            raise ControlError("not_found", f"no page for an app called {app[:32]!r}")
        if not _PATH_RE.match(path) or ".." in path or "//" in path:
            raise ControlError("bad_request", "path: not an app route")
        if not _QUERY_RE.match(query or ""):
            raise ControlError("bad_request", "query: letters, digits and = & only")
        # Exactly a route the page calls, with the method it calls it with. A
        # suffix (`/api/chat/messages/<id>`) is not one of those.
        if {"method": method, "path": path} not in offered[app]["routes"]:
            raise ControlError("not_found",
                               f"{app}'s page does not call {method} {path}")
        payload = None
        if method == "POST":
            payload = json.dumps(body if isinstance(body, dict) else {}).encode("utf-8")
        target = path + ("?" + query if query else "")
        try:
            status, ctype, answer = surface.call(method, target, payload)
        except ControlError:
            raise
        except Exception:                       # noqa: BLE001 — never leak
            raise ControlError("unavailable", "this node's console did not answer") from None
        answer = answer[:MAX_ANSWER] if isinstance(answer, (bytes, bytearray)) else b""
        if "json" in str(ctype or ""):
            try:
                data = json.loads(bytes(answer).decode("utf-8") or "null")
            except (UnicodeDecodeError, ValueError):
                data = None
        else:
            # Bytes a page would save rather than read — an avatar, a file.
            # Their size is the answer; their content is not text to relay.
            data = {"bytes": len(answer), "type": str(ctype or "")[:80]}
        return {"status": int(status), "ok": 200 <= int(status) < 300, "data": data}
