"""
The routes an app's page calls, read from the page itself.

An app with a page talks to its own routes (``/api/chat/send``,
``/api/fleet/shell``…). Nothing declares them as operations, and writing each
one again would be a second implementation per route that drifts from the page
the day somebody adds a button. So they are **read from what the browser is
sent**: the bundle the console serves for the page is scanned for the calls it
makes, with the method each one uses. What the page can do is, by construction,
what is offered — the control plane's ``web`` module and the MCP app both read
this list rather than keeping one.

Read once per bundle: a bundle is a constant of this build, so the answer is
too.
"""
from __future__ import annotations

import functools
import re

# `api("/api/chat/send", "POST", …)`, `apiJson("/api/fleet/state?…")`,
# `FEED.read("/api/chat/messages", …)` — the shared runtime's three doors
# (`webassets/ui.py`), plus a bare `fetch` for the page that signs in before
# the runtime has a token. No method named means GET, as in the runtime.
_CALL = re.compile(
    r'\b(?:apiJson|api|FEED\.read|fetch)\(\s*"(/api/[a-z][a-z0-9_]*/[a-z0-9_\-/]*)'
    r'[^"]*"(?:[^,)]*?)\s*(?:,\s*"(GET|POST|PUT|DELETE)")?')
MAX_ROUTES = 64


@functools.lru_cache(maxsize=16)
def routes_in(bundle: str, prefix: str) -> tuple:
    """``(method, path)`` pairs under ``prefix`` that ``bundle`` calls, sorted."""
    found = set()
    for match in _CALL.finditer(bundle or ""):
        path = match.group(1)
        if not path.startswith(prefix) or path == prefix:
            continue
        found.add((match.group(2) or "GET", path.rstrip("/")))
    return tuple(sorted(found, key=lambda pair: (pair[1], pair[0])))[:MAX_ROUTES]
