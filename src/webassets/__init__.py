"""
Embedded web assets — one design system, three pages.

Everything the browser loads lives here as Python strings: the console is often
installed read-only, and a page that reads files at runtime is a page that can
half-load. Served same-origin so a strict ``default-src 'self'`` CSP applies,
with no inline script and no external resource (no CDN, no web font, no
analytics — the console works on a machine with no internet at all).

Layout, and the rule that keeps it from drifting:

* :mod:`.ui` is the **design system** — tokens, base, components, app shell,
  and the JS every page shares. Nothing page-specific goes in it.
* :mod:`.console`, :mod:`.chat`, :mod:`.fleet` and :mod:`.nodeview` hold one
  page each: markup, the page's own JS, and only the CSS that genuinely belongs
  to that page.
* :mod:`.terminal` is the other shared piece: the emulator, the session driver
  and the styles a terminal needs, mounted by ``/fleet`` for its panel and by
  ``/term`` for the full-screen page it also carries. Two terminals would be two
  copies of every bug in one.
* :mod:`.nodeview` is the exception that proves the rule: it is a *view* before
  it is a page. All three pages mount it — the console in a dialog, chat in a
  panel, fleet in its sheet — and it also serves itself at ``/node`` for the
  window or tab a viewer may prefer. One description of a node, not four that
  drift.

Each page's stylesheet is ``ui.CSS`` plus its own, and each page's script is
``ui.JS`` plus its own. So a token changed once changes all three pages, and a
page cannot quietly grow a second button style: there is one to reach for.
"""
from . import ui
from .chat import CHAT_HTML, CHAT_PAGE_CSS, CHAT_PAGE_JS
from .console import INDEX_HTML, CONSOLE_PAGE_CSS, CONSOLE_PAGE_JS
from .fleet import FLEET_HTML, FLEET_PAGE_CSS, FLEET_PAGE_JS
from .nodeview import (NODE_PAGE_CSS_FULL as _NODE_PAGE_CSS,
                       PAGE_HTML as NODE_HTML, PAGE_JS as _NODE_PAGE_JS)
from . import nodeview, terminal
from .terminal import PAGE_HTML as TERM_HTML

# The node view rides along with the console page: the dialog there mounts it.
STYLE_CSS = ui.CSS + nodeview.CSS + CONSOLE_PAGE_CSS
APP_JS = ui.JS + nodeview.JS + CONSOLE_PAGE_JS

# Chat and fleet mount the same view in place rather than framing the page:
# same code, same document, nothing to let through a frame.
CHAT_CSS = ui.CSS + nodeview.CSS + CHAT_PAGE_CSS
CHAT_JS = ui.JS + nodeview.JS + CHAT_PAGE_JS

FLEET_CSS = ui.CSS + nodeview.CSS + terminal.CSS + FLEET_PAGE_CSS
FLEET_JS = ui.JS + nodeview.JS + terminal.JS + FLEET_PAGE_JS

# The terminal, given the whole screen. Same emulator and same session driver as
# the panel on /fleet — mounted here with the page that is built around them.
TERM_CSS = ui.CSS + terminal.CSS + terminal.PAGE_CSS
TERM_JS = ui.JS + terminal.JS + terminal.PAGE_JS

NODE_CSS = ui.CSS + _NODE_PAGE_CSS
NODE_JS = ui.JS + nodeview.JS + _NODE_PAGE_JS

__all__ = ["INDEX_HTML", "STYLE_CSS", "APP_JS",
           "CHAT_HTML", "CHAT_CSS", "CHAT_JS",
           "FLEET_HTML", "FLEET_CSS", "FLEET_JS",
           "TERM_HTML", "TERM_CSS", "TERM_JS",
           "NODE_HTML", "NODE_CSS", "NODE_JS", "ui"]
