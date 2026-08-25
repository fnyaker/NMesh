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
* :mod:`.console`, :mod:`.chat` and :mod:`.fleet` hold one page each: markup,
  the page's own JS, and only the CSS that genuinely belongs to that page.

Each page's stylesheet is ``ui.CSS`` plus its own, and each page's script is
``ui.JS`` plus its own. So a token changed once changes all three pages, and a
page cannot quietly grow a second button style: there is one to reach for.
"""
from . import ui
from .chat import CHAT_HTML, CHAT_PAGE_CSS, CHAT_PAGE_JS
from .console import INDEX_HTML, CONSOLE_PAGE_CSS, CONSOLE_PAGE_JS
from .fleet import FLEET_HTML, FLEET_PAGE_CSS, FLEET_PAGE_JS

STYLE_CSS = ui.CSS + CONSOLE_PAGE_CSS
APP_JS = ui.JS + CONSOLE_PAGE_JS

CHAT_CSS = ui.CSS + CHAT_PAGE_CSS
CHAT_JS = ui.JS + CHAT_PAGE_JS

FLEET_CSS = ui.CSS + FLEET_PAGE_CSS
FLEET_JS = ui.JS + FLEET_PAGE_JS

__all__ = ["INDEX_HTML", "STYLE_CSS", "APP_JS",
           "CHAT_HTML", "CHAT_CSS", "CHAT_JS",
           "FLEET_HTML", "FLEET_CSS", "FLEET_JS", "ui"]
