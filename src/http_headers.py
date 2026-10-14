"""
The headers every page this node serves to a browser carries.

One dictionary for the console and chat's server alike: two copies of a
security policy are two chances for one of them to fall behind.

What is *not* here is as deliberate. ``Strict-Transport-Security`` would turn
the browser's warning about the console's self-signed certificate into a page
that cannot be opened at all, for a year, on every name the console was
reached by; trust in that certificate comes from its pinned fingerprint, not
from a browser being told to refuse anything else.
"""

SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; "
        "form-action 'self'; object-src 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    # No page here asks for any of these; a script that got in cannot either.
    # The terminal's clipboard is the page's own, so it stays allowed to self.
    "Permissions-Policy": (
        "camera=(), microphone=(), geolocation=(), usb=(), serial=(), "
        "hid=(), payment=(), display-capture=(), "
        "clipboard-read=(self), clipboard-write=(self)"
    ),
    # Nothing served here is for another site to open, embed or read.
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Cross-Origin-Embedder-Policy": "require-corp",
}
