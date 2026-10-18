"""
How one app on this node reaches the address books.

Chat does not keep a list of contacts of its own: it asks the contacts app, the
way any app would, through the operations that app declares (``API`` in
:mod:`.contacts_web`). What makes it *standard* is the second half — each
operation names a permission (``contacts.read``, ``contacts.write``), and the
link asks the permission book whether the app a link speaks for was given it
before the call is made. An app that was refused gets a refusal, not a
degraded answer, and says so to the person using it, who can grant it from the
Apps page or from the prompt the app shows.

The link holds nothing: the host and the book are looked up on every call, so a
contacts app that was stopped a second ago is not reachable through a reference
this object kept.
"""
from __future__ import annotations

from .. import app_api

APP = "contacts"


class Unavailable(Exception):
    """The contacts app is not running here."""


class Denied(Exception):
    """The app this link speaks for was not given the permission."""

    def __init__(self, permission: str) -> None:
        super().__init__(permission)
        self.permission = permission


class ContactsLink:
    def __init__(self, host, perms, app_hex: str) -> None:
        self._host = host
        self._perms = perms
        self._app = app_hex

    def _live_host(self):
        host = self._host() if callable(self._host) else self._host
        return host

    def access(self) -> str:
        """What the app behind this link may do with the books right now:
        ``"write"``, ``"read"``, ``"denied"`` (running, but not allowed) or
        ``"unavailable"`` (no contacts app on this node)."""
        host = self._live_host()
        if host is None or host.bridge(APP) is None:
            return "unavailable"
        if self._perms is None:
            return "denied"
        if self._perms.allows(self._app, "contacts.write"):
            return "write"
        if self._perms.allows(self._app, "contacts.read"):
            return "read"
        return "denied"

    def call(self, op: str, **args) -> dict:
        """One operation of the contacts app, as this app. Raises
        :class:`Unavailable`, :class:`Denied` or
        :class:`~src.app_api.AppAPIError`."""
        host = self._live_host()
        if host is None or host.bridge(APP) is None:
            raise Unavailable(APP)
        surface = app_api.AppAPI(host)
        declared = surface.find(APP, op)
        if declared is None:
            raise Unavailable(op)
        need = declared.get("permission") or ""
        if self._perms is None or not need or not self._perms.allows(self._app, need):
            raise Denied(need or "contacts")
        return surface.call(APP, op, {k: v for k, v in args.items() if v is not None})


