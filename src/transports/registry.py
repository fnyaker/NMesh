"""The transports that ship with the node, declared in one place.

This is the file to edit to add a medium to the node, and the only one: a
transport is named here, and nothing above knows the list. The console asks the
node what schemes it has, the node asks the manager, and the manager knows what
was registered — so adding a media is one entry below and no other change.

Compare ``src/control/modules/__init__.py``, which does the same job for the
control plane. Both are deliberately boring: the interesting part is the
contract (``contract.py``), and a declaration file that grew logic would be a
second place for the contract to be slightly different.

An entry is ``(scheme, transport module, transport class, server class)``.

``liboqs`` is not needed to *read* this file — only to load ``udp`` or ``tcp``,
which use it for the packet layer. A node that only ever speaks ``spool`` pays
for nothing else, which is the reason the imports are inside
:func:`register_all` rather than at the top.
"""
from __future__ import annotations

from .. import faults
from .manager import TransportManager

#: Scheme -> (module path, transport name, server name). The module is imported
#: lazily by :func:`register_all`, so listing a transport does not load it.
BUILT_IN = (
    ("tcp", "tcp", "TCPTransport", "TCPServer"),
    ("udp", "udp", "UDPTransport", "UDPServer"),
    ("spool", "spool", "SpoolTransport", "SpoolServer"),
)

#: Where the built-in modules live: the *containing* package, not this module.
#: ``__name__`` here is ``...transports.registry``, one level too deep to reach
#: a sibling, so importing ``f"{__name__}.tcp"`` asks for a package that does
#: not exist. Every built-in then hits the ``continue`` below, and a node comes
#: up with no transports at all and nothing on screen saying why.
_PKG = __package__


def register_all(manager: TransportManager) -> TransportManager:
    """Register every built-in scheme onto ``manager``.

    The import is per entry and on purpose: a medium that fails to load — a
    missing optional dependency, a bad file — must not take the others with it,
    or a node with no network at all could not even run its spool transport.
    A scheme that cannot be imported is skipped, and *recorded*: a transport
    that silently failed to register is a scheme the console does not offer and
    nobody can explain, which is the failure mode ``src/faults.py`` exists for.

    **One entry failing costs exactly that entry.** Everything a single entry
    can do — importing, resolving its two classes, and the registration itself
    — is inside the one guard below, and the loop moves to the next entry
    whatever went wrong. Two ways this was not true, and both lost transports:

    * the guard named ``ImportError`` and ``AttributeError`` only. A medium
      whose native dependency refuses to initialise raises ``RuntimeError`` or
      ``OSError``; one whose file is half-written raises ``SyntaxError`` or
      ``ValueError``. None of those were caught, so it did not skip the entry —
      it propagated, and **every entry after it was never reached**. The loop
      dies in the middle of the list, which is why losing one medium looks
      like losing an arbitrary suffix of them.
    * ``manager.register`` was *outside* the guard. It raises ``TransportError``
      for a duplicate or malformed scheme, which aborted the loop the same way.
      So a scheme a plug-in had already claimed took the built-ins after it
      down with it.

    A node is meant to hold as many media as its operator cares to declare, and
    a declaration list only works if one bad line is one bad line. ``Exception``
    and not ``BaseException`` on purpose: a shutdown or a ``KeyboardInterrupt``
    is the caller's business, not something to swallow and carry on from.
    """
    import importlib

    for scheme, module_name, transport_name, server_name in BUILT_IN:
        try:
            module = importlib.import_module(f"{_PKG}.{module_name}")
            transport_cls = getattr(module, transport_name)
            server_cls = getattr(module, server_name)
            manager.register(scheme, transport_cls, server_cls)
        except Exception as exc:
            faults.note(f"transports.register.{scheme}", exc)
            continue        # this medium is unavailable here; the others are not
    return manager
