"""
The modules the node ships with, and the one place they are wired up.

:func:`install` is what makes the plane **modular by default**: a module is
added by naming it here, not by editing a router, and it declares its own
operations, their arguments, their ceilings and whether a remote console may
reach them. Nothing above knows the list — the console asks the plane what
exists, and the page asks the console.

An app can register its own module at runtime for the same reason
(``plane.register(...)``): an app that is not running exposes nothing, which is
the honest answer to "what can this node do?" rather than a button that fails
when pressed.
"""
from __future__ import annotations

from ..plane import ControlPlane
from .apps import AppsModule
from .core import ControlModule
from .jobs import JobsModule
from .node import NodeModule
from .pseudo import PseudoModule
from .releases import ReleasesModule
from .join import JoinModule
from .keys import KeysModule
from .network import NetworkModule
from .packages import PackagesModule
from .settings import ConfigModule, TransportsModule
from .store import StoreModule
from .transfer import TransferModule
from .trace import TraceModule
from .trust import TrustModule

# The order is the order a catalogue is read in, and nothing else depends on it.
BUILT_IN = (NodeModule, ConfigModule, TransportsModule, TraceModule,
            PseudoModule, AppsModule, TrustModule, NetworkModule,
            ReleasesModule, PackagesModule, KeysModule, StoreModule,
            JoinModule, TransferModule)


def install(plane: ControlPlane, context) -> ControlPlane:
    """Register every built-in module onto ``plane``.

    ``control`` and ``jobs`` last and separately: they are the two modules that
    need the plane itself. One answers what the plane *is*; the other runs what
    the plane declares, which is why a job can never reach further than a call
    — it goes back through the same door."""
    for module in BUILT_IN:
        plane.register(module(context))
    plane.register(ControlModule(plane, context))
    plane.register(JobsModule(plane, context))
    return plane
