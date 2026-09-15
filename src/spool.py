"""Deprecated import path — the module now lives in :mod:`src.transports.bundle`.

Kept as a permanent alias rather than a temporary one, because
`Docs/Transports/guide` and `Docs/Transports/template.py` told people to
import from here, and a transport somebody wrote by hand should not break
because the core's own files were rearranged. New code imports
`src.transports.bundle` directly.

The alias is the *same module object*, not a copy of its names, so a class
obtained through either path is the same class — `isinstance` and
`monkeypatch.setattr` behave identically whichever door was used.
"""
import sys

from .transports import bundle as _module

sys.modules[__name__] = _module
