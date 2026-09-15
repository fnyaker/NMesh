"""Deprecated import path — the module now lives in :mod:`src.transports.tcp`.

Kept as a permanent alias rather than a temporary one: this was the
documented path for as long as the module existed, and a transport somebody
already wrote by hand should not break because the core's own files were
rearranged. New code imports
`src.transports.tcp` directly.

The alias is the *same module object*, not a copy of its names, so a class
obtained through either path is the same class — `isinstance` and
`monkeypatch.setattr` behave identically whichever door was used.
"""
import sys

from .transports import tcp as _module

sys.modules[__name__] = _module
