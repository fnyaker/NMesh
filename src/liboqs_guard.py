"""
Refuse to import liboqs-python when there is no liboqs for it to load.

The wrapper's answer to a missing library is to fetch one: it clones the
liboqs tag matching its own version from GitHub and compiles it, there and
then, unchecked. A node would then run post-quantum crypto built from whatever
that tag pointed at that day. The build this tree trusts is
``scripts/build_liboqs.sh``, which proves the source against
``scripts/liboqs.lock`` first, so a missing library is an install to finish,
not something to repair from the network.

The search is the wrapper's: ``$OQS_INSTALL_PATH`` (default ``~/_oqs``), its
``lib`` and ``lib64``, then the system linker's.
"""
from __future__ import annotations

import ctypes.util
import os
import sys
from pathlib import Path


def library_on_disk() -> bool:
    prefix = Path(os.environ.get("OQS_INSTALL_PATH") or Path.home() / "_oqs")
    for part in ("lib", "lib64", "bin"):
        if any((prefix / part).glob("liboqs.*")) or any((prefix / part).glob("oqs.dll")):
            return True
    for variable in ("LD_LIBRARY_PATH", "DYLD_LIBRARY_PATH"):
        for directory in (os.environ.get(variable) or "").split(os.pathsep):
            if directory and any(Path(directory).glob("liboqs.*")):
                return True
    return ctypes.util.find_library("oqs") is not None


def ensure() -> None:
    """Raise ``ImportError`` rather than let the wrapper fetch liboqs itself."""
    if "oqs" in sys.modules:
        return
    if not library_on_disk():
        raise ImportError(
            "liboqs is not installed, and liboqs-python would fetch and build "
            "it unchecked. Run ./start.sh, or scripts/build_liboqs.sh <prefix> "
            "and set OQS_INSTALL_PATH=<prefix>.")
