"""
The running version, and how to compare two of them.

Kept as a plain constant rather than read from ``pyproject.toml``: a node may
run from a zipapp or from a tree that never carried the packaging metadata, and
"which version am I?" must always have an answer. ``tests/test_updater.py``
checks that ``pyproject.toml`` agrees with this file, so the two cannot drift.
"""
from __future__ import annotations

import re

__version__ = "0.1.37"

# Releases are tagged ``vX.Y.Z`` (see .github/workflows/release.yml). Anything
# after the numbers (``-rc1``, ``+build``) is kept but only used to break ties
# against an otherwise identical version.
_VERSION_RE = re.compile(r"^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(.*)$")


def parse(text) -> tuple | None:
    """``"v1.2.3"`` → ``(1, 2, 3, "")``. ``None`` for anything unparseable.

    Refusing to guess matters: an unreadable tag must never look *newer* than
    what is running, or a node would happily "upgrade" to something it cannot
    identify."""
    if not isinstance(text, str):
        return None
    match = _VERSION_RE.match(text.strip())
    if match is None:
        return None
    major, minor, patch, suffix = match.groups()
    try:
        return (int(major), int(minor or 0), int(patch or 0), suffix or "")
    except ValueError:
        return None


def is_newer(candidate, current=__version__) -> bool:
    """Is ``candidate`` strictly newer than ``current``?

    A pre-release suffix sorts *before* the plain version (``1.2.0-rc1`` is
    older than ``1.2.0``), so a release candidate never supersedes the release
    it leads to."""
    left, right = parse(candidate), parse(current)
    if left is None or right is None:
        return False
    if left[:3] != right[:3]:
        return left[:3] > right[:3]
    # Same numbers: no suffix beats a suffix, otherwise compare textually.
    if left[3] == right[3]:
        return False
    if not left[3]:
        return True
    if not right[3]:
        return False
    return left[3] > right[3]
