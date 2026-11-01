"""
How many files this process may hold open.

A node holds a descriptor per link, per console connection, per command it runs
and per file it writes. The soft limit a service manager hands out is often 1024
— a number chosen for a shell, not for a server — and when it is reached
everything fails at once, in places that have nothing to do with each other: a
command cannot start (``Too many open files: '/dev/null'``), a link cannot be
accepted, a state file cannot be written. The hard limit is the real ceiling and
raising the soft one to it needs no privilege.
"""
from __future__ import annotations

# Above this, more descriptors only hide a leak for longer.
CEILING = 65536


def raise_soft_limit(ceiling: int = CEILING) -> tuple[int, int] | None:
    """Raise the soft limit to ``min(hard limit, ceiling)``. Returns ``(soft,
    hard)`` as they now stand, or ``None`` where there is no such limit to
    raise. Never raises."""
    try:
        import resource
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        unlimited = resource.RLIM_INFINITY
        wanted = ceiling if hard == unlimited else min(hard, ceiling)
        if soft != unlimited and soft < wanted:
            resource.setrlimit(resource.RLIMIT_NOFILE, (wanted, hard))
            soft = wanted
        return soft, hard
    except (ImportError, ValueError, OSError):
        return None
