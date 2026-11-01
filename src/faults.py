"""
How this node writes down something that went wrong where nobody is listening.

Most failures in this project have somewhere to go: a refusal travels back to
whoever asked, a dropped packet is counted, a link that dies is reaped. This is
for the other kind — the ones caught by a guard whose whole job is that the node
must not fall over, and which therefore have **no reader at all** unless one is
made here.

Two of those guards exist and both were silent:

* a control module that throws. The plane answers a type name on purpose — on
  some channels the reader is a peer, and an exception's text is a description
  of this machine — so the console said ``node.state failed: AttributeError``
  and the node's own log said nothing. The one machine able to fix it was the
  one machine not told.
* a section of the console snapshot that throws. One field out of forty raised
  and took the *whole* management surface down with it, for as long as whatever
  caused it lasted.

So: **stderr, bounded, named.** A node already says what it has to say there, a
management plane must never become a way to fill somebody's disk, and a line
nobody can read past is a line nobody reads.

A node that is keeping a log wants these lines in it as well, so there is one
**sink** here: a callable set by whoever is keeping the log, handed the same
name and the same exception, and dropped the moment they stop. It is a single
global rather than a registry because stderr is one too — this is what the
process says about itself, not what one object says about its own state.

What does **not** go here is anything that travels. A reply is relayed, pasted
into an issue and read by scripts, and `tests/test_control_plane.py` holds the
plane to carrying nothing of this machine in one, whoever asked for it. A log is
the machine's own; a reply never is.
"""
from __future__ import annotations

import sys
import threading
import time
import traceback

# Enough to name the line that raised and how it was reached, and no more.
MAX_FRAMES = 12

# Whoever is keeping a log of this process, or None. Set by `MeshNode`; never
# called for its answer, and never allowed to make a guard fail.
_sink = None


def watch(sink) -> None:
    """Have every swallowed failure handed to ``sink(where, exc)`` as well.

    Last one wins: a process runs one node. ``None`` stops it — and stops it
    only for whoever is *currently* listening, which matters in a process
    holding more than one node (every test in this suite): a node shutting down
    must not take the log of the node still running with it."""
    global _sink
    _sink = sink if callable(sink) else None


def unwatch(sink) -> None:
    """Stop listening, if this is who is listening.

    ``==``, never ``is``: a bound method is a fresh object on every attribute
    access, so ``node._note_fault is node._note_fault`` is false and an
    identity test here would never unhook anything."""
    global _sink
    if _sink == sink:
        _sink = None


# A guard that fails in a loop — a console section on every poll — must not
# write a traceback per pass: the journal is the disk, and the disk is not ours.
# The first failure of a place is written whole; after it the place is quiet for
# `QUIET_SECONDS`, then says how many it swallowed.
QUIET_SECONDS = 60.0
MAX_PLACES = 64
_places: dict[str, list] = {}       # where -> [last written at, swallowed since]
_places_lock = threading.Lock()


def _admit(where: str) -> int | None:
    """None to stay quiet, else how many were swallowed since the last write."""
    now = time.monotonic()
    with _places_lock:
        entry = _places.get(where)
        if entry is None:
            while len(_places) >= MAX_PLACES:
                del _places[next(iter(_places))]
            _places[where] = [now, 0]
            return 0
        if now - entry[0] < QUIET_SECONDS:
            entry[1] += 1
            return None
        swallowed, entry[0], entry[1] = entry[1], now, 0
        return swallowed


def note(where: str, exc: BaseException) -> None:
    """Write one swallowed failure down. **Never raises** — a failed report is
    not itself a failure, and the guard that called this was protecting
    something more important than its own logging."""
    try:
        swallowed = _admit(where)
        if swallowed is not None:
            if swallowed:
                sys.stderr.write(f"nmesh: {where} failed again, {swallowed} "
                                 f"time(s) since it was last written\n")
            sys.stderr.write(f"nmesh: {where} failed\n")
            sys.stderr.write("".join(traceback.format_exception(
                type(exc), exc, exc.__traceback__, limit=MAX_FRAMES)))
            sys.stderr.flush()
    except Exception:                       # noqa: BLE001 — never the reason
        pass
    sink = _sink
    if sink is None:
        return
    try:
        sink(where, exc)
    except Exception:                       # noqa: BLE001 — same rule, and the
        pass                                # sink is the newer of the two
