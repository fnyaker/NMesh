"""
What this node is doing, by name.

A node runs a dozen background loops, and most of them only act when nobody is
looking. "This node feels busy" and "which part of it is busy" were the same
question with no answer: a process CPU figure says *how much*, never *what*. The
only way to find out was to read `node.py` and guess.

So every loop says who it is, once, and bumps a counter each time it completes a
pass. A registration is one dict insert at start; a pass is `+= 1` and a
timestamp. **Nothing here is on the packet path** — the hot path already has its
own counters (`metrics.py`) and this must not add a single instruction to it.
The point is the loops, which run on the order of once a second at their very
fastest and usually far less.

Each job also declares **what wakes it**, which is the other half of the answer:
after the loops stopped polling, "who is subscribed to what" became a real
question, and the honest place for it is next to the loop that does the waiting.
`tests/test_activity.py` checks the declarations against the node's actual wake
events, so a loop that changes what it waits on cannot quietly keep describing
the old thing.
"""
from __future__ import annotations

import time

# A name nobody can read is a name that will be shown to somebody anyway.
_MAX_NAME = 40
_MAX_TEXT = 160
# Bounded like everything else. Jobs are declared by this codebase and not by
# anything a peer sends, so this is a guard against a bug, not against an
# adversary — but an unbounded table is an unbounded table.
_MAX_JOBS = 64


class Job:
    """One named piece of background work."""

    __slots__ = ("name", "what", "wakes_on", "runs", "last", "started_at")

    def __init__(self, name: str, what: str, wakes_on: str) -> None:
        self.name = name[:_MAX_NAME]
        self.what = what[:_MAX_TEXT]
        self.wakes_on = wakes_on[:_MAX_TEXT]
        self.runs = 0
        self.last: float | None = None
        self.started_at = time.monotonic()

    def ran(self) -> None:
        """One pass completed. Two attribute writes, called by loops — never by
        anything that handles a packet."""
        self.runs += 1
        self.last = time.monotonic()

    def as_dict(self, now: float | None = None) -> dict:
        now = time.monotonic() if now is None else now
        return {
            "name": self.name,
            "what": self.what,
            "wakes_on": self.wakes_on,
            "runs": self.runs,
            "idle_for": None if self.last is None else round(now - self.last, 1),
            "up_for": round(now - self.started_at, 1),
        }


class Activity:
    """The node's jobs, by name. One instance per node."""

    __slots__ = ("_jobs",)

    def __init__(self) -> None:
        self._jobs: dict[str, Job] = {}

    def register(self, name: str, what: str, wakes_on: str) -> Job:
        """Declare a job, or return the one already declared under this name.

        Idempotent because the **name is the identity**: a loop that dies and is
        restarted is the same job doing the same work, and giving it a second
        row would turn "how many times has this run" into two numbers that each
        answer part of the question. The description is refreshed so the answer
        follows the code rather than whichever start happened to be first."""
        name = name[:_MAX_NAME]
        job = self._jobs.get(name)
        if job is not None:
            job.what = what[:_MAX_TEXT]
            job.wakes_on = wakes_on[:_MAX_TEXT]
            return job
        if len(self._jobs) >= _MAX_JOBS:
            raise ValueError("too many jobs registered")
        job = self._jobs[name] = Job(name, what, wakes_on)
        return job

    def get(self, name: str) -> Job | None:
        return self._jobs.get(name)

    def jobs(self) -> list[dict]:
        """Every job, busiest first. Built on demand, for a console."""
        now = time.monotonic()
        rows = [job.as_dict(now) for job in self._jobs.values()]
        rows.sort(key=lambda row: row["runs"], reverse=True)
        return rows

    def wake_sources(self) -> list[str]:
        """The distinct things jobs wait on — the "who is subscribed to what"
        view, read off the declarations rather than kept as a second list that
        would have to be maintained in step."""
        return sorted({job.wakes_on for job in self._jobs.values()})

    def __len__(self) -> int:
        return len(self._jobs)
