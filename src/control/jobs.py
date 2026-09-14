"""
Operations too long to answer inside one call, and how they travel anyway.

The fleet relay carries **one bounded request and its answer**: a frame goes
over the mesh, the far node's console answers it, and the answer comes back
inside :data:`~src.apps.fleet_console.CALL_TIMEOUT`. That is a good shape — it
has no stream to wedge, no connection to hold, nothing to resume — and it made
a whole family of operations unreachable from a distance. Installing a release
takes four hundred seconds. Publishing one takes three hundred. Walking a
node's dead addresses takes sixty. None of them fits, and an operator managing
a machine needs all of them.

So they are not carried. **A ticket is.**

``jobs.start`` takes the name of an operation and its arguments, checks them the
way any call is checked, runs it here, and hands back an identifier.
``jobs.poll`` answers what became of it. Both are small calls that fit the relay
with room to spare, so what crosses the mesh is never the wait — it is a
question about the wait, asked as often or as rarely as the operator likes, and
answered the same whether the console is on this machine or four hops away.

Three rules keep it from being a way in:

* **A job is the operation's permission, not a way around it.** ``jobs.start``
  refuses anything the caller could not have called directly — same reach, same
  arguments, bound by the same declaration. It is a *channel* for an operation,
  never a second door to one.
* **The book is bounded, in every direction.** How many jobs may run at once,
  how many a console at a distance may run at once, how many records are kept
  and for how long. A peer that starts jobs faster than they finish is refused
  rather than remembered.
* **A ticket is only readable by the kind of console that could have made it.**
  A job started here is not visible from the mesh, and one started by a console
  holding ``govern`` is not readable by one that only holds ``manage`` — the
  answer to "create a key" must not be collectable by whoever can poll.

What runs it is a **daemon thread that is never joined**, for the reason
``Docs/Architecture/gotchas.md`` gives about ``to_thread``: asyncio joins its
default executor on the way out, so one wedged operation would hang the process
at shutdown. A job that outlives its declared ceiling is abandoned and reported
as failed — the thread is let go, and its slot with it.
"""
from __future__ import annotations

import secrets
import threading
import time

from .errors import ControlError
from .plane import Origin, reaches

# How many jobs may be running at once, and how many of those a console at a
# distance may hold. The second is the one that matters: the first bounds this
# node's own work, the second bounds what the network can make it do.
MAX_RUNNING = 4
MAX_RUNNING_REMOTE = 2
# Records kept, finished ones included. Small on purpose — a job is a thing an
# operator is waiting for, not a log.
MAX_JOBS = 24
# How long a finished job's answer is kept for whoever asked. Long enough for a
# console that lost its connection during a four-minute install to come back and
# read the outcome; short enough that nothing accumulates.
KEEP = 900.0
# Past its own declared ceiling, an operation that has not come back is not
# coming back in a way we can still describe. The grace is for the module's own
# bookkeeping after `context.ask` gives up, not for the operation.
GRACE = 30.0

RUNNING = "running"
DONE = "done"
FAILED = "failed"


class JobBook:
    """Every job this node is running or has just run.

    One book per plane, held by the module that declares the operations. It is
    touched from the console's threads *and* from each job's own, so everything
    here takes the lock — a management plane that can be raced is a management
    plane whose bounds are advisory."""

    def __init__(self, plane, *, clock=time.monotonic) -> None:
        self._plane = plane
        self._clock = clock
        self._lock = threading.Lock()
        self._jobs: dict = {}

    # -- starting ---------------------------------------------------------

    def start(self, op: str, params: dict, origin: str) -> dict:
        """Run ``op`` in the background and hand back its ticket.

        Every refusal a direct call would have made is made here first, and
        made *before* a thread exists: an argument this operation never declared
        must not cost a thread to find out about."""
        found = self._plane.find(op)
        if found is None:
            raise ControlError("not_found", "no such operation")
        _module, entry = found
        if not reaches(origin, entry):
            # The same sentence the plane itself would have used. A job is not
            # a way to ask for something you may not ask for, and an operator
            # reading this must not have to wonder whether it might be.
            raise ControlError("refused",
                               f"{op} cannot be driven from this console")
        if op.startswith("jobs."):
            # A job that starts jobs is an amplifier with a bound of its own
            # multiplied by itself. There is nothing here worth doing that way.
            raise ControlError("refused", "a job cannot start a job")
        # Bound now, in the caller's own call, so a bad argument is a refusal
        # they can read rather than a ticket that fails a minute later.
        self._plane.check(op, params, origin=origin)
        with self._lock:
            # `room=1`: tidying has to leave space for the job being started,
            # or a book full of *finished* records refuses new work for as long
            # as the oldest answer is worth keeping. A bound that stops the node
            # working is not a bound, it is an outage with a ceiling.
            self._prune(room=1)
            running = [job for job in self._jobs.values()
                       if job["state"] == RUNNING]
            if len(running) >= MAX_RUNNING:
                raise ControlError("conflict",
                                   "this node is already running as many jobs "
                                   "as it will run at once")
            if origin != Origin.LOCAL and len([
                    job for job in running
                    if job["origin"] != Origin.LOCAL]) >= MAX_RUNNING_REMOTE:
                raise ControlError("conflict",
                                   "as many jobs as a console at a distance "
                                   "may run at once are already running")
            if len(self._jobs) >= MAX_JOBS:
                raise ControlError("conflict", "too many jobs are remembered")
            ident = secrets.token_hex(8)
            now = self._clock()
            self._jobs[ident] = {
                "id": ident, "op": op, "origin": origin, "state": RUNNING,
                "started": now, "deadline": now + entry["timeout"] + GRACE,
                "finished": 0.0, "result": None, "code": "", "error": "",
            }
        threading.Thread(target=self._run, args=(ident, op, params, origin),
                         name="nmesh-control-job", daemon=True).start()
        return {"job": ident, "op": op, "state": RUNNING}

    def _run(self, ident: str, op: str, params: dict, origin: str) -> None:
        """One job, start to finish. **Never raises** — it is a thread's whole
        body, and an exception here would be a traceback on somebody's stderr
        with nobody left to answer the operator."""
        try:
            result = self._plane.invoke(op, params, origin=origin)
            outcome = {"state": DONE, "result": result, "code": "", "error": ""}
        except ControlError as exc:
            outcome = {"state": FAILED, "result": None, "code": exc.code,
                       "error": exc.message, "detail": exc.detail}
        except Exception:                       # noqa: BLE001 — never leak
            # Same rule as the plane's own dispatch: an exception's text is a
            # description of this machine, and on some channels the reader is a
            # peer.
            outcome = {"state": FAILED, "result": None, "code": "failed",
                       "error": f"{op} failed"}
        with self._lock:
            job = self._jobs.get(ident)
            if job is None or job["state"] != RUNNING:
                return              # given up on, and its slot already freed
            job.update(outcome)
            job["finished"] = self._clock()

    # -- reading ----------------------------------------------------------

    def poll(self, ident: str, origin: str) -> dict:
        with self._lock:
            self._prune()
            job = self._jobs.get(ident)
            if job is None or not self._visible(job, origin):
                # Not "you may not read this": a ticket somebody else's console
                # holds is a ticket that does not exist here, and saying which
                # of the two it was would be a way to count them.
                raise ControlError("not_found", "no such job")
            return self._describe(job, full=True)

    def listing(self, origin: str) -> dict:
        with self._lock:
            self._prune()
            jobs = [self._describe(job, full=False)
                    for job in self._jobs.values()
                    if self._visible(job, origin)]
        jobs.sort(key=lambda entry: entry["age"])
        return {"jobs": jobs, "running": sum(1 for job in jobs
                                             if job["state"] == RUNNING)}

    def forget(self, ident: str, origin: str) -> dict:
        with self._lock:
            job = self._jobs.get(ident)
            if job is None or not self._visible(job, origin):
                raise ControlError("not_found", "no such job")
            if job["state"] == RUNNING:
                # Nothing here can stop a release from installing halfway, and
                # a ticket dropped while its work continues is how an operator
                # ends up with two of them running.
                raise ControlError("conflict", "that job is still running")
            self._jobs.pop(ident, None)
        return {"forgotten": True}

    # -- the rules --------------------------------------------------------

    def _visible(self, job: dict, origin: str) -> bool:
        """Only the kind of console that could have started it may read it.

        Exactly the origin, not "at least as much reach": a console holding
        ``manage`` alone must not read what a console holding ``govern``
        started, because the answer to "adopt this key" or "mint this ticket"
        is the thing the second grant exists to gate. Two operators sharing one
        capability do share a view — the plane knows *which kind* of console is
        asking and never *which machine*, and pretending otherwise would be a
        promise this layer cannot keep."""
        return job["origin"] == origin

    def _describe(self, job: dict, *, full: bool) -> dict:
        out = {"job": job["id"], "op": job["op"], "state": job["state"],
               "age": round(max(0.0, self._clock() - job["started"]), 1)}
        if job["state"] == RUNNING:
            return out
        out["took"] = round(max(0.0, job["finished"] - job["started"]), 1)
        if job["state"] == FAILED:
            out["code"] = job["code"]
            out["error"] = job["error"]
            if full and job.get("detail"):
                out["detail"] = job["detail"]
        elif full:
            out["result"] = job["result"]
        return out

    def _prune(self, room: int = 0) -> None:
        """Drop what is finished with, and give up on what will not finish.

        Called under the lock by everything that reads or writes the book, so
        there is no timer to leak and no sweep to schedule: the book is tidied
        by being used, and a node nobody is managing does no work at all."""
        now = self._clock()
        for ident, job in list(self._jobs.items()):
            if job["state"] == RUNNING:
                if now > job["deadline"]:
                    # The thread is abandoned, exactly as `fleet_console.bounded`
                    # abandons a wedged console call, and the slot is freed. If
                    # it does finish later it finds its own record no longer
                    # `running` and writes nothing.
                    job.update({"state": FAILED, "finished": now,
                                "code": "unavailable",
                                "error": "that operation did not finish in the "
                                         "time it declared"})
                continue
            if now - job["finished"] > KEEP:
                self._jobs.pop(ident, None)
        # Still too many records: the oldest *finished* one goes. A running job
        # is never dropped — its thread would still be running, and a bound
        # that forgets what it is bounding is not one.
        while len(self._jobs) + room > MAX_JOBS:
            finished = [job for job in self._jobs.values()
                        if job["state"] != RUNNING]
            if not finished:
                return
            self._jobs.pop(min(finished, key=lambda job: job["finished"])["id"],
                           None)
