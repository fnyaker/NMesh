"""
What a control module is given, and deliberately nothing else.

A module needs four things: the node, a way to run something on the node's
event loop from whatever thread it is on, the configuration file this node was
started from (if any), and the book of what has moved. It is handed exactly
those.

What it is **not** handed is the console, and that is the whole design. An
operation that could see which channel carried its request would sooner or
later behave differently depending on who asked — a session it could read, a
socket it could write to, a status code it could choose — and the plane's one
promise is that a request means the same thing however it arrived. Whoever owns
the node builds one context and hands it over; the channels stay on their side
of it.
"""
from __future__ import annotations

import asyncio
import concurrent.futures

from .errors import ControlError


class NotRunning(RuntimeError):
    """There is no node loop to run this on — it is stopping, or never started.

    Its own type because it is the one failure of the bridge that is a *state*
    of the node rather than a mistake by the caller, and the two must not reach
    an operator as the same sentence."""


class Context:
    """The node, as a control module is allowed to see it.

    ``call`` is the thread bridge: the console's HTTP server answers on its own
    threads and node state is only ever touched on the loop, so a module that
    needs the node runs a coroutine through here and waits with a ceiling. The
    ceiling is the operation's own declared one — the same constant appears in
    its declaration, so the two cannot drift.
    """

    def __init__(self, *, node, loop=None, config_path=None, apps=None,
                 changes=None) -> None:
        self.node = node
        self._loop = loop
        self.config_path = config_path or ""
        self._apps = apps
        self.changes = changes

    def bind_loop(self, loop) -> None:
        """Point the bridge at the loop the node is actually running on.

        Separate from construction because the console is built before it is
        started, and a context that captured ``None`` would be a plane that
        answers nothing for the lifetime of the process."""
        self._loop = loop

    def call(self, coro, timeout: float):
        """Run a coroutine on the node's loop and wait up to ``timeout``.

        Raises ``RuntimeError`` when there is no loop to run it on, and
        whatever the coroutine raised otherwise — a module translates that into
        the plane's vocabulary, because only the module knows whether a refusal
        was the caller's fault."""
        loop = self._loop
        if loop is None or loop.is_closed():
            self._drop(coro)
            raise NotRunning("the node is not running")
        try:
            running = asyncio.get_running_loop()
        except RuntimeError:
            running = None
        if running is loop:
            # Called *from* the loop it would wait on. `future.result()` blocks
            # the thread, so the coroutine it is waiting for can never run and
            # the node freezes until the ceiling expires — a hang that reads as
            # "the console is slow" and says nothing about where it is. Refused
            # immediately instead, naming the fix (`Docs/Architecture/gotchas.md`).
            self._drop(coro)
            raise RuntimeError("the control plane is called from a thread, "
                               "never from the node's own loop")
        future = asyncio.run_coroutine_threadsafe(coro, loop)
        return future.result(timeout=timeout)

    def ask(self, coro, timeout: float):
        """:meth:`call`, in the plane's vocabulary.

        A node that is not there, or a call that outlived its ceiling, is
        ``unavailable`` — the honest answer, and the one a page can act on by
        keeping what it has on screen rather than painting an error over it.
        Anything the coroutine itself raised travels on: only the module that
        called knows whether that was the caller's fault.

        Every module goes through here, so "the node is stopping" reads the
        same whichever operation the operator happened to press."""
        try:
            return self.call(coro, timeout)
        except (NotRunning, concurrent.futures.TimeoutError,
                asyncio.TimeoutError):
            raise ControlError("unavailable", "the node did not answer") from None

    @staticmethod
    def _drop(coro) -> None:
        """Close a coroutine for a call that will not happen.

        Left alone it becomes a "never awaited" warning on somebody else's
        stderr, and a management plane must not be a source of noise."""
        close = getattr(coro, "close", None)
        if callable(close):
            close()

    def apps(self) -> list:
        """The built-in apps and their state, or an empty list.

        A callable rather than a value: an app enabled a second ago has to
        appear, and an app stopped a second ago has to stop appearing."""
        if self._apps is None:
            return []
        try:
            return self._apps()
        except Exception:
            return []


async def on_loop(function, *args, **kwargs):
    """A plain function, awaited — so ``Context.call`` is the only bridge.

    Reading node state is synchronous but must still happen *on the loop*: a
    snapshot taken from a server thread can read a dict another coroutine is
    halfway through writing. Used as
    ``context.call(on_loop(node.something, arg), timeout)``, and imported by
    the console for its own routes, so there is one of these rather than two
    spellings of the same adapter."""
    return function(*args, **kwargs)
