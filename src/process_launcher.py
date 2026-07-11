"""
Process launcher — the node spawns declared applications and wires them to the
mesh's data connector.

When you launch a NMesh node you can declare programs to run alongside it. The
launcher starts each one and injects, via the environment, the coordinates of
the local data connector (host, port, and its bearer token). The child then uses
``ConnectorClient.from_env()`` to join the mesh — so the node becomes the network
bridge for the app, and the app never has to know how the mesh works.

Security (see CLAUDE.md): commands are operator-declared configuration, not
network input; they are executed with ``exec`` (never a shell), so there is no
command-injection surface. The token is passed only through the child's
environment. The number of children is bounded, and all of them are terminated
when the node stops.
"""
from __future__ import annotations

import asyncio
import os

_MAX_PROCS = 64
_TERM_GRACE = 5.0   # seconds to wait after SIGTERM before SIGKILL


class LaunchedProcess:
    def __init__(self, name: str, process: asyncio.subprocess.Process) -> None:
        self.name = name
        self.process = process

    @property
    def pid(self) -> int:
        return self.process.pid

    @property
    def returncode(self) -> int | None:
        return self.process.returncode


class ProcessLauncher:
    def __init__(self, connector, node_id=None) -> None:
        self._connector = connector
        self._node_id = node_id
        self._procs: list[LaunchedProcess] = []

    def connection_env(self) -> dict[str, str]:
        """Environment variables an ``exec``'d child reads to reach the mesh."""
        return {
            "NMESH_CONNECTOR_HOST": self._connector.host,
            "NMESH_CONNECTOR_PORT": str(self._connector.port),
            "NMESH_CONNECTOR_TOKEN": self._connector.token,
            "NMESH_NODE_ID": self._node_id.raw.hex() if self._node_id else "",
        }

    async def launch(self, command, *, name: str | None = None,
                     env: dict | None = None, cwd: str | None = None) -> LaunchedProcess:
        if not isinstance(command, (list, tuple)) or not command:
            raise ValueError("command must be a non-empty list of arguments")
        if any(not isinstance(a, str) for a in command):
            raise ValueError("command arguments must be strings")
        if len(self._procs) >= _MAX_PROCS:
            raise RuntimeError("process launcher at capacity")
        child_env = dict(os.environ)
        child_env.update(self.connection_env())
        if env:
            child_env.update(env)
        proc = await asyncio.create_subprocess_exec(*command, env=child_env, cwd=cwd)
        lp = LaunchedProcess(name or os.path.basename(command[0]), proc)
        self._procs.append(lp)
        return lp

    @property
    def processes(self) -> list[LaunchedProcess]:
        return list(self._procs)

    async def _terminate(self, lp: LaunchedProcess) -> None:
        if lp.process.returncode is not None:
            return
        try:
            lp.process.terminate()
        except ProcessLookupError:
            return
        try:
            await asyncio.wait_for(lp.process.wait(), _TERM_GRACE)
        except asyncio.TimeoutError:
            try:
                lp.process.kill()
            except ProcessLookupError:
                pass
            try:
                await lp.process.wait()
            except Exception:
                pass

    async def stop_all(self) -> None:
        await asyncio.gather(*(self._terminate(lp) for lp in list(self._procs)),
                             return_exceptions=True)
        self._procs.clear()
