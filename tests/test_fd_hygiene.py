"""Descriptors are given back on the paths that fail, and the limit is raised."""
import asyncio
import os
import resource
import sys

import pytest

from src import fd_limit
from src.apps import fleet_ssh


def _open_fds():
    return len(os.listdir("/proc/self/fd"))


pytestmark = pytest.mark.skipif(not os.path.isdir("/proc/self/fd"),
                                reason="counts descriptors through /proc")


def test_a_killed_child_is_collected_and_its_pipes_closed():
    async def go():
        before = _open_fds()
        for _ in range(5):
            proc = await asyncio.create_subprocess_exec(
                sys.executable, "-c", "import time; time.sleep(60)",
                stdout=asyncio.subprocess.PIPE, stdin=asyncio.subprocess.DEVNULL)
            await fleet_ssh.kill_and_reap(proc)
            assert proc.returncode is not None
        await asyncio.sleep(0.2)
        return _open_fds() - before

    assert asyncio.run(go()) <= 1


def test_kill_and_reap_survives_a_child_already_gone():
    async def go():
        proc = await asyncio.create_subprocess_exec(sys.executable, "-c", "pass")
        await proc.wait()
        await fleet_ssh.kill_and_reap(proc)

    asyncio.run(go())


def test_the_soft_limit_is_raised_to_the_hard_one(monkeypatch):
    seen = {}
    monkeypatch.setattr(resource, "getrlimit", lambda _which: (1024, 4096))
    monkeypatch.setattr(resource, "setrlimit",
                        lambda which, pair: seen.setdefault("set", pair))
    assert fd_limit.raise_soft_limit() == (4096, 4096)
    assert seen["set"] == (4096, 4096)


def test_the_soft_limit_never_goes_past_the_ceiling(monkeypatch):
    seen = {}
    monkeypatch.setattr(resource, "getrlimit",
                        lambda _which: (1024, resource.RLIM_INFINITY))
    monkeypatch.setattr(resource, "setrlimit",
                        lambda which, pair: seen.setdefault("set", pair))
    fd_limit.raise_soft_limit()
    assert seen["set"][0] == fd_limit.CEILING


def test_a_refused_change_is_not_an_error(monkeypatch):
    def refuse(*_a):
        raise ValueError("no")

    monkeypatch.setattr(resource, "getrlimit", lambda _which: (1024, 4096))
    monkeypatch.setattr(resource, "setrlimit", refuse)
    assert fd_limit.raise_soft_limit() is None
