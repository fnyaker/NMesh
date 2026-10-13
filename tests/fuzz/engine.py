"""
A coverage-guided fuzzer on the standard library.

Random bytes stop at the first length check. What gets past it is an input
that keeps what made a parser take a new branch and mutates from there — the
idea behind AFL and libFuzzer. The coverage comes from ``sys.monitoring``
(Python 3.12+): a branch or line in ``src/`` fires once, is recorded and then
disabled, so a known one costs nothing on the next run and "this input reached
something new" is simply "the callback ran".

A target is a function of ``bytes`` and the exceptions its contract allows.
Anything else it raises is a finding, and so is a run slower than
``slow_seconds``: in a receive loop, a slow parse is an amplification.
"""
from __future__ import annotations

import hashlib
import os
import random
import struct
import sys
import time
import traceback
from dataclasses import dataclass, field

SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))), "src") + os.sep

_INTERESTING_8 = (0, 1, 2, 0x7F, 0x80, 0xFE, 0xFF)
_INTERESTING_16 = (0, 1, 0x7F, 0x80, 0xFF, 0x100, 0x7FFF, 0x8000, 0xFFFF)
_INTERESTING_32 = (0, 1, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF, 0x10000, 0xFFFF)


@dataclass
class Target:
    name: str
    run: object                      # callable(bytes) -> anything
    allowed: tuple = ()              # exception types the contract permits
    seeds: object = None             # callable() -> list[bytes]
    max_len: int = 4096
    slow_seconds: float = 0.5


@dataclass
class Finding:
    target: str
    kind: str                        # "exception" or "slow"
    data: bytes
    summary: str
    detail: str

    @property
    def key(self) -> str:
        return hashlib.sha256(self.summary.encode()).hexdigest()[:16]


@dataclass
class Report:
    target: str
    runs: int = 0
    corpus: int = 0
    coverage: int = 0
    findings: list = field(default_factory=list)


class _Coverage:
    """Counts first sightings of branches and lines under ``src/``."""

    def __init__(self) -> None:
        self.seen = 0
        self._tool = None

    def __enter__(self):
        monitoring = sys.monitoring
        for tool in range(1, 6):
            if monitoring.get_tool(tool) is None:
                monitoring.use_tool_id(tool, "nmesh-fuzz")
                self._tool = tool
                break
        else:
            raise RuntimeError("no free sys.monitoring tool id")
        events = monitoring.events
        wanted = events.LINE
        branch_events = [getattr(events, name) for name in
                         ("BRANCH", "BRANCH_LEFT", "BRANCH_RIGHT")
                         if hasattr(events, name)]
        for event in branch_events:
            wanted |= event
            monitoring.register_callback(self._tool, event, self._branch)
        monitoring.register_callback(self._tool, events.LINE, self._line)
        monitoring.restart_events()
        monitoring.set_events(self._tool, wanted)
        return self

    def __exit__(self, *exc) -> None:
        monitoring = sys.monitoring
        monitoring.set_events(self._tool, 0)
        monitoring.free_tool_id(self._tool)
        monitoring.restart_events()

    def _line(self, code, line):
        if code.co_filename.startswith(SRC):
            self.seen += 1
        return sys.monitoring.DISABLE

    def _branch(self, code, offset, destination):
        if code.co_filename.startswith(SRC):
            self.seen += 1
        return sys.monitoring.DISABLE


def _summary(exc: BaseException) -> str:
    """Type and the innermost frame in ``src/`` — what makes two crashes one."""
    where = "?"
    for frame in traceback.extract_tb(exc.__traceback__):
        if frame.filename.startswith(SRC):
            where = f"{os.path.relpath(frame.filename, os.path.dirname(SRC))}:{frame.lineno}"
    return f"{type(exc).__name__} at {where}"


class Fuzzer:
    def __init__(self, target: Target, *, seed: int = 0) -> None:
        self.target = target
        self.rng = random.Random(seed)
        self.corpus: list[bytes] = []
        self.findings: dict[str, Finding] = {}
        self.runs = 0

    # -- mutation -------------------------------------------------------

    def _mutate(self, data: bytes) -> bytes:
        rng = self.rng
        buf = bytearray(data)
        for _ in range(1 + rng.randrange(4)):
            choice = rng.randrange(10)
            if not buf or choice == 0:
                at = rng.randrange(len(buf) + 1)
                buf[at:at] = bytes(rng.randrange(256) for _ in range(1 + rng.randrange(8)))
            elif choice == 1:
                at = rng.randrange(len(buf))
                buf[at] ^= 1 << rng.randrange(8)
            elif choice == 2:
                buf[rng.randrange(len(buf))] = rng.choice(_INTERESTING_8)
            elif choice == 3 and len(buf) >= 2:
                at = rng.randrange(len(buf) - 1)
                buf[at:at + 2] = struct.pack(rng.choice("<>") + "H",
                                             rng.choice(_INTERESTING_16))
            elif choice == 4 and len(buf) >= 4:
                at = rng.randrange(len(buf) - 3)
                buf[at:at + 4] = struct.pack(rng.choice("<>") + "I",
                                             rng.choice(_INTERESTING_32))
            elif choice == 5:
                start = rng.randrange(len(buf))
                del buf[start:start + 1 + rng.randrange(16)]
            elif choice == 6:
                start = rng.randrange(len(buf))
                chunk = buf[start:start + 1 + rng.randrange(32)]
                at = rng.randrange(len(buf) + 1)
                buf[at:at] = chunk
            elif choice == 7 and self.corpus:
                other = rng.choice(self.corpus)
                cut = rng.randrange(len(buf) + 1)
                buf = buf[:cut] + other[rng.randrange(len(other) + 1):]
            elif choice == 8:
                del buf[rng.randrange(len(buf) + 1):]
            else:
                at = rng.randrange(len(buf))
                buf[at] = (buf[at] + rng.choice((-1, 1, -16, 16))) & 0xFF
        return bytes(buf[:self.target.max_len])

    # -- execution ------------------------------------------------------

    def _execute(self, data: bytes, coverage: _Coverage) -> bool:
        """Run once; ``True`` when the run reached something new."""
        before = coverage.seen
        started = time.perf_counter()
        try:
            self.target.run(data)
        except self.target.allowed:
            pass
        except Exception as exc:          # noqa: BLE001 — every escape is a finding
            finding = Finding(self.target.name, "exception", data, _summary(exc),
                              "".join(traceback.format_exception(exc)))
            self.findings.setdefault(finding.key, finding)
        elapsed = time.perf_counter() - started
        self.runs += 1
        if elapsed > self.target.slow_seconds:
            finding = Finding(self.target.name, "slow", data,
                              f"slow ({elapsed:.2f}s) on {len(data)} bytes",
                              f"{elapsed:.3f}s")
            self.findings.setdefault("slow", finding)
        return coverage.seen > before

    def run(self, *, iterations: int | None = None,
            seconds: float | None = None, corpus=()) -> Report:
        seeds = list(corpus)
        if self.target.seeds is not None:
            seeds += list(self.target.seeds())
        seeds = seeds or [b""]
        # A seed is a valid input by construction: the cap must never cut one.
        self.target.max_len = max([self.target.max_len, *map(len, seeds)])
        deadline = time.monotonic() + seconds if seconds else None
        with _Coverage() as coverage:
            for data in seeds:
                if self._execute(data, coverage) or not self.corpus:
                    self.corpus.append(data)
            while True:
                if iterations is not None and self.runs >= iterations:
                    break
                if deadline is not None and time.monotonic() >= deadline:
                    break
                data = self._mutate(self.rng.choice(self.corpus))
                if self._execute(data, coverage):
                    self.corpus.append(data)
            seen = coverage.seen
        return Report(self.target.name, self.runs, len(self.corpus), seen,
                      list(self.findings.values()))
