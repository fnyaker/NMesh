"""
The coverage-guided fuzzer (`tests/fuzz`), held to two things.

It has to find what random bytes cannot — a planted bug four comparisons deep,
which a random input reaches once in four billion tries — and it has to tell a
parser keeping its contract from one breaking it. Then every target runs a
short, seeded campaign here, so a contract broken by a change shows up in the
suite; `python -m tests.fuzz` and `.github/workflows/fuzz.yml` run the long
ones.
"""
import sys
import time

import pytest

from tests.fuzz.engine import Fuzzer, Target
from tests.fuzz.targets import TARGETS

pytestmark = pytest.mark.skipif(not hasattr(sys, "monitoring"),
                                reason="sys.monitoring is Python 3.12+")

SHORT_CAMPAIGN = 3000


def _planted(data: bytes) -> None:
    if len(data) >= 4 and data[0] == 0x4E:
        if data[1] == 0x4D:
            if data[2] == 0x45:
                if data[3] == 0x53:
                    raise RuntimeError("planted")


class TestTheEngine:
    def test_coverage_finds_what_random_bytes_do_not(self, monkeypatch):
        import tests.fuzz.engine as engine
        monkeypatch.setattr(engine, "SRC", __file__)
        fuzzer = Fuzzer(Target("planted", _planted), seed=1)
        report = fuzzer.run(iterations=300000, corpus=[b"\x00\x00\x00\x00"])
        assert [f.kind for f in report.findings] == ["exception"]
        assert report.findings[0].data[:4] == b"NMES"
        assert report.corpus >= 4

    def test_without_coverage_it_would_not(self, monkeypatch):
        """The same campaign with no coverage to steer by: it should miss."""
        import tests.fuzz.engine as engine
        monkeypatch.setattr(engine, "SRC", "/nowhere/")
        fuzzer = Fuzzer(Target("planted", _planted), seed=1)
        report = fuzzer.run(iterations=300000, corpus=[b"\x00\x00\x00\x00"])
        assert report.findings == []

    def test_what_the_contract_allows_is_not_a_finding(self):
        def refuse(data):
            raise ValueError("no")
        report = Fuzzer(Target("refuse", refuse, (ValueError,))).run(iterations=50)
        assert report.findings == []

    def test_anything_else_is(self):
        def broken(data):
            raise KeyError("oops")
        report = Fuzzer(Target("broken", broken, (ValueError,))).run(iterations=50)
        assert [f.kind for f in report.findings] == ["exception"]
        assert report.findings[0].summary.startswith("KeyError")

    def test_a_slow_parse_is_a_finding(self):
        def slow(data):
            time.sleep(0.02)
        report = Fuzzer(Target("slow", slow, slow_seconds=0.01)).run(iterations=3)
        assert [f.kind for f in report.findings] == ["slow"]

    def test_a_seed_longer_than_the_cap_is_kept_whole(self):
        seen = []
        Fuzzer(Target("long", seen.append, max_len=8)).run(iterations=1,
                                                           corpus=[b"x" * 100])
        assert seen[0] == b"x" * 100


@pytest.mark.parametrize("target", TARGETS, ids=lambda t: t.name)
def test_every_target_starts_from_valid_inputs(target):
    assert target.seeds is not None
    assert target.seeds(), "a target fuzzed from nothing finds little"


@pytest.mark.parametrize("target", TARGETS, ids=lambda t: t.name)
def test_every_parser_keeps_its_contract(target):
    report = Fuzzer(target, seed=0).run(iterations=SHORT_CAMPAIGN)
    assert report.coverage > 0, "the campaign never reached src/"
    assert not report.findings, "\n\n".join(
        f"{f.summary}\ninput: {f.data!r}\n{f.detail}" for f in report.findings)
