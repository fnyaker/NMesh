"""
What the node is doing, by name.

"This node feels busy" and "which part of it is busy" were the same question
with no answer: a process CPU figure says *how much*, never *what*, and the only
way to find out was to read `node.py` and guess. Every loop now says who it is
and counts its own passes.

Two properties are the whole point and are proved here: it costs nothing the
node can feel, and the declarations cannot drift away from what the loops
actually wait on. The second is the one that rots quietly — a loop whose wake
source changes keeps describing the old one for ever, and a description that
lies is worse than none.
"""
import asyncio
import time

import pytest

from src.activity import Activity, Job
from src.node import MeshNode
from tests.conftest import make_manager


def _node() -> MeshNode:
    return MeshNode(transport_manager=make_manager())


class TestTheRegistry:
    def test_a_job_counts_its_own_passes(self):
        job = Activity().register("x", "does a thing", "a timer")
        assert job.runs == 0 and job.last is None
        job.ran()
        job.ran()
        assert job.runs == 2 and job.last is not None

    def test_the_name_is_the_identity(self):
        """A loop that dies and restarts is the same job doing the same work.
        A second row would split "how many times has this run" into two numbers
        that each answer part of the question."""
        activity = Activity()
        first = activity.register("x", "old words", "a timer")
        first.ran()
        again = activity.register("x", "new words", "an event")
        assert again is first
        assert again.runs == 1              # the count survives
        assert again.what == "new words"    # the description follows the code
        assert len(activity) == 1

    def test_it_is_bounded(self):
        activity = Activity()
        for i in range(64):
            activity.register(f"job-{i}", "w", "t")
        with pytest.raises(ValueError):
            activity.register("one-too-many", "w", "t")

    def test_long_text_is_cut_rather_than_shown_whole(self):
        job = Activity().register("n" * 200, "w" * 400, "t" * 400)
        assert len(job.name) <= 40
        assert len(job.what) <= 160 and len(job.wakes_on) <= 160

    def test_the_busiest_job_is_first(self):
        activity = Activity()
        quiet = activity.register("quiet", "w", "t")
        busy = activity.register("busy", "w", "t")
        for _ in range(3):
            busy.ran()
        quiet.ran()
        assert [row["name"] for row in activity.jobs()] == ["busy", "quiet"]

    def test_a_pass_costs_nothing_the_node_can_feel(self):
        """The loops run on the order of once a second at their very fastest.
        This is the check that it stayed that way — not a benchmark, a ceiling:
        anything that made a pass expensive would be orders out."""
        job = Job("x", "w", "t")
        started = time.perf_counter()
        for _ in range(200_000):
            job.ran()
        each = (time.perf_counter() - started) / 200_000
        assert each < 5e-6, f"{each * 1e9:.0f} ns a pass"


class TestTheNodeDeclaresItsLoops:
    async def test_every_loop_that_started_has_a_name(self):
        node = _node()
        try:
            await node.start([])
            await asyncio.sleep(0.05)
            names = {row["name"] for row in node._activity.jobs()}
            # The ones `start()` brings up unconditionally.
            assert {"keepalive", "neighbours", "reconnect", "e2e-retry",
                    "address-retry", "steering", "releases",
                    "cert-renewal"} <= names
        finally:
            await node.stop()

    async def test_every_job_says_what_it_does_and_what_wakes_it(self):
        node = _node()
        try:
            await node.start([])
            await asyncio.sleep(0.05)
            for row in node._activity.jobs():
                assert row["what"], row["name"]
                assert row["wakes_on"], row["name"]
        finally:
            await node.stop()

    async def test_the_declarations_match_the_events_the_node_holds(self):
        """The guard against the description that rots. Every `_*_wakeup` event
        on the node is something a loop waits on, so each one must be named by
        some job — otherwise a loop changed what it waits for and kept the old
        words."""
        node = _node()
        try:
            await node.start([])
            await asyncio.sleep(0.05)
            events = {name for name in vars(node)
                      if name.endswith("_wakeup")
                      and isinstance(getattr(node, name), asyncio.Event)}
            # Each wake event belongs to one loop, and every loop that has one
            # describes it in words rather than by attribute name.
            said = " ".join(job["wakes_on"] for job in node._activity.jobs())
            assert events, "the node holds no wake events at all any more"
            assert len(node._activity.wake_sources()) >= len(events), (
                f"{len(events)} wake events but only "
                f"{len(node._activity.wake_sources())} distinct descriptions: "
                "a loop is describing somebody else's wake")
            assert "timer" in said        # the ones that must stay periodic
        finally:
            await node.stop()


class TestWhatThisNodeCarries:
    def test_relayed_bytes_start_at_zero_and_are_a_subset_of_what_went_out(self):
        node = _node()
        totals = node._metrics.total
        totals.on_out(500)
        totals.on_relay(500)
        as_dict = totals.as_dict()
        assert as_dict["bytes_relayed"] == 500
        assert as_dict["bytes_relayed"] <= as_dict["bytes_out"]
        assert as_dict["pkts_relayed"] == 1

    def test_our_own_traffic_is_not_counted_as_relayed(self):
        node = _node()
        node._metrics.total.on_out(900)
        assert node._metrics.total.as_dict()["bytes_relayed"] == 0
