"""
A fleet's logs: collected from machines an operator manages, kept here.

Three questions decide whether this is safe to ship, and they are the three
these tests ask.

**Who may read a machine's log?** Only a node that machine granted `logs` to,
by name — not `status`, not `manage`, and not "an operator, broadly". A log says
who a node talked to and when, so the machine keeping it decides, and it decides
per grant like everything else in this ledger.

**What does a machine push, and to whom?** Only to a console that asked to
follow, only while that follow is live, and never to one that never asked: a
pushed frame carries the rid of the follow the operator opened, so an
unsolicited one is dropped rather than shown.

**What does collecting cost the operator?** One bounded ring per node, a bounded
number of rings, and a policy per node — because a fleet is not uniform and a
chatty machine must never be able to push a quiet one's log out.
"""
import asyncio

import pytest

from src import logbook
from src import webassets
from src.apps import fleet, fleet_logs
from src.apps.fleet import LogsReceived
from src.logbook import LogBook
from tests.test_fleet import Peer, deliver, enrol, settle


@pytest.fixture
def operator():
    return Peer()


@pytest.fixture
def agent():
    return Peer()


class _LogSource:
    """The connector client's log half, backed by a real `LogBook`.

    A real one rather than a list of dicts: the node's ring is what decides what
    a filter matches, what a sequence number means and what `lost` says, and a
    double that answered those itself would be testing the double."""

    def __init__(self, client):
        self.book = LogBook()
        self.book.start()
        self.granted = True
        self.watching = False
        self._pushed = []
        self.book.sink = self._pushed.append
        client.logs_query = self.logs_query
        client.logs_since = self.logs_since
        client.logs_watch = self.logs_watch
        client.next_log = self.next_log

    async def logs_query(self, **filters):
        if not self.granted:
            return {"lines": [], "matched": 0, "returned": 0, "seq": 0,
                    "refused": True}
        return self.book.query(**filters)

    async def logs_since(self, seq=0, **filters):
        if not self.granted:
            return {"lines": [], "matched": 0, "returned": 0, "seq": 0,
                    "refused": True}
        return self.book.since(seq, **filters)

    async def logs_watch(self, on=True, *, level="info"):
        if not self.granted:
            return False
        self.watching = bool(on)
        return self.watching

    def next_log(self):
        return self._pushed.pop(0) if self._pushed else None


def _logs(peer):
    source = getattr(peer, "log_source", None)
    if source is None:
        source = peer.log_source = _LogSource(peer.client)
    return source


def _received(peer):
    return [event for event in peer.drain_events()
            if isinstance(event, LogsReceived)]


class TestOnlyTheGrantOpensIt:
    async def test_a_node_that_granted_nothing_answers_nothing(self, operator, agent):
        _logs(agent).book.record("node", "a secret line")
        await operator.app.request_logs(agent.id)
        await deliver(operator, agent)
        await deliver(agent, operator)
        assert _received(operator) == []

    async def test_status_is_not_logs(self, operator, agent):
        """The over-grant this capability exists to avoid: reading a machine's
        uptime is not reading what it said about who it talked to."""
        await enrol(operator, agent, caps=["status"])
        _logs(agent).book.record("node", "a secret line")
        await operator.app.request_logs(agent.id)
        await deliver(operator, agent)
        await deliver(agent, operator)
        assert _received(operator) == []

    async def test_with_the_grant_the_lines_come_back(self, operator, agent):
        await enrol(operator, agent, caps=["logs"])
        _logs(agent).book.record("node", "a link died", level=logbook.WARN,
                                 topic="link")
        await operator.app.request_logs(agent.id)
        await deliver(operator, agent)
        await deliver(agent, operator)
        [event] = _received(operator)
        assert [line["message"] for line in event.lines] == ["a link died"]

    async def test_a_revoked_grant_stops_answering(self, operator, agent):
        await enrol(operator, agent, caps=["logs"])
        _logs(agent).book.record("node", "a line")
        agent.app.state.set_operator_caps(operator.id.raw.hex(), [])
        await operator.app.request_logs(agent.id)
        await deliver(operator, agent)
        await deliver(agent, operator)
        assert _received(operator) == []

    async def test_a_node_whose_app_may_not_read_says_so(self, operator, agent):
        """The grant an operator holds and the grant the *app* holds are two
        different grants, and an operator has to be able to tell which is
        missing — "nothing came back" would look like a node that is down."""
        await enrol(operator, agent, caps=["logs"])
        _logs(agent).granted = False
        await operator.app.request_logs(agent.id)
        await deliver(operator, agent)
        await deliver(agent, operator)
        failures = [event for event in operator.drain_events()
                    if isinstance(event, fleet.Failure)]
        assert failures and "granted its fleet app" in failures[0].error


class TestFollowing:
    async def _following(self, operator, agent, **kwargs):
        await enrol(operator, agent, caps=["logs"])
        _logs(agent)
        await operator.app.follow_logs(agent.id, True, **kwargs)
        await deliver(operator, agent)
        await deliver(agent, operator)
        return agent.app._log_followers

    async def test_a_follow_is_registered_and_answered(self, operator, agent):
        followers = await self._following(operator, agent)
        assert list(followers) == [operator.id.raw.hex()]
        assert operator.app.following() == [agent.id.raw.hex()]

    async def test_a_follow_begins_with_what_was_missed(self, operator, agent):
        """A follow that starts at "now" leaves a hole exactly where the
        operator stopped being able to look."""
        await enrol(operator, agent, caps=["logs"])
        _logs(agent).book.record("node", "while nobody was watching")
        await operator.app.follow_logs(agent.id, True, seq=0)
        await deliver(operator, agent)
        await deliver(agent, operator)
        messages = [line["message"] for event in _received(operator)
                    for line in event.lines]
        assert "while nobody was watching" in messages

    async def test_lines_recorded_afterwards_are_pushed(self, operator, agent):
        await self._following(operator, agent)
        operator.drain_events()
        _logs(agent).book.record("node", "something just happened")
        await _pump_once(agent.app)
        await deliver(agent, operator)
        pushed = [line["message"] for event in _received(operator)
                  if event.pushed for line in event.lines]
        assert pushed == ["something just happened"]

    async def test_a_floor_is_a_floor(self, operator, agent):
        await self._following(operator, agent, level="warn")
        operator.drain_events()
        _logs(agent).book.record("node", "chatter", level=logbook.DEBUG)
        _logs(agent).book.record("node", "trouble", level=logbook.ERROR)
        await _pump_once(agent.app)
        await deliver(agent, operator)
        pushed = [line["message"] for event in _received(operator)
                  if event.pushed for line in event.lines]
        assert pushed == ["trouble"]

    async def test_stopping_stops_it(self, operator, agent):
        await self._following(operator, agent)
        await operator.app.follow_logs(agent.id, False)
        await deliver(operator, agent)
        assert agent.app._log_followers == {}
        assert operator.app.following() == []

    async def test_a_follow_expires_rather_than_running_for_ever(self, operator,
                                                                 agent):
        """A console that died must stop costing that machine anything without
        it having to notice."""
        followers = await self._following(operator, agent)
        for entry in followers.values():
            entry["until"] = 0.0
        _logs(agent).book.record("node", "nobody is listening")
        await _pump_once(agent.app)
        assert agent.app._log_followers == {}

    async def test_the_number_of_followers_is_bounded(self, operator, agent):
        await enrol(operator, agent, caps=["logs"])
        _logs(agent)
        agent.app._log_followers = {
            f"{n:040x}": {"id": operator.id, "rid": "x", "level": "info",
                          "until": 1e12}
            for n in range(fleet.MAX_LOG_FOLLOWERS)}
        await operator.app.follow_logs(agent.id, True)
        await deliver(operator, agent)
        assert operator.id.raw.hex() not in agent.app._log_followers

    async def test_a_push_nobody_asked_for_is_dropped(self, operator, agent):
        """The one thing this shape could become: a machine pushing lines at a
        console that never asked, which a page would then render."""
        await enrol(operator, agent, caps=["logs"])
        agent.app._reply(operator.id, fleet.LOGS_REPLY,
                         {"rid": "not-ours", "op": "push", "ok": True,
                          "lines": [{"seq": 1, "at": 1.0, "level": "error",
                                     "source": "node", "topic": "",
                                     "message": "trust me", "fields": {}}]})
        await deliver(agent, operator)
        assert _received(operator) == []


async def _pump_once(app):
    """One turn of the agent's push loop, without waiting out its interval.

    The app's own two steps, called directly rather than re-implemented here: a
    copy of the loop in a test proves the copy."""
    app._push_to_followers(app._take_lines())
    await settle()


class TestTheArchiveHoldsOneRingPerNode:
    def test_a_chatty_node_cannot_push_out_a_quiet_ones_log(self):
        """The property a shared ring does not have, and the reason this is a
        ring per node: an adversary among the machines we manage would aim for
        exactly that."""
        archive = fleet_logs.LogArchive()
        quiet, loud = "aa" * 20, "bb" * 20
        archive.absorb(quiet, [{"seq": 1, "at": 1.0, "message": "the one line",
                                "source": "node", "level": "info"}])
        archive.absorb(loud, [{"seq": n, "at": 2.0, "message": "x" * 400,
                               "source": "node", "level": "info"}
                              for n in range(1, logbook.MAX_QUERY)])
        assert archive.query(node=quiet)["matched"] == 1

    def test_the_number_of_rings_is_bounded_and_the_quietest_goes(self):
        archive = fleet_logs.LogArchive()
        for number in range(fleet_logs.MAX_NODES + 4):
            archive.absorb(f"{number:040x}",
                           [{"seq": 1, "at": 1.0, "message": "hello",
                             "source": "node", "level": "info"}])
        held = archive.query()["nodes"]
        assert len(held) == fleet_logs.MAX_NODES
        assert f"{0:040x}" not in held        # the first to speak, the first out

    def test_a_line_already_held_is_not_held_twice(self):
        archive = fleet_logs.LogArchive()
        node = "cc" * 20
        line = {"seq": 3, "at": 1.0, "message": "once", "source": "node",
                "level": "info"}
        assert archive.absorb(node, [line]) == 1
        assert archive.absorb(node, [line]) == 0
        assert archive.seen(node) == 3

    def test_a_gap_is_recorded_rather_than_papered_over(self):
        archive = fleet_logs.LogArchive()
        node = "dd" * 20
        archive.absorb(node, [{"seq": 40, "at": 1.0, "message": "after",
                               "source": "node", "level": "info"}], lost=12)
        messages = [line["message"] for line in archive.query(node=node)["lines"]]
        assert any("12 lines were lost" in message for message in messages)

    def test_every_node_is_answered_at_once_and_ordered_by_our_clock(self):
        """Not by theirs. A machine we manage is an adversary that happens to
        hold a grant, and a merge ordered by the time *it* supplied is a merge
        it can pin its own lines to the top of for ever."""
        archive = fleet_logs.LogArchive()
        clock = [1000.0]
        archive.book("ee" * 20)._clock = lambda: clock[0]
        archive.book("ff" * 20)._clock = lambda: clock[0]
        archive.absorb("ee" * 20, [{"seq": 1, "at": 10.0, "message": "first",
                                    "source": "node", "level": "info"}])
        clock[0] = 2000.0
        # The second machine claims its line is far older. It is not.
        archive.absorb("ff" * 20, [{"seq": 1, "at": 1.0, "message": "second",
                                    "source": "node", "level": "info"}])
        answer = archive.query()
        assert [line["message"] for line in answer["lines"]] == ["second", "first"]
        assert answer["matched"] == 2
        # Their word for when it happened is kept, and kept as *their* word.
        assert answer["lines"][0]["fields"]["said_at"] == 1.0
        # And each line says which machine said it, or a merged view is a list
        # of sentences with no author.
        assert {line["node"] for line in answer["lines"]} == {"ee" * 20, "ff" * 20}

    def test_hostile_lines_are_bounded_like_any_other(self):
        """These arrive from a machine we manage, which the threat model says
        to treat as an adversary that happens to hold a grant."""
        archive = fleet_logs.LogArchive()
        node = "ab" * 20
        archive.absorb(node, [{"seq": 1, "message": "m" * 10_000,
                               "source": "s" * 500, "level": "invented",
                               "topic": "t" * 400, "at": "soon",
                               "fields": {f"k{n}": "v" * 900 for n in range(40)}}])
        [line] = archive.query(node=node)["lines"]
        assert len(line["message"]) <= logbook.MAX_MESSAGE
        assert line["source"] == "unknown"
        assert line["level"] == logbook.INFO
        assert len(line["fields"]) <= logbook.MAX_FIELDS

    def test_nothing_useful_is_learned_from_a_body_that_is_not_lines(self):
        archive = fleet_logs.LogArchive()
        for junk in (None, "lines", 42, [None, 3, "x"], [{"no": "seq"}]):
            archive.absorb("ba" * 20, junk)      # must not raise
        assert archive.query()["matched"] <= 1


class TestTheLiveTail:
    """One question the per-node rings do not answer.

    They answer "what happened on that machine". A console watching the whole
    network asks "what is happening, anywhere, right now" — and answering that
    by merging N rings needs a cursor per ring, a map the page would carry and
    every layer between would be widened for. So arrivals are written once more
    into one small ring of their own, and the answer is `LogBook.since` on that:
    the subscriber shape the rest of the product already speaks, and one integer
    for a page to hold.
    """

    def _archive(self):
        return fleet_logs.LogArchive()

    def test_every_machine_comes_back_on_one_cursor(self):
        archive = self._archive()
        first, second = "aa" * 20, "bb" * 20
        archive.absorb(first, [{"seq": 1, "at": 1.0, "message": "one",
                                "source": "node", "level": "info"}])
        archive.absorb(second, [{"seq": 1, "at": 2.0, "message": "two",
                                 "source": "node", "level": "error"}])
        answer = archive.stream(0)
        # Oldest first: a tail is read downwards, unlike the query a person
        # makes, which is newest first.
        assert [line["message"] for line in answer["lines"]] == ["one", "two"]
        assert [line["node"] for line in answer["lines"]] == [first, second]
        assert answer["seq"] > 0 and answer["lost"] == 0
        assert answer["nodes"] == sorted([first, second])

    def test_a_cursor_is_not_handed_the_same_line_twice(self):
        archive = self._archive()
        node = "cc" * 20
        archive.absorb(node, [{"seq": 1, "at": 1.0, "message": "once",
                               "source": "node", "level": "info"}])
        first = archive.stream(0)
        assert len(first["lines"]) == 1
        again = archive.stream(first["seq"])
        assert again["lines"] == [] and again["seq"] == first["seq"]
        archive.absorb(node, [{"seq": 2, "at": 2.0, "message": "twice",
                               "source": "node", "level": "info"}])
        assert [line["message"] for line in archive.stream(first["seq"])["lines"]] \
            == ["twice"]

    def test_the_tail_is_ordered_by_arrival_here(self):
        """Not by the time a machine claims. Same rule as the merged query, and
        it matters more here: a live view is read from the bottom, so a line a
        machine could place at the bottom is a line it could put in front of
        everybody else's."""
        archive = self._archive()
        archive.absorb("ee" * 20, [{"seq": 1, "at": 9_000_000.0,
                                    "message": "claims the future",
                                    "source": "node", "level": "info"}])
        archive.absorb("ff" * 20, [{"seq": 1, "at": 1.0, "message": "honest",
                                    "source": "node", "level": "info"}])
        assert [line["message"] for line in archive.stream(0)["lines"]] \
            == ["claims the future", "honest"]

    def test_a_machine_cannot_sign_a_line_with_somebody_elses_name(self):
        """The one thing a merged view must never get wrong. Every line in it
        carries who said it, and `clean_fields` keeps the *first* `MAX_FIELDS`
        entries — so a machine sending a field called `node`, or simply sending
        eight of its own, could otherwise displace or overwrite the attribution
        and be read as a neighbour."""
        archive = self._archive()
        liar, victim = "ab" * 20, "cd" * 20
        archive.absorb(victim, [{"seq": 1, "at": 1.0, "message": "innocent",
                                 "source": "node", "level": "info"}])
        archive.absorb(liar, [{
            "seq": 1, "at": 1.0, "message": "it was them", "source": "node",
            "level": "info",
            "fields": dict({"node": victim, "seq": 9999, "said_at": 0.0},
                           **{f"pad{n}": n for n in range(logbook.MAX_FIELDS)})}])
        lines = {line["message"]: line for line in archive.stream(0)["lines"]}
        forged = lines["it was them"]
        assert forged["node"] == liar
        assert forged["fields"]["node"] == liar
        assert forged["fields"]["seq"] == 1
        # And the per-node ring says the same thing, because it is stamped by
        # the same helper rather than by a second copy of the rule.
        [held] = archive.query(node=liar, contains="it was them")["lines"]
        assert held["fields"]["node"] == liar

    def test_a_machine_we_were_told_to_forget_is_not_answered_for(self):
        archive = self._archive()
        gone, kept = "aa" * 20, "bb" * 20
        archive.absorb(gone, [{"seq": 1, "at": 1.0, "message": "before",
                               "source": "node", "level": "info"}])
        archive.forget(gone)
        archive.absorb(kept, [{"seq": 1, "at": 2.0, "message": "after",
                               "source": "node", "level": "info"}])
        # And speaking again gets a fresh ring, which must not come with what
        # was said before somebody pressed forget.
        archive.absorb(gone, [{"seq": 2, "at": 3.0, "message": "returned",
                               "source": "node", "level": "info"}])
        messages = [line["message"] for line in archive.stream(0)["lines"]]
        assert "before" not in messages
        assert messages == ["after", "returned"]

    def test_a_reader_that_fell_behind_is_told_rather_than_lied_to(self):
        """The ring is the buffer, and nothing is held per subscriber. So a page
        that was away comes back with the number it last saw and is told how much
        went past — never handed a gap it cannot see."""
        import os

        archive = self._archive()
        node = "dd" * 20
        archive.absorb(node, [{"seq": 1, "at": 1.0, "message": "kept",
                               "source": "node", "level": "info"}])
        held = archive.stream(0)["seq"]
        # A tail at its floor, filled with lines that do not compress: what a
        # page away for a minute over a busy fleet comes back to.
        archive._tail.start(megabytes=logbook.MIN_BYTES / 1024 / 1024)
        seq = 2
        for _batch in range(4):
            archive.absorb(node, [{"seq": seq + n, "at": 2.0,
                                   "source": "node", "level": "info",
                                   "message": os.urandom(200).hex()}
                                  for n in range(logbook.MAX_QUERY)])
            seq += logbook.MAX_QUERY
        answer = archive.stream(held)
        assert answer["lost"] > 0
        assert len(answer["lines"]) <= logbook.MAX_QUERY
        # And the cursor still moves, so a reader told about the gap resumes
        # rather than asking for the same missing lines for ever.
        assert answer["seq"] > held

    def test_the_tail_is_bounded_and_counted_apart(self):
        """It is a second copy, so an operator asking what this costs is owed
        both halves rather than one quietly folded into the other."""
        archive = self._archive()
        node = "ee" * 20
        archive.absorb(node, [{"seq": n, "at": 1.0, "message": "y" * 400,
                               "source": "node", "level": "info"}
                              for n in range(1, logbook.MAX_QUERY)])
        status = archive.status()
        assert status["tail"]["megabytes"] == fleet_logs.TAIL_MEGABYTES
        assert status["tail"]["used_bytes"] <= \
            fleet_logs.TAIL_MEGABYTES * 1024 * 1024
        assert status["tail"]["records"] > 0
        # Counted apart from the per-node rings, not inside them.
        assert "tail" not in status["nodes"]

    def test_making_room_is_not_forgetting(self):
        """A fleet at `MAX_NODES` evicts its quietest ring whenever a new
        machine speaks. If that also cleared the live tail, a console watching a
        busy fleet would lose the whole stream every time an unfamiliar node
        said anything — so eviction drops the ring and leaves the tail, and only
        an operator saying *forget* drops both."""
        archive = self._archive()
        speaker = "aa" * 20
        archive.absorb(speaker, [{"seq": 1, "at": 1.0, "message": "still here",
                                  "source": "node", "level": "info"}])
        for number in range(fleet_logs.MAX_NODES + 4):
            archive.absorb(f"{number:040x}",
                           [{"seq": 1, "at": 2.0, "message": "crowding in",
                             "source": "node", "level": "info"}])
        # Rings were evicted — that bound still holds…
        assert len(archive.status()["nodes"]) == fleet_logs.MAX_NODES
        # …and the tail kept running through all of it.
        assert len(archive.stream(0)["lines"]) > 1
        # The operator's verb is the one that drops it.
        archive.forget(f"{fleet_logs.MAX_NODES:040x}")
        assert archive.stream(0)["lines"] == []

    def test_a_reader_and_the_loop_writing_do_not_collide(self):
        """Lines arrive on the node's loop and every reader here is a console
        thread, so the table of rings is iterated by one while the other adds to
        it and evicts from it. In CPython that is
        `RuntimeError: dictionary keys changed during iteration` — a crash, not
        a stale answer, and one a machine could time by speaking while somebody
        has the page open. The charter calls a crash a security bug.

        A live page reads this once a second, which is what turned a race nobody
        had hit into one worth writing down.

        Every thread runs the same number of rounds from a barrier and yields
        between them, which is what makes the overlap real: the first draft of
        this test let the writer finish in ten milliseconds, before a reader had
        been scheduled at all, and proved nothing while passing.

        It is attempted more than once because a race is caught by luck, not by
        construction — the unguarded version survives a single attempt often
        enough that one would be a coin toss wearing a guard's clothes. Even so
        this is a *guard*, not a proof: what makes the lock correct is that a
        dict cannot be iterated while another thread resizes it, and the test is
        here to notice if somebody takes it back out."""
        import threading
        import time as clock

        for _attempt in range(3):
            archive = self._archive()
            rounds = 400
            seq, made, failures = [0], [0], []

            def churn():
                made[0] += 1
                # A new identity every round, so the table is growing *and*
                # evicting under the readers rather than merely changing.
                archive.absorb(f"{made[0]:040x}",
                               [{"seq": 1, "at": float(made[0]),
                                 "source": "node", "level": "info",
                                 "message": f"line {made[0]}"}])

            def follow():
                seq[0] = archive.stream(seq[0])["seq"]

            work = {"churn": churn, "follow": follow, "status": archive.status,
                    "query": archive.query,
                    "resize": lambda: archive.set_default_megabytes(2.0)}
            ready = threading.Barrier(len(work))

            def run(name):
                ready.wait(timeout=30)
                try:
                    for _ in range(rounds):
                        work[name]()
                        clock.sleep(0)      # hand the interpreter over
                except Exception as exc:           # noqa: BLE001 — the point
                    failures.append((name, repr(exc)))

            threads = [threading.Thread(target=run, args=(name,))
                       for name in work]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=120)
            assert not failures, failures
            assert not any(thread.is_alive() for thread in threads)
            # And it still answers afterwards, rather than merely not raising: a
            # lock that made every read return nothing would pass everything
            # above and none of the point of it.
            assert made[0] == rounds
            follow()
            assert seq[0] > 0
            assert len(archive.status()["nodes"]) == fleet_logs.MAX_NODES

    def test_nothing_hostile_in_a_body_reaches_the_tail_unbounded(self):
        archive = self._archive()
        node = "ba" * 20
        for junk in (None, "lines", 42, [None, 3, "x"], [{"no": "seq"}]):
            archive.stream(junk if isinstance(junk, int) else 0)   # must not raise
            archive.absorb(node, junk)
        archive.absorb(node, [{"seq": 1, "message": "m" * 10_000,
                               "source": "s" * 500, "level": "invented",
                               "at": "soon",
                               "fields": {f"k{n}": "v" * 900 for n in range(40)}}])
        for line in archive.stream(0)["lines"]:
            assert len(line["message"]) <= logbook.MAX_MESSAGE
            assert len(line["fields"]) <= logbook.MAX_FIELDS
            assert line["level"] in logbook.LEVELS


class TestThePolicyIsPerNodeWithADefault:
    def test_the_default_is_active_and_a_node_inherits_it(self):
        from src.apps.fleet_state import FleetState

        state = FleetState()
        assert state.log_defaults()["policy"] == fleet_logs.ACTIVE
        assert state.log_policy("ab" * 20)["policy"] == fleet_logs.ACTIVE

    def test_a_node_may_have_its_own_and_hand_it_back(self):
        from src.apps.fleet_state import FleetState

        state = FleetState()
        node = "ab" * 20
        state.add_managed(node, caps=["logs"])
        assert state.set_log_policy(node, policy="always")["policy"] == "always"
        assert state.log_policy(node)["own"] == ["policy"]
        state.set_log_defaults(policy="never")
        assert state.log_policy(node)["policy"] == "always"   # its own wins
        state.set_log_policy(node, inherit=True)
        assert state.log_policy(node)["policy"] == "never"

    def test_a_policy_about_a_node_we_do_not_manage_is_refused(self):
        from src.apps.fleet_state import FleetState

        assert FleetState().set_log_policy("ab" * 20, policy="always") is None

    def test_a_size_is_clamped_to_something_this_machine_can_hold(self):
        from src.apps.fleet_state import FleetState

        state = FleetState()
        assert state.set_log_defaults(megabytes=10_000)["megabytes"] == \
            fleet_logs.MAX_MEGABYTES
        assert state.set_log_defaults(megabytes=-1)["megabytes"] == \
            fleet_logs.DEFAULT_MEGABYTES
        assert state.set_log_defaults(megabytes="lots")["megabytes"] == \
            fleet_logs.DEFAULT_MEGABYTES

    def test_active_means_somebody_is_looking_and_stops_meaning_it(self):
        archive = fleet_logs.LogArchive()
        node = "ab" * 20
        assert archive.wants(node, fleet_logs.ACTIVE) is False
        archive.note_active(node, now=1000.0)
        assert archive.wants(node, fleet_logs.ACTIVE, now=1000.0) is True
        assert archive.wants(node, fleet_logs.ACTIVE,
                             now=1000.0 + fleet_logs.ACTIVE_TTL + 1) is False
        # The other two answer the same whoever is looking.
        assert archive.wants(node, fleet_logs.ALWAYS, now=1e9) is True
        assert archive.wants(node, fleet_logs.NEVER, now=1000.0) is False

    def test_an_unknown_policy_reads_as_the_default(self):
        assert fleet_logs.clean_policy("everything") == fleet_logs.DEFAULT_POLICY
        assert fleet_logs.clean_policy(None) == fleet_logs.DEFAULT_POLICY


class TestTheCapabilityIsDeclaredOnce:
    def test_it_is_in_the_ledger_and_described(self):
        from src.apps.fleet_state import CAPABILITIES, CAP_DESCRIPTIONS

        assert "logs" in CAPABILITIES
        assert CAP_DESCRIPTIONS["logs"]

    def test_the_request_carries_its_own_purpose(self):
        """A signature obtained for one action is useless for another, which is
        what a purpose per capability is for."""
        assert fleet._PURPOSE_FOR[fleet.LOGS_REQUEST] == "fleet.logs"
        assert fleet.PURPOSE_BY_CAP["logs"] == "fleet.logs"


class TestTheConsoleSideOfIt:
    """The bridge between the collected rings and the page that reads them."""

    async def _bridge(self):
        from src.app_registry import FLEET_APP_ID
        from src.apps.fleet import FleetApp
        from src.apps.fleet_state import FleetState
        from src.apps.fleet_web import FleetBridge
        from src.node import MeshNode
        from tests.conftest import make_manager
        from tests.test_console_fleet import StubClient

        node = MeshNode(transport_manager=make_manager())
        app = FleetApp(StubClient(), node.app_auth(FLEET_APP_ID),
                       state=FleetState(), auto_status=False)
        bridge = FleetBridge(app)
        bridge.start(asyncio.get_running_loop())
        return node, app, bridge

    async def test_what_arrives_is_held_and_answered_to_the_page(self):
        node, app, bridge = await self._bridge()
        machine = "ab" * 20
        try:
            app.state.add_managed(machine, caps=["logs"])
            app._log_follows[machine] = "rid"
            app._on_logs_reply(
                fleet.NodeID.from_hex(machine),
                {"rid": "rid", "op": "push", "ok": True,
                 "lines": [{"seq": 1, "at": 10.0, "level": "error",
                            "source": "node", "topic": "link",
                            "message": "a link died", "fields": {}}]})
            await settle()
            answer = bridge.logs()
            assert answer["matched"] == 1
            assert answer["lines"][0]["node"] == machine
            # Everything the page needs in one answer: what is held, what the
            # policies are, what is being followed. Three questions would be
            # three chances for the answers to disagree.
            assert answer["defaults"]["policy"] == fleet_logs.DEFAULT_POLICY
            assert machine in answer["policies"]
            assert answer["status"]["nodes"][machine]["records"] == 1
        finally:
            bridge.stop()
            await node.stop()

    async def test_the_live_page_is_answered_from_here_and_never_the_mesh(self):
        """Two operations, one for each half of what a network page shows: what
        has arrived, and who it arrives from. Both read rings this console
        already holds — a page following forty machines is not forty machines'
        worth of traffic."""
        node, app, bridge = await self._bridge()
        machine = "ab" * 20
        try:
            app.state.add_managed(machine, caps=["logs"], label="the relay")
            app._log_follows[machine] = "rid"
            app._on_logs_reply(
                fleet.NodeID.from_hex(machine),
                {"rid": "rid", "op": "push", "ok": True,
                 "lines": [{"seq": 1, "at": 10.0, "level": "warn",
                            "source": "peers", "topic": "link",
                            "message": "a link flapped", "fields": {}}]})
            await settle()
            stream = bridge.api_logs_stream()
            assert [line["message"] for line in stream["lines"]] \
                == ["a link flapped"]
            assert stream["lines"][0]["node"] == machine
            # And the cursor it hands back is the one to come back with.
            assert bridge.api_logs_stream(seq=stream["seq"])["lines"] == []

            board = bridge.api_logs_machines()
            [row] = board["machines"]
            assert row["id"] == machine and row["label"] == "the relay"
            assert row["records"] == 1 and row["caps"] == ["logs"]
            assert row["policy"] == fleet_logs.DEFAULT_POLICY
            # The choices belong to the form that offers them, once — not to
            # every row in a list that may be a hundred long.
            assert "policies" not in row and board["policies"]
            assert board["held"]["tail"]["records"] == 1
        finally:
            bridge.stop()
            await node.stop()

    async def test_a_machine_nobody_manages_is_on_neither_answer(self):
        node, app, bridge = await self._bridge()
        try:
            assert bridge.api_logs_stream()["lines"] == []
            assert bridge.api_logs_machines()["machines"] == []
        finally:
            bridge.stop()
            await node.stop()

    async def test_reading_a_nodes_log_is_what_active_means(self):
        node, app, bridge = await self._bridge()
        machine = "ab" * 20
        try:
            app.state.add_managed(machine, caps=["logs"])
            assert bridge._logs.wants(machine, fleet_logs.ACTIVE) is False
            bridge.logs_watching(machine)
            assert bridge._logs.wants(machine, fleet_logs.ACTIVE) is True
        finally:
            bridge.stop()
            await node.stop()

    async def test_the_follows_track_the_policies(self):
        node, app, bridge = await self._bridge()
        watched, ignored = "ab" * 20, "cd" * 20
        try:
            app.state.add_managed(watched, caps=["logs"])
            app.state.add_managed(ignored, caps=["logs"])
            app.state.set_log_policy(watched, policy="always")
            app.state.set_log_policy(ignored, policy="never")
            await bridge._reconcile_follows()
            assert app.following() == [watched]
            # And a policy taken back stops the follow rather than leaving a
            # machine pushing at a console that no longer wants it.
            app.state.set_log_policy(watched, policy="never")
            await bridge._reconcile_follows()
            assert app.following() == []
        finally:
            bridge.stop()
            await node.stop()

    async def test_a_node_that_granted_us_nothing_is_never_followed(self):
        """Asking a machine for something it never granted is noise an operator
        has to interpret — and on this path it would be noise on a timer."""
        node, app, bridge = await self._bridge()
        machine = "ab" * 20
        try:
            app.state.add_managed(machine, caps=["status"])
            app.state.set_log_policy(machine, policy="always")
            await bridge._reconcile_follows()
            assert app.following() == []
        finally:
            bridge.stop()
            await node.stop()

    async def test_forgetting_drops_what_was_collected(self):
        node, app, bridge = await self._bridge()
        machine = "ab" * 20
        try:
            bridge._logs.absorb(machine, [{"seq": 1, "at": 1.0,
                                           "message": "a line",
                                           "source": "node", "level": "info"}])
            assert bridge.logs()["matched"] == 1
            bridge.forget_logs()
            assert bridge.logs()["matched"] == 0
        finally:
            bridge.stop()
            await node.stop()

    async def test_a_size_set_for_one_node_follows_it(self):
        node, app, bridge = await self._bridge()
        machine = "ab" * 20
        try:
            app.state.add_managed(machine, caps=["logs"])
            bridge._logs.book(machine)
            bridge.set_log_policy(machine, megabytes=7)
            assert bridge._logs.megabytes_for(machine) == 7.0
            assert bridge._logs.book(machine).status()["megabytes"] == 7.0
            bridge.set_log_policy(machine, inherit=True)
            assert bridge._logs.megabytes_for(machine) == \
                fleet_logs.DEFAULT_MEGABYTES
        finally:
            bridge.stop()
            await node.stop()


class TestThePageOffersItWithoutDecidingAnything:
    def test_the_fleet_page_has_a_logs_panel_and_a_filter_per_axis(self):
        html = webassets.FLEET_HTML
        assert 'data-tab="logs"' in html and 'data-panel="logs"' in html
        # The four axes an operator filters on, named in the user's request:
        # when, which machine, what kind, what it says.
        for control in ("logs-node", "logs-level", "logs-contains",
                        "logs-since", "logs-until"):
            assert f'id="{control}"' in html

    def test_the_page_never_asks_the_network_to_scroll(self):
        """Reading is a read of what this node already holds. A page that asked
        the mesh on every keystroke would turn a filter into forty requests."""
        source = webassets.FLEET_JS
        block = source.split("// ---- the logs of the machines we manage")[1]
        block = block.split("// ---- notifications")[0]
        assert "/api/fleet/logs" in block
        # The one call that does reach a machine is the button that says so.
        assert block.count("/api/fleet/logs-fetch") == 1

    def test_every_policy_the_module_declares_is_offered_by_the_page(self):
        """Two lists again: an operator cannot choose what the page will not
        name, and a policy added here would otherwise be invisible."""
        html = webassets.FLEET_HTML
        for policy in fleet_logs.POLICIES:
            assert f'value="{policy}"' in html


class TestNothingKeepsRunningForNobody:
    async def test_the_push_loop_ends_when_the_last_follower_goes(self, operator,
                                                                  agent):
        """A node that is followed by nobody must stop compressing and queueing
        lines for nobody — and must let go of the subscription it opened."""
        await enrol(operator, agent, caps=["logs"])
        source = _logs(agent)
        await operator.app.follow_logs(agent.id, True)
        await deliver(operator, agent)
        assert agent.app._log_pump is not None and source.watching is True
        await operator.app.follow_logs(agent.id, False)
        await deliver(operator, agent)
        for _ in range(40):                   # its own next turn, not a cancel
            await asyncio.sleep(0.01)
            if agent.app._log_pump is None:
                break
        assert agent.app._log_pump is None
        assert source.watching is False

    async def test_stopping_the_app_lets_go_of_everything(self, operator, agent):
        await enrol(operator, agent, caps=["logs"])
        _logs(agent)
        await operator.app.follow_logs(agent.id, True)
        await deliver(operator, agent)
        await agent.app.stop()
        assert agent.app._log_followers == {}
        assert agent.app._log_pump is None
        await operator.app.stop()
        assert operator.app.following() == []


class TestTheDecisionIsOfferedWhereTheMachineIs:
    """A policy about a machine belongs on that machine's card — which is the
    one the console's map, chat and fleet all open."""

    async def test_the_relation_carries_what_we_collect(self):
        from src.app_registry import FLEET_APP_ID
        from src.apps.fleet import FleetApp
        from src.apps.fleet_state import FleetState
        from src.apps.fleet_web import FleetBridge
        from src.node import MeshNode
        from tests.conftest import make_manager
        from tests.test_console_fleet import StubClient

        node = MeshNode(transport_manager=make_manager())
        app = FleetApp(StubClient(), node.app_auth(FLEET_APP_ID),
                       state=FleetState(), auto_status=False)
        bridge = FleetBridge(app)
        bridge.start(asyncio.get_running_loop())
        machine = "ab" * 20
        try:
            app.state.add_managed(machine, caps=["logs"])
            relation = bridge.api_relation(machine)
            assert relation["logs"]["policy"] == fleet_logs.DEFAULT_POLICY
            # The choices come back with the answer, so a page never holds its
            # own copy of what the policies are.
            assert relation["logs"]["policies"] == list(fleet_logs.POLICIES)
            answer = bridge.api_logs_policy(machine, "always")
            assert answer["ok"] is True
            assert answer["logs"]["policy"] == "always"
            assert bridge.api_relation(machine)["logs"]["policy"] == "always"
            # A node nobody manages has no policy to show, rather than a
            # default that will never be acted on.
            assert bridge.api_relation("cd" * 20)["logs"] is None
            assert bridge.api_logs_policy("cd" * 20, "always")["ok"] is False
        finally:
            bridge.stop()
            await node.stop()

    def test_the_node_card_renders_it_from_what_it_was_told(self):
        source = webassets.APP_JS
        block = source.split("logsSentence(logs){")[1].split("schemes(view)")[0]
        # The words are the product's; the values and the choices are the
        # node's, so a policy this page has never heard of still renders.
        assert "logs.policies" in block
        assert "data-nv-logs" in block
        # And the sentence says what is *kept here*, not only what the policy
        # is: "collected always" with nothing kept is the state an operator
        # most needs to be able to see.
        assert "logs.records" in block and "logs.following" in block
