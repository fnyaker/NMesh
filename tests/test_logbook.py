"""
What a node says about itself — kept only when asked, bounded, and readable.

Written from the decision rather than from `src/logbook.py`: a log of who this
node talked to and when is exactly the material the threat model says to hold as
little of as possible, so the questions here are the ones an operator would ask
before turning it on.

* Is anything kept before somebody asks for it? **No** — and stopping drops what
  was kept rather than leaving it in memory.
* Does the bound hold under pressure, in the unit an operator sized it in?
* Does a subscriber that lost its connection catch up, and is it told when it
  cannot?
* Can a line from a peer, or from an app, make any of that stop being true?
"""
import json
import time

import pytest

from src import logbook
from src.logbook import LogBook


def _fill(book, count, *, source="node", level=logbook.INFO, message="a line"):
    for number in range(count):
        book.record(source, f"{message} {number}", level=level, topic="t")


class TestNothingIsKeptUntilSomebodyAsks:
    def test_a_fresh_book_keeps_nothing_at_all(self):
        book = LogBook()
        _fill(book, 5000)
        status = book.status()
        assert status["running"] is False
        assert status["records"] == 0
        assert status["seq"] == 0
        assert book.query()["lines"] == []

    def test_stopping_drops_what_was_kept(self):
        """The opposite of the trace, and the reason this file exists: a ring
        of what a node was thinking, left in memory after the person reading it
        stopped, is a record it has no business holding."""
        book = LogBook()
        book.start()
        _fill(book, 100)
        assert book.status()["records"] == 100
        assert book.stop()["records"] == 0
        assert book.query()["lines"] == []
        # And it stays stopped: a line arriving after is not kept either.
        _fill(book, 10)
        assert book.status()["records"] == 0

    def test_clearing_keeps_it_running(self):
        book = LogBook()
        book.start()
        _fill(book, 10)
        book.clear()
        assert book.status()["running"] is True
        _fill(book, 3)
        assert book.status()["records"] == 3


class TestTheBoundIsTheOneAnOperatorSized:
    def test_a_flood_never_grows_past_the_ring(self):
        """The property that matters under an attacker: whatever is written,
        what is *held* stays inside what was allowed."""
        book = LogBook()
        book.start(megabytes=logbook.MIN_BYTES / 1024 / 1024)
        _fill(book, 40_000, message="x" * 400)
        assert book.status()["used_bytes"] <= logbook.MIN_BYTES
        assert book.status()["dropped"] > 0

    def test_the_size_is_clamped_to_what_the_module_allows(self):
        book = LogBook()
        assert book.start(megabytes=0)["megabytes"] == round(
            logbook.MIN_BYTES / 1024 / 1024, 2)
        assert book.start(megabytes=10_000)["megabytes"] == round(
            logbook.MAX_BYTES / 1024 / 1024, 2)

    def test_compression_is_what_makes_the_bound_generous(self):
        """Log lines are the most repetitive text a program produces. If this
        ever stops being true the ring holds an order of magnitude less than
        the file says it does, and nobody would notice."""
        book = LogBook()
        book.start()
        _fill(book, 4000)
        status = book.status()
        assert status["records"] == 4000
        # Four thousand lines in well under a megabyte, which is the claim.
        assert status["used_bytes"] < 1024 * 1024
        # And the *reported* ratio is the one an operator would measure: it
        # read 1.0 on a ring compressing forty to one, because it divided the
        # compressed size by itself. A number is a claim about what it counts.
        lines, seen = [], 0
        while True:                       # one page is bounded; the ring is not
            page = book.since(seen, limit=logbook.MAX_QUERY)
            if not page["lines"]:
                break
            lines.extend(page["lines"])
            seen = page["seq"]
        assert len(lines) == 4000
        measured = len(json.dumps(lines).encode("utf-8")) / status["used_bytes"]
        assert status["ratio"] > 2.0
        assert 0.3 < status["ratio"] / measured < 3.0, (
            f"status says {status['ratio']}, the bytes say {measured:.1f}")


class TestASubscriberCatchesUp:
    def test_since_answers_only_what_came_after(self):
        book = LogBook()
        book.start()
        _fill(book, 10)
        seen = book.since(0)["seq"]
        _fill(book, 5)
        answer = book.since(seen)
        assert answer["returned"] == 5
        assert [line["seq"] for line in answer["lines"]] == list(range(11, 16))
        assert answer["lost"] == 0

    def test_a_reader_too_slow_for_the_ring_is_told_so(self):
        """Nothing is buffered per subscriber — the ring is the buffer. A
        reader that fell behind is told how much went past rather than handed a
        gap it cannot see."""
        book = LogBook()
        book.start(megabytes=logbook.MIN_BYTES / 1024 / 1024)
        _fill(book, 20)
        seen = book.since(0)["seq"]
        _fill(book, 20_000, message="y" * 400)
        assert book.since(seen)["lost"] > 0

    def test_a_sequence_that_is_not_a_number_reads_as_the_beginning(self):
        book = LogBook()
        book.start()
        _fill(book, 3)
        for bad in (None, "", "abc", [], {"seq": 1}):
            assert book.since(bad)["returned"] == 3


class TestFiltersAnswerTheQuestionAsked:
    def _book(self):
        book = LogBook()
        book.start()
        book.record("node", "a link died", level=logbook.WARN, topic="link")
        book.record("app:beef", "hello", level=logbook.DEBUG, topic="chat")
        book.record("node", "handshake refused", level=logbook.ERROR,
                    topic="security", fields={"peer": "abcd"})
        return book

    def test_a_level_is_a_floor_not_an_equality(self):
        book = self._book()
        assert book.query(level=logbook.WARN)["matched"] == 2
        assert book.query(level=logbook.ERROR)["matched"] == 1
        assert book.query(level=logbook.DEBUG)["matched"] == 3

    def test_source_topic_and_content(self):
        book = self._book()
        assert book.query(source="app:")["matched"] == 1
        assert book.query(topic="link")["matched"] == 1
        assert book.query(contains="refused")["matched"] == 1
        # The structured half is searched too, or a field would be a place to
        # put something a search can never find.
        assert book.query(contains="abcd")["matched"] == 1

    def test_a_query_is_bounded_however_wide_the_filter(self):
        book = LogBook()
        book.start()
        _fill(book, logbook.MAX_QUERY * 3)
        answer = book.query(limit=10_000_000)
        assert answer["returned"] == logbook.MAX_QUERY
        assert answer["matched"] == logbook.MAX_QUERY * 3

    def test_a_query_answers_newest_first_and_since_oldest_first(self):
        book = LogBook()
        book.start()
        _fill(book, 5)
        assert book.query()["lines"][0]["seq"] == 5
        assert book.since(0)["lines"][0]["seq"] == 1

    def test_time_bounds(self):
        moment = [1000.0]
        book = LogBook(clock=lambda: moment[0])
        book.start()
        book.record("node", "early")
        moment[0] = 2000.0
        book.record("node", "late")
        assert book.query(since_time=1500.0)["matched"] == 1
        assert book.query(until_time=1500.0)["matched"] == 1


class TestALineIsNeverTrusted:
    """An app writes these, and an app is a local process this node does not
    trust with anything else either."""

    def test_every_axis_is_bounded(self):
        book = LogBook()
        book.start()
        book.record("s" * 500, "m" * 10_000, topic="t" * 500,
                    fields={f"k{n}": "v" * 1000 for n in range(50)})
        [line] = book.query()["lines"]
        assert len(line["message"]) <= logbook.MAX_MESSAGE
        assert len(line["topic"]) <= logbook.MAX_TOPIC
        assert len(line["fields"]) <= logbook.MAX_FIELDS
        assert all(len(str(v)) <= logbook.MAX_FIELD_TEXT
                   for v in line["fields"].values())

    def test_a_source_that_is_not_a_name_is_refused_rather_than_repaired(self):
        """A source is what every filter in the product groups by. One that can
        contain anything is a filter that can be made to match anything."""
        book = LogBook()
        book.start()
        for bad in ("a b", "app:\nnode", "../../etc", "x" * 200, "", None,
                    "app:beef\x00node"):
            book.record(bad, "line")
        assert {line["source"] for line in book.query()["lines"]} == {"unknown"}
        # Surrounding whitespace is the one repair, because it is not a
        # different name — everything else is a different name.
        book.clear()
        book.record("  app:beef\n", "line")
        assert book.query()["lines"][0]["source"] == "app:beef"

    def test_a_level_nobody_recognises_is_info_rather_than_a_dropped_line(self):
        book = LogBook()
        book.start()
        book.record("node", "line", level="catastrophic")
        assert book.query()["lines"][0]["level"] == logbook.INFO

    def test_recording_never_raises_whatever_it_is_handed(self):
        """`record` is called from receive loops and handlers, where an
        exception is a dropped packet or a dead loop."""
        class _Awkward:
            def __str__(self):
                raise RuntimeError("no")

        book = LogBook()
        book.start()
        for message in (None, 12, b"bytes", _Awkward()):
            book.record("node", message)          # must not raise
        book.record("node", "fine", fields={"bad": _Awkward()})
        assert book.status()["running"] is True

    def test_a_line_is_json_serialisable_because_it_travels(self):
        book = LogBook()
        book.start()
        book.record("node", "line", fields={"n": 1, "f": 1.5, "b": True,
                                            "none": None, "o": object()})
        json.dumps(book.query())              # must not raise


class TestTheSinkIsForWhoeverIsListeningNow:
    def test_every_recorded_line_reaches_the_sink(self):
        seen = []
        book = LogBook()
        book.sink = seen.append
        book.start()
        _fill(book, 3)
        assert [line["message"] for line in seen] == [
            "a line 0", "a line 1", "a line 2"]
        # The same shape a query answers with, so a subscriber that catches up
        # after a gap does not find different keys.
        assert set(seen[0]) == set(book.query()["lines"][0])

    def test_a_sink_that_throws_costs_one_line_and_nothing_else(self):
        def _angry(_line):
            raise RuntimeError("no")

        book = LogBook()
        book.sink = _angry
        book.start()
        book.record("node", "line")           # must not raise
        assert book.status()["records"] == 1

    def test_nothing_reaches_a_sink_while_the_book_is_stopped(self):
        seen = []
        book = LogBook()
        book.sink = seen.append
        _fill(book, 10)
        assert seen == []


class TestRankIsSharedRatherThanReimplemented:
    def test_an_unknown_level_ranks_where_it_is_stored(self):
        assert logbook.rank("nonsense") == logbook.rank(logbook.INFO)
        assert logbook.rank(None) == logbook.rank(logbook.INFO)
        assert logbook.rank("WARN ") == logbook.rank(logbook.WARN)
        assert logbook.rank(logbook.ERROR) > logbook.rank(logbook.DEBUG)


class TestReadingIsCheapEnoughToOffer:
    def test_a_query_over_a_full_ring_does_not_stall_a_page(self):
        """A floor, not a benchmark. A search that decompressed the whole ring
        for every question would be the reason nobody leaves this on."""
        book = LogBook()
        book.start()
        _fill(book, 20_000)
        started = time.perf_counter()
        answer = book.query(contains="a line 19999")
        elapsed = time.perf_counter() - started
        assert answer["matched"] >= 1
        assert elapsed < 2.0, f"a query over 20k lines took {elapsed:.2f}s"


class TestASwallowedFailureHasAReaderAtLast:
    """The failures a guard catches are the ones with no other reader at all
    (`src/faults.py`) — which makes them the lines an operator turning a log on
    is most often looking for."""

    async def test_a_guarded_failure_lands_in_the_ring(self):
        from src import faults
        from src.node import MeshNode
        from tests.conftest import make_manager

        node = MeshNode(transport_manager=make_manager())
        try:
            node.logs.start()
            faults.note("something.somewhere", ValueError("no"))
            [line] = node.logs.query(source="faults")["lines"]
            assert line["level"] == logbook.ERROR
            assert "something.somewhere" in line["message"]
            # The *name* of the failure, never the machine's own words for it:
            # a log line is the node's, but the habit that keeps a reply clean
            # is worth keeping here too.
            assert line["fields"] == {"error": "ValueError"}
            assert "no" not in line["message"]
        finally:
            await node.stop()

    async def test_a_node_that_stops_does_not_silence_one_still_running(self):
        """Two nodes in one process is every test in this suite, and a global
        that the first one to stop clears is a log that quietly stops."""
        from src import faults
        from src.node import MeshNode
        from tests.conftest import make_manager

        first = MeshNode(transport_manager=make_manager())
        second = MeshNode(transport_manager=make_manager())
        second.logs.start()
        try:
            await first.stop()
            faults.note("after.the.first.stopped", ValueError("no"))
            assert second.logs.query(source="faults")["matched"] == 1
        finally:
            await second.stop()

    async def test_the_last_node_to_stop_leaves_nothing_listening(self):
        from src import faults
        from src.node import MeshNode
        from tests.conftest import make_manager

        node = MeshNode(transport_manager=make_manager())
        await node.stop()
        assert faults._sink is None
        faults.note("nobody.is.listening", ValueError("no"))   # must not raise
