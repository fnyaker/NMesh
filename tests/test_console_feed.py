"""
What the console sends a page, and how the two stay in step.

The symptom this exists for is a page that suddenly has nothing on it. Three
different things produced it and they are tested apart: an error body assigned
over held state, a whole ledger re-sent because one row moved, and a node that
updated itself under an open page.

Two of those are this module's; the third is the page's, and what is held here
is the half the node owes it — saying which build answered, and never handing
back an answer that is only partly one.
"""
import json

import pytest

from src import console_feed
from src.version import __version__


class TestRevision:
    def test_it_is_the_content_and_not_a_counter(self):
        """A counter is bumped by whoever writes, and the writer that forgets is
        a section that quietly stops updating — which looks like everything
        working. This cannot drift from what it describes."""
        assert console_feed.revision([1, 2, 3]) == console_feed.revision([1, 2, 3])
        assert console_feed.revision([1, 2, 3]) != console_feed.revision([1, 2, 4])

    def test_key_order_is_not_content(self):
        """Two dictionaries that say the same thing are the same section, and a
        re-send because Python happened to iterate differently is a re-send."""
        assert (console_feed.revision({"a": 1, "b": 2})
                == console_feed.revision({"b": 2, "a": 1}))

    def test_something_unserialisable_has_no_revision_rather_than_a_wrong_one(self):
        assert console_feed.revision({"a": object()}) == ""


class TestWhatAReaderClaimsToHold:
    def test_a_claim_is_names_and_revisions(self):
        assert console_feed.parse_have("managed:1a2b3c4d,jobs:00ff00ff") == {
            "managed": "1a2b3c4d", "jobs": "00ff00ff"}

    def test_anything_that_is_not_one_is_dropped_not_interpreted(self):
        """A claim we cannot read means the reader gets everything, which is
        always correct and only ever slower."""
        parsed = console_feed.parse_have(
            "good:1a2b3c4d,nocolon,bad rev:zzzzzzzz,short:1a2b,:1a2b3c4d")
        assert parsed == {"good": "1a2b3c4d"}
        for junk in ("", None, 7, "x" * (console_feed.MAX_HAVE + 1)):
            assert console_feed.parse_have(junk) == {}

    def test_it_is_bounded(self):
        many = ",".join(f"s{index}:1a2b3c4d" for index in range(200))
        assert len(console_feed.parse_have(many)) <= console_feed.MAX_SECTIONS

    def test_the_shape_asked_for_is_brought_into_range(self):
        assert console_feed.clean_proto(2) == console_feed.PROTO
        assert console_feed.clean_proto(99) == console_feed.PROTO
        assert console_feed.clean_proto(0) == console_feed.MIN_PROTO
        assert console_feed.clean_proto("nonsense") == console_feed.MIN_PROTO


SECTIONS = {"managed": [{"id": "aa"}], "jobs": [], "host": {"os": "linux"}}


class TestTwoVersionsAtOnce:
    def test_a_reader_that_knows_nothing_gets_the_shape_it_always_got(self):
        """The case this is for: a page from before an update, against a node
        from after one."""
        answer = console_feed.build(SECTIONS, proto=1)
        assert answer["managed"] == SECTIONS["managed"]
        assert answer["host"] == SECTIONS["host"]
        assert "sections" not in answer and "revs" not in answer

    def test_every_answer_says_who_spoke(self):
        for proto in (1, 2):
            answer = console_feed.build(SECTIONS, proto=proto)
            assert answer["build"] == __version__
            assert answer["proto"] == proto

    def test_a_reader_holding_nothing_gets_everything(self):
        answer = console_feed.build(SECTIONS, proto=2)
        assert answer["full"] is True
        assert set(answer["sections"]) == set(SECTIONS)
        assert set(answer["revs"]) == set(SECTIONS)

    def test_a_reader_that_is_up_to_date_gets_nothing_back(self):
        first = console_feed.build(SECTIONS, proto=2)
        have = ",".join(f"{name}:{rev}" for name, rev in first["revs"].items())
        again = console_feed.build(SECTIONS, have=have, proto=2)
        assert again["sections"] == {}
        assert again["full"] is False
        assert again["revs"] == first["revs"]

    def test_only_the_section_that_moved_comes_back(self):
        first = console_feed.build(SECTIONS, proto=2)
        have = ",".join(f"{name}:{rev}" for name, rev in first["revs"].items())
        moved = dict(SECTIONS, jobs=[{"rid": "x"}])
        answer = console_feed.build(moved, have=have, proto=2)
        assert set(answer["sections"]) == {"jobs"}
        assert answer["revs"]["managed"] == first["revs"]["managed"]

    def test_a_revision_we_do_not_recognise_gets_the_section(self):
        answer = console_feed.build(SECTIONS, have="managed:deadbeef", proto=2)
        assert "managed" in answer["sections"]

    def test_what_is_not_a_section_always_travels(self):
        """The log is read by sequence rather than by revision — it is already
        incremental, and holding it back would hold back the one thing that is
        different every time."""
        answer = console_feed.build(SECTIONS, proto=2,
                                    extra={"log": [1], "log_seq": 4})
        assert answer["log"] == [1] and answer["log_seq"] == 4
        assert "log" not in answer["sections"]

    def test_a_delta_is_smaller_than_the_thing_it_replaces(self):
        """The point of the exercise: a ledger re-sent because one job finished
        is most of what a console costs."""
        big = {"managed": [{"id": f"{index:040x}", "caps": ["status"],
                            "label": "machine"} for index in range(60)],
               "jobs": []}
        whole = console_feed.build(big, proto=2)
        have = ",".join(f"{name}:{rev}" for name, rev in whole["revs"].items())
        moved = dict(big, jobs=[{"rid": "x"}])
        delta = console_feed.build(moved, have=have, proto=2)
        assert len(json.dumps(delta)) * 4 < len(json.dumps(whole))
