"""
The log, driven from a console — including one four hops away.

The whole reason the reader is shaped as "everything after a sequence number"
is that it has to work over a channel carrying one bounded question and its
answer. So these are the questions an operator's page asks, put to the plane
rather than to `LogBook`: is anything kept, keep some, stop, size it, read it,
follow it.

Two decisions are held here rather than in `test_logbook.py` because they are
decisions about the *product*:

* turning the trace on turns the log on with it — what crossed the wire and
  what the node thought while it crossed are two halves of one answer;
* what an app may read is the registry's answer (`apps.grant`), and it is a
  different decision from whether the app runs at all.
"""
import asyncio

import pytest

from src import control
from src import logbook
from src.app_registry import AppRegistry, GRANTS
from src.logbook import LogBook
from src.trace import Trace


class _Node:
    """Enough node for the module, and nothing that could answer for it."""

    def __init__(self):
        self.logs = LogBook()
        # The real one. A hand-rolled trace is a double missing whichever
        # keyword the module passes, and the failure reads as the module's.
        self.trace = Trace()
        self.pseudo = ""


def _chan(node):
    return control.LocalChannel(control.build(
        control.Context(node=node, loop=asyncio.get_event_loop())))


class TestTheSwitchIsTheOperatorsRatherThanTheCodes:
    async def test_nothing_is_kept_until_the_plane_is_told_to(self):
        node = _Node()
        chan = _chan(node)
        node.logs.record("node", "before")
        assert chan.call("logs.status").result["running"] is False
        assert chan.call("logs.status").result["records"] == 0

        assert chan.call("logs.set", {"action": "start"}).result["running"]
        node.logs.record("node", "after")
        assert chan.call("logs.status").result["records"] == 1

    async def test_stopping_through_the_plane_drops_the_ring(self):
        node = _Node()
        chan = _chan(node)
        chan.call("logs.set", {"action": "start"})
        node.logs.record("node", "a line")
        answer = chan.call("logs.set", {"action": "stop"}).result
        assert answer["running"] is False and answer["records"] == 0

    async def test_a_size_can_be_set_before_it_is_turned_on(self):
        """The order anybody would use: size the ring, then start it."""
        node = _Node()
        chan = _chan(node)
        answer = chan.call("logs.set",
                           {"action": "resize", "megabytes": 2}).result
        assert answer["running"] is False
        assert answer["megabytes"] == 2.0
        assert chan.call("logs.set", {"action": "start"}).result["megabytes"] == 2.0

    async def test_starting_without_a_size_leaves_the_size_alone(self):
        node = _Node()
        chan = _chan(node)
        chan.call("logs.set", {"action": "resize", "megabytes": 3})
        chan.call("logs.set", {"action": "stop"})
        assert chan.call("logs.set", {"action": "start"}).result["megabytes"] == 3.0

    async def test_a_size_nobody_should_be_allowed_to_ask_for_is_refused(self):
        node = _Node()
        chan = _chan(node)
        ceiling = logbook.MAX_BYTES // 1024 // 1024
        # A count with a limit is *clamped* rather than refused, because the
        # thing bounded owns the bound (`src/control/params.py`) — what must
        # never happen is the ring growing to what was asked for.
        answer = chan.call("logs.set",
                           {"action": "start", "megabytes": ceiling * 10}).result
        assert answer["megabytes"] == float(ceiling)
        # A negative size is not a size: a count floors at zero and zero means
        # "leave it alone", so nothing an operator can type here makes a ring
        # smaller than the module's own floor.
        assert chan.call("logs.set",
                         {"action": "start", "megabytes": -1}
                         ).result["megabytes"] == float(ceiling)
        assert chan.call("logs.set", {"action": "burn"}).ok is False
        assert chan.call("logs.set", {"action": "start",
                                      "megabytes": "lots"}).ok is False

    async def test_clearing_keeps_it_running(self):
        node = _Node()
        chan = _chan(node)
        chan.call("logs.set", {"action": "start"})
        node.logs.record("node", "a line")
        answer = chan.call("logs.set", {"action": "clear"}).result
        assert answer["running"] is True and answer["records"] == 0


class TestReadingItFromAConsole:
    def _ready(self):
        node = _Node()
        chan = _chan(node)
        chan.call("logs.set", {"action": "start"})
        node.logs.record("node", "a link died", level=logbook.WARN, topic="link")
        node.logs.record("app:beef", "hello", topic="chat")
        return node, chan

    async def test_the_question_a_person_asks(self):
        _node, chan = self._ready()
        answer = chan.call("logs.query").result
        assert answer["matched"] == 2
        assert answer["lines"][0]["seq"] == 2        # newest first
        assert chan.call("logs.query",
                         {"level": "warn"}).result["matched"] == 1
        assert chan.call("logs.query",
                         {"contains": "hello"}).result["matched"] == 1

    async def test_the_question_a_subscriber_asks(self):
        node, chan = self._ready()
        seen = chan.call("logs.since").result["seq"]
        node.logs.record("node", "and then this")
        answer = chan.call("logs.since", {"seq": seen}).result
        assert answer["returned"] == 1
        assert answer["lines"][0]["message"] == "and then this"
        assert answer["lost"] == 0

    async def test_a_filter_can_only_offer_names_that_exist(self):
        _node, chan = self._ready()
        assert chan.call("logs.sources").result["sources"] == ["app:beef", "node"]

    async def test_a_reply_is_bounded_however_much_is_asked_for(self):
        node, chan = self._ready()
        for _ in range(logbook.MAX_QUERY * 2):
            node.logs.record("node", "more")
        for asked in (10 ** 9, logbook.MAX_QUERY, 0):
            answer = chan.call("logs.query", {"limit": asked}).result
            assert answer["returned"] == logbook.MAX_QUERY
            assert answer["matched"] > logbook.MAX_QUERY

    async def test_a_node_with_no_book_is_a_refusal_rather_than_a_crash(self):
        class _Bare:
            logs = None
            trace = Trace()

        chan = _chan(_Bare())
        assert chan.call("logs.status").ok is False


class TestOneSwitchForBothRecordings:
    async def test_starting_the_trace_starts_the_log(self):
        node = _Node()
        chan = _chan(node)
        chan.call("trace.set", {"action": "start"})
        assert node.logs.status()["running"] is True
        chan.call("trace.set", {"action": "stop"})
        assert node.logs.status()["running"] is False

    async def test_the_log_can_still_be_kept_on_its_own(self):
        """The case the shared switch cannot express: a node whose packet
        headers you have no business recording, whose lines you still want."""
        node = _Node()
        chan = _chan(node)
        chan.call("logs.set", {"action": "start"})
        assert node.logs.status()["running"] is True
        assert node.trace.status()["running"] is False

    async def test_a_node_that_cannot_keep_a_log_still_traces(self):
        class _NoBook:
            logs = None
            trace = Trace()

        node = _NoBook()
        chan = _chan(node)
        assert chan.call("trace.set", {"action": "start"}).ok is True
        assert node.trace.status()["running"] is True


class TestWhatAnAppMayRead:
    def _console(self, tmp_path):
        from src.app_registry import AppHost

        registry = AppRegistry(str(tmp_path))
        host = AppHost(registry)
        context = control.Context(node=_Node(), loop=asyncio.get_event_loop(),
                                  apps=host.overview, host=lambda: host)
        return registry, control.LocalChannel(control.build(context))

    async def test_a_grant_is_given_and_taken_back_through_the_plane(self, tmp_path):
        registry, chan = self._console(tmp_path)
        answer = await asyncio.to_thread(
            chan.call, "apps.grant",
            {"app": "fleet", "capability": "logs", "granted": True})
        assert answer.ok is True
        assert registry.granted("fleet", "logs") is True
        # The list comes back with it, so a page that just toggled a grant does
        # not have to ask a second question that could disagree.
        fleet = next(app for app in answer.result["apps"] if app["id"] == "fleet")
        assert [grant["granted"] for grant in fleet["grants"]] == [True]

        await asyncio.to_thread(
            chan.call, "apps.grant",
            {"app": "fleet", "capability": "logs", "granted": False})
        assert registry.granted("fleet", "logs") is False

    async def test_only_a_declared_capability_and_a_real_app(self, tmp_path):
        registry, chan = self._console(tmp_path)
        bad = await asyncio.to_thread(
            chan.call, "apps.grant",
            {"app": "fleet", "capability": "root", "granted": True})
        assert bad.ok is False
        missing = await asyncio.to_thread(
            chan.call, "apps.grant",
            {"app": "nonesuch", "capability": "logs", "granted": True})
        assert missing.ok is False and missing.code == "bad_request"

    def test_every_grant_the_registry_declares_is_offered_by_the_plane(self):
        """Two lists, and two lists are two chances to drift: an operator
        cannot grant what the plane will not name."""
        from src.control.modules.apps import AppsModule

        declared = next(op for op in AppsModule.OPERATIONS
                        if op["name"] == "grant")
        choices = next(p for p in declared["params"]
                       if p["name"] == "capability")["choices"]
        assert tuple(grant["name"] for grant in GRANTS) == tuple(choices)
