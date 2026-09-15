"""
An app's side of the log: say things, and — only if granted — read them.

The two halves are deliberately unequal, and these tests are that inequality
written down. Writing a line costs nothing to give away, because the *node*
stamps the source: an app can only ever be quoted as itself. Reading is this
node's whole diary — every other app's lines and the core's — which is a
different question, closed until an operator opens it in the Apps page.

What is checked here is the boundary, not the ring (`test_logbook.py`):

* an app cannot write a line that reads as another app's, or as the core's;
* an app without the grant is **answered** and refused, rather than left
  waiting — a node that says nothing looks exactly like one that has wedged;
* a grant can be taken back, and is taken back by uninstalling;
* a subscriber is pushed lines as they happen, is dropped when it goes away,
  and a slow one costs itself and nobody else.
"""
import asyncio
import json

import pytest

from src import logbook
from src.app_channel import GENERIC_APP_ID, builtin_id
from src.app_registry import GRANTS, AppRegistry
from src.data_connector import (
    DataConnector, ConnectorClient, _read_frame, _write_frame,
    _AUTH, _AUTH_OK, _LOG_WRITE, _LOG_QUERY, _LOG_WATCH, _LOG_LINES,
)
from tests.conftest import make_node

TOKEN = "logs-token"
OTHER = builtin_id("chat")


async def _make(*, grant=True):
    node, _fake = await make_node()
    node.logs.start()
    conn = DataConnector(node, host="127.0.0.1", port=0, token=TOKEN,
                         log_access=lambda app_id: grant)
    await conn.start()
    return node, conn


async def _client(conn, app_id=GENERIC_APP_ID):
    client = ConnectorClient(conn._host, conn.port, TOKEN, app_id)
    await client.connect()
    return client


async def _until(predicate, timeout=2.0):
    deadline = asyncio.get_event_loop().time() + timeout
    while asyncio.get_event_loop().time() < deadline:
        if predicate():
            return True
        await asyncio.sleep(0.01)
    return False


class TestAnAppSpeaksOnlyAsItself:
    async def test_the_node_stamps_the_source(self):
        node, conn = await _make()
        client = await _client(conn)
        try:
            await client.log("something happened", level="warn", topic="boot")
            assert await _until(lambda: node.logs.status()["records"] == 1)
            [line] = node.logs.query()["lines"]
            assert line["source"] == f"app:{GENERIC_APP_ID.hex()[:16]}"
            assert line["message"] == "something happened"
            assert line["level"] == logbook.WARN
            assert line["topic"] == "boot"
        finally:
            await client.close()
            await conn.stop()
            await node.stop()

    async def test_two_apps_cannot_be_confused_with_each_other(self):
        node, conn = await _make()
        one, two = await _client(conn), await _client(conn, OTHER)
        try:
            await one.log("from one")
            await two.log("from two")
            assert await _until(lambda: node.logs.status()["records"] == 2)
            by_source = {line["source"]: line["message"]
                         for line in node.logs.query()["lines"]}
            assert len(by_source) == 2
            assert by_source[f"app:{OTHER.hex()[:16]}"] == "from two"
        finally:
            await one.close()
            await two.close()
            await conn.stop()
            await node.stop()

    async def test_a_malformed_write_costs_the_line_and_not_the_link(self):
        node, conn = await _make()
        reader, writer = await asyncio.open_connection(conn._host, conn.port)
        try:
            await _write_frame(writer, _AUTH, GENERIC_APP_ID + TOKEN.encode())
            assert (await _read_frame(reader))[0] == _AUTH_OK
            for body in (b"", b"\xff", b"i", b"i\xff", b"i\x02z",
                         b"i\x00" + b"\xff\xfe" * 10):
                await _write_frame(writer, _LOG_WRITE, body)
            # The connection is still there and still serving.
            await _write_frame(writer, _LOG_QUERY, b"{}")
            ftype, _body = await asyncio.wait_for(_read_frame(reader), 2.0)
            assert ftype == _LOG_LINES
        finally:
            writer.close()
            await conn.stop()
            await node.stop()


class TestReadingIsAGrant:
    async def test_without_it_a_read_is_answered_and_refused(self):
        """Answered on purpose. A silent drop leaves the app waiting on a reply
        that is never coming, which is indistinguishable from a wedged node."""
        node, conn = await _make(grant=False)
        client = await _client(conn)
        try:
            node.log("a line the app may not read")
            assert (await client.logs_query()).get("refused") is True
            assert (await client.logs_since(0)).get("refused") is True
            assert await client.logs_watch(True) is False
        finally:
            await client.close()
            await conn.stop()
            await node.stop()

    async def test_with_it_the_app_reads_the_whole_diary(self):
        node, conn = await _make()
        client = await _client(conn)
        try:
            node.log("the core said this", topic="core")
            await client.log("and the app said this")
            assert await _until(lambda: node.logs.status()["records"] == 2)
            answer = await client.logs_query()
            assert answer["matched"] == 2
            assert {line["source"] for line in answer["lines"]} == {
                "node", f"app:{GENERIC_APP_ID.hex()[:16]}"}
        finally:
            await client.close()
            await conn.stop()
            await node.stop()

    async def test_the_grant_is_asked_per_frame_not_captured_once(self):
        """An operator who takes a grant back has taken it back now."""
        allowed = [True]
        node, _fake = await make_node()
        node.logs.start()
        conn = DataConnector(node, host="127.0.0.1", port=0, token=TOKEN,
                             log_access=lambda app_id: allowed[0])
        await conn.start()
        client = await _client(conn)
        try:
            assert (await client.logs_query()).get("refused") is None
            allowed[0] = False
            assert (await client.logs_query()).get("refused") is True
        finally:
            await client.close()
            await conn.stop()
            await node.stop()

    async def test_a_check_that_throws_is_a_refusal(self):
        def _angry(_app_id):
            raise RuntimeError("no")

        node, _fake = await make_node()
        node.logs.start()
        conn = DataConnector(node, host="127.0.0.1", port=0, token=TOKEN,
                             log_access=_angry)
        await conn.start()
        client = await _client(conn)
        try:
            assert (await client.logs_query()).get("refused") is True
        finally:
            await client.close()
            await conn.stop()
            await node.stop()

    async def test_no_check_at_all_means_nobody_reads(self):
        """Closed until somebody opens it: a connector built without the
        question answers no to it."""
        node, _fake = await make_node()
        node.logs.start()
        conn = DataConnector(node, host="127.0.0.1", port=0, token=TOKEN)
        await conn.start()
        client = await _client(conn)
        try:
            assert (await client.logs_query()).get("refused") is True
        finally:
            await client.close()
            await conn.stop()
            await node.stop()


class TestSubscribing:
    async def test_a_watcher_is_pushed_lines_as_they_happen(self):
        node, conn = await _make()
        client = await _client(conn)
        try:
            assert await client.logs_watch(True) is True
            node.log("live", topic="now")
            assert await _until(lambda: client.next_log() is not None)
        finally:
            await client.close()
            await conn.stop()
            await node.stop()

    async def test_a_floor_is_a_floor(self):
        node, conn = await _make()
        client = await _client(conn)
        try:
            await client.logs_watch(True, level="warn")
            node.log("chatter", level=logbook.DEBUG)
            node.log("chatter", level=logbook.INFO)
            node.log("trouble", level=logbook.ERROR)
            assert await _until(lambda: client.next_log() is not None)
            # Only the one above the floor was pushed; the chatter was not.
            await asyncio.sleep(0.05)
            assert client.next_log() is None
        finally:
            await client.close()
            await conn.stop()
            await node.stop()

    async def test_unsubscribing_stops_it(self):
        node, conn = await _make()
        client = await _client(conn)
        try:
            await client.logs_watch(True)
            assert await client.logs_watch(False) is False
            node.log("after")
            await asyncio.sleep(0.05)
            assert client.next_log() is None
        finally:
            await client.close()
            await conn.stop()
            await node.stop()

    async def test_a_watcher_that_goes_away_is_forgotten(self):
        """The leak this shape invites: a dict keyed by a socket that nobody
        removes from when the socket dies."""
        node, conn = await _make()
        client = await _client(conn)
        await client.logs_watch(True)
        assert len(conn._log_watchers) == 1
        await client.close()
        try:
            assert await _until(lambda: not conn._log_watchers)
            node.log("nobody is listening")     # must not raise
        finally:
            await conn.stop()
            await node.stop()

    async def test_the_watcher_table_is_bounded(self):
        from src.data_connector import _MAX_CLIENTS

        node, conn = await _make()
        try:
            conn._log_watchers = {object(): "info" for _ in range(_MAX_CLIENTS)}
            client = await _client(conn)
            try:
                assert await client.logs_watch(True) is False
            finally:
                await client.close()
        finally:
            conn._log_watchers = {}
            await conn.stop()
            await node.stop()

    async def test_a_line_recorded_off_the_loop_still_reaches_a_watcher(self):
        """`LogBook.record` is called from console threads as well as from the
        node's loop, and an `asyncio.Queue` is not thread-safe."""
        node, conn = await _make()
        client = await _client(conn)
        try:
            await client.logs_watch(True)
            await asyncio.to_thread(node.log, "from another thread")
            assert await _until(lambda: client.next_log() is not None)
        finally:
            await client.close()
            await conn.stop()
            await node.stop()

    async def test_stopping_the_connector_lets_go_of_the_book(self):
        node, conn = await _make()
        assert node.logs.sink is not None
        await conn.stop()
        try:
            assert node.logs.sink is None
            node.log("after the connector went")     # must not raise
        finally:
            await node.stop()


class TestAnAnswerAlwaysFitsAndIsAlwaysJson:
    async def test_a_huge_ring_still_answers_one_valid_frame(self):
        node, conn = await _make()
        client = await _client(conn)
        try:
            for number in range(logbook.MAX_QUERY):
                node.log("x" * logbook.MAX_MESSAGE, topic="wide")
            answer = await client.logs_query(limit=logbook.MAX_QUERY)
            # Halved until it fits, never truncated mid-object: the client
            # parsed it, and what came back says how much it is.
            assert answer["returned"] == len(answer["lines"])
            assert answer["returned"] < answer["matched"]
        finally:
            await client.close()
            await conn.stop()
            await node.stop()


class TestAFilterIsAnArgumentFromAProcessWeDoNotTrust:
    """An app supplies these, so they are declared, coerced and bounded here
    exactly as the control plane does with an operation's arguments."""

    async def test_nonsense_in_a_filter_costs_neither_the_answer_nor_the_link(self):
        node, conn = await _make()
        client = await _client(conn)
        try:
            node.log("a line")
            for asked in ({"limit": "lots"}, {"limit": None}, {"limit": -5},
                          {"seq": "soon"}, {"since_time": "yesterday"},
                          {"until_time": [1, 2]}, {"level": 7},
                          {"source": {"a": 1}}, {"contains": "x" * 5000},
                          {"topic": "\x00" * 100}, {"unknown": "field"},
                          {"limit": 10 ** 12}):
                answer = await client.logs_query(**asked)
                assert isinstance(answer.get("lines"), list)
                assert answer["returned"] <= logbook.MAX_QUERY
        finally:
            await client.close()
            await conn.stop()
            await node.stop()

    async def test_a_body_that_is_not_a_filter_is_answered_anyway(self):
        node, conn = await _make()
        reader, writer = await asyncio.open_connection(conn._host, conn.port)
        try:
            await _write_frame(writer, _AUTH, GENERIC_APP_ID + TOKEN.encode())
            assert (await _read_frame(reader))[0] == _AUTH_OK
            node.log("a line")
            for body in (b"", b"[]", b"null", b"not json", b"3", b"\xff\xfe",
                         b'{"lines": {"$ne": null}}'):
                await _write_frame(writer, _LOG_QUERY, body)
                ftype, answer = await asyncio.wait_for(_read_frame(reader), 2.0)
                assert ftype == _LOG_LINES
                assert isinstance(json.loads(answer)["lines"], list)
        finally:
            writer.close()
            await conn.stop()
            await node.stop()


class TestTheRegistryIsWhereAGrantLives:
    def test_nothing_is_granted_by_default(self, tmp_path):
        registry = AppRegistry(str(tmp_path))
        for app in registry.overview():
            assert [grant["name"] for grant in app["grants"]] == \
                [grant["name"] for grant in GRANTS]
            assert all(grant["granted"] is False for grant in app["grants"])
            # Named and explained by the node, so a page never holds its own
            # copy of what a grant means.
            assert app["grants"][0]["title"]
            assert app["grants"][0]["description"]
        assert registry.granted("fleet", "logs") is False
        assert registry.granted_to_id(builtin_id("fleet"), "logs") is False

    def test_a_grant_is_given_and_taken_back(self, tmp_path):
        registry = AppRegistry(str(tmp_path))
        assert registry.set_grant("fleet", "logs", True) is True
        assert registry.granted_to_id(builtin_id("fleet"), "logs") is True
        # And it survives a restart, like every other decision an operator made.
        assert AppRegistry(str(tmp_path)).granted("fleet", "logs") is True
        registry.set_grant("fleet", "logs", False)
        assert registry.granted("fleet", "logs") is False

    def test_uninstalling_drops_every_grant(self, tmp_path):
        """A reinstalled app starts from nothing, rather than from what
        somebody allowed the app that used to have that name."""
        registry = AppRegistry(str(tmp_path))
        registry.set_grant("fleet", "logs", True)
        registry.set_installed("fleet", False)
        registry.set_installed("fleet", True)
        assert registry.granted("fleet", "logs") is False

    def test_an_unknown_app_or_capability_is_refused(self, tmp_path):
        registry = AppRegistry(str(tmp_path))
        assert registry.set_grant("nonesuch", "logs", True) is False
        assert registry.set_grant("fleet", "root", True) is False
        assert registry.granted("fleet", "root") is False
        assert registry.granted_to_id(b"", "logs") is False
        assert registry.granted_to_id(b"\x00" * 20, "logs") is False

    def test_a_state_file_can_never_grant_by_being_broken(self, tmp_path):
        """Defaults are what a corrupt file yields, and a default is never a
        grant."""
        (tmp_path / "apps.json").write_text('{"fleet": {"grants": "yes"}}')
        assert AppRegistry(str(tmp_path)).granted("fleet", "logs") is False
        (tmp_path / "apps.json").write_text("not json at all")
        assert AppRegistry(str(tmp_path)).granted("fleet", "logs") is False
