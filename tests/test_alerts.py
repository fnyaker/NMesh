"""
The notice board: what is wrong here, in one sentence each.

Written from the decision rather than from `src/alerts.py`. A log records
everything and is off until somebody asks; this records the handful of things
worth telling a person and is **always on**, because the conditions worth waking
an operator for are exactly the ones nobody had the foresight to start recording.

That makes it a surface an adversary can write to — through a peer that
misbehaves, or through an app on this machine — so the questions here are the
ones that keep it readable: is a flood one line or a thousand, does a warning
push out an error, can one app post as another, and can any of it make the node
act on its own.
"""
import pytest

from src import alerts
from src.alerts import AlertBook


class TestOneEntryPerProblem:
    def test_a_flood_is_one_line_with_a_count(self):
        """Three hundred refused handshakes are a sentence an operator can act
        on. Three hundred rows are a wall somebody else chose the contents of."""
        book = AlertBook()
        for _ in range(300):
            book.raise_alert("handshake", "handshakes refused",
                             level=alerts.ERROR)
        status = book.status()
        assert status["count"] == 1
        assert status["alerts"][0]["count"] == 300

    def test_the_first_time_is_kept_as_well_as_the_last(self):
        moment = [1000.0]
        book = AlertBook(clock=lambda: moment[0])
        book.raise_alert("k", "something")
        moment[0] = 2000.0
        book.raise_alert("k", "something")
        [entry] = book.alerts()
        assert entry["first"] == 1000.0 and entry["at"] == 2000.0

    def test_a_problem_that_comes_back_is_news_again(self):
        book = AlertBook()
        book.raise_alert("k", "something")
        book.acknowledge("k")
        assert book.status()["unread"] == 0
        book.raise_alert("k", "something")
        assert book.status()["unread"] == 1


class TestTheBoardStaysReadable:
    def test_it_is_bounded(self):
        book = AlertBook()
        for number in range(alerts.MAX_ALERTS * 3):
            book.raise_alert(f"k{number}", "something")
        assert book.status()["count"] == alerts.MAX_ALERTS

    def test_a_chatty_warning_never_pushes_out_an_error(self):
        """Evicting by age alone is the obvious implementation and the wrong
        one: the board would empty itself of exactly what it is for."""
        book = AlertBook()
        book.raise_alert("the-error", "something broke", level=alerts.ERROR)
        for number in range(alerts.MAX_ALERTS * 2):
            book.raise_alert(f"noise{number}", "a warning", level=alerts.WARN)
        keys = [entry["key"] for entry in book.alerts()]
        assert "the-error" in keys

    def test_worst_first_then_newest(self):
        moment = [1000.0]
        book = AlertBook(clock=lambda: moment[0])
        book.raise_alert("old-error", "one", level=alerts.ERROR)
        moment[0] = 2000.0
        book.raise_alert("new-warning", "two", level=alerts.WARN)
        moment[0] = 3000.0
        book.raise_alert("new-error", "three", level=alerts.ERROR)
        assert [entry["key"] for entry in book.alerts()] == [
            "new-error", "old-error", "new-warning"]

    def test_every_axis_is_bounded(self):
        book = AlertBook()
        book.raise_alert("k" * 500, "s" * 500, detail="d" * 2000,
                         source="x" * 500, node="n" * 200)
        [entry] = book.alerts()
        assert len(entry["key"]) <= alerts.MAX_KEY
        assert len(entry["summary"]) <= alerts.MAX_SUMMARY
        assert len(entry["detail"]) <= alerts.MAX_DETAIL
        assert len(entry["source"]) <= alerts.MAX_SOURCE

    def test_raising_never_raises(self):
        class _Awkward:
            def __str__(self):
                raise RuntimeError("no")

        book = AlertBook()
        # No key at all falls back to the summary, which is still a name for
        # the problem; nothing at all is refused rather than filed under "".
        assert book.raise_alert("", "no key at all")["key"] == "no key at all"
        assert book.raise_alert("", "") is None
        book.raise_alert("k", _Awkward())            # must not raise
        book.raise_alert(_Awkward(), "s")            # must not raise

    def test_an_unknown_level_is_a_warning_rather_than_a_dropped_notice(self):
        book = AlertBook()
        book.raise_alert("k", "s", level="catastrophic")
        assert book.alerts()[0]["level"] == alerts.WARN


class TestSeenIsNotGone:
    def test_acknowledging_keeps_the_row(self):
        """"Is it still happening?" is a question about the count, not about
        whether somebody dismissed it."""
        book = AlertBook()
        book.raise_alert("k", "something")
        assert book.acknowledge("k") is True
        assert book.status()["count"] == 1
        assert book.status()["unread"] == 0
        assert book.alerts(unacknowledged=True) == []

    def test_dropping_forgets_one_or_all(self):
        book = AlertBook()
        book.raise_alert("a", "one")
        book.raise_alert("b", "two")
        assert book.drop("a") == 1
        assert book.drop("nonesuch") == 0
        assert book.drop() == 1
        assert book.status()["count"] == 0

    def test_acknowledging_something_that_is_not_there(self):
        assert AlertBook().acknowledge("nonesuch") is False


class TestTheNodeRaisesItsOwn:
    async def test_a_peer_this_node_stops_enduring_lands_on_the_board(self):
        """The condition an operator most wants to be told about without having
        started a recording first."""
        from src.node import MeshNode
        from src.node_id import NodeID
        from tests.conftest import make_manager

        node = MeshNode(transport_manager=make_manager())
        try:
            peer = NodeID.generate()
            for _ in range(50):
                node.report_abuse(peer, 1.0, "protocol violations")
            board = node.alerts.alerts()
            assert board, "a peer crossing a threshold said nothing"
            assert board[0]["node"] == peer.raw.hex()
            assert board[0]["source"] == "peers"
        finally:
            await node.stop()

    async def test_the_board_never_acts_on_anything(self):
        """An alert is a sentence for a human. What acts on a peer is the
        reputation book, on what this node saw itself."""
        import ast
        import inspect

        # The *code*, with the prose stripped out: this file explains what it
        # deliberately does not do, and a test that cannot tell an explanation
        # from a call is a test that fails on its own documentation.
        tree = ast.parse(inspect.getsource(alerts))
        called = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                target = node.func
                called.add(getattr(target, "attr", None)
                           or getattr(target, "id", ""))
        for forbidden in ("report_abuse", "_tarpit", "disconnect", "send",
                          "open", "write"):
            assert forbidden not in called, (
                f"the notice board does something ({forbidden}) — it is a "
                "sentence for a person, not a decision")

    async def test_a_node_with_a_problem_says_so_in_its_snapshot(self):
        from src.node import MeshNode
        from tests.conftest import make_manager

        node = MeshNode(transport_manager=make_manager())
        try:
            node.alert("disk", "the state directory is full",
                       level=alerts.ERROR, detail="0 bytes free")
            snapshot = await node.console_snapshot()
            assert snapshot["alerts"]["unread"] == 1
            assert snapshot["alerts"]["worst"] == alerts.ERROR
        finally:
            await node.stop()


class TestDrivenFromAConsole:
    async def _chan(self):
        import asyncio

        from src import control
        from src.node import MeshNode
        from tests.conftest import make_manager

        node = MeshNode(transport_manager=make_manager())
        context = control.Context(node=node, loop=asyncio.get_running_loop())
        return node, control.LocalChannel(control.build(context))

    async def test_the_board_is_read_acknowledged_and_dropped(self):
        node, chan = await self._chan()
        try:
            node.alert("disk", "the state directory is full",
                       level=alerts.ERROR)
            assert chan.call("alerts.list").result["count"] == 1
            assert chan.call("alerts.list",
                             {"unread": True}).result["alerts"][0]["key"] == "disk"
            assert chan.call("alerts.ack", {"key": "disk"}).result["unread"] == 0
            assert chan.call("alerts.list",
                             {"unread": True}).result["alerts"] == []
            assert chan.call("alerts.drop", {"key": "disk"}).result["count"] == 0
        finally:
            await node.stop()

    async def test_every_operation_travels(self):
        """A node that has a problem is exactly the node nobody is sitting in
        front of."""
        from src.control.modules.alerts import AlertsModule

        assert all(op["reach"] == "remote" for op in AlertsModule.OPERATIONS)


class TestAnAppMaySayWhatIsWrongWithItself:
    async def test_the_node_attributes_the_notice(self):
        """Only chat knows what "too many failed uploads" means for chat — and
        only the node decides what the board says an app is called."""
        from src.app_channel import GENERIC_APP_ID, builtin_id
        from src.data_connector import DataConnector, ConnectorClient
        from tests.conftest import make_node
        import asyncio

        node, _fake = await make_node()
        conn = DataConnector(node, host="127.0.0.1", port=0, token="tok")
        await conn.start()
        one = ConnectorClient(conn._host, conn.port, "tok", GENERIC_APP_ID)
        two = ConnectorClient(conn._host, conn.port, "tok", builtin_id("chat"))
        await one.connect()
        await two.connect()
        try:
            await one.notify("uploads", "too many failed uploads",
                             level="error", detail="12 in a minute")
            await two.notify("uploads", "a different app's problem")
            deadline = asyncio.get_event_loop().time() + 2.0
            while (node.alerts.status()["count"] < 2
                   and asyncio.get_event_loop().time() < deadline):
                await asyncio.sleep(0.01)
            board = node.alerts.alerts()
            assert len(board) == 2, "one app's notice overwrote another's"
            sources = {entry["source"] for entry in board}
            assert sources == {f"app:{GENERIC_APP_ID.hex()[:16]}",
                               f"app:{builtin_id('chat').hex()[:16]}"}
            assert all(entry["key"].startswith("app:") for entry in board)
        finally:
            await one.close()
            await two.close()
            await conn.stop()
            await node.stop()

    async def test_a_malformed_notice_costs_the_notice_and_not_the_link(self):
        from src.app_channel import GENERIC_APP_ID
        from src.data_connector import (DataConnector, _read_frame,
                                        _write_frame, _AUTH, _AUTH_OK, _NOTIFY,
                                        _WHOAMI, _WHOAMI_RESP)
        from tests.conftest import make_node
        import asyncio

        node, _fake = await make_node()
        conn = DataConnector(node, host="127.0.0.1", port=0, token="tok")
        await conn.start()
        reader, writer = await asyncio.open_connection(conn._host, conn.port)
        try:
            await _write_frame(writer, _AUTH, GENERIC_APP_ID + b"tok")
            assert (await _read_frame(reader))[0] == _AUTH_OK
            for body in (b"", b"w", b"w\xff", b"w\x02z", b"w\x00not json",
                         b"e\x01k[1,2]", b"\xff\xfe" * 8):
                await _write_frame(writer, _NOTIFY, body)
            # Still serving: the connection survived every one of them.
            await _write_frame(writer, _WHOAMI, b"")
            ftype, _body = await asyncio.wait_for(_read_frame(reader), 2.0)
            assert ftype == _WHOAMI_RESP
        finally:
            writer.close()
            await conn.stop()
            await node.stop()

    async def test_a_notice_is_answered_by_nothing(self):
        """Like an abuse report: a reply would let an app read the node's state
        back, and what else is wrong with this machine is the operator's."""
        from src.data_connector import ConnectorClient

        source = ConnectorClient.notify.__doc__ or ""
        assert "answered by nothing" in source


class TestThePageShowsItWithoutDecidingAnything:
    def test_the_console_renders_the_board_from_the_snapshot(self):
        from src import webassets

        assert 'id="alerts-card"' in webassets.INDEX_HTML
        block = webassets.APP_JS.split("// ---- what wants attention")[1]
        block = block.split("// The rail is hidden")[0]
        # Read from the snapshot, acted on through the plane — not through a
        # route of its own, which is what every new surface used to grow.
        assert "state.alerts" in block
        assert 'CHANNEL.ask(seen ? "alerts.ack" : "alerts.drop"' in block
        assert "/api/" not in block

    def test_the_count_is_of_problems_rather_than_of_occurrences(self):
        """The label and the number are one claim: "3 times" belongs on the
        row, and the badge counts rows."""
        from src import webassets

        block = webassets.APP_JS.split("// ---- what wants attention")[1]
        assert "alert.count > 1" in block
        assert "board.unread" in block
