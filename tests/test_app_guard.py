"""
What an app uses to hold a peer to its own thresholds.

Chat is the case this exists for. It is the most exposed application on a node —
any authenticated member can send it anything, unasked — and it had size bounds
on every field and no rate limit at all: one member could hold the receive loop
with profile updates for as long as it liked, and nothing anywhere counted.

The tests below are mostly about the *shape* of the limits rather than their
numbers. The numbers are the app's to choose; that they are per kind, that a
breach is reported once rather than per message, and that reporting can never
break the app that noticed, are not.
"""
import asyncio

import pytest

from src.app_guard import AppGuard, Limit
from src.apps.chat import ChatApp, _KINDS, _LIMITS
from src.node_id import NodeID


class _Client:
    """A connector client that records reports instead of sending them."""

    def __init__(self, *, broken: bool = False) -> None:
        self.reports = []
        self._broken = broken

    async def report_abuse(self, node, weight=1, *, kind=0, reason="") -> None:
        if self._broken:
            raise ConnectionError("connector is gone")
        self.reports.append((bytes(node.raw), weight, kind, reason))

    async def close(self) -> None: ...


def _guard(client, limits=None, **kwargs):
    jobs = []

    def spawn(coro):
        jobs.append(coro)

    guard = AppGuard(client, limits or {"messages": Limit(3, 10.0)},
                     spawn=spawn, **kwargs)
    return guard, jobs


async def _drain(jobs):
    for coro in jobs:
        await coro
    jobs.clear()


class TestTheAllowance:
    async def test_it_allows_up_to_the_ceiling_then_reports_once(self):
        """Once per spent window, not per refused message: a peer flooding at
        ten thousand a second must not make us call the node ten thousand
        times."""
        client = _Client()
        guard, jobs = _guard(client)
        sender = NodeID.generate()
        results = [guard.allow("messages", sender, now=0.0) for _ in range(50)]
        await _drain(jobs)
        assert results[:3] == [True, True, True]
        assert not any(results[3:])
        assert len(client.reports) == 1
        assert client.reports[0][3] == "too many messages"

    async def test_the_window_moves_on_and_so_does_the_report(self):
        client = _Client()
        guard, jobs = _guard(client)
        sender = NodeID.generate()
        for _ in range(6):
            guard.allow("messages", sender, now=0.0)
        assert guard.allow("messages", sender, now=100.0) is True
        for _ in range(6):
            guard.allow("messages", sender, now=100.0)
        await _drain(jobs)
        assert len(client.reports) == 2

    async def test_one_sender_does_not_spend_another_s_allowance(self):
        client = _Client()
        guard, jobs = _guard(client)
        a, b = NodeID.generate(), NodeID.generate()
        for _ in range(6):
            guard.allow("messages", a, now=0.0)
        assert guard.allow("messages", b, now=0.0) is True
        await _drain(jobs)
        assert len(client.reports) == 1
        assert client.reports[0][0] == a.raw

    async def test_a_kind_with_no_declared_limit_is_not_gated(self):
        """An app gates what it chose to gate. Silently refusing everything
        else would make adding a message type a way to break the app."""
        client = _Client()
        guard, _jobs = _guard(client)
        sender = NodeID.generate()
        assert all(guard.allow("something else", sender, now=0.0)
                   for _ in range(100))
        assert client.reports == []

    async def test_the_kinds_do_not_share_a_bucket(self):
        """The whole reason this is a table and not one rate gate: a typing
        notice and a file offer are not comparable, and one shared ceiling has
        to be set for the loudest of them."""
        client = _Client()
        guard, jobs = _guard(client, {"cheap": Limit(100, 10.0),
                                      "costly": Limit(2, 10.0)})
        sender = NodeID.generate()
        for _ in range(50):
            assert guard.allow("cheap", sender, now=0.0) is True
        assert guard.allow("costly", sender, now=0.0) is True
        assert guard.allow("costly", sender, now=0.0) is True
        assert guard.allow("costly", sender, now=0.0) is False
        await _drain(jobs)
        assert [reason for _n, _w, _k, reason in client.reports] == \
            ["too many costly"]

    async def test_the_weight_follows_the_kind(self):
        """Flooding text might be a stuck client; flooding group invitations is
        not something a correct one does at all."""
        client = _Client()
        guard, jobs = _guard(client, {"rude": Limit(1, 10.0),
                                      "telling": Limit(1, 10.0, weight=3)})
        sender = NodeID.generate()
        for kind in ("rude", "rude", "telling", "telling"):
            guard.allow(kind, sender, now=0.0)
        await _drain(jobs)
        assert sorted(weight for _n, weight, _k, _r in client.reports) == [1, 3]


class TestReportingIsNeverFatal:
    async def test_a_broken_connector_does_not_break_the_app(self):
        """An app that noticed a problem must not become one."""
        client = _Client(broken=True)
        guard, jobs = _guard(client)
        sender = NodeID.generate()
        for _ in range(6):
            assert guard.allow("messages", sender, now=0.0) in (True, False)
        with pytest.raises(ConnectionError):
            await _drain(jobs)      # the failure is the job's, not the caller's

    async def test_a_client_that_cannot_report_at_all_is_fine(self):
        class _Mute:
            pass
        guard = AppGuard(_Mute(), {"messages": Limit(1, 10.0)})
        sender = NodeID.generate()
        assert guard.allow("messages", sender, now=0.0) is True
        assert guard.allow("messages", sender, now=0.0) is False

    async def test_nowhere_to_run_the_report_is_not_a_stray_coroutine(self):
        """One nobody awaits is a warning at collection time, from a line with
        nothing to do with it."""
        client = _Client()
        guard = AppGuard(client, {"messages": Limit(1, 10.0)}, spawn=None)
        sender = NodeID.generate()
        guard.allow("messages", sender, now=0.0)
        guard.allow("messages", sender, now=0.0)
        assert client.reports == []      # closed, not leaked


class TestChatIsFullyCovered:
    def test_every_message_type_draws_on_a_declared_limit(self):
        """A type added without a limit is a flood nobody counts. This is the
        test that keeps the table honest as chat grows."""
        from src.apps.chat import _HANDLERS
        for mtype in _HANDLERS:
            assert mtype in _KINDS, f"message type {mtype:#x} has no limit"
            assert _KINDS[mtype] in _LIMITS

    def test_the_expensive_kinds_are_the_tight_ones(self):
        """Sized per kind means the rare-and-costly actually get a low ceiling
        — which is exactly what one shared bucket could never give them."""
        assert _LIMITS["file offers"].max_events < _LIMITS["messages"].max_events
        assert _LIMITS["profile updates"].max_events < _LIMITS["messages"].max_events
        assert _LIMITS["group invitations"].max_events < _LIMITS["messages"].max_events
        # …and real-time media is not throttled into a broken call.
        assert _LIMITS["call frames"].max_events > 1000

    async def test_chat_drops_a_flood_and_tells_the_node(self):
        client = _Client()
        app = ChatApp(client, node_id=NodeID.generate())
        sender = NodeID.generate()
        payload = bytes([0x05]) + b"\x00\x00\x00\x00"     # a profile update
        try:
            for _ in range(40):
                app._dispatch(sender, payload)
            await asyncio.sleep(0)
            assert len(client.reports) == 1
            assert client.reports[0][3] == "too many profile updates"
        finally:
            await app.stop()

    async def test_an_ordinary_conversation_is_never_reported(self):
        """The failure that would matter most: a limit low enough to fire on
        somebody typing."""
        client = _Client()
        app = ChatApp(client, node_id=NodeID.generate())
        sender = NodeID.generate()
        text = bytes([0x01]) + b"\x00" * 32 + b"hello"
        try:
            for _ in range(30):
                app._dispatch(sender, text)
            await asyncio.sleep(0)
            assert client.reports == []
        finally:
            await app.stop()
