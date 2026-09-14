"""
A plug-in must not be able to break the node it plugs into.

Anyone implements ``BaseTransport`` + ``BaseServer`` and registers it by URL
scheme; anyone writes an app and the host starts it. That is the third
principle, and it means the core runs beside code it has never seen — some of it
written badly, some of it written by somebody who wants this node to stop.

The core already wrapped most of those calls in ``try``. That is half the job.
The half these tests are about is the other one: **it guarded the call and
trusted the answer.** `remote_ip` is annotated ``str | None``, so the code did
``remote.encode(...)``; `idle_timeout` is annotated ``float | None``, so the
code did ``timeout <= 0``; `receive` is annotated ``Packet``, so the loop did
``len(packet.payload)`` — outside its own guard. An annotation is a note between
people who agree, and a hostile implementation is not disagreeing with it. It is
simply not bound by it.

So: three transports that answer wrongly in three different ways, a server that
does the same, and an app factory that does not return what it said it would.
The node has to keep running, keep serving, and keep being *readable* — a
console that goes dark is how the operator finds out, and by then it is too
late.
"""
import asyncio

import pytest

from src import medium
from src.app_registry import AppHost, AppRegistry
from src.node import MeshNode, PING
from src.packet import Packet
from src.node_id import NodeID
from src.transport import BaseTransport, BaseServer
from src.transport_manager import TransportManager
from tests.conftest import FakeTransport, FakeServer, make_manager

pytestmark = pytest.mark.asyncio


# ---------------------------------------------------------------------------
# Three ways for a medium to be wrong
# ---------------------------------------------------------------------------

class ThrowingTransport(FakeTransport):
    """Answers every optional question with an exception."""

    def remote_ip(self):
        raise RuntimeError("no")

    def endpoints(self):
        raise RuntimeError("no")

    def idle_timeout(self):
        raise RuntimeError("no")

    def stats(self):
        raise RuntimeError("no")


class LyingTransport(FakeTransport):
    """Answers every optional question with the wrong type.

    Not malice, necessarily: this is what a half-finished transport looks like,
    and the node cannot tell the difference anyway."""

    def remote_ip(self):
        return 4242

    def endpoints(self):
        return ["local", "remote"]

    def idle_timeout(self):
        return "soon"

    def stats(self):
        return [("not", "a dict")]


class FloodingTransport(FakeTransport):
    """Answers with things that are the right type and far too large."""

    def remote_ip(self):
        return "9" * 100_000

    def endpoints(self):
        return {"local": "x" * 100_000, "remote": "y" * 100_000}

    def idle_timeout(self):
        return float("inf")

    def stats(self):
        return {("k" * 500): ("v" * 100_000) for _ in range(1)} | \
               {f"n{i}": i for i in range(500)}


class BareTransport(BaseTransport):
    """The minimum the interface asks for, and not one method more.

    A perfectly correct transport: `remote_ip`, `endpoints`, `idle_timeout` and
    `stats` are all optional. The first version of `src/medium.py` read the
    attribute *before* entering its own guard, so this one — the honest,
    minimal, documented case — was the one it broke on."""

    async def connect(self, address): ...
    async def listen(self, address): ...
    async def close(self): ...
    async def send(self, packet): ...

    async def receive(self):
        await asyncio.Event().wait()


HOSTILE = [ThrowingTransport, LyingTransport, FloodingTransport]


@pytest.mark.parametrize("kind", HOSTILE + [BareTransport, FakeTransport])
async def test_the_console_still_has_something_to_say(kind):
    """`node.state` is what every page of the console reads first. A medium
    that answers nonsense must not be able to empty it."""
    node = MeshNode(transport_manager=make_manager())
    try:
        await node._inject_peer(kind())
        snapshot = await node.console_snapshot()
        assert snapshot["broken"] == []
        assert snapshot["id"] == node.id.raw.hex()
        assert len(snapshot["peers"]) == 1
    finally:
        await node.stop()


@pytest.mark.parametrize("kind", HOSTILE + [BareTransport])
async def test_every_answer_comes_back_as_what_was_asked_for(kind):
    transport = kind()
    assert medium.remote_ip(transport) is None or \
        isinstance(medium.remote_ip(transport), str)
    ends = medium.endpoints(transport)
    assert set(ends) == {"local", "remote"}
    for value in ends.values():
        assert value is None or isinstance(value, str)
    timeout = medium.idle_timeout(transport)
    assert timeout is None or (isinstance(timeout, float) and timeout > 0)
    assert isinstance(medium.stats(transport), dict)


async def test_what_comes_back_is_bounded_as_well_as_typed():
    """"Bounds everywhere" applies to what a plug-in *returns* exactly as it
    applies to what arrives on a socket — a medium must not be able to put a
    megabyte into a console page, a log line or a counter key."""
    transport = FloodingTransport()
    assert len(medium.remote_ip(transport)) <= medium.MAX_ADDRESS
    for value in medium.endpoints(transport).values():
        assert len(value) <= medium.MAX_ADDRESS
    # An infinite timeout is not a timeout.
    assert medium.idle_timeout(transport) is None
    stats = medium.stats(transport)
    assert len(stats) <= medium.MAX_STATS
    for key, value in stats.items():
        assert len(key) <= medium.MAX_STAT_KEY
        assert not isinstance(value, str) or len(value) <= medium.MAX_STAT_TEXT


async def test_a_lying_medium_does_not_stop_the_keepalive_arithmetic():
    """`_idle_ceiling` divides by whatever the medium says. It used to compare
    it to zero first, which is a `TypeError` on a string — inside the sweep
    that decides when to probe, and a sweep that raises is a node that stops
    noticing dead links."""
    node = MeshNode(transport_manager=make_manager())
    try:
        peer = await node._inject_peer(LyingTransport())
        assert node._idle_ceiling(peer) is None
        assert isinstance(node._keepalive_interval(peer), float)
    finally:
        await node.stop()


# ---------------------------------------------------------------------------
# A medium that hands back something that is not a packet
# ---------------------------------------------------------------------------

class NotAPacketTransport(FakeTransport):
    """`receive()` answers, and what it answers is not a packet.

    Everything after the loop's guard counted its length, traced it and handed
    it to a handler. So this used to raise *outside* that guard, end the task
    with nobody to retrieve the exception, and take the link down without ever
    charging the peer for it."""

    def __init__(self, answers):
        super().__init__()
        self._answers = list(answers)

    async def receive(self):
        if self._answers:
            return self._answers.pop(0)
        return await super().receive()


async def _until(predicate, timeout=2.0):
    loop = asyncio.get_event_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline and not predicate():
        await asyncio.sleep(0.01)
    return predicate()


async def test_a_reply_that_is_not_a_packet_is_charged_not_fatal():
    from src.node import _MAX_MALFORMED

    node = MeshNode(transport_manager=make_manager())
    try:
        junk = [None, "a packet, honest", 7, b"\x00" * 40, object()]
        transport = NotAPacketTransport(junk)
        peer = await node._inject_peer(transport)
        assert await _until(lambda: peer._malformed >= len(junk))
        # Under the threshold: the link is alive and the node still has it.
        assert peer in node._peers and not peer._task.done()
        # And a real packet after all that is still served.
        transport.inject(Packet.create(PING, NodeID.generate().raw,
                                       node.id.raw, b""))
        assert await _until(lambda: peer.counters.as_dict()["pkts_in"] >= 1)
    finally:
        await node.stop()


async def test_a_medium_answering_only_nonsense_gets_cut():
    from src.node import _MAX_MALFORMED

    node = MeshNode(transport_manager=make_manager())
    try:
        transport = NotAPacketTransport([None] * (_MAX_MALFORMED + 5))
        peer = await node._inject_peer(transport)
        assert await _until(lambda: peer not in node._peers)
    finally:
        await node.stop()


# ---------------------------------------------------------------------------
# A server that describes this node wrongly
# ---------------------------------------------------------------------------

class LyingServer(FakeServer):
    def reachability(self, uri, ctx):
        return [1, 2, "three", None, {"ok": True}]


class ThrowingServer(FakeServer):
    def reachability(self, uri, ctx):
        raise RuntimeError("no")


class FloodingServer(FakeServer):
    def reachability(self, uri, ctx):
        return [{"n": i} for i in range(10_000)]


@pytest.mark.parametrize("kind", [LyingServer, ThrowingServer, FloodingServer,
                                  FakeServer])
async def test_a_listener_can_only_contribute_descriptors(kind):
    """Every reader of a descriptor indexes into it — the console, a join
    ticket, the addressing logic. A server answering a list of integers used to
    reach all three."""
    out = medium.reachability(kind(), "fake://here", {})
    assert isinstance(out, list)
    assert len(out) <= medium.MAX_DESCRIPTORS
    assert all(isinstance(entry, dict) for entry in out)


@pytest.mark.parametrize("kind", [LyingServer, ThrowingServer, FloodingServer])
async def test_the_node_still_answers_how_to_reach_it(kind):
    manager = TransportManager()
    manager.register("fake", FakeTransport, kind)
    node = MeshNode(transport_manager=manager)
    try:
        await node.start(["fake://here:1"])
        assert all(isinstance(entry, dict) for entry in node.reachability())
        assert isinstance(node.public_endpoints(), list)
        assert (await node.console_snapshot())["broken"] == []
    finally:
        await node.stop()


# ---------------------------------------------------------------------------
# An app that is not what it said it was
# ---------------------------------------------------------------------------

class _Fine:
    def __init__(self):
        self.started = False

    async def start(self):
        self.started = True

    async def stop(self):
        self.started = False


async def _host(factory, name="chat"):
    registry = AppRegistry()               # nothing persisted: state_dir=None
    registry.set_installed(name, True)
    registry.set_enabled(name, True)
    host = AppHost(registry)
    host.register(name, factory)
    return host


@pytest.mark.parametrize("built", [
    None, 5, "app", (1,), (1, 2, 3), [None, None], object(),
])
async def test_a_factory_that_answers_wrongly_starts_nothing(built):
    """`app, bridge = built` is an unpack, and an unpack of the wrong thing
    raises where nothing catches it — taking `apply()` with it, which on
    start-up is the node."""
    async def factory():
        return built

    host = await _host(factory)
    await host.apply()                     # must not raise
    assert host.running() == set()


async def test_a_factory_that_throws_starts_nothing():
    async def factory():
        raise RuntimeError("no")

    host = await _host(factory)
    await host.apply()
    assert host.running() == set()


async def test_an_app_that_cannot_stop_is_still_let_go_of():
    class _Stuck(_Fine):
        async def stop(self):
            raise RuntimeError("no")

    app = _Stuck()

    async def factory():
        return app, None

    host = await _host(factory)
    await host.apply()
    assert host.running() == {"chat"}
    assert await host.disable("chat") is True
    # An app that will not stop is not an app that keeps running.
    assert host.running() == set()


async def test_a_bridge_that_throws_does_not_stop_the_app():
    class _BadBridge:
        def start(self, loop):
            raise RuntimeError("no")

        def stop(self):
            raise RuntimeError("no")

    app = _Fine()

    async def factory():
        return app, _BadBridge()

    host = await _host(factory)
    host.bind_console(asyncio.get_event_loop())
    await host.apply()
    assert host.running() == {"chat"} and app.started is True
