"""
Integration: a refused node's traffic is dropped where it enters, not where it
ends.

A destination that no longer serves a node used to receive everything that node
sent it through relays and drop it last — every relay on the path paid for
traffic the destination had already decided to refuse. Now the destination
drops it on the header, asks the relay that delivered it to stop with a request
it signed itself, and that relay passes the same request back to whoever fed
it. A relay that announced the plane and goes on delivering is charged by the
node that asked — something it saw itself, which is all a charge may stand on.

Real TCP on loopback, real post-quantum keys. Hole punching is off and the
endpoints have no listener, so the relays are the only way through.
"""
import asyncio

import pytest

import src.node as node_mod
from src import MeshNode
from src.transport_manager import TransportManager
from src.tcp_transport import TCPTransport, TCPServer
from tests.integration import free_port

pytestmark = pytest.mark.xdist_group("stop_relay")


def _node() -> MeshNode:
    manager = TransportManager()
    manager.register("tcp", TCPTransport, TCPServer)
    return MeshNode(manager)


async def _until(predicate, seconds: float = 15.0) -> bool:
    for _ in range(int(seconds / 0.05)):
        if predicate():
            return True
        await asyncio.sleep(0.05)
    return predicate()


async def _behind(relay_addr: str, relay: MeshNode) -> MeshNode:
    node = _node()
    await node.start([])
    await node.join(relay_addr, relay.generate_invite())
    await node.wait_for_session(timeout=15.0)
    return node


async def _star(extra: int = 0):
    """sender, target and ``extra`` more, none with a listener, behind one relay."""
    base = free_port()
    relay = _node()
    await relay.start([f"tcp://127.0.0.1:{base}"])
    behind = [await _behind(f"tcp://127.0.0.1:{base}", relay)
              for _ in range(2 + extra)]
    for node in [relay] + behind:
        node._punch_enabled = False
    return [relay] + behind


async def _talking(sender: MeshNode, target: MeshNode) -> None:
    await sender.send_data(target.id, b"hello")
    got = await asyncio.wait_for(target.receive_data(), timeout=15.0)
    assert got == (sender.id, b"hello")


def _refuse(target: MeshNode, sender: MeshNode) -> None:
    """Have ``target`` stop serving ``sender``: one report weighs at most
    `reputation.MAX_WEIGHT`, so it takes a few to cross the line."""
    while not target._reputation.is_suspect(sender.id):
        target.report_abuse(sender.id, 4.0, "test")


async def _keep_sending(sender: MeshNode, target: MeshNode, count: int) -> None:
    for index in range(count):
        await sender.send_data(target.id, b"more %d" % index)
        await asyncio.sleep(0.05)


class TestTheRelayStops:

    async def test_the_destination_drops_and_the_relay_takes_the_rule(self):
        relay, sender, target = await _star()
        try:
            await _talking(sender, target)
            _refuse(target, sender)      # no longer served
            await _keep_sending(sender, target, 5)
            assert await _until(lambda: (sender.id.raw, target.id.raw)
                                in relay._stop_rules)
            # Nothing it sent after that reached the application.
            assert target._data_queue.empty()
            # And the relay now drops it itself: what it forwards stops growing
            # while the sender goes on.
            before = relay._metrics.total.pkts_relayed
            await _keep_sending(sender, target, 10)
            assert relay._metrics.total.pkts_relayed == before
        finally:
            for node in (sender, target, relay):
                await node.stop()

    async def test_a_rule_speaks_only_for_its_destination(self):
        relay, sender, target, bystander = await _star(extra=1)
        try:
            await _talking(sender, target)
            _refuse(target, sender)
            await _keep_sending(sender, target, 5)
            assert await _until(lambda: relay._stop_rules)
            assert all(dst == target.id.raw for _, dst in relay._stop_rules)
            # The same relay still carries the sender to anybody else.
            await _talking(sender, bystander)
        finally:
            for node in (sender, target, bystander, relay):
                await node.stop()


class TestTheRequestGoesBackAlongThePath:

    async def test_two_relays_both_end_up_dropping(self):
        base = free_port(2)
        far, near = _node(), _node()
        await far.start([f"tcp://127.0.0.1:{base}"])
        await near.start([f"tcp://127.0.0.1:{base + 1}"])
        await near.join(f"tcp://127.0.0.1:{base}", far.generate_invite())
        await near.wait_for_session(timeout=15.0)
        sender = await _behind(f"tcp://127.0.0.1:{base}", far)        # sender — far
        target = await _behind(f"tcp://127.0.0.1:{base + 1}", near)   # near — target
        nodes = (sender, target, near, far)
        for node in nodes:
            node._punch_enabled = False

        async def _no_dial(*_args, **_kwargs):
            return None
        # The target must only ever hear the sender through `near`: a link of
        # its own to `far` would let it ask `far` directly, and the test would
        # no longer be about the request travelling back.
        target._dial_uri = _no_dial
        try:
            assert not any(p.authenticated_id == far.id for p in target._peers)
            await _talking(sender, target)
            _refuse(target, sender)
            key = (sender.id.raw, target.id.raw)
            await _keep_sending(sender, target, 5)
            assert await _until(lambda: key in near._stop_rules)
            await _keep_sending(sender, target, 5)
            # `near` was fed by `far`, so `far` got the target's own request —
            # from `near`, since the target holds no link to `far`.
            assert await _until(lambda: key in far._stop_rules)
            assert not any(p.authenticated_id == far.id for p in target._peers)
        finally:
            for node in nodes:
                await node.stop()


class TestARelayThatWillNotStop:

    async def test_it_is_charged_by_the_node_that_asked(self, monkeypatch):
        monkeypatch.setattr(node_mod, "_STOP_RELAY_GRACE", 0.2)

        async def _ignore(self, peer, packet):
            return None
        # Every node still announces the plane; none acts on a request.
        monkeypatch.setitem(node_mod._HANDLERS, node_mod.STOP_RELAY, _ignore)
        relay, sender, target = await _star()
        try:
            await _talking(sender, target)
            before = target._reputation.score(relay.id)
            _refuse(target, sender)
            await _keep_sending(sender, target, 5)
            await asyncio.sleep(0.4)
            await _keep_sending(sender, target, 5)
            assert await _until(lambda: target._reputation.score(relay.id) > before)
        finally:
            for node in (sender, target, relay):
                await node.stop()
