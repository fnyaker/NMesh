"""
The mesh map past one node's own eyes — over a real mesh.

The unit tests wire the two dispatchers into each other. Here everything is
real: an invitation, the post-quantum handshake, the E2E session, the data
connector, the per-section framing, both grants. What is checked is the claim
the feature makes and nothing else:

  an operator's map learns that a machine gained a link **because the machine
  said so**, within seconds, without anybody asking again.

And the two refusals that make it safe to offer: a machine that granted the
capability but whose own fleet app was never granted the node's `links` right
says which one is missing, and a machine that granted nothing says nothing at
all.

Excluded from the default suite; run it explicitly:
    pytest tests/integration/test_fleet_map.py -q
"""
import asyncio
import os

import pytest

from src import MeshNode
from src.app_registry import FLEET_APP_ID
from src.apps.fleet import Failure, FleetApp, LinksReceived
from src.apps.fleet_state import FleetState
from src.apps.fleet_web import FleetBridge
from src.data_connector import ConnectorClient, DataConnector
from src.tcp_transport import TCPTransport, TCPServer
from src.transport_manager import TransportManager

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))


def _mgr() -> TransportManager:
    mgr = TransportManager()
    mgr.register("tcp", TCPTransport, TCPServer)
    return mgr


class Party:
    def __init__(self, node, connector, app, bridge=None):
        self.node = node
        self.connector = connector
        self.app = app
        self.bridge = bridge

    @property
    def id(self):
        return self.node.id

    @property
    def hex(self) -> str:
        return self.node.id.raw.hex()

    async def close(self):
        if self.bridge is not None:
            self.bridge.stop()
        await self.app.stop()
        await self.connector.stop()
        await self.node.stop()

    async def wait_for(self, kind, timeout=20.0):
        async with asyncio.timeout(timeout):
            while True:
                event = await self.app.next_event()
                if isinstance(event, kind):
                    return event


async def _party(node, *, grants=True, bridge=False) -> Party:
    # The grant the *node* gives its own fleet app, which is the second of the
    # two and the one an operator ticks in the Apps page.
    connector = DataConnector(
        node, host="127.0.0.1", port=0,
        grants=(lambda app_id, capability: bool(grants)) if grants else None)
    await connector.start()
    client = ConnectorClient(connector.host, connector.port, connector.token,
                             FLEET_APP_ID)
    await client.connect()
    app = FleetApp(client, node.app_auth(FLEET_APP_ID), state=FleetState(),
                   repo_root=ROOT, auto_status=False)
    await app.start()
    web = None
    if bridge:
        web = FleetBridge(app)
        web.start(asyncio.get_running_loop())
    return Party(node, connector, app, web)


async def _linked_pair(port: int, *, grants=True, bridge=False):
    host = MeshNode(_mgr())
    guest = MeshNode(_mgr())
    code = host.generate_invite()
    await host.start([f"tcp://127.0.0.1:{port}"])
    await guest.join(f"tcp://127.0.0.1:{port}", code)
    await guest.wait_for_session(timeout=20.0)
    await host.wait_for_session(timeout=20.0)
    return (await _party(host, bridge=bridge),
            await _party(guest, grants=grants))


async def _enrol(operator: Party, agent: Party, caps) -> None:
    await operator.app.request_enrolment(agent.id, caps=list(caps),
                                         label="a machine")
    async with asyncio.timeout(20.0):
        while agent.app.state.pending_in() == []:
            await asyncio.sleep(0.05)
    assert await agent.app.approve_enrolment(operator.hex, list(caps)) is True
    async with asyncio.timeout(20.0):
        while operator.app.state.managed_one(agent.hex) is None:
            await asyncio.sleep(0.05)


class TestTheMapIsLive:
    async def test_a_machine_reports_its_links_and_keeps_reporting(self):
        operator, agent = await _linked_pair(19334, bridge=True)
        try:
            await _enrol(operator, agent, ["links"])
            # A page opened the map: that, and only that, is what makes this
            # console follow anything.
            operator.bridge.api_map_links()
            await operator.bridge._reconcile_links()
            event = await operator.wait_for(LinksReceived)
            assert event.src == agent.id
            # The guest's one link is the host it joined through — us.
            assert [link["id"] for link in event.links] == [operator.hex]

            async with asyncio.timeout(20.0):
                while not operator.bridge.api_map_links()["sources"]:
                    await asyncio.sleep(0.05)
            view = operator.bridge.api_map_links()
            [source] = view["sources"]
            assert source["id"] == agent.hex and source["links"] == 1
            # Fresh by construction: what is on the map was confirmed seconds
            # ago, not kept from an earlier run.
            assert source["age"] < view["fresh_for"]
            assert operator.app.following_links() == [agent.hex]
        finally:
            await operator.close()
            await agent.close()

    async def test_a_link_that_appears_reaches_the_map_on_its_own(self):
        """The whole point: a third machine joins the agent, and the operator's
        map learns it because the agent said so."""
        operator, agent = await _linked_pair(19335, bridge=True)
        third = MeshNode(_mgr())
        try:
            await _enrol(operator, agent, ["links"])
            operator.bridge.api_map_links()
            await operator.bridge._reconcile_links()
            await operator.wait_for(LinksReceived)

            # A machine the operator has never met joins the agent.
            await agent.node.start(["tcp://127.0.0.1:19336"])
            await third.join("tcp://127.0.0.1:19336", agent.node.generate_invite())
            await third.wait_for_session(timeout=20.0)

            async with asyncio.timeout(30.0):
                while True:
                    edges = operator.bridge.api_map_links()["edges"]
                    if any(edge["b"] == third.id.raw.hex()
                           or edge["a"] == third.id.raw.hex() for edge in edges):
                        break
                    await asyncio.sleep(0.1)
            [edge] = [edge for edge in operator.bridge.api_map_links()["edges"]
                      if third.id.raw.hex() in (edge["a"], edge["b"])]
            # Attributed, and young: the map says who claimed this and when.
            assert edge["from"] == agent.hex
            assert edge["age"] < 30.0
        finally:
            await third.stop()
            await operator.close()
            await agent.close()

    async def test_the_operator_stops_being_told_once_nobody_looks(self):
        operator, agent = await _linked_pair(19337, bridge=True)
        try:
            await _enrol(operator, agent, ["links"])
            operator.bridge.api_map_links()
            await operator.bridge._reconcile_links()
            await operator.wait_for(LinksReceived)
            assert operator.app.following_links() == [agent.hex]

            # The map was closed: nothing says "somebody is looking" any more.
            operator.bridge._links._watching = 0.0
            await operator.bridge._reconcile_links()
            assert operator.app.following_links() == []
            # And what it held goes with the follow — the map is a picture of
            # now, so there is nothing left to draw.
            assert operator.bridge.api_map_links()["edges"] == []
        finally:
            await operator.close()
            await agent.close()


class TestTheTwoRefusals:
    async def test_a_machine_that_granted_nothing_answers_nothing(self):
        operator, agent = await _linked_pair(19338)
        try:
            await operator.app.request_links(agent.id)
            failure = await operator.wait_for(Failure)
            assert "not authorised" in failure.error
        finally:
            await operator.close()
            await agent.close()

    async def test_a_machine_whose_app_was_never_granted_says_which(self):
        """Two grants, and an operator has to be able to tell which is missing:
        "nothing came back" and "that machine's fleet app may not read its
        links" are different problems with different fixes."""
        operator, agent = await _linked_pair(19339, grants=False)
        try:
            await _enrol(operator, agent, ["links"])
            await operator.app.request_links(agent.id)
            failure = await operator.wait_for(Failure)
            assert "granted its fleet app" in failure.error
        finally:
            await operator.close()
            await agent.close()
