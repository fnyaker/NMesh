"""
Tests d'intégration de l'app Fleet — deux nœuds réels, vrai mesh.

Les tests unitaires (`tests/test_fleet.py`) branchent les dispatchers l'un sur
l'autre. Ici tout est réel : invitation, handshake post-quantique, session E2E,
connecteur de données, cadrage par section. On vérifie que la chaîne complète
tient — enrôlement avec décision humaine, puis commandes autorisées — et
surtout qu'un opérateur non enrôlé n'obtient rien à travers un mesh authentique.

Exclus de la suite par défaut ; lancer explicitement :
    pytest tests/integration/test_fleet.py -q
"""
import asyncio
import os
import tempfile

import pytest

from src import MeshNode
from src.app_registry import FLEET_APP_ID
from src.data_connector import ConnectorClient, DataConnector
from src.apps.fleet import FleetApp, StatusReceived, EnrolRequested, Failure
from src.apps.fleet_state import FleetState
from src.node_id import NodeID
from src.tcp_transport import TCPTransport, TCPServer
from src.transport_manager import TransportManager


def _mgr() -> TransportManager:
    mgr = TransportManager()
    mgr.register("tcp", TCPTransport, TCPServer)
    return mgr


class Party:
    """Un nœud réel, son connecteur, et l'app Fleet branchée dessus."""

    def __init__(self, node, connector, app):
        self.node = node
        self.connector = connector
        self.app = app

    @property
    def id(self) -> NodeID:
        return self.node.id

    @property
    def hex(self) -> str:
        return self.node.id.raw.hex()

    async def close(self):
        await self.app.stop()
        await self.connector.stop()
        await self.node.stop()

    async def wait_for(self, kind, timeout=20.0):
        """Attend un événement d'un type donné (jamais un sleep arbitraire)."""
        async with asyncio.timeout(timeout):
            while True:
                event = await self.app.next_event()
                if isinstance(event, kind):
                    return event


async def _party(node) -> Party:
    connector = DataConnector(node, host="127.0.0.1", port=0)
    await connector.start()
    client = ConnectorClient(connector.host, connector.port, connector.token,
                             FLEET_APP_ID)
    await client.connect()
    app = FleetApp(client, node.app_auth(FLEET_APP_ID), state=FleetState(),
                   auto_status=False)
    await app.start()
    return Party(node, connector, app)


async def _linked_pair(port: int):
    """Deux nœuds joints par invitation, avec une session E2E établie.

    Un port fixe **unique par test** (cf. `Docs/Architecture/gotchas.md` : un
    port partagé entre tests entrerait en collision entre workers xdist)."""
    host = MeshNode(_mgr())
    guest = MeshNode(_mgr())
    code = host.generate_invite()
    await host.start([f"tcp://127.0.0.1:{port}"])
    await guest.join(f"tcp://127.0.0.1:{port}", code)
    await guest.wait_for_session(timeout=20.0)
    await host.wait_for_session(timeout=20.0)
    return await _party(host), await _party(guest)


class TestEnrolmentOverRealMesh:
    async def test_full_flow_enrol_then_status(self):
        operator, agent = await _linked_pair(19310)
        try:
            await operator.app.request_enrolment(agent.id, caps=["status"],
                                                 label="my laptop")
            request = await agent.wait_for(EnrolRequested)
            assert request.src == operator.id
            assert request.caps == ["status"]
            # Rien n'est accordé tant qu'un humain n'a pas répondu.
            assert agent.app.state.allows(operator.hex, "status") is False

            assert await agent.app.approve_enrolment(operator.hex) is True
            async with asyncio.timeout(20.0):
                while operator.app.state.managed_one(agent.hex) is None:
                    await asyncio.sleep(0.05)

            await operator.app.request_status(agent.id)
            report = await operator.wait_for(StatusReceived)
            assert report.src == agent.id
            assert report.status["memory"]["total"] > 0
            assert isinstance(report.status["disks"], list)
        finally:
            await operator.close()
            await agent.close()

    async def test_unenrolled_operator_gets_nothing(self):
        """La porte du ledger tient à travers un mesh réel, pas seulement en
        test unitaire : la session E2E authentifie, elle n'autorise pas."""
        operator, agent = await _linked_pair(19311)
        try:
            await operator.app.request_status(agent.id)
            failure = await operator.wait_for(Failure)
            assert "not authorised" in failure.error
            assert agent.app.state.operators() == []
        finally:
            await operator.close()
            await agent.close()

    async def test_capability_not_granted_is_refused(self):
        operator, agent = await _linked_pair(19312)
        try:
            await operator.app.request_enrolment(agent.id, caps=["status"])
            await agent.wait_for(EnrolRequested)
            await agent.app.approve_enrolment(operator.hex)
            async with asyncio.timeout(20.0):
                while operator.app.state.managed_one(agent.hex) is None:
                    await asyncio.sleep(0.05)

            # « status » passe, « update » (jamais accordé) est refusé.
            await operator.app.request_status(agent.id)
            await operator.wait_for(StatusReceived)
            await operator.app.request_update(agent.id)
            failure = await operator.wait_for(Failure)
            assert "not authorised for update" in failure.error
        finally:
            await operator.close()
            await agent.close()

    async def test_revoke_cuts_access_for_real(self):
        operator, agent = await _linked_pair(19313)
        try:
            await operator.app.request_enrolment(agent.id, caps=["status"])
            await agent.wait_for(EnrolRequested)
            await agent.app.approve_enrolment(operator.hex)
            async with asyncio.timeout(20.0):
                while operator.app.state.managed_one(agent.hex) is None:
                    await asyncio.sleep(0.05)

            assert await agent.app.revoke(operator.hex) is True
            async with asyncio.timeout(20.0):
                while operator.app.state.managed_one(agent.hex) is not None:
                    await asyncio.sleep(0.05)

            await operator.app.request_status(agent.id)
            failure = await operator.wait_for(Failure)
            assert "not authorised" in failure.error
        finally:
            await operator.close()
            await agent.close()


class TestSectionIsolation:
    async def test_fleet_traffic_stays_in_its_section(self):
        """Une app branchée sur une autre section ne voit rien du trafic Fleet
        (le connecteur démultiplexe par app_id)."""
        operator, agent = await _linked_pair(19314)
        other = ConnectorClient(agent.connector.host, agent.connector.port,
                                agent.connector.token, b"\x09" * 8)
        await other.connect()
        try:
            await operator.app.request_enrolment(agent.id, caps=["status"])
            await agent.wait_for(EnrolRequested)
            with pytest.raises(asyncio.TimeoutError):
                async with asyncio.timeout(2.0):
                    await other.recv()
        finally:
            await other.close()
            await operator.close()
            await agent.close()
