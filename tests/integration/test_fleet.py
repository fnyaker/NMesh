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
from src.apps.fleet import (FleetApp, StatusReceived, EnrolRequested,
                            Failure, ScanReceived)
from src.apps.fleet_web import FleetBridge
from src.apps.fleet_state import FleetState
from src.node_id import NodeID
from src.tcp_transport import TCPTransport, TCPServer
from src.transport_manager import TransportManager

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))


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


async def _party(node, *, mesh_invite=None) -> Party:
    connector = DataConnector(node, host="127.0.0.1", port=0)
    await connector.start()
    client = ConnectorClient(connector.host, connector.port, connector.token,
                             FLEET_APP_ID)
    await client.connect()
    app = FleetApp(client, node.app_auth(FLEET_APP_ID), state=FleetState(),
                   repo_root=ROOT, mesh_invite=mesh_invite, auto_status=False)
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


class TestRightsOverRealMesh:
    async def test_asking_for_more_waits_for_a_human(self):
        """La demande de droit supplémentaire traverse un mesh réel sans rien
        accorder : c'est l'approbation locale qui ouvre la porte, pas la
        demande."""
        operator, agent = await _linked_pair(19318)
        try:
            await operator.app.request_enrolment(agent.id, caps=["status"])
            await agent.wait_for(EnrolRequested)
            await agent.app.approve_enrolment(operator.hex)
            async with asyncio.timeout(20.0):
                while operator.app.state.managed_one(agent.hex) is None:
                    await asyncio.sleep(0.05)

            assert await operator.app.request_capabilities(
                agent.id, ["update"]) is True
            await agent.wait_for(EnrolRequested)
            assert agent.app.state.allows(operator.hex, "update") is False
            await operator.app.request_update(agent.id)
            failure = await operator.wait_for(Failure)
            assert "not authorised for update" in failure.error

            # Un humain accepte : la porte s'ouvre, et l'opérateur l'apprend.
            assert await agent.app.approve_enrolment(operator.hex) is True
            assert agent.app.state.allows(operator.hex, "update") is True
            async with asyncio.timeout(20.0):
                while "update" not in (operator.app.state.managed_one(
                        agent.hex) or {}).get("caps", []):
                    await asyncio.sleep(0.05)
        finally:
            await operator.close()
            await agent.close()

    async def test_giving_a_right_back_needs_no_approval(self):
        operator, agent = await _linked_pair(19319)
        try:
            await operator.app.request_enrolment(agent.id,
                                                 caps=["status", "update"])
            await agent.wait_for(EnrolRequested)
            await agent.app.approve_enrolment(operator.hex)
            async with asyncio.timeout(20.0):
                while operator.app.state.managed_one(agent.hex) is None:
                    await asyncio.sleep(0.05)

            assert await operator.app.drop_capabilities(
                agent.hex, ["update"]) is True
            async with asyncio.timeout(20.0):
                while agent.app.state.allows(operator.hex, "update"):
                    await asyncio.sleep(0.05)
            assert agent.app.state.allows(operator.hex, "status") is True
            await operator.app.request_update(agent.id)
            failure = await operator.wait_for(Failure)
            assert "not authorised for update" in failure.error
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


# ---------------------------------------------------------------------------
# L'intégration au réseau d'une machine provisionnée
# ---------------------------------------------------------------------------

class TestProvisionedNodeJoinsTheMesh:
    """Une machine provisionnée doit finir **membre du réseau**, avec un
    certificat émis par la node qui a lancé le scan. C'est le flux d'invitation
    ordinaire — invitation → handshake → `issue_cert` — simplement automatisé.

    Le transfert SSH n'est pas rejouable ici (pas de machine cible), mais tout ce
    qui suit l'est : l'invitation que le provisionneur dépose, sa redemption par
    la nouvelle node, et la chaîne de certificats qui en résulte."""

    async def test_certificate_is_issued_by_the_scanning_node(self):
        provisioner = MeshNode(_mgr())
        await provisioner.start(["tcp://127.0.0.1:19320"])
        party = await _party(
            provisioner,
            mesh_invite=lambda: {"uris": ["tcp://127.0.0.1:19320"],
                                 "code": provisioner.generate_invite(3600)})
        newcomer = MeshNode(_mgr())
        try:
            # Ce que le provisioning dépose sur la machine neuve.
            uris, code = party.app._fresh_invitation([], "")
            assert uris and code

            # Ce que la machine neuve en fait à son premier démarrage.
            await newcomer.join(uris[0], code)
            await newcomer.wait_for_session(timeout=20.0)
            await provisioner.wait_for_session(timeout=20.0)

            # Le certificat de la nouvelle node est émis par le provisionneur.
            chain = newcomer._cert_store.get_chain_to_root(newcomer.id)
            assert chain, "la nouvelle node n'a pas de chaîne de certificats"
            assert chain[0].subject_id == newcomer.id
            assert chain[0].issuer_id == provisioner.id
            # Et cette chaîne remonte bien à une racine que le réseau reconnaît.
            assert newcomer._cert_store.verify_chain(chain) is not None
        finally:
            await party.close()
            await newcomer.stop()

    async def test_the_invitation_is_single_use(self):
        """Deux machines ne partagent jamais un code : le premier qui l'utilise
        le consomme, et un second essai échoue."""
        provisioner = MeshNode(_mgr())
        await provisioner.start(["tcp://127.0.0.1:19321"])
        party = await _party(
            provisioner,
            mesh_invite=lambda: {"uris": ["tcp://127.0.0.1:19321"],
                                 "code": provisioner.generate_invite(3600)})
        first = MeshNode(_mgr())
        second = MeshNode(_mgr())
        try:
            uris, code = party.app._fresh_invitation([], "")
            await first.join(uris[0], code)
            await first.wait_for_session(timeout=20.0)

            with pytest.raises(Exception):
                await second.join(uris[0], code)
                await second.wait_for_session(timeout=5.0)
        finally:
            await party.close()
            await first.stop()
            await second.stop()

    async def test_each_machine_gets_its_own_invitation(self):
        """Une invitation par machine : l'échec de l'une ne brûle pas l'autre."""
        provisioner = MeshNode(_mgr())
        await provisioner.start(["tcp://127.0.0.1:19322"])
        party = await _party(
            provisioner,
            mesh_invite=lambda: {"uris": ["tcp://127.0.0.1:19322"],
                                 "code": provisioner.generate_invite(3600)})
        try:
            _uris_a, code_a = party.app._fresh_invitation([], "")
            _uris_b, code_b = party.app._fresh_invitation([], "")
            assert code_a != code_b
        finally:
            await party.close()

    async def test_without_a_provider_the_caller_sees_no_invitation(self):
        """Sans moyen d'inviter, la machine serait installée sans rejoindre
        quoi que ce soit — le résultat doit le dire, pas le cacher."""
        node = MeshNode(_mgr())
        party = await _party(node, mesh_invite=None)
        try:
            uris, code = party.app._fresh_invitation([], "")
            assert uris == [] and code == ""
        finally:
            await party.close()

    async def test_a_broken_provider_does_not_break_provisioning(self):
        def boom():
            raise RuntimeError("no invite for you")

        node = MeshNode(_mgr())
        party = await _party(node, mesh_invite=boom)
        try:
            assert party.app._fresh_invitation(["tcp://fallback:1"], "fb") == (
                ["tcp://fallback:1"], "fb")
        finally:
            await party.close()


# ---------------------------------------------------------------------------
# Le scan **distant** : la panne que l'utilisateur a rencontrée
# ---------------------------------------------------------------------------

class TestRemoteScan:
    """Un scan demandé à une node distante doit revenir jusqu'au pont console.
    C'est le chemin complet : requête signée → autorisation → balayage sur
    l'autre machine → réponse routée → état visible par l'interface."""

    async def _ssh_listener(self):
        async def handle(reader, writer):
            writer.write(b"SSH-2.0-OpenSSH_9.6\r\n")
            await writer.drain()
            writer.close()
        server = await asyncio.start_server(handle, "127.0.0.1", 0)
        return server, server.sockets[0].getsockname()[1]

    @staticmethod
    async def _via_thread(fn, *args):
        """Le pont marshalle vers la boucle : l'appeler *depuis* la boucle
        interbloque (cf. `gotchas.md`). Comme la console, on passe par un thread."""
        return await asyncio.to_thread(fn, *args)

    async def _enrolled(self, port_base, caps):
        operator, agent = await _linked_pair(port_base)
        await operator.app.request_enrolment(agent.id, caps=caps)
        await agent.wait_for(EnrolRequested)
        await agent.app.approve_enrolment(operator.hex)
        async with asyncio.timeout(20.0):
            while operator.app.state.managed_one(agent.hex) is None:
                await asyncio.sleep(0.05)
        return operator, agent

    async def test_remote_scan_result_reaches_the_console_bridge(self):
        operator, agent = await self._enrolled(19330, ["scan"])
        bridge = FleetBridge(operator.app)
        bridge.start(asyncio.get_running_loop())
        server, port = await self._ssh_listener()
        try:
            rid = await self._via_thread(
                bridge.scan, agent.hex, [f"127.0.0.1:{port}"])
            event = await operator.wait_for(ScanReceived, timeout=60.0)
            assert event.src == agent.id
            assert [(h["ip"], h["port"]) for h in event.hosts] == [("127.0.0.1", port)]

            # Ce que l'interface lit réellement : le snapshot du pont.
            snapshot = await self._via_thread(bridge.snapshot)
            stored = snapshot["scans"][agent.hex]
            assert [h["port"] for h in stored["hosts"]] == [port]
            # …et l'opération est marquée terminée, pas « en cours » à vie.
            job = next(j for j in snapshot["jobs"] if j["rid"] == rid)
            assert job["state"] == "ok" and job["kind"] == "scan"
        finally:
            server.close()
            bridge.stop()
            await operator.close()
            await agent.close()

    async def test_remote_scan_without_the_capability_is_reported(self):
        """Un refus doit se voir comme un refus, pas comme un silence."""
        operator, agent = await self._enrolled(19331, ["status"])
        bridge = FleetBridge(operator.app)
        bridge.start(asyncio.get_running_loop())
        try:
            rid = await self._via_thread(bridge.scan, agent.hex,
                                         ["127.0.0.1:22"])
            failure = await operator.wait_for(Failure, timeout=30.0)
            assert "not authorised" in failure.error
            snapshot = await self._via_thread(bridge.snapshot)
            job = next(j for j in snapshot["jobs"] if j["rid"] == rid)
            assert job["state"] == "failed"
        finally:
            bridge.stop()
            await operator.close()
            await agent.close()

    async def test_remote_status_closes_its_job(self):
        operator, agent = await self._enrolled(19332, ["status"])
        bridge = FleetBridge(operator.app)
        bridge.start(asyncio.get_running_loop())
        try:
            rid = await self._via_thread(bridge.status, agent.hex)
            await operator.wait_for(StatusReceived, timeout=30.0)
            snapshot = await self._via_thread(bridge.snapshot)
            job = next(j for j in snapshot["jobs"] if j["rid"] == rid)
            assert job["state"] == "ok"
        finally:
            bridge.stop()
            await operator.close()
            await agent.close()
