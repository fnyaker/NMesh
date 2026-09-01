"""
Integration tests for the Fleet app — two real nodes, a real mesh.

The unit tests (`tests/test_fleet.py`) wire the dispatchers into each other.
Here everything is real: the invitation, the post-quantum handshake, the E2E
session, the data connector, the per-section framing. We check that the whole
chain holds — enrolment with a human decision, then authorised commands — and
above all that an unenrolled operator gets nothing through a genuine mesh.

Excluded from the default suite; run it explicitly:
    pytest tests/integration/test_fleet.py -q
"""
import asyncio
import os
import tempfile

import pytest

from src import MeshNode
from src.app_registry import FLEET_APP_ID
from src.data_connector import ConnectorClient, DataConnector
from src.apps import fleet_files
from src.apps.fleet import (ConsoleProxyError, FileTransferError, FleetApp,
                            StatusReceived, EnrolRequested, Failure,
                            ScanReceived)
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
    """A real node, its connector, and the Fleet app plugged into it."""

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
        """Wait for an event of a given kind (never an arbitrary sleep)."""
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
    """Two nodes joined by invitation, with an E2E session established.

    A fixed port, **unique per test** (see `Docs/Architecture/gotchas.md`: a port
    shared between tests would collide across xdist workers)."""
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
            # Nothing is granted until a human has answered.
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
        """The ledger gate holds across a real mesh, not only in a unit test:
        the E2E session authenticates, it does not authorise."""
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

            # "status" goes through, "update" (never granted) is refused.
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
        """Asking for one more right crosses a real mesh granting nothing: it is
        the local approval that opens the gate, not the request."""
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

            # A human accepts: the gate opens, and the operator learns of it.
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


class StubConsole:
    """The real loopback console has no place here: what we want to prove is
    that the call crosses a real mesh and comes back intact."""

    def __init__(self):
        self.calls = []
        self.available = True

    def call(self, method, path, body, token, timeout=None):
        self.calls.append((method, path, body, token))
        return 200, "application/json", b'{"id":"the-target"}' + b"." * 90_000


class TestRemoteConsoleOverRealMesh:
    async def test_a_console_call_crosses_the_mesh_and_comes_back(self):
        """A response larger than one frame: the splitting and the reassembly go
        over a real link, not a transport stub."""
        operator, agent = await _linked_pair(19340)
        console = StubConsole()
        agent.app._local_console = console
        try:
            await operator.app.request_enrolment(agent.id, caps=["manage"])
            await agent.wait_for(EnrolRequested)
            await agent.app.approve_enrolment(operator.hex)
            async with asyncio.timeout(20.0):
                while operator.app.state.managed_one(agent.hex) is None:
                    await asyncio.sleep(0.05)

            status, ctype, body = await operator.app.console_call(
                agent.id, "GET", "/api/state", token="a-remote-token")
            assert status == 200
            assert ctype.startswith("application/json")
            assert body.startswith(b'{"id":"the-target"}')
            assert len(body) == 19 + 90_000
            assert console.calls == [("GET", "/api/state", None, "a-remote-token")]
        finally:
            await operator.close()
            await agent.close()

    async def test_without_the_grant_the_call_is_refused(self):
        operator, agent = await _linked_pair(19341)
        console = StubConsole()
        agent.app._local_console = console
        try:
            await operator.app.request_enrolment(agent.id, caps=["status"])
            await agent.wait_for(EnrolRequested)
            await agent.app.approve_enrolment(operator.hex)
            async with asyncio.timeout(20.0):
                while operator.app.state.managed_one(agent.hex) is None:
                    await asyncio.sleep(0.05)

            with pytest.raises(ConsoleProxyError) as failure:
                await operator.app.console_call(agent.id, "GET", "/api/state")
            assert "not authorised for manage" in str(failure.value)
            assert console.calls == []
        finally:
            await operator.close()
            await agent.close()


class TestFilesOverRealMesh:
    """The file surface behind `shell`, over a real link and through the bridge
    the console actually calls — slicing, reassembly and all."""

    async def test_a_file_goes_up_and_comes_back_whole(self, tmp_path):
        """Bigger than one slice in both directions: what is proved is the
        chunking, not that a small string survives a round trip."""
        operator, agent = await _linked_pair(19350)
        bridge = FleetBridge(operator.app)
        bridge.start(asyncio.get_running_loop())
        try:
            await operator.app.request_enrolment(agent.id, caps=["shell"])
            await agent.wait_for(EnrolRequested)
            await agent.app.approve_enrolment(operator.hex)
            async with asyncio.timeout(20.0):
                while operator.app.state.managed_one(agent.hex) is None:
                    await asyncio.sleep(0.05)

            body = os.urandom(fleet_files.WRITE_SLICE * 2 + 1234)
            result = await asyncio.to_thread(
                bridge.files_upload, agent.hex, str(tmp_path), "payload.bin", body)
            assert result["done"] is True and result["size"] == len(body)
            assert (tmp_path / "payload.bin").read_bytes() == body

            listed = await asyncio.to_thread(bridge.files_list, agent.hex,
                                             str(tmp_path))
            assert [row["name"] for row in listed["entries"]] == ["payload.bin"]

            name, data = await asyncio.to_thread(
                bridge.files_download, agent.hex, str(tmp_path / "payload.bin"))
            assert name == "payload.bin" and data == body
        finally:
            bridge.stop()
            await operator.close()
            await agent.close()

    async def test_without_the_shell_right_nothing_is_listed(self, tmp_path):
        operator, agent = await _linked_pair(19351)
        bridge = FleetBridge(operator.app)
        bridge.start(asyncio.get_running_loop())
        try:
            await operator.app.request_enrolment(agent.id, caps=["status"])
            await agent.wait_for(EnrolRequested)
            await agent.app.approve_enrolment(operator.hex)
            async with asyncio.timeout(20.0):
                while operator.app.state.managed_one(agent.hex) is None:
                    await asyncio.sleep(0.05)

            # Refused here, before it costs a round trip: an operation that can
            # only come back denied is one the bridge should never send.
            with pytest.raises(FileTransferError, match="has not granted"):
                await asyncio.to_thread(bridge.files_list, agent.hex,
                                        str(tmp_path))
            # And refused over there too, if it somehow left.
            with pytest.raises(FileTransferError, match="not authorised"):
                await operator.app.list_files(agent.id, str(tmp_path))
        finally:
            bridge.stop()
            await operator.close()
            await agent.close()


class TestSectionIsolation:
    async def test_fleet_traffic_stays_in_its_section(self):
        """An app plugged into another section sees nothing of Fleet's traffic
        (the connector demultiplexes by app_id)."""
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
# How a provisioned machine joins the network
# ---------------------------------------------------------------------------

class TestProvisionedNodeJoinsTheMesh:
    """A provisioned machine has to end up a **member of the network**, with a
    certificate issued by the node that ran the scan. It is the ordinary
    invitation flow — invitation → handshake → `issue_cert` — simply automated.

    The SSH transfer cannot be replayed here (there is no target machine), but
    everything after it can: the invitation the provisioner leaves, its
    redemption by the new node, and the certificate chain that results."""

    async def test_certificate_is_issued_by_the_scanning_node(self):
        provisioner = MeshNode(_mgr())
        await provisioner.start(["tcp://127.0.0.1:19320"])
        party = await _party(
            provisioner,
            mesh_invite=lambda: {"uris": ["tcp://127.0.0.1:19320"],
                                 "code": provisioner.generate_invite(3600)})
        newcomer = MeshNode(_mgr())
        try:
            # What provisioning leaves on the new machine.
            uris, code = party.app._fresh_invitation([], "")
            assert uris and code

            # What the new machine does with it on its first start.
            await newcomer.join(uris[0], code)
            await newcomer.wait_for_session(timeout=20.0)
            await provisioner.wait_for_session(timeout=20.0)

            # The new node's certificate is issued by the provisioner.
            chain = newcomer._cert_store.get_chain_to_root(newcomer.id)
            assert chain, "the new node has no certificate chain"
            assert chain[0].subject_id == newcomer.id
            assert chain[0].issuer_id == provisioner.id
            # And that chain really walks up to a root the network recognises.
            assert newcomer._cert_store.verify_chain(chain) is not None
        finally:
            await party.close()
            await newcomer.stop()

    async def test_the_invitation_is_single_use(self):
        """Two machines never share a code: the first to use it consumes it, and
        a second attempt fails."""
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
        """One invitation per machine: one failing does not burn the other."""
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
        """With no way to invite, the machine would be installed without joining
        anything — the result must say so, not hide it."""
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
# The **remote** scan: the failure the user ran into
# ---------------------------------------------------------------------------

class TestRemoteScan:
    """A scan asked of a remote node has to come all the way back to the console
    bridge. That is the whole path: a signed request → authorisation → the sweep
    on the other machine → a routed reply → state the interface can see."""

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

            # What the interface actually reads: the bridge's snapshot.
            snapshot = await self._via_thread(bridge.snapshot)
            stored = snapshot["scans"][agent.hex]
            assert [h["port"] for h in stored["hosts"]] == [port]
            # …and the operation is marked finished, not "in progress" forever.
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
