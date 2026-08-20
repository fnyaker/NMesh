"""
Console tests for the fleet page and the built-in app toggles.

Two boundaries are checked here. First, the usual console one: nothing under
``/api/fleet/*`` or ``/api/apps/*`` is reachable without a session, and a
disabled app is a 404 rather than a half-wired surface. Second, the toggle
itself — enabling an app must actually start it, disabling must stop it and take
its page away, and uninstalling must purge its drawer.

A real server runs on an ephemeral loopback port and every HTTP call goes
through a worker thread, so the event loop stays free to service the console's
``run_coroutine_threadsafe`` bridge (a synchronous call from the loop thread
would deadlock against it).
"""
import asyncio
import base64
import os
import tempfile

import pytest

from src.app_registry import FLEET_APP_ID, AppHost, AppRegistry
from src.apps.fleet import FleetApp, Failure, StatusReceived
from src.apps.fleet_state import FleetState
from src.apps.fleet_web import FleetBridge
from src.crypto import CryptoIdentity
from src.node import MeshNode
from src.node_id import NodeID
from src.webconsole import WebConsole
from tests.conftest import make_manager
from tests.test_webconsole import _request, _login, PW


class StubClient:
    """Stands in for the connector: records sends, never yields inbound data."""

    def __init__(self):
        self.sent = []

    async def send(self, target, payload):
        self.sent.append((target, payload))

    async def recv(self):
        await asyncio.Event().wait()

    async def close(self):
        pass


async def _make(enabled=False, state_dir=None):
    """A node + console with the fleet app wired through an AppHost."""
    node = MeshNode(transport_manager=make_manager())
    registry = AppRegistry(state_dir)
    if enabled:
        registry.set_enabled("fleet", True)
    host = AppHost(registry, app_storage=node.app_storage)
    built = {}

    def factory():
        async def build():
            identity = CryptoIdentity()
            node_id = NodeID.from_public_key(identity.dsa_public_key)
            app = FleetApp(StubClient(), node.app_auth(FLEET_APP_ID),
                           state=FleetState(), auto_status=False)
            built["app"] = app
            return app, FleetBridge(app)
        return build

    host.register("fleet", factory())
    await host.apply()
    console = WebConsole(node, host="127.0.0.1", port=0, use_tls=False,
                         password=PW, app_host=host)
    console.start(loop=asyncio.get_running_loop())
    return node, console, host, built


async def _post(console, path, token, body):
    return await asyncio.to_thread(_request, console, "POST", path, token, body)


async def _get(console, path, token=None):
    return await asyncio.to_thread(_request, console, "GET", path, token)


class TestDisabledApp:
    async def test_fleet_api_is_absent_when_disabled(self):
        node, console, host, _ = await _make(enabled=False)
        try:
            _status, token = await _login(console)
            status, _, _, _ = await _get(console, "/api/fleet/state", token)
            assert status == 404
            status, _, _, _ = await _get(console, "/fleet")
            assert status == 404
        finally:
            console.stop()
            await host.stop_all()
            await node.stop()

    async def test_fleet_api_requires_auth_when_enabled(self):
        node, console, host, _ = await _make(enabled=True)
        try:
            status, _, _, _ = await _get(console, "/api/fleet/state")
            assert status == 401
            status, _, _, _ = await _post(console, "/api/fleet/enrol", None,
                                          {"node": "aa" * 20, "caps": ["status"]})
            assert status == 401
        finally:
            console.stop()
            await host.stop_all()
            await node.stop()


class TestAppToggles:
    async def test_enable_starts_the_app_and_serves_its_page(self):
        node, console, host, built = await _make(enabled=False)
        try:
            _status, token = await _login(console)
            status, _, _, body = await _post(console, "/api/apps/enable", token,
                                             {"id": "fleet"})
            assert status == 200
            entry = next(a for a in body["apps"] if a["id"] == "fleet")
            assert entry["enabled"] is True and entry["running"] is True
            status, _, _, snapshot = await _get(console, "/api/fleet/state", token)
            assert status == 200 and len(snapshot["me"]) == 40
            status, _, page, _ = await _get(console, "/fleet")
            assert status == 200 and b"NMesh" in page
        finally:
            console.stop()
            await host.stop_all()
            await node.stop()

    async def test_disable_stops_the_app_and_takes_the_page_away(self):
        node, console, host, _ = await _make(enabled=True)
        try:
            _status, token = await _login(console)
            assert (await _get(console, "/api/fleet/state", token))[0] == 200
            status, _, _, body = await _post(console, "/api/apps/disable", token,
                                             {"id": "fleet"})
            assert status == 200
            entry = next(a for a in body["apps"] if a["id"] == "fleet")
            assert entry["running"] is False
            assert (await _get(console, "/api/fleet/state", token))[0] == 404
            assert (await _get(console, "/fleet"))[0] == 404
        finally:
            console.stop()
            await host.stop_all()
            await node.stop()

    async def test_toggle_survives_a_restart(self):
        with tempfile.TemporaryDirectory() as data:
            node, console, host, _ = await _make(enabled=False, state_dir=data)
            try:
                _status, token = await _login(console)
                await _post(console, "/api/apps/enable", token, {"id": "fleet"})
            finally:
                console.stop()
                await host.stop_all()
                await node.stop()
            assert AppRegistry(data).is_enabled("fleet") is True

    async def test_uninstall_purges_the_drawer(self):
        node, console, host, _ = await _make(enabled=True)
        try:
            node.app_store_put(FLEET_APP_ID, "fleet-state", b"a ledger")
            assert node.app_store_get(FLEET_APP_ID, "fleet-state") is not None
            _status, token = await _login(console)
            status, _, _, _ = await _post(console, "/api/apps/uninstall", token,
                                          {"id": "fleet"})
            assert status == 200
            # Uninstall means the state is gone, not just the wiring.
            assert node.app_store_get(FLEET_APP_ID, "fleet-state") is None
            assert host.registry.is_enabled("fleet") is False
        finally:
            console.stop()
            await host.stop_all()
            await node.stop()

    async def test_unknown_app_is_refused(self):
        node, console, host, _ = await _make()
        try:
            _status, token = await _login(console)
            for body in ({"id": "../etc"}, {"id": ""}, {"id": 5}, {}):
                status, _, _, _ = await _post(console, "/api/apps/enable", token,
                                              body)
                assert status == 400
        finally:
            console.stop()
            await host.stop_all()
            await node.stop()

    async def test_apps_appear_in_the_state_snapshot(self):
        node, console, host, _ = await _make(enabled=True)
        try:
            _status, token = await _login(console)
            _s, _h, _b, snapshot = await _get(console, "/api/state", token)
            names = {a["id"] for a in snapshot["apps"]}
            assert {"chat", "fleet"} <= names
        finally:
            console.stop()
            await host.stop_all()
            await node.stop()


class TestFleetRoutes:
    async def test_snapshot_shape(self):
        node, console, host, _ = await _make(enabled=True)
        try:
            _status, token = await _login(console)
            _s, _h, _b, snapshot = await _get(console, "/api/fleet/state", token)
            for key in ("me", "managed", "operators", "pending_in",
                        "capabilities", "host", "log"):
                assert key in snapshot
            assert {c["name"] for c in snapshot["capabilities"]} >= {"status",
                                                                    "shell"}
        finally:
            console.stop()
            await host.stop_all()
            await node.stop()

    async def test_enrol_validates_its_input(self):
        node, console, host, _ = await _make(enabled=True)
        try:
            _status, token = await _login(console)
            for body in ({"node": "nothex", "caps": ["status"]},
                         {"node": "aa" * 20, "caps": []},
                         {"node": "aa" * 20, "caps": ["root"]},
                         {"node": "", "caps": ["status"]}):
                status, _, _, _ = await _post(console, "/api/fleet/enrol", token,
                                              body)
                assert status in (400, 503)
        finally:
            console.stop()
            await host.stop_all()
            await node.stop()

    async def test_enrol_reaches_the_app(self):
        node, console, host, built = await _make(enabled=True)
        try:
            _status, token = await _login(console)
            target = "bb" * 20
            status, _, _, _ = await _post(console, "/api/fleet/enrol", token,
                                          {"node": target, "caps": ["status"],
                                           "label": "lab"})
            assert status == 200
            pending = built["app"].state.pending_out()
            assert [p["id"] for p in pending] == [target]
        finally:
            console.stop()
            await host.stop_all()
            await node.stop()

    async def test_shell_input_requires_valid_base64(self):
        node, console, host, _ = await _make(enabled=True)
        try:
            _status, token = await _login(console)
            for data in ("not base64!!", 5, None, "=="):
                status, _, _, _ = await _post(
                    console, "/api/fleet/input", token,
                    {"node": "aa" * 20, "sid": "cc" * 16, "data": data})
                assert status == 400
        finally:
            console.stop()
            await host.stop_all()
            await node.stop()

    async def test_shell_data_for_an_unknown_session(self):
        node, console, host, _ = await _make(enabled=True)
        try:
            _status, token = await _login(console)
            status, _, _, _ = await _get(console, "/api/fleet/shell?sid=deadbeef",
                                         token)
            assert status == 404
        finally:
            console.stop()
            await host.stop_all()
            await node.stop()

    async def test_provision_requires_targets_and_user(self):
        node, console, host, _ = await _make(enabled=True)
        try:
            _status, token = await _login(console)
            for body in ({"targets": [], "username": "root"},
                         {"targets": [{"ip": "10.0.0.1"}]},
                         {"targets": "nope", "username": "root"},
                         {"targets": [{"ip": "10.0.0.1"}], "username": ""}):
                status, _, _, _ = await _post(console, "/api/fleet/provision",
                                              token, body)
                assert status == 400
        finally:
            console.stop()
            await host.stop_all()
            await node.stop()

    async def test_local_keys_never_return_key_material(self, tmp_path):
        node, console, host, _ = await _make(enabled=True)
        try:
            _status, token = await _login(console)
            _s, _h, raw, body = await _get(console, "/api/fleet/keys", token)
            assert "keys" in body
            assert b"PRIVATE KEY" not in raw
        finally:
            console.stop()
            await host.stop_all()
            await node.stop()


class TestOperationTracking:
    """Une action distante répond de façon asynchrone. Sans suivi, la page n'a
    aucun moyen de dire si elle a réussi, échoué, ou tourne encore — c'est
    exactement ce qui faisait qu'un scan distant « ne faisait rien »."""

    async def _bridge(self):
        node = MeshNode(transport_manager=make_manager())
        app = FleetApp(StubClient(), node.app_auth(FLEET_APP_ID),
                       state=FleetState(), auto_status=False)
        bridge = FleetBridge(app)
        bridge.start(asyncio.get_running_loop())
        return node, app, bridge

    async def test_a_started_operation_is_visible_as_running(self):
        node, app, bridge = await self._bridge()
        try:
            rid = await asyncio.to_thread(bridge.status, "aa" * 20)
            job = next(j for j in bridge.snapshot()["jobs"] if j["rid"] == rid)
            assert job == {"rid": rid, "kind": "status", "node": "aa" * 20,
                           "state": "running", "detail": "", "at": job["at"]}
        finally:
            bridge.stop()
            await node.stop()

    async def test_completion_closes_the_job(self):
        node, app, bridge = await self._bridge()
        try:
            rid = await asyncio.to_thread(bridge.status, "aa" * 20)
            app._emit(StatusReceived(NodeID(bytes.fromhex("aa" * 20)),
                                     {"uptime": 1.0}, rid))
            job = next(j for j in bridge.snapshot()["jobs"] if j["rid"] == rid)
            assert job["state"] == "ok"
        finally:
            bridge.stop()
            await node.stop()

    async def test_a_refusal_shows_as_failed(self):
        node, app, bridge = await self._bridge()
        try:
            rid = await asyncio.to_thread(bridge.scan, "aa" * 20, ["10.0.0.1"])
            app._emit(Failure(NodeID(bytes.fromhex("aa" * 20)), rid,
                              "not authorised for scan"))
            job = next(j for j in bridge.snapshot()["jobs"] if j["rid"] == rid)
            assert job["state"] == "failed"
            assert "not authorised" in job["detail"]
        finally:
            bridge.stop()
            await node.stop()

    async def test_an_answer_that_beats_its_registration_still_lands(self):
        """Un pair proche répond en moins d'une milliseconde, avant même que le
        thread appelant ait noté le rid. La clôture ne doit pas dépendre de cet
        ordre — sinon l'opération reste « en cours » à vie."""
        node, app, bridge = await self._bridge()
        try:
            rid = "ff" * 8
            bridge._finish(rid, "ok", "arrivé en avance")   # avant le _job
            bridge._job(rid, "scan", "aa" * 20)
            job = next(j for j in bridge.snapshot()["jobs"] if j["rid"] == rid)
            assert job["state"] == "ok" and job["detail"] == "arrivé en avance"
        finally:
            bridge.stop()
            await node.stop()

    async def test_job_table_is_bounded(self):
        node, app, bridge = await self._bridge()
        try:
            from src.apps.fleet_web import MAX_JOBS
            for i in range(MAX_JOBS + 40):
                bridge._job(f"{i:016x}", "status", "aa" * 20)
            assert len(bridge.snapshot()["jobs"]) <= MAX_JOBS
        finally:
            bridge.stop()
            await node.stop()

    async def test_early_completions_are_bounded_too(self):
        node, app, bridge = await self._bridge()
        try:
            from src.apps.fleet_web import MAX_JOBS
            for i in range(MAX_JOBS + 40):
                bridge._finish(f"{i:016x}", "ok")
            assert len(bridge._done_early) <= MAX_JOBS
        finally:
            bridge.stop()
            await node.stop()

    async def test_jobs_appear_in_the_console_snapshot(self):
        node, console, host, built = await _make(enabled=True)
        try:
            _status, token = await _login(console)
            _s, _h, _b, snapshot = await _get(console, "/api/fleet/state", token)
            assert "jobs" in snapshot and isinstance(snapshot["jobs"], list)
        finally:
            console.stop()
            await host.stop_all()
            await node.stop()


class TestKeyUpload:
    """Importer une clé depuis la console — le seul moyen d'en donner une à un
    nœud en conteneur, où `~/.ssh` n'existe pas."""

    KEY = ("-----BEGIN OPENSSH PRIVATE KEY-----\n"
           "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAA\n"
           "-----END OPENSSH PRIVATE KEY-----\n")

    async def test_upload_then_list_then_remove(self):
        node, console, host, _ = await _make(enabled=True)
        try:
            _status, token = await _login(console)
            status, _, _, body = await _post(console, "/api/fleet/keys", token,
                                             {"name": "laptop", "data": self.KEY})
            assert status == 200 and body["ok"] is True
            key_id = body["key"]["id"]
            assert body["key"]["name"] == "laptop"

            _s, _h, raw, listing = await _get(console, "/api/fleet/keys", token)
            assert b"PRIVATE KEY" not in raw          # metadata only, ever
            assert any(k["id"] == key_id for k in listing["keys"])

            status, _, _, body = await _post(console, "/api/fleet/keys-remove",
                                             token, {"id": key_id})
            assert status == 200
            assert not any(k["id"] == key_id for k in body["keys"])
        finally:
            console.stop()
            await host.stop_all()
            await node.stop()

    async def test_base64_upload_is_accepted(self):
        node, console, host, _ = await _make(enabled=True)
        try:
            _status, token = await _login(console)
            encoded = "b64:" + base64.b64encode(self.KEY.encode()).decode()
            status, _, _, body = await _post(console, "/api/fleet/keys", token,
                                             {"name": "k", "data": encoded})
            assert status == 200 and body["ok"] is True
        finally:
            console.stop()
            await host.stop_all()
            await node.stop()

    async def test_junk_is_refused(self):
        node, console, host, _ = await _make(enabled=True)
        try:
            _status, token = await _login(console)
            for data in ("hello", "", None, 42,
                         "ssh-ed25519 AAAAC3Nz me@host"):
                status, _, _, body = await _post(console, "/api/fleet/keys",
                                                 token, {"name": "k", "data": data})
                assert status == 400 and body["ok"] is False
        finally:
            console.stop()
            await host.stop_all()
            await node.stop()

    async def test_upload_requires_a_session(self):
        node, console, host, _ = await _make(enabled=True)
        try:
            status, _, _, _ = await _post(console, "/api/fleet/keys", None,
                                          {"name": "k", "data": self.KEY})
            assert status == 401
        finally:
            console.stop()
            await host.stop_all()
            await node.stop()

    async def test_uploaded_key_is_offered_for_provisioning(self):
        """Le pont doit résoudre l'id choisi en *matériel*, puisque la machine
        qui s'en servira n'a aucun chemin vers ce fichier."""
        node, console, host, built = await _make(enabled=True)
        try:
            _status, token = await _login(console)
            _s, _h, _b, body = await _post(console, "/api/fleet/keys", token,
                                           {"name": "k", "data": self.KEY})
            bridge = host.bridge("fleet")
            path, material = bridge._resolve_key(body["key"]["id"], None)
            assert path is None and material == self.KEY
            # Une clé du disque voyage à l'inverse par son chemin.
            path, material = bridge._resolve_key("file:/home/me/.ssh/id", None)
            assert path == "/home/me/.ssh/id" and material is None
        finally:
            console.stop()
            await host.stop_all()
            await node.stop()
