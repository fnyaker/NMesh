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
import json
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


async def _post(console, path, token, body, headers=None):
    return await asyncio.to_thread(_request, console, "POST", path, token, body,
                                   None, False, None, headers)


async def _get(console, path, token=None, headers=None):
    return await asyncio.to_thread(_request, console, "GET", path, token, None,
                                   None, False, None, headers)


class TestTheTerminalPage:
    """`/term` rides with the fleet app: no fleet, no page — the same rule as
    every other sub-page, so a console with the app off has no dead route."""

    async def test_it_is_served_only_when_the_app_runs(self):
        node, console, host, _ = await _make(enabled=False)
        try:
            for path in ("/term", "/term.js", "/term.css"):
                status, _, _, _ = await _get(console, path)
                assert status == 404
        finally:
            console.stop()
            await host.stop_all()
            await node.stop()

    async def test_the_page_is_public_and_its_api_is_not(self):
        """Like /fleet: the markup is public, the session guards every call it
        makes. A login form behind a login is not a login form."""
        node, console, host, _ = await _make(enabled=True)
        try:
            for path in ("/term", "/term.js", "/term.css"):
                status, _, body, _ = await _get(console, path)
                assert status == 200 and body
            status, _, _, _ = await _get(console, "/api/fleet/files?node="
                                         + "ee" * 20)
            assert status == 401
        finally:
            console.stop()
            await host.stop_all()
            await node.stop()


class TestFileRoutes:
    async def test_they_need_a_session_and_a_real_node(self):
        node, console, host, _built = await _make(enabled=True)
        try:
            status, _, _, _ = await _get(console, "/api/fleet/files?node=zz")
            assert status == 401
            _status, token = await _login(console)
            for path in ("/api/fleet/files?node=nothex",
                         "/api/fleet/file?node=nothex&path=/tmp"):
                status, _, _, data = await _get(console, path, token)
                assert status == 400 and "node" in data["error"]
        finally:
            console.stop()
            await host.stop_all()
            await node.stop()

    async def test_a_node_that_granted_nothing_is_refused_here(self):
        """Refused by this console, before it costs a round trip: an operation
        that can only come back denied is one to stop at home."""
        node, console, host, built = await _make(enabled=True)
        try:
            _status, token = await _login(console)
            built["app"].state.add_managed("ee" * 20, caps=["status"])
            status, _, _, data = await _get(
                console, "/api/fleet/files?node=" + "ee" * 20, token)
            assert status == 502 and "has not granted" in data["error"]
            status, _, _, data = await _post(console, "/api/fleet/mkdir", token,
                                             {"node": "ee" * 20, "path": "/tmp",
                                              "name": "x"})
            assert status == 502 and "has not granted" in data["error"]
        finally:
            console.stop()
            await host.stop_all()
            await node.stop()

    async def test_an_upload_without_a_file_is_a_bad_request(self):
        node, console, host, built = await _make(enabled=True)
        try:
            _status, token = await _login(console)
            built["app"].state.add_managed("ee" * 20, caps=["shell"])
            status, _, _, data = await _post(console, "/api/fleet/upload", token,
                                             {"node": "ee" * 20, "path": "/tmp"})
            assert status == 400 and "file" in data["error"]
            status, _, _, data = await _post(console, "/api/fleet/upload", token,
                                             {"node": "ee" * 20, "path": "/tmp",
                                              "data": "aGk=", "name": ""})
            assert status == 400 and "name" in data["error"]
        finally:
            console.stop()
            await host.stop_all()
            await node.stop()

    async def test_a_shell_can_be_found_by_node_rather_than_by_sid(self):
        """The terminal page has just asked for a shell and knows the node, not
        the session — the open answers asynchronously."""
        node, console, host, built = await _make(enabled=True)
        try:
            _status, token = await _login(console)
            status, _, _, _ = await _get(
                console, "/api/fleet/shell?node=" + "ee" * 20, token)
            assert status == 404
            bridge = host.bridge("fleet")
            bridge._open_shell_record("ab" * 16, "ee" * 20)
            status, _, _, data = await _get(
                console, "/api/fleet/shell?node=" + "ee" * 20, token)
            assert status == 200 and data["sid"] == "ab" * 16
        finally:
            console.stop()
            await host.stop_all()
            await node.stop()


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

    async def test_caps_routes_reach_the_ledger(self):
        """The three rights routes, over HTTP: what a human here may set, and
        what a node we manage may only ask for."""
        node, console, host, built = await _make(enabled=True)
        try:
            _status, token = await _login(console)
            app = built["app"]
            peer = "cc" * 20
            app.state.add_operator(peer, b"\x01" * 32, caps=["status"],
                                   label="boss")
            status, _, _, _ = await _post(console, "/api/fleet/caps-set", token,
                                          {"node": peer,
                                           "caps": ["status", "update"]})
            assert status == 200
            assert app.state.allows(peer, "update") is True

            # Nothing to change on a node we do not manage.
            status, _, _, _ = await _post(console, "/api/fleet/caps-request",
                                          token, {"node": "dd" * 20,
                                                  "caps": ["shell"]})
            assert status == 400
            status, _, _, _ = await _post(console, "/api/fleet/caps-drop", token,
                                          {"node": "dd" * 20, "caps": ["shell"]})
            assert status == 400
        finally:
            console.stop()
            await host.stop_all()
            await node.stop()

    async def test_caps_routes_refuse_junk(self):
        node, console, host, built = await _make(enabled=True)
        try:
            _status, token = await _login(console)
            peer = "cc" * 20
            built["app"].state.add_operator(peer, b"\x01" * 32, caps=["status"])
            for route, body in (("caps-set", {"node": "nothex", "caps": ["status"]}),
                                ("caps-set", {"node": peer, "caps": ["root"]}),
                                ("caps-request", {"node": peer, "caps": []}),
                                ("caps-drop", {"node": peer, "caps": "shell"})):
                status, _, _, _ = await _post(console, "/api/fleet/" + route,
                                              token, body)
                assert status in (400, 503), (route, body)
            # An unknown capability must not have quietly become a grant.
            assert set(built["app"].state.operator(peer)["caps"]) == {"status"}
        finally:
            console.stop()
            await host.stop_all()
            await node.stop()

    async def test_remote_targets_lists_only_manage_grants(self):
        """The context selector offers only what has been granted."""
        node, console, host, built = await _make(enabled=True)
        try:
            _status, token = await _login(console)
            state = built["app"].state
            managed = "ee" * 20
            other = "ff" * 20
            state.add_managed(managed, caps=["status", "manage"], label="edge")
            state.add_managed(other, caps=["status"], label="sensor")
            _s, _h, _b, data = await _get(console, "/api/remote/targets", token)
            assert data["available"] is True
            ids = [entry["id"] for entry in data["targets"]]
            assert ids == [managed]
            assert data["targets"][0]["connected"] is False
            # The page has to know which of two things to ask for.
            assert data["targets"][0]["passwordless"] is False
        finally:
            console.stop()
            await host.stop_all()
            await node.stop()

    async def test_remote_routes_need_a_session_and_a_grant(self):
        node, console, host, built = await _make(enabled=True)
        try:
            # No session at all.
            status, _, _, _ = await _get(console, "/api/remote/targets", None)
            assert status == 401
            _status, token = await _login(console)
            # A node we do not manage cannot be connected to.
            status, _, _, data = await _post(console, "/api/remote/connect", token,
                                             {"node": "ee" * 20, "password": "x" * 12})
            assert status == 403 and "granted" in data["error"]
            # `manage` alone does not make the password optional.
            built["app"].state.add_managed("ee" * 20, caps=["manage"])
            status, _, _, data = await _post(console, "/api/remote/connect", token,
                                             {"node": "ee" * 20})
            assert status == 403 and "password" in data["error"]
            # Nor is a real node id.
            status, _, _, _ = await _post(console, "/api/remote/connect", token,
                                          {"node": "nothex", "password": "x" * 12})
            assert status == 400
        finally:
            console.stop()
            await host.stop_all()
            await node.stop()

    async def test_a_passwordless_grant_connects_with_no_password(self):
        """A machine this operator provisioned never had a password they could
        type: the grant is the key, and the page must be able to use it."""
        node, console, host, built = await _make(enabled=True)
        try:
            _status, token = await _login(console)
            target = "ee" * 20
            built["app"].state.add_managed(target,
                                           caps=["manage", "passwordless"])

            async def session(node_id):
                assert node_id.raw.hex() == target
                return "granted-token"

            built["app"].console_session = session
            status, _, _, data = await _post(console, "/api/remote/connect",
                                             token, {"node": target})
            assert status == 200 and data["ok"] is True
            _s, _h, _b, targets = await _get(console, "/api/remote/targets", token)
            row = targets["targets"][0]
            assert row["passwordless"] is True and row["connected"] is True
        finally:
            console.stop()
            await host.stop_all()
            await node.stop()

    async def test_the_context_header_without_a_session_is_refused(self):
        """With no remote session the request is refused — never run locally.
        An ignored header would act on the wrong machine."""
        node, console, host, built = await _make(enabled=True)
        try:
            _status, token = await _login(console)
            built["app"].state.add_managed("ee" * 20, caps=["manage"])
            status, _, _, data = await _get(console, "/api/state", token,
                                            headers={"X-NMesh-Node": "ee" * 20})
            assert status == 409
            assert "connect" in data["error"]
            status, _, _, _ = await _get(console, "/api/state", token,
                                         headers={"X-NMesh-Node": "nothex"})
            assert status == 400
        finally:
            console.stop()
            await host.stop_all()
            await node.stop()

    async def test_our_own_id_in_the_header_stays_local(self):
        """Naming ourselves is not a round trip through the mesh."""
        node, console, host, _built = await _make(enabled=True)
        try:
            _status, token = await _login(console)
            status, _, _, data = await _get(console, "/api/state", token,
                                            headers={"X-NMesh-Node": node.id.raw.hex()})
            assert status == 200 and data["id"] == node.id.raw.hex()
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


class TestInviteRoute:
    """`POST /api/fleet/invite` is the one fleet route that waits for its own
    answer: what comes back *is* the invitation, and a page cannot poll for a
    secret it has to show exactly once."""

    async def test_it_hands_back_the_invitation_the_node_minted(self):
        node, console, host, built = await _make(enabled=True)
        try:
            _status, token = await _login(console)
            app = built["app"]
            target = "cd" * 20
            # Stand in for the far node: the reply arrives as if it had come
            # back over the mesh, against the request id the bridge minted.
            original = app.request_invite

            async def _answer(node_id, *, ttl=None, ticket=False):
                rid = await original(node_id, ttl=ttl, ticket=ticket)
                app._on_invite_issued(node_id, {
                    "rid": rid, "code": "abcdefghij", "uris": ["tcp://h:9"],
                    "ticket": "TICKET" if ticket else "",
                    "expires_at": 1000.0, "ttl": ttl or 300})
                return rid
            app.request_invite = _answer
            status, _, _, body = await _post(
                console, "/api/fleet/invite", token,
                {"node": target, "ttl": 3600, "ticket": True})
            assert status == 200
            assert body["code"] == "abcdefghij"
            assert body["ticket"] == "TICKET"
            assert body["qr_svg"].startswith("<svg")
        finally:
            console.stop(); await host.stop_all(); await node.stop()

    async def test_an_invitation_is_handed_over_once(self):
        """It is a single-use secret. A console that re-serves it leaves it on
        the screen of whoever opens the fleet page next."""
        node, console, host, built = await _make(enabled=True)
        try:
            bridge = host.bridge("fleet")
            from src.apps.fleet import InviteIssued
            bridge._record_invite("cd" * 20, InviteIssued(
                NodeID(bytes.fromhex("cd" * 20)), "aa" * 8, [], "code", "", 0, 300))
            assert bridge.take_invite("cd" * 20)["code"] == "code"
            assert bridge.take_invite("cd" * 20) is None
            # And it never rides along in the polled snapshot.
            assert "code" not in json.dumps(bridge.snapshot())
        finally:
            console.stop(); await host.stop_all(); await node.stop()

    async def test_it_needs_a_session(self):
        node, console, host, _ = await _make(enabled=True)
        try:
            status, _, _, _ = await _post(console, "/api/fleet/invite", None,
                                          {"node": "cd" * 20})
            assert status == 401
        finally:
            console.stop(); await host.stop_all(); await node.stop()


class TestOperationTracking:
    """A remote action answers asynchronously. With no tracking, the page has
    no way of saying whether it succeeded, failed, or is still running — which
    is exactly what made a remote scan look like it "did nothing"."""

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
        """A nearby peer answers in under a millisecond, before the calling
        thread has even noted the rid. Closing must not depend on that order —
        or the operation stays "in progress" forever."""
        node, app, bridge = await self._bridge()
        try:
            rid = "ff" * 8
            bridge._finish(rid, "ok", "arrived early")   # before the _job
            bridge._job(rid, "scan", "aa" * 20)
            job = next(j for j in bridge.snapshot()["jobs"] if j["rid"] == rid)
            assert job["state"] == "ok" and job["detail"] == "arrived early"
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
    """Importing a key from the console — the only way to give one to a node in
    a container, where `~/.ssh` does not exist."""

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
        """The bridge has to resolve the chosen id into *material*, since the
        machine that will use it has no path to that file."""
        node, console, host, built = await _make(enabled=True)
        try:
            _status, token = await _login(console)
            _s, _h, _b, body = await _post(console, "/api/fleet/keys", token,
                                           {"name": "k", "data": self.KEY})
            bridge = host.bridge("fleet")
            path, material = bridge._resolve_key(body["key"]["id"], None)
            assert path is None and material == self.KEY
            # A key from disk travels the other way, by its path.
            path, material = bridge._resolve_key("file:/home/me/.ssh/id", None)
            assert path == "/home/me/.ssh/id" and material is None
        finally:
            console.stop()
            await host.stop_all()
            await node.stop()


class TestAppApiOverHttp:
    """The single door, seen from the browser. What matters here is that it is
    still a door: authenticated, only for what an app declared, and no wider
    than the app's own rules."""

    async def test_the_catalogue_needs_a_session(self):
        node, console, host, _ = await _make(enabled=True)
        try:
            status, _, _, _ = await _get(console, "/api/app-api")
            assert status == 401
            status, _, _, _ = await _post(console, "/api/app-call", None,
                                          {"app": "fleet", "op": "relation",
                                           "args": {"node": "ab" * 20}})
            assert status == 401
        finally:
            console.stop(); await host.stop_all(); await node.stop()

    async def test_the_catalogue_lists_the_running_apps(self):
        node, console, host, _ = await _make(enabled=True)
        try:
            _status, token = await _login(console)
            status, _, _, body = await _get(console, "/api/app-api", token)
            assert status == 200
            apps = {entry["app"]: entry for entry in body["apps"]}
            assert "fleet" in apps
            names = {op["name"] for op in apps["fleet"]["operations"]}
            assert names == {"relation", "enrol", "request", "invite"}
        finally:
            console.stop(); await host.stop_all(); await node.stop()

    async def test_a_disabled_app_offers_nothing_and_answers_nothing(self):
        node, console, host, _ = await _make(enabled=False)
        try:
            _status, token = await _login(console)
            _s, _h, _b, body = await _get(console, "/api/app-api", token)
            assert body["apps"] == []
            status, _, _, body = await _post(console, "/api/app-call", token,
                                             {"app": "fleet", "op": "relation",
                                              "args": {"node": "ab" * 20}})
            assert status == 400 and body["ok"] is False
        finally:
            console.stop(); await host.stop_all(); await node.stop()

    async def test_a_declared_read_answers_with_the_ledger(self):
        node, console, host, _ = await _make(enabled=True)
        try:
            _status, token = await _login(console)
            status, _, _, body = await _post(console, "/api/app-call", token,
                                             {"app": "fleet", "op": "relation",
                                              "args": {"node": "ab" * 20}})
            assert status == 200 and body["ok"] is True
            result = body["result"]
            assert result["managed"] is False and result["operator"] is False
            assert any(cap["name"] == "status" and cap["description"]
                       for cap in result["capabilities"])
        finally:
            console.stop(); await host.stop_all(); await node.stop()

    async def test_an_undeclared_operation_is_refused(self):
        node, console, host, _ = await _make(enabled=True)
        try:
            _status, token = await _login(console)
            for op in ("revoke", "open_shell", "snapshot", "api_relation",
                       "__init__"):
                status, _, _, body = await _post(
                    console, "/api/app-call", token,
                    {"app": "fleet", "op": op, "args": {"node": "ab" * 20}})
                assert status == 400, op
                assert body["ok"] is False
        finally:
            console.stop(); await host.stop_all(); await node.stop()

    async def test_a_malformed_call_is_refused_before_the_app_sees_it(self):
        node, console, host, _ = await _make(enabled=True)
        try:
            _status, token = await _login(console)
            for payload in ({}, {"app": "fleet"}, {"op": "relation"},
                            {"app": 7, "op": "relation"},
                            {"app": "fleet", "op": "relation", "args": {"node": "nope"}},
                            {"app": "fleet", "op": "relation",
                             "args": {"node": "ab" * 20, "extra": 1}}):
                status, _, _, _ = await _post(console, "/api/app-call", token, payload)
                assert status == 400, payload
        finally:
            console.stop(); await host.stop_all(); await node.stop()

    async def test_asking_for_rights_still_goes_through_the_app(self):
        """`enrol` reached this way is the same `enrol` the fleet page calls: it
        sends a request and a human on the other machine answers. Nothing about
        arriving through the app API grants anything."""
        node, console, host, built = await _make(enabled=True)
        try:
            _status, token = await _login(console)
            status, _, _, body = await _post(
                console, "/api/app-call", token,
                {"app": "fleet", "op": "enrol",
                 "args": {"node": "cd" * 20, "caps": ["status"], "label": "nas"}})
            assert status == 200
            # The ledger records a request, never a granted capability.
            state = built["app"].state
            assert state.managed_one("cd" * 20) is None
            assert any(row["id"] == "cd" * 20 for row in state.pending_out())
        finally:
            console.stop(); await host.stop_all(); await node.stop()

    async def test_a_capability_it_never_asked_for_is_refused(self):
        node, console, host, _ = await _make(enabled=True)
        try:
            _status, token = await _login(console)
            status, _, _, body = await _post(
                console, "/api/app-call", token,
                {"app": "fleet", "op": "enrol",
                 "args": {"node": "cd" * 20, "caps": ["root", "everything"]}})
            # clean_caps drops what is not a capability; nothing was asked.
            assert status == 200 and body["result"]["sent"] is False
        finally:
            console.stop(); await host.stop_all(); await node.stop()
