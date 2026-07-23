"""
Web console tests.

The console is the node's remote management plane, so these focus on the
security boundary: no access without auth, brute-force lockout, bearer-token
enforcement, request-size cap, and that the management actions actually touch
node state. A real server runs on an ephemeral loopback port; HTTP calls run in
a worker thread so the event loop stays free to service the console's
run_coroutine_threadsafe bridge.
"""
import asyncio
import base64
import http.client
import json
import os
import ssl
import tempfile

import pytest

from src.node import MeshNode
from src.node_id import NodeID
from src.webconsole import WebConsole, _LOGIN_MAX_FAILURES
from tests.conftest import make_manager

PW = "correct-horse-battery-staple"


async def _make_console(**kwargs):
    node = MeshNode(transport_manager=make_manager())
    await node._inject_peer(_FakeAuthPeerTransport())  # give it one peer to show
    console = WebConsole(node, host="127.0.0.1", port=0, use_tls=False,
                         password=PW, **kwargs)
    console.start(loop=asyncio.get_running_loop())
    return node, console


class _FakeAuthPeerTransport:
    """Minimal transport that never yields packets (keeps a peer 'connected')."""
    def __init__(self):
        self.on_connect = None
    async def connect(self, a): ...
    async def listen(self, a): ...
    async def send(self, p): ...
    async def close(self): ...
    async def receive(self):
        await asyncio.Event().wait()  # block forever


def _request(console, method, path, token=None, body=None, raw=None, tls=False,
             cookie=None):
    """Blocking HTTP request — call via asyncio.to_thread."""
    if tls:
        ctx = ssl._create_unverified_context()
        conn = http.client.HTTPSConnection(console.host, console.port,
                                           timeout=8, context=ctx)
    else:
        conn = http.client.HTTPConnection(console.host, console.port, timeout=8)
    headers = {}
    if token:
        headers["Authorization"] = "Bearer " + token
    if cookie:
        headers["Cookie"] = cookie
    data = raw
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    conn.request(method, path, body=data, headers=headers)
    r = conn.getresponse()
    payload = r.read()
    hdrs = {k.lower(): v for k, v in r.getheaders()}
    conn.close()
    try:
        parsed = json.loads(payload) if payload else None
    except Exception:
        parsed = None
    return r.status, hdrs, payload, parsed


async def _login(console, password=PW):
    status, _, _, j = await asyncio.to_thread(
        _request, console, "POST", "/api/login", None, {"password": password})
    return status, (j or {}).get("token")


# ---------------------------------------------------------------------------

class TestAuth:
    async def test_state_requires_auth(self):
        node, console = await _make_console()
        try:
            status, _, _, _ = await asyncio.to_thread(_request, console, "GET", "/api/state")
            assert status == 401
        finally:
            console.stop(); await node.stop()

    async def test_wrong_password_rejected(self):
        node, console = await _make_console()
        try:
            status, token = await _login(console, "nope")
            assert status == 401 and token is None
        finally:
            console.stop(); await node.stop()

    async def test_login_lockout(self):
        node, console = await _make_console()
        try:
            for _ in range(_LOGIN_MAX_FAILURES):
                await _login(console, "wrong")
            # Locked now — even the correct password is refused with 429.
            status, _, _, _ = await asyncio.to_thread(
                _request, console, "POST", "/api/login", None, {"password": PW})
            assert status == 429
        finally:
            console.stop(); await node.stop()

    async def test_login_then_state(self):
        node, console = await _make_console()
        try:
            status, token = await _login(console)
            assert status == 200 and token
            status, hdrs, _, snap = await asyncio.to_thread(
                _request, console, "GET", "/api/state", token)
            assert status == 200
            for key in ("id", "peers", "total", "load", "routing", "uptime",
                        "advertised", "listen", "local_ips", "transports",
                        "listening", "network", "transport_details",
                        "punch_enabled", "join_status", "reachability",
                        "relay_capable", "pending_seeks", "lan_discovery"):
                assert key in snap
            assert snap["id"] == node.id.raw.hex()
            assert "fake" in snap["transports"]
            assert "content-security-policy" in hdrs
        finally:
            console.stop(); await node.stop()

    async def test_bad_token_rejected(self):
        node, console = await _make_console()
        try:
            status, _, _, _ = await asyncio.to_thread(
                _request, console, "GET", "/api/state", "not-a-real-token")
            assert status == 401
        finally:
            console.stop(); await node.stop()

    async def test_logout_revokes_token(self):
        node, console = await _make_console()
        try:
            _, token = await _login(console)
            await asyncio.to_thread(_request, console, "POST", "/api/logout", token)
            status, _, _, _ = await asyncio.to_thread(
                _request, console, "GET", "/api/state", token)
            assert status == 401
        finally:
            console.stop(); await node.stop()

    async def test_login_sets_session_cookie(self):
        node, console = await _make_console()
        try:
            status, hdrs, _, _ = await asyncio.to_thread(
                _request, console, "POST", "/api/login", None, {"password": PW})
            assert status == 200
            sc = hdrs.get("set-cookie", "")
            assert sc.startswith("nmesh_session=")
            assert "HttpOnly" in sc and "SameSite=Strict" in sc
            # No TLS here, so the Secure attribute must be absent (else the
            # browser would drop the cookie on the plain-HTTP console).
            assert "Secure" not in sc
        finally:
            console.stop(); await node.stop()

    async def test_cookie_authenticates_without_bearer(self):
        # A refresh sends only the cookie (no Authorization header). It must be
        # accepted on its own — that is the whole point of the session cookie.
        node, console = await _make_console()
        try:
            _, token = await _login(console)
            cookie = "nmesh_session=" + token
            status, _, _, _ = await asyncio.to_thread(
                _request, console, "GET", "/api/state", None, None, None, False, cookie)
            assert status == 200
        finally:
            console.stop(); await node.stop()

    async def test_logout_clears_cookie_and_revokes(self):
        node, console = await _make_console()
        try:
            _, token = await _login(console)
            cookie = "nmesh_session=" + token
            _, hdrs, _, _ = await asyncio.to_thread(
                _request, console, "POST", "/api/logout", None, None, None, False, cookie)
            assert "max-age=0" in hdrs.get("set-cookie", "").lower()
            # The token behind the cookie is revoked, not just the cookie dropped.
            status, _, _, _ = await asyncio.to_thread(
                _request, console, "GET", "/api/state", None, None, None, False, cookie)
            assert status == 401
        finally:
            console.stop(); await node.stop()

    async def test_secure_cookie_under_tls(self):
        node = MeshNode(transport_manager=make_manager())
        console = WebConsole(node, host="127.0.0.1", port=0, use_tls=True, password=PW)
        console.start(loop=asyncio.get_running_loop())
        try:
            _, hdrs, _, _ = await asyncio.to_thread(
                _request, console, "POST", "/api/login", None, {"password": PW},
                None, True)
            assert "Secure" in hdrs.get("set-cookie", "")
        finally:
            console.stop(); await node.stop()


class TestAppStore:
    async def test_publish_install_uninstall_via_api(self):
        node, console = await _make_console()
        try:
            _, token = await _login(console)
            files = {"main.py": base64.b64encode(b"print('hi')\n").decode()}
            status, _, _, j = await asyncio.to_thread(
                _request, console, "POST", "/api/store/publish", token,
                {"name": "widget", "version": "1.0.0", "files": files})
            assert status == 200 and j["ok"]
            app_id = j["app_id"]

            # The catalog view (computed in Python) shows it as installable.
            status, _, _, view = await asyncio.to_thread(
                _request, console, "GET", "/api/store", token)
            assert status == 200
            entry = next(a for a in view["catalog"] if a["app_id"] == app_id)
            assert entry["state"] == "install" and entry["action"] == "install"

            # Install, then the view flips to installed with no action.
            status, _, _, j = await asyncio.to_thread(
                _request, console, "POST", "/api/store/install", token, {"app_id": app_id})
            assert status == 200 and j["ok"]
            _, _, _, view = await asyncio.to_thread(_request, console, "GET", "/api/store", token)
            entry = next(a for a in view["catalog"] if a["app_id"] == app_id)
            assert entry["state"] == "installed" and entry["action"] is None
            assert any(m["app_id"] == app_id for m in view["installed"])

            # Uninstall.
            status, _, _, j = await asyncio.to_thread(
                _request, console, "POST", "/api/store/uninstall", token, {"app_id": app_id})
            assert status == 200 and j["ok"]
            _, _, _, view = await asyncio.to_thread(_request, console, "GET", "/api/store", token)
            assert not view["installed"]
        finally:
            console.stop(); await node.stop()

    async def test_store_requires_auth(self):
        node, console = await _make_console()
        try:
            status, _, _, _ = await asyncio.to_thread(_request, console, "GET", "/api/store")
            assert status == 401
        finally:
            console.stop(); await node.stop()

    async def test_store_action_needs_app_id(self):
        node, console = await _make_console()
        try:
            _, token = await _login(console)
            status, _, _, _ = await asyncio.to_thread(
                _request, console, "POST", "/api/store/install", token, {})
            assert status == 400
        finally:
            console.stop(); await node.stop()


class TestListEndpoints:
    @pytest.mark.parametrize("path", [
        "/api/nodes?scope=active",
        "/api/nodes?scope=known",
        "/api/store/catalog",
        "/api/store/installed",
    ])
    async def test_lists_require_auth(self, path):
        node, console = await _make_console()
        try:
            status, _, _, _ = await asyncio.to_thread(
                _request, console, "GET", path)
            assert status == 401
        finally:
            console.stop(); await node.stop()

    async def test_node_scopes_search_ids_and_routing_addresses(self):
        node, console = await _make_console()
        try:
            direct_id = NodeID(b"\x01" * 20)
            known_id = NodeID(b"\x02" * 20)
            peer = node._peers[0]
            peer.authenticated_id = direct_id
            peer.session = object()
            peer.remote_addr = "fake://direct.example:7"
            peer.dsa_pub = b"direct-key"
            peer.last_rtt = 0.01234
            node._routing.add(
                direct_id, ["tcp://Route-Needle.example:9000"], b"route-key")
            node._routing.add(
                known_id, ["spool:///var/drop/address-match"], b"known-key")

            _, token = await _login(console)
            status, _, _, page = await asyncio.to_thread(
                _request, console, "GET",
                "/api/nodes?scope=active&q=route-needle", token)
            assert status == 200
            assert {"items", "total", "limit", "offset"} == set(page)
            assert page["total"] == 1 and page["limit"] == 20 and page["offset"] == 0
            active = page["items"][0]
            assert active["id"] == direct_id.raw.hex()
            assert active["authenticated_id"] == direct_id.raw.hex()
            assert active["connected"] is True and active["has_session"] is True
            assert active["rtt_ms"] == 12.3 and active["has_key"] is True
            assert active["addresses"] == [
                "fake://direct.example:7", "tcp://Route-Needle.example:9000"]

            status, _, _, page = await asyncio.to_thread(
                _request, console, "GET",
                "/api/nodes?scope=known&q=ADDRESS-MATCH", token)
            assert status == 200 and page["total"] == 1
            assert page["items"][0]["id"] == known_id.raw.hex()
            assert page["items"][0]["addresses"] == [
                "spool:///var/drop/address-match"]

            status, _, _, page = await asyncio.to_thread(
                _request, console, "GET",
                f"/api/nodes?scope=known&q={direct_id.raw.hex()[4:20]}", token)
            assert status == 200 and page["total"] == 1
            assert page["items"][0]["connected"] is True
        finally:
            console.stop(); await node.stop()

    async def test_store_lists_search_paginate_and_keep_fields(self):
        node, console = await _make_console()
        try:
            for i in range(205):
                app_id = i.to_bytes(20, "big")
                node._catalog._apps[app_id] = {
                    "app_id": app_id,
                    "release": b"release",
                    "release_id": (i + 1000).to_bytes(20, "big"),
                    "name": "Needle Suite" if i == 17 else f"App {i:03d}",
                    "version": f"1.0.{i}",
                    "author": (i + 500).to_bytes(20, "big"),
                    "root_key": (i + 2000).to_bytes(20, "big"),
                    "ts": i,
                }
            installed_id = (17).to_bytes(20, "big").hex()
            installed = {
                "app_id": installed_id,
                "name": "Needle Suite",
                "version": "1.0.17",
                "author": (517).to_bytes(20, "big").hex(),
                "release_id": (1017).to_bytes(20, "big").hex(),
                "ts": 17,
                "installed_ts": 123456,
            }
            node._installed._apps[installed_id] = installed
            _, token = await _login(console)

            status, _, _, page = await asyncio.to_thread(
                _request, console, "GET",
                "/api/store/catalog?q=needle", token)
            assert status == 200 and page["total"] == 1
            assert page["items"][0]["state"] == "installed"
            assert page["items"][0]["action"] is None

            status, _, _, page = await asyncio.to_thread(
                _request, console, "GET",
                "/api/store/installed?q=1.0.17", token)
            assert status == 200 and page["items"] == [installed]

            status, _, _, page = await asyncio.to_thread(
                _request, console, "GET",
                "/api/store/catalog?limit=100&offset=100", token)
            assert status == 200
            assert page["total"] == 205 and len(page["items"]) == 100
            assert page["limit"] == 100 and page["offset"] == 100
            assert page["items"][0]["app_id"] == (104).to_bytes(20, "big").hex()

            status, _, _, page = await asyncio.to_thread(
                _request, console, "GET",
                "/api/store/catalog?limit=100&offset=200", token)
            assert status == 200 and len(page["items"]) == 5
        finally:
            console.stop(); await node.stop()

    async def test_malformed_list_queries_are_rejected(self):
        node, console = await _make_console()
        try:
            _, token = await _login(console)
            bad_paths = [
                "/api/nodes",
                "/api/nodes?scope=all",
                "/api/nodes?scope=active&scope=known",
                "/api/nodes?scope=known&q=" + "x" * 129,
                "/api/nodes?scope=known&limit=0",
                "/api/nodes?scope=known&limit=101",
                "/api/nodes?scope=known&limit=-1",
                "/api/nodes?scope=known&limit=1.5",
                "/api/nodes?scope=known&offset=-1",
                "/api/nodes?scope=known&offset=nope",
                "/api/store/catalog?scope=known",
                "/api/store/installed?q=a&q=b",
                "/api/store/installed?q=%ZZ",
            ]
            for path in bad_paths:
                status, _, _, _ = await asyncio.to_thread(
                    _request, console, "GET", path, token)
                assert status == 400, path
        finally:
            console.stop(); await node.stop()


class TestManagement:
    async def test_generate_invite(self):
        node, console = await _make_console()
        try:
            _, token = await _login(console)
            status, _, _, j = await asyncio.to_thread(
                _request, console, "POST", "/api/invite", token)
            assert status == 200 and j["code"]
            assert node._invite.verify_response  # sanity
            assert j["code"] in node._invite._codes
        finally:
            console.stop(); await node.stop()

    async def test_join_requires_fields(self):
        node, console = await _make_console()
        try:
            _, token = await _login(console)
            status, _, _, _ = await asyncio.to_thread(
                _request, console, "POST", "/api/join", token, {"uri": "tcp://x:1"})
            assert status == 400
        finally:
            console.stop(); await node.stop()

    async def test_trust_certificate_roundtrip(self):
        node_a, console_a = await _make_console()
        node_b = MeshNode(transport_manager=make_manager())
        try:
            _, token = await _login(console_a)
            cert_hex = node_b.console_root_cert_hex()
            status, _, _, j = await asyncio.to_thread(
                _request, console_a, "POST", "/api/trust", token, {"cert_hex": cert_hex})
            assert status == 200 and j["ok"] is True
            assert node_a._cert_store.is_root(node_b.id)
        finally:
            console_a.stop(); await node_a.stop(); await node_b.stop()

    async def test_trust_rejects_garbage(self):
        node, console = await _make_console()
        try:
            _, token = await _login(console)
            status, _, _, j = await asyncio.to_thread(
                _request, console, "POST", "/api/trust", token, {"cert_hex": "deadbeef"})
            assert status == 400 and j["ok"] is False
        finally:
            console.stop(); await node.stop()

    async def test_invite_block_roundtrip(self):
        node, console = await _make_console()
        try:
            _, token = await _login(console)
            status, _, _, j = await asyncio.to_thread(
                _request, console, "POST", "/api/invite/block", token)
            assert status == 200 and j["block"]
            data = json.loads(base64.b64decode(j["block"]))
            assert data["v"] == 1 and data["code"] in node._invite._codes
        finally:
            console.stop(); await node.stop()

    async def test_join_block_rejects_garbage(self):
        node, console = await _make_console()
        try:
            _, token = await _login(console)
            for bad in ({"block": "not-base64!!!"}, {"block": ""}, {}):
                status, _, _, j = await asyncio.to_thread(
                    _request, console, "POST", "/api/join/block", token, bad)
                assert status == 400 and j["ok"] is False
        finally:
            console.stop(); await node.stop()

    async def test_connect_request_and_accept(self):
        # host node accepts a request block and returns an invite block
        node, console = await _make_console()
        try:
            _, token = await _login(console)
            status, _, _, j = await asyncio.to_thread(
                _request, console, "POST", "/api/connect/request", token)
            assert status == 200 and j["block"]
            # a request block with a fake-supported address is accepted
            from src.node import _encode_conn_block
            req = _encode_conn_block("req", uris=["fake://peer:1"])
            status, _, _, j = await asyncio.to_thread(
                _request, console, "POST", "/api/connect/accept", token,
                {"block": req})
            assert status == 200 and j["ok"] is True and j["block"]
            from src.node import _decode_conn_block
            inv = _decode_conn_block(j["block"], "inv")
            assert inv["code"] in node._invite._codes
        finally:
            console.stop(); await node.stop()

    async def test_connect_endpoints_reject_garbage(self):
        node, console = await _make_console()
        try:
            _, token = await _login(console)
            for path in ("/api/connect/accept", "/api/connect/complete"):
                for bad in ({"block": "not-base64!!!"}, {"block": ""}, {}):
                    status, _, _, j = await asyncio.to_thread(
                        _request, console, "POST", path, token, bad)
                    assert status == 400 and j["ok"] is False
        finally:
            console.stop(); await node.stop()

    async def test_relay_invite_and_join_endpoints(self):
        node, console = await _make_console()
        try:
            _, token = await _login(console)
            status, _, _, j = await asyncio.to_thread(
                _request, console, "POST", "/api/relay/invite", token)
            assert status == 200 and j["block"]
            import base64 as _b64, json as _json
            data = _json.loads(_b64.b64decode(j["block"]))
            assert data["v"] == 3 and data["kind"] == "relay-inv"
            # join with garbage → validation error surfaced
            status, _, _, j = await asyncio.to_thread(
                _request, console, "POST", "/api/relay/join", token,
                {"block": "not-base64!!!"})
            assert status == 400 and j["ok"] is False
        finally:
            console.stop(); await node.stop()

    async def test_lan_discovery_toggle(self):
        node, console = await _make_console()
        try:
            _, token = await _login(console)
            status, _, _, j = await asyncio.to_thread(
                _request, console, "POST", "/api/lan/discovery", token,
                {"enabled": True})
            assert status == 200 and j["enabled"] is True
            assert node._lan_discovery is not None
            status, _, _, _ = await asyncio.to_thread(
                _request, console, "POST", "/api/lan/discovery", token,
                {"enabled": False})
            assert status == 200 and node._lan_discovery is None
            # type-checked
            status, _, _, _ = await asyncio.to_thread(
                _request, console, "POST", "/api/lan/discovery", token,
                {"enabled": "yes"})
            assert status == 400
        finally:
            await node.stop_lan_discovery()
            console.stop(); await node.stop()

    async def test_punch_toggle(self):
        node, console = await _make_console()
        try:
            _, token = await _login(console)
            assert node._punch_enabled is True  # on by default
            status, _, _, j = await asyncio.to_thread(
                _request, console, "POST", "/api/punch", token, {"enabled": False})
            assert status == 200 and j["enabled"] is False
            assert node._punch_enabled is False
            status, _, _, _ = await asyncio.to_thread(
                _request, console, "POST", "/api/punch", token, {"enabled": True})
            assert status == 200 and node._punch_enabled is True
            # type-checked input
            status, _, _, _ = await asyncio.to_thread(
                _request, console, "POST", "/api/punch", token, {"enabled": "yes"})
            assert status == 400
        finally:
            console.stop(); await node.stop()

    async def test_punch_keepalive_toggle(self):
        node, console = await _make_console()
        try:
            _, token = await _login(console)
            assert node._punch_keepalive is False
            status, _, _, j = await asyncio.to_thread(
                _request, console, "POST", "/api/punch/keepalive", token,
                {"enabled": True})
            assert status == 200 and j["keepalive"] is True
            assert node._punch_keepalive is True
            status, _, _, _ = await asyncio.to_thread(
                _request, console, "POST", "/api/punch/keepalive", token,
                {"enabled": "nope"})
            assert status == 400
        finally:
            node.console_set_punch_keepalive(False)
            console.stop(); await node.stop()

    async def test_open_hole_endpoint(self):
        node, console = await _make_console()
        try:
            _, token = await _login(console)
            # no UDP listener yet → rejected
            status, _, _, j = await asyncio.to_thread(
                _request, console, "POST", "/api/punch/open", token,
                {"endpoint": "90.54.169.91:9001"})
            assert status == 400 and j["ok"] is False
            await node.start_udp(0, "127.0.0.1")
            node._udp_server._sock.sendto = lambda *a: None  # no real traffic
            status, _, _, j = await asyncio.to_thread(
                _request, console, "POST", "/api/punch/open", token,
                {"endpoint": "90.54.169.91:9001"})
            assert status == 200 and j["ok"] is True
            assert j["host"] == "90.54.169.91" and j["port"] == 9001
            assert ("90.54.169.91", 9001) in node._manual_holes
            # malformed endpoint
            status, _, _, j = await asyncio.to_thread(
                _request, console, "POST", "/api/punch/open", token,
                {"endpoint": "garbage"})
            assert status == 400 and j["ok"] is False
        finally:
            node._cancel_manual_holes()
            console.stop(); await node.stop()

    async def test_punch_requires_auth(self):
        node, console = await _make_console()
        try:
            status, _, _, _ = await asyncio.to_thread(
                _request, console, "POST", "/api/punch", None, {"enabled": False})
            assert status == 401 and node._punch_enabled is True
        finally:
            console.stop(); await node.stop()

    async def test_udp_start_stop(self):
        node, console = await _make_console()
        try:
            _, token = await _login(console)
            status, _, _, _ = await asyncio.to_thread(
                _request, console, "POST", "/api/udp", token,
                {"action": "start", "port": 0})
            assert status == 400  # port 0 refused
            status, _, _, _ = await asyncio.to_thread(
                _request, console, "POST", "/api/udp", token, {"action": "bogus"})
            assert status == 400
            # pick an ephemeral free port by binding then releasing
            import socket as _socket
            s = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
            s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()
            status, _, _, _ = await asyncio.to_thread(
                _request, console, "POST", "/api/udp", token,
                {"action": "start", "port": port})
            assert status == 200 and node._udp_server is not None
            status, _, _, _ = await asyncio.to_thread(
                _request, console, "POST", "/api/udp", token, {"action": "stop"})
            assert status == 200 and node._udp_server is None
        finally:
            console.stop(); await node.stop()

    async def test_listen_unlisten(self):
        node, console = await _make_console()
        try:
            _, token = await _login(console)
            status, _, _, _ = await asyncio.to_thread(
                _request, console, "POST", "/api/listen", token, {"uri": "garbage"})
            assert status == 400
            status, _, _, _ = await asyncio.to_thread(
                _request, console, "POST", "/api/listen", token,
                {"uri": "tcp://x:1"})
            assert status == 400  # tcp not registered on this test manager
            status, _, _, _ = await asyncio.to_thread(
                _request, console, "POST", "/api/listen", token,
                {"uri": "fake://addr:1"})
            assert status == 200
            assert "fake://addr:1" in node._transport_manager.listening_uris()
            status, _, _, j = await asyncio.to_thread(
                _request, console, "POST", "/api/unlisten", token,
                {"uri": "fake://addr:1"})
            assert status == 200 and j["ok"] is True
            status, _, _, _ = await asyncio.to_thread(
                _request, console, "POST", "/api/unlisten", token,
                {"uri": "fake://addr:1"})
            assert status == 404  # already gone
        finally:
            console.stop(); await node.stop()

    async def test_net_recheck(self):
        node, console = await _make_console()
        try:
            _, token = await _login(console)
            status, _, _, j = await asyncio.to_thread(
                _request, console, "POST", "/api/net/recheck", token)
            assert status == 200 and j["ok"] is False  # monitor not started
        finally:
            console.stop(); await node.stop()

    async def test_ping_endpoints_require_auth_and_respond(self):
        node, console = await _make_console()
        try:
            # No token → unauthorized.
            status, _, _, _ = await asyncio.to_thread(
                _request, console, "POST", "/api/ping")
            assert status == 401
            _, token = await _login(console)
            # Ping all peers: fake peer isn't authenticated → nothing sent.
            status, _, _, j = await asyncio.to_thread(
                _request, console, "POST", "/api/ping", token)
            assert status == 200 and j["ok"] is True and j["sent"] == 0
            # Ping a node by id: missing id → 400.
            status, _, _, _ = await asyncio.to_thread(
                _request, console, "POST", "/api/ping/node", token, {})
            assert status == 400
            # Unknown id → reachable False (no crash).
            status, _, _, j = await asyncio.to_thread(
                _request, console, "POST", "/api/ping/node", token,
                {"id": "aa" * 20})
            assert status == 200 and j["reachable"] is False
        finally:
            console.stop(); await node.stop()


class TestHardening:
    async def test_oversized_body_rejected(self):
        node, console = await _make_console()
        try:
            _, token = await _login(console)
            status, _, _, _ = await asyncio.to_thread(
                _request, console, "POST", "/api/trust", token, None, b"x" * (65 * 1024))
            assert status == 413
        finally:
            console.stop(); await node.stop()

    async def test_static_index_served(self):
        node, console = await _make_console()
        try:
            status, hdrs, body, _ = await asyncio.to_thread(_request, console, "GET", "/")
            assert status == 200
            assert b"NMesh" in body
            assert "content-security-policy" in hdrs
            assert "default-src 'self'" in hdrs["content-security-policy"]
        finally:
            console.stop(); await node.stop()


class TestApps:
    async def test_publish_then_fetch(self):
        # On a lone node the DHT stores locally, so publish + fetch round-trips
        # through the console without needing peers.
        node, console = await _make_console()
        try:
            _, token = await _login(console)
            files = {"main.py": b"print('hi')\n" * 100, "README": b"demo"}
            payload = {"name": "chat", "version": "0.1.0",
                       "files": {p: base64.b64encode(d).decode() for p, d in files.items()}}
            status, _, _, j = await asyncio.to_thread(
                _request, console, "POST", "/api/app/publish", token, payload)
            assert status == 200 and len(j["app_id"]) == 40

            status, _, _, j2 = await asyncio.to_thread(
                _request, console, "POST", "/api/app/fetch", token, {"app_id": j["app_id"]})
            assert status == 200 and j2["found"] is True
            assert j2["name"] == "chat"
            got = {p: base64.b64decode(b) for p, b in j2["files"].items()}
            assert got == files
        finally:
            console.stop(); await node.stop()

    async def test_fetch_unknown(self):
        node, console = await _make_console()
        try:
            _, token = await _login(console)
            status, _, _, j = await asyncio.to_thread(
                _request, console, "POST", "/api/app/fetch", token, {"app_id": "00" * 20})
            assert status == 404 and j["found"] is False
        finally:
            console.stop(); await node.stop()

    async def test_publish_requires_auth(self):
        node, console = await _make_console()
        try:
            status, _, _, _ = await asyncio.to_thread(
                _request, console, "POST", "/api/app/publish", None,
                {"name": "x", "version": "1", "files": {}})
            assert status == 401
        finally:
            console.stop(); await node.stop()

    async def test_publish_bad_request(self):
        node, console = await _make_console()
        try:
            _, token = await _login(console)
            status, _, _, _ = await asyncio.to_thread(
                _request, console, "POST", "/api/app/publish", token, {"name": "x"})
            assert status == 400
        finally:
            console.stop(); await node.stop()


class TestTLS:
    async def test_tls_end_to_end(self):
        node = MeshNode(transport_manager=make_manager())
        with tempfile.TemporaryDirectory() as d:
            console = WebConsole(node, host="127.0.0.1", port=0, use_tls=True,
                                 password=PW, state_dir=d)
            console.start(loop=asyncio.get_running_loop())
            try:
                assert console.url.startswith("https://")
                assert console.cert_fingerprint
                status, token = await _tls_login(console)
                assert status == 200 and token
                status, _, _, snap = await asyncio.to_thread(
                    _request, console, "GET", "/api/state", token, tls=True)
                assert status == 200 and snap["id"] == node.id.raw.hex()
                # cert + key persisted with restrictive perms
                assert os.path.exists(os.path.join(d, "console_cert.pem"))
            finally:
                console.stop(); await node.stop()

    async def test_password_generated_and_persisted(self):
        node = MeshNode(transport_manager=make_manager())
        with tempfile.TemporaryDirectory() as d:
            c1 = WebConsole(node, host="127.0.0.1", port=0, use_tls=False, state_dir=d)
            assert c1.generated_password  # freshly generated
            pw = c1.generated_password
            assert os.path.exists(os.path.join(d, "console.cred"))
            # Reload: hash is read back, no new password, old one still verifies.
            c2 = WebConsole(node, host="127.0.0.1", port=0, use_tls=False, state_dir=d)
            assert c2.generated_password is None
            assert c2._check_password(pw)
        await node.stop()

    async def test_explicit_password_used_and_overrides_stored(self):
        """A caller-supplied password (the NMESH_CONSOLE_PASSWORD path) is the
        one that authenticates, is never echoed as 'generated', and takes over
        an existing credential file so a restart with a new value applies it."""
        node = MeshNode(transport_manager=make_manager())
        with tempfile.TemporaryDirectory() as d:
            c1 = WebConsole(node, host="127.0.0.1", port=0, use_tls=False,
                            state_dir=d, password="first-pass")
            assert c1.generated_password is None      # not auto-generated
            assert c1._check_password("first-pass")
            assert os.path.exists(os.path.join(d, "console.cred"))

            # Restart with a different explicit password → the new one wins,
            # the old one no longer authenticates.
            c2 = WebConsole(node, host="127.0.0.1", port=0, use_tls=False,
                            state_dir=d, password="second-pass")
            assert c2._check_password("second-pass")
            assert not c2._check_password("first-pass")
        await node.stop()


async def _tls_login(console, password=PW):
    status, _, _, j = await asyncio.to_thread(
        _request, console, "POST", "/api/login", None, {"password": password}, None, True)
    return status, (j or {}).get("token")
