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
             cookie=None, headers=None):
    """Blocking HTTP request — call via asyncio.to_thread."""
    if tls:
        ctx = ssl._create_unverified_context()
        conn = http.client.HTTPSConnection(console.host, console.port,
                                           timeout=8, context=ctx)
    else:
        conn = http.client.HTTPConnection(console.host, console.port, timeout=8)
    headers = dict(headers or {})
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

    async def test_forget_node_removes_routing_entry_and_requires_auth(self):
        node, console = await _make_console()
        try:
            known_id = NodeID(b"\x03" * 20)
            node._routing.add(known_id, ["tcp://forget.example:9000"], b"known-key")
            assert node._routing.contains(known_id)

            # No token → unauthorized, and the entry survives.
            status, _, _, _ = await asyncio.to_thread(
                _request, console, "POST", "/api/nodes/forget", None,
                {"id": known_id.raw.hex()})
            assert status == 401
            assert node._routing.contains(known_id)

            _, token = await _login(console)
            # Missing id → 400.
            status, _, _, _ = await asyncio.to_thread(
                _request, console, "POST", "/api/nodes/forget", token, {})
            assert status == 400

            # Unknown id → 404, no crash.
            status, _, _, j = await asyncio.to_thread(
                _request, console, "POST", "/api/nodes/forget", token,
                {"id": "aa" * 20})
            assert status == 404 and j["ok"] is False

            # Malformed hex → 404, no crash.
            status, _, _, j = await asyncio.to_thread(
                _request, console, "POST", "/api/nodes/forget", token,
                {"id": "not-hex"})
            assert status == 404 and j["ok"] is False

            # Own id → refused, no crash.
            status, _, _, j = await asyncio.to_thread(
                _request, console, "POST", "/api/nodes/forget", token,
                {"id": node._id.raw.hex()})
            assert status == 404 and j["ok"] is False

            # Known id → removed from the routing table.
            status, _, _, j = await asyncio.to_thread(
                _request, console, "POST", "/api/nodes/forget", token,
                {"id": known_id.raw.hex()})
            assert status == 200 and j["ok"] is True
            assert not node._routing.contains(known_id)
        finally:
            console.stop(); await node.stop()

    async def test_forget_node_disconnects_live_peer(self):
        node, console = await _make_console()
        try:
            direct_id = NodeID(b"\x04" * 20)
            peer = node._peers[0]
            peer.authenticated_id = direct_id
            peer.session = object()
            node._routing.add(direct_id, ["fake://direct.example:7"], b"direct-key")

            _, token = await _login(console)
            status, _, _, j = await asyncio.to_thread(
                _request, console, "POST", "/api/nodes/forget", token,
                {"id": direct_id.raw.hex()})
            assert status == 200 and j["ok"] is True
            assert not node._routing.contains(direct_id)
            assert peer not in node._peers
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


class TestConfiguration:
    """The launch options are editable from the console.

    Two requirements cross here: the console must never write a value the node
    would refuse at startup, and it must never become a way of choosing what the
    node runs."""

    async def test_reading_needs_a_session(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "nmesh.conf")
            node, console = await _make_console(config_path=path)
            try:
                status, _, _, _ = await asyncio.to_thread(
                    _request, console, "GET", "/api/config")
                assert status == 401
            finally:
                console.stop(); await node.stop()

    async def test_writing_needs_a_session(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "nmesh.conf")
            node, console = await _make_console(config_path=path)
            try:
                status, _, _, _ = await asyncio.to_thread(
                    _request, console, "POST", "/api/config", None,
                    {"settings": {"fleet": True}})
                assert status == 401
                assert not os.path.exists(path)
            finally:
                console.stop(); await node.stop()

    async def test_a_round_trip_through_the_console(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "nmesh.conf")
            node, console = await _make_console(config_path=path)
            try:
                _, token = await _login(console)
                status, _, _, body = await asyncio.to_thread(
                    _request, console, "GET", "/api/config", token)
                assert status == 200 and body["available"] is True
                names = {s["name"] for s in body["settings"]}
                assert {"listen", "fleet", "console_port"} <= names

                status, _, _, body = await asyncio.to_thread(
                    _request, console, "POST", "/api/config", token,
                    {"settings": {"fleet": True, "console_port": 9443}})
                assert status == 200 and body["restart_required"] is True

                from src import config as node_config
                stored, problems = node_config.load(path)
                assert problems == []
                assert stored["fleet"] is True and stored["console_port"] == 9443
            finally:
                console.stop(); await node.stop()

    async def test_a_refused_value_writes_nothing_at_all(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "nmesh.conf")
            node, console = await _make_console(config_path=path)
            try:
                _, token = await _login(console)
                await asyncio.to_thread(
                    _request, console, "POST", "/api/config", token,
                    {"settings": {"fleet": True}})
                status, _, _, body = await asyncio.to_thread(
                    _request, console, "POST", "/api/config", token,
                    {"settings": {"console_port": 99999}})
                assert status == 400 and body["rejected"]
                from src import config as node_config
                stored, _ = node_config.load(path)
                # The previous file is intact: one bad field does not carry
                # away what was already set.
                assert stored["fleet"] is True
                assert stored.get("console_port") == 8787
            finally:
                console.stop(); await node.stop()

    async def test_the_console_cannot_choose_what_the_node_runs(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "nmesh.conf")
            node, console = await _make_console(config_path=path)
            try:
                _, token = await _login(console)
                status, _, _, body = await asyncio.to_thread(
                    _request, console, "POST", "/api/config", token,
                    {"settings": {"launch": "/bin/sh -c whatever"}})
                assert status == 400
                assert any("launch" in r for r in body["rejected"])
                from src import config as node_config
                stored, _ = node_config.load(path)
                assert not stored.get("launch")
            finally:
                console.stop(); await node.stop()

    async def test_an_unknown_setting_cannot_be_invented(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "nmesh.conf")
            node, console = await _make_console(config_path=path)
            try:
                _, token = await _login(console)
                status, _, _, body = await asyncio.to_thread(
                    _request, console, "POST", "/api/config", token,
                    {"settings": {"backdoor": "1"}})
                assert status == 400 and body["rejected"]
            finally:
                console.stop(); await node.stop()

    async def test_a_node_without_a_config_file_says_so(self):
        node, console = await _make_console()
        try:
            _, token = await _login(console)
            status, _, _, body = await asyncio.to_thread(
                _request, console, "GET", "/api/config", token)
            assert status == 200 and body["available"] is False
            status, _, _, _ = await asyncio.to_thread(
                _request, console, "POST", "/api/config", token,
                {"settings": {"fleet": True}})
            assert status == 409
        finally:
            console.stop(); await node.stop()

    async def test_problems_in_the_file_are_surfaced_not_hidden(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "nmesh.conf")
            with open(path, "w") as handle:
                handle.write("nonsense\nbackdoor = yes\nfleet = true\n")
            node, console = await _make_console(config_path=path)
            try:
                _, token = await _login(console)
                _, _, _, body = await asyncio.to_thread(
                    _request, console, "GET", "/api/config", token)
                assert len(body["problems"]) == 2
                fleet = [s for s in body["settings"] if s["name"] == "fleet"][0]
                assert fleet["value"] is True
            finally:
                console.stop(); await node.stop()


class TestTrace:
    """The trace is a record of routing metadata: it requires the same session
    as everything else, and must never return a payload."""

    async def test_reading_needs_a_session(self):
        node, console = await _make_console()
        try:
            status, _, _, _ = await asyncio.to_thread(
                _request, console, "GET", "/api/trace")
            assert status == 401
            status, _, _, _ = await asyncio.to_thread(
                _request, console, "GET", "/api/trace/export")
            assert status == 401
        finally:
            console.stop(); await node.stop()

    async def test_starting_needs_a_session(self):
        node, console = await _make_console()
        try:
            status, _, _, _ = await asyncio.to_thread(
                _request, console, "POST", "/api/trace", None,
                {"action": "start"})
            assert status == 401
            assert node.trace.status()["running"] is False
        finally:
            console.stop(); await node.stop()

    async def test_start_then_stop(self):
        node, console = await _make_console()
        try:
            _, token = await _login(console)
            status, _, _, body = await asyncio.to_thread(
                _request, console, "POST", "/api/trace", token,
                {"action": "start", "seconds": 30})
            assert status == 200 and body["running"] is True
            assert node.trace.status()["running"] is True

            status, _, _, body = await asyncio.to_thread(
                _request, console, "POST", "/api/trace", token,
                {"action": "stop"})
            assert status == 200 and body["running"] is False
        finally:
            console.stop(); await node.stop()

    async def test_a_nonsense_action_is_refused(self):
        node, console = await _make_console()
        try:
            _, token = await _login(console)
            status, _, _, _ = await asyncio.to_thread(
                _request, console, "POST", "/api/trace", token,
                {"action": "rm -rf"})
            assert status == 400
            assert node.trace.status()["running"] is False
        finally:
            console.stop(); await node.stop()

    async def test_hostile_bounds_are_clamped_not_obeyed(self):
        node, console = await _make_console()
        try:
            _, token = await _login(console)
            _, _, _, body = await asyncio.to_thread(
                _request, console, "POST", "/api/trace", token,
                {"action": "start", "seconds": 10 ** 9, "events": 10 ** 9})
            from src import trace as trace_mod
            assert body["capacity"] <= trace_mod.MAX_EVENTS
            assert body["seconds_left"] <= trace_mod.MAX_SECONDS
        finally:
            console.stop(); await node.stop()

    async def test_non_numeric_bounds_do_not_break_it(self):
        node, console = await _make_console()
        try:
            _, token = await _login(console)
            status, _, _, body = await asyncio.to_thread(
                _request, console, "POST", "/api/trace", token,
                {"action": "start", "seconds": "banana", "events": None})
            assert status == 200 and body["running"] is True
        finally:
            console.stop(); await node.stop()

    async def test_the_export_carries_no_payload(self):
        node, console = await _make_console()
        try:
            _, token = await _login(console)
            await asyncio.to_thread(_request, console, "POST", "/api/trace",
                                    token, {"action": "start", "seconds": 30})

            class _Packet:
                type = 0x01
                payload = b"PLAINTEXT-MUST-NOT-APPEAR"
                ttl = 64
                src_id = b"\x01" * 20
                dst_id = b"\x02" * 20

            node.trace.record("in", _Packet(), 80)
            _, _, raw, _ = await asyncio.to_thread(
                _request, console, "GET", "/api/trace/export", token)
            assert b"PLAINTEXT-MUST-NOT-APPEAR" not in raw
            assert b"nmesh-trace-1" in raw
        finally:
            console.stop(); await node.stop()

    async def test_message_types_are_named_not_hex(self):
        node, console = await _make_console()
        try:
            _, token = await _login(console)
            await asyncio.to_thread(_request, console, "POST", "/api/trace",
                                    token, {"action": "start", "seconds": 30})

            class _Found:
                type = 0x04          # FOUND_NODE
                payload = b""
                ttl = 64
                src_id = b"\x01" * 20
                dst_id = b"\x02" * 20

            node.trace.record("in", _Found(), 15000)
            _, _, _, body = await asyncio.to_thread(
                _request, console, "GET", "/api/trace", token)
            assert body["summary"]["rows"][0]["type"] == "FOUND_NODE"
        finally:
            console.stop(); await node.stop()


class TestPasswordChange:
    """Changing the password from the console.

    The property that matters: a stolen session must not be enough. Without the
    current password, a stolen session would become permanent control of the
    node."""

    async def test_a_session_alone_is_not_enough(self):
        with tempfile.TemporaryDirectory() as d:
            node, console = await _make_console(state_dir=d)
            try:
                _, token = await _login(console)
                status, _, _, body = await asyncio.to_thread(
                    _request, console, "POST", "/api/password", token,
                    {"current": "not-the-password", "new": "a-new-password-1"})
                assert status == 403
                assert console._check_password(PW)      # unchanged
            finally:
                console.stop(); await node.stop()

    async def test_without_a_session_it_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            node, console = await _make_console(state_dir=d)
            try:
                status, _, _, _ = await asyncio.to_thread(
                    _request, console, "POST", "/api/password", None,
                    {"current": PW, "new": "a-new-password-1"})
                assert status == 401
                assert console._check_password(PW)
            finally:
                console.stop(); await node.stop()

    async def test_a_valid_change_takes_effect(self):
        with tempfile.TemporaryDirectory() as d:
            node, console = await _make_console(state_dir=d)
            try:
                _, token = await _login(console)
                status, _, _, body = await asyncio.to_thread(
                    _request, console, "POST", "/api/password", token,
                    {"current": PW, "new": "a-brand-new-password"})
                assert status == 200 and body["changed"] is True
                assert console._check_password("a-brand-new-password")
                assert not console._check_password(PW)
            finally:
                console.stop(); await node.stop()

    async def test_it_survives_a_restart_of_the_console(self):
        """The new password has to be on disk, not only in RAM."""
        with tempfile.TemporaryDirectory() as d:
            node, console = await _make_console(state_dir=d)
            try:
                _, token = await _login(console)
                await asyncio.to_thread(
                    _request, console, "POST", "/api/password", token,
                    {"current": PW, "new": "a-brand-new-password"})
            finally:
                console.stop()
            try:
                fresh = WebConsole(node, host="127.0.0.1", port=0,
                                   use_tls=False, state_dir=d)
                assert fresh._check_password("a-brand-new-password")
                assert not fresh._check_password(PW)
            finally:
                await node.stop()

    async def test_other_sessions_are_signed_out_but_not_this_one(self):
        with tempfile.TemporaryDirectory() as d:
            node, console = await _make_console(state_dir=d)
            try:
                _, mine = await _login(console)
                _, other = await _login(console)
                status, _, _, body = await asyncio.to_thread(
                    _request, console, "POST", "/api/password", mine,
                    {"current": PW, "new": "a-brand-new-password"})
                assert status == 200 and body["sessions_revoked"] == 1
                assert console._valid_token(mine)
                assert not console._valid_token(other)
            finally:
                console.stop(); await node.stop()

    async def test_a_weak_new_password_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            node, console = await _make_console(state_dir=d)
            try:
                _, token = await _login(console)
                status, _, _, body = await asyncio.to_thread(
                    _request, console, "POST", "/api/password", token,
                    {"current": PW, "new": "short"})
                assert status == 400 and "12" in body["error"]
                assert console._check_password(PW)
            finally:
                console.stop(); await node.stop()

    async def test_a_missing_new_password_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            node, console = await _make_console(state_dir=d)
            try:
                _, token = await _login(console)
                status, _, _, _ = await asyncio.to_thread(
                    _request, console, "POST", "/api/password", token,
                    {"current": PW})
                assert status == 400
                assert console._check_password(PW)
            finally:
                console.stop(); await node.stop()

    async def test_guessing_the_current_password_hits_the_lockout(self):
        """This endpoint must not be a way of guessing the password faster than
        the login page."""
        with tempfile.TemporaryDirectory() as d:
            node, console = await _make_console(state_dir=d)
            try:
                _, token = await _login(console)
                for _ in range(_LOGIN_MAX_FAILURES):
                    await asyncio.to_thread(
                        _request, console, "POST", "/api/password", token,
                        {"current": "wrong", "new": "a-brand-new-password"})
                status, _, _, _ = await asyncio.to_thread(
                    _request, console, "POST", "/api/password", token,
                    {"current": PW, "new": "a-brand-new-password"})
                assert status == 429
                assert console._check_password(PW)
            finally:
                console.stop(); await node.stop()

    async def test_the_stored_file_never_holds_the_password(self):
        with tempfile.TemporaryDirectory() as d:
            node, console = await _make_console(state_dir=d)
            try:
                _, token = await _login(console)
                await asyncio.to_thread(
                    _request, console, "POST", "/api/password", token,
                    {"current": PW, "new": "a-brand-new-password"})
                with open(os.path.join(d, "console.cred")) as handle:
                    assert "a-brand-new-password" not in handle.read()
            finally:
                console.stop(); await node.stop()


class TestJoinTicket:
    """Émettre un ticket et rejoindre avec, depuis la console."""

    async def test_issuing_needs_a_session(self):
        node, console = await _make_console()
        try:
            status, _, _, _ = await asyncio.to_thread(
                _request, console, "POST", "/api/ticket", None, {"ttl": 600})
            assert status == 401
        finally:
            console.stop(); await node.stop()

    async def test_a_node_with_no_public_address_is_told_why(self):
        """409 avec une explication, pas un ticket qui ne peut pas marcher."""
        node, console = await _make_console()
        try:
            _, token = await _login(console)
            status, _, _, body = await asyncio.to_thread(
                _request, console, "POST", "/api/ticket", token, {"ttl": 600})
            assert status == 409
            assert "public" in body["error"]
        finally:
            console.stop(); await node.stop()

    async def test_a_reachable_node_issues_a_ticket_with_its_qr(self):
        node, console = await _make_console()
        node.reachability = lambda: [
            {"transport": "tcp", "scope": "world", "anchor": "",
             "address": "tcp://203.0.113.7:9000", "confirmed": True}]
        try:
            _, token = await _login(console)
            status, _, _, body = await asyncio.to_thread(
                _request, console, "POST", "/api/ticket", token, {"ttl": 600})
            assert status == 200
            from src import join_ticket
            parsed = join_ticket.decode(body["ticket"])
            assert parsed["uri"] == "tcp://203.0.113.7:9000"
            assert body["qr_svg"].startswith("<svg")
            # The code travels inside the ticket; repeating it would put it in
            # one more place.
            assert "code" not in body
        finally:
            console.stop(); await node.stop()

    async def test_a_silly_lifetime_is_clamped_not_obeyed(self):
        node, console = await _make_console()
        node.reachability = lambda: [
            {"transport": "tcp", "scope": "world", "anchor": "",
             "address": "tcp://203.0.113.7:9000", "confirmed": True}]
        try:
            _, token = await _login(console)
            _, _, _, body = await asyncio.to_thread(
                _request, console, "POST", "/api/ticket", token, {"ttl": 10 ** 9})
            from src import join_ticket
            assert body["ttl"] == join_ticket.MAX_TTL
        finally:
            console.stop(); await node.stop()

    async def test_joining_with_a_broken_ticket_is_refused_locally(self):
        """A typo has to fail here, with a clear message, not by dialling some
        random address."""
        node, console = await _make_console()
        try:
            _, token = await _login(console)
            status, _, _, body = await asyncio.to_thread(
                _request, console, "POST", "/api/join", token,
                {"ticket": "NOT-A-REAL-TICKET"})
            assert status == 400
            assert body["error"]
        finally:
            console.stop(); await node.stop()

    async def test_joining_still_accepts_a_uri_and_a_code(self):
        """Le ticket s'ajoute au join complet, il ne le remplace pas."""
        node, console = await _make_console()
        try:
            _, token = await _login(console)
            status, _, _, _ = await asyncio.to_thread(
                _request, console, "POST", "/api/join", token, {"uri": "tcp://"})
            assert status == 400          # uri and code required, as before
        finally:
            console.stop(); await node.stop()


class TestAddressRetryEndpoints:
    """The two routes added for addresses: replaying, and steering on latency.
    They return usable words, and refuse everything else."""

    async def test_retry_needs_an_id(self):
        node, console = await _make_console()
        try:
            _, token = await _login(console)
            for payload in ({}, {"id": ""}, {"id": 12}, {"id": "aa", "uri": 5}):
                status, _, _, _ = await asyncio.to_thread(
                    _request, console, "POST", "/api/peers/retry", token, payload)
                assert status == 400, payload
        finally:
            console.stop(); await node.stop()

    async def test_retry_requires_auth(self):
        node, console = await _make_console()
        try:
            status, _, _, _ = await asyncio.to_thread(
                _request, console, "POST", "/api/peers/retry", None, {"id": "aa" * 20})
            assert status == 401
        finally:
            console.stop(); await node.stop()

    async def test_retrying_an_unknown_node_says_so_and_dials_nothing(self):
        node, console = await _make_console()
        try:
            _, token = await _login(console)
            status, _, _, body = await asyncio.to_thread(
                _request, console, "POST", "/api/peers/retry", token,
                {"id": "ab" * 20})
            assert status == 400
            assert "no known address" in body["error"]
        finally:
            console.stop(); await node.stop()

    async def test_retrying_reports_what_each_address_did(self):
        node, console = await _make_console()
        try:
            _, token = await _login(console)
            target = NodeID(b"\x5a" * 20)
            # A scheme no transport serves: the answer is immediate *and* it
            # names the problem, which is the point of the button.
            node._routing.add(target, ["nope://nowhere:1", "nope://elsewhere:2"])
            status, _, _, body = await asyncio.to_thread(
                _request, console, "POST", "/api/peers/retry", token,
                {"id": target.raw.hex()})
            assert status == 200 and body["ok"] is True
            assert body["connected"] is False
            assert {row["uri"] for row in body["results"]} == {
                "nope://nowhere:1", "nope://elsewhere:2"}
            assert all(row["outcome"] == "no transport" for row in body["results"])
            # And the failure is recorded where the address table reads it.
            assert node._dial_log[target.raw.hex()]
        finally:
            console.stop(); await node.stop()

    async def test_an_address_that_is_not_that_nodes_is_refused(self):
        node, console = await _make_console()
        try:
            _, token = await _login(console)
            target = NodeID(b"\x5b" * 20)
            node._routing.add(target, ["nope://known:1"])
            status, _, _, body = await asyncio.to_thread(
                _request, console, "POST", "/api/peers/retry", token,
                {"id": target.raw.hex(), "uri": "tcp://169.254.169.254:80"})
            assert status == 400
            assert "not an address of that node" in body["error"]
        finally:
            console.stop(); await node.stop()

    async def test_dynamic_addressing_toggles_and_shows_up_in_the_snapshot(self):
        node, console = await _make_console()
        try:
            _, token = await _login(console)
            _, _, _, state = await asyncio.to_thread(
                _request, console, "GET", "/api/state", token)
            assert state["dynamic_address"] is False
            status, _, _, body = await asyncio.to_thread(
                _request, console, "POST", "/api/addressing/dynamic", token,
                {"enabled": True})
            assert status == 200 and body["enabled"] is True
            assert node.dynamic_address is True
            _, _, _, state = await asyncio.to_thread(
                _request, console, "GET", "/api/state", token)
            assert state["dynamic_address"] is True
        finally:
            console.stop(); await node.stop()

    async def test_dynamic_addressing_refuses_anything_but_a_boolean(self):
        node, console = await _make_console()
        try:
            _, token = await _login(console)
            for payload in ({}, {"enabled": "yes"}, {"enabled": 1}, {"enable": True}):
                status, _, _, _ = await asyncio.to_thread(
                    _request, console, "POST", "/api/addressing/dynamic", token, payload)
                assert status == 400, payload
        finally:
            console.stop(); await node.stop()

    async def test_the_balance_is_settable_and_shows_the_resulting_order(self):
        node, console = await _make_console()
        try:
            _, token = await _login(console)
            status, _, _, body = await asyncio.to_thread(
                _request, console, "POST", "/api/addressing/balance", token,
                {"value": 100})
            assert status == 200 and body["value"] == 100
            assert node.transport_balance == 100
            # The console receives the order the node computed, not an
            # instruction to recompute it itself.
            assert [entry["scheme"] for entry in body["preference"]]
            _, _, _, state = await asyncio.to_thread(
                _request, console, "GET", "/api/state", token)
            assert state["transport_balance"] == 100
            assert state["transport_preference"] == body["preference"]
        finally:
            console.stop(); await node.stop()

    async def test_the_balance_refuses_anything_outside_its_range(self):
        node, console = await _make_console()
        try:
            _, token = await _login(console)
            for payload in ({}, {"value": -1}, {"value": 101}, {"value": "half"},
                            {"value": None}):
                status, _, _, _ = await asyncio.to_thread(
                    _request, console, "POST", "/api/addressing/balance", token, payload)
                assert status == 400, payload
            assert node.transport_balance == 50
        finally:
            console.stop(); await node.stop()


class TestTheNodePage:
    """`/node` is the node view as a page of its own, for the window and the tab
    a viewer may prefer. In place, chat and fleet mount the same view directly —
    so nothing here has to be frameable, and nothing here is."""

    async def test_it_is_served_with_its_assets(self):
        node, console = await _make_console()
        try:
            for path, kind in (("/node", "text/html"),
                               ("/node.js", "application/javascript"),
                               ("/node.css", "text/css")):
                status, headers, body, _ = await asyncio.to_thread(
                    _request, console, "GET", path)
                assert status == 200, path
                assert headers["content-type"].startswith(kind), path
                assert body
        finally:
            console.stop(); await node.stop()

    async def test_nothing_this_console_serves_may_be_framed(self):
        """Showing a node inside chat is a *mount*, not a frame: the same view,
        in the same document. So there is no reason to let anything here be
        put in a frame, and the answer stays no for every page."""
        node, console = await _make_console()
        try:
            for path in ("/", "/node", "/node.js", "/node.css"):
                _s, headers, _b, _j = await asyncio.to_thread(
                    _request, console, "GET", path)
                policy = headers["content-security-policy"]
                assert "frame-ancestors 'none'" in policy, path
                assert policy.count("frame-ancestors") == 1, path
                assert "default-src 'self'" in policy and "unsafe-inline" not in policy
        finally:
            console.stop(); await node.stop()

    async def test_the_page_is_public_but_says_nothing_without_a_session(self):
        """Same shape as every other page here: the markup is public, and every
        call it makes needs the session."""
        node, console = await _make_console()
        try:
            status, _, body, _ = await asyncio.to_thread(_request, console, "GET", "/node")
            assert status == 200 and b"Sign in" in body
            for path in ("/api/state", "/api/app-api"):
                status, _, _, _ = await asyncio.to_thread(_request, console, "GET", path)
                assert status == 401, path
        finally:
            console.stop(); await node.stop()
