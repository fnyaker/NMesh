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


def _request(console, method, path, token=None, body=None, raw=None, tls=False):
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
            for key in ("id", "peers", "total", "load", "routing", "uptime"):
                assert key in snap
            assert snap["id"] == node.id.raw.hex()
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


async def _tls_login(console, password=PW):
    status, _, _, j = await asyncio.to_thread(
        _request, console, "POST", "/api/login", None, {"password": password}, None, True)
    return status, (j or {}).get("token")
