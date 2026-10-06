"""
The data connector as the internal API: who an app is, what it may do, and
what it may never do — over a real socket, against a real node.

* an app is an app only with its **own** token; the shared one says "a local
  process", and is never answered anything a person granted an app;
* a frame an app may not send is refused with an answer, never a hang;
* a control call is the plane's answer, refused by the plane's own words;
* a hook belongs to its client and to its permission, and the node survives it;
* an app's declared operations are reachable by name, and only the client that
  was asked can answer;
* nothing an app sends, however malformed, ends its connection or the node's.
"""
import asyncio
import json
import os

import pytest

from src import app_perms, control
from src.app_perms import ControlGate, PermissionBook
from src.data_connector import (
    DataConnector, ConnectorClient, _read_frame, _write_frame,
    _AUTH, _AUTH_OK, _AUTH_FAIL, _CONTROL, _CONTROL_REPLY, _MANIFEST,
    _MOD_HOOK, _PERMS, _RETURN, _STORE_GET, _STORE_VALUE, _WHOAMI, _WHOAMI_RESP,
)
from tests.conftest import make_node

TOKEN = "shared-token"
APP = bytes.fromhex("a1b2c3d4e5f60718")
OTHER = bytes.fromhex("0011223344556677")


async def _setup(*, perms=True):
    node, _fake = await make_node()
    book = PermissionBook() if perms else None
    conn = DataConnector(node, host="127.0.0.1", port=0, token=TOKEN,
                         perms=book, app_secret=b"\x01" * 32,
                         reserved_names=("chat", "fleet", "mcp"))
    await conn.start()
    context = control.Context(node=node, loop=asyncio.get_running_loop())
    plane = control.build(context)
    if book is not None:
        plane.set_app_gate(ControlGate(book, plane))
        context.provide(perms=book, connector=conn)
    plane.set_hooks(conn.hooks)
    conn.bind_plane(plane)
    return node, conn, book, plane


async def _close(node, conn, *clients):
    for client in clients:
        try:
            await client.close()
        except Exception:
            pass
    await conn.stop()
    await node.stop()


async def _client(conn, app_id=APP, token=None):
    client = ConnectorClient(conn.host, conn.port,
                             token or conn.token_for(app_id), app_id)
    await client.connect()
    return client


async def _grant(book, app_id, *names):
    for name in names:
        assert book.set_grant(app_id.hex(), name, True), name


class TestWhoAnAppIs:
    async def test_an_app_token_is_that_app_and_no_other(self):
        node, conn, _book, _plane = await _setup()
        clients = []
        try:
            assert conn.token_for(APP) != conn.token_for(OTHER)
            assert conn.token_for(APP) != conn.token
            # The same secret gives the same token: a container keeps working
            # across a restart because the node keeps the secret.
            again = DataConnector(node, token=TOKEN, app_secret=b"\x01" * 32)
            assert again.token_for(APP) == conn.token_for(APP)
            with pytest.raises(ConnectionError):
                await _client(conn, APP, token=conn.token_for(OTHER))
            with pytest.raises(ConnectionError):
                await _client(conn, APP, token="nope")
            clients.append(await _client(conn, APP))
            assert (await clients[0].permissions())["identified"] is True
            clients.append(await _client(conn, APP, token=TOKEN))
            assert (await clients[1].permissions())["identified"] is False
        finally:
            await _close(node, conn, *clients)

    async def test_the_shared_token_is_never_answered_a_grant(self):
        node, conn, book, _plane = await _setup()
        own = await _client(conn, APP)
        await own.declare({"name": "demo", "permissions": ["readstate"]})
        await _grant(book, APP, "readstate")
        shared = await _client(conn, APP, token=TOKEN)
        try:
            assert (await own.control("node.state"))["ok"] is True
            refused = await shared.control("node.state")
            assert refused["ok"] is False and refused["code"] == "unauthorized"
            assert (await shared.links())["refused"] is True
        finally:
            await _close(node, conn, own, shared)


class TestWhatAnAppMayDo:
    async def test_a_frame_not_asked_for_is_answered_empty(self):
        node, conn, _book, _plane = await _setup()
        client = await _client(conn, APP)
        try:
            await client.declare({"name": "demo", "permissions": ["network"]})
            assert await client.store_put("k", b"v") is False
            assert await client.store_get("k") is None
            assert await client.lookup_pseudo("anyone") == []
            assert await client.my_pseudo() == ""
        finally:
            await _close(node, conn, client)

    async def test_without_a_manifest_an_app_keeps_what_it_had(self):
        node, conn, _book, _plane = await _setup()
        client = await _client(conn, APP)
        try:
            assert await client.store_put("k", b"v") is True
            assert await client.store_get("k") == b"v"
        finally:
            await _close(node, conn, client)

    async def test_a_manifest_is_answered_with_what_was_refused(self):
        node, conn, _book, _plane = await _setup()
        client = await _client(conn, APP)
        try:
            answer = await client.declare({"name": "demo",
                                           "permissions": ["network", "root"]})
            assert "root" in answer["error"]
            for garbage in ([], "x", {"name": "Bad"}, {"name": "d", "permissions": 4}):
                answer = await client.declare(garbage)
                assert answer["error"]
            assert await client.whoami() == node.id
        finally:
            await _close(node, conn, client)


class TestTheInternalApi:
    async def test_a_control_call_is_the_planes_answer(self):
        node, conn, book, _plane = await _setup()
        client = await _client(conn, APP)
        try:
            await client.declare({"name": "demo",
                                  "permissions": ["readstate.node", "control.node"]})
            refused = await client.control("node.state")
            assert refused["ok"] is False and "readstate.node" in refused["error"]
            await _grant(book, APP, "readstate.node")
            state = await client.control("node.state")
            assert state["ok"] is True and state["result"]["id"] == node.id.raw.hex()
            # Not granted, never answerable, and nothing at all: three refusals.
            assert "control.config" in (await client.control("config.save",
                                                             {"settings": {}}))["error"]
            permit = await client.control("apps.permit", {"app": APP.hex(),
                                                          "permission": "control.node",
                                                          "granted": True})
            assert permit["ok"] is False and "person" in permit["error"]
            assert (await client.control("nope.nothing"))["code"] == "not_found"
        finally:
            await _close(node, conn, client)

    async def test_a_frame_that_is_not_one_is_answered_with_its_id(self):
        node, conn, _book, _plane = await _setup()
        reader, writer = await asyncio.open_connection(conn.host, conn.port)
        try:
            await _write_frame(writer, _AUTH, APP + conn.token_for(APP).encode())
            assert (await _read_frame(reader))[0] == _AUTH_OK
            for body in (b'{"id": "q1", "op": 7}', b'{"id": "q2"', b"[" * 9000,
                         b"\xff" * 64, os.urandom(500)):
                await _write_frame(writer, _CONTROL, body)
                ftype, answer = await asyncio.wait_for(_read_frame(reader, 600_000), 3.0)
                assert ftype == _CONTROL_REPLY
                assert json.loads(answer)["ok"] is False
            await _write_frame(writer, _CONTROL, b'{"id": "q9", "op": 7}')
            _ftype, answer = await asyncio.wait_for(_read_frame(reader, 600_000), 3.0)
            assert json.loads(answer)["id"] == "q9"
            await _write_frame(writer, _WHOAMI, b"")
            assert (await asyncio.wait_for(_read_frame(reader), 3.0))[0] == _WHOAMI_RESP
        finally:
            writer.close()
            await _close(node, conn)

    async def test_no_plane_is_unavailable_not_a_hang(self):
        node, _fake = await make_node()
        conn = DataConnector(node, host="127.0.0.1", port=0, token=TOKEN,
                             perms=PermissionBook())
        await conn.start()
        client = await _client(conn, APP)
        try:
            assert (await client.control("node.state"))["code"] == "unavailable"
        finally:
            await _close(node, conn, client)


class TestModding:
    async def test_a_hook_needs_the_permission_and_belongs_to_its_client(self):
        node, conn, book, plane = await _setup()
        client = await _client(conn, APP)
        try:
            await client.declare({"name": "demo", "permissions": ["modding"]})
            answer = await client.hook("control.catalogue", "after", lambda p: None)
            assert answer["ok"] is False and "modding" in answer["error"]
            await _grant(book, APP, "modding")
            assert (await client.hook("apps.permit", "replace", lambda p: None))["ok"] is False
            assert (await client.hook("node.nothing", "after", lambda p: None))["ok"] is False
            assert (await client.hook("node.state", "sideways", lambda p: None))["ok"] is False

            def tag(payload):
                return {"result": dict(payload["result"], modded=True)}
            assert (await client.hook("node.state", "after", tag))["ok"] is True
            state = await asyncio.to_thread(plane.call, "node.state")
            assert state["modded"] is True
            # A second app may not take the same operation.
            other = await _client(conn, OTHER)
            book.declare(OTHER.hex(), {"name": "other", "permissions": ["modding"]})
            await _grant(book, OTHER, "modding")
            assert "already modded" in (await other.hook("node.state", "after", tag))["error"]
            # Gone with its client.
            await client.close()
            await asyncio.sleep(0.2)
            assert conn.hooks.listing() == {}
            await other.close()
        finally:
            await _close(node, conn)

    async def test_a_hook_that_does_not_answer_is_the_native_answer(self, monkeypatch):
        from src import data_connector
        monkeypatch.setattr(data_connector, "_MOD_TIMEOUT", 0.3)
        node, conn, book, plane = await _setup()
        client = await _client(conn, APP)
        try:
            await client.declare({"name": "demo", "permissions": ["modding"]})
            await _grant(book, APP, "modding")

            async def sleepy(_payload):
                await asyncio.sleep(5)
                return {"result": {"never": True}}
            await client.hook("node.state", "replace", sleepy)
            state = await asyncio.to_thread(plane.call, "node.state")
            assert "never" not in state and state["id"] == node.id.raw.hex()

            def broken(_payload):
                raise RuntimeError("a mod with a bug")
            await client.hook("node.state", "replace", broken)
            assert "id" in await asyncio.to_thread(plane.call, "node.state")
        finally:
            await _close(node, conn, client)

    async def test_taking_modding_back_takes_the_hook_at_once(self):
        node, conn, book, plane = await _setup()
        client = await _client(conn, APP)
        try:
            await client.declare({"name": "demo", "permissions": ["modding"]})
            await _grant(book, APP, "modding")
            await client.hook("node.state", "replace",
                              lambda p: {"result": {"replaced": True}})
            assert (await asyncio.to_thread(plane.call, "node.state")) == {"replaced": True}
            book.set_grant(APP.hex(), "modding", False)
            assert "id" in await asyncio.to_thread(plane.call, "node.state")
        finally:
            await _close(node, conn, client)


class TestAnAppsOwnApi:
    MANIFEST = {"name": "demo", "permissions": ["network"],
                "api": [{"name": "hello", "summary": "Say hello",
                         "params": [{"name": "who", "kind": "text"}]}]}

    async def test_declared_operations_are_answered_by_name(self):
        node, conn, _book, _plane = await _setup()
        client = await _client(conn, APP)
        try:
            client.serve("hello", lambda params: {"greeting": "hello " + params["who"]})
            assert "error" not in await client.declare(self.MANIFEST)
            assert conn.api_catalogue()[0]["app"] == "demo"
            answer = await asyncio.to_thread(conn.api_call, "demo", "hello", {"who": "you"})
            assert answer == {"greeting": "hello you"}
        finally:
            await _close(node, conn, client)

    async def test_only_an_identified_app_exposes_anything(self):
        node, conn, _book, _plane = await _setup()
        shared = await _client(conn, APP, token=TOKEN)
        reserved = await _client(conn, OTHER)
        try:
            assert "own token" in (await shared.declare(self.MANIFEST))["error"]
            assert "built-in" in (await reserved.declare(
                dict(self.MANIFEST, name="chat")))["error"]
            assert conn.api_catalogue() == []
        finally:
            await _close(node, conn, shared, reserved)

    async def test_only_the_client_asked_can_answer(self):
        node, conn, _book, _plane = await _setup()
        client = await _client(conn, APP)
        intruder_reader, intruder = await asyncio.open_connection(conn.host, conn.port)
        try:
            await _write_frame(intruder, _AUTH, OTHER + conn.token_for(OTHER).encode())
            await _read_frame(intruder_reader)

            async def slow(_params):
                await asyncio.sleep(0.5)
                return {"from": "the app"}
            client.serve("hello", slow)
            await client.declare(self.MANIFEST)
            asked = asyncio.create_task(asyncio.to_thread(
                conn.api_call, "demo", "hello", {"who": "x"}))
            await asyncio.sleep(0.1)
            for ident in list(conn._calls):
                await _write_frame(intruder, _RETURN, json.dumps(
                    {"call": ident, "ok": True, "result": {"from": "the intruder"}}).encode())
            assert await asked == {"from": "the app"}
        finally:
            intruder.close()
            await _close(node, conn, client)


class TestHostileFrames:
    @pytest.mark.parametrize("ftype", [_MANIFEST, _CONTROL, _MOD_HOOK, _RETURN])
    async def test_garbage_never_ends_the_connection(self, ftype):
        node, conn, _book, _plane = await _setup()
        reader, writer = await asyncio.open_connection(conn.host, conn.port)
        try:
            await _write_frame(writer, _AUTH, APP + conn.token_for(APP).encode())
            assert (await _read_frame(reader))[0] == _AUTH_OK
            for body in (b"", b"null", b"[]", b"{}", b'{"call": 5}', b"\x00" * 100,
                         os.urandom(2048), b'{"op": "' + b"a" * 5000 + b'"}'):
                await _write_frame(writer, ftype, body)
            await _write_frame(writer, _WHOAMI, b"")
            deadline = asyncio.get_running_loop().time() + 5
            while asyncio.get_running_loop().time() < deadline:
                ftype_back, _body = await asyncio.wait_for(_read_frame(reader, 600_000), 5)
                if ftype_back == _WHOAMI_RESP:
                    break
            else:
                pytest.fail("the connection stopped answering")
        finally:
            writer.close()
            await _close(node, conn)

    async def test_an_unknown_app_token_is_refused_at_the_door(self):
        node, conn, _book, _plane = await _setup()
        reader, writer = await asyncio.open_connection(conn.host, conn.port)
        try:
            await _write_frame(writer, _AUTH, APP + b"app-" + b"A" * 32)
            assert (await _read_frame(reader))[0] == _AUTH_FAIL
        finally:
            writer.close()
            await _close(node, conn)
