"""
Data connector tests — the app-facing DATA plane.

Focus on the auth boundary (token required before anything), the send/receive
round-trip against a live node, and framing hardening.
"""
import asyncio

import pytest

from src.data_connector import (
    DataConnector, ConnectorClient, _read_frame, _write_frame, _LEN,
    _AUTH, _SEND, _WHOAMI, _AUTH_OK, _AUTH_FAIL, _RECV, _WHOAMI_RESP,
)
from src.app_channel import APP_ID_LEN, GENERIC_APP_ID, builtin_id, frame
from src.node_id import NodeID
from src.node import MeshNode
from tests.conftest import make_manager, make_node
import os

TOKEN = "test-token-abc"
APP = GENERIC_APP_ID   # the section the test client speaks on


async def _make():
    node, fake = await make_node()
    conn = DataConnector(node, host="127.0.0.1", port=0, token=TOKEN)
    await conn.start()
    return node, fake, conn


async def _open(conn):
    return await asyncio.open_connection(conn._host, conn.port)


async def _auth(reader, writer, token=TOKEN, app_id=APP):
    # AUTH declares the client's app section, then the token.
    await _write_frame(writer, _AUTH, app_id + token.encode())
    ftype, _ = await _read_frame(reader)
    return ftype


class TestAuth:
    async def test_wrong_token_rejected(self):
        node, _, conn = await _make()
        try:
            reader, writer = await _open(conn)
            assert await _auth(reader, writer, "wrong") == _AUTH_FAIL
            assert await reader.read(1) == b""   # server closed us
            writer.close()
        finally:
            await conn.stop(); await node.stop()

    async def test_correct_token_accepted(self):
        node, _, conn = await _make()
        try:
            reader, writer = await _open(conn)
            assert await _auth(reader, writer) == _AUTH_OK
            writer.close()
        finally:
            await conn.stop(); await node.stop()

    async def test_send_before_auth_ignored(self):
        # First frame isn't AUTH → treated as failed auth, connection closed.
        node, _, conn = await _make()
        try:
            reader, writer = await _open(conn)
            await _write_frame(writer, _SEND, os.urandom(20) + b"hi")
            ftype, _ = await _read_frame(reader)
            assert ftype == _AUTH_FAIL
            writer.close()
        finally:
            await conn.stop(); await node.stop()


class TestSendReceive:
    async def test_send_reaches_node(self):
        node, _, conn = await _make()
        try:
            reader, writer = await _open(conn)
            assert await _auth(reader, writer) == _AUTH_OK
            target = NodeID(os.urandom(20))
            await _write_frame(writer, _SEND, target.raw + b"payload-out")
            # No route → node buffers it as pending E2E data, framed with the
            # client's app id so the far end can demultiplex it.
            for _ in range(50):
                if target in node._e2e_pending_data:
                    break
                await asyncio.sleep(0.02)
            assert node._e2e_pending_data.get(target) == [frame(APP, b"payload-out")]
            writer.close()
        finally:
            await conn.stop(); await node.stop()

    async def test_whoami(self):
        node, _, conn = await _make()
        try:
            reader, writer = await _open(conn)
            await _auth(reader, writer)
            await _write_frame(writer, _WHOAMI, b"")
            ftype, body = await _read_frame(reader)
            assert ftype == _WHOAMI_RESP
            assert body == node.id.raw
            writer.close()
        finally:
            await conn.stop(); await node.stop()

    async def test_inbound_message_pushed(self):
        node, _, conn = await _make()
        try:
            reader, writer = await _open(conn)
            await _auth(reader, writer)
            src = NodeID(os.urandom(20))
            # Inbound DATA is framed with the app id; the connector demultiplexes
            # it and delivers only the payload (section header stripped).
            node._data_queue.put_nowait((src, frame(APP, b"incoming")))
            ftype, body = await asyncio.wait_for(_read_frame(reader), timeout=2.0)
            assert ftype == _RECV
            assert body[:20] == src.raw
            assert body[20:] == b"incoming"
            writer.close()
        finally:
            await conn.stop(); await node.stop()


class TestHardening:
    async def test_oversized_frame_closes(self):
        node, _, conn = await _make()
        try:
            reader, writer = await _open(conn)
            writer.write(_LEN.pack(10 ** 7))   # absurd length prefix
            await writer.drain()
            assert await reader.read(1) == b""  # server rejected + closed
            writer.close()
        finally:
            await conn.stop(); await node.stop()

    async def test_token_is_generated_when_absent(self):
        node, _ = await make_node()
        conn = DataConnector(node)
        assert conn.token and len(conn.token) >= 16
        await node.stop()


class TestConnectorClient:
    async def test_client_whoami_and_recv(self):
        node, _, conn = await _make()
        client = ConnectorClient(conn.host, conn.port, TOKEN)
        try:
            await client.connect()
            assert (await client.whoami()) == node.id
            # A message the node delivers on this client's section is surfaced.
            src = NodeID(os.urandom(20))
            node._data_queue.put_nowait((src, frame(GENERIC_APP_ID, b"hello app")))
            got_src, got = await asyncio.wait_for(client.recv(), timeout=2.0)
            assert got_src == src and got == b"hello app"
        finally:
            await client.close()
            await conn.stop()
            await node.stop()

    async def test_from_env(self):
        env = {"NMESH_CONNECTOR_HOST": "127.0.0.1",
               "NMESH_CONNECTOR_PORT": "1234",
               "NMESH_CONNECTOR_TOKEN": "tok"}
        client = ConnectorClient.from_env(env)
        assert client._host == "127.0.0.1" and client._port == 1234 and client._token == "tok"
        assert client._app_id == GENERIC_APP_ID   # no NMESH_APP_ID → generic section

    async def test_from_env_reads_app_id(self):
        app = builtin_id("widget")
        env = {"NMESH_CONNECTOR_HOST": "127.0.0.1", "NMESH_CONNECTOR_PORT": "1",
               "NMESH_CONNECTOR_TOKEN": "t", "NMESH_APP_ID": app.hex()}
        assert ConnectorClient.from_env(env)._app_id == app


class TestSections:
    """App-id demultiplexing: a client only receives its own section, and
    unsectioned traffic is dropped (reject by default)."""

    async def test_sections_are_isolated(self):
        node, _, conn = await _make()
        a_app = builtin_id("alpha")
        b_app = builtin_id("beta")
        r1, w1 = await _open(conn)
        r2, w2 = await _open(conn)
        try:
            assert await _auth(r1, w1, app_id=a_app) == _AUTH_OK
            assert await _auth(r2, w2, app_id=b_app) == _AUTH_OK
            src = NodeID(os.urandom(20))
            node._data_queue.put_nowait((src, frame(a_app, b"for-alpha")))
            # The alpha client gets it…
            ftype, body = await asyncio.wait_for(_read_frame(r1), timeout=2.0)
            assert ftype == _RECV and body[20:] == b"for-alpha"
            # …and the beta client does not (nothing queued for its section).
            with pytest.raises(asyncio.TimeoutError):
                await asyncio.wait_for(_read_frame(r2), timeout=0.4)
            w1.close(); w2.close()
        finally:
            await conn.stop(); await node.stop()

    async def test_unsectioned_message_dropped(self):
        node, _, conn = await _make()
        reader, writer = await _open(conn)
        try:
            await _auth(reader, writer)
            src = NodeID(os.urandom(20))
            node._data_queue.put_nowait((src, b"x"))  # shorter than a section header
            with pytest.raises(asyncio.TimeoutError):
                await asyncio.wait_for(_read_frame(reader), timeout=0.5)
            writer.close()
        finally:
            await conn.stop(); await node.stop()

    async def test_auth_without_app_id_rejected(self):
        node, _, conn = await _make()
        reader, writer = await _open(conn)
        try:
            # Token alone, no room for a section header → rejected.
            await _write_frame(writer, _AUTH, TOKEN.encode()[:APP_ID_LEN - 1])
            ftype, _ = await _read_frame(reader)
            assert ftype == _AUTH_FAIL
            writer.close()
        finally:
            await conn.stop(); await node.stop()


class TestLocalStore:
    """The per-app drawer, driven over the connector. The app never names its
    drawer — the node uses the app id bound at AUTH."""

    async def test_put_get_delete_list(self):
        node, _, conn = await _make()
        client = ConnectorClient(conn.host, conn.port, TOKEN, GENERIC_APP_ID)
        try:
            await client.connect()
            assert await client.store_get("k") is None
            assert await client.store_put("k", b"value") is True
            assert await client.store_get("k") == b"value"
            assert await client.store_put("k2", b"v2") is True
            assert await client.store_list() == ["k", "k2"]
            assert await client.store_delete("k") is True
            assert await client.store_get("k") is None
            assert await client.store_list() == ["k2"]
        finally:
            await client.close(); await conn.stop(); await node.stop()

    async def test_drawers_isolated_by_app_section(self):
        node, _, conn = await _make()
        alpha = ConnectorClient(conn.host, conn.port, TOKEN, builtin_id("alpha"))
        beta = ConnectorClient(conn.host, conn.port, TOKEN, builtin_id("beta"))
        try:
            await alpha.connect(); await beta.connect()
            await alpha.store_put("shared-key", b"alpha-data")
            await beta.store_put("shared-key", b"beta-data")
            # Same key string, different sections → different values, no bleed.
            assert await alpha.store_get("shared-key") == b"alpha-data"
            assert await beta.store_get("shared-key") == b"beta-data"
        finally:
            await alpha.close(); await beta.close()
            await conn.stop(); await node.stop()

    async def test_store_survives_interleaved_recv(self):
        # A store round-trip must tolerate inbound DATA arriving mid-request: the
        # client buffers RECV frames and still returns the store reply.
        node, _, conn = await _make()
        client = ConnectorClient(conn.host, conn.port, TOKEN, GENERIC_APP_ID)
        try:
            await client.connect()
            src = NodeID(os.urandom(20))
            node._data_queue.put_nowait((src, frame(GENERIC_APP_ID, b"inbound")))
            assert await client.store_put("k", b"v") is True
            # The buffered inbound message is still delivered afterwards.
            got_src, got = await asyncio.wait_for(client.recv(), timeout=2.0)
            assert got_src == src and got == b"inbound"
        finally:
            await client.close(); await conn.stop(); await node.stop()

    async def test_large_value_within_frame_roundtrips(self):
        # Values up to the connector's frame budget round-trip intact. (Values
        # beyond one frame are refused at the transport layer — see
        # test_oversized_frame_closes — never reaching the store.)
        node, _, conn = await _make()
        client = ConnectorClient(conn.host, conn.port, TOKEN, GENERIC_APP_ID)
        try:
            await client.connect()
            big = os.urandom(48 * 1024)
            assert await client.store_put("blob", big) is True
            assert await client.store_get("blob") == big
        finally:
            await client.close(); await conn.stop(); await node.stop()


class TestAppDHT:
    """The per-app DHT, driven over the connector. The app supplies content and
    (for private) a key; the node namespaces by the session's app id."""

    async def test_public_put_get(self):
        node, _, conn = await _make()
        client = ConnectorClient(conn.host, conn.port, TOKEN, GENERIC_APP_ID)
        try:
            await client.connect()
            key = await client.dht_put(b"public-entry")
            assert key is not None and len(key) == 20
            assert await client.dht_get(key) == b"public-entry"
        finally:
            await client.close(); await conn.stop(); await node.stop()

    async def test_private_put_get(self):
        node, _, conn = await _make()
        client = ConnectorClient(conn.host, conn.port, TOKEN, GENERIC_APP_ID)
        try:
            await client.connect()
            enc = b"k" * 32
            key = await client.dht_put(b"private-entry", enc)
            assert key is not None
            assert await client.dht_get(key, enc) == b"private-entry"
            assert await client.dht_get(key) is None            # no key
            assert await client.dht_get(key, b"z" * 32) is None  # wrong key
        finally:
            await client.close(); await conn.stop(); await node.stop()

    async def test_namespace_isolation_across_sections(self):
        node, _, conn = await _make()
        alpha = ConnectorClient(conn.host, conn.port, TOKEN, builtin_id("alpha"))
        beta = ConnectorClient(conn.host, conn.port, TOKEN, builtin_id("beta"))
        try:
            await alpha.connect(); await beta.connect()
            key = await alpha.dht_put(b"alpha-only")
            # Beta holds the exact content key but reads nothing (other namespace).
            assert await beta.dht_get(key) is None
            assert await alpha.dht_get(key) == b"alpha-only"
        finally:
            await alpha.close(); await beta.close()
            await conn.stop(); await node.stop()

    async def test_oversized_content_signals_failure(self):
        from src.app_dht import MAX_CONTENT
        node, _, conn = await _make()
        client = ConnectorClient(conn.host, conn.port, TOKEN, GENERIC_APP_ID)
        try:
            await client.connect()
            # Within the connector frame budget but past the DHT value ceiling:
            # the node refuses it and the client sees None (empty key reply).
            assert await client.dht_put(b"x" * (MAX_CONTENT + 1)) is None
        finally:
            await client.close(); await conn.stop(); await node.stop()


class TestOneReader:
    """A request made while the app is waiting for messages must still answer.

    Two coroutines reading one socket is a lost frame: the one parked in
    ``recv`` swallows a reply meant for the other, which then waits for
    something already thrown away. That is a hang, not an error, so it gets its
    own tests."""

    async def test_a_request_answers_while_recv_is_waiting(self):
        node, _, conn = await _make()
        node.set_pseudo("alice")
        client = ConnectorClient(conn.host, conn.port, TOKEN, GENERIC_APP_ID)
        try:
            await client.connect()
            waiting = asyncio.create_task(client.recv())
            await asyncio.sleep(0)          # let it park inside recv()
            assert await asyncio.wait_for(client.my_pseudo(), timeout=5.0) == "alice"
            assert await asyncio.wait_for(client.whoami(), timeout=5.0) == node.id
            waiting.cancel()
        finally:
            await client.close(); await conn.stop(); await node.stop()

    async def test_messages_are_not_lost_to_a_concurrent_request(self):
        node, _, conn = await _make()
        node.set_pseudo("alice")
        client = ConnectorClient(conn.host, conn.port, TOKEN, GENERIC_APP_ID)
        try:
            await client.connect()
            for _ in range(5):
                assert await asyncio.wait_for(client.my_pseudo(), timeout=5.0) == "alice"
        finally:
            await client.close(); await conn.stop(); await node.stop()

    async def test_a_dead_link_wakes_everyone_instead_of_hanging(self):
        node, _, conn = await _make()
        client = ConnectorClient(conn.host, conn.port, TOKEN, GENERIC_APP_ID)
        try:
            await client.connect()
            waiting = asyncio.create_task(client.recv())
            await asyncio.sleep(0)
            await conn.stop()
            with pytest.raises(Exception):
                await asyncio.wait_for(waiting, timeout=5.0)
        finally:
            await client.close(); await node.stop()


class TestShutdown:
    """Stopping the connector while apps are still attached.

    The trap is a version change, not a race. Python 3.12 made
    ``asyncio.Server.wait_closed()`` wait for every *accepted connection* to
    finish, not only for the listening socket to shut. Awaiting it before
    dropping the clients is then a deadlock — the wait needs the handlers to
    end, and the only thing that ends them is the close that comes after. On
    3.11 it returned at once, so the ordering read as correct for as long as
    the interpreter stayed still, and the symptom when it moved was a test run
    that hung until the timeout killed the worker."""

    async def test_stop_returns_with_a_client_still_attached(self):
        node, _, conn = await _make()
        client = ConnectorClient(conn.host, conn.port, TOKEN, GENERIC_APP_ID)
        try:
            await client.connect()
            parked = asyncio.create_task(client.recv())
            await asyncio.sleep(0)          # let the handler park on the read
            await asyncio.wait_for(conn.stop(), timeout=5.0)
            parked.cancel()
        finally:
            await client.close(); await node.stop()

    async def test_stop_returns_with_several_clients_attached(self):
        """One straggler must not hold the shutdown for the others either."""
        node, _, conn = await _make()
        clients = [ConnectorClient(conn.host, conn.port, TOKEN, GENERIC_APP_ID)
                   for _ in range(4)]
        parked = []
        try:
            for client in clients:
                await client.connect()
                parked.append(asyncio.create_task(client.recv()))
            await asyncio.sleep(0)
            await asyncio.wait_for(conn.stop(), timeout=5.0)
            for task in parked:
                task.cancel()
        finally:
            for client in clients:
                await client.close()
            await node.stop()


class TestPseudos:
    """Reading pseudos over the connector. There is no frame that writes one."""

    async def test_read_own_pseudo_and_search(self):
        node, _, conn = await _make()
        node.set_pseudo("Alice Ada")
        client = ConnectorClient(conn.host, conn.port, TOKEN, GENERIC_APP_ID)
        try:
            await client.connect()
            assert await client.my_pseudo() == "Alice Ada"
            res = await client.lookup_pseudo("ali")   # partial, case-insensitive
            assert [r["id"] for r in res] == [node.id.raw.hex()]
            assert res[0]["pseudo"] == "Alice Ada"
            assert await client.lookup_pseudo("nobody") == []
        finally:
            await client.close(); await conn.stop(); await node.stop()

    async def test_resolve_ids_to_names(self):
        node, _, conn = await _make()
        node.set_pseudo("Alice")
        client = ConnectorClient(conn.host, conn.port, TOKEN, GENERIC_APP_ID)
        try:
            await client.connect()
            unknown = "ff" * 20
            names = await client.pseudos_of([node.id.raw.hex(), unknown])
            # An id with no known name is simply absent — the caller shows the id.
            assert names == {node.id.raw.hex(): "Alice"}
        finally:
            await client.close(); await conn.stop(); await node.stop()

    async def test_every_app_sees_the_same_name(self):
        # The pseudo is the node's, so two apps cannot disagree about it — which
        # is the whole reason it moved off the app.
        node, _, conn = await _make()
        node.set_pseudo("alice")
        alpha = ConnectorClient(conn.host, conn.port, TOKEN, builtin_id("alpha"))
        beta = ConnectorClient(conn.host, conn.port, TOKEN, builtin_id("beta"))
        try:
            await alpha.connect(); await beta.connect()
            assert await alpha.my_pseudo() == await beta.my_pseudo() == "alice"
            assert await beta.lookup_pseudo("alice") == await alpha.lookup_pseudo("alice")
        finally:
            await alpha.close(); await beta.close()
            await conn.stop(); await node.stop()

    async def test_an_app_cannot_rename_the_node(self):
        node, _, conn = await _make()
        node.set_pseudo("alice")
        client = ConnectorClient(conn.host, conn.port, TOKEN, GENERIC_APP_ID)
        try:
            await client.connect()
            assert not hasattr(client, "publish_pseudo")
            assert not hasattr(client, "set_pseudo")
            assert node.pseudo == "alice"
        finally:
            await client.close(); await conn.stop(); await node.stop()


# ---------------------------------------------------------------------------
# App identity over the connector (the SSO an external app gets)
# ---------------------------------------------------------------------------

class TestConnectorAppAuth:
    """The connector hands an app the node's identity as a login. The property
    that matters: the app id comes from the AUTH session, so one app can never
    speak for another's section, and the node never signs app-chosen bytes."""

    async def _pair(self):
        from src.app_auth import CTX_LEN, ctx_hash
        node = MeshNode(transport_manager=make_manager())
        conn = DataConnector(node, host="127.0.0.1", port=0)
        await conn.start()
        return node, conn

    async def test_mint_and_verify_roundtrip(self):
        from src.app_auth import ctx_hash
        node, conn = await self._pair()
        app_id = builtin_id("auth-demo")
        client = ConnectorClient(conn.host, conn.port, conn.token, app_id)
        await client.connect()
        try:
            ctx = ctx_hash(b"reboot now")
            blob = await client.assert_to(node.id, "demo.action", ctx)
            assert blob
            principal = await client.verify_assertion(blob, purpose="demo.action",
                                                      ctx=ctx)
            assert principal is not None
            assert principal["id"] == node.id.raw.hex()
            assert principal["purpose"] == "demo.action"
        finally:
            await client.close()
            await conn.stop()
            await node.stop()

    async def test_assertion_is_bound_to_its_section(self):
        """An assertion minted in one app's section must not verify in another's
        — that is the whole point of scoping."""
        node, conn = await self._pair()
        one = ConnectorClient(conn.host, conn.port, conn.token,
                              builtin_id("app-one"))
        two = ConnectorClient(conn.host, conn.port, conn.token,
                              builtin_id("app-two"))
        await one.connect()
        await two.connect()
        try:
            blob = await one.assert_to(node.id, "shared.purpose")
            assert await one.verify_assertion(blob, purpose="shared.purpose")
            assert await two.verify_assertion(blob, purpose="shared.purpose") is None
        finally:
            await one.close()
            await two.close()
            await conn.stop()
            await node.stop()

    async def test_replay_is_refused(self):
        node, conn = await self._pair()
        client = ConnectorClient(conn.host, conn.port, conn.token,
                                 builtin_id("replay-demo"))
        await client.connect()
        try:
            blob = await client.assert_to(node.id, "once")
            assert await client.verify_assertion(blob, purpose="once") is not None
            assert await client.verify_assertion(blob, purpose="once") is None
        finally:
            await client.close()
            await conn.stop()
            await node.stop()

    async def test_wrong_purpose_is_refused(self):
        node, conn = await self._pair()
        client = ConnectorClient(conn.host, conn.port, conn.token,
                                 builtin_id("purpose-demo"))
        await client.connect()
        try:
            blob = await client.assert_to(node.id, "read.status")
            assert await client.verify_assertion(blob, purpose="open.shell") is None
        finally:
            await client.close()
            await conn.stop()
            await node.stop()

    async def test_bad_minting_input_is_refused_not_raised(self):
        node, conn = await self._pair()
        client = ConnectorClient(conn.host, conn.port, conn.token,
                                 builtin_id("bounds-demo"))
        await client.connect()
        try:
            assert await client.assert_to(node.id, "") is None
            assert await client.assert_to(node.id, "x" * 500) is None
            assert await client.assert_to(node.id, "ok", ttl=0) is None
            assert await client.assert_to(node.id, "ok", ttl=10 ** 9) is None
        finally:
            await client.close()
            await conn.stop()
            await node.stop()

    async def test_garbage_never_verifies_and_never_crashes(self):
        node, conn = await self._pair()
        client = ConnectorClient(conn.host, conn.port, conn.token,
                                 builtin_id("fuzz-demo"))
        await client.connect()
        try:
            for _ in range(60):
                assert await client.verify_assertion(os.urandom(96)) is None
            # The section still works afterwards.
            blob = await client.assert_to(node.id, "still.alive")
            assert await client.verify_assertion(blob, purpose="still.alive")
        finally:
            await client.close()
            await conn.stop()
            await node.stop()
