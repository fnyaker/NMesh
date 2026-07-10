import asyncio
import pytest
from src.transport_manager import TransportManager, TransportError
from src.transport import BaseTransport, BaseServer
from src.packet import Packet
from tests.conftest import FakeTransport, FakeServer


def make_manager() -> TransportManager:
    m = TransportManager()
    m.register("fake", FakeTransport, FakeServer)
    return m


# ---------------------------------------------------------------------------
# register()
# ---------------------------------------------------------------------------

class TestRegister:
    def test_register_valid_scheme(self):
        m = TransportManager()
        m.register("tcp", FakeTransport, FakeServer)
        assert m.is_supported("tcp")

    def test_register_invalid_scheme_uppercase(self):
        m = TransportManager()
        with pytest.raises(TransportError):
            m.register("TCP", FakeTransport, FakeServer)

    def test_register_invalid_scheme_empty(self):
        m = TransportManager()
        with pytest.raises(TransportError):
            m.register("", FakeTransport, FakeServer)

    def test_register_invalid_scheme_too_long(self):
        m = TransportManager()
        with pytest.raises(TransportError):
            m.register("a" * 17, FakeTransport, FakeServer)

    def test_register_invalid_scheme_starts_with_digit(self):
        m = TransportManager()
        with pytest.raises(TransportError):
            m.register("1tcp", FakeTransport, FakeServer)

    def test_register_duplicate_scheme_rejected(self):
        m = TransportManager()
        m.register("tcp", FakeTransport, FakeServer)
        with pytest.raises(TransportError):
            m.register("tcp", FakeTransport, FakeServer)

    def test_register_bad_transport_cls(self):
        m = TransportManager()
        with pytest.raises(TransportError):
            m.register("tcp", object, FakeServer)

    def test_register_bad_server_cls(self):
        m = TransportManager()
        with pytest.raises(TransportError):
            m.register("tcp", FakeTransport, object)


# ---------------------------------------------------------------------------
# connect()
# ---------------------------------------------------------------------------

class TestConnect:
    async def test_connect_unknown_scheme_raises(self):
        m = TransportManager()
        with pytest.raises(TransportError):
            await m.connect("tcp://127.0.0.1:9000")

    async def test_connect_malformed_uri_raises(self):
        m = make_manager()
        with pytest.raises(TransportError):
            await m.connect("not-a-uri")

    async def test_connect_returns_transport(self):
        m = make_manager()
        t = await m.connect("fake://anything")
        assert isinstance(t, FakeTransport)

    async def test_connect_failure_closes_transport(self):
        """A connect() that raises must close the partially-initialised transport."""
        closed: list[bool] = []

        class FailingTransport(FakeTransport):
            async def connect(self, address: str) -> None:
                raise ConnectionRefusedError("nope")

            async def close(self) -> None:
                closed.append(True)

        m = TransportManager()
        m.register("fail", FailingTransport, FakeServer)
        with pytest.raises(TransportError):
            await m.connect("fail://host")
        assert closed == [True]


# ---------------------------------------------------------------------------
# listen()
# ---------------------------------------------------------------------------

class TestListen:
    async def test_listen_starts_server(self):
        m = make_manager()
        await m.listen("fake://anything")
        assert "fake://anything" in m._servers

    async def test_listen_failure_no_server_stored(self):
        class FailingServer(FakeServer):
            async def listen(self, address: str) -> None:
                raise OSError("bind failed")

        m = TransportManager()
        m.register("fail", FakeTransport, FailingServer)
        with pytest.raises(OSError):
            await m.listen("fail://anything")
        assert "fail://anything" not in m._servers

    async def test_listen_multiple_addresses_same_scheme(self):
        # Several listeners of the same scheme on distinct addresses are allowed.
        m = make_manager()
        await m.listen("fake://first")
        await m.listen("fake://second")
        assert "fake://first" in m._servers
        assert "fake://second" in m._servers

    async def test_listen_duplicate_uri_rejected(self):
        m = make_manager()
        await m.listen("fake://same")
        with pytest.raises(TransportError):
            await m.listen("fake://same")

    async def test_listen_unknown_scheme_raises(self):
        m = TransportManager()
        with pytest.raises(TransportError):
            await m.listen("tcp://127.0.0.1:9000")

    async def test_listen_malformed_uri_raises(self):
        m = make_manager()
        with pytest.raises(TransportError):
            await m.listen("not-a-uri")


# ---------------------------------------------------------------------------
# close_all()
# ---------------------------------------------------------------------------

class TestCloseAll:
    async def test_close_all_stops_all_servers(self):
        closed: list[str] = []

        class TrackingServer(FakeServer):
            def __init__(self, name: str) -> None:
                super().__init__()
                self._name = name

            async def close(self) -> None:
                closed.append(self._name)

        class TrackingServerA(TrackingServer):
            def __init__(self) -> None:
                super().__init__("a")

        class TrackingServerB(TrackingServer):
            def __init__(self) -> None:
                super().__init__("b")

        m = TransportManager()
        m.register("scha", FakeTransport, TrackingServerA)
        m.register("schb", FakeTransport, TrackingServerB)
        await m.listen("scha://x")
        await m.listen("schb://x")
        await m.close_all()
        assert set(closed) == {"a", "b"}
        assert m._servers == {}

    async def test_close_all_continues_on_error(self):
        closed: list[str] = []

        class ErrorServer(FakeServer):
            async def close(self) -> None:
                raise RuntimeError("boom")

        class OkServer(FakeServer):
            async def close(self) -> None:
                closed.append("ok")

        m = TransportManager()
        m.register("err", FakeTransport, ErrorServer)
        m.register("ok", FakeTransport, OkServer)
        await m.listen("err://x")
        await m.listen("ok://x")
        await m.close_all()  # should not raise
        assert "ok" in closed


# ---------------------------------------------------------------------------
# _dispatch_incoming()
# ---------------------------------------------------------------------------

class TestDispatch:
    async def test_incoming_connection_dispatched_to_callback(self):
        received: list[BaseTransport] = []

        async def on_conn(t: BaseTransport) -> None:
            received.append(t)

        m = make_manager()
        m.on_new_connection = on_conn
        fake = FakeTransport()
        await m._dispatch_incoming(fake)
        assert received == [fake]

    async def test_incoming_connection_closed_when_no_callback(self):
        closed: list[bool] = []

        class TrackingTransport(FakeTransport):
            async def close(self) -> None:
                closed.append(True)

        m = make_manager()
        await m._dispatch_incoming(TrackingTransport())
        assert closed == [True]
