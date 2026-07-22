import asyncio
import pytest
from src.transport import BaseTransport, BaseServer
from src.transport_manager import TransportManager
from src.packet import Packet
from src.node import MeshNode
from typing import TYPE_CHECKING


class FakeTransport(BaseTransport):
    def __init__(self) -> None:
        super().__init__()
        self.sent: list[Packet] = []
        self._queue: asyncio.Queue[Packet] = asyncio.Queue()
        self.connect_error: Exception | None = None

    async def connect(self, address: str) -> None:
        if self.connect_error is not None:
            raise self.connect_error

    async def listen(self, address: str) -> None: ...
    async def close(self) -> None: ...

    async def send(self, packet: Packet) -> None:
        self.sent.append(packet)

    async def receive(self) -> Packet:
        return await self._queue.get()

    def inject(self, packet: Packet) -> None:
        self._queue.put_nowait(packet)


class FakeServer(BaseServer):
    async def listen(self, address: str) -> None: ...
    async def close(self) -> None: ...


def make_manager() -> TransportManager:
    manager = TransportManager()
    manager.register("fake", FakeTransport, FakeServer)
    return manager


async def make_node() -> tuple[MeshNode, FakeTransport]:
    fake = FakeTransport()
    node = MeshNode(transport_manager=make_manager())
    await node._inject_peer(fake)
    return node, fake


# ---------------------------------------------------------------------------
# Bidirectional fake transport for on-demand routing tests
# ---------------------------------------------------------------------------

class LinkedFakeTransport(BaseTransport):
    """Each send() delivers the packet to partner's recv queue."""

    def __init__(self) -> None:
        super().__init__()
        self.sent: list[Packet] = []
        self._recv_queue: asyncio.Queue[Packet] = asyncio.Queue()
        self.partner: 'LinkedFakeTransport | None' = None

    async def connect(self, address: str) -> None: ...
    async def listen(self, address: str) -> None: ...
    async def close(self) -> None: ...

    async def send(self, packet: Packet) -> None:
        self.sent.append(packet)
        if self.partner is not None:
            self.partner._recv_queue.put_nowait(packet)

    async def receive(self) -> Packet:
        return await self._recv_queue.get()


class ConnectableFakeTransportManager:
    """
    Drop-in transport manager for on-demand routing tests.

    Pre-register ``address → MeshNode`` mappings with ``register_target``.
    When ``connect(uri)`` is called, a ``LinkedFakeTransport`` pair is created
    and ``_on_new_transport`` is triggered on the target node automatically —
    so the full CHALLENGE → HANDSHAKE → HANDSHAKE_ACK flow runs without any
    manual injection.

    Pass ``target_node=None`` to ``register_target`` to register a dead address
    where no handshake will ever complete (useful for timeout tests).
    """

    def __init__(self) -> None:
        self._targets: dict[str, 'MeshNode | None'] = {}
        self.on_new_connection = None   # set by MeshNode.__init__
        self.connect_calls: int = 0

    def register_target(self, address: str, node: 'MeshNode | None') -> None:
        self._targets[address] = node

    def is_supported(self, scheme: str) -> bool:
        return True

    async def connect(self, uri: str) -> BaseTransport:
        self.connect_calls += 1
        if uri not in self._targets:
            raise Exception(f"ConnectableFakeTransportManager: no target for {uri!r}")
        target_node = self._targets[uri]
        client = LinkedFakeTransport()
        if target_node is not None:
            server = LinkedFakeTransport()
            client.partner = server
            server.partner = client
            asyncio.create_task(target_node._on_new_transport(server))
        return client

    async def listen(self, uri: str) -> None: ...
    async def close_all(self) -> None: ...


# ---------------------------------------------------------------------------
# Keep tests off the public internet
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _no_public_network_probes(monkeypatch):
    """Stub the node's outward network discovery for every test.

    ``discover_public_ip`` (HTTP to ip.me/…) and the STUN probe reach the public
    internet. On a restricted network (CI, air-gapped) a DNS or connect that
    hangs would wedge the whole run — the cause of a job that never finishes.
    Real discovery is network-dependent and not asserted anywhere here, so make
    both fast no-ops. Tests that exercise discovery inject their own probes."""
    async def _none(self, *args, **kwargs):
        return None
    monkeypatch.setattr(MeshNode, "discover_public_ip", _none, raising=False)
    monkeypatch.setattr(MeshNode, "_probe_stun_if_udp", _none, raising=False)
