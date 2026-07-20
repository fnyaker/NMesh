from abc import ABC, abstractmethod
from collections.abc import Callable, Coroutine
from typing import Any, TYPE_CHECKING

from .packet import Packet

if TYPE_CHECKING:
    pass


class BaseTransport(ABC):
    """
    Represents a single bidirectional connection between two nodes.

    One instance = one link. The transport is responsible for:
    - Framing (delimiting packet boundaries on stream protocols like TCP)
    - Serialisation of Packet objects to bytes and back

    It knows nothing about routing, encryption, or the mesh protocol.
    """

    def __init__(self) -> None:
        self.on_connect: Callable[[], Coroutine[Any, Any, None]] | None = None

    @abstractmethod
    async def connect(self, address: str) -> None:
        """Open an outgoing connection to the given address."""
        ...

    @abstractmethod
    async def listen(self, address: str) -> None:
        """Listen on the given address and accept exactly one incoming connection.
        Blocks until a client connects."""
        ...

    @abstractmethod
    async def send(self, packet: Packet) -> None:
        """Send a packet over this connection."""
        ...

    @abstractmethod
    async def receive(self) -> Packet:
        """Block until a packet is received and return it."""
        ...

    @abstractmethod
    async def close(self) -> None:
        """Close this connection and release resources."""
        ...

    def remote_ip(self) -> str | None:
        """The peer's source IP as observed locally, if the medium exposes one.

        Lets a node learn its own public address from a peer that accepted its
        connection (mesh-native public-IP discovery). Media without a network
        address (e.g. spool files) return None."""
        return None


class BaseServer(ABC):
    """
    Server-side transport: listens and accepts multiple incoming connections.

    One instance = one listening endpoint that spawns a new BaseTransport
    per accepted client. The server calls on_new_connection(transport) for
    each incoming connection.

    Implement this alongside BaseTransport to make your protocol fully
    pluggable with MeshNode.
    """

    def __init__(self) -> None:
        self.on_new_connection: (
            Callable[['BaseTransport'], Coroutine[Any, Any, None]] | None
        ) = None

    @abstractmethod
    async def listen(self, address: str) -> None:
        """Bind to the given address and start accepting connections.
        Returns immediately after binding (non-blocking)."""
        ...

    @abstractmethod
    async def close(self) -> None:
        """Stop accepting connections and release resources."""
        ...

    def reachability(self, uri: str, ctx: dict) -> list[dict]:
        """Describe how this server can be reached, and by which audience.

        Transport-agnostic: the core never classifies addresses itself — each
        transport reports its own reachability descriptors. A descriptor is::

            {"transport": scheme, "scope": "world"|"lan"|"broadcast"|"none",
             "anchor": str, "address": uri|None, "confirmed": bool}

        ``scope`` is the audience breadth; ``anchor`` distinguishes two audiences
        of the same breadth (e.g. a LAN ``192.168.0.0/24`` is anchored by the
        public IP it sits behind, so it is not the neighbour's identical range).
        ``uri`` is this listener's URI; ``ctx`` carries node-level discovered
        facts (see ``MeshNode._reachability_ctx``). Default: nothing known."""
        return []

    async def broadcast(self, data: bytes) -> bool:
        """Send *data* to every reachable peer on this medium at once, if the
        transport supports it (LAN UDP, BLE advertising, LoRa…). Used for
        opportunistic discovery when no relay is configured. Returns True if
        the transport actually broadcast. Default: not broadcast-capable."""
        return False
