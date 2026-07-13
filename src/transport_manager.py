from collections.abc import Callable, Awaitable
from .transport import BaseTransport, BaseServer
from .uri import _validate_uri, _SCHEME_RE


class TransportError(Exception):
    pass


class TransportManager:

    def __init__(self) -> None:
        self._registry: dict[str, tuple[type[BaseTransport], type[BaseServer]]] = {}
        # Active listeners, keyed by their full URI so a node can listen on
        # several addresses of the same scheme (e.g. two spool:// directories).
        self._servers: dict[str, BaseServer] = {}
        self.on_new_connection: Callable[[BaseTransport], Awaitable[None]] | None = None

    def register(self, scheme: str, transport_cls: type[BaseTransport],
                 server_cls: type[BaseServer]) -> None:
        if not _SCHEME_RE.match(scheme):
            raise TransportError(f"invalid scheme: {scheme!r}")
        if scheme in self._registry:
            raise TransportError(f"scheme already registered: {scheme!r}")
        if not (isinstance(transport_cls, type) and issubclass(transport_cls, BaseTransport)):
            raise TransportError("transport_cls must be a subclass of BaseTransport")
        if not (isinstance(server_cls, type) and issubclass(server_cls, BaseServer)):
            raise TransportError("server_cls must be a subclass of BaseServer")
        self._registry[scheme] = (transport_cls, server_cls)

    def is_supported(self, scheme: str) -> bool:
        return scheme in self._registry

    async def connect(self, uri: str) -> BaseTransport:
        result = _validate_uri(uri)
        if result is None:
            raise TransportError(f"invalid URI: {uri!r}")
        scheme, opaque = result
        if scheme not in self._registry:
            raise TransportError(f"scheme not registered: {scheme!r}")
        transport_cls, _ = self._registry[scheme]
        transport = transport_cls()
        try:
            await transport.connect(opaque)
        except Exception as exc:
            await transport.close()
            raise TransportError(f"connect failed: {exc}") from exc
        return transport

    async def listen(self, uri: str) -> None:
        result = _validate_uri(uri)
        if result is None:
            raise TransportError(f"invalid URI: {uri!r}")
        scheme, opaque = result
        if scheme not in self._registry:
            raise TransportError(f"scheme not registered: {scheme!r}")
        # Key by the exact URI. This both allows multiple listeners per scheme
        # and rejects a duplicate address — important for media with no OS-level
        # bind conflict (e.g. two spool servers on the same directory would
        # otherwise both accept the same sessions and double every peer).
        if uri in self._servers:
            raise TransportError(f"already listening on URI: {uri!r}")
        _, server_cls = self._registry[scheme]
        server = server_cls()
        server.on_new_connection = self._dispatch_incoming
        await server.listen(opaque)
        self._servers[uri] = server

    async def _dispatch_incoming(self, transport: BaseTransport) -> None:
        if self.on_new_connection is None:
            await transport.close()
            return
        await self.on_new_connection(transport)

    def schemes(self) -> list[str]:
        """URL schemes with a registered transport."""
        return sorted(self._registry.keys())

    def scheme_of(self, transport: BaseTransport) -> str | None:
        """Registered scheme a transport instance belongs to, if any."""
        for scheme, (transport_cls, _) in self._registry.items():
            if isinstance(transport, transport_cls):
                return scheme
        return None

    def listening_uris(self) -> list[str]:
        """URIs this manager is currently listening on."""
        return sorted(self._servers.keys())

    async def stop_listen(self, uri: str) -> bool:
        """Stop one active listener. Returns True if it was listening."""
        server = self._servers.pop(uri, None)
        if server is None:
            return False
        try:
            await server.close()
        except Exception:
            pass
        return True

    async def close_all(self) -> None:
        for server in list(self._servers.values()):
            try:
                await server.close()
            except Exception:
                pass
        self._servers.clear()
