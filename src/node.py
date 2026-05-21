import asyncio
import struct
from .node_id import NodeID
from .routing import RoutingTable, NodeEntry
from .transport import BaseTransport
from .packet import Packet
from .crypto import CryptoIdentity, SessionKey
from .invite import InviteManager, compute_response
from .transport import BaseServer
from .tcp_transport import TCPServer, TCPTransport

DATA          = 0x00
PING          = 0x01
PONG          = 0x02
FIND_NODE     = 0x03
FOUND_NODE    = 0x04
HANDSHAKE     = 0x08
HANDSHAKE_ACK = 0x09
INVITE        = 0x0A
INVITE_ACK    = 0x0B
CHALLENGE     = 0x0C

_ACK_ACCEPTED = 0x00
_ACK_REJECTED = 0x01

_ENTRY_HEADER = struct.Struct('!20sB')
_HS_HEADER    = struct.Struct('!HH')


def _encode_entries(entries: list[NodeEntry]) -> bytes:
    out = bytes([len(entries)])
    for e in entries:
        addr = e.address.encode()
        out += _ENTRY_HEADER.pack(e.node_id.raw, len(addr)) + addr
    return out


def _decode_entries(data: bytes) -> list[NodeEntry]:
    count = data[0]
    offset = 1
    entries = []
    for _ in range(count):
        raw_id, addr_len = _ENTRY_HEADER.unpack_from(data, offset)
        offset += _ENTRY_HEADER.size
        address = data[offset:offset + addr_len].decode()
        offset += addr_len
        entries.append(NodeEntry(NodeID(raw_id), address))
    return entries


def _encode_handshake(kem_pub: bytes, dsa_pub: bytes, signature: bytes) -> bytes:
    return _HS_HEADER.pack(len(kem_pub), len(dsa_pub)) + kem_pub + dsa_pub + signature


def _decode_handshake(data: bytes) -> tuple[bytes, bytes, bytes]:
    kem_len, dsa_len = _HS_HEADER.unpack_from(data, 0)
    offset = _HS_HEADER.size
    kem_pub = data[offset:offset + kem_len]; offset += kem_len
    dsa_pub = data[offset:offset + dsa_len]; offset += dsa_len
    return kem_pub, dsa_pub, data[offset:]


def _encode_handshake_ack(ciphertext: bytes, dsa_pub: bytes, signature: bytes) -> bytes:
    return _HS_HEADER.pack(len(ciphertext), len(dsa_pub)) + ciphertext + dsa_pub + signature


def _decode_handshake_ack(data: bytes) -> tuple[bytes, bytes, bytes]:
    ct_len, dsa_len = _HS_HEADER.unpack_from(data, 0)
    offset = _HS_HEADER.size
    ciphertext = data[offset:offset + ct_len]; offset += ct_len
    dsa_pub = data[offset:offset + dsa_len]; offset += dsa_len
    return ciphertext, dsa_pub, data[offset:]


class _Peer:
    """État par connexion : transport, session crypto, pending state."""

    def __init__(self, transport: BaseTransport) -> None:
        self.transport = transport
        self.session: SessionKey | None = None
        self.pending_kem_secret: bytes | None = None
        self.join_code: str | None = None
        self.pending_challenge: bytes | None = None
        self._task: asyncio.Task | None = None

    async def start(self, on_packet) -> None:
        self._task = asyncio.create_task(self._loop(on_packet))

    async def _loop(self, on_packet) -> None:
        try:
            while True:
                packet = await self.transport.receive()
                await on_packet(self, packet)
        except (asyncio.IncompleteReadError, ConnectionError, asyncio.CancelledError):
            pass

    async def send(self, packet: Packet) -> None:
        await self.transport.send(packet)

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        await self.transport.close()


class MeshNode:

    def __init__(self,
                 transport_factory: type[BaseTransport] = TCPTransport,
                 server_factory: type[BaseServer] = TCPServer) -> None:
        self._id = NodeID.generate()
        self._identity = CryptoIdentity()
        self._routing = RoutingTable(self._id)
        self._address: str = ""
        self._running = False
        self._peers: list[_Peer] = []
        self._server: BaseServer | None = None
        self._invite = InviteManager()
        self._data_queue: asyncio.Queue[bytes] = asyncio.Queue()
        self._transport_factory = transport_factory
        self._server_factory = server_factory

    @property
    def id(self) -> NodeID:
        return self._id

    @property
    def session(self) -> SessionKey | None:
        return next((p.session for p in self._peers if p.session is not None), None)

    def generate_invite(self) -> str:
        return self._invite.generate_code()

    async def start(self, address: str) -> None:
        self._address = address
        self._running = True
        self._server = self._server_factory()
        self._server.on_new_connection = self._on_new_transport
        await self._server.listen(address)

    async def join(self, address: str, code: str) -> None:
        transport = self._transport_factory()
        await transport.connect(address)
        peer = _Peer(transport)
        peer.join_code = code
        self._peers.append(peer)
        self._running = True
        await peer.start(self._handle_packet)

    async def stop(self) -> None:
        self._running = False
        for peer in list(self._peers):
            await peer.stop()
        self._peers.clear()
        if self._server:
            await self._server.close()
            self._server = None

    async def wait_for_session(self, timeout: float = 10.0) -> None:
        deadline = asyncio.get_event_loop().time() + timeout
        while not any(p.session is not None for p in self._peers):
            if asyncio.get_event_loop().time() >= deadline:
                raise TimeoutError("session not established in time")
            await asyncio.sleep(0.05)

    async def send_data(self, payload: bytes) -> None:
        targets = [p for p in self._peers if p.session is not None]
        if not targets:
            raise RuntimeError("no session established — handshake required")
        for peer in targets:
            packet = Packet.create_encrypted(DATA, self._id.raw,
                                             NodeID(b"\xff" * 20).raw,
                                             payload, peer.session)
            await peer.send(packet)

    async def receive_data(self) -> bytes:
        return await self._data_queue.get()

    async def ping(self, peer: _Peer) -> None:
        payload = self._address.encode()
        packet = Packet.create(PING, self._id.raw, NodeID(b"\xff" * 20).raw, payload)
        await peer.send(packet)

    async def find_node(self, target: NodeID) -> None:
        for peer in self._peers:
            packet = Packet.create(FIND_NODE, self._id.raw,
                                   NodeID(b"\xff" * 20).raw, target.raw)
            await peer.send(packet)

    async def initiate_handshake(self, peer: _Peer) -> None:
        kem_pub, kem_secret = self._identity.generate_kem_keypair()
        peer.pending_kem_secret = kem_secret
        dsa_pub = self._identity.dsa_public_key
        signature = self._identity.sign(kem_pub + dsa_pub)
        payload = _encode_handshake(kem_pub, dsa_pub, signature)
        packet = Packet.create(HANDSHAKE, self._id.raw,
                               NodeID(b"\xff" * 20).raw, payload)
        await peer.send(packet)

    async def _on_new_transport(self, transport: BaseTransport) -> None:
        peer = _Peer(transport)
        self._peers.append(peer)
        await peer.start(self._handle_packet)
        challenge = self._invite.generate_challenge()
        peer.pending_challenge = challenge
        packet = Packet.create(CHALLENGE, self._id.raw,
                               NodeID(b"\xff" * 20).raw, challenge)
        await peer.send(packet)

    async def _inject_peer(self, transport: BaseTransport) -> _Peer:
        """For testing only — injects a fake transport as a peer."""
        peer = _Peer(transport)
        self._peers.append(peer)
        self._running = True
        await peer.start(self._handle_packet)
        return peer

    async def _handle_packet(self, peer: _Peer, packet: Packet) -> None:
        handlers = {
            DATA:          self._handle_data,
            PING:          self._handle_ping,
            PONG:          self._handle_pong,
            FIND_NODE:     self._handle_find_node,
            FOUND_NODE:    self._handle_found_node,
            HANDSHAKE:     self._handle_handshake,
            HANDSHAKE_ACK: self._handle_handshake_ack,
            CHALLENGE:     self._handle_challenge,
            INVITE:        self._handle_invite,
            INVITE_ACK:    self._handle_invite_ack,
        }
        handler = handlers.get(packet.type)
        if handler:
            await handler(peer, packet)

    async def _handle_data(self, peer: _Peer, packet: Packet) -> None:
        if peer.session is None:
            return
        plaintext = packet.decrypt_payload(peer.session)
        await self._data_queue.put(plaintext)

    async def _handle_ping(self, peer: _Peer, packet: Packet) -> None:
        src = NodeID(packet.src_id)
        address = packet.payload.decode()
        self._routing.add(src, address)
        pong = Packet.create(PONG, self._id.raw, packet.src_id, b"")
        await peer.send(pong)

    async def _handle_pong(self, peer: _Peer, packet: Packet) -> None:
        pass

    async def _handle_find_node(self, peer: _Peer, packet: Packet) -> None:
        target = NodeID(packet.payload)
        closest = self._routing.get_closest(target)
        response = Packet.create(FOUND_NODE, self._id.raw, packet.src_id,
                                 _encode_entries(closest))
        await peer.send(response)

    async def _handle_found_node(self, peer: _Peer, packet: Packet) -> None:
        entries = _decode_entries(packet.payload)
        for entry in entries:
            self._routing.add(entry.node_id, entry.address)

    async def _handle_challenge(self, peer: _Peer, packet: Packet) -> None:
        if peer.join_code is None:
            return
        response = compute_response(peer.join_code, packet.payload)
        invite_pkt = Packet.create(INVITE, self._id.raw, packet.src_id, response)
        await peer.send(invite_pkt)

    async def _handle_invite(self, peer: _Peer, packet: Packet) -> None:
        if peer.pending_challenge is None:
            return
        if not self._invite.verify_response(peer.pending_challenge, packet.payload):
            self._invite.record_failure()
            ack = Packet.create(INVITE_ACK, self._id.raw, packet.src_id,
                                bytes([_ACK_REJECTED]))
            await peer.send(ack)
            return
        self._invite.consume(peer.pending_challenge, packet.payload)
        peer.pending_challenge = None
        ack = Packet.create(INVITE_ACK, self._id.raw, packet.src_id,
                            bytes([_ACK_ACCEPTED]))
        await peer.send(ack)

    async def _handle_invite_ack(self, peer: _Peer, packet: Packet) -> None:
        if packet.payload[0] == _ACK_ACCEPTED:
            peer.join_code = None
            await self.initiate_handshake(peer)

    async def _handle_handshake(self, peer: _Peer, packet: Packet) -> None:
        kem_pub, bob_dsa_pub, signature = _decode_handshake(packet.payload)
        if not self._identity.verify(kem_pub + bob_dsa_pub, signature, bob_dsa_pub):
            return
        ciphertext, shared_secret = self._identity.kem_encapsulate(kem_pub)
        peer.session = SessionKey(shared_secret)
        dsa_pub = self._identity.dsa_public_key
        signature = self._identity.sign(ciphertext + dsa_pub)
        payload = _encode_handshake_ack(ciphertext, dsa_pub, signature)
        ack = Packet.create(HANDSHAKE_ACK, self._id.raw, packet.src_id, payload)
        await peer.send(ack)

    async def _handle_handshake_ack(self, peer: _Peer, packet: Packet) -> None:
        if peer.pending_kem_secret is None:
            return
        ciphertext, alice_dsa_pub, signature = _decode_handshake_ack(packet.payload)
        if not self._identity.verify(ciphertext + alice_dsa_pub, signature, alice_dsa_pub):
            return
        shared_secret = self._identity.kem_decapsulate(ciphertext,
                                                        peer.pending_kem_secret)
        peer.session = SessionKey(shared_secret)
        peer.pending_kem_secret = None
