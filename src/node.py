import asyncio
import os
import struct
import time
from collections import OrderedDict
from .node_id import NodeID
from .routing import RoutingTable, NodeEntry
from .transport import BaseTransport
from .packet import Packet
from .crypto import CryptoIdentity, SessionKey
from .invite import InviteManager, compute_response
from .cert import Certificate
from .cert_store import CertStore
from .transport_manager import TransportManager
from .metrics import NodeMetrics, Counters
from .dht import ContentStore
from .ip_utils import local_ip_addresses, expand_listen_uri
from .app_package import (
    build as _app_build, parse_manifest as _app_parse_manifest,
    reassemble as _app_reassemble, chunk_keys as _app_chunk_keys,
    content_key as _content_key, AppPackageError,
    pack_root as _app_pack_root, parse_root as _app_parse_root,
    reassemble_bytes as _app_reassemble_bytes,
)
from .uri import _validate_uri, _MAX_URI_LEN, _MAX_ADDRESSES

_HEADER_BYTES = 79  # fixed packet header size, for byte accounting

DATA          = 0x00
PING          = 0x01
PONG          = 0x02
FIND_NODE     = 0x03
FOUND_NODE    = 0x04
FIND_VALUE    = 0x05
FOUND_VALUE   = 0x06
STORE         = 0x07
HANDSHAKE     = 0x08
HANDSHAKE_ACK = 0x09
INVITE        = 0x0A
INVITE_ACK    = 0x0B
CHALLENGE         = 0x0C
E2E_HANDSHAKE     = 0x0D
E2E_HANDSHAKE_ACK = 0x0E

_ACK_ACCEPTED = 0x00
_ACK_REJECTED = 0x01

# HANDSHAKE: kem_len(H) | dsa_len(H) | chain_bytes_len(H)
_HS_HEADER   = struct.Struct('!HHH')
# HANDSHAKE_ACK: ct_len(H) | dsa_len(H) | chain_bytes_len(H) | issued_cert_len(H)
_ACK_HEADER  = struct.Struct('!HHHH')
# FOUND_NODE entry: node_id(20) | addr_count(B) | chain_bytes_len(H)
_ENTRY_HEADER = struct.Struct('!20sBH')
# Per-cert length prefix inside a chain blob
_CERT_LEN    = struct.Struct('!H')
# Address length prefix inside address lists
_ADDR_LEN    = struct.Struct('!H')
# E2E handshake: nonce(32) || var1_len(H) || var2_len(H) || chain_bytes_len(H)
_E2E_HEADER  = struct.Struct('!32sHHH')

_DIRECT_TYPES    = {PING, PONG, FIND_NODE, FOUND_NODE, FIND_VALUE, FOUND_VALUE, STORE}
_ROUTABLE_TYPES  = {DATA, E2E_HANDSHAKE, E2E_HANDSHAKE_ACK}
_DHT_K              = 6      # replication: store/fetch across this many closest nodes
_DHT_QUERY_TIMEOUT  = 5.0
_POST_AUTH_TYPES = _DIRECT_TYPES | _ROUTABLE_TYPES
_BROADCAST_ID    = b"\xff" * 20
_MSG_DEDUP_MAX         = 10_000
_MAX_PEERS             = 128
_MAX_MALFORMED         = 32     # bad frames from one peer before we cut it (node rejection)
_MAX_PENDING_PER_TARGET = 128   # buffered payloads awaiting an E2E session, per target
_MAX_PENDING_TARGETS    = 256   # distinct half-open destinations kept in RAM
_ON_DEMAND_TIMEOUT     = 5.0    # transport open + handshake
_KAD_LOOKUP_TIMEOUT    = 3.0    # per FIND_NODE round
_KAD_LOOKUP_MAX_ROUNDS = 2
_AUTH_POLL_INTERVAL    = 0.05
_QID_LEN               = 8     # query_id bytes appended to FIND_NODE / prefix of FOUND_NODE


# ---------------------------------------------------------------------------
# Chain codec
# ---------------------------------------------------------------------------

def _encode_chain(chain: list[Certificate]) -> bytes:
    """count(B) || [cert_len(H) || cert_bytes]*count"""
    parts: list[bytes] = [bytes([len(chain)])]
    for cert in chain:
        cert_bytes = cert.serialize()
        parts.append(_CERT_LEN.pack(len(cert_bytes)))
        parts.append(cert_bytes)
    return b"".join(parts)


def _decode_chain(data: bytes) -> list[Certificate]:
    if not data:
        return []
    count = data[0]
    offset = 1
    certs: list[Certificate] = []
    for _ in range(count):
        if offset + 2 > len(data):
            raise ValueError("chain truncated at length field")
        cert_len = _CERT_LEN.unpack_from(data, offset)[0]
        offset += 2
        if offset + cert_len > len(data):
            raise ValueError("chain truncated at cert data")
        certs.append(Certificate.deserialize(data[offset:offset + cert_len]))
        offset += cert_len
    return certs


# ---------------------------------------------------------------------------
# Handshake codec
# ---------------------------------------------------------------------------

def _encode_handshake(kem_pub: bytes, dsa_pub: bytes,
                      chain: list[Certificate], signature: bytes) -> bytes:
    chain_bytes = _encode_chain(chain)
    return (_HS_HEADER.pack(len(kem_pub), len(dsa_pub), len(chain_bytes))
            + kem_pub + dsa_pub + chain_bytes + signature)


def _decode_handshake(data: bytes) -> tuple[bytes, bytes, list[Certificate], bytes]:
    if len(data) < _HS_HEADER.size:
        raise ValueError("handshake payload too short")
    kem_len, dsa_len, chain_len = _HS_HEADER.unpack_from(data, 0)
    offset = _HS_HEADER.size
    if offset + kem_len + dsa_len + chain_len > len(data):
        raise ValueError("handshake payload truncated")
    kem_pub     = data[offset:offset + kem_len];   offset += kem_len
    dsa_pub     = data[offset:offset + dsa_len];   offset += dsa_len
    chain_bytes = data[offset:offset + chain_len]; offset += chain_len
    return kem_pub, dsa_pub, _decode_chain(chain_bytes), data[offset:]


def _encode_handshake_ack(ciphertext: bytes, dsa_pub: bytes,
                          chain: list[Certificate],
                          issued_cert: Certificate | None,
                          signature: bytes) -> bytes:
    chain_bytes  = _encode_chain(chain)
    issued_bytes = issued_cert.serialize() if issued_cert is not None else b""
    return (_ACK_HEADER.pack(len(ciphertext), len(dsa_pub),
                             len(chain_bytes), len(issued_bytes))
            + ciphertext + dsa_pub + chain_bytes + issued_bytes + signature)


def _decode_handshake_ack(data: bytes) -> tuple[bytes, bytes, list[Certificate],
                                                 Certificate | None, bytes]:
    if len(data) < _ACK_HEADER.size:
        raise ValueError("handshake_ack payload too short")
    ct_len, dsa_len, chain_len, issued_len = _ACK_HEADER.unpack_from(data, 0)
    offset = _ACK_HEADER.size
    if offset + ct_len + dsa_len + chain_len + issued_len > len(data):
        raise ValueError("handshake_ack payload truncated")
    ciphertext   = data[offset:offset + ct_len];     offset += ct_len
    dsa_pub      = data[offset:offset + dsa_len];    offset += dsa_len
    chain_bytes  = data[offset:offset + chain_len];  offset += chain_len
    issued_bytes = data[offset:offset + issued_len]; offset += issued_len
    chain       = _decode_chain(chain_bytes)
    issued_cert = Certificate.deserialize(issued_bytes) if issued_bytes else None
    return ciphertext, dsa_pub, chain, issued_cert, data[offset:]


# ---------------------------------------------------------------------------
# Address list codec
# addr_count(B) || [addr_len(H) || addr_bytes]*addr_count
# ---------------------------------------------------------------------------

def _encode_addresses(addresses: list[str]) -> bytes:
    count = min(len(addresses), _MAX_ADDRESSES)
    parts: list[bytes] = [bytes([count])]
    for addr in addresses[:count]:
        b = addr.encode('utf-8')
        parts.append(_ADDR_LEN.pack(len(b)))
        parts.append(b)
    return b"".join(parts)


def _decode_addresses(data: bytes) -> list[str]:
    """Decode a packed address list. Raises ValueError on structural errors or count > _MAX_ADDRESSES."""
    if not data:
        raise ValueError("empty address payload")
    count = data[0]
    if count > _MAX_ADDRESSES:
        raise ValueError(f"too many addresses: {count}")
    offset = 1
    addresses: list[str] = []
    for _ in range(count):
        if offset + 2 > len(data):
            raise ValueError("truncated addr_len")
        addr_len = _ADDR_LEN.unpack_from(data, offset)[0]
        offset += 2
        if addr_len > _MAX_URI_LEN:
            raise ValueError(f"addr_len too large: {addr_len}")
        if offset + addr_len > len(data):
            raise ValueError("truncated addr_bytes")
        addr = data[offset:offset + addr_len].decode('utf-8')
        addresses.append(addr)
        offset += addr_len
    return addresses


# ---------------------------------------------------------------------------
# E2E handshake codecs
# E2E_HANDSHAKE payload:  nonce(32) || kem_pub_len(H) || dsa_pub_len(H) || chain_len(H)
#                          || kem_pub || dsa_pub || chain_bytes || signature
# E2E_HANDSHAKE_ACK payload: same struct, fields are ct_len / dsa_len / chain_len
#                          || ciphertext || dsa_pub || chain_bytes || signature
# ---------------------------------------------------------------------------

def _encode_e2e_handshake(nonce: bytes, kem_pub: bytes, dsa_pub: bytes,
                           chain: list[Certificate], signature: bytes) -> bytes:
    chain_bytes = _encode_chain(chain)
    return (_E2E_HEADER.pack(nonce, len(kem_pub), len(dsa_pub), len(chain_bytes))
            + kem_pub + dsa_pub + chain_bytes + signature)


def _decode_e2e_handshake(data: bytes) -> tuple[bytes, bytes, bytes, list[Certificate], bytes]:
    if len(data) < _E2E_HEADER.size:
        raise ValueError("e2e_handshake payload too short")
    nonce, kem_len, dsa_len, chain_len = _E2E_HEADER.unpack_from(data, 0)
    offset = _E2E_HEADER.size
    if offset + kem_len + dsa_len + chain_len > len(data):
        raise ValueError("e2e_handshake payload truncated")
    kem_pub     = data[offset:offset + kem_len];   offset += kem_len
    dsa_pub     = data[offset:offset + dsa_len];   offset += dsa_len
    chain_bytes = data[offset:offset + chain_len]; offset += chain_len
    return nonce, kem_pub, dsa_pub, _decode_chain(chain_bytes), data[offset:]


def _encode_e2e_handshake_ack(nonce: bytes, ciphertext: bytes, dsa_pub: bytes,
                               chain: list[Certificate], signature: bytes) -> bytes:
    chain_bytes = _encode_chain(chain)
    return (_E2E_HEADER.pack(nonce, len(ciphertext), len(dsa_pub), len(chain_bytes))
            + ciphertext + dsa_pub + chain_bytes + signature)


def _decode_e2e_handshake_ack(data: bytes) -> tuple[bytes, bytes, bytes, list[Certificate], bytes]:
    if len(data) < _E2E_HEADER.size:
        raise ValueError("e2e_handshake_ack payload too short")
    nonce, ct_len, dsa_len, chain_len = _E2E_HEADER.unpack_from(data, 0)
    offset = _E2E_HEADER.size
    if offset + ct_len + dsa_len + chain_len > len(data):
        raise ValueError("e2e_handshake_ack payload truncated")
    ciphertext  = data[offset:offset + ct_len];    offset += ct_len
    dsa_pub     = data[offset:offset + dsa_len];   offset += dsa_len
    chain_bytes = data[offset:offset + chain_len]; offset += chain_len
    return nonce, ciphertext, dsa_pub, _decode_chain(chain_bytes), data[offset:]


# ---------------------------------------------------------------------------
# FOUND_NODE entry codec
# node_id(20) | addr_count(B) | chain_bytes_len(H)
#   | [addr_len(H) | addr_bytes]*addr_count
#   | chain_bytes
# ---------------------------------------------------------------------------

def _encode_entries(entries: list[NodeEntry]) -> bytes:
    out = bytes([len(entries)])
    for e in entries:
        chain_bytes = _encode_chain(e.cert_chain)
        addrs = e.addresses[:_MAX_ADDRESSES]
        out += _ENTRY_HEADER.pack(e.node_id.raw, len(addrs), len(chain_bytes))
        for addr in addrs:
            b = addr.encode('utf-8')
            out += _ADDR_LEN.pack(len(b)) + b
        out += chain_bytes
    return out


def _decode_entries(data: bytes) -> list[NodeEntry]:
    if len(data) < 1:
        raise ValueError("empty payload")
    count = data[0]
    offset = 1
    entries: list[NodeEntry] = []
    for _ in range(count):
        if offset + _ENTRY_HEADER.size > len(data):
            raise ValueError("truncated entry header")
        raw_id, addr_count, chain_bytes_len = _ENTRY_HEADER.unpack_from(data, offset)
        offset += _ENTRY_HEADER.size
        if addr_count > _MAX_ADDRESSES:
            raise ValueError(f"too many addresses in entry: {addr_count}")
        addresses: list[str] = []
        valid = True
        for _ in range(addr_count):
            if offset + 2 > len(data):
                raise ValueError("truncated addr_len in entry")
            addr_len = _ADDR_LEN.unpack_from(data, offset)[0]
            offset += 2
            if addr_len > _MAX_URI_LEN:
                valid = False
            if offset + addr_len > len(data):
                raise ValueError("truncated addr_bytes in entry")
            try:
                addr = data[offset:offset + addr_len].decode('utf-8')
            except UnicodeDecodeError:
                valid = False
                addr = ""
            offset += addr_len
            if _validate_uri(addr) is None:
                valid = False
            addresses.append(addr)
        if offset + chain_bytes_len > len(data):
            raise ValueError("truncated chain in entry")
        chain_bytes = data[offset:offset + chain_bytes_len]
        offset += chain_bytes_len
        if not valid:
            continue  # drop entry with any malformed URI
        try:
            chain = _decode_chain(chain_bytes)
        except Exception:
            chain = []
        entries.append(NodeEntry(NodeID(raw_id), addresses, b"", chain))
    return entries


# ---------------------------------------------------------------------------
# Peer state
# ---------------------------------------------------------------------------

class _Peer:

    def __init__(self, transport: BaseTransport, is_client_side: bool = False) -> None:
        self.transport = transport
        self.session: SessionKey | None = None
        self.pending_kem_secret: bytes | None = None
        self.join_code: str | None = None
        self.pending_challenge: bytes | None = None
        self.received_challenge: bytes | None = None
        self.authenticated_id: NodeID | None = None
        self.invite_accepted: bool = False
        self.invite_sent: bool = False
        self.is_client_side: bool = is_client_side
        self.remote_addr: str | None = None   # dialled URI, for routing/reconnect
        self._invite_failures: int = 0
        self._invite_lockout_ts: float = 0.0
        self.dsa_pub: bytes = b""
        self._malformed: int = 0
        self.counters = Counters()   # per-link throughput
        self.total = None            # node-wide Counters, set by the node
        # Invoked when the receive loop exits on its own (dead link or abuse),
        # so the node can prune this peer. Cleared on intentional stop().
        self.on_dead = None
        self._task: asyncio.Task | None = None

    async def start(self, on_packet) -> None:
        self._task = asyncio.create_task(self._run(on_packet))

    async def _run(self, on_packet) -> None:
        try:
            await self._loop(on_packet)
        finally:
            cb = self.on_dead
            if cb is not None:
                self.on_dead = None
                try:
                    await cb(self)
                except Exception:
                    pass

    async def _loop(self, on_packet) -> None:
        while True:
            try:
                packet = await self.transport.receive()
            except asyncio.CancelledError:
                raise
            except (asyncio.IncompleteReadError, ConnectionError, OSError, EOFError):
                return  # link is dead — exit so the node reaps this peer
            except Exception:
                # Malformed frame on a still-live link (e.g. bad length prefix,
                # oversized payload). One bad packet must never kill the link:
                # drop it, count the abuse, and keep serving. Persistent garbage
                # is treated as hostile and the peer is cut.
                self._malformed += 1
                if self._malformed > _MAX_MALFORMED:
                    return
                continue
            nbytes = _HEADER_BYTES + len(packet.payload)
            self.counters.on_in(nbytes)
            if self.total is not None:
                self.total.on_in(nbytes)
            try:
                await on_packet(self, packet)
            except asyncio.CancelledError:
                raise
            except Exception:
                pass  # malformed payload or handler bug — drop, loop continues

    async def send(self, packet: Packet) -> None:
        await self.transport.send(packet)
        nbytes = _HEADER_BYTES + len(packet.payload)
        self.counters.on_out(nbytes)
        if self.total is not None:
            self.total.on_out(nbytes)

    async def stop(self) -> None:
        self.on_dead = None  # intentional shutdown — do not trigger reaping
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        await self.transport.close()


# ---------------------------------------------------------------------------
# MeshNode
# ---------------------------------------------------------------------------

class MeshNode:

    def __init__(self,
                 transport_manager: TransportManager,
                 identity_path: str | None = None,
                 cert_store_path: str | None = None,
                 session_store_path: str | None = None) -> None:
        if identity_path:
            self._identity = CryptoIdentity.load(identity_path)
            self._identity.save(identity_path)
        else:
            self._identity = CryptoIdentity()
        self._id = NodeID.from_public_key(self._identity.dsa_public_key)
        self._routing = RoutingTable(self._id)
        self._addresses: list[str] = []      # configured listen URIs (may be wildcard)
        self._local_ips: list[str] = []      # cached host addresses (for expansion)
        self._extra_addrs: list[str] = []    # externally-discovered (e.g. public IP)
        self._running = False
        self._peers: list[_Peer] = []
        self._invite = InviteManager()
        self._cert_store_path = cert_store_path
        self._cert_store = (CertStore.load(cert_store_path, self._id)
                            if cert_store_path else CertStore(self._id))
        self._cert_store.add(self._identity.self_signed_cert())
        self._seen_msgs: OrderedDict[int, float] = OrderedDict()
        self._data_queue: asyncio.Queue[tuple[NodeID, bytes]] = asyncio.Queue()
        self._e2e_sessions: dict[NodeID, SessionKey] = {}
        self._e2e_pending_kem: dict[NodeID, bytes] = {}
        self._e2e_pending_nonce: dict[NodeID, bytes] = {}
        self._e2e_pending_data: dict[NodeID, list[bytes]] = {}
        self._pending_connections: dict[NodeID, asyncio.Event] = {}
        self._pending_lookups: dict[NodeID, asyncio.Event] = {}
        self._pending_finds: dict[bytes, asyncio.Future] = {}
        self._dht_store = ContentStore()
        self._pending_values: dict[bytes, asyncio.Future] = {}
        self._transport_manager = transport_manager
        self._metrics = NodeMetrics()
        # Opt-in E2E session persistence (encrypted at rest). Off by default:
        # keys stay in RAM only. When enabled, resume prior sessions on start.
        self._session_store = None
        if session_store_path:
            from .session_store import SessionStore
            self._session_store = SessionStore(session_store_path, self._identity)
            restored = self._session_store.load()
            self._e2e_sessions.update(restored.e2e_sessions)
            self._e2e_pending_kem.update(restored.pending_kem)
            self._e2e_pending_nonce.update(restored.pending_nonce)
            self._e2e_pending_data.update(restored.pending_data)
            # Restore known peers so links can be rebuilt on demand after a
            # restart — re-authenticated via the persisted cert store, so no
            # re-invitation is needed.
            self._routing.import_entries(restored.routing)
        transport_manager.on_new_connection = self._on_new_transport

    @property
    def id(self) -> NodeID:
        return self._id

    @property
    def session(self) -> SessionKey | None:
        return next((p.session for p in self._peers if p.session is not None), None)

    def generate_invite(self) -> str:
        return self._invite.generate_code()

    async def start(self, addresses: list[str]) -> None:
        self._running = True
        for uri in addresses:
            try:
                await self._transport_manager.listen(uri)
                self._addresses.append(uri)
            except Exception:
                pass
        self._local_ips = local_ip_addresses()

    async def add_listen(self, uri: str) -> None:
        """Start listening on another address at runtime (e.g. add a port)."""
        await self._transport_manager.listen(uri)
        if uri not in self._addresses:
            self._addresses.append(uri)
        self._running = True
        self._local_ips = local_ip_addresses()

    async def remove_listen(self, uri: str) -> bool:
        """Stop listening on an address at runtime."""
        ok = await self._transport_manager.stop_listen(uri)
        if uri in self._addresses:
            self._addresses.remove(uri)
        return ok

    def advertised_uris(self) -> list[str]:
        """Concrete, connectable URIs a peer can reach us at — each configured
        listen URI expanded over the host's addresses (and any discovered
        external address). Wildcards like 0.0.0.0 become one URI per address."""
        out: list[str] = []
        seen: set[str] = set()
        for uri in self._addresses:
            for u in expand_listen_uri(uri, self._local_ips, self._extra_addrs):
                if u not in seen:
                    seen.add(u)
                    out.append(u)
        return out

    async def join(self, address: str, code: str) -> None:
        transport = await self._transport_manager.connect(address)
        peer = _Peer(transport, is_client_side=True)
        peer.on_dead = self._reap_peer
        peer.total = self._metrics.total
        peer.remote_addr = address
        peer.join_code = code
        self._peers.append(peer)
        self._running = True
        await peer.start(self._handle_packet)

    async def stop(self) -> None:
        self._running = False
        self._persist_state()
        for peer in list(self._peers):
            await peer.stop()
        self._peers.clear()
        await self._transport_manager.close_all()

    async def wait_for_session(self, timeout: float = 10.0) -> None:
        deadline = asyncio.get_event_loop().time() + timeout
        while not any(p.session is not None for p in self._peers):
            if asyncio.get_event_loop().time() >= deadline:
                raise TimeoutError("session not established in time")
            await asyncio.sleep(0.05)

    async def send_data(self, target: NodeID, payload: bytes) -> None:
        if target == self._id:
            raise ValueError("cannot send to self")
        if target not in self._e2e_sessions:
            pending = self._e2e_pending_data
            # Cap half-open destinations so an app flooding unreachable targets
            # can't exhaust memory; evict the oldest destination if needed.
            if target not in pending and len(pending) >= _MAX_PENDING_TARGETS:
                del pending[next(iter(pending))]
            queue = pending.setdefault(target, [])
            queue.append(payload)
            if len(queue) > _MAX_PENDING_PER_TARGET:
                del queue[0]  # drop oldest — bounded backlog per target
            if target not in self._e2e_pending_kem:
                await self._initiate_e2e_handshake(target)
            self._persist_state()
            return
        session = self._e2e_sessions[target]
        packet = Packet.create_encrypted(DATA, self._id.raw, target.raw, payload, session)
        await self._route_outbound(packet)

    async def receive_data(self) -> tuple[NodeID, bytes]:
        return await self._data_queue.get()

    async def ping(self, peer: _Peer) -> None:
        payload = _encode_addresses(self.advertised_uris())
        packet = Packet.create(PING, self._id.raw, NodeID(b"\xff" * 20).raw, payload)
        await peer.send(packet)

    async def find_node(self, target: NodeID) -> None:
        qid = os.urandom(_QID_LEN)
        for peer in self._peers:
            packet = Packet.create(FIND_NODE, self._id.raw,
                                   NodeID(b"\xff" * 20).raw, target.raw + qid)
            await peer.send(packet)

    async def initiate_handshake(self, peer: _Peer) -> None:
        kem_pub, kem_secret = self._identity.generate_kem_keypair()
        peer.pending_kem_secret = kem_secret
        dsa_pub   = self._identity.dsa_public_key
        challenge = peer.received_challenge if peer.received_challenge is not None else os.urandom(32)
        chain     = self._cert_store.get_chain_to_root(self._id) or []
        signature = self._identity.sign(challenge + kem_pub + dsa_pub)
        payload   = _encode_handshake(kem_pub, dsa_pub, chain, signature)
        packet    = Packet.create(HANDSHAKE, self._id.raw,
                                  NodeID(b"\xff" * 20).raw, payload)
        await peer.send(packet)

    async def _wait_for_peer_authenticated(self, peer: _Peer,
                                            target: NodeID,
                                            timeout: float) -> bool:
        deadline = asyncio.get_event_loop().time() + timeout
        while True:
            if peer not in self._peers:
                return False
            if peer.authenticated_id == target and peer.session is not None:
                return True
            if asyncio.get_event_loop().time() >= deadline:
                return False
            await asyncio.sleep(_AUTH_POLL_INTERVAL)

    async def _kademlia_lookup(self, target: NodeID, timeout: float) -> bool:
        existing = self._pending_lookups.get(target)
        if existing is not None:
            try:
                await asyncio.wait_for(existing.wait(), timeout=timeout)
            except asyncio.TimeoutError:
                pass
            return self._routing.contains(target)

        event = asyncio.Event()
        self._pending_lookups[target] = event
        try:
            seen_peers: set[bytes] = set()
            deadline = asyncio.get_event_loop().time() + timeout
            for _ in range(_KAD_LOOKUP_MAX_ROUNDS):
                if self._routing.contains(target):
                    return True
                queried = 0
                for p in list(self._peers):
                    if p.authenticated_id is None or p.session is None:
                        continue
                    if p.authenticated_id.raw in seen_peers:
                        continue
                    seen_peers.add(p.authenticated_id.raw)
                    pkt = Packet.create(FIND_NODE, self._id.raw,
                                        NodeID(b"\xff" * 20).raw,
                                        target.raw + os.urandom(_QID_LEN))
                    try:
                        await p.send(pkt)
                        queried += 1
                    except Exception:
                        pass
                if queried == 0:
                    break
                sub_deadline = min(deadline,
                                   asyncio.get_event_loop().time() + _KAD_LOOKUP_TIMEOUT)
                while asyncio.get_event_loop().time() < sub_deadline:
                    if self._routing.contains(target):
                        return True
                    await asyncio.sleep(_AUTH_POLL_INTERVAL)
            return self._routing.contains(target)
        finally:
            event.set()
            self._pending_lookups.pop(target, None)

    async def _ensure_route_to(self, target: NodeID,
                                timeout: float = _ON_DEMAND_TIMEOUT) -> _Peer | None:
        if target == self._id:
            return None
        existing = next(
            (p for p in self._peers
             if p.authenticated_id == target and p.session is not None),
            None,
        )
        if existing is not None:
            return existing
        pending = self._pending_connections.get(target)
        if pending is not None:
            try:
                await asyncio.wait_for(pending.wait(), timeout=timeout)
            except asyncio.TimeoutError:
                return None
            return next(
                (p for p in self._peers
                 if p.authenticated_id == target and p.session is not None),
                None,
            )
        event = asyncio.Event()
        self._pending_connections[target] = event
        try:
            if not self._routing.contains(target):
                await self._kademlia_lookup(
                    target, _KAD_LOOKUP_TIMEOUT * _KAD_LOOKUP_MAX_ROUNDS
                )
                if not self._routing.contains(target):
                    return None
            peer = await self._connect_routing(target)
            if peer is None:
                return None
            ok = await self._wait_for_peer_authenticated(peer, target, timeout)
            if not ok:
                try:
                    await peer.stop()
                except Exception:
                    pass
                if peer in self._peers:
                    self._peers.remove(peer)
                return None
            return peer
        finally:
            event.set()
            self._pending_connections.pop(target, None)

    async def _kad_query_node(self, node_id: NodeID, target: NodeID,
                               timeout: float = 5.0) -> list[NodeEntry]:
        peer = next(
            (p for p in self._peers
             if p.authenticated_id == node_id and p.session is not None),
            None,
        )
        if peer is None:
            peer = await self._ensure_route_to(node_id, timeout)
            if peer is None:
                return []
        query_id = os.urandom(_QID_LEN)
        future: asyncio.Future = asyncio.get_event_loop().create_future()
        self._pending_finds[query_id] = future
        packet = Packet.create(FIND_NODE, self._id.raw,
                               NodeID(b"\xff" * 20).raw,
                               target.raw + query_id)
        try:
            await peer.send(packet)
            return await asyncio.wait_for(asyncio.shield(future), timeout)
        except (asyncio.TimeoutError, Exception):
            return []
        finally:
            self._pending_finds.pop(query_id, None)
            if not future.done():
                future.cancel()

    async def kad_lookup(self, target: NodeID, k: int = 20, alpha: int = 3,
                         max_rounds: int = 10) -> list[NodeID]:
        shortlist: set[NodeID] = {e.node_id for e in self._routing.get_closest(target, k)}
        for p in self._peers:
            if p.authenticated_id is not None and p.session is not None:
                shortlist.add(p.authenticated_id)
        queried: set[NodeID] = set()
        closest_seen: NodeID | None = None
        for _ in range(max_rounds):
            candidates = sorted(
                (nid for nid in shortlist if nid not in queried),
                key=lambda n: target.distance(n),
            )[:alpha]
            if not candidates:
                break
            queried.update(candidates)
            results = await asyncio.gather(
                *[self._kad_query_node(nid, target) for nid in candidates],
                return_exceptions=True,
            )
            for r in results:
                if isinstance(r, list):
                    for entry in r:
                        if entry.node_id != self._id:
                            shortlist.add(entry.node_id)
            sorted_ids = sorted(shortlist, key=lambda n: target.distance(n))[:k]
            shortlist = set(sorted_ids)
            new_closest = sorted_ids[0] if sorted_ids else None
            if new_closest == closest_seen:
                break
            closest_seen = new_closest
        return sorted(shortlist, key=lambda n: target.distance(n))

    async def bootstrap(self) -> None:
        """Kademlia join: advertise own addresses then iteratively populate routing table."""
        if not self._peers:
            return
        for peer in list(self._peers):
            if peer.session is not None and self._addresses:
                await self.ping(peer)
        discovered = await self.kad_lookup(self._id)
        tasks = []
        for nid in discovered:
            if nid == self._id:
                continue
            if any(p.authenticated_id == nid for p in self._peers):
                continue
            tasks.append(asyncio.create_task(self._ensure_route_to(nid)))
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _route_outbound(self, packet: Packet) -> None:
        target = NodeID(packet.dst_id)
        direct = next(
            (p for p in self._peers
             if p.authenticated_id == target and p.session is not None),
            None,
        )
        if direct is not None:
            await direct.send(packet)
            return
        candidates = [p for p in self._peers
                      if p.authenticated_id is not None and p.session is not None]
        if candidates:
            best = min(candidates, key=lambda p: target.distance(p.authenticated_id))
            await best.send(packet)
            return
        peer = await self._ensure_route_to(target)
        if peer is not None:
            await peer.send(packet)

    async def _initiate_e2e_handshake(self, target: NodeID) -> None:
        nonce = os.urandom(32)
        kem_pub, kem_secret = self._identity.generate_kem_keypair()
        dsa_pub = self._identity.dsa_public_key
        cert_chain = self._cert_store.get_chain_to_root(self._id)
        if cert_chain is None:
            return
        signature = self._identity.sign(nonce + kem_pub + dsa_pub)
        payload = _encode_e2e_handshake(nonce, kem_pub, dsa_pub, cert_chain, signature)
        self._e2e_pending_kem[target] = kem_secret
        self._e2e_pending_nonce[target] = nonce
        self._persist_state()
        packet = Packet.create(E2E_HANDSHAKE, self._id.raw, target.raw, payload)
        await self._route_outbound(packet)

    async def _on_new_transport(self, transport: BaseTransport) -> None:
        if len(self._peers) >= _MAX_PEERS:
            await transport.close()
            return
        peer = _Peer(transport, is_client_side=False)
        peer.on_dead = self._reap_peer
        peer.total = self._metrics.total
        self._peers.append(peer)
        await peer.start(self._handle_packet)
        challenge = self._invite.generate_challenge()
        peer.pending_challenge = challenge
        packet = Packet.create(CHALLENGE, self._id.raw,
                               NodeID(b"\xff" * 20).raw, challenge)
        await peer.send(packet)

    async def _connect_routing(self, node_id: NodeID) -> _Peer | None:
        entry = self._routing.get(node_id)
        if entry is None:
            return None
        for uri in entry.addresses:
            result = _validate_uri(uri)
            if result is None:
                continue
            scheme, _ = result
            if not self._transport_manager.is_supported(scheme):
                continue
            try:
                transport = await self._transport_manager.connect(uri)
            except Exception:
                continue
            peer = _Peer(transport, is_client_side=True)
            peer.on_dead = self._reap_peer
            peer.total = self._metrics.total
            peer.remote_addr = uri
            self._peers.append(peer)
            await peer.start(self._handle_packet)
            return peer
        return None

    async def _inject_peer(self, transport: BaseTransport) -> _Peer:
        """For testing only — injects a fake transport as a client-side peer."""
        peer = _Peer(transport, is_client_side=True)
        peer.on_dead = self._reap_peer
        peer.total = self._metrics.total
        self._peers.append(peer)
        self._running = True
        await peer.start(self._handle_packet)
        return peer

    async def _reap_peer(self, peer: _Peer) -> None:
        """Prune a peer whose link died or which was cut for abuse.

        Called from the peer's own receive task, so it must not cancel that
        task (that is stop()'s job) — it just drops the peer from routing and
        releases the transport. On-demand routing re-establishes any link that
        is needed again, so the mesh self-heals without explicit reconnect.
        """
        try:
            self._peers.remove(peer)
        except ValueError:
            pass
        try:
            await peer.transport.close()
        except Exception:
            pass

    def _persist_state(self) -> None:
        """Snapshot E2E + routing state to the encrypted store, if persistence
        is on. Never raises — a disk problem must not take the node down."""
        if self._session_store is None:
            return
        try:
            self._session_store.save(
                self._e2e_sessions, self._e2e_pending_kem,
                self._e2e_pending_nonce, self._e2e_pending_data,
                self._routing.export_entries(),
            )
        except Exception:
            pass

    # -- console / management surface -------------------------------------
    # These read or mutate node state and are meant to be driven from the web
    # console. Async ones run on the event loop; the console marshals into it.

    async def console_snapshot(self) -> dict:
        """A JSON-serialisable view of the node. Built on the event loop, so it
        reads live state atomically (no awaits mid-iteration)."""
        peers = []
        for p in self._peers:
            peers.append({
                "authenticated_id": p.authenticated_id.raw.hex() if p.authenticated_id else None,
                "is_client_side": p.is_client_side,
                "has_session": p.session is not None,
                "malformed": p._malformed,
                "counters": p.counters.as_dict(),
            })
        routing = [
            {"id": e.node_id.raw.hex(), "addresses": list(e.addresses)}
            for e in self._routing.all_entries()
        ]
        return {
            "id": self._id.raw.hex(),
            "addresses": list(self._addresses),
            "listen": list(self._addresses),
            "advertised": self.advertised_uris(),
            "local_ips": list(self._local_ips),
            "transports": self._transport_manager.schemes(),
            "listening": self._transport_manager.listening_uris(),
            "running": self._running,
            "uptime": self._metrics.uptime(),
            "peer_count": len(self._peers),
            "authenticated_peers": sum(
                1 for p in self._peers if p.authenticated_id and p.session
            ),
            "peers": peers,
            "routing": routing,
            "routing_size": len(routing),
            "e2e_sessions": [nid.raw.hex() for nid in self._e2e_sessions],
            "total": self._metrics.total.as_dict(),
            "load": self._metrics.load(),
        }

    def console_root_cert_hex(self) -> str:
        """Our self-signed root cert, hex-encoded — paste it into another node's
        console to have that node trust ours."""
        return self._identity.self_signed_cert().serialize().hex()

    def console_add_root(self, cert_hex: str) -> bool:
        """Trust another node's self-signed root cert (hex). Returns success."""
        try:
            cert = Certificate.deserialize(bytes.fromhex(cert_hex))
        except Exception:
            return False
        if not cert.is_self_signed:
            return False
        self._cert_add(cert)
        self._cert_store.add_root(cert.subject_id)
        return True

    def _cert_add(self, cert: Certificate) -> bool:
        ok = self._cert_store.add(cert)
        if ok and self._cert_store_path:
            self._cert_store.save(self._cert_store_path)
        return ok

    def _is_seen(self, msg_id: int) -> bool:
        if msg_id in self._seen_msgs:
            return True
        if len(self._seen_msgs) >= _MSG_DEDUP_MAX:
            self._seen_msgs.popitem(last=False)
        self._seen_msgs[msg_id] = time.monotonic()
        return False

    async def _forward_packet(self, from_peer: _Peer, packet: Packet) -> None:
        if packet.ttl <= 1:
            return
        target = NodeID(packet.dst_id)
        # Direct peer is always preferred
        direct = next(
            (p for p in self._peers
             if p is not from_peer
             and p.authenticated_id == target
             and p.session is not None),
            None,
        )
        if direct is not None:
            await direct.send(packet.with_decremented_ttl())
            return
        # Routing table entry → on-demand is more reliable than random XOR hop,
        # especially across network boundaries where only certain nodes have reachability.
        if self._routing.contains(target):
            peer = await self._ensure_route_to(target)
            if peer is not None and peer is not from_peer:
                await peer.send(packet.with_decremented_ttl())
                return
        candidates = [
            p for p in self._peers
            if p is not from_peer
            and p.authenticated_id is not None
            and p.session is not None
        ]
        if candidates:
            best = min(candidates, key=lambda p: target.distance(p.authenticated_id))
            await best.send(packet.with_decremented_ttl())
            return
        # Last resort: Kademlia lookup + on-demand
        peer = await self._ensure_route_to(target)
        if peer is not None and peer is not from_peer:
            await peer.send(packet.with_decremented_ttl())

    async def _handle_packet(self, peer: _Peer, packet: Packet) -> None:
        if packet.type in _DIRECT_TYPES:
            if peer.authenticated_id is None:
                return
            if packet.src_id != peer.authenticated_id.raw:
                return
        if packet.type in _ROUTABLE_TYPES:
            if peer.authenticated_id is None:
                return
            # msg_id must commit to the packet's content. This stops a relay from
            # minting fresh msg_ids for the same payload to slip past dedup and
            # amplify a flood — any tampering to change the id also breaks it.
            if packet.msg_id != packet.compute_msg_id():
                return
            if self._is_seen(packet.msg_id):
                return
            if packet.dst_id != self._id.raw and packet.dst_id != _BROADCAST_ID:
                await self._forward_packet(peer, packet)
                return
        handlers = {
            DATA:              self._handle_data,
            PING:              self._handle_ping,
            PONG:              self._handle_pong,
            FIND_NODE:         self._handle_find_node,
            FOUND_NODE:        self._handle_found_node,
            FIND_VALUE:        self._handle_find_value,
            FOUND_VALUE:       self._handle_found_value,
            STORE:             self._handle_store,
            HANDSHAKE:         self._handle_handshake,
            HANDSHAKE_ACK:     self._handle_handshake_ack,
            CHALLENGE:         self._handle_challenge,
            INVITE:            self._handle_invite,
            INVITE_ACK:        self._handle_invite_ack,
            E2E_HANDSHAKE:     self._handle_e2e_handshake,
            E2E_HANDSHAKE_ACK: self._handle_e2e_handshake_ack,
        }
        handler = handlers.get(packet.type)
        if handler:
            await handler(peer, packet)

    async def _handle_data(self, peer: _Peer, packet: Packet) -> None:
        src = NodeID(packet.src_id)
        session = self._e2e_sessions.get(src)
        if session is None:
            return
        try:
            plaintext = packet.decrypt_payload(session)
        except Exception:
            return
        await self._data_queue.put((src, plaintext))

    async def _handle_ping(self, peer: _Peer, packet: Packet) -> None:
        if not packet.payload:
            return
        src = NodeID(packet.src_id)
        if peer.authenticated_id != src:
            return
        try:
            raw_addrs = _decode_addresses(packet.payload)
        except (ValueError, UnicodeDecodeError):
            return
        valid_uris = [a for a in raw_addrs if _validate_uri(a) is not None]
        if not valid_uris:
            return
        self._routing.add(src, valid_uris, peer.dsa_pub)
        pong = Packet.create(PONG, self._id.raw, packet.src_id, b"")
        await peer.send(pong)

    async def _handle_pong(self, peer: _Peer, packet: Packet) -> None:
        pass

    async def _handle_find_node(self, peer: _Peer, packet: Packet) -> None:
        if len(packet.payload) != 20 + _QID_LEN:
            return
        target = NodeID(packet.payload[:20])
        query_id = packet.payload[20:]
        closest: list[NodeEntry] = []
        for e in self._routing.get_closest(target):
            if not e.dsa_pub:
                continue
            chain = self._cert_store.get_chain_to_root(e.node_id) or []
            closest.append(NodeEntry(e.node_id, e.addresses, e.dsa_pub, chain))
        response = Packet.create(FOUND_NODE, self._id.raw, packet.src_id,
                                 query_id + _encode_entries(closest))
        await peer.send(response)

    async def _handle_found_node(self, peer: _Peer, packet: Packet) -> None:
        if len(packet.payload) < _QID_LEN:
            return
        query_id = packet.payload[:_QID_LEN]
        try:
            entries = _decode_entries(packet.payload[_QID_LEN:])
        except Exception:
            entries = []
        valid_entries: list[NodeEntry] = []
        for entry in entries:
            if not entry.cert_chain:
                continue
            anchor = self._cert_store.verify_chain(entry.cert_chain)
            if anchor is None:
                continue
            first = entry.cert_chain[0]
            if first.subject_id != entry.node_id:
                continue
            dsa_pub = first.subject_pub
            for cert in entry.cert_chain:
                self._cert_add(cert)
            self._routing.add(entry.node_id, entry.addresses, dsa_pub)
            valid_entries.append(entry)
        future = self._pending_finds.pop(query_id, None)
        if future is not None and not future.done():
            future.set_result(valid_entries)

    # -- DHT (content-addressed value store) ------------------------------

    async def _handle_store(self, peer: _Peer, packet: Packet) -> None:
        # payload: key(20) || value ; stored only if key == hash(value)
        if len(packet.payload) < 20:
            return
        key = packet.payload[:20]
        value = packet.payload[20:]
        self._dht_store.put(key, value)  # put() rejects non-content-addressed data

    async def _handle_find_value(self, peer: _Peer, packet: Packet) -> None:
        # payload: key(20) || query_id(8) ; reply carries the value or empty
        if len(packet.payload) != 20 + _QID_LEN:
            return
        key = packet.payload[:20]
        query_id = packet.payload[20:]
        value = self._dht_store.get(key) or b""
        reply = Packet.create(FOUND_VALUE, self._id.raw, packet.src_id,
                              query_id + value)
        await peer.send(reply)

    async def _handle_found_value(self, peer: _Peer, packet: Packet) -> None:
        if len(packet.payload) < _QID_LEN:
            return
        query_id = packet.payload[:_QID_LEN]
        value = packet.payload[_QID_LEN:]
        future = self._pending_values.pop(query_id, None)
        if future is not None and not future.done():
            future.set_result(value if value else None)

    async def _dht_store_at(self, node_id: NodeID, key: bytes, value: bytes) -> None:
        peer = await self._ensure_route_to(node_id, _DHT_QUERY_TIMEOUT)
        if peer is None:
            return
        try:
            await peer.send(Packet.create(STORE, self._id.raw,
                                          NodeID(b"\xff" * 20).raw, key + value))
        except Exception:
            pass

    async def _dht_find_value_at(self, node_id: NodeID, key: bytes) -> bytes | None:
        peer = await self._ensure_route_to(node_id, _DHT_QUERY_TIMEOUT)
        if peer is None:
            return None
        query_id = os.urandom(_QID_LEN)
        future: asyncio.Future = asyncio.get_event_loop().create_future()
        self._pending_values[query_id] = future
        try:
            await peer.send(Packet.create(FIND_VALUE, self._id.raw,
                                          NodeID(b"\xff" * 20).raw, key + query_id))
            return await asyncio.wait_for(asyncio.shield(future), _DHT_QUERY_TIMEOUT)
        except Exception:
            return None
        finally:
            self._pending_values.pop(query_id, None)
            if not future.done():
                future.cancel()

    async def dht_put(self, value: bytes) -> bytes:
        """Store a value in the DHT, addressed by its own hash. Returns the key."""
        key = _content_key(value)
        self._dht_store.put(key, value)  # keep a local copy (and re-share)
        targets = await self.kad_lookup(NodeID(key))
        await asyncio.gather(
            *(self._dht_store_at(nid, key, value)
              for nid in targets[:_DHT_K] if nid != self._id),
            return_exceptions=True,
        )
        return key

    async def dht_get(self, key: bytes) -> bytes | None:
        """Fetch a value by key, verifying it hashes to the key. Caches locally."""
        local = self._dht_store.get(key)
        if local is not None:
            return local
        for nid in (await self.kad_lookup(NodeID(key)))[:_DHT_K]:
            if nid == self._id:
                continue
            value = await self._dht_find_value_at(nid, key)
            if value is not None and _content_key(value) == key:
                self._dht_store.put(key, value)  # cache → this node now re-shares it
                return value
        return None

    # -- application packages ---------------------------------------------

    async def publish_app(self, name: str, version: str,
                          files: dict[str, bytes]) -> bytes:
        """Publish an app on the DHT. Returns the app id (= hash of the root).

        Content chunks, the manifest (itself chunked), and a small root that
        lists the manifest chunks are all stored content-addressed — so an app
        can have arbitrarily many files."""
        _, manifest, chunks = _app_build(name, version, files)
        from .dht import MAX_VALUE
        for value in chunks.values():
            await self.dht_put(value)
        root_bytes, manifest_chunks = _app_pack_root(manifest)
        if len(root_bytes) > MAX_VALUE:
            raise AppPackageError("app has too many files even after chunking")
        for value in manifest_chunks.values():
            await self.dht_put(value)
        return await self.dht_put(root_bytes)

    async def fetch_app(self, app_id: bytes) -> tuple[dict, dict[str, bytes]] | None:
        """Fetch and verify an app by id. Returns (manifest, files) or None."""
        root_bytes = await self.dht_get(app_id)
        if root_bytes is None:
            return None
        root = _app_parse_root(root_bytes)
        mchunks: dict[bytes, bytes] = {}
        for h in root["chunks"]:
            value = await self.dht_get(bytes.fromhex(h))
            if value is not None:
                mchunks[bytes.fromhex(h)] = value
        manifest_bytes = _app_reassemble_bytes(
            root["size"], root["sha256"], root["chunks"], mchunks.get)
        manifest = _app_parse_manifest(manifest_bytes)
        fetched: dict[bytes, bytes] = {}
        for ck in _app_chunk_keys(manifest):
            value = await self.dht_get(ck)
            if value is not None:
                fetched[ck] = value
        files = _app_reassemble(manifest, fetched.get)  # verifies every hash
        return manifest, files

    async def _handle_challenge(self, peer: _Peer, packet: Packet) -> None:
        if len(packet.payload) != 32:
            return
        peer.received_challenge = packet.payload
        if not peer.is_client_side:
            return  # Unsolicited challenge — ignore
        if peer.join_code is None:
            # Reconnecting routing peer — present our chain directly
            await self.initiate_handshake(peer)
            return
        response    = compute_response(peer.join_code, packet.payload)
        invite_pkt  = Packet.create(INVITE, self._id.raw, packet.src_id, response)
        peer.invite_sent = True
        await peer.send(invite_pkt)

    async def _handle_invite(self, peer: _Peer, packet: Packet) -> None:
        if peer.pending_challenge is None:
            return
        if peer._invite_failures >= 3 and time.monotonic() - peer._invite_lockout_ts < 60:
            return
        if not self._invite.verify_response(peer.pending_challenge, packet.payload):
            peer._invite_failures += 1
            if peer._invite_failures >= 3:
                peer._invite_lockout_ts = time.monotonic()
            ack = Packet.create(INVITE_ACK, self._id.raw, packet.src_id,
                                bytes([_ACK_REJECTED]))
            await peer.send(ack)
            return
        self._invite.consume(peer.pending_challenge, packet.payload)
        peer.invite_accepted = True
        ack = Packet.create(INVITE_ACK, self._id.raw, packet.src_id,
                            bytes([_ACK_ACCEPTED]))
        await peer.send(ack)

    async def _handle_invite_ack(self, peer: _Peer, packet: Packet) -> None:
        if len(packet.payload) < 1:
            return
        if not peer.invite_sent:
            return
        peer.invite_sent = False
        if packet.payload[0] == _ACK_ACCEPTED:
            peer.join_code = None
            await self.initiate_handshake(peer)

    async def _handle_e2e_handshake(self, peer: _Peer, packet: Packet) -> None:
        try:
            nonce, kem_pub, dsa_pub, cert_chain, signature = _decode_e2e_handshake(packet.payload)
        except Exception:
            return
        src = NodeID(packet.src_id)
        if NodeID.from_public_key(dsa_pub) != src:
            return
        if self._cert_store.verify_chain(cert_chain) is None:
            return
        if not self._identity.verify(nonce + kem_pub + dsa_pub, signature, dsa_pub):
            return
        # Simultaneous-open (glare) resolution: if we also have a handshake
        # in flight to this peer, only one may win or the two ends settle on
        # different keys and deadlock. The lower NodeID is the canonical
        # initiator; if that's us, ignore their handshake and let ours win.
        if src in self._e2e_pending_nonce and self._id.raw < src.raw:
            return
        self._e2e_pending_nonce.pop(src, None)
        self._e2e_pending_kem.pop(src, None)
        my_cert_chain = self._cert_store.get_chain_to_root(self._id)
        if my_cert_chain is None:
            return
        ciphertext, shared_secret = self._identity.kem_encapsulate(kem_pub)
        self._e2e_sessions[src] = SessionKey(shared_secret)
        ack_sig = self._identity.sign(nonce + ciphertext + self._identity.dsa_public_key)
        ack_payload = _encode_e2e_handshake_ack(
            nonce, ciphertext, self._identity.dsa_public_key, my_cert_chain, ack_sig
        )
        ack = Packet.create(E2E_HANDSHAKE_ACK, self._id.raw, packet.src_id, ack_payload)
        await self._route_outbound(ack)
        # We became the responder — flush anything we had queued for this peer,
        # otherwise data sent before the session existed is stranded forever.
        for payload in self._e2e_pending_data.pop(src, []):
            pkt = Packet.create_encrypted(DATA, self._id.raw, src.raw, payload,
                                          self._e2e_sessions[src])
            await self._route_outbound(pkt)
        self._persist_state()

    async def _handle_e2e_handshake_ack(self, peer: _Peer, packet: Packet) -> None:
        try:
            nonce, ciphertext, dsa_pub, cert_chain, signature = _decode_e2e_handshake_ack(packet.payload)
        except Exception:
            return
        src = NodeID(packet.src_id)
        expected_nonce = self._e2e_pending_nonce.get(src)
        if expected_nonce is None or nonce != expected_nonce:
            return
        if NodeID.from_public_key(dsa_pub) != src:
            return
        if self._cert_store.verify_chain(cert_chain) is None:
            return
        if not self._identity.verify(nonce + ciphertext + dsa_pub, signature, dsa_pub):
            return
        kem_secret = self._e2e_pending_kem.pop(src, None)
        if kem_secret is None:
            return
        self._e2e_pending_nonce.pop(src, None)
        shared_secret = self._identity.kem_decapsulate(ciphertext, kem_secret)
        self._e2e_sessions[src] = SessionKey(shared_secret)
        pending = self._e2e_pending_data.pop(src, [])
        for payload in pending:
            pkt = Packet.create_encrypted(DATA, self._id.raw, src.raw, payload,
                                          self._e2e_sessions[src])
            await self._route_outbound(pkt)
        self._persist_state()

    async def _handle_handshake(self, peer: _Peer, packet: Packet) -> None:
        if peer.authenticated_id is not None:
            return
        if peer.pending_challenge is None:
            return
        try:
            kem_pub, bob_dsa_pub, chain, signature = _decode_handshake(packet.payload)
        except Exception:
            return
        if not self._identity.verify(peer.pending_challenge + kem_pub + bob_dsa_pub,
                                     signature, bob_dsa_pub):
            return
        claimed_id = NodeID.from_public_key(bob_dsa_pub)
        if claimed_id != NodeID(packet.src_id):
            return

        issued_cert: Certificate | None = None
        if peer.invite_accepted:
            issued_cert = self._identity.issue_cert(claimed_id, bob_dsa_pub)
            self._cert_add(issued_cert)
        else:
            if not chain:
                return
            anchor = self._cert_store.verify_chain(chain)
            if anchor is None:
                return
            for cert in chain:
                self._cert_add(cert)

        peer.authenticated_id = claimed_id
        peer.dsa_pub = bob_dsa_pub
        self._routing.add(claimed_id, [], bob_dsa_pub)
        ciphertext, shared_secret = self._identity.kem_encapsulate(kem_pub)
        peer.session = SessionKey(shared_secret)
        dsa_pub      = self._identity.dsa_public_key
        server_chain = self._cert_store.get_chain_to_root(self._id) or []
        signature    = self._identity.sign(peer.pending_challenge + ciphertext + dsa_pub)
        payload      = _encode_handshake_ack(ciphertext, dsa_pub, server_chain,
                                             issued_cert, signature)
        peer.pending_challenge = None
        ack = Packet.create(HANDSHAKE_ACK, self._id.raw, packet.src_id, payload)
        await peer.send(ack)
        self._persist_state()  # persist the newly-known peer for restart recovery

    async def _handle_handshake_ack(self, peer: _Peer, packet: Packet) -> None:
        if peer.pending_kem_secret is None:
            return
        if peer.received_challenge is None:
            return
        try:
            ciphertext, alice_dsa_pub, server_chain, issued_cert, signature = (
                _decode_handshake_ack(packet.payload)
            )
        except Exception:
            return
        if not self._identity.verify(peer.received_challenge + ciphertext + alice_dsa_pub,
                                     signature, alice_dsa_pub):
            return
        if NodeID.from_public_key(alice_dsa_pub) != NodeID(packet.src_id):
            return
        server_id = NodeID(packet.src_id)

        if issued_cert is not None:
            if issued_cert.issuer_id != server_id:
                return
            if issued_cert.subject_id != self._id:
                return
            for cert in server_chain:
                self._cert_add(cert)
            if server_chain:
                last = server_chain[-1]
                if last.is_self_signed:
                    self._cert_store.add_root(last.subject_id)
            self._cert_add(issued_cert)
        else:
            if not server_chain:
                return
            anchor = self._cert_store.verify_chain(server_chain)
            if anchor is None:
                return
            for cert in server_chain:
                self._cert_add(cert)

        peer.authenticated_id = server_id
        peer.dsa_pub = alice_dsa_pub
        # Record the address we dialled so this peer is reconnectable after a
        # restart (validated before advertising it to anyone else).
        addrs = ([peer.remote_addr]
                 if peer.remote_addr and _validate_uri(peer.remote_addr) else [])
        self._routing.add(server_id, addrs, alice_dsa_pub)
        shared_secret         = self._identity.kem_decapsulate(ciphertext,
                                                                peer.pending_kem_secret)
        peer.session          = SessionKey(shared_secret)
        peer.pending_kem_secret = None
        self._persist_state()  # persist the newly-known peer for restart recovery
