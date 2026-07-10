"""
Hostile-input fuzzing.

The charter is blunt: a crash is a security bug, and nothing that arrives from
the wire can be trusted. These tests throw random and malformed bytes at every
parsing surface and at a live node, and assert three things:

  1. No crash — parsers only ever raise ordinary Exceptions, never a
     BaseException (MemoryError, RecursionError, a hang).
  2. Rejection — malformed input is dropped, never acted upon.
  3. Liveness — after being flooded with garbage, a node still works and a
     misbehaving peer gets cut.

Determinism: every test seeds `random` so a failure is reproducible.
"""

import asyncio
import os
import random
import struct

import pytest

from src.node import (
    MeshNode,
    _decode_chain,
    _decode_addresses,
    _decode_entries,
    _decode_handshake,
    _decode_handshake_ack,
    _decode_e2e_handshake,
    _decode_e2e_handshake_ack,
    _MAX_MALFORMED,
    DATA, PING, PONG, FIND_NODE, FOUND_NODE,
    HANDSHAKE, HANDSHAKE_ACK, CHALLENGE, INVITE, INVITE_ACK,
    E2E_HANDSHAKE, E2E_HANDSHAKE_ACK,
)
from src.node_id import NodeID
from src.packet import Packet, PacketError
from src.cert import Certificate
from src.crypto import SessionKey
from src.transport import BaseTransport
from tests.conftest import FakeTransport, make_node

# Anything a parser is allowed to throw on garbage. The point is that it throws
# an *ordinary* exception the caller can swallow — never a BaseException.
_OK_EXC = (ValueError, PacketError, struct.error, UnicodeDecodeError,
           IndexError, KeyError, OverflowError)

_ALL_TYPES = [DATA, PING, PONG, FIND_NODE, FOUND_NODE, HANDSHAKE, HANDSHAKE_ACK,
              CHALLENGE, INVITE, INVITE_ACK, E2E_HANDSHAKE, E2E_HANDSHAKE_ACK]


def _random_bytes(rng: random.Random, max_len: int = 4096) -> bytes:
    return bytes(rng.getrandbits(8) for _ in range(rng.randint(0, max_len)))


def _guard(fn, data: bytes) -> None:
    """Call a parser on bytes; fail only on a genuine crash (BaseException) or
    a wildly wrong exception type — never on a clean rejection."""
    try:
        fn(data)
    except _OK_EXC:
        pass
    except Exception as exc:  # unexpected but still recoverable — surface it
        raise AssertionError(f"{fn.__name__} raised unexpected {type(exc).__name__}: {exc}")
    # BaseException (MemoryError, RecursionError, KeyboardInterrupt) propagates
    # and fails the test loudly, which is exactly what we want.


# ---------------------------------------------------------------------------
# Packet.unpack — the very first thing a hostile peer touches
# ---------------------------------------------------------------------------

class TestPacketUnpackFuzz:
    def test_random_bytes_never_crash(self):
        rng = random.Random(0xC0FFEE)
        for _ in range(5000):
            data = _random_bytes(rng, 200)
            try:
                p = Packet.unpack(data)
            except PacketError:
                continue
            # If it decoded, re-packing must round-trip the header exactly.
            assert p.pack()[:79] == data[:79]

    def test_truncated_headers(self):
        full = Packet.create(DATA, os.urandom(20), os.urandom(20), b"payload").pack()
        for n in range(len(full)):
            with pytest.raises(PacketError) if n < 79 else _noraise():
                Packet.unpack(full[:n])

    def test_oversized_payload_rejected(self):
        # A frame carrying more than the payload cap must be refused, not OOM.
        header = Packet.create(DATA, os.urandom(20), os.urandom(20), b"").pack()[:79]
        with pytest.raises(PacketError):
            Packet.unpack(header + b"x" * 60001)


class _noraise:
    def __enter__(self): return self
    def __exit__(self, *a): return False


# ---------------------------------------------------------------------------
# Every codec in the wire protocol
# ---------------------------------------------------------------------------

class TestCodecFuzz:
    CODECS = [
        _decode_chain, _decode_addresses, _decode_entries,
        _decode_handshake, _decode_handshake_ack,
        _decode_e2e_handshake, _decode_e2e_handshake_ack,
    ]

    def test_random_bytes(self):
        rng = random.Random(0xBADC0DE)
        for codec in self.CODECS:
            for _ in range(2000):
                _guard(codec, _random_bytes(rng, 1024))

    def test_length_prefix_lies(self):
        # Structured garbage: valid-looking length prefixes that overrun the
        # buffer. Parsers must bounds-check before slicing, never allocate huge.
        rng = random.Random(0x1234)
        for codec in self.CODECS:
            for _ in range(2000):
                count = rng.randint(0, 255)
                blob = bytes([count])
                for _ in range(rng.randint(0, 8)):
                    blob += struct.pack('!H', rng.randint(0, 0xFFFF))
                    blob += _random_bytes(rng, 64)
                _guard(codec, blob)

    def test_certificate_deserialize(self):
        rng = random.Random(0x5EED)
        for _ in range(3000):
            _guard(Certificate.deserialize, _random_bytes(rng, 512))


# ---------------------------------------------------------------------------
# A live node under a hostile packet stream
# ---------------------------------------------------------------------------

def _auth_peer(node: MeshNode):
    """Promote the node's injected peer to an authenticated, session-bearing
    state so fuzzed packets reach the deep handlers (decrypt, decoders)."""
    peer = node._peers[0]
    peer.authenticated_id = NodeID(os.urandom(20))
    peer.session = SessionKey(os.urandom(32))
    peer.dsa_pub = os.urandom(64)
    return peer


class TestNodeHandlerFuzz:
    async def test_handle_packet_never_raises(self):
        node, _ = await make_node()
        peer = _auth_peer(node)
        rng = random.Random(0xABCDEF)
        src = peer.authenticated_id.raw
        for _ in range(4000):
            ptype = rng.choice(_ALL_TYPES)
            payload = _random_bytes(rng, 512)
            # Keep dst local/broadcast so routable garbage is handled here and
            # doesn't kick off slow on-demand forwarding — the forward path is
            # covered by the routing tests.
            dst = rng.choice([node.id.raw, b"\xff" * 20])
            pkt = Packet.create(ptype, src, dst, payload)
            # Must not raise, whatever the garbage.
            await node._handle_packet(peer, pkt)
        await node.stop()

    async def test_node_alive_after_flood(self):
        # After a burst of garbage a valid PING must still elicit a PONG,
        # proving the node did not wedge.
        node, fake = await make_node()
        peer = _auth_peer(node)
        src = peer.authenticated_id.raw
        rng = random.Random(0x999)
        for _ in range(500):
            pkt = Packet.create(rng.choice(_ALL_TYPES), src,
                                node.id.raw, _random_bytes(rng, 256))
            await node._handle_packet(peer, pkt)
        fake.sent.clear()
        from src.node import _encode_addresses
        ping = Packet.create(PING, src, b"\xff" * 20, _encode_addresses(["tcp://127.0.0.1:1"]))
        await node._handle_packet(peer, ping)
        assert any(p.type == PONG for p in fake.sent)
        await node.stop()

    async def test_tampered_msg_id_dropped(self):
        # A DATA packet whose msg_id doesn't commit to its content is a forged /
        # replay-evasion attempt and must be dropped before dedup.
        node, _ = await make_node()
        peer = _auth_peer(node)
        good = Packet.create(DATA, peer.authenticated_id.raw, os.urandom(20), b"x")
        # Corrupt msg_id while keeping everything else intact.
        forged = Packet(1, DATA, 64, good.src_id, good.dst_id,
                        good.msg_id ^ 0x1, good.nonce,
                        good.pack()[63:79], good.payload)
        seen_before = len(node._seen_msgs)
        await node._handle_packet(peer, forged)
        # Dropped: it must not have been recorded as seen nor forwarded.
        assert len(node._seen_msgs) == seen_before
        await node.stop()


# ---------------------------------------------------------------------------
# Transport-level resilience: a bad frame must not kill the link, and a peer
# that keeps sending garbage must be cut and reaped (node self-heals).
# ---------------------------------------------------------------------------

class ScriptedTransport(BaseTransport):
    """receive() replays a script of ('raise', exc) / ('packet', pkt) steps,
    then blocks as an idle-but-live link until closed."""

    def __init__(self, script):
        super().__init__()
        self._script = list(script)
        self._gate = asyncio.Event()
        self.closed = False

    async def connect(self, address): ...
    async def listen(self, address): ...
    async def send(self, packet): ...

    async def close(self):
        self.closed = True
        self._gate.set()

    async def receive(self):
        if self._script:
            kind, payload = self._script.pop(0)
            if kind == "raise":
                raise payload
            return payload
        await self._gate.wait()
        raise ConnectionError("closed")


async def _wait(predicate, timeout=2.0):
    loop = asyncio.get_event_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        if predicate():
            return True
        await asyncio.sleep(0.01)
    return predicate()


class TestTransportResilience:
    async def test_malformed_frames_do_not_kill_link(self):
        node = MeshNode(transport_manager=_make_manager())
        script = [("raise", PacketError("bad frame")) for _ in range(_MAX_MALFORMED - 1)]
        t = ScriptedTransport(script)
        peer = await node._inject_peer(t)
        assert await _wait(lambda: peer._malformed == _MAX_MALFORMED - 1)
        # Under threshold: still connected, task still running, not reaped.
        assert peer in node._peers
        assert not peer._task.done()
        assert not t.closed
        await node.stop()

    async def test_persistent_garbage_gets_peer_cut(self):
        node = MeshNode(transport_manager=_make_manager())
        script = [("raise", PacketError("bad")) for _ in range(_MAX_MALFORMED + 5)]
        t = ScriptedTransport(script)
        peer = await node._inject_peer(t)
        # Exceeds threshold → peer reaped and transport closed automatically.
        assert await _wait(lambda: peer not in node._peers)
        assert await _wait(lambda: t.closed)
        await node.stop()

    async def test_dead_link_is_reaped(self):
        node = MeshNode(transport_manager=_make_manager())
        t = ScriptedTransport([("raise", ConnectionError("reset"))])
        peer = await node._inject_peer(t)
        assert await _wait(lambda: peer not in node._peers)
        await node.stop()


def _make_manager():
    from src.transport_manager import TransportManager
    from tests.conftest import FakeServer
    m = TransportManager()
    m.register("fake", FakeTransport, FakeServer)
    return m
