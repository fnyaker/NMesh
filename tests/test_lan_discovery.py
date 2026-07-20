"""
LAN relay discovery (étape 4).

When no relay is configured but a mesh member sits on the same broadcast
domain, a joiner finds it by broadcasting a beacon; the member answers with
the address(es) it can be reached at, which feed the ordinary relay path.
These cover the answer codec (hostile input), the request→answer round trip
(exercised on loopback via a unicast target — same protocol as broadcast),
the per-source rate limit, and the node-level integration.
"""
import asyncio

import pytest

from src.lan_discovery import (
    LanDiscovery, _encode_answer, _decode_answer, _REQ, _ANS,
    _MAX_ADDRS, _RATE_MAX, DISCOVERY_PORT,
)
from src.node import MeshNode
from src.transport_manager import TransportManager
from src.udp_transport import UDPTransport, UDPServer
from src.tcp_transport import TCPTransport, TCPServer
from tests.conftest import make_manager


def _ip_mgr() -> TransportManager:
    m = TransportManager()
    m.register("tcp", TCPTransport, TCPServer)
    m.register("udp", UDPTransport, UDPServer)
    return m


class TestAnswerCodec:
    def test_roundtrip(self):
        nid = b"\x01" * 20
        out = _encode_answer(nid, ["tcp://1.2.3.4:9000", "udp://1.2.3.4:9001"])
        parsed = _decode_answer(out)
        assert parsed == (nid, ["tcp://1.2.3.4:9000", "udp://1.2.3.4:9001"])

    def test_caps_address_count(self):
        out = _encode_answer(b"\x01" * 20, [f"tcp://h:{i}" for i in range(50)])
        nid, addrs = _decode_answer(out)
        assert len(addrs) <= _MAX_ADDRS

    def test_rejects_garbage(self):
        assert _decode_answer(b"") is None
        assert _decode_answer(b"XXXX" + b"\x00" * 20) is None       # wrong magic
        assert _decode_answer(_ANS + b"\x00" * 5) is None            # too short
        assert _decode_answer(_ANS + b"\x00" * 20 + b"not-json") is None
        assert _decode_answer(_ANS + b"\x00" * 20 + b"9000") is None  # not a list


class TestRoundTrip:
    async def test_discover_finds_answerer(self):
        # answerer advertises two relay addresses
        answerer = LanDiscovery(b"\xaa" * 20,
                                lambda: ["tcp://127.0.0.1:9000", "udp://127.0.0.1:9001"])
        await answerer.start()
        try:
            joiner = LanDiscovery(b"\xbb" * 20, lambda: [])
            found = await joiner.discover(timeout=1.0, targets=("127.0.0.1",))
            assert "tcp://127.0.0.1:9000" in found
            assert "udp://127.0.0.1:9001" in found
        finally:
            await answerer.stop()

    async def test_answerer_silent_when_no_relays(self):
        answerer = LanDiscovery(b"\xaa" * 20, lambda: [])   # nothing to offer
        await answerer.start()
        try:
            joiner = LanDiscovery(b"\xbb" * 20, lambda: [])
            found = await joiner.discover(timeout=0.6, targets=("127.0.0.1",))
            assert found == []
        finally:
            await answerer.stop()

    async def test_ignores_own_answer(self):
        same = b"\xcc" * 20
        answerer = LanDiscovery(same, lambda: ["tcp://127.0.0.1:9000"])
        await answerer.start()
        try:
            joiner = LanDiscovery(same, lambda: [])   # same node id
            found = await joiner.discover(timeout=0.6, targets=("127.0.0.1",))
            assert found == []   # our own answer is dropped
        finally:
            await answerer.stop()

    async def test_rate_limited_per_source(self):
        calls = {"n": 0}
        def relays():
            calls["n"] += 1
            return ["tcp://127.0.0.1:9000"]
        answerer = LanDiscovery(b"\xaa" * 20, relays)
        await answerer.start()
        try:
            # hammer the answerer from one source
            for _ in range(_RATE_MAX + 10):
                answerer._on_request(_REQ + b"\xbb" * 20, ("127.0.0.1", 5000))
            assert calls["n"] <= _RATE_MAX
        finally:
            await answerer.stop()


class TestNodeIntegration:
    async def test_answerer_offers_reachable_addresses(self):
        node = MeshNode(transport_manager=_ip_mgr())
        await node.start(["tcp://127.0.0.1:0"])
        node._local_ips = ["192.168.1.5"]
        node._extra_addrs = ["1.1.1.1"]
        try:
            addrs = node._lan_relay_addrs()
            assert any("1.1.1.1" in a for a in addrs)   # our reachable world addr
        finally:
            await node.stop()

    async def test_discover_lan_relays_filters_unsupported(self):
        # a node whose manager only knows "fake" ignores tcp/udp answers
        node = MeshNode(transport_manager=make_manager())
        answerer = LanDiscovery(b"\xaa" * 20, lambda: ["tcp://127.0.0.1:9000"])
        await answerer.start()
        try:
            found = await node.discover_lan_relays(timeout=0.8, targets=("127.0.0.1",))
            assert found == []   # tcp not supported by this node
        finally:
            await answerer.stop()

    async def test_relay_join_uses_discovered_relay(self):
        # block with NO relays → joiner discovers R on the LAN and joins through it
        base_mgr = _ip_mgr
        R, A, B = MeshNode(base_mgr()), MeshNode(base_mgr()), MeshNode(base_mgr())
        import random, base64, json
        port = random.randint(20000, 40000)
        await R.start([f"tcp://127.0.0.1:{port}"])
        await A.join(f"tcp://127.0.0.1:{port}", R.generate_invite())
        await asyncio.wait_for(A.wait_for_session(10), 15)
        R._lan_relay_addrs = lambda: [f"tcp://127.0.0.1:{port}"]
        await R.start_lan_discovery()
        await B.start_udp(0, "127.0.0.1")   # gives B a broadcast-capable transport
        # force B's discovery to loopback-unicast the beacon
        orig = B.discover_lan_relays
        B.discover_lan_relays = lambda timeout=1.5, targets=None: orig(
            timeout=1.0, targets=("127.0.0.1",))
        try:
            block = A.console_relay_invite()
            d = json.loads(base64.b64decode(block)); d["relays"] = []
            no_relays = base64.b64encode(json.dumps(d).encode()).decode()
            B.console_relay_join(no_relays)
            async with asyncio.timeout(25):
                while B._join_status["running"]:
                    await asyncio.sleep(0.05)
            assert B._join_status["connected"] == f"tcp://127.0.0.1:{port}"
            assert any(p.authenticated_id == A.id and p.session for p in B._peers)
        finally:
            await A.stop(); await B.stop(); await R.stop()
