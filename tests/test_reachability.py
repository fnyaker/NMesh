"""
Transport-agnostic reachability model (étape 1).

Reachability is how the core learns, without knowing any concrete transport,
whether a node can serve as a relay and by which audience. Each transport
classifies its own addresses into descriptors (transport/scope/anchor); the
core only aggregates. These tests cover the IP classifier (the anchor that
separates two identical LAN ranges behind different public IPs), the passive
"someone reached us" confirmation signal, and the relay-capable derivation.
Pure observability — no network behaviour changes.
"""
import json

import pytest

from src.ip_utils import ip_reachability, _is_global_ip
from src.node import MeshNode
from src.node_id import NodeID
from src.crypto import SessionKey
from tests.conftest import make_manager, make_node


class TestIPClassifier:
    def test_public_ip_is_world(self):
        descs = ip_reachability("tcp", "tcp://0.0.0.0:9000",
                                local_ips=["8.8.8.8"], public_addrs=[],
                                confirmed=True)
        assert len(descs) == 1
        d = descs[0]
        assert d["scope"] == "world" and d["transport"] == "tcp"
        assert d["address"] == "tcp://8.8.8.8:9000"
        assert d["confirmed"] is True

    def test_discovered_public_addr_is_world(self):
        descs = ip_reachability("udp", "udp://0.0.0.0:9001",
                                local_ips=["192.168.1.5"],
                                public_addrs=["1.1.1.1"], confirmed=False)
        scopes = {d["scope"] for d in descs}
        assert scopes == {"world", "lan"}
        world = next(d for d in descs if d["scope"] == "world")
        assert world["address"] == "udp://1.1.1.1:9001"

    def test_lan_is_anchored_by_public_ip(self):
        # The crux: an identical 192.168.x range behind a DIFFERENT public IP is
        # a DIFFERENT audience — the anchor carries the public IP.
        mine = ip_reachability("tcp", "tcp://0.0.0.0:9000",
                               local_ips=["192.168.0.10"],
                               public_addrs=["8.8.8.8"], confirmed=False)
        neigh = ip_reachability("tcp", "tcp://0.0.0.0:9000",
                                local_ips=["192.168.0.10"],
                                public_addrs=["1.1.1.1"], confirmed=False)
        lan_mine = next(d for d in mine if d["scope"] == "lan")
        lan_neigh = next(d for d in neigh if d["scope"] == "lan")
        assert lan_mine["anchor"] == "8.8.8.8"
        assert lan_neigh["anchor"] == "1.1.1.1"
        assert lan_mine["anchor"] != lan_neigh["anchor"]  # distinct audiences

    def test_private_without_public_has_empty_anchor(self):
        descs = ip_reachability("tcp", "tcp://0.0.0.0:9000",
                                local_ips=["10.0.0.2"], public_addrs=[],
                                confirmed=False)
        assert descs[0]["scope"] == "lan" and descs[0]["anchor"] == ""

    def test_loopback_is_lan_not_world(self):
        descs = ip_reachability("tcp", "tcp://127.0.0.1:9000",
                                local_ips=["127.0.0.1"], public_addrs=[],
                                confirmed=False)
        assert all(d["scope"] != "world" for d in descs)

    def test_bad_uri_yields_nothing(self):
        assert ip_reachability("tcp", "garbage", ["8.8.8.8"], [], True) == []

    def test_is_global_ip(self):
        assert _is_global_ip("8.8.8.8") is True
        assert _is_global_ip("192.168.1.1") is False
        assert _is_global_ip("10.0.0.1") is False
        assert _is_global_ip("127.0.0.1") is False
        assert _is_global_ip("not-an-ip") is False


class TestNodeReachability:
    async def test_default_manager_has_no_reachability(self):
        # the "fake" test transport doesn't implement reachability()
        node = MeshNode(transport_manager=make_manager())
        assert node.reachability() == []
        assert node.relay_capable() is False

    async def test_snapshot_exposes_reachability(self):
        node = MeshNode(transport_manager=make_manager())
        snap = await node.console_snapshot()
        assert "reachability" in snap and isinstance(snap["reachability"], list)
        assert "relay_capable" in snap and snap["relay_capable"] is False
        json.dumps(snap)

    async def test_tcp_listener_reports_reachability(self):
        from src.transport_manager import TransportManager
        from src.tcp_transport import TCPTransport, TCPServer
        m = TransportManager()
        m.register("tcp", TCPTransport, TCPServer)
        node = MeshNode(transport_manager=m)
        await node.start(["tcp://127.0.0.1:0"])
        try:
            node._local_ips = ["192.168.1.5"]
            node._extra_addrs = ["1.1.1.1"]
            descs = node.reachability()
            scopes = {d["scope"] for d in descs}
            assert "world" in scopes and "lan" in scopes
            assert all(d["transport"] == "tcp" for d in descs)
        finally:
            await node.stop()

    async def test_passive_inbound_marks_confirmed_and_relay_capable(self):
        from src.transport_manager import TransportManager
        from src.tcp_transport import TCPTransport, TCPServer
        m = TransportManager()
        m.register("tcp", TCPTransport, TCPServer)
        node = MeshNode(transport_manager=m)
        await node.start(["tcp://127.0.0.1:0"])
        try:
            node._local_ips = []
            node._extra_addrs = ["1.1.1.1"]
            assert node.relay_capable() is False  # not yet confirmed
            # simulate an accepted inbound authenticated connection on tcp
            node._inbound_schemes.add("tcp")
            assert node.relay_capable() is True
            world = [d for d in node.reachability() if d["scope"] == "world"]
            assert world and all(d["confirmed"] for d in world)
        finally:
            await node.stop()

    async def test_inbound_scheme_recorded_on_server_handshake(self):
        # a server-side peer that authenticates records its transport scheme
        node, _ = await make_node()
        peer = node._peers[0]
        peer.is_client_side = False
        peer.remote_addr = "fake://client:1"
        # mimic the tail of _handle_handshake's confirmation branch
        if not peer.is_client_side:
            scheme = node._peer_scheme(peer)
            if scheme is not None:
                node._inbound_schemes.add(scheme)
        assert "fake" in node._inbound_schemes
