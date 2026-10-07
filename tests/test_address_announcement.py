"""
What a bounded announcement of our addresses keeps.

A PING carries eight addresses and a join block sixteen. A host with container
bridges expands each wildcard listener into one URI per interface, TCP's all
before UDP's, so cutting by position kept TCP only: a node listening on both
never announced a UDP address, and its join blocks gave the host nothing to
punch towards (seen live: 32 advertised, the eight on the wire all TCP).
"""
import base64
import json

from src.ip_utils import announcement_order
from src.mesh.codecs import _decode_addresses_at
from src.node import MeshNode, PING, _decode_conn_block
from tests.conftest import make_manager, make_node

LOCAL = ["10.8.0.2", "fd00:db8::1", "10.1.2.3", "100.64.0.1"] + [
    f"172.{n}.0.1" for n in range(17, 29)]


def _crowded(node: MeshNode) -> MeshNode:
    node._addresses = ["tcp://0.0.0.0:9000", "udp://0.0.0.0:9001"]
    node._local_ips = list(LOCAL)
    return node


class TestAnnouncementOrder:

    def test_every_medium_gets_a_share(self):
        uris = [f"tcp://10.0.0.{n}:1" for n in range(10)] + [
            f"udp://10.0.0.{n}:2" for n in range(10)]
        out = announcement_order(uris, 8)
        assert [u.split(":")[0] for u in out] == ["tcp", "udp"] * 4

    def test_the_host_order_is_kept_within_a_medium(self):
        uris = [f"tcp://10.0.0.{n}:1" for n in range(5)]
        assert announcement_order(uris, 3) == uris[:3]

    def test_a_public_address_goes_first(self):
        uris = ["tcp://10.0.0.1:1", "tcp://172.17.0.1:1", "tcp://93.184.216.33:1"]
        assert announcement_order(uris, 2)[0] == "tcp://93.184.216.33:1"

    def test_a_name_counts_as_public(self):
        uris = ["tcp://10.0.0.1:1", "tcp://node.example.org:1"]
        assert announcement_order(uris, 1) == ["tcp://node.example.org:1"]

    def test_a_medium_with_few_addresses_leaves_its_slots_to_others(self):
        uris = ["udp://10.0.0.1:2"] + [f"tcp://10.0.0.{n}:1" for n in range(10)]
        out = announcement_order(uris, 8)
        assert len(out) == 8 and out.count("udp://10.0.0.1:2") == 1

    def test_never_more_than_the_limit_nor_an_invalid_uri(self):
        assert announcement_order(["nonsense", "tcp://10.0.0.1:1"], 8) == [
            "tcp://10.0.0.1:1"]
        assert announcement_order([f"tcp://10.0.0.{n}:1" for n in range(20)],
                                  8) == [f"tcp://10.0.0.{n}:1" for n in range(8)]


class TestWhatLeavesTheNode:

    async def test_a_ping_announces_udp_too(self):
        node, fake = await make_node()
        _crowded(node)
        await node.ping(node._peers[0])
        ping = [p for p in fake.sent if p.type == PING][-1]
        addresses, _end = _decode_addresses_at(ping.payload)
        await node.stop()
        assert len(addresses) == 8
        assert "udp://10.8.0.2:9001" in addresses
        assert "tcp://10.8.0.2:9000" in addresses
        assert not any(a.startswith("tcp://172.") for a in addresses)

    def test_a_join_block_lists_udp_endpoints(self):
        node = _crowded(MeshNode(transport_manager=make_manager()))
        uris = _decode_conn_block(node.console_connect_request(), "req")["uris"]
        assert any(u.startswith("udp://") for u in uris)
        invite = json.loads(base64.b64decode(node.console_invite_block()))
        assert any(u.startswith("udp://") for u in invite["uris"])

    def test_the_console_still_shows_everything(self):
        node = _crowded(MeshNode(transport_manager=make_manager()))
        assert len(node.advertised_uris()) == 2 * len(LOCAL)
