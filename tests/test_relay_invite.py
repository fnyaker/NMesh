"""
Relayed invitation — block generation + join validation (step 3).

A single block lets a node bring in a peer with no direct link: it carries a
signed rendezvous token plus relays the joiner can reach the inviter through.
These cover the block's shape, relay selection, and the hostile-input
validation of the join side. The full tunnelled handshake (A↔B via a relay,
no direct link) is exercised end-to-end in tests/integration/test_relay_invite.
"""
import base64
import json
import time

import pytest

from src.node import MeshNode, _h_code, _RELAY_INVITE_TTL
from src.node_id import NodeID
from src.crypto import SessionKey, CryptoIdentity
from tests.conftest import make_manager, make_node, FakeTransport


def _block(**over) -> str:
    inviter = over.pop("_identity", CryptoIdentity())
    pub = inviter.dsa_public_key
    exp = over.pop("exp", int(time.time()) + 300)
    code = over.pop("code", "abc1234567")
    from src.node import _seek_signed_blob
    token = over.pop("token", inviter.sign(_seek_signed_blob(_h_code(code), exp)))
    data = {"v": 3, "kind": "relay-inv", "code": code, "exp": exp,
            "pub": pub.hex(), "token": token.hex(),
            "relays": over.pop("relays", ["fake://relay:1"])}
    data.update(over)
    return base64.b64encode(json.dumps(data).encode()).decode()


class TestBlockGeneration:
    async def test_block_shape(self):
        node = MeshNode(transport_manager=make_manager())
        block = node.console_relay_invite()
        data = json.loads(base64.b64decode(block))
        assert data["v"] == 3 and data["kind"] == "relay-inv"
        assert data["code"] in node._invite._codes
        assert data["exp"] > time.time()
        assert data["pub"] == node._identity.dsa_public_key.hex()
        assert isinstance(data["relays"], list)

    async def test_relay_selection_prefers_dialled_authed_peers(self):
        node, _ = await make_node()   # one injected client-side peer
        p = node._peers[0]
        p.authenticated_id = NodeID(b"\x02" * 20)
        p.session = SessionKey(b"\x00" * 32)
        p.remote_addr = "fake://relay:9000"
        relays = node._select_relays()
        assert relays == ["fake://relay:9000"]

    async def test_relay_selection_skips_unreachable(self):
        node, _ = await make_node()
        p = node._peers[0]
        p.authenticated_id = NodeID(b"\x02" * 20)
        p.session = SessionKey(b"\x00" * 32)
        p.remote_addr = None            # inbound / no dialled address
        assert node._select_relays() == []


class TestWhichRelaysAJoinerIsGiven:
    """The old rule was `remote_addr` off the links *we* dialled, on the
    reasoning "we reached them, so a joiner likely can too". For a peer on our
    own LAN that address is `192.168.x.y`, and the block goes to somebody who
    is not on our LAN — so the joiner worked down a list that could not connect,
    said "no relay found", and the operator went and joined directly against a
    node with a public IP instead."""

    def _peer(self, node, node_id, *, addr=None, advertises=(), client=True):
        from src.node import _Peer
        peer = _Peer(FakeTransport(), is_client_side=client)
        peer.authenticated_id = node_id
        peer.session = SessionKey(b"\x00" * 32)
        peer.remote_addr = addr
        node._peers.append(peer)
        if advertises:
            node._routing.add(node_id, list(advertises))
        return peer

    async def test_a_world_address_comes_before_a_lan_one(self):
        node = MeshNode(transport_manager=make_manager())
        self._peer(node, NodeID(b"\x02" * 20), addr="tcp://192.168.1.7:9000")
        self._peer(node, NodeID(b"\x03" * 20), addr="tcp://81.240.12.33:9000")
        assert node._select_relays()[0] == "tcp://81.240.12.33:9000"

    async def test_a_lan_address_is_still_offered_last(self):
        """A joiner on that LAN can use it, and an ordered list costs
        nothing."""
        node = MeshNode(transport_manager=make_manager())
        self._peer(node, NodeID(b"\x02" * 20), addr="tcp://192.168.1.7:9000")
        assert node._select_relays() == ["tcp://192.168.1.7:9000"]

    async def test_what_the_peer_advertises_beats_how_we_reached_it(self):
        """What it advertises is what it says a stranger can reach it at — and
        since `advertised_uris` requires proof, a claim it has had to earn."""
        node = MeshNode(transport_manager=make_manager())
        self._peer(node, NodeID(b"\x02" * 20), addr="tcp://192.168.1.7:9000",
                   advertises=["tcp://81.240.12.33:9000"])
        assert node._select_relays()[0] == "tcp://81.240.12.33:9000"

    async def test_a_peer_that_dialled_us_is_a_relay_too(self):
        """It is the half of the mesh most likely to be publicly reachable, and
        it was skipped outright."""
        node = MeshNode(transport_manager=make_manager())
        self._peer(node, NodeID(b"\x02" * 20), client=False,
                   advertises=["tcp://81.240.12.33:9000"])
        assert node._select_relays() == ["tcp://81.240.12.33:9000"]

    async def test_the_list_is_bounded(self):
        node = MeshNode(transport_manager=make_manager())
        for index in range(12):
            self._peer(node, NodeID(bytes([index + 2]) * 20),
                       addr="tcp://81.240.12.%d:9000" % (index + 1))
        assert len(node._select_relays()) == 5

    def test_what_counts_as_world_reachable(self):
        node = MeshNode(transport_manager=make_manager())
        for uri in ("tcp://81.240.12.33:9000", "tcp://example.org:9000",
                    "fake://relay:1"):
            assert node._is_world_address(uri), uri
        for uri in ("tcp://192.168.1.7:9000", "tcp://10.0.0.4:1",
                    "tcp://127.0.0.1:1", "", "://", "no-scheme"):
            assert not node._is_world_address(uri), uri


class TestASeekGetsMoreThanOneChance:
    """Greedy XOR to a single neighbour fails precisely when that neighbour has
    no path to the inviter — and a seek has no reply, no retry and no second
    attempt: it either arrives or the join does not happen."""

    def _mesh(self, count: int):
        from src.node import _Peer
        node = MeshNode(transport_manager=make_manager())
        node._running = True
        sent: list = []
        peers = []
        for index in range(count):
            peer = _Peer(FakeTransport(), is_client_side=True)
            peer.authenticated_id = NodeID(bytes([index + 2]) * 20)
            peer.session = SessionKey(b"\x00" * 32)
            async def _send(packet, _p=peer):
                sent.append((_p, packet))

            peer.send = _send
            node._peers.append(peer)
            peers.append(peer)
        return node, peers, sent

    async def test_two_neighbours_carry_it(self):
        from src.node import _SEEK_FANOUT, _encode_seek, _h_code, INVITE_SEEK
        from src.packet import Packet
        node, peers, sent = self._mesh(4)
        inviter = NodeID(b"\xfe" * 20)
        packet = Packet.create(INVITE_SEEK, b"\x09" * 20, inviter.raw,
                               _encode_seek(0, _h_code("x"), b"k", b"t"), ttl=6)
        await node._forward_seek(peers[0], packet)
        assert len({p for p, _ in sent}) == _SEEK_FANOUT

    async def test_one_full_buffer_does_not_decide_the_join(self):
        from src.node import _encode_seek, _h_code, INVITE_SEEK
        from src.packet import Packet
        node, peers, sent = self._mesh(4)

        async def _boom(packet):
            raise OSError("buffer full")

        node._peers[1].send = _boom
        inviter = NodeID(b"\xfe" * 20)
        packet = Packet.create(INVITE_SEEK, b"\x09" * 20, inviter.raw,
                               _encode_seek(0, _h_code("x"), b"k", b"t"), ttl=6)
        await node._forward_seek(peers[0], packet)
        assert sent          # somebody still carried it

    async def test_a_direct_link_to_the_inviter_ends_it_in_one_hop(self):
        from src.node import _encode_seek, _h_code, INVITE_SEEK
        from src.packet import Packet
        node, peers, sent = self._mesh(3)
        inviter = peers[1].authenticated_id
        packet = Packet.create(INVITE_SEEK, b"\x09" * 20, inviter.raw,
                               _encode_seek(0, _h_code("x"), b"k", b"t"), ttl=6)
        await node._forward_seek(peers[0], packet)
        assert [p for p, _ in sent] == [peers[1]]


class TestJoinValidation:
    async def test_rejects_garbage(self):
        node = MeshNode(transport_manager=make_manager())
        for bad in ("", "not-base64!!!", "x" * 40000,
                    base64.b64encode(b"[1,2]").decode()):
            with pytest.raises(ValueError):
                node.console_relay_join(bad)

    async def test_rejects_wrong_version_or_kind(self):
        node = MeshNode(transport_manager=make_manager())
        v2 = base64.b64encode(json.dumps({"v": 2, "kind": "relay-inv"}).encode()).decode()
        wrong_kind = base64.b64encode(json.dumps({"v": 3, "kind": "req"}).encode()).decode()
        for b in (v2, wrong_kind):
            with pytest.raises(ValueError):
                node.console_relay_join(b)

    async def test_rejects_expired(self):
        node = MeshNode(transport_manager=make_manager())
        with pytest.raises(ValueError):
            node.console_relay_join(_block(exp=int(time.time()) - 10))

    async def test_rejects_bad_pub(self):
        node = MeshNode(transport_manager=make_manager())
        bad = base64.b64encode(json.dumps({
            "v": 3, "kind": "relay-inv", "code": "abc1234567",
            "exp": int(time.time()) + 300, "pub": "zz", "token": "aa",
            "relays": ["fake://r:1"]}).encode()).decode()
        with pytest.raises(ValueError):
            node.console_relay_join(bad)

    async def test_rejects_own_invite(self):
        # a block that carries our own key → we would be joining ourselves
        node, _ = await make_node()
        block = node.console_relay_invite()
        with pytest.raises(ValueError):
            node.console_relay_join(block)

    async def test_rejects_no_reachable_relay(self):
        node = MeshNode(transport_manager=make_manager())  # only "fake" registered
        with pytest.raises(ValueError):
            node.console_relay_join(_block(relays=["tcp://x:1"]))  # tcp unsupported
        with pytest.raises(ValueError):
            node.console_relay_join(_block(relays=[]))

    async def test_valid_block_starts_join(self):
        # a well-formed block over a supported scheme starts a background join
        node, _ = await make_node()   # "fake" scheme supported
        node._relay_join_timeout = 0.2
        result = node.console_relay_join(_block(relays=["fake://relay:1"]))
        assert result["relays"] == 1
        assert node._join_task is not None
        # let it fail fast (fake connect won't complete a handshake)
        import asyncio
        async with asyncio.timeout(5):
            while node._join_status["running"]:
                await asyncio.sleep(0.02)
        assert node._join_status["connected"] is None
