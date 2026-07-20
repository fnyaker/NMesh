"""
Relayed invitation — block generation + join validation (étape 3).

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
