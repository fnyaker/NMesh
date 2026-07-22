"""
Pseudo directory tests.

Two layers: the pure keyed-directory logic in src.pseudo_dir (self-authenticating
claims, node-id binding, bounds, hostile input), and the node-level publish /
lookup with its DIR_STORE / DIR_FIND / DIR_FOUND handlers.
"""
import os
import struct

import pytest

from src import pseudo_dir
from src.pseudo_dir import (
    dir_key, build_claim, parse_claim, PseudoStore, PseudoDirError,
    encode_claims, decode_claims,
)
from src.crypto import CryptoIdentity
from src.node_id import NodeID
from src.node import MeshNode, DIR_STORE, DIR_FIND, DIR_FOUND, _QID_LEN
from src.packet import Packet
from src.app_channel import CHAT_APP_ID, builtin_id
from tests.conftest import make_manager

APP = CHAT_APP_ID
OTHER_APP = builtin_id("other")


def _claim(ident, app=APP, pseudo="alice", ts=1000):
    return build_claim(app, pseudo, ident.dsa_public_key, ident.sign, ts)


class TestKey:
    def test_deterministic_and_case_insensitive(self):
        assert dir_key(APP, "Alice") == dir_key(APP, "  alice ")
        assert len(dir_key(APP, "alice")) == 20

    def test_app_scoped(self):
        assert dir_key(APP, "alice") != dir_key(OTHER_APP, "alice")

    def test_distinct_pseudos_differ(self):
        assert dir_key(APP, "alice") != dir_key(APP, "bob")


class TestClaim:
    def test_roundtrip_and_node_binding(self):
        ident = CryptoIdentity()
        c = parse_claim(_claim(ident), ident.verify)
        assert c is not None
        # The node id is derived from the pubkey in the claim — not free to set.
        assert c["node_id"] == NodeID.from_public_key(ident.dsa_public_key).raw
        assert c["pseudo"] == "alice"
        assert c["key"] == dir_key(APP, "alice")
        assert c["app_id"] == APP

    def test_cannot_claim_a_victims_node_id(self):
        # Whatever a claim says, its node id is hash(pubkey_in_claim). An attacker
        # signing with their own key can only ever produce their own node id, so
        # they cannot map a pseudo onto someone else's identity.
        attacker = CryptoIdentity()
        victim_id = NodeID.from_public_key(CryptoIdentity().dsa_public_key).raw
        c = parse_claim(_claim(attacker, pseudo="victim"), attacker.verify)
        assert c["node_id"] != victim_id

    def test_wrong_key_rejected(self):
        ident, other = CryptoIdentity(), CryptoIdentity()
        raw = _claim(ident)
        # Verifying with a key that isn't the claim's pubkey must fail.
        assert parse_claim(raw, lambda m, s, k: other.verify(m, s, other.dsa_public_key)) is None

    def test_tampered_pseudo_rejected(self):
        ident = CryptoIdentity()
        raw = bytearray(_claim(ident, pseudo="alice"))
        i = raw.find(b"alice")
        raw[i:i + 5] = b"evilx"          # flip the pseudo → signature breaks
        assert parse_claim(bytes(raw), ident.verify) is None

    def test_bad_app_id_rejected_on_build(self):
        ident = CryptoIdentity()
        with pytest.raises(PseudoDirError):
            build_claim(b"short", "alice", ident.dsa_public_key, ident.sign)

    def test_hostile_input_never_crashes(self):
        ident = CryptoIdentity()
        for bad in (b"", b"\x00", os.urandom(9), os.urandom(50),
                    APP + struct.pack("!QHHH", 0, 9999, 9999, 9999) + b"x"):
            assert parse_claim(bad, ident.verify) is None


class TestPseudoStore:
    def test_multiple_claimants_per_pseudo(self):
        a, b = CryptoIdentity(), CryptoIdentity()
        store = PseudoStore()
        ca, cb = _claim(a), _claim(b)
        assert store.put(parse_claim(ca, a.verify), ca)
        assert store.put(parse_claim(cb, b.verify), cb)
        # Same pseudo → same key → both claims kept.
        assert len(store.get(dir_key(APP, "alice"))) == 2

    def test_newer_ts_supersedes_same_node(self):
        ident = CryptoIdentity()
        store = PseudoStore()
        old, new = _claim(ident, ts=1000), _claim(ident, ts=2000)
        assert store.put(parse_claim(old, ident.verify), old)
        assert store.put(parse_claim(new, ident.verify), new)
        assert store.put(parse_claim(old, ident.verify), old) is False  # older ignored
        assert len(store.get(dir_key(APP, "alice"))) == 1

    def test_per_key_bounded(self):
        store = PseudoStore(max_per_key=3)
        for _ in range(5):
            idn = CryptoIdentity()
            raw = _claim(idn)
            store.put(parse_claim(raw, idn.verify), raw)
        assert len(store.get(dir_key(APP, "alice"))) == 3

    def test_key_count_bounded(self):
        store = PseudoStore(max_keys=2)
        ident = CryptoIdentity()
        for name in ("a", "b", "c"):
            raw = _claim(ident, pseudo=name)
            store.put(parse_claim(raw, ident.verify), raw)
        assert len(store) == 2

    def test_encode_decode_roundtrip(self):
        ident = CryptoIdentity()
        claims = [_claim(ident, pseudo="alice")]
        assert decode_claims(encode_claims(claims)) == claims

    def test_decode_hostile(self):
        assert decode_claims(b"") == []
        assert decode_claims(struct.pack("!H", 9999) + b"short") == []


class _FakePeer:
    def __init__(self):
        self.authenticated_id = NodeID(os.urandom(20))
        self.session = object()
        self.sent = []
        self.relay_only = False
    async def send(self, pkt):
        self.sent.append(pkt)
    async def stop(self):
        pass


class TestNodeDirectory:
    async def _node(self):
        return MeshNode(transport_manager=make_manager())

    async def test_publish_then_lookup_local(self):
        node = await self._node()
        try:
            await node.publish_pseudo(APP, "Alice")
            res = await node.lookup_pseudo(APP, "alice")   # case-insensitive
            assert res == [{"id": node.id.raw.hex(), "pseudo": "Alice"}]
        finally:
            await node.stop()

    async def test_lookup_unknown_empty(self):
        node = await self._node()
        try:
            assert await node.lookup_pseudo(APP, "nobody") == []
        finally:
            await node.stop()

    async def test_app_namespaced(self):
        node = await self._node()
        try:
            await node.publish_pseudo(APP, "alice")
            # Same pseudo, different app namespace → no leak.
            assert await node.lookup_pseudo(OTHER_APP, "alice") == []
        finally:
            await node.stop()

    async def test_handle_dir_store_accepts_valid_rejects_forged(self):
        node = await self._node()
        author = CryptoIdentity()
        try:
            raw = _claim(author, pseudo="carol")
            peer = _FakePeer()
            await node._handle_dir_store(peer, Packet.create(DIR_STORE,
                peer.authenticated_id.raw, b"\xff" * 20, raw))
            assert node._pseudo_store.get(dir_key(APP, "carol"))
            # A tampered claim is dropped.
            bad = bytearray(raw); bad[-1] ^= 0xFF
            await node._handle_dir_store(peer, Packet.create(DIR_STORE,
                peer.authenticated_id.raw, b"\xff" * 20, bytes(bad)))
            assert len(node._pseudo_store.get(dir_key(APP, "carol"))) == 1
        finally:
            await node.stop()

    async def test_handle_dir_find_replies_with_claims(self):
        node = await self._node()
        author = CryptoIdentity()
        try:
            raw = _claim(author, pseudo="dave")
            node._pseudo_store.put(parse_claim(raw, node._identity.verify), raw)
            peer = _FakePeer()
            qid = os.urandom(_QID_LEN)
            await node._handle_dir_find(peer, Packet.create(DIR_FIND,
                peer.authenticated_id.raw, node.id.raw, dir_key(APP, "dave") + qid))
            assert peer.sent and peer.sent[-1].type == DIR_FOUND
            assert peer.sent[-1].payload[:_QID_LEN] == qid
            assert decode_claims(peer.sent[-1].payload[_QID_LEN:]) == [raw]
        finally:
            await node.stop()

    async def test_rate_limit_blocks_flood(self):
        node = await self._node()
        try:
            from src.node import _DIR_RATE_MAX
            peer = _FakePeer()
            allowed = sum(node._dir_allowed(peer) for _ in range(_DIR_RATE_MAX + 20))
            assert allowed == _DIR_RATE_MAX
        finally:
            await node.stop()
