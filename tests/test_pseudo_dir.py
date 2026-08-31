"""
The pseudo directory.

Two layers: the pure claim logic in ``src.pseudo_dir`` (self-authenticating
records, node-id binding, canonical names, bounds, hostile input), and the
node-level publish / lookup with its DIR_STORE / DIR_FIND / DIR_FOUND handlers.
"""
import os

import pytest

from src.pseudo_dir import (
    dir_key, build_claim, parse_claim, PseudoBook, PseudoDirError,
    encode_claims, decode_claims, MAX_CLAIM, _MAX_PER_KEY,
)
from src.crypto import CryptoIdentity
from src.metrics import LinkQuality
from src.node_id import NodeID
from src.node import MeshNode, DIR_STORE, DIR_FIND, DIR_FOUND, _QID_LEN
from src.packet import Packet
from tests.conftest import make_manager


def _claim(ident, pseudo="alice", ts=1000):
    return build_claim(pseudo, ident.dsa_public_key, ident.sign, ts)


def _parsed(ident, pseudo="alice", ts=1000):
    raw = _claim(ident, pseudo, ts)
    return parse_claim(raw, ident.verify), raw


class TestKey:
    def test_deterministic_case_and_accent_insensitive(self):
        assert dir_key("Alice") == dir_key("alice")
        assert dir_key("José") == dir_key("jose")
        assert len(dir_key("alice")) == 20

    def test_distinct_pseudos_differ(self):
        assert dir_key("alice") != dir_key("bob")


class TestClaim:
    def test_roundtrip_and_node_binding(self):
        ident = CryptoIdentity()
        claim, raw = _parsed(ident, "Alice", 42)
        assert claim["pseudo"] == "Alice" and claim["ts"] == 42
        assert claim["node_id"] == NodeID.from_public_key(ident.dsa_public_key).raw
        assert claim["key"] == dir_key("alice")
        assert len(raw) <= MAX_CLAIM

    def test_cannot_claim_a_victims_node_id(self):
        # The id is derived from the pubkey *inside* the claim, so the only id a
        # signer can bind a name to is its own. There is no field to lie in.
        attacker, victim = CryptoIdentity(), CryptoIdentity()
        claim, _ = _parsed(attacker, "victim")
        assert claim["node_id"] != NodeID.from_public_key(victim.dsa_public_key).raw

    def test_tampered_pseudo_rejected(self):
        ident = CryptoIdentity()
        raw = bytearray(_claim(ident, "alice"))
        i = raw.index(b"alice")
        raw[i:i + 5] = b"alicE"
        assert parse_claim(bytes(raw), ident.verify) is None

    def test_tampered_signature_rejected(self):
        ident = CryptoIdentity()
        raw = bytearray(_claim(ident))
        raw[-1] ^= 0xFF
        assert parse_claim(bytes(raw), ident.verify) is None

    def test_a_non_canonical_name_is_refused_on_both_sides(self):
        # Refused when signing, so we never emit one…
        ident = CryptoIdentity()
        for bad in ("bob ", "  bob", "bo​b", "x" * 51, "ali‮ce"):
            with pytest.raises(PseudoDirError):
                build_claim(bad, ident.dsa_public_key, ident.sign)

    def test_a_signed_non_canonical_name_is_still_refused_on_receipt(self):
        # …and refused on arrival even when perfectly signed, which is the case
        # that matters: the signer is hostile, not buggy.
        import struct
        from src.pseudo_dir import _HDR, _signing_input, CLAIM_VERSION
        ident = CryptoIdentity()
        pseudo = "ali‮ce"        # right-to-left override, renders reversed
        node_id = NodeID.from_public_key(ident.dsa_public_key).raw
        encoded = pseudo.encode("utf-8")
        sig = ident.sign(_signing_input(node_id, pseudo, 7))
        forged = (_HDR.pack(CLAIM_VERSION, 7, len(ident.dsa_public_key),
                            len(encoded), len(sig))
                  + ident.dsa_public_key + encoded + sig)
        assert parse_claim(forged, ident.verify) is None

    def test_version_is_checked(self):
        ident = CryptoIdentity()
        raw = bytearray(_claim(ident))
        raw[0] = 99
        assert parse_claim(bytes(raw), ident.verify) is None

    def test_hostile_input_never_crashes(self):
        ident = CryptoIdentity()
        for junk in (b"", b"\x00", os.urandom(64), os.urandom(MAX_CLAIM + 1),
                     b"\x02" + b"\xff" * 40, None, "not bytes", 42):
            assert parse_claim(junk, ident.verify) is None

    def test_a_verifier_that_throws_is_not_a_way_in(self):
        def explode(*_args):
            raise RuntimeError("boom")
        assert parse_claim(_claim(CryptoIdentity()), explode) is None


class TestPseudoBook:
    def test_several_nodes_may_wear_one_name(self):
        book = PseudoBook()
        idents = [CryptoIdentity() for _ in range(3)]
        for ident in idents:
            book.offer(*_parsed(ident, "alice"))
        assert len(book.get(dir_key("alice"))) == 3
        assert len(book) == 3

    def test_newer_ts_supersedes_and_older_is_ignored(self):
        book = PseudoBook()
        ident = CryptoIdentity()
        node_id = NodeID.from_public_key(ident.dsa_public_key).raw
        assert book.offer(*_parsed(ident, "alice", 100)) is True
        assert book.offer(*_parsed(ident, "alicia", 200)) is True
        assert book.pseudo_of(node_id) == "alicia"
        # A replayed older claim must not roll the name back.
        assert book.offer(*_parsed(ident, "alice", 100)) is False
        assert book.pseudo_of(node_id) == "alicia"
        # Nor may the same timestamp re-open the question.
        assert book.offer(*_parsed(ident, "alice", 200)) is False
        assert book.pseudo_of(node_id) == "alicia"

    def test_one_entry_per_node_whatever_the_name(self):
        book = PseudoBook()
        ident = CryptoIdentity()
        book.offer(*_parsed(ident, "alice", 1))
        book.offer(*_parsed(ident, "bob", 2))
        assert len(book) == 1
        assert book.get(dir_key("alice")) == []      # the old key is released
        assert len(book.get(dir_key("bob"))) == 1

    def test_bounded_by_entries(self):
        book = PseudoBook(max_nodes=4)
        for i in range(10):
            book.offer(*_parsed(CryptoIdentity(), f"p{i}"))
        assert len(book) == 4

    def test_bounded_by_bytes(self):
        # Claims are ~5 kB each: without a byte budget, a flood of perfectly
        # valid signed claims is a memory-exhaustion vector.
        book = PseudoBook(max_nodes=1000, max_bytes=12_000)
        for i in range(10):
            book.offer(*_parsed(CryptoIdentity(), f"p{i}"))
        assert book.nbytes <= 12_000
        assert 0 < len(book) < 10

    def test_a_claim_evicted_on_the_way_in_is_not_a_change(self):
        # Saying our view changed would have us re-gossip a claim we do not
        # hold, every time it arrives: an epidemic that never terminates, and
        # only under memory pressure — the worst time to find out.
        book = PseudoBook(max_nodes=1000, max_bytes=100)   # under one claim
        assert book.offer(*_parsed(CryptoIdentity(), "alice")) is False
        assert len(book) == 0

    def test_bounded_per_key(self):
        book = PseudoBook()
        for _ in range(_MAX_PER_KEY + 5):
            book.offer(*_parsed(CryptoIdentity(), "crowded"))
        assert len(book.get(dir_key("crowded"))) == _MAX_PER_KEY

    def test_search_ranks_best_first(self):
        book = PseudoBook()
        for name in ("Alice Ada", "alicia", "Bob", "Malice"):
            book.offer(*_parsed(CryptoIdentity(), name))
        names = [h["pseudo"] for h in book.search("ali")]
        # prefix matches before the one that only contains it; "Bob" not at all.
        assert names[-1] == "Malice" and set(names[:2]) == {"Alice Ada", "alicia"}
        assert "Bob" not in names

    def test_search_is_limited(self):
        book = PseudoBook()
        for i in range(20):
            book.offer(*_parsed(CryptoIdentity(), f"alice{i}"))
        assert len(book.search("alice", limit=5)) == 5

    def test_recent_is_newest_first_and_bounded(self):
        book = PseudoBook()
        for i in range(5):
            book.offer(*_parsed(CryptoIdentity(), f"p{i}"))
        recent = book.recent(2)
        assert len(recent) == 2
        assert recent[0] == book.claims()[-1]

    def test_forget_releases_both_indexes(self):
        book = PseudoBook()
        ident = CryptoIdentity()
        claim, raw = _parsed(ident, "alice")
        book.offer(claim, raw)
        book.forget(claim["node_id"])
        assert len(book) == 0 and book.nbytes == 0
        assert book.get(dir_key("alice")) == []


class TestWireEncoding:
    def test_encode_decode_roundtrip(self):
        claims = [_claim(CryptoIdentity(), f"p{i}") for i in range(3)]
        assert decode_claims(encode_claims(claims)) == claims

    def test_decode_hostile(self):
        assert decode_claims(b"") == []
        assert decode_claims(b"\xff\xff") == []          # length beyond the blob
        assert decode_claims(b"\x00\x00") == []          # zero-length entry


class _FakePeer:
    def __init__(self):
        self.authenticated_id = NodeID(os.urandom(20))
        self.session = object()
        self.sent = []
        self.relay_only = False
        self._malformed = 0
        # A stand-in for a link is only useful while it still looks like one:
        # choosing between two links reads what they measured.
        self.remote_addr = "fake://peer:1"
        self.transport = None
        self.last_rtt = None
        self.quality = LinkQuality()

    def note_abuse(self) -> bool:
        from src.node import _MAX_MALFORMED
        self._malformed += 1
        return self._malformed > _MAX_MALFORMED

    async def send(self, pkt):
        self.sent.append(pkt)

    async def stop(self):
        pass


class TestNodeDirectory:
    async def _node(self, pseudo=None):
        return MeshNode(transport_manager=make_manager(), pseudo=pseudo)

    async def test_publish_then_lookup_local(self):
        node = await self._node("Alice")
        try:
            await node.publish_pseudo()
            res = await node.lookup_pseudo("alice")   # case-insensitive
            assert [r["id"] for r in res] == [node.id.raw.hex()]
            assert res[0]["pseudo"] == "Alice"
        finally:
            await node.stop()

    async def test_publish_without_a_pseudo_does_nothing(self):
        node = await self._node()
        try:
            assert await node.publish_pseudo() == ""
        finally:
            await node.stop()

    async def test_lookup_unknown_empty(self):
        node = await self._node("alice")
        try:
            assert await node.lookup_pseudo("nobody") == []
        finally:
            await node.stop()

    async def test_handle_dir_store_accepts_valid_rejects_forged(self):
        node = await self._node()
        author = CryptoIdentity()
        try:
            raw = _claim(author, "carol")
            peer = _FakePeer()
            await node._handle_dir_store(peer, Packet.create(
                DIR_STORE, peer.authenticated_id.raw, b"\xff" * 20, raw))
            assert node._pseudo_book.get(dir_key("carol"))
            bad = bytearray(raw); bad[-1] ^= 0xFF
            await node._handle_dir_store(peer, Packet.create(
                DIR_STORE, peer.authenticated_id.raw, b"\xff" * 20, bytes(bad)))
            assert len(node._pseudo_book.get(dir_key("carol"))) == 1
            assert peer._malformed == 1      # and the sender wears it
        finally:
            await node.stop()

    async def test_handle_dir_find_replies_with_claims(self):
        node = await self._node()
        author = CryptoIdentity()
        try:
            claim, raw = _parsed(author, "dave")
            node._pseudo_book.offer(claim, raw)
            peer = _FakePeer()
            node._peers.append(peer)   # DIR_FOUND routes back via _route_outbound
            qid = os.urandom(_QID_LEN)
            await node._handle_dir_find(peer, Packet.create(
                DIR_FIND, peer.authenticated_id.raw, node.id.raw,
                dir_key("dave") + qid))
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


async def _node_with_peer():
    node = MeshNode(transport_manager=make_manager())
    peer = _FakePeer()
    node._peers.append(peer)
    return node, peer


class TestPlaneCeilings:
    """Every plane that spends our CPU or our bandwidth on a peer's say-so has
    a valve. These are the ones that were missing one."""

    async def test_dir_find_is_rate_limited(self):
        """28 bytes of question buy up to `_FOUND_BUDGET` of signed claims,
        routed to a src_id nothing has verified. `_dir_allowed` covered
        DIR_STORE only."""
        from src.node import DIR_FIND, _QUERY_RATE_MAX
        node, peer = await _node_with_peer()
        payload = os.urandom(20) + os.urandom(8)
        for _ in range(_QUERY_RATE_MAX + 200):
            await node._handle_dir_find(
                peer, Packet.create(DIR_FIND, peer.authenticated_id.raw,
                                    node.id.raw, payload))
        assert node._query_rate[node._rate_key(peer)][0] <= _QUERY_RATE_MAX
        await node.stop()

    async def test_store_is_rate_limited(self):
        """Content addressing stops a peer choosing a key; it does not stop
        them filling the store, and eviction is one global LRU over the app
        chunks and release content that matter."""
        from src.node import STORE, _STORE_RATE_MAX
        from src.app_package import content_key
        node, peer = await _node_with_peer()
        for i in range(_STORE_RATE_MAX + 100):
            value = b"junk%d" % i
            await node._handle_store(
                peer, Packet.create(STORE, peer.authenticated_id.raw,
                                    node.id.raw, content_key(value) + value))
        assert len(node._dht_store) <= _STORE_RATE_MAX
        await node.stop()
