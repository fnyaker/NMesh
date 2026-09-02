"""
Capability negotiation: what two nodes agree they can say to each other.

A version number would have put every build on one line and forced a comparison
— newer or older — which answers the wrong question twice: it has nothing to say
about a node that implements half the protocol and one thing of its own, and it
turns "I do not know this message" into "you are ahead of me".

The two properties worth defending here are the ones that decide whether this
mechanism connects nodes or isolates them:

  - **Silence means the classic set.** A peer that announces nothing is one from
    before this existed, not one with no features. Read the other way, the
    negotiation would be an upgrade that cuts off everyone who has not taken it.
  - **Negotiation only ever adds.** No name may switch off a check. The
    announcement happens before anybody has proved anything, so if a name could
    weaken something, the negotiation would be the way in.
"""
import pytest

from src import features
from src.crypto import SessionKey
from src.node import CAPABILITIES, CHALLENGE, MeshNode
from src.node_id import NodeID
from src.packet import Packet
from tests.conftest import FakeTransport, make_manager, make_node, settle


class TestTheRecord:
    def test_round_trip(self):
        assert features.decode(features.encode(features.SPOKEN)) == features.SPOKEN

    def test_the_encoding_is_canonical(self):
        """Order is not meaningful, so two nodes with the same features produce
        the same bytes — which makes a record comparable and a test readable."""
        assert features.encode(["b", "a"]) == features.encode(["a", "b"])

    def test_names_we_do_not_know_are_kept(self):
        """The whole reason a custom build is not a broken one. Dropping them
        would leave us unable to tell "speaks something I have never heard of"
        from "speaks nothing", and those call for opposite judgements."""
        theirs = features.decode(features.encode({"core", "somethingelse"}))
        assert "somethingelse" in theirs

    @pytest.mark.parametrize("blob", [
        b"", b"\x01", b"\xff" * 4, b"\x02\x00\x01\x04core",     # bad version
        b"\x01\x00\x01\x00",                                    # zero-length name
        b"\x01\x00\x01\x04CORE",                                # not lowercase
        b"\x01\x00\x01\x04core\x00",                            # trailing byte
        b"\x01\x00\x02\x04core",                                # count lies
    ])
    def test_no_hostile_byte_string_raises(self, blob):
        assert features.decode(blob) is None

    def test_an_absurd_number_of_features_is_refused(self):
        many = features.encode({f"f{i}" for i in range(features.MAX_FEATURES)})
        assert features.decode(many) is not None
        with pytest.raises(features.FeatureError):
            features.encode({f"f{i}" for i in range(features.MAX_FEATURES + 1)})

    def test_a_record_is_bounded_before_it_is_parsed(self):
        assert features.decode(b"\x01" * (features.MAX_RECORD + 1)) is None


class TestAgreement:
    def test_the_shared_set_is_the_intersection(self):
        ours = {"core", "kad", "pseudo"}
        theirs = {"core", "pseudo", "theirown"}
        assert features.agree(theirs, ours) == {"core", "pseudo"}

    def test_core_is_never_negotiable(self):
        """It is the messages that carry the negotiation itself. A peer that
        omitted it is old, not mute."""
        assert features.CORE in features.agree(set(), {"core", "kad"})
        assert features.CORE in features.agree({"kad"}, {"kad"})

    def test_a_build_with_nothing_in_common_still_shares_core(self):
        assert features.agree({"alien"}, {"kad"}) == {features.CORE}


class TestOnALink:
    async def test_a_peer_that_says_nothing_keeps_everything(self):
        """The property that decides whether this connects nodes or isolates
        them. An old peer announced nothing and must go on receiving exactly
        what it received before."""
        node, _fake = await make_node()
        try:
            peer = node._peers[0]
            assert peer.agreed is None
            for name in features.SPOKEN:
                assert node.peer_speaks(peer, name) is True
            assert node.peer_speaks(peer, "something-we-invent-later") is True
        finally:
            await node.stop()

    async def test_an_announcement_narrows_what_we_send(self):
        node, _fake = await make_node()
        try:
            peer = node._peers[0]
            await node._handle_capabilities(peer, Packet.create(
                CAPABILITIES, NodeID.generate().raw, b"\xff" * 20,
                features.encode({features.CORE, features.PSEUDO})))
            assert node.peer_speaks(peer, features.PSEUDO) is True
            assert node.peer_speaks(peer, features.RELEASE) is False
        finally:
            await node.stop()

    async def test_a_name_we_do_not_know_is_not_an_offence(self):
        """A node running tomorrow's build, or somebody's own, must not be
        charged for saying so."""
        node, _fake = await make_node()
        try:
            peer = node._peers[0]
            before = peer._malformed
            await node._handle_capabilities(peer, Packet.create(
                CAPABILITIES, NodeID.generate().raw, b"\xff" * 20,
                features.encode({features.CORE, "quantumtunnel"})))
            assert peer._malformed == before
            assert "quantumtunnel" in peer.features
            assert "quantumtunnel" not in peer.agreed   # we cannot speak it
        finally:
            await node.stop()

    async def test_a_malformed_announcement_is_charged(self):
        node, _fake = await make_node()
        try:
            peer = node._peers[0]
            before = peer._malformed
            await node._handle_capabilities(peer, Packet.create(
                CAPABILITIES, NodeID.generate().raw, b"\xff" * 20, b"\xff" * 40))
            assert peer._malformed > before
        finally:
            await node.stop()

    async def test_it_rides_the_round_trip_that_was_happening_anyway(self):
        """No extra exchange and no added latency: the announcement goes out
        with the challenge a connecting link was getting regardless."""
        node, _fake = await make_node()
        opened = FakeTransport()
        try:
            await node._on_new_transport(opened)
            kinds = [p.type for p in opened.sent]
            assert CAPABILITIES in kinds and CHALLENGE in kinds
        finally:
            await node.stop()

    async def test_gossip_skips_a_peer_that_does_not_speak_the_plane(self):
        node, _fake = await make_node()
        second = FakeTransport()
        await node._inject_peer(second)
        try:
            for peer in node._peers:
                peer.authenticated_id = NodeID.generate()
                peer.session = SessionKey(b"\x00" * 32)
            deaf, hearing = node._peers[0], node._peers[1]
            deaf.features = frozenset({features.CORE})
            deaf.agreed = features.agree(deaf.features)
            targets = node._gossip_targets(None, 8, features.PSEUDO)
            assert deaf not in targets and hearing in targets
            # …and with no feature asked for, everybody is a target as before.
            assert deaf in node._gossip_targets(None, 8)
        finally:
            await node.stop()


class TestNothingSecurityCriticalIsNegotiable:
    def test_the_spoken_set_names_planes_not_checks(self):
        """The rule that keeps the negotiation from being the way in: it runs
        before anybody has proved anything, so no name may correspond to a
        verification, an authorisation or a cipher. Each of these is a plane of
        optional *messages* — the checks that guard them are unconditional."""
        forbidden = ("verify", "auth", "sig", "crypt", "cert", "trust", "check",
                     "perm", "root", "key")
        for name in features.SPOKEN - {features.RENEW, features.REVOKE}:
            assert not any(word in name for word in forbidden), name

    async def test_an_empty_announcement_does_not_disarm_the_handshake(self):
        """A peer claiming to speak nothing still has to prove who it is."""
        node, _fake = await make_node()
        try:
            peer = node._peers[0]
            await node._handle_capabilities(peer, Packet.create(
                CAPABILITIES, NodeID.generate().raw, b"\xff" * 20,
                features.encode([])))
            assert peer.agreed == frozenset({features.CORE})
            assert peer.authenticated_id is None   # nothing was granted
            assert peer.session is None
        finally:
            await node.stop()
