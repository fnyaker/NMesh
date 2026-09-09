"""
Handing a publisher key over: the three messages, and what each one refuses.

This moves a **private signing key** — the only secret this product copies on
purpose — so almost every test here is a refusal. The two that matter most:

* an acceptance from anybody but the node the offer named is refused, because
  that is the substitution a relay would make to read the grant;
* a grant that does not decrypt, or whose secret does not match the public half
  that was offered, yields nothing — a signature would not have caught the
  second, and arithmetic does.
"""
import pytest

from src import key_share as ks
from src.crypto import CryptoIdentity
from src.node_id import NodeID


@pytest.fixture(scope="module")
def alice():
    return CryptoIdentity()


@pytest.fixture(scope="module")
def bob():
    return CryptoIdentity()


@pytest.fixture(scope="module")
def publisher():
    return CryptoIdentity()


def _id(identity) -> bytes:
    return NodeID.from_public_key(identity.dsa_public_key).raw


def _node_id_of(public: bytes) -> bytes:
    return NodeID.from_public_key(public).raw


def _offer(publisher, alice, bob, label="release key", ts=None):
    return ks.build_offer(ks.new_offer_id(), _id(alice), _id(bob),
                          publisher.dsa_public_key, publisher.sign,
                          label=label, ts=ts)


class TestTheOfferProvesPossession:
    def test_an_offer_round_trips(self, publisher, alice, bob):
        raw = _offer(publisher, alice, bob)
        parsed = ks.parse_offer(raw, _id(alice), _id(bob), bob.verify)
        assert parsed is not None
        assert parsed["publisher"] == publisher.dsa_public_key
        assert parsed["label"] == "release key"

    def test_it_is_signed_by_the_key_it_offers(self, publisher, alice, bob):
        """Otherwise anybody could offer a key they do not have and collect
        acceptances from people who thought they knew who was asking."""
        forged = ks.build_offer(ks.new_offer_id(), _id(alice), _id(bob),
                                publisher.dsa_public_key, alice.sign)
        assert ks.parse_offer(forged, _id(alice), _id(bob), bob.verify) is None

    def test_an_offer_for_somebody_else_is_refused(self, publisher, alice, bob):
        raw = _offer(publisher, alice, bob)
        assert ks.parse_offer(raw, _id(alice), b"\x07" * 20, bob.verify) is None

    def test_a_rewritten_sender_is_refused(self, publisher, alice, bob):
        """`src_id` is not authenticated on a routed packet — but it is inside
        the signature, so a relay that rewrites it breaks the offer instead of
        redirecting the answer."""
        raw = _offer(publisher, alice, bob)
        assert ks.parse_offer(raw, b"\x09" * 20, _id(bob), bob.verify) is None

    def test_a_flipped_byte_is_refused(self, publisher, alice, bob):
        raw = bytearray(_offer(publisher, alice, bob))
        raw[-1] ^= 0xFF
        assert ks.parse_offer(bytes(raw), _id(alice), _id(bob), bob.verify) is None

    def test_a_label_that_would_not_render_is_refused(self, publisher, alice, bob):
        """It is shown to a human beside a key id. A control character there is
        a way to make one offer look like another."""
        raw = _offer(publisher, alice, bob, label="release‮key")
        assert ks.parse_offer(raw, _id(alice), _id(bob), bob.verify) is None

    @pytest.mark.parametrize("blob", [b"", b"\x01" * 8, None, 5, b"\x02" * 40])
    def test_hostile_input_never_raises(self, blob, alice, bob):
        assert ks.parse_offer(blob, _id(alice), _id(bob), bob.verify) is None

    def test_trailing_bytes_are_refused(self, publisher, alice, bob):
        raw = _offer(publisher, alice, bob) + b"x"
        assert ks.parse_offer(raw, _id(alice), _id(bob), bob.verify) is None


class TestOnlyTheNamedNodeCanAccept:
    def _accept(self, offer_id, recipient, sender_id, kem_public):
        return ks.build_accept(offer_id, _id(recipient), sender_id, kem_public,
                               recipient.dsa_public_key, recipient.sign)

    def test_an_acceptance_round_trips(self, alice, bob):
        offer_id = ks.new_offer_id()
        kem_public, _secret = bob.generate_kem_keypair()
        raw = self._accept(offer_id, bob, _id(alice), kem_public)
        parsed = ks.parse_accept(raw, _id(bob), _id(alice), alice.verify,
                                 _node_id_of)
        assert parsed is not None and parsed["kem_public"] == kem_public

    def test_a_third_party_cannot_accept_in_their_name(self, alice, bob,
                                                       publisher):
        """The substitution a relay would make: put its own KEM key here and
        read the grant. It would need Bob's signing key."""
        offer_id = ks.new_offer_id()
        kem_public, _secret = publisher.generate_kem_keypair()
        raw = self._accept(offer_id, publisher, _id(alice), kem_public)
        # Signed by a third party, presented as Bob's.
        assert ks.parse_accept(raw, _id(bob), _id(alice), alice.verify,
                               _node_id_of) is None

    def test_the_key_inside_must_produce_the_id_it_claims(self, alice, bob):
        offer_id = ks.new_offer_id()
        kem_public, _secret = bob.generate_kem_keypair()
        raw = self._accept(offer_id, bob, _id(alice), kem_public)
        assert ks.parse_accept(raw, b"\x03" * 20, _id(alice), alice.verify,
                               _node_id_of) is None

    def test_an_acceptance_for_another_sender_is_refused(self, alice, bob):
        offer_id = ks.new_offer_id()
        kem_public, _secret = bob.generate_kem_keypair()
        raw = self._accept(offer_id, bob, _id(alice), kem_public)
        assert ks.parse_accept(raw, _id(bob), b"\x04" * 20, alice.verify,
                               _node_id_of) is None

    def test_a_flipped_byte_is_refused(self, alice, bob):
        offer_id = ks.new_offer_id()
        kem_public, _secret = bob.generate_kem_keypair()
        raw = bytearray(self._accept(offer_id, bob, _id(alice), kem_public))
        raw[-1] ^= 0xFF
        assert ks.parse_accept(bytes(raw), _id(bob), _id(alice), alice.verify,
                               _node_id_of) is None

    @pytest.mark.parametrize("blob", [b"", b"\x01" * 8, None, 5])
    def test_hostile_input_never_raises(self, blob, alice, bob):
        assert ks.parse_accept(blob, _id(bob), _id(alice), alice.verify,
                               _node_id_of) is None
        assert ks.accept_offer_id(blob) is None


class TestTheGrantOpensForOneNodeOnly:
    def _exchange(self, alice, bob, publisher):
        offer_id = ks.new_offer_id()
        kem_public, kem_secret = bob.generate_kem_keypair()
        secret = publisher._signer.export_secret_key()
        grant = ks.seal_grant(offer_id, _id(alice), _id(bob),
                              publisher.dsa_public_key, secret, kem_public,
                              alice.kem_encapsulate)
        return offer_id, grant, kem_secret, secret

    def test_the_recipient_recovers_the_secret(self, alice, bob, publisher):
        offer_id, grant, kem_secret, secret = self._exchange(alice, bob, publisher)
        assert ks.grant_offer_id(grant) == offer_id
        opened = ks.open_grant(grant, _id(alice), _id(bob),
                               publisher.dsa_public_key, kem_secret,
                               bob.kem_decapsulate)
        assert opened == secret
        # …and it really is the key that was offered. This is the check no
        # signature would have made.
        recovered = CryptoIdentity.from_pair(publisher.dsa_public_key, opened)
        try:
            assert recovered.dsa_public_key == publisher.dsa_public_key
        finally:
            recovered.close()

    def test_somebody_else_s_kem_key_opens_nothing(self, alice, bob, publisher):
        _offer_id, grant, _kem_secret, _secret = self._exchange(alice, bob,
                                                                publisher)
        _other_public, other_secret = publisher.generate_kem_keypair()
        assert ks.open_grant(grant, _id(alice), _id(bob),
                             publisher.dsa_public_key, other_secret,
                             bob.kem_decapsulate) is None

    def test_a_tampered_grant_opens_nothing(self, alice, bob, publisher):
        _offer_id, grant, kem_secret, _secret = self._exchange(alice, bob,
                                                               publisher)
        broken = bytearray(grant)
        broken[-1] ^= 0xFF
        assert ks.open_grant(bytes(broken), _id(alice), _id(bob),
                             publisher.dsa_public_key, kem_secret,
                             bob.kem_decapsulate) is None

    def test_it_cannot_be_lifted_into_another_exchange(self, alice, bob,
                                                       publisher):
        """The offer id, both node ids and the public half are the AEAD's
        associated data, so a grant is bound to the exchange it belongs to."""
        _offer_id, grant, kem_secret, _secret = self._exchange(alice, bob,
                                                               publisher)
        for wrong in (
            (b"\x05" * 20, _id(bob), publisher.dsa_public_key),
            (_id(alice), b"\x06" * 20, publisher.dsa_public_key),
            (_id(alice), _id(bob), alice.dsa_public_key),
        ):
            assert ks.open_grant(grant, *wrong, kem_secret,
                                 bob.kem_decapsulate) is None

    @pytest.mark.parametrize("blob", [b"", b"\x01" * 8, None, 5])
    def test_hostile_input_never_raises(self, blob, alice, bob, publisher):
        assert ks.grant_offer_id(blob) is None
        assert ks.open_grant(blob, _id(alice), _id(bob),
                             publisher.dsa_public_key, b"\x00" * 32,
                             bob.kem_decapsulate) is None


class TestBuildersRefuseNonsense:
    def test_ids_must_be_node_ids(self, publisher, alice):
        with pytest.raises(ks.KeyShareError):
            ks.build_offer(ks.new_offer_id(), b"short", b"\x00" * 20,
                           publisher.dsa_public_key, publisher.sign)

    def test_an_offer_id_is_fixed_width(self, publisher, alice, bob):
        with pytest.raises(ks.KeyShareError):
            ks.build_offer(b"\x00" * 4, _id(alice), _id(bob),
                           publisher.dsa_public_key, publisher.sign)

    def test_an_empty_secret_is_refused(self, alice, bob, publisher):
        kem_public, _secret = bob.generate_kem_keypair()
        with pytest.raises(ks.KeyShareError):
            ks.seal_grant(ks.new_offer_id(), _id(alice), _id(bob),
                          publisher.dsa_public_key, b"", kem_public,
                          alice.kem_encapsulate)

    def test_a_label_is_cut_to_what_will_be_shown(self, publisher, alice, bob):
        raw = _offer(publisher, alice, bob, label="x" * 500)
        parsed = ks.parse_offer(raw, _id(alice), _id(bob), bob.verify)
        assert parsed is not None and len(parsed["label"]) == ks.MAX_LABEL


class TestTheStoreHoldsWhatCanSign:
    """A key store is not a cache: what is in it can publish under a name other
    people pinned, so it is re-read from the files rather than from an index
    that could disagree with them."""

    def _key(self):
        return CryptoIdentity()

    def test_a_key_round_trips_and_unlocks(self, tmp_path):
        from src import publisher_key as pk
        store = pk.KeyStore(str(tmp_path))
        identity = self._key()
        try:
            row = store.put(identity.dsa_public_key,
                            identity._signer.export_secret_key(), "pass",
                            label="release", n=2 ** 8, r=8, p=1)
            assert row["id"] == pk.publisher_id(identity.dsa_public_key).hex()
            assert row["label"] == "release"
            public, secret = pk.load(store.path_for(row["id"]), "pass")
            assert public == identity.dsa_public_key
            assert secret == identity._signer.export_secret_key()
        finally:
            identity.close()

    def test_the_file_is_readable_only_by_this_user(self, tmp_path):
        import os
        from src import publisher_key as pk
        store = pk.KeyStore(str(tmp_path))
        identity = self._key()
        try:
            row = store.put(identity.dsa_public_key,
                            identity._signer.export_secret_key(), "pass",
                            n=2 ** 8, r=8, p=1)
        finally:
            identity.close()
        assert oct(os.stat(store.path_for(row["id"])).st_mode & 0o777) == "0o600"

    def test_a_key_filed_under_somebody_else_s_id_answers_as_itself(self, tmp_path):
        """The files are the truth. A key renamed to another id is not that
        key, and saying so is the difference between a store and a guess."""
        import os
        from src import publisher_key as pk
        store = pk.KeyStore(str(tmp_path))
        identity = self._key()
        try:
            row = store.put(identity.dsa_public_key,
                            identity._signer.export_secret_key(), "pass",
                            n=2 ** 8, r=8, p=1)
        finally:
            identity.close()
        os.rename(store.path_for(row["id"]),
                  os.path.join(str(tmp_path), "aa" * 20 + ".key"))
        assert store.get("aa" * 20) is None
        assert store.list() == []

    def test_a_corrupt_index_costs_the_labels_and_nothing_else(self, tmp_path):
        from src import publisher_key as pk
        store = pk.KeyStore(str(tmp_path))
        identity = self._key()
        try:
            row = store.put(identity.dsa_public_key,
                            identity._signer.export_secret_key(), "pass",
                            label="release", n=2 ** 8, r=8, p=1)
        finally:
            identity.close()
        (tmp_path / "index.json").write_text("not json")
        again = pk.KeyStore(str(tmp_path))
        assert [entry["id"] for entry in again.list()] == [row["id"]]
        assert again.get(row["id"])["label"] == ""

    def test_forgetting_removes_the_file(self, tmp_path):
        import os
        from src import publisher_key as pk
        store = pk.KeyStore(str(tmp_path))
        identity = self._key()
        try:
            row = store.put(identity.dsa_public_key,
                            identity._signer.export_secret_key(), "pass",
                            n=2 ** 8, r=8, p=1)
        finally:
            identity.close()
        path = store.path_for(row["id"])
        assert store.forget(row["id"]) is True
        assert not os.path.exists(path) and len(store) == 0
        assert store.forget(row["id"]) is False

    @pytest.mark.parametrize("bad", ["", "zz", "a" * 39, "../../etc/passwd"])
    def test_an_id_that_is_not_an_id_names_nothing(self, tmp_path, bad):
        from src import publisher_key as pk
        store = pk.KeyStore(str(tmp_path))
        assert store.path_for(bad) is None and store.get(bad) is None


class TestTheNodeHandsOneOver:
    """The three handlers, driven with the routing stubbed out. What is under
    test is the state machine: who holds what, and for how long."""

    def _nodes(self, tmp_path):
        from src.node import MeshNode
        from tests.conftest import make_manager
        alice = MeshNode(transport_manager=make_manager(),
                         release_dir=str(tmp_path / "alice"))
        bob = MeshNode(transport_manager=make_manager(),
                       release_dir=str(tmp_path / "bob"))
        sent = []

        async def route(packet, blocking=True):
            sent.append(packet)

        alice._route_outbound = route
        bob._route_outbound = route
        return alice, bob, sent

    class _Peer:
        authenticated_id = None
        malformed = 0

        def note_abuse(self):
            self.malformed += 1
            return False

    async def _make_key(self, node, passphrase="mine"):
        import src.publisher_key as pk
        # The cheap scrypt cost is the test's, not the product's: `create` uses
        # the real one, which is a fraction of a second an operator notices once
        # and a guessing rig pays per attempt.
        identity = CryptoIdentity()
        try:
            return node._publisher_keys.put(
                identity.dsa_public_key, identity._signer.export_secret_key(),
                passphrase, label="release key", n=2 ** 8, r=8, p=1), pk
        finally:
            identity.close()

    async def test_a_key_crosses_and_can_sign_on_the_other_side(self, tmp_path):
        alice, bob, sent = self._nodes(tmp_path)
        try:
            row, pk = await self._make_key(alice)
            offer = await alice.offer_publisher_key(
                bob.id, alice.publisher_key_path(row["id"]), "mine",
                label="release key")
            assert offer["key_id"] == row["id"]

            peer = self._Peer()
            await bob._handle_key_offer(peer, sent.pop())
            waiting = bob.key_share_overview()["incoming"]
            assert [entry["key_id"] for entry in waiting] == [row["id"]]
            assert waiting[0]["from"] == alice.id.raw.hex()

            await bob.accept_publisher_key(offer["offer_id"], "theirs")
            await alice._handle_key_accept(peer, sent.pop())
            await bob._handle_key_grant(peer, sent.pop())

            held = bob.key_share_overview()["keys"]
            assert [entry["id"] for entry in held] == [row["id"]]
            assert held[0]["received_from"] == alice.id.raw.hex()
            # Under Bob's passphrase, never Alice's.
            public, secret = pk.load(bob.publisher_key_path(row["id"]), "theirs")
            with pytest.raises(pk.PublisherKeyError):
                pk.load(bob.publisher_key_path(row["id"]), "mine")
            signer = CryptoIdentity.from_pair(public, secret)
            try:
                assert signer.verify(b"x", signer.sign(b"x"), public)
            finally:
                signer.close()
            assert peer.malformed == 0
        finally:
            await alice.stop(); await bob.stop()

    async def test_the_sender_stops_holding_the_secret(self, tmp_path):
        """The offer is the window in which an unlocked key sits in memory. It
        closes when the grant goes out, whether or not it arrives."""
        alice, bob, sent = self._nodes(tmp_path)
        try:
            row, _pk = await self._make_key(alice)
            offer = await alice.offer_publisher_key(
                bob.id, alice.publisher_key_path(row["id"]), "mine")
            assert alice.key_share_overview()["outgoing"]
            peer = self._Peer()
            await bob._handle_key_offer(peer, sent.pop())
            await bob.accept_publisher_key(offer["offer_id"], "theirs")
            await alice._handle_key_accept(peer, sent.pop())
            assert alice.key_share_overview()["outgoing"] == []
            assert alice._key_offers_out == {}
        finally:
            await alice.stop(); await bob.stop()

    async def test_an_expired_offer_takes_the_secret_with_it(self, tmp_path):
        alice, bob, sent = self._nodes(tmp_path)
        try:
            row, _pk = await self._make_key(alice)
            await alice.offer_publisher_key(
                bob.id, alice.publisher_key_path(row["id"]), "mine")
            for entry in alice._key_offers_out.values():
                entry["deadline"] = 0.0
            assert alice.key_share_overview()["outgoing"] == []
        finally:
            await alice.stop(); await bob.stop()

    async def test_nothing_travels_without_an_acceptance(self, tmp_path):
        """The point of the middle message: refuse, and there is no key
        material for the secret to be sealed to."""
        alice, bob, sent = self._nodes(tmp_path)
        try:
            row, _pk = await self._make_key(alice)
            offer = await alice.offer_publisher_key(
                bob.id, alice.publisher_key_path(row["id"]), "mine")
            await bob._handle_key_offer(self._Peer(), sent.pop())
            assert bob.refuse_publisher_key(offer["offer_id"]) is True
            assert bob.key_share_overview()["incoming"] == []
            assert sent == []                       # a refusal answers nobody
            assert bob.key_share_overview()["keys"] == []
        finally:
            await alice.stop(); await bob.stop()

    async def test_an_acceptance_nobody_offered_is_ignored(self, tmp_path):
        alice, bob, sent = self._nodes(tmp_path)
        try:
            row, _pk = await self._make_key(bob)
            offer = await bob.offer_publisher_key(
                alice.id, bob.publisher_key_path(row["id"]), "mine")
            await alice._handle_key_offer(self._Peer(), sent.pop())
            await alice.accept_publisher_key(offer["offer_id"], "theirs")
            accept = sent.pop()
            # Alice's acceptance, replayed at a node that offered nothing.
            third = self._nodes(tmp_path / "third")[0]
            try:
                peer = self._Peer()
                await third._handle_key_accept(peer, accept)
                assert sent == [] and peer.malformed == 0
            finally:
                await third.stop()
        finally:
            await alice.stop(); await bob.stop()

    async def test_a_grant_nobody_accepted_writes_nothing(self, tmp_path):
        alice, bob, sent = self._nodes(tmp_path)
        try:
            row, _pk = await self._make_key(alice)
            offer = await alice.offer_publisher_key(
                bob.id, alice.publisher_key_path(row["id"]), "mine")
            peer = self._Peer()
            await bob._handle_key_offer(peer, sent.pop())
            await bob.accept_publisher_key(offer["offer_id"], "theirs")
            await alice._handle_key_accept(peer, sent.pop())
            grant = sent.pop()
            bob._key_accepts.clear()              # …as an expiry would have
            await bob._handle_key_grant(peer, grant)
            assert bob.key_share_overview()["keys"] == []
        finally:
            await alice.stop(); await bob.stop()

    async def test_a_forged_offer_is_charged_to_whoever_sent_it(self, tmp_path):
        from src.packet import Packet
        from src.node import KEY_OFFER
        alice, bob, _sent = self._nodes(tmp_path)
        try:
            peer = self._Peer()
            await bob._handle_key_offer(peer, Packet.create(
                KEY_OFFER, alice.id.raw, bob.id.raw, b"not an offer"))
            assert peer.malformed == 1
            assert bob.key_share_overview()["incoming"] == []
        finally:
            await alice.stop(); await bob.stop()

    async def test_offers_waiting_for_a_human_are_bounded(self, tmp_path):
        from src.node import _MAX_KEY_OFFERS
        alice, bob, sent = self._nodes(tmp_path)
        try:
            row, _pk = await self._make_key(alice)
            path = alice.publisher_key_path(row["id"])
            peer = self._Peer()
            for _ in range(_MAX_KEY_OFFERS + 4):
                await alice.offer_publisher_key(bob.id, path, "mine")
                await bob._handle_key_offer(peer, sent.pop())
            assert len(bob.key_share_overview()["incoming"]) == _MAX_KEY_OFFERS
        finally:
            await alice.stop(); await bob.stop()

    async def test_a_node_cannot_offer_a_key_to_itself(self, tmp_path):
        alice, bob, _sent = self._nodes(tmp_path)
        try:
            row, _pk = await self._make_key(alice)
            with pytest.raises(ks.KeyShareError):
                await alice.offer_publisher_key(
                    alice.id, alice.publisher_key_path(row["id"]), "mine")
        finally:
            await alice.stop(); await bob.stop()

    async def test_the_wrong_passphrase_offers_nothing(self, tmp_path):
        from src import publisher_key as pk
        alice, bob, sent = self._nodes(tmp_path)
        try:
            row, _pk = await self._make_key(alice)
            with pytest.raises(pk.PublisherKeyError):
                await alice.offer_publisher_key(
                    bob.id, alice.publisher_key_path(row["id"]), "not it")
            assert sent == [] and alice._key_offers_out == {}
        finally:
            await alice.stop(); await bob.stop()
