"""
What may replace this node's code, and on whose word.

A release is the highest-authority payload the mesh carries: everything else it
delivers is data, this one is the program. So the tests here are almost entirely
about *refusing* — and about one distinction that the obvious design gets wrong.

**Serving is not vouching.** Mirroring a package is free, and content addressing
already makes the bytes safe to fetch from anyone; a thousand mirrors say
nothing that one does not. What costs an attacker something is a second *key*
put behind the same content. So corroboration is counted in signatures, never in
servers — and the keys whose signatures count are chosen by a human, one at a
time, which is what a quorum has to be to survive somebody minting two hundred
identities.
"""
import os

import pytest

from src import core_release as cr
from src import publisher_key
from src.crypto import CryptoError, CryptoIdentity
from src.node import MeshNode
from tests.conftest import make_manager


def _tree(root, version="9.9.9", marker="# the code\n"):
    os.makedirs(os.path.join(root, "src"), exist_ok=True)
    with open(os.path.join(root, "src", "version.py"), "w") as handle:
        handle.write(f'__version__ = "{version}"\n')
    with open(os.path.join(root, "src", "node.py"), "w") as handle:
        handle.write(marker)
    with open(os.path.join(root, "start.sh"), "w") as handle:
        handle.write("#!/bin/sh\necho hi\n")
    return root


def _node(quorum=0):
    return MeshNode(transport_manager=make_manager(), release_quorum=quorum)


def _signed(identity, package, version="9.9.9", ts=None):
    return cr.build_release(package, version, identity.dsa_public_key,
                            identity.sign, ts=ts)


def _package(tmp_path, name, version="9.9.9", marker="# the code\n"):
    root = _tree(str(tmp_path / name), version, marker)
    return cr.build_package(cr.read_tree(root))


# ---------------------------------------------------------------------------
# Counting corroboration
# ---------------------------------------------------------------------------

class TestAttestation:
    def test_attesters_are_the_keys_that_signed_this_content(self, tmp_path):
        catalog = cr.ReleaseCatalog()
        package = _package(tmp_path, "a")
        a, b = CryptoIdentity(), CryptoIdentity()
        for identity in (a, b):
            catalog.offer(_signed(identity, package), cr_verify())
        doc = cr.parse_release(_signed(a, package), cr_verify())
        assert len(catalog.attesters(doc["version"], doc["sha256"])) == 2

    def test_a_second_signature_over_other_content_is_not_corroboration(
            self, tmp_path):
        """Two publishers agreeing on a version number while shipping different
        code is a disagreement, not a confirmation."""
        catalog = cr.ReleaseCatalog()
        honest = _package(tmp_path, "honest")
        theirs = _package(tmp_path, "theirs", marker="# not the code\n")
        a, b = CryptoIdentity(), CryptoIdentity()
        catalog.offer(_signed(a, honest), cr_verify())
        catalog.offer(_signed(b, theirs), cr_verify())
        doc = cr.parse_release(_signed(a, honest), cr_verify())
        assert len(catalog.attesters(doc["version"], doc["sha256"])) == 1
        assert catalog.contradicts(doc["version"], doc["sha256"]) is True

    def test_one_publisher_signing_twice_is_one_attester(self, tmp_path):
        """The quantity that means something is how many distinct parties, so
        the same key twice must not price a quorum at one machine."""
        catalog = cr.ReleaseCatalog()
        package = _package(tmp_path, "a")
        a = CryptoIdentity()
        catalog.offer(_signed(a, package, ts=100), cr_verify())
        catalog.offer(_signed(a, package, ts=200), cr_verify())
        doc = cr.parse_release(_signed(a, package), cr_verify())
        assert len(catalog.attesters(doc["version"], doc["sha256"])) == 1


class TestEndorsement:
    def test_only_endorsed_keys_count(self, tmp_path):
        pins = cr.TrustedPublishers()
        keys = [CryptoIdentity() for _ in range(4)]
        pins.add(keys[0].dsa_public_key, "one", endorsed=True)
        pins.add(keys[1].dsa_public_key, "two", endorsed=True)
        pins.add(keys[2].dsa_public_key, "three")           # pinned, not endorsed
        counted = pins.endorsed_among([k.dsa_public_key for k in keys])
        assert len(counted) == 2

    def test_the_same_key_offered_twice_counts_once(self):
        pins = cr.TrustedPublishers()
        one = CryptoIdentity()
        pins.add(one.dsa_public_key, "one", endorsed=True)
        assert len(pins.endorsed_among([one.dsa_public_key] * 5)) == 1

    def test_endorsing_is_not_auto_installing(self):
        """Two different statements, and neither implies the other: one hands a
        key a scheduled restart, the other only lets its word count."""
        pins = cr.TrustedPublishers()
        one = CryptoIdentity()
        pins.add(one.dsa_public_key, "one", endorsed=True)
        assert pins.auto_for(one.dsa_public_key) is False
        assert pins.endorsed_among([one.dsa_public_key]) != []

    def test_flags_survive_a_reload(self, tmp_path):
        path = str(tmp_path / "publishers.json")
        one = CryptoIdentity()
        cr.TrustedPublishers(path).add(one.dsa_public_key, "one",
                                       auto=True, endorsed=True)
        entry = cr.TrustedPublishers(path).entry(one.dsa_public_key)
        assert entry["auto"] is True and entry["endorsed"] is True


# ---------------------------------------------------------------------------
# The decision
# ---------------------------------------------------------------------------

class TestUnattendedInstall:
    async def _catalogued(self, node, identity, package, ts=None):
        blob = _signed(identity, package, ts=ts)
        node._releases.offer(blob, node._identity.verify, node._trusts_publisher)
        return node._releases.get(
            cr.publisher_id(identity.dsa_public_key).hex())

    async def test_a_pinned_auto_publisher_is_enough(self, tmp_path):
        node = _node()
        one = CryptoIdentity()
        try:
            entry = await self._catalogued(node, one, _package(tmp_path, "a"))
            assert node.may_auto_install(entry)[0] is False
            node.trust_publisher(one.dsa_public_key.hex(), "one", auto=True)
            assert node.may_auto_install(entry)[0] is True
        finally:
            await node.stop()

    async def test_without_a_quorum_setting_endorsement_installs_nothing(
            self, tmp_path):
        """Off by default. An operator asks for this route deliberately: it is
        the setting that lets code install itself without a key pinned for it."""
        node = _node(quorum=0)
        package = _package(tmp_path, "a")
        try:
            entry = None
            for _ in range(3):
                identity = CryptoIdentity()
                node.trust_publisher(identity.dsa_public_key.hex(),
                                     endorsed=True)
                entry = await self._catalogued(node, identity, package)
            allowed, why = node.may_auto_install(entry)
            assert allowed is False
            assert "pinned for automatic install" in why
        finally:
            await node.stop()

    async def test_a_quorum_of_endorsed_publishers_installs(self, tmp_path):
        node = _node(quorum=3)
        package = _package(tmp_path, "a")
        try:
            entry = None
            for index in range(3):
                identity = CryptoIdentity()
                node.trust_publisher(identity.dsa_public_key.hex(),
                                     endorsed=True)
                entry = await self._catalogued(node, identity, package)
                allowed, _why = node.may_auto_install(entry)
                assert allowed is (index == 2)      # only once the third signs
        finally:
            await node.stop()

    async def test_two_hundred_unendorsed_publishers_reach_no_quorum(
            self, tmp_path):
        """The attack the endorsement list exists for. Minting publishers is as
        cheap as minting identities; being chosen by a human is not.

        Two bounds hold here, and the second is the one that matters: most of
        the two hundred never even reach the catalogue, because an untrusted
        publisher cannot evict anybody — and the handful that do fit still count
        for nothing, because none of them was endorsed."""
        node = _node(quorum=2)
        package = _package(tmp_path, "a")
        try:
            entry = await self._catalogued(node, CryptoIdentity(), package)
            for _ in range(200):
                await self._catalogued(node, CryptoIdentity(), package)
            assert len(node._releases) <= cr.MAX_CATALOG
            assert node._publishers.endorsed_among(
                node._releases.attesters(entry["version"],
                                         entry["sha256"])) == []
            assert node.may_auto_install(entry)[0] is False
        finally:
            await node.stop()

    async def test_a_disputed_version_is_never_installed_unattended(
            self, tmp_path):
        """Not an accusation — two honest publishers can disagree by accident,
        and the answer to that is the same as to an attack: stop and let a human
        look. Refusing an update is recoverable; installing a hostile one is
        not."""
        node = _node()
        honest, attacker = CryptoIdentity(), CryptoIdentity()
        try:
            node.trust_publisher(honest.dsa_public_key.hex(), auto=True)
            entry = await self._catalogued(node, honest,
                                           _package(tmp_path, "honest"))
            assert node.may_auto_install(entry)[0] is True
            await self._catalogued(node, attacker,
                                   _package(tmp_path, "theirs",
                                            marker="# not the code\n"))
            allowed, why = node.may_auto_install(entry)
            assert allowed is False
            assert "different content" in why
        finally:
            await node.stop()

    async def test_the_dispute_blocks_the_quorum_route_too(self, tmp_path):
        node = _node(quorum=2)
        package = _package(tmp_path, "a")
        try:
            for _ in range(2):
                identity = CryptoIdentity()
                node.trust_publisher(identity.dsa_public_key.hex(),
                                     endorsed=True)
                entry = await self._catalogued(node, identity, package)
            assert node.may_auto_install(entry)[0] is True
            await self._catalogued(node, CryptoIdentity(),
                                   _package(tmp_path, "b",
                                            marker="# not the code\n"))
            assert node.may_auto_install(entry)[0] is False
        finally:
            await node.stop()

    async def test_the_overview_shows_who_stands_behind_it(self, tmp_path):
        node = _node(quorum=2)
        package = _package(tmp_path, "a")
        try:
            endorsed = CryptoIdentity()
            node.trust_publisher(endorsed.dsa_public_key.hex(), endorsed=True)
            await self._catalogued(node, endorsed, package)
            await self._catalogued(node, CryptoIdentity(), package)
            overview = node.release_overview()
            assert overview["quorum"] == 2
            row = overview["releases"][0]
            assert row["attesters"] == 2
            assert row["endorsed_attesters"] == 1
            assert row["disputed"] is False
            assert row["unattended"] is False
        finally:
            await node.stop()


# ---------------------------------------------------------------------------
# The key that is not in memory
# ---------------------------------------------------------------------------

class TestPublisherKey:
    def _fast(self):
        """scrypt at its real cost is ~128 MiB per call. The tests exercise the
        format and the refusals, not the cost parameter — which is stored in the
        file precisely so it can differ."""
        return {"n": 1 << 8, "r": 8, "p": 1}

    def test_round_trip(self, tmp_path):
        path = str(tmp_path / "publisher.key")
        identity = CryptoIdentity()
        secret = identity._signer.export_secret_key()
        publisher_key.save(path, identity.dsa_public_key, secret, "correct horse",
                           **self._fast())
        public, unlocked = publisher_key.load(path, "correct horse")
        assert public == identity.dsa_public_key
        assert unlocked == secret

    def test_the_wrong_passphrase_does_not_open_it(self, tmp_path):
        path = str(tmp_path / "publisher.key")
        identity = CryptoIdentity()
        publisher_key.save(path, identity.dsa_public_key,
                           identity._signer.export_secret_key(), "right",
                           **self._fast())
        with pytest.raises(publisher_key.PublisherKeyError):
            publisher_key.load(path, "wrong")

    def test_an_altered_file_does_not_open_it(self, tmp_path):
        path = str(tmp_path / "publisher.key")
        identity = CryptoIdentity()
        publisher_key.save(path, identity.dsa_public_key,
                           identity._signer.export_secret_key(), "pass",
                           **self._fast())
        blob = bytearray(open(path, "rb").read())
        blob[-1] ^= 1
        open(path, "wb").write(bytes(blob))
        with pytest.raises(publisher_key.PublisherKeyError):
            publisher_key.load(path, "pass")

    def test_the_cost_parameters_cannot_be_lowered_in_place(self, tmp_path):
        """The header is the AAD, so the salt and the scrypt costs are under the
        tag: an attacker who can edit the file cannot weaken the derivation and
        hand it back to be opened cheaply."""
        path = str(tmp_path / "publisher.key")
        identity = CryptoIdentity()
        publisher_key.save(path, identity.dsa_public_key,
                           identity._signer.export_secret_key(), "pass",
                           **self._fast())
        blob = bytearray(open(path, "rb").read())
        blob[5] = 1                       # log2(n) → 2
        open(path, "wb").write(bytes(blob))
        with pytest.raises(publisher_key.PublisherKeyError):
            publisher_key.load(path, "pass")

    def test_the_public_half_needs_no_passphrase(self, tmp_path):
        """A publisher has to be able to say which key it is without unlocking
        anything — that answer is public by definition."""
        path = str(tmp_path / "publisher.key")
        identity = CryptoIdentity()
        publisher_key.save(path, identity.dsa_public_key,
                           identity._signer.export_secret_key(), "pass",
                           **self._fast())
        assert publisher_key.public_of(path) == identity.dsa_public_key

    def test_the_file_is_created_unreadable_to_others(self, tmp_path):
        path = str(tmp_path / "publisher.key")
        identity = CryptoIdentity()
        publisher_key.save(path, identity.dsa_public_key,
                           identity._signer.export_secret_key(), "pass",
                           **self._fast())
        assert oct(os.stat(path).st_mode & 0o777) == "0o600"

    @pytest.mark.parametrize("blob", [
        b"", b"NMPK", b"XXXX" + b"\x00" * 60, b"NMPK\x02" + b"\x00" * 60,
        b"NMPK\x01\x08\x00\x08\x00\x01" + b"\x00" * 40,
    ])
    def test_a_hostile_file_raises_nothing_else(self, tmp_path, blob):
        path = str(tmp_path / "publisher.key")
        open(path, "wb").write(blob)
        with pytest.raises(publisher_key.PublisherKeyError):
            publisher_key.load(path, "pass")

    def test_a_missing_file_says_so(self, tmp_path):
        with pytest.raises(publisher_key.PublisherKeyError):
            publisher_key.load(str(tmp_path / "nope"), "pass")

    def test_an_empty_passphrase_is_refused(self, tmp_path):
        path = str(tmp_path / "publisher.key")
        identity = CryptoIdentity()
        with pytest.raises(publisher_key.PublisherKeyError):
            publisher_key.save(path, identity.dsa_public_key,
                               identity._signer.export_secret_key(), "",
                               **self._fast())


class TestSigningWithIt:
    def test_a_mismatched_pair_is_refused(self):
        """It would sign things nobody can verify, and the only symptom would be
        a release the whole network quietly refuses."""
        a, b = CryptoIdentity(), CryptoIdentity()
        with pytest.raises(CryptoError):
            CryptoIdentity.from_pair(a.dsa_public_key,
                                     b._signer.export_secret_key())

    async def test_a_release_signed_by_the_locked_key_names_that_key(
            self, tmp_path):
        node = _node()
        path = str(tmp_path / "publisher.key")
        publisher = CryptoIdentity()
        publisher_key.save(path, publisher.dsa_public_key,
                           publisher._signer.export_secret_key(), "pass",
                           n=1 << 8, r=8, p=1)
        try:
            info = await node.publish_release(_tree(str(tmp_path / "tree")),
                                              key_path=path, passphrase="pass")
            assert info["publisher_key"] == publisher.dsa_public_key.hex()
            assert info["publisher_id"] == cr.publisher_id(
                publisher.dsa_public_key).hex()
            # …and it is *not* the node's own key, which is the whole point.
            assert info["publisher_key"] != node._identity.dsa_public_key.hex()
        finally:
            await node.stop()

    async def test_the_wrong_passphrase_publishes_nothing(self, tmp_path):
        node = _node()
        path = str(tmp_path / "publisher.key")
        publisher = CryptoIdentity()
        publisher_key.save(path, publisher.dsa_public_key,
                           publisher._signer.export_secret_key(), "right",
                           n=1 << 8, r=8, p=1)
        try:
            with pytest.raises(cr.ReleaseError):
                await node.publish_release(_tree(str(tmp_path / "tree")),
                                           key_path=path, passphrase="wrong")
        finally:
            await node.stop()


def cr_verify():
    """The module-level verifier, as `parse_release` wants it."""
    from src.crypto import verify_signature
    return verify_signature
