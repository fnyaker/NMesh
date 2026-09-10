"""
The package directory across a real mesh: publish here, find it there by name.

This is the flow that replaced two things at once. A node's own code used to be
discoverable only by gossip, and pinning its publisher meant an operator copying
a hex key across from somewhere. Third-party apps used to live in a gossiped
catalogue every node carried whether it wanted it or not — a list, which is a
thing to flood.

Now nothing is listed. A publisher files a signed record under its own key and
under its name's prefixes, and a reader asks a question: *this* name, or *that*
node. What comes back carries the publisher's key, so pinning is a confirmation
rather than a transcription.

Excluded from the default suite (see the pyproject addopts); run it explicitly:
    pytest tests/integration/test_pkg_dir.py -q
"""
import asyncio
import os

import pytest

from src import core_release as cr
from src import pkg_dir
from src import updater
from src.node import MeshNode
from src.transport_manager import TransportManager
from src.tcp_transport import TCPTransport, TCPServer


def _mgr() -> TransportManager:
    mgr = TransportManager()
    mgr.register("tcp", TCPTransport, TCPServer)
    return mgr


def _tree(root: str, version: str, note: str = "# the code\n") -> str:
    os.makedirs(os.path.join(root, "src"), exist_ok=True)
    with open(os.path.join(root, "src", "version.py"), "w") as handle:
        handle.write(f'__version__ = "{version}"\n')
    with open(os.path.join(root, "src", "node.py"), "w") as handle:
        handle.write(note)
    with open(os.path.join(root, "start.sh"), "w") as handle:
        handle.write("#!/bin/sh\necho hi\n")
    return root


async def _pair(port: int, state=None) -> tuple[MeshNode, MeshNode]:
    """Two joined nodes. ``state`` gives each one a directory, which is what a
    node needs before it can keep a publisher key at all."""
    dirs = ({"release_dir": os.path.join(str(state), "a")},
            {"release_dir": os.path.join(str(state), "b")}) if state else ({}, {})
    publisher, node = MeshNode(_mgr(), **dirs[0]), MeshNode(_mgr(), **dirs[1])
    code = publisher.generate_invite()
    await publisher.start([f"tcp://127.0.0.1:{port}"])
    await node.join(f"tcp://127.0.0.1:{port}", code)
    await node.wait_for_session(timeout=15.0)
    await publisher.wait_for_session(timeout=15.0)
    await publisher.bootstrap()
    await node.bootstrap()
    return publisher, node


async def _until(predicate, timeout=20.0):
    deadline = asyncio.get_event_loop().time() + timeout
    while asyncio.get_event_loop().time() < deadline:
        if predicate():
            return True
        await asyncio.sleep(0.1)
    return predicate()


class TestFindingAPackage:
    async def test_a_release_is_found_by_a_partial_name(self, tmp_path):
        publisher, node = await _pair(19400)
        try:
            await publisher.publish_release(
                _tree(str(tmp_path / "tree"), "9.9.9"),
                notes="a couple of lines about what changed")
            await publisher._publish_package_records()

            # The reader has never heard of this key, and types three letters.
            found = await node.search_packages("nme")
            assert found, "the directory answered nothing"
            entry = found[0]
            assert entry["name"] == cr.PROJECT_NAME
            assert entry["version"] == "9.9.9"
            assert entry["notes"].startswith("a couple of lines")
            assert entry["kind"] == "core"
            assert entry["trusted"] is False   # found is not trusted
        finally:
            await node.stop(); await publisher.stop()

    async def test_a_node_id_says_what_that_node_publishes(self, tmp_path):
        """The details page's question: I am looking at this machine — does it
        offer anything?"""
        publisher, node = await _pair(19401)
        try:
            await publisher.publish_release(_tree(str(tmp_path / "tree"), "9.9.9"))
            await publisher._publish_package_records()
            offered = await node.packages_of(publisher.id)
            assert [row["version"] for row in offered] == ["9.9.9"]
            assert offered[0]["node_id"] == publisher.id.raw.hex()
            assert offered[0]["published"] is True
        finally:
            await node.stop(); await publisher.stop()

    async def test_the_key_arrives_with_the_thing_it_signed(self, tmp_path,
                                                            monkeypatch):
        """The whole point of replacing the pasted hex key: the record carries
        the publisher's key, checked against the signature it made."""
        publisher, node = await _pair(19402)
        try:
            await publisher.publish_release(_tree(str(tmp_path / "tree"), "9.9.9"))
            await publisher._publish_package_records()
            entry = (await node.search_packages("nmesh"))[0]

            assert node._publishers.trusts(
                publisher._identity.dsa_public_key) is False
            pinned = node.trust_package_signer(entry["id"])
            assert pinned["key"] == publisher._identity.dsa_public_key.hex()
            assert node._publishers.trusts(
                publisher._identity.dsa_public_key) is True

            # …and the release is then installable, end to end, with the
            # descriptor pulled off the DHT rather than gossiped at us.
            node._releases = type(node._releases)()      # forget the gossip
            applied = {}

            async def fake_apply(files, version, **kwargs):
                applied.update({"files": files, "version": version})
                return {"applied": version, "restart_required": True}

            monkeypatch.setattr(updater, "apply_files", fake_apply)
            result = await node.install_package(entry["id"])
            assert result["version"] == "9.9.9"
            assert applied["files"]["src/version.py"] == b'__version__ = "9.9.9"\n'
        finally:
            await node.stop(); await publisher.stop()

    async def test_a_package_can_be_downloaded_whole(self, tmp_path):
        """An operator who wants to open the archive by hand before trusting
        anybody gets the bytes the publisher signed, and nothing else."""
        publisher, node = await _pair(19403)
        try:
            await publisher.publish_release(_tree(str(tmp_path / "tree"), "9.9.9"))
            await publisher._publish_package_records()
            entry = (await node.search_packages("nmesh"))[0]
            fetched = await node.fetch_package(entry["id"])
            assert fetched is not None
            _entry, blob, name = fetched
            assert name == "nmesh-9.9.9.tar.gz"
            assert cr.version_of(cr.open_package(blob)) == "9.9.9"
        finally:
            await node.stop(); await publisher.stop()

    async def test_an_app_is_found_the_same_way(self, tmp_path):
        """Third-party apps take exactly the path a release takes. There is no
        store, so there is no list to flood."""
        publisher, node = await _pair(19404)
        try:
            await publisher.publish_store_app(
                "Sketchpad", "2.0.0", {"main.py": b"print('draw')\n"},
                notes="draws things")
            await publisher._publish_package_records()
            found = await node.search_packages("sketch")
            assert [row["name"] for row in found] == ["Sketchpad"]
            assert found[0]["kind"] == "app"
            assert found[0]["notes"] == "draws things"

            installed = await node.install_package(found[0]["id"])
            assert installed["name"] == "Sketchpad"
            assert node._installed.is_installed(installed["app_id"])
        finally:
            await node.stop(); await publisher.stop()


class TestCorroboration:
    async def test_two_publishers_of_one_source_agree(self, tmp_path):
        """"Put X packages in competition": two keys that built the same code
        agree, even when their release notes differ — the digest ignores
        documentation, and nothing had to be downloaded to compare them."""
        publisher, node = await _pair(19405)
        second = MeshNode(_mgr())
        try:
            tree = _tree(str(tmp_path / "tree"), "9.9.9")
            with open(os.path.join(tree, "README.md"), "w") as handle:
                handle.write("one publisher's words\n")
            await publisher.publish_release(tree, notes="from the first")
            await publisher._publish_package_records()

            with open(os.path.join(tree, "README.md"), "w") as handle:
                handle.write("a completely different readme\n")
            await second.publish_release(tree, notes="from the second")

            # The second node's record reaches the reader by hand here: what is
            # under test is the agreement, not the carriage.
            for raw in second._package_records.values():
                record = pkg_dir.parse_record(raw, node._identity.verify)
                node._package_book.offer(record, raw)

            entry = next(row for row in await node.search_packages("nmesh")
                         if row["node_id"] == publisher.id.raw.hex())
            assert entry["attesters"] == 2
        finally:
            await second.stop(); await node.stop(); await publisher.stop()

    async def test_different_code_does_not_agree(self, tmp_path):
        publisher, node = await _pair(19406)
        second = MeshNode(_mgr())
        try:
            await publisher.publish_release(
                _tree(str(tmp_path / "a"), "9.9.9", "# the code\n"))
            await second.publish_release(
                _tree(str(tmp_path / "b"), "9.9.9", "# something else\n"))
            await publisher._publish_package_records()
            for raw in second._package_records.values():
                record = pkg_dir.parse_record(raw, node._identity.verify)
                node._package_book.offer(record, raw)
            entry = next(row for row in await node.search_packages("nmesh")
                         if row["node_id"] == publisher.id.raw.hex())
            assert entry["attesters"] == 1
        finally:
            await second.stop(); await node.stop(); await publisher.stop()

    async def test_two_watched_publishers_of_one_source_satisfy_a_quorum(
            self, tmp_path):
        """The other half: with both watched and both carrying the same code,
        the quorum is met and the hold comes off."""
        publisher, node = await _pair(19411)
        second = MeshNode(_mgr())
        try:
            tree = _tree(str(tmp_path / "tree"), "9.9.9")
            await publisher.publish_release(tree, notes="from the first")
            await second.publish_release(tree, notes="from the second")
            await publisher._publish_package_records()
            for raw in second._package_records.values():
                record = pkg_dir.parse_record(raw, node._identity.verify)
                node._package_book.offer(record, raw)

            # A quorum counts keys the operator endorsed one at a time: a
            # signature from somebody nobody chose is a party an attacker can
            # mint, and that is the whole reason the number means anything.
            for row in await node.search_packages("nmesh"):
                node.trust_package_signer(row["id"], endorsed=True)
            node.subscribe_package(
                (await node.packages_of(publisher.id))[0]["id"], quorum=2)
            entry = node._package_book.entry(bytes.fromhex(
                (await node.packages_of(publisher.id))[0]["id"]))
            assert node._package_agreement(entry) == (2, 2)
        finally:
            await second.stop(); await node.stop(); await publisher.stop()

    async def test_a_subscription_holds_back_until_enough_agree(self, tmp_path):
        """A quorum only ever withholds. Set it to two with one publisher
        watched, and the automatic install does not happen."""
        publisher, node = await _pair(19407)
        try:
            await publisher.publish_release(_tree(str(tmp_path / "tree"), "9.9.9"))
            await publisher._publish_package_records()
            entry = (await node.search_packages("nmesh"))[0]
            node.trust_package_signer(entry["id"], auto=True, endorsed=True)
            node.subscribe_package(entry["id"], auto=True, quorum=2)

            record = node._package_book.entry(bytes.fromhex(entry["id"]))
            agreeing, needed = node._package_agreement(record)
            assert (agreeing, needed) == (1, 2)

            installs = []
            node.install_release_entry = lambda *a, **k: installs.append(a)
            await node._subscribed_install_pass()
            assert installs == []
        finally:
            await node.stop(); await publisher.stop()


class TestADetachedPublisherKey:
    """A release signed with a key that is not the node's identity.

    This used to need a second artefact — a two-halved pairing — because records
    were filed under the *publisher key*, which names a machine only by
    coincidence and names nothing at all once the key is detached. Now the node
    signs the record and the key co-signs a proof naming that node, so one
    record says both things and one lookup finds it."""

    def _key(self, path):
        from src import publisher_key
        from src.crypto import CryptoIdentity
        identity = CryptoIdentity()
        publisher_key.save(path, identity.dsa_public_key,
                           identity._signer.export_secret_key(), "pass",
                           n=2 ** 8, r=8, p=1)
        return identity.dsa_public_key

    async def test_a_node_id_finds_it_with_no_second_artefact(self, tmp_path):
        publisher, node = await _pair(19412)
        try:
            path = str(tmp_path / "publisher.key")
            public = self._key(path)
            await publisher.publish_release(_tree(str(tmp_path / "tree"), "9.9.9"),
                                            key_path=path, passphrase="pass")
            await publisher._publish_package_records()

            offered = await node.packages_of(publisher.id)
            assert [row["version"] for row in offered] == ["9.9.9"]
            # The record is the machine's own sentence about itself…
            assert offered[0]["node_id"] == publisher.id.raw.hex()
            # …and it names the key the release was signed with, proved.
            assert offered[0]["published"] is True
            assert offered[0]["signer"] == public.hex()
            assert offered[0]["signer_id"] != publisher.id.raw.hex()
        finally:
            await node.stop(); await publisher.stop()

    async def test_a_node_cannot_put_a_strangers_package_on_its_own_page(
            self, tmp_path):
        """The property the pairing existed to protect, now free: a record can
        only be filed under the node that signed it."""
        publisher, node = await _pair(19413)
        stranger = MeshNode(_mgr())
        try:
            await stranger.publish_release(_tree(str(tmp_path / "tree"), "9.9.9"))
            for raw in stranger._package_records.values():
                record = pkg_dir.parse_record(raw, node._identity.verify)
                node._package_book.offer(record, raw)

            assert await node.packages_of(publisher.id, wide=False) == []
            theirs = await node.packages_of(stranger.id, wide=False)
            assert [row["node_id"] for row in theirs] == [stranger.id.raw.hex()]
        finally:
            await stranger.stop(); await node.stop(); await publisher.stop()

    async def test_the_key_pinned_is_the_key_that_signed_the_release(
            self, tmp_path, monkeypatch):
        publisher, node = await _pair(19414)
        try:
            path = str(tmp_path / "publisher.key")
            public = self._key(path)
            await publisher.publish_release(_tree(str(tmp_path / "tree"), "9.9.9"),
                                            key_path=path, passphrase="pass")
            await publisher._publish_package_records()
            entry = (await node.packages_of(publisher.id))[0]
            assert node.trust_package_signer(entry["id"])["key"] == public.hex()

            applied = {}

            async def fake_apply(files, version, **kwargs):
                applied.update({"version": version})
                return {"applied": version, "restart_required": True}

            monkeypatch.setattr(updater, "apply_files", fake_apply)
            assert (await node.install_package(entry["id"]))["version"] == "9.9.9"
            assert applied["version"] == "9.9.9"
        finally:
            await node.stop(); await publisher.stop()


class TestHandingAPublisherKeyOver:
    """A private signing key crossing a real mesh, and being published with on
    the other side. The transfer is three routed messages; what makes it safe
    is that the middle one only exists because a human accepted."""

    async def test_a_key_crosses_and_the_recipient_publishes_with_it(
            self, tmp_path):
        alice, bob = await _pair(19415, tmp_path / "state")
        try:
            row = alice.create_publisher_key("alice pass", label="release key")
            offer = await alice.offer_publisher_key(
                bob.id, alice.publisher_key_path(row["id"]), "alice pass",
                label="release key")

            # The offer travels on its own; Bob's operator sees it and accepts.
            assert await _until(
                lambda: bool(bob.key_share_overview()["incoming"]), timeout=20.0)
            waiting = bob.key_share_overview()["incoming"][0]
            assert waiting["key_id"] == row["id"]
            assert waiting["from"] == alice.id.raw.hex()

            await bob.accept_publisher_key(offer["offer_id"], "bob pass")
            assert await _until(
                lambda: bool(bob.key_share_overview()["keys"]), timeout=20.0)
            held = bob.key_share_overview()["keys"][0]
            assert held["id"] == row["id"]
            assert held["received_from"] == alice.id.raw.hex()

            # …and Bob can now publish under it. The record names that key, so
            # anybody who pinned it accepts what Bob signs.
            info = await bob.publish_release(
                _tree(str(tmp_path / "tree"), "9.9.9"),
                key_path=bob.publisher_key_path(row["id"]),
                passphrase="bob pass", notes="published by the other one")
            assert info["publisher_id"] == row["id"]
            await bob._publish_package_records()
            found = await alice.search_packages("nmesh")
            assert [entry["signer_id"] for entry in found] == [row["id"]]
            # …and the record is bob's own sentence about bob's machine, even
            # though the key that signed the release came from alice.
            assert found[0]["node_id"] == bob.id.raw.hex()
        finally:
            await bob.stop(); await alice.stop()

    async def test_a_refused_offer_leaves_nothing_behind(self, tmp_path):
        alice, bob = await _pair(19416, tmp_path / "state")
        try:
            row = alice.create_publisher_key("alice pass")
            offer = await alice.offer_publisher_key(
                bob.id, alice.publisher_key_path(row["id"]), "alice pass")
            assert await _until(
                lambda: bool(bob.key_share_overview()["incoming"]), timeout=20.0)
            assert bob.refuse_publisher_key(offer["offer_id"]) is True

            # Nothing arrives, and Alice's copy expires rather than being told:
            # a refusal that answered would tell whoever asked that this node is
            # here and listening.
            await asyncio.sleep(0.5)
            assert bob.key_share_overview()["keys"] == []
            assert alice.key_share_overview()["outgoing"], "the offer stands"
        finally:
            await bob.stop(); await alice.stop()


class TestRecommendingIsServing:
    """The sentence a node signs is "I hold this and I serve it", so the set of
    records under a release **is** the set of machines that can hand it over.
    That is the whole of how a fetch works through routing with no publisher to
    fall back on."""

    async def test_a_recommendation_is_found_by_the_release_it_names(
            self, tmp_path):
        publisher, node = await _pair(19417)
        try:
            info = await publisher.publish_release(
                _tree(str(tmp_path / "tree"), "9.9.9"))
            await publisher._publish_package_records()

            holders = await node.package_holders(bytes.fromhex(info["release"]))
            assert holders == [publisher.id]
        finally:
            await node.stop(); await publisher.stop()

    async def test_the_holders_are_where_a_fetch_looks(self, tmp_path):
        """No hint, no announce that reached us, no publisher fallback — the
        directory is what says who has the bytes."""
        publisher, node = await _pair(19418)
        try:
            info = await publisher.publish_release(
                _tree(str(tmp_path / "tree"), "9.9.9"))
            await publisher._publish_package_records()
            node._release_sources.clear()
            node._peers = []          # nothing to ask but the directory

            entry = node._releases.get(info["release"])
            if entry is None:
                entry = await node.package_release(
                    (await node.search_packages("nmesh"))[0]["id"])
            assert publisher.id in await node._release_sources_for(entry)
        finally:
            await node.stop(); await publisher.stop()

    async def test_installing_makes_this_node_a_source_too(self, tmp_path):
        """Everyone who installed it is somewhere the next node can get it.
        This is what replaces "ask the publisher, they will always have it"."""
        publisher, node = await _pair(19419)
        try:
            await publisher.publish_store_app(
                "Sketchpad", "1.0.0", {"main.py": b"print('hi')\n"})
            await publisher._publish_package_records()
            entry = (await node.search_packages("sketch"))[0]

            await node.install_package(entry["id"])

            ours = await node.packages_of(node.id, wide=False)
            assert [row["name"] for row in ours] == ["Sketchpad"]
            assert ours[0]["published"] is False      # we hold it, we did not sign it
            assert bytes.fromhex(ours[0]["release"]) == \
                bytes.fromhex(entry["release"])
        finally:
            await node.stop(); await publisher.stop()


class TestARecordSaysNothingAboutTrust:
    async def test_a_node_that_only_serves_carries_no_key_to_pin(self, tmp_path):
        """Pinning whoever handed you a copy would hand the machine to a
        mirror. A record without the publication proof carries no key at all,
        which is the refusal rather than a check somebody could forget."""
        from src.version import __version__ as running
        publisher, node = await _pair(19408)
        stranger = MeshNode(_mgr())
        try:
            # The publisher runs a version somebody else signed: it holds the
            # release and offers to serve it, and that is all it says.
            blob = (await stranger.publish_release(
                _tree(str(tmp_path / "tree"), running)))
            descriptor = stranger._releases.get(blob["release"])["release"]
            publisher._releases.offer(descriptor, publisher._identity.verify,
                                      publisher._trusts_publisher)
            publisher._recommend_version = True
            await publisher._recommend_pass()
            await publisher._publish_package_records()

            offered = await node.packages_of(publisher.id)
            assert offered and offered[0]["published"] is False
            assert offered[0]["signer"] is None
            with pytest.raises(Exception, match="did not sign"):
                node.trust_package_signer(offered[0]["id"])
        finally:
            await stranger.stop(); await node.stop(); await publisher.stop()

    async def test_a_recommendation_points_at_a_descriptor_that_resolves(
            self, tmp_path):
        """A pointer at a package id is a pointer nothing can follow: `dht_get`
        resolves descriptors, and the package moves on the release transfer."""
        from src.version import __version__ as running
        publisher, node = await _pair(19410)
        try:
            # A node recommends the version it *runs*, so the release it points
            # at has to be that one.
            await publisher.publish_release(_tree(str(tmp_path / "tree"), running))
            publisher._recommend_version = True
            await publisher._recommend_pass()
            await publisher._publish_package_records()
            offered = await node.packages_of(publisher.id)
            assert offered, "nothing was recommended"
            described = await node.package_descriptor(offered[0]["id"])
            assert described is not None and described["version"] == running
            # …and it says something about the code, which is the whole worth of
            # a recommendation: a second party running these exact bytes.
            assert offered[0]["src"] != "00" * 32
        finally:
            await node.stop(); await publisher.stop()

    async def test_finding_a_release_does_not_make_it_installable(self, tmp_path):
        publisher, node = await _pair(19409)
        try:
            await publisher.publish_release(_tree(str(tmp_path / "tree"), "9.9.9"))
            await publisher._publish_package_records()
            entry = (await node.search_packages("nmesh"))[0]
            assert entry["trusted"] is False
            with pytest.raises(Exception, match="not trusted"):
                await node.install_package(entry["id"])
        finally:
            await node.stop(); await publisher.stop()
