"""
Mesh-native releases: the signed descriptor, the pins, the catalogue.

This is the module that decides what may replace the node's own code, so the
tests are mostly about what it must **refuse**: a forged or lifted signature, a
release that announces one version and carries another, a replayed old release,
a flood of strangers trying to crowd out the publisher an operator pinned, and a
trust file that has been tampered with.

Nothing here touches the network — the mesh half lives in `test_release_mesh.py`.
"""
import json
import os
import time

import pytest

from src import core_release as cr
from src.app_package import build_release as build_app_release
from src.crypto import CryptoIdentity


def _release(identity, version="0.2.0", ts=1000, notes="",
             root=b"\x11" * 20, sha="a" * 64):
    return cr.build_release(root, sha, version, identity.dsa_public_key,
                            identity.sign, ts, notes)


class TestTheDescriptor:
    def test_a_signed_release_reads_back(self):
        idn = CryptoIdentity()
        doc = cr.parse_release(_release(idn, notes="hello"), idn.verify)
        assert doc["version"] == "0.2.0"
        assert doc["notes"] == "hello"
        assert doc["publisher"] == idn.dsa_public_key
        assert doc["publisher_id"] == cr.publisher_id(idn.dsa_public_key)

    def test_the_publisher_id_follows_from_the_key(self):
        """There is no id to lie about: it is derived, never carried."""
        idn = CryptoIdentity()
        doc = cr.parse_release(_release(idn), idn.verify)
        assert doc["publisher_id"] == cr.publisher_id(doc["publisher"])

    def test_a_tampered_field_breaks_the_signature(self):
        idn = CryptoIdentity()
        blob = _release(idn)
        doc = json.loads(blob)
        doc["version"] = "9.9.9"
        with pytest.raises(cr.ReleaseError):
            cr.parse_release(json.dumps(doc).encode(), idn.verify)

    def test_a_tampered_root_breaks_the_signature(self):
        """The root is the whole point: change it and you change the code."""
        idn = CryptoIdentity()
        doc = json.loads(_release(idn))
        doc["root_key"] = (b"\x22" * 20).hex()
        with pytest.raises(cr.ReleaseError):
            cr.parse_release(json.dumps(doc).encode(), idn.verify)

    def test_another_key_cannot_sign_for_this_publisher(self):
        idn, other = CryptoIdentity(), CryptoIdentity()
        doc = json.loads(_release(idn))
        doc["publisher"] = other.dsa_public_key.hex()
        with pytest.raises(cr.ReleaseError):
            cr.parse_release(json.dumps(doc).encode(), idn.verify)

    def test_an_app_release_is_not_a_core_release(self):
        """The same ML-DSA key signs app releases, certificates and handshakes.
        A shared domain would let one be replayed as another; this one is its
        own, so an app descriptor cannot become a code update."""
        idn = CryptoIdentity()
        blob, _app_id = build_app_release(b"\x11" * 20, "a" * 64, "widget",
                                          "0.2.0", idn.dsa_public_key,
                                          idn.sign, 1000)
        with pytest.raises(cr.ReleaseError):
            cr.parse_release(blob, idn.verify)

    def test_a_signature_over_the_same_fields_in_another_domain_is_refused(self):
        idn = CryptoIdentity()
        body = json.loads(_release(idn))
        payload = json.dumps({k: body[k] for k in cr._RELEASE_KEYS},
                             sort_keys=True).encode()
        body["sig"] = idn.sign(b"some-other-domain-v1" + payload).hex()
        with pytest.raises(cr.ReleaseError):
            cr.parse_release(json.dumps(body).encode(), idn.verify)

    def test_building_refuses_an_unusable_version_or_root(self):
        idn = CryptoIdentity()
        with pytest.raises(cr.ReleaseError):
            cr.build_release(b"\x11" * 20, "a" * 64, "", idn.dsa_public_key,
                             idn.sign)
        with pytest.raises(cr.ReleaseError):
            cr.build_release(b"\x11" * 3, "a" * 64, "1.0.0",
                             idn.dsa_public_key, idn.sign)
        with pytest.raises(cr.ReleaseError):
            cr.build_release(b"\x11" * 20, "short", "1.0.0",
                             idn.dsa_public_key, idn.sign)

    def test_notes_are_bounded_at_signing_time(self):
        idn = CryptoIdentity()
        doc = cr.parse_release(_release(idn, notes="x" * 10_000), idn.verify)
        assert len(doc["notes"]) == cr.MAX_NOTES_LEN

    @pytest.mark.parametrize("blob", [
        b"", b"{", b"[]", b"null", b"not json at all",
        json.dumps({"v": 2}).encode(),
        json.dumps({"v": 1, "version": "1.0.0"}).encode(),
        json.dumps({"v": 1, "version": "1.0.0", "root_key": "zz",
                    "root_sha256": "a" * 64, "publisher": "aa",
                    "sig": "bb", "ts": 1}).encode(),
        json.dumps({"v": 1, "version": "1.0.0", "root_key": "11" * 20,
                    "root_sha256": "a" * 64, "publisher": "aa",
                    "sig": "bb", "ts": "soon"}).encode(),
        b"x" * 200_000,
    ])
    def test_hostile_blobs_raise_nothing_but_release_error(self, blob):
        idn = CryptoIdentity()
        with pytest.raises(cr.ReleaseError):
            cr.parse_release(blob, idn.verify)

    def test_random_bytes_never_raise_anything_else(self):
        idn = CryptoIdentity()
        for _ in range(200):
            with pytest.raises(cr.ReleaseError):
                cr.parse_release(os.urandom(64), idn.verify)


class TestTheVersionCannotLie:
    def test_the_tree_names_its_own_version(self):
        files = {"src/version.py": b'__version__ = "1.4.2"\n'}
        assert cr.version_of(files) == "1.4.2"

    def test_a_tree_with_no_readable_version_is_refused(self):
        for files in ({}, {"src/version.py": b"nothing here"},
                      {"src/version.py": b"\xff\xfe binary"}):
            with pytest.raises(cr.ReleaseError):
                cr.check_tree({**files, "start.sh": b"#!/bin/sh\n"}, "1.0.0")

    def test_announcing_one_version_and_carrying_another_is_refused(self):
        """Otherwise the signed version is decoration: a publisher could
        announce 9.9.9 and ship anything at all."""
        files = {"src/version.py": b'__version__ = "0.1.0"\n',
                 "start.sh": b"#!/bin/sh\n"}
        with pytest.raises(cr.ReleaseError) as failure:
            cr.check_tree(files, "9.9.9")
        assert "announces 9.9.9" in str(failure.value)
        cr.check_tree(files, "0.1.0")

    def test_a_release_without_the_pieces_that_make_a_node_is_refused(self):
        with pytest.raises(cr.ReleaseError):
            cr.check_tree({"src/version.py": b'__version__ = "1.0.0"\n'}, "1.0.0")


class TestReadingATree:
    def _tree(self, tmp_path, version="0.1.0"):
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "version.py").write_text(
            f'__version__ = "{version}"\n')
        (tmp_path / "src" / "node.py").write_text("code\n")
        (tmp_path / "start.sh").write_text("#!/bin/sh\n")
        return tmp_path

    def test_it_reads_what_a_release_is_made_of(self, tmp_path):
        files = cr.read_tree(str(self._tree(tmp_path)))
        assert files["src/node.py"] == b"code\n"
        assert cr.version_of(files) == "0.1.0"

    def test_state_caches_and_the_virtualenv_never_travel(self, tmp_path):
        root = self._tree(tmp_path)
        (root / "data").mkdir()
        (root / "data" / "node.key").write_text("IDENTITY")
        (root / ".venv").mkdir()
        (root / ".venv" / "marker").write_text("venv")
        (root / "src" / "__pycache__").mkdir()
        (root / "src" / "__pycache__" / "node.pyc").write_text("bytecode")
        files = cr.read_tree(str(root))
        assert not [p for p in files if "data/" in p or ".venv" in p]
        assert not [p for p in files if p.endswith(".pyc")]

    def test_a_symlink_is_not_carried(self, tmp_path):
        """A release is regular files. A link is a way of pointing the
        extraction at something it was never meant to write."""
        root = self._tree(tmp_path)
        outside = tmp_path.parent / "secret.txt"
        outside.write_text("not yours")
        os.symlink(str(outside), str(root / "src" / "link.py"))
        files = cr.read_tree(str(root))
        assert "src/link.py" not in files

    def test_a_directory_that_is_not_a_node_is_refused(self, tmp_path):
        (tmp_path / "README.md").write_text("hello")
        with pytest.raises(cr.ReleaseError):
            cr.read_tree(str(tmp_path))

    def test_an_oversized_tree_is_refused_rather_than_read(self, tmp_path,
                                                           monkeypatch):
        root = self._tree(tmp_path)
        (root / "src" / "big.py").write_bytes(b"x" * 4096)
        monkeypatch.setattr(cr, "MAX_TREE_BYTES", 1024)
        with pytest.raises(cr.ReleaseError):
            cr.read_tree(str(root))


class TestPinnedPublishers:
    def test_a_pin_is_keyed_by_the_hash_of_the_key(self):
        idn = CryptoIdentity()
        pins = cr.TrustedPublishers()
        entry = pins.add(idn.dsa_public_key, "me")
        assert entry["id"] == cr.publisher_id(idn.dsa_public_key).hex()
        assert pins.trusts(idn.dsa_public_key)
        assert not pins.trusts(CryptoIdentity().dsa_public_key)

    def test_re_pinning_updates_rather_than_duplicates(self):
        idn = CryptoIdentity()
        pins = cr.TrustedPublishers()
        pins.add(idn.dsa_public_key, "first")
        pins.add(idn.dsa_public_key, "second")
        assert len(pins) == 1
        assert pins.list()[0]["name"] == "second"

    def test_trusting_is_not_auto_installing(self):
        """Two decisions, taken separately: one says whose code we accept, the
        other hands them a restart."""
        idn = CryptoIdentity()
        pins = cr.TrustedPublishers()
        entry = pins.add(idn.dsa_public_key, "me")
        assert entry["auto"] is False
        assert pins.auto_for(idn.dsa_public_key) is False
        assert pins.set_auto(entry["id"], True) is True
        assert pins.auto_for(idn.dsa_public_key) is True

    def test_removing_a_pin_stops_the_trust(self):
        idn = CryptoIdentity()
        pins = cr.TrustedPublishers()
        entry = pins.add(idn.dsa_public_key)
        assert pins.remove(entry["id"]) is True
        assert pins.remove(entry["id"]) is False
        assert not pins.trusts(idn.dsa_public_key)

    def test_the_list_is_bounded(self):
        pins = cr.TrustedPublishers(max_publishers=2)
        for _ in range(2):
            pins.add(CryptoIdentity().dsa_public_key)
        with pytest.raises(cr.ReleaseError):
            pins.add(CryptoIdentity().dsa_public_key)

    def test_an_unusable_key_is_refused(self):
        pins = cr.TrustedPublishers()
        for bad in (b"", None, "not bytes"):
            with pytest.raises(cr.ReleaseError):
                pins.add(bad)

    def test_pins_survive_a_restart(self, tmp_path):
        path = str(tmp_path / "publishers.json")
        idn = CryptoIdentity()
        first = cr.TrustedPublishers(path)
        first.add(idn.dsa_public_key, "me", auto=True)
        again = cr.TrustedPublishers(path)
        assert again.trusts(idn.dsa_public_key)
        assert again.auto_for(idn.dsa_public_key) is True

    def test_the_file_is_owner_only(self, tmp_path):
        """It holds no secret, but it decides what may replace this node's
        code — not something to leave writable by everyone."""
        import stat
        path = str(tmp_path / "publishers.json")
        pins = cr.TrustedPublishers(path)
        pins.add(CryptoIdentity().dsa_public_key)
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o600

    def test_a_corrupt_file_trusts_nobody(self, tmp_path):
        """Failing closed costs a re-pin. Failing open costs the machine."""
        path = tmp_path / "publishers.json"
        for junk in ("", "[]", "not json", '{"a": 1}'):
            path.write_text(junk)
            assert len(cr.TrustedPublishers(str(path))) == 0

    def test_an_entry_whose_id_does_not_follow_from_its_key_is_dropped(self,
                                                                      tmp_path):
        """A doctored file cannot slip a publisher in under a familiar id."""
        idn, other = CryptoIdentity(), CryptoIdentity()
        path = tmp_path / "publishers.json"
        path.write_text(json.dumps({
            cr.publisher_id(idn.dsa_public_key).hex(): {
                "key": other.dsa_public_key.hex(), "name": "trusted?"},
        }))
        pins = cr.TrustedPublishers(str(path))
        assert len(pins) == 0
        assert not pins.trusts(other.dsa_public_key)

    def test_a_stored_list_is_bounded_on_load(self, tmp_path):
        path = tmp_path / "publishers.json"
        stored = {}
        for _ in range(6):
            key = CryptoIdentity().dsa_public_key
            stored[cr.publisher_id(key).hex()] = {"key": key.hex()}
        path.write_text(json.dumps(stored))
        assert len(cr.TrustedPublishers(str(path), max_publishers=3)) == 3


class TestTheCatalogue:
    def test_a_release_is_kept_and_worth_gossiping_once(self):
        idn = CryptoIdentity()
        catalogue = cr.ReleaseCatalog()
        blob = _release(idn)
        assert catalogue.offer(blob, idn.verify) == "new"
        assert catalogue.offer(blob, idn.verify) is None      # epidemic stops
        assert catalogue.list()[0]["version"] == "0.2.0"

    def test_a_newer_signed_release_supersedes(self):
        idn = CryptoIdentity()
        catalogue = cr.ReleaseCatalog()
        catalogue.offer(_release(idn, "0.2.0", ts=1000), idn.verify)
        assert catalogue.offer(_release(idn, "0.3.0", ts=2000),
                               idn.verify) == "updated"
        assert catalogue.list()[0]["version"] == "0.3.0"

    def test_replaying_an_older_one_cannot_walk_us_back(self):
        idn = CryptoIdentity()
        catalogue = cr.ReleaseCatalog()
        old = _release(idn, "0.2.0", ts=1000)
        catalogue.offer(_release(idn, "0.3.0", ts=2000), idn.verify)
        assert catalogue.offer(old, idn.verify) is None
        assert catalogue.list()[0]["version"] == "0.3.0"

    def test_one_entry_per_publisher_not_per_release(self):
        first, second = CryptoIdentity(), CryptoIdentity()
        catalogue = cr.ReleaseCatalog()
        catalogue.offer(_release(first), first.verify)
        catalogue.offer(_release(second), second.verify)
        assert len(catalogue) == 2

    def test_an_unsigned_or_forged_release_is_never_stored(self):
        idn = CryptoIdentity()
        catalogue = cr.ReleaseCatalog()
        assert catalogue.offer(b"garbage", idn.verify) is None
        assert catalogue.offer(os.urandom(200), idn.verify) is None
        assert len(catalogue) == 0

    def test_an_untrusted_publisher_is_carried_but_flagged(self):
        """We relay what we do not install — refusing to carry it would break
        discovery for everyone else."""
        idn = CryptoIdentity()
        catalogue = cr.ReleaseCatalog()
        assert catalogue.offer(_release(idn), idn.verify,
                               trusted=lambda key: False) == "new"
        assert catalogue.list()[0]["trusted"] is False

    def test_a_flood_of_strangers_cannot_evict_the_pinned_publisher(self):
        pinned = CryptoIdentity()
        catalogue = cr.ReleaseCatalog(max_entries=3)
        trusted = lambda key: key == pinned.dsa_public_key
        assert catalogue.offer(_release(pinned, ts=500), pinned.verify,
                               trusted) == "new"
        for index in range(20):
            stranger = CryptoIdentity()
            catalogue.offer(_release(stranger, ts=1000 + index),
                            stranger.verify, trusted)
        assert len(catalogue) == 3
        mine = catalogue.get(cr.publisher_id(pinned.dsa_public_key).hex())
        assert mine is not None and mine["trusted"] is True

    def test_a_trusted_newcomer_evicts_a_stranger_when_full(self):
        catalogue = cr.ReleaseCatalog(max_entries=2)
        strangers = [CryptoIdentity() for _ in range(2)]
        for index, stranger in enumerate(strangers):
            catalogue.offer(_release(stranger, ts=1000 + index),
                            stranger.verify, lambda key: False)
        pinned = CryptoIdentity()
        assert catalogue.offer(_release(pinned), pinned.verify,
                               lambda key: key == pinned.dsa_public_key) == "new"
        assert len(catalogue) == 2
        assert catalogue.get(cr.publisher_id(pinned.dsa_public_key).hex())

    def test_a_stranger_is_simply_refused_when_full(self):
        catalogue = cr.ReleaseCatalog(max_entries=1)
        first, second = CryptoIdentity(), CryptoIdentity()
        catalogue.offer(_release(first), first.verify, lambda key: False)
        assert catalogue.offer(_release(second), second.verify,
                               lambda key: False) is None

    def test_pinning_later_applies_to_what_we_already_heard(self):
        idn = CryptoIdentity()
        catalogue = cr.ReleaseCatalog()
        catalogue.offer(_release(idn), idn.verify, lambda key: False)
        assert catalogue.list()[0]["trusted"] is False
        catalogue.retrust(lambda key: key == idn.dsa_public_key)
        assert catalogue.list()[0]["trusted"] is True

    def test_releases_are_handed_back_verbatim_for_syncing(self):
        idn = CryptoIdentity()
        catalogue = cr.ReleaseCatalog()
        blob = _release(idn)
        catalogue.offer(blob, idn.verify)
        assert catalogue.releases() == [blob]

    def test_an_unreadable_publisher_id_finds_nothing(self):
        catalogue = cr.ReleaseCatalog()
        for bad in ("", "zz", None, "aa" * 40):
            assert catalogue.get(bad) is None
