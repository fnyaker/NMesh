"""
Subscriptions: what this node watches, and what it may take on its own.

A subscription names a **package** — this kind, this name — never a publisher.
The file decides an unattended install, so it fails closed on everything: a
corrupt entry is dropped rather than guessed, a quorum is clamped rather than
trusted, and a row whose key is not the one its own kind and name produce is not
a row.
"""
import json

import pytest

from src.pkg_dir import KIND_APP, KIND_CORE
from src.subscriptions import (MAX_QUORUM, MAX_SUBSCRIPTIONS, SubscriptionError,
                               Subscriptions, subscription_id)

NMESH = subscription_id(KIND_CORE, "NMesh")
SKETCH = subscription_id(KIND_APP, "Sketchpad")


class TestASubscriptionNamesAPackage:
    def test_it_is_named_by_its_kind_and_name(self):
        assert subscription_id(KIND_CORE, "NMesh") == subscription_id(
            KIND_CORE, "nmesh")
        assert subscription_id(KIND_CORE, "NMesh") != subscription_id(
            KIND_APP, "NMesh")

    def test_two_signers_of_one_package_are_one_subscription(self):
        """The whole point of the change: watching a package found on one node
        and again on another is watching one thing."""
        subs = Subscriptions()
        subs.add(KIND_CORE, "NMesh")
        subs.add(KIND_CORE, "nmesh")
        assert len(subs) == 1


class TestAddingAndRemoving:
    def test_a_subscription_round_trips(self, tmp_path):
        path = str(tmp_path / "subs.json")
        subs = Subscriptions(path)
        subs.add(KIND_CORE, "NMesh", auto=True, quorum=3)
        again = Subscriptions(path)
        entry = again.get(NMESH)
        assert entry["kind"] == KIND_CORE and entry["name"] == "NMesh"
        assert entry["auto"] is True and entry["quorum"] == 3

    def test_re_subscribing_updates_rather_than_duplicates(self):
        subs = Subscriptions()
        subs.add(KIND_CORE, "NMesh", auto=True, quorum=3)
        subs.add(KIND_CORE, "NMesh", auto=False, quorum=1)
        assert len(subs) == 1
        assert subs.get(NMESH)["auto"] is False

    def test_removing_says_whether_there_was_anything(self):
        subs = Subscriptions()
        assert subs.remove(NMESH) is False
        subs.add(KIND_CORE, "NMesh")
        assert subs.remove(NMESH) is True
        assert subs.has(NMESH) is False

    def test_a_quorum_is_clamped_to_something_reachable(self):
        subs = Subscriptions()
        subs.add(KIND_CORE, "NMesh", quorum=0)
        assert subs.get(NMESH)["quorum"] == 1
        subs.add(KIND_CORE, "NMesh", quorum=9999)
        assert subs.get(NMESH)["quorum"] == MAX_QUORUM

    @pytest.mark.parametrize("kind,name", [
        (99, "NMesh"), (0, "NMesh"), (KIND_CORE, ""), (KIND_CORE, "\u200b"),
    ])
    def test_a_row_that_names_nothing_real_is_refused(self, kind, name):
        with pytest.raises(SubscriptionError):
            Subscriptions().add(kind, name)

    def test_the_table_is_bounded(self):
        subs = Subscriptions(max_entries=2)
        for index in range(2):
            subs.add(KIND_APP, f"App {index}")
        with pytest.raises(SubscriptionError, match="too many"):
            subs.add(KIND_CORE, "NMesh")
        # …but updating one already held always goes through.
        subs.add(KIND_APP, "App 0", auto=True)
        assert subs.get(subscription_id(KIND_APP, "App 0"))["auto"] is True


class TestFindingOne:
    def test_a_package_finds_its_own_subscription(self):
        subs = Subscriptions()
        subs.add(KIND_APP, "Sketchpad", quorum=2)
        assert subs.for_package(KIND_APP, "sketchpad")["quorum"] == 2

    def test_a_different_kind_is_a_different_package(self):
        subs = Subscriptions()
        subs.add(KIND_CORE, "NMesh")
        assert subs.for_package(KIND_APP, "NMesh") is None

    def test_the_name_is_folded_like_every_other_name(self):
        subs = Subscriptions()
        subs.add(KIND_APP, "Sketchpad")
        assert subs.for_package(KIND_APP, "SKETCHPAD") is not None


class TestAFileIsNotATrustedInput:
    def test_a_corrupt_file_yields_no_subscriptions(self, tmp_path):
        path = tmp_path / "subs.json"
        path.write_text("not json at all")
        assert len(Subscriptions(str(path))) == 0

    def test_a_file_that_is_not_an_object_yields_nothing(self, tmp_path):
        path = tmp_path / "subs.json"
        path.write_text("[1, 2, 3]")
        assert len(Subscriptions(str(path))) == 0

    @pytest.mark.parametrize("row", [
        {"kind": 99, "name": "NMesh"},
        {"kind": 1, "name": ""},
        {"kind": True, "name": "NMesh"},
        "a string",
    ])
    def test_a_row_that_does_not_check_out_is_dropped(self, tmp_path, row):
        path = tmp_path / "subs.json"
        path.write_text(json.dumps({NMESH: row}))
        assert len(Subscriptions(str(path))) == 0

    def test_a_key_that_is_not_an_entry_id_is_dropped(self, tmp_path):
        path = tmp_path / "subs.json"
        path.write_text(json.dumps(
            {"../../etc/passwd": {"kind": 1, "name": "x"}}))
        assert len(Subscriptions(str(path))) == 0

    def test_a_key_that_does_not_match_its_own_row_is_dropped(self, tmp_path):
        """A row filed under the wrong key is a row nothing can find, since the
        only question asked of one is "what is watching this package?"."""
        path = tmp_path / "subs.json"
        path.write_text(json.dumps({SKETCH: {"kind": 1, "name": "NMesh"}}))
        assert len(Subscriptions(str(path))) == 0

    def test_a_stored_quorum_is_re_clamped_on_the_way_in(self, tmp_path):
        path = tmp_path / "subs.json"
        path.write_text(json.dumps(
            {NMESH: {"kind": 1, "name": "NMesh", "quorum": 10 ** 9}}))
        assert Subscriptions(str(path)).get(NMESH)["quorum"] == MAX_QUORUM

    def test_the_file_is_bounded_on_the_way_in(self, tmp_path):
        path = tmp_path / "subs.json"
        path.write_text(json.dumps({
            subscription_id(KIND_APP, f"App {index}"):
                {"kind": KIND_APP, "name": f"App {index}"}
            for index in range(MAX_SUBSCRIPTIONS + 20)}))
        assert len(Subscriptions(str(path))) == MAX_SUBSCRIPTIONS

    def test_the_file_is_written_readable_only_by_this_user(self, tmp_path):
        import os
        path = tmp_path / "subs.json"
        Subscriptions(str(path)).add(KIND_CORE, "NMesh")
        assert oct(os.stat(path).st_mode & 0o777) == "0o600"


class TestRememberingWhatWasSeen:
    def test_a_version_is_only_written_when_it_moves(self, tmp_path):
        path = tmp_path / "subs.json"
        subs = Subscriptions(str(path))
        subs.add(KIND_CORE, "NMesh")
        subs.note_version(NMESH, "1.0.0")
        assert Subscriptions(str(path)).get(NMESH)["version_seen"] == "1.0.0"
        subs.note_version(NMESH, "1.0.0")      # no-op, must not raise
        subs.note_version("f" * 40, "2.0.0")   # unknown, must not raise
        assert subs.get(NMESH)["version_seen"] == "1.0.0"
