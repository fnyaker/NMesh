"""
Subscriptions: what this node watches, and what it may take on its own.

The file decides an unattended install, so it fails closed on everything: a
corrupt entry is dropped rather than guessed, a quorum is clamped rather than
trusted, and a row that does not name a real publisher is not a row.
"""
import json

import pytest

from src.pkg_dir import KIND_APP, KIND_CORE
from src.subscriptions import (MAX_QUORUM, MAX_SUBSCRIPTIONS, SubscriptionError,
                               Subscriptions)

ENTRY = "a" * 40
PUB = "b" * 40
OTHER_ENTRY = "c" * 40
OTHER_PUB = "d" * 40


class TestAddingAndRemoving:
    def test_a_subscription_round_trips(self, tmp_path):
        path = str(tmp_path / "subs.json")
        subs = Subscriptions(path)
        subs.add(ENTRY, PUB, KIND_CORE, "NMesh", auto=True, quorum=3)
        again = Subscriptions(path)
        entry = again.get(ENTRY)
        assert entry["publisher_id"] == PUB
        assert entry["kind"] == KIND_CORE
        assert entry["auto"] is True and entry["quorum"] == 3

    def test_re_subscribing_updates_rather_than_duplicates(self):
        subs = Subscriptions()
        subs.add(ENTRY, PUB, KIND_CORE, "NMesh", auto=True, quorum=3)
        subs.add(ENTRY, PUB, KIND_CORE, "NMesh", auto=False, quorum=1)
        assert len(subs) == 1
        assert subs.get(ENTRY)["auto"] is False

    def test_removing_says_whether_there_was_anything(self):
        subs = Subscriptions()
        assert subs.remove(ENTRY) is False
        subs.add(ENTRY, PUB, KIND_CORE, "NMesh")
        assert subs.remove(ENTRY) is True
        assert subs.has(ENTRY) is False

    def test_a_quorum_is_clamped_to_something_reachable(self):
        subs = Subscriptions()
        subs.add(ENTRY, PUB, KIND_CORE, "NMesh", quorum=0)
        assert subs.get(ENTRY)["quorum"] == 1
        subs.add(ENTRY, PUB, KIND_CORE, "NMesh", quorum=9999)
        assert subs.get(ENTRY)["quorum"] == MAX_QUORUM

    @pytest.mark.parametrize("entry,publisher,kind", [
        ("", PUB, KIND_CORE), ("zz", PUB, KIND_CORE), (ENTRY, "nope", KIND_CORE),
        (ENTRY, PUB, 99), (ENTRY, PUB, 0),
    ])
    def test_a_row_that_names_nothing_real_is_refused(self, entry, publisher, kind):
        with pytest.raises(SubscriptionError):
            Subscriptions().add(entry, publisher, kind, "NMesh")

    def test_the_table_is_bounded(self):
        subs = Subscriptions(max_entries=2)
        for index in range(2):
            subs.add(f"{index:040x}", PUB, KIND_CORE, "NMesh")
        with pytest.raises(SubscriptionError, match="too many"):
            subs.add(ENTRY, PUB, KIND_CORE, "NMesh")
        # …but updating one already held always goes through.
        subs.add(f"{0:040x}", PUB, KIND_CORE, "NMesh", auto=True)
        assert subs.get(f"{0:040x}")["auto"] is True


class TestCountingWhoAgrees:
    def test_only_watched_publishers_count(self):
        """A signature from somebody nobody chose is a party an attacker can
        mint. The quorum is counted over the set the operator picked."""
        subs = Subscriptions()
        subs.add(ENTRY, PUB, KIND_CORE, "NMesh")
        subs.add(OTHER_ENTRY, OTHER_PUB, KIND_CORE, "nmesh")
        assert subs.publishers_for(KIND_CORE, "nmesh") == {PUB, OTHER_PUB}

    def test_a_different_kind_is_a_different_package(self):
        subs = Subscriptions()
        subs.add(ENTRY, PUB, KIND_CORE, "NMesh")
        subs.add(OTHER_ENTRY, OTHER_PUB, KIND_APP, "NMesh")
        assert subs.publishers_for(KIND_CORE, "nmesh") == {PUB}

    def test_the_name_is_folded_like_every_other_name(self):
        subs = Subscriptions()
        subs.add(ENTRY, PUB, KIND_APP, "Sketchpad")
        assert subs.publishers_for(KIND_APP, "sketchpad") == {PUB}


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
        {"publisher_id": "nope", "kind": 1, "name": "NMesh"},
        {"publisher_id": PUB, "kind": 99, "name": "NMesh"},
        {"publisher_id": PUB, "kind": 1, "name": ""},
        {"publisher_id": PUB, "kind": True, "name": "NMesh"},
        "a string",
    ])
    def test_a_row_that_does_not_check_out_is_dropped(self, tmp_path, row):
        path = tmp_path / "subs.json"
        path.write_text(json.dumps({ENTRY: row}))
        assert len(Subscriptions(str(path))) == 0

    def test_a_key_that_is_not_an_entry_id_is_dropped(self, tmp_path):
        path = tmp_path / "subs.json"
        path.write_text(json.dumps(
            {"../../etc/passwd": {"publisher_id": PUB, "kind": 1, "name": "x"}}))
        assert len(Subscriptions(str(path))) == 0

    def test_a_stored_quorum_is_re_clamped_on_the_way_in(self, tmp_path):
        path = tmp_path / "subs.json"
        path.write_text(json.dumps(
            {ENTRY: {"publisher_id": PUB, "kind": 1, "name": "NMesh",
                     "quorum": 10 ** 9}}))
        assert Subscriptions(str(path)).get(ENTRY)["quorum"] == MAX_QUORUM

    def test_the_file_is_bounded_on_the_way_in(self, tmp_path):
        path = tmp_path / "subs.json"
        path.write_text(json.dumps(
            {f"{index:040x}": {"publisher_id": PUB, "kind": 1, "name": "NMesh"}
             for index in range(MAX_SUBSCRIPTIONS + 20)}))
        assert len(Subscriptions(str(path))) == MAX_SUBSCRIPTIONS

    def test_the_file_is_written_readable_only_by_this_user(self, tmp_path):
        import os
        path = tmp_path / "subs.json"
        Subscriptions(str(path)).add(ENTRY, PUB, KIND_CORE, "NMesh")
        assert oct(os.stat(path).st_mode & 0o777) == "0o600"


class TestRememberingWhatWasSeen:
    def test_a_version_is_only_written_when_it_moves(self, tmp_path):
        path = tmp_path / "subs.json"
        subs = Subscriptions(str(path))
        subs.add(ENTRY, PUB, KIND_CORE, "NMesh")
        subs.note_version(ENTRY, "1.0.0")
        assert Subscriptions(str(path)).get(ENTRY)["version_seen"] == "1.0.0"
        subs.note_version(ENTRY, "1.0.0")      # no-op, must not raise
        subs.note_version("f" * 40, "2.0.0")   # unknown, must not raise
        assert subs.get(ENTRY)["version_seen"] == "1.0.0"
