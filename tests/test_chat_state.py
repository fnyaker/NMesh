"""
ChatState — the app-level contacts / pseudo / groups store.

Pure, synchronous state: bounds, persistence round-trip, and pseudo search.
No node, no network.
"""
import os

from src.apps.chat_state import (
    ChatState, normalize_pseudo,
    _MAX_CONTACTS, _MAX_KNOWN, _MAX_GROUPS, _MAX_PSEUDO,
)

ID_A = "aa" * 20
ID_B = "bb" * 20
GID = "cc" * 16


class TestBasics:
    def test_pseudo_normalized_and_capped(self):
        s = ChatState()
        s.set_pseudo("   " + "x" * 100 + "   ")
        assert s.pseudo == "x" * _MAX_PSEUDO
        assert normalize_pseudo("  hi  ") == "hi"

    def test_add_remove_contact(self):
        s = ChatState()
        assert s.add_contact(ID_A, "alice") is True
        assert s.contacts[ID_A]["pseudo"] == "alice"
        assert s.remove_contact(ID_A) is True
        assert s.remove_contact(ID_A) is False

    def test_bad_id_rejected(self):
        s = ChatState()
        assert s.add_contact("nothex", "x") is False
        assert s.add_contact("ab" * 10, "x") is False   # wrong length

    def test_learn_pseudo_goes_to_known_then_promoted(self):
        s = ChatState()
        s.learn_pseudo(ID_B, "bob")
        assert s.known[ID_B]["pseudo"] == "bob" and ID_B not in s.contacts
        s.add_contact(ID_B, "bob")
        assert ID_B in s.contacts and ID_B not in s.known   # promoted, de-duped

    def test_learn_updates_existing_contact(self):
        s = ChatState()
        s.add_contact(ID_A, "old")
        s.learn_pseudo(ID_A, "new")
        assert s.contacts[ID_A]["pseudo"] == "new" and ID_A not in s.known

    def test_group_roundtrip(self):
        s = ChatState()
        assert s.add_group(GID, "team", [ID_A, ID_B, ID_A]) is True  # dedup
        assert s.group_members(GID) == [ID_A, ID_B]
        assert s.remove_group(GID) is True


class TestBounds:
    def test_contacts_bounded(self):
        s = ChatState()
        for i in range(_MAX_CONTACTS):
            assert s.add_contact(f"{i:040x}", "p")
        assert s.add_contact("ff" * 20, "p") is False  # full
        assert len(s.contacts) == _MAX_CONTACTS

    def test_known_lru_bounded(self):
        s = ChatState()
        for i in range(_MAX_KNOWN + 50):
            s.learn_pseudo(f"{i:040x}", f"p{i}")
        assert len(s.known) == _MAX_KNOWN

    def test_group_members_bounded(self):
        s = ChatState()
        many = [f"{i:040x}" for i in range(1000)]
        s.add_group(GID, "big", many)
        assert len(s.group_members(GID)) <= 256


class TestSearch:
    def test_find_by_pseudo_case_insensitive_substring(self):
        s = ChatState()
        s.add_contact(ID_A, "Alice")
        s.learn_pseudo(ID_B, "alicia")
        hits = s.find_by_pseudo("ali")
        ids = {h["id"] for h in hits}
        assert ids == {ID_A, ID_B}
        kinds = {h["id"]: h["kind"] for h in hits}
        assert kinds[ID_A] == "contact" and kinds[ID_B] == "known"

    def test_find_empty_query(self):
        s = ChatState()
        s.add_contact(ID_A, "alice")
        assert s.find_by_pseudo("   ") == []

    def test_matches_my_pseudo(self):
        s = ChatState()
        s.set_pseudo("Zoe")
        assert s.matches_my_pseudo("zoe") is True
        assert s.matches_my_pseudo("zoey") is False


class TestPersistence:
    def test_roundtrip(self, tmp_path):
        path = os.path.join(tmp_path, "chat_state.json")
        s = ChatState(path)
        s.set_pseudo("alice")
        s.add_contact(ID_A, "bob")
        s.learn_pseudo(ID_B, "carol")
        s.add_group(GID, "team", [ID_A, ID_B])
        # A fresh store on the same path sees everything.
        s2 = ChatState(path)
        assert s2.pseudo == "alice"
        assert s2.contacts[ID_A]["pseudo"] == "bob"
        assert s2.known[ID_B]["pseudo"] == "carol"
        assert s2.group_members(GID) == [ID_A, ID_B]
        assert oct(os.stat(path).st_mode)[-3:] == "600"

    def test_corrupt_file_starts_empty(self, tmp_path):
        path = os.path.join(tmp_path, "chat_state.json")
        with open(path, "w") as f:
            f.write("{ not json")
        s = ChatState(path)  # must not raise
        assert s.contacts == {} and s.pseudo == ""

    def test_no_path_is_memory_only(self):
        s = ChatState()
        s.add_contact(ID_A, "x")
        assert s.contacts[ID_A]["pseudo"] == "x"  # works, just not persisted
