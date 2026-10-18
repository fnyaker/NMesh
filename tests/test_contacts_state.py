"""
Contacts state — books, contacts, search, and the rules a merge keeps.

No node and no network: the state is data with rules, so every rule is tested
by feeding it what a person types and what a hostile peer might send.
"""
import json
import random
import secrets

from src.apps import contacts_state as cs
from src.apps.contacts_state import ContactsState

ME = "01" * 20
A = "0a" * 20
B = "0b" * 20
C = "0c" * 20


class Drawer:
    """The two calls the state makes of the encrypted drawer."""

    def __init__(self):
        self.data = {}

    def get(self, key):
        return self.data.get(key)

    def put(self, key, value):
        self.data[key] = bytes(value)
        return True

    def delete(self, key):
        return self.data.pop(key, None) is not None


def _state(**kw):
    return ContactsState(me=ME, **kw)


class TestBooks:
    def test_the_first_contact_makes_a_default_book(self):
        st = _state()
        ok, contact = st.add_node(A, "Ada")
        assert ok and contact["name"] == "Ada"
        books = st.books()
        assert len(books) == 1 and books[0]["default"] and books[0]["count"] == 1

    def test_books_are_bounded(self):
        st = _state()
        made = [st.create_book("b%d" % i) for i in range(cs.MAX_BOOKS + 3)]
        assert sum(1 for b in made if b) == cs.MAX_BOOKS

    def test_a_book_name_is_one_printable_line(self):
        st = _state()
        book = st.create_book("  Family\n\x00‮  ")
        assert st.book(book)["name"] == "Family"

    def test_unknown_colour_falls_back(self):
        st = _state()
        assert st.book(st.create_book("x", "<script>"))["color"] == "blue"

    def test_deleting_the_default_picks_another_of_mine(self):
        st = _state()
        first, second = st.create_book("one"), st.create_book("two")
        assert st.default == first
        st.delete_book(first)
        assert st.default == second

    def test_a_mirror_cannot_be_renamed(self):
        st = _state()
        st.receive_offer(A, "ab" * 16, "Shared", "red", "read", 0)
        st.accept_offer(st.take_offer("ab" * 16, A))
        assert not st.set_book("ab" * 16, name="Mine now")


class TestContacts:
    def test_a_contact_needs_a_name_or_a_node(self):
        st = _state()
        book = st.create_book("b")
        assert st.save(book, {"name": "", "nodes": []}) == (False, "empty")
        assert st.save(book, {"name": "Ada"})[0]
        assert st.save(book, {"nodes": [{"id": A}]})[0]

    def test_fields_are_bounded(self):
        st = _state()
        book = st.create_book("b")
        ok, contact = st.save(book, {
            "name": "x" * 500, "note": "n" * 5000,
            "nodes": [{"id": "%040x" % i, "label": "l" * 99} for i in range(30)]})
        assert ok
        assert len(contact["name"]) == cs.MAX_NAME
        assert len(contact["note"]) == cs.MAX_NOTE
        assert len(contact["nodes"]) == cs.MAX_NODES
        assert all(len(n["label"]) <= cs.MAX_LABEL for n in contact["nodes"])

    def test_a_bad_node_id_is_dropped_not_kept(self):
        st = _state()
        book = st.create_book("b")
        ok, contact = st.save(book, {"name": "x", "nodes": [
            {"id": "zz" * 20}, {"id": A.upper()}, {"id": A}, "nope", 5]})
        assert [n["id"] for n in contact["nodes"]] == [A]

    def test_editing_bumps_the_version_under_my_id(self):
        st = _state()
        book = st.create_book("b")
        _, first = st.save(book, {"name": "Ada"})
        _, second = st.save(book, {"name": "Ada L."}, first["id"])
        assert second["v"] == [2, ME] and first["v"] == [1, ME]

    def test_deleting_leaves_a_tombstone_that_travels(self):
        st = _state()
        book = st.create_book("b")
        _, contact = st.save(book, {"name": "Ada"})
        assert st.remove(book, contact["id"]) == (True, None)
        assert st.get(book, contact["id"]) is None
        assert st.entries(book) == []
        [tomb] = st.raw_entries(book, [contact["id"]])
        assert tomb["del"] and tomb["name"] == "" and tomb["v"][0] == 2

    def test_a_deleted_contact_cannot_be_edited(self):
        st = _state()
        book = st.create_book("b")
        _, contact = st.save(book, {"name": "Ada"})
        st.remove(book, contact["id"])
        assert st.save(book, {"name": "Ghost"}, contact["id"]) == (False, "no_contact")

    def test_add_node_is_idempotent_per_book(self):
        st = _state()
        st.add_node(A, "Ada")
        ok, again = st.add_node(A, "Somebody else")
        assert ok and again["name"] == "Ada"
        assert len(st.entries()) == 1

    def test_add_node_names_a_nameless_contact(self):
        st = _state()
        st.add_node(A)
        ok, named = st.add_node(A, "Ada")
        assert named["name"] == "Ada" and len(st.entries()) == 1

    def test_remove_node_keeps_a_contact_that_has_other_nodes(self):
        st = _state()
        book = st.create_book("b")
        st.save(book, {"name": "Ada", "nodes": [{"id": A}, {"id": B}]})
        assert st.remove_node(A) == 1
        [contact] = st.entries(book)
        assert [n["id"] for n in contact["nodes"]] == [B]

    def test_remove_node_drops_an_anonymous_contact(self):
        st = _state()
        st.add_node(A)
        assert st.remove_node(A) == 1
        assert st.entries() == []

    def test_a_book_that_no_longer_fits_refuses_and_keeps_what_it_had(self, monkeypatch):
        st = _state(store=Drawer())
        book = st.create_book("b")
        assert st.save(book, {"name": "one"})[0]
        monkeypatch.setattr(cs, "_VALUE_MAX", 400)
        ok, why = st.save(book, {"name": "two", "note": "x" * 500})
        assert (ok, why) == (False, "full")
        assert [e["name"] for e in st.entries(book)] == ["one"]
        assert st.book(book)["seq"] == 1

    def test_tombstones_make_room_when_old_enough(self, monkeypatch):
        monkeypatch.setattr(cs, "MAX_ENTRIES", 3)
        st = _state()
        book = st.create_book("b")
        ids = [st.save(book, {"name": "n%d" % i})[1]["id"] for i in range(3)]
        for cid in ids:
            st.remove(book, cid)
        assert st.save(book, {"name": "new"}) == (False, "full")
        for entry in st._entries[book].values():
            entry["t"] = 1.0
        assert st.save(book, {"name": "new"})[0]


class TestSearch:
    def _st(self):
        st = _state()
        book = st.create_book("b")
        st.save(book, {"name": "José Martín", "nodes": [{"id": A, "label": "phone"}]})
        st.save(book, {"name": "Josephine", "nodes": [{"id": B}]})
        st.save(book, {"name": "Maria", "note": "knows Jose from school", "nodes": [{"id": C}]})
        return st

    def test_it_ignores_case_and_accents(self):
        names = [r["name"] for r in self._st().search("jose")]
        assert "José Martín" in names and "Josephine" in names

    def test_exact_before_prefix_before_word_before_note(self):
        st = _state()
        book = st.create_book("b")
        for name in ("zed alice", "alice", "alicexyz"):
            st.save(book, {"name": name})
        st.save(book, {"name": "other", "note": "met alice once"})
        assert [r["name"] for r in st.search("alice")] == ["alice", "alicexyz", "zed alice", "other"]

    def test_by_the_start_of_a_node_id(self):
        [row] = self._st().search(A[:8])
        assert row["name"] == "José Martín"

    def test_a_label_is_searched(self):
        assert self._st().search("phone")[0]["name"] == "José Martín"

    def test_nothing_for_nothing(self):
        st = self._st()
        assert st.search("") == [] and st.search("   ") == []
        assert st.search("zzzzzz") == []

    def test_a_deleted_contact_is_not_found(self):
        st = self._st()
        book = st.default
        [maria] = [e for e in st.entries(book) if e["name"] == "Maria"]
        st.remove(book, maria["id"])
        assert st.search("maria") == []

    def test_the_limit_is_honoured_and_bounded(self):
        st = _state()
        book = st.create_book("b")
        for i in range(30):
            st.save(book, {"name": "alice %d" % i})
        assert len(st.search("alice", limit=5)) == 5
        assert len(st.search("alice", limit=10 ** 9)) == 30

    def test_find_by_node_puts_my_own_books_first(self):
        st = _state()
        st.receive_offer(A, "ab" * 16, "Shared", "red", "write", 0)
        st.accept_offer(st.take_offer("ab" * 16, A))
        st.merge("ab" * 16, [{"id": "1" * 32, "name": "Shared Ada", "nodes": [{"id": B}],
                              "v": [1, A], "seq": 1}], from_owner=True)
        st.add_node(B, "My Ada")
        assert [r["name"] for r in st.find(B)] == ["My Ada", "Shared Ada"]
        assert st.node_names()[B] == "My Ada"


class TestPersistence:
    def test_everything_survives_a_restart(self):
        drawer = Drawer()
        st = _state(store=drawer)
        book = st.create_book("Work", "green")
        st.save(book, {"name": "Ada", "note": "hello\nthere", "fav": True,
                       "nodes": [{"id": A, "label": "laptop"}]})
        st.share(book, B, "write")
        st.receive_offer(C, "cd" * 16, "Theirs", "red", "read", 3)
        again = _state(store=drawer)
        assert again.books()[0]["name"] == "Work" and again.default == book
        [contact] = again.entries(book)
        assert contact["note"] == "hello\nthere" and contact["fav"] is True
        assert again.member_state(book, B) == {"role": "write", "state": "offered", "tries": 0}
        assert again.offers()[0]["name"] == "Theirs"
        assert again.search("ada")

    def test_garbage_in_the_drawer_starts_empty(self):
        drawer = Drawer()
        drawer.put("index", b"\xff\xfe not json")
        assert _state(store=drawer).books() == []
        drawer.put("index", json.dumps({"books": ["ab" * 16], "default": "x"}).encode())
        drawer.put("book:" + "ab" * 16, b'{"meta": 5, "entries": []}')
        assert _state(store=drawer).books() == []

    def test_a_hostile_stored_book_is_cleaned_not_trusted(self):
        drawer = Drawer()
        book = "ab" * 16
        drawer.put("index", json.dumps({"books": [book], "default": book}).encode())
        drawer.put("book:" + book, json.dumps({
            "meta": {"role": "owner", "name": "x" * 999, "color": "nope",
                     "members": {A: {"role": "admin"}, "bad": {"role": "read"}}},
            "entries": {"k": {"id": "short"}, "e" * 32: {"id": "e" * 32, "name": "ok",
                                                         "v": [5, A], "seq": -4}}}).encode())
        st = _state(store=drawer)
        [meta] = st.books()
        assert len(meta["name"]) == cs.MAX_BOOK_NAME and meta["color"] == "blue"
        assert meta["members"] == {}
        assert [e["name"] for e in st.entries()] == ["ok"]


class TestMerge:
    def _mirror(self, role="write"):
        st = _state()
        st.receive_offer(A, "ab" * 16, "Shared", "red", role, 0)
        st.accept_offer(st.take_offer("ab" * 16, A))
        return st, "ab" * 16

    def _entry(self, name, counter, writer, cid="1" * 32, seq=1, **more):
        return dict({"id": cid, "name": name, "nodes": [], "v": [counter, writer],
                     "seq": seq}, **more)

    def test_the_higher_counter_wins_and_a_stale_one_is_ignored(self):
        st, book = self._mirror()
        assert st.merge(book, [self._entry("v2", 2, A)], from_owner=True)
        assert st.merge(book, [self._entry("v1", 1, A)], from_owner=True) == []
        assert st.entries(book)[0]["name"] == "v2"

    def test_a_tie_goes_to_the_higher_writer_on_every_replica(self):
        for order in ((A, B), (B, A)):
            st, book = self._mirror()
            for writer in order:
                st.merge(book, [self._entry("by-" + writer[:2], 3, writer)], from_owner=True)
            assert st.entries(book)[0]["name"] == "by-0b"

    def test_an_entry_with_no_writer_is_refused(self):
        st, book = self._mirror()
        assert st.merge(book, [self._entry("x", 0, "")], from_owner=True) == []

    def test_a_counter_out_of_range_is_refused(self):
        st, book = self._mirror()
        assert st.merge(book, [self._entry("x", cs.MAX_COUNTER + 1, A)], from_owner=True) == []
        assert st.merge(book, [self._entry("x", -1, A)], from_owner=True) == []
        assert st.merge(book, [self._entry("x", True, A)], from_owner=True) == []

    def test_the_owner_numbers_what_a_member_sends(self):
        st = _state()
        book = st.create_book("b")
        taken = st.merge(book, [self._entry("from B", 1, B)], from_owner=False, writer=B)
        assert taken == ["1" * 32]
        assert st.raw_entries(book, taken)[0]["seq"] == 1
        assert st.book(book)["seq"] == 1

    def test_a_member_cannot_write_under_somebody_elses_id(self):
        st = _state()
        book = st.create_book("b")
        assert st.merge(book, [self._entry("forged", 9, C)], from_owner=False, writer=B) == []

    def test_a_tombstone_wins_over_the_older_contact(self):
        st, book = self._mirror()
        st.merge(book, [self._entry("alive", 1, A)], from_owner=True)
        st.merge(book, [{"id": "1" * 32, "del": True, "v": [2, A], "seq": 2}], from_owner=True)
        assert st.entries(book) == []

    def test_the_owner_winning_clears_my_pending_edit(self):
        st, book = self._mirror("write")
        _, mine = st.save(book, {"name": "mine"})
        assert mine["id"] in st.book(book)["dirty"]
        st.merge(book, [self._entry("theirs", 5, A, cid=mine["id"])], from_owner=True)
        assert st.book(book)["dirty"] == []


class TestOffers:
    def test_a_book_i_already_have_is_not_offered_again(self):
        st = _state()
        book = st.create_book("b")
        assert not st.receive_offer(A, book, "x", "blue", "read", 0)

    def test_bounded_per_sender_and_in_all(self):
        st = _state()
        assert st.receive_offer(A, "1" * 32, "a", "blue", "read", 0)
        assert st.receive_offer(A, "2" * 32, "b", "blue", "read", 0)
        assert not st.receive_offer(A, "3" * 32, "c", "blue", "read", 0)
        for i in range(cs.MAX_OFFERS):
            st.receive_offer("%040x" % (i + 100), secrets.token_hex(16), "n", "blue", "read", 0)
        assert len(st.offers()) == cs.MAX_OFFERS

    def test_the_same_offer_twice_is_one(self):
        st = _state()
        st.receive_offer(A, "1" * 32, "first", "blue", "read", 0)
        st.receive_offer(A, "1" * 32, "second", "blue", "write", 0)
        [offer] = st.offers()
        assert offer["name"] == "second" and offer["role"] == "write"

    def test_an_old_offer_expires(self):
        st = _state()
        st.receive_offer(A, "1" * 32, "a", "blue", "read", 0)
        st._offers[0]["at"] = 1.0
        assert st.offers() == []

    def test_a_garbled_offer_is_refused(self):
        st = _state()
        assert not st.receive_offer("short", "1" * 32, "a", "blue", "read", 0)
        assert not st.receive_offer(A, "short", "a", "blue", "read", 0)
        assert not st.receive_offer(A, "1" * 32, "a", "blue", "admin", 0)

    def test_detach_makes_the_copy_mine(self):
        st = _state()
        st.receive_offer(A, "1" * 32, "a", "blue", "write", 0)
        st.accept_offer(st.take_offer("1" * 32, A))
        assert st.detach("1" * 32)
        meta = st.book("1" * 32)
        assert meta["role"] == "owner" and meta["owner"] == ME and st.can_write("1" * 32)


class TestHostileEntries:
    def test_clean_entry_never_raises_and_never_keeps_junk(self):
        rng = random.Random(7)
        atoms = [None, True, 0, -1, 2 ** 70, 1.5, "", "x" * 3000, "\x00", "‮", [], {},
                 [1, 2, 3], {"id": "e" * 32}, A, "e" * 32, {"id": A}]

        def junk(depth=0):
            kind = rng.random()
            if depth > 3 or kind < 0.5:
                return rng.choice(atoms)
            if kind < 0.75:
                return [junk(depth + 1) for _ in range(rng.randint(0, 4))]
            return {rng.choice(["id", "name", "nodes", "note", "fav", "del", "v", "seq", "t", "x"]):
                    junk(depth + 1) for _ in range(rng.randint(0, 6))}

        for _ in range(3000):
            for keep in (False, True):
                entry = cs.clean_entry(junk(), keep_version=keep)
                if entry is None:
                    continue
                assert cs.is_cid(entry["id"])
                assert len(entry["name"]) <= cs.MAX_NAME and len(entry["note"]) <= cs.MAX_NOTE
                assert len(entry["nodes"]) <= cs.MAX_NODES
                assert all(cs.is_node(n["id"]) for n in entry["nodes"])
                assert 0 <= entry["v"][0] <= cs.MAX_COUNTER and 0 <= entry["seq"] <= cs.MAX_COUNTER

    def test_merge_survives_junk(self):
        st = _state()
        book = st.create_book("b")
        for payload in (None, 5, "x", {}, [None, 1, "x", {"id": 1}], [{"id": "z" * 32}] * 5000):
            st.merge(book, payload, from_owner=True)
            st.merge(book, payload, from_owner=False, writer=A)
