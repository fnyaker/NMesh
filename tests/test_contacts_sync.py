"""
Contacts sync — two, three nodes keeping one book in step.

Each node is a real :class:`ContactsApp` over a stub client; a wire hands what
one sends straight to the other's handler, so the whole protocol runs without a
node. What is under test is the part that has to hold against a hostile peer:
nothing enters a book that was not accepted, a reader cannot write, and a
message that is not what it says is dropped.
"""
import asyncio
import json
import random

import pytest

from src.apps import contacts as cmod
from src.apps.contacts import ContactsApp
from src.apps.contacts_state import ContactsState
from src.node_id import NodeID

ID = {name: NodeID(bytes([n]) * 20) for name, n in
      (("owner", 0x11), ("bob", 0x22), ("carol", 0x33), ("mallory", 0x66))}


class Wire:
    def __init__(self):
        self.apps = {}
        self.dropped = []
        self.reports = []

    def client(self, who):
        wire = self

        class Client:
            async def send(self, target, payload):
                app = wire.apps.get(target.raw)
                if app is None:
                    wire.dropped.append(payload)
                    return
                await app._dispatch(ID[who], payload)

            async def recv(self):
                await asyncio.Event().wait()

            async def close(self):
                pass

            async def report_abuse(self, node, weight=1, *, kind=0, reason=""):
                wire.reports.append((who, node.hex() if isinstance(node, bytes) else node, reason))

        return Client()

    def add(self, who):
        app = ContactsApp(self.client(who), node_id=ID[who],
                          state=ContactsState(me=ID[who].raw.hex()))
        self.apps[ID[who].raw] = app
        return app


def hexid(who):
    return ID[who].raw.hex()


@pytest.fixture
def wire():
    return Wire()


async def _shared(wire, role="read", members=("bob",)):
    owner = wire.add("owner")
    book = owner.state.create_book("Family", "green")
    owner.state.save(book, {"name": "Ada", "nodes": [{"id": "aa" * 20}]})
    others = {}
    for who in members:
        others[who] = wire.add(who)
        await owner.offer(book, hexid(who), role)
        [offer] = others[who].state.offers()
        assert await others[who].respond(offer["book"], offer["from"], True)
    return owner, others, book


class TestInvitation:
    async def test_nothing_arrives_until_a_human_accepts(self, wire):
        owner, bob = wire.add("owner"), wire.add("bob")
        book = owner.state.create_book("Family")
        owner.state.save(book, {"name": "Ada"})
        await owner.offer(book, hexid("bob"), "read")
        assert bob.state.books() == []
        [offer] = bob.state.offers()
        assert offer["name"] == "Family" and offer["role"] == "read"
        assert owner.state.member_state(book, hexid("bob"))["state"] == "offered"

    async def test_accepting_brings_the_contacts(self, wire):
        owner, others, book = await _shared(wire)
        bob = others["bob"]
        assert [e["name"] for e in bob.state.entries(book)] == ["Ada"]
        assert bob.state.book(book)["role"] == "read" and bob.state.book(book)["owner"] == hexid("owner")
        assert owner.state.member_state(book, hexid("bob"))["state"] == "active"
        assert bob.state.book(book)["synced"] == owner.state.book(book)["seq"]

    async def test_declining_removes_the_member(self, wire):
        owner, bob = wire.add("owner"), wire.add("bob")
        book = owner.state.create_book("Family")
        await owner.offer(book, hexid("bob"), "read")
        [offer] = bob.state.offers()
        await bob.respond(offer["book"], offer["from"], False)
        assert bob.state.books() == [] and owner.state.member_state(book, hexid("bob")) is None

    async def test_an_unanswered_invitation_is_sent_again_a_bounded_number_of_times(self, wire):
        owner = wire.add("owner")
        book = owner.state.create_book("Family")
        owner.state.save(book, {"name": "Ada"})
        owner.state.share(book, hexid("bob"), "read")
        for _ in range(cmod.OFFER_RETRIES + 5):
            await owner.sync_round()
        assert len(wire.dropped) == cmod.OFFER_RETRIES    # bob is not on the wire

    async def test_a_stranger_cannot_fill_the_queue(self, wire):
        bob = wire.add("bob")
        mallory = wire.add("mallory")
        for _ in range(40):
            book = mallory.state.create_book("x")
            mallory.state.share(book, hexid("bob"), "write")
            await mallory._offer_to(book, hexid("bob"))
        assert len(bob.state.offers()) <= 2
        await asyncio.sleep(0.01)       # the report is a job off the receive path
        assert wire.reports and wire.reports[0][0] == "bob"

    async def test_a_changed_role_reaches_a_member_that_already_follows(self, wire):
        owner, others, book = await _shared(wire, "read")
        await owner.offer(book, hexid("bob"), "write")
        assert others["bob"].state.book(book)["role"] == "write"


class TestFollowing:
    async def test_an_edit_by_the_owner_reaches_every_member(self, wire):
        owner, others, book = await _shared(wire, members=("bob", "carol"))
        ok, ada = owner.state.save(book, {"name": "Ada L."}, owner.state.entries(book)[0]["id"])
        await owner.after_change(book, [ada["id"]])
        for who in ("bob", "carol"):
            assert others[who].state.entries(book)[0]["name"] == "Ada L."

    async def test_a_deletion_travels(self, wire):
        owner, others, book = await _shared(wire)
        cid = owner.state.entries(book)[0]["id"]
        owner.state.remove(book, cid)
        await owner.after_change(book, [cid])
        assert others["bob"].state.entries(book) == []

    async def test_a_lost_push_is_made_up_by_the_next_round(self, wire):
        owner, others, book = await _shared(wire)
        owner.state.save(book, {"name": "Grace"})          # nobody told bob
        assert len(others["bob"].state.entries(book)) == 1
        await others["bob"].sync_round()
        assert sorted(e["name"] for e in others["bob"].state.entries(book)) == ["Ada", "Grace"]

    async def test_more_than_a_page_is_pulled_in_turn(self, wire):
        owner = wire.add("owner")
        book = owner.state.create_book("Big")
        for i in range(cmod.PAGE_ENTRIES * 2 + 5):
            owner.state.save(book, {"name": "c%03d" % i})
        bob = wire.add("bob")
        await owner.offer(book, hexid("bob"), "read")
        [offer] = bob.state.offers()
        await bob.respond(offer["book"], offer["from"], True)
        assert len(bob.state.entries(book)) == cmod.PAGE_ENTRIES * 2 + 5
        assert bob.state.book(book)["synced"] == owner.state.book(book)["seq"]

    async def test_a_reader_cannot_write(self, wire):
        owner, others, book = await _shared(wire, "read")
        bob = others["bob"]
        assert bob.state.save(book, {"name": "Mine"}) == (False, "read_only")
        forged = [{"id": "5" * 32, "name": "Injected", "nodes": [], "v": [9, hexid("bob")]}]
        await bob._push_to(hexid("owner"), book, forged)
        assert [e["name"] for e in owner.state.entries(book)] == ["Ada"]

    async def test_a_writer_reaches_the_owner_and_the_other_members(self, wire):
        owner, others, book = await _shared(wire, "write", members=("bob", "carol"))
        bob = others["bob"]
        ok, contact = bob.state.save(book, {"name": "Added by bob"})
        assert ok
        await bob.after_change(book, [contact["id"]])
        assert "Added by bob" in [e["name"] for e in owner.state.entries(book)]
        assert "Added by bob" in [e["name"] for e in others["carol"].state.entries(book)]
        assert bob.state.book(book)["dirty"] == []

    async def test_a_writer_that_was_offline_is_acknowledged_on_the_next_round(self, wire):
        owner, others, book = await _shared(wire, "write")
        bob = others["bob"]
        bob.state.save(book, {"name": "While offline"})
        assert bob.state.book(book)["dirty"]
        await bob.sync_round()
        assert "While offline" in [e["name"] for e in owner.state.entries(book)]
        assert bob.state.book(book)["dirty"] == []

    async def test_two_writers_settle_on_the_same_contact(self, wire):
        owner, others, book = await _shared(wire, "write", members=("bob", "carol"))
        cid = owner.state.entries(book)[0]["id"]
        for who in ("bob", "carol"):
            await others[who].sync_round()
        others["bob"].state.save(book, {"name": "bob's version"}, cid)
        others["carol"].state.save(book, {"name": "carol's version"}, cid)
        await others["bob"].after_change(book, [cid])
        await others["carol"].after_change(book, [cid])
        for app in (owner, others["bob"], others["carol"]):
            await app.sync_round()
        names = {a.state.entries(book)[0]["name"] for a in (owner, *others.values())}
        assert names == {"carol's version"}      # equal counters: the higher writer id wins


class TestRefusals:
    async def test_a_stranger_cannot_push_into_a_book(self, wire):
        owner, others, book = await _shared(wire, "write")
        mallory = wire.add("mallory")
        forged = [{"id": "5" * 32, "name": "Bank", "nodes": [], "v": [9, hexid("mallory")]}]
        await mallory._push_to(hexid("owner"), book, forged)
        await mallory._push_to(hexid("bob"), book, forged)
        assert [e["name"] for e in owner.state.entries(book)] == ["Ada"]
        assert [e["name"] for e in others["bob"].state.entries(book)] == ["Ada"]

    async def test_a_member_cannot_push_to_another_member(self, wire):
        owner, others, book = await _shared(wire, "write", members=("bob", "carol"))
        forged = [{"id": "5" * 32, "name": "Sideways", "nodes": [], "v": [9, hexid("bob")]}]
        await others["bob"]._push_to(hexid("carol"), book, forged)
        assert [e["name"] for e in others["carol"].state.entries(book)] == ["Ada"]

    async def test_a_stranger_cannot_pull_a_book(self, wire):
        owner, others, book = await _shared(wire)
        mallory = wire.add("mallory")
        await mallory._send(hexid("owner"), cmod._PULL, {"book": book, "since": 0})
        assert mallory.state.books() == [] and wire.dropped == []

    async def test_a_stranger_cannot_revoke_or_leave_for_someone_else(self, wire):
        owner, others, book = await _shared(wire)
        mallory = wire.add("mallory")
        await mallory._send(hexid("bob"), cmod._REVOKE, {"book": book})
        await mallory._send(hexid("owner"), cmod._LEAVE, {"book": book})
        assert others["bob"].state.book(book)["role"] == "read"
        assert owner.state.member_state(book, hexid("bob")) is not None

    async def test_a_forged_acknowledgement_clears_nothing(self, wire):
        owner, others, book = await _shared(wire, "write")
        bob = others["bob"]
        bob.state.save(book, {"name": "pending"})
        mallory = wire.add("mallory")
        ids = list(bob.state.book(book)["dirty"])
        await mallory._send(hexid("bob"), cmod._ACK, {"book": book, "ids": ids})
        assert bob.state.book(book)["dirty"] == ids

    async def test_a_pushed_entry_must_be_a_contact(self, wire):
        owner, others, book = await _shared(wire, "write")
        junk = [None, 5, "x", {"id": 3}, {"id": "5" * 32, "v": "no"}, {"id": "5" * 32, "v": [1]}]
        await others["bob"]._send(hexid("owner"), cmod._PUSH, {"book": book, "entries": junk})
        assert [e["name"] for e in owner.state.entries(book)] == ["Ada"]


class TestLeaving:
    async def test_a_member_that_leaves_is_forgotten_by_the_owner(self, wire):
        owner, others, book = await _shared(wire)
        assert await others["bob"].remove_book(book)
        assert others["bob"].state.book(book) is None
        assert owner.state.member_state(book, hexid("bob")) is None

    async def test_revoking_leaves_the_member_a_copy_of_its_own(self, wire):
        owner, others, book = await _shared(wire, "write")
        assert await owner.revoke(book, hexid("bob"))
        meta = others["bob"].state.book(book)
        assert meta["role"] == "owner" and meta["owner"] == hexid("bob")
        assert [e["name"] for e in others["bob"].state.entries(book)] == ["Ada"]
        owner.state.save(book, {"name": "later"})
        await owner.sync_round()
        assert [e["name"] for e in others["bob"].state.entries(book)] == ["Ada"]

    async def test_deleting_a_shared_book_lets_every_member_go(self, wire):
        owner, others, book = await _shared(wire, members=("bob", "carol"))
        assert await owner.remove_book(book)
        for who in ("bob", "carol"):
            assert others[who].state.book(book)["role"] == "owner"

    async def test_a_member_whose_revoke_was_lost_is_told_when_it_asks_again(self, wire):
        owner, others, book = await _shared(wire)
        owner.state.unshare(book, hexid("bob"))          # the revoke never left
        await others["bob"].sync_round()
        assert others["bob"].state.book(book)["role"] == "owner"


class TestHostileWire:
    async def test_random_bytes_never_raise_and_change_nothing(self, wire):
        owner, others, book = await _shared(wire, "write")
        rng = random.Random(3)
        before = (owner.state.books(), owner.state.entries(), others["bob"].state.entries())
        for _ in range(500):
            kind = rng.choice([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 255])
            body = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 200)))
            for app in (owner, others["bob"]):
                await app._dispatch(ID["mallory"], bytes([kind]) + body)
        assert (owner.state.books(), owner.state.entries(), others["bob"].state.entries()) == before

    async def test_structured_junk_is_dropped(self, wire):
        owner, others, book = await _shared(wire, "write")
        before = (owner.state.entries(), others["bob"].state.entries())
        for kind in range(1, 9):
            for body in ({}, {"book": 5}, {"book": book}, {"book": book, "entries": "x"},
                         {"book": book, "since": "x"}, {"book": "z" * 32}, [], "x", None,
                         {"book": book, "entries": [{}] * 500}):
                await owner._dispatch(ID["mallory"], bytes([kind]) + json.dumps(body).encode())
                await others["bob"]._dispatch(ID["mallory"], bytes([kind]) + json.dumps(body).encode())
        assert (owner.state.entries(), others["bob"].state.entries()) == before

    async def test_an_oversized_message_is_not_parsed(self, wire):
        owner = wire.add("owner")
        await owner._dispatch(ID["mallory"], bytes([cmod._OFFER]) + b" " * (cmod.MAX_MESSAGE + 1))
        assert owner.state.offers() == []

    async def test_deeply_nested_json_does_not_raise(self, wire):
        owner = wire.add("owner")
        await owner._dispatch(ID["mallory"], bytes([cmod._OFFER]) + b"[" * 30_000 + b"]" * 30_000)

    async def test_a_flood_of_pulls_is_reported_once_per_window(self, wire):
        owner, others, book = await _shared(wire)
        mallory = wire.add("mallory")
        for _ in range(200):
            await mallory._send(hexid("owner"), cmod._PULL, {"book": book, "since": 0})
        await asyncio.sleep(0.01)
        assert 1 <= len([r for r in wire.reports if r[0] == "owner"]) <= 2
