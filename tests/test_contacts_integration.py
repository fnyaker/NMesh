"""
Chat and the address books: one permission, two sub-permissions, no shortcut.

The books are the contacts app's. What chat knows about the people in them it
asks for through the operations that app declares, and only as far as a person
let it. These hold the line at each step: what the permission tree says, what
the link does with a missing grant, and what chat shows and does in each of the
four states (``unavailable``, ``denied``, ``read``, ``write``).
"""
import asyncio

import pytest

from src import app_api, app_perms
from src.app_registry import (BUILTIN_APPS, CHAT_APP_ID, CONTACTS_APP_ID,
                              AppRegistry)
from src.apps import contacts_link
from src.apps.chat import ChatApp
from src.apps.chat_state import ChatState
from src.apps.chat_web import ChatBridge
from src.apps.contacts import ContactsApp
from src.apps.contacts_state import ContactsState
from src.apps.contacts_web import ContactsBridge
from src.node_id import NodeID

ME = NodeID(bytes([0x11]) * 20)
PEER = NodeID(bytes(range(20)))
ADA = "aa" * 20
BOB = "bb" * 20
CHAT_HEX = CHAT_APP_ID.hex()


class Quiet:
    async def send(self, target, payload):
        pass

    async def recv(self):
        await asyncio.Event().wait()

    async def close(self):
        pass


class Host:
    def __init__(self, **bridges):
        self._bridges = bridges

    def running(self):
        return set(self._bridges)

    def bridge(self, name):
        return self._bridges.get(name)


@pytest.fixture
def perms():
    return AppRegistry(None).perms


@pytest.fixture
async def books():
    app = ContactsApp(Quiet(), node_id=ME, state=ContactsState(me=ME.raw.hex()))
    app.state.ensure_default()
    bridge = ContactsBridge(app)
    bridge.start(asyncio.get_running_loop())
    return app, bridge


def link(bridge, perms):
    return contacts_link.ContactsLink(Host(contacts=bridge) if bridge else Host(),
                                      perms, CHAT_HEX)


class TestThePermission:
    def test_contacts_is_sensitive_and_has_a_read_and_a_write_half(self):
        assert app_perms.level("contacts") == app_perms.SENSITIVE
        assert set(app_perms.children("contacts")) == {"contacts.read", "contacts.write"}
        for name in ("contacts.read", "contacts.write"):
            assert app_perms.level(name) == app_perms.SENSITIVE

    def test_nothing_is_granted_by_asking(self, perms):
        for name in ("contacts", "contacts.read", "contacts.write"):
            assert not perms.allows(CHAT_HEX, name)

    def test_reading_does_not_let_an_app_write(self, perms):
        assert perms.set_grant(CHAT_HEX, "contacts.read", True)
        assert perms.allows(CHAT_HEX, "contacts.read")
        assert not perms.allows(CHAT_HEX, "contacts.write")

    def test_taking_back_what_was_given_takes_it_back(self, perms):
        perms.set_grant(CHAT_HEX, "contacts.read", True)
        perms.set_grant(CHAT_HEX, "contacts.write", True)
        perms.set_grant(CHAT_HEX, "contacts.read", False)
        assert not perms.allows(CHAT_HEX, "contacts.read")

    def test_a_client_holding_only_the_shared_token_never_gets_contacts(self, perms):
        perms.set_grant(CHAT_HEX, "contacts.read", True)
        assert not perms.allows(CHAT_HEX, "contacts.read", identified=False)

    def test_chat_asks_for_both_and_says_why(self):
        chat = next(a for a in BUILTIN_APPS if a["name"] == "chat")
        asked = {p["name"]: p.get("why", "") for p in chat["permissions"]}
        assert asked["contacts.read"] and asked["contacts.write"]

    def test_the_contacts_app_does_not_ask_for_its_own_permission(self):
        mine = next(a for a in BUILTIN_APPS if a["name"] == "contacts")
        assert not any(p["name"].startswith("contacts") for p in mine["permissions"])

    def test_an_operation_names_what_it_needs_and_a_stranger_name_is_ignored(self):
        assert app_perms.app_call_need({"permission": "contacts.write"}) == "contacts.write"
        assert app_perms.app_call_need({"changes": True}) == "control.apps"
        assert app_perms.app_call_need({}) == "readstate.apps"
        # a name that is not on the tree cannot be a way to need nothing
        assert app_perms.app_call_need({"permission": "nothing.at.all"}) == "readstate.apps"
        assert app_perms.app_call_need({"permission": 7}) == "readstate.apps"

    def test_every_operation_of_the_books_names_a_permission_that_exists(self):
        ops = app_api.declared(ContactsBridge)
        assert ops
        for op in ops:
            assert op.get("permission") in ("contacts.read", "contacts.write"), op["name"]
        for op in ops:
            if op.get("changes"):
                assert op["permission"] == "contacts.write", op["name"]


class TestTheLink:
    async def test_no_contacts_app_is_unavailable_not_denied(self, perms):
        gone = link(None, perms)
        assert gone.access() == "unavailable"
        with pytest.raises(contacts_link.Unavailable):
            gone.call("names")

    async def test_the_four_states(self, books, perms):
        _, bridge = books
        chat = link(bridge, perms)
        assert chat.access() == "denied"
        perms.set_grant(CHAT_HEX, "contacts.read", True)
        assert chat.access() == "read"
        perms.set_grant(CHAT_HEX, "contacts.write", True)
        assert chat.access() == "write"

    async def test_a_refused_app_gets_a_refusal_not_a_thinner_answer(self, books, perms):
        _, bridge = books
        chat = link(bridge, perms)
        with pytest.raises(contacts_link.Denied) as refused:
            chat.call("names")
        assert refused.value.permission == "contacts.read"

    async def test_a_reader_can_read_and_cannot_write(self, books, perms):
        _, bridge = books
        perms.set_grant(CHAT_HEX, "contacts.read", True)
        chat = link(bridge, perms)
        assert (await asyncio.to_thread(chat.call, "names"))["names"] == {}
        with pytest.raises(contacts_link.Denied) as refused:
            await asyncio.to_thread(chat.call, "add", node=ADA, name="Ada")
        assert refused.value.permission == "contacts.write"
        assert bridge.state.find(ADA) == []

    async def test_a_writer_adds_and_the_books_hold_it(self, books, perms):
        _, bridge = books
        perms.set_grant(CHAT_HEX, "contacts.read", True)
        perms.set_grant(CHAT_HEX, "contacts.write", True)
        chat = link(bridge, perms)
        done = await asyncio.to_thread(chat.call, "add", node=ADA, name="Ada")
        assert done["added"] is True
        assert [f["name"] for f in bridge.state.find(ADA)] == ["Ada"]

    async def test_an_operation_nobody_declared_is_not_found(self, books, perms):
        _, bridge = books
        perms.set_grant(CHAT_HEX, "contacts.read", True)
        with pytest.raises(contacts_link.Unavailable):
            link(bridge, perms).call("wipe_everything")

    async def test_with_no_permission_book_everything_is_denied(self, books):
        _, bridge = books
        chat = contacts_link.ContactsLink(Host(contacts=bridge), None, CHAT_HEX)
        assert chat.access() == "denied"
        with pytest.raises(contacts_link.Denied):
            chat.call("names")

    async def test_a_host_that_vanishes_between_calls_is_not_held_on_to(self, books, perms):
        _, bridge = books
        state = {"host": Host(contacts=bridge)}
        chat = contacts_link.ContactsLink(lambda: state["host"], perms, CHAT_HEX)
        perms.set_grant(CHAT_HEX, "contacts.read", True)
        assert chat.access() == "read"
        state["host"] = Host()
        assert chat.access() == "unavailable"


def _chat(bridge, perms):
    app = ChatApp(Quiet())
    return app, ChatBridge(app, peer=PEER, contacts=link(bridge, perms))


class TestChatOverTheBooks:
    async def test_it_says_which_of_the_four_states_it_is_in(self, books, perms):
        _, bridge = books
        _, chat = _chat(bridge, perms)
        assert chat.snapshot(0)["contacts_access"] == "denied"
        perms.set_grant(CHAT_HEX, "contacts.read", True)
        assert chat.snapshot(0)["contacts_access"] == "read"
        _, alone = _chat(None, perms)
        assert alone.snapshot(0)["contacts_access"] == "unavailable"

    async def test_without_the_permission_the_old_contacts_are_still_shown(self, books, perms):
        _, bridge = books
        app, chat = _chat(bridge, perms)
        app.state.add_contact(ADA)
        got = await asyncio.to_thread(chat.snapshot, 0)
        assert [c["id"] for c in got["contacts"]] == [ADA]
        assert bridge.state.find(ADA) == []        # nothing moved behind the person's back

    async def test_the_first_time_it_may_write_the_old_contacts_move_into_the_books(
            self, books, perms):
        _, bridge = books
        app, chat = _chat(bridge, perms)
        app.state.add_contact(ADA)
        app.state.add_contact(BOB)
        perms.set_grant(CHAT_HEX, "contacts.read", True)
        await asyncio.to_thread(chat.snapshot, 0)
        assert app.state.migrated is False         # read alone cannot move them
        assert bridge.state.find(ADA) == []
        perms.set_grant(CHAT_HEX, "contacts.write", True)
        await asyncio.to_thread(chat.snapshot, 0)
        assert app.state.migrated is True
        assert {n for n in (ADA, BOB) if bridge.state.find(n)} == {ADA, BOB}

    async def test_what_the_books_call_someone_is_what_chat_shows(self, books, perms):
        _, bridge = books
        app, chat = _chat(bridge, perms)
        perms.set_grant(CHAT_HEX, "contacts.read", True)
        perms.set_grant(CHAT_HEX, "contacts.write", True)
        bridge.state.add_node(ADA, "Ada at work")
        await asyncio.to_thread(chat.snapshot, 0)
        row = next(c for c in app.state.snapshot()["contacts"] if c["id"] == ADA)
        assert row["label"] == "Ada at work"
        # and what a node was taken out of the books for is gone from chat's copy
        bridge.state.remove_node(ADA)
        await asyncio.to_thread(chat.snapshot, 0)
        assert app.state.snapshot()["contacts"] == []

    async def test_saving_somebody_without_the_permission_names_the_permission(
            self, books, perms):
        _, bridge = books
        _, chat = _chat(bridge, perms)
        with pytest.raises(PermissionError) as refused:
            await asyncio.to_thread(chat.add_contact, ADA)
        assert str(refused.value) == "contacts.write"
        assert bridge.state.find(ADA) == []

    async def test_saving_somebody_with_it_puts_them_in_the_books(self, books, perms):
        _, bridge = books
        _, chat = _chat(bridge, perms)
        perms.set_grant(CHAT_HEX, "contacts.read", True)
        perms.set_grant(CHAT_HEX, "contacts.write", True)
        assert await asyncio.to_thread(chat.add_contact, ADA) is True
        assert bridge.state.find(ADA)

    async def test_removing_somebody_is_the_books_to_decide_too(self, books, perms):
        _, bridge = books
        _, chat = _chat(bridge, perms)
        perms.set_grant(CHAT_HEX, "contacts.read", True)
        with pytest.raises(PermissionError):
            await asyncio.to_thread(chat.remove_contact, ADA)

    async def test_a_saved_name_finds_somebody_the_network_has_never_heard_of(
            self, books, perms):
        """The books are searched first: a contact is found by the name its owner
        gave it, with nothing asked of the network."""
        _, bridge = books
        _, chat = _chat(bridge, perms)
        perms.set_grant(CHAT_HEX, "contacts.read", True)
        perms.set_grant(CHAT_HEX, "contacts.write", True)
        bridge.state.add_node(ADA, "Grace Hopper")
        hits = await asyncio.to_thread(chat.search_pseudo, "hopper")
        assert hits and hits[0]["id"] == ADA and hits[0]["pseudo"] == "Grace Hopper"
        assert hits[0]["match"] == -1

    async def test_the_peer_card_gives_the_name_the_person_chose(self, books, perms):
        _, bridge = books
        app, chat = _chat(bridge, perms)
        perms.set_grant(CHAT_HEX, "contacts.read", True)
        perms.set_grant(CHAT_HEX, "contacts.write", True)
        bridge.state.add_node(ADA, "Ada at work")
        await asyncio.to_thread(chat.snapshot, 0)
        got = chat.api_peer(ADA)
        assert got["contact"] is True and got["pseudo"] == "Ada at work"
        assert got["conversation"] == "/chat#c/" + ADA

    async def test_the_contact_operation_turns_a_refusal_into_an_api_error(
            self, books, perms):
        _, bridge = books
        _, chat = _chat(bridge, perms)
        with pytest.raises(app_api.AppAPIError):
            await asyncio.to_thread(chat.api_contact, ADA)


class TestOnlyTheOwnersOfAFieldWriteIt:
    def test_the_chat_copy_cannot_be_made_to_hold_garbage(self):
        state = ChatState()
        state.replace_contacts({ADA: "ok", "not-a-node": "x", BOB: "x" * 500, 7: "y"})
        ids = {c["id"] for c in state.snapshot()["contacts"]}
        assert ids == {ADA, BOB}
        assert all(len(c["label"]) <= 64 for c in state.snapshot()["contacts"])

    def test_replacing_the_copy_with_nothing_empties_it(self):
        state = ChatState()
        state.add_contact(ADA)
        state.replace_contacts({})
        assert state.snapshot()["contacts"] == []
        assert state.migrated is True
