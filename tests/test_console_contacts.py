"""
The console's side of the Contacts app: its page, its routes, its refusals.

A real server runs on an ephemeral loopback port and every HTTP call goes
through a worker thread (see ``test_console_fleet``). The app is built through an
:class:`AppHost` like the node does, so "the app is off" means what it means in
production: no page, no routes.
"""
import asyncio

import pytest

from src.app_registry import CONTACTS_APP_ID, AppHost, AppRegistry
from src.apps.contacts import ContactsApp
from src.apps.contacts_state import ContactsState
from src.apps.contacts_web import ContactsBridge
from src.node import MeshNode
from src.node_id import NodeID
from src.webconsole import WebConsole
from tests.conftest import make_manager
from tests.test_console_fleet import StubClient, _get, _post
from tests.test_webconsole import _login, PW

ME = NodeID(bytes([0x11]) * 20)
ADA = "aa" * 20
BOB = "bb" * 20


async def _make(enabled=True):
    node = MeshNode(transport_manager=make_manager())
    registry = AppRegistry(None)
    registry.set_enabled("contacts", enabled)
    host = AppHost(registry, app_storage=node.app_storage)

    async def build():
        app = ContactsApp(StubClient(), node_id=ME, state=ContactsState(me=ME.raw.hex()))
        return app, ContactsBridge(app)

    host.register("contacts", build)
    await host.apply()
    console = WebConsole(node, host="127.0.0.1", port=0, use_tls=False,
                         password=PW, app_host=host)
    console.start(loop=asyncio.get_running_loop())
    return node, console, host


@pytest.fixture
async def running():
    node, console, host = await _make()
    _, token = await _login(console)
    try:
        yield console, token
    finally:
        console.stop()
        await host.stop_all()
        await node.stop()


async def _book(console, token):
    status, _, _, body = await _get(console, "/api/contacts/state", token)
    assert status == 200
    return body["book"], body


class TestThePage:
    async def test_it_is_served_only_while_the_app_runs(self):
        node, console, host = await _make(enabled=False)
        try:
            for path in ("/contacts", "/contacts.js", "/contacts.css"):
                status, _, _, _ = await _get(console, path)
                assert status == 404, path
            _, token = await _login(console)
            status, _, _, _ = await _get(console, "/api/contacts/state", token)
            assert status == 404
        finally:
            console.stop(); await host.stop_all(); await node.stop()

    async def test_the_markup_is_public_and_the_api_is_not(self, running):
        console, token = running
        for path in ("/contacts", "/contacts.js", "/contacts.css"):
            status, _, body, _ = await _get(console, path)
            assert status == 200 and body, path
        for path in ("/api/contacts/state", "/api/contacts/people?q=ada",
                     "/api/contacts/export?book=" + "ab" * 16):
            status, _, _, _ = await _get(console, path)
            assert status == 401, path
        status, _, _, _ = await _post(console, "/api/contacts/save", None,
                                      {"book": "x", "name": "n"})
        assert status == 401

    async def test_the_page_loads_the_catalogue_after_the_theme(self):
        from src import webassets
        html = webassets.CONTACTS_HTML
        assert html.index('<script src="/theme.js">') < html.index('<script src="/i18n.js">')


class TestAddingAndReading:
    async def test_a_saved_contact_is_in_the_next_read(self, running):
        console, token = running
        book, _ = await _book(console, token)
        status, _, _, saved = await _post(console, "/api/contacts/save", token, {
            "book": book, "name": "Ada", "nodes": [{"id": ADA, "label": "phone"}], "note": "hi"})
        assert status == 200 and saved["ok"] is True
        _, state = await _book(console, token)
        assert [c["name"] for c in state["contacts"]] == ["Ada"]
        assert state["contacts"][0]["nodes"] == [{"id": ADA, "label": "phone"}]

    async def test_a_book_that_is_not_there_says_why_in_a_code(self, running):
        console, token = running
        status, _, _, body = await _post(console, "/api/contacts/save", token,
                                         {"book": "not-a-book", "name": "Ada"})
        assert status == 400 and body["why"] == "no_book" and body["ok"] is False

    async def test_a_contact_with_nothing_in_it_is_refused(self, running):
        console, token = running
        book, _ = await _book(console, token)
        status, _, _, body = await _post(console, "/api/contacts/save", token, {"book": book})
        assert status == 400 and body["why"] == "empty"

    async def test_an_id_that_is_not_a_node_is_refused(self, running):
        console, token = running
        book, _ = await _book(console, token)
        status, _, _, _ = await _post(console, "/api/contacts/save", token, {
            "book": book, "name": "Ada", "nodes": [{"id": "zz" * 20}]})
        # The entry is kept without the bad node rather than with a lie in it.
        _, state = await _book(console, token)
        assert all(n["id"] != "zz" * 20 for c in state["contacts"] for n in c["nodes"])

    async def test_people_search_finds_a_saved_contact_first(self, running):
        console, token = running
        book, _ = await _book(console, token)
        await _post(console, "/api/contacts/save", token,
                    {"book": book, "name": "Ada Lovelace", "nodes": [{"id": ADA}]})
        status, _, _, found = await _get(console, "/api/contacts/people?q=lovel", token)
        assert status == 200
        assert found["results"][0]["kind"] == "contact"
        assert found["results"][0]["name"] == "Ada Lovelace"


class TestExportAndImport:
    async def test_a_book_leaves_as_a_vcard_and_comes_back(self, running):
        console, token = running
        book, _ = await _book(console, token)
        await _post(console, "/api/contacts/save", token,
                    {"book": book, "name": "Ada", "nodes": [{"id": ADA, "label": "main"}]})
        status, headers, body, _ = await _get(
            console, "/api/contacts/export?book=" + book, token)
        assert status == 200 and headers["content-type"].startswith("text/vcard")
        assert "attachment" in headers["content-disposition"]
        text = body.decode()
        assert "BEGIN:VCARD" in text and ADA in text
        other = await _post(console, "/api/contacts/book", token,
                            {"action": "create", "name": "Copy"})
        target = other[3]["book"]
        status, _, _, done = await _post(console, "/api/contacts/import", token,
                                         {"book": target, "text": text})
        assert status == 200 and done["added"] == 1

    async def test_exporting_a_book_that_does_not_exist_is_a_404(self, running):
        console, token = running
        status, _, _, _ = await _get(console, "/api/contacts/export?book=nope", token)
        assert status == 404
        status, _, _, _ = await _get(console, "/api/contacts/export", token)
        assert status == 404

    async def test_an_import_larger_than_the_cap_is_refused(self, running):
        console, token = running
        book, _ = await _book(console, token)
        from tests.test_webconsole import _request
        big = b'{"book":"%s","text":"%s"}' % (book.encode(), b"A" * (2 * 1024 * 1024 + 4096))
        try:
            status, _, _, _ = await asyncio.to_thread(
                _request, console, "POST", "/api/contacts/import", token, None, big)
        except OSError:
            return              # the server stopped reading, which is the refusal
        assert status == 413


class TestHostileCalls:
    async def test_an_unknown_operation_is_a_404(self, running):
        console, token = running
        for op in ("nope", "", "../state", "do_save", "__init__", "state"):
            status, _, _, _ = await _post(console, "/api/contacts/" + op, token, {})
            assert status == 404, op

    @pytest.mark.parametrize("body", [
        {}, {"book": 5}, {"book": ["a"]}, {"id": {"a": 1}}, {"name": "x" * 100000},
        {"nodes": "nope"}, {"nodes": [5, None, {"id": 3}]}, {"action": 7},
        {"query": {"a": 1}}, {"text": 5}, {"role": "root", "node": ADA},
    ])
    async def test_nonsense_never_becomes_a_server_error(self, running, body):
        console, token = running
        for op in ("save", "delete", "move", "book", "share", "unshare", "answer",
                   "people", "import"):
            status, _, _, doc = await _post(console, "/api/contacts/" + op, token, body)
            assert status < 500, (op, status)
            assert isinstance(doc, dict)

    async def test_a_body_that_is_not_json_is_not_a_server_error(self, running):
        console, token = running
        from tests.test_webconsole import _request
        status, _, _, _ = await asyncio.to_thread(
            _request, console, "POST", "/api/contacts/save", token, None, b"\xff\xfe not json")
        assert status < 500

    async def test_only_the_owner_can_share(self, running):
        console, token = running
        book, _ = await _book(console, token)
        # sharing with this very node is refused rather than looped
        status, _, _, body = await _post(console, "/api/contacts/share", token,
                                         {"book": book, "node": ME.raw.hex(), "role": "read"})
        assert status == 400 and body["why"] == "self"
        status, _, _, body = await _post(console, "/api/contacts/share", token,
                                         {"book": book, "node": "nothex", "role": "read"})
        assert status == 400 and body["why"] == "bad_node"


class TestChatPermissionRefusal:
    async def test_a_denied_write_is_a_403_with_the_permission_named(self):
        """Chat asking to save somebody without the permission is not a failure
        of the request: the page turns the answer into the question a person
        answers."""
        from src.apps.chat import ChatApp
        from src.apps.chat_web import ChatBridge
        node = MeshNode(transport_manager=make_manager())

        class Link:
            def access(self):
                return "denied"

            def call(self, op, **kw):
                from src.apps import contacts_link
                raise contacts_link.Denied("contacts.write")

        bridge = ChatBridge(ChatApp(StubClient()), peer=NodeID(bytes(range(20))),
                            contacts=Link())
        console = WebConsole(node, host="127.0.0.1", port=0, use_tls=False,
                             password=PW, chat_bridge=bridge)
        console.start(loop=asyncio.get_running_loop())
        try:
            _, token = await _login(console)
            status, _, _, body = await _post(console, "/api/chat/contact", token,
                                             {"op": "add", "id": ADA})
            assert status == 403
            assert body == {"ok": False, "error": "permission", "permission": "contacts.write"}
        finally:
            console.stop(); await node.stop()
