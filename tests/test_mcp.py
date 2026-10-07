"""
The MCP app: tools generated from what the node lists, a protocol answered
correctly, and a door that is shut to everything but its own token.

* the tools are the catalogue's operations, minus the machinery, plus the apps'
  and the page routes — and nothing is listed that this app may not call;
* a refusal from the node is a tool result the model can read, never a
  protocol error;
* the JSON-RPC surface answers what the spec says and refuses the rest;
* over HTTP: no token, a foreign web page's ``Origin``, a body too large, a
  method it does not serve — each refused before anything is asked of the node;
* the bridge's three operations that carry the server's authority are a
  person's to call, never another app's.
"""
import asyncio
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request

import pytest

from src.apps import mcp
from src.apps.mcp import McpApp, McpBridge, build_tools

CATALOGUE = [
    {"module": "node", "operations": [
        {"name": "state", "summary": "What this node is doing", "params": [],
         "changes": False, "background": False, "timeout": 5},
        {"name": "retry", "summary": "Try the links again", "params": [],
         "changes": True, "background": True, "timeout": 60},
        {"name": "ping_node", "summary": "Ping one node",
         "params": [{"name": "node", "kind": "node", "required": True}],
         "changes": False, "background": False, "timeout": 5},
    ]},
    {"module": "control", "operations": [
        {"name": "catalogue", "summary": "", "params": [], "changes": False}]},
    {"module": "jobs", "operations": [
        {"name": "start", "summary": "", "params": [], "changes": True},
        {"name": "poll", "summary": "", "params": [], "changes": False}]},
    {"module": "apps", "operations": [
        {"name": "call", "summary": "", "params": [], "changes": True},
        {"name": "list", "summary": "The apps", "params": [], "changes": False}]},
    {"module": "web", "operations": [
        {"name": "request", "summary": "", "params": [], "changes": True}]},
    {"module": "trace", "operations": [
        {"name": "set", "summary": "Start or stop",
         "params": [{"name": "action", "kind": "choice", "choices": ["start", "stop"],
                     "required": True},
                    {"name": "seconds", "kind": "count", "limit": 600,
                     "required": False, "default": 0}],
         "changes": True, "background": False, "timeout": 5}]},
]
APPS = [{"app": "chat", "operations": [
    {"name": "peer", "summary": "What chat knows", "changes": False,
     "params": [{"name": "node", "kind": "node", "required": True}]}]}]
PAGES = [{"app": "chat", "title": "Chat", "routes": [
    {"method": "POST", "path": "/api/chat/send"},
    {"method": "GET", "path": "/api/chat/messages"}]}]


class FakeClient:
    """The connector client, answering from a table of replies."""

    def __init__(self, replies=None):
        self.replies = replies or {}
        self.asked = []

    async def connect(self):
        pass

    async def close(self):
        pass

    async def control(self, op, params=None, *, timeout=30.0):
        self.asked.append((op, params))
        answer = self.replies.get(op)
        if callable(answer):
            return answer(params or {})
        if answer is None:
            return {"ok": False, "code": "refused", "error": f"{op} needs a permission"}
        return {"ok": True, "result": answer}


def _replies(**extra):
    table = {"control.catalogue": {"modules": CATALOGUE},
             "apps.catalogue": {"apps": APPS},
             "web.routes": {"apps": PAGES},
             "node.state": {"id": "ab" * 20, "uptime": 3}}
    table.update(extra)
    return table


async def _running(replies=None, store=None):
    app = McpApp(FakeClient(replies if replies is not None else _replies()),
                 store=store)
    app.port = 0
    await app.start()
    return app


def _post(app, body, *, token=None, origin=None, raw=None, method="POST"):
    data = raw if raw is not None else json.dumps(body).encode()
    request = urllib.request.Request(f"http://127.0.0.1:{app.port}/mcp",
                                     data=data if method == "POST" else None,
                                     method=method)
    request.add_header("Content-Type", "application/json")
    if token is not False:
        request.add_header("Authorization", "Bearer " + (token or app.token))
    if origin:
        request.add_header("Origin", origin)
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            payload = response.read()
            return response.status, json.loads(payload) if payload else None
    except urllib.error.HTTPError as error:
        payload = error.read()
        return error.code, json.loads(payload) if payload else None


class TestToolsComeFromTheCatalogue:
    def test_operations_become_tools_and_machinery_does_not(self):
        tools = build_tools(CATALOGUE, APPS, PAGES)
        assert {"node_state", "node_retry", "node_ping_node", "trace_set",
                "apps_list"} <= set(tools)
        for machinery in ("control_catalogue", "jobs_start", "jobs_poll",
                          "apps_call", "web_request"):
            assert machinery not in tools
        assert "app_chat_peer" in tools
        assert {"web_chat_post_send", "web_chat_get_messages"} <= set(tools)

    def test_a_schema_follows_the_declaration(self):
        tools = build_tools(CATALOGUE, [], [])
        schema = tools["trace_set"][0]["inputSchema"]
        assert schema["properties"]["action"]["enum"] == ["start", "stop"]
        assert schema["properties"]["seconds"]["maximum"] == 600
        assert schema["required"] == ["action"]
        assert schema["additionalProperties"] is False
        node = tools["node_ping_node"][0]["inputSchema"]["properties"]["node"]
        assert node["pattern"] == "^[0-9a-f]{40}$"

    def test_a_tool_says_whether_it_changes_anything(self):
        tools = build_tools(CATALOGUE, [], [])
        assert tools["node_state"][0]["annotations"]["readOnlyHint"] is True
        assert tools["trace_set"][0]["annotations"]["destructiveHint"] is True
        assert "job" in tools["node_retry"][0]["description"]
        assert tools["node_retry"][1]["background"] is True

    def test_the_list_is_bounded(self):
        many = [{"module": "m", "operations": [
            {"name": f"op{index}", "summary": "", "params": [], "changes": False}
            for index in range(mcp.MAX_TOOLS + 50)]}]
        assert len(build_tools(many, [], [])) == mcp.MAX_TOOLS


class TestAPageRouteIsCalledAsDeclared:
    """What the bridge sends to `web.request` must bind against the module's
    own declaration — a GET has no body, and a null one was refused."""

    @staticmethod
    def _answer(params):
        from src.control.modules.web import WebModule
        from src.control.params import ControlError, bind
        declared = next(op for op in WebModule.OPERATIONS
                        if op["name"] == "request")["params"]
        try:
            return {"ok": True, "result": {"bound": bind(declared, params)}}
        except ControlError as exc:
            return {"ok": False, "code": exc.code, "error": exc.message}

    async def _call(self, name, arguments):
        app = await _running(_replies(**{"web.request": self._answer}))
        try:
            result = await asyncio.to_thread(app.call_tool, name, arguments)
        finally:
            await app.stop()
        sent = [params for op, params in app._client.asked if op == "web.request"]
        return result, sent

    async def test_a_get_without_a_body_binds(self):
        result, sent = await self._call("web_chat_get_messages", {})
        assert result["isError"] is False, result
        assert "body" not in sent[0]

    async def test_a_post_carries_its_body(self):
        result, sent = await self._call("web_chat_post_send", {"body": {"text": "hi"}})
        assert result["isError"] is False, result
        assert sent[0]["body"] == {"text": "hi"}


class TestTheProtocol:
    async def test_initialize_agrees_on_a_version(self):
        app = McpApp(FakeClient(_replies()))
        answer = app.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                             "params": {"protocolVersion": "2025-03-26"}})
        assert answer["result"]["protocolVersion"] == "2025-03-26"
        assert "tools" in answer["result"]["capabilities"]
        unknown = app.handle({"jsonrpc": "2.0", "id": 2, "method": "initialize",
                              "params": {"protocolVersion": "1999-01-01"}})
        assert unknown["result"]["protocolVersion"] == mcp.VERSIONS[0]

    @pytest.mark.parametrize("message,code", [
        ({"id": 1, "method": "ping"}, -32600),
        ({"jsonrpc": "1.0", "id": 1, "method": "ping"}, -32600),
        ({"jsonrpc": "2.0", "id": 1}, -32600),
        ({"jsonrpc": "2.0", "id": 1, "method": "nothing/here"}, -32601),
        ({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {}}, -32602),
        ("a string", -32600), (7, -32600), (None, -32600),
    ])
    def test_what_is_not_a_request_is_refused(self, message, code):
        answer = McpApp(FakeClient()).handle(message)
        assert answer["error"]["code"] == code

    def test_a_notification_and_a_response_are_not_answered(self):
        app = McpApp(FakeClient())
        assert app.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None
        assert app.handle({"jsonrpc": "2.0", "id": 4, "result": {}}) is None

    async def test_a_tool_call_answers_what_the_node_answered(self):
        app = await _running()
        try:
            listed = await asyncio.to_thread(app.handle, {
                "jsonrpc": "2.0", "id": 1, "method": "tools/list"})
            assert "node_state" in [tool["name"] for tool in listed["result"]["tools"]]
            called = await asyncio.to_thread(app.handle, {
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": "node_state", "arguments": {}}})
            result = called["result"]
            assert result["isError"] is False
            assert result["structuredContent"]["uptime"] == 3
        finally:
            await app.stop()

    async def test_a_refusal_is_a_result_the_model_can_read(self):
        app = await _running()
        try:
            called = await asyncio.to_thread(app.handle, {
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": "trace_set", "arguments": {"action": "start"}}})
            assert called["result"]["isError"] is True
            assert "permission" in called["result"]["content"][0]["text"]
        finally:
            await app.stop()

    async def test_a_job_is_started_and_polled_to_its_end(self, monkeypatch):
        monkeypatch.setattr(mcp, "_POLL", 0.01)
        polls = iter([{"state": "running"}, {"state": "done", "result": {"retried": 4}}])
        app = await _running(_replies(**{
            "jobs.start": {"job": "j1", "state": "running"},
            "jobs.poll": lambda params: {"ok": True, "result": next(polls)}}))
        try:
            called = await asyncio.to_thread(app.call_tool, "node_retry", {})
            assert called["structuredContent"] == {"retried": 4}
            assert ("jobs.start", {"op": "node.retry", "params": {}}) in app._client.asked
        finally:
            await app.stop()

    async def test_routes_are_offered_only_to_a_server_that_may_call_them(self):
        without = [module for module in CATALOGUE if module["module"] != "web"]
        app = await _running(_replies(**{"control.catalogue": {"modules": without}}))
        try:
            tools = await asyncio.to_thread(app.tools, True)
            assert not any(name.startswith("web_") for name in tools)
        finally:
            await app.stop()


class TestTheDoor:
    async def test_a_request_without_the_token_is_refused(self):
        app = await _running()
        try:
            ping = {"jsonrpc": "2.0", "id": 1, "method": "ping"}
            assert (await asyncio.to_thread(_post, app, ping, token=False))[0] == 401
            assert (await asyncio.to_thread(_post, app, ping, token="mcp-wrong"))[0] == 401
            status, answer = await asyncio.to_thread(_post, app, ping)
            assert status == 200 and answer["result"] == {}
        finally:
            await app.stop()

    async def test_a_web_page_elsewhere_is_refused_before_the_token(self):
        """DNS rebinding: a page on another site that a browser sends here."""
        app = await _running()
        try:
            ping = {"jsonrpc": "2.0", "id": 1, "method": "ping"}
            assert (await asyncio.to_thread(_post, app, ping,
                                            origin="https://evil.example"))[0] == 403
            assert (await asyncio.to_thread(_post, app, ping,
                                            origin="http://localhost:3000"))[0] == 200
        finally:
            await app.stop()

    async def test_the_rest_of_the_surface(self):
        app = await _running()
        try:
            assert (await asyncio.to_thread(_post, app, None, method="GET"))[0] == 405
            status, answer = await asyncio.to_thread(_post, app, None, raw=b"{not json")
            assert status == 400 and answer["error"]["code"] == -32700
            assert (await asyncio.to_thread(
                _post, app, None, raw=b" " * (mcp.MAX_BODY + 1)))[0] == 413
            assert (await asyncio.to_thread(
                _post, app, {"jsonrpc": "2.0", "method": "notifications/initialized"}))[0] == 202
            status, answers = await asyncio.to_thread(_post, app, [
                {"jsonrpc": "2.0", "id": 1, "method": "ping"},
                {"jsonrpc": "2.0", "method": "notifications/x"}])
            assert status == 200 and [entry["id"] for entry in answers] == [1]
            assert (await asyncio.to_thread(_post, app, []))[0] == 400
            assert (await asyncio.to_thread(
                _post, app, [{"jsonrpc": "2.0", "id": 1, "method": "ping"}] * 40))[0] == 400
        finally:
            await app.stop()

    async def test_a_port_already_taken_is_said_not_fatal(self):
        first = await _running()
        second = McpApp(FakeClient(_replies()))
        try:
            second.port = first.port
            await second.start()
            assert second.status()["running"] is False
            assert "cannot listen" in second.status()["error"]
        finally:
            await second.stop()
            await first.stop()

    async def test_the_token_lives_in_the_drawer_and_survives(self):
        drawer = {}
        store = (drawer.get, drawer.__setitem__)
        app = await _running(store=store)
        token = app.token
        await app.stop()
        again = await _running(store=store)
        try:
            assert again.token == token and token.startswith("mcp-")
            assert again.rotate() != token
        finally:
            await again.stop()


class TestTheBridge:
    def test_what_carries_the_servers_authority_is_a_persons(self):
        declared = {row["name"]: row for row in McpBridge.API}
        for name in ("token", "rotate", "configure"):
            assert declared[name]["operator"] is True
            assert declared[name]["remote"] is False
        assert declared["status"]["operator"] is False

    def test_a_host_must_be_an_address(self):
        app = McpApp(FakeClient())
        for bad in ("", "a b", "x" * 80, "host;rm", "http://x"):
            with pytest.raises(Exception):
                app.configure(bad, 8790)
        with pytest.raises(Exception):
            app.configure("127.0.0.1", 70000)


class TestTheStdioBridge:
    async def test_lines_in_answers_out(self):
        app = await _running()
        script = os.path.join(os.path.dirname(os.path.dirname(__file__)),
                              "scripts", "nmesh_mcp_stdio.py")
        lines = "\n".join(json.dumps(message) for message in (
            {"jsonrpc": "2.0", "id": 1, "method": "ping"},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
             "params": {"name": "node_state", "arguments": {}}})) + "\n"
        try:
            result = await asyncio.to_thread(
                subprocess.run, [sys.executable, script], input=lines,
                capture_output=True, text=True, timeout=30,
                env=dict(os.environ, NMESH_MCP_URL=f"http://127.0.0.1:{app.port}/mcp",
                         NMESH_MCP_TOKEN=app.token))
            answers = [json.loads(line) for line in result.stdout.splitlines()]
            assert [answer["id"] for answer in answers] == [1, 2]
            assert answers[1]["result"]["isError"] is False
            refused = await asyncio.to_thread(
                subprocess.run, [sys.executable, script], input=lines,
                capture_output=True, text=True, timeout=30,
                env=dict(os.environ, NMESH_MCP_URL=f"http://127.0.0.1:{app.port}/mcp",
                         NMESH_MCP_TOKEN="mcp-wrong"))
            assert "error" in json.loads(refused.stdout.splitlines()[0])
        finally:
            await app.stop()


class TestTheServerIsBounded:
    async def test_past_its_ceiling_a_request_is_told_to_come_back(self, monkeypatch):
        app = await _running()
        try:
            for _ in range(mcp.MAX_INFLIGHT):
                assert app._inflight.acquire(blocking=False)
            status, _answer = await asyncio.to_thread(
                _post, app, {"jsonrpc": "2.0", "id": 1, "method": "ping"})
            assert status == 503
            app._inflight.release()
            status, _answer = await asyncio.to_thread(
                _post, app, {"jsonrpc": "2.0", "id": 1, "method": "ping"})
            assert status == 200
        finally:
            await app.stop()
