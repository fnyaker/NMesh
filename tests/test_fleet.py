"""
Fleet application tests — the authorisation surface above all.

The fleet app grants remote code execution, so the tests that matter most are
the ones proving a command does **not** run: unenrolled sender, missing
capability, unsigned frame, edited body, replayed signature, signature minted
for another node or another purpose, reply nobody asked for. Each of the three
gates (mesh authentication, ledger enrolment, per-command signature) is checked
in isolation, so none of them can quietly stop pulling its weight.
"""
import asyncio
import base64
import json
import os
import random

import pytest

from src.app_auth import AppAuth, ctx_hash, make_assertion
from src.apps import fleet
from src.apps.fleet import (
    CapsChanged, CommandResult, ConsoleProxyError, EnrolAnswered, EnrolRequested,
    FleetApp, Failure, NodeAdopted, Revoked, ScanReceived, StatusReceived,
    console_path_refusal,
)
from src.apps.fleet_state import CAPABILITIES, FleetState
from src.apps import fleet_provision
from src.crypto import CryptoIdentity
from src.node_id import NodeID


class StubClient:
    def __init__(self):
        self.sent = []

    async def send(self, target, payload):
        self.sent.append((target, payload))

    async def recv(self):
        await asyncio.sleep(3600)

    async def close(self):
        pass


class Peer:
    """One node running the fleet app, with its identity and stub transport."""

    def __init__(self, repo_root=None):
        self.identity = CryptoIdentity()
        self.id = NodeID.from_public_key(self.identity.dsa_public_key)
        self.client = StubClient()
        self.app = FleetApp(self.client,
                            AppAuth(self.identity, fleet.FLEET_APP_ID, self.id),
                            state=FleetState(), repo_root=repo_root,
                            auto_status=False)

    def drain_events(self):
        out = []
        while not self.app._events.empty():
            out.append(self.app._events.get_nowait())
        return out

    def take_sent(self):
        out = list(self.client.sent)
        self.client.sent.clear()
        return out


async def settle():
    """Let the app's spawned reply tasks run."""
    for _ in range(8):
        await asyncio.sleep(0)


async def deliver(sender: Peer, receiver: Peer) -> None:
    """Hand everything ``sender`` emitted to ``receiver``'s dispatcher."""
    await settle()
    for _target, payload in sender.take_sent():
        receiver.app._dispatch(sender.id, payload)
    await settle()


@pytest.fixture
def operator():
    return Peer()


@pytest.fixture
def agent():
    return Peer()


async def enrol(operator: Peer, agent: Peer, caps=("status",), grant=None):
    """Drive a full enrolment and return the capabilities actually granted."""
    await operator.app.request_enrolment(agent.id, caps=list(caps), label="lab")
    await deliver(operator, agent)
    await agent.app.approve_enrolment(operator.id.raw.hex(),
                                      list(grant) if grant else None)
    await deliver(agent, operator)
    return agent.app.state.operator(operator.id.raw.hex())


# ---------------------------------------------------------------------------
# Enrolment — the trust hand-off
# ---------------------------------------------------------------------------

class TestEnrolment:
    async def test_request_raises_a_notification_not_a_grant(self, operator, agent):
        await operator.app.request_enrolment(agent.id, caps=["status", "shell"],
                                             label="my laptop")
        await deliver(operator, agent)
        events = [e for e in agent.drain_events() if isinstance(e, EnrolRequested)]
        assert len(events) == 1
        assert set(events[0].caps) == {"status", "shell"}
        assert events[0].label == "my laptop"
        # Nothing is granted until a human answers.
        assert agent.app.state.operator(operator.id.raw.hex()) is None
        assert agent.app.state.allows(operator.id.raw.hex(), "status") is False
        assert len(agent.app.state.pending_in()) == 1

    async def test_approval_establishes_both_sides(self, operator, agent):
        entry = await enrol(operator, agent, caps=["status", "update"])
        assert entry is not None and set(entry["caps"]) == {"status", "update"}
        managed = operator.app.state.managed_one(agent.id.raw.hex())
        assert managed is not None and set(managed["caps"]) == {"status", "update"}
        answered = [e for e in operator.drain_events()
                    if isinstance(e, EnrolAnswered)]
        assert answered and answered[0].granted is True

    async def test_approval_can_narrow_but_never_widen(self, operator, agent):
        # Asked for status only; the approver tries to hand over a shell too.
        entry = await enrol(operator, agent, caps=["status"],
                            grant=["status", "shell"])
        assert set(entry["caps"]) == {"status"}
        assert agent.app.state.allows(operator.id.raw.hex(), "shell") is False

    async def test_denial_leaves_nothing_behind(self, operator, agent):
        await operator.app.request_enrolment(agent.id, caps=["shell"])
        await deliver(operator, agent)
        assert await agent.app.deny_enrolment(operator.id.raw.hex(), "no") is True
        await deliver(agent, operator)
        assert agent.app.state.operator(operator.id.raw.hex()) is None
        assert operator.app.state.managed_one(agent.id.raw.hex()) is None
        answered = [e for e in operator.drain_events()
                    if isinstance(e, EnrolAnswered)]
        assert answered and answered[0].granted is False

    async def test_unsolicited_grant_is_ignored(self, operator, agent):
        """A node we never asked cannot plant itself in our managed list."""
        await agent.app._send(operator.id, agent.app._signed_frame(
            fleet.ENROL_GRANT, operator.id, fleet.PURPOSE_GRANT,
            {"caps": ["shell"], "label": "surprise"}))
        await deliver(agent, operator)
        assert operator.app.state.managed_one(agent.id.raw.hex()) is None

    async def test_repeated_requests_do_not_grow_the_queue(self, operator, agent):
        for _ in range(20):
            await operator.app.request_enrolment(agent.id, caps=["status"])
            await deliver(operator, agent)
        assert len(agent.app.state.pending_in()) == 1

    async def test_revoke_clears_both_directions(self, operator, agent):
        await enrol(operator, agent, caps=["status"])
        assert await operator.app.revoke(agent.id.raw.hex()) is True
        await deliver(operator, agent)
        assert operator.app.state.managed_one(agent.id.raw.hex()) is None
        assert agent.app.state.operator(operator.id.raw.hex()) is None
        assert agent.app.state.allows(operator.id.raw.hex(), "status") is False
        assert any(isinstance(e, Revoked) for e in agent.drain_events())


# ---------------------------------------------------------------------------
# Changing the rights on a standing relationship
# ---------------------------------------------------------------------------

class TestCapabilityChanges:
    """The asymmetry is the whole point: a right can be handed back by whoever
    holds it, but only ever handed *out* by a human on the machine that pays
    for it. Every test here exists to keep one half from drifting into the
    other."""

    async def test_asking_for_more_grants_nothing_on_its_own(self, operator, agent):
        await enrol(operator, agent, caps=["status"])
        assert await operator.app.request_capabilities(agent.id, ["shell"]) is True
        await deliver(operator, agent)
        # Parked for a human, and the ledger is untouched until they answer.
        assert agent.app.state.allows(operator.id.raw.hex(), "shell") is False
        assert set(agent.app.state.operator(operator.id.raw.hex())["caps"]) == {"status"}
        pending = agent.app.state.pending_in()
        assert len(pending) == 1
        assert set(pending[0]["caps"]) == {"status", "shell"}
        # The human is told what they already hold, so the delta is visible.
        assert pending[0]["have"] == ["status"]

    async def test_approving_the_request_widens_both_sides(self, operator, agent):
        await enrol(operator, agent, caps=["status"])
        await operator.app.request_capabilities(agent.id, ["update"])
        await deliver(operator, agent)
        assert await agent.app.approve_enrolment(operator.id.raw.hex()) is True
        await deliver(agent, operator)
        assert agent.app.state.allows(operator.id.raw.hex(), "update") is True
        managed = operator.app.state.managed_one(agent.id.raw.hex())
        assert set(managed["caps"]) == {"status", "update"}

    async def test_the_approver_still_cannot_be_talked_into_more(self, operator, agent):
        await enrol(operator, agent, caps=["status"])
        await operator.app.request_capabilities(agent.id, ["update"])
        await deliver(operator, agent)
        # A human ticking a box that was never asked for changes nothing:
        # approval intersects with the request.
        await agent.app.approve_enrolment(operator.id.raw.hex(),
                                          ["status", "update", "shell"])
        assert agent.app.state.allows(operator.id.raw.hex(), "shell") is False

    async def test_asking_for_a_node_we_do_not_manage_is_refused(self, operator, agent):
        assert await operator.app.request_capabilities(agent.id, ["shell"]) is False
        assert operator.take_sent() == []

    async def test_asking_for_what_we_hold_sends_nothing(self, operator, agent):
        await enrol(operator, agent, caps=["status"])
        operator.take_sent()
        assert await operator.app.request_capabilities(agent.id, ["status"]) is False
        assert operator.take_sent() == []

    async def test_dropping_a_right_needs_nobody(self, operator, agent):
        await enrol(operator, agent, caps=["status", "shell"])
        assert await operator.app.drop_capabilities(
            agent.id.raw.hex(), ["shell"]) is True
        await deliver(operator, agent)
        assert agent.app.state.allows(operator.id.raw.hex(), "shell") is False
        assert agent.app.state.allows(operator.id.raw.hex(), "status") is True
        assert set(operator.app.state.managed_one(
            agent.id.raw.hex())["caps"]) == {"status"}
        assert any(isinstance(e, CapsChanged) for e in agent.drain_events())

    async def test_dropping_the_last_right_ends_the_relationship(self, operator, agent):
        await enrol(operator, agent, caps=["status"])
        assert await operator.app.drop_capabilities(
            agent.id.raw.hex(), ["status"]) is True
        await deliver(operator, agent)
        assert agent.app.state.operator(operator.id.raw.hex()) is None
        assert operator.app.state.managed_one(agent.id.raw.hex()) is None

    async def test_a_narrow_frame_can_only_narrow(self, operator, agent):
        """The one frame accepted without a human. Even minted correctly by the
        operator, asking for more through it must widen nothing."""
        await enrol(operator, agent, caps=["status"])
        await operator.app._send(agent.id, operator.app._signed_frame(
            fleet.ENROL_NARROW, agent.id, fleet.PURPOSE_NARROW,
            {"caps": ["status", "shell", "provision"]}))
        await deliver(operator, agent)
        assert set(agent.app.state.operator(
            operator.id.raw.hex())["caps"]) == {"status"}
        assert agent.app.state.allows(operator.id.raw.hex(), "shell") is False

    async def test_a_narrow_frame_from_a_stranger_does_nothing(self, operator, agent):
        stranger = Peer()
        await enrol(operator, agent, caps=["status"])
        await stranger.app._send(agent.id, stranger.app._signed_frame(
            fleet.ENROL_NARROW, agent.id, fleet.PURPOSE_NARROW, {"caps": []}))
        await deliver(stranger, agent)
        assert agent.app.state.allows(operator.id.raw.hex(), "status") is True

    async def test_local_human_can_widen_and_the_operator_learns_of_it(
            self, operator, agent):
        await enrol(operator, agent, caps=["status"])
        assert await agent.app.set_operator_capabilities(
            operator.id.raw.hex(), ["status", "update"]) is True
        await deliver(agent, operator)
        assert agent.app.state.allows(operator.id.raw.hex(), "update") is True
        assert set(operator.app.state.managed_one(
            agent.id.raw.hex())["caps"]) == {"status", "update"}

    async def test_local_human_can_narrow(self, operator, agent):
        await enrol(operator, agent, caps=["status", "update"])
        await agent.app.set_operator_capabilities(operator.id.raw.hex(), ["status"])
        await deliver(agent, operator)
        assert agent.app.state.allows(operator.id.raw.hex(), "update") is False
        assert set(operator.app.state.managed_one(
            agent.id.raw.hex())["caps"]) == {"status"}

    async def test_local_human_emptying_the_list_cuts_the_node_off(
            self, operator, agent):
        await enrol(operator, agent, caps=["status"])
        assert await agent.app.set_operator_capabilities(
            operator.id.raw.hex(), []) is True
        await deliver(agent, operator)
        assert agent.app.state.operator(operator.id.raw.hex()) is None
        assert operator.app.state.managed_one(agent.id.raw.hex()) is None

    async def test_an_unknown_name_is_not_read_as_no_rights(self, operator, agent):
        """Fail-safe would be to cut them off; that turns a typo into an outage.
        A list we did not understand is refused instead."""
        await enrol(operator, agent, caps=["status"])
        assert await agent.app.set_operator_capabilities(
            operator.id.raw.hex(), ["root"]) is False
        assert agent.app.state.allows(operator.id.raw.hex(), "status") is True

    async def test_setting_rights_on_a_stranger_does_nothing(self, operator, agent):
        assert await agent.app.set_operator_capabilities(
            operator.id.raw.hex(), ["shell"]) is False
        assert agent.app.state.operator(operator.id.raw.hex()) is None

    async def test_losing_shell_kills_the_shell_already_open(self, operator, agent):
        await enrol(operator, agent, caps=["shell"])
        await operator.app.open_shell(agent.id, cols=80, rows=24)
        await deliver(operator, agent)
        assert agent.app._shells, "the agent should be hosting a shell"
        await agent.app.set_operator_capabilities(operator.id.raw.hex(), ["status"])
        assert agent.app._shells == {}

    async def test_a_still_managed_node_may_restate_its_grant(self, operator, agent):
        """How a human on the far side reaches our list — and only for their own
        entry: it is their own signed frame that carries it."""
        await enrol(operator, agent, caps=["status"])
        await agent.app._send(operator.id, agent.app._signed_frame(
            fleet.ENROL_GRANT, operator.id, fleet.PURPOSE_GRANT,
            {"caps": ["status", "scan"], "label": "lab"}))
        await deliver(agent, operator)
        assert set(operator.app.state.managed_one(
            agent.id.raw.hex())["caps"]) == {"status", "scan"}
        assert any(isinstance(e, CapsChanged) and e.direction == "managed"
                   for e in operator.drain_events())


# ---------------------------------------------------------------------------
# Remote console — the `manage` capability
# ---------------------------------------------------------------------------

class StubConsole:
    """Stands in for the node's own console: records calls, answers canned."""

    def __init__(self, status=200, body=b'{"ok":true}', ctype="application/json"):
        self.calls = []
        self.status, self.body, self.ctype = status, body, ctype
        self.available = True

    def call(self, method, path, body, token, timeout=None):
        self.calls.append((method, path, body, token))
        return self.status, self.ctype, self.body


async def deliver_both(a: Peer, b: Peer, rounds: int = 6) -> None:
    """Pump frames in both directions — a call and its answer need both."""
    for _ in range(rounds):
        await deliver(a, b)
        await deliver(b, a)


class TestRemoteConsolePaths:
    """What may be reached through the proxy is decided by a pure function, so
    it can be checked without a mesh in the way."""

    @pytest.mark.parametrize("path", [
        "/api/state", "/api/nodes?scope=active", "/api/config", "/api/trace",
        "/api/password", "/api/update/check", "/api/apps/enable",
    ])
    def test_the_console_api_is_reachable(self, path):
        assert console_path_refusal(path) == ""

    @pytest.mark.parametrize("path", [
        "/api/fleet/state",            # a managed node is not a jump host
        "/api/fleet/shell",
        "/api/remote/connect",         # the proxy driving the proxy
        "/api/chat/messages",          # not what the grant was asked for
        "/", "/style.css", "/fleet", "/../etc/passwd", "",
    ])
    def test_everything_else_is_refused(self, path):
        assert console_path_refusal(path) != ""


class TestRemoteConsole:
    async def test_without_the_capability_nothing_is_relayed(self, operator, agent):
        agent.app._local_console = StubConsole()
        await enrol(operator, agent, caps=["status"])
        operator.take_sent()
        task = asyncio.ensure_future(
            operator.app.console_call(agent.id, "GET", "/api/state"))
        await deliver_both(operator, agent)
        with pytest.raises(ConsoleProxyError) as failure:
            await task
        assert "not authorised for manage" in str(failure.value)
        assert agent.app._local_console.calls == []

    async def test_a_granted_call_reaches_the_console_and_comes_back(
            self, operator, agent):
        console = StubConsole(body=b'{"id":"abc"}')
        agent.app._local_console = console
        await enrol(operator, agent, caps=["manage"])
        task = asyncio.ensure_future(operator.app.console_call(
            agent.id, "GET", "/api/state", token="remote-token"))
        await deliver_both(operator, agent)
        status, ctype, body = await task
        assert (status, body) == (200, b'{"id":"abc"}')
        assert ctype.startswith("application/json")
        # The token travels with the call: the agent mints nothing of its own.
        assert console.calls == [("GET", "/api/state", None, "remote-token")]

    async def test_the_answer_is_chunked_and_reassembled(self, operator, agent):
        """One console snapshot on a busy node does not fit a single frame."""
        payload = bytes(range(256)) * 400            # ~100 KiB, > one frame
        agent.app._local_console = StubConsole(body=payload)
        await enrol(operator, agent, caps=["manage"])
        task = asyncio.ensure_future(
            operator.app.console_call(agent.id, "GET", "/api/state"))
        await deliver_both(operator, agent, rounds=12)
        _status, _ctype, body = await task
        assert body == payload

    async def test_an_answer_beyond_the_ceiling_is_explained_not_truncated(
            self, operator, agent):
        """Half a JSON document with no explanation is the worst outcome."""
        agent.app._local_console = StubConsole(body=b"x" * (fleet.CONSOLE_RESP_MAX + 5000))
        await enrol(operator, agent, caps=["manage"])
        task = asyncio.ensure_future(
            operator.app.console_call(agent.id, "GET", "/api/state"))
        await deliver_both(operator, agent, rounds=8)
        status, _ctype, body = await asyncio.wait_for(task, 2.0)
        assert status == 502
        assert b"too large" in body

    async def test_an_agent_flooding_chunks_is_cut_off(self, operator, agent):
        """The ceiling holds on our side too: the answer comes from a machine we
        do not control, and it can lie about how much is left."""
        agent.app._local_console = StubConsole()
        await enrol(operator, agent, caps=["manage"])
        task = asyncio.ensure_future(
            operator.app.console_call(agent.id, "GET", "/api/state"))
        await settle()
        rid = next(iter(operator.app._console_calls))
        chunk = base64.b64encode(b"x" * 32768).decode()
        for seq in range(fleet.CONSOLE_RESP_MAX // 32768 + 2):
            agent.app._reply(operator.id, fleet.CONSOLE_REPLY, {
                "rid": rid, "status": 200, "seq": seq, "more": True,
                "body": chunk})
        await deliver(agent, operator)
        with pytest.raises(ConsoleProxyError) as failure:
            await asyncio.wait_for(task, 2.0)
        assert "too large" in str(failure.value)

    async def test_an_oversized_request_never_leaves(self, operator, agent):
        await enrol(operator, agent, caps=["manage"])
        operator.take_sent()
        with pytest.raises(ConsoleProxyError):
            await operator.app.console_call(agent.id, "POST", "/api/store/publish",
                                            body=b"x" * (fleet.CONSOLE_REQ_MAX + 1))
        assert operator.take_sent() == []

    async def test_a_denied_path_is_refused_by_the_agent(self, operator, agent):
        console = StubConsole()
        agent.app._local_console = console
        await enrol(operator, agent, caps=["manage"])
        task = asyncio.ensure_future(
            operator.app.console_call(agent.id, "GET", "/api/fleet/state"))
        await deliver_both(operator, agent)
        with pytest.raises(ConsoleProxyError):
            await task
        assert console.calls == []

    async def test_only_get_and_post_are_relayed(self, operator, agent):
        console = StubConsole()
        agent.app._local_console = console
        await enrol(operator, agent, caps=["manage"])
        task = asyncio.ensure_future(
            operator.app.console_call(agent.id, "DELETE", "/api/state"))
        await deliver_both(operator, agent)
        with pytest.raises(ConsoleProxyError):
            await task
        assert console.calls == []

    async def test_a_node_without_a_console_says_so(self, operator, agent):
        await enrol(operator, agent, caps=["manage"])
        task = asyncio.ensure_future(
            operator.app.console_call(agent.id, "GET", "/api/state"))
        await deliver_both(operator, agent)
        with pytest.raises(ConsoleProxyError) as failure:
            await task
        assert "no console" in str(failure.value)

    async def test_an_unsolicited_answer_is_dropped(self, operator, agent):
        """A reply nobody asked for must not resolve a call, nor crash."""
        await enrol(operator, agent, caps=["manage"])
        agent.app._reply(operator.id, fleet.CONSOLE_REPLY, {
            "rid": "deadbeefdeadbeef", "status": 200, "seq": 0, "more": False,
            "ctype": "application/json", "body": ""})
        await deliver(agent, operator)
        assert operator.app._console_calls == {}

    async def test_an_answer_from_another_node_is_dropped(self, operator, agent):
        """The rid is real, the sender is not — that is a forged answer."""
        stranger = Peer()
        agent.app._local_console = StubConsole()
        await enrol(operator, agent, caps=["manage"])
        task = asyncio.ensure_future(
            operator.app.console_call(agent.id, "GET", "/api/state"))
        await settle()
        rid = next(iter(operator.app._console_calls))
        stranger.app._reply(operator.id, fleet.CONSOLE_REPLY, {
            "rid": rid, "status": 200, "seq": 0, "more": False,
            "body": base64.b64encode(b'{"id":"forged"}').decode()})
        await deliver(stranger, operator)
        assert not operator.app._console_calls[rid]["future"].done()
        # The real answer still lands.
        await deliver_both(operator, agent)
        _status, _ctype, body = await task
        assert b"forged" not in body

    async def test_the_agent_bounds_concurrent_calls(self, operator, agent):
        """A peer holding `manage` cannot open unbounded local sockets."""
        agent.app._local_console = StubConsole()
        await enrol(operator, agent, caps=["manage"])
        agent.app._console_hosted[operator.id.raw.hex()] = fleet.MAX_CONSOLE_CALLS
        task = asyncio.ensure_future(
            operator.app.console_call(agent.id, "GET", "/api/state"))
        await deliver_both(operator, agent)
        with pytest.raises(ConsoleProxyError) as failure:
            await task
        assert "in flight" in str(failure.value)


# ---------------------------------------------------------------------------
# Gate 2 — the ledger
# ---------------------------------------------------------------------------

class TestEnrolmentGate:
    async def test_unenrolled_operator_is_refused(self, operator, agent):
        await operator.app.request_status(agent.id)
        await deliver(operator, agent)
        await deliver(agent, operator)
        failures = [e for e in operator.drain_events() if isinstance(e, Failure)]
        assert failures and "not authorised" in failures[0].error
        assert not any(isinstance(e, StatusReceived) for e in operator.drain_events())

    async def test_capability_is_per_action(self, operator, agent):
        await enrol(operator, agent, caps=["status"])
        # Granted: status works.
        await operator.app.request_status(agent.id)
        await deliver(operator, agent)
        await deliver(agent, operator)
        assert any(isinstance(e, StatusReceived) for e in operator.drain_events())
        # Not granted: update and shell are refused, with a reason.
        for call in (operator.app.request_update, operator.app.open_shell):
            await call(agent.id)
            await deliver(operator, agent)
            await deliver(agent, operator)
            failures = [e for e in operator.drain_events() if isinstance(e, Failure)]
            assert failures and "not authorised" in failures[0].error

    async def test_revoked_operator_loses_access(self, operator, agent):
        await enrol(operator, agent, caps=["status"])
        agent.app.state.remove_operator(operator.id.raw.hex())
        await operator.app.request_status(agent.id)
        await deliver(operator, agent)
        await deliver(agent, operator)
        assert any(isinstance(e, Failure) for e in operator.drain_events())


# ---------------------------------------------------------------------------
# Gate 3 — the per-command signature
# ---------------------------------------------------------------------------

class TestSignatureGate:
    async def _enrolled(self, operator, agent):
        await enrol(operator, agent, caps=list(CAPABILITIES))

    def _status_frame(self, operator: Peer, agent: Peer) -> bytes:
        return operator.app._signed_frame(
            fleet.STATUS_REQUEST, agent.id, fleet.PURPOSE_BY_CAP["status"],
            {"rid": "aa" * 8})

    async def test_unsigned_command_is_dropped(self, operator, agent):
        await self._enrolled(operator, agent)
        body = json.dumps({"rid": "aa" * 8}).encode()
        agent.app._dispatch(operator.id, bytes([fleet.STATUS_REQUEST]) + body)
        await settle()
        assert agent.take_sent() == []

    async def test_edited_body_is_dropped(self, operator, agent):
        """The signature covers the body bytes, so a relay cannot retarget the
        command and keep the proof."""
        await self._enrolled(operator, agent)
        frame = bytearray(self._status_frame(operator, agent))
        frame[-2] = frame[-2] ^ 0x01
        agent.app._dispatch(operator.id, bytes(frame))
        await settle()
        assert agent.take_sent() == []

    async def test_replayed_command_is_dropped(self, operator, agent):
        await self._enrolled(operator, agent)
        frame = self._status_frame(operator, agent)
        agent.app._dispatch(operator.id, frame)
        await settle()
        assert len(agent.take_sent()) == 1        # first one is honoured
        agent.app._dispatch(operator.id, frame)   # same nonce, second time
        await settle()
        assert agent.take_sent() == []

    async def test_signature_for_another_node_is_dropped(self, operator, agent):
        """An assertion whose audience is a third party must not work here."""
        await self._enrolled(operator, agent)
        elsewhere = Peer()
        frame = operator.app._signed_frame(
            fleet.STATUS_REQUEST, elsewhere.id, fleet.PURPOSE_BY_CAP["status"],
            {"rid": "bb" * 8})
        agent.app._dispatch(operator.id, frame)
        await settle()
        assert agent.take_sent() == []

    async def test_signature_for_another_purpose_is_dropped(self, operator, agent):
        """A signature obtained for a status read cannot open a shell."""
        await self._enrolled(operator, agent)
        body = json.dumps({"rid": "cc" * 8}).encode()
        assertion = make_assertion(
            operator.identity, fleet.FLEET_APP_ID, audience=agent.id,
            purpose=fleet.PURPOSE_BY_CAP["status"],
            ctx=ctx_hash(b"fleet", bytes([fleet.SHELL_OPEN]), body)).serialize()
        frame = (bytes([fleet.SHELL_OPEN])
                 + len(assertion).to_bytes(2, "big") + assertion + body)
        agent.app._dispatch(operator.id, frame)
        await settle()
        assert agent.take_sent() == []

    async def test_command_signed_by_someone_else_is_dropped(self, operator, agent):
        """Relaying an enrolled operator's frame from a different src fails: the
        assertion's subject must be the peer that sent it."""
        await self._enrolled(operator, agent)
        mallory = Peer()
        agent.app._dispatch(mallory.id, self._status_frame(operator, agent))
        await settle()
        assert agent.take_sent() == []


# ---------------------------------------------------------------------------
# Replies
# ---------------------------------------------------------------------------

class TestReplies:
    async def test_unsolicited_reply_is_ignored(self, operator, agent):
        await enrol(operator, agent, caps=["status"])
        agent.app._reply(operator.id, fleet.STATUS_REPORT,
                         {"rid": "ff" * 8, "status": {"hostname": "evil"}})
        await deliver(agent, operator)
        assert not any(isinstance(e, StatusReceived) for e in operator.drain_events())

    async def test_reply_from_the_wrong_node_is_ignored(self, operator, agent):
        await enrol(operator, agent, caps=["status"])
        rid = await operator.app.request_status(agent.id)
        operator.take_sent()
        stranger = Peer()
        operator.app._dispatch(stranger.id, bytes([fleet.STATUS_REPORT])
                               + json.dumps({"rid": rid,
                                             "status": {"hostname": "x"}}).encode())
        await settle()
        assert not any(isinstance(e, StatusReceived) for e in operator.drain_events())

    async def test_reply_of_the_wrong_kind_is_ignored(self, operator, agent):
        await enrol(operator, agent, caps=["status"])
        rid = await operator.app.request_status(agent.id)
        operator.take_sent()
        operator.app._dispatch(agent.id, bytes([fleet.SCAN_RESULT])
                               + json.dumps({"rid": rid, "hosts": []}).encode())
        await settle()
        assert not any(isinstance(e, ScanReceived) for e in operator.drain_events())


# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------

class TestStatus:
    async def test_status_roundtrip(self, operator, agent):
        await enrol(operator, agent, caps=["status"])
        await operator.app.request_status(agent.id)
        await deliver(operator, agent)
        await deliver(agent, operator)
        reports = [e for e in operator.drain_events()
                   if isinstance(e, StatusReceived)]
        assert len(reports) == 1
        status = reports[0].status
        assert "disks" in status and "memory" in status and "uptime" in status
        # It is cached against the managed record for the UI.
        cached = operator.app.state.managed_one(agent.id.raw.hex())
        assert cached["status"]["memory"] == status["memory"]


# ---------------------------------------------------------------------------
# Shell session binding
# ---------------------------------------------------------------------------

class TestShellBinding:
    """A shell is bound to the operator it was opened for. These drive the real
    dispatcher against a real ``_Shell`` whose pty is stood in for by a pipe, so
    the binding check under test is the one that ships."""

    def _shell(self, agent: Peer, owner: NodeID):
        read_fd, write_fd = os.pipe()
        os.set_blocking(read_fd, False)
        sid = os.urandom(fleet.SID_LEN)
        shell = fleet._Shell(sid, owner, _DummyProc(), write_fd)
        agent.app._shells[sid] = shell
        return sid, read_fd

    def _typed(self, read_fd: int) -> bytes:
        try:
            return os.read(read_fd, 65536)
        except BlockingIOError:
            return b""

    async def test_input_from_another_node_is_dropped(self, operator, agent):
        sid, read_fd = self._shell(agent, operator.id)
        mallory = Peer()
        agent.app._dispatch(mallory.id,
                            bytes([fleet.SHELL_INPUT]) + sid + b"rm -rf /\n")
        assert self._typed(read_fd) == b""
        agent.app._dispatch(operator.id,
                            bytes([fleet.SHELL_INPUT]) + sid + b"id\n")
        assert self._typed(read_fd) == b"id\n"

    async def test_oversized_input_is_dropped(self, operator, agent):
        sid, read_fd = self._shell(agent, operator.id)
        agent.app._dispatch(operator.id, bytes([fleet.SHELL_INPUT]) + sid
                            + b"x" * (fleet.SHELL_INPUT_MAX + 1))
        assert self._typed(read_fd) == b""

    async def test_input_for_an_unknown_session_is_dropped(self, operator, agent):
        agent.app._dispatch(operator.id, bytes([fleet.SHELL_INPUT])
                            + os.urandom(fleet.SID_LEN) + b"whoami\n")
        assert agent.take_sent() == []

    async def test_resize_from_another_node_is_dropped(self, operator, agent):
        sid, _read_fd = self._shell(agent, operator.id)
        mallory = Peer()
        # Nothing to assert on the fd itself; what matters is that no exception
        # escapes and the session stays owned by its operator.
        agent.app._dispatch(mallory.id, bytes([fleet.SHELL_RESIZE]) + sid
                            + b"\x00\x50\x00\x18")
        assert agent.app._shells[sid].owner == operator.id

    async def test_output_for_an_unknown_session_is_dropped(self, operator, agent):
        operator.app._dispatch(agent.id, bytes([fleet.SHELL_OUTPUT])
                               + os.urandom(fleet.SID_LEN) + b"junk")
        assert operator.drain_events() == []


class _DummyProc:
    """Stands in for the shell subprocess: closing it must not raise."""

    returncode = 0

    def send_signal(self, sig):
        pass

    def kill(self):
        pass


@pytest.fixture(autouse=True)
def _close_shells(agent, operator):
    """Every fake shell holds a pipe fd; close them so the suite leaks none."""
    yield
    for peer in (agent, operator):
        for sid in list(peer.app._shells):
            peer.app._shells.pop(sid).close()


# ---------------------------------------------------------------------------
# Pre-authorisation (a provisioned machine coming online)
# ---------------------------------------------------------------------------

class TestPreauth:
    def _document(self, operator: Peer, caps=("status", "update")):
        document, token = fleet_provision.make_preauth(
            operator.id.raw, operator.identity.dsa_public_key,
            capabilities=list(caps), join_uris=[], join_code=None, label="new box")
        parsed = fleet_provision.parse_preauth(document)
        return parsed, token

    async def test_claim_binds_a_new_node_to_its_provisioning_run(self, operator):
        newbie = Peer()
        parsed, token = self._document(operator)
        digest = fleet_provision.token_digest(token)
        operator.app.state.add_provisioned(digest, host="10.0.0.5",
                                           caps=["status", "update"],
                                           label="new box")
        assert await newbie.app.claim_preauth(parsed) is True
        # The new node now obeys the operator whose key arrived over SSH.
        assert newbie.app.state.allows(operator.id.raw.hex(), "update") is True
        await deliver(newbie, operator)
        adopted = [e for e in operator.drain_events() if isinstance(e, NodeAdopted)]
        assert len(adopted) == 1 and adopted[0].src == newbie.id
        assert operator.app.state.managed_one(newbie.id.raw.hex()) is not None

    async def test_unknown_token_is_ignored(self, operator):
        newbie = Peer()
        parsed, _token = self._document(operator)
        assert await newbie.app.claim_preauth(parsed) is True
        await deliver(newbie, operator)   # operator never provisioned anything
        assert operator.app.state.managed_one(newbie.id.raw.hex()) is None

    async def test_token_is_single_use(self, operator):
        newbie = Peer()
        parsed, token = self._document(operator)
        operator.app.state.add_provisioned(fleet_provision.token_digest(token),
                                           host="10.0.0.5", caps=["status"])
        await newbie.app.claim_preauth(parsed)
        await deliver(newbie, operator)
        operator.app.state.remove_managed(newbie.id.raw.hex())
        # A second claim of the same token finds no record.
        impostor = Peer()
        await impostor.app.claim_preauth(parsed)
        await deliver(impostor, operator)
        assert operator.app.state.managed_one(impostor.id.raw.hex()) is None


# ---------------------------------------------------------------------------
# Hostile input
# ---------------------------------------------------------------------------

class TestHostileInput:
    async def test_random_frames_never_crash(self, operator, agent):
        await enrol(operator, agent, caps=list(CAPABILITIES))
        rng = random.Random(1234)
        for _ in range(3000):
            size = rng.randint(0, 300)
            agent.app._dispatch(operator.id,
                                bytes(rng.randrange(256) for _ in range(size)))
        await settle()
        # Still alive and still enrolled.
        assert agent.app.state.allows(operator.id.raw.hex(), "status") is True

    async def test_truncated_signed_frames_never_crash(self, operator, agent):
        await enrol(operator, agent, caps=["status"])
        frame = operator.app._signed_frame(
            fleet.STATUS_REQUEST, agent.id, fleet.PURPOSE_BY_CAP["status"],
            {"rid": "aa" * 8})
        for cut in range(0, len(frame), 7):
            agent.app._dispatch(operator.id, frame[:cut])
        await settle()
        assert agent.take_sent() == []

    async def test_absurd_json_bodies_are_dropped(self, operator, agent):
        await enrol(operator, agent, caps=["status", "shell"])
        for body in (b"[]", b"null", b"123", b'{"rid":' + b"9" * 5000 + b"}",
                     b"\xff\xfe", b"{"):
            agent.app._dispatch(operator.id, bytes([fleet.STATUS_REPORT]) + body)
            agent.app._dispatch(operator.id, bytes([fleet.SHELL_OPENED]) + body)
        await settle()

    async def test_hostile_winsize_is_clamped(self):
        for value in (-5, 0, 10 ** 9, "big", None, float("nan")):
            assert 1 <= fleet._dim(value) <= 1000

    async def test_hostile_targets_are_filtered(self):
        assert fleet._clean_targets("not a list") == []
        assert fleet._clean_targets([{"ip": ""}, {"nope": 1}, 5]) == []
        cleaned = fleet._clean_targets([{"ip": "10.0.0.1", "port": 999999,
                                        "known_hosts": "nope"}])
        assert cleaned == [{"ip": "10.0.0.1", "port": 22, "label": "10.0.0.1",
                            "known_hosts": []}]


# ---------------------------------------------------------------------------
# Réponses qui doivent tenir dans une trame
# ---------------------------------------------------------------------------

class TestReplyFraming:
    """Couper du JSON à un offset produit quelque chose que le destinataire ne
    parse pas et jette en silence — la pire panne possible pour une réponse que
    l'opérateur attend. On coupe donc des **entrées**, jamais des octets."""

    def _fat_hosts(self, count):
        return [{"ip": f"10.0.{i // 256}.{i % 256}", "port": 22,
                 "banner": "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5",
                 "keys": [{"type": "ssh-rsa", "fingerprint": "SHA256:" + "C" * 43,
                           "line": f"10.0.0.{i} ssh-rsa " + "D" * 600}
                          for _ in range(3)]}
                for i in range(count)]

    def test_small_reply_is_untouched(self):
        document = {"rid": "aa" * 8, "hosts": [{"ip": "10.0.0.1"}]}
        assert json.loads(fleet._dump_json(document, "hosts")) == document

    def test_oversized_reply_stays_parseable(self):
        document = {"rid": "aa" * 8, "hosts": self._fat_hosts(400),
                    "networks": [], "rejected": [], "ssh_client": True}
        blob = fleet._dump_json(document, "hosts", "networks")
        assert len(blob) <= fleet.MAX_BODY
        parsed = json.loads(blob)                     # the whole point
        assert parsed["rid"] == "aa" * 8
        assert 0 < len(parsed["hosts"]) < 400
        assert parsed["truncated"] == 400 - len(parsed["hosts"])

    def test_truncation_survives_the_dispatcher(self, operator, agent):
        """A trimmed reply must still be understood by the far side."""
        document = {"rid": "bb" * 8, "hosts": self._fat_hosts(400)}
        blob = fleet._dump_json(document, "hosts")
        assert fleet._load_json(blob) is not None

    def test_an_untrimmable_reply_reports_itself(self):
        """Nothing left to drop: send a readable error, not a broken frame."""
        document = {"rid": "cc" * 8, "note": "x" * (fleet.MAX_BODY + 100)}
        parsed = json.loads(fleet._dump_json(document, "hosts"))
        assert parsed["error"] == "reply too large"
        assert parsed["rid"] == "cc" * 8

    async def test_scan_result_reaches_the_operator_when_huge(self, operator, agent):
        """End to end through the real dispatchers: a fat scan result is
        trimmed, not lost."""
        await enrol(operator, agent, caps=["scan"])
        rid = await operator.app.request_scan(agent.id, ["10.0.0.0/30"])
        operator.take_sent()
        agent.app._reply(operator.id, fleet.SCAN_RESULT,
                         {"rid": rid, "hosts": self._fat_hosts(400),
                          "networks": [], "rejected": []},
                         "hosts", "networks", "rejected")
        await deliver(agent, operator)
        received = [e for e in operator.drain_events()
                    if isinstance(e, ScanReceived)]
        assert len(received) == 1
        assert received[0].hosts and received[0].truncated > 0
