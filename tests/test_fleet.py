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
import json
import os
import random

import pytest

from src.app_auth import AppAuth, ctx_hash, make_assertion
from src.apps import fleet
from src.apps.fleet import (
    CommandResult, EnrolAnswered, EnrolRequested, FleetApp, Failure,
    NodeAdopted, Revoked, ScanReceived, StatusReceived,
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
