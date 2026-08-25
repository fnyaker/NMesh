"""
Fleet — remote management and automated deployment over the mesh.

Every node runs the same app and can play either role:

  - the **agent** role obeys: it answers status requests, runs its own package
    manager, opens a shell, sweeps its LAN, provisions machines it can reach —
    but only for an operator it has explicitly enrolled, and only for the
    capabilities that enrolment granted;
  - the **operator** role drives: it asks nodes to enrol it, keeps the list of
    nodes that accepted, and sends them commands.

Authorisation — three independent gates
---------------------------------------
A command runs only if all three hold. They are independent on purpose: any one
of them failing alone is enough to stop it.

1. **The mesh authenticated the sender.** A DATA payload reaching this app
   carries a ``src_id`` proven by the E2E session (ML-DSA + certificate chain).
2. **The sender is enrolled here, with this capability.** The ledger
   (:mod:`src.apps.fleet_state`) is local, persistent, and only ever grows by an
   explicit local decision.
3. **The command carries a fresh signature over its own bytes.** Each request
   embeds an app-auth assertion (:mod:`src.app_auth`) whose audience is *this*
   node, whose purpose names the capability, and whose context is the hash of
   the request body. A replayed, redirected, or edited command fails to verify.

Gate 3 is defence in depth over gate 1, and it buys something gate 1 cannot: the
proof is *portable*. "This node authorised this exact command at this time" stays
verifiable after the session is gone, which is what makes a remote-execution
feature auditable instead of merely functional.

The shell is the exception worth naming: signing every keystroke would cost a
post-quantum signature per character. Opening a shell is signed; the keystrokes
that follow are bound to the resulting session id and ride the same
end-to-end-encrypted channel from the same authenticated peer. The signed act is
"open a shell as me", which is the act that matters.

Wire format inside the fleet section of the E2E DATA plane::

    signed request : type(1) ‖ alen(2) ‖ assertion ‖ json_body
    reply          : type(1) ‖ json_body
    shell stream   : type(1) ‖ sid(16) ‖ raw bytes

Every inbound frame is bounded and validated before use; a malformed one is
dropped without a side effect, never fatal (the charter applies at the app layer
too).
"""
from __future__ import annotations

import asyncio
import base64
import json
import os
import secrets
import shutil
import signal
import struct
import time
from dataclasses import dataclass, field

from ..app_auth import ctx_hash
from ..app_channel import builtin_id
from ..node_id import NodeID
from . import fleet_host, fleet_provision, fleet_ssh
from .fleet_state import CAPABILITIES, FleetState, clean_caps, clean_label

FLEET_APP_ID = builtin_id("fleet")

# -- message types ----------------------------------------------------------
ENROL_REQUEST = 0x01
ENROL_GRANT = 0x02
ENROL_DENY = 0x03
ENROL_REVOKE = 0x04
PREAUTH_CLAIM = 0x05
ENROL_NARROW = 0x06               # an operator giving a right up, unilaterally

STATUS_REQUEST = 0x10
STATUS_REPORT = 0x11
ERROR = 0x12

UPDATE_REQUEST = 0x20
UPDATE_OUTPUT = 0x21
UPDATE_RESULT = 0x22

SHELL_OPEN = 0x30
SHELL_OPENED = 0x31
SHELL_INPUT = 0x32
SHELL_OUTPUT = 0x33
SHELL_RESIZE = 0x34
SHELL_CLOSE = 0x35

SCAN_REQUEST = 0x40
SCAN_RESULT = 0x41
PROVISION_REQUEST = 0x42
PROVISION_PROGRESS = 0x43
PROVISION_RESULT = 0x44

# Purposes an assertion may carry. One per capability, plus enrolment, so a
# signature obtained for one action is useless for another.
PURPOSE_ENROL = "fleet.enrol"
PURPOSE_GRANT = "fleet.grant"
PURPOSE_PREAUTH = "fleet.preauth"
PURPOSE_NARROW = "fleet.narrow"
PURPOSE_BY_CAP = {cap: f"fleet.{cap}" for cap in CAPABILITIES}

# -- bounds -----------------------------------------------------------------
MAX_BODY = 56_000                 # json body per frame (under the DATA ceiling)
MAX_ASSERTION = 32 * 1024
SID_LEN = 16
RID_LEN = 8
MAX_SHELLS = 4                    # concurrent shells this node will host
SHELL_IDLE_TIMEOUT = 900.0        # a forgotten shell is reaped
SHELL_CHUNK = 8192
SHELL_INPUT_MAX = 8192
MAX_INFLIGHT = 64                 # requests we track as an operator
UPDATE_TIMEOUT = 1800.0
UPDATE_CHUNK = 4096
SCAN_TIMEOUT = 300.0
MAX_KEY_DATA = 64 * 1024          # an uploaded private key, bounded
KEYSCAN_TIMEOUT = 60.0            # whole fingerprint pass, not per host
_ASSERTION_TTL = 300              # a command signature is good for five minutes

_LEN = struct.Struct("!H")
_WINSIZE = struct.Struct("!HH")


# ---------------------------------------------------------------------------
# Events surfaced to listeners (the web bridge turns these into UI records)
# ---------------------------------------------------------------------------

@dataclass
class EnrolRequested:
    """An operator asks to manage us — this is the notification a human answers."""
    src: NodeID
    caps: list
    label: str


@dataclass
class EnrolAnswered:
    src: NodeID
    granted: bool
    caps: list = field(default_factory=list)
    reason: str = ""


@dataclass
class NodeAdopted:
    """A machine we provisioned came up and claimed its pre-authorisation."""
    src: NodeID
    host: str
    label: str


@dataclass
class Revoked:
    src: NodeID


@dataclass
class CapsChanged:
    """The capability set on an existing relationship moved.

    ``direction`` says whose rights: ``"operator"`` is what that node may do to
    us, ``"managed"`` is what we may do to it."""
    src: NodeID
    caps: list
    direction: str


@dataclass
class StatusReceived:
    src: NodeID
    status: dict
    rid: str = ""


@dataclass
class CommandOutput:
    src: NodeID
    rid: str
    kind: str            # "update" | "provision"
    text: str
    # Set when this frame marks a step rather than carrying output:
    # {"index", "total", "name", "elapsed"}. An update is minutes long, and
    # a wall of package-manager output is not progress.
    step: dict | None = None


@dataclass
class CommandResult:
    src: NodeID
    rid: str
    kind: str
    ok: bool
    detail: dict = field(default_factory=dict)


@dataclass
class ScanReceived:
    src: NodeID
    rid: str
    hosts: list
    networks: list = field(default_factory=list)
    rejected: list = field(default_factory=list)
    truncated: int = 0


@dataclass
class ShellOpened:
    src: NodeID
    rid: str
    sid: bytes


@dataclass
class ShellOutput:
    src: NodeID
    sid: bytes
    data: bytes


@dataclass
class ShellClosed:
    src: NodeID
    sid: bytes
    status: int


@dataclass
class Failure:
    """A request we sent was refused or failed on the far side."""
    src: NodeID
    rid: str
    error: str


# ---------------------------------------------------------------------------
# Local shell sessions (agent side)
# ---------------------------------------------------------------------------

def _make_controlling_tty(slave_fd: int):
    """Make the pty the new session's **controlling terminal**.

    A pty on the shell's file descriptors is not enough. Without this ioctl the
    session has no controlling terminal at all: `/dev/tty` cannot be opened, so
    `sudo` refuses to ask for a password ("a terminal is required"), job control
    is off, and every program that wants to talk to the user directly fails. One
    ioctl is the difference between a pipe with a prompt in it and a terminal.

    ``start_new_session=True`` has already called ``setsid()`` by the time this
    runs, so calling it again here would fail — the session exists, it just owns
    no terminal yet. Runs in the forked child, before exec: keep it tiny."""
    def _setup() -> None:
        try:
            import fcntl
            import termios
            fcntl.ioctl(slave_fd, termios.TIOCSCTTY, 0)
        except Exception:
            pass          # a platform without it still gets a usable pipe
    return _setup


class _Shell:
    """One interactive shell bound to one operator, on a pty."""

    __slots__ = ("sid", "owner", "proc", "master_fd", "stop_reader", "last_active")

    def __init__(self, sid: bytes, owner: NodeID, proc, master_fd: int) -> None:
        self.sid = sid
        self.owner = owner
        self.proc = proc
        self.master_fd = master_fd
        self.stop_reader = None
        self.last_active = time.monotonic()

    def close(self) -> None:
        if self.stop_reader is not None:
            try:
                self.stop_reader()
            except Exception:
                pass
            self.stop_reader = None
        # SIGHUP first (a shell's own way of being told the terminal is gone),
        # then kill: a child that ignores the hangup still goes away.
        try:
            self.proc.send_signal(signal.SIGHUP)
        except Exception:
            pass
        try:
            self.proc.kill()
        except Exception:
            pass
        try:
            os.close(self.master_fd)
        except OSError:
            pass


# ---------------------------------------------------------------------------
# The app
# ---------------------------------------------------------------------------

class FleetApp:
    """Fleet management over a :class:`~src.data_connector.ConnectorClient`.

    ``auth`` is the app-scoped authentication service the node hands out
    (``node.app_auth(FLEET_APP_ID)``): the app signs and verifies through it and
    never sees the node's signing key. ``repo_root`` is the NMesh tree this node
    would push when provisioning; with none, the provision capability reports
    itself unavailable rather than half working.

    ``mesh_invite()`` returns ``{"uris": [...], "code": "..."}`` — a fresh
    single-use invitation to *this* node's mesh. Provisioning calls it once per
    machine so the new node joins through the node that installed it and has its
    certificate signed by it (see ``Docs/Apps/fleet``). Keeping it a callable
    rather than a node reference is what lets the app stay ignorant of the node,
    exactly like every other connector app."""

    def __init__(self, client, auth, *, state: FleetState | None = None,
                 repo_root: str | None = None, mesh_invite=None,
                 auto_status: bool = True) -> None:
        self._client = client
        self._auth = auth              # src.app_auth.AppAuth, scoped to our app id
        self.node_id = auth.node_id
        self.state = state or FleetState()
        self._repo_root = repo_root
        self._mesh_invite = mesh_invite
        self._auto_status = auto_status
        self._facts: fleet_host.HostFacts | None = None
        self._events: asyncio.Queue = asyncio.Queue()
        self._listeners: list = []
        self._task: asyncio.Task | None = None
        self._reaper: asyncio.Task | None = None
        self._shells: dict[bytes, _Shell] = {}          # agent side
        self._open_shells: dict[bytes, NodeID] = {}     # operator side
        self._inflight: dict[str, tuple[NodeID, str, float]] = {}
        self._jobs: set[asyncio.Task] = set()

    # -- lifecycle --------------------------------------------------------

    @property
    def facts(self) -> fleet_host.HostFacts:
        """This machine's self-description, detected once at first use (the
        app's "install" moment) and cached."""
        if self._facts is None:
            self._facts = fleet_host.detect()
        return self._facts

    def refresh_facts(self) -> fleet_host.HostFacts:
        self._facts = fleet_host.detect()
        return self._facts

    async def start(self) -> None:
        self.facts                              # detect at install time
        self._task = asyncio.create_task(self._loop())
        self._reaper = asyncio.create_task(self._reap_loop())

    async def stop(self) -> None:
        for task in (self._task, self._reaper):
            if task is not None:
                task.cancel()
        for task in (self._task, self._reaper):
            if task is not None:
                try:
                    await task
                except (asyncio.CancelledError, Exception):
                    pass
        self._task = self._reaper = None
        for job in list(self._jobs):
            job.cancel()
        self._jobs.clear()
        for shell in list(self._shells.values()):
            shell.close()
        self._shells.clear()
        await self._client.close()

    def add_listener(self, fn) -> None:
        self._listeners.append(fn)

    def remove_listener(self, fn) -> None:
        try:
            self._listeners.remove(fn)
        except ValueError:
            pass

    def _emit(self, event) -> None:
        if self._events.qsize() >= 1000:
            try:
                self._events.get_nowait()
            except asyncio.QueueEmpty:
                pass
        self._events.put_nowait(event)
        for fn in list(self._listeners):
            try:
                fn(event)
            except Exception:
                pass          # a bad listener must not break the app

    async def next_event(self):
        return await self._events.get()

    def _spawn(self, coro) -> None:
        """Run a long job off the receive loop. Bounded, and every job is
        cancelled at stop() — nothing outlives the app."""
        if len(self._jobs) >= MAX_INFLIGHT:
            coro.close()
            return
        task = asyncio.create_task(coro)
        self._jobs.add(task)
        task.add_done_callback(self._jobs.discard)

    # -- receive loop -----------------------------------------------------

    async def _loop(self) -> None:
        while True:
            try:
                src, payload = await self._client.recv()
            except asyncio.CancelledError:
                raise
            except Exception:
                await asyncio.sleep(0.5)
                continue
            try:
                self._dispatch(src, payload)
            except asyncio.CancelledError:
                raise
            except Exception:
                continue      # a hostile frame never kills the loop

    async def _reap_loop(self) -> None:
        """Close shells nobody is talking to any more."""
        while True:
            await asyncio.sleep(30.0)
            now = time.monotonic()
            for sid, shell in list(self._shells.items()):
                if now - shell.last_active > SHELL_IDLE_TIMEOUT:
                    self._close_shell(sid, status=-1)

    def _dispatch(self, src: NodeID, payload: bytes) -> None:
        if not payload:
            return
        kind, body = payload[0], payload[1:]
        # Shell streaming is raw and hot; everything else is JSON.
        if kind in (SHELL_INPUT, SHELL_OUTPUT, SHELL_RESIZE, SHELL_CLOSE):
            self._dispatch_shell_stream(src, kind, body)
            return
        if kind in _SIGNED_INBOUND:
            parsed = self._open_signed(src, kind, body)
            if parsed is None:
                return
            principal, document = parsed
            _SIGNED_INBOUND[kind](self, src, principal, document)
            return
        handler = _REPLY_INBOUND.get(kind)
        if handler is None:
            return
        document = _load_json(body)
        if document is not None:
            handler(self, src, document)

    # -- framing ----------------------------------------------------------

    def _signed_frame(self, kind: int, target: NodeID, purpose: str,
                      document: dict) -> bytes:
        body = _dump_json(document)
        assertion = self._auth.assert_to(
            target, purpose, ctx_hash(b"fleet", bytes([kind]), body),
            ttl=_ASSERTION_TTL)
        return bytes([kind]) + _LEN.pack(len(assertion)) + assertion + body

    def _open_signed(self, src: NodeID, kind: int, body: bytes):
        """Unwrap a signed request: bounds, signature, context binding.

        Returns ``(principal, document)`` or ``None``. The signature is checked
        against the *exact* body bytes, so an intermediary cannot edit the
        command and keep the proof."""
        if len(body) < _LEN.size:
            return None
        (alen,) = _LEN.unpack_from(body, 0)
        if not 0 < alen <= MAX_ASSERTION or len(body) < _LEN.size + alen:
            return None
        assertion = body[_LEN.size:_LEN.size + alen]
        raw = body[_LEN.size + alen:]
        if len(raw) > MAX_BODY:
            return None
        purpose = _PURPOSE_FOR[kind]
        principal = self._auth.verify(
            assertion, purpose=purpose,
            ctx=ctx_hash(b"fleet", bytes([kind]), raw))
        if principal is None or principal.node_id != src:
            return None      # unsigned, replayed, redirected, or not from src
        document = _load_json(raw)
        if document is None:
            return None
        # Hand the handlers the proof itself, so an enrolment can be stored with
        # the signature that created it. Set *after* parsing, so a peer cannot
        # smuggle its own value in under this key.
        document["_proof"] = assertion
        return principal, document

    async def _send(self, target: NodeID, payload: bytes) -> None:
        try:
            await self._client.send(target, payload)
        except Exception:
            pass          # a dead peer must not break a handler

    def _reply(self, target: NodeID, kind: int, document: dict,
               *trim_keys: str) -> None:
        self._spawn(self._send(target,
                               bytes([kind]) + _dump_json(document, *trim_keys)))

    def _fail(self, target: NodeID, rid: str, error: str) -> None:
        self._reply(target, ERROR, {"rid": rid, "error": error[:256]})

    # -- authorisation ----------------------------------------------------

    def _authorised(self, src: NodeID, capability: str, rid: str) -> bool:
        """Gate 2: the ledger. Gate 3 (the signature) already passed by the time
        we get here; gate 1 is the mesh. A refusal is reported, not silent — the
        operator must be able to tell "denied" from "unreachable"."""
        if self.state.allows(src.raw.hex(), capability):
            return True
        self._fail(src, rid, f"not authorised for {capability}")
        return False

    # ======================================================================
    # Enrolment
    # ======================================================================

    async def request_enrolment(self, target: NodeID, *, caps: list[str],
                                label: str = "") -> bool:
        """Operator side: ask ``target`` to let us manage it. The target raises a
        notification; a human there accepts or denies."""
        caps = clean_caps(caps)
        if not caps:
            return False
        self.state.add_pending_out(target.raw.hex(), caps=caps, label=label)
        await self._send(target, self._signed_frame(
            ENROL_REQUEST, target, PURPOSE_ENROL,
            {"caps": caps, "label": clean_label(label)}))
        return True

    def _on_enrol_request(self, src: NodeID, principal, document: dict) -> None:
        """Agent side: park the request for a human. We never auto-accept — an
        enrolment is a standing grant of remote execution."""
        caps = clean_caps(document.get("caps"))
        if not caps:
            return
        node_hex = src.raw.hex()
        # An operator we already trust asking for more is the same decision as a
        # stranger asking for the first time: a human here answers it. There is
        # no path that widens a grant without one, or the whole ladder collapses
        # to whatever the least capability lets an attacker reach.
        held = clean_caps((self.state.operator(node_hex) or {}).get("caps"))
        entry = self.state.add_pending_in(
            node_hex, principal.public_key, caps=caps,
            label=clean_label(document.get("label")),
            proof=document.get("_proof", b""), have=held)
        if entry is not None:
            self._emit(EnrolRequested(src, caps, entry["label"]))

    async def approve_enrolment(self, node_hex: str,
                                caps: list[str] | None = None) -> bool:
        """Agent side: a human accepted. ``caps`` may narrow — never widen — what
        was asked for, so approving cannot grant more than the request showed."""
        pending = self.state.take_pending_in(node_hex)
        if pending is None:
            return False
        asked = clean_caps(pending.get("caps"))
        granted = [c for c in clean_caps(caps) if c in asked] if caps else asked
        if not granted:
            return False
        try:
            public_key = bytes.fromhex(pending.get("pub", ""))
            target = NodeID.from_hex(node_hex)
        except ValueError:
            return False
        try:
            proof = base64.b64decode(pending.get("proof") or "", validate=True)
        except (ValueError, TypeError):
            proof = b""
        if self.state.add_operator(node_hex, public_key, caps=granted,
                                   label=pending.get("label", ""),
                                   proof=proof) is None:
            return False
        await self._send(target, self._signed_frame(
            ENROL_GRANT, target, PURPOSE_GRANT,
            {"caps": granted, "label": self.facts.hostname or ""}))
        return True

    async def deny_enrolment(self, node_hex: str, reason: str = "") -> bool:
        if self.state.take_pending_in(node_hex) is None:
            return False
        try:
            target = NodeID.from_hex(node_hex)
        except ValueError:
            return False
        await self._send(target, self._signed_frame(
            ENROL_DENY, target, PURPOSE_GRANT, {"reason": str(reason)[:256]}))
        return True

    def _on_enrol_grant(self, src: NodeID, principal, document: dict) -> None:
        """Operator side: the node accepted. Keep the signed grant — it is the
        proof this node really consented, verifiable long after the fact."""
        caps = clean_caps(document.get("caps"))
        node_hex = src.raw.hex()
        # Only a node we actually asked can grant us anything: an unsolicited
        # grant is either noise or an attempt to plant an entry in our list.
        # A node we already manage may restate its grant, which is how a human
        # over there adding or removing one of our rights reaches us.
        asked = self.state.drop_pending_out(node_hex)
        known = self.state.managed_one(node_hex) is not None
        if not caps or not (asked or known):
            return
        self.state.add_managed(node_hex, caps=caps,
                               label=clean_label(document.get("label")),
                               grant=document.get("_proof", b"")
                               or self.state.grant_proof(node_hex))
        if not asked:
            self._emit(CapsChanged(src, caps, "managed"))
            return
        self._emit(EnrolAnswered(src, True, caps))
        if self._auto_status:
            self._spawn(self.request_status(src))

    def _on_enrol_deny(self, src: NodeID, principal, document: dict) -> None:
        self.state.drop_pending_out(src.raw.hex())
        self._emit(EnrolAnswered(src, False,
                                 reason=str(document.get("reason", ""))[:256]))

    async def revoke(self, node_hex: str) -> bool:
        """Drop a relationship in whichever direction it exists, and tell the
        other side so it stops trying."""
        dropped = (self.state.remove_operator(node_hex)
                   | self.state.remove_managed(node_hex))
        self.state.drop_pending_out(node_hex)
        if not dropped:
            return False
        try:
            target = NodeID.from_hex(node_hex)
        except ValueError:
            return True
        await self._send(target, self._signed_frame(
            ENROL_REVOKE, target, PURPOSE_GRANT, {}))
        return True

    def _on_revoke(self, src: NodeID, principal, document: dict) -> None:
        node_hex = src.raw.hex()
        self._drop_shells_of(src)
        self.state.remove_operator(node_hex)
        self.state.remove_managed(node_hex)
        self._emit(Revoked(src))

    def _drop_shells_of(self, src: NodeID) -> None:
        """Tear down every shell this peer holds, in both roles.

        A right that has just been taken away must not survive in a session
        opened while it still held — otherwise revoking ``shell`` only stops
        the *next* one."""
        for sid, owner in list(self._open_shells.items()):
            if owner == src:
                self._open_shells.pop(sid, None)
        for sid, shell in list(self._shells.items()):
            if shell.owner == src:
                self._close_shell(sid, status=-1)

    # -- changing the rights on a standing relationship -------------------

    async def request_capabilities(self, target: NodeID, caps: list[str]) -> bool:
        """Operator side: ask a node we already manage for extra rights.

        It is the ordinary enrolment request carrying the *whole* set we want,
        so the human over there sees one list to accept or narrow — and so this
        cannot become a second, quieter way in."""
        entry = self.state.managed_one(target.raw.hex())
        if entry is None:
            return False
        held = clean_caps(entry.get("caps"))
        want = clean_caps(held + clean_caps(caps))
        if want == held:
            return False
        return await self.request_enrolment(target, caps=want,
                                            label=clean_label(entry.get("label")))

    async def drop_capabilities(self, node_hex: str, caps: list[str]) -> bool:
        """Operator side: give rights up on a node we manage.

        Unilateral by design — nobody needs to approve holding *less* — and it
        takes effect here first, so a node that never hears us still ends up
        with less than we could use."""
        entry = self.state.managed_one(node_hex)
        if entry is None:
            return False
        giving = set(clean_caps(caps))
        keep = [cap for cap in clean_caps(entry.get("caps")) if cap not in giving]
        if len(keep) == len(entry.get("caps") or []):
            return False
        if not keep:
            return await self.revoke(node_hex)
        try:
            target = NodeID.from_hex(node_hex)
        except ValueError:
            return False
        self.state.add_managed(node_hex, caps=keep,
                               label=clean_label(entry.get("label")),
                               grant=self.state.grant_proof(node_hex))
        self._emit(CapsChanged(target, keep, "managed"))
        await self._send(target, self._signed_frame(
            ENROL_NARROW, target, PURPOSE_NARROW, {"caps": keep}))
        return True

    def _on_cap_narrow(self, src: NodeID, principal, document: dict) -> None:
        """Agent side: an operator handing a right back.

        ``narrow_only`` is what makes this safe to accept without a human: the
        set is intersected with what they already hold, so the worst a forged or
        replayed frame can do is take rights away from its own sender."""
        caps = clean_caps(document.get("caps"))
        node_hex = src.raw.hex()
        result = self.state.set_operator_caps(node_hex, caps, narrow_only=True)
        if result is None:
            return
        if "shell" not in result:
            self._drop_shells_of(src)
        if not result:
            self._emit(Revoked(src))
            return
        self._emit(CapsChanged(src, result, "operator"))

    async def set_operator_capabilities(self, node_hex: str,
                                        caps: list[str]) -> bool:
        """Agent side, driven by a human here: set what an operator may do.

        This is the only way a grant grows, and it is deliberately local: the
        person changing it is on the machine that bears the consequence."""
        wanted = clean_caps(caps)
        if self.state.operator(node_hex) is None:
            return False
        if not wanted:
            # An empty list means "cut them off"; a list that *cleaned* to empty
            # means we did not understand it, and must not be read as one.
            if caps:
                return False
            return await self.revoke(node_hex)
        caps = wanted
        result = self.state.set_operator_caps(node_hex, caps)
        if not result:
            return False
        try:
            target = NodeID.from_hex(node_hex)
        except ValueError:
            return False
        if "shell" not in result:
            self._drop_shells_of(target)
        self._emit(CapsChanged(target, result, "operator"))
        # Tell them, so their own list stops offering buttons that would now be
        # refused — and starts offering one that would not.
        await self._send(target, self._signed_frame(
            ENROL_GRANT, target, PURPOSE_GRANT,
            {"caps": result, "label": self.facts.hostname or ""}))
        return True

    # -- pre-authorisation (a machine we provisioned coming online) --------

    async def claim_preauth(self, document: dict) -> bool:
        """Agent side, first start after provisioning: adopt the operator whose
        key arrived over the SSH channel, then prove to them that *this* mesh
        identity is the machine they just installed."""
        operator_id = document["operator_id"]
        caps = clean_caps(document.get("capabilities"))
        if not caps:
            return False
        node_hex = operator_id.hex()
        if self.state.add_operator(node_hex, document["operator_pub"], caps=caps,
                                   label=clean_label(document.get("label"))) is None:
            return False
        target = NodeID(operator_id)
        await self._send(target, self._signed_frame(
            PREAUTH_CLAIM, target, PURPOSE_PREAUTH,
            {"token": document["token"].hex(), "caps": caps,
             "host": self.facts.hostname or ""}))
        return True

    def _on_preauth_claim(self, src: NodeID, principal, document: dict) -> None:
        """Operator side: match the token against a provisioning run we started.
        That binds a brand-new mesh identity to a machine we installed, without
        a human having to confirm anything on a headless box."""
        token_hex = document.get("token")
        if not isinstance(token_hex, str) or len(token_hex) != fleet_provision.TOKEN_LEN * 2:
            return
        try:
            token = bytes.fromhex(token_hex)
        except ValueError:
            return
        record = self.state.take_provisioned(fleet_provision.token_digest(token))
        if record is None:
            return          # unknown or already-claimed token — ignore
        caps = clean_caps(document.get("caps")) or clean_caps(record.get("caps"))
        label = clean_label(record.get("label")) or clean_label(document.get("host"))
        self.state.add_managed(src.raw.hex(), caps=caps, label=label)
        self._emit(NodeAdopted(src, str(record.get("host", ""))[:128], label))
        if self._auto_status:
            self._spawn(self.request_status(src))

    # ======================================================================
    # Status
    # ======================================================================

    async def request_status(self, target: NodeID) -> str:
        rid = self._new_rid(target, "status")
        await self._send(target, self._signed_frame(
            STATUS_REQUEST, target, PURPOSE_BY_CAP["status"], {"rid": rid}))
        return rid

    def _on_status_request(self, src: NodeID, principal, document: dict) -> None:
        rid = _rid(document)
        if not self._authorised(src, "status", rid):
            return
        self._reply(src, STATUS_REPORT,
                    {"rid": rid, "status": fleet_host.collect_status(self.facts)})

    def _on_status_report(self, src: NodeID, document: dict) -> None:
        if not self._claim_inflight(src, document, "status"):
            return
        status = document.get("status")
        if isinstance(status, dict):
            self.state.record_status(src.raw.hex(), status)
            self._emit(StatusReceived(src, status, _rid(document)))

    # ======================================================================
    # Update
    # ======================================================================

    async def request_update(self, target: NodeID) -> str:
        rid = self._new_rid(target, "update")
        await self._send(target, self._signed_frame(
            UPDATE_REQUEST, target, PURPOSE_BY_CAP["update"], {"rid": rid}))
        return rid

    def _on_update_request(self, src: NodeID, principal, document: dict) -> None:
        rid = _rid(document)
        if not self._authorised(src, "update", rid):
            return
        commands = fleet_host.update_plan(self.facts)
        if commands is None:
            self._fail(src, rid, "no package manager, or no path to root")
            return
        self._spawn(self._run_update(src, rid, commands))

    async def _run_update(self, src: NodeID, rid: str,
                          commands: list[list[str]]) -> None:
        """Run the host's own upgrade commands, streaming output back.

        Each command is an argv list built by :mod:`src.apps.fleet_host` from a
        fixed table — nothing the operator sent reaches it, so there is no
        command string to inject into."""
        ok = True
        status = 0
        started = time.monotonic()
        total = len(commands)
        for index, command in enumerate(commands, start=1):
            # Announced before it runs, not after: an update is minutes long and
            # a progress line that only appears once a step is over is not
            # progress, it is a summary.
            self._reply(src, UPDATE_OUTPUT, {
                "rid": rid, "kind": "update", "text": "",
                "step": {"index": index, "total": total,
                         "name": _step_name(command),
                         "elapsed": round(time.monotonic() - started, 1)}})
            status = await self._stream_command(src, rid, command, "update",
                                                UPDATE_OUTPUT, UPDATE_TIMEOUT)
            if status != 0:
                ok = False
                break
        self._reply(src, UPDATE_RESULT, {
            "rid": rid, "ok": ok, "status": status,
            "elapsed": round(time.monotonic() - started, 1)})

    async def _stream_command(self, src: NodeID, rid: str, argv: list[str],
                              kind: str, out_type: int, timeout: float) -> int:
        try:
            proc = await asyncio.create_subprocess_exec(
                *argv, stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                stdin=asyncio.subprocess.DEVNULL,
                env=_clean_env())
        except (OSError, ValueError) as exc:
            self._reply(src, out_type,
                        {"rid": rid, "kind": kind, "text": f"cannot run: {exc}"[:256]})
            return -1

        async def pump() -> None:
            while True:
                chunk = await proc.stdout.read(UPDATE_CHUNK)
                if not chunk:
                    return
                text = chunk.decode("utf-8", "replace")[:UPDATE_CHUNK]
                # The granted wrapper announces its own steps. Turn those into
                # progress rather than printing them as noise.
                step, text = _take_step_marker(text)
                document = {"rid": rid, "kind": kind, "text": text}
                if step is not None:
                    document["step"] = step
                if text or step is not None:
                    self._reply(src, out_type, document)

        pump_task = asyncio.create_task(pump())
        try:
            async with asyncio.timeout(timeout):
                return await proc.wait()
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except (ProcessLookupError, OSError):
                pass
            return -1
        finally:
            pump_task.cancel()
            try:
                await pump_task
            except (asyncio.CancelledError, Exception):
                pass

    def _on_update_output(self, src: NodeID, document: dict) -> None:
        rid = _rid(document)
        if rid not in self._inflight:
            return
        step = document.get("step")
        self._emit(CommandOutput(src, rid, "update",
                                 str(document.get("text", ""))[:UPDATE_CHUNK],
                                 step if isinstance(step, dict) else None))

    def _on_update_result(self, src: NodeID, document: dict) -> None:
        if not self._claim_inflight(src, document, "update"):
            return
        self._emit(CommandResult(src, _rid(document), "update",
                                 bool(document.get("ok")),
                                 {"status": document.get("status")}))
        if self._auto_status:
            self._spawn(self.request_status(src))

    # ======================================================================
    # Shell
    # ======================================================================

    async def open_shell(self, target: NodeID, *, cols: int = 80,
                         rows: int = 24) -> str:
        rid = self._new_rid(target, "shell")
        await self._send(target, self._signed_frame(
            SHELL_OPEN, target, PURPOSE_BY_CAP["shell"],
            {"rid": rid, "cols": _dim(cols), "rows": _dim(rows)}))
        return rid

    def _on_shell_open(self, src: NodeID, principal, document: dict) -> None:
        rid = _rid(document)
        if not self._authorised(src, "shell", rid):
            return
        if len(self._shells) >= MAX_SHELLS:
            self._fail(src, rid, "too many open shells")
            return
        self._spawn(self._spawn_shell(src, rid, _dim(document.get("cols")),
                                      _dim(document.get("rows"))))

    async def _spawn_shell(self, src: NodeID, rid: str, cols: int, rows: int) -> None:
        import pty
        shell_path = os.environ.get("SHELL") or shutil.which("bash") or "/bin/sh"
        master_fd, slave_fd = pty.openpty()
        _set_winsize(master_fd, cols, rows)
        try:
            proc = await asyncio.create_subprocess_exec(
                shell_path, "-i",
                stdin=slave_fd, stdout=slave_fd, stderr=slave_fd,
                start_new_session=True, env=_shell_env(),
                preexec_fn=_make_controlling_tty(slave_fd))
        except (OSError, ValueError) as exc:
            os.close(master_fd)
            os.close(slave_fd)
            self._fail(src, rid, f"cannot start shell: {exc}"[:128])
            return
        os.close(slave_fd)
        sid = secrets.token_bytes(SID_LEN)
        shell = _Shell(sid, src, proc, master_fd)
        self._shells[sid] = shell
        self._reply(src, SHELL_OPENED, {"rid": rid, "sid": sid.hex()})
        self._pump_shell(shell)

    def _pump_shell(self, shell: _Shell) -> None:
        """Stream the pty back to its operator until it closes.

        Reader-based, never a thread: a blocking read on a pty is joined at
        asyncio shutdown and wedges it (``gotchas.md`` §2)."""
        def on_chunk(chunk: bytes) -> None:
            shell.last_active = time.monotonic()
            self._spawn(self._send(shell.owner,
                                   bytes([SHELL_OUTPUT]) + shell.sid + chunk))

        def on_eof() -> None:
            status = shell.proc.returncode
            self._close_shell(shell.sid, status=status if status is not None else 0)

        shell.stop_reader = fleet_ssh.watch_pty(shell.master_fd, on_chunk, on_eof)

    def _close_shell(self, sid: bytes, *, status: int = 0,
                     notify: bool = True) -> None:
        shell = self._shells.pop(sid, None)
        if shell is None:
            return
        owner = shell.owner
        shell.close()
        if notify:
            self._spawn(self._send(owner, bytes([SHELL_CLOSE]) + sid
                                   + struct.pack("!h", max(-1, min(status, 255)))))

    def _dispatch_shell_stream(self, src: NodeID, kind: int, body: bytes) -> None:
        if len(body) < SID_LEN:
            return
        sid, rest = body[:SID_LEN], body[SID_LEN:]
        if kind == SHELL_INPUT:
            shell = self._shells.get(sid)
            # Session-bound: only the operator the shell was opened for may type
            # into it. A different peer naming the same sid is dropped.
            if shell is None or shell.owner != src or len(rest) > SHELL_INPUT_MAX:
                return
            shell.last_active = time.monotonic()
            try:
                os.write(shell.master_fd, rest)
            except OSError:
                self._close_shell(sid, status=-1)
        elif kind == SHELL_RESIZE:
            shell = self._shells.get(sid)
            if shell is None or shell.owner != src or len(rest) != _WINSIZE.size:
                return
            cols, rows = _WINSIZE.unpack(rest)
            _set_winsize(shell.master_fd, _dim(cols), _dim(rows))
        elif kind == SHELL_OUTPUT:
            if self._open_shells.get(sid) == src:
                self._emit(ShellOutput(src, sid, rest[:SHELL_CHUNK]))
        elif kind == SHELL_CLOSE:
            if self._open_shells.get(sid) == src:
                # Operator side: the agent hung up on a shell we had open.
                self._open_shells.pop(sid, None)
                status = struct.unpack("!h", rest)[0] if len(rest) == 2 else 0
                self._emit(ShellClosed(src, sid, status))
                return
            # Agent side: the operator asked us to hang up on a shell we host.
            shell = self._shells.get(sid)
            if shell is not None and shell.owner == src:
                self._close_shell(sid, status=0, notify=False)

    def _on_shell_opened(self, src: NodeID, document: dict) -> None:
        if not self._claim_inflight(src, document, "shell"):
            return
        sid = _hex_bytes(document.get("sid"), SID_LEN)
        if sid is None:
            return
        self._open_shells[sid] = src
        self._emit(ShellOpened(src, _rid(document), sid))

    async def shell_input(self, target: NodeID, sid: bytes, data: bytes) -> None:
        if self._open_shells.get(sid) != target or len(data) > SHELL_INPUT_MAX:
            return
        await self._send(target, bytes([SHELL_INPUT]) + sid + data)

    async def shell_resize(self, target: NodeID, sid: bytes, cols: int,
                           rows: int) -> None:
        if self._open_shells.get(sid) != target:
            return
        await self._send(target, bytes([SHELL_RESIZE]) + sid
                         + _WINSIZE.pack(_dim(cols), _dim(rows)))

    async def close_shell(self, target: NodeID, sid: bytes) -> None:
        if self._open_shells.pop(sid, None) != target:
            return
        await self._send(target, bytes([SHELL_CLOSE]) + sid + b"\x00\x00")

    # ======================================================================
    # LAN scan
    # ======================================================================

    async def request_scan(self, target: NodeID,
                           targets: list[str] | None = None) -> str:
        """Ask ``target`` to look for SSH hosts. ``targets`` may name subnets
        *or* precise machines (``10.0.0.5``, ``nas.lan:2222``); empty means
        every network that node is attached to."""
        rid = self._new_rid(target, "scan")
        document = {"rid": rid}
        if targets:
            document["targets"] = [str(t)[:255] for t in targets][:64]
        await self._send(target, self._signed_frame(
            SCAN_REQUEST, target, PURPOSE_BY_CAP["scan"], document))
        return rid

    def _on_scan_request(self, src: NodeID, principal, document: dict) -> None:
        rid = _rid(document)
        if not self._authorised(src, "scan", rid):
            return
        entries = document.get("targets")
        entries = [t for t in entries if isinstance(t, str)][:64] \
            if isinstance(entries, list) else None
        self._spawn(self._run_scan(src, rid, entries))

    async def _run_scan(self, src: NodeID, rid: str,
                        entries: list[str] | None) -> None:
        try:
            async with asyncio.timeout(SCAN_TIMEOUT):
                hosts, rejected = await fleet_ssh.scan(entries)
        except (asyncio.TimeoutError, OSError):
            self._fail(src, rid, "scan timed out")
            return
        except Exception as exc:
            self._fail(src, rid, f"scan failed: {type(exc).__name__}")
            return
        # Fingerprints let the operator confirm host keys before provisioning,
        # which is what makes the later trust-on-first-use an informed one.
        # Bounded and concurrent: one ssh-keyscan per host, run in series with
        # no overall deadline, left a remote scan looking stalled for minutes
        # while the operator saw nothing at all.
        await fleet_ssh.attach_host_keys(hosts, timeout=KEYSCAN_TIMEOUT)
        self._reply(src, SCAN_RESULT, {
            "rid": rid, "hosts": hosts[:256],
            "targets": entries or fleet_ssh.local_subnets(),
            # Anything we could not make sense of comes back named, so a typo
            # reads as a typo instead of "nothing found".
            "rejected": rejected[:32],
            # What this node is actually attached to, prefix and interface
            # included, so the operator sees whether a big network was narrowed
            # rather than silently swept in part.
            "networks": [] if entries else fleet_ssh.detected_networks(),
            "ssh_client": fleet_ssh.ssh_available(),
        }, "hosts", "networks", "rejected", "targets")

    def _on_scan_result(self, src: NodeID, document: dict) -> None:
        if not self._claim_inflight(src, document, "scan"):
            return
        hosts = document.get("hosts")
        networks = document.get("networks")
        rejected = document.get("rejected")
        truncated = document.get("truncated")
        self._emit(ScanReceived(src, _rid(document),
                                hosts[:256] if isinstance(hosts, list) else [],
                                networks[:32] if isinstance(networks, list) else [],
                                rejected[:32] if isinstance(rejected, list) else [],
                                truncated if isinstance(truncated, int) else 0))

    # ======================================================================
    # Provisioning
    # ======================================================================

    async def request_provision(self, target: NodeID, *, targets: list[dict],
                                username: str, password: str | None = None,
                                key_path: str | None = None,
                                key_data: str | None = None,
                                key_passphrase: str | None = None,
                                can_sudo: bool = True,
                                sudo_user: str | None = None,
                                sudo_password: str | None = None,
                                mode: str = "system",
                                caps: list[str] | None = None,
                                join_uris: list[str] | None = None,
                                join_code: str | None = None) -> str:
        """Operator side: have ``target`` install NMesh on machines it can reach.

        The SSH credential travels inside the end-to-end-encrypted DATA payload
        to a node this operator explicitly trusts, and is wiped there as soon as
        the run ends. It is never written to disk on either side. That trust is
        already total — ``provision`` implies the far node runs code we send it —
        so this adds no exposure that enrolment did not already grant."""
        rid = self._new_rid(target, "provision")
        document = {
            "rid": rid,
            "targets": _clean_targets(targets),
            "username": str(username)[:64],
            "caps": clean_caps(caps) if caps else ["status", "update"],
            "join_uris": [str(u)[:256] for u in (join_uris or [])][:8],
            "join_code": str(join_code or "")[:64],
            "mode": "user" if str(mode) == "user" else "system",
            "can_sudo": bool(can_sudo),
        }
        if sudo_user:
            document["sudo_user"] = str(sudo_user)[:64]
        if sudo_password:
            # Same channel and same reasoning as the SSH password below: E2E
            # encrypted, to a node already trusted with `provision`, wiped there.
            document["sudo_password"] = str(sudo_password)
        if password:
            document["password"] = str(password)
        if key_path:
            document["key_path"] = str(key_path)[:512]
        if key_data:
            # A key the far node has no path for (uploaded through the console).
            # It rides the same end-to-end-encrypted payload as the password,
            # to a node already trusted with `provision`, and is wiped there.
            document["key_data"] = str(key_data)[:MAX_KEY_DATA]
        if key_passphrase:
            document["key_passphrase"] = str(key_passphrase)
        await self._send(target, self._signed_frame(
            PROVISION_REQUEST, target, PURPOSE_BY_CAP["provision"], document))
        return rid

    def _on_provision_request(self, src: NodeID, principal, document: dict) -> None:
        rid = _rid(document)
        if not self._authorised(src, "provision", rid):
            return
        if self._repo_root is None:
            self._fail(src, rid, "no NMesh tree to push from this node")
            return
        if not fleet_ssh.ssh_available():
            self._fail(src, rid, "no ssh client on this node")
            return
        self._spawn(self._run_provision(src, rid, document))

    async def _run_provision(self, src: NodeID, rid: str, document: dict) -> None:
        targets = _clean_targets(document.get("targets"))
        if not targets:
            self._fail(src, rid, "no targets")
            return
        try:
            creds = fleet_ssh.SshCredentials(
                str(document.get("username", "")),
                password=document.get("password"),
                key_path=document.get("key_path"),
                key_data=_key_material(document.get("key_data")),
                key_passphrase=document.get("key_passphrase"),
                can_sudo=bool(document.get("can_sudo", True)),
                sudo_user=document.get("sudo_user"),
                sudo_password=document.get("sudo_password"))
        except fleet_ssh.SshError as exc:
            self._fail(src, rid, str(exc))
            return
        mode = "user" if document.get("mode") == "user" else "system"
        if mode == "system" and not creds.has_elevation:
            self._fail(src, rid, "a system install needs root on the target: "
                                 "the login account must be able to sudo, or "
                                 "another account must be named")
            return
        try:
            payload = fleet_provision.build_payload(self._repo_root)
        except fleet_provision.ProvisionError as exc:
            self._fail(src, rid, str(exc))
            return

        caps = clean_caps(document.get("caps")) or ["status", "update"]
        join_uris = document.get("join_uris")
        join_uris = [u for u in join_uris if isinstance(u, str)][:8] \
            if isinstance(join_uris, list) else []
        results = []
        try:
            for target in targets:
                results.append(await self._provision_one(
                    src, rid, target, creds, payload, caps, join_uris,
                    str(document.get("join_code") or ""), mode))
        finally:
            creds.wipe()          # the secret does not outlive the run
        self._reply(src, PROVISION_RESULT, {"rid": rid, "results": results},
                    "results")

    async def _provision_one(self, src: NodeID, rid: str, target: dict,
                             creds, payload: bytes, caps: list[str],
                             join_uris: list[str], join_code: str,
                             mode: str = "system") -> dict:
        """Provision one machine, reporting each step as it happens.

        The pre-authorisation is minted *here*, on the node doing the SSH, but
        it names the **operator** as the node to trust — the machine we install
        ends up managed by the human who asked, not by the relay that installed
        it."""
        host = target["ip"]
        # The mesh invitation comes from *this* node — the one running the scan
        # and the SSH. It is on the same LAN as the machine being installed, so
        # it is the one actually reachable, and the certificate it issues at the
        # handshake anchors the newcomer to the network. The operator is a
        # separate matter: it is who the machine will *obey*, carried by the
        # pre-authorisation, and it need not be reachable at first boot.
        uris, code = self._fresh_invitation(join_uris, join_code)
        preauth, token = fleet_provision.make_preauth(
            src.raw, self._operator_key(src), capabilities=caps,
            join_uris=uris, join_code=code,
            label=target.get("label", host))
        self._reply(src, PROVISION_PROGRESS, {
            "rid": rid, "host": host, "step": "starting",
            "token_digest": fleet_provision.token_digest(token)})

        def on_progress(hostname: str, step: str) -> None:
            self._reply(src, PROVISION_PROGRESS,
                        {"rid": rid, "host": hostname, "step": step[:256]})

        result = await fleet_provision.provision_host(
            host, creds, payload=payload, preauth=preauth,
            port=int(target.get("port") or 22),
            known_hosts_lines=target.get("known_hosts"),
            mode=mode, on_progress=on_progress)
        result["token_digest"] = fleet_provision.token_digest(token)
        result["label"] = target.get("label", host)
        # Installed but with nowhere to join is a half-success worth naming: the
        # machine will run and never appear on the mesh.
        result["joins"] = bool(uris and code)
        return result

    def _fresh_invitation(self, fallback_uris: list[str],
                          fallback_code: str) -> tuple[list[str], str]:
        """One single-use mesh invitation for one machine.

        Minted per target, never shared: an invitation is single-use by design,
        so one machine failing to come up must not burn another's. The window is
        long because the machine only redeems it *after* installing its
        dependencies, which can take a long while on a small box.

        Falls back to whatever the caller passed when this node cannot invite
        (no provider wired) — the machine is then installed but joins nothing,
        which the caller reports rather than hiding."""
        if self._mesh_invite is None:
            return fallback_uris, fallback_code
        try:
            invitation = self._mesh_invite()
        except Exception:
            return fallback_uris, fallback_code
        if not isinstance(invitation, dict):
            return fallback_uris, fallback_code
        uris = invitation.get("uris")
        code = invitation.get("code")
        if not isinstance(code, str) or not code:
            return fallback_uris, fallback_code
        uris = [u for u in uris if isinstance(u, str)][:8] \
            if isinstance(uris, list) else []
        return (uris or fallback_uris), code

    def _operator_key(self, src: NodeID) -> bytes:
        entry = self.state.operator(src.raw.hex()) or {}
        try:
            return bytes.fromhex(entry.get("pub", ""))
        except ValueError:
            return b""

    def _on_provision_progress(self, src: NodeID, document: dict) -> None:
        rid = _rid(document)
        if rid not in self._inflight:
            return
        digest = document.get("token_digest")
        if isinstance(digest, str) and len(digest) == 64:
            # Remember the run *now*: the new node may claim its token before
            # the batch finishes, and an unknown claim is dropped.
            self.state.add_provisioned(
                digest, host=str(document.get("host", ""))[:128],
                caps=["status", "update"],
                label=str(document.get("host", ""))[:128])
        self._emit(CommandOutput(src, rid, "provision",
                                 f"{document.get('host', '?')}: "
                                 f"{str(document.get('step', ''))[:256]}"))

    def _on_provision_result(self, src: NodeID, document: dict) -> None:
        if not self._claim_inflight(src, document, "provision"):
            return
        results = document.get("results")
        results = [r for r in results if isinstance(r, dict)][:64] \
            if isinstance(results, list) else []
        for entry in results:
            digest = entry.get("token_digest")
            if entry.get("ok") and isinstance(digest, str) and len(digest) == 64:
                self.state.add_provisioned(
                    digest, host=str(entry.get("host", ""))[:128],
                    caps=["status", "update"],
                    label=str(entry.get("label") or entry.get("host", ""))[:128])
        self._emit(CommandResult(src, _rid(document), "provision",
                                 all(r.get("ok") for r in results) if results else False,
                                 {"results": results}))

    # ======================================================================
    # Local provisioning (this node's own LAN, no relay involved)
    # ======================================================================

    async def scan_local(self, entries: list[str] | None = None) -> dict:
        hosts, rejected = await fleet_ssh.scan(entries)
        await fleet_ssh.attach_host_keys(hosts, timeout=KEYSCAN_TIMEOUT)
        return {"hosts": hosts, "rejected": rejected[:32],
                "targets": entries or fleet_ssh.local_subnets(),
                "networks": [] if entries else fleet_ssh.detected_networks(),
                "ssh_client": fleet_ssh.ssh_available(),
                "keys": fleet_ssh.discover_private_keys()}

    async def provision_local(self, targets: list[dict], *, username: str,
                              password: str | None = None,
                              key_path: str | None = None,
                              key_data: str | None = None,
                              key_passphrase: str | None = None,
                              can_sudo: bool = True,
                              sudo_user: str | None = None,
                              sudo_password: str | None = None,
                              mode: str = "system",
                              caps: list[str] | None = None,
                              join_uris: list[str] | None = None,
                              join_code: str | None = None,
                              on_progress=None) -> list[dict]:
        """Provision machines on *our* LAN, from this node, for ourselves.

        ``mode`` decides where the node lands: ``"system"`` gives it the
        dedicated service account under ``/opt`` that a host machine should
        have, ``"user"`` installs under the login account for a machine where
        root is not available."""
        if self._repo_root is None:
            raise fleet_provision.ProvisionError("no NMesh tree to push")
        targets = _clean_targets(targets)
        creds = fleet_ssh.SshCredentials(username, password=password,
                                         key_path=key_path, key_data=key_data,
                                         key_passphrase=key_passphrase,
                                         can_sudo=can_sudo,
                                         sudo_user=sudo_user,
                                         sudo_password=sudo_password)
        if mode == "system" and not creds.has_elevation:
            raise fleet_provision.ProvisionError(
                "a system install needs root on the target: either the login "
                "account can sudo, or name one that can — or install under the "
                "login account instead")
        payload = fleet_provision.build_payload(self._repo_root)
        caps = clean_caps(caps) or ["status", "update"]
        results = []
        try:
            for target in targets:
                uris, code = self._fresh_invitation(join_uris or [],
                                                    join_code or "")
                preauth, token = fleet_provision.make_preauth(
                    self.node_id.raw, self._auth.public_key,
                    capabilities=caps, join_uris=uris, join_code=code,
                    label=target.get("label", target["ip"]))
                digest = fleet_provision.token_digest(token)
                self.state.add_provisioned(digest, host=target["ip"], caps=caps,
                                           label=target.get("label", target["ip"]))
                result = await fleet_provision.provision_host(
                    target["ip"], creds, payload=payload, preauth=preauth,
                    port=int(target.get("port") or 22),
                    known_hosts_lines=target.get("known_hosts"),
                    mode=mode, on_progress=on_progress)
                result["token_digest"] = digest
                result["joins"] = bool(uris and code)
                results.append(result)
        finally:
            creds.wipe()
        return results

    # -- in-flight request bookkeeping ------------------------------------

    def _new_rid(self, target: NodeID, kind: str) -> str:
        rid = secrets.token_hex(RID_LEN)
        while len(self._inflight) >= MAX_INFLIGHT:
            self._inflight.pop(next(iter(self._inflight)), None)
        self._inflight[rid] = (target, kind, time.monotonic())
        return rid

    def _claim_inflight(self, src: NodeID, document: dict, kind: str) -> bool:
        """A reply counts only if it answers a request *we* minted, for this
        kind, from the node we sent it to. Unsolicited replies are dropped."""
        rid = _rid(document)
        entry = self._inflight.get(rid)
        if entry is None or entry[0] != src or entry[1] != kind:
            return False
        self._inflight.pop(rid, None)
        return True

    def _on_error(self, src: NodeID, document: dict) -> None:
        rid = _rid(document)
        entry = self._inflight.pop(rid, None)
        if entry is not None and entry[0] == src:
            self._emit(Failure(src, rid, str(document.get("error", ""))[:256]))


# ---------------------------------------------------------------------------
# Helpers — all hostile-input safe
# ---------------------------------------------------------------------------

def _key_material(value) -> str | None:
    """Validate key material arriving from the network before it is written to
    a file. Shape check only — OpenSSH reads the file and is the real judge."""
    if not isinstance(value, str) or not 0 < len(value) <= MAX_KEY_DATA:
        return None
    return value if "PRIVATE KEY" in value else None


def _dump_json(document: dict, *trim_keys: str) -> bytes:
    """Serialise a reply so it fits one DATA frame.

    Cutting JSON at a byte offset produces something the far side cannot parse
    and therefore drops in silence — the worst possible failure for a reply the
    operator is waiting on. So we drop **entries**, never bytes: the named list
    keys are shortened until the frame fits, and ``truncated`` says how many
    went. A short answer beats an answer that never arrives."""
    blob = _encode(document)
    if len(blob) <= MAX_BODY:
        return blob
    document = dict(document)
    dropped = 0
    for key in trim_keys:
        items = document.get(key)
        if not isinstance(items, list) or not items:
            continue
        keep = len(items)
        while keep > 0:
            keep = keep * 3 // 4 if keep > 4 else keep - 1
            document[key] = items[:keep]
            document["truncated"] = dropped + (len(items) - keep)
            blob = _encode(document)
            if len(blob) <= MAX_BODY:
                return blob
        dropped += len(items)
        document[key] = []
    # Even with every list emptied the fixed part is too big: say so rather
    # than send a frame nobody can read.
    return _encode({"rid": str(document.get("rid", ""))[:RID_LEN * 2],
                    "truncated": dropped, "error": "reply too large"})


def _encode(document: dict) -> bytes:
    return json.dumps(document, separators=(",", ":")).encode("utf-8")


def _load_json(raw: bytes) -> dict | None:
    if not raw or len(raw) > MAX_BODY:
        return None
    try:
        document = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None
    return document if isinstance(document, dict) else None


def _rid(document: dict) -> str:
    rid = document.get("rid")
    return rid[:RID_LEN * 2] if isinstance(rid, str) else ""


def _hex_bytes(value, length: int) -> bytes | None:
    if not isinstance(value, str) or len(value) != length * 2:
        return None
    try:
        return bytes.fromhex(value)
    except ValueError:
        return None


def _dim(value) -> int:
    """Clamp a terminal dimension. A hostile winsize must not reach ioctl raw."""
    try:
        return max(1, min(int(value), 1000))
    except (TypeError, ValueError):
        return 24


def _clean_targets(raw) -> list[dict]:
    """Validate a provisioning target list from the network."""
    if not isinstance(raw, list):
        return []
    out = []
    for entry in raw[:64]:
        if not isinstance(entry, dict):
            continue
        ip = entry.get("ip")
        if not isinstance(ip, str) or not 0 < len(ip) <= 64:
            continue
        try:
            port = int(entry.get("port") or 22)
        except (TypeError, ValueError):
            port = 22
        known = entry.get("known_hosts")
        out.append({
            "ip": ip,
            "port": port if 0 < port < 65536 else 22,
            "label": str(entry.get("label") or ip)[:128],
            "known_hosts": [k for k in known if isinstance(k, str)][:8]
                           if isinstance(known, list) else [],
        })
    return out


def _set_winsize(fd: int, cols: int, rows: int) -> None:
    try:
        import fcntl
        import termios
        fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
    except Exception:
        pass


_STEP_MARKER = "::nmesh-step::"


def _step_name(command: list) -> str:
    """A human name for a step, from the command about to run."""
    if not command:
        return "step"
    tail = [part for part in command if not part.startswith("-")]
    binary = os.path.basename(tail[0]) if tail else os.path.basename(command[0])
    if binary in ("sudo", "doas") and len(tail) > 1:
        binary = os.path.basename(tail[1])
    verb = next((part for part in command[1:]
                 if not part.startswith("-") and "/" not in part), "")
    return f"{binary} {verb}".strip()


def _take_step_marker(text: str):
    """Split a chunk into ``(step, remaining text)``.

    The wrapper announces its own steps on stdout because it is the only thing
    that knows how many it has. Recognising them here keeps them out of the
    output pane, where they would read as noise."""
    if _STEP_MARKER not in text:
        return None, text
    step = None
    kept = []
    for line in text.splitlines(keepends=True):
        marker = line.strip()
        if marker.startswith(_STEP_MARKER):
            body = marker[len(_STEP_MARKER):].strip()
            if body == "done":
                continue
            index, _, name = body.partition(" ")
            position, _, total = index.partition("/")
            try:
                step = {"index": int(position), "total": int(total or position),
                        "name": name or "step"}
            except ValueError:
                step = None
            continue
        kept.append(line)
    return step, "".join(kept)


def _clean_env() -> dict:
    """A minimal environment for a spawned maintenance command. The node's own
    connector token lives in ``os.environ``; never hand it to a child."""
    keep = ("PATH", "HOME", "LANG", "LC_ALL", "TERM", "USER", "LOGNAME")
    env = {k: v for k, v in os.environ.items() if k in keep}
    env.setdefault("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
    env["DEBIAN_FRONTEND"] = "noninteractive"
    return env


def _shell_env() -> dict:
    env = _clean_env()
    env.pop("DEBIAN_FRONTEND", None)
    env["TERM"] = os.environ.get("TERM", "xterm-256color")
    return env


# Dispatch tables, built once. Keeping them beside the handlers makes the set of
# accepted message types explicit: anything not listed here is dropped.
_SIGNED_INBOUND = {
    ENROL_REQUEST: FleetApp._on_enrol_request,
    ENROL_GRANT: FleetApp._on_enrol_grant,
    ENROL_DENY: FleetApp._on_enrol_deny,
    ENROL_REVOKE: FleetApp._on_revoke,
    ENROL_NARROW: FleetApp._on_cap_narrow,
    PREAUTH_CLAIM: FleetApp._on_preauth_claim,
    STATUS_REQUEST: FleetApp._on_status_request,
    UPDATE_REQUEST: FleetApp._on_update_request,
    SHELL_OPEN: FleetApp._on_shell_open,
    SCAN_REQUEST: FleetApp._on_scan_request,
    PROVISION_REQUEST: FleetApp._on_provision_request,
}

_PURPOSE_FOR = {
    ENROL_REQUEST: PURPOSE_ENROL,
    ENROL_GRANT: PURPOSE_GRANT,
    ENROL_DENY: PURPOSE_GRANT,
    ENROL_REVOKE: PURPOSE_GRANT,
    ENROL_NARROW: PURPOSE_NARROW,
    PREAUTH_CLAIM: PURPOSE_PREAUTH,
    STATUS_REQUEST: PURPOSE_BY_CAP["status"],
    UPDATE_REQUEST: PURPOSE_BY_CAP["update"],
    SHELL_OPEN: PURPOSE_BY_CAP["shell"],
    SCAN_REQUEST: PURPOSE_BY_CAP["scan"],
    PROVISION_REQUEST: PURPOSE_BY_CAP["provision"],
}

_REPLY_INBOUND = {
    STATUS_REPORT: FleetApp._on_status_report,
    UPDATE_OUTPUT: FleetApp._on_update_output,
    UPDATE_RESULT: FleetApp._on_update_result,
    SHELL_OPENED: FleetApp._on_shell_opened,
    SCAN_RESULT: FleetApp._on_scan_result,
    PROVISION_PROGRESS: FleetApp._on_provision_progress,
    PROVISION_RESULT: FleetApp._on_provision_result,
    ERROR: FleetApp._on_error,
}
