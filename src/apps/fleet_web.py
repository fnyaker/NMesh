"""
Console bridge for the fleet app.

Same shape as :mod:`src.apps.chat_web`: the HTTP front-end runs on the console's
server thread while the app lives on the event loop, so this class is the
thread-safe seam between them. It subscribes to the app's events, keeps a
bounded model the browser can poll, and marshals every action back onto the
loop.

A monotonic ``version`` counter drives polling: any change — a new enrolment
request, a status report, a line of update output, a byte of shell — bumps it, so
the front-end knows to redraw without diffing everything itself.

Everything the browser can reach is bounded: log lines, scan results, shell
backlog per session, and the number of live shells. A managed node that floods
its operator with output costs a bounded amount of memory and nothing more.
"""
from __future__ import annotations

import asyncio
import base64
import threading
import time
from collections import OrderedDict, deque

from ..node_id import NodeID
from .fleet import (
    CommandOutput, CommandResult, EnrolAnswered, EnrolRequested, Failure,
    NodeAdopted, Revoked, ScanReceived, ShellClosed, ShellOpened, ShellOutput,
    StatusReceived,
)
from .fleet_state import CAP_DESCRIPTIONS, CAPABILITIES, clean_caps

MAX_LOG = 500                 # activity lines kept for the UI
MAX_SHELL_BACKLOG = 256 * 1024   # bytes buffered per shell session
MAX_SHELLS = 8                # shell sessions tracked at once
MAX_SCAN_HOSTS = 256
_CALL_TIMEOUT = 30.0


class FleetBridge:
    """Loop-thread-safe fleet state + actions for the console front-end."""

    def __init__(self, fleet_app) -> None:
        self._app = fleet_app
        self._loop: asyncio.AbstractEventLoop | None = None
        self._lock = threading.Lock()
        self._version = 0
        self._log: deque = deque(maxlen=MAX_LOG)
        self._log_seq = 0
        self._scans: dict[str, dict] = {}          # node hex -> last scan result
        self._shells: "OrderedDict[str, dict]" = OrderedDict()
        self._notice: str = ""

    # -- lifecycle --------------------------------------------------------

    def start(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop
        self._app.add_listener(self._on_event)

    def stop(self) -> None:
        self._app.remove_listener(self._on_event)

    @property
    def me(self) -> str:
        return self._app.node_id.raw.hex()

    def _bump(self) -> None:
        self._version += 1

    def _say(self, level: str, text: str, node: str = "") -> None:
        with self._lock:
            self._log_seq += 1
            self._log.append({"seq": self._log_seq, "at": time.time(),
                              "level": level, "text": text[:512], "node": node})
            self._bump()

    # -- events from the app ----------------------------------------------

    def _on_event(self, event) -> None:
        node = getattr(event, "src", None)
        node_hex = node.raw.hex() if isinstance(node, NodeID) else ""
        short = node_hex[:12]
        if isinstance(event, EnrolRequested):
            self._say("warn", f"{short}… asks to manage this node "
                              f"({', '.join(event.caps)})", node_hex)
        elif isinstance(event, EnrolAnswered):
            self._say("ok" if event.granted else "warn",
                      f"{short}… {'granted ' + ', '.join(event.caps) if event.granted else 'denied: ' + event.reason}",
                      node_hex)
        elif isinstance(event, NodeAdopted):
            self._say("ok", f"{event.host or short}… came online and joined "
                            f"the fleet", node_hex)
        elif isinstance(event, Revoked):
            self._say("warn", f"{short}… revoked the relationship", node_hex)
        elif isinstance(event, StatusReceived):
            with self._lock:
                self._bump()
        elif isinstance(event, CommandOutput):
            self._say("out", event.text.rstrip(), node_hex)
        elif isinstance(event, CommandResult):
            self._say("ok" if event.ok else "err",
                      f"{event.kind} {'finished' if event.ok else 'failed'} "
                      f"on {short}…", node_hex)
        elif isinstance(event, ScanReceived):
            with self._lock:
                self._scans[node_hex] = {"at": time.time(),
                                         "hosts": event.hosts[:MAX_SCAN_HOSTS],
                                         "networks": event.networks[:32],
                                         "rejected": event.rejected[:32]}
                self._bump()
            self._say("ok", f"{short}… swept {_describe(event.networks)} and "
                            f"found {len(event.hosts)} SSH host(s)", node_hex)
            for bad in event.rejected:
                self._say("warn", f"{short}… could not understand target "
                                  f"{bad!r}", node_hex)
        elif isinstance(event, ShellOpened):
            self._open_shell_record(event.sid.hex(), node_hex)
            self._say("ok", f"shell opened on {short}…", node_hex)
        elif isinstance(event, ShellOutput):
            self._append_shell(event.sid.hex(), event.data)
        elif isinstance(event, ShellClosed):
            with self._lock:
                record = self._shells.get(event.sid.hex())
                if record is not None:
                    record["open"] = False
                    record["status"] = event.status
                self._bump()
            self._say("warn", f"shell closed on {short}…", node_hex)
        elif isinstance(event, Failure):
            self._say("err", f"{short}…: {event.error}", node_hex)

    def _open_shell_record(self, sid: str, node_hex: str) -> None:
        with self._lock:
            while len(self._shells) >= MAX_SHELLS:
                self._shells.popitem(last=False)
            self._shells[sid] = {"sid": sid, "node": node_hex, "open": True,
                                 "data": bytearray(), "seq": 0, "status": None,
                                 "at": time.time()}
            self._bump()

    def _append_shell(self, sid: str, data: bytes) -> None:
        with self._lock:
            record = self._shells.get(sid)
            if record is None:
                return          # output for a session we are not showing
            buffer = record["data"]
            buffer += data
            if len(buffer) > MAX_SHELL_BACKLOG:
                # Keep the tail: a terminal's recent output is what matters.
                del buffer[:len(buffer) - MAX_SHELL_BACKLOG]
            record["seq"] += len(data)
            self._bump()

    # -- snapshot (what the browser polls) --------------------------------

    def snapshot(self, since: int = 0) -> dict:
        state = self._app.state
        with self._lock:
            version = self._version + state.version
            log = [entry for entry in self._log if entry["seq"] > since]
            scans = {node: dict(value) for node, value in self._scans.items()}
            shells = [{"sid": r["sid"], "node": r["node"], "open": r["open"],
                       "seq": r["seq"], "status": r["status"]}
                      for r in self._shells.values()]
        return {
            "me": self.me,
            "version": version,
            "log_seq": self._log_seq,
            "log": log,
            "managed": sorted(state.managed(),
                              key=lambda entry: entry.get("label") or entry["id"]),
            "operators": state.operators(),
            "pending_in": state.pending_in(),
            "pending_out": state.pending_out(),
            "provisioned": state.provisioned(),
            "scans": scans,
            "shells": shells,
            "capabilities": [{"name": cap, "description": CAP_DESCRIPTIONS[cap]}
                             for cap in CAPABILITIES],
            "host": self._app.facts.as_dict(),
            "notice": self._notice,
        }

    def shell_data(self, sid: str, offset: int = 0) -> dict | None:
        """Terminal bytes since ``offset``, base64-encoded (a terminal stream is
        not text, and must not be mangled by JSON's encoding)."""
        with self._lock:
            record = self._shells.get(sid)
            if record is None:
                return None
            buffer = bytes(record["data"])
            total = record["seq"]
            # The buffer holds the tail; map an absolute offset onto it.
            start = max(0, len(buffer) - max(0, total - offset))
            return {"sid": sid, "seq": total, "open": record["open"],
                    "status": record["status"],
                    "data": base64.b64encode(buffer[start:]).decode("ascii")}

    # -- actions (marshalled onto the node's loop) ------------------------

    def _call(self, coro, timeout: float = _CALL_TIMEOUT):
        if self._loop is None:
            raise RuntimeError("fleet bridge not started")
        return asyncio.run_coroutine_threadsafe(coro, self._loop).result(timeout)

    @staticmethod
    def _node(node_hex: str) -> NodeID:
        return NodeID.from_hex(str(node_hex))

    def enrol(self, node_hex: str, caps, label: str = "") -> bool:
        caps = clean_caps(caps)
        if not caps:
            return False
        return self._call(self._app.request_enrolment(
            self._node(node_hex), caps=caps, label=str(label)[:128]))

    def approve(self, node_hex: str, caps=None) -> bool:
        return self._call(self._app.approve_enrolment(
            str(node_hex), clean_caps(caps) if caps else None))

    def deny(self, node_hex: str, reason: str = "") -> bool:
        return self._call(self._app.deny_enrolment(str(node_hex),
                                                   str(reason)[:256]))

    def revoke(self, node_hex: str) -> bool:
        return self._call(self._app.revoke(str(node_hex)))

    def status(self, node_hex: str) -> str:
        return self._call(self._app.request_status(self._node(node_hex)))

    def update(self, node_hex: str) -> str:
        return self._call(self._app.request_update(self._node(node_hex)))

    def scan(self, node_hex: str, targets=None) -> str:
        return self._call(self._app.request_scan(self._node(node_hex), targets))

    def open_shell(self, node_hex: str, cols: int = 80, rows: int = 24) -> str:
        return self._call(self._app.open_shell(self._node(node_hex),
                                               cols=cols, rows=rows))

    def shell_input(self, node_hex: str, sid: str, data: bytes) -> bool:
        raw = bytes.fromhex(sid) if _is_hex(sid) else b""
        if not raw:
            return False
        self._call(self._app.shell_input(self._node(node_hex), raw, data))
        return True

    def shell_resize(self, node_hex: str, sid: str, cols: int, rows: int) -> bool:
        raw = bytes.fromhex(sid) if _is_hex(sid) else b""
        if not raw:
            return False
        self._call(self._app.shell_resize(self._node(node_hex), raw, cols, rows))
        return True

    def close_shell(self, node_hex: str, sid: str) -> bool:
        raw = bytes.fromhex(sid) if _is_hex(sid) else b""
        if not raw:
            return False
        self._call(self._app.close_shell(self._node(node_hex), raw))
        with self._lock:
            record = self._shells.get(sid)
            if record is not None:
                record["open"] = False
            self._bump()
        return True

    def provision(self, node_hex: str, targets, *, username: str,
                  password: str | None = None, key_path: str | None = None,
                  key_passphrase: str | None = None, caps=None,
                  join_uris=None, join_code: str | None = None) -> str:
        """Kick off a provisioning run on a managed node.

        The credential passed in from the browser is handed straight to the app
        and never stored here — the bridge keeps a log of *steps*, never of the
        login that produced them."""
        return self._call(self._app.request_provision(
            self._node(node_hex), targets=targets, username=username,
            password=password, key_path=key_path,
            key_passphrase=key_passphrase, caps=clean_caps(caps) if caps else None,
            join_uris=join_uris, join_code=join_code))

    # -- local (this node's own LAN) --------------------------------------

    def scan_local(self, targets=None) -> dict:
        result = self._call(self._app.scan_local(targets), timeout=360.0)
        networks = result.get("networks") or []
        with self._lock:
            self._scans[self.me] = {"at": time.time(),
                                    "hosts": result["hosts"][:MAX_SCAN_HOSTS],
                                    "networks": networks[:32],
                                    "rejected": (result.get("rejected") or [])[:32]}
            self._bump()
        self._say("ok", f"local scan swept {_describe(networks, result.get('targets'))}"
                        f" and found {len(result['hosts'])} SSH host(s)", self.me)
        for bad in result.get("rejected") or []:
            self._say("warn", f"could not understand target {bad!r}", self.me)
        return result

    def provision_local(self, targets, *, username: str,
                        password: str | None = None, key_path: str | None = None,
                        key_passphrase: str | None = None, caps=None,
                        join_uris=None, join_code: str | None = None) -> list:
        def on_progress(host: str, step: str) -> None:
            self._say("out", f"{host}: {step}", self.me)

        results = self._call(self._app.provision_local(
            targets, username=username, password=password, key_path=key_path,
            key_passphrase=key_passphrase, caps=caps, join_uris=join_uris,
            join_code=join_code, on_progress=on_progress), timeout=3600.0)
        ok = sum(1 for entry in results if entry.get("ok"))
        self._say("ok" if ok == len(results) else "err",
                  f"provisioned {ok}/{len(results)} machine(s)", self.me)
        return results

    def local_keys(self) -> list:
        from . import fleet_ssh
        return fleet_ssh.discover_private_keys()


def _describe(networks, targets=None) -> str:
    """One line naming what a sweep covered, so "found nothing" is never
    ambiguous about *where* it looked."""
    if not networks:
        named = [str(t) for t in (targets or [])][:4]
        return ", ".join(named) if named else "the given targets"
    parts = []
    for entry in networks[:4]:
        text = str(entry.get("scan") or entry.get("cidr") or "?")
        if entry.get("interface"):
            text += f" ({entry['interface']})"
        if entry.get("narrowed"):
            text += " [narrowed]"
        parts.append(text)
    if len(networks) > 4:
        parts.append(f"+{len(networks) - 4} more")
    return ", ".join(parts)


def _is_hex(value) -> bool:
    if not isinstance(value, str) or len(value) % 2 or not value:
        return False
    try:
        bytes.fromhex(value)
    except ValueError:
        return False
    return True
