"""
Fleet trust ledger — who may manage us, and whom we may manage.

Two directions, deliberately kept apart, because they carry very different risk:

  - **operators**: nodes this machine has agreed to obey. Every entry here is a
    standing grant of remote code execution, so it only ever appears after an
    explicit local decision (a human accepting a request, or a pre-authorisation
    delivered over the provisioning channel) and it names the exact capabilities
    granted — trusting a node to report its disk usage is not trusting it to
    open a shell.
  - **managed**: nodes that have agreed to obey *us*. Losing this list costs
    convenience, not safety.

Each entry keeps the **signed assertion** that created it (see
:mod:`src.app_auth`). That is what makes the ledger auditable rather than merely
stateful: months later, offline, one can still verify that the node holding a
grant really asked for it, with these capabilities, at that time. A record whose
proof no longer verifies is a record that should never have been there.

Persistence rides the node's encrypted per-app drawer, so the ledger is
encrypted at rest under the node identity, like every other app's state. Every
list is bounded, and a corrupt or tampered blob yields an **empty** ledger
(fail closed: forget who you trusted rather than trust a forged list).
"""
from __future__ import annotations

import base64
import json
import threading
import time

# What an operator may be granted. Ordered from harmless to total.
CAPABILITIES = ("status", "update", "scan", "provision", "shell")
CAP_DESCRIPTIONS = {
    "status": "read uptime, load, memory and disk usage",
    "update": "run the system package manager's upgrade",
    "scan": "sweep this machine's LAN for SSH hosts",
    "provision": "install NMesh on machines on this LAN",
    "shell": "open an interactive shell as this node's user",
}

MAX_OPERATORS = 64
MAX_MANAGED = 4096
MAX_PENDING = 256
MAX_PROVISION_RECORDS = 512
MAX_LABEL = 128
_STATE_KEY = "fleet-state"
_STATE_BUDGET = 200 * 1024        # serialised ledger ceiling (under the drawer cap)
PENDING_TTL = 7 * 86400           # an unanswered request expires after a week


def clean_caps(caps) -> list[str]:
    """Normalise a capability list from *anywhere* (network, UI, file).

    Unknown names are dropped rather than stored: a capability we do not
    understand must never sit in the ledger looking like a grant."""
    if not isinstance(caps, (list, tuple, set)):
        return []
    return [cap for cap in CAPABILITIES if cap in set(caps)]


def clean_label(label) -> str:
    return str(label)[:MAX_LABEL] if isinstance(label, str) else ""


def _b64(raw: bytes | None) -> str:
    return base64.b64encode(raw).decode("ascii") if raw else ""


def _unb64(text) -> bytes:
    if not isinstance(text, str) or not text:
        return b""
    try:
        return base64.b64decode(text, validate=True)
    except (ValueError, TypeError):
        return b""


class FleetState:
    """The ledger. Thread-safe: the app drives it from the event loop while the
    console front-end reads it from the server thread."""

    def __init__(self, store=None) -> None:
        self._store = store
        self._lock = threading.RLock()
        self._operators: dict[str, dict] = {}    # node hex -> grant we gave them
        self._managed: dict[str, dict] = {}      # node hex -> grant they gave us
        self._pending_in: dict[str, dict] = {}   # requests awaiting our decision
        self._pending_out: dict[str, dict] = {}  # our requests awaiting an answer
        self._provisioned: dict[str, dict] = {}  # token digest -> provisioning run
        self._version = 0
        self._load()

    # -- lifecycle --------------------------------------------------------

    @property
    def version(self) -> int:
        """Bumped on every mutation, so a polling UI knows when to redraw."""
        with self._lock:
            return self._version

    def _load(self) -> None:
        if self._store is None:
            return
        try:
            blob = self._store.get(_STATE_KEY)
            document = json.loads(blob.decode("utf-8")) if blob else None
        except Exception:
            return          # unreadable / tampered → empty ledger, never a crash
        if not isinstance(document, dict):
            return
        self._operators = _load_map(document.get("operators"), MAX_OPERATORS)
        self._managed = _load_map(document.get("managed"), MAX_MANAGED)
        self._pending_in = _load_map(document.get("pending_in"), MAX_PENDING)
        self._pending_out = _load_map(document.get("pending_out"), MAX_PENDING)
        self._provisioned = _load_map(document.get("provisioned"),
                                      MAX_PROVISION_RECORDS)
        self._expire_pending()

    def _save(self) -> None:
        self._version += 1
        if self._store is None:
            return
        document = {
            "operators": self._operators,
            "managed": self._managed,
            "pending_in": self._pending_in,
            "pending_out": self._pending_out,
            "provisioned": self._provisioned,
        }
        try:
            blob = json.dumps(document, separators=(",", ":")).encode("utf-8")
        except (TypeError, ValueError):
            return
        # Grants are what matter; if we are over budget, drop cached status
        # payloads (rebuildable) before dropping anything that carries trust.
        if len(blob) > _STATE_BUDGET:
            trimmed = dict(document)
            trimmed["managed"] = {
                key: {k: v for k, v in entry.items() if k != "status"}
                for key, entry in self._managed.items()}
            blob = json.dumps(trimmed, separators=(",", ":")).encode("utf-8")
        try:
            self._store.put(_STATE_KEY, blob[:_STATE_BUDGET])
        except Exception:
            pass          # a full drawer must not break a live session

    # -- operators (who may manage us) ------------------------------------

    def operator(self, node_hex: str) -> dict | None:
        with self._lock:
            return dict(self._operators.get(node_hex, {})) or None

    def operators(self) -> list[dict]:
        with self._lock:
            return [dict(entry, id=key) for key, entry in self._operators.items()]

    def allows(self, node_hex: str, capability: str) -> bool:
        """The authorisation gate. Both the enrolment *and* the specific
        capability must be present — an enrolled operator is not an omnipotent
        one."""
        with self._lock:
            entry = self._operators.get(node_hex)
            return bool(entry) and capability in (entry.get("caps") or [])

    def add_operator(self, node_hex: str, public_key: bytes, *,
                     caps: list[str], label: str = "",
                     proof: bytes = b"") -> dict | None:
        """Record a standing grant. ``proof`` is the operator's signed enrolment
        request, kept so the grant stays verifiable later."""
        caps = clean_caps(caps)
        if not caps or not _is_node_hex(node_hex) or not public_key:
            return None
        with self._lock:
            if (node_hex not in self._operators
                    and len(self._operators) >= MAX_OPERATORS):
                return None
            entry = {
                "pub": public_key.hex(),
                "caps": caps,
                "label": clean_label(label),
                "enrolled_at": time.time(),
                "proof": _b64(proof),
            }
            self._operators[node_hex] = entry
            self._pending_in.pop(node_hex, None)
            self._save()
            return dict(entry, id=node_hex)

    def remove_operator(self, node_hex: str) -> bool:
        with self._lock:
            gone = self._operators.pop(node_hex, None) is not None
            if gone:
                self._save()
            return gone

    # -- managed (whom we may manage) -------------------------------------

    def managed(self) -> list[dict]:
        with self._lock:
            return [dict(entry, id=key) for key, entry in self._managed.items()]

    def managed_one(self, node_hex: str) -> dict | None:
        with self._lock:
            entry = self._managed.get(node_hex)
            return dict(entry, id=node_hex) if entry else None

    def add_managed(self, node_hex: str, *, caps: list[str], label: str = "",
                    grant: bytes = b"") -> dict | None:
        caps = clean_caps(caps)
        if not caps or not _is_node_hex(node_hex):
            return None
        with self._lock:
            if node_hex not in self._managed and len(self._managed) >= MAX_MANAGED:
                return None
            existing = self._managed.get(node_hex, {})
            entry = {
                "caps": caps,
                "label": clean_label(label) or existing.get("label", ""),
                "enrolled_at": existing.get("enrolled_at") or time.time(),
                "grant": _b64(grant),
                "status": existing.get("status"),
                "last_seen": time.time(),
            }
            self._managed[node_hex] = entry
            self._pending_out.pop(node_hex, None)
            self._save()
            return dict(entry, id=node_hex)

    def remove_managed(self, node_hex: str) -> bool:
        with self._lock:
            gone = self._managed.pop(node_hex, None) is not None
            if gone:
                self._save()
            return gone

    def record_status(self, node_hex: str, status: dict) -> None:
        with self._lock:
            entry = self._managed.get(node_hex)
            if entry is None:
                return
            entry["status"] = status
            entry["last_seen"] = time.time()
            self._save()

    def grant_proof(self, node_hex: str) -> bytes:
        with self._lock:
            return _unb64((self._managed.get(node_hex) or {}).get("grant"))

    # -- pending decisions (the notification an operator's request raises) -

    def pending_in(self) -> list[dict]:
        with self._lock:
            self._expire_pending()
            return [dict(entry, id=key) for key, entry in self._pending_in.items()]

    def pending_out(self) -> list[dict]:
        with self._lock:
            self._expire_pending()
            return [dict(entry, id=key) for key, entry in self._pending_out.items()]

    def add_pending_in(self, node_hex: str, public_key: bytes, *,
                       caps: list[str], label: str, proof: bytes) -> dict | None:
        """Park an incoming enrolment request until a human decides.

        Re-requesting only refreshes the existing entry: a peer cannot fill the
        queue by asking repeatedly, and the queue is capped besides."""
        caps = clean_caps(caps)
        if not caps or not _is_node_hex(node_hex):
            return None
        with self._lock:
            self._expire_pending()
            if (node_hex not in self._pending_in
                    and len(self._pending_in) >= MAX_PENDING):
                return None
            entry = {
                "pub": public_key.hex(),
                "caps": caps,
                "label": clean_label(label),
                "at": time.time(),
                "proof": _b64(proof),
            }
            self._pending_in[node_hex] = entry
            self._save()
            return dict(entry, id=node_hex)

    def take_pending_in(self, node_hex: str) -> dict | None:
        with self._lock:
            entry = self._pending_in.pop(node_hex, None)
            if entry is not None:
                self._save()
            return dict(entry, id=node_hex) if entry else None

    def add_pending_out(self, node_hex: str, *, caps: list[str],
                        label: str = "") -> dict | None:
        caps = clean_caps(caps)
        if not caps or not _is_node_hex(node_hex):
            return None
        with self._lock:
            self._expire_pending()
            if (node_hex not in self._pending_out
                    and len(self._pending_out) >= MAX_PENDING):
                return None
            entry = {"caps": caps, "label": clean_label(label), "at": time.time()}
            self._pending_out[node_hex] = entry
            self._save()
            return dict(entry, id=node_hex)

    def drop_pending_out(self, node_hex: str) -> bool:
        with self._lock:
            gone = self._pending_out.pop(node_hex, None) is not None
            if gone:
                self._save()
            return gone

    def _expire_pending(self) -> None:
        now = time.time()
        for table in (self._pending_in, self._pending_out):
            for key in [k for k, entry in table.items()
                        if now - float(entry.get("at") or 0) > PENDING_TTL]:
                table.pop(key, None)

    # -- provisioning runs awaiting their node ----------------------------

    def add_provisioned(self, digest: str, *, host: str, caps: list[str],
                        label: str = "") -> None:
        """Remember that we provisioned a machine and expect a node holding the
        matching token to show up. Keyed by the token *digest* — the token
        itself only ever exists on the machine we sent it to."""
        with self._lock:
            while len(self._provisioned) >= MAX_PROVISION_RECORDS:
                self._provisioned.pop(next(iter(self._provisioned)), None)
            self._provisioned[str(digest)[:64]] = {
                "host": str(host)[:128],
                "caps": clean_caps(caps),
                "label": clean_label(label),
                "at": time.time(),
            }
            self._save()

    def take_provisioned(self, digest: str) -> dict | None:
        """Consume a provisioning record. Single use: a token claimed twice is
        a replay, and the second claim finds nothing."""
        with self._lock:
            entry = self._provisioned.pop(str(digest)[:64], None)
            if entry is not None:
                self._save()
            return entry

    def provisioned(self) -> list[dict]:
        with self._lock:
            return [dict(entry, digest=key)
                    for key, entry in self._provisioned.items()]


def _is_node_hex(value) -> bool:
    if not isinstance(value, str) or len(value) != 40:
        return False
    try:
        bytes.fromhex(value)
    except ValueError:
        return False
    return True


def _load_map(raw, limit: int) -> dict[str, dict]:
    """Rebuild one table from a persisted document, dropping bad entries
    individually — one corrupt record must not cost the whole ledger."""
    if not isinstance(raw, dict):
        return {}
    out: dict[str, dict] = {}
    for key, entry in raw.items():
        if len(out) >= limit or not isinstance(entry, dict):
            continue
        if not isinstance(key, str) or len(key) > 64:
            continue
        cleaned = dict(entry)
        if "caps" in cleaned:
            cleaned["caps"] = clean_caps(cleaned.get("caps"))
        if "label" in cleaned:
            cleaned["label"] = clean_label(cleaned.get("label"))
        out[key] = cleaned
    return out
