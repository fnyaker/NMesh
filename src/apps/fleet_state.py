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

A grant is not frozen at enrolment, but the two directions of change are not
symmetric: :meth:`set_operator_caps` widens only for a caller that already holds
the authority locally, and offers ``narrow_only`` for the one case a remote peer
may drive — handing a right back.

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
import hashlib
import json
import re
import threading
import time

# What an operator may be granted. Ordered from harmless to total.
CAPABILITIES = ("status", "invite", "update", "scan", "provision", "shell",
                "docker", "manage", "govern", "passwordless")
CAP_DESCRIPTIONS = {
    "status": "read uptime, load, memory and disk usage",
    # Deliberately separate from "manage": handing somebody the whole console
    # so they can mint an invitation is a grant out of all proportion to the
    # thing they wanted. This one does that and nothing else.
    "invite": "mint a single-use invitation to this node's mesh, on its behalf",
    "update": "run the system package manager's upgrade",
    "scan": "sweep this machine's LAN for SSH hosts",
    "provision": "install NMesh on machines on this LAN",
    "shell": "open an interactive shell as this node's user",
    # Root, said plainly. A process that can talk to the docker socket can start
    # a privileged container bind-mounting `/`, which is the machine — so this
    # is not "manage containers", it is "be root here", and the description has
    # to say the thing an operator is actually agreeing to.
    "docker": "drive this machine's docker: containers, images and stacks "
              "(equivalent to root — the docker socket is)",
    # Not a second way in: the operator still has to type this node's console
    # password. The grant opens the channel; the password opens the session.
    "manage": "drive this node's web console remotely (its console password is "
              "still required)",
    # The difference between *operating* a machine and *deciding what it
    # trusts*. `manage` covers everything an operator does to a node they look
    # after — its settings, its transports, its apps, its links. This covers the
    # handful of things that are not operation but judgement: which signing keys
    # this node accepts a program from, who it lets into its network, and which
    # private keys it holds. Those used to be reachable from nowhere but the
    # machine itself; they are reachable from a console now, and this is the
    # grant that makes them so — asked for on its own, and taken back on its
    # own. Useless without `manage`, which is what carries the call.
    "govern": "decide what this node trusts: pin signing keys, mint "
              "invitations, hold private keys (needs `manage` too)",
    # The one grant that removes a key instead of adding one. A machine nobody
    # ever typed a password on — one this operator provisioned — has a console
    # password only its own log ever saw, so without this the `manage` grant
    # opens a door nobody holds the second key to. Useless on its own: it mints
    # a session, and `manage` is what carries a call.
    "passwordless": "open this node's console with no password — the grant is "
                    "the only key (needs `manage` too)",
}

MAX_OPERATORS = 64
MAX_MANAGED = 4096
MAX_PENDING = 256
MAX_PROVISION_RECORDS = 512
MAX_LABEL = 128
MAX_UPDATE_STACKS = 32            # stacks one node's Update may also bring up
MAX_GROUPS = 32                   # groups an operator may keep
MAX_GROUP_NODES = 512             # nodes in one group
_GROUP_RE = re.compile(r"\A[^\x00-\x1f]{1,48}\Z")
_STACK_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")
MAX_SSH_KEYS = 8                  # uploaded private keys held at once
MAX_SSH_KEY_BYTES = 64 * 1024
_KEY_PREFIX = "sshkey:"           # drawer key holding one uploaded private key
_SECRET_PREFIX = "secret:"        # drawer key holding one credential we hold
MAX_SECRET_BYTES = 4096
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


def clean_group(name) -> str:
    """A group name from anywhere. A label, so it may hold anything printable —
    it never reaches a shell, a path or another machine."""
    if not isinstance(name, str):
        return ""
    text = " ".join(name.split())[:48]
    return text if text and _GROUP_RE.match(text) else ""


def clean_stack_names(raw) -> list[str]:
    """Stack names from anywhere, bounded and charset-checked.

    A stack name reaches an argv on the far side, so what is not a name is
    dropped rather than escaped — there is no escaping here to get wrong."""
    if not isinstance(raw, (list, tuple, set)):
        return []
    out: list[str] = []
    for name in list(raw)[:MAX_UPDATE_STACKS]:
        if (isinstance(name, str) and _STACK_RE.match(name)
                and name not in out):
            out.append(name)
    return out


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
        self._ssh_keys: dict[str, dict] = {}     # key id -> metadata (never material)
        self._ram_keys: dict[str, str] = {}      # material when no drawer is wired
        self._ram_secrets: dict[str, bytes] = {}  # ditto, for held credentials
        # Group name -> the nodes in it. One membership list, not a field on
        # each node: two places saying who is in a group is two chances for
        # them to disagree, and the group is the thing an operator acts on.
        self._groups: dict[str, dict] = {}
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
        self._ssh_keys = _load_map(document.get("ssh_keys"), MAX_SSH_KEYS)
        self._groups = {
            name: {"nodes": [node for node in (entry.get("nodes") or [])
                             if _is_node_hex(node)][:MAX_GROUP_NODES],
                   "at": entry.get("at") or time.time()}
            for name, entry in _load_map(document.get("groups"), MAX_GROUPS).items()
            if clean_group(name)
        }
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
            "ssh_keys": self._ssh_keys,
            "groups": self._groups,
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

    def set_operator_caps(self, node_hex: str, caps,
                          *, narrow_only: bool = False) -> list[str] | None:
        """Change what an existing operator may do, without re-enrolling them.

        Two callers, with deliberately different powers. A human on *this*
        machine may set any capability set: they already hold the authority the
        grant delegates, so there is nothing to escalate. A remote operator may
        only ever *narrow* (``narrow_only``) — giving a right up needs nobody's
        permission, taking one needs the human above.

        Returns the resulting list — empty when the last capability went and the
        operator was dropped — or ``None`` when there is no such operator."""
        caps = clean_caps(caps)
        with self._lock:
            entry = self._operators.get(node_hex)
            if entry is None:
                return None
            if narrow_only:
                held = entry.get("caps") or []
                caps = [cap for cap in caps if cap in held]
            if not caps:
                self._operators.pop(node_hex, None)
                self._save()
                return []
            entry["caps"] = caps
            entry["changed_at"] = time.time()
            self._save()
            return list(caps)

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
                # Carried over rather than rebuilt: re-enrolment refreshes the
                # grant, and it would be a poor surprise for it to also forget
                # which stacks an operator had chosen to update.
                "update_stacks": existing.get("update_stacks") or [],
            }
            self._managed[node_hex] = entry
            self._pending_out.pop(node_hex, None)
            self._save()
            return dict(entry, id=node_hex)

    def set_update_stacks(self, node_hex: str, stacks) -> list[str]:
        """Which of that node's docker stacks *Update* should also bring up.

        Ours, not theirs: it is a choice an operator made on this console about
        a machine, so it lives beside the grant we hold rather than travelling
        with every request."""
        clean = clean_stack_names(stacks)
        with self._lock:
            entry = self._managed.get(node_hex)
            if entry is None:
                return []
            entry["update_stacks"] = clean
            self._save()
            return list(clean)

    def update_stacks(self, node_hex: str) -> list[str]:
        with self._lock:
            entry = self._managed.get(node_hex)
            return list(entry.get("update_stacks") or []) if entry else []

    # -- groups (an operator's own names for sets of machines) -------------
    #
    # Ours, not theirs: a group is a way of pointing at several machines at
    # once from this console, and says nothing to any of them. Membership lives
    # in one place — the group's list — so "which groups is this node in?" is
    # derived rather than stored a second time and allowed to disagree.

    def groups(self) -> list[dict]:
        with self._lock:
            return [{"name": name, "nodes": list(entry.get("nodes") or []),
                     "at": entry.get("at") or 0}
                    for name, entry in sorted(self._groups.items())]

    def group_nodes(self, name) -> list[str]:
        clean = clean_group(name)
        with self._lock:
            entry = self._groups.get(clean)
            # Only nodes we still manage: a group holding a node whose grant is
            # gone is a button that half works.
            return [node for node in (entry.get("nodes") or [])
                    if node in self._managed] if entry else []

    def set_group(self, name, nodes) -> dict | None:
        """Create a group, or replace what is in one."""
        clean = clean_group(name)
        if not clean:
            return None
        members = []
        if isinstance(nodes, (list, tuple, set)):
            for node in list(nodes)[:MAX_GROUP_NODES]:
                if _is_node_hex(node) and node not in members:
                    members.append(node)
        with self._lock:
            if clean not in self._groups and len(self._groups) >= MAX_GROUPS:
                return None
            entry = self._groups.setdefault(clean, {"nodes": [], "at": time.time()})
            entry["nodes"] = members
            self._save()
            return {"name": clean, "nodes": list(members), "at": entry["at"]}

    def remove_group(self, name) -> bool:
        clean = clean_group(name)
        with self._lock:
            if self._groups.pop(clean, None) is None:
                return False
            self._save()
            return True

    def set_node_groups(self, node_hex: str, names) -> list[str]:
        """Put one node in exactly these groups — a node may be in several.

        Written through the same one list per group, so this is an edit of the
        membership rather than a second copy of it."""
        if not _is_node_hex(node_hex):
            return []
        wanted = []
        if isinstance(names, (list, tuple, set)):
            for name in list(names)[:MAX_GROUPS]:
                clean = clean_group(name)
                if clean and clean not in wanted:
                    wanted.append(clean)
        with self._lock:
            for name in wanted:
                if name not in self._groups and len(self._groups) >= MAX_GROUPS:
                    continue
                entry = self._groups.setdefault(name, {"nodes": [], "at": time.time()})
                if node_hex not in entry["nodes"]:
                    if len(entry["nodes"]) >= MAX_GROUP_NODES:
                        continue
                    entry["nodes"].append(node_hex)
            for name, entry in self._groups.items():
                if name not in wanted and node_hex in entry["nodes"]:
                    entry["nodes"].remove(node_hex)
            self._save()
            return [name for name, entry in sorted(self._groups.items())
                    if node_hex in entry["nodes"]]

    def may_use(self, node_hex: str, capability: str) -> bool:
        """Whether *that* node granted *us* this capability.

        The mirror of :meth:`allows`, and just as much a gate: an action we were
        never granted must not leave this node either — a request that can only
        be refused is noise the operator has to interpret."""
        with self._lock:
            entry = self._managed.get(node_hex)
            return bool(entry) and capability in (entry.get("caps") or [])

    def remove_managed(self, node_hex: str) -> bool:
        with self._lock:
            gone = self._managed.pop(node_hex, None) is not None
            if gone:
                # Out of the groups too. A membership pointing at a node this
                # console no longer manages is a row that looks like a machine
                # and is not one.
                for entry in self._groups.values():
                    if node_hex in entry["nodes"]:
                        entry["nodes"].remove(node_hex)
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
                       caps: list[str], label: str, proof: bytes,
                       have: list[str] | None = None) -> dict | None:
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
                # What they hold already, so a human sees "asks for shell on
                # top of status" rather than an undifferentiated list.
                "have": clean_caps(have),
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

    # -- uploaded SSH keys ------------------------------------------------
    #
    # A container has no ``~/.ssh``, so an operator needs a way to hand the node
    # a key. The material lives in the app's **encrypted drawer** (AES-256-GCM
    # under a key derived from the node identity — the same trust boundary as
    # the identity file itself), one drawer entry per key so the state blob
    # stays small. Metadata and material are kept apart on purpose: everything
    # the UI reads goes through :meth:`ssh_keys`, which never returns material.

    def add_ssh_key(self, name: str, material: str) -> dict | None:
        if not looks_like_private_key(material):
            return None
        key_id = _key_id(material)
        with self._lock:
            if key_id not in self._ssh_keys and len(self._ssh_keys) >= MAX_SSH_KEYS:
                return None
            entry = {
                "name": clean_label(name) or f"key-{key_id[:8]}",
                "encrypted": ("ENCRYPTED" in material
                              or ("OPENSSH PRIVATE KEY" in material
                                  and "bcrypt" in material)),
                "at": time.time(),
            }
            if self._store is not None:
                try:
                    if not self._store.put(_KEY_PREFIX + key_id,
                                           material.encode("utf-8")):
                        return None      # drawer full — refuse, do not half-store
                except Exception:
                    return None
            else:
                self._ram_keys[key_id] = material
            self._ssh_keys[key_id] = entry
            self._save()
            return dict(entry, id=key_id)

    def ssh_keys(self) -> list[dict]:
        """Metadata only — never the key material."""
        with self._lock:
            return [dict(entry, id=key_id, source="uploaded")
                    for key_id, entry in self._ssh_keys.items()]

    def ssh_key_material(self, key_id: str) -> str | None:
        with self._lock:
            if key_id not in self._ssh_keys:
                return None
            if self._store is None:
                return self._ram_keys.get(key_id)
            try:
                blob = self._store.get(_KEY_PREFIX + key_id)
            except Exception:
                return None
            return blob.decode("utf-8", "replace") if blob else None

    def remove_ssh_key(self, key_id: str) -> bool:
        with self._lock:
            if self._ssh_keys.pop(str(key_id), None) is None:
                return False
            self._ram_keys.pop(key_id, None)
            if self._store is not None:
                try:
                    self._store.delete(_KEY_PREFIX + key_id)
                except Exception:
                    pass
            self._save()
            return True

    # -- a credential this node holds for something else -------------------
    #
    # One drawer entry per name, encrypted at rest under the node identity like
    # every other app's state, and deliberately **not** in the ledger blob: the
    # ledger is read by the console on every poll, and a token has no business
    # travelling that path. Nothing reads one of these back over the mesh —
    # what a console is told is that one is configured, and where.

    def write_secret(self, name: str, value: dict | None) -> bool:
        key = _SECRET_PREFIX + str(name)[:32]
        with self._lock:
            if value is None:
                self._ram_secrets.pop(key, None)
                if self._store is not None:
                    try:
                        self._store.delete(key)
                    except Exception:
                        pass
                self._save()
                return True
            try:
                blob = json.dumps(value, separators=(",", ":")).encode("utf-8")
            except (TypeError, ValueError):
                return False
            if len(blob) > MAX_SECRET_BYTES:
                return False
            if self._store is None:
                self._ram_secrets[key] = blob
            else:
                try:
                    if not self._store.put(key, blob):
                        return False
                except Exception:
                    return False
            self._save()
            return True

    def read_secret(self, name: str) -> dict | None:
        key = _SECRET_PREFIX + str(name)[:32]
        with self._lock:
            if self._store is None:
                blob = self._ram_secrets.get(key)
            else:
                try:
                    blob = self._store.get(key)
                except Exception:
                    blob = None
            if not blob:
                return None
            try:
                value = json.loads(blob.decode("utf-8"))
            except Exception:
                return None
            return value if isinstance(value, dict) else None

    def provisioned(self) -> list[dict]:
        with self._lock:
            return [dict(entry, digest=key)
                    for key, entry in self._provisioned.items()]


def _key_id(material: str) -> str:
    """Content-derived id, so uploading the same key twice is one entry."""
    return hashlib.sha256(material.encode("utf-8", "replace")).hexdigest()[:16]


def looks_like_private_key(material) -> bool:
    """Cheap shape check before anything is stored. Not a parse: OpenSSH reads
    the file itself at connect time and is the real judge."""
    return (isinstance(material, str) and 0 < len(material) <= MAX_SSH_KEY_BYTES
            and "PRIVATE KEY" in material)


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
