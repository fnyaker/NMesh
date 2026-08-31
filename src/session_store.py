"""
Opt-in persistence of E2E session state, encrypted at rest.

Delay-tolerant delivery and node restarts need session state to survive on disk:
the established E2E keys, any handshake still in flight (so a reply that comes
back days later still completes), and data queued for a peer not yet reachable.

Security (see CLAUDE.md): keys in RAM is the default; this is only active when a
``session_store_path`` is given. The blob is encrypted with AES-256-GCM under a
key derived from the node's long-term identity, so its confidentiality sits at
the *same* trust boundary as the identity file already on disk — no new secret
is exposed to the medium. Persisting session keys does trade away some forward
secrecy (disk + identity ⇒ past traffic), which is inherent to resuming sessions
across restarts; that is why it is opt-in.

:class:`PseudoStore` sits beside it and keeps the *names* this node has learned.
Separate on purpose, and not because the bytes are different: the session blob is
rewritten every couple of seconds while data flows, and a book of ~5 kB claims
folded into it would put a megabyte through ``fsync`` on the hot path. Names
change once in a blue moon, so they get their own file and their own cadence.

The load path treats the file as hostile: any corruption, truncation, tamper
(GCM auth failure), or malformed field yields an empty state and a fresh start,
never a crash.
"""
from __future__ import annotations

import json
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .node_id import NodeID
from .crypto import SessionKey

_INFO = b"nmesh-session-store-v1"
_NAMES_INFO = b"nmesh-pseudo-store-v1"
_NONCE_LEN = 12
_MAX_FILE = 16 * 1024 * 1024   # 16 MiB ceiling on the on-disk blob
# Claims are ~5.3 kB each (an ML-DSA-65 public key and signature). This many is
# a neighbourhood's worth of names and a file of about 1.5 MiB, which is what a
# cache of display names is worth spending.
MAX_STORED_CLAIMS = 256
_MAX_NAMES_FILE = 4 * 1024 * 1024


class SessionState:
    """Plain container for the persisted pieces of E2E + routing state."""

    __slots__ = ("e2e_sessions", "pending_kem", "pending_nonce", "pending_data",
                 "routing")

    def __init__(self) -> None:
        self.e2e_sessions: dict[NodeID, SessionKey] = {}
        self.pending_kem: dict[NodeID, bytes] = {}
        self.pending_nonce: dict[NodeID, bytes] = {}
        self.pending_data: dict[NodeID, list[bytes]] = {}
        self.routing: list[dict] = []


class SessionStore:
    def __init__(self, path: str, identity) -> None:
        self._path = path
        self._key = identity.derive_secret(_INFO, 32)

    # -- save -------------------------------------------------------------

    def save(self, e2e_sessions, pending_kem, pending_nonce, pending_data,
             routing=None) -> None:
        doc = {
            "e2e_sessions": {n.raw.hex(): s.key_bytes.hex()
                             for n, s in e2e_sessions.items()},
            "pending_kem": {n.raw.hex(): v.hex() for n, v in pending_kem.items()},
            "pending_nonce": {n.raw.hex(): v.hex() for n, v in pending_nonce.items()},
            "pending_data": {n.raw.hex(): [p.hex() for p in lst]
                             for n, lst in pending_data.items()},
            "routing": routing or [],
        }
        _write_sealed(self._path, self._key, doc)

    # -- load -------------------------------------------------------------

    def load(self) -> SessionState:
        state = SessionState()
        doc = _read_sealed(self._path, self._key, _MAX_FILE)
        if doc is None:
            return state
        _load_map(doc.get("e2e_sessions"), state.e2e_sessions, _as_session)
        _load_map(doc.get("pending_kem"), state.pending_kem, _as_bytes)
        _load_map(doc.get("pending_nonce"), state.pending_nonce, _as_bytes)
        _load_map(doc.get("pending_data"), state.pending_data, _as_byte_list)
        routing = doc.get("routing")
        if isinstance(routing, list):
            state.routing = [r for r in routing if isinstance(r, dict)]
        return state


class PseudoStore:
    """The names this node has learned, kept across a restart.

    Only raw claims are stored — never the name as text. A claim carries its own
    public key and signature, so what comes back off disk is re-verified exactly
    like a claim arriving from a stranger (:func:`src.pseudo_dir.parse_claim`),
    and a tampered file buys an attacker nothing but an empty cache. That is why
    a *name* is safe to keep on disk at all: it is not believed, it is checked.
    """

    def __init__(self, path: str, identity) -> None:
        self._path = path
        self._key = identity.derive_secret(_NAMES_INFO, 32)

    def save(self, claims) -> None:
        """``claims`` is an iterable of raw claim bytes, most valuable last (the
        book hands them over least-recently-touched first). The tail is what
        survives the cap, so the names most recently in use are the ones kept."""
        kept = [bytes(c).hex() for c in list(claims)[-MAX_STORED_CLAIMS:]]
        _write_sealed(self._path, self._key, {"claims": kept})

    def load(self) -> list[bytes]:
        doc = _read_sealed(self._path, self._key, _MAX_NAMES_FILE)
        if doc is None:
            return []
        raw = doc.get("claims")
        if not isinstance(raw, list):
            return []
        out: list[bytes] = []
        for item in raw[:MAX_STORED_CLAIMS]:
            decoded = _as_bytes(item)
            if decoded:
                out.append(decoded)
        return out


# ---------------------------------------------------------------------------
# Sealed files — one encrypt/decrypt idiom for both stores above.
# ---------------------------------------------------------------------------

def _write_sealed(path: str, key: bytes, doc: dict) -> None:
    plaintext = json.dumps(doc).encode("utf-8")
    nonce = os.urandom(_NONCE_LEN)
    blob = nonce + AESGCM(key).encrypt(nonce, plaintext, None)
    tmp = f"{path}.tmp.{os.getpid()}"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, blob)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, path)


def _read_sealed(path: str, key: bytes, ceiling: int) -> dict | None:
    """The document, or ``None`` for anything missing, oversized, corrupt or
    tampered with. Never raises: a bad file means "start fresh", never a crash."""
    try:
        if os.path.getsize(path) > ceiling:
            return None
        with open(path, "rb") as handle:
            blob = handle.read()
    except (FileNotFoundError, OSError):
        return None
    if len(blob) < _NONCE_LEN + 16:
        return None
    try:
        plaintext = AESGCM(key).decrypt(blob[:_NONCE_LEN], blob[_NONCE_LEN:], None)
        doc = json.loads(plaintext.decode("utf-8"))
    except Exception:
        return None
    return doc if isinstance(doc, dict) else None


# ---------------------------------------------------------------------------
# Defensive field decoders — any bad value drops just that entry.
# ---------------------------------------------------------------------------

def _node_id(hex_str: str) -> NodeID | None:
    try:
        raw = bytes.fromhex(hex_str)
    except (ValueError, TypeError):
        return None
    return NodeID(raw) if len(raw) == 20 else None


def _as_session(value):
    if not isinstance(value, str):
        return None
    try:
        return SessionKey.from_key(bytes.fromhex(value))
    except (ValueError, TypeError):
        return None


def _as_bytes(value):
    if not isinstance(value, str):
        return None
    try:
        return bytes.fromhex(value)
    except (ValueError, TypeError):
        return None


def _as_byte_list(value):
    if not isinstance(value, list):
        return None
    out: list[bytes] = []
    for item in value:
        b = _as_bytes(item)
        if b is not None:
            out.append(b)
    return out


def _load_map(raw, target: dict, decode) -> None:
    if not isinstance(raw, dict):
        return
    for k, v in raw.items():
        node = _node_id(k)
        if node is None:
            continue
        decoded = decode(v)
        if decoded is not None:
            target[node] = decoded
