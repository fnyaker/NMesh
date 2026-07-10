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
_NONCE_LEN = 12
_MAX_FILE = 16 * 1024 * 1024   # 16 MiB ceiling on the on-disk blob


class SessionState:
    """Plain container for the persisted pieces of E2E state."""

    __slots__ = ("e2e_sessions", "pending_kem", "pending_nonce", "pending_data")

    def __init__(self) -> None:
        self.e2e_sessions: dict[NodeID, SessionKey] = {}
        self.pending_kem: dict[NodeID, bytes] = {}
        self.pending_nonce: dict[NodeID, bytes] = {}
        self.pending_data: dict[NodeID, list[bytes]] = {}


class SessionStore:
    def __init__(self, path: str, identity) -> None:
        self._path = path
        self._key = identity.derive_secret(_INFO, 32)

    # -- save -------------------------------------------------------------

    def save(self, e2e_sessions, pending_kem, pending_nonce, pending_data) -> None:
        doc = {
            "e2e_sessions": {n.raw.hex(): s.key_bytes.hex()
                             for n, s in e2e_sessions.items()},
            "pending_kem": {n.raw.hex(): v.hex() for n, v in pending_kem.items()},
            "pending_nonce": {n.raw.hex(): v.hex() for n, v in pending_nonce.items()},
            "pending_data": {n.raw.hex(): [p.hex() for p in lst]
                             for n, lst in pending_data.items()},
        }
        plaintext = json.dumps(doc).encode("utf-8")
        nonce = os.urandom(_NONCE_LEN)
        blob = nonce + AESGCM(self._key).encrypt(nonce, plaintext, None)
        tmp = f"{self._path}.tmp.{os.getpid()}"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, blob)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, self._path)

    # -- load -------------------------------------------------------------

    def load(self) -> SessionState:
        state = SessionState()
        try:
            if os.path.getsize(self._path) > _MAX_FILE:
                return state
            with open(self._path, "rb") as f:
                blob = f.read()
        except (FileNotFoundError, OSError):
            return state
        if len(blob) < _NONCE_LEN + 16:
            return state
        try:
            nonce, ct = blob[:_NONCE_LEN], blob[_NONCE_LEN:]
            plaintext = AESGCM(self._key).decrypt(nonce, ct, None)
            doc = json.loads(plaintext.decode("utf-8"))
            if not isinstance(doc, dict):
                return state
        except Exception:
            return state  # tampered / corrupt / wrong key — start fresh

        _load_map(doc.get("e2e_sessions"), state.e2e_sessions, _as_session)
        _load_map(doc.get("pending_kem"), state.pending_kem, _as_bytes)
        _load_map(doc.get("pending_nonce"), state.pending_nonce, _as_bytes)
        _load_map(doc.get("pending_data"), state.pending_data, _as_byte_list)
        return state


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
