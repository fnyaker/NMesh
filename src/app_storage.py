"""
Per-app local secure store — each app gets its own encrypted "drawer".

Apps (the built-in chat, and external ones plugged in over the data connector)
need a place to keep local state — contacts, keys, cursors, cached blobs. This
gives each app an isolated, bounded, encrypted key→value drawer on the node.

Isolation (see CLAUDE.md — reject by default, minimal blast radius):

  - A drawer is named by the app's ``app_id`` (the same 8-byte section id the
    connector already binds each client to at AUTH). An app never names another
    app's drawer: the node supplies the id from the authenticated session, the
    app cannot spoof it. One file per drawer, so blast radius is one app.
  - Each drawer is encrypted under its **own** key, derived from the node's
    long-term identity via HKDF with the app id mixed in. Even with the file in
    hand, one app's key never derives another's, and the ciphertext is bound to
    its app id as GCM AAD — a drawer file renamed to another id fails to decrypt.

Security at rest: same trust boundary as the identity file already on disk (the
key comes from the identity, no new secret is exposed to the medium). AES-256-GCM
is post-quantum-safe as a symmetric primitive. Persistence is opt-in: with no
``base_dir`` the drawers live in RAM only, exactly like session persistence.

Bounds everywhere (anti-exhaustion, anti-amplification): key length, value size,
keys per drawer, bytes per drawer, and number of drawers are all hard-capped.

The load path treats every file as hostile: corruption, truncation, tamper (GCM
auth failure), a wrong key, or a malformed field all yield an empty drawer and a
fresh start — never a crash, never another app's data.
"""
from __future__ import annotations

import base64
import json
import os
import threading

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .app_channel import APP_ID_LEN

_INFO = b"nmesh-app-store-v1\x00"      # HKDF domain; app id is appended
_NONCE_LEN = 12

# Hard bounds. A hostile local app cannot exhaust memory or disk through us.
MAX_KEY_LEN = 256
MAX_VALUE = 256 * 1024                 # 256 KiB per value
MAX_KEYS = 4096                        # entries per drawer
MAX_DRAWER_BYTES = 8 * 1024 * 1024     # 8 MiB of values per drawer
MAX_DRAWERS = 256                      # distinct app drawers
_MAX_FILE = MAX_DRAWER_BYTES + 4 * 1024 * 1024   # on-disk blob ceiling


class AppStorage:
    """Isolated, encrypted, bounded key→value drawers, one per app id.

    All public methods take the app id as their first argument; the caller
    (the connector / a built-in app) is responsible for passing the id bound to
    the authenticated session, never one chosen by the app itself.
    """

    def __init__(self, base_dir: str | None, identity) -> None:
        self._identity = identity
        self._base_dir = base_dir
        if base_dir:
            os.makedirs(base_dir, exist_ok=True)
        self._lock = threading.Lock()
        # app_id -> {key: value}. Loaded lazily; the source of truth once loaded.
        self._drawers: dict[bytes, dict[str, bytes]] = {}
        self._loaded: set[bytes] = set()

    # -- keys / paths -----------------------------------------------------

    def _drawer_key(self, app_id: bytes) -> bytes:
        return self._identity.derive_secret(_INFO + app_id, 32)

    def _path(self, app_id: bytes) -> str | None:
        if not self._base_dir:
            return None
        return os.path.join(self._base_dir, app_id.hex() + ".drawer")

    # -- load / save ------------------------------------------------------

    def _load(self, app_id: bytes) -> dict[str, bytes]:
        """Return the drawer's map, loading (and decrypting) it once. Any problem
        with the on-disk blob yields an empty drawer — never a raised error."""
        if app_id in self._loaded:
            return self._drawers.setdefault(app_id, {})
        self._loaded.add(app_id)
        drawer: dict[str, bytes] = {}
        path = self._path(app_id)
        if path is not None:
            drawer = self._read_file(app_id, path)
        self._drawers[app_id] = drawer
        return drawer

    def _read_file(self, app_id: bytes, path: str) -> dict[str, bytes]:
        try:
            if os.path.getsize(path) > _MAX_FILE:
                return {}
            with open(path, "rb") as f:
                blob = f.read()
        except (FileNotFoundError, OSError):
            return {}
        if len(blob) < _NONCE_LEN + 16:
            return {}
        try:
            nonce, ct = blob[:_NONCE_LEN], blob[_NONCE_LEN:]
            # app_id as AAD: a file renamed to another drawer fails to decrypt.
            plaintext = AESGCM(self._drawer_key(app_id)).decrypt(nonce, ct, app_id)
            doc = json.loads(plaintext.decode("utf-8"))
            if not isinstance(doc, dict):
                return {}
        except Exception:
            return {}  # tampered / corrupt / wrong key — start empty
        return _decode_map(doc)

    def _save(self, app_id: bytes, drawer: dict[str, bytes]) -> None:
        path = self._path(app_id)
        if path is None:
            return  # RAM-only mode
        doc = {k: base64.b64encode(v).decode("ascii") for k, v in drawer.items()}
        plaintext = json.dumps(doc).encode("utf-8")
        nonce = os.urandom(_NONCE_LEN)
        blob = nonce + AESGCM(self._drawer_key(app_id)).encrypt(nonce, plaintext, app_id)
        tmp = f"{path}.tmp.{os.getpid()}"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, blob)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, path)

    # -- public API -------------------------------------------------------

    def get(self, app_id: bytes, key: str) -> bytes | None:
        if not _valid_id(app_id) or not _valid_key(key):
            return None
        with self._lock:
            return self._load(app_id).get(key)

    def put(self, app_id: bytes, key: str, value: bytes) -> bool:
        """Store ``value`` under ``key`` in the app's drawer. Rejects (returns
        False) anything that would breach a bound — oversized key/value, a full
        drawer, or a brand-new drawer once the drawer cap is reached."""
        if not _valid_id(app_id) or not _valid_key(key):
            return False
        if not isinstance(value, (bytes, bytearray)) or len(value) > MAX_VALUE:
            return False
        value = bytes(value)
        with self._lock:
            if (app_id not in self._loaded and app_id not in self._drawers
                    and len(self._drawers) >= MAX_DRAWERS):
                return False
            drawer = self._load(app_id)
            if key not in drawer and len(drawer) >= MAX_KEYS:
                return False
            new_bytes = (sum(len(v) for k, v in drawer.items() if k != key)
                         + len(value))
            if new_bytes > MAX_DRAWER_BYTES:
                return False
            drawer[key] = value
            self._save(app_id, drawer)
            return True

    def delete(self, app_id: bytes, key: str) -> bool:
        if not _valid_id(app_id) or not _valid_key(key):
            return False
        with self._lock:
            drawer = self._load(app_id)
            if key not in drawer:
                return False
            del drawer[key]
            self._save(app_id, drawer)
            return True

    def list_keys(self, app_id: bytes) -> list[str]:
        if not _valid_id(app_id):
            return []
        with self._lock:
            return sorted(self._load(app_id).keys())


# ---------------------------------------------------------------------------
# Validators / decoders — reject by default, drop bad entries individually.
# ---------------------------------------------------------------------------

def _valid_id(app_id: bytes) -> bool:
    return isinstance(app_id, (bytes, bytearray)) and len(app_id) == APP_ID_LEN


def _valid_key(key: str) -> bool:
    return isinstance(key, str) and 0 < len(key) <= MAX_KEY_LEN


def _decode_map(doc: dict) -> dict[str, bytes]:
    out: dict[str, bytes] = {}
    for k, v in doc.items():
        if not _valid_key(k) or not isinstance(v, str) or len(out) >= MAX_KEYS:
            continue
        try:
            raw = base64.b64decode(v, validate=True)
        except (ValueError, TypeError):
            continue
        if len(raw) <= MAX_VALUE:
            out[k] = raw
    return out
