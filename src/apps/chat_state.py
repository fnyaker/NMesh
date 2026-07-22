"""
Chat application state — contacts, your own pseudo, and groups.

This is **app-level** state (the node knows nothing about it): a small,
bounded directory the chat app keeps for the user. It is owned by the chat app
and read by its web front-end, so every access is guarded by a lock (the app
mutates it on the event loop, the web thread reads snapshots).

Persistence is opt-in and can go two ways:
  - a **``store`` backend** (:class:`DrawerStore`) — the node's per-app encrypted
    drawer (:mod:`src.app_storage`). This is what the built-in chat uses so that
    contacts/pseudos never sit in the clear on disk (charter: aucun secret en
    clair sur disque sans raison).
  - a plain **``path``** — an atomic 0600 JSON file, kept for demos/tests that
    hold no real data.
With neither, the state stays purely in memory. It holds routing metadata (node
ids, pseudos, group membership), never keys.

Every collection is hard-bounded (charter: bornes partout) so a hostile peer
spraying profiles or group invites cannot grow it without limit.
"""
from __future__ import annotations

import json
import os
import threading
import time
from collections import OrderedDict

_STATE_KEY = "state"    # drawer key holding the serialised state doc


class DrawerStore:
    """Tiny key→bytes persistence backed by the node's encrypted per-app drawer.

    Thread-safe: :class:`src.app_storage.AppStorage` guards itself, so the chat
    app (event loop) and its web front-end (server thread) can both drive it.
    """

    def __init__(self, app_storage, app_id: bytes) -> None:
        self._s = app_storage
        self._app = app_id

    def get(self, key: str) -> bytes | None:
        return self._s.get(self._app, key)

    def put(self, key: str, value: bytes) -> bool:
        return self._s.put(self._app, key, value)

    def delete(self, key: str) -> bool:
        return self._s.delete(self._app, key)

_MAX_PSEUDO = 32
_MAX_BIO = 1024
_MAX_AVATAR = 48 * 1024    # avatar thumbnail bytes (per profile)
_MAX_AVATARS = 128         # peers whose avatar we cache (LRU bounded)
_MAX_CONTACTS = 1000
_MAX_KNOWN = 5000          # learned pseudos (not confirmed contacts) — LRU bounded
_MAX_GROUPS = 256
_MAX_GROUP_MEMBERS = 256
_MAX_GROUP_NAME = 64
_AVATAR_PREFIX = "avatar:"   # drawer key prefix; avatars live outside the state blob


def normalize_pseudo(pseudo: str) -> str:
    """Trim and cap a pseudo for storage; empty if only whitespace."""
    return pseudo.strip()[:_MAX_PSEUDO]


def _match_key(pseudo: str) -> str:
    """Case-insensitive key used to search pseudos."""
    return normalize_pseudo(pseudo).casefold()


class ChatState:
    def __init__(self, path: str | None = None, store: DrawerStore | None = None) -> None:
        self._path = path
        self._store = store
        self._lock = threading.Lock()
        self.pseudo = ""
        self.bio = ""
        self.avatar = b""                     # my own avatar thumbnail bytes
        self.contacts: dict[str, dict] = {}   # id_hex -> {pseudo, added, bio}
        self.known: dict[str, dict] = {}      # id_hex -> {pseudo, seen, bio}
        self.groups: dict[str, dict] = {}     # gid_hex -> {name, members:[id_hex]}
        # Avatars live in their own drawer keys (they'd bloat the state blob).
        # In-memory LRU cache; ids present here also have a store key.
        self._avatars: "OrderedDict[str, bytes]" = OrderedDict()  # id_hex|'self' -> bytes
        self._load()

    # -- persistence ------------------------------------------------------

    def _read_doc(self) -> dict | None:
        """Read the raw persisted doc from whichever backend is configured."""
        try:
            if self._store is not None:
                blob = self._store.get(_STATE_KEY)
                return json.loads(blob.decode("utf-8")) if blob else None
            if self._path and os.path.exists(self._path):
                with open(self._path) as f:
                    return json.load(f)
        except Exception:
            return None  # unreadable/corrupt → start empty, never crash
        return None

    def _load(self) -> None:
        doc = self._read_doc()
        if not isinstance(doc, dict):
            return
        self.pseudo = normalize_pseudo(str(doc.get("pseudo", "")))
        self.bio = str(doc.get("bio", ""))[:_MAX_BIO]
        if isinstance(doc.get("contacts"), dict):
            for k, v in list(doc["contacts"].items())[:_MAX_CONTACTS]:
                if _is_id(k) and isinstance(v, dict):
                    self.contacts[k] = {"pseudo": normalize_pseudo(str(v.get("pseudo", ""))),
                                        "added": float(v.get("added", 0) or 0),
                                        "bio": str(v.get("bio", ""))[:_MAX_BIO]}
        if isinstance(doc.get("known"), dict):
            for k, v in list(doc["known"].items())[:_MAX_KNOWN]:
                if _is_id(k) and isinstance(v, dict):
                    self.known[k] = {"pseudo": normalize_pseudo(str(v.get("pseudo", ""))),
                                     "seen": float(v.get("seen", 0) or 0),
                                     "bio": str(v.get("bio", ""))[:_MAX_BIO]}
        if isinstance(doc.get("groups"), dict):
            for k, v in list(doc["groups"].items())[:_MAX_GROUPS]:
                if _is_gid(k) and isinstance(v, dict):
                    members = [m for m in v.get("members", [])
                               if _is_id(m)][:_MAX_GROUP_MEMBERS]
                    self.groups[k] = {"name": str(v.get("name", ""))[:_MAX_GROUP_NAME],
                                      "members": members}
        # Track which peers have a cached avatar (ids only; bytes loaded lazily).
        if isinstance(doc.get("avatar_ids"), list):
            for aid in doc["avatar_ids"][:_MAX_AVATARS]:
                if isinstance(aid, str):
                    self._avatars[aid] = b""     # placeholder → lazy-loaded on get
        # Load my own avatar eagerly (send_profile needs the bytes).
        if self._store is not None:
            mine = self._store.get(_AVATAR_PREFIX + "self")
            if mine:
                self.avatar = mine[:_MAX_AVATAR]

    def _save_locked(self) -> None:
        doc = {"pseudo": self.pseudo, "bio": self.bio,
               "contacts": self.contacts, "known": self.known,
               "groups": self.groups, "avatar_ids": list(self._avatars.keys())}
        if self._store is not None:
            try:
                self._store.put(_STATE_KEY, json.dumps(doc).encode("utf-8"))
            except Exception:
                pass  # best-effort; a store hiccup must not crash the app
            return
        if not self._path:
            return
        tmp = self._path + ".tmp"
        try:
            with open(tmp, "w") as f:
                json.dump(doc, f)
            os.replace(tmp, self._path)
            try:
                os.chmod(self._path, 0o600)
            except OSError:
                pass
        except OSError:
            pass  # best-effort; a full disk must not crash the app

    # -- mutations (called on the event loop thread) ----------------------

    def set_pseudo(self, pseudo: str) -> None:
        with self._lock:
            self.pseudo = normalize_pseudo(pseudo)
            self._save_locked()

    def set_profile(self, *, pseudo: str | None = None, bio: str | None = None,
                    avatar: bytes | None = None) -> None:
        """Update my own profile. Only provided fields change; ``avatar=b''``
        clears the picture."""
        with self._lock:
            if pseudo is not None:
                self.pseudo = normalize_pseudo(pseudo)
            if bio is not None:
                self.bio = str(bio)[:_MAX_BIO]
            if avatar is not None:
                self.avatar = bytes(avatar)[:_MAX_AVATAR]
                self._store_avatar_locked("self", self.avatar)
            self._save_locked()

    def add_contact(self, id_hex: str, pseudo: str = "") -> bool:
        if not _is_id(id_hex):
            return False
        with self._lock:
            if id_hex not in self.contacts and len(self.contacts) >= _MAX_CONTACTS:
                return False
            existing = self.contacts.get(id_hex, {})
            self.contacts[id_hex] = {
                "pseudo": normalize_pseudo(pseudo) or existing.get("pseudo", ""),
                "added": existing.get("added") or time.time(),
                "bio": existing.get("bio", "") or self.known.get(id_hex, {}).get("bio", ""),
            }
            self.known.pop(id_hex, None)  # promoted from learned → confirmed
            self._save_locked()
            return True

    def remove_contact(self, id_hex: str) -> bool:
        with self._lock:
            if self.contacts.pop(id_hex, None) is None:
                return False
            self._save_locked()
            return True

    def learn_pseudo(self, id_hex: str, pseudo: str) -> None:
        """Record a pseudo announced by a peer. Confirmed contacts are updated
        in place; others go to the bounded 'known' directory (LRU by last seen)."""
        pseudo = normalize_pseudo(pseudo)
        if not _is_id(id_hex) or not pseudo:
            return
        with self._lock:
            if id_hex in self.contacts:
                self.contacts[id_hex]["pseudo"] = pseudo
            else:
                if id_hex not in self.known and len(self.known) >= _MAX_KNOWN:
                    oldest = min(self.known, key=lambda k: self.known[k]["seen"])
                    self.known.pop(oldest, None)
                prev = self.known.get(id_hex, {})
                self.known[id_hex] = {"pseudo": pseudo, "seen": time.time(),
                                      "bio": prev.get("bio", "")}
            self._save_locked()

    def learn_profile(self, id_hex: str, *, bio: str = "", avatar: bytes = b"") -> None:
        """Record a peer's bio/avatar from their PROFILE announce. Bounded: the
        avatar goes to an LRU cache (own drawer key), bio next to their pseudo."""
        if not _is_id(id_hex):
            return
        with self._lock:
            rec = self.contacts.get(id_hex) or self.known.get(id_hex)
            if rec is not None and bio:
                rec["bio"] = str(bio)[:_MAX_BIO]
            if avatar:
                self._store_avatar_locked(id_hex, bytes(avatar)[:_MAX_AVATAR])
            self._save_locked()

    # -- avatars (LRU cache; each in its own drawer key) ------------------

    def _store_avatar_locked(self, key_id: str, data: bytes) -> None:
        if key_id in self._avatars:
            self._avatars.move_to_end(key_id)
        elif len(self._avatars) >= _MAX_AVATARS:
            old, _ = self._avatars.popitem(last=False)   # evict least-recent
            if old != "self" and self._store is not None:
                try:
                    self._store.delete(_AVATAR_PREFIX + old)
                except Exception:
                    pass
        self._avatars[key_id] = data
        if self._store is not None:
            try:
                self._store.put(_AVATAR_PREFIX + key_id, data)
            except Exception:
                pass

    def get_avatar(self, id_hex: str) -> bytes | None:
        """Avatar bytes for a peer (or 'self'), or None. Lazy-loaded from the
        drawer on first access after a restart."""
        with self._lock:
            data = self._avatars.get(id_hex)
            if data:
                self._avatars.move_to_end(id_hex)
                return data
            if id_hex in self._avatars and self._store is not None:
                loaded = self._store.get(_AVATAR_PREFIX + id_hex)
                if loaded:
                    self._avatars[id_hex] = loaded
                    return loaded
            return None

    def add_group(self, gid_hex: str, name: str, members: list[str]) -> bool:
        if not _is_gid(gid_hex):
            return False
        members = [m for m in dict.fromkeys(members) if _is_id(m)][:_MAX_GROUP_MEMBERS]
        with self._lock:
            if gid_hex not in self.groups and len(self.groups) >= _MAX_GROUPS:
                return False
            self.groups[gid_hex] = {"name": str(name)[:_MAX_GROUP_NAME], "members": members}
            self._save_locked()
            return True

    def remove_group(self, gid_hex: str) -> bool:
        with self._lock:
            if self.groups.pop(gid_hex, None) is None:
                return False
            self._save_locked()
            return True

    # -- reads (called from the web thread) -------------------------------

    def group_members(self, gid_hex: str) -> list[str]:
        with self._lock:
            g = self.groups.get(gid_hex)
            return list(g["members"]) if g else []

    def find_by_pseudo(self, pseudo: str) -> list[dict]:
        """Local directory search: contacts + learned pseudos matching (case-
        insensitive substring). Returns [{id, pseudo, kind}]."""
        needle = _match_key(pseudo)
        if not needle:
            return []
        out: list[dict] = []
        with self._lock:
            for src, kind in ((self.contacts, "contact"), (self.known, "known")):
                for id_hex, rec in src.items():
                    if needle in rec.get("pseudo", "").casefold():
                        out.append({"id": id_hex, "pseudo": rec["pseudo"], "kind": kind})
        return out

    def matches_my_pseudo(self, pseudo: str) -> bool:
        with self._lock:
            return bool(self.pseudo) and _match_key(self.pseudo) == _match_key(pseudo)

    def snapshot(self) -> dict:
        with self._lock:
            def entry(k, v):
                return {"id": k, **v, "has_avatar": k in self._avatars}
            return {
                "pseudo": self.pseudo,
                "bio": self.bio,
                "has_avatar": "self" in self._avatars,
                "contacts": [entry(k, v) for k, v in self.contacts.items()],
                "known": [entry(k, v) for k, v in self.known.items()],
                "groups": [{"id": k, **v} for k, v in self.groups.items()],
            }


def _is_id(x) -> bool:
    return isinstance(x, str) and len(x) == 40 and _is_hex(x)


def _is_gid(x) -> bool:
    return isinstance(x, str) and len(x) == 32 and _is_hex(x)


def _is_hex(x: str) -> bool:
    try:
        bytes.fromhex(x)
        return True
    except ValueError:
        return False
