"""
Chat application state — contacts, your own pseudo, and groups.

This is **app-level** state (the node knows nothing about it): a small,
bounded, JSON-persisted directory the chat app keeps for the user. It is owned
by the chat app and read by its web front-end, so every access is guarded by a
lock (the app mutates it on the event loop, the web thread reads snapshots).

Persistence is opt-in: with a path, the store is written atomically (0600) on
every change so contacts/groups survive a restart; without one it stays purely
in memory (demos/tests). It holds routing metadata (node ids, pseudos, group
membership), never keys or secrets.

Every collection is hard-bounded (charter: bornes partout) so a hostile peer
spraying profiles or group invites cannot grow it without limit.
"""
from __future__ import annotations

import json
import os
import threading
import time

_MAX_PSEUDO = 32
_MAX_CONTACTS = 1000
_MAX_KNOWN = 5000          # learned pseudos (not confirmed contacts) — LRU bounded
_MAX_GROUPS = 256
_MAX_GROUP_MEMBERS = 256
_MAX_GROUP_NAME = 64


def normalize_pseudo(pseudo: str) -> str:
    """Trim and cap a pseudo for storage; empty if only whitespace."""
    return pseudo.strip()[:_MAX_PSEUDO]


def _match_key(pseudo: str) -> str:
    """Case-insensitive key used to search pseudos."""
    return normalize_pseudo(pseudo).casefold()


class ChatState:
    def __init__(self, path: str | None = None) -> None:
        self._path = path
        self._lock = threading.Lock()
        self.pseudo = ""
        self.contacts: dict[str, dict] = {}   # id_hex -> {pseudo, added}
        self.known: dict[str, dict] = {}      # id_hex -> {pseudo, seen}
        self.groups: dict[str, dict] = {}     # gid_hex -> {name, members:[id_hex]}
        self._load()

    # -- persistence ------------------------------------------------------

    def _load(self) -> None:
        if not self._path or not os.path.exists(self._path):
            return
        try:
            with open(self._path) as f:
                doc = json.load(f)
        except Exception:
            return  # unreadable/corrupt → start empty, never crash
        if not isinstance(doc, dict):
            return
        self.pseudo = normalize_pseudo(str(doc.get("pseudo", "")))
        if isinstance(doc.get("contacts"), dict):
            for k, v in list(doc["contacts"].items())[:_MAX_CONTACTS]:
                if _is_id(k) and isinstance(v, dict):
                    self.contacts[k] = {"pseudo": normalize_pseudo(str(v.get("pseudo", ""))),
                                        "added": float(v.get("added", 0) or 0)}
        if isinstance(doc.get("known"), dict):
            for k, v in list(doc["known"].items())[:_MAX_KNOWN]:
                if _is_id(k) and isinstance(v, dict):
                    self.known[k] = {"pseudo": normalize_pseudo(str(v.get("pseudo", ""))),
                                     "seen": float(v.get("seen", 0) or 0)}
        if isinstance(doc.get("groups"), dict):
            for k, v in list(doc["groups"].items())[:_MAX_GROUPS]:
                if _is_gid(k) and isinstance(v, dict):
                    members = [m for m in v.get("members", [])
                               if _is_id(m)][:_MAX_GROUP_MEMBERS]
                    self.groups[k] = {"name": str(v.get("name", ""))[:_MAX_GROUP_NAME],
                                      "members": members}

    def _save_locked(self) -> None:
        if not self._path:
            return
        doc = {"pseudo": self.pseudo, "contacts": self.contacts,
               "known": self.known, "groups": self.groups}
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
                self.known[id_hex] = {"pseudo": pseudo, "seen": time.time()}
            self._save_locked()

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
            return {
                "pseudo": self.pseudo,
                "contacts": [{"id": k, **v} for k, v in self.contacts.items()],
                "known": [{"id": k, **v} for k, v in self.known.items()],
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
