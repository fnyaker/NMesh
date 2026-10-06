"""
Console sessions that outlive the process: the ones ``nmeshctl login`` asks for.

A browser's session lives in the console's memory and slides an hour at a time,
and a node forgets it every time it restarts — which is every time it updates.
That is right for a tab, and wrong for an operator at a terminal over SSH who
said "keep me signed in for eight hours": the next automatic update would sign
them out in the middle of whatever they were doing.

So these are written down — and only what is needed to recognise one: a hash of
the token, never the token, in a file created 0600 from its first byte. The
lifetime is **absolute**, chosen at login and capped at `MAX_SECONDS`, and it
does not slide: a credential sitting in a file on another machine must end on a
date somebody chose, not whenever its holder stops using it. Bounded at
`MAX_SESSIONS`, the oldest pushed out first. A password change ends every one of
them but the caller's, like the console's own.

Wall-clock time, not monotonic: the deadline has to mean the same instant after
a restart, and a monotonic clock starts again at boot.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import threading
import time

FILENAME = "console.sessions"
MIN_SECONDS = 60
MAX_SECONDS = 24 * 3600
DEFAULT_SECONDS = 8 * 3600
MAX_SESSIONS = 16
MAX_LABEL = 64
_FILE_MAX = 64 * 1024


def path_for(state_dir: str | None) -> str | None:
    return os.path.join(state_dir, FILENAME) if state_dir else None


def _digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8", "replace")).hexdigest()


def clamp_seconds(value) -> int:
    """A lifetime somebody asked for, inside the bounds. A number that is not
    one is the default rather than an error: the operator asked to stay signed
    in, and the bound is what keeps that safe."""
    try:
        seconds = int(value)
    except (TypeError, ValueError):
        return DEFAULT_SECONDS
    return max(MIN_SECONDS, min(seconds, MAX_SECONDS))


def _clean_label(label) -> str:
    if not isinstance(label, str):
        return ""
    return "".join(ch for ch in label if ch.isprintable())[:MAX_LABEL]


class LastingSessions:
    """The sessions a console keeps across its own restarts.

    ``path`` ``None`` keeps them in memory only — a console with no state
    directory has nowhere to write, and still honours what it issued until it
    stops."""

    def __init__(self, path: str | None) -> None:
        self._path = path
        self._lock = threading.Lock()
        self._held: dict[str, dict] = {}
        self._load()

    # -- the file ---------------------------------------------------------

    def _load(self) -> None:
        if not self._path or not os.path.exists(self._path):
            return
        try:
            with open(self._path, "rb") as handle:
                raw = handle.read(_FILE_MAX + 1)
            if len(raw) > _FILE_MAX:
                return
            document = json.loads(raw.decode("utf-8"))
        except (OSError, ValueError, UnicodeDecodeError):
            # Unreadable means nobody stays signed in, which is the safe way
            # round: the operator signs in again, and nothing is trusted that
            # could not be read.
            return
        if not isinstance(document, list):
            return
        now = time.time()
        for row in document[:MAX_SESSIONS]:
            if not isinstance(row, dict):
                continue
            digest, until = row.get("h"), row.get("until")
            if (not isinstance(digest, str) or len(digest) != 64
                    or not all(ch in "0123456789abcdef" for ch in digest)
                    or not isinstance(until, (int, float)) or until <= now):
                continue
            # A deadline further away than any login could have asked for was
            # not written by this code; it is dropped rather than believed.
            if until > now + MAX_SECONDS + 60:
                continue
            self._held[digest] = {"until": float(until),
                                  "made": float(row.get("made") or now),
                                  "label": _clean_label(row.get("label"))}

    def _save(self) -> None:
        if not self._path:
            return
        rows = [{"h": digest, **entry} for digest, entry in self._held.items()]
        tmp = self._path + ".tmp"
        try:
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as handle:
                json.dump(rows, handle)
            os.chmod(tmp, 0o600)
            os.replace(tmp, self._path)
        except OSError:
            try:
                os.unlink(tmp)
            except OSError:
                pass

    def _expire(self, now: float) -> bool:
        gone = [digest for digest, entry in self._held.items()
                if entry["until"] <= now]
        for digest in gone:
            del self._held[digest]
        return bool(gone)

    # -- what the console asks --------------------------------------------

    def issue(self, seconds, label: str = "") -> tuple[str, float]:
        """A new session: ``(token, deadline)``. The token is returned once and
        kept nowhere."""
        token = secrets.token_urlsafe(32)
        now = time.time()
        until = now + clamp_seconds(seconds)
        with self._lock:
            self._expire(now)
            while len(self._held) >= MAX_SESSIONS:
                oldest = min(self._held, key=lambda key: self._held[key]["made"])
                del self._held[oldest]
            self._held[_digest(token)] = {"until": until, "made": now,
                                          "label": _clean_label(label)}
            self._save()
        return token, until

    def valid(self, token: str | None) -> bool:
        if not isinstance(token, str) or not token:
            return False
        now = time.time()
        with self._lock:
            entry = self._held.get(_digest(token))
            if entry is None:
                return False
            if entry["until"] <= now:
                del self._held[_digest(token)]
                self._save()
                return False
            return True

    def deadline(self, token: str | None) -> float | None:
        if not isinstance(token, str) or not token:
            return None
        with self._lock:
            entry = self._held.get(_digest(token))
            return entry["until"] if entry else None

    def revoke(self, token: str | None) -> bool:
        if not isinstance(token, str) or not token:
            return False
        with self._lock:
            if self._held.pop(_digest(token), None) is None:
                return False
            self._save()
            return True

    def revoke_all_except(self, keep: str | None) -> int:
        spared = _digest(keep) if isinstance(keep, str) and keep else ""
        with self._lock:
            doomed = [digest for digest in self._held if digest != spared]
            for digest in doomed:
                del self._held[digest]
            if doomed:
                self._save()
        return len(doomed)

    def overview(self) -> list[dict]:
        """What is held, for an operator to read — never a hash, never a token."""
        now = time.time()
        with self._lock:
            if self._expire(now):
                self._save()
            return sorted(({"label": entry["label"], "made": int(entry["made"]),
                            "expires_at": int(entry["until"])}
                           for entry in self._held.values()),
                          key=lambda row: row["made"])
