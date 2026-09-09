"""
What this node watches for new versions — and what it may take on its own.

A subscription names one publisher's offering of one package: *this* key, this
kind, this name. Subscribing to several publishers of the same package is the
point rather than a side effect, because of what a **quorum** then means:

    install only when this many subscribed publishers carry the same code.

"The same code" is :func:`src.pkg_dir.source_digest` — a digest over the
package's files with its documentation left out — so two publishers who build
the same source with different release notes still agree. That is the whole
answer to "am I looking at the official version?", and it is answerable
*before* anything is downloaded, because the digest travels in the signed
record.

A quorum of one is "I do not care, install it" and is the default: an operator
who wants corroboration asks for it. A quorum only ever *withholds* an install,
never authorises one that the publisher pins would refuse — see
``MeshNode.may_auto_install``.

Three things this file is not
-----------------------------
- **Not a trust store.** Subscribing to a publisher is watching them, not
  accepting their code: :class:`src.core_release.TrustedPublishers` is what says
  whose signature may replace this node's program, and nothing here changes it.
- **Not writable from the network.** Every entry comes from an operator acting
  locally, exactly like a pin.
- **Not a cache.** It is small, deliberate and persisted; a corrupt file yields
  **no** subscriptions rather than a guess, because failing closed here costs a
  re-subscribe and failing open costs an unattended install nobody asked for.
"""
from __future__ import annotations

import json
import os
import re
import time

from .pkg_dir import KINDS, MAX_NAME, MAX_VERSION
from .pseudo import fold

MAX_SUBSCRIPTIONS = 64
MAX_QUORUM = 8
_HEX_ID = re.compile(r"[0-9a-f]{40}")


class SubscriptionError(Exception):
    """A subscription that cannot be stored, phrased for whoever asked."""


class Subscriptions:
    """The packages this node watches, persisted as plain JSON.

    Keyed by the directory entry id (publisher ‖ kind ‖ folded name), which is
    the same identity the package directory files a record under — so a
    subscription and the record it watches are never two ways of naming one
    thing that can drift apart."""

    def __init__(self, path: str | None = None,
                 max_entries: int = MAX_SUBSCRIPTIONS) -> None:
        self._path = path
        self._max = max_entries
        self._entries: dict[str, dict] = self._load()

    # -- persistence ------------------------------------------------------

    def _load(self) -> dict[str, dict]:
        if not self._path:
            return {}
        try:
            with open(self._path) as handle:
                doc = json.load(handle)
        except (FileNotFoundError, OSError, ValueError):
            return {}
        if not isinstance(doc, dict):
            return {}
        out: dict[str, dict] = {}
        for key, value in doc.items():
            if len(out) >= self._max:
                break
            entry = self._clean(key, value)
            if entry is not None:
                out[key] = entry
        return out

    def _clean(self, key: str, value) -> dict | None:
        if not isinstance(key, str) or not _HEX_ID.fullmatch(key):
            return None
        if not isinstance(value, dict):
            return None
        publisher = value.get("publisher_id")
        name = value.get("name")
        kind = value.get("kind")
        if not isinstance(publisher, str) or not _HEX_ID.fullmatch(publisher):
            return None
        if not isinstance(name, str) or not 0 < len(name) <= MAX_NAME:
            return None
        if not isinstance(kind, int) or isinstance(kind, bool) or kind not in KINDS:
            return None
        quorum = value.get("quorum")
        if not isinstance(quorum, int) or isinstance(quorum, bool):
            quorum = 1
        seen = value.get("version_seen")
        return {
            "id": key,
            "publisher_id": publisher,
            "kind": kind,
            "name": name,
            "auto": value.get("auto") is True,
            "quorum": max(1, min(int(quorum), MAX_QUORUM)),
            "version_seen": (seen if isinstance(seen, str) else "")[:MAX_VERSION],
            "added": int(value["added"]) if isinstance(value.get("added"), int)
                     and not isinstance(value.get("added"), bool) else 0,
        }

    def _save(self) -> None:
        if not self._path:
            return
        tmp = f"{self._path}.tmp.{os.getpid()}"
        handle = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(handle, "w") as stream:
                json.dump(self._entries, stream)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        os.replace(tmp, self._path)

    # -- mutation ---------------------------------------------------------

    def add(self, entry_id_hex: str, publisher_id_hex: str, kind: int,
            name: str, *, auto: bool = False, quorum: int = 1) -> dict:
        """Watch this publisher's offering of this package.

        Re-subscribing updates the flags rather than adding a second entry: one
        offering is one row, however many times somebody presses the toggle."""
        if not _HEX_ID.fullmatch(entry_id_hex or ""):
            raise SubscriptionError("that is not a package")
        if not _HEX_ID.fullmatch(publisher_id_hex or ""):
            raise SubscriptionError("that is not a publisher")
        if kind not in KINDS:
            raise SubscriptionError("unknown package kind")
        if (entry_id_hex not in self._entries
                and len(self._entries) >= self._max):
            raise SubscriptionError("too many subscriptions")
        existing = self._entries.get(entry_id_hex, {})
        self._entries[entry_id_hex] = {
            "id": entry_id_hex,
            "publisher_id": publisher_id_hex,
            "kind": int(kind),
            "name": str(name)[:MAX_NAME],
            "auto": bool(auto),
            "quorum": max(1, min(int(quorum), MAX_QUORUM)),
            "version_seen": existing.get("version_seen", ""),
            "added": existing.get("added") or int(time.time()),
        }
        self._save()
        return dict(self._entries[entry_id_hex])

    def remove(self, entry_id_hex: str) -> bool:
        if entry_id_hex not in self._entries:
            return False
        del self._entries[entry_id_hex]
        self._save()
        return True

    def note_version(self, entry_id_hex: str, version: str) -> None:
        """Remember the newest version we have told the operator about, so a
        version already seen does not announce itself again on every sweep."""
        entry = self._entries.get(entry_id_hex)
        if entry is None or entry["version_seen"] == version:
            return
        entry["version_seen"] = str(version)[:MAX_VERSION]
        self._save()

    # -- reading ----------------------------------------------------------

    def get(self, entry_id_hex: str) -> dict | None:
        found = self._entries.get(entry_id_hex)
        return dict(found) if found else None

    def has(self, entry_id_hex: str) -> bool:
        return entry_id_hex in self._entries

    def publishers_for(self, kind: int, name_folded: str) -> set:
        """Which publishers this operator watches for one package.

        The set a quorum is counted against: a signature from somebody nobody
        subscribed to says nothing here, which is what keeps "several parties
        agree" from being reachable by minting parties."""
        return {entry["publisher_id"] for entry in self._entries.values()
                if entry["kind"] == kind and fold(entry["name"]) == name_folded}

    def list(self) -> list[dict]:
        return sorted((dict(entry) for entry in self._entries.values()),
                      key=lambda entry: (entry["name"].lower(),
                                         entry["publisher_id"]))

    def __len__(self) -> int:
        return len(self._entries)
