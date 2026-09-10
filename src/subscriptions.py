"""
What this node watches for new versions — and what it may take on its own.

A subscription names **a package**, not a publisher: this kind, this name. It
used to name one key's offering of one package, which made a signing key into a
name for a thing — so a package could only be watched through whoever happened
to sign it, and a second signer of the same code was a second subscription.

What a subscription asks for is a **quorum**:

    install only when this many keys I chose have signed the same code.

"The same code" is :func:`src.pkg_dir.source_digest` — a digest over the
package's files with its documentation left out — so two publishers who build
the same source with different release notes still agree. That is the whole
answer to "am I looking at the official version?", and it is answerable
*before* anything is downloaded, because the digest travels in the signed
record.

A quorum of one is "I do not care, install it" and is the default: an operator
who wants corroboration asks for it. Counting is
``MeshNode._package_agreement``, over keys chosen one at a time — a key the
operator endorsed, or the pin the release in front of them was pinned under —
which is what keeps "several parties agree" out of reach of somebody minting
parties. A quorum only ever *withholds* an install, never authorises one the
pins would refuse — see ``MeshNode.may_auto_install``.

Three things this file is not
-----------------------------
- **Not a trust store.** Watching a package is not accepting anybody's code:
  :class:`src.core_release.TrustedPublishers` is what says whose signature may
  replace this node's program, and nothing here changes it.
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

import hashlib

from .pkg_dir import KINDS, MAX_NAME, MAX_VERSION
from .pseudo import canonical, fold

MAX_SUBSCRIPTIONS = 64
MAX_QUORUM = 8
_HEX_ID = re.compile(r"[0-9a-f]{40}")


def subscription_id(kind: int, name: str) -> str:
    """What a subscription is named by: the package, and nothing else.

    Derived from the kind and the folded name, so the same package is the same
    subscription however it was reached — a search, a node's page, a record
    signed by somebody new. It used to be the directory entry id, which carries
    the *node* that filed the record: two nodes offering one package were two
    subscriptions, and unsubscribing from one left the other watching."""
    return hashlib.sha256(
        b"nmesh-subscription-v2" + bytes([int(kind)])
        + fold(name).encode("utf-8")).digest()[:20].hex()


class SubscriptionError(Exception):
    """A subscription that cannot be stored, phrased for whoever asked."""


class Subscriptions:
    """The packages this node watches, persisted as plain JSON.

    Keyed by :func:`subscription_id` — the kind and the folded name — so one
    package is one row whoever signs or serves it."""

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
        name = value.get("name")
        kind = value.get("kind")
        if not isinstance(name, str) or not 0 < len(name) <= MAX_NAME:
            return None
        if not isinstance(kind, int) or isinstance(kind, bool) or kind not in KINDS:
            return None
        # The key has to be the one this name and kind produce. A file naming a
        # row something else is a file whose rows cannot be found by the only
        # question anybody asks of them.
        if key != subscription_id(kind, name):
            return None
        quorum = value.get("quorum")
        if not isinstance(quorum, int) or isinstance(quorum, bool):
            quorum = 1
        seen = value.get("version_seen")
        return {
            "id": key,
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

    def add(self, kind: int, name: str, *, auto: bool = False,
            quorum: int = 1) -> dict:
        """Watch this package for new versions.

        Re-subscribing updates the flags rather than adding a second entry: one
        package is one row, however many times somebody presses the toggle and
        whoever signed the release they pressed it on."""
        if kind not in KINDS:
            raise SubscriptionError("unknown package kind")
        try:
            # The one accepted form of a displayed name, and the same one the
            # directory files a record under. A name this refuses is a name no
            # record could carry, so a subscription to it would watch nothing.
            name = canonical(name)
        except Exception:
            raise SubscriptionError("that is not a package name") from None
        if not 0 < len(name) <= MAX_NAME:
            raise SubscriptionError("that is not a package name")
        ident = subscription_id(kind, name)
        if ident not in self._entries and len(self._entries) >= self._max:
            raise SubscriptionError("too many subscriptions")
        existing = self._entries.get(ident, {})
        self._entries[ident] = {
            "id": ident,
            "kind": int(kind),
            "name": name,
            "auto": bool(auto),
            "quorum": max(1, min(int(quorum), MAX_QUORUM)),
            "version_seen": existing.get("version_seen", ""),
            "added": existing.get("added") or int(time.time()),
        }
        self._save()
        return dict(self._entries[ident])

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

    def note_package_version(self, kind: int, name, version: str) -> None:
        """:meth:`note_version` for callers holding a package rather than a row.

        The install path has a directory record in hand, not a subscription, and
        deriving the id there is what went wrong: it passed the **record** id,
        which names no row, so the write silently did nothing."""
        self.note_version(subscription_id(kind, name), version)

    # -- reading ----------------------------------------------------------

    def get(self, entry_id_hex: str) -> dict | None:
        found = self._entries.get(entry_id_hex)
        return dict(found) if found else None

    def has(self, entry_id_hex: str) -> bool:
        return entry_id_hex in self._entries

    def for_package(self, kind: int, name) -> dict | None:
        """The subscription watching this package, if any."""
        return self.get(subscription_id(kind, name))

    def list(self) -> list[dict]:
        return sorted((dict(entry) for entry in self._entries.values()),
                      key=lambda entry: (entry["name"].lower(), entry["kind"]))

    def __len__(self) -> int:
        return len(self._entries)
