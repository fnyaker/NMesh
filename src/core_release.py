"""
Mesh-native releases — a node publishes the node's own code, signed.

Downloading an update from a web host makes one company's account the root of
trust for every node on the mesh. This module removes it: a release is a
**content-addressed package on the DHT** (exactly like an app package, see
:mod:`src.app_package`) plus a small **descriptor signed with the publisher's
ML-DSA identity**. Nodes gossip the descriptor; a node that has pinned that
publisher's key can fetch the content, verify every byte against the signed
root, and install it.

Three separate things, deliberately not merged:

  - **the content** is verified by hash. Ask for a key, check what comes back
    hashes to it — a relay can neither substitute nor corrupt it, and no trust
    in whoever handed it over is needed.
  - **the descriptor** says *who* published *which* content, and when. Its
    signature is the only thing that makes "who" meaningful.
  - **the pin** says whose signature this operator accepts. Nothing arriving
    from the network can add one: a release from an unpinned publisher is
    relayed and displayed, never installed.

Signing domain
--------------
``nmesh-core-release-v1`` is distinct from every other domain in the repository
(app releases, certificates, handshakes, the pseudo directory, app-auth). The
same ML-DSA key signs all of them, so a shared domain would let a descriptor be
replayed as something else entirely.

Anti-rollback
-------------
The descriptor carries a signed ``ts`` and a ``version``. The catalogue keeps
the highest ``ts`` per publisher, so replaying an old signed release cannot walk
a node backwards; and an install additionally refuses any version that is not
strictly newer than what is running (:func:`src.version.is_newer`).

The version cannot lie
----------------------
The descriptor's ``version`` is checked against ``src/version.py`` *inside the
package* — when it is built and again before anything is installed. A release
that announces one version and carries another is refused rather than unpacked.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import time

from .app_package import KEY_LEN, content_key

_DOMAIN = b"nmesh-core-release-v1"

# Bounds. A release is source code, not a disk image: a package that does not
# fit these is not a release, whatever it claims to be.
MAX_TREE_BYTES = 64 * 1024 * 1024
MAX_FILES = 8192
MAX_VERSION_LEN = 64
MAX_NOTES_LEN = 4000
MAX_NAME_LEN = 64
MAX_PUBLISHERS = 32          # pinned keys an operator may hold
MAX_CATALOG = 64             # publishers tracked in the gossiped catalogue
PUBLISHER_ID_LEN = 20

# What a release is made of. The same list the updater swaps in: the node's
# state, its virtualenv and anything an operator left in the install directory
# are not part of a release and are never carried by one.
INCLUDE = ("src", "scripts", "start.sh", "install.sh", "requirements.txt",
           "pyproject.toml", "Docs", "docker", "README.md", "CLAUDE.md")
REQUIRED = ("src/version.py", "start.sh")
_EXCLUDE_DIRS = {"__pycache__", ".git", ".venv", "data", "_oqs", "node_modules",
                 ".nmesh-previous", ".nmesh-update"}
_EXCLUDE_SUFFIXES = (".pyc", ".pyo", ".so", ".o")

_RELEASE_KEYS = ("v", "version", "root_key", "root_sha256", "publisher", "ts",
                 "notes")
_VERSION_IN_TREE = re.compile(r'^__version__\s*=\s*["\']([^"\']{1,64})["\']',
                              re.MULTILINE)


class ReleaseError(Exception):
    """Anything that stops a release being built, read or trusted."""


def publisher_id(public_key: bytes) -> bytes:
    """A publisher is named by the hash of its key, like a NodeID.

    There is therefore no id to lie about: an id that cannot be derived from the
    key presented is not a mismatch to resolve, it is a forgery."""
    return hashlib.sha256(public_key).digest()[:PUBLISHER_ID_LEN]


# ---------------------------------------------------------------------------
# Reading a tree, and what version it says it is
# ---------------------------------------------------------------------------

def version_of(files: dict) -> str | None:
    """The version declared by ``src/version.py`` inside a package.

    This is what makes the signed ``version`` field checkable rather than
    decorative: whoever publishes cannot announce one version and ship another,
    and an installer re-checks it after reassembly."""
    raw = files.get("src/version.py")
    if not isinstance(raw, (bytes, bytearray)):
        return None
    try:
        text = bytes(raw).decode("utf-8")
    except UnicodeDecodeError:
        return None
    match = _VERSION_IN_TREE.search(text)
    return match.group(1) if match else None


def _skip(relative: str) -> bool:
    parts = set(relative.split(os.sep))
    return bool(parts & _EXCLUDE_DIRS) or relative.endswith(_EXCLUDE_SUFFIXES)


def read_tree(root: str) -> dict[str, bytes]:
    """Read the parts of an installed tree that make up a release.

    Symlinks are not followed and not carried: a release is a set of regular
    files, and a link is a way of pointing the extraction somewhere it was never
    meant to write."""
    files: dict[str, bytes] = {}
    total = 0
    for entry in INCLUDE:
        source = os.path.join(root, entry)
        if os.path.islink(source) or not os.path.exists(source):
            continue
        paths = []
        if os.path.isdir(source):
            for base, dirs, names in os.walk(source):
                dirs[:] = [d for d in dirs if d not in _EXCLUDE_DIRS
                           and not os.path.islink(os.path.join(base, d))]
                paths.extend(os.path.join(base, name) for name in names)
        else:
            paths.append(source)
        for path in paths:
            if os.path.islink(path) or not os.path.isfile(path):
                continue
            relative = os.path.relpath(path, root).replace(os.sep, "/")
            if _skip(relative):
                continue
            with open(path, "rb") as handle:
                content = handle.read()
            total += len(content)
            if total > MAX_TREE_BYTES or len(files) >= MAX_FILES:
                raise ReleaseError("this tree is too large to publish")
            files[relative] = content
    missing = [name for name in REQUIRED if name not in files]
    if missing:
        raise ReleaseError("not an NMesh tree: missing " + ", ".join(missing))
    return files


def check_tree(files: dict, version: str) -> None:
    """Everything an installer must agree with before a file touches disk."""
    missing = [name for name in REQUIRED if name not in files]
    if missing:
        raise ReleaseError("the release is missing " + ", ".join(missing))
    declared = version_of(files)
    if declared is None:
        raise ReleaseError("the release carries no readable version")
    if declared != version:
        raise ReleaseError(
            f"the release announces {version} but carries {declared}")


# ---------------------------------------------------------------------------
# The signed descriptor
# ---------------------------------------------------------------------------

def _signing_input(body: dict) -> bytes:
    return _DOMAIN + json.dumps({k: body[k] for k in _RELEASE_KEYS},
                                sort_keys=True).encode("utf-8")


def build_release(root_key: bytes, root_sha256: str, version: str,
                  publisher_pub: bytes, sign, ts: int | None = None,
                  notes: str = "") -> bytes:
    """Sign a descriptor binding a content root to this publisher.

    ``sign(message) -> signature`` signs with the publisher's ML-DSA identity.
    Nothing here signs bytes the caller chose: the input is this domain plus
    these named fields, so the signature cannot be lifted into another meaning.
    """
    if not isinstance(version, str) or not 0 < len(version) <= MAX_VERSION_LEN:
        raise ReleaseError("version invalid")
    if len(root_key) != KEY_LEN or len(root_sha256) != 64:
        raise ReleaseError("root reference invalid")
    body = {
        "v": 1,
        "version": version,
        "root_key": root_key.hex(),
        "root_sha256": root_sha256,
        "publisher": publisher_pub.hex(),
        "ts": int(ts if ts is not None else time.time()),
        "notes": str(notes or "")[:MAX_NOTES_LEN],
    }
    body["sig"] = sign(_signing_input(body)).hex()
    return json.dumps(body, sort_keys=True).encode("utf-8")


def parse_release(data: bytes, verify) -> dict:
    """Parse and cryptographically verify a descriptor.

    ``verify(message, signature, public_key) -> bool``. Every gate rejects by
    default — bad JSON, a missing or oversized field, an unreadable hex value,
    or a failed signature all raise :class:`ReleaseError`. The caller never has
    to tell "invalid" from "malformed"."""
    if not isinstance(data, (bytes, bytearray)) or len(data) > 64 * 1024:
        raise ReleaseError("release blob invalid")
    try:
        doc = json.loads(bytes(data).decode("utf-8"))
    except Exception as exc:
        raise ReleaseError(f"release not valid JSON: {exc}") from exc
    if not isinstance(doc, dict) or doc.get("v") != 1:
        raise ReleaseError("bad release")
    for key in ("version", "root_key", "root_sha256", "publisher", "sig"):
        if not isinstance(doc.get(key), str):
            raise ReleaseError(f"release field {key} invalid")
    if not 0 < len(doc["version"]) <= MAX_VERSION_LEN:
        raise ReleaseError("release version invalid")
    notes = doc.get("notes", "")
    if not isinstance(notes, str) or len(notes) > MAX_NOTES_LEN:
        raise ReleaseError("release notes invalid")
    ts = doc.get("ts")
    if not isinstance(ts, int) or isinstance(ts, bool) or not 0 <= ts <= 1 << 62:
        raise ReleaseError("release ts invalid")
    try:
        root_key = bytes.fromhex(doc["root_key"])
        publisher = bytes.fromhex(doc["publisher"])
        signature = bytes.fromhex(doc["sig"])
    except ValueError as exc:
        raise ReleaseError("release hex field invalid") from exc
    if len(root_key) != KEY_LEN or len(doc["root_sha256"]) != 64:
        raise ReleaseError("release root reference invalid")
    if not publisher or len(publisher) > 8192:
        raise ReleaseError("release publisher key invalid")
    if not verify(_signing_input(doc), signature, publisher):
        raise ReleaseError("release signature invalid")
    doc["root_key"] = root_key
    doc["publisher"] = publisher
    doc["publisher_id"] = publisher_id(publisher)
    doc["notes"] = notes
    return doc


# ---------------------------------------------------------------------------
# Who this operator accepts releases from
# ---------------------------------------------------------------------------

class TrustedPublishers:
    """The pinned publisher keys, persisted as plain JSON.

    No secret lives here — public keys, a label, and two booleans — but it is
    the file that decides what may replace this node's code, so a corrupt one
    yields **no** trusted publisher rather than a guess. Failing closed here
    costs an operator one re-pin; failing open costs them the machine."""

    def __init__(self, path: str | None = None,
                 max_publishers: int = MAX_PUBLISHERS) -> None:
        self._path = path
        self._max = max_publishers
        self._entries: dict[str, dict] = self._load()

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
            if len(out) >= self._max or not isinstance(value, dict):
                continue
            entry = self._clean(key, value)
            if entry is not None:
                out[key] = entry
        return out

    def _clean(self, key: str, value: dict) -> dict | None:
        """A stored entry is re-derived, never taken at face value: the id must
        follow from the key, or the file is telling us something it cannot
        know."""
        if not isinstance(key, str) or len(key) != PUBLISHER_ID_LEN * 2:
            return None
        raw = value.get("key")
        if not isinstance(raw, str):
            return None
        try:
            public = bytes.fromhex(raw)
        except ValueError:
            return None
        if not public or publisher_id(public).hex() != key:
            return None
        name = value.get("name")
        return {
            "id": key,
            "key": public.hex(),
            "name": (name if isinstance(name, str) else "")[:MAX_NAME_LEN],
            "auto": value.get("auto") is True,
            "added": int(value["added"]) if isinstance(value.get("added"), int)
                     and not isinstance(value.get("added"), bool) else 0,
        }

    def _save(self) -> None:
        if not self._path:
            return
        tmp = f"{self._path}.tmp.{os.getpid()}"
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        handle = os.open(tmp, flags, 0o600)
        try:
            with os.fdopen(handle, "w") as stream:
                json.dump(self._entries, stream)
        except BaseException:
            os.unlink(tmp)
            raise
        os.replace(tmp, self._path)

    def add(self, public_key: bytes, name: str = "", auto: bool = False) -> dict:
        """Pin a publisher. Raises when the key is unusable or the list is full.

        Re-pinning a key already held updates its label and auto flag rather
        than adding a second entry for the same identity."""
        if not isinstance(public_key, (bytes, bytearray)) or not public_key:
            raise ReleaseError("publisher key invalid")
        public_key = bytes(public_key)
        key_id = publisher_id(public_key).hex()
        if key_id not in self._entries and len(self._entries) >= self._max:
            raise ReleaseError("too many trusted publishers")
        existing = self._entries.get(key_id, {})
        self._entries[key_id] = {
            "id": key_id,
            "key": public_key.hex(),
            "name": str(name or existing.get("name", ""))[:MAX_NAME_LEN],
            "auto": bool(auto),
            "added": existing.get("added") or int(time.time()),
        }
        self._save()
        return dict(self._entries[key_id])

    def remove(self, key_id_hex: str) -> bool:
        if key_id_hex not in self._entries:
            return False
        del self._entries[key_id_hex]
        self._save()
        return True

    def set_auto(self, key_id_hex: str, auto: bool) -> bool:
        """Auto-install is a second decision, taken after the pin: trusting a
        publisher is not the same as handing them a scheduled restart."""
        entry = self._entries.get(key_id_hex)
        if entry is None:
            return False
        entry["auto"] = bool(auto)
        self._save()
        return True

    def entry(self, public_key: bytes) -> dict | None:
        found = self._entries.get(publisher_id(public_key).hex())
        return dict(found) if found else None

    def trusts(self, public_key: bytes) -> bool:
        return publisher_id(public_key).hex() in self._entries

    def auto_for(self, public_key: bytes) -> bool:
        entry = self._entries.get(publisher_id(public_key).hex())
        return bool(entry and entry["auto"])

    def list(self) -> list[dict]:
        return sorted((dict(e) for e in self._entries.values()),
                      key=lambda e: (e["name"].lower(), e["id"]))

    def __len__(self) -> int:
        return len(self._entries)


# ---------------------------------------------------------------------------
# What the network is offering
# ---------------------------------------------------------------------------

class ReleaseCatalog:
    """Bounded, signature-verified view of the releases the mesh is offering,
    one entry per publisher (the highest ``ts`` it has signed).

    Untrusted publishers are kept and relayed on purpose — refusing to carry
    what we do not install ourselves would break discovery for everyone else.
    They can never crowd out a pinned one: when the catalogue is full, an
    untrusted entry is evicted for a trusted newcomer, and an untrusted
    newcomer is simply refused."""

    def __init__(self, max_entries: int = MAX_CATALOG) -> None:
        self._max = max_entries
        self._entries: dict[bytes, dict] = {}

    def offer(self, release_bytes: bytes, verify, trusted=None) -> str | None:
        """Consider a signed release.

        Returns ``"new"`` / ``"updated"`` when our view changed (the caller
        should re-gossip it), or ``None`` when it was invalid, a duplicate, or
        older than what we hold — which is what stops the epidemic."""
        try:
            doc = parse_release(release_bytes, verify)
        except ReleaseError:
            return None
        key = doc["publisher_id"]
        is_trusted = bool(trusted(doc["publisher"])) if trusted else False
        existing = self._entries.get(key)
        if existing is not None:
            if doc["ts"] <= existing["ts"]:
                return None                      # anti-rollback
            outcome = "updated"
        else:
            if len(self._entries) >= self._max and not self._make_room(is_trusted):
                return None
            outcome = "new"
        self._entries[key] = {
            "publisher_id": key,
            "publisher": doc["publisher"],
            "release": bytes(release_bytes),
            "release_id": content_key(bytes(release_bytes)),
            "version": doc["version"],
            "root_key": doc["root_key"],
            "root_sha256": doc["root_sha256"],
            "notes": doc["notes"],
            "ts": doc["ts"],
            "trusted": is_trusted,
        }
        return outcome

    def _make_room(self, for_trusted: bool) -> bool:
        if not for_trusted:
            return False
        untrusted = [(entry["ts"], key) for key, entry in self._entries.items()
                     if not entry["trusted"]]
        if not untrusted:
            return False
        del self._entries[min(untrusted)[1]]
        return True

    def retrust(self, trusted) -> None:
        """Re-evaluate the trusted flag — a pin added now applies to what we
        already heard, without waiting for the publisher to announce again."""
        for entry in self._entries.values():
            entry["trusted"] = bool(trusted(entry["publisher"]))

    def get(self, publisher_id_hex: str) -> dict | None:
        try:
            key = bytes.fromhex(publisher_id_hex)
        except (ValueError, TypeError):
            return None
        return self._entries.get(key)

    def releases(self) -> list[bytes]:
        return [entry["release"] for entry in self._entries.values()]

    def list(self) -> list[dict]:
        """UI-facing metadata (no raw bytes), newest first."""
        out = [{
            "publisher_id": entry["publisher_id"].hex(),
            "publisher": entry["publisher"].hex(),
            "release_id": entry["release_id"].hex(),
            "version": entry["version"],
            "notes": entry["notes"],
            "ts": entry["ts"],
            "trusted": entry["trusted"],
        } for entry in self._entries.values()]
        out.sort(key=lambda entry: entry["ts"], reverse=True)
        return out

    def __len__(self) -> int:
        return len(self._entries)
