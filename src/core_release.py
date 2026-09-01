"""
Mesh-native releases — a node publishes the node's own code, signed.

Downloading an update from a web host makes one company's account the root of
trust for every node on the mesh. This module removes it: a release is a
**content-addressed package on the DHT** (exactly like an app package, see
:mod:`src.app_package`) plus a small **descriptor signed with the publisher's
ML-DSA identity**. Nodes gossip the descriptor; a node that has pinned that
publisher's key can fetch the content, verify every byte against the signed
root, and install it.

A release is **one blob** — the tree as a deterministic ``tar.gz`` — plus a
descriptor naming its size and SHA-256, signed. Publishing is therefore signing
and announcing: no network at all. A node that wants the release asks a node
that has it, checks the bytes against the signed hash, and by keeping them
becomes somewhere else to ask.

Three separate things, deliberately not merged:

  - **the blob** is verified by hash. The descriptor names its SHA-256, so a
    relay can neither substitute nor corrupt it, and no trust in whoever handed
    it over is needed.
  - **the descriptor** says *who* published *which* bytes, and when. Its
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

Why one blob and not a hundred chunks
-------------------------------------
The first cut of this pushed the tree onto the DHT as ~120 content-addressed
chunks, each costing a Kademlia lookup **at publish time** — a hundred round
trips paid up front, for nodes that may never ask. One blob moves that cost to
whoever actually wants the release, compresses 1.8 MB to about 0.5, and lets a
publisher sign a release with no peers at all.

Installing is not restarting — and yet it has to be
--------------------------------------------------
A release replaces files a running process already loaded, so an install only
takes effect when the node starts again. The unattended installer therefore ends
in a restart, and :class:`AutoInstallJournal` is what keeps that pair from
becoming a loop: an attempt is written down before the node leaves and read back
when it returns, so a release that installs and never becomes the running
version is abandoned instead of restarted into for ever.

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

import gzip
import hashlib
import io
import json
import os
import re
import tarfile
import time

_DOMAIN = b"nmesh-core-release-v1"

# Bounds. A release is source code, not a disk image: a package that does not
# fit these is not a release, whatever it claims to be.
MAX_TREE_BYTES = 64 * 1024 * 1024      # the tree, unpacked
MAX_PACKAGE_BYTES = 32 * 1024 * 1024   # the blob that carries it
MAX_FILES = 8192
MAX_VERSION_LEN = 64
MAX_NOTES_LEN = 4000
MAX_NAME_LEN = 64
MAX_PUBLISHERS = 32          # pinned keys an operator may hold
MAX_CATALOG = 64             # publishers tracked in the gossiped catalogue
MAX_HELD_PACKAGES = 4        # packages this node keeps to serve others
PUBLISHER_ID_LEN = 20
# An automatic install ends in a restart, so it must be able to give up: a
# release that installs and never becomes the running version is tried this
# many times and then abandoned, rather than restarting the node for ever.
MAX_AUTO_ATTEMPTS = 2
MAX_AUTO_JOURNAL = 8         # releases the journal remembers attempting

# What a release is made of. The same list the updater swaps in: the node's
# state, its virtualenv and anything an operator left in the install directory
# are not part of a release and are never carried by one.
INCLUDE = ("src", "scripts", "start.sh", "install.sh", "requirements.txt",
           "pyproject.toml", "Docs", "docker", "README.md", "CLAUDE.md")
REQUIRED = ("src/version.py", "start.sh")
_EXCLUDE_DIRS = {"__pycache__", ".git", ".venv", "data", "_oqs", "node_modules",
                 ".nmesh-previous", ".nmesh-update"}
_EXCLUDE_SUFFIXES = (".pyc", ".pyo", ".so", ".o")

_RELEASE_KEYS = ("v", "version", "size", "sha256", "publisher", "ts", "notes")
_HEX_ID = re.compile(r"[0-9a-f]{%d}" % (PUBLISHER_ID_LEN * 2))
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
# The package: one blob, and what it takes to open one safely
# ---------------------------------------------------------------------------

def release_id(package: bytes) -> bytes:
    """A release is named by the hash of its bytes."""
    return hashlib.sha256(package).digest()[:PUBLISHER_ID_LEN]


def build_package(files: dict) -> bytes:
    """Pack a tree into one deterministic ``tar.gz``.

    Deterministic on purpose — sorted paths, no mtimes, no uid/gid, a fixed
    mode — so the same tree packs to the same bytes on any machine. Two
    publishers building the same source produce the same hash, and a rebuild
    does not look like a new release."""
    if not files:
        raise ReleaseError("nothing to package")
    if len(files) > MAX_FILES:
        raise ReleaseError("too many files to package")
    # gzip stamps the time into its own header, so the tar is built first and
    # compressed with an explicit mtime — otherwise "deterministic" would hold
    # for the archive and not for the bytes anyone actually hashes.
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as tar:
        for path in sorted(files):
            safe = safe_relative(path)
            if safe is None:
                raise ReleaseError(f"unusable path in the tree: {path!r}")
            content = bytes(files[path])
            info = tarfile.TarInfo(safe.replace(os.sep, "/"))
            info.size = len(content)
            info.mtime = 0
            info.mode = 0o644
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            tar.addfile(info, io.BytesIO(content))
    compressed = io.BytesIO()
    with gzip.GzipFile(fileobj=compressed, mode="wb", mtime=0) as zipped:
        zipped.write(buffer.getvalue())
    package = compressed.getvalue()
    if len(package) > MAX_PACKAGE_BYTES:
        raise ReleaseError("the packaged tree is too large to publish")
    return package


def open_package(package: bytes) -> dict[str, bytes]:
    """Unpack a blob into ``path -> bytes``, treating it as hostile.

    The caller has already checked the blob against the SHA-256 a pinned
    publisher signed, so this is not the trust boundary — but a signature says
    who sent it, never that what they sent is sane. Decompression is where a
    small blob becomes a large one, so the bound is applied **while** reading,
    not after; and only regular files with a usable relative path come out."""
    if not isinstance(package, (bytes, bytearray)):
        raise ReleaseError("package is not bytes")
    if not package or len(package) > MAX_PACKAGE_BYTES:
        raise ReleaseError("package size out of bounds")
    files: dict[str, bytes] = {}
    total = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(bytes(package)), mode="r:gz") as tar:
            for info in tar:
                if len(files) >= MAX_FILES:
                    raise ReleaseError("package holds too many files")
                if not info.isfile():
                    # Links, devices and directories carry no content and are
                    # how an archive reaches outside itself. Refused, not
                    # sanitised — see updater.safe_relative.
                    if info.isdir():
                        continue
                    raise ReleaseError(f"package holds a {info.type!r} entry")
                safe = safe_relative(info.name)
                if safe is None:
                    raise ReleaseError(f"package holds an unusable path: {info.name!r}")
                total += max(0, info.size)
                if total > MAX_TREE_BYTES:
                    raise ReleaseError("package unpacks to more than we accept")
                handle = tar.extractfile(info)
                content = handle.read(MAX_TREE_BYTES + 1) if handle else b""
                if len(content) > MAX_TREE_BYTES:
                    raise ReleaseError("package unpacks to more than we accept")
                files[safe.replace(os.sep, "/")] = content
    except ReleaseError:
        raise
    except Exception as exc:
        raise ReleaseError(f"package is unreadable: {exc}") from exc
    if not files:
        raise ReleaseError("package is empty")
    return files


def safe_relative(path):
    """A relative path with no absolute root, no ``..`` escape, no NUL.

    The same rule the updater applies when writing files out; a package that
    breaks it is refused rather than trimmed into something that looks fine."""
    from .updater import safe_relative as _safe
    return _safe(path)


# ---------------------------------------------------------------------------
# The signed descriptor
# ---------------------------------------------------------------------------

def _signing_input(body: dict) -> bytes:
    return _DOMAIN + json.dumps({k: body[k] for k in _RELEASE_KEYS},
                                sort_keys=True).encode("utf-8")


def build_release(package: bytes, version: str, publisher_pub: bytes, sign,
                  ts: int | None = None, notes: str = "") -> bytes:
    """Sign a descriptor naming this package's bytes.

    ``sign(message) -> signature`` signs with the publisher's ML-DSA identity.
    Nothing here signs bytes the caller chose: the input is this domain plus
    these named fields, so the signature cannot be lifted into another meaning.
    """
    if not isinstance(version, str) or not 0 < len(version) <= MAX_VERSION_LEN:
        raise ReleaseError("version invalid")
    if not isinstance(package, (bytes, bytearray)) or not package:
        raise ReleaseError("package invalid")
    if len(package) > MAX_PACKAGE_BYTES:
        raise ReleaseError("package too large")
    body = {
        "v": 2,
        "version": version,
        "size": len(package),
        "sha256": hashlib.sha256(package).hexdigest(),
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
    if not isinstance(doc, dict) or doc.get("v") != 2:
        raise ReleaseError("bad release")
    for key in ("version", "sha256", "publisher", "sig"):
        if not isinstance(doc.get(key), str):
            raise ReleaseError(f"release field {key} invalid")
    size = doc.get("size")
    if (not isinstance(size, int) or isinstance(size, bool)
            or not 0 < size <= MAX_PACKAGE_BYTES):
        raise ReleaseError("release size invalid")
    if not 0 < len(doc["version"]) <= MAX_VERSION_LEN:
        raise ReleaseError("release version invalid")
    notes = doc.get("notes", "")
    if not isinstance(notes, str) or len(notes) > MAX_NOTES_LEN:
        raise ReleaseError("release notes invalid")
    ts = doc.get("ts")
    if not isinstance(ts, int) or isinstance(ts, bool) or not 0 <= ts <= 1 << 62:
        raise ReleaseError("release ts invalid")
    try:
        publisher = bytes.fromhex(doc["publisher"])
        signature = bytes.fromhex(doc["sig"])
        bytes.fromhex(doc["sha256"])
    except ValueError as exc:
        raise ReleaseError("release hex field invalid") from exc
    if len(doc["sha256"]) != 64:
        raise ReleaseError("release hash invalid")
    if not publisher or len(publisher) > 8192:
        raise ReleaseError("release publisher key invalid")
    if not verify(_signing_input(doc), signature, publisher):
        raise ReleaseError("release signature invalid")
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
# What the unattended installer has already tried
# ---------------------------------------------------------------------------

class AutoInstallJournal:
    """Automatic installs attempted, remembered **across restarts**.

    An automatic install only takes effect when the node comes back on the tree
    it just wrote, so the loop that installs also has to leave. That pair —
    install, restart — is a loop waiting to happen: a release that installs
    cleanly and yet never becomes the running version (a tree the service
    manager does not start from, a swap that a stale copy shadows) would be
    installed and restarted into, for ever, on a machine nobody is watching.
    In-memory bookkeeping cannot see it, because the process it would have to
    outlive is the one that exits.

    So each attempt is written down **before** the node leaves and read back
    when it returns. A release whose version is the one now running worked and
    is forgotten; one that has been attempted :data:`MAX_AUTO_ATTEMPTS` times
    without that ever happening is abandoned, and stays abandoned until an
    operator installs something by hand.

    Bounded like everything else, and fail-open in the harmless direction only:
    an unreadable journal means "nothing attempted yet", which costs one extra
    attempt, never an unbounded number."""

    def __init__(self, path: str | None = None,
                 max_entries: int = MAX_AUTO_JOURNAL) -> None:
        self._path = path
        self._max = max_entries
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
        version = value.get("version")
        attempts = value.get("attempts")
        if not isinstance(version, str) or len(version) > MAX_VERSION_LEN:
            return None
        if not isinstance(attempts, int) or isinstance(attempts, bool):
            return None
        return {"version": version,
                "attempts": max(0, min(attempts, MAX_AUTO_ATTEMPTS)),
                "at": int(value["at"]) if isinstance(value.get("at"), int)
                      and not isinstance(value.get("at"), bool) else 0}

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

    def settle(self, running_version: str) -> list[str]:
        """Read the journal against what is actually running, at startup.

        Every entry naming the running version did what it was written for, and
        is dropped. Returns the versions that did **not** take, so the node can
        say so rather than quietly trying again."""
        stale = []
        for key, entry in list(self._entries.items()):
            if entry["version"] == running_version:
                del self._entries[key]
            else:
                stale.append(entry["version"])
        if stale or not self._entries:
            self._save()
        return stale

    def attempts(self, release_id_hex: str) -> int:
        entry = self._entries.get(release_id_hex)
        return entry["attempts"] if entry else 0

    def exhausted(self, release_id_hex: str) -> bool:
        return self.attempts(release_id_hex) >= MAX_AUTO_ATTEMPTS

    def record(self, release_id_hex: str, version: str) -> int:
        """Note one attempt, on disk, and return how many there have been.

        Called **before** the node restarts into it: an attempt written after
        the exit is an attempt nobody ever counts."""
        if not _HEX_ID.fullmatch(release_id_hex or ""):
            return 0
        entry = self._entries.get(release_id_hex)
        attempts = (entry["attempts"] if entry else 0) + 1
        self._entries[release_id_hex] = {
            "version": str(version)[:MAX_VERSION_LEN],
            "attempts": min(attempts, MAX_AUTO_ATTEMPTS),
            "at": int(time.time()),
        }
        while len(self._entries) > self._max:
            self._entries.pop(next(iter(self._entries)))
        self._save()
        return attempts

    def forget(self, release_id_hex: str) -> None:
        """Drop one entry — an operator installing by hand is a fresh start."""
        if self._entries.pop(release_id_hex, None) is not None:
            self._save()

    def __len__(self) -> int:
        return len(self._entries)


# ---------------------------------------------------------------------------
# What this node holds, and can hand to someone else
# ---------------------------------------------------------------------------

class ReleaseStore:
    """The packages this node has, on disk, ready to serve.

    A node that fetched a release keeps it and becomes somewhere else to ask —
    that is the whole distribution model: one publisher, then a swarm. Kept on
    disk rather than in memory so a restart does not undo it, and bounded so
    that helping the network never becomes unbounded storage.

    Nothing enters without matching the SHA-256 a pinned publisher signed. A
    file already on disk is re-checked when it is read back: the store is a
    cache, and a cache that hands out what it was not given is worse than an
    empty one."""

    def __init__(self, directory: str | None = None,
                 max_packages: int = MAX_HELD_PACKAGES) -> None:
        self._dir = directory
        self._max = max_packages
        if self._dir:
            try:
                os.makedirs(self._dir, exist_ok=True)
            except OSError:
                self._dir = None          # no store; we simply hold nothing
        self._memory: dict[str, bytes] = {}     # used when there is no directory

    def _path(self, release_id_hex: str) -> str | None:
        if not self._dir or not _HEX_ID.fullmatch(release_id_hex or ""):
            return None
        return os.path.join(self._dir, f"{release_id_hex}.pkg")

    def put(self, release_id_hex: str, package: bytes, sha256_hex: str) -> bool:
        """Keep a package, if it really is the one that hash names."""
        if not isinstance(package, (bytes, bytearray)) or not package:
            return False
        if len(package) > MAX_PACKAGE_BYTES:
            return False
        if hashlib.sha256(bytes(package)).hexdigest() != sha256_hex:
            return False
        self._evict_to(self._max - 1)
        if self._dir is None:
            self._memory[release_id_hex] = bytes(package)
            return True
        path = self._path(release_id_hex)
        if path is None:
            return False
        tmp = f"{path}.tmp.{os.getpid()}"
        try:
            handle = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(handle, "wb") as stream:
                stream.write(bytes(package))
            os.replace(tmp, path)
        except OSError:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            return False
        return True

    def get(self, release_id_hex: str) -> bytes | None:
        """The package, re-checked against the id it is filed under."""
        if self._dir is None:
            return self._memory.get(release_id_hex)
        path = self._path(release_id_hex)
        if path is None or not os.path.isfile(path):
            return None
        try:
            if os.path.getsize(path) > MAX_PACKAGE_BYTES:
                return None
            with open(path, "rb") as handle:
                package = handle.read(MAX_PACKAGE_BYTES + 1)
        except OSError:
            return None
        if len(package) > MAX_PACKAGE_BYTES:
            return None
        if hashlib.sha256(package).digest()[:PUBLISHER_ID_LEN].hex() != release_id_hex:
            return None               # a file that is not what it is filed as
        return package

    def has(self, release_id_hex: str) -> bool:
        return self.get(release_id_hex) is not None

    def ids(self) -> list[str]:
        if self._dir is None:
            return sorted(self._memory)
        try:
            names = os.listdir(self._dir)
        except OSError:
            return []
        return sorted(name[:-4] for name in names if name.endswith(".pkg")
                      and _HEX_ID.fullmatch(name[:-4]))

    def _evict_to(self, keep: int) -> None:
        """Drop the least recently touched packages down to ``keep``."""
        held = self.ids()
        if len(held) <= max(0, keep):
            return
        if self._dir is None:
            for release_id_hex in held[:len(held) - keep]:
                self._memory.pop(release_id_hex, None)
            return
        def age(release_id_hex: str) -> float:
            try:
                return os.path.getmtime(self._path(release_id_hex))
            except OSError:
                return 0.0
        for release_id_hex in sorted(held, key=age)[:len(held) - keep]:
            try:
                os.unlink(self._path(release_id_hex))
            except OSError:
                pass

    def __len__(self) -> int:
        return len(self.ids())


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
            # Named by the package it points at, not by the descriptor: two
            # nodes holding the same release agree on what to ask each other
            # for, whatever their copy of the descriptor looks like.
            "release_id": bytes.fromhex(doc["sha256"])[:PUBLISHER_ID_LEN],
            "version": doc["version"],
            "sha256": doc["sha256"],
            "size": doc["size"],
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
            "size": entry["size"],
            "notes": entry["notes"],
            "ts": entry["ts"],
            "trusted": entry["trusted"],
        } for entry in self._entries.values()]
        out.sort(key=lambda entry: entry["ts"], reverse=True)
        return out

    def __len__(self) -> int:
        return len(self._entries)
