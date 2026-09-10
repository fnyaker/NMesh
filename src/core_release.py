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
  - **the pin** says whose signature this operator accepts, and **for what**:
    a key pinned from an app's record is a party to that app, not somebody who
    may replace this program (``TrustedPublishers``, the ``code`` flag).
    Nothing arriving from the network can add one: a release from a publisher
    unpinned for code is relayed and displayed, never installed.

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
from collections import OrderedDict

_DOMAIN = b"nmesh-core-release-v1"

# What a core release is called in the package directory. A name, not an
# identity: several publishers offer "NMesh" and the key is what tells them
# apart — which is exactly the shape a search by name needs.
PROJECT_NAME = "NMesh"

# Bounds. A release is source code, not a disk image: a package that does not
# fit these is not a release, whatever it claims to be.
MAX_TREE_BYTES = 64 * 1024 * 1024      # the tree, unpacked
MAX_PACKAGE_BYTES = 32 * 1024 * 1024   # the blob that carries it
MAX_FILES = 8192
MAX_VERSION_LEN = 64
MAX_NOTES_LEN = 4000
MAX_NAME_LEN = 64
MAX_PUBLISHERS = 32          # pinned keys an operator may hold
MAX_CATALOG = 64             # releases tracked in the gossiped book
MAX_EQUIVOCATIONS = 8        # publishers we keep a self-contradiction proof about
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
    """The signing keys this operator accepts, persisted as plain JSON.

    No secret lives here — public keys, a label, and three booleans — but it is
    the file that decides what may replace this node's code, so a corrupt one
    yields **no** trusted publisher rather than a guess. Failing closed here
    costs an operator one re-pin; failing open costs them the machine.

    **Being in this list is not one permission.** ``code`` says whether this
    key may sign *this node's own program*; a key pinned from an app's record
    is a key an operator chose as a party to that app, and nothing more. One
    list without that field would have made "pin the key that signed this app"
    a way to hand the machine to whoever wrote an app — the same button, two
    meanings, and only one of them on screen."""

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
        # A row written before this field existed is a row written by the only
        # thing that could write one: a core release's record. Reading it as
        # anything else would quietly stop every node already running from
        # updating itself, and would misreport what its operator decided.
        code = value.get("code") is not False
        return {
            "id": key,
            "key": public.hex(),
            "name": (name if isinstance(name, str) else "")[:MAX_NAME_LEN],
            "code": code,
            # Re-derived rather than read: "may replace my code without asking"
            # cannot outlive "may replace my code", and a file saying both
            # things at once is answered with the narrower one.
            "auto": value.get("auto") is True and code,
            "endorsed": value.get("endorsed") is True,
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

    def add(self, public_key: bytes, name: str = "", auto: bool = False,
            endorsed: bool = False, code: bool = True) -> dict:
        """Pin a signing key. Raises when the key is unusable or the list is full.

        Re-pinning a key already held updates its label and flags rather than
        adding a second entry for the same identity.

        The three flags are different statements and none implies another.
        ``code`` says "releases of **this node's own program** signed by this
        key may be installed here" — the strongest of them, and the one a key
        pinned from an app's record does not get. ``auto`` says "this key alone
        may replace my code without asking me", so it means nothing without
        ``code`` and is stored as nothing. ``endorsed`` says "this key's word
        counts towards a quorum" — much weaker on its own, and it is the answer
        to somebody minting two hundred publishers: a quorum made of keys a
        human chose one at a time cannot be reached by creating identities, only
        by compromising chosen ones.

        A re-pin **widens** ``code`` and never narrows it: pinning the key of an
        app you already accept node software from is not a decision to stop
        accepting node software from it, and silently making it one would take a
        permission away in the middle of a sentence about something else."""
        if not isinstance(public_key, (bytes, bytearray)) or not public_key:
            raise ReleaseError("publisher key invalid")
        public_key = bytes(public_key)
        key_id = publisher_id(public_key).hex()
        if key_id not in self._entries and len(self._entries) >= self._max:
            raise ReleaseError("too many trusted publishers")
        existing = self._entries.get(key_id, {})
        code = bool(code) or existing.get("code") is True
        self._entries[key_id] = {
            "id": key_id,
            "key": public_key.hex(),
            "name": str(name or existing.get("name", ""))[:MAX_NAME_LEN],
            "code": code,
            "auto": bool(auto) and code,
            "endorsed": bool(endorsed),
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
        publisher is not the same as handing them a scheduled restart.

        Refused for a key that may not replace this node's code at all — there
        is no unattended install for it to allow, and storing the flag anyway
        would leave a ticked box promising something nothing honours."""
        entry = self._entries.get(key_id_hex)
        if entry is None or (auto and not entry["code"]):
            return False
        entry["auto"] = bool(auto)
        self._save()
        return True

    def set_endorse(self, key_id_hex: str, endorsed: bool) -> bool:
        """Whether this key's attestation counts towards a quorum."""
        entry = self._entries.get(key_id_hex)
        if entry is None:
            return False
        entry["endorsed"] = bool(endorsed)
        self._save()
        return True

    def endorsed_among(self, public_keys) -> list[str]:
        """Which of these keys this operator has endorsed, by id.

        By id and de-duplicated, because the quantity that means something is
        *how many distinct endorsed parties* said it — the same key signing
        twice is one party, and counting it twice would price a quorum at one
        compromised machine."""
        found = []
        for key in public_keys:
            try:
                key_id = publisher_id(bytes(key)).hex()
            except (TypeError, ValueError):
                continue
            entry = self._entries.get(key_id)
            if entry is not None and entry["endorsed"] and key_id not in found:
                found.append(key_id)
        return found

    def entry(self, public_key: bytes) -> dict | None:
        found = self._entries.get(publisher_id(public_key).hex())
        return dict(found) if found else None

    def pinned(self, public_key: bytes) -> bool:
        """Is this key in the list at all — a party this operator chose?

        Not "may it replace this node's code": that is :meth:`may_install_code`
        and it is a narrower question. One method answering both is how a button
        on an app's page came close to handing out the machine."""
        return publisher_id(public_key).hex() in self._entries

    def may_install_code(self, public_key: bytes) -> bool:
        """May releases of **this node's own program** signed by this key be
        installed here? The strongest thing this file says about a key."""
        entry = self._entries.get(publisher_id(public_key).hex())
        return bool(entry and entry["code"])

    def auto_for(self, public_key: bytes) -> bool:
        entry = self._entries.get(publisher_id(public_key).hex())
        return bool(entry and entry["auto"] and entry["code"])

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

def descriptor_key(release_bytes: bytes) -> bytes:
    """Where a signed descriptor lives on the DHT — and what names the release.

    The same derivation the DHT uses for any value, so a node that stores a
    descriptor and a node that names one arrive at the same 20 bytes without
    telling each other anything. This is the release's name everywhere: in the
    book, in the directory key that lists who can serve it, and in the record a
    node signs to say it holds it."""
    return hashlib.sha256(bytes(release_bytes)).digest()[:PUBLISHER_ID_LEN]


def catalogue_entry(doc: dict, release_bytes: bytes,
                    is_trusted: bool = False) -> dict:
    """The shape everything downstream reads a release through.

    One expression, because there are now two ways to arrive at a release: the
    catalogue (gossiped, one entry per publisher) and a **signed descriptor
    handed to us directly** — the record an operator clicked in the package
    directory. The second must not go through the first: a catalogue is indexed
    by publisher and holds only that key's newest signature, so resolving an
    install through it installs *whatever that key has signed since*, not the
    thing on the screen. A release is bytes and a signature; this is that
    signature's own view of them."""
    return {
        # What names this release, everywhere: the descriptor's own content
        # key. Derived here so nothing downstream has to re-derive it and get a
        # different answer.
        "key": descriptor_key(release_bytes),
        "publisher_id": doc["publisher_id"],
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
        "trusted": bool(is_trusted),
    }


class ReleaseBook:
    """Every signed release we know, keyed by **the descriptor's own content
    key** — one entry per release, several per signing key.

    It used to be one entry per publisher: its newest signature, and nothing
    else. That made a key a *name for a release*, which it is not. Two things
    broke on it. Installing resolved a publisher id through here, so clicking a
    release installed whatever that key had signed since; and a release found by
    name in the directory, never gossiped at us, could not be held at all
    because a newer one from the same key was already in its slot.

    A release is bytes and a signature. The signature says who may replace this
    node's code — that is decided by the pins, at the install gate — and the
    bytes are named by their hash. Neither is a reason to index by publisher.

    Untrusted signers are kept and relayed on purpose: refusing to carry what we
    do not install ourselves would break discovery for everyone else. They can
    never crowd out a pinned one — when the book is full, an untrusted entry is
    evicted for a trusted newcomer, and an untrusted newcomer is simply
    refused."""

    def __init__(self, max_entries: int = MAX_CATALOG) -> None:
        self._max = max_entries
        self._entries: "OrderedDict[bytes, dict]" = OrderedDict()
        # Signing keys caught signing one version twice, with different bytes
        # each time. One proof per key, bounded beside the table it describes.
        self._equivocations: dict[bytes, bytes] = {}

    # -- mutation ---------------------------------------------------------

    def offer(self, release_bytes: bytes, verify, trusted=None) -> str | None:
        """Consider a signed release.

        Returns ``"new"`` when our view changed (the caller should re-gossip
        it), or ``None`` when it was invalid or one we already hold — which is
        what stops the epidemic. There is no "updated": a descriptor is named by
        its own bytes, so a changed descriptor is a different release, and the
        same one arriving twice is a duplicate whatever its timestamp says.

        No anti-rollback here, deliberately. An old release cannot walk this node
        backwards because the **install** gate refuses anything that is not
        strictly newer than what is running; keeping the old descriptor in a book
        is how an operator can still look at it, and how a node can still serve
        it to somebody who wants it."""
        try:
            doc = parse_release(release_bytes, verify)
        except ReleaseError:
            return None
        key = descriptor_key(release_bytes)
        if key in self._entries:
            self._entries.move_to_end(key)
            return None
        is_trusted = bool(trusted(doc["publisher"])) if trusted else False
        self._note_equivocation(doc, release_bytes, is_trusted)
        if len(self._entries) >= self._max and not self._make_room(is_trusted):
            return None
        self._entries[key] = catalogue_entry(doc, release_bytes, is_trusted)
        return "new"

    def _note_equivocation(self, doc: dict, incoming: bytes,
                           is_trusted: bool) -> None:
        """Keep the pair when one key signs one version twice, differently.

        One proof per key, the first one seen: a second is the same fact about
        the same key, and the table is bounded like every other thing here that
        an outsider can grow. When it is full a proof about a key this operator
        never pinned makes way for one about a key they did — the table's whole
        use is refusing an unattended install, so the keys that could actually
        cause one are the keys worth the room."""
        signer = doc["publisher_id"]
        if signer in self._equivocations:
            return
        existing = next(
            (entry for entry in self._entries.values()
             if entry["publisher_id"] == signer
             and entry["version"] == doc["version"]
             and entry["sha256"] != doc["sha256"]), None)
        if existing is None:
            return
        from . import equivocation
        try:
            proof = equivocation.build(
                equivocation.KIND_RELEASE, existing["release"], bytes(incoming))
        except Exception:
            return        # a proof we cannot frame is not a reason to drop the release
        if len(self._equivocations) >= MAX_EQUIVOCATIONS:
            if not is_trusted or not self._evict_equivocation():
                return
        self._equivocations[signer] = proof

    def _evict_equivocation(self) -> bool:
        for signer in self._equivocations:
            if not any(entry["publisher_id"] == signer and entry["trusted"]
                       for entry in self._entries.values()):
                del self._equivocations[signer]
                return True
        return False

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
        already heard, without waiting for anybody to announce again."""
        for entry in self._entries.values():
            entry["trusted"] = bool(trusted(entry["publisher"]))

    # -- reading ----------------------------------------------------------

    def get(self, key) -> dict | None:
        """One release, by its descriptor key (bytes or hex)."""
        if isinstance(key, str):
            try:
                key = bytes.fromhex(key)
            except (ValueError, TypeError):
                return None
        if not isinstance(key, (bytes, bytearray)):
            return None
        return self._entries.get(bytes(key))

    def equivocations(self) -> dict[bytes, bytes]:
        """``signer_id -> proof``, for whoever wants to act on it or pass it
        on. A copy: nothing outside may edit the book by iterating it."""
        return dict(self._equivocations)

    def equivocated(self, key) -> bytes | None:
        """The proof that this signing key contradicted itself, if we hold one.

        Takes the id or the key it is derived from: both are what a caller has
        to hand, and deriving one from the other is not a decision worth making
        at four call sites."""
        if not isinstance(key, (bytes, bytearray)):
            return None
        key = bytes(key)
        if len(key) != PUBLISHER_ID_LEN:
            key = publisher_id(key)
        return self._equivocations.get(key)

    def releases(self) -> list[bytes]:
        return [entry["release"] for entry in self._entries.values()]

    def by_signer(self, signer_id) -> list[dict]:
        """Every release this key has signed that we hold, newest first.

        A view, not the storage. The console asks it because "what has this key
        I pinned offered?" is a real question; nothing on the install path does,
        because "which release?" is answered by a release."""
        if isinstance(signer_id, str):
            try:
                signer_id = bytes.fromhex(signer_id)
            except (ValueError, TypeError):
                return []
        signer_id = bytes(signer_id)
        found = [entry for entry in self._entries.values()
                 if entry["publisher_id"] == signer_id]
        found.sort(key=lambda entry: entry["ts"], reverse=True)
        return found

    def attesters(self, version: str, sha256: str) -> list[bytes]:
        """The signing keys that have signed **this exact content**.

        This is what corroboration is counted in. Not the nodes serving the
        package: mirroring bytes is free and the content hash already makes
        them safe to fetch from anyone, so a thousand mirrors say nothing that
        one does not. A second *signature* over the same hash says a second
        party put their key behind the same code, and that is the only thing
        here an attacker cannot get for nothing.

        De-duplicated by key: one key signing a version twice is one party, and
        counting it twice would price a quorum at one compromised machine."""
        found: list[bytes] = []
        for entry in self._entries.values():
            if entry["version"] != version or entry["sha256"] != sha256:
                continue
            if entry["publisher"] not in found:
                found.append(entry["publisher"])
        return found

    def contradicts(self, version: str, sha256: str) -> bool:
        """Does anybody claim this version with *different* content?

        Either the network has forked or somebody is signing a build of their
        own under a version everyone recognises. Both are things to stop an
        unattended install for, and neither is a reason to accuse anybody: two
        honest publishers can disagree by accident, and the answer to that is
        also to stop and let a human look."""
        return any(entry["version"] == version and entry["sha256"] != sha256
                   for entry in self._entries.values())

    def list(self) -> list[dict]:
        """UI-facing metadata (no raw bytes), newest first — one row per
        release, each naming the key that signed it."""
        out = [{
            "key": entry["key"].hex(),
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
