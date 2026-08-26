"""
Self-update — check GitHub for a newer release, and install it if asked.

Two halves, deliberately separate:

  - **check** is read-only and safe to run whenever. It asks the GitHub API for
    the latest release and compares its tag to :data:`src.version.__version__`.
  - **apply** replaces the installed tree. It never runs on its own: the caller
    must pass the exact version it is confirming, and that version must still be
    the one on offer. A page left open for an hour cannot install something the
    operator never saw.

There are two ways in
---------------------
``apply``/``apply_sync`` take a GitHub tag and download it. ``apply_files`` takes
files a caller has already fetched from the mesh and verified against a signed
content root (:mod:`src.core_release`) — no download, no GitHub, no TLS. Both
end in the same swap, so the backup-and-restore path is written once.

Where the trust actually sits
-----------------------------
This is a supply-chain surface, so it is worth stating plainly rather than
burying. Downloading a release trusts, in order: the TLS certificate chain to
``api.github.com`` and ``codeload.github.com``, GitHub itself, and whoever can
publish a release in the pinned repository. There is **no signature over the
release** today, so a GitHub account compromise is a code-execution path into
every node that accepts an update. What limits it:

  - the repository is **pinned** (``NMESH_UPDATE_REPO`` exists for forks, but a
    peer cannot choose it — nothing on the mesh reaches this module);
  - an update from GitHub is **never automatic** — a human confirms a named
    version;
  - the download is **bounded**, the archive is extracted with a filter that
    refuses paths outside the destination, and the unpacked tree is checked to
    look like NMesh before anything is replaced;
  - the previous tree is **kept** until the new one is in place, and restored if
    the swap fails.

The mesh path exists precisely to take GitHub out of that set:
:mod:`src.core_release` signs a release with an ML-DSA identity and this node
installs it only from a publisher whose key its operator pinned. What neither
path can defend against is a compromised machine — ``todo/peer-integrity.md``
covers that wider problem.

Never on the event loop
-----------------------
Every network call runs in a daemon thread that is abandoned on timeout, never
joined — a hung TLS handshake or DNS lookup on a restricted network would
otherwise wedge interpreter shutdown (``Docs/Architecture/gotchas.md`` §2).
"""
from __future__ import annotations

import asyncio
import io
import json
import os
import shutil
import tarfile
import threading
import time
import urllib.error
import urllib.request

from .version import __version__, is_newer

DEFAULT_REPO = "fnyaker/NMesh"
API_TIMEOUT = 15.0
DOWNLOAD_TIMEOUT = 300.0
MAX_API_BYTES = 1 * 1024 * 1024
MAX_DOWNLOAD_BYTES = 64 * 1024 * 1024
MAX_NOTES = 8000
_USER_AGENT = f"nmesh/{__version__}"

# What an unpacked release must contain before we replace anything with it.
REQUIRED_ENTRIES = ("src", "start.sh")
# What we swap in. Deliberately not the whole archive: the node's state, its
# virtualenv and anything an operator left in the install directory stay put.
REPLACE_ENTRIES = ("src", "scripts", "start.sh", "install.sh",
                   "requirements.txt", "pyproject.toml", "Docs", "docker",
                   "README.md", "CLAUDE.md")
_BACKUP_DIR = ".nmesh-previous"
_STAGE_DIR = ".nmesh-update"


class UpdateError(Exception):
    """Anything that stops an update, phrased for the operator."""


def repo() -> str:
    return os.environ.get("NMESH_UPDATE_REPO") or DEFAULT_REPO


def install_root() -> str:
    """The directory holding the running tree (the parent of ``src``)."""
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def service_managed() -> bool:
    """True when something will restart us if we exit.

    ``install.sh`` sets this in every unit it writes. Without it, exiting to
    pick up an update would simply stop the node — so we don't."""
    return os.environ.get("NMESH_SERVICE_MANAGED") == "1"


def updatable() -> tuple[bool, str]:
    """Can this install be updated in place? ``(ok, reason_if_not)``."""
    root = install_root()
    if not os.path.isdir(os.path.join(root, "src")):
        return False, "the running tree has no src/ directory"
    if not os.access(root, os.W_OK):
        return False, f"{root} is not writable by this process"
    if os.path.exists("/.dockerenv") and not os.path.exists(
            os.path.join(root, ".git")):
        return False, ("this node runs from a container image — update it by "
                       "pulling a newer image, not from here")
    return True, ""


# ---------------------------------------------------------------------------
# Bounded network access
# ---------------------------------------------------------------------------

async def _bounded(call, timeout: float, what: str = "talking to GitHub"):
    """Await a blocking call that runs in a daemon thread we never join.

    Not ``to_thread`` / ``run_in_executor``: asyncio joins its default executor
    at shutdown, so one stuck TLS handshake would hang the process on the way
    out. Same shape as ``ip_utils.bounded_getaddrinfo`` — on timeout the thread
    is simply abandoned."""
    loop = asyncio.get_running_loop()
    fut: asyncio.Future = loop.create_future()

    def worker() -> None:
        try:
            result = call()
        except BaseException as exc:      # noqa: BLE001 — relayed to the caller
            result = exc
        if not loop.is_closed():
            loop.call_soon_threadsafe(
                lambda: fut.done() or fut.set_result(result))

    threading.Thread(target=worker, name="nmesh-update", daemon=True).start()
    try:
        result = await asyncio.wait_for(fut, timeout)
    except asyncio.TimeoutError:
        raise UpdateError(f"timed out {what}") from None
    if isinstance(result, BaseException):
        raise result
    return result


def _fetch(url: str, *, timeout: float, max_bytes: int,
           accept: str = "application/json") -> bytes:
    request = urllib.request.Request(url, headers={
        "Accept": accept,
        "User-Agent": _USER_AGENT,
        "X-GitHub-Api-Version": "2022-11-28",
    })
    # Default context: certificates are verified against the system store.
    with urllib.request.urlopen(request, timeout=timeout) as response:
        # Read one byte past the cap so an oversized body is detected rather
        # than silently truncated into something that half-parses.
        body = response.read(max_bytes + 1)
    if len(body) > max_bytes:
        raise UpdateError("the response from GitHub was implausibly large")
    return body


# ---------------------------------------------------------------------------
# Check
# ---------------------------------------------------------------------------

def _latest_release() -> dict:
    url = f"https://api.github.com/repos/{repo()}/releases/latest"
    try:
        raw = _fetch(url, timeout=API_TIMEOUT, max_bytes=MAX_API_BYTES)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            raise UpdateError("no published release in "
                              f"{repo()} yet") from exc
        raise UpdateError(f"GitHub answered {exc.code}") from exc
    except (urllib.error.URLError, OSError) as exc:
        raise UpdateError(f"could not reach GitHub: {exc.reason if hasattr(exc, 'reason') else exc}") from exc
    try:
        document = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise UpdateError("GitHub returned something unreadable") from exc
    if not isinstance(document, dict):
        raise UpdateError("GitHub returned something unreadable")
    return document


def check_sync() -> dict:
    """Blocking check. Prefer :func:`check`."""
    document = _latest_release()
    tag = document.get("tag_name")
    if not isinstance(tag, str) or not tag:
        raise UpdateError("the latest release has no tag")
    notes = document.get("body")
    return {
        "current": __version__,
        "latest": tag,
        "available": is_newer(tag, __version__),
        "url": str(document.get("html_url") or "")[:512],
        "published_at": str(document.get("published_at") or "")[:64],
        "notes": (notes[:MAX_NOTES] if isinstance(notes, str) else ""),
        "repo": repo(),
        "checked_at": time.time(),
    }


async def check() -> dict:
    """Ask GitHub what the latest release is. Read-only; changes nothing."""
    return await _bounded(check_sync, API_TIMEOUT + 5)


# ---------------------------------------------------------------------------
# Apply
# ---------------------------------------------------------------------------

def _download(tag: str) -> bytes:
    url = f"https://codeload.github.com/{repo()}/tar.gz/refs/tags/{tag}"
    try:
        return _fetch(url, timeout=DOWNLOAD_TIMEOUT,
                      max_bytes=MAX_DOWNLOAD_BYTES,
                      accept="application/octet-stream")
    except urllib.error.HTTPError as exc:
        raise UpdateError(f"could not download {tag}: GitHub answered "
                          f"{exc.code}") from exc
    except (urllib.error.URLError, OSError) as exc:
        raise UpdateError(f"could not download {tag}: {exc}") from exc


def _extract(archive: bytes, dest: str) -> str:
    """Unpack a GitHub source tarball and return its single top-level dir.

    Extraction uses the ``data`` filter: no absolute paths, no ``..``, no
    symlinks pointing outside, no device nodes. An archive that tries any of
    that is refused rather than sanitised."""
    os.makedirs(dest, exist_ok=True)
    try:
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tar:
            _refuse_unsafe_members(tar, dest)
            try:
                tar.extractall(dest, filter="data")
            except TypeError:
                # Python without the tarfile filters. The members were already
                # checked above, so this stays a safe extraction — there is no
                # branch here that trusts the archive.
                tar.extractall(dest)
    except (tarfile.TarError, OSError, ValueError) as exc:
        raise UpdateError(f"the downloaded archive is unusable: {exc}") from exc
    entries = [name for name in os.listdir(dest)
               if os.path.isdir(os.path.join(dest, name))]
    if len(entries) != 1:
        raise UpdateError("the archive does not look like a source release")
    return os.path.join(dest, entries[0])


def _refuse_unsafe_members(tar: tarfile.TarFile, dest: str) -> None:
    """Reject an archive that reaches outside ``dest`` — never sanitise it.

    Absolute paths, ``..``, links pointing out of the tree, and anything that is
    not a plain file or directory are all grounds for refusal. Quietly rewriting
    such a member would hide the fact that the release is not what it claims."""
    root = os.path.realpath(dest)
    for member in tar.getmembers():
        if member.name.startswith("/") or os.path.isabs(member.name):
            raise UpdateError("the archive contains an absolute path")
        target = os.path.realpath(os.path.join(root, member.name))
        if target != root and not target.startswith(root + os.sep):
            raise UpdateError("the archive tries to write outside its directory")
        if member.issym() or member.islnk():
            link = os.path.realpath(
                os.path.join(os.path.dirname(target), member.linkname))
            if not link.startswith(root + os.sep):
                raise UpdateError("the archive contains a link out of the tree")
        elif not (member.isfile() or member.isdir()):
            raise UpdateError("the archive contains a special file")


def _verify_tree(path: str) -> None:
    missing = [entry for entry in REQUIRED_ENTRIES
               if not os.path.exists(os.path.join(path, entry))]
    if missing:
        raise UpdateError("the downloaded release is missing "
                          + ", ".join(missing))


def _swap_tree(source: str, root: str) -> str:
    """Put ``source`` in place of the installed tree, and return the backup dir.

    The previous tree is moved aside, not deleted, and restored if the swap
    fails part-way — a half-replaced install is the one outcome worth ruling
    out. Shared by every way of obtaining a release, so the recovery path is
    written once: a second, weaker swap is how one route ends up less solid
    than the other."""
    backup = os.path.join(root, _BACKUP_DIR)
    shutil.rmtree(backup, ignore_errors=True)
    os.makedirs(backup, exist_ok=True)
    moved: list[str] = []
    try:
        for entry in REPLACE_ENTRIES:
            incoming = os.path.join(source, entry)
            if not os.path.exists(incoming):
                continue
            current = os.path.join(root, entry)
            if os.path.exists(current):
                shutil.move(current, os.path.join(backup, entry))
                moved.append(entry)
            if os.path.isdir(incoming):
                shutil.copytree(incoming, current, symlinks=True)
            else:
                shutil.copy2(incoming, current)
    except Exception as exc:
        # Put back exactly what we took, so a failed update leaves the node
        # running the version it was running before.
        for entry in moved:
            target = os.path.join(root, entry)
            if os.path.isdir(target):
                shutil.rmtree(target, ignore_errors=True)
            elif os.path.exists(target):
                os.unlink(target)
            shutil.move(os.path.join(backup, entry), target)
        raise UpdateError(f"could not replace the tree: {exc}") from exc

    for script in ("start.sh", "install.sh"):
        path = os.path.join(root, script)
        if os.path.exists(path):
            os.chmod(path, 0o755)
    return backup


def apply_sync(tag: str, *, root: str | None = None) -> dict:
    """Download ``tag`` and put it in place. Returns what happened."""
    root = root or install_root()
    ok, reason = updatable()
    if not ok:
        raise UpdateError(reason)

    archive = _download(tag)
    stage = os.path.join(root, _STAGE_DIR)
    shutil.rmtree(stage, ignore_errors=True)
    try:
        source = _extract(archive, stage)
        _verify_tree(source)
        backup = _swap_tree(source, root)
    finally:
        shutil.rmtree(stage, ignore_errors=True)

    return {
        "applied": tag,
        "previous": __version__,
        "root": root,
        "backup": backup,
        "restart_required": True,
        "service_managed": service_managed(),
    }


def apply_files_sync(files: dict, version: str, *,
                     root: str | None = None) -> dict:
    """Put an already-verified set of files in place of the installed tree.

    This is the mesh path (see :mod:`src.core_release`): the caller has fetched
    a content-addressed package and checked every byte of it against a signed
    root, so there is nothing to download and nothing left to trust here. What
    remains is still ours to check — the paths, which decide *where* those bytes
    land, and the shape of the tree they make."""
    root = root or install_root()
    ok, reason = updatable()
    if not ok:
        raise UpdateError(reason)
    if not files:
        raise UpdateError("the release is empty")

    stage = os.path.join(root, _STAGE_DIR)
    shutil.rmtree(stage, ignore_errors=True)
    source = os.path.join(stage, "tree")
    try:
        os.makedirs(source, exist_ok=True)
        for path, content in files.items():
            safe = safe_relative(path)
            if safe is None:
                # Refused, not sanitised: a package reaching outside its own
                # tree is not a release with one bad path in it.
                raise UpdateError(f"the release contains an unusable path: {path!r}")
            dest = os.path.join(source, safe)
            os.makedirs(os.path.dirname(dest) or source, exist_ok=True)
            with open(dest, "wb") as handle:
                handle.write(content)
        _verify_tree(source)
        backup = _swap_tree(source, root)
    finally:
        shutil.rmtree(stage, ignore_errors=True)

    return {
        "applied": version,
        "previous": __version__,
        "root": root,
        "backup": backup,
        "restart_required": True,
        "service_managed": service_managed(),
    }


def safe_relative(path) -> str | None:
    """A relative path with no absolute root, no ``..`` escape, no NUL — or
    ``None``. The one gate between a package's own idea of where its files go
    and this machine's filesystem."""
    if not isinstance(path, str) or not path or "\x00" in path:
        return None
    norm = os.path.normpath(path.replace("\\", "/"))
    if os.path.isabs(norm) or norm.startswith("..") or norm == ".":
        return None
    parts = norm.split(os.sep)
    if ".." in parts or not all(parts):
        return None
    return norm


async def apply(tag: str, *, root: str | None = None) -> dict:
    """Install release ``tag``. The caller is responsible for having asked."""
    return await _bounded(lambda: apply_sync(tag, root=root),
                          DOWNLOAD_TIMEOUT + 60)


async def apply_files(files: dict, version: str, *,
                      root: str | None = None) -> dict:
    """Install verified files. The caller is responsible for having verified
    them — this only puts them in place."""
    return await _bounded(lambda: apply_files_sync(files, version, root=root),
                          300.0, what="installing the release")
