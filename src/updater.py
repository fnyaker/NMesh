"""
Self-update — check GitHub for a newer release, and install it if asked.

Two halves, deliberately separate:

  - **check** is read-only and safe to run whenever. It asks the GitHub API for
    the latest release and compares its tag to :data:`src.version.__version__`.
    An operator who does not want to wait for a release can name a branch
    instead (``update_branch`` in the configuration, or ``NMESH_UPDATE_BRANCH``):
    the answer then comes from the ``__version__`` declared in ``src/version.py``
    at that branch, and installing takes the branch's tree. That file is read,
    never executed — it arrives from the network like anything else.
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
    version, and a branch (which moves) is refused if it no longer carries the
    version that was confirmed;
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
import re
import shutil
import sys
import tarfile
import threading
import time
import urllib.error
import urllib.request

from . import config
from .version import __version__, is_newer, parse as parse_version

DEFAULT_REPO = "fnyaker/NMesh"
API_TIMEOUT = 15.0
DOWNLOAD_TIMEOUT = 300.0
MAX_API_BYTES = 1 * 1024 * 1024
MAX_SOURCE_BYTES = 256 * 1024
MAX_DOWNLOAD_BYTES = 64 * 1024 * 1024
MAX_NOTES = 8000
_USER_AGENT = f"nmesh/{__version__}"
UPDATE_BRANCH_ENV = "NMESH_UPDATE_BRANCH"

# The one line wanted out of a `version.py`, wherever that file comes from.
_VERSION_LINE = re.compile(rb"""^__version__\s*=\s*['"]([^'"\n]{1,64})['"]""",
                           re.MULTILINE)
# What such a line is allowed to say. Everything else is refused rather than
# trimmed: this value is displayed, and comes back in the install request.
_VERSION_TEXT = re.compile(r"[A-Za-z0-9.+-]{1,64}")

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


def update_branch(config_path=None) -> str:
    """The branch this node follows, or ``""`` when it follows releases.

    ``NMESH_UPDATE_BRANCH`` wins over the file, the way a command-line flag wins
    everywhere else in the project. A name the configuration would refuse counts
    as not set: a half-valid ref is how a URL ends up asking somewhere nobody
    chose, and falling back to the published releases is the safe reading."""
    env = os.environ.get(UPDATE_BRANCH_ENV)
    if env is not None:
        return _validated_branch(env)
    path = config_path or config.path_for(install_root())
    values, _problems = config.load(path)
    return _validated_branch(values.get("update_branch", ""))


def _validated_branch(raw) -> str:
    # Validated by the configuration module rather than again here: one
    # definition of what a usable branch name is, whichever way it arrived.
    try:
        return config.validate("update_branch", raw)
    except Exception:
        return ""


def install_root() -> str:
    """The directory holding the running tree (the parent of ``src``)."""
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def service_managed() -> bool:
    """True when something will restart us if we exit.

    ``install.sh`` sets this in every unit it writes, next to ``Restart=always``
    / ``KeepAlive``. It is what the console checks before leaving to come back
    on freshly installed code: without it, exiting would simply stop the node —
    a worse outcome than running the previous version — so it stays up and says
    so instead."""
    return os.environ.get("NMESH_SERVICE_MANAGED") == "1"


# How this process came into the world, captured **before** anything can chdir
# or rewrite ``sys.argv``. A restart re-runs exactly this, so it has to be the
# launch as it happened, not as the process looks by the time somebody asks.
_LAUNCH = (sys.executable, list(sys.argv), os.getcwd())

# Restart routes, most preferred first. ``service`` is exiting and letting the
# supervisor bring us back; ``reexec`` is replacing this process image with a
# fresh interpreter on the same command line.
RESTART_SERVICE = "service"
RESTART_REEXEC = "reexec"


def restart_plan() -> tuple[str, tuple, str]:
    """How this node can come back on freshly installed code.

    ``(mode, launch, reason)`` — ``mode`` is one of the two constants above, or
    ``""`` when there is no way back and the reason says why.

    **A supervisor is preferred whenever there is one.** Exiting is the clean
    route: the whole process image goes, along with any file descriptor, thread
    or C library state an update may have invalidated, and something whose job
    is to start us does the starting.

    **Re-exec is the fallback, and it is what Android needed.** Termux has no
    init a package can reach; without ``termux-services`` a node installs an
    update and then sits on it until somebody reopens the app and types the
    command again. ``os.execv`` is not an exit — it replaces this process with a
    fresh interpreter reading the tree that was just written, keeping the pid,
    the session and the terminal. Nothing outside has to cooperate.

    Every descriptor Python opens is close-on-exec (PEP 446), so the listening
    sockets are gone by the time the new image binds them; the caller still
    stops the node first, because a peer deserves a closed link rather than a
    reset one."""
    executable, argv, cwd = _LAUNCH
    if service_managed():
        return RESTART_SERVICE, (executable, argv, cwd), ""
    if not executable or not os.path.isfile(executable):
        return "", (), "this process has no interpreter to start again"
    if not argv or not argv[0]:
        return "", (), "this process does not know how it was started"
    # ``python -m package`` leaves ``argv[0]`` as the module's ``__main__``
    # path, which exists; a zipapp or a frozen build may leave something that
    # is not a file at all, and re-running it would land nowhere.
    entry = argv[0]
    if not os.path.isabs(entry):
        entry = os.path.join(cwd, entry)
    if not os.path.exists(entry):
        return "", (), f"the script this node was started from is gone ({argv[0]})"
    if not os.path.isdir(cwd):
        return "", (), "the directory this node was started in is gone"
    return RESTART_REEXEC, (executable, argv, cwd), ""


def restart_possible() -> tuple[bool, str]:
    """Can this node come back if it leaves? ``(ok, reason_if_not)``."""
    mode, _launch, reason = restart_plan()
    return bool(mode), reason


def reexec() -> None:
    """Replace this process with a fresh one on the same command line.

    Never returns when it works. The caller has already stopped the node: this
    is the last thing the old image does."""
    _mode, launch, _reason = restart_plan()
    if not launch:
        raise OSError("nothing to re-exec")
    executable, argv, cwd = launch
    os.chdir(cwd)
    os.execv(executable, [executable] + list(argv))


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


def _source_version(branch: str) -> str:
    """The version ``src/version.py`` declares at ``branch``.

    Read with a regular expression, never executed: this is a file fetched from
    the network, and the only thing wanted out of it is one string. A value that
    does not parse as a version is an error rather than a candidate — something
    unreadable must never come out looking newer than what is running."""
    url = f"https://raw.githubusercontent.com/{repo()}/{branch}/src/version.py"
    try:
        raw = _fetch(url, timeout=API_TIMEOUT, max_bytes=MAX_SOURCE_BYTES,
                     accept="text/plain")
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            raise UpdateError(f"{repo()} has no src/version.py on "
                              f"{branch}") from exc
        raise UpdateError(f"GitHub answered {exc.code}") from exc
    except (urllib.error.URLError, OSError) as exc:
        raise UpdateError("could not reach GitHub: "
                          f"{exc.reason if hasattr(exc, 'reason') else exc}") from exc
    match = _VERSION_LINE.search(raw)
    if match is None:
        raise UpdateError(f"no version is declared in src/version.py on {branch}")
    version = match.group(1).decode("utf-8", "replace")
    # Two gates, not one: `parse` keeps whatever follows the numbers as a
    # tie-break suffix, so it alone would accept a "version" carrying anything
    # at all — and this string is shown on a page and repeated in a request.
    if parse_version(version) is None or not _VERSION_TEXT.fullmatch(version):
        raise UpdateError(f"{branch} declares a version that cannot be read")
    return version


def _check_branch(branch: str) -> dict:
    """What a branch says the latest version is. Same shape as a release check,
    so nothing downstream has to know which of the two it is looking at."""
    latest = _source_version(branch)
    return {
        "current": __version__,
        "latest": latest,
        "available": is_newer(latest, __version__),
        "url": f"https://github.com/{repo()}/tree/{branch}",
        "published_at": "",
        "notes": "",
        "repo": repo(),
        "source": "branch",
        "branch": branch,
        "checked_at": time.time(),
    }


def check_sync(branch=None) -> dict:
    """Blocking check. Prefer :func:`check`."""
    branch = update_branch() if branch is None else _validated_branch(branch)
    if branch:
        return _check_branch(branch)
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
        "source": "release",
        "branch": "",
        "checked_at": time.time(),
    }


async def check(branch=None) -> dict:
    """Ask GitHub what the latest version is. Read-only; changes nothing.

    ``branch`` is the caller's answer to "which branch does *this* node follow?"
    — the console knows its own configuration file, and reading a different one
    here would answer for a node nobody is looking at. ``None`` means work it
    out from the environment and the default file."""
    return await _bounded(lambda: check_sync(branch), API_TIMEOUT + 5)


# ---------------------------------------------------------------------------
# Apply
# ---------------------------------------------------------------------------

def _codeload(ref: str, what: str) -> bytes:
    url = f"https://codeload.github.com/{repo()}/tar.gz/{ref}"
    try:
        return _fetch(url, timeout=DOWNLOAD_TIMEOUT,
                      max_bytes=MAX_DOWNLOAD_BYTES,
                      accept="application/octet-stream")
    except urllib.error.HTTPError as exc:
        raise UpdateError(f"could not download {what}: GitHub answered "
                          f"{exc.code}") from exc
    except (urllib.error.URLError, OSError) as exc:
        raise UpdateError(f"could not download {what}: {exc}") from exc


def _download(tag: str) -> bytes:
    return _codeload(f"refs/tags/{tag}", tag)


def _download_branch(branch: str) -> bytes:
    return _codeload(f"refs/heads/{branch}", f"branch {branch}")


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


def _tree_version(path: str, expected: str) -> None:
    """Refuse a tree that no longer carries the version somebody confirmed.

    A tag names one commit for good, so downloading it is the whole check. A
    branch is whatever was pushed to it last, and between the check an operator
    read and the click that follows, that can be something else entirely —
    installing it would put code on the machine nobody looked at."""
    try:
        with open(os.path.join(path, "src", "version.py"), "rb") as handle:
            raw = handle.read(MAX_SOURCE_BYTES)
    except OSError as exc:
        raise UpdateError("the downloaded tree declares no version") from exc
    match = _VERSION_LINE.search(raw)
    found = match.group(1).decode("utf-8", "replace") if match else ""
    if found != expected:
        raise UpdateError(f"the branch now carries {found or 'no version'}, "
                          f"not {expected} — check again and re-confirm")


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
    _precompile(root)
    return backup


def _precompile(root: str) -> None:
    """Write the bytecode now rather than on the next start.

    A node that has just replaced its tree starts with an empty `__pycache__`,
    so the first run after every update compiles the whole of `src/` before it
    can listen — measured at about a hundred milliseconds, which is roughly the
    entire startup cost paid a second time, on the one start an operator is
    most likely to be watching. Doing it here spends the same time while the
    node is already stopped, and every later start reads the cache.

    Never fatal: a read-only tree, a stale `.pyc`, a Python that refuses — none
    of it stops the update. The node simply compiles on the way up, as it did
    before."""
    try:
        import compileall
        compileall.compile_dir(os.path.join(root, "src"), quiet=2, force=False)
    except Exception:
        pass


def apply_sync(tag: str, *, root: str | None = None, branch=None) -> dict:
    """Download the confirmed version and put it in place. Returns what happened.

    ``tag`` is what the operator confirmed: a release tag, or — when this node
    follows a branch — the version that branch declared when it was checked.
    Either way nothing else installs: a branch whose ``version.py`` has moved
    since is refused, not installed under the name that was on screen."""
    root = root or install_root()
    ok, reason = updatable()
    if not ok:
        raise UpdateError(reason)

    branch = update_branch() if branch is None else _validated_branch(branch)
    archive = _download_branch(branch) if branch else _download(tag)
    stage = os.path.join(root, _STAGE_DIR)
    shutil.rmtree(stage, ignore_errors=True)
    try:
        source = _extract(archive, stage)
        _verify_tree(source)
        if branch:
            _tree_version(source, tag)
        backup = _swap_tree(source, root)
    finally:
        shutil.rmtree(stage, ignore_errors=True)

    return {
        "applied": tag,
        "previous": __version__,
        "root": root,
        "backup": backup,
        "restart_required": True,
        "can_restart": restart_possible()[0],
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
        "can_restart": restart_possible()[0],
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


async def apply(tag: str, *, root: str | None = None, branch=None) -> dict:
    """Install the version ``tag`` names. The caller is responsible for having
    asked, and for saying which branch this node follows (see :func:`check`)."""
    return await _bounded(lambda: apply_sync(tag, root=root, branch=branch),
                          DOWNLOAD_TIMEOUT + 60)


async def apply_files(files: dict, version: str, *,
                      root: str | None = None) -> dict:
    """Install verified files. The caller is responsible for having verified
    them — this only puts them in place."""
    return await _bounded(lambda: apply_files_sync(files, version, root=root),
                          300.0, what="installing the release")
