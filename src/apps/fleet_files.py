"""
Files on a managed machine — list a directory, move a file either way.

This is the ``shell`` capability shown as a surface instead of a prompt. It
grants nothing new: an operator who can open a shell as the node's user can
already `ls`, `cat` and `tee` anything that user can reach. What it adds is a
way to do it from a phone, where typing `scp` is not an option and a terminal is
the wrong tool for "put this file over there".

So the authority is the node's own account, exactly as the shell has it, and
this module is deliberately thin: no root, no escalation, no path magic. What it
*does* own is the bounds, because unlike a shell every call here comes off the
mesh as a string somebody else chose:

  - a path is bounded, NUL-free, and resolved before it is used;
  - a listing is capped and says how much it left out, rather than trying to
    serialise a directory with a million entries into one frame;
  - only **regular files and directories** are touched. Reading `/dev/zero`
    would be an unbounded read that never ends, and a fifo would block the
    handler that opened it — neither is a file transfer, so neither is offered;
  - an upload lands in a temporary file beside its target and is renamed into
    place only when it is complete: an interrupted transfer never half-replaces
    the file it was meant to update.

Nothing here executes anything. The one thing this module can do that a shell
cannot is *nothing extra*, which is the point.
"""
from __future__ import annotations

import os
import secrets
import stat
import time

MAX_PATH = 4096
MAX_NAME = 255
MAX_ENTRIES = 500                 # rows one listing returns
# How many names a listing will even look at before giving up on being complete.
# Sorting is what makes a listing readable, and sorting cannot start until every
# name is in memory — so a directory with a million files is counted, not read.
MAX_SCAN = 10_000
# One slice per frame. A DATA body is 56 KB and base64 costs a third, so a read
# slice is sized to fit with room to spare; a write also carries the signed
# assertion (~3.3 KB of ML-DSA), which is why it is smaller.
READ_SLICE = 32 * 1024
WRITE_SLICE = 24 * 1024
# A whole transfer, either way. Not a limit on what the machine holds — it is
# what one console request is allowed to hold in memory at once.
MAX_TRANSFER = 32 * 1024 * 1024
MAX_UPLOADS = 2                   # concurrent uploads one operator may hold
UPLOAD_IDLE = 300.0               # an abandoned upload is reaped


class FileError(Exception):
    """Anything that stops a file operation, phrased for the operator."""


def home() -> str:
    """Where a listing starts when nobody said. The node's own home if it has
    one, else wherever it is running: an operator opening the files view must
    land somewhere real rather than on an error."""
    for path in (os.path.expanduser("~"), os.getcwd(), "/"):
        try:
            if path and os.path.isdir(path):
                return os.path.realpath(path)
        except OSError:
            continue
    return "/"


def clean_path(raw) -> str:
    """A path from the network into one this machine can use.

    Empty means :func:`home` — the natural landing place, and the one answer a
    caller with nothing to say should get. Anything else must be absolute: a
    relative path would be resolved against a working directory the operator
    cannot see, which is a different file on every node."""
    if raw is None or raw == "":
        return home()
    if not isinstance(raw, str) or len(raw) > MAX_PATH or "\x00" in raw:
        raise FileError("that path cannot be used")
    path = os.path.expanduser(raw) if raw.startswith("~") else raw
    if not os.path.isabs(path):
        raise FileError("a path has to be absolute")
    return os.path.realpath(path)


def clean_name(raw) -> str:
    """One path *component* — a new directory's name, an uploaded file's name.

    Refused rather than sanitised: a name carrying a separator is not a name
    with a mistake in it, it is a caller trying to write somewhere else."""
    if not isinstance(raw, str) or not 0 < len(raw) <= MAX_NAME:
        raise FileError("that name cannot be used")
    if "\x00" in raw or "/" in raw or "\\" in raw or raw in (".", ".."):
        raise FileError("that name cannot be used")
    return raw


def _kind(entry_stat) -> str:
    if stat.S_ISDIR(entry_stat.st_mode):
        return "dir"
    if stat.S_ISREG(entry_stat.st_mode):
        return "file"
    return "other"


def listing(path: str) -> dict:
    """One directory, as rows a page can draw.

    Per-entry failures are absorbed: a dangling symlink or a directory whose
    permissions changed between the scan and the stat must not take the whole
    listing down with it — the row simply says what little is known."""
    if not os.path.isdir(path):
        raise FileError(f"{path} is not a directory")
    names, truncated = [], 0
    try:
        with os.scandir(path) as scan:
            for item in scan:
                if len(names) >= MAX_SCAN:
                    truncated += 1
                    continue
                names.append(item)
    except PermissionError:
        raise FileError("permission denied") from None
    except OSError as exc:
        raise FileError(f"cannot read that directory ({exc.strerror or exc})") from None
    names.sort(key=lambda item: item.name.lower())
    entries = []
    for item in names:
        if len(entries) >= MAX_ENTRIES:
            truncated += 1
            continue
        row = {"name": item.name, "kind": "other", "size": 0, "mtime": 0,
               "link": False}
        try:
            row["link"] = item.is_symlink()
            info = item.stat()          # follows the link, like opening it would
            row["kind"] = _kind(info)
            row["size"] = int(info.st_size)
            row["mtime"] = int(info.st_mtime)
        except OSError:
            pass                        # a row we cannot describe is still a row
        entries.append(row)
    # Directories first, then names: the order somebody navigating expects, and
    # decided here rather than in the page so every front end agrees.
    entries.sort(key=lambda row: (row["kind"] != "dir", row["name"].lower()))
    parent = os.path.dirname(path.rstrip("/")) or "/"
    return {"path": path, "parent": parent if path != "/" else "",
            "entries": entries, "truncated": truncated,
            "writable": os.access(path, os.W_OK)}


def stat_file(path: str) -> dict:
    """What a download is about to move, before a byte of it is asked for."""
    try:
        info = os.stat(path)
    except FileNotFoundError:
        raise FileError("no such file") from None
    except PermissionError:
        raise FileError("permission denied") from None
    except OSError as exc:
        raise FileError(f"cannot read that file ({exc.strerror or exc})") from None
    if not stat.S_ISREG(info.st_mode):
        # A directory, a device, a socket, a fifo: none of them is a file to
        # move, and two of them would hang or never end if read.
        raise FileError("only a regular file can be transferred")
    return {"path": path, "name": os.path.basename(path) or "file",
            "size": int(info.st_size), "mtime": int(info.st_mtime)}


def read_slice(path: str, offset: int, length: int) -> tuple[bytes, bool, dict]:
    """``(bytes, eof, info)`` at ``offset``. The caller walks the file itself.

    Offsets rather than a stream because the operator is on the other side of a
    mesh: a slice that goes missing is re-asked for, not a transfer restarted.
    The file's own description comes back with the slice because the caller
    needs it — its size, to know what it is fetching — and stat'ing it twice per
    slice is a thousand wasted syscalls over a large file."""
    if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0:
        raise FileError("bad offset")
    length = max(1, min(int(length or READ_SLICE), READ_SLICE))
    info = stat_file(path)
    if offset > info["size"]:
        raise FileError("offset past the end of the file")
    try:
        handle = os.open(path, os.O_RDONLY)
    except OSError as exc:
        raise FileError(f"cannot open that file ({exc.strerror or exc})") from None
    try:
        data = os.pread(handle, length, offset)
    except OSError as exc:
        raise FileError(f"cannot read that file ({exc.strerror or exc})") from None
    finally:
        os.close(handle)
    return data, offset + len(data) >= info["size"], info


def make_dir(parent: str, name: str) -> str:
    """Create one directory inside ``parent``. Returns its path."""
    name = clean_name(name)
    if not os.path.isdir(parent):
        raise FileError(f"{parent} is not a directory")
    path = os.path.join(parent, name)
    try:
        os.mkdir(path, 0o755)
    except FileExistsError:
        raise FileError("something with that name is already there") from None
    except PermissionError:
        raise FileError("permission denied") from None
    except OSError as exc:
        raise FileError(f"cannot create that directory ({exc.strerror or exc})") from None
    return path


class Upload:
    """A file arriving in slices, held in a temporary file until it is whole.

    The temporary lives **beside** the target, not in ``/tmp``: the rename that
    puts it in place has to be on the same filesystem, or the last step of every
    upload becomes a copy that can itself fail half way.

    Offsets are checked, never trusted: slices arrive in order or the upload is
    abandoned. Out-of-order writes into a file being assembled is how a
    truncated download ends up looking like a complete one."""

    __slots__ = ("path", "temp", "handle", "written", "started", "last_active")

    def __init__(self, directory: str, name: str) -> None:
        name = clean_name(name)
        if not os.path.isdir(directory):
            raise FileError(f"{directory} is not a directory")
        self.path = os.path.join(directory, name)
        self.temp = os.path.join(directory,
                                 f".{name[:80]}.nmesh-part-{secrets.token_hex(6)}")
        try:
            self.handle = os.open(self.temp,
                                  os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except PermissionError:
            raise FileError("permission denied") from None
        except OSError as exc:
            raise FileError(f"cannot write there ({exc.strerror or exc})") from None
        self.written = 0
        self.started = time.monotonic()
        self.last_active = self.started

    def write(self, offset: int, data: bytes) -> int:
        if offset != self.written:
            self.abort()
            raise FileError("that slice does not follow the last one")
        if self.written + len(data) > MAX_TRANSFER:
            self.abort()
            raise FileError("that file is too large to transfer this way")
        try:
            os.write(self.handle, data)
        except OSError as exc:
            self.abort()
            raise FileError(f"cannot write there ({exc.strerror or exc})") from None
        self.written += len(data)
        self.last_active = time.monotonic()
        return self.written

    def finish(self) -> dict:
        """Put the assembled file in place, replacing what was there."""
        try:
            os.close(self.handle)
        except OSError:
            pass
        try:
            os.chmod(self.temp, 0o644)
            os.replace(self.temp, self.path)
        except OSError as exc:
            self.abort()
            raise FileError(f"cannot put the file in place "
                            f"({exc.strerror or exc})") from None
        return {"path": self.path, "name": os.path.basename(self.path),
                "size": self.written}

    def abort(self) -> None:
        try:
            os.close(self.handle)
        except OSError:
            pass
        try:
            os.unlink(self.temp)
        except OSError:
            pass
