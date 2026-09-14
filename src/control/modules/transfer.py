"""
The ``transfer`` module: what bytes this node will carry, and for what.

Six operations, and a table of **kinds**. The operations are the carrier and
know nothing about what they carry; a kind names one thing bytes can be *for*,
and carries its own reach and its own ceiling — because "may this console send
bytes" was never the question. Publishing an app is the question, and a kind is
where that is answered.

``transfer.kinds``
    What this console may carry, filtered by who is asking, so a page draws a
    download button only where there is one to press.

``transfer.fetch`` → ``transfer.take``
    Bytes **down**. The kind produces them, the book holds them, and each call
    takes one chunk out of a reply.

``transfer.offer`` → ``transfer.put`` → ``transfer.commit``
    Bytes **up**. Each chunk is one request, and committing hands the finished
    set to whatever the kind is for.

Both ends are just operations, so both follow the channel: the same page driving
another node moves the same bytes to and from *that* machine, with nothing
rewritten and no second door. The bounds are in :mod:`src.control.transfer`,
next to the book that enforces them.

``fetch`` and ``commit`` are the two that do real work — a package comes off the
directory, an app is signed and announced — so they declare the ceiling that
work needs and travel as **jobs**. The two mechanisms compose exactly as they
should: nothing here had to learn what a job is, and neither did any page.
"""
from __future__ import annotations

from ..errors import ControlError
from ..params import param
from ..plane import operation
from ..transfer import DOWN, UP, UP_CHUNK_B64, TransferBook

# Both directions of the book are answers about memory this process already
# holds, so the moving operations are the cheapest thing in the plane. The two
# that reach the node take what the node takes.
_QUICK = 5.0
_WORK = 60.0             # a directory fetch, or signing and announcing a tree

# What one kind may carry, end to end. The app figure is the console's own
# `_MAX_APP_BODY` said once more where the bytes actually arrive — the console's
# cap is on an HTTP body and stops applying the moment the bytes come through a
# frame instead.
MAX_APP = 4 * 1024 * 1024
MAX_PACKAGE = 8 * 1024 * 1024


def kind(name: str, summary: str, *, way: str, reach: str, limit: int) -> dict:
    """Declare one thing bytes can be for.

    ``reach`` is the same vocabulary an operation uses, and it is the *kind*
    that carries it rather than the operation: ``transfer.put`` is the same call
    whatever it is carrying, and what is being sent is what decides whether it
    may be."""
    return {"name": name, "summary": summary, "way": way, "reach": reach,
            "limit": int(limit)}


class TransferModule:
    """Bytes, on the channel the rest of the console already speaks."""

    NAME = "transfer"

    KINDS = (
        kind("package", "One signed package, as bytes, to read before trusting",
             way=DOWN, reach="remote", limit=MAX_PACKAGE),
        kind("app", "An app's files, published from this node onto the mesh",
             way=UP, reach="govern", limit=MAX_APP),
        kind("release", "An app's files, published to the store as a release",
             way=UP, reach="govern", limit=MAX_APP),
    )

    OPERATIONS = (
        operation("kinds", "What bytes this console may move, and which way",
                  remote=True, timeout=_QUICK, wants_origin=True),
        operation("fetch", "Start reading something out of this node",
                  [param("kind", "choice",
                         choices=tuple(entry["name"] for entry in KINDS)),
                   param("id", "line")],
                  remote=True, background=True, timeout=_WORK,
                  wants_origin=True),
        operation("take", "One chunk out",
                  [param("transfer", "line"), param("path", "line"),
                   param("seq", "count", required=False, default=0)],
                  remote=True, timeout=_QUICK, wants_origin=True),
        operation("offer", "Start sending something to this node",
                  [param("kind", "choice",
                         choices=tuple(entry["name"] for entry in KINDS)),
                   param("meta", "document", required=False, default=None)],
                  changes=True, remote=True, timeout=_QUICK, wants_origin=True),
        operation("put", "One chunk in",
                  [param("transfer", "line"), param("path", "line"),
                   param("seq", "count", required=False, default=0),
                   param("data", "blob", limit=UP_CHUNK_B64)],
                  changes=True, remote=True, timeout=_QUICK, wants_origin=True),
        operation("commit", "Hand what was sent to whatever it was for",
                  [param("transfer", "line")],
                  changes=True, remote=True, background=True, timeout=_WORK,
                  wants_origin=True),
        operation("drop", "Forget a transfer without finishing it",
                  [param("transfer", "line")],
                  changes=True, remote=True, timeout=_QUICK, wants_origin=True),
    )

    def __init__(self, context) -> None:
        self._context = context
        self._book = TransferBook()
        # Named handlers, looked up by a name a *kind* wrote down and never by
        # one a caller supplied — the plane's own rule, one layer in.
        self._readers = {"package": self._read_package}
        self._writers = {"app": self._write_app,
                         "release": self._write_release}

    # -- what exists ------------------------------------------------------

    def op_kinds(self, origin) -> dict:
        from ..plane import REACHED_BY
        allowed = REACHED_BY.get(origin, ())
        return {"kinds": [dict(entry) for entry in self.KINDS
                          if entry["reach"] in allowed]}

    def _kind(self, name: str, origin: str, way: str) -> dict:
        from ..plane import REACHED_BY
        for entry in self.KINDS:
            if entry["name"] != name:
                continue
            if entry["reach"] not in REACHED_BY.get(origin, ()):
                raise ControlError(
                    "refused", f"{name} needs the govern capability"
                    if entry["reach"] == "govern"
                    else f"{name} cannot be moved from a remote console")
            if entry["way"] != way:
                raise ControlError("bad_request",
                                   f"{name} does not travel that way")
            return entry
        raise ControlError("not_found", "no such kind")

    # -- down -------------------------------------------------------------

    def op_fetch(self, kind, id, origin) -> dict:
        entry = self._kind(kind, origin, DOWN)
        meta, files = self._readers[entry["name"]](id)
        return self._book.fetch(entry, meta, files, origin)

    def op_take(self, transfer, path, seq, origin) -> dict:
        return self._book.take(transfer, path, int(seq), origin)

    def _read_package(self, record: str) -> tuple:
        """The bytes of one signed package, every one of them checked against a
        hash its author signed — which is what makes handing them to somebody
        to open by hand a reasonable thing to offer."""
        node = self._context.node
        fetched = self._context.ask(node.fetch_package(record), _WORK)
        if fetched is None:
            raise ControlError("not_found", "no such package")
        _entry, blob, name = fetched
        safe = str(name or "package").rsplit("/", 1)[-1] or "package"
        return {"name": safe, "record": record}, {safe: blob}

    # -- up ---------------------------------------------------------------

    def op_offer(self, kind, meta, origin) -> dict:
        entry = self._kind(kind, origin, UP)
        return self._book.offer(entry, meta or {}, origin)

    def op_put(self, transfer, path, seq, data, origin) -> dict:
        return self._book.put(transfer, path, int(seq), data, origin)

    def op_commit(self, transfer, origin) -> dict:
        entry, meta, files = self._book.collect(transfer, origin)
        # Checked again, on the way out: the grant that let this transfer open
        # can have been taken back while it was filling, and the moment that
        # matters is the one where the bytes are acted on.
        self._kind(entry["name"], origin, UP)
        return self._writers[entry["name"]](meta, files)

    def op_drop(self, transfer, origin) -> dict:
        return self._book.drop(transfer, origin)

    def _write_app(self, meta: dict, files: dict) -> dict:
        name, version = self._named(meta)
        app_id = self._context.ask(
            self._context.node.publish_app(name, version, files), _WORK)
        return {"app_id": app_id.hex() if isinstance(app_id, bytes) else app_id,
                "files": len(files)}

    def _write_release(self, meta: dict, files: dict) -> dict:
        name, version = self._named(meta)
        notes = meta.get("notes")
        info = self._context.ask(
            self._context.node.publish_store_app(
                name, version, files,
                notes=notes if isinstance(notes, str) else ""), _WORK)
        return {"ok": True, **(info if isinstance(info, dict) else {})}

    @staticmethod
    def _named(meta: dict) -> tuple:
        name = meta.get("name")
        version = meta.get("version") or "1.0.0"
        if not isinstance(name, str) or not name.strip():
            raise ControlError("bad_request", "a name is required")
        if not isinstance(version, str) or not version.strip():
            raise ControlError("bad_request", "a version is required")
        return name.strip(), version.strip()
