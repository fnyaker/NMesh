"""
Files, on the same channel as everything else.

The console's byte-carrying routes were the last thing that did not follow the
context. A page driving another node relayed every *call* to it, but a download
was an ``<a href download>`` — a browser navigation, which cannot carry the
header that says which node is being driven — so it fetched from the machine
serving the page, silently, whichever machine the operator thought they were
looking at. And an upload could not have gone the other way anyway: the relay
caps a request at ``fleet.CONSOLE_REQ_MAX``, 24 kB, and an app is four
megabytes. Two different failures of one idea, which is that bytes are special.

They are not. **A file is a question and an answer, asked more than once.**

A transfer is a *named set of byte streams* — one for a package, several for an
app's tree — carried a chunk per frame, in whichever direction the kind says.
Uploading is ``offer`` then ``put`` per chunk then ``commit``; downloading is
``fetch`` then ``take`` per chunk. Both are ordinary operations on the plane, so
both follow the channel: the same page, driving another node, moves the same
bytes to and from *that* machine with nothing rewritten and no second door.

What a transfer is *for* is a **kind**, and a kind is declared next to the code
that consumes the bytes — with its own reach and its own ceiling. That is the
whole of the permission model here, and it is deliberate: "may this console send
bytes" is not a question worth answering, because bytes are never the point.
Publishing an app is the point, and it is that which is allowed or refused.

The bounds, all of them here rather than spread over the callers:

* a chunk going up fits a frame with its envelope around it, and one coming
  down fits a reply;
* how many transfers may be open at once, and how few of those a console at a
  distance may hold;
* how many bytes every open transfer may hold *together*, which is the one that
  matters — a peer opening the maximum number of maximum-sized transfers must
  not be a way to spend this node's memory;
* a chunk that must be the *next* one — counted, never derived from the length
  so far, because a short chunk leaves that quotient where it was and the same
  sequence number would stay acceptable for ever — with no gap, no rewrite, and
  nothing at all after the short chunk that ends a file;
* and an idle transfer is dropped, because a peer that opens one and says
  nothing more must not hold anything for longer than it takes to notice.
"""
from __future__ import annotations

import secrets
import threading
import time

from .errors import ControlError
from .plane import Origin

# One chunk on the way **up** travels as a parameter inside a request frame, so
# it has to fit `frame.MAX_FRAME` (24 kB) once base64 has made it a third
# bigger, with the operation name, the ticket and the path still to fit beside
# it. 12 kB of bytes is 16 kB of base64 and leaves the envelope room it will
# never need all of.
UP_CHUNK = 12 * 1024
UP_CHUNK_B64 = (UP_CHUNK + 2) // 3 * 4
# One chunk on the way **down** travels in a reply, which is twenty times the
# size (`frame.MAX_REPLY`, and `fleet.CONSOLE_RESP_MAX` behind it). 192 kB of
# bytes is 256 kB of base64: a package comes back in a handful of round trips
# rather than a hundred, and still inside half of what a reply may be.
DOWN_CHUNK = 192 * 1024

# How many transfers may be open at once, and how many of those a console at a
# distance may hold. As with jobs, the second figure is the one doing the work.
MAX_OPEN = 6
MAX_OPEN_REMOTE = 3
# Files in one transfer — an app's tree, not a disk.
MAX_FILES = 256
# What every open transfer may hold together. The ceiling that actually bounds
# this node's memory: a per-transfer limit multiplied by the number of open
# transfers is the number an attacker reads.
MAX_HELD = 16 * 1024 * 1024
# A transfer nobody has touched. Long enough for a slow link and a person
# choosing a file, short enough that abandoning one costs nothing for long.
IDLE = 180.0

UP = "up"
DOWN = "down"


def clean_path(raw) -> str:
    """A path inside a transfer, or a refusal.

    Refused rather than repaired, and refused *here* rather than by each kind:
    a path that climbs out of a tree is the oldest bug in the business, and a
    kind that has to remember to check for it is a kind that will forget."""
    if not isinstance(raw, str) or not raw:
        raise ControlError("bad_request", "a file needs a name")
    text = raw.replace("\\", "/").strip()
    if len(text) > 200:
        raise ControlError("bad_request", "that name is too long")
    if text.startswith("/") or ":" in text:
        raise ControlError("bad_request", "a name inside a transfer is relative")
    parts = [part for part in text.split("/") if part]
    if not parts or any(part in (".", "..") for part in parts):
        raise ControlError("bad_request", "that name climbs out of the transfer")
    if any("\x00" in part for part in parts):
        raise ControlError("bad_request", "that name holds a null byte")
    return "/".join(parts)


class TransferBook:
    """Every transfer this node has open, and what each one holds.

    Touched from the console's threads and from a job's, so everything here
    takes the lock. Holds bytes, which is why every method that adds any checks
    the total first — this class *is* the memory bound."""

    def __init__(self, *, clock=time.monotonic) -> None:
        self._clock = clock
        self._lock = threading.Lock()
        self._open: dict = {}

    # -- opening ----------------------------------------------------------

    def offer(self, kind: dict, meta: dict, origin: str) -> dict:
        """Start a transfer **up**: the caller is about to send files.

        It does not say *which*, and it does not promise a size. A declaration
        would only be a number to trust — the bound that matters is applied to
        every chunk as it arrives (:meth:`_room`), and a caller told "too large"
        at the first chunk over the line learns it just as early as one told at
        the offer, without anybody having believed anything."""
        with self._lock:
            self._prune()
            self._room(origin, 0)
            ident = self._enrol(kind, meta, origin, UP)
        return {"transfer": ident, "chunk": UP_CHUNK,
                "limit": int(kind["limit"])}

    def fetch(self, kind: dict, meta: dict, files, origin: str) -> dict:
        """Start a transfer **down**: ``files`` is what the kind produced."""
        wanted = []
        with self._lock:
            self._prune()
            total = sum(len(blob) for blob in files.values())
            self._room(origin, total)
            if total > int(kind["limit"]):
                raise ControlError("conflict",
                                   "that is larger than this node will carry")
            ident = self._enrol(kind, meta, origin, DOWN)
            entry = self._open[ident]
            entry["held"] = {clean_path(path): bytearray(blob)
                             for path, blob in files.items()}
            wanted = sorted((path, len(blob))
                            for path, blob in entry["held"].items())
        return {"transfer": ident, "chunk": DOWN_CHUNK, "meta": meta,
                "files": [{"path": path, "size": size} for path, size in wanted]}

    # -- moving -----------------------------------------------------------

    def put(self, ident: str, path: str, seq: int, data: bytes,
            origin: str) -> dict:
        """One chunk, at the one position it may go."""
        name = clean_path(path)
        with self._lock:
            entry = self._entry(ident, origin, UP)
            if name not in entry["held"]:
                if len(entry["held"]) >= MAX_FILES:
                    raise ControlError("conflict",
                                       "too many files in one transfer")
                entry["held"][name] = bytearray()
                entry["chunks"][name] = 0
            held = entry["held"][name]
            if name in entry["closed"]:
                # A short chunk ended this file. Anything after it is either a
                # mistake or the start of an append nobody asked for.
                raise ControlError("conflict", f"{name} is already complete")
            # The count is its own number, not `len(held) // UP_CHUNK`. Derived
            # from the length it says the right thing for every chunk but the
            # last: a short one leaves the quotient where it was, so the *same*
            # sequence number stayed acceptable for ever and a caller could
            # append to a file it had already finished — bytes through a
            # ceiling that had already counted them. Count the thing.
            if int(seq) != entry["chunks"][name]:
                raise ControlError("conflict",
                                   f"expected chunk {entry['chunks'][name]}")
            if len(data) > UP_CHUNK:
                raise ControlError("bad_request", "that chunk is too large")
            self._room(origin, len(data), adding_to=entry)
            held.extend(data)
            entry["chunks"][name] += 1
            if len(data) < UP_CHUNK:
                entry["closed"].add(name)
            entry["touched"] = self._clock()
            return {"path": name, "have": len(held),
                    "complete": name in entry["closed"],
                    "held": sum(len(blob) for blob in entry["held"].values())}

    def take(self, ident: str, path: str, seq: int, origin: str) -> dict:
        """One chunk out. The answer's own size is the bound on this."""
        name = clean_path(path)
        with self._lock:
            entry = self._entry(ident, origin, DOWN)
            held = entry["held"].get(name)
            if held is None:
                raise ControlError("not_found", "that file is not in this transfer")
            start = int(seq) * DOWN_CHUNK
            if start > len(held):
                raise ControlError("bad_request", "past the end of that file")
            entry["touched"] = self._clock()
            chunk = bytes(held[start:start + DOWN_CHUNK])
            return {"path": name, "seq": int(seq), "data": chunk,
                    "last": start + len(chunk) >= len(held)}

    # -- ending -----------------------------------------------------------

    def collect(self, ident: str, origin: str) -> tuple:
        """``(kind, meta, {path: bytes})`` for a finished upload, and forget it.

        The transfer is dropped **before** the kind is asked to do anything with
        it: whatever committing costs, it must not cost a ticket's worth of
        memory held open beside it."""
        with self._lock:
            entry = self._entry(ident, origin, UP)
            if not entry["held"]:
                raise ControlError("conflict", "nothing was sent")
            self._open.pop(ident, None)
        return (entry["kind"], entry["meta"],
                {path: bytes(blob) for path, blob in entry["held"].items()})

    def drop(self, ident: str, origin: str) -> dict:
        with self._lock:
            entry = self._open.get(ident)
            if entry is None or entry["origin"] != origin:
                raise ControlError("not_found", "no such transfer")
            self._open.pop(ident, None)
        return {"dropped": True}

    def listing(self, origin: str) -> dict:
        with self._lock:
            self._prune()
            return {"transfers": [
                {"transfer": entry["id"], "kind": entry["kind"]["name"],
                 "way": entry["way"],
                 "have": sum(len(blob) for blob in entry["held"].values())}
                for entry in self._open.values() if entry["origin"] == origin]}

    # -- the rules --------------------------------------------------------

    def _enrol(self, kind: dict, meta: dict, origin: str, way: str) -> str:
        if len(self._open) >= MAX_OPEN:
            raise ControlError("conflict", "too many transfers are open here")
        if origin != Origin.LOCAL and len([
                entry for entry in self._open.values()
                if entry["origin"] != Origin.LOCAL]) >= MAX_OPEN_REMOTE:
            raise ControlError("conflict", "as many transfers as a console at a "
                                           "distance may hold are already open")
        ident = secrets.token_hex(8)
        now = self._clock()
        self._open[ident] = {"id": ident, "kind": kind, "meta": meta,
                             "origin": origin, "way": way, "touched": now,
                             "held": {}, "chunks": {}, "closed": set()}
        return ident

    def _entry(self, ident: str, origin: str, way: str) -> dict:
        self._prune()
        entry = self._open.get(ident)
        # Not "that is not yours": a ticket somebody else's console holds is a
        # ticket that does not exist here, exactly as with a job.
        if entry is None or entry["origin"] != origin or entry["way"] != way:
            raise ControlError("not_found", "no such transfer")
        return entry

    def _room(self, origin: str, adding: int, adding_to=None) -> None:
        """Refuse before holding, never after. Under the lock, always."""
        held = sum(sum(len(blob) for blob in entry["held"].values())
                   for entry in self._open.values())
        if held + adding > MAX_HELD:
            raise ControlError(
                "conflict", "this node is already holding as many bytes in "
                            "transit as it will hold")
        if adding_to is not None:
            limit = int(adding_to["kind"]["limit"])
            current = sum(len(blob) for blob in adding_to["held"].values())
            if current + adding > limit:
                raise ControlError("conflict",
                                   "that is larger than this kind carries")

    def _prune(self) -> None:
        """Drop what nobody has touched. Called by everything that reads or
        writes the book, so there is no timer to leak: the book is tidied by
        being used, and a node nobody is managing does no work at all."""
        now = self._clock()
        for ident, entry in list(self._open.items()):
            if now - entry["touched"] > IDLE:
                self._open.pop(ident, None)
