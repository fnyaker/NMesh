"""
What the console sends a page, and how the two stay in step.

A page used to ask for its whole world on every read and replace what it held
with whatever came back. Three things were wrong with that, and all three show
up as the same symptom — **a page that suddenly has nothing on it**:

* **An error is not a state.** `apiJson` answers a 502 with a body like
  ``{"error": …}``, and a page that assigns it over what it holds has just
  replaced every list with nothing. The reload that "fixes" it is the operator
  doing by hand what the page should never have needed.
* **Everything, every time.** A ledger of forty machines is tens of kilobytes,
  re-encoded and re-sent because one job finished. On a mesh relay that is the
  whole of a console's cost.
* **No version between them.** A node that updates itself replaces the assets
  under an open page. The page then asks questions the new node no longer
  answers, gets refusals, and — see the first point — empties.

So a read carries three things this module owns: **who is speaking**
(`proto`, `build`), **what changed** (sections, by revision), and **what to do
when the two cannot agree** (say so; never hand back half an answer).

Sections, and why the revision is the content
---------------------------------------------
A payload is split into named sections — the machines, the groups, the jobs —
and a read says which revisions it already holds. Only the sections that moved
come back.

The revision is a **checksum of the section itself**, not a counter bumped at
every mutation. A counter has to be bumped from every place that writes, and the
one place that forgets is a section that silently stops updating — the worst
possible failure, because everything still works. Deriving it from the content
cannot go stale: if the bytes are the same, the revision is the same, and if
they are not, it is not.

Two versions at once
--------------------
`proto=1` is the flat snapshot every page before this sent and understood, and
it is still answered exactly as it was. `proto=2` is the sectioned one. A reader
asks for what it knows; a node answers what it was asked for. That is what lets
a page from before an update keep working against a node from after one, which
is the case this exists for.
"""
from __future__ import annotations

import json
import zlib

from .version import __version__

# The shape of what a page is sent. Bumped only when a reader that does not know
# the new shape would misread it — a *added* section is not a new version,
# because a reader that has never heard of it does not ask for it and does not
# get it.
PROTO = 2
MIN_PROTO = 1

# What a `have` parameter may be. One entry per section, and a section name is a
# name — this is a query string from a browser, and the bound is what stops it
# being a way to make the console parse a megabyte.
MAX_HAVE = 4096
MAX_SECTIONS = 64
MAX_NAME = 32


def revision(payload) -> str:
    """The revision of one section: a checksum of the section itself.

    Never a counter. A counter is bumped by whoever writes, and the one writer
    that forgets is a section that quietly stops updating — which looks like
    everything working. This cannot drift from what it describes, because it
    *is* what it describes."""
    try:
        # No `default=`: a section that is not JSON cannot be sent either, and
        # coercing it here would produce a revision from a repr — which carries
        # a memory address, changes every run, and would re-send that section on
        # every single read for ever.
        blob = json.dumps(payload, separators=(",", ":"),
                          sort_keys=True).encode("utf-8")
    except (TypeError, ValueError):
        return ""
    return format(zlib.crc32(blob) & 0xFFFFFFFF, "08x")


def parse_have(text) -> dict:
    """``"managed:1a2b3c4d,jobs:00ff00ff"`` → what the reader says it holds.

    Hostile input like anything else off the wire: bounded, and anything that is
    not a name and a revision is dropped rather than interpreted. A reader whose
    claim we cannot read simply gets everything, which is always correct and
    only ever slower."""
    if not isinstance(text, str) or not text or len(text) > MAX_HAVE:
        return {}
    out: dict = {}
    for entry in text.split(",")[:MAX_SECTIONS]:
        name, _, rev = entry.partition(":")
        name = name.strip()
        if not name or len(name) > MAX_NAME or not name.isidentifier():
            continue
        if len(rev) != 8 or not all(ch in "0123456789abcdef" for ch in rev.lower()):
            continue
        out[name] = rev.lower()
    return out


def clean_proto(value) -> int:
    """Which shape the reader asked for, brought inside what we answer."""
    try:
        wanted = int(value)
    except (TypeError, ValueError):
        return MIN_PROTO
    return max(MIN_PROTO, min(wanted, PROTO))


def build(sections: dict, *, have=None, proto: int = MIN_PROTO,
          extra: dict | None = None) -> dict:
    """One answer, in the shape the reader asked for.

    ``sections`` is the whole payload, split by name. ``extra`` is what does not
    belong to a section — the log slice, the sequence it ends at — and always
    travels, because it is already incremental and already small."""
    payload = dict(extra or {})
    payload["proto"] = min(max(proto, MIN_PROTO), PROTO)
    # Which build answered. A page served by one and answered by another is a
    # page whose assets were replaced under it; it can then reload once instead
    # of asking questions the new node no longer recognises.
    payload["build"] = __version__
    if payload["proto"] < 2:
        payload.update(sections)
        return payload
    held = parse_have(have) if isinstance(have, str) else (have or {})
    revs, changed = {}, {}
    for name, value in sections.items():
        rev = revision(value)
        revs[name] = rev
        if held.get(name) != rev or not rev:
            changed[name] = value
    payload["revs"] = revs
    payload["sections"] = changed
    # Said plainly rather than inferred from the count: "everything came back"
    # and "nothing changed" are both ordinary, and a reader should not have to
    # tell them apart by arithmetic.
    payload["full"] = not held
    return payload
