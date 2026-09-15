"""
The links of the machines an operator manages, as they are **now**.

The map a node draws from its own eyes stops at its neighbours. Past that it can
only ask, and what comes back is a machine's word about its own links — first
hand for it, hearsay for us. That is drawable, and the fleet guide says under
what conditions; what it must never become is a *record*.

Which is the whole design of this file. It is a **freshness book**, not a
history:

**Nothing is kept that has not just been confirmed.** Every source carries the
instant it last spoke, and `FRESH_FOR` seconds later its links are gone — not
greyed out, gone. A mesh map showing a link that died twenty minutes ago is
worse than a map missing it: one is incomplete, the other is wrong, and only one
of them looks right.

**A source replaces, never merges.** A machine's answer *is* its link list, so a
link it no longer names is a link that ended. Merging would make this an
accumulator, which is the shape that ends up showing an hour of ghosts.

**Bounded, like every book in this product.** Sources, links per source, and the
total the map will draw.

It lives in the fleet app rather than in the page that draws it, so a reload
does not empty the map and two tabs do not each go asking every machine. It
lives in **memory**: who talks to whom is exactly what the threat model says to
hold as little of as possible, and a claim about somebody else's neighbours is
not something this node should still have after a restart.
"""
from __future__ import annotations

import threading
import time

# How long a source's answer is worth drawing. Deliberately short: the map says
# "now", and the machines refresh far more often than this (`fleet.LINKS_EVERY`).
# Past it there is nothing to draw rather than something old to believe.
FRESH_FOR = 45.0

# Sources held at once, links kept from one answer, and the edges the map may
# hold in total. A fleet is thousands of machines; a drawing is not.
MAX_SOURCES = 128
MAX_LINKS_PER_SOURCE = 64
MAX_EDGES = 512


def _edge_key(one: str, other: str) -> str:
    """One name for one link, whichever end is speaking. Two machines both
    reporting the same link must not draw two."""
    return f"{one}|{other}" if one < other else f"{other}|{one}"


class LinkMap:
    """What the machines we manage say they are connected to, while it is true.

    Touched from the app's loop and read from the console's threads, so
    everything takes the lock. Nothing in here blocks: it is two bounded dicts.
    """

    def __init__(self, *, clock=time.monotonic) -> None:
        self._clock = clock
        self._lock = threading.Lock()
        self._sources: dict[str, dict] = {}   # node -> {at, links:[...]}
        self._watching: float = 0.0           # when a page last drew the map

    # -- what a machine says ----------------------------------------------

    def absorb(self, source: str, links) -> int:
        """One machine's own link list. **Replaces** what it said before.

        Returns how many were kept. Every field is bounded here rather than
        where it is drawn: this arrives from a machine we manage, which the
        threat model says to treat as an adversary that happens to hold a
        grant."""
        if not isinstance(links, (list, tuple)):
            links = []
        kept = []
        for link in list(links)[:MAX_LINKS_PER_SOURCE]:
            if not isinstance(link, dict):
                continue
            node = str(link.get("id") or "")[:40]
            if len(node) != 40 or node == source:
                continue          # not an id, or a machine claiming itself
            kept.append({
                "id": node,
                "pseudo": str(link.get("pseudo") or "")[:50],
                "transport": str(link.get("transport") or "")[:16],
                "rtt_ms": _number(link.get("rtt_ms")),
                "since": _number(link.get("since")),
            })
        with self._lock:
            if source not in self._sources and len(self._sources) >= MAX_SOURCES:
                self._sources.pop(next(iter(self._sources)), None)
            self._sources[source] = {"at": self._clock(), "links": kept}
        return len(kept)

    def forget(self, source: str = "") -> None:
        with self._lock:
            if source:
                self._sources.pop(source, None)
            else:
                self._sources.clear()

    # -- who is being looked at -------------------------------------------

    def note_watching(self) -> None:
        """A page is drawing the map.

        One mark for the whole map rather than one per node, because that is
        the only question anybody asks of it: *is* somebody looking. A mark per
        machine would be a field nothing reads.

        Said as it happens rather than stored: a page that was closed stops
        saying it, and a browser that died says nothing at all. So "somebody is
        looking" has to be a thing that decays on its own."""
        with self._lock:
            self._watching = self._clock()

    def watched(self) -> bool:
        """Is anybody drawing the map right now?"""
        with self._lock:
            return (self._clock() - self._watching) <= FRESH_FOR

    # -- what the map should draw ------------------------------------------

    def view(self) -> dict:
        """The edges worth drawing, and how old each source's word is.

        Stale sources are **dropped here**, on the way out, rather than swept on
        a timer: a book that is only correct between two sweeps is a book that
        is sometimes wrong, and this one is read far more often than it is
        written."""
        now = self._clock()
        with self._lock:
            for node in [node for node, entry in self._sources.items()
                         if now - entry["at"] > FRESH_FOR]:
                self._sources.pop(node, None)
            sources = {node: {"at": entry["at"], "links": list(entry["links"])}
                       for node, entry in self._sources.items()}
        edges: dict[str, dict] = {}
        nodes: dict[str, dict] = {}
        for source, entry in sorted(sources.items()):
            age = max(0.0, now - entry["at"])
            for link in entry["links"]:
                key = _edge_key(source, link["id"])
                if key not in edges and len(edges) >= MAX_EDGES:
                    continue
                # First source wins, and sources are walked in a fixed order:
                # two machines reporting the same link must draw the same edge
                # whichever answered last, or the map flickers between two
                # descriptions of one thing.
                edges.setdefault(key, {
                    "a": source, "b": link["id"], "from": source,
                    "age": round(age, 1), "transport": link["transport"],
                    "rtt_ms": link["rtt_ms"],
                })
                nodes.setdefault(link["id"], {"id": link["id"],
                                              "pseudo": link["pseudo"],
                                              "from": source,
                                              "age": round(age, 1)})
        return {
            "edges": list(edges.values()),
            "nodes": sorted(nodes.values(), key=lambda row: row["id"]),
            "sources": [{"id": node, "age": round(max(0.0, now - entry["at"]), 1),
                         "links": len(entry["links"])}
                        for node, entry in sorted(sources.items())],
            "fresh_for": FRESH_FOR,
        }


def _number(raw) -> float | None:
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return None
    return round(value, 1) if value == value else None
