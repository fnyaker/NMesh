"""
Multi-link operation: two links to one node, carrying its traffic together.

A node already holds several links to one peer as a matter of course — a LAN
address and a punched UDP path, IPv4 and IPv6 — and until now exactly one of
them carried anything. `_link_to` picked the best by score and the other sat
there being kept alive at our expense. MLO spends both: packets go down them in
turn, so the pair carries what neither carries alone, and a link that starts
losing is left behind within seconds rather than at the next reap.

Three things had to be true before that is anything but a good way to break a
mesh, and each one is a rule in this file.

**Only links that measure the same.** Striping across a 5 ms link and a 300 ms
one does not double anything: it delivers half the packets a third of a second
late, which every consumer above reads as loss. So a bundle is formed from
links whose measured round trips sit within one configured skew of each other
(`MLOSettings.skew_ms`), and the skew is what the reordering budget is derived
from — not a guess, and not a constant.

**Only measurements worth acting on.** Every number here comes from the last
`metrics.LinkQuality.WINDOW` probes of *that link*. A link with too few probes
behind it is not eligible: unproven is not the same as good, and handing half
the traffic to a link nothing has come back from yet is the failure this whole
mechanism exists to avoid.

**Leaving is cheap, coming back is not.** A member whose drop share reaches the
configured threshold is benched at once — it keeps its keepalive, so it keeps
being measured, but it carries nothing. Coming back needs the share to fall to
*half* the threshold, and that asymmetry is not a detail: with one number in
both directions a fifty-probe window flips on a single answer, so a link at the
threshold would rejoin, drop, leave and rejoin about ten times a second, which
sprays traffic down the one link known to be losing it. The window damps
nothing on its own; the margin is what does.

What this module is not
-----------------------
It holds no link objects, no sockets and no node state — the same shape as
`behaviour.py` and `seen.py`. Callers hand it *keys* (whatever identifies a
link to them) with the two numbers a bundle decides on, and it hands back which
keys carry traffic, in what order, and what that costs in reordering. That is
what makes it testable without a mesh.

The keepalive accord
--------------------
Also here, because it is the same subject seen from the other end: a bundle is
only as current as its measurements, and at the twenty-second cadence the rest
of the node runs on, "this link is losing packets" arrives a minute and a half
late. MLO therefore needs a probe roughly every hundred milliseconds — which is
a cost neither node may impose on the other. So the two of them **declare a
window and take the intersection**, and everything either one does afterwards
has to sit inside it. See `accord`.
"""
from __future__ import annotations

from dataclasses import dataclass

# ---------------------------------------------------------------------------
# The keepalive accord
# ---------------------------------------------------------------------------
# Hard bounds on anything a peer may propose. These are not tuning: they are
# what stops a proposal being an instruction. Below the floor a peer could ask
# us to spend a core on timers; above the ceiling it could ask us to stop
# probing altogether and never notice the link had died.
FLOOR_MS = 50
CEILING_MS = 600_000

# What a node declares is **four** numbers, not two: a range for each of the
# two cadences it runs at.
#
#     fast = [fast_min, fast_max]    while it is striping
#     slow = [slow_min, slow_max]    while it is idle
#
# One range would have been the obvious thing and it is short by half. With a
# single `[min, max]` the *floor* is the only number that protects anybody: it
# is a `max` across the two nodes, so nobody can be dragged below what they
# declared. The ceiling is a `min`, and a `min` is a lever anybody can pull —
# a peer proposing `(100, 150)` pulled the shared ceiling to 150 ms and bought
# six probes a second on that link, for eight bytes, for as long as it stayed
# open. There is no way to write that model where the ceiling is not either a
# lever or ignored.
#
# Four numbers put a floor **and** a ceiling on each mode, and every one of the
# four says something a node needs to be able to say:
#
#     fast_min   the fastest I will ever be probed at, striping or not
#     fast_max   the slowest that is still worth calling "fast" to me
#     slow_min   the fastest I want to be probed at when nothing is happening
#     slow_max   the slowest I can be probed at before I stop believing the link
#
# The two agreed cadences then come out as `max` of things, in both modes — so
# **no value a peer can send lowers this node's own probe interval**. Not
# bounded by a constant, not clamped afterwards: there is no expression in
# `accord` a peer's number enters where being smaller helps it. That property
# is why the four are worth the eight extra bytes on the wire.

#: Defaults. The pair a node ships with reproduces exactly what every link did
#: before any of this existed — a probe every twenty seconds when idle — and
#: offers ten a second when two links are actually being bundled.
DEFAULT_FAST_MIN_MS = 100
DEFAULT_FAST_MAX_MS = 1000
DEFAULT_SLOW_MIN_MS = 15_000
DEFAULT_SLOW_MAX_MS = 20_000

#: How much of a medium's own death timeout the idle cadence may use. The
#: mirror of the rule the UDP keepalive already follows — a death verdict is at
#: least three times the largest legitimate cadence (`gotchas.md` §7) — read
#: backwards, because here it is the cadence that is being chosen. Two nodes
#: that agreed to idle at five minutes over a transport that reaps at sixty
#: seconds have agreed to lose the link.
IDLE_TIMEOUT_SHARE = 1.0 / 3.0

#: Probes a link must have behind it before its numbers decide anything.
MIN_PROBES = 8

#: Links one bundle may hold. Two is what a bundle is for and what the
#: reordering budget below is defined over; a third link adds a second skew
#: nothing measures against the first.
MAX_MEMBERS = 2

#: Default skew two links must agree within to be bundled, in milliseconds.
DEFAULT_SKEW_MS = 30
#: Default drop share (percent) at which a member is benched.
DEFAULT_DROP_PERCENT = 10
#: A benched member rejoins at this fraction of the bench threshold. See the
#: module note: one number in both directions is a link that flaps per probe.
RECOVER_SHARE = 0.5


@dataclass(frozen=True)
class Bounds:
    """What one node is willing to run at: a range per mode, four numbers.

    Held together rather than passed around loose, because three of the four
    rules below read two of them at once and a pair of them swapped is a node
    that probes a hundred times too often."""

    fast_min: int = DEFAULT_FAST_MIN_MS
    fast_max: int = DEFAULT_FAST_MAX_MS
    slow_min: int = DEFAULT_SLOW_MIN_MS
    slow_max: int = DEFAULT_SLOW_MAX_MS

    def as_tuple(self) -> tuple[int, int, int, int]:
        return (self.fast_min, self.fast_max, self.slow_min, self.slow_max)


def clamp_bounds(fast_min, fast_max, slow_min, slow_max) -> Bounds:
    """Force a proposal inside the hard limits and into a shape that has one.

    Never raises and never refuses: refusing here would make a malformed
    proposal a way to *stop* the negotiation, and the point of a declaration is
    that both ends always have one. Whether the proposal was one a correct node
    could have meant is a separate question, asked by `well_formed` — this only
    makes sure whatever comes out can be reasoned about."""
    try:
        values = [int(fast_min), int(fast_max), int(slow_min), int(slow_max)]
    except (TypeError, ValueError):
        return Bounds()
    values = [max(FLOOR_MS, min(CEILING_MS, value)) for value in values]
    # Sorted, so the four always read fast_min ≤ fast_max ≤ slow_min ≤ slow_max
    # whatever arrived. A peer that sent them jumbled gets a coherent
    # declaration and a K3 finding from `well_formed`, not a shape nothing
    # downstream can reason about.
    values.sort()
    return Bounds(*values)


def well_formed(fast_min, fast_max, slow_min, slow_max) -> bool:
    """Is this a declaration a correct node could have meant? (rule K3)

    Four claims, and none of them is a preference expressed awkwardly:

    - a mode whose floor is not below its ceiling is not a range;
    - a "fast" mode slower than the "slow" one at either end is the two
      swapped, which is the one mistake here that costs a hundredfold.
    """
    try:
        fast_min, fast_max = int(fast_min), int(fast_max)
        slow_min, slow_max = int(slow_min), int(slow_max)
    except (TypeError, ValueError):
        return False
    return (fast_min < fast_max and slow_min < slow_max
            and fast_min <= slow_min and fast_max <= slow_max)


@dataclass(frozen=True)
class Accord:
    """The two cadences a pair is held to, computed by both of them.

    Nothing is exchanged to settle it: each end knows both declarations,
    applies `accord`, and gets the same answer — the same trick as the
    canonical link and the punch initiator, and for the same reason."""

    fast_ms: int
    slow_ms: int
    #: Whether a striping cadence exists at all. Two nodes can agree on a
    #: number and still not agree it is *fast*: a battery peer offering
    #: `fast = [2000, 5000]` and a server offering `[100, 500]` have no cadence
    #: both would call fast, and the honest outcome is no bundling with that
    #: peer rather than one of them paying for the other's idea of it.
    fast_ok: bool = True

    @property
    def window(self) -> tuple[int, int]:
        """What an announced cadence is judged against (rule K1).

        The two agreed cadences *are* the two ends of it: nothing between
        striping and idling is out of bounds, and nothing outside them is in."""
        return (self.fast_ms, self.slow_ms)


def accord(mine: Bounds, theirs: Bounds) -> Accord:
    """The cadences two nodes are held to.

        fast = max(the two fast floors)      … and only if both still call it fast
        slow = max(the two slow floors, the lower of the two slow ceilings)

    Both are a `max` over something each node declared, which is the whole
    design: **the agreed cadence is never below either node's own floor**, so
    nothing a peer sends can make this node spend more than it offered to. The
    protection is the shape of the arithmetic, not a limit bolted onto it.

    The slow cadence takes the *slower* of "as slow as both tolerate" and "no
    faster than either wants" — the cheaper answer wins, which is what a link
    at rest should cost. The fast cadence takes the fastest both allow, because
    that is what fast mode is for; when the two ranges do not overlap there is
    no fast mode, rather than one node's floor imposed as the other's ceiling.
    """
    fast_ms = max(mine.fast_min, theirs.fast_min)
    fast_ok = fast_ms <= min(mine.fast_max, theirs.fast_max)
    slow_ms = max(mine.slow_min, theirs.slow_min,
                  min(mine.slow_max, theirs.slow_max))
    # `well_formed` guarantees each node's slow floor is at or above its fast
    # floor, so this holds for any declaration that passed it. A clamped
    # nonsense proposal is made to hold here rather than downstream.
    slow_ms = max(slow_ms, fast_ms)
    return Accord(fast_ms=fast_ms, slow_ms=slow_ms, fast_ok=fast_ok)


def inside(value_ms, window: tuple) -> bool:
    """Is an announced cadence inside the accord? Used by rule K1."""
    try:
        value = int(value_ms)
    except (TypeError, ValueError):
        return False
    low, high = window
    return low <= value <= high


# ---------------------------------------------------------------------------
# The bundle
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class MLOSettings:
    """What an operator decided. One object, so a bundle is never handed three
    loose numbers that could each come from a different place."""

    skew_ms: float = DEFAULT_SKEW_MS
    drop_percent: float = DEFAULT_DROP_PERCENT
    max_members: int = MAX_MEMBERS

    @property
    def drop_share(self) -> float:
        return max(0.0, min(1.0, self.drop_percent / 100.0))

    @property
    def recover_share(self) -> float:
        return self.drop_share * RECOVER_SHARE


@dataclass(frozen=True)
class Candidate:
    """One link offering itself to a bundle, as the bundle sees it.

    ``mean_ms`` and ``drop`` are read off that link's recent probe window
    (`metrics.LinkQuality`), and ``None`` in either means *unmeasured* — which
    is never read as good."""

    key: object
    mean_ms: float | None = None
    drop: float | None = None
    probes: int = 0

    @property
    def measured(self) -> bool:
        return (self.mean_ms is not None and self.drop is not None
                and self.probes >= MIN_PROBES)


class Bundle:
    """The links carrying one node's traffic together, and the turn they take.

    Holds no link objects: `update` is handed candidates and keeps the keys it
    chose. Everything else — which key is next, how far apart the members are,
    what that costs in reordering — is read off that choice."""

    __slots__ = ("_settings", "_keys", "_benched", "_skew_ms", "_turn")

    def __init__(self, settings: MLOSettings | None = None) -> None:
        self._settings = settings or MLOSettings()
        self._keys: tuple = ()
        # Keys currently held out for losing too much. Kept — not recomputed —
        # because coming back needs a *lower* share than leaving did, and that
        # question cannot be answered without knowing whether it left. A dict
        # rather than a set: nothing here may sort keys it knows nothing about,
        # so the only order it can offer is the one they arrived in.
        self._benched: dict = {}
        self._skew_ms: float = 0.0
        self._turn = 0

    # -- what it decided --------------------------------------------------

    @property
    def keys(self) -> tuple:
        """The members, fastest first. Empty when there is no bundle."""
        return self._keys

    @property
    def active(self) -> bool:
        return len(self._keys) > 1

    @property
    def skew_ms(self) -> float:
        """How far apart the members measure, in milliseconds."""
        return self._skew_ms

    @property
    def reorder_ms(self) -> float:
        """How far out of order a receiver should expect packets to arrive.

        Twice the measured skew, which is the number this was asked for and is
        deliberately generous: the skew is a difference of *round trips*, so
        the one-way spread it stands for is about half of it, and doubling it
        again leaves the budget at roughly four times the reordering a healthy
        pair actually produces. A budget that is too small is a consumer
        dropping packets that did arrive."""
        return 2.0 * self._skew_ms

    def benched(self) -> tuple:
        """Links held out for losing too much. They keep their keepalive —
        that is how they get back in — and carry nothing meanwhile.

        In the order they were benched, which is the order they were offered:
        nothing here may sort keys it knows nothing about."""
        return tuple(self._benched)

    # -- deciding ---------------------------------------------------------

    def update(self, candidates) -> tuple:
        """Choose the members from this pass's candidates. Returns the keys.

        Never raises: this runs on the keepalive sweep, which must not die."""
        candidates = list(candidates)
        offered = {id(candidate.key): candidate.key for candidate in candidates}
        # A key that is no longer offered is a link that has gone. Forgetting it
        # here is what keeps the bench from outliving the links it names — and
        # holding a link object one sweep past its death is all this can ever
        # cost, because the sweep that drops it is the same one that rebuilds.
        for key in [held for held in self._benched if id(held) not in offered]:
            del self._benched[key]
        eligible = []
        for candidate in candidates:
            if not candidate.measured:
                continue
            bar = (self._settings.recover_share
                   if candidate.key in self._benched
                   else self._settings.drop_share)
            if candidate.drop >= bar:
                self._benched[candidate.key] = True
                continue
            self._benched.pop(candidate.key, None)
            eligible.append(candidate)
        eligible.sort(key=lambda candidate: candidate.mean_ms)
        chosen = []
        for candidate in eligible[:max(1, self._settings.max_members)]:
            if chosen and candidate.mean_ms - chosen[0].mean_ms > self._settings.skew_ms:
                break        # sorted, so nothing after this one is closer
            chosen.append(candidate)
        if len(chosen) < 2:
            self._keys, self._skew_ms = (), 0.0
            return self._keys
        leader = chosen[0].mean_ms
        self._skew_ms = sum(candidate.mean_ms - leader
                            for candidate in chosen[1:]) / (len(chosen) - 1)
        self._keys = tuple(candidate.key for candidate in chosen)
        return self._keys

    def next_key(self):
        """Whose turn it is. ``None`` while there is no bundle.

        Round robin rather than weighted: the members are inside one skew of
        each other by construction, so there is nothing left to weigh, and a
        rule that has to be recomputed per packet is a rule on the hot path."""
        if len(self._keys) < 2:
            return None
        self._turn += 1
        return self._keys[self._turn % len(self._keys)]

    def status(self) -> dict:
        """What this bundle is doing, in the numbers that are its own.

        The *members* are not named here: a key is whatever the caller uses to
        identify a link, and only the caller knows how to write one down. It
        names them (`node.mlo_status`) and reads these numbers off the bundle
        rather than deriving them again beside it."""
        return {
            "active": self.active,
            "members": len(self._keys),
            "benched": len(self._benched),
            "skew_ms": round(self._skew_ms, 2),
            "reorder_ms": round(self.reorder_ms, 2),
        }
