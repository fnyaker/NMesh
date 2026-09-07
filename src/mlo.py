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

#: The tightest ceiling a **peer** can impose on the accord.
#:
#: Without it the ceiling is the amplifier the floor is not. The floor is
#: `max` of the two, so nobody can be dragged below what they declared; the
#: ceiling is `min`, so a peer proposing ``(100, 150)`` would pull the accord's
#: ceiling to 150 ms and this node — which clamps its cadence into the accord —
#: would probe that link six times a second for as long as it existed. Eight
#: bytes, once, for a permanent traffic multiplier on every link an adversary
#: opens.
#:
#: A ceiling exists so a peer is not left unable to tell a live link from a
#: dead one, and no honest liveness requirement is measured in milliseconds:
#: each end's own probes are what its own liveness verdict counts, and our
#: PONGs answer its probes whatever our own rate is. So the ceiling floors out
#: here, at the cadence every link had before any of this existed
#: (`node._LINK_KEEPALIVE_INTERVAL`, held in step by a test) — and a peer
#: therefore can **never make this node probe faster than it already did**.
CEILING_MIN_MS = 20_000

#: What a node asks for while it is striping: ten probes a second on each
#: member, so a link that starts losing is benched within a couple of seconds
#: rather than at the next twenty-second sweep.
FAST_MS = 100

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


def clamp_window(low_ms, high_ms) -> tuple[int, int]:
    """Force a proposed window inside the hard bounds, floor below ceiling.

    Never raises and never refuses: refusing here would make a malformed
    proposal a way to stop the negotiation, and the whole point of a window is
    that both ends always have one."""
    try:
        low = int(low_ms)
        high = int(high_ms)
    except (TypeError, ValueError):
        return FLOOR_MS, CEILING_MS
    low = max(FLOOR_MS, min(CEILING_MS, low))
    high = max(FLOOR_MS, min(CEILING_MS, high))
    return low, max(low, high)


def well_formed(low_ms, high_ms) -> bool:
    """Is this a window a correct node could have meant?

    A floor above a ceiling is not a preference expressed awkwardly — it is a
    claim that cannot be true, and it is the one thing about a proposal worth
    holding against whoever sent it (rule K3)."""
    try:
        return int(low_ms) < int(high_ms)
    except (TypeError, ValueError):
        return False


def accord(mine: tuple, theirs: tuple) -> tuple[int, int]:
    """The keepalive window two nodes are held to, computed by both of them.

    Nothing is exchanged to settle it: each end knows both windows, applies
    this, and gets the same answer — the same trick as the canonical link and
    the punch initiator, and for the same reason.

        floor   = the higher of the two floors
        ceiling = the lower of the two ceilings, never below the floor
                  and never below CEILING_MIN_MS

    The floor is the fastest cadence *both* said they could sustain, so it can
    never be one node's demand on the other. When the two windows do not
    overlap at all — one node's ceiling is below the other's floor — there is
    no agreement to find, and the floor wins: the higher of the two, because a
    node's floor is the one half of its window it stated as a limit on what it
    will be *made* to do.

    The ceiling needs the same protection read the other way round, and gets it
    from :data:`CEILING_MIN_MS`: `min` of two numbers is a lever anyone can
    pull down, and a cadence is a cost. See that constant."""
    my_low, my_high = clamp_window(*mine)
    their_low, their_high = clamp_window(*theirs)
    low = max(my_low, their_low)
    high = min(my_high, their_high)
    return low, max(low, high, CEILING_MIN_MS)


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
