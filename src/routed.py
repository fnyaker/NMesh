"""
Routed paths — reaching a node *through* another node, as something measured
rather than assumed.

A direct link is probed, scored, and replaced when it stops working. A routed
path — the same packet, addressed to the same id, handed to a different
neighbour — had none of that. The first hop was picked by whichever peer
traffic from that id last happened to arrive through, then by XOR distance, and
a relay that accepted a packet and dropped it was indistinguishable from one
that delivered it: ``peer.send()`` returns either way. Nothing noticed and
nothing retried, so a node that had been reachable a moment ago simply stopped
answering — and the operator's fix was to make a direct link by hand.

So a routed path is an object here, and the same three questions are asked of
it as of a link: does it answer, how fast, and how much does it lose. That buys
three things at once.

* **Failover.** A path that stops answering is dropped and another first hop is
  tried. That is what a mesh is *for*, and it is the one thing the send path
  could not do.
* **MRLO** — multi *routed* link operation. Several measured paths to one
  identity can carry its traffic together exactly as two direct links do:
  `mlo.Bundle` is written over opaque keys, and a path is as opaque as a link.
* **HMLO** — the hybrid. A bundle whose members are a mix of direct links and
  routed paths. Keeping one routed path warm beside a direct link means losing
  the direct one costs a turn of the round robin rather than a reconnect.

Two things this module deliberately does not know: what a packet is, and what a
peer is. It holds identities and measurements, so every rule in it can be
tested without a mesh — the same reason `mlo.py` is shaped that way.

**What a routed probe actually measures.** The probe goes out through a chosen
first hop; the answer comes back by whatever route the far end picks, which may
not be the same one. So the number is "reach this id through this neighbour and
hear back", not "the round trip of this path". That is the question worth
asking — it is the one that decides whether to send down it — and it is the
same bargain a direct link's probe strikes, where a PONG is also only evidence
that the pair can hear each other.
"""
from __future__ import annotations

import time
from collections import OrderedDict

from .metrics import LinkQuality
from .node_id import NodeID

#: Identities we keep paths for. A path costs a probe, so this is bounded by
#: what the node is actually talking to rather than by what it has heard of.
MAX_TARGETS = 16
#: First hops tried per identity. Three is two more than the send path used to
#: have and enough for a bundle plus a spare; beyond that the probes cost more
#: than the redundancy is worth.
MAX_PER_TARGET = 3
#: Probes with no answer before a path is given up on. Same shape as a link's
#: `_DEAD_LINK_PROBES`, and for the same reason: a run, not a share, because a
#: path that worked for an hour and then broke never shows a high lifetime loss.
DEAD_PROBES = 3
#: How long an identity stays worth keeping paths for after the last time
#: anything addressed it. Long enough to survive a pause in a conversation,
#: short enough that a node reached once does not buy a probe for ever.
INTEREST_TTL = 300.0
#: After giving up on a first hop, how long before it is offered again for that
#: identity — doubling per time we give up on it. Without this the pass drops a
#: dead path and the very next pass re-opens it, because the thing that chose
#: it (a hint, XOR proximity) has not changed and cannot: giving up has to be
#: *remembered* or it is not giving up, it is a loop.
SHUN_MIN = 60.0
SHUN_MAX = 900.0
#: Bounded like every other book here. Keyed by (identity, first hop), which is
#: a pair a peer's behaviour can produce, so it cannot be allowed to grow.
MAX_SHUNNED = 64


class Path:
    """One way to reach ``target``: through ``via``, and what that measures.

    Only ever a *routed* path. A direct link already carries its own
    `LinkQuality` on the peer, and a second copy of it here would be a second
    number that can disagree with the first.
    """

    __slots__ = ("target", "via", "quality", "probed_at", "created_at")

    def __init__(self, target: NodeID, via: NodeID, *,
                 now: float | None = None) -> None:
        stamp = time.monotonic() if now is None else now
        self.target = target
        self.via = via
        self.quality = LinkQuality()
        self.probed_at: float = 0.0
        self.created_at: float = stamp

    # -- what the send path asks of it -------------------------------------

    def answered(self, token, at: float) -> float | None:
        return self.quality.answered(token, at)

    def sent(self, token, at: float) -> None:
        self.probed_at = at
        self.quality.sent(token, at)

    def loss(self) -> float | None:
        """What this path is losing *now*, or ``None`` while unproven.

        The recent window, for the reason `node._loss_factor` reads it: a path
        that carried traffic all afternoon and broke ten minutes ago still
        shows a lifetime share near zero."""
        recent = self.quality.recent_loss()
        return self.quality.loss() if recent is None else recent

    def dead(self) -> bool:
        """Has it stopped answering altogether?

        A run of unanswered probes, never a share. The share of a path that
        worked for an hour cannot rise fast enough to notice that it stopped,
        which is the whole of what this has to notice."""
        return self.quality.since_pong >= DEAD_PROBES

    def unproven(self) -> bool:
        return self.quality.pongs == 0

    # A bundle reads three numbers off every member and does not care which
    # kind it is (`mlo.Candidate`). These are that interface, spelled exactly
    # as a link spells it, so `node._update_bundles` has one expression rather
    # than a branch per kind.
    def recent_ms(self) -> float | None:
        return self.quality.recent_ms()

    def recent_loss(self) -> float | None:
        return self.quality.recent_loss()

    def recent_probes(self) -> int:
        return self.quality.recent_probes()

    def as_dict(self) -> dict:
        return {
            "target": self.target.raw.hex(),
            "via": self.via.raw.hex(),
            "rtt_ms": self.quality.recent_ms(),
            "loss": self.loss(),
            "probes": self.quality.recent_probes(),
            "unanswered": self.quality.since_pong,
            "age": round(time.monotonic() - self.created_at, 1),
        }


class PathBook:
    """The routed paths this node holds, bounded on both axes.

    Keyed target → first hop, because "how do I reach T" is the question, and
    the first hop is the answer rather than the subject. Both levels are LRU:
    a partition that costs every route must not cost memory too.
    """

    def __init__(self, *, max_targets: int = MAX_TARGETS,
                 max_per_target: int = MAX_PER_TARGET,
                 interest_ttl: float = INTEREST_TTL) -> None:
        self._max_targets = max(1, int(max_targets))
        self._max_per_target = max(1, int(max_per_target))
        self._interest_ttl = float(interest_ttl)
        self._paths: OrderedDict[bytes, OrderedDict[bytes, Path]] = OrderedDict()
        #: target → when something last addressed it. A path exists to serve
        #: traffic; one kept for an id nobody is talking to is a probe a peer
        #: never asked for and an operator never benefits from.
        self._interest: OrderedDict[bytes, float] = OrderedDict()
        #: (target, via) → (times given up on, not before). See `SHUN_MIN`.
        self._shunned: OrderedDict[tuple, tuple] = OrderedDict()

    # -- what the node is talking to ---------------------------------------

    def note_interest(self, target: NodeID, *, now: float | None = None) -> None:
        """Something addressed this id. Never raises: callers are send paths."""
        stamp = time.monotonic() if now is None else now
        self._interest.pop(target.raw, None)
        self._interest[target.raw] = stamp
        while len(self._interest) > self._max_targets:
            dropped, _ = self._interest.popitem(last=False)
            self._paths.pop(dropped, None)

    def warm(self, *, now: float | None = None) -> list[NodeID]:
        """The identities worth holding paths to, most recent first."""
        stamp = time.monotonic() if now is None else now
        out: list[NodeID] = []
        for raw, at in reversed(list(self._interest.items())):
            if stamp - at > self._interest_ttl:
                self._interest.pop(raw, None)
                self._paths.pop(raw, None)
                continue
            out.append(NodeID(raw))
        return out

    def is_warm(self, target: NodeID, *, now: float | None = None) -> bool:
        at = self._interest.get(target.raw)
        if at is None:
            return False
        stamp = time.monotonic() if now is None else now
        return stamp - at <= self._interest_ttl

    # -- the paths themselves ----------------------------------------------

    def ensure(self, target: NodeID, via: NodeID) -> Path:
        """The path through ``via``, opening one if we had none."""
        book = self._paths.get(target.raw)
        if book is None:
            while len(self._paths) >= self._max_targets:
                self._paths.popitem(last=False)
            book = self._paths[target.raw] = OrderedDict()
        self._paths.move_to_end(target.raw)
        path = book.get(via.raw)
        if path is None:
            path = book[via.raw] = Path(target, via)
            while len(book) > self._max_per_target:
                book.popitem(last=False)
        return path

    def get(self, target: NodeID, via: NodeID) -> Path | None:
        return (self._paths.get(target.raw) or {}).get(via.raw)

    def has(self, target: NodeID) -> bool:
        """Do we hold any path to this id?

        One dict lookup, because the send path asks it per packet and the
        answer is "no" for every id this node is not routing to."""
        return bool(self._paths.get(target.raw))

    def paths(self, target: NodeID) -> list[Path]:
        """Every path to one identity, best first.

        Best is the least lossy, then the fastest — the same order of questions
        `node._link_score` asks, minus the medium's priority, which a routed
        path does not have one of: the hops it crosses are not ours to choose.
        An unproven path sorts last but is never excluded, because it is how a
        path becomes proven."""
        book = self._paths.get(target.raw)
        if not book:
            return []
        def rank(path: Path) -> tuple:
            loss = path.loss()
            rtt = path.quality.recent_ms()
            return (1 if path.unproven() else 0,
                    1.0 if loss is None else loss,
                    float("inf") if rtt is None else rtt)
        return sorted(book.values(), key=rank)

    def live(self, target: NodeID) -> list[Path]:
        """The paths worth sending down: everything that has not given up."""
        return [path for path in self.paths(target) if not path.dead()]

    def drop(self, target: NodeID, via: NodeID) -> bool:
        book = self._paths.get(target.raw)
        if book is None or via.raw not in book:
            return False
        del book[via.raw]
        if not book:
            self._paths.pop(target.raw, None)
        return True

    def forget_via(self, via: NodeID) -> int:
        """Drop every path through one first hop — that link has gone.

        Returns how many went. Keeping them would hand the send path a first
        hop it no longer holds a link to, once per packet."""
        gone = 0
        for target_raw in list(self._paths):
            book = self._paths[target_raw]
            if book.pop(via.raw, None) is not None:
                gone += 1
            if not book:
                self._paths.pop(target_raw, None)
        return gone

    def forget(self, target: NodeID) -> None:
        self._paths.pop(target.raw, None)
        self._interest.pop(target.raw, None)

    def reap(self, target: NodeID, *, now: float | None = None) -> list[Path]:
        """Drop the paths to one identity that have stopped answering.

        Returns what went, so a caller can say so. A dead path is not kept "in
        case it comes back": the whole point is to pick a different first hop,
        and the book is what the choice is made from. It *is* remembered, for
        a while — see `shunned`."""
        book = self._paths.get(target.raw)
        if not book:
            return []
        stamp = time.monotonic() if now is None else now
        dead = [path for path in book.values() if path.dead()]
        for path in dead:
            book.pop(path.via.raw, None)
            self._shun(target, path.via, stamp)
        if not book:
            self._paths.pop(target.raw, None)
        return dead

    def _shun(self, target: NodeID, via: NodeID, now: float) -> None:
        key = (target.raw, via.raw)
        times = self._shunned.pop(key, (0, 0.0))[0] + 1
        delay = min(SHUN_MAX, SHUN_MIN * (2 ** min(times - 1, 4)))
        self._shunned[key] = (times, now + delay)
        while len(self._shunned) > MAX_SHUNNED:
            self._shunned.popitem(last=False)

    def shunned(self, target: NodeID, via: NodeID, *,
                now: float | None = None) -> bool:
        """Have we given up on this first hop for this identity, recently?

        Asked before a first hop is *offered*, never before a packet is sent:
        the send path chooses among paths that exist, and this decides which
        ones get to exist."""
        held = self._shunned.get((target.raw, via.raw))
        if held is None:
            return False
        stamp = time.monotonic() if now is None else now
        if stamp >= held[1]:
            return False
        return True

    def forgive(self, target: NodeID, via: NodeID) -> None:
        """A path through here worked: forget that it ever did not."""
        self._shunned.pop((target.raw, via.raw), None)

    # -- reporting ---------------------------------------------------------

    def targets(self) -> list[NodeID]:
        return [NodeID(raw) for raw in self._paths]

    def rows(self) -> list[dict]:
        """Every path, for an operator. Flat: a table, not a tree."""
        return [path.as_dict()
                for book in self._paths.values() for path in book.values()]

    def __len__(self) -> int:
        return sum(len(book) for book in self._paths.values())
