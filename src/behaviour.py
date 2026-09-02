"""
Noticing a peer that is not playing the protocol.

The catalogue is [`Docs/Architecture/behaviour-rules.md`](../Docs/Architecture/behaviour-rules.md);
this is the first slice of it, and the frame the rest goes into. What is here is
deliberately small — four rules — because the frame is the part that decides
whether any of them can be deployed safely, and a frame proved by four rules is
worth more than forty rules with none.

Six constraints, from the catalogue's doctrine, and all six are structural
rather than advisory:

**Nothing costs latency.** The receive loop increments integers. That is the
whole hot-path contribution: no hashing, no allocation, no walk, no clock
arithmetic. Judgement happens in :meth:`BehaviourWatch.sweep`, called from the
keepalive loop that already runs — a detector that makes the mesh slower has
done more damage than what it detects.

**A peer is compared to its peer group, never to a constant.** Absolute
thresholds are wrong on every deployment but the one they were tuned on, and
they punish the slow medium rather than the bad actor. Every ratio here is
measured against the *median of comparable peers*, comparable meaning same
transport class: a LoRa peer and a TCP peer share no baseline worth having.

**No rule bans.** Rules return a weight; the weight goes to
:meth:`MeshNode.report_abuse` and the ledger decides. A rule that cut a peer off
directly would be a rule whose false-positive rate is an outage.

**Unknown is not hostile.** A rule may only fire on something the peer *agreed*
it would not do. That is what the capability negotiation is for, and why
``undeclared`` counts nothing for a peer that has announced nothing.

**A rule that fires on everyone disarms itself** (:data:`UNIVERSAL_SHARE`). If
most peers look wrong, we are wrong — our clock, our uplink, our config — and a
detector that keeps accusing under those conditions turns a local fault into a
network-wide fight. This is not an optimisation; it is what makes the rest safe
to switch on.

**Every judgement is named.** A rule's id travels with the report, so an
operator reading "reported for C1" can go and read C1 and disagree.
"""
from __future__ import annotations

from dataclasses import dataclass, field

# A rule needs enough of a sample to mean anything. Below this a peer is simply
# new, and being new is the first entry in the catalogue's anti-rules.
MIN_PACKETS = 64
# …and enough *peers* to have a median worth comparing against. With three
# links, "twice the median" is a description of one of them.
MIN_GROUP = 4
# A rule firing on more than this share of comparable peers is measuring us.
UNIVERSAL_SHARE = 0.5
# How far past the group a ratio has to be before it is a signal rather than a
# spread. Deliberately generous: the cost of being wrong here is accusing an
# honest node, and the rules that matter most are not the noisy ones.
OUTLIER_FACTOR = 8.0

# What a rule does when it fires. Two classes, because two rules can be equally
# true and call for opposite handling.
SCORE = "score"      # hand a weight to the ledger; the ledger decides
NOTICE = "notice"    # tell the operator, and nothing else

# Profiling (rule D5). Sweeps a peer must contribute before it has habits worth
# comparing against — under this it is simply new, and being new is the first
# anti-rule.
PROFILE_MATURITY = 12
# How much the exponential average moves per sweep. Slow: a profile that
# followed a peer closely would follow it straight through a compromise.
PROFILE_ALPHA = 0.15
# How far a dimension must move to count as changed, and how many dimensions
# must move together. One number wandering is weather; three at once is a
# different node behind the same key.
PROFILE_BREAK = 4.0
PROFILE_DIMENSIONS = 2
MAX_PROFILES = 1024


@dataclass
class Observation:
    """What the sweep knows about one peer at one moment.

    Assembled from counters that were already being kept, plus three integers
    the receive loop adds. Nothing here is measured *for* this — that is the
    difference between a detector and a tax."""

    node_id: object
    transport: str = ""
    packets_in: int = 0
    packets_out: int = 0
    bytes_in: int = 0
    bytes_out: int = 0
    # Messages belonging to a plane this peer announced it does not speak.
    # Zero for a peer that announced nothing: see the module note.
    undeclared: int = 0
    # Routing answers, and how many of them named the answerer itself.
    found_entries: int = 0
    found_self: int = 0
    # Set by the watch, from the profile book — not measured here, because it
    # is the one thing that cannot be read off a single moment.
    profile_break: bool = False

    @property
    def ratio_out(self) -> float:
        """Bytes we sent it per byte it sent us. A relay is roughly symmetric."""
        return self.bytes_out / self.bytes_in if self.bytes_in else 0.0

    @property
    def self_promotion(self) -> float:
        return (self.found_self / self.found_entries) if self.found_entries else 0.0

    @property
    def sampled(self) -> bool:
        return self.packets_in >= MIN_PACKETS


@dataclass
class Group:
    """The medians a peer is judged against — its own transport class only."""

    size: int = 0
    ratio_out: float = 0.0
    self_promotion: float = 0.0

    @property
    def comparable(self) -> bool:
        return self.size >= MIN_GROUP


@dataclass(frozen=True)
class Rule:
    """One named thing worth noticing.

    ``weight`` is what a firing is worth to the ledger — never what happens
    next, which is the ledger's to decide. ``wrong_when`` is not documentation
    for its own sake: a rule whose honest lookalike cannot be stated is a
    superstition, and writing the field is how that gets caught."""

    id: str
    summary: str
    weight: float
    wrong_when: str
    test: object = field(repr=False, default=None)
    # What firing *means*. Most rules score, and the ledger decides what the
    # scores add up to. A few can only ever notify: where the honest lookalike
    # is "the operator changed what this node does", scoring would punish the
    # operator for administering their own fleet, and the useful thing to do
    # with the signal is show it to them.
    response: str = SCORE

    def fires(self, observation: Observation, group: Group) -> bool:
        try:
            return bool(self.test(observation, group))
        except Exception:
            return False       # a rule that raises judges nobody, and says so


class ProfileBook:
    """What a peer has been like, so a change of habits becomes visible.

    Every other rule in this file detects a *stranger*. This one detects the
    peer that was already trusted — and it is the only thing here that can,
    because an attacker who steals a key gets the identity and not the habits.
    Nothing else in the trust system has anything to say about a compromise of
    something it already accepted.

    Three dimensions, all read off counters that were already being kept:

      - **rate** — packets per sweep;
      - **direction** — bytes out per byte in;
      - **shape** — mean inbound packet size.

    None of them is interesting alone. What is interesting is several moving at
    once, which is why a break needs `PROFILE_DIMENSIONS` of them: one number
    wandering is weather, and a rule that fired on one would fire on everybody
    with a busy afternoon.

    **Deltas, never totals.** The counters are cumulative, so a profile built
    from them would flatten out and stop noticing anything; what is averaged is
    what happened *since the last sweep*. An idle sweep contributes nothing —
    a peer that said nothing has not changed its habits, it has been quiet.

    **In memory only, on purpose.** After a restart this node has no history
    and must not pretend otherwise: a profile restored from disk would be
    compared against a network that moved on while we were away, and the first
    sweep back would accuse everybody. Losing it is the correct behaviour, not
    a limitation."""

    __slots__ = ("_profiles", "_max")

    def __init__(self, max_profiles: int = MAX_PROFILES) -> None:
        # identity → [packets_in, bytes_in, bytes_out, rate, ratio, size, n]
        self._profiles: dict = {}
        self._max = max(1, int(max_profiles))

    def observe(self, observation: Observation) -> bool:
        """Fold one sweep in. ``True`` when this peer's habits just changed."""
        key = getattr(observation.node_id, "raw", observation.node_id)
        held = self._profiles.get(key)
        totals = (observation.packets_in, observation.bytes_in,
                  observation.bytes_out)
        if held is None:
            self._profiles[key] = [*totals, 0.0, 0.0, 0.0, 0]
            self._evict()
            return False
        packets = observation.packets_in - held[0]
        if packets <= 0:
            return False          # nothing happened; that is not a change
        bytes_in = max(0, observation.bytes_in - held[1])
        bytes_out = max(0, observation.bytes_out - held[2])
        rate = float(packets)
        ratio = (bytes_out / bytes_in) if bytes_in else 0.0
        size = bytes_in / packets
        held[0], held[1], held[2] = totals
        broke = False
        if held[6] >= PROFILE_MATURITY:
            moved = sum(1 for now, before in ((rate, held[3]),
                                              (ratio, held[4]),
                                              (size, held[5]))
                        if _moved(now, before))
            broke = moved >= PROFILE_DIMENSIONS
        for index, value in ((3, rate), (4, ratio), (5, size)):
            held[index] = (value if not held[6]
                           else held[index] * (1 - PROFILE_ALPHA)
                           + value * PROFILE_ALPHA)
        held[6] += 1
        return broke

    def forget(self, node_id) -> None:
        self._profiles.pop(getattr(node_id, "raw", node_id), None)

    def mature(self) -> int:
        return sum(1 for held in self._profiles.values()
                   if held[6] >= PROFILE_MATURITY)

    def __len__(self) -> int:
        return len(self._profiles)

    def _evict(self) -> None:
        """The least-established profile goes first.

        Backwards from the usual, and deliberately: a profile is worth what its
        history is worth, so throwing away the longest-observed peer to make
        room for one seen once would spend the only thing this rule has."""
        while len(self._profiles) > self._max:
            victim = min(self._profiles, key=lambda k: self._profiles[k][6])
            del self._profiles[victim]


def _moved(now: float, before: float) -> bool:
    """Has one dimension changed enough to mean something?

    Both directions: a peer that suddenly goes quiet has changed as much as one
    that suddenly floods, and a compromise can look like either. Zero is not a
    special case to skip — going from something to nothing is the change."""
    if before <= 0.0 and now <= 0.0:
        return False
    if before <= 0.0 or now <= 0.0:
        return True
    return max(now / before, before / now) > PROFILE_BREAK


def _median(values: list) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    middle = len(ordered) // 2
    if len(ordered) % 2:
        return float(ordered[middle])
    return (ordered[middle - 1] + ordered[middle]) / 2.0


# ---------------------------------------------------------------------------
# The rules
# ---------------------------------------------------------------------------

def _undeclared_plane(observation: Observation, _group: Group) -> bool:
    return observation.undeclared > 0


def _traffic_asymmetry(observation: Observation, group: Group) -> bool:
    if not (observation.sampled and group.comparable and group.ratio_out > 0):
        return False
    return observation.ratio_out > group.ratio_out * OUTLIER_FACTOR


def _self_promotion(observation: Observation, group: Group) -> bool:
    if observation.found_entries < MIN_PACKETS or not group.comparable:
        return False
    # A node legitimately ranks itself among the candidates it returns — the
    # answer would otherwise never mention it and a lookup routed *to* it would
    # come back without it. So the signal is not "mentions itself" but "does
    # little else", measured against what the peer group does.
    floor = max(group.self_promotion * OUTLIER_FACTOR, 0.5)
    return observation.self_promotion > floor


def _profile_break(observation: Observation, _group: Group) -> bool:
    return observation.profile_break


RULES = (
    Rule(
        id="C1",
        summary="used a plane it announced it does not speak",
        weight=2.0,
        wrong_when="a node restarting mid-session and reusing a persisted "
                   "session — which is why a restart re-announces, and why a "
                   "peer that has announced nothing is counted at zero",
        test=_undeclared_plane,
    ),
    Rule(
        id="D2",
        summary="sends far less than it is sent, against its peer group",
        weight=1.0,
        wrong_when="a legitimately quiet consumer — a node that listens and "
                   "rarely answers is a node, so this is weak on purpose and "
                   "means nothing without something else",
        test=_traffic_asymmetry,
    ),
    Rule(
        id="E1",
        summary="answers routing queries mostly with itself",
        weight=1.0,
        wrong_when="a small mesh, where a node genuinely is the closest thing "
                   "to most keys — hence the group comparison and the floor",
        test=_self_promotion,
    ),
    Rule(
        id="D5",
        summary="an established peer's habits changed abruptly",
        weight=0.0,
        wrong_when="the operator upgraded it, or changed what it does — which "
                   "is the common case by far, and why this one notifies "
                   "rather than scores: an operator administering their own "
                   "fleet must not be punished for it",
        test=_profile_break,
        response=NOTICE,
    ),
)


class BehaviourWatch:
    """Runs the rules over one sweep, and reports what survives.

    Holds no per-peer state of its own: the counters live on the links, and
    everything else is recomputed. State here would be a second place for a
    peer's history to live, and two places is two answers."""

    def __init__(self, rules=RULES, *,
                 universal_share: float = UNIVERSAL_SHARE,
                 profiles=None) -> None:
        self._rules = tuple(rules)
        self._universal = universal_share
        # The one piece of state this layer keeps, and it keeps it here rather
        # than on the links: a compromise follows the *identity*, so a profile
        # that died with a reconnect would miss exactly what it exists for.
        self._profiles = profiles if profiles is not None else ProfileBook()
        # id → how many peers it fired on, last sweep. For the console, and for
        # an operator asking why a rule stopped saying anything.
        self._fired: dict[str, int] = {}
        self._disarmed: dict[str, int] = {}

    def sweep(self, observations, report) -> list[tuple[object, str, float]]:
        """Judge every peer once. ``report(node_id, weight, rule_id, summary)``
        is called for each finding that survived.

        Returns what was reported, for the caller's tests and console."""
        observations = list(observations)
        # Fold every peer into its profile first, and *before* any rule runs:
        # the book must see every sweep, or the averages it compares against
        # would themselves depend on what the rules happened to decide.
        for observation in observations:
            observation.profile_break = self._profiles.observe(observation)
        groups = self._groups(observations)
        # Every rule is evaluated against every peer *before* anything is
        # reported, because whether a rule may speak at all depends on how many
        # peers it fired on — and that cannot be known while reporting.
        findings: dict[str, list[Observation]] = {}
        for rule in self._rules:
            group_of = groups.get
            fired = [obs for obs in observations
                     if rule.fires(obs, group_of(obs.transport, Group()))]
            if fired:
                findings[rule.id] = fired
        self._fired = {rule_id: len(hits) for rule_id, hits in findings.items()}
        self._disarmed = {}
        reported: list[tuple[object, str, float]] = []
        for rule in self._rules:
            hits = findings.get(rule.id)
            if not hits:
                continue
            comparable = sum(1 for obs in observations
                             if groups.get(obs.transport, Group()).comparable) \
                or len(observations)
            if len(hits) > max(1, comparable * self._universal):
                # It is measuring us, not them. Say so and stay quiet: a
                # detector that keeps accusing while our own clock or uplink is
                # broken turns a local fault into a network-wide fight.
                self._disarmed[rule.id] = len(hits)
                continue
            for observation in hits:
                report(observation.node_id, rule.weight, rule.id, rule.summary,
                       rule.response)
                reported.append((observation.node_id, rule.id, rule.weight))
        return reported

    def forget(self, node_id) -> None:
        """Drop a peer's history — an operator saying "that change was me"."""
        self._profiles.forget(node_id)

    def _groups(self, observations) -> dict:
        """Medians per transport class. A LoRa peer and a TCP peer share no
        baseline worth having, so they are never in the same group."""
        buckets: dict[str, list[Observation]] = {}
        for observation in observations:
            buckets.setdefault(observation.transport, []).append(observation)
        return {
            name: Group(
                size=len(members),
                ratio_out=_median([m.ratio_out for m in members if m.sampled]),
                self_promotion=_median([m.self_promotion for m in members
                                        if m.found_entries]),
            )
            for name, members in buckets.items()
        }

    def status(self) -> dict:
        """What each rule did last sweep, for the console."""
        return {
            "rules": [{
                "id": rule.id,
                "summary": rule.summary,
                "weight": rule.weight,
                "fired": self._fired.get(rule.id, 0),
                "disarmed": rule.id in self._disarmed,
                "wrong_when": rule.wrong_when,
                "response": rule.response,
            } for rule in self._rules],
            "disarmed": sorted(self._disarmed),
            "profiles": len(self._profiles),
            "profiled": self._profiles.mature(),
        }
