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

    def fires(self, observation: Observation, group: Group) -> bool:
        try:
            return bool(self.test(observation, group))
        except Exception:
            return False       # a rule that raises judges nobody, and says so


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
)


class BehaviourWatch:
    """Runs the rules over one sweep, and reports what survives.

    Holds no per-peer state of its own: the counters live on the links, and
    everything else is recomputed. State here would be a second place for a
    peer's history to live, and two places is two answers."""

    def __init__(self, rules=RULES, *,
                 universal_share: float = UNIVERSAL_SHARE) -> None:
        self._rules = tuple(rules)
        self._universal = universal_share
        # id → how many peers it fired on, last sweep. For the console, and for
        # an operator asking why a rule stopped saying anything.
        self._fired: dict[str, int] = {}
        self._disarmed: dict[str, int] = {}

    def sweep(self, observations, report) -> list[tuple[object, str, float]]:
        """Judge every peer once. ``report(node_id, weight, rule_id, summary)``
        is called for each finding that survived.

        Returns what was reported, for the caller's tests and console."""
        observations = list(observations)
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
                report(observation.node_id, rule.weight, rule.id, rule.summary)
                reported.append((observation.node_id, rule.id, rule.weight))
        return reported

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
            } for rule in self._rules],
            "disarmed": sorted(self._disarmed),
        }
