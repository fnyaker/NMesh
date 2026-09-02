"""
Noticing a peer that is not playing the protocol.

The catalogue is [`Docs/Architecture/behaviour-rules.md`](../Docs/Architecture/behaviour-rules.md);
this is the first slice of it, and the frame the rest goes into. What is here is
deliberately small — six rules — because the frame is the part that decides
whether any of them can be deployed safely, and a frame proved by six rules is
worth more than forty rules with none.

Seven constraints, from the catalogue's doctrine, and all seven are structural
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

**A condition is charged once, not once per sweep** (:data:`RULE_RECHARGE`).
Every rule here reads a cumulative counter, so a rule that becomes true tends to
stay true — and the sweep runs every twenty seconds against a ledger that halves
every hour. Charging per sweep would have made every rule reach the hostile
threshold on its own within minutes, whatever weight it carried and whatever its
`wrong_when` promised. Charging once per half-life instead makes a rule that
never stops firing converge on twice its weight, which is how "no single rule
ever bans" becomes something a test can assert.

**Every judgement is named.** A rule's id travels with the report, so an
operator reading "reported for C1" can go and read C1 and disagree.
"""
from __future__ import annotations

import time
from collections import OrderedDict
from dataclasses import dataclass, field

from .reputation import DEFAULT_HALFLIFE

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

# How often one rule may charge one peer. A rule fires on a *condition*, and a
# condition seen twice is one observation, not two — but the sweep runs every
# keepalive, so a rule left to charge once per sweep would out-run the ledger's
# decay by two orders of magnitude and make every rule decisive whatever its
# weight said. D2 documents itself as "weak, means nothing without something
# else" and would have cut off a quiet consumer in under seven minutes.
#
# At one charge per half-life a rule that never stops firing converges on twice
# its weight, and that is what makes the doctrine assertable rather than
# aspirational: `test_no_single_rule_can_reach_suspect` holds every weight in
# this file below the point where one rule alone sanctions anybody.
RULE_RECHARGE = DEFAULT_HALFLIFE
# Peers × rules, several times over. Nothing an attacker can grow: entries only
# exist for a peer we hold an authenticated link to *and* a rule that fired.
MAX_CHARGES = 4096

# Rule E2. Routing answers a peer must have given, beside other peers' answers
# to the same question, before its answers are worth judging.
MIN_ANSWERS = 12
# An answer this small says nothing about anybody: two nodes can legitimately
# name two different closest candidates.
MIN_ANSWER_SIZE = 3
# The share of an answer that must appear in *somebody* else's answer for it to
# count as the same view of the network. Not zero: a peer steering us into a
# region it controls can always pad its answer with one famous id, and a test
# for emptiness would be cleared by exactly that.
DISJOINT_OVERLAP = 0.25
# …and the share of judged answers that must have been disjoint before this is
# a claim rather than a coincidence. A floor, because in a healthy mesh the
# group median is zero and eight times zero is zero.
DISJOINT_FLOOR = 0.5

# Rule A1. Windows an issuer must have been watched over before its own rate
# means anything — an issuer we have just met has no history to deviate from,
# and the catalogue gives a first-seen issuer no accusation for that reason.
ISSUER_MATURITY = 8
ISSUER_ALPHA = 0.15
# The multiple of an issuer's own rate that counts as a burst, and the number
# of members below which no window is ever a burst however quiet the history:
# without the floor an issuer that admitted nobody for an hour would "burst" on
# its next single member.
ISSUER_BURST = 8.0
ISSUER_FLOOR = 4
MAX_ISSUERS = 512

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
    # Routing answers we were able to hold beside other peers' answers to the
    # same question, and how many of those shared almost nothing with any of
    # them. Only ever counted when several peers were asked at once.
    answers_judged: int = 0
    answers_disjoint: int = 0
    # Set by the watch, from the books it keeps — neither can be read off a
    # single moment, which is the whole reason those books exist.
    profile_break: bool = False
    # Only ever set on the issuer sweep, where `node_id` is an *issuer* and not
    # a link. One dataclass rather than two: an issuer finding and a peer
    # finding travel the same road to the ledger, and a second shape would be a
    # second set of rules about who may say what.
    issuer_burst: bool = False

    @property
    def ratio_out(self) -> float:
        """Bytes we sent it per byte it sent us. A relay is roughly symmetric."""
        return self.bytes_out / self.bytes_in if self.bytes_in else 0.0

    @property
    def self_promotion(self) -> float:
        return (self.found_self / self.found_entries) if self.found_entries else 0.0

    @property
    def disjoint_share(self) -> float:
        if not self.answers_judged:
            return 0.0
        return self.answers_disjoint / self.answers_judged

    @property
    def sampled(self) -> bool:
        return self.packets_in >= MIN_PACKETS


@dataclass
class Group:
    """The medians a peer is judged against — its own transport class only."""

    size: int = 0
    ratio_out: float = 0.0
    self_promotion: float = 0.0
    disjoint_share: float = 0.0

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
            self._evict(protect=key)
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

    def _evict(self, protect=None) -> None:
        """The least-established profile goes first.

        Backwards from the usual, and deliberately: a profile is worth what its
        history is worth, so throwing away the longest-observed peer to make
        room for one seen once would spend the only thing this rule has.

        The entry just inserted is exempt, which is not a detail. Without it
        the newcomer is its own least-established profile and is dropped again
        in the same breath, so a book at capacity would never accept anybody
        new — and 1024 throwaway identities would freeze D5 for every peer that
        joined afterwards. Among the equally new, the oldest goes: ties resolve
        in insertion order."""
        while len(self._profiles) > self._max:
            victim = min((k for k in self._profiles if k != protect),
                         key=lambda k: self._profiles[k][6], default=protect)
            del self._profiles[victim]


class IssuerBook:
    """How fast an issuer admits members, measured against its own history.

    Identities are free; a plausible ancestry is not. This is the one place the
    shape of a Sybil attack is visible before any of its members has done
    anything: they arrive together, and they arrive under one signature.

    **An issuer is compared to itself, never to other issuers.** A hobbyist's
    root that admits one node a month and a datacentre's that admits thirty a
    day are both correct, and a constant that separates them does not exist.

    **In memory only, like the profiles and for a sharper reason.** A book
    restored from disk would meet a network that grew while we were away and
    read every issuer as bursting at once. Worse, joining a network is itself a
    burst — everything is new to us on the first day — so an issuer earns the
    right to be judged by being watched for `ISSUER_MATURITY` windows, which is
    also what gives a first-seen issuer the catalogue's answer: no accusation,
    because it has no history to have deviated from."""

    __slots__ = ("_issuers", "_max")

    def __init__(self, max_issuers: int = MAX_ISSUERS) -> None:
        # key → [rate, windows, issuer]. The issuer itself is held, not just
        # its key: a window in which it admitted nobody still has to be folded
        # in, and the report that may come out the other side names a node.
        self._issuers: dict = {}
        self._max = max(1, int(max_issuers))

    def observe(self, issuer, arrivals: int) -> bool:
        """Fold one window in. ``True`` when this issuer just admitted far more
        members than it ever has."""
        key = getattr(issuer, "raw", issuer)
        held = self._issuers.get(key)
        if held is None:
            held = self._issuers[key] = [0.0, 0, issuer]
            self._evict(protect=key)
        arrivals = max(0, int(arrivals))
        # The rate is floored before it multiplies: an issuer whose average has
        # decayed to nearly nothing would otherwise make any arrival at all a
        # burst by arithmetic, and `ISSUER_FLOOR` alone would be carrying the
        # whole rule.
        burst = (held[1] >= ISSUER_MATURITY
                 and arrivals >= ISSUER_FLOOR
                 and arrivals > max(held[0], 1.0) * ISSUER_BURST)
        held[0] = (float(arrivals) if not held[1]
                   else held[0] * (1 - ISSUER_ALPHA) + arrivals * ISSUER_ALPHA)
        held[1] += 1
        return burst

    def known(self) -> list:
        """Every issuer we hold a rate for — the population a window is folded
        into, so that admitting nobody is part of an issuer's history too."""
        return [held[2] for held in self._issuers.values()]

    def forget(self, issuer) -> None:
        self._issuers.pop(getattr(issuer, "raw", issuer), None)

    def mature(self) -> int:
        return sum(1 for held in self._issuers.values()
                   if held[1] >= ISSUER_MATURITY)

    def __len__(self) -> int:
        return len(self._issuers)

    def _evict(self, protect=None) -> None:
        """The least-watched issuer goes first, as with the profiles and for
        the same reason: a rate is worth what its history is worth, and making
        room by discarding the issuer we know best spends the only thing this
        rule has. The entry just inserted is exempt, or a full book would never
        accept another issuer again."""
        while len(self._issuers) > self._max:
            victim = min((k for k in self._issuers if k != protect),
                         key=lambda k: self._issuers[k][1], default=protect)
            del self._issuers[victim]


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


def _disjoint_answers(observation: Observation, group: Group) -> bool:
    if observation.answers_judged < MIN_ANSWERS or not group.comparable:
        return False
    # A floor as well as a group comparison, for the same reason E1 has one:
    # where the median is zero, any multiple of it is still zero, and a peer
    # that was odd once would be the only one above the bar.
    floor = max(group.disjoint_share * OUTLIER_FACTOR, DISJOINT_FLOOR)
    return observation.disjoint_share > floor


def _profile_break(observation: Observation, _group: Group) -> bool:
    return observation.profile_break


def _issuer_burst(observation: Observation, _group: Group) -> bool:
    return observation.issuer_burst


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
        id="E2",
        summary="answers routing queries with a view nobody else shares",
        weight=1.0,
        wrong_when="a partitioned mesh, or a peer that simply knows a region "
                   "we do not — which is why this is weighted as weak as the "
                   "rest of its family and can never sanction on its own: the "
                   "same signal is the best way to *notice* a partition",
        test=_disjoint_answers,
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


# A1 judges an *issuer*, not a link, so it is swept over a different
# population — see `BehaviourWatch.sweep_issuers`. Same `Rule`, same weights,
# same disarm: only the thing being observed differs.
ISSUER_RULES = (
    Rule(
        id="A1",
        summary="admitted far more members at once than it ever has",
        weight=0.0,
        wrong_when="a real deployment rolling out fifty machines on a Tuesday "
                   "— which is the common case, and why this notifies rather "
                   "than scores. It is also why the comparison is against the "
                   "issuer's own history and never against other issuers",
        test=_issuer_burst,
        response=NOTICE,
    ),
)


class BehaviourWatch:
    """Runs the rules over one sweep, and reports what survives.

    Holds no per-peer *counters* of its own: those live on the links, and
    everything derived from them is recomputed. What it does keep is the state
    no single moment contains — what a peer has been like (`ProfileBook`), how
    fast an issuer admits members (`IssuerBook`), and when each rule last
    charged each subject."""

    def __init__(self, rules=RULES, *,
                 universal_share: float = UNIVERSAL_SHARE,
                 issuer_rules=ISSUER_RULES,
                 recharge: float = RULE_RECHARGE,
                 profiles=None, issuers=None) -> None:
        self._rules = tuple(rules)
        self._issuer_rules = tuple(issuer_rules)
        self._universal = universal_share
        self._recharge = max(0.0, float(recharge))
        # The books live here rather than on the links: both follow an
        # *identity*, and a history that died with a reconnect would miss
        # exactly what it exists for.
        self._profiles = profiles if profiles is not None else ProfileBook()
        self._issuers = issuers if issuers is not None else IssuerBook()
        # (subject, rule) → when it last charged. See `RULE_RECHARGE`.
        self._charged: OrderedDict = OrderedDict()
        # id → how many subjects it fired on, last sweep. For the console, and
        # for an operator asking why a rule stopped saying anything.
        self._fired: dict[str, int] = {}
        self._disarmed: dict[str, int] = {}

    def sweep(self, observations, report, *, now=None):
        """Judge every peer once. ``report(node_id, weight, rule_id, summary,
        response)`` is called for each finding that survived.

        Returns what was reported, for the caller's tests and console."""
        observations = list(observations)
        # Fold every peer into its profile first, and *before* any rule runs:
        # the book must see every sweep, or the averages it compares against
        # would themselves depend on what the rules happened to decide.
        for observation in observations:
            observation.profile_break = self._profiles.observe(observation)
        groups = self._groups(observations)
        empty = Group()
        comparable = sum(1 for obs in observations
                         if groups.get(obs.transport, empty).comparable)
        return self._judge(observations, self._rules, report,
                           group_of=lambda obs: groups.get(obs.transport, empty),
                           population=comparable or len(observations),
                           now=now)

    def sweep_issuers(self, arrivals, report, *, now=None):
        """Judge every issuer we watch once, over one window.

        ``arrivals`` maps an issuer to how many subjects it certified that were
        new to us in that window. Issuers already in the book but absent from
        the mapping are folded in at zero — admitting nobody is part of an
        issuer's history, and leaving it out would let a burst hide behind the
        quiet that preceded it."""
        counts = {getattr(issuer, "raw", issuer): (issuer, count)
                  for issuer, count in arrivals.items()}
        for issuer in self._issuers.known():
            counts.setdefault(getattr(issuer, "raw", issuer), (issuer, 0))
        observations = []
        for issuer, count in counts.values():
            observations.append(Observation(
                node_id=issuer,
                issuer_burst=self._issuers.observe(issuer, count),
            ))
        # The disarm's denominator is the issuers old enough to be judged: a
        # node that has just come back from a partition absorbs everybody's
        # members at once, and that is a fact about *us*.
        return self._judge(observations, self._issuer_rules, report,
                           group_of=lambda _obs: Group(),
                           population=self._issuers.mature(), now=now)

    def _judge(self, observations, rules, report, *, group_of, population,
               now=None):
        """One population, one set of rules. Everything that decides whether a
        rule may speak at all lives here, once."""
        now = time.monotonic() if now is None else float(now)
        # Every rule is evaluated against every subject *before* anything is
        # reported, because whether a rule may speak at all depends on how many
        # subjects it fired on — and that cannot be known while reporting.
        findings: dict[str, list[Observation]] = {}
        for rule in rules:
            fired = [obs for obs in observations if rule.fires(obs, group_of(obs))]
            if fired:
                findings[rule.id] = fired
        self._fired.update({rule.id: len(findings.get(rule.id, ()))
                            for rule in rules})
        for rule in rules:
            self._disarmed.pop(rule.id, None)
        reported: list[tuple[object, str, float]] = []
        for rule in rules:
            hits = findings.get(rule.id)
            if not hits:
                continue
            if len(hits) > max(1, population * self._universal):
                # It is measuring us, not them. Say so and stay quiet: a
                # detector that keeps accusing while our own clock or uplink is
                # broken turns a local fault into a network-wide fight.
                self._disarmed[rule.id] = len(hits)
                continue
            for observation in hits:
                if not self._may_charge(observation.node_id, rule.id, now):
                    continue
                report(observation.node_id, rule.weight, rule.id, rule.summary,
                       rule.response)
                reported.append((observation.node_id, rule.id, rule.weight))
        return reported

    def _may_charge(self, node_id, rule_id: str, now: float) -> bool:
        """Has this rule already said this about this subject, recently?

        A rule fires on a condition, and every condition here is read off a
        cumulative counter — so once true it tends to stay true. The sweep runs
        every twenty seconds and the ledger halves every hour, so charging per
        sweep would have made the weakest rule in the file decisive within
        minutes, which is precisely what its `wrong_when` promises it is not."""
        key = (getattr(node_id, "raw", node_id), rule_id)
        last = self._charged.get(key)
        if last is not None and now - last < self._recharge:
            self._charged.move_to_end(key)
            return False
        self._charged[key] = now
        self._charged.move_to_end(key)
        while len(self._charged) > MAX_CHARGES:
            self._charged.popitem(last=False)
        return True

    def forget(self, node_id) -> None:
        """Drop a subject's history — an operator saying "that change was me".

        Everything it is remembered by goes, the charges included: the point of
        the button is that what this node does now is what it is expected to
        do, and a charge left behind would date the next finding from before
        the operator answered."""
        self._profiles.forget(node_id)
        self._issuers.forget(node_id)
        key = getattr(node_id, "raw", node_id)
        for charged in [k for k in self._charged if k[0] == key]:
            del self._charged[charged]

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
                disjoint_share=_median([m.disjoint_share for m in members
                                        if m.answers_judged]),
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
            } for rule in self._rules + self._issuer_rules],
            "disarmed": sorted(self._disarmed),
            "profiles": len(self._profiles),
            "profiled": self._profiles.mature(),
            "issuers": len(self._issuers),
        }
