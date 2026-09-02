"""
What this node thinks of the nodes it talks to.

Joining a network is not being trusted. A membership certificate says an issuer
vouched for an identity once; it says nothing about how that identity behaves
afterwards, and an authenticated peer is exactly the adversary the threat model
names — a relay that alters, replays, amplifies or floods. Until now the only
answer to a peer behaving badly was `_Peer.note_abuse`, which counts frames a
*link* could not decode and cuts that link. That is right as far as it goes and
it goes one hop: it forgets everything the moment the socket closes, it cannot
hear what an application saw, and it cannot tell one node holding four links
from four nodes.

This is the node-wide version. One score per **identity**, fed from three
places, decaying on its own so that a node which misbehaved once and then
behaved comes back:

  - the core, for protocol violations it sees itself;
  - the applications, each judging by its own thresholds — only chat knows what
    too many messages is, only fleet knows what too many commands is — and
    reporting through :meth:`MeshNode.report_abuse`;
  - other nodes, as signed accusations.

Who gets believed
-----------------
This is the part that decides whether the whole mechanism is a defence or a
weapon. An accusation is not a fact: if hearsay alone could get a node cut off,
then anybody able to speak on the mesh could cut anybody off it, and we would
have built a censorship primitive with a reputation label on it.

So evidence lands in two buckets and they are not equal:

  - **direct** — what we saw ourselves, plus what a witness the *operator*
    designated said. This is the only bucket that can reach `HOSTILE`.
  - **rumour** — ordinary members accusing. Counted as *how many distinct
    members* say it, never how many times they say it, so shouting louder buys
    nothing. Hard-capped strictly below the hostile threshold: a swarm of
    accusers can make this node wary of a peer, and can never on its own make
    it cut one off.

An accuser we already hold as suspect is not counted at all. A stranger — a
node we cannot place in our own network — is not counted at all either.

How many voices a crowd is
--------------------------
"How many distinct members" was still the wrong count, and it was the live
hole in this file: the cap is *hostile* minus one, and the threshold that
stops us serving a peer is far below that. Eight members saying it reached
`SUSPECT` — so eight certified identities, which one compromised issuer mints
in an afternoon, could get any node on the mesh dropped by us in silence.

So an accusation is now counted **per family** and not per member: the max one
family says, summed across families. A family is whoever heads that node's
line just below a root (`CertStore.family`), which is the same independence
test the release quorum already applies to signers, asked here of witnesses.
Two hundred identities minted under one issuer are one voice — not because
they are guilty of anything, but because they are not two hundred *independent*
observations, and it is only independence that made counting them meaningful.

Two more things a voice can lose (catalogue F3):

  - **Volume.** An accuser that names more than `MAX_SUBJECTS` distinct nodes
    inside a half-life is not testifying, it is voting. Its later accusations
    are recorded at nothing.
  - **Retaliation.** Two nodes accusing each other tell us that one of them is
    lying and nothing about which, so **both** directions stop counting. It is
    symmetric on purpose: making the *later* one the retaliation would hand
    anybody who accuses first a shield against the node they attacked. A voice
    already discounted cannot cancel anything, or counter-accusing everybody
    would be a way to silence the mesh one honest node at a time.

None of this ever *accuses* the accuser: a family is not a conspiracy, and a
node that talks too much is not a hostile node. It stops being counted, and
that is the whole of it.

What it costs the accused
-------------------------
Nothing they can measure, which is the point. `SUSPECT` means their traffic is
dropped and their link tarpitted; `HOSTILE` means it is dropped and the link
goes away after a while, with no message either time. A node that is told
"you have been detected" simply changes identity and starts again.
"""
from __future__ import annotations

import math
import time

from .config import SETTINGS
from .node_id import NodeID

# Standings, in the order they get worse.
OK = "ok"
SUSPECT = "suspect"
HOSTILE = "hostile"

# Default thresholds, read back out of the settings table rather than written
# down twice: an operator moves them in `nmesh.conf`, and a second copy here
# would be a second chance for the number in the code and the number in the help
# they read to disagree. An application never sets them — it only reports what it
# saw, because weighing one app's complaint against another's is a node-wide
# judgement.
DEFAULT_SUSPECT = SETTINGS["abuse_suspect"][1]
DEFAULT_HOSTILE = SETTINGS["abuse_hostile"][1]
DEFAULT_HALFLIFE = SETTINGS["abuse_halflife"][1]

# What one report may be worth at most. Two things follow from it, and both are
# deliberate: an application with a bug in its own accounting cannot bring a peer
# down in a single call, and **one complaint is never on its own decisive** —
# with the default thresholds it takes two maximal reports to stop serving a peer
# and five to refuse it outright.
#
# It must also stay strictly *below* `DEFAULT_SUSPECT`, not merely at or under
# it. When the two were equal, the strongest report a caller could make landed
# exactly on the threshold and the first decay tick put it back underneath: the
# worst thing an app could say about a peer changed nothing at all, for ever,
# and nothing anywhere said why.
MAX_WEIGHT = 4.0

MAX_TRACKED = 4096              # identities we hold an opinion about
MAX_ACCUSERS = 64               # distinct accusers remembered per subject
MAX_REASON = 64                 # characters of the reason we keep, for the console
# Distinct subjects one accuser may name inside a half-life before we stop
# believing it. Deliberately generous: a node at the centre of a real flood
# honestly sees a lot, and the cost of being wrong here is ignoring a witness.
MAX_SUBJECTS = 16


def _decay(value: float, age: float, halflife: float) -> float:
    if value <= 0.0 or age <= 0.0:
        return max(0.0, value)
    if halflife <= 0.0:
        return 0.0
    return value * math.pow(0.5, age / halflife)


class _Standing:
    """What we hold against one identity. Decayed lazily, on the way past."""

    __slots__ = ("direct", "accusers", "at", "reason", "reports")

    def __init__(self) -> None:
        self.direct: float = 0.0
        # accuser_id.raw → (weight, when, family). Weight, not a count: one
        # accuser saying it ten times is still one accuser — and `family`, so
        # that a hundred accusers who are one line of descent are one voice.
        self.accusers: dict[bytes, tuple[float, float, bytes]] = {}
        self.at: float = 0.0            # when `direct` was last brought forward
        self.reason: str = ""           # the most recent, for an operator to read
        self.reports: int = 0           # how many complaints in total, ever


class Reputation:
    """The node-wide opinion table. Bounded, decaying, and never authoritative
    about anybody but the node that holds it."""

    def __init__(self, *, suspect: float = DEFAULT_SUSPECT,
                 hostile: float = DEFAULT_HOSTILE,
                 halflife: float = DEFAULT_HALFLIFE,
                 max_tracked: int = MAX_TRACKED) -> None:
        self._suspect = max(0.1, float(suspect))
        self._hostile = max(self._suspect + 0.1, float(hostile))
        self._halflife = max(1.0, float(halflife))
        self._max_tracked = max(1, int(max_tracked))
        self._standings: dict[bytes, _Standing] = {}
        # Rumour may carry a node up to here and no further. Strictly below the
        # *suspect* threshold, and that word matters: the ceiling used to sit
        # just below `hostile`, which read as "hearsay can make us wary but
        # never cut anybody off" — except that being wary is what SUSPECT is,
        # and a suspect peer already has its traffic dropped and its link
        # tarpitted, in silence. Hearsay alone was therefore decisive, and eight
        # certified identities were the price. Below `suspect`, a crowd can
        # bring a node to the edge of the judgement and never past it: what we
        # saw ourselves is what carries it over, which is what "hearsay is never
        # authority" was always supposed to mean.
        self._rumour_ceiling = max(0.0, self._suspect - 0.1)

    # -- reporting --------------------------------------------------------

    def note(self, node_id: NodeID, weight: float, reason: str = "",
             *, now: float | None = None) -> str:
        """Record something **we** saw. Returns the resulting standing.

        This is the bucket that can reach hostile, so only two things reach it:
        the core's own observations, and a witness the operator designated."""
        stamp = time.monotonic() if now is None else now
        entry = self._entry(node_id.raw)
        entry.direct = _decay(entry.direct, stamp - entry.at, self._halflife)
        entry.direct += max(0.0, min(float(weight), MAX_WEIGHT))
        entry.at = stamp
        entry.reports += 1
        if reason:
            entry.reason = str(reason)[:MAX_REASON]
        self._enforce_bound()
        return self.standing(node_id, now=stamp)

    def note_accusation(self, node_id: NodeID, accuser: NodeID,
                        weight: float = 1.0, reason: str = "",
                        *, family: bytes | None = None,
                        now: float | None = None) -> str:
        """Record that ``accuser`` says ``node_id`` is misbehaving.

        Kept per accuser and overwritten, never added: the quantity that means
        something is *how many distinct members* are saying it. Repeating an
        accusation is free to send, so counting repetitions would price the
        whole mechanism at whatever the loudest node feels like paying.

        ``family`` is who heads the accuser's line below a root, and it is what
        the score is grouped by — see the module note. ``None`` means we could
        not place the accuser, and an unplaceable accuser is its own family:
        erring the other way would put every stranger in one crowd together."""
        if accuser == node_id:
            return self.standing(node_id, now=now)   # nobody accuses themselves
        stamp = time.monotonic() if now is None else now
        allowance = max(0.0, min(float(weight), MAX_WEIGHT))
        if self._reach(accuser.raw, stamp) >= MAX_SUBJECTS:
            # It is not testifying, it is voting. Recorded at nothing rather
            # than thrown away: the record is what its own reach is counted
            # from, so discarding it would let the flooder drop back under the
            # limit on its next accusation and be believed again. It is not
            # surfaced anywhere either, and that is deliberate — a table of
            # everyone a flooder named is a console it gets to write.
            allowance = 0.0
        entry = self._entry(node_id.raw)
        entry.accusers[accuser.raw] = (allowance, stamp,
                                       family if family else accuser.raw)
        while len(entry.accusers) > MAX_ACCUSERS:
            oldest = min(entry.accusers, key=lambda k: entry.accusers[k][1])
            del entry.accusers[oldest]
        if allowance > 0.0:
            self._cancel_if_mutual(node_id.raw, accuser.raw)
        entry.reports += 1
        if reason:
            entry.reason = str(reason)[:MAX_REASON]
        self._enforce_bound()
        return self.standing(node_id, now=stamp)

    def _reach(self, accuser_raw: bytes, now: float) -> int:
        """How many distinct nodes this accuser has named inside a half-life.

        Derived from the table rather than tallied beside it: a second count of
        the same events is a second chance to disagree with the first, and this
        one would be an attacker-sized table of its own.

        It counts what the accuser *said*, not what we credited it with. Count
        only the accusations we believed and an accuser over the limit would see
        its own reach fall back under it on the next thing it said, and be
        believed again — a ratchet that only ever turns one way is the point.

        The table it walks is bounded, so the ratchet is too: enough eviction
        pressure eventually forgets what a flooder said. Reaching that state
        costs an attacker `MAX_TRACKED` entries that outscore its own, which it
        cannot manufacture from one family — the same bound, doing the same work
        twice."""
        count = 0
        for entry in self._standings.values():
            held = entry.accusers.get(accuser_raw)
            if held is not None and now - held[1] <= self._halflife:
                count += 1
                if count >= MAX_SUBJECTS:
                    break     # the answer is already "too many"
        return count

    def _cancel_if_mutual(self, subject_raw: bytes, accuser_raw: bytes) -> None:
        """They have accused each other. Neither says anything about the other.

        One of the two is lying and this tells us nothing about which, so the
        pair stops counting in **both** directions. Symmetric on purpose:
        treating the later accusation as the retaliation would make accusing
        first a shield, which is a strictly better move than behaving."""
        mirror = self._standings.get(accuser_raw)
        if mirror is None:
            return
        held = mirror.accusers.get(subject_raw)
        if held is None or held[0] <= 0.0:
            return
        mirror.accusers[subject_raw] = (0.0, held[1], held[2])
        entry = self._standings[subject_raw]
        ours = entry.accusers[accuser_raw]
        entry.accusers[accuser_raw] = (0.0, ours[1], ours[2])

    def forgive(self, node_id: NodeID) -> bool:
        """Drop everything held against a node — an operator overruling us."""
        return self._standings.pop(node_id.raw, None) is not None

    # -- reading ----------------------------------------------------------

    def score(self, node_id: NodeID, *, now: float | None = None) -> float:
        entry = self._standings.get(node_id.raw)
        if entry is None:
            return 0.0
        stamp = time.monotonic() if now is None else now
        direct = _decay(entry.direct, stamp - entry.at, self._halflife)
        rumour = sum(self._by_family(entry, stamp).values())
        return direct + min(rumour, self._rumour_ceiling)

    def _by_family(self, entry: '_Standing', now: float) -> dict:
        """The most any one family says, per family. Never the sum over
        accusers — see the module note; that count is what two hundred minted
        identities were priced at nothing to buy."""
        loudest: dict[bytes, float] = {}
        for weight, at, family in entry.accusers.values():
            value = _decay(weight, now - at, self._halflife)
            if value > loudest.get(family, 0.0):
                loudest[family] = value
        return {family: value for family, value in loudest.items() if value > 0.0}

    def voices(self, node_id: NodeID, *, now: float | None = None) -> int:
        """Independent families accusing this node, out of however many nodes
        did. The number the score is actually made of — computed from the same
        grouping the score is, so the two cannot come to disagree — and shown
        beside the other one rather than instead of it."""
        entry = self._standings.get(node_id.raw)
        if entry is None:
            return 0
        stamp = time.monotonic() if now is None else now
        return len(self._by_family(entry, stamp))

    def standing(self, node_id: NodeID, *, now: float | None = None) -> str:
        value = self.score(node_id, now=now)
        if value >= self._hostile:
            return HOSTILE
        if value >= self._suspect:
            return SUSPECT
        return OK

    def direct_standing(self, node_id: NodeID, *,
                        now: float | None = None) -> str:
        """The standing this node would have on **our own evidence alone**.

        Asked before we tell the network anything. A node that crossed a
        threshold because other people said so has been judged by us, which is
        our business; repeating it under our own signature would make it
        everybody's, and each hop would turn one node's opinion into a fresh
        independent accuser. That is how hearsay launders into testimony, and
        it is the shape of a censorship primitive."""
        entry = self._standings.get(node_id.raw)
        if entry is None:
            return OK
        stamp = time.monotonic() if now is None else now
        value = _decay(entry.direct, stamp - entry.at, self._halflife)
        if value >= self._hostile:
            return HOSTILE
        return SUSPECT if value >= self._suspect else OK

    def is_hostile(self, node_id: NodeID) -> bool:
        return self.standing(node_id) == HOSTILE

    def is_suspect(self, node_id: NodeID) -> bool:
        return self.standing(node_id) != OK

    def rows(self, limit: int = 64) -> list[dict]:
        """Worst first, for the console. Nodes we hold nothing against are not
        listed: an empty table is the normal state and says so."""
        now = time.monotonic()
        rows = []
        for raw, entry in self._standings.items():
            value = self.score(NodeID(raw), now=now)
            if value <= 0.0:
                continue
            rows.append({
                "node": raw.hex(),
                "score": round(value, 2),
                "standing": (HOSTILE if value >= self._hostile
                             else SUSPECT if value >= self._suspect else OK),
                "accusers": len(entry.accusers),
                "voices": self.voices(NodeID(raw), now=now),
                "reports": entry.reports,
                "reason": entry.reason,
            })
        rows.sort(key=lambda row: row["score"], reverse=True)
        return rows[:limit]

    def __len__(self) -> int:
        return len(self._standings)

    # -- housekeeping -----------------------------------------------------

    def _entry(self, raw: bytes) -> _Standing:
        entry = self._standings.get(raw)
        if entry is None:
            entry = self._standings[raw] = _Standing()
            entry.at = time.monotonic()
        return entry

    def _enforce_bound(self) -> None:
        """Evict the *least* suspect first.

        The usual oldest-first would be exactly backwards here: an attacker
        holding identities cheaply would mint fresh ones until the node it
        actually cares about aged out of the table, and walk back in clean."""
        if len(self._standings) <= self._max_tracked:
            return
        now = time.monotonic()
        ranked = sorted(self._standings,
                        key=lambda raw: self.score(NodeID(raw), now=now))
        for raw in ranked[:len(self._standings) - self._max_tracked]:
            del self._standings[raw]


class RateGate:
    """A per-sender allowance an application can hold, and what it does when
    one is spent.

    Every app that has ever needed this wrote its own — fleet counts requests
    per window, the core counts gossip per link, chat counts messages — and each
    one wrote it slightly differently. The thresholds still belong to the app
    (only chat knows what too many messages is), but the *shape* does not, and
    neither does what happens next: the app reports the sender and the node
    decides, because weighing one app's complaint against another's is a
    node-wide judgement, not an app's.

    Bounded by construction: senders are forgotten oldest-first, so tracking
    cannot itself become the memory the flood was after."""

    __slots__ = ("_max", "_window", "_max_senders", "_seen")

    def __init__(self, max_events: int, window: float,
                 max_senders: int = 512) -> None:
        self._max = max(1, int(max_events))
        self._window = max(0.001, float(window))
        self._max_senders = max(1, int(max_senders))
        self._seen: dict[bytes, tuple[int, float]] = {}

    def allow(self, sender: NodeID, *, now: float | None = None) -> bool:
        """Claim one event. ``False`` once the sender is over its allowance —
        which is the moment the caller should report it."""
        stamp = time.monotonic() if now is None else now
        for key in [k for k, (_n, start) in self._seen.items()
                    if stamp - start > self._window]:
            del self._seen[key]
        while len(self._seen) >= self._max_senders and sender.raw not in self._seen:
            self._seen.pop(next(iter(self._seen)), None)
        count, start = self._seen.get(sender.raw, (0, stamp))
        if stamp - start > self._window:
            count, start = 0, stamp
        count += 1
        self._seen[sender.raw] = (count, start)
        return count <= self._max

    def forget(self, sender: NodeID) -> None:
        self._seen.pop(sender.raw, None)
