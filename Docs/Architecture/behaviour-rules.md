# Detecting a node that is not playing the protocol

**Status: mostly a catalogue.** It is the list of things worth measuring,
written down before any of it is built, so that what does get built is chosen
rather than accumulated. Each rule carries what it costs and how much it is
worth believing, because both decide whether it deserves to exist at all.

**Implemented so far** (`src/behaviour.py`, swept from the keepalive loop):
**M1** — the self-disarm, first, because it is what makes the rest safe to
switch on — plus **M5**, **A1**, **C1**, **D2**, **E1**, **E2** and **D5**.
**G2**, **G3** and **G4** live in the release path
(`MeshNode.may_auto_install`), and the genealogy half of **A2/G1** is there too,
as the independence test on a quorum (`CertStore.ancestors` /
`shared_ancestor`). Everything else below is still a description.

**D5 added a second response class.** Most rules score, and the ledger decides
what the scores add up to. D5 can only ever *notify*: its honest lookalike is
"the operator upgraded that machine", which is the common case by far, and
scoring it would punish somebody for administering their own fleet. So a rule
now carries `response` — `SCORE` or `NOTICE` — and a test asserts a notifying
rule is worth nothing to the ledger, because otherwise the distinction would
decay into a weight somebody quietly raised.

**M5 made the weights mean something.** Every rule here reads a *cumulative*
counter, so a rule that becomes true tends to stay true — and the sweep runs
every twenty seconds against a ledger that halves every hour. Charging per
sweep, the weakest rule in the file reached the hostile threshold on its own in
under seven minutes, whatever its weight said and whatever its `wrong_when`
promised. A rule now charges one subject at most once per half-life, so a rule
that never stops firing converges on *twice its weight* — and doctrine 3 stops
being a promise and becomes an inequality a test asserts.

The frame is the part that matters and it is done: rules are named, weighted,
compared against the peer group rather than a constant, and hand their findings
to the ledger rather than acting. Adding a rule is now writing a `Rule` and its
`wrong_when` — and a test asserts every rule has one, because a rule whose
honest lookalike cannot be stated is a superstition.

Related, and already built:
[`security.md`](security.md) (the reputation ledger, the accusation format, the
capability negotiation), [`routing.md`](routing.md), [`protocol.md`](protocol.md).

---

## The doctrine

Seven rules about the rules. Every entry below is subordinate to these, and an
entry that cannot satisfy them does not get implemented however clever it is.

**1. A rule may never cost latency.** The hot path increments integer counters
and nothing else — no hashing, no allocation, no walk, no clock arithmetic
beyond one subtraction. Judgement runs on a timer that already exists (the
keepalive sweep). A detector that makes the mesh slower has already done more
damage than what it detects.

**2. A rule compares a peer to its peer group, not to a constant.** Absolute
thresholds are wrong on every deployment but the one they were tuned on, and
they punish the slow medium rather than the bad actor. Compare against the
median of comparable peers — comparable meaning *same transport class*: a LoRa
peer and a TCP peer share no baseline worth having.

**3. No single rule ever bans.** Rules feed the score in
[`reputation.py`](../../src/reputation.py); the ledger decides. A rule that
directly cuts a peer off is a rule whose false-positive rate is now an outage.

**4. Unknown is not hostile.** The capability negotiation exists precisely so
that "I do not understand this" and "you should not have sent this" are
different events. Any rule that fires on unfamiliarity — a name we do not know,
a message type we have not seen, a version ahead of ours — is a rule that
isolates the future of the network. See the anti-rules at the end; they are not
an afterthought.

**5. A rule is a claim about the *peer*, never about the network.** If a signal
fires on most of our peers at once, it is measuring **us** — our clock, our
config, our uplink. Such a rule must disarm itself (see M1).

**6. A condition is charged once, not once per sweep.** A rule fires on a
state, and every state here is read off a counter that only goes up: once true
it stays true long after the peer stopped. The sweep, meanwhile, runs on the
keepalive. Charge per sweep and the *repetition* decides, not the weight — see
M5. Charge once per half-life and a permanent condition settles at twice the
rule's weight, which is the arithmetic that makes doctrine 3 true rather than
intended.

**7. Every rule is falsifiable and named.** It states what would make it wrong,
and its identifier travels with the report, so an operator reading "cut off for
G2" can go and read G2 and disagree.

### How an entry is written

| Field | Meaning |
|---|---|
| **Signal** | What is measured. |
| **Why** | What a correct node does instead. If this cannot be answered crisply, the rule is a superstition. |
| **Cost** | `O(1)` = a counter on the hot path. `sweep` = computed on the existing timer. `walk` = needs a graph traversal, so it runs rarely and bounded. |
| **Confidence** | `weak` (nudge only), `moderate`, `strong` (may, with corroboration, reach hostile). |
| **Wrong when** | The honest case that looks identical. Every rule has one. |

---

## A. Genealogy — reading the chain of trust as a graph

The certificate store is already a graph of who vouched for whom. Nobody has
ever queried it as one. This family is the highest-value and the least explored,
because it is the only place an attacker's *structure* shows: identities are
free, but a plausible ancestry is not.

### A1 — Sybil burst under one ancestor
**Signal** New identities appearing within a short window whose chains converge
on a single issuer, relative to that issuer's own historical rate.
**Why** An honest issuer admits nodes at human pace. Minting is what a Sybil
attack *is*, and the certificate chain is where it is visible.
**Cost** sweep (issuer counter per window) · **Confidence** moderate
**Wrong when** A real deployment rolls out fifty machines on a Tuesday. Hence:
the signal is the *deviation from that issuer's own history*, and a first-seen
issuer has no history, so it gets no accusation — only a lower weight in
anything else it says.

**Built** (`IssuerBook`, and `MeshNode._note_cert_arrival` on the counting
side). Four things decide whether it defends or attacks:

- **An issuer is compared to itself, never to other issuers.** A hobbyist's
  root admitting one node a month and a datacentre's admitting thirty a day are
  both correct, and the constant that separates them does not exist.
- **Joining a network is itself a burst** — on the first day everything is new
  to us — so an issuer earns the right to be judged by being watched over
  `ISSUER_MATURITY` windows. The same maturity requirement is what gives a
  first-seen issuer the answer above, without a special case for it.
- **A window in which an issuer admitted nobody is folded in at zero.** Leave
  those windows out and a burst hides behind the quiet that preceded it.
- **It notifies; it never scores.** The honest lookalike is provisioning day,
  and a rule that sanctions an operator for administering their own fleet is
  worse than no rule. The console offers "that was me", which drops the notice
  and the issuer's rate with it.

The counting side is where the bound is. An arrival is an `(issuer, subject)`
*pair*, held in a bounded set until the next sweep: a peer that could make us
count one subject twice — by offering it again after the store's own limits
evicted it — could otherwise manufacture a burst under any issuer it chose. It
can still cost that issuer a **notice**, which is all A1 ever produces.

### A2 — Correlated novelty: new subtree, new signing key
**Signal** A group of nodes sharing a common ancestor (at any depth) appears,
**and** announces a release signed by a publisher key nobody had seen before.
**Why** Two independent unlikely things arriving together are one event, not
two. Legitimate new code comes from a key that has been around, or arrives at
nodes that have been around; both being new at once is the shape of an attacker
who built a subtree in order to have somewhere to publish from.
**Cost** walk (ancestor set per publisher's announcers) · **Confidence** strong
**Wrong when** A genuinely new organisation joins and immediately publishes its
own build. The response is therefore *never auto-install* — not *cut off*.

### A3 — Chain depth far from the network norm
**Signal** A chain markedly deeper than the median depth we see.
**Why** Depth is how far the delegation went. A network where everyone is two
hops from a root, plus one branch six deep, means somebody built a hierarchy.
**Cost** sweep · **Confidence** weak
**Wrong when** A federated deployment legitimately delegates. Weak on its own;
useful with A1.

### A4 — Issuer fan-out acceleration
**Signal** An issuer's certification rate jumps by orders of magnitude.
**Why** A compromised issuer key is used hard and fast; an honest one is not.
**Cost** sweep · **Confidence** moderate
**Wrong when** Provisioning day. Pair with A5 — a real rollout produces nodes
that then *talk to each other and to everyone*.

### A5 — Low-conductance region (the branch that only talks to itself)
**Signal** A set of identities whose observed links are almost entirely internal
to the set, plus a thin edge to us.
**Why** This is the graph signature of a Sybil region and it is expensive to
fake: to look connected, the attacker must actually carry other people's
traffic, which costs real resources and makes the attack less useful.
**Cost** walk, rare · **Confidence** strong (as a group signal, never per node)
**Wrong when** A genuinely isolated site behind one uplink. Note the response:
this lowers the *weight of that group's testimony*, it does not cut anybody off.

### A6 — Vouched for by the recently disowned
**Signal** A chain passing through an issuer that was revoked or expired within
the last window.
**Why** Already fatal for verification. Worth *counting* separately: a peer that
keeps presenting chains through a dead issuer is either not updating or hoping.
**Cost** O(1) · **Confidence** weak

### A7 — Timestamp inversion inside a chain
**Signal** A certificate whose `issued_at` precedes its own issuer's.
**Why** An issuer cannot vouch before it existed. This is a forged or
back-dated chain, or a badly broken clock.
**Cost** O(1) at parse · **Confidence** strong
**Wrong when** Clocks. Which is why it is a *strict* inversion beyond skew.
**Correction, from building the renewal:** an issuer whose own certificate was
renewed carries an `issued_at` **later** than the certificates it signed before
the renewal, and every one of those chains is honest. So the inversion this
entry describes is a normal state of a healthy network, and refusing on it would
have cut off every node whose issuer renewed. It survives only as something to
*count*, weakly, and never as a verification rule.

### A8 — Certificate older than first sighting, by a lot
**Signal** A node presenting a year-old certificate that nobody in our view has
ever mentioned.
**Why** Not proof of anything — a node can be offline for a year — but combined
with A2 it is the "prepared identity" pattern: certificates minted in advance
and held.
**Cost** sweep · **Confidence** weak

### A9 — Identity shopping
**Signal** One subject certified by two unrelated roots within a short window.
**Why** An honest node joins a network. A node joining several unrelated ones
simultaneously is either a deliberate bridge (fine, and rare) or looking for the
anchor that gets it furthest.
**Cost** sweep · **Confidence** weak

### A10 — Re-admission churn
**Signal** An identity revoked by one issuer and certified by another
immediately after.
**Why** Someone was told no and found a yes. Worth surfacing to an operator even
when it is legitimate.
**Cost** O(1) on revocation absorb · **Confidence** moderate

### A11 — Ancestry concentration in our own routing table
**Signal** The share of our routing table descending from a single issuer
crossing a ceiling.
**Why** This is the precursor to an eclipse: before an attacker controls what we
see, it must first *be* most of what we see. Measuring it is how the eclipse is
noticed before it works.
**Cost** sweep · **Confidence** moderate — and the response is not a sanction,
it is **go and find peers elsewhere** (diversify the neighbourhood).

### A12 — Two chains, one identity
**Signal** The same node presenting different chains on different links, or over
time, that anchor differently.
**Why** Legitimate (a node in two networks) but it is exactly how a node
presents one face to one region and another elsewhere.
**Cost** O(1) · **Confidence** weak, **strong** if the two chains disagree about
the node's *key*.

---

## B. Identity and keys

### B1 — Id not derived from the key
Already fatal everywhere. Listed so the catalogue is complete, and because it
should be *counted* as well as refused: a peer that tries it once is broken, a
peer that tries it a hundred times is probing.
**Cost** O(1) · **Confidence** strong

### B2 — Id grinding near a target
**Signal** New identities whose ids fall unusually close (XOR) to a key we are
known to publish or to a node we are known to talk to.
**Why** Kademlia position is the one thing about an id that matters, and it is
grindable. Ids clustering around a valuable point were chosen, not generated.
**Cost** sweep · **Confidence** strong (the birthday maths makes coincidence
implausible fast)
**Wrong when** Small networks, where everything is close to everything.

### B3 — Bucket flooding
**Signal** A burst of new identities landing in one k-bucket.
**Why** The cheapest eclipse: fill the bucket that routes toward the target.
**Cost** O(1) at routing insert · **Confidence** moderate

### B4 — One address, many identities over time
**Signal** The same observed IP/port presenting a succession of node ids.
**Why** Identity rotation to shed a reputation — which is precisely what the
per-identity counter exists to catch, and this catches the other half.
**Cost** O(1) · **Confidence** moderate
**Wrong when** Carrier-grade NAT, a shared relay, a datacentre. Never on its own.

### B5 — Address churn
**Signal** A node changing its advertised addresses far more often than its
transport class implies.
**Why** Evading address-based blocking, or a broken announce loop.
**Cost** O(1) · **Confidence** weak
**Wrong when** Mobile. Genuinely mobile nodes are the point of the project — so
weak, always, and never alone.

### B6 — Near-collision pseudo
**Signal** A claimed name within a small edit distance of a name already
well-established in our book.
**Why** Non-canonical forms are already refused; this is the *canonical*
impersonation — `alice` and `alicе`-with-a-Latin-e-that-is-legitimately-Latin.
**Cost** sweep · **Confidence** weak — a pseudo decides nothing, so the response
is to **show both** in the interface, never to sanction.

---

## C. Protocol conformance

This family only became possible with the capability negotiation. Before it,
every one of these rules would have fired on any node newer than us.

### C1 — Behaviour changed, declaration did not
**Signal** A peer starts using a plane it never announced, or stops answering
one it did, without a new `CAPABILITIES`.
**Why** The declaration is cheap and the protocol requires re-announcing after
authentication; a node whose code changed underneath a live session and did not
say so is either not the node it was a moment ago, or is testing what we accept.
**Cost** O(1) (message type → plane, one lookup) · **Confidence** strong
**Wrong when** A node restarting mid-session and reusing a persisted session.
Which is why the *right* fix is that a restart re-announces — and the rule is
what makes that a requirement rather than a nicety.

### C2 — The pre-auth and post-auth announcements differ
**Signal** The set announced before authentication is not the set announced
after.
**Why** Either a machine in the middle stripped names, or the peer lied to the
unauthenticated exchange. Both are worth knowing; the first is worth knowing
loudly, because it means somebody is on the path.
**Cost** O(1) · **Confidence** strong

### C3 — Declaration and behaviour diverge over time
**Signal** A peer announcing a broad set that only ever exercises one plane, or
announcing a narrow set and pushing at the edges of others.
**Why** An honest set is a description. A set chosen to maximise what it is
excused for is not.
**Cost** sweep · **Confidence** weak

### C4 — Boundary probing
**Signal** Repeated fields at exactly the maximum permitted value, across
different message types.
**Why** Correct clients produce a distribution of sizes. Something producing
`MAX` every time is measuring where the wall is.
**Cost** O(1) · **Confidence** moderate
**Wrong when** A chunked transfer, where full chunks are the norm — so exclude
the planes where `MAX` is the honest value.

### C5 — Implausible TTL
**Signal** TTL on arrival inconsistent with any path we believe exists.
**Why** A forged hop count, or a loop.
**Cost** O(1) · **Confidence** weak

### C6 — Version claimed, version behaved
**Signal** A node announcing a release version whose protocol behaviour does not
match what that version is known to do.
**Why** Claiming to be a build in order to be excused for what that build does.
**Cost** sweep · **Confidence** moderate — and it requires the network to have a
notion of "what that version does", which is itself worth building.

---

## D. Traffic shape

Everything here is derived from counters the metrics layer already keeps. Nothing
in this family may add a measurement to the hot path.

### D1 — Machine regularity
**Signal** Inter-arrival variance near zero.
**Why** Human-driven traffic jitters. A perfectly periodic sender is a loop, and
loops are what floods are made of.
**Cost** O(1) (running variance, two adds) · **Confidence** weak
**Wrong when** Keepalives, sensors, any legitimately periodic app. Exclude the
planes that are *supposed* to be periodic.

### D2 — Send/receive asymmetry
**Signal** Bytes out to a peer vastly exceeding bytes in, or the reverse,
against the median for that transport class.
**Why** A relay is roughly symmetric. A sink or a firehose is not.
**Cost** O(1) (already counted) · **Confidence** weak

### D3 — Blackholing
**Signal** We route through this peer and the destination never responds, at a
rate above the network's baseline loss.
**Why** Accepting traffic and dropping it is the cheapest attack on a mesh and
leaves no other trace.
**Cost** sweep (correlate sends with acks we already track) · **Confidence**
moderate
**Wrong when** The far end is genuinely gone. Hence: compare per-peer failure
rate against the *same destination reached other ways*.

### D4 — Amplification seeking
**Signal** Small requests yielding large replies, at rate, from one peer.
**Why** The classic reflection setup. Every plane already has a valve; this is
the cross-plane view none of them has.
**Cost** O(1) · **Confidence** moderate

### D5 — Profile break on an established peer
**Signal** A peer with months of stable behaviour changing shape abruptly.
**Why** **This is the compromise signal**, and it is the one thing an attacker
who steals a key cannot avoid: they have the identity but not the habits.
Everything else in this catalogue detects a *new* adversary; this detects the
one that was already trusted.
**Cost** sweep · **Confidence** moderate
**Wrong when** The operator upgraded, or changed what the node does. So the
response is to **ask the operator**, not to cut — a notification, not a sanction.

### D6 — Timer synchronisation
**Signal** Bursts arriving aligned to our own sweep periods.
**Why** Something is watching our timing and shaping traffic around it.
**Cost** sweep · **Confidence** weak, but very hard to explain innocently.

### D7 — Directional clock drift
**Signal** A peer's timestamps drifting steadily against ours.
**Why** Ordinary skew is noise. Steady one-way drift is a clock being *moved* —
and several defences here (accusation freshness, claim ordering, certificate
expiry) are keyed on time.
**Cost** O(1) · **Confidence** weak

---

## E. Routing behaviour

### E1 — Self-promotion
**Signal** A peer returning itself in `FOUND_NODE` far more often than proximity
justifies.
**Why** The first move of every eclipse.
**Cost** O(1) · **Confidence** moderate

### E2 — Disjoint answers
**Signal** For the same target, this peer's answer shares almost nothing with
what everyone else returns.
**Why** Either it knows a different part of the network (interesting) or it is
steering us into a region it controls (also interesting).
**Cost** sweep, only when we already query several peers · **Confidence** strong
**Wrong when** A genuinely partitioned mesh — which this same signal is the best
way to *notice*.

**Built.** Counted in `MeshNode._note_answer_overlap`, on the lookup's own timer
and never on a packet's: a Kademlia round already holds several answers to one
question, so the comparison costs a set intersection over ids we have in hand.
Three things it does not do:

- **It does not test for an empty intersection.** A peer steering us into a
  region it controls can pad its answer with one id everybody knows, and
  emptiness is cleared by exactly that. Overlap is a *share* of the answer.
- **It does not judge a small answer.** Two honest nodes may name two different
  closest candidates; below `MIN_ANSWER_SIZE` there is nothing to disagree
  about.
- **It does not charge a node we only reach through relays.** That answer was
  handled by nodes other than the one that signed it, and charging the far end
  for what the path did names whoever is innocent.

The partition case answers itself, and before the disarm has to: a majority
that sees a different network *is* the median it is compared against, so nobody
is an outlier against it. The rule does not fire and then get silenced — it does
not fire.

**Known limit, stated rather than hidden:** two colluding answerers in one round
can make an *honest* third look disjoint, because "everybody else" is whoever
else we happened to ask. There is no fix inside this rule — independence between
answerers is exactly what we do not know — so the answer is the one M5 gives
every rule here: the framed peer accrues at most twice E2's weight however long
it goes on, which is not enough to reach any threshold on its own. A signal that
can be gamed and cannot sanction alone is worth having; the same signal able to
sanction alone would be a weapon handed to whoever can afford two identities.

### E3 — Omniscience
**Signal** A peer answering usefully for every region of the keyspace.
**Why** Real routing tables have shape. A node closest to everything is lying.
**Cost** sweep · **Confidence** moderate

### E4 — Addresses that never connect
**Signal** A peer advertising endpoints that consistently fail to dial.
**Why** Padding the address list to look reachable, or pointing us at a victim.
**Cost** O(1) (dial outcomes already known) · **Confidence** weak
**Wrong when** NAT, which is the normal case. Weak forever.

### E5 — Third-party address announcement
**Signal** Announcing addresses for *another* node that we can show belong to
somebody else.
**Why** Redirection: making us dial a victim, or intercept.
**Cost** sweep · **Confidence** strong

### E6 — Store/serve asymmetry
**Signal** Accepts `STORE` and never returns the value.
**Why** Consuming the network's storage without providing any, or quietly
censoring specific keys.
**Cost** sweep · **Confidence** moderate

---

## F. Gossip

### F1 — Re-gossiping what we sent it
**Signal** Returning an epidemic item to its immediate source.
**Why** Every plane's terminating rule forbids it. Doing it doubles traffic per
hop and is the shape of an amplification loop.
**Cost** O(1) · **Confidence** moderate

### F2 — Relaying what it did not verify
**Signal** Forwarding claims/records whose signatures do not check.
**Why** Already charged today. Kept here because it is the cleanest "not running
the protocol" signal there is: an honest relay verifies before re-sending.
**Cost** O(1) · **Confidence** strong

### F3 — Accusation patterns
**Signal** A node that accuses many distinct nodes; accuses only nodes in one
subtree; or accuses whoever accused it, immediately.
**Why** The reputation plane is the one an attacker most wants to hold, and
these are its three tells: volume, targeting, and retaliation.
**Cost** sweep · **Confidence** strong — and the response is to **stop counting
its accusations**, which is already how the ledger treats a suspect accuser.

### F4 — Choreographed accusations
**Signal** Several nodes emitting near-identical accusations inside a tight
window, especially when they share an ancestor (→ A5).
**Why** Independent observers do not agree to the second. This is the "I created
200 nodes" attack seen from the receiving end.
**Cost** sweep · **Confidence** strong, as a *group* signal that discounts the
whole group's testimony.

### F5 — Testimony about the unreachable
**Signal** Reporting abuse from a node it has no plausible path to.
**Why** It is not testifying, it is voting.
**Cost** sweep · **Confidence** moderate

---

## G. The update chain

The highest-authority payload the mesh carries. Every rule here defaults to
**do not auto-install** rather than to a sanction: refusing an update is
recoverable, installing a hostile one is not.

### G1 — New key, new family, one moment (the headline case)
**Signal** A release signed by a previously unseen publisher, announced
predominantly by nodes that share a recent common ancestor.
**Why** As A2. The attacker needs somewhere to publish *from*, and building that
somewhere leaves a subtree.
**Cost** walk · **Confidence** strong → **never auto-install**

### G2 — Corroboration deficit
**Signal** Fewer than *K* independent attestations of the same `(version,
content hash)`.
**Why** **Serving bytes is not vouching.** Mirroring a package is free and
proves nothing — content addressing already makes the bytes safe to fetch from
anyone. What costs an attacker something is *independent signatures over the
same hash*. Corroboration must therefore be counted in signers, never in
servers.
**Cost** O(1) per descriptor · **Confidence** strong → the gate for
zero-interaction installs.

### G3 — Hash disagreement
**Signal** Two publishers signing different content for the same version.
**Why** A fork or an attack. Either way, not something to install unattended.
**Cost** O(1) · **Confidence** strong

### G4 — One key, two hashes
**Signal** A single publisher signing two different hashes for one version.
**Why** A publisher that contradicts itself has either lost its key or is
serving different code to different people.
**Cost** O(1) · **Confidence** strong

### G5 — Instant publisher
**Signal** A publisher key first seen and publishing within the same window.
**Why** Reputation for a signing key is time. A key with none has none.
**Cost** O(1) · **Confidence** moderate

### G6 — Version leap
**Signal** A version far beyond the spread observed across the network.
**Why** Skipping ahead is how you get installed before anyone can compare.
**Cost** sweep · **Confidence** moderate

### G7 — Backwards under a fresh timestamp
**Signal** An older version re-announced with a newer signed timestamp.
**Why** A downgrade to reachable bugs. The catalogue's monotonic `ts` already
blocks the replay; this catches the *re-signed* version of it.
**Cost** O(1) · **Confidence** strong

### G8 — Announced only by newcomers
**Signal** Every announcer of a release joined recently.
**Why** Real code spreads through nodes that were already there.
**Cost** sweep · **Confidence** moderate

### G9 — Reproducibility mismatch
**Signal** A build that does not reproduce to the hash its publisher signed.
**Why** The strongest available statement about code provenance — and the one
thing "compare the source to what we already have" can honestly become.
**Cost** offline, expensive · **Confidence** strong where available.
**Note** Comparing to previously downloaded source proves *similarity*, never
good faith: an attacker's build is mostly the real code by construction. Only
independent parties arriving at the *same hash* says anything.

---

## H. Application layer

### H1 — Per-kind allowance breach
Built (see [`app_guard.py`](../../src/app_guard.py)). Listed for completeness.

### H2 — Messages into conversations it is not in
**Signal** Group traffic for groups whose roster does not contain the sender.
**Cost** O(1) · **Confidence** strong

### H3 — Reservation without use
**Signal** File offers never followed by chunks; streams opened and never fed.
**Why** Reserving the reassembly buffers that bound the app.
**Cost** sweep · **Confidence** moderate

### H4 — Chunks for an offer that never came
**Signal** Transfer data for ids never announced.
**Cost** O(1) · **Confidence** moderate

### H5 — Receipt probing
**Signal** Read receipts for message ids that never existed.
**Why** Enumerating what we hold — an oracle for message existence.
**Cost** O(1) · **Confidence** strong

---

## M. Meta — rules about the rules

### M1 — A rule that fires on everyone disarms itself
**Signal** A rule's fire rate across distinct peers crosses a ceiling.
**Why** Doctrine 5. If most peers look wrong, we are wrong: our clock is off,
our uplink is bad, our config is unusual. A detector that keeps accusing under
those conditions turns a local fault into a network-wide fight.
**Response** The rule stops contributing and says so in the console. This is not
an optimisation; it is what makes the whole family safe to deploy.

### M2 — Corroborated signals count more than their sum
**Signal** Several independent families firing on one peer.
**Why** Any one of these has an honest explanation. A2 (genealogy) *and* D5
(profile break) *and* F3 (accusation pattern) do not have one explanation
between them.
**Response** Superlinear weight — but still through the ledger, still never a
direct ban.

### M3 — Group signals discount testimony, they do not sanction
**Signal** Anything computed over a *set* of nodes (A5, F4).
**Why** Group guilt is how a reputation system becomes a purge. A cluster that
looks coordinated should stop being *believed*; its members should not be cut
off for the company they keep.

### M4 — Every judgement is explainable
Any score change carries the rule id that caused it, and the console shows it.
An operator must be able to read why, disagree, and clear it — the ledger
already has `console_forgive` for exactly this.

### M5 — A condition is charged once, not once per sweep
**Signal** The same rule firing on the same subject, sweep after sweep, over a
state that has not changed.
**Why** Doctrine 6, and the arithmetic behind doctrine 3. Every rule in this
catalogue reads a counter that only goes up, so a rule that becomes true stays
true; the sweep runs every twenty seconds and the ledger halves every hour.
Charged per sweep, a rule worth 1.0 settles at about **260** against a hostile
threshold of 20 — so "weak" and "strong" described nothing and every rule
sanctioned alone within minutes. D2, whose entry says in as many words that it
means nothing without something else, would have cut off a quiet consumer.
**Response** One charge per subject per rule per half-life. A permanently
firing rule then converges on twice its weight, and
`test_no_single_rule_can_reach_suspect` asserts that this is below the point
where anything happens — so corroboration between rules is what crosses a
threshold, which is what the catalogue said all along.
**Note** The charge is dropped when an operator answers a notice ("that was
me"), or the next finding would be dated from before they answered.

---

## The anti-rules

Things that must **never** become signals, however tempting. Each one has been a
real mistake in some real system.

- **Being new.** Every honest node is new once.
- **Being slow, lossy, or high-latency.** That is the entire point of a
  transport-agnostic mesh. A LoRa node is not a bad TCP node.
- **Running a version we do not have.** Doctrine 4. This one is how a network
  freezes: the majority stops accepting the minority that upgraded, so nobody
  upgrades again.
- **Speaking a capability we do not know.** Same, and it is the specific case the
  negotiation was built to make safe.
- **Changing address, or being behind NAT.** Mobile nodes are a requirement.
- **Low uptime.** Store-and-forward over a USB stick is a supported transport.
- **Being reported by strangers.** Already the ledger's rule; repeated because it
  is the one that turns a defence into a weapon.
- **Anything derived from IP geography or ASN.** Wrong, unfair, and trivially
  spoofed.
- **Sending unusually little.** A quiet node is a node.

---

## The response ladder

| Confidence reached | What happens |
|---|---|
| weak, alone | Counted. Nothing else. Visible in the console. |
| moderate, alone | Counted, and the peer is deprioritised for routing — we prefer others, we do not refuse it. |
| strong, alone | Score contribution large enough to matter — and, by M5, still below the tarpit on its own however long it goes on. |
| corroborated (M2) | May cross `abuse_suspect` → the peer stops being served, silently. |
| first-hand + corroborated | May cross `abuse_hostile` → refused a fresh link. |
| any group signal | Discounts the group's *testimony* only (M3). |
| any update-chain rule | Refuses the unattended install. Never a sanction. |

Nothing in this table is reached by hearsay alone; that invariant belongs to the
ledger and this catalogue does not get to weaken it.

---

## Where to start

If only three of these are ever built, they should be the three that cover the
three different adversaries:

1. **G2 (corroboration deficit)** — the only one guarding the payload that can
   replace the node's own code. Cheapest to build, largest consequence.
2. **A2/G1 (correlated novelty)** — the attacker who prepares. It is the rule
   this catalogue was started for, and the genealogy it needs is already sitting
   unqueried in the certificate store.
3. **D5 (profile break)** — the attacker who was already trusted. Everything
   else here detects strangers; only this one detects a stolen key.

And **M1** before any of them, because it is what makes deploying the rest
survivable.
