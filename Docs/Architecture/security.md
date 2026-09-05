# Identity, crypto & trust

Source: `crypto.py`, `node_id.py`, `cert.py`, `cert_store.py`, `invite.py`, and
the handshake handlers in `node.py`.

## Identity

- `CryptoIdentity` (`crypto.py`) holds an **ML-DSA-65** pair (signature). The
  private key stays in memory; `save/load` persists it as raw binary under the
  state directory (`node.key`), **created 0600 at open time** (not a `chmod`
  afterwards, which would leave a window in which it could be read) and
  tightened again if a more permissive file is left over from an earlier
  version. The state directory itself is 700 and belongs to the node's
  dedicated account when `install.sh` put it there (see
  [`../Setup/guide`](../Setup/guide)).
- **A file that is there and unreadable raises**; only a missing one means
  "generate". `load` used to answer any failure with a fresh key pair, and the
  caller writes back what it gets — so one truncated write, one bad sector, one
  half-restored backup destroyed the identity permanently, and the symptom
  looked like a network fault. `load` also **checks the pair against itself**:
  nothing verified that the stored public half belonged to the stored secret,
  and a mismatched file produced a node whose signatures nobody could verify.
- `NodeID = sha256(DSA_public_key)[:20]` (`NodeID.from_public_key`). So **the ID
  is derivable from the key**: a `NodeID` that does not match the key presented
  is a lie → reject (`claimed_id != NodeID(packet.src_id)`).
- ML-KEM-768 is used **only** to negotiate a secret during the handshake;
  throughput after that is AES-256-GCM.

## Session keys (`SessionKey`)

- `SessionKey(shared_secret)` derives an AES-256 key with **HKDF-SHA256**
  (`info = b"nmesh-session-key"`).
- `from_key` rebuilds a session from the already-derived 32-byte key
  (persistence — we store the key, never the raw ML-KEM secret).
- `derive_secret` (HKDF over the DSA key) produces at-rest subkeys under the
  same trust boundary as the identity (encrypting the session store).

## Certificates & self-rooted P2P PKI

There is **no central authority**. Every node is its own self-signed root; trust
propagates through certificate chains.

- `Certificate` (`cert.py`): `subject_id/pub`, `issuer_id/pub`, `issued_at`,
  `expires_at`, `signature`. `signed_body()` covers everything but the
  signature. `_build()` **re-validates three invariants** on every
  (de)serialisation: `subject_id` derives from `subject_pub`, `issuer_id` from
  `issuer_pub`, and the issuer's signature is valid. → a malformed certificate
  raises before it ever reaches RAM.
- `issue_cert`: at the end of a handshake accepted by invitation, the host
  issues a certificate for the new node (attesting it as a member), included in
  the `HANDSHAKE_ACK`, valid **one year**. `self_signed_cert`: the root, which
  never expires (`expires_at == 0`).
- `Certificate.is_expired(now)` is the **one** definition of expired in the
  tree: the chain walk, the pruning and `verify_chain` all ask it rather than
  each comparing the field themselves.
- `CertStore` (`cert_store.py`): `subject_id → [certs]` plus a set of roots
  (`_roots`, containing at least ourselves).
  - `get_chain_to_root(target)`: a **BFS** through the issuance graph up to a
    root. **Prefers an external root** (the network): presenting our own
    self-signed root authenticates nothing to a peer; the network chain (through
    the issuer who invited us) is the only one anybody else can verify.
    **Expired certificates are not walked** — a chain carrying one is refused by
    every `verify_chain` on the network, so returning it is not a degraded
    answer but a wrong one. Among the live ones the **longest-lived wins**, or a
    renewal would sit unused beside the certificate it replaces until the day
    that one died. `now=` asks what we *would* present at another moment
    (the renewal sweep, the console) and bypasses the cache rather than
    poisoning it.
  - `chain_expires_at(target)` / `prune_expired(now)`: when the chain we present
    stops verifying, and dropping the certificates that already have. `add`
    refuses an expired certificate outright — it proves nothing and never will
    again, but it still costs a slot in a bounded list, so replaying old ones
    could crowd out the live certificate for a subject an attacker picked.
  - `verify_chain(chain)`: continuous issuance links + a self-signed last cert +
    the last `subject_id ∈ roots` + nothing expired → returns the anchor,
    otherwise None.
  - **Bounded** (`MAX_SUBJECTS`, `MAX_PER_SUBJECT`, LRU), with the roots and
    **every subject our own chain runs through** pinned (`_pinned`) — a bound
    that can leave us unable to authenticate is an outage, not a bound. Pinning
    the roots and ourselves is not enough: the intermediates are what join the
    two, and evicting one leaves `get_chain_to_root(own_id)` falling back to our
    self-signed chain, which nobody trusts. We would go on authenticating
    everyone else while nobody could authenticate us, and nothing would error
    anywhere. The per-subject trim never drops the certificate the chain is
    using either. `get_chain_to_root` is **memoised per subject** and the cache
    is dropped on any change — before the bounds run, since the bounds ask what
    the chain is made of. It is a BFS, `_handle_find_node` runs it once per
    candidate it considers, and an unbounded store made a 28-byte packet buy an
    unbounded graph walk. The cache entry also **expires with the earliest
    certificate in it**: that is the one way a memoised chain rots with nothing
    changing, and nothing cleared the cache for it.
  - **The root set is persisted state too.** Pinning one goes through
    `MeshNode._trust_root`, never `CertStore.add_root` directly: only `add` used
    to be paired with a "write me" mark, by convention, and `console_add_root`
    marked *before* pinning — so on the path that writes inline, the file went
    out without the root and the dirty flag was already cleared. The operator
    was told the certificate was trusted; the next start had never heard of it.

## Renewal: a membership that runs out is an outage nobody sees coming

A membership certificate lasts a year and **nothing renewed it**. On the day it
expired the node went on presenting a chain every peer refuses: it dropped out
of the mesh, no test failed, no counter moved, and the symptom looked exactly
like a network fault. Every deployment carried a dated outage.

`CERT_RENEW` / `CERT_RENEWED` (`node.py`, routable — the issuer is rarely still
a neighbour a year on) close it:

- `_cert_renewal_loop` sweeps every 6 h, first pass 30 s after start. It prunes
  what has expired and, when our own chain has less than `_CERT_RENEW_WINDOW`
  (30 days) left, sends the certificate back to its issuer.
- The issuer (`_handle_cert_renew`) can only ever re-sign a binding **it already
  made**: the subject, its key and the issuer are all fixed by the certificate
  presented, and `Certificate.deserialize` refuses one whose ids do not derive
  from its keys or whose signature does not check — so `issuer_id == our id` is
  proof we signed it. `packet.src_id` must be the subject. It costs one ML-DSA
  signature, so it is rate limited **per subject** (`_CERT_RENEW_MIN_GAP`, 1 h),
  never per link: reconnecting must not buy a fresh allowance, which is the hole
  the invite lockout had before it was counted node-wide.
- The two windows differ on purpose. A node asks a month out; the issuer serves
  anything within `_CERT_RENEW_ACCEPT` (3 months), so clock skew, a slow relayed
  path and a few missed sweeps can never turn a request made in time into a
  refusal.
- **An expired membership is never renewed.** Expiry is how a node that left
  stops being a member; re-signing one would be a readmission with no human in
  it. The way back is an invitation. This is also why the window is generous and
  the sweep frequent: the asking must happen while the chain still verifies,
  because a node that cannot authenticate has no link left to ask on.
- `_handle_cert_renewed` takes the answer only if it renews the binding we had —
  us as subject, our own key, and an issuer that has certified us before. A
  certificate from a stranger authenticates nothing anyway (it anchors on a root
  we do not trust), but absorbing one would let any node fill our own bounded
  slot list.
- `node.trust_status()` puts it on the console (Network → Membership): standing,
  countdown, issuer, anchor, chain length. A deadline an operator can act on
  rather than a fault they diagnose afterwards.
- **`standing` is one word for the whole answer**, computed there so nothing
  downstream re-derives it: `member` (a chain to a root somebody else signed),
  `root` (our own root, and we have vouched for others, so it *is* a root out
  there), `expired` (our own root only, but we still trust an anchor we did not
  sign — we were admitted once and are not any more), `none` (our own root only,
  and we trust nobody else's: nothing on the network will authenticate us).
  The last three all present a single self-signed certificate and are
  indistinguishable in every other field, while one of them works everywhere and
  two work nowhere. They are told apart by the anchors we trust and the
  certificates we have issued — both persisted — never by the expired
  certificate, which `add` refuses to read back and `prune_expired` deletes.
  A node whose standing is `expired` or `none` is refused in silence by every
  peer, which from the inside looks exactly like a broken network, so the
  console says it across the top of every page and not only on that card.

## Revocation: taking a membership back (`revocation.py`)

Expiry is the slow way out of a network. It is far too slow for the case this
exists for — a key that leaked this morning — and until it existed there was no
fast way at all: once a certificate was signed nothing in the tree could undo
it, and a compromised node stayed a full member until the following year.

A revocation is one signed sentence: **"I, the issuer, no longer vouch for this
subject, as of this moment."** Domain `nmesh-revocation-v1`.

- **Only the issuer may say it.** That is not a new authority, it is the one it
  already exercised by signing; and it needs no arbiter, because the signature
  *is* the claim and the issuer id derives from the key that made it. Nobody can
  revoke anybody else's members — which is exactly what stops this being a
  primitive for cutting nodes off the network. A revocation signed by a stranger
  names a pair we hold nothing for and voids nothing.
- **It names a moment, not a certificate.** Everything that issuer signed for
  that subject at or before its timestamp is void. Naming one certificate would
  leave whichever copy the attacker kept quiet about, and a subject may hold
  several from one issuer. A certificate issued *after* stands: an issuer that
  changes its mind signs again, so readmission stays a deliberate act.
- **A root cannot be revoked this way.** A root's certificate is self-signed, so
  the only node entitled to revoke it is itself — no use when the point is that
  it has gone bad, and `parse` refuses a record whose issuer and subject are the
  same node. Distrusting an anchor is `CertStore.remove_root`, a local decision
  by whoever runs the node, because there is nobody above a root to appeal to.
  Our own id is not removable: a node that is not its own root can present
  nothing at all.
- **`_usable(cert, now)` is the single predicate** — not expired *and* not
  revoked — asked by the chain walk, by `verify_chain` and by `add`. One
  revoked link voids the whole chain, not just its own hop: everything below it
  was vouched for *through* the node just disowned.
- **Bounded, pinned, persisted.** Revocations are kept for pairs whose
  certificates we may never have seen — forgetting one means accepting the
  certificate it voided next time somebody presents it — so `MAX_REVOCATIONS` is
  its own bound, and records signed by a **root we trust are pinned** against
  eviction: otherwise anyone able to mint revocations of their own members could
  flush the table and bring a revoked node back. They are saved with the store
  and **re-verified at load**, before the certificates, so `add` refuses what the
  same file says is void. A revocation that only held while the process happened
  to be running would be undone by a restart — the one moment a compromised
  member most wants.
- **Gossiped like a pseudo claim** (`CERT_REVOKE`, a direct type re-stamped at
  each hop, rate limited per link, bounded fan-out): passed on only when it told
  us something new, so the epidemic dies out. A record that does not verify is
  charged to the peer that sent it (an honest relay verifies before re-sending);
  one we already knew costs it nothing, because that is the ordinary end of an
  epidemic. `_schedule_revocation_sync` catches a freshly authenticated peer up,
  so a node that was offline for the compromise learns of it on reconnecting
  rather than from the next handshake it wrongly accepts.
- **Enforced, not merely recorded.** `_enforce_revocation` drops the E2E
  session, the routing entry and every live link to that node. A revocation that
  only changed what future handshakes decide has revoked nothing an attacker is
  currently using — the same judgement as the Fleet app tearing down the shells
  a withdrawn capability had opened.
- **Announce before you enforce.** `_announce_revocation` picks the fan-out
  *synchronously*, then sends in the background. Enforcing tears down every link
  to the node named, so a list computed when the background task finally ran
  could be empty: on a node whose only link was that node, the revocation died
  where it was issued and nobody else ever heard.

## Capability negotiation: two nodes build the protocol they share

Source: `features.py`, `CAPABILITIES` in `node.py`.

A version number was the obvious answer and the wrong one. It puts every build
on one line and forces a comparison — *newer* or *older* — which answers the
wrong question twice: it has nothing to say about a node implementing half the
protocol plus one thing of its own, and it turns "I do not know this message"
into "you are ahead of me", one short step from treating an unfamiliar peer as a
broken one.

So a node announces **a set of names for what it can speak**, and two nodes work
in the intersection (`features.agree`). A build with an extra plane and a build
without it agree on everything they share; a node with something entirely of its
own is not mis-versioned, it is a node whose set contains a name we do not
recognise, and that costs nobody anything.

**This is what makes behavioural judgement possible at all.** Without it, "a
message I do not understand" and "a message I should not have been sent" are the
same event, and anything judging behaviour has to guess which one it is looking
at. Guess one way and a node running tomorrow's build is reported by every node
running today's; guess the other and the judgement is worthless, because
everything unrecognised is excused.

Three rules, and they are load-bearing:

1. **The envelope never changes.** `BASE_VERSION` exists so a node can refuse a
   negotiation it cannot parse, and for nothing else. Everything that evolves
   evolves as a name in the set — a second version of this format would be the
   very problem it removes.
2. **Silence means the classic set.** `peer_speaks` returns True for a peer that
   has announced nothing: that is a node from before this existed, not one with
   no features. Read the other way, the negotiation would be an upgrade that
   cuts off everyone who has not taken it.
3. **Negotiation may only ever add.** No name switches off a check, weakens a
   cipher, skips a verification or widens an authorisation. The announcement
   happens *before* anybody has proved anything, so a name that could weaken
   something would be the way in. What is negotiated is only which **optional
   messages** are worth sending — the gossip planes, the directory, renewal,
   revocation, abuse reports. A test asserts no feature name reads like a check.

Mechanics: the announcement rides the round trip that was happening anyway (the
server sends it with its `CHALLENGE`, the client answers it on receiving one), so
it costs no extra exchange and no latency. It is reachable **pre-authentication**
on purpose — the point is knowing what to send *during* a join — and carries no
secret and grants nothing. It is re-sent once the link is authenticated, and
that record is the one that counts: until then the claim is unsigned, so a
machine in the middle could strip names from it. Stripping can only ever take
away an optional plane, which is exactly why rule 3 is not optional.

`node.negotiation_status()` shows, per link, what is shared, what they have that
we do not, and what we have that they do not.

## Zero trust: being in the network is not being trusted

Source: `reputation.py`, `accusation.py`, and `MeshNode.report_abuse`.

A membership says an issuer vouched for an identity **once**. It says nothing
about how that identity behaves afterwards, and an authenticated peer is exactly
the adversary the threat model names — a relay that alters, replays, amplifies
or floods. The only answer used to be `_Peer.note_abuse`, which counts frames a
*link* could not decode and cuts that link: right as far as it goes, and it goes
one hop. It forgets everything when the socket closes, so reconnecting shed the
count; it cannot hear what an application saw; and it cannot tell one node
holding four links from four nodes.

### Who decides what

- **The applications own the thresholds.** Only chat knows what too many
  messages is, only fleet knows what too many commands is. Each judges by its
  own numbers and reports the sender — in-process through
  `MeshNode.report_abuse`, or from another process through the connector's
  `_ABUSE` frame, where the app id comes from the session and never the frame,
  as for the drawer and the per-app DHT. `app_guard.AppGuard` is that loop
  written once with the reporting attached, so each app stops writing it
  slightly differently and stops forgetting the report — two of the three did.
  Its limits are **per kind**, not one bucket: a typing notice and a file offer
  are not comparable, and a shared ceiling sized for the loudest hands that same
  allowance to the expensive ones. The numbers stay the app's.
- **The node owns what the reports add up to.** Weighing one app's complaint
  against another's is not something one app can do. Thresholds live in
  `nmesh.conf` (`abuse_suspect`, `abuse_hostile`, `abuse_halflife`,
  `no_abuse_gossip`) — a node on a hostile link and a node among machines its
  operator installed want different numbers, and neither is one the code can
  guess. Those four settings are the **source** for `reputation.py`'s defaults,
  which read them back out rather than keeping a second copy.
- **Nothing is reported about ourselves**: a bug in an app must never make a
  node stop serving its own operator.
- One report is never on its own decisive (`MAX_WEIGHT`, strictly below
  `abuse_suspect` — when the two were equal, the strongest thing an app could
  say landed exactly on the line and the first decay tick put it back under).
  Evidence **fades** on a half-life, so a node that misbehaved once and then
  behaved comes back with nobody doing anything.

### What an accusation may not do

This is the dangerous part. If hearsay alone could get a node cut off, anybody
able to speak on the mesh could cut anybody off it — a censorship primitive with
a reputation label on it. So evidence lands in two buckets and they are not
equal:

- **direct** — what we saw ourselves, plus a witness the *operator* designated
  (`console_add_witness`; the natural entries are the Fleet operators this node
  is enrolled with, which is already where "I trust this specific node" lives).
  Only this bucket can reach hostile.
- **rumour** — ordinary members of our own network accusing. Never counted as
  how many *times*: repeating an accusation is free to send, so counting
  repetitions would price the mechanism at whatever the loudest node feels like
  paying. And no longer counted as how many *members* either — see below.
  Hard-capped strictly below the **suspect** threshold, so a swarm can bring a
  node to the edge of the judgement and never past it.

#### Two things that had to change here, and both were live

**The cap was one threshold too high.** It sat just below `hostile`, which read
as "a swarm can make this node wary but never cut anyone off" — except that
being wary is what `SUSPECT` *is*: a suspect peer has its traffic dropped and
its link tarpitted, in silence, which from where it is standing is being cut
off. Hearsay alone was decisive, and the price was eight certified identities.
The cap is now `suspect` minus a margin: what we saw ourselves is what carries a
node over, which is what "hearsay is never authority" was always supposed to
mean. Rumour still matters, and matters a great deal — it is what makes a single
first-hand observation enough.

**A verdict reached on hearsay was re-broadcast under our own key.** The
announcement fired on any crossing of the *combined* standing, so a crowd
convinced us, we signed their conclusion ourselves, and our neighbours counted
us as one more independent accuser. One node's opinion became as many as there
are hops, which is exactly the number the receiver is trying to count.
Announcing is now decided on the **direct** bucket alone and on its own
crossing (`MeshNode._maybe_announce`, which only `report_abuse` calls, so
nothing on the accusation-handling path can reach it). A designated witness is
believed here as if we had seen it — its word goes in the direct bucket — and is
still not repeated under our name: our neighbours did not designate it, and to
them our signature would be a second independent observation of one event.

#### How many voices a crowd is

"How many distinct members" was still the wrong count. It prices a voice at one
certified identity, and one compromised issuer mints those in an afternoon. What
makes several observations worth more than one is that they are **independent**,
so that is what is counted: the most any one *family* says, summed over the
families. A family is whoever heads that node's line just below a root
(`CertStore.family`) — the same independence test the release quorum already
applies to signers, asked here of witnesses. Two hundred identities minted under
one issuer are one voice.

Not because they are guilty of anything: a family is not a conspiracy. They are
simply not two hundred independent observations, and independence is the only
thing that made counting them mean anything. A node certified **directly** by a
root is its own family — a root's direct children are as independent as the
network can make them, each having cost the root a membership — and inserting
levels buys nothing, because the family is read at the top of the line and not
at the bottom.

Two more ways a voice stops counting, both from the catalogue's F3:

- **Volume.** An accuser that names more than `MAX_SUBJECTS` distinct nodes
  inside a half-life is not testifying, it is voting. Its later accusations are
  recorded at nothing — recorded, because the record is what its own reach is
  counted from, and discarding it would let the flooder drop back under the
  limit on its next accusation and be believed again. Shown nowhere, because a
  table listing everybody a flooder named is a console it gets to write.
- **Retaliation.** Two nodes accusing each other tell us that one of them is
  lying and nothing about which, so **both** directions stop counting.
  Symmetric on purpose: treating the later one as the retaliation would make
  accusing first a shield, which is strictly better than behaving. And a voice
  already discounted cannot cancel one that counts, or counter-accusing
  everybody would silence the mesh one honest node at a time. The direct bucket
  is untouched by any of it — accusing us back may not erase what we watched
  happen.

An accuser we already hold as suspect counts for nothing. A node we cannot place
in our own network counts for nothing. An accusation naming *us* is neither
acted on nor relayed — a node cannot be asked to spread the case against itself,
and a receiver that did would make every accusation self-amplifying. Records
carry a timestamp and are refused when stale (`MAX_AGE`) or ahead of us
(`MAX_SKEW`): an old accusation is a replay, not evidence.

**One statement is absorbed once**, and passed on once, keyed on *what it says*
— accuser, subject, moment — rather than on its bytes. Two things need it. An
accusation stays valid for an hour, so a record re-gossiped unconditionally
circulates between neighbours for that whole hour. And ML-DSA signatures are
randomised, so signing one statement twice gives two different records: a
byte-wise check would have stopped the relay loop and nothing else, leaving
re-signing as a way to be counted again — which for a designated witness, whose
word counts as direct evidence, was an unbounded score from one statement. The
digest is claimed **after** the signature verifies, never before, so unsigned
rubbish cannot evict live entries — the same rule as the app-auth nonce cache.

### What it costs the accused: as little information as possible

`SUSPECT` **tarpits** the link. Not a close: everything it sends is dropped at
the top of `_handle_packet`, nothing is answered, no error is returned, and the
socket stays open and quiet. A node that is disconnected knows the moment it
happens, changes identity and starts again — so the useful thing to take away is
not the connection but the feedback. The link is let go after a delay drawn at
**random** (`_TARPIT_MIN`…`_TARPIT_MAX`), because a fixed one is a message too,
only slower. `HOSTILE` also refuses a fresh handshake, checked after the two
SHA-256s that prove which identity is asking and before the post-quantum
verification, so refusing costs us almost nothing and reconnecting is not a way
to reset an allowance.

The sweep that lets expired tarpits go rides the keepalive loop rather than a
task per link: each would sit asleep for minutes holding one of the
`_MAX_DETACHED` slots the whole node shares, so a flood from many identities
would starve the fan-outs and teardowns that budget exists for.

We say something to the network only about what we saw **ourselves**, at most
once per node per `_ACCUSE_MIN_GAP` — an accusation is a broadcast, and a node
under attack must not answer by becoming the flood — and never to the node it
names: it will find out when its traffic stops being answered, but not from us,
and not with a timestamp telling it which of the things it tried was noticed.

### Behavioural rules (`behaviour.py`)

The core reports what it *sees*; this is what it *notices*. Named rules run over
counters the links already keep, on the keepalive sweep — the receive loop's
whole contribution is three integer increments, because a detector that costs
latency has already done more damage than what it detects.

Five things make it deployable rather than merely clever, and each is structural:

- **A peer is compared to the median of its own transport class.** Absolute
  thresholds are wrong on every deployment but the one they were tuned on, and
  they punish the slow medium rather than the bad actor.
- **A rule that fires on most peers disarms itself** (M1, `UNIVERSAL_SHARE`). If
  most peers look wrong, we are wrong — our clock, our uplink, our config — and
  a detector that keeps accusing then turns a local fault into a network-wide
  fight. The console says a rule went quiet and why, because a detector that
  goes silent without explaining looks exactly like one with nothing to report.
- **No rule bans.** Each returns a weight, handed to `report_abuse`; the ledger
  decides. A rule acting directly would be a rule whose false-positive rate is
  an outage.
- **Every rule states what would make it wrong** (`Rule.wrong_when`), and a test
  asserts it is non-empty: a rule whose honest lookalike cannot be stated is a
  superstition, and this is how that gets caught rather than argued about.
- **A condition is charged once, not once per sweep** (M5, `RULE_RECHARGE`).
  Every rule reads a counter that only goes up, so a rule that becomes true
  stays true — and the sweep runs every twenty seconds against a ledger that
  halves every hour. Charged per sweep, a rule worth 1.0 settles around **260**
  against a hostile threshold of 20: "weak" and "strong" described nothing, and
  D2 — whose own `wrong_when` says it means nothing on its own — would have cut
  off a quiet consumer in under seven minutes. One charge per subject per rule
  per half-life makes a permanently firing rule converge on *twice its weight*,
  and `test_no_single_rule_can_reach_suspect` asserts that this is below the
  point where anything happens. "No single rule ever bans" stops being a promise
  and becomes arithmetic.

Live today: **C1** (used a plane it announced it does not speak — only
expressible because of the capability negotiation, and counted at zero for a
peer that announced nothing), **D2** (traffic asymmetry against the group),
**E1** (answers routing queries mostly with itself), **E2** and **A1** (below),
and **D5** (below).

**E2 — the peer whose view of the network nobody shares.** A Kademlia round
already holds several answers to one question, so comparing them costs the
lookup a set intersection over ids it has in hand and the receive loop nothing
at all (`MeshNode._note_answer_overlap`). Overlap is measured as a *share* of
the answer and never as an empty intersection: a peer steering us into a region
it controls can pad its answer with one id everybody knows, and a test for
emptiness is cleared by exactly that. Answers smaller than three ids are not
judged — two honest nodes may name two different closest candidates — and an
answer that reached us through relays is not charged to the node that signed it,
because the path handled it too. The honest lookalike, a partitioned mesh,
answers itself before the disarm has to: a majority that sees a different
network *is* the median it would be compared against, so nobody is an outlier
against it.

**A1 — the burst under one signature.** Identities are free; a plausible
ancestry is not, and the certificate store has always been a graph of who
vouched for whom. `IssuerBook` keeps, per issuer, a slow average of how many
subjects it certified that were new to us per sweep, and notices a window far
beyond that issuer's own rate. Four things decide whether it defends or attacks:
an issuer is compared to **itself** and never to other issuers (a hobbyist root
admitting one node a month and a datacentre's admitting thirty a day are both
correct); joining a network is itself a burst, so an issuer earns the right to
be judged by being watched over `ISSUER_MATURITY` windows — which is also what
gives a first-seen issuer no accusation, with no special case for it; a window
in which an issuer admitted nobody is folded in at zero, or a burst hides behind
the quiet before it; and it **notifies and never scores**, because the honest
lookalike is a real deployment rolling out fifty machines on a Tuesday.

An arrival is an `(issuer, subject)` **pair** held in a bounded set until the
next sweep, and that is where the bound is: a peer that could make us count one
subject twice — by offering it again after the store's own limits evicted it —
could otherwise manufacture a burst under any issuer it chose. It can still cost
that issuer a notice, which is all A1 ever produces.

**D5 — the peer that was already trusted.** Every other rule detects a
*stranger*. This one detects a compromise of something already accepted, and it
is the only thing in the trust system that can: an attacker who steals a key
gets the identity and not the habits. `ProfileBook` keeps a slow exponential
average of three numbers read off counters already kept — packets per sweep,
bytes out per byte in, mean inbound packet size — and a break needs *two of the
three* to move together, because one number wandering is weather. Deltas, never
totals, or the average flattens and stops noticing; an idle sweep teaches
nothing, because a peer that said nothing has not changed its habits. It is held
in memory only: a profile restored from disk would be compared against a network
that moved on while we were away, so the first sweep back would accuse
everybody.

Its response class is different, and that is the point. D5 **notifies and never
scores** — the honest lookalike is "the operator upgraded that machine", and
scoring it would punish somebody for administering their own fleet. The console
shows the change and offers the one answer this node cannot work out for itself
(`console_accept_change`, "that was me"), which drops the notice and the history
behind it — profile, issuer rate and the rule's charge alike — so what the peer
does now becomes what it is expected to do. A1 lands in the same place and
answers to the same button, which is why the console block says "noticed, not
judged" rather than naming one of the two.

The catalogue of what else is worth measuring, with the anti-rules that must
never become signals, is [`behaviour-rules.md`](behaviour-rules.md).

`console_forgive` drops everything held against a node. There has to be such a
thing and it has to be local: every input to this table is a judgement made
under pressure by software, and some of them will be wrong about somebody's
node.

There is **no TOFU table**. There used to be one (`trust.py`, `NodeID → DSA
key`), documented here as a live defence, wired to nothing and imported only by
its own tests. It could not have helped anywhere it was offered: every identity
in this tree — a certificate subject, an app-auth assertion, a pseudo claim, a
release publisher — has its id *derived* from the key presented, so there is no
id that can disagree with its key and nothing for a first-use table to catch.
The check that matters is the derivation itself, and it is made at every gate.

## Invitation (`invite.py`)

Joining = proving knowledge of a code **without sending it in the clear**.

- `generate_code()`: a 10-character code, TTL 5 min, several codes may be live
  at once (star networks).
- Challenge/response: `response = HMAC-SHA256(code, challenge)`
  (`compute_response`). `verify_response` compares in **constant time**
  (`hmac.compare_digest`) and purges expired codes.
- **Single use**: `consume(challenge, response)` deletes the code that matched.
- Anti-bruteforce, at **two** levels: `peer._invite_failures` cuts one abusive
  link (three tries, then 60 s), and `InviteManager.record_failure` counts
  node-wide — `_MAX_FAILURES = 3` → a `_LOCKOUT_TTL = 60 s` lockout across every
  link. The node-wide one existed and nothing ever called it, so dropping the
  connection and reconnecting bought three fresh attempts at no cost. The
  per-link counter stays because it is what lets an abusive link be cut without
  locking out an honest joiner.
- **Expiry is enforced wherever the pool is read**, not only in
  `verify_response`: `live_codes()` purges on the way past, so an expired code
  cannot look recognised to `_recognize_seek` and start a relayed invite that
  could never be redeemed.
- **TTL per code.** `generate_code(ttl)` widens the window of one specific code,
  bounded by `_MAX_TTL` (6 h). This is for invitations that are not typed by
  hand: the one a node leaves on a machine being provisioned is only redeemed
  after its dependencies are installed, well beyond the default five minutes.
  Single use and lockout apply unchanged; only the window moves, and that is an
  explicit choice by the caller.

## Join ticket (`join_ticket.py`)

The same invitation, carried differently: a single short string carrying the
address **and** the code, for a QR code or for reading aloud.

- `generate_seeded_code(ttl)` issues an ordinary code — single use, same
  lockout, never transmitted in the clear — but derived from 8 random bytes, so
  a ticket can carry it in 8 bytes rather than in characters. Both sides derive
  the string from the code the same way (`code_from_seed`).
- **The ticket is the secret.** It is worth exactly the code inside it: whoever
  reads it can join until it expires or is used once. 64 bits of entropy behind
  a single-use code and a lockout at three failures.
- **Issued only from a confirmed `world` address** (`public_endpoints`): not "we
  believe this address is public", but "an authenticated inbound connection
  arrived on it". A ticket pointing at an unreachable address would fail after
  it had already been shared.
- The expiry written into the ticket is a **hint** for the reader, never an
  authority: only the issuing node decides whether the code still works.
- The checksum (2 bytes) catches a typo before anything is dialled. It is **not**
  integrity against an attacker — they would recompute it.
- A ticket carries a **numeric address**, never a hostname: a name would need a
  resolver on the scanner's side and could point somewhere else later.
- Decoding is treated as hostile input: bounded length, every field validated
  before use, and nothing but a `TicketError` can come out.

## Admission: a link that never proves itself does not keep its place

`_MAX_PEERS` bounds open links, and `_MAX_UNAUTH_PEERS` bounds how many of them
may still be unauthenticated. Past `_HANDSHAKE_DEADLINE` an unauthenticated link
is swept (`_reap_stale_unauthenticated`, a bounded pass run when the pressure is
felt, not a timer per peer).

The transport read timeout is no defence on its own: any packet resets it,
including one the gates drop at the first test, so a byte every thirty seconds
held a slot indefinitely. And a full `_peers` also stops `_dial_uri` dialling —
so 128 idle sockets did not merely block new peers, they left the node unable to
re-join the mesh they had pushed it out of.

Relayed virtual peers are exempt from the sweep: a relayed invitation
legitimately sits unauthenticated for the length of a join.

## Per-hop handshake (establishing a session between two direct peers)

Flow (see `_on_new_transport`, `_handle_challenge`, `initiate_handshake`,
`_handle_handshake`, `_handle_handshake_ack`):

1. The server accepting a connection sends a **CHALLENGE** (random, and marks
   `pending_challenge`).
2. The client answers through `initiate_handshake`: **HANDSHAKE** = ML-KEM
   public key + ML-DSA public key + certificate chain +
   `sign(challenge‖kem_pub‖dsa_pub)`. If the client was joining by invitation,
   the HMAC response to the challenge proves the code.
3. The server (`_handle_handshake`) verifies `claimed_id`, verifies the
   signature, verifies the chain (or issues a cert if `invite_accepted`),
   encapsulates ML-KEM → `HANDSHAKE_ACK` = ML-KEM ciphertext + its DSA key + its
   chain + the issued cert + a signature. `peer.session =
   SessionKey(shared_secret)`.

   **In that order, and it matters.** This handler is reachable on an
   unauthenticated link, and a failed attempt clears neither of its guards, so
   the same connection may try again. `claimed_id != NodeID(src_id)` is two
   SHA-256s and rules the packet out; the handshake signature is one ML-DSA
   verification; parsing the chain is one *per certificate* in it. So the
   payload is sliced without parsing the chain (`_split_handshake`), the cheap
   test runs first, and `_decode_chain` — which verifies as it builds — runs
   only once the packet has earned it. `_MAX_HANDSHAKE_ATTEMPTS` bounds how
   many tries one link gets at all, and `_decode_chain` refuses a chain longer
   than `_ENTRY_CHAIN_MAX`.
   **The ACK leaves before anything else.** Once `peer.session` is set, the
   peer has proved who it is and is owed its answer, so the ACK is built and
   sent immediately; the bookkeeping that follows (duplicate-link collapse,
   change notices, the catalog/release/pseudo syncs) all happens after it. It
   used to run first, and one of those lines closed the very link the answer
   was about to go down — see `gotchas.md` and `transports.md`.
4. The client (`_handle_handshake_ack`) verifies and decapsulates → the same
   `SessionKey`.

### Refusing out loud

Every test above drops the packet with no side effect, which is the rule. What
neither handler used to do is **say so**, and a node that refuses in silence
cannot be debugged: the far end retries for ever, each attempt dies at one of a
dozen tests, and nothing anywhere names the test.

Both handlers now call `_refuse_handshake(packet, reason)`. It changes nothing
on the wire — no reply, no side effect, the packet is still dropped — and
records the reason for the operator (`node.handshake_refusals()`, shown in the
console under Network → Reachability). Counted **per reason, never per peer**:
the reasons are this file's own words, so nothing a peer sends can grow the
store, and `_REFUSALS_KEPT` bounds it regardless. The most recent id refused
under each reason is kept, which is a fixed 20 bytes.

Telling an operator why *their own node* refused is not telling an attacker
anything: the console is authenticated, and the refusing node sends nothing
back.

From then on `peer.authenticated_id` is set on both sides and all traffic on the
link is AES-256-GCM encrypted. Trust is **mutual** (each side challenges the
other).

### Adopting a root: the joiner decides, not the answer

Step 4 is where a node can gain a **new trust root** — the host's self-signed
certificate, arriving at the end of a join. From then on every chain anchored
there authenticates, so this is the single most consequential thing a handshake
does, and it is the one branch that must never be chosen by the remote side.

It is not. The branch is gated on `peer.joined_by_invite`, which only
`_handle_invite_ack` sets, and only on an `_ACK_ACCEPTED` — that is, only when
**we** presented a code on **this link** and it was accepted. The `issued_cert`
field in the answer is not evidence of anything: the peer writes it, and it has
our public key (we sent it in the HANDSHAKE one step earlier), so it can always
mint a certificate naming us.

Without that gate, every address we dial is a trust anchor waiting to be
planted — and we dial addresses learned from gossip (`_maintain_neighbors`,
`_address_retry_loop`, the console's manual retry, latency steering). A single
peer answering an ordinary reconnect could have made itself a root and then
minted memberships for identities it generated on the spot, which is the whole
invitation gate removed. Locked down by
`tests/test_invite_to_handshake.py::test_dialled_peer_cannot_plant_a_trust_root`,
with its counterpart `test_joining_by_invite_still_adopts_the_host_root` so the
bound cannot close the door it exists to open.

A link that presents no code takes the other branch and is held to the ordinary
rule: its chain must verify to a root we already hold, or the link does not
authenticate at all.

> **Address invariant note**: the handshake does **not** yet carry the peer's
> full set of announced addresses. After authentication we only know the address
> that was dialled (client) or none at all (server: `_routing.add(id, [],
> pub)`). The full set arrives by **gossip** (a PING carrying
> `advertised_uris`, FOUND_NODE). See `routing.md` §address propagation for the
> intended invariant and its mechanism.

## E2E session (end to end)

`_initiate_e2e_handshake` / `_handle_e2e_handshake(_ack)`: ML-KEM + signature +
chain, but **routed** across the mesh (`_ROUTABLE_TYPES`) to the final
destination. Result: `_e2e_sessions[peer]`. DATA is encrypted under that E2E
session (`create_encrypted`): **relays never decrypt** — they see only the
routing header.

### Re-keying on the responder's side: a probed candidate, never a blind overwrite

A valid handshake arriving while a session is **already live** may be a late
duplicate (a retry every 5 s, a slow relayed path) or a genuine re-key (the peer
lost its session). Overwriting the session blindly poisons the link in the
duplicate case (the initiator ignores the ACK, keeps the old key → a permanent
key disagreement → every DATA silently dropped at the GCM). The responder
therefore derives a **candidate** session (`_e2e_rekey`, bounded by
`_E2E_REKEY_MAX`, TTL `_E2E_REKEY_TTL`), ACKs normally, and **promotes** the
candidate only when a DATA **decrypts** under it (`_handle_data`) — proof that
the peer really holds the new key.

Why this is safe: planting a candidate requires the peer's ML-DSA identity (a
fresh signature + an anchored chain, as for a normal establishment); promoting
it requires decapsulating the KEM (only the holder of the KEM secret produces a
valid DATA). A **replayed** handshake produces a candidate the attacker can
never promote (they cannot decapsulate our fresh ciphertext) → it expires. A
legitimate duplicate breaks nothing: the live session is kept.

## Application identity (on top of the E2E session)

Source: `app_auth.py`, exposed by `node.app_auth(app_id)` and by the connector's
`AUTH_*` frames. Full detail: [`Docs/AppAuth/guide`](../AppAuth/guide).

The E2E session authenticates the **transport**: when a DATA payload reaches an
app, its `src_id` is proven. But that proof is confined to a live session —
unrecoverable after a restart, untransferable, and silent about **intent**.
`app_auth` adds an **assertion**: an ML-DSA-signed statement that "node S
asserts, in app A, to B, for purpose P, over context C, at time T", portable,
scoped, fresh and single-use.

Two security invariants, not to be broken:

- **This is not a signing oracle.** The same ML-DSA key signs certificates,
  handshakes, releases and directory claims. Nothing in `app_auth` signs bytes
  supplied by the app: the signed input is always
  `b"nmesh-app-auth-v1" ‖ <bounded structured fields>`, and free-form context
  only enters through a 32-byte hash. The domain is distinct from every other in
  the repository. An app therefore cannot get a certificate body signed.
- **The `app_id` comes from the session, never from the frame** — as for the
  drawer and the per-app DHT. An app cannot issue for another's section.

The signer's identity is not a separate field: `NodeID` derives from the key
presented, so there is no id to lie about (the same invariant as the handshake).

**The signing domains, in one place.** One identity key signs everything, so
each use gets its own domain and none of them can be replayed as another:
`nmesh-app-auth-v1` (assertions), `nmesh-app-release-v1` (app packages),
`nmesh-core-release-v1` (a release of the node's own code — see
[`Docs/Updates/guide`](../Updates/guide)), `nmesh-pseudo-v2` (a node's claim to
a name — see below), plus the certificate body and the handshake input. Adding a
seventh use means adding a seventh domain, not reusing the nearest one.

`verify_assertion` orders its checks from cheapest to most expensive, and burns
the anti-replay nonce **after the signature**, not before it. Everything ahead of
the signature is structural — an attacker copies the app id, the audience, the
purpose and the ctx off a legitimate assertion and picks a fresh timestamp — so
claiming the nonce there let unsigned rubbish evict live entries from the
bounded cache, which reopens the replay window the cache exists to close. A
claim is a mutation, and mutations go after the last gate.

**Authentication is not authorisation.** An assertion proves "who, for what";
deciding whether that "who" is allowed remains the app's job. The Fleet app
(`Docs/Apps/fleet`) keeps a local, persistent capability ledger for that, and
requires **all three** gates: an authenticated mesh peer, enrolled with the
capability, and a fresh signature over the exact bytes of the command.

The `manage` capability adds a second key rather than widening the first: the
mesh grant opens the channel, the **target's console password** opens the
session, and the two are held by different people. The relayed call is
**replayed against the target's own console** (loopback, pinned certificate), so
session checking, ceilings and the anti-bruteforce lockout are the console's own
— a relay that answered by itself would be a second front door with its own bugs.

`passwordless` is the one case where that second key is **given rather than
typed**, and it exists because of a machine where nobody can type it: a node an
operator provisioned generated its own console password on first start and
printed it to a log on a box with no screen. The grant then *is* the second key,
and it is granted the way every other right is — by a human on the target, or by
the pre-authorisation that stands in for one on a machine they just installed.
It skips the password and nothing else: the mesh session, the ledger entry and a
fresh signature are all still required, the session it mints is an ordinary
console session with the console's own expiry, `manage` is still needed to carry
a call, and taking either right back **ends the sessions already open** rather
than only stopping the next one.

That ledger is never widened by the network. A right is only ever added by a
local decision on the machine that bears it; the one message that touches
capabilities without a human (`ENROL_NARROW`) is **intersected** with what its
sender already holds, so it can only take some away. Without that asymmetry the
weakest capability would be enough to reach all the others.

## Pseudos (a name is a label, never an identity)

A node's identity is its `NodeID`, the hash of its ML-DSA public key. A pseudo
is the changeable name shown beside it. It never decides anything — not routing,
not authentication, not trust — so an attacker who registers a lookalike gains
nothing they did not already have.

What keeps it usable anyway is that a name never travels bare. It travels as a
**claim signed by the very identity it names**, and the id inside that claim is
derived from the key that signed it, so a claim can only ever bind a name to its
author's own node. That is why a claim from a stranger can be accepted, cached
and re-served without a second thought — see
[`routing.md`](routing.md) for the format.

**The form is checked, not repaired.** `src/pseudo.py` defines one canonical
spelling (NFC, no `C*`-category character, plain spaces only, single-spaced, at
most 50 characters), and a receiver re-derives it from what arrived. A pseudo
that is not already canonical is **refused, however well it is signed** — a
trailing space, a zero-width joiner or a right-to-left override is not sloppy
input, it is a name engineered to render as somebody else's. Refusing before
verifying also means a hostile name costs no signature check.

**A peer that sends one is charged for it.** A claim that is oversized,
unparseable, badly signed, or non-canonical is counted against the link it came
on (`_Peer.note_abuse`), and the peer is cut once the count passes
`_MAX_MALFORMED` — the same counter and the same ceiling as an undecodable
frame, because it is the same judgement. An honest relay verifies before
re-sending, so whoever hands us a bad claim either forged it or forwarded
without checking; neither is something to absorb quietly.

**A name only moves forward.** Claims carry a timestamp that must strictly
increase per node id, so a relay replaying an old claim cannot roll somebody
back to a name they abandoned.

**No app can rename the node.** The connector exposes reading and searching
pseudos and nothing else. The node's name is shown in its console and used by
every app, so choosing it belongs to whoever runs the node — not to any app that
happens to hold a connector token.
