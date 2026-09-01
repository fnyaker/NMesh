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
