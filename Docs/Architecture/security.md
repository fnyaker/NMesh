# Identity, crypto & trust

Source: `crypto.py`, `node_id.py`, `cert.py`, `cert_store.py`, `trust.py`,
`invite.py`, and the handshake handlers in `node.py`.

## Identity

- `CryptoIdentity` (`crypto.py`) holds an **ML-DSA-65** pair (signature). The
  private key stays in memory; `save/load` persists it as raw binary under the
  state directory (`node.key`), **created 0600 at open time** (not a `chmod`
  afterwards, which would leave a window in which it could be read) and
  tightened again if a more permissive file is left over from an earlier
  version. The state directory itself is 700 and belongs to the node's
  dedicated account when `install.sh` put it there (see
  [`../Setup/guide`](../Setup/guide)).
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
  the `HANDSHAKE_ACK`. `self_signed_cert`: the root.
- `CertStore` (`cert_store.py`): `subject_id → [certs]` plus a set of roots
  (`_roots`, containing at least ourselves).
  - `get_chain_to_root(target)`: a **BFS** through the issuance graph up to a
    root. **Prefers an external root** (the network): presenting our own
    self-signed root authenticates nothing to a peer; the network chain (through
    the issuer who invited us) is the only one anybody else can verify.
  - `verify_chain(chain)`: continuous issuance links + a self-signed last cert +
    the last `subject_id ∈ roots` + nothing expired → returns the anchor,
    otherwise None.
- `TrustTable` (`trust.py`): **TOFU** `NodeID → DSA key`. First sighting →
  store; a later sighting with a **different key** → `False` (compromise or
  impersonation).

## Invitation (`invite.py`)

Joining = proving knowledge of a code **without sending it in the clear**.

- `generate_code()`: a 10-character code, TTL 5 min, several codes may be live
  at once (star networks).
- Challenge/response: `response = HMAC-SHA256(code, challenge)`
  (`compute_response`). `verify_response` compares in **constant time**
  (`hmac.compare_digest`) and purges expired codes.
- **Single use**: `consume(challenge, response)` deletes the code that matched.
- Anti-bruteforce: `_MAX_FAILURES = 3` → a `_LOCKOUT_TTL = 60 s` lockout.
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

## Per-hop handshake (establishing a session between two direct peers)

Flow (see `_on_new_transport`, `_handle_challenge`, `initiate_handshake`,
`_handle_handshake`, `_handle_handshake_ack`):

1. The server accepting a connection sends a **CHALLENGE** (random, and marks
   `pending_challenge`).
2. The client answers through `initiate_handshake`: **HANDSHAKE** = ML-KEM
   public key + ML-DSA public key + certificate chain +
   `sign(challenge‖kem_pub‖dsa_pub)`. If the client was joining by invitation,
   the HMAC response to the challenge proves the code.
3. The server (`_handle_handshake`) verifies the signature, verifies
   `claimed_id`, verifies the chain (or issues a cert if `invite_accepted`),
   encapsulates ML-KEM → `HANDSHAKE_ACK` = ML-KEM ciphertext + its DSA key + its
   chain + the issued cert + a signature. `peer.session =
   SessionKey(shared_secret)`.
4. The client (`_handle_handshake_ack`) verifies and decapsulates → the same
   `SessionKey`.

From then on `peer.authenticated_id` is set on both sides and all traffic on the
link is AES-256-GCM encrypted. Trust is **mutual** (each side challenges the
other).

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

`verify_assertion` orders its checks from cheapest to most expensive and burns
the anti-replay nonce **only after** the cheap ones — otherwise a flood of
invalid assertions would evict live entries from a bounded cache.

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

That ledger is never widened by the network. A right is only ever added by a
local decision on the machine that bears it; the one message that touches
capabilities without a human (`ENROL_NARROW`) is **intersected** with what its
sender already holds, so it can only take some away. Without that asymmetry the
weakest capability would be enough to reach all the others.
