# Design plan — agnostic reachability + relayed invitation

> **Status: A PLAN, not implemented yet.** A working document to be validated
> before any code. The goal: letting two nodes reach each other even behind
> CGNAT / double NAT / symmetric NAT, **without depending on a concrete
> transport**, and without a contraption (no dedicated quota database).

## 0. Guiding principles (a charter reminder)

1. **Security first.** Every packet is presumed hostile. `NodeID = hash(DSA key)`.
   Reject by default. Bounds everywhere.
2. **Transport-agnostic.** The core knows **no** concrete transport.
   Reachability, broadcast and hole punching are **transport details** exposed to
   the core through a generic interface.
3. **As automatic as possible.** Fine tuning is for experts; by default
   everything organises itself.

The observation that motivates all of it: direct hole punching fails by
construction when both peers are behind symmetric NAT (4G CGNAT, double NAT).
The only robust answer, universally adopted (Tailscale DERP, WebRTC TURN, libp2p
circuit-relay), is **relaying** the E2E-encrypted traffic. NMesh already routes
E2E-encrypted packets through intermediaries: we build on that.

---

## 1. An agnostic reachability model (`reachability`)

### 1.1 The descriptor

Every **transport server** (`BaseServer`) can describe how it is reached, as a
list of descriptors opaque to the core:

```
Reachability = {
  "transport": str,     # scheme, e.g. "tcp", "udp", "ble"
  "scope":     str,     # "world" | "lan" | "broadcast" | "none"
  "anchor":    str,     # an audience discriminator (see below)
  "address":   str|None,# a directly reachable URI if applicable, else None
  "confirmed": bool,    # reachability proven (dial-back / inbound accepted) vs assumed
}
```

- **`scope`** = the width of the audience, ordered: `world` > `lan` >
  `broadcast` > `none`.
- **`anchor`** = what distinguishes two audiences of the same scope. **This is
  the key to the `192.168.0.0/24` problem**: my LAN carries the anchor
  `<my-public-IP>`, my neighbour's `<their-public-IP>` → the same private subnet,
  **distinct audiences**.

Concrete examples:

| Situation | Descriptor |
|---|---|
| A TCP port open to the world | `(tcp, world, "", tcp://IP:port, confirmed)` |
| A LAN behind my public IP | `(tcp, lan, "<pub-ip>/24", tcp://192.168.x:port, confirmed)` |
| UDP + STUN, a public mapping | `(udp, world, "", udp://IP:port, confirmed)` |
| Bluetooth (to come) | `(ble, broadcast, "", None, confirmed)` |
| Behind NAT, not reachable | `(udp, none, "", None, False)` |

### 1.2 The contract on transports

Two **optional** capabilities are added to the interfaces (with safe defaults so
nothing breaks for existing transports):

```python
class BaseServer:
    def reachability(self) -> list[Reachability]:
        """How this server is reachable, and by which audience.
        Default: []  (the transport does not know / is not reachable)."""
        return []

    async def broadcast(self, data: bytes) -> bool:
        """Broadcasts data blind into the medium's domain (LAN UDP, BLE…).
        Returns True if the transport can broadcast. Default: False."""
        return False

class BaseTransport:
    @classmethod
    def can_reach(cls, desc: Reachability, local_ctx: dict) -> bool:
        """From our network context (local_ctx), can we try to reach a node
        advertising desc? Default: desc has an address + scope != none."""
```

- **`reachability()`**: the IP transport fills it in from what we already have
  (the address observed through `remote_ip()`/OBSERVED_ADDR, STUN keepalive,
  and above all an **accepted authenticated inbound connection** = passive proof
  of reachability).
- **`can_reach()`**: IP returns `True` for `world`, and for `lan` only if the
  anchor matches our observed public IP. `broadcast` → handled separately (we
  broadcast, we do not "route" towards it).
- **`broadcast()`**: UDP/BLE implement it; TCP/spool do not. The core calls it
  without knowing how it is done.

The core **aggregates** the `reachability()` of all its servers → its own
reachability → advertises it (in routing/presence) and tags itself
**relay-capable** if it has ≥1 `confirmed` descriptor at `world` scope (or at a
usefully defined scope).

### 1.3 Auto-detecting the relay role

- **Passive (free, safe)**: a node that accepted an authenticated inbound
  connection it did not initiate is *proven* reachable → `confirmed=True`.
- **Active (phase 2, AutoNAT style)**: `REACH_PROBE` — we ask a peer to
  reconnect to our advertised address and confirm. Anti-amplification
  safeguards: only the address claimed in the same family as the observed
  source, never the private ranges, bounded, rate-limited, and the reconnection
  attempts a real handshake (a 1:1 failure on a random victim).

---

## 2. Relayed invitation + broadcast (one block)

### 2.1 The principle

**Relaying an invitation ≈ relaying a packet.** No node has a special role
imposed on it; no quota database. A **single** b64 block, generated by inviter
A, handed to invitee B out of band. B "tries everything": it **broadcasts** the
request on the transports capable of it **and** **routes** it towards a list of
fallback relays. Any node in the network that receives the request verifies it
and passes it on towards A.

### 2.2 What is in the b64 block

```
InviteBlock = {
  "v":      3,
  "code":   <invitation code>,           # the anti-abuse capability (existing, TTL 5 min)
  "cert":   <A's self-signed cert, hex>, # carries the public key; NodeID(A)=hash(key)
  "exp":    <expiry timestamp>,
  "token":  <sig_A( TAG || H(code) || exp ), hex>,  # the rendezvous authorisation
  "relays": [ Reachability, ... ]        # widely reachable nodes, a fallback when there is no broadcast
}
```

- `cert` gives A's public key ⇒ any receiver checks `NodeID(A)=hash(key)` and
  the validity of `token`.
- `token` = **A signs the rendezvous authorisation**. That is the anti-spam
  safeguard: an outsider cannot forge an invitation "issued by a member" without
  A's key. A receiver that **shares A's root** additionally checks network
  membership; otherwise it at least checks self-consistency (a valid signature
  for the key supplied) and **rate-limits per key**.
- `relays`: only nodes at a **defined and wide** scope (`world`, or an audience
  B stands a chance of sharing). **Never** `broadcast` (we do not route towards
  an undefined domain — it only serves opportunistically).

### 2.3 A new packet type: `INVITE_SEEK` (pre-auth, bounded)

This is the only packet **routable before authentication** — it carries its own
proof (`token`), it is TTL-bounded, deduplicated, rate-limited.

```
INVITE_SEEK payload = {
  inviter_id,           # NodeID(A) — who to route towards (in the clear, accepted)
  cert_A, exp, token,   # copied from the block (verifiable by any node)
  seeker_id, cert_B,    # B's identity (its real NodeID) — for the return path
  rdv_nonce             # correlates a round trip, bounds the rendezvous table
}
```

**The decision (settled): A's ID travels in the clear.** No cryptographic risk
(`NodeID = hash(public key)`, no impersonation possible without the private
key), and above all it keeps routing **directed** (Kademlia, ~log(n) hops) → it
scales from 4 to 4000 nodes. We explicitly **rule out** any network flood (which
would not scale). Hiding A's ID (group encryption, a recognition tag, ephemeral
IDs) is **abandoned**: it required either a shared network key (a single point
of compromise, ineffective against a hostile member) or flooding. A possible
improvement is noted for later if a threat model demands it, but it is out of
v1.

### 2.4 The join state machine

```
B (invitee)                   R (relay, a direct peer of A)     A (inviter)
   │                             │                                │
   │ 1. opens a link to R (outbound → traverses any NAT)          │
   │    + sends INVITE_SEEK ─────┤                                │
   │ 1'. (opportunistic) broadcasts the SEEK on capable transports│
   │                             │                                │
   │                             │ 2. checks token+cert+exp       │
   │                             │    (otherwise drop + rate-limit)│
   │                             │ 3. notes rdv_nonce → link(B)   │
   │                             │    (rendezvous table, bounded) │
   │                             │ 4. routes the SEEK to inviter_id┤
   │                             │    (directed: a direct peer,   │
   │                             │     else Kademlia/on-demand, TTL)│
   │                             │                                │ 5. A sees
   │                             │                                │  H(code)+token OK
   │                             │ 6. CHALLENGE (dst = seeker_id) ◄┤
   │                             │ 7. return path via the rdv table│
   │ 8. CHALLENGE received ◄─────┤                                │
   │                             │                                │
   │ 9. INVITE(code) / HANDSHAKE (ML-DSA signed) tunnelled A↔B through R (E2E)
   │        … the existing invitation sequence, end to end …      │
   │ 10. E2E session established (routed by R) — reliable at once │
   │                             │                                │
   │ 11. (optional) a direct punch attempt → switch over if it works│
```

Key points:
- **Directed routing, no flood.** R routes the SEEK towards `inviter_id`: in the
  simple case R is a **direct peer of A** (A chose it among its own widely
  reachable peers) → 2 hops, a trivial return path. The general case: Kademlia
  towards `inviter_id`, TTL-bounded. It scales to thousands of nodes.
- **R is nothing but a pipe**: it routes signed packets it cannot forge (the
  NMesh invariant: "a relay sees nothing but routing metadata").
- **The return path**: R keeps a **rendezvous table** `rdv_nonce → (link, exp)`,
  bounded and short-lived. A answers addressing `seeker_id`; R sends it back over
  the link the SEEK came from.
- **B is reached over the link it opened itself towards R** (outbound →
  traverses any NAT). No inbound reachability is required on B's side.
- **Opportunistic broadcast**: if a node on the network hears the SEEK on the
  same medium (BLE, LAN UDP), it plays R and routes (always directed towards
  `inviter_id`, never a flood). Otherwise the block's `relays` list takes over.

### 2.5 Choosing the block's relays (the answer to "not at random")

A picks the relays on deterministic criteria:
1. Candidates = nodes A knows with ≥1 `reachability` descriptor that is
   **`confirmed`, scope `world`** (reachable by anyone, therefore by B wherever
   it is).
2. Failing `world`, **varied** defined scopes (different anchors) to **cover
   several audiences** — maximising the chance that B shares one.
3. Bounded (5, say, configurable). Sorted by how fresh the confirmation is.
4. Never `broadcast`/`none`.

### 2.6 On the invitee's side, after the join

B **keeps the list of relays used** (to communicate at first), then **fleshes
out its own view** as the mesh discovers things (the existing routing/DHT). No
dedicated database: it is the routing table + presence already there.

---

## 3. Security model (review points)

| Risk | Answer |
|---|---|
| An outsider spamming SEEKs to kill a node | A `token` signed by a member is required; otherwise drop. Rate-limit **per cert key**. TTL + dedup on the SEEK's routing. |
| Amplification (a SEEK routed forever) | TTL decremented per hop, bounded dedup (already in place for routed packets), a bounded rendezvous table. |
| A malicious relay | It can only **drop or delay** (never read or forge: ML-DSA-signed handshake, E2E). That is already in the threat model. |
| Replaying the block | A single-use `code` + `exp`. A can invalidate it (the code expires; cancelling = let it expire / regenerate). |
| Metadata leak (A's ID broadcast) | **Accepted (decided).** An ID is an address, not a key compromise. Hiding it (a group key / tag / ephemeral IDs) is ruled out in v1 because it forces flooding or a shared key that neither scale nor protect. A future improvement if needed. |
| Pre-auth traffic crossing the mesh | **One** type only (`INVITE_SEEK`) is allowed pre-auth, strictly token-gated, bounded, rate-limited. A dedicated security review at implementation time. |

**Cancelling an invitation** (a user request): no DB to purge — the `code` is
single-use and expires. "Cancel" = regenerate / let it expire. If we want active
revocation later, it will go through the same signed channel (out of scope for
v1).

---

## 4. Web UI refactor — **generic** status/config per transport

Today the "Transports" section is wired to IP (punch, STUN, public IP). We make
it agnostic:

- **`console_snapshot`** exposes, per active transport, a **generic** block:
  `{ scheme, reachability: [...], status: {<free keys>}, config: {<free keys>} }`.
  The core does not invent those keys: **each transport** supplies its `status()`
  and its `config_schema()`. The web UI **renders them generically** (a key/value
  table + typed controls from the schema).
- Hole punching / STUN / manual holes become the UDP transport's
  `status()`/`config()`, and stop being core concepts. The Transports section
  shows "what the transport declares", whatever it is.
- **Per-transport config from the UI**: a standard `config_schema()` (a list of
  fields `{key, type, label, default}`) → the UI generates the controls;
  `console_set_transport_config(scheme, {...})` applies them. A future BLE
  transport requires **no** UI change.

The invitation panel: "Connect a node" (generate a block / paste a block), the
join's progress, and — in **expert** mode — the list of relays chosen and their
state.

---

## 5. Implementation plan (tested increments)

Each step stands alone, is tested (hostile inputs included), and the suite is
green before merging.

- **Step 1 — The reachability model (core + IP).** `Reachability`,
  `reachability()` on `BaseServer`, aggregation in the core, the passive signal
  (an accepted inbound), the relay auto-tag. The snapshot exposes reachability.
  *No change in network behaviour — observability only.*
- **Step 2 — `INVITE_SEEK` + the rendezvous table + bounded pre-auth routing.**
  The packet, its verification (token/cert/exp), routing towards `inviter_id`,
  the `rdv_id→link` table. Hostile tests (a forged token, an expired one, a
  flood, TTL).
- **Step 3 — Invitation block v3 + a "try everything" join.** Generating and
  validating the block, sending to the relays + `broadcast()` on capable
  transports, A's answer, the tunnelled handshake, an E2E session through the
  relay. An end-to-end test A↔B through a relay, **with no direct link**.
- **Step 4 — `broadcast()` over UDP (LAN) + relay discovery.** ✅ A refinement
  adopted over "broadcast the raw SEEK": the return path of a fire-and-forget
  broadcast is fragile (the witness has no link to B). Instead, **LAN
  discovery** (`src/lan_discovery.py`): B broadcasts an `NDSC` beacon, any member
  of the medium answers (`NDSA`) with its reachable addresses; B adds them to its
  candidate relays and joins through the **step-3 path** (a real, reliable link).
  The same effect ("a member of the medium acts as a relay"), with no datagram
  bridge. Bounded + rate-limited. Fixed port 45888, a generic `broadcast()`
  capability on `BaseServer`/UDP.
- **Step 5 — The generic web UI refactor** (status/config per transport, UDP
  moved behind the interface, the invitation panel).
- **Step 6 — Bonus**: direct IPv6 preference; active `REACH_PROBE` (AutoNAT); an
  ephemeral rendezvous ID for A.

## 6. Out of scope (to be explicit)

- Implementing a Bluetooth/LoRa transport (we prepare the interface, we do not
  code the medium).
- A quota database / a per-node invitation DB (abandoned — pointless).
- Active invitation revocation (the TTL is enough in v1).
- Hiding A's permanent ID (a future improvement, noted).
