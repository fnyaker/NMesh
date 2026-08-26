# Routing, DHT & address propagation

Source: `routing.py`, `dht.py`, and inside `node.py`: `_ensure_route_to`,
`_connect_routing`, `_kademlia_lookup`, `_forward_packet`, `ping`/`_handle_ping`,
`_handle_found_node`, keepalive.

## Routing table (`routing.py`)

Kademlia with 160 buckets. `NodeEntry` = `node_id`, `addresses`, `dsa_pub`,
`cert_chain`, **`last_seen`** (monotonic, set on every `add`).

- `KBucket.K = 20`. A full bucket returns its oldest entry (an eviction
  candidate). A node that is `add`ed again moves to the end of the bucket (LRU →
  we keep the active ones).
- `RoutingTable.add(id, addresses, dsa_pub)`: **merges** the addresses
  (`dict.fromkeys(existing + new)`) and the DSA key; creates a fresh `NodeEntry`
  → `last_seen` refreshed. Ignores adding ourselves.
- `all_entries()`, `get_closest(target, k)` (sorted by XOR distance),
  `export_entries`/`import_entries` (persistence; only entries with a DSA key
  are exportable — without a key we cannot re-authenticate).
- `last_seen` feeds the console ("Known nodes", the N most recent) and **must**
  feed targeted address propagation (see below).

## Kademlia "improved" (on-demand routing)

The base concept is Kademlia, but routing is **medium-agnostic** and **on
demand** rather than a blind XOR hop:

- `_forward_packet` (see `protocol.md`): a direct peer > the **observed return
  path** (`_route_hints`, see below) > the nearest XOR neighbour > acquiring the
  route **in a background task**. We prefer a route that is actually reachable
  to a theoretical XOR hop — crucial across network boundaries where only some
  nodes have reachability.
- `_ensure_route_to(target)`: returns an authenticated peer towards `target`,
  establishing one if needed. Order: an existing peer → if absent from the
  table, `_kademlia_lookup` → `_connect_routing` (tries the known addresses,
  IPv6 first) → if no address is reachable, `_punch_route_to` (a NAT hole punch
  coordinated by a relay, see `transports.md`).
- `_kademlia_lookup(target)`: a bounded iterative `FIND_NODE`
  (`_KAD_LOOKUP_TIMEOUT`, `_KAD_LOOKUP_MAX_ROUNDS`), aggregating `FOUND_NODE`
  until it stabilises.

### ⚑ Acquiring a route **never** blocks a receive loop

`_ensure_route_to` takes seconds (lookup, dial, punch). Calling it from a
handler — therefore from `_Peer._loop` — freezes the incoming link for that
whole budget, **and cannot succeed** when the `FOUND_NODE` it waits for has to
come back over that very link (the case of a node with a single peer: a
guaranteed deadlock).

→ `_route_outbound(packet, blocking=False)` and `_forward_packet` only do the
fast path (send to a live candidate); with no candidate, the packet goes into
`_defer_route`: a **bounded background task** (`_MAX_DEFERRED_ROUTES`, tracked
and cancelled by `stop()`) that acquires the route and re-sends. Every handler
called from the receive loop (`_handle_find_node`, `_handle_find_value`,
`_handle_dir_find`, `_handle_echo_request`, both E2E handlers) uses
`blocking=False`. `_maybe_upgrade_path` goes through the same task pool.
**Never await `_ensure_route_to` from a packet handler.**

### Reaching an id **remotely** (multi-hop) — not only a direct peer

**Everything addressed to a `node id` is routable** and relayed hop by hop
(`_forward_packet`, greedily towards the target while excluding the peer the
packet came from — on a chain this degenerates into "pass it to the other
neighbour") up to the recipient, over **any medium**. Routable: `DATA`,
`E2E_HANDSHAKE`/`_ACK`, `ECHO_REQUEST`/`_REPLY`, **and the whole Kademlia/DHT
control plane** — `FIND_NODE`/`FOUND_NODE`, `STORE`/`FIND_VALUE`/`FOUND_VALUE`,
`DIR_STORE`/`DIR_FIND`/`DIR_FOUND`. Still **direct** (one authenticated hop):
`PING`/`PONG` (per-link keepalive), the punch signalling, and catalogue gossip
(re-stamped at every hop).

### A return path learned from traffic (`_route_hints`) ⚑

XOR proximity is only a **hypothesis** about an overlay we have not finished
learning; the link a packet just arrived on is **proof** that it carries traffic
from that source. Routing a reply by a fresh greedy guess, while the request's
own path is right there, used to send `FOUND_NODE`/`ECHO_REPLY`/E2E ACKs into a
dead end.

- `_learn_reverse_path(peer, packet)`: after the validation gates (`msg_id`
  verified, not a duplicate, link authenticated), we note
  `packet.src_id → ingress peer`. A peer reachable **directly** gets no entry
  (the direct link is already the shortest).
- `_route_candidates` puts that first hop **at the front**, unless a direct link
  to the target exists — that one always wins. The rest of the list (neighbours
  sorted by XOR) follows, so a send that fails keeps walking down the list.
- Bounded (`_ROUTE_HINT_MAX = 256`, FIFO eviction) and dated
  (`_ROUTE_HINT_TTL`).
- **Self-repair**: `_forget_route_hint(target)` as soon as a routed request goes
  unanswered (`_kad_query_node`, `_dht_find_value_at`, `_dir_find_at`,
  `_routed_ping`); `_forget_hints_via(peer)` when a link dies. A first hop that
  stops carrying — or that lies to attract traffic — costs one request timing
  out, and then disappears.

An accepted attack surface: an authenticated peer can forge `src_id` to attract
our traffic towards a target and drop it. They gain nothing they did not already
have: the hint only **reorders peers that are already authenticated** (never an
unauthenticated hop), it does not override a direct link, it is bounded, dated,
and erased at the first silence. A relay chosen by XOR could already drop
traffic the same way.

Consequence: `A → X across the whole alphabet` works for **everything** —
messages, ping, content-addressed DHT, pseudo directory — even if A and X cannot
connect directly (remote / NAT). Requests (`_kad_query_node`,
`_dht_store_at`/`_dht_find_value_at`, `_dir_store_at`/`_dir_find_at`) address the
packet to the target `node id` and go through `_route_outbound` (direct if
adjacent, multi-hop otherwise); replies (`FOUND_*`) are routed back to the
seeker. For **liveness**, `console_ping_node` sends a routed `ECHO_REQUEST` and
measures the RTT (`_routed_ping`); the `via` field is `direct` or `route`. E2E
additionally requires a **shared trust root** between the ends (routing reaches
the target, authentication wants a shared anchor).

## Content-addressed DHT (`dht.py`)

- `ContentStore.put(key, value)` **refuses** if `key != sha256(value)[:20]`
  (`content_key`). → a peer can never store arbitrary data under a chosen key:
  classic DHT poisoning is closed by construction.
- Bounded: `_MAX_ENTRIES = 8192`, `_MAX_BYTES = 128 MiB`, LRU eviction.
- Replication: `_DHT_K = 6` nearest nodes (STORE/FIND_VALUE).
- Use: sharing applications (`app_package.py`, see `Docs/AppSharing/guide`).

## Public/private per-app DHT (`app_dht.py`)

An application overlay above the content-addressed store, without weakening its
anti-poisoning (it is still the *framed* value that is hashed and stored). Every
value is `app_id(8) ‖ flag(1) ‖ body`:

- **A namespace per app.** The `app_id` is the one the node holds for the
  authenticated session — **the app does not declare it**. A reader only accepts
  a value whose framed `app_id` matches its own: two apps never read each other,
  even knowing the other's content key.
- **Public** (`flag=0`): `body = content` in the clear → any instance of the
  *same* app, on any node, reads it ("all the nodes").
- **Private** (`flag=1`): `body = nonce(12) ‖ AES-256-GCM(content)`, encrypted by
  the **node** under a key supplied by **the app** (16/24/32 bytes; AAD =
  `app_id ‖ flag`). Only instances that also hold the key can read. The node does
  the DHT crypto; the app owns the content, the key, and its distribution
  between nodes. Symmetric AES-GCM = post-quantum.

Node API: `app_dht_put(app_id, content, enc_key?) -> key` /
`app_dht_get(app_id, key, dec_key?) -> content | None`. From an external app,
the same operations through the connector (`ConnectorClient.dht_put/dht_get`,
with the `app_id` coming from the session — see `Docs/DataConnector/guide`).
Content bounded by `MAX_CONTENT` (≈ one DHT value). The app keeps its own index
of content keys.

## Pseudos: the directory and the gossip (`pseudo.py`, `pseudo_dir.py`)

A node's identity is its `NodeID`. A **pseudo** is the changeable label beside
it: freely chosen, freely changed, and **not unique** — several nodes may wear
"alice". Nothing the network decides ever depends on one; wherever a pseudo is
shown, the id is shown with it.

### The form is part of the protocol (`pseudo.py`)

`canonical()` defines the one accepted spelling: NFC, no character in a `C*`
category (control, format, surrogate, private-use, unassigned — this is what
removes zero-width and right-to-left characters), only `U+0020` between words,
single-spaced, no edges, at most **50 characters**. A receiver re-derives it and
**refuses anything else**: the gap between what was sent and what renders is
exactly where impersonation lives, so a non-canonical pseudo is treated as
hostile rather than tidied up (see `security.md`).

`fold()` derives the search key — case- and accent-insensitive, so `jose` finds
`José`. It is only ever a key; it never replaces what is displayed.

### The claim (`pseudo_dir.py`)

```
claim = version ‖ ts ‖ pubkey ‖ pseudo ‖ ML-DSA signature
signed over  "nmesh-pseudo-v2" ‖ node_id ‖ ts ‖ pseudo
key   = sha256("nmesh-pseudo-v2" : fold(pseudo))[:20]
```

- The **node id is derived from the claim's own `pubkey`**
  (`NodeID.from_public_key`), and the signature is verified under that pubkey. A
  claim can therefore only bind a pseudo to **its author's own** id — mapping
  "alice" onto a victim's id is impossible, the same closure of
  poisoning/impersonation as the content-addressed store.
- The receiver **recomputes the key** from the claim's pseudo → filing it under
  an unrelated key is impossible.
- `ts` only moves **forward** per node id, so a relay replaying an old claim
  cannot roll a name back to one its owner abandoned. A rename inside the same
  second still advances it (`set_pseudo` uses `max(now, previous + 1)`).

### Two planes, one book

`PseudoBook` holds every verified claim, indexed by node id (what is this node
called?) and by directory key (who is called this?). Bounded **in entries and in
bytes** — a claim is ~5.3 kB of ML-DSA, so a count-only bound would still be a
memory-exhaustion vector.

- **Gossip** (`PSEUDO_ANNOUNCE`, a direct type re-stamped at each hop) spreads a
  claim to everyone reachable, and a freshly authenticated peer is caught up
  with `_PSEUDO_SYNC_MAX` claims, ours first. Re-gossiped **only when the view
  changed**, so the epidemic terminates on its own. This is what makes a
  *partial* search possible at all: you cannot hash half a name into a DHT key,
  but you can rank the names you already hold.
- **The keyed directory** (`DIR_STORE` / `DIR_FIND` / `DIR_FOUND`, replicated to
  and queried from the `_DIR_K` nodes nearest the key plus our direct peers)
  covers the rest: an **exact** name whose owner sits beyond the gossip horizon.

Both planes are bounded and rate-limited per ingress link, and both charge a bad
claim to the peer that sent it (`security.md`).

Node API: `set_pseudo` / `pseudo` / `pseudo_of(id)`, `find_pseudo(query)` (local,
ranked, instant), `search_pseudo(query)` (the same, widened by one exact
directory lookup), `publish_pseudo()` (replicate our claim into the directory),
`lookup_pseudo(pseudo)` (exact, network-wide). From an app:
`ConnectorClient.my_pseudo` / `lookup_pseudo` / `pseudos_of` / `refresh_names` —
all **read-only**, because the node's name belongs to whoever runs the node, not
to an app holding a connector token.

## Target-neighbourhood maintenance and recovery at startup

A node does not survive a sparse neighbourhood: it actively maintains a **group
of neighbours** chosen by XOR distance (the only criterion for keeping the
table), and can reach any node-id by relaying through its neighbours and the DHT
even with no common direct peer.

### The two regimes (`_maintain_neighbors`)

The cycle runs every `_NEIGHBOR_REFRESH = 30 s` (at startup through `start()`,
then in a loop), but what it does depends on what we already hold:

- **Searching** — while the node holds **fewer than `_NEIGHBOR_FLOOR = 3` live
  authenticated links**: a `kad_lookup` on its own id to refresh its
  neighbourhood, then a directed dial of the `_NEIGHBOR_TARGET = 5` XOR-nearest
  entries it has no session with (`_connect_routing`, IPv6 then IPv4). It is a
  directed dial, not a broadcast.
- **Quiet** — as soon as `_NEIGHBOR_FLOOR` links are held: no lookup, no dial. A
  node searching for its own id forever is nothing but traffic, and a mesh that
  never settles is a mesh an adversary can keep busy. Losing one of the three
  links (`_drop_failed_peer`, keepalive) restarts the search immediately.
- `force=True` (join/`bootstrap`) imposes a full searching cycle whatever we
  already hold: a fresh table has to fill up.

### Promoting a node seen in transit

The maintained set (`_neighbor_slots`) = the `_NEIGHBOR_FLOOR` nearest live
links; its **interest bound** (`_neighbor_cutoff`) is the distance of the worst
of the three.

- `_learn_reverse_path` sees every routable packet go by: if its `src_id` is not
  already a peer and it is **strictly nearer** than the bound, it enters
  `_neighbor_watch` (`_note_neighbor_candidate`).
- The next cycle dials those candidates **even in the quiet regime**: once the
  session is up, the new one enters the set and the least interesting leaves it.
  The evicted link is **never cut by force** (it may carry application traffic or
  relay for others): it simply stops being guaranteed.
- Bounds and safety: `_neighbor_watch` is capped
  (`_NEIGHBOR_WATCH_TRACKED = 64`, oldest evicted), entries that became live or
  were passed are purged on every cycle (`_neighbor_promotions`, at most
  `_NEIGHBOR_TARGET` per cycle), and **observing never wakes the loop**: the
  `src_id` of a routed packet is not authenticated, so it must not drive our dial
  cadence. At worst it costs one backed-off attempt towards an identity that will
  then have to prove its key at the handshake (`NodeID` = hash of the DSA key).
- Back-off per identity: every failing identity delays its next attempts
  (`_neighbor_retry_until`, minimum `2 s`, ceiling `60 s`); the number of
  identities tracked is bounded (`_NEIGHBOR_RETRY_TRACKED = 128`) so a wide scan
  cannot create endless state. Once the session is up, `_add_authed_peer` clears
  the penalty.
- Networks with no direct peers: if we have no reachable neighbour entry, we fall
  back on `_kademlia_lookup` and then an ordered multi-peer send to up to
  `_ROUTE_SEND_FANOUT = 5` candidates chosen by XOR distance, with a shared
  deadline. A peer that fails does not bring the message down: we try the next.
  Total failure is picked up by background route acquisition (`_defer_route`),
  never by blocking the incoming link.
- A lookup **does not inherit another's verdict**. `_kademlia_lookup`
  deduplicates by target (`_pending_lookups`): if one is in flight it waits for
  it — but if the target is still not in the table at the end, it **starts its
  own** with the remaining budget. That other lookup began from a different
  shortlist at a different moment; returning its failure as ours means giving up
  on an id we never asked about. One retry only: if the slot has been taken in
  the meantime we return `False` — two nodes cannot chain each other forever.
- Last resort: a bounded iterative `_kademlia_lookup(target)`
  (`_KAD_LOOKUP_MAX_ROUNDS = 4`, `_KAD_LOOKUP_TIMEOUT = 3.0 s`) aggregates
  `FOUND_NODE` until it stabilises; the results feed `_connect_routing` and the
  routing table.

## ⚑ The size of a `FOUND_NODE` (a post-quantum constraint)

An ML-DSA-65 certificate weighs **~7.3 kB** (subject key + issuer key +
signature), so a chain up to a root is ~**14.6 kB**. Answering a `FIND_NODE`
with Kademlia's `k = 20` entries would be ~292 kB: far beyond a packet's 60 000
byte ceiling. `Packet.create` raised, the exception was swallowed by the receive
loop, and **no** `FOUND_NODE` ever left — from the fifth known certified node
onwards, every lookup on the network timed out silently.

The reply is therefore **budgeted**:

- `_EntryPacker(budget)` stacks the nearest entries while they fit inside
  `_FOUND_NODE_MAX_BYTES = 32 000`, and **shares certificates** through an
  indexed pool (every chain ends on the same network root: sending it once per
  entry doubled the packet). In practice ≈ 3 entries per reply instead of
  nothing at all.
- Entries **with no chain** are skipped: the receiver drops them anyway
  (`_handle_found_node` requires a verifiable chain), so there is no point
  spending the budget. Chains are built as we go, so the budget also caps the
  CPU cost of a `FIND_NODE`.
- We **scan wider than k** (`_FIND_NODE_SCAN = 64`) to fill that budget: `k`
  bounds what we **return**, not what we **look at**. Usable entries are
  scattered through the table (a table learned by gossip holds many with no
  chain); limiting ourselves to the k nearest returned an **empty** reply as soon
  as those k had no chain.
- **The responder puts itself in the reply**, ranked by distance like any other
  entry. Kademlia classically excludes the responder (the seeker already knows
  it, they just talked) — false here: a `FIND_NODE` is **routed**, so the seeker
  may only reach the responder through a relay and never learn its entry. A
  lookup routed all the way to the **exact id being sought** then came back with
  that node's neighbours, the shortlist stopped progressing, and the lookup gave
  up one hop from an id it had in fact reached (`_kademlia_lookup` returns
  `routing.contains(target)`). The receiver still verifies the chain **and** that
  the subject of the first certificate *is* the entry's node_id: a relay cannot
  forge that entry.
- Fewer entries per reply = a few more rounds, never a dead lookup.
- `_query_allowed` limits `FIND_NODE`/`FIND_VALUE` per incoming link
  (`_QUERY_RATE_MAX` per `_QUERY_RATE_WINDOW`): these are the only tiny requests
  whose reply is enormous **and** routed towards an unverified `src_id` (a
  reflection lever). It is an **anti-flood valve, not shaping**: a peer's
  legitimate peak is around 66 per window (α × a lookup's rounds, flat as the
  network grows), and the bound is well above that. A bound close to normal
  traffic kills real lookups.

## Address propagation  ⚑ a central invariant

**The goal**: *knowing a node ⟹ knowing the whole set of addresses it
announces*, so that routing can pick the best medium ("if A↔B is Bluetooth and
B↔C is Wi-Fi…").

### What exists today

- `advertised_uris()` = every listening URI expanded over `_local_ips` +
  `_extra_addrs` (the discovered public IP, observed addresses).
- The **PING carries `advertised_uris`**; `_handle_ping` does
  `_routing.add(src, valid_uris, dsa_pub)` (a merge) and answers PONG.
  `_validate_uri` filters before adding ("reject by default").
- PINGs are sent: at `bootstrap()`, by the **keepalive loop** (~20 s,
  `_link_keepalive_loop`), **and on an address change** (targeted gossip, see
  below). `FOUND_NODE` also propagates known addresses. The PING doubles as an
  **RTT** measurement (see `_handle_pong`, surfaced in the console).
- Address discovery: `OBSERVED_ADDR` (a peer tells us the IP it sees us from),
  STUN, the public IP over HTTP → they feed `_extra_addrs`, then `_poke_net`.

### Address gossip on change (implemented)

When the announced set changes, we announce it **immediately** to recent peers
rather than waiting for the periodic keepalive:

- `_announce_addresses(reason)`: recomputes `advertised_uris()`, **skips if
  unchanged** (`_last_announced` → no storm), otherwise sends a PING (which
  already carries `advertised_uris`) to the **≤ `_ANNOUNCE_FANOUT` = 5**
  authenticated peers sorted by descending `last_seen`
  (`_recent_authed_peers`). Targeted Kademlia gossip: little traffic, fast
  convergence. It never raises.
- Triggers (`_announce_addresses_soon`, fire-and-forget from a sync context):
  `_on_network_change` (public/local IP), `_handle_observed_addr` (a new observed
  address), `add_listen` / `remove_listen`.
- The receiving peer, through `_handle_ping`, does
  `_routing.add(src, advertised_uris)` → it knows the new address. More distant
  nodes learn it lazily through a Kademlia lookup (`FIND_NODE`) — the normal
  Kademlia model.

An accepted limit: we push to our most recent **direct peers** (a PING is a
direct message). Wide diffusion stays lazy through Kademlia. A freshly
authenticated peer therefore does not *instantly* have all our addresses; they
arrive with the first gossip or keepalive. Do not write a hard dependency on
"an authenticated peer ⟹ all its addresses known at instant T".
