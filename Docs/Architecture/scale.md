# Scale: what grows with the mesh, and what must not

NMesh is meant to run on thousands of machines and more. A cost that grows with
the number of nodes in the mesh — per node, in CPU, memory, storage or traffic —
is a cost every node pays more of as the mesh succeeds, and the mesh stops
before it gets big. This document is the audit of that, one point at a time:
what each point costs as a function of the mesh, what bounds it, and what was
found wrong.

**Method.** For each point: the cost written as a function of `N` (nodes in the
mesh), `P` (links one node holds, ≤ `_MAX_PEERS`) and `D` (generations of
invitation between a member and its root); every table it fills and the bound
on it; a measurement on real nodes where the arithmetic is not enough
(a probe script first, then a test in `tests/integration`); a fix with a
test for anything that grows.

| # | Point | State |
|---|---|---|
| 1 | Membership chains and the routing answers that carry them | **fixed** (compaction, lookup end); smaller chains on the wire in progress |
| 2 | Links per node, and what probing them costs a relay | **fixed** (probe budget) |
| 3 | Gossip planes (addresses, revocations, abuse, releases) | open |
| 4 | Distributed storage (DHT, names, package directory) | open |
| 5 | Per-remote-node tables | partly reviewed (below) |
| 6 | Relaying and routed paths | open |
| 7 | CPU of post-quantum verification | open |
| 8 | Persistence | open |
| 9 | Apps, console, metrics | open |

## 1. Membership chains

A member's certificate is signed by whoever invited it (`_handle_handshake`,
`issue_cert` on an accepted invitation), and that inviter's by whoever invited
it: the chain to the root is `D + 1` certificates. One certificate is 7 275 bytes
(ML-DSA-65: the subject's key, the issuer's key and a signature). Measured on
real nodes inviting one another in a line:

| `D` | chain | bytes | what broke |
|---|---|---|---|
| 1 | 2 | 14 550 | — |
| 2 | 3 | 21 825 | one entry per `FOUND_NODE` |
| 3 | 4 | 29 100 | one entry, at the edge of `_FOUND_NODE_MAX_BYTES` (32 000) |
| 4 | 5 | 36 375 | **no longer fits a routing answer**: undiscoverable to anybody who does not already hold the certificates |
| 6 | 7 | 50 925 | **refused by every handshake** (`_ENTRY_CHAIN_MAX` = 6) |
| 7 | — | — | **cannot join**: the inviter's own chain is refused |

The cost is linear in `D`, and `D` is how the mesh grew, not something anybody
chose: a fleet where machines invite machines reaches it in a week.

**Fixed — chain compaction.** A member whose chain is longer than two sends it
to an ancestor, the root first (`_compact_own_chain`, a `CERT_RENEW` whose
payload starts with `_COMPACT_MAGIC`); the ancestor checks the chain runs
through it and signs the member directly (`_serve_chain_compaction`). A root
that does not answer is followed by the next ancestor down, then the asking
backs off — the mesh is decentralised, and no member depends on one node being
up: `_renew_own_membership` keeps every membership alive with its own issuer,
so the chain through the inviter is a live fallback for the day the root is
gone. Every member then presents two
certificates whatever `D` is — measured to `D` = 8, each joining with three and
ending with two. The renewal loop asks after its first sweep and every
`_COMPACT_RETRY` until it is short, so a root that was offline is asked again.

What a direct signature would have lost is revocation: revoking an inviter used
to void every chain through it. The root keeps, for each member it compacted,
the issuers its chain ran through (`lineage.py`, persisted with the
certificates), and when it accepts a revocation of any of them it revokes its
own certificates for the members below (`_cascade_revocation`) — and for the
named member itself when the revocation comes from one of its own ancestors,
which could already take it out by revoking its own invitee. The book is
bounded (`lineage.MAX_ENTRIES`) and **full refuses rather than evicts**: a member
left with its long chain is better than one its inviter can no longer revoke.

**Ceilings, measured before moved.** `_ENTRY_CHAIN_MAX` (6) is already what the
packet cap allows: an invitation's answer carries the inviter's chain, the
certificate it issues and the key material, and with 7 kB certificates a
seven-long chain makes it ~64 kB, past `Packet`'s 60 000. It can only rise once
certificates are smaller on the wire. `_FOUND_NODE_MAX_BYTES` was **not**
raised: a simulated Kademlia mesh (1 000 to 100 000 ids) finds its targets
equally well with 3, 5, 8 or 20 entries per answer — answer size is not what
limits a lookup, and a bigger one only buys an attacker more reflection.

What did limit it was the **lookup's end**. With tables as sparse as NMesh's
(it never refreshes a bucket) and a share of nodes offline:

| mesh | per bucket | offline | old rule, 4 rounds | Kademlia's rule, 10 rounds |
|---|---|---|---|---|
| 10 000 | 2 | 30 % | 64 % | 98 % |
| 50 000 | 2 | 30 % | 30 % | 96 % |
| 50 000 | 3 | 30 % | 62 % | 96 % |
| 50 000 | 2 | 50 % | 18 % | 66 % |

The old rule stopped when the closest id it *knew of* stopped changing — what a
round whose candidates were all offline does. `kad_lookup` now stops when the
closest node that *answered* did not improve and nothing left to ask is closer,
under `_KAD_LOOKUP_MAX_ROUNDS` = 10 (was 4); it costs 6–7 rounds on average in
the hard case, and ends as early as before in the easy one.
`tests/test_lookup_termination.py` runs the real loop against such a mesh
(70 % found under the old rule, ≥ 90 % now). Keeping buckets populated is the
other lever, left to point 3.

Still to do on this point: smaller chains on the wire (the issuer's key is the
next certificate's subject key — 27 % per certificate, negotiated so older
nodes still parse), after which `_ENTRY_CHAIN_MAX` can rise.

**Not a scale problem, recorded so it is not re-audited:** `_QUERY_RATE_MAX`
(512 per 10 s per ingress identity) is a flood valve, measured against a
legitimate peak of ~66 that does not grow with `N`. What it still allows a
hostile peer is ~1.6 MB/s of answers from one link — a matter for point 3 and
for the early-drop work, not for growth.

## 2. Links per node, and what probing them costs a relay

A node holds at most `_MAX_PEERS` = 128 **links** (not nodes). That is the
capacity a public relay gives the members behind NAT that depend on it, and
the ratio of public nodes to NAT'd ones has to respect it: a member that finds
its relay full is refused at the handshake and looks for another through its
neighbourhood.

Per link, measured on one relay with twenty leaves each holding a TCP and a UDP
link to it:

| state | relay, packets/s | relay, kB/s |
|---|---|---|
| leaves idle (slow cadence, 15–20 s) | 8 | 0.8 |
| leaves awake, before | 810 | 80 |
| leaves awake, after | 400 | 35 |

Idle costs nothing. Awake — somebody's console or app open on a leaf — every
link it bundles is probed ten times a second, and the relay answers each: its
cost grew with how many *other* nodes were being looked at, with nothing on its
side to bound it. At 128 links that was ~2 600 packets a second of probes.

**Fixed — a probe budget.** The fast floor a node offers rises with the links
probing it fast, so their answers stay under `mlo.FAST_PROBE_BUDGET` (200 a
second); `accord` takes the higher floor, so every peer follows without being
asked, and the floor never closes the fast range. A relay's probe load is now
~400 packets a second at most, whatever the mesh, and every bundle measured
stays active (`transports.md`, *A busy node offers a higher fast floor*).

Per-link memory is bounded by the media: a UDP link's reorder buffer
(`max_reorder`, 256 frames of ~1.2 kB) is its largest structure, ~300 kB at
worst, so 128 links are ~40 MB in the worst case and far less in practice.

## 5. Per-remote-node tables (first pass)

`MeshNode.__init__` holds 89 containers. Every one keyed by something the network
chooses is bounded: the rate tables share `_gossip_allowed` (≤ `_MAX_PEERS`
keys), the E2E tables `_MAX_PENDING_TARGETS`, `_MAX_PENDING_PER_TARGET` and
`_MAX_E2E_SESSIONS`, the rest by their own `_…_TRACKED`/`_…_MAX`. Two costs to
come back to: `_gossip_allowed` and `_query_allowed` sweep their whole table on
every packet (≤ `_MAX_PEERS`, so bounded, but per packet), and `_MAX_PEERS` = 128
links is what a public relay can give the members behind NAT that depend on it.
