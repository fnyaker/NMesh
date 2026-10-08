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
| 1 | Membership chains and the routing answers that carry them | **fixed** (compaction), options below in progress |
| 2 | Links per node, and what probing them costs a relay | open |
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

Still to do on this point, as decided: smaller chains on the wire (the issuer's
key is the next certificate's subject key — 27 % per certificate, negotiated so
older nodes still parse), and ceilings (`_ENTRY_CHAIN_MAX`,
`_FOUND_NODE_MAX_BYTES`) set with room for the transient chain a member holds
between joining and being compacted.

**Not a scale problem, recorded so it is not re-audited:** `_QUERY_RATE_MAX`
(512 per 10 s per ingress identity) is a flood valve, measured against a
legitimate peak of ~66 that does not grow with `N`. What it still allows a
hostile peer is ~1.6 MB/s of answers from one link — a matter for point 3 and
for the early-drop work, not for growth.

## 5. Per-remote-node tables (first pass)

`MeshNode.__init__` holds 89 containers. Every one keyed by something the network
chooses is bounded: the rate tables share `_gossip_allowed` (≤ `_MAX_PEERS`
keys), the E2E tables `_MAX_PENDING_TARGETS`, `_MAX_PENDING_PER_TARGET` and
`_MAX_E2E_SESSIONS`, the rest by their own `_…_TRACKED`/`_…_MAX`. Two costs to
come back to: `_gossip_allowed` and `_query_allowed` sweep their whole table on
every packet (≤ `_MAX_PEERS`, so bounded, but per packet), and `_MAX_PEERS` = 128
links is what a public relay can give the members behind NAT that depend on it.
