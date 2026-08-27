# Inter-node protocol

Source of truth: `src/packet.py`, `src/node.py` (constants + `_handle_packet`).

## Packet format

`HEADER_FORMAT = '!BBB20s20sQ12s16s'` → a **79-byte header**, followed by the
payload.

| Field | Size | Notes |
|---|---|---|
| version | 1 | protocol (=1) |
| type | 1 | see the type table |
| ttl | 1 | decremented at every hop; **excluded from the AAD and from `msg_id`** |
| src_id | 20 | sender NodeID |
| dst_id | 20 | recipient NodeID (`0xff…ff` = broadcast) |
| msg_id | 8 | uint64, see below |
| nonce | 12 | `os.urandom(12)`, unique per packet (AES-GCM) |
| gcm_tag | 16 | AES-256-GCM authenticity tag |
| payload | ≤ 60000 | in the clear for control, encrypted for DATA/E2E |

> **Correction.** The old "75 bytes / CRC32" note is wrong: it is 79 bytes and a uint64
> `msg_id` derived from sha256.

### `msg_id` (anti-replay / anti-amplification)

`msg_id = int(sha256(version‖type‖src‖dst‖nonce‖gcm_tag‖payload)[:8])`
(`Packet.compute_msg_id`). **TTL and msg_id are excluded** from the computation.

It *binds the content* of the packet: a relay cannot forge a new `msg_id` for
the same payload to sidestep deduplication and amplify a flood. Verified on
receipt for routable types (see the gates).

### AAD and encryption (`Packet.aad`, `create_encrypted`, `decrypt_payload`)

- **AAD** (authenticated, not encrypted) = `version‖type‖src‖dst‖nonce` — **the
  TTL is not in it** (it changes at every hop).
- The DATA/E2E payload is encrypted with AES-256-GCM under the session key; the
  `gcm_tag` covers AAD + payload.
- The header is therefore *in the clear but authenticated*.

## Type table (`src/node.py`)

| Type | Val | Role |
|---|---|---|
| DATA | 0x00 | application data (E2E encrypted) |
| PING / PONG | 0x01 / 0x02 | liveness + **address gossip** (the PING carries `advertised_uris`; the PONG is **unconditional** — a node with no announceable address is entitled to one) |
| FIND_NODE / FOUND_NODE | 0x03 / 0x04 | Kademlia lookup (nearby nodes) |
| FIND_VALUE / FOUND_VALUE | 0x05 / 0x06 | DHT lookup by key |
| STORE | 0x07 | store a DHT value (content-addressed) |
| HANDSHAKE / HANDSHAKE_ACK | 0x08 / 0x09 | per-hop session (ML-KEM + ML-DSA + cert) |
| INVITE / INVITE_ACK | 0x0A / 0x0B | (legacy) presenting an invitation code |
| CHALLENGE | 0x0C | authentication challenge |
| E2E_HANDSHAKE / _ACK | 0x0D / 0x0E | end-to-end session (re-keying with a live session: the candidate is probed by DATA, see `security.md`) |
| OBSERVED_ADDR | 0x0F | "here is the IP I see you from" (public address discovery) |
| PUNCH_REQUEST / _RELAY | 0x10 / 0x11 | coordinating a NAT hole punch through a relay |
| PUNCH_PROBE / _ACK | 0x12 / 0x13 | **raw UDP datagrams** (not mesh Packets), ML-DSA signed |
| INVITE_SEEK | 0x14 | relayed invitation, **routable BEFORE auth**, token-gated |
| RELAY_CARRY | 0x15 | carries a handshake packet between two nodes through a relay |
| REACH_PROBE / _ACK | 0x16 / 0x17 | AutoNAT: "call me back to confirm I am reachable" |
| CATALOG_ANNOUNCE | 0x18 | gossip of a **signed release** for the app store catalogue |
| DIR_STORE / _FIND / _FOUND | 0x19 / 0x1A / 0x1B | pseudo directory: store/seek/answer a **signed claim** pseudo→node_id (exact name; the partial search is answered from the gossiped book) |
| ECHO_REQUEST / _REPLY | 0x1C / 0x1D | **routable liveness probe**: reach a node id multi-hop (a remote ping through relays) |
| RELEASE_ANNOUNCE | 0x1E | gossip of a **signed release of the node's own code**, prefixed by a `have` byte saying whether the sender holds the package (see [`../Updates/guide`](../Updates/guide)) |
| RELEASE_FETCH / _DATA | 0x1F / 0x20 | "send me this release's package from this offset" and a slice in answer — **routable**, so a holder several hops away is reachable |
| PSEUDO_ANNOUNCE | 0x21 | gossip of a **signed claim** binding a node's chosen name to its id (see [`routing.md`](routing.md)) |

Groupings (constants):
- `_DIRECT_TYPES`: a single authenticated hop → **they require an authenticated
  peer and `src_id == the authenticated peer`**. Only what is intrinsically
  per-link: `PING`/`PONG` (keepalive), `OBSERVED_ADDR`, the punch signalling
  (`PUNCH_*`, `REACH_PROBE*`), and the three gossip planes `CATALOG_ANNOUNCE` /
  `RELEASE_ANNOUNCE` / `PSEUDO_ANNOUNCE` (re-stamped at every hop during
  epidemic gossip).
- `_ROUTABLE_TYPES`: **everything addressed to a `node id`** → relayed multi-hop
  towards `dst_id` (`_forward_packet`). Includes `DATA`, `E2E_HANDSHAKE`/`_ACK`,
  `ECHO_REQUEST`/`_REPLY`, **and the Kademlia/DHT control plane**: `FIND_NODE`/
  `FOUND_NODE`, `STORE`/`FIND_VALUE`/`FOUND_VALUE`, `DIR_STORE`/`DIR_FIND`/
  `DIR_FOUND`, plus the release transfer `RELEASE_FETCH`/`RELEASE_DATA`. → the
  DHT, the directory and a package download work `A→X` through relays, not only
  towards a direct peer.
- `INVITE_SEEK` and `RELAY_CARRY` are handled **before** the gates (pre-auth,
  strictly bounded/token-gated).

### Application sections (inside the DATA payload)

**Management** (everything else in the table: PING, routing, DHT, handshakes…)
lives in **distinct packet types** — never in DATA. **Application data**, on the
other hand, lives only in `DATA`, and is subdivided into **per-app sections**:
the E2E-decrypted DATA payload is `app_id(8) ‖ payload` (see
`src/app_channel.py`). The node treats the payload as opaque; it is the
**connector** that adds/removes the frame and demultiplexes by `app_id`, so that
an app sees only its own section. A payload too short to carry an `app_id` is
dropped. `app_id` is reserved for built-in apps (`builtin_id`) and bound to the
author key for deployed apps (`deployed_id`, signed package).

Built-in apps each occupy their own section: `builtin_id("chat")`,
`builtin_id("fleet")`. The management app **adds no packet type** — its protocol
(enrolment, status, update, shell, scan, provisioning) lives entirely inside its
`DATA` section, so the node's management plane is untouched. See
[`Docs/Apps/fleet`](../Apps/fleet).

## Validation gates (`_handle_packet`) — the security core

The exact order applied to every packet received:

1. `INVITE_SEEK` → dedicated pre-auth handler (rate-limited per link, bounded).
   Return.
2. `RELAY_CARRY` → dedicated handler. Return.

> **Order inside the two pre-auth handlers.** TTL, then the **rate limit**, then
> `msg_id`, then dedup, then the signature. The rate limit sits above `_is_seen`
> because `_is_seen` is not a query — it *inserts*, into the node-wide dedup
> table. These handlers run before every authentication gate, so any socket that
> connects reaches them; with the limit below the insert, an unauthenticated
> peer could flush the whole replay window (`_MSG_DEDUP_MAX`, FIFO) at line
> rate, and dedup is what stops a routed packet looping and a relay
> re-injecting the same payload. The expensive ML-DSA verification stays last.
3. If `type ∈ _DIRECT_TYPES`: reject if the peer is not authenticated, or if
   `src_id != authenticated_id`. ("reject by default".)
4. If `type ∈ _ROUTABLE_TYPES`:
   - an authenticated peer is required;
   - `msg_id == compute_msg_id()` or reject (anti-amplification);
   - `_is_seen(msg_id)` → already seen → reject (bounded deduplication,
     `_MSG_DEDUP_MAX = 10 000`, FIFO eviction);
   - `_learn_reverse_path`: the ingress link is remembered as the return path
     towards `src_id` (bounded/dated, see `routing.md`);
   - if `dst_id` is neither us nor broadcast → `_forward_packet`, then return.
5. Otherwise, dispatch to the type's handler.

## Forwarding (`_forward_packet`) — greedy routing

For a packet we are not the destination of (TTL > 1):
1. A **direct peer** towards `dst` (authenticated, with a session) → send
   (TTL-1).
2. Otherwise the **observed return path** towards `dst` (`_route_hints`), if it
   is fresh and its link alive — proof beats an XOR guess.
3. Otherwise the **nearest neighbour** by XOR distance
   (`min(distance(dst, peer))`).
4. No candidate → `_defer_route`: a Kademlia lookup plus an on-demand route in a
   **bounded background task**, never inside the receive loop of the incoming
   link (it used to sit there frozen for several seconds, and the `FOUND_NODE`
   it waited for often had to come back over that very link — see `routing.md`
   and `gotchas.md`).

`with_decremented_ttl()` at every hop; TTL ≤ 1 → we do not relay (anti-loop, on
top of `msg_id` deduplication).

## The body of a `FOUND_NODE` (certificate pool)

```
query_id(8) ‖ pool_count(H) ‖ [cert_len(H) ‖ cert]*pool_count
            ‖ entry_count(B) ‖ entry*entry_count
entry = node_id(20) ‖ addr_count(B) ‖ chain_len(B)
        ‖ [addr_len(H) ‖ addr]*addr_count ‖ index(H)*chain_len
```

Chains reference the pool by index instead of repeating post-quantum
certificates of ~7.3 kB. Decoding bounds (reject by default):
`pool_count ≤ _ENTRY_POOL_MAX`, `entry_count ≤ _ENTRY_COUNT_MAX` (= k),
`chain_len ≤ _ENTRY_CHAIN_MAX`, indices inside the pool. An unreadable
certificate voids the entry's chain (never a partial chain). On the sending
side, the reply is **budgeted in bytes** — see `routing.md`, it is an invariant:
without the budget the reply exceeded the packet ceiling and was never sent. The
sender **includes itself** among the candidates (ranked by distance): a routed
`FIND_NODE` may come from a seeker who only reaches it through a relay and who
would otherwise never learn its entry (see `routing.md`).

## Invariants (reminder, see CLAUDE.md)

- The header is in the clear but **authenticated** (AAD). The application
  payload is E2E encrypted.
- `msg_id` binds the content, and is **verified on receipt**.
- TTL decremented per hop, outside the AAD and outside `msg_id`.
- Bounded deduplication. Reject by default for any malformed/unauthorised
  packet.
