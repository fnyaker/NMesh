# Live test over MCP — 2026-10-06 (0.4.61)

A pass over the node's operations through the MCP server, on the real mesh,
with MLO first. Nothing in the code was changed by this pass; every problem
below is still open unless stated otherwise.

State left on the node: every setting changed during the pass was put back
(`balance` 40, `dynamic` off, `skew_ms` 30). The log ring was started for the
pass and **left running** so the traces can be read; the trace stopped by
itself after 60 s.

## What works

### MLO

- **Two direct links in one bundle**: relay B (UDP 31 ms + TCP 48 ms) and
  relay A (UDP 37 ms + TCP 63 ms) formed on their own. The second link
  was dialled automatically, and a link losing more than 10 % is benched.
- **Bundles over routed paths** (through one or two neighbours): node D and
  node C form and fall apart with loss, as designed.
- **The dial backoff** works, and `waiting` lists the candidate it waits on.
- **Settings**: `skew_ms` 0 is clamped to 1 (then restored to 30). On a local
  test node, `drop_percent` outside 1–100 and a huge `skew` are clamped
  (150 → 100, -5 → 1, 10⁹ → 10000).

### Network

- `node_ping`, `node_ping_node` (routed, 40 ms), `network_recheck`,
  `network_probe` answer.
- `network_balance` set to 50 and back to 40.
- `network_dynamic` turned on and off again; no steering was observed while on.
- `network_listen` then `network_unlisten` on `tcp://127.0.0.1:19500`, checked
  end to end with a socket.

### Read-only

Every read tool answers: `node_state`, `node_list`, `transports_options`,
`trace_set` / `trace_status`, `logs_*`, `alerts_list`, `pseudo_get` /
`pseudo_search`, `packages_search`, `keys_overview`, `store_overview`,
`app_mcp_status`, `app_fleet_relation`.

## Problems found (none fixed)

1. **UDP collapses under load.**
   Speedtests to relay B: 107 kB/s with 28 % probe loss, then 340 kB/s with
   4.4 %. RTT goes from ~30 ms idle to 380–470 ms loaded. TCP on the same path:
   ~1 MB/s, no loss.
   Probable cause: a 50 ms RTO floor against a filling queue. Frames time out
   while not lost, the window falls back to its 32 kB floor, and Karn's rule
   keeps the RTT estimate from following (464 timeouts on the relay B link).
   Proposed fix: a higher `_RTO_MIN` and/or undoing a spurious RTO.
   Note: this revisits the retraction recorded in `AGENTS.md` ("A conclusion
   drawn from a metric that cannot carry it"); the loss is real on the wire, but
   the collapse of the window under queueing is a defect either way.
2. **Links are re-dialled constantly.** Healthy TCP and UDP links to
   relay A (L130, L134, L149, then L191, L193, L211) and relay B (L131,
   L132) are re-dialled every 20–30 s, and the redundant-link reaper closes the
   older one. Each time costs a post-quantum handshake plus ~324 kB of
   `RELEASE_ANNOUNCE` (BUGSVULNS 53). The dialler is not identified; ruled out:
   route acquisition, MLO, steering, rescue, reach dial-back.
3. **Links end without a trace.** L131 (TCP to relay B) closed with no
   "link dropped" nor "link lost" line in the log.
4. **The zombie UDP link is back in another shape.** relay B's inbound UDP link
   was never authenticated, delivered 0 packets, and was still held after
   991 s. relay B never sends a CHALLENGE, so the double-accept fix does not
   fire. relay B also publishes no version in the directory while the others
   show 0.4.61 — it may run an older release.
   Proposed fix: reap an inbound unauthenticated link that delivered nothing
   within the handshake deadline — after listing every holder of that state
   (`relay_only` links and a relay's joiner link are unauthenticated on
   purpose).
5. **`logs_query` cannot filter by date.** `since_time` / `until_time` are
   capped at `app_api.MAX_COUNT` = 10⁶ (`src/control/modules/logs.py:68-69`),
   while the log stamps unix seconds (~1.79 × 10⁹). Fix: give both parameters a
   `limit=` that fits a timestamp.
6. **The speedtest cannot read the 4 MB/s goal.** It keeps 8 probes of 16 kB
   in flight (`_SPEED_INFLIGHT`, `_SPEED_CHUNK`), which caps it near 1 MB/s at
   a 130 ms loaded RTT. It also loads a single link, so it never measures what
   an MLO bundle adds.
7. **`releases_overview` is too large for an MCP client**: 144 000 characters,
   because each of the 30 releases embeds its publisher's full public key.
8. **Minor**
   - `fast_min` greater than `fast_max` is silently swapped instead of refused.
   - `transfer_kinds` is empty for the MCP origin.
   - relay A now announces only its private UDP address
     (`udp://10.0.199.10:9001`), so `_mlo_second_address` dials an
     unreachable address.

## Not tested

- **Hostile values on the real node**: the permission classifier refused
  `network_mlo` with `drop_percent=150` and with `fast_min` > `fast_max`. They
  were checked on a local test node instead (above). Allowing them needs a
  permission rule for `mcp__nmesh__network_mlo`.
- **Left out on purpose** — destructive, or reaching other people:
  - `node_restart`, `node_forget`;
  - `trust_*`, `keys_create` / `keys_adopt` / `keys_offer`;
  - releases and store (`releases_publish` / `install` / `apply` / `trust`,
    `store_install` / `uninstall`);
  - `join_*`, chat sending, fleet enrolment / invitation / shell;
  - punch on/off, `network_udp` stop, `config_profile`, `config_save`.
- **Not done yet**: `mlo_always`, LAN discovery, `network_punch_open`, the
  `releases_check` and `node_retry` jobs, and a measurement of MLO under real
  load across two links.

## Proposed order of work

1. UDP RTO under load (1).
2. Link re-dialling and silent link ends (2, 3).
3. The inbound zombie (4).
4. `logs_query` dates and the speedtest bounds (5, 6).
5. `releases_overview` size and the minor items (7, 8).

## Follow-up (0.4.62)

Items 1 to 6 and 8 were then worked on, in that order. What the live node's log
showed while doing so changed two of the diagnoses above.

| Item | Outcome | BUGSVULNS |
|---|---|---|
| 1. UDP under load | The log showed `srtt` 29 ms beside `rto` 1 600 ms: a timeout resent the whole window, so nothing could be timed. Fixed with F-RTO; the higher `_RTO_MIN` proposed above was measured and **rejected** (it costs 20–45 % on a lossy path). IP fragmentation of large frames is the other suspect and stays open. | 61, 63 |
| 1b. Found on the way | A two-hour suspend left links its peers had dropped, black-holing traffic for 96 s. Fixed: links end on waking from a long sleep. | 62 |
| 2. Link churn | The dialler was found: node c0ffee00 shares a public IP with two others, and each `WRONG_ADDRESS_TTL` (600 s) bought a handshake and a whole redundant link. Fixed. | 64 |
| 3. Silent link ends | The dial's clean-up of that same churn. Fixed, with the two other silent paths. | 65 |
| 4. The inbound zombie | Fixed: an accepted link with no packet by the handshake deadline is ended. | 66 |
| 5. `logs_query` dates | Fixed, with the sequence numbers that had the same ceiling. | 67 |
| 6. Speed test ceiling | Fixed: the window opens with the link; `bundle` measures every direct member at once. | 68 |
| 7. `releases_overview` size | Not done. | — |
| 8. Minor | All three fixed. | 69 |

## Re-test on 0.4.62, after the deploy

| What | Reading |
|---|---|
| Speed test to relay B (TCP) | 32.9 MB/s one way, 0 loss, 19.3 ms idle / 25.1 ms loaded, window grown to 64 — was 6.7 MB/s with the fixed window |
| UDP links to relay B, relay A, node C | 0 spurious timeouts, `rto` 50 ms beside `srtt` 14–20 ms |
| `transfer_kinds` for the MCP origin | `package`, `app`, `release` — was empty |
| Mute accepted link (66) | ended at 60 s every time; relay B's listener opens a new one every ~100 s |
| Wrong-node dials (64) | refused at the handshake, three in eight minutes — but each cost the answering node's healthy link (**71, open**) |
| Found | a storm of UDP links between our listener and node C's, ~70 a second (**70, open**) |

The MCP tool list was read before the deploy, so `node_speedtest` did not
offer `bundle` yet; the bundle measurement is still to be read live.
