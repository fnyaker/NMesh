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

- **Two direct links in one bundle**: DTrump (UDP 31 ms + TCP 48 ms) and
  JeffreyEpstein (UDP 37 ms + TCP 63 ms) formed on their own. The second link
  was dialled automatically, and a link losing more than 10 % is benched.
- **Bundles over routed paths** (through one or two neighbours): Danil and
  The island form and fall apart with loss, as designed.
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
   Speedtests to DTrump: 107 kB/s with 28 % probe loss, then 340 kB/s with
   4.4 %. RTT goes from ~30 ms idle to 380–470 ms loaded. TCP on the same path:
   ~1 MB/s, no loss.
   Probable cause: a 50 ms RTO floor against a filling queue. Frames time out
   while not lost, the window falls back to its 32 kB floor, and Karn's rule
   keeps the RTT estimate from following (464 timeouts on the DTrump link).
   Proposed fix: a higher `_RTO_MIN` and/or undoing a spurious RTO.
   Note: this revisits the retraction recorded in `AGENTS.md` ("A conclusion
   drawn from a metric that cannot carry it"); the loss is real on the wire, but
   the collapse of the window under queueing is a defect either way.
2. **Links are re-dialled constantly.** Healthy TCP and UDP links to
   JeffreyEpstein (L130, L134, L149, then L191, L193, L211) and DTrump (L131,
   L132) are re-dialled every 20–30 s, and the redundant-link reaper closes the
   older one. Each time costs a post-quantum handshake plus ~324 kB of
   `RELEASE_ANNOUNCE` (BUGSVULNS 53). The dialler is not identified; ruled out:
   route acquisition, MLO, steering, rescue, reach dial-back.
3. **Links end without a trace.** L131 (TCP to DTrump) closed with no
   "link dropped" nor "link lost" line in the log.
4. **The zombie UDP link is back in another shape.** DTrump's inbound UDP link
   was never authenticated, delivered 0 packets, and was still held after
   991 s. DTrump never sends a CHALLENGE, so the double-accept fix does not
   fire. DTrump also publishes no version in the directory while the others
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
   - JeffreyEpstein now announces only its private UDP address
     (`udp://10.200.199.10:9001`), so `_mlo_second_address` dials an
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
