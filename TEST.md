# Testing guide — NMesh

## Unit tests

Fast, no real network. They cover all the internal logic, including fuzzing (no
hostile byte crashes a parser).

```bash
NMESH_SETUP_ONLY=1 ./start.sh   # installs everything, starts no node
. .venv/bin/activate
pytest
```

(`start.sh` also installs the test dependencies; it handles distributions that
ship `pip`/`venv` separately — see [`Docs/Setup/guide`](Docs/Setup/guide). By
hand: `python3 -m venv .venv && . .venv/bin/activate &&
pip install -r requirements.txt`.)

Around 1600 tests in ~30 seconds.

---

## Integration tests

Real nodes, real post-quantum crypto, a real network stack. Excluded by default
(see `pyproject.toml`); run them explicitly:

```bash
pytest tests/integration
```

Among other things they check:
- The full flow invitation → handshake → session → E2E data, over **TCP** and
  over the **spool** transport (directory/file, no socket).
- **Multi-hop A→B→C** routing (the ends only talk through the relay), including
  over two distinct file media.
- Routing **beyond a handful of nodes** (`test_routing_scale.py`): a relay whose
  table exceeds the historical cliff of five certified nodes must still answer
  lookups, relay ping/data/directory, learn the return path along a chain, and
  stay responsive under packets addressed to unreachable ids.
- Recovery **after a restart** without re-inviting (routing + E2E sessions
  restored from disk).
- **Self-repair** (purging a dead peer) and the **app→mesh→app** path through
  the data connectors.
- The **management app on a real mesh** (`tests/integration/test_fleet.py`):
  a full enrolment with a human decision followed by an authorised command, an
  un-enrolled operator who gets nothing, an ungranted capability refused,
  revocation cutting access off, and section isolation (another app sees none of
  the traffic).

---

## CI

GitHub CI (`.github/workflows/ci.yml`) runs the unit tests and then the
integration tests on every push to `main` and every pull request.

The tests run **inside the base image** (`docker/Dockerfile.base`, published by
`base-image.yml`), which already carries a **compiled liboqs** and every
dependency. So the heavy C library is no longer rebuilt on every run, and we
test on the exact runtime the app ships with (Python 3.13). If the base image is
not reachable (first bootstrap, or a fork PR with no package access), CI builds
it once locally to stay green — the same fallback as the `docker` job.

### `[gwN] node down: Not properly terminated`

This is **not** a test failure and not flaky infrastructure. It means a
pytest-xdist worker *process* died without finishing its side of the protocol,
and in this repository there is one way that happens: a test hung, and
`--timeout=120 --timeout-method=thread` answered the hang with `os._exit(1)`.
The stack dump the plugin writes on its way out is usually lost with the
process, which is why the line arrives with no traceback and no test named.

To find the test, re-run with the timeout raising an exception instead of
killing the worker:

```bash
pytest -q --timeout=60 --timeout-method=signal
```

That reports the hang as an ordinary failure, with the traceback pointing at
whatever the loop was parked on.

**Reproduce on the CI interpreter, not yours.** CI runs Python 3.13; the suite
passing on an older local Python proves less than it looks. `wait_closed()`
changed semantics in 3.12 and deadlocked the data connector's shutdown on 3.13
while staying green 3.11 (`gotchas.md` §1). Either run the base image, or point
a 3.13 interpreter at the tree:

```bash
docker run --rm -v "$PWD:/app" -w /app ghcr.io/fnyaker/nmesh-base:latest pytest -q
```

---

## Where the tests are

```
tests/
├── test_packet.py / test_crypto.py / test_cert.py     — primitives
├── test_node.py / test_routing.py / test_handshake.py — node & routing
├── test_routing_stability.py                          — routing regressions:
│     the size of a FOUND_NODE, acquiring a route outside the receive loop,
│     the return path learned from traffic, bounded teardown
├── test_e2e.py / test_data.py                         — E2E encryption
├── test_invite*.py / test_cert_store.py               — invitations & trust
├── test_features.py                                   — capability negotiation:
│     silence means the classic set, a name we do not know is not an offence,
│     nothing security-critical is negotiable
├── test_reputation.py / test_app_guard.py             — zero trust: the ledger,
│     the rate gate, the signed accusation, and above all what hearsay may NOT
│     do — no crowd of members can get a node cut off, an accusation naming us
│     is neither acted on nor relayed, the accused is never told; plus an app's
│     own per-kind allowances, reported once per window and never fatally
├── test_cert_renewal.py / test_revocation.py          — certificate lifecycle:
│     expiry, pruning, the renewal exchange and its refusals; and taking a
│     membership back: who may say it, what it may not reach, a root that can
│     only be dropped locally, records that survive a restart
├── test_fuzz.py                                       — hostile inputs
├── test_spool.py                                      — bundle & file transport
├── test_webconsole.py / test_data_connector.py        — console & connector
├── test_app_auth.py                                   — application identity:
│     scoping (app/audience/purpose/ctx), freshness, anti-replay, key binding,
│     hostile parsing, mutual login
├── test_fleet*.py / test_console_fleet.py             — the management app: the
│     three authorisation gates taken one at a time (a signature missing/altered/
│     replayed/issued for another node or another purpose, an un-enrolled sender,
│     a missing capability), SSH credentials that never leak, a ledger that fails
│     closed, and the `manage` console relay: refused paths (fleet, remote, chat,
│     outside the API), splitting and reassembling a reply, an over-large reply
│     explained rather than truncated, a reply forged by a third party ignored,
│     bounded calls
├── test_fleet_deploy.py                               — remote deployment and the
│     right to update: the authorised script is not inside the node's prefix, the
│     rule names one path with no wildcard, the wrapper refuses every argument,
│     the plan prefers the grant when there is one, `NoNewPrivileges` is seen
│     **before** sudo is ever run (and a node already root is unaffected), and the
│     systemd unit follows the grant instead of undoing it; plus, for deployment:
│     install.sh travels in the payload and nothing reimplements it, no password
│     written into a script, escalation stated rather than probed, prompt order
│     (login then escalation, never replayed), refusing a system install with no
│     route to root
├── test_join_ticket.py / test_qr.py                   — compact ticket and QR:
│     round trip, case and spaces immaterial, a typo caught, random bytes that
│     raise nothing but TicketError, a hostname refused; for the QR, structure and
│     bounds, plus — if the optional tooling is installed — module-by-module
│     equality with an independent encoder and a real decode of the rendered SVG
├── test_console_auth.py                               — console credential:
│     the password never stored, a salt per credential, a corrupt file or an
│     unknown algorithm refused, an outsized input rejected before hashing,
│     mode 0600 even under a permissive umask
├── test_trace.py                                      — protocol trace:
│     never a payload in what is kept, a bounded ring, automatic stop, a
│     malformed packet that does not raise, throughput computed over the
│     recording window (not over the burst), the file in 0600
├── test_session_store.py                              — persistence (encrypted)
├── test_start_script.py / test_install_script.py      — both scripts, sourced in
│     library mode (nothing is installed): distro, sudo, venv probe for one;
│     init detection (systemctl without systemd), privileges, paths, creating the
│     dedicated system account, directories never handed to root by mistake,
│     generated units, tree copying for the other. Including: a bare
│     systemd-style environment (no HOME, a home that does not exist or is not
│     writable) and liboqs reuse (cache, an unloadable candidate never adopted,
│     verification at the destination)
├── test_updater.py                                    — GitHub update:
│     version comparison, hostile fields bounded, a booby-trapped archive
│     (absolute path, traversal, symlink, special file), state and venv never
│     touched, restore after a failure, the repository pinned
├── test_config.py                                     — configuration file:
│     hostile parsing (a broken line, an unknown key, a huge file, random bytes,
│     a value trying to open a second line), precedence, settings not editable
│     from the console, mode 0600, installer merge
├── test_docker_image_tree.py                          — the image carries what
│     fleet provisioning requires ("no NMesh tree at /app")
├── test_webassets.py                                  — the web assets, checked
│     at build time: the JS parses (a syntax error is a blank page, not a red
│     test), no `$("id")` points at a missing element, no external resource, no
│     `style=` attribute (the CSP ignores it silently), and the terminal emulator
│     reads back what a real shell writes (`term_emulator_test.js`, run under
│     node). Also the shared node view: one implementation mounted in four places
│     (the console dialog, chat's panel, fleet's sheet, the `/node` page), it only
│     offers what an app declares, it hides the button pointing back where you
│     came from, and the addresses start folded away
├── test_transport_options.py                          — configuring a transport
│     without knowing what a transport is: coercion and bounds for every kind
│     (bool/int/float/text/choice/multi), partial application (one bad field does
│     not throw away the good ones), SETTINGS replaced and not mutated, the file
│     carrying `scheme.option` keys without validating them, a bounded section, a
│     render/parse round trip, and a mistyped setting reported at startup, never
│     fatal
├── test_link_stats.py                                 — what the mesh shows of
│     itself: jitter telling a steady link from one that oscillates, loss not
│     inferred from a single probe, a bounded history, per-address status (in use
│     beats the log, "never tried" ≠ "broken"), a log bounded on both axes, and a
│     transport that raises or returns nonsense not breaking the snapshot
├── test_app_api.py                                    — the app API surface: an
│     operation that is not declared does not exist (even when the method is
│     there), an undeclared argument is refused and not ignored, every value is
│     coerced and bounded, an app that stopped is no longer reachable, an app that
│     raises does not hand over its internals — and what chat and fleet expose is
│     pinned (widening it is a security change)
├── test_address_retry.py                              — re-dialling an address:
│     by hand (one `proto://addr` or all of them, and what each one did is
│     reported; an address that is not this node's is refused without dialling),
│     the periodic loop (the cadence belongs to the medium, a pass is capped
│     however many nodes are waiting, a node already linked is never re-dialled,
│     and the loop survives a medium that raises), and latency steering (off
│     until asked for, a marginal gain moves nothing, a real gain moves and closes
│     the old link, never two links to one node after the measurement), plus the
│     priority system: a priority's bounds, the latency↔priority slider at both
│     extremes, an address never measured worth the middle, latency that curves
│     (an absurd measurement does not flatten the real differences), the order
│     shown to the operator being the one that dials, and a transport manager that
│     cannot answer stopping nothing
├── test_ui_contrast.py                                — colour tokens: the WCAG
│     ratio of every text/background pair in both themes, and no page redefining
│     a token of the system
└── integration/                                       — real nodes (TCP + spool)
      including test_idle_chatter.py: two joined, idle nodes stay quiet (the
      FIND_NODE/FOUND_NODE loop that used to saturate the link), and discovery
      still works when there really is something to find; test_join_ticket.py:
      a real join from the ticket alone, single use, an expired ticket, a forged
      code, the "confirmed public address" gate; and test_fleet.py, which sends a
      relayed console call across a real mesh (a 90 kB reply, so several frames)
      and checks that it is refused without the `manage` grant
```
