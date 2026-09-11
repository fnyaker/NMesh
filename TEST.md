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

Around 2500 tests in ~30 seconds.

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
- **Two real links, one bundle** (`tests/integration/test_mlo_pair.py`): a pair
  holding both a TCP and a UDP link negotiates a cadence, probes fast enough to
  measure both, forms a bundle and actually sends down both of them — the one
  thing no unit test can show, because every way this breaks is a bundle that
  quietly never forms while everything goes on working at half the throughput.
  And the other direction: a node that declares a phone's cadences is left alone
  over real sockets — no striping at it, and an idle probe once a minute.
  The same file also starts a pair on **one** link and lets it get the second
  one itself: nothing in the test dials it, which is what makes the case worth
  running — every other pair in that file was bundled because the test opened
  the second link by hand, exactly as an operator pressing "retry every
  address" used to have to.
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
├── test_release_trust.py                              — what may replace this
│     node's code: corroboration counted in signatures and never in mirrors, a
│     quorum of endorsed keys that 200 minted publishers cannot reach, a
│     disputed version refused by both routes, and a publisher key that stays
│     encrypted at rest
├── test_pkg_dir.py                                    — the package directory:
│     a record can only say what its own key signed, an unknown flag or kind is
│     refused, the keys it is filed under are derived from the name and from
│     the release rather than declared, a source digest that ignores
│     documentation and nothing else, a crowded prefix bucket that drops a
│     pointer and never a package — and the publication proof, which names the
│     node and the release so it cannot be lifted onto another record
├── test_release_mesh.py                               — releases over a mesh:
│     publishing, gossip that terminates, the three install gates, the
│     automatic pass and the restart it ends in — and that a release is bytes
│     and a signature, so the publisher is never one of the nodes a fetch asks,
│     holders come before peers, the number asked is bounded, an install runs
│     on the descriptor in hand rather than on that key's newest, and dropping
│     the publisher index did not drop the publisher gate; plus recommending is
│     holding — a record is the node's own sentence, a detached key needs no
│     second artefact, and a release nobody can point at is not recommended
├── test_key_share.py                                  — handing a publisher key
│     to another node: an offer signed by a key the sender does not hold, an
│     offer replayed at a node it does not name, an acceptance whose node id
│     does not match the key inside it, a substituted KEM key, a grant opened
│     with the wrong secret or carrying a secret that does not match the offered
│     public half, an offer that expired, and a store that only ever keeps a
│     file whose two halves agree
├── test_subscriptions.py                              — what this node watches:
│     a corrupt or doctored file yields no subscriptions, a quorum is clamped to
│     something reachable, and only publishers the operator chose are counted
│     towards one
├── test_behaviour.py                                  — the detection frame: a
│     rule that fires on everyone disarms itself, transport classes judged
│     apart, being new / quiet / unfamiliar are never signals, every rule
│     states what would make it wrong, and a condition is charged **once** and
│     not once per sweep — the inequality that makes "no single rule ever bans"
│     true rather than intended; then D5, the profile break, the only signal
│     that catches a stolen key; E2, the peer whose view of the network nobody
│     shares (padding with one famous id does not clear it, a partition says
│     nothing); and A1, the burst of members under one issuer, compared to that
│     issuer's own history and never to anybody else's
├── test_features.py                                   — capability negotiation:
│     silence means the classic set, a name we do not know is not an offence,
│     nothing security-critical is negotiable
├── test_mlo.py                                        — multi-link operation and
│     the keepalive accord: which links measure alike enough to carry one node's
│     traffic together, the reordering that buys, a lossy member benched and
│     rejoining only at *half* the threshold (one number in both directions is a
│     link that flaps on a single probe); probes matched to their own answer, and
│     a probe nobody answers charged as lost rather than left pending; and the
│     three properties an adversary would go for — a peer that never heard of
│     this is untouched, a request can only ever ask this node to do **less**
│     and lapses rather than sticking, and *no declaration at all* lowers either
│     of this node's cadences (swept over every corner of the hard range, not
│     argued: it is why a cadence is negotiated as a range per mode rather than
│     as one window whose ceiling anybody could pull down). Plus what a probe
│     weighs: the addresses ride it only when the peer might not have them, and
│     a probe that carries none still proves recency — the invariant the old
│     unconditional merge protected
├── test_reputation.py / test_app_guard.py             — zero trust: the ledger,
│     the rate gate, the signed accusation, and above all what hearsay may NOT
│     do — hearsay alone sanctions nobody (it stops below the *first* threshold,
│     not the last, because being "wary" already means dropping the peer's
│     traffic), a verdict a crowd reached for us is never re-broadcast under our
│     own key, one line of descent is one voice however many identities it
│     holds, an accuser that names everybody stops being counted, two nodes
│     accusing each other cancel both ways, an accusation naming us is neither
│     acted on nor relayed, the accused is never told; plus an app's own
│     per-kind allowances, reported once per window and never fatally
├── test_cert_renewal.py / test_revocation.py          — certificate lifecycle:
│     expiry, pruning, the renewal exchange and its refusals; and taking a
│     membership back: who may say it, what it may not reach, a root that can
│     only be dropped locally, records that survive a restart
├── test_fuzz.py                                       — hostile inputs
├── test_spool.py                                      — bundle & file transport
├── test_webconsole.py / test_data_connector.py        — console & connector,
│     including that **every route answers**: a handler that raises, or a body
│     that is not JSON, becomes a 500 and not a closed socket — which is what a
│     page draws a spinner for ever on
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
│     touched, restore after a failure, the repository pinned, and the two ways
│     a node comes back after an install — a supervisor, or re-execing itself
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
│     came from, and the addresses start folded away. And the wiring a switch of
│     node depends on: each shared view drops what it holds *itself* (so a page
│     that never heard of the context is still reset), the stream and the
│     repaint restart once for every page after everybody has dropped, and a
│     managed node that throws us out — or goes quiet three times running —
│     hands the context back instead of leaving a page that answers nothing
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
├── tests/integration/test_fleet.py (control frames)    — the same frame a page
│     sends to its own console, crossing a **real mesh** to another node's real
│     plane: answered by the node it was addressed to, refused there when that
│     node keeps the operation to itself, and answered rather than dropped when
│     what arrives is not a frame at all
├── test_control_plane.py (the ledger is true)          — the table in
│     `Docs/Architecture/control-plane.md` is read back and compared against the
│     plane: every operation present, every "local only" star matching the
│     declaration, and the bounds quoted in kilobytes equal to the constants.
│     It caught two lies the moment it was written (a frame that had grown to
│     24 kB and an operation that had stopped travelling), which is the argument
│     for it: a table maintained by hand is a table that drifts
├── test_control_plane.py (the whole plane at once)     — two sweeps rather than
│     two examples: the node is asked what it exposes and then asked for **every
│     operation** with the marker a relayed call carries — each answers a frame,
│     each one not declared remote comes back refused — and a few dozen
│     generated frames must each come back with a code from the closed set and
│     nothing of this machine in them. A module added later is covered by
│     construction, which is the only way a gate stays true
├── test_control_plane.py (store & joining)             — an app is not the
│     node's own program, so installing one travels while pinning a signing key
│     does not; a catalogue paged and sorted where the list is; minting an
│     invitation stays here and joining travels; a ticket carries both halves or
│     you send both; a join that fails says which of the five ways, with the
│     detail beside the sentence rather than folded into it
├── test_control_plane.py (packages & keys)             — asking this node and
│     asking the network are two operations with two ceilings (and only the
│     cheap one travels), a lookup asks one question rather than two, installing
│     and pinning are confirmed and local, and of the key operations only the
│     overview travels — a passphrase is typed at the machine that will hold the
│     key, and reaches the node exactly as typed
├── test_control_plane.py (releases)                    — the node's own code:
│     only the read travels (what a node accepts for replacing its program is
│     pinned by a human at that node, and the rest would not fit the relay
│     anyway), a passphrase is the one field never trimmed, a key is hex before
│     the node sees it, a version GitHub has moved past is refused rather than
│     installed, and GitHub not answering comes back as the answer
├── test_control_plane.py (a node that went away)       — the relay's own
│     failures, read back as codes: a node that never answered is `unavailable`
│     (it came back as a 502, and calling that "failed" left a console pointed
│     at a machine that had gone, looking alive and showing nothing), and a far
│     node's session expiring is that node's, never this console's
├── test_webassets.py (a switch of node)               — what a page drops and
│     when: each shared view registers its own reset, the stream and the repaint
│     restart once for every page *after* everybody has dropped, a stale reply is
│     never painted as a failure, and a view on the cadence says when it could
│     not read instead of keeping what it last held
├── test_control_plane.py (trust & network)             — the two modules an
│     operator uses on a machine they are not in front of: a certificate that is
│     hex before the node is asked to parse it, a toggle that takes a boolean
│     and nothing else, a value the *node* decides the range of, a partial
│     update that leaves the six fields it did not mention alone, and a refusal
│     per operation rather than one sentence for all of them
├── test_control_plane.py                              — the management plane: an
│     operation nobody declared does not exist (even when the method is there),
│     an undeclared argument is refused, a frame that is not one is answered
│     anyway, a local-only operation is refused from a remote console and the
│     catalogue a remote console reads is the narrow one, a module that throws
│     says nothing about this machine — plus the bounds held against the relay's
│     (a frame that fits `CONSOLE_REQ_MAX`, every remote operation's ceiling
│     inside `REMOTE_BUDGET`), and that a far node's session expiring is not read
│     as ours
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
├── test_reconnect.py                                  — getting a node back the
│     moment its link dies: an established link lost under us is chased from half
│     a second, doubling to a ceiling and giving up at the end of its window; a
│     link we cut ourselves (tarpitted, or cut for noise) is never dialled back;
│     losing one of two media to a node is not losing the node; our own evidence
│     decides and the crowd's does not; a second loss extends the window without
│     re-arming the backoff; and the bounds hold — the book, the dials in flight,
│     the wait between passes — with a dial that raises not killing the loop.
│     Plus the two ways a chase must end early: a membership its issuer took
│     back, and a node the operator forgot
├── test_integration_ports.py                          — no two integration
│     tests bind the same loopback port: under xdist that is a race whose loser
│     fails in `wait_for_session` fifteen seconds later, reading as a flaky mesh
│     rather than as a reused number. Checked in the fast suite, because a guard
│     you only run beside the thing it guards is one CI tells you about
├── test_ui_contrast.py                                — colour tokens: the WCAG
│     ratio of every text/background pair in both themes, and no page redefining
│     a token of the system
└── integration/                                       — real nodes (TCP + spool)
      including test_idle_chatter.py: two joined, idle nodes stay quiet (the
      FIND_NODE/FOUND_NODE loop that used to saturate the link), and discovery
      still works when there really is something to find; test_join_ticket.py:
      a real join from the ticket alone, single use, an expired ticket, a forged
      code, the "confirmed public address" gate; test_pkg_dir.py, which publishes
      a release on one node and finds it on another by typing three letters, by
      the publisher's node id, pins the key that came inside the record and
      installs from it — plus the two refusals (a recommendation cannot be
      pinned, and finding a release does not make it installable) and a
      publisher key handed from one node to the other, the recipient then
      signing a release with it; and
      test_fleet.py, which sends a relayed console call across a real mesh (a
      90 kB reply, so several frames) and checks that it is refused without the
      `manage` grant
```
