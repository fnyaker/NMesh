# NMesh — engineering charter

A decentralised, transport-agnostic mesh network, built to carry sensitive data
through a **hostile** environment. This file sets the non-negotiable
principles. Every contribution must respect them.

## Architecture documentation — MANDATORY

`Docs/Architecture/` describes **how the code actually works** (protocol,
security, routing, transports, and above all `gotchas.md`: the hard-won traps
around hangs and flakiness).

- **BEFORE any change or debugging session**, read the relevant documents. For a
  hang or a flaky test, **start with `Docs/Architecture/gotchas.md`**.
- **AFTER any change to behaviour described there**, update the document **in
  the same commit**. Documentation that lies is worse than none.
- A new non-trivial mechanism → an entry in the right document (or a new file
  plus a link in `Docs/Architecture/README.md`).

Index: [`Docs/Architecture/README.md`](Docs/Architecture/README.md).

## Threat model (the founding assumption)

> The moment data leaves the node, it enters **hostile territory**.
> We trust neither the network, nor the peers, nor the transport, nor — as far
> as possible — the local machine.

- Anything arriving from a peer is **presumed malicious** until validated.
- An authenticated peer may behave as an adversary (a relay that alters,
  replays, amplifies or floods). **Authentication is not trust, and joining a
  network is not being trusted**: a membership says an issuer vouched for an
  identity once, and says nothing about how it behaves afterwards. Nothing is
  trusted by default; what trust exists is named, local and revocable — the
  anchors an operator pinned, the capabilities a human granted in Fleet, the
  witnesses they designated, the permissions a human granted an app (held by the
  app's own identity, never by whoever holds a shared token).
- **Hearsay is never authority.** A node's opinion of another node travels, and
  is weighed by whoever receives it — never obeyed. If a report from a stranger
  could get a node cut off, anybody able to speak could cut anybody off, and the
  reputation system would be a censorship primitive. Only what we saw ourselves,
  or what a witness the operator named saw, is ever decisive.
- We defend against the device itself: sensitive keys kept in memory where
  possible, minimal attack surface, no secret in the clear on disk without a
  reason.
- We assume a state-resourced adversary who wants to break the network. The
  question to ask on every line: "what would they do with this?".

## The principles, in priority order

### 1. Security — never negotiable
- **Post-quantum** cryptography end to end: ML-KEM-768 (key exchange), ML-DSA-65
  (signatures), AES-256-GCM (authenticated encryption).
- **Reject by default.** Any packet that is malformed, unauthorised,
  unauthenticated or of an unexpected type is dropped with no side effect. A
  valid input must prove its validity; it is not the receiver's job to prove
  invalidity.
- All application data is E2E encrypted: relays see routing metadata only, never
  the content.
- A node's identity = the hash of its DSA public key. A `NodeID` that cannot be
  derived from the key presented is a lie → reject.
- Secrets compared in constant time (`hmac.compare_digest`).

### 2. Solidity — the network never goes down
- **Zero crash. A crash is a security bug.** No network input, however hostile,
  may bring a node down or kill a receive loop. If the unthinkable happens, the
  node must **repair itself** (auto-recovery): purge the corrupted state,
  reconnect on demand, resume service.
- **Active peer rejection.** A peer that sends noise, invalid packets or abuses
  the protocol is counted and then cut off. We do not endure an adversary.
  Counted **per identity**, not per link: a peer that reconnects to shed an
  exhausted count is the whole point of counting. And cut off **silently** — its
  traffic is dropped with no error and the link is let go a little later, at a
  random moment. A node told it has been detected changes identity and starts
  again, so the thing worth taking away is the feedback, not the socket.
- **Every app judges, the node decides.** Only chat knows what too many messages
  is; only fleet knows what too many commands is. An app sets its own thresholds
  and reports the sender (`report_abuse`); what the reports add up to, and what
  happens next, belongs to the node. An app never gets to read the standing back
  — that would be a probe for finding out how much a peer can get away with.
- **Bounds everywhere.** Every queue, cache, buffer and counter has a hard
  limit. Nothing that can grow without end under an attacker's pressure (no
  memory exhaustion, no amplification).
- Works in **degraded conditions**: loss, enormous latency, partitions,
  asynchronous transports (store-and-forward of the "USB stick carried on foot"
  kind). Error correction, retry, delay tolerance.

### 3. Flexibility — transport-agnostic
- Anyone implements `BaseTransport` + `BaseServer` and registers it by URL
  scheme (`tcp://`, `ble://`, `lora://`, `usb://`…). The "Jarvis" goal: run over
  any medium capable of carrying bytes.
- **Every module of the core is medium-agnostic except two, and each exception
  is bounded and named.** The core is not one file any more; it is `node.py`
  plus the modules it is assembled from, so this rule names modules rather than
  a filename. Two of them may know a medium, for reasons that are not laziness:
  - **UDP**, for **NAT traversal**, known to `src/node.py` alone. A hole is
    punched through a stateful datagram NAT by sending from the very socket the
    listener owns; there is no medium-agnostic spelling of that, and an
    interface general enough to express it would be a UDP interface under
    another name.
    What the punch path *needs* from such a medium is small, and it is declared
    on the contract rather than reached for: `BaseServer.bound_endpoint`,
    `holds`, `adopt` and `send_raw`, plus `BaseTransport.scheme` — carried by the
    *link*, because a dialled one has no listener to ask — and `is_closed` and
    `keepalive` for the keepalive bursts that open a punched link. Any medium may
    implement them — and a medium that cannot punch inherits defaults that make
    the traversal simply not happen, which is the honest answer for a stream or
    a file. So the exception is one of *naming* a class, not of knowing its
    privates: `node.py` may say `UDPServer`, and may not read `_sock`,
    `_transports` or `_from_server`. The capability list lives in
    `src/transports/contract.py`.
  - **`RelayedTransport`**, defined by `src/mesh/peers.py` (the module that holds
    a link and the pieces describing one): a link that is not a socket at all
    but another node carrying frames between two peers that cannot reach each
    other. That is core routing wearing the transport interface, not a medium.
    `node.py` also *names* it, to ask "is this link relayed?" when counting
    physical links against virtual ones — a question a core that routes through
    relays has to be able to ask.
  A **third** would be something else entirely, so the list is checked:
  `tests/test_medium_agnostic.py` fails if any other module names a medium, if
  the core names a third one, **if a medium spreads to a module that did not
  previously own one**, or **if the punch path reads any private of a medium**.
  Saying "no concrete transport" and meaning "two, in two named places" is how a
  principle stops being one.
- Whatever a medium *answers* is checked on the way back, never trusted for its
  annotated type (`src/transports/medium.py`).
- Routing is medium-agnostic: if A↔B is Bluetooth and B↔C is Wi-Fi, A talks to
  C by routing through B, choosing the best link.
- Nodes announce themselves with URLs listing their transports; each node only
  uses the schemes it knows.

### 4. Speed — close to real time
- Goal: comfortably beat the ~4 MB/s already reached (TCP + routing).
- **And measure it.** A node card carries a *speed test* that loads the link to
  one peer and reports what it actually carries (`node.speedtest`,
  `SPEED_PROBE`/`SPEED_ECHO`). A principle with a figure in it and nothing that
  reads the figure is a wish; this is the reading. It is bounded on both sides,
  refused without a direct authenticated link, and negotiated under its own
  feature name so a node on a metered link declines it and nothing else.
- Optimise **without ever losing** security, solidity or flexibility. A
  performance gain that weakens any of the three above is refused.
- Hot paths with no superfluous allocation, no needless copy, no redundant
  crypto.

## Supply chain

- **Minimal external dependencies.** Every dependency is an attack surface (see
  the poisoned NPM/PyPI packages). By default: **the Python stdlib**.
- An external dependency is admitted only if it is indispensable, very widely
  used and audited. Today, strictly:
  - `liboqs-python` — post-quantum crypto (no stdlib equivalent).
  - `cryptography` — AES-GCM/HKDF (the Python ecosystem's reference).
  - `pytest` / `pytest-asyncio` / `pytest-xdist` / `pytest-timeout` — tests
    only, outside the runtime (`pytest-xdist` spreads the suite over every core;
    `pytest-timeout` bounds each test so a hang fails fast instead of running
    the job for hours).
- Adding a runtime dependency = an explicit justification in the PR + an update
  to this list. When in doubt: reimplement on the stdlib.

## Contribution discipline

- **Documentation follows the code, in the same commit — always, no
  exception.** This rule generalises the section above to **all** the
  documentation, not only `Docs/Architecture/`.
  - **BEFORE coding: read the documents concerned.** `Docs/Architecture/` first
    (internal mechanics), then the usage guides affected
    (`Docs/DataConnector/`, `Docs/Apps/`, `Docs/WebConsole/`,
    `Docs/AppSharing/`…), and `TEST.md` / `README.md` if the change touches
    them. Never code a documented mechanism blind.
  - **AFTER coding: update EVERY document the change touches, in the same
    commit** — the protocol, an app's guide, the console's API table, CI, the
    map of the code, the message table… A feature shipped without its
    documentation is **incomplete**, never "to be documented later".
    Documentation that is wrong or missing is a bug exactly like a red test.
- **Every change is proved by tests**, including hostile-input tests (fuzzing,
  random/malformed packets). "It works" is not enough: it has to "hold up".
- We never merge with the suite red.
- Readable code beats clever code. Write like the neighbour: same idioms, same
  comment density.
- A comment explains only a **constraint** the code cannot show, never the
  "what" nor where it came from.

### Report every bug — always

- **A bug found is a bug reported**, every time: one outside the task, one you
  worked around, one you are not going to fix, one that "probably" does not
  matter. A workaround that hides a defect without naming it is how the defect
  survives — the speed test once had its probe window lowered to dodge a
  collapse of the UDP transport, and that collapse would have stayed in the
  code had it not been said out loud.
- **Tell the person you work for, in the same turn**, in plain words: what
  fails, how to reproduce it, how bad it is, and whether you fixed it.
- **Write it down where the next reader looks**: a fixed trap goes in
  `Docs/Architecture/gotchas.md`; one still open goes in `BUGSVULNS.MD` (or an
  issue), with the reproduction.
- Never "flaky", never "unrelated", never silent without a root cause: those
  are the words a bug hides behind.

### Name the thing, then count the thing

Most of the bugs that reach a user are not hard: they are a name that lies. A
`_Peer` in this codebase is a **link**, and a node may hold several at once — so
`authenticated_peers` counted links while the console printed "Connected to N
**nodes**". One number, four labels, right for two of them, and it survived a
whole pass that grouped those very links by node.

- **The name carries the unit.** `link_count` and `node_count`, never `peers`.
  If a reader has to open the definition to know what a number counts, rename it
  rather than comment it.
- **Derive, do not re-derive.** There was already a helper returning one link per
  identity; the snapshot re-implemented the count inline and got a different
  meaning. Two expressions for one quantity is two chances to be wrong.
- **Read the label out loud against the value.** Before shipping a number to a
  screen, say the sentence it will render: "Connected to 3 nodes" — is it three
  *nodes*? A label and its value are one claim, and the claim has to be true.
- **Ask who else uses this.** Every change: what reads this field, this
  function, this row — and what will? A count consumed under two labels is a
  count that will be wrong under one of them.
- Change the *cause*, not the symptom: a wrong number on a page is fixed in the
  thing that computes it, once, not corrected at each place it is displayed.

### No emoji in an interface

Emoji make a product look cheap, render differently on every platform, and carry
no meaning to a screen reader. They are also the lazy way out of drawing
something.

- **Graphical interfaces use SVG icons** — `icon()` in
  [`src/webassets/ui.py`](src/webassets/ui.py), one set, shared by every page,
  inheriting `currentColor` and sized in `em`. A page never inlines its own
  glyph.
- **Terminal output uses words**, aligned: `ok`, `warning:`, `failed`. A dingbat
  is not guaranteed to render in a minimal console, and a word always is.
- **Documentation uses structure** — a heading, a table, an admonition line in
  prose. Not a green tick.
- The one exception is content that *is* an emoji: the chat reaction palette,
  and what a person types. Those are the user's, not the interface's.
- **Every finished piece of work bumps the version**, in the same commit. One
  step on the patch number per task (or per block of tasks landing together):
  `0.1.3` → `0.1.4`. The patch number is **not capped at 9** — it counts up
  freely, `0.1.99` → `0.1.100`, and keeps going. A **minor** bump (`0.2.0`) is a
  deliberate act, marking a body of work worth naming, never something a patch
  count rolls over into.
  Two files carry it and a test holds them together:
  [`src/version.py`](src/version.py) and `pyproject.toml`.

## Network invariants (quick reminders)

- The header is in the clear but **authenticated** (as the GCM AAD); the payload
  is encrypted.
- `msg_id` binds the packet's content (anti-replay, anti-amplification); it is
  verified on receipt, not only when sending. Its hash is negotiated per link
  and rewritten per hop; a receiver accepts either, and dedup keys on the
  node's own id of the content, never on the header.
- TTL is decremented at every hop, excluded from authentication and from
  `msg_id`.
- Bounded deduplication of routed messages (anti-loop, anti-flood).

## Language

The project — code, comments, documentation, commit messages — is written in
**English**.

## Working notes

### Mistakes agents have made — read before you start

Every mistake an agent makes here is written down in this list, in the same
commit as the work, with the rule that would have prevented it. Not the bugs
found in the code — those go to `gotchas.md` and `BUGSVULNS.MD` — but the
agent's own slips: a wrong claim, a misplaced edit, a fix applied to half its
scope. Add yours.

- **A conclusion drawn from a metric that cannot carry it.** An agent reported
  "spurious retransmit timeouts" on a UDP link because its probes showed 0 %
  loss. Probes ride the reliable layer: a lost probe is resent and arrives late,
  so they show 0 % whatever the wire loses. The timeouts were real loss,
  recovered as designed; the claim was retracted. → Before reading a figure as
  evidence, say what produces it and what it cannot see.
- **A fix applied to one of two places that compute the same thing.** Link-local
  addresses were filtered out of `expand_listen_uri` and left in
  `ip_reachability` — both publish this node's addresses. Only inspecting the
  live node after the deploy showed it (BUGSVULNS 57). → Before fixing a rule,
  grep every producer of the quantity, not only the one the bug was seen in,
  and put the rule in one helper both call.
- **A test class inserted in the middle of another.** Text inserted after an
  existing method's last line landed inside its class, so the methods below it
  silently became the new class's. The suite stayed green, which is why it went
  unnoticed until `-k NewClass` collected 7 tests instead of 4. → Insert at a
  class boundary, and check `-k` collects exactly the tests you wrote.
- **An assertion outside the patch it depends on.** `facts.update_granted` is
  computed when read, and the assertion sat after the `with mock.patch(...)`
  block, so it read the real host again. → Everything that reads a patched
  premise goes inside the `with`.
- **A stale `.pyc` taken for a failing test** after `git stash pop` — see
  *Verifying a fix actually guards something*. Clear `__pycache__` after every
  stash round trip.
- **A history comment in the code** ("this side once set bit i for…"), which
  the charter forbids; caught on self-review. History belongs in `gotchas.md`;
  a comment states the constraint.
- **A sweep proposed before its exemptions were known.** The first idea for the
  double-accepted UDP link was to reap every unauthenticated link on a timer;
  `relay_only` links and a relay's joiner link are unauthenticated on purpose
  for as long as a relayed join lives, and it would have cut them. Caught before
  coding. → Before broadening a sweep, list every holder of the state it reaps.
- **The same history comment, twice.** After the rule above was written, the
  next change wrote "this used to let through…" into `apps._reachable`. Caught
  on reread again. → Before committing, reread every comment you added, and
  delete any sentence about what the code *was*.
- **A test that could not fail.** An "ambiguous name" test named a prefix only
  one node had, so it would have passed against code that never detects
  ambiguity. Caught by reading the test before running it. → For each new test,
  say which line of the code under test it would catch removed.
- **`str()` on a value that may be absent.** `nmeshctl` joined an unset
  `--caps` option into the list as the capability `"None"`, and a bare
  `--flag` swallowed the next `name=value` as its answer. Both caught by the
  tests written beside them. → Optional inputs are checked for presence, never
  stringified; a value is consumed only when it is one of the values expected.
- **A new secret beside a credential, and a writer of that credential that
  never heard of it.** Sessions that outlive restarts were ended by a password
  change through the console, and not by `install.sh --reset-password`, which
  writes the credential directly — the one path used when a way in is thought
  stolen. Caught while wiring the installer. → When state hangs off a
  credential, find every writer of the credential, not only the one you call.
- **Test doubles updated where the default run looks, and nowhere else.** A
  signature change (`LocalConsole.call` gained `apps`, `full`, `node`) was
  carried into every stub under `tests/` — and not into the two in
  `tests/integration/test_fleet.py`, which `pytest -q` ignores. Six integration
  tests failed with a 502 that read like a relay bug. → After changing a
  signature, `grep -rn` the method name over `tests/` *including*
  `tests/integration`, and run both suites before calling it green.
- **A fix chosen before its cost was measured.** The test report proposed a
  higher `_RTO_MIN` for the UDP collapse; a model of the path showed it cost
  20–45 % of the throughput on a lossy link for 2–3 % on a jittery one, and the
  next candidate (an "ACK too early to answer the resend" check) could not fire
  in the very case seen live. Both caught before commit. → Before proposing a
  fix, run it against the failure *and* against the conditions it must not
  hurt, and check it triggers on the numbers actually observed.
- **A test asserting a value that correct code changes.** The F-RTO tests
  first asserted the timer unchanged after a SACK — but a SACKed original is a
  valid measurement and rightly brings the timer down. → Assert the property
  the test is named for (no new timeout, no extra backoff), not every field
  that happens to hold still on the path you imagined.
- **An empty log answer read as "nothing happened".** After a restart the log
  ring is off (no hold survives one — `logging.md`), so a query returns nothing
  whatever happened. → `logs.status` first; an answer from a ring that is not
  running is no evidence of absence.

### Running the tests (read this before trusting "green")

`pyproject.toml` sets:

```
addopts = "-n auto --dist loadgroup --timeout=120 --timeout-method=thread --ignore=tests/integration"
```

so a bare `pytest -q` **silently skips `tests/integration`**. CI runs *two*
steps: `pytest -q`, then `pytest tests/integration -q`. A local "full suite" that
does not also run integration has not tested the transport layer at all. Run both:

```
pytest -q
pytest tests/integration -q
```

CI uses Python 3.13 (base image); a local venv is often 3.12. Not every failure
reproduces across versions — check both when a difference matters.

### The integration suite is genuinely flaky under parallelism

`tests/integration` binds **fixed ports** and measures **wall-clock deadlines**
(20–25 s `wait_for_session`). Under `-n auto` on a loaded machine it fails
intermittently — and it fails on **`origin/main` too**, on *different tests* each
run (`test_fleet`, `test_relay_invite`, `test_idle_chatter`, `test_spool_transport`).

Consequences for debugging:

- A single red CI run on `tests/integration` is **not** evidence that your change
  broke it. A *different* test failing per run is the signature of load, not of
  your diff.
- `1/N` vs `0/N` local reruns are not evidence either way — the confidence
  intervals overlap almost completely. Do not use rerun counts to argue.
- To get a trustworthy signal, run **serially** (`-n0`), where both revisions pass
  consistently (~2 min), or compare *failure identities* across commits.

Only 3 files carry `@pytest.mark.xdist_group` (needed for LAN-broadcast tests to
share a worker). The fixed-port tests are **not** grouped, which is the root of
the flakiness. A real fix would group them by port or serialise integration in CI.

### Verifying a fix actually guards something

Mutation-test by reverting **only** the source, keeping the new tests:

```
git stash push -q src/     # NOT a bare `git stash` — that takes the tests too
pytest <new tests> -q      # must FAIL here
git stash pop -q
pytest <new tests> -q      # must PASS here
```

Clear `__pycache__` after the pop (`find src tests -name __pycache__ -prune
-exec rm -rf {} +`) when a stashed edit kept the file's size — a version bump
is the usual one. `git stash pop` rewrites the file within the same second, and
a `.pyc` is trusted on mtime-in-seconds plus size: the suite then ran the
*stashed* `src/version.py` and failed `test_matches_pyproject` on a tree whose
two version files agreed.

Beware the **vacuous guard**: a test that passes on the buggy revision tests
nothing. Example encountered: a `_peer_scheme` guard using a manager that already
registered `udp` — `scheme_of` answered first and the fallback under test never
ran. Point such tests at a manager with nothing registered.

### Transport registration: one declaration point, and it is load-bearing

`src/transports/registry.py:register_all()` is what `scripts/nmesh_node.py`,
`chat_demo.py` and `call_demo.py` all call. It is the *only* place the built-ins
are declared. On `main` there was no such file — each script imported the
transports directly — so this is new surface, and it is not covered by any test
unless you add one.

It imports each module **lazily** and, on `ImportError`/`AttributeError`, calls
`faults.note(...)` and `continue`s. That is deliberate (a missing optional
dependency, e.g. `liboqs`, must not stop the node running `spool`), but it makes
a wrong module path look exactly like an unavailable medium: **the node starts
fine with no transports at all and nothing on screen saying why.**

Real bug this hid: `import_module(f"{__name__}.{module}")`. Inside that module
`__name__` is `src.transports.registry`, so it asked for
`src.transports.registry.tcp` — not a package. Every built-in was skipped and
`tcp://` vanished from an updated node. Use `__package__` (the containing
package) to reach a **sibling** module; `__name__` is one level too deep.

Note the failure mode is silent *and* survives CI, because `register_all` had no
test. When you add a scheme, assert it arrives:

```
register_all(TransportManager())._registry   # must contain what BUILT_IN lists
```

### The updater swaps whole directories

`src/updater.py` copies `REPLACE_ENTRIES` (`src`, `scripts`, `Docs`, `start.sh`,
…) over the install root; anything not listed is left alone. A new top-level
directory in the repo that `REPLACE_ENTRIES` doesn't name **will not ship** to
nodes updating from GitHub. `src/` and `scripts/` are listed, so the transport
package does travel — but a new top-level dir needs its entry added.

To exercise the real thing end-to-end against a branch (changes nothing local):

```
updater.apply_sync(<version>, root=<tempdir>, branch="<branch>")
```

Confirm the resulting tree actually registers its transports — that is the step
that would have caught the `tcp://` regression.

### Transport medium identity

A link's medium is asked of the **link** (`BaseTransport.scheme()` / `SCHEME`),
not of a listener. A dialled link (`UDPTransport.connect`) has `_server = None`,
so "which links does my server own?" answers *no* for exactly the initiator half
of every hole punch. `scheme()` is used by real logic, not just the console:
`_redundant_links` (which **closes** links), `_mlo_medium_ready`, and traffic
allocation.

### Reading CI logs

`GET /repos/{o}/{r}/actions/jobs/{job_id}/logs` **302-redirects** to blob storage.
`urllib` follows it, but bulk/unauthorised access returns `403`. Fetching logs for
many jobs in one pass fails silently if you don't check — an early scan reported
"no failures ever" purely because every fetch 403'd.

### Clock-origin bugs: the suite must run as a freshly booted machine

`time.monotonic()` is measured from the **machine's boot**, so the same code
sees `now ~= 10` in a fresh CI container and `now ~= 500000` on a developer box.
Any absolute-uptime comparison breaks only in the first case:

- a cooldown seeded `0.0` and compared as `now - field < LIMIT` reads an
  *unstarted* cooldown as a *freshly started* one. `_last_loss_burst` hit this:
  CI (fresh container) failed `test_reconnect.py`'s first-burst tests on a
  commit that only bumped a version string, while local (long uptime) passed
  every time.
- The fix is a sentinel that cannot be confused with a timestamp: seed `None`
  and skip the comparison while it is unset.

**The suite could not catch this** because nothing ran the node under a fresh
clock. `tests/conftest.py` now has a `fresh_boot` fixture that shifts the clock
*origin* for `src.node` **and** the calling test module together. Shift both or
neither: moving only `src.node` leaves the test writing its own
`time.monotonic()` deadlines days into the node's future, and the resulting
failures look like real bugs. The clock still advances, so deadline waits work.

To reproduce a "passes locally, fails in CI" timing report, run the failing test
with `fresh_boot` before touching anything else. Both tests CI named
(`test_enough_of_them_re_verifies_our_own_addresses`,
`test_a_peer_flapping_cannot_buy_a_probe_per_flap`) fail on old code under that
fixture and pass on fixed code.

Audit scope when hunting this class: the dangerous direction is
`now - field < LIMIT` (a cooldown), not `now - field >= LIMIT` (elapsed). The
`0.0` defaults throughout `src/mesh/peers.py` are mostly the safe direction.

### A test must not assert on how the suite was invoked

The same shape as the clock-origin bug above, with the runner in place of the
clock: a module-level capture of the *process* is a capture of whatever started
it, and under a test runner that is the runner.

`updater._LAUNCH = (sys.executable, list(sys.argv), os.getcwd())` is read at
import, and `restart_plan()` decides "is there a way back?" from it — chiefly
whether `argv[0]` still exists on disk. That answer depends on the invocation:

- `python -m pytest ...` leaves `argv[0]` as pytest's own `__main__.py`, which
  **does** exist → `restart_plan()` says `reexec`;
- a `pytest-xdist` worker is started through execnet's bootstrap, which does
  not → `restart_plan()` says there is no way back.

`test_a_mesh_install_says_whether_it_is_restarting` asserted
`body["restarting"] is False` without pinning either. It passed for one reason
only: `pyproject.toml` puts `-n auto` in `addopts`, so the suite always ran in a
worker. Run that file with `-n 0` — one test, one file, an IDE runner, anything
that bypasses xdist — and it failed, on a product that was behaving correctly.
The test two above it pins `updater._LAUNCH` for exactly this reason and says so
in a comment; this one did not, and nothing made the omission visible.

→ Pin the premise (`restart_plan`, or `_LAUNCH`) rather than inherit the
runner's. And when a test is named "says **whether** X", parametrise both
answers: asserting one of them lets a constant pass, which is what let this sit
behind a green suite.

Audit scope for this class: anything captured at **import** from `sys.argv`,
`sys.executable`, `os.getcwd()`, `os.environ` or `__main__`, then asserted on.
`-n 0` is the cheap way to find it — if a test's verdict changes between `-n 0`
and `-n auto`, it is reading the runner, not the code.

The **host** is a premise of the same kind, and CI's container hides it as well
as the runner did. Two tests failed only on a developer machine that runs a
node: `test_without_the_grant_it_falls_back_to_the_package_manager` found the
real `/usr/local/lib/nmesh/nmesh-update` (its neighbour pinned `os.path.exists`,
it did not), and `test_termux_with_services_has_a_service_manager` put the
host's `/usr/bin` on `PATH`, so a booted systemd answered before the phone was
asked about. Pin the file test; isolate the `PATH` (`run_snippet(isolate=True)`).

### `register_all`: one bad entry must cost only itself

`BUILT_IN` is ordered `tcp, udp, spool`. A failure that propagates out of the
per-entry guard costs an **arbitrary suffix** of that list, so the symptom
appears on a later, innocent scheme while the recorded fault names the cause.
Two ways this happened, both now fixed:

- the guard named `ImportError` only; a native dependency failing to initialise
  raises `RuntimeError`/`OSError`, and a half-written file raises `SyntaxError`.
- `manager.register` sat **outside** the guard, so its `TransportError`
  (duplicate or malformed scheme) aborted the loop.

Now there is one `try` around import + resolve + register, catching `Exception`
(not `BaseException` — a shutdown must still propagate). There is no scheme
cap; a 50-entry list was verified end-to-end.

### Version bumps and the branch updater

`updater._source_version(branch)` reads `src/version.py` on the branch and
offers it only when `is_newer(latest, __version__)`. If the branch and the
running tree declare the same version the updater correctly reports
`offered: false` and **silently delivers nothing** — which is how this branch's
fixes failed to reach a node following it. Bump `src/version.py` **and**
`pyproject.toml` together (`tests/test_updater.py` asserts they agree) before
expecting a branch to be offered.