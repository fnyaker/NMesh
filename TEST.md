# Testing guide — NMesh

The suite is the specification's proof. This file says how to run it, what it
covers, and the traps that make a green run lie. The charter itself is in
[`AGENTS.md`](AGENTS.md); the hard-won failure modes are in
[`Docs/Architecture/gotchas.md`](Docs/Architecture/gotchas.md).

## Quick start

```bash
NMESH_SETUP_ONLY=1 ./start.sh   # installs everything, starts no node
. .venv/bin/activate

pytest -q                       # unit tests: fast, no real network
pytest tests/integration -q     # real nodes, real crypto, real sockets
```

A bare `pytest` **silently skips** `tests/integration` (`pyproject.toml`; see
below). CI runs both, in two steps. A local “full suite” that does not also run
integration has not tested the transport layer at all.

CI runs Python 3.14 in the base image; a local venv is often 3.12. Not every
failure reproduces across versions — check both when a difference matters.

## What the suites cover

| Area | Unit | Integration |
|---|---|---|
| Primitives — packet, crypto, certificates, codecs | yes | — |
| Node, routing table, DHT, E2E sessions, handshake | yes | yes |
| Transports — TCP, UDP, veil, spool, hole punching, MLO | yes | yes |
| Invitations, join tickets, relayed invitation, pseudos | yes | yes |
| Hostile input — random bytes, guided fuzzing, hostile plugins | yes | — |
| Console, control plane, HTTP server, web assets, `nmeshctl` | yes | fleet calls |
| Connector, app API, permissions, storage, MCP | yes | yes |
| Chat, contacts, calls, file transfer | yes | yes |
| Fleet — grants, SSH, Docker, stacks, files, terminal | yes | yes |
| Updates, releases, package directory, boot guard | yes | yes |
| Installer, launcher, Docker tree, liboqs lock | yes (sourced) | — |
| i18n, UI contrast, no emoji, no external asset | yes | — |

Tests live in `tests/`; real-node scenarios in `tests/integration/`; the
guided fuzzer in `tests/fuzz/`; measuring and attack tools in `tests/tools/`.
Test names and docstrings say what each one protects — read the file before
changing it.

## `pyproject.toml` decides what a bare run means

```toml
addopts = "-n auto --dist loadgroup --timeout=120 --timeout-method=thread --ignore=tests/integration"
```

- `-n auto` spreads the suite over every core; `--dist loadgroup` honours
  `@pytest.mark.xdist_group` so LAN-broadcast tests share a worker.
- `--timeout=120 --timeout-method=thread` turns a hang into a fast failure with
  a traceback, instead of a job that runs for hours.
- `--ignore=tests/integration` is why the second command above exists.

Run one file with `-n0` when a result is surprising:
`pytest tests/test_x.py -q -n0`.

## The integration suite is genuinely load-sensitive

`tests/integration` binds **fixed ports** and measures **wall-clock deadlines**
(20–25 s `wait_for_session`). Under `-n auto` on a loaded machine it fails
intermittently, on `origin/main` too, on *different* tests each run.

- A single red CI run on integration is **not** evidence that your change broke
  it. A different test failing per run is the signature of load.
- `1/N` vs `0/N` rerun counts are not evidence either way; the confidence
  intervals overlap. Do not argue from them.
- To get a trustworthy signal, run serially (`-n0`), where both revisions pass
  consistently, or compare *failure identities* across commits.
- Before blaming load, run the suite under `-n auto` four to six times and look
  at *which* test fails: one name failing most runs is a test bug; names
  changing run to run is load.
- Every port a test uses must be reserved:
  `free_port(n + 1)` when the test listens on `base + n`.
  `tests/test_integration_ports.py` refuses a shared `127.0.0.1:NNNN`.

`test_spool_transport`'s one CI failure is still unexplained
([`BUGSVULNS.MD`](BUGSVULNS.MD), finding 81).

## `[gwN] node down: Not properly terminated`

This is **not** a test failure and not flaky infrastructure. A pytest-xdist
worker *process* died without finishing its side of the protocol. In this
repository there is one way that happens: a test hung, and the thread timeout
answered with `os._exit(1)`; the stack dump is usually lost with the process.

Re-run with the timeout raising an exception instead of killing the worker:

```bash
pytest -q --timeout=60 --timeout-method=signal
```

That reports the hang as an ordinary failure, with the traceback pointing at
whatever the loop was parked on.

## Clock-origin bugs: run as a freshly booted machine

`time.monotonic()` is measured from the machine's boot, so the same code sees
`now ~= 10` in a fresh CI container and `now ~= 500000` on a developer box.
Any absolute-uptime comparison breaks only in the first case.

- The dangerous direction is `now - field < LIMIT` (a cooldown), not
  `now - field >= LIMIT` (elapsed).
- The fix is a sentinel that cannot be a timestamp: seed `None` and skip the
  comparison while unset.
- `tests/conftest.py` has a `fresh_boot` fixture that shifts the clock **origin**
  for `src.node` and the calling test module together. Shift both or neither;
  moving only one leaves the test writing deadlines days into the node's future.
- When CI reports “passes locally, fails here” for a timing test, run it under
  `fresh_boot` first.

Audit scope: anything captured at import from `sys.argv`, `sys.executable`,
`os.getcwd()`, `os.environ` or `__main__`, then asserted on. A test must not
assert how the suite was invoked — pin the premise (`restart_plan`, `_LAUNCH`)
instead. `-n0` is the cheap way to find both classes: if a verdict changes
between `-n0` and `-n auto`, the test is reading the runner, not the code.

The **host** is a premise of the same kind. Pin `os.path.exists`, isolate
`PATH`, and do not let a developer machine's installed NMesh answer for the
code under test.

## Proving a fix actually guards something

Mutation-test by reverting **only** the source, keeping the new tests:

```bash
git stash push -q src/     # NOT a bare `git stash` — that takes the tests too
pytest <new tests> -q      # must FAIL here
git stash pop -q
pytest <new tests> -q      # must PASS here
```

Clear `__pycache__` after the pop when a stashed edit kept the file's size — a
version bump is the usual one. `git stash pop` rewrites the file within the same
second, and a `.pyc` is trusted on mtime-in-seconds plus size: the suite then
ran the *stashed* `src/version.py` and failed `test_matches_pyproject` on a tree
whose two version files agreed.

```bash
find src tests -name __pycache__ -prune -exec rm -rf {} +
```

Beware the **vacuous guard**: a test that passes on the buggy revision tests
nothing. Point such a test at a manager with nothing registered, at a fake that
decides by a field rather than by `type`, or at a topology that removes the
shortcut.

## Fuzzing

`tests/test_fuzz.py` throws random bytes, which stop at the first length check.
`tests/fuzz` keeps what made a parser take a new branch and mutates from there,
on the standard library alone: coverage comes from `sys.monitoring`, counting
first sightings of lines and branches under `src/`.

```
python -m tests.fuzz --list
python -m tests.fuzz                       # every target, 60 s each
python -m tests.fuzz packet core_release -s 600
```

Every parser a peer's bytes reach is a target in `tests/fuzz/targets.py`, with
the contract its code states (“raises `TicketError`, never anything else”,
“`None` for anything that does not check out”). Anything else it raises is a
finding, as is a parse slower than half a second. Seeds are built by the tree's
own encoders; a seed that fails to build fails the suite rather than leaving a
target fuzzed from nothing. The short run (`tests/test_fuzz_guided.py`) catches
a contract a change breaks outright; `fuzz.yml` runs every target weekly.

A new parser of peer input gets a target in the same commit.

## Measuring, not guessing

`tests/tools/mesh_sim.py` runs nodes over several processes (real TCP on
loopback) so the event loop is not the measurement:

```bash
python tests/tools/mesh_sim.py --procs 8 --nodes 120 --pairs 100 --wait 12
python tests/tools/mesh_sim.py --procs 8 --nodes 120 --kill 0.3      # then heal
```

It prints deliveries, retries, packets sent and relayed, and the **lateness of
the slowest worker's event loop**. Past a loop lag p99 of a few hundred
milliseconds the figures describe the machine, not the mesh. `--fast` replaces
`oqs` with `tests/tools/fake_oqs.py` (same sizes, hashes instead of lattices).
`--explain` says what both ends of an undelivered first contact looked like.

`tests/tools/api_fuzz.py` signs in to a throwaway node and sends every route
the page's scripts call: no session, truncated, binary, deeply nested and
oversized bodies, wrong types. A relay's `502 {"error": …}` is a refusal and is
counted as one.

## CI, in one screen

`.github/actions/suite` is the whole test job; `ci.yml` runs it on every push
and PR, `release.yml` runs it before publishing. It runs inside the base image
(`docker/Dockerfile.base`) with a compiled liboqs and Python 3.14, so the C
library is not rebuilt per run and the runtime matches what ships.

Alongside it: CodeQL (Python, JavaScript and the workflows, plus
`.github/codeql/nmesh` with mesh input as its source), secret scanning with push
protection, Dependabot, zizmor, gitleaks, hadolint, Trivy, pip-audit, liboqs
advisories, OWASP ZAP against a throwaway console, and OpenSSF Scorecard. The
canonical inventory is [`SECURITY.md`](SECURITY.md); CI mechanics that a change
can break are held by `tests/test_workflows_pinned.py` and
`tests/test_ci_scripts.py`.

A release job publishes only a commit the suite passed on. Every action is
pinned to a full commit SHA and every workflow starts from `permissions: {}`.
A new action goes in by SHA with its version as a comment (`@<sha> # v4.4.0`);
Dependabot moves the pin.

## Reading CI logs

`GET /repos/{o}/{r}/actions/jobs/{job_id}/logs` **302-redirects** to blob
storage. `urllib` follows it, but bulk or unauthorised access returns `403`.
Fetching logs for many jobs in one pass fails silently if you do not check — an
early scan reported “no failures ever” purely because every fetch 403'd.

## Version bumps and branch updates

Every finished piece of work bumps [`src/version.py`](src/version.py) **and**
`pyproject.toml` together; `tests/test_updater.py` asserts they agree.

`updater._source_version(branch)` reads `src/version.py` on the branch and
offers it only when `is_newer(latest, __version__)`. If the branch and the
running tree declare the same version, the updater correctly reports
`offered: false` and **silently delivers nothing** — which is how a branch's
fixes fail to reach a node following it. Bump both files before expecting a
branch to be offered.

## Test-writing rules

- Write from the charter or the bug, not from the code; otherwise the test only
  proves the code agrees with itself.
- For each new test, say which line would have to be removed for it to fail.
  If there is no such line, it is not a test.
- Assert the property the test is named for, not every field that happens to
  hold still on the path you imagined.
- Read the test before rewriting it. A replacement written from memory matches
  nothing and leaves the suite red for a reason that looks like the code's.
- After changing a signature, `grep -rn` the method name over `tests/`
  **including** `tests/integration`; the default run does not look there.
- Never use a real address, node name, hostname, account or path in a fixture or
  a bug report: use 192.0.2.0/24, 198.51.100.0/24 or 203.0.113.0/24.
  `tests/test_no_live_addresses.py` refuses a real IPv4 literal.
- A test that corrupts something must corrupt it whatever was there; pin the
  premise rather than inheriting the runner's.
- Before broadening a sweep, list every holder of the state it reaps.

More process errors, with the rule each one produced:
[`Docs/Contributing/agent-mistakes.md`](Docs/Contributing/agent-mistakes.md).
