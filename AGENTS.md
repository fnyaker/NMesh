# NMesh — working notes

## Running the tests (read this before trusting "green")

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

## The integration suite is genuinely flaky under parallelism

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

## Verifying a fix actually guards something

Mutation-test by reverting **only** the source, keeping the new tests:

```
git stash push -q src/     # NOT a bare `git stash` — that takes the tests too
pytest <new tests> -q      # must FAIL here
git stash pop -q
pytest <new tests> -q      # must PASS here
```

Beware the **vacuous guard**: a test that passes on the buggy revision tests
nothing. Example encountered: a `_peer_scheme` guard using a manager that already
registered `udp` — `scheme_of` answered first and the fallback under test never
ran. Point such tests at a manager with nothing registered.

## Transport registration: one declaration point, and it is load-bearing

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

## The updater swaps whole directories

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

## Transport medium identity

A link's medium is asked of the **link** (`BaseTransport.scheme()` / `SCHEME`),
not of a listener. A dialled link (`UDPTransport.connect`) has `_server = None`,
so "which links does my server own?" answers *no* for exactly the initiator half
of every hole punch. `scheme()` is used by real logic, not just the console:
`_redundant_links` (which **closes** links), `_mlo_medium_ready`, and traffic
allocation.

## Reading CI logs

`GET /repos/{o}/{r}/actions/jobs/{job_id}/logs` **302-redirects** to blob storage.
`urllib` follows it, but bulk/unauthorised access returns `403`. Fetching logs for
many jobs in one pass fails silently if you don't check — an early scan reported
"no failures ever" purely because every fetch 403'd.

## Clock-origin bugs: the suite must run as a freshly booted machine

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

## `register_all`: one bad entry must cost only itself

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

## Version bumps and the branch updater

`updater._source_version(branch)` reads `src/version.py` on the branch and
offers it only when `is_newer(latest, __version__)`. If the branch and the
running tree declare the same version the updater correctly reports
`offered: false` and **silently delivers nothing** — which is how this branch's
fixes failed to reach a node following it. Bump `src/version.py` **and**
`pyproject.toml` together (`tests/test_updater.py` asserts they agree) before
expecting a branch to be offered.