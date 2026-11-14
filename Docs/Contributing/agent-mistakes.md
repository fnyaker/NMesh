# Agent mistakes — the ledger

Every mistake an agent has made on NMesh is written down here, in the same
commit as the work, with the rule that would have prevented it. This is not the
list of bugs found in the code — those go to
[`Docs/Architecture/gotchas.md`](../Architecture/gotchas.md) and
[`BUGSVULNS.MD`](../../BUGSVULNS.MD). These are the agent's own slips: a wrong
claim, a misplaced edit, a fix applied to half its scope. Add yours.

Read this before you start. It is cheaper than repeating one of them.

## The ledger

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
- **History comments, a third time.** Ten docstrings and comments in one
  branch told the incident ("seen live", "a laptop woken after two hours",
  "used to") instead of the constraint, after two entries above saying not to.
  Caught on the pre-commit reread. → Write the incident in `gotchas.md` and
  `BUGSVULNS.MD` *first*; then the code comment has somewhere to point and only
  the rule left to say.
- **The same unreadable metric, read again.** A speed test's 21 % "lost"
  probes over UDP were reported to the user as the UDP link stalling under
  wifi. They were the far end's echo ceiling (`_SPEED_MAX_PER_WINDOW`), reached
  by the two tests run just before, and dropped silently by design. → Before
  calling a loss a link's, count what this session already asked of the far end
  against every ceiling it keeps.
- **`pkill -f` with a pattern the shell running it also matched.** It killed
  its own command, so an edit queued after it in the same command never ran,
  and the next test run tested the old file. → Kill by PID, or never put work
  after a `pkill` in one command. **And the PID must not come from `pgrep -f`
  either**: the same agent later ran `for p in $(pgrep -f devmesh.py); do kill
  $p; done`, the loop's own shell matched, and it killed itself the same way.
  Take the PID the background task reported, or match with `ps … | grep
  "[d]evmesh"`, whose pattern does not match its own text.
- **`pkill -f` a third time, over `ssh`/`pct exec`.** `pct exec 112 -- bash -c
  'pkill -f nmesh_node.py; …deploy…'` matched the `bash -c` carrying that very
  text, so the deploy after it never ran and the screenshot taken next showed
  the old page. → Kill by PID read from `pgrep`/`ps` in a separate step, and
  confirm the new file is on the target (grep for the new string) before
  looking at what it renders.
- **A scale figure that measured the simulator.** Routing results at 100 and
  200 nodes were taken with every node in one process: its event loop was
  hundreds of milliseconds late, retries came every 8 s instead of 5, and the
  "failures" were CPU. They went into `BUGSVULNS.MD` before anyone read the
  loop's lateness, and had to be withdrawn. → A simulation reports its own
  clock error next to its result (the lateness of a 50 ms timer is enough),
  and a number taken while that error is large is not a number about the
  system. Prefer a metric that does not read the wall clock — "did the sender
  have to retry" — over a latency taken on a saturated loop.
- **A clock patched through a module that shares it.** `monkeypatch.setattr(
  node_mod.time, "monotonic", …)` replaces `time.monotonic` for the whole
  process, the event loop's clock included: every `sleep` and `wait_for` froze
  and the test hung to its timeout. → Move the state's timestamp instead (age
  the entry), or patch a name the loop does not read.
- **A quota outcome predicted from what was reserved, not what was spent.**
  Live, the third speed test in a minute was announced as "must be refused"; it
  ran, correctly — the budget gives back what a test did not send, and the two
  before had sent 408 probes, not 1 030. → Before predicting a limit's verdict,
  add up what the code counts, not what it could have counted.
- **The F-RTO slip, once more.** A new test asserted the congestion window
  *equal* to its value before a spurious timeout; the cut was undone and the
  ACK then grew the window, as it must. Caught by the run, fixed to `>=`. →
  The rule above it already said so: assert the property the test is named for.
- **A side effect cut without asking who lived on it.** To stop lookups
  dialling nodes long gone, an agent made only conversations buy a direct
  dial — and the dial a lookup bought was how two nodes sharing only a relay
  became neighbours; `test_idle_chatter` failed every time. The fix kept the
  dial and refused it only towards the gone. → Before removing what a path
  does on the side, find what depends on it happening: grep its effect, and
  run the integration suite before calling it done.
- **An existing file overwritten unread.** To guard integration ports, an agent
  wrote `tests/test_integration_ports.py` with `cat >` — and the file already
  existed, holding the same rule in a stricter form (attributed per test, with
  a check that it finds anything at all). Caught only because the unit count
  went *down* by one after adding a test. → Before writing a file, check it
  does not exist (`git ls-files`, or `Read`); a shell redirect never asks.
- **A cause named from one network.** A 40 ms TCP-over-UDP probe gap was put
  on the relays' answering ("the time is spent on the relays") from
  measurements taken on one path, through a VPN. Off the VPN the gap was gone on
  every link; the relays had never been the cause. → Before naming where time
  goes, vary the path: a second network, or loopback, is what separates the
  code from the road.
- **A test that could not fail, again.** The stop-relay propagation test passed
  with the propagation removed: the destination had dialled the far relay and
  asked it directly. Caught by a targeted mutation. → Mutate each mechanism a
  test is named for, one at a time, and pin the topology the test assumes
  (here: no link from the destination to the far relay).
- **A fix that quietly centralised a decentralised system.** Chain compaction
  made the root sign compacted members, and renewal only asked the issuer of
  the shortest chain — so every compacted member would have needed the root
  alive each year, where each used to be renewed by its own inviter. The
  operator's question ("and if the root disappears?") found it, not the tests.
  → Before shipping anything that names a special node (a root, a relay, an
  issuer), ask what happens when that node is gone for good, and test it.
- **A live network copied into a public repository.** Bug reports, gotchas and
  a test written from live observations carried the operator's public
  addresses, relays' addresses, interface addresses and every node's name —
  merged, in a public repository. → Write an incident with placeholders from
  the start (see *Report every bug*); before a push, grep the diff for what
  the session's live tools showed.
- **`git commit -a` in a tree holding someone's local files.** It took the
  operator's `.claude/settings.local.json` into a pushed branch. → Stage by
  path (`git add <files>`), never `-a`, and read `git status` before a commit.
- **A commit made on a red suite.** `pytest -q | tail -1 && git commit …`:
  the pipe's status is `tail`'s, so `1 failed` printed and the commit and push
  went ahead. → Never chain a commit after a piped test run; run the tests,
  read the line, then commit (or use `set -o pipefail`).
- **The rule read, its other breakers not looked for.** The `free_port`
  docstring says random ports collide; the agent read it while fixing two
  integration tests, and did not grep for `randint` — two unit tests still
  did it, one of them the cause of a red CI on `main` the day before. → When a
  comment names a bad pattern, grep the whole tree for it before moving on.
- **An empty log answer read as "nothing happened".** After a restart the log
  ring is off (no hold survives one — `logging.md`), so a query returns nothing
  whatever happened. → `logs.status` first; an answer from a ring that is not
  running is no evidence of absence.
- **The suite run in the base image as root, over the working tree.**
  `docker run -v "$PWD:/app" … pytest` wrote root-owned `__pycache__` into
  `src/` and `tests/`, which the next local `rm -rf` of the caches could not
  remove. → Run it with `-e PYTHONDONTWRITEBYTECODE=1 -p no:cacheprovider` (or
  `--user "$(id -u):$(id -g)"`), and clear the caches from inside the container
  if it already happened.
- **A merge sent while a check was still pending.** `gh pr merge` was run on a
  PR whose `docker` job had not finished, folded into a command that was
  meant to download a scan; the permission layer stopped it. "CI green" is
  every check `pass`, read from `gh pr checks` in its own step. → Never put a
  merge in a command doing something else, and read the checks first.
- **A tool's blind spot named without asking the tool.** The agent told the
  operator CodeQL could not see the console's HTTP server; it can — the console,
  chat and MCP all subclass `BaseHTTPRequestHandler`, which the library models.
  Listing `RemoteFlowSource` on a local database showed it, and showed the
  real gap: the mesh. → Before saying what an analyser sees, query it for its
  sources.
- **A test helper that swallowed its own failures.** The fuzzer's first seed
  builders caught every exception "so one bad seed does not stop a campaign";
  three targets were then fuzzed from nothing for a whole run, and one from a
  seed cut in half by the length cap, all reporting zero findings. → A helper
  that builds a test's premise raises; check the premise is there (seeds
  non-empty, coverage above zero) before reading a quiet result.
- **A cut turned into "keep going" without asking what the cut bounded.** To
  make the abuse cut silent, an agent let a muted link's receive loop continue;
  on a medium that fails without awaiting, that loop then spun forever and the
  suite hung. The close had been the only thing ending it. → Before removing an
  exit from a loop, find what else that exit was the bound for, and test the
  loop with a medium that never waits.
- **`ls a b` used as "does either exist".** A probe for a library in `lib` or
  `lib64` listed both; `ls` fails when either is missing, so a library in `lib`
  alone was never seen and the rebuild it was meant to trigger never ran. The
  end-to-end scenario caught it; the unit tests had not been written yet. → In
  shell, test existence with `[ -e ]` per path, and write the unit test for a
  probe with each of its branches before the scenario that relies on it.
- **A test edited from memory of it.** A replacement was written for a cache
  test the agent had not opened, and matched nothing; the half of the edit that
  did apply left the suite red for a reason that looked like the code's. →
  Read the test before writing its replacement, every time.
- **Work done on a base 30 versions old.** A bounded HTTP server was written,
  tested and documented against `f422105`, and `origin/main` already had
  `src/http_server.py` doing the same job better (per-address bound included).
  The conflict showed it at commit time, after the work. → `git fetch` and read
  `git log HEAD..origin/main` before writing a fix, not after.
- **A ceiling test that a timeout could pass.** The first test of the HTTP
  connection ceiling gave its handler a 0.4 s idle timeout, so with the ceiling
  removed the extra connection was closed by the timeout and the test still
  passed. Caught by mutating the line. → Make every other way out slower than
  the test, then mutate the mechanism.
- **A baseline taken on a stub.** With `oqs` stubbed to import, 165 webconsole
  tests failed on `HEAD` and on the change alike, and "the same failures" was
  about to be read as no regression. → Before comparing two runs, check the
  baseline is mostly green; a premise that fails everything compares nothing.
  A venv with a real liboqs existed (`~/NMesh/.venv`) and was found by
  searching for `site-packages/oqs`.
- **A path read relative to the current directory in a script that is
  sourced.** `start.sh` read `scripts/liboqs.lock` relative to wherever it had
  `cd`'d, which under the test harness was `/usr/bin`; every stamp then looked
  wrong. → A file that decides trust is read from the script's own tree
  (`BASH_SOURCE`), never from the current directory.
- **An absence asserted on the file's text instead of on what it means.** A
  test that the release no longer pushes `:latest` was written as `":latest"
  not in text`; the comment explaining the rule and the base image's tag both
  contain it, so the test failed on correct code. Caught by the run. → Assert on
  the thing parsed (here, the tags given to `-t` and `docker push`), and run the
  new test against both trees before trusting either verdict.
- **A check whose failure an `echo` swallowed.** Workflows were written as
  `echo "BASE=$(provide-base.sh …)" >> "$GITHUB_ENV"`: the step's status is
  `echo`'s, so a failed provenance check would have left `BASE` empty and the
  job going on. Caught on the reread before commit. → Assign a command's output
  to a variable first (`x="$(cmd)"` fails under `bash -e`), then use it;
  `tests/test_workflows_pinned.py` refuses the other form.
- **A required check renamed without asking what required it.** The suite was
  moved into a reusable workflow, and `ci.yml`'s `test` check became `test /
  test`; branch protection waits for `test` by name, so the PR sat blocked with
  every check green until the operator noticed the check never reported. →
  Before renaming or moving a job, ask whether branch protection names it;
  a check's name is an interface.
- **A rate called "at rest" that was a mesh still settling.** About 30 packets
  per second per node was published as idle traffic; it was taken 25 s after
  start, with searches and handshakes still running, and the same mesh sent
  under 2 packets per second (about 0.2 KiB/s, pings only) after 150 s. →
  Measure at two settling times, publish the later one, and state the time.

- **A build given the timeout of a test run.** liboqs takes about forty
  minutes to compile on four cores; it was started under `timeout 900`, killed
  two thirds of the way, and the half hour it had run was lost. → Before
  bounding a command, estimate how long it takes (count its steps); bound it to
  that, not to a habit.
- **A test double that answered two shapes with one test.** A fake Engine
  returned "the container" when its table was a `dict` — and a table of
  containers is a `dict` too, so every lookup returned the table and the test
  failed for a reason that looked like the code's. → A fake that serves one
  thing or many decides by a field of the thing, not by its type.
- **A slice anchored on the first match, not the intended one.** Editing a
  test file with a Python slice from `subprocess.run([NODE, "-e", script]` to
  `return result.stdout.strip()` cut from the first test that contained the
  first string to the helper that contained the second, deleting ninety tests
  in between; the file was not committed and had to be rebuilt from memory. →
  Anchor both ends of a slice inside the block you mean, assert the slice's
  length is what you expect, and commit a test file before rewriting it by
  script.
- **A key registered before it was used.** The extraction script wrote a
  catalogue entry as soon as it saw a candidate and only then checked the
  candidate was safe to rewrite, leaving a dozen keys no page asked for. →
  Register an effect after the decision to take it, never before; a test
  that every key is used (`test_no_key_is_left_unused`) catches the rest.
