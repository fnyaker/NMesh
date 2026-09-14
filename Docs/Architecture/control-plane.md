# The control plane (backend ↔ front end, and the same link at a distance)

Source of truth: `src/control/` (the plane, the frame, the channels, the
modules), `src/webconsole.py` (the one HTTP route onto it),
`src/webassets/channel.py` (the browser's half), `src/apps/fleet_console.py`
(the pipe to another node).

The plane carries **operations** — a question and its answer. What a page *holds*
between them, and how it stays in step with the node holding the truth, is the
other half and is `src/console_feed.py`: the protocol version and the build on
every answer, the named sections sent only when their content moved, and the
rule that an answer which is not one never replaces what a page has. The two
meet at the routes that have not moved onto the plane yet — the fleet state feed
and chat's are the two that carry a page's whole world.

> **Read this before adding an operation to the console, before changing what a
> remote operator may do, and before touching `_from_plane`.**

## What this replaced, and why it had to be replaced

The console *was* the management plane. An operator's every action was an
`if path == "/api/…"` in one 3000-line file, its arguments validated inline, its
answer written as a status code. Driving another node meant taking the whole
HTTP request — method, path, headers, body — and replaying it against that
node's own console over the mesh (`fleet_console`, still how the bytes travel).

That worked, and it had three structural faults. None of them was a bug anybody
wrote; each was a consequence of the *shape*.

1. **The remote permission was a denylist of strings.** The only thing the far
   side could check about a replayed request was the prefix of its path
   (`_CONSOLE_DENIED`: not `/api/fleet/`, not `/api/remote/`, not `/api/chat/`).
   So every route added anywhere in the console became reachable by a peer
   holding `manage` **by default** — the exact inverse of the first principle in
   `CLAUDE.md`.
2. **The front end was pinned to HTTP.** A page knew paths, query strings and
   status codes, so nothing else could ever drive a node: not a command line,
   not a second front end, not a test without a socket.
3. **Nothing could answer "what can this node do?"** A page offered every button
   and found out on the press — including for operations the far node would
   refuse, or could not finish in the time the relay allows.

## The shape now

```
   a page in this browser              an operator's console, elsewhere
            │                                        │
            │  frame                                 │  the same frame
            ▼                                        ▼
   ┌──────────────────┐                    ┌────────────────────────┐
   │ LocalChannel     │                    │ RemoteChannel          │
   │ origin = local   │                    │ relay → fleet `manage` │
   └────────┬─────────┘                    └───────────┬────────────┘
            │                                          │  POST /api/control
            │                                          ▼  (replayed on that
            │                              ┌──────────────────────┐  machine's
            │                              │ that node's console  │  own console)
            │                              │ origin = remote      │
            │                              └───────────┬──────────┘
            ▼                                          ▼
   ┌───────────────────────────────────────────────────────────────┐
   │ ControlPlane — the modules, and nothing else                   │
   │   node · config · transports · trace · pseudo · jobs ·         │
   │   transfer · control                                           │
   └───────────────────────────────────────────────────────────────┘
```

One vocabulary in three places: the page, the console, the node being managed.
Which machine answers is **which channel carried the frame** — not a different
route, not a second front end, not another set of buttons.

## The frame

`src/control/frame.py`. Two documents, and no third:

```json
request   {"v": 1, "id": "7f3a", "op": "node.state", "params": {…}}
reply     {"v": 1, "id": "7f3a", "ok": true,  "result": {…}}
          {"v": 1, "id": "7f3a", "ok": false, "code": "refused",
           "error": "node.retry cannot be driven from a remote console",
           "detail": {…}}
```

* `id` is the caller's own, echoed back untouched. A page with three panels open
  matches answers to questions by it; nothing on the node ever *reads* it — an
  identifier a caller chooses must not become a key into our state.
* `code` comes from a closed set (`src/control/errors.py`): `bad_request`,
  `unauthorized`, `refused`, `not_found`, `conflict`, `unavailable`, `failed`.
  **Not a status number** — the plane is reached over more than one channel, and
  a status is one channel's word for a refusal. `webconsole._STATUS_BY_CODE`
  holds the translation to HTTP, once, at the door.
* `detail` is the refusal that has a shape as well as a sentence. The settings
  form is the case that matters: "some settings were refused" is not actionable,
  `{"rejected": ["console_port: …"]}` is.
* Decoding is hostile-input first: a size cap **on the bytes** before parsing, a
  type check on every field, a bound on every string, and no recursion of our
  own — the *parser* recurses, so a frame of nothing but brackets is refused by
  an explicit, non-recursive bracket-depth scan (`frame._shallow_enough`,
  `MAX_NESTING`) before `json` ever sees it, rather than by leaning on the
  interpreter's own recursion limit — a Python 3.13 change let a 5 000-bracket
  frame that used to hit that limit parse clean instead
  (`Docs/Architecture/gotchas.md`).

### There is no event frame

Events travel as an ordinary operation — `control.changes`, "what has moved
since sequence N". A channel that carries one bounded request and its answer,
which the mesh relay is, cannot hold a stream; one mechanism that works on every
channel beats two that each work on one. The console's `text/event-stream`
(`/api/events`) is a *push optimisation* of that same information over the one
channel that can hold a socket open. A page driving another node polls
`control.changes` instead (`CHANGES` in `webassets/channel.py`) and repaints on
what actually moved — where it used to be told nothing at all and fall back to a
blind timer.

## Declaring an operation

A module groups the operations of one subject and declares them next to itself:

```python
class TraceModule:
    NAME = "trace"
    OPERATIONS = (
        operation("status", "The trace's state, totals and recent events",
                  [param("events", "flag", required=False, default=False)],
                  remote=True, timeout=_READ),
        operation("set", "Start, stop or clear the trace",
                  [param("action", "choice", choices=("start", "stop", "clear")),
                   param("seconds", "count", required=False, default=0,
                         limit=int(MAX_SECONDS))],
                  changes=True, remote=True, timeout=_READ),
    )

    def op_status(self, events): ...
    def op_set(self, action, seconds, events): ...
```

| Field | Means |
|---|---|
| `changes` | alters state — lets a page confirm first, keeps reads and writes apart at a glance. Not a permission. |
| `remote` | **may be driven from another operator's console.** Defaults to `False`. |
| `govern` | may be driven from one that also holds the fleet's `govern` capability. Not `remote` plus something — `remote` already includes every console that holds `govern`, so declaring both is a contradiction and is refused. |
| `background` | run as a **job**: `jobs.start` hands back a ticket rather than the answer. Required of anything that travels and declares more than `REMOTE_BUDGET`, refused on anything that fits it. |
| `timeout` | how long this may take. Also the ceiling the module waits with. |
| `wants_origin` | the answer depends on who is asking (`control.catalogue`, and every `jobs` operation). Injected; a caller cannot forge it, and declaring a parameter of that name is refused. |

Reject by default, three times over:

* an operation that is not declared **does not exist** — dispatch never looks up
  a name a caller supplied, only a name a module wrote down (`op_read` is not
  reachable as `sample.op_read`, and a method that exists but is undeclared is
  not reachable at all);
* an argument that is not declared is refused, never passed through;
* an operation is local-only unless it says otherwise.

### Parameters

`src/control/params.py`. The kinds an app already declares (`src/app_api.py` —
`node`, `text`, `flag`, `count`, `tokens`) are **reused, not restated**: the
shape of a `NodeID` is checked in one place in this project. Five are added for
the management plane — `line` (a path or URI: longer than a label, still one
line), `document` (a bounded mapping, two levels, scalars at the leaves),
`choice` (one of a closed list the operation writes down), `hex` (bytes written
as hex, with a limit: a certificate is 14 kB of it), `secret` (a passphrase,
and the only kind that is never trimmed — a space at the end of one *is* the
passphrase) and `payload` (the arguments of *another* operation, on their way
through `jobs.start`).

`payload` is deliberately not a `document`: a document is a settings file's
worth of values and caps a leaf at 512 characters, which would have quietly
refused the 8 kB signing key `releases.publish` takes. So its shape is checked
— a mapping, named keys, no more of them than a frame carries — and every value
is handed on untouched for the target operation's own `bind` to judge. One
authority per argument, and it is the operation that declared it.

A `document`'s leaves may not contain a newline, and that is not a nicety.
These values are written into a configuration file, one `name = value` per
line, so a newline in a value makes a **second setting** rather than a longer
one — which is how a value for `spool`, editable here, wrote a `launch` line,
which deliberately is not (`gotchas.md`, "a value with a newline in it is not
one value"). The file layer refuses it too: a check in one layer is a check
somebody can route around.

Two rules that are easy to get backwards:

* **A refusal, not a repair.** A value that is not what was declared is refused
  with a sentence naming the field. Truncating a path gives you a different file
  and tells nobody. `text` is narrowed here compared with the app API: a frame is
  JSON, so a field declared as text arrived as text or the caller made a mistake
  — renaming a node to `"42"` because somebody sent the number is a repair.
* **Except a `count` with a `limit`, which is clamped** — because whatever it
  bounds already owns the ceiling. `trace.set` declares
  `limit=trace.MAX_SECONDS`: the same constant, not a second guess at it. Two
  layers with different opinions about "too much" is the bug; one layer
  deferring to the other is not.

## Origins: what a peer may ask of this node

`Origin.LOCAL` is a page on this machine holding a session this console issued.
`Origin.REMOTE` is a peer driving us through the fleet's `manage` capability —
authenticated long before the frame arrived (mesh session, ledger entry, fresh
signature), and still **not somebody at this node**.

The console decides which, and never the caller: a request carrying
`fleet_console.REPLAY_HEADER` is a page on *their* machine, so it reaches the
plane as `REMOTE`. That marker can only ever ask for *less*, so nothing that can
set it gains anything by lying.

`control.catalogue` is filtered by origin, so a remote console draws what that
node will actually answer.

### Origins: and the third one

`Origin.GOVERN` is the same peer as `Origin.REMOTE`, holding the fleet's
`govern` capability as well as `manage`. The console decides which of the three
a request is, and never the caller: a call replayed through the relay carries
`fleet_console.REPLAY_HEADER`, and beside it `GOVERN_HEADER` **written by this
node out of its own ledger** — what arrives over the mesh is a method, a path, a
body and a token, never a header. The govern marker is only ever read together
with the replay marker, so on its own it is a header anybody holding a console
session could set and it grants nothing; both can only ever ask for *less* than
a page here already has, which is why nothing that can set them gains anything
by lying.

Reach, written once, in `plane.REACHED_BY`:

| Origin | Reaches |
|---|---|
| `LOCAL` | everything |
| `GOVERN` | `govern=True` and `remote=True` |
| `REMOTE` | `remote=True` |

## Everything travels, and the two things that stood in the way

The goal was always "an operator can do at a distance whatever they could do at
the machine". Twenty-two operations could not, and reading them as one list was
the mistake — they were two lists with nothing in common but the symptom.

### A ceiling: what does not fit in one call is a job

The relay carries one bounded call and its answer. `REMOTE_BUDGET` (15 s) is
what fits inside `fleet_console.CALL_TIMEOUT` (20 s) and `fleet.CONSOLE_TIMEOUT`
(25 s), and installing a release takes four hundred. So the *work* stays here
and a **ticket** travels: `jobs.start` checks the call exactly as a direct one is
checked, runs it on a daemon thread, and answers with an identifier; `jobs.poll`
says what became of it. Both are small calls with room to spare.

An operation says which it is, and the two are exclusive:

* travels and declares more than `REMOTE_BUDGET` → must say `background=True`;
* declares less → must **not**, because a ticket for something that could simply
  have been answered is a second mechanism for nothing.

Both halves are refused *at declaration*, at import, not on the press
(`tests/test_control_plane.py`). A caller therefore never has to work out which
mechanism an operation uses — its ceiling already says — and a remote console
calling a job operation directly is not left to time out: it is refused with
`detail: {"background": true, "job": "releases.install"}`, which is what
`CHANNEL.call` in the browser re-asks on, so no page had to learn about jobs.

The book is bounded in every direction that an attacker could push
(`src/control/jobs.py`): how many run at once, how many of those a console at a
distance may hold, how many records are kept and for how long. A job that
outlives its own declared ceiling is abandoned and reported failed — the thread
is let go, never joined, for the reason `gotchas.md` gives about `to_thread`.

**A ticket is only readable by the kind of console that could have made it.** A
job started here is invisible from the mesh, and one started by a console
holding `govern` cannot be polled by one holding only `manage` — otherwise "make
a key" would be an answer collectable by whoever can poll. The plane knows which
*kind* of console is asking and never which machine, so two operators sharing a
capability do share a view; pretending otherwise would be a promise this layer
cannot keep.

### A decision: what a node trusts is a second grant

The other list was never about time. Pinning a signing key, minting an
invitation, holding a private key — those are not "drive this console", they are
"decide what this node trusts", and `manage` covers the first. Folding them in
would have made one grant mean two things, and an operator handing somebody the
console so they could restart a service would have handed them the choice of
what program the machine is allowed to become.

So there is a capability for exactly that — `govern`, granted by a human at the
target and taken back the same way, useless without `manage` because `manage` is
what carries the call. `MeshNode.trust_publisher` still says the only way a key
enters its list is an operator acting locally, and that is still true of a
*packet*; what changed is that a console two grants deep is now one of the ways
somebody is "at" a node.

What each of them covers:

| `govern` | Why it is not `manage` |
|---|---|
| `releases.trust` `untrust` `auto` `endorse` | which signing keys this node accepts a program from |
| `releases.apply` `publish` `install` | what program it becomes, and what it signs in its own name |
| `packages.trust` `subscribe` `install` | the same decision, reached through a record |
| `keys.*` (bar the overview) | private keys this node holds, and the passphrases over them |
| `join.invite` `ticket` `block` | who is let into its network — a credential, not a setting |

`store` stays on `manage`, and the distinction is worth stating: installing a
**node release** replaces the code this process is running, while installing an
**app** writes a directory and starts something beside it. Managing a machine is
managing its apps. It is not choosing its program.

A passphrase now travels, and that is a real change rather than an oversight.
It crosses inside the mesh session (ML-KEM-768, AES-256-GCM) to a node whose
operator granted `govern` deliberately, and it is the only way "install this
release on that machine" can be a thing an operator does from where they are.
An operator who does not want that grants `manage` and not `govern`, which is
the whole reason the two are separate words.

## The channels

`src/control/channel.py`. `send(frame) -> frame`, and `call()` written once on
top of it so a Python caller and a browser take the same path through the same
validation.

* `LocalChannel(plane, origin)` — the plane in this process.
* `RefusedChannel(code, message)` — one that answers a refusal and nothing
  else, for a request whose *target* is already wrong. A node id that is not one
  used to fall through to "this node", which would have run a restart or a
  configuration on the **wrong machine**; handing back a channel rather than
  special-casing the caller keeps every path on the rule that something always
  answers, and answers a frame.
* `RemoteChannel(node_hex, relay)` — the same channel, pointed elsewhere. The
  relay is **injected, never imported**: this package knows nothing about the
  fleet app, about HTTP, or about how a frame reaches another node. Today it is
  `WebConsole._control_relay`, which hands the frame to the `manage` capability.

Neither ever raises. A relay that fails is `unavailable` ("the message did not
get there"), which is not the same as the far node refusing, and an operator has
to be able to tell them apart.

### The status describes the console you asked; the frame describes the node you asked about

`POST /api/control` answers a *local* frame with the status its code maps to,
and a *relayed* one with **200 carrying whatever the far node said**. That is
not cosmetic: every client here reads an HTTP 401 as "this console signed me
out", so a managed node dropping our session used to sign the operator out of
their own console. Now that arrives as `{"ok": false, "code": "unauthorized"}`
and the page asks for that node's password again.

## Calling it from Python

```python
context = control.Context(node=node, config_path=path, apps=host.overview,
                          changes=book)
plane = control.build(context)                 # every built-in module
control.LocalChannel(plane).call("node.state").raise_for_refusal()
```

`Context` is deliberately narrow: the node, a bridge onto its loop, the
configuration file, the change book. **Not the console** — an operation that
could see which channel carried its request would sooner or later behave
differently depending on who asked.

`Context.call` is a *thread-side* door: it marshals onto the node's loop and
waits. Calling it **from** that loop is refused immediately with a sentence
naming the fix, because waiting there is a freeze that reads as "the console is
slow" and says nothing about where it is. `Context.ask` is the same call phrased
in the plane's vocabulary (a node that is stopping or slow is `unavailable`), and
every module goes through it so that "the node is stopping" reads the same
whichever operation the operator happened to press.

## What is on the plane, and what is not yet

The console still serves its older routes. They are **not a second
implementation**: a migrated route is a thin adapter (`_from_plane`) that asks
the plane exactly what a frame would and unwraps the answer into the shape that
route always had — so a script, a runbook `curl` or a page nobody has rewritten
keeps working, with one implementation behind it.

| Module | Operations | Older route |
|---|---|---|
| `node` | `state` `list` `ping` `ping_node` `forget` `rootcert` `restart` `retry`~ | `/api/state`, `/api/nodes`, `/api/ping`, `/api/ping/node`, `/api/nodes/forget`, `/api/rootcert`, `/api/restart`, `/api/peers/retry` |
| `trust` | `add` `untrust` `revoke` `forgive` `accept_change` `witness` | `/api/trust`, `/api/trust/*` |
| `network` | `probe` `recheck` `dynamic` `balance` `mlo` `punch` `punch_keepalive` `punch_open` `discovery` `udp` `listen` `unlisten` | `/api/reachability/probe`, `/api/net/recheck`, `/api/addressing/*`, `/api/mlo`, `/api/punch*`, `/api/lan/discovery`, `/api/udp`, `/api/listen`, `/api/unlisten` |
| `config` | `get` `save` | `/api/config` |
| `transports` | `options` `save` | `/api/transports` |
| `trace` | `status` `set` `export` | `/api/trace`, `/api/trace/export` |
| `pseudo` | `get` `search` `save` `lookup`~ | `/api/pseudo` (`?q=`, `?wide=1`) |
| `control` | `catalogue` `changes` | — |
| `jobs` | `start` `poll` `list` `forget` | — (new) |
| `apps` | `catalogue` `call` `list` `set` | `/api/app-api`, `/api/app-call`, `/api/apps/*` |
| `releases` | `overview` `check`~ `apply`\*~ `publish`\*~ `install`\*~ `trust`\* `untrust`\* `auto`\* `endorse`\* | `/api/releases`, `/api/releases/*`, `/api/update/check`, `/api/update/apply` |
| `packages` | `search` `held` `entry` `lookup`~ `describe`~ `install`\*~ `trust`\* `subscribe`\* | `/api/packages`, `/api/packages/<id>`, `/api/packages/*` |
| `keys` | `overview` `create`\*~ `adopt`\*~ `offer`\*~ `accept`\*~ `refuse`\* `forget`\* | `/api/keys`, `/api/keys/*` |
| `store` | `overview` `list` `install` `update` `uninstall` | `/api/store`, `/api/store/catalog`, `/api/store/installed`, `/api/store/install|update|uninstall` |
| `transfer` | `kinds` `fetch`~ `take` `offer` `put` `commit`~ `drop` | `/api/packages/<id>/download`, `/api/app/publish`, `/api/store/publish` |
| `join` | `network` `invite`\* `ticket`\* `block`\* `use_block` | `/api/join`, `/api/invite`, `/api/ticket`, `/api/invite/block`, `/api/join/block` |

`\*` needs the fleet's `govern` capability as well as `manage`. `~` travels as a
**job** — `jobs.start` hands back a ticket, `jobs.poll` answers what became of
it — because it declares more than `REMOTE_BUDGET` and the relay cannot hold a
call open that long. **Nothing is local-only**, and
`tests/test_control_plane.py` asserts it operation by operation.


### What is still not on the plane

Everything the plane declares now travels. What is left outside it is a shorter
list than it used to be, and each entry is outside for a reason that is not
"nobody got to it yet":

* **Login, and the console password.** How a session begins, and that door's own
  key rather than the node's state. A managed node's password is typed once, by
  the operator, into their own console (`/api/remote/connect`); `passwordless`
  is the grant that replaces even that.
* **Bytes.** Publishing an app or a release's files, downloading a package, a
  chat file, an avatar. A control frame is capped to fit `fleet.CONSOLE_REQ_MAX`
  (24 kB) and a reply to `CONSOLE_RESP_MAX`; a 64 MB upload is not a sentence,
  and cutting it into frames would be a transport written twice. The fleet app
  already carries files to a machine you manage, and that is where it belongs.
* **The relay and connect blocks.** 32 kB by their own ceiling
  (`node._RELAY_BLOCK_MAX_LEN`), larger than a frame — and pasted into the
  console of the machine you are sitting at anyway.
* **Chat and fleet's own page surfaces.** By design, not by omission: a managed
  node is not a jump host. What those apps choose to expose *as operations*
  travels on the plane like everything else.

The path relay (`console_path_refusal`) therefore still governs the older routes
that have not moved, and shrinks as they do. The rule to hold on to: **a route
that moves onto the plane loses its prefix-based remote permission and gains a
declared one.**

## The apps are on it too, and they declare their own reach

An app already declares its operations (`src/app_api.py`); `apps.call` puts that
surface on this channel, so an app can be driven on a node somebody manages
rather than only on the one serving the page. **Two gates, and they are not the
same gate:**

* the plane's own `remote` on `apps.call` — may a remote console reach the app
  surface at all;
* the app's per-operation `remote` — which of its operations that console may
  then call.

Both default to no. So an app added tomorrow is unreachable from a distance
until its author writes down what may travel, and the enforcement is in one
place: the plane, which is the layer that knows who is asking. An app never has
to work that out for itself.

The built-in apps declare almost nothing. Chat declares none — somebody else's
conversations were never part of managing their machine. Fleet declares
`relation` only: a read of this node's own ledger, which is what an operator
managing it needs to see, while `enrol`, `request` and `invite` each *act*
through this node's identity towards another, and a node one operator manages
must not become a way to reach the nodes it manages.

This closed a real gap rather than only tidying one. `/api/chat/*` was refused
by the relay, but `/api/app-call` was not — so an operator managing a node could
reach chat's declared operations on it (adding a contact to *their* address
book) through a route the denylist did not name. The permission is now on the
operation, where a new route cannot slip past it.

## Two changes to what the API answers

* A refusal is one shape everywhere: `{"error": "…"}` plus whatever `detail`
  the module attached, and the status from the code. `/api/nodes/forget` used to
  answer `{"ok": false}` for a node it did not know; it now answers
  `{"error": …}` with the same 404, and a malformed id is a 400 rather than a
  404 (it is not a node identity at all, which is the caller's mistake rather
  than a node we have never heard of).
* `/api/app-call` answers **404** for an operation that does not exist — an app
  that is not running, or a name nobody declared — where it used to answer 400
  for both that and a malformed call. Naming nothing at all is still 400: an
  operator reading a 404 would go looking for a missing app rather than at what
  their client sent.
* `/api/pseudo?q=…&wide=1` maps to `pseudo.lookup`, `?q=…` alone to
  `pseudo.search`. They were one route with two costs, which meant one ceiling
  for both — the cheap question inherited the expensive one's timeout, and
  neither could be given one that fitted the relay.

## The bounds, and where they come from

| Bound | Value | Held against |
|---|---|---|
| `frame.MAX_FRAME` | 24 kB | `fleet.CONSOLE_REQ_MAX` — exactly it, because the largest real request is a certificate on its way to being trusted |
| `frame.MAX_REPLY` | 512 kB | `fleet.CONSOLE_RESP_MAX`, `fleet_console.READ_MAX` |
| `plane.REMOTE_BUDGET` | 15 s | `fleet_console.CALL_TIMEOUT` (20 s), `fleet.CONSOLE_TIMEOUT` (25 s) |
| `plane.MAX_MODULES` / `MAX_OPERATIONS` / `MAX_PARAMS` | 32 / 32 / 12 | the declaration cannot itself be an attack |
| `params.MAX_LINE` / `MAX_KEYS` / `MAX_VALUE` | 1024 / 64 / 512 | an argument cannot become a payload |
| `params.MAX_HEX` | 20000 | a certificate (about 14 kB of hex) and no more |
| `params.MAX_SECRET` | 512 | a passphrase, which is the one field never trimmed |

`tests/test_control_plane.py` asserts the first three pairs, and that **every**
remotely-reachable operation's ceiling fits the budget. A comment would have
drifted the first time somebody changed the relay.

## The browser's half

`src/webassets/channel.py`, shipped in every page bundle right after `ui.JS`.

```js
await CHANNEL.call("node.state");                    // the answer, or a throw
const {ok, error, detail, data} =
      await CHANNEL.ask("config.save", {settings});  // refusal painted in place
CHANNEL.has("node.retry");                           // draw the button, or do not
```

`{local: true}` forces one call to this node whatever is being driven — a view
mounted inside a local app needs it, because "what is my link to this person" is
*this* node's question. `CHANNEL.operations()` reads the catalogue once per
context (`CONTEXT.epoch` invalidates it), which is what lets the node view drop
the Retry button when the node being driven will not answer it.
