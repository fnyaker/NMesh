# The control plane (backend ↔ front end, and the same link at a distance)

Source of truth: `src/control/` (the plane, the frame, the channels, the
modules), `src/webconsole.py` (the one HTTP route onto it),
`src/webassets/channel.py` (the browser's half), `src/apps/fleet_console.py`
(the pipe to another node).

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
   │   node · config · transports · trace · pseudo · control        │
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
  type check on every field, a bound on every string, no recursion.

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
| `timeout` | how long this may take. Also the ceiling the module waits with. |
| `wants_origin` | the answer depends on who is asking (only `control.catalogue`). Injected; a caller cannot forge it, and declaring a parameter of that name is refused. |

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
shape of a `NodeID` is checked in one place in this project. Three are added for
the management plane — `line` (a path or URI: longer than a label, still one
line), `document` (a bounded mapping, two levels, scalars at the leaves) and
`choice` (one of a closed list the operation writes down).

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

### Why two operations are local-only

Not secrecy — a ceiling. The relay carries one bounded call and its answer, and
`REMOTE_BUDGET` (15 s) is what fits inside `fleet_console.CALL_TIMEOUT` (20 s)
and `fleet.CONSOLE_TIMEOUT` (25 s). An operation declaring more **and** `remote`
is refused *at declaration*, at import, not on the press:

| Operation | Ceiling | Why it cannot travel |
|---|---|---|
| `node.retry` | 60 s | one dial per known address; a machine with several dead ones outlasts the pipe |
| `pseudo.lookup` | 30 s | a Kademlia round plus a query per target |

Both used to be reachable remotely and would simply time out somewhere in the
middle, telling the operator nothing. `Docs/Architecture/gotchas.md` — "a bound
at one layer is not a bound".

## The channels

`src/control/channel.py`. `send(frame) -> frame`, and `call()` written once on
top of it so a Python caller and a browser take the same path through the same
validation.

* `LocalChannel(plane, origin)` — the plane in this process.
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
| `node` | `state` `ping` `ping_node` `forget` `rootcert` `restart` `retry`\* | `/api/state`, `/api/ping`, `/api/ping/node`, `/api/nodes/forget`, `/api/rootcert`, `/api/restart`, `/api/peers/retry` |
| `trust` | `add` `untrust` `revoke` `forgive` `accept_change` `witness` | `/api/trust`, `/api/trust/*` |
| `network` | `probe` `recheck` `dynamic` `balance` `mlo` `punch` `punch_keepalive` `punch_open` `discovery` `udp` `listen` `unlisten` | `/api/reachability/probe`, `/api/net/recheck`, `/api/addressing/*`, `/api/mlo`, `/api/punch*`, `/api/lan/discovery`, `/api/udp`, `/api/listen`, `/api/unlisten` |
| `config` | `get` `save` | `/api/config` |
| `transports` | `options` `save` | `/api/transports` |
| `trace` | `status` `set` `export` | `/api/trace`, `/api/trace/export` |
| `pseudo` | `get` `search` `lookup`\* `save` | `/api/pseudo` (`?q=`, `?wide=1`) |
| `control` | `catalogue` `changes` | — (new) |
| `apps` | `catalogue` `call` `list` `set` | `/api/app-api`, `/api/app-call`, `/api/apps/*` |
| `node` (lists) | `list` | `/api/nodes` |
| `releases` | `overview` `check` `apply`\* `publish`\* `install`\* `trust`\* `untrust`\* `auto`\* `endorse`\* | `/api/releases`, `/api/releases/*`, `/api/update/check`, `/api/update/apply` |
| `packages` | `search` `held` `entry` `lookup`\* `describe`\* `install`\* `trust`\* `subscribe`\* | `/api/packages`, `/api/packages/<id>`, `/api/packages/*` |
| `keys` | `overview` `create`\* `adopt`\* `offer`\* `accept`\* `refuse`\* `forget`\* | `/api/keys`, `/api/keys/*` |
| `store` | `overview` `list` `install` `update` `uninstall` | `/api/store`, `/api/store/catalog`, `/api/store/installed`, `/api/store/install\|update\|uninstall` |
| `join` | `network` `use_block` `invite`\* `ticket`\* `block`\* | `/api/join`, `/api/invite`, `/api/ticket`, `/api/invite/block`, `/api/join/block` |

\* local only.

### The releases module is almost entirely local, and on purpose

Two reasons that look like one and are not.

**What a node accepts is pinned by a human at that node.**
`MeshNode.trust_publisher` says it in its own docstring — *the only way a key
enters this list is here, an operator acting locally, never a packet*. A console
reached over the mesh is not a packet, but it is not somebody at that machine
either: the fleet's `manage` right is "drive that node's console", not "decide
what may replace its program". Updating a node somebody manages has its own
capability and its own path (`update`, in `Docs/Apps/fleet`), which reports
progress instead of holding a call open. So pinning, unpinning, endorsing and
arming automatic installs are local — a **tightening** against the old path
relay, which allowed all of them to anybody holding `manage`.

**And the rest would not fit anyway.** Publishing signs a whole tree (300 s),
installing fetches and replaces it (400 s), asking GitHub is 40 s. The relay
carries 15. An operation that declares more than `REMOTE_BUDGET` *and* `remote`
is refused at declaration, so this half is not a rule anybody has to remember.

What does travel is the one read — what this node holds, what it has pinned and
what it is watching — because an operator managing a machine needs to see that
without being able to change it.

`store` is the deliberate exception in that family, and the distinction is
worth stating: installing a **node release** replaces the code this process is
running, while installing an **app** writes a directory and starts something
beside it. So an operator managing a machine may install, update and remove its
apps — that is what managing a machine is — and may not change what its own
program is allowed to become.

`join` splits the same way. **Minting is local**: a code this node issues lets
somebody into *its* network, which is a credential rather than a setting, and
the fleet already has a capability for asking a node you manage to mint one
(`invite`) — leaving `join.invite` local is what keeps `manage` from quietly
including it. **Joining travels**, because pointing a machine you manage at a
network is what provisioning one is.

`packages` and `keys` follow from the same sentence. Pinning the key inside a
record, installing what a record names, and watching a package are the same
decision as pinning a publisher, so they stay local; asking the *directory* is
local because a Kademlia round does not fit the relay, while what this node
already knows answers a remote console fine. And for `keys` it is simpler
still: **a passphrase is typed at the machine that will hold the key**, so only
the overview travels — which is the structural half of what
:mod:`src.key_share` is for.

Still routes of their own: chat and fleet's own page surfaces, and what carries
bytes — publishing an app or a release's files, downloading a package, a chat
file or avatar. Plus login/logout. Four things are not candidates at all: **login** is how a session begins, **the
console password** is that door's own key rather than the node's state,
**uploads and downloads** carry bytes rather than a sentence (a control frame is
capped to fit `fleet.CONSOLE_REQ_MAX`), and the **relay and connect blocks** are
32 kB by their own ceiling (`node._RELAY_BLOCK_MAX_LEN`) — larger than a frame,
and pasted into the console of the machine you are sitting at anyway. Chat and
fleet keep their page APIs by design — a managed node is not a jump host — while
what they choose to expose *as operations* travels on the plane like everything
else.

The path relay (`console_path_refusal`) therefore still governs the routes that
have not moved, and shrinks as they do. The rule to hold on to: **a route that
moves onto the plane loses its prefix-based remote permission and gains a
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
| `frame.MAX_FRAME` | 16 kB | `fleet.CONSOLE_REQ_MAX` (24 kB) |
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
