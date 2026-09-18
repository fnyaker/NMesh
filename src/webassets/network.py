"""
`/network` — the whole network, live.

Every other page in this console answers a question about *one* thing and
answers it when asked: this node, that node, that machine's log. An operator
running a mesh has a question none of them answers — **what is happening,
anywhere, right now** — and answering it meant opening four pages and reading
them against each other.

So: one page, two live regions, and nothing on it that is asked for twice.

* **The board** is every node this console can see, in one list, each with what
  it is and whether its log reaches us. It is a merge of two ledgers that
  already exist — the node's own routing table and the fleet's list of managed
  machines — joined on the identity, never a third copy of either.
* **The stream** is every line those nodes are saying, oldest at the top,
  arriving as they arrive. Two subscriptions, both by sequence number
  (``logs.since`` for this node, ``fleet.logs_stream`` for the machines it
  manages), merged in the browser.

Three rules the rest of this file exists to keep:

**Nothing is recorded because a page was opened.** The node's ring is off until
somebody says otherwise (`Docs/Architecture/logging.md`), and a page that turned
it on by being loaded would be a console that starts keeping a record of who
this node talks to because a tab was left open. The switch is on the page, it
says what it does, and a person presses it.

**A filter is a view, never a subscription.** Both streams are asked for
unfiltered and the page filters what it holds. A filter on the wire would be a
different subscription: change it and the cursor has already consumed the lines
the new filter wanted — they are gone, and nothing says so.

**This console, not the node being driven.** Every call is ``{local: true}``.
The fleet's rings are on *this* machine, and asking a managed node for its idea
of the network would be a different question wearing the same words.
"""


HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="theme-color" content="#f6f8fa" media="(prefers-color-scheme: light)">
<meta name="theme-color" content="#0a0e13" media="(prefers-color-scheme: dark)">
<title>NMesh network</title>
<script src="/theme.js"></script>
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<link rel="stylesheet" href="/network.css">
</head>
<body data-app-name="NMesh network">
<a class="skip" href="#main">Skip to content</a>

<div id="login" class="gate hidden">
  <form id="login-form">
    <div class="mark" aria-hidden="true">NM</div>
    <div><p class="eyebrow">Network</p><h1>Sign in</h1></div>
    <p class="muted small">This page reads the console of this node, so it needs
      the console password.</p>
    <label class="field"><span>Console password</span>
      <input id="password" type="password" autocomplete="current-password" autofocus></label>
    <button type="submit" class="primary wide">Enter</button>
    <p id="login-error" class="msg error" role="alert"></p>
  </form>
</div>

<main id="main" class="net-page hidden">
  <header class="net-head">
    <a class="brand" href="/"><span class="mark" aria-hidden="true">NM</span>
      <span><b>NMesh</b><span>Network</span></span></a>
    <span class="grow"></span>
    <div class="net-actions">
      <span id="net-live" class="badge">holding</span>
      <button id="net-keep" class="sm">Start keeping</button>
      <button id="theme-toggle" class="icon" aria-label="Switch theme"><svg class="ic" viewBox="0 0 24 24" aria-hidden="true"><path d="M20.5 14.8A8.6 8.6 0 0 1 9.2 3.5a8.6 8.6 0 1 0 11.3 11.3Z"/></svg></button>
    </div>
  </header>

  <p id="net-notice" class="notice" hidden></p>

  <section class="stats" id="net-stats" aria-label="This console's reach"></section>

  <div class="net-body">
    <section class="card net-board">
      <div class="card-head"><div class="grow"><h2>Nodes <span id="net-node-count" class="badge"></span></h2>
        <div class="sub">Every node this console can see, and whether its log reaches here.</div></div>
        <label class="search"><span class="sr-only">Search nodes</span>
          <input id="net-node-search" type="search" placeholder="Search name or id" spellcheck="false"></label>
      </div>
      <div class="card-body tight"><div id="net-nodes"></div></div>
    </section>

    <section class="card net-stream">
      <div class="card-head"><div class="grow"><h2>Live <span id="net-line-count" class="badge"></span></h2>
        <div class="sub">What those nodes are saying, as they say it.</div></div></div>
      <div class="net-filters">
        <label class="field"><span>Node</span>
          <select id="net-filter-node"><option value="">Every node</option></select></label>
        <label class="field"><span>Level</span>
          <select id="net-filter-level">
            <option value="">Everything</option>
            <option value="debug">debug and above</option>
            <option value="info">info and above</option>
            <option value="warn">warnings and errors</option>
            <option value="error">errors only</option>
          </select></label>
        <label class="field grow"><span>Contains</span>
          <input id="net-filter-text" type="search" placeholder="text, a source, a field value" spellcheck="false"></label>
        <button id="net-clear" class="sm">Clear</button>
      </div>
      <div id="net-lines" class="net-lines" role="log" aria-label="Live log" tabindex="0"></div>
      <button id="net-jump" class="net-jump sm" hidden>Jump to the newest</button>
    </section>
  </div>
</main>

<dialog id="confirm-dialog" aria-labelledby="confirm-title">
  <div class="sheet">
    <header class="sheet-head"><h2 id="confirm-title"></h2></header>
    <div class="sheet-body"><div id="confirm-body"></div></div>
    <footer class="sheet-foot">
      <button id="confirm-cancel">Cancel</button>
      <button id="confirm-ok" class="primary">Confirm</button>
    </footer>
  </div>
</dialog>

<div id="toasts" class="toasts" role="status" aria-live="polite"></div>
<script src="/network.js"></script>
</body>
</html>
"""


CSS = """
.net-page{max-width:1500px;margin:0 auto;padding:var(--s-4) var(--s-4) var(--s-6);
  display:flex;flex-direction:column;gap:var(--s-4);min-height:100dvh}
.net-head{display:flex;align-items:center;gap:var(--s-3);flex-wrap:wrap}
/* Grouped, so a narrow screen wraps the controls together rather than leaving
   the theme toggle stranded on a line of its own. */
.net-actions{display:flex;align-items:center;gap:var(--s-3)}
/* Two columns where there is room, one where there is not. The stream is the
   taller half, so it takes the wider column rather than the equal one. */
.net-body{display:grid;gap:var(--s-4);grid-template-columns:minmax(320px,26rem) minmax(0,1fr);
  align-items:start;flex:1;min-height:0}
@media (max-width:1040px){.net-body{grid-template-columns:minmax(0,1fr)}}
.net-board,.net-stream{min-width:0}
.net-stream{display:flex;flex-direction:column;position:relative;
  max-height:min(76dvh,900px)}
.net-filters{display:flex;flex-wrap:wrap;gap:var(--s-3);align-items:flex-end;
  padding:var(--s-3) var(--s-5);border-bottom:1px solid var(--border)}
.net-filters .field{min-width:0}

/* -- the stream ----------------------------------------------------------- */
/* Scrolls on its own so the page around it stays put: an operator reading the
   board must not have it move because a machine said something. */
.net-lines{overflow:auto;flex:1;min-height:14rem;padding:var(--s-2) 0;
  font-family:var(--mono);font-size:var(--fs-xs);line-height:1.55}
.net-line{display:grid;grid-template-columns:5.5rem 7rem 4.2rem minmax(0,1fr);gap:var(--s-3);
  padding:2px var(--s-5);align-items:baseline;border-left:2px solid transparent}
@media (max-width:640px){.net-line{grid-template-columns:5.5rem minmax(0,1fr)}
  .net-line .who,.net-line .lvl{display:none}}
.net-line:hover{background:var(--surface-2)}
.net-line .at{color:var(--text-faint);font-variant-numeric:tabular-nums}
.net-line .who{color:var(--text-muted);overflow:hidden;text-overflow:ellipsis;
  white-space:nowrap}
.net-line .lvl{color:var(--text-faint);text-transform:uppercase;font-size:.85em;
  letter-spacing:.04em}
.net-line .said{color:var(--text);word-break:break-word;min-width:0}
.net-line .src{color:var(--text-faint)}
.net-line .extra{color:var(--text-muted)}
.net-line.warn{border-left-color:var(--warn)}
.net-line.warn .lvl{color:var(--warn)}
.net-line.error{border-left-color:var(--danger);background:var(--danger-soft)}
.net-line.error .lvl{color:var(--danger)}
.net-line.gap{border-left-color:var(--warn);font-style:italic}
.net-jump{position:absolute;left:50%;transform:translateX(-50%);bottom:var(--s-4);
  box-shadow:var(--shadow-2)}

/* -- the board ------------------------------------------------------------ */
.net-rows{display:flex;flex-direction:column}
.net-row{display:flex;gap:var(--s-3);align-items:baseline;flex-wrap:wrap;
  padding:var(--s-3) var(--s-5);border-bottom:1px solid var(--border)}
.net-row:last-child{border-bottom:0}
.net-row .who{font-weight:600;min-width:0;overflow:hidden;text-overflow:ellipsis;
  white-space:nowrap}
.net-row .rid{color:var(--text-faint);font-family:var(--mono);font-size:var(--fs-xs)}
.net-row .facts{flex-basis:100%;color:var(--text-muted);font-size:var(--fs-xs);
  display:flex;flex-wrap:wrap;gap:var(--s-1) var(--s-3)}
.net-row.self{background:var(--surface-2)}
"""


JS = r"""
// -- /network ---------------------------------------------------------------
// The whole network, live. `src/webassets/network.py` says what this page is
// and the three rules it keeps; below is how.

// What the page holds. Bounded on every axis a busy fleet — or an adversary
// among it — could otherwise grow: a tab left open for a week has to cost what
// one opened a minute ago costs.
const HELD_LINES = 4000;    // kept in the page, for a filter to look through
const DRAWN_LINES = 600;    // in the document at once
const PER_TICK = 500;       // per subscription per tick: the ring's own ceiling

const NET = {
  self: "",            // this node, so the board can put it first
  ownSeq: 0,           // cursor into this node's own ring
  fleetSeq: 0,         // cursor into the fleet archive's tail
  fleet: true,         // is there a fleet app here at all
  lines: [],           // what has arrived since this page opened
  state: null,         // node.state
  held: null,          // logs.status — this node's own ring
  machines: [],        // fleet.logs_machines
  fleetHeld: null,
  following: true,     // is the stream pinned to the newest line
  waiting: 0,          // lines that arrived while it was not
  drawn: 0,            // how much of `lines` is already in the document
  filter: null,        // the filter the document was drawn under
};

function call(op, params){ return CHANNEL.call(op, params, {local:true}); }

// The fleet is an app, and an app may be absent, stopped or uninstalled. Asked
// for once and then not again: a page polling an app that is not there is a
// page spending a call a second to find that out afresh.
async function fleetCall(op, args){
  if(!NET.fleet) return null;
  try{
    const answer = await call("apps.call", {app:"fleet", op, args: args || {}});
    return answer.result || {};
  }catch(_){
    NET.fleet = false;
    return null;
  }
}

// ---- what is being kept ----------------------------------------------------
// The node keeps nothing until somebody says so, and this page is not somebody.
// It reports the state and offers the switch; pressing it is the operator's.
function paintKeeping(){
  const on = !!(NET.held && NET.held.running);
  const pill = $("net-live");
  pill.textContent = on ? "recording" : "not recording";
  pill.className = "badge " + (on ? "ok" : "");
  $("net-keep").textContent = on ? "Stop keeping" : "Start keeping";
  const notice = $("net-notice");
  if(on){ notice.hidden = true; return; }
  const machines = (NET.machines || []).length;
  notice.hidden = false;
  notice.className = "notice warn";
  // Said in full rather than left to a badge, because the page looks *working*
  // and empty — the one state a person reads as broken.
  notice.textContent =
    "This node keeps no log of itself until you ask it to, so its own lines are "
    + "not in the stream below" + (machines
      ? " — the " + plural(machines, "machine") + " this console manages are "
        + "collected separately and still appear."
      : ".");
}

// ---- the board -------------------------------------------------------------
// One row per node, from the two ledgers that already answer this: the node's
// own routing table (who is out there, and how we reach them) and the fleet's
// list of managed machines (whose log arrives here). Joined on the identity, so
// a node that is both is one row rather than two.
function boardRows(){
  const state = NET.state || {};
  const rows = new Map();
  const put = (id, extra) => {
    if(!id) return;
    rows.set(id, Object.assign(rows.get(id) || {id}, extra));
  };
  put(state.id, {self:true, name: state.pseudo || "This node",
                 version: state.version || ""});
  (state.routing || []).forEach((entry) => put(entry.id, {
    name: entry.pseudo || "", connected: !!entry.connected,
    rtt: entry.rtt_ms, seen: entry.seen_ago, silent: !!entry.silent,
    transport: (entry.link || {}).transport || "",
  }));
  (NET.machines || []).forEach((machine) => put(machine.id, {
    managed: true, name: (rows.get(machine.id) || {}).name || machine.label || "",
    policy: machine.policy || "", following: !!machine.following,
    records: machine.records || 0, mayLog: (machine.caps || []).includes("logs"),
  }));
  const query = $("net-node-search").value.trim().toLowerCase();
  const said = tallyByNode();
  return [...rows.values()]
    .map((row) => Object.assign(row, said[row.id] || {}))
    .filter((row) => !query ||
                     (row.id + " " + (row.name || "")).toLowerCase().includes(query))
    // This node first, then whoever is in trouble. Sorted by identity, the
    // machine that is on fire is wherever its hex happens to fall.
    //
    // And *not* by how much each is saying, though that was the obvious third
    // key: it changes every second, so the list would reorder itself under
    // somebody trying to read a row. An error count moves rarely and means
    // something when it does; the rest is alphabetical, which stands still.
    .sort((a, b) => (b.self ? 1 : 0) - (a.self ? 1 : 0)
                 || (b.errors || 0) - (a.errors || 0)
                 || (b.connected ? 1 : 0) - (a.connected ? 1 : 0)
                 || (a.name || a.id).localeCompare(b.name || b.id));
}

// What each node has said *in what this page is holding* — which is what the
// numbers beside it claim and all they claim. Counted off the one buffer the
// stream draws from, so the board and the stream cannot disagree.
function tallyByNode(){
  const out = {};
  for(const line of NET.lines){
    const row = out[line.node] ||
                (out[line.node] = {said:0, errors:0, warns:0});
    row.said += 1;
    if(line.level === "error") row.errors += 1;
    else if(line.level === "warn") row.warns += 1;
  }
  return out;
}

function paintBoard(){
  const rows = boardRows();
  $("net-node-count").textContent = rows.length || "";
  setHTML("net-nodes", rows.length
    ? '<div class="net-rows">' + rows.map(boardRow).join("") + "</div>"
    : emptyHTML("No node yet", "Nothing is connected and nothing is known."));
  // The filter offers what the board shows, so a node an operator can see is a
  // node they can single out. `fill` keeps the choice and leaves an open
  // dropdown open, which is the whole reason it is shared rather than inlined.
  fill($("net-filter-node"), [["", "Every node"]].concat(
    rows.map((row) => [row.id, (row.name || shortId(row.id)) +
                               (row.self ? " (this node)" : "")])));
}

function boardRow(row){
  const standing = row.self ? badge("this node", "accent")
    : row.connected ? badge("connected", "ok")
    : row.silent ? badge("silent", "warn")
    : badge("known");
  // What a log says about this node, in the one place a reader looks for it.
  const log = row.self
    ? (NET.held && NET.held.running ? badge("recording", "ok")
                                    : badge("not recording"))
    : !row.managed ? badge("no log here")
    : row.following ? badge("log arriving", "ok")
    : badge(row.mayLog ? "log " + (row.policy || "idle") : "no log grant",
            row.mayLog ? "" : "warn");
  const facts = [];
  if(row.transport) facts.push(row.transport);
  if(row.rtt != null) facts.push(row.rtt + " ms");
  if(!row.self && !row.connected && row.seen != null)
    facts.push("seen " + fmtAgo(row.seen));
  if(row.version) facts.push("v" + row.version);
  if(row.records) facts.push(plural(row.records, "line") + " held");
  if(row.said) facts.push(row.said + " in view");
  if(row.errors) facts.push(plural(row.errors, "error"));
  else if(row.warns) facts.push(plural(row.warns, "warning"));
  return '<div class="net-row' + (row.self ? " self" : "") + '">' +
    '<span class="who">' + esc(row.name || shortId(row.id)) + "</span>" +
    '<span class="rid">' + esc(shortId(row.id)) + "</span>" +
    '<span class="grow"></span>' + log + standing +
    (facts.length ? '<span class="facts">' + facts.map((fact) =>
        "<span>" + esc(fact) + "</span>").join("") + "</span>" : "") +
    "</div>";
}

function paintStats(){
  const state = NET.state || {};
  const machines = NET.machines || [];
  const held = NET.fleetHeld || {};
  const arriving = machines.filter((machine) => machine.following).length;
  // Every label here was read out loud against its value before it shipped. A
  // link is not a node — one node may hold several — and the two are both worth
  // showing and never the same claim (`CLAUDE.md`).
  const stats = [
    ["Nodes connected", fmtNum(state.node_count)],
    ["Links held", fmtNum(state.link_count)],
    ["Nodes known", fmtNum((state.routing || []).length)],
    ["Logs arriving", NET.fleet ? arriving + " of " + machines.length : "none"],
    ["Lines in view", fmtNum(NET.lines.length)],
    ["Collected here", fmtBytes((held.used_bytes || 0) +
                                ((held.tail || {}).used_bytes || 0))],
  ];
  setHTML("net-stats", stats.map(([label, value]) =>
    '<div class="stat sm"><span class="v">' + esc(String(value)) +
    '</span><span class="k">' + esc(label) + "</span></div>").join(""));
}

// ---- the stream ------------------------------------------------------------
const RANK = ["debug", "info", "warn", "error"];

function matches(line){
  const node = $("net-filter-node").value;
  if(node && line.node !== node) return false;
  // A level is a **floor**, the same way it is everywhere else this product
  // filters one (`src/logbook.py`): asking for warnings means warnings and
  // what is worse, never warnings alone.
  const floor = RANK.indexOf($("net-filter-level").value);
  if(floor >= 0 && RANK.indexOf(line.level) < floor) return false;
  const needle = $("net-filter-text").value.trim().toLowerCase();
  if(!needle) return true;
  return (line.message + " " + line.source + " " + line.extra)
    .toLowerCase().includes(needle);
}

// The filter the document was drawn under. When it changes the document is
// wrong from the top rather than from the end, so it is drawn again.
function filterKey(){
  return JSON.stringify([$("net-filter-node").value,
                         $("net-filter-level").value,
                         $("net-filter-text").value.trim()]);
}

function lineHTML(line){
  const extra = line.extra
    ? ' <span class="extra">' + esc(line.extra) + "</span>" : "";
  return '<div class="net-line ' + esc(line.level) +
    (line.topic === "gap" ? " gap" : "") + '">' +
    '<span class="at">' + esc(fmtTime(line.at)) + "</span>" +
    '<span class="who">' + esc(line.who) + "</span>" +
    '<span class="lvl">' + esc(line.level) + "</span>" +
    '<span class="said"><span class="src">' + esc(line.source) + "</span> " +
    esc(line.message) + extra + "</span></div>";
}

function paintStream(){
  const holder = $("net-lines");
  const key = filterKey();
  if(key !== NET.filter){ NET.filter = key; NET.drawn = 0; holder.textContent = ""; }
  // Appended, never re-assigned. This container is what somebody is reading,
  // and rewriting it on the cadence takes their selection and their scroll
  // position with it — which is the whole of
  // `test_no_page_paints_a_live_container_with_raw_innerhtml`.
  const fresh = NET.lines.slice(NET.drawn).filter(matches);
  NET.drawn = NET.lines.length;
  if(fresh.length)
    holder.insertAdjacentHTML("beforeend", fresh.map(lineHTML).join(""));
  while(holder.childElementCount > DRAWN_LINES) holder.firstElementChild.remove();
  $("net-line-count").textContent = holder.childElementCount || "";
  if(NET.following){ holder.scrollTop = holder.scrollHeight; NET.waiting = 0; }
  else NET.waiting += fresh.length;
  const jump = $("net-jump");
  jump.hidden = NET.following;
  jump.textContent = NET.waiting
    ? plural(NET.waiting, "new line") + " — jump to the newest"
    : "Jump to the newest";
}

// One line, from either subscription, in the shape this page draws. Written
// once so that a line from this node and a line from a machine four hops away
// are the same object by the time anything looks at one — two renderers drift,
// and the field that only one of them sets is where they drift first.
function asLine(raw, node, who){
  const fields = raw.fields || {};
  const extra = Object.entries(fields)
    // The three this console put there are not the line's own, and a field
    // carrying nothing is `address=` on screen — a word a reader has to look at
    // to find out it says nothing. `0` and `false` stay: those are answers.
    .filter(([key, value]) => !["said_at", "seq", "node"].includes(key) &&
                              value !== "" && value != null)
    .map(([key, value]) => key + "=" + value).join(" ");
  return {node, who, at: raw.at || 0, level: raw.level || "info",
          source: raw.source || "", topic: raw.topic || "",
          message: raw.message || "", extra};
}

// A gap is a line like any other: a reader told "some of this is missing" can
// act on it, and one left to notice the jump itself cannot.
function gapLine(node, who, message){
  return {node, who, at: Date.now() / 1000, level: "warn", source: "console",
          topic: "gap", message, extra: ""};
}

function nameOf(id){
  if(id === NET.self) return (NET.state || {}).pseudo || "this node";
  const machine = (NET.machines || []).find((row) => row.id === id);
  if(machine && machine.label) return machine.label;
  const entry = ((NET.state || {}).routing || []).find((row) => row.id === id);
  return (entry && entry.pseudo) || shortId(id);
}

function absorb(lines){
  if(!lines.length) return;
  NET.lines.push(...lines);
  if(NET.lines.length > HELD_LINES){
    const cut = NET.lines.length - HELD_LINES;
    NET.lines.splice(0, cut);
    NET.drawn = Math.max(0, NET.drawn - cut);
  }
}

// ---- the cadences ----------------------------------------------------------
// Two of them, because the halves move at different speeds. The stream is what
// "live" means and runs every second; the board is a list of machines and where
// they stand, which does not change that fast and costs a snapshot to read.
async function tickStream(){
  const arrived = [];
  // Only once this node's own identity is known. Every line from its ring is
  // attributed to it, and a line attributed to `""` is one the board cannot
  // count and the filter cannot single out — which is exactly what the first
  // tick did, before the board had answered, for the whole ring at once. The
  // collected half needs no such wait: those lines say who said them.
  if(NET.self){
    try{
      const own = await call("logs.since", {seq: NET.ownSeq, limit: PER_TICK});
      if(own.lost) arrived.push(gapLine(NET.self, nameOf(NET.self),
        own.lost + " of this node's lines went past before this one"));
      (own.lines || []).forEach((line) =>
        arrived.push(asLine(line, NET.self, nameOf(NET.self))));
      if(own.seq) NET.ownSeq = own.seq;
    }catch(_){ /* keep what is on screen: it was true a moment ago */ }
  }
  const fleet = await fleetCall("logs_stream", {seq: NET.fleetSeq, limit: PER_TICK});
  if(fleet){
    if(fleet.lost) arrived.push(gapLine("", "fleet",
      fleet.lost + " collected lines went past before this one"));
    (fleet.lines || []).forEach((line) =>
      arrived.push(asLine(line, line.node, nameOf(line.node))));
    if(fleet.seq) NET.fleetSeq = fleet.seq;
  }
  // In the order they arrived here, which is the only clock this page has for
  // all of them at once. A machine we manage is an adversary holding a grant,
  // and ordering a merged view by a time *it* supplied would let it pin its
  // lines wherever it liked — the same reason the archive keeps `said_at` as a
  // field and orders by its own (`src/apps/fleet_logs.py`).
  absorb(arrived);
  paintStream();
  // The board counts off this same buffer, so it is repainted here rather than
  // left to its own slower cadence: a row reading "14 in view" beside a heading
  // reading 20 is one claim contradicting another, and both were drawn from the
  // same array a second apart. Both paints compare before they write.
  if(arrived.length){ paintBoard(); paintStats(); }
}

async function tickBoard(){
  try{
    NET.state = await call("node.state");
    NET.self = NET.state.id || NET.self;
  }catch(_){ /* keep what is held */ }
  try{ NET.held = await call("logs.status"); }catch(_){}
  const fleet = await fleetCall("logs_machines");
  if(fleet){
    NET.machines = fleet.machines || [];
    NET.fleetHeld = fleet.held || {};
  }
  paintKeeping();
  paintBoard();
  paintStats();
}

// ---- wiring ----------------------------------------------------------------
async function enter(){
  $("login").classList.add("hidden");
  $("main").classList.remove("hidden");
  // The board first and waited for, because it is what tells this page which
  // node it is sitting on. The stream needs that before it can say who said
  // what, and both cadences run from here on.
  await tickBoard();
  tickStream();
  setInterval(tickStream, 1000);
  setInterval(tickBoard, 4000);
}

async function boot(){
  THEME.paint();
  $("theme-toggle").addEventListener("click", () => THEME.toggle());
  $("confirm-cancel").addEventListener("click", () => $("confirm-dialog").close());

  // Following is the default and staying followed is the point — but an
  // operator who has scrolled up is reading something, so the stream lets go of
  // the bottom and says how much it is holding back rather than yanking them
  // forward every second.
  $("net-lines").addEventListener("scroll", () => {
    const holder = $("net-lines");
    const atEnd = holder.scrollHeight - holder.scrollTop - holder.clientHeight < 24;
    if(atEnd === NET.following) return;
    NET.following = atEnd;
    if(atEnd) NET.waiting = 0;
    $("net-jump").hidden = atEnd;
  });
  $("net-jump").addEventListener("click", () => {
    NET.following = true; NET.waiting = 0;
    $("net-lines").scrollTop = $("net-lines").scrollHeight;
    $("net-jump").hidden = true;
  });

  $("net-filter-text").addEventListener("input", debounce(paintStream, 150));
  $("net-filter-node").addEventListener("change", paintStream);
  $("net-filter-level").addEventListener("change", paintStream);
  $("net-node-search").addEventListener("input", debounce(paintBoard, 150));
  $("net-clear").addEventListener("click", () => {
    NET.lines = []; NET.drawn = 0; NET.waiting = 0;
    $("net-lines").textContent = "";
    paintStream(); paintBoard(); paintStats();
  });

  // The one button here that changes anything on the node. Stopping *drops*
  // what was kept — the node's rule, not this page's — so it is said before it
  // happens rather than explained after.
  $("net-keep").addEventListener("click", async () => {
    const on = !!(NET.held && NET.held.running);
    if(on && !await confirmAction({
        title: "Stop keeping this node's log?",
        body: "What it has kept is dropped, not left in memory. The machines " +
              "this console collects from are not affected.",
        confirm: "Stop keeping"})) return;
    try{
      NET.held = await call("logs.set", {action: on ? "stop" : "start"});
      // A ring just started holds nothing from before this moment, and one just
      // stopped holds nothing at all: either way the cursor we were carrying is
      // about a ring that is gone.
      NET.ownSeq = 0;
      paintKeeping();
      toast(on ? "No longer keeping this node's log"
               : "Keeping this node's log", "ok");
    }catch(error){ toast(error.message || "The node refused", "warn"); }
  });

  $("login-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    try{
      const {ok, data} = await apiJson("/api/login", "POST",
                                       {password:$("password").value});
      if(!ok || !data.token){
        setMessage("login-error", data.error || "Wrong password", true);
        return;
      }
      SESSION.set(data.token);
      enter();
    }catch(_){ setMessage("login-error", "Console is not reachable", true); }
  });

  // Ask before drawing, and ask `local`: a stored token can be stale, and a
  // console reached over loopback may need none at all. This page answers for
  // this machine whatever the console next door is driving, so the question
  // about our session is asked here too.
  SESSION.load();
  try{
    const {ok} = await CHANNEL.ask("node.state", null, {local:true});
    if(ok){ enter(); return; }
  }catch(_){}
  SESSION.clear();
  $("login").classList.remove("hidden");
}

boot();
"""
