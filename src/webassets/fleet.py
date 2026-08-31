"""
Fleet sub-page (/fleet).

Remote management: the nodes this one manages, the nodes that manage *it*,
deployment over SSH, an interactive shell, and the log of what happened. Served
by the console, behind the same session, under the same strict CSP.

Five sections, split along the question being asked: *whom do I control*
(Nodes), *who controls me* (Access), *bring a machine in* (Deploy), *do
something now* (Shell), *what happened* (Activity).
"""

FLEET_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="theme-color" content="#f6f8fa" media="(prefers-color-scheme: light)">
<meta name="theme-color" content="#0a0e13" media="(prefers-color-scheme: dark)">
<title>NMesh Fleet</title>
<script src="/theme.js"></script>
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<link rel="stylesheet" href="/fleet.css">
</head>
<body data-app-name="NMesh Fleet">

<div id="login" class="gate hidden">
  <form id="login-form">
    <div class="mark" aria-hidden="true">NM</div>
    <div><p class="eyebrow">Fleet</p><h1>Sign in</h1></div>
    <p class="muted small">Fleet uses the console password of this node.</p>
    <label class="field"><span>Console password</span>
      <input id="password" type="password" autocomplete="current-password" autofocus></label>
    <button type="submit" class="primary wide">Enter</button>
    <p id="err" class="msg error" role="alert"></p>
  </form>
</div>

<a class="skip" href="#main">Skip to content</a>
<div id="shell" class="shell hidden">
  <aside class="rail">
    <a class="brand" href="/fleet"><span class="mark" aria-hidden="true">NM</span>
      <span><b>NMesh</b><span>Fleet</span></span></a>
    <nav id="nav" class="nav" role="tablist" aria-label="Fleet sections">
      <button role="tab" data-tab="nodes" data-label="Nodes" aria-selected="true"><span class="lbl">Nodes</span><span id="nav-managed" class="tail"></span></button>
      <button role="tab" data-tab="access" data-label="Access" aria-selected="false"><span class="lbl">Who controls this node</span><span id="nav-pending" class="tail"></span></button>
      <button role="tab" data-tab="deploy" data-label="Deploy" aria-selected="false"><span class="lbl">Discover &amp; deploy</span></button>
      <button role="tab" data-tab="shell" data-label="Shell" aria-selected="false"><span class="lbl">Shell</span></button>
      <button role="tab" data-tab="activity" data-label="Activity" aria-selected="false"><span class="lbl">Activity</span></button>
    </nav>
    <div class="rail-foot">
      <div class="rail-state"><span id="rail-dot" class="dot ok"></span><span id="rail-text">Fleet</span></div>
      <a class="btn ghost wide" href="/">Back to console</a>
    </div>
  </aside>

  <main id="main">
    <header class="topbar">
      <div class="who"><span class="badge">This node</span>
        <button id="me" class="ghost sm mono" title="This node's id"></button></div>
      <span class="grow"></span>
      <div class="menu-wrap">
        <button id="notif-open" class="icon" data-menu="notif" aria-haspopup="true"
                aria-expanded="false" aria-label="Notifications">
          <svg class="ic" width="17" height="17" viewBox="0 0 20 20" fill="none"
               stroke="currentColor" stroke-width="1.6" aria-hidden="true">
            <path d="M5 8a5 5 0 0 1 10 0c0 4 1.4 5.2 1.4 5.2H3.6S5 12 5 8Z"
                  stroke-linejoin="round"/><path d="M8.2 16a2 2 0 0 0 3.6 0"/></svg>
          <span id="notif-count" class="count" hidden></span></button>
        <div id="notif" class="menu" role="region" hidden aria-label="Notifications">
          <div class="menu-head"><span class="grow">Notifications</span>
            <button id="notif-clear" class="ghost sm" data-menu-close>Mark all read</button></div>
          <div id="notif-list"></div>
        </div>
      </div>
      <div id="refresh" class="refresh">
        <label class="sr-only" for="refresh-secs">Auto-refresh, in seconds (0 turns it off)</label>
        <input id="refresh-secs" type="number" min="0" max="30" step="1" inputmode="numeric">
        <span class="unit" aria-hidden="true">s</span>
        <label class="sr-only" for="refresh-pick">Auto-refresh</label>
        <select id="refresh-pick">
          <option value="0">Off</option>
          <option value="1">1s</option>
          <option value="2">2s</option>
          <option value="5">5s</option>
          <option value="10">10s</option>
          <option value="30">30s</option>
        </select>
        <button id="refresh-now" class="icon sm" aria-label="Refresh now" title="Refresh now">⟳</button>
      </div>
      <button id="palette-open" class="ghost sm">Search <span class="kbd">⌘K</span></button>
      <button id="theme-toggle" class="icon" aria-label="Switch theme"><svg class="ic" viewBox="0 0 24 24" aria-hidden="true"><path d="M20.5 14.8A8.6 8.6 0 0 1 9.2 3.5a8.6 8.6 0 1 0 11.3 11.3Z"/></svg></button>
      <div class="menu-wrap more-wrap">
        <button class="icon" data-menu="more" aria-haspopup="true" aria-expanded="false"
                aria-label="More">⋯</button>
        <div id="more" class="menu" role="region" hidden aria-label="More">
          <div class="menu-head"><span class="grow">Fleet</span></div>
          <button class="item" id="more-search" data-menu-close>Search &amp; commands</button>
          <div class="sep"></div>
          <a href="/">Back to console</a>
        </div>
      </div>
    </header>

    <!-- ── Nodes we manage ──────────────────────────────────────────────── -->
    <section id="panel-nodes" class="content panel" role="tabpanel" data-panel="nodes">
      <div class="page-head">
        <div class="grow"><p class="eyebrow">Managed</p><h1>Nodes you control</h1>
          <p class="lede">Each of these accepted a request from this node, and granted exactly the
            capabilities shown. Nothing here was taken; all of it was given.</p></div>
        <div class="actions"><button id="add-open" class="primary">Request access to a node</button></div>
      </div>
      <div id="nodes" class="cards"></div>
    </section>

    <!-- ── Who controls this node ───────────────────────────────────────── -->
    <section id="panel-access" class="content panel" role="tabpanel" data-panel="access" hidden>
      <div class="page-head">
        <div class="grow"><p class="eyebrow">Inbound</p><h1>Who controls this node</h1>
          <p class="lede">Every node listed here can act on this machine. A right is only ever added
            from here — a node can ask, but someone standing on this machine has to agree.</p></div>
      </div>
      <div id="inbox" class="stack"></div>
      <div id="operators" class="cards"></div>
    </section>

    <!-- ── Discover & deploy ────────────────────────────────────────────── -->
    <section id="panel-deploy" class="content panel" role="tabpanel" data-panel="deploy" hidden>
      <div class="page-head">
        <div class="grow"><p class="eyebrow">Expand</p><h1>Discover &amp; deploy</h1>
          <p class="lede">Sweep a network for SSH hosts, then install NMesh on the ones you pick —
            with the same <code class="inline">install.sh</code> a local install runs.</p></div>
      </div>

      <article class="card">
        <div class="card-head"><div class="grow"><h2>1 · Scan</h2>
          <div class="sub">From this node, or from any node that granted you <code class="inline">scan</code></div></div></div>
        <div class="card-body">
          <div class="toolbar">
            <label class="field"><span>Scan from</span><select id="scan-from"></select></label>
            <label class="field grow"><span>Targets</span>
              <input id="scan-nets" class="mono" placeholder="auto — or 192.168.1.0/24, 10.0.0.5, nas.lan:2222" spellcheck="false">
              <span class="hint">A subnet, a machine, or nothing to sweep every attached network.</span></label>
            <button id="scan-btn" class="primary">Scan</button>
          </div>
          <div id="scan-nets-found" class="chips"></div>
          <p id="scan-note" class="msg"></p>
          <div id="hosts" class="stack"></div>
        </div>
      </article>

      <article id="deploy" class="card hidden">
        <div class="card-head"><div class="grow"><h2>2 · Install</h2>
          <div class="sub">Credentials are held in memory for the run only</div></div>
          <span class="badge accent"><span id="deploy-count">0</span> selected</span></div>
        <div class="card-body">
          <div class="notice"><span>Secrets never touch the target's disk and are never passed on a
            command line. An uploaded key lives in this node's <b>encrypted</b> store and is written
            to a private temporary file only while a command runs.</span></div>

          <div class="toolbar">
            <label class="field grow"><span>SSH key</span><select id="ssh-key"></select></label>
            <input id="key-file" type="file" hidden>
            <button type="button" id="key-add">Upload a key…</button>
            <button type="button" id="key-del" class="danger">Remove</button>
          </div>
          <p id="key-note" class="msg"></p>

          <div class="form-grid">
            <label class="field"><span>SSH user</span>
              <input id="ssh-user" autocomplete="off" placeholder="root" spellcheck="false"></label>
            <label class="field"><span>Password</span>
              <input id="ssh-pass" type="password" autocomplete="new-password" placeholder="optional"></label>
            <label class="field"><span>Key passphrase</span>
              <input id="ssh-kpass" type="password" autocomplete="new-password" placeholder="optional"></label>
          </div>
          <p class="muted small">Give a password, a key, or both — both are tried.</p>

          <label class="check"><input id="ssh-sudo" type="checkbox" checked>
            <span>This user can run <code class="inline">sudo</code></span></label>
          <div class="form-grid">
            <label class="field"><span>Otherwise, an account that can</span>
              <input id="sudo-user" autocomplete="off" placeholder="sudo account" spellcheck="false" disabled></label>
            <label class="field"><span>Its password</span>
              <input id="sudo-pass" type="password" autocomplete="new-password" placeholder="optional" disabled></label>
          </div>

          <fieldset class="field bare">
            <legend class="field"><span>Where NMesh goes on each machine</span></legend>
            <div class="form-grid">
              <label class="check card-like"><input type="radio" name="dep-mode" value="system" checked>
                <span><b>System</b> — <code class="inline">/opt/nmesh</code>, its own service account.
                  A boot service, install and state owned by that account in mode 700. Needs root on
                  the target. <b>Recommended.</b></span></label>
              <label class="check card-like"><input type="radio" name="dep-mode" value="user">
                <span><b>User</b> — the login account's home, no root needed. Everything that account
                  runs can read the node's identity key.</span></label>
            </div>
          </fieldset>

          <div class="field"><span>Capabilities the new machines grant you</span>
            <div id="deploy-caps" class="chips"></div></div>

          <div class="btn-row">
            <button id="deploy-btn" class="primary">Deploy to <span id="deploy-count-2">0</span> machine(s)</button>
            <span id="deploy-state" class="msg"></span>
          </div>
        </div>
      </article>
    </section>

    <!-- ── Shell ────────────────────────────────────────────────────────── -->
    <section id="panel-shell" class="content panel" role="tabpanel" data-panel="shell" hidden>
      <div class="page-head">
        <div class="grow"><p class="eyebrow">Live</p><h1>Shell</h1>
          <p class="lede">A real terminal on a node that granted <code class="inline">shell</code>.
            Keystrokes go straight to the remote pty — Ctrl-C, Tab, arrows, and password prompts
            that stay invisible because the pty turns echo off.</p></div>
      </div>
      <article class="card">
        <div class="card-head">
          <label class="field grow"><span class="sr-only">Node</span><select id="shell-node"></select></label>
          <button id="shell-open" class="primary">Open shell</button>
          <button id="shell-kill" class="danger">Close</button>
        </div>
        <div class="card-body tight">
          <pre id="term" class="term" tabindex="0" role="textbox" aria-label="Remote shell"
               aria-multiline="true">Open a shell on a node that granted you the shell capability.</pre>
          <form id="term-form" class="toolbar padded">
            <label class="field grow"><span class="sr-only">Send a whole line</span>
              <input id="term-in" class="mono" placeholder="…or type a whole line here and press Enter"
                     autocomplete="off" spellcheck="false"></label>
            <button type="submit" class="primary">Send</button>
          </form>
        </div>
      </article>
    </section>

    <!-- ── Activity ─────────────────────────────────────────────────────── -->
    <section id="panel-activity" class="content panel" role="tabpanel" data-panel="activity" hidden>
      <div class="page-head">
        <div class="grow"><p class="eyebrow">History</p><h1>Activity</h1>
          <p class="lede">What this node asked, what it was asked, and how each ended.</p></div>
      </div>
      <article class="card"><div class="card-body tight"><div id="log" class="log"></div></div></article>
    </section>
  </main>
</div>

<dialog id="modal" aria-labelledby="modal-title">
  <div class="sheet">
    <header class="sheet-head"><h2 id="modal-title"></h2>
      <button id="modal-close" class="icon" aria-label="Close"><svg class="ic" viewBox="0 0 24 24" aria-hidden="true"><path d="M18 6 6 18M6 6l12 12"/></svg></button></header>
    <div id="modal-body" class="sheet-body"></div>
  </div>
</dialog>

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

<dialog id="palette" class="palette" aria-label="Command palette">
  <div class="sheet">
    <input id="palette-input" type="text" placeholder="Jump to a section, or run an action…"
           autocomplete="off" spellcheck="false" aria-controls="palette-list">
    <div id="palette-list" class="list" role="listbox"></div>
  </div>
</dialog>

<div id="toasts" class="toasts" role="status" aria-live="polite"></div>
<script src="/fleet.js"></script>
</body>
</html>
"""


FLEET_PAGE_CSS = """
/* The terminal is the one place with its own colour world: it renders bytes a
   remote shell chose, so it keeps a fixed dark ground in both themes rather
   than recolouring somebody else's output. */
.term{--page-term-bg:#0a0f16;--page-term-fg:#cfe0f7;
  margin:0;padding:var(--s-4);min-height:440px;max-height:62vh;overflow:auto;
  background:var(--page-term-bg);color:var(--page-term-fg);
  font:13px/1.45 var(--mono);white-space:pre-wrap;overflow-wrap:anywhere;
  border-bottom:1px solid var(--border)}
.term:focus-visible{outline:2px solid var(--ring);outline-offset:-2px}
.t-c0{color:#5b6b80}.t-c1{color:#ff8079}.t-c2{color:#5fd39a}.t-c3{color:#f2c261}
.t-c4{color:#79b0ff}.t-c5{color:#d79bff}.t-c6{color:#5fd9d0}.t-c7{color:#e8eef5}
.t-b{font-weight:700}.t-cur{background:#cfe0f7;color:#0a0f16}

.log{max-height:64vh;overflow:auto;font-size:var(--fs-sm)}
.log .line{display:grid;grid-template-columns:76px 62px minmax(0,1fr);gap:var(--s-3);
  padding:var(--s-2) var(--s-4);border-bottom:1px solid var(--border)}
.log .line:last-child{border-bottom:0}
.log time{color:var(--text-faint);font-variant-numeric:tabular-nums}
.log b{font-size:var(--fs-2xs);text-transform:uppercase;letter-spacing:.05em;align-self:center;
  color:var(--text-muted)}
.log .warn b{color:var(--warn)} .log .err b{color:var(--danger)}

.host{display:flex;align-items:center;gap:var(--s-3);padding:var(--s-2) var(--s-3);
  border:1px solid var(--border);border-radius:var(--r-md);background:var(--surface);
  cursor:pointer;font-size:var(--fs-sm)}
.host:has(input:checked){border-color:var(--accent);background:var(--accent-soft)}
.host .fp{font-size:var(--fs-2xs);color:var(--text-faint)}
/* A notification row: dot, two lines, time. Fixed shape whatever the text, so
   the dropdown scrolls instead of the entries reflowing. */
.menu .notif{align-items:flex-start;gap:var(--s-3)}
.menu .notif>.dot{margin-top:7px}
.menu .notif>.grow{display:flex;flex-direction:column;gap:1px;min-width:0}
.menu .notif b{font-weight:620}
.menu .notif .tiny{font-weight:400;line-height:1.4;overflow-wrap:anywhere}
.menu .notif>.tiny{margin-top:2px}

.node-card .caps{display:flex;flex-wrap:wrap;gap:var(--s-1)}
.node-card .stats{grid-template-columns:repeat(auto-fit,minmax(110px,1fr))}
.upd{display:flex;flex-direction:column;gap:4px}
.cap-pick{display:grid;gap:var(--s-2);grid-template-columns:repeat(auto-fit,minmax(200px,1fr))}
"""


FLEET_PAGE_JS = r"""
// ── fleet page ──────────────────────────────────────────────────────────────
// One polled snapshot drives every panel. Actions post and let the next poll
// tell the truth, so two operators looking at the same node see the same thing.

let VER = 0, ST = {}, POLL = null;
let SHELL = {sid:null, node:null, off:0}, PICKED = {}, HOSTS = [], KEYS = [];
let SCAN_AT = null;              // when the selected node last reported a scan
let DEPLOY_RID = null;           // the remote deployment we are waiting on

SESSION.onLost = () => {
  if(POLL){ clearInterval(POLL); POLL = null; }
  $("shell").classList.add("hidden");
  $("login").classList.remove("hidden");
};
SESSION.load();

// ---- capability pickers ----------------------------------------------------
function capBoxes(container, checked){
  const caps = ST.capabilities || [];
  container.innerHTML = caps.map((cap) =>
    '<label class="check" title="' + esc(cap.description) + '">' +
    '<input type="checkbox" value="' + esc(cap.name) + '"' +
    ((checked || []).includes(cap.name) ? " checked" : "") + "><span>" +
    esc(cap.name) + "</span></label>").join("");
}
function capsOf(container){
  return $$("input:checked", container).map((input) => input.value);
}
function capsList(caps){
  return (caps || []).map((cap) => badge(cap, "accent")).join(" ");
}

// ---- polling ---------------------------------------------------------------
async function poll(){
  let data;
  try{ data = (await apiJson("/api/fleet/state?since=" + VER)).data; }
  catch(_){ return; }
  const first = !ST.capabilities;
  ST = data;
  if(typeof data.log_seq === "number") VER = data.log_seq;
  $("me").textContent = shortId(data.me);
  $("me").title = data.me || "";
  if(first){
    capBoxes($("deploy-caps"), ["status", "update"]);
  }
  paintInbox(); paintNodes(); paintOperators(); paintPickers(); paintLog(); paintJobs();
  if(first) paintHosts(null);
  // A scan asked of a remote node answers asynchronously: its result lands in
  // ST.scans on a later poll, so the deploy tab has to redraw here.
  const stamp = scanStamp();
  if(stamp !== SCAN_AT){ SCAN_AT = stamp; HOSTS = []; paintHosts(null); }
  if(DEPLOY_RID){
    const job = (ST.jobs || []).find((entry) => entry.rid === DEPLOY_RID);
    if(job && job.state !== "running"){
      setMessage("deploy-state", (job.state === "ok" ? "Done: " : "Failed: ") +
        (job.detail || job.state), job.state !== "ok");
      DEPLOY_RID = null;
    }
  }
  if(SHELL.node) pollShell();
}

// ---- decisions waiting on a human ------------------------------------------
function paintInbox(){
  const list = ST.pending_in || [];
  $("nav-pending").textContent = list.length || "";
  setHTML("inbox", list.map((request) => {
    const have = request.have || [];
    const asked = (request.caps || []).map((cap) =>
      badge(cap, have.length && !have.includes(cap) ? "warn" : "accent")).join(" ");
    return '<article class="card"><div class="card-head"><div class="grow">' +
      "<h2>" + (have.length ? "More rights requested" : "Access request") + "</h2>" +
      '<div class="sub mono">' + esc(shortId(request.id)) +
      (request.label ? " · " + esc(request.label) : "") + "</div></div>" +
      badge("waiting on you", "warn") + "</div>" +
      '<div class="card-body"><div class="stack">' +
      (have.length ? '<div class="small muted">Already holds: ' +
        esc(have.join(", ")) + "</div>" : "") +
      '<div class="caps">Wants ' + asked + "</div></div>" +
      '<div class="btn-row"><button class="primary" data-approve="' + esc(request.id) +
      '">Review &amp; accept</button><button class="danger" data-deny="' + esc(request.id) +
      '">Deny</button></div></div></article>';
  }).join(""));
}
function approveDialog(id){
  const request = (ST.pending_in || []).find((entry) => entry.id === id);
  if(!request) return;
  $("modal-title").textContent = "Accept " + shortId(id) + "?";
  $("modal-body").innerHTML =
    '<p class="muted small">Each capability you grant lets that node act on this one. You can ' +
    "narrow the list; you cannot grant more than was asked. What you leave ticked is exactly " +
    "what it holds afterwards" + ((request.have || []).length ? " — including what it has now." : ".") +
    '</p><div id="ap-caps" class="cap-pick"></div>' +
    '<div class="btn-row"><button id="ap-ok" class="primary">Grant access</button>' +
    '<button id="ap-no">Cancel</button></div>';
  const box = $("ap-caps");
  box.innerHTML = (request.caps || []).map((cap) => {
    const known = (ST.capabilities || []).find((entry) => entry.name === cap);
    return '<label class="check card-like" title="' + esc(known ? known.description : "") + '">' +
      '<input type="checkbox" value="' + esc(cap) + '" checked><span><b>' + esc(cap) +
      "</b><br>" + esc(known ? known.description : "") + "</span></label>";
  }).join("");
  $("ap-ok").addEventListener("click", async () => {
    await api("/api/fleet/approve", "POST", {node:id, caps:capsOf(box)});
    $("modal").close(); toast("Access granted", "ok"); poll();
  });
  $("ap-no").addEventListener("click", () => $("modal").close());
  $("modal").showModal();
}

// ---- nodes we manage -------------------------------------------------------
function statusHTML(status){
  if(!status) return '<p class="small muted">No status yet.</p>';
  const memory = status.memory || {}, disks = status.disks || [];
  const root = disks[0] || null, host = status.host || {};
  const load = (status.load && status.load.length) ? status.load[0].toFixed(2) : "—";
  // The status document comes from a managed node over the mesh, so every
  // field in it is network input — including the ones that look like numbers.
  const cell = (key, value, meter) =>
    '<div class="stat sm"><span class="v">' + esc(value) +
    '</span><span class="k">' + esc(key) + "</span>" + (meter || "") + "</div>";
  const meter = (used, total) => {
    const share = total > 0 ? Math.min(100, Math.round(100 * used / total)) : 0;
    return '<progress class="meter ' + (share >= 88 ? "hot" : "") +
      '" value="' + share + '" max="100">' + share + "%</progress>";
  };
  let out = '<div class="stats">' +
    cell("Uptime", esc(fmtDuration(status.uptime))) +
    cell("Load / " + esc(status.cpu_count || "?") + " cpu", esc(load)) +
    cell("Memory", esc(fmtBytes(memory.used)) + " / " + esc(fmtBytes(memory.total)),
         meter(memory.used, memory.total));
  if(root) out += cell("Disk " + esc(root.mount), esc(fmtBytes(root.free)) + " free",
                       meter(root.total - root.free, root.total));
  out += "</div>";
  if(host.distro || host.package_manager)
    out += '<p class="small muted">' + esc(host.distro || host.system || "") +
      (host.package_manager ? " · " + esc(host.package_manager) : "") +
      (host.arch ? " · " + esc(host.arch) : "") +
      (host.can_update === false ? " · <b>cannot self-update</b>" : "") + "</p>";
  return out;
}
// An update runs for minutes. Show where it has got to, not just that a log is
// scrolling somewhere — and keep the last outcome visible once it is over.
function updateHTML(nodeId){
  const run = (ST.updates || {})[nodeId];
  if(!run) return "";
  const position = run.total ? (run.index + "/" + run.total) : String(run.index || "");
  if(run.running){
    const share = run.total ? Math.round(100 * Math.max(0, run.index - 1) / run.total) : 0;
    return '<div class="upd"><progress class="meter" value="' + share + '" max="100">' +
      share + '%</progress>' +
      '<span class="small muted">updating — step ' + esc(position) +
      (run.name ? " · " + esc(run.name) : "") + "</span></div>";
  }
  const took = run.elapsed ? (" in " + Math.round(run.elapsed) + "s") : "";
  return '<p class="small muted">Last update: ' +
    (run.ok ? badge("done" + took, "ok") : badge("failed at step " + position, "danger")) + "</p>";
}
function paintNodes(){
  const managed = ST.managed || [], waiting = ST.pending_out || [];
  $("nav-managed").textContent = managed.length || "";
  let html = waiting.map((entry) =>
    '<article class="card node-card"><div class="card-head"><div class="grow">' +
    "<h2>" + esc(entry.label || entry.pseudo || shortId(entry.id)) + '</h2><div class="sub mono">' +
    esc(shortId(entry.id)) + "</div></div>" + badge("awaiting answer", "warn") + "</div>" +
    '<div class="card-body"><p class="small muted">Waiting for someone on that node to accept. ' +
    'Nothing runs until they do.</p><div class="btn-row"><button class="danger" data-revoke="' +
    esc(entry.id) + '">Cancel request</button></div></div></article>').join("");
  html += managed.map((node) => {
    const caps = node.caps || [], can = (cap) => caps.includes(cap);
    return '<article class="card node-card"><div class="card-head"><div class="grow">' +
      "<h2>" + esc(node.label || node.pseudo || shortId(node.id)) + '</h2><div class="sub mono truncate">' +
      esc(node.id) + "</div></div>" + badge("managed", "ok") + "</div>" +
      '<div class="card-body">' +
      '<div class="caps">' + capsList(caps) + "</div>" +
      updateHTML(node.id) + statusHTML(node.status) +
      '<div class="btn-row">' +
      (can("status") ? '<button data-status="' + esc(node.id) + '">Refresh</button>' : "") +
      (can("invite") ? '<button data-invite="' + esc(node.id) + '">Invite</button>' : "") +
      (can("update") ? '<button data-update="' + esc(node.id) + '">Update</button>' : "") +
      (can("shell") ? '<button data-shell="' + esc(node.id) + '">Shell</button>' : "") +
      (can("scan") ? '<button data-scan="' + esc(node.id) + '">Scan LAN</button>' : "") +
      '<button data-rights="' + esc(node.id) + '">Rights</button>' +
      '<button data-details="' + esc(node.id) + '">Details</button>' +
      '<button class="danger" data-revoke="' + esc(node.id) + '">Revoke</button>' +
      "</div></div></article>";
  }).join("");
  setHTML("nodes", html || emptyHTML("No node yet",
    "Ask a node to let you manage it, or install one from Discover & deploy."));
}
function addDialog(){
  $("modal-title").textContent = "Request access to a node";
  $("modal-body").innerHTML =
    '<p class="muted small">The target node raises a notification; someone there must accept ' +
    "before anything runs.</p>" +
    '<label class="field"><span>Node id</span><input id="add-id" class="mono" ' +
    'placeholder="40 hex characters" autocomplete="off" spellcheck="false"></label>' +
    '<label class="field"><span>Label (optional)</span><input id="add-label" ' +
    'placeholder="What you will call it here"></label>' +
    '<div class="field"><span>Capabilities to ask for</span>' +
    '<div id="add-caps" class="cap-pick"></div></div>' +
    '<div class="btn-row"><button id="add-go" class="primary">Send request</button>' +
    '<button id="add-no">Cancel</button></div>' +
    '<p id="add-msg" class="msg"></p>';
  capBoxes($("add-caps"), ["status", "update"]);
  $("add-go").addEventListener("click", (event) => withBusy(event.target, async () => {
    const id = $("add-id").value.trim().toLowerCase();
    if(!/^[0-9a-f]{40}$/.test(id)){
      setMessage("add-msg", "A node id is 40 hexadecimal characters.", true); return;
    }
    const caps = capsOf($("add-caps"));
    if(!caps.length){ setMessage("add-msg", "Ask for at least one capability.", true); return; }
    const {ok} = await apiJson("/api/fleet/enrol", "POST",
      {node:id, caps, label:$("add-label").value.trim()});
    if(!ok){ setMessage("add-msg", "That request was refused.", true); return; }
    $("modal").close(); toast("Request sent — it is theirs to accept"); poll();
  }));
  $("add-no").addEventListener("click", () => $("modal").close());
  $("modal").showModal();
  $("add-id").focus();
}

// ---- who can control this node ---------------------------------------------
function paintOperators(){
  const operators = ST.operators || [], caps = ST.capabilities || [];
  setHTML("operators", operators.map((operator) => {
    const held = operator.caps || [];
    return '<article class="card"><div class="card-head"><div class="grow">' +
      "<h2>" + esc(operator.label || operator.pseudo || shortId(operator.id)) + '</h2>' +
      '<div class="sub mono truncate">' + esc(operator.id) + "</div></div>" +
      badge("controls this node", "warn") + "</div>" +
      '<div class="card-body"><div class="cap-pick" data-ops="' + esc(operator.id) + '">' +
      caps.map((cap) =>
        '<label class="check card-like" title="' + esc(cap.description) + '">' +
        '<input type="checkbox" value="' + esc(cap.name) + '"' +
        (held.includes(cap.name) ? " checked" : "") + "><span><b>" + esc(cap.name) +
        "</b><br>" + esc(cap.description) + "</span></label>").join("") + "</div>" +
      '<div class="btn-row"><button class="primary" data-caps-set="' + esc(operator.id) +
      '">Apply rights</button><button data-details="' + esc(operator.id) +
      '">Details</button><button class="danger" data-revoke="' + esc(operator.id) +
      '">Cut off</button></div></div></article>';
  }).join("") || emptyHTML("No node can control this one",
    "A node that asks appears here first, as a request waiting on you."));
}
// Changing what *we* hold on a node we manage. The two halves are not
// symmetric, and the dialog says so: dropping is ours to do, asking is theirs
// to answer.
function rightsDialog(id){
  const node = (ST.managed || []).find((entry) => entry.id === id);
  if(!node) return;
  const held = node.caps || [];
  $("modal-title").textContent = "Rights on " + shortId(id);
  $("modal-body").innerHTML =
    '<p class="muted small">Untick a right and it is gone at once — giving one up needs ' +
    "nobody's permission. Tick one and that node raises a request; someone there has to accept " +
    "before it works.</p><div id=\"rt-caps\" class=\"cap-pick\"></div>" +
    '<div class="btn-row"><button id="rt-ok" class="primary">Apply</button>' +
    '<button id="rt-no">Cancel</button></div>';
  const box = $("rt-caps");
  box.innerHTML = (ST.capabilities || []).map((cap) =>
    '<label class="check card-like"><input type="checkbox" value="' + esc(cap.name) + '"' +
    (held.includes(cap.name) ? " checked" : "") + "><span><b>" + esc(cap.name) + "</b><br>" +
    esc(cap.description) + "</span></label>").join("");
  $("rt-ok").addEventListener("click", (event) => withBusy(event.target, async () => {
    const want = capsOf(box);
    const drop = held.filter((cap) => !want.includes(cap));
    const ask = want.filter((cap) => !held.includes(cap));
    if(drop.length) await api("/api/fleet/caps-drop", "POST", {node:id, caps:drop});
    if(ask.length) await api("/api/fleet/caps-request", "POST", {node:id, caps:ask});
    $("modal").close();
    toast(ask.length ? "Asked for " + ask.join(", ") + " — that node must accept"
                     : "Rights given up", ask.length ? "" : "ok");
    poll();
  }));
  $("rt-no").addEventListener("click", () => $("modal").close());
  $("modal").showModal();
}

// ---- pickers and activity --------------------------------------------------
function paintPickers(){
  const managed = ST.managed || [];
  fill($("shell-node"), managed.filter((node) => (node.caps || []).includes("shell"))
       .map((node) => [node.id, node.label || node.pseudo || shortId(node.id)]));
  fill($("scan-from"), [[ST.me, "This node (local LAN)"]].concat(
    managed.filter((node) => (node.caps || []).includes("scan"))
           .map((node) => [node.id, node.label || node.pseudo || shortId(node.id)])));
}
function fill(select, pairs){
  const keep = select.value;
  select.innerHTML = pairs.map((pair) =>
    '<option value="' + esc(pair[0]) + '">' + esc(pair[1]) + "</option>").join("");
  if(pairs.some((pair) => pair[0] === keep)) select.value = keep;
}
function paintLog(){
  const lines = ST.log || [];
  const box = $("log");
  if(!lines.length){
    // An empty panel that says nothing looks broken; say that nothing has
    // happened yet, which is the actual state.
    if(!box.childElementCount)
      box.innerHTML = emptyHTML("Nothing has happened yet",
        "Requests, updates, scans and deployments are recorded here as they run.");
    return;
  }
  if(box.querySelector(".empty")) box.innerHTML = "";
  const atEnd = box.scrollTop + box.clientHeight >= box.scrollHeight - 40;
  for(const line of lines){
    const element = document.createElement("div");
    element.className = "line " + esc(line.level);
    element.innerHTML = "<time>" + esc(fmtTime(line.at)) + "</time><b>" + esc(line.level) +
      "</b><span>" + esc(line.text) + "</span>";
    box.appendChild(element);
  }
  while(box.childElementCount > 500) box.removeChild(box.firstChild);
  if(atEnd) box.scrollTop = box.scrollHeight;
}
// ---- notifications ---------------------------------------------------------
// These used to be chips laid straight into the topbar, which grew the bar every
// time a job or a request showed up — the one place on the page whose height
// must not move. They live in a dropdown now: the bar carries a bell and a
// count, and the count is a badge floating over the button, so two digits do
// not widen anything either.
//
// "Unread" is keyed on rid *and* state, so a job finishing is news even though
// its start already was. The set is bounded like everything else here.
const NOTIF_SEEN = new Set();
const NOTIF_MAX = 20, NOTIF_SEEN_MAX = 200;

function notifications(){
  const items = (ST.pending_in || []).map((request) => ({
    key: "req:" + request.id,
    kind: "warn",
    title: (request.have || []).length ? "More rights requested" : "Access request",
    detail: managedLabel(request.id) + " is waiting on someone here",
    at: request.at || 0,
    tab: "access",
  }));
  (ST.jobs || []).slice(-NOTIF_MAX).forEach((job) => items.push({
    key: job.rid + ":" + job.state,
    kind: job.state === "running" ? "" : (job.state === "ok" ? "ok" : "danger"),
    title: job.kind + " · " + managedLabel(job.node),
    detail: job.state === "running" ? "running…"
      : (job.detail || (job.state === "ok" ? "done" : "failed")),
    at: job.at || 0,
    tab: "activity",
  }));
  // Newest first; a request waiting on a human outranks a job either way.
  items.sort((a, b) => (b.at || 0) - (a.at || 0));
  return items.slice(0, NOTIF_MAX);
}

function paintJobs(){
  const items = notifications();
  const unread = items.filter((item) => !NOTIF_SEEN.has(item.key)).length;
  const count = $("notif-count");
  count.textContent = unread > 9 ? "9+" : String(unread);
  count.hidden = unread === 0;
  $("notif-open").setAttribute("aria-label",
    unread ? "Notifications, " + unread + " unread" : "Notifications");
  if(MENU.open === "notif") paintNotifList(items);
}

function paintNotifList(items){
  const list = items || notifications();
  $("notif-list").innerHTML = list.length ? list.map((item) =>
    '<button class="item notif" data-notif-tab="' + esc(item.tab) + '" data-menu-close>' +
    '<i class="dot ' + esc(item.kind) + '"></i>' +
    '<span class="grow"><b class="truncate">' + esc(item.title) + "</b>" +
    '<span class="tiny muted">' + esc(item.detail) + "</span></span>" +
    (item.at ? '<span class="tiny muted flex-none">' + esc(fmtTime(item.at)) + "</span>" : "") +
    "</button>").join("")
    : '<div class="none">Nothing waiting. Jobs and access requests show up here.</div>';
}

function markNotifRead(){
  const items = notifications();
  if(NOTIF_SEEN.size + items.length > NOTIF_SEEN_MAX) NOTIF_SEEN.clear();
  items.forEach((item) => NOTIF_SEEN.add(item.key));
  paintJobs();
}

MENU.onShow.notif = () => { paintNotifList(); markNotifRead(); };
// How a managed node is named here: the label this operator gave it if there is
// one, otherwise the node's own signed pseudo — and either way the id, because
// a name is never what you check before acting on a machine.
function managedLabel(id){
  if(!id) return "";
  if(id === ST.me) return "this node";
  const node = (ST.managed || []).find((entry) => entry.id === id);
  return nodeLabel(id, (node && (node.label || node.pseudo)) || "");
}

// ---- discovery -------------------------------------------------------------
async function runScan(event){
  const from = $("scan-from").value;
  const targets = $("scan-nets").value.split(",").map((part) => part.trim()).filter(Boolean);
  await withBusy(event ? event.target : $("scan-btn"), async () => {
    setMessage("scan-note", "Scanning… this takes a moment.");
    try{
      const {data} = await apiJson("/api/fleet/scan", "POST", {node:from, targets});
      if(data.hosts){ HOSTS = data.hosts; KEYS = data.keys || []; SCAN_AT = null; paintHosts(data); }
      else{
        // Remote: the answer comes back through the poll, so arm the watcher.
        SCAN_AT = scanStamp(); HOSTS = [];
        setMessage("scan-note", "Scan running on the remote node…");
      }
    }catch(_){ setMessage("scan-note", "Scan failed.", true); }
  });
}
function scanStamp(){
  const entry = (ST.scans || {})[$("scan-from").value];
  return entry ? entry.at : null;
}
function paintNets(nets){
  $("scan-nets-found").innerHTML = (nets || []).map((net) =>
    '<span class="chip">' + esc(net.scan || net.cidr) +
    (net.interface ? ' <span class="muted">' + esc(net.interface) + "</span>" : "") +
    (net.narrowed ? " " + badge("narrowed from " + net.cidr, "warn") : "") + "</span>").join("");
}
function paintHosts(meta){
  // A local scan answers in the POST body; a remote one lands in the polled
  // snapshot. Either way the stored result is the source of truth.
  const stored = (ST.scans || {})[$("scan-from").value] || {};
  if(!HOSTS.length) HOSTS = (meta && meta.hosts) || stored.hosts || [];
  paintNets((meta && meta.networks) || stored.networks || []);
  const notes = [];
  if(meta && meta.ssh_client === false) notes.push("That node has no ssh client, so it cannot deploy.");
  else if(HOSTS.length) notes.push(HOSTS.length + " SSH host(s) found.");
  else if(SCAN_AT || meta) notes.push("No SSH hosts found.");
  const rejected = (meta && meta.rejected) || stored.rejected || [];
  if(rejected.length) notes.push("Could not understand: " + rejected.join(", ") + ".");
  const cut = (meta && meta.truncated) || stored.truncated || 0;
  if(cut) notes.push(cut + " result(s) dropped — the reply did not fit one frame; " +
                     "narrow the target to see them.");
  setMessage("scan-note", notes.join(" "));
  PICKED = {};
  $("hosts").innerHTML = HOSTS.length ? HOSTS.map((host, index) => {
    const fingerprint = (host.keys || []).map((key) => key.fingerprint).filter(Boolean)[0] || "";
    return '<label class="host"><input type="checkbox" data-host="' + index + '">' +
      '<span class="mono">' + esc(host.ip) + ":" + esc(String(host.port)) + "</span>" +
      '<span class="muted grow truncate">' + esc(host.banner || "") + "</span>" +
      (fingerprint ? '<span class="fp mono">' + esc(fingerprint) + "</span>"
                   : badge("no host key", "warn")) + "</label>";
  }).join("") : (SCAN_AT || meta ? "" : emptyHTML("Nothing scanned yet",
    "Pick where to scan from and press Scan. Only hosts with an open SSH port appear."));
  paintKeys();
  $("deploy").classList.toggle("hidden", HOSTS.length === 0);
  updateCount();
}
$("hosts").addEventListener("change", (event) => {
  const index = event.target.dataset.host;
  if(index === undefined) return;
  if(event.target.checked) PICKED[index] = true; else delete PICKED[index];
  updateCount();
});
function updateCount(){
  const count = Object.keys(PICKED).length;
  $("deploy-count").textContent = count;
  $("deploy-count-2").textContent = count;
  $("deploy-btn").disabled = count === 0;
}

// ---- ssh keys --------------------------------------------------------------
function keyLabel(key){
  return key.name + (key.encrypted ? " (passphrase)" : "") +
    (key.source === "uploaded" ? " — uploaded" : (key.comment ? " — " + key.comment : ""));
}
function paintKeys(){
  fill($("ssh-key"), [["", "No key — password only"]].concat(
    KEYS.map((key) => [key.id || ("file:" + key.path), keyLabel(key)])));
  const chosen = $("ssh-key").value;
  $("key-del").disabled = !(KEYS.length && chosen && chosen.indexOf("file:") !== 0);
}
async function loadKeys(){
  try{ KEYS = (await apiJson("/api/fleet/keys")).data.keys || []; }
  catch(_){ KEYS = []; }
  paintKeys();
}
async function uploadKey(file){
  if(!file) return;
  if(file.size > 128 * 1024){ setMessage("key-note", "That file is too large for a key.", true); return; }
  const text = await file.text();
  if(!text.includes("PRIVATE KEY")){
    setMessage("key-note", "That does not look like a private key.", true); return;
  }
  const {ok, data} = await apiJson("/api/fleet/keys", "POST", {name:file.name, data:text});
  KEYS = data.keys || KEYS;
  paintKeys();
  if(data.key) $("ssh-key").value = data.key.id;
  setMessage("key-note", ok
    ? "Key " + (data.key ? data.key.name : "") + " added — it will be used to deploy."
    : "Could not store that key.", !ok);
  paintKeys();
}
async function removeKey(){
  const id = $("ssh-key").value;
  if(!id || id.indexOf("file:") === 0) return;
  const agreed = await confirmAction({title:"Remove this key?",
    body:'<p class="muted small">It is deleted from this node\'s encrypted store. Deployments ' +
      "that used it will need another credential.</p>",
    confirmLabel:"Remove key", danger:true});
  if(!agreed) return;
  const {data} = await apiJson("/api/fleet/keys-remove", "POST", {id});
  KEYS = data.keys || KEYS;
  paintKeys();
  toast("Key removed");
}
function syncSudoFields(){
  const own = $("ssh-sudo").checked;
  $("sudo-user").disabled = own; $("sudo-pass").disabled = own;
  if(own){ $("sudo-user").value = ""; $("sudo-pass").value = ""; }
}

// ---- deployment ------------------------------------------------------------
async function deploy(event){
  const targets = Object.keys(PICKED).map((index) => {
    const host = HOSTS[index];
    return {ip:host.ip, port:host.port, label:host.ip,
            known_hosts:(host.keys || []).map((key) => key.line).filter(Boolean)};
  });
  if(!targets.length) return;
  const body = {
    node:$("scan-from").value, targets,
    username:$("ssh-user").value.trim(),
    password:$("ssh-pass").value || null,
    key_id:$("ssh-key").value || null,
    key_passphrase:$("ssh-kpass").value || null,
    can_sudo:$("ssh-sudo").checked,
    sudo_user:$("ssh-sudo").checked ? null : ($("sudo-user").value.trim() || null),
    sudo_password:$("ssh-sudo").checked ? null : ($("sudo-pass").value || null),
    mode:(document.querySelector('input[name="dep-mode"]:checked') || {}).value || "system",
    caps:capsOf($("deploy-caps")),
  };
  if(!body.username){ setMessage("deploy-state", "An SSH user is required.", true); return; }
  if(!body.password && !body.key_id){
    setMessage("deploy-state", "Give a password, a key, or both.", true); return;
  }
  // Said here as well as on the node: a system install with no way to reach
  // root fails after the operator has already typed everything.
  if(body.mode === "system" && !body.can_sudo && !body.sudo_user){
    setMessage("deploy-state",
      "A system install needs root: tick sudo, name a sudo account, or install under the user.",
      true);
    return;
  }
  await withBusy(event ? event.target : $("deploy-btn"), async () => {
    setMessage("deploy-state", "Deploying… watch Activity.");
    try{
      const {data} = await apiJson("/api/fleet/provision", "POST", body);
      if(data.results){
        const good = data.results.filter((result) => result.ok).length;
        setMessage("deploy-state", "Done: " + good + "/" + data.results.length + " succeeded.",
                   good !== data.results.length);
      }else{
        // Remote: the outcome arrives through the polled job list.
        DEPLOY_RID = data.rid || null;
        setMessage("deploy-state", "Running on the remote node…");
      }
    }catch(_){ setMessage("deploy-state", "Deployment failed to start.", true); }
    finally{
      // Drop the secrets from the DOM as soon as the run has been handed over.
      $("ssh-pass").value = ""; $("ssh-kpass").value = "";
      poll();
    }
  });
}

// ---- a small terminal ------------------------------------------------------
// Written rather than depended on: a shell you can type `sudo` into needs a
// terminal, not a log pane, and pulling in an emulator library for it would
// cost a name in the supply chain this project keeps deliberately short.
//
// What it implements is what a shell session actually uses: printable text,
// CR/LF/BS/TAB/BEL, cursor movement, the two erase commands, and SGR colours.
// Anything else is consumed and ignored rather than printed — an unknown escape
// must never end up on screen as garbage.
function Term(cols,rows){
  this.cols=cols; this.rows=rows;
  this.x=0; this.y=0; this.sgr=""; this.scrollback=[];
  this.grid=[]; for(let i=0;i<rows;i++)this.grid.push(this.blankRow());
  this.pending="";
}
Term.prototype.blankRow=function(){
  const row=[]; for(let i=0;i<this.cols;i++)row.push({ch:" ",cls:""});
  return row;
};
Term.prototype.newline=function(){
  this.y++;
  if(this.y>=this.rows){
    this.scrollback.push(this.grid.shift());
    if(this.scrollback.length>2000)this.scrollback.shift();
    this.grid.push(this.blankRow());
    this.y=this.rows-1;
  }
};
Term.prototype.put=function(ch){
  if(this.x>=this.cols){this.x=0;this.newline();}
  this.grid[this.y][this.x]={ch:ch,cls:this.sgr};
  this.x++;
};
Term.prototype.eraseLine=function(mode){
  const row=this.grid[this.y];
  const from=mode===1?0:(mode===2?0:this.x);
  const to=mode===0?this.cols:(mode===1?this.x+1:this.cols);
  for(let i=from;i<to&&i<this.cols;i++)row[i]={ch:" ",cls:""};
};
Term.prototype.eraseDisplay=function(mode){
  if(mode===2||mode===3){
    for(let y=0;y<this.rows;y++)this.grid[y]=this.blankRow();
    if(mode===2){this.x=0;this.y=0;}
    return;
  }
  this.eraseLine(mode===1?1:0);
  if(mode===0)for(let y=this.y+1;y<this.rows;y++)this.grid[y]=this.blankRow();
  else for(let y=0;y<this.y;y++)this.grid[y]=this.blankRow();
};
Term.prototype.sgrClass=function(params){
  // Only the attributes that make output readable: reset, bold, and the eight
  // foreground colours (plus their bright forms).
  let cls=this.sgr;
  for(const raw of params){
    const n=raw===""?0:parseInt(raw,10);
    if(n===0)cls="";
    else if(n===1)cls=(cls+" t-b").trim();
    else if(n>=30&&n<=37)cls=cls.replace(/t-c\d/g,"").trim()+" t-c"+(n-30);
    else if(n>=90&&n<=97)cls=cls.replace(/t-c\d/g,"").trim()+" t-c"+(n-90)+" t-b";
    else if(n===39)cls=cls.replace(/t-c\d/g,"").trim();
  }
  return cls.replace(/\s+/g," ").trim();
};
Term.prototype.write=function(text){
  let data=this.pending+text; this.pending="";
  for(let i=0;i<data.length;i++){
    const ch=data[i];
    if(ch==="\x1b"){
      // An escape may be split across two chunks: keep the tail and retry.
      const rest=data.slice(i);
      const csi=/^\x1b\[([0-9;?]*)([ -\/]*)([@-~])/.exec(rest);
      if(csi){ this.csi(csi[1],csi[3]); i+=csi[0].length-1; continue; }
      const osc=/^\x1b\][^\x07\x1b]*(\x07|\x1b\\)/.exec(rest);
      if(osc){ i+=osc[0].length-1; continue; }        // window title and friends
      const two=/^\x1b[=>()#][0-9A-Za-z]?/.exec(rest);
      if(two){ i+=two[0].length-1; continue; }
      if(rest.length<8){ this.pending=rest; return; }  // incomplete, wait
      continue;                                        // unknown: drop it
    }
    if(ch==="\n"){ this.newline(); continue; }
    if(ch==="\r"){ this.x=0; continue; }
    if(ch==="\b"){ if(this.x>0)this.x--; continue; }
    if(ch==="\t"){ const next=(Math.floor(this.x/8)+1)*8;
                   while(this.x<next&&this.x<this.cols)this.put(" ");
                   continue; }
    if(ch==="\x07")continue;                          // bell
    if(ch<" ")continue;                                // other control bytes
    this.put(ch);
  }
};
Term.prototype.csi=function(paramText,final){
  const params=paramText.replace("?","").split(";");
  const n=Math.max(1,parseInt(params[0]||"1",10)||1);
  switch(final){
    case "A": this.y=Math.max(0,this.y-n); break;
    case "B": this.y=Math.min(this.rows-1,this.y+n); break;
    case "C": this.x=Math.min(this.cols-1,this.x+n); break;
    case "D": this.x=Math.max(0,this.x-n); break;
    case "G": this.x=Math.min(this.cols-1,Math.max(0,n-1)); break;
    case "H": case "f": {
      const row=Math.max(1,parseInt(params[0]||"1",10)||1);
      const col=Math.max(1,parseInt(params[1]||"1",10)||1);
      this.y=Math.min(this.rows-1,row-1); this.x=Math.min(this.cols-1,col-1);
      break;
    }
    case "J": this.eraseDisplay(parseInt(params[0]||"0",10)||0); break;
    case "K": this.eraseLine(parseInt(params[0]||"0",10)||0); break;
    case "m": this.sgr=this.sgrClass(params); break;
    default: break;                                    // consumed, never printed
  }
};
Term.prototype.render=function(showCursor){
  const rows=this.scrollback.slice(-800).concat(this.grid);
  // Where the cursor is, in the concatenated view. Drawn because a terminal you
  // type into without one is disorienting — and because on a password prompt
  // the cursor not moving is the visible sign that echo is off.
  const cursorRow=showCursor===false?-1:this.scrollback.slice(-800).length+this.y;
  const out=[];
  for(let index=0;index<rows.length;index++){
    const row=rows[index];
    let line="",cls=null,run="";
    const flush=()=>{
      if(!run)return;
      line+=cls?('<span class="'+cls+'">'+escHtml(run)+"</span>"):escHtml(run);
      run="";
    };
    for(let column=0;column<row.length;column++){
      const cell=row[column];
      const isCursor=index===cursorRow&&column===this.x;
      const cellCls=isCursor?(cell.cls+" t-cur").trim():cell.cls;
      if(cellCls!==cls){flush();cls=cellCls;}
      run+=cell.ch;
    }
    flush();
    // Trailing blanks are trimmed: a row is `cols` cells wide, and padding
    // every line to the full width would make the pane scroll sideways for
    // nothing. The cursor cell survives because it carries a class.
    out.push(line.replace(/(\s|&nbsp;)+$/,""));
  }
  return out.join("\n");
};
function escHtml(text){
  return text.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
}

// ---- shell ----
let TERM = null;
function termSize(){
  // Measured from the pane rather than assumed: the remote pty is told these
  // dimensions, and a shell that thinks it has a different width redraws wrong.
  const box = $("term");
  const probe = document.createElement("span");
  probe.style.cssText = "position:absolute;visibility:hidden;white-space:pre";
  probe.textContent = "0".repeat(80);
  box.appendChild(probe);
  const charWidth = (probe.getBoundingClientRect().width / 80) || 8;
  const lineHeight = parseFloat(getComputedStyle(box).lineHeight) || 16;
  box.removeChild(probe);
  return {
    cols: Math.max(20, Math.min(200, Math.floor((box.clientWidth - 24) / charWidth))),
    rows: Math.max(10, Math.min(60, Math.floor((box.clientHeight - 24) / lineHeight))),
  };
}
async function openShell(){
  const node = $("shell-node").value;
  if(!node){ $("term").textContent = "No node has granted you a shell."; return; }
  const size = termSize();
  TERM = new Term(size.cols, size.rows);
  $("term").textContent = "";
  SHELL = {sid:null, node, off:0};
  try{ await api("/api/fleet/shell", "POST", {node, cols:size.cols, rows:size.rows}); }
  catch(_){ $("term").textContent = "Could not open a shell."; return; }
  $("term").focus();
}
async function pollShell(){
  if(!SHELL.node) return;
  if(!SHELL.sid){
    const open = (ST.shells || []).filter((entry) => entry.node === SHELL.node && entry.open).pop();
    if(!open) return;
    SHELL.sid = open.sid; SHELL.off = 0;
  }
  let data;
  try{
    data = (await apiJson("/api/fleet/shell?sid=" + encodeURIComponent(SHELL.sid) +
                          "&offset=" + SHELL.off)).data;
  }catch(_){ return; }
  if(!data) return;
  if(data.data){
    const raw = atob(data.data);
    let text;
    try{ text = new TextDecoder().decode(Uint8Array.from(raw, (c) => c.charCodeAt(0))); }
    catch(_){ text = raw; }
    const box = $("term");
    const atEnd = box.scrollTop + box.clientHeight >= box.scrollHeight - 40;
    if(!TERM) TERM = new Term(80, 24);
    TERM.write(text);
    box.innerHTML = TERM.render();
    if(atEnd) box.scrollTop = box.scrollHeight;
  }
  SHELL.off = data.seq;
  if(!data.open){
    $("term").textContent += "\n[session closed]\n";
    SHELL.sid = null; SHELL.node = null;
  }
}
async function sendBytes(text){
  if(!SHELL.sid) return;
  const encoded = new TextEncoder().encode(text);
  let binary = "";
  encoded.forEach((byte) => { binary += String.fromCharCode(byte); });
  await api("/api/fleet/input", "POST", {node:SHELL.node, sid:SHELL.sid, data:btoa(binary)});
}

// What a key sends. Nothing is echoed locally: the remote pty decides what
// comes back, which is exactly why a password prompt stays invisible — the pty
// turns echo off and there is nothing on this side to show it anyway.
function keyBytes(event){
  if(event.ctrlKey && !event.altKey && event.key.length === 1){
    const code = event.key.toUpperCase().charCodeAt(0);
    if(code >= 64 && code <= 95) return String.fromCharCode(code - 64);   // ^A..^_
    if(event.key === "?") return "\x7f";
  }
  switch(event.key){
    case "Enter": return "\r";
    case "Backspace": return "\x7f";
    case "Tab": return "\t";
    case "Escape": return "\x1b";
    case "ArrowUp": return "\x1b[A";
    case "ArrowDown": return "\x1b[B";
    case "ArrowRight": return "\x1b[C";
    case "ArrowLeft": return "\x1b[D";
    case "Home": return "\x1b[H";
    case "End": return "\x1b[F";
    case "Delete": return "\x1b[3~";
    case "PageUp": return "\x1b[5~";
    case "PageDown": return "\x1b[6~";
    default: break;
  }
  if(event.key.length === 1 && !event.ctrlKey && !event.metaKey) return event.key;
  return null;
}

// ---- wiring ----------------------------------------------------------------
document.body.addEventListener("click", async (event) => {
  const button = event.target.closest("button");
  if(!button) return;
  const data = button.dataset;
  if(data.approve) return approveDialog(data.approve);
  if(data.rights) return rightsDialog(data.rights);
  if(data.details) return nodeDialog(data.details);
  if(data.capsSet){
    const box = document.querySelector('[data-ops="' + data.capsSet + '"]');
    if(!box) return;
    await withBusy(button, async () => {
      const {ok} = await apiJson("/api/fleet/caps-set", "POST",
        {node:data.capsSet, caps:capsOf(box)});
      toast(ok ? "Rights updated" : "That change was refused", ok ? "ok" : "danger");
      poll();
    });
    return;
  }
  if(data.deny){
    const agreed = await confirmAction({title:"Deny this request?",
      body:'<p class="muted small">Nothing is granted and the request disappears. They can ask ' +
        "again.</p>", confirmLabel:"Deny", danger:true});
    if(!agreed) return;
    await api("/api/fleet/deny", "POST", {node:data.deny});
    toast("Request denied");
    return poll();
  }
  if(data.revoke){
    const agreed = await confirmAction({title:"Cut this relationship?",
      body:'<p class="muted small">Every right in both directions is dropped, the other side is ' +
        "told, and any shell it holds is closed.</p>" +
        '<p class="mono small">' + esc(data.revoke) + "</p>",
      confirmLabel:"Revoke", danger:true});
    if(!agreed) return;
    await api("/api/fleet/revoke", "POST", {node:data.revoke});
    toast("Relationship revoked");
    return poll();
  }
  if(data.copy) return void copyText(data.copy);
  if(data.invite) return inviteDialog(data.invite);
  if(data.status){ await api("/api/fleet/status", "POST", {node:data.status}); return; }
  if(data.update){
    const agreed = await confirmAction({title:"Run the package upgrade there?",
      body:'<p class="muted small">The node runs its own package manager as root, through the one ' +
        "command it is allowed to run. It can take several minutes and may restart services.</p>",
      confirmLabel:"Update"});
    if(!agreed) return;
    await api("/api/fleet/update", "POST", {node:data.update});
    toast("Update started — progress shows on the node's card");
    return;
  }
  if(data.scan){
    $("scan-from").value = data.scan; HOSTS = [];
    ROUTER.go("deploy");
    return runScan();
  }
  if(data.shell){
    $("shell-node").value = data.shell;
    ROUTER.go("shell");
    return openShell();
  }
});
// ---- an invitation minted by somebody else ---------------------------------
// The node that will honour the invitation is the one that mints it, so this is
// an ask, not a local action: it goes over the mesh, that node checks the
// `invite` right, and what comes back is a live single-use code.
//
// Shown once. The console holds it until the page collects it and then forgets
// it — a code re-served to every poll is a code sitting on the screen of
// whoever opens this page next.
const INVITE_WINDOWS = [["300", "5 minutes"], ["3600", "1 hour"],
                        ["21600", "6 hours"]];

function inviteDialog(id){
  const who = managedLabel(id);
  $("modal-title").textContent = "Invite somebody to " + who + "'s mesh";
  $("modal-body").innerHTML =
    '<p class="muted small">' + esc(who) + " mints it, not this node: whoever uses it " +
    "joins through that machine and has their certificate signed by it. It is single " +
    "use, and it stops working when the window closes.</p>" +
    '<label class="field"><span>Stays live for</span><select id="inv-ttl">' +
    INVITE_WINDOWS.map((pair) => '<option value="' + pair[0] + '">' + pair[1] +
      "</option>").join("") + "</select></label>" +
    '<label class="check"><input id="inv-ticket" type="checkbox" checked>' +
    "<span>Also make it scannable — needs a confirmed public address on that node, " +
    "and it is left out rather than refused when there is none</span></label>" +
    '<div class="btn-row"><button id="inv-go" class="primary">Create</button>' +
    '<button id="inv-no">Cancel</button></div>' +
    '<p id="inv-msg" class="msg"></p><div id="inv-out"></div>';
  $("modal").showModal();
  $("inv-no").addEventListener("click", () => $("modal").close());
  $("inv-go").addEventListener("click", (event) => withBusy(event.target, async () => {
    setMessage("inv-msg", "Asking " + who + "…");
    const {ok, data} = await apiJson("/api/fleet/invite", "POST",
      {node:id, ttl:parseInt($("inv-ttl").value, 10) || 300,
       ticket:$("inv-ticket").checked});
    if(!ok || data.error){
      setMessage("inv-msg", data.error || "That node refused.", true);
      return;
    }
    setMessage("inv-msg", "");
    $("inv-out").innerHTML = inviteHTML(data);
  }));
}

function inviteHTML(invite){
  const uris = (invite.uris || []).map((uri) =>
    '<div class="mono tiny truncate">' + esc(uri) + "</div>").join("");
  return '<div class="notice"><span>Shown once. Close this and it is gone from ' +
    "here — the invitation itself stays live until it is used or expires.</span></div>" +
    '<div class="copyable"><code class="mono">' + esc(invite.code) +
    '</code><button class="sm" data-copy="' + esc(invite.code) + '">Copy code</button></div>' +
    (invite.ticket ? '<div class="copyable"><code class="mono">' + esc(invite.ticket) +
      '</code><button class="sm" data-copy="' + esc(invite.ticket) +
      '">Copy ticket</button></div>' : "") +
    (invite.qr_svg ? '<div class="qr-holder">' + invite.qr_svg + "</div>" : "") +
    (uris ? '<p class="small muted">Reachable at</p>' + uris : "");
}

// The console's description of a node, in fleet's own sheet: the same view, so
// a machine looks the same whether it is being managed or being talked to. The
// fleet button is dropped — you are already here.
function nodeDialog(id){
  $("modal-title").textContent = "Node " + shortId(id);
  $("modal-body").innerHTML = '<div id="fleet-node-view"></div>';
  $("modal").showModal();
  return NODEVIEW.mount("fleet-node-view", id, {
    hide:["fleet"],
    onGone(){ $("modal").close(); poll(); },
  });
}
$("add-open").addEventListener("click", addDialog);
$("modal-close").addEventListener("click", () => $("modal").close());
$("scan-from").addEventListener("change", () => {
  HOSTS = []; PICKED = {}; SCAN_AT = scanStamp(); paintHosts(null);
});
$("scan-btn").addEventListener("click", runScan);
$("key-add").addEventListener("click", () => $("key-file").click());
$("key-file").addEventListener("change", (event) => {
  const file = event.target.files[0];
  event.target.value = "";
  uploadKey(file);
});
$("key-del").addEventListener("click", removeKey);
$("ssh-key").addEventListener("change", paintKeys);
$("ssh-sudo").addEventListener("change", syncSudoFields);
$("deploy-btn").addEventListener("click", deploy);
$("shell-open").addEventListener("click", openShell);
$("shell-kill").addEventListener("click", async () => {
  if(!SHELL.sid) return;
  await api("/api/fleet/close", "POST", {node:SHELL.node, sid:SHELL.sid});
  SHELL = {sid:null, node:null, off:0};
});
$("term-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const line = $("term-in").value;
  $("term-in").value = "";
  await sendBytes(line + "\n");
});
// Raw keystrokes: this is what makes it a terminal rather than a form. The pane
// is focusable, so a click puts the keyboard where the user is looking.
$("term").addEventListener("keydown", async (event) => {
  if(!SHELL.sid) return;
  if((event.ctrlKey || event.metaKey) && ["c", "v", "C", "V"].includes(event.key) &&
     window.getSelection().toString()) return;          // let copy/paste through
  const bytes = keyBytes(event);
  if(bytes === null) return;
  event.preventDefault();
  await sendBytes(bytes);
});
$("term").addEventListener("paste", async (event) => {
  if(!SHELL.sid) return;
  event.preventDefault();
  await sendBytes((event.clipboardData || window.clipboardData).getData("text"));
});

[["Nodes you control", "nodes"], ["Who controls this node", "access"],
 ["Discover & deploy", "deploy"], ["Shell", "shell"], ["Activity", "activity"],
].forEach(([label, section]) => PALETTE.add(label, "Go to", () => ROUTER.go(section)));
PALETTE.add("Request access to a node", "Action", addDialog);
PALETTE.add("Scan for machines", "Action", () => { ROUTER.go("deploy"); runScan(); });
PALETTE.add("Switch theme", "Action", () => THEME.toggle());
PALETTE.add("Back to the console", "Go to", () => { window.location = "/"; });
$("palette-open").addEventListener("click", () => PALETTE.open());
$("more-search").addEventListener("click", () => PALETTE.open());
$("notif-clear").addEventListener("click", () => markNotifRead());
$("notif-list").addEventListener("click", (event) => {
  const row = event.target.closest("[data-notif-tab]");
  if(row) ROUTER.go(row.dataset.notifTab);
});

// ---- auth and boot ---------------------------------------------------------
async function enter(token){
  const headers = {};
  if(token) headers.Authorization = "Bearer " + token;
  const response = await fetch("/api/fleet/state?since=0", {headers});
  if(!response.ok) return false;
  if(token) SESSION.set(token);
  $("login").classList.add("hidden");
  $("shell").classList.remove("hidden");
  mountShell();
  ROUTER.start(() => {});
  await poll();
  await loadKeys();
  if(POLL) clearInterval(POLL);
  POLL = setInterval(poll, 1500);
  return true;
}
$("login-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  setMessage("err", "");
  await withBusy(event.submitter || $("login-form").querySelector("button"), async () => {
    try{
      const response = await fetch("/api/login", {method:"POST",
        headers:{"Content-Type":"application/json"},
        body:JSON.stringify({password:$("password").value})});
      if(!response.ok){
        const data = await response.json().catch(() => ({}));
        setMessage("err", data.error || "Login failed", true);
        return;
      }
      $("password").value = "";
      await enter((await response.json()).token);
    }catch(_){ setMessage("err", "Console is not reachable", true); }
  });
});
(function boot(){
  let token = null;
  try{ token = sessionStorage.getItem("nmesh_token"); }catch(_){}
  enter(token).then((ok) => { if(!ok) $("login").classList.remove("hidden"); });
})();
"""
