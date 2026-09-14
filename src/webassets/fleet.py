"""
Fleet sub-page (/fleet).

Remote management: the nodes this one manages, the nodes that manage *it*,
deployment over SSH, an interactive shell, and the log of what happened. Served
by the console, behind the same session, under the same strict CSP.

Five sections, split along the question being asked: *whom do I control*
(Nodes), *who controls me* (Access), *bring a machine in* (Deploy), *do
something now* (Shell), *what happened* (Activity).
"""

from . import ui

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
<body data-app-name="NMesh Fleet"
      data-ctx-local="Fleet runs on this node — that one has a fleet of its own.">

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
      <button role="tab" data-tab="docker" data-label="Docker" aria-selected="false"><span class="lbl">Docker</span><span id="nav-docker" class="tail"></span></button>
      <button role="tab" data-tab="deploy" data-label="Deploy" aria-selected="false"><span class="lbl">Discover &amp; deploy</span></button>
      <button role="tab" data-tab="shell" data-label="Shell" aria-selected="false"><span class="lbl">Shell</span></button>
      <button role="tab" data-tab="logs" data-label="Logs" aria-selected="false"><span class="lbl">Logs</span><span id="nav-logs" class="tail"></span></button>
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
""" + ui.CTX_BAR + """
    <!-- ── Nodes we manage ──────────────────────────────────────────────── -->
    <section id="panel-nodes" class="content panel" role="tabpanel" data-panel="nodes">
      <div class="page-head">
        <div class="grow"><p class="eyebrow">Managed</p><h1>Nodes you control</h1>
          <p class="lede">Each of these accepted a request from this node, and granted exactly the
            capabilities shown. Nothing here was taken; all of it was given.</p></div>
        <div class="actions"><button id="group-new" class="ghost">New group</button>
          <button id="add-open" class="primary">Request access to a node</button></div>
      </div>
      <!-- Groups: this console's own names for sets of machines. They say
           nothing to any node in them — they are a way of pointing at several
           at once from here. -->
      <div id="groups" class="stack"></div>
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

    <!-- ── Docker ───────────────────────────────────────────────────────── -->
    <section id="panel-docker" class="content panel" role="tabpanel" data-panel="docker" hidden>
      <div class="page-head">
        <div class="grow"><p class="eyebrow">Containers</p><h1>Docker</h1>
          <p class="lede">What a node runs in containers, and the stacks on top of them —
            including the ones Portainer owns. The <code class="inline">docker</code> right is
            root on that machine: the socket is.</p></div>
        <div class="actions">
          <label class="field"><span class="sr-only">Node</span><select id="dk-node"></select></label>
          <button id="dk-refresh" class="primary">Refresh</button>
        </div>
      </div>
      <div id="dk-overview" class="stats"></div>
      <p id="dk-msg" class="msg"></p>

      <article class="card">
        <div class="card-head"><div class="grow"><h2>Stacks</h2>
          <div class="sub">A stack is a compose project. Ticking one adds it to what
            <b>Update</b> brings up on that node.</div></div>
          <button id="dk-stack-new" class="ghost sm">Deploy a stack</button></div>
        <div class="card-body tight"><div id="dk-stacks" class="stack"></div></div>
      </article>

      <article class="card">
        <div class="card-head"><div class="grow"><h2>Containers</h2>
          <div class="sub">Everything on that machine, in a stack or not</div></div>
          <button id="dk-container-new" class="ghost sm">Run a container</button></div>
        <div class="card-body tight"><div id="dk-containers" class="stack"></div></div>
      </article>

      <details class="card"><summary>Images</summary>
        <div class="card-body">
          <form id="dk-pull-form" class="toolbar">
            <label class="field grow"><span class="sr-only">Image</span>
              <input id="dk-pull" class="mono" placeholder="ghcr.io/owner/image:tag"
                     autocomplete="off" spellcheck="false"></label>
            <button type="submit" class="primary">Pull</button>
          </form>
          <div id="dk-images" class="stack"></div>
        </div>
      </details>

      <details class="card"><summary>Portainer</summary>
        <div class="card-body">
          <p class="muted small">A stack Portainer owns is updated <b>through</b> Portainer —
            running compose behind its back leaves its record stale and the next thing it does
            undoes the update. The token is written to that node's encrypted drawer and never
            read back over the mesh.</p>
          <div class="split">
            <div class="stack">
              <label class="field"><span>Address</span>
                <input id="pt-url" class="mono" placeholder="https://portainer.lan:9443"
                       autocomplete="off" spellcheck="false"></label>
              <label class="field"><span>Access token</span>
                <input id="pt-token" type="password" autocomplete="new-password"
                       placeholder="ptr_…"></label>
              <label class="field"><span>Certificate fingerprint (optional)</span>
                <input id="pt-fp" class="mono" placeholder="sha256, 64 hex characters"
                       autocomplete="off" spellcheck="false"></label>
              <div class="btn-row"><button id="pt-save" class="primary">Save</button>
                <button id="pt-forget" class="danger">Forget</button></div>
              <p id="pt-msg" class="msg"></p>
            </div>
            <div class="stack"><h3>Its stacks</h3>
              <div id="pt-stacks" class="stack"></div></div>
          </div>
        </div>
      </details>
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

          <label class="check"><input id="deploy-auto" type="checkbox" checked>
            <span>Keep them updated from the publishers this node accepts</span></label>
          <p class="muted small">The new machines pin the same release publishers as this node
            (and this node itself), and install their signed releases on their own. It is set
            here or nowhere: a headless box has nobody to paste a publisher key into a console,
            and would accept nothing from the mesh for ever.</p>

          <details class="card"><summary>Install options</summary>
            <div class="card-body stack">
              <p class="muted small">Every one of these is a switch
                <code class="inline">install.sh</code> already has. Chosen here because a machine
                installed from this page is a machine nobody is going to log into afterwards to
                change its mind.</p>
              <label class="check"><input id="dep-docker" type="checkbox">
                <span>Let the node manage that machine's <b>docker</b> — its account joins the
                  <code class="inline">docker</code> group</span></label>
              <p class="muted small">Off by default, and it is not a small tick: an account that
                can reach the docker socket can start a privileged container bind-mounting
                <code class="inline">/</code>. That is root on that machine. It is also what the
                <code class="inline">docker</code> capability needs in order to work at all.</p>
              <label class="check"><input id="dep-update" type="checkbox" checked>
                <span>Let it run its own system updates (one fixed root command)</span></label>
              <label class="check"><input id="dep-fleet" type="checkbox" checked>
                <span>Start the fleet app on it, so it can be managed and can deploy further</span></label>
              <div class="split">
                <label class="field"><span>Install directory</span>
                  <input id="dep-prefix" class="mono" placeholder="/opt/nmesh"
                         autocomplete="off" spellcheck="false"></label>
                <label class="field"><span>State directory</span>
                  <input id="dep-data" class="mono" placeholder="/var/lib/nmesh"
                         autocomplete="off" spellcheck="false"></label>
                <label class="field"><span>Service name</span>
                  <input id="dep-service" class="mono" placeholder="nmesh"
                         autocomplete="off" spellcheck="false"></label>
              </div>
            </div>
          </details>

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
          <button id="shell-full" class="ghost">Full screen</button>
          <button id="shell-kill" class="danger">Close</button>
        </div>
        <div class="card-body tight">
          <div id="term" class="term" tabindex="0" role="application"
               aria-label="Remote shell"></div>
          <form id="term-form" class="toolbar padded">
            <label class="field grow"><span class="sr-only">Send a whole line</span>
              <input id="term-in" class="mono" placeholder="…or type a whole line here and press Enter"
                     autocomplete="off" spellcheck="false"></label>
            <button type="submit" class="primary">Send</button>
          </form>
        </div>
      </article>
    </section>

    <!-- ── Logs ─────────────────────────────────────────────────────────── -->
    <section id="panel-logs" class="content panel" role="tabpanel" data-panel="logs" hidden>
      <div class="page-head">
        <div class="grow"><p class="eyebrow">What the machines said</p><h1>Logs</h1>
          <p class="lede">Lines collected from the machines this node manages —
            what happened on them while nobody was looking. Kept here, in memory,
            one bounded ring per machine.</p></div>
      </div>

      <article class="card">
        <div class="card-head"><div class="grow"><h2>Collection</h2>
          <div class="sub">What is followed, and how much of it is kept.</div></div></div>
        <div class="card-body">
          <div class="row wrap gap-4">
            <label class="field"><span>Default behaviour</span>
              <select id="logs-default-policy">
                <option value="always">Always follow</option>
                <option value="active">Only while a page is open on it</option>
                <option value="never">Never — ask when needed</option>
              </select></label>
            <label class="field"><span>Megabytes kept per machine</span>
              <input id="logs-default-size" type="number" min="0.1" step="0.5"></label>
            <span class="grow"></span>
            <button id="logs-forget" class="danger">Forget everything collected</button>
          </div>
          <div id="logs-collection" class="small muted"></div>
        </div>
      </article>

      <article class="card">
        <div class="card-head"><div class="grow"><h2>Lines <span id="logs-count" class="badge"></span></h2>
          <div class="sub">Newest first, by the time this node received them.</div></div></div>
        <div class="card-body">
          <div class="row wrap gap-4">
            <label class="field"><span>Machine</span>
              <select id="logs-node"><option value="">Every machine</option></select></label>
            <label class="field"><span>Level</span>
              <select id="logs-level">
                <option value="">Everything</option>
                <option value="debug">debug and above</option>
                <option value="info">info and above</option>
                <option value="warn">warnings and errors</option>
                <option value="error">errors only</option>
              </select></label>
            <label class="field"><span>Source</span>
              <input id="logs-source" type="search" placeholder="node, peers, app:…"></label>
            <label class="field"><span>Contains</span>
              <input id="logs-contains" type="search" placeholder="text or a field value"></label>
            <label class="field"><span>Since</span>
              <input id="logs-since" type="datetime-local"></label>
            <label class="field"><span>Until</span>
              <input id="logs-until" type="datetime-local"></label>
            <span class="grow"></span>
            <button id="logs-fetch">Ask this machine now</button>
          </div>
          <div id="logs-policy" class="small muted"></div>
          <div class="table-wrap"><table>
            <thead><tr><th>When</th><th>Machine</th><th>Level</th><th>Source</th>
              <th>Line</th></tr></thead>
            <tbody id="logs-rows"></tbody></table></div>
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

let VER = 0, ST = {};
let PICKED = {}, HOSTS = [], KEYS = [];
let SCAN_AT = null;              // when the selected node last reported a scan
let DEPLOY_RID = null;           // the remote deployment we are waiting on

SESSION.onLost = () => {
  REFRESH.stop();
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
// Whether what is on screen is still being confirmed. Said in the rail rather
// than by emptying the page: a list that went blank reads as "there is nothing",
// which is a different and much worse claim than "I have not heard lately".
function feedState(live){
  $("rail-dot").className = "dot " + (live ? "ok" : "warn");
  $("rail-text").textContent = live ? "Fleet" : "Not answering";
}
async function poll(){
  let data;
  // Through `FEED`, which merges what changed into what is held and hands back
  // nothing when an answer is unusable. Assigning the answer straight over `ST`
  // is what emptied this page: a 502 has a body too, and its body has no
  // machines in it.
  try{ data = await FEED.read("/api/fleet/state", {since: VER}); }
  catch(_){ data = null; }
  if(!data){
    feedState(false);
    return;                      // keep what is on screen: it was true a moment ago
  }
  feedState(true);
  const first = !ST.capabilities;
  ST = data;
  if(typeof data.log_seq === "number") VER = data.log_seq;
  $("me").textContent = shortId(data.me);
  $("me").title = data.me || "";
  if(first){
    // A machine installed from here has no operator in front of it and a
    // console password nobody typed: without `manage` and `passwordless`,
    // whoever deployed it cannot reach the console it just started.
    capBoxes($("deploy-caps"), ["status", "update", "manage", "passwordless"]);
  }
  paintInbox(); paintGroups(); paintNodes(); paintOperators(); paintPickers();
  paintDocker(); paintLog(); paintJobs(); paintLogNodes();
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
// Which groups a node is in, derived from the one membership list rather than
// stored a second time on the node — two places saying it is two chances for
// them to disagree.
function groupChips(nodeId){
  const names = groupsOf(nodeId);
  if(!names.length) return "";
  return '<div class="chips">' + names.map(
    (name) => '<span class="chip">' + esc(name) + "</span>").join("") + "</div>";
}
// What Update will also bring up there. Said on the card, because "Update" not
// saying which stacks it touches is the same button meaning two things.
function stacksLine(node){
  const stacks = node.update_stacks || [];
  if(!stacks.length) return "";
  return '<p class="small muted">Update also brings up ' +
    esc(stacks.join(", ")) + "</p>";
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
      groupChips(node.id) + stacksLine(node) +
      updateHTML(node.id) + statusHTML(node.status) +
      '<div class="btn-row">' +
      (can("status") ? '<button data-status="' + esc(node.id) + '">Refresh</button>' : "") +
      (can("invite") ? '<button data-invite="' + esc(node.id) + '">Invite</button>' : "") +
      (can("update") ? '<button data-update="' + esc(node.id) + '">Update</button>' : "") +
      (can("shell") ? '<button data-shell="' + esc(node.id) + '">Shell</button>' : "") +
      (can("scan") ? '<button data-scan="' + esc(node.id) + '">Scan LAN</button>' : "") +
      (can("docker") ? '<button data-docker="' + esc(node.id) + '">Docker</button>' : "") +
      '<button data-groups="' + esc(node.id) + '">Groups</button>' +
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
  const dockerAble = dockerNodes();
  fill($("dk-node"), dockerAble.map(
    (node) => [node.id, node.label || node.pseudo || shortId(node.id)]));
  if(!DK.node && dockerAble.length){ DK.node = dockerAble[0].id; $("dk-node").value = DK.node; }
  fill($("scan-from"), [[ST.me, "This node (local LAN)"]].concat(
    managed.filter((node) => (node.caps || []).includes("scan"))
           .map((node) => [node.id, node.label || node.pseudo || shortId(node.id)])));
}
// Rewritten only when the options actually differ. This runs on every poll, and
// replacing the options of a `<select>` closes it — so a dropdown opened to pick
// a node shut itself a second later, every second, on the page whose whole job
// is picking a node.
function fill(select, pairs){
  const keep = select.value;
  const html = pairs.map((pair) =>
    '<option value="' + esc(pair[0]) + '">' + esc(pair[1]) + "</option>").join("");
  if(select.innerHTML === html) return;
  select.innerHTML = html;
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
// ---- the logs of the machines we manage ------------------------------------
// Read from what this node has already collected, never from the network: a
// page scrolling a log must not become traffic towards forty machines. The one
// button that *does* ask is the one labelled as asking.
let LOGS = {lines:[], policies:{}, defaults:{}, status:{}};
let LOGS_TIMER = null;

function logsFilters(){
  const stamp = (id) => {
    const raw = $(id).value;
    if(!raw) return 0;
    const at = Date.parse(raw);
    return Number.isFinite(at) ? Math.floor(at / 1000) : 0;
  };
  return {node: $("logs-node").value, level: $("logs-level").value,
          source: $("logs-source").value.trim(),
          contains: $("logs-contains").value.trim(),
          since_time: stamp("logs-since"), until_time: stamp("logs-until")};
}
async function refreshLogs(){
  if(ROUTER.section !== "logs") return;
  const filters = logsFilters();
  const query = Object.entries(filters)
    .filter(([_k, value]) => value !== "" && value !== 0)
    .map(([key, value]) => key + "=" + encodeURIComponent(value)).join("&");
  try{
    LOGS = await apiJson("/api/fleet/logs" + (query ? "?" + query : ""));
  }catch(_){ return; }            // keep what is on screen; it was true a moment ago
  paintLogs();
}
function paintLogs(){
  const lines = LOGS.lines || [];
  $("logs-count").textContent = lines.length
    ? lines.length + " of " + (LOGS.matched || lines.length) : "";
  $("nav-logs").textContent = (LOGS.following || []).length || "";
  setHTML("logs-rows", lines.length ? lines.map(logRow).join("")
    : '<tr><td colspan="5">' + emptyHTML("Nothing collected yet",
        "Machines are followed by the rule above; one that is never followed " +
        "can still be asked.") + "</td></tr>");
  const held = LOGS.status || {};
  const nodes = Object.keys(held.nodes || {}).length;
  $("logs-collection").textContent =
    nodes ? nodes + " machine(s) held, " + fmtBytes(held.used_bytes || 0) +
            " compressed, " + (held.records || 0) + " line(s); following " +
            (LOGS.following || []).length
          : "Nothing is being kept yet.";
  const policy = LOGS.policies && LOGS.policies[$("logs-node").value];
  $("logs-policy").textContent = policy
    ? "This machine: " + policy.policy + ", " + policy.megabytes + " MB" +
      ((policy.own || []).length ? " (its own setting)" : " (the default)")
    : "";
  const defaults = LOGS.defaults || {};
  if(document.activeElement !== $("logs-default-policy") && defaults.policy)
    $("logs-default-policy").value = defaults.policy;
  if(document.activeElement !== $("logs-default-size") && defaults.megabytes)
    $("logs-default-size").value = defaults.megabytes;
}
function logRow(line){
  const fields = line.fields || {};
  const said = fields.said_at ? " · said " + esc(fmtTime(fields.said_at)) : "";
  const extra = Object.entries(fields)
    .filter(([key]) => key !== "said_at" && key !== "seq")
    .map(([key, value]) => key + "=" + value).join(" ");
  return "<tr><td class=\"mono small\" title=\"" + esc(fmtTime(line.at)) + said +
    "\">" + esc(fmtTime(line.at)) + "</td>" +
    "<td class=\"mono small\">" + esc(shortId(line.node || "")) + "</td>" +
    "<td>" + badge(esc(line.level), line.level === "error" ? "danger"
      : line.level === "warn" ? "warn" : "") + "</td>" +
    "<td class=\"mono small\">" + esc(line.source || "") + "</td>" +
    "<td>" + esc(line.message || "") +
    (extra ? ' <span class="muted small">' + esc(extra) + "</span>" : "") +
    "</td></tr>";
}
function paintLogNodes(){
  // The machines we manage, as a filter. Kept in step with the ledger rather
  // than with what has spoken: a machine that has said nothing is exactly the
  // one an operator goes looking for.
  fill($("logs-node"), [["", "Every machine"]].concat(
    (ST.managed || []).map((node) =>
      [node.id, node.label || node.pseudo || shortId(node.id)])));
}
// While the panel is open, on its own cadence. Reading a node's log is also
// what *keeps* an `active` follow alive on that machine, so a page left open
// is a page still receiving — which is the behaviour the policy promises.
setInterval(() => { if(ROUTER.section === "logs") refreshLogs(); }, 5000);
for(const id of ["logs-node", "logs-level", "logs-source", "logs-contains",
                 "logs-since", "logs-until"]){
  $(id).addEventListener("input", () => {
    clearTimeout(LOGS_TIMER);
    LOGS_TIMER = setTimeout(refreshLogs, 200);
  });
}
$("logs-default-policy").addEventListener("change", async () => {
  await apiJson("/api/fleet/logs-policy", "POST",
                {policy: $("logs-default-policy").value});
  refreshLogs();
});
$("logs-default-size").addEventListener("change", async () => {
  await apiJson("/api/fleet/logs-policy", "POST",
                {megabytes: Number($("logs-default-size").value) || 0});
  refreshLogs();
});
$("logs-fetch").addEventListener("click", async (event) => {
  const node = $("logs-node").value;
  if(!node){ toast("Choose a machine first", "warn"); return; }
  await withBusy(event.target, async () => {
    try{
      await apiJson("/api/fleet/logs-fetch", "POST", {node});
      toast("Asked " + shortId(node) + " for its log");
    }catch(_){ toast("That machine did not answer", "danger"); }
  });
  setTimeout(refreshLogs, 1200);
});
$("logs-forget").addEventListener("click", async (event) => {
  const agreed = await confirmAction({
    title: "Forget every collected log?",
    body: '<p class="muted small">The lines this node has collected from the ' +
      "machines it manages are dropped. Their own rings are untouched.</p>",
    confirmLabel: "Forget", danger: true});
  if(!agreed) return;
  await withBusy(event.target, async () => {
    await apiJson("/api/fleet/logs-forget", "POST", {});
    toast("Collected logs dropped");
  });
  refreshLogs();
});

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
  // Repainted while the menu is open, so it has to leave alone what has not
  // changed: these rows are buttons, and one replaced under a finger is a tap
  // that lands on nothing.
  setHTML("notif-list", list.length ? list.map((item) =>
    '<button class="item notif" data-notif-tab="' + esc(item.tab) + '" data-menu-close>' +
    '<i class="dot ' + esc(item.kind) + '"></i>' +
    '<span class="grow"><b class="truncate">' + esc(item.title) + "</b>" +
    '<span class="tiny muted">' + esc(item.detail) + "</span></span>" +
    (item.at ? '<span class="tiny muted flex-none">' + esc(fmtTime(item.at)) + "</span>" : "") +
    "</button>").join("")
    : '<div class="none">Nothing waiting. Jobs and access requests show up here.</div>');
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
  // A read that failed must not empty this: the rest of the page then offers
  // password-only deployment as though the node held no key at all, which is
  // a false statement about a machine's credentials.
  const data = await FEED.read("/api/fleet/keys").catch(() => null);
  if(data && Array.isArray(data.keys)) KEYS = data.keys;
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
    auto_update:$("deploy-auto").checked,
    // What the install itself should be. Blank means "whatever install.sh
    // would have chosen", which is the only sensible default for a path.
    options:{
      docker:$("dep-docker").checked,
      allow_update:$("dep-update").checked,
      install_dir:$("dep-prefix").value.trim(),
      data_dir:$("dep-data").value.trim(),
      service:$("dep-service").value.trim(),
      node_flags:$("dep-fleet").checked ? ["--fleet"] : [],
    },
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

// ---- groups ----------------------------------------------------------------
// This console's own names for sets of machines. A group says nothing to any
// node in it — it is a way of pointing at several at once from here, which is
// why the whole of it lives in our ledger and none of it travels.

function groupsOf(nodeId){
  return (ST.groups || []).filter((group) => (group.nodes || []).includes(nodeId))
                          .map((group) => group.name);
}
function paintGroups(){
  const groups = ST.groups || [];
  const managed = new Set((ST.managed || []).map((node) => node.id));
  setHTML("groups", groups.length ? '<div class="chips">' + groups.map((group) => {
    const live = (group.nodes || []).filter((id) => managed.has(id));
    return '<span class="chip"><b>' + esc(group.name) + "</b>" +
      '<span class="muted">' + plural(live.length, "node") + "</span>" +
      '<button class="sm" data-group-update="' + esc(group.name) + '"' +
      (live.length ? "" : " disabled") + ">Update group</button>" +
      '<button class="sm ghost" data-group-edit="' + esc(group.name) + '">Edit</button>' +
      "</span>";
  }).join("") + "</div>" : "");
}
function groupDialog(name){
  const existing = (ST.groups || []).find((group) => group.name === name);
  const members = new Set(existing ? existing.nodes || [] : []);
  $("modal-title").textContent = existing ? "Group " + name : "New group";
  $("modal-body").innerHTML =
    '<p class="muted small">A group is local to this console. Nothing is sent to the nodes in ' +
    "it, and being in one grants nobody anything.</p>" +
    '<label class="field"><span>Name</span><input id="gp-name" value="' +
    esc(name || "") + '" placeholder="production, homelab, edge…"></label>' +
    '<div class="field"><span>Nodes</span><div id="gp-nodes" class="cap-pick"></div></div>' +
    '<div class="btn-row"><button id="gp-ok" class="primary">Save</button>' +
    (existing ? '<button id="gp-del" class="danger">Delete group</button>' : "") +
    '<button id="gp-no">Cancel</button></div><p id="gp-msg" class="msg"></p>';
  $("gp-nodes").innerHTML = (ST.managed || []).map((node) =>
    '<label class="check card-like"><input type="checkbox" value="' + esc(node.id) + '"' +
    (members.has(node.id) ? " checked" : "") + "><span><b>" +
    esc(node.label || node.pseudo || shortId(node.id)) + "</b><br>" +
    esc(shortId(node.id)) + "</span></label>").join("")
    || emptyHTML("No node yet", "Ask a node to let you manage it first.");
  $("gp-ok").addEventListener("click", (event) => withBusy(event.target, async () => {
    const wanted = $("gp-name").value.trim();
    if(!wanted){ setMessage("gp-msg", "A group needs a name.", true); return; }
    const nodes = $$("#gp-nodes input:checked").map((box) => box.value);
    // Renaming is a delete and a create: the name *is* the key, so there is no
    // second identity to keep in step with it.
    if(existing && wanted !== name){
      await api("/api/fleet/groups", "POST", {op:"remove", group:name});
    }
    const {ok} = await apiJson("/api/fleet/groups", "POST",
                               {op:"set", group:wanted, nodes});
    if(!ok){ setMessage("gp-msg", "That group name was refused.", true); return; }
    $("modal").close(); toast("Group saved", "ok"); poll();
  }));
  if(existing){
    $("gp-del").addEventListener("click", (event) => withBusy(event.target, async () => {
      await api("/api/fleet/groups", "POST", {op:"remove", group:name});
      $("modal").close(); toast("Group deleted"); poll();
    }));
  }
  $("gp-no").addEventListener("click", () => $("modal").close());
  $("modal").showModal();
  $("gp-name").focus();
}
function nodeGroupsDialog(id){
  const held = new Set(groupsOf(id));
  $("modal-title").textContent = "Groups for " + shortId(id);
  $("modal-body").innerHTML =
    '<p class="muted small">A node can be in several. Ticking one here is the same edit as ' +
    "adding it from the group's own row — there is one membership list, not two.</p>" +
    '<div id="ng-list" class="cap-pick"></div>' +
    '<label class="field"><span>Or a new group</span><input id="ng-new" ' +
    'placeholder="name it"></label>' +
    '<div class="btn-row"><button id="ng-ok" class="primary">Apply</button>' +
    '<button id="ng-no">Cancel</button></div>';
  $("ng-list").innerHTML = (ST.groups || []).map((group) =>
    '<label class="check card-like"><input type="checkbox" value="' + esc(group.name) + '"' +
    (held.has(group.name) ? " checked" : "") + "><span><b>" + esc(group.name) +
    "</b><br>" + plural((group.nodes || []).length, "node") + "</span></label>").join("")
    || '<p class="muted small">No group yet — name one below.</p>';
  $("ng-ok").addEventListener("click", (event) => withBusy(event.target, async () => {
    const groups = $$("#ng-list input:checked").map((box) => box.value);
    const fresh = $("ng-new").value.trim();
    if(fresh && !groups.includes(fresh)) groups.push(fresh);
    await api("/api/fleet/groups", "POST", {op:"node", node:id, groups});
    $("modal").close(); toast("Groups updated", "ok"); poll();
  }));
  $("ng-no").addEventListener("click", () => $("modal").close());
  $("modal").showModal();
}

// ---- docker ----------------------------------------------------------------
// One node at a time, because everything here is about one machine. The reads
// are waited on by the console; the ones that pull images are started and
// watched through the job list, since a browser will not hold a request open
// for minutes and an operation that says nothing until it ends is one nobody
// can tell from a hang.

const DK = {node:"", overview:null, stacks:[], containers:[], images:[],
            portainer:[], busy:false};

function dockerNodes(){
  return (ST.managed || []).filter((node) => (node.caps || []).includes("docker"));
}
async function dockerCall(op, extra){
  if(!DK.node) throw new Error("pick a node first");
  const answer = await apiJson("/api/fleet/docker", "POST",
                               Object.assign({node:DK.node, op}, extra || {}));
  if(!answer.ok) throw new Error((answer.data && answer.data.error) || "that was refused");
  return answer.data;
}
async function dockerLoad(){
  if(!DK.node || DK.busy) return;
  DK.busy = true;
  setMessage("dk-msg", "Reading that machine…");
  try{
    const overview = await dockerCall("overview");
    const stacks = await dockerCall("stacks");
    const containers = await dockerCall("containers");
    DK.overview = overview.info || {};
    DK.stacks = stacks.items || [];
    DK.containers = containers.items || [];
    setMessage("dk-msg", "");
  }catch(error){
    DK.overview = null; DK.stacks = []; DK.containers = [];
    setMessage("dk-msg", String(error.message || error), true);
  }finally{ DK.busy = false; }
  paintDocker();
}
// Which stacks *Update* also brings up on that node. Read from the ledger, not
// from the checkbox: it is a choice this console remembers about a machine, and
// the node card's Update button reads the same one.
function dockerChosen(){
  const node = (ST.managed || []).find((entry) => entry.id === DK.node);
  return new Set((node && node.update_stacks) || []);
}
function stat(value, key, tone){
  return '<div class="stat' + (tone ? " " + tone : "") + '"><span class="v">' +
    esc(String(value)) + '</span><span class="k">' + esc(key) + "</span></div>";
}
function paintDockerOverview(){
  const info = DK.overview;
  if(!info){ setHTML("dk-overview", ""); return; }
  setHTML("dk-overview",
    stat(info.running + "/" + info.containers, "containers running", "accent") +
    stat(DK.stacks.length, "stacks") +
    stat(info.images || 0, "images") +
    stat(info.version || "—", "engine") +
    stat(info.compose ? "yes" : "no", "docker compose") +
    stat(info.portainer ? "configured" : "none", "portainer"));
}
function stackRow(stack){
  const chosen = dockerChosen().has(stack.name);
  const owner = stack.portainer_id ? "portainer" : (stack.files ? "compose" : "unmanaged");
  return '<div class="row wrap">' +
    '<label class="check" title="Include this stack in Update on that node">' +
    '<input type="checkbox" data-stack-pick="' + esc(stack.name) + '"' +
    (chosen ? " checked" : "") + '><span class="tiny">update</span></label>' +
    '<b class="grow truncate">' + esc(stack.name) + "</b>" +
    badge(stack.running + "/" + stack.total + " up",
          stack.running === stack.total ? "ok" : (stack.running ? "warn" : "")) +
    badge(owner, owner === "portainer" ? "accent" : "") +
    '<span class="btn-row">' +
    '<button class="sm" data-stack-act="start" data-stack="' + esc(stack.name) + '">Start</button>' +
    '<button class="sm" data-stack-act="stop" data-stack="' + esc(stack.name) + '">Stop</button>' +
    '<button class="sm" data-stack-act="restart" data-stack="' + esc(stack.name) + '">Restart</button>' +
    '<button class="sm primary" data-stack-act="update" data-stack="' + esc(stack.name) + '">Update</button>' +
    "</span></div>";
}
function containerRow(entry){
  const running = entry.state === "running";
  return '<div class="row wrap">' +
    '<b class="grow truncate">' + esc(entry.name || shortId(entry.id)) + "</b>" +
    '<span class="muted small truncate">' + esc(entry.image) + "</span>" +
    (entry.project ? badge(entry.project) : "") +
    badge(entry.state || "?", running ? "ok" : "warn") +
    (entry.ports.length ? '<span class="mono tiny muted">' +
      esc(entry.ports.join(" ")) + "</span>" : "") +
    '<span class="btn-row">' +
    '<button class="sm" data-ct-act="' + (running ? "stop" : "start") + '" data-ct="' +
      esc(entry.id) + '">' + (running ? "Stop" : "Start") + "</button>" +
    '<button class="sm" data-ct-act="restart" data-ct="' + esc(entry.id) + '">Restart</button>' +
    '<button class="sm ghost" data-ct-logs="' + esc(entry.id) + '">Logs</button>' +
    '<button class="sm danger" data-ct-act="remove" data-ct="' + esc(entry.id) + '">Remove</button>' +
    "</span></div>";
}
function portainerRow(stack){
  return '<div class="row wrap"><b class="grow truncate">' + esc(stack.name) + "</b>" +
    badge(stack.active ? "active" : "stopped", stack.active ? "ok" : "") +
    (stack.git ? badge("git") : "") +
    '<span class="btn-row">' +
    '<button class="sm" data-pt-act="' + (stack.active ? "stop" : "start") +
      '" data-pt="' + stack.id + '">' + (stack.active ? "Stop" : "Start") + "</button>" +
    '<button class="sm primary" data-pt-act="redeploy" data-pt="' + stack.id +
      '">Redeploy</button></span></div>';
}
function paintDocker(){
  $("nav-docker").textContent = dockerNodes().length || "";
  paintDockerOverview();
  // Nothing read yet is not the same as nothing there, and a panel that says
  // "no stack" before it has looked is a panel that lies once a second.
  const waiting = DK.overview === null;
  setHTML("dk-stacks", DK.stacks.map(stackRow).join("") ||
    (waiting ? emptyHTML("Not read yet", "Pick a node, then Refresh.")
             : emptyHTML("No stack here",
                 "A stack is a compose project. Deploy one, or run plain containers.")));
  setHTML("dk-containers", DK.containers.map(containerRow).join("") ||
    (waiting ? "" : emptyHTML("Nothing is running", "No container on that machine.")));
  setHTML("dk-images", DK.images.map((image) =>
    '<div class="row"><b class="grow truncate mono">' +
    esc((image.tags[0] || image.id).slice(0, 80)) + "</b>" +
    '<span class="muted small">' + fmtBytes(image.size) + "</span></div>").join("") ||
    '<p class="muted small">Nothing read yet.</p>');
  setHTML("pt-stacks", DK.portainer.map(portainerRow).join("") ||
    '<p class="muted small">Nothing read from Portainer yet.</p>');
}

// A long job — a pull, a deploy, a stack coming up — is started and then
// watched in the job list. Reporting only at the end is indistinguishable from
// a hang, and this is minutes of somebody else's machine.
async function dockerJob(label, op, extra){
  let answer;
  try{ answer = await dockerCall(op, extra); }
  catch(error){ toast(String(error.message || error), "danger"); return; }
  if(!answer.rid){ toast(label + " done", "ok"); await dockerLoad(); return; }
  toast(label + " started — it shows in Activity");
  const rid = answer.rid;
  for(let tries = 0; tries < 600; tries++){
    await new Promise((resolve) => setTimeout(resolve, 2000));
    const job = (ST.jobs || []).find((entry) => entry.rid === rid);
    if(job && job.state !== "running"){
      toast(label + (job.state === "ok" ? " done" : " failed: " + (job.detail || "")),
            job.state === "ok" ? "ok" : "danger");
      break;
    }
  }
  await dockerLoad();
}

async function dockerLogs(id){
  $("modal-title").textContent = "Logs";
  $("modal-body").innerHTML = '<pre class="term" id="dk-log">Reading…</pre>';
  $("modal").showModal();
  try{
    const answer = await dockerCall("logs", {id, tail:400});
    // Written as text, never as markup: these are bytes a container chose.
    $("dk-log").textContent = answer.text || "(nothing)";
  }catch(error){ $("dk-log").textContent = String(error.message || error); }
}

function runDialog(){
  $("modal-title").textContent = "Run a container";
  $("modal-body").innerHTML =
    '<p class="muted small">Built field by field on the far side — a container body passed ' +
    "through whole would be every field that node does not know about.</p>" +
    '<label class="field"><span>Name</span><input id="rn-name" class="mono" ' +
    'placeholder="my-service" autocomplete="off" spellcheck="false"></label>' +
    '<label class="field"><span>Image</span><input id="rn-image" class="mono" ' +
    'placeholder="ghcr.io/owner/image:tag" autocomplete="off" spellcheck="false"></label>' +
    '<label class="field"><span>Ports (host:container, one per line)</span>' +
    '<textarea id="rn-ports" class="mono" rows="2" placeholder="8080:80"></textarea></label>' +
    '<label class="field"><span>Volumes (host:container[:ro], one per line)</span>' +
    '<textarea id="rn-vols" class="mono" rows="2" placeholder="/srv/data:/data"></textarea></label>' +
    '<label class="field"><span>Environment (KEY=value, one per line)</span>' +
    '<textarea id="rn-env" class="mono" rows="3" placeholder="TZ=Europe/Paris"></textarea></label>' +
    '<label class="field"><span>Restart policy</span><select id="rn-restart">' +
    '<option value="unless-stopped">unless-stopped</option><option value="always">always</option>' +
    '<option value="on-failure">on-failure</option><option value="no">no</option></select></label>' +
    '<div class="btn-row"><button id="rn-go" class="primary">Run</button>' +
    '<button id="rn-no">Cancel</button></div><p id="rn-msg" class="msg"></p>';
  $("rn-go").addEventListener("click", (event) => withBusy(event.target, async () => {
    const image = $("rn-image").value.trim();
    if(!image){ setMessage("rn-msg", "An image is required.", true); return; }
    const lines = (id) => $(id).value.split("\n").map((line) => line.trim()).filter(Boolean);
    const ports = lines("rn-ports").map((line) => {
      const [host, container, proto] = line.split(":");
      return {host:parseInt(host, 10), container:parseInt(container, 10),
              proto:proto === "udp" ? "udp" : "tcp"};
    });
    const volumes = lines("rn-vols").map((line) => {
      const parts = line.split(":");
      return {host:parts[0], container:parts[1], ro:parts[2] === "ro"};
    });
    const env = {};
    lines("rn-env").forEach((line) => {
      const at = line.indexOf("=");
      if(at > 0) env[line.slice(0, at)] = line.slice(at + 1);
    });
    $("modal").close();
    await dockerJob("Container", "deploy", {spec:{
      name:$("rn-name").value.trim(), image, ports, volumes, env,
      restart:$("rn-restart").value}});
  }));
  $("rn-no").addEventListener("click", () => $("modal").close());
  $("modal").showModal();
  $("rn-name").focus();
}

function stackDialog(){
  const viaPortainer = !!(DK.overview && DK.overview.portainer);
  $("modal-title").textContent = "Deploy a stack";
  $("modal-body").innerHTML =
    '<p class="muted small">A compose file, kept on that machine under this node\'s own state ' +
    "so a redeploy later finds it where compose recorded it.</p>" +
    '<label class="field"><span>Name</span><input id="sk-name" class="mono" ' +
    'placeholder="my-stack" autocomplete="off" spellcheck="false"></label>' +
    (viaPortainer ? '<label class="check"><input id="sk-pt" type="checkbox">' +
      "<span>Deploy through Portainer, so it owns and can redeploy it</span></label>" +
      '<label class="field"><span>Portainer environment id</span>' +
      '<input id="sk-endpoint" class="mono" value="1"></label>' : "") +
    '<label class="field"><span>docker-compose.yml</span>' +
    '<textarea id="sk-body" class="mono" rows="12" spellcheck="false" ' +
    'placeholder="services:&#10;  web:&#10;    image: nginx:alpine"></textarea></label>' +
    '<div class="btn-row"><button id="sk-go" class="primary">Deploy</button>' +
    '<button id="sk-no">Cancel</button></div><p id="sk-msg" class="msg"></p>';
  $("sk-go").addEventListener("click", (event) => withBusy(event.target, async () => {
    const name = $("sk-name").value.trim();
    const compose = $("sk-body").value;
    if(!name || !compose.trim()){
      setMessage("sk-msg", "A name and a compose file are required.", true); return;
    }
    const through = viaPortainer && $("sk-pt").checked;
    $("modal").close();
    await dockerJob("Stack " + name,
                    through ? "portainer_deploy" : "deploy_stack",
                    through ? {stack:name, compose,
                               endpoint:parseInt($("sk-endpoint").value, 10) || 1}
                            : {stack:name, compose});
  }));
  $("sk-no").addEventListener("click", () => $("modal").close());
  $("modal").showModal();
  $("sk-name").focus();
}

// ---- shell -----------------------------------------------------------------
// The emulator, the session driver and the key mapping are shared with the
// full-screen page (`webassets/terminal.py`): one terminal, drawn in two
// places. What is here is this panel's wiring and nothing else.
let TERM_SESSION = null;

async function openShell(){
  const node = $("shell-node").value;
  if(!TERM_SESSION) TERM_SESSION = new ShellSession($("term"), {});
  if(!node){ TERM_SESSION.say("No node has granted you a shell."); return; }
  if(await TERM_SESSION.open(node)) $("term").focus();
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
    const node = (ST.managed || []).find((entry) => entry.id === data.update);
    const stacks = (node && node.update_stacks) || [];
    const agreed = await confirmAction({title:"Bring that machine up to date?",
      body:'<p class="muted small">The node runs its own package manager as root, through the one ' +
        "command it is allowed to run. It can take several minutes and may restart services.</p>" +
        (stacks.length ? '<p class="muted small">It will also bring up ' +
          esc(stacks.join(", ")) + " — pulled and recreated, through Portainer where " +
          "Portainer owns the stack.</p>" : ""),
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
  if(data.docker){
    DK.node = data.docker;
    $("dk-node").value = data.docker;
    ROUTER.go("docker");
    return dockerLoad();
  }
  if(data.groups) return nodeGroupsDialog(data.groups);
  if(data.groupEdit) return groupDialog(data.groupEdit);
  if(data.groupUpdate){
    const group = (ST.groups || []).find((entry) => entry.name === data.groupUpdate);
    const count = group ? (group.nodes || []).length : 0;
    const agreed = await confirmAction({title:"Update " + plural(count, "node") + "?",
      body:'<p class="muted small">Each one runs its own package manager, and brings up the ' +
        "docker stacks chosen for it. It takes minutes and may restart services.</p>",
      confirmLabel:"Update group"});
    if(!agreed) return;
    const answer = await apiJson("/api/fleet/update-group", "POST",
                                 {group:data.groupUpdate});
    const started = (answer.data && answer.data.started) || [];
    toast("Update started on " + plural(started.length, "node"),
          started.length ? "ok" : "warn");
    return poll();
  }
  if(data.stackAct){
    const name = data.stack;
    if(data.stackAct === "update"){
      return dockerJob("Stack " + name, "stack", {stack:name, action:"update"});
    }
    return withBusy(button, async () => {
      try{
        await dockerCall("stack", {stack:name, action:data.stackAct});
        toast("Stack " + name + " " + data.stackAct + "ed", "ok");
      }catch(error){ toast(String(error.message || error), "danger"); }
      await dockerLoad();
    });
  }
  if(data.ctLogs) return dockerLogs(data.ctLogs);
  if(data.ctAct){
    if(data.ctAct === "remove"){
      const agreed = await confirmAction({title:"Remove this container?",
        body:'<p class="muted small">It is stopped and deleted. Anything it wrote outside a ' +
          "volume goes with it.</p>", confirmLabel:"Remove", danger:true});
      if(!agreed) return;
    }
    return withBusy(button, async () => {
      try{
        await dockerCall("act", {id:data.ct, action:data.ctAct});
      }catch(error){ toast(String(error.message || error), "danger"); }
      await dockerLoad();
    });
  }
  if(data.ptAct){
    if(data.ptAct === "redeploy"){
      return dockerJob("Portainer redeploy", "portainer_stack",
                       {id:parseInt(data.pt, 10), action:"redeploy"});
    }
    return withBusy(button, async () => {
      try{
        await dockerCall("portainer_stack",
                         {id:parseInt(data.pt, 10), action:data.ptAct});
        DK.portainer = (await dockerCall("portainer_stacks")).items || [];
        paintDocker();
      }catch(error){ toast(String(error.message || error), "danger"); }
    });
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
    '<div class="btn-row"><button id="inv-go" class="primary">Create</button>' +
    '<button id="inv-no">Cancel</button></div>' +
    '<p id="inv-msg" class="msg"></p><div id="inv-out"></div>';
  $("modal").showModal();
  $("inv-no").addEventListener("click", () => $("modal").close());
  $("inv-go").addEventListener("click", (event) => withBusy(event.target, async () => {
    setMessage("inv-msg", "Asking " + who + "…");
    // Always scannable when that node can manage it: one invitation carries
    // both routes in, and a node with neither answers with the code alone
    // rather than refusing.
    const {ok, data} = await apiJson("/api/fleet/invite", "POST",
      {node:id, ttl:parseInt($("inv-ttl").value, 10) || 300, ticket:true});
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
      '">Copy invitation</button></div>' : "") +
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
    local:true,
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
// ---- docker & groups wiring -------------------------------------------------

$("group-new").addEventListener("click", () => groupDialog(""));
$("dk-node").addEventListener("change", () => {
  DK.node = $("dk-node").value;
  DK.images = []; DK.portainer = [];
  dockerLoad();
});
$("dk-refresh").addEventListener("click", (event) => withBusy(event.target, async () => {
  await dockerLoad();
  // The two lists nothing else needs: read on demand rather than on every
  // refresh of the panel.
  try{ DK.images = (await dockerCall("images")).items || []; }catch(_){ DK.images = []; }
  if(DK.overview && DK.overview.portainer){
    try{ DK.portainer = (await dockerCall("portainer_stacks")).items || []; }
    catch(_){ DK.portainer = []; }
  }
  paintDocker();
}));
// Read when the panel is opened, not on every poll: this is a round trip to
// somebody else's machine, and a tab nobody is looking at should cost nothing.
ROUTER.onChange = (section) => {
  if(section === "docker" && DK.node && DK.overview === null) dockerLoad();
  if(section === "logs") refreshLogs();
};
$("dk-stack-new").addEventListener("click", () => stackDialog());
$("dk-container-new").addEventListener("click", () => runDialog());
$("dk-pull-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const image = $("dk-pull").value.trim();
  if(!image) return;
  $("dk-pull").value = "";
  await dockerJob("Pull of " + image, "pull", {image});
});
$("pt-save").addEventListener("click", (event) => withBusy(event.target, async () => {
  const url = $("pt-url").value.trim();
  const token = $("pt-token").value;
  if(!url || !token){
    setMessage("pt-msg", "An address and a token are required.", true); return;
  }
  try{
    const answer = await dockerCall("portainer",
      {url, token, fingerprint:$("pt-fp").value.trim()});
    // Never echoed back: the field is cleared here because the token now lives
    // in that node's drawer and nothing reads it out again.
    $("pt-token").value = "";
    const items = answer.items || [];
    setMessage("pt-msg", "Saved" + (answer.info && answer.info.pinned ? ", pinned" : "") +
      " — " + plural(items.length, "environment") + " visible.");
    DK.portainer = (await dockerCall("portainer_stacks")).items || [];
    paintDocker();
  }catch(error){ setMessage("pt-msg", String(error.message || error), true); }
}));
$("pt-forget").addEventListener("click", (event) => withBusy(event.target, async () => {
  const agreed = await confirmAction({title:"Forget that Portainer?",
    body:'<p class="muted small">The address and token are deleted from that node\'s drawer. ' +
      "Its stacks keep running; this console just stops being able to redeploy them.</p>",
    confirmLabel:"Forget", danger:true});
  if(!agreed) return;
  try{
    await dockerCall("portainer", {clear:true});
    DK.portainer = [];
    setMessage("pt-msg", "Forgotten.");
    await dockerLoad();
  }catch(error){ setMessage("pt-msg", String(error.message || error), true); }
}));
// The tick that decides what Update also brings up. Written the moment it
// changes, because a preference that needs a second button to save it is one
// that is routinely lost.
$("dk-stacks").addEventListener("change", async (event) => {
  const box = event.target.closest("[data-stack-pick]");
  if(!box) return;
  const chosen = $$("#dk-stacks [data-stack-pick]")
    .filter((entry) => entry.checked).map((entry) => entry.dataset.stackPick);
  await api("/api/fleet/stacks", "POST", {node:DK.node, stacks:chosen});
  poll();
});

$("ssh-sudo").addEventListener("change", syncSudoFields);
$("deploy-btn").addEventListener("click", deploy);
$("shell-open").addEventListener("click", openShell);
$("shell-full").addEventListener("click", () => {
  // A tab, never a window: this button exists because a terminal in a panel is
  // a terminal in a box, and a 700px pop-up is the same box with a title bar.
  const node = $("shell-node").value;
  window.open("/term" + (node ? "?node=" + encodeURIComponent(node) : ""),
              "_blank", "noopener");
});
$("shell-kill").addEventListener("click", async () => {
  if(TERM_SESSION) await TERM_SESSION.stop();
});
$("term-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const line = $("term-in").value;
  $("term-in").value = "";
  if(TERM_SESSION) await TERM_SESSION.send(line + "\n");
});
// Raw keystrokes: this is what makes it a terminal rather than a form. The pane
// is focusable, so a click puts the keyboard where the user is looking.
$("term").addEventListener("keydown", async (event) => {
  if(!TERM_SESSION || !TERM_SESSION.live()) return;
  // Copy and paste are the browser's while something is selected on the screen.
  if((event.ctrlKey || event.metaKey) && ["c", "v", "C", "V"].includes(event.key) &&
     TERM_SESSION.screen.selected()) return;
  // Shift with a page key scrolls the scrollback rather than reaching the pty —
  // the convention every terminal uses, and the only way back up now that the
  // screen is drawn rather than laid out.
  if(event.shiftKey && (event.key === "PageUp" || event.key === "PageDown")){
    if(TERM_SESSION.screen.scrollBy(
        (event.key === "PageUp" ? -1 : 1) * (TERM_SESSION.screen.rows - 1))){
      TERM_SESSION.paint(true);
    }
    event.preventDefault();
    return;
  }
  const bytes = keyBytes(event, TERM_SESSION.term);
  if(bytes === null) return;
  event.preventDefault();
  await TERM_SESSION.send(bytes);
});
$("term").addEventListener("paste", async (event) => {
  if(!TERM_SESSION || !TERM_SESSION.live()) return;
  event.preventDefault();
  await TERM_SESSION.paste((event.clipboardData || window.clipboardData).getData("text"));
});
// The pointer, the wheel and the selection belong to the session: it owns the
// screen they act on, and there is no text in the DOM for a browser to select.
$("term").addEventListener("copy", (event) => {
  if(!TERM_SESSION) return;
  const picked = TERM_SESSION.screen.selected();
  if(!picked) return;
  event.preventDefault();
  event.clipboardData.setData("text/plain", picked);
});
// The panel changes size without the window moving — a tab switch, a rail
// folding away — and a pty told the old size draws every box to the wrong
// place. So the element is watched, not the window.
if(window.ResizeObserver){
  new ResizeObserver(debounce(() => {
    if(TERM_SESSION) TERM_SESSION.fit();
  }, 150)).observe($("term"));
}

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
  CONTEXT.confirm();
  ROUTER.start(() => {});
  await poll();
  await loadKeys();
  // The interval in the top bar drives this page too. It used to be markup with
  // nothing behind it while the page polled at a rate of its own — a control
  // that does nothing is worse than no control.
  REFRESH.mount(poll);
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
