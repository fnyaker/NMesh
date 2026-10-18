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
<script src="/i18n.js"></script>
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<link rel="stylesheet" href="/fleet.css">
</head>
<body data-app-name="NMesh Fleet"
      data-ctx-needs="full"
      data-ctx-local="Fleet runs on this node — reaching that one's fleet needs its full grant.">

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
      <div id="passwords" class="stack"></div>
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
          <p class="lede">The stacks and containers of one machine, found from what it runs —
            whether compose or Portainer deployed them — and brought up to date the way
            their owner would.</p></div>
        <div class="actions">
          <label class="field"><span class="sr-only">Machine</span><select id="dk-node"></select></label>
          <button id="dk-refresh" class="ghost">Refresh</button>
        </div>
      </div>
      <div id="dk-summary"></div>

      <nav id="dk-tabs" class="subnav" role="tablist" aria-label="Docker views">
        <button role="tab" data-subtab="stacks" aria-selected="true">Stacks <span id="dk-n-stacks" class="tail"></span></button>
        <button role="tab" data-subtab="containers" aria-selected="false">Containers <span id="dk-n-containers" class="tail"></span></button>
        <button role="tab" data-subtab="images" aria-selected="false">Images</button>
        <button role="tab" data-subtab="storage" aria-selected="false">Volumes &amp; networks</button>
        <button role="tab" data-subtab="portainer" aria-selected="false">Portainer <span id="dk-n-portainer" class="tail"></span></button>
      </nav>

      <div data-sub="stacks" class="stack">
        <div class="toolbar">
          <label class="search"><span class="sr-only">Filter stacks</span>
            <input id="dk-stack-filter" type="search" placeholder="Filter stacks" autocomplete="off"></label>
          <span id="dk-checked" class="muted small grow"></span>
          <button id="dk-check" class="ghost">Check for updates</button>
          <button id="dk-update-all" class="primary" hidden>Update all</button>
          <button id="dk-stack-new" class="ghost">Deploy a stack</button>
        </div>
        <div id="dk-stacks" class="stack"></div>
      </div>

      <div data-sub="containers" class="stack" hidden>
        <div class="toolbar">
          <label class="search"><span class="sr-only">Filter containers</span>
            <input id="dk-ct-filter" type="search" placeholder="Filter containers" autocomplete="off"></label>
          <div class="segmented" role="group" aria-label="Which containers">
            <button data-dk-scope="all" aria-selected="true">All</button>
            <button data-dk-scope="loose" aria-selected="false">Outside a stack</button>
          </div>
          <span class="grow"></span>
          <button id="dk-container-new" class="ghost">Run a container</button>
        </div>
        <article class="card"><div class="card-body tight"><div id="dk-containers"></div></div></article>
      </div>

      <div data-sub="images" class="stack" hidden>
        <form id="dk-pull-form" class="toolbar">
          <label class="field grow"><span class="sr-only">Image</span>
            <input id="dk-pull" class="mono" placeholder="ghcr.io/owner/image:tag"
                   autocomplete="off" spellcheck="false"></label>
          <button type="submit" class="primary">Pull</button>
        </form>
        <article class="card"><div class="card-body tight"><div id="dk-images"></div></div></article>
      </div>

      <div data-sub="storage" class="stack" hidden>
        <article class="card"><div class="card-head"><div class="grow"><h2>Volumes</h2></div></div>
          <div class="card-body tight"><div id="dk-volumes"></div></div></article>
        <article class="card"><div class="card-head"><div class="grow"><h2>Networks</h2></div></div>
          <div class="card-body tight"><div id="dk-networks"></div></div></article>
      </div>

      <div data-sub="portainer" class="stack" hidden>
        <div id="dk-portainer" class="stack"></div>
      </div>
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
              <label class="check"><input id="dep-docker" type="checkbox" checked>
                <span>Let the node manage that machine's <b>docker</b> — its account joins the
                  <code class="inline">docker</code> group</span></label>
              <p class="muted small">On by default for a system install of a machine that has
                docker, like <code class="inline">install.sh</code> run with sudo. It is not a small
                tick: an account that can reach the docker socket can start a privileged container
                bind-mounting <code class="inline">/</code> — that is root on that machine. Untick it
                and the machine is told no, and remembers it across upgrades.</p>
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

/* Docker. A stack is a card whose title carries who owns it and where it
   stands; the counts on the sub-tabs are plain numbers, hidden while empty. */
#panel-docker .card-head h2.row{gap:var(--s-2);font-size:var(--fs-md)}
#panel-docker .card-head h2 .badge{font-weight:500}
#dk-tabs .tail{color:var(--text-faint);font-size:var(--fs-xs);margin-left:var(--s-1)}
#dk-tabs .tail:empty{display:none}
#panel-docker td .badge{white-space:nowrap}
#panel-docker td.mono{overflow-wrap:anywhere;min-width:12ch}
#panel-docker .flush{margin:0}
#panel-docker progress.meter{flex:1 1 auto;max-width:240px}
#panel-docker .fp{overflow-wrap:anywhere}
#panel-docker .notice .btn-row,#panel-docker .notice button{flex:none}
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
    // A machine installed from here has nobody in front of it to grant
    // anything later, and whoever deploys it already has root on it.
    capBoxes($("deploy-caps"), ["full"]);
  }
  paintInbox(); paintPasswords(); paintGroups(); paintNodes(); paintOperators(); paintPickers();
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
// A machine provisioned from here sent the console password it generated. The
// list says which ones did; the password itself is fetched on a click and the
// console forgets it as it answers.
function paintPasswords(){
  const list = ST.passwords || [];
  setHTML("passwords", list.map((entry) =>
    '<article class="card"><div class="card-head"><div class="grow">' +
    "<h2>Console password waiting</h2>" +
    '<div class="sub mono">' + esc(entry.label || entry.host || shortId(entry.node)) +
    " · " + esc(shortId(entry.node)) + "</div></div>" + badge("once", "warn") + "</div>" +
    '<div class="card-body"><p class="small muted">This machine was installed from here and ' +
    "generated its console password. It can be shown once: after that, only the machine " +
    "has it.</p>" +
    '<div class="btn-row"><button class="primary" data-reveal-password="' + esc(entry.node) +
    '">Show it</button></div></div></article>').join(""));
}
async function passwordDialog(id){
  const {ok, data} = await apiJson("/api/fleet/password", "POST", {node:id});
  if(!ok || data.error){
    toast(data.error || "That password is no longer here.", "danger");
    return poll();
  }
  $("modal-title").textContent = "Console of " + (data.label || data.host || shortId(id));
  $("modal-body").innerHTML =
    '<div class="notice"><span>Shown once. Close this and it is gone from this console; ' +
    "change it from that machine's Settings if it was seen by anybody else.</span></div>" +
    '<div class="copyable"><code class="mono">' + esc(data.password) +
    '</code><button class="sm" data-copy="' + esc(data.password) + '">Copy password</button></div>';
  $("modal").showModal();
  poll();
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
      groupChips(node.id) + stacksLine(node) + logsLine(node) +
      updateHTML(node.id) + statusHTML(node.status) +
      '<div class="btn-row">' +
      (can("status") ? '<button data-status="' + esc(node.id) + '">Refresh</button>' : "") +
      (can("invite") ? '<button data-invite="' + esc(node.id) + '">Invite</button>' : "") +
      (can("update") ? '<button data-update="' + esc(node.id) + '">Update</button>' : "") +
      (can("shell") ? '<button data-shell="' + esc(node.id) + '">Shell</button>' : "") +
      (can("scan") ? '<button data-scan="' + esc(node.id) + '">Scan LAN</button>' : "") +
      (can("docker") ? '<button data-docker="' + esc(node.id) + '">Docker</button>' : "") +
      (can("logs") ? '<button data-logs="' + esc(node.id) + '">Logs</button>' : "") +
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
// What this node does about that machine's log, said on the machine's own card
// rather than only in a settings page: the decision is about *this* machine,
// and an operator reading its card is where they make it.
function logsLine(node){
  if(!(node.caps || []).includes("logs")) return "";
  const policy = (LOGS.policies || {})[node.id] || LOGS.defaults || {};
  const held = ((LOGS.status || {}).nodes || {})[node.id];
  const words = {always: "always collected",
                 active: "collected while its page is open",
                 never: "not collected"};
  return '<div class="row wrap small muted"><span>Log: ' +
    esc(words[policy.policy] || "") +
    ((policy.own || []).length ? "" : " (the default)") +
    (held ? " · " + esc(held.records) + " line(s) here" : "") + "</span>" +
    '<select class="sm" data-log-policy="' + esc(node.id) + '">' +
    ["always", "active", "never"].map((name) =>
      '<option value="' + name + '"' +
      (policy.policy === name ? " selected" : "") + ">" +
      esc(words[name]) + "</option>").join("") + "</select></div>";
}
document.addEventListener("change", async (event) => {
  const picker = event.target.closest("[data-log-policy]");
  if(!picker) return;
  const node = picker.dataset.logPolicy;
  try{
    const {ok} = await apiJson("/api/fleet/logs-policy", "POST",
                               {node, policy: picker.value});
    if(ok) toast("Log collection for " + shortId(node) + ": " + picker.value);
    else toast("That could not be changed", "danger");
  }catch(_){ toast("That could not be changed", "danger"); }
  refreshLogs(true);
});

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
// `apiJson` answers `{ok, status, data}`, and this assigned that envelope as
// though it were the answer: `lines`, `policies` and `status` were never there,
// so the panel said "Nothing collected yet" over a node holding thousands of
// lines, and the per-machine lines on the cards never knew a policy. Read the
// body, and only a body that is one — an error keeps what is on screen.
async function refreshLogs(force){
  if(ROUTER.section !== "logs" && !force) return;
  const filters = logsFilters();
  const query = Object.entries(filters)
    .filter(([_k, value]) => value !== "" && value !== 0)
    .map(([key, value]) => key + "=" + encodeURIComponent(value)).join("&");
  try{
    const {ok, data} = await apiJson("/api/fleet/logs" + (query ? "?" + query : ""));
    if(!ok || !data || !Array.isArray(data.lines)) return;
    LOGS = data;
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
            " in memory, " + (held.records || 0) + " line(s); following " +
            (LOGS.following || []).length
          : "Nothing is being kept yet.";
  const chosen = $("logs-node").value;
  const policy = LOGS.policies && LOGS.policies[chosen];
  const problems = held.problems || {};
  const refusing = Object.keys(problems);
  $("logs-policy").textContent = policy
    ? "This machine: " + policy.policy + ", " + policy.megabytes + " MB" +
      ((policy.own || []).length ? " (its own setting)" : " (the default)") +
      (problems[chosen] ? " — it sends nothing: " + problems[chosen] : "")
    : refusing.length
      ? refusing.length + " machine(s) followed but sending nothing: " +
        refusing.map((id) => shortId(id) + " (" + problems[id] + ")").join(", ")
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
// While the panel is open and the tab is on screen, every two seconds: it reads
// what this node already holds, so it costs no traffic towards the machines.
// Reading a node's log is also what *keeps* an `active` follow alive on that
// machine, so a page left open is a page still receiving — which is the
// behaviour the policy promises.
setInterval(() => {
  if(ROUTER.section === "logs" && !document.hidden) refreshLogs();
}, 2000);
for(const id of ["logs-node", "logs-level", "logs-source", "logs-contains",
                 "logs-since", "logs-until"]){
  $(id).addEventListener("input", () => {
    clearTimeout(LOGS_TIMER);
    LOGS_TIMER = setTimeout(refreshLogs, 200);
  });
}
$("logs-default-policy").addEventListener("change", async () => {
  try{
    const {ok} = await apiJson("/api/fleet/logs-policy", "POST",
                               {policy: $("logs-default-policy").value});
    if(!ok) toast("The default could not be changed", "danger");
  }catch(_){ toast("The default could not be changed", "danger"); }
  refreshLogs();
});
$("logs-default-size").addEventListener("change", async () => {
  try{
    const {ok} = await apiJson("/api/fleet/logs-policy", "POST",
                               {megabytes: Number($("logs-default-size").value) || 0});
    if(!ok) toast("The size could not be changed", "danger");
  }catch(_){ toast("The size could not be changed", "danger"); }
  refreshLogs();
});
$("logs-fetch").addEventListener("click", async (event) => {
  const node = $("logs-node").value;
  if(!node){ toast("Choose a machine first", "warn"); return; }
  await withBusy(event.target, async () => {
    try{
      const {ok} = await apiJson("/api/fleet/logs-fetch", "POST", {node});
      if(ok) toast("Asked " + shortId(node) + " for its log");
      else toast("That machine could not be asked", "danger");
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
// One machine at a time, because everything here is about one machine. Quick
// reads are waited on by the console; the ones that pull images — an update, a
// check, a deploy — hand back a rid and are asked about until they answer,
// because a browser will not hold a request open for minutes and an operation
// that says nothing until it ends is one nobody can tell from a hang.

const DK = {node:"", overview:null, stacks:null, containers:null, images:null,
            volumes:null, networks:null, stats:{}, check:null, checkedAt:0,
            running:{}, results:{}, scope:"all", probe:null, error:"", loading:false};

function dockerNodes(){
  return (ST.managed || []).filter((node) => (node.caps || []).includes("docker"));
}
async function dockerCall(op, extra, node){
  const target = node || DK.node;
  if(!target) throw new Error("pick a machine first");
  const answer = await apiJson("/api/fleet/docker", "POST",
                               Object.assign({node:target, op}, extra || {}));
  if(!answer.ok) throw new Error((answer.data && answer.data.error) || "that was refused");
  return answer.data;
}
// A slow operation: started, then asked about every two seconds until the node
// has answered. Thirty minutes is the far side's own ceiling on a compose run.
async function dockerSlow(op, extra){
  const node = DK.node;
  const started = await dockerCall(op, extra, node);
  if(!started.rid) return started;
  for(let tries = 0; tries < 900; tries++){
    await new Promise((resolve) => setTimeout(resolve, 2000));
    const answer = await dockerCall("answer", {rid:started.rid}, node);
    if(!answer.pending) return answer;
  }
  throw new Error("that machine stopped answering about it");
}
// Something long running, drawn as running wherever it shows, for as long as
// it runs — and only on the machine it was started on.
async function dockerRun(key, label, op, extra){
  const node = DK.node;
  DK.running[key] = {label, since:Date.now(), node};
  paintDocker();
  try{ return await dockerSlow(op, extra); }
  finally{ delete DK.running[key]; paintDocker(); }
}
function dockerBusy(key){
  const job = DK.running[key];
  return job && job.node === DK.node ? job : null;
}

async function dockerLoad(){
  if(!DK.node || DK.loading) return;
  DK.loading = true;
  DK.error = "";
  paintDocker();
  try{
    DK.overview = (await dockerCall("overview")).info || {};
    if(DK.overview.engine){
      const [stacks, containers] = await Promise.all(
        [dockerCall("stacks"), dockerCall("containers")]);
      DK.stacks = stacks.items || [];
      DK.containers = containers.items || [];
      if(stacks.info && stacks.info.portainer_problem)
        toast("Portainer did not answer", "warn", stacks.info.portainer_problem);
    }else{ DK.stacks = []; DK.containers = []; }
  }catch(error){
    DK.error = String(error.message || error);
  }finally{ DK.loading = false; }
  paintDocker();
  if(DK.overview && DK.overview.engine){
    dockerSample();
    dockerLoadTab(ROUTER.sub);
  }
}
// Usage figures take about a second a container to read, so the list is shown
// first and they join it when they arrive.
async function dockerSample(){
  const node = DK.node;
  try{
    const answer = await dockerCall("stats");
    if(node === DK.node){ DK.stats = answer.info || {}; paintDocker(); }
  }catch(_){ /* the list stands without them */ }
}
// The lists only one tab needs are read when that tab is opened, not on every
// refresh of the panel: each is a round trip to somebody else's machine.
async function dockerLoadTab(sub, force){
  if(!DK.node || !DK.overview || !DK.overview.engine) return;
  const node = DK.node;
  const wanted = {images:["images"], storage:["volumes", "networks"]}[sub] || [];
  for(const op of wanted){
    if(DK[op] !== null && !force) continue;
    try{
      const items = (await dockerCall(op)).items || [];
      if(node === DK.node) DK[op] = items;
    }catch(error){ toast(String(error.message || error), "danger"); }
  }
  paintDocker();
}
function dockerReset(){
  Object.assign(DK, {overview:null, stacks:null, containers:null, images:null,
                     volumes:null, networks:null, stats:{}, check:null, checkedAt:0,
                     probe:null, error:""});
}

// ---- what is drawn -----------------------------------------------------------
// Which stacks *Update* also brings up on that node. Read from the ledger, not
// from a checkbox: it is a choice this console remembers about a machine, and
// the node card's Update button reads the same one.
function dockerChosen(){
  const node = (ST.managed || []).find((entry) => entry.id === DK.node);
  return new Set((node && node.update_stacks) || []);
}
function stat(value, key, tone){
  return '<div class="stat' + (tone ? " " + tone : "") + '"><span class="v">' +
    esc(String(value)) + '</span><span class="k">' + esc(key) + "</span></div>";
}
function stateBadge(state){
  const tone = {running:"ok", restarting:"warn", paused:"warn", created:"",
                exited:"danger", dead:"danger"}[state];
  return badge(state || "unknown", tone === undefined ? "" : tone);
}
// What a check said about one container, as a word and a colour.
const UPDATE_WORDS = {
  outdated:["update available", "warn"], pulled:["newer image here", "info"],
  current:["up to date", "ok"], pinned:["pinned", ""], local:["local image", ""],
  unknown:["could not check", ""],
};
function updateBadge(id){
  const state = DK.check && DK.check.containers && DK.check.containers[id];
  if(!state) return "";
  const [word, tone] = UPDATE_WORDS[state] || [state, ""];
  return badge(word, tone);
}
function stackNeedsUpdate(stack){
  if(!DK.check) return false;
  return (stack.services || []).some((row) =>
    ["outdated", "pulled"].includes(DK.check.containers[row.container]));
}
function portainerWord(info){
  const pt = (info && info.portainer) || {};
  if(pt.connected) return ["connected", "ok"];
  if(pt.server) return ["found", "warn"];
  if(pt.agent) return ["agent", ""];
  return ["none", ""];
}
function useText(id){
  const use = DK.stats[id];
  return use ? use.cpu.toFixed(1) + "% · " + fmtBytes(use.memory) : "";
}

function paintDockerSummary(){
  const nodes = dockerNodes();
  if(!nodes.length){
    setHTML("dk-summary", emptyHTML("No machine has granted docker",
      "A machine you manage has to grant the docker right before it can be read here. " +
      "It is root on that machine, so it is never granted by default."));
    return;
  }
  if(DK.error){
    setHTML("dk-summary", errorHTML("That machine did not answer", DK.error));
    return;
  }
  const info = DK.overview;
  if(!info){
    setHTML("dk-summary", DK.loading ? skeletonHTML(1) : "");
    return;
  }
  if(!info.engine){
    setHTML("dk-summary", errorHTML("No docker to drive on that machine",
      (info.problem || "") + ". Install docker there, or re-run install.sh --docker so " +
      "the node's account can reach the socket."));
    return;
  }
  const [ptWord, ptTone] = portainerWord(info);
  let updates = "not checked", tone = "";
  if(DK.check){
    const waiting = Object.values(DK.check.containers || {})
      .filter((state) => state === "outdated" || state === "pulled").length;
    updates = waiting ? waiting + " behind" : "up to date";
    tone = waiting ? "warn" : "ok";
  }
  setHTML("dk-summary", '<div class="stats">' +
    stat((info.running || 0) + " / " + (info.containers || 0), "containers running", "accent") +
    stat(DK.stacks ? DK.stacks.length : (info.stacks || 0), "stacks") +
    stat(updates, "updates", tone) +
    stat(info.version || "—", "docker engine") +
    stat(info.compose || "not installed", "docker compose", info.compose ? "" : "warn") +
    stat(ptWord, "portainer", ptTone) + "</div>");
}

function stackOwner(stack){
  if(stack.owner === "portainer")
    return badge("Portainer" + (stack.portainer_id ? " · stack " + stack.portainer_id : ""),
                 "accent");
  return badge(stack.nmesh ? "compose · deployed from here" : "compose");
}
function stackStateBadge(stack){
  if(!stack.total) return badge("stopped");
  if(stack.running === stack.total) return badge(stack.total + " running", "ok");
  if(!stack.running) return badge("stopped", "danger");
  return badge(stack.running + " of " + stack.total + " running", "warn");
}
// Where the stack comes from, said in the words an operator would look for.
function stackSource(stack){
  if(stack.owner === "portainer"){
    return stack.portainer_api ? "Held by Portainer, which is connected here" +
      (stack.git ? " — redeployed from its git repository" : "")
      : "Held by Portainer, which is not connected here";
  }
  if(!(stack.files || []).length) return "No compose file is recorded for it";
  return (stack.files || []).join(", ") + (stack.files_ok ? "" : " — not readable by the node");
}
function serviceRows(stack){
  if(!(stack.services || []).length)
    return '<p class="muted small flush">Nothing of it runs on this machine.</p>';
  return '<div class="table-wrap"><table><thead><tr><th>Service</th><th>Image</th>' +
    "<th>State</th><th>Use</th><th>Image status</th><th></th></tr></thead><tbody>" +
    stack.services.map((row) =>
      "<tr><td><b>" + esc(row.service || row.name) + "</b>" +
      '<div class="tiny muted mono truncate">' + esc(row.name) + "</div></td>" +
      '<td class="mono tiny">' + esc(row.image) + "</td>" +
      "<td>" + stateBadge(row.state) + '<div class="tiny muted">' + esc(row.status || "") +
      "</div></td>" +
      '<td class="mono tiny nowrap">' + esc(useText(row.container)) + "</td>" +
      "<td>" + updateBadge(row.container) + "</td>" +
      '<td class="tight"><button class="sm ghost" data-dk="logs" data-id="' +
      esc(row.container) + '" data-label="' + esc(row.service || row.name) +
      '">Logs</button></td></tr>').join("") + "</tbody></table></div>";
}
function stackCard(stack){
  const key = "stack:" + stack.name;
  const busy = dockerBusy(key);
  const name = esc(stack.name);
  const running = stack.running > 0;
  const off = busy ? " disabled" : "";
  const result = DK.results[stack.name];
  const chosen = dockerChosen().has(stack.name);
  return '<article class="card"><div class="card-head"><div class="grow">' +
    '<h2 class="row wrap">' + name + " " + stackOwner(stack) + " " + stackStateBadge(stack) +
    (stackNeedsUpdate(stack) ? " " + badge("update available", "warn") : "") + "</h2>" +
    '<div class="sub">' + esc(stackSource(stack)) + "</div></div>" +
    '<div class="btn-row">' +
    '<button class="sm primary" data-dk="update" data-stack="' + name + '"' + off + ">Update</button>" +
    '<button class="sm" data-dk="stack" data-action="' + (running ? "stop" : "start") +
      '" data-stack="' + name + '"' + off + ">" + (running ? "Stop" : "Start") + "</button>" +
    (running ? '<button class="sm" data-dk="stack" data-action="restart" data-stack="' + name +
      '"' + off + ">Restart</button>" : "") +
    '<button class="sm ghost" data-dk="file" data-stack="' + name + '">File</button>' +
    "</div></div>" +
    '<div class="card-body stack">' + serviceRows(stack) +
    '<p class="muted small flush"><b>Update</b> ' + esc(stack.why || "") + ".</p>" +
    (busy ? '<div class="row"><progress class="meter"></progress><span class="small nowrap" ' +
      'data-since="' + busy.since + '">' + esc(busy.label) + "</span></div>" : "") +
    (!busy && result ? '<div class="notice ' + (result.ok ? "ok" : "danger") + '">' +
      '<span class="grow">' + esc(result.text) + "</span>" +
      (result.output ? '<button class="sm ghost" data-dk="output" data-stack="' + name +
        '">Output</button>' : "") + "</div>" : "") +
    "</div>" +
    '<div class="card-foot"><label class="check" title="Update on the machine\'s card also ' +
    'brings this stack up to date"><input type="checkbox" role="switch" data-dk-pick="' + name +
    '"' + (chosen ? " checked" : "") + "><span>Include in this machine's Update</span></label></div>" +
    "</article>";
}
function paintDockerStacks(){
  const all = DK.stacks;
  if(all === null){
    setHTML("dk-stacks", DK.loading ? skeletonHTML(3) : "");
    return;
  }
  const filter = $("dk-stack-filter").value.trim().toLowerCase();
  const shown = all.filter((stack) => !filter || stack.name.toLowerCase().includes(filter) ||
    (stack.services || []).some((row) => (row.image + " " + row.service).toLowerCase().includes(filter)));
  setHTML("dk-stacks", shown.map(stackCard).join("") ||
    (all.length ? emptyHTML("No stack matches that filter")
      : emptyHTML("No stack on this machine",
          "A stack is a compose project, deployed by compose or by Portainer. Deploy one, or " +
          "look at the containers that run on their own.")));
  const behind = all.filter(stackNeedsUpdate);
  $("dk-update-all").hidden = !behind.length;
  $("dk-update-all").textContent = "Update " + plural(behind.length, "stack");
  $("dk-check").disabled = !!dockerBusy("check");
  $("dk-check").textContent = dockerBusy("check") ? "Checking…" : "Check for updates";
  $("dk-checked").textContent = DK.check
    ? "Checked " + fmtAgo((Date.now() - DK.checkedAt) / 1000) : "";
}

function containerRow(entry){
  const running = entry.state === "running";
  const key = "ct:" + entry.id;
  const off = dockerBusy(key) ? " disabled" : "";
  const id = esc(entry.id);
  return "<tr><td><b class=\"truncate\">" + esc(entry.name || shortId(entry.id)) + "</b>" +
    (entry.ports.length ? '<div class="tiny muted mono">' + esc(entry.ports.join("  ")) +
      "</div>" : "") + "</td>" +
    '<td class="mono tiny">' + esc(entry.image) + "</td>" +
    "<td>" + (entry.project ? badge(entry.project) : '<span class="muted tiny">—</span>') + "</td>" +
    "<td>" + stateBadge(entry.state) + "</td>" +
    '<td class="mono tiny nowrap">' + esc(useText(entry.id)) + "</td>" +
    "<td>" + (dockerBusy(key) ? badge("updating…", "info") : updateBadge(entry.id)) + "</td>" +
    '<td class="tight"><span class="btn-row">' +
    '<button class="sm" data-dk="act" data-action="' + (running ? "stop" : "start") +
      '" data-id="' + id + '"' + off + ">" + (running ? "Stop" : "Start") + "</button>" +
    (running ? '<button class="sm" data-dk="act" data-action="restart" data-id="' + id + '"' +
      off + ">Restart</button>" : "") +
    // Inside a stack, the stack's Update is the one that knows its owner.
    (entry.project ? "" : '<button class="sm" data-dk="recreate" data-id="' + id +
      '" data-label="' + esc(entry.name) + '"' + off + ">Update</button>") +
    '<button class="sm ghost" data-dk="logs" data-id="' + id + '" data-label="' +
      esc(entry.name) + '">Logs</button>' +
    '<button class="sm danger" data-dk="remove" data-id="' + id + '" data-label="' +
      esc(entry.name) + '"' + off + ">Remove</button></span></td></tr>";
}
function paintDockerContainers(){
  const all = DK.containers;
  if(all === null){ setHTML("dk-containers", DK.loading ? skeletonHTML(4) : ""); return; }
  const filter = $("dk-ct-filter").value.trim().toLowerCase();
  const shown = all.filter((entry) => (DK.scope === "all" || !entry.project) &&
    (!filter || (entry.name + " " + entry.image + " " + entry.project).toLowerCase().includes(filter)));
  $$("[data-dk-scope]").forEach((button) =>
    button.setAttribute("aria-selected", button.dataset.dkScope === DK.scope ? "true" : "false"));
  setHTML("dk-containers", shown.length ? '<div class="table-wrap"><table><thead><tr>' +
    "<th>Name</th><th>Image</th><th>Stack</th><th>State</th><th>Use</th><th>Image status</th>" +
    "<th></th></tr></thead><tbody>" + shown.map(containerRow).join("") + "</tbody></table></div>"
    : emptyHTML(all.length ? "No container matches" : "No container on this machine"));
}

function paintDockerImages(){
  if(DK.images === null){ setHTML("dk-images", skeletonHTML(3)); return; }
  const used = new Set((DK.containers || []).map((entry) => entry.image_id));
  setHTML("dk-images", DK.images.length ? '<div class="table-wrap"><table><thead><tr>' +
    '<th>Image</th><th class="num">Size</th><th>Created</th><th></th></tr></thead><tbody>' +
    DK.images.map((image) => {
      const name = image.tags[0] || image.id;
      return '<tr><td class="mono tiny">' + esc(name) +
        (image.tags.length > 1 ? '<div class="muted">' + esc(image.tags.slice(1).join(", ")) +
          "</div>" : "") + "</td>" +
        '<td class="num">' + fmtBytes(image.size) + "</td>" +
        '<td class="nowrap">' + (image.created
          ? esc(new Date(image.created * 1000).toLocaleDateString()) : "—") + "</td>" +
        '<td class="tight">' + (used.has(image.id) ? badge("in use", "ok")
          : '<button class="sm danger" data-dk="rmi" data-image="' + esc(name) +
            '">Remove</button>') + "</td></tr>";
    }).join("") + "</tbody></table></div>" : emptyHTML("No image on this machine"));
}
function paintDockerStorage(){
  setHTML("dk-volumes", DK.volumes === null ? skeletonHTML(2) : DK.volumes.length
    ? '<div class="table-wrap"><table><thead><tr><th>Name</th><th>Driver</th></tr></thead><tbody>' +
      DK.volumes.map((volume) => '<tr><td class="mono tiny">' + esc(volume.name) + "</td><td>" +
        esc(volume.driver) + "</td></tr>").join("") + "</tbody></table></div>"
    : emptyHTML("No volume"));
  setHTML("dk-networks", DK.networks === null ? skeletonHTML(2) : DK.networks.length
    ? '<div class="table-wrap"><table><thead><tr><th>Name</th><th>Driver</th><th>Subnet</th>' +
      '<th class="num">Containers</th></tr></thead><tbody>' +
      DK.networks.map((network) => "<tr><td><b>" + esc(network.name) + "</b></td><td>" +
        esc(network.driver) + '</td><td class="mono tiny">' + esc(network.subnet || "—") +
        '</td><td class="num">' + network.attached + "</td></tr>").join("") +
      "</tbody></table></div>"
    : emptyHTML("No network"));
}

// The Portainer tab is a conversation in three states: none here, found but
// not connected, connected. Rebuilt only when that state changes, so a token
// half typed is never wiped by a poll.
function portainerKey(){
  const pt = (DK.overview && DK.overview.portainer) || {};
  return JSON.stringify([DK.node, !!DK.overview, pt.connected, pt.url, pt.pinned,
                         pt.server && pt.server.id, pt.agent, DK.probe]);
}
let PT_DRAWN = "";
function paintDockerPortainer(){
  const key = portainerKey();
  const pt = (DK.overview && DK.overview.portainer) || null;
  $("dk-n-portainer").textContent = pt && pt.connected ? "connected"
    : pt && pt.server ? "found" : "";
  if(key === PT_DRAWN) return;
  PT_DRAWN = key;
  if(!pt){ setHTML("dk-portainer", DK.loading ? skeletonHTML(2) : ""); return; }
  const server = pt.server;
  let html = "";
  if(server){
    html += '<article class="card"><div class="card-head"><div class="grow"><h2>Portainer ' +
      "runs on this machine</h2><div class=\"sub\">Found from its container — no credential " +
      "is needed to see it, or to see which stacks are its.</div></div>" +
      stateBadge(server.state) + "</div>" +
      '<div class="card-body"><dl class="kv">' +
      "<dt>Container</dt><dd>" + esc(server.name) + "</dd>" +
      '<dt>Image</dt><dd class="mono">' + esc(server.image) + "</dd>" +
      "<dt>Edition</dt><dd>" + esc(server.edition) + "</dd>" +
      '<dt>Address here</dt><dd class="mono">' + esc(server.url || "publishes no port") + "</dd>" +
      "</dl></div></article>";
  }else if(pt.agent){
    html += '<div class="notice">This machine runs a Portainer agent: its stacks are deployed ' +
      "by a Portainer elsewhere. Connect that Portainer to update them through it.</div>";
  }
  if(pt.connected){
    html += '<article class="card"><div class="card-head"><div class="grow"><h2>Connected</h2>' +
      '<div class="sub">Stacks Portainer owns are updated through its API — it pulls and ' +
      "redeploys with the file and environment it holds, and its own record stays true." +
      "</div></div>" + badge("connected", "ok") + "</div>" +
      '<div class="card-body"><dl class="kv"><dt>Address</dt><dd class="mono">' + esc(pt.url) +
      "</dd><dt>Certificate</dt><dd>" + (pt.pinned ? "pinned" :
        pt.url.startsWith("http:") ? "none: loopback only" : "verified by its chain") +
      "</dd><dt>Token</dt><dd>kept in that node's encrypted drawer, never read back</dd></dl></div>" +
      '<div class="card-foot"><button class="danger" data-dk="pt-forget">Forget</button></div>' +
      "</article>";
  }else{
    const suggested = (server && server.url) || "";
    const probe = DK.probe;
    html += '<article class="card"><div class="card-head"><div class="grow"><h2>Connect ' +
      (server ? "it" : "a Portainer") + "</h2>" +
      '<div class="sub">Without it, a Portainer stack is updated by pulling its images and ' +
      "recreating its containers with the settings they run with. Connected, it is " +
      "redeployed by Portainer itself.</div></div></div>" +
      '<div class="card-body stack">' +
      '<div class="toolbar"><label class="field grow"><span>Address, as that machine reaches it</span>' +
      '<input id="pt-url" class="mono" value="' + esc((probe && probe.url) || suggested) +
      '" placeholder="https, host and port" autocomplete="off" spellcheck="false"></label>' +
      '<button class="ghost" data-dk="pt-probe">Read its certificate</button></div>' +
      (probe ? '<div class="notice ok"><span class="grow">Portainer ' + esc(probe.version) +
        " answers there." + (probe.fingerprint ? ' Its certificate: <span class="mono fp">' +
        esc(probe.fingerprint.match(/../g).join(":")) + "</span>" : "") + "</span></div>" +
        (probe.fingerprint ? '<label class="check"><input id="pt-pin" type="checkbox" checked>' +
          "<span>Trust this certificate (pin it). Compare it with the one your browser shows " +
          "for Portainer if the address is not this machine's own.</span></label>" : "") : "") +
      '<label class="field"><span>Access token</span><input id="pt-token" type="password" ' +
      'autocomplete="new-password" placeholder="ptr_…">' +
      '<span class="hint">In Portainer: your account, then Access tokens, then Add access ' +
      "token. It is written to that node's encrypted drawer and never read back.</span></label>" +
      '<div class="btn-row"><button class="primary" data-dk="pt-connect">Connect</button></div>' +
      '<p id="pt-msg" class="msg"></p></div></article>';
  }
  if(!server && !pt.agent && !pt.connected){
    html = '<div class="notice">No Portainer runs on this machine. Stacks deployed with compose ' +
      "are updated from their own files; connect a Portainer below only if one elsewhere " +
      "manages this machine.</div>" + html;
  }
  setHTML("dk-portainer", html);
}

function paintDocker(){
  $("nav-docker").textContent = dockerNodes().length || "";
  $("dk-n-stacks").textContent = DK.stacks ? DK.stacks.length : "";
  $("dk-n-containers").textContent = DK.containers ? DK.containers.length : "";
  paintDockerSummary();
  const engine = !!(DK.overview && DK.overview.engine) || DK.loading;
  $("dk-tabs").hidden = !engine && !!DK.overview;
  paintDockerStacks();
  paintDockerContainers();
  paintDockerImages();
  paintDockerStorage();
  paintDockerPortainer();
  tickDocker();
}
// The elapsed time on a running job, rewritten in place: a whole repaint a
// second would close whatever the operator had open.
function tickDocker(){
  $$("#panel-docker [data-since]").forEach((element) => {
    const seconds = Math.round((Date.now() - Number(element.dataset.since)) / 1000);
    const label = element.dataset.label || element.textContent.replace(/ · \d+:\d\d$/, "");
    element.dataset.label = label;
    element.textContent = label + " · " + Math.floor(seconds / 60) + ":" +
      String(seconds % 60).padStart(2, "0");
  });
}
setInterval(tickDocker, 1000);

// ---- what is done ------------------------------------------------------------

function stackByName(name){
  return (DK.stacks || []).find((stack) => stack.name === name);
}
// Updating is the one act here that restarts services, so it says what it will
// do before doing it: through whom, and which containers.
async function updateStack(name, quiet){
  const stack = stackByName(name);
  if(!stack) return false;
  if(!quiet){
    const services = (stack.services || []).map((row) =>
      "<li><b>" + esc(row.service || row.name) + '</b> <span class="mono tiny">' +
      esc(row.image) + "</span></li>").join("");
    const agreed = await confirmAction({title:"Update " + name + "?",
      body:'<p class="small">' + esc(stack.why || "") + ".</p>" +
        (services ? '<ul class="small">' + services + "</ul>" : "") +
        '<p class="muted small">A container whose image changed is recreated, so its service ' +
        "is down for a few seconds. Volumes are kept.</p>",
      confirmLabel:"Update"});
    if(!agreed) return false;
  }
  try{
    const answer = await dockerRun("stack:" + name, "Updating", "stack",
                                   {stack:name, action:"update"});
    const info = answer.info || {};
    const steps = info.steps || [];
    const text = info.through === "engine"
      ? (info.updated ? plural(info.updated, "container") + " recreated on a newer image"
                      : "Already on the newest images — nothing recreated")
      : info.through === "portainer" ? "Redeployed by Portainer, images pulled"
      : "Pulled and brought up with compose";
    DK.results[name] = {ok:true, text, output:info.output ||
      steps.map((step) => step.service + ": " + step.result).join("\n")};
    if(!quiet) toast(name + ": " + text, "ok");
    return true;
  }catch(error){
    DK.results[name] = {ok:false, text:String(error.message || error), output:""};
    toast(name + " could not be updated", "danger", String(error.message || error));
    return false;
  }finally{
    await dockerLoad();
    if(DK.check) checkUpdates(true);
  }
}
async function updateAll(){
  const names = (DK.stacks || []).filter(stackNeedsUpdate).map((stack) => stack.name);
  const agreed = await confirmAction({title:"Update " + plural(names.length, "stack") + "?",
    body:'<p class="small">One after the other, each the way its owner would: ' +
      esc(names.join(", ")) + ".</p>" +
      '<p class="muted small">Each container whose image changed is recreated.</p>',
    confirmLabel:"Update all"});
  if(!agreed) return;
  let done = 0;
  for(const name of names){ if(await updateStack(name, true)) done++; }
  toast(plural(done, "stack") + " of " + names.length + " updated",
        done === names.length ? "ok" : "warn");
}
async function checkUpdates(quiet){
  try{
    const answer = await dockerRun("check", "Checking", "check", {});
    DK.check = answer.info || {containers:{}, images:{}};
    DK.checkedAt = Date.now();
    if(!quiet){
      const behind = Object.values(DK.check.containers || {})
        .filter((state) => state === "outdated" || state === "pulled").length;
      toast(behind ? plural(behind, "container") + " can be updated" : "Everything is up to date",
            behind ? "warn" : "ok");
    }
  }catch(error){ if(!quiet) toast(String(error.message || error), "danger"); }
  paintDocker();
}
async function stackAct(name, action, button){
  return withBusy(button, async () => {
    try{
      await dockerCall("stack", {stack:name, action});
      toast(name + ": " + ({start:"started", stop:"stopped", restart:"restarted"}[action] || action), "ok");
    }catch(error){ toast(String(error.message || error), "danger"); }
    await dockerLoad();
  });
}
async function containerAct(id, action, label, button){
  if(action === "remove"){
    const agreed = await confirmAction({title:"Remove " + (label || "this container") + "?",
      body:'<p class="muted small">It is stopped and deleted. Anything it wrote outside a ' +
        "volume goes with it.</p>", confirmLabel:"Remove", danger:true});
    if(!agreed) return;
  }
  return withBusy(button, async () => {
    try{ await dockerCall("act", {id, action}); }
    catch(error){ toast(String(error.message || error), "danger"); }
    await dockerLoad();
  });
}
async function recreateContainer(id, label){
  const agreed = await confirmAction({title:"Update " + (label || "this container") + "?",
    body:'<p class="small">Its image is pulled again. If the registry has a newer one, the ' +
      "container is recreated from it with the settings it runs with, and put back as it " +
      "was if the new one does not stay up.</p>", confirmLabel:"Update"});
  if(!agreed) return;
  try{
    const info = (await dockerRun("ct:" + id, "Updating", "recreate", {id})).info || {};
    toast((label || "Container") + ": " + (info.result === "updated" ? "recreated on a newer image"
      : info.result === "pinned" ? "pinned to a digest, nothing to pull" : "already up to date"), "ok");
  }catch(error){ toast(String(error.message || error), "danger"); }
  await dockerLoad();
}
function textDialog(title, sub, text){
  $("modal-title").textContent = title;
  $("modal-body").innerHTML = (sub ? '<p class="muted small mono">' + esc(sub) + "</p>" : "") +
    '<pre class="term" id="dk-text"></pre>' +
    '<div class="btn-row"><button id="dk-text-copy" class="ghost">Copy</button></div>';
  // Written as text, never as markup: these are bytes a container or a file chose.
  $("dk-text").textContent = text;
  $("dk-text-copy").addEventListener("click", () => copyText(text));
  $("modal").showModal();
}
async function dockerLogs(id, label){
  $("modal-title").textContent = "Logs · " + (label || shortId(id));
  $("modal-body").innerHTML = '<pre class="term" id="dk-log">Reading…</pre>' +
    '<div class="btn-row"><button id="dk-log-more" class="ghost">Reload</button></div>';
  $("modal").showModal();
  const read = async () => {
    try{
      const answer = await dockerCall("logs", {id, tail:400});
      $("dk-log").textContent = answer.text || "(nothing)";
      $("dk-log").scrollTop = $("dk-log").scrollHeight;
    }catch(error){ $("dk-log").textContent = String(error.message || error); }
  };
  $("dk-log-more").addEventListener("click", read);
  await read();
}
async function stackFile(name){
  try{
    const info = (await dockerCall("stack_file", {stack:name})).info || {};
    textDialog(name + " · compose file", info.path || "", info.text || "");
  }catch(error){ toast(String(error.message || error), "danger"); }
}
async function portainerProbe(button){
  const url = $("pt-url").value.trim();
  if(!url){ setMessage("pt-msg", "An address is needed.", true); return; }
  return withBusy(button, async () => {
    try{
      DK.probe = (await dockerCall("portainer_probe", {url})).info || null;
      paintDocker();
    }catch(error){ setMessage("pt-msg", String(error.message || error), true); }
  });
}
async function portainerConnect(button){
  const url = $("pt-url").value.trim();
  const token = $("pt-token").value;
  if(!url || !token){ setMessage("pt-msg", "An address and a token are needed.", true); return; }
  const pin = $("pt-pin") && $("pt-pin").checked && DK.probe && DK.probe.url === url
    ? DK.probe.fingerprint : "";
  return withBusy(button, async () => {
    try{
      const answer = await dockerCall("portainer", {url, token, fingerprint:pin});
      // Never echoed back: the token now lives in that node's drawer.
      $("pt-token").value = "";
      DK.probe = null;
      toast("Portainer connected — " + plural((answer.items || []).length, "environment") +
            " visible", "ok");
      await dockerLoad();
    }catch(error){ setMessage("pt-msg", String(error.message || error), true); }
  });
}
async function portainerForget(button){
  const agreed = await confirmAction({title:"Forget that Portainer?",
    body:'<p class="muted small">The address and token are deleted from that node\'s drawer. ' +
      "Its stacks keep running; they are then updated by recreating their containers " +
      "instead of through Portainer.</p>", confirmLabel:"Forget", danger:true});
  if(!agreed) return;
  return withBusy(button, async () => {
    try{ await dockerCall("portainer", {clear:true}); toast("Portainer forgotten"); }
    catch(error){ toast(String(error.message || error), "danger"); }
    await dockerLoad();
  });
}

function runDialog(){
  $("modal-title").textContent = "Run a container";
  $("modal-body").innerHTML =
    '<div class="form-grid">' +
    '<label class="field"><span>Name</span><input id="rn-name" class="mono" ' +
    'placeholder="my-service" autocomplete="off" spellcheck="false"></label>' +
    '<label class="field"><span>Image</span><input id="rn-image" class="mono" ' +
    'placeholder="ghcr.io/owner/image:tag" autocomplete="off" spellcheck="false"></label>' +
    '<label class="field"><span>Ports</span>' +
    '<textarea id="rn-ports" class="mono" rows="2" placeholder="8080:80"></textarea>' +
    '<span class="hint">host:container, one per line; add :udp for UDP</span></label>' +
    '<label class="field"><span>Volumes</span>' +
    '<textarea id="rn-vols" class="mono" rows="2" placeholder="/srv/data:/data"></textarea>' +
    '<span class="hint">host path or volume name : container path, :ro for read-only</span></label>' +
    '<label class="field"><span>Environment</span>' +
    '<textarea id="rn-env" class="mono" rows="3" placeholder="TZ=Europe/Paris"></textarea>' +
    '<span class="hint">KEY=value, one per line</span></label>' +
    '<label class="field"><span>Restart policy</span><select id="rn-restart">' +
    '<option value="unless-stopped">unless-stopped</option><option value="always">always</option>' +
    '<option value="on-failure">on-failure</option><option value="no">no</option></select></label>' +
    "</div>" +
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
    try{
      await dockerRun("run", "Starting " + image, "deploy", {spec:{
        name:$("rn-name").value.trim(), image, ports, volumes, env,
        restart:$("rn-restart").value}});
      toast(image + " is running", "ok");
    }catch(error){ toast(String(error.message || error), "danger"); }
    await dockerLoad();
  }));
  $("rn-no").addEventListener("click", () => $("modal").close());
  $("modal").showModal();
  $("rn-name").focus();
}

function stackDialog(){
  const connected = !!(DK.overview && DK.overview.portainer && DK.overview.portainer.connected);
  const compose = !!(DK.overview && DK.overview.compose);
  $("modal-title").textContent = "Deploy a stack";
  $("modal-body").innerHTML =
    (connected ? '<div class="segmented" role="group" aria-label="Deployed by">' +
      '<button data-sk-through="compose" aria-selected="' + (compose ? "true" : "false") +
      '"' + (compose ? "" : " disabled") + ">Compose, on that machine</button>" +
      '<button data-sk-through="portainer" aria-selected="' + (compose ? "false" : "true") +
      '">Portainer</button></div>' : "") +
    '<p id="sk-where" class="muted small"></p>' +
    '<label class="field"><span>Name</span><input id="sk-name" class="mono" ' +
    'placeholder="my-stack" autocomplete="off" spellcheck="false">' +
    '<span class="hint">lowercase letters, digits, - and _</span></label>' +
    '<label class="field"><span>docker-compose.yml</span>' +
    '<textarea id="sk-body" class="mono" rows="14" spellcheck="false" ' +
    'placeholder="services:&#10;  web:&#10;    image: nginx:alpine"></textarea></label>' +
    '<div class="btn-row"><button id="sk-go" class="primary">Deploy</button>' +
    '<button id="sk-no">Cancel</button></div><p id="sk-msg" class="msg"></p>';
  let through = connected && !compose ? "portainer" : "compose";
  const explain = () => {
    $("sk-where").textContent = through === "portainer"
      ? "Portainer keeps the file and owns the stack; it is updated through Portainer."
      : "The file is kept on that machine under the node's own state, and compose brings it up.";
    $$("[data-sk-through]").forEach((button) =>
      button.setAttribute("aria-selected", button.dataset.skThrough === through ? "true" : "false"));
  };
  $$("[data-sk-through]").forEach((button) => button.addEventListener("click", () => {
    through = button.dataset.skThrough; explain();
  }));
  explain();
  if(!compose && !connected)
    setMessage("sk-msg", "That machine has no docker compose: install it there first.", true);
  $("sk-go").addEventListener("click", (event) => withBusy(event.target, async () => {
    const name = $("sk-name").value.trim();
    const body = $("sk-body").value;
    if(!/^[a-z0-9][a-z0-9_-]{0,62}$/.test(name) || !body.trim()){
      setMessage("sk-msg", "A lowercase name and a compose file are needed.", true); return;
    }
    $("modal").close();
    try{
      await dockerRun("deploy:" + name, "Deploying " + name, "deploy_stack",
                      {stack:name, compose:body, portainer:through === "portainer"});
      toast("Stack " + name + " deployed", "ok");
    }catch(error){ toast("Stack " + name + " failed", "danger", String(error.message || error)); }
    await dockerLoad();
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
  if(await TERM_SESSION.open(node)) TERM_SESSION.focus();
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
  if(data.revealPassword) return passwordDialog(data.revealPassword);
  if(data.logs){
    // The machine's own card sends the operator to the panel, filtered to it.
    $("logs-node").value = data.logs;
    ROUTER.go("logs");
    refreshLogs();
    return;
  }
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
    if(DK.node !== data.docker){ DK.node = data.docker; dockerReset(); }
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
  dockerReset();
  dockerLoad();
});
$("dk-refresh").addEventListener("click", (event) => withBusy(event.target, async () => {
  DK.images = null; DK.volumes = null; DK.networks = null;
  await dockerLoad();
}));
// Read when the panel is opened, not on every poll: this is a round trip to
// somebody else's machine, and a tab nobody is looking at should cost nothing.
ROUTER.onChange = (section, sub) => {
  if(section === "docker" && DK.node){
    if(DK.overview === null) dockerLoad(); else dockerLoadTab(sub);
  }
  if(section === "logs") refreshLogs();
};
$("panel-docker").addEventListener("click", (event) => {
  const scope = event.target.closest("[data-dk-scope]");
  if(scope){ DK.scope = scope.dataset.dkScope; paintDocker(); return; }
  const button = event.target.closest("[data-dk]");
  if(!button) return;
  const data = button.dataset;
  const act = {
    update: () => updateStack(data.stack),
    stack: () => stackAct(data.stack, data.action, button),
    file: () => stackFile(data.stack),
    output: () => {
      const result = DK.results[data.stack];
      if(result) textDialog(data.stack + " · last update", "", result.output || result.text);
    },
    logs: () => dockerLogs(data.id, data.label),
    act: () => containerAct(data.id, data.action, data.label, button),
    remove: () => containerAct(data.id, "remove", data.label, button),
    recreate: () => recreateContainer(data.id, data.label),
    rmi: () => removeImage(data.image, button),
    "pt-probe": () => portainerProbe(button),
    "pt-connect": () => portainerConnect(button),
    "pt-forget": () => portainerForget(button),
  }[data.dk];
  if(act) act();
});
// The switch that decides what Update also brings up. Written the moment it
// changes, because a preference that needs a second button to save it is one
// that is routinely lost.
$("panel-docker").addEventListener("change", async (event) => {
  const box = event.target.closest("[data-dk-pick]");
  if(!box) return;
  const chosen = dockerChosen();
  if(box.checked) chosen.add(box.dataset.dkPick); else chosen.delete(box.dataset.dkPick);
  await api("/api/fleet/stacks", "POST", {node:DK.node, stacks:[...chosen]});
  poll();
});
$("dk-stack-filter").addEventListener("input", paintDocker);
$("dk-ct-filter").addEventListener("input", paintDocker);
$("dk-check").addEventListener("click", () => checkUpdates(false));
$("dk-update-all").addEventListener("click", updateAll);
$("dk-stack-new").addEventListener("click", () => stackDialog());
$("dk-container-new").addEventListener("click", () => runDialog());
$("dk-pull-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const image = $("dk-pull").value.trim();
  if(!image) return;
  $("dk-pull").value = "";
  toast("Pulling " + image + "…");
  try{
    const info = (await dockerRun("pull", "Pulling " + image, "pull", {image})).info || {};
    toast("Pulled " + (info.image || image), "ok");
  }catch(error){ toast(String(error.message || error), "danger"); }
  await dockerLoadTab("images", true);
});
async function removeImage(image, button){
  const agreed = await confirmAction({title:"Remove this image?",
    body:'<p class="mono small">' + esc(image) + "</p>" +
      '<p class="muted small">The daemon refuses while a container uses it.</p>',
    confirmLabel:"Remove", danger:true});
  if(!agreed) return;
  return withBusy(button, async () => {
    try{ await dockerCall("remove_image", {image}); }
    catch(error){ toast(String(error.message || error), "danger"); }
    await dockerLoadTab("images", true);
  });
}

$("ssh-sudo").addEventListener("change", syncSudoFields);
$("deploy-btn").addEventListener("click", deploy);
$("shell-open").addEventListener("click", openShell);
$("shell-full").addEventListener("click", () => {
  // A tab, never a window: this button exists because a terminal in a panel is
  // a terminal in a box, and a 700px pop-up is the same box with a title bar.
  // `node` is the shell's target. The node this page is *driving*, when it
  // follows one, travels beside it as `ctx` — a different question, and a
  // claim the terminal checks against this console before believing.
  const node = $("shell-node").value;
  const query = [];
  if(node) query.push("node=" + encodeURIComponent(node));
  if(CONTEXT.node && CONTEXT.caps.includes("full"))
    query.push("ctx=" + encodeURIComponent(CONTEXT.node));
  window.open("/term" + (query.length ? "?" + query.join("&") : ""),
              "_blank", "noopener");
});
$("shell-kill").addEventListener("click", async () => {
  if(TERM_SESSION) await TERM_SESSION.stop();
});
$("term-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const line = $("term-in").value;
  $("term-in").value = "";
  // A return, as Enter sends: a line feed is not what a raw-mode program reads
  // as the end of a line.
  if(TERM_SESSION) await TERM_SESSION.typed(line + "\r", true);
});
// Keystrokes, the clipboard and the pointer are the session's own (see
// `ShellSession.bind`): one keyboard path for both places a shell is drawn, so
// a key that works in the full-screen terminal works here too.
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
  // No handler passed: the one set beside the panels is the handler, and a
  // fresh one here would replace it.
  ROUTER.start();
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
