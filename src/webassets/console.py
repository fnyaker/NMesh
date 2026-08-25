"""
Console page (/).

Four sections, in the order someone actually needs them: what this node is doing
(Overview), who it is talking to and how to reach it (Network), what runs on it
(Apps), and what you can change (Settings). Every section is a route, so any
sub-page can be linked to, bookmarked, and reached with the Back button.
"""

INDEX_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="theme-color" content="#f6f8fa" media="(prefers-color-scheme: light)">
<meta name="theme-color" content="#0a0e13" media="(prefers-color-scheme: dark)">
<title>NMesh Console</title>
<script src="/theme.js"></script>
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<link rel="stylesheet" href="/style.css">
</head>
<body data-app-name="NMesh Console">

<div id="login" class="gate">
  <form id="login-form">
    <div class="mark" aria-hidden="true">NM</div>
    <div>
      <p class="eyebrow">Local management plane</p>
      <h1>Unlock this node</h1>
    </div>
    <p class="muted small">The password is checked on this machine and never leaves it. It
      protects every management action, including the ones that can restart or update the node.</p>
    <label class="field"><span>Console password</span>
      <input id="password" type="password" autocomplete="current-password" autofocus>
    </label>
    <button type="submit" class="primary wide">Open console</button>
    <p id="login-error" class="msg error" role="alert"></p>
  </form>
</div>

<div id="shell" class="shell hidden">
  <aside class="rail">
    <a class="brand" href="/"><span class="mark" aria-hidden="true">NM</span>
      <span><b>NMesh</b><span>Console</span></span></a>
    <nav id="nav" class="nav" role="tablist" aria-label="Console sections">
      <button role="tab" data-tab="overview" data-label="Overview" aria-controls="panel-overview" aria-selected="true">Overview</button>
      <button role="tab" data-tab="network" data-label="Network" aria-controls="panel-network" aria-selected="false">Network<span id="nav-peers" class="tail"></span></button>
      <button role="tab" data-tab="apps" data-label="Apps" aria-controls="panel-apps" aria-selected="false">Apps</button>
      <button role="tab" data-tab="settings" data-label="Settings" aria-controls="panel-settings" aria-selected="false">Settings</button>
      <p class="eyebrow nav-label">Applications</p>
      <div id="app-links"></div>
    </nav>
    <div class="rail-foot">
      <div class="rail-state"><span id="rail-dot" class="dot"></span><span id="rail-text">Connecting…</span></div>
      <button id="logout" class="ghost wide">Sign out</button>
    </div>
  </aside>

  <main>
    <header class="topbar">
      <button id="rail-toggle" class="icon rail-toggle" aria-label="Show sections">☰</button>
      <div class="who">
        <span class="badge" id="node-state">…</span>
        <button id="self-node" class="ghost sm mono" title="Show this node's details"></button>
      </div>
      <span class="grow"></span>
      <button id="palette-open" class="ghost sm">Search <span class="kbd">⌘K</span></button>
      <button id="theme-toggle" class="icon" aria-label="Switch theme">☾</button>
    </header>

    <!-- ── Overview ─────────────────────────────────────────────────────── -->
    <section id="panel-overview" class="content panel" role="tabpanel" data-panel="overview">
      <div class="page-head">
        <div class="grow">
          <p class="eyebrow">This node</p>
          <h1 id="overview-title">Reading node status…</h1>
          <p class="lede" id="overview-lede">Health, throughput, and the links this node has authenticated.</p>
        </div>
        <div class="actions">
          <button id="ping-btn">Ping active nodes</button>
          <button id="go-join" class="primary">Add a node</button>
        </div>
      </div>
      <div id="metrics" class="stats"></div>
      <div class="split wide-first">
        <article class="card">
          <div class="card-head"><div class="grow"><h2>Throughput</h2>
            <div class="sub">NMesh packet bytes, excluding transport overhead</div></div>
            <span id="rate-now" class="badge num"></span></div>
          <div class="card-body">
            <canvas id="chart" height="240" aria-label="Inbound and outbound bytes per second"></canvas>
            <div class="row small muted gap-4">
              <span class="row"><i class="dot in"></i>Inbound</span>
              <span class="row"><i class="dot out"></i>Outbound</span>
              <span class="grow"></span><span id="chart-peak" class="num"></span>
            </div>
          </div>
        </article>
        <article class="card">
          <div class="card-head"><div class="grow"><h2>Topology</h2>
            <div class="sub">Direct links, and sessions routed through them</div></div>
            <span id="map-count" class="badge"></span></div>
          <div class="card-body">
            <svg id="graph" viewBox="0 0 420 250" role="img" aria-label="Connected nodes"></svg>
            <p class="tiny muted">Solid: authenticated direct link. Dashed: session routed
              through a first hop — anything deeper is opaque to this node by design.</p>
          </div>
        </article>
      </div>
    </section>

    <!-- ── Network ──────────────────────────────────────────────────────── -->
    <section id="panel-network" class="content panel" role="tabpanel" data-panel="network" hidden>
      <div class="page-head">
        <div class="grow"><p class="eyebrow">Mesh</p><h1>Network</h1>
          <p class="lede">Who this node is connected to, how it can be reached, and how to bring
            another node in.</p></div>
      </div>
      <nav class="subnav" role="tablist" aria-label="Network views">
        <button role="tab" data-subtab="peers" aria-selected="true">Peers</button>
        <button role="tab" data-subtab="reach" aria-selected="false">Reachability</button>
        <button role="tab" data-subtab="join" aria-selected="false">Add a node</button>
      </nav>

      <div data-sub="peers" class="stack">
        <article class="card">
          <div class="card-head"><div class="grow"><h2>Active links <span id="active-count" class="badge"></span></h2>
            <div class="sub">Authenticated, currently open</div></div>
            <label class="search"><span class="sr-only">Search active nodes</span>
              <input id="active-search" type="search" placeholder="Search id, address, transport…" spellcheck="false"></label>
          </div>
          <div class="card-body tight"><div class="table-wrap"><table id="active-table">
            <thead><tr><th>Node</th><th>State</th><th>Transport</th><th class="num">RTT</th><th>Seen</th><th class="tight"></th></tr></thead>
            <tbody id="active-list"></tbody></table></div>
            <div id="active-pager" class="pager"></div></div>
        </article>
        <article class="card">
          <div class="card-head"><div class="grow"><h2>Known nodes <span id="known-count" class="badge"></span></h2>
            <div class="sub">The routing table — reachable, not necessarily connected</div></div>
            <label class="search"><span class="sr-only">Search known nodes</span>
              <input id="known-search" type="search" placeholder="Search id or address…" spellcheck="false"></label>
            <label class="field"><span class="sr-only">Rows per page</span>
              <select id="known-limit" aria-label="Rows per page">
                <option value="10">10 rows</option>
                <option value="20" selected>20 rows</option>
                <option value="50">50 rows</option>
                <option value="100">100 rows</option>
              </select></label>
          </div>
          <div class="card-body tight"><div class="table-wrap"><table>
            <thead><tr><th>Node</th><th>State</th><th>Transport</th><th class="num">RTT</th><th>Seen</th><th class="tight"></th></tr></thead>
            <tbody id="known-list"></tbody></table></div>
            <div id="known-pager" class="pager"></div></div>
        </article>
      </div>

      <div data-sub="reach" class="stack" hidden>
        <article class="card">
          <div class="card-head"><div class="grow"><h2>Reachability</h2>
            <div class="sub">Whether other nodes can open a link to this one</div></div>
            <span id="relay-state" class="badge"></span></div>
          <div class="card-body">
            <div id="network-summary" class="stats"></div>
            <div class="btn-row">
              <button id="reach-probe">Confirm reachability</button>
              <button id="net-recheck">Re-check network</button>
              <button id="punch-toggle"></button>
              <button id="keepalive-toggle"></button>
              <button id="lan-toggle"></button>
            </div>
            <p id="transport-status" class="msg"></p>
          </div>
        </article>
        <article class="card">
          <div class="card-head"><div class="grow"><h2>Transports</h2>
            <div class="sub">Every medium this node can speak, and what is bound</div></div></div>
          <div class="card-body tight"><div class="table-wrap"><table>
            <thead><tr><th>Scheme</th><th class="num">Peers</th><th class="num">Listeners</th><th>Ports</th></tr></thead>
            <tbody id="transport-list"></tbody></table></div></div>
        </article>
        <article class="card">
          <div class="card-head"><div class="grow"><h2>Listeners &amp; addressing</h2>
            <div class="sub">Where this node accepts connections, and what it advertises</div></div></div>
          <div class="card-body">
            <dl id="addressing" class="kv"></dl>
            <div class="toolbar">
              <label class="field grow"><span class="sr-only">Listener URI</span>
                <input id="listen-uri" class="mono" placeholder="tcp://0.0.0.0:9002" spellcheck="false"></label>
              <button id="listen-btn">Add listener</button>
            </div>
            <div id="listener-list" class="chips"></div>
            <div class="toolbar">
              <label class="field"><span>UDP hole punching</span>
                <input id="udp-port" type="number" min="1" max="65535" value="9001" aria-label="UDP port"></label>
              <button id="udp-toggle"></button>
            </div>
          </div>
        </article>
      </div>

      <div data-sub="join" class="stack" hidden>
        <article class="card">
          <div class="card-head"><div class="grow"><h2>Quick join</h2>
            <div class="sub">One short string carrying the address and a single-use code</div></div></div>
          <div class="card-body">
            <div class="notice warn"><span>The ticket <b>is</b> the secret. Anyone who can read it
              can join this mesh until it expires or is used once. Only a node with a confirmed
              public address can issue one — a scanner has nothing else to go on.</span></div>
            <div class="split">
              <div class="stack">
                <h3>Invite someone</h3>
                <label class="field"><span>Valid for</span>
                  <select id="tk-ttl">
                    <option value="60">1 minute</option>
                    <option value="300">5 minutes</option>
                    <option value="600" selected>10 minutes</option>
                    <option value="3600">1 hour</option>
                    <option value="21600">6 hours (maximum)</option>
                  </select></label>
                <button id="tk-make" class="primary">Create join ticket</button>
                <div id="tk-qr" class="qr-holder"></div>
                <div id="tk-out" class="copyable" hidden>
                  <code id="tk-text" class="mono"></code>
                  <button id="tk-copy" class="sm">Copy</button>
                </div>
                <p id="tk-status" class="msg"></p>
              </div>
              <div class="stack">
                <h3>Use a ticket</h3>
                <label class="field"><span>Ticket</span>
                  <textarea id="tk-in" class="mono" rows="3" placeholder="Paste or scan a join ticket…" spellcheck="false"></textarea></label>
                <div class="btn-row">
                  <button id="tk-join" class="primary">Join</button>
                  <button id="tk-scan">Scan with camera</button>
                  <button id="tk-scan-stop" hidden>Stop camera</button>
                </div>
                <video id="tk-video" class="qr-video" hidden muted playsinline></video>
                <p id="tk-scan-status" class="msg"></p>
              </div>
            </div>
          </div>
        </article>
        <details class="card"><summary>Connect two nodes by hand</summary>
          <div class="card-body">
            <p class="muted small">For nodes that cannot see each other yet: three blocks of text,
              moved by whatever channel you already trust.</p>
            <div class="split">
              <div class="stack"><h3>Join someone</h3>
                <button id="cx-request">1 · Create request</button>
                <textarea id="cx-request-out" class="mono" rows="3" readonly placeholder="Send this request block"></textarea>
                <textarea id="cx-reply-in" class="mono" rows="3" placeholder="3 · Paste their reply block"></textarea>
                <button id="cx-complete" class="primary">Connect</button>
              </div>
              <div class="stack"><h3>Accept someone</h3>
                <textarea id="cx-accept-in" class="mono" rows="3" placeholder="Paste their request block"></textarea>
                <button id="cx-accept">2 · Make invite</button>
                <textarea id="cx-accept-out" class="mono" rows="3" readonly placeholder="Send this invite block back"></textarea>
              </div>
            </div>
            <p id="connect-status" class="msg"></p>
          </div>
        </details>
        <details class="card"><summary>Invite through a relay</summary>
          <div class="card-body"><div class="split">
            <div class="stack"><button id="rly-invite">Generate relay invite</button>
              <textarea id="rly-invite-out" class="mono" rows="3" readonly></textarea></div>
            <div class="stack"><textarea id="rly-join-in" class="mono" rows="3" placeholder="Paste a relay invite"></textarea>
              <button id="rly-join" class="primary">Join via relay</button></div>
          </div><p id="relay-status" class="msg"></p></div>
        </details>
        <details class="card"><summary>Invite codes and certificates</summary>
          <div class="card-body">
            <div class="toolbar"><button id="gen-invite">Generate invite code</button>
              <code id="invite-out" class="mono grow"></code></div>
            <div class="toolbar">
              <label class="field grow"><span class="sr-only">Address</span>
                <input id="join-uri" class="mono" placeholder="tcp://host:port" spellcheck="false"></label>
              <label class="field grow"><span class="sr-only">Invite code</span>
                <input id="join-code" class="mono" placeholder="Invite code" spellcheck="false"></label>
              <button id="join-btn">Join</button></div>
            <hr>
            <div class="btn-row"><button id="show-cert">Show our root certificate</button></div>
            <textarea id="cert-out" class="mono" rows="3" readonly></textarea>
            <textarea id="trust-in" class="mono" rows="3" placeholder="Paste a root certificate to trust"></textarea>
            <div class="btn-row"><button id="trust-btn">Trust certificate</button></div>
            <p id="manage-status" class="msg"></p>
          </div>
        </details>
      </div>
    </section>

    <!-- ── Apps ─────────────────────────────────────────────────────────── -->
    <section id="panel-apps" class="content panel" role="tabpanel" data-panel="apps" hidden>
      <div class="page-head">
        <div class="grow"><p class="eyebrow">Software</p><h1>Apps</h1>
          <p class="lede">Built-in applications on this node, and the signed catalog the mesh
            shares. The catalog is browsed page by page — it is never loaded whole.</p></div>
      </div>
      <nav class="subnav" role="tablist" aria-label="App views">
        <button role="tab" data-subtab="installed" aria-selected="true">Installed</button>
        <button role="tab" data-subtab="store" aria-selected="false">App store</button>
      </nav>

      <div data-sub="installed" class="stack">
        <div id="builtin-apps" class="cards"></div>
        <article class="card">
          <div class="card-head"><div class="grow"><h2>Local packages <span id="installed-count" class="badge"></span></h2>
            <div class="sub">Fetched from the catalog and unpacked on this node</div></div>
            <label class="search"><span class="sr-only">Search installed apps</span>
              <input id="installed-search" type="search" placeholder="Search installed…"></label></div>
          <div class="card-body tight"><div class="table-wrap"><table>
            <thead><tr><th>App</th><th>Version</th><th>Id</th><th class="tight"></th></tr></thead>
            <tbody id="installed-list"></tbody></table></div>
            <div id="installed-pager" class="pager"></div></div>
        </article>
      </div>

      <div data-sub="store" class="stack" hidden>
        <article class="card">
          <div class="card-head"><div class="grow"><h2>App store <span id="catalog-count" class="badge"></span></h2>
            <div class="sub">Signed releases published to the mesh</div></div>
            <label class="search"><span class="sr-only">Search catalog</span>
              <input id="catalog-search" type="search" placeholder="Search name, version, id, author…"></label></div>
          <div class="card-body tight"><div class="table-wrap"><table>
            <thead><tr><th>App</th><th>Version</th><th>Id</th><th class="tight"></th></tr></thead>
            <tbody id="catalog-list"></tbody></table></div>
            <div id="catalog-pager" class="pager"></div></div>
        </article>
        <details class="card"><summary>Publish a signed release</summary>
          <div class="card-body">
            <div class="form-grid">
              <label class="field"><span>Name</span><input id="store-name"></label>
              <label class="field"><span>Version</span><input id="store-version" value="1.0.0"></label>
            </div>
            <label class="field"><span>Files</span><input id="store-files" type="file" multiple></label>
            <div class="btn-row"><button id="store-publish-btn" class="primary">Publish to store</button></div>
            <p id="store-status" class="msg"></p>
          </div>
        </details>
      </div>
    </section>

    <!-- ── Settings ─────────────────────────────────────────────────────── -->
    <section id="panel-settings" class="content panel" role="tabpanel" data-panel="settings" hidden>
      <div class="page-head">
        <div class="grow"><p class="eyebrow">Node controls</p><h1>Settings</h1>
          <p class="lede">Everything that changes how this node runs. Kept apart from live status
            so nothing here is a click away from a graph you were only reading.</p></div>
      </div>
      <nav class="subnav" role="tablist" aria-label="Settings sections">
        <button role="tab" data-subtab="updates" aria-selected="true">Updates</button>
        <button role="tab" data-subtab="security" aria-selected="false">Security</button>
        <button role="tab" data-subtab="config" aria-selected="false">Configuration</button>
        <button role="tab" data-subtab="diagnostics" aria-selected="false">Diagnostics</button>
        <button role="tab" data-subtab="advanced" aria-selected="false">Advanced</button>
      </nav>

      <div data-sub="updates" class="stack">
        <article class="card">
          <div class="card-head"><div class="grow"><h2>Software updates</h2>
            <div class="sub">Checks this project's published releases on GitHub</div></div>
            <span id="version-pill" class="badge"></span></div>
          <div class="card-body">
            <p class="muted small">Nothing is installed without you confirming the exact version.
              Applying an update replaces the node's files and restarts it.</p>
            <div class="btn-row">
              <button id="update-check">Check for updates</button>
              <button id="update-apply" class="primary" hidden>Install</button>
            </div>
            <p id="update-status" class="msg"></p>
            <pre id="update-notes" class="block" hidden></pre>
          </div>
        </article>
      </div>

      <div data-sub="security" class="stack" hidden>
        <article class="card">
          <div class="card-head"><div class="grow"><h2>Console password</h2>
            <div class="sub">The only credential between the network and this node's controls</div></div></div>
          <div class="card-body">
            <p class="muted small">Changing it needs the current one, even from a signed-in session:
              a stolen session must never be able to lock you out of your own node. Every other
              session is signed out; this one stays. Lost it entirely?
              Run <code class="inline">./install.sh --reset-password</code> on the machine itself.</p>
            <div class="form-grid">
              <label class="field"><span>Current password</span>
                <input id="pw-current" type="password" autocomplete="current-password"></label>
              <label class="field"><span>New password</span>
                <input id="pw-new" type="password" autocomplete="new-password"></label>
              <label class="field"><span>Repeat new password</span>
                <input id="pw-repeat" type="password" autocomplete="new-password"></label>
            </div>
            <div class="btn-row"><button id="pw-save" class="primary">Change password</button></div>
            <p id="pw-status" class="msg"></p>
          </div>
        </article>
      </div>

      <div data-sub="config" class="stack" hidden>
        <article class="card">
          <div class="card-head"><div class="grow"><h2>Startup configuration</h2>
            <div class="sub">The launch options this node reads from its file</div></div>
            <span id="config-pill" class="badge"></span></div>
          <div class="card-body">
            <p class="muted small">Changes are written to that file and take effect when the node
              restarts — nothing here changes a running node. Options passed on the command line
              still win over the file.</p>
            <p id="config-path" class="msg mono"></p>
            <div id="config-problems" class="notice warn" hidden></div>
            <div id="config-fields" class="form-grid"></div>
            <div class="btn-row">
              <button id="config-save" class="primary">Save configuration</button>
              <button id="config-reload">Reload from file</button>
            </div>
            <p id="config-status" class="msg"></p>
          </div>
        </article>
      </div>

      <div data-sub="diagnostics" class="stack" hidden>
        <article class="card">
          <div class="card-head"><div class="grow"><h2>Protocol trace</h2>
            <div class="sub">What this node actually sends and receives, by message type</div></div>
            <span id="trace-pill" class="badge"></span></div>
          <div class="card-body">
            <p class="muted small">For questions the throughput graph cannot answer — like "why are
              two idle nodes talking at all?". <b>No payload is ever recorded</b>, only routing
              metadata: type, size, TTL and node ids. It lives in memory, is bounded, and stops on
              its own.</p>
            <div class="toolbar">
              <button id="trace-start" class="primary">Start recording</button>
              <button id="trace-stop">Stop</button>
              <label class="field narrow"><span class="sr-only">Seconds</span>
                <input id="trace-seconds" type="number" min="1" max="3600" value="120" aria-label="Seconds to record"></label>
              <span class="grow"></span>
              <button id="trace-export">Download</button>
              <button id="trace-clear">Clear</button>
            </div>
            <p id="trace-status" class="msg"></p>
            <div class="table-wrap"><table>
              <thead><tr><th>Message</th><th class="num">Packets</th><th class="num">Bytes</th><th class="num">Rate</th></tr></thead>
              <tbody id="trace-summary"></tbody></table></div>
          </div>
        </article>
      </div>

      <div data-sub="advanced" class="stack" hidden>
        <article class="card">
          <div class="card-head"><div class="grow"><h2>Content-addressed transfer</h2>
            <div class="sub">Raw DHT package exchange — not the signed app store</div></div></div>
          <div class="card-body">
            <div class="form-grid">
              <label class="field"><span>Name</span><input id="app-name"></label>
              <label class="field"><span>Version</span><input id="app-version" value="1.0.0"></label>
            </div>
            <label class="field"><span>Files</span><input id="app-files" type="file" multiple></label>
            <div class="btn-row"><button id="publish-btn">Publish content</button></div>
            <code id="app-id-out" class="mono"></code>
            <hr>
            <div class="toolbar">
              <label class="field grow"><span class="sr-only">Content id</span>
                <input id="fetch-id" class="mono" placeholder="40-character content id" spellcheck="false"></label>
              <button id="fetch-btn">Fetch</button></div>
            <div id="app-files-out" class="chips"></div>
            <p id="app-status" class="msg"></p>
          </div>
        </article>
      </div>
    </section>
  </main>
</div>

<dialog id="node-dialog" aria-labelledby="node-dialog-title">
  <div class="sheet">
    <header class="sheet-head"><h2 id="node-dialog-title">Node</h2>
      <button id="node-dialog-close" class="icon" aria-label="Close">✕</button></header>
    <div class="sheet-body"><dl id="node-detail-body" class="kv"></dl>
      <p id="detail-status" class="msg"></p></div>
    <footer class="sheet-foot">
      <button id="detail-forget" class="danger">Forget node</button>
      <button id="detail-ping" class="primary">Ping node</button>
    </footer>
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
<script src="/app.js"></script>
</body>
</html>
"""


# Only what is genuinely this page's: the two drawings, the QR holder, and the
# app tiles. Everything else comes from the design system — if something here
# starts to look reusable, it belongs in `ui.py`, not in a second copy.
CONSOLE_PAGE_CSS = """
#chart{width:100%;height:236px;display:block}
.dot.in{background:var(--accent)}
.dot.out{background:var(--warn)}
/* Each card keeps its own height: stretching the shorter one left a hole under
   the graph, and growing the canvas to fill it fed back into the row height. */
#panel-overview .split{align-items:start}
#graph{width:100%;height:auto;max-height:260px}
#graph .edge{stroke:var(--border-strong);stroke-width:1.5}
#graph .edge.routed{stroke-dasharray:3 4;opacity:.75}
#graph .node circle{stroke:var(--surface);stroke-width:2;transition:r var(--speed) var(--ease)}
#graph .node.direct circle{fill:var(--accent)}
#graph .node.routed circle{fill:var(--warn)}
#graph .node.self circle{fill:var(--text)}
#graph .node.self text{fill:var(--text);font-weight:700}
/* Labels sit over the edges: painting the stroke first gives each one a halo of
   the card's own background, so nothing has to be moved out of the way. */
#graph .node text{font:600 9px var(--font);fill:var(--text-muted);text-anchor:middle;
  paint-order:stroke;stroke:var(--surface);stroke-width:3px;stroke-linejoin:round}
#graph .node{cursor:pointer}
#graph .node:hover circle,#graph .node:focus-visible circle{r:13}
#graph .node:focus-visible{outline:none}
#graph .node:focus-visible circle{stroke:var(--ring);stroke-width:2.5}

.qr-holder{display:flex;justify-content:center;padding:var(--s-4);border-radius:var(--r-md);
  background:#fff;border:1px solid var(--border)}
.qr-holder:empty{display:none}
.qr-holder svg{width:min(220px,100%);height:auto}
.qr-video{width:100%;max-height:260px;border-radius:var(--r-md);background:#000;object-fit:cover}

.app-tile{display:flex;flex-direction:column;gap:var(--s-3);padding:var(--s-4);
  background:var(--surface);border:1px solid var(--border);border-radius:var(--r-lg);
  box-shadow:var(--shadow-1)}
.app-tile .top{display:flex;align-items:center;gap:var(--s-3)}
.app-ic{width:34px;height:34px;flex:none;border-radius:10px;display:grid;place-items:center;
  background:var(--accent-soft);color:var(--accent);font:700 var(--fs-xs)/1 var(--font)}
.app-tile h3{flex:1 1 auto;min-width:0}
.app-tile p{font-size:var(--fs-sm);color:var(--text-muted);flex:1 1 auto}
.app-tile .btn-row{margin-top:auto}
"""


CONSOLE_PAGE_JS = r"""
// ── console page ────────────────────────────────────────────────────────────
// Reads /api/state on a timer and paints; every control posts and re-reads.
// Nothing is cached across a reload: what the node says is the truth.

let STATE = null, PREVIOUS = null, POLL = null, TICKING = false;
const RATES = [];                       // ~90 samples, the throughput window

// ---- gate ------------------------------------------------------------------
function showGate(){
  if(POLL){ clearInterval(POLL); POLL = null; }
  $("shell").classList.add("hidden");
  $("login").classList.remove("hidden");
  $("password").focus();
}
function enterConsole(){
  $("login").classList.add("hidden");
  $("shell").classList.remove("hidden");
  ROUTER.start(onRoute);
  tick();
  if(!POLL) POLL = setInterval(tick, 2000);
}
SESSION.onLost = showGate;
SESSION.load();

$("login-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  setMessage("login-error", "");
  const button = event.submitter || $("login-form").querySelector("button");
  await withBusy(button, async () => {
    try{
      const response = await fetch("/api/login", {method:"POST",
        headers:{"Content-Type":"application/json"},
        body: JSON.stringify({password: $("password").value})});
      const data = await response.json().catch(() => ({}));
      if(!response.ok){ setMessage("login-error", data.error || "Login failed", true); return; }
      SESSION.set(data.token);
      $("password").value = "";
      enterConsole();
    }catch(_){ setMessage("login-error", "Console is not reachable", true); }
  });
});
$("logout").addEventListener("click", async () => {
  try{ await api("/api/logout", "POST"); }catch(_){}
  SESSION.clear(); showGate();
});

// ---- polling ---------------------------------------------------------------
function onRoute(section, sub){
  if(section === "network" && sub === "peers") refreshPeers();
  if(section === "apps") refreshApps();
  // Read on entry rather than on a timer: both files can be edited by hand, and
  // a stale form would offer to save values they no longer hold.
  if(section === "settings" && sub === "config") loadConfig();
  if(section === "settings" && sub === "diagnostics") loadTrace();
}
async function tick(){
  if(TICKING) return;
  TICKING = true;
  try{
    const response = await api("/api/state");
    if(!response.ok) return;
    STATE = await response.json();
    trackRates(STATE);
    paintHeader(STATE); paintMetrics(STATE); drawChart(); drawGraph(STATE);
    paintApps(STATE); paintReach(STATE);
  }catch(_){
    $("rail-dot").className = "dot danger";
    $("rail-text").textContent = "Console unreachable";
  }finally{ TICKING = false; }
}
function trackRates(state){
  let inbound = 0, outbound = 0;
  const restarted = !PREVIOUS || PREVIOUS.id !== state.id || state.uptime < PREVIOUS.uptime ||
    state.total.bytes_in < PREVIOUS.bytes_in || state.total.bytes_out < PREVIOUS.bytes_out;
  if(!restarted){
    const elapsed = state.server_time - PREVIOUS.time;
    if(elapsed > 0){
      inbound = (state.total.bytes_in - PREVIOUS.bytes_in) / elapsed;
      outbound = (state.total.bytes_out - PREVIOUS.bytes_out) / elapsed;
    }
  }else RATES.length = 0;
  PREVIOUS = {id:state.id, uptime:state.uptime, time:state.server_time,
              bytes_in:state.total.bytes_in, bytes_out:state.total.bytes_out};
  RATES.push({inbound:Math.max(0,inbound), outbound:Math.max(0,outbound)});
  while(RATES.length > 90) RATES.shift();
  state._rates = {inbound, outbound};
}

// ---- header and metrics ----------------------------------------------------
function paintHeader(state){
  const peers = state.authenticated_peers || 0;
  $("self-node").textContent = shortId(state.id);
  $("self-node").title = state.id;
  const pill = $("node-state");
  pill.textContent = state.running ? "Running · up " + fmtDuration(state.uptime) : "Stopped";
  pill.className = "badge " + (state.running ? "ok" : "danger");
  $("rail-dot").className = "dot " + (state.running ? (peers ? "live" : "ok") : "danger");
  $("rail-text").textContent = state.running
    ? (peers ? peers + " link" + (peers === 1 ? "" : "s") + " up" : "Online, no peers")
    : "Node stopped";
  $("nav-peers").textContent = peers || "";
  $("overview-title").textContent = peers
    ? "Connected to " + peers + " node" + (peers === 1 ? "" : "s")
    : "Looking for a neighbour";
  $("overview-lede").textContent = peers
    ? "Health, throughput, and the links this node has authenticated."
    : "This node is running but has no authenticated link yet. Add one from Network → Add a node.";
}
function paintMetrics(state){
  const load = state.load || {};
  const cards = [
    ["Active links", state.authenticated_peers || 0, "accent"],
    ["Known nodes", state.routing_size || 0, ""],
    ["E2E sessions", (state.e2e_sessions || []).length, ""],
    ["Inbound", fmtRate(state._rates.inbound), ""],
    ["Outbound", fmtRate(state._rates.outbound), ""],
    ["CPU", load.cpu_percent == null ? "—" : Math.round(load.cpu_percent) + "%", ""],
    ["Memory", fmtBytes(load.rss_bytes), ""],
  ];
  $("metrics").innerHTML = cards.map(([label, value, tone]) =>
    '<div class="stat ' + tone + '"><span class="v">' + esc(value) +
    '</span><span class="k">' + esc(label) + "</span></div>").join("");
  $("rate-now").textContent = fmtRate(state._rates.inbound) + " in · " +
    fmtRate(state._rates.outbound) + " out";
}

// ---- throughput ------------------------------------------------------------
// Drawn from the theme's own variables, so the graph follows the theme instead
// of being a dark rectangle in a light page.
// `getPropertyValue` hands back the token's *text*, which for a semantic token
// is another `var(...)` — something canvas cannot paint. Bouncing it through a
// real element makes the browser resolve it to an actual colour.
const PROBE = document.createElement("span");
PROBE.style.display = "none";
document.body.appendChild(PROBE);
function cssColour(name){
  PROBE.style.color = "var(" + name + ")";
  return getComputedStyle(PROBE).color || "#888";
}
function withAlpha(colour, alpha){
  const parts = colour.match(/[\d.]+/g);
  return parts && parts.length >= 3
    ? "rgba(" + parts[0] + "," + parts[1] + "," + parts[2] + "," + alpha + ")" : colour;
}
function drawChart(){
  const canvas = $("chart");
  if(!canvas.clientWidth) return;
  const ratio = window.devicePixelRatio || 1;
  const width = canvas.clientWidth, height = Math.max(160, canvas.clientHeight);
  if(canvas.width !== Math.floor(width * ratio) || canvas.height !== Math.floor(height * ratio)){
    canvas.width = Math.floor(width * ratio); canvas.height = Math.floor(height * ratio);
  }
  const context = canvas.getContext("2d");
  context.setTransform(ratio, 0, 0, ratio, 0, 0);
  context.clearRect(0, 0, width, height);

  const grid = cssColour("--border"), accent = cssColour("--accent"), warn = cssColour("--warn");
  const peak = Math.max(1, ...RATES.flatMap((point) => [point.inbound, point.outbound]));
  $("chart-peak").textContent = RATES.length ? "peak " + fmtRate(peak) : "";

  context.strokeStyle = grid; context.lineWidth = 1;
  for(let row = 0; row <= 4; row++){
    const y = Math.round(row * (height - 16) / 4) + 8.5;
    context.beginPath(); context.moveTo(0, y); context.lineTo(width, y); context.stroke();
  }
  const at = (index) => index * width / Math.max(1, RATES.length - 1);
  const level = (value) => height - 8 - value * (height - 24) / peak;
  const draw = (key, colour) => {
    if(RATES.length < 2) return;
    context.beginPath();
    RATES.forEach((point, index) => {
      const x = at(index), y = level(point[key]);
      index ? context.lineTo(x, y) : context.moveTo(x, y);
    });
    const fill = context.createLinearGradient(0, 0, 0, height);
    fill.addColorStop(0, withAlpha(colour, .28)); fill.addColorStop(1, withAlpha(colour, 0));
    context.strokeStyle = colour; context.lineWidth = 2; context.lineJoin = "round";
    context.stroke();
    context.lineTo(at(RATES.length - 1), height); context.lineTo(0, height); context.closePath();
    context.fillStyle = fill; context.fill();
  };
  draw("inbound", accent); draw("outbound", warn);
}
window.addEventListener("resize", debounce(drawChart, 120));

// ---- topology --------------------------------------------------------------
const SVG_NS = "http://www.w3.org/2000/svg";
function svgEl(name, attrs){
  const node = document.createElementNS(SVG_NS, name);
  Object.entries(attrs || {}).forEach(([key, value]) => node.setAttribute(key, String(value)));
  return node;
}
function drawGraph(state){
  const svg = $("graph");
  svg.replaceChildren();
  const topology = state.topology || {}, direct = topology.direct || [], routed = topology.routed || [];
  const centre = {x:210, y:120}, place = new Map();
  direct.forEach((node, index) => {
    // Half a step off the top, so the centre node's own label has room.
    const step = Math.PI * 2 / Math.max(1, direct.length);
    const angle = step * index - Math.PI / 2 + step / 2;
    place.set(node.id, {x:centre.x + Math.cos(angle) * 96, y:centre.y + Math.sin(angle) * 58});
  });
  routed.forEach((node, index) => {
    const step = Math.PI * 2 / Math.max(1, routed.length);
    const angle = step * index - Math.PI / 2 + step / 2 + .3;
    place.set(node.id, {x:centre.x + Math.cos(angle) * 168, y:centre.y + Math.sin(angle) * 100});
  });
  direct.forEach((node) => {
    const point = place.get(node.id);
    svg.appendChild(svgEl("line", {x1:centre.x, y1:centre.y, x2:point.x, y2:point.y, class:"edge"}));
  });
  routed.forEach((node) => {
    const from = place.get(node.via) || centre, to = place.get(node.id);
    svg.appendChild(svgEl("line", {x1:from.x, y1:from.y, x2:to.x, y2:to.y, class:"edge routed"}));
  });
  const dot = (id, point, kind, label) => {
    const group = svgEl("g", {class:"node " + kind, tabindex:"0", role:"button",
                              "data-node-id":id, "aria-label":label});
    group.appendChild(svgEl("circle", {cx:point.x, cy:point.y, r:kind === "self" ? 12 : 9}));
    const text = svgEl("text", {x:point.x, y:point.y + (kind === "self" ? 27 : 20)});
    text.textContent = kind === "self" ? "this node" : shortId(id);
    group.appendChild(text);
    svg.appendChild(group);
  };
  direct.forEach((node) => dot(node.id, place.get(node.id), "direct", "Direct link to " + node.id));
  routed.forEach((node) => dot(node.id, place.get(node.id), "routed",
                               "Routed session with " + node.id + " via " + node.via));
  dot(state.id, centre, "self", "This node");
  if(!direct.length && !routed.length){
    const text = svgEl("text", {x:centre.x, y:centre.y + 46, class:"lonely"});
    text.setAttribute("fill", "var(--text-faint)");
    text.setAttribute("text-anchor", "middle");
    text.textContent = "no links yet";
    svg.appendChild(text);
  }
  $("map-count").textContent = direct.length + " direct" +
    (routed.length ? " · " + routed.length + " routed" : "");
}
$("graph").addEventListener("click", (event) => {
  const node = event.target.closest && event.target.closest("[data-node-id]");
  if(node) openNode(node.dataset.nodeId);
});
$("graph").addEventListener("keydown", (event) => {
  if(!["Enter", " "].includes(event.key)) return;
  const node = event.target.closest("[data-node-id]");
  if(node){ openNode(node.dataset.nodeId); event.preventDefault(); }
});
$("self-node").addEventListener("click", () => STATE &&
  openNode(STATE.id, {id:STATE.id, connected:true, self:true, addresses:STATE.advertised || []}));

// ---- paged lists -----------------------------------------------------------
// One paging implementation for peers, packages and catalog: same controls,
// same empty states, same failure text.
const PAGES = {
  active:{scope:"active", query:"", limit:20, offset:0, total:0},
  known:{scope:"known", query:"", limit:20, offset:0, total:0},
  catalog:{query:"", limit:20, offset:0, total:0},
  installed:{query:"", limit:20, offset:0, total:0},
};
const PAGE_URL = {catalog:"/api/store/catalog", installed:"/api/store/installed"};
async function fetchPage(kind){
  const page = PAGES[kind];
  const params = new URLSearchParams({q:page.query, limit:String(page.limit),
                                      offset:String(page.offset)});
  if(page.scope) params.set("scope", page.scope);
  const response = await api((PAGE_URL[kind] || "/api/nodes") + "?" + params.toString());
  if(!response.ok) throw new Error("list failed");
  const data = await response.json();
  page.total = data.total;
  return data.items || [];
}
function paintPager(kind, id, redraw){
  const page = PAGES[kind], element = $(id);
  const first = page.total ? page.offset + 1 : 0;
  const last = Math.min(page.total, page.offset + page.limit);
  element.innerHTML = '<span class="grow num">' + first + "–" + last + " of " + page.total +
    '</span><button class="sm" data-page="prev"' + (page.offset === 0 ? " disabled" : "") +
    '>Previous</button><button class="sm" data-page="next"' +
    (page.offset + page.limit >= page.total ? " disabled" : "") + ">Next</button>";
  element.onclick = (event) => {
    const direction = event.target.dataset.page;
    if(!direction) return;
    page.offset = direction === "next" ? page.offset + page.limit
                                       : Math.max(0, page.offset - page.limit);
    redraw();
  };
}
function spanRow(columns, html){
  return '<tr><td colspan="' + columns + '" class="flush">' + html + "</td></tr>";
}

// ---- peers -----------------------------------------------------------------
async function refreshPeers(){
  await Promise.all([paintNodes("active"), paintNodes("known")]);
}
async function paintNodes(kind){
  const body = $(kind + "-list");
  if(!body.childElementCount) body.innerHTML = spanRow(6, skeletonHTML(3));
  try{
    const items = await fetchPage(kind);
    $(kind + "-count").textContent = PAGES[kind].total;
    body.innerHTML = items.length ? items.map((node) => {
      const transport = node.transport ||
        ((node.addresses || [])[0] || "").split(":", 1)[0] || "—";
      const tone = node.connected ? "ok" : (node.has_key ? "" : "warn");
      const label = node.connected ? "authenticated" : (node.has_key ? "key known" : "no key");
      return '<tr data-clickable data-node-id="' + esc(node.id) + '">' +
        '<td class="mono">' + esc(shortId(node.id)) + "</td>" +
        "<td>" + badge(label, tone) + "</td>" +
        "<td>" + esc(transport) + "</td>" +
        '<td class="num">' + (node.rtt_ms == null ? "—" : esc(node.rtt_ms) + " ms") + "</td>" +
        "<td>" + (node.seen_ago == null ? "live" : esc(fmtAgo(node.seen_ago))) + "</td>" +
        '<td class="tight"><button class="sm" data-node-id="' + esc(node.id) +
        '">Details</button></td></tr>';
    }).join("") : spanRow(6, emptyHTML(
      PAGES[kind].query ? "No node matches that" :
        kind === "active" ? "No authenticated link yet" : "No known node yet",
      PAGES[kind].query ? "Try a shorter prefix of the id, or an address." :
        kind === "active" ? "Add one from Network → Add a node."
                          : "Nodes appear here once this one has heard of them."));
    paintPager(kind, kind + "-pager", () => paintNodes(kind));
  }catch(_){
    body.innerHTML = spanRow(6, errorHTML("Node list unavailable",
      "The console could not read the routing table just now."));
  }
}
["active-list", "known-list"].forEach((id) => $(id).addEventListener("click", (event) => {
  const row = event.target.closest("[data-node-id]");
  if(row) openNode(row.dataset.nodeId);
}));
$("active-search").addEventListener("input", debounce(() => {
  PAGES.active.query = $("active-search").value.trim(); PAGES.active.offset = 0; paintNodes("active");
}));
$("known-search").addEventListener("input", debounce(() => {
  PAGES.known.query = $("known-search").value.trim(); PAGES.known.offset = 0; paintNodes("known");
}));
$("known-limit").addEventListener("change", () => {
  PAGES.known.limit = Math.max(1, Math.min(100, parseInt($("known-limit").value, 10) || 20));
  PAGES.known.offset = 0;
  paintNodes("known");
});
$("ping-btn").addEventListener("click", (event) => withBusy(event.target, async () => {
  try{
    const {data} = await apiJson("/api/ping", "POST");
    toast("Sent " + (data.sent || 0) + " probe(s)");
    setTimeout(tick, 800);
  }catch(_){ toast("Ping failed", "danger"); }
}));
$("go-join").addEventListener("click", () => ROUTER.go("network", "join"));

// ---- node details ----------------------------------------------------------
let DETAIL_ID = null;
async function exactNode(scope, id){
  const params = new URLSearchParams({scope, q:id, limit:"20", offset:"0"});
  const response = await api("/api/nodes?" + params.toString());
  if(!response.ok) return null;
  return (await response.json()).items.find((item) => item.id === id) || null;
}
async function openNode(id, seed){
  DETAIL_ID = id;
  const dialog = $("node-dialog");
  if(!dialog.open) dialog.showModal();
  $("node-dialog-title").textContent = shortId(id);
  $("node-detail-body").innerHTML = "<dt>Status</dt><dd>Loading…</dd>";
  setMessage("detail-status", "");
  let known = null, active = null;
  if(STATE && id !== STATE.id)
    [known, active] = await Promise.all([exactNode("known", id).catch(() => null),
                                         exactNode("active", id).catch(() => null)]);
  const node = Object.assign({}, known || {}, active || {}, seed || {}, {id});
  const addresses = node.addresses || [];
  const rows = [
    ["Node id", '<span class="mono">' + esc(id) + "</span>"],
    ["Relationship", node.self ? "This console's node" : active ? "Authenticated direct link"
      : known ? "Known routing identity" : "Routed session endpoint"],
    ["Session", node.has_session === false ? "Not established"
      : active ? "Open" : node.self ? "Local" : "Not directly observed"],
    ["Direction", node.self ? "Local" : node.is_client_side == null ? "Unknown"
      : node.is_client_side ? "Outbound" : "Inbound"],
    ["Transport", esc(node.transport || "Unknown")],
    ["Round trip", node.rtt_ms == null ? "Not measured" : esc(node.rtt_ms) + " ms"],
    ["Last seen", node.seen_ago == null ? "Live" : esc(fmtAgo(node.seen_ago))],
    ["Identity key", node.has_key == null ? "Unknown" : node.has_key ? "Known" : "Missing"],
    ["Malformed input", node.malformed == null ? "—" : esc(node.malformed)],
    ["Traffic", node.counters ? esc(fmtBytes(node.counters.bytes_in)) + " in / " +
      esc(fmtBytes(node.counters.bytes_out)) + " out" : "—"],
    ["Addresses", addresses.length
      ? addresses.map((address) => '<div class="mono">' + esc(address) + "</div>").join("")
      : "None advertised"],
  ];
  $("node-detail-body").innerHTML = rows.map(([key, value]) =>
    "<dt>" + key + "</dt><dd>" + value + "</dd>").join("");
  $("detail-ping").hidden = !!node.self;
  $("detail-forget").hidden = !!node.self;
}
$("node-dialog-close").addEventListener("click", () => $("node-dialog").close());
$("detail-ping").addEventListener("click", (event) => withBusy(event.target, async () => {
  if(!DETAIL_ID) return;
  setMessage("detail-status", "Pinging through the mesh…");
  try{
    const {data} = await apiJson("/api/ping/node", "POST", {id:DETAIL_ID});
    setMessage("detail-status", data.reachable
      ? "Reachable in " + (data.rtt_ms == null ? "an unknown time" : data.rtt_ms + " ms") +
        " via " + (data.via || "the mesh")
      : "Node is currently unreachable", !data.reachable);
    tick();
  }catch(_){ setMessage("detail-status", "Ping failed", true); }
}));
$("detail-forget").addEventListener("click", async () => {
  if(!DETAIL_ID) return;
  const agreed = await confirmAction({
    title:"Forget this node?",
    body:'<p class="muted small">It is removed from the routing table and disconnected. ' +
      "It can reappear on its own if it contacts this node again.</p>" +
      '<p class="mono small">' + esc(DETAIL_ID) + "</p>",
    confirmLabel:"Forget node", danger:true});
  if(!agreed) return;
  await withBusy($("detail-forget"), async () => {
    try{
      const {ok, data} = await apiJson("/api/nodes/forget", "POST", {id:DETAIL_ID});
      if(ok && data.ok){
        $("node-dialog").close();
        toast("Node forgotten");
        await Promise.all([refreshPeers(), tick()]);
      }else setMessage("detail-status", data.error || "Node not found", true);
    }catch(_){ setMessage("detail-status", "Forget failed", true); }
  });
});

// ---- reachability ----------------------------------------------------------
function paintReach(state){
  const network = state.network || {};
  const relay = $("relay-state");
  relay.textContent = state.relay_capable ? "Relay capable" : "Client reachability";
  relay.className = "badge " + (state.relay_capable ? "ok" : "");
  const summary = [
    ["Internet", network.internet == null ? "Checking…" : network.internet ? "Online" : "Offline"],
    ["Public IP", network.public_ip || "Unknown"],
    ["Public UDP", network.stun_addr || "Unknown"],
    ["Pending seeks", state.pending_seeks || 0],
  ];
  $("network-summary").innerHTML = summary.map(([key, value]) =>
    '<div class="stat sm"><span class="v">' + esc(value) +
    '</span><span class="k">' + esc(key) + "</span></div>").join("");
  const transports = state.transport_details || [];
  $("transport-list").innerHTML = transports.length ? transports.map((transport) =>
    "<tr><td><b>" + esc(transport.scheme) + "</b></td>" +
    '<td class="num">' + esc(transport.peers || 0) + "</td>" +
    '<td class="num">' + (transport.listening || []).length + "</td>" +
    "<td>" + ((transport.ports || []).length ? esc(transport.ports.join(", ")) : "—") +
    "</td></tr>").join("")
    : spanRow(4, emptyHTML("No transport registered",
        "A node with no transport can neither listen nor dial."));
  const udpOn = transports.some((transport) => transport.hole_punch);
  $("punch-toggle").textContent = "Hole punching: " + (state.punch_enabled ? "on" : "off");
  $("keepalive-toggle").textContent = "NAT keepalive: " + (state.punch_keepalive ? "on" : "off");
  $("lan-toggle").textContent = "LAN discovery: " + (state.lan_discovery ? "on" : "off");
  $("udp-toggle").textContent = udpOn ? "Stop UDP" : "Start UDP";
  $("udp-port").disabled = udpOn;
  $("addressing").innerHTML = [
    ["Advertised", (state.advertised || []).join("\n") || "None"],
    ["Local IPs", (state.local_ips || []).join(", ") || "None"],
    ["Schemes", (state.transports || []).join(", ") || "None"],
  ].map(([key, value]) => "<dt>" + esc(key) + '</dt><dd class="mono pre">' +
    esc(value) + "</dd>").join("");
  $("listener-list").innerHTML = (state.listening || []).map((uri) =>
    '<span class="chip">' + esc(uri) + '<button class="icon sm" data-remove-listener="' +
    esc(uri) + '" aria-label="Remove listener ' + esc(uri) + '">✕</button></span>').join("") ||
    '<span class="small muted">No listener bound.</span>';
}
async function post(path, body, message){
  try{
    const response = await api(path, "POST", body);
    if(!response.ok) throw new Error();
    toast(message);
    tick();
    return true;
  }catch(_){ toast("Control action failed", "danger"); return false; }
}
$("punch-toggle").addEventListener("click", () => STATE &&
  post("/api/punch", {enabled:!STATE.punch_enabled}, "Hole punching updated"));
$("keepalive-toggle").addEventListener("click", () => STATE &&
  post("/api/punch/keepalive", {enabled:!STATE.punch_keepalive}, "NAT keepalive updated"));
$("lan-toggle").addEventListener("click", () => STATE &&
  post("/api/lan/discovery", {enabled:!STATE.lan_discovery}, "LAN discovery updated"));
$("net-recheck").addEventListener("click", () => post("/api/net/recheck", {}, "Network check requested"));
$("reach-probe").addEventListener("click", (event) => withBusy(event.target, async () => {
  try{
    const {data} = await apiJson("/api/reachability/probe", "POST");
    toast(data.sent ? "Sent " + data.sent + " reachability probe(s)"
                    : "No active peer can probe us", data.sent ? "" : "warn");
  }catch(_){ toast("Probe failed", "danger"); }
}));
$("udp-toggle").addEventListener("click", () => {
  if(!STATE) return;
  const on = (STATE.transport_details || []).some((item) => item.hole_punch);
  const port = parseInt($("udp-port").value, 10);
  if(!on && !(port > 0 && port < 65536)){ toast("Enter a valid UDP port", "warn"); return; }
  post("/api/udp", on ? {action:"stop"} : {action:"start", port}, on ? "UDP stopped" : "UDP started");
});
$("listen-btn").addEventListener("click", (event) => withBusy(event.target, async () => {
  const uri = $("listen-uri").value.trim();
  if(!uri){ toast("Enter a listener URI", "warn"); return; }
  const {ok, data} = await apiJson("/api/listen", "POST", {uri});
  if(ok){ $("listen-uri").value = ""; toast("Listener added"); tick(); }
  else toast(data.error || "Listener failed", "danger");
}));
$("listener-list").addEventListener("click", async (event) => {
  const uri = event.target.closest("[data-remove-listener]");
  if(!uri) return;
  await api("/api/unlisten", "POST", {uri:uri.dataset.removeListener}).catch(() => {});
  toast("Listener removed");
  tick();
});

// ---- apps ------------------------------------------------------------------
function paintApps(state){
  const apps = state.apps || [];
  $("builtin-apps").innerHTML = apps.length ? apps.map(appTile).join("")
    : emptyHTML("No built-in app", "This build ships without optional applications.");
  $("app-links").innerHTML = apps.filter((app) => app.running !== false && app.installed)
    .map((app) => '<a href="' + esc(app.path) + '">' + esc(app.name) + "</a>").join("");
}
function appTile(app){
  const known = typeof app.enabled === "boolean";
  const state = !app.installed ? ["Not installed", ""]
    : app.running ? ["Running", "ok"] : [app.enabled ? "Starting…" : "Stopped", "warn"];
  const action = !app.installed ? "install" : (app.enabled ? "disable" : "enable");
  const label = !app.installed ? "Install" : (app.enabled ? "Disable" : "Enable");
  const buttons = [];
  if(known) buttons.push('<button class="' + (app.enabled ? "" : "primary") +
    '" data-builtin-id="' + esc(app.id) + '" data-builtin-action="' + action + '">' + label + "</button>");
  if(known && app.installed) buttons.push('<button class="danger" data-builtin-id="' +
    esc(app.id) + '" data-builtin-action="uninstall">Uninstall</button>');
  if(app.running !== false) buttons.push('<a class="btn" href="' + esc(app.path) + '">Open</a>');
  return '<article class="app-tile"><div class="top">' +
    '<span class="app-ic" aria-hidden="true">' + esc((app.name || "A").slice(0, 2).toUpperCase()) +
    "</span><h3>" + esc(app.name) + "</h3>" + badge(state[0], state[1]) + "</div>" +
    "<p>" + esc(app.description || "Built-in application.") + "</p>" +
    '<div class="btn-row">' + buttons.join("") + "</div></article>";
}
$("builtin-apps").addEventListener("click", async (event) => {
  const button = event.target.closest("[data-builtin-action]");
  if(!button) return;
  const action = button.dataset.builtinAction, id = button.dataset.builtinId;
  if(action === "uninstall"){
    const agreed = await confirmAction({
      title:"Uninstall " + id + "?",
      body:'<p class="muted small">Its stored state on this node is erased. Anything that app ' +
        "keeps — conversations, fleet grants, uploaded keys — goes with it.</p>",
      confirmLabel:"Uninstall", danger:true});
    if(!agreed) return;
  }
  await withBusy(button, async () => {
    try{
      const {ok, data} = await apiJson("/api/apps/" + action, "POST", {id});
      if(ok && data.ok !== false){
        toast(id + " " + action + "d");
        if(data.apps && STATE) STATE.apps = data.apps;
      }else toast(data.error || (action + " failed"), "danger");
    }catch(_){ toast(action + " failed", "danger"); }
    finally{ if(STATE) paintApps(STATE); }
  });
});
async function refreshApps(){
  if(ROUTER.section !== "apps") return;
  await paintAppList(ROUTER.sub === "store" ? "catalog" : "installed");
}
async function paintAppList(kind){
  const body = $(kind + "-list");
  if(!body.childElementCount) body.innerHTML = spanRow(4, skeletonHTML(3));
  try{
    const items = await fetchPage(kind);
    $(kind + "-count").textContent = PAGES[kind].total;
    body.innerHTML = items.length ? items.map((app) => {
      const action = kind === "installed" ? "uninstall" : app.action;
      const cell = action
        ? '<button class="' + (action === "uninstall" ? "danger" : "primary") +
          ' sm" data-app-id="' + esc(app.app_id) + '" data-app-action="' + esc(action) + '">' +
          (action === "uninstall" ? "Delete" : action === "update" ? "Update" : "Install") + "</button>"
        : badge("Installed", "ok");
      return "<tr><td><b>" + esc(app.name) + "</b></td><td>" + esc(app.version) + "</td>" +
        '<td class="mono" title="' + esc(app.app_id) + '">' + esc(shortId(app.app_id)) + "</td>" +
        '<td class="tight">' + cell + "</td></tr>";
    }).join("") : spanRow(4, emptyHTML(
      PAGES[kind].query ? "Nothing matches that"
        : kind === "installed" ? "No local package" : "The catalog is empty",
      kind === "installed" ? "Install one from the App store tab."
        : "Releases published by any node on this mesh appear here."));
    paintPager(kind, kind + "-pager", () => paintAppList(kind));
  }catch(_){
    body.innerHTML = spanRow(4, errorHTML("App list unavailable",
      "The catalog could not be read just now."));
  }
}
$("installed-search").addEventListener("input", debounce(() => {
  PAGES.installed.query = $("installed-search").value.trim();
  PAGES.installed.offset = 0; paintAppList("installed");
}));
$("catalog-search").addEventListener("input", debounce(() => {
  PAGES.catalog.query = $("catalog-search").value.trim();
  PAGES.catalog.offset = 0; paintAppList("catalog");
}));
[$("catalog-list"), $("installed-list")].forEach((list) => list.addEventListener("click",
  async (event) => {
    const button = event.target.closest("[data-app-action]");
    if(!button) return;
    const action = button.dataset.appAction, appId = button.dataset.appId;
    if(action === "uninstall"){
      const agreed = await confirmAction({title:"Delete this app from this node?",
        body:'<p class="muted small">The mesh catalog is not changed — it can be installed again.</p>',
        confirmLabel:"Delete", danger:true});
      if(!agreed) return;
    }
    await withBusy(button, async () => {
      try{
        const {ok, data} = await apiJson("/api/store/" + action, "POST", {app_id:appId});
        toast(ok && data.ok !== false
          ? (action === "uninstall" ? "Local app deleted" : action + " complete")
          : (data.error || action + " failed"), ok && data.ok !== false ? "" : "danger");
      }catch(_){ toast(action + " failed", "danger"); }
      finally{ await refreshApps(); }
    });
  }));
function fileToBase64(file){
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result).split(",")[1] || "");
    reader.onerror = reject;
    reader.readAsDataURL(file);
  });
}
async function selectedFiles(input){
  const files = {};
  for(const file of input.files) files[file.name] = await fileToBase64(file);
  return files;
}
$("store-publish-btn").addEventListener("click", (event) => withBusy(event.target, async () => {
  const name = $("store-name").value.trim();
  const version = $("store-version").value.trim() || "1.0.0";
  const input = $("store-files");
  if(!name || !input.files.length){
    setMessage("store-status", "A name and at least one file are required.", true); return;
  }
  setMessage("store-status", "Reading and signing files…");
  try{
    const {ok, data} = await apiJson("/api/store/publish", "POST",
      {name, version, files:await selectedFiles(input)});
    setMessage("store-status", ok ? "Release published to the mesh." : (data.error || "Publish failed"), !ok);
    if(ok){ input.value = ""; toast("Published " + name + " " + version); }
  }catch(_){ setMessage("store-status", "Publish failed", true); }
  finally{ await paintAppList("catalog"); }
}));

// ---- updates ---------------------------------------------------------------
let UPDATE_OFFER = null;                  // the exact release on screen
async function checkForUpdates(event){
  await withBusy(event.target, async () => {
    const status = $("update-status"), notes = $("update-notes");
    status.textContent = "Asking GitHub…";
    $("update-apply").hidden = true; notes.hidden = true; UPDATE_OFFER = null;
    try{
      const {data} = await apiJson("/api/update/check");
      if(data.error){ status.textContent = data.error; return; }
      if(!data.available){
        status.textContent = "Up to date — running " + data.current + ", latest is " + data.latest + ".";
        return;
      }
      if(!data.can_apply){
        status.textContent = data.latest + " is available, but this install cannot update itself: " +
          data.blocked;
        return;
      }
      UPDATE_OFFER = data.latest;
      status.textContent = data.latest + " is available (you run " + data.current + ").";
      if(data.notes){ notes.textContent = data.notes; notes.hidden = false; }
      const apply = $("update-apply");
      apply.textContent = "Install " + data.latest;
      apply.hidden = false;
    }catch(_){ status.textContent = "Could not check for updates."; }
  });
}
async function applyUpdate(event){
  if(!UPDATE_OFFER) return;
  // The version is named in the confirmation *and* in the request: the node
  // refuses to install anything other than what was on screen.
  const agreed = await confirmAction({
    title:"Install " + UPDATE_OFFER + "?",
    body:'<p class="muted small">The node replaces its own files and restarts. The previous ' +
      "files are kept, so a bad release can be rolled back on the machine itself.</p>",
    confirmLabel:"Install " + UPDATE_OFFER});
  if(!agreed) return;
  await withBusy(event.target, async () => {
    const status = $("update-status");
    status.textContent = "Downloading and installing " + UPDATE_OFFER + "…";
    try{
      const {ok, data} = await apiJson("/api/update/apply", "POST",
        {version:UPDATE_OFFER, confirm:true});
      if(!ok){ status.textContent = data.error || "Update failed."; return; }
      status.textContent = data.service_managed
        ? "Installed " + data.applied + ". The node is restarting — reload this page in a moment."
        : "Installed " + data.applied + ". Restart the node to run it (previous files in " +
          data.backup + ").";
      $("update-apply").hidden = true;
      UPDATE_OFFER = null;
    }catch(_){ status.textContent = "Update failed."; }
  });
}
$("update-check").addEventListener("click", checkForUpdates);
$("update-apply").addEventListener("click", applyUpdate);

// ---- configuration file ----------------------------------------------------
// The form is built from what the node reports, never from a list hard-coded
// here: a setting added on the node side shows up on its own, and one the node
// refuses to expose cannot be typed into existence from this page.
let CONFIG_FIELDS = [];
const configFieldId = (name) => "cfg-" + name.replace(/_/g, "-");

function paintConfig(data){
  const fields = $("config-fields"), pill = $("config-pill"), problems = $("config-problems");
  fields.innerHTML = ""; CONFIG_FIELDS = [];
  if(!data || !data.available){
    pill.textContent = "unavailable"; pill.className = "badge";
    $("config-path").textContent = (data && data.reason) || "No configuration file for this node.";
    $("config-save").disabled = true; $("config-reload").disabled = true;
    return;
  }
  pill.textContent = "restart to apply"; pill.className = "badge warn";
  $("config-path").textContent = data.path;
  $("config-save").disabled = false; $("config-reload").disabled = false;
  if(data.problems && data.problems.length){
    problems.textContent = "Problems in the file: " + data.problems.join(" · ");
    problems.hidden = false;
  }else problems.hidden = true;
  for(const setting of data.settings || []){
    CONFIG_FIELDS.push(setting);
    const id = configFieldId(setting.name);
    const label = document.createElement("label");
    label.className = "field";
    const title = document.createElement("span");
    title.textContent = setting.name.replace(/_/g, " ") + (setting.editable ? "" : " (file only)");
    label.appendChild(title);
    let input;
    if(setting.kind === "bool"){
      input = document.createElement("input"); input.type = "checkbox";
      input.checked = !!setting.value;
      label.className = "check";
      label.replaceChildren(input, title);
    }else if(setting.kind === "list"){
      input = document.createElement("textarea");
      input.className = "mono"; input.rows = 3;
      input.value = (setting.value || []).join("\n");
      label.appendChild(input);
    }else{
      input = document.createElement("input");
      input.type = setting.kind === "int" ? "number" : "text";
      if(setting.kind === "int"){ input.min = 1; input.max = 65535; }
      input.value = setting.value == null ? "" : String(setting.value);
      label.appendChild(input);
    }
    input.id = id;
    // Not editable here means not editable here: `launch` chooses what the node
    // executes, and `data` is the installer's business.
    if(!setting.editable) input.disabled = true;
    const help = document.createElement("small");
    help.className = "hint";
    help.textContent = setting.help + (setting.flag ? "  ·  " + setting.flag : "");
    label.appendChild(help);
    fields.appendChild(label);
  }
}
async function loadConfig(){
  try{ paintConfig((await apiJson("/api/config")).data); }
  catch(_){ setMessage("config-status", "Could not read the configuration.", true); }
}
$("config-save").addEventListener("click", (event) => withBusy(event.target, async () => {
  const settings = {};
  for(const setting of CONFIG_FIELDS){
    if(!setting.editable) continue;
    const input = $(configFieldId(setting.name));
    if(!input) continue;
    settings[setting.name] = setting.kind === "bool" ? input.checked : input.value;
  }
  setMessage("config-status", "Saving…");
  try{
    const {ok, data} = await apiJson("/api/config", "POST", {settings});
    if(!ok){
      setMessage("config-status", (data.error || "Save failed") +
        (data.rejected ? ": " + data.rejected.join(" · ") : ""), true);
      return;
    }
    setMessage("config-status", data.service_managed
      ? "Saved. Restart the node for it to take effect (systemd will bring it back)."
      : "Saved. Restart the node for it to take effect.");
    toast("Configuration saved");
    await loadConfig();
  }catch(_){ setMessage("config-status", "Save failed", true); }
}));
$("config-reload").addEventListener("click", loadConfig);

// ---- quick join: tickets and QR codes --------------------------------------
$("tk-make").addEventListener("click", (event) => withBusy(event.target, async () => {
  setMessage("tk-status", "Creating…");
  $("tk-qr").innerHTML = ""; $("tk-out").hidden = true;
  try{
    const {ok, data} = await apiJson("/api/ticket", "POST", {ttl:Number($("tk-ttl").value)});
    if(!ok){ setMessage("tk-status", data.error || "Could not create a ticket", true); return; }
    $("tk-text").textContent = data.ticket;
    $("tk-out").hidden = false;
    // The SVG comes from the node, built from the ticket it just minted.
    $("tk-qr").innerHTML = data.qr_svg || "";
    const minutes = Math.round((data.ttl || 0) / 60);
    setMessage("tk-status", "Valid for " +
      (minutes >= 60 ? (minutes / 60) + " hour(s)" : minutes + " minute(s)") +
      ". Single use — treat it like a password.");
  }catch(_){ setMessage("tk-status", "Could not create a ticket", true); }
}));
$("tk-copy").addEventListener("click", () => copyText($("tk-text").textContent));
$("tk-join").addEventListener("click", (event) => withBusy(event.target, async () => {
  const ticket = $("tk-in").value.trim();
  if(!ticket){ setMessage("tk-scan-status", "Paste or scan a ticket first.", true); return; }
  setMessage("tk-scan-status", "Joining…");
  try{
    const {ok, data} = await apiJson("/api/join", "POST", {ticket});
    setMessage("tk-scan-status", ok ? "Joined." : (data.error || "Join failed"), !ok);
    if(ok){ $("tk-in").value = ""; toast("Joining the node from the ticket"); }
  }catch(_){ setMessage("tk-scan-status", "Join failed", true); }
}));

// Scanning uses the browser's own BarcodeDetector — no library, consistent with
// a project that takes a dependency only when there is no alternative. Where it
// is missing, say so plainly instead of failing silently: pasting still works.
let SCAN_STOP = null;
async function startScan(){
  const video = $("tk-video"), status = "tk-scan-status";
  if(!("BarcodeDetector" in window)){
    setMessage(status, "This browser cannot scan QR codes. Paste the ticket instead.", true);
    return;
  }
  let formats = [];
  try{ formats = await window.BarcodeDetector.getSupportedFormats(); }catch(_){}
  if(formats.length && !formats.includes("qr_code")){
    setMessage(status, "This browser cannot scan QR codes. Paste the ticket instead.", true);
    return;
  }
  let stream;
  try{
    stream = await navigator.mediaDevices.getUserMedia({video:{facingMode:"environment"}});
  }catch(_){
    // Denied, no camera, or a page not served over HTTPS/localhost.
    setMessage(status, "No camera available. It needs your permission, and a secure page " +
      "(HTTPS or localhost).", true);
    return;
  }
  const detector = new window.BarcodeDetector({formats:["qr_code"]});
  video.srcObject = stream; video.hidden = false;
  $("tk-scan").hidden = true; $("tk-scan-stop").hidden = false;
  await video.play().catch(() => {});
  setMessage(status, "Point the camera at the ticket's QR code.");
  let running = true;
  const timer = setInterval(async () => {
    if(!running) return;
    try{
      const found = await detector.detect(video);
      if(found && found.length){
        $("tk-in").value = found[0].rawValue || "";
        setMessage(status, "Ticket scanned — check it, then press Join.");
        stopScan();
      }
    }catch(_){ /* a frame that could not be read is not an error worth showing */ }
  }, 350);
  SCAN_STOP = () => {
    running = false; clearInterval(timer);
    stream.getTracks().forEach((track) => track.stop());
    video.srcObject = null; video.hidden = true;
    $("tk-scan").hidden = false; $("tk-scan-stop").hidden = true;
    SCAN_STOP = null;
  };
}
function stopScan(){ if(SCAN_STOP) SCAN_STOP(); }
$("tk-scan").addEventListener("click", startScan);
$("tk-scan-stop").addEventListener("click", stopScan);

// ---- console password ------------------------------------------------------
$("pw-save").addEventListener("click", (event) => withBusy(event.target, async () => {
  const current = $("pw-current").value, fresh = $("pw-new").value, repeat = $("pw-repeat").value;
  if(!current || !fresh){
    setMessage("pw-status", "Both the current and the new password are needed.", true); return;
  }
  // Checked here as a courtesy; the node checks everything again for real.
  if(fresh !== repeat){ setMessage("pw-status", "The two new passwords do not match.", true); return; }
  setMessage("pw-status", "Changing…");
  try{
    const {ok, data} = await apiJson("/api/password", "POST", {current, new:fresh});
    if(!ok){ setMessage("pw-status", data.error || "Could not change the password", true); return; }
    setMessage("pw-status", "Password changed." +
      (data.sessions_revoked ? " " + data.sessions_revoked + " other session(s) signed out." : ""));
    toast("Console password changed", "ok");
    // Never leave a password sitting in a form field.
    $("pw-current").value = ""; $("pw-new").value = ""; $("pw-repeat").value = "";
  }catch(_){ setMessage("pw-status", "Could not change the password", true); }
}));

// ---- protocol trace --------------------------------------------------------
// Polled only while it is recording: a diagnostic that keeps asking questions
// when nobody is looking is just more traffic to explain.
let TRACE_POLL = null;
function paintTrace(data){
  const status = data.status || {}, summary = data.summary || {};
  const pill = $("trace-pill");
  pill.textContent = status.running ? "recording" : (status.events ? "stopped" : "off");
  pill.className = "badge " + (status.running ? "ok" : "");
  const bits = summary.bits_per_second || 0;
  const rate = bits >= 1000 ? (bits / 1000).toFixed(1) + " kbit/s" : bits.toFixed(0) + " bit/s";
  setMessage("trace-status", status.events
    ? status.events + " packets over " + summary.window_seconds + "s — " + rate +
      (status.dropped ? " (" + status.dropped + " dropped, buffer full)" : "") +
      (status.running ? " · " + Math.round(status.seconds_left) + "s left" : "")
    : (status.running ? "Recording — nothing seen yet." : "Not recording."));
  const rows = summary.rows || [];
  $("trace-summary").innerHTML = rows.length ? rows.map((row) =>
    "<tr><td>" + (row.direction === "in" ? "← " : "→ ") + esc(row.type) + "</td>" +
    '<td class="num">' + esc(row.packets) + "</td>" +
    '<td class="num">' + esc(fmtBytes(row.bytes)) + "</td>" +
    '<td class="num">' + esc(fmtRate(row.bytes_per_second)) + "</td></tr>").join("")
    : spanRow(4, emptyHTML("Nothing recorded",
        "Start a recording to see which message types this node exchanges."));
}
async function loadTrace(){
  try{
    const {data} = await apiJson("/api/trace");
    paintTrace(data);
    if(!data.status || !data.status.running) stopTracePolling();
  }catch(_){ stopTracePolling(); }
}
function stopTracePolling(){ if(TRACE_POLL){ clearInterval(TRACE_POLL); TRACE_POLL = null; } }
async function traceAction(action, extra){
  try{
    const {ok, data} = await apiJson("/api/trace", "POST", Object.assign({action}, extra || {}));
    if(!ok){ setMessage("trace-status", data.error || "Trace command failed", true); return; }
    await loadTrace();
    if(action === "start" && !TRACE_POLL) TRACE_POLL = setInterval(loadTrace, 2000);
    if(action !== "start") stopTracePolling();
  }catch(_){ setMessage("trace-status", "Trace command failed", true); }
}
$("trace-start").addEventListener("click", () =>
  traceAction("start", {seconds:Number($("trace-seconds").value) || 120}));
$("trace-stop").addEventListener("click", () => traceAction("stop"));
$("trace-clear").addEventListener("click", () => traceAction("clear"));
$("trace-export").addEventListener("click", () => { window.location = "/api/trace/export"; });

// ---- manual connection, relay, trust ---------------------------------------
$("cx-request").addEventListener("click", (event) => withBusy(event.target, async () => {
  try{
    const {data} = await apiJson("/api/connect/request", "POST");
    $("cx-request-out").value = data.block;
    await copyText(data.block);
    setMessage("connect-status", "Send this block to the other side.");
  }catch(_){ setMessage("connect-status", "Could not create a request", true); }
}));
$("cx-accept").addEventListener("click", (event) => withBusy(event.target, async () => {
  const block = $("cx-accept-in").value.trim();
  if(!block){ setMessage("connect-status", "Paste a request first.", true); return; }
  try{
    const {ok, data} = await apiJson("/api/connect/accept", "POST", {block});
    if(!ok){ setMessage("connect-status", data.error || "Accept failed", true); return; }
    $("cx-accept-out").value = data.block;
    await copyText(data.block);
    setMessage("connect-status", "Send this invite block back.");
  }catch(_){ setMessage("connect-status", "Accept failed", true); }
}));
$("cx-complete").addEventListener("click", (event) => withBusy(event.target, async () => {
  const block = $("cx-reply-in").value.trim();
  if(!block){ setMessage("connect-status", "Paste the reply first.", true); return; }
  try{
    const {ok, data} = await apiJson("/api/connect/complete", "POST", {block});
    setMessage("connect-status", ok ? "Trying " + data.candidates + " candidate address(es)…"
      : (data.error || "Connect failed"), !ok);
  }catch(_){ setMessage("connect-status", "Connect failed", true); }
}));
$("rly-invite").addEventListener("click", (event) => withBusy(event.target, async () => {
  try{
    const {data} = await apiJson("/api/relay/invite", "POST");
    $("rly-invite-out").value = data.block;
    await copyText(data.block);
    setMessage("relay-status", "Relay invite ready.");
  }catch(_){ setMessage("relay-status", "Invite failed", true); }
}));
$("rly-join").addEventListener("click", (event) => withBusy(event.target, async () => {
  const block = $("rly-join-in").value.trim();
  if(!block){ setMessage("relay-status", "Paste a relay invite.", true); return; }
  try{
    const {ok, data} = await apiJson("/api/relay/join", "POST", {block});
    setMessage("relay-status", ok ? "Joining through " + data.relays + " relay(s)…"
      : (data.error || "Join failed"), !ok);
  }catch(_){ setMessage("relay-status", "Join failed", true); }
}));
$("gen-invite").addEventListener("click", (event) => withBusy(event.target, async () => {
  try{
    const {data} = await apiJson("/api/invite", "POST");
    $("invite-out").textContent = data.code;
    await copyText(data.code);
  }catch(_){ setMessage("manage-status", "Invite generation failed", true); }
}));
$("show-cert").addEventListener("click", (event) => withBusy(event.target, async () => {
  try{ $("cert-out").value = (await apiJson("/api/rootcert")).data.cert_hex; }
  catch(_){ setMessage("manage-status", "Certificate unavailable", true); }
}));
$("trust-btn").addEventListener("click", (event) => withBusy(event.target, async () => {
  const cert_hex = $("trust-in").value.trim();
  if(!cert_hex){ setMessage("manage-status", "Paste a certificate.", true); return; }
  const {ok} = await apiJson("/api/trust", "POST", {cert_hex});
  setMessage("manage-status", ok ? "Certificate trusted." : "Invalid certificate", !ok);
  if(ok) $("trust-in").value = "";
}));
$("join-btn").addEventListener("click", (event) => withBusy(event.target, async () => {
  const uri = $("join-uri").value.trim(), code = $("join-code").value.trim();
  if(!uri || !code){ setMessage("manage-status", "An address and an invite code are required.", true); return; }
  const {ok, data} = await apiJson("/api/join", "POST", {uri, code});
  setMessage("manage-status", ok ? "Join started." : (data.error || "Join failed"), !ok);
}));

// ---- raw content transfer --------------------------------------------------
$("publish-btn").addEventListener("click", (event) => withBusy(event.target, async () => {
  const name = $("app-name").value.trim();
  const version = $("app-version").value.trim() || "1.0.0";
  const input = $("app-files");
  if(!name || !input.files.length){
    setMessage("app-status", "A name and files are required.", true); return;
  }
  setMessage("app-status", "Publishing content…");
  try{
    const {ok, data} = await apiJson("/api/app/publish", "POST",
      {name, version, files:await selectedFiles(input)});
    if(ok){ $("app-id-out").textContent = data.app_id; setMessage("app-status", "Content published."); }
    else setMessage("app-status", data.error || "Publish failed", true);
  }catch(_){ setMessage("app-status", "Publish failed", true); }
}));
$("fetch-btn").addEventListener("click", (event) => withBusy(event.target, async () => {
  const app_id = $("fetch-id").value.trim();
  if(!app_id){ setMessage("app-status", "Enter a content id.", true); return; }
  setMessage("app-status", "Fetching content…");
  try{
    const {ok, status, data} = await apiJson("/api/app/fetch", "POST", {app_id});
    if(!ok){
      setMessage("app-status", status === 404 ? "Content not found" : (data.error || "Fetch failed"), true);
      return;
    }
    $("app-files-out").innerHTML = Object.entries(data.files || {}).map(([path, b64]) =>
      '<a class="chip" download="' + esc(path) + '" href="data:application/octet-stream;base64,' +
      b64 + '">' + esc(path) + "</a>").join("");
    setMessage("app-status", data.name + " " + data.version + " fetched.");
  }catch(_){ setMessage("app-status", "Fetch failed", true); }
}));

// ---- palette ---------------------------------------------------------------
[["Overview", "overview", ""],
 ["Peers", "network", "peers"],
 ["Reachability", "network", "reach"],
 ["Add a node", "network", "join"],
 ["Installed apps", "apps", "installed"],
 ["App store", "apps", "store"],
 ["Updates", "settings", "updates"],
 ["Console password", "settings", "security"],
 ["Configuration", "settings", "config"],
 ["Protocol trace", "settings", "diagnostics"],
 ["Advanced transfer", "settings", "advanced"],
].forEach(([label, section, sub]) =>
  PALETTE.add(label, "Go to", () => ROUTER.go(section, sub)));
PALETTE.add("Ping active nodes", "Action", () => $("ping-btn").click());
PALETTE.add("Create a join ticket", "Action", () => {
  ROUTER.go("network", "join"); $("tk-make").click();
});
PALETTE.add("Check for updates", "Action", () => {
  ROUTER.go("settings", "updates"); $("update-check").click();
});
PALETTE.add("Switch theme", "Action", () => THEME.toggle());
$("palette-open").addEventListener("click", () => PALETTE.open());

mountShell();
// A live cookie session means the console can be entered without re-typing the
// password; anything else drops to the gate.
(async function resume(){
  try{
    const response = await fetch("/api/state");
    if(response.ok){ enterConsole(); return; }
  }catch(_){}
  showGate();
})();
"""
