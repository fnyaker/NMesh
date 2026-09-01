"""
Console page (/).

Four sections, in the order someone actually needs them: what this node is doing
(Overview), who it is talking to and how to reach it (Network), what runs on it
(Apps), and what you can change (Settings). Every section is a route, so any
sub-page can be linked to, bookmarked, and reached with the Back button.
"""

from . import ui

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

<a class="skip" href="#main">Skip to content</a>
<div id="shell" class="shell hidden">
  <aside class="rail">
    <a class="brand" href="/"><span class="mark" aria-hidden="true">NM</span>
      <span><b>NMesh</b><span>Console</span></span></a>
    <nav id="nav" class="nav" role="tablist" aria-label="Console sections">
      <button role="tab" data-tab="overview" data-label="Overview" aria-controls="panel-overview" aria-selected="true"><span class="lbl">Overview</span></button>
      <button role="tab" data-tab="network" data-label="Network" aria-controls="panel-network" aria-selected="false"><span class="lbl">Network</span><span id="nav-peers" class="tail"></span></button>
      <button role="tab" data-tab="apps" data-label="Apps" aria-controls="panel-apps" aria-selected="false"><span class="lbl">Apps</span></button>
      <button role="tab" data-tab="settings" data-label="Settings" aria-controls="panel-settings" aria-selected="false"><span class="lbl">Settings</span></button>
      <p class="eyebrow nav-label">Applications</p>
      <div id="app-links"></div>
    </nav>
    <div class="rail-foot">
      <div class="rail-state"><span id="rail-dot" class="dot"></span><span id="rail-text">Connecting…</span></div>
      <button id="logout" class="ghost wide">Sign out</button>
    </div>
  </aside>

  <main id="main">
    <header class="topbar">
      <div class="who">
        <span class="badge" id="node-state">…</span>
        <button id="self-node" class="ghost sm mono" title="Show this node's details"></button>
      </div>
      <label class="ctx-pick" id="ctx-pick" hidden><span class="sr-only">Node being managed</span>
        <select id="ctx-node"></select></label>
      <span class="grow"></span>
      <div id="refresh" class="refresh">
        <i id="refresh-live" class="live" aria-hidden="true"></i>
        <label class="sr-only" for="refresh-secs">How often the changing numbers are re-read, in seconds (0 turns it off)</label>
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
          <div class="menu-head"><span class="grow">This node</span>
            <span class="row"><i id="more-dot" class="dot"></i>
              <span id="more-state" class="muted">Connecting…</span></span></div>
          <button class="item" id="more-search" data-menu-close>Search &amp; commands</button>
          <div id="more-apps"></div>
          <div class="sep"></div>
          <button class="item danger" id="more-restart" data-menu-close>Restart this node</button>
          <p id="more-restart-why" class="menu-note" hidden></p>
          <button class="item" id="more-logout" data-menu-close>Sign out</button>
        </div>
      </div>
    </header>

""" + ui.CTX_BAR + """

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
            <div class="sub">Nodes linked directly, and nodes reached through them</div></div>
            <span id="map-count" class="badge"></span>
            <button id="map-open" class="sm">Expand</button></div>
          <div class="card-body">
            <svg id="graph" class="mesh-graph clickable" viewBox="0 0 420 250" role="img"
                 aria-label="Connected nodes — click to open the full map"></svg>
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
          <div class="card-head"><div class="grow"><h2>Connected nodes <span id="active-count" class="badge"></span></h2>
            <div class="sub">Authenticated and open. A node holding several links unfolds onto them</div></div>
            <label class="search"><span class="sr-only">Search active nodes</span>
              <input id="active-search" type="search" placeholder="Search name, id, address, transport…" spellcheck="false"></label>
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
              <input id="known-search" type="search" placeholder="Search name, id or address…" spellcheck="false"></label>
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
            <div class="sub">Whether other nodes can open a link to this one</div></div></div>
          <div class="card-body">
            <div id="network-summary" class="stats"></div>
            <div class="btn-row">
              <button id="reach-probe">Confirm reachability</button>
              <button id="net-recheck">Re-check network</button>
              <button id="dyn-toggle"></button>
            </div>
            <p class="muted small">Dynamic addressing moves a live link onto another address
              of the <em>same</em> node when that one scores better — a LAN address instead
              of the public one, IPv6 instead of IPv4. It costs a dial and a handshake to find
              out, so it is off unless you ask for it.</p>
            <hr>
            <label class="field" for="balance"><span>Choosing between a node&rsquo;s addresses</span>
              <span class="hint">Nodes are often reachable more than one way. This decides
                which one is tried first: what the link <em>measures</em>, or what you said
                the <em>medium</em> is worth. Each transport carries its own priority, in its
                block below.</span>
              <input id="balance" type="range" min="0" max="100" step="5" value="50"
                     aria-describedby="balance-order"></label>
            <div class="scale"><span>Fastest measured</span><b id="balance-value"></b>
              <span>Preferred medium</span></div>
            <p id="balance-order" class="hint"></p>
            <p id="transport-status" class="msg"></p>
          </div>
        </article>
        <article class="card">
          <div class="card-head"><div class="grow"><h2>Transports</h2>
            <div class="sub">One block per medium: what is bound, what it carries, what it takes</div></div></div>
          <div class="card-body">
            <p class="muted small">Settings apply to the running node immediately unless one
              says otherwise, then go to the configuration file so they survive a restart.
              A value the transport refuses never reaches the file.</p>
            <div id="transport-blocks" class="stack"></div>
          </div>
        </article>
        <article class="card">
          <div class="card-head"><div class="grow"><h2>Addressing</h2>
            <div class="sub">What this node tells other nodes about itself</div></div></div>
          <div class="card-body"><dl id="addressing" class="kv"></dl></div>
        </article>
        <article class="card" id="refusals-card" hidden>
          <div class="card-head"><div class="grow"><h2>Refused handshakes</h2>
            <div class="sub">Links that reached this node and were turned away, and why</div></div></div>
          <div class="card-body">
            <p class="muted small">A node drops anything it cannot verify, which is the point —
              but a mesh that will not connect looks the same from outside as one nobody is
              calling. These are the tests that failed, newest first. Nothing here is an error
              on its own: a stranger dialling a closed door lands here too.</p>
            <div class="table-wrap"><table class="rows">
            <thead><tr><th>Reason</th><th>From</th><th class="num">Times</th><th>Last</th></tr></thead>
            <tbody id="refusals-list"></tbody></table></div>
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
        <button role="tab" data-subtab="identity" aria-selected="true">Identity</button>
        <button role="tab" data-subtab="updates" aria-selected="false">Updates</button>
        <button role="tab" data-subtab="security" aria-selected="false">Security</button>
        <button role="tab" data-subtab="appearance" aria-selected="false">This browser</button>
        <button role="tab" data-subtab="config" aria-selected="false">Configuration</button>
        <button role="tab" data-subtab="diagnostics" aria-selected="false">Diagnostics</button>
        <button role="tab" data-subtab="advanced" aria-selected="false">Advanced</button>
      </nav>

      <div data-sub="identity" class="stack">
        <article class="card">
          <div class="card-head"><div class="grow"><h2>What this node is called</h2>
            <div class="sub">A name you choose, beside the id you cannot</div></div></div>
          <div class="card-body">
            <p class="muted small">The id below is this node's identity: it comes from its
              signing key and never changes. The name is only a label — it is signed and
              gossiped so nobody can put it on somebody else's node, but names are not
              unique, so the id is what you check before you trust anything.</p>
            <div class="form-grid">
              <label class="field"><span>Name</span>
                <input id="pseudo-input" type="text" maxlength="50" autocomplete="off"
                       placeholder="unnamed" spellcheck="false"></label>
              <label class="field"><span>Node id</span>
                <input id="pseudo-id" type="text" class="mono" readonly></label>
            </div>
            <div class="btn-row"><button id="pseudo-save" class="primary">Save name</button>
              <button id="pseudo-clear">Remove the name</button></div>
            <p id="pseudo-status" class="msg"></p>
          </div>
        </article>

        <article class="card">
          <div class="card-head"><div class="grow"><h2>Find a node by name</h2>
            <div class="sub">Whole or partial — best match first</div></div>
            <button id="pseudo-wide" title="Also ask the network for this exact name">Ask the network</button></div>
          <div class="card-body">
            <label class="field"><span>Name</span>
              <input id="pseudo-search" type="search" autocomplete="off"
                     placeholder="alice" spellcheck="false"></label>
            <div class="table-wrap"><table class="rows">
              <thead><tr><th>Name</th><th>Node id</th><th></th></tr></thead>
              <tbody id="pseudo-results"></tbody></table></div>
            <p id="pseudo-search-status" class="msg"></p>
          </div>
        </article>
      </div>

      <div data-sub="updates" class="stack" hidden>
        <article class="card">
          <div class="card-head"><div class="grow"><h2>Software updates</h2>
            <div class="sub">Checks this project's published releases on GitHub</div></div>
            <span id="version-pill" class="badge"></span></div>
          <div class="card-body">
            <p class="muted small">Nothing is installed without you confirming the exact version.
              Applying an update replaces the node's files, then restarts the node if something
              is there to bring it back — otherwise it says so and waits for you.</p>
            <div class="btn-row">
              <button id="update-check">Check for updates</button>
              <button id="update-apply" class="primary" hidden>Install</button>
            </div>
            <p id="update-status" class="msg"></p>
            <pre id="update-notes" class="block" hidden></pre>
          </div>
        </article>

        <article class="card">
          <div class="card-head"><div class="grow"><h2>From the mesh</h2>
            <div class="sub">Releases published by nodes, signed — no web host in the way</div></div></div>
          <div class="card-body stack">
            <p class="muted small">A node publishes its own code, signed with its identity, and
              hands the package to whoever asks — publisher or any node that kept a copy. You
              decide whose signature this node accepts: nothing arriving from the network can add
              a publisher, and a release from anyone you have not pinned is shown but never
              installed.</p>
            <div class="table-wrap">
              <table><thead><tr><th>Version</th><th>Publisher</th><th>Published</th><th></th></tr></thead>
                <tbody id="release-rows"></tbody></table>
            </div>
            <p id="release-empty" class="empty" hidden>No node has announced a release yet.</p>
            <p id="release-status" class="msg"></p>
          </div>
        </article>

        <article class="card">
          <div class="card-head"><div class="grow"><h2>Publishers you accept</h2>
            <div class="sub">Whose signature may replace this node's code</div></div></div>
          <div class="card-body stack">
            <div class="table-wrap">
              <table><thead><tr><th>Name</th><th>Key</th><th>Install automatically</th><th></th></tr></thead>
                <tbody id="publisher-rows"></tbody></table>
            </div>
            <p id="publisher-empty" class="empty" hidden>No publisher pinned — this node installs
              nothing from the mesh.</p>
            <div class="form-grid">
              <label class="field"><span>Publisher key</span>
                <input id="pin-key" placeholder="the public key they gave you" autocomplete="off">
                <span class="hint">Get it from them over a channel you trust. Anyone who can change
                  it can ship you code.</span></label>
              <label class="field"><span>Name</span>
                <input id="pin-name" placeholder="who this is" autocomplete="off"></label>
            </div>
            <label class="check"><input id="pin-auto" type="checkbox" checked>
              <span>Install their releases automatically</span></label>
            <p class="muted small">An automatic install takes effect the way any other does — the
              node restarts onto the new code, if a service manager is there to bring it back.
              A release that installs and never becomes the running version is retried once and
              then abandoned, so that pair can never become a restart loop. Trusting a publisher
              and letting them install while nobody is watching stay two separate decisions;
              this box is the second one, and it starts ticked.</p>
            <div class="btn-row"><button id="pin-add" class="primary">Pin publisher</button></div>
            <p id="pin-status" class="msg"></p>
          </div>
        </article>

        <article class="card">
          <div class="card-head"><div class="grow"><h2>Publish this node's code</h2>
            <div class="sub">Sign what is installed here and offer it to the mesh</div></div></div>
          <div class="card-body stack">
            <p class="muted small">Publishing signs the tree and announces it — nothing is sent
              anywhere. The package moves only when someone who pinned <strong>this node's</strong>
              key asks for it, and whoever receives it keeps it and can serve the next node. The
              version comes from the tree itself, so a release cannot announce one version and
              carry another.</p>
            <label class="field"><span>Release notes</span>
              <textarea id="publish-notes" rows="3" placeholder="what changed"></textarea></label>
            <div class="kv"><div>This node's publisher key</div>
              <div><code id="publish-key" class="inline"></code></div></div>
            <div class="btn-row"><button id="publish-go">Publish</button></div>
            <p id="publish-status" class="msg"></p>
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

      <div data-sub="appearance" class="stack" hidden>
        <article class="card">
          <div class="card-head"><div class="grow"><h2>This browser</h2>
            <div class="sub">Preferences about this screen, kept here and nowhere else</div></div></div>
          <div class="card-body">
            <p class="muted small">These are not settings of the node: they live in this
              browser, so a different machine signed into the same console keeps its own.
              Nothing here is sent anywhere.</p>
            <div class="form-grid">
              <label class="field" for="pref-theme"><span>Theme</span>
                <select id="pref-theme">
                  <option value="system">Follow the system</option>
                  <option value="light">Light</option>
                  <option value="dark">Dark</option>
                </select></label>
              <label class="field" for="pref-open"><span>Opening another app</span>
                <select id="pref-open">
                  <option value="auto">Decide by screen size</option>
                  <option value="window">In a separate window</option>
                  <option value="tab">In a new tab</option>
                </select>
                <span class="hint">Following a link into Chat or Fleet — messaging a node
                  from its details, say. A window keeps what you were doing in view;
                  a phone gets a tab either way.</span></label>
            </div>
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

<dialog id="node-dialog" class="wide" aria-labelledby="node-dialog-title">
  <div class="sheet">
    <header class="sheet-head"><h2 id="node-dialog-title">Node</h2>
      <button id="node-dialog-close" class="icon" aria-label="Close"><svg class="ic" viewBox="0 0 24 24" aria-hidden="true"><path d="M18 6 6 18M6 6l12 12"/></svg></button></header>
    <!-- The whole body is the shared node view — the same one /node serves. -->
    <div class="sheet-body"><div id="node-detail"></div></div>
  </div>
</dialog>

<dialog id="map-dialog" class="full" aria-labelledby="map-title">
  <div class="sheet">
    <header class="sheet-head">
      <h2 id="map-title">Mesh map</h2>
      <span class="row small muted gap-4 map-legend">
        <span class="row"><i class="dot self"></i>this node</span>
        <span class="row"><i class="dot direct"></i>direct link</span>
        <span class="row"><i class="dot routed"></i>routed session</span>
      </span>
      <span class="grow"></span>
      <span id="map-summary" class="badge"></span>
      <button id="map-close" class="icon" aria-label="Close"><svg class="ic" viewBox="0 0 24 24" aria-hidden="true"><path d="M18 6 6 18M6 6l12 12"/></svg></button>
    </header>
    <div class="sheet-body map-body">
      <div class="map-canvas">
        <svg id="map-svg" class="mesh-graph" viewBox="0 0 900 520" role="img"
             aria-label="Mesh map, draggable and zoomable"></svg>
        <div class="map-zoom" role="group" aria-label="Zoom">
          <button id="map-in" class="icon sm" aria-label="Zoom in">+</button>
          <button id="map-out" class="icon sm" aria-label="Zoom out">−</button>
          <button id="map-fit" class="icon sm" aria-label="Fit the whole mesh">⤢</button>
        </div>
        <p id="map-hint" class="map-hint muted tiny">Drag to move · pinch or scroll to zoom</p>
      </div>
      <aside class="map-side">
        <h3>Links</h3>
        <div id="map-links" class="stack"></div>
      </aside>
    </div>
  </div>
</dialog>

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
<script src="/app.js"></script>
</body>
</html>
"""


# Only what is genuinely this page's: the two drawings, the QR holder, and the
# app tiles. Everything else comes from the design system — if something here
# starts to look reusable, it belongs in `ui.py`, not in a second copy.
CONSOLE_PAGE_CSS = """
#chart{width:100%;height:236px;display:block}
/* A node's own links, unfolded under it: indented, quieter, and not clickable
   as a row — the node above is the thing you open. */
.link-row.group>td:first-child{display:flex;align-items:center;gap:var(--s-2)}
.link-row .fold{width:20px;min-height:20px;font-size:var(--fs-xs);flex:none}
.link-row[data-inner]{background:var(--surface-2)}
.link-row[data-inner]>td{color:var(--text-muted)}
.link-in{display:inline-block;width:14px;border-left:1px solid var(--border-strong);
  border-bottom:1px solid var(--border-strong);height:8px;margin-right:var(--s-2)}
.dot.in{background:var(--accent)}
.dot.out{background:var(--warn)}
/* Each card keeps its own height: stretching the shorter one left a hole under
   the graph, and growing the canvas to fill it fed back into the row height. */
#panel-overview .split{align-items:start}
#graph{width:100%;height:auto;max-height:260px}
#map-svg{width:100%;height:100%;min-height:320px}
#graph.clickable{cursor:zoom-in}
.mesh-graph .edge{stroke:var(--border-strong);stroke-width:1.5}
.mesh-graph .edge.routed{stroke-dasharray:3 4;opacity:.75}
.mesh-graph .node circle{stroke:var(--surface);stroke-width:2;transition:r var(--speed) var(--ease)}
.mesh-graph .node circle.hit{fill:transparent;stroke:none;transition:none}
.mesh-graph .node.direct circle:not(.hit){fill:var(--accent)}
.mesh-graph .node.routed circle:not(.hit){fill:var(--warn)}
.mesh-graph .node.self circle:not(.hit){fill:var(--text)}
.mesh-graph .node.self text{fill:var(--text);font-weight:700}
/* Labels sit over the edges: painting the stroke first gives each one a halo of
   the card's own background, so nothing has to be moved out of the way. */
.mesh-graph .node text{font:600 9px var(--font);fill:var(--text-muted);text-anchor:middle;
  paint-order:stroke;stroke:var(--surface);stroke-width:3px;stroke-linejoin:round}
.mesh-graph .node{cursor:pointer}
.mesh-graph .node:hover circle:not(.hit),
.mesh-graph .node:focus-visible circle:not(.hit){r:13}
.mesh-graph .node:focus-visible{outline:none}
.mesh-graph .node:focus-visible circle:not(.hit){stroke:var(--ring);stroke-width:2.5}

#map-svg{width:100%;height:100%;min-height:0;flex:1 1 auto;
  /* The browser's own pan/zoom would fight the drag handler for the same
     gesture, and on a phone it wins. This map does its own. */
  touch-action:none;cursor:grab;user-select:none}
#map-svg.grabbing{cursor:grabbing}
.map-body{display:grid;grid-template-columns:minmax(0,1fr) 280px;gap:var(--s-4);
  padding:var(--s-4);overflow:hidden;flex:1 1 auto}
.map-canvas{position:relative;display:flex;min-width:0;min-height:0;overflow:hidden;
  border:1px solid var(--border);border-radius:var(--r-md);background:var(--surface)}
.map-zoom{position:absolute;right:var(--s-3);bottom:var(--s-3);display:flex;
  flex-direction:column;gap:2px;padding:2px;background:var(--surface);
  border:1px solid var(--border);border-radius:var(--r-md);box-shadow:var(--shadow-1)}
.map-zoom button{width:30px;min-height:30px}
#transport-blocks [data-panel]{display:flex;flex-direction:column;gap:var(--s-4)}
#transport-blocks [data-facts]:empty{display:none}
#transport-blocks h3{margin-bottom:calc(-1 * var(--s-2))}
.map-hint{position:absolute;left:var(--s-3);bottom:var(--s-3);pointer-events:none}
.map-side{overflow-y:auto;min-height:0;border-left:1px solid var(--border);
  padding-left:var(--s-4)}
.map-legend .dot.self{background:var(--text)}
.map-legend .dot.direct{background:var(--accent)}
.map-legend .dot.routed{background:var(--warn)}
.map-link{border:1px solid var(--border);border-radius:var(--r-md);padding:var(--s-2) var(--s-3);
  cursor:pointer;font-size:var(--fs-sm);background:var(--surface)}
.map-link:hover,.map-link.on{border-color:var(--accent);background:var(--accent-soft)}
.map-link .top{display:flex;gap:var(--s-2);align-items:baseline}
.map-link .top b{font-family:var(--mono);font-size:var(--fs-xs);flex:1 1 auto;min-width:0;
  overflow:hidden;text-overflow:ellipsis}
.mesh-graph .edge.lossy{stroke:var(--warn)}
#map-svg .edge.on{stroke:var(--accent);stroke-width:3}
#map-svg .node.picked circle:not(.hit){stroke:var(--accent);stroke-width:3}
#map-svg .node.picked text{fill:var(--text);font-weight:700}
/* Sized in drawing units scaled by --map-unit, which the camera keeps in step
   with the zoom — the on-screen result is a constant 12px and 10px. */
#map-svg .node text{font-size:calc(12px * var(--map-unit,1))}
#map-svg .node text,#map-svg .elabel{stroke-width:calc(3px * var(--map-unit,1))}
#map-svg .elabel{font:600 calc(10px * var(--map-unit,1)) var(--font);fill:var(--text-muted);
  text-anchor:middle;paint-order:stroke;stroke:var(--surface);stroke-linejoin:round}
/* A link's thickness says how much it carries; that reading should not change
   because the operator zoomed in. */
#map-svg .edge{vector-effect:non-scaling-stroke}
#map-svg.lod-2 .elabel{display:none}
#map-svg.lod-3 text{display:none}
/* On a narrow screen the link list is not dropped — it goes under the drawing,
   which is where the drawing sends you anyway once you tap an edge. */
@media (max-width:900px){
  /* The drawing is nearly twice as wide as it is tall, so a tall row is mostly
     empty letterbox — height it to what the drawing actually uses. */
  .map-body{grid-template-columns:minmax(0,1fr);grid-template-rows:minmax(200px,34vh) minmax(0,1fr);
    padding:var(--s-3);gap:var(--s-3)}
  .map-side{border-left:0;border-top:1px solid var(--border);padding-left:0;
    padding-top:var(--s-3)}
  .map-legend{display:none}
  /* Kept on a phone: at the fitted zoom the drawing is dots, and the line is
     what says they have names a tap away. */
  .map-hint{right:44px}
}
@media (max-width:720px){
  /* The small card's labels are in viewBox units: at phone width the drawing is
     scaled to about three quarters, and 9px lands under 7. */
  #graph .node text{font-size:12px}
  /* The bar has to fit an identifier, a state and the controls; the context
     picker gives up width first because its label is repeated underneath it. */
  .ctx-pick select{max-width:120px}
}

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
/* A release row stays one line high: the notes are a hint, not the row. The
   wrapper scrolls on a narrow screen rather than squeezing the version into a
   column one character wide. */
#release-rows td:first-child strong{white-space:nowrap}
#release-rows .tiny{max-width:34ch;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
#release-rows code,#publisher-rows code{white-space:nowrap}
"""


CONSOLE_PAGE_JS = r"""
// ── console page ────────────────────────────────────────────────────────────
// Reads /api/state on a timer and paints; every control posts and re-reads.
// Nothing is cached across a reload: what the node says is the truth.

let STATE = null, PREVIOUS = null;
// `false`, or the context epoch a request is in flight for. Never a boolean
// once one is running: see tick().
let TICKING = false;
const RATES = [];                       // ~90 samples, the throughput window
// The last rate measured. A repaint triggered by a change did not measure one
// and must not invent a zero: nothing about the throughput changed because a
// link came up.
let RATE_NOW = {inbound:0, outbound:0};

// ---- gate ------------------------------------------------------------------
function showGate(){
  REFRESH.stop();
  $("shell").classList.add("hidden");
  $("login").classList.remove("hidden");
  $("password").focus();
}
function enterConsole(){
  $("login").classList.add("hidden");
  $("shell").classList.remove("hidden");
  ROUTER.start(onRoute);
  CONTEXT.paint();
  // A context carried over a reload is a claim until the console that holds the
  // session agrees; `confirm` drops it if that session is gone.
  CONTEXT.confirm().then(loadTargets);
  REFRESH.mount(tick);
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
  // Straight to the local console: signing out is never a remote action, and
  // the remote session goes with it rather than outliving the operator.
  await CONTEXT.leave();
  try{ await api("/api/logout", "POST"); }catch(_){}
  SESSION.clear(); showGate();
});

// ---- polling ---------------------------------------------------------------
function onRoute(section, sub){
  // Leaving the panel that opened it stops the camera: a scanner still running
  // behind a hidden section is a light on somebody's phone with nothing on
  // screen to explain it.
  if(section !== "network" || sub !== "join") stopScan();
  if(section === "network" && sub === "peers") refreshPeers();
  if(section === "network" && sub === "reach") loadTransportOptions();
  if(section === "settings" && sub === "appearance") paintPrefs();
  if(section === "apps") refreshApps();
  // Read on entry rather than on a timer: both files can be edited by hand, and
  // a stale form would offer to save values they no longer hold.
  if(section === "settings" && sub === "config") loadConfig();
  if(section === "settings" && sub === "diagnostics") loadTrace();
  if(section === "settings" && sub === "updates") refreshReleases();
  if(section === "settings" && sub === "identity") refreshPseudo();
}
// One reader of `/api/state`, two reasons to call it.
//
//   * the **interval**, for the numbers that never stop moving — throughput,
//     latency, jitter, load. Those want a steady cadence: a rate is a
//     difference over a known time, and sampling it whenever a link happened to
//     come up would make the chart a picture of the mesh's mood rather than of
//     its throughput.
//   * a **change**, for the things that either are or are not. Those want to be
//     instant, and they carry no rate.
//
// So `sample` is the whole difference between the two, and it is the only one.
// Two readers would be two descriptions of one node.
async function tick(sample){
  // Held per context, not as a plain flag: a tick for the node we just left
  // must not make the tick for the node we just entered look redundant. That
  // is how a switch used to leave the old machine's numbers on screen until
  // the next timer — for ever, with auto-refresh off.
  const epoch = CONTEXT.epoch;
  if(TICKING === epoch) return;
  TICKING = epoch;
  try{
    const response = await api("/api/state");
    if(!response.ok) return;
    STATE = await response.json();
    if(sample === false) STATE._rates = RATE_NOW;
    else trackRates(STATE);
    paintHeader(STATE); paintMetrics(STATE); drawChart(); drawGraph(STATE);
    paintApps(STATE); paintReach(STATE); paintMap(); paintRestart(STATE);
    if(ROUTER.section === "network" && ROUTER.sub === "peers") refreshPeers();
    if(ROUTER.section === "settings" && ROUTER.sub === "updates") refreshReleases();
  }catch(error){
    if(!isStale(error)) railState("danger", "Console unreachable");
  }finally{ if(TICKING === epoch) TICKING = false; }
}
// The node says when something structural moved; the page reads then. Every
// event inside one frame is answered by one repaint (EVENTS.FRAME), so a burst
// of forty link changes is one pass over the list rather than forty.
EVENTS.on(["links", "nodes", "names", "reach"], () => tick(false));

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
  state._rates = RATE_NOW = {inbound, outbound};
}

// The rail is hidden on a phone and the same line shows in the ⋯ menu; written
// once so the two cannot disagree about whether this node is up.
function railState(kind, text){
  ["rail", "more"].forEach((where) => {
    $(where + "-dot").className = "dot " + kind;
    $(where === "rail" ? "rail-text" : "more-state").textContent = text;
  });
}

// ---- header and metrics ----------------------------------------------------
// Two counts, never one: a node may hold several links at once, so "3 links up"
// and "connected to 2 nodes" are both true at the same time. Each label below
// takes the one it actually names.
function paintHeader(state){
  const links = state.link_count || 0, nodes = state.node_count || 0;
  $("self-node").textContent = nodeLabel(state.id, state.pseudo);
  $("self-node").title = state.pseudo ? state.pseudo + "\n" + state.id : state.id;
  const pill = $("node-state");
  pill.textContent = state.running ? "Running · up " + fmtDuration(state.uptime) : "Stopped";
  pill.className = "badge " + (state.running ? "ok" : "danger");
  railState(state.running ? (links ? "live" : "ok") : "danger", state.running
    ? (links ? plural(links, "link") + " up" : "Online, not connected")
    : "Node stopped");
  $("nav-peers").textContent = nodes || "";
  $("overview-title").textContent = nodes
    ? "Connected to " + plural(nodes, "node")
    : "Looking for a neighbour";
  $("overview-lede").textContent = nodes
    ? "Health, throughput, and the " + plural(links, "link") + " this node has authenticated."
    : "This node is running but has no authenticated link yet. Add one from Network → Add a node.";
}
function paintMetrics(state){
  const load = state.load || {};
  const cards = [
    ["Connected nodes", state.node_count || 0, "accent"],
    ["Active links", state.link_count || 0, ""],
    ["Known nodes", state.routing_size || 0, ""],
    ["E2E sessions", (state.e2e_sessions || []).length, ""],
    ["Inbound", fmtRate(state._rates.inbound), ""],
    ["Outbound", fmtRate(state._rates.outbound), ""],
    ["CPU", load.cpu_percent == null ? "—" : Math.round(load.cpu_percent) + "%", ""],
    ["Memory", fmtBytes(load.rss_bytes), ""],
  ];
  // The cards are the shape; the numbers are written into them. Rewriting the
  // markup every two seconds replaced eight elements that had not changed —
  // losing any text selected in them, and the element under a click about to
  // land.
  const values = {};
  cards.forEach(([label, value]) => { values["metric:" + label] = String(value); });
  paintLive("metrics", cards.map(([label]) => label).join("|"),
    () => cards.map(([label, , tone]) =>
      '<div class="stat ' + tone + '"><span class="v" data-v="metric:' + esc(label) +
      '"></span><span class="k">' + esc(label) + "</span></div>").join(""),
    values);
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
// One drawing routine, two sizes. The small card is a glance; the expanded one
// is where the mesh is actually watched, so it labels every edge with the
// medium and the latency, and thickens it with what it carries.
const GRAPH_SMALL = {w:420, h:250, rx:96, ry:58, rx2:168, ry2:100, r:9, self:12,
                     labels:false};
const GRAPH_BIG = {w:900, h:520, rx:250, ry:150, rx2:390, ry2:225, r:13, self:18,
                   labels:true};

function drawGraph(state){ renderGraph($("graph"), state, GRAPH_SMALL); }

// Every direct edge shares one endpoint, so labelling at the midpoint piles
// them all around the centre. Two thirds of the way out, nudged off the line,
// they sit next to the node they describe instead.
function edgeLabelAt(from, to, share){
  const t = share == null ? .66 : share;
  const dx = to.x - from.x, dy = to.y - from.y;
  const length = Math.hypot(dx, dy) || 1;
  return {x:from.x + dx * t - (dy / length) * 9,
          y:from.y + dy * t + (dx / length) * 9 - 2};
}

let MAP_NAMES = {};

function renderGraph(svg, state, size){
  svg.replaceChildren();
  svg.setAttribute("viewBox", "0 0 " + size.w + " " + size.h);
  const topology = state.topology || {}, direct = topology.direct || [], routed = topology.routed || [];
  const centre = {x:size.w / 2, y:size.h / 2}, place = new Map();
  // Node labels are drawn from ids alone deeper in, so collect the names here.
  MAP_NAMES = {};
  for(const node of direct.concat(routed)) if(node.pseudo) MAP_NAMES[node.id] = node.pseudo;
  direct.forEach((node, index) => {
    // Half a step off the top, so the centre node's own label has room.
    const step = Math.PI * 2 / Math.max(1, direct.length);
    const angle = step * index - Math.PI / 2 + (direct.length > 1 ? step / 2 : Math.PI / 2);
    place.set(node.id, {x:centre.x + Math.cos(angle) * size.rx,
                        y:centre.y + Math.sin(angle) * size.ry});
  });
  routed.forEach((node, index) => {
    const step = Math.PI * 2 / Math.max(1, routed.length);
    const angle = step * index - Math.PI / 2 + step / 2 + .3;
    place.set(node.id, {x:centre.x + Math.cos(angle) * size.rx2,
                        y:centre.y + Math.sin(angle) * size.ry2});
  });
  // Thickness carries volume, colour carries health: a fat pale line is a busy
  // healthy link, a thin amber one is a link losing probes.
  const weight = (bytes) => Math.min(5, 1.2 + Math.log10(1 + (bytes || 0) / 1024) * 0.7);
  direct.forEach((node) => {
    const point = place.get(node.id);
    const counters = node.counters || {};
    const quality = node.quality || {};
    const lossy = (quality.loss || 0) >= 0.1 || (quality.jitter_ms || 0) > 150;
    const line = svgEl("line", {
      x1:centre.x, y1:centre.y, x2:point.x, y2:point.y,
      class:"edge" + (lossy ? " lossy" : ""), "data-edge":node.id,
      "stroke-width":weight((counters.bytes_in || 0) + (counters.bytes_out || 0)).toFixed(2)});
    svg.appendChild(line);
    if(size.labels){
      const label = svgEl("text", Object.assign(
        edgeLabelAt(centre, point), {class:"elabel"}));
      label.textContent = (node.transport || "?") +
        (node.rtt_ms == null ? "" : " · " + node.rtt_ms + " ms") +
        (quality.loss ? " · " + Math.round(quality.loss * 100) + "% loss" : "");
      svg.appendChild(label);
    }
  });
  routed.forEach((node) => {
    const from = place.get(node.via) || centre, to = place.get(node.id);
    svg.appendChild(svgEl("line", {x1:from.x, y1:from.y, x2:to.x, y2:to.y,
                                   class:"edge routed"}));
    if(size.labels){
      const label = svgEl("text", Object.assign(edgeLabelAt(from, to, .5),
                                                {class:"elabel"}));
      label.textContent = "via " + shortId(node.via);
      svg.appendChild(label);
    }
  });
  const dot = (id, point, kind, label, caption) => {
    const group = svgEl("g", {class:"node " + kind, tabindex:"0", role:"button",
                              "data-node-id":id, "aria-label":label});
    // An invisible, generous target under the visible dot. A 9px circle is a
    // fine thing to look at and a poor thing to hit — with a finger it is
    // barely a third of what a touch target has to be, and even with a mouse
    // the gap between the circle and its label swallowed clicks.
    group.appendChild(svgEl("circle", {cx:point.x, cy:point.y, class:"hit",
                                       r:Math.max(size.r * 2.2, 18)}));
    group.appendChild(svgEl("circle", {cx:point.x, cy:point.y,
                                       r:kind === "self" ? size.self : size.r}));
    const text = svgEl("text", {x:point.x,
                                y:point.y + (kind === "self" ? size.self + 15 : size.r + 11)});
    text.textContent = kind === "self" ? "this node"
                                       : nodeLabel(id, (MAP_NAMES[id] || ""));
    group.appendChild(text);
    if(caption && size.labels){
      const under = svgEl("text", {x:point.x, y:point.y + size.r + 22, class:"elabel"});
      under.textContent = caption;
      group.appendChild(under);
    }
    svg.appendChild(group);
  };
  direct.forEach((node) => dot(node.id, place.get(node.id), "direct",
                               "Direct link to " + node.id,
                               node.since ? "up " + fmtDuration(node.since) : ""));
  routed.forEach((node) => dot(node.id, place.get(node.id), "routed",
                               "Routed session with " + node.id + " via " + node.via));
  dot(state.id, centre, "self", "This node");
  if(!direct.length && !routed.length){
    const text = svgEl("text", {x:centre.x, y:centre.y + size.self + 34, class:"lonely"});
    text.setAttribute("fill", "var(--text-faint)");
    text.setAttribute("text-anchor", "middle");
    text.textContent = "no links yet";
    svg.appendChild(text);
  }
  // Both are node counts: the map draws one dot per identity, however many
  // links that identity holds. The card's sub-line says so in words.
  const summary = direct.length + " direct" +
    (routed.length ? " · " + routed.length + " routed" : "");
  if(size.labels) $("map-summary").textContent = summary;
  else $("map-count").textContent = summary;
}

// ---- the expanded map ------------------------------------------------------
// Same data, more of it: the small card answers "am I connected", this answers
// "what is the mesh doing right now".
let MAP_PICK = null;

function paintMap(){
  const dialog = $("map-dialog");
  if(!dialog.open || !STATE) return;
  renderGraph($("map-svg"), STATE, GRAPH_BIG);
  // renderGraph resets the viewBox to the whole drawing; whatever the operator
  // had zoomed into has to survive the two-second poll, or the map is unusable
  // as soon as it refreshes under the finger.
  applyMapView();
  const direct = (STATE.topology || {}).direct || [];
  // A pick that no longer exists is dropped — the one deselection a repaint is
  // allowed to make.
  if(MAP_PICK && !direct.some((node) => node.id === MAP_PICK)) MAP_PICK = null;
  setHTML("map-links", direct.length ? direct.map((node) => {
    const quality = node.quality || {}, counters = node.counters || {};
    const loss = quality.loss == null ? null : Math.round(quality.loss * 100);
    return '<div class="map-link' + (MAP_PICK === node.id ? " on" : "") +
      '" data-link="' + esc(node.id) + '">' +
      '<div class="top"><b>' + esc(nodeLabel(node.id, node.pseudo)) + "</b>" +
      badge(node.transport || "?", "") +
      (loss ? badge(loss + "%", "warn") : "") + "</div>" +
      '<div class="tiny muted">' +
      (node.rtt_ms == null ? "no probe yet" : node.rtt_ms + " ms" +
        (quality.jitter_ms ? " ±" + quality.jitter_ms : "")) +
      " · " + fmtBytes((counters.bytes_in || 0) + (counters.bytes_out || 0)) +
      (node.since ? " · up " + fmtDuration(node.since) : "") + "</div>" +
      (node.remote ? '<div class="tiny muted mono truncate">' + esc(node.remote) + "</div>" : "") +
      sparkHTML(quality.samples_ms, {width:240, height:22}) +
      '<div class="btn-row"><button class="sm" data-link-details="' + esc(node.id) +
      '">Details</button></div></div>';
  }).join("") : emptyHTML("No direct link",
                          "Nothing to watch until this node has a neighbour."));
  highlightEdge();
  revealPick();
}

// The drawing and the list are one selection, so picking on either has to bring
// the other into view — otherwise clicking a node on the map appears to do
// nothing when its row is below the fold.
function revealPick(){
  if(!MAP_PICK) return;
  const row = document.querySelector('[data-link="' + CSS.escape(MAP_PICK) + '"]');
  if(row) row.scrollIntoView({block:"nearest"});
}
function highlightEdge(){
  $$("#map-svg [data-edge]").forEach((edge) =>
    edge.classList.toggle("on", edge.dataset.edge === MAP_PICK));
  $$("#map-svg [data-node-id]").forEach((node) =>
    node.classList.toggle("picked", node.dataset.nodeId === MAP_PICK));
}
// ---- panning and zooming the map -------------------------------------------
// The viewBox *is* the camera: moving it pans, shrinking it zooms, and every
// label and stroke stays crisp because nothing is rasterised. Null means "the
// whole drawing", which is what a fresh open and the fit button both give.
let MAP_VIEW = null;
// Fitted with a margin: labels are drawn outside their circle, and a box that
// ends exactly at the outermost node cuts the captions on the rim in half.
const MAP_FIT = {x:-60, y:-24, w:GRAPH_BIG.w + 120, h:GRAPH_BIG.h + 48};
const MAP_MIN_W = MAP_FIT.w / 10, MAP_MAX_W = MAP_FIT.w;
const MAP_ASPECT = MAP_FIT.h / MAP_FIT.w;

function mapView(){
  return MAP_VIEW || MAP_FIT;
}
function applyMapView(){
  const svg = $("map-svg"), view = mapView();
  svg.setAttribute("viewBox", view.x + " " + view.y + " " + view.w + " " + view.h);
  $("map-fit").disabled = MAP_VIEW === null;
  // How many drawing units one screen pixel is worth right now. Labels are
  // sized from it, so a name stays the same size on screen whatever the zoom
  // and whatever the screen: zooming in spreads the mesh out instead of
  // inflating the text, and a phone gets readable labels at the fitted view
  // rather than the 4px it would get from a fixed size in a 1020-wide box.
  const rect = svg.getBoundingClientRect();
  const unit = rect.width ? Math.max(view.w / rect.width, view.h / rect.height) : 1;
  svg.style.setProperty("--map-unit", unit.toFixed(3));
  // Level of detail. Readable labels and a whole mesh on a 344px-wide phone are
  // not both possible, and shrinking the text until it fits produces neither.
  // So the drawing drops detail as it zooms out — captions first, then names —
  // and gives it back on the way in, which is what a map does.
  svg.classList.toggle("lod-2", unit > 1.6);
  svg.classList.toggle("lod-3", unit > 2.6);
  $("map-hint").textContent = unit > 2.6
    ? "Zoom in for names · tap a node for its details"
    : "Drag to move · pinch or scroll to zoom";
}
// The SVG letterboxes itself inside its box (xMidYMid meet), so screen-to-user
// has to account for the bars as well as the scale.
function mapFrame(view){
  const rect = $("map-svg").getBoundingClientRect();
  const scale = Math.min(rect.width / view.w, rect.height / view.h) || 1;
  return {rect, scale,
          padX:(rect.width - view.w * scale) / 2,
          padY:(rect.height - view.h * scale) / 2};
}
function mapPoint(clientX, clientY){
  const view = mapView(), frame = mapFrame(view);
  return {x:view.x + (clientX - frame.rect.left - frame.padX) / frame.scale,
          y:view.y + (clientY - frame.rect.top - frame.padY) / frame.scale};
}
// Zoom about a fixed point: whatever was under the cursor (or between the two
// fingers) stays under it, which is the only zoom that does not feel random.
function zoomMapTo(width, anchor, clientX, clientY){
  const w = Math.min(MAP_MAX_W, Math.max(MAP_MIN_W, width));
  const h = w * MAP_ASPECT;
  const frame = mapFrame({x:0, y:0, w, h});
  // All the way out is the fitted view, not a camera that happens to be that
  // wide: zooming out fully is how you ask for "show me everything again".
  MAP_VIEW = w >= MAP_MAX_W ? null
    : {x:anchor.x - (clientX - frame.rect.left - frame.padX) / frame.scale,
       y:anchor.y - (clientY - frame.rect.top - frame.padY) / frame.scale, w, h};
  applyMapView();
}
function zoomMapBy(factor){
  const view = mapView(), rect = $("map-svg").getBoundingClientRect();
  const cx = rect.left + rect.width / 2, cy = rect.top + rect.height / 2;
  zoomMapTo(view.w / factor, mapPoint(cx, cy), cx, cy);
}

const MAP_PTR = new Map();       // live pointers, so a pinch can be told from a drag
let MAP_PINCH = null, MAP_MOVED = 0;
// Capturing the pointer is what makes a drag survive leaving the element — and
// it also retargets the `click` that follows onto the capturing element. So the
// node under the finger is remembered here, at press time, or clicking a node
// on the map reaches the SVG and never the node.
let MAP_DOWN_ON = null;

function mapPointerDown(event){
  MAP_PTR.set(event.pointerId, {x:event.clientX, y:event.clientY});
  MAP_DOWN_ON = (event.target.closest && event.target.closest("[data-node-id]")) || null;
  $("map-svg").setPointerCapture(event.pointerId);
  MAP_MOVED = 0;
  if(MAP_PTR.size === 2){
    const [a, b] = [...MAP_PTR.values()];
    MAP_PINCH = {span:Math.hypot(a.x - b.x, a.y - b.y) || 1,
                 width:mapView().w,
                 anchor:mapPoint((a.x + b.x) / 2, (a.y + b.y) / 2)};
  }
  $("map-svg").classList.add("grabbing");
}
function mapPointerMove(event){
  const last = MAP_PTR.get(event.pointerId);
  if(!last) return;
  const dx = event.clientX - last.x, dy = event.clientY - last.y;
  MAP_PTR.set(event.pointerId, {x:event.clientX, y:event.clientY});
  MAP_MOVED += Math.abs(dx) + Math.abs(dy);
  if(MAP_PTR.size >= 2 && MAP_PINCH){
    const [a, b] = [...MAP_PTR.values()];
    const span = Math.hypot(a.x - b.x, a.y - b.y) || 1;
    zoomMapTo(MAP_PINCH.width * (MAP_PINCH.span / span), MAP_PINCH.anchor,
              (a.x + b.x) / 2, (a.y + b.y) / 2);
    return;
  }
  const view = mapView(), frame = mapFrame(view);
  MAP_VIEW = {x:view.x - dx / frame.scale, y:view.y - dy / frame.scale,
              w:view.w, h:view.h};
  applyMapView();
}
function mapPointerUp(event){
  MAP_PTR.delete(event.pointerId);
  if(MAP_PTR.size < 2) MAP_PINCH = null;
  if(!MAP_PTR.size) $("map-svg").classList.remove("grabbing");
}

$("map-svg").addEventListener("pointerdown", mapPointerDown);
$("map-svg").addEventListener("pointermove", mapPointerMove);
$("map-svg").addEventListener("pointerup", mapPointerUp);
$("map-svg").addEventListener("pointercancel", mapPointerUp);
// Not passive: a scroll over the map has to zoom the map, not the sheet.
$("map-svg").addEventListener("wheel", (event) => {
  event.preventDefault();
  const factor = Math.exp(-event.deltaY * (event.deltaMode === 1 ? .03 : .0015));
  zoomMapTo(mapView().w / factor, mapPoint(event.clientX, event.clientY),
            event.clientX, event.clientY);
}, {passive:false});
$("map-svg").addEventListener("dblclick", () => { MAP_VIEW = null; applyMapView(); });
$("map-in").addEventListener("click", () => zoomMapBy(1.5));
$("map-out").addEventListener("click", () => zoomMapBy(1 / 1.5));
$("map-fit").addEventListener("click", () => { MAP_VIEW = null; applyMapView(); });
$("map-dialog").addEventListener("keydown", (event) => {
  if(event.key === "+" || event.key === "=") zoomMapBy(1.5);
  else if(event.key === "-") zoomMapBy(1 / 1.5);
  else if(event.key === "0"){ MAP_VIEW = null; applyMapView(); }
  else return;
  event.preventDefault();
});

$("map-open").addEventListener("click", () => {
  MAP_VIEW = null;
  $("map-dialog").showModal();
  paintMap();
});
$("map-close").addEventListener("click", () => $("map-dialog").close());
$("map-links").addEventListener("click", (event) => {
  const details = event.target.closest("[data-link-details]");
  if(details){ openNode(details.dataset.linkDetails); return; }
  const row = event.target.closest("[data-link]");
  if(!row) return;
  MAP_PICK = MAP_PICK === row.dataset.link ? null : row.dataset.link;
  paintMap();
});
$("map-svg").addEventListener("click", (event) => {
  // A pan that happens to end on a node is not a click on it.
  if(MAP_MOVED > 6) return;
  const node = MAP_DOWN_ON ||
    (event.target.closest && event.target.closest("[data-node-id]"));
  if(!node) return;
  const id = node.dataset.nodeId;
  // Selecting, not opening: the details are one button away in the row this
  // highlights, and a dialog over the map hides the thing being explored.
  MAP_PICK = MAP_PICK === id ? null : id;
  paintMap();
});
$("graph").addEventListener("click", (event) => {
  const node = event.target.closest && event.target.closest("[data-node-id]");
  if(node){ openNode(node.dataset.nodeId); return; }
  // Clicking the card itself is the obvious way to ask for a bigger one.
  $("map-open").click();
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
// One node may hold several links at once — a LAN address and a punched UDP
// path, say. Listing them flat makes a node with five links look like five
// nodes, and hides the only number that matters at a glance: the best one it
// has. So the table is one row per *node*, opening onto its links.
// Per table, not shared: a node with three links in "active" may have one entry
// in "known", and pruning the shared set against the wrong table folded the row
// back on the next refresh.
const LINKS_OPEN = {active: new Set(), known: new Set()};

function groupByNode(items){
  const order = [], byNode = new Map();
  for(const item of items){
    let group = byNode.get(item.id);
    if(!group){
      group = {id:item.id, pseudo:item.pseudo || "", links:[], best:null, node:item};
      byNode.set(item.id, group);
      order.push(group);
    }
    group.links.push(item);
    const rtt = item.rtt_ms;
    // The best link is the yardstick, and its jitter is the one worth showing:
    // the jitter of a link nobody is using answers no question.
    if(rtt != null && (group.best == null || rtt < group.best.rtt_ms)) group.best = item;
  }
  return order;
}

// A row's *shape* is what it is a row of; its numbers are written in afterwards
// (see `rowValues` and `paintLive`). One row per link, keyed by the link, so a
// table repainted every second keeps the row under the reader's finger.
function rowKey(node, inner){
  return (inner ? "l:" : "n:") + node.id +
         (inner ? "|" + ((node.link || {}).scheme || node.transport || "?") +
                  "|" + ((node.link || {}).remote || "") : "");
}

function linkRowHTML(node, kind, inner){
  const transport = node.transport ||
    ((node.addresses || [])[0] || "").split(":", 1)[0] || "—";
  const key = rowKey(node, inner);
  return '<tr class="link-row"' + (inner ? ' data-inner' : ' data-clickable') +
    ' data-node-id="' + esc(node.id) + '">' +
    '<td class="mono">' + (inner ? '<span class="link-in"></span>' : "") +
      esc(inner ? (transport + " link") : nodeLabel(node.id, node.pseudo)) + "</td>" +
    '<td><span class="badge" data-base="badge" data-v="' + esc(key + ":state") +
      '"></span> <span data-v="' + esc(key + ":loss") + '"></span></td>' +
    "<td>" + esc(transport) +
      ((node.link && node.link.remote)
        ? '<div class="tiny muted mono truncate">' + esc(node.link.remote) + "</div>" : "") +
    "</td>" +
    '<td class="num"><span data-v="' + esc(key + ":rtt") + '"></span>' +
      '<div class="tiny muted" data-v="' + esc(key + ":jitter") + '"></div></td>' +
    '<td data-v="' + esc(key + ":seen") + '"></td>' +
    '<td class="tight">' + (inner ? "" :
      '<button class="sm" data-node-id="' + esc(node.id) + '">Details</button>') +
    "</td></tr>";
}

// The numbers of one row, whether it stands for a node or for one of its links.
function rowValues(node, inner, out){
  const key = rowKey(node, inner);
  const quality = (node.link || {}).quality || {};
  const loss = quality.loss == null ? null : Math.round(quality.loss * 100);
  out[key + ":state"] = {
    text: node.connected ? "authenticated" : (node.has_key ? "key known" : "no key"),
    tone: node.connected ? "ok" : (node.has_key ? "" : "warn")};
  out[key + ":loss"] = {html: loss ? badge(loss + "% loss", "warn") : ""};
  out[key + ":rtt"] = node.rtt_ms == null ? "—" : node.rtt_ms + " ms";
  out[key + ":jitter"] = quality.jitter_ms ? "±" + quality.jitter_ms + " ms" : "";
  out[key + ":seen"] = node.seen_ago == null ? "live" : fmtAgo(node.seen_ago);
  return out;
}

function groupRowHTML(group, unfolded){
  const open = unfolded.has(group.id);
  const best = group.best || group.links[0];
  const quality = (best.link || {}).quality || {};
  const schemes = [...new Set(group.links.map((link) => link.transport ||
    ((link.link || {}).scheme) || "?"))];
  const key = "g:" + group.id;
  return '<tr class="link-row group" data-clickable data-node-id="' + esc(group.id) +
    '"><td class="mono">' +
    '<button class="icon sm fold" data-fold="' + esc(group.id) + '" aria-expanded="' +
    (open ? "true" : "false") + '" aria-label="' +
    (open ? "Hide" : "Show") + ' the links to ' + esc(nodeLabel(group.id, group.pseudo)) + '">' +
    '<svg class="ic turn" viewBox="0 0 24 24" aria-hidden="true"><path d="M6 9.5 12 15.5l6-6"/></svg>' +
    "</button>" + esc(nodeLabel(group.id, group.pseudo)) + "</td>" +
    '<td><span class="badge ok">' + esc(plural(group.links.length, "link")) +
      "</span></td>" +
    "<td>" + esc(schemes.join(", ")) + "</td>" +
    '<td class="num"><span data-v="' + esc(key + ":rtt") + '"></span>' +
      '<div class="tiny muted" data-v="' + esc(key + ":jitter") + '"></div></td>' +
    '<td data-v="' + esc(key + ":seen") + '"></td>' +
    '<td class="tight"><button class="sm" data-node-id="' + esc(group.id) +
    '">Details</button></td></tr>';
}

function groupValues(group, out){
  const key = "g:" + group.id;
  const best = group.best || group.links[0];
  const quality = (best.link || {}).quality || {};
  out[key + ":rtt"] = best.rtt_ms == null ? "—" : best.rtt_ms + " ms";
  out[key + ":jitter"] = quality.jitter_ms ? "±" + quality.jitter_ms + " ms" : "";
  out[key + ":seen"] = best.seen_ago == null ? "live" : fmtAgo(best.seen_ago);
  return out;
}

async function paintNodes(kind){
  const body = $(kind + "-list");
  if(!body.childElementCount) body.innerHTML = spanRow(6, skeletonHTML(3));
  try{
    const items = await fetchPage(kind);
    $(kind + "-count").textContent = PAGES[kind].total;
    const groups = groupByNode(items);
    // A node that is *gone* has nothing to unfold. A node that momentarily
    // shows one link has not gone anywhere — a flapping second link used to
    // fold the row shut under the reader, and it stayed shut.
    const unfolded = LINKS_OPEN[kind];
    [...unfolded].forEach((id) => {
      if(!groups.some((entry) => entry.id === id)) unfolded.delete(id);
    });
    if(!groups.length){
      setHTML(body, spanRow(6, emptyHTML(
        PAGES[kind].query ? "No node matches that" :
          kind === "active" ? "Not connected to any node yet" : "No known node yet",
        PAGES[kind].query ? "Try a shorter prefix of the id, or an address." :
          kind === "active" ? "Add one from Network → Add a node."
                            : "Nodes appear here once this one has heard of them.")));
      body.dataset.shape = "";
    }else{
      // Which rows exist decides the markup; their numbers are written into it.
      // Rebuilding the table every second replaced the row under the reader's
      // finger and shut every row they had unfolded.
      const shape = JSON.stringify(groups.map((group) => [
        group.id, group.pseudo, group.links.length > 1 && unfolded.has(group.id),
        group.links.map((link) => rowKey(link, group.links.length > 1))]));
      const values = {};
      groups.forEach((group) => {
        if(group.links.length > 1){
          groupValues(group, values);
          if(unfolded.has(group.id))
            group.links.forEach((link) => rowValues(link, true, values));
        }else rowValues(group.links[0], false, values);
      });
      paintLive(body, shape, () => groups.map((group) =>
        group.links.length > 1
          ? groupRowHTML(group, unfolded) + (unfolded.has(group.id)
              ? group.links.map((link) => linkRowHTML(link, kind, true)).join("") : "")
          : linkRowHTML(group.links[0], kind, false)).join(""), values);
    }
    paintPager(kind, kind + "-pager", () => paintNodes(kind));
  }catch(_){
    setHTML(body, spanRow(6, errorHTML("Node list unavailable",
      "The console could not read the routing table just now.")));
    body.dataset.shape = "";
  }
}
["active-list", "known-list"].forEach((id) => $(id).addEventListener("click", (event) => {
  const fold = event.target.closest("[data-fold]");
  if(fold){
    const kind = id.split("-")[0], node = fold.dataset.fold;
    if(LINKS_OPEN[kind].has(node)) LINKS_OPEN[kind].delete(node);
    else LINKS_OPEN[kind].add(node);
    paintNodes(kind);
    return;
  }
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
// The dialog is a frame; what is inside it is the shared view, which is also
// what /node serves. One description of a node, wherever it is looked at.
async function openNode(id, seed){
  DETAIL_ID = id;
  const dialog = $("node-dialog");
  if(!dialog.open) dialog.showModal();
  $("node-dialog-title").textContent = nodeLabel(id, (seed && seed.pseudo) || MAP_NAMES[id] || "");
  await NODEVIEW.mount("node-detail", id, {
    selfId: STATE ? STATE.id : null,
    seed,
    onGone(){ dialog.close(); Promise.all([refreshPeers(), tick()]); },
  });
}
$("node-dialog-close").addEventListener("click", () => $("node-dialog").close());

// ---- reachability ----------------------------------------------------------
function paintReach(state){
  const network = state.network || {};
  // What is left here is about the *node*: can it see out at all, and how many
  // seeks are in flight. A public IP is a fact about IP, and it now lives in
  // the transport that dials with it.
  const summary = [
    ["Internet", network.internet == null ? "Checking…" : network.internet ? "Online" : "Offline"],
    ["Pending seeks", state.pending_seeks || 0],
  ];
  setHTML("network-summary", summary.map(([key, value]) =>
    '<div class="stat sm"><span class="v">' + esc(value) +
    '</span><span class="k">' + esc(key) + "</span></div>").join(""));
  const transports = state.transport_details || [];
  // Aggregated from the live links rather than reported per scheme: the peers
  // are where the bytes and the latency actually are.
  const byScheme = {};
  for(const peer of (state.peers || [])){
    const link = peer.link || {};
    const scheme = link.scheme || peer.transport || "?";
    const row = byScheme[scheme] || (byScheme[scheme] = {bytes:0, rtt:[], links:0});
    row.links++;
    row.bytes += ((link.counters || {}).bytes_in || 0) + ((link.counters || {}).bytes_out || 0);
    const rtt = (link.quality || {}).rtt_ms;
    if(rtt != null) row.rtt.push(rtt);
  }
  TRANSPORT_LIVE = byScheme;
  $("dyn-toggle").textContent = "Dynamic addressing: " + (state.dynamic_address ? "on" : "off");
  paintBalance(state);
  const address = [
    ["Advertised", (state.advertised || []).join("\n") || "None"],
    ["Local IPs", (state.local_ips || []).join(", ") || "None"],
    ["Schemes", (state.transports || []).join(", ") || "None"],
  ];
  paintLive("addressing", "addressing",
    () => address.map(([key]) => "<dt>" + esc(key) + '</dt><dd class="mono pre" data-v="addr:' +
      esc(key) + '"></dd>').join(""),
    Object.fromEntries(address.map(([key, value]) => ["addr:" + key, value])));
  paintTransportLive(state);
  paintRefusals(state);
}
// Refusals are a table of *reasons*, so the row key is the reason: a count that
// climbs must climb in place rather than redraw the list under a reader.
function paintRefusals(state){
  const rows = state.handshake_refusals || [];
  $("refusals-card").hidden = rows.length === 0;
  if(!rows.length) return;
  const cell = (key) => '<span data-v="' + esc(key) + '"></span>';
  const values = {};
  rows.forEach((row) => {
    values[row.reason + ":peer"] = row.peer ? shortId(row.peer) : "—";
    values[row.reason + ":count"] = row.count;
    values[row.reason + ":at"] = row.at ? fmtAgo(Date.now() / 1000 - row.at) : "—";
  });
  paintLive("refusals-list", rows.map((row) => row.reason).join("|"),
    () => rows.map((row) =>
      "<tr><td>" + esc(row.reason) +
      '</td><td class="mono">' + cell(row.reason + ":peer") +
      '</td><td class="num">' + cell(row.reason + ":count") +
      "</td><td>" + cell(row.reason + ":at") + "</td></tr>").join(""),
    values);
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
// The slider says how the two halves of a score are weighed; the line under it
// is the answer, computed by the node and not re-derived here — one rule, one
// implementation.
function paintBalance(state){
  const slider = $("balance");
  // Never yank the handle out from under a finger mid-drag.
  if(document.activeElement !== slider && !BALANCE_HELD)
    slider.value = state.transport_balance == null ? 50 : state.transport_balance;
  showBalance(Number(slider.value));
  const order = state.transport_preference || [];
  setHTML("balance-order", order.length
    ? "Tried in this order, all else equal: " + order.map((entry) =>
        '<span class="chip">' + esc(entry.scheme) +
        '<span class="muted">' + (entry.priority > 0 ? "+" : "") +
        esc(entry.priority) + "</span></span>").join(" ")
    : "");
}
function showBalance(value){
  $("balance-value").textContent = value === 0 ? "Latency only"
    : value === 100 ? "Priority only"
    : value + "% priority · " + (100 - value) + "% latency";
}
let BALANCE_HELD = false;
$("balance").addEventListener("input", (event) => {
  BALANCE_HELD = true;
  showBalance(Number(event.target.value));
});
$("balance").addEventListener("change", async (event) => {
  const value = Number(event.target.value);
  try{
    const {ok, data} = await apiJson("/api/addressing/balance", "POST", {value});
    if(!ok){ toast(data.error || "Refused", "warn"); return; }
    toast("Address preference updated", "ok");
  }catch(_){ toast("Could not save the balance", "danger"); }
  finally{ BALANCE_HELD = false; tick(); }
});
$("net-recheck").addEventListener("click", () => post("/api/net/recheck", {}, "Network check requested"));
$("dyn-toggle").addEventListener("click", () => STATE &&
  post("/api/addressing/dynamic", {enabled:!STATE.dynamic_address},
       "Dynamic addressing updated"));
$("reach-probe").addEventListener("click", (event) => withBusy(event.target, async () => {
  try{
    const {data} = await apiJson("/api/reachability/probe", "POST");
    toast(data.sent ? "Sent " + data.sent + " reachability probe(s)"
                    : "No connected node can probe us", data.sent ? "" : "warn");
  }catch(_){ toast("Probe failed", "danger"); }
}));
$("transport-blocks").addEventListener("click", async (event) => {
  const block = event.target.closest("[data-scheme]");
  if(!block) return;
  const scheme = block.dataset.scheme;

  const remove = event.target.closest("[data-remove-listener]");
  if(remove){
    await api("/api/unlisten", "POST", {uri:remove.dataset.removeListener}).catch(() => {});
    toast("Listener removed");
    tick();
    return;
  }
  if(event.target.closest("[data-listen-add]")){
    const input = block.querySelector("[data-listen-uri]");
    const uri = input.value.trim();
    if(!uri){ toast("Enter a listener URI", "warn"); return; }
    await withBusy(event.target, async () => {
      const {ok, data} = await apiJson("/api/listen", "POST", {uri});
      if(ok){ input.value = ""; toast("Listener added"); tick(); }
      else toast(data.error || "Listener failed", "danger");
    });
    return;
  }
  if(event.target.closest("[data-udp-toggle]")){
    if(!STATE) return;
    const on = (STATE.transport_details || []).some((item) => item.hole_punch);
    const port = parseInt(block.querySelector("[data-udp-port]").value, 10);
    if(!on && !(port > 0 && port < 65536)){ toast("Enter a valid UDP port", "warn"); return; }
    post("/api/udp", on ? {action:"stop"} : {action:"start", port},
         on ? "UDP stopped" : "UDP started");
    return;
  }
  const view = event.target.closest("[data-view]");
  if(view){
    const wanted = view.dataset.view;
    $$("[data-view]", block).forEach((button) =>
      button.setAttribute("aria-selected", button.dataset.view === wanted ? "true" : "false"));
    $$("[data-panel]", block).forEach((panel) => {
      panel.hidden = panel.dataset.panel !== wanted;
    });
    return;
  }
  const flag = event.target.closest("[data-flag]");
  if(flag && STATE){
    const paths = {punch:"/api/punch", keepalive:"/api/punch/keepalive",
                   lan:"/api/lan/discovery"};
    const fields = {punch:"punch_enabled", keepalive:"punch_keepalive",
                    lan:"lan_discovery"};
    const name = flag.dataset.flag;
    post(paths[name], {enabled:!STATE[fields[name]]}, "Setting updated");
    return;
  }
  if(event.target.closest("[data-apply]")) await applyTransport(scheme, event.target);
});

// ---- transport settings ----------------------------------------------------
// Every field is rendered from what the transport declared: name, kind, bounds,
// choices, help. The console has no idea what a "reorder buffer" is, and that is
// the point — a medium added tomorrow gets this form for free.
let TRANSPORT_FORM = [], TRANSPORT_LIVE = {};

function fieldId(scheme, name){ return "opt-" + scheme + "-" + name.replace(/_/g, "-"); }

function optionHTML(scheme, field){
  const id = fieldId(scheme, field.name);
  const label = esc(field.label) + (field.unit ? ' <span class="muted">(' +
    esc(field.unit) + ")</span>" : "") +
    (field.restart ? " " + badge("restart", "warn") : "");
  const help = '<span class="hint">' + esc(field.help) + "</span>";
  if(field.kind === "bool")
    return '<label class="check card-like"><input type="checkbox" id="' + id + '"' +
      (field.value ? " checked" : "") + "><span><b>" + label + "</b><br>" +
      esc(field.help) + "</span></label>";
  if(field.kind === "multi")
    return '<div class="field"><span>' + label + "</span>" +
      '<div class="chips" id="' + id + '">' + (field.choices || []).map((choice) =>
        '<label class="check"><input type="checkbox" value="' + esc(choice.value) + '"' +
        ((field.value || []).includes(choice.value) ? " checked" : "") + "><span>" +
        esc(choice.label || choice.value) + "</span></label>").join("") + "</div>" +
      help + "</div>";
  if(field.kind === "choice")
    return '<label class="field"><span>' + label + '</span><select id="' + id + '">' +
      (field.choices || []).map((choice) =>
        '<option value="' + esc(choice.value) + '"' +
        (choice.value === field.value ? " selected" : "") + ">" +
        esc(choice.label || choice.value) + "</option>").join("") + "</select>" +
      help + "</label>";
  const type = (field.kind === "int" || field.kind === "float") ? "number" : "text";
  const step = field.kind === "float" ? ' step="any"' : "";
  return '<label class="field"><span>' + label + '</span><input id="' + id +
    '" type="' + type + '"' + step +
    (field.min == null ? "" : ' min="' + esc(field.min) + '"') +
    (field.max == null ? "" : ' max="' + esc(field.max) + '"') +
    (field.placeholder ? ' placeholder="' + esc(field.placeholder) + '"' : "") +
    ' value="' + esc(field.value == null ? "" : field.value) + '">' + help + "</label>";
}

function readOption(scheme, field){
  const element = $(fieldId(scheme, field.name));
  if(!element) return null;
  if(field.kind === "bool") return element.checked;
  if(field.kind === "multi")
    return $$("input:checked", element).map((input) => input.value);
  if(field.kind === "int") return parseInt(element.value, 10);
  if(field.kind === "float") return parseFloat(element.value);
  return element.value;
}

// One block per medium. What used to be three cards — a table of live
// transports, a form of declared settings, and a "Listeners & addressing" card
// that was in fact TCP and UDP settings under a neutral name — is one list of
// blocks: everything about tcp is in the tcp block, everything about udp is in
// the udp block, and a medium nobody has written yet gets the same shape for
// free. Only *addressing* stayed apart: what this node advertises is a fact
// about the node, not about one medium.

// Per-scheme extras the core cannot derive: controls that exist because of what
// that medium is. Anything a transport can declare belongs in its OPTIONS
// instead — this table is for the few things that are a node-level action on
// one medium rather than a value.
const SCHEME_EXTRAS = {
  udp: () =>
    '<div class="toolbar">' +
    '<label class="field"><span>UDP port</span>' +
    '<input type="number" min="1" max="65535" value="9001" data-udp-port aria-label="UDP port"></label>' +
    "<button data-udp-toggle></button>" +
    '<button data-flag="punch"></button>' +
    '<button data-flag="keepalive"></button>' +
    '<button data-flag="lan"></button></div>' +
    '<p class="hint">Hole punching and the NAT keepalive are what make this node ' +
    "reachable from behind a router; LAN discovery answers beacons on the local " +
    "network. All three ride on this socket.</p>",
};

// Opening a transport answers "how is this medium doing" before it answers
// "what can I change about it". Both in one scroll made the second question
// bury the first, and the first is the one people open the block for.
function transportBlockHTML(scheme, options, open, view){
  const extras = SCHEME_EXTRAS[scheme];
  const settings = view === "settings";
  return '<details class="card" data-scheme="' + esc(scheme) + '"' + (open ? " open" : "") +
    "><summary>" + esc(scheme) +
    '<span class="grow"></span><span class="row" data-summary></span></summary>' +
    '<div class="card-body">' +
    '<div class="segmented" role="tablist" aria-label="' + esc(scheme) + ' view">' +
    '<button role="tab" data-view="status" aria-selected="' + (settings ? "false" : "true") +
    '">Status</button>' +
    '<button role="tab" data-view="settings" aria-selected="' + (settings ? "true" : "false") +
    '">Settings</button></div>' +

    '<div data-panel="status"' + (settings ? " hidden" : "") + ">" +
    '<div class="stats" data-stats></div>' +
    '<dl class="kv" data-facts></dl>' +
    "<h3>Listeners</h3>" +
    '<div class="chips" data-listeners></div>' +
    '<div class="toolbar"><label class="field grow"><span class="sr-only">Listener URI</span>' +
    '<input class="mono" data-listen-uri spellcheck="false" placeholder="' +
    esc(scheme) + '://0.0.0.0:9002"></label>' +
    "<button data-listen-add>Add listener</button></div>" +
    (extras ? extras() : "") + "</div>" +

    '<div data-panel="settings"' + (settings ? "" : " hidden") + ">" +
    (options.length
      ? '<div class="form-grid">' +
        options.map((field) => optionHTML(scheme, field)).join("") +
        '</div><div class="btn-row"><button class="primary" data-apply>Apply</button>' +
        '<span class="msg" id="opt-msg-' + esc(scheme) + '"></span></div>'
      : '<p class="hint">This medium declares no setting.</p>') +
    "</div></div></details>";
}

// Facts that belong to one medium and to no other. The public IP is what a peer
// dials over TCP; the STUN address is what it dials over UDP; neither is a
// property of the node, which is where they used to be shown.
//
// Reachability is the exception, and knowingly so: the node decides it once,
// across every transport (`relay_capable`). Showing it on the IP transports is
// a presentation choice — where an operator looks for it — not a claim that it
// was measured per medium. Making it genuinely per-transport is backend work.
const SCHEME_FACTS = {
  tcp: (state) => [
    ["Public IP", (state.network || {}).public_ip || "Unknown"],
    ["Reachable from", state.relay_capable ? "the open internet" : "this network only"],
  ],
  udp: (state) => [
    ["Public UDP", (state.network || {}).stun_addr || "Unknown"],
    ["Reachable from", state.relay_capable ? "the open internet" : "this network only"],
  ],
};

// Rebuilt only when the set of transports or their declared settings changes:
// a redraw on every tick would wipe the field someone is typing in.
async function loadTransportOptions(){
  const holder = $("transport-blocks");
  const open = new Set($$("#transport-blocks details[open]")
    .map((element) => element.dataset.scheme));
  const views = {};
  $$("#transport-blocks [data-scheme]").forEach((block) => {
    const chosen = block.querySelector('[data-view][aria-selected="true"]');
    if(chosen) views[block.dataset.scheme] = chosen.dataset.view;
  });
  const declared = {};
  let persisted = true;
  try{
    const {data} = await apiJson("/api/transports");
    TRANSPORT_FORM = data.transports || [];
    persisted = data.persisted !== false;
    TRANSPORT_FORM.forEach((entry) => { declared[entry.scheme] = entry.options; });
  }catch(_){
    holder.innerHTML = errorHTML("Transports unavailable", "The node did not answer.");
    return;
  }
  const schemes = [...new Set([
    ...((STATE && STATE.transport_details) || []).map((item) => item.scheme),
    ...Object.keys(declared),
  ])].sort();
  holder.innerHTML = schemes.length
    ? schemes.map((scheme) =>
        transportBlockHTML(scheme, declared[scheme] || [], open.has(scheme),
                           views[scheme] || "status")).join("")
    : emptyHTML("No transport registered",
                "A node with no transport can neither listen nor dial.");
  if(!persisted && schemes.length)
    holder.insertAdjacentHTML("afterbegin",
      '<div class="notice warn"><span>This node has no configuration file, so a ' +
      "change applies now but is forgotten on restart.</span></div>");
  if(STATE) paintTransportLive(STATE);
}

// The volatile half, safe to run on every tick: counters, listeners and the
// state of the toggles. Never touches a settings input.
function paintTransportLive(state){
  const details = state.transport_details || [];
  const listening = state.listening || [];
  $$("#transport-blocks [data-scheme]").forEach((block) => {
    const scheme = block.dataset.scheme;
    const info = details.find((item) => item.scheme === scheme) || {};
    const live = TRANSPORT_LIVE[scheme] || {bytes:0, rtt:[], links:0};
    const rtt = live.rtt.length
      ? Math.round(live.rtt.reduce((a, b) => a + b, 0) / live.rtt.length * 10) / 10 : null;
    const mine = listening.filter((uri) => uri.split("://")[0] === scheme);
    const links = info.links || 0;
    setHTML(block.querySelector("[data-summary]"),
      badge(plural(links, "link"), links ? "accent" : "") + " " +
      badge(plural(mine.length, "listener"), "") +
      (info.hole_punch ? " " + badge("hole punching", "ok") : ""));
    setHTML(block.querySelector("[data-stats]"), [
      ["Links", links],
      ["Latency", rtt == null ? "—" : rtt + " ms"],
      ["Carried", fmtBytes(live.bytes)],
      ["Ports", (info.ports || []).length ? info.ports.join(", ") : "—"],
    ].map(([key, value]) => '<div class="stat sm"><span class="v">' + esc(value) +
      '</span><span class="k">' + esc(key) + "</span></div>").join(""));
    const facts = SCHEME_FACTS[scheme];
    setHTML(block.querySelector("[data-facts]"), facts
      ? facts(state).map(([key, value]) => "<dt>" + esc(key) + "</dt><dd>" +
          esc(value) + "</dd>").join("") : "");
    // These chips carry a button each: rebuilt on the cadence, "remove this
    // listener" was a button that could be replaced between the press and the
    // click.
    setHTML(block.querySelector("[data-listeners]"), mine.length ? mine.map((uri) =>
      '<span class="chip">' + esc(uri) + '<button class="icon sm" data-remove-listener="' +
      esc(uri) + '" aria-label="Remove listener ' + esc(uri) + '">' + icon("close") +
    "</button></span>").join("")
      : '<span class="small muted">Nothing bound — this node cannot be dialled over ' +
        esc(scheme) + ".</span>");
    if(scheme !== "udp") return;
    const on = details.some((item) => item.hole_punch);
    const port = block.querySelector("[data-udp-port]");
    block.querySelector("[data-udp-toggle]").textContent = on ? "Stop UDP" : "Start UDP";
    port.disabled = on;
    const labels = {punch:["Hole punching", state.punch_enabled],
                    keepalive:["NAT keepalive", state.punch_keepalive],
                    lan:["LAN discovery", state.lan_discovery]};
    $$("[data-flag]", block).forEach((button) => {
      const [name, value] = labels[button.dataset.flag] || ["", false];
      button.textContent = name + ": " + (value ? "on" : "off");
    });
  });
}

async function applyTransport(scheme, button){
  const entry = TRANSPORT_FORM.find((item) => item.scheme === scheme);
  if(!entry) return;
  const values = {};
  for(const field of entry.options){
    const value = readOption(scheme, field);
    if(value !== null && value === value) values[field.name] = value;
  }
  await withBusy(button, async () => {
    const {ok, data} = await apiJson("/api/transports", "POST", {scheme, values});
    const refused = Object.entries(data.rejected || {});
    if(!ok || refused.length){
      // Deliberately no redraw: what was typed stays on screen next to the
      // reason it was refused, which is the only way to fix it.
      setMessage("opt-msg-" + scheme,
        refused.map(([name, why]) => name + ": " + why).join(" · ") ||
        (data.error || "refused"), true);
      return;
    }
    await loadTransportOptions();
    setMessage("opt-msg-" + scheme,
      data.persisted ? "Applied and saved." : (data.note || "Applied."));
    toast(scheme + " settings applied", "ok");
  });
}

// ---- apps ------------------------------------------------------------------
function paintApps(state){
  const apps = state.apps || [];
  // `setHTML`, not `innerHTML`: this runs on the cadence, and a tile rewritten
  // when nothing about the app changed takes its own buttons with it — the one
  // being pressed included.
  setHTML("builtin-apps", apps.length ? apps.map(appTile).join("")
    : emptyHTML("No built-in app", "This build ships without optional applications."));
  const links = apps.filter((app) => app.running !== false && app.installed)
    .map((app) => '<a href="' + esc(app.path) + '">' + esc(app.name) + "</a>").join("");
  setHTML("app-links", links);
  setHTML("more-apps", links ? '<div class="sep"></div>' + links : "");
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
      // What it says is what the node reported doing, not what we hope: a node
      // nothing would bring back does not restart itself, and says so.
      status.textContent = data.restarting
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

// ---- releases from the mesh ------------------------------------------------
// The node decides everything worth deciding — whose signature it accepts,
// which version is newer, whether this install can be updated at all. Each row
// arrives with its own state and the verb to POST, so nothing here re-derives
// a rule that lives in Python.
function releaseRowHTML(entry){
  const words = {available:"", running:"running now", older:"older than what you run",
                 untrusted:"publisher not pinned"};
  const action = entry.action === "install"
    ? '<button class="sm primary" data-install="' + esc(entry.publisher_id) + '">Install</button>'
    : '<span class="muted small">' + esc(words[entry.state] || entry.state) + "</span>";
  // The size belongs with the version: it is how much this release costs to
  // fetch, not a fact about the publisher.
  const aside = [entry.size ? fmtBytes(entry.size) : "",
                 entry.notes ? esc(entry.notes.slice(0, 140)) : ""].filter(Boolean);
  return "<tr><td><strong>" + esc(entry.version) + "</strong>" +
    (aside.length ? '<div class="tiny muted">' + aside.join(" · ") + "</div>" : "") +
    "</td><td><code>" + esc(shortId(entry.publisher_id)) + "</code>" +
    (entry.trusted ? ' <span class="badge ok">pinned</span>'
                   : ' <span class="badge">unpinned</span>') +
    "</td><td>" + fmtAgo(Date.now() / 1000 - entry.ts) + "</td><td>" + action + "</td></tr>";
}
function publisherRowHTML(entry){
  return '<tr><td>' + (entry.name ? esc(entry.name) : '<span class="muted">unnamed</span>') +
    "</td><td><code>" + esc(shortId(entry.id)) + "</code></td><td>" +
    '<label class="check"><input type="checkbox" data-auto="' + esc(entry.id) + '"' +
    (entry.auto ? " checked" : "") + '><span class="sr-only">Install automatically</span></label>' +
    '</td><td><button class="sm danger" data-unpin="' + esc(entry.id) + '">Unpin</button></td></tr>';
}
// ---- the node's own name ---------------------------------------------------
async function refreshPseudo(){
  try{
    const {ok, data} = await apiJson("/api/pseudo");
    if(!ok) return;
    // Never overwrite a name being typed: this also runs on every tab entry.
    if(document.activeElement !== $("pseudo-input")) $("pseudo-input").value = data.pseudo || "";
    $("pseudo-id").value = data.id || "";
    $("pseudo-input").maxLength = data.max || 50;
  }catch(_){}
}

async function savePseudo(wanted){
  const {ok, data} = await apiJson("/api/pseudo", "POST", {pseudo:wanted});
  if(!ok){
    setMessage("pseudo-status", data.error || "The node refused that name.", true);
    return;
  }
  $("pseudo-input").value = data.pseudo || "";
  // The node keeps the name on its own — it signed a claim and its name store
  // holds it. The configuration file only matters when there is one: a file
  // still naming the old node wins at the next start, and that is the one
  // failure worth warning about.
  const stale = data.error ? " — but " + data.error +
    ", so the configuration file still names the old one." : "";
  setMessage("pseudo-status", data.pseudo
    ? "Now called " + data.pseudo + (stale || " — it survives a restart.")
    : "The name is gone; this node shows only its id.", !!data.error);
  tick();
}

$("pseudo-save").addEventListener("click", (event) =>
  withBusy(event.target, () => savePseudo($("pseudo-input").value)));
$("pseudo-clear").addEventListener("click", async (event) => {
  const agreed = await confirmAction({
    title:"Remove this node's name?",
    body:'<p class="muted small">It will show as its id everywhere until you give it ' +
      "another one. Nothing else changes.</p>",
    confirmLabel:"Remove the name"});
  if(agreed) await withBusy(event.target, () => savePseudo(""));
});
$("pseudo-input").addEventListener("keydown", (event) => {
  if(event.key === "Enter") $("pseudo-save").click();
});

function pseudoRowHTML(hit){
  return '<tr><td><strong>' + esc(hit.pseudo) + "</strong></td>" +
    '<td class="mono" title="' + esc(hit.id) + '">' + esc(shortId(hit.id)) + "</td>" +
    '<td class="tight"><button class="sm" data-node-id="' + esc(hit.id) +
    '">Details</button></td></tr>';
}

async function searchPseudo(wide){
  const query = $("pseudo-search").value.trim();
  if(!query){
    setHTML("pseudo-results", "");
    setMessage("pseudo-search-status", "");
    return;
  }
  try{
    const {ok, data} = await apiJson("/api/pseudo?q=" + encodeURIComponent(query) +
                                     (wide ? "&wide=1" : ""));
    if(!ok) return;
    setHTML("pseudo-results", data.results.map(pseudoRowHTML).join(""));
    setMessage("pseudo-search-status", data.results.length ? "" :
      (wide ? "Nobody on this mesh answers to that."
            : "Nothing here by that name — try asking the network."));
  }catch(_){}
}

$("pseudo-search").addEventListener("input", debounce(() => searchPseudo(false), 200));
$("pseudo-wide").addEventListener("click", (event) =>
  withBusy(event.target, () => searchPseudo(true)));
$("pseudo-results").addEventListener("click", (event) => {
  const button = event.target.closest("[data-node-id]");
  if(button) openNode(button.dataset.nodeId);
});

async function refreshReleases(){
  try{
    const {ok, data} = await apiJson("/api/releases");
    if(!ok) return;
    setHTML("release-rows", data.releases.map(releaseRowHTML).join(""));
    $("release-empty").hidden = data.releases.length > 0;
    setHTML("publisher-rows", data.publishers.map(publisherRowHTML).join(""));
    $("publisher-empty").hidden = data.publishers.length > 0;
    $("publish-key").textContent = data.publisher_key || "";
    if(!data.updatable && data.reason)
      setMessage("release-status", "This install cannot update itself: " + data.reason, true);
    const last = data.log[data.log.length - 1];
    if(last && last.outcome === "installed")
      setMessage("release-status", "Installed " + last.version +
        " — restart the node to run it.");
  }catch(_){}
}
$("release-rows").addEventListener("click", async (event) => {
  const button = event.target.closest("[data-install]");
  if(!button) return;
  const row = button.closest("tr");
  const version = row ? row.querySelector("strong").textContent : "";
  const agreed = await confirmAction({
    title:"Install " + version + "?",
    body:'<p class="muted small">The node fetches this release from the mesh, checks every byte ' +
      "against the signature you pinned, and replaces its own files. It then restarts if a " +
      "service manager is there to bring it back. The previous files are kept either way.</p>",
    confirmLabel:"Install " + version});
  if(!agreed) return;
  await withBusy(button, async () => {
    setMessage("release-status", "Asking a node that has it, and verifying…");
    try{
      const {ok, data} = await apiJson("/api/releases/install", "POST",
        {publisher_id:button.dataset.install, confirm:true});
      setMessage("release-status", ok
        ? (data.restarting
           ? "Installed " + data.version + ". The node is restarting — reload in a moment."
           : "Installed " + data.version + ". Restart the node to run it (previous files kept).")
        : (data.error || "Install failed"), !ok);
    }catch(_){
      // A restart cuts the connection mid-answer, which is a success we cannot
      // read. Say what is true: reload and look.
      setMessage("release-status", "The console stopped answering — if the node "
        + "was restarting, reload this page in a moment.", true);
    }
    await refreshReleases();
  });
});
$("publisher-rows").addEventListener("click", async (event) => {
  const unpin = event.target.closest("[data-unpin]");
  if(!unpin) return;
  const agreed = await confirmAction({
    title:"Unpin this publisher?",
    body:'<p class="muted small">Their releases stay visible, but this node stops accepting ' +
      "code from them.</p>", confirmLabel:"Unpin", danger:true});
  if(!agreed) return;
  await apiJson("/api/releases/untrust", "POST", {publisher_id:unpin.dataset.unpin});
  await refreshReleases();
});
$("publisher-rows").addEventListener("change", async (event) => {
  const box = event.target.closest("[data-auto]");
  if(!box) return;
  const {ok} = await apiJson("/api/releases/auto", "POST",
    {publisher_id:box.dataset.auto, auto:box.checked});
  if(!ok) box.checked = !box.checked;
  else toast(box.checked ? "Their releases will install automatically"
                         : "Automatic installs off for this publisher");
});
$("pin-add").addEventListener("click", (event) => withBusy(event.target, async () => {
  const key = $("pin-key").value.trim();
  if(!key){ setMessage("pin-status", "Paste the publisher's key first", true); return; }
  try{
    const {ok, data} = await apiJson("/api/releases/trust", "POST",
      {key, name:$("pin-name").value.trim(), auto:$("pin-auto").checked});
    setMessage("pin-status", ok ? "Pinned." : (data.error || "Could not pin that key"), !ok);
    if(ok){ $("pin-key").value = ""; $("pin-name").value = ""; $("pin-auto").checked = true; }
  }catch(_){ setMessage("pin-status", "The node did not answer.", true); }
  await refreshReleases();
}));
$("publish-go").addEventListener("click", (event) => withBusy(event.target, async () => {
  const agreed = await confirmAction({
    title:"Publish this node's code?",
    body:'<p class="muted small">The tree installed here is signed with this node\'s identity and ' +
      "offered to the mesh. Anyone who pinned this key can install it.</p>",
    confirmLabel:"Publish"});
  if(!agreed) return;
  // A tree is ~120 chunks onto the DHT: on a busy mesh this is not instant.
  // Whatever happens it must end in a message — a status left mid-sentence is
  // indistinguishable from a node that died.
  setMessage("publish-status", "Reading, hashing and signing — this can take a "
    + "moment on a busy mesh…");
  try{
    const {ok, data} = await apiJson("/api/releases/publish", "POST",
      {notes:$("publish-notes").value});
    setMessage("publish-status", ok
      ? "Published " + data.version + " — " + data.files + " files, "
        + fmtBytes(data.package_bytes) + " to send when someone asks."
      : (data.error || "Publish failed"), !ok);
    if(ok) await refreshReleases();
  }catch(_){
    setMessage("publish-status", "Publishing did not finish — the node may still "
      + "be working. Check Settings → Updates again in a minute.", true);
  }
}));

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
  setHTML("trace-summary", rows.length ? rows.map((row) =>
    "<tr><td>" + (row.direction === "in" ? "← " : "→ ") + esc(row.type) + "</td>" +
    '<td class="num">' + esc(row.packets) + "</td>" +
    '<td class="num">' + esc(fmtBytes(row.bytes)) + "</td>" +
    '<td class="num">' + esc(fmtRate(row.bytes_per_second)) + "</td></tr>").join("")
    : spanRow(4, emptyHTML("Nothing recorded",
        "Start a recording to see which message types this node exchanges.")));
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

// ---- managing another node -------------------------------------------------
// The fleet app knows which nodes granted us `manage`; the console lists them
// here. Switching is not a login by itself: the target's own console password
// is asked for, and the token it returns never reaches this page — it stays in
// the local console's memory for as long as this session lasts.
// A node that also granted `passwordless` mints that session against the grant
// instead, which is the only key an operator holds on a machine they
// provisioned: its password was generated on first start, on a box with no
// screen, and printed to a log nobody read.
let TARGETS = [];

async function loadTargets(){
  let data;
  try{ data = (await apiJson("/api/remote/targets")).data; }catch(_){ return; }
  TARGETS = data.targets || [];
  const pick = $("ctx-pick");
  pick.hidden = !(data.available && TARGETS.length);
  const select = $("ctx-node");
  const options = [["", "This node"]].concat(TARGETS.map((target) =>
    [target.id, (target.label || shortId(target.id)) +
     (target.connected || target.passwordless ? "" : " — password needed")]));
  const keep = select.value;
  select.innerHTML = options.map((pair) =>
    '<option value="' + esc(pair[0]) + '">' + esc(pair[1]) + "</option>").join("");
  select.value = TARGETS.some((target) => target.id === keep) ? keep : CONTEXT.node;
}

// Everything on this page describes one node. A switch invalidates all of it at
// once — the caches, the panels, and anything still in flight — because the
// alternative is a number nobody re-derived still standing under the new
// machine's name. Registered rather than called inline, so a view added later
// is reset by the same list as the rest.
CONTEXT.subscribe(() => {
  STATE = null; PREVIOUS = null; RATES.length = 0; TICKING = false;
  RATE_NOW = {inbound:0, outbound:0};
  MAP_NAMES = {}; MAP_PICK = null; UPDATE_OFFER = null;
  TRANSPORT_FORM = []; TRANSPORT_LIVE = {}; CONFIG_FIELDS = [];
  // What a node can offer is that node's answer, and the buttons drawn from it
  // are the ones an operator is about to press.
  NODEVIEW.apps = {};
  stopTracePolling();
  // A camera is not something to leave running behind a hidden panel.
  stopScan();
  ["active", "known", "catalog", "installed"].forEach((kind) => {
    PAGES[kind].offset = 0; PAGES[kind].query = "";
    LINKS_OPEN[kind] && LINKS_OPEN[kind].clear();
    $(kind + "-list").innerHTML = "";
  });
  // A node card describes a peer of the machine we just left.
  if($("node-dialog").open) $("node-dialog").close();
  $("ctx-node").value = CONTEXT.node;
  // The stream belongs to the console serving this page, so driving another
  // node closes it and coming back opens it again. `start` knows which of the
  // two this is; the page only has to tell it that the answer moved.
  EVENTS.start();
  tick();
  onRoute(ROUTER.section, ROUTER.sub);
  loadTargets();
});

function askForContext(node){
  const target = TARGETS.find((entry) => entry.id === node);
  if(!target){ $("ctx-node").value = CONTEXT.node; return; }
  if(target.connected){ CONTEXT.set(node, target.label); return; }
  const name = target.label || shortId(node);
  const free = !!target.passwordless;
  $("modal-title").textContent = "Manage " + name;
  $("modal-body").innerHTML =
    '<p class="muted small">' + (free
      ? "That node granted this one <b>manage</b> and <b>passwordless</b>: the grant " +
        "is the key, and its console asks for nothing more. Take the right back on " +
        "that node and the session ends with it."
      : "That node granted this one the <b>manage</b> capability. " +
        "It still wants its own console password — the grant opens the channel, the " +
        "password opens the session. It is used once, over the encrypted mesh link, and " +
        "never stored here.") + "</p>" +
    '<p class="mono tiny muted">' + esc(node) + "</p>" +
    (free ? "" :
      '<label class="field"><span>Console password of ' + esc(name) + "</span>" +
      '<input id="ctx-pass" type="password" autocomplete="off"></label>') +
    '<div class="btn-row"><button id="ctx-go" class="primary">Connect</button>' +
    '<button id="ctx-no">Cancel</button></div><p id="ctx-msg" class="msg"></p>';
  const finish = () => { $("modal").close(); $("ctx-node").value = CONTEXT.node; };
  $("ctx-go").addEventListener("click", (event) => withBusy(event.target, async () => {
    const password = free ? null : $("ctx-pass").value;
    if(!free && !password){ setMessage("ctx-msg", "A password is needed.", true); return; }
    setMessage("ctx-msg", "Connecting over the mesh…");
    const {ok, data} = await apiJson("/api/remote/connect", "POST", {node, password});
    if(!free) $("ctx-pass").value = "";
    if(!ok || !data.ok){
      setMessage("ctx-msg", data.error ||
        (free ? "That node refused the grant." : "That node refused the password."), true);
      return;
    }
    $("modal").close();
    CONTEXT.set(node, target.label);
    toast("Managing " + name, "warn");
  }));
  $("ctx-no").addEventListener("click", finish);
  $("modal").addEventListener("close", () => { $("ctx-node").value = CONTEXT.node; },
                              {once:true});
  $("modal").showModal();
  if(!free) $("ctx-pass").focus();
}

$("ctx-node").addEventListener("change", (event) => {
  const node = event.target.value;
  if(!node){ CONTEXT.leave(); return; }
  askForContext(node);
});

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
PALETTE.add("Back to this node", "Action", () => CONTEXT.leave());
PALETTE.add("Open the mesh map", "Action", () => $("map-open").click());
PALETTE.add("Transport settings", "Go to", () => ROUTER.go("network", "reach"));
// Per-browser preferences. They are read where they are used (THEME, OPEN), so
// there is nothing to apply here beyond storing the choice.
function paintPrefs(){
  $("pref-theme").value = THEME.stored() || "system";
  $("pref-open").value = OPEN.read();
}
$("pref-theme").addEventListener("change", (event) => {
  THEME.choose(event.target.value);
  toast("Theme updated");
});
$("pref-open").addEventListener("change", (event) => {
  OPEN.set(event.target.value);
  toast("Links will open " + (event.target.value === "tab" ? "in a new tab"
    : event.target.value === "window" ? "in a separate window"
    : "to suit the screen"));
});
// ---- restarting the node ---------------------------------------------------
// A process cannot restart itself; it can only exit and be started again. So
// the offer depends on there being a service manager watching, and when there
// is not, the item says why rather than disappearing — an operator looking for
// "restart" deserves to find out it is not available and what would make it so.
function paintRestart(state){
  const managed = !!state.service_managed;
  const item = $("more-restart");
  item.disabled = !managed;
  item.textContent = CONTEXT.node
    ? "Restart " + (CONTEXT.label || shortId(CONTEXT.node)) : "Restart this node";
  const why = $("more-restart-why");
  why.hidden = managed;
  why.textContent = managed ? ""
    : "This node runs outside a service manager, so nothing would start it again.";
}

async function restartNode(){
  const who = CONTEXT.node ? (CONTEXT.label || shortId(CONTEXT.node)) : "this node";
  const agreed = await confirmAction({
    title:"Restart " + who + "?",
    danger:true,
    confirmLabel:"Restart",
    body:'<p class="muted small">Every link drops and the node comes back a few ' +
      "seconds later, reconnecting on its own. Sessions and known nodes are kept; " +
      "anything queued for a peer that is not reachable is kept too.</p>" +
      (CONTEXT.node ? '<p class="muted small">This console goes back to the local ' +
        "node while that one is away.</p>" : ""),
  });
  if(!agreed) return;
  const {ok, data} = await apiJson("/api/restart", "POST", {confirm:true});
  if(!ok || !data.restarting){
    toast("Not restarting", "danger", (data && data.error) || "The node refused.");
    return;
  }
  toast("Restarting " + who, "warn", "It should be back in a few seconds.");
  // The node we were driving is the one going away, so stop driving it.
  if(CONTEXT.node) CONTEXT.leave();
}

$("more-restart").addEventListener("click", restartNode);
PALETTE.add("Restart this node", "Action", restartNode);

$("palette-open").addEventListener("click", () => PALETTE.open());
$("more-search").addEventListener("click", () => PALETTE.open());
$("more-logout").addEventListener("click", () => $("logout").click());
$("modal-close").addEventListener("click", () => $("modal").close());

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
