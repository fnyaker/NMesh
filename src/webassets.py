"""Embedded, self-contained web console assets (no external resources).

Served same-origin so a strict ``default-src 'self'`` CSP applies with no
inline scripts or styles.
"""

INDEX_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>NMesh Console</title>
<link rel="stylesheet" href="/style.css">
</head>
<body>
<div id="login" class="login">
  <form id="login-form" class="card">
    <h1>NMesh<span>console</span></h1>
    <p class="muted">Local node management</p>
    <input id="password" type="password" placeholder="Console password" autocomplete="current-password" autofocus>
    <button type="submit">Unlock</button>
    <div id="login-error" class="error"></div>
  </form>
</div>

<div id="app" class="app hidden">
  <header>
    <div class="brand">NMesh<span>console</span></div>
    <div class="node-meta">
      <span id="node-id" class="mono"></span>
      <span id="node-state" class="badge"></span>
      <span id="node-uptime" class="muted"></span>
    </div>
    <button id="logout" class="ghost">Log out</button>
  </header>

  <section class="tiles" id="tiles"></section>

  <section class="grid">
    <div class="card">
      <h2>Throughput</h2>
      <canvas id="chart" width="600" height="180"></canvas>
      <div class="legend"><span class="dot in"></span>in <span class="dot out"></span>out (KB/s)</div>
    </div>
    <div class="card">
      <h2>Network</h2>
      <svg id="graph" viewBox="0 0 320 260" preserveAspectRatio="xMidYMid meet"></svg>
    </div>
  </section>

  <section class="card">
    <h2>Peers</h2>
    <div class="mrow">
      <button id="ping-btn" class="ghost" title="PING every connected peer now — refreshes round-trip time and liveness">Ping peers</button>
      <span id="ping-status" class="muted"></span>
    </div>
    <table id="peers"><thead><tr>
      <th>Node</th><th>Dir</th><th>Session</th><th>RTT</th><th>Bad</th><th>In</th><th>Out</th>
    </tr></thead><tbody></tbody></table>
  </section>

  <section class="card">
    <h2>Known nodes <span id="known-count" class="muted"></span></h2>
    <div class="mrow">
      <input id="known-search" type="search" placeholder="search id or address…"
             title="filter known nodes by id or address">
      <label class="muted" for="known-limit">Show latest</label>
      <input id="known-limit" type="number" min="1" max="1000" value="20"
             title="how many of the most recently seen nodes from the routing table to show">
    </div>
    <table id="known"><thead><tr>
      <th>Node</th><th>Addresses</th><th>Last seen</th><th>Link</th><th></th>
    </tr></thead><tbody></tbody></table>
    <div id="known-status" class="muted"></div>
  </section>

  <section class="card">
    <h2>Transports</h2>
    <div id="reach-status" class="netrow"></div>
    <div id="net-status" class="netrow"></div>
    <div class="mrow tctl">
      <button id="punch-toggle" class="ghost"></button>
      <button id="keepalive-toggle" class="ghost" title="keep the NAT mapping open continuously so this node stays reachable / can relay behind NAT"></button>
      <button id="udp-toggle" class="ghost"></button>
      <input id="udp-port" type="number" min="1" max="65535" value="9001" title="UDP port">
      <button id="lan-toggle" class="ghost" title="answer LAN discovery beacons — be findable as a relay by joiners on your network"></button>
      <button id="reach-probe" class="ghost" title="ask a peer to dial you back and confirm you're reachable (AutoNAT)">Confirm reachability</button>
      <button id="net-recheck" class="ghost">Re-check network</button>
      <span id="tctl-status" class="muted"></span>
    </div>
    <div id="reach-cards" class="tcards"></div>
    <div id="transport-cards" class="tcards"></div>
    <div id="punch-block"></div>
  </section>

  <section class="card expert">
    <h2>Expert — addressing</h2>
    <div class="xrow"><span class="xk">Advertised URIs</span><ul id="x-advertised" class="mono"></ul></div>
    <div class="xrow"><span class="xk">Listening</span><ul id="x-listening" class="mono"></ul></div>
    <div class="xrow"><span class="xk">Local IPs</span><ul id="x-localips" class="mono"></ul></div>
    <div class="mrow join">
      <input id="listen-uri" placeholder="tcp://0.0.0.0:9002 — add a listener">
      <button id="listen-btn" class="ghost">Listen</button>
    </div>
  </section>

  <section class="card">
    <h2>Connect a node</h2>
    <p class="muted">Two copy-pastes, no relay needed. NAT holes open automatically.</p>
    <div class="connect">
      <div class="cbox">
        <div class="ctitle">Join someone <span class="muted">(you connect to them)</span></div>
        <button id="cx-request">1 · Create request</button>
        <textarea id="cx-request-out" class="mono" readonly placeholder="→ send this block to the node you want to join"></textarea>
        <textarea id="cx-reply-in" class="mono" placeholder="3 · paste the block they send back"></textarea>
        <div class="mrow">
          <button id="cx-complete">Connect</button>
          <span id="cx-join-progress" class="muted"></span>
        </div>
      </div>
      <div class="cbox">
        <div class="ctitle">Accept someone <span class="muted">(they connect to you)</span></div>
        <textarea id="cx-accept-in" class="mono" placeholder="2 · paste their request block"></textarea>
        <button id="cx-accept">Make invite</button>
        <textarea id="cx-accept-out" class="mono" readonly placeholder="→ send this block back to them"></textarea>
      </div>
    </div>
    <div id="connect-status" class="muted"></div>
  </section>

  <section class="card">
    <h2>Invite across NAT (relay)</h2>
    <p class="muted">When a direct link is impossible (4G/CGNAT, double NAT): the invitation is routed through a relay — a public node, or any member found on your LAN. No direct link needed.</p>
    <div class="connect">
      <div class="cbox">
        <div class="ctitle">Invite a node <span class="muted">(bring someone in)</span></div>
        <button id="rly-invite">Generate relay invite</button>
        <textarea id="rly-invite-out" class="mono" readonly placeholder="→ send this block to the node you want to bring in"></textarea>
      </div>
      <div class="cbox">
        <div class="ctitle">Join a network <span class="muted">(you connect in)</span></div>
        <textarea id="rly-join-in" class="mono" placeholder="paste a relay invite block"></textarea>
        <div class="mrow">
          <button id="rly-join">Join via relay</button>
          <span id="rly-join-progress" class="muted"></span>
        </div>
      </div>
    </div>
    <div id="rly-status" class="muted"></div>
  </section>

  <section class="card expert">
    <h2>Manage</h2>
    <div class="manage">
      <details class="expert-join">
        <summary class="muted">One-shot invite block (host is publicly reachable)</summary>
        <div class="mrow">
          <button id="gen-block" class="ghost">Generate invite block</button>
        </div>
        <textarea id="block-out" class="mono" readonly placeholder="Invite block (base64)"></textarea>
        <textarea id="join-block-in" class="mono" placeholder="Paste an invite block to join"></textarea>
        <div class="mrow">
          <button id="join-block-btn" class="ghost">Join with block</button>
          <span id="join-progress" class="muted"></span>
        </div>
      </details>
      <details class="expert-join">
        <summary class="muted">Manual invite / join (uri + code)</summary>
        <div class="mrow">
          <button id="gen-invite" class="ghost">Generate invite code</button>
          <code id="invite-out" class="mono"></code>
        </div>
        <div class="mrow join">
          <input id="join-uri" placeholder="tcp://host:port">
          <input id="join-code" placeholder="invite code">
          <button id="join-btn" class="ghost">Join network</button>
        </div>
      </details>
      <div class="mrow">
        <button id="show-cert">Show our root certificate</button>
      </div>
      <textarea id="cert-out" class="mono" readonly placeholder="Our root cert (share it so another node trusts us)"></textarea>
      <textarea id="trust-in" class="mono" placeholder="Paste another node's root cert (hex) to trust it"></textarea>
      <div class="mrow"><button id="trust-btn">Trust certificate</button></div>
      <div id="manage-status" class="muted"></div>
    </div>
  </section>

  <section class="card" id="apps-card">
    <h2>Apps</h2>
    <p class="muted">Applications running on this node, wired to the mesh.</p>
    <div id="apps-list" class="apps"></div>
  </section>

  <section class="card">
    <h2>Apps (DHT)</h2>
    <div class="manage">
      <div class="mrow join">
        <input id="app-name" placeholder="app name">
        <input id="app-version" placeholder="version" value="1.0.0">
      </div>
      <div class="mrow">
        <input id="app-files" type="file" multiple>
        <button id="publish-btn">Publish to mesh</button>
      </div>
      <div class="mrow">Published id: <code id="app-id-out" class="mono"></code></div>
      <div class="mrow join">
        <input id="fetch-id" placeholder="app id (hex) to fetch">
        <button id="fetch-btn">Fetch from mesh</button>
      </div>
      <div id="app-files-out"></div>
      <div id="app-status" class="muted"></div>
    </div>
  </section>

  <section class="card" id="store-card">
    <h2>App Store</h2>
    <p class="muted">Apps published on the network. Publishing announces to every
      node; the catalog is shared and re-gossiped automatically.</p>
    <div class="manage">
      <div class="mrow join">
        <input id="store-name" placeholder="app name">
        <input id="store-version" placeholder="version" value="1.0.0">
      </div>
      <div class="mrow">
        <input id="store-files" type="file" multiple>
        <button id="store-publish-btn">Publish to store</button>
      </div>
      <div id="store-status" class="muted"></div>
    </div>
    <h3>Available</h3>
    <table class="store-table"><tbody id="store-catalog"></tbody></table>
    <h3>Installed</h3>
    <table class="store-table"><tbody id="store-installed"></tbody></table>
  </section>
</div>

<script src="/app.js"></script>
</body>
</html>
"""

STYLE_CSS = """
:root{--bg:#0e1116;--card:#171b22;--line:#242a33;--fg:#e6e9ef;--muted:#8b93a1;
--accent:#4da3ff;--in:#3fb950;--out:#f78166;--ok:#3fb950;--bad:#f85149}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);
font:14px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
.hidden{display:none!important}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
.muted{color:var(--muted)}
.error{color:var(--bad);min-height:1.2em;margin-top:8px}
.login{display:flex;min-height:100vh;align-items:center;justify-content:center}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:18px}
.login .card{width:320px;text-align:center}
h1{margin:0 0 2px;font-size:26px}
h1 span,.brand span{color:var(--accent);margin-left:6px;font-weight:400}
h2{margin:0 0 12px;font-size:14px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted)}
input,textarea,button{font:inherit}
input,textarea{width:100%;background:#0e1116;border:1px solid var(--line);color:var(--fg);
border-radius:8px;padding:9px 11px;margin-top:8px}
textarea{min-height:70px;resize:vertical;word-break:break-all}
button{background:var(--accent);color:#04122a;border:0;border-radius:8px;
padding:9px 14px;font-weight:600;cursor:pointer}
button.ghost{background:transparent;color:var(--muted);border:1px solid var(--line);font-weight:500}
button:hover{filter:brightness(1.08)}
.app{max-width:980px;margin:0 auto;padding:18px}
header{display:flex;align-items:center;gap:14px;margin-bottom:16px}
.brand{font-size:20px;font-weight:700}
.node-meta{display:flex;gap:12px;align-items:center;margin-left:auto;flex-wrap:wrap}
.badge{padding:2px 9px;border-radius:999px;font-size:12px;background:#223;color:var(--muted)}
.badge.up{background:rgba(63,185,80,.15);color:var(--ok)}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:12px;margin-bottom:16px}
.tile{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px}
.tile .v{font-size:22px;font-weight:700}
.tile .k{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.05em}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:16px}
@media(max-width:760px){.grid{grid-template-columns:1fr}}
canvas{width:100%;height:auto;background:#0e1116;border-radius:8px}
.legend{margin-top:8px;color:var(--muted);font-size:12px}
.dot{display:inline-block;width:9px;height:9px;border-radius:50%;margin:0 4px 0 10px}
.dot.in{background:var(--in)}.dot.out{background:var(--out)}
svg{width:100%;height:auto}
table{width:100%;border-collapse:collapse}
th,td{text-align:left;padding:7px 8px;border-bottom:1px solid var(--line);font-size:13px}
th{color:var(--muted);font-weight:500}
.manage{display:flex;flex-direction:column;gap:10px}
.mrow{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
.mrow.join input{width:auto;flex:1;margin:0}
#invite-out{color:var(--accent)}
section{margin-bottom:16px}
.expert .xrow{display:grid;grid-template-columns:150px 1fr;gap:10px;padding:6px 0;border-bottom:1px solid var(--line)}
.expert .xk{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.05em}
.expert ul{margin:0;padding:0;list-style:none;display:flex;flex-direction:column;gap:2px}
.expert ul li{word-break:break-all}
.pill{display:inline-block;background:#223;border:1px solid var(--line);border-radius:999px;
padding:2px 9px;margin:2px 4px 2px 0;font-size:12px}
.pill.on{background:rgba(63,185,80,.15);color:var(--ok);border-color:transparent}
.netrow{display:flex;gap:14px;flex-wrap:wrap;align-items:center;margin-bottom:12px}
.netrow .badge.down{background:rgba(248,81,73,.15);color:var(--bad)}
.netrow .nk{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.05em;margin-right:4px}
.krow{white-space:nowrap}
.krow button{margin-left:6px}
tr.kdetails td{background:rgba(127,127,127,.06)}
.kd{display:grid;grid-template-columns:110px 1fr;gap:6px 12px;padding:8px 4px}
.kd .nk{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.05em}
.kd ul{margin:0;padding-left:16px}
#known-search{min-width:200px}
.tcards{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px}
.tcard{background:#0e1116;border:1px solid var(--line);border-radius:10px;padding:12px}
.tcard h3{margin:0 0 8px;font-size:13px;display:flex;align-items:center;gap:8px}
.tcard .kv{display:flex;justify-content:space-between;gap:8px;font-size:13px;padding:2px 0}
.tcard .kv .k{color:var(--muted)}
.tcard ul{margin:4px 0 0;padding:0;list-style:none;font-size:12px}
.tcard ul li{word-break:break-all}
.tctl{margin-bottom:12px}
.tctl #udp-port{width:90px;margin:0}
.unlisten{background:transparent;color:var(--muted);border:0;padding:0 4px;font-weight:400;cursor:pointer}
.unlisten:hover{color:var(--bad)}
details.expert-join{border-top:1px solid var(--line);padding-top:8px}
.store-table{width:100%;border-collapse:collapse;font-size:13px;margin:4px 0 8px}
.store-table td{padding:5px 6px;border-bottom:1px solid var(--line);vertical-align:middle}
.store-table td:last-child{text-align:right}
.store-table button{padding:3px 10px;font-size:12px;margin:0}
#store-card h3{margin:12px 0 2px;font-size:13px}
details.expert-join summary{cursor:pointer}
details.expert-join .mrow{margin-top:8px}
.connect{display:grid;grid-template-columns:1fr 1fr;gap:14px}
@media(max-width:760px){.connect{grid-template-columns:1fr}}
.cbox{background:#0e1116;border:1px solid var(--line);border-radius:10px;padding:12px;
display:flex;flex-direction:column;gap:8px}
.cbox .ctitle{font-size:13px;font-weight:600}
.cbox textarea{min-height:56px;margin:0}
#punch-block{margin-top:12px}
#punch-block h3{margin:0 0 8px;font-size:13px;color:var(--muted);
text-transform:uppercase;letter-spacing:.05em}
.apps{display:flex;flex-wrap:wrap;gap:10px}
.appitem{display:flex;align-items:center;gap:10px;padding:10px 12px;border:1px solid var(--line);
border-radius:10px;background:var(--bg)}
.appitem .aname{font-weight:600}
.appitem a.open{background:var(--accent);color:#04122a;border-radius:8px;padding:6px 12px;
font-weight:600;text-decoration:none}
.apps .muted{align-self:center}
"""

APP_JS = r"""
let TOKEN = null;
let timer = null;     // status polling interval (guarded so re-entry never stacks)
let storeTimer = null; // app-store catalog polling interval
let prev = null;      // previous {t, bytes_in, bytes_out}
let last = null;      // last full state snapshot (drives the control buttons)
const hist = [];      // [{in,out}] KB/s samples

const $ = (id) => document.getElementById(id);

async function api(path, method = "GET", body) {
  const headers = {};
  if (TOKEN) headers["Authorization"] = "Bearer " + TOKEN;
  if (body) headers["Content-Type"] = "application/json";
  const res = await fetch(path, { method, headers, body: body ? JSON.stringify(body) : undefined });
  if (res.status === 401) { logout(); throw new Error("unauthorized"); }
  return res;
}

$("login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  $("login-error").textContent = "";
  try {
    const res = await fetch("/api/login", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ password: $("password").value }),
    });
    if (!res.ok) {
      const j = await res.json().catch(() => ({}));
      $("login-error").textContent = j.error || "login failed";
      return;
    }
    TOKEN = (await res.json()).token;
    // Hand the token to same-tab sub-pages (e.g. /chat) without a second login.
    // sessionStorage is per-tab and never written to disk.
    try { sessionStorage.setItem("nmesh_token", TOKEN); } catch (_) {}
    $("password").value = "";
    startApp();
  } catch (_) { $("login-error").textContent = "network error"; }
});

function startApp() {
  $("login").classList.add("hidden");
  $("app").classList.remove("hidden");
  tick();
  refreshStore();
  if (!timer) timer = setInterval(tick, 1500);
  // The catalog changes rarely and arrives via gossip; poll it slowly.
  if (!storeTimer) storeTimer = setInterval(refreshStore, 5000);
}

function logout() {
  if (TOKEN) api("/api/logout", "POST").catch(() => {});
  TOKEN = null;
  try { sessionStorage.removeItem("nmesh_token"); } catch (_) {}
  if (timer) { clearInterval(timer); timer = null; }
  if (storeTimer) { clearInterval(storeTimer); storeTimer = null; }
  $("app").classList.add("hidden");
  $("login").classList.remove("hidden");
}
$("logout").addEventListener("click", logout);

// On load, the session cookie set at login is sent automatically, so a refresh
// resumes the session without a second password prompt. Probe one authed
// endpoint: 200 → straight into the app, otherwise show the login form.
(async function bootstrap() {
  try {
    const r = await fetch("/api/state");
    if (r.ok) startApp();
  } catch (_) { /* stay on the login screen */ }
})();

function fmtBytes(n) {
  if (n == null) return "n/a";
  const u = ["B", "KB", "MB", "GB", "TB"]; let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return n.toFixed(i ? 1 : 0) + " " + u[i];
}
function fmtDur(s) {
  s = Math.floor(s); const d = Math.floor(s / 86400); s %= 86400;
  const h = Math.floor(s / 3600); s %= 3600; const m = Math.floor(s / 60);
  return (d ? d + "d " : "") + (h ? h + "h " : "") + m + "m";
}
const short = (hex) => hex ? hex.slice(0, 10) + "…" : "—";
function fmtAgo(sec) {
  sec = Math.max(0, Math.floor(sec || 0));
  if (sec < 60) return sec + "s";
  if (sec < 3600) return Math.floor(sec / 60) + "m";
  if (sec < 86400) return Math.floor(sec / 3600) + "h";
  return Math.floor(sec / 86400) + "d";
}

async function tick() {
  let s;
  try { s = await (await api("/api/state")).json(); } catch (_) { return; }

  $("node-id").textContent = short(s.id);
  const st = $("node-state");
  st.textContent = s.running ? "running" : "stopped";
  st.className = "badge" + (s.running ? " up" : "");
  $("node-uptime").textContent = "up " + fmtDur(s.uptime);

  // throughput deltas
  let kin = 0, kout = 0;
  if (prev) {
    const dt = s.server_time - prev.t;
    if (dt > 0) {
      kin = Math.max(0, (s.total.bytes_in - prev.bytes_in) / dt / 1024);
      kout = Math.max(0, (s.total.bytes_out - prev.bytes_out) / dt / 1024);
    }
  }
  prev = { t: s.server_time, bytes_in: s.total.bytes_in, bytes_out: s.total.bytes_out };
  hist.push({ in: kin, out: kout });
  while (hist.length > 80) hist.shift();

  const cpu = s.load && s.load.cpu_percent != null ? s.load.cpu_percent.toFixed(0) + "%" : "n/a";
  const rss = s.load ? fmtBytes(s.load.rss_bytes) : "n/a";
  tiles([
    ["Peers", s.authenticated_peers + " / " + s.peer_count],
    ["Routing", s.routing_size],
    ["E2E sessions", s.e2e_sessions.length],
    ["In", kin.toFixed(1) + " KB/s"],
    ["Out", kout.toFixed(1) + " KB/s"],
    ["CPU", cpu],
    ["Memory", rss],
  ]);
  last = s;
  drawChart();
  drawGraph(s);
  drawPeers(s.peers);
  drawKnownNodes(s);
  drawTransports(s);
  drawExpert(s);
  drawApps(s.apps);
  drawJoinProgress(s.join_status);
}

function drawApps(apps) {
  const el = $("apps-list");
  if (!el) return;
  apps = apps || [];
  if (!apps.length) { el.innerHTML = '<span class="muted">No built-in apps.</span>'; return; }
  el.innerHTML = "";
  for (const a of apps) {
    const row = document.createElement("div");
    row.className = "appitem";
    const name = document.createElement("span");
    name.className = "aname";
    name.textContent = a.name;
    const open = document.createElement("a");
    open.className = "open";
    open.href = a.path;           // same-tab: carries the sessionStorage token
    open.textContent = "Open";
    row.appendChild(name);
    row.appendChild(open);
    el.appendChild(row);
  }
}

function drawExpert(s) {
  const list = (id, arr) => {
    $(id).innerHTML = (arr && arr.length)
      ? arr.map((x) => `<li>${x}</li>`).join("")
      : '<li class="muted">—</li>';
  };
  list("x-advertised", s.advertised);
  list("x-localips", s.local_ips);
  $("x-listening").innerHTML = (s.listening && s.listening.length)
    ? s.listening.map((u) =>
        `<li>${u} <button class="unlisten" data-uri="${u}" title="stop listening">✕</button></li>`
      ).join("")
    : '<li class="muted">—</li>';
}

function drawJoinProgress(js) {
  let text = "", color = "";
  if (js) {
    if (js.connected) { text = "connected ✓ via " + js.connected; }
    else if (js.running) {
      text = "trying " + (js.current || "…") + (js.tried.length ? ` (${js.tried.length} failed)` : "");
    } else if (js.tried && js.tried.length) {
      const lastTry = js.tried[js.tried.length - 1];
      text = "join failed — " + `${lastTry.uri}: ${lastTry.error}`;
      color = "var(--bad)";
    }
  }
  for (const id of ["join-progress", "cx-join-progress", "rly-join-progress"]) {
    const el = $(id);
    if (el) { el.textContent = text; el.style.color = color; }
  }
}

function fmtAge(a) {
  if (a == null) return "never";
  if (a < 60) return Math.round(a) + "s ago";
  return Math.round(a / 60) + "m ago";
}

function drawReachability(s) {
  // "How am I reachable, and by whom" — transport-agnostic, from descriptors.
  const relay = s.relay_capable
    ? '<span class="badge up">relay-capable</span>'
    : '<span class="badge">not a relay</span>';
  const seeks = s.pending_seeks ? ` <span class="muted">· ${s.pending_seeks} invite seek(s)</span>` : "";
  $("reach-status").innerHTML =
    `<span><span class="nk">Reachability</span>${relay}${seeks}</span>`;
  const byT = {};
  (s.reachability || []).forEach((d) => {
    (byT[d.transport] = byT[d.transport] || []).push(d);
  });
  const scopeBadge = (d) => {
    const cls = d.scope === "world" ? "on" : "";
    const mark = d.confirmed ? " ✓" : "";
    const anc = d.anchor ? `@${d.anchor}` : "";
    return `<span class="pill ${cls}">${d.scope}${anc}${mark}</span>`;
  };
  $("reach-cards").innerHTML = Object.keys(byT).map((t) =>
    `<div class="tcard"><h3><span class="pill on">${t}</span> reachable as</h3>` +
    byT[t].map((d) =>
      `<div class="kv"><span>${scopeBadge(d)}</span><span class="mono muted">${d.address || "—"}</span></div>`
    ).join("") + `</div>`
  ).join("");
}

function drawTransports(s) {
  drawReachability(s);
  const udpOn = (s.transport_details || []).some((t) => t.hole_punch);
  const pt = $("punch-toggle");
  pt.textContent = "Hole punching: " + (s.punch_enabled ? "ON" : "OFF");
  pt.className = s.punch_enabled ? "" : "ghost";
  const ka = $("keepalive-toggle");
  ka.textContent = "Continuous: " + (s.punch_keepalive ? "ON" : "OFF");
  ka.className = s.punch_keepalive ? "" : "ghost";
  ka.classList.toggle("hidden", !udpOn);
  const lt = $("lan-toggle");
  lt.textContent = "LAN relay discovery: " + (s.lan_discovery ? "ON" : "OFF");
  lt.className = s.lan_discovery ? "" : "ghost";
  $("udp-toggle").textContent = udpOn ? "Stop UDP" : "Start UDP";
  $("udp-port").classList.toggle("hidden", udpOn);

  const net = s.network;
  if (net) {
    const inet = net.internet == null
      ? '<span class="badge">checking…</span>'
      : net.internet
        ? '<span class="badge up">online</span>'
        : '<span class="badge down">offline</span>';
    $("net-status").innerHTML =
      `<span><span class="nk">Internet</span>${inet}</span>` +
      `<span><span class="nk">Public IP</span><span class="mono">${net.public_ip || "unknown"}</span></span>` +
      `<span><span class="nk">Public UDP (STUN)</span><span class="mono">${net.stun_addr || "—"}</span></span>` +
      `<span><span class="nk">Checked</span>${fmtAge(net.last_full_check_age)}</span>` +
      (net.triggers && net.triggers.length
        ? `<span><span class="nk">Last trigger</span>${net.triggers[0].reason}</span>` : "");
  } else {
    $("net-status").innerHTML = '<span class="muted">network monitor not running</span>';
  }

  const details = s.transport_details || [];
  $("transport-cards").innerHTML = details.map((t) => {
    const live = t.listening && t.listening.length;
    return `<div class="tcard">
      <h3><span class="pill ${live ? "on" : ""}">${t.scheme}${live ? " ●" : ""}</span></h3>
      <div class="kv"><span class="k">Peers</span><span>${t.peers}</span></div>
      <div class="kv"><span class="k">Ports</span><span class="mono">${(t.ports || []).join(", ") || "—"}</span></div>
      <div class="kv"><span class="k">Listening</span><span>${live ? t.listening.length : "no"}</span></div>
      <ul class="mono muted">${(t.listening || []).map((u) => `<li>${u}</li>`).join("")}</ul>
    </div>`;
  }).join("");

  const udp = details.find((t) => t.hole_punch);
  if (udp) {
    const hp = udp.hole_punch;
    const rows = (hp.pending || []).map((p) => `<tr>
      <td class="mono">${short(p.target)}</td>
      <td class="mono">${p.remote_addr}</td>
      <td>${p.probes_sent} / ${p.probes_received}</td>
      <td>${p.ack_received ? "✓" : "…"}</td>
      <td>${p.expires_in.toFixed(0)}s</td>
    </tr>`).join("");
    const publicUdp = hp.public_udp
      ? ` · public ${hp.public_udp}` : "";
      const cont = hp.keepalive
        ? ` · continuous (${hp.stats.keepalives || 0} keepalives)` : "";
    const readiness = hp.reason
      ? `<div class="muted" style="margin-bottom:8px">${hp.ready ? "✓" : "⚠"} ${hp.reason}</div>`
      : "";
    const holes = (hp.manual_holes || []).length
      ? `<div class="muted" style="margin:6px 0">Manual holes: ` +
        hp.manual_holes.map((h) =>
          `<span class="pill ${h.active ? "on" : ""}">${h.addr} (${h.sent} sent${h.active ? ", active" : ""})</span>`
        ).join("") + `</div>`
      : "";
    $("punch-block").innerHTML =
      `<h3>UDP hole punching — port ${hp.udp_port ?? "—"}${publicUdp}${cont} · ` +
      `${hp.stats.completed} ok / ${hp.stats.failed} failed / ${hp.stats.attempted} tried</h3>` +
      readiness + holes +
      (rows
        ? `<table><thead><tr><th>Target</th><th>Remote</th><th>Probes s/r</th>
           <th>Ack</th><th>Expires</th></tr></thead><tbody>${rows}</tbody></table>`
        : '<div class="muted">no relay-coordinated punch in progress</div>');
  } else {
    $("punch-block").innerHTML = "";
  }
}

function tiles(items) {
  $("tiles").innerHTML = items.map(
    ([k, v]) => `<div class="tile"><div class="v">${v}</div><div class="k">${k}</div></div>`
  ).join("");
}

function drawChart() {
  const c = $("chart"), ctx = c.getContext("2d");
  const W = c.width, H = c.height;
  ctx.clearRect(0, 0, W, H);
  const max = Math.max(1, ...hist.map((p) => Math.max(p.in, p.out)));
  const line = (key, color) => {
    ctx.beginPath(); ctx.strokeStyle = color; ctx.lineWidth = 2;
    hist.forEach((p, i) => {
      const x = (i / Math.max(1, hist.length - 1)) * W;
      const y = H - (p[key] / max) * (H - 10) - 5;
      i ? ctx.lineTo(x, y) : ctx.moveTo(x, y);
    });
    ctx.stroke();
  };
  line("in", "#3fb950");
  line("out", "#f78166");
}

function drawGraph(s) {
  const g = $("graph"); const cx = 160, cy = 130;
  const peers = s.peers.filter((p) => p.authenticated_id);
  const parts = [];
  // edges + peer nodes on a ring
  peers.forEach((p, i) => {
    const a = (2 * Math.PI * i) / Math.max(1, peers.length) - Math.PI / 2;
    const x = cx + Math.cos(a) * 95, y = cy + Math.sin(a) * 95;
    const col = p.has_session ? "#4da3ff" : "#8b93a1";
    parts.push(`<line x1="${cx}" y1="${cy}" x2="${x}" y2="${y}" stroke="${col}" stroke-width="1.5" opacity="0.6"/>`);
    parts.push(`<circle cx="${x}" cy="${y}" r="9" fill="${col}"><title>${p.authenticated_id}</title></circle>`);
  });
  parts.push(`<circle cx="${cx}" cy="${cy}" r="14" fill="#e6e9ef"/>`);
  parts.push(`<text x="${cx}" y="${cy + 30}" fill="#8b93a1" font-size="10" text-anchor="middle">self</text>`);
  g.innerHTML = parts.join("");
}

function drawPeers(peers) {
  const tb = $("peers").querySelector("tbody");
  tb.innerHTML = peers.map((p) => {
    const c = p.counters;
    const rtt = p.rtt_ms != null ? p.rtt_ms + " ms" : "—";
    return `<tr>
      <td class="mono">${short(p.authenticated_id)}</td>
      <td>${p.is_client_side ? "out" : "in"}</td>
      <td>${p.has_session ? "✓" : "—"}</td>
      <td>${rtt}</td>
      <td>${p.malformed}</td>
      <td>${fmtBytes(c.bytes_in)}</td>
      <td>${fmtBytes(c.bytes_out)}</td>
    </tr>`;
  }).join("");
}

$("ping-btn").addEventListener("click", async () => {
  const st = $("ping-status");
  st.textContent = "pinging…"; st.style.color = "";
  try {
    const j = await (await api("/api/ping", "POST")).json();
    st.textContent = `pinged ${j.sent} peer(s) — RTT updates below`;
  } catch (_) {
    st.textContent = "ping failed"; st.style.color = "var(--bad)";
  }
});

function knownLimit() {
  const v = parseInt($("known-limit").value, 10);
  return (Number.isFinite(v) && v > 0) ? v : 20;
}

const esc = (s) => String(s == null ? "" : s).replace(/[&<>"]/g,
  (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
const knownExpanded = new Set();   // node ids whose details are open

function knownMatch(n, q) {
  if (!q) return true;
  q = q.toLowerCase();
  if (n.id.toLowerCase().includes(q)) return true;
  return (n.addresses || []).some((a) => a.toLowerCase().includes(q));
}

function drawKnownNodes(s) {
  const all = s.routing || [];           // already sorted most-recent-first
  const q = ($("known-search").value || "").trim();
  const matched = all.filter((n) => knownMatch(n, q));
  const rows = matched.slice(0, knownLimit());
  $("known-count").textContent =
    rows.length + " of " + (q ? matched.length + " matched" : (s.routing_size || 0));
  const tb = $("known").querySelector("tbody");
  if (!rows.length) {
    tb.innerHTML = `<tr><td colspan="5" class="muted">${q ? "no match" : "no known nodes yet"}</td></tr>`;
    return;
  }
  tb.innerHTML = rows.map((n) => {
    const addrs = (n.addresses && n.addresses.length)
      ? esc(n.addresses.join(", ")) : "—";
    const link = n.connected
      ? `<span class="badge up">direct${n.rtt_ms != null ? " " + n.rtt_ms + " ms" : ""}</span>`
      : "—";
    const open = knownExpanded.has(n.id);
    let html = `<tr>
      <td class="mono" title="${esc(n.id)}">${short(n.id)}</td>
      <td class="mono">${addrs}</td>
      <td>${fmtAgo(n.seen_ago)} ago</td>
      <td>${link}</td>
      <td class="krow">
        <button class="ghost" data-ping="${esc(n.id)}">Ping</button>
        <button class="ghost" data-details="${esc(n.id)}">${open ? "Hide" : "Details"}</button>
      </td>
    </tr>`;
    if (open) {
      const addrList = (n.addresses && n.addresses.length)
        ? n.addresses.map((a) => `<li>${esc(a)}</li>`).join("") : '<li class="muted">none</li>';
      html += `<tr class="kdetails"><td colspan="5"><div class="kd">
        <div><span class="nk">Full id</span><span class="mono">${esc(n.id)}</span></div>
        <div><span class="nk">Addresses</span><ul class="mono">${addrList}</ul></div>
        <div><span class="nk">Last seen</span><span>${fmtAgo(n.seen_ago)} ago</span></div>
        <div><span class="nk">Link</span><span>${n.connected ? "direct peer" + (n.rtt_ms != null ? " · " + n.rtt_ms + " ms RTT" : "") : "not connected"}</span></div>
        <div><span class="nk">Auth key</span><span>${n.has_key ? "known" : "missing"}</span></div>
      </div></td></tr>`;
    }
    return html;
  }).join("");
}

function kstatus(msg, bad = false) {
  const el = $("known-status");
  el.textContent = msg; el.style.color = bad ? "var(--bad)" : "";
}

// Re-render when the operator changes the count or the search.
$("known-limit").addEventListener("input", () => { if (last) drawKnownNodes(last); });
$("known-search").addEventListener("input", () => { if (last) drawKnownNodes(last); });

// Per-row Ping / Details via event delegation.
$("known").addEventListener("click", async (ev) => {
  const pingId = ev.target.getAttribute && ev.target.getAttribute("data-ping");
  const detId = ev.target.getAttribute && ev.target.getAttribute("data-details");
  if (detId) {
    if (knownExpanded.has(detId)) knownExpanded.delete(detId);
    else knownExpanded.add(detId);
    if (last) drawKnownNodes(last);
    return;
  }
  if (pingId) {
    ev.target.disabled = true;
    kstatus("pinging " + short(pingId) + " …");
    try {
      const j = await (await api("/api/ping/node", "POST", { id: pingId })).json();
      if (!j.reachable) kstatus(short(pingId) + " : unreachable", true);
      else kstatus(short(pingId) + " : " + (j.rtt_ms != null ? j.rtt_ms + " ms" : "reachable"));
    } catch (_) {
      kstatus("ping failed", true);
    } finally {
      ev.target.disabled = false;
    }
  }
});

// two-step connect exchange
function cstatus(msg, ok = true) {
  const el = $("connect-status");
  el.textContent = msg; el.style.color = ok ? "" : "var(--bad)";
}
async function copyText(t) {
  try { await navigator.clipboard.writeText(t); return true; } catch (_) { return false; }
}
$("cx-request").addEventListener("click", async () => {
  try {
    const j = await (await api("/api/connect/request", "POST")).json();
    $("cx-request-out").value = j.block;
    cstatus((await copyText(j.block)) ? "request copied — send it to them" : "request ready — copy it to them");
  } catch (_) { cstatus("failed to create request", false); }
});
$("cx-accept").addEventListener("click", async () => {
  const block = $("cx-accept-in").value.trim();
  if (!block) { cstatus("paste their request block first", false); return; }
  try {
    const res = await api("/api/connect/accept", "POST", { block });
    const j = await res.json();
    if (res.ok) {
      $("cx-accept-out").value = j.block; $("cx-accept-in").value = "";
      cstatus((await copyText(j.block)) ? "invite copied — send it back to them" : "invite ready — copy it back to them");
    } else cstatus("accept failed: " + (j.error || ""), false);
  } catch (_) { cstatus("accept failed", false); }
});
$("cx-complete").addEventListener("click", async () => {
  const block = $("cx-reply-in").value.trim();
  if (!block) { cstatus("paste the block they sent back first", false); return; }
  try {
    const res = await api("/api/connect/complete", "POST", { block });
    const j = await res.json();
    if (res.ok) { cstatus(`connecting — trying ${j.candidates} address(es)…`); $("cx-reply-in").value = ""; }
    else cstatus("connect failed: " + (j.error || ""), false);
  } catch (_) { cstatus("connect failed", false); }
});

// relay invitation (across NAT)
function rstatus(msg, ok = true) {
  const el = $("rly-status");
  el.textContent = msg; el.style.color = ok ? "" : "var(--bad)";
}
$("rly-invite").addEventListener("click", async () => {
  try {
    const j = await (await api("/api/relay/invite", "POST")).json();
    $("rly-invite-out").value = j.block;
    rstatus((await copyText(j.block)) ? "invite copied — send it to the node you're inviting" : "invite ready — copy it");
  } catch (_) { rstatus("failed to generate relay invite", false); }
});
$("rly-join").addEventListener("click", async () => {
  const block = $("rly-join-in").value.trim();
  if (!block) { rstatus("paste a relay invite block first", false); return; }
  try {
    const res = await api("/api/relay/join", "POST", { block });
    const j = await res.json();
    if (res.ok) { rstatus(`joining via relay — ${j.relays} relay(s) + LAN discovery…`); $("rly-join-in").value = ""; }
    else rstatus("join failed: " + (j.error || ""), false);
  } catch (_) { rstatus("join failed", false); }
});

// management
function status(msg, ok = true) {
  const el = $("manage-status");
  el.textContent = msg; el.style.color = ok ? "" : "var(--bad)";
}
$("gen-invite").addEventListener("click", async () => {
  try { const j = await (await api("/api/invite", "POST")).json(); $("invite-out").textContent = j.code; }
  catch (_) { status("failed to generate invite", false); }
});
$("gen-block").addEventListener("click", async () => {
  try { const j = await (await api("/api/invite/block", "POST")).json(); $("block-out").value = j.block; }
  catch (_) { status("failed to generate invite block", false); }
});
$("join-block-btn").addEventListener("click", async () => {
  const block = $("join-block-in").value.trim();
  if (!block) { status("paste an invite block first", false); return; }
  try {
    const res = await api("/api/join/block", "POST", { block });
    const j = await res.json();
    if (res.ok) { status(`joining — trying ${j.candidates} address(es)…`); $("join-block-in").value = ""; }
    else status("join failed: " + (j.error || ""), false);
  } catch (_) { status("join failed", false); }
});

// transport controls
function tctl(msg, ok = true) {
  const el = $("tctl-status");
  el.textContent = msg; el.style.color = ok ? "" : "var(--bad)";
  if (msg) setTimeout(() => { if (el.textContent === msg) el.textContent = ""; }, 4000);
}
$("punch-toggle").addEventListener("click", async () => {
  if (!last) return;
  try {
    await api("/api/punch", "POST", { enabled: !last.punch_enabled });
    tick();
  } catch (_) { tctl("failed to toggle hole punching", false); }
});
$("keepalive-toggle").addEventListener("click", async () => {
  if (!last) return;
  try {
    await api("/api/punch/keepalive", "POST", { enabled: !last.punch_keepalive });
    tctl(!last.punch_keepalive ? "continuous punching on" : "continuous punching off");
    tick();
  } catch (_) { tctl("failed to toggle continuous mode", false); }
});
$("udp-toggle").addEventListener("click", async () => {
  if (!last) return;
  const udpOn = (last.transport_details || []).some((t) => t.hole_punch);
  try {
    let res;
    if (udpOn) res = await api("/api/udp", "POST", { action: "stop" });
    else {
      const port = parseInt($("udp-port").value, 10);
      if (!(port > 0 && port < 65536)) { tctl("invalid UDP port", false); return; }
      res = await api("/api/udp", "POST", { action: "start", port });
    }
    if (!res.ok) tctl("UDP: " + ((await res.json()).error || "failed"), false);
    tick();
  } catch (_) { tctl("UDP control failed", false); }
});
$("net-recheck").addEventListener("click", async () => {
  try { await api("/api/net/recheck", "POST"); tctl("network re-check requested"); tick(); }
  catch (_) { tctl("re-check failed", false); }
});
$("lan-toggle").addEventListener("click", async () => {
  if (!last) return;
  try {
    await api("/api/lan/discovery", "POST", { enabled: !last.lan_discovery });
    tctl(!last.lan_discovery ? "LAN relay discovery on" : "LAN relay discovery off");
    tick();
  } catch (_) { tctl("failed to toggle LAN discovery", false); }
});
$("reach-probe").addEventListener("click", async () => {
  try {
    const j = await (await api("/api/reachability/probe", "POST")).json();
    tctl(j.sent ? `reachability probe sent (${j.sent}) — check the badge` : "no peer to probe through");
    setTimeout(tick, 3500);
  } catch (_) { tctl("reachability probe failed", false); }
});
$("listen-btn").addEventListener("click", async () => {
  const uri = $("listen-uri").value.trim();
  if (!uri) { tctl("enter a listen URI", false); return; }
  try {
    const res = await api("/api/listen", "POST", { uri });
    if (res.ok) { $("listen-uri").value = ""; tctl("listening on " + uri); }
    else tctl("listen failed: " + ((await res.json()).error || ""), false);
    tick();
  } catch (_) { tctl("listen failed", false); }
});
$("x-listening").addEventListener("click", async (e) => {
  const uri = e.target && e.target.dataset && e.target.dataset.uri;
  if (!uri) return;
  try { await api("/api/unlisten", "POST", { uri }); tick(); }
  catch (_) { tctl("failed to stop listener", false); }
});
$("show-cert").addEventListener("click", async () => {
  try { const j = await (await api("/api/rootcert")).json(); $("cert-out").value = j.cert_hex; }
  catch (_) { status("failed to load cert", false); }
});
$("join-btn").addEventListener("click", async () => {
  const uri = $("join-uri").value.trim(), code = $("join-code").value.trim();
  if (!uri || !code) { status("uri and code required", false); return; }
  status("joining…");
  try {
    const res = await api("/api/join", "POST", { uri, code });
    status(res.ok ? "join initiated" : "join failed: " + (await res.json()).error, res.ok);
  } catch (_) { status("join failed", false); }
});
$("trust-btn").addEventListener("click", async () => {
  const cert_hex = $("trust-in").value.trim();
  if (!cert_hex) { status("paste a certificate first", false); return; }
  try {
    const res = await api("/api/trust", "POST", { cert_hex });
    status(res.ok ? "certificate trusted" : "invalid certificate", res.ok);
    if (res.ok) $("trust-in").value = "";
  } catch (_) { status("trust failed", false); }
});

// apps (DHT)
function appStatus(msg, ok = true) {
  const el = $("app-status");
  el.textContent = msg; el.style.color = ok ? "" : "var(--bad)";
}
function fileToB64(file) {
  return new Promise((resolve, reject) => {
    const r = new FileReader();
    r.onload = () => resolve((r.result + "").split(",")[1] || "");
    r.onerror = reject;
    r.readAsDataURL(file);
  });
}
$("publish-btn").addEventListener("click", async () => {
  const name = $("app-name").value.trim();
  const version = $("app-version").value.trim() || "1.0.0";
  const input = $("app-files");
  if (!name || !input.files.length) { appStatus("name and at least one file required", false); return; }
  appStatus("reading files…");
  const files = {};
  for (const f of input.files) files[f.name] = await fileToB64(f);
  try {
    const res = await api("/api/app/publish", "POST", { name, version, files });
    const j = await res.json();
    if (res.ok) { $("app-id-out").textContent = j.app_id; appStatus("published ✓"); }
    else appStatus("publish failed: " + (j.error || ""), false);
  } catch (_) { appStatus("publish failed", false); }
});
$("fetch-btn").addEventListener("click", async () => {
  const id = $("fetch-id").value.trim();
  if (!id) { appStatus("enter an app id", false); return; }
  appStatus("fetching…");
  try {
    const res = await api("/api/app/fetch", "POST", { app_id: id });
    if (res.status === 404) { appStatus("not found on the mesh", false); return; }
    const j = await res.json();
    if (!res.ok) { appStatus("fetch failed: " + (j.error || ""), false); return; }
    $("app-files-out").innerHTML =
      `<div class="muted">${j.name} v${j.version}</div>` +
      Object.entries(j.files).map(([p, b64]) =>
        `<div class="mrow"><a download="${p}" href="data:application/octet-stream;base64,${b64}">${p}</a>`
        + ` <span class="muted">(${atob(b64).length} B)</span></div>`).join("");
    appStatus("fetched ✓");
  } catch (_) { appStatus("fetch failed", false); }
});

// app store (shared catalog + installed set)
function storeStatus(msg, ok = true) {
  const el = $("store-status");
  el.textContent = msg; el.style.color = ok ? "" : "var(--bad)";
}
// The backend (Python) computes every app's state/action; this only renders it.
const CAP = (s) => s ? s.charAt(0).toUpperCase() + s.slice(1) : "";
async function refreshStore() {
  try {
    const view = await (await api("/api/store")).json();
    const catalog = view.catalog || [], installed = view.installed || [];
    $("store-catalog").innerHTML = catalog.length ? catalog.map((a) => {
      const cell = a.action
        ? `<button data-app="${a.app_id}" data-act="${a.action}">${CAP(a.action)}</button>`
        : `<span class="muted">${esc(a.state)}</span>`;
      return `<tr><td>${esc(a.name)}</td><td class="muted">v${esc(a.version)}</td>`
           + `<td class="mono">${short(a.app_id)}</td><td>${cell}</td></tr>`;
    }).join("") : '<tr><td class="muted" colspan="4">No apps published yet.</td></tr>';
    $("store-installed").innerHTML = installed.length ? installed.map((m) =>
      `<tr><td>${esc(m.name)}</td><td class="muted">v${esc(m.version)}</td>`
      + `<td class="mono">${short(m.app_id)}</td>`
      + `<td><button data-app="${m.app_id}" data-act="uninstall">Uninstall</button></td></tr>`
    ).join("") : '<tr><td class="muted" colspan="4">Nothing installed.</td></tr>';
  } catch (_) { /* transient — next refresh retries */ }
}
async function storeAction(app_id, act) {
  const path = "/api/store/" + act;
  storeStatus(act + "…");
  try {
    const res = await api(path, "POST", { app_id });
    const j = await res.json().catch(() => ({}));
    if (res.ok && j.ok !== false) storeStatus(act + " ✓");
    else storeStatus(act + " failed: " + (j.error || "no change"), false);
  } catch (_) { storeStatus(act + " failed", false); }
  refreshStore();
}
$("store-card").addEventListener("click", (e) => {
  const b = e.target.closest("button[data-act]");
  if (b) storeAction(b.getAttribute("data-app"), b.getAttribute("data-act"));
});
$("store-publish-btn").addEventListener("click", async () => {
  const name = $("store-name").value.trim();
  const version = $("store-version").value.trim() || "1.0.0";
  const input = $("store-files");
  if (!name || !input.files.length) { storeStatus("name and at least one file required", false); return; }
  storeStatus("reading files…");
  const files = {};
  for (const f of input.files) files[f.name] = await fileToB64(f);
  try {
    const res = await api("/api/store/publish", "POST", { name, version, files });
    const j = await res.json();
    if (res.ok) { storeStatus("published to store ✓"); input.value = ""; }
    else storeStatus("publish failed: " + (j.error || ""), false);
  } catch (_) { storeStatus("publish failed", false); }
  refreshStore();
});
"""


# ---------------------------------------------------------------------------
# Chat sub-page (/chat) — hosted by the console, reuses the console session.
#
# A full chat client: identity (your id + pseudo), a contact directory, pseudo
# search, and both 1:1 and group conversations. All of it is app state served
# by the ChatBridge; the node is untouched. Same strict CSP as the console
# (default-src 'self', no inline), same bearer token via sessionStorage.
# ---------------------------------------------------------------------------

# Console v2 replaces the original long-form shell above. Chat remains an
# independent sub-page and keeps the assets below.
INDEX_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark">
<title>NMesh Console</title>
<link rel="stylesheet" href="/style.css">
</head>
<body>
<div id="login" class="login-screen">
  <form id="login-form" class="login-card">
    <div class="mark" aria-hidden="true">NM</div>
    <p class="eyebrow">Local management plane</p>
    <h1>Unlock this node</h1>
    <p class="subtle">Credentials stay on this device and protect every management action.</p>
    <label class="field"><span>Password</span><input id="password" type="password" autocomplete="current-password" autofocus></label>
    <button type="submit" class="primary wide">Open console</button>
    <p id="login-error" class="message error" role="alert"></p>
  </form>
</div>

<div id="app" class="shell hidden">
  <aside class="rail">
    <div class="identity"><div class="mark">NM</div><div><strong>NMesh</strong><span>Console</span></div></div>
    <nav id="tabs" class="tabs" role="tablist" aria-label="Console sections">
      <button role="tab" data-tab="overview" aria-controls="panel-overview" aria-selected="true"><span class="tab-index">01</span><span>Overview</span></button>
      <button role="tab" data-tab="apps" aria-controls="panel-apps" aria-selected="false"><span class="tab-index">02</span><span>Apps</span></button>
      <button role="tab" data-tab="connectivity" aria-controls="panel-connectivity" aria-selected="false"><span class="tab-index">03</span><span>Connectivity</span></button>
      <button role="tab" data-tab="settings" aria-controls="panel-settings" aria-selected="false"><span class="tab-index">04</span><span>Settings</span></button>
    </nav>
    <div class="rail-foot"><span id="rail-dot" class="status-dot"></span><span id="rail-state">Connecting</span><button id="logout" class="text-button">Log out</button></div>
  </aside>

  <main>
    <header class="topbar">
      <div><p class="eyebrow">Current node</p><button id="self-node" class="node-id mono" title="Show local node details"></button></div>
      <div class="top-meta"><span id="node-state" class="state-pill"></span><span id="node-uptime"></span></div>
    </header>

    <section id="panel-overview" class="panel active" role="tabpanel" data-panel="overview">
      <div class="page-head"><div><p class="eyebrow">Live mesh</p><h1 id="overview-status">Reading node status</h1></div><p class="lede">A concise view of this node's health, traffic, and authenticated mesh links.</p></div>
      <div id="metrics" class="metrics"></div>
      <div class="dashboard-grid">
        <article class="surface traffic-card">
          <div class="surface-head"><div><p class="eyebrow">Traffic</p><h2>Mesh bandwidth</h2></div><span id="rate-now" class="mono subtle"></span></div>
          <canvas id="chart" width="900" height="300" aria-label="Inbound and outbound NMesh bytes per second"></canvas>
          <div class="legend"><span><i class="swatch inbound"></i>Inbound</span><span><i class="swatch outbound"></i>Outbound</span><small>NMesh packet bytes, excluding physical transport overhead</small></div>
        </article>
        <article class="surface topology-card">
          <div class="surface-head"><div><p class="eyebrow">Topology</p><h2>Current connections</h2></div><span id="map-count" class="count-pill"></span></div>
          <svg id="graph" viewBox="0 0 620 390" role="img" aria-label="Clickable connected-node map"></svg>
          <p class="map-note"><span class="line-key solid"></span> authenticated direct link <span class="line-key dashed"></span> locally observed first hop; deeper relays are opaque</p>
        </article>
      </div>
    </section>

    <section id="panel-apps" class="panel" role="tabpanel" data-panel="apps" hidden>
      <div class="page-head"><div><p class="eyebrow">Applications</p><h1>Installed software and network catalog</h1></div><p class="lede">Browse a signed catalog without loading the full store into the browser.</p></div>
      <div class="segmented" role="tablist" aria-label="Application views"><button data-app-view="installed" class="active">Installed</button><button data-app-view="store">App store</button></div>
      <div id="apps-installed-view" class="app-view">
        <article class="surface"><div class="surface-head"><div><p class="eyebrow">Running now</p><h2>Built-in apps</h2></div></div><div id="builtin-apps" class="app-grid"></div></article>
        <article class="surface list-surface">
          <div class="list-head"><div><p class="eyebrow">Local packages</p><h2>Installed apps <span id="installed-count" class="soft-count"></span></h2></div><label class="search"><span class="sr-only">Search installed apps</span><input id="installed-search" type="search" placeholder="Search installed apps"></label></div>
          <div id="installed-list" class="record-list"></div><div id="installed-pager" class="pager"></div>
        </article>
      </div>
      <div id="apps-store-view" class="app-view hidden">
        <article class="surface list-surface">
          <div class="list-head"><div><p class="eyebrow">Signed releases</p><h2>App store <span id="catalog-count" class="soft-count"></span></h2></div><label class="search"><span class="sr-only">Search catalog</span><input id="catalog-search" type="search" placeholder="Search name, version, id, or author"></label></div>
          <div id="catalog-list" class="record-list"></div><div id="catalog-pager" class="pager"></div>
        </article>
        <details class="surface disclosure"><summary>Publish a signed app release</summary>
          <div class="form-grid two"><label class="field"><span>Name</span><input id="store-name"></label><label class="field"><span>Version</span><input id="store-version" value="1.0.0"></label></div>
          <label class="field"><span>Files</span><input id="store-files" type="file" multiple></label><div class="action-row"><button id="store-publish-btn" class="primary">Publish to store</button><span id="store-status" class="message"></span></div>
        </details>
      </div>
    </section>

    <section id="panel-connectivity" class="panel" role="tabpanel" data-panel="connectivity" hidden>
      <div class="page-head"><div><p class="eyebrow">Mesh membership</p><h1>Active and known nodes</h1></div><div class="head-actions"><button id="ping-btn" class="secondary">Ping active nodes</button><span id="ping-status" class="message"></span></div></div>
      <article class="surface list-surface">
        <div class="list-head"><div><p class="eyebrow">Authenticated links</p><h2>Active with us <span id="active-count" class="soft-count"></span></h2></div><label class="search"><span class="sr-only">Search active nodes</span><input id="active-search" type="search" placeholder="Search id, address, or transport"></label></div>
        <div id="active-list" class="record-list node-list"></div><div id="active-pager" class="pager"></div>
      </article>
      <article class="surface list-surface">
        <div class="list-head"><div><p class="eyebrow">Routing table</p><h2>Known nodes <span id="known-count" class="soft-count"></span></h2></div><div class="list-tools"><label class="search"><span class="sr-only">Search known nodes</span><input id="known-search" type="search" placeholder="Search id or address"></label><label class="limit">Show <input id="known-limit" type="number" min="1" max="100" value="20"></label></div></div>
        <div id="known-list" class="record-list node-list"></div><div id="known-pager" class="pager"></div>
      </article>
    </section>

    <section id="panel-settings" class="panel" role="tabpanel" data-panel="settings" hidden>
      <div class="page-head"><div><p class="eyebrow">Node controls</p><h1>Connectivity and management</h1></div><p class="lede">Operational controls are separated from live status to reduce accidental changes.</p></div>
      <article class="surface">
        <div class="surface-head"><div><p class="eyebrow">Transport health</p><h2>Reachability</h2></div><span id="relay-state" class="state-pill"></span></div>
        <div id="network-summary" class="info-strip"></div><div id="transport-list" class="transport-grid"></div>
        <div class="action-row wrap"><button id="punch-toggle" class="secondary"></button><button id="keepalive-toggle" class="secondary"></button><button id="udp-toggle" class="secondary"></button><input id="udp-port" class="compact" type="number" min="1" max="65535" value="9001"><button id="lan-toggle" class="secondary"></button><button id="reach-probe" class="secondary">Confirm reachability</button><button id="net-recheck" class="secondary">Re-check network</button></div><p id="transport-status" class="message"></p>
      </article>
      <div class="settings-grid">
        <details class="surface disclosure" open><summary>Connect two nodes</summary><div class="form-grid two">
          <div class="form-block"><h3>Join someone</h3><button id="cx-request" class="secondary">Create request</button><textarea id="cx-request-out" class="mono" readonly placeholder="Send this request block"></textarea><textarea id="cx-reply-in" class="mono" placeholder="Paste their reply block"></textarea><button id="cx-complete" class="primary">Connect</button></div>
          <div class="form-block"><h3>Accept someone</h3><textarea id="cx-accept-in" class="mono" placeholder="Paste their request block"></textarea><button id="cx-accept" class="secondary">Make invite</button><textarea id="cx-accept-out" class="mono" readonly placeholder="Send this invite block back"></textarea></div>
        </div><p id="connect-status" class="message"></p></details>
        <details class="surface disclosure"><summary>Invite through a relay</summary><div class="form-grid two"><div class="form-block"><button id="rly-invite" class="secondary">Generate relay invite</button><textarea id="rly-invite-out" class="mono" readonly></textarea></div><div class="form-block"><textarea id="rly-join-in" class="mono" placeholder="Paste relay invite"></textarea><button id="rly-join" class="primary">Join via relay</button></div></div><p id="relay-status" class="message"></p></details>
        <details class="surface disclosure"><summary>Listeners and addressing</summary><div id="addressing" class="definition-list"></div><div class="action-row"><input id="listen-uri" placeholder="tcp://0.0.0.0:9002"><button id="listen-btn" class="secondary">Add listener</button></div><div id="listener-list" class="chip-list"></div></details>
        <details class="surface disclosure"><summary>Trust and invitations</summary>
          <div class="action-row"><button id="gen-invite" class="secondary">Generate invite code</button><code id="invite-out" class="mono"></code></div><div class="action-row"><input id="join-uri" placeholder="tcp://host:port"><input id="join-code" placeholder="Invite code"><button id="join-btn" class="secondary">Join</button></div>
          <button id="show-cert" class="secondary">Show our root certificate</button><textarea id="cert-out" class="mono" readonly></textarea><textarea id="trust-in" class="mono" placeholder="Paste a root certificate to trust"></textarea><button id="trust-btn" class="secondary">Trust certificate</button><p id="manage-status" class="message"></p>
        </details>
        <details class="surface disclosure"><summary>Raw content-addressed app transfer</summary><p class="subtle">Advanced DHT package exchange. This is separate from installed signed apps.</p>
          <div class="form-grid two"><label class="field"><span>Name</span><input id="app-name"></label><label class="field"><span>Version</span><input id="app-version" value="1.0.0"></label></div><label class="field"><span>Files</span><input id="app-files" type="file" multiple></label><button id="publish-btn" class="secondary">Publish content</button><code id="app-id-out" class="mono output"></code>
          <div class="action-row"><input id="fetch-id" placeholder="40-character content id"><button id="fetch-btn" class="secondary">Fetch</button></div><div id="app-files-out"></div><p id="app-status" class="message"></p>
        </details>
      </div>
    </section>
  </main>

  <dialog id="node-dialog" aria-labelledby="node-dialog-title">
    <form method="dialog" class="dialog-head"><div><p class="eyebrow">Node details</p><h2 id="node-dialog-title">Mesh identity</h2></div><button class="icon-button" value="close" aria-label="Close">Close</button></form>
    <div id="node-detail-body" class="node-detail"></div><div class="dialog-actions"><button id="detail-ping" class="primary">Ping node</button><button id="detail-forget" class="secondary">Forget node</button><span id="detail-status" class="message"></span></div>
  </dialog>
</div>
<script src="/app.js"></script>
</body>
</html>
"""


STYLE_CSS = """
:root{--ink:#eef4f8;--muted:#8c9aa7;--faint:#5f6c78;--base:#081018;--rail:#0b141d;--surface:#101b25;--raised:#14222d;--line:#26343f;--line-strong:#3b4b58;--cyan:#61d6c8;--cyan-dim:#173d3b;--blue:#75a7ff;--amber:#e6b76a;--red:#ff7b72;--radius:10px;--shadow:0 18px 55px rgba(0,0,0,.26)}
*{box-sizing:border-box}html{background:var(--base);color:var(--ink);scroll-behavior:smooth}body{margin:0;font:14px/1.5 Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:var(--base)}button,input,textarea{font:inherit}button{cursor:pointer}.hidden,[hidden]{display:none!important}.mono{font-family:"SFMono-Regular",Consolas,"Liberation Mono",monospace}.subtle{color:var(--muted)}.sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}
.login-screen{min-height:100vh;display:grid;place-items:center;padding:24px;background:linear-gradient(90deg,transparent 49.9%,rgba(255,255,255,.025) 50%,transparent 50.1%),var(--base);background-size:64px 64px}.login-card{width:min(430px,100%);padding:40px;background:var(--surface);border:1px solid var(--line);border-top:3px solid var(--cyan);box-shadow:var(--shadow)}.login-card h1{margin:8px 0;font-size:30px;letter-spacing:-.04em}.login-card .field{margin:28px 0 14px}.mark{width:42px;height:42px;display:grid;place-items:center;background:var(--cyan);color:#061311;font-weight:900;letter-spacing:-.08em;border-radius:5px}.eyebrow{margin:0 0 4px;color:var(--cyan);font-size:11px;font-weight:750;text-transform:uppercase;letter-spacing:.13em}
.shell{min-height:100vh;display:grid;grid-template-columns:220px minmax(0,1fr)}.rail{position:sticky;top:0;height:100vh;padding:24px 18px;display:flex;flex-direction:column;background:var(--rail);border-right:1px solid var(--line)}.identity{display:flex;align-items:center;gap:12px;padding:0 8px 28px}.identity strong,.identity span{display:block}.identity strong{font-size:17px}.identity span{color:var(--muted);font-size:12px}.tabs{display:flex;flex-direction:column;gap:5px}.tabs button{display:grid;grid-template-columns:28px 1fr;gap:8px;text-align:left;align-items:center;padding:11px 12px;color:var(--muted);background:transparent;border:1px solid transparent;border-radius:7px;font-weight:650}.tabs button:hover{color:var(--ink);background:rgba(255,255,255,.025)}.tabs button[aria-selected="true"]{color:var(--ink);background:var(--surface);border-color:var(--line)}.tab-index{font:10px/1 "SFMono-Regular",monospace;color:var(--faint)}.rail-foot{margin-top:auto;padding:16px 8px 0;border-top:1px solid var(--line);display:grid;grid-template-columns:auto 1fr;gap:7px 9px;align-items:center;color:var(--muted);font-size:12px}.rail-foot .text-button{grid-column:2;text-align:left}.status-dot{width:8px;height:8px;border-radius:50%;background:var(--faint)}.status-dot.up{background:var(--cyan);box-shadow:0 0 0 4px rgba(97,214,200,.1)}
main{min-width:0;width:100%;max-width:1460px;padding:0 40px 56px}.topbar{height:86px;display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid var(--line);margin-bottom:38px}.node-id{padding:0;background:transparent;border:0;color:var(--ink);font-size:13px}.top-meta{display:flex;gap:12px;align-items:center;color:var(--muted);font-size:12px}.state-pill,.count-pill{display:inline-flex;align-items:center;padding:5px 9px;border:1px solid var(--line);border-radius:999px;color:var(--muted);font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.06em}.state-pill.up{color:var(--cyan);border-color:#285c56;background:var(--cyan-dim)}.panel{animation:panel-in .18s ease-out}.page-head{display:flex;justify-content:space-between;gap:40px;align-items:end;margin-bottom:26px}.page-head h1{margin:0;max-width:760px;font-size:clamp(26px,3vw,42px);line-height:1.08;letter-spacing:-.045em}.lede{max-width:420px;margin:0;color:var(--muted)}.head-actions{display:flex;align-items:center;gap:12px}.surface{background:var(--surface);border:1px solid var(--line);border-radius:var(--radius);padding:22px;box-shadow:0 1px rgba(255,255,255,.02) inset}.surface-head,.list-head{display:flex;justify-content:space-between;align-items:center;gap:20px;margin-bottom:18px}.surface h2,.list-head h2{margin:0;font-size:18px;letter-spacing:-.02em}
.metrics{display:grid;grid-template-columns:repeat(6,minmax(110px,1fr));gap:10px;margin-bottom:16px}.metric{min-height:104px;padding:16px;background:var(--surface);border:1px solid var(--line);border-radius:var(--radius);display:flex;flex-direction:column;justify-content:space-between}.metric strong{font-size:24px;letter-spacing:-.04em}.metric span{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.09em}.dashboard-grid{display:grid;grid-template-columns:minmax(0,1fr) minmax(420px,.9fr);gap:16px}.traffic-card canvas{display:block;width:100%;height:300px;background:#0b151e;border:1px solid #1b2b36;border-radius:6px}.legend{display:flex;align-items:center;gap:16px;margin-top:12px;color:var(--muted);font-size:12px}.legend small{margin-left:auto}.swatch{display:inline-block;width:18px;height:2px;margin-right:6px;vertical-align:middle}.swatch.inbound{background:var(--cyan)}.swatch.outbound{background:var(--amber)}#graph{display:block;width:100%;min-height:310px;background:#0b151e;border:1px solid #1b2b36;border-radius:6px}.map-note{margin:11px 0 0;color:var(--muted);font-size:11px}.line-key{display:inline-block;width:22px;margin:0 5px 2px 12px;border-top:2px solid var(--blue)}.line-key.dashed{border-top-style:dashed;border-color:var(--amber)}.graph-node{cursor:pointer}.graph-node circle{stroke-width:2;transition:r .12s,filter .12s}.graph-node:hover circle,.graph-node:focus circle{r:14;filter:brightness(1.18)}.graph-node text{pointer-events:none;font:10px "SFMono-Regular",monospace}.graph-edge{fill:none;stroke-width:1.5;opacity:.7}.graph-edge.routed{stroke-dasharray:5 6;stroke:var(--amber)}.graph-edge.direct{stroke:var(--blue)}
.segmented{display:inline-flex;padding:4px;margin-bottom:16px;background:var(--rail);border:1px solid var(--line);border-radius:8px}.segmented button{padding:8px 15px;border:0;border-radius:5px;background:transparent;color:var(--muted);font-weight:700}.segmented button.active{background:var(--raised);color:var(--ink)}.app-view{display:grid;gap:16px}.app-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(210px,1fr));gap:10px}.app-tile{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:14px;background:var(--rail);border:1px solid var(--line);border-radius:7px}.app-icon{width:34px;height:34px;display:grid;place-items:center;border-radius:6px;background:var(--cyan-dim);color:var(--cyan);font-weight:800}.list-surface{margin-bottom:16px}.search input{width:min(340px,42vw);margin:0}.list-tools{display:flex;align-items:center;gap:10px}.limit{display:flex;align-items:center;gap:7px;color:var(--muted);font-size:12px}.limit input{width:66px;margin:0}.record-list{display:flex;flex-direction:column}.record{display:grid;grid-template-columns:minmax(180px,1.3fr) minmax(110px,.6fr) minmax(150px,.8fr) auto;gap:16px;align-items:center;min-height:70px;padding:12px 4px;border-top:1px solid var(--line)}.record:first-child{border-top:0}.record-main{min-width:0}.record-main strong{display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.record-main small,.record-meta{color:var(--muted);font-size:12px}.record-id{overflow:hidden;text-overflow:ellipsis;color:var(--muted);font-size:12px}.record-actions{display:flex;justify-content:flex-end;gap:7px}.node-record{grid-template-columns:minmax(210px,1.2fr) minmax(140px,.8fr) minmax(110px,.5fr) auto}.empty{padding:34px 0;border-top:1px solid var(--line);color:var(--muted);text-align:center}.soft-count{color:var(--muted);font-size:13px;font-weight:500}.pager{display:flex;justify-content:flex-end;align-items:center;gap:8px;padding-top:15px;border-top:1px solid var(--line);color:var(--muted);font-size:12px}.pager button{padding:6px 10px}.pager button:disabled{opacity:.35;cursor:not-allowed}
input,textarea{width:100%;padding:10px 12px;color:var(--ink);background:#0a141d;border:1px solid var(--line);border-radius:6px;outline:none}input:focus,textarea:focus{border-color:var(--cyan);box-shadow:0 0 0 3px rgba(97,214,200,.09)}textarea{min-height:82px;resize:vertical;word-break:break-all}.field{display:block}.field>span{display:block;margin-bottom:6px;color:var(--muted);font-size:12px;font-weight:650}.primary,.secondary,.icon-button,.text-button{border-radius:6px;font-weight:750}.primary{padding:9px 14px;border:1px solid var(--cyan);background:var(--cyan);color:#071614}.secondary{padding:9px 13px;border:1px solid var(--line-strong);background:transparent;color:var(--ink)}.primary:hover,.secondary:hover{filter:brightness(1.1)}button:disabled{opacity:.5;cursor:wait}.wide{width:100%}.text-button{padding:0;border:0;background:transparent;color:var(--muted)}.icon-button{padding:7px 10px;border:1px solid var(--line);background:transparent;color:var(--muted)}.message{min-height:20px;margin:0;color:var(--muted);font-size:12px}.message.error{color:var(--red)}.action-row{display:flex;align-items:center;gap:10px;margin-top:12px}.action-row.wrap{flex-wrap:wrap}.action-row input{margin:0}.compact{width:90px}.disclosure{margin-bottom:16px}.disclosure>summary{cursor:pointer;font-size:16px;font-weight:750;list-style:none}.disclosure>summary:after{content:"+";float:right;color:var(--muted)}.disclosure[open]>summary:after{content:"-"}.disclosure[open]>summary{margin-bottom:20px}.form-grid{display:grid;gap:14px}.form-grid.two,.settings-grid{grid-template-columns:repeat(2,minmax(0,1fr))}.settings-grid{display:grid;gap:16px}.form-block{display:flex;flex-direction:column;gap:9px;padding:14px;background:var(--rail);border:1px solid var(--line);border-radius:7px}.form-block h3{margin:0 0 4px}.info-strip{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:14px}.info-item{padding:7px 10px;background:var(--rail);border:1px solid var(--line);border-radius:6px;color:var(--muted);font-size:12px}.info-item strong{color:var(--ink);margin-left:5px}.transport-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:10px}.transport-card{padding:13px;background:var(--rail);border:1px solid var(--line);border-radius:7px}.transport-card strong{display:block;margin-bottom:8px;text-transform:uppercase;letter-spacing:.08em;font-size:11px;color:var(--cyan)}.transport-card span{display:block;color:var(--muted);font-size:12px}.definition-list{display:grid;grid-template-columns:120px 1fr;gap:9px 16px}.definition-list dt{color:var(--muted)}.definition-list dd{margin:0;word-break:break-all;white-space:pre-line}.chip-list{display:flex;flex-wrap:wrap;gap:7px;margin-top:12px}.chip{display:inline-flex;align-items:center;gap:7px;padding:6px 9px;border:1px solid var(--line);border-radius:999px;color:var(--muted);font-size:11px}.chip button{padding:0;border:0;background:transparent;color:var(--red)}.output{display:block;margin-top:10px;word-break:break-all;color:var(--cyan)}
dialog{width:min(680px,calc(100vw - 28px));padding:0;color:var(--ink);background:var(--surface);border:1px solid var(--line-strong);border-radius:12px;box-shadow:var(--shadow)}dialog::backdrop{background:rgba(1,6,10,.78);backdrop-filter:blur(3px)}.dialog-head{display:flex;justify-content:space-between;align-items:center;padding:20px 22px;border-bottom:1px solid var(--line)}.dialog-head h2{margin:0}.node-detail{padding:22px;display:grid;grid-template-columns:140px 1fr;gap:12px 18px}.node-detail .key{color:var(--muted);font-size:12px}.node-detail .value{min-width:0;word-break:break-all}.node-detail ul{margin:0;padding-left:18px}.dialog-actions{display:flex;align-items:center;gap:12px;padding:0 22px 22px}
@keyframes panel-in{from{opacity:.3;transform:translateY(4px)}to{opacity:1;transform:none}}@media(prefers-reduced-motion:reduce){*{scroll-behavior:auto!important;animation:none!important;transition:none!important}}
@media(max-width:1100px){.metrics{grid-template-columns:repeat(3,1fr)}.dashboard-grid{grid-template-columns:1fr}.settings-grid{grid-template-columns:1fr}.topology-card{min-height:420px}}
@media(max-width:760px){.shell{display:block}.rail{position:fixed;z-index:20;left:0;right:0;top:auto;bottom:0;width:auto;height:68px;padding:7px 8px;background:rgba(11,20,29,.97);border:0;border-top:1px solid var(--line)}.identity,.rail-foot{display:none}.tabs{height:100%;display:grid;grid-template-columns:repeat(4,1fr);gap:4px}.tabs button{display:flex;flex-direction:column;justify-content:center;gap:3px;padding:5px 2px;text-align:center;font-size:11px}.tab-index{display:none}main{padding:0 16px 92px}.topbar{height:74px;margin-bottom:28px}.top-meta{gap:7px}.page-head{display:block;margin-bottom:20px}.page-head .lede,.page-head .head-actions{margin-top:12px}.page-head h1{font-size:29px}.metrics{grid-template-columns:repeat(2,1fr)}.metric{min-height:90px}.metric strong{font-size:20px}.surface{padding:17px}.surface-head,.list-head{align-items:flex-start;flex-direction:column}.search,.search input{width:100%}.list-tools{width:100%;align-items:stretch}.list-tools .search{flex:1}.record,.node-record{grid-template-columns:minmax(0,1fr) auto;gap:8px}.record-meta,.record-id{grid-column:1}.record-actions{grid-column:2;grid-row:1 / span 3;flex-direction:column}.form-grid.two{grid-template-columns:1fr}.definition-list{grid-template-columns:1fr;gap:4px}.definition-list dd{margin-bottom:8px}.legend{flex-wrap:wrap}.legend small{width:100%;margin:0}#graph{min-height:260px}.node-detail{grid-template-columns:1fr;gap:3px}.node-detail .value{margin-bottom:9px}}
"""


APP_JS = r"""
let TOKEN = null, statusTimer = null, storeTimer = null;
let last = null, previous = null, activeTab = "overview", ticking = false;
const rateHistory = [];
const $ = (id) => document.getElementById(id);
const esc = (value) => String(value == null ? "" : value).replace(/[&<>"']/g,
  (char) => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[char]));
const short = (id) => id ? id.slice(0, 8) + "..." + id.slice(-5) : "unknown";

async function api(path, method = "GET", body) {
  const headers = {};
  if (TOKEN) headers.Authorization = "Bearer " + TOKEN;
  if (body !== undefined) headers["Content-Type"] = "application/json";
  const response = await fetch(path, {method, headers,
    body:body === undefined ? undefined : JSON.stringify(body)});
  if (response.status === 401) { showLogin(); throw new Error("unauthorized"); }
  return response;
}
function setMessage(id, text, bad = false) {
  const element = $(id); if (!element) return;
  element.textContent = text || ""; element.classList.toggle("error", !!bad);
}
function fmtBytes(value) {
  if (value == null || !Number.isFinite(Number(value))) return "n/a";
  let amount = Number(value), unit = 0; const units = ["B","KB","MB","GB","TB"];
  while (amount >= 1024 && unit < units.length - 1) { amount /= 1024; unit++; }
  return amount.toFixed(unit ? 1 : 0) + " " + units[unit];
}
function fmtDuration(value) {
  let seconds = Math.max(0, Math.floor(value || 0));
  const days = Math.floor(seconds / 86400); seconds %= 86400;
  const hours = Math.floor(seconds / 3600); seconds %= 3600;
  const minutes = Math.floor(seconds / 60);
  return [days ? days + "d" : "",hours ? hours + "h" : "",minutes + "m"].filter(Boolean).join(" ");
}
function fmtAgo(value) {
  const seconds = Math.max(0, Math.floor(value || 0));
  if (seconds < 60) return seconds + "s ago";
  if (seconds < 3600) return Math.floor(seconds / 60) + "m ago";
  if (seconds < 86400) return Math.floor(seconds / 3600) + "h ago";
  return Math.floor(seconds / 86400) + "d ago";
}

function showLogin() {
  TOKEN = null; try { sessionStorage.removeItem("nmesh_token"); } catch (_) {}
  if (statusTimer) clearInterval(statusTimer); if (storeTimer) clearInterval(storeTimer);
  statusTimer = storeTimer = null; $("app").classList.add("hidden"); $("login").classList.remove("hidden");
}
function startApp() {
  $("login").classList.add("hidden"); $("app").classList.remove("hidden");
  selectTab((location.hash || "#overview").slice(1), false); tick();
  if (!statusTimer) statusTimer = setInterval(tick, 2000);
  if (!storeTimer) storeTimer = setInterval(() => activeTab === "apps" && refreshApps(), 7000);
}
$("login-form").addEventListener("submit", async (event) => {
  event.preventDefault(); setMessage("login-error", "");
  try {
    const response = await fetch("/api/login", {method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({password:$("password").value})});
    const data = await response.json().catch(() => ({}));
    if (!response.ok) { setMessage("login-error", data.error || "Login failed", true); return; }
    TOKEN = data.token; try { sessionStorage.setItem("nmesh_token", TOKEN); } catch (_) {}
    $("password").value = ""; startApp();
  } catch (_) { setMessage("login-error", "Console is not reachable", true); }
});
$("logout").addEventListener("click", async () => { try { await api("/api/logout", "POST"); } catch (_) {} showLogin(); });
(async function resumeSession(){try{const response=await fetch("/api/state");if(response.ok)startApp();}catch(_){}})();

function selectTab(name, updateHash = true) {
  if (!document.querySelector(`[data-panel="${name}"]`)) name = "overview";
  activeTab = name;
  document.querySelectorAll("[data-tab]").forEach((button) => {
    const selected = button.dataset.tab === name;
    button.setAttribute("aria-selected", selected ? "true" : "false"); button.tabIndex = selected ? 0 : -1;
  });
  document.querySelectorAll("[data-panel]").forEach((panel) => { panel.hidden = panel.dataset.panel !== name; });
  if (updateHash) window.history.replaceState(null, "", "#" + name);
  if (name === "connectivity") refreshConnectivity(); if (name === "apps") refreshApps();
}
$("tabs").addEventListener("click", (event) => { const button=event.target.closest("[data-tab]");if(button)selectTab(button.dataset.tab); });
$("tabs").addEventListener("keydown", (event) => {
  if (!["ArrowLeft","ArrowRight","ArrowUp","ArrowDown"].includes(event.key)) return;
  const buttons=[...document.querySelectorAll("[data-tab]")], current=buttons.findIndex((button)=>button.dataset.tab===activeTab);
  const step=["ArrowRight","ArrowDown"].includes(event.key)?1:-1, next=buttons[(current+step+buttons.length)%buttons.length];
  next.focus(); selectTab(next.dataset.tab); event.preventDefault();
});

async function tick() {
  if (ticking) return; ticking = true;
  try {
    const response=await api("/api/state"); if(!response.ok)return;
    const state=await response.json(); updateRates(state); last=state;
    renderHeader(state); renderMetrics(state); drawChart(); drawGraph(state); renderSettings(state);
  } catch (_) { $("rail-dot").classList.remove("up"); $("rail-state").textContent="Unavailable"; }
  finally { ticking=false; }
}
function updateRates(state) {
  let inbound=0,outbound=0;
  const reset=!previous||previous.id!==state.id||state.uptime<previous.uptime||state.total.bytes_in<previous.bytes_in||state.total.bytes_out<previous.bytes_out;
  if (!reset) { const elapsed=state.server_time-previous.time;if(elapsed>0){inbound=(state.total.bytes_in-previous.bytes_in)/elapsed;outbound=(state.total.bytes_out-previous.bytes_out)/elapsed;} }
  else rateHistory.length=0;
  previous={id:state.id,uptime:state.uptime,time:state.server_time,bytes_in:state.total.bytes_in,bytes_out:state.total.bytes_out};
  rateHistory.push({inbound:Math.max(0,inbound),outbound:Math.max(0,outbound)});while(rateHistory.length>90)rateHistory.shift();
  state._rates={inbound,outbound};
}
function renderHeader(state) {
  $("self-node").textContent=short(state.id);$("node-uptime").textContent="Up "+fmtDuration(state.uptime);
  const pill=$("node-state");pill.textContent=state.running?"Running":"Stopped";pill.className="state-pill"+(state.running?" up":"");
  $("rail-dot").classList.toggle("up",!!state.running);$("rail-state").textContent=state.running?"Node online":"Node stopped";
  const connected=state.authenticated_peers||0;$("overview-status").textContent=connected?`Actively connected to ${connected} node${connected===1?"":"s"}`:"Searching for a mesh neighbor";
}
function renderMetrics(state) {
  const cpu=state.load&&state.load.cpu_percent!=null?Math.round(state.load.cpu_percent)+"%":"n/a";
  const items=[["Active links",state.authenticated_peers||0],["Known nodes",state.routing_size||0],["E2E sessions",(state.e2e_sessions||[]).length],["Inbound",fmtBytes(state._rates.inbound)+"/s"],["Outbound",fmtBytes(state._rates.outbound)+"/s"],["CPU / memory",cpu+" / "+fmtBytes(state.load&&state.load.rss_bytes)]];
  $("metrics").innerHTML=items.map(([label,value])=>`<div class="metric"><strong>${esc(value)}</strong><span>${esc(label)}</span></div>`).join("");
  $("rate-now").textContent=fmtBytes(state._rates.inbound)+"/s in  "+fmtBytes(state._rates.outbound)+"/s out";
}
function drawChart() {
  const canvas=$("chart"),context=canvas.getContext("2d"),width=canvas.width,height=canvas.height;context.clearRect(0,0,width,height);
  context.strokeStyle="#1d303c";context.lineWidth=1;for(let row=1;row<5;row++){const y=row*height/5;context.beginPath();context.moveTo(0,y);context.lineTo(width,y);context.stroke();}
  const maximum=Math.max(1,...rateHistory.flatMap((point)=>[point.inbound,point.outbound]));
  const plot=(key,color)=>{context.beginPath();context.strokeStyle=color;context.lineWidth=2.5;rateHistory.forEach((point,index)=>{const x=index*width/Math.max(1,rateHistory.length-1),y=height-14-point[key]*(height-28)/maximum;index?context.lineTo(x,y):context.moveTo(x,y);});context.stroke();};
  plot("inbound","#61d6c8");plot("outbound","#e6b76a");
}

const SVG_NS="http://www.w3.org/2000/svg";
function svgElement(name,attrs={}){const node=document.createElementNS(SVG_NS,name);Object.entries(attrs).forEach(([key,value])=>node.setAttribute(key,String(value)));return node;}
function drawGraph(state) {
  const svg=$("graph");svg.replaceChildren();const topology=state.topology||{direct:[],routed:[]},direct=topology.direct||[],routed=topology.routed||[],center={x:310,y:194},positions=new Map();
  direct.forEach((node,index)=>{const angle=Math.PI*2*index/Math.max(1,direct.length)-Math.PI/2;positions.set(node.id,{x:center.x+Math.cos(angle)*112,y:center.y+Math.sin(angle)*112});});
  routed.forEach((node,index)=>{const angle=Math.PI*2*index/Math.max(1,routed.length)-Math.PI/2+.23;positions.set(node.id,{x:center.x+Math.cos(angle)*178,y:center.y+Math.sin(angle)*158});});
  direct.forEach((node)=>{const point=positions.get(node.id);svg.appendChild(svgElement("line",{x1:center.x,y1:center.y,x2:point.x,y2:point.y,class:"graph-edge direct"}));});
  routed.forEach((node)=>{const from=positions.get(node.via)||center,to=positions.get(node.id);svg.appendChild(svgElement("line",{x1:from.x,y1:from.y,x2:to.x,y2:to.y,class:"graph-edge routed"}));});
  const addNode=(id,point,kind,label)=>{const group=svgElement("g",{class:"graph-node",tabindex:"0",role:"button","data-node-id":id,"aria-label":label});group.appendChild(svgElement("circle",{cx:point.x,cy:point.y,r:kind==="self"?14:11,fill:kind==="self"?"#eef4f8":kind==="direct"?"#75a7ff":"#e6b76a",stroke:kind==="self"?"#eef4f8":"#0b151e"}));const text=svgElement("text",{x:point.x,y:point.y+27,"text-anchor":"middle",fill:"#8c9aa7"});text.textContent=kind==="self"?"this node":short(id);group.appendChild(text);svg.appendChild(group);};
  direct.forEach((node)=>addNode(node.id,positions.get(node.id),"direct",`Direct node ${node.id}`));routed.forEach((node)=>addNode(node.id,positions.get(node.id),"routed",`Routed session ${node.id} via ${node.via}`));addNode(state.id,center,"self","This node "+state.id);
  $("map-count").textContent=`${direct.length} direct${routed.length?` + ${routed.length} routed`:""}`;
}
$("graph").addEventListener("click",(event)=>{const node=event.target.closest&&event.target.closest("[data-node-id]");if(node)openNode(node.dataset.nodeId);});
$("graph").addEventListener("keydown",(event)=>{if(!["Enter"," "].includes(event.key))return;const node=event.target.closest("[data-node-id]");if(node){openNode(node.dataset.nodeId);event.preventDefault();}});
$("self-node").addEventListener("click",()=>last&&openNode(last.id,{id:last.id,connected:true,self:true,addresses:last.advertised||[]}));

const pages={active:{scope:"active",query:"",limit:20,offset:0,total:0},known:{scope:"known",query:"",limit:20,offset:0,total:0},catalog:{query:"",limit:20,offset:0,total:0},installed:{query:"",limit:20,offset:0,total:0}};
async function fetchPage(kind) {
  const page=pages[kind],base=kind==="catalog"?"/api/store/catalog":kind==="installed"?"/api/store/installed":"/api/nodes";
  const params=new URLSearchParams({q:page.query,limit:String(page.limit),offset:String(page.offset)});if(page.scope)params.set("scope",page.scope);
  const response=await api(base+"?"+params.toString());if(!response.ok)throw new Error("list failed");const data=await response.json();page.total=data.total;return data.items||[];
}
function pager(kind,id,render) {
  const page=pages[kind],element=$(id),first=page.total?page.offset+1:0,lastItem=Math.min(page.total,page.offset+page.limit);
  element.innerHTML=`<span>${first}-${lastItem} of ${page.total}</span><button class="secondary" data-page="prev" ${page.offset===0?"disabled":""}>Previous</button><button class="secondary" data-page="next" ${page.offset+page.limit>=page.total?"disabled":""}>Next</button>`;
  element.onclick=(event)=>{const direction=event.target.dataset.page;if(!direction)return;page.offset=direction==="next"?page.offset+page.limit:Math.max(0,page.offset-page.limit);render();};
}
async function refreshConnectivity(){if(activeTab!=="connectivity")return;await Promise.all([renderNodeList("active"),renderNodeList("known")]);}
async function renderNodeList(kind) {
  const target=$(kind+"-list");
  try {
    const items=await fetchPage(kind);$(kind+"-count").textContent=`(${pages[kind].total})`;
    target.innerHTML=items.length?items.map((node)=>{const detail=node.connected?"Authenticated direct link":node.has_key?"Identity key known":"Identity key unavailable",transport=node.transport||((node.addresses||[])[0]||"").split(":",1)[0]||"No address";return `<div class="record node-record"><div class="record-main"><strong class="mono">${esc(short(node.id))}</strong><small>${esc(detail)}</small></div><div class="record-meta">${esc(transport)}${node.rtt_ms!=null?` | ${esc(node.rtt_ms)} ms`:""}</div><div class="record-id mono">${node.seen_ago==null?"Live now":esc(fmtAgo(node.seen_ago))}</div><div class="record-actions"><button class="secondary" data-node-id="${esc(node.id)}">Details</button></div></div>`;}).join(""):`<div class="empty">${pages[kind].query?"No matching nodes":kind==="active"?"No authenticated links yet":"No known nodes yet"}</div>`;
    pager(kind,kind+"-pager",()=>renderNodeList(kind));
  } catch (_) { target.innerHTML='<div class="empty">Node list unavailable</div>'; }
}
document.querySelectorAll(".node-list").forEach((list)=>list.addEventListener("click",(event)=>{const button=event.target.closest("[data-node-id]");if(button)openNode(button.dataset.nodeId);}));
function debounce(callback,delay=250){let timer;return(...args)=>{clearTimeout(timer);timer=setTimeout(()=>callback(...args),delay);};}
$("active-search").addEventListener("input",debounce(()=>{pages.active.query=$("active-search").value.trim();pages.active.offset=0;renderNodeList("active");}));
$("known-search").addEventListener("input",debounce(()=>{pages.known.query=$("known-search").value.trim();pages.known.offset=0;renderNodeList("known");}));
$("known-limit").addEventListener("change",()=>{const value=Math.max(1,Math.min(100,parseInt($("known-limit").value,10)||20));$("known-limit").value=value;pages.known.limit=value;pages.known.offset=0;renderNodeList("known");});

let detailNodeId=null;
async function exactNode(scope,id){const params=new URLSearchParams({scope,q:id,limit:"20",offset:"0"}),response=await api("/api/nodes?"+params.toString());if(!response.ok)return null;return(await response.json()).items.find((item)=>item.id===id)||null;}
async function openNode(id,seed={}) {
  detailNodeId=id;const dialog=$("node-dialog");if(!dialog.open)dialog.showModal();$("node-dialog-title").textContent=short(id);$("node-detail-body").innerHTML='<div class="key">Status</div><div class="value">Loading current details...</div>';setMessage("detail-status","");
  let known=null,active=null;if(last&&id!==last.id)[known,active]=await Promise.all([exactNode("known",id).catch(()=>null),exactNode("active",id).catch(()=>null)]);
  const node=Object.assign({},known||{},active||{},seed,{id}),addresses=node.addresses||[];
  const rows=[["Full node ID",`<span class="mono">${esc(id)}</span>`],["Relationship",node.self?"This console's node":active?"Authenticated direct link":known?"Known routing identity":"Routed session endpoint"],["Session",node.has_session===false?"Not established":active?"Open":node.self?"Local":"Not directly observed"],["Direction",node.self?"Local":node.is_client_side==null?"Unknown":node.is_client_side?"Outbound":"Inbound"],["Transport",esc(node.transport||"Unknown")],["RTT",node.rtt_ms==null?"Not measured":esc(node.rtt_ms)+" ms"],["Last seen",node.seen_ago==null?"Live / unavailable":esc(fmtAgo(node.seen_ago))],["Identity key",node.has_key==null?"Unknown":node.has_key?"Known":"Missing"],["Malformed input",node.malformed==null?"Not available":esc(node.malformed)],["Traffic",node.counters?`${esc(fmtBytes(node.counters.bytes_in))} in / ${esc(fmtBytes(node.counters.bytes_out))} out`:"Not available"],["Addresses",addresses.length?`<ul class="mono">${addresses.map((address)=>`<li>${esc(address)}</li>`).join("")}</ul>`:"None advertised"]];
  $("node-detail-body").innerHTML=rows.map(([key,value])=>`<div class="key">${key}</div><div class="value">${value}</div>`).join("");$("detail-ping").classList.toggle("hidden",!!node.self);$("detail-forget").classList.toggle("hidden",!!node.self);
}
$("detail-ping").addEventListener("click",async()=>{if(!detailNodeId)return;$("detail-ping").disabled=true;setMessage("detail-status","Pinging through the mesh...");try{const response=await api("/api/ping/node","POST",{id:detailNodeId}),data=await response.json();setMessage("detail-status",data.reachable?`Reachable in ${data.rtt_ms==null?"an unknown time":data.rtt_ms+" ms"} via ${data.via||"mesh"}`:"Node is currently unreachable",!data.reachable);tick();}catch(_){setMessage("detail-status","Ping failed",true);}finally{$("detail-ping").disabled=false;}});
$("detail-forget").addEventListener("click",async()=>{if(!detailNodeId)return;if(!confirm("Forget this node? It will be removed from the routing table and disconnected; it may reappear if it contacts us again."))return;$("detail-forget").disabled=true;setMessage("detail-status","Forgetting node...");try{const response=await api("/api/nodes/forget","POST",{id:detailNodeId}),data=await response.json();if(response.ok&&data.ok){$("node-dialog").close();await Promise.all([refreshConnectivity(),tick()]);}else setMessage("detail-status",data.error||"Node not found",true);}catch(_){setMessage("detail-status","Forget failed",true);}finally{$("detail-forget").disabled=false;}});
$("ping-btn").addEventListener("click",async()=>{$("ping-btn").disabled=true;setMessage("ping-status","Pinging...");try{const data=await(await api("/api/ping","POST")).json();setMessage("ping-status",`Sent ${data.sent||0} probes`);setTimeout(tick,800);}catch(_){setMessage("ping-status","Ping failed",true);}finally{$("ping-btn").disabled=false;}});

let appView="installed";
document.querySelector(".segmented").addEventListener("click",(event)=>{const button=event.target.closest("[data-app-view]");if(!button)return;appView=button.dataset.appView;document.querySelectorAll("[data-app-view]").forEach((item)=>item.classList.toggle("active",item===button));$("apps-installed-view").classList.toggle("hidden",appView!=="installed");$("apps-store-view").classList.toggle("hidden",appView!=="store");refreshApps();});
async function refreshApps(){if(activeTab!=="apps")return;renderBuiltins();if(appView==="installed")await renderAppList("installed");else await renderAppList("catalog");}
function renderBuiltins(){const apps=last&&last.apps||[];$("builtin-apps").innerHTML=apps.length?apps.map((app)=>`<div class="app-tile"><div class="action-row"><span class="app-icon">${esc((app.name||"A").slice(0,2).toUpperCase())}</span><div><strong>${esc(app.name)}</strong><div class="subtle">Running built-in</div></div></div><a class="primary" href="${esc(app.path)}">Open</a></div>`).join(""):'<div class="empty">No built-in apps are running</div>';}
async function renderAppList(kind) {
  const target=$(kind+"-list");try{const items=await fetchPage(kind);$(kind+"-count").textContent=`(${pages[kind].total})`;target.innerHTML=items.length?items.map((app)=>{const action=kind==="installed"?"uninstall":app.action,actionCell=action?`<button class="${action==="uninstall"?"secondary":"primary"}" data-app-id="${esc(app.app_id)}" data-app-action="${esc(action)}">${action==="uninstall"?"Delete local":action==="update"?"Update":"Install"}</button>`:'<span class="state-pill up">Installed</span>';return `<div class="record"><div class="record-main"><strong>${esc(app.name)}</strong><small>Version ${esc(app.version)}</small></div><div class="record-meta">${kind==="installed"?"Local package":esc(app.state||"Available")}</div><div class="record-id mono" title="${esc(app.app_id)}">${esc(short(app.app_id))}</div><div class="record-actions">${actionCell}</div></div>`;}).join(""):`<div class="empty">${pages[kind].query?"No matching apps":kind==="installed"?"No local packages installed":"No signed releases in the catalog"}</div>`;pager(kind,kind+"-pager",()=>renderAppList(kind));}catch(_){target.innerHTML='<div class="empty">App list unavailable</div>';}}
$("installed-search").addEventListener("input",debounce(()=>{pages.installed.query=$("installed-search").value.trim();pages.installed.offset=0;renderAppList("installed");}));
$("catalog-search").addEventListener("input",debounce(()=>{pages.catalog.query=$("catalog-search").value.trim();pages.catalog.offset=0;renderAppList("catalog");}));
async function appAction(button){const action=button.dataset.appAction,appId=button.dataset.appId;if(action==="uninstall"&&!confirm("Delete this app from this node? The network catalog is not changed."))return;button.disabled=true;setMessage("store-status",action+" in progress...");try{const response=await api("/api/store/"+action,"POST",{app_id:appId}),data=await response.json().catch(()=>({}));setMessage("store-status",response.ok&&data.ok!==false?(action==="uninstall"?"Local app deleted":action+" complete"):data.error||action+" failed",!response.ok||data.ok===false);}catch(_){setMessage("store-status",action+" failed",true);}finally{button.disabled=false;await refreshApps();}}
[$("catalog-list"),$("installed-list")].forEach((list)=>list.addEventListener("click",(event)=>{const button=event.target.closest("[data-app-action]");if(button)appAction(button);}));
function fileToBase64(file){return new Promise((resolve,reject)=>{const reader=new FileReader();reader.onload=()=>resolve(String(reader.result).split(",")[1]||"");reader.onerror=reject;reader.readAsDataURL(file);});}
async function selectedFiles(input){const files={};for(const file of input.files)files[file.name]=await fileToBase64(file);return files;}
$("store-publish-btn").addEventListener("click",async()=>{const name=$("store-name").value.trim(),version=$("store-version").value.trim()||"1.0.0",input=$("store-files");if(!name||!input.files.length){setMessage("store-status","Name and at least one file are required",true);return;}$("store-publish-btn").disabled=true;setMessage("store-status","Reading and signing files...");try{const response=await api("/api/store/publish","POST",{name,version,files:await selectedFiles(input)}),data=await response.json().catch(()=>({}));setMessage("store-status",response.ok?"Release published to the mesh":data.error||"Publish failed",!response.ok);if(response.ok)input.value="";}catch(_){setMessage("store-status","Publish failed",true);}finally{$("store-publish-btn").disabled=false;await renderAppList("catalog");}});

function renderSettings(state) {
  const network=state.network||{};$("relay-state").textContent=state.relay_capable?"Relay capable":"Client reachability";$("relay-state").className="state-pill"+(state.relay_capable?" up":"");
  const summary=[["Internet",network.internet==null?"Checking":network.internet?"Online":"Offline"],["Public IP",network.public_ip||"Unknown"],["Public UDP",network.stun_addr||"Unknown"],["Pending seeks",state.pending_seeks||0]];$("network-summary").innerHTML=summary.map(([key,value])=>`<span class="info-item">${esc(key)}<strong>${esc(value)}</strong></span>`).join("");
  $("transport-list").innerHTML=(state.transport_details||[]).map((transport)=>`<div class="transport-card"><strong>${esc(transport.scheme)}</strong><span>${esc(transport.peers||0)} peer(s)</span><span>${(transport.listening||[]).length} listener(s)</span><span>${(transport.ports||[]).length?"Ports "+esc(transport.ports.join(", ")):"No bound port"}</span></div>`).join("")||'<div class="empty">No transport registered</div>';
  const udpOn=(state.transport_details||[]).some((transport)=>transport.hole_punch);$("punch-toggle").textContent="Hole punching "+(state.punch_enabled?"on":"off");$("keepalive-toggle").textContent="NAT keepalive "+(state.punch_keepalive?"on":"off");$("udp-toggle").textContent=udpOn?"Stop UDP":"Start UDP";$("udp-port").classList.toggle("hidden",udpOn);$("lan-toggle").textContent="LAN discovery "+(state.lan_discovery?"on":"off");
  $("addressing").innerHTML=[["Advertised",(state.advertised||[]).join("\n")||"None"],["Local IPs",(state.local_ips||[]).join(", ")||"None"],["Schemes",(state.transports||[]).join(", ")||"None"]].map(([key,value])=>`<dt>${esc(key)}</dt><dd class="mono">${esc(value)}</dd>`).join("");
  $("listener-list").innerHTML=(state.listening||[]).map((uri)=>`<span class="chip mono">${esc(uri)}<button data-remove-listener="${esc(uri)}" aria-label="Remove listener">x</button></span>`).join("");
}
async function toggle(path,body,message){try{const response=await api(path,"POST",body);if(!response.ok)throw new Error();setMessage("transport-status",message);tick();}catch(_){setMessage("transport-status","Control action failed",true);}}
$("punch-toggle").addEventListener("click",()=>last&&toggle("/api/punch",{enabled:!last.punch_enabled},"Hole punching updated"));$("keepalive-toggle").addEventListener("click",()=>last&&toggle("/api/punch/keepalive",{enabled:!last.punch_keepalive},"NAT keepalive updated"));$("lan-toggle").addEventListener("click",()=>last&&toggle("/api/lan/discovery",{enabled:!last.lan_discovery},"LAN discovery updated"));$("net-recheck").addEventListener("click",()=>toggle("/api/net/recheck",{},"Network check requested"));
$("reach-probe").addEventListener("click",async()=>{try{const data=await(await api("/api/reachability/probe","POST")).json();setMessage("transport-status",data.sent?`Sent ${data.sent} reachability probe(s)`:"No active peer can probe us");}catch(_){setMessage("transport-status","Probe failed",true);}});
$("udp-toggle").addEventListener("click",()=>{if(!last)return;const on=(last.transport_details||[]).some((item)=>item.hole_punch),port=parseInt($("udp-port").value,10);if(!on&&!(port>0&&port<65536)){setMessage("transport-status","Enter a valid UDP port",true);return;}toggle("/api/udp",on?{action:"stop"}:{action:"start",port},on?"UDP stopped":"UDP started");});
async function copyText(text){try{await navigator.clipboard.writeText(text);return true;}catch(_){return false;}}
$("cx-request").addEventListener("click",async()=>{try{const data=await(await api("/api/connect/request","POST")).json();$("cx-request-out").value=data.block;setMessage("connect-status",await copyText(data.block)?"Request copied":"Request ready");}catch(_){setMessage("connect-status","Could not create request",true);}});
$("cx-accept").addEventListener("click",async()=>{const block=$("cx-accept-in").value.trim();if(!block){setMessage("connect-status","Paste a request first",true);return;}try{const response=await api("/api/connect/accept","POST",{block}),data=await response.json();if(!response.ok)throw new Error(data.error);$("cx-accept-out").value=data.block;setMessage("connect-status",await copyText(data.block)?"Invite copied":"Invite ready");}catch(error){setMessage("connect-status",error.message||"Accept failed",true);}});
$("cx-complete").addEventListener("click",async()=>{const block=$("cx-reply-in").value.trim();if(!block){setMessage("connect-status","Paste the reply first",true);return;}try{const response=await api("/api/connect/complete","POST",{block}),data=await response.json();setMessage("connect-status",response.ok?`Trying ${data.candidates} candidate address(es)`:data.error||"Connect failed",!response.ok);}catch(_){setMessage("connect-status","Connect failed",true);}});
$("rly-invite").addEventListener("click",async()=>{try{const data=await(await api("/api/relay/invite","POST")).json();$("rly-invite-out").value=data.block;setMessage("relay-status",await copyText(data.block)?"Relay invite copied":"Relay invite ready");}catch(_){setMessage("relay-status","Invite failed",true);}});
$("rly-join").addEventListener("click",async()=>{const block=$("rly-join-in").value.trim();if(!block){setMessage("relay-status","Paste a relay invite",true);return;}try{const response=await api("/api/relay/join","POST",{block}),data=await response.json();setMessage("relay-status",response.ok?`Joining through ${data.relays} relay(s)`:data.error||"Join failed",!response.ok);}catch(_){setMessage("relay-status","Join failed",true);}});
$("listen-btn").addEventListener("click",async()=>{const uri=$("listen-uri").value.trim();if(!uri){setMessage("transport-status","Enter a listener URI",true);return;}try{const response=await api("/api/listen","POST",{uri});setMessage("transport-status",response.ok?"Listener added":(await response.json()).error||"Listener failed",!response.ok);if(response.ok)$("listen-uri").value="";tick();}catch(_){setMessage("transport-status","Listener failed",true);}});
$("listener-list").addEventListener("click",async(event)=>{const uri=event.target.dataset.removeListener;if(uri){await api("/api/unlisten","POST",{uri}).catch(()=>{});tick();}});
$("gen-invite").addEventListener("click",async()=>{try{$("invite-out").textContent=(await(await api("/api/invite","POST")).json()).code;}catch(_){setMessage("manage-status","Invite generation failed",true);}});
$("show-cert").addEventListener("click",async()=>{try{$("cert-out").value=(await(await api("/api/rootcert")).json()).cert_hex;}catch(_){setMessage("manage-status","Certificate unavailable",true);}});
$("trust-btn").addEventListener("click",async()=>{const cert_hex=$("trust-in").value.trim();if(!cert_hex){setMessage("manage-status","Paste a certificate",true);return;}try{const response=await api("/api/trust","POST",{cert_hex});setMessage("manage-status",response.ok?"Certificate trusted":"Invalid certificate",!response.ok);if(response.ok)$("trust-in").value="";}catch(_){setMessage("manage-status","Trust failed",true);}});
$("join-btn").addEventListener("click",async()=>{const uri=$("join-uri").value.trim(),code=$("join-code").value.trim();if(!uri||!code){setMessage("manage-status","URI and invite code are required",true);return;}try{const response=await api("/api/join","POST",{uri,code});setMessage("manage-status",response.ok?"Join started":(await response.json()).error||"Join failed",!response.ok);}catch(_){setMessage("manage-status","Join failed",true);}});
$("publish-btn").addEventListener("click",async()=>{const name=$("app-name").value.trim(),version=$("app-version").value.trim()||"1.0.0",input=$("app-files");if(!name||!input.files.length){setMessage("app-status","Name and files are required",true);return;}try{setMessage("app-status","Publishing content...");const response=await api("/api/app/publish","POST",{name,version,files:await selectedFiles(input)}),data=await response.json();if(response.ok){$("app-id-out").textContent=data.app_id;setMessage("app-status","Content published");}else setMessage("app-status",data.error||"Publish failed",true);}catch(_){setMessage("app-status","Publish failed",true);}});
$("fetch-btn").addEventListener("click",async()=>{const app_id=$("fetch-id").value.trim();if(!app_id){setMessage("app-status","Enter a content id",true);return;}try{setMessage("app-status","Fetching content...");const response=await api("/api/app/fetch","POST",{app_id}),data=await response.json();if(!response.ok){setMessage("app-status",response.status===404?"Content not found":data.error||"Fetch failed",true);return;}$("app-files-out").innerHTML=Object.entries(data.files||{}).map(([path,b64])=>`<div class="action-row"><a class="primary" download="${esc(path)}" href="data:application/octet-stream;base64,${b64}">${esc(path)}</a></div>`).join("");setMessage("app-status",`${data.name} ${data.version} fetched`);}catch(_){setMessage("app-status","Fetch failed",true);}});
"""


CHAT_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>NMesh Chat</title>
<link rel="stylesheet" href="/chat.css">
</head>
<body>
<div id="login" class="center">
  <form id="login-form" class="card">
    <div class="logo">NMesh<span>chat</span></div>
    <p class="muted">Sign in with the console password</p>
    <input id="password" type="password" placeholder="Console password" autocomplete="current-password" autofocus>
    <button type="submit">Enter</button>
    <div id="err" class="err"></div>
  </form>
</div>

<div id="app" class="app hidden">
  <aside id="sidebar">
    <header class="side-head">
      <button id="me-btn" class="avatar-btn" title="My profile"><span id="me-av" class="avatar"></span></button>
      <div class="side-title"><div id="me-name" class="name"></div><div id="me-sub" class="muted mono"></div></div>
      <button id="new-btn" class="icon" title="New chat">✎</button>
    </header>
    <div class="search-wrap">
      <input id="side-search" type="search" placeholder="Search chats and people…" autocomplete="off">
      <div id="side-results" class="dropdown hidden"></div>
    </div>
    <div id="chat-list" class="chat-list"></div>
  </aside>

  <main id="chat-pane">
    <div id="empty" class="empty">
      <div class="empty-inner">
        <div class="logo">NMesh<span>chat</span></div>
        <p class="muted">Select a chat or start a new one.</p>
      </div>
    </div>
    <section id="conv" class="conv hidden">
      <header class="conv-head">
        <button id="back-btn" class="icon only-mobile" title="Back">‹</button>
        <button id="info-btn" class="peer">
          <span id="conv-av" class="avatar"></span>
          <span class="peer-txt"><span id="conv-title" class="name"></span><span id="conv-sub" class="muted"></span></span>
        </button>
        <span class="grow"></span>
        <button id="del-conv" class="icon" title="Delete conversation">🗑</button>
      </header>
      <div id="log" class="log"></div>
      <div id="reply-bar" class="reply-bar hidden">
        <div class="reply-info"><span class="reply-name" id="reply-who"></span><span id="reply-text" class="muted"></span></div>
        <button id="reply-cancel" class="icon">✕</button>
      </div>
      <form id="send-form" class="composer">
        <button type="button" id="attach-btn" class="icon" title="Attach file">📎</button>
        <input id="file-input" type="file" hidden>
        <textarea id="msg" rows="1" placeholder="Message" autocomplete="off"></textarea>
        <button type="button" id="emoji-btn" class="icon" title="Emoji">🙂</button>
        <button type="submit" id="send-btn" class="icon send" title="Send">➤</button>
      </form>
    </section>
  </main>
</div>

<div id="ctx" class="ctx hidden"></div>
<div id="emoji-pop" class="emoji-pop hidden"></div>
<div id="viewer" class="viewer hidden"><img id="viewer-img" alt=""></div>

<div id="settings" class="modal hidden">
  <div class="sheet">
    <header class="sheet-head"><b>My profile</b><button class="icon close" data-close="settings">✕</button></header>
    <div class="sheet-body">
      <div class="prof-av-wrap">
        <span id="set-av" class="avatar big"></span>
        <label class="link">Change photo<input id="av-input" type="file" accept="image/*" hidden></label>
        <button id="av-clear" class="link danger">Remove</button>
      </div>
      <label class="fld">Display name<input id="set-name" maxlength="32" placeholder="Your name"></label>
      <label class="fld">Bio<textarea id="set-bio" maxlength="1024" rows="3" placeholder="A few words about you"></textarea></label>
      <div class="fld">Your ID <code id="set-id" class="mono"></code></div>
      <button id="save-prof" class="primary">Save</button>
    </div>
  </div>
</div>

<div id="newchat" class="modal hidden">
  <div class="sheet">
    <header class="sheet-head"><b id="nc-title">New chat</b><button class="icon close" data-close="newchat">✕</button></header>
    <div class="sheet-body">
      <div class="seg"><button id="nc-tab-dm" class="seg-b active">Find people</button><button id="nc-tab-grp" class="seg-b">New group</button></div>
      <div id="nc-dm">
        <input id="nc-search" type="search" placeholder="Search by name…">
        <div id="nc-results" class="results"></div>
        <div class="fld">Or paste a node ID<div class="row"><input id="nc-id" class="mono" placeholder="40-hex node id"><button id="nc-add">Start</button></div></div>
      </div>
      <div id="nc-grp" class="hidden">
        <label class="fld">Group name<input id="grp-name" maxlength="64" placeholder="Group name"></label>
        <div class="muted">Pick members</div>
        <div id="grp-members" class="results"></div>
        <button id="grp-create" class="primary">Create group</button>
      </div>
    </div>
  </div>
</div>

<script src="/chat.js"></script>
</body>
</html>"""

CHAT_CSS = """
:root{
  --bg:#f2f4f7; --panel:#ffffff; --side:#ffffff; --line:#e5e8ee; --text:#0f1720;
  --muted:#7a8699; --accent:#3a7afe; --accent-2:#eaf1ff; --mine:#d7e7ff;
  --theirs:#ffffff; --shadow:0 1px 2px rgba(16,24,40,.08); --danger:#e5484d;
  --tick:#3a7afe; --badge:#3a7afe;
}
@media (prefers-color-scheme:dark){
  :root{--bg:#0e1621;--panel:#0f1a26;--side:#0f1a26;--line:#1e2b3a;--text:#e7edf5;
    --muted:#8aa0b6;--accent:#4f8cff;--accent-2:#16283f;--mine:#245a9e;--theirs:#17232f;
    --shadow:0 1px 2px rgba(0,0,0,.3);--tick:#7fb0ff;--badge:#4f8cff;}
}
*{box-sizing:border-box}
html,body{height:100%}
body{margin:0;background:var(--bg);color:var(--text);
  font:14px/1.45 system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;
  -webkit-font-smoothing:antialiased}
.hidden{display:none!important}
.muted{color:var(--muted)}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
button{font:inherit;cursor:pointer;border:0;background:none;color:inherit}
input,textarea{font:inherit;color:var(--text);background:var(--panel);
  border:1px solid var(--line);border-radius:10px;padding:9px 12px;outline:none;width:100%}
input:focus,textarea:focus{border-color:var(--accent)}
textarea{resize:none}
.link{color:var(--accent);cursor:pointer;background:none;font-size:13px}
.link.danger{color:var(--danger)}
.grow{flex:1}
code.mono{word-break:break-all}

/* login */
.center{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:16px;
  padding:28px;width:340px;max-width:100%;text-align:center;box-shadow:var(--shadow)}
.card input,.card button{margin-top:12px}
.card button[type=submit]{background:var(--accent);color:#fff;border-radius:10px;padding:10px;font-weight:600}
.logo{font-weight:800;font-size:22px;letter-spacing:-.3px}
.logo span{color:var(--accent)}
.err{color:var(--danger);font-size:13px;margin-top:10px;min-height:16px}

/* shell */
.app{display:grid;grid-template-columns:340px 1fr;height:100vh;height:100dvh}
#sidebar{background:var(--side);border-right:1px solid var(--line);display:flex;flex-direction:column;min-width:0}
.side-head{display:flex;align-items:center;gap:10px;padding:12px 14px;border-bottom:1px solid var(--line)}
.side-title{flex:1;min-width:0}
.side-title .name{font-weight:600}
.side-title .mono{font-size:11px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.avatar-btn{padding:0;border-radius:50%}
.icon{width:38px;height:38px;border-radius:10px;display:inline-flex;align-items:center;
  justify-content:center;font-size:18px;color:var(--muted)}
.icon:hover{background:var(--accent-2);color:var(--accent)}
.icon.send{color:var(--accent)}
.search-wrap{padding:10px 12px;position:relative}
.dropdown{position:absolute;left:12px;right:12px;top:48px;z-index:30;background:var(--panel);
  border:1px solid var(--line);border-radius:12px;box-shadow:0 8px 30px rgba(0,0,0,.2);
  max-height:340px;overflow:auto;padding:4px}
.dropdown .dhead{font-size:11px;color:var(--muted);padding:6px 10px 2px;text-transform:uppercase;letter-spacing:.04em}
.dropdown .note{padding:10px}
.chat-list{flex:1;overflow-y:auto}

/* chat list rows */
.row-chat{display:flex;gap:11px;align-items:center;padding:9px 12px;cursor:pointer;border-radius:12px;margin:2px 8px}
.row-chat:hover{background:var(--accent-2)}
.row-chat.active{background:var(--accent-2)}
.row-chat .body{flex:1;min-width:0}
.row-chat .top{display:flex;justify-content:space-between;gap:8px}
.row-chat .rname{font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.row-chat .time{font-size:11px;color:var(--muted);flex:none}
.row-chat .prev{color:var(--muted);font-size:13px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.badge{background:var(--badge);color:#fff;border-radius:11px;min-width:20px;height:20px;
  padding:0 6px;font-size:12px;display:inline-flex;align-items:center;justify-content:center;font-weight:600}

/* avatars */
.avatar{width:42px;height:42px;border-radius:50%;flex:none;display:inline-flex;
  align-items:center;justify-content:center;color:#fff;font-weight:600;font-size:16px;
  background:linear-gradient(135deg,#5b8def,#7c5cf6);overflow:hidden;background-size:cover;background-position:center}
.avatar.big{width:96px;height:96px;font-size:34px}
.avatar img{width:100%;height:100%;object-fit:cover}

/* conversation */
#chat-pane{min-width:0;display:flex;flex-direction:column;background:var(--bg)}
.empty{flex:1;display:flex;align-items:center;justify-content:center;text-align:center}
.conv{display:flex;flex-direction:column;height:100%;min-height:0}
.conv-head{display:flex;align-items:center;gap:8px;padding:9px 12px;background:var(--panel);border-bottom:1px solid var(--line)}
.peer{display:flex;align-items:center;gap:11px;flex:1;min-width:0;text-align:left}
.peer .avatar{width:40px;height:40px}
.peer-txt{min-width:0;display:flex;flex-direction:column}
.peer-txt .name{font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.peer-txt .muted{font-size:12px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.log{flex:1;overflow-y:auto;padding:14px min(6%,60px);display:flex;flex-direction:column;gap:2px}
.daysep{align-self:center;background:var(--panel);border:1px solid var(--line);color:var(--muted);
  font-size:12px;padding:2px 12px;border-radius:12px;margin:10px 0}

/* message bubbles */
.msg{display:flex;max-width:76%;margin-top:2px}
.msg.mine{align-self:flex-end;flex-direction:row-reverse}
.msg.grouped{margin-top:1px}
.msg .m-av{width:28px;height:28px;border-radius:50%;flex:none;align-self:flex-end;margin:0 8px 2px 0;
  background:linear-gradient(135deg,#5b8def,#7c5cf6);font-size:12px}
.msg.mine .m-av{display:none}
.msg.grouped .m-av{visibility:hidden}
.bubble{background:var(--theirs);border:1px solid var(--line);border-radius:16px;
  padding:7px 11px;box-shadow:var(--shadow);position:relative;min-width:44px;word-wrap:break-word;overflow-wrap:anywhere}
.msg.mine .bubble{background:var(--mine);border-color:transparent}
.bubble .who{font-size:12px;font-weight:600;color:var(--accent);margin-bottom:2px}
.bubble .txt{white-space:pre-wrap}
.bubble .meta{float:right;margin:4px 0 -2px 10px;font-size:11px;color:var(--muted);display:inline-flex;gap:4px;align-items:center}
.bubble .tick{color:var(--tick)}
.bubble.deleted .txt{font-style:italic;color:var(--muted)}
.bubble .edited{font-size:10px;color:var(--muted)}
.bubble img.media{max-width:min(320px,60vw);border-radius:10px;display:block;cursor:pointer;margin:2px 0}
.file-card{display:flex;align-items:center;gap:10px;text-decoration:none;color:inherit;padding:4px 2px}
.file-card .fi{width:40px;height:40px;border-radius:10px;background:var(--accent);color:#fff;
  display:flex;align-items:center;justify-content:center;font-size:18px;flex:none}
.file-card .fmeta{min-width:0}
.file-card .fn{font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:200px}
.quote{border-left:3px solid var(--accent);padding:2px 8px;margin-bottom:4px;background:rgba(58,122,254,.08);
  border-radius:6px;font-size:13px;cursor:pointer}
.quote .qn{color:var(--accent);font-weight:600;display:block;font-size:12px}
.quote .qt{color:var(--muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;display:block}
.reacts{display:flex;gap:4px;flex-wrap:wrap;margin-top:4px}
.react{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:0 7px;
  font-size:13px;line-height:22px;cursor:pointer}
.react.me{border-color:var(--accent);background:var(--accent-2)}

/* reply bar + composer */
.reply-bar{display:flex;align-items:center;gap:8px;padding:8px 12px;background:var(--panel);border-top:1px solid var(--line)}
.reply-info{flex:1;min-width:0;border-left:3px solid var(--accent);padding-left:8px}
.reply-name{color:var(--accent);font-weight:600;font-size:12px;display:block}
.composer{display:flex;align-items:flex-end;gap:6px;padding:10px 12px;background:var(--panel);border-top:1px solid var(--line)}
.composer textarea{max-height:140px;border-radius:20px;padding:9px 14px}

/* modals / menus */
.modal{position:fixed;inset:0;background:rgba(10,15,25,.45);display:flex;align-items:center;justify-content:center;z-index:40;padding:16px}
.sheet{background:var(--panel);border:1px solid var(--line);border-radius:16px;width:420px;max-width:100%;
  max-height:90vh;overflow:auto;box-shadow:0 10px 40px rgba(0,0,0,.3)}
.sheet-head{display:flex;align-items:center;justify-content:space-between;padding:14px 16px;border-bottom:1px solid var(--line)}
.sheet-body{padding:16px;display:flex;flex-direction:column;gap:12px}
.fld{display:flex;flex-direction:column;gap:6px;font-size:13px;color:var(--muted)}
.fld input,.fld textarea{color:var(--text)}
.row{display:flex;gap:8px}
.row input{flex:1}
.row button,#nc-add,#grp-create,.primary,#save-prof{background:var(--accent);color:#fff;border-radius:10px;padding:9px 14px;font-weight:600}
.primary{width:100%}
.prof-av-wrap{display:flex;flex-direction:column;align-items:center;gap:8px}
.seg{display:flex;background:var(--bg);border-radius:10px;padding:3px}
.seg-b{flex:1;padding:7px;border-radius:8px;color:var(--muted);font-weight:600}
.seg-b.active{background:var(--panel);color:var(--text);box-shadow:var(--shadow)}
.results{display:flex;flex-direction:column;gap:2px;max-height:280px;overflow:auto}
.res{display:flex;align-items:center;gap:10px;padding:8px;border-radius:10px;cursor:pointer}
.res:hover{background:var(--accent-2)}
.res .avatar{width:36px;height:36px;font-size:14px}
.res .rn{flex:1;min-width:0}
.res .rn .p{font-weight:600}
.res .rn .i{font-size:11px;color:var(--muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.res .pick{width:20px;height:20px;border:2px solid var(--line);border-radius:6px}
.res.sel .pick{background:var(--accent);border-color:var(--accent)}
.ctx{position:fixed;background:var(--panel);border:1px solid var(--line);border-radius:12px;
  box-shadow:0 8px 30px rgba(0,0,0,.25);z-index:50;overflow:hidden;min-width:170px}
.ctx button{display:block;width:100%;text-align:left;padding:10px 14px;font-size:14px}
.ctx button:hover{background:var(--accent-2)}
.ctx button.danger{color:var(--danger)}
.emoji-pop{position:fixed;background:var(--panel);border:1px solid var(--line);border-radius:14px;
  box-shadow:0 8px 30px rgba(0,0,0,.25);z-index:50;padding:8px;display:flex;gap:4px;flex-wrap:wrap;max-width:250px}
.emoji-pop button{font-size:22px;width:38px;height:38px;border-radius:10px}
.emoji-pop button:hover{background:var(--accent-2)}
.viewer{position:fixed;inset:0;background:rgba(0,0,0,.9);display:flex;align-items:center;justify-content:center;z-index:60}
.viewer img{max-width:92vw;max-height:92vh;border-radius:8px}
.only-mobile{display:none}

/* responsive */
@media (max-width:760px){
  .app{grid-template-columns:1fr}
  #chat-pane{display:none}
  .app.show-conv #sidebar{display:none}
  .app.show-conv #chat-pane{display:flex}
  .only-mobile{display:inline-flex}
  .msg{max-width:86%}
}
"""

CHAT_JS = r"""
"use strict";
let TOKEN=null, VER=0, sel=null, timer=null;
let ST={me:null,pseudo:"",bio:"",has_avatar:false,contacts:[],known:[],groups:[]};
let UNREAD={}, TYPING={}, replyTo=null, ncSel={};
const MSGS={};            // conv -> {id -> record}
const REACTS=["👍","❤️","😂","😮","😢","🔥","🎉","👏"];
const $=(id)=>document.getElementById(id);
const esc=(s)=>String(s==null?"":s).replace(/[&<>"]/g,(c)=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
const short=(h)=>h?h.slice(0,8)+"…"+h.slice(-4):"";
const initials=(s)=>{s=(s||"").trim();return s?s.slice(0,2).toUpperCase():"?";};

async function api(path,method="GET",body){
  const h={}; if(TOKEN)h["Authorization"]="Bearer "+TOKEN; if(body)h["Content-Type"]="application/json";
  const r=await fetch(path,{method,headers:h,body:body?JSON.stringify(body):undefined});
  if(r.status===401){logout();throw new Error("unauth");}
  return r;
}
function logout(){TOKEN=null;try{sessionStorage.removeItem("nmesh_token");}catch(_){}
  if(timer){clearInterval(timer);timer=null;}$("app").classList.add("hidden");$("login").classList.remove("hidden");}

// ---- identity / naming ----
function hasAvatar(id){
  if(id===ST.me||id==="self")return ST.has_avatar;
  const r=findPerson(id); return !!(r&&r.has_avatar);
}
function findPerson(id){return ST.contacts.find(c=>c.id===id)||ST.known.find(c=>c.id===id)||null;}
function personName(id){
  if(id===ST.me)return ST.pseudo||"You";
  const r=findPerson(id); return (r&&r.pseudo)||short(id);
}
function convIsGroup(conv){return conv&&conv.startsWith("g:");}
function convName(conv){
  if(convIsGroup(conv)){const g=ST.groups.find(x=>"g:"+x.id===conv);return g?g.name:"Group";}
  return personName(conv);
}
function convAvatarId(conv){return convIsGroup(conv)?null:conv;}
function avatarHTML(id,name,cls){
  const c="avatar"+(cls?" "+cls:"");
  if(id&&hasAvatar(id))
    return '<span class="'+c+'"><img alt="" src="/api/chat/avatar?id='+encodeURIComponent(id)+'&v='+VER+'"></span>';
  return '<span class="'+c+'">'+esc(initials(name))+'</span>';
}

// ---- polling ----
async function poll(){
  let j; try{ j=await(await api("/api/chat/messages?since="+VER)).json(); }catch(_){return;}
  ST.me=j.me; ST.pseudo=j.pseudo||""; ST.bio=j.bio||""; ST.has_avatar=!!j.has_avatar;
  ST.contacts=j.contacts||[]; ST.known=j.known||[]; ST.groups=j.groups||[];
  UNREAD=j.unread||{}; TYPING=j.typing||{};
  let touchedActive=false;
  for(const m of (j.messages||[])){ (MSGS[m.conv]=MSGS[m.conv]||{})[m.id]=m; if(m.conv===sel)touchedActive=true; }
  if(typeof j.version==="number")VER=j.version;
  renderList();
  if(sel){ renderHead(); if(touchedActive)renderLog(); }
}

// ---- chat list ----
function lastMsg(conv){const m=MSGS[conv];if(!m)return null;let best=null;for(const k in m){if(!best||m[k].id>best.id)best=m[k];}return best;}
function preview(m){
  if(!m)return "";
  if(m.deleted)return "deleted message";
  if(m.kind==="image")return "🖼 Photo";
  if(m.kind==="file")return "📎 "+(m.name||"File");
  return m.text||"";
}
function fmtTime(t){if(!t)return "";const d=new Date(t*1000);return d.toLocaleTimeString([],{hour:"2-digit",minute:"2-digit"});}
function convList(){
  const seen=new Set(), out=[];
  for(const conv in MSGS){const m=lastMsg(conv);if(m)out.push({conv,m,t:m.t||0});seen.add(conv);}
  for(const g of ST.groups){const c="g:"+g.id;if(!seen.has(c)){out.push({conv:c,m:null,t:0});seen.add(c);}}
  for(const c of ST.contacts){if(!seen.has(c.id)){out.push({conv:c.id,m:null,t:0});seen.add(c.id);}}
  out.sort((a,b)=>b.t-a.t);
  return out;
}
function renderList(){
  const q=($("side-search").value||"").trim().toLowerCase();
  const el=$("chat-list"); el.innerHTML="";
  $("me-name").textContent=ST.pseudo||"Set your name";
  $("me-sub").textContent=ST.me?short(ST.me):"";
  $("me-av").outerHTML='<span id="me-av">'+avatarHTML(ST.me,ST.pseudo)+'</span>';
  for(const it of convList()){
    const name=convName(it.conv);
    if(q&&!name.toLowerCase().includes(q))continue;
    const row=document.createElement("div"); row.className="row-chat"+(it.conv===sel?" active":"");
    row.dataset.conv=it.conv;
    const typing=TYPING[it.conv];
    const prev=typing?"<i>typing…</i>":esc(preview(it.m));
    const un=UNREAD[it.conv]||0;
    row.innerHTML=avatarHTML(convAvatarId(it.conv),name)+
      '<div class="body"><div class="top"><span class="rname">'+esc(name)+'</span>'+
      '<span class="time">'+(it.m?fmtTime(it.m.t):"")+'</span></div>'+
      '<div class="top"><span class="prev">'+prev+'</span>'+
      (un?'<span class="badge">'+un+'</span>':'')+'</div></div>';
    el.appendChild(row);
  }
}

// ---- conversation ----
function openConv(conv){
  sel=conv; replyTo=null; setReplyBar();
  $("empty").classList.add("hidden"); $("conv").classList.remove("hidden");
  $("app").classList.add("show-conv");
  renderHead(); renderLog(true); markRead();
  renderList();
}
function markRead(){ if(sel){api("/api/chat/read","POST",{conv:sel}).catch(()=>{}); UNREAD[sel]=0;} }
function renderHead(){
  const name=convName(sel);
  $("conv-av").outerHTML='<span id="conv-av">'+avatarHTML(convAvatarId(sel),name)+'</span>';
  $("conv-title").textContent=name;
  let sub="";
  if(TYPING[sel]){sub="typing…";}
  else if(convIsGroup(sel)){const g=ST.groups.find(x=>"g:"+x.id===sel);sub=g?(g.members.length+" members"):"";}
  else{const r=findPerson(sel);sub=r&&r.bio?r.bio:short(sel);}
  $("conv-sub").textContent=sub;
}
function sameDay(a,b){const x=new Date(a*1000),y=new Date(b*1000);return x.toDateString()===y.toDateString();}
function tickHTML(status){
  if(status==="read")return '<span class="tick">✓✓</span>';
  if(status==="delivered")return '<span>✓✓</span>';
  return '<span>✓</span>';
}
function renderLog(force){
  const log=$("log");
  const nearBottom=force||(log.scrollHeight-log.scrollTop-log.clientHeight<80);
  const store=MSGS[sel]||{};
  const list=Object.values(store).sort((a,b)=>a.id-b.id);
  log.innerHTML="";
  let prev=null;
  for(const m of list){
    if(!prev||!sameDay(prev.t,m.t)){
      const d=document.createElement("div");d.className="daysep";
      d.textContent=new Date(m.t*1000).toLocaleDateString([],{month:"short",day:"numeric"});
      log.appendChild(d);
    }
    log.appendChild(msgEl(m,prev));
    prev=m;
  }
  if(nearBottom)log.scrollTop=log.scrollHeight;
}
function msgEl(m,prev){
  const mine=m.src==="me";
  const grouped=prev&&prev.src===m.src&&!prev._sep&&sameDay(prev.t,m.t);
  const wrap=document.createElement("div");
  wrap.className="msg"+(mine?" mine":"")+(grouped?" grouped":"");
  wrap.dataset.mid=m.mid||""; wrap.dataset.id=m.id;
  let inner="";
  if(!mine)inner+=avatarHTML(m.src,personName(m.src)).replace('class="avatar"','class="avatar m-av"');
  let body='<div class="bubble'+(m.deleted?" deleted":"")+'">';
  if(!mine&&convIsGroup(sel)&&!grouped)body+='<div class="who">'+esc(personName(m.src))+'</div>';
  if(m.reply){const q=(MSGS[sel]||{});let qr=null;for(const k in q)if(q[k].mid===m.reply)qr=q[k];
    if(qr)body+='<div class="quote" data-goto="'+qr.id+'"><span class="qn">'+esc(qr.src==="me"?"You":personName(qr.src))+
      '</span><span class="qt">'+esc(preview(qr))+'</span></div>';}
  if(m.deleted){body+='<div class="txt">deleted message</div>';}
  else if(m.kind==="image"){body+='<img class="media" alt="'+esc(m.name||"")+'" src="/api/chat/file?mid='+m.mid+'">';
    if(m.text)body+='<div class="txt">'+esc(m.text)+'</div>';}
  else if(m.kind==="file"){body+='<a class="file-card" href="/api/chat/file?mid='+m.mid+'" download="'+esc(m.name||"file")+'">'+
    '<span class="fi">📄</span><span class="fmeta"><span class="fn">'+esc(m.name||"file")+'</span>'+
    '<span class="muted">'+fmtSize(m.size)+'</span></span></a>';}
  else{body+='<div class="txt">'+linkify(m.text)+'</div>';}
  body+='<span class="meta">'+(m.edited&&!m.deleted?'<span class="edited">edited</span>':'')+
    fmtTime(m.t)+(mine&&!m.deleted?tickHTML(m.status):'')+'</span>';
  body+=reactsHTML(m);
  body+='</div>';
  inner+=body;
  wrap.innerHTML=inner;
  return wrap;
}
function reactsHTML(m){
  const r=m.reactions||{}; const keys=Object.keys(r); if(!keys.length)return "";
  let h='<div class="reacts">';
  for(const e of keys){const arr=r[e]||[];const meIn=arr.includes(ST.me);
    h+='<span class="react'+(meIn?" me":"")+'" data-react="'+esc(e)+'" data-mid="'+m.mid+'">'+esc(e)+' '+arr.length+'</span>';}
  return h+'</div>';
}
function fmtSize(n){if(n==null)return"";const u=["B","KB","MB","GB"];let i=0;while(n>=1024&&i<3){n/=1024;i++;}return n.toFixed(i?1:0)+" "+u[i];}
function linkify(t){t=esc(t);return t.replace(/(https?:\/\/[^\s]+)/g,'<a href="$1" target="_blank" rel="noreferrer noopener">$1</a>');}

// ---- sending ----
async function sendText(){
  const ta=$("msg"); const text=ta.value.trim(); if(!text||!sel)return;
  ta.value=""; autoGrow(); const reply=replyTo; replyTo=null; setReplyBar();
  await api("/api/chat/send","POST",{conv:sel,text,reply}).catch(()=>{});
  poll();
}
async function sendFile(file){
  if(!file||!sel)return;
  const b64=await toB64(file);
  await api("/api/chat/file","POST",{conv:sel,name:file.name,data:b64,reply:replyTo}).catch(()=>{});
  replyTo=null; setReplyBar(); poll();
}
function toB64(file){return new Promise((res,rej)=>{const r=new FileReader();
  r.onload=()=>res((r.result+"").split(",")[1]||"");r.onerror=rej;r.readAsDataURL(file);});}
let typingSent=0, typingStop=null;
function onTyping(){
  if(!sel)return; const now=Date.now();
  if(now-typingSent>3000){typingSent=now;api("/api/chat/typing","POST",{conv:sel,active:true}).catch(()=>{});}
  clearTimeout(typingStop);
  typingStop=setTimeout(()=>{typingSent=0;api("/api/chat/typing","POST",{conv:sel,active:false}).catch(()=>{});},3500);
}
function autoGrow(){const t=$("msg");t.style.height="auto";t.style.height=Math.min(t.scrollHeight,140)+"px";}

// ---- reply / context menu / reactions ----
function setReplyBar(){
  const bar=$("reply-bar"); if(!replyTo){bar.classList.add("hidden");return;}
  const q=MSGS[sel]||{};let r=null;for(const k in q)if(q[k].mid===replyTo)r=q[k];
  if(!r){replyTo=null;bar.classList.add("hidden");return;}
  $("reply-who").textContent=r.src==="me"?"You":personName(r.src);
  $("reply-text").textContent=preview(r); bar.classList.remove("hidden"); $("msg").focus();
}
function openCtx(x,y,mid){
  const m=(MSGS[sel]||{});let rec=null;for(const k in m)if(m[k].mid===mid)rec=m[k];
  if(!rec||rec.deleted)return;
  const mine=rec.src==="me";
  const ctx=$("ctx");
  ctx.innerHTML='<button data-a="reply">Reply</button><button data-a="react">React</button>'+
    (rec.kind==="text"?'<button data-a="copy">Copy</button>':'')+
    (mine&&rec.kind==="text"?'<button data-a="edit">Edit</button>':'')+
    (mine?'<button data-a="delete" class="danger">Delete</button>':'');
  ctx.dataset.mid=mid; ctx.classList.remove("hidden");
  const w=ctx.offsetWidth||180,h=ctx.offsetHeight||160;
  ctx.style.left=Math.min(x,innerWidth-w-8)+"px"; ctx.style.top=Math.min(y,innerHeight-h-8)+"px";
}
function closeCtx(){$("ctx").classList.add("hidden");$("emoji-pop").classList.add("hidden");}
function ctxAction(a){
  const mid=$("ctx").dataset.mid; const m=(MSGS[sel]||{});let rec=null;for(const k in m)if(m[k].mid===mid)rec=m[k];
  closeCtx(); if(!rec)return;
  if(a==="reply"){replyTo=mid;setReplyBar();}
  else if(a==="copy"){navigator.clipboard&&navigator.clipboard.writeText(rec.text||"");}
  else if(a==="edit"){const t=prompt("Edit message",rec.text||"");if(t!=null&&t.trim())api("/api/chat/edit","POST",{conv:sel,mid,text:t.trim()}).then(poll);}
  else if(a==="delete"){if(confirm("Delete this message for everyone?"))api("/api/chat/delete","POST",{conv:sel,mid}).then(poll);}
  else if(a==="react"){openEmoji(mid);}
}
function openEmoji(mid){
  const pop=$("emoji-pop"); pop.innerHTML=REACTS.map(e=>'<button data-e="'+e+'" data-mid="'+mid+'">'+e+'</button>').join("");
  pop.classList.remove("hidden");
  const r=$("ctx").getBoundingClientRect();
  pop.style.left=Math.min(r.left,innerWidth-260)+"px"; pop.style.top=Math.max(8,r.top-56)+"px";
}
function react(mid,emoji){api("/api/chat/react","POST",{conv:sel,mid,emoji}).then(poll).catch(()=>{});}

// ---- profile ----
function openSettings(){
  $("set-name").value=ST.pseudo||""; $("set-bio").value=ST.bio||"";
  $("set-id").textContent=ST.me||"";
  $("set-av").outerHTML='<span id="set-av" class="avatar big">'+
    (ST.has_avatar?'<img alt="" src="/api/chat/avatar?id=self&v='+VER+'">':esc(initials(ST.pseudo)))+'</span>';
  pendingAvatar=undefined; $("settings").classList.remove("hidden");
}
let pendingAvatar=undefined;   // undefined=unchanged, ""=clear, string=new b64
async function pickAvatar(file){
  const b64=await resizeImage(file,256);
  pendingAvatar=b64;
  $("set-av").innerHTML='<img alt="" src="data:image/jpeg;base64,'+b64+'">';
}
function resizeImage(file,size){return new Promise((res,rej)=>{
  const img=new Image(); const url=URL.createObjectURL(file);
  img.onload=()=>{const s=Math.min(img.width,img.height);const c=document.createElement("canvas");
    c.width=c.height=size;const g=c.getContext("2d");
    g.drawImage(img,(img.width-s)/2,(img.height-s)/2,s,s,0,0,size,size);
    URL.revokeObjectURL(url); res(c.toDataURL("image/jpeg",0.85).split(",")[1]);};
  img.onerror=rej; img.src=url;});
}
async function saveProfile(){
  const body={pseudo:$("set-name").value.trim(),bio:$("set-bio").value};
  if(pendingAvatar!==undefined)body.avatar=pendingAvatar;
  await api("/api/chat/profile","POST",body).catch(()=>{});
  $("settings").classList.add("hidden"); poll();
}

// ---- new chat / search / groups ----
let ncMode="dm";
function openNew(){ncMode="dm";ncSel={};$("nc-search").value="";$("nc-results").innerHTML="";
  $("grp-name").value="";$("nc-id").value="";switchNc("dm");$("newchat").classList.remove("hidden");}
function switchNc(m){ncMode=m;
  $("nc-tab-dm").classList.toggle("active",m==="dm");$("nc-tab-grp").classList.toggle("active",m==="grp");
  $("nc-dm").classList.toggle("hidden",m!=="dm");$("nc-grp").classList.toggle("hidden",m!=="grp");
  if(m==="grp")renderGroupPicker();}
async function doSearch(q){
  if(!q||!q.trim()){$("nc-results").innerHTML="";return;}
  let hits=[]; try{hits=(await(await api("/api/chat/search","POST",{pseudo:q.trim()})).json()).results||[];}catch(_){}
  const el=$("nc-results"); el.innerHTML="";
  for(const r of hits){el.appendChild(personRow(r.id,r.pseudo||short(r.id),()=>{startChat(r.id);}));}
  if(!hits.length)el.innerHTML='<div class="note muted">No one found.</div>';
}
function personRow(id,name,onClick){
  const d=document.createElement("div");d.className="res";
  d.innerHTML=avatarHTML(id,name)+'<div class="rn"><div class="p">'+esc(name)+'</div><div class="i mono">'+esc(id)+'</div></div>';
  d.addEventListener("click",onClick); return d;
}
async function startChat(id){
  await api("/api/chat/contact","POST",{op:"add",id}).catch(()=>{});
  $("newchat").classList.add("hidden"); await poll(); openConv(id);
}
function resRow(avId,name,sub,onClick){
  const d=document.createElement("div");d.className="res";
  d.innerHTML=avatarHTML(avId,name)+'<div class="rn"><div class="p">'+esc(name)+'</div>'+
    (sub?'<div class="i mono">'+esc(sub)+'</div>':'')+'</div>';
  d.addEventListener("click",onClick);return d;
}
// Sidebar search: filters the chat list AND shows a dropdown of matching chats
// and people (local directory + network DHT). Pseudos aren't unique, so several
// hits can appear — the dropdown lets you pick the right node id.
let sideT=null;
function sideSearch(){
  renderList();
  const q=($("side-search").value||"").trim();
  const dd=$("side-results");
  if(!q){dd.classList.add("hidden");dd.innerHTML="";return;}
  const ql=q.toLowerCase();
  const chats=convList().filter(it=>convName(it.conv).toLowerCase().includes(ql));
  dd.innerHTML="";
  if(chats.length){
    const h=document.createElement("div");h.className="dhead";h.textContent="Chats";dd.appendChild(h);
    for(const it of chats.slice(0,8))
      dd.appendChild(resRow(convAvatarId(it.conv),convName(it.conv),
        convIsGroup(it.conv)?"group":short(it.conv),()=>{closeSide();openConv(it.conv);}));
  }
  const loading=document.createElement("div");loading.className="dhead";loading.textContent="People";dd.appendChild(loading);
  const wait=document.createElement("div");wait.className="note muted";wait.textContent="Searching…";dd.appendChild(wait);
  dd.classList.remove("hidden");
  clearTimeout(sideT);
  sideT=setTimeout(async()=>{
    if(($("side-search").value||"").trim()!==q)return;   // stale
    let hits=[]; try{hits=(await(await api("/api/chat/search","POST",{pseudo:q})).json()).results||[];}catch(_){}
    hits=hits.filter(x=>!chats.some(c=>c.conv===x.id));
    wait.remove();
    if(hits.length){for(const r of hits)
      dd.appendChild(resRow(r.id,r.pseudo||short(r.id),short(r.id),()=>{closeSide();startChat(r.id);}));}
    else{const n=document.createElement("div");n.className="note muted";n.textContent="No people found.";dd.appendChild(n);}
  },320);
}
function closeSide(){$("side-results").classList.add("hidden");$("side-search").value="";renderList();}
function renderGroupPicker(){
  const el=$("grp-members");el.innerHTML="";
  const people=[...ST.contacts,...ST.known];
  const seen=new Set();
  for(const p of people){if(seen.has(p.id))continue;seen.add(p.id);
    const row=personRow(p.id,p.pseudo||short(p.id),null);
    row.classList.toggle("sel",!!ncSel[p.id]);
    const pick=document.createElement("span");pick.className="pick";row.appendChild(pick);
    row.addEventListener("click",()=>{ncSel[p.id]=!ncSel[p.id];row.classList.toggle("sel",ncSel[p.id]);});
    el.appendChild(row);}
  if(!people.length)el.innerHTML='<div class="note muted">Add contacts first.</div>';
}
async function createGroup(){
  const name=$("grp-name").value.trim();const members=Object.keys(ncSel).filter(k=>ncSel[k]);
  if(!name||!members.length)return;
  const j=await(await api("/api/chat/group","POST",{op:"create",name,members})).json().catch(()=>({}));
  $("newchat").classList.add("hidden"); await poll(); if(j.id)openConv("g:"+j.id);
}

// ---- events ----
function bind(){
  $("side-search").addEventListener("input",sideSearch);
  $("side-search").addEventListener("focus",sideSearch);
  document.addEventListener("click",(e)=>{if(!e.target.closest(".search-wrap"))$("side-results").classList.add("hidden");});
  $("me-btn").addEventListener("click",openSettings);
  $("new-btn").addEventListener("click",openNew);
  $("back-btn").addEventListener("click",()=>{sel=null;$("app").classList.remove("show-conv");$("conv").classList.add("hidden");$("empty").classList.remove("hidden");renderList();});
  $("del-conv").addEventListener("click",()=>{if(!sel)return;
    if(convIsGroup(sel)){if(confirm("Leave and delete this group?"))api("/api/chat/group","POST",{op:"remove",id:sel.slice(2)}).then(()=>{delete MSGS[sel];sel=null;$("conv").classList.add("hidden");$("empty").classList.remove("hidden");poll();});}
    else{if(confirm("Remove this contact?"))api("/api/chat/contact","POST",{op:"remove",id:sel}).then(()=>{delete MSGS[sel];sel=null;$("conv").classList.add("hidden");$("empty").classList.remove("hidden");poll();});}});
  $("info-btn").addEventListener("click",()=>{ if(sel&&!convIsGroup(sel)){/* future: peer profile */ } });
  $("chat-list").addEventListener("click",(e)=>{const r=e.target.closest(".row-chat");if(r)openConv(r.dataset.conv);});
  $("send-form").addEventListener("submit",(e)=>{e.preventDefault();sendText();});
  $("msg").addEventListener("input",()=>{autoGrow();onTyping();});
  $("msg").addEventListener("keydown",(e)=>{if(e.key==="Enter"&&!e.shiftKey){e.preventDefault();sendText();}});
  $("attach-btn").addEventListener("click",()=>$("file-input").click());
  $("file-input").addEventListener("change",(e)=>{if(e.target.files[0])sendFile(e.target.files[0]);e.target.value="";});
  $("emoji-btn").addEventListener("click",()=>{const t=$("msg");t.value+="🙂";t.focus();autoGrow();});
  $("reply-cancel").addEventListener("click",()=>{replyTo=null;setReplyBar();});
  $("log").addEventListener("click",(e)=>{
    const img=e.target.closest("img.media");if(img){$("viewer-img").src=img.src;$("viewer").classList.remove("hidden");return;}
    const q=e.target.closest(".quote");if(q){const t=$("log").querySelector('.msg[data-id="'+q.dataset.goto+'"]');if(t)t.scrollIntoView({block:"center"});return;}
    const rc=e.target.closest(".react");if(rc){react(rc.dataset.mid,rc.dataset.react);return;}});
  $("log").addEventListener("contextmenu",(e)=>{const b=e.target.closest(".msg");if(b&&b.dataset.mid){e.preventDefault();openCtx(e.clientX,e.clientY,b.dataset.mid);}});
  // long-press for touch
  let lp=null;
  $("log").addEventListener("touchstart",(e)=>{const b=e.target.closest(".msg");if(b&&b.dataset.mid){lp=setTimeout(()=>{const t=e.touches[0];openCtx(t.clientX,t.clientY,b.dataset.mid);},500);}},{passive:true});
  $("log").addEventListener("touchend",()=>clearTimeout(lp));
  $("ctx").addEventListener("click",(e)=>{const b=e.target.closest("button");if(b)ctxAction(b.dataset.a);});
  $("emoji-pop").addEventListener("click",(e)=>{const b=e.target.closest("button");if(b){react(b.dataset.mid,b.dataset.e);closeCtx();}});
  document.addEventListener("click",(e)=>{if(!e.target.closest(".ctx")&&!e.target.closest("#emoji-pop")&&!e.target.closest(".msg"))closeCtx();});
  $("viewer").addEventListener("click",()=>$("viewer").classList.add("hidden"));
  document.querySelectorAll("[data-close]").forEach(b=>b.addEventListener("click",()=>$(b.dataset.close).classList.add("hidden")));
  $("av-input").addEventListener("change",(e)=>{if(e.target.files[0])pickAvatar(e.target.files[0]);});
  $("av-clear").addEventListener("click",()=>{pendingAvatar="";$("set-av").innerHTML=esc(initials($("set-name").value));});
  $("save-prof").addEventListener("click",saveProfile);
  $("nc-tab-dm").addEventListener("click",()=>switchNc("dm"));
  $("nc-tab-grp").addEventListener("click",()=>switchNc("grp"));
  let st=null;
  $("nc-search").addEventListener("input",(e)=>{clearTimeout(st);const v=e.target.value;st=setTimeout(()=>doSearch(v),300);});
  $("nc-add").addEventListener("click",()=>{const id=$("nc-id").value.trim();if(/^[0-9a-fA-F]{40}$/.test(id))startChat(id.toLowerCase());});
  $("grp-create").addEventListener("click",createGroup);
}

// ---- auth / boot ----
async function enter(token){
  const h={}; if(token)h["Authorization"]="Bearer "+token;
  const r=await fetch("/api/chat/messages?since=0",{headers:h});
  if(!r.ok)return false;
  TOKEN=token||null; if(TOKEN){try{sessionStorage.setItem("nmesh_token",TOKEN);}catch(_){}}
  $("login").classList.add("hidden"); $("app").classList.remove("hidden");
  await poll(); if(timer)clearInterval(timer); timer=setInterval(poll,1200);
  return true;
}
$("login-form").addEventListener("submit",async(e)=>{
  e.preventDefault();$("err").textContent="";
  try{const res=await fetch("/api/login",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({password:$("password").value})});
    if(!res.ok){const j=await res.json().catch(()=>({}));$("err").textContent=j.error||"login failed";return;}
    $("password").value=""; await enter((await res.json()).token);
  }catch(_){$("err").textContent="network error";}
});
bind();
(function(){let tok=null;try{tok=sessionStorage.getItem("nmesh_token");}catch(_){}
  enter(tok).then((ok)=>{if(!ok)$("login").classList.remove("hidden");});})();
"""
