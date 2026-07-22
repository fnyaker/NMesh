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
      <input id="side-search" type="search" placeholder="Search chats and people…">
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
.search-wrap{padding:10px 12px}
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
  $("side-search").addEventListener("input",renderList);
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
