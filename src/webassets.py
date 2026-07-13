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
    <table id="peers"><thead><tr>
      <th>Node</th><th>Dir</th><th>Session</th><th>Bad</th><th>In</th><th>Out</th>
    </tr></thead><tbody></tbody></table>
  </section>

  <section class="card">
    <h2>Transports</h2>
    <div id="net-status" class="netrow"></div>
    <div id="transport-cards" class="tcards"></div>
    <div id="punch-block"></div>
  </section>

  <section class="card expert">
    <h2>Expert — addressing</h2>
    <div class="xrow"><span class="xk">Advertised URIs</span><ul id="x-advertised" class="mono"></ul></div>
    <div class="xrow"><span class="xk">Listening</span><ul id="x-listening" class="mono"></ul></div>
    <div class="xrow"><span class="xk">Local IPs</span><ul id="x-localips" class="mono"></ul></div>
  </section>

  <section class="card">
    <h2>Manage</h2>
    <div class="manage">
      <div class="mrow">
        <button id="gen-invite">Generate invite code</button>
        <code id="invite-out" class="mono"></code>
      </div>
      <div class="mrow">
        <button id="show-cert">Show our root certificate</button>
      </div>
      <textarea id="cert-out" class="mono" readonly placeholder="Our root cert (share it so another node trusts us)"></textarea>
      <div class="mrow join">
        <input id="join-uri" placeholder="tcp://host:port">
        <input id="join-code" placeholder="invite code">
        <button id="join-btn">Join network</button>
      </div>
      <textarea id="trust-in" class="mono" placeholder="Paste another node's root cert (hex) to trust it"></textarea>
      <div class="mrow"><button id="trust-btn">Trust certificate</button></div>
      <div id="manage-status" class="muted"></div>
    </div>
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
.tcards{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px}
.tcard{background:#0e1116;border:1px solid var(--line);border-radius:10px;padding:12px}
.tcard h3{margin:0 0 8px;font-size:13px;display:flex;align-items:center;gap:8px}
.tcard .kv{display:flex;justify-content:space-between;gap:8px;font-size:13px;padding:2px 0}
.tcard .kv .k{color:var(--muted)}
.tcard ul{margin:4px 0 0;padding:0;list-style:none;font-size:12px}
.tcard ul li{word-break:break-all}
#punch-block{margin-top:12px}
#punch-block h3{margin:0 0 8px;font-size:13px;color:var(--muted);
text-transform:uppercase;letter-spacing:.05em}
"""

APP_JS = r"""
let TOKEN = null;
let prev = null;      // previous {t, bytes_in, bytes_out}
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
    $("password").value = "";
    $("login").classList.add("hidden");
    $("app").classList.remove("hidden");
    tick();
    setInterval(tick, 1500);
  } catch (_) { $("login-error").textContent = "network error"; }
});

function logout() {
  if (TOKEN) api("/api/logout", "POST").catch(() => {});
  TOKEN = null;
  $("app").classList.add("hidden");
  $("login").classList.remove("hidden");
}
$("logout").addEventListener("click", logout);

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
  drawChart();
  drawGraph(s);
  drawPeers(s.peers);
  drawTransports(s);
  drawExpert(s);
}

function drawExpert(s) {
  const list = (id, arr) => {
    $(id).innerHTML = (arr && arr.length)
      ? arr.map((x) => `<li>${x}</li>`).join("")
      : '<li class="muted">—</li>';
  };
  list("x-advertised", s.advertised);
  list("x-listening", s.listening);
  list("x-localips", s.local_ips);
}

function fmtAge(a) {
  if (a == null) return "never";
  if (a < 60) return Math.round(a) + "s ago";
  return Math.round(a / 60) + "m ago";
}

function drawTransports(s) {
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
    $("punch-block").innerHTML =
      `<h3>UDP hole punching — port ${hp.udp_port ?? "—"} · ` +
      `${hp.stats.completed} ok / ${hp.stats.failed} failed / ${hp.stats.attempted} tried</h3>` +
      (rows
        ? `<table><thead><tr><th>Target</th><th>Remote</th><th>Probes s/r</th>
           <th>Ack</th><th>Expires</th></tr></thead><tbody>${rows}</tbody></table>`
        : '<div class="muted">no punch in progress</div>');
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
    return `<tr>
      <td class="mono">${short(p.authenticated_id)}</td>
      <td>${p.is_client_side ? "out" : "in"}</td>
      <td>${p.has_session ? "✓" : "—"}</td>
      <td>${p.malformed}</td>
      <td>${fmtBytes(c.bytes_in)}</td>
      <td>${fmtBytes(c.bytes_out)}</td>
    </tr>`;
  }).join("");
}

// management
function status(msg, ok = true) {
  const el = $("manage-status");
  el.textContent = msg; el.style.color = ok ? "" : "var(--bad)";
}
$("gen-invite").addEventListener("click", async () => {
  try { const j = await (await api("/api/invite", "POST")).json(); $("invite-out").textContent = j.code; }
  catch (_) { status("failed to generate invite", false); }
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
"""
