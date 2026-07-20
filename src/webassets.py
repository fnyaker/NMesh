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
.tctl{margin-bottom:12px}
.tctl #udp-port{width:90px;margin:0}
.unlisten{background:transparent;color:var(--muted);border:0;padding:0 4px;font-weight:400;cursor:pointer}
.unlisten:hover{color:var(--bad)}
details.expert-join{border-top:1px solid var(--line);padding-top:8px}
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
"""

APP_JS = r"""
let TOKEN = null;
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
  last = s;
  drawChart();
  drawGraph(s);
  drawPeers(s.peers);
  drawTransports(s);
  drawExpert(s);
  drawJoinProgress(s.join_status);
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
"""
