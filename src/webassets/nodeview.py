"""
One node, described once — in a dialog, on a page of its own, from anywhere.

The console had this view inside a `<dialog>` in its own page. That was fine
while the console was the only place anyone looked at a node. It is not: from a
conversation you want to know what the link to that person actually is, and from
the fleet you want to write to the machine you are managing. Three copies of the
same view, drifting apart, was the alternative.

So the view lives here, once, and two things mount it:

* the console's node dialog, over the state it already polls;
* ``/node#<id>``, a page of its own that chat and fleet open — in a panel, a
  window or a tab, whichever the operator chose.

What it *offers* is not decided here either. It asks the app API what is running
(:mod:`src.app_api`) and draws the buttons those apps make possible: chat says
whether it knows this identity, fleet says how the two nodes stand. An app that
is not installed contributes nothing and no button is drawn — rather than a
button that fails when pressed.

The page is a page like the others: the markup is public, every call it makes
carries the console session. Nothing here decides who may do what; it asks, and
the app answers with the same rules it always applies.
"""

# ---------------------------------------------------------------------------
# Styles
# ---------------------------------------------------------------------------
# Only what is this view's own. Everything else — cards, stats, tables,
# disclosures — comes from the design system, which is the whole point.

CSS = """
.nodeview{display:flex;flex-direction:column;gap:var(--s-4);min-width:0}
.nv-head{display:flex;align-items:center;gap:var(--s-3);min-width:0}
.nv-mark{width:44px;height:44px;flex:none;border-radius:14px;display:grid;
  place-items:center;background:var(--accent-soft);color:var(--accent);
  font:700 var(--fs-md)/1 var(--mono);letter-spacing:.02em}
.nv-head .nv-title{font-size:var(--fs-xl);font-weight:640;letter-spacing:-.02em;
  overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.nv-head .nv-sub{display:flex;flex-wrap:wrap;gap:var(--s-2);margin-top:3px}
.nv-actions{gap:var(--s-2)}
/* The full identity is 40 characters nobody reads and everybody copies. */
.nv-id code{font-size:var(--fs-xs)}
.nv-caps{display:flex;flex-wrap:wrap;gap:var(--s-1)}
.nv-pick{display:grid;gap:var(--s-2);grid-template-columns:repeat(auto-fit,minmax(min(200px,100%),1fr))}
/* Sections that answer "and what about…" rather than "what is this": folded,
   because an address table nobody asked for is the reason the old dialog
   needed scrolling before it said anything. */
.nodeview details.card>summary{padding:var(--s-3) var(--s-4);font-size:var(--fs-sm)}
.nodeview details.card>.card-body{padding:var(--s-4)}
.nodeview details.card>summary .tail{margin-left:auto;color:var(--text-muted);
  font-weight:500;font-size:var(--fs-xs)}
"""


# ---------------------------------------------------------------------------
# The view
# ---------------------------------------------------------------------------
# Loaded by both mounts. `NODEVIEW.mount(container, id, options)` is the whole
# public surface; everything below it is private to this file.

JS = r"""
// ── one node, described ─────────────────────────────────────────────────────
const ADDRESS_TONE = {"in-use":"ok", connected:"ok", timeout:"warn",
                      refused:"danger", "no-answer":"warn", untried:"",
                      invalid:"danger", "no transport":"danger", "peer limit":"warn"};

const NODEVIEW = {
  // What the app API says is reachable right now, read once per mount.
  apps: {},

  async catalogue(){
    try{
      const {data} = await apiJson("/api/app-api");
      const out = {};
      (data.apps || []).forEach((entry) => { out[entry.app] = entry.operations; });
      this.apps = out;
    }catch(_){ this.apps = {}; }
    return this.apps;
  },

  has(app, op){
    return (this.apps[app] || []).some((entry) => entry.name === op);
  },

  async call(app, op, args){
    const {ok, data} = await apiJson("/api/app-call", "POST", {app, op, args});
    if(!ok || !data.ok) throw new Error((data && data.error) || "refused");
    return data.result || {};
  },

  // -- gathering ------------------------------------------------------------
  // Everything the view needs, from the endpoints that already exist. A node
  // this console has never heard of still renders: the identity is real, the
  // rest is simply empty.
  async facts(id, selfId, seed){
    const scoped = async (scope) => {
      const params = new URLSearchParams({scope, q:id, limit:"20", offset:"0"});
      const response = await api("/api/nodes?" + params.toString());
      if(!response.ok) return null;
      return (await response.json()).items.find((item) => item.id === id) || null;
    };
    let known = null, active = null;
    if(id !== selfId)
      [known, active] = await Promise.all([scoped("known").catch(() => null),
                                           scoped("active").catch(() => null)]);
    const node = Object.assign({}, known || {}, active || {}, seed || {}, {id});
    node.self = node.self || id === selfId;
    node.direct = !!active;
    node.knownHere = !!known;
    return node;
  },

  async extras(id, self){
    const out = {chat:null, fleet:null};
    if(self) return out;
    const jobs = [];
    if(this.has("chat", "peer"))
      jobs.push(this.call("chat", "peer", {node:id})
                    .then((value) => { out.chat = value; }).catch(() => {}));
    if(this.has("fleet", "relation"))
      jobs.push(this.call("fleet", "relation", {node:id})
                    .then((value) => { out.fleet = value; }).catch(() => {}));
    await Promise.all(jobs);
    return out;
  },

  // -- drawing --------------------------------------------------------------
  render(node, extras, options){
    const hide = options.hide || [];
    const chat = extras.chat, fleet = extras.fleet;
    const name = (chat && chat.pseudo) || shortId(node.id);
    const badges = [];
    if(node.self) badges.push(badge("this node", "accent"));
    else if(node.direct) badges.push(badge("direct link", "ok"));
    else if(node.knownHere) badges.push(badge("known, not linked", ""));
    else badges.push(badge("routed session", "warn"));
    if(node.has_key === false) badges.push(badge("no identity key", "warn"));
    if(chat && chat.contact) badges.push(badge("contact", "accent"));
    if(fleet && fleet.managed) badges.push(badge("managed", "accent"));
    if(fleet && fleet.operator) badges.push(badge("controls this node", "warn"));

    return '<div class="nodeview">' +
      '<header class="nv-head"><span class="nv-mark" aria-hidden="true">' +
        esc(name.trim().slice(0, 2).toUpperCase()) + "</span>" +
        '<div class="grow"><div class="nv-title">' + esc(name) + "</div>" +
        '<div class="nv-sub">' + badges.join(" ") + "</div></div></header>" +
      '<div class="copyable nv-id"><code class="mono" data-nv-id>' + esc(node.id) +
        '</code><button class="sm" data-nv-act="copy">Copy</button></div>' +
      this.actionsHTML(node, extras, hide) +
      this.glanceHTML(node) +
      this.relationHTML(fleet, hide) +
      this.factsHTML(node) +
      this.foldHTML("Addresses", this.addressHTML(node), this.addressCount(node)) +
      this.foldHTML(((node.link || {}).scheme || "Transport") + " counters",
                    this.statsHTML(node.link), "") +
      '<p class="msg" data-nv-status role="status"></p>' +
      "</div>";
  },

  actionsHTML(node, extras, hide){
    if(node.self)
      return '<div class="btn-row nv-actions"><button data-nv-act="refresh">Refresh</button></div>';
    const chat = extras.chat, fleet = extras.fleet;
    const buttons = [];
    if(chat && hide.indexOf("chat") < 0)
      buttons.push('<button class="primary" data-nv-act="message">Message' +
        (chat.unread ? " " + badge(chat.unread, "danger") : "") + "</button>");
    if(chat && !chat.contact && hide.indexOf("chat") < 0)
      buttons.push('<button data-nv-act="contact">Add to contacts</button>');
    if(fleet && hide.indexOf("fleet") < 0){
      if(fleet.managed) buttons.push('<button data-nv-act="fleet">Open in Fleet</button>');
      else if(fleet.waiting_on_them)
        buttons.push('<button disabled>Access requested</button>');
      else buttons.push('<button data-nv-act="enrol">Request access</button>');
    }
    buttons.push('<button data-nv-act="ping">Ping</button>');
    buttons.push('<button data-nv-act="retry-all">Retry addresses</button>');
    buttons.push('<button class="danger" data-nv-act="forget">Forget</button>');
    return '<div class="btn-row nv-actions">' + buttons.join("") + "</div>";
  },

  // The four numbers that say whether this link is any good, before any of the
  // detail. One RTT cannot tell a steady link from a flapping one.
  glanceHTML(node){
    const link = node.link || {};
    const quality = link.quality || {};
    const counters = node.counters || {};
    if(!quality.probes && node.rtt_ms == null && !counters.bytes_in) return "";
    const loss = quality.loss == null ? null : Math.round(quality.loss * 100);
    const cell = (label, value, extra) =>
      '<div class="stat sm"><span class="v">' + value + '</span><span class="k">' +
      esc(label) + "</span>" + (extra || "") + "</div>";
    return '<div class="stats">' +
      cell("Round trip",
           quality.rtt_ms != null ? quality.rtt_ms + " ms"
             : (node.rtt_ms == null ? "—" : node.rtt_ms + " ms"),
           quality.samples_ms ? '<div class="' +
             ((loss != null && loss >= 10) ? "spark warn" : "") + '">' +
             sparkHTML(quality.samples_ms) + "</div>" : "") +
      cell("Jitter", quality.jitter_ms == null ? "—" : quality.jitter_ms + " ms") +
      cell("Probe loss", loss == null ? "—" : loss + "%") +
      cell("Traffic", counters.bytes_in == null ? "—"
           : fmtBytes((counters.bytes_in || 0) + (counters.bytes_out || 0))) +
      "</div>";
  },

  // Where the two nodes stand, in words rather than in a table: "managed" and
  // "controls this node" are independent and reading them apart is the whole
  // difficulty.
  relationHTML(fleet, hide){
    if(!fleet || hide.indexOf("fleet") >= 0) return "";
    const lines = [];
    if(fleet.managed)
      lines.push("<div>This node may <b>" + esc(fleet.caps.join(", ") || "do nothing") +
        "</b> on that one.</div>");
    if(fleet.operator)
      lines.push("<div>That node may <b>" +
        esc(fleet.operator_caps.join(", ") || "do nothing") +
        "</b> on this one.</div>");
    if(fleet.waiting_on_them)
      lines.push("<div>Waiting on someone there to allow <b>" +
        esc(fleet.asked_caps.join(", ")) + "</b>.</div>");
    if(fleet.waiting_on_us)
      lines.push("<div>Waiting on <b>you</b> to answer its request.</div>");
    if(!lines.length) return "";
    return '<div class="notice"><span>' + lines.join("") + "</span></div>";
  },

  factsHTML(node){
    const link = node.link || null;
    const rows = [
      ["Relationship", node.self ? "This console's node"
        : node.direct ? "Authenticated direct link"
        : node.knownHere ? "Known routing identity" : "Routed session endpoint"],
      ["Session", node.has_session === false ? "Not established"
        : node.direct ? "Open" : node.self ? "Local" : "Not directly observed"],
      ["Last seen", node.seen_ago == null ? "Live" : esc(fmtAgo(node.seen_ago))],
      ["Identity key", node.has_key == null ? "Unknown"
        : node.has_key ? "Known" : "Missing"],
    ];
    if(link){
      rows.push(["Link", esc(link.scheme || "?") + " · " + esc(link.direction) +
        " · up " + esc(fmtDuration(link.since))]);
      if(link.local)
        rows.push(["Local endpoint", '<span class="mono">' + esc(link.local) + "</span>"]);
      if(link.remote)
        rows.push(["Remote endpoint", '<span class="mono">' + esc(link.remote) + "</span>"]);
      if(link.dialled && link.dialled !== link.remote)
        rows.push(["Dialled", '<span class="mono">' + esc(link.dialled) + "</span>"]);
    }else{
      rows.push(["Transport", esc(node.transport || "Unknown")]);
    }
    rows.push(["Malformed input", node.malformed == null ? "—" : esc(node.malformed)]);
    return '<dl class="kv">' + rows.map(([key, value]) =>
      "<dt>" + esc(key) + "</dt><dd>" + value + "</dd>").join("") + "</dl>";
  },

  // A fold with a count in its summary: closed it still says how much is in
  // there, so nobody has to open it to find out there is nothing.
  foldHTML(title, body, count){
    if(!body) return "";
    return '<details class="card"><summary>' + esc(title) +
      '<span class="tail">' + esc(count) + "</span></summary>" +
      '<div class="card-body">' + body + "</div></details>";
  },

  addressCount(node){
    const rows = (node.address_status && node.address_status.length)
      ? node.address_status : (node.addresses || []);
    return rows.length ? String(rows.length) : "none";
  },

  addressHTML(node){
    const rows = (node.address_status && node.address_status.length)
      ? node.address_status
      : (node.addresses || []).map((uri) => ({uri, outcome:"untried"}));
    if(!rows.length)
      return '<p class="small muted">No address is advertised for this node.</p>';
    // A node advertising four addresses of which one works is the normal case;
    // "try that one again, now" is the question an operator has while looking
    // at this table, so the button is in the table.
    const action = node.self ? "" : '<th class="tight"></th>';
    return '<div class="table-wrap"><table><thead><tr>' +
      '<th>Address</th><th>State</th><th class="num">Tried</th>' + action +
      "</tr></thead><tbody>" +
      rows.map((row) => '<tr><td class="mono">' + esc(row.uri) + "</td><td>" +
        badge(row.outcome, ADDRESS_TONE[row.outcome] || "") +
        (row.detail ? ' <span class="tiny muted">' + esc(row.detail) + "</span>" : "") +
        '</td><td class="num">' +
        (row.ago == null ? "—" : esc(fmtAgo(row.ago)) +
          (row.ms == null ? "" : " · " + esc(row.ms) + " ms")) +
        "</td>" + (node.self ? "" :
          '<td class="tight"><button class="sm" data-nv-retry="' +
          esc(row.uri) + '">Retry</button></td>') +
        "</tr>").join("") + "</tbody></table></div>";
  },

  // Whatever the medium chose to report. This view does not know what a
  // retransmit or an SNR is — it renders the names it is given.
  statsHTML(link){
    const stats = link && link.stats;
    if(!stats || !Object.keys(stats).length) return "";
    return '<dl class="kv">' + Object.entries(stats).map(([key, value]) =>
      "<dt>" + esc(key) + "</dt><dd>" + esc(value) + "</dd>").join("") + "</dl>";
  },

  // -- mounting -------------------------------------------------------------
  // `options.hide` names the buttons that point back where the viewer came
  // from; `options.onGone` is called when the node is forgotten, so the mount
  // can close itself.
  async mount(container, id, options){
    options = options || {};
    const element = typeof container === "string" ? $(container) : container;
    if(!element) return;
    element.innerHTML = skeletonHTML(4);
    if(!Object.keys(this.apps).length) await this.catalogue();
    let selfId = options.selfId || null;
    if(selfId == null){
      try{
        const {data} = await apiJson("/api/state");
        selfId = data.id;
      }catch(_){ selfId = null; }
    }
    let node;
    try{
      node = await this.facts(id, selfId, options.seed);
    }catch(_){
      element.innerHTML = errorHTML("Node unavailable", "The console did not answer.");
      return;
    }
    const extras = await this.extras(id, node.self);
    element.innerHTML = this.render(node, extras, options);
    if(!element.dataset.nvWired){
      element.dataset.nvWired = "1";
      element.addEventListener("click", (event) => this.act(event, element, options));
    }
    element.dataset.nvId = id;
    this.current = {id, node, extras, options, element};
  },

  say(element, text, bad){
    const box = element.querySelector("[data-nv-status]");
    if(!box) return;
    box.textContent = text || "";
    box.className = "msg" + (bad ? " error" : "");
  },

  async act(event, element, options){
    const retry = event.target.closest("[data-nv-retry]");
    if(retry){ await this.retry(element, retry, retry.dataset.nvRetry); return; }
    const button = event.target.closest("[data-nv-act]");
    if(!button) return;
    const id = element.dataset.nvId;
    const what = button.dataset.nvAct;
    if(what === "copy"){ copyText(id); return; }
    if(what === "refresh"){ await this.mount(element, id, options); return; }
    if(what === "retry-all"){ await this.retry(element, button, ""); return; }
    if(what === "message"){ openLinked("/chat#c/" + id); return; }
    if(what === "fleet"){ openLinked("/fleet#nodes"); return; }
    if(what === "ping"){ await this.ping(element, button, id); return; }
    if(what === "contact"){ await this.contact(element, button, id, options); return; }
    if(what === "enrol"){ await this.enrol(element, button, id, options); return; }
    if(what === "forget"){ await this.forget(element, id, options); return; }
  },

  async ping(element, button, id){
    await withBusy(button, async () => {
      this.say(element, "Pinging through the mesh…");
      try{
        const {data} = await apiJson("/api/ping/node", "POST", {id});
        this.say(element, data.reachable
          ? "Reachable in " + (data.rtt_ms == null ? "an unknown time" : data.rtt_ms + " ms") +
            " via " + (data.via || "the mesh")
          : "Node is currently unreachable", !data.reachable);
      }catch(_){ this.say(element, "Ping failed", true); }
    });
  },

  async retry(element, button, uri){
    const id = element.dataset.nvId;
    await withBusy(button, async () => {
      this.say(element, uri ? "Dialling " + uri + "…" : "Dialling every address…");
      try{
        const {ok, data} = await apiJson("/api/peers/retry", "POST", {id, uri:uri || ""});
        if(!ok){ this.say(element, data.error || "Retry refused", true); return; }
        this.say(element, (data.results || []).map((row) =>
          row.uri + ": " + row.outcome + (row.detail ? " (" + row.detail + ")" : ""))
          .join(" · ") || "Nothing to dial", !data.connected);
      }catch(_){ this.say(element, "Retry failed", true); }
    });
  },

  async contact(element, button, id, options){
    await withBusy(button, async () => {
      try{
        await this.call("chat", "contact", {node:id});
        toast("Added to contacts", "ok");
        await this.mount(element, id, options);
      }catch(error){ this.say(element, String(error.message || error), true); }
    });
  },

  // Asking for rights is a request, never a grant: someone on that machine has
  // to agree. The picker says which rights, because "access" alone is not a
  // thing anybody can answer.
  async enrol(element, button, id, options){
    const fleet = (this.current && this.current.extras.fleet) || {};
    const caps = fleet.capabilities || [];
    if(!caps.length){ this.say(element, "Fleet is not available", true); return; }
    const agreed = await confirmAction({
      title:"Request access to " + shortId(id),
      confirmLabel:"Send request",
      body:'<p class="muted small">Nothing is granted by asking. This node raises a ' +
        "request there, and someone standing on that machine decides what to allow — " +
        "they can allow less than you ask for, never more.</p>" +
        '<div class="nv-pick">' + caps.map((cap) =>
          '<label class="check card-like"><input type="checkbox" value="' +
          esc(cap.name) + '"' + (cap.name === "status" ? " checked" : "") +
          "><span><b>" + esc(cap.name) + "</b><br>" + esc(cap.description) +
          "</span></label>").join("") + "</div>",
    });
    if(!agreed) return;
    const wanted = $$("#confirm-body input:checked").map((input) => input.value);
    if(!wanted.length){ this.say(element, "Pick at least one right", true); return; }
    await withBusy(button, async () => {
      try{
        const result = await this.call("fleet", "enrol", {node:id, caps:wanted});
        if(!result.sent){ this.say(element, "Fleet refused that request", true); return; }
        toast("Request sent — someone there has to accept it", "ok");
        await this.mount(element, id, options);
      }catch(error){ this.say(element, String(error.message || error), true); }
    });
  },

  async forget(element, id, options){
    const agreed = await confirmAction({
      title:"Forget this node?",
      danger:true,
      confirmLabel:"Forget",
      body:'<p class="muted small">It is removed from the routing table and ' +
        "disconnected. It can reappear on its own if it contacts this node again.</p>" +
        '<p class="mono small">' + esc(id) + "</p>",
    });
    if(!agreed) return;
    try{
      await api("/api/nodes/forget", "POST", {id});
      toast("Node forgotten");
      if(options.onGone) options.onGone();
    }catch(_){ this.say(element, "Could not forget that node", true); }
  },
};
"""


# ---------------------------------------------------------------------------
# The standalone page
# ---------------------------------------------------------------------------
# Deliberately bare: no rail, no tabs. It is opened *about* something, from
# somewhere else, and it should look like a card that belongs to whatever
# opened it rather than a second console.

PAGE_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="theme-color" content="#f6f8fa" media="(prefers-color-scheme: light)">
<meta name="theme-color" content="#0a0e13" media="(prefers-color-scheme: dark)">
<title>NMesh node</title>
<script src="/theme.js"></script>
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<link rel="stylesheet" href="/node.css">
</head>
<body data-app-name="NMesh node">

<div id="login" class="gate hidden">
  <form id="login-form">
    <div class="mark" aria-hidden="true">NM</div>
    <div><p class="eyebrow">Node</p><h1>Sign in</h1></div>
    <p class="muted small">This page reads the console of this node, so it needs
      the console password.</p>
    <label class="field"><span>Console password</span>
      <input id="password" type="password" autocomplete="current-password" autofocus></label>
    <button type="submit" class="primary wide">Enter</button>
    <p id="login-error" class="msg error" role="alert"></p>
  </form>
</div>

<main id="main" class="node-page hidden">
  <header class="node-page-head">
    <a class="brand" href="/"><span class="mark" aria-hidden="true">NM</span>
      <span><b>NMesh</b><span>Node</span></span></a>
    <span class="grow"></span>
    <button id="theme-toggle" class="icon" aria-label="Switch theme">☾</button>
  </header>
  <div id="view"></div>
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
<script src="/node.js"></script>
</body>
</html>
"""


NODE_PAGE_CSS_FULL = CSS + """
.node-page{max-width:760px;margin:0 auto;padding:var(--s-4) var(--s-4) var(--s-8);
  display:flex;flex-direction:column;gap:var(--s-4)}
.node-page-head{display:flex;align-items:center;gap:var(--s-3)}
/* Framed inside another app, the header is chrome the host already provides. */
.framed .node-page-head{display:none}
.framed .node-page{padding-top:var(--s-3)}
"""


PAGE_JS = r"""
// ── /node ───────────────────────────────────────────────────────────────────
// Opened about one identity, from somewhere else. The id is in the fragment
// (never the path: a fragment is not sent to the server, and this page is
// opened by pasting a link as often as by clicking one) and `?from=` names the
// app that opened it, so the button pointing back there is not drawn.

function targetId(){
  const raw = (location.hash || "").replace(/^#/, "").trim().toLowerCase();
  return /^[0-9a-f]{40}$/.test(raw) ? raw : "";
}

function hiddenActions(){
  const from = new URLSearchParams(location.search).get("from") || "";
  return ["chat", "fleet"].filter((name) => name === from);
}

async function draw(){
  const id = targetId();
  if(!id){
    $("view").innerHTML = errorHTML("No node named",
      "This page needs a node identity in its address.");
    return;
  }
  await NODEVIEW.mount("view", id, {
    hide: hiddenActions(),
    onGone(){
      $("view").innerHTML = emptyHTML("Node forgotten",
        "It is out of the routing table. Close this and carry on.");
    },
  });
}

function enter(){
  $("login").classList.add("hidden");
  $("main").classList.remove("hidden");
  draw();
}

async function boot(){
  THEME.paint();
  const toggle = $("theme-toggle");
  if(toggle) toggle.addEventListener("click", () => THEME.toggle());
  const close = $("confirm-cancel");
  if(close) close.addEventListener("click", () => $("confirm-dialog").close());
  $$("dialog").forEach((element) => element.addEventListener("click", (event) => {
    if(event.target === element) element.close();
  }));
  // Framed by another app: drop our own chrome so it reads as one panel.
  if(window.self !== window.top) document.body.classList.add("framed");
  window.addEventListener("hashchange", draw);

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

  // Ask before drawing. A stored token can be stale, and a console reached
  // over loopback may not need one at all — the same test settles both, and
  // the same test every other page in this product makes.
  SESSION.load();
  try{
    const response = await api("/api/state");
    if(response.ok){ enter(); return; }
  }catch(_){}
  SESSION.clear();
  $("login").classList.remove("hidden");
}

boot();
"""
