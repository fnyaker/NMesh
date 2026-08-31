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

## What it says, in the order it says it

The first version listed everything it could find, in the order the endpoints
happened to return it: a table of key/value rows, a fold of addresses, a fold of
counters. Everything was there and nothing was answered. This one is built round
the three questions somebody actually opens it with.

1. **Who is this, and what are we to each other?** The name, the id under it,
   and the relationship in words — in your contacts, you manage it, it can drive
   this console. That last one is not a detail: it is the reason to open the
   card at all, and it used to be a row two thirds of the way down a table.
2. **Is the link any good?** The links *drawn* — one wire per link, thickness
   from what it carries, colour from whether it is losing probes, latency on the
   wire — over four numbers. A node reached over tcp and udp at once is the
   normal case here, and a list of rows never showed it as one picture.
3. **Everything else, folded.** Each link's endpoints and counters, the address
   book with what each address last did, the identity and session facts. Present
   for whoever needs them, silent for everybody else (progressive disclosure:
   the fold *says how much is inside*, so nobody has to open it to find out
   there is nothing).

Actions follow the same rule, and the well-documented trap with it: an overflow
menu hides what people then never find. So the one or two that matter stay
visible as buttons — message them, open them in fleet, ping them — and the rest
(copy the id, retry an address, mint an invitation, forget the node) live behind
the **⋯**, where secondary actions belong.

It is **live** on both counts. A link that comes up is a change, so the card is
told (`EVENTS`) and re-reads at once, apps included. Latency, jitter, loss and
what a link has carried are not changes — they never stop moving — so they come
from the statistics cadence every other view is on (`REFRESH.on`), reading only
the live rows. A card nobody is looking at reads nothing: a closed dialog keeps
its contents in the page, so being connected is not the same as being read.

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
# Only what is this view's own — the identity header, the wires, the link rows.
# Everything else — cards, stats, badges, folds, menus — comes from the design
# system, which is the whole point of there being one.

CSS = """
.nodeview{display:flex;flex-direction:column;gap:var(--s-4);min-width:0}

/* -- who this is --------------------------------------------------------- */
.nv-head{display:flex;align-items:flex-start;gap:var(--s-3);min-width:0}
.nv-mark{width:44px;height:44px;flex:none;border-radius:14px;display:grid;
  place-items:center;background:var(--accent-soft);color:var(--accent);
  font:700 var(--fs-md)/1 var(--mono);letter-spacing:.02em}
.nv-head .grow{min-width:0}
.nv-title{font-size:var(--fs-xl);font-weight:640;letter-spacing:-.02em;
  overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.nv-sub{display:flex;flex-wrap:wrap;gap:var(--s-2);margin-top:4px}
/* The full identity is 40 characters nobody reads and everybody copies. */
.nv-id code{font-size:var(--fs-xs)}

/* -- what we are to each other ------------------------------------------- */
/* Sentences, not a table. "managed" and "controls this node" are independent,
   and reading them apart is the whole difficulty. */
.nv-rel{display:flex;flex-direction:column;gap:var(--s-2);margin:0;padding:0;
  list-style:none}
.nv-rel li{display:flex;align-items:flex-start;gap:var(--s-2);
  font-size:var(--fs-sm);color:var(--text)}
.nv-rel .ic{flex:none;margin-top:2px;color:var(--text-muted)}
.nv-rel li.warn .ic{color:var(--warn)}

/* -- the links, drawn ---------------------------------------------------- */
.nv-wires{width:100%;height:auto;display:block;overflow:visible}
.nv-wire{fill:none;stroke:var(--ok);stroke-linecap:round}
.nv-wire.warn{stroke:var(--warn)}
.nv-wire.idle{stroke:var(--text-faint);stroke-dasharray:5 5}
.nv-node{fill:var(--accent-soft);stroke:var(--accent)}
.nv-node.them{fill:var(--surface-2);stroke:var(--border-strong)}
.nv-glyph{fill:var(--accent);font:700 9px var(--mono)}
.nv-glyph.them{fill:var(--text-muted)}
.nv-cap{fill:var(--text-muted);font:500 9px var(--font)}
.nv-wire-label{fill:var(--text-muted);font:600 9px var(--font);
  font-variant-numeric:tabular-nums}

/* -- one row per link ---------------------------------------------------- */
.nv-links{display:flex;flex-direction:column;gap:var(--s-2)}
.nv-link{border:1px solid var(--border);border-radius:var(--r-md);
  background:var(--surface);overflow:hidden}
.nv-link>summary{display:flex;align-items:center;gap:var(--s-3);
  padding:var(--s-2) var(--s-3);cursor:pointer;min-height:var(--tap);
  font-size:var(--fs-sm);list-style:none}
.nv-link>summary::-webkit-details-marker{display:none}
.nv-link>summary:hover{background:var(--surface-2)}
.nv-link>summary .ic.turn{color:var(--text-muted)}
.nv-link .nv-scheme{flex:none;font:600 var(--fs-2xs)/1 var(--mono);
  text-transform:uppercase;letter-spacing:.05em;padding:4px 6px;
  border-radius:var(--r-sm);background:var(--surface-2);color:var(--text-muted)}
.nv-link .nv-where{flex:1 1 auto;min-width:0}
.nv-link .nv-num{flex:none;font-variant-numeric:tabular-nums;
  color:var(--text-muted);font-size:var(--fs-xs)}
.nv-link-body{padding:0 var(--s-3) var(--s-3);border-top:1px solid var(--border)}
.nv-link-body .kv{margin-top:var(--s-3)}

/* -- folds --------------------------------------------------------------- */
/* Sections that answer "and what about…" rather than "what is this": folded,
   because an address table nobody asked for is the reason the first version
   needed scrolling before it said anything. */
.nodeview details.card>summary{padding:var(--s-3) var(--s-4);font-size:var(--fs-sm)}
.nodeview details.card>.card-body{padding:var(--s-4)}
.nodeview details.card>summary .tail{margin-left:auto;color:var(--text-muted);
  font-weight:500;font-size:var(--fs-xs)}
.nv-pick{display:grid;gap:var(--s-2);grid-template-columns:repeat(auto-fit,minmax(min(200px,100%),1fr))}
"""


# ---------------------------------------------------------------------------
# The view
# ---------------------------------------------------------------------------
# Loaded by every mount. `NODEVIEW.mount(container, id, options)` is the whole
# public surface; everything below it is private to this file.

JS = r"""
// ── one node, described ─────────────────────────────────────────────────────
const ADDRESS_TONE = {"in-use":"ok", connected:"ok", timeout:"warn",
                      refused:"danger", "no-answer":"warn", untried:"",
                      advertised:"accent",
                      invalid:"danger", "no transport":"danger", "peer limit":"warn"};
// Above this share of probes lost, a link is drawn as troubled rather than
// merely slow. One in ten is where a human starts noticing.
const LOSS_TROUBLE = 0.1;
// Links drawn as wires. Past this the picture stops being a picture; the list
// below it still carries every one of them.
const MAX_WIRES = 6;

const NODEVIEW = {
  // What the app API says is reachable right now, read once per mount.
  apps: {},
  // Whose point of view this view takes. A mount inside a local app (chat's
  // panel, fleet's sheet) asks *this* node about the identity on screen, even
  // while the console is driving another one: "what is my link to this person"
  // is a different question depending on who "my" is, and answering it from the
  // wrong machine gives a confidently wrong answer rather than an error.
  here: false,
  // The mount that is open, so a change on the mesh can repaint it.
  current: null,
  // One repaint of this card is five requests — two scopes of the node list,
  // the state, and what chat and fleet make of the identity. The stream's frame
  // bounds events at ten a second, which would be fifty calls a second here, so
  // the card keeps a floor of its own on top of it. Half a second is under what
  // anybody reads as a delay and an order of magnitude off the cost.
  REREAD_FLOOR: 500,
  reread: null,
  lastRead: 0,
  // Set when the next repaint has to re-ask the apps as well as the node.
  deep: false,

  // Every call this view makes goes through here, so a mount cannot half
  // follow the context.
  ask(path, method, body){
    return apiJson(path, method, body, {local:this.here});
  },

  async catalogue(){
    try{
      const {data} = await this.ask("/api/app-api");
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
    const {ok, data} = await this.ask("/api/app-call", "POST", {app, op, args});
    if(!ok || !data.ok) throw new Error((data && data.error) || "refused");
    return data.result || {};
  },

  // -- gathering ------------------------------------------------------------
  // Everything the view needs, from the endpoints that already exist. A node
  // this console has never heard of still renders: the identity is real, the
  // rest is simply empty.
  //
  // `/api/nodes?scope=active` answers one row **per link**, and a node may hold
  // several. Taking the first and calling it "the link" is what made a node
  // reached over tcp *and* udp look like a node reached over tcp.
  async facts(id, selfId, seed, keep){
    const rows = async (scope) => {
      const params = new URLSearchParams({scope, q:id, limit:"20", offset:"0"});
      const {ok, data} = await this.ask("/api/nodes?" + params.toString());
      if(!ok) return [];
      return (data.items || []).filter((item) => item.id === id);
    };
    // `keep` is the previous read's routing-table row, handed back on the
    // cadence. Every number that moves — latency, jitter, loss, what the link
    // has carried, how long it has been up — is in the *active* rows; the
    // address book and the identity key are not, and asking for them again
    // every two seconds doubles what an open card costs for nothing. A
    // structural change re-reads both.
    let known = keep || [], active = [];
    if(id !== selfId){
      const answers = await Promise.all(
        [rows("active").catch(() => [])].concat(
          keep ? [] : [rows("known").catch(() => [])]));
      active = answers[0];
      if(!keep) known = answers[1];
    }
    const view = Object.assign({}, known[0] || {}, active[0] || {}, seed || {}, {id});
    view.self = view.self || id === selfId;
    view.direct = active.length > 0;
    view.knownHere = known.length > 0;
    view.links = active;
    view.known = known;          // handed to the next cadence read as `keep`
    view.addresses = this.addressRows(known, active);
    // This node has no entry in its own routing table, so its addresses are the
    // ones it advertises. Without this the card said "no address is advertised
    // for this node" about the node doing the advertising.
    if(view.self) view.addresses = await this.ownAddresses();
    return view;
  },

  async ownAddresses(){
    try{
      const {data} = await this.ask("/api/state");
      return (data.advertised || []).map((uri) => ({uri, outcome:"advertised"}));
    }catch(_){ return []; }
  },

  // One row per address, from every link and from the routing table. The live
  // one wins: an address carrying traffic right now is "in use" whatever it did
  // last week, and it is the row somebody is looking for.
  addressRows(known, active){
    const seen = new Map();
    const consider = (row) => {
      if(!row || !row.uri) return;
      const held = seen.get(row.uri);
      if(!held || row.outcome === "in-use") seen.set(row.uri, row);
    };
    (known[0] ? known[0].address_status || [] : []).forEach(consider);
    active.forEach((link) => (link.address_status || []).forEach(consider));
    if(!seen.size)
      ((known[0] || active[0] || {}).addresses || [])
        .forEach((uri) => consider({uri, outcome:"untried"}));
    return [...seen.values()];
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
  // Drawn once, then written into. This card repaints every tick, and rewriting
  // its markup shut every fold the reader had opened, dropped what they were
  // selecting, and moved the row under their finger. So the *shape* — which
  // links exist, which buttons are drawn, which addresses are listed — decides
  // whether anything is rebuilt, and the numbers are patched into the markup
  // that is already there. See `paintLive` in the design system.

  render(view, extras, options){
    return '<div class="nodeview">' +
      this.headerHTML(view, extras) +
      this.relationHTML(view, extras, options) +
      this.actionsHTML(view, extras, options) +
      this.linksHTML(view) +
      this.foldHTML("Addresses", this.addressHTML(view), this.addressCount(view)) +
      this.foldHTML("Identity and session", this.identityHTML(view), "") +
      '<p class="msg" data-nv-status role="status"></p>' +
      "</div>";
  },

  // Everything the markup is built from, and nothing that merely fills it.
  // A link appearing changes this; its latency does not.
  shape(view, extras, options){
    const chat = extras.chat || {}, fleet = extras.fleet || {};
    return JSON.stringify([
      view.id, view.self, view.direct, view.knownHere, view.has_key,
      view.links.map((link) => this.linkKey(link)),
      view.addresses.map((row) => row.uri),
      (options.hide || []), !!extras.chat, !!chat.contact, !!chat.seen,
      !!chat.unread, !!extras.fleet, !!fleet.managed, !!fleet.operator,
      (fleet.caps || []), (fleet.operator_caps || []),
      !!fleet.waiting_on_them, !!fleet.waiting_on_us, (fleet.asked_caps || []),
    ]);
  },

  // One link, named by what does not change while it is up. Two links on one
  // scheme are told apart by their endpoint.
  linkKey(link){
    const detail = link.link || {};
    return (detail.scheme || link.transport || "?") + "|" +
           (detail.remote || detail.dialled || "");
  },

  // What gets written into that markup on every tick.
  values(view, extras){
    const out = {};
    if(!view.self && view.links.length){
      const best = this.bestLink(view);
      const quality = (best.link || {}).quality || {};
      const loss = quality.loss == null ? null : Math.round(quality.loss * 100);
      const carried = view.links.reduce((sum, link) => {
        const counters = (link.link || {}).counters || link.counters || {};
        return sum + (counters.bytes_in || 0) + (counters.bytes_out || 0);
      }, 0);
      out["glance:rtt"] = best.rtt_ms == null ? "—" : best.rtt_ms + " ms";
      out["glance:jitter"] = quality.jitter_ms == null ? "—" : quality.jitter_ms + " ms";
      out["glance:loss"] = loss == null ? "—" : loss + "%";
      out["glance:carried"] = carried ? fmtBytes(carried) : "—";
      out["glance:spark"] = {html: quality.samples_ms
        ? sparkHTML(quality.samples_ms) : ""};
      // The wires are a drawing, so they are replaced whole rather than
      // patched — an SVG holds no fold, no selection and no focus.
      out.wires = {html: this.wiresHTML(view)};
    }
    view.links.forEach((link) => {
      const key = "link:" + this.linkKey(link);
      const detail = link.link || {};
      const quality = detail.quality || {};
      const counters = detail.counters || link.counters || {};
      const loss = quality.loss == null ? null : Math.round(quality.loss * 100);
      out[key + ":rtt"] = link.rtt_ms == null ? "—" : link.rtt_ms + " ms";
      out[key + ":up"] = fmtDuration(detail.since);
      out[key + ":carried"] = fmtBytes((counters.bytes_in || 0) +
                                       (counters.bytes_out || 0)) +
        " (" + fmtBytes(counters.bytes_in) + " in, " +
        fmtBytes(counters.bytes_out) + " out)";
      out[key + ":probes"] = quality.probes
        ? quality.probes + (loss == null ? "" : " · " + loss + "% lost")
        : "none yet";
      out[key + ":malformed"] = detail.malformed == null ? "—" : detail.malformed;
      Object.entries(detail.stats || {}).slice(0, 16).forEach(([name, value]) => {
        out[key + ":stat:" + name] = value;
      });
    });
    view.addresses.forEach((row) => {
      out["addr:" + row.uri + ":state"] = {
        text: row.outcome, tone: ADDRESS_TONE[row.outcome] || ""};
      out["addr:" + row.uri + ":detail"] = row.detail || "";
      out["addr:" + row.uri + ":tried"] = row.ago == null ? "—"
        : fmtAgo(row.ago) + (row.ms == null ? "" : " · " + row.ms + " ms");
    });
    out.seen = view.seen_ago == null ? "Live" : fmtAgo(view.seen_ago);
    return out;
  },

  // The node's own pseudo, from its signed claim. The full id sits right under
  // it, because a name is never proof of who this is.
  // Two badges at most, and only about the mesh: how this node is reached, and
  // whether its key is known. Everything else about the relationship is said in
  // sentences just below, and a badge repeating a sentence is the clutter this
  // rewrite exists to remove.
  headerHTML(view, extras){
    const name = view.pseudo || shortId(view.id);
    const badges = [];
    if(view.self) badges.push(badge("this node", "accent"));
    else if(view.links.length > 1)
      badges.push(badge(plural(view.links.length, "link"), "ok"));
    else if(view.direct) badges.push(badge("direct link", "ok"));
    else if(view.knownHere) badges.push(badge("known, not linked", ""));
    else badges.push(badge("routed session", "warn"));
    if(view.has_key === false) badges.push(badge("no identity key", "warn"));
    return '<header class="nv-head"><span class="nv-mark" aria-hidden="true">' +
      esc(name.trim().slice(0, 2).toUpperCase()) + "</span>" +
      '<div class="grow"><div class="nv-title">' + esc(name) + "</div>" +
      '<div class="nv-sub">' + badges.join(" ") + "</div></div>" +
      this.menuHTML(view, extras) + "</header>" +
      '<div class="copyable nv-id"><code class="mono" data-nv-id>' + esc(view.id) +
      '</code><button class="sm" data-nv-act="copy">Copy</button></div>';
  },

  // What we are to each other, in sentences. The two fleet directions are
  // independent — holding rights over a node says nothing about what it holds
  // over this one — so they are two lines, never one summary.
  relationHTML(view, extras, options){
    const hide = options.hide || [];
    const chat = extras.chat, fleet = extras.fleet;
    const lines = [];
    const say = (name, text, tone) =>
      lines.push('<li' + (tone ? ' class="' + tone + '"' : "") + ">" +
                 icon(name) + "<span>" + text + "</span></li>");
    if(view.self)
      say("server", "This is the node whose console you are reading.");
    else if(view.links.length > 1)
      say("link", "Reached over " + esc(this.schemes(view).join(" and ")) +
          " at the same time.");
    else if(view.direct)
      say("link", "One authenticated link, over " +
          esc(this.schemes(view)[0] || "an unnamed medium") + ".");
    else if(view.knownHere)
      say("link", "Known here, with no link open. It can be dialled again.");
    else
      say("link", "Reached through the mesh — no direct link to it.");

    if(chat && chat.contact)
      say("person", "In your contacts" +
          (chat.unread ? ", with " + plural(chat.unread, "unread message") : "") + ".");
    else if(chat && chat.seen)
      say("person", "Seen in chat, not in your contacts.");

    if(fleet && hide.indexOf("fleet") < 0){
      if(fleet.managed)
        say("server", "You hold <b>" + esc(fleet.caps.join(", ") || "nothing") +
            "</b> on it.");
      if(fleet.operator)
        say("server", "It holds <b>" +
            esc(fleet.operator_caps.join(", ") || "nothing") +
            "</b> on this node.", "warn");
      if(fleet.waiting_on_them)
        say("server", "Waiting for somebody there to allow <b>" +
            esc(fleet.asked_caps.join(", ")) + "</b>.");
      if(fleet.waiting_on_us)
        say("server", "Waiting on <b>you</b> to answer its request.", "warn");
    }
    return '<ul class="nv-rel">' + lines.join("") + "</ul>";
  },

  schemes(view){
    return [...new Set(view.links.map((link) =>
      (link.link || {}).scheme || link.transport || "?"))];
  },

  // -- actions --------------------------------------------------------------
  // The one or two anybody came for stay visible; the rest go behind the ⋯.
  // An overflow menu is where secondary actions belong and where primary ones
  // go to be never found.
  actionsHTML(view, extras, options){
    if(view.self)
      return '<div class="btn-row"><button data-nv-act="refresh">Refresh</button></div>';
    const hide = options.hide || [];
    const chat = extras.chat, fleet = extras.fleet;
    const buttons = [];
    if(chat && hide.indexOf("chat") < 0)
      buttons.push('<button class="primary" data-nv-act="message">Message' +
        (chat.unread ? " " + badge(chat.unread, "danger") : "") + "</button>");
    if(fleet && hide.indexOf("fleet") < 0){
      if(fleet.managed) buttons.push('<button data-nv-act="fleet">Open in Fleet</button>');
      else if(fleet.waiting_on_them)
        buttons.push('<button disabled>Access requested</button>');
      else buttons.push('<button data-nv-act="enrol">Request access</button>');
    }
    buttons.push('<button data-nv-act="ping">' + icon("pulse") + "Ping</button>");
    return '<div class="btn-row">' + buttons.join("") + "</div>";
  },

  // Secondary actions only. The visible row above keeps the one or two anybody
  // came for; what goes behind a ⋯ is what people would otherwise never find,
  // so nothing they need often is put here.
  menuHTML(view, extras){
    // Nothing to hide behind a ⋯ for this node's own card: the id has its own
    // copy button, and a one-item menu is a button with a lid on.
    if(view.self) return "";
    const chat = extras.chat, fleet = extras.fleet;
    const items = ['<button class="item" data-nv-act="copy" data-menu-close>' +
                   icon("copy") + "Copy the identity</button>",
                   '<button class="item" data-nv-act="window" data-menu-close>' +
                   icon("window") + "Open in its own window</button>"];
    if(chat && !chat.contact)
      items.push('<button class="item" data-nv-act="contact" data-menu-close>' +
                 icon("person") + "Add to contacts</button>");
    if(fleet && fleet.managed && (fleet.caps || []).indexOf("invite") >= 0)
      items.push('<button class="item" data-nv-act="invite" data-menu-close>' +
                 icon("send") + "Mint an invitation to its mesh</button>");
    items.push('<div class="sep"></div>');
    if(view.addresses.length)
      items.push('<button class="item" data-nv-act="retry-all" data-menu-close>' +
                 icon("pulse") + "Retry every address</button>");
    items.push('<button class="item danger" data-nv-act="forget" data-menu-close>' +
               icon("trash") + "Forget this node</button>");
    return '<div class="menu-wrap"><button class="icon" data-menu="nv-menu" ' +
      'aria-haspopup="true" aria-expanded="false" aria-label="More about this node">' +
      icon("dots") + "</button>" +
      '<div id="nv-menu" class="menu" role="region" hidden aria-label="Node actions">' +
      items.join("") + "</div></div>";
  },

  // -- the links ------------------------------------------------------------
  linksHTML(view){
    if(view.self) return "";
    if(!view.links.length)
      return '<div class="card"><div class="card-body">' +
        emptyHTML("No link to this node",
          view.knownHere
            ? "It is in the routing table; retry an address to open one."
            : "Anything sent to it travels through the mesh.") + "</div></div>";
    return '<article class="card"><div class="card-head"><div class="grow">' +
      "<h2>" + plural(view.links.length, "link") + "</h2>" +
      '<div class="sub">' + esc(this.schemes(view).join(" · ")) + "</div></div></div>" +
      '<div class="card-body"><div data-v="wires"></div>' + this.glanceHTML(view) +
      '<div class="nv-links">' +
      view.links.map((link) => this.linkHTML(link)).join("") +
      "</div></div></article>";
  },

  // The links as one picture rather than as a list of rows: one wire per link,
  // thicker with what it carries, amber when it is losing probes, its latency
  // written on it. A node reached two ways is the normal case here, and a table
  // never showed that as a shape.
  wiresHTML(view){
    const links = view.links.slice(0, MAX_WIRES);
    const rows = links.length;
    const height = 62 + Math.max(0, rows - 1) * 22;
    const mid = height / 2;
    const carried = links.map((link) => {
      const counters = (link.link || {}).counters || link.counters || {};
      return (counters.bytes_in || 0) + (counters.bytes_out || 0);
    });
    const busiest = Math.max(1, ...carried);
    const wires = links.map((link, index) => {
      const quality = (link.link || {}).quality || {};
      const loss = quality.loss;
      const apex = mid + (index - (rows - 1) / 2) * 22;
      const control = 2 * apex - mid;
      // Two to six pixels: enough that the busy wire reads as the busy one,
      // never so much that a quiet link disappears.
      const width = (2 + 4 * Math.min(1, carried[index] / busiest)).toFixed(1);
      const troubled = loss != null && loss >= LOSS_TROUBLE;
      const tone = troubled ? " warn" : (link.rtt_ms == null ? " idle" : "");
      const label = (link.link || {}).scheme || link.transport || "?";
      // The colour says it too, and colour is never the only signal: a wire
      // drawn amber has to read as amber in words as well.
      const latency = (link.rtt_ms == null ? "" : " · " + link.rtt_ms + " ms") +
        (troubled ? " · " + Math.round(loss * 100) + "% lost" : "");
      return '<path class="nv-wire' + tone + '" stroke-width="' + width + '" d="M46 ' +
        mid.toFixed(1) + " Q160 " + control.toFixed(1) + " 274 " + mid.toFixed(1) + '"/>' +
        '<text class="nv-wire-label" x="160" y="' + (apex - 5).toFixed(1) +
        '" text-anchor="middle">' + esc(label + latency) + "</text>";
    }).join("");
    const hidden = view.links.length - links.length;
    return '<svg class="nv-wires" viewBox="0 0 320 ' + height +
      '" role="img" aria-label="' +
      esc(plural(view.links.length, "link") + " to this node") + '">' + wires +
      '<circle class="nv-node" cx="32" cy="' + mid + '" r="13"/>' +
      '<text class="nv-glyph" x="32" y="' + (mid + 3) + '" text-anchor="middle">NM</text>' +
      '<text class="nv-cap" x="32" y="' + (height - 5) + '" text-anchor="middle">this node</text>' +
      '<circle class="nv-node them" cx="288" cy="' + mid + '" r="13"/>' +
      '<text class="nv-glyph them" x="288" y="' + (mid + 3) + '" text-anchor="middle">' +
      esc((view.pseudo || shortId(view.id)).trim().slice(0, 2).toUpperCase()) + "</text>" +
      '<text class="nv-cap" x="288" y="' + (height - 5) + '" text-anchor="middle">' +
      esc(shortId(view.id)) + "</text>" +
      (hidden > 0 ? '<text class="nv-cap" x="160" y="' + (height - 5) +
        '" text-anchor="middle">' + esc("+" + hidden + " more below") + "</text>" : "") +
      "</svg>";
  },

  // The four numbers that say whether this is any good, before any of the
  // detail. One round trip cannot tell a steady link from a flapping one, which
  // is why the spread is beside it rather than behind a fold.
  glanceHTML(view){
    const best = this.bestLink(view);
    if(!best) return "";
    const quality = (best.link || {}).quality || {};
    const loss = quality.loss == null ? null : Math.round(quality.loss * 100);
    const totals = view.links.reduce((sum, link) => {
      const counters = (link.link || {}).counters || link.counters || {};
      return sum + (counters.bytes_in || 0) + (counters.bytes_out || 0);
    }, 0);
    // The numbers are written in afterwards (`values`), so the cells here are
    // empty slots. `patchValues` sets them as text, never as markup, which is
    // the same guarantee `esc()` gave: under a remote context these come
    // verbatim from *another* node's console and are network input.
    const cell = (key, label, extra) =>
      '<div class="stat sm"><span class="v" data-v="glance:' + key +
      '"></span><span class="k">' + esc(label) + "</span>" + (extra || "") + "</div>";
    return '<div class="stats">' +
      cell("rtt", "Round trip",
           '<div data-v="glance:spark"' +
           ((loss != null && loss >= 10) ? ' class="spark warn"' : "") + "></div>") +
      cell("jitter", "Jitter") +
      cell("loss", "Probe loss") +
      cell("carried", "Carried") +
      "</div>";
  },

  // The yardstick is the fastest link, and its spread is the one worth showing:
  // the jitter of a link nobody is using answers no question.
  bestLink(view){
    let best = null;
    view.links.forEach((link) => {
      if(link.rtt_ms == null) return;
      if(best == null || link.rtt_ms < best.rtt_ms) best = link;
    });
    return best || view.links[0] || null;
  },

  linkHTML(link){
    const detail = link.link || {};
    const quality = detail.quality || {};
    const counters = detail.counters || link.counters || {};
    const loss = quality.loss == null ? null : Math.round(quality.loss * 100);
    const key = "link:" + this.linkKey(link);
    const slot = (name) => '<span data-v="' + esc(key + ":" + name) + '"></span>';
    const rows = [
      ["Direction", esc(detail.direction || (link.is_client_side ? "outbound" : "inbound"))],
      ["Up for", slot("up")],
      ["Local endpoint", detail.local ? '<span class="mono">' + esc(detail.local) + "</span>" : "—"],
      ["Remote endpoint", detail.remote ? '<span class="mono">' + esc(detail.remote) + "</span>" : "—"],
    ];
    if(detail.dialled && detail.dialled !== detail.remote)
      rows.push(["Dialled", '<span class="mono">' + esc(detail.dialled) + "</span>"]);
    rows.push(["Carried", slot("carried")]);
    rows.push(["Probes", slot("probes")]);
    rows.push(["Malformed input", slot("malformed")]);
    // Whatever the medium chose to report. This view does not know what a
    // retransmit or an SNR is — it renders the names it is given.
    Object.keys(detail.stats || {}).slice(0, 16).forEach((name) =>
      rows.push([name, slot("stat:" + name)]));
    const where = detail.remote || detail.dialled || link.transport || "—";
    return '<details class="nv-link"><summary>' +
      icon("chevron", "", "turn") +
      '<span class="nv-scheme">' + esc(detail.scheme || link.transport || "?") + "</span>" +
      '<span class="nv-where mono truncate">' + esc(where) + "</span>" +
      '<span class="nv-num" data-v="' + esc(key + ":rtt") + '"></span>' +
      '<span class="nv-num" data-v="' + esc(key + ":up") + '"></span></summary>' +
      '<div class="nv-link-body"><dl class="kv">' + rows.map(([name, value]) =>
        "<dt>" + esc(name) + "</dt><dd>" + value + "</dd>").join("") +
      "</dl></div></details>";
  },

  // -- the folds ------------------------------------------------------------
  // A fold with a count in its summary: closed it still says how much is in
  // there, so nobody has to open it to find out there is nothing.
  foldHTML(title, body, count){
    if(!body) return "";
    return '<details class="card"><summary>' + esc(title) +
      '<span class="tail">' + esc(count) + "</span></summary>" +
      '<div class="card-body">' + body + "</div></details>";
  },

  addressCount(view){
    return view.addresses.length ? String(view.addresses.length) : "none";
  },

  addressHTML(view){
    const rows = view.addresses;
    if(!rows.length)
      return '<p class="small muted">' + (view.self
        ? "This node advertises no address — nothing can dial it."
        : "No address is advertised for this node.") + "</p>";
    // A node advertising four addresses of which one works is the normal case;
    // "try that one again, now" is the question an operator has while looking
    // at this table, so the button is in the table.
    const action = view.self ? "" : '<th class="tight"></th>';
    return '<div class="table-wrap"><table><thead><tr>' +
      '<th>Address</th><th>State</th><th class="num">Tried</th>' + action +
      "</tr></thead><tbody>" +
      rows.map((row) => '<tr><td class="mono">' + esc(row.uri) + "</td><td>" +
        '<span class="badge" data-base="badge" data-v="' +
        esc("addr:" + row.uri + ":state") + '"></span>' +
        ' <span class="tiny muted" data-v="' +
        esc("addr:" + row.uri + ":detail") + '"></span>' +
        '</td><td class="num" data-v="' + esc("addr:" + row.uri + ":tried") + '">' +
        "</td>" + (view.self ? "" :
          '<td class="tight"><button class="sm" data-nv-retry="' +
          esc(row.uri) + '">Retry</button></td>') +
        "</tr>").join("") + "</tbody></table></div>";
  },

  identityHTML(view){
    const rows = [
      ["Relationship", view.self ? "This console's node"
        : view.direct ? "Authenticated direct link"
        : view.knownHere ? "Known routing identity" : "Routed session endpoint"],
      ["Session", view.has_session === false ? "Not established"
        : view.direct ? "Open" : view.self ? "Local" : "Not directly observed"],
      ["Last seen", '<span data-v="seen"></span>'],
      ["Identity key", view.has_key == null ? "Unknown"
        : view.has_key ? "Known" : "Missing"],
      ["Malformed input", view.malformed == null ? "—" : esc(view.malformed)],
    ];
    return '<dl class="kv">' + rows.map(([key, value]) =>
      "<dt>" + esc(key) + "</dt><dd>" + value + "</dd>").join("") + "</dl>";
  },

  // -- mounting -------------------------------------------------------------
  // `options.hide` names the buttons that point back where the viewer came
  // from; `options.onGone` is called when the node is forgotten, so the mount
  // can close itself; `options.local` makes this view ask *this* node.
  async mount(container, id, options){
    options = options || {};
    const element = typeof container === "string" ? $(container) : container;
    if(!element) return;
    // Set before the first call: everything below reads it.
    this.here = !!options.local;
    if(element.dataset.nvId !== id) element.innerHTML = skeletonHTML(4);
    if(!Object.keys(this.apps).length) await this.catalogue();
    let selfId = options.selfId || null;
    if(selfId == null){
      try{
        const {data} = await this.ask("/api/state");
        selfId = data.id;
      }catch(_){ selfId = null; }
    }
    if(!element.dataset.nvWired){
      element.dataset.nvWired = "1";
      element.addEventListener("click", (event) => this.act(event, element, options));
    }
    element.dataset.nvId = id;
    this.current = {id, selfId, options, element, extras:null};
    await this.read(true);
  },

  // Read this node again and repaint. `deep` also re-asks the apps what they
  // make of the identity; the cadence does not, because "in your contacts" and
  // "you hold status on it" do not move between two ticks and asking every two
  // seconds would triple the cost of a card being open for nothing.
  async read(deep){
    const open = this.current;
    if(!open || !open.element.isConnected) return;

    const element = open.element;
    this.here = !!open.options.local;
    this.lastRead = Date.now();
    let view;
    try{
      view = await this.facts(open.id, open.selfId, open.options.seed,
                              deep ? null : (open.view || {}).known);
    }catch(error){
      if(isStale(error) || this.current !== open) return;
      element.innerHTML = errorHTML("Node unavailable", "The console did not answer.");
      return;
    }
    if(this.current !== open) return;      // mounted elsewhere while we asked
    if(deep || open.extras == null) open.extras = await this.extras(open.id, view.self);
    if(this.current !== open) return;
    open.view = view;
    // The shape decides whether anything is rebuilt; the numbers are written
    // into what is already there. A card repainted every second that rewrote
    // its markup shut every fold the reader had opened.
    paintLive(element, this.shape(view, open.extras, open.options),
              () => this.render(view, open.extras, open.options),
              this.values(view, open.extras));
  },

  // Repaint what is open, on a trailing edge and never faster than the floor
  // above. `deep` when something structural moved — a link, a name, a grant —
  // and not on the plain cadence, which is only about the numbers.
  refresh(deep){
    if(!this.showing()) return;
    if(deep) this.deep = true;
    if(this.reread) return;
    const wait = Math.max(0, this.REREAD_FLOOR - (Date.now() - this.lastRead));
    this.reread = setTimeout(() => { this.reread = null; this.repaint(); }, wait);
  },

  // Mounted, in the document, and actually drawing something. A dialog that is
  // closed keeps its contents in the page, so `isConnected` alone would have
  // this card polling for ever behind a card nobody is looking at; a box with
  // no client rect has no reader.
  showing(){
    const open = this.current;
    return !!(open && open.element.isConnected
              && open.element.getClientRects().length);
  },

  repaint(){
    const open = this.current;
    if(!this.showing()) return;
    // Never while the ⋯ is open: replacing the panel under the finger that
    // opened it is worse than being a beat late. Try again rather than dropping
    // the change, or the card stays stale until the next thing moves.
    if(MENU.open === "nv-menu"){ this.refresh(); return; }
    const deep = this.deep;
    this.deep = false;
    this.read(deep);
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
    if(what === "window"){ openLinked("/node#" + id); return; }
    if(what === "retry-all"){ await this.retry(element, button, ""); return; }
    if(what === "message"){ openLinked("/chat#c/" + id); return; }
    if(what === "fleet"){ openLinked("/fleet#nodes"); return; }
    if(what === "ping"){ await this.ping(element, button, id); return; }
    if(what === "contact"){ await this.contact(element, button, id, options); return; }
    if(what === "invite"){ await this.invite(element, button, id); return; }
    if(what === "enrol"){ await this.enrol(element, button, id, options); return; }
    if(what === "forget"){ await this.forget(element, id, options); return; }
  },

  async ping(element, button, id){
    await withBusy(button, async () => {
      this.say(element, "Pinging through the mesh…");
      try{
        const {data} = await this.ask("/api/ping/node", "POST", {id});
        this.say(element, data.reachable
          ? "Reachable in " + (data.rtt_ms == null ? "an unknown time" : data.rtt_ms + " ms") +
            " via " + (data.via || "the mesh")
          : "Node is currently unreachable", !data.reachable);
      }catch(error){ if(!isStale(error)) this.say(element, "Ping failed", true); }
    });
  },

  async retry(element, button, uri){
    const id = element.dataset.nvId;
    await withBusy(button, async () => {
      this.say(element, uri ? "Dialling " + uri + "…" : "Dialling every address…");
      try{
        const {ok, data} = await this.ask("/api/peers/retry", "POST", {id, uri:uri || ""});
        if(!ok){ this.say(element, data.error || "Retry refused", true); return; }
        this.say(element, (data.results || []).map((row) =>
          row.uri + ": " + row.outcome + (row.detail ? " (" + row.detail + ")" : ""))
          .join(" · ") || "Nothing to dial", !data.connected);
      }catch(error){ if(!isStale(error)) this.say(element, "Retry failed", true); }
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

  // Minting an invitation on somebody else's behalf is a right of its own
  // (`invite`), separate from driving their console: the node that will honour
  // the code is the node that makes it, and it decides how long it lives.
  async invite(element, button, id){
    const agreed = await confirmAction({
      title:"Mint an invitation to that node's mesh",
      confirmLabel:"Create",
      body:'<p class="muted small">That node makes it, not this one: whoever uses ' +
        "it joins through that machine and has their certificate signed by it. " +
        "Single use, and it stops working when the window closes.</p>" +
        '<label class="field"><span>Stays live for</span><select id="nv-ttl">' +
        '<option value="300">5 minutes</option>' +
        '<option value="3600">1 hour</option>' +
        '<option value="21600">6 hours</option></select></label>' +
        '<label class="check"><input id="nv-ticket" type="checkbox" checked>' +
        "<span>Also make it scannable, if that node has a public address</span></label>",
    });
    if(!agreed) return;
    const ttl = parseInt(($("nv-ttl") || {}).value, 10) || 300;
    const ticket = !!($("nv-ticket") || {}).checked;
    await withBusy(button, async () => {
      try{
        const result = await this.call("fleet", "invite", {node:id, ttl, ticket});
        if(result.error){ this.say(element, result.error, true); return; }
        // Shown once, where it was asked for. A single-use secret does not
        // belong in a list a page keeps.
        await confirmAction({
          title:"Invitation to " + shortId(id),
          confirmLabel:"Done",
          body:'<p class="muted small">Shown once. The invitation itself stays ' +
            "live until it is used or expires.</p>" +
            '<div class="copyable"><code class="mono">' + esc(result.code) +
            '</code></div>' +
            (result.ticket ? '<div class="copyable"><code class="mono">' +
              esc(result.ticket) + "</code></div>" : "") +
            (result.qr_svg ? '<div class="qr-holder">' + result.qr_svg + "</div>" : ""),
        });
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
      await this.ask("/api/nodes/forget", "POST", {id});
      toast("Node forgotten");
      this.current = null;
      if(options.onGone) options.onGone();
    }catch(error){
      if(!isStale(error)) this.say(element, "Could not forget that node", true);
    }
  },
};

// A link that came up is the thing this view is about, so it does not wait for
// a timer. The stream's frame already bounds how often that can happen, and a
// structural change is the one worth re-asking the apps about.
EVENTS.on(["links", "nodes", "names"], () => NODEVIEW.refresh(true));
// And the numbers on it move without anything "happening" — latency, jitter,
// loss, what the link has carried — so the card is on the statistics cadence
// like every other view that shows one. It used to be on neither, and stood
// still for as long as it was open.
REFRESH.on(() => NODEVIEW.refresh());
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
    <button id="theme-toggle" class="icon" aria-label="Switch theme"><svg class="ic" viewBox="0 0 24 24" aria-hidden="true"><path d="M20.5 14.8A8.6 8.6 0 0 1 9.2 3.5a8.6 8.6 0 1 0 11.3 11.3Z"/></svg></button>
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
//
// `?from=` also settles whose point of view the page takes. Opened from chat or
// fleet it answers for *this* node, because those apps run here whatever the
// console is driving; opened from the console it follows the console.

function targetId(){
  const raw = (location.hash || "").replace(/^#/, "").trim().toLowerCase();
  return /^[0-9a-f]{40}$/.test(raw) ? raw : "";
}

function openedFrom(){
  return new URLSearchParams(location.search).get("from") || "";
}

function hiddenActions(){
  const from = openedFrom();
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
    local: ["chat", "fleet"].includes(openedFrom()),
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
  // The card is registered with both already; this is what arms them. Without
  // it the page opened, drew once and stood still — the one view in the product
  // that was on no cadence at all.
  REFRESH.mount();
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
  // The view's ⋯ is a shell menu like any other, and this page has no shell.
  MENU.mount();
  // Framed by another app: drop our own chrome so it reads as one panel.
  if(window.self !== window.top) document.body.classList.add("framed");
  window.addEventListener("hashchange", draw);
  CONTEXT.restore();

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
