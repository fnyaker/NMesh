"""
Packages — one search, one detail card, mounted wherever a package appears.

The console used to answer "what can I install?" with two lists. Settings →
Updates printed every publisher that had announced a release and asked the
operator to paste a public key in by hand. Apps → Store printed a gossiped
catalogue of everything anybody had ever published. Both were lists nobody
asked for, and a list is a thing to flood.

This replaces both with a question. You type part of a name, or you open a
node's details and see what *that* machine offers; either way the answer is a
signed record carrying its publisher's key — so pinning is a confirmation of
something that arrived with the thing it signed, not a hex string copied from a
channel nobody can vouch for.

## What the card says, in the order somebody reads it

1. **What is this, and whose is it.** Name, version, publisher — and whether
   this is a publication or somebody saying "this is the release I run".
2. **What it says about itself.** The few signed lines a publisher wrote: the
   only description available before anything is fetched, so it is shown before
   any button.
3. **What else agrees.** How many publishers have signed a package carrying the
   same *code* — documentation excluded, so different release notes do not
   break agreement. This is the number a quorum counts.
4. **What you can do.** Download it to open by hand, install it, watch it. In
   that order, because reading before running is the whole argument for showing
   a download button at all.

Mounted by the console (Updates and Apps), by the node view, and served at
``/package#<id>`` for the window or tab an operator may prefer — the same rule
:mod:`.nodeview` follows, and for the same reason: one description of a package,
not four that drift.
"""

# ---------------------------------------------------------------------------
# Styles
# ---------------------------------------------------------------------------

CSS = """
.pkg-search{display:flex;flex-direction:column;gap:var(--s-3)}
.pkg-search .search{max-width:none;width:100%}
.pkg-hits{display:flex;flex-direction:column;gap:var(--s-2)}
.pkg-hit{display:flex;align-items:center;gap:var(--s-3);width:100%;text-align:left;
  padding:var(--s-3);border:1px solid var(--line);border-radius:var(--r-2);
  background:var(--surface);cursor:pointer;min-width:0}
.pkg-hit:hover{border-color:var(--accent);background:var(--surface-2)}
.pkg-hit .grow{min-width:0}
.pkg-hit b{display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.pkg-hit .tiny{color:var(--text-muted)}
.pkg-mark{width:34px;height:34px;flex:none;border-radius:10px;display:grid;
  place-items:center;background:var(--accent-soft);color:var(--accent)}

/* -- the card ----------------------------------------------------------- */
.pkg-card{display:flex;flex-direction:column;gap:var(--s-4);min-width:0}
.pkg-head{display:flex;align-items:flex-start;gap:var(--s-3);min-width:0}
.pkg-title{font-size:var(--fs-xl);font-weight:640;letter-spacing:-.02em;
  overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.pkg-sub{display:flex;flex-wrap:wrap;gap:var(--s-2);margin-top:4px}
/* The signed description. A few lines, so it reads as prose rather than as a
   field — and pre-wrap, because whoever wrote it chose where the lines end. */
.pkg-notes{white-space:pre-wrap;font-size:var(--fs-sm);color:var(--text);
  background:var(--surface-2);border:1px solid var(--line);
  border-radius:var(--r-2);padding:var(--s-3);margin:0;max-height:16em;
  overflow:auto}
.pkg-notes.empty{color:var(--text-muted);font-style:italic}
.pkg-facts{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));
  gap:var(--s-3)}
.pkg-fact{min-width:0}
.pkg-fact .k{font-size:var(--fs-xs);color:var(--text-muted);
  text-transform:uppercase;letter-spacing:.04em}
.pkg-fact .v{font-size:var(--fs-md);font-weight:600;overflow:hidden;
  text-overflow:ellipsis;white-space:nowrap}
.pkg-actions{display:flex;flex-wrap:wrap;gap:var(--s-2);align-items:center}
.pkg-watch{display:flex;flex-wrap:wrap;gap:var(--s-3);align-items:center;
  padding:var(--s-3);border:1px solid var(--line);border-radius:var(--r-2);
  background:var(--surface-2)}
/* One line, label then box: the label is four words, and as a `.field` it
   wrapped to three lines and pulled the checkboxes out of alignment. */
.pkg-quorum{display:flex;align-items:center;gap:var(--s-2);
  font-size:var(--fs-sm);white-space:nowrap}
.pkg-quorum input{width:5em}
"""


# ---------------------------------------------------------------------------
# The shared view
# ---------------------------------------------------------------------------

JS = r"""
// ── the package directory ───────────────────────────────────────────────────
// Nothing here lists anything. `search` asks the directory a name, `forNode`
// asks it about one identity, and `card` draws one signed record. Every
// decision — is it trusted, does anything agree with it, may it be installed —
// is made by the node and read off the row: this file renders.

const PACKAGES = {
  // The record last drawn, so the buttons know what they act on without
  // re-reading the address bar.
  current: null,

  async ask(path, method, body){
    return apiJson(path, method, body);
  },

  async search(query, wide){
    const params = new URLSearchParams({q:query});
    if(wide) params.set("wide", "1");
    const {ok, data} = await this.ask("/api/packages?" + params.toString());
    return ok ? (data.results || []) : [];
  },

  async forNode(id, wide){
    const params = new URLSearchParams({node:id});
    if(wide) params.set("wide", "1");
    const {ok, data} = await this.ask("/api/packages?" + params.toString());
    return ok ? (data.results || []) : [];
  },

  async read(id, fetchDescriptor){
    const suffix = fetchDescriptor ? "?fetch=1" : "";
    const {ok, data} = await this.ask("/api/packages/" + encodeURIComponent(id) + suffix);
    return ok ? data : null;
  },

  kindLabel(row){
    if(row.recommend) return "recommended";
    return row.kind === "core" ? "node software" : "app";
  },

  // A hit is a button: the whole row opens the card, because a row with one
  // link inside it is a row people click everywhere except the link.
  hitHTML(row){
    return '<button class="pkg-hit" data-pkg-open="' + esc(row.id) + '">' +
      '<span class="pkg-mark" aria-hidden="true">' +
        icon(row.kind === "core" ? "server" : "window") + "</span>" +
      '<span class="grow"><b>' + esc(row.name) + "</b>" +
      '<span class="tiny">' + esc(row.version) + " · " +
        esc(this.kindLabel(row)) + " · " + esc(shortId(row.publisher_id)) +
      "</span></span>" +
      (row.trusted ? badge("pinned", "ok") : "") +
      ((row.vouched_by || []).length ? badge("paired") : "") +
      (row.attesters > 1 ? badge(row.attesters + " agree", "ok") : "") +
      "</button>";
  },

  hitsHTML(rows, emptyHint){
    if(!rows.length)
      return emptyHTML("Nothing under that name",
                       emptyHint || "Try fewer letters, or ask the network.");
    return '<div class="pkg-hits">' +
      rows.map((row) => this.hitHTML(row)).join("") + "</div>";
  },

  // -- the card ------------------------------------------------------------

  cardHTML(row, options){
    const opts = options || {};
    const badges = [badge(this.kindLabel(row), row.recommend ? "warn" : null)];
    if(row.trusted) badges.push(badge("publisher pinned", "ok"));
    if(row.mine) badges.push(badge("published here"));
    if((row.vouched_by || []).length) badges.push(badge("paired with a node"));
    if(row.equivocated)
      badges.push(badge("signed two different programs as one version", "bad"));
    const facts = [
      ["Version", esc(row.version)],
      ["Publisher", '<code class="inline">' + esc(shortId(row.publisher_id)) + "</code>"],
      ["Published", esc(fmtAgo(Date.now() / 1000 - row.ts))],
      ["Agreeing publishers", String(row.attesters)],
    ];
    return '<div class="pkg-card" data-pkg-id="' + esc(row.id) + '">' +
      '<div class="pkg-head">' +
        '<span class="pkg-mark" aria-hidden="true">' +
          icon(row.kind === "core" ? "server" : "window") + "</span>" +
        '<span class="grow"><div class="pkg-title">' + esc(row.name) + "</div>" +
        '<div class="pkg-sub">' + badges.join("") + "</div></span>" +
      "</div>" +
      '<div><p class="eyebrow">What it says about itself</p>' +
        '<pre class="pkg-notes' + (row.notes ? "" : " empty") + '">' +
          esc(row.notes || "The publisher wrote no description.") + "</pre></div>" +
      '<div class="pkg-facts">' + facts.map(([k, v]) =>
        '<div class="pkg-fact"><div class="k">' + esc(k) + '</div>' +
        '<div class="v">' + v + "</div></div>").join("") + "</div>" +
      this.explainHTML(row) +
      this.actionsHTML(row, opts) +
      this.watchHTML(row, opts) +
      '<p id="pkg-status" class="msg"></p>' +
      "</div>";
  },

  // Why the buttons are what they are. A refusal that does not say what would
  // change it is a refusal somebody works around rather than understands.
  explainHTML(row){
    const paired = row.vouched_by || [];
    // A key that is not a node identity, tied to the machine that uses it by
    // two signatures. Said in full because the alternative reads as a mystery:
    // "why is this publisher not the node I opened?"
    const pairing = paired.length
      ? '<p class="muted small">This is a publisher key of its own, not a ' +
        "node's identity — which is how a key that decides what your machine " +
        "runs stays out of the memory of a node that is running. It is paired " +
        "with " + (paired.length === 1
          ? "node <code class=\"inline\">" + esc(shortId(paired[0])) + "</code>"
          : plural(paired.length, "node")) +
        ": both signed saying so, and neither could have said it for the " +
        "other.</p>"
      : "";
    if(row.recommend)
      return pairing + '<p class="muted small">This node is not the publisher: ' +
        "it is saying which release it runs. That counts towards agreement when " +
        "you watch it, and towards nothing otherwise — pin the publisher it " +
        "points at, never the machine that agreed with them.</p>";
    if(row.kind === "core" && !row.trusted)
      return pairing + '<p class="muted small">This key is not pinned here, so ' +
        "nothing from it can replace this node's code. Pinning it is one press " +
        "and a confirmation — the key came with the record and was checked " +
        "against the signature it made, so there is nothing to copy across.</p>";
    return pairing;
  },

  actionsHTML(row, opts){
    const buttons = [];
    if(!row.recommend){
      buttons.push('<a class="btn" download href="/api/packages/' +
        encodeURIComponent(row.id) + '/download">' + icon("arrowDown") +
        " Download</a>");
      if(row.kind === "core" && !row.trusted)
        buttons.push('<button class="primary" data-pkg-act="trust">' +
          "Pin this publisher</button>");
      else
        buttons.push('<button class="primary" data-pkg-act="install">' +
          "Install</button>");
    }
    if(!opts.hideOpen)
      buttons.push('<button data-pkg-act="page">Open on its own</button>');
    return '<div class="pkg-actions">' + buttons.join("") + "</div>";
  },

  watchHTML(row, opts){
    if(row.recommend && opts.hideWatch) return "";
    const sub = row.subscription || null;
    const quorum = sub ? sub.quorum : 1;
    return '<div class="pkg-watch">' +
      '<label class="check"><input type="checkbox" data-pkg-act="watch"' +
        (sub ? " checked" : "") + "><span>Watch for new versions</span></label>" +
      '<label class="check"><input type="checkbox" data-pkg-act="auto"' +
        (sub && sub.auto ? " checked" : "") + (sub ? "" : " disabled") +
        "><span>Install them without asking</span></label>" +
      '<label class="pkg-quorum"><span>Publishers that must agree</span>' +
        '<input type="number" min="1" max="8" data-pkg-act="quorum" value="' +
        esc(quorum) + '"' + (sub ? "" : " disabled") + "></label>" +
      '<p class="muted small">Agreement is over the package’s code with its ' +
      "documentation left out, so two publishers whose release notes differ " +
      "still agree. One means install whatever this publisher offers; more " +
      "means hold back until that many publishers you watch have signed the " +
      "same code.</p></div>";
  },

  // -- acting on a card ----------------------------------------------------

  async mount(container, id, options){
    const element = typeof container === "string" ? $(container) : container;
    if(!element) return;
    setHTML(element, skeletonHTML(3));
    const row = await this.read(id, true);
    if(!row){
      setHTML(element, errorHTML("Package not found",
        "Nothing here holds a record with that id any more."));
      return;
    }
    this.current = row;
    setHTML(element, this.cardHTML(row, options || {}));
    element.addEventListener("click", (event) => this.onClick(event, element));
    element.addEventListener("change", (event) => this.onChange(event, element));
  },

  async repaint(element, options){
    if(!this.current) return;
    const row = await this.read(this.current.id, false);
    if(!row) return;
    this.current = row;
    setHTML(element, this.cardHTML(row, options || {}));
  },

  async onClick(event, element){
    const button = event.target.closest("[data-pkg-act]");
    if(!button || button.tagName === "INPUT") return;
    const row = this.current;
    if(!row) return;
    if(button.dataset.pkgAct === "page"){
      openLinked("/package#" + row.id, "nmesh-package");
      return;
    }
    if(button.dataset.pkgAct === "trust"){ await this.trust(row, element); return; }
    if(button.dataset.pkgAct === "install"){ await this.install(row, element); }
  },

  async onChange(event, element){
    const input = event.target.closest("[data-pkg-act]");
    if(!input || input.tagName !== "INPUT") return;
    const row = this.current;
    if(!row) return;
    const what = input.dataset.pkgAct;
    if(what === "watch" && !input.checked){
      await this.ask("/api/packages/subscribe", "POST", {id:row.id, on:false});
      toast("No longer watching " + row.name);
      await this.repaint(element);
      return;
    }
    const card = element.querySelector(".pkg-card");
    const auto = !!(card && card.querySelector('[data-pkg-act="auto"]').checked);
    const quorum = parseInt(
      (card && card.querySelector('[data-pkg-act="quorum"]').value) || "1", 10) || 1;
    const {ok, data} = await this.ask("/api/packages/subscribe", "POST",
                                      {id:row.id, on:true, auto, quorum});
    if(!ok){ setMessage("pkg-status", data.error || "Could not save", true); return; }
    toast("Watching " + row.name);
    await this.repaint(element);
  },

  async trust(row, element){
    const agreed = await confirmAction({
      title:"Pin " + row.name + "’s publisher?",
      confirmLabel:"Pin this key",
      body:'<p class="muted small">Whoever holds this key can offer code that ' +
        "replaces this node’s own. The key below came inside the record and " +
        "was checked against the signature it made — so it is the key that " +
        "signed what you are looking at, and nothing else.</p>" +
        '<div class="kv"><div>Publisher</div><div><code class="inline">' +
        esc(row.publisher_id) + "</code></div></div>" +
        '<label class="check"><input id="pkg-pin-auto" type="checkbox">' +
        "<span>Let this key install its releases without asking</span></label>",
    });
    if(!agreed) return;
    const auto = !!($("pkg-pin-auto") || {}).checked;
    const {ok, data} = await this.ask("/api/packages/trust", "POST",
                                      {id:row.id, confirm:true, auto});
    if(!ok){ setMessage("pkg-status", data.error || "Could not pin", true); return; }
    toast("Pinned " + shortId(row.publisher_id), "ok");
    await this.repaint(element);
  },

  async install(row, element){
    const core = row.kind === "core";
    const agreed = await confirmAction({
      title:"Install " + row.name + " " + row.version + "?",
      danger:core,
      confirmLabel:"Install",
      body:'<p class="muted small">' + (core
        ? "This replaces the node’s files and restarts it. Every byte is " +
          "checked against the hash its publisher signed before anything " +
          "touches disk, and the previous tree is kept so a bad release can be " +
          "rolled back on the machine itself."
        : "The app is fetched, every byte checked against the hash its author " +
          "signed, and written into a directory of its own.") + "</p>" +
      (row.attesters > 1
        ? '<p class="muted small">' + row.attesters + " publishers have signed " +
          "a package carrying this same code.</p>"
        : '<p class="muted small">No other publisher has signed this code. That ' +
          "is normal for something only one person builds — it is not, on its " +
          "own, a reason to worry or a reason not to.</p>"),
    });
    if(!agreed) return;
    setMessage("pkg-status", "Fetching and verifying…");
    const {ok, data} = await this.ask("/api/packages/install", "POST",
                                      {id:row.id, confirm:true});
    if(!ok){
      setMessage("pkg-status", data.error || "Install failed", true);
      return;
    }
    setMessage("pkg-status", data.restarting
      ? "Installed " + row.version + " — the node is restarting onto it."
      : "Installed " + row.version + ".");
    toast("Installed " + row.name + " " + row.version, "ok");
    await this.repaint(element);
  },
};

// A field that searches the directory. Typing answers from what this node
// already holds — instant and free; the button is what spends a round of
// queries on the network, which is the same bargain the name search makes.
function mountPackageSearch(options){
  const opts = options || {};
  const field = $(opts.input);
  const results = $(opts.results);
  if(!field || !results) return;
  let latest = "";
  const draw = async (wide) => {
    const query = (field.value || "").trim();
    latest = query;
    if(!query){ setHTML(results, ""); return; }
    if(wide) setHTML(results, skeletonHTML(2));
    const rows = await PACKAGES.search(query, wide);
    if(latest !== query) return;                 // a later keystroke won
    setHTML(results, PACKAGES.hitsHTML(rows));
  };
  field.addEventListener("input", debounce(() => draw(false), 200));
  const wideButton = $(opts.wide);
  if(wideButton)
    wideButton.addEventListener("click", () => withBusy(wideButton, () => draw(true)));
  results.addEventListener("click", (event) => {
    const hit = event.target.closest("[data-pkg-open]");
    if(!hit) return;
    if(opts.onOpen) opts.onOpen(hit.dataset.pkgOpen);
    else openLinked("/package#" + hit.dataset.pkgOpen, "nmesh-package");
  });
}
"""


# ---------------------------------------------------------------------------
# The standalone page
# ---------------------------------------------------------------------------
# Bare, like /node and for the same reason: it is opened *about* something,
# from somewhere else.

PAGE_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="theme-color" content="#f6f8fa" media="(prefers-color-scheme: light)">
<meta name="theme-color" content="#0a0e13" media="(prefers-color-scheme: dark)">
<title>NMesh package</title>
<script src="/theme.js"></script>
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<link rel="stylesheet" href="/package.css">
</head>
<body data-app-name="NMesh package">

<div id="login" class="gate hidden">
  <form id="login-form">
    <div class="mark" aria-hidden="true">NM</div>
    <div><p class="eyebrow">Package</p><h1>Sign in</h1></div>
    <p class="muted small">This page reads the console of this node, so it needs
      the console password.</p>
    <label class="field"><span>Console password</span>
      <input id="password" type="password" autocomplete="current-password" autofocus></label>
    <button type="submit" class="primary wide">Enter</button>
    <p id="login-error" class="msg error" role="alert"></p>
  </form>
</div>

<main id="main" class="pkg-page hidden">
  <header class="pkg-page-head">
    <a class="brand" href="/"><span class="mark" aria-hidden="true">NM</span>
      <span><b>NMesh</b><span>Package</span></span></a>
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
<script src="/package.js"></script>
</body>
</html>
"""


PAGE_JS = r"""
// ── /package ────────────────────────────────────────────────────────────────
// One record, described. The id is in the fragment, like /node — a fragment is
// not sent to the server, and this page is opened by pasting a link as often as
// by clicking one.

function packageId(){
  const raw = (location.hash || "").replace(/^#/, "").trim().toLowerCase();
  return /^[0-9a-f]{40}$/.test(raw) ? raw : "";
}

async function draw(){
  const id = packageId();
  if(!id){
    setHTML("view", errorHTML("No package named",
      "This page needs a package id in its address."));
    return;
  }
  await PACKAGES.mount("view", id, {hideOpen:true});
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


PAGE_CSS = """
.pkg-page{max-width:760px;margin:0 auto;padding:var(--s-4) var(--s-4) var(--s-8);
  display:flex;flex-direction:column;gap:var(--s-4)}
.pkg-page-head{display:flex;align-items:center;gap:var(--s-3)}
.framed .pkg-page-head{display:none}
.framed .pkg-page{padding-top:var(--s-3)}
"""
