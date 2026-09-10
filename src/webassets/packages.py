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
   break agreement. Every publisher of it, which is **not** the quorum's
   number: that one counts only the keys this operator chose, and it is printed
   beside the box that spends it. One word over both quantities is how the card
   came to read "2" above a row reading "0 of 1".
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
/* Every line under the controls takes the whole row. "1 of 2" is short enough
   to sit in the gap beside the last checkbox, where it reads as that
   checkbox's label rather than as the count it is. */
.pkg-watch p{flex:1 0 100%;margin:0}
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
  // re-reading the address bar — and how it was mounted, so a repaint draws
  // the same card rather than a fresh one with every button back on it.
  current: null,
  opts: {},

  // Every call goes through here, and it **never throws**. A rejected fetch —
  // the console closing a connection, the network going — used to unwind out
  // of `mount`, which had already drawn a skeleton and never drew anything
  // else. "It loads for ever" is what a caller that can throw looks like from
  // the outside.
  async ask(path, method, body){
    try{
      return await apiJson(path, method, body);
    }catch(_){
      return {ok:false, data:{error:"The console did not answer."}};
    }
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
    return row.kind === "core" ? "node software" : "app";
  },

  // The one sentence a record makes. "Serves" is not a lesser version of
  // "publishes": both mean the bytes are here and can be had from here, and
  // only one of them also carries the key they were signed with.
  roleLabel(row){
    return row.published ? "publishes" : "serves";
  },

  // A hit is a button: the whole row opens the card, because a row with one
  // link inside it is a row people click everywhere except the link.
  hitHTML(row){
    return '<button class="pkg-hit" data-pkg-open="' + esc(row.id) + '">' +
      '<span class="pkg-mark" aria-hidden="true">' +
        icon(row.kind === "core" ? "server" : "window") + "</span>" +
      '<span class="grow"><b>' + esc(row.name) + "</b>" +
      '<span class="tiny">' + esc(row.version) + " · " +
        esc(this.kindLabel(row)) + " · " + esc(this.roleLabel(row)) +
      "</span></span>" +
      (row.trusted ? badge("pinned", "ok") : "") +
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
    const badges = [badge(this.kindLabel(row)),
                    badge(this.roleLabel(row), row.published ? null : "warn")];
    if(row.trusted) badges.push(badge("signing key pinned", "ok"));
    if(row.mine) badges.push(badge("this node"));
    if(row.equivocated)
      badges.push(badge("offered two different releases as one version", "bad"));
    const facts = [
      ["Version", esc(row.version)],
      ["Signed by", row.signer_id
        ? '<code class="inline">' + esc(shortId(row.signer_id)) + "</code>"
        : '<span class="muted">not stated here</span>'],
      ["Held by", '<code class="inline">' + esc(shortId(row.node_id)) + "</code>"],
      ["Said", esc(fmtAgo(Date.now() / 1000 - row.ts))],
      // Every publisher of this same code, forks under another name excluded.
      // Not the quorum's number: that one counts only the keys this operator
      // chose, it lives beside the box that spends it, and calling both of them
      // "agreeing" is how this card came to read 2 above a row reading 0 of 1.
      ["Publishers of this code", String(row.attesters)],
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
    if(!row.published)
      return '<p class="muted small">This node holds these bytes and will ' +
        "serve them — it did not sign them, and it is not saying who did. The " +
        "release itself carries that signature, and it is checked before " +
        "anything is installed either way. Open a copy that was published to " +
        "pin the key.</p>";
    if(row.kind === "core" && !row.trusted)
      return '<p class="muted small">This signing key is not pinned here, so ' +
        "nothing signed with it can replace this node's code. Pinning it is one " +
        "press and a confirmation — the key came with the record and was " +
        "checked against a signature it made, so there is nothing to copy " +
        "across.</p>";
    if(!row.trusted)
      return '<p class="muted small">Installing this yourself asks for no ' +
        "pin: you pressed the button. Pinning the key that signed it is for " +
        "the other half — a new version landing on its own, which waits until " +
        "enough keys you chose have signed the same code. It is accepted for " +
        "this app, never for the node's own program.</p>";
    return "";
  },

  // Which of the two acts is the primary one is the whole design here. Nothing
  // signed by an unpinned key may replace this node's program, so for node
  // software the pin *is* the button and Install comes after it. An app needs
  // no pin to be installed by hand — a person pressed it — so Install stays
  // primary and the pin sits beside it, for the operator who wants a version
  // of it to land without being asked.
  actionsHTML(row, opts){
    const buttons = [];
    // Downloading works off any copy: the bytes are content-addressed and the
    // hash was signed, so who hands them over is not a question worth asking.
    buttons.push('<a class="btn" download href="/api/packages/' +
      encodeURIComponent(row.id) + '/download">' + icon("arrowDown") +
      " Download</a>");
    const core = row.kind === "core";
    if(core && !row.trusted)
      buttons.push('<button class="primary" data-pkg-act="trust"' +
        (row.published ? "" : " disabled") + ">Pin the signing key</button>");
    else
      buttons.push('<button class="primary" data-pkg-act="install">' +
        "Install</button>");
    if(!core && row.published && !row.trusted)
      buttons.push('<button data-pkg-act="trust">Pin the signing key</button>');
    if(!opts.hideOpen)
      buttons.push('<button data-pkg-act="page">Open on its own</button>');
    return '<div class="pkg-actions">' + buttons.join("") + "</div>";
  },

  // The toggle, the two settings it governs, and how far this code already
  // agrees with itself. The state is the node's: `row.subscription` is what it
  // holds for this *package*, so the box is ticked on whichever copy of it an
  // operator opens.
  watchHTML(row, opts){
    if(opts.hideWatch) return "";
    const sub = row.subscription || null;
    const quorum = sub ? sub.quorum : 1;
    const enough = row.agreeing >= row.needed;
    return '<div class="pkg-watch">' +
      '<label class="check"><input type="checkbox" data-pkg-act="watch"' +
        (sub ? " checked" : "") + "><span>Watch for new versions</span></label>" +
      '<label class="check"><input type="checkbox" data-pkg-act="auto"' +
        (sub && sub.auto ? " checked" : "") + (sub ? "" : " disabled") +
        "><span>Install them without asking</span></label>" +
      '<label class="pkg-quorum"><span>Signing keys that must agree</span>' +
        '<input type="number" min="1" max="8" data-pkg-act="quorum" value="' +
        esc(quorum) + '"' + (sub ? "" : " disabled") + "></label>" +
      (sub ? '<p class="small' + (enough ? " muted" : "") + '">Keys you chose ' +
        "that have signed this code: " +
        esc(row.agreeing + " of " + row.needed) +
        (enough ? "." : " — an install without asking waits for the rest.") +
        "</p>" : "") +
      '<p class="muted small">Agreement is over the package’s code with its ' +
      "documentation left out, so two publishers whose release notes differ " +
      "still agree, and it counts keys you chose one at a time: the key you " +
      "pinned this release under, and any other you endorsed. One is that key " +
      "on its own; more holds an install without asking back until that many " +
      "have signed the same code.</p></div>";
  },

  // -- acting on a card ----------------------------------------------------

  async mount(container, id, options){
    const element = typeof container === "string" ? $(container) : container;
    if(!element) return;
    // Kept, because every repaint after this one has to draw the same card:
    // `repaint` took its own options and no caller had any to give, so one
    // press on /package grew the button that opens /package.
    this.opts = options || {};
    setHTML(element, skeletonHTML(3));
    const row = await this.read(id, true);
    if(!row){
      setHTML(element, errorHTML("Package not found",
        "Nothing here holds a record with that id any more, or the console " +
        "could not answer for it."));
      return;
    }
    this.current = row;
    setHTML(element, this.cardHTML(row, this.opts));
    // Once per element, like the node view: this runs again on every
    // hashchange, and a second pair of listeners is one press acting twice.
    if(!element.dataset.pkgWired){
      element.dataset.pkgWired = "1";
      element.addEventListener("click", (event) => this.onClick(event, element));
      element.addEventListener("change", (event) => this.onChange(event, element));
    }
  },

  async repaint(element){
    if(!this.current) return;
    const row = await this.read(this.current.id, false);
    if(!row) return;
    this.current = row;
    setHTML(element, this.cardHTML(row, this.opts));
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
      // The subscription's own id when the node gave us one: it names the
      // package, and the record this card sits on may not be the copy the row
      // was filed from. The node takes either name.
      const sub = row.subscription || null;
      await this.ask("/api/packages/subscribe", "POST",
                     {id:sub ? sub.id : row.id, on:false});
      toast("No longer watching " + row.name);
      await this.repaint(element);
      return;
    }
    // Read defensively: a mount that hides the watch block has neither of
    // these, and reading `.checked` off nothing throws inside a handler.
    const card = element.querySelector(".pkg-card");
    const box = card && card.querySelector('[data-pkg-act="auto"]');
    const field = card && card.querySelector('[data-pkg-act="quorum"]');
    const auto = !!(box && box.checked);
    const quorum = parseInt((field && field.value) || "1", 10) || 1;
    const {ok, data} = await this.ask("/api/packages/subscribe", "POST",
                                      {id:row.id, on:true, auto, quorum});
    if(!ok){ setMessage("pkg-status", data.error || "Could not save", true); return; }
    toast("Watching " + row.name);
    await this.repaint(element);
  },

  // What a pin *means* follows the record it is made from, and the node decides
  // that — the page only has to say it. Pinning from an app is a party to that
  // app; pinning from node software is somebody who may replace this program.
  // One dialog that said the second sentence over both would have been asking
  // for the machine on an app's page.
  async trust(row, element){
    const core = row.kind === "core";
    const agreed = await confirmAction({
      title:"Pin the key that signed " + row.name + "?",
      confirmLabel:"Pin this key",
      danger:core,
      body:'<p class="muted small">' + (core
        ? "Whoever holds this key can offer code that replaces this node’s " +
          "own. "
        : "This key signs " + esc(row.name) + ". Pinning it counts its " +
          "signature as one you chose, which is what a version of this app " +
          "installing itself waits for — it is not accepted for this node’s " +
          "own code, and nothing here can make it so. ") +
        "The key below came inside the record and was checked against a " +
        "signature it made — so it is the key that signed what you are " +
        "looking at, and nothing else. It is the only thing pinned: not the " +
        "node that handed it over, not a name.</p>" +
        '<div class="kv"><div>Signing key</div><div><code class="inline">' +
        esc(row.signer_id || "") + "</code></div>" +
        "<div>Accepted for</div><div>" +
        esc(core ? "this node’s own code" : "apps signed by it") +
        "</div></div>" +
        (core ? '<label class="check"><input id="pkg-pin-auto" type="checkbox">' +
          "<span>Let this key install its releases without asking</span></label>"
          : ""),
    });
    if(!agreed) return;
    const auto = !!($("pkg-pin-auto") || {}).checked;
    const {ok, data} = await this.ask("/api/packages/trust", "POST",
                                      {id:row.id, confirm:true, auto});
    if(!ok){ setMessage("pkg-status", data.error || "Could not pin", true); return; }
    toast("Pinned " + shortId(row.signer_id), "ok");
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
    const {ok} = await CHANNEL.ask("node.state");
    if(ok){ enter(); return; }
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
