"""
Contacts sub-page (/contacts).

The address books of this node: who is in them, which of them are shared with
other nodes, and the invitations waiting for an answer. Served by the console
and backed by the ContactsBridge; same session, same strict CSP.

Three panes, one attribute: books, the contacts of one book, one contact.
``data-view`` says which of them is on screen, and the stylesheet decides from
the width whether that means one pane (a phone) or all three (a desktop). The
page never asks which device it is on.

Everything here is prefixed ``ct-``, for the reason the chat page's prefix
exists: the generic names belong to :mod:`.ui`.
"""

from . import ui

CONTACTS_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="theme-color" content="#f6f8fa" media="(prefers-color-scheme: light)">
<meta name="theme-color" content="#0a0e13" media="(prefers-color-scheme: dark)">
<title>NMesh Contacts</title>
<script src="/theme.js"></script>
<script src="/i18n.js"></script>
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<link rel="stylesheet" href="/contacts.css">
</head>
<body data-app-name="NMesh Contacts" data-ctx-needs="apps"
      data-ctx-local="" data-ctx-local-key="contacts.ctx_local">

<div id="login" class="gate hidden">
  <form id="login-form">
    <div class="mark" aria-hidden="true">NM</div>
    <div><p class="eyebrow" data-i18n="contacts.title"></p><h1 data-i18n="login.title"></h1></div>
    <p class="muted small" data-i18n="contacts.login.hint"></p>
    <label class="field"><span data-i18n="login.password"></span>
      <input id="password" type="password" autocomplete="current-password" autofocus></label>
    <button type="submit" class="primary wide" data-i18n="login.enter"></button>
    <p id="err" class="msg error" role="alert"></p>
  </form>
</div>

<a class="skip" href="#main" data-i18n="contacts.skip"></a>
""" + ui.CTX_BAR + """
<div id="app" class="ct hidden" data-view="books">

  <!-- the books: this page's navigation -->
  <aside class="ct-books" aria-labelledby="books-title">
    <header class="ct-head">
      <h1 id="books-title" class="ct-title" data-i18n="contacts.title"></h1>
      <span class="grow"></span>
      <button id="theme-toggle" class="icon"></button>
      <button id="book-new" class="icon" data-i18n-attr="title:contacts.book.new;aria-label:contacts.book.new"></button>
    </header>
    <div id="offers" class="ct-offers" hidden></div>
    <div id="book-list" class="ct-booklist" role="list"></div>
    <div class="ct-foot"><a class="btn ghost wide" href="/" data-i18n="common.back_to_console"></a></div>
  </aside>

  <!-- the contacts of the open book -->
  <section class="ct-list" aria-labelledby="book-title">
    <header class="ct-head">
      <button id="to-books" class="icon ct-back" data-i18n-attr="aria-label:common.back;title:common.back"></button>
      <div class="ct-bookname">
        <h2 id="book-title" class="truncate"></h2>
        <span id="book-sub" class="tiny muted truncate"></span>
      </div>
      <button id="book-share" class="icon" data-i18n-attr="title:contacts.share.title;aria-label:contacts.share.title"></button>
      <button id="book-menu" class="icon" data-i18n-attr="title:contacts.book.more;aria-label:contacts.book.more"></button>
    </header>
    <div class="ct-search">
      <label class="search"><span class="sr-only" data-i18n="contacts.search.label"></span>
        <input id="search" type="search" autocomplete="off" spellcheck="false"
               data-i18n-attr="placeholder:contacts.search.placeholder"></label>
    </div>
    <div id="rows" class="ct-rows" role="list"></div>
    <div class="ct-foot">
      <button id="add" class="primary wide" data-i18n="contacts.add"></button>
    </div>
  </section>

  <!-- one contact -->
  <main id="main" class="ct-detail">
    <div id="blank" class="ct-blank">
      <div class="mark" aria-hidden="true">NM</div>
      <div class="t" data-i18n="contacts.blank.title"></div>
      <div class="h" data-i18n="contacts.blank.hint"></div>
    </div>
    <form id="editor" class="ct-editor" hidden autocomplete="off">
      <header class="ct-head">
        <button type="button" id="to-list" class="icon ct-back" data-i18n-attr="aria-label:common.back;title:common.back"></button>
        <h2 id="editor-title" class="truncate"></h2>
        <span class="grow"></span>
        <button type="button" id="fav" class="icon" aria-pressed="false"
                data-i18n-attr="title:contacts.favourite;aria-label:contacts.favourite"></button>
      </header>
      <div class="ct-editor-body">
        <label class="field"><span data-i18n="contacts.name"></span>
          <input id="f-name" maxlength="64" data-i18n-attr="placeholder:contacts.name.placeholder"></label>
        <div class="field"><span data-i18n="contacts.nodes"></span>
          <div id="f-nodes" class="ct-nodes"></div>
          <div class="toolbar"><button type="button" id="node-add" data-i18n="contacts.node.add"></button></div>
          <small class="hint" data-i18n="contacts.nodes.hint"></small></div>
        <label class="field"><span data-i18n="contacts.note"></span>
          <textarea id="f-note" rows="3" maxlength="512" data-i18n-attr="placeholder:contacts.note.placeholder"></textarea></label>
        <label class="field" id="f-move-field"><span data-i18n="contacts.move"></span>
          <select id="f-move"></select></label>
        <p id="editor-msg" class="msg" role="status"></p>
      </div>
      <footer class="ct-editor-foot">
        <button type="button" id="del" class="danger" data-i18n="common.delete"></button>
        <span class="grow"></span>
        <a id="chat-link" class="btn" href="/chat" data-i18n="contacts.chat"></a>
        <button type="submit" id="save" class="primary" data-i18n="common.save"></button>
      </footer>
    </form>
  </main>
</div>

<dialog id="people" aria-labelledby="people-title">
  <div class="sheet">
    <header class="sheet-head"><h2 id="people-title" data-i18n="contacts.people.title"></h2>
      <button class="icon" data-close="people" data-i18n-attr="aria-label:common.close"></button></header>
    <div class="sheet-body">
      <label class="search"><span class="sr-only" data-i18n="contacts.people.label"></span>
        <input id="people-q" type="search" autocomplete="off" spellcheck="false"
               data-i18n-attr="placeholder:contacts.people.placeholder"></label>
      <div id="people-rows" class="ct-people"></div>
      <div class="field"><span data-i18n="contacts.people.byid"></span>
        <div class="toolbar"><input id="people-id" class="mono grow" spellcheck="false" maxlength="40">
          <button id="people-add" class="primary" data-i18n="common.add"></button></div></div>
    </div>
  </div>
</dialog>

<dialog id="bookform" aria-labelledby="bookform-title">
  <div class="sheet">
    <header class="sheet-head"><h2 id="bookform-title"></h2>
      <button class="icon" data-close="bookform" data-i18n-attr="aria-label:common.close"></button></header>
    <div class="sheet-body">
      <label class="field"><span data-i18n="contacts.book.name"></span>
        <input id="bf-name" maxlength="48"></label>
      <div class="field"><span data-i18n="contacts.book.color"></span>
        <div id="bf-colors" class="ct-colors" role="radiogroup"></div></div>
    </div>
    <footer class="sheet-foot"><button id="bf-save" class="primary" data-i18n="common.save"></button></footer>
  </div>
</dialog>

<dialog id="share" aria-labelledby="share-title">
  <div class="sheet">
    <header class="sheet-head"><h2 id="share-title" data-i18n="contacts.share.title"></h2>
      <button class="icon" data-close="share" data-i18n-attr="aria-label:common.close"></button></header>
    <div class="sheet-body">
      <p class="muted small" data-i18n="contacts.share.hint"></p>
      <div id="share-members" class="ct-members"></div>
      <div id="share-add" class="field"><span data-i18n="contacts.share.add"></span>
        <div class="toolbar">
          <input id="sh-node" class="mono grow" spellcheck="false" maxlength="40"
                 data-i18n-attr="placeholder:contacts.share.node">
          <select id="sh-role" data-i18n-attr="aria-label:contacts.share.role">
            <option value="read" data-i18n="contacts.role.read"></option>
            <option value="write" data-i18n="contacts.role.write"></option>
          </select>
          <button id="sh-send" class="primary" data-i18n="contacts.share.invite"></button>
        </div>
        <div id="sh-hits" class="ct-people"></div>
      </div>
      <p id="share-msg" class="msg" role="status"></p>
    </div>
  </div>
</dialog>

<dialog id="menu-dialog" aria-labelledby="menu-title">
  <div class="sheet">
    <header class="sheet-head"><h2 id="menu-title" data-i18n="contacts.book.more"></h2>
      <button class="icon" data-close="menu-dialog" data-i18n-attr="aria-label:common.close"></button></header>
    <div class="sheet-body ct-menu">
      <button id="m-rename" data-i18n="contacts.book.rename"></button>
      <button id="m-default" data-i18n="contacts.book.default"></button>
      <button id="m-export" data-i18n="contacts.export"></button>
      <label class="btn" id="m-import-label"><span data-i18n="contacts.import"></span>
        <input id="m-import" type="file" accept=".vcf,text/vcard,text/x-vcard" hidden></label>
      <button id="m-delete" class="danger"></button>
    </div>
  </div>
</dialog>

<dialog id="confirm-dialog" aria-labelledby="confirm-title">
  <div class="sheet">
    <header class="sheet-head"><h2 id="confirm-title"></h2></header>
    <div class="sheet-body"><div id="confirm-body"></div></div>
    <footer class="sheet-foot">
      <button id="confirm-cancel" data-i18n="common.cancel"></button>
      <button id="confirm-ok" class="primary" data-i18n="common.confirm"></button>
    </footer>
  </div>
</dialog>

<div id="toasts" class="toasts" role="status" aria-live="polite"></div>
<script src="/contacts.js"></script>
</body>
</html>
"""

CONTACTS_PAGE_CSS = """
/* Every grid track is minmax(0,…) and every text holder min-width:0 — the two
   rules the chat page learned the hard way (a long word otherwise widens the
   page past a phone). */
:root{--ct-books-w:248px; --ct-list-w:340px}
.ct{display:grid;height:100dvh;overflow:hidden;background:var(--canvas);
  grid-template-columns:var(--ct-books-w) minmax(0,var(--ct-list-w)) minmax(0,1fr)}
.ct>*{min-width:0;min-height:0}
.ct-books,.ct-list,.ct-detail{display:flex;flex-direction:column}
.ct-books{background:var(--rail);border-right:1px solid var(--border)}
.ct-list{border-right:1px solid var(--border);background:var(--surface)}
.ct-head{display:flex;align-items:center;gap:var(--s-1);padding:var(--s-3);
  border-bottom:1px solid var(--border);min-width:0}
.ct-title{font-size:var(--fs-md);font-weight:650;margin:0}
.ct-bookname{flex:1 1 auto;min-width:0;display:flex;flex-direction:column}
.ct-bookname h2{margin:0;font-size:var(--fs-md);font-weight:650}
.ct-foot{padding:var(--s-3) var(--s-3) calc(var(--s-3) + env(safe-area-inset-bottom));
  border-top:1px solid var(--border)}
.ct-back{display:none}

.ct-booklist,.ct-rows{flex:1 1 auto;min-height:0;overflow-y:auto;overflow-x:hidden;
  padding:var(--s-2);overscroll-behavior:contain}
.ct-book,.ct-row{display:flex;align-items:center;gap:var(--s-3);width:100%;min-width:0;
  padding:var(--s-2) var(--s-3);border:0;background:transparent;text-align:left;
  border-radius:var(--r-md);cursor:pointer}
.ct-book:hover,.ct-row:hover{background:var(--surface-2);border-color:transparent}
.ct-book[aria-current="true"],.ct-row[aria-current="true"]{background:var(--accent-soft)}
.ct-dot{width:12px;height:12px;border-radius:50%;flex:none;background:var(--accent)}
.ct-dot[data-c="green"]{background:var(--ok,#2da44e)}
.ct-dot[data-c="teal"]{background:#1b9e9e}
.ct-dot[data-c="amber"]{background:#d29922}
.ct-dot[data-c="red"]{background:var(--danger,#cf222e)}
.ct-dot[data-c="purple"]{background:#8250df}
.ct-dot[data-c="pink"]{background:#bf3989}
.ct-dot[data-c="gray"]{background:var(--text-faint)}
.ct-body{flex:1 1 auto;min-width:0;display:flex;flex-direction:column;gap:1px}
.ct-name{font-weight:600;font-size:var(--fs-sm)}
.ct-sub{font-size:var(--fs-xs);color:var(--text-muted)}
.ct-av{width:36px;height:36px;flex:none;border-radius:50%;display:grid;place-items:center;
  background:var(--accent-soft);color:var(--accent);font:700 var(--fs-xs)/1 var(--font)}
.ct-fav{flex:none;color:var(--accent);width:1em;height:1em}

.ct-offers{padding:var(--s-2);display:flex;flex-direction:column;gap:var(--s-2);
  border-bottom:1px solid var(--border)}
.ct-offer{padding:var(--s-3);border:1px solid var(--border);border-radius:var(--r-md);
  background:var(--surface);display:flex;flex-direction:column;gap:var(--s-2)}
.ct-offer .btn-row{display:flex;gap:var(--s-2)}

.ct-search{padding:var(--s-3)}
.ct-search .search{max-width:none;width:100%}
.ct-detail{background:var(--canvas)}
.ct-blank{flex:1;display:flex;flex-direction:column;align-items:center;justify-content:center;
  gap:var(--s-3);padding:var(--s-6);text-align:center}
.ct-blank .t{font-size:var(--fs-lg);font-weight:620}
.ct-blank .h{color:var(--text-muted);max-width:44ch}
.ct-editor{display:flex;flex-direction:column;flex:1 1 auto;min-height:0}
.ct-editor[hidden],.ct-blank[hidden]{display:none}
.ct-editor-body{flex:1 1 auto;min-height:0;overflow-y:auto;padding:var(--s-4);
  display:flex;flex-direction:column;gap:var(--s-4);max-width:640px;width:100%}
.ct-editor-foot{display:flex;gap:var(--s-2);align-items:center;padding:var(--s-3) var(--s-4)
  calc(var(--s-3) + env(safe-area-inset-bottom));border-top:1px solid var(--border);
  background:var(--surface)}
.ct-nodes{display:flex;flex-direction:column;gap:var(--s-2)}
.ct-node{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,9rem) auto;gap:var(--s-2);align-items:center}
.ct-node-name{grid-column:1 / -1;font-size:var(--fs-xs);color:var(--text-muted)}
#fav[aria-pressed="true"]{color:var(--accent)}
#fav[aria-pressed="true"] .ic{fill:currentColor}

.ct-people,.ct-members{display:flex;flex-direction:column;gap:var(--s-1);margin:var(--s-2) 0}
.ct-person{display:flex;align-items:center;gap:var(--s-3);padding:var(--s-2);
  border-radius:var(--r-md);min-width:0}
.ct-person:hover{background:var(--surface-2)}
.ct-person .btn-row{display:flex;gap:var(--s-1);flex:none}
.ct-colors{display:flex;gap:var(--s-2);flex-wrap:wrap}
.ct-colors button{width:28px;height:28px;border-radius:50%;padding:0;border:2px solid transparent}
.ct-colors button[aria-checked="true"]{border-color:var(--text)}
.ct-menu{display:flex;flex-direction:column;gap:var(--s-2)}

/* Wide enough for all three panes: no pane is ever hidden. */
@media (max-width: 1000px){
  .ct{grid-template-columns:minmax(0,1fr)}
  .ct[data-view="books"] .ct-list,.ct[data-view="books"] .ct-detail,
  .ct[data-view="list"] .ct-books,.ct[data-view="list"] .ct-detail,
  .ct[data-view="detail"] .ct-books,.ct[data-view="detail"] .ct-list{display:none}
  .ct-back{display:inline-flex}
  .ct-books{border-right:0}.ct-list{border-right:0}
  .ct-editor-body{max-width:none}
}
@media (min-width: 1001px){
  #to-books,#to-list{display:none}
}
"""

CONTACTS_PAGE_JS = r"""
// ── contacts page ───────────────────────────────────────────────────────────
// Polled like chat, rendered the same way: keyed rows, and the editor is never
// rebuilt under somebody who is typing in it.

const COLORS = ["blue","green","teal","amber","red","purple","pink","gray"];
let ST = {me:"", books:[], offers:[], contacts:[], names:{}, book:""};
let bookId = "", current = null, draft = null, dirty = false, timer = null, hits = [];
let formMode = "create";

SESSION.onLost = () => {
  if(timer){ clearInterval(timer); timer = null; }
  EVENTS.stop();
  $("app").classList.add("hidden"); $("login").classList.remove("hidden");
};
SESSION.load();

function view(next){
  const app = $("app");
  if(next) app.dataset.view = next;
  return app.dataset.view;
}
const initials = (s) => { s = (s || "").trim(); return s ? s.slice(0, 2).toUpperCase() : "?"; };
const bookOf = (id) => ST.books.find((b) => b.id === id) || null;
const isNode = (s) => /^[0-9a-f]{40}$/.test(s);
const nodeName = (id) => ST.names[id] || "";

// What a refusal is called is the page's word, never the node's: the node sends
// a stable code (`why`) and each language says it in its own.
function failure(body){
  if(body && body.why && STRINGS["contacts.err." + body.why]) return t("contacts.err." + body.why);
  if(body && body.error === "permission") return t("contacts.err.permission");
  return t("common.failed");
}
async function call(op, data){
  let res;
  try{ res = await api("/api/contacts/" + op, "POST", data || {}); }
  catch(error){ if(isStale(error)) throw error; return {ok:false, body:{}}; }
  const body = await res.json().catch(() => ({}));
  return {ok: res.ok && body.ok !== false, body};
}

// ---- polling ---------------------------------------------------------------
async function poll(){
  let j;
  try{ j = await FEED.read("/api/contacts/state", {book: bookId}); }
  catch(_){ j = null; }
  if(!j) return;
  ST = Object.assign(ST, j);
  if(!bookId || !bookOf(bookId)) bookId = j.book || "";
  renderBooks(); renderOffers(); renderBook(); renderRows();
  if(current && current !== "new" && !dirty){
    const found = ST.contacts.find((c) => c.id === current);
    if(found) fillEditor(found, true); else closeEditor();
  }
}
function pickBook(id){
  bookId = id; current = null; closeEditor(); view("list");
  $("search").value = "";
  poll();
}

// ---- books -----------------------------------------------------------------
function roleText(b){
  if(b.role === "owner") return b.shared ? t("contacts.book.shared_out") : t("contacts.book.private");
  return b.role === "write" ? t("contacts.book.shared_edit") : t("contacts.book.shared_read");
}
function renderBooks(){
  const host = $("book-list");
  if(!ST.books.length){ setHTML(host, emptyHTML(t("contacts.none.title"), t("contacts.none.hint"))); return; }
  setHTML(host, ST.books.map((b) =>
    '<button type="button" class="ct-book" role="listitem" data-id="' + esc(b.id) + '" aria-current="' +
      (b.id === bookId) + '"><span class="ct-dot" data-c="' + esc(b.color) + '"></span>' +
    '<span class="ct-body"><span class="ct-name truncate">' + esc(b.name) + '</span>' +
    '<span class="ct-sub truncate">' + esc(roleText(b)) + "</span></span>" +
    '<span class="badge">' + esc(b.count) + "</span></button>").join(""));
}
function renderBook(){
  const b = bookOf(bookId);
  $("book-title").textContent = b ? b.name : "";
  $("book-sub").textContent = b ? roleText(b) + (b.role !== "owner" && nodeName(b.owner)
    ? " · " + nodeName(b.owner) : "") : "";
  $("add").disabled = !b || !b.writable;
  $("book-share").hidden = !b || b.role !== "owner";
  $("book-share").innerHTML = icon("share");
  $("book-menu").innerHTML = icon("dots");
  $("f-move-field").hidden = !b || !b.writable ||
    ST.books.filter((x) => x.writable && x.id !== bookId).length === 0;
}
function renderOffers(){
  const host = $("offers");
  host.hidden = !ST.offers.length;
  setHTML(host, ST.offers.map((o) =>
    '<div class="ct-offer"><div><b>' + esc(o.name) + '</b><div class="tiny muted">' +
    esc(t("contacts.offer.from", {who: nodeName(o.from) || shortId(o.from)})) + " · " +
    esc(o.role === "write" ? t("contacts.role.write") : t("contacts.role.read")) + " · " +
    esc(t("count.contact", {count: o.count})) + '</div></div>' +
    '<div class="btn-row"><button class="primary" data-a="yes" data-b="' + esc(o.book) +
    '" data-f="' + esc(o.from) + '">' + esc(t("contacts.offer.accept")) + '</button>' +
    '<button data-a="no" data-b="' + esc(o.book) + '" data-f="' + esc(o.from) + '">' +
    esc(t("contacts.offer.decline")) + "</button></div></div>").join(""));
}

// ---- the rows --------------------------------------------------------------
function rowName(c){ return c.name || nodeName(c.nodes[0] && c.nodes[0].id) || shortId(c.nodes[0] && c.nodes[0].id); }
function renderRows(){
  const q = ($("search").value || "").trim().toLowerCase();
  const rows = ST.contacts.filter((c) => !q || (rowName(c) + " " + c.note + " " +
    c.nodes.map((n) => n.id + " " + n.label + " " + nodeName(n.id)).join(" ")).toLowerCase().includes(q));
  const host = $("rows");
  if(!rows.length){
    setHTML(host, q ? emptyHTML(t("contacts.nomatch.title"), t("contacts.nomatch.hint"))
                    : emptyHTML(t("contacts.empty.title"), t("contacts.empty.hint")));
    return;
  }
  setHTML(host, rows.map((c) =>
    '<button type="button" class="ct-row" role="listitem" data-id="' + esc(c.id) + '" aria-current="' +
      (c.id === current) + '"><span class="ct-av">' + esc(initials(rowName(c))) + '</span>' +
    '<span class="ct-body"><span class="ct-name truncate">' + esc(rowName(c)) + '</span>' +
    '<span class="ct-sub truncate">' + esc(c.nodes.length
      ? (nodeName(c.nodes[0].id) || c.nodes[0].label || shortId(c.nodes[0].id))
      : t("contacts.no_node")) + "</span></span>" +
    (c.fav ? icon("star", "", "ct-fav") : "") + "</button>").join(""));
}

// ---- the editor ------------------------------------------------------------
function nodeRow(n){
  const known = nodeName(n.id);
  return '<div class="ct-node"><input class="mono" data-f="id" maxlength="40" spellcheck="false" value="' +
    esc(n.id) + '" aria-label="' + esc(t("contacts.node.id")) + '">' +
    '<input data-f="label" maxlength="32" value="' + esc(n.label) + '" placeholder="' +
    esc(t("contacts.node.label")) + '" aria-label="' + esc(t("contacts.node.label")) + '">' +
    '<button type="button" class="icon sm" data-a="drop" aria-label="' + esc(t("common.remove")) + '">' +
    icon("close") + "</button>" +
    (known ? '<div class="ct-node-name">' + esc(t("contacts.node.known", {name: known})) + "</div>" : "") +
    "</div>";
}
function paintNodes(){
  setHTML("f-nodes", draft.nodes.map(nodeRow).join(""));
}
function readNodes(){
  draft.nodes = $$(".ct-node", $("f-nodes")).map((row) => ({
    id: row.querySelector('[data-f="id"]').value.trim().toLowerCase(),
    label: row.querySelector('[data-f="label"]').value.trim()}));
}
function setFav(on){
  draft.fav = !!on;
  $("fav").setAttribute("aria-pressed", String(!!on));
  $("fav").innerHTML = icon("star");
}
function fillEditor(entry, quiet){
  const b = bookOf(bookId);
  const writable = !!(b && b.writable);
  draft = {id: entry.id || "", name: entry.name || "", note: entry.note || "", fav: !!entry.fav,
           nodes: (entry.nodes || []).map((n) => ({id:n.id, label:n.label || ""}))};
  $("blank").hidden = true; $("editor").hidden = false;
  $("editor-title").textContent = entry.id ? rowName(entry) : t("contacts.new");
  $("f-name").value = draft.name; $("f-note").value = draft.note;
  paintNodes(); setFav(draft.fav);
  for(const el of $$("input,textarea", $("editor"))) el.disabled = !writable;
  $("save").hidden = $("del").hidden = $("node-add").hidden = !writable;
  $("fav").disabled = !writable;
  const first = (draft.nodes[0] || {}).id;
  $("chat-link").hidden = !first;
  if(first) $("chat-link").setAttribute("href", "/chat#c/" + first);
  fillMove();
  setMessage("editor-msg", writable ? "" : t("contacts.err.read_only"));
  dirty = false;
  if(!quiet) view("detail");
}
function fillMove(){
  const targets = ST.books.filter((x) => x.writable && x.id !== bookId);
  setHTML("f-move", '<option value="">' + esc(t("contacts.move.keep")) + "</option>" +
    targets.map((x) => '<option value="' + esc(x.id) + '">' + esc(x.name) + "</option>").join(""));
}
function closeEditor(){
  current = null; draft = null; dirty = false;
  $("editor").hidden = true; $("blank").hidden = false;
  if(view() === "detail") view("list");
  renderRows();
}
function openContact(id){
  const entry = ST.contacts.find((c) => c.id === id);
  if(!entry) return;
  current = id; fillEditor(entry); renderRows();
}
function newContact(seed){
  current = "new";
  fillEditor(Object.assign({id:"", name:"", note:"", fav:false, nodes:[]}, seed || {}));
  dirty = true;
  $("f-name").focus();
  renderRows();
}
async function saveContact(event){
  event.preventDefault();
  if(!draft) return;
  readNodes();
  draft.name = $("f-name").value.trim(); draft.note = $("f-note").value.trim();
  const nodes = draft.nodes.filter((n) => n.id || n.label);
  if(nodes.some((n) => !isNode(n.id))){ setMessage("editor-msg", t("contacts.err.bad_node"), true); return; }
  const payload = {book: bookId, name: draft.name, nodes, note: draft.note, fav: draft.fav};
  if(draft.id) payload.id = draft.id;
  await withBusy($("save"), async () => {
    const r = await call("save", payload);
    if(!r.ok){ setMessage("editor-msg", failure(r.body), true); return; }
    const target = $("f-move").value;
    if(target && r.body.contact)
      await call("move", {book: bookId, to: target, id: r.body.contact.id});
    toast(t("common.saved"));
    dirty = false; current = r.body.contact ? r.body.contact.id : null;
    if(target){ closeEditor(); }
    await poll();
    if(current) openContact(current);
  });
}
async function deleteContact(){
  if(!draft || !draft.id) { closeEditor(); return; }
  const ok = await confirmAction({title: t("contacts.delete.title"),
    body: "<p>" + esc(t("contacts.delete.body", {name: rowName(draft)})) + "</p>",
    confirmLabel: t("common.delete"), danger: true});
  if(!ok) return;
  const r = await call("delete", {book: bookId, id: draft.id});
  if(!r.ok){ toast(failure(r.body), "danger"); return; }
  closeEditor(); poll();
}

// ---- books: create, rename, delete, share -----------------------------------
function openBookForm(mode){
  formMode = mode;
  const b = mode === "rename" ? bookOf(bookId) : null;
  $("bookform-title").textContent = t(mode === "rename" ? "contacts.book.rename" : "contacts.book.new");
  $("bf-name").value = b ? b.name : "";
  paintColors(b ? b.color : "blue");
  $("bookform").showModal();
  $("bf-name").focus();
}
function paintColors(chosen){
  setHTML("bf-colors", COLORS.map((c) =>
    '<button type="button" role="radio" class="ct-dot" data-c="' + c + '" data-v="' + c +
    '" aria-checked="' + (c === chosen) + '" aria-label="' + esc(t("contacts.color." + c)) + '"></button>').join(""));
}
async function saveBookForm(){
  const name = $("bf-name").value.trim();
  if(!name) return;
  const picked = document.querySelector('#bf-colors [aria-checked="true"]');
  const chosen = picked ? picked.dataset.v : "blue";
  const r = formMode === "rename"
    ? await call("book", {action:"rename", book: bookId, name, color: chosen})
    : await call("book", {action:"create", name, color: chosen});
  if(!r.ok){ toast(failure(r.body), "danger"); return; }
  $("bookform").close();
  if(r.body.book) bookId = r.body.book;
  poll();
}
async function deleteBook(){
  const b = bookOf(bookId); if(!b) return;
  $("menu-dialog").close();
  const ok = await confirmAction({
    title: t(b.role === "owner" ? "contacts.book.delete_title" : "contacts.book.leave_title"),
    body: "<p>" + esc(t(b.role === "owner" ? "contacts.book.delete_body" : "contacts.book.leave_body",
                         {name: b.name})) + "</p>",
    confirmLabel: t(b.role === "owner" ? "common.delete" : "contacts.book.leave"), danger: true});
  if(!ok) return;
  const r = await call("book", {action:"delete", book: bookId});
  if(!r.ok){ toast(failure(r.body), "danger"); return; }
  bookId = ""; closeEditor(); view("books"); poll();
}
function memberRows(b){
  const rows = Object.keys(b.members || {}).map((node) => {
    const m = b.members[node];
    return '<div class="ct-person"><span class="ct-body"><span class="ct-name truncate">' +
      esc(nodeName(node) || shortId(node)) + '</span><span class="ct-sub">' +
      esc(m.state === "offered" ? t("contacts.share.pending") : t("contacts.share.active")) + " · " +
      esc(m.role === "write" ? t("contacts.role.write") : t("contacts.role.read")) + "</span></span>" +
      '<span class="btn-row"><button data-a="role" data-n="' + esc(node) + '" data-r="' +
      (m.role === "write" ? "read" : "write") + '">' +
      esc(t(m.role === "write" ? "contacts.share.make_read" : "contacts.share.make_write")) + "</button>" +
      '<button class="danger" data-a="revoke" data-n="' + esc(node) + '">' +
      esc(t("contacts.share.revoke")) + "</button></span></div>";
  });
  return rows.length ? rows.join("") : '<p class="muted small">' + esc(t("contacts.share.nobody")) + "</p>";
}
function openShare(){
  const b = bookOf(bookId); if(!b || b.role !== "owner") return;
  setHTML("share-members", memberRows(b));
  setMessage("share-msg", "");
  $("share").showModal();
}
async function invite(node){
  node = (node || "").trim().toLowerCase();
  if(!isNode(node)){ setMessage("share-msg", t("contacts.err.bad_node"), true); return; }
  const r = await call("share", {book: bookId, node, role: $("sh-role").value});
  if(!r.ok){ setMessage("share-msg", failure(r.body), true); return; }
  setMessage("share-msg", t(r.body.sent ? "contacts.share.sent" : "contacts.share.queued"));
  $("sh-node").value = ""; setHTML("sh-hits", "");
  await poll(); setHTML("share-members", memberRows(bookOf(bookId)));
}

// ---- people: everyone on the network who answers to a name ------------------
async function findPeople(q){
  q = (q || "").trim();
  const host = $("people-rows");
  if(!q){ setHTML(host, ""); return; }
  setHTML(host, skeletonHTML(3));
  const r = await apiJson("/api/contacts/people?q=" + encodeURIComponent(q));
  hits = (r.data && r.data.results) || [];
  if(!hits.length){ setHTML(host, emptyHTML(t("contacts.people.none"), t("contacts.people.none_hint"))); return; }
  setHTML(host, hits.map((h, i) => personRow(h, i)).join(""));
}
function personRow(h, i){
  if(h.kind === "contact")
    return '<div class="ct-person"><span class="ct-av">' + esc(initials(h.name)) + '</span>' +
      '<span class="ct-body"><span class="ct-name truncate">' + esc(h.name) + '</span><span class="ct-sub truncate">' +
      esc(h.book_name) + '</span></span><span class="badge">' + esc(t("contacts.people.saved")) + "</span></div>";
  return '<div class="ct-person"><span class="ct-av">' + esc(initials(h.pseudo)) + '</span>' +
    '<span class="ct-body"><span class="ct-name truncate">' + esc(h.pseudo) + '</span><span class="ct-sub mono truncate">' +
    esc(shortId(h.node)) + '</span></span>' +
    (h.saved ? '<span class="badge">' + esc(t("contacts.people.saved")) + "</span>"
             : '<button class="primary" data-a="pick" data-i="' + i + '">' + esc(t("common.add")) + "</button>") + "</div>";
}
function openPeople(){
  $("people-q").value = ""; $("people-id").value = ""; setHTML("people-rows", "");
  $("people").showModal(); $("people-q").focus();
}
function addFromPeople(node, name){
  $("people").close();
  newContact({name: name || "", nodes: [{id: node, label: ""}]});
}

// ---- import / export -------------------------------------------------------
async function exportBook(){
  $("menu-dialog").close();
  const res = await api("/api/contacts/export?book=" + encodeURIComponent(bookId));
  if(!res.ok){ toast(t("common.failed"), "danger"); return; }
  const b = bookOf(bookId);
  saveBytes((b ? b.name : "contacts").replace(/[^A-Za-z0-9._-]+/g, "_") + ".vcf",
            new Uint8Array(await res.arrayBuffer()), "text/vcard");
}
async function importFile(file){
  $("menu-dialog").close();
  if(!file) return;
  const text = await file.text();
  const r = await call("import", {book: bookId, text});
  if(!r.ok){ toast(failure(r.body), "danger"); return; }
  toast(t("contacts.import.done", {count: r.body.added}),
        "", r.body.skipped ? t("contacts.import.skipped", {count: r.body.skipped}) : "");
  poll();
}

// ---- wiring ----------------------------------------------------------------
function bind(){
  $("book-new").innerHTML = icon("plus");
  $("book-new").addEventListener("click", () => openBookForm("create"));
  $("to-books").innerHTML = icon("back"); $("to-list").innerHTML = icon("back");
  $("to-books").addEventListener("click", () => view("books"));
  $("to-list").addEventListener("click", () => { closeEditor(); view("list"); });
  $("fav").innerHTML = icon("star");
  $("fav").addEventListener("click", () => { if(draft){ setFav(!draft.fav); dirty = true; } });
  $$("[data-close]").forEach((b) => { b.innerHTML = icon("close");
    b.addEventListener("click", () => $(b.dataset.close).close()); });
  $("book-list").addEventListener("click", (e) => {
    const b = e.target.closest(".ct-book"); if(b) pickBook(b.dataset.id);
  });
  $("offers").addEventListener("click", async (e) => {
    const b = e.target.closest("button"); if(!b) return;
    const r = await call("answer", {book: b.dataset.b, from: b.dataset.f, accept: b.dataset.a === "yes"});
    if(!r.ok) toast(failure(r.body), "danger");
    poll();
  });
  $("rows").addEventListener("click", (e) => {
    const r = e.target.closest(".ct-row"); if(r) openContact(r.dataset.id);
  });
  $("search").addEventListener("input", debounce(renderRows, 120));
  $("add").addEventListener("click", openPeople);
  $("editor").addEventListener("submit", saveContact);
  $("editor").addEventListener("input", () => { dirty = true; });
  $("del").addEventListener("click", deleteContact);
  $("node-add").addEventListener("click", () => {
    readNodes(); draft.nodes.push({id:"", label:""}); paintNodes();
    const last = $$(".ct-node input", $("f-nodes")); if(last.length) last[last.length - 2].focus();
  });
  $("f-nodes").addEventListener("click", (e) => {
    const b = e.target.closest('[data-a="drop"]'); if(!b) return;
    readNodes(); const at = $$(".ct-node", $("f-nodes")).indexOf(b.closest(".ct-node"));
    draft.nodes.splice(at, 1); paintNodes(); dirty = true;
  });
  $("people-q").addEventListener("input", debounce((e) => findPeople(e.target.value), 300));
  $("people-rows").addEventListener("click", (e) => {
    const b = e.target.closest('[data-a="pick"]'); if(!b) return;
    const h = hits[Number(b.dataset.i)]; if(h) addFromPeople(h.node, h.pseudo);
  });
  $("people-add").addEventListener("click", () => {
    const id = $("people-id").value.trim().toLowerCase();
    if(isNode(id)) addFromPeople(id, nodeName(id)); else toast(t("contacts.err.bad_node"), "warn");
  });
  $("bf-colors").addEventListener("click", (e) => {
    const b = e.target.closest("button"); if(b) paintColors(b.dataset.v);
  });
  $("bf-save").addEventListener("click", saveBookForm);
  $("book-share").addEventListener("click", openShare);
  $("sh-send").addEventListener("click", () => invite($("sh-node").value));
  $("sh-node").addEventListener("input", debounce(async (e) => {
    const q = e.target.value.trim();
    if(q.length < 2 || isNode(q.toLowerCase())){ setHTML("sh-hits", ""); return; }
    const r = await apiJson("/api/contacts/people?q=" + encodeURIComponent(q));
    hits = ((r.data && r.data.results) || []).filter((h) => h.kind === "node");
    setHTML("sh-hits", hits.map((h, i) => '<div class="ct-person"><span class="ct-body"><span class="ct-name truncate">' +
      esc(h.pseudo) + '</span><span class="ct-sub mono truncate">' + esc(shortId(h.node)) + '</span></span>' +
      '<button data-a="invite" data-i="' + i + '">' + esc(t("contacts.share.invite")) + "</button></div>").join(""));
  }, 300));
  $("sh-hits").addEventListener("click", (e) => {
    const b = e.target.closest('[data-a="invite"]'); if(!b) return;
    const h = hits[Number(b.dataset.i)]; if(h) invite(h.node);
  });
  $("share-members").addEventListener("click", async (e) => {
    const b = e.target.closest("button"); if(!b) return;
    const r = b.dataset.a === "revoke"
      ? await call("unshare", {book: bookId, node: b.dataset.n})
      : await call("share", {book: bookId, node: b.dataset.n, role: b.dataset.r});
    if(!r.ok) setMessage("share-msg", failure(r.body), true);
    await poll(); setHTML("share-members", memberRows(bookOf(bookId)));
  });
  $("book-menu").addEventListener("click", () => {
    const b = bookOf(bookId); if(!b) return;
    $("m-rename").hidden = b.role !== "owner";
    $("m-default").hidden = b.default || b.role !== "owner";
    $("m-import-label").hidden = !b.writable;
    $("m-delete").textContent = t(b.role === "owner" ? "contacts.book.delete" : "contacts.book.leave");
    $("menu-dialog").showModal();
  });
  $("m-rename").addEventListener("click", () => { $("menu-dialog").close(); openBookForm("rename"); });
  $("m-default").addEventListener("click", async () => {
    $("menu-dialog").close(); await call("book", {action:"default", book: bookId}); poll();
  });
  $("m-export").addEventListener("click", exportBook);
  $("m-import").addEventListener("change", (e) => { importFile(e.target.files[0]); e.target.value = ""; });
  $("m-delete").addEventListener("click", deleteBook);
  PALETTE.add(t("contacts.add"), t("palette.action"), openPeople);
  PALETTE.add(t("contacts.book.new"), t("palette.action"), () => openBookForm("create"));
  PALETTE.add(t("common.back_to_console"), t("palette.goto"), () => { window.location = "/"; });
}

// ---- auth and boot ---------------------------------------------------------
async function enter(token){
  const headers = {};
  if(token) headers["Authorization"] = "Bearer " + token;
  const res = await fetch("/api/contacts/state", {headers});
  if(!res.ok) return false;
  if(token) SESSION.set(token);
  $("login").classList.add("hidden"); $("app").classList.remove("hidden");
  mountShell();
  CONTEXT.confirm();
  REFRESH.mount();
  await poll();
  if(timer) clearInterval(timer);
  timer = setInterval(poll, 2000);
  return true;
}
$("login-form").addEventListener("submit", async (e) => {
  e.preventDefault(); setMessage("err", "");
  await withBusy(e.submitter || $("login-form").querySelector("button"), async () => {
    try{
      const res = await fetch("/api/login", {method:"POST",
        headers:{"Content-Type":"application/json"},
        body:JSON.stringify({password:$("password").value})});
      if(!res.ok){
        const body = await res.json().catch(() => ({}));
        setMessage("err", body.error || t("login.failed"), true); return;
      }
      $("password").value = "";
      await enter((await res.json()).token);
    }catch(_){ setMessage("err", t("login.unreachable"), true); }
  });
});
bind();
(function(){
  let token = null;
  try{ token = sessionStorage.getItem("nmesh_token"); }catch(_){}
  enter(token).then((ok) => { if(!ok) $("login").classList.remove("hidden"); });
})();
"""
