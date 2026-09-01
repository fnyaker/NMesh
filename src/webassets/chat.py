"""
Chat sub-page (/chat).

A full chat client — identity, contact directory, 1:1 and group conversations,
files, replies and reactions — served by the console and backed by the
ChatBridge. Same session, same strict CSP: no inline script, no external
resource.

Three panes, one grid: the conversation list, the thread, and the node card of
whoever you are talking to. Which of them is on screen is a single attribute
(``data-view``) rather than a set of classes that can contradict each other, so
"what am I looking at" has exactly one answer at any width.

Everything here is prefixed ``ch-``. The design system in :mod:`.ui` owns the
generic names, and a page that redefines one of them (this page used to redefine
``.msg``) silently changes a component for itself alone — which is the drift the
split exists to prevent.
"""

from . import ui

CHAT_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="theme-color" content="#f6f8fa" media="(prefers-color-scheme: light)">
<meta name="theme-color" content="#0a0e13" media="(prefers-color-scheme: dark)">
<title>NMesh Chat</title>
<script src="/theme.js"></script>
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<link rel="stylesheet" href="/chat.css">
</head>
<body data-app-name="NMesh Chat"
      data-ctx-local="Chat runs on this node — its conversations are not part of managing another.">

<div id="login" class="gate hidden">
  <form id="login-form">
    <div class="mark" aria-hidden="true">NM</div>
    <div><p class="eyebrow">Chat</p><h1>Sign in</h1></div>
    <p class="muted small">Chat uses the console password of this node. Messages are end-to-end
      encrypted; relays carry them without being able to read them.</p>
    <label class="field"><span>Console password</span>
      <input id="password" type="password" autocomplete="current-password" autofocus></label>
    <button type="submit" class="primary wide">Enter</button>
    <p id="err" class="msg error" role="alert"></p>
  </form>
</div>

<a class="skip" href="#main">Skip to the conversation</a>
""" + ui.CTX_BAR + """
<div id="app" class="ch hidden" data-view="list">

  <!-- ── the conversation list: this page's navigation ──────────────────── -->
  <aside class="ch-side" aria-label="Conversations">
    <header class="ch-side-head">
      <button id="me-btn" class="ch-me" title="Your profile">
        <span id="me-av-slot" class="ch-av-slot"></span>
        <span class="ch-me-txt">
          <span id="me-name" class="ch-me-name truncate">…</span>
          <span id="me-sub" class="mono ch-me-sub truncate"></span>
        </span>
      </button>
      <button id="theme-toggle" class="icon" aria-label="Switch theme"><svg class="ic" viewBox="0 0 24 24" aria-hidden="true"><path d="M20.5 14.8A8.6 8.6 0 0 1 9.2 3.5a8.6 8.6 0 1 0 11.3 11.3Z"/></svg></button>
      <button id="new-btn" class="icon" title="New chat" aria-label="New chat"><svg class="ic" viewBox="0 0 24 24" aria-hidden="true"><path d="M12 20h9M16.4 3.6a2.1 2.1 0 0 1 3 3L7.5 18.5 3.5 19.5l1-4Z"/></svg></button>
    </header>

    <div class="ch-side-search">
      <label class="search"><span class="sr-only">Search chats and people</span>
        <input id="side-search" type="search" placeholder="Search chats and people…"
               autocomplete="off" spellcheck="false"></label>
      <div id="side-results" class="ch-drop" hidden></div>
    </div>

    <div id="chat-list" class="ch-list" role="list"></div>

    <div class="ch-side-foot"><a class="btn ghost wide" href="/">Back to console</a></div>
  </aside>

  <!-- ── the thread ─────────────────────────────────────────────────────── -->
  <main id="main" class="ch-main">
    <div id="empty" class="ch-blank">
      <div class="mark" aria-hidden="true">NM</div>
      <div class="t">No conversation open</div>
      <div class="h">Pick someone on the left, or start a new chat. Everything you send is
        end-to-end encrypted between the two nodes.</div>
      <button id="empty-new" class="primary">Start a chat</button>
    </div>

    <section id="conv" class="ch-conv" hidden>
      <header class="ch-head">
        <button id="back-btn" class="icon ch-back" title="Back to the list" aria-label="Back to the list"><svg class="ic" viewBox="0 0 24 24" aria-hidden="true"><path d="M15 18 9 12l6-6"/></svg></button>
        <button id="info-btn" class="ch-peer">
          <span id="conv-av-slot" class="ch-av-slot"></span>
          <span class="ch-peer-txt">
            <span id="conv-title" class="ch-peer-name truncate"></span>
            <span id="conv-sub" class="tiny muted truncate"></span>
          </span>
        </button>
        <button id="del-conv" class="icon ch-head-act" title="Delete conversation"
                aria-label="Delete conversation"><svg class="ic" viewBox="0 0 24 24" aria-hidden="true"><path d="M3 6h18M8 6V4h8v2M18.5 6l-1 14h-11l-1-14M10 10.5v6M14 10.5v6"/></svg></button>
      </header>

      <div class="ch-logwrap">
        <div id="log" class="ch-log" tabindex="0" role="log" aria-label="Messages"></div>
        <button id="jump" class="ch-jump" hidden>New messages ↓</button>
      </div>

      <div id="reply-bar" class="ch-reply" hidden>
        <span class="ch-reply-mark" aria-hidden="true"></span>
        <span class="grow">
          <span id="reply-who" class="ch-reply-who"></span>
          <span id="reply-text" class="muted small truncate"></span>
        </span>
        <button id="reply-cancel" class="icon sm" aria-label="Cancel reply"><svg class="ic" viewBox="0 0 24 24" aria-hidden="true"><path d="M18 6 6 18M6 6l12 12"/></svg></button>
      </div>

      <form id="send-form" class="ch-composer">
        <button type="button" id="attach-btn" class="icon" title="Attach a file"
                aria-label="Attach a file"><svg class="ic" viewBox="0 0 24 24" aria-hidden="true"><path d="M21 11.6 12.4 20a5.5 5.5 0 1 1-7.8-7.8l8.6-8.5a3.7 3.7 0 0 1 5.2 5.2l-8.6 8.5a1.8 1.8 0 1 1-2.6-2.6l7.9-7.8"/></svg></button>
        <input id="file-input" type="file" hidden>
        <div class="ch-input">
          <textarea id="msg" rows="1" placeholder="Message" autocomplete="off"
                    aria-label="Message"></textarea>
        </div>
        <button type="button" id="emoji-btn" class="icon" title="Emoji" aria-label="Emoji"><svg class="ic" viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M9 10h.01M15 10h.01M8.5 14.5a4.5 4.5 0 0 0 7 0"/></svg></button>
        <button type="submit" id="send-btn" class="ch-send" title="Send" aria-label="Send"><svg class="ic" viewBox="0 0 24 24" aria-hidden="true"><path d="M22 2 11 13M22 2l-7 20-4-9-9-4Z"/></svg></button>
      </form>
    </section>
  </main>

  <!-- Who you are talking to, as the console describes them: the same view the
       node page serves, mounted here rather than framed. -->
  <aside id="peer-panel" class="ch-aside" hidden aria-label="Node details">
    <header class="ch-aside-head">
      <button id="peer-back" class="icon ch-back" title="Back" aria-label="Back"><svg class="ic" viewBox="0 0 24 24" aria-hidden="true"><path d="M15 18 9 12l6-6"/></svg></button>
      <h2>Node</h2><span class="grow"></span>
      <button id="peer-panel-close" class="icon" aria-label="Close"><svg class="ic" viewBox="0 0 24 24" aria-hidden="true"><path d="M18 6 6 18M6 6l12 12"/></svg></button>
    </header>
    <div id="peer-view" class="ch-aside-body"></div>
  </aside>
</div>

<div id="ctx" class="ch-ctx" hidden></div>
<div id="emoji-pop" class="ch-emoji" hidden></div>
<div id="viewer" class="ch-viewer" hidden><img id="viewer-img" alt=""></div>

<dialog id="settings" aria-labelledby="settings-title">
  <div class="sheet">
    <header class="sheet-head"><h2 id="settings-title">Your profile</h2>
      <button class="icon" data-close="settings" aria-label="Close"><svg class="ic" viewBox="0 0 24 24" aria-hidden="true"><path d="M18 6 6 18M6 6l12 12"/></svg></button></header>
    <div class="sheet-body">
      <div class="ch-prof">
        <span id="set-av" class="ch-av big"></span>
        <div class="btn-row">
          <label class="btn">Change photo<input id="av-input" type="file" accept="image/*" hidden></label>
          <button id="av-clear" class="danger">Remove</button>
        </div>
      </div>
      <label class="field"><span>Display name</span>
        <input id="set-name" maxlength="50" placeholder="Your name">
        <small class="hint">This is your node's name, shown everywhere it appears —
          not just in chat.</small></label>
      <label class="field"><span>Bio</span>
        <textarea id="set-bio" maxlength="1024" rows="3" placeholder="A few words about you"></textarea></label>
      <div class="field"><span>Your node id</span>
        <div class="copyable"><code id="set-id" class="mono"></code></div>
        <span class="hint">This is what someone else needs to start a chat with you.</span></div>
      <hr>
      <h3>Preferences</h3>
      <label class="field" for="set-details"><span>Opening someone&rsquo;s node details</span>
        <select id="set-details">
          <option value="panel">Beside the conversation</option>
          <option value="window">In a separate window</option>
          <option value="tab">In a new tab</option>
        </select>
        <span class="hint">Tapping the name at the top of a conversation shows what
          this node knows about that identity — the link, its addresses, and what
          each of you may do to the other.</span></label>
    </div>
    <footer class="sheet-foot"><button id="save-prof" class="primary">Save profile</button></footer>
  </div>
</dialog>

<dialog id="newchat" aria-labelledby="nc-title">
  <div class="sheet">
    <header class="sheet-head"><h2 id="nc-title">New chat</h2>
      <button class="icon" data-close="newchat" aria-label="Close"><svg class="ic" viewBox="0 0 24 24" aria-hidden="true"><path d="M18 6 6 18M6 6l12 12"/></svg></button></header>
    <div class="sheet-body">
      <div class="segmented" role="tablist">
        <button id="nc-tab-dm" role="tab" aria-selected="true">Find people</button>
        <button id="nc-tab-grp" role="tab" aria-selected="false">New group</button>
      </div>
      <div id="nc-dm" class="stack">
        <label class="search"><span class="sr-only">Search by name</span>
          <input id="nc-search" type="search" placeholder="Search by name…" spellcheck="false"></label>
        <div id="nc-results" class="ch-results"></div>
        <div class="field"><span>Or paste a node id</span>
          <div class="toolbar"><input id="nc-id" class="mono grow" placeholder="40-hex node id" spellcheck="false">
            <button id="nc-add" class="primary">Start</button></div></div>
      </div>
      <div id="nc-grp" class="stack" hidden>
        <label class="field"><span>Group name</span>
          <input id="grp-name" maxlength="64" placeholder="Group name"></label>
        <div class="field"><span>Members</span><div id="grp-members" class="ch-results"></div></div>
        <button id="grp-create" class="primary">Create group</button>
      </div>
    </div>
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
    <input id="palette-input" type="text" placeholder="Run an action…"
           autocomplete="off" spellcheck="false" aria-controls="palette-list">
    <div id="palette-list" class="list" role="listbox"></div>
  </div>
</dialog>

<div id="toasts" class="toasts" role="status" aria-live="polite"></div>
<script src="/chat.js"></script>
</body>
</html>
"""

CHAT_PAGE_CSS = """
/* ── the shell ───────────────────────────────────────────────────────────────
   Three rules hold this page together. Each of them is a bug that was really
   here, so none of them is decoration:

   1. every grid track is `minmax(0,…)`, never a bare `1fr`. A `1fr` track takes
      its *minimum* from its content, so one long word in a preview line pushed
      the whole page 126px wider than a phone and the page scrolled sideways.
   2. everything that can hold text carries `min-width:0` and wraps anywhere.
      A flex or grid child refuses to shrink below its longest word otherwise,
      and a pasted URL is one very long word.
   3. `overflow:hidden` here is the backstop. If rules 1 and 2 are ever broken
      again, the page clips instead of scrolling sideways — a visible bug beats
      an unusable one.

   `dvh`, not `vh`: on a phone `100vh` is the viewport *without* the browser's
   own bars, so the composer sits under them and the last message is cut. */
.ch{display:grid;grid-template-columns:var(--page-side-w) minmax(0,1fr);
  height:100dvh;overflow:hidden;background:var(--canvas)}
.ch>*{min-width:0;min-height:0}
:root{--page-side-w:320px; --page-aside-w:380px; --page-bubble-max:min(58ch,80%)}

/* The node card takes a third column when there is room for one. */
.ch[data-view="peer"]{grid-template-columns:var(--page-side-w) minmax(0,1fr) minmax(0,var(--page-aside-w))}
.ch[data-view="peer"] .ch-aside{display:flex}

/* ── the list pane ──────────────────────────────────────────────────────── */
.ch-side{display:flex;flex-direction:column;background:var(--rail);
  border-right:1px solid var(--border)}
.ch-side-head{display:flex;align-items:center;gap:var(--s-1);padding:var(--s-3);
  border-bottom:1px solid var(--border)}
.ch-me{flex:1 1 auto;min-width:0;display:flex;align-items:center;gap:var(--s-3);
  justify-content:flex-start;text-align:left;border:0;background:transparent;
  padding:var(--s-1) var(--s-2)}
.ch-me:hover{background:var(--surface-2);border-color:transparent}
.ch-me-txt{display:flex;flex-direction:column;min-width:0}
.ch-me-name{font-weight:620;font-size:var(--fs-sm)}
.ch-me-sub{font-size:var(--fs-2xs);color:var(--text-faint)}
.ch-side-search{padding:var(--s-3);position:relative}
.ch-side-search .search{max-width:none;width:100%}
.ch-side-foot{padding:var(--s-3) var(--s-3)
              calc(var(--s-3) + env(safe-area-inset-bottom));
  border-top:1px solid var(--border)}
.ch-list{flex:1 1 auto;min-height:0;overflow-y:auto;overflow-x:hidden;
  padding:0 var(--s-2) var(--s-2);overscroll-behavior:contain}

.ch-row{display:flex;gap:var(--s-3);align-items:center;padding:var(--s-2);
  border-radius:var(--r-md);cursor:pointer;min-width:0;width:100%;
  border:0;background:transparent;text-align:left}
.ch-row:hover{background:var(--surface-2);border-color:transparent}
.ch-row[aria-current="true"]{background:var(--accent-soft)}
.ch-row[aria-current="true"] .ch-row-name{color:var(--accent)}
.ch-row-body{flex:1 1 auto;min-width:0;display:flex;flex-direction:column;gap:1px}
.ch-row-top{display:flex;align-items:baseline;gap:var(--s-2);min-width:0}
.ch-row-name{flex:1 1 auto;min-width:0;font-weight:600;font-size:var(--fs-sm)}
.ch-row-time{flex:none;font-size:var(--fs-2xs);color:var(--text-faint)}
.ch-row-prev{flex:1 1 auto;min-width:0;font-size:var(--fs-xs);color:var(--text-muted)}
.ch-row-prev i{font-style:normal;color:var(--accent)}
.ch-row .badge{flex:none}

/* ── avatars ────────────────────────────────────────────────────────────── */
/* A slot the script refills, so replacing the picture never replaces the
   element an event listener is attached to. */
.ch-av-slot{display:contents}
.ch-av{width:36px;height:36px;flex:none;border-radius:50%;display:grid;place-items:center;
  background:var(--accent-soft);color:var(--accent);font:700 var(--fs-xs)/1 var(--font);
  overflow:hidden;user-select:none}
.ch-av img{width:100%;height:100%;object-fit:cover}
.ch-av.big{width:76px;height:76px;font-size:var(--fs-xl)}
.ch-av.sm{width:26px;height:26px;font-size:9px}

/* ── the thread pane ────────────────────────────────────────────────────── */
.ch-main{display:flex;flex-direction:column;min-width:0;min-height:0}
.ch-blank{flex:1 1 auto;display:flex;flex-direction:column;align-items:center;
  justify-content:center;gap:var(--s-3);padding:var(--s-6);text-align:center}
.ch-blank[hidden]{display:none}
.ch-blank .t{font-size:var(--fs-lg);font-weight:620}
.ch-blank .h{color:var(--text-muted);max-width:44ch}
.ch-conv{display:flex;flex-direction:column;flex:1 1 auto;min-height:0;min-width:0}
.ch-conv[hidden]{display:none}

.ch-head{display:flex;align-items:center;gap:var(--s-1);min-width:0;
  padding:var(--s-2) var(--s-3);border-bottom:1px solid var(--border);
  background:var(--surface)}
.ch-peer{flex:1 1 auto;min-width:0;display:flex;align-items:center;gap:var(--s-3);
  justify-content:flex-start;text-align:left;border:0;background:transparent;
  padding:var(--s-1) var(--s-2)}
.ch-peer:hover{background:var(--surface-2);border-color:transparent}
.ch-peer-txt{display:flex;flex-direction:column;min-width:0}
.ch-peer-name{font-weight:620;font-size:var(--fs-md)}
.ch-head-act{flex:none}
.ch-back{display:none;flex:none}

/* ── the log ─────────────────────────────────────────────────────────────
   A flex column whose children are `flex:none`. Without that they inherit
   `flex-shrink:1`, and once the messages are taller than the pane the browser
   shrinks every one of them instead of scrolling: bubbles crushed to 20px,
   overlapping each other, and no way to read the conversation. */
.ch-logwrap{position:relative;flex:1 1 auto;min-height:0;display:flex}
.ch-log{flex:1 1 auto;min-width:0;min-height:0;overflow-y:auto;overflow-x:hidden;
  overscroll-behavior:contain;scroll-behavior:auto;
  padding:var(--s-4) var(--s-4) var(--s-3);
  display:flex;flex-direction:column;gap:2px}
.ch-log>*{flex:none}
/* A short conversation sits at the bottom, where the next message will appear,
   without breaking scrolling once it is long. */
.ch-log>:first-child{margin-top:auto}
.ch-log:focus-visible{outline-offset:-2px}

/* Sticky, so "which day am I reading" survives scrolling back through a long
   conversation. It therefore floats over the messages, and needs the depth of
   something that floats — an outlined pill alone reads as text on text. */
.ch-day{align-self:center;position:sticky;top:var(--s-1);z-index:2;margin:var(--s-3) 0;
  padding:2px 10px;border-radius:var(--r-full);background:var(--surface);
  border:1px solid var(--border);box-shadow:var(--shadow-2);
  font-size:var(--fs-2xs);color:var(--text-muted);white-space:nowrap}

/* The width cap lives on the *row*, not on the bubble, and that is not a
   detail: the row is a flex item of the log, so it has a definite width to take
   a percentage of. A percentage max-width on the bubble resolved against a row
   that was itself shrink-to-fit — a circular constraint the browser settles by
   undersizing, which wrapped "line three" onto two lines inside a bubble with
   room to spare. `fit-content` + `margin-left:auto` right-aligns my own
   messages without ever making the row's width depend on its content's. */
.ch-m{display:flex;gap:var(--s-2);align-items:flex-end;min-width:0;
  width:fit-content;max-width:var(--page-bubble-max);margin-top:var(--s-3)}
.ch-m.mine{flex-direction:row-reverse;margin-left:auto}
.ch-m.grouped{margin-top:0}
.ch-m.grouped .ch-av{visibility:hidden}
@media (prefers-reduced-motion:no-preference){
  .ch-m.fresh{animation:ch-in .18s var(--ease) both}
}
@keyframes ch-in{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:none}}

/* The bubble is where arbitrary text lands, so wrapping is not optional here.
   `break-word`, deliberately, and not `anywhere`: both break a 300-character
   word, but `anywhere` also counts those breaks when the browser works out the
   box's intrinsic width, which collapses a shrink-to-fit bubble towards one
   character — a three-line message came out one narrow column. `break-word`
   sizes the bubble to its longest line, lets `max-width` cap it, and breaks the
   unbreakable token inside that cap. */
.ch-bubble{position:relative;min-width:0;
  background:var(--surface);border:1px solid var(--border);border-radius:var(--r-lg);
  padding:var(--s-2) var(--s-3);box-shadow:var(--shadow-1);font-size:var(--fs-sm);
  overflow-wrap:break-word}
.ch-m.mine .ch-bubble{background:var(--accent-soft);border-color:var(--accent-line)}
.ch-bubble.deleted{opacity:.65;font-style:italic}
.ch-bubble.target{outline:2px solid var(--accent);outline-offset:2px}
.ch-who{font-size:var(--fs-2xs);font-weight:700;color:var(--accent);margin-bottom:2px}
.ch-txt{white-space:pre-wrap;overflow-wrap:break-word}
.ch-txt a{overflow-wrap:break-word}
/* `nowrap` is what stops a two-word message from being squeezed into a bubble
   too narrow for its own timestamp, which then wrapped onto three lines. The
   bubble now cannot be narrower than its meta line. */
.ch-meta{display:flex;align-items:center;gap:4px;justify-content:flex-end;
  white-space:nowrap;font-size:var(--fs-2xs);color:var(--text-faint);margin-top:2px}
.ch-meta .edited{font-style:italic}
.ch-meta .tick{color:var(--accent)}
/* The delivery marks sit in 11px text, where the shared 1.15em would be a
   smudge; they are the one place an icon is deliberately larger than its line. */
.ch-meta .ic{width:1.35em;height:1.35em;stroke-width:2.4}

.ch-quote{display:flex;flex-direction:column;gap:1px;padding:4px 8px;margin-bottom:4px;
  border-left:2px solid var(--accent);background:var(--surface-2);border-radius:var(--r-sm);
  cursor:pointer;font-size:var(--fs-xs);min-width:0}
.ch-quote .qn{font-weight:700;color:var(--accent)}
.ch-quote .qt{color:var(--text-muted);overflow:hidden;text-overflow:ellipsis;
  white-space:nowrap;min-width:0}

/* Bounded in both axes: a portrait photo would otherwise take a whole screen
   and push the conversation out of reach. */
.ch-media{display:block;max-width:100%;max-height:min(48dvh,420px);width:auto;
  border-radius:var(--r-md);cursor:zoom-in;margin:-2px 0 4px}
.ch-file{display:flex;align-items:center;gap:var(--s-2);padding:var(--s-2);
  border-radius:var(--r-md);background:var(--surface-2);color:inherit;
  text-decoration:none;min-width:0}
.ch-file:hover{text-decoration:none;background:var(--surface-3)}
.ch-file .fi{flex:none;display:flex;color:var(--text-muted);font-size:20px}
.ch-file .fm{display:flex;flex-direction:column;min-width:0}
.ch-file .fn{font-weight:600;font-size:var(--fs-sm);overflow-wrap:break-word}

.ch-reacts{display:flex;flex-wrap:wrap;gap:4px;margin-top:4px}
.ch-react{padding:1px 7px;border-radius:var(--r-full);background:var(--surface-2);
  border:1px solid var(--border);font-size:var(--fs-2xs);cursor:pointer;
  min-height:0;color:var(--text-muted)}
.ch-react.me{border-color:var(--accent);background:var(--accent-soft);color:var(--accent)}

/* Reading back through a conversation must not be interrupted by an autoscroll,
   so a new message while you are up there offers itself instead of jumping. */
.ch-jump{position:absolute;left:50%;bottom:var(--s-3);transform:translateX(-50%);
  z-index:3;min-height:var(--ctl-h-sm);padding:0 var(--s-3);font-size:var(--fs-xs);
  font-weight:600;border-radius:var(--r-full);background:var(--accent);
  color:var(--accent-fg);border-color:var(--accent);box-shadow:var(--shadow-2)}
.ch-jump:hover{background:var(--accent-hover);color:var(--accent-fg)}
.ch-jump[hidden]{display:none}

/* ── composing ──────────────────────────────────────────────────────────── */
.ch-reply{display:flex;align-items:center;gap:var(--s-2);min-width:0;
  padding:var(--s-2) var(--s-3);border-top:1px solid var(--border);
  background:var(--surface-2);font-size:var(--fs-sm)}
.ch-reply[hidden]{display:none}
.ch-reply>.grow{display:flex;align-items:baseline;gap:var(--s-2);min-width:0}
.ch-reply-mark{width:2px;align-self:stretch;background:var(--accent);border-radius:2px;flex:none}
.ch-reply-who{font-weight:700;color:var(--accent);flex:none}
.ch-composer{display:flex;align-items:flex-end;gap:var(--s-2);min-width:0;
  padding:var(--s-3) var(--s-3) calc(var(--s-3) + env(safe-area-inset-bottom));
  border-top:1px solid var(--border);background:var(--surface)}
.ch-composer>button{flex:none}
.ch-input{flex:1 1 auto;min-width:0}
.ch-composer textarea{width:100%;min-height:var(--ctl-h);max-height:min(40dvh,160px);
  resize:none;border-radius:var(--r-xl);padding:7px var(--s-4);overflow-y:auto;
  /* 16px: anything smaller and iOS zooms the page on focus, which leaves the
     composer off-screen and the layout at a scale nobody asked for. */
  font-size:max(var(--fs-md),16px)}
.ch-send{flex:none;width:var(--ctl-h);height:var(--ctl-h);padding:0;border-radius:50%;
  background:var(--accent);color:var(--accent-fg);border-color:var(--accent);
  font-size:14px}
.ch-send:hover{background:var(--accent-hover);color:var(--accent-fg)}
.ch-send:disabled{opacity:.5}

/* ── the node card beside the conversation ──────────────────────────────── */
.ch-aside{display:none;flex-direction:column;min-width:0;min-height:0;
  background:var(--canvas);border-left:1px solid var(--border)}
.ch-aside-head{display:flex;align-items:center;gap:var(--s-2);flex:none;
  padding:var(--s-2) var(--s-4);border-bottom:1px solid var(--border);
  background:var(--surface)}
.ch-aside-head h2{font-size:var(--fs-md)}
.ch-aside-body{flex:1 1 auto;min-height:0;overflow-y:auto;overflow-x:hidden;
  padding:var(--s-4);padding-bottom:calc(var(--s-4) + env(safe-area-inset-bottom))}

/* ── search results, menus, overlays ────────────────────────────────────── */
.ch-drop{position:absolute;left:var(--s-3);right:var(--s-3);top:calc(100% - var(--s-2));
  z-index:30;background:var(--surface);border:1px solid var(--border);
  border-radius:var(--r-md);box-shadow:var(--shadow-3);max-height:60dvh;
  overflow-y:auto;overflow-x:hidden;padding:var(--s-1)}
.ch-drop[hidden]{display:none}
.ch-results{display:flex;flex-direction:column;gap:2px;max-height:46dvh;
  overflow-y:auto;overflow-x:hidden}
.ch-res{display:flex;align-items:center;gap:var(--s-3);padding:var(--s-2);
  border-radius:var(--r-sm);cursor:pointer;font-size:var(--fs-sm);min-width:0;
  width:100%;border:0;background:transparent;text-align:left}
.ch-res:hover{background:var(--surface-2);border-color:transparent}
.ch-res-txt{display:flex;flex-direction:column;min-width:0;flex:1 1 auto}
.ch-res-sub{font-size:var(--fs-2xs);color:var(--text-muted)}
.ch-res.head{padding:var(--s-2) var(--s-2) 2px;cursor:default}
.ch-res.head:hover{background:transparent}
.ch-res.none{cursor:default;color:var(--text-muted);padding:var(--s-3) var(--s-2)}
.ch-res.none:hover{background:transparent}

.ch-ctx{position:fixed;z-index:70;background:var(--surface);border:1px solid var(--border);
  border-radius:var(--r-md);box-shadow:var(--shadow-3);padding:var(--s-1);min-width:170px;
  max-width:min(260px,calc(100vw - 16px))}
.ch-ctx[hidden]{display:none}
.ch-ctx button{width:100%;justify-content:flex-start;border:0;background:transparent;
  border-radius:var(--r-sm);font-weight:500}
.ch-ctx button:hover{background:var(--surface-2);border-color:transparent}
.ch-emoji{position:fixed;z-index:71;display:flex;flex-wrap:wrap;gap:2px;padding:var(--s-1);
  max-width:min(300px,calc(100vw - 16px));
  background:var(--surface);border:1px solid var(--border);border-radius:var(--r-xl);
  box-shadow:var(--shadow-3)}
.ch-emoji[hidden]{display:none}
.ch-emoji button{font-size:19px;width:34px;min-height:34px;padding:0;border:0;
  background:transparent;border-radius:50%}
.ch-viewer{position:fixed;inset:0;z-index:80;background:rgba(0,0,0,.9);
  display:grid;place-items:center;padding:var(--s-5);cursor:zoom-out}
.ch-viewer[hidden]{display:none}
.ch-viewer img{max-width:100%;max-height:100%;border-radius:var(--r-md)}
.ch-prof{display:flex;flex-direction:column;align-items:center;gap:var(--s-3)}

/* ── narrow: one pane at a time ──────────────────────────────────────────
   The list *is* the navigation on this page, so a phone shows exactly one of
   the three panes and `data-view` says which. No drawer, no hamburger — the
   same stance the console takes with its tab bar. */
@media (max-width:860px){
  .ch,.ch[data-view="peer"]{grid-template-columns:minmax(0,1fr)}
  .ch>.ch-side,.ch>.ch-main,.ch>.ch-aside{grid-area:1/1;display:none}
  .ch[data-view="list"]>.ch-side{display:flex}
  .ch[data-view="conv"]>.ch-main{display:flex}
  .ch[data-view="peer"]>.ch-aside{display:flex}
  .ch-back{display:inline-flex}
  .ch-aside{border-left:0}
  :root{--page-bubble-max:88%}
  .ch-log{padding:var(--s-3) var(--s-3) var(--s-2)}
  .ch-head,.ch-composer{padding-inline:var(--s-2)}
}

/* Between the two: room for the list and one of the other panes, not all three.
   The conversation is what steps aside, because everything in the node card is
   about the conversation anyway. */
@media (min-width:861px) and (max-width:1180px){
  .ch[data-view="peer"]{grid-template-columns:var(--page-side-w) minmax(0,1fr)}
  .ch[data-view="peer"]>.ch-main{display:none}
}

/* A short viewport (a laptop with the keyboard up, a split screen) has no room
   for a 320px list column either. */
@media (max-width:1024px) and (min-width:861px){
  :root{--page-side-w:270px}
}
"""

CHAT_PAGE_JS = r"""
// ── chat page ───────────────────────────────────────────────────────────────
// The page polls, so rendering has to be cheap and non-destructive: rebuilding
// the log every 1.2s threw away the scroll position, any text selection, and
// the click somebody was in the middle of making. Both lists are therefore
// keyed — a row is created once, updated in place, and removed when it goes.

let VER = 0, sel = null, timer = null;
let ST = {me:null, pseudo:"", bio:"", has_avatar:false, contacts:[], known:[], groups:[]};
let UNREAD = {}, TYPING = {}, replyTo = null, ncSel = {};
const MSGS = {};                 // conv -> {id -> record}
const REACTS = ["👍","❤️","😂","😮","😢","🔥","🎉","👏"];
const initials = (s) => { s = (s || "").trim(); return s ? s.slice(0, 2).toUpperCase() : "?"; };

SESSION.onLost = () => {
  if(timer){ clearInterval(timer); timer = null; }
  EVENTS.stop();
  $("app").classList.add("hidden"); $("login").classList.remove("hidden");
};
SESSION.load();

// ---- which pane is on screen ----------------------------------------------
// One attribute, so the three panes can never disagree about who is showing.
function view(next){
  const app = $("app");
  if(next) app.dataset.view = next;
  return app.dataset.view;
}

// ---- identity / naming -----------------------------------------------------
function hasAvatar(id){
  if(id === ST.me || id === "self") return ST.has_avatar;
  const r = findPerson(id); return !!(r && r.has_avatar);
}
function findPerson(id){
  return ST.contacts.find((c) => c.id === id) || ST.known.find((c) => c.id === id) || null;
}
function personName(id){
  if(id === ST.me) return ST.pseudo || "You";
  const r = findPerson(id); return (r && r.pseudo) || shortId(id);
}
function convIsGroup(conv){ return !!conv && conv.startsWith("g:"); }
function convName(conv){
  if(convIsGroup(conv)){
    const g = ST.groups.find((x) => "g:" + x.id === conv); return g ? g.name : "Group";
  }
  return personName(conv);
}
function convAvatarId(conv){ return convIsGroup(conv) ? null : conv; }
function avatarHTML(id, name, cls){
  const c = "ch-av" + (cls ? " " + cls : "");
  if(id && hasAvatar(id))
    return '<span class="' + c + '"><img alt="" src="/api/chat/avatar?id=' +
           encodeURIComponent(id) + '&v=' + VER + '"></span>';
  return '<span class="' + c + '">' + esc(initials(name)) + "</span>";
}

// ---- polling ---------------------------------------------------------------
async function poll(){
  let j;
  try{ j = await (await api("/api/chat/messages?since=" + VER)).json(); }catch(_){ return; }
  ST.me = j.me; ST.pseudo = j.pseudo || ""; ST.bio = j.bio || ""; ST.has_avatar = !!j.has_avatar;
  ST.contacts = j.contacts || []; ST.known = j.known || []; ST.groups = j.groups || [];
  UNREAD = j.unread || {}; TYPING = j.typing || {};
  let touched = false;
  for(const m of (j.messages || [])){
    (MSGS[m.conv] = MSGS[m.conv] || {})[m.id] = m;
    if(m.conv === sel) touched = true;
  }
  if(typeof j.version === "number") VER = j.version;
  renderMe(); renderList();
  if(sel){ renderHead(); if(touched) renderLog(); }
}

// ---- the conversation list -------------------------------------------------
function lastMsg(conv){
  const m = MSGS[conv]; if(!m) return null;
  let best = null; for(const k in m) if(!best || m[k].id > best.id) best = m[k];
  return best;
}
function preview(m){
  if(!m) return "";
  if(m.deleted) return "deleted message";
  if(m.kind === "image") return "Photo";
  if(m.kind === "file") return m.name || "File";
  return m.text || "";
}
function clock(t){
  if(!t) return "";
  return new Date(t * 1000).toLocaleTimeString([], {hour:"2-digit", minute:"2-digit"});
}
function convList(){
  const seen = new Set(), out = [];
  for(const conv in MSGS){ const m = lastMsg(conv); if(m) out.push({conv, m, t:m.t || 0}); seen.add(conv); }
  for(const g of ST.groups){ const c = "g:" + g.id; if(!seen.has(c)){ out.push({conv:c, m:null, t:0}); seen.add(c); } }
  for(const c of ST.contacts){ if(!seen.has(c.id)){ out.push({conv:c.id, m:null, t:0}); seen.add(c.id); } }
  out.sort((a, b) => b.t - a.t);
  return out;
}
function renderMe(){
  $("me-name").textContent = ST.pseudo || "Set your name";
  $("me-sub").textContent = ST.me ? shortId(ST.me) : "";
  setHTML("me-av-slot", avatarHTML(ST.me, ST.pseudo));
}
function rowHTML(it){
  const name = convName(it.conv);
  const typing = TYPING[it.conv];
  const un = UNREAD[it.conv] || 0;
  return avatarHTML(convAvatarId(it.conv), name) +
    '<span class="ch-row-body">' +
      '<span class="ch-row-top"><span class="ch-row-name truncate">' + esc(name) + "</span>" +
      '<span class="ch-row-time">' + (it.m ? esc(clock(it.m.t)) : "") + "</span></span>" +
      '<span class="ch-row-top"><span class="ch-row-prev truncate">' +
        (typing ? "<i>typing…</i>" : esc(preview(it.m))) + "</span>" +
      (un ? '<span class="badge accent">' + esc(un) + "</span>" : "") +
    "</span></span>";
}
function renderList(){
  const q = ($("side-search").value || "").trim().toLowerCase();
  const items = convList().filter((it) => !q || convName(it.conv).toLowerCase().includes(q));
  const host = $("chat-list");
  if(!items.length){
    setHTML(host, q
      ? emptyHTML("Nothing matches that", "Try a shorter name, or paste a node id.")
      : emptyHTML("No conversation yet",
                  "Start one with the pencil above, or by pasting someone's node id."));
    return;
  }
  if(host.firstElementChild && !host.firstElementChild.classList.contains("ch-row"))
    host.innerHTML = "";
  // Keyed: reuse the row that is already there, in the order the data says.
  const have = new Map();
  for(const el of host.children) have.set(el.dataset.conv, el);
  let previous = null;
  for(const it of items){
    let el = have.get(it.conv);
    if(!el){
      el = document.createElement("button");
      el.type = "button"; el.className = "ch-row"; el.dataset.conv = it.conv;
      el.setAttribute("role", "listitem");
    }
    have.delete(it.conv);
    setHTML(el, rowHTML(it));
    el.setAttribute("aria-current", it.conv === sel ? "true" : "false");
    // insertBefore with the node already in place is a no-op, so an unchanged
    // list touches nothing and a click in flight survives the poll.
    const next = previous ? previous.nextSibling : host.firstChild;
    if(next !== el) host.insertBefore(el, next);
    previous = el;
  }
  for(const el of have.values()) el.remove();
}

// ---- opening a conversation ------------------------------------------------
function openConv(conv){
  const changed = conv !== sel;
  sel = conv; replyTo = null; setReplyBar();
  $("empty").hidden = true; $("conv").hidden = false;
  view("conv");
  renderHead();
  if(changed) $("log").replaceChildren();     // a different conversation, not a redraw
  renderLog(true);
  markRead(); renderList();
}
function closeConv(){
  sel = null;
  $("conv").hidden = true; $("empty").hidden = false;
  view("list"); renderList();
}
function markRead(){
  if(!sel) return;
  api("/api/chat/read", "POST", {conv:sel}).catch(() => {});
  UNREAD[sel] = 0;
}
function renderHead(){
  const name = convName(sel);
  setHTML("conv-av-slot", avatarHTML(convAvatarId(sel), name));
  $("conv-title").textContent = name;
  let sub = "";
  if(TYPING[sel]) sub = "typing…";
  else if(convIsGroup(sel)){
    const g = ST.groups.find((x) => "g:" + x.id === sel);
    sub = g ? plural(g.members.length, "member") : "";
  }else{
    const r = findPerson(sel); sub = (r && r.bio) ? r.bio : shortId(sel);
  }
  $("conv-sub").textContent = sub;
  $("info-btn").disabled = convIsGroup(sel);
}

// ---- the log ---------------------------------------------------------------
function sameDay(a, b){
  return new Date(a * 1000).toDateString() === new Date(b * 1000).toDateString();
}
function tickHTML(status){
  if(status === "read") return '<span class="tick">' + icon("checkTwice", "read") + "</span>";
  if(status === "delivered") return "<span>" + icon("checkTwice", "delivered") + "</span>";
  return "<span>" + icon("check", "sent") + "</span>";
}
function atBottom(log){ return log.scrollHeight - log.scrollTop - log.clientHeight < 60; }
function toBottom(log, smooth){
  log.scrollTo({top:log.scrollHeight, behavior:smooth ? "smooth" : "auto"});
  $("jump").hidden = true;
}
function renderLog(force){
  const log = $("log");
  const pinned = force || atBottom(log);
  const list = Object.values(MSGS[sel] || {}).sort((a, b) => a.id - b.id);
  const have = new Map();
  for(const el of log.children) if(el.dataset.key) have.set(el.dataset.key, el);
  const fresh = log.childElementCount > 0;

  let previous = null, anchor = null, added = 0;
  for(const m of list){
    // A day separator is a row like any other, keyed by its date, so it is not
    // rebuilt (and does not flicker) when a message arrives under it.
    if(!previous || !sameDay(previous.t, m.t)){
      const key = "d" + new Date(m.t * 1000).toDateString();
      let sep = have.get(key);
      if(!sep){
        sep = document.createElement("div");
        sep.className = "ch-day"; sep.dataset.key = key;
        sep.textContent = new Date(m.t * 1000).toLocaleDateString([], {month:"short", day:"numeric"});
      }
      have.delete(key);
      anchor = place(log, sep, anchor);
    }
    const key = "m" + m.id;
    let el = have.get(key);
    const isNew = !el;
    if(isNew){
      el = document.createElement("div");
      el.dataset.key = key;
      if(fresh) el.classList.add("fresh");
      added++;
    }
    have.delete(key);
    paintMsg(el, m, previous);
    anchor = place(log, el, anchor);
    previous = m;
  }
  for(const el of have.values()) el.remove();

  if(pinned) toBottom(log);
  else if(added) $("jump").hidden = false;
}
// Put `el` straight after `anchor`, doing nothing when it is already there.
function place(host, el, anchor){
  const next = anchor ? anchor.nextSibling : host.firstChild;
  if(next !== el) host.insertBefore(el, next);
  return el;
}
function paintMsg(el, m, prev){
  const mine = m.src === "me";
  const grouped = !!prev && prev.src === m.src && sameDay(prev.t, m.t);
  const cls = "ch-m" + (mine ? " mine" : "") + (grouped ? " grouped" : "") +
              (el.classList.contains("fresh") ? " fresh" : "");
  if(el.className !== cls) el.className = cls;
  el.dataset.mid = m.mid || ""; el.dataset.id = m.id;

  let html = mine ? "" : avatarHTML(m.src, personName(m.src), "sm");
  html += '<div class="ch-bubble' + (m.deleted ? " deleted" : "") + '">';
  if(!mine && convIsGroup(sel) && !grouped)
    html += '<div class="ch-who">' + esc(personName(m.src)) + "</div>";
  if(m.reply){
    const store = MSGS[sel] || {};
    let quoted = null; for(const k in store) if(store[k].mid === m.reply) quoted = store[k];
    if(quoted)
      html += '<div class="ch-quote" data-goto="' + esc(quoted.id) + '">' +
        '<span class="qn">' + esc(quoted.src === "me" ? "You" : personName(quoted.src)) + "</span>" +
        '<span class="qt">' + esc(preview(quoted)) + "</span></div>";
  }
  if(m.deleted){
    html += '<div class="ch-txt">deleted message</div>';
  }else if(m.kind === "image"){
    html += '<img class="ch-media" alt="' + esc(m.name || "") + '" src="/api/chat/file?mid=' +
            encodeURIComponent(m.mid) + '">';
    if(m.text) html += '<div class="ch-txt">' + linkify(m.text) + "</div>";
  }else if(m.kind === "file"){
    html += '<a class="ch-file" href="/api/chat/file?mid=' + encodeURIComponent(m.mid) +
      '" download="' + esc(m.name || "file") + '"><span class="fi">' + icon("file") + "</span>" +
      '<span class="fm"><span class="fn">' + esc(m.name || "file") + "</span>" +
      '<span class="muted tiny">' + esc(fmtBytes(m.size)) + "</span></span></a>";
  }else{
    html += '<div class="ch-txt">' + linkify(m.text) + "</div>";
  }
  html += '<div class="ch-meta">' +
    (m.edited && !m.deleted ? '<span class="edited">edited</span>' : "") +
    esc(clock(m.t)) + (mine && !m.deleted ? tickHTML(m.status) : "") + "</div>";
  html += reactsHTML(m) + "</div>";
  setHTML(el, html);
}
function reactsHTML(m){
  const r = m.reactions || {}, keys = Object.keys(r);
  if(!keys.length) return "";
  let out = '<div class="ch-reacts">';
  for(const e of keys){
    const who = r[e] || [];
    out += '<button type="button" class="ch-react' + (who.includes(ST.me) ? " me" : "") +
      '" data-react="' + esc(e) + '" data-mid="' + esc(m.mid) + '">' +
      esc(e) + " " + who.length + "</button>";
  }
  return out + "</div>";
}
function linkify(text){
  return esc(text).replace(/(https?:\/\/[^\s<]+)/g,
    '<a href="$1" target="_blank" rel="noreferrer noopener">$1</a>');
}
function flash(id){
  const el = $("log").querySelector('[data-id="' + CSS.escape(String(id)) + '"] .ch-bubble');
  if(!el) return;
  el.scrollIntoView({block:"center", behavior:"smooth"});
  el.classList.add("target");
  setTimeout(() => el.classList.remove("target"), 1200);
}

// ---- sending ---------------------------------------------------------------
// The box is cleared first so typing feels immediate — which means a send that
// fails has to give the text back. Losing what somebody wrote, with nothing on
// screen to say so, is the worst thing a composer can do.
async function sendText(){
  const box = $("msg"), text = box.value.trim();
  if(!text || !sel) return;
  const conv = sel, reply = replyTo;
  box.value = ""; autoGrow();
  replyTo = null; setReplyBar();
  let sent = false;
  try{
    const response = await api("/api/chat/send", "POST", {conv, text, reply});
    sent = response.ok;
  }catch(_){}
  if(!sent){
    if(!box.value.trim()){ box.value = text; autoGrow(); }
    replyTo = reply; setReplyBar();
    toast("That message was not sent — it is back in the box", "danger");
    return;
  }
  toBottom($("log")); poll();
}
async function sendFile(file){
  if(!file || !sel) return;
  const conv = sel, reply = replyTo;
  let b64;
  try{ b64 = await toB64(file); }
  catch(_){ toast("That file could not be read", "danger"); return; }
  let sent = false;
  try{
    const response = await api("/api/chat/file", "POST",
                               {conv, name:file.name, data:b64, reply});
    sent = response.ok;
  }catch(_){}
  if(!sent){ toast(file.name + " was not sent", "danger"); return; }
  replyTo = null; setReplyBar(); toBottom($("log")); poll();
}
function toB64(file){
  return new Promise((res, rej) => {
    const reader = new FileReader();
    reader.onload = () => res((reader.result + "").split(",")[1] || "");
    reader.onerror = rej; reader.readAsDataURL(file);
  });
}
let typingSent = 0, typingStop = null;
function onTyping(){
  if(!sel) return;
  const now = Date.now();
  if(now - typingSent > 3000){
    typingSent = now;
    api("/api/chat/typing", "POST", {conv:sel, active:true}).catch(() => {});
  }
  clearTimeout(typingStop);
  typingStop = setTimeout(() => {
    typingSent = 0;
    api("/api/chat/typing", "POST", {conv:sel, active:false}).catch(() => {});
  }, 3500);
}
// The textarea grows with what is typed, up to the ceiling the stylesheet sets;
// past that it scrolls, so the composer can never eat the conversation.
function autoGrow(){
  const box = $("msg");
  box.style.height = "auto";
  const max = parseFloat(getComputedStyle(box).maxHeight) || 160;
  box.style.height = Math.min(box.scrollHeight, max) + "px";
  $("send-btn").disabled = !box.value.trim();
}

// ---- reply, context menu, reactions ---------------------------------------
function recordFor(mid){
  const store = MSGS[sel] || {};
  for(const k in store) if(store[k].mid === mid) return store[k];
  return null;
}
function setReplyBar(){
  const bar = $("reply-bar");
  const rec = replyTo ? recordFor(replyTo) : null;
  if(!rec){ replyTo = null; bar.hidden = true; return; }
  $("reply-who").textContent = rec.src === "me" ? "You" : personName(rec.src);
  $("reply-text").textContent = preview(rec);
  bar.hidden = false; $("msg").focus();
}
function openCtx(x, y, mid){
  const rec = recordFor(mid);
  if(!rec || rec.deleted) return;
  const mine = rec.src === "me", ctx = $("ctx");
  setHTML(ctx,
    '<button data-a="reply">Reply</button><button data-a="react">React</button>' +
    (rec.kind === "text" ? '<button data-a="copy">Copy</button>' : "") +
    (mine && rec.kind === "text" ? '<button data-a="edit">Edit</button>' : "") +
    (mine ? '<button data-a="delete" class="danger">Delete</button>' : ""));
  ctx.dataset.mid = mid; ctx.hidden = false;
  const w = ctx.offsetWidth || 180, h = ctx.offsetHeight || 160;
  ctx.style.left = Math.max(8, Math.min(x, innerWidth - w - 8)) + "px";
  ctx.style.top = Math.max(8, Math.min(y, innerHeight - h - 8)) + "px";
}
function closeCtx(){ $("ctx").hidden = true; $("emoji-pop").hidden = true; }
function ctxAction(action){
  const mid = $("ctx").dataset.mid, rec = recordFor(mid);
  if(action !== "react") closeCtx();
  if(!rec) return;
  if(action === "reply"){ replyTo = mid; setReplyBar(); }
  else if(action === "copy"){ copyText(rec.text || ""); }
  else if(action === "edit"){ editMessage(mid, rec); }else if(action === "delete"){
    confirmAction({title:"Delete this message for everyone?",
      body:'<p class="muted small">It is replaced by a tombstone on every node that has it.</p>',
      confirmLabel:"Delete", danger:true}).then((yes) => {
        if(yes) api("/api/chat/delete", "POST", {conv:sel, mid}).then(poll);
      });
  }else if(action === "react"){ openEmoji(mid); }
}
// In the page, not through `prompt()`: a browser dialog cannot be styled, and a
// browser that has decided this page asks too often simply stops showing them —
// which would make editing quietly do nothing.
function editMessage(mid, rec){
  const conv = sel;
  confirmAction({
    title:"Edit this message",
    confirmLabel:"Save",
    body:'<label class="field"><span class="sr-only">Message</span>' +
      '<textarea id="edit-text" rows="3" class="mono"></textarea></label>',
  }).then((agreed) => {
    const box = $("edit-text");
    const text = box ? box.value.trim() : "";
    if(!agreed || !text || text === (rec.text || "")) return;
    api("/api/chat/edit", "POST", {conv, mid, text}).then(poll).catch(() => {
      toast("That edit was not saved", "danger");
    });
  });
  const box = $("edit-text");
  if(box){ box.value = rec.text || ""; box.focus(); }
}
function openEmoji(mid){
  const pop = $("emoji-pop");
  setHTML(pop, REACTS.map((e) =>
    '<button type="button" data-e="' + esc(e) + '" data-mid="' + esc(mid) + '">' + esc(e) + "</button>").join(""));
  pop.hidden = false;
  const box = $("ctx").getBoundingClientRect();
  const w = pop.offsetWidth || 260, h = pop.offsetHeight || 44;
  pop.style.left = Math.max(8, Math.min(box.left, innerWidth - w - 8)) + "px";
  pop.style.top = Math.max(8, Math.min(box.top - h - 8, innerHeight - h - 8)) + "px";
  $("ctx").hidden = true;
}
function react(mid, emoji){
  api("/api/chat/react", "POST", {conv:sel, mid, emoji}).then(poll).catch(() => {});
}

// ---- profile ---------------------------------------------------------------
let pendingAvatar = undefined;   // undefined = unchanged, "" = clear, string = new b64
function openSettings(){
  $("set-name").value = ST.pseudo || "";
  $("set-bio").value = ST.bio || "";
  $("set-id").textContent = ST.me || "";
  setHTML("set-av", ST.has_avatar
    ? '<img alt="" src="/api/chat/avatar?id=self&v=' + VER + '">'
    : esc(initials(ST.pseudo)));
  $("set-details").value = detailMode();
  pendingAvatar = undefined; $("settings").showModal();
}
async function pickAvatar(file){
  const b64 = await resizeImage(file, 256);
  pendingAvatar = b64;
  setHTML("set-av", '<img alt="" src="data:image/jpeg;base64,' + b64 + '">');
}
function resizeImage(file, size){
  return new Promise((res, rej) => {
    const img = new Image(), url = URL.createObjectURL(file);
    img.onload = () => {
      const side = Math.min(img.width, img.height);
      const canvas = document.createElement("canvas");
      canvas.width = canvas.height = size;
      canvas.getContext("2d").drawImage(img, (img.width - side) / 2, (img.height - side) / 2,
                                        side, side, 0, 0, size, size);
      URL.revokeObjectURL(url);
      res(canvas.toDataURL("image/jpeg", 0.85).split(",")[1]);
    };
    img.onerror = (error) => { URL.revokeObjectURL(url); rej(error); };
    img.src = url;
  });
}
async function saveProfile(){
  setDetailMode($("set-details").value);
  // Two writes, because they belong to two owners: the name is the node's and
  // is signed by it, the bio and avatar are the chat app's own.
  const name = $("set-name").value.trim();
  if(name !== (ST.pseudo || "")){
    const res = await api("/api/pseudo", "POST", {pseudo:name}).catch(() => null);
    if(res && !res.ok){
      const body = await res.json().catch(() => ({}));
      toast(body.error || "That name cannot be used.", "danger");
      return;
    }
  }
  const body = {bio:$("set-bio").value};
  if(pendingAvatar !== undefined) body.avatar = pendingAvatar;
  await api("/api/chat/profile", "POST", body).catch(() => {});
  $("settings").close(); toast("Profile saved"); poll();
}

// ---- new chat, search, groups ---------------------------------------------
function openNew(){
  ncSel = {};
  $("nc-search").value = ""; $("nc-results").replaceChildren();
  $("grp-name").value = ""; $("nc-id").value = "";
  switchNc("dm"); $("newchat").showModal();
}
function switchNc(mode){
  $("nc-tab-dm").setAttribute("aria-selected", String(mode === "dm"));
  $("nc-tab-grp").setAttribute("aria-selected", String(mode === "grp"));
  $("nc-dm").hidden = mode !== "dm";
  $("nc-grp").hidden = mode !== "grp";
  if(mode === "grp") renderGroupPicker();
}
function resRow(avatarId, name, sub, onClick){
  const el = document.createElement("button");
  el.type = "button"; el.className = "ch-res";
  el.innerHTML = avatarHTML(avatarId, name) +
    '<span class="ch-res-txt"><span class="truncate">' + esc(name) + "</span>" +
    (sub ? '<span class="ch-res-sub mono truncate">' + esc(sub) + "</span>" : "") + "</span>";
  if(onClick) el.addEventListener("click", onClick);
  return el;
}
function noneRow(text){
  const el = document.createElement("div");
  el.className = "ch-res none"; el.textContent = text; return el;
}
async function doSearch(query){
  const host = $("nc-results");
  if(!query || !query.trim()){ host.replaceChildren(); return; }
  host.replaceChildren(noneRow("Searching…"));
  let hits = [];
  try{ hits = (await (await api("/api/chat/search", "POST", {pseudo:query.trim()})).json()).results || []; }
  catch(_){}
  host.replaceChildren();
  for(const r of hits)
    host.appendChild(resRow(r.id, r.pseudo || shortId(r.id), shortId(r.id), () => startChat(r.id)));
  if(!hits.length) host.appendChild(noneRow("No one found."));
}
async function startChat(id){
  await api("/api/chat/contact", "POST", {op:"add", id}).catch(() => {});
  $("newchat").close(); await poll(); openConv(id);
}
// The list search filters the conversations *and* offers people who are not in
// them yet — pseudos are not unique, so the id under each hit is what picks the
// right node.
let sideTimer = null;
function sideSearch(){
  renderList();
  const query = ($("side-search").value || "").trim();
  const drop = $("side-results");
  if(!query){ drop.hidden = true; drop.replaceChildren(); return; }
  const lower = query.toLowerCase();
  const chats = convList().filter((it) => convName(it.conv).toLowerCase().includes(lower));
  drop.replaceChildren();
  if(chats.length){
    const head = document.createElement("div");
    head.className = "ch-res head eyebrow"; head.textContent = "Chats";
    drop.appendChild(head);
    for(const it of chats.slice(0, 8))
      drop.appendChild(resRow(convAvatarId(it.conv), convName(it.conv),
        convIsGroup(it.conv) ? "group" : shortId(it.conv),
        () => { closeSide(); openConv(it.conv); }));
  }
  const head = document.createElement("div");
  head.className = "ch-res head eyebrow"; head.textContent = "People";
  drop.appendChild(head);
  const waiting = noneRow("Searching…");
  drop.appendChild(waiting);
  drop.hidden = false;
  clearTimeout(sideTimer);
  sideTimer = setTimeout(async () => {
    if(($("side-search").value || "").trim() !== query) return;    // stale
    let hits = [];
    try{ hits = (await (await api("/api/chat/search", "POST", {pseudo:query})).json()).results || []; }
    catch(_){}
    hits = hits.filter((x) => !chats.some((c) => c.conv === x.id));
    waiting.remove();
    if(hits.length){
      for(const r of hits)
        drop.appendChild(resRow(r.id, r.pseudo || shortId(r.id), shortId(r.id),
          () => { closeSide(); startChat(r.id); }));
    }else{
      drop.appendChild(noneRow("No people found."));
    }
  }, 320);
}
function closeSide(){
  $("side-results").hidden = true; $("side-search").value = ""; renderList();
}
function renderGroupPicker(){
  const host = $("grp-members");
  host.replaceChildren();
  const seen = new Set(), people = [...ST.contacts, ...ST.known];
  let shown = 0;
  for(const p of people){
    if(seen.has(p.id)) continue;
    seen.add(p.id); shown++;
    const row = resRow(p.id, p.pseudo || shortId(p.id), shortId(p.id), null);
    const pick = document.createElement("input");
    pick.type = "checkbox"; pick.checked = !!ncSel[p.id]; pick.tabIndex = -1;
    row.appendChild(pick);
    row.addEventListener("click", () => { ncSel[p.id] = !ncSel[p.id]; pick.checked = !!ncSel[p.id]; });
    host.appendChild(row);
  }
  if(!shown) host.appendChild(noneRow("Add contacts first."));
}
async function createGroup(){
  const name = $("grp-name").value.trim();
  const members = Object.keys(ncSel).filter((k) => ncSel[k]);
  if(!name || !members.length){ toast("A group needs a name and a member", "warn"); return; }
  const j = await (await api("/api/chat/group", "POST",
                             {op:"create", name, members})).json().catch(() => ({}));
  $("newchat").close(); await poll();
  if(j.id) openConv("g:" + j.id);
}

// ---- who you are talking to ------------------------------------------------
// The console already describes a node better than a chat page ever would: the
// link, its addresses, what each side may do to the other. So chat does not
// describe it again — it mounts the same view. Where it appears is a preference
// about this screen, so it is stored per browser like the theme.
const DETAIL_MODES = ["panel", "window", "tab"];
function detailMode(){
  try{
    const v = localStorage.getItem("nmesh_chat_details");
    if(DETAIL_MODES.includes(v)) return v;
  }catch(_){}
  return "panel";
}
function setDetailMode(mode){
  if(!DETAIL_MODES.includes(mode)) return;
  try{ localStorage.setItem("nmesh_chat_details", mode); }catch(_){}
}
function closePeerPanel(){
  $("peer-panel").hidden = true;
  $("peer-view").replaceChildren();
  view(sel ? "conv" : "list");
}
async function showPeer(id){
  if(!id) return;
  if(detailMode() !== "panel"){ openLinked("/node?from=chat#" + id); return; }
  $("peer-panel").hidden = false;
  view("peer");
  await NODEVIEW.mount("peer-view", id, {
    // "What is my link to this person" is this node's question, whoever the
    // console happens to be managing.
    local:true,
    hide:["chat"],                       // you are already in the conversation
    onGone(){ closePeerPanel(); closeConv(); poll(); },
  });
}

// ---- events ----------------------------------------------------------------
function bind(){
  $("side-search").addEventListener("input", sideSearch);
  $("side-search").addEventListener("focus", sideSearch);
  document.addEventListener("click", (e) => {
    if(!e.target.closest(".ch-side-search")) $("side-results").hidden = true;
  });
  $("me-btn").addEventListener("click", openSettings);
  $("new-btn").addEventListener("click", openNew);
  $("empty-new").addEventListener("click", openNew);
  $("back-btn").addEventListener("click", closeConv);
  $("peer-back").addEventListener("click", closePeerPanel);
  $("del-conv").addEventListener("click", async () => {
    if(!sel) return;
    const group = convIsGroup(sel);
    const agreed = await confirmAction({
      title:group ? "Leave and delete this group?" : "Remove this contact?",
      body:'<p class="muted small">The conversation disappears from this node. ' +
        (group ? "The other members keep theirs." : "They can still write to you again.") + "</p>",
      confirmLabel:group ? "Leave group" : "Remove", danger:true});
    if(!agreed) return;
    const gone = sel;
    await api(group ? "/api/chat/group" : "/api/chat/contact", "POST",
      group ? {op:"remove", id:gone.slice(2)} : {op:"remove", id:gone}).catch(() => {});
    delete MSGS[gone];
    closeConv();
    toast(group ? "Group left" : "Contact removed");
    poll();
  });
  $("info-btn").addEventListener("click", () => { if(sel && !convIsGroup(sel)) showPeer(sel); });
  $("peer-panel-close").addEventListener("click", closePeerPanel);
  $("chat-list").addEventListener("click", (e) => {
    const row = e.target.closest(".ch-row");
    if(row) openConv(row.dataset.conv);
  });
  $("send-form").addEventListener("submit", (e) => { e.preventDefault(); sendText(); });
  $("msg").addEventListener("input", () => { autoGrow(); onTyping(); });
  $("msg").addEventListener("keydown", (e) => {
    if(e.key === "Enter" && !e.shiftKey){ e.preventDefault(); sendText(); }
  });
  $("attach-btn").addEventListener("click", () => $("file-input").click());
  $("file-input").addEventListener("change", (e) => {
    if(e.target.files[0]) sendFile(e.target.files[0]);
    e.target.value = "";
  });
  $("emoji-btn").addEventListener("click", () => {
    const box = $("msg"); box.value += "🙂"; box.focus(); autoGrow();
  });
  $("reply-cancel").addEventListener("click", () => { replyTo = null; setReplyBar(); });
  $("jump").addEventListener("click", () => toBottom($("log"), true));
  $("log").addEventListener("scroll", () => { if(atBottom($("log"))) $("jump").hidden = true; });
  $("log").addEventListener("click", (e) => {
    const img = e.target.closest("img.ch-media");
    if(img){ $("viewer-img").src = img.src; $("viewer").hidden = false; return; }
    const quote = e.target.closest(".ch-quote");
    if(quote){ flash(quote.dataset.goto); return; }
    const chip = e.target.closest(".ch-react");
    if(chip){ react(chip.dataset.mid, chip.dataset.react); return; }
  });
  $("log").addEventListener("contextmenu", (e) => {
    const row = e.target.closest(".ch-m");
    if(row && row.dataset.mid){ e.preventDefault(); openCtx(e.clientX, e.clientY, row.dataset.mid); }
  });
  // Long press is the touch equivalent of a right click; a finger that moves is
  // a scroll, so the timer is cancelled rather than firing under the drag.
  let press = null, from = null;
  $("log").addEventListener("touchstart", (e) => {
    const row = e.target.closest(".ch-m");
    if(!row || !row.dataset.mid) return;
    const touch = e.touches[0];
    from = {x:touch.clientX, y:touch.clientY};
    press = setTimeout(() => openCtx(from.x, from.y, row.dataset.mid), 500);
  }, {passive:true});
  $("log").addEventListener("touchmove", (e) => {
    if(!press || !from) return;
    const touch = e.touches[0];
    if(Math.abs(touch.clientX - from.x) > 10 || Math.abs(touch.clientY - from.y) > 10){
      clearTimeout(press); press = null;
    }
  }, {passive:true});
  $("log").addEventListener("touchend", () => { clearTimeout(press); press = null; });
  $("ctx").addEventListener("click", (e) => {
    const button = e.target.closest("button");
    if(button) ctxAction(button.dataset.a);
  });
  $("emoji-pop").addEventListener("click", (e) => {
    const button = e.target.closest("button");
    if(button){ react(button.dataset.mid, button.dataset.e); closeCtx(); }
  });
  document.addEventListener("click", (e) => {
    if(!e.target.closest(".ch-ctx") && !e.target.closest("#emoji-pop") && !e.target.closest(".ch-m"))
      closeCtx();
  });
  $("viewer").addEventListener("click", () => { $("viewer").hidden = true; });
  document.addEventListener("keydown", (e) => {
    if(e.key !== "Escape") return;
    if(!$("viewer").hidden){ $("viewer").hidden = true; return; }
    if(!$("ctx").hidden || !$("emoji-pop").hidden){ closeCtx(); return; }
    if(!$("side-results").hidden){ $("side-results").hidden = true; return; }
    if(view() === "peer"){ closePeerPanel(); return; }
    if(replyTo){ replyTo = null; setReplyBar(); }
  });
  $$("[data-close]").forEach((b) => b.addEventListener("click", () => $(b.dataset.close).close()));
  $("av-input").addEventListener("change", (e) => { if(e.target.files[0]) pickAvatar(e.target.files[0]); });
  $("av-clear").addEventListener("click", () => {
    pendingAvatar = "";
    setHTML("set-av", esc(initials($("set-name").value)));
  });
  $("save-prof").addEventListener("click", saveProfile);
  $("nc-tab-dm").addEventListener("click", () => switchNc("dm"));
  $("nc-tab-grp").addEventListener("click", () => switchNc("grp"));
  $("nc-search").addEventListener("input", debounce((e) => doSearch(e.target.value), 300));
  $("nc-add").addEventListener("click", () => {
    const id = $("nc-id").value.trim();
    if(/^[0-9a-fA-F]{40}$/.test(id)) startChat(id.toLowerCase());
    else toast("A node id is 40 hexadecimal characters", "warn");
  });
  $("grp-create").addEventListener("click", createGroup);
  PALETTE.add("New chat", "Action", openNew);
  PALETTE.add("Your profile", "Action", openSettings);
  PALETTE.add("Switch theme", "Action", () => THEME.toggle());
  PALETTE.add("Back to the console", "Go to", () => { window.location = "/"; });
}

// ---- auth and boot ---------------------------------------------------------
async function enter(token){
  const headers = {};
  if(token) headers["Authorization"] = "Bearer " + token;
  const res = await fetch("/api/chat/messages?since=0", {headers});
  if(!res.ok) return false;
  if(token) SESSION.set(token);
  $("login").classList.add("hidden"); $("app").classList.remove("hidden");
  mountShell();
  // The bar says which node the console is driving; this page still drives
  // this one. Confirming drops a claim the local console no longer honours.
  CONTEXT.confirm();
  // The conversation is this app's own business and keeps its own poll. The
  // node panel beside it is not: it shows links, which are told rather than
  // asked, and latency, which is read on the shared cadence like everywhere
  // else. `REFRESH.mount` arms both.
  REFRESH.mount();
  autoGrow();
  await poll();
  if(timer) clearInterval(timer);
  timer = setInterval(poll, 1200);
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
        setMessage("err", body.error || "Login failed", true); return;
      }
      $("password").value = "";
      await enter((await res.json()).token);
    }catch(_){ setMessage("err", "Console is not reachable", true); }
  });
});
bind();
(function(){
  let token = null;
  try{ token = sessionStorage.getItem("nmesh_token"); }catch(_){}
  enter(token).then((ok) => { if(!ok) $("login").classList.remove("hidden"); });
})();
"""
