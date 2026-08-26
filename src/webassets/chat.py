"""
Chat sub-page (/chat).

A full chat client — identity, contact directory, 1:1 and group conversations,
files, replies and reactions — served by the console and backed by the
ChatBridge. Same session, same strict CSP: no inline script, no external
resource.

The conversation list *is* the navigation, so this page takes the shell's rail
slot for it rather than adding a second level of chrome.
"""

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
<body data-app-name="NMesh Chat">

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
<div id="app" class="chat hidden">
  <aside class="side">
    <header class="side-head">
      <button id="me-btn" class="avatar-btn" title="Your profile" aria-label="Your profile">
        <span id="me-av" class="avatar"></span></button>
      <div class="side-who">
        <div id="me-name" class="name truncate"></div>
        <div id="me-sub" class="mono tiny muted truncate"></div>
      </div>
      <button id="theme-toggle" class="icon" aria-label="Switch theme">☾</button>
      <button id="new-btn" class="icon" title="New chat" aria-label="New chat">✎</button>
    </header>
    <div class="side-search">
      <label class="search"><span class="sr-only">Search chats and people</span>
        <input id="side-search" type="search" placeholder="Search chats and people…" autocomplete="off"></label>
      <div id="side-results" class="dropdown hidden"></div>
    </div>
    <div id="chat-list" class="chat-list"></div>
    <div class="side-foot"><a class="btn ghost wide" href="/">Back to console</a></div>
  </aside>

  <main id="main" class="thread">
    <div id="empty" class="empty">
      <div class="mark" aria-hidden="true">NM</div>
      <div class="t">No conversation open</div>
      <div class="h">Pick someone on the left, or start a new chat. Everything you send is
        end-to-end encrypted between the two nodes.</div>
      <button id="empty-new" class="primary">Start a chat</button>
    </div>

    <section id="conv" class="conv hidden">
      <header class="conv-head">
        <button id="back-btn" class="icon only-mobile" title="Back" aria-label="Back">‹</button>
        <button id="info-btn" class="peer">
          <span id="conv-av" class="avatar"></span>
          <span class="peer-txt"><span id="conv-title" class="name truncate"></span>
            <span id="conv-sub" class="tiny muted truncate"></span></span>
        </button>
        <span class="grow"></span>
        <button id="del-conv" class="icon" title="Delete conversation" aria-label="Delete conversation">🗑</button>
      </header>
      <div id="log" class="log"></div>
      <div id="reply-bar" class="reply-bar hidden">
        <div class="grow"><span id="reply-who" class="name"></span>
          <span id="reply-text" class="muted small"></span></div>
        <button id="reply-cancel" class="icon sm" aria-label="Cancel reply">✕</button>
      </div>
      <form id="send-form" class="composer">
        <button type="button" id="attach-btn" class="icon" title="Attach file" aria-label="Attach file">📎</button>
        <input id="file-input" type="file" hidden>
        <textarea id="msg" rows="1" placeholder="Message" autocomplete="off"></textarea>
        <button type="button" id="emoji-btn" class="icon" title="Emoji" aria-label="Emoji">🙂</button>
        <button type="submit" id="send-btn" class="icon send" title="Send" aria-label="Send">➤</button>
      </form>
    </section>
  </main>

  <!-- Who you are talking to, as the console describes them: the same view the
       node page serves, mounted here rather than framed. -->
  <aside id="peer-panel" class="peer-panel" hidden aria-label="Node details">
    <header class="peer-panel-head"><h2>Node</h2><span class="grow"></span>
      <button id="peer-panel-close" class="icon" aria-label="Close">✕</button></header>
    <div id="peer-view" class="peer-panel-body"></div>
  </aside>
</div>

<div id="ctx" class="ctx hidden"></div>
<div id="emoji-pop" class="emoji-pop hidden"></div>
<div id="viewer" class="viewer hidden"><img id="viewer-img" alt=""></div>

<dialog id="settings" aria-labelledby="settings-title">
  <div class="sheet">
    <header class="sheet-head"><h2 id="settings-title">Your profile</h2>
      <button class="icon" data-close="settings" aria-label="Close">✕</button></header>
    <div class="sheet-body">
      <div class="prof">
        <span id="set-av" class="avatar big"></span>
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
      <button class="icon" data-close="newchat" aria-label="Close">✕</button></header>
    <div class="sheet-body">
      <div class="segmented" role="tablist">
        <button id="nc-tab-dm" role="tab" aria-selected="true">Find people</button>
        <button id="nc-tab-grp" role="tab" aria-selected="false">New group</button>
      </div>
      <div id="nc-dm" class="stack">
        <label class="search"><span class="sr-only">Search by name</span>
          <input id="nc-search" type="search" placeholder="Search by name…"></label>
        <div id="nc-results" class="results"></div>
        <div class="field"><span>Or paste a node id</span>
          <div class="toolbar"><input id="nc-id" class="mono grow" placeholder="40-hex node id" spellcheck="false">
            <button id="nc-add" class="primary">Start</button></div></div>
      </div>
      <div id="nc-grp" class="stack hidden">
        <label class="field"><span>Group name</span>
          <input id="grp-name" maxlength="64" placeholder="Group name"></label>
        <div class="field"><span>Members</span><div id="grp-members" class="results"></div></div>
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
/* dvh, not vh: on a phone `100vh` is the viewport *without* the browser's
   own bars, so the composer sits under them and the last message is cut. */
.chat{display:grid;grid-template-columns:320px minmax(0,1fr);height:100dvh;
  background:var(--canvas)}
.side{display:flex;flex-direction:column;min-height:0;background:var(--rail);
  border-right:1px solid var(--border)}
.side-head{display:flex;align-items:center;gap:var(--s-2);padding:var(--s-3) var(--s-3);
  border-bottom:1px solid var(--border)}
.side-who{flex:1 1 auto;min-width:0}
.side-who .name{font-weight:620;font-size:var(--fs-sm)}
.side-search{padding:var(--s-3);position:relative}
.side-search .search{max-width:none;width:100%}
.side-foot{padding:var(--s-3);border-top:1px solid var(--border)}
.chat-list{flex:1 1 auto;min-height:0;overflow-y:auto;padding:0 var(--s-2) var(--s-2)}
.row-chat{display:flex;gap:var(--s-3);align-items:center;padding:var(--s-2);border-radius:var(--r-md);
  cursor:pointer}
.row-chat:hover{background:var(--surface-2)}
.row-chat.active{background:var(--accent-soft)}
.row-chat .body{flex:1 1 auto;min-width:0}
.row-chat .top{display:flex;align-items:baseline;gap:var(--s-2)}
.row-chat .rname{font-weight:600;font-size:var(--fs-sm);flex:1 1 auto;min-width:0;
  overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.row-chat .time{font-size:var(--fs-2xs);color:var(--text-faint);flex:none}
.row-chat .prev{font-size:var(--fs-xs);color:var(--text-muted);flex:1 1 auto;min-width:0;
  overflow:hidden;text-overflow:ellipsis;white-space:nowrap}

.avatar{width:36px;height:36px;flex:none;border-radius:50%;display:grid;place-items:center;
  background:var(--accent-soft);color:var(--accent);font:700 var(--fs-xs)/1 var(--font);
  overflow:hidden}
.avatar img{width:100%;height:100%;object-fit:cover}
.avatar.big{width:76px;height:76px;font-size:var(--fs-xl)}
.avatar-btn{padding:0;width:auto;min-height:0;border:0;background:transparent}
.avatar-btn:hover{background:transparent;border-color:transparent}

.thread{display:flex;flex-direction:column;min-width:0;min-height:0}
.peer-panel{display:flex;flex-direction:column;min-width:0;min-height:0;
  background:var(--canvas);border-left:1px solid var(--border)}
.peer-panel-head{display:flex;align-items:center;gap:var(--s-2);
  padding:var(--s-2) var(--s-4);border-bottom:1px solid var(--border);
  background:var(--surface)}
.peer-panel-head h2{font-size:var(--fs-md)}
.peer-panel-body{flex:1 1 auto;min-height:0;overflow-y:auto;padding:var(--s-4);
  padding-bottom:calc(var(--s-4) + env(safe-area-inset-bottom))}
.thread>.empty{flex:1 1 auto;justify-content:center}
.conv{display:flex;flex-direction:column;flex:1 1 auto;min-height:0}
.conv-head{display:flex;align-items:center;gap:var(--s-2);padding:var(--s-2) var(--s-4);
  border-bottom:1px solid var(--border);background:var(--surface)}
.peer{display:flex;align-items:center;gap:var(--s-3);border:0;background:transparent;
  padding:var(--s-1) var(--s-2);min-width:0;text-align:left}
.peer:hover{background:var(--surface-2)}
.peer-txt{display:flex;flex-direction:column;min-width:0}
.peer-txt .name{font-weight:620;font-size:var(--fs-md)}
.only-mobile{display:none}

.log{flex:1 1 auto;min-height:0;overflow-y:auto;padding:var(--s-4);display:flex;
  flex-direction:column;gap:2px;overscroll-behavior:contain}
/* A short conversation sits at the bottom, where the next message will appear,
   without breaking scrolling once it is long. */
.log>:first-child{margin-top:auto}
.daysep{align-self:center;margin:var(--s-3) 0;padding:2px 10px;border-radius:var(--r-full);
  background:var(--surface-2);border:1px solid var(--border);font-size:var(--fs-2xs);
  color:var(--text-muted)}
.msg{display:flex;gap:var(--s-2);align-items:flex-end;max-width:min(680px,86%)}
.msg.mine{align-self:flex-end;flex-direction:row-reverse}
.msg.grouped{margin-top:0}
.msg:not(.grouped){margin-top:var(--s-3)}
.m-av{width:26px;height:26px;font-size:9px}
.msg.grouped .m-av{visibility:hidden}
.bubble{position:relative;background:var(--surface);border:1px solid var(--border);
  border-radius:var(--r-lg);padding:var(--s-2) var(--s-3);min-width:64px;
  box-shadow:var(--shadow-1);font-size:var(--fs-sm)}
.msg.mine .bubble{background:var(--accent-soft);border-color:var(--accent-line)}
.bubble.deleted{opacity:.6;font-style:italic}
.bubble .who{font-size:var(--fs-2xs);font-weight:700;color:var(--accent);margin-bottom:2px}
.bubble .txt{white-space:pre-wrap;overflow-wrap:anywhere}
.bubble .meta{display:flex;align-items:center;gap:4px;justify-content:flex-end;
  font-size:var(--fs-2xs);color:var(--text-faint);margin-top:2px}
.bubble .edited{font-style:italic}
.bubble .tick{color:var(--accent)}
.quote{display:flex;flex-direction:column;gap:1px;padding:4px 8px;margin-bottom:4px;
  border-left:2px solid var(--accent);background:var(--surface-2);border-radius:var(--r-sm);
  cursor:pointer;font-size:var(--fs-xs)}
.quote .qn{font-weight:700;color:var(--accent)}
.quote .qt{color:var(--text-muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.media{max-width:min(420px,100%);border-radius:var(--r-md);cursor:zoom-in;margin:-2px 0 2px}
.file-card{display:flex;align-items:center;gap:var(--s-2);padding:var(--s-2);border-radius:var(--r-md);
  background:var(--surface-2);color:inherit;text-decoration:none}
.file-card:hover{text-decoration:none;background:var(--surface-3)}
.file-card .fi{font-size:20px}
.file-card .fmeta{display:flex;flex-direction:column;min-width:0}
.file-card .fn{font-weight:600;font-size:var(--fs-sm)}
.reacts{display:flex;flex-wrap:wrap;gap:4px;margin-top:4px}
.react{padding:1px 7px;border-radius:var(--r-full);background:var(--surface-2);
  border:1px solid var(--border);font-size:var(--fs-2xs);cursor:pointer}
.react.me{border-color:var(--accent);background:var(--accent-soft);color:var(--accent)}

.reply-bar{display:flex;align-items:center;gap:var(--s-2);padding:var(--s-2) var(--s-4);
  border-top:1px solid var(--border);background:var(--surface-2);font-size:var(--fs-sm)}
.reply-bar .name{font-weight:700;color:var(--accent);margin-right:var(--s-2)}
.composer{display:flex;align-items:flex-end;gap:var(--s-2);padding:var(--s-3) var(--s-4);
  border-top:1px solid var(--border);background:var(--surface)}
.composer textarea{flex:1 1 auto;min-height:var(--ctl-h);max-height:140px;resize:none;
  border-radius:var(--r-xl);padding:8px var(--s-4)}
.composer .send{color:var(--accent-fg);background:var(--accent);border-color:var(--accent);
  border-radius:50%}
.composer .send:hover{background:var(--accent-hover);color:var(--accent-fg)}

.dropdown{position:absolute;left:var(--s-3);right:var(--s-3);top:calc(100% - var(--s-2));z-index:30;
  background:var(--surface);border:1px solid var(--border);border-radius:var(--r-md);
  box-shadow:var(--shadow-3);max-height:60vh;overflow-y:auto;padding:var(--s-1)}
.results{display:flex;flex-direction:column;gap:2px;max-height:46vh;overflow-y:auto}
.res{display:flex;align-items:center;gap:var(--s-3);padding:var(--s-2);border-radius:var(--r-sm);
  cursor:pointer;font-size:var(--fs-sm)}
.res:hover{background:var(--surface-2)}
.res .rt{display:flex;flex-direction:column;min-width:0}
.res .rs{font-size:var(--fs-2xs);color:var(--text-muted)}
.res .head{padding:var(--s-2) var(--s-2) 2px}

.ctx{position:fixed;z-index:70;background:var(--surface);border:1px solid var(--border);
  border-radius:var(--r-md);box-shadow:var(--shadow-3);padding:var(--s-1);min-width:170px}
.ctx button{width:100%;justify-content:flex-start;border:0;background:transparent;
  border-radius:var(--r-sm);font-weight:500}
.ctx button:hover{background:var(--surface-2);border-color:transparent}
.emoji-pop{position:fixed;z-index:71;display:flex;gap:2px;padding:var(--s-1);
  background:var(--surface);border:1px solid var(--border);border-radius:var(--r-full);
  box-shadow:var(--shadow-3)}
.emoji-pop button{font-size:19px;width:34px;min-height:34px;padding:0;border:0;
  background:transparent;border-radius:50%}
.viewer{position:fixed;inset:0;z-index:80;background:rgba(0,0,0,.9);display:grid;place-items:center;
  padding:var(--s-5);cursor:zoom-out}
.viewer img{max-width:100%;max-height:100%;border-radius:var(--r-md)}
.prof{display:flex;flex-direction:column;align-items:center;gap:var(--s-3)}

@media (max-width:860px){
  .chat{grid-template-columns:1fr}
  .thread{display:none}
  .chat.show-conv .side{display:none}
  .chat.show-conv .thread{display:flex}
  .only-mobile{display:inline-flex}
  .msg{max-width:94%}
  /* The home indicator on a phone sits exactly where the composer and the last
     row of the list are. */
  .composer{padding-bottom:calc(var(--s-2) + env(safe-area-inset-bottom))}
  .side-foot{padding-bottom:calc(var(--s-3) + env(safe-area-inset-bottom))}
  .log{padding:var(--s-3)}
}

/* The details panel, and what has to give way to it as the screen narrows.
   Declared after the rules above on purpose: same specificity, so it is the
   order that decides, and "the panel is open" has to be the last word. */
.chat.show-peer{grid-template-columns:320px minmax(0,1fr) minmax(320px,380px)}
@media (max-width:1180px){
  /* No room for three: the conversation steps aside, its list stays.
     Everything in the panel is *about* the conversation anyway. */
  .chat.show-peer{grid-template-columns:320px minmax(0,1fr)}
  .chat.show-peer .thread{display:none}
}
@media (max-width:860px){
  .chat.show-peer{grid-template-columns:1fr}
  .chat.show-peer .side{display:none}
  .chat.show-peer .thread{display:none}
  .peer-panel{border-left:0}
}
"""


CHAT_PAGE_JS = r"""
// ── chat page ───────────────────────────────────────────────────────────────
let VER=0, sel=null, timer=null;
let ST={me:null,pseudo:"",bio:"",has_avatar:false,contacts:[],known:[],groups:[]};
let UNREAD={}, TYPING={}, replyTo=null, ncSel={};
const MSGS={};            // conv -> {id -> record}
const REACTS=["👍","❤️","😂","😮","😢","🔥","🎉","👏"];
const initials=(s)=>{s=(s||"").trim();return s?s.slice(0,2).toUpperCase():"?";};

SESSION.onLost=()=>{
  if(timer){clearInterval(timer);timer=null;}
  $("app").classList.add("hidden"); $("login").classList.remove("hidden");
};
SESSION.load();

// ---- identity / naming ----
function hasAvatar(id){
  if(id===ST.me||id==="self")return ST.has_avatar;
  const r=findPerson(id); return !!(r&&r.has_avatar);
}
function findPerson(id){return ST.contacts.find(c=>c.id===id)||ST.known.find(c=>c.id===id)||null;}
function personName(id){
  if(id===ST.me)return ST.pseudo||"You";
  const r=findPerson(id); return (r&&r.pseudo)||shortId(id);
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
function clock(t){if(!t)return "";const d=new Date(t*1000);return d.toLocaleTimeString([],{hour:"2-digit",minute:"2-digit"});}
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
  $("me-name").textContent=ST.pseudo||"Set your name";
  $("me-sub").textContent=ST.me?shortId(ST.me):"";
  $("me-av").outerHTML='<span id="me-av">'+avatarHTML(ST.me,ST.pseudo)+'</span>';
  // Built as a string and written only if it differs: this runs on the poll,
  // and replacing the row under a pointer loses the click being made on it.
  let html="", shown=0;
  for(const it of convList()){
    const name=convName(it.conv);
    if(q&&!name.toLowerCase().includes(q))continue;
    shown++;
    const typing=TYPING[it.conv];
    const prev=typing?"<i>typing…</i>":esc(preview(it.m));
    const un=UNREAD[it.conv]||0;
    html+='<div class="row-chat'+(it.conv===sel?" active":"")+'" data-conv="'+esc(it.conv)+'">'+
      avatarHTML(convAvatarId(it.conv),name)+
      '<div class="body"><div class="top"><span class="rname">'+esc(name)+'</span>'+
      '<span class="time">'+(it.m?clock(it.m.t):"")+'</span></div>'+
      '<div class="top"><span class="prev">'+prev+'</span>'+
      (un?'<span class="badge">'+un+'</span>':'')+'</div></div></div>';
  }
  if(!shown)
    html=q
      ? emptyHTML("Nothing matches that","Try a shorter name, or paste a node id.")
      : emptyHTML("No conversation yet",
                  "Start one with the pencil above, or by pasting someone's node id.");
  setHTML("chat-list",html);
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
  else{const r=findPerson(sel);sub=r&&r.bio?r.bio:shortId(sel);}
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
    clock(m.t)+(mine&&!m.deleted?tickHTML(m.status):'')+'</span>';
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
  else if(a==="copy"){copyText(rec.text||"");}
  else if(a==="edit"){const t=prompt("Edit message",rec.text||"");if(t!=null&&t.trim())api("/api/chat/edit","POST",{conv:sel,mid,text:t.trim()}).then(poll);}
  else if(a==="delete"){confirmAction({title:"Delete this message for everyone?",
    body:'<p class="muted small">It is replaced by a tombstone on every node that has it.</p>',
    confirmLabel:"Delete", danger:true}).then((yes)=>{
      if(yes)api("/api/chat/delete","POST",{conv:sel,mid}).then(poll);});}
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
  $("set-details").value=detailMode();
  pendingAvatar=undefined; $("settings").showModal();
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
  setDetailMode($("set-details").value);
  // Two writes, because they belong to two owners: the name is the node's and
  // is signed by it, the bio and avatar are the chat app's own.
  const name=$("set-name").value.trim();
  if(name!==(ST.pseudo||"")){
    const r=await api("/api/pseudo","POST",{pseudo:name}).catch(()=>null);
    if(r&&!r.ok){
      const j=await r.json().catch(()=>({}));
      alert(j.error||"That name cannot be used.");
      return;
    }
  }
  const body={bio:$("set-bio").value};
  if(pendingAvatar!==undefined)body.avatar=pendingAvatar;
  await api("/api/chat/profile","POST",body).catch(()=>{});
  $("settings").close(); poll();
}

// ---- new chat / search / groups ----
let ncMode="dm";
function openNew(){ncMode="dm";ncSel={};$("nc-search").value="";$("nc-results").innerHTML="";
  $("grp-name").value="";$("nc-id").value="";switchNc("dm");$("newchat").showModal();}
function switchNc(m){ncMode=m;
  $("nc-tab-dm").setAttribute("aria-selected",m==="dm");
  $("nc-tab-grp").setAttribute("aria-selected",m==="grp");
  $("nc-dm").classList.toggle("hidden",m!=="dm");$("nc-grp").classList.toggle("hidden",m!=="grp");
  if(m==="grp")renderGroupPicker();}
async function doSearch(q){
  if(!q||!q.trim()){$("nc-results").innerHTML="";return;}
  let hits=[]; try{hits=(await(await api("/api/chat/search","POST",{pseudo:q.trim()})).json()).results||[];}catch(_){}
  const el=$("nc-results"); el.innerHTML="";
  for(const r of hits){el.appendChild(personRow(r.id,r.pseudo||shortId(r.id),()=>{startChat(r.id);}));}
  if(!hits.length)el.innerHTML='<div class="res rs">No one found.</div>';
}
function personRow(id,name,onClick){
  const d=document.createElement("div");d.className="res";
  d.innerHTML=avatarHTML(id,name)+'<div class="rt"><div class="truncate">'+esc(name)+
    '</div><div class="rs mono truncate">'+esc(id)+'</div></div>';
  d.addEventListener("click",onClick); return d;
}
async function startChat(id){
  await api("/api/chat/contact","POST",{op:"add",id}).catch(()=>{});
  $("newchat").close(); await poll(); openConv(id);
}
function resRow(avId,name,sub,onClick){
  const d=document.createElement("div");d.className="res";
  d.innerHTML=avatarHTML(avId,name)+'<div class="rt"><div class="truncate">'+esc(name)+'</div>'+
    (sub?'<div class="rs mono truncate">'+esc(sub)+'</div>':'')+'</div>';
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
    const h=document.createElement("div");h.className="res head eyebrow";h.textContent="Chats";dd.appendChild(h);
    for(const it of chats.slice(0,8))
      dd.appendChild(resRow(convAvatarId(it.conv),convName(it.conv),
        convIsGroup(it.conv)?"group":shortId(it.conv),()=>{closeSide();openConv(it.conv);}));
  }
  const loading=document.createElement("div");loading.className="res head eyebrow";loading.textContent="People";dd.appendChild(loading);
  const wait=document.createElement("div");wait.className="res rs";wait.textContent="Searching…";dd.appendChild(wait);
  dd.classList.remove("hidden");
  clearTimeout(sideT);
  sideT=setTimeout(async()=>{
    if(($("side-search").value||"").trim()!==q)return;   // stale
    let hits=[]; try{hits=(await(await api("/api/chat/search","POST",{pseudo:q})).json()).results||[];}catch(_){}
    hits=hits.filter(x=>!chats.some(c=>c.conv===x.id));
    wait.remove();
    if(hits.length){for(const r of hits)
      dd.appendChild(resRow(r.id,r.pseudo||shortId(r.id),shortId(r.id),()=>{closeSide();startChat(r.id);}));}
    else{const n=document.createElement("div");n.className="res rs";n.textContent="No people found.";dd.appendChild(n);}
  },320);
}
function closeSide(){$("side-results").classList.add("hidden");$("side-search").value="";renderList();}
function renderGroupPicker(){
  const el=$("grp-members");el.innerHTML="";
  const people=[...ST.contacts,...ST.known];
  const seen=new Set();
  for(const p of people){if(seen.has(p.id))continue;seen.add(p.id);
    const row=personRow(p.id,p.pseudo||shortId(p.id),null);
    const pick=document.createElement("input");
    pick.type="checkbox"; pick.checked=!!ncSel[p.id]; pick.tabIndex=-1;
    row.appendChild(pick);
    row.addEventListener("click",()=>{ncSel[p.id]=!ncSel[p.id];pick.checked=!!ncSel[p.id];});
    el.appendChild(row);}
  if(!people.length)el.innerHTML='<div class="res rs">Add contacts first.</div>';
}
async function createGroup(){
  const name=$("grp-name").value.trim();const members=Object.keys(ncSel).filter(k=>ncSel[k]);
  if(!name||!members.length)return;
  const j=await(await api("/api/chat/group","POST",{op:"create",name,members})).json().catch(()=>({}));
  $("newchat").close(); await poll(); if(j.id)openConv("g:"+j.id);
}

// ---- who you are talking to ----
// The console already describes a node better than a chat page ever would:
// the link, its addresses, what each side may do to the other. So chat does not
// describe it again — it mounts the same view. Where it appears is a preference
// about this screen, so it is stored per browser like the theme.
const DETAIL_MODES=["panel","window","tab"];
function detailMode(){
  try{const v=localStorage.getItem("nmesh_chat_details");
      if(DETAIL_MODES.includes(v))return v;}catch(_){}
  return "panel";
}
function setDetailMode(mode){
  if(!DETAIL_MODES.includes(mode))return;
  try{localStorage.setItem("nmesh_chat_details",mode);}catch(_){}
}
function closePeerPanel(){
  $("peer-panel").hidden=true;
  $("app").classList.remove("show-peer");
  $("peer-view").innerHTML="";
}
async function showPeer(id){
  if(!id)return;
  const mode=detailMode();
  if(mode!=="panel"){ openLinked("/node?from=chat#"+id); return; }
  $("peer-panel").hidden=false;
  $("app").classList.add("show-peer");
  await NODEVIEW.mount("peer-view",id,{
    hide:["chat"],                       // you are already in the conversation
    onGone(){ closePeerPanel(); sel=null; poll(); },
  });
}

// ---- events ----
function bind(){
  $("side-search").addEventListener("input",sideSearch);
  $("side-search").addEventListener("focus",sideSearch);
  document.addEventListener("click",(e)=>{if(!e.target.closest(".side-search"))$("side-results").classList.add("hidden");});
  $("me-btn").addEventListener("click",openSettings);
  $("new-btn").addEventListener("click",openNew);
  $("empty-new").addEventListener("click",openNew);
  $("back-btn").addEventListener("click",()=>{sel=null;$("app").classList.remove("show-conv");$("conv").classList.add("hidden");$("empty").classList.remove("hidden");renderList();});
  $("del-conv").addEventListener("click",async()=>{
    if(!sel)return;
    const group=convIsGroup(sel);
    const agreed=await confirmAction({
      title:group?"Leave and delete this group?":"Remove this contact?",
      body:'<p class="muted small">The conversation disappears from this node. '+
        (group?"The other members keep theirs.":"They can still write to you again.")+"</p>",
      confirmLabel:group?"Leave group":"Remove", danger:true});
    if(!agreed)return;
    const gone=sel;
    await api(group?"/api/chat/group":"/api/chat/contact","POST",
      group?{op:"remove",id:gone.slice(2)}:{op:"remove",id:gone}).catch(()=>{});
    delete MSGS[gone]; sel=null;
    $("conv").classList.add("hidden"); $("empty").classList.remove("hidden");
    $("app").classList.remove("show-conv");
    toast(group?"Group left":"Contact removed");
    poll();});
  $("info-btn").addEventListener("click",()=>{ if(sel&&!convIsGroup(sel))showPeer(sel); });
  $("peer-panel-close").addEventListener("click",closePeerPanel);
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
  document.querySelectorAll("[data-close]").forEach(b=>b.addEventListener("click",()=>$(b.dataset.close).close()));
  $("av-input").addEventListener("change",(e)=>{if(e.target.files[0])pickAvatar(e.target.files[0]);});
  $("av-clear").addEventListener("click",()=>{pendingAvatar="";$("set-av").innerHTML=esc(initials($("set-name").value));});
  $("save-prof").addEventListener("click",saveProfile);
  $("nc-tab-dm").addEventListener("click",()=>switchNc("dm"));
  $("nc-tab-grp").addEventListener("click",()=>switchNc("grp"));
  let st=null;
  $("nc-search").addEventListener("input",(e)=>{clearTimeout(st);const v=e.target.value;st=setTimeout(()=>doSearch(v),300);});
  $("nc-add").addEventListener("click",()=>{const id=$("nc-id").value.trim();if(/^[0-9a-fA-F]{40}$/.test(id))startChat(id.toLowerCase());});
  $("grp-create").addEventListener("click",createGroup);
  PALETTE.add("New chat","Action",openNew);
  PALETTE.add("Your profile","Action",openSettings);
  PALETTE.add("Switch theme","Action",()=>THEME.toggle());
  PALETTE.add("Back to the console","Go to",()=>{window.location="/";});
}

// ---- auth / boot ----
async function enter(token){
  const h={}; if(token)h["Authorization"]="Bearer "+token;
  const r=await fetch("/api/chat/messages?since=0",{headers:h});
  if(!r.ok)return false;
  if(token)SESSION.set(token);
  $("login").classList.add("hidden"); $("app").classList.remove("hidden");
  mountShell();
  await poll(); if(timer)clearInterval(timer); timer=setInterval(poll,1200);
  return true;
}
$("login-form").addEventListener("submit",async(e)=>{
  e.preventDefault(); setMessage("err","");
  await withBusy(e.submitter||$("login-form").querySelector("button"),async()=>{
    try{
      const res=await fetch("/api/login",{method:"POST",
        headers:{"Content-Type":"application/json"},
        body:JSON.stringify({password:$("password").value})});
      if(!res.ok){const j=await res.json().catch(()=>({}));
        setMessage("err",j.error||"Login failed",true);return;}
      $("password").value=""; await enter((await res.json()).token);
    }catch(_){ setMessage("err","Console is not reachable",true); }
  });
});
bind();
(function(){let tok=null;try{tok=sessionStorage.getItem("nmesh_token");}catch(_){}
  enter(tok).then((ok)=>{if(!ok)$("login").classList.remove("hidden");});})();
"""
