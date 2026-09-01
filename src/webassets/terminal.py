"""
The terminal: one emulator, one session driver, and the page that gives them
the whole screen.

Split out of the fleet page because there are now two places a shell is drawn —
the panel on ``/fleet`` and the full-screen ``/term`` — and two copies of a
terminal is two copies of every bug in one. What lives here:

* :data:`CSS` / :data:`JS` — the emulator, the key mapping and the session
  driver, mounted by both pages. The emulator is written rather than depended
  on: a shell you can type ``sudo`` into needs a terminal, not a log pane, and
  an emulator library would cost a name in a supply chain this project keeps
  deliberately short.
* :data:`PAGE_HTML` / :data:`PAGE_CSS` / :data:`PAGE_JS` — ``/term``: the
  terminal with nothing around it, a key row for the keys a phone does not
  have, and the files of the machine it is talking to.

Why a page of its own, and why it is built for a phone
------------------------------------------------------
A terminal in a panel is a terminal in a box: 62% of the viewport, a rail beside
it, and on a phone a keyboard covering what is left. The full-screen page is the
same session seen properly — and it is opened in a **tab**, never a pop-up
window, because a 700px window is exactly the thing being escaped.

On Android nothing about a terminal is automatic. The soft keyboard only appears
for a focused editable element, so there is a real one behind the screen and a
tap on the terminal focuses it. It reports no usable ``keydown`` (an IME sends
``229``), so what is typed is read from ``input`` events instead. It has no
Escape, no Tab, no Ctrl and no arrows, so those are a row of keys under the
screen — the arrangement Termux settled on, for the same reasons. And it resizes
the viewport instead of scrolling the page, so the layout follows
``visualViewport`` rather than guessing.
"""

CSS = """
/* The terminal is the one place with its own colour world: it renders bytes a
   remote shell chose, so it keeps a fixed dark ground in both themes rather
   than recolouring somebody else's output. */
.term{--page-term-bg:#0a0f16;--page-term-fg:#cfe0f7;
  margin:0;padding:var(--s-4);min-height:440px;max-height:62vh;overflow:auto;
  background:var(--page-term-bg);color:var(--page-term-fg);
  font:13px/1.45 var(--mono);white-space:pre-wrap;overflow-wrap:anywhere;
  border-bottom:1px solid var(--border)}
.term:focus-visible{outline:2px solid var(--ring);outline-offset:-2px}
.t-c0{color:#5b6b80}.t-c1{color:#ff8079}.t-c2{color:#5fd39a}.t-c3{color:#f2c261}
.t-c4{color:#79b0ff}.t-c5{color:#d79bff}.t-c6{color:#5fd9d0}.t-c7{color:#e8eef5}
.t-b{font-weight:700}.t-cur{background:#cfe0f7;color:#0a0f16}
"""


JS = r"""
// ---- a small terminal ------------------------------------------------------
// Written rather than depended on: a shell you can type `sudo` into needs a
// terminal, not a log pane, and pulling in an emulator library for it would
// cost a name in the supply chain this project keeps deliberately short.
//
// What it implements is what a shell session actually uses: printable text,
// CR/LF/BS/TAB/BEL, cursor movement, the two erase commands, and SGR colours.
// Anything else is consumed and ignored rather than printed — an unknown escape
// must never end up on screen as garbage.
function Term(cols,rows){
  this.cols=cols; this.rows=rows;
  this.x=0; this.y=0; this.sgr=""; this.scrollback=[];
  this.grid=[]; for(let i=0;i<rows;i++)this.grid.push(this.blankRow());
  this.pending="";
}
Term.prototype.blankRow=function(){
  const row=[]; for(let i=0;i<this.cols;i++)row.push({ch:" ",cls:""});
  return row;
};
Term.prototype.newline=function(){
  this.y++;
  if(this.y>=this.rows){
    this.scrollback.push(this.grid.shift());
    if(this.scrollback.length>2000)this.scrollback.shift();
    this.grid.push(this.blankRow());
    this.y=this.rows-1;
  }
};
Term.prototype.put=function(ch){
  if(this.x>=this.cols){this.x=0;this.newline();}
  this.grid[this.y][this.x]={ch:ch,cls:this.sgr};
  this.x++;
};
Term.prototype.eraseLine=function(mode){
  const row=this.grid[this.y];
  const from=mode===1?0:(mode===2?0:this.x);
  const to=mode===0?this.cols:(mode===1?this.x+1:this.cols);
  for(let i=from;i<to&&i<this.cols;i++)row[i]={ch:" ",cls:""};
};
Term.prototype.eraseDisplay=function(mode){
  if(mode===2||mode===3){
    for(let y=0;y<this.rows;y++)this.grid[y]=this.blankRow();
    if(mode===2){this.x=0;this.y=0;}
    return;
  }
  this.eraseLine(mode===1?1:0);
  if(mode===0)for(let y=this.y+1;y<this.rows;y++)this.grid[y]=this.blankRow();
  else for(let y=0;y<this.y;y++)this.grid[y]=this.blankRow();
};
Term.prototype.sgrClass=function(params){
  // Only the attributes that make output readable: reset, bold, and the eight
  // foreground colours (plus their bright forms).
  let cls=this.sgr;
  for(const raw of params){
    const n=raw===""?0:parseInt(raw,10);
    if(n===0)cls="";
    else if(n===1)cls=(cls+" t-b").trim();
    else if(n>=30&&n<=37)cls=cls.replace(/t-c\d/g,"").trim()+" t-c"+(n-30);
    else if(n>=90&&n<=97)cls=cls.replace(/t-c\d/g,"").trim()+" t-c"+(n-90)+" t-b";
    else if(n===39)cls=cls.replace(/t-c\d/g,"").trim();
  }
  return cls.replace(/\s+/g," ").trim();
};
Term.prototype.write=function(text){
  let data=this.pending+text; this.pending="";
  for(let i=0;i<data.length;i++){
    const ch=data[i];
    if(ch==="\x1b"){
      // An escape may be split across two chunks: keep the tail and retry.
      const rest=data.slice(i);
      const csi=/^\x1b\[([0-9;?]*)([ -\/]*)([@-~])/.exec(rest);
      if(csi){ this.csi(csi[1],csi[3]); i+=csi[0].length-1; continue; }
      const osc=/^\x1b\][^\x07\x1b]*(\x07|\x1b\\)/.exec(rest);
      if(osc){ i+=osc[0].length-1; continue; }        // window title and friends
      const two=/^\x1b[=>()#][0-9A-Za-z]?/.exec(rest);
      if(two){ i+=two[0].length-1; continue; }
      if(rest.length<8){ this.pending=rest; return; }  // incomplete, wait
      continue;                                        // unknown: drop it
    }
    if(ch==="\n"){ this.newline(); continue; }
    if(ch==="\r"){ this.x=0; continue; }
    if(ch==="\b"){ if(this.x>0)this.x--; continue; }
    if(ch==="\t"){ const next=(Math.floor(this.x/8)+1)*8;
                   while(this.x<next&&this.x<this.cols)this.put(" ");
                   continue; }
    if(ch==="\x07")continue;                          // bell
    if(ch<" ")continue;                                // other control bytes
    this.put(ch);
  }
};
Term.prototype.csi=function(paramText,final){
  const params=paramText.replace("?","").split(";");
  const n=Math.max(1,parseInt(params[0]||"1",10)||1);
  switch(final){
    case "A": this.y=Math.max(0,this.y-n); break;
    case "B": this.y=Math.min(this.rows-1,this.y+n); break;
    case "C": this.x=Math.min(this.cols-1,this.x+n); break;
    case "D": this.x=Math.max(0,this.x-n); break;
    case "G": this.x=Math.min(this.cols-1,Math.max(0,n-1)); break;
    case "H": case "f": {
      const row=Math.max(1,parseInt(params[0]||"1",10)||1);
      const col=Math.max(1,parseInt(params[1]||"1",10)||1);
      this.y=Math.min(this.rows-1,row-1); this.x=Math.min(this.cols-1,col-1);
      break;
    }
    case "J": this.eraseDisplay(parseInt(params[0]||"0",10)||0); break;
    case "K": this.eraseLine(parseInt(params[0]||"0",10)||0); break;
    case "m": this.sgr=this.sgrClass(params); break;
    default: break;                                    // consumed, never printed
  }
};
Term.prototype.render=function(showCursor){
  const rows=this.scrollback.slice(-800).concat(this.grid);
  // Where the cursor is, in the concatenated view. Drawn because a terminal you
  // type into without one is disorienting — and because on a password prompt
  // the cursor not moving is the visible sign that echo is off.
  const cursorRow=showCursor===false?-1:this.scrollback.slice(-800).length+this.y;
  const out=[];
  for(let index=0;index<rows.length;index++){
    const row=rows[index];
    let line="",cls=null,run="";
    const flush=()=>{
      if(!run)return;
      line+=cls?('<span class="'+cls+'">'+escHtml(run)+"</span>"):escHtml(run);
      run="";
    };
    for(let column=0;column<row.length;column++){
      const cell=row[column];
      const isCursor=index===cursorRow&&column===this.x;
      const cellCls=isCursor?(cell.cls+" t-cur").trim():cell.cls;
      if(cellCls!==cls){flush();cls=cellCls;}
      run+=cell.ch;
    }
    flush();
    // Trailing blanks are trimmed: a row is `cols` cells wide, and padding
    // every line to the full width would make the pane scroll sideways for
    // nothing. The cursor cell survives because it carries a class.
    out.push(line.replace(/(\s|&nbsp;)+$/,""));
  }
  return out.join("\n");
};
function escHtml(text){
  return text.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
}

// ---- one shell session -----------------------------------------------------
// Both pages drive a session through this. It owns the terminal, the polling
// cadence and the sid; the page owns the chrome around it and says what to do
// when it opens or closes.
//
// The cadence is its own, faster than any ledger poll and running only while a
// session is live, so the refresh interval in a top bar can be set to zero
// without freezing somebody's shell.
const SHELL_TICK = 600;

function termSize(box){
  // Measured from the pane rather than assumed: the remote pty is told these
  // dimensions, and a shell that thinks it has a different width redraws wrong.
  const probe = document.createElement("span");
  probe.style.cssText = "position:absolute;visibility:hidden;white-space:pre";
  probe.textContent = "0".repeat(80);
  box.appendChild(probe);
  const charWidth = (probe.getBoundingClientRect().width / 80) || 8;
  const lineHeight = parseFloat(getComputedStyle(box).lineHeight) || 16;
  box.removeChild(probe);
  return {
    cols: Math.max(20, Math.min(200, Math.floor((box.clientWidth - 24) / charWidth))),
    rows: Math.max(10, Math.min(60, Math.floor((box.clientHeight - 24) / lineHeight))),
  };
}

function ShellSession(box, handlers){
  this.box = box;
  this.on = handlers || {};
  this.node = null; this.sid = null; this.off = 0; this.term = null;
  this.timer = null; this.size = {cols:80, rows:24};
  this.pending = ""; this.sending = null;
}
ShellSession.prototype.say = function(text){
  this.box.textContent = text;
};
ShellSession.prototype.open = async function(node){
  await this.stop();
  this.node = node; this.sid = null; this.off = 0;
  this.size = termSize(this.box);
  this.term = new Term(this.size.cols, this.size.rows);
  this.box.textContent = "";
  try{
    await api("/api/fleet/shell", "POST",
              {node, cols:this.size.cols, rows:this.size.rows});
  }catch(_){
    this.node = null;
    this.say("Could not open a shell on that node.");
    return false;
  }
  this.timer = setInterval(() => this.poll(), SHELL_TICK);
  if(this.on.opened) this.on.opened();
  return true;
};
// Attaching rather than opening: a shell this console already holds — one this
// tab did not start — is picked back up instead of a second one being spawned.
ShellSession.prototype.attach = function(node){
  this.node = node; this.sid = null; this.off = 0;
  this.size = termSize(this.box);
  this.term = new Term(this.size.cols, this.size.rows);
  this.box.textContent = "";
  if(!this.timer) this.timer = setInterval(() => this.poll(), SHELL_TICK);
};
ShellSession.prototype.poll = async function(){
  if(!this.node) return;
  const where = this.sid ? "sid=" + encodeURIComponent(this.sid)
                         : "node=" + encodeURIComponent(this.node);
  let answer;
  try{ answer = await apiJson("/api/fleet/shell?" + where + "&offset=" + this.off); }
  catch(_){ return; }
  if(!answer.ok || !answer.data) return;       // not open yet, or already gone
  const data = answer.data;
  if(!this.sid){ this.sid = data.sid; this.off = 0; }
  if(data.data){
    const raw = atob(data.data);
    let text;
    try{ text = new TextDecoder().decode(Uint8Array.from(raw, (c) => c.charCodeAt(0))); }
    catch(_){ text = raw; }
    const atEnd = this.box.scrollTop + this.box.clientHeight >= this.box.scrollHeight - 40;
    if(!this.term) this.term = new Term(80, 24);
    this.term.write(text);
    this.box.innerHTML = this.term.render();
    if(atEnd) this.box.scrollTop = this.box.scrollHeight;
  }
  this.off = data.seq;
  if(!data.open){
    this.box.innerHTML = (this.term ? this.term.render(false) : "") +
      "\n[session closed]\n";
    this.node = null; this.sid = null;
    this.halt();
    if(this.on.closed) this.on.closed();
  }
};
// Keystrokes are queued, never fired in parallel. One request per key looks
// fine and is not: two POSTs in flight reach a threaded server in whichever
// order they finish, so typing quickly delivers `panle` instead of `panel`.
// Draining a buffer keeps the order and coalesces a burst into one request.
ShellSession.prototype.send = function(text){
  if(!this.sid || !text) return Promise.resolve();
  this.pending += text;
  if(!this.sending) this.sending = this.drain();
  return this.sending;
};
ShellSession.prototype.drain = async function(){
  try{
    while(this.pending && this.sid){
      const text = this.pending;
      this.pending = "";
      const encoded = new TextEncoder().encode(text);
      let binary = "";
      encoded.forEach((byte) => { binary += String.fromCharCode(byte); });
      try{
        await api("/api/fleet/input", "POST",
                  {node:this.node, sid:this.sid, data:btoa(binary)});
      }catch(_){}                               // the poll will show it went
    }
  }finally{ this.sending = null; }
};
// The pty is told the size it actually has: a shell that thinks it is 80 wide
// on a 40-column phone redraws every prompt wrong.
ShellSession.prototype.fit = async function(){
  if(!this.sid || !this.term) return;
  const size = termSize(this.box);
  if(size.cols === this.size.cols && size.rows === this.size.rows) return;
  this.size = size;
  this.term.cols = size.cols; this.term.rows = size.rows;
  try{
    await api("/api/fleet/resize", "POST",
              {node:this.node, sid:this.sid, cols:size.cols, rows:size.rows});
  }catch(_){}
};
ShellSession.prototype.halt = function(){
  if(this.timer){ clearInterval(this.timer); this.timer = null; }
};
ShellSession.prototype.stop = async function(){
  this.halt();
  const node = this.node, sid = this.sid;
  this.node = null; this.sid = null;
  if(!sid) return;
  try{ await api("/api/fleet/close", "POST", {node, sid}); }catch(_){}
};
ShellSession.prototype.live = function(){ return !!this.sid; };

// What a key sends. Nothing is echoed locally: the remote pty decides what
// comes back, which is exactly why a password prompt stays invisible — the pty
// turns echo off and there is nothing on this side to show it anyway.
function keyBytes(event){
  if(event.ctrlKey && !event.altKey && event.key.length === 1){
    const code = event.key.toUpperCase().charCodeAt(0);
    if(code >= 64 && code <= 95) return String.fromCharCode(code - 64);   // ^A..^_
    if(event.key === "?") return "\x7f";
  }
  switch(event.key){
    case "Enter": return "\r";
    case "Backspace": return "\x7f";
    case "Tab": return "\t";
    case "Escape": return "\x1b";
    case "ArrowUp": return "\x1b[A";
    case "ArrowDown": return "\x1b[B";
    case "ArrowRight": return "\x1b[C";
    case "ArrowLeft": return "\x1b[D";
    case "Home": return "\x1b[H";
    case "End": return "\x1b[F";
    case "Delete": return "\x1b[3~";
    case "PageUp": return "\x1b[5~";
    case "PageDown": return "\x1b[6~";
    default: break;
  }
  if(event.key.length === 1 && !event.ctrlKey && !event.metaKey) return event.key;
  return null;
}
"""


PAGE_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="theme-color" content="#0a0f16">
<title>NMesh Terminal</title>
<script src="/theme.js"></script>
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<link rel="stylesheet" href="/term.css">
</head>
<body data-app-name="NMesh Terminal">

<div id="login" class="gate hidden">
  <form id="login-form">
    <div class="mark" aria-hidden="true">NM</div>
    <div><p class="eyebrow">Terminal</p><h1>Sign in</h1></div>
    <p class="muted small">The terminal uses the console password of this node.</p>
    <label class="field"><span>Console password</span>
      <input id="password" type="password" autocomplete="current-password" autofocus></label>
    <button type="submit" class="primary wide">Enter</button>
    <p id="err" class="msg error" role="alert"></p>
  </form>
</div>

<div id="page" class="page hidden">
  <header class="tbar">
    <a class="btn ghost sm" href="/fleet" title="Back to the fleet">Fleet</a>
    <label class="sr-only" for="node">Node</label>
    <select id="node" class="sm"></select>
    <span id="state" class="badge">idle</span>
    <span class="grow"></span>
    <button id="open" class="primary sm">Open</button>
    <button id="files-open" class="ghost sm">Files</button>
    <button id="copy" class="ghost sm">Copy</button>
    <button id="paste" class="ghost sm">Paste</button>
    <button id="kbd" class="ghost sm" aria-pressed="false">Keyboard</button>
    <button id="stop" class="danger sm">Close</button>
  </header>

  <pre id="term" class="term full" tabindex="0" role="textbox" aria-label="Remote shell"
       aria-multiline="true">Pick a node and press Open.</pre>

  <!-- The real editable element. Android only raises its keyboard for one of
       these, and only while it has focus — so it lives behind the screen rather
       than being hidden, which would make it unfocusable. -->
  <textarea id="tin" class="offscreen" autocapitalize="off" autocorrect="off"
            autocomplete="off" spellcheck="false" aria-hidden="true" tabindex="-1"></textarea>

  <div id="keys" class="keys" role="toolbar" aria-label="Terminal keys"></div>
</div>

<dialog id="files-dialog">
  <div class="sheet">
    <div class="sheet-head">
      <h2>Files</h2>
      <button id="files-up" class="ghost sm">Up</button>
      <button id="files-new" class="ghost sm">New folder</button>
      <button id="files-send" class="ghost sm">Upload</button>
      <button id="files-close" class="icon sm" aria-label="Close">&times;</button>
    </div>
    <div class="sheet-body">
      <p id="files-path" class="mono tiny muted"></p>
      <form id="mkdir-form" class="toolbar" hidden>
        <label class="field grow"><span class="sr-only">Folder name</span>
          <input id="mkdir-name" placeholder="folder name" autocomplete="off"></label>
        <button type="submit" class="primary sm">Create</button>
      </form>
      <input id="files-file" type="file" multiple class="hidden">
      <div id="files-list" class="files"></div>
      <p id="files-msg" class="msg"></p>
    </div>
  </div>
</dialog>

<dialog id="paste-dialog">
  <form id="paste-form" method="dialog">
    <h2>Paste into the terminal</h2>
    <p class="muted small">This browser did not hand over the clipboard, so paste
      here and send it. Nothing is stored.</p>
    <label class="field"><span class="sr-only">Text to send</span>
      <textarea id="paste-text" rows="4" class="mono" autocomplete="off"></textarea></label>
    <div class="btn-row"><button id="paste-send" class="primary">Send</button>
      <button value="cancel">Cancel</button></div>
  </form>
</dialog>

<div id="toasts" class="toasts" role="status" aria-live="polite"></div>
<script src="/term.js"></script>
</body>
</html>
"""


PAGE_CSS = """
/* The page is the terminal. Everything else is a strip above it and a strip
   below, and the middle takes whatever is left — `--vh` rather than a viewport
   unit because on Android the soft keyboard shrinks the *visual* viewport and
   `100dvh` keeps describing the screen behind it. */
body{height:100vh;overflow:hidden}
.page{display:flex;flex-direction:column;height:var(--page-vh,100dvh);
  background:var(--canvas)}
.tbar{display:flex;align-items:center;gap:var(--s-2);flex-wrap:wrap;
  padding:var(--s-2) var(--s-3);border-bottom:1px solid var(--border);
  background:var(--surface);padding-top:calc(var(--s-2) + env(safe-area-inset-top))}
.tbar select{min-width:0;max-width:40vw}
.term.full{flex:1 1 auto;min-height:0;max-height:none;border-bottom:0;
  padding:var(--s-3);font-size:13px}
/* Behind the screen, not hidden: `display:none` cannot take focus, and focus is
   the only thing that raises a phone's keyboard. */
.offscreen{position:fixed;left:-9999px;top:0;width:1px;height:1px;opacity:0;
  border:0;padding:0;resize:none}
.keys{display:flex;gap:6px;overflow-x:auto;scrollbar-width:none;
  padding:6px var(--s-2) calc(6px + env(safe-area-inset-bottom));
  border-top:1px solid var(--border);background:var(--surface)}
.keys::-webkit-scrollbar{display:none}
.keys button{min-height:34px;padding:0 10px;font:600 var(--fs-xs)/1 var(--mono);
  flex:0 0 auto;color:var(--text-muted)}
.keys button[aria-pressed="true"]{background:var(--accent-soft);
  border-color:var(--accent);color:var(--accent)}
.files{display:flex;flex-direction:column;border:1px solid var(--border);
  border-radius:var(--r-md);overflow:hidden}
.files .row{display:flex;align-items:center;gap:var(--s-3);width:100%;
  padding:var(--s-2) var(--s-3);border:0;border-bottom:1px solid var(--border);
  background:transparent;text-align:left;font-size:var(--fs-sm);min-height:40px}
.files .row:last-child{border-bottom:0}
.files .row:hover{background:var(--surface-2)}
.files .row .n{flex:1 1 auto;min-width:0;overflow:hidden;text-overflow:ellipsis;
  white-space:nowrap}
.files .row .s{color:var(--text-faint);font-size:var(--fs-2xs);
  font-variant-numeric:tabular-nums}
.files .row.dir .n{font-weight:620}
@media (max-width:640px){
  .tbar{gap:6px}
  .tbar .btn,.tbar button{font-size:var(--fs-2xs)}
  .term.full{font-size:12px;padding:var(--s-2)}
}
"""


PAGE_JS = r"""
// ---- /term: the terminal with the whole screen ------------------------------
// One session at a time, on the node named in the picker. What this page adds
// over the panel on /fleet is everything a phone needs: a real editable element
// behind the screen so Android raises its keyboard, the keys that keyboard does
// not have, a clipboard that works both ways, and the machine's files.

let TERM_SESSION = null;
let NODES = [];
const MODS = {ctrl:false, alt:false};
const FILES = {node:"", path:"", busy:false};

function setState(text, tone){
  const chip = $("state");
  chip.textContent = text;
  chip.className = "badge" + (tone ? " " + tone : "");
}

// ---- the node this terminal is talking to ----------------------------------

async function loadNodes(){
  let data;
  // A high `since` because this page wants the node list, not the activity log:
  // asking for everything and dropping most of it is the ledger's whole weight
  // over the wire on every open.
  try{ data = (await apiJson("/api/fleet/state?since=2000000000")).data; }
  catch(_){ return; }
  NODES = (data.managed || []).filter((entry) => (entry.caps || []).includes("shell"));
  const select = $("node");
  const wanted = new URLSearchParams(location.search).get("node") || select.value;
  select.innerHTML = NODES.map((entry) =>
    '<option value="' + esc(entry.id) + '">' +
    esc(entry.label || entry.pseudo || shortId(entry.id)) + "</option>").join("");
  if(!NODES.length){
    select.innerHTML = '<option value="">No node has granted a shell</option>';
    setState("nothing to open");
    return;
  }
  if(wanted && NODES.some((entry) => entry.id === wanted)) select.value = wanted;
}

function currentNode(){ return $("node").value || ""; }

// ---- keys the phone does not have ------------------------------------------
// The row Termux settled on, and for the same reason: without Esc, Tab, Ctrl and
// the arrows, a soft keyboard cannot drive a shell at all. Ctrl and Alt are
// sticky for one keystroke — pressing two keys at once is not something a touch
// screen does well.

const KEYROW = [
  ["esc", "\x1b"], ["tab", "\t"], ["ctrl", "#ctrl"], ["alt", "#alt"],
  ["arrowLeft", "\x1b[D"], ["arrowUp", "\x1b[A"], ["arrowDown", "\x1b[B"],
  ["arrowRight", "\x1b[C"],
  ["home", "\x1b[H"], ["end", "\x1b[F"], ["pgup", "\x1b[5~"], ["pgdn", "\x1b[6~"],
  ["^c", "\x03"], ["^d", "\x04"], ["^z", "\x1a"],
  ["-", "-"], ["/", "/"], ["|", "|"], ["~", "~"],
  ["paste", "#paste"],
];
const ARROWS = {arrowLeft:"Left", arrowUp:"Up", arrowDown:"Down", arrowRight:"Right"};

function paintKeys(){
  $("keys").innerHTML = KEYROW.map(([label, payload]) => {
    const sticky = payload === "#ctrl" || payload === "#alt";
    const pressed = sticky ? MODS[payload.slice(1)] : false;
    const body = ARROWS[label] ? icon(label, ARROWS[label] + " arrow") : esc(label);
    return '<button type="button" data-key="' + esc(payload) + '"' +
      (sticky ? ' aria-pressed="' + (pressed ? "true" : "false") + '"' : "") +
      ' title="' + esc(ARROWS[label] || label) + '">' + body + "</button>";
  }).join("");
}

function ctrlChar(text){
  const code = text.toUpperCase().charCodeAt(0);
  if(code >= 64 && code <= 95) return String.fromCharCode(code - 64);   // ^A..^_
  if(text === "?") return "\x7f";
  if(text === " ") return "\x00";
  return text;
}

// Everything typed goes through here, from whichever of the three input paths:
// the physical keyboard, the hidden field the soft keyboard feeds, and the row.
async function typeIn(text){
  if(!text || !TERM_SESSION) return;
  if(MODS.ctrl && text.length === 1) text = ctrlChar(text);
  if(MODS.alt) text = "\x1b" + text;
  if(MODS.ctrl || MODS.alt){ MODS.ctrl = MODS.alt = false; paintKeys(); }
  await TERM_SESSION.send(text);
}

// ---- the three ways something gets typed ------------------------------------

// 1. A physical keyboard, on the pane itself.
$("term").addEventListener("keydown", async (event) => {
  if(!TERM_SESSION || !TERM_SESSION.live()) return;
  if((event.ctrlKey || event.metaKey) && ["c", "C"].includes(event.key) &&
     String(window.getSelection() || "")) return;         // let a copy through
  if((event.ctrlKey || event.metaKey) && ["v", "V"].includes(event.key)) return;
  const bytes = keyBytes(event);
  if(bytes === null) return;
  event.preventDefault();
  // A modifier already held on a real keyboard is in `bytes`; the sticky ones
  // are for the row, so they must not be applied twice.
  if(event.ctrlKey || event.metaKey || event.altKey) await TERM_SESSION.send(bytes);
  else await typeIn(bytes);
});

// 2. A soft keyboard, through the field behind the screen. Android reports no
//    usable key for an IME (`keydown` arrives as 229), so what was typed is read
//    from the input events instead and the field is emptied again at once.
$("tin").addEventListener("input", async (event) => {
  const text = event.target.value;
  event.target.value = "";
  if(!text) return;
  // Enter arrives as a line break; a pty wants a carriage return.
  await typeIn(text.replace(/\n/g, "\r"));
});
$("tin").addEventListener("beforeinput", async (event) => {
  // Backspace on an empty field produces no `input` event at all, so it has to
  // be caught here or it would never reach the shell.
  if(event.inputType === "deleteContentBackward"){
    event.preventDefault();
    await typeIn("\x7f");
  }
});
$("tin").addEventListener("keydown", async (event) => {
  // A phone with a hardware keyboard attached, or the arrows some soft keyboards
  // do send: handled here so the field never has to hold them.
  if(["Enter", "Backspace"].includes(event.key)) return;   // the input path has these
  const bytes = keyBytes(event);
  if(bytes === null || bytes === event.key) return;        // plain text: let it type
  event.preventDefault();
  await typeIn(bytes);
});
$("tin").addEventListener("paste", async (event) => {
  event.preventDefault();
  await TERM_SESSION.send((event.clipboardData || window.clipboardData).getData("text"));
});
$("term").addEventListener("paste", async (event) => {
  event.preventDefault();
  await TERM_SESSION.send((event.clipboardData || window.clipboardData).getData("text"));
});

// 3. The key row. `pointerdown` is where the default is stopped: without it the
//    button takes focus, the phone's keyboard folds away, and every second key
//    press is spent bringing it back.
$("keys").addEventListener("pointerdown", (event) => {
  if(event.target.closest("button")) event.preventDefault();
});
$("keys").addEventListener("click", async (event) => {
  const button = event.target.closest("[data-key]");
  if(!button) return;
  const payload = button.dataset.key;
  if(payload === "#ctrl" || payload === "#alt"){
    const name = payload.slice(1);
    MODS[name] = !MODS[name];
    paintKeys();
    focusInput();
    return;
  }
  if(payload === "#paste"){ await pasteIn(); return; }
  await typeIn(payload);
  focusInput();
});

// Tapping the screen means "type here", which on a phone means "raise the
// keyboard" — and the only thing that does that is focus on a real field.
function focusInput(){
  const input = $("tin");
  try{ input.focus({preventScroll:true}); }catch(_){ input.focus(); }
}
$("term").addEventListener("pointerup", () => {
  if(String(window.getSelection() || "")) return;   // a selection is not a tap
  if(TERM_SESSION && TERM_SESSION.live()) focusInput();
});
$("kbd").addEventListener("click", () => {
  const wanted = $("kbd").getAttribute("aria-pressed") !== "true";
  $("kbd").setAttribute("aria-pressed", wanted ? "true" : "false");
  if(wanted) focusInput(); else $("tin").blur();
});

// ---- clipboard --------------------------------------------------------------

$("copy").addEventListener("click", async () => {
  const selected = String(window.getSelection() || "");
  const text = selected || $("term").innerText;
  if(!text.trim()){ toast("Nothing to copy", "warn"); return; }
  await copyText(text);
});

async function pasteIn(){
  let text = "";
  try{ text = await navigator.clipboard.readText(); }
  catch(_){ text = ""; }
  if(text){ await TERM_SESSION.send(text); return; }
  // Firefox and most of Android refuse a silent clipboard read. A field the
  // person pastes into themselves is the one path that always works.
  $("paste-text").value = "";
  $("paste-dialog").showModal();
  $("paste-text").focus();
}
$("paste").addEventListener("click", () => pasteIn());
$("paste-send").addEventListener("click", async (event) => {
  event.preventDefault();
  const text = $("paste-text").value;
  $("paste-text").value = "";
  $("paste-dialog").close();
  await TERM_SESSION.send(text);
  focusInput();
});

// ---- opening and closing ----------------------------------------------------

$("open").addEventListener("click", (event) => withBusy(event.target, async () => {
  const node = currentNode();
  if(!node) return;
  setState("opening…");
  const ok = await TERM_SESSION.open(node);
  setState(ok ? "live" : "failed", ok ? "ok" : "danger");
  if(ok){ FILES.node = node; FILES.path = ""; focusInput(); }
}));

$("stop").addEventListener("click", async () => {
  await TERM_SESSION.stop();
  setState("closed");
});

$("node").addEventListener("change", () => {
  if(TERM_SESSION.live()) return;                  // a live session keeps its node
  setState("idle");
  $("term").textContent = "Press Open to start a shell on that node.";
});

// The soft keyboard shrinks the *visual* viewport rather than scrolling the
// page, so the layout follows it — otherwise the key row ends up under the
// keyboard, which is exactly where it is least useful.
function fitViewport(){
  const view = window.visualViewport;
  document.body.style.setProperty("--page-vh",
    (view ? view.height : window.innerHeight) + "px");
  if(TERM_SESSION) TERM_SESSION.fit();
}
if(window.visualViewport){
  window.visualViewport.addEventListener("resize", debounce(fitViewport, 120));
}
window.addEventListener("resize", debounce(fitViewport, 200));
window.addEventListener("orientationchange", () => setTimeout(fitViewport, 300));

// ---- files ------------------------------------------------------------------
// The same right as the shell, so it is the same node and needs no second grant.
// What it is *for* is the case a terminal is bad at: getting a file off the
// machine, or onto it, from a phone.

function fileRow(entry){
  const kind = entry.kind === "dir" ? "dir" : "file";
  return '<button type="button" class="row ' + kind + '" data-name="' +
    esc(entry.name) + '" data-kind="' + kind + '">' +
    icon(kind === "dir" ? "folder" : "file") +
    '<span class="n">' + esc(entry.name) + "</span>" +
    (entry.link ? '<span class="s">link</span>' : "") +
    '<span class="s">' + (kind === "dir" ? "" : fmtBytes(entry.size)) + "</span></button>";
}

async function loadFiles(path){
  const node = FILES.node || currentNode();
  if(!node){ setMessage("files-msg", "Pick a node first.", true); return; }
  FILES.node = node;
  setMessage("files-msg", "Reading…");
  let answer;
  try{
    answer = await apiJson("/api/fleet/files?node=" + encodeURIComponent(node) +
                           "&path=" + encodeURIComponent(path || ""));
  }catch(_){ setMessage("files-msg", "That node could not be reached.", true); return; }
  if(!answer.ok){
    setMessage("files-msg", answer.data.error || "That directory could not be read.", true);
    return;
  }
  const data = answer.data;
  FILES.path = data.path;
  FILES.parent = data.parent || "";
  $("files-path").textContent = data.path;
  $("files-up").disabled = !data.parent;
  $("files-list").innerHTML = (data.entries || []).map(fileRow).join("")
    || emptyHTML("Nothing here", "This directory is empty.");
  setMessage("files-msg", data.truncated
    ? "Showing the first " + (data.entries || []).length + " entries — " +
      data.truncated + " more are not listed."
    : (data.writable ? "" : "Read-only for that node's account."));
}

$("files-open").addEventListener("click", async () => {
  $("files-dialog").showModal();
  await loadFiles(FILES.path);
});
$("files-close").addEventListener("click", () => $("files-dialog").close());
$("files-up").addEventListener("click", () => loadFiles(FILES.parent));
$("files-list").addEventListener("click", async (event) => {
  const row = event.target.closest("[data-name]");
  if(!row || FILES.busy) return;
  const path = FILES.path.replace(/\/$/, "") + "/" + row.dataset.name;
  if(row.dataset.kind === "dir"){ await loadFiles(path); return; }
  await download(path, row.dataset.name);
});

async function download(path, name){
  FILES.busy = true;
  setMessage("files-msg", "Fetching " + name + "…");
  try{
    const response = await api("/api/fleet/file?node=" + encodeURIComponent(FILES.node) +
                               "&path=" + encodeURIComponent(path));
    if(!response.ok){
      const data = await response.json().catch(() => ({}));
      setMessage("files-msg", data.error || "That file could not be fetched.", true);
      return;
    }
    const blob = await response.blob();
    // Handed to the browser as a download rather than opened: bytes from
    // somebody else's machine are not something this page should render.
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url; link.download = name;
    document.body.appendChild(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 10000);
    setMessage("files-msg", "Saved " + name + " (" + fmtBytes(blob.size) + ").");
  }catch(_){
    setMessage("files-msg", "That file could not be fetched.", true);
  }finally{ FILES.busy = false; }
}

$("files-new").addEventListener("click", () => {
  const form = $("mkdir-form");
  form.hidden = !form.hidden;
  if(!form.hidden) $("mkdir-name").focus();
});
$("mkdir-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const name = $("mkdir-name").value.trim();
  if(!name) return;
  const answer = await apiJson("/api/fleet/mkdir", "POST",
    {node:FILES.node, path:FILES.path, name});
  if(!answer.ok){
    setMessage("files-msg", answer.data.error || "That folder was refused.", true);
    return;
  }
  $("mkdir-name").value = "";
  $("mkdir-form").hidden = true;
  await loadFiles(FILES.path);
});

$("files-send").addEventListener("click", () => $("files-file").click());
$("files-file").addEventListener("change", async (event) => {
  const files = Array.from(event.target.files || []);
  event.target.value = "";
  for(const file of files){
    setMessage("files-msg", "Sending " + file.name + "…");
    let answer;
    try{
      answer = await apiJson("/api/fleet/upload", "POST", {
        node:FILES.node, path:FILES.path, name:file.name,
        data:await base64Of(file)});
    }catch(_){
      setMessage("files-msg", "That upload could not be sent.", true);
      return;
    }
    if(!answer.ok){
      setMessage("files-msg", answer.data.error || "That upload was refused.", true);
      return;
    }
  }
  await loadFiles(FILES.path);
  toast(plural(files.length, "file") + " sent");
});

// Base64 in slices: `String.fromCharCode(...bytes)` on a whole file blows the
// argument limit somewhere around a megabyte, which is exactly the size a file
// worth sending starts at.
async function base64Of(file){
  const bytes = new Uint8Array(await file.arrayBuffer());
  let binary = "";
  for(let index = 0; index < bytes.length; index += 8192){
    binary += String.fromCharCode.apply(null, bytes.subarray(index, index + 8192));
  }
  return btoa(binary);
}

// ---- auth and boot ----------------------------------------------------------

async function enter(token){
  const headers = {};
  if(token) headers.Authorization = "Bearer " + token;
  const response = await fetch("/api/fleet/state?since=2000000000", {headers});
  if(!response.ok) return false;
  if(token) SESSION.set(token);
  $("login").classList.add("hidden");
  $("page").classList.remove("hidden");
  THEME.paint();
  paintKeys();
  fitViewport();
  await loadNodes();
  TERM_SESSION = new ShellSession($("term"), {
    closed: () => setState("closed"),
  });
  // A session this console already holds is picked up rather than replaced: the
  // tab that opened this one may have started it, and two shells where the
  // operator asked for one is a machine with a stray login on it.
  const node = currentNode();
  if(node){
    const answer = await apiJson("/api/fleet/shell?node=" + encodeURIComponent(node) +
                                 "&offset=0").catch(() => ({ok:false}));
    if(answer.ok && answer.data && answer.data.open){
      TERM_SESSION.attach(node);
      FILES.node = node;
      setState("live", "ok");
      focusInput();
    }else{
      $("term").textContent = "Press Open to start a shell on that node.";
      setState("idle");
    }
  }
  return true;
}

SESSION.onLost = () => {
  if(TERM_SESSION) TERM_SESSION.halt();
  $("page").classList.add("hidden");
  $("login").classList.remove("hidden");
};
SESSION.load();

$("login-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  setMessage("err", "");
  await withBusy(event.submitter || $("login-form").querySelector("button"), async () => {
    try{
      const response = await fetch("/api/login", {method:"POST",
        headers:{"Content-Type":"application/json"},
        body:JSON.stringify({password:$("password").value})});
      if(!response.ok){
        const data = await response.json().catch(() => ({}));
        setMessage("err", data.error || "Login failed", true);
        return;
      }
      $("password").value = "";
      await enter((await response.json()).token);
    }catch(_){ setMessage("err", "Console is not reachable", true); }
  });
});

$$("dialog").forEach((element) => element.addEventListener("click", (event) => {
  if(event.target === element) element.close();
}));

(function boot(){
  let token = null;
  try{ token = sessionStorage.getItem("nmesh_token"); }catch(_){}
  enter(token).then((ok) => { if(!ok) $("login").classList.remove("hidden"); });
})();
"""
