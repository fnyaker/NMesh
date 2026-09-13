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

What the emulator implements, and why that much
-----------------------------------------------
A log pane shows what a shell *printed*. A terminal shows what a program
*drew*, and the two only coincide for programs that draw nothing. ``btop``,
``htop``, ``vim`` and ``less`` all do the same four things a line-oriented
emulator cannot: they take the **alternate screen** so the scrollback is not
destroyed, they set a **scroll region** and move lines inside it instead of
repainting, they paint **backgrounds** (256-colour and 24-bit), and they ask
the terminal to **report the mouse**. Any one of those missing makes the screen
garbage, so all four are here.

Two of them are also why a terminal has to be told its size. A pty carries
``TIOCSWINSZ``; a full-screen program reads it once and lays its whole screen
out on the answer. Resize the pane without telling the pty and every box is
drawn to the old width — which is the same picture as a broken emulator, and
was for a long time the same bug. So the pane is measured, the size is pushed
to the pty, the emulator's own grid is resized with the content kept, and the
program is signalled.

Why the output is streamed rather than polled
---------------------------------------------
Output used to be fetched on a timer. A timer is a floor on latency — half the
interval on average, all of it at worst — and it is paid on every keystroke,
because what a person sees after typing is the echo coming back. The read is
now a **held request**: the console answers as soon as there are bytes, and the
page asks again straight away. Idle costs one parked request instead of a
question every fraction of a second, and a keystroke costs one round trip.
"""

CSS = """
/* The terminal is the one place with its own colour world: it renders bytes a
   remote shell chose, so it keeps a fixed dark ground in both themes rather
   than recolouring somebody else's output. */
.term{--page-term-bg:#0a0f16;--page-term-fg:#cfe0f7;
  margin:0;padding:var(--s-4);min-height:440px;max-height:62vh;overflow:auto;
  background:var(--page-term-bg);color:var(--page-term-fg);
  font:13px/1.25 var(--mono);white-space:pre;overflow-wrap:normal;
  border-bottom:1px solid var(--border)}
.term:focus-visible{outline:2px solid var(--ring);outline-offset:-2px}
/* One element per line. `pre` keeps the spaces; the rows exist so a repaint
   touches the lines that changed instead of the whole screen. */
.term .t-row{min-height:1.25em}
/* While a program is reporting the mouse, dragging must not select text — the
   drag *is* the message being sent. */
.term.t-mouse{user-select:none;-webkit-user-select:none}
.t-b{font-weight:700}.t-d{opacity:.62}.t-i{font-style:italic}
.t-u{text-decoration:underline}.t-s{text-decoration:line-through}
.t-u.t-s{text-decoration:underline line-through}
.t-h{visibility:hidden}
.t-cur{background:#cfe0f7;color:#0a0f16}
.t-c0{color:#5b6b80}.t-c1{color:#ff8079}.t-c2{color:#5fd39a}.t-c3{color:#f2c261}
.t-c4{color:#79b0ff}.t-c5{color:#d79bff}.t-c6{color:#5fd9d0}.t-c7{color:#e8eef5}
.t-c8{color:#7d8ea6}.t-c9{color:#ff9d97}.t-c10{color:#86e3b6}.t-c11{color:#ffd684}
.t-c12{color:#9cc6ff}.t-c13{color:#e4b8ff}.t-c14{color:#8fe9e2}.t-c15{color:#ffffff}
.t-g0{background:#0a0f16}.t-g1{background:#ff8079}.t-g2{background:#5fd39a}
.t-g3{background:#f2c261}.t-g4{background:#79b0ff}.t-g5{background:#d79bff}
.t-g6{background:#5fd9d0}.t-g7{background:#e8eef5}.t-g8{background:#3a475a}
.t-g9{background:#ff9d97}.t-g10{background:#86e3b6}.t-g11{background:#ffd684}
.t-g12{background:#9cc6ff}.t-g13{background:#e4b8ff}.t-g14{background:#8fe9e2}
.t-g15{background:#ffffff}
"""


JS = r"""
// ---- a small terminal ------------------------------------------------------
// Written rather than depended on: a shell you can type `sudo` into needs a
// terminal, not a log pane, and pulling in an emulator library for it would
// cost a name in the supply chain this project keeps deliberately short.
//
// What it implements is what a full-screen program actually uses: the printable
// text and the control bytes, cursor movement, the erase and edit commands, a
// scroll region, the alternate screen, insert/delete of lines and characters,
// SGR from the eight colours up to 24-bit, the DEC private modes a TUI sets on
// the way in, mouse reporting, and the few reports a program asks for and then
// waits on. Anything else is consumed and ignored rather than printed — an
// unknown escape must never end up on screen as garbage.

// Attribute bits. Kept as a mask rather than booleans because every cell on the
// screen carries one, and a screen is a few thousand cells repainted many times
// a second.
const T_BOLD = 1, T_DIM = 2, T_ITALIC = 4, T_UNDER = 8;
const T_INVERSE = 16, T_HIDDEN = 32, T_STRIKE = 64;

// The 256-colour cube, for the indices that have no class of their own. 0..15
// are the palette in the stylesheet, so they never come through here.
function t256(index){
  if(index < 16) return null;
  if(index < 232){
    const n = index - 16;
    const step = (value) => (value ? 55 + value * 40 : 0);
    return [step(Math.floor(n / 36) % 6), step(Math.floor(n / 6) % 6), step(n % 6)];
  }
  const grey = 8 + (index - 232) * 10;
  return [grey, grey, grey];
}
function t_rgb(colour){
  return "rgb(" + colour[0] + "," + colour[1] + "," + colour[2] + ")";
}
function t_colourKey(colour){
  return colour === null ? "-" : (typeof colour === "number" ? String(colour)
                                                             : colour.join(","));
}

// Styles are interned: a screen has thousands of cells and a handful of
// distinct looks, so cells share one object and a repaint compares references
// instead of strings.
const T_STYLES = new Map();
const T_DEF_BG = "#0a0f16", T_DEF_FG = "#cfe0f7";

// The sixteen palette colours have classes in the stylesheet. Everything past
// them — the 256-colour cube, 24-bit — gets a class **minted at runtime**,
// because the console's CSP has no `unsafe-inline` and a `style=` attribute is
// therefore ignored by the browser without an error. A rule inserted through
// the CSSOM is not inline, and is the one way to colour a cell here.
const T_COLOURS = new Map();          // declaration -> class name
const T_MAX_COLOURS = 1024;           // bounded, like everything a peer can grow
let T_SHEET;

function t_sheet(){
  if(T_SHEET !== undefined) return T_SHEET;
  T_SHEET = null;
  if(typeof document === "undefined") return T_SHEET;
  try{
    const sheet = new CSSStyleSheet();
    document.adoptedStyleSheets = document.adoptedStyleSheets.concat([sheet]);
    T_SHEET = sheet;
  }catch(_){
    // Older engines: use a sheet the page already served rather than adding a
    // `<style>` element, which the policy would refuse.
    try{ T_SHEET = document.styleSheets[0] || null; }catch(_e){ T_SHEET = null; }
  }
  return T_SHEET;
}
function t_class(declaration){
  let name = T_COLOURS.get(declaration);
  if(name !== undefined) return name;
  if(T_COLOURS.size >= T_MAX_COLOURS) return "";
  name = "t-x" + T_COLOURS.size;
  T_COLOURS.set(declaration, name);
  const sheet = t_sheet();
  if(sheet){
    try{ sheet.insertRule("." + name + "{" + declaration + "}", sheet.cssRules.length); }
    catch(_){}
  }
  return name;
}
function t_colour(value){
  if(typeof value === "number") return t_rgb(t256(value));
  return Array.isArray(value) ? t_rgb(value) : value;
}

function termStyle(fg, bg, flags){
  const key = t_colourKey(fg) + "|" + t_colourKey(bg) + "|" + flags;
  let style = T_STYLES.get(key);
  if(style) return style;
  // Inverse is resolved here rather than at paint time: it is a swap, and doing
  // it once per distinct look beats doing it once per cell per frame.
  let front = fg, back = bg;
  if(flags & T_INVERSE){
    front = bg; back = fg;
    if(front === null) front = T_DEF_BG;
    if(back === null) back = T_DEF_FG;
  }
  const classes = [];
  const add = (declaration) => {
    const name = t_class(declaration);
    if(name) classes.push(name);
  };
  if(typeof front === "number" && front < 16) classes.push("t-c" + front);
  else if(front !== null) add("color:" + t_colour(front));
  if(typeof back === "number" && back < 16) classes.push("t-g" + back);
  else if(back !== null) add("background:" + t_colour(back));
  if(flags & T_BOLD) classes.push("t-b");
  if(flags & T_DIM) classes.push("t-d");
  if(flags & T_ITALIC) classes.push("t-i");
  if(flags & T_UNDER) classes.push("t-u");
  if(flags & T_STRIKE) classes.push("t-s");
  if(flags & T_HIDDEN) classes.push("t-h");
  style = {key:key, fg:fg, bg:bg, flags:flags,
           cls:classes.join(" "), plain:!classes.length};
  if(T_STYLES.size < 4096) T_STYLES.set(key, style);
  return style;
}
const T_PLAIN = termStyle(null, null, 0);

// How many columns one code point takes. Full-width forms take two, combining
// marks take none and are hung on the cell before them; everything else is one.
// A width that is wrong here is a line that drifts sideways, which is what a
// box-drawing program looks like when it breaks.
function termWidth(code){
  if(code < 0x0300) return 1;
  if((code >= 0x0300 && code <= 0x036f) || (code >= 0x1ab0 && code <= 0x1aff) ||
     (code >= 0x1dc0 && code <= 0x1dff) || (code >= 0x20d0 && code <= 0x20f0) ||
     (code >= 0xfe00 && code <= 0xfe0f) || (code >= 0xfe20 && code <= 0xfe2f) ||
     code === 0x200b || code === 0x200d) return 0;
  if((code >= 0x1100 && code <= 0x115f) ||
     (code >= 0x2e80 && code <= 0x303e) || (code >= 0x3041 && code <= 0x33ff) ||
     (code >= 0x3400 && code <= 0x4dbf) || (code >= 0x4e00 && code <= 0xa4cf) ||
     (code >= 0xa960 && code <= 0xa97f) || (code >= 0xac00 && code <= 0xd7a3) ||
     (code >= 0xf900 && code <= 0xfaff) || (code >= 0xfe10 && code <= 0xfe19) ||
     (code >= 0xfe30 && code <= 0xfe6f) || (code >= 0xff00 && code <= 0xff60) ||
     (code >= 0xffe0 && code <= 0xffe6) ||
     (code >= 0x1f300 && code <= 0x1f64f) || (code >= 0x1f900 && code <= 0x1f9ff) ||
     (code >= 0x20000 && code <= 0x3fffd)) return 2;
  return 1;
}

// The DEC special graphics set (`ESC ( 0`): the line-drawing characters older
// programs still use instead of the Unicode ones.
const T_DEC_GRAPHICS = {
  "j":"┘", "k":"┐", "l":"┌", "m":"└", "n":"┼",
  "q":"─", "t":"├", "u":"┤", "v":"┴", "w":"┬",
  "x":"│", "a":"▒", "`":"◆", "f":"°", "g":"±",
  "o":"⎺", "p":"⎻", "r":"⎼", "s":"⎽", "0":"█",
  "~":"·", "y":"≤", "z":"≥", "{":"π", "|":"≠",
  "}":"£", ".":"▼", ",":"◀", "+":"▶", "-":"▲",
  "h":"▒", "i":"▒",
};

const T_SCROLLBACK = 2000;      // lines kept above the screen
const T_PENDING_MAX = 4096;     // an unterminated escape is dropped, never grown

function Term(cols, rows){
  this.cols = Math.max(2, cols | 0); this.rows = Math.max(1, rows | 0);
  this.scrollback = [];         // rendered lines, oldest first
  this.sbTotal = 0;             // lines ever pushed (so a painter can catch up)
  this.onReply = null;          // where a program's requested report is sent
  this.onBell = null;
  this.reset();
}
Term.prototype.reset = function(){
  this.grid = this.blankGrid(this.rows);
  this.altGrid = null;
  this.x = 0; this.y = 0; this.wrapNext = false;
  this.fg = null; this.bg = null; this.flags = 0; this.style = T_PLAIN;
  this.top = 0; this.bot = this.rows - 1;
  this.saved = null; this.savedAlt = null;
  this.autowrap = true; this.insert = false; this.origin = false;
  this.cursorVisible = true; this.appCursor = false; this.appKeypad = false;
  this.bracketed = false; this.mouse = 0; this.mouseSgr = false;
  this.graphics = false; this.title = "";
  this.pending = ""; this.dirty = true;
  this.tabs = {};
};
Term.prototype.blankRow = function(){
  const row = new Array(this.cols);
  for(let i = 0; i < this.cols; i++) row[i] = {c:" ", s:T_PLAIN, w:1};
  return row;
};
// Erasing paints the *current* background, which is how a full-screen program
// fills a panel: it sets a background and erases. Without this every painted
// area comes back the colour of the page.
Term.prototype.eraseCell = function(){
  const style = (this.bg === null && !(this.flags & T_INVERSE))
    ? T_PLAIN : termStyle(null, this.bg, this.flags & T_INVERSE);
  return {c:" ", s:style, w:1};
};
Term.prototype.eraseRow = function(){
  const row = new Array(this.cols), cell = this.eraseCell();
  for(let i = 0; i < this.cols; i++) row[i] = {c:cell.c, s:cell.s, w:1};
  return row;
};
Term.prototype.blankGrid = function(rows){
  const grid = [];
  for(let i = 0; i < rows; i++) grid.push(this.blankRow());
  return grid;
};
Term.prototype.alt = function(){ return this.altGrid !== null; };

// Resizing keeps the content. A pty is told its new size and a full-screen
// program redraws from scratch, but a shell at a prompt is not told anything
// and never repaints — so what is already on the screen has to survive.
Term.prototype.resize = function(cols, rows){
  cols = Math.max(2, cols | 0); rows = Math.max(1, rows | 0);
  if(cols === this.cols && rows === this.rows) return false;
  const oldCols = this.cols;
  this.cols = cols;
  const blankRow = (row) => row.every((cell) => cell.c === " " && cell.s.plain);
  const fit = (grid, keep) => {
    for(const row of grid){
      if(cols < oldCols) row.length = cols;
      else for(let i = oldCols; i < cols; i++) row[i] = {c:" ", s:T_PLAIN, w:1};
    }
    while(grid.length > rows){
      // Empty rows below the cursor go first, and only then does the top
      // scroll away: dropping from the top while the screen is mostly blank
      // would take the prompt off with it.
      if(grid.length - 1 > this.y && blankRow(grid[grid.length - 1])){
        grid.pop();
        continue;
      }
      const gone = grid.shift();
      if(keep) this.pushScrollback(gone);
      this.y = Math.max(0, this.y - 1);
    }
    while(grid.length < rows) grid.push(this.blankRow());
  };
  fit(this.grid, !this.alt());
  if(this.altGrid) fit(this.altGrid, false);
  this.rows = rows;
  this.top = 0; this.bot = rows - 1;
  this.x = Math.min(this.x, cols - 1);
  this.y = Math.min(this.y, rows - 1);
  this.wrapNext = false;
  this.dirty = true;
  return true;
};
Term.prototype.pushScrollback = function(row){
  this.scrollback.push(this.rowHtml(row, -1));
  this.sbTotal++;
  if(this.scrollback.length > T_SCROLLBACK) this.scrollback.shift();
};
// Scrolling happens inside the region, never over the whole screen: that is the
// difference between a pane a program can animate and one that jumps.
Term.prototype.scrollUp = function(count){
  const grid = this.alt() ? this.altGrid : this.grid;
  for(let n = 0; n < count; n++){
    const gone = grid.splice(this.top, 1)[0];
    if(!this.alt() && this.top === 0) this.pushScrollback(gone);
    grid.splice(this.bot, 0, this.eraseRow());
  }
  this.dirty = true;
};
Term.prototype.scrollDown = function(count){
  const grid = this.alt() ? this.altGrid : this.grid;
  for(let n = 0; n < count; n++){
    grid.splice(this.bot, 1);
    grid.splice(this.top, 0, this.eraseRow());
  }
  this.dirty = true;
};
Term.prototype.screen = function(){ return this.alt() ? this.altGrid : this.grid; };
Term.prototype.newline = function(){
  if(this.y === this.bot) this.scrollUp(1);
  else if(this.y < this.rows - 1) this.y++;
};
Term.prototype.reverseNewline = function(){
  if(this.y === this.top) this.scrollDown(1);
  else if(this.y > 0) this.y--;
};
Term.prototype.put = function(ch, width){
  const row = this.screen()[this.y];
  if(width === 0){                       // a combining mark joins the cell before
    const at = this.x > 0 ? this.x - 1 : 0;
    if(row[at] && row[at].c) row[at] = {c:row[at].c + ch, s:row[at].s, w:row[at].w};
    return;
  }
  if(this.wrapNext || this.x + width > this.cols){
    if(this.autowrap){ this.x = 0; this.newline(); }
    else this.x = this.cols - width;
    this.wrapNext = false;
  }
  if(this.insert){
    const row2 = this.screen()[this.y];
    for(let n = 0; n < width; n++){ row2.splice(this.cols - 1, 1); row2.splice(this.x, 0, this.eraseCell()); }
  }
  const line = this.screen()[this.y];
  line[this.x] = {c:ch, s:this.style, w:width};
  for(let n = 1; n < width; n++){
    if(this.x + n < this.cols) line[this.x + n] = {c:"", s:this.style, w:0};
  }
  this.x += width;
  if(this.x >= this.cols){ this.x = this.cols - 1; this.wrapNext = true; }
};
Term.prototype.eraseLine = function(mode){
  const row = this.screen()[this.y];
  const from = mode === 0 ? this.x : 0;
  const to = mode === 1 ? this.x + 1 : this.cols;
  for(let i = from; i < to && i < this.cols; i++) row[i] = this.eraseCell();
};
Term.prototype.eraseDisplay = function(mode){
  const grid = this.screen();
  if(mode === 2 || mode === 3){
    for(let y = 0; y < this.rows; y++) grid[y] = this.eraseRow();
    if(mode === 3){ this.scrollback.length = 0; this.sbTotal = 0; }
    return;
  }
  this.eraseLine(mode === 1 ? 1 : 0);
  if(mode === 0) for(let y = this.y + 1; y < this.rows; y++) grid[y] = this.eraseRow();
  else for(let y = 0; y < this.y; y++) grid[y] = this.eraseRow();
};
Term.prototype.eraseChars = function(count){
  const row = this.screen()[this.y];
  for(let i = this.x; i < Math.min(this.cols, this.x + count); i++) row[i] = this.eraseCell();
};
Term.prototype.deleteChars = function(count){
  const row = this.screen()[this.y];
  for(let n = 0; n < count && this.x < this.cols; n++){
    row.splice(this.x, 1); row.push(this.eraseCell());
  }
};
Term.prototype.insertChars = function(count){
  const row = this.screen()[this.y];
  for(let n = 0; n < count; n++){ row.splice(this.cols - 1, 1); row.splice(this.x, 0, this.eraseCell()); }
};
Term.prototype.insertLines = function(count){
  if(this.y < this.top || this.y > this.bot) return;
  const grid = this.screen();
  for(let n = 0; n < count; n++){
    grid.splice(this.bot, 1);
    grid.splice(this.y, 0, this.eraseRow());
  }
};
Term.prototype.deleteLines = function(count){
  if(this.y < this.top || this.y > this.bot) return;
  const grid = this.screen();
  for(let n = 0; n < count; n++){
    grid.splice(this.y, 1);
    grid.splice(this.bot, 0, this.eraseRow());
  }
};
Term.prototype.setAttrs = function(params){
  // Only the attributes a program can actually be seen to use. Anything else is
  // consumed: an unhandled SGR must change nothing, never print.
  for(let i = 0; i < params.length; i++){
    const n = params[i] === "" ? 0 : parseInt(params[i], 10);
    if(!isFinite(n)) continue;
    if(n === 0){ this.fg = null; this.bg = null; this.flags = 0; }
    else if(n === 1) this.flags |= T_BOLD;
    else if(n === 2) this.flags |= T_DIM;
    else if(n === 3) this.flags |= T_ITALIC;
    else if(n === 4) this.flags |= T_UNDER;
    else if(n === 7) this.flags |= T_INVERSE;
    else if(n === 8) this.flags |= T_HIDDEN;
    else if(n === 9) this.flags |= T_STRIKE;
    else if(n === 21 || n === 22) this.flags &= ~(T_BOLD | T_DIM);
    else if(n === 23) this.flags &= ~T_ITALIC;
    else if(n === 24) this.flags &= ~T_UNDER;
    else if(n === 27) this.flags &= ~T_INVERSE;
    else if(n === 28) this.flags &= ~T_HIDDEN;
    else if(n === 29) this.flags &= ~T_STRIKE;
    else if(n >= 30 && n <= 37) this.fg = n - 30;
    else if(n === 38 || n === 48){
      const mode = parseInt(params[i + 1] || "", 10);
      let colour = null;
      if(mode === 5){ colour = parseInt(params[i + 2] || "", 10) & 255; i += 2; }
      else if(mode === 2){
        colour = [parseInt(params[i + 2] || "0", 10) & 255,
                  parseInt(params[i + 3] || "0", 10) & 255,
                  parseInt(params[i + 4] || "0", 10) & 255];
        i += 4;
      }else{ i += 1; }
      if(n === 38) this.fg = colour; else this.bg = colour;
    }
    else if(n === 39) this.fg = null;
    else if(n >= 40 && n <= 47) this.bg = n - 40;
    else if(n === 49) this.bg = null;
    else if(n >= 90 && n <= 97) this.fg = n - 90 + 8;
    else if(n >= 100 && n <= 107) this.bg = n - 100 + 8;
  }
  this.style = termStyle(this.fg, this.bg, this.flags);
};
Term.prototype.reply = function(text){
  if(this.onReply) try{ this.onReply(text); }catch(_){}
};
Term.prototype.setMode = function(params, on, priv){
  for(const raw of params){
    const n = parseInt(raw, 10);
    if(!isFinite(n)) continue;
    if(!priv){
      if(n === 4) this.insert = on;
      continue;
    }
    switch(n){
      case 1: this.appCursor = on; break;
      case 6: this.origin = on;
              this.x = 0; this.y = on ? this.top : 0; this.wrapNext = false; break;
      case 7: this.autowrap = on; break;
      case 25: this.cursorVisible = on; break;
      case 9: this.mouse = on ? 9 : 0; break;
      case 1000: this.mouse = on ? 1000 : 0; break;
      case 1001: case 1002: this.mouse = on ? 1002 : 0; break;
      case 1003: this.mouse = on ? 1003 : 0; break;
      case 1005: break;                       // UTF-8 mouse: SGR is preferred
      case 1006: case 1015: this.mouseSgr = on; break;
      case 2004: this.bracketed = on; break;
      case 47: case 1047: case 1049:
        this.useAlt(on, n === 1049);
        break;
      default: break;                         // consumed, never printed
    }
  }
  this.dirty = true;
};
// The alternate screen is what keeps `btop` from eating the scrollback: the
// program gets a blank grid of its own and the shell's screen comes back
// untouched when it exits.
Term.prototype.useAlt = function(on, withCursor){
  if(on){
    if(this.alt()) return;
    if(withCursor) this.savedAlt = this.cursorState();
    this.altGrid = this.blankGrid(this.rows);
    this.x = 0; this.y = 0; this.wrapNext = false;
    this.top = 0; this.bot = this.rows - 1;
  }else{
    if(!this.alt()) return;
    this.altGrid = null;
    this.top = 0; this.bot = this.rows - 1;
    if(withCursor && this.savedAlt) this.restoreCursor(this.savedAlt);
    this.savedAlt = null;
  }
};
Term.prototype.cursorState = function(){
  return {x:this.x, y:this.y, fg:this.fg, bg:this.bg, flags:this.flags,
          graphics:this.graphics, origin:this.origin};
};
Term.prototype.restoreCursor = function(state){
  if(!state) return;
  this.x = Math.min(state.x, this.cols - 1);
  this.y = Math.min(state.y, this.rows - 1);
  this.fg = state.fg; this.bg = state.bg; this.flags = state.flags;
  this.graphics = state.graphics; this.origin = state.origin;
  this.style = termStyle(this.fg, this.bg, this.flags);
  this.wrapNext = false;
};
Term.prototype.goto = function(row, col){
  const base = this.origin ? this.top : 0;
  const limit = this.origin ? this.bot : this.rows - 1;
  this.y = Math.max(0, Math.min(limit, base + row));
  this.x = Math.max(0, Math.min(this.cols - 1, col));
  this.wrapNext = false;
};
Term.prototype.nextTab = function(count){
  for(let n = 0; n < count; n++){
    let at = this.x + 1;
    while(at < this.cols - 1 && !(this.tabs[at] || at % 8 === 0)) at++;
    this.x = Math.min(this.cols - 1, at);
  }
  this.wrapNext = false;
};
Term.prototype.prevTab = function(count){
  for(let n = 0; n < count; n++){
    let at = this.x - 1;
    while(at > 0 && !(this.tabs[at] || at % 8 === 0)) at--;
    this.x = Math.max(0, at);
  }
};

const T_CSI = /^\x1b\[([\x30-\x3f]*)([\x20-\x2f]*)([\x40-\x7e])/;
const T_OSC = /^\x1b\](\d*);?([^\x07\x1b]*)(\x07|\x1b\\)/;
const T_STR = /^\x1b[P^_X][\s\S]*?(\x1b\\|\x07)/;
const T_ESC2 = /^\x1b([()*+%#])([0-9A-Za-z@])/;
// A CSI that has not finished yet: parameter and intermediate bytes and then
// the end of what arrived. Told apart from a malformed one, which is dropped
// rather than waited on for ever.
const T_CSI_PART = /^\x1b\[[\x30-\x3f]*[\x20-\x2f]*$/;

Term.prototype.write = function(text){
  let data = this.pending + text; this.pending = "";
  const length = data.length;
  for(let i = 0; i < length; i++){
    const ch = data[i];
    if(ch === "\x1b"){
      const rest = data.slice(i);
      const csi = T_CSI.exec(rest);
      if(csi){ this.csi(csi[1], csi[2], csi[3]); i += csi[0].length - 1; continue; }
      const osc = T_OSC.exec(rest);
      if(osc){
        if(osc[1] === "0" || osc[1] === "2") this.title = osc[2].slice(0, 200);
        i += osc[0].length - 1; continue;
      }
      const str = T_STR.exec(rest);
      if(str){ i += str[0].length - 1; continue; }
      const two = T_ESC2.exec(rest);
      if(two){
        if(two[1] === "(") this.graphics = two[2] === "0";
        i += two[0].length - 1; continue;
      }
      // `rest` runs to the end of what has arrived, so a sequence that did
      // not match above is either split across two reads — kept and retried
      // when the rest comes — or malformed, and dropped.
      if(T_CSI_PART.test(rest)){
        if(rest.length < T_PENDING_MAX) this.pending = rest;
        return;
      }
      if(rest.length >= 2){
        const next = rest[1];
        if(next === "7"){ this.saved = this.cursorState(); i++; continue; }
        if(next === "8"){ this.restoreCursor(this.saved); i++; continue; }
        if(next === "D"){ this.newline(); i++; continue; }
        if(next === "E"){ this.x = 0; this.newline(); i++; continue; }
        if(next === "M"){ this.reverseNewline(); i++; continue; }
        if(next === "H"){ this.tabs[this.x] = true; i++; continue; }
        if(next === "c"){ this.reset(); i++; continue; }
        if(next === "=" || next === ">"){ this.appKeypad = next === "="; i++; continue; }
        if(next === "\\"){ i++; continue; }
        if(next === "]" || next === "P" || next === "^" || next === "_" || next === "X"){
          // A string sequence whose terminator has not arrived yet.
          if(rest.length < T_PENDING_MAX){ this.pending = rest; return; }
          continue;
        }
        i++; continue;                       // unknown two-byte escape: dropped
      }
      this.pending = rest; return;           // incomplete, wait for more
    }
    if(ch === "\n" || ch === "\x0b" || ch === "\x0c"){ this.newline(); this.wrapNext = false; continue; }
    if(ch === "\r"){ this.x = 0; this.wrapNext = false; continue; }
    if(ch === "\b"){ if(this.x > 0) this.x--; this.wrapNext = false; continue; }
    if(ch === "\t"){ this.nextTab(1); continue; }
    if(ch === "\x07"){ if(this.onBell) try{ this.onBell(); }catch(_){} continue; }
    if(ch === "\x0e"){ this.graphics = true; continue; }
    if(ch === "\x0f"){ this.graphics = false; continue; }
    if(ch < " " || ch === "\x7f") continue;  // other control bytes
    let glyph = ch, code = ch.charCodeAt(0);
    if(code >= 0xd800 && code <= 0xdbff && i + 1 < length){
      glyph = ch + data[i + 1]; code = glyph.codePointAt(0); i++;
    }
    if(this.graphics && T_DEC_GRAPHICS[glyph]) glyph = T_DEC_GRAPHICS[glyph];
    this.put(glyph, termWidth(code));
  }
  this.dirty = true;
};
Term.prototype.csi = function(paramText, intermediate, final){
  const priv = paramText.charCodeAt(0) === 0x3f;      // `?` — a DEC private mode
  const params = (priv ? paramText.slice(1) : paramText).split(";");
  const first = Math.max(1, parseInt(params[0] || "1", 10) || 1);
  const raw0 = parseInt(params[0] || "0", 10) || 0;
  switch(final){
    case "A": this.y = Math.max(this.origin ? this.top : 0, this.y - first); this.wrapNext = false; break;
    case "B": this.y = Math.min(this.origin ? this.bot : this.rows - 1, this.y + first); this.wrapNext = false; break;
    case "C": this.x = Math.min(this.cols - 1, this.x + first); this.wrapNext = false; break;
    case "D": this.x = Math.max(0, this.x - first); this.wrapNext = false; break;
    case "E": this.x = 0; this.y = Math.min(this.rows - 1, this.y + first); break;
    case "F": this.x = 0; this.y = Math.max(0, this.y - first); break;
    case "G": case "`": this.x = Math.min(this.cols - 1, Math.max(0, first - 1)); this.wrapNext = false; break;
    case "d": this.y = Math.min(this.rows - 1, Math.max(0, first - 1)); this.wrapNext = false; break;
    case "H": case "f": {
      const row = Math.max(1, parseInt(params[0] || "1", 10) || 1);
      const col = Math.max(1, parseInt(params[1] || "1", 10) || 1);
      this.goto(row - 1, col - 1);
      break;
    }
    case "I": this.nextTab(first); break;
    case "Z": this.prevTab(first); break;
    case "J": this.eraseDisplay(raw0); break;
    case "K": this.eraseLine(raw0); break;
    case "L": this.insertLines(first); break;
    case "M": this.deleteLines(first); break;
    case "P": this.deleteChars(first); break;
    case "@": this.insertChars(first); break;
    case "X": this.eraseChars(first); break;
    case "S": this.scrollUp(first); break;
    case "T": this.scrollDown(first); break;
    case "h": this.setMode(params, true, priv); break;
    case "l": this.setMode(params, false, priv); break;
    case "m": if(!priv) this.setAttrs(params); break;
    case "r": {
      const top = Math.max(1, parseInt(params[0] || "1", 10) || 1);
      const bot = Math.max(top, parseInt(params[1] || String(this.rows), 10) || this.rows);
      this.top = Math.min(this.rows - 1, top - 1);
      this.bot = Math.min(this.rows - 1, bot - 1);
      this.goto(0, 0);
      break;
    }
    case "s": this.saved = this.cursorState(); break;
    case "u": this.restoreCursor(this.saved); break;
    case "n":
      // A program that asks where the cursor is *waits* for the answer. Silence
      // here is a hang, not a missing feature.
      if(raw0 === 6) this.reply("\x1b[" + (this.y + 1) + ";" + (this.x + 1) + "R");
      else if(raw0 === 5) this.reply("\x1b[0n");
      break;
    case "c": this.reply("\x1b[?1;2c"); break;         // "a VT100 with options"
    case "t": if(raw0 === 18) this.reply("\x1b[8;" + this.rows + ";" + this.cols + "t"); break;
    case "g": if(raw0 === 3) this.tabs = {}; else delete this.tabs[this.x]; break;
    default: break;                                     // consumed, never printed
  }
  this.dirty = true;
};

// ---- drawing ----------------------------------------------------------------

function escHtml(text){
  return text.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
}
function t_span(style, cursor){
  if(style.plain && !cursor) return null;
  const cls = cursor ? (style.cls ? style.cls + " t-cur" : "t-cur") : style.cls;
  return '<span class="' + cls + '">';
}
Term.prototype.rowHtml = function(row, cursorX){
  // Trailing blanks are dropped: a row is `cols` cells wide and padding every
  // line to the full width would make the pane scroll sideways for nothing. A
  // blank carrying a background is not blank — a painted panel ends there.
  let end = row.length;
  while(end > 0 && row[end - 1].c === " " && row[end - 1].s.plain) end--;
  if(cursorX >= 0) end = Math.max(end, cursorX + 1);
  let html = "", run = "", open = null;
  const flush = () => {
    if(!run) return;
    html += open ? open + escHtml(run) + "</span>" : escHtml(run);
    run = "";
  };
  for(let i = 0; i < end; i++){
    const cell = row[i] || {c:" ", s:T_PLAIN, w:1};
    if(cell.w === 0) continue;
    const span = t_span(cell.s, i === cursorX);
    if(span !== open){ flush(); open = span; }
    run += cell.c || " ";
  }
  flush();
  return html;
};
Term.prototype.render = function(showCursor){
  const cursorY = (showCursor === false || !this.cursorVisible) ? -1 : this.y;
  const grid = this.screen();
  const out = this.alt() ? [] : this.scrollback.slice();
  for(let y = 0; y < grid.length; y++){
    out.push(this.rowHtml(grid[y], y === cursorY ? this.x : -1));
  }
  return out.join("\n");
};
// Repainting is per line. The whole screen as one `innerHTML` is a few thousand
// cells rebuilt for a cursor that moved one column — and it drops the selection
// somebody was in the middle of making.
Term.prototype.paint = function(box, showCursor){
  let back = box.firstElementChild;
  if(!back || back.className !== "t-sb"){
    box.textContent = "";
    back = document.createElement("div"); back.className = "t-sb";
    const front = document.createElement("div"); front.className = "t-gr";
    box.appendChild(back); box.appendChild(front);
    box._sbTotal = 0; box._rows = [];
  }
  const front = back.nextElementSibling;
  back.hidden = this.alt();
  if(box._sbTotal !== this.sbTotal){
    const fresh = Math.min(this.sbTotal - box._sbTotal, this.scrollback.length);
    for(let i = this.scrollback.length - fresh; i < this.scrollback.length; i++){
      const line = document.createElement("div");
      line.className = "t-row";
      line.innerHTML = this.scrollback[i];
      back.appendChild(line);
    }
    while(back.childElementCount > this.scrollback.length) back.removeChild(back.firstChild);
    box._sbTotal = this.sbTotal;
  }
  const grid = this.screen();
  const cursorY = (showCursor === false || !this.cursorVisible) ? -1 : this.y;
  while(front.childElementCount > grid.length){
    front.removeChild(front.lastChild); box._rows.pop();
  }
  while(front.childElementCount < grid.length){
    const line = document.createElement("div");
    line.className = "t-row";
    front.appendChild(line); box._rows.push(null);
  }
  for(let y = 0; y < grid.length; y++){
    const html = this.rowHtml(grid[y], y === cursorY ? this.x : -1);
    if(box._rows[y] === html) continue;
    box._rows[y] = html;
    front.children[y].innerHTML = html;
  }
  this.dirty = false;
};
Term.prototype.text = function(){
  // What a copy takes: the screen as characters, no markup, no trailing blanks.
  const lines = this.alt() ? [] : this.scrollback.map(
    (html) => html.replace(/<[^>]*>/g, ""));
  const grid = this.screen();
  for(let y = 0; y < grid.length; y++) lines.push(this.rowHtml(grid[y], -1).replace(/<[^>]*>/g, ""));
  return lines.join("\n").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&");
};

// What a mouse event looks like on the wire, for a program that asked to see
// it. SGR (`?1006`) is used wherever it was enabled: the older encoding cannot
// express a column past 223, which is a real width on a wide screen.
Term.prototype.mouseReport = function(button, col, row, release){
  if(!this.mouse) return null;
  const x = Math.min(this.cols, Math.max(1, col)), y = Math.min(this.rows, Math.max(1, row));
  if(this.mouseSgr){
    return "\x1b[<" + button + ";" + x + ";" + y + (release ? "m" : "M");
  }
  if(x > 223 || y > 223) return null;
  const code = release ? 3 : button;
  return "\x1b[M" + String.fromCharCode(32 + code, 32 + x, 32 + y);
};

// What a key sends. Nothing is echoed locally: the remote pty decides what
// comes back, which is exactly why a password prompt stays invisible — the pty
// turns echo off and there is nothing on this side to show it anyway.
//
// The cursor keys have two forms and the program chooses: `ESC [ A` normally,
// `ESC O A` once it has set DECCKM. Sending the wrong one is why an arrow key
// prints a letter inside a full-screen program.
const T_FKEYS = {
  F1:"\x1bOP", F2:"\x1bOQ", F3:"\x1bOR", F4:"\x1bOS",
  F5:"\x1b[15~", F6:"\x1b[17~", F7:"\x1b[18~", F8:"\x1b[19~",
  F9:"\x1b[20~", F10:"\x1b[21~", F11:"\x1b[23~", F12:"\x1b[24~",
};
function keyBytes(event, term){
  if(event.ctrlKey && !event.altKey && event.key.length === 1){
    const code = event.key.toUpperCase().charCodeAt(0);
    if(code >= 64 && code <= 95) return String.fromCharCode(code - 64);   // ^A..^_
    if(event.key === "?") return "\x7f";
    if(event.key === " ") return "\x00";
  }
  const app = term && term.appCursor;
  const arrow = (letter) => (app ? "\x1bO" : "\x1b[") + letter;
  switch(event.key){
    case "Enter": return "\r";
    case "Backspace": return "\x7f";
    case "Tab": return event.shiftKey ? "\x1b[Z" : "\t";
    case "Escape": return "\x1b";
    case "ArrowUp": return arrow("A");
    case "ArrowDown": return arrow("B");
    case "ArrowRight": return arrow("C");
    case "ArrowLeft": return arrow("D");
    case "Home": return app ? "\x1bOH" : "\x1b[H";
    case "End": return app ? "\x1bOF" : "\x1b[F";
    case "Insert": return "\x1b[2~";
    case "Delete": return "\x1b[3~";
    case "PageUp": return "\x1b[5~";
    case "PageDown": return "\x1b[6~";
    default: break;
  }
  if(T_FKEYS[event.key]) return T_FKEYS[event.key];
  if(event.key.length === 1 && !event.ctrlKey && !event.metaKey){
    return event.altKey ? "\x1b" + event.key : event.key;
  }
  return null;
}

// ---- one shell session -----------------------------------------------------
// Both pages drive a session through this. It owns the terminal, the reading
// loop and the sid; the page owns the chrome around it and says what to do when
// it opens or closes.
//
// The read is a *held* request: the console answers the moment the pty produces
// bytes, and the loop asks again straight away. So an idle shell costs one
// parked request rather than a question several times a second, and what a
// person sees after a keystroke costs one round trip instead of one round trip
// plus half a polling interval.
const SHELL_RETRY = 700;        // after a failed read, before trying again
const SHELL_MISSES = 20;        // …and how many in a row before giving up
const SHELL_FRAME = 1000 / 30;  // repaints are coalesced to a frame

// Measured from the pane rather than assumed: the remote pty is told these
// dimensions, and a program that thinks it has a different width draws every
// box to the wrong place.
function termMetrics(box){
  const probe = document.createElement("div");
  probe.className = "t-row";
  probe.style.cssText = "position:absolute;visibility:hidden;white-space:pre;left:0;top:0";
  probe.textContent = "0".repeat(80);
  box.appendChild(probe);
  const rect = probe.getBoundingClientRect();
  const charWidth = (rect.width / 80) || 8;
  const lineHeight = rect.height || 16;
  box.removeChild(probe);
  const style = getComputedStyle(box);
  const padX = (parseFloat(style.paddingLeft) || 0) + (parseFloat(style.paddingRight) || 0);
  const padY = (parseFloat(style.paddingTop) || 0) + (parseFloat(style.paddingBottom) || 0);
  return {
    cw: charWidth, lh: lineHeight,
    padLeft: parseFloat(style.paddingLeft) || 0,
    padTop: parseFloat(style.paddingTop) || 0,
    cols: Math.max(20, Math.min(400, Math.floor((box.clientWidth - padX) / charWidth))),
    rows: Math.max(6, Math.min(200, Math.floor((box.clientHeight - padY) / lineHeight))),
  };
}

function ShellSession(box, handlers){
  this.box = box;
  this.on = handlers || {};
  this.node = null; this.sid = null; this.off = 0; this.term = null;
  this.size = {cols:80, rows:24}; this.metrics = null;
  this.reading = false; this.stopped = true; this.retry = null;
  this.pending = ""; this.sending = null; this.frame = null;
  this.decoder = null; this.lastCell = null; this.misses = 0;
}
ShellSession.prototype.say = function(text){
  this.box.textContent = text;
};
ShellSession.prototype.newTerm = function(){
  this.metrics = termMetrics(this.box);
  this.size = {cols:this.metrics.cols, rows:this.metrics.rows};
  this.term = new Term(this.size.cols, this.size.rows);
  // A program that asks the terminal a question waits for the answer, so the
  // reply goes back up the same pipe the keystrokes do.
  this.term.onReply = (text) => { this.send(text); };
  this.decoder = new TextDecoder();
  this.box.textContent = "";
  this.box._rows = null;
};
ShellSession.prototype.open = async function(node){
  await this.stop();
  this.node = node; this.sid = null; this.off = 0; this.stopped = false;
  this.misses = 0;
  this.newTerm();
  try{
    await api("/api/fleet/shell", "POST",
              {node, cols:this.size.cols, rows:this.size.rows});
  }catch(_){
    this.node = null; this.stopped = true;
    this.say("Could not open a shell on that node.");
    return false;
  }
  this.loop();
  if(this.on.opened) this.on.opened();
  return true;
};
// Attaching rather than opening: a shell this console already holds — one this
// tab did not start — is picked back up instead of a second one being spawned.
ShellSession.prototype.attach = function(node){
  this.node = node; this.sid = null; this.off = 0; this.stopped = false;
  this.misses = 0;
  this.newTerm();
  this.loop();
};
ShellSession.prototype.loop = function(){
  if(this.reading || this.stopped) return;
  this.reading = true;
  this.read().finally(() => {
    this.reading = false;
    if(this.stopped || !this.node) return;
    this.loop();
  });
};
ShellSession.prototype.read = async function(){
  if(!this.node) return;
  const where = this.sid ? "sid=" + encodeURIComponent(this.sid)
                         : "node=" + encodeURIComponent(this.node);
  let answer;
  try{
    answer = await apiJson("/api/fleet/shell?" + where + "&offset=" + this.off + "&wait=1");
  }catch(_){ return this.miss(); }
  if(!answer.ok || !answer.data) return this.miss();   // not open yet, or gone
  this.misses = 0;
  const data = answer.data;
  if(!this.sid){ this.sid = data.sid; this.off = 0; }
  if(data.data){
    const raw = atob(data.data);
    const bytes = Uint8Array.from(raw, (c) => c.charCodeAt(0));
    let text;
    // Streaming: a multi-byte character split across two reads has to survive
    // the join, or a box-drawing screen fills with replacement glyphs.
    try{ text = this.decoder.decode(bytes, {stream:true}); }
    catch(_){ text = raw; }
    if(!this.term) this.newTerm();
    this.term.write(text);
    this.schedule();
  }
  this.off = data.seq;
  if(!data.open){
    this.schedule(true);
    this.node = null; this.sid = null; this.stopped = true;
    if(this.on.closed) this.on.closed();
  }
};
// A read that answered nothing. Retried, but not for ever: a session the
// console has forgotten answers 404 as readily as one that is merely slow to
// open, and a loop that cannot tell them apart is a tab asking a question
// nobody will ever answer.
ShellSession.prototype.miss = function(){
  this.misses += 1;
  if(this.misses < SHELL_MISSES){
    return new Promise((resolve) => { this.retry = setTimeout(resolve, SHELL_RETRY); });
  }
  this.node = null; this.sid = null; this.stopped = true;
  this.say("That session is gone.");
  if(this.on.closed) this.on.closed();
  return Promise.resolve();
};
// Repaints are coalesced to one a frame: a program redrawing a whole screen
// sends it in several chunks, and painting each one is the same picture three
// times.
ShellSession.prototype.schedule = function(closed){
  if(closed){
    if(this.frame){ clearTimeout(this.frame); this.frame = null; }
    this.draw(false);
    this.box.appendChild(document.createTextNode("\n[session closed]\n"));
    return;
  }
  if(this.frame) return;
  this.frame = setTimeout(() => { this.frame = null; this.draw(true); }, SHELL_FRAME);
};
ShellSession.prototype.draw = function(showCursor){
  if(!this.term) return;
  const box = this.box;
  const atEnd = box.scrollTop + box.clientHeight >= box.scrollHeight - 40;
  this.term.paint(box, showCursor);
  box.classList.toggle("t-mouse", !!this.term.mouse);
  if(atEnd || this.term.alt()) box.scrollTop = box.scrollHeight;
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
      }catch(_){}                               // the read will show it went
    }
  }finally{ this.sending = null; }
};
// The pty is told the size it actually has, and the emulator's own grid follows
// it. Telling one and not the other is the bug that makes every full-screen
// program look broken: the program lays out to one width and the screen holds
// another.
ShellSession.prototype.fit = async function(){
  if(!this.term) return;
  const metrics = termMetrics(this.box);
  this.metrics = metrics;
  if(metrics.cols === this.size.cols && metrics.rows === this.size.rows) return;
  this.size = {cols:metrics.cols, rows:metrics.rows};
  this.term.resize(metrics.cols, metrics.rows);
  this.box._rows = null;                        // the grid changed shape
  this.draw(true);
  if(!this.sid) return;
  try{
    await api("/api/fleet/resize", "POST",
              {node:this.node, sid:this.sid, cols:metrics.cols, rows:metrics.rows});
  }catch(_){}
};
// Where a pointer event landed, in cells. One-based, because that is what the
// report carries.
ShellSession.prototype.cellAt = function(event){
  if(!this.metrics) this.metrics = termMetrics(this.box);
  const rect = this.box.getBoundingClientRect();
  const x = event.clientX - rect.left - this.metrics.padLeft + this.box.scrollLeft;
  const y = event.clientY - rect.top - this.metrics.padTop + this.box.scrollTop;
  // The screen starts below whatever scrollback is drawn above it, so a click
  // is measured from there rather than from the top of the pane.
  const above = (this.term && !this.term.alt() && this.box.firstElementChild)
    ? this.box.firstElementChild.offsetHeight : 0;
  return {col: Math.floor(x / this.metrics.cw) + 1,
          row: Math.floor((y - above) / this.metrics.lh) + 1};
};
// A program that turned mouse reporting on is *waiting* for these: without them
// a pointer does nothing in `btop`, `htop` or `less`, and a click that does
// nothing reads as a broken terminal rather than a missing feature.
ShellSession.prototype.mouse = function(event, kind){
  const term = this.term;
  if(!term || !term.mouse || !this.sid) return false;
  const at = this.cellAt(event);
  if(at.row < 1 || at.row > term.rows) return false;
  let button;
  if(kind === "wheel") button = event.deltaY < 0 ? 64 : 65;
  else button = event.button === 1 ? 1 : (event.button === 2 ? 2 : 0);
  if(kind === "move"){
    if(term.mouse < 1002) return false;
    if(term.mouse === 1002 && event.buttons === 0) return false;
    const key = at.col + ":" + at.row;
    if(this.lastCell === key) return true;      // one report per cell, not per pixel
    this.lastCell = key;
    button = (event.buttons === 0 ? 3 : button) + 32;
  }
  if(event.shiftKey) button += 4;
  if(event.altKey) button += 8;
  if(event.ctrlKey) button += 16;
  const report = term.mouseReport(button, at.col, at.row,
                                 kind === "up" && term.mouseSgr);
  if(report === null) return false;
  if(kind === "up" && !term.mouseSgr){
    this.send(term.mouseReport(3, at.col, at.row, false));
    return true;
  }
  this.send(report);
  return true;
};
ShellSession.prototype.halt = function(){
  this.stopped = true;
  if(this.retry){ clearTimeout(this.retry); this.retry = null; }
  if(this.frame){ clearTimeout(this.frame); this.frame = null; }
};
ShellSession.prototype.stop = async function(){
  this.halt();
  const node = this.node, sid = this.sid;
  this.node = null; this.sid = null;
  if(!sid) return;
  try{ await api("/api/fleet/close", "POST", {node, sid}); }catch(_){}
};
ShellSession.prototype.live = function(){ return !!this.sid; };
ShellSession.prototype.copyText = function(){
  const selected = String(window.getSelection() || "");
  return selected || (this.term ? this.term.text() : this.box.innerText);
};
// Bracketed paste: a program that asked for it wants to know the text arrived
// as a paste rather than as typing — which is what stops an editor
// auto-indenting every line of it.
ShellSession.prototype.paste = function(text){
  if(!text) return Promise.resolve();
  if(this.term && this.term.bracketed) text = "\x1b[200~" + text + "\x1b[201~";
  return this.send(text);
};

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
  const bytes = keyBytes(event, TERM_SESSION.term);
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
  const bytes = keyBytes(event, TERM_SESSION ? TERM_SESSION.term : null);
  if(bytes === null || bytes === event.key) return;        // plain text: let it type
  event.preventDefault();
  await typeIn(bytes);
});
$("tin").addEventListener("paste", async (event) => {
  event.preventDefault();
  await TERM_SESSION.paste((event.clipboardData || window.clipboardData).getData("text"));
});
$("term").addEventListener("paste", async (event) => {
  event.preventDefault();
  await TERM_SESSION.paste((event.clipboardData || window.clipboardData).getData("text"));
});

// ---- the pointer ------------------------------------------------------------
// Only while a program has asked for it. Nothing is invented on this side: with
// mouse reporting off, a drag stays an ordinary text selection.

$("term").addEventListener("mousedown", (event) => {
  if(TERM_SESSION && TERM_SESSION.mouse(event, "down")) event.preventDefault();
});
$("term").addEventListener("mouseup", (event) => {
  if(TERM_SESSION && TERM_SESSION.mouse(event, "up")) event.preventDefault();
});
$("term").addEventListener("mousemove", (event) => {
  if(TERM_SESSION) TERM_SESSION.mouse(event, "move");
});
$("term").addEventListener("wheel", (event) => {
  if(TERM_SESSION && TERM_SESSION.mouse(event, "wheel")) event.preventDefault();
}, {passive:false});
$("term").addEventListener("contextmenu", (event) => {
  if(TERM_SESSION && TERM_SESSION.term && TERM_SESSION.term.mouse) event.preventDefault();
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
  const text = TERM_SESSION ? TERM_SESSION.copyText() : $("term").innerText;
  if(!text.trim()){ toast("Nothing to copy", "warn"); return; }
  await copyText(text);
});

async function pasteIn(){
  let text = "";
  try{ text = await navigator.clipboard.readText(); }
  catch(_){ text = ""; }
  if(text){ await TERM_SESSION.paste(text); return; }
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
  await TERM_SESSION.paste(text);
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
// The window is not the only thing that resizes the pane: a key row appearing,
// a font loading or a panel opening all change it while the window stands
// still. Watching the element catches every one of them.
if(window.ResizeObserver){
  const watch = new ResizeObserver(debounce(() => {
    if(TERM_SESSION) TERM_SESSION.fit();
  }, 120));
  watch.observe($("term"));
}

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
