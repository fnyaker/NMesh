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
   than recolouring somebody else's output.

   The screen itself is a canvas. A grid of text in the DOM depends on every
   glyph in the font having the same advance, and the moment one does not — a
   box-drawing character the font lacks, a braille cell, an emoji — the browser
   falls back per glyph and the whole line drifts sideways. That is what a
   broken `btop` looks like. Drawing each cell at a computed x removes the
   question. */
.term{--page-term-bg:#0a0f16;--page-term-fg:#cfe0f7;
  margin:0;position:relative;min-height:440px;height:62vh;overflow:hidden;
  background:var(--page-term-bg);color:var(--page-term-fg);
  border-bottom:1px solid var(--border);
  font:13px/1.25 var(--term-font)}
.term canvas{display:block;width:100%;height:100%}
.term:focus-visible{outline:2px solid var(--ring);outline-offset:-2px}
/* While a program is reporting the mouse, dragging must not look like a text
   selection — the drag *is* the message being sent. */
.term.t-mouse{cursor:default}
/* A screen reader has nothing to read off a canvas, so the same text is kept
   beside it, off screen and updated far more slowly than the picture. */
.term .t-a11y{position:absolute;left:-9999px;top:0;width:1px;height:1px;
  overflow:hidden;white-space:pre}
.t-back{position:absolute;right:6px;top:6px;z-index:2;
  padding:2px 8px;border-radius:var(--r-full);
  background:var(--surface);border:1px solid var(--border);
  font:var(--fs-2xs)/1.6 var(--mono);color:var(--text-muted)}
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
//
// Two things about the *shape* of it are load-bearing, and both were bugs:
//
//   * The parser never slices. It used to take `data.slice(i)` at every escape
//     to run a regex against, which on a screen `btop` draws — thousands of
//     escapes in one chunk — copies the remaining buffer thousands of times.
//     That is quadratic in the size of a frame, and it is what made a redraw
//     stutter. Sticky regexes match in place instead.
//   * The screen is drawn on a **canvas**, not in the DOM. A grid of text in
//     the DOM depends on every glyph having the same advance; the moment one
//     does not — a box-drawing character the font lacks, a braille cell — the
//     browser falls back per glyph and the line drifts. Drawing each cell at a
//     computed x removes the question, and a repaint stops being thousands of
//     DOM nodes.

// Attribute bits. Kept as a mask rather than booleans because every cell on the
// screen carries one, and a screen is a few thousand cells repainted many times
// a second.
const T_BOLD = 1, T_DIM = 2, T_ITALIC = 4, T_UNDER = 8;
const T_INVERSE = 16, T_HIDDEN = 32, T_STRIKE = 64;

// The sixteen palette colours, as the canvas needs them: a colour, not a class.
const T_PALETTE = [
  "#5b6b80", "#ff8079", "#5fd39a", "#f2c261", "#79b0ff", "#d79bff", "#5fd9d0", "#e8eef5",
  "#7d8ea6", "#ff9d97", "#86e3b6", "#ffd684", "#9cc6ff", "#e4b8ff", "#8fe9e2", "#ffffff",
];
const T_DEF_BG = "#0a0f16", T_DEF_FG = "#cfe0f7";
const T_SELECT = "rgba(124,168,255,.35)";

function t_hex(value){
  return "#" + value.map((part) => part.toString(16).padStart(2, "0")).join("");
}
// The 256-colour cube, for the indices past the palette.
function t256(index){
  if(index < 16) return T_PALETTE[index];
  if(index < 232){
    const n = index - 16;
    const step = (value) => (value ? 55 + value * 40 : 0);
    return t_hex([step(Math.floor(n / 36) % 6), step(Math.floor(n / 6) % 6), step(n % 6)]);
  }
  const grey = 8 + (index - 232) * 10;
  return t_hex([grey, grey, grey]);
}
function t_colour(value){
  if(value === null) return null;
  if(typeof value === "number") return t256(value & 255);
  return Array.isArray(value) ? t_hex(value.map((part) => part & 255)) : value;
}
function t_key(value){
  return value === null ? "-" : (typeof value === "number" ? String(value)
                                                           : String(value));
}

// Styles are interned: a screen has thousands of cells and a handful of
// distinct looks, so cells share one object and a repaint compares references
// instead of colours.
const T_STYLES = new Map();
const T_MAX_STYLES = 4096;

function termStyle(fg, bg, flags){
  const key = t_key(fg) + "|" + t_key(bg) + "|" + flags;
  let style = T_STYLES.get(key);
  if(style) return style;
  // Inverse is resolved here rather than at paint time: it is a swap, and doing
  // it once per distinct look beats doing it once per cell per frame.
  let front = fg, back = bg;
  if(flags & T_INVERSE){
    front = bg === null ? T_DEF_BG : bg;
    back = fg === null ? T_DEF_FG : fg;
  }
  style = {
    key: key, fg: fg, bg: bg, flags: flags,
    front: t_colour(front) || T_DEF_FG,
    back: t_colour(back),
    bold: !!(flags & T_BOLD), dim: !!(flags & T_DIM),
    italic: !!(flags & T_ITALIC), under: !!(flags & T_UNDER),
    strike: !!(flags & T_STRIKE), hidden: !!(flags & T_HIDDEN),
    plain: fg === null && bg === null && flags === 0,
  };
  if(T_STYLES.size < T_MAX_STYLES) T_STYLES.set(key, style);
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
  this.scrollback = [];         // cell rows, trailing blanks trimmed
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
  this.pending = "";
  // Which rows a repaint has to touch. A frame that changed one line should
  // cost one line, and `all` is the honest answer when the screen moved.
  this.dirty = new Set(); this.allDirty = true; this.sbAdded = 0;
  this.tabs = {};
};
Term.prototype.touch = function(y){
  if(y >= 0 && y < this.rows) this.dirty.add(y);
};
Term.prototype.touchAll = function(){ this.allDirty = true; };
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
Term.prototype.screen = function(){ return this.alt() ? this.altGrid : this.grid; };

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
  this.touchAll();
  return true;
};
Term.prototype.pushScrollback = function(row){
  // Trimmed before it is kept: a scrollback line is usually a prompt and a
  // short command, and storing every one of them padded to the full width is
  // most of a megabyte for nothing.
  let end = row.length;
  while(end > 0 && row[end - 1].c === " " && row[end - 1].s.plain) end--;
  this.scrollback.push(row.slice(0, end));
  this.sbAdded++;
  if(this.scrollback.length > T_SCROLLBACK) this.scrollback.shift();
};
// Scrolling happens inside the region, never over the whole screen: that is the
// difference between a pane a program can animate and one that jumps.
Term.prototype.scrollUp = function(count){
  const grid = this.screen();
  for(let n = 0; n < count; n++){
    const gone = grid.splice(this.top, 1)[0];
    if(!this.alt() && this.top === 0) this.pushScrollback(gone);
    grid.splice(this.bot, 0, this.eraseRow());
  }
  this.touchAll();
};
Term.prototype.scrollDown = function(count){
  const grid = this.screen();
  for(let n = 0; n < count; n++){
    grid.splice(this.bot, 1);
    grid.splice(this.top, 0, this.eraseRow());
  }
  this.touchAll();
};
Term.prototype.newline = function(){
  if(this.y === this.bot) this.scrollUp(1);
  else if(this.y < this.rows - 1){ this.touch(this.y); this.y++; this.touch(this.y); }
};
Term.prototype.reverseNewline = function(){
  if(this.y === this.top) this.scrollDown(1);
  else if(this.y > 0){ this.touch(this.y); this.y--; this.touch(this.y); }
};
Term.prototype.put = function(ch, width){
  if(width === 0){                       // a combining mark joins the cell before
    const row = this.screen()[this.y];
    const at = this.x > 0 ? this.x - 1 : 0;
    if(row[at] && row[at].c) row[at] = {c:row[at].c + ch, s:row[at].s, w:row[at].w};
    this.touch(this.y);
    return;
  }
  if(this.wrapNext || this.x + width > this.cols){
    if(this.autowrap){ this.x = 0; this.newline(); }
    else this.x = this.cols - width;
    this.wrapNext = false;
  }
  const line = this.screen()[this.y];
  if(this.insert){
    for(let n = 0; n < width; n++){
      line.splice(this.cols - 1, 1); line.splice(this.x, 0, this.eraseCell());
    }
  }
  line[this.x] = {c:ch, s:this.style, w:width};
  for(let n = 1; n < width; n++){
    if(this.x + n < this.cols) line[this.x + n] = {c:"", s:this.style, w:0};
  }
  this.touch(this.y);
  this.x += width;
  if(this.x >= this.cols){ this.x = this.cols - 1; this.wrapNext = true; }
};
Term.prototype.eraseLine = function(mode){
  const row = this.screen()[this.y];
  const from = mode === 0 ? this.x : 0;
  const to = mode === 1 ? this.x + 1 : this.cols;
  for(let i = from; i < to && i < this.cols; i++) row[i] = this.eraseCell();
  this.touch(this.y);
};
Term.prototype.eraseDisplay = function(mode){
  const grid = this.screen();
  if(mode === 2 || mode === 3){
    for(let y = 0; y < this.rows; y++) grid[y] = this.eraseRow();
    if(mode === 3){ this.scrollback.length = 0; this.sbAdded = 0; }
    this.touchAll();
    return;
  }
  this.eraseLine(mode === 1 ? 1 : 0);
  if(mode === 0) for(let y = this.y + 1; y < this.rows; y++) grid[y] = this.eraseRow();
  else for(let y = 0; y < this.y; y++) grid[y] = this.eraseRow();
  this.touchAll();
};
Term.prototype.eraseChars = function(count){
  const row = this.screen()[this.y];
  for(let i = this.x; i < Math.min(this.cols, this.x + count); i++) row[i] = this.eraseCell();
  this.touch(this.y);
};
Term.prototype.deleteChars = function(count){
  const row = this.screen()[this.y];
  for(let n = 0; n < count && this.x < this.cols; n++){
    row.splice(this.x, 1); row.push(this.eraseCell());
  }
  this.touch(this.y);
};
Term.prototype.insertChars = function(count){
  const row = this.screen()[this.y];
  for(let n = 0; n < count; n++){
    row.splice(this.cols - 1, 1); row.splice(this.x, 0, this.eraseCell());
  }
  this.touch(this.y);
};
Term.prototype.insertLines = function(count){
  if(this.y < this.top || this.y > this.bot) return;
  const grid = this.screen();
  for(let n = 0; n < count; n++){
    grid.splice(this.bot, 1); grid.splice(this.y, 0, this.eraseRow());
  }
  this.touchAll();
};
Term.prototype.deleteLines = function(count){
  if(this.y < this.top || this.y > this.bot) return;
  const grid = this.screen();
  for(let n = 0; n < count; n++){
    grid.splice(this.y, 1); grid.splice(this.bot, 0, this.eraseRow());
  }
  this.touchAll();
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
  this.touchAll();
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
  this.touchAll();
};
Term.prototype.cursorState = function(){
  return {x:this.x, y:this.y, fg:this.fg, bg:this.bg, flags:this.flags,
          graphics:this.graphics, origin:this.origin};
};
Term.prototype.restoreCursor = function(state){
  if(!state) return;
  this.touch(this.y);
  this.x = Math.min(state.x, this.cols - 1);
  this.y = Math.min(state.y, this.rows - 1);
  this.fg = state.fg; this.bg = state.bg; this.flags = state.flags;
  this.graphics = state.graphics; this.origin = state.origin;
  this.style = termStyle(this.fg, this.bg, this.flags);
  this.wrapNext = false;
  this.touch(this.y);
};
Term.prototype.goto = function(row, col){
  const base = this.origin ? this.top : 0;
  const limit = this.origin ? this.bot : this.rows - 1;
  this.touch(this.y);
  this.y = Math.max(0, Math.min(limit, base + row));
  this.x = Math.max(0, Math.min(this.cols - 1, col));
  this.wrapNext = false;
  this.touch(this.y);
};
Term.prototype.nextTab = function(count){
  for(let n = 0; n < count; n++){
    let at = this.x + 1;
    while(at < this.cols - 1 && !(this.tabs[at] || at % 8 === 0)) at++;
    this.x = Math.min(this.cols - 1, at);
  }
  this.wrapNext = false;
  this.touch(this.y);
};
Term.prototype.prevTab = function(count){
  for(let n = 0; n < count; n++){
    let at = this.x - 1;
    while(at > 0 && !(this.tabs[at] || at % 8 === 0)) at--;
    this.x = Math.max(0, at);
  }
  this.touch(this.y);
};

// Sticky, every one of them: they are matched **in place** at the escape's own
// offset. The version that sliced the buffer first was quadratic in the size of
// a frame, which is exactly the thing a full-screen program sends.
const T_CSI = /\x1b\[([\x30-\x3f]*)([\x20-\x2f]*)([\x40-\x7e])/y;
const T_OSC = /\x1b\](\d*);?([^\x07\x1b]*)(\x07|\x1b\\)/y;
const T_STR = /\x1b[P^_X][\s\S]*?(\x1b\\|\x07)/y;
const T_ESC2 = /\x1b([()*+%#])([0-9A-Za-z@])/y;
// A CSI that has not finished yet: parameter and intermediate bytes and then
// the end of what arrived. Told apart from a malformed one, which is dropped
// rather than waited on for ever.
const T_CSI_PART = /\x1b\[[\x30-\x3f]*[\x20-\x2f]*$/y;

Term.prototype.write = function(text){
  const data = this.pending + text;
  this.pending = "";
  const length = data.length;
  let i = 0;
  while(i < length){
    const ch = data[i];
    if(ch === "\x1b"){
      const at = this.escape(data, i, length);
      if(at < 0) return;                     // incomplete: kept in `pending`
      i = at;
      continue;
    }
    i++;
    if(ch === "\n" || ch === "\x0b" || ch === "\x0c"){ this.newline(); this.wrapNext = false; continue; }
    if(ch === "\r"){ this.x = 0; this.wrapNext = false; this.touch(this.y); continue; }
    if(ch === "\b"){ if(this.x > 0) this.x--; this.wrapNext = false; this.touch(this.y); continue; }
    if(ch === "\t"){ this.nextTab(1); continue; }
    if(ch === "\x07"){ if(this.onBell) try{ this.onBell(); }catch(_){} continue; }
    if(ch === "\x0e"){ this.graphics = true; continue; }
    if(ch === "\x0f"){ this.graphics = false; continue; }
    if(ch < " " || ch === "\x7f") continue;  // other control bytes
    let glyph = ch, code = ch.charCodeAt(0);
    if(code >= 0xd800 && code <= 0xdbff && i < length){
      glyph = ch + data[i]; code = glyph.codePointAt(0); i++;
    }
    if(this.graphics && T_DEC_GRAPHICS[glyph]) glyph = T_DEC_GRAPHICS[glyph];
    this.put(glyph, termWidth(code));
  }
};
// One escape sequence at `start`. Returns the offset just past it, or -1 when
// it is incomplete (and has been kept for the next chunk).
Term.prototype.escape = function(data, start, length){
  T_CSI.lastIndex = start;
  let match = T_CSI.exec(data);
  if(match){ this.csi(match[1], match[2], match[3]); return T_CSI.lastIndex; }
  T_OSC.lastIndex = start;
  match = T_OSC.exec(data);
  if(match){
    if(match[1] === "0" || match[1] === "2") this.title = match[2].slice(0, 200);
    return T_OSC.lastIndex;
  }
  T_STR.lastIndex = start;
  match = T_STR.exec(data);
  if(match) return T_STR.lastIndex;
  T_ESC2.lastIndex = start;
  match = T_ESC2.exec(data);
  if(match){
    if(match[1] === "(") this.graphics = match[2] === "0";
    return T_ESC2.lastIndex;
  }
  // Nothing matched: either the sequence is split across two reads — kept and
  // retried when the rest comes — or it is malformed, and dropped.
  T_CSI_PART.lastIndex = start;
  if(T_CSI_PART.test(data)){
    if(length - start < T_PENDING_MAX) this.pending = data.slice(start);
    return -1;
  }
  if(start + 1 >= length){ this.pending = data.slice(start); return -1; }
  const next = data[start + 1];
  switch(next){
    case "7": this.saved = this.cursorState(); return start + 2;
    case "8": this.restoreCursor(this.saved); return start + 2;
    case "D": this.newline(); return start + 2;
    case "E": this.x = 0; this.newline(); return start + 2;
    case "M": this.reverseNewline(); return start + 2;
    case "H": this.tabs[this.x] = true; return start + 2;
    case "c": this.reset(); return start + 2;
    case "=": case ">": this.appKeypad = next === "="; return start + 2;
    case "\\": return start + 2;
    case "]": case "P": case "^": case "_": case "X":
      // A string sequence whose terminator has not arrived yet.
      if(length - start < T_PENDING_MAX){ this.pending = data.slice(start); return -1; }
      return start + 2;
    default: return start + 2;               // unknown two-byte escape: dropped
  }
};
Term.prototype.csi = function(paramText, intermediate, final){
  const priv = paramText.charCodeAt(0) === 0x3f;      // `?` — a DEC private mode
  const params = (priv ? paramText.slice(1) : paramText).split(";");
  const first = Math.max(1, parseInt(params[0] || "1", 10) || 1);
  const raw0 = parseInt(params[0] || "0", 10) || 0;
  switch(final){
    case "A": this.touch(this.y); this.y = Math.max(this.origin ? this.top : 0, this.y - first); this.wrapNext = false; this.touch(this.y); break;
    case "B": this.touch(this.y); this.y = Math.min(this.origin ? this.bot : this.rows - 1, this.y + first); this.wrapNext = false; this.touch(this.y); break;
    case "C": this.x = Math.min(this.cols - 1, this.x + first); this.wrapNext = false; this.touch(this.y); break;
    case "D": this.x = Math.max(0, this.x - first); this.wrapNext = false; this.touch(this.y); break;
    case "E": this.touch(this.y); this.x = 0; this.y = Math.min(this.rows - 1, this.y + first); this.touch(this.y); break;
    case "F": this.touch(this.y); this.x = 0; this.y = Math.max(0, this.y - first); this.touch(this.y); break;
    case "G": case "`": this.x = Math.min(this.cols - 1, Math.max(0, first - 1)); this.wrapNext = false; this.touch(this.y); break;
    case "d": this.touch(this.y); this.y = Math.min(this.rows - 1, Math.max(0, first - 1)); this.wrapNext = false; this.touch(this.y); break;
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
};

// ---- reading the screen back ------------------------------------------------
// Not a rendering path: nothing here draws. It is what a copy takes, what a
// screen reader is given, and what a test asserts on.

function t_rowText(row){
  let end = row.length;
  while(end > 0 && row[end - 1].c === " " && row[end - 1].s.plain) end--;
  let out = "";
  for(let i = 0; i < end; i++) if(row[i].w !== 0) out += row[i].c || " ";
  return out;
}
Term.prototype.line = function(y){
  const grid = this.screen();
  return y >= 0 && y < grid.length ? t_rowText(grid[y]) : "";
};
Term.prototype.cell = function(y, x){
  const grid = this.screen();
  return (grid[y] && grid[y][x]) || null;
};
// Every line the pane holds: the scrollback above the screen, then the screen.
// The alternate screen has no scrollback — that is the whole point of it.
Term.prototype.lines = function(){
  const out = this.alt() ? [] : this.scrollback.map(t_rowText);
  const grid = this.screen();
  for(let y = 0; y < grid.length; y++) out.push(t_rowText(grid[y]));
  return out;
};
Term.prototype.text = function(){ return this.lines().join("\n"); };
// The text between two points, as a copy takes it.
Term.prototype.range = function(from, to){
  const all = this.lines();
  const above = this.alt() ? 0 : this.scrollback.length;
  let start = from, end = to;
  if(start.row > end.row || (start.row === end.row && start.col > end.col)){
    start = to; end = from;
  }
  const out = [];
  for(let row = Math.max(0, start.row); row <= Math.min(end.row, all.length - 1); row++){
    const line = all[row];
    const left = row === start.row ? start.col : 0;
    const right = row === end.row ? end.col : line.length;
    out.push(line.slice(left, Math.max(left, right)));
  }
  return {text: out.join("\n"), above: above};
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

// ---- the screen -------------------------------------------------------------
// A canvas, and the reasons are the two complaints it answers.
//
// **Alignment.** A grid of text in the DOM depends on every glyph having the
// same advance. `btop` draws with box-drawing and braille characters, which
// many monospace fonts do not carry; the browser then falls back per glyph, the
// advance changes mid-line, and every column after it drifts. Drawing each cell
// at `col * cw` removes the question — and `fillText`'s own `maxWidth` condenses
// a glyph that came from a wider fallback into the cell it belongs to.
//
// **Cost.** The DOM version rebuilt a few thousand nodes for a frame in which a
// program moved one line. Here a repaint touches the rows that changed, and a
// row is a handful of canvas calls.

const T_A11Y_TICK = 700;        // how often the off-screen text mirror catches up

function TermScreen(host){
  this.host = host;
  host.textContent = "";
  this.canvas = document.createElement("canvas");
  this.canvas.setAttribute("aria-hidden", "true");
  host.appendChild(this.canvas);
  // A screen reader has nothing to read off a canvas, so the same text is kept
  // beside it — off screen, and updated far more slowly than the picture.
  this.mirror = document.createElement("pre");
  this.mirror.className = "t-a11y";
  host.appendChild(this.mirror);
  this.back = document.createElement("button");
  this.back.className = "t-back";
  this.back.type = "button";
  this.back.textContent = "back to the bottom";
  this.back.hidden = true;
  host.appendChild(this.back);
  this.back.addEventListener("click", () => { this.toBottom(); this.draw(true); });

  this.ctx = this.canvas.getContext("2d", {alpha:false});
  this.term = null;
  this.cw = 8; this.lh = 16; this.dpr = 1;
  this.cols = 80; this.rows = 24;
  this.viewTop = 0; this.following = true;
  this.painted = -1; this.lastCursor = null; this.lastSb = 0;
  this.select = null; this.focused = false;
  this.mirrorAt = 0;
  this.measure();
}
TermScreen.prototype.font = function(style){
  const weight = style && style.bold ? "700 " : "";
  const slant = style && style.italic ? "italic " : "";
  return slant + weight + this.size + "px " + this.family;
};
// Measured from the element, once per resize: the cell is whatever the font
// actually advances, and every column is placed on that.
TermScreen.prototype.measure = function(){
  const shown = getComputedStyle(this.host);
  this.family = shown.fontFamily || "monospace";
  this.size = parseFloat(shown.fontSize) || 13;
  this.lh = Math.max(2, Math.round(parseFloat(shown.lineHeight) || this.size * 1.25));
  this.dpr = Math.min(3, window.devicePixelRatio || 1);
  const ctx = this.ctx;
  ctx.font = this.font(null);
  // A run rather than one character: a single glyph's advance is rounded, and
  // the rounding is what makes a long line drift by a pixel a column.
  this.cw = ctx.measureText("0".repeat(32)).width / 32 || 8;
  const padX = (parseFloat(shown.paddingLeft) || 0) + (parseFloat(shown.paddingRight) || 0);
  const padY = (parseFloat(shown.paddingTop) || 0) + (parseFloat(shown.paddingBottom) || 0);
  const width = Math.max(40, this.host.clientWidth - padX);
  const height = Math.max(20, this.host.clientHeight - padY);
  this.cols = Math.max(20, Math.min(400, Math.floor(width / this.cw)));
  this.rows = Math.max(6, Math.min(200, Math.floor(height / this.lh)));
  this.canvas.width = Math.round(width * this.dpr);
  this.canvas.height = Math.round(height * this.dpr);
  this.canvas.style.width = width + "px";
  this.canvas.style.height = height + "px";
  ctx.setTransform(this.dpr, 0, 0, this.dpr, 0, 0);
  ctx.textBaseline = "alphabetic";
  this.painted = -1;
  return {cols:this.cols, rows:this.rows};
};
TermScreen.prototype.attach = function(term){
  this.term = term;
  this.viewTop = 0; this.following = true;
  this.painted = -1; this.lastCursor = null; this.lastSb = term.sbAdded;
  this.select = null;
};
TermScreen.prototype.total = function(){
  const term = this.term;
  return (term.alt() ? 0 : term.scrollback.length) + term.rows;
};
TermScreen.prototype.toBottom = function(){
  this.following = true;
  this.viewTop = Math.max(0, this.total() - this.rows);
};
TermScreen.prototype.scrollBy = function(lines){
  const top = Math.max(0, Math.min(this.total() - this.rows,
                                   this.viewTop + lines));
  if(top === this.viewTop) return false;
  this.viewTop = top;
  this.following = top >= this.total() - this.rows;
  return true;
};
// The line at a screen row: the scrollback above, then the grid.
TermScreen.prototype.rowAt = function(index){
  const term = this.term;
  const above = term.alt() ? 0 : term.scrollback.length;
  if(index < above) return term.scrollback[index];
  const grid = term.screen();
  return grid[index - above] || null;
};

TermScreen.prototype.draw = function(showCursor){
  const term = this.term;
  if(!term) return;
  if(this.following) this.toBottom();
  const ctx = this.ctx;
  const cursorOn = showCursor !== false && term.cursorVisible && !this.select;
  const cursor = cursorOn ? {x:term.x, y:term.y} : null;
  // A full repaint when the view moved under us, and only the rows a program
  // touched otherwise.
  const moved = this.painted !== this.viewTop || term.allDirty ||
                term.sbAdded !== this.lastSb || this.select;
  const wanted = new Set();
  if(moved){
    for(let k = 0; k < this.rows; k++) wanted.add(k);
  }else{
    const above = term.alt() ? 0 : term.scrollback.length;
    for(const y of term.dirty){
      const k = y + above - this.viewTop;
      if(k >= 0 && k < this.rows) wanted.add(k);
    }
    for(const point of [this.lastCursor, cursor]){
      if(!point) continue;
      const k = point.y + above - this.viewTop;
      if(k >= 0 && k < this.rows) wanted.add(k);
    }
  }
  term.dirty.clear(); term.allDirty = false;
  this.lastSb = term.sbAdded; this.painted = this.viewTop;
  this.lastCursor = cursor;
  const above = term.alt() ? 0 : term.scrollback.length;
  for(const k of wanted){
    const row = this.rowAt(this.viewTop + k);
    const onCursor = cursor && (cursor.y + above - this.viewTop) === k ? cursor.x : -1;
    this.drawRow(k, row, onCursor);
  }
  this.back.hidden = this.following;
  const now = Date.now();
  if(now - this.mirrorAt > T_A11Y_TICK){
    this.mirrorAt = now;
    // textContent, never markup: this is bytes a remote machine chose.
    this.mirror.textContent = term.lines().slice(-this.rows).join("\n");
  }
};
TermScreen.prototype.drawRow = function(k, row, cursorX){
  const ctx = this.ctx, cw = this.cw, lh = this.lh;
  const top = k * lh;
  ctx.fillStyle = T_DEF_BG;
  ctx.fillRect(0, top, this.canvas.width, lh);
  if(!row) return;
  const width = Math.min(row.length, this.cols);
  // Backgrounds first, as runs: a panel is one rectangle, not two hundred.
  let start = 0;
  while(start < width){
    const style = row[start].s;
    let end = start + 1;
    while(end < width && row[end].s === style) end++;
    if(style.back){
      ctx.fillStyle = style.back;
      ctx.fillRect(start * cw, top, (end - start) * cw, lh);
    }
    start = end;
  }
  if(this.select) this.drawSelection(k, top);
  const baseline = top + Math.round(lh * 0.78);
  let run = "", runAt = 0, runStyle = null;
  const flush = () => {
    if(!run) return;
    ctx.fillStyle = runStyle.front;
    ctx.globalAlpha = runStyle.dim ? 0.62 : 1;
    ctx.font = this.font(runStyle);
    ctx.fillText(run, runAt * cw, baseline, run.length * cw);
    ctx.globalAlpha = 1;
    run = "";
  };
  for(let column = 0; column < width; column++){
    const cell = row[column];
    if(cell.w === 0) continue;
    const style = cell.s;
    const glyph = cell.c || " ";
    // A run is only ever plain ASCII of width one: those are the characters the
    // measured advance was taken from, so drawing them together lands each one
    // exactly where drawing them apart would. Everything else — a box, a
    // braille cell, a wide form — is placed on its own column, which is the
    // whole reason this is a canvas.
    const simple = cell.w === 1 && glyph.length === 1 && glyph < "\x7f" &&
                   glyph >= " " && style !== null;
    if(simple && style === runStyle && runAt + run.length === column){
      run += glyph;
      continue;
    }
    flush();
    if(style.hidden || glyph === " "){
      if(style.under || style.strike){ this.decorate(ctx, column, top, cell.w, style); }
      if(simple){ runStyle = style; runAt = column; run = ""; }
      continue;
    }
    if(simple){ runStyle = style; runAt = column; run = glyph; continue; }
    ctx.fillStyle = style.front;
    ctx.globalAlpha = style.dim ? 0.62 : 1;
    ctx.font = this.font(style);
    ctx.fillText(glyph, column * cw, baseline, cw * Math.max(1, cell.w));
    ctx.globalAlpha = 1;
    if(style.under || style.strike) this.decorate(ctx, column, top, cell.w, style);
  }
  flush();
  // The underline and strike of a run, drawn once the text is down.
  for(let column = 0; column < width; column++){
    const cell = row[column];
    if(cell.w !== 0 && (cell.s.under || cell.s.strike) && cell.c !== " ")
      this.decorate(ctx, column, top, cell.w, cell.s);
  }
  if(cursorX >= 0 && cursorX < this.cols) this.drawCursor(cursorX, top, row[cursorX]);
};
TermScreen.prototype.decorate = function(ctx, column, top, width, style){
  ctx.fillStyle = style.front;
  const span = Math.max(1, width) * this.cw;
  if(style.under) ctx.fillRect(column * this.cw, top + this.lh - 2, span, 1);
  if(style.strike) ctx.fillRect(column * this.cw, top + Math.round(this.lh * 0.55), span, 1);
};
TermScreen.prototype.drawCursor = function(column, top, cell){
  const ctx = this.ctx, cw = this.cw;
  const style = (cell && cell.s) || T_PLAIN;
  if(!this.focused){
    ctx.strokeStyle = style.front || T_DEF_FG;
    ctx.lineWidth = 1;
    ctx.strokeRect(column * cw + 0.5, top + 0.5, cw - 1, this.lh - 1);
    return;
  }
  ctx.fillStyle = style.front || T_DEF_FG;
  ctx.fillRect(column * cw, top, cw, this.lh);
  const glyph = cell && cell.c && cell.c !== " " ? cell.c : "";
  if(glyph){
    ctx.fillStyle = style.back || T_DEF_BG;
    ctx.font = this.font(style);
    ctx.fillText(glyph, column * cw, top + Math.round(this.lh * 0.78), cw);
  }
};
TermScreen.prototype.drawSelection = function(k, top){
  const span = this.selectionOn(this.viewTop + k);
  if(!span) return;
  this.ctx.fillStyle = T_SELECT;
  this.ctx.fillRect(span[0] * this.cw, top, (span[1] - span[0]) * this.cw, this.lh);
};
TermScreen.prototype.selectionOn = function(line){
  if(!this.select) return null;
  let from = this.select.from, to = this.select.to;
  if(from.row > to.row || (from.row === to.row && from.col > to.col)){
    from = this.select.to; to = this.select.from;
  }
  if(line < from.row || line > to.row) return null;
  const left = line === from.row ? from.col : 0;
  const right = line === to.row ? to.col : this.cols;
  return right > left ? [left, right] : null;
};

// ---- where the pointer is, in cells -----------------------------------------

TermScreen.prototype.pointAt = function(event){
  const rect = this.canvas.getBoundingClientRect();
  const col = Math.max(0, Math.min(this.cols,
    Math.round((event.clientX - rect.left) / this.cw)));
  const k = Math.max(0, Math.min(this.rows - 1,
    Math.floor((event.clientY - rect.top) / this.lh)));
  return {row: this.viewTop + k, col: col, screenRow: k};
};
TermScreen.prototype.beginSelect = function(event){
  const at = this.pointAt(event);
  this.select = {from:at, to:at};
};
TermScreen.prototype.extendSelect = function(event){
  if(!this.select) return false;
  this.select.to = this.pointAt(event);
  return true;
};
TermScreen.prototype.clearSelect = function(){
  if(!this.select) return false;
  this.select = null;
  this.painted = -1;                       // the highlight has to come off
  return true;
};
TermScreen.prototype.selected = function(){
  if(!this.select || !this.term) return "";
  const from = this.select.from, to = this.select.to;
  if(from.row === to.row && from.col === to.col) return "";
  return this.term.range({row:from.row, col:from.col},
                         {row:to.row, col:to.col}).text;
};

// ---- one shell session -----------------------------------------------------
// Both pages drive a session through this. It owns the terminal, the screen it
// is drawn on, the reading loop and the sid; the page owns the chrome around it
// and says what to do when it opens or closes.
//
// The read is a *held* request: the console answers the moment the pty produces
// bytes, and the loop asks again straight away. So an idle shell costs one
// parked request rather than a question several times a second, and what a
// person sees after a keystroke costs one round trip instead of one round trip
// plus half a polling interval.
const SHELL_RETRY = 700;        // after a failed read, before trying again
const SHELL_MISSES = 20;        // …and how many in a row before giving up

function ShellSession(box, handlers){
  this.box = box;
  this.on = handlers || {};
  this.node = null; this.sid = null; this.off = 0; this.term = null;
  this.size = {cols:80, rows:24};
  this.screen = new TermScreen(box);
  this.reading = false; this.stopped = true; this.retry = null;
  this.pending = ""; this.sending = null; this.frame = null;
  this.decoder = null; this.lastCell = null; this.misses = 0;
  this.dragging = false;
  this.bind();
}
ShellSession.prototype.say = function(text){
  this.screen.mirror.textContent = text;
  const ctx = this.screen.ctx;
  ctx.fillStyle = T_DEF_BG;
  ctx.fillRect(0, 0, this.screen.canvas.width, this.screen.canvas.height);
  ctx.fillStyle = T_DEF_FG;
  ctx.font = this.screen.font(null);
  ctx.fillText(text, 0, this.screen.lh);
};
ShellSession.prototype.newTerm = function(){
  const fit = this.screen.measure();
  this.size = {cols:fit.cols, rows:fit.rows};
  this.term = new Term(fit.cols, fit.rows);
  // A program that asks the terminal a question waits for the answer, so the
  // reply goes back up the same pipe the keystrokes do.
  this.term.onReply = (text) => { this.send(text); };
  this.decoder = new TextDecoder();
  this.screen.attach(this.term);
  this.paint(true);
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
    if(!this.term) this.newTerm();
    // Streaming: a multi-byte character split across two reads has to survive
    // the join, or a box-drawing screen fills with replacement glyphs.
    let text;
    try{ text = this.decoder.decode(t_bytes(data.data), {stream:true}); }
    catch(_){ text = ""; }
    this.term.write(text);
    this.paint();
  }
  this.off = data.seq;
  if(!data.open){
    this.paint(false, true);
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
// Repaints are coalesced to one a frame, by the browser's own clock: a program
// redrawing a whole screen sends it in several chunks, and painting each one is
// the same picture three times — out of step with the display on top of it.
ShellSession.prototype.paint = function(now, closed){
  if(closed){
    if(this.frame){ cancelAnimationFrame(this.frame); this.frame = null; }
    this.screen.draw(false);
    this.say_closed();
    return;
  }
  if(now){ this.draw(); return; }
  if(this.frame) return;
  this.frame = requestAnimationFrame(() => { this.frame = null; this.draw(); });
};
ShellSession.prototype.draw = function(){
  if(!this.term) return;
  this.screen.draw(true);
  this.box.classList.toggle("t-mouse", !!this.term.mouse);
};
ShellSession.prototype.say_closed = function(){
  const screen = this.screen, ctx = screen.ctx;
  ctx.fillStyle = T_DEF_FG;
  ctx.font = screen.font(null);
  ctx.fillText("[session closed]", 0,
               Math.min(screen.rows, screen.term ? screen.term.y + 2 : 1) * screen.lh);
};
// Keystrokes are queued, never fired in parallel. One request per key looks
// fine and is not: two POSTs in flight reach a threaded server in whichever
// order they finish, so typing quickly delivers `panle` instead of `panel`.
// Draining a buffer keeps the order and coalesces a burst into one request.
ShellSession.prototype.send = function(text){
  if(!this.sid || !text) return Promise.resolve();
  this.pending += text;
  if(!this.sending){
    // One turn of the event loop before the first send: two keys pressed in the
    // same tick — a paste, a key repeat — then cost one request rather than
    // two, and nothing waits on a timer for it.
    this.sending = Promise.resolve().then(() => this.drain());
  }
  return this.sending;
};
ShellSession.prototype.drain = async function(){
  try{
    while(this.pending && this.sid){
      const text = this.pending;
      this.pending = "";
      try{
        await api("/api/fleet/input", "POST",
                  {node:this.node, sid:this.sid, data:t_b64(text)});
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
  const fit = this.screen.measure();
  if(fit.cols === this.size.cols && fit.rows === this.size.rows){
    this.paint(true);
    return;
  }
  this.size = {cols:fit.cols, rows:fit.rows};
  this.term.resize(fit.cols, fit.rows);
  this.screen.toBottom();
  this.paint(true);
  if(!this.sid) return;
  try{
    await api("/api/fleet/resize", "POST",
              {node:this.node, sid:this.sid, cols:fit.cols, rows:fit.rows});
  }catch(_){}
};
// A program that turned mouse reporting on is *waiting* for these: without them
// a pointer does nothing in `btop`, `htop` or `less`, and a click that does
// nothing reads as a broken terminal rather than a missing feature.
ShellSession.prototype.mouse = function(event, kind){
  const term = this.term;
  if(!term || !term.mouse || !this.sid) return false;
  const at = this.screen.pointAt(event);
  const row = at.screenRow + 1, col = Math.max(1, at.col);
  if(row < 1 || row > term.rows) return false;
  let button;
  if(kind === "wheel") button = event.deltaY < 0 ? 64 : 65;
  else button = event.button === 1 ? 1 : (event.button === 2 ? 2 : 0);
  if(kind === "move"){
    if(term.mouse < 1002) return false;
    if(term.mouse === 1002 && event.buttons === 0) return false;
    const key = col + ":" + row;
    if(this.lastCell === key) return true;      // one report per cell, not per pixel
    this.lastCell = key;
    button = (event.buttons === 0 ? 3 : button) + 32;
  }
  if(event.shiftKey) button += 4;
  if(event.altKey) button += 8;
  if(event.ctrlKey) button += 16;
  const report = term.mouseReport(button, col, row,
                                  kind === "up" && term.mouseSgr);
  if(report === null) return false;
  if(kind === "up" && !term.mouseSgr){
    this.send(term.mouseReport(3, col, row, false));
    return true;
  }
  this.send(report);
  return true;
};
// Selection and scrollback, for when no program asked for the pointer. Both are
// the screen's, not the browser's — there is no text in the DOM to select.
ShellSession.prototype.bind = function(){
  const box = this.box;
  box.addEventListener("mousedown", (event) => {
    if(this.mouse(event, "down")){ event.preventDefault(); return; }
    if(event.button !== 0) return;
    this.dragging = true;
    this.screen.beginSelect(event);
    this.screen.painted = -1;
    this.paint(true);
    event.preventDefault();
  });
  box.addEventListener("mousemove", (event) => {
    if(this.dragging){
      if(this.screen.extendSelect(event)){ this.screen.painted = -1; this.paint(); }
      return;
    }
    this.mouse(event, "move");
  });
  window.addEventListener("mouseup", (event) => {
    if(this.dragging){ this.dragging = false; this.screen.extendSelect(event); this.paint(true); return; }
    this.mouse(event, "up");
  });
  box.addEventListener("wheel", (event) => {
    if(this.mouse(event, "wheel")){ event.preventDefault(); return; }
    if(!this.term) return;
    const lines = event.deltaMode === 1 ? event.deltaY : event.deltaY / this.screen.lh;
    if(this.screen.scrollBy(Math.round(lines) || (event.deltaY > 0 ? 1 : -1))){
      this.paint(true);
      event.preventDefault();
    }
  }, {passive:false});
  box.addEventListener("focus", () => { this.screen.focused = true; this.paint(true); });
  box.addEventListener("blur", () => { this.screen.focused = false; this.paint(true); });
  box.addEventListener("contextmenu", (event) => {
    if(this.term && this.term.mouse) event.preventDefault();
  });
};
ShellSession.prototype.halt = function(){
  this.stopped = true;
  if(this.retry){ clearTimeout(this.retry); this.retry = null; }
  if(this.frame){ cancelAnimationFrame(this.frame); this.frame = null; }
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
  const picked = this.screen.selected();
  return picked || (this.term ? this.term.text() : "");
};
// Bracketed paste: a program that asked for it wants to know the text arrived
// as a paste rather than as typing — which is what stops an editor
// auto-indenting every line of it.
ShellSession.prototype.paste = function(text){
  if(!text) return Promise.resolve();
  if(this.term && this.term.bracketed) text = "\x1b[200~" + text + "\x1b[201~";
  return this.send(text);
};

// base64 both ways, without a callback per byte. `atob` and `btoa` are the only
// pair in the platform that does this, and a screen `btop` draws is tens of
// kilobytes several times a second — a per-character closure there is real time.
function t_bytes(encoded){
  const raw = atob(encoded);
  const out = new Uint8Array(raw.length);
  for(let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
  return out;
}
function t_b64(text){
  const bytes = new TextEncoder().encode(text);
  let binary = "";
  for(let i = 0; i < bytes.length; i += 8192){
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + 8192));
  }
  return btoa(binary);
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

  <div id="term" class="term full" tabindex="0" role="application"
       aria-label="Remote shell"></div>

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
     TERM_SESSION.screen.selected()) return;             // let a copy through
  if((event.ctrlKey || event.metaKey) && ["v", "V"].includes(event.key)) return;
  // Shift with a page key scrolls the scrollback rather than reaching the pty —
  // the convention every terminal uses, and the only way back up now that the
  // screen is drawn rather than laid out.
  if(event.shiftKey && (event.key === "PageUp" || event.key === "PageDown")){
    if(TERM_SESSION.screen.scrollBy(
        (event.key === "PageUp" ? -1 : 1) * (TERM_SESSION.screen.rows - 1))){
      TERM_SESSION.paint(true);
    }
    event.preventDefault();
    return;
  }
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
// The pointer, the wheel and the selection belong to the session: it owns the
// screen they act on, and there is no text in the DOM for a browser to select.
$("term").addEventListener("copy", (event) => {
  if(!TERM_SESSION) return;
  const picked = TERM_SESSION.screen.selected();
  if(!picked) return;
  event.preventDefault();
  event.clipboardData.setData("text/plain", picked);
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
  if(TERM_SESSION && TERM_SESSION.screen.selected()) return;  // a selection is not a tap
  if(TERM_SESSION && TERM_SESSION.live()) focusInput();
});
$("kbd").addEventListener("click", () => {
  const wanted = $("kbd").getAttribute("aria-pressed") !== "true";
  $("kbd").setAttribute("aria-pressed", wanted ? "true" : "false");
  if(wanted) focusInput(); else $("tin").blur();
});

// ---- clipboard --------------------------------------------------------------

$("copy").addEventListener("click", async () => {
  const text = TERM_SESSION ? TERM_SESSION.copyText() : "";
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
  TERM_SESSION.say("Press Open to start a shell on that node.");
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
      TERM_SESSION.say("Press Open to start a shell on that node.");
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
