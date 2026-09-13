// Feed the emulator the exact bytes a real shell session produced, and check the
// screen reads back the way a human would see it.
//
// Read back from the *model*, not from markup: the screen is drawn on a canvas
// now, so there is no HTML to assert on — and no HTML injection to guard
// against either. What a test can hold here is what the cells say, which is
// also what a copy takes and what a screen reader is given.
const src = require('fs').readFileSync(process.argv[2], 'utf8');
eval(src);

function screen(t){ return t.lines(); }

let fails = 0;
function check(name, got, want){
  const ok = got === want;
  if(!ok){ fails++; console.log("FAIL", name, "\n  got: "+JSON.stringify(got)+"\n  want:"+JSON.stringify(want)); }
  else console.log("ok  ", name);
}

let t = new Term(40, 5);
t.write("hello world");
check("plain text", screen(t)[0], "hello world");

t = new Term(40, 5);
t.write("password: ");            // sudo's prompt, echo off, nothing typed back
check("prompt stays put", screen(t)[0], "password:");   // trailing space trimmed

t = new Term(40, 5);
t.write("abc\b\b\bxyz");          // backspace editing, as readline does
check("backspace edits in place", screen(t)[0], "xyz");

t = new Term(40, 5);
t.write("line one\r\nline two");
check("crlf", screen(t)[1], "line two");

t = new Term(40, 5);
t.write("abcdef\r\x1b[Kzz");      // carriage return + erase to end of line
check("CR + erase line", screen(t)[0], "zz");

t = new Term(40, 5);
t.write("keep\x1b[2J");           // clear screen
check("clear screen", screen(t)[0], "");

t = new Term(40, 5);
t.write("\x1b[31mred\x1b[0m ok");
check("colour is not printed", screen(t)[0], "red ok");
check("colour is on the cell", t.cell(0, 0).s.fg, 1);
check("and it stops where it was reset", t.cell(0, 4).s.fg, null);

t = new Term(40, 5);
t.write("\x1b]0;a window title\x07shown");
check("OSC title swallowed", screen(t)[0], "shown");
check("…and kept", t.title, "a window title");

t = new Term(40, 5);
t.write("a\x1b[");                 // escape split across two chunks
t.write("31mb");
check("split escape rejoined", screen(t)[0], "ab");

t = new Term(40, 5);
t.write("\x1b[?2004hprompt$ ");    // bracketed paste, as bash sends
check("bracketed paste mode hidden", screen(t)[0], "prompt$");
check("…and remembered", t.bracketed, true);

t = new Term(6, 3);
t.write("abcdefghij");             // wrap at the right margin
check("wraps at the margin", screen(t)[0]+"|"+screen(t)[1], "abcdef|ghij");

t = new Term(10, 2);
t.write("one\r\ntwo\r\nthree");    // scrolls, keeps scrollback
check("scrolls", screen(t).slice(-2).join("|"), "two|three");
check("and the line above is kept", screen(t)[0], "one");

t = new Term(40, 3);
t.write("<script>alert(1)</script>");
check("markup is text like anything else", screen(t)[0], "<script>alert(1)</script>");

t = new Term(20, 2);
t.write("ab");
check("the cursor is where the text left it", t.x + ":" + t.y, "2:0");
t.write("\x1b[?25l");
check("a program can hide it", t.cursorVisible, false);

// ---- what a full-screen program does --------------------------------------
// Everything below is a thing `btop`, `htop`, `vim` or `less` does on the way
// in. Each one of them, missing, is a screen of garbage rather than a missing
// feature — so each one is held here.

t = new Term(20, 4);
t.write("shell line\r\n");
t.write("\x1b[?1049h");            // take the alternate screen
t.write("full screen");
check("alt screen is its own grid", screen(t)[0], "full screen");
check("alt screen hides the scrollback", screen(t).length, 4);
t.write("\x1b[?1049l");            // give it back
check("leaving alt restores the shell", screen(t)[0], "shell line");

t = new Term(10, 5);
t.write("\x1b[2;4r");              // a scroll region over rows 2..4
t.write("\x1b[2;1Haaa\r\n bbb\r\nccc\r\nddd");
check("scrolling stays inside the region", screen(t)[0], "");
check("the region scrolled", screen(t).slice(1, 4).join("|"), " bbb|ccc|ddd");

t = new Term(8, 4);
t.write("one\r\ntwo\r\nthree");
t.write("\x1b[1;1H\x1b[L");        // insert a line at the top
check("insert line pushes down", screen(t).slice(0, 2).join("|"), "|one");
t.write("\x1b[1;1H\x1b[M");        // and take it back out
check("delete line pulls up", screen(t)[0], "one");

t = new Term(12, 2);
t.write("abcdef\x1b[1;3H\x1b[2P"); // delete two characters under the cursor
check("delete char closes the gap", screen(t)[0], "abef");
t = new Term(12, 2);
t.write("abcdef\x1b[1;3H\x1b[2@"); // and insert two
check("insert char opens one", screen(t)[0], "ab  cdef");
t = new Term(12, 2);
t.write("abcdef\x1b[1;3H\x1b[2X"); // erase in place, no shifting
check("erase char leaves the rest", screen(t)[0], "ab  ef");

t = new Term(20, 2);
t.write("\x1b[38;5;208morange\x1b[0m");
check("256-colour is a style, not text", screen(t)[0], "orange");
check("256-colour resolves to a colour", t.cell(0, 0).s.front, "#ff8700");
t = new Term(20, 2);
t.write("\x1b[48;2;10;20;30mdeep\x1b[0m");
check("24-bit background", t.cell(0, 0).s.back, "#0a141e");

// Background-colour erase: a program sets a background and erases to paint a
// panel. Without it every painted area comes back the colour of the page.
t = new Term(6, 2);
t.write("\x1b[41m\x1b[2J");
check("erase paints the background", t.cell(0, 0).s.bg, 1);

t = new Term(20, 2);
t.write("\x1b[7minverse\x1b[27m");
check("inverse swaps, it does not print", screen(t)[0], "inverse");
check("…and the swap is resolved once", t.cell(0, 0).s.back, "#cfe0f7");

// Resizing keeps the content: a shell at a prompt is never told the size
// changed and never repaints.
t = new Term(40, 5);
t.write("kept across a resize");
t.resize(60, 8);
check("resize keeps the content", screen(t)[0], "kept across a resize");
check("resize widens the grid", t.grid[0].length, 60);
check("resize deepens the grid", t.grid.length, 8);
t.resize(20, 3);
check("shrinking keeps the cursor line", screen(t).slice(-3)[0].slice(0, 20), "kept across a resize");

// A program that asks the terminal a question waits for the answer. Silence is
// a hang, not a missing feature.
t = new Term(30, 4);
let replies = [];
t.onReply = (text) => replies.push(text);
t.write("\x1b[3;7H\x1b[6n");
check("cursor position is reported", replies[0], "\x1b[3;7R");
t.write("\x1b[18t");
check("the size is reported", replies[1], "\x1b[8;4;30t");
t.write("\x1b[c");
check("it answers a device attribute request", replies[2], "\x1b[?1;2c");

// Mouse reporting: a click that does nothing in `btop` reads as a broken
// terminal, so the modes are tracked and the report is built the way the
// program asked for it.
t = new Term(30, 4);
check("mouse is off until asked for", t.mouse, 0);
t.write("\x1b[?1002h\x1b[?1006h");
check("mouse mode is remembered", t.mouse, 1002);
check("SGR encoding is remembered", t.mouseSgr, true);
check("a press reports in SGR", t.mouseReport(0, 12, 3, false), "\x1b[<0;12;3M");
check("a release reports in SGR", t.mouseReport(0, 12, 3, true), "\x1b[<0;12;3m");
t.write("\x1b[?1006l");
check("without SGR it is the old encoding",
      t.mouseReport(0, 12, 3, false), "\x1b[M" + String.fromCharCode(32, 44, 35));
t.write("\x1b[?1002l");
check("the program can turn it off again", t.mouse, 0);

// The cursor keys have two forms and the program chooses. Sending the wrong one
// is why an arrow key prints a letter inside a full-screen program.
t = new Term(20, 4);
check("arrows are ANSI by default", keyBytes({key:"ArrowUp"}, t), "\x1b[A");
t.write("\x1b[?1h");
check("DECCKM switches them", keyBytes({key:"ArrowUp"}, t), "\x1bOA");
check("control keys are unaffected",
      keyBytes({key:"c", ctrlKey:true}, t), "\x03");
check("a function key has a sequence", keyBytes({key:"F5"}, t), "\x1b[15~");

// Wide characters take two columns. A width that is wrong is a line that drifts
// sideways, which is what a box-drawing screen looks like when it breaks.
t = new Term(10, 2);
t.write("你好!");
check("a wide character takes two cells", t.x, 5);
check("and reads back whole", screen(t)[0], "你好!");
check("its second column is a continuation", t.cell(0, 1).w, 0);

// `ESC ( 0` — the line-drawing set older programs still use.
t = new Term(10, 2);
t.write("\x1b(0qqq\x1b(Bx");
check("line drawing is mapped", screen(t)[0], "───x");

// An unterminated escape must never be printed, and must never grow without
// end either.
t = new Term(20, 2);
t.write("\x1b]0;a title that never ends");
check("an unfinished OSC prints nothing", screen(t)[0], "");
t.write("\x07after");
check("and finishes when the rest arrives", screen(t)[0], "after");

// Autowrap off: the last column holds instead of moving to the next line.
t = new Term(5, 3);
t.write("\x1b[?7labcdefgh");
check("no wrap means no second line", screen(t)[1], "");

// ---- the shape of the parser -----------------------------------------------
// It used to slice the remaining buffer at every escape to run a regex against,
// which on a screen a full-screen program draws — thousands of escapes in one
// chunk — is quadratic in the size of a frame. That is not a thing a unit test
// can assert directly, so it is asserted as time: a frame's worth of escapes
// has to parse in well under the frame it belongs to.
t = new Term(200, 60);
let frame = "";
for(let row = 1; row <= 60; row++){
  frame += "\x1b[" + row + ";1H";
  for(let col = 0; col < 60; col++) frame += "\x1b[38;5;" + (col % 200 + 16) + "m⠿";
}
const started = Date.now();
for(let n = 0; n < 10; n++) t.write(frame);
const elapsed = (Date.now() - started) / 10;
check("a frame parses in well under a frame", elapsed < 60, true);
if(elapsed >= 60) console.log("  (took " + elapsed.toFixed(1) + "ms per frame)");

// The dirty set is what makes a repaint cost the lines that moved. A program
// that wrote one line must not ask for the whole screen back.
t = new Term(80, 24);
t.write("first\r\n");
t.dirty.clear(); t.allDirty = false;
t.write("\x1b[5;1Hjust this line");
// Two: the line that was written, and the one the cursor left — a repaint has
// to take the old cursor off as well as draw the new one.
check("one line written, two lines dirty", t.dirty.size, 2);
check("the one that moved", t.dirty.has(4), true);
check("and the one the cursor left", t.dirty.has(1), true);
check("without claiming the whole screen", t.allDirty, false);
t.write("\x1b[2J");
check("clearing the screen claims all of it", t.allDirty, true);

// What a copy takes, and what a screen reader is given.
t = new Term(20, 3);
t.write("one\r\ntwo\r\nthree");
check("text is the lines joined", t.text(), "one\ntwo\nthree");
check("a range spans rows", t.range({row:0, col:1}, {row:1, col:2}).text, "ne\ntw");

process.exit(fails ? 1 : 0);
