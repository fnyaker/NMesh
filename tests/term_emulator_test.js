// Feed the emulator the exact bytes a real bash session produced, and check the
// screen reads back the way a human would see it.
global.escHtml = null;
const src = require('fs').readFileSync(process.argv[2], 'utf8');
eval(src);

function screen(t){ return t.render(false).split("\n").map(l=>l.replace(/<[^>]*>/g,"")); }

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
check("prompt stays put", screen(t)[0], "password:");   // fin d'espace coupée à l'affichage

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
check("colour becomes a class", /t-c1/.test(t.render()), true);

t = new Term(40, 5);
t.write("\x1b]0;a window title\x07shown");
check("OSC title swallowed", screen(t)[0], "shown");

t = new Term(40, 5);
t.write("a\x1b[");                 // escape split across two chunks
t.write("31mb");
check("split escape rejoined", screen(t)[0], "ab");

t = new Term(40, 5);
t.write("\x1b[?2004hprompt$ ");    // bracketed paste, as bash sends
check("bracketed paste mode hidden", screen(t)[0], "prompt$");

t = new Term(6, 3);
t.write("abcdefghij");             // wrap at the right margin
check("wraps at the margin", screen(t)[0]+"|"+screen(t)[1], "abcdef|ghij");

t = new Term(10, 2);
t.write("one\r\ntwo\r\nthree");    // scrolls, keeps scrollback
check("scrolls", screen(t).slice(-2).join("|"), "two|three");

t = new Term(40, 3);
t.write("<script>alert(1)</script>");
check("html is escaped", /&lt;script&gt;/.test(t.render()), true);
check("no raw tag", /<script>/.test(t.render()), false);

t = new Term(20, 2);
t.write("ab");
check("cursor is drawn", /t-cur/.test(t.render()), true);
check("cursor can be hidden", /t-cur/.test(t.render(false)), false);

process.exit(fails ? 1 : 0);
