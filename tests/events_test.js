// The console's change stream, driven without a browser.
//
// Held here: a stream that came back (a restart, a network blip) repaints
// everything, because what moved while it was down was told to nobody; and a
// stream the browser gave up on (a 503 when too many are open, a 401) is opened
// again rather than leaving the page on its timer for the rest of the session.
const src = require('fs').readFileSync(process.argv[2], 'utf8');

let fails = 0;
function check(name, ok, detail){
  if(!ok){ fails++; console.log("FAIL", name, detail === undefined ? "" : JSON.stringify(detail)); }
  else console.log("ok  ", name);
}

let timers = [];
global.setTimeout = (fn, ms) => { const t = {fn, ms, live:true}; timers.push(t); return t; };
global.clearTimeout = (t) => { if(t) t.live = false; };
function fire(){
  const due = timers.filter((t) => t.live);
  timers = [];
  due.forEach((t) => { t.live = false; t.fn(); });
}
const sources = [];
global.EventSource = class {
  constructor(url){ this.url = url; this.readyState = 0; this.on = {}; sources.push(this); }
  addEventListener(name, fn){ this.on[name] = fn; }
  close(){ this.readyState = 2; this.closed = true; }
  emit(name, data){ this.on[name]({data: JSON.stringify(data || {})}); }
};
global.CONTEXT = {remote:false};
global.CHANGES = {start(){}, stop(){}};
global.FEED = {agrees(){ return true; }};
let runs = 0;
global.REFRESH = {run(){ runs++; }};
eval(src + "\n;globalThis.EVENTS = EVENTS;");

const painted = [];
EVENTS.on(["links", "nodes"], (topics) => painted.push(topics.slice().sort().join()));
EVENTS.on("names", () => painted.push("names"));

EVENTS.start();
let s = sources[0];
s.emit("ready", {build:"x"});
fire();
check("a first ready repaints nothing on its own", painted.length === 0 && runs === 0,
      {painted, runs});

// A network blip: the browser reconnects by itself (readyState stays 0).
s.readyState = 0; s.on.error();
check("a reconnecting stream is not reopened by hand",
      timers.filter((t) => t.live).length === 0 && sources.length === 1);
s.emit("ready", {build:"x"});
fire();
check("coming back repaints every view once", painted.length === 2, painted);
check("…and re-reads the moving numbers", runs === 1, runs);

// A refusal: the browser closes the stream for good.
s.readyState = 2; s.on.error();
const reopen = timers.filter((t) => t.live);
check("a stream the browser gave up on is reopened later",
      reopen.length === 1 && reopen[0].ms >= 2500, reopen.map((t) => t.ms));
fire();
check("…as a new stream", sources.length === 2 && sources[1].url === "/api/events");
s = sources[1];
s.readyState = 2; s.on.error();
const second = timers.filter((t) => t.live)[0];
check("…waiting longer each time it is refused", second.ms > reopen[0].ms,
      [reopen[0].ms, second.ms]);
s.emit("ready", {build:"x"});
check("a stream that answers resets the wait", EVENTS.retry === 0, EVENTS.retry);
EVENTS.stop();
check("stopping cancels a pending reopen", !second.live);

if(fails){ console.log(fails + " failed"); process.exit(1); }
