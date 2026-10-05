// The control channel's two loops, driven without a browser.
//
// What is held here is what broke for somebody driving another node: a poll
// that outlived the `stop()` meant to end it and ran twice, then three times;
// a node restarting (an update ends in that) whose changes were answered with
// "nothing moved"; and one link being rebuilt throwing the operator off a node
// that was back seconds later.
const src = require('fs').readFileSync(process.argv[2], 'utf8');

let fails = 0;
function check(name, ok, detail){
  if(!ok){ fails++; console.log("FAIL", name, detail === undefined ? "" : JSON.stringify(detail)); }
  else console.log("ok  ", name);
}

// ---- just enough of the page for channel.js to load and run ---------------
let NOW = 1000000;
const realNow = Date.now;
Date.now = () => NOW;
let timers = [];
global.setTimeout = (fn, ms) => { const t = {fn, ms, live:true}; timers.push(t); return t; };
global.clearTimeout = (t) => { if(t) t.live = false; };
const lost = [];
global.CONTEXT = {node:"ab".repeat(20), remote:true, epoch:1, listeners:[],
  subscribe(fn){ this.listeners.push(fn); },
  trouble(){}, lost(reason){ lost.push(reason); }};
global.EVENTS = {pending:new Set(), scheduled:0, schedule(){ this.scheduled++; }};
global.TOKEN = "";
global.SESSION = {clear(){}, onLost(){}};
global.StaleContext = class extends Error {};
global.isStale = (e) => e instanceof StaleContext;
// `const` inside an eval stays inside it; the two objects under test are
// handed out explicitly.
eval(src + "\n;globalThis.CHANNEL = CHANNEL; globalThis.CHANGES = CHANGES;");

async function settle(){ for(let i = 0; i < 10; i++) await Promise.resolve(); }
async function fire(){
  const due = timers.filter((t) => t.live);
  timers = [];
  due.forEach((t) => { t.live = false; t.fn(); });
  await settle();
}

(async () => {
  // ---- one loop, whatever stop/start did while a question was out ---------
  let asked = 0, release = null;
  CHANNEL.call = () => { asked++; return new Promise((r) => { release = r; }); };
  CHANGES.start();
  await fire();                       // the first question goes out…
  check("a question is asked", asked === 1);
  CHANGES.stop(); CHANGES.start();    // …and the page switches meanwhile
  release({seq:1, topics:[]});        // the old question comes back late
  await settle();
  const armed = timers.filter((t) => t.live).length;
  check("a late answer does not re-arm a stopped loop", armed === 1, armed);
  CHANNEL.call = () => { asked++; return Promise.resolve({seq:2, topics:[]}); };
  for(let i = 0; i < 3; i++) await fire();
  check("one question per tick, not one per loop ever started",
        asked === 4, asked);
  CHANGES.stop();

  // ---- a node that restarted is read from the start of its new run --------
  const sinces = [];
  CHANNEL.call = (op, params) => {
    sinces.push(params.since);
    return Promise.resolve(params.since === 0
      ? {seq:3, topics:["links", "names"]} : {seq:3, topics:[]});
  };
  CHANGES.seq = 50;
  const data = await CHANGES.call();
  check("a counter that went backwards is asked again from zero",
        JSON.stringify(sinces) === "[50,0]", sinces);
  check("…and what that run moved reaches the page",
        data.topics.join() === "links,names" && CHANGES.seq === 3, data);

  // ---- a link being rebuilt is not a node that has gone -------------------
  CHANNEL.forget();
  const miss = {ok:false, code:"unavailable", error:"that node did not answer in time"};
  CHANNEL.judge(miss); CHANNEL.judge(miss);
  check("two misses in one second keep the context", lost.length === 0, lost);
  NOW += 30000; CHANNEL.judge(miss);
  check("…and thirty seconds of them still do", lost.length === 0, lost);
  CHANNEL.judge({ok:true});
  NOW += 120000; CHANNEL.judge(miss);
  check("an answer in between starts the clock again", lost.length === 0, lost);
  NOW += CHANNEL.LOST_AFTER; CHANNEL.judge(miss);
  check("a node silent for the whole of LOST_AFTER is handed back",
        lost.length === 1, lost);
  CHANNEL.judge({ok:false, code:"unauthorized", error:"x"});
  check("a refusal still hands it back at once", lost.length === 2, lost);

  Date.now = realNow;
  if(fails){ console.log(fails + " failed"); process.exit(1); }
})();
