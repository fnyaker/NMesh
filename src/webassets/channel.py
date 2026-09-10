"""
The browser's half of the control channel.

Mirrors :mod:`src.control`: one frame, one route, and the node being driven is a
*target* rather than a different set of paths. A page asks for an operation —
``CHANNEL.call("node.state")`` — and whether that reaches the machine serving
the page or the machine it is managing is settled below, once, instead of in
every view.

What this replaces, and why it is worth a module of its own:

* **A path per action.** ``apiJson("/api/pseudo?q=…&wide=1")`` encoded the
  question, its arguments and its cost in a string, and every caller had to get
  all three right. ``CHANNEL.call("pseudo.search", {query})`` names one of them
  and the node declares the rest.
* **A status code per outcome.** A refusal now arrives as a *code* from a closed
  set, so a page can tell "this node will not do that" (``refused``) from "the
  node did not answer" (``unavailable``) from "you are not signed in"
  (``unauthorized``) without reading English.
* **A remote console that could not be told anything.** The relay carries one
  bounded request and its answer, so a page driving another node had no change
  stream and fell back to a blind timer. ``control.changes`` is the same
  question over any channel, and :data:`CHANGES` below asks it on the cadence
  when the stream is not available.
* **Somebody else's 401 read as ours.** A managed node dropping our session
  used to come back as an HTTP 401, which every client here reads as *this*
  console signing us out. The status now describes the console we asked and the
  frame describes the node we asked about, so the two are no longer confusable.

The old ``api()`` is still there for the routes that have not moved onto the
plane (uploads, the app store, chat, fleet) — ``Docs/Architecture/control-plane.md``
keeps the ledger of what is where.
"""
from __future__ import annotations

JS = r"""
// ---- the control channel ---------------------------------------------------
// One route, one frame, and `CONTEXT.node` decides which node answers it. See
// `src/control/` for the other end and `Docs/Architecture/control-plane.md`
// for why the management plane is a channel rather than a routing table.
const CONTROL_PATH = "/api/control";

// A refusal, with the node's own sentence and the code that says what kind it
// was. Thrown rather than returned: a caller that only wants the answer should
// not have to check a flag first, and the ones that do care ask `isRefused`.
class Refused extends Error {
  constructor(reply){
    super((reply && reply.error) || "refused");
    this.code = (reply && reply.code) || "failed";
    this.detail = (reply && reply.detail) || {};
    this.refused = true;
  }
}
const isRefused = (error) => !!(error && error.refused);

const CHANNEL = {
  // Correlation ids. The plane echoes one back untouched, which is what lets a
  // page with three panels open match answers to questions; nothing on the
  // node reads it, so a counter is enough.
  seq: 0,

  // `options.local` forces one call to this node whatever is being driven. A
  // view mounted inside a local app needs it: "what is my link to this person"
  // is *this* node's question, and answering it from the machine being managed
  // would be a different question with the same wording.
  async frame(op, params, options){
    const opts = options || {};
    const at = CONTEXT.epoch;
    const here = !!opts.local;
    const headers = {"Content-Type": "application/json"};
    if(TOKEN) headers.Authorization = "Bearer " + TOKEN;
    if(CONTEXT.node && !here) headers["X-NMesh-Node"] = CONTEXT.node;
    this.seq = (this.seq + 1) % 100000;
    const response = await fetch(CONTROL_PATH, {method:"POST", headers,
      body: JSON.stringify({v:1, id:String(this.seq), op, params: params || {}})});
    // An HTTP 401 is this console's own session, and only ever that: a managed
    // node's refusal comes back as a 200 carrying `unauthorized`.
    if(response.status === 401 && !CONTEXT.node){
      SESSION.clear(); SESSION.onLost(); throw new Error("unauthorized");
    }
    let reply = null;
    try{ reply = await response.json(); }catch(_){ reply = null; }
    if(!reply || typeof reply !== "object"){
      throw new Refused({code:"failed", error:"the console answered with nothing"});
    }
    // A reply belongs to the node that was being driven when it was asked for,
    // and must not paint over the one that replaced it.
    if(!here && CONTEXT.epoch !== at) throw new StaleContext();
    return reply;
  },

  // The answer, or a throw. What almost every caller wants.
  async call(op, params, options){
    const reply = await this.frame(op, params, options);
    if(!reply.ok) throw new Refused(reply);
    return reply.result || {};
  },

  // The answer *and* whether it was refused, for a caller that paints the
  // refusal in place rather than as a toast.
  async ask(op, params, options){
    try{
      const reply = await this.frame(op, params, options);
      return {ok: !!reply.ok, code: reply.code || "", error: reply.error || "",
              detail: reply.detail || {}, data: reply.result || {}};
    }catch(error){
      if(isStale(error)) throw error;
      if(isRefused(error)) return {ok:false, code:error.code, error:error.message,
                                   detail:error.detail, data:{}};
      throw error;
    }
  },

  // ---- what the node being driven can actually do --------------------------
  // Read once per context and kept, so a page can hide what the far node does
  // not expose instead of offering it and failing on the press. Cheap: one
  // call, and a switch of context throws it away.
  catalogue: null,
  catalogueAt: -1,

  async operations(){
    if(this.catalogue && this.catalogueAt === CONTEXT.epoch) return this.catalogue;
    try{
      const data = await this.call("control.catalogue");
      const out = {};
      (data.modules || []).forEach((entry) => { out[entry.module] = entry.operations; });
      this.catalogue = out;
      this.catalogueAt = CONTEXT.epoch;
    }catch(_){ this.catalogue = {}; this.catalogueAt = CONTEXT.epoch; }
    return this.catalogue;
  },

  // Synchronous, on what `operations()` last read: a paint cannot await.
  has(op){
    if(!this.catalogue) return true;   // nothing read yet — do not hide anything
    const [module, name] = String(op).split(".");
    return (this.catalogue[module] || []).some((entry) => entry.name === name);
  },
};

// ---- change topics, when there is no stream to listen to -------------------
// `EVENTS` holds a `text/event-stream` open, which only the console serving the
// page can do. Driving another node, the same information is one bounded
// question — so it is asked on a cadence rather than not at all, and the page
// repaints on what moved instead of on a timer that hopes.
const CHANGES = {
  EVERY: 2000,
  timer: null,
  seq: 0,

  start(){
    this.stop();
    if(!CONTEXT.remote) return;      // the stream is live here; nothing to poll
    this.seq = 0;
    const tick = async () => {
      this.timer = null;
      try{
        const data = await this.call();
        if(data && data.topics && data.topics.length){
          data.topics.forEach((topic) => EVENTS.pending.add(topic));
          EVENTS.schedule();
        }
      }catch(_){}
      if(CONTEXT.remote) this.timer = setTimeout(tick, this.EVERY);
    };
    this.timer = setTimeout(tick, this.EVERY);
  },

  async call(){
    const data = await CHANNEL.call("control.changes", {since:this.seq});
    if(data && typeof data.seq === "number") this.seq = data.seq;
    return data;
  },

  stop(){
    if(this.timer){ clearTimeout(this.timer); this.timer = null; }
  },
};
"""
