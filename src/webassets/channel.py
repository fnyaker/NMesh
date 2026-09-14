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

  // Consecutive answers from the node being managed that never arrived. A
  // single one is a mesh hop having a bad moment; a run of them is a machine
  // that has gone, and a page that keeps asking it forever looks alive and
  // shows nothing — which is what left people reloading the console by hand.
  //
  // Two, not more: each of these costs the relay's full ceiling (25 s) before
  // it comes back, so the count is also a stopwatch. The strip says "not
  // answering" from the first one, which is the half an operator reads.
  MISSES: 2,
  misses: 0,

  // What a refusal from *over there* means for the context we are in.
  //   unauthorized — that node dropped our session; nothing here will work
  //   conflict     — there is no session to that node any more (or no fleet
  //                  app to carry one), which is the same dead end
  //   unavailable  — it did not answer *this time*; said in the strip, and
  //                  handed back only after `MISSES` in a row
  judge(reply){
    if(!CONTEXT.node) return;
    if(reply.ok){ this.misses = 0; CONTEXT.trouble(false); return; }
    if(reply.code === "unauthorized" || reply.code === "conflict"){
      this.misses = 0;
      CONTEXT.lost(reply.error || "");
      return;
    }
    if(reply.code !== "unavailable"){ CONTEXT.trouble(false); return; }
    this.misses += 1;
    if(this.misses >= this.MISSES){
      this.misses = 0;
      CONTEXT.lost(reply.error || "");
    }else CONTEXT.trouble(true, reply.error || "");
  },

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
    let response;
    try{
      response = await fetch(CONTROL_PATH, {method:"POST", headers,
        body: JSON.stringify({v:1, id:String(this.seq), op, params: params || {}})});
    }catch(error){
      // Checked here as well as below, and for the failure rather than the
      // answer: a call to the node we have just left can sit on the relay for
      // its full ceiling and then fail, long after the operator is somewhere
      // else. Painting that as the current node's trouble is what used to say
      // "Console unreachable" about a console that was answering (`ui.js`,
      // `api`, same fix).
      if(!here && CONTEXT.epoch !== at) throw new StaleContext();
      throw error;
    }
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
    if(!here) this.judge(reply);
    return reply;
  },

  // The answer, or a throw. What almost every caller wants.
  //
  // A node the operator is managing refuses anything that takes longer than
  // one call across the mesh — installing a release is four hundred seconds
  // and the relay holds twenty — and says so with a shape rather than only a
  // sentence: `detail.background`. That is not a refusal to show anybody; it
  // is the node saying "ask me for this as a job", so the ask is made here,
  // once, and no page ever had to learn there is such a thing as a job.
  async call(op, params, options){
    const reply = await this.frame(op, params, options);
    if(reply.ok) return reply.result || {};
    if(reply.detail && reply.detail.background && !String(op).startsWith("jobs."))
      return this.run(op, params, options);
    throw new Refused(reply);
  },

  // ---- a long operation, watched instead of waited on ----------------------
  // The node runs it; this asks what became of it. Two seconds is the cadence
  // a four-minute install deserves — often enough that a page finishing feels
  // immediate, rare enough that a mesh hop is not carrying a question a second
  // for the whole of it.
  JOB_EVERY: 2000,
  // Longer than the longest ceiling any operation declares (400 s), plus the
  // node's own grace, plus room for a slow relay. Past it the job is still the
  // node's — `jobs.list` will still show it — but this page stops asking, so a
  // button cannot spin for ever on something that will never come back.
  JOB_FOR: 600000,

  async run(op, params, options){
    const started = await this.call("jobs.start", {op, params: params || {}},
                                    options);
    const ticket = started.job;
    if(!ticket) throw new Refused({code:"failed", error:"that node started no job"});
    const until = Date.now() + this.JOB_FOR;
    for(;;){
      await new Promise((wake) => setTimeout(wake, this.JOB_EVERY));
      // `call` throws `StaleContext` when the node being driven has changed,
      // which is what stops a poll outliving the context that started it.
      const state = await this.call("jobs.poll", {job: ticket}, options);
      if(state.state === "done") return state.result || {};
      if(state.state !== "running"){
        throw new Refused({code: state.code || "failed", detail: state.detail,
                           error: state.error || (op + " did not finish")});
      }
      if(Date.now() > until){
        throw new Refused({code:"unavailable", error:
          "that node is still working on it — it is listed under its jobs"});
      }
    }
  },

  // ---- bytes ---------------------------------------------------------------
  // A file is a question and an answer, asked more than once. There is no
  // second door for it: a download used to be an `<a href download>`, which is
  // a browser *navigation* and cannot carry the header saying which node is
  // being driven — so it always fetched from the machine serving the page,
  // silently, whichever machine the operator thought they were looking at. And
  // an upload could not have gone the other way at all, because the relay caps
  // a request at 24 kB. Both go through here now, a chunk per frame, so bytes
  // follow the context exactly like every other call.

  // Base64 both ways, in pieces: `String.fromCharCode(...bytes)` on a four
  // megabyte array is an argument list a browser refuses (`RangeError`), and
  // the refusal only shows up on somebody's big file.
  encode(bytes){
    let text = "";
    for(let at = 0; at < bytes.length; at += 8192)
      text += String.fromCharCode.apply(null, bytes.subarray(at, at + 8192));
    return btoa(text);
  },
  decode(text){
    const raw = atob(text || "");
    const out = new Uint8Array(raw.length);
    for(let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
    return out;
  },

  // `files` is `[{path, bytes}]`. Answers whatever committing the kind gives
  // back — publishing an app answers its id, like the route it replaces.
  async upload(kind, meta, files, onProgress){
    const started = await this.call("transfer.offer", {kind, meta: meta || {}});
    const id = started.transfer, chunk = started.chunk || 12288;
    const total = files.reduce((sum, file) => sum + file.bytes.length, 0);
    let sent = 0;
    try{
      for(const file of files){
        // A file with no bytes still has to exist on the far side, so it is
        // sent as one empty chunk rather than skipped.
        const pieces = Math.max(1, Math.ceil(file.bytes.length / chunk));
        for(let seq = 0; seq < pieces; seq++){
          const slice = file.bytes.subarray(seq * chunk, (seq + 1) * chunk);
          await this.call("transfer.put", {transfer:id, path:file.path,
                                           seq, data:this.encode(slice)});
          sent += slice.length;
          if(onProgress) onProgress(sent, total);
        }
      }
      return await this.call("transfer.commit", {transfer:id});
    }catch(error){
      // A transfer nobody finishes is dropped on its own after a few minutes;
      // saying so now gives the node its memory back at the moment we know we
      // are not coming back for it.
      if(!isStale(error))
        try{ await this.call("transfer.drop", {transfer:id}); }catch(_){}
      throw error;
    }
  },

  // Answers `{meta, files:[{path, bytes}]}` — the bytes of whatever the kind
  // names, off whichever node this channel is pointed at.
  async download(kind, id, onProgress){
    const opened = await this.call("transfer.fetch", {kind, id});
    const chunk = opened.chunk || 196608;
    const total = (opened.files || []).reduce((sum, f) => sum + f.size, 0);
    const out = [];
    let got = 0;
    try{
      for(const file of opened.files || []){
        const pieces = Math.max(1, Math.ceil(file.size / chunk));
        const parts = [];
        for(let seq = 0; seq < pieces; seq++){
          const piece = await this.call("transfer.take",
            {transfer:opened.transfer, path:file.path, seq});
          const bytes = this.decode(piece.data);
          parts.push(bytes);
          got += bytes.length;
          if(onProgress) onProgress(got, total);
          if(piece.last) break;
        }
        const whole = new Uint8Array(parts.reduce((sum, p) => sum + p.length, 0));
        let at = 0;
        parts.forEach((part) => { whole.set(part, at); at += part.length; });
        out.push({path:file.path, bytes:whole});
      }
    }finally{
      try{ await this.call("transfer.drop", {transfer:opened.transfer}); }catch(_){}
    }
    return {meta: opened.meta || {}, files: out};
  },

  // The answer *and* whether it was refused, for a caller that paints the
  // refusal in place rather than as a toast. Through `call`, so a long
  // operation is a long answer here too rather than a refusal nobody asked for.
  async ask(op, params, options){
    try{
      return {ok:true, code:"", error:"", detail:{},
              data: await this.call(op, params, options)};
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

  // What a node offers is that node's answer. Registered here rather than
  // reset by whoever switches, so the module that holds it is the module that
  // drops it.
  forget(){ this.catalogue = null; this.catalogueAt = -1; this.misses = 0; },

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

CONTEXT.subscribe(() => CHANNEL.forget());

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
