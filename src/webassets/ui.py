"""
The design system: tokens, base, components, app shell, shared runtime.

Three pages share this file so the product looks like one product. The rule is
narrow on purpose: **nothing page-specific lives here, and nothing here is
redefined in a page.** A page that needs a new kind of button adds it here, once,
and every page gets it.

Tokens are in three layers, one-way (primitive → semantic → component), which is
what lets a theme swap be a block of variables rather than a rewrite:

* **primitive** — the raw ramps (``--n-050`` … ``--teal-500``). Never used
  directly by a component.
* **semantic** — what the colour *means* here (``--surface``, ``--text-muted``,
  ``--danger``). This is the layer components speak.
* **component** — the handful of exceptions a component needs for itself
  (``--btn-h``, ``--rail-w``).

Contrast is not a matter of taste: ``tests/test_ui_contrast.py`` computes the
WCAG ratio of every text/background pair in both themes and fails below 4.5.
"""

# ---------------------------------------------------------------------------
# Tokens
# ---------------------------------------------------------------------------
# Light is the default declaration and dark is an override, because a stylesheet
# that only defines a colour inside a media query has no value when the query
# does not match. `data-theme` wins over the media query in both directions, so
# an explicit choice is honoured on a machine set the other way.

TOKENS = """
:root{
  /* -- primitives: neutral ramp (cool, slightly blue — an infra console) -- */
  --n-000:#ffffff; --n-025:#f6f8fa; --n-050:#f1f4f8; --n-100:#e8edf3;
  --n-200:#dfe5ec; --n-300:#87919f; --n-400:#9aa8b8; --n-500:#66727c;
  --n-600:#5b6875; --n-700:#3d4854; --n-800:#222c39; --n-850:#1c2430;
  --n-900:#161d28; --n-950:#111721; --n-975:#0a0e13;
  /* -- primitives: hues -- */
  --teal-100:#eafaf7; --teal-300:#7fcabd; --teal-600:#097061; --teal-700:#065a4d;
  --teal-400:#3fd8c2; --teal-800:#1d5e55; --teal-900:#0f2f2c; --teal-950:#04211c;
  --green-100:#e3f6ec; --green-600:#12764f; --green-400:#4bd48a; --green-900:#0d2c1f;
  --amber-100:#fbeed6; --amber-600:#8a5b00; --amber-400:#f2b755; --amber-900:#33270d;
  --red-100:#fde8e6; --red-600:#b4241c; --red-400:#ff7a70; --red-900:#3a1512;
  --blue-100:#e4ecfd; --blue-600:#1d4ed8; --blue-400:#7fb0ff; --blue-900:#152443;

  /* -- semantic: surfaces -- */
  --canvas:var(--n-025); --surface:var(--n-000); --surface-2:var(--n-050);
  --surface-3:var(--n-100); --rail:var(--n-000); --overlay:rgba(16,24,34,.44);
  --border:var(--n-200); --border-strong:var(--n-300);
  /* -- semantic: text -- */
  --text:#101822; --text-muted:var(--n-600); --text-faint:var(--n-500);
  /* -- semantic: accent and status -- */
  --accent:var(--teal-600); --accent-hover:var(--teal-700); --accent-fg:#ffffff;
  --accent-soft:var(--teal-100); --accent-line:var(--teal-300);
  --ok:var(--green-600); --ok-soft:var(--green-100);
  --warn:var(--amber-600); --warn-soft:var(--amber-100);
  --danger:var(--red-600); --danger-hover:#8f1c15; --danger-soft:var(--red-100);
  --info:var(--blue-600); --info-soft:var(--blue-100);
  /* -- semantic: depth. Two layers: a wide ambient wash and a tight direct
        shadow. One alone reads as either a smudge or a sticker. -- */
  --shadow-1:0 1px 2px rgba(16,24,34,.06), 0 1px 1px rgba(16,24,34,.04);
  --shadow-2:0 4px 12px rgba(16,24,34,.08), 0 2px 4px rgba(16,24,34,.05);
  --shadow-3:0 16px 40px rgba(16,24,34,.16), 0 4px 10px rgba(16,24,34,.08);
  --ring:var(--accent);

  /* -- type -- */
  --font:ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  --mono:ui-monospace,SFMono-Regular,"SF Mono",Menlo,Consolas,"Liberation Mono",monospace;
  --fs-2xs:11px; --fs-xs:12px; --fs-sm:13px; --fs-md:14px; --fs-lg:16px;
  --fs-xl:20px; --fs-2xl:26px; --fs-3xl:32px;
  --lh-tight:1.25; --lh:1.55;

  /* -- space (4px base) -- */
  --s-1:4px; --s-2:8px; --s-3:12px; --s-4:16px; --s-5:20px; --s-6:24px;
  --s-7:32px; --s-8:40px; --s-9:56px;

  /* -- radius: a child's radius never exceeds its parent's -- */
  --r-sm:6px; --r-md:9px; --r-lg:14px; --r-xl:20px; --r-full:999px;

  /* -- component-level -- */
  --rail-w:236px; --topbar-h:56px; --content-max:1180px;
  --ctl-h:36px; --ctl-h-sm:28px; --tap:24px;
  --speed:.16s; --ease:cubic-bezier(.2,.6,.3,1);
}

/* Dark. Not pure black: an OLED-black surface cannot carry a shadow, so depth
   would have to come from borders alone, and white on it haloes for a lot of
   people. */
:root[data-theme="dark"]{ color-scheme:dark; }
:root[data-theme="light"]{ color-scheme:light; }
@media (prefers-color-scheme:dark){ :root:not([data-theme="light"]){ color-scheme:dark; } }

"""

# The dark block is emitted twice — once behind the media query for "follow the
# system", once behind the attribute for "I chose". Written once here so the two
# cannot drift apart.
_DARK_BODY = """
  --canvas:var(--n-975); --surface:var(--n-950); --surface-2:var(--n-900);
  --surface-3:var(--n-850); --rail:#0c1219; --overlay:rgba(3,6,10,.66);
  --border:var(--n-800); --border-strong:#576573;
  --text:#e6edf5; --text-muted:#9aa8b8; --text-faint:#8493a3;
  --accent:var(--teal-400); --accent-hover:#63e3d1; --accent-fg:var(--teal-950);
  --accent-soft:var(--teal-900); --accent-line:var(--teal-800);
  --ok:var(--green-400); --ok-soft:var(--green-900);
  --warn:var(--amber-400); --warn-soft:var(--amber-900);
  --danger:var(--red-400); --danger-hover:#ff9a92; --danger-soft:var(--red-900);
  --info:var(--blue-400); --info-soft:var(--blue-900);
  --shadow-1:0 1px 2px rgba(0,0,0,.4);
  --shadow-2:0 4px 14px rgba(0,0,0,.45), 0 1px 3px rgba(0,0,0,.4);
  --shadow-3:0 20px 50px rgba(0,0,0,.6), 0 6px 14px rgba(0,0,0,.45);
"""

TOKENS += (f"@media (prefers-color-scheme:dark){{:root:not([data-theme=\"light\"])"
           f"{{{_DARK_BODY}}}}}\n"
           f":root[data-theme=\"dark\"]{{{_DARK_BODY}}}\n")


# ---------------------------------------------------------------------------
# Base
# ---------------------------------------------------------------------------

BASE = """
*,*::before,*::after{box-sizing:border-box}
html{-webkit-text-size-adjust:100%;scroll-behavior:smooth}
body{margin:0;background:var(--canvas);color:var(--text);
  font:var(--fs-md)/var(--lh) var(--font);-webkit-font-smoothing:antialiased;
  text-rendering:optimizeLegibility;touch-action:manipulation}
:where(h1,h2,h3,h4,h5,p,figure,blockquote,dl,dd,ul,ol){margin:0;padding:0}
:where(ul,ol){list-style:none}
h1{font-size:var(--fs-2xl);line-height:var(--lh-tight);letter-spacing:-.021em;font-weight:640}
h2{font-size:var(--fs-lg);line-height:var(--lh-tight);letter-spacing:-.012em;font-weight:620}
h3{font-size:var(--fs-md);line-height:var(--lh-tight);font-weight:620}
a{color:var(--accent);text-decoration:none}
a:hover{text-decoration:underline}
img,svg,video,canvas{max-width:100%;height:auto;display:block}
hr{border:0;border-top:1px solid var(--border);margin:var(--s-5) 0}
[hidden]{display:none!important}
.hidden{display:none!important}
.sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;
  clip:rect(0 0 0 0);white-space:nowrap;border:0}
/* Visible only once tabbed to: a keyboard user should not walk the whole rail
   to reach the page they opened. */
.skip{position:absolute;left:var(--s-3);top:-60px;z-index:90;background:var(--surface);
  border:1px solid var(--border-strong);border-radius:var(--r-md);padding:var(--s-2) var(--s-3);
  font-size:var(--fs-sm);font-weight:600;transition:top var(--speed) var(--ease)}
.skip:focus{top:var(--s-3);text-decoration:none}
:where(h1,h2,h3,[id]){scroll-margin-top:calc(var(--topbar-h) + var(--s-4))}

/* One focus treatment for the whole product. Never removed without a
   replacement: a keyboard user who loses the ring is lost on the page. */
:focus-visible{outline:2px solid var(--ring);outline-offset:2px}
:focus:not(:focus-visible){outline:none}
::selection{background:var(--accent-soft);color:var(--text)}

.mono{font-family:var(--mono);font-variant-ligatures:none;font-size:.94em}
.num{font-variant-numeric:tabular-nums}
.muted{color:var(--text-muted)}
.faint{color:var(--text-faint)}
.small{font-size:var(--fs-sm)}
.tiny{font-size:var(--fs-xs)}
.grow{flex:1 1 auto;min-width:0}
.wrap{flex-wrap:wrap}
.nowrap{white-space:nowrap}
.truncate{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;min-width:0}
.eyebrow{font-size:var(--fs-2xs);letter-spacing:.09em;text-transform:uppercase;
  color:var(--text-faint);font-weight:600}
.stack{display:flex;flex-direction:column;gap:var(--s-3);align-items:stretch}
.stack>button,.stack>.btn{align-self:flex-start}
.row{display:flex;align-items:center;gap:var(--s-2)}
.lede{color:var(--text-muted);max-width:68ch}

/* Scrollbars: visible enough to grab, quiet enough to ignore. */
*{scrollbar-width:thin;scrollbar-color:var(--border-strong) transparent}
*::-webkit-scrollbar{width:10px;height:10px}
*::-webkit-scrollbar-thumb{background:var(--border-strong);border-radius:var(--r-full);
  border:3px solid transparent;background-clip:content-box}
*::-webkit-scrollbar-track{background:transparent}

@media (prefers-reduced-motion:reduce){
  *,*::before,*::after{animation-duration:.001ms!important;animation-iteration-count:1!important;
    transition-duration:.001ms!important;scroll-behavior:auto!important}
}
"""


# ---------------------------------------------------------------------------
# Components
# ---------------------------------------------------------------------------
# Styled on the *element* wherever there is one (`button`, `input`, `table`), so
# a control that forgets its class still looks like the product. Classes are for
# variants, not for the baseline.

COMPONENTS = """
/* -- buttons ------------------------------------------------------------- */
button,.btn{
  --btn-bg:var(--surface); --btn-fg:var(--text); --btn-line:var(--border-strong);
  display:inline-flex;align-items:center;justify-content:center;gap:var(--s-2);
  min-height:var(--ctl-h);padding:0 var(--s-3);border-radius:var(--r-md);
  border:1px solid var(--btn-line);background:var(--btn-bg);color:var(--btn-fg);
  font:600 var(--fs-sm)/1 var(--font);cursor:pointer;white-space:nowrap;
  text-decoration:none;position:relative;
  transition:background-color var(--speed) var(--ease),
             border-color var(--speed) var(--ease), color var(--speed) var(--ease),
             transform var(--speed) var(--ease)}
button:hover,.btn:hover{background:var(--surface-2);border-color:var(--text-faint);text-decoration:none}
button:active,.btn:active{transform:translateY(.5px)}
button:disabled,.btn[aria-disabled="true"]{opacity:.5;cursor:not-allowed;transform:none}
button.primary,.btn.primary{--btn-bg:var(--accent);--btn-fg:var(--accent-fg);--btn-line:var(--accent)}
button.primary:hover,.btn.primary:hover{background:var(--accent-hover);border-color:var(--accent-hover)}
button.danger,.btn.danger{--btn-fg:var(--danger);--btn-line:var(--border-strong)}
button.danger:hover,.btn.danger:hover{background:var(--danger-soft);border-color:var(--danger)}
button.danger.solid{--btn-bg:var(--danger);--btn-fg:#fff;--btn-line:var(--danger)}
button.danger.solid:hover{background:var(--danger-hover);border-color:var(--danger-hover)}
button.ghost,.btn.ghost{--btn-bg:transparent;--btn-line:transparent;--btn-fg:var(--text-muted)}
button.ghost:hover,.btn.ghost:hover{background:var(--surface-2);border-color:var(--border);color:var(--text)}
button.sm,.btn.sm{min-height:var(--ctl-h-sm);padding:0 var(--s-2);font-size:var(--fs-xs)}
button.wide,.btn.wide{width:100%}
/* An icon-only control still needs a comfortable target and an accessible name. */
button.icon{padding:0;width:var(--ctl-h);min-height:var(--ctl-h);--btn-bg:transparent;
  --btn-line:transparent;--btn-fg:var(--text-muted);font-size:var(--fs-lg);font-weight:400}
button.icon:hover{background:var(--surface-2);border-color:var(--border);color:var(--text)}
button.icon.sm{width:var(--ctl-h-sm);min-height:var(--ctl-h-sm);font-size:var(--fs-md)}
/* Busy: the label stays put and the spinner takes the icon slot, so the button
   does not resize and the user does not lose what they clicked. */
button[aria-busy="true"]{color:transparent!important;pointer-events:none}
button[aria-busy="true"]::after{content:"";position:absolute;width:14px;height:14px;
  border:2px solid currentColor;border-top-color:transparent;border-radius:50%;
  color:var(--text);animation:nm-spin .7s linear infinite}
button.primary[aria-busy="true"]::after{color:var(--accent-fg)}
@keyframes nm-spin{to{transform:rotate(360deg)}}
.btn-row{display:flex;flex-wrap:wrap;gap:var(--s-2);align-items:center}

/* -- form controls ------------------------------------------------------- */
input,select,textarea{
  width:100%;min-height:var(--ctl-h);padding:var(--s-2) var(--s-3);
  background:var(--surface);color:var(--text);border:1px solid var(--border-strong);
  border-radius:var(--r-md);font:400 var(--fs-md)/1.4 var(--font);
  transition:border-color var(--speed) var(--ease),box-shadow var(--speed) var(--ease)}
textarea{min-height:88px;resize:vertical;line-height:1.5}
input[type="checkbox"],input[type="radio"]{width:16px;height:16px;min-height:0;
  accent-color:var(--accent);margin:0;flex:none}
input[type="file"]{padding:var(--s-1) var(--s-2);font-size:var(--fs-sm)}
input:hover,select:hover,textarea:hover{border-color:var(--text-faint)}
input:focus,select:focus,textarea:focus{outline:none;border-color:var(--accent);
  box-shadow:0 0 0 3px var(--accent-soft)}
input::placeholder,textarea::placeholder{color:var(--text-faint)}
input:disabled,select:disabled,textarea:disabled{background:var(--surface-2);
  color:var(--text-faint);cursor:not-allowed}
select{appearance:none;padding-right:var(--s-6);
  background-image:linear-gradient(45deg,transparent 50%,currentColor 50%),
                   linear-gradient(135deg,currentColor 50%,transparent 50%);
  background-position:right 15px top 50%,right 10px top 50%;
  background-size:5px 5px,5px 5px;background-repeat:no-repeat}
/* iOS zooms the page when a focused input is under 16px. */
@media (max-width:720px){input,select,textarea{font-size:var(--fs-lg)}}

.field{display:flex;flex-direction:column;gap:var(--s-1);min-width:0}
.field>span:not(.hint),.field>label{font-size:var(--fs-sm);font-weight:560;color:var(--text)}
.field .hint{font-size:var(--fs-xs);color:var(--text-muted)}
.field.invalid input,.field.invalid textarea,.field.invalid select{border-color:var(--danger)}
.field .err{font-size:var(--fs-xs);color:var(--danger)}
/* Label and control share one hit target: no dead zone between them. */
.check{display:flex;align-items:flex-start;gap:var(--s-2);min-height:var(--tap);
  padding:var(--s-1) 0;cursor:pointer;font-size:var(--fs-sm)}
.check input{margin-top:2px}
.check.card-like{border:1px solid var(--border);border-radius:var(--r-md);
  padding:var(--s-3);background:var(--surface)}
.check.card-like:has(input:checked){border-color:var(--accent);background:var(--accent-soft)}
.form-grid{display:grid;gap:var(--s-4);grid-template-columns:repeat(auto-fit,minmax(240px,1fr))}
.form-grid.one{grid-template-columns:1fr}

/* -- cards --------------------------------------------------------------- */
.card{background:var(--surface);border:1px solid var(--border);border-radius:var(--r-lg);
  box-shadow:var(--shadow-1);overflow:hidden}
.card>.card-head{display:flex;align-items:center;gap:var(--s-3);flex-wrap:wrap;
  padding:var(--s-4) var(--s-5);border-bottom:1px solid var(--border)}
.card>.card-head>.grow{min-width:120px}
.card-head h2{margin:0}
.card-head .sub{font-size:var(--fs-sm);color:var(--text-muted);margin-top:2px}
.card>.card-body{padding:var(--s-5);display:flex;flex-direction:column;gap:var(--s-4)}
.card>.card-body.tight{padding:0}
.card>.card-foot{padding:var(--s-3) var(--s-5);border-top:1px solid var(--border);
  background:var(--surface-2);display:flex;gap:var(--s-2);align-items:center;flex-wrap:wrap}
.card.quiet{box-shadow:none;background:var(--surface-2)}
.cards{display:grid;gap:var(--s-4);grid-template-columns:repeat(auto-fill,minmax(320px,1fr))}

/* -- disclosure ---------------------------------------------------------- */
details.card>summary{list-style:none;cursor:pointer;padding:var(--s-4) var(--s-5);
  display:flex;align-items:center;gap:var(--s-2);font-weight:620;font-size:var(--fs-md)}
details.card>summary::-webkit-details-marker{display:none}
details.card>summary::before{content:"";width:7px;height:7px;flex:none;
  border-right:1.8px solid var(--text-faint);border-bottom:1.8px solid var(--text-faint);
  transform:rotate(-45deg);transition:transform var(--speed) var(--ease)}
details.card[open]>summary::before{transform:rotate(45deg)}
details.card>summary:hover{background:var(--surface-2)}
details.card[open]>summary{border-bottom:1px solid var(--border)}

/* -- stats --------------------------------------------------------------- */
.stats{display:grid;gap:var(--s-3);grid-template-columns:repeat(auto-fit,minmax(150px,1fr))}
.stat{background:var(--surface);border:1px solid var(--border);border-radius:var(--r-md);
  padding:var(--s-3) var(--s-4);display:flex;flex-direction:column;gap:2px;min-width:0}
.stat .k{font-size:var(--fs-xs);color:var(--text-muted);order:2}
.stat .v{font-size:var(--fs-xl);font-weight:640;letter-spacing:-.02em;
  font-variant-numeric:tabular-nums;line-height:1.15;order:1}
.stat .v small{font-size:var(--fs-sm);font-weight:560;color:var(--text-muted)}
.stat.accent .v{color:var(--accent)}
/* Anything else a stat carries (a meter, a trend) sits under the label. */
.stat>*{order:3}
.stat .meter{margin-top:2px}

/* -- badges, dots, pills ------------------------------------------------- */
.badge{display:inline-flex;align-items:center;gap:6px;padding:2px 8px;border-radius:var(--r-full);
  font-size:var(--fs-xs);font-weight:600;background:var(--surface-2);color:var(--text-muted);
  border:1px solid var(--border);white-space:nowrap;line-height:1.6}
.badge.ok{background:var(--ok-soft);color:var(--ok);border-color:transparent}
.badge.warn{background:var(--warn-soft);color:var(--warn);border-color:transparent}
.badge.danger{background:var(--danger-soft);color:var(--danger);border-color:transparent}
.badge.info{background:var(--info-soft);color:var(--info);border-color:transparent}
.badge.accent{background:var(--accent-soft);color:var(--accent);border-color:transparent}
/* Colour is never the only cue: every status badge also carries its own word. */
.dot{width:7px;height:7px;border-radius:50%;background:var(--text-faint);flex:none}
.dot.ok{background:var(--ok)} .dot.warn{background:var(--warn)}
.dot.danger{background:var(--danger)} .dot.live{background:var(--ok);
  box-shadow:0 0 0 0 var(--ok);animation:nm-pulse 2.4s var(--ease) infinite}
@keyframes nm-pulse{70%{box-shadow:0 0 0 5px transparent}100%{box-shadow:0 0 0 0 transparent}}
.kbd{font:600 var(--fs-2xs)/1 var(--mono);padding:4px 6px;border-radius:var(--r-sm);
  border:1px solid var(--border-strong);background:var(--surface-2);color:var(--text-muted)}

/* -- tabs and segmented -------------------------------------------------- */
.segmented{display:inline-flex;gap:2px;padding:3px;background:var(--surface-2);
  border:1px solid var(--border);border-radius:var(--r-md);overflow-x:auto;max-width:100%}
.segmented button{min-height:var(--ctl-h-sm);border:0;background:transparent;
  color:var(--text-muted);border-radius:var(--r-sm);padding:0 var(--s-3);font-size:var(--fs-sm)}
.segmented button:hover{background:var(--surface-3);color:var(--text)}
.segmented button[aria-selected="true"]{background:var(--surface);color:var(--text);
  box-shadow:var(--shadow-1)}
.subnav{display:flex;gap:var(--s-1);border-bottom:1px solid var(--border);overflow-x:auto}
.subnav button{border:0;background:transparent;border-radius:0;color:var(--text-muted);
  min-height:38px;padding:0 var(--s-3);border-bottom:2px solid transparent;margin-bottom:-1px}
.subnav button:hover{background:transparent;color:var(--text);border-color:var(--border-strong)}
.subnav button[aria-selected="true"]{color:var(--text);border-bottom-color:var(--accent)}

/* -- tables -------------------------------------------------------------- */
.table-wrap{overflow-x:auto;border-radius:var(--r-md)}
table{width:100%;border-collapse:collapse;font-size:var(--fs-sm)}
thead th{position:sticky;top:0;z-index:1;background:var(--surface-2);text-align:left;
  font-size:var(--fs-xs);font-weight:600;color:var(--text-muted);letter-spacing:.03em;
  text-transform:uppercase;padding:var(--s-2) var(--s-4);white-space:nowrap;
  border-bottom:1px solid var(--border)}
tbody td{padding:var(--s-3) var(--s-4);border-bottom:1px solid var(--border);vertical-align:middle}
tbody tr:last-child td{border-bottom:0}
tbody tr:hover{background:var(--surface-2)}
td.num,th.num{text-align:right;font-variant-numeric:tabular-nums}
td.tight{width:1%;white-space:nowrap}
tbody tr[data-clickable]{cursor:pointer}

/* -- key/value lists ----------------------------------------------------- */
.kv{display:grid;grid-template-columns:minmax(120px,auto) 1fr;gap:var(--s-2) var(--s-4);
  font-size:var(--fs-sm);align-items:baseline}
.kv dt{color:var(--text-muted)}
.kv dd{margin:0;min-width:0;overflow-wrap:anywhere}

/* -- empty, loading, error ----------------------------------------------- */
.empty{display:flex;flex-direction:column;align-items:center;gap:var(--s-2);
  padding:var(--s-8) var(--s-5);text-align:center;color:var(--text-muted)}
.empty .t{font-weight:620;color:var(--text);font-size:var(--fs-md)}
.empty .h{font-size:var(--fs-sm);max-width:44ch}
.empty.error .t{color:var(--danger)}
.skel{background:linear-gradient(90deg,var(--surface-2),var(--surface-3),var(--surface-2));
  background-size:200% 100%;animation:nm-skel 1.3s linear infinite;border-radius:var(--r-sm);
  height:12px}
@keyframes nm-skel{to{background-position:-200% 0}}
.skel-rows{display:flex;flex-direction:column;gap:var(--s-4);padding:var(--s-4)}
.skel-rows>i{display:block;height:14px}
.w-45{width:45%}.w-55{width:55%}.w-70{width:70%}.w-85{width:85%}
/* A native <progress>: the console's CSP has no 'unsafe-inline', which kills a
   `style="width:42%"` attribute silently — and a bar that never fills is worse
   than no bar. This one carries its value in an attribute the browser draws
   itself, and reads correctly to a screen reader besides. */
progress.meter{appearance:none;-webkit-appearance:none;display:block;width:100%;height:6px;
  border:0;border-radius:var(--r-full);overflow:hidden;background:var(--surface-3);color:var(--accent)}
progress.meter::-webkit-progress-bar{background:var(--surface-3)}
progress.meter::-webkit-progress-value{background:var(--accent);border-radius:var(--r-full);
  transition:width .4s var(--ease)}
progress.meter::-moz-progress-bar{background:var(--accent)}
progress.meter.hot::-webkit-progress-value{background:var(--warn)}
progress.meter.hot::-moz-progress-bar{background:var(--warn)}
progress.meter.crit::-webkit-progress-value{background:var(--danger)}
progress.meter.crit::-moz-progress-bar{background:var(--danger)}

/* -- notices (inline, keep their place in the flow) ---------------------- */
.notice{display:flex;gap:var(--s-2);padding:var(--s-3) var(--s-4);border-radius:var(--r-md);
  font-size:var(--fs-sm);background:var(--surface-2);color:var(--text-muted);
  border:1px solid var(--border)}
.notice.ok{background:var(--ok-soft);color:var(--ok);border-color:transparent}
.notice.warn{background:var(--warn-soft);color:var(--warn);border-color:transparent}
.notice.danger{background:var(--danger-soft);color:var(--danger);border-color:transparent}
.notice:empty{display:none}
.msg{font-size:var(--fs-sm);color:var(--text-muted);min-height:1lh}
.msg.error{color:var(--danger)}
.msg:empty{min-height:0}

/* -- toasts -------------------------------------------------------------- */
.toasts{position:fixed;z-index:60;bottom:var(--s-4);right:var(--s-4);display:flex;
  flex-direction:column;gap:var(--s-2);width:min(380px,calc(100vw - var(--s-6)));
  pointer-events:none}
.toast{pointer-events:auto;display:flex;gap:var(--s-3);align-items:flex-start;
  background:var(--surface);border:1px solid var(--border);border-left:3px solid var(--text-faint);
  border-radius:var(--r-md);box-shadow:var(--shadow-3);padding:var(--s-3) var(--s-4);
  font-size:var(--fs-sm);animation:nm-toast .18s var(--ease)}
.toast.ok{border-left-color:var(--ok)}
.toast.warn{border-left-color:var(--warn)}
.toast.danger{border-left-color:var(--danger)}
.toast .t{font-weight:600}
.toast .b{color:var(--text-muted);margin-top:2px}
@keyframes nm-toast{from{opacity:0;transform:translateY(6px)}}

/* -- dialogs ------------------------------------------------------------- */
dialog{border:0;padding:0;background:transparent;max-width:min(560px,calc(100vw - var(--s-6)));
  width:100%;color:var(--text);overscroll-behavior:contain}
dialog::backdrop{background:var(--overlay);backdrop-filter:blur(2px)}
dialog>form,dialog>.sheet{background:var(--surface);border:1px solid var(--border);
  border-radius:var(--r-lg);box-shadow:var(--shadow-3);overflow:hidden;
  max-height:min(80vh,760px);display:flex;flex-direction:column}
.sheet-head{display:flex;align-items:center;gap:var(--s-3);padding:var(--s-4) var(--s-5);
  border-bottom:1px solid var(--border)}
.sheet-head h2{flex:1 1 auto;min-width:0}
.sheet-body{padding:var(--s-5);overflow-y:auto;display:flex;flex-direction:column;gap:var(--s-4)}
.sheet-foot{padding:var(--s-3) var(--s-5);border-top:1px solid var(--border);
  background:var(--surface-2);display:flex;gap:var(--s-2);justify-content:flex-end;flex-wrap:wrap}
dialog.wide{max-width:min(880px,calc(100vw - var(--s-6)))}

/* -- command palette ----------------------------------------------------- */
dialog.palette{max-width:min(560px,calc(100vw - var(--s-4)));margin-top:12vh}
.palette input{border:0;border-radius:0;min-height:52px;font-size:var(--fs-lg);
  padding:0 var(--s-5);background:transparent}
.palette input:focus{box-shadow:none}
.palette .list{overflow-y:auto;max-height:52vh;padding:var(--s-2);border-top:1px solid var(--border)}
.palette .it{display:flex;align-items:center;gap:var(--s-3);padding:var(--s-2) var(--s-3);
  border-radius:var(--r-sm);cursor:pointer;font-size:var(--fs-sm)}
.palette .it[aria-selected="true"]{background:var(--accent-soft);color:var(--text)}
.palette .it .where{margin-left:auto;font-size:var(--fs-xs);color:var(--text-faint)}
.palette .none{padding:var(--s-5);text-align:center;color:var(--text-muted);font-size:var(--fs-sm)}

/* -- misc ---------------------------------------------------------------- */
.copyable{display:flex;gap:var(--s-2);align-items:stretch}
.copyable code,.copyable input{flex:1 1 auto;min-width:0;overflow-x:auto;white-space:nowrap;
  font-family:var(--mono);font-size:var(--fs-sm);background:var(--surface-2);
  border:1px solid var(--border);border-radius:var(--r-md);padding:var(--s-2) var(--s-3);
  display:flex;align-items:center}
pre.block{margin:0;padding:var(--s-4);background:var(--surface-2);border:1px solid var(--border);
  border-radius:var(--r-md);overflow:auto;max-height:340px;font:var(--fs-xs)/1.6 var(--mono);
  white-space:pre-wrap;overflow-wrap:anywhere}
code.inline{font-family:var(--mono);font-size:.92em;background:var(--surface-2);
  border:1px solid var(--border);border-radius:var(--r-sm);padding:1px 5px}
.chips{display:flex;flex-wrap:wrap;gap:var(--s-2)}
.chip{display:inline-flex;align-items:center;gap:var(--s-2);padding:4px 4px 4px 10px;
  border:1px solid var(--border);border-radius:var(--r-full);background:var(--surface-2);
  font:var(--fs-xs)/1.6 var(--mono)}
.pager{display:flex;align-items:center;gap:var(--s-2);padding:var(--s-3) var(--s-4);
  border-top:1px solid var(--border);font-size:var(--fs-sm);color:var(--text-muted)}
.pager .grow{flex:1}
.toolbar{display:flex;gap:var(--s-2);align-items:center;flex-wrap:wrap}
.toolbar.padded{padding:var(--s-3) var(--s-4)}
.gap-4{gap:var(--s-4)}
.narrow{max-width:120px}
.pre{white-space:pre-wrap}
.flush{padding:0}
.bare{border:0;padding:0;margin:0;min-width:0}
.stat.sm .v{font-size:var(--fs-md);font-weight:600}
.search{position:relative;min-width:200px;flex:1 1 220px;max-width:340px}
.search input{padding-left:var(--s-7)}
.search::before{content:"";position:absolute;left:13px;top:50%;width:11px;height:11px;
  margin-top:-7px;border:1.6px solid var(--text-faint);border-radius:50%;pointer-events:none}
.search::after{content:"";position:absolute;left:22px;top:50%;width:6px;height:1.6px;
  margin-top:2px;background:var(--text-faint);transform:rotate(45deg);pointer-events:none}
"""


# ---------------------------------------------------------------------------
# App shell
# ---------------------------------------------------------------------------
# One frame for all three pages: a rail that names where you are, a topbar that
# says what this node is doing, and a single content column. Consistency here is
# what makes /chat and /fleet feel like the same product as /.

SHELL = """
.shell{display:grid;grid-template-columns:var(--rail-w) minmax(0,1fr);min-height:100vh}

/* -- rail ---------------------------------------------------------------- */
.rail{position:sticky;top:0;height:100vh;display:flex;flex-direction:column;gap:var(--s-2);
  padding:var(--s-4) var(--s-3);background:var(--rail);border-right:1px solid var(--border);
  overflow-y:auto}
.brand{display:flex;align-items:center;gap:var(--s-3);padding:var(--s-2);margin-bottom:var(--s-2);
  color:var(--text);text-decoration:none}
.brand:hover{text-decoration:none}
.mark{width:30px;height:30px;flex:none;border-radius:9px;display:grid;place-items:center;
  background:var(--accent);color:var(--accent-fg);font:700 var(--fs-xs)/1 var(--font);
  letter-spacing:.02em}
.brand b{font-size:var(--fs-md);font-weight:640;letter-spacing:-.01em;display:block}
.brand span{font-size:var(--fs-xs);color:var(--text-faint);display:block;margin-top:-2px}
.nav{display:flex;flex-direction:column;gap:2px}
.nav-label{padding:var(--s-3) var(--s-2) var(--s-1)}
.nav button,.nav a{display:flex;align-items:center;gap:var(--s-3);width:100%;min-height:34px;
  padding:0 var(--s-3);border:0;background:transparent;color:var(--text-muted);
  border-radius:var(--r-md);font:560 var(--fs-sm)/1 var(--font);justify-content:flex-start;
  text-decoration:none}
.nav button:hover,.nav a:hover{background:var(--surface-2);color:var(--text);
  border-color:transparent;text-decoration:none}
.nav button[aria-selected="true"]{background:var(--accent-soft);color:var(--accent)}
.nav .ic{width:16px;height:16px;flex:none;opacity:.9}
.nav .tail{margin-left:auto;font-size:var(--fs-xs);color:var(--text-faint);font-weight:600}
.rail-foot{margin-top:auto;padding-top:var(--s-3);border-top:1px solid var(--border);
  display:flex;flex-direction:column;gap:var(--s-2)}
.rail-state{display:flex;align-items:center;gap:var(--s-2);padding:0 var(--s-2);
  font-size:var(--fs-xs);color:var(--text-muted)}

/* -- topbar -------------------------------------------------------------- */
.topbar{position:sticky;top:0;z-index:20;display:flex;align-items:center;gap:var(--s-3);
  min-height:var(--topbar-h);background:color-mix(in srgb,var(--canvas) 88%,transparent);
  backdrop-filter:blur(8px);border-bottom:1px solid var(--border);
  /* Lines up with the content column on a wide screen, instead of drifting to
     the far edge while the page sits in the middle. */
  padding-inline:max(var(--s-5),(100% - var(--content-max))/2)}
.topbar .who{display:flex;align-items:center;gap:var(--s-2);min-width:0;overflow:hidden}
.topbar .who>*{flex:0 1 auto;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.topbar .who button{font-family:var(--mono);font-size:var(--fs-xs);min-height:var(--ctl-h-sm);
  color:var(--text-muted)}
.rail-toggle{display:none}

/* -- page ---------------------------------------------------------------- */
main{min-width:0;display:flex;flex-direction:column}
.content{width:100%;max-width:var(--content-max);margin:0 auto;padding:var(--s-6) var(--s-5) var(--s-9);
  display:flex;flex-direction:column;gap:var(--s-5)}
.page-head{display:flex;align-items:flex-end;gap:var(--s-4);flex-wrap:wrap}
.page-head .grow{min-width:min(100%,320px)}
.page-head h1{margin-top:2px}
.page-head .actions{display:flex;gap:var(--s-2);flex-wrap:wrap;margin-left:auto}
.panel{display:flex;flex-direction:column;gap:var(--s-5)}
.panel[hidden]{display:none}
.split{display:grid;gap:var(--s-4);grid-template-columns:repeat(auto-fit,minmax(320px,1fr))}
.split.wide-first{grid-template-columns:minmax(0,1.6fr) minmax(280px,1fr)}
@media (max-width:1040px){.split.wide-first{grid-template-columns:1fr}}

/* -- narrow: the rail becomes a drawer ----------------------------------- */
@media (max-width:900px){
  .shell{grid-template-columns:1fr}
  .rail{position:fixed;z-index:40;left:0;top:0;width:min(280px,84vw);
    transform:translateX(-102%);transition:transform var(--speed) var(--ease);
    box-shadow:var(--shadow-3)}
  .shell.rail-open .rail{transform:none}
  .shell.rail-open::after{content:"";position:fixed;inset:0;z-index:30;background:var(--overlay)}
  .rail-toggle{display:inline-flex}
  .content{padding:var(--s-4) var(--s-4) var(--s-8)}
  .topbar{padding:0 var(--s-4)}
}
@media (max-width:720px){
  /* The palette is a keyboard affordance; on a phone it is only clutter in a
     bar that has to fit an identifier. */
  .topbar #palette-open{display:none}
  .page-head .actions{margin-left:0}
}

/* -- the login gate ------------------------------------------------------ */
.gate{min-height:100vh;display:grid;place-items:center;padding:var(--s-5);
  background:radial-gradient(1200px 600px at 50% -10%,var(--accent-soft),transparent 70%),var(--canvas)}
.gate form{width:min(400px,100%);background:var(--surface);border:1px solid var(--border);
  border-radius:var(--r-xl);box-shadow:var(--shadow-3);padding:var(--s-7) var(--s-6);
  display:flex;flex-direction:column;gap:var(--s-4)}
.gate .mark{width:38px;height:38px;font-size:var(--fs-sm);border-radius:11px}
.gate h1{font-size:var(--fs-xl)}
"""

CSS = TOKENS + BASE + COMPONENTS + SHELL


# ---------------------------------------------------------------------------
# Theme bootstrap
# ---------------------------------------------------------------------------
# Served as its own file and loaded *blocking* in <head>: a stored choice has to
# be on the element before the first paint, or the page flashes the other theme.
# The CSP forbids inline script, so it cannot simply be a tag in the page.

THEME_JS = r"""
try{
  var choice=localStorage.getItem("nmesh_theme");
  if(choice==="light"||choice==="dark")document.documentElement.dataset.theme=choice;
}catch(_){/* private mode, or storage disabled: the media query still decides */}
"""


# ---------------------------------------------------------------------------
# Favicon
# ---------------------------------------------------------------------------
# Served as a file rather than a data: URI, because `default-src 'self'` blocks
# data: for images too. Without it every page load asks for /favicon.ico and
# takes a 404 in the browser console.

FAVICON_SVG = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">
<rect width="32" height="32" rx="8" fill="#097061"/>
<g stroke="#ffffff" stroke-width="1.6" stroke-linecap="round" opacity=".85">
<path d="M16 16 L9 10 M16 16 L23 10 M16 16 L11 24 M16 16 L23 21"/></g>
<g fill="#ffffff">
<circle cx="16" cy="16" r="3.4"/><circle cx="9" cy="10" r="2.1"/>
<circle cx="23" cy="10" r="2.1"/><circle cx="11" cy="24" r="2.1"/>
<circle cx="23" cy="21" r="2.1"/></g></svg>
"""


# ---------------------------------------------------------------------------
# Shared runtime
# ---------------------------------------------------------------------------
# Every page gets this before its own script. It holds the things all three
# pages were each solving separately — the session, formatting, feedback,
# routing — so there is one behaviour to fix rather than three.

JS = r"""
"use strict";

// ---- tiny DOM helpers ------------------------------------------------------
const $ = (id) => document.getElementById(id);
const $$ = (selector, root) => Array.from((root || document).querySelectorAll(selector));
const esc = (value) => String(value == null ? "" : value).replace(/[&<>"']/g,
  (c) => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const shortId = (id) => id ? id.slice(0, 6) + "…" + id.slice(-4) : "unknown";
function debounce(fn, delay){
  let timer; return (...args) => { clearTimeout(timer); timer = setTimeout(() => fn(...args), delay || 250); };
}

// ---- formatting ------------------------------------------------------------
// Locale-aware where a human reads it, fixed where a machine does.
function fmtBytes(value){
  if(value == null || !Number.isFinite(Number(value))) return "—";
  let amount = Number(value), unit = 0;
  const units = ["B","kB","MB","GB","TB"];
  while(amount >= 1024 && unit < units.length - 1){ amount /= 1024; unit++; }
  return (unit ? amount.toFixed(1) : Math.round(amount)) + " " + units[unit];
}
function fmtRate(value){ return value == null ? "—" : fmtBytes(value) + "/s"; }
function fmtNum(value){
  return value == null ? "—" : Number(value).toLocaleString(undefined, {maximumFractionDigits:1});
}
function fmtDuration(value){
  let seconds = Math.max(0, Math.floor(value || 0));
  const days = Math.floor(seconds / 86400); seconds %= 86400;
  const hours = Math.floor(seconds / 3600); seconds %= 3600;
  const minutes = Math.floor(seconds / 60);
  if(days) return days + "d " + hours + "h";
  if(hours) return hours + "h " + minutes + "m";
  if(minutes) return minutes + "m";
  return Math.max(0, Math.floor(value || 0)) + "s";
}
function fmtAgo(seconds){
  if(seconds == null) return "—";
  seconds = Math.max(0, Math.floor(seconds));
  if(seconds < 45) return "just now";
  return fmtDuration(seconds) + " ago";
}
function fmtTime(epochSeconds){
  try{ return new Date(epochSeconds * 1000).toLocaleTimeString(); }
  catch(_){ return ""; }
}

// ---- session ---------------------------------------------------------------
// The token lives in sessionStorage and nowhere else: never on disk, gone when
// the tab closes. A 401 anywhere drops straight back to the gate.
let TOKEN = null;
const SESSION = {
  onLost: () => {},
  load(){ try{ TOKEN = sessionStorage.getItem("nmesh_token"); }catch(_){ TOKEN = null; } return TOKEN; },
  set(token){ TOKEN = token; try{ sessionStorage.setItem("nmesh_token", token); }catch(_){} },
  clear(){ TOKEN = null; try{ sessionStorage.removeItem("nmesh_token"); }catch(_){} },
};
async function api(path, method, body){
  const headers = {};
  if(TOKEN) headers.Authorization = "Bearer " + TOKEN;
  if(body !== undefined) headers["Content-Type"] = "application/json";
  const response = await fetch(path, {method: method || "GET", headers,
    body: body === undefined ? undefined : JSON.stringify(body)});
  if(response.status === 401){ SESSION.clear(); SESSION.onLost(); throw new Error("unauthorized"); }
  return response;
}
async function apiJson(path, method, body){
  const response = await api(path, method, body);
  const data = await response.json().catch(() => ({}));
  return {ok: response.ok, status: response.status, data};
}

// ---- feedback --------------------------------------------------------------
// Toasts are for what just happened somewhere else on the page; inline messages
// stay next to the control they belong to. Announced politely, never as an
// alert: a status line must not interrupt a screen reader mid-sentence.
function toast(text, kind, detail){
  const region = $("toasts"); if(!region) return;
  const node = document.createElement("div");
  node.className = "toast " + (kind || "");
  node.innerHTML = '<div class="grow"><div class="t">' + esc(text) + "</div>" +
    (detail ? '<div class="b">' + esc(detail) + "</div>" : "") + "</div>" +
    '<button class="icon sm" aria-label="Dismiss">✕</button>';
  node.querySelector("button").addEventListener("click", () => node.remove());
  region.appendChild(node);
  setTimeout(() => node.remove(), kind === "danger" ? 9000 : 5000);
  while(region.childElementCount > 4) region.firstElementChild.remove();
}
function setMessage(id, text, bad){
  const element = $(id); if(!element) return;
  element.textContent = text || "";
  element.classList.toggle("error", !!bad);
}
// Keeps the label in place while a request is in flight, so the button does not
// resize under the pointer and the user can still read what they pressed.
async function withBusy(button, work){
  if(!button) return work();
  button.setAttribute("aria-busy", "true"); button.disabled = true;
  try{ return await work(); }
  finally{ button.removeAttribute("aria-busy"); button.disabled = false; }
}
async function copyText(text){
  try{ await navigator.clipboard.writeText(text); toast("Copied to clipboard"); return true; }
  catch(_){ toast("Could not copy — select and copy by hand", "warn"); return false; }
}

// ---- confirmation ----------------------------------------------------------
// Destructive actions ask first, in the page rather than through window.confirm:
// it can be styled, it says what will actually happen, and it cannot be
// suppressed by a browser that has decided the page asks too often.
function confirmAction(options){
  const dialog = $("confirm-dialog");
  return new Promise((resolve) => {
    if(!dialog){ resolve(false); return; }
    $("confirm-title").textContent = options.title || "Are you sure?";
    $("confirm-body").innerHTML = options.body || "";
    const ok = $("confirm-ok");
    ok.textContent = options.confirmLabel || "Confirm";
    ok.className = options.danger ? "danger solid" : "primary";
    let answer = false;
    const accept = () => { answer = true; dialog.close(); };
    ok.addEventListener("click", accept, {once:true});
    dialog.addEventListener("close", () => {
      ok.removeEventListener("click", accept);
      resolve(answer);
    }, {once:true});
    dialog.showModal();
  });
}

// ---- markup fragments every page needs -------------------------------------
function emptyHTML(title, hint, action){
  return '<div class="empty"><div class="t">' + esc(title) + "</div>" +
    (hint ? '<div class="h">' + esc(hint) + "</div>" : "") + (action || "") + "</div>";
}
function errorHTML(title, hint){
  return '<div class="empty error"><div class="t">' + esc(title) + "</div>" +
    (hint ? '<div class="h">' + esc(hint) + "</div>" : "") + "</div>";
}
// A skeleton mirrors the shape of what is coming, so nothing jumps when it
// arrives.
function skeletonHTML(rows){
  const widths = ["w-70", "w-45", "w-85", "w-55"];
  let out = '<div class="skel-rows">';
  for(let i = 0; i < (rows || 3); i++)
    out += '<i class="skel ' + widths[i % widths.length] + '"></i>';
  return out + "</div>";
}
function badge(text, tone){
  return '<span class="badge ' + (tone || "") + '">' + esc(text) + "</span>";
}

// ---- theme -----------------------------------------------------------------
// Three states: follow the system, or an explicit choice in either direction.
// The choice is per-browser and never leaves it.
const THEME = {
  stored(){ try{ return localStorage.getItem("nmesh_theme"); }catch(_){ return null; } },
  current(){
    return this.stored() ||
      (window.matchMedia && matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
  },
  set(value){
    try{
      if(value) localStorage.setItem("nmesh_theme", value);
      else localStorage.removeItem("nmesh_theme");
    }catch(_){}
    if(value) document.documentElement.dataset.theme = value;
    else delete document.documentElement.dataset.theme;
    this.paint();
  },
  toggle(){ this.set(this.current() === "dark" ? "light" : "dark"); },
  paint(){
    const button = $("theme-toggle"); if(!button) return;
    const dark = this.current() === "dark";
    button.textContent = dark ? "☀" : "☾";
    button.title = dark ? "Switch to the light theme" : "Switch to the dark theme";
    button.setAttribute("aria-label", button.title);
  },
};

// ---- routing ---------------------------------------------------------------
// The address bar is the state: a section (and its sub-section) can be linked,
// bookmarked, and reached with Back. Panels are `data-panel`, sub-panels are
// `data-sub` inside them.
const ROUTER = {
  section: "", sub: "", onChange: () => {},
  parse(){
    const raw = (location.hash || "").replace(/^#/, "");
    const [section, sub] = raw.split("/");
    return {section: section || "", sub: sub || ""};
  },
  go(section, sub, replace){
    const hash = "#" + section + (sub ? "/" + sub : "");
    if(location.hash === hash){ this.apply(); return; }
    if(replace) history.replaceState(null, "", hash); else history.pushState(null, "", hash);
    this.apply();
  },
  apply(){
    const wanted = this.parse();
    const panels = $$("[data-panel]");
    if(!panels.length) return;
    let section = wanted.section;
    if(!panels.some((panel) => panel.dataset.panel === section))
      section = panels[0].dataset.panel;
    this.section = section;
    panels.forEach((panel) => { panel.hidden = panel.dataset.panel !== section; });
    $$("[data-tab]").forEach((button) => {
      const on = button.dataset.tab === section;
      button.setAttribute("aria-selected", on ? "true" : "false");
      button.tabIndex = on ? 0 : -1;
    });
    const panel = panels.find((p) => p.dataset.panel === section);
    const subs = panel ? $$("[data-sub]", panel) : [];
    let sub = wanted.sub;
    if(subs.length){
      if(!subs.some((element) => element.dataset.sub === sub)) sub = subs[0].dataset.sub;
      subs.forEach((element) => { element.hidden = element.dataset.sub !== sub; });
      $$("[data-subtab]", panel).forEach((button) => {
        button.setAttribute("aria-selected", button.dataset.subtab === sub ? "true" : "false");
      });
    }
    this.sub = subs.length ? sub : "";
    document.title = this.title();
    this.onChange(this.section, this.sub);
  },
  title(){
    const button = $$("[data-tab]").find((b) => b.dataset.tab === this.section);
    const label = button ? (button.dataset.label || button.textContent.trim()) : "";
    return (label ? label + " · " : "") + (document.body.dataset.appName || "NMesh");
  },
  start(onChange){
    this.onChange = onChange || this.onChange;
    window.addEventListener("hashchange", () => this.apply());
    this.apply();
  },
};

// ---- command palette -------------------------------------------------------
// Ctrl/Cmd-K. Every section is reachable from it, and so is any action a page
// registers — a keyboard route to things that would otherwise need three clicks.
const PALETTE = {
  items: [], filtered: [], index: 0,
  add(label, where, run){ this.items.push({label, where, run}); },
  open(){
    const dialog = $("palette"); if(!dialog) return;
    $("palette-input").value = ""; this.filter("");
    dialog.showModal(); $("palette-input").focus();
  },
  filter(query){
    const needle = query.trim().toLowerCase();
    this.filtered = needle
      ? this.items.filter((item) => (item.label + " " + item.where).toLowerCase().includes(needle))
      : this.items.slice();
    this.index = 0; this.paint();
  },
  paint(){
    const list = $("palette-list"); if(!list) return;
    if(!this.filtered.length){ list.innerHTML = '<div class="none">Nothing matches that.</div>'; return; }
    list.innerHTML = this.filtered.map((item, i) =>
      '<div class="it" role="option" data-i="' + i + '" aria-selected="' +
      (i === this.index ? "true" : "false") + '"><span>' + esc(item.label) +
      '</span><span class="where">' + esc(item.where) + "</span></div>").join("");
    const active = list.querySelector('[aria-selected="true"]');
    if(active) active.scrollIntoView({block:"nearest"});
  },
  move(step){
    if(!this.filtered.length) return;
    this.index = (this.index + step + this.filtered.length) % this.filtered.length;
    this.paint();
  },
  run(index){
    const item = this.filtered[index == null ? this.index : index];
    $("palette").close();
    if(item) item.run();
  },
};

// ---- shell wiring ----------------------------------------------------------
// Done once here rather than per page: the chrome is the same everywhere, so it
// should not be three near-identical copies that drift.
function mountShell(){
  THEME.paint();
  const toggle = $("theme-toggle");
  if(toggle) toggle.addEventListener("click", () => THEME.toggle());

  const rail = $("rail-toggle"), shell = $("shell");
  if(rail && shell){
    rail.addEventListener("click", () => shell.classList.toggle("rail-open"));
    shell.addEventListener("click", (event) => {
      if(shell.classList.contains("rail-open") && event.target === shell)
        shell.classList.remove("rail-open");
    });
  }
  const nav = $("nav");
  if(nav){
    nav.addEventListener("click", (event) => {
      const button = event.target.closest("[data-tab]");
      if(!button) return;
      ROUTER.go(button.dataset.tab);
      if(shell) shell.classList.remove("rail-open");
    });
    nav.addEventListener("keydown", (event) => {
      if(!["ArrowUp","ArrowDown"].includes(event.key)) return;
      const buttons = $$("[data-tab]", nav);
      const current = buttons.findIndex((b) => b.dataset.tab === ROUTER.section);
      const step = event.key === "ArrowDown" ? 1 : -1;
      const next = buttons[(current + step + buttons.length) % buttons.length];
      next.focus(); ROUTER.go(next.dataset.tab); event.preventDefault();
    });
  }
  document.addEventListener("click", (event) => {
    const button = event.target.closest("[data-subtab]");
    if(button) ROUTER.go(ROUTER.section, button.dataset.subtab);
  });

  // A click on the backdrop closes the dialog it belongs to — the pattern every
  // modal on the web has trained people to expect.
  $$("dialog").forEach((element) => element.addEventListener("click", (event) => {
    if(event.target === element) element.close();
  }));

  const dialog = $("palette");
  if(dialog){
    $("palette-input").addEventListener("input", (event) => PALETTE.filter(event.target.value));
    $("palette-input").addEventListener("keydown", (event) => {
      if(event.key === "ArrowDown"){ PALETTE.move(1); event.preventDefault(); }
      else if(event.key === "ArrowUp"){ PALETTE.move(-1); event.preventDefault(); }
      else if(event.key === "Enter"){ PALETTE.run(); event.preventDefault(); }
      // A search input eats Escape to clear itself, so the dialog never sees the
      // cancel and the palette would stay open on the one key everybody presses.
      else if(event.key === "Escape"){ dialog.close(); event.preventDefault(); }
    });
    $("palette-list").addEventListener("click", (event) => {
      const item = event.target.closest("[data-i]");
      if(item) PALETTE.run(Number(item.dataset.i));
    });
    document.addEventListener("keydown", (event) => {
      if((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k"){
        PALETTE.open(); event.preventDefault();
      }
    });
  }
  const close = $("confirm-cancel");
  if(close) close.addEventListener("click", () => $("confirm-dialog").close());
}
"""
