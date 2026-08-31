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
  --rail-w:236px; --topbar-h:56px; --content-max:1180px; --tabbar-h:58px;
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
.flex-none{flex:none}
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

/* -- range: a value with two named ends ---------------------------------- */
/* Every part of a range has to be restyled per engine — a bare one is invisible
   against this palette, and its thumb is under the 24px a finger needs. */
input[type="range"]{appearance:none;-webkit-appearance:none;width:100%;padding:0;border:0;
  background:transparent;min-height:var(--tap);cursor:pointer}
input[type="range"]:hover,input[type="range"]:focus{border:0;box-shadow:none;background:transparent}
input[type="range"]::-webkit-slider-runnable-track{height:6px;border-radius:var(--r-full);
  background:var(--surface-3);border:1px solid var(--border)}
input[type="range"]::-moz-range-track{height:6px;border-radius:var(--r-full);
  background:var(--surface-3);border:1px solid var(--border)}
input[type="range"]::-webkit-slider-thumb{appearance:none;-webkit-appearance:none;
  width:22px;height:22px;margin-top:-9px;border-radius:50%;background:var(--surface);
  border:2px solid var(--accent);box-shadow:var(--shadow-2)}
input[type="range"]::-moz-range-thumb{width:22px;height:22px;border-radius:50%;
  background:var(--surface);border:2px solid var(--accent);box-shadow:var(--shadow-2)}
input[type="range"]:focus-visible::-webkit-slider-thumb{box-shadow:0 0 0 4px var(--accent-soft)}
input[type="range"]:focus-visible::-moz-range-thumb{box-shadow:0 0 0 4px var(--accent-soft)}
/* The two ends of the scale, named: a number alone says nothing about which
   way is which. */
.scale{display:flex;align-items:baseline;gap:var(--s-3);font-size:var(--fs-xs);
  color:var(--text-muted)}
.scale>b{flex:1 1 auto;text-align:center;font-weight:600;color:var(--text)}
.scale>span{flex:0 1 auto;min-width:0}
.scale>span:last-child{text-align:right}
/* On a phone the middle reading wraps and squeezes the two ends into columns;
   given its own line it stays a sentence. */
@media (max-width:560px){
  .scale{flex-wrap:wrap}
  .scale>b{order:-1;flex:1 1 100%;text-align:left}
}

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
.form-grid{display:grid;gap:var(--s-4);
  grid-template-columns:repeat(auto-fit,minmax(min(240px,100%),1fr))}
.form-grid.one{grid-template-columns:minmax(0,1fr)}

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
.cards{display:grid;gap:var(--s-4);
  grid-template-columns:repeat(auto-fill,minmax(min(320px,100%),1fr))}

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
.stats{display:grid;gap:var(--s-3);
  grid-template-columns:repeat(auto-fit,minmax(min(150px,100%),1fr))}
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
.spark{display:block;overflow:visible}
.spark path{fill:none;stroke:var(--accent);stroke-width:1.5;stroke-linejoin:round;
  stroke-linecap:round;vector-effect:non-scaling-stroke}
.spark.warn path{stroke:var(--warn)}

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
.kv{display:grid;grid-template-columns:minmax(120px,auto) minmax(0,1fr);gap:var(--s-2) var(--s-4);
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

/* -- menus (a popover that hangs off its button) ------------------------- */
/* Anything that would otherwise grow a bar goes in one of these: a bar with a
   fixed height cannot be pushed around by how much there is to say. */
.menu-wrap{position:relative;display:inline-flex}
.menu{position:absolute;top:calc(100% + 6px);right:0;z-index:50;
  width:min(360px,calc(100vw - var(--s-5)));max-height:min(60vh,440px);overflow-y:auto;
  overscroll-behavior:contain;background:var(--surface);border:1px solid var(--border);
  border-radius:var(--r-lg);box-shadow:var(--shadow-3);padding:var(--s-2);
  display:flex;flex-direction:column;gap:2px;animation:nm-menu .14s var(--ease)}
.menu[hidden]{display:none}
@keyframes nm-menu{from{opacity:0;transform:translateY(-4px)}}
.menu-head{display:flex;align-items:center;gap:var(--s-2);padding:var(--s-2) var(--s-3);
  font-size:var(--fs-xs);font-weight:640;color:var(--text-muted);letter-spacing:.03em;
  text-transform:uppercase}
.menu-head .grow{flex:1 1 auto;min-width:0}
/* Whatever a menu head says beside its title is a sentence, not a label. */
.menu-head .row{text-transform:none;letter-spacing:0;font-weight:500}
.menu a,.menu button.item{display:flex;align-items:center;gap:var(--s-3);width:100%;
  min-height:var(--tap);padding:var(--s-2) var(--s-3);border:0;background:transparent;
  color:var(--text);border-radius:var(--r-md);justify-content:flex-start;
  font:560 var(--fs-sm)/1.35 var(--font);text-align:left;white-space:normal;
  text-decoration:none}
.menu a:hover,.menu button.item:hover{background:var(--surface-2);border-color:transparent;
  text-decoration:none}
.menu button.item.danger{color:var(--danger)}
.menu button.item[disabled]{color:var(--text-muted);cursor:not-allowed}
.menu button.item[disabled]:hover{background:transparent}
/* Why an item is unavailable, under the item — a disabled control that does not
   say what would enable it is a dead end. */
.menu .menu-note{margin:0;padding:0 var(--s-3) var(--s-2);
  font-size:var(--fs-xs);color:var(--text-muted)}
.menu .sep{height:1px;background:var(--border);margin:var(--s-1) var(--s-2)}
.menu .none{padding:var(--s-5) var(--s-3);text-align:center;color:var(--text-muted);
  font-size:var(--fs-sm)}
/* A count badge floats over its button instead of sitting beside it, so a
   two-digit number cannot widen the bar it lives in. */
.count{position:absolute;top:-1px;right:-1px;min-width:17px;height:17px;padding:0 4px;
  border-radius:var(--r-full);background:var(--danger);color:#fff;
  font:700 var(--fs-2xs)/17px var(--font);text-align:center;pointer-events:none;
  border:2px solid var(--canvas);box-sizing:content-box}
.count[hidden]{display:none}
/* On a phone a dropdown pinned under a corner button is both unreachable and
   too narrow. Same markup, same script: it becomes a sheet at the bottom, where
   a thumb already is. `::before` is the scrim — a click on it lands on .menu. */
@media (max-width:640px){
  .menu{position:fixed;inset:auto 0 0 0;width:auto;max-height:74vh;
    border-radius:var(--r-xl) var(--r-xl) 0 0;border-bottom:0;
    padding:var(--s-3) var(--s-3) calc(var(--s-4) + env(safe-area-inset-bottom));
    animation:nm-sheet .18s var(--ease)}
  .menu::before{content:"";position:fixed;inset:0;z-index:-1;background:var(--overlay)}
  @keyframes nm-sheet{from{transform:translateY(14px);opacity:0}}
}

/* -- toasts -------------------------------------------------------------- */
.toasts{position:fixed;z-index:60;bottom:var(--s-4);right:var(--s-4);display:flex;
  flex-direction:column;gap:var(--s-2);width:min(380px,calc(100vw - var(--s-6)));
  pointer-events:none}
/* The tab bar owns the bottom of a narrow screen; a toast that lands on top of
   it hides the navigation and eats the tap meant for it. */
@media (max-width:900px){
  .toasts{right:var(--s-3);left:var(--s-3);width:auto;
    bottom:calc(var(--tabbar-h) + env(safe-area-inset-bottom) + var(--s-3))}
}
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
dialog.full{max-width:calc(100vw - var(--s-5));width:100%}
dialog.full>.sheet{max-height:calc(100vh - var(--s-5));height:min(88vh,900px)}
/* A phone has no room for a floating card with a margin all round: a modal
   becomes a sheet rising from the bottom, and a full one takes the screen.
   `dvh` and not `vh`, or the browser's own chrome crops the last row off. */
@media (max-width:640px){
  dialog{max-width:100vw;width:100vw;margin:0;position:fixed;inset:auto 0 0 0}
  dialog>form,dialog>.sheet{border-radius:var(--r-xl) var(--r-xl) 0 0;
    max-height:min(90dvh,900px);border-bottom:0}
  .sheet-body{padding:var(--s-4);padding-bottom:calc(var(--s-4) + env(safe-area-inset-bottom))}
  .sheet-head,.sheet-foot{padding-inline:var(--s-4)}
  .sheet-foot{padding-bottom:calc(var(--s-3) + env(safe-area-inset-bottom))}
  dialog.full{height:100dvh;max-height:100dvh}
  dialog.full>.sheet{height:100dvh;max-height:100dvh;border-radius:0;border:0}
}

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
/* A QR always sits on white, in either theme: a scanner reads contrast, not
   taste, and an inverted code is a code nothing can read. */
.qr-holder{display:flex;justify-content:center;padding:var(--s-4);
  border-radius:var(--r-md);background:#fff;border:1px solid var(--border)}
.qr-holder:empty{display:none}
.qr-holder svg{width:min(220px,100%);height:auto}
.stat.sm .v{font-size:var(--fs-md);font-weight:600}
/* -- icons ---------------------------------------------------------------- */
/* Sized in `em` and painted with `currentColor`, so an icon is the size and the
   colour of the text it sits beside, in every theme, without a second rule.
   These replaced emoji: a different picture on every platform, nothing at all
   for a screen reader, and cheap-looking wherever they did render. */
.ic{width:1.15em;height:1.15em;flex:none;display:inline-block;vertical-align:-.16em;
  stroke:currentColor;fill:none;stroke-width:1.9;stroke-linecap:round;stroke-linejoin:round}
.ic.lg{width:1.4em;height:1.4em}
/* A disclosure chevron points down when open and right when closed — one icon
   turned, not two drawings to keep in step. */
.ic.turn{transform:rotate(-90deg);transition:transform var(--speed) var(--ease)}
[aria-expanded="true"] .ic.turn{transform:none}
button>.ic:only-child{width:1.25em;height:1.25em}

.search{position:relative;min-width:min(200px,100%);flex:1 1 220px;max-width:340px}
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
.nav .ic{width:16px;height:16px;opacity:.9}
.nav .tail{margin-left:auto;font-size:var(--fs-xs);color:var(--text-faint);font-weight:600}
.rail-foot{margin-top:auto;padding-top:var(--s-3);border-top:1px solid var(--border);
  display:flex;flex-direction:column;gap:var(--s-2)}
.rail-state{display:flex;align-items:center;gap:var(--s-2);padding:0 var(--s-2);
  font-size:var(--fs-xs);color:var(--text-muted)}

/* -- topbar -------------------------------------------------------------- */
.topbar{position:sticky;top:0;z-index:45;display:flex;align-items:center;gap:var(--s-3);
  min-height:var(--topbar-h);border-bottom:1px solid var(--border);
  /* Lines up with the content column on a wide screen, instead of drifting to
     the far edge while the page sits in the middle. */
  padding-inline:max(var(--s-5),(100% - var(--content-max))/2)}
/* The wash is painted by a pseudo-element and not by the bar itself: a
   `backdrop-filter` on the bar would become the containing block of every
   fixed-position descendant, and the menus that hang off it are exactly that. */
.topbar::before{content:"";position:absolute;inset:0;z-index:-1;
  background:color-mix(in srgb,var(--canvas) 88%,transparent);backdrop-filter:blur(8px)}
.topbar .who{display:flex;align-items:center;gap:var(--s-2);min-width:0;overflow:hidden}
.topbar .who>*{flex:0 1 auto;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.topbar .who button{font-family:var(--mono);font-size:var(--fs-xs);min-height:var(--ctl-h-sm);
  /* Left, not the button default of centre: a centred label clips at both ends
     on a narrow screen, so the node's name would lose its first letters and the
     ellipsis would never appear. */
  color:var(--text-muted);text-align:left}

/* -- driving another node ------------------------------------------------ */
/* Impossible to miss on purpose: every destructive control on the page now
   points somewhere else, and "which machine am I on" must never be a guess. */
.ctx-bar{display:flex;align-items:center;gap:var(--s-3);flex-wrap:wrap;
  padding:var(--s-2) var(--s-5);background:var(--warn-soft);color:var(--warn);
  border-bottom:1px solid var(--border);font-size:var(--fs-sm);font-weight:600}
.ctx-bar .mono{font-weight:400}
.ctx-bar .ctx-note{font-weight:500;color:var(--text-muted)}
.ctx-bar .ctx-note:empty{display:none}
.ctx-bar button{margin-left:auto}
.shell.remote .mark{background:var(--warn);color:var(--warn-soft)}
.ctx-pick{display:flex;align-items:center;gap:var(--s-2);min-width:0}
.ctx-pick select{min-height:var(--ctl-h-sm);font-size:var(--fs-sm);max-width:220px;
  padding-block:0}

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
.split{display:grid;gap:var(--s-4);
  grid-template-columns:repeat(auto-fit,minmax(min(320px,100%),1fr))}
.split.wide-first{grid-template-columns:minmax(0,1.6fr) minmax(280px,1fr)}
@media (max-width:1040px){.split.wide-first{grid-template-columns:minmax(0,1fr)}}

/* The overflow menu carries what the rail carries on a wide screen; showing it
   there too would be the same commands twice. Declared before the media query
   that turns it on — at equal specificity the last rule wins, query or no. */
/* -- auto-refresh -------------------------------------------------------- */
/* Two controls, one preference. A number field is the right thing with a
   keyboard — any value, typed — and the wrong thing on a phone, where a
   spinner is a 12px target and the keyboard covers the page. So the phone gets
   a short list of the intervals anybody actually picks. */
.refresh{display:inline-flex;align-items:center;gap:4px}
.refresh input[type="number"]{width:56px;min-height:var(--ctl-h-sm);padding:0 var(--s-2);
  font-size:var(--fs-xs);text-align:right;font-variant-numeric:tabular-nums}
.refresh .unit{font-size:var(--fs-xs);color:var(--text-muted)}
.refresh select{display:none;min-height:var(--ctl-h-sm);font-size:var(--fs-xs);
  padding-block:0;width:auto}
.refresh.paused input[type="number"],.refresh.paused select{color:var(--text-faint)}
/* Live means the node says when something moves; the interval beside it is
   only how often the numbers that move constantly are re-read. The dot is a
   dot *and* a title, because a colour on its own says nothing to a reader who
   cannot see it. */
.refresh .live{width:7px;height:7px;flex:none;border-radius:var(--r-full);
  background:var(--text-faint)}
.refresh.streaming .live{background:var(--ok)}
@media (max-width:720px){
  .refresh input[type="number"],.refresh .unit{display:none}
  .refresh select{display:block}
}

.more-wrap{display:none}

/* -- narrow: the rail becomes a bottom tab bar --------------------------- */
/* Not a hamburger drawer. Navigation that costs two taps and hides where you
   are is the thing people complain about on a phone; a tab bar is always
   visible, always says which section is showing, and sits under the thumb.
   Same markup as the rail — only the axis changes, so there is no second
   navigation to keep in sync. The rail's brand and foot have no place in a
   58px strip, so they move to the topbar's overflow menu (`.more-wrap`). */
@media (max-width:900px){
  .shell{grid-template-columns:minmax(0,1fr)}
  .rail{position:fixed;z-index:40;inset:auto 0 0 0;top:auto;height:auto;width:auto;
    flex-direction:row;align-items:stretch;gap:0;padding:0;overflow:visible;
    border-right:0;border-top:1px solid var(--border);
    background:color-mix(in srgb,var(--rail) 92%,transparent);backdrop-filter:blur(10px);
    padding-bottom:env(safe-area-inset-bottom)}
  .rail .brand,.rail .rail-foot,.rail .nav-label,.rail #app-links{display:none}
  .nav{flex-direction:row;flex:1 1 auto;gap:0;min-width:0}
  .nav button,.nav a{flex:1 1 0;min-width:0;flex-direction:column;justify-content:center;
    gap:3px;min-height:var(--tabbar-h);padding:var(--s-2) 2px;border-radius:0;
    font-size:var(--fs-2xs);font-weight:640;line-height:1.2;text-align:center;
    position:relative}
  /* The rail spells the section out; the strip has room for the short name the
     markup already carries for the palette. */
  .nav .lbl{display:none}
  .nav button::before,.nav a::before{content:attr(data-label)}
  .nav button:hover,.nav a:hover{background:transparent;color:var(--text)}
  .nav button[aria-selected="true"]{background:transparent;color:var(--accent)}
  /* Where you are, stated without relying on colour alone. */
  .nav button[aria-selected="true"]::after{content:"";position:absolute;top:0;
    left:22%;right:22%;height:2px;border-radius:0 0 2px 2px;background:var(--accent)}
  .nav .tail{position:absolute;top:5px;left:50%;margin-left:8px;min-width:17px;height:17px;
    padding:0 5px;border-radius:var(--r-full);background:var(--accent-soft);
    color:var(--accent);font:700 var(--fs-2xs)/17px var(--font);text-align:center}
  .nav .tail:empty{display:none}
  .more-wrap{display:inline-flex}
  /* The bar floats over the page, so the page has to end above it. */
  .content{padding:var(--s-4) var(--s-4)
           calc(var(--tabbar-h) + env(safe-area-inset-bottom) + var(--s-6))}
  .topbar{padding-inline:var(--s-4)}
}
@media (max-width:720px){
  /* The palette is a keyboard affordance; on a phone it is only clutter in a
     bar that has to fit an identifier. It stays reachable from the ⋯ menu. */
  .topbar #palette-open{display:none}
  .page-head .actions{margin-left:0}
  .page-head h1{font-size:var(--fs-xl)}
  .card>.card-head,.card>.card-body{padding-inline:var(--s-4)}
  .card>.card-body{padding-block:var(--s-4)}
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
# Markup every page shares
# ---------------------------------------------------------------------------
# The strip saying which machine the controls on this page now point at. One
# definition, embedded by each page: three pages writing it three times is three
# chances for one of them to say it differently, and this is the one line on
# screen that must never be wrong.
#
# `data-ctx-local` on the page's <body> says what this particular page cannot do
# for that node — chat and fleet run here whatever is on screen, because the far
# console refuses them by design (see Docs/Apps/fleet).

CTX_BAR = """
    <div id="ctx-bar" class="ctx-bar" role="status" hidden>
      <span>Managing <b id="ctx-label"></b></span>
      <span id="ctx-id" class="mono tiny"></span>
      <span id="ctx-note" class="ctx-note"></span>
      <button id="ctx-leave" class="sm">Back to this node</button>
    </div>
"""


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
// A pseudo is a label somebody chose, not an identity: two nodes may wear the
// same one, and a lookalike costs an attacker nothing to register. So the id
// always travels with it — never a name on its own.
const nodeLabel = (id, pseudo) => pseudo ? pseudo + " · " + shortId(id) : shortId(id);
// ---- icons -----------------------------------------------------------------
// One set for the whole product. Paths only: the wrapper is written once by
// `icon()`, so every icon shares a stroke weight, a box and a baseline.
const ICONS = {
  close:      '<path d="M18 6 6 18M6 6l12 12"/>',
  back:       '<path d="M15 18 9 12l6-6"/>',
  moon:       '<path d="M20.5 14.8A8.6 8.6 0 0 1 9.2 3.5a8.6 8.6 0 1 0 11.3 11.3Z"/>',
  sun:        '<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/>',
  attach:     '<path d="M21 11.6 12.4 20a5.5 5.5 0 1 1-7.8-7.8l8.6-8.5a3.7 3.7 0 0 1 5.2 5.2l-8.6 8.5a1.8 1.8 0 1 1-2.6-2.6l7.9-7.8"/>',
  emoji:      '<circle cx="12" cy="12" r="9"/><path d="M9 10h.01M15 10h.01M8.5 14.5a4.5 4.5 0 0 0 7 0"/>',
  compose:    '<path d="M12 20h9M16.4 3.6a2.1 2.1 0 0 1 3 3L7.5 18.5 3.5 19.5l1-4Z"/>',
  trash:      '<path d="M3 6h18M8 6V4h8v2M18.5 6l-1 14h-11l-1-14M10 10.5v6M14 10.5v6"/>',
  send:       '<path d="M22 2 11 13M22 2l-7 20-4-9-9-4Z"/>',
  image:      '<rect x="3" y="4.5" width="18" height="15" rx="2"/><circle cx="8.5" cy="10" r="1.5"/><path d="M21 15.5 16 10.5 5.5 21"/>',
  file:       '<path d="M14 2.5H6.5a2 2 0 0 0-2 2v15a2 2 0 0 0 2 2h11a2 2 0 0 0 2-2V8ZM14 2.5V8h5.5"/>',
  check:      '<path d="M20 6.5 9.2 17.3 4 12.1"/>',
  checkTwice: '<path d="M1.5 12.4 6 16.9 15.2 7.7M12 16.9 21.7 7.2"/>',
  chevron:    '<path d="M6 9.5 12 15.5l6-6"/>',
};
// `title` is what a screen reader announces; without one the icon is decorative
// and hidden, because a button beside it already carries the label.
function icon(name, title){
  const path = ICONS[name];
  if(!path) return "";
  return '<svg class="ic" viewBox="0 0 24 24" ' +
    (title ? 'role="img"><title>' + esc(title) + "</title>"
           : 'aria-hidden="true">') + path + "</svg>";
}

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
// "1 node", "2 nodes". Written once so a count and its unit always agree — and
// so the unit is right there in the call, where a reader can check it.
function plural(count, word){ return count + " " + word + (count === 1 ? "" : "s"); }
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
// ---- the node this page is driving -----------------------------------------
// Empty means the one serving the page; set to another id, every call below
// carries it and the console relays the call over the mesh. One place to
// change, so no view can forget it and quietly act on the wrong machine.
//
// Three families are never relayed, and the far side refuses them anyway
// (`_CONSOLE_DENIED` in src/apps/fleet.py): `/api/fleet/`, because a managed
// node is not a jump host; `/api/remote/`, because that is the proxy driving
// the proxy; `/api/chat/`, because somebody else's conversations were never
// part of managing their machine. Signing in and out are this console's own.
// The rule is written on both sides on purpose — sending the header anyway
// would turn a designed refusal into a 403 every page has to explain.
const LOCAL_ONLY = ["/api/remote/", "/api/fleet/", "/api/chat/",
                    "/api/login", "/api/logout"];
const local = (path) => LOCAL_ONLY.some((prefix) => path.startsWith(prefix));

// A reply is stale when the node it came from is no longer the node on screen.
// Thrown rather than returned: every caller already has a catch, and the one
// thing none of them should do is paint it.
class StaleContext extends Error {
  constructor(){ super("the node being managed changed"); this.stale = true; }
}
const isStale = (error) => !!(error && error.stale);

const CONTEXT = {
  node: "", label: "",
  // Bumped on every switch. A request records it and its reply is dropped if
  // it no longer matches: a page that switched machines mid-flight used to
  // paint the one it had just left, and with auto-refresh off it stayed that
  // way. This is what makes the switch atomic rather than eventual.
  epoch: 0,
  listeners: [],

  get remote(){ return !!this.node; },

  // Remembered for this tab only — never localStorage. It is the same lifetime
  // as the session token it travels with, and a context that outlived the tab
  // would greet somebody with a machine they did not choose.
  save(){
    try{
      if(this.node) sessionStorage.setItem("nmesh_context",
                                           JSON.stringify({node:this.node, label:this.label}));
      else sessionStorage.removeItem("nmesh_context");
    }catch(_){}
  },

  restore(){
    try{
      const stored = JSON.parse(sessionStorage.getItem("nmesh_context") || "null");
      if(stored && /^[0-9a-f]{40}$/.test(stored.node || "")){
        this.node = stored.node;
        this.label = typeof stored.label === "string" ? stored.label : "";
      }
    }catch(_){}
    return this.node;
  },

  set(node, label){
    this.node = /^[0-9a-f]{40}$/.test(node || "") ? node : "";
    this.label = this.node ? (label || "") : "";
    this.epoch += 1;
    this.save();
    this.paint();
    this.listeners.forEach((fn) => { try{ fn(this); }catch(_){} });
  },

  // Called by anything that has to forget what it was holding. Registered
  // rather than called from one place, so a view added later cannot be the one
  // nobody remembered to reset.
  subscribe(fn){ this.listeners.push(fn); },

  // Hand the remote session back and return to this node. The local console
  // holds that session, so telling it to drop the session is what actually
  // ends the access — clearing the field would only hide it.
  async leave(){
    const left = this.node;
    if(!left) return;
    try{ await api("/api/remote/disconnect", "POST", {node:left}); }catch(_){}
    this.set("", "");
  },

  // A context restored from a reload is a claim, not a fact: the remote session
  // lives in the local console and may be gone. Check before believing it —
  // driving a node this console can no longer reach would fail every call with
  // nothing on screen to say why.
  async confirm(){
    if(!this.node) return;
    try{
      const {data} = await apiJson("/api/remote/targets");
      const target = (data.targets || []).find((entry) => entry.id === this.node);
      if(target && target.connected){
        if(target.label && target.label !== this.label) this.set(this.node, target.label);
        return;
      }
    }catch(_){}
    this.set("", "");
  },

  paint(){
    const shell = $("shell");
    if(shell) shell.classList.toggle("remote", this.remote);
    const bar = $("ctx-bar");
    if(bar) bar.hidden = !this.remote;
    const label = $("ctx-label");
    if(label) label.textContent = this.label || shortId(this.node);
    const id = $("ctx-id");
    if(id) id.textContent = this.node;
    // What this page can and cannot do for the node being managed. Chat and
    // fleet run here whatever is on screen (the far console refuses them), and
    // a bar that did not say so would be the whole point of the bar missed.
    const note = $("ctx-note");
    if(note) note.textContent = document.body.dataset.ctxLocal || "";
    document.body.dataset.appName = this.remote
      ? "NMesh — " + (this.label || shortId(this.node))
      : (document.body.dataset.appHome || document.body.dataset.appName || "NMesh");
  },
};

// `options.local` forces one call to this node whatever the console is driving.
// A view mounted inside a local app needs it: "what is my link to this person"
// is *this* node's question, and answering it from the machine being managed
// would be a different question with the same wording.
async function api(path, method, body, options){
  const headers = {};
  const at = CONTEXT.epoch;
  const here = local(path) || !!(options && options.local);
  if(TOKEN) headers.Authorization = "Bearer " + TOKEN;
  if(body !== undefined) headers["Content-Type"] = "application/json";
  if(CONTEXT.node && !here) headers["X-NMesh-Node"] = CONTEXT.node;
  const response = await fetch(path, {method: method || "GET", headers,
    body: body === undefined ? undefined : JSON.stringify(body)});
  if(response.status === 401){ SESSION.clear(); SESSION.onLost(); throw new Error("unauthorized"); }
  // A local call answers for this node whatever is on screen, so it is never
  // stale; everything else belongs to the node that was being driven when it
  // was asked for, and must not paint over the one that replaced it.
  if(!here && CONTEXT.epoch !== at) throw new StaleContext();
  return response;
}
async function apiJson(path, method, body, options){
  const response = await api(path, method, body, options);
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
    '<button class="icon sm" aria-label="Dismiss">' + icon("close") + "</button>";
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

// ---- opening another part of the product -----------------------------------
// A link from one app to another is not a navigation *away*: whoever clicked it
// was in the middle of something. So it opens beside what they were doing —
// except on a phone, where a 380px window is worse than useless and a tab is
// the native answer. Stored per browser like the theme, because it is a
// preference about this screen, not a property of the node.
const OPEN_MODES = ["auto", "window", "tab"];
const OPEN = {
  read(){
    try{
      const stored = localStorage.getItem("nmesh_open_mode");
      if(OPEN_MODES.includes(stored)) return stored;
    }catch(_){}
    return "auto";
  },
  set(mode){
    if(!OPEN_MODES.includes(mode)) return;
    try{ localStorage.setItem("nmesh_open_mode", mode); }catch(_){}
  },
  effective(){
    const mode = this.read();
    if(mode !== "auto") return mode;
    return (window.matchMedia && window.matchMedia("(max-width: 900px)").matches)
      ? "tab" : "window";
  },
};

function openLinked(url, name){
  if(OPEN.effective() === "tab"){ window.open(url, "_blank", "noopener"); return; }
  const width = Math.min(760, Math.max(420, Math.round(screen.availWidth * 0.5)));
  const height = Math.min(900, Math.max(480, Math.round(screen.availHeight * 0.8)));
  const opened = window.open(url, name || "nmesh-linked",
    "noopener,width=" + width + ",height=" + height);
  // Popup blocked, or a browser that refuses the feature string: a tab is a
  // worse fit but an infinitely better outcome than nothing happening.
  if(!opened) window.open(url, "_blank", "noopener");
}

// A list painted on a timer must not be rebuilt when nothing changed. It is not
// only waste: replacing a node under the pointer loses the click someone was
// making, drops focus out of the page, and closes whatever was open inside it.
// Comparing the string first is cheaper than the DOM work it avoids.
function setHTML(target, html){
  const element = typeof target === "string" ? $(target) : target;
  if(!element || element.innerHTML === html) return element;
  element.innerHTML = html;
  return element;
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
// A shape, not a chart: thirty numbers in the space of a word. Used wherever a
// series would otherwise be a single figure that hides how it got there.
function sparkHTML(values, options){
  const points = (values || []).filter((value) => value != null);
  if(points.length < 2) return "";
  const width = (options && options.width) || 84, height = (options && options.height) || 20;
  const high = Math.max(...points), low = Math.min(...points);
  const span = (high - low) || 1;
  const step = width / (points.length - 1);
  const path = points.map((value, index) =>
    (index ? "L" : "M") + (index * step).toFixed(1) + " " +
    (height - 1 - ((value - low) / span) * (height - 2)).toFixed(1)).join(" ");
  return '<svg class="spark" viewBox="0 0 ' + width + " " + height +
    '" width="' + width + '" height="' + height + '" aria-hidden="true">' +
    '<path d="' + path + '"/></svg>';
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
  // "system" is the absence of a choice, not a third value to store: a stored
  // "system" would stop following the system the day the default changes.
  choose(value){ this.set(value === "system" ? "" : value); },
  paint(){
    const button = $("theme-toggle"); if(!button) return;
    const dark = this.current() === "dark";
    // The button offers the theme you would switch *to*, so the sun shows
    // while the page is dark.
    setHTML(button, icon(dark ? "sun" : "moon"));
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

// ---- auto-refresh ----------------------------------------------------------
// How often a page re-reads the node. Zero means never, and that is a real
// answer: someone reading a table does not want it moving, and a node reached
// over an expensive link does not want to be polled at all.
//
// The contract for whoever supplies the job: a refresh **updates values**. It
// does not close what is open, does not drop a selection, and does not wipe a
// field being typed in. Losing a selection is legitimate in exactly one case —
// the thing selected is no longer there.
// ---- what changed, the moment it changes -----------------------------------
// A console on a timer is either late or wasteful: at two seconds a link that
// came up is invisible for two seconds, and at a tenth of a second it asks two
// hundred times a minute for nothing. So the node says when something moved
// (`GET /api/events`, one line per change) and the page reads only then.
//
// Two rules make that usable rather than frantic:
//
//   * **a frame.** However many events arrive, at most `FRAME` repaints a
//     second, and every event inside one frame is answered by one repaint. Ten
//     a second reads as instant; a hundred is a page that fights the pointer.
//   * **structure only.** Links, nodes, names, addressing — things that either
//     are or are not. Latency, jitter and throughput move constantly and by
//     tiny amounts, and they stay on the timer, because a repaint per
//     measurement says nothing new and costs the whole list.
//
// The stream is the local console's: it is a connection held open, and the
// fleet relay moves one bounded request and its answer. Driving another node
// therefore keeps the cadence, and `EVENTS.live` is how a page says which of
// the two it is on.
const EVENTS = {
  FRAME: 100,
  source: null,
  live: false,
  pending: new Set(),
  timer: null,
  handlers: {},
  onLive: null,

  // `topics` is a list of names, or "*" for anything at all.
  on(topics, fn){
    (Array.isArray(topics) ? topics : [topics]).forEach((topic) => {
      (this.handlers[topic] = this.handlers[topic] || []).push(fn);
    });
  },

  start(){
    this.stop();
    // Driving another node: there is nothing to listen to here, and pretending
    // otherwise would leave the page waiting on a stream that never speaks.
    if(CONTEXT.remote || typeof EventSource === "undefined"){ this.say(false); return; }
    let source;
    try{ source = new EventSource("/api/events"); }
    catch(_){ this.say(false); return; }
    this.source = source;
    source.addEventListener("ready", () => this.say(true));
    source.addEventListener("change", (event) => {
      let topics = [];
      try{ topics = (JSON.parse(event.data) || {}).topics || []; }catch(_){}
      topics.forEach((topic) => this.pending.add(topic));
      this.schedule();
    });
    // The browser reconnects on its own; what it cannot do is tell the page it
    // is currently blind. Saying so is what puts the timer back.
    source.addEventListener("error", () => this.say(false));
  },

  stop(){
    if(this.source){ this.source.close(); this.source = null; }
    if(this.timer){ clearTimeout(this.timer); this.timer = null; }
    this.pending.clear();
    this.say(false);
  },

  say(live){
    if(this.live === live) return;
    this.live = live;
    if(this.onLive) this.onLive(live);
  },

  schedule(){
    if(this.timer) return;      // a frame is already open; ride it
    this.timer = setTimeout(() => { this.timer = null; this.flush(); }, this.FRAME);
  },

  flush(){
    const topics = [...this.pending];
    this.pending.clear();
    if(!topics.length) return;
    const called = new Set();
    topics.concat("*").forEach((topic) => {
      (this.handlers[topic] || []).forEach((fn) => {
        if(called.has(fn)) return;    // one repaint per frame, not one per topic
        called.add(fn);
        try{ fn(topics); }catch(_){}
      });
    });
  },
};

const REFRESH = {
  MAX: 30,
  DEFAULT: 2,
  timer: null,
  job: null,

  read(){
    try{
      const stored = parseInt(localStorage.getItem("nmesh_refresh"), 10);
      if(Number.isFinite(stored)) return Math.min(this.MAX, Math.max(0, stored));
    }catch(_){}
    return this.DEFAULT;
  },

  write(seconds){
    try{ localStorage.setItem("nmesh_refresh", String(seconds)); }catch(_){}
  },

  clean(value){
    const seconds = parseInt(value, 10);
    if(!Number.isFinite(seconds)) return this.read();
    return Math.min(this.MAX, Math.max(0, seconds));
  },

  paint(seconds){
    const field = $("refresh-secs"), pick = $("refresh-pick"), box = $("refresh");
    if(field && String(field.value) !== String(seconds)) field.value = seconds;
    if(pick){
      // The phone's list is short on purpose; a value typed on a keyboard that
      // is not in it must not silently become one that is.
      if(![...pick.options].some((option) => option.value === String(seconds))){
        const extra = document.createElement("option");
        extra.value = String(seconds);
        extra.textContent = seconds + "s";
        pick.appendChild(extra);
      }
      pick.value = String(seconds);
    }
    if(box){
      box.classList.toggle("paused", seconds === 0);
      // Two different things, said in one place so they cannot contradict:
      // whether changes arrive by themselves, and how often the numbers that
      // never stop moving are re-read.
      const stream = EVENTS.live
        ? "Links and nodes update as they change. "
        : "Not streaming — everything is read on this interval. ";
      box.title = stream + (seconds === 0
        ? "The interval is off, so ping, jitter and throughput stand still."
        : "Ping, jitter and throughput every " + seconds + " seconds.");
    }
  },

  arm(seconds){
    if(this.timer){ clearInterval(this.timer); this.timer = null; }
    if(seconds > 0 && this.job) this.timer = setInterval(this.job, seconds * 1000);
  },

  set(value){
    const seconds = this.clean(value);
    this.write(seconds);
    this.paint(seconds);
    this.arm(seconds);
    return seconds;
  },

  stop(){
    if(this.timer){ clearInterval(this.timer); this.timer = null; }
    EVENTS.stop();
  },

  // The stream coming up or going down changes what the interval means, and the
  // control has to say so — a dot that only ever means "on" is decoration.
  live(streaming){
    const box = $("refresh");
    if(box) box.classList.toggle("streaming", !!streaming);
    this.paint(this.read());
  },

  // Called once the page has something to refresh. Runs the job immediately —
  // whoever mounts this wants the first paint now, whatever the interval — and
  // opens the change stream, which is what makes the interval a *statistics*
  // interval rather than the only thing keeping the page true.
  mount(job){
    this.job = job;
    const field = $("refresh-secs"), pick = $("refresh-pick"), now = $("refresh-now");
    if(field) field.addEventListener("change", (event) => this.set(event.target.value));
    if(pick) pick.addEventListener("change", (event) => this.set(event.target.value));
    // Off is a choice, not a dead end: one press still reads the node.
    if(now) now.addEventListener("click", () => { if(this.job) this.job(); });
    EVENTS.onLive = (streaming) => this.live(streaming);
    this.set(this.read());
    if(this.job) this.job();
    EVENTS.start();
  },
};

// ---- menus -----------------------------------------------------------------
// One controller for every popover in the chrome: a button carrying
// `data-menu="id"` opens the element with that id. Only one is ever open, it
// closes on Escape, on a click anywhere else, and — in sheet mode on a phone —
// on its own scrim, which is a pseudo-element and so reports the menu itself as
// the target. Anything that would otherwise stretch a bar belongs in one.
const MENU = {
  open: null,
  // id -> what to run when that menu is shown (a page registers its painter
  // here, so a list is built when it is looked at and not on every poll).
  onShow: {},
  show(id){
    const panel = $(id); if(!panel) return;
    this.close();
    panel.hidden = false;
    const button = document.querySelector('[data-menu="' + id + '"]');
    if(button) button.setAttribute("aria-expanded", "true");
    this.open = id;
    if(this.onShow[id]) this.onShow[id]();
  },
  close(){
    if(!this.open) return;
    const panel = $(this.open);
    if(panel) panel.hidden = true;
    const button = document.querySelector('[data-menu="' + this.open + '"]');
    if(button) button.setAttribute("aria-expanded", "false");
    this.open = null;
  },
  toggle(id){ if(this.open === id) this.close(); else this.show(id); },
  mount(){
    document.addEventListener("click", (event) => {
      const button = event.target.closest("[data-menu]");
      if(button){ this.toggle(button.dataset.menu); event.preventDefault(); return; }
      if(!this.open) return;
      const panel = $(this.open);
      // Inside the panel and not on the scrim, and not on something that asked
      // to close it: leave it open.
      if(panel && panel.contains(event.target) && event.target !== panel &&
         !event.target.closest("[data-menu-close]")) return;
      this.close();
    });
    document.addEventListener("keydown", (event) => {
      if(event.key === "Escape" && this.open){ this.close(); event.stopPropagation(); }
    });
  },
};

// ---- shell wiring ----------------------------------------------------------
// Done once here rather than per page: the chrome is the same everywhere, so it
// should not be three near-identical copies that drift.
function mountShell(){
  THEME.paint();
  const toggle = $("theme-toggle");
  if(toggle) toggle.addEventListener("click", () => THEME.toggle());

  MENU.mount();

  const nav = $("nav");
  if(nav){
    nav.addEventListener("click", (event) => {
      const button = event.target.closest("[data-tab]");
      if(!button) return;
      ROUTER.go(button.dataset.tab);
    });
    // The same list is a column in the rail and a row in the tab bar, so both
    // pairs of arrows have to walk it.
    nav.addEventListener("keydown", (event) => {
      const back = ["ArrowUp","ArrowLeft"].includes(event.key);
      if(!back && !["ArrowDown","ArrowRight"].includes(event.key)) return;
      const buttons = $$("[data-tab]", nav);
      const current = buttons.findIndex((b) => b.dataset.tab === ROUTER.section);
      const next = buttons[(current + (back ? -1 : 1) + buttons.length) % buttons.length];
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

  // The context is the page's, not this view's: restored before anything is
  // drawn, so nothing paints for the wrong machine on the way in, and checked
  // against the console that holds the session before it is believed.
  document.body.dataset.appHome = document.body.dataset.appName || "NMesh";
  CONTEXT.restore();
  CONTEXT.paint();
  const leave = $("ctx-leave");
  if(leave) leave.addEventListener("click", () => CONTEXT.leave());
}
"""
