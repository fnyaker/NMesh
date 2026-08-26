"""The console's assets are Python strings: nothing compiles them.

A syntax error in the JS does not break one test, it breaks the *whole* console
at runtime — a blank page, with no message. Those checks are therefore made
here, at build time.
"""
import pathlib
import re
import shutil
import subprocess
import tempfile

import pytest

from src import webassets
from src.webassets import ui

NODE = shutil.which("node")

SCRIPTS = ("APP_JS", "CHAT_JS", "FLEET_JS", "NODE_JS")


@pytest.mark.skipif(NODE is None, reason="node is needed to parse the JS")
@pytest.mark.parametrize("name", SCRIPTS)
def test_the_script_parses(name):
    source = getattr(webassets, name)
    with tempfile.NamedTemporaryFile("w", suffix=".js", encoding="utf-8") as handle:
        handle.write(source)
        handle.flush()
        result = subprocess.run([NODE, "--check", handle.name],
                                capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr


# XML namespace URIs (`http://www.w3.org/...`) are identifiers, not addresses to
# load: `createElementNS` never goes to the network.
_NAMESPACE_URIS = ("http://www.w3.org/", "http://www.w3.org/1999/xhtml")


@pytest.mark.parametrize("name", SCRIPTS)
def test_no_external_resource_is_pulled_in(name):
    """The console is offline by construction: nothing may be loaded from a
    third party — no script, no font, no image."""
    import re
    source = getattr(webassets, name)
    for match in re.finditer(r'https?://[^\s"\'`)]*', source):
        url = match.group(0)
        assert url.startswith(_NAMESPACE_URIS), url


def test_every_element_the_scripts_reach_for_exists():
    """A `$("id")` that matches nothing throws at load and takes the rest of the
    script with it."""
    import re
    pages = {"APP_JS": "INDEX_HTML", "CHAT_JS": "CHAT_HTML",
             "FLEET_JS": "FLEET_HTML", "NODE_JS": "NODE_HTML"}
    for script_name, html_name in pages.items():
        html = getattr(webassets, html_name)
        # Only the page's own part: the shared runtime keeps every access behind
        # an `if(element)`, precisely because not every page carries the whole
        # shell.
        source = getattr(webassets, script_name)[len(webassets.ui.JS):]
        # Only the literal accesses at load time: dynamically built ones target
        # elements the script creates itself.
        for match in re.finditer(r'\$\("([a-z0-9-]+)"\)\.addEventListener', source):
            element = match.group(1)
            # An id the script mints itself (injected markup) has no business
            # being in the static page.
            if f'id="{element}"' in source:
                continue
            assert f'id="{element}"' in html, f"{script_name}: {element}"


# ── the terminal emulator ───────────────────────────────────────────────────
# Written rather than taken as a dependency (a shell where you type `sudo` needs
# a terminal, not a log pane). So it is on us to prove it reads correctly what a
# real shell writes.

TERM_SUITE = pathlib.Path(__file__).with_name("term_emulator_test.js")


def _terminal_source() -> str:
    body = webassets.FLEET_JS.split("// ---- a small terminal")[1]
    return "// ---- a small terminal" + body.split("// ---- shell ----")[0]


@pytest.mark.skipif(NODE is None, reason="node is needed to run the JS")
def test_the_terminal_reads_back_what_a_shell_writes(tmp_path):
    source = tmp_path / "term.js"
    source.write_text(_terminal_source(), encoding="utf-8")
    result = subprocess.run([NODE, str(TERM_SUITE), str(source)],
                            capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, result.stdout + result.stderr


def test_the_terminal_never_renders_unescaped_markup():
    """The output comes from a remote machine: it is written into the DOM as
    innerHTML, so escaping is not cosmetic."""
    source = _terminal_source()
    assert "escHtml" in source
    assert 'replace(/&/g,"&amp;")' in source


def test_the_terminal_pane_takes_real_keystrokes():
    """A line-by-line text field would show a password in the clear; raw
    keystrokes let the remote pty decide what comes back."""
    assert 'addEventListener("keydown"' in webassets.FLEET_JS
    assert "function keyBytes" in webassets.FLEET_JS
    assert 'tabindex="0"' in webassets.FLEET_HTML


def test_the_rights_panel_is_wired_to_a_real_element():
    """The "who can control this node" view is the only place a right is added:
    if its container is missing, it disappears silently."""
    assert 'id="operators"' in webassets.FLEET_HTML
    assert 'data-tab="access"' in webassets.FLEET_HTML
    assert "function paintOperators" in webassets.FLEET_JS
    for route in ("/api/fleet/caps-set", "/api/fleet/caps-request",
                  "/api/fleet/caps-drop"):
        assert route in webassets.FLEET_JS, route


# ── the strict CSP, applied to the assets themselves ────────────────────────
# `default-src 'self'` without `unsafe-inline`: a `style=` attribute is ignored
# by the browser **silently**. A progress bar written that way never fills and
# nobody sees an error. CSSOM assignments (`element.style.x = …`) are not
# covered and stay allowed.

STYLE_ATTRIBUTE = re.compile(r"""style\s*=\s*["']""")


@pytest.mark.parametrize("name", ["INDEX_HTML", "CHAT_HTML", "FLEET_HTML",
                                  "NODE_HTML", "APP_JS", "CHAT_JS", "FLEET_JS",
                                  "NODE_JS", "STYLE_CSS", "CHAT_CSS",
                                  "FLEET_CSS", "NODE_CSS"])
def test_no_inline_style_attribute_anywhere(name):
    source = getattr(webassets, name)
    # The comment explaining the rule is allowed to quote it.
    lines = [line for line in source.splitlines()
             if STYLE_ATTRIBUTE.search(line) and "attribute silently" not in line]
    assert not lines, f"{name}: inline style attribute — {lines[:2]}"


def test_the_console_still_forbids_inline_anything():
    """If the CSP were relaxed, the rule above would lose its meaning."""
    from src.webconsole import _SECURITY_HEADERS
    policy = _SECURITY_HEADERS["Content-Security-Policy"]
    assert "default-src 'self'" in policy
    assert "unsafe-inline" not in policy


def test_every_page_offers_a_skip_link_and_a_focus_ring():
    """Two keyboard guarantees that are lost without anyone noticing: skipping
    the rail to reach the content, and seeing where the focus is."""
    for html in (webassets.INDEX_HTML, webassets.CHAT_HTML, webassets.FLEET_HTML):
        assert 'class="skip"' in html
        assert 'id="main"' in html
    for css in (webassets.STYLE_CSS, webassets.CHAT_CSS, webassets.FLEET_CSS,
                webassets.NODE_CSS):
        assert ":focus-visible{outline:2px solid var(--ring)" in css


def test_the_three_pages_share_one_design_system():
    """The package's contract: one source for the tokens, the components and the
    runtime. If a page stopped loading it, it would diverge silently."""
    for css in (webassets.STYLE_CSS, webassets.CHAT_CSS, webassets.FLEET_CSS,
                webassets.NODE_CSS):
        assert css.startswith(webassets.ui.CSS)
    for script in (webassets.APP_JS, webassets.CHAT_JS, webassets.FLEET_JS,
                   webassets.NODE_JS):
        assert script.startswith(webassets.ui.JS)


def test_the_two_maps_share_one_drawing_routine():
    """The small map and the expanded map are the same function at two sizes.
    Two implementations would diverge at the first change."""
    source = webassets.APP_JS
    assert "function renderGraph(" in source
    assert source.count("function renderGraph(") == 1
    assert "GRAPH_SMALL" in source and "GRAPH_BIG" in source
    assert 'id="map-dialog"' in webassets.INDEX_HTML
    assert 'class="mesh-graph"' in webassets.INDEX_HTML


def test_the_console_renders_whatever_a_transport_reports():
    """A transport's counters are displayed under their own names: the console
    knows neither "retransmits" nor "SNR", and that is the point."""
    source = webassets.APP_JS
    assert "statsHTML(link)" in source
    assert "Object.entries(stats)" in source


# ── narrow navigation and the menus ─────────────────────────────────────────
# Each of these tests matches a bug really met in a real browser: they are here
# so it does not come back.

PAGES = {"INDEX_HTML": "APP_JS", "CHAT_HTML": "CHAT_JS", "FLEET_HTML": "FLEET_JS",
         "NODE_HTML": "NODE_JS"}


@pytest.mark.parametrize("html_name", list(PAGES))
def test_every_menu_starts_closed(html_name):
    """A `.menu` panel with no `hidden` attribute shows at load and intercepts
    the clicks of the button meant to open it."""
    html = getattr(webassets, html_name)
    for match in re.finditer(r'<div id="([a-z-]+)" class="menu"([^>]*)>', html):
        assert "hidden" in match.group(2), match.group(1)


@pytest.mark.parametrize("html_name", list(PAGES))
def test_every_menu_button_points_at_a_panel(html_name):
    html = getattr(webassets, html_name)
    for match in re.finditer(r'data-menu="([a-z-]+)"', html):
        assert f'id="{match.group(1)}" class="menu"' in html, match.group(1)


@pytest.mark.parametrize("html_name", ["INDEX_HTML", "FLEET_HTML"])
def test_every_tab_has_a_short_name_for_the_tab_bar(html_name):
    """In the tab bar the long label is hidden and `data-label` takes its place
    through `::before`: without it, the tab is empty."""
    html = getattr(webassets, html_name)
    # The main navigation only: a section's subtabs do not go down into the
    # bottom bar.
    tabs = re.findall(r'<button role="tab"[^>]*data-tab="[^"]+".*?</button>', html, re.S)
    assert tabs
    for tab in tabs:
        assert 'data-label="' in tab, tab
        # The long label must be wrapped, or there is nothing to hide.
        assert '<span class="lbl">' in tab, tab[:90]


def test_the_topbar_does_not_capture_its_own_menus():
    """`backdrop-filter` on an element makes it the containing block for every
    `position:fixed` descendant: the notification sheet then anchored under the
    bar instead of the bottom of the screen. The blur lives on a pseudo-element."""
    block = ui.SHELL.split(".topbar{", 1)[1].split("}", 1)[0]
    assert "backdrop-filter" not in block
    assert "backdrop-filter" in ui.SHELL.split(".topbar::before{", 1)[1].split("}", 1)[0]


def test_the_overflow_button_defaults_to_hidden_before_the_query_shows_it():
    """At equal specificity the last rule wins — media query or not. The default
    must therefore be declared before the query that turns it on."""
    default = ui.SHELL.index(".more-wrap{display:none}")
    shown = ui.SHELL.index(".more-wrap{display:inline-flex}")
    assert default < shown


def test_the_tab_bar_hides_what_cannot_fit_and_the_page_ends_above_it():
    narrow = ui.SHELL.split("@media (max-width:900px){", 1)[1]
    assert ".rail .brand,.rail .rail-foot" in narrow
    assert "--tabbar-h" in narrow


# ── one node view, shared ───────────────────────────────────────────────────
# It is mounted in two places: the console's dialog and the `/node` page chat
# and fleet open. Two copies drifting apart was the other option; these tests
# are here so we do not fall back into it.

def test_one_node_view_mounted_twice_and_never_copied():
    for script in (webassets.APP_JS, webassets.NODE_JS):
        assert "const NODEVIEW = {" in script
        assert script.count("const NODEVIEW = {") == 1
    assert 'NODEVIEW.mount("node-detail"' in webassets.APP_JS
    assert 'NODEVIEW.mount("view"' in webassets.NODE_JS


def test_the_view_only_offers_what_an_app_declares():
    """A button calling an app that is not there must not be drawn: the view
    reads the catalogue before deciding what to offer."""
    source = webassets.NODE_JS
    assert '"/api/app-api"' in source
    assert 'this.has("chat", "peer")' in source
    assert 'this.has("fleet", "relation")' in source


def test_the_view_hides_the_button_pointing_back_where_it_came_from():
    source = webassets.NODE_JS
    assert 'get("from")' in source
    assert 'hide.indexOf("chat")' in source and 'hide.indexOf("fleet")' in source


def test_the_addresses_are_folded_away_by_default():
    """The "which addresses" question comes after "is this link healthy?". An
    unfolded table pushed the answers below the fold."""
    source = webassets.NODE_JS
    assert 'foldHTML("Addresses"' in source
    assert "<details class=\\\"card\\\"><summary>" in source or \
           '<details class="card"><summary>' in source


# ── the journeys from one app to another ────────────────────────────────────

def test_every_page_mounts_the_same_view_and_hides_the_way_it_came():
    """The button leading back where you came from is not drawn: from chat we do
    not offer chat, from fleet we do not offer fleet."""
    assert 'NODEVIEW.mount("peer-view"' in webassets.CHAT_JS
    assert 'hide:["chat"]' in webassets.CHAT_JS
    assert 'NODEVIEW.mount("fleet-node-view"' in webassets.FLEET_JS
    assert 'hide:["fleet"]' in webassets.FLEET_JS


def test_chat_can_show_a_node_beside_a_window_or_a_tab():
    assert 'id="peer-panel"' in webassets.CHAT_HTML
    assert 'id="set-details"' in webassets.CHAT_HTML
    for mode in ('value="panel"', 'value="window"', 'value="tab"'):
        assert mode in webassets.CHAT_HTML, mode
    # Leaving chat goes through the page, not through a frame.
    assert 'openLinked("/node?from=chat#"' in webassets.CHAT_JS


def test_the_console_keeps_its_browser_preferences_in_the_browser():
    """The theme and the open mode are not the node's settings: two machines
    connected to the same console each keep their own."""
    assert 'data-subtab="appearance"' in webassets.INDEX_HTML
    assert 'id="pref-open"' in webassets.INDEX_HTML and 'id="pref-theme"' in webassets.INDEX_HTML
    assert 'localStorage.getItem("nmesh_open_mode")' in webassets.ui.JS
    assert "/api/pref" not in webassets.APP_JS


# ── layout that cannot overflow ─────────────────────────────────────────────
# Both of these were real: a long message made the chat page scroll sideways on
# a phone, and every bubble in the log was crushed to 20px so the conversation
# could not be read at all.

def _tracks(value: str):
    """Split a `grid-template-columns` value into its tracks. Tracks are
    separated by spaces; commas only ever appear inside a function."""
    out, current, depth = [], "", 0
    for ch in value:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == " " and depth == 0:
            if current:
                out.append(current)
            current = ""
        else:
            current += ch
    if current:
        out.append(current)
    return out


@pytest.mark.parametrize("name", ["STYLE_CSS", "CHAT_CSS", "FLEET_CSS", "NODE_CSS"])
def test_no_grid_track_takes_its_minimum_from_its_content(name):
    """A bare `1fr` track is sized `minmax(auto,1fr)`, and that `auto` minimum is
    the content's *min-content* width. One pasted URL in such a track is one very
    long word, and the whole page grows wider than the screen — which is exactly
    how a long chat message made a phone scroll sideways.

    `minmax(0,1fr)` says the track may shrink to nothing, so the content wraps or
    scrolls inside it instead of pushing the page."""
    css = getattr(webassets, name)
    for match in re.finditer(r"grid-template-columns:([^;}]+)", css):
        for track in _tracks(match.group(1).strip()):
            assert not re.fullmatch(r"[\d.]*fr", track), (name, match.group(1))


def test_the_chat_log_cannot_squash_its_messages():
    """The log is a flex column. Flex children shrink by default, so once the
    messages were taller than the pane the browser shrank every one of them
    instead of scrolling: bubbles crushed to a fraction of their height,
    overlapping each other, and nothing readable. `flex:none` is the whole fix
    and it must stay."""
    assert ".ch-log>*{flex:none}" in webassets.CHAT_CSS


def test_the_chat_shell_clips_instead_of_scrolling_sideways():
    """The backstop behind the two rules above: if a future change reintroduces
    an overflow, the page clips it. A visible bug beats an unusable one."""
    assert re.search(r"\.ch\{[^}]*overflow:hidden", webassets.CHAT_CSS)


def test_arbitrary_text_in_chat_wraps_rather_than_widening():
    """A 300-character word and a pasted URL are the same thing to a layout
    engine: one unbreakable token. Everything that receives message text says how
    to break it.

    `break-word` and not `anywhere`: both break the token, but `anywhere` also
    counts those breaks in the box's intrinsic width, which collapses a
    shrink-to-fit bubble towards a single character."""
    for rule in (".ch-bubble{", ".ch-txt{"):
        block = webassets.CHAT_CSS.split(rule, 1)[1].split("}", 1)[0]
        assert "overflow-wrap:break-word" in block, rule
    # …and the flex children holding it may actually become that narrow.
    assert "min-width:0" in webassets.CHAT_CSS.split(".ch-bubble{", 1)[1].split("}", 1)[0]


def test_the_message_width_cap_hangs_off_something_definite():
    """A percentage `max-width` needs a containing block with a width to be a
    percentage *of*. Capping the bubble instead of the row put the percentage
    against a row that was itself shrink-to-fit — circular, and the browser
    resolves it by undersizing: a three-line message wrapped inside a bubble
    with room to spare. The cap sits on the row, which is a flex item of the log
    and therefore has a definite width."""
    row = webassets.CHAT_CSS.split(".ch-m{", 1)[1].split("}", 1)[0]
    bubble = webassets.CHAT_CSS.split(".ch-bubble{", 1)[1].split("}", 1)[0]
    assert "max-width:var(--page-bubble-max)" in row
    assert "max-width" not in bubble


def test_the_chat_page_does_not_redefine_the_design_system():
    """`.msg` is a form message in :mod:`.ui`; chat used the same name for a
    message bubble, so one page quietly changed a shared component for itself.
    Everything of chat's own is prefixed, and the prefix is what keeps that from
    happening again."""
    own = webassets.CHAT_PAGE_CSS
    for selector in re.finditer(r"(?m)^\.([a-z][a-z0-9-]*)", own):
        name = selector.group(1)
        assert name.startswith("ch-") or name == "ch", name


def test_a_list_painted_on_a_timer_is_not_rebuilt_for_nothing():
    """Replacing a row under the pointer loses the click in progress, and resets
    the scroll under the reader. Lists repainted on the poll write only what
    actually changed — either by writing the whole list through ``setHTML``, or,
    where the rows are long-lived, by keying them and rewriting one row."""
    assert "function setHTML(" in webassets.ui.JS
    for source, holder in ((webassets.FLEET_JS, '"nodes"'),
                           (webassets.FLEET_JS, '"operators"'),
                           (webassets.FLEET_JS, '"inbox"')):
        assert "setHTML(" + holder in source, holder
    # Chat keys both of its lists, because both are repainted every 1.2s and one
    # of them is a conversation somebody is reading.
    for marker in ("setHTML(el, rowHTML(it))",     # the conversation list
                   "setHTML(el, html)",            # one message
                   "if(next !== el) host.insertBefore(el, next)"):
        assert marker in webassets.CHAT_JS, marker


# ── auto-refresh, and what a refresh is not allowed to do ────────────────────

def test_the_refresh_interval_is_a_number_here_and_a_list_there():
    """A number field is the right control on a keyboard and the wrong one on a
    phone (a 12 px target, a keyboard covering the page)."""
    for html in (webassets.INDEX_HTML, webassets.FLEET_HTML):
        assert 'id="refresh-secs"' in html and 'type="number"' in html
        assert 'max="30"' in html
        assert 'id="refresh-pick"' in html
        assert 'value="0">Off' in html
        # Off is not a dead end: one press still reads the node.
        assert 'id="refresh-now"' in html
    narrow = webassets.ui.CSS.split("@media (max-width:720px){", 1)[1]
    assert ".refresh select{display:block}" in narrow


def test_the_interval_is_clamped_and_remembered_in_the_browser():
    source = webassets.ui.JS
    assert 'localStorage.getItem("nmesh_refresh")' in source
    assert "Math.min(this.MAX, Math.max(0, seconds))" in source
    assert "/api/refresh" not in webassets.APP_JS      # not a setting of the node


def test_a_refresh_repaints_values_without_rebuilding_what_is_open():
    """The contract: a refresh updates values. Lists repainted on the poll go
    through `setHTML`, which writes only when the content changed."""
    source = webassets.APP_JS
    for holder in ('"network-summary"', '"map-links"'):
        assert "setHTML(" + holder in source, holder
    assert "setHTML(body," in source          # the peer tables


def test_only_a_vanished_thing_may_be_deselected():
    source = webassets.APP_JS
    assert "if(MAP_PICK && !direct.some(" in source
    assert "if(!group || group.links.length < 2) unfolded.delete(id)" in source


# ── active links, grouped by node ───────────────────────────────────────────

def test_active_links_are_one_row_per_node_openable_onto_its_links():
    source = webassets.APP_JS
    assert "function groupByNode(" in source
    assert "const LINKS_OPEN = {active: new Set(), known: new Set()}" in source
    # The yardstick shown is the best link, and the jitter is *its own*.
    assert "group.best == null || rtt < group.best.rtt_ms" in source
    assert "data-fold=" in source


# ── the map and its list ────────────────────────────────────────────────────

def test_the_map_and_its_list_share_one_selection():
    source = webassets.APP_JS
    assert "MAP_PICK = MAP_PICK === id ? null : id" in source
    assert "function revealPick(" in source
    assert "data-link-details=" in source


def test_a_captured_pointer_does_not_swallow_the_click_on_a_node():
    """Capturing the pointer (so a drag survives leaving the element) also
    retargets the `click` onto the capturing element: without remembering the
    target at pointerdown, clicking a node no longer reached the node."""
    source = webassets.APP_JS
    assert "let MAP_DOWN_ON = null" in source
    assert "MAP_DOWN_ON = (event.target.closest" in source
    assert "const node = MAP_DOWN_ON ||" in source


def test_a_node_on_the_map_has_a_target_a_finger_can_hit():
    source = webassets.APP_JS
    assert 'class:"hit"' in source
    assert "Math.max(size.r * 2.2, 18)" in source
    assert "circle.hit{fill:transparent" in webassets.STYLE_CSS


# ── releases published by nodes ─────────────────────────────────────────────
# The page must not re-derive who may install what: the node hands each row its
# own state and the verb to POST.

def test_the_release_rows_render_what_the_node_decided():
    source = webassets.APP_JS
    assert "function releaseRowHTML(" in source
    assert 'entry.action === "install"' in source
    # No version comparison in JavaScript — that rule lives in Python.
    assert "is_newer" not in source and "compareVersions" not in source


def test_an_unpinned_publisher_is_shown_without_an_install_button():
    source = webassets.APP_JS
    assert 'untrusted:"publisher not pinned"' in source
    assert 'entry.trusted ?' in source


def test_installing_a_release_asks_first():
    """Replacing the node's own code is not a button you press by accident."""
    source = webassets.APP_JS
    block = source.split('data-install', 1)[1]
    assert "confirmAction(" in block
    assert '"/api/releases/install"' in source and "confirm:true" in source


def test_pinning_a_publisher_is_the_only_way_a_key_gets_in():
    html, source = webassets.INDEX_HTML, webassets.APP_JS
    assert 'id="pin-key"' in html and 'id="pin-add"' in html
    assert '"/api/releases/trust"' in source
    # Trusting and auto-installing are two controls, not one.
    assert 'id="pin-auto"' in html and '"/api/releases/auto"' in source


def test_the_node_offers_its_own_publisher_key_to_copy():
    assert 'id="publish-key"' in webassets.INDEX_HTML
    assert 'data.publisher_key' in webassets.APP_JS


def test_no_release_action_can_end_mid_sentence():
    """A status left on "Reading, hashing and signing…" is indistinguishable
    from a node that died. Every one of these ends in a message, including when
    the call itself fails — a restart cuts the connection mid-answer, so this is
    a path that really happens."""
    source = webassets.APP_JS
    for route in ('"/api/releases/publish"', '"/api/releases/install"',
                  '"/api/releases/trust"'):
        call = source.index(route)
        window = source[call - 400:call + 700]
        assert "catch(" in window, route


# ── what belongs to a transport lives in that transport ─────────────────────

def test_transport_facts_left_the_node_card():
    assert 'id="relay-state"' not in webassets.INDEX_HTML
    source = webassets.APP_JS
    assert "const SCHEME_FACTS = {" in source
    assert '"Public IP"' in source and '"Public UDP"' in source
    # The node's card keeps only what is true of the node.
    summary = source.split('const summary = [', 1)[1].split("];", 1)[0]
    assert '"Internet"' in summary and '"Pending seeks"' in summary
    assert "public_ip" not in summary and "stun_addr" not in summary


def test_a_transport_opens_on_its_status_then_its_settings():
    source = webassets.APP_JS
    assert 'data-view="status"' in source and 'data-view="settings"' in source
    assert 'data-panel="status"' in source and 'data-panel="settings"' in source
    # The chosen view survives a redraw, like the fold.
    assert "views[scheme] || \"status\"" in source
