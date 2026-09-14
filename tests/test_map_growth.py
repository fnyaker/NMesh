"""
Growing the link map past what this node can see.

The map a node draws from its own eyes stops at its neighbours and the sessions
it routes. Everything beyond that is **somebody else's knowledge**, and the
charter has one sentence about that: hearsay is never authority. So the question
this feature had to answer is not "how do we draw more nodes" but "how do we
show a claim without it being mistaken for a measurement".

The answers, and these tests:

* it is asked for, never pushed — one machine, one call, when an operator
  presses a button;
* it is only ever asked of a machine the operator already **manages**, through
  the console relay that remote management uses, and only fleet offers it —
  growing a map is driving another machine's console under another name;
* what comes back is kept **apart**: its own store in the browser, its own line
  style, its own word in the panel, who reported it, and an expiry;
* and it never reaches the node. Nothing here is stored, gossiped or acted on:
  a claim about who is connected to whom must not become something this console
  keeps.
"""
import re

import pytest

from src import webassets

JS = webassets.APP_JS


def _block(name, until):
    return JS.split(name)[1].split(until)[0]


class TestAClaimIsNeverAMeasurement:
    def test_reported_links_are_drawn_as_claims(self):
        css = webassets.STYLE_CSS
        assert ".mesh-graph .edge.reported" in css
        assert "stroke-dasharray" in _css_rule(css, ".mesh-graph .edge.reported")
        # Hollow, faint: nothing this node measured looks like this.
        assert "fill:none" in _css_rule(
            css, ".mesh-graph .node.reported circle:not(.hit)")

    def test_every_reported_edge_says_who_said_it(self):
        block = _block("grown.edges.forEach", "const dot =")
        assert '"said by " + shortId(edge.from)' in block
        # And the label is *not* a latency: we did not measure this one.
        assert "rtt" not in block

    def test_the_legend_names_the_third_layer(self):
        assert "reported by a machine you manage" in webassets.INDEX_HTML

    def test_a_reported_row_carries_its_age_and_its_author(self):
        block = _block('setHTML("map-reported"', 'setHTML("map-links"')
        assert "said by" in block and "fmtAgo" in block


class TestItIsAskedForAndBounded:
    def test_growth_is_bounded_on_every_axis(self):
        book = _block("const MAP_GROWTH = {", "let MAP_NAMES")
        for bound in ("MAX_NODES", "MAX_EDGES", "TTL", "ASK_EVERY"):
            assert bound in book, f"the map's growth has no {bound}"
        # The oldest goes when the store is full, rather than the store growing.
        assert "this.nodes.delete(this.nodes.keys().next().value)" in book
        assert "this.edges.delete(this.edges.keys().next().value)" in book

    def test_a_report_expires_on_its_own(self):
        book = _block("const MAP_GROWTH = {", "let MAP_NAMES")
        sweep = book.split("sweep(){")[1].split("},")[0]
        assert "this.edges.delete" in sweep and "this.nodes.delete" in sweep

    def test_one_machine_is_asked_at_most_once_in_a_while(self):
        book = _block("const MAP_GROWTH = {", "let MAP_NAMES")
        assert "mayAsk(id)" in book
        grow = _block("async function growFrom", "$(\"map-grow-list\")")
        assert "MAP_GROWTH.mayAsk(id)" in grow

    def test_asking_them_all_is_one_at_a_time(self):
        """Forty console calls at once is a burst this node would be the source
        of, which is the shape of an amplifier seen from the inside."""
        block = _block('$("map-grow-all")', '$("map-grow-clear")')
        assert "for(const target of MAP_TARGETS)" in block
        assert "await growFrom" in block

    def test_what_a_machine_answers_is_bounded_before_it_is_kept(self):
        book = _block("const MAP_GROWTH = {", "let MAP_NAMES")
        absorb = book.split("absorb(from, topology){")[1].split("remember(id")[0]
        assert ".slice(0, 64)" in absorb, "a machine's answer is not bounded"
        assert 'typeof peer.id !== "string"' in absorb


class TestOnlyThroughAMachineTheOperatorManages:
    def test_the_page_asks_fleet_and_only_fleet(self):
        block = _block("async function loadMapExtras", "function paintGrow")
        assert 'app:"fleet"' in block
        # No second app, and no route of its own: it goes through the plane's
        # one door like everything else.
        assert "/api/" not in block

    def test_a_machine_with_no_session_is_not_offered_a_button(self):
        block = _block("function paintGrow", "async function growFrom")
        assert "target.connected || target.passwordless" in block
        assert "needs its password" in block

    def test_fleet_offers_the_targets_from_its_own_ledger(self):
        from src.apps.fleet_web import FleetBridge

        source = FleetBridge.api_map_targets.__doc__ or ""
        assert "manage" in source and "passwordless" in source

    def test_the_map_grows_only_on_the_console_you_are_at(self):
        """Neither question acts, so letting them travel looks harmless. It is
        not: together they hand a remote operator the list of machines this node
        manages and can reach, which is how a node somebody manages becomes a
        way to reach the nodes it manages."""
        from src.apps.fleet_web import FleetBridge

        travelling = {entry["name"] for entry in FleetBridge.API
                      if entry.get("remote")}
        assert "map_targets" not in travelling
        assert "map_overlay" not in travelling

    def test_growing_never_moves_the_operators_context(self):
        """A map that had to leave the node on screen and come back between
        every question would be a map nobody uses twice."""
        channel = webassets.APP_JS
        frame = channel.split("async frame(op, params, options){")[1] \
                       .split("// The answer, or a throw")[0]
        assert "opts.node" in frame
        assert 'headers["X-NMesh-Node"] = opts.node' in frame
        # And a far machine being slow says nothing about the console on screen.
        assert "!here && !elsewhere) this.judge(reply)" in frame


class TestNothingReachesTheNode:
    def test_the_growth_lives_only_in_the_page(self):
        """No route, no operation, no node state: a claim about who is
        connected to whom must not become something this console keeps."""
        import pathlib

        root = pathlib.Path(__file__).resolve().parent.parent
        for name in ("src/node.py", "src/webconsole.py"):
            text = (root / name).read_text()
            assert "MAP_GROWTH" not in text
            assert "reported_edges" not in text

    def test_a_reported_edge_is_dropped_once_we_can_see_it_ourselves(self):
        """Our own link and a claim about the same link are one link. Drawing
        both would say the mesh is twice the size it is."""
        book = _block("const MAP_GROWTH = {", "let MAP_NAMES")
        view = book.split("view(state){")[1]
        assert "known.has(edge.a) && known.has(edge.b)" in view

    def test_the_operator_can_forget_all_of_it(self):
        block = _block('$("map-grow-clear")', "// The drawing and the list")
        assert "MAP_GROWTH.clear()" in block


class TestFleetsWordsRatherThanThePages:
    def test_badges_are_rendered_not_invented(self):
        block = _block("function overlayBadges", "// The drawing and the list")
        assert "row.badges" in block
        # The page holds no idea of what any of them mean.
        for word in ("managed", "govern", "log"):
            assert f'"{word}"' not in block

    def test_fleet_says_what_it_knows_about_each_node(self):
        from src.apps.fleet_state import FleetState
        from src.apps.fleet_web import FleetBridge

        class _App:
            state = FleetState()
            node_id = None

            def following(self):
                return []

        bridge = FleetBridge.__new__(FleetBridge)
        bridge._app = _App()
        bridge._app.state.add_managed("ab" * 20, caps=["logs", "manage"],
                                      label="lab")
        overlay = FleetBridge.api_map_overlay(bridge)["nodes"]
        assert overlay["ab" * 20]["badges"] == ["managed"]
        assert overlay["ab" * 20]["label"] == "lab"

    def test_a_node_that_controls_this_one_outranks_everything_it_says(self):
        from src.apps.fleet_state import FleetState
        from src.apps.fleet_web import FleetBridge

        class _App:
            state = FleetState()

            def following(self):
                return []

        bridge = FleetBridge.__new__(FleetBridge)
        bridge._app = _App()
        node = "cd" * 20
        bridge._app.state.add_managed(node, caps=["status"])
        bridge._app.state.add_operator(node, b"a key", caps=["manage"])
        row = FleetBridge.api_map_overlay(bridge)["nodes"][node]
        assert "controls this node" in row["badges"]
        assert row["tone"] == "warn"


def _css_rule(css, selector):
    match = re.search(re.escape(selector) + r"\s*\{([^}]*)\}", css)
    assert match, f"{selector} is not in the stylesheet"
    return match.group(1)
