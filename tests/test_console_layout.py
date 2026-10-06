"""
The console holds still, says what it measured, and shows a person what they
came for.

Four complaints, each one a rule here rather than a fix that could quietly come
undone:

* the permission list could not be scrolled — a flex child of a scrolling body
  shrank instead, and its own `overflow:hidden` clipped the rest;
* numbers moved the page: a rate in a card header grew a digit, wrapped, and
  the card grew a line;
* the throughput graph had lines and no figures on them;
* the speed test measured and then showed nothing — the answer was read with
  the wrong shape and every result became "the speed test failed".

And the simple/expert split: one attribute, set before the first paint, that
decides what is shown and never what the node does.
"""
import pathlib
import shutil
import subprocess

import pytest

from src import webassets

NODE = shutil.which("node")
ROOT = pathlib.Path(__file__).resolve().parent.parent


class TestADialogScrolls:
    def test_a_sheet_body_scrolls_rather_than_squeezing_its_children(self):
        css = webassets.ui.CSS
        assert ".sheet-body>*{flex:none}" in css
        block = css.split(".sheet-body{", 1)[1].split("}", 1)[0]
        assert "overflow-y:auto" in block

    def test_the_permission_list_lives_in_one(self):
        html = webassets.console.INDEX_HTML
        dialog = html.split('<dialog id="perm-dialog"', 1)[1].split("</dialog>", 1)[0]
        body = dialog.split('class="sheet-body', 1)[1]
        assert 'id="perm-body"' in body


class TestNumbersDoNotMoveThePage:
    def test_a_stat_value_cannot_wrap_or_widen_its_tile(self):
        block = webassets.ui.CSS.split(".stat .v{", 1)[1].split("}", 1)[0]
        assert "white-space:nowrap" in block
        assert "tabular-nums" in block

    def test_the_live_rates_are_not_in_a_card_header(self):
        """A header badge that grew a digit wrapped the head a line taller."""
        html = webassets.console.INDEX_HTML
        assert 'id="rate-now"' not in html
        legend = html.split('class="chart-legend', 1)[1].split("</div>", 1)[0]
        for name in ("rate-in", "rate-out", "chart-peak"):
            assert f'id="{name}"' in legend
        rule = webassets.STYLE_CSS.split(".chart-legend b{", 1)[1].split("}", 1)[0]
        assert "min-width" in rule

    def test_the_feed_comes_after_the_drawings(self):
        """A card that appears and disappears with what just happened must not
        push the graph up and down."""
        html = webassets.console.INDEX_HTML
        overview = html.split('data-panel="overview"', 1)[1].split("</section>", 1)[0]
        assert overview.index('id="chart"') < overview.index('id="feed-card"')


GRAPH_SUITE = r"""
const src = require('fs').readFileSync(process.argv[2], 'utf8');
eval(src + "\n;globalThis.niceScale = niceScale; globalThis.tickLabel = tickLabel;");
let fails = 0;
function check(name, ok, detail){
  if(!ok){ fails++; console.log("FAIL", name, JSON.stringify(detail)); }
}
for(const peak of [0, 1, 700, 1024, 1500, 9999, 1.37 * 1048576, 4 * 1048576,
                   123456789, 5e12, NaN, -5, null]){
  const scale = niceScale(peak);
  const labels = scale.ticks.map((value) => tickLabel(value, scale));
  check("starts at zero " + peak, scale.ticks[0] === 0, scale.ticks);
  check("covers the peak " + peak, scale.top >= (Number(peak) || 0), scale);
  check("a handful of lines " + peak, scale.ticks.length >= 2 && scale.ticks.length <= 6, labels);
  check("never more than twice the room needed " + peak,
        scale.top <= Math.max(1024, Number(peak) || 0) * 2.5, scale);
  check("one unit on every label " + peak,
        labels.slice(1).every((text) => text.endsWith(" " + scale.unit)), labels);
  check("short labels " + peak, labels.every((text) => text.length <= 10), labels);
  check("evenly spaced " + peak, scale.ticks.every((value, index) =>
    Math.abs(value - index * scale.ticks[1]) < 1e-6 * scale.top), scale.ticks);
}
const steady = niceScale(1.30 * 1048576), moved = niceScale(1.40 * 1048576);
check("a small change keeps the scale", steady.top === moved.top, [steady, moved]);
process.exit(fails ? 1 : 0);
"""


@pytest.mark.skipif(NODE is None, reason="node is needed to run the JS")
def test_the_throughput_axis_is_round_numbers_in_one_unit(tmp_path):
    body = webassets.console.CONSOLE_PAGE_JS
    source = body.split("const RATE_UNITS", 1)[1].split("function drawChart(){", 1)[0]
    (tmp_path / "scale.js").write_text("const RATE_UNITS" + source, encoding="utf-8")
    (tmp_path / "suite.js").write_text(GRAPH_SUITE, encoding="utf-8")
    result = subprocess.run([NODE, str(tmp_path / "suite.js"), str(tmp_path / "scale.js")],
                            capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stdout + result.stderr


def test_the_chart_labels_its_lines():
    body = webassets.console.CONSOLE_PAGE_JS
    chart = body.split("function drawChart(){", 1)[1].split("\n}\n", 1)[0]
    assert "fillText(labels[index]" in chart
    assert '"now"' in chart


class TestTheSpeedTestShowsWhatItMeasured:
    def test_the_answer_is_read_in_the_shape_it_comes_in(self):
        """`CHANNEL.call` hands back the data itself; destructuring `{ok, data}`
        out of it made every result `undefined`, and the throw that followed
        was painted as "the speed test failed"."""
        js = webassets.nodeview.JS
        method = js.split("  async speedtest(element, button, id){", 1)[1].split("\n  },\n", 1)[0]
        assert 'CHANNEL.ask(\n          "node.speedtest"' in method
        assert "await this.op(\"node.speedtest\"" not in method

    def test_the_results_are_a_block_that_survives_a_repaint(self):
        js = webassets.nodeview.JS
        render = js.split("  render(view, extras, options){", 1)[1].split("\n  },\n", 1)[0]
        assert "this.speedHTML(view.id)" in render
        tiles = js.split("  speedHTML(id){", 1)[1].split("\n  },\n", 1)[0]
        for label in ("Each way", "Latency at rest", "Latency under load", "Lost"):
            assert f'"{label}"' in tiles
        assert "only-expert" in tiles

    def test_a_context_switch_drops_the_last_measurement(self):
        js = webassets.nodeview.JS
        reset = js.split("  reset(){", 1)[1].split("\n  },\n", 1)[0]
        assert "this.speed = {}" in reset


class TestExpertMode:
    def test_one_attribute_decides_and_it_is_set_before_the_first_paint(self):
        css = webassets.ui.CSS
        assert ':root:not([data-expert="1"]) .only-expert{display:none!important}' in css
        assert ':root[data-expert="1"] .only-simple{display:none!important}' in css
        assert 'nmesh_expert' in webassets.ui.THEME_JS
        assert 'dataset.expert="1"' in webassets.ui.THEME_JS

    def test_every_switch_is_wired_by_the_shell(self):
        js = webassets.ui.JS
        assert "const EXPERT = {" in js
        mount = js.split("function mountShell(){", 1)[1]
        assert "[data-expert-toggle]" in mount and "EXPERT.set(" in mount
        html = webassets.console.INDEX_HTML
        # In the rail, behind the ⋯ on a phone, and with the other preferences.
        assert html.count("data-expert-toggle") >= 3

    def test_the_simple_view_hides_the_numbers_the_bar_is_made_of(self):
        html = webassets.console.INDEX_HTML
        mlo = html.split("<h2>Multi-link operation</h2>", 1)[0].rsplit("<article", 1)[1]
        assert "only-expert" in mlo
        transports = html.split("<h2>Transports</h2>", 1)[0].rsplit("<article", 1)[1]
        assert "only-expert" in transports
        config = html.split("<h2>Configuration file</h2>", 1)[0].rsplit("<article", 1)[1]
        assert "only-expert" in config
        power = html.split('id="power-card"', 1)[1].split("</article>", 1)[0]
        assert "only-expert" not in power.split('id="power-values"', 1)[0]


class TestTheEnergyBar:
    def test_ten_steps_and_an_adaptive_mode_that_says_it_is_not_here_yet(self):
        html = webassets.console.INDEX_HTML
        power = html.split('id="power-card"', 1)[1].split("</article>", 1)[0]
        assert 'id="power-step" type="range" min="1" max="10" step="1"' in power
        adaptive = power.split('data-power-panel="adaptive"', 1)[1]
        assert 'min="1" max="5"' in adaptive and "disabled" in adaptive
        assert "Soon" in power

    def test_the_bar_applies_through_the_plane_and_rereads_the_node(self):
        js = webassets.console.CONSOLE_PAGE_JS
        handler = js.split('$("power-step").addEventListener("change"', 1)[1].split("\n});\n", 1)[0]
        assert 'CHANNEL.ask("config.profile", {step})' in handler
        assert "await loadConfig()" in handler

    def test_the_card_is_not_offered_by_a_node_that_cannot_do_it(self):
        js = webassets.console.CONSOLE_PAGE_JS
        paint = js.split("function paintPower(data){", 1)[1].split("\n}\n", 1)[0]
        assert 'CHANNEL.has("config.profile")' in paint

    def test_the_form_is_split_on_what_applies_now(self):
        js = webassets.console.CONSOLE_PAGE_JS
        paint = js.split("function paintConfig(data){", 1)[1].split("\n}\n", 1)[0]
        assert '$(setting.live ? "config-fields" : "config-fields-restart")' in paint
        html = webassets.console.INDEX_HTML
        assert 'id="config-fields-restart"' in html
        assert "nothing here changes a running node" not in html
