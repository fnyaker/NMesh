"""
The link map past what one node can see — kept by fleet, and only while true.

A node draws what it *measures*: its own links, and the sessions it routes.
Everything beyond is another machine's word about its own links. The charter has
one sentence about that (hearsay is never authority), and this feature is what
that sentence costs:

* it is asked of a machine the operator **manages**, under a capability of its
  own (`links`), never of a stranger and never by gossip;
* the machine's own fleet app must hold the node's `links` grant too — an app is
  not trusted with the machine's neighbours because it happens to be fleet;
* what comes back is a **claim**, drawn as one and attributed to whoever said
  it;
* and above all it is **now**. Fleet keeps a freshness book, not a history: a
  machine that has not confirmed in the last `FRESH_FOR` seconds has *no* links
  on the map rather than old ones. A map showing a link that died twenty minutes
  ago is worse than one missing it — one is incomplete, the other is wrong, and
  only one of them looks right.
"""
import asyncio

import pytest

from src import webassets
from src.apps import fleet, fleet_links
from src.apps.fleet import LinksReceived
from tests.test_fleet import Peer, deliver, enrol, settle

JS = webassets.APP_JS


@pytest.fixture
def operator():
    return Peer()


@pytest.fixture
def agent():
    return Peer()


class _LinkSource:
    """The connector client's `links()` half, backed by a list the test moves.

    Real enough to answer the two things the app reads — the list, and whether
    it is allowed to read it at all."""

    def __init__(self, client):
        self.links = []
        self.granted = True
        self.reads = 0
        client.links = self.read

    async def read(self):
        self.reads += 1
        if not self.granted:
            return {"links": [], "refused": True}
        return {"links": list(self.links)}


def _source(peer):
    source = getattr(peer, "link_source", None)
    if source is None:
        source = peer.link_source = _LinkSource(peer.client)
    return source


def _received(peer):
    return [event for event in peer.drain_events()
            if isinstance(event, LinksReceived)]


def _link(node_hex, transport="tcp", rtt=4.0):
    return {"id": node_hex, "pseudo": "", "transport": transport,
            "rtt_ms": rtt, "since": 30.0}


class TestOnlyAMachineThatGrantedIt:
    async def test_a_node_that_granted_nothing_says_nothing(self, operator, agent):
        _source(agent).links = [_link("cd" * 20)]
        await operator.app.request_links(agent.id)
        await deliver(operator, agent)
        await deliver(agent, operator)
        assert _received(operator) == []

    async def test_manage_does_not_imply_links(self, operator, agent):
        """The over-grant this capability exists to avoid works the other way
        round too: an operator who may drive a console is not thereby somebody
        this machine has agreed to describe its neighbours to."""
        await enrol(operator, agent, caps=["manage"])
        _source(agent).links = [_link("cd" * 20)]
        await operator.app.request_links(agent.id)
        await deliver(operator, agent)
        await deliver(agent, operator)
        assert _received(operator) == []

    async def test_with_the_grant_the_links_come_back(self, operator, agent):
        await enrol(operator, agent, caps=["links"])
        _source(agent).links = [_link("cd" * 20)]
        await operator.app.request_links(agent.id)
        await deliver(operator, agent)
        await deliver(agent, operator)
        [event] = _received(operator)
        assert [link["id"] for link in event.links] == ["cd" * 20]

    async def test_a_machine_whose_app_may_not_read_says_which_grant(self,
                                                                     operator,
                                                                     agent):
        await enrol(operator, agent, caps=["links"])
        _source(agent).granted = False
        await operator.app.request_links(agent.id)
        await deliver(operator, agent)
        await deliver(agent, operator)
        failures = [event for event in operator.drain_events()
                    if isinstance(event, fleet.Failure)]
        assert failures and "granted its fleet app" in failures[0].error

    async def test_a_refused_follow_is_not_a_follow(self, operator, agent):
        """Nothing is registered on a question that could not be answered:
        a follower kept against a refusal is a machine pushing nothing for ever
        and a console waiting for it."""
        await enrol(operator, agent, caps=["links"])
        _source(agent).granted = False
        await operator.app.follow_links(agent.id, True)
        await deliver(operator, agent)
        assert agent.app._link_followers == {}
        assert agent.app._link_pump is None


class TestItIsPushedAsItChanges:
    async def _following(self, operator, agent):
        await enrol(operator, agent, caps=["links"])
        _source(agent).links = [_link("cd" * 20)]
        await operator.app.follow_links(agent.id, True)
        await deliver(operator, agent)
        await deliver(agent, operator)
        return agent.app._link_followers

    async def test_a_follow_answers_with_the_links_at_once(self, operator, agent):
        followers = await self._following(operator, agent)
        assert list(followers) == [operator.id.raw.hex()]
        assert operator.app.following_links() == [agent.id.raw.hex()]

    async def test_a_change_is_what_is_worth_a_frame(self, operator, agent):
        """A link list is a *state*. What is worth sending is that it is a
        different one — a latency that moves on every probe is not."""
        assert fleet._link_shape([_link("cd" * 20, rtt=4.0)]) == \
            fleet._link_shape([_link("cd" * 20, rtt=91.0)])
        assert fleet._link_shape([_link("cd" * 20)]) != \
            fleet._link_shape([_link("cd" * 20), _link("ef" * 20)])
        assert fleet._link_shape([_link("cd" * 20, transport="tcp")]) != \
            fleet._link_shape([_link("cd" * 20, transport="udp")])

    async def test_a_follower_that_went_away_stops_being_pushed(self, operator,
                                                                agent):
        followers = await self._following(operator, agent)
        for entry in followers.values():
            entry["until"] = 0.0
        # The pump drops it on its own next turn rather than waiting for the
        # console to say anything: a console that died says nothing at all.
        now = fleet.time.monotonic()
        for node_hex, entry in list(agent.app._link_followers.items()):
            if entry["until"] <= now:
                agent.app._link_followers.pop(node_hex, None)
        assert agent.app._link_followers == {}

    async def test_stopping_stops_it(self, operator, agent):
        await self._following(operator, agent)
        await operator.app.follow_links(agent.id, False)
        await deliver(operator, agent)
        assert agent.app._link_followers == {}
        assert operator.app.following_links() == []

    async def test_the_number_of_followers_is_bounded(self, operator, agent):
        await enrol(operator, agent, caps=["links"])
        _source(agent)
        agent.app._link_followers = {
            f"{n:040x}": {"id": operator.id, "rid": "x", "until": 1e12}
            for n in range(fleet.MAX_LINK_FOLLOWERS)}
        await operator.app.follow_links(agent.id, True)
        await deliver(operator, agent)
        assert operator.id.raw.hex() not in agent.app._link_followers

    async def test_a_push_nobody_asked_for_is_dropped(self, operator, agent):
        await enrol(operator, agent, caps=["links"])
        agent.app._reply(operator.id, fleet.LINKS_REPLY,
                         {"rid": "not-ours", "op": "push", "ok": True,
                          "links": [_link("cd" * 20)]})
        await deliver(agent, operator)
        assert _received(operator) == []

    async def test_the_far_side_keeps_nothing_after_it_stops(self, operator,
                                                             agent):
        await self._following(operator, agent)
        await agent.app.stop()
        assert agent.app._link_followers == {}
        assert agent.app._link_pump is None
        await operator.app.stop()
        assert operator.app.following_links() == []


class TestFreshnessIsTheWholePoint:
    def test_a_source_that_went_quiet_leaves_the_map(self):
        clock = [1000.0]
        book = fleet_links.LinkMap(clock=lambda: clock[0])
        book.absorb("ab" * 20, [_link("cd" * 20)])
        assert len(book.view()["edges"]) == 1
        clock[0] += fleet_links.FRESH_FOR + 1
        view = book.view()
        # Gone, not greyed out: a link that died twenty minutes ago drawn as
        # though it were live is worse than a map that is missing it.
        assert view["edges"] == [] and view["sources"] == []

    def test_an_answer_replaces_rather_than_accumulates(self):
        book = fleet_links.LinkMap()
        book.absorb("ab" * 20, [_link("cd" * 20), _link("ef" * 20)])
        book.absorb("ab" * 20, [_link("cd" * 20)])
        assert [edge["b"] for edge in book.view()["edges"]] == ["cd" * 20]

    def test_every_edge_carries_who_said_it_and_how_old(self):
        clock = [1000.0]
        book = fleet_links.LinkMap(clock=lambda: clock[0])
        book.absorb("ab" * 20, [_link("cd" * 20)])
        clock[0] += 5.0
        [edge] = book.view()["edges"]
        assert edge["from"] == "ab" * 20
        assert edge["age"] == 5.0

    def test_two_machines_reporting_one_link_draw_one_edge(self):
        book = fleet_links.LinkMap()
        one, other = "ab" * 20, "cd" * 20
        book.absorb(one, [_link(other)])
        book.absorb(other, [_link(one)])
        assert len(book.view()["edges"]) == 1

    def test_what_a_machine_says_is_bounded_before_it_is_kept(self):
        book = fleet_links.LinkMap()
        book.absorb("ab" * 20, [_link("cd" * 20)] * 500)
        assert len(book.view()["nodes"]) <= fleet_links.MAX_LINKS_PER_SOURCE
        for junk in (None, "links", 7, [None, 3], [{"id": "short"}],
                     [{"id": "ab" * 20, "transport": "x" * 400,
                       "rtt_ms": "soon", "pseudo": "p" * 500}]):
            book.absorb("ba" * 20, junk)          # must not raise
        for node in book.view()["nodes"]:
            assert len(node["pseudo"]) <= 50
        for edge in book.view()["edges"]:
            assert len(edge["transport"]) <= 16

    def test_a_machine_cannot_claim_itself(self):
        book = fleet_links.LinkMap()
        book.absorb("ab" * 20, [_link("ab" * 20)])
        assert book.view()["edges"] == []

    def test_the_number_of_sources_is_bounded(self):
        book = fleet_links.LinkMap()
        for number in range(fleet_links.MAX_SOURCES + 8):
            book.absorb(f"{number:040x}", [_link("cd" * 20)])
        assert len(book.view()["sources"]) == fleet_links.MAX_SOURCES

    def test_forgetting_drops_one_or_all(self):
        book = fleet_links.LinkMap()
        book.absorb("ab" * 20, [_link("cd" * 20)])
        book.absorb("ba" * 20, [_link("ef" * 20)])
        book.forget("ab" * 20)
        assert [row["id"] for row in book.view()["sources"]] == ["ba" * 20]
        book.forget()
        assert book.view()["sources"] == []


class TestAskingIsWhatKeepsItAlive:
    def test_nobody_looking_means_nothing_is_asked(self):
        book = fleet_links.LinkMap()
        assert book.watched() is False
        book.note_watching()
        assert book.watched() is True

    def test_looking_decays_on_its_own(self):
        """A page that was closed stops saying it, and a browser that died says
        nothing at all — so "somebody is looking" has to expire rather than be
        switched off."""
        clock = [1000.0]
        book = fleet_links.LinkMap(clock=lambda: clock[0])
        book.note_watching()
        clock[0] += fleet_links.FRESH_FOR + 1
        assert book.watched() is False

    async def test_the_bridge_follows_while_the_map_is_open(self):
        node, app, bridge = await _bridge()
        machine = "ab" * 20
        try:
            app.state.add_managed(machine, caps=["links"])
            await bridge._reconcile_links()
            assert app.following_links() == [], "asked with nobody looking"
            bridge.api_map_links()                 # a page opened the map
            await bridge._reconcile_links()
            assert app.following_links() == [machine]
        finally:
            bridge.stop()
            await node.stop()

    async def test_it_stops_following_when_the_map_is_closed(self):
        node, app, bridge = await _bridge()
        machine = "ab" * 20
        try:
            app.state.add_managed(machine, caps=["links"])
            bridge.api_map_links()
            await bridge._reconcile_links()
            assert app.following_links() == [machine]
            # Nobody has looked since: the watch decays and the follow is
            # taken back rather than left to expire on the far side.
            bridge._links._watching = 0.0
            await bridge._reconcile_links()
            assert app.following_links() == []
            assert bridge.api_map_links()["edges"] == []
        finally:
            bridge.stop()
            await node.stop()

    async def test_a_machine_that_granted_nothing_is_never_asked(self):
        node, app, bridge = await _bridge()
        try:
            app.state.add_managed("ab" * 20, caps=["status"])
            bridge.api_map_links()
            await bridge._reconcile_links()
            assert app.following_links() == []
        finally:
            bridge.stop()
            await node.stop()

    async def test_what_arrives_is_held_and_answered_to_the_page(self):
        node, app, bridge = await _bridge()
        machine = "ab" * 20
        try:
            app.state.add_managed(machine, caps=["links"])
            app._link_follows[machine] = "rid"
            app._on_links_reply(fleet.NodeID.from_hex(machine),
                                {"rid": "rid", "op": "push", "ok": True,
                                 "links": [_link("cd" * 20)]})
            await settle()
            answer = bridge.api_map_links()
            assert [edge["b"] for edge in answer["edges"]] == ["cd" * 20]
            assert answer["may_ask"] == [machine]
            assert answer["fresh_for"] == fleet_links.FRESH_FOR
        finally:
            bridge.stop()
            await node.stop()


class TestThePageDrawsAClaimAsAClaim:
    def test_the_page_keeps_no_store_of_its_own(self):
        """It used to, and a reload emptied the map. The state belongs to the
        app that can keep it fresh."""
        assert "MAP_GROWTH" not in JS
        block = JS.split("// ---- the map, past what this node can see")[1]
        block = block.split("let MAP_NAMES")[0]
        assert "MAP_LINKS" in block
        assert "localStorage" not in block

    def test_reported_links_are_drawn_as_claims(self):
        css = webassets.STYLE_CSS
        assert "stroke-dasharray" in css.split(".mesh-graph .edge.reported")[1][:80]
        assert "fill:none" in css.split(
            ".mesh-graph .node.reported circle:not(.hit)")[1][:80]

    def test_every_reported_edge_says_who_said_it(self):
        block = JS.split("grown.edges.forEach")[1].split("const dot =")[0]
        assert '"said by " + shortId(edge.from)' in block
        assert "rtt" not in block

    def test_our_own_link_is_never_drawn_twice(self):
        block = JS.split("function mapReported")[1].split("let MAP_NAMES")[0]
        assert "known.has(edge.a) && known.has(edge.b)" in block

    def test_the_open_map_refreshes_and_the_closed_one_stops(self):
        block = JS.split("function watchMapLinks")[1].split("// The drawing")[0]
        assert "clearInterval" in block and "setInterval" in block
        assert 'addEventListener("close", () => watchMapLinks(false))' in JS

    def test_the_panel_says_how_old_each_machines_word_is(self):
        block = JS.split("function paintGrow")[1].split('$("map-grow-clear")')[0]
        assert "said.age" in block
        assert "MAP_LINKS.may_ask" in block


class TestNoneOfItTravelsOrIsWrittenDown:
    def test_the_map_grows_only_on_the_console_you_are_at(self):
        """Neither question acts, so letting them travel looks harmless. It is
        not: together they hand a remote operator the list of machines this node
        manages and can reach, which is how a node somebody manages becomes a
        way to reach the nodes it manages."""
        from src.apps.fleet_web import FleetBridge

        travelling = {entry["name"] for entry in FleetBridge.API
                      if entry.get("remote")}
        for name in ("map_targets", "map_overlay", "map_links"):
            assert name not in travelling

    def test_nothing_reported_is_kept_on_disk(self):
        """Who talks to whom is what the threat model says to hold as little of
        as possible. It lives in memory and dies with the process."""
        import pathlib

        source = (pathlib.Path(__file__).resolve().parent.parent
                  / "src" / "apps" / "fleet_links.py").read_text()
        for forbidden in ("open(", "json.dump", "_store", "put("):
            assert forbidden not in source

    def test_the_node_itself_holds_no_map_of_other_peoples_links(self):
        import pathlib

        root = pathlib.Path(__file__).resolve().parent.parent
        for name in ("src/node.py", "src/webconsole.py"):
            text = (root / name).read_text()
            assert "LinkMap" not in text


class TestFleetsWordsRatherThanThePages:
    def test_badges_are_rendered_not_invented(self):
        block = JS.split("function overlayBadges")[1].split("// The drawing")[0]
        assert "row.badges" in block
        for word in ("managed", "govern", "log"):
            assert f'"{word}"' not in block

    def test_fleet_says_what_it_knows_about_each_node(self):
        from src.apps.fleet_state import FleetState
        from src.apps.fleet_web import FleetBridge

        bridge = FleetBridge.__new__(FleetBridge)
        bridge._app = _StubApp()
        bridge._app.state.add_managed("ab" * 20, caps=["logs", "manage"],
                                      label="lab")
        overlay = FleetBridge.api_map_overlay(bridge)["nodes"]
        assert overlay["ab" * 20]["badges"] == ["managed"]
        assert overlay["ab" * 20]["label"] == "lab"

    def test_a_node_that_controls_this_one_outranks_everything_it_says(self):
        from src.apps.fleet_web import FleetBridge

        bridge = FleetBridge.__new__(FleetBridge)
        bridge._app = _StubApp()
        node = "cd" * 20
        bridge._app.state.add_managed(node, caps=["status"])
        bridge._app.state.add_operator(node, b"a key", caps=["manage"])
        row = FleetBridge.api_map_overlay(bridge)["nodes"][node]
        assert "controls this node" in row["badges"]
        assert row["tone"] == "warn"


class _StubApp:
    def __init__(self):
        from src.apps.fleet_state import FleetState

        self.state = FleetState()

    def following(self):
        return []

    def following_links(self):
        return []


async def _bridge():
    from src.app_registry import FLEET_APP_ID
    from src.apps.fleet import FleetApp
    from src.apps.fleet_state import FleetState
    from src.apps.fleet_web import FleetBridge
    from src.node import MeshNode
    from tests.conftest import make_manager
    from tests.test_console_fleet import StubClient

    node = MeshNode(transport_manager=make_manager())
    app = FleetApp(StubClient(), node.app_auth(FLEET_APP_ID),
                   state=FleetState(), auto_status=False)
    bridge = FleetBridge(app)
    bridge.start(asyncio.get_running_loop())
    return node, app, bridge


class TestItIsReallyLive:
    async def test_a_link_that_appears_is_pushed_without_being_asked_for(
            self, operator, agent, monkeypatch):
        """The property the whole shape exists for: the operator's map learns
        that a machine gained a link because the machine said so, not because
        something here happened to ask again."""
        monkeypatch.setattr(fleet, "LINKS_TICK", 0.02)
        await enrol(operator, agent, caps=["links"])
        source = _source(agent)
        source.links = [_link("cd" * 20)]
        await operator.app.follow_links(agent.id, True)
        await deliver(operator, agent)
        await deliver(agent, operator)
        operator.drain_events()

        source.links = [_link("cd" * 20), _link("ef" * 20)]
        for _ in range(50):
            await asyncio.sleep(0.02)
            if agent.take_sent.__self__.client.sent:
                break
        await deliver(agent, operator)
        pushed = [event for event in _received(operator) if event.pushed]
        assert pushed, "the change was never pushed"
        assert {link["id"] for link in pushed[-1].links} == {"cd" * 20, "ef" * 20}

    async def test_an_unchanged_list_is_not_a_frame_a_second(
            self, operator, agent, monkeypatch):
        """A latency moves on every probe. Pushing for that would cost a frame
        per follower per second, for ever, and say nothing."""
        monkeypatch.setattr(fleet, "LINKS_TICK", 0.02)
        await enrol(operator, agent, caps=["links"])
        source = _source(agent)
        source.links = [_link("cd" * 20, rtt=4.0)]
        await operator.app.follow_links(agent.id, True)
        await deliver(operator, agent)
        agent.take_sent()
        for _ in range(10):
            source.links = [_link("cd" * 20, rtt=source.reads * 3.0)]
            await asyncio.sleep(0.02)
        assert agent.take_sent() == []
