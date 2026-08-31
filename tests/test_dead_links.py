"""
Cutting a link that answers nothing.

The console showed a node reached over two links, one of them at 100% loss, and
the node kept it: it was listed, it was counted, and it was there to be picked.
A link that returns no probe is not a slow link — it is a socket both ends have
stopped agreeing about (a half-open TCP connection, a UDP mapping the NAT
forgot), and nothing about it will ever error. Silence is the only evidence
there is, so silence has to be enough to act on.

What is proved here: the run of unanswered probes is what decides, the ratio
cannot, and a cut heals the link rather than losing the node.
"""
import asyncio

import pytest

from src.metrics import LinkQuality
from src.node import MeshNode, _Peer, _DEAD_LINK_PROBES
from src.node_id import NodeID
from tests.conftest import FakeTransport, make_manager


def _node() -> MeshNode:
    node = MeshNode(transport_manager=make_manager())
    node._running = True
    return node


def _link(node: MeshNode, target: NodeID, *, uri: str = "fake://a:1",
          pings: int = 0, pongs: int = 0) -> _Peer:
    peer = _Peer(FakeTransport(), is_client_side=True)
    peer.authenticated_id = target
    peer.session = object()
    peer.remote_addr = uri
    quality = LinkQuality()
    for _ in range(pongs):
        quality.on_ping()
        quality.on_pong(0.01)
    for _ in range(pings):
        quality.on_ping()
    peer.quality = quality
    node._peers.append(peer)
    return peer


async def _settle(node: MeshNode, peer: _Peer) -> None:
    for _ in range(50):
        if peer not in node._peers:
            return
        await asyncio.sleep(0)


TARGET = NodeID(b"\x11" * 20)
OTHER = NodeID(b"\x22" * 20)


class TestCountingSilence:
    def test_a_probe_that_comes_back_clears_the_run(self):
        quality = LinkQuality()
        for _ in range(10):
            quality.on_ping()
        assert quality.since_pong == 10
        quality.on_pong(0.02)
        assert quality.since_pong == 0

    def test_an_answer_too_late_to_time_is_still_an_answer(self):
        """Only the latest probe is kept for timing, so an answer that arrives
        after the next one went out has no round trip. It is still proof the
        link works, and a link slower than the probe interval must not be read
        as a dead one."""
        quality = LinkQuality()
        for _ in range(_DEAD_LINK_PROBES):
            quality.on_ping()
        quality.on_answer()
        assert quality.since_pong == 0
        assert quality.pongs == 1
        assert quality.last is None           # nothing was measured

    def test_the_run_is_what_the_ratio_cannot_see(self):
        """An hour of good probes outvotes a dead link forever. That is the
        reason the run exists: the share stays low while the link is gone."""
        quality = LinkQuality()
        for _ in range(1000):
            quality.on_ping()
            quality.on_pong(0.01)
        for _ in range(_DEAD_LINK_PROBES):
            quality.on_ping()
        assert quality.loss() < 0.01              # the ratio says the link is fine
        assert quality.since_pong == _DEAD_LINK_PROBES


class TestReapingSilentLinks:
    async def test_a_link_that_answers_nothing_is_cut(self):
        node = _node()
        dead = _link(node, TARGET, pings=_DEAD_LINK_PROBES)
        node._reap_silent_links()
        await _settle(node, dead)
        assert dead not in node._peers

    async def test_one_probe_short_is_left_alone(self):
        """The threshold is a threshold, not a direction of travel."""
        node = _node()
        peer = _link(node, TARGET, pings=_DEAD_LINK_PROBES - 1)
        node._reap_silent_links()
        await asyncio.sleep(0)
        assert peer in node._peers

    async def test_a_link_that_answers_is_left_alone(self):
        node = _node()
        peer = _link(node, TARGET, pongs=20)
        node._reap_silent_links()
        await asyncio.sleep(0)
        assert peer in node._peers

    async def test_a_slow_link_that_answers_late_survives(self):
        """One answer is proof of life however long it took, and the run starts
        again from there — a medium measured in minutes is not a dead one."""
        node = _node()
        peer = _link(node, TARGET, pings=_DEAD_LINK_PROBES - 1)
        peer.quality.on_pong(90.0)
        peer.quality.on_ping()
        node._reap_silent_links()
        await asyncio.sleep(0)
        assert peer in node._peers

    async def test_cutting_one_medium_keeps_the_other(self):
        """The case from the console: tcp healthy, udp answering nothing. The
        node stays reached — it loses the link, not the neighbour."""
        node = _node()
        dead = _link(node, TARGET, uri="udp://host:2", pings=_DEAD_LINK_PROBES)
        alive = _link(node, TARGET, uri="fake://host:1", pongs=12)
        node._reap_silent_links()
        await _settle(node, dead)
        assert dead not in node._peers
        assert alive in node._peers
        assert node._link_to(TARGET) is alive

    async def test_the_addresses_of_a_cut_link_are_still_known(self):
        """Cutting has to heal the link, not lose the node: maintenance dials
        it again, which it can only do from what we still know about it."""
        node = _node()
        node._routing.add(TARGET, ["fake://a:1"], b"\x00" * 32)
        dead = _link(node, TARGET, pings=_DEAD_LINK_PROBES)
        node._reap_silent_links()
        await _settle(node, dead)
        assert "fake://a:1" in node._known_addresses(TARGET)

    async def test_a_relayed_link_carries_no_probes_of_its_own(self):
        node = _node()
        virtual = _link(node, TARGET, pings=_DEAD_LINK_PROBES)
        virtual.relay_only = True
        node._reap_silent_links()
        await asyncio.sleep(0)
        assert virtual in node._peers

    async def test_a_link_under_measurement_is_left_to_its_owner(self):
        node = _node()
        candidate = _link(node, TARGET, pings=_DEAD_LINK_PROBES)
        candidate.probation = True
        node._reap_silent_links()
        await asyncio.sleep(0)
        assert candidate in node._peers

    async def test_an_unauthenticated_link_is_not_the_reaper_s_business(self):
        """A link still handshaking has its own deadline and its own sweep."""
        node = _node()
        half = _link(node, TARGET, pings=_DEAD_LINK_PROBES)
        half.session = None
        node._reap_silent_links()
        await asyncio.sleep(0)
        assert half in node._peers

    async def test_every_link_is_judged_on_its_own_probes(self):
        node = _node()
        dead = _link(node, TARGET, pings=_DEAD_LINK_PROBES)
        healthy = _link(node, OTHER, uri="fake://b:2", pongs=5)
        node._reap_silent_links()
        await _settle(node, dead)
        assert dead not in node._peers
        assert healthy in node._peers
