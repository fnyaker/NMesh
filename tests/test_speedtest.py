"""
Measuring a link by loading it — and the refusals that make that safe.

`AGENTS.md` names speed a principle and quotes a figure to beat, and nothing in
this project measured one. Everything else here measures a link by *watching*
it: round trips, loss, whatever bytes happened to flow. That answers "is it
alive" and never "how fast is it".

So there is a plane whose whole purpose is to **spend** somebody else's
bandwidth, which makes it the one place where the design is the list of things
it will not do. These tests are that list, written from the rule rather than
from the implementation:

* answered **only on a direct authenticated link** — a stranger must never be
  able to make this node generate traffic, towards it or towards a victim;
* **one echo for one probe, of exactly the size that arrived** — a reflector
  that answers more than it was sent is an amplifier, which is the single worst
  thing this pair could be;
* **bounded by the answering side**, per identity, so a peer cannot make us echo
  without end however politely it asks — and counted per identity, so
  reconnecting sheds nothing;
* **bounded by the asking side** in bytes and in seconds, whichever ends first;
* and **negotiated**, so a node on a metered link declines this and nothing
  else.
"""
import asyncio

import pytest

from src import features
from src.node import (MeshNode, _Peer, SPEED_PROBE, SPEED_ECHO, _SPEED_CHUNK,
                      _SPEED_IDLE_PROBES, _SPEED_INFLIGHT, _SPEED_MAX_BYTES,
                      _SPEED_MAX_SECONDS, _SPEED_MAX_PER_WINDOW,
                      _SPEED_PROBE_TIMEOUT, _QID_LEN)
from src.node_id import NodeID
from src.packet import Packet
from tests.conftest import FakeTransport, make_manager

async def _node():
    return MeshNode(transport_manager=make_manager())


class _Link(_Peer):
    """A real `_Peer`, authenticated, whose sends are recorded.

    A *real* one on purpose. A hand-rolled stub of this project's own type is
    how `test_key_share` ended up with a peer that had no transport, and how
    this file first ended up with one that had no address — both found only
    when a path nobody was testing happened to touch the missing field. A
    subclass cannot be missing anything."""

    def __init__(self, node, *, authed=True, session=True):
        super().__init__(FakeTransport(), is_client_side=True)
        self.authenticated_id = NodeID.generate() if authed else None
        self.session = object() if session else None
        self.remote_addr = "fake://there:1"
        self.sent = []

    async def send(self, packet):
        self.sent.append(packet)


def _probe(src, dst, payload):
    return Packet.create(SPEED_PROBE, src, dst, payload)


class TestItIsAnsweredOnlyToSomebodyWeKnow:
    async def test_a_stranger_gets_nothing(self):
        """Pre-authentication this is somebody asking us to generate traffic.
        There is no version of that worth serving."""
        node = await _node()
        try:
            for authed, session in ((False, True), (True, False), (False, False)):
                link = _Link(node, authed=authed, session=session)
                await node._handle_speed_probe(
                    link, _probe(NodeID.generate().raw, node.id.raw, b"x" * 64))
                assert link.sent == []
        finally:
            await node.stop()

    async def test_a_probe_addressed_elsewhere_is_never_reflected(self):
        """The reflection that would make this a weapon: a peer asking us to
        answer *to somebody else*."""
        node = await _node()
        try:
            link = _Link(node)
            victim = NodeID.generate()
            await node._handle_speed_probe(
                link, _probe(link.authenticated_id.raw, victim.raw, b"x" * 64))
            assert link.sent == []
        finally:
            await node.stop()


class TestOneForOne:
    async def test_the_echo_is_exactly_what_arrived(self):
        """Not a byte more. A pair that answered more than it was sent is an
        amplifier, whoever is on the other end of it."""
        node = await _node()
        try:
            link = _Link(node)
            for size in (1, 64, 4096, _SPEED_CHUNK):
                link.sent.clear()
                payload = bytes(range(256)) * (size // 256) + b"\x00" * (size % 256)
                await node._handle_speed_probe(
                    link, _probe(link.authenticated_id.raw, node.id.raw, payload))
                [answer] = link.sent
                assert answer.type == SPEED_ECHO
                assert answer.payload == payload
                assert len(answer.payload) == size
        finally:
            await node.stop()

    async def test_a_probe_larger_than_one_chunk_is_charged_not_echoed(self):
        node = await _node()
        try:
            link = _Link(node)
            await node._handle_speed_probe(
                link, _probe(link.authenticated_id.raw, node.id.raw,
                             b"x" * (_SPEED_CHUNK + 1)))
            assert link.sent == []
            assert link._malformed == 1
        finally:
            await node.stop()

    async def test_an_empty_probe_is_not_a_probe(self):
        node = await _node()
        try:
            link = _Link(node)
            await node._handle_speed_probe(
                link, _probe(link.authenticated_id.raw, node.id.raw, b""))
            assert link.sent == []
        finally:
            await node.stop()


class TestTheAnsweringSideKeepsItsOwnCeiling:
    async def test_a_peer_cannot_make_us_echo_without_end(self):
        """The bound that matters: the side being measured owns it, and the
        side measuring cannot raise it."""
        node = await _node()
        try:
            link = _Link(node)
            payload = b"x" * 512
            for _ in range(_SPEED_MAX_PER_WINDOW):
                await node._handle_speed_probe(
                    link, _probe(link.authenticated_id.raw, node.id.raw, payload))
            answered = len(link.sent)
            assert answered == _SPEED_MAX_PER_WINDOW
            # Past the ceiling: dropped, and dropped *silently*. A peer told it
            # hit a limit has been told how much it may get away with.
            for _ in range(20):
                await node._handle_speed_probe(
                    link, _probe(link.authenticated_id.raw, node.id.raw, payload))
            assert len(link.sent) == answered
            assert link._malformed == 0
        finally:
            await node.stop()

    async def test_the_ceiling_is_per_identity_and_a_reconnect_sheds_nothing(self):
        """`AGENTS.md`: counted per identity, not per link — "a peer that
        reconnects to shed an exhausted count is the whole point of counting"."""
        node = await _node()
        try:
            first = _Link(node)
            payload = b"x" * 512
            for _ in range(_SPEED_MAX_PER_WINDOW):
                await node._handle_speed_probe(
                    first, _probe(first.authenticated_id.raw, node.id.raw, payload))
            # Same identity, brand new link object — a reconnection.
            again = _Link(node)
            again.authenticated_id = first.authenticated_id
            await node._handle_speed_probe(
                again, _probe(again.authenticated_id.raw, node.id.raw, payload))
            assert again.sent == []
        finally:
            await node.stop()


class TestTheAskingSideIsBoundedToo:
    async def test_it_refuses_without_a_direct_link(self):
        """Routing a speed test would measure somebody else's link and spend it
        to do so."""
        node = await _node()
        try:
            answer = await node.console_speedtest(NodeID.generate().raw.hex())
            assert answer["ok"] is False
            assert "direct" in answer["error"]
        finally:
            await node.stop()

    async def test_a_node_cannot_measure_itself(self):
        node = await _node()
        try:
            answer = await node.console_speedtest(node.id.raw.hex())
            assert answer["ok"] is False
        finally:
            await node.stop()

    async def test_a_bad_id_is_refused_rather_than_guessed_at(self):
        node = await _node()
        try:
            for bad in ("", "zz", "ab" * 19, "not hex at all"):
                answer = await node.console_speedtest(bad)
                assert answer["ok"] is False, bad
        finally:
            await node.stop()

    def test_the_ceilings_are_ceilings_a_person_would_accept(self):
        """Written as a judgement about the product, not as a copy of the
        constants: a test that spends eight megabytes of somebody's metered link
        is a test nobody runs twice, and one that runs for a minute is one
        nobody waits for."""
        assert _SPEED_MAX_SECONDS <= 15.0
        assert _SPEED_MAX_BYTES <= 16 * 1024 * 1024
        # And one chunk stays well inside what a packet carries, so a probe is
        # never a way to find the framing's edge.
        assert _SPEED_CHUNK < 60000 // 2
        assert _SPEED_CHUNK > _QID_LEN


class TestItIsNegotiated:
    def test_the_plane_has_a_name_of_its_own(self):
        """A node on a metered link declines *this* and nothing else, which is
        the whole argument for a feature set rather than a version number."""
        assert features.SPEEDTEST in features.SPOKEN
        assert features.SPEEDTEST in features.SINCE_NEGOTIATION

    def test_both_messages_are_gated_on_it(self):
        from src.node import _MESSAGE_PLANE

        assert _MESSAGE_PLANE[SPEED_PROBE] == features.SPEEDTEST
        assert _MESSAGE_PLANE[SPEED_ECHO] == features.SPEEDTEST

    async def test_a_node_that_never_heard_of_it_is_not_asked(self):
        node = await _node()
        try:
            link = _Link(node)
            node._peers.append(link)
            try:
                # No announced features at all: the oldest peer there is.
                answer = await node.console_speedtest(
                    link.authenticated_id.raw.hex())
                assert answer["ok"] is False
                assert "speed" in answer["error"]
            finally:
                node._peers.remove(link)
        finally:
            await node.stop()


class _Echoing(_Link):
    """A peer that answers probes the way a real one would, after ``delay``,
    dropping every ``drop``-th one — through the node's own echo handler, so
    the measurement is fed exactly what a link would feed it."""

    def __init__(self, node, *, delay=0.002, drop=0):
        super().__init__(node)
        self.node, self.delay, self.drop, self.seen = node, delay, drop, 0
        self.agreed = frozenset({features.SPEEDTEST})
        self.tasks = set()

    async def send(self, packet):
        if packet.type != SPEED_PROBE:
            return
        self.seen += 1
        if self.drop and self.seen % self.drop == 0:
            return
        echo = Packet.create(SPEED_ECHO, self.authenticated_id.raw,
                             packet.src_id, packet.payload)

        async def later():
            await asyncio.sleep(self.delay)
            await self.node._handle_speed_echo(self, echo)
        task = asyncio.get_running_loop().create_task(later())
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)


class TestTheMeasurementItself:
    """What the figures say, against a peer whose behaviour is known."""

    async def _measure(self, **kwargs):
        node = await _node()
        link = _Echoing(node, **kwargs)
        node._peers.append(link)
        try:
            return link, await node.console_speedtest(
                link.authenticated_id.raw.hex())
        finally:
            node._peers.remove(link)
            await node.stop()

    async def test_a_clean_link_is_measured_to_the_byte_ceiling(self):
        link, answer = await self._measure()
        assert answer["ok"] is True, answer
        assert answer["lost_probes"] == 0 and answer["loss_percent"] == 0.0
        # Bounded by bytes: the ceiling, plus the probes at rest, and no more.
        assert answer["sent_bytes"] <= _SPEED_MAX_BYTES + _SPEED_CHUNK * _SPEED_IDLE_PROBES
        assert answer["echoed_bytes"] == answer["sent_bytes"]
        assert answer["one_way_bps"] > 0
        assert answer["round_trip_bps"] == 2 * answer["one_way_bps"]
        assert answer["idle_ms"] is not None and answer["rtt_ms"] is not None
        # Never more than the window outstanding: the far side's ceiling is
        # what keeps it safe, and this is what keeps us inside it.
        assert link.seen == answer["probes"]

    async def test_one_lost_probe_does_not_hold_the_test_to_its_deadline(self):
        """The bug the sliding window removed: a batch waited for its slowest
        member, so a single dropped datagram stalled everything until the
        clock ran out, and the figure was the deadline rather than the link."""
        started = asyncio.get_running_loop().time()
        _link, answer = await self._measure(drop=50)
        took = asyncio.get_running_loop().time() - started
        assert answer["ok"] is True
        assert answer["lost_probes"] > 0
        assert 0 < answer["loss_percent"] < 10
        assert took < _SPEED_MAX_SECONDS - 1
        # A lost probe costs its slot for the probe timeout and no longer.
        assert took < _SPEED_PROBE_TIMEOUT * 3

    async def test_a_silent_peer_is_all_loss_and_still_ends(self):
        node = await _node()
        link = _Echoing(node, drop=1)
        node._peers.append(link)
        try:
            answer = await asyncio.wait_for(node.console_speedtest(
                link.authenticated_id.raw.hex()), _SPEED_MAX_SECONDS + 5)
            assert answer["ok"] is True
            assert answer["echoed_bytes"] == 0
            assert answer["loss_percent"] == 100.0
            assert answer["one_way_bps"] == 0
            assert answer["rtt_ms"] is None and answer["idle_ms"] is None
            assert link.seen <= _SPEED_IDLE_PROBES + _SPEED_MAX_BYTES // _SPEED_CHUNK
            # No echo is left waiting in the node's book once it has answered.
            assert not node._pending_echo
        finally:
            node._peers.remove(link)
            await node.stop()

    def test_the_window_stays_inside_what_the_far_side_will_echo(self):
        """One test must fit under the answering side's ceiling with room to
        run it again, or the second test of a minute reads as total loss."""
        per_test = _SPEED_IDLE_PROBES + _SPEED_MAX_BYTES // _SPEED_CHUNK
        assert per_test * 2 <= _SPEED_MAX_PER_WINDOW
        assert _SPEED_INFLIGHT * _SPEED_CHUNK <= 1024 * 1024
