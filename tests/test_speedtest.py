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
                      _SPEED_IDLE_PROBES, _SPEED_INFLIGHT, _SPEED_INFLIGHT_MAX,
                      _SPEED_MAX_BYTES,
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
        assert _SPEED_INFLIGHT_MAX * _SPEED_CHUNK <= 1024 * 1024


class _Queueing(_Echoing):
    """A link whose round trip grows with what is in flight on it — a queue
    in front of a bottleneck, the way a real full link behaves."""

    def __init__(self, node, *, base=0.01, per=0.004):
        super().__init__(node, delay=base)
        self.base, self.per = base, per

    async def send(self, packet):
        self.delay = self.base + self.per * len(self.tasks)
        await super().send(packet)


class TestTheWindowOpensToWhatTheLinkTakes:
    """Eight probes in flight read at most eight per round trip: about 1 MB/s
    at 130 ms, which is how a speed test could never read the 4 MB/s the
    charter names on any path longer than a room."""

    async def _measure(self, link_type, **kwargs):
        node = await _node()
        link = link_type(node, **kwargs)
        node._peers.append(link)
        try:
            return await node.console_speedtest(link.authenticated_id.raw.hex())
        finally:
            node._peers.remove(link)
            await node.stop()

    async def test_a_long_clean_path_is_not_capped_by_the_window(self):
        answer = await self._measure(_Echoing, delay=0.06)
        assert answer["ok"] is True, answer
        [row] = answer["links"]
        assert row["window"] > _SPEED_INFLIGHT
        fixed_window_ceiling = _SPEED_INFLIGHT * _SPEED_CHUNK / 0.06
        assert answer["one_way_bps"] > 1.5 * fixed_window_ceiling

    async def test_it_stops_opening_once_a_queue_builds(self):
        """Past the point the link is full, more in flight only queues — the
        round trip under load is what says so."""
        answer = await self._measure(_Queueing)
        assert answer["ok"] is True, answer
        [row] = answer["links"]
        assert row["window"] < _SPEED_INFLIGHT_MAX

    async def test_it_never_passes_its_ceiling(self):
        answer = await self._measure(_Echoing, delay=0.03)
        [row] = answer["links"]
        assert row["window"] <= _SPEED_INFLIGHT_MAX


class TestABundleIsMeasuredAsOne:
    """A speed test loads one link, so it could not show what multi-link
    operation adds. Asked to, it loads every direct member of the bundle at
    once and reports the sum and each link."""

    async def test_every_direct_member_carries_its_share(self):
        node = await _node()
        first = _Echoing(node, delay=0.01)
        second = _Echoing(node, delay=0.02)
        second.authenticated_id = first.authenticated_id
        node._peers.extend([first, second])
        node._speed_members = lambda target: [first, second]
        try:
            answer = await node.console_speedtest(
                first.authenticated_id.raw.hex(), bundle=True)
        finally:
            node._peers.clear()
            await node.stop()
        assert answer["ok"] is True, answer
        assert len(answer["links"]) == 2
        assert all(row["echoed_bytes"] > 0 for row in answer["links"])
        assert first.seen > 0 and second.seen > 0
        assert answer["echoed_bytes"] == sum(row["echoed_bytes"]
                                             for row in answer["links"])
        assert answer["sent_bytes"] <= (_SPEED_MAX_BYTES
                                        + 2 * _SPEED_CHUNK * _SPEED_IDLE_PROBES)

    async def test_without_a_bundle_it_says_so(self):
        node = await _node()
        link = _Echoing(node)
        node._peers.append(link)
        try:
            answer = await node.console_speedtest(
                link.authenticated_id.raw.hex(), bundle=True)
        finally:
            node._peers.clear()
            await node.stop()
        assert answer == {"ok": False,
                          "error": "no bundle of two direct links to that node"}


class TestTheAskingSideKnowsTheFarEndsCeiling:
    """The far end stops echoing at `_SPEED_MAX_PER_WINDOW`, silently. Seen
    live: a third test to one node inside a minute had 21 % of its probes go
    unanswered and said so as loss, on a link that had lost nothing."""

    async def _tests(self, count: int, *, age: float = 0.0):
        node = await _node()
        link = _Echoing(node)
        node._peers.append(link)
        target = link.authenticated_id.raw.hex()
        answers = []
        try:
            for _ in range(count):
                answers.append(await node.console_speedtest(target))
                if age:
                    # Age the window rather than patch the clock: the event
                    # loop reads the same `time.monotonic`.
                    key = link.authenticated_id.raw
                    spent, started = node._speed_spent[key]
                    node._speed_spent[key] = (spent, started - age)
            return link, answers
        finally:
            node._peers.remove(link)
            await node.stop()

    async def test_a_test_that_would_pass_it_is_refused_and_says_when(self):
        link, (first, second, third) = await self._tests(3)
        assert first["ok"] is True and second["ok"] is True, (first, second)
        assert third["ok"] is False
        assert 0 < third["retry_after"] <= 62
        assert str(_SPEED_MAX_PER_WINDOW) in third["error"]
        assert link.seen == first["probes"] + second["probes"], \
            "the refused test sent probes"

    async def test_after_the_window_it_runs_again(self):
        _, answers = await self._tests(3, age=62.0)
        assert all(answer["ok"] for answer in answers), answers

    async def test_a_short_test_gives_back_what_it_did_not_send(self):
        """A test reserves the most it could send; one cut short by its clock
        must not hold the far end's budget it never used."""
        node = await _node()
        target = NodeID.generate()
        try:
            reserved = _SPEED_MAX_BYTES // _SPEED_CHUNK + _SPEED_IDLE_PROBES
            assert node._speed_spend(target, reserved) == 0
            assert node._speed_spend(target, 20 - reserved) == 0
            assert node._speed_spend(target, reserved) == 0
            assert node._speed_spend(target, reserved) == 0
            assert node._speed_spend(target, reserved) > 0
        finally:
            await node.stop()

    async def test_the_count_is_bounded(self):
        from src.node import _MAX_PEERS
        node = await _node()
        try:
            for _ in range(_MAX_PEERS + 10):
                node._speed_spend(NodeID.generate(), 1)
            assert len(node._speed_spent) <= _MAX_PEERS
        finally:
            await node.stop()


class TestItMeasuresTheLinkSetUpForThroughput:
    """A speed test asks how much a link carries, which is what bulk traffic
    gets out of it: it declares bulk while it runs, and takes it back."""

    async def _measure(self, **kwargs):
        node = await _node()
        link = _Echoing(node)
        seen = []
        link.transport.set_profile = seen.append
        node._peers.append(link)
        try:
            answer = await node.console_speedtest(
                link.authenticated_id.raw.hex(), **kwargs)
            return node, link, seen, answer
        finally:
            node._peers.remove(link)
            await node.stop()

    async def test_bulk_while_it_runs_and_nothing_after(self):
        node, link, seen, answer = await self._measure()
        assert answer["ok"] is True and answer["profile"] == "bulk"
        assert seen == [frozenset({"bulk"}), frozenset()]
        assert not node._traffic

    async def test_default_measures_the_link_as_it_is(self):
        node, link, seen, answer = await self._measure(profile="default")
        assert answer["ok"] is True and answer["profile"] == "default"
        assert seen == []

    async def test_an_unknown_profile_is_refused(self):
        node, link, seen, answer = await self._measure(profile="turbo")
        assert answer["ok"] is False and seen == []
