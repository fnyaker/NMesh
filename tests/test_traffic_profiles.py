"""
What an app says its traffic needs, and what each layer does with it.

`src/mesh/traffic.py` holds the declarations; the node tells the links that
carry them (`medium.set_profile`) and stops striping realtime traffic; UDP picks
its timer floor from it and TCP its congestion control. The UDP half also holds
the measurement that made the idle timer learn the path: an ACK sooner after a
resend than half the shortest round trip answers the original.
"""
import socket
import struct
import time

import pytest

import src.transports.udp as udp_mod
from src.mesh import traffic
from src.mesh.traffic import TrafficProfiles
from src.node_id import NodeID
from src.packet import Packet
from src.transports.tcp import TCPTransport, _BULK_CONGESTION
from src.transports.udp import (_FRAME, _MAGIC, _RTO_FLOOR, _RTO_MIN,
                                FLAG_KEEPALIVE, UDPTransport, _ReliableLink)
from tests.conftest import FakeTransport
from tests.test_mlo import SPEAKS, TARGET, _link, _node, _ready, _second_medium

APP = b"A" * 8
OTHER_APP = b"B" * 8


def _packet(size: int = 100) -> Packet:
    return Packet(version=1, type=1, ttl=64, src_id=bytes(20), dst_id=bytes(20),
                  msg_id=0, nonce=bytes(12), gcm_tag=bytes(16), payload=b"x" * size)


# ---------------------------------------------------------------------------
# The table
# ---------------------------------------------------------------------------

class TestTheTable:
    def test_a_declaration_is_what_the_target_needs(self):
        table = TrafficProfiles()
        assert table.declare(APP, b"t" * 20, "realtime", 30, now=0.0)
        assert table.of(b"t" * 20) == {"realtime"}
        assert table.realtime(b"t" * 20)

    def test_two_apps_add_up(self):
        table = TrafficProfiles()
        table.declare(APP, b"t" * 20, "realtime", 30, now=0.0)
        table.declare(OTHER_APP, b"t" * 20, "bulk", 30, now=0.0)
        assert table.of(b"t" * 20) == {"realtime", "bulk"}

    def test_it_runs_out_unless_declared_again(self):
        table = TrafficProfiles()
        table.declare(APP, b"t" * 20, "bulk", 30, now=0.0)
        assert table.expire(29.0) is False
        assert table.expire(31.0) is True
        assert table.of(b"t" * 20) == frozenset() and not table

    def test_a_lifetime_is_clamped(self):
        table = TrafficProfiles()
        table.declare(APP, b"t" * 20, "bulk", 10 ** 6, now=0.0)
        assert table.view(0.0)[0]["expires_in"] == traffic.MAX_TTL

    def test_taking_it_back(self):
        table = TrafficProfiles()
        table.declare(APP, b"t" * 20, "bulk", 30, now=0.0)
        assert table.declare(APP, b"t" * 20, None, 0, now=1.0)
        assert not table

    def test_an_unknown_profile_is_refused(self):
        table = TrafficProfiles()
        assert not table.declare(APP, b"t" * 20, "turbo", 30, now=0.0)
        assert not table

    def test_one_app_is_bounded(self):
        table = TrafficProfiles()
        for index in range(traffic.MAX_PER_APP):
            assert table.declare(APP, index.to_bytes(20, "big"), "bulk", 30, 0.0)
        assert not table.declare(APP, b"\xff" * 20, "bulk", 30, 0.0)
        # Renewing what it already holds is not a new entry.
        assert table.declare(APP, (0).to_bytes(20, "big"), "bulk", 30, 0.0)

    def test_the_table_is_bounded_and_never_evicts(self):
        """One app must not push another's declaration out."""
        table = TrafficProfiles()
        apps = [bytes([i]) * 8 for i in range(traffic.MAX_TARGETS // traffic.MAX_PER_APP)]
        for a, app in enumerate(apps):
            for index in range(traffic.MAX_PER_APP):
                target = (a * 1000 + index).to_bytes(20, "big")
                assert table.declare(app, target, "bulk", 30, 0.0)
        assert not table.declare(OTHER_APP, b"\xfe" * 20, "bulk", 30, 0.0)
        assert len(table.targets()) == traffic.MAX_TARGETS

    def test_an_app_that_goes_takes_everything_it_declared(self):
        table = TrafficProfiles()
        table.declare(APP, b"t" * 20, "bulk", 30, now=0.0)
        table.declare(OTHER_APP, b"t" * 20, "realtime", 30, now=0.0)
        table.forget_app(APP)
        assert table.of(b"t" * 20) == {"realtime"}


# ---------------------------------------------------------------------------
# UDP: the timer floor, and timing a resend's original
# ---------------------------------------------------------------------------

class _Clock:
    def __init__(self) -> None:
        self.t = 1000.0

    def monotonic(self) -> float:
        return self.t


@pytest.fixture
def clock(monkeypatch):
    """The UDP module's own clock only: the event loop keeps the real one."""
    fake = _Clock()
    monkeypatch.setattr(udp_mod, "time", fake)
    return fake


def _measured(link: _ReliableLink, clock: _Clock, rtt: float) -> None:
    frame = link.build_frame(_packet())
    clock.t += rtt
    link.process_ack(struct.unpack_from("!I", frame, 4)[0], 0)


class TestTheTimerFloor:
    def test_undeclared_traffic_waits_out_a_stall(self, clock):
        link = _ReliableLink()
        for _ in range(20):
            _measured(link, clock, 0.020)
        assert link._rto == pytest.approx(_RTO_FLOOR)

    def test_declared_traffic_keeps_the_short_timer(self, clock):
        transport = UDPTransport()
        for _ in range(20):
            _measured(transport._link, clock, 0.020)
        transport.set_profile(frozenset({"realtime"}))
        assert transport._link._rto < _RTO_FLOOR
        assert transport._link._rto >= _RTO_MIN
        transport.set_profile(frozenset({"bulk"}))
        assert transport._link._rto < _RTO_FLOOR

    def test_taking_the_declaration_back_restores_the_floor_at_once(self, clock):
        transport = UDPTransport()
        for _ in range(20):
            _measured(transport._link, clock, 0.020)
        transport.set_profile(frozenset({"realtime"}))
        transport.set_profile(frozenset())
        assert transport._link._rto == pytest.approx(_RTO_FLOOR)

    def test_the_link_says_what_it_was_told(self):
        transport = UDPTransport()
        assert transport.stats()["profile"] == "default"
        transport.set_profile(frozenset({"realtime", "bulk"}))
        assert transport.stats()["profile"] == "bulk, realtime"


class TestALateOriginalIsTimed:
    """With one frame in flight, the frames slower than the timer were exactly
    the ones resent, Karn forbade timing them, and F-RTO needs a second frame
    to decide: the estimate never saw the path's stalls."""

    def _late(self, clock, answer_after_resend: float):
        link = _ReliableLink()
        link.set_rto_floor(_RTO_MIN)
        for _ in range(20):
            _measured(link, clock, 0.030)
        cwnd = link._cwnd
        srtt = link._srtt
        frame = link.build_frame(_packet())
        clock.t += link._rto + 0.001
        resent = link.get_retransmit_frames()
        assert resent and link.timeouts == 1
        clock.t += answer_after_resend
        link.process_ack(struct.unpack_from("!I", frame, 4)[0], 0)
        return link, cwnd, srtt

    def test_an_answer_too_soon_for_the_resend_times_the_original(self, clock):
        link, cwnd, srtt = self._late(clock, 0.005)       # < 30 ms / 2
        assert link._srtt > srtt
        assert link.spurious == 1
        assert link._cwnd >= cwnd                          # the cut is undone

    def test_a_needless_fast_retransmit_is_not_a_timeout(self, clock):
        """A SACK hole resent fast and then filled by its late original is
        undone like a spurious timeout — and counted as what it was. Counted as
        a timeout, a link with no timeout at all read "1 spurious timeout"."""
        link = _ReliableLink()
        for _ in range(20):
            _measured(link, clock, 0.030)
        frames = [link.build_frame(_packet()) for _ in range(5)]
        seqs = [struct.unpack_from("!I", frame, 4)[0] for frame in frames]
        clock.t += 0.010
        resent = link.process_ack((seqs[0] - 1) & 0xFFFFFFFF, 0b1110)
        assert frames[0] in resent
        clock.t += 0.002            # < half the 10 ms the SACKed frames took
        link.process_ack(seqs[3], 0)
        assert link.timeouts == 0 and link.spurious == 0
        assert link.spurious_fast == 1

    def test_an_answer_that_could_be_the_resends_is_not_timed(self, clock):
        link, cwnd, srtt = self._late(clock, 0.020)       # >= 30 ms / 2
        assert link._srtt == srtt
        assert link.spurious == 0
        assert link._cwnd < cwnd


# ---------------------------------------------------------------------------
# TCP: bulk asks for a congestion control that does not halve on every loss
# ---------------------------------------------------------------------------

class _Writer:
    def __init__(self, sock) -> None:
        self._sock = sock

    def get_extra_info(self, name):
        return self._sock if name == "socket" else None


def _bbr_allowed() -> bool:
    option = getattr(socket, "TCP_CONGESTION", None)
    if option is None:
        return False
    probe = socket.socket()
    try:
        probe.setsockopt(socket.IPPROTO_TCP, option, _BULK_CONGESTION)
        return True
    except OSError:
        return False
    finally:
        probe.close()


def _congestion(sock) -> bytes:
    return sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_CONGESTION,
                           16).split(b"\0", 1)[0]


class TestBulkOverTCP:
    @pytest.mark.skipif(not _bbr_allowed(), reason="this kernel will not let us choose bbr")
    def test_bulk_asks_for_bbr_and_gives_it_back(self):
        sock = socket.socket()
        try:
            before = _congestion(sock)
            transport = TCPTransport()
            transport._writer = _Writer(sock)
            transport.set_profile(frozenset({"bulk"}))
            assert _congestion(sock) == _BULK_CONGESTION
            transport.set_profile(frozenset({"realtime"}))
            assert _congestion(sock) == before
        finally:
            sock.close()

    def test_a_refusal_leaves_the_link_working(self, monkeypatch):
        class Refusing:
            def getsockopt(self, *args):
                return b"cubic\0"

            def setsockopt(self, *args):
                raise PermissionError(1, "Operation not permitted")

        transport = TCPTransport()
        transport._writer = _Writer(Refusing())
        transport.set_profile(frozenset({"bulk"}))     # must not raise
        assert transport._profile == {"bulk"}

    def test_a_link_without_a_socket_is_left_alone(self):
        TCPTransport().set_profile(frozenset({"bulk"}))


# ---------------------------------------------------------------------------
# The node: which links are told, and realtime is never striped
# ---------------------------------------------------------------------------

class _Recording(FakeTransport):
    def __init__(self) -> None:
        super().__init__()
        self.profiles: list = []

    def set_profile(self, profile) -> None:
        self.profiles.append(profile)


def _recording_link(node, target=TARGET, uri="fake://a:1"):
    peer = _link(node, target, uri=uri, mean_ms=10.0, probes=50)
    peer.transport = _Recording()
    return peer


class TestTheNodeTellsTheLinks:
    def test_every_link_to_the_target_is_told(self):
        node = _node()
        first = _recording_link(node)
        second = _recording_link(node, uri="fake2://b:2")
        assert node.set_traffic_profile(APP, TARGET, "bulk", 30)
        assert first.transport.profiles == [frozenset({"bulk"})]
        assert second.transport.profiles == [frozenset({"bulk"})]

    def test_a_link_to_another_node_is_not(self):
        node = _node()
        _recording_link(node)
        other = _recording_link(node, NodeID(b"\x33" * 20), uri="fake://c:3")
        node.set_traffic_profile(APP, TARGET, "realtime", 30)
        assert other.transport.profiles == []

    def test_a_routed_target_is_carried_by_its_first_hop(self):
        node = _node()
        hop = _recording_link(node)
        far = NodeID(b"\x12" + b"\x11" * 19)          # nearest to the hop
        node.set_traffic_profile(APP, far, "bulk", 30)
        assert hop.transport.profiles == [frozenset({"bulk"})]

    def test_a_link_is_told_only_when_what_it_carries_changes(self):
        node = _node()
        peer = _recording_link(node)
        node.set_traffic_profile(APP, TARGET, "bulk", 30)
        node.set_traffic_profile(APP, TARGET, "bulk", 30)      # a renewal
        node._apply_traffic_profiles()
        assert peer.transport.profiles == [frozenset({"bulk"})]

    def test_expiry_takes_it_back(self):
        node = _node()
        peer = _recording_link(node)
        node.set_traffic_profile(APP, TARGET, "bulk", 30)
        for entries in node._traffic._held.values():
            for app, (profile, _until) in list(entries.items()):
                entries[app] = (profile, time.monotonic() - 1)
        node._apply_traffic_profiles()
        assert peer.transport.profiles[-1] == frozenset()

    def test_an_app_that_goes_takes_it_back(self):
        node = _node()
        peer = _recording_link(node)
        node.set_traffic_profile(APP, TARGET, "realtime", 30)
        node.forget_traffic_profiles(APP)
        assert peer.transport.profiles[-1] == frozenset()

    def test_a_medium_that_throws_is_left_as_it_was(self):
        node = _node()
        peer = _link(node, mean_ms=10.0, probes=50)

        class Broken(FakeTransport):
            def set_profile(self, profile):
                raise RuntimeError("nope")

        peer.transport = Broken()
        assert node.set_traffic_profile(APP, TARGET, "bulk", 30)


class TestRealtimeIsNotStriped:
    def _bundled(self):
        node = _node()
        _second_medium(node)
        _ready(node, "fake", "fake2")
        node.note_awake("test")
        first = _link(node, uri="fake://a:1", mean_ms=10.0, probes=50)
        second = _link(node, uri="fake2://b:2", mean_ms=11.0, probes=50)
        node._update_bundles()
        assert node._bundles[TARGET].active
        return node, first, second

    def test_undeclared_traffic_is_spread(self):
        node, first, second = self._bundled()
        heads = {id(node._stripe(TARGET, [first, second])[0]) for _ in range(8)}
        assert heads == {id(first), id(second)}

    def test_realtime_traffic_takes_the_best_link_alone(self):
        node, first, second = self._bundled()
        node.set_traffic_profile(APP, TARGET, "realtime", 30)
        heads = {id(node._stripe(TARGET, [first, second])[0]) for _ in range(8)}
        assert heads == {id(first)}

    def test_bulk_traffic_is_still_spread(self):
        node, first, second = self._bundled()
        node.set_traffic_profile(APP, TARGET, "bulk", 30)
        heads = {id(node._stripe(TARGET, [first, second])[0]) for _ in range(8)}
        assert heads == {id(first), id(second)}
