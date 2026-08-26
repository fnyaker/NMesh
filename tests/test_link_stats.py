"""
What the mesh shows of itself, live.

Two things are tested here and they have the same shape: **the core knows
nothing of the medium**. A transport describes its own endpoints and its own
counters (`endpoints`/`stats`), the console displays them as they are — so a
transport this file has never seen becomes observable with no extra line. The
corollary is a test: a transport that lies, that raises, or that returns
anything at all must **not** break the snapshot.
"""
import asyncio

import pytest

from src.metrics import LinkQuality
from src.node import MeshNode
from tests.conftest import FakeTransport, make_manager, make_node


class TestLinkQuality:
    def test_one_number_is_not_a_measurement(self):
        """The starting point: two links with the same average RTT but very
        different jitter must not look alike."""
        steady, flappy = LinkQuality(), LinkQuality()
        for value in (0.020, 0.021, 0.020, 0.019):
            steady.on_ping(); steady.on_pong(value)
        for value in (0.002, 0.040, 0.003, 0.035):
            flappy.on_ping(); flappy.on_pong(value)
        assert abs(steady.as_dict()["avg_ms"] - flappy.as_dict()["avg_ms"]) < 1.0
        assert flappy.as_dict()["jitter_ms"] > steady.as_dict()["jitter_ms"] * 10

    def test_loss_needs_more_than_one_probe(self):
        """Une sonde en vol n'est pas 100 % de perte."""
        quality = LinkQuality()
        quality.on_ping()
        assert quality.loss() is None
        assert quality.as_dict()["loss"] is None

    def test_loss_is_counted_not_guessed(self):
        quality = LinkQuality()
        for _ in range(4):
            quality.on_ping()
        quality.on_pong(0.01)
        quality.on_pong(0.01)
        assert quality.as_dict()["loss"] == 0.5

    def test_history_is_bounded(self):
        """A link that lives for months must not grow memory."""
        quality = LinkQuality()
        for index in range(LinkQuality.HISTORY * 10):
            quality.on_ping(); quality.on_pong(index / 1000)
        assert len(quality.samples) == LinkQuality.HISTORY
        assert len(quality.as_dict()["samples_ms"]) == LinkQuality.HISTORY

    def test_an_empty_link_says_nothing_rather_than_zero(self):
        """Zero milliseconds would be a lie; "not measured" is the truth."""
        empty = LinkQuality().as_dict()
        assert empty["rtt_ms"] is None and empty["avg_ms"] is None
        assert empty["jitter_ms"] is None and empty["probes"] == 0


class HostileTransport(FakeTransport):
    """A transport that answers anything at all — because one will exist."""

    def endpoints(self):
        raise RuntimeError("boom")

    def stats(self):
        return {"fine": 1, "nested": {"not": "scalar"}, "huge": "x" * 10_000,
                **{f"key{i}": i for i in range(50)}}


class SilentTransport(FakeTransport):
    """The normal case of a medium with no address: a spool, a USB stick."""


class TalkativeTransport(FakeTransport):
    def endpoints(self):
        return {"local": "fake://here:1", "remote": "fake://there:2"}

    def stats(self):
        return {"retransmits": 7, "rto ms": 50.0}


class TestLinkView:
    async def test_a_transport_describes_itself(self):
        node, _fake = await make_node()
        try:
            peer = await node._inject_peer(TalkativeTransport())
            view = node._link_view(peer, 0.0)
            assert view["local"] == "fake://here:1"
            assert view["remote"] == "fake://there:2"
            assert view["stats"] == {"retransmits": 7, "rto ms": 50.0}
            assert view["direction"] == "outbound"
        finally:
            await node.stop()

    async def test_a_medium_without_an_address_is_not_an_error(self):
        node, _fake = await make_node()
        try:
            peer = await node._inject_peer(SilentTransport())
            view = node._link_view(peer, 0.0)
            assert view["local"] is None and view["remote"] is None
            assert view["stats"] == {}
        finally:
            await node.stop()

    async def test_a_broken_transport_cannot_break_the_snapshot(self):
        """A console falling over because a transport answered badly would be a
        crash caused by a peer. The bounds apply here too."""
        node, _fake = await make_node()
        try:
            peer = await node._inject_peer(HostileTransport())
            view = node._link_view(peer, 0.0)
            assert view["local"] is None            # endpoints() raised
            assert len(view["stats"]) <= 16         # bounded
            assert "nested" not in view["stats"]    # not scalar, dropped
            snapshot = await node.console_snapshot()
            assert snapshot["peers"][0]["link"]["local"] is None
        finally:
            await node.stop()


class TestAddressStatus:
    async def test_the_address_in_use_wins_over_the_log(self):
        node, _fake = await make_node()
        try:
            peer = await node._inject_peer(FakeTransport())
            peer.remote_addr = "tcp://10.0.0.1:9000"
            node._note_dial("aa" * 20, "tcp://10.0.0.1:9000", "refused", "OSError")
            rows = node._address_status("aa" * 20, ["tcp://10.0.0.1:9000"], peer)
            assert rows[0]["outcome"] == "in-use"
        finally:
            await node.stop()

    async def test_a_failure_is_remembered_with_its_reason(self):
        node, _fake = await make_node()
        try:
            node._note_dial("bb" * 20, "tcp://10.0.0.2:9000", "timeout", "", 5.0)
            rows = node._address_status(
                "bb" * 20, ["tcp://10.0.0.2:9000", "udp://10.0.0.2:9001"], None)
            by_uri = {row["uri"]: row for row in rows}
            assert by_uri["tcp://10.0.0.2:9000"]["outcome"] == "timeout"
            assert by_uri["tcp://10.0.0.2:9000"]["ms"] == 5000.0
            # An address never tried is not a broken address.
            assert by_uri["udp://10.0.0.2:9001"]["outcome"] == "untried"
        finally:
            await node.stop()

    async def test_an_accepted_link_shows_the_socket_it_arrived_on(self):
        """On the receiving side there is no dialled URI: the only address that
        exists is the one the medium observes, and it is the one carrying the
        traffic."""
        node, _fake = await make_node()
        try:
            peer = await node._inject_peer(TalkativeTransport())
            peer.remote_addr = None
            rows = node._address_status("cc" * 20, [], peer)
            assert rows == [{"uri": "fake://there:2", "outcome": "in-use",
                             "detail": "", "ago": None, "ms": None}]
        finally:
            await node.stop()

    async def test_the_log_is_bounded_on_both_axes(self):
        """A peer advertising a thousand addresses does not grow memory."""
        from src.node import _DIAL_LOG_ADDRESSES, _DIAL_LOG_NODES
        node, _fake = await make_node()
        try:
            for index in range(_DIAL_LOG_NODES * 2):
                node._note_dial(f"{index:040x}", "tcp://1.2.3.4:1", "refused")
            assert len(node._dial_log) <= _DIAL_LOG_NODES
            for index in range(_DIAL_LOG_ADDRESSES * 3):
                node._note_dial("dd" * 20, f"tcp://1.2.3.4:{index}", "refused")
            assert len(node._dial_log["dd" * 20]) <= _DIAL_LOG_ADDRESSES
        finally:
            await node.stop()


class TestSnapshotCarriesTheLink:
    async def test_topology_carries_what_the_map_draws(self):
        """The expanded map draws thickness from the bytes and colour from the
        quality: both have to be in the snapshot."""
        node, _fake = await make_node()
        try:
            snapshot = await node.console_snapshot()
            assert "topology" in snapshot
            peers = snapshot["peers"]
            assert peers and set(peers[0]["link"]) >= {
                "scheme", "direction", "since", "quality", "counters", "stats",
                "local", "remote", "dialled"}
        finally:
            await node.stop()
