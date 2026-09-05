"""
What the background loops do when there is nothing to do.

A node at rest used to wake fifty-eight times a minute, and all but three of
those were timers whose whole purpose was to find nothing: three booleans to
test, two empty dictionaries to walk, sixty-four routing entries to scan and
rediscover that no medium had asked to be retried. None of it was expensive on
its own, and all of it ran for the life of the process on every node in the
mesh.

The other half is reactivity, and it is the half that actually cost something. A
change waited out the rest of whatever tick it landed in: a state change up to
two seconds unwritten, a stalled handshake up to five before anything re-drove
it. Waiting for a clock to come round is not the same as waiting for the thing
you are actually waiting for.

So each of these waits on its own event, or on the moment the next piece of work
is genuinely due. What is proved here: they are quiet when they should be, they
react when they should, and — the one that would be a real fault — none of them
can spin.
"""
import asyncio
import time

import pytest

from src.node import MeshNode, NodeID, _E2E_RETRY_INTERVAL
from tests.conftest import make_manager


def _node() -> MeshNode:
    return MeshNode(transport_manager=make_manager())


class TestTheE2ERetryKnowsWhenItIsDue:
    def test_nothing_queued_means_nothing_to_wait_for(self):
        """The normal state of a healthy node, and the one it should spend
        asleep rather than walking two empty dictionaries every five seconds."""
        assert _node()._e2e_retry_wait() is None

    def test_a_target_never_attempted_is_due_now(self):
        node = _node()
        node._e2e_pending_data[NodeID(b"\x21" * 20)] = [b"x"]
        assert node._e2e_retry_wait() == 0.0

    def test_a_target_just_attempted_waits_out_its_own_interval(self):
        node = _node()
        target = NodeID(b"\x21" * 20)
        node._e2e_pending_data[target] = [b"x"]
        node._e2e_attempt[target] = time.monotonic()
        wait = node._e2e_retry_wait()
        assert 0 < wait <= _E2E_RETRY_INTERVAL

    def test_a_target_that_has_a_session_is_not_waited_on(self):
        node = _node()
        target = NodeID(b"\x21" * 20)
        node._e2e_pending_data[target] = [b"x"]
        node._e2e_sessions[target] = object()
        assert node._e2e_retry_wait() is None

    async def test_a_target_it_cannot_handshake_does_not_spin(self, monkeypatch):
        """The failure mode a due-time loop invites, and the one that would
        matter: `_initiate_e2e_handshake` returns without recording an attempt
        when this node has no chain to present, so the target stays due for
        ever. Without a floor that is a busy loop at a hundred percent of a
        core, on exactly the node that is already broken."""
        monkeypatch.setattr("src.node._E2E_RETRY_INTERVAL", 0.02)
        node = _node()
        node._e2e_pending_data[NodeID(b"\x21" * 20)] = [b"x"]
        tries = []

        async def _records_nothing(target):
            tries.append(target)

        node._initiate_e2e_handshake = _records_nothing
        node._running = True
        task = asyncio.create_task(node._e2e_retry_loop())
        try:
            await asyncio.sleep(0.25)
        finally:
            node._running = False
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass
        # A quarter of a second at a 20 ms floor is a dozen passes at most.
        # A spin would be thousands.
        assert 1 <= len(tries) <= 25, len(tries)


class TestTheAddressRetryKnowsWhenItIsDue:
    def test_no_medium_asks_to_be_retried_by_default(self):
        """`retry_interval` ships at 0 on every transport, so a stock node has
        nothing this loop may ever act on — and used to rescan sixty-four
        routing entries every five seconds to establish that."""
        node = _node()
        node._routing.add(NodeID(b"\x31" * 20), ["fake://a:1"])
        assert node._retry_wait() is None

    def test_an_address_never_dialled_is_due_at_once(self):
        node = _node()
        node._routing.add(NodeID(b"\x31" * 20), ["fake://a:1"])
        node._retry_interval = lambda uri: 30.0
        assert node._retry_wait() == 0.0

    def test_an_address_just_dialled_waits_out_the_medium_s_cadence(self):
        node = _node()
        target = NodeID(b"\x31" * 20)
        node._routing.add(target, ["fake://a:1"])
        node._retry_interval = lambda uri: 30.0
        node._note_dial(target.raw.hex(), "fake://a:1", "no-answer")
        wait = node._retry_wait()
        assert 0 < wait <= 30.0

    def test_a_node_already_linked_is_not_waited_on(self):
        from src.node import _Peer
        from tests.conftest import FakeTransport
        node = _node()
        target = NodeID(b"\x31" * 20)
        node._routing.add(target, ["fake://a:1"])
        node._retry_interval = lambda uri: 30.0
        peer = _Peer(FakeTransport(), is_client_side=True)
        peer.authenticated_id, peer.session = target, object()
        node._peers.append(peer)
        assert node._retry_wait() is None


class TestTheStateWriterWaitsForAChange:
    async def test_it_writes_nothing_while_nothing_is_dirty(self, monkeypatch):
        monkeypatch.setattr("src.node._STATE_WRITE_INTERVAL", 0.01)
        node = _node()
        writes = []

        def _write():
            node._state_dirty = False
            writes.append(1)

        node._write_state_now = _write
        node._running = True
        task = asyncio.create_task(node._state_writer_loop())
        try:
            await asyncio.sleep(0.15)
            assert writes == []
            # …and the change itself is what starts it, not the next tick.
            node._state_dirty = True
            node._state_wakeup.set()
            await asyncio.sleep(0.15)
            assert writes
        finally:
            node._running = False
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass

    async def test_it_stops_once_nothing_is_dirty_and_the_node_is_down(self):
        """`_stop_state_writer` cancels this and flushes what is left, so the
        loop owes shutdown nothing beyond ending."""
        node = _node()
        node._running = False
        await asyncio.wait_for(node._state_writer_loop(), timeout=1.0)


class TestSteeringWaitsOnItsSwitch:
    async def test_it_is_quiet_while_off_and_starts_when_switched_on(
            self, monkeypatch):
        monkeypatch.setattr("src.node._ADDR_STEER_INTERVAL", 0.01)
        node = _node()
        passes = []

        async def _pass():
            passes.append(1)
            return "nothing to examine"

        node._steer_pass = _pass
        node._running = True
        task = asyncio.create_task(node._address_steering_loop())
        try:
            await asyncio.sleep(0.1)
            assert passes == [], "steering ran while it was switched off"
            node.set_dynamic_address(True)
            await asyncio.sleep(0.1)
            assert passes, "the switch did not wake the loop"
        finally:
            node._running = False
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass


class TestTheWakesAreWiredUp:
    def test_a_lost_link_makes_its_addresses_dialable_again(self):
        from src.node import _Peer
        from tests.conftest import FakeTransport
        node = _node()
        peer = _Peer(FakeTransport(), is_client_side=True)
        peer.authenticated_id, peer.session = NodeID(b"\x31" * 20), object()
        node._retry_wakeup.clear()
        node._note_node_lost(peer)
        assert node._retry_wakeup.is_set()

    def test_a_medium_s_settings_changing_wakes_the_retry(self):
        """Turning `retry_interval` on must not wait out a ceiling: the loop is
        asleep precisely because the setting said there was nothing to do."""
        node = _node()
        node._retry_wakeup.clear()
        node._transport_manager.configure("fake", {})
        assert node._retry_wakeup.is_set()
