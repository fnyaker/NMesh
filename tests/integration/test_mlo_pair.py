"""Two real nodes, two real links, one bundle.

The unit tests decide each rule on its own. This one proves the rules add up
over sockets: two nodes that hold both a TCP and a UDP link to each other
negotiate a cadence, probe fast enough to measure both links, form a bundle,
and then actually send down both of them.

The one thing here that no unit test can show is the part that goes wrong
quietly. A bundle is formed from *measurements*, and measurements come from
probes matched to their own answers — so if the token, the accord, the fast
cadence or the recent window is broken in any way, a bundle simply never forms
and everything goes on working at half the throughput with nothing anywhere
saying why.

Excluded from the default suite (see the pyproject addopts): it observes real
time, because a cadence is a thing that only exists in real time.
"""
import asyncio

import pytest

from src import MeshNode
from src import mlo
from src.transport_manager import TransportManager
from src.tcp_transport import TCPTransport, TCPServer
from src.udp_transport import UDPTransport, UDPServer


def make_node() -> MeshNode:
    manager = TransportManager()
    manager.register("tcp", TCPTransport, TCPServer)
    manager.register("udp", UDPTransport, UDPServer)
    return MeshNode(manager)


async def _wait(condition, timeout: float = 30.0, step: float = 0.05):
    """Poll an observable condition rather than sleeping at a guess."""
    deadline = asyncio.get_event_loop().time() + timeout
    while asyncio.get_event_loop().time() < deadline:
        if condition():
            return True
        await asyncio.sleep(step)
    return False


async def _two_linked_nodes(tcp_addr: str, udp_addr: str):
    """A pair holding a TCP link and a UDP link to each other.

    Both media are marked MLO ready and both nodes are held awake, which is
    what an operator ticking two boxes does."""
    for transport in (TCPTransport, UDPTransport):
        transport.SETTINGS = dict(transport.SETTINGS, mlo=True)
    host, guest = make_node(), make_node()
    code = host.generate_invite()
    await host.start([f"tcp://{tcp_addr}", f"udp://{udp_addr}"])
    await guest.join(f"tcp://{tcp_addr}", code)
    await guest.wait_for_session(timeout=20.0)
    await host.wait_for_session(timeout=20.0)
    # A second link over the other medium, to the same identity.
    await guest._dial_uri(host.id, f"udp://{udp_addr}", 10.0)
    for node in (host, guest):
        node.set_mlo_always(True)
    return host, guest


def _links_to(node: MeshNode, target) -> list:
    return [peer for peer in node._peers
            if peer.authenticated_id == target and peer.session is not None]


@pytest.mark.asyncio
class TestABundleOverRealSockets:
    async def test_two_links_negotiate_probe_and_bundle(self):
        host, guest = await _two_linked_nodes("127.0.0.1:19461", "127.0.0.1:19462")
        try:
            assert await _wait(lambda: len(_links_to(guest, host.id)) >= 2), \
                "the pair never held two links"

            # Both ends proposed a window, and both computed the same accord.
            assert await _wait(lambda: all(peer.ka_accord is not None
                                           for peer in _links_to(guest, host.id)))
            accords = {peer.ka_accord for peer in _links_to(guest, host.id)}
            assert accords == {mlo.accord(guest.keepalive_window(),
                                          host.keepalive_window())}

            # Candidacy buys the fast cadence, and the fast cadence is what
            # fills the window a bundle is judged on.
            guest._update_bundles()
            assert all(peer.ka_wanted_ms == mlo.FAST_MS
                       for peer in _links_to(guest, host.id))
            assert await _wait(
                lambda: all(peer.quality.recent_probes() >= mlo.MIN_PROBES
                            for peer in _links_to(guest, host.id)),
                timeout=30.0)

            guest._update_bundles()
            bundle = guest._bundles.get(host.id)
            assert bundle is not None and bundle.active, guest.mlo_status()
            assert guest.reorder_budget_ms(host.id) == pytest.approx(
                2 * bundle.skew_ms)

            # …and the traffic really goes down both of them.
            leads = {guest._route_candidates(host.id)[0] for _ in range(6)}
            assert len(leads) == 2, "one link carried everything"
        finally:
            await guest.stop()
            await host.stop()

    async def test_a_sleeping_node_holds_no_bundle_and_probes_slowly(self):
        """The trade an operator is agreeing to: a node nobody is using goes
        back to one probe per link every twenty seconds."""
        host, guest = await _two_linked_nodes("127.0.0.1:19463", "127.0.0.1:19464")
        try:
            assert await _wait(lambda: len(_links_to(guest, host.id)) >= 2)
            guest.set_mlo_always(False)
            guest._awake_since.clear()
            guest._awake_holds.clear()
            guest._update_bundles()
            assert guest._bundles == {}
            assert all(peer.ka_wanted_ms is None
                       for peer in _links_to(guest, host.id))
            assert all(guest._keepalive_interval(peer) == 20.0
                       for peer in _links_to(guest, host.id))
        finally:
            await guest.stop()
            await host.stop()
