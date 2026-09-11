"""
Proving our own public address instead of guessing it.

`_extra_addrs` holds IPs somebody reported seeing us at — an HTTPS probe, a
peer's `OBSERVED_ADDR`, a STUN reflexive address. `advertised_uris` paired each
of them with the **local listener port** and announced the result, which is not
an address: it is a claim that the NAT in front of this machine forwards that
port, made from no evidence, and the mesh carried it to everybody.

Two nodes behind one household or office IP therefore announced the *same URI*
and took turns being wrong about it. Whoever the router forwards to answers, so
the other one's entry is struck off ("it answers as somebody else"); and a node
whose router forwards back to itself dials its own public address and refuses
its own handshake ("the challenge presents our own identity"). Both were read
as bugs in the mesh. Neither was.

What is proved here: a public endpoint is announced only once somebody **off
our own networks** has opened that transport to us; a LAN peer's inbound link
is not that proof and does not make us a relay for the world; the proof is
actually produced rather than waited for (AutoNAT had one caller, a console
button); addressing moving withdraws it; and when a collision does happen the
node names the cause instead of the symptom.
"""
import asyncio
import time

import pytest

from src.ip_utils import ip_reachability, is_global_ip
from src.node import (MeshNode, NodeID, _Peer, _AUTONAT_RETRY_MAX,
                      _AUTONAT_RETRY_MIN)
from tests.conftest import FakeTransport, make_manager


TARGET = NodeID(b"\x11" * 20)


def _node() -> MeshNode:
    node = MeshNode(transport_manager=make_manager())
    node._running = True
    return node


class _Remote(FakeTransport):
    """A transport that says where its peer is, as a socket-based one does."""

    def __init__(self, ip: str | None) -> None:
        super().__init__()
        self._ip = ip

    def remote_ip(self):
        return self._ip


def _link(node: MeshNode, ip: str | None, *, target: NodeID = TARGET,
          uri: str = "fake://a:1") -> _Peer:
    peer = _Peer(_Remote(ip), is_client_side=True)
    peer.authenticated_id = target
    peer.session = object()
    peer.remote_addr = uri
    node._peers.append(peer)
    return peer


class TestWhatMayBeAnnounced:
    def test_a_local_address_needs_no_proof(self):
        """It is an address of an interface on this machine. A peer that
        cannot reach it simply fails to."""
        node = _node()
        node._addresses = ["tcp://0.0.0.0:9000"]
        node._local_ips = ["192.168.1.20"]
        assert node.advertised_uris() == ["tcp://192.168.1.20:9000"]

    def test_a_discovered_public_ip_is_not_announced_unproved(self):
        node = _node()
        node._addresses = ["tcp://0.0.0.0:9000"]
        node._local_ips = ["192.168.1.20"]
        node._extra_addrs = ["81.240.12.33"]
        assert "tcp://81.240.12.33:9000" not in node.advertised_uris()

    def test_and_is_announced_once_the_listener_is_proved(self):
        node = _node()
        node._addresses = ["tcp://0.0.0.0:9000"]
        node._local_ips = ["192.168.1.20"]
        node._extra_addrs = ["81.240.12.33"]
        node._note_public_scheme("tcp")
        assert "tcp://81.240.12.33:9000" in node.advertised_uris()

    def test_the_proof_is_per_transport(self):
        """tcp forwarded and udp not is an ordinary router configuration."""
        node = _node()
        node._addresses = ["tcp://0.0.0.0:9000", "udp://0.0.0.0:9000"]
        node._local_ips = []
        node._extra_addrs = ["81.240.12.33"]
        node._note_public_scheme("tcp")
        assert node.advertised_uris() == ["tcp://81.240.12.33:9000"]

    def test_a_concrete_listen_uri_is_the_operator_s_way_to_say_so(self):
        """Somebody who knows their forwarding works has always been able to
        state it, and still can: only wildcards are expanded."""
        node = _node()
        node._addresses = ["tcp://81.240.12.33:9000"]
        node._local_ips = ["192.168.1.20"]
        assert node.advertised_uris() == ["tcp://81.240.12.33:9000"]


class TestWhatCountsAsProof:
    def test_a_peer_off_our_networks_proves_it(self):
        node = _node()
        assert node._off_our_networks(_link(node, "81.240.12.33")) is True

    def test_a_peer_on_our_lan_does_not(self):
        """It dialled a LAN address. That proves the listener and says nothing
        whatever about the NAT in front of it."""
        node = _node()
        for ip in ("192.168.1.9", "10.0.0.4", "127.0.0.1", "169.254.1.1"):
            assert node._off_our_networks(_link(node, ip)) is False, ip

    def test_a_transport_that_cannot_say_proves_nothing(self):
        node = _node()
        assert node._off_our_networks(_link(node, None)) is False

    def test_a_relayed_link_is_never_evidence_about_a_listener(self):
        """Nothing was opened to us."""
        from src.node import RelayedTransport
        node = _node()
        peer = _link(node, "81.240.12.33")
        peer.transport = RelayedTransport.__new__(RelayedTransport)
        assert node._off_our_networks(peer) is False

    def test_proving_it_announces_the_new_set(self):
        node = _node()
        node._addresses = ["tcp://0.0.0.0:9000"]
        node._extra_addrs = ["81.240.12.33"]
        sent: list[str] = []
        node._announce_addresses_soon = lambda reason: sent.append(reason)
        node._note_public_scheme("tcp")
        node._note_public_scheme("tcp")          # already known: no second one
        assert len(sent) == 1


class TestTheTwoAudiences:
    """A `lan` descriptor and a `world` one are claims to different people and
    are not proved by the same thing."""

    def test_a_lan_descriptor_is_confirmed_by_any_inbound_link(self):
        rows = ip_reachability("tcp", "tcp://0.0.0.0:9000", ["192.168.1.5"],
                               ["1.1.1.1"], True, False)
        lan = [r for r in rows if r["scope"] == "lan"]
        assert lan and all(r["confirmed"] for r in lan)

    def test_a_world_descriptor_is_not(self):
        rows = ip_reachability("tcp", "tcp://0.0.0.0:9000", ["192.168.1.5"],
                               ["1.1.1.1"], True, False)
        world = [r for r in rows if r["scope"] == "world"]
        assert world and not any(r["confirmed"] for r in world)

    def test_an_older_transport_signature_behaves_as_it_did(self):
        rows = ip_reachability("tcp", "tcp://0.0.0.0:9000", ["192.168.1.5"],
                               ["1.1.1.1"], True)
        assert all(r["confirmed"] for r in rows)

    def test_is_global_ip_is_one_answer(self):
        assert is_global_ip("81.240.12.33") and not is_global_ip("192.168.1.1")


class TestTheProofIsProduced:
    """AutoNAT was written, documented and tested, and the only thing that ever
    called it was a button in the console — the shape `gotchas.md` calls "a
    feature whose precondition nothing produces". The announcement rests on it
    now, so something has to ask."""

    def _listening(self, node: MeshNode, uris: list[str]) -> None:
        node._transport_manager.listening_uris = lambda: uris

    def test_nothing_to_ask_when_every_scheme_is_proved(self):
        node = _node()
        self._listening(node, ["tcp://0.0.0.0:9000"])
        assert node._autonat_due() is True
        node._public_schemes = {"tcp"}
        node._autonat_at = time.monotonic()
        assert node._autonat_due() is False

    def test_a_proof_is_re_established_before_it_can_rot(self):
        """A router forgets a rule, an ISP moves us behind a different CGNAT.
        A confirmation nobody re-checks is how a node goes on announcing an
        address that stopped working months ago."""
        from src.node import _AUTONAT_REFRESH
        node = _node()
        self._listening(node, ["tcp://0.0.0.0:9000"])
        node._public_schemes = {"tcp"}
        node._autonat_at = time.monotonic() - _AUTONAT_REFRESH - 1
        assert node._autonat_due() is True

    async def test_a_round_asks_and_backs_off_when_it_proves_nothing(self):
        node = _node()
        self._listening(node, ["tcp://0.0.0.0:9000"])
        _link(node, "81.240.12.33")
        asked = []

        async def _probe():
            asked.append(1)
            return 1

        node.probe_reachability = _probe
        gaps = []
        for _ in range(8):
            node._autonat_next = 0.0
            await node._autonat_round()
            gaps.append(node._autonat_next - time.monotonic())
        assert len(asked) == 8
        assert gaps[0] == pytest.approx(_AUTONAT_RETRY_MIN, abs=1.0)
        assert gaps[1] > gaps[0]
        assert max(gaps) <= _AUTONAT_RETRY_MAX + 1

    async def test_a_round_that_proved_something_starts_over(self):
        node = _node()
        self._listening(node, ["tcp://0.0.0.0:9000", "udp://0.0.0.0:9000"])
        _link(node, "81.240.12.33")

        async def _probe():
            node._public_schemes.add("tcp")
            return 1

        node.probe_reachability = _probe
        node._autonat_rounds = 4
        await node._autonat_round()
        assert node._autonat_rounds == 0

    async def test_nobody_off_our_networks_means_nobody_to_ask(self):
        node = _node()
        self._listening(node, ["tcp://0.0.0.0:9000"])
        _link(node, "192.168.1.9")
        asked = []
        node.probe_reachability = lambda: asked.append(1)
        assert await node._autonat_round() == 0
        assert asked == []

    async def test_the_loop_survives_a_probe_that_raises(self):
        """This loop dying takes the node's public address with it, quietly."""
        node = _node()
        self._listening(node, ["tcp://0.0.0.0:9000"])
        _link(node, "81.240.12.33")
        calls = []

        async def _boom():
            calls.append(1)
            raise OSError("no route")

        node.probe_reachability = _boom
        node._ensure_autonat()
        try:
            node._autonat_next = 0.0
            node._wake_autonat()
            deadline = time.monotonic() + 5.0
            while not calls and time.monotonic() < deadline:
                await asyncio.sleep(0.05)
            task = node._autonat_task
            assert task is not None and not task.done()
        finally:
            await node._stop_autonat()
        assert calls

    async def test_addressing_moving_withdraws_the_proof(self):
        """It was proved about an address we no longer have."""
        node = _node()
        node._public_schemes = {"tcp"}
        node._on_network_change({"local_ips": ["10.0.0.9"]},
                                {"local_ips": ([], ["10.0.0.9"])})
        assert node._public_schemes == set()


class TestNamingTheCollision:
    def test_our_own_public_ip_is_named_as_the_cause(self):
        """"It answers as somebody else" is true and tells an operator
        nothing."""
        node = _node()
        node._extra_addrs = ["81.240.12.33"]
        detail = node._wrong_node_detail("tcp://81.240.12.33:9000", TARGET)
        assert "81.240.12.33" in detail and "one port" in detail

    def test_anything_else_still_names_who_answered(self):
        node = _node()
        detail = node._wrong_node_detail("tcp://203.0.113.4:9000", TARGET)
        assert TARGET.raw.hex() in detail

    def test_ourselves_is_its_own_sentence(self):
        node = _node()
        assert "this node itself" in node._wrong_node_detail(
            "tcp://203.0.113.4:9000", node._id)

    def test_a_broken_uri_does_not_raise(self):
        node = _node()
        for rubbish in ("", "://", "no-scheme", "tcp:/x"):
            assert node._wrong_node_detail(rubbish, TARGET)
