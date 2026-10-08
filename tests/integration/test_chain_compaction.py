"""
Integration: a chain that stays two long however the mesh grew.

A member's certificate is signed by whoever invited it, so each generation of
invitations used to add a ~7 kB certificate: the fourth generation no longer fit
a routing answer, the sixth was refused by every handshake (`_ENTRY_CHAIN_MAX`)
and the seventh could not join at all. The root now signs a member directly once
its chain proves it belongs, and remembers who it was vouched through so that a
revocation by any of them still reaches it.

Real TCP on loopback, real post-quantum certificates.
"""
import asyncio

import pytest

from src import MeshNode
from src.transport_manager import TransportManager
from src.tcp_transport import TCPTransport, TCPServer
from tests.integration import free_port

pytestmark = pytest.mark.xdist_group("chain_compaction")


def _node() -> MeshNode:
    manager = TransportManager()
    manager.register("tcp", TCPTransport, TCPServer)
    return MeshNode(manager)


def _chain_len(node: MeshNode) -> int:
    return len(node._cert_store.get_chain_to_root(node.id) or [])


async def _until(predicate, seconds: float = 15.0) -> bool:
    for _ in range(int(seconds / 0.1)):
        if predicate():
            return True
        await asyncio.sleep(0.1)
    return predicate()


async def _line(generations: int, compact: bool = True):
    """root invites n1, n1 invites n2, ... — each compacted before it invites,
    unless ``compact`` is off."""
    base = free_port(generations + 1)
    nodes = [_node()]
    await nodes[0].start([f"tcp://127.0.0.1:{base}"])
    for index in range(1, generations + 1):
        node = _node()
        await node.start([f"tcp://127.0.0.1:{base + index}"])
        await node.join(f"tcp://127.0.0.1:{base + index - 1}",
                        nodes[-1].generate_invite())
        await node.wait_for_session(timeout=20)
        nodes.append(node)
        if compact and _chain_len(node) > 2:
            assert await node._compact_own_chain()
            assert await _until(lambda: _chain_len(node) == 2)
    return nodes, base


class TestTheChainStaysShort:

    async def test_every_generation_ends_two_certificates_long(self):
        nodes, base = await _line(5)
        try:
            assert [_chain_len(n) for n in nodes[1:]] == [2] * 5
            root, deepest = nodes[0], nodes[-1]
            # The deepest one authenticates to the root directly, which a
            # seven-long chain never could. Compacting usually opened that link
            # already; if not, dial it.
            if not any(p.authenticated_id == root.id and p.session
                       for p in deepest._peers):
                await deepest._dial_uri(root.id, f"tcp://127.0.0.1:{base}", 10.0)
            assert any(p.authenticated_id == root.id and p.session
                       for p in deepest._peers)
            assert len(root._cert_store.lineage) == 4      # n2..n5 were compacted
        finally:
            for node in nodes:
                await node.stop()

    async def test_a_chain_to_somebody_else_is_not_shortened(self):
        nodes, _ = await _line(2)
        try:
            root, first, second = nodes
            # `first` is not a root: a chain sent to it is a chain to another.
            chain = second._cert_store.get_chain_to_root(second.id)
            from src.node import _COMPACT_MAGIC, _encode_chain, CERT_RENEW
            from src.packet import Packet
            before = len(first._cert_store.lineage)
            await first._serve_chain_compaction(Packet.create(
                CERT_RENEW, second.id.raw, first.id.raw,
                _COMPACT_MAGIC + _encode_chain(chain)))
            assert len(first._cert_store.lineage) == before
        finally:
            for node in nodes:
                await node.stop()


class TestWhatTheRootRefuses:

    async def test_somebody_elses_chain_and_noise_change_nothing(self):
        import os
        from src.node import _COMPACT_MAGIC, _encode_chain, CERT_RENEW
        from src.packet import Packet
        nodes, _ = await _line(2)
        root, first, second = nodes
        try:
            # second's original, long chain: signed by first, then first's own.
            by_first = next(c for c in second._cert_store.certs_for(second.id)
                            if c.issuer_id == first.id)
            long_chain = [by_first] + first._cert_store.get_chain_to_root(first.id)
            assert len(long_chain) == 3
            issued = len(root._cert_store.certs_for(second.id))
            book = dict(root._cert_store.lineage.to_json())
            # Sent under first's id: only the subject may ask for its own.
            await root._serve_chain_compaction(Packet.create(
                CERT_RENEW, first.id.raw, root.id.raw,
                _COMPACT_MAGIC + _encode_chain(long_chain)))
            for _ in range(50):
                await root._serve_chain_compaction(Packet.create(
                    CERT_RENEW, second.id.raw, root.id.raw,
                    _COMPACT_MAGIC + os.urandom(os.urandom(1)[0] * 40)))
            assert len(root._cert_store.certs_for(second.id)) == issued
            assert root._cert_store.lineage.to_json() == book
        finally:
            for node in nodes:
                await node.stop()


class TestARevocationStillReachesACompactedMember:

    async def test_the_inviters_revocation_is_passed_on_by_the_root(self):
        nodes, _ = await _line(3)
        root, first, second, third = nodes
        try:
            # `first` invited `second`, which invited `third`; both now hold a
            # certificate signed by the root. `first` takes `second` back.
            assert first.console_revoke_member(second.id.raw.hex())
            assert await _until(
                lambda: root._cert_store.lineage.ancestors(third.id.raw) == ())

            def voided(node):
                return not any(c.issuer_id == root.id and
                               not root._cert_store.is_revoked(c)
                               for c in root._cert_store.certs_for(node.id))
            assert voided(second) and voided(third)
            assert not voided(first)
        finally:
            for node in nodes:
                await node.stop()


class TestTheRootIsNotNeeded:
    """Decentralised means a member never depends on one node being up."""

    async def test_with_the_root_gone_an_ancestor_shortens_the_chain(self):
        nodes, _ = await _line(4, compact=False)
        root, first, second, third, fourth = nodes
        try:
            assert _chain_len(fourth) == 5
            await root.stop()
            # Root first, then down the chain: the root stays silent, so the
            # next ask goes to `first`, whose chain is two long.
            for _ in range(3):
                fourth._compact_not_before = 0.0
                await fourth._compact_own_chain()
                if await _until(lambda: _chain_len(fourth) < 5, 4.0):
                    break
            assert _chain_len(fourth) == 3
            assert fourth._cert_store.get_chain_to_root(fourth.id)[0].issuer_id == first.id
            assert first._cert_store.lineage.ancestors(fourth.id.raw)
        finally:
            for node in nodes[1:]:
                await node.stop()

    async def test_every_membership_is_renewed_and_the_long_chain_is_a_fallback(
            self, monkeypatch):
        import src.node as node_mod
        nodes, _ = await _line(2)
        root, first, second = nodes
        try:
            assert _chain_len(second) == 2      # signed by the root directly
            sent = []

            async def _record(packet, **_):
                sent.append(packet.dst_id)
            monkeypatch.setattr(node_mod, "_CERT_RENEW_WINDOW", 10 ** 9)
            monkeypatch.setattr(second, "_route_outbound", _record)
            assert await second._renew_own_membership()
            assert {root.id.raw, first.id.raw} <= set(sent)
            # Without the root's certificate the chain through the inviter
            # still holds: nothing about the member depended on the root.
            store = second._cert_store
            store._certs[second.id.raw] = [c for c in store.certs_for(second.id)
                                           if c.issuer_id != root.id]
            store._chains.clear()
            assert _chain_len(second) == 3
        finally:
            for node in nodes:
                await node.stop()
