"""
Integration: two NATted nodes through one relay — the exact reported topology.

B is a relay with an open port; A and C are "behind NATs" (no listeners — they
can only dial out). Both join B by invite code. Everything they exchange must
travel through B:

  1. routed liveness ping A↔C (console_ping_node, ECHO multi-hop),
  2. E2E data both ways (what the chat app rides on),
  3. a stale/late duplicate E2E handshake must NOT poison the session (the
     retry loop sends one every 5s while data is queued — on a slow relayed
     path that used to flip the responder to a key the initiator never held,
     silently killing delivery in both directions),
  4. a peer that loses its session (restart without persistence) re-keys
     cleanly through the candidate mechanism.

Real TCP on loopback. Excluded from the default suite (see pyproject addopts).
"""
import asyncio
import os
import random

import pytest

from src import MeshNode
from src.transport_manager import TransportManager
from src.tcp_transport import TCPTransport, TCPServer
import src.node as nodemod
from src.packet import Packet


def _mgr() -> TransportManager:
    m = TransportManager()
    m.register("tcp", TCPTransport, TCPServer)
    return m


async def _nat_trio(base: int):
    """Start relay B on 127.0.0.1:base; join NATted (listener-less) A and C."""
    b = MeshNode(_mgr())
    a = MeshNode(_mgr())
    c = MeshNode(_mgr())
    await b.start([f"tcp://127.0.0.1:{base}"])
    await a.start([])
    await c.start([])
    await a.join(f"tcp://127.0.0.1:{base}", b.generate_invite())
    await a.wait_for_session(timeout=15.0)
    await c.join(f"tcp://127.0.0.1:{base}", b.generate_invite())
    await c.wait_for_session(timeout=15.0)
    # hole punching disabled: relay routing is the only path
    for n in (a, b, c):
        n._punch_enabled = False
    return a, b, c


class TestNatRelayRouting:
    async def test_ping_and_data_both_ways_through_relay(self):
        base = random.randint(20000, 40000)
        a, b, c = await _nat_trio(base)
        try:
            assert not any(p.authenticated_id == c.id for p in a._peers)

            res = await asyncio.wait_for(a.console_ping_node(c.id.raw.hex()), 15.0)
            assert res["reachable"] is True and res["via"] == "route"
            assert res["rtt_ms"] is not None
            res = await asyncio.wait_for(c.console_ping_node(a.id.raw.hex()), 15.0)
            assert res["reachable"] is True and res["via"] == "route"

            await a.send_data(c.id, b"hello from A")
            got = await asyncio.wait_for(c.receive_data(), timeout=15.0)
            assert (got[0], got[1]) == (a.id, b"hello from A")
            await c.send_data(a.id, b"hello from C")
            got = await asyncio.wait_for(a.receive_data(), timeout=15.0)
            assert (got[0], got[1]) == (c.id, b"hello from C")
        finally:
            await a.stop()
            await c.stop()
            await b.stop()


class TestE2ESessionRobustness:
    async def test_stale_handshake_does_not_poison_session(self):
        """A duplicate handshake arriving after establishment must leave the
        live session key intact on the responder (candidate parked instead),
        so delivery keeps working in both directions."""
        base = random.randint(20000, 40000)
        a, b, c = await _nat_trio(base)
        try:
            await a.send_data(c.id, b"first")
            got = await asyncio.wait_for(c.receive_data(), timeout=15.0)
            assert got[1] == b"first"
            key_before_a = a._e2e_sessions[c.id].key_bytes
            key_before_c = c._e2e_sessions[a.id].key_bytes
            assert key_before_a == key_before_c

            # A duplicate of an earlier attempt, as the retry loop emits every
            # 5s while data is queued. A keeps NO pending state for it — its
            # session was completed by the first ACK.
            nonce = os.urandom(32)
            kem_pub, _ = a._identity.generate_kem_keypair()
            chain = a._cert_store.get_chain_to_root(a.id)
            sig = a._identity.sign(nonce + kem_pub + a._identity.dsa_public_key)
            payload = nodemod._encode_e2e_handshake(
                nonce, kem_pub, a._identity.dsa_public_key, chain, sig)
            await a._route_outbound(
                Packet.create(nodemod.E2E_HANDSHAKE, a.id.raw, c.id.raw, payload))
            await asyncio.sleep(1.0)   # let it travel A→B→C and the ACK return

            assert c._e2e_sessions[a.id].key_bytes == key_before_c   # not clobbered
            assert a._e2e_sessions[c.id].key_bytes == key_before_a
            assert a.id in c._e2e_rekey                              # candidate parked

            await a.send_data(c.id, b"second")
            got = await asyncio.wait_for(c.receive_data(), timeout=15.0)
            assert got[1] == b"second"
            await c.send_data(a.id, b"third")
            got = await asyncio.wait_for(a.receive_data(), timeout=15.0)
            assert got[1] == b"third"
        finally:
            await a.stop()
            await c.stop()
            await b.stop()

    async def test_session_loss_rekeys_and_heals(self):
        """A 'restarted' A (E2E state wiped) re-handshakes; C parks a candidate
        and A's first DATA under the new key promotes it — delivery resumes."""
        base = random.randint(20000, 40000)
        a, b, c = await _nat_trio(base)
        try:
            await a.send_data(c.id, b"first")
            got = await asyncio.wait_for(c.receive_data(), timeout=15.0)
            assert got[1] == b"first"
            old_key_c = c._e2e_sessions[a.id].key_bytes

            a._e2e_sessions.clear()
            a._e2e_pending_kem.clear()
            a._e2e_pending_nonce.clear()
            a._e2e_pending_data.clear()
            a._e2e_attempt.clear()

            await a.send_data(c.id, b"after restart")
            got = await asyncio.wait_for(c.receive_data(), timeout=15.0)
            assert got[1] == b"after restart"
            new_key_c = c._e2e_sessions[a.id].key_bytes
            assert new_key_c == a._e2e_sessions[c.id].key_bytes
            assert new_key_c != old_key_c
        finally:
            await a.stop()
            await c.stop()
            await b.stop()
