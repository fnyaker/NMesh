"""
Relayed invitation — end-to-end (step 3).

The point of the whole feature: a node brings in a peer with NO direct link,
through a relay. Real TCP on loopback; A and B never connect to each other —
only both to R. The invite handshake tunnels A↔B through R, then E2E data
flows both ways over the relayed path.

Excluded from the default suite (see pyproject addopts); run explicitly:

    pytest tests/integration/test_relay_invite.py -q
"""
import asyncio

import pytest

from src import MeshNode
from src.transport_manager import TransportManager
from src.tcp_transport import TCPTransport, TCPServer
from tests.integration import free_port


def _mgr() -> TransportManager:
    m = TransportManager()
    m.register("tcp", TCPTransport, TCPServer)
    return m


def _authed_relayed(node, other):
    return any(p.authenticated_id == other and p.session is not None
               for p in node._peers)


class TestRelayedInvitation:
    async def test_join_via_relay_no_direct_link(self):
        base = free_port()
        R, A, B = MeshNode(_mgr()), MeshNode(_mgr()), MeshNode(_mgr())
        await R.start([f"tcp://127.0.0.1:{base}"])
        # A joins the network through R (A dials R → R becomes a usable relay)
        await A.join(f"tcp://127.0.0.1:{base}", R.generate_invite())
        await asyncio.wait_for(A.wait_for_session(10), 15)
        try:
            # A invites B with a single relay block; B ingests it and joins
            # A THROUGH R — A and B never share a direct link.
            block = A.console_relay_invite()
            assert f"tcp://127.0.0.1:{base}" in __import__("json").loads(
                __import__("base64").b64decode(block))["relays"]
            B.console_relay_join(block)

            async with asyncio.timeout(20):
                while B._join_status["running"]:
                    await asyncio.sleep(0.05)
            assert B._join_status["connected"] == f"tcp://127.0.0.1:{base}"
            assert _authed_relayed(B, A.id)   # B ↔ A authenticated (via relay)
            assert _authed_relayed(A, B.id)

            # E2E data flows both ways over the relayed path
            await B.send_data(A.id, b"hello A via relay")
            async with asyncio.timeout(15):
                while True:
                    src, data = await A.receive_data()
                    if data == b"hello A via relay" and src == B.id:
                        break
            await A.send_data(B.id, b"reply to B")
            async with asyncio.timeout(15):
                while True:
                    src, data = await B.receive_data()
                    if data == b"reply to B" and src == A.id:
                        break
        finally:
            await A.stop()
            await B.stop()
            await R.stop()

    async def test_join_falls_back_to_next_relay(self):
        base = free_port()
        R, A, B = MeshNode(_mgr()), MeshNode(_mgr()), MeshNode(_mgr())
        await R.start([f"tcp://127.0.0.1:{base}"])
        await A.join(f"tcp://127.0.0.1:{base}", R.generate_invite())
        await asyncio.wait_for(A.wait_for_session(10), 15)
        try:
            B._relay_join_timeout = 3.0
            # first relay is dead (nothing listening), second is R
            import base64, json
            block = A.console_relay_invite()
            data = json.loads(base64.b64decode(block))
            data["relays"] = [f"tcp://127.0.0.1:{base + 1}"] + data["relays"]
            block2 = base64.b64encode(json.dumps(data).encode()).decode()
            B.console_relay_join(block2)
            async with asyncio.timeout(30):
                while B._join_status["running"]:
                    await asyncio.sleep(0.05)
            assert B._join_status["connected"] == f"tcp://127.0.0.1:{base}"
            assert _authed_relayed(B, A.id)
        finally:
            await A.stop()
            await B.stop()
            await R.stop()


class TestTicketThroughARelay:
    """The same journey, out of a string short enough to put in a QR code.

    A relayed invitation is an ML-DSA key plus a signature — five kilobytes,
    which is far past what any QR code carries. So the heavy part is left *with
    the relay* as a rendezvous, and the ticket carries an identity, a seed and
    where to find that relay. What the joiner sends is 40 bytes.

    This is the whole reason an invitation no longer comes in two shapes: one
    string works whether or not the inviter has an address of its own, and there
    is no second exchange to decide between them.
    """

    async def test_a_ticket_reaches_a_node_with_no_address_of_its_own(self):
        base = free_port()
        R, A, B = MeshNode(_mgr()), MeshNode(_mgr()), MeshNode(_mgr())
        await R.start([f"tcp://127.0.0.1:{base}"])
        await A.join(f"tcp://127.0.0.1:{base}", R.generate_invite())
        await asyncio.wait_for(A.wait_for_session(10), 15)
        try:
            # A has nothing a stranger could dial: what the ticket carries is R.
            assert A.public_endpoints() == []
            ticket = await A.issue_join_ticket(600)
            assert ticket["uri"] == ""
            assert ticket["relay_uri"] == f"tcp://127.0.0.1:{base}"

            from src import join_ticket
            parsed = join_ticket.decode(ticket["ticket"])
            assert parsed["node"] == A.id.raw.hex()
            # And the rendezvous is on its way to R before the string is handed
            # over: what is left is one network trip, against a human reading a
            # QR code.
            from src.node import _h_code
            async with asyncio.timeout(10):
                while _h_code(parsed["code"]) not in R._offers:
                    await asyncio.sleep(0.02)

            outcome = await B.console_use_ticket(ticket["ticket"])
            assert outcome["ok"] is True and outcome["through"] == "relay"
            assert _authed_relayed(B, A.id)
            assert _authed_relayed(A, B.id)

            await B.send_data(A.id, b"hello A from a ticket")
            async with asyncio.timeout(15):
                while True:
                    src, data = await A.receive_data()
                    if data == b"hello A from a ticket" and src == B.id:
                        break
        finally:
            await A.stop()
            await B.stop()
            await R.stop()

    async def test_the_same_ticket_prefers_the_direct_route(self):
        """Direct first, because a relayed link is the thing a direct one exists
        to stand in for — and trying it costs one connection."""
        base = free_port()
        R, A, B = MeshNode(_mgr()), MeshNode(_mgr()), MeshNode(_mgr())
        await R.start([f"tcp://127.0.0.1:{base}"])
        await A.start([f"tcp://127.0.0.1:{base + 1}"])
        await A.join(f"tcp://127.0.0.1:{base}", R.generate_invite())
        await asyncio.wait_for(A.wait_for_session(10), 15)
        try:
            # A loopback listener is nobody's public address, and confirming one
            # needs a connection from off this machine's networks. So the
            # reachability A would have on a real host is stated here — what is
            # under test is the *order* the two routes are tried in.
            real = A.reachability
            A.reachability = lambda: list(real()) + [
                {"transport": "tcp", "scope": "world", "anchor": "",
                 "address": f"tcp://127.0.0.1:{base + 1}", "confirmed": True}]
            ticket = await A.issue_join_ticket(600)
            from src import join_ticket
            parsed = join_ticket.decode(ticket["ticket"])
            # Both routes are in it: the relay is what the direct one falls back
            # to if that address turns out not to answer.
            assert parsed["uri"] == f"tcp://127.0.0.1:{base + 1}"
            assert parsed["relay_uri"] == f"tcp://127.0.0.1:{base}"
            outcome = await B.console_use_ticket(ticket["ticket"])
            assert outcome["ok"] is True and outcome["through"] == "direct"
        finally:
            await A.stop()
            await B.stop()
            await R.stop()
