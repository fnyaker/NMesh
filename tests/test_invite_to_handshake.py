"""
Integration tests for the full INVITE → INVITE_ACK → HANDSHAKE → HANDSHAKE_ACK flow.

These tests deliberately avoid using _setup_challenge_pair() so that the real
challenge/invite machinery is exercised end-to-end.
"""
import asyncio
import pytest
from src.node import (
    MeshNode,
    CHALLENGE, INVITE, INVITE_ACK, HANDSHAKE, HANDSHAKE_ACK,
    _ACK_ACCEPTED,
    _decode_handshake,
)
from src.node_id import NodeID
from src.packet import Packet
from tests.conftest import FakeTransport, make_node


@pytest.mark.asyncio
async def test_full_invite_to_handshake():
    """Complete INVITE→HANDSHAKE flow without bypassing pending_challenge."""
    node_a, fake_a = await make_node()   # joiner (client side)
    node_b, fake_b = await make_node()   # host   (server side)

    # node_b generates an invite; node_a will use that code
    code = node_b.generate_invite()
    node_a._peers[0].join_code = code
    node_a._peers[0].is_client_side = True

    # Simulate node_b sending CHALLENGE (as _on_new_transport does)
    challenge = node_b._invite.generate_challenge()
    node_b._peers[0].pending_challenge = challenge
    node_b._peers[0].invite_accepted = False
    chal_pkt = Packet.create(CHALLENGE, node_b.id.raw, NodeID(b"\xff" * 20).raw, challenge)
    fake_a.inject(chal_pkt)
    await asyncio.sleep(0.1)

    # node_a must have sent INVITE
    invite_pkt = next((p for p in fake_a.sent if p.type == INVITE), None)
    assert invite_pkt is not None, "Joiner did not send INVITE"
    fake_b.inject(invite_pkt)
    await asyncio.sleep(0.1)

    # node_b must have sent INVITE_ACK(accepted)
    ack_pkt = next((p for p in fake_b.sent if p.type == INVITE_ACK), None)
    assert ack_pkt is not None, "Host did not send INVITE_ACK"
    assert ack_pkt.payload[0] == _ACK_ACCEPTED, "INVITE was rejected"
    fake_a.inject(ack_pkt)
    await asyncio.sleep(0.1)

    # node_a must have sent HANDSHAKE (triggered by INVITE_ACK → initiate_handshake)
    hs_pkt = next((p for p in fake_a.sent if p.type == HANDSHAKE), None)
    assert hs_pkt is not None, "Joiner did not send HANDSHAKE after INVITE_ACK"
    fake_b.inject(hs_pkt)
    await asyncio.sleep(0.1)

    # node_b must have sent HANDSHAKE_ACK  ← this was the broken step before the fix
    hs_ack = next((p for p in fake_b.sent if p.type == HANDSHAKE_ACK), None)
    assert hs_ack is not None, (
        "Host did not send HANDSHAKE_ACK — Bug #1: pending_challenge was cleared "
        "prematurely in _handle_invite before _handle_handshake could verify it"
    )
    fake_a.inject(hs_ack)
    await asyncio.sleep(0.1)

    # Both sessions must be established
    assert node_a._peers[0].session is not None, "Joiner session not established"
    assert node_b._peers[0].session is not None, "Host session not established"
    assert node_a._peers[0].authenticated_id == node_b.id
    assert node_b._peers[0].authenticated_id == node_a.id

    await node_a.stop()
    await node_b.stop()


@pytest.mark.asyncio
async def test_handshake_signature_verified_with_original_challenge():
    """
    HANDSHAKE signature covers the challenge bytes. Verifying that the challenge
    is still available in peer.pending_challenge when _handle_handshake runs.
    If the fix is reverted, the verify() call in _handle_handshake will receive
    a None challenge and the HANDSHAKE packet will be silently dropped.
    """
    node_a, fake_a = await make_node()
    node_b, fake_b = await make_node()

    code = node_b.generate_invite()
    node_a._peers[0].join_code = code
    node_a._peers[0].is_client_side = True

    challenge = node_b._invite.generate_challenge()
    node_b._peers[0].pending_challenge = challenge

    chal_pkt = Packet.create(CHALLENGE, node_b.id.raw, NodeID(b"\xff" * 20).raw, challenge)
    fake_a.inject(chal_pkt)
    await asyncio.sleep(0.1)

    invite_pkt = next(p for p in fake_a.sent if p.type == INVITE)
    fake_b.inject(invite_pkt)
    await asyncio.sleep(0.1)

    ack_pkt = next(p for p in fake_b.sent if p.type == INVITE_ACK)
    fake_a.inject(ack_pkt)
    await asyncio.sleep(0.1)

    # After INVITE_ACK, pending_challenge must still be set on node_b's peer
    assert node_b._peers[0].pending_challenge is not None, (
        "pending_challenge cleared too early — _handle_handshake will reject HANDSHAKE"
    )

    hs_pkt = next(p for p in fake_a.sent if p.type == HANDSHAKE)

    # The HANDSHAKE signature must verify against the original challenge
    kem_pub, dsa_pub, chain, signature = _decode_handshake(hs_pkt.payload)
    ok = node_b._identity.verify(challenge + kem_pub + dsa_pub, signature, dsa_pub)
    assert ok, "HANDSHAKE signature does not verify against challenge"

    await node_a.stop()
    await node_b.stop()


@pytest.mark.asyncio
async def test_invite_rejected_on_bad_code():
    """Host sends INVITE_ACK(rejected) when the invite code is wrong."""
    node_a, fake_a = await make_node()
    node_b, fake_b = await make_node()

    node_b.generate_invite()                      # generate, but give a wrong code
    node_a._peers[0].join_code = "wrong-code-000"
    node_a._peers[0].is_client_side = True

    challenge = node_b._invite.generate_challenge()
    node_b._peers[0].pending_challenge = challenge

    chal_pkt = Packet.create(CHALLENGE, node_b.id.raw, NodeID(b"\xff" * 20).raw, challenge)
    fake_a.inject(chal_pkt)
    await asyncio.sleep(0.1)

    invite_pkt = next((p for p in fake_a.sent if p.type == INVITE), None)
    assert invite_pkt is not None
    fake_b.inject(invite_pkt)
    await asyncio.sleep(0.1)

    ack_pkt = next((p for p in fake_b.sent if p.type == INVITE_ACK), None)
    assert ack_pkt is not None
    assert ack_pkt.payload[0] != _ACK_ACCEPTED, "Bad code should be rejected"

    # No session established
    assert node_b._peers[0].session is None
    assert node_b._peers[0].authenticated_id is None

    await node_a.stop()
    await node_b.stop()


# ---------------------------------------------------------------------------
# A root is adopted because we presented a code — never because the answer
# carried a certificate. Whoever we dial writes that field, and it knows our
# public key (we just sent it), so it can always forge one.
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_dialled_peer_cannot_plant_a_trust_root():
    """A node we dial with no code may not become one of our roots.

    The joiner path is the only thing that adopts a root, and it is entered on
    our own record of having presented a code (`peer.joined_by_invite`). A peer
    that simply answers with an `issued_cert` gets nothing: without this, every
    address learned from gossip is a trust anchor waiting to be planted."""
    from src.crypto import CryptoIdentity
    from src.node import _encode_handshake_ack

    victim, fake = await make_node()          # dialled out; holds no code
    peer = victim._peers[0]
    assert peer.join_code is None
    assert peer.joined_by_invite is False

    attacker = CryptoIdentity()
    attacker_id = NodeID.from_public_key(attacker.dsa_public_key)
    attacker_root = attacker.self_signed_cert()

    # It challenges, as any accepting server does.
    challenge = attacker.sign(b"nonce")[:32]
    fake.inject(Packet.create(CHALLENGE, attacker_id.raw, victim.id.raw, challenge))
    await asyncio.sleep(0.05)

    handshake = next(p for p in fake.sent if p.type == HANDSHAKE)
    kem_pub, victim_pub, _chain, _sig = _decode_handshake(handshake.payload)

    # …then answers with a certificate it minted for us, and its own root.
    forged = attacker.issue_cert(NodeID.from_public_key(victim_pub), victim_pub)
    ciphertext, _shared = attacker.kem_encapsulate(kem_pub)
    signature = attacker.sign(challenge + ciphertext + attacker.dsa_public_key)
    payload = _encode_handshake_ack(ciphertext, attacker.dsa_public_key,
                                    [attacker_root], forged, signature)
    fake.inject(Packet.create(HANDSHAKE_ACK, attacker_id.raw, victim.id.raw,
                              payload))
    await asyncio.sleep(0.05)

    assert not victim._cert_store.is_root(attacker_id), (
        "a peer we merely dialled installed itself as a trust root"
    )
    # And nothing it mints from that root authenticates either.
    stranger = CryptoIdentity()
    minted = attacker.issue_cert(NodeID.from_public_key(stranger.dsa_public_key),
                                 stranger.dsa_public_key)
    assert victim._cert_store.verify_chain([minted, attacker_root]) is None
    # The link itself is refused too: an unanchored chain is not a membership.
    assert peer.authenticated_id is None

    await victim.stop()


@pytest.mark.asyncio
async def test_joining_by_invite_still_adopts_the_host_root():
    """The bound this protects must not close the door it exists to open."""
    node_a, fake_a = await make_node()   # joiner
    node_b, fake_b = await make_node()   # host

    code = node_b.generate_invite()
    node_a._peers[0].join_code = code
    node_a._peers[0].is_client_side = True

    challenge = node_b._invite.generate_challenge()
    node_b._peers[0].pending_challenge = challenge
    fake_a.inject(Packet.create(CHALLENGE, node_b.id.raw,
                                NodeID(b"\xff" * 20).raw, challenge))
    await asyncio.sleep(0.05)
    fake_b.inject(next(p for p in fake_a.sent if p.type == INVITE))
    await asyncio.sleep(0.05)
    fake_a.inject(next(p for p in fake_b.sent if p.type == INVITE_ACK))
    await asyncio.sleep(0.05)

    assert node_a._peers[0].joined_by_invite is True

    fake_b.inject(next(p for p in fake_a.sent if p.type == HANDSHAKE))
    await asyncio.sleep(0.05)
    fake_a.inject(next(p for p in fake_b.sent if p.type == HANDSHAKE_ACK))
    await asyncio.sleep(0.05)

    assert node_a._cert_store.is_root(node_b.id), (
        "a node that joined by invitation must trust the host's root"
    )
    assert node_a._peers[0].authenticated_id == node_b.id

    await node_a.stop()
    await node_b.stop()
