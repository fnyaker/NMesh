"""Neighbourhood maintenance: a floor of 3 links, promoting a node seen in
transit, a prioritised keepalive.

A node searches actively while it holds fewer than `_NEIGHBOR_FLOOR` links;
above that it goes quiet. If it sees traffic from a node XOR-closer than its
worst slot, it discovers it and maintains it in that slot's place. See
`Docs/Architecture/routing.md`.
"""
import asyncio
import os

import pytest

import src.node

from src.node import (
    MeshNode, _NEIGHBOR_FLOOR, _NEIGHBOR_TARGET, _NEIGHBOR_WATCH_TRACKED,
    PING,
)
from src.node_id import NodeID
from src.packet import Packet
from tests.conftest import FakeTransport, make_manager


async def _node() -> MeshNode:
    return MeshNode(transport_manager=make_manager())


def _id_at_distance(node: MeshNode, prefix_bits_shared: int) -> NodeID:
    """An identity sharing `prefix_bits_shared` leading bits with `node`.

    The longer the prefix, the shorter the XOR distance: that is the only
    criterion for keeping a slot (see routing.md).
    """
    raw = bytearray(os.urandom(20))
    own = node.id.raw
    for bit in range(prefix_bits_shared):
        byte, offset = divmod(bit, 8)
        mask = 1 << (7 - offset)
        if own[byte] & mask:
            raw[byte] |= mask
        else:
            raw[byte] &= 0xFF ^ mask
    # The next bit differs: the distance is bounded by exactly this prefix.
    byte, offset = divmod(prefix_bits_shared, 8)
    mask = 1 << (7 - offset)
    raw[byte] = (raw[byte] & (0xFF ^ mask)) | (mask if not own[byte] & mask else 0)
    return NodeID(bytes(raw))


async def _attach_peer(node: MeshNode, node_id: NodeID) -> object:
    """A fake authenticated peer (a live link, with no real crypto)."""
    fake = FakeTransport()
    peer = await node._inject_peer(fake)
    if peer is None:
        peer = node._peers[-1]
    peer.authenticated_id = node_id
    peer.session = object()
    return peer


# ── discovery regimes ───────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_searches_while_below_the_floor(monkeypatch):
    """Fewer than 3 links: we search (lookup + dial) on every cycle."""
    node = await _node()
    for index in range(_NEIGHBOR_FLOOR - 1):
        await _attach_peer(node, _id_at_distance(node, 8))
    for index in range(4):
        node._routing.add(_id_at_distance(node, 4), [f"fake://n{index}"], b"k")

    attempted = []

    async def fake_ensure(node_id, timeout=5.0):
        attempted.append(node_id)
        return None

    monkeypatch.setattr(node, "_ensure_route_to", fake_ensure)
    await node._maintain_neighbors()
    assert attempted, "a node below the floor must keep searching"
    await node.stop()


@pytest.mark.asyncio
async def test_quiet_once_the_floor_is_reached(monkeypatch):
    """Trois liens tenus : plus de lookup, plus de dial — le mesh est rejoint."""
    node = await _node()
    for _ in range(_NEIGHBOR_FLOOR):
        await _attach_peer(node, _id_at_distance(node, 8))
    for index in range(4):
        node._routing.add(_id_at_distance(node, 4), [f"fake://n{index}"], b"k")

    attempted = []
    looked_up = []

    async def fake_ensure(node_id, timeout=5.0):
        attempted.append(node_id)
        return None

    async def fake_lookup(*args, **kwargs):
        looked_up.append(args)
        return []

    monkeypatch.setattr(node, "_ensure_route_to", fake_ensure)
    monkeypatch.setattr(node, "kad_lookup", fake_lookup)
    await node._maintain_neighbors()
    assert attempted == []
    assert looked_up == []
    await node.stop()


@pytest.mark.asyncio
async def test_force_searches_even_when_satisfied(monkeypatch):
    """The bootstrap forces a full cycle whatever we already hold."""
    node = await _node()
    for _ in range(_NEIGHBOR_FLOOR):
        await _attach_peer(node, _id_at_distance(node, 8))
    node._routing.add(_id_at_distance(node, 4), ["fake://n"], b"k")

    attempted = []

    async def fake_ensure(node_id, timeout=5.0):
        attempted.append(node_id)
        return None

    monkeypatch.setattr(node, "_ensure_route_to", fake_ensure)
    monkeypatch.setattr(node, "kad_lookup", lambda *a, **k: asyncio.sleep(0))
    await node._maintain_neighbors(force=True)
    assert attempted, "force=True must restart a full search"
    await node.stop()


@pytest.mark.asyncio
async def test_losing_a_slot_resumes_the_search(monkeypatch):
    """Losing one of the 3 links puts the node back into searching."""
    node = await _node()
    peers = [await _attach_peer(node, _id_at_distance(node, 8))
             for _ in range(_NEIGHBOR_FLOOR)]
    node._routing.add(_id_at_distance(node, 4), ["fake://n"], b"k")

    attempted = []

    async def fake_ensure(node_id, timeout=5.0):
        attempted.append(node_id)
        return None

    monkeypatch.setattr(node, "_ensure_route_to", fake_ensure)
    monkeypatch.setattr(node, "kad_lookup", lambda *a, **k: asyncio.sleep(0))

    await node._maintain_neighbors()
    assert attempted == []

    peers[0].session = None          # un lien tombe
    await node._maintain_neighbors()
    assert attempted, "sous le plancher, la recherche doit repartir"
    await node.stop()


# ── promoting a node seen in transit ────────────────────────────────────────

@pytest.mark.asyncio
async def test_closer_node_seen_in_transit_is_watched():
    node = await _node()
    for _ in range(_NEIGHBOR_FLOOR):
        await _attach_peer(node, _id_at_distance(node, 4))

    closer = _id_at_distance(node, 32)
    node._note_neighbor_candidate(closer)
    assert closer in node._neighbor_watch
    assert node._neighbor_promotions() == [closer]
    await node.stop()


@pytest.mark.asyncio
async def test_farther_node_seen_in_transit_is_ignored():
    """The criterion is XOR distance: farther than our worst slot = no."""
    node = await _node()
    for _ in range(_NEIGHBOR_FLOOR):
        await _attach_peer(node, _id_at_distance(node, 32))

    farther = _id_at_distance(node, 4)
    node._note_neighbor_candidate(farther)
    assert node._neighbor_watch == {}
    await node.stop()


@pytest.mark.asyncio
async def test_relayed_packet_feeds_the_watch_list():
    """The real hook: a routed packet crossing the node names its sender."""
    node = await _node()
    relay_id = _id_at_distance(node, 4)
    relay = await _attach_peer(node, relay_id)
    for _ in range(_NEIGHBOR_FLOOR - 1):
        await _attach_peer(node, _id_at_distance(node, 4))

    origin = _id_at_distance(node, 40)
    packet = Packet.create(PING, origin.raw, node.id.raw, b"")
    node._learn_reverse_path(relay, packet)

    assert origin in node._neighbor_watch
    await node.stop()


@pytest.mark.asyncio
async def test_promotion_is_dialled_even_when_satisfied(monkeypatch):
    """Above the floor we stay quiet… except for a better node."""
    node = await _node()
    for _ in range(_NEIGHBOR_FLOOR):
        await _attach_peer(node, _id_at_distance(node, 4))

    closer = _id_at_distance(node, 40)
    node._note_neighbor_candidate(closer)

    attempted = []

    async def fake_ensure(node_id, timeout=5.0):
        attempted.append(node_id)
        return None

    monkeypatch.setattr(node, "_ensure_route_to", fake_ensure)
    monkeypatch.setattr(node, "kad_lookup", lambda *a, **k: asyncio.sleep(0))
    await node._maintain_neighbors()
    assert attempted == [closer]
    await node.stop()


@pytest.mark.asyncio
async def test_promoted_node_takes_the_worst_slot():
    """Once the link is up, the promoted node enters the set and the worst one
    leaves."""
    node = await _node()
    worst = _id_at_distance(node, 4)
    await _attach_peer(node, worst)
    for _ in range(_NEIGHBOR_FLOOR - 1):
        await _attach_peer(node, _id_at_distance(node, 20))

    assert worst in node._neighbor_slots()

    promoted = _id_at_distance(node, 40)
    node._note_neighbor_candidate(promoted)
    await _attach_peer(node, promoted)     # le dial aboutit

    slots = node._neighbor_slots()
    assert promoted in slots
    assert worst not in slots
    assert len(slots) == _NEIGHBOR_FLOOR
    await node.stop()


@pytest.mark.asyncio
async def test_watch_list_is_cleaned_and_bounded():
    """No stale entry, no endless growth (a peer that relays everything)."""
    node = await _node()
    for _ in range(_NEIGHBOR_FLOOR):
        await _attach_peer(node, _id_at_distance(node, 4))

    for _ in range(_NEIGHBOR_WATCH_TRACKED * 3):
        node._note_neighbor_candidate(_id_at_distance(node, 40))
    assert len(node._neighbor_watch) <= _NEIGHBOR_WATCH_TRACKED

    # A candidate that became a live peer leaves the waiting list.
    watched = next(iter(node._neighbor_watch))
    await _attach_peer(node, watched)
    assert watched not in node._neighbor_promotions()
    assert watched not in node._neighbor_watch
    await node.stop()


@pytest.mark.asyncio
async def test_promotions_are_capped():
    node = await _node()
    for _ in range(_NEIGHBOR_FLOOR):
        await _attach_peer(node, _id_at_distance(node, 4))
    for _ in range(_NEIGHBOR_WATCH_TRACKED):
        node._note_neighbor_candidate(_id_at_distance(node, 40))
    assert len(node._neighbor_promotions()) <= _NEIGHBOR_TARGET
    await node.stop()


@pytest.mark.asyncio
async def test_own_id_and_live_peers_are_never_watched():
    node = await _node()
    live = _id_at_distance(node, 40)
    await _attach_peer(node, live)

    node._note_neighbor_candidate(node.id)
    node._note_neighbor_candidate(live)
    assert node._neighbor_watch == {}
    await node.stop()


@pytest.mark.asyncio
async def test_watching_never_wakes_the_loop():
    """A src_id is not authenticated: it must not drive our cadence."""
    node = await _node()
    node._running = True
    node._neighbor_wakeup.clear()
    for _ in range(_NEIGHBOR_FLOOR):
        await _attach_peer(node, _id_at_distance(node, 4))

    node._note_neighbor_candidate(_id_at_distance(node, 40))
    assert not node._neighbor_wakeup.is_set()
    node._running = False
    await node.stop()


# ── keepalive ────────────────────────────────────────────────────────────────

async def _run_keepalive_once(node, monkeypatch, expected: int) -> list:
    """Laisse tourner un cycle de keepalive et renvoie l'ordre des PING."""
    pinged = []

    async def fake_ping(peer):
        pinged.append(peer.authenticated_id)

    monkeypatch.setattr(node, "ping", fake_ping)
    monkeypatch.setattr(src.node, "_LINK_KEEPALIVE_INTERVAL", 0)

    node._running = True
    task = asyncio.create_task(node._link_keepalive_loop())
    for _ in range(200):
        if len(pinged) >= expected:
            break
        await asyncio.sleep(0)
    node._running = False
    task.cancel()
    try:
        await task
    except (asyncio.CancelledError, Exception):
        pass
    return pinged


@pytest.mark.asyncio
async def test_keepalive_pings_the_maintained_slots_first(monkeypatch):
    """The 3 maintained links come before the others: never starved by a slow
    one."""
    node = await _node()
    far = [await _attach_peer(node, _id_at_distance(node, 2)) for _ in range(3)]
    near = [await _attach_peer(node, _id_at_distance(node, 40))
            for _ in range(_NEIGHBOR_FLOOR)]

    slots = set(node._neighbor_slots())
    assert slots == {p.authenticated_id for p in near}

    pinged = await _run_keepalive_once(node, monkeypatch, len(far) + len(near))

    assert set(pinged[:len(slots)]) == slots
    assert all(p.authenticated_id in pinged for p in far), "les autres suivent"
    await node.stop()


@pytest.mark.asyncio
async def test_keepalive_pings_every_peer_when_below_the_floor(monkeypatch):
    node = await _node()
    peers = [await _attach_peer(node, _id_at_distance(node, 8)) for _ in range(2)]

    pinged = await _run_keepalive_once(node, monkeypatch, len(peers))

    assert {p.authenticated_id for p in peers} <= set(pinged)
    await node.stop()


@pytest.mark.asyncio
async def test_keepalive_rearms_the_search_when_short(monkeypatch):
    """Below the floor after a keepalive cycle: the search is restarted."""
    node = await _node()
    await _attach_peer(node, _id_at_distance(node, 8))

    node._neighbor_wakeup.clear()
    await _run_keepalive_once(node, monkeypatch, 1)
    assert node._neighbor_wakeup.is_set()
    await node.stop()


@pytest.mark.asyncio
async def test_keepalive_pings_concurrently_not_sequentially(monkeypatch):
    """One slow link must not delay the pings to the others.

    Sequentially, a single slow peer would hold up every ping behind it; a
    gather runs them together so the healthy links are refreshed on time."""
    node = await _node()
    peers = [await _attach_peer(node, _id_at_distance(node, 8)) for _ in range(3)]
    slow = peers[0]

    pinged = []

    async def fake_ping(peer):
        if peer is slow:
            await asyncio.sleep(0.5)
        pinged.append(peer.authenticated_id)

    monkeypatch.setattr(node, "ping", fake_ping)
    monkeypatch.setattr(src.node, "_LINK_KEEPALIVE_INTERVAL", 0)

    node._running = True
    task = asyncio.create_task(node._link_keepalive_loop())
    for _ in range(200):
        if len(pinged) >= len(peers) - 1:
            break
        await asyncio.sleep(0)
    assert len(pinged) >= len(peers) - 1, "fast peers pinged while slow one sleeps"
    node._running = False
    task.cancel()
    try:
        await task
    except (asyncio.CancelledError, Exception):
        pass
    await node.stop()
