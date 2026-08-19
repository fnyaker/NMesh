"""Maintien du voisinage : plancher de 3 liens, promotion d'une node vue en
transit, keepalive prioritaire.

Un nœud cherche activement tant qu'il tient moins de `_NEIGHBOR_FLOOR` liens ;
au-dessus il se tait. S'il voit passer du trafic d'une node XOR-plus-proche que
son plus mauvais créneau, il la découvre et la maintient à sa place. Voir
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
    """Une identité qui partage `prefix_bits_shared` bits de tête avec `node`.

    Plus le préfixe est long, plus la distance XOR est courte : c'est le seul
    critère de maintien de table (cf. routing.md).
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
    # Le bit suivant diffère : la distance est bornée par ce préfixe exactement.
    byte, offset = divmod(prefix_bits_shared, 8)
    mask = 1 << (7 - offset)
    raw[byte] = (raw[byte] & (0xFF ^ mask)) | (mask if not own[byte] & mask else 0)
    return NodeID(bytes(raw))


async def _attach_peer(node: MeshNode, node_id: NodeID) -> object:
    """Un pair authentifié factice (lien vivant, sans crypto réelle)."""
    fake = FakeTransport()
    peer = await node._inject_peer(fake)
    if peer is None:
        peer = node._peers[-1]
    peer.authenticated_id = node_id
    peer.session = object()
    return peer


# ── régimes de découverte ────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_searches_while_below_the_floor(monkeypatch):
    """Moins de 3 liens : on cherche (lookup + dial) à chaque cycle."""
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
    assert attempted, "un nœud sous le plancher doit continuer à chercher"
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
    """Le bootstrap force un cycle complet quoi qu'on tienne déjà."""
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
    assert attempted, "force=True doit relancer une recherche complète"
    await node.stop()


@pytest.mark.asyncio
async def test_losing_a_slot_resumes_the_search(monkeypatch):
    """Perdre un des 3 liens remet le nœud en recherche."""
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


# ── promotion d'une node vue en transit ──────────────────────────────────────

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
    """Le critère est la distance XOR : plus loin que notre pire créneau = non."""
    node = await _node()
    for _ in range(_NEIGHBOR_FLOOR):
        await _attach_peer(node, _id_at_distance(node, 32))

    farther = _id_at_distance(node, 4)
    node._note_neighbor_candidate(farther)
    assert node._neighbor_watch == {}
    await node.stop()


@pytest.mark.asyncio
async def test_relayed_packet_feeds_the_watch_list():
    """Le hook réel : un paquet routé traversant le nœud désigne son émetteur."""
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
    """Au-dessus du plancher on reste silencieux… sauf pour une meilleure node."""
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
    """Une fois le lien établi, la promue entre dans le set, la pire en sort."""
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
    """Aucune entrée périmée, aucune croissance sans fin (pair qui relaie tout)."""
    node = await _node()
    for _ in range(_NEIGHBOR_FLOOR):
        await _attach_peer(node, _id_at_distance(node, 4))

    for _ in range(_NEIGHBOR_WATCH_TRACKED * 3):
        node._note_neighbor_candidate(_id_at_distance(node, 40))
    assert len(node._neighbor_watch) <= _NEIGHBOR_WATCH_TRACKED

    # Une candidate devenue pair vivant sort de la liste d'attente.
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
    """Un src_id n'est pas authentifié : il ne doit pas piloter notre cadence."""
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
    """Les 3 liens tenus passent avant les autres : jamais affamés par un lent."""
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
    """Sous le plancher après un cycle de keepalive : la recherche est relancée."""
    node = await _node()
    await _attach_peer(node, _id_at_distance(node, 8))

    node._neighbor_wakeup.clear()
    await _run_keepalive_once(node, monkeypatch, 1)
    assert node._neighbor_wakeup.is_set()
    await node.stop()
