"""
When a Kademlia lookup stops.

It used to stop as soon as the closest id it knew of stopped changing — which is
what happens on any round whose candidates were all offline, and in a sparse
table with churn that is most rounds. Simulated at 50 000 nodes with two ids per
bucket and a third of them offline, four rounds of that found the target one
time in three; Kademlia's own rule (the closest node that *answered* stopped
improving, and nothing left to ask is closer) with ten rounds found it 96 times
in a hundred (`Docs/Architecture/scale.md`, point 1).

Here the real `kad_lookup` runs against a synthetic mesh: a few thousand ids,
each knowing two per bucket, a third of them silent. Only the answers are
synthetic — the loop, its termination and its bookkeeping are the node's.
"""
import asyncio
import bisect
import random

from src.mesh.constants import _KAD_LOOKUP_MAX_ROUNDS
from src.node import MeshNode
from src.node_id import NodeID
from src.routing import NodeEntry, RoutingTable
from tests.conftest import make_manager

BITS = 160
N, PER_BUCKET, DOWN, ENTRIES = 3000, 2, 0.3, 3


def _mesh(seed: int):
    rng = random.Random(seed)
    ids = sorted({rng.getrandbits(BITS) for _ in range(N)})
    tables = {}
    for me in ids:
        known = []
        for bit in range(BITS):
            low = ((me >> (bit + 1)) << (bit + 1)) | (((~me >> bit) & 1) << bit)
            high = low | ((1 << bit) - 1)
            i, j = bisect.bisect_left(ids, low), bisect.bisect_right(ids, high)
            if j > i:
                known += ids[i:j] if j - i <= PER_BUCKET else rng.sample(ids[i:j], PER_BUCKET)
        tables[me] = known
    down = set(rng.sample(ids, int(N * DOWN)))
    return ids, tables, down, rng


def _as_id(value: int) -> NodeID:
    return NodeID(value.to_bytes(20, "big"))


def _success_rate(seed: int, lookups: int) -> float:
    ids, tables, down, rng = _mesh(seed)
    alive = [x for x in ids if x not in down]
    node = MeshNode(transport_manager=make_manager())

    async def answer(node_id, target, timeout=5.0):
        me = int.from_bytes(node_id.raw, "big")
        if me in down:
            return None
        goal = int.from_bytes(target.raw, "big")
        best = sorted(tables[me] + [me], key=lambda x: x ^ goal)[:ENTRIES]
        return [NodeEntry(_as_id(x), []) for x in best]

    node._kad_query_node = answer
    found = 0
    for _ in range(lookups):
        source, target = rng.sample(alive, 2)
        node._id = _as_id(source)
        node._routing = RoutingTable(node._id)
        for known in tables[source]:
            node._routing.add(_as_id(known), [])
        result = asyncio.run(node.kad_lookup(_as_id(target), k=20, alpha=3,
                                             max_rounds=_KAD_LOOKUP_MAX_ROUNDS))
        found += _as_id(target) in result
    return found / lookups


def test_a_lookup_finds_its_target_through_offline_nodes():
    assert _success_rate(seed=7, lookups=60) >= 0.9
