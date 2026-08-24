"""Deux nœuds joints et inactifs ne doivent presque rien s'échanger.

Le bug d'origine : `_maintain_neighbors` envoyait un FIND_NODE, la réponse
FOUND_NODE réveillait la maintenance, qui repartait sans le moindre délai.
Comme un FOUND_NODE transporte des chaînes de certificats (~15 ko), deux nœuds
au repos saturaient le lien — 3 Mbit/s mesurés en local, un débit constant sur
un lien réel. Un mesh plus petit que `_NEIGHBOR_FLOOR` ne peut jamais atteindre
ce plancher, donc la recherche ne s'arrêtait jamais d'elle-même.

Exclu de la suite par défaut (voir pyproject addopts) : ce test observe du
temps réel.
"""
import asyncio

import pytest

from src import MeshNode
from src.node import MESSAGE_NAMES
from src.transport_manager import TransportManager
from src.tcp_transport import TCPTransport, TCPServer


def make_node() -> MeshNode:
    mgr = TransportManager()
    mgr.register("tcp", TCPTransport, TCPServer)
    return MeshNode(mgr)


async def _joined_pair(addr: str):
    host, guest = make_node(), make_node()
    code = host.generate_invite()
    await host.start([f"tcp://{addr}"])
    await guest.join(f"tcp://{addr}", code)
    await guest.wait_for_session(timeout=15.0)
    await host.wait_for_session(timeout=15.0)
    await guest.bootstrap()
    await host.bootstrap()
    return host, guest


class TestIdleChatter:
    async def test_two_idle_nodes_stay_quiet(self):
        host, guest = await _joined_pair("127.0.0.1:19341")
        try:
            await asyncio.sleep(2)          # laisser le join se poser
            host.trace.start(seconds=40, events=20000, names=MESSAGE_NAMES)
            await asyncio.sleep(20)
            host.trace.stop()
            summary = host.trace.summary()

            # Le seuil est large exprès : ce test attrape une boucle emballée,
            # pas une variation de quelques paquets. Avant le correctif, cette
            # fenêtre portait des mégaoctets.
            assert summary["bytes_in"] + summary["bytes_out"] < 200_000, summary

            found = [row for row in summary["rows"]
                     if row["type"] == "FOUND_NODE"]
            packets = sum(row["packets"] for row in found)
            assert packets <= 4, f"FOUND_NODE en boucle : {summary['rows']}"
        finally:
            await guest.stop()
            await host.stop()

    async def test_a_reply_that_teaches_nothing_does_not_relaunch_the_search(self):
        """Le cœur du bug : une réponse ne doit pas être la cause de la question
        suivante. Notre propre id compte comme « déjà connu » — la table refuse
        de le stocker, donc `contains` est faux pour lui à jamais et chaque
        réponse qui nous mentionne passait pour une découverte.

        Mesuré sur une fenêtre qui couvre au moins un cycle de maintenance,
        sinon le test passerait aussi sur le code bogué."""
        host, guest = await _joined_pair("127.0.0.1:19342")
        try:
            await asyncio.sleep(2)
            wakes = []
            original = host._wake_neighbor_maintenance

            def spy():
                wakes.append(1)
                return original()

            host._wake_neighbor_maintenance = spy
            await asyncio.sleep(25)
            assert len(wakes) <= 3, f"maintenance réveillée {len(wakes)} fois"
        finally:
            await guest.stop()
            await host.stop()

    async def test_discovery_still_works_when_there_is_something_to_find(self):
        """La borne ne doit pas éteindre la découverte : un troisième nœud qui
        arrive doit être trouvé par le premier, qui ne l'a jamais dialé."""
        host, guest = await _joined_pair("127.0.0.1:19343")
        third = make_node()
        try:
            code = host.generate_invite()
            await third.join("tcp://127.0.0.1:19343", code)
            await third.wait_for_session(timeout=15.0)
            await third.bootstrap()
            deadline = asyncio.get_event_loop().time() + 30
            while asyncio.get_event_loop().time() < deadline:
                if guest._routing.contains(third.id):
                    break
                await asyncio.sleep(0.5)
            assert guest._routing.contains(third.id), \
                "le troisième nœud n'a jamais été appris"
        finally:
            await third.stop()
            await guest.stop()
            await host.stop()
