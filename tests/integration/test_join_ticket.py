"""Rejoindre un réseau avec un ticket compact, et rien d'autre.

Le ticket porte l'adresse *et* le code : si le join marche en ne passant que
cette chaîne, la fonctionnalité tient. Le reste vérifie qu'il ne marche pas
quand il ne devrait pas — expiré, déjà utilisé, mal tapé.

Exclu de la suite par défaut (voir pyproject addopts).
"""
import asyncio
import time

import pytest

from src import MeshNode, join_ticket
from src.transport_manager import TransportManager
from src.tcp_transport import TCPTransport, TCPServer


def make_node() -> MeshNode:
    mgr = TransportManager()
    mgr.register("tcp", TCPTransport, TCPServer)
    return MeshNode(mgr)


async def _ticket_for(host, port: int, ttl: float = 600.0) -> str:
    """Émet un ticket vers 127.0.0.1 sans exiger une IP publique.

    Le test valide le *transport* du ticket ; la porte « adresse publique
    confirmée » est vérifiée séparément, sans quoi il faudrait une vraie IP
    routable pour tester quoi que ce soit."""
    code, seed = host._invite.generate_seeded_code(ttl)
    return join_ticket.encode("127.0.0.1", port, seed, time.time() + ttl)


class TestJoinByTicket:
    async def test_a_ticket_is_all_it_takes(self):
        host, guest = make_node(), make_node()
        await host.start(["tcp://127.0.0.1:19371"])
        try:
            ticket = await _ticket_for(host, 19371)
            parsed = join_ticket.decode(ticket)
            await guest.join(parsed["uri"], parsed["code"])
            await guest.wait_for_session(timeout=15.0)
            await host.wait_for_session(timeout=15.0)
            assert guest.id in [p.authenticated_id for p in host._peers]
        finally:
            await guest.stop()
            await host.stop()

    async def test_the_same_ticket_cannot_be_used_twice(self):
        """Le code à l'intérieur reste à usage unique : un ticket photographié
        par deux personnes n'en fait pas entrer deux."""
        host, first, second = make_node(), make_node(), make_node()
        await host.start(["tcp://127.0.0.1:19372"])
        try:
            parsed = join_ticket.decode(await _ticket_for(host, 19372))
            await first.join(parsed["uri"], parsed["code"])
            await first.wait_for_session(timeout=15.0)

            await second.join(parsed["uri"], parsed["code"])
            with pytest.raises(Exception):
                await second.wait_for_session(timeout=5.0)
        finally:
            await second.stop()
            await first.stop()
            await host.stop()

    async def test_an_expired_ticket_does_not_get_in(self):
        host, guest = make_node(), make_node()
        await host.start(["tcp://127.0.0.1:19373"])
        try:
            parsed = join_ticket.decode(await _ticket_for(host, 19373, ttl=1.0))
            await asyncio.sleep(1.5)
            await guest.join(parsed["uri"], parsed["code"])
            with pytest.raises(Exception):
                await guest.wait_for_session(timeout=5.0)
        finally:
            await guest.stop()
            await host.stop()

    async def test_a_ticket_for_the_wrong_code_does_not_get_in(self):
        """Un ticket bien formé dont le code n'a jamais été émis ici."""
        host, guest = make_node(), make_node()
        await host.start(["tcp://127.0.0.1:19374"])
        try:
            forged = join_ticket.encode("127.0.0.1", 19374, b"\x09" * 8,
                                        time.time() + 600)
            parsed = join_ticket.decode(forged)
            await guest.join(parsed["uri"], parsed["code"])
            with pytest.raises(Exception):
                await guest.wait_for_session(timeout=5.0)
        finally:
            await guest.stop()
            await host.stop()


class TestPublicGate:
    async def test_a_node_with_no_public_address_refuses_to_issue_one(self):
        """Un ticket qui pointe vers une adresse que personne ne peut joindre
        est pire que pas de ticket : il échoue après avoir été partagé."""
        node = make_node()
        await node.start(["tcp://127.0.0.1:19375"])
        try:
            assert node.public_endpoints() == []
            with pytest.raises(ValueError):
                node.issue_join_ticket(600)
        finally:
            await node.stop()

    async def test_it_issues_one_when_an_address_is_confirmed_public(self, monkeypatch):
        node = make_node()
        await node.start(["tcp://127.0.0.1:19376"])
        try:
            monkeypatch.setattr(node, "reachability", lambda: [
                {"transport": "tcp", "scope": "world", "anchor": "",
                 "address": "tcp://203.0.113.7:9000", "confirmed": True},
            ])
            ticket = node.issue_join_ticket(600)
            parsed = join_ticket.decode(ticket["ticket"])
            assert parsed["uri"] == "tcp://203.0.113.7:9000"
            assert parsed["code"] == ticket["code"]
        finally:
            await node.stop()

    async def test_an_unconfirmed_public_address_is_not_enough(self):
        """« On pense que cette adresse est publique » n'est pas « une
        connexion entrante est arrivée dessus »."""
        node = make_node()
        await node.start(["tcp://127.0.0.1:19377"])
        try:
            node.reachability = lambda: [
                {"transport": "tcp", "scope": "world", "anchor": "",
                 "address": "tcp://203.0.113.7:9000", "confirmed": False},
            ]
            assert node.public_endpoints() == []
            with pytest.raises(ValueError):
                node.issue_join_ticket(600)
        finally:
            await node.stop()
