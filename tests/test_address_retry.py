"""
Redialler une adresse : à la main, ou toute seule.

Une node qui annonce quatre adresses dont une seule marche est le cas normal sur
un vrai réseau. Trois mécanismes en découlent, et ce fichier les tient :

* **le bouton** — rejouer une adresse précise, ou toutes, et *dire* ce que
  chacune a fait ;
* **la boucle** — réessayer périodiquement, à la cadence que le *medium* déclare
  (`retry_interval`), jamais à une cadence que le cœur impose ;
* **le pilotage par latence** — déplacer un lien vivant vers une meilleure
  adresse de la même node, uniquement si on l'a demandé.

Le fil rouge : rien de tout ça ne doit pouvoir devenir une inondation, et une
entrée hostile (id inconnu, URI qui n'est pas à cette node) ne compose rien.
"""
import asyncio
import time

import pytest

from src.node import NodeID, _RETRY_MAX_PER_PASS
from src.tcp_transport import TCPTransport
from src.transport import BaseTransport
from src.udp_transport import UDPTransport
from tests.conftest import FakeTransport, make_manager


def _node():
    from src.node import MeshNode
    return MeshNode(transport_manager=make_manager())


def _peer_id(seed: int) -> NodeID:
    return NodeID(bytes([seed]) * 20)


class TestTheMediumOwnsTheCadence:
    """Le cœur n'a pas d'avis sur la fréquence : une radio qui coûte une pile
    par tentative et un Ethernet ne partagent pas un nombre."""

    def test_tcp_and_udp_both_declare_it_and_it_is_off_by_default(self):
        for cls in (TCPTransport, UDPTransport):
            field = next(f for f in cls.OPTIONS if f["name"] == "retry_interval")
            assert field["default"] == 0.0, cls
            assert field["min"] == 0.0 and field["max"] == 3600.0

    def test_a_transport_that_declares_nothing_is_never_retried(self):
        """`fake://` n'a pas d'option : la boucle doit le laisser tranquille,
        pas supposer une valeur."""
        node = _node()
        assert node._retry_interval("fake://somewhere") == 0.0

    def test_the_value_in_force_is_the_one_the_medium_was_given(self):
        node = _node()
        node._transport_manager.register("tcp", TCPTransport, _server_of(TCPTransport))
        try:
            TCPTransport.configure({"retry_interval": 30.0})
            assert node._retry_interval("tcp://10.0.0.1:9000") == 30.0
        finally:
            TCPTransport.SETTINGS = {}

    def test_a_broken_uri_is_not_a_retry(self):
        node = _node()
        for rubbish in ("", "://", "no-scheme", "tcp:/x", "\x00tcp://a"):
            assert node._retry_interval(rubbish) == 0.0


def _server_of(cls):
    from src.tcp_transport import TCPServer
    from src.udp_transport import UDPServer
    return TCPServer if cls is TCPTransport else UDPServer


class TestTheManualRetry:
    """Le bouton. Il rend compte, et il ne compose que ce que la node connaît
    déjà de cette identité."""

    @pytest.mark.asyncio
    async def test_an_unknown_id_is_refused_without_dialling(self):
        node = _node()
        for bad in ("", "zz", "00" * 19, "nonsense"):
            result = await node.console_retry_addresses(bad)
            assert result["ok"] is False

    @pytest.mark.asyncio
    async def test_our_own_id_is_refused(self):
        node = _node()
        result = await node.console_retry_addresses(node._id.raw.hex())
        assert result == {"ok": False, "error": "self"}

    @pytest.mark.asyncio
    async def test_a_node_with_no_known_address_says_so(self):
        node = _node()
        result = await node.console_retry_addresses(_peer_id(7).raw.hex())
        assert result["ok"] is False and "no known address" in result["error"]

    @pytest.mark.asyncio
    async def test_an_address_that_is_not_that_nodes_is_refused(self):
        """La console est authentifiée, mais « tape une adresse et la node s'y
        connecte » est une autre fonctionnalité, avec un autre modèle de
        menace. Ici on ne compose que ce qu'on sait déjà d'elle."""
        node = _node()
        target = _peer_id(8)
        node._routing.add(target, ["fake://known:1"])
        dialled = []

        async def _spy(node_id, uri, timeout):
            dialled.append(uri)
            return None
        node._dial_uri = _spy
        result = await node.console_retry_addresses(target.raw.hex(),
                                                    "fake://evil.example:1")
        assert result["ok"] is False
        assert dialled == []

    @pytest.mark.asyncio
    async def test_every_address_is_reported_with_what_it_did(self):
        node = _node()
        target = _peer_id(9)
        node._routing.add(target, ["fake://a:1", "fake://b:2"])

        async def _fail(node_id, uri, timeout):
            node._note_dial(node_id.raw.hex(), uri, "refused", "ConnectionRefusedError")
            return None
        node._dial_uri = _fail
        result = await node.console_retry_addresses(target.raw.hex())
        assert result["ok"] is True and result["connected"] is False
        assert [row["uri"] for row in result["results"]] == ["fake://a:1", "fake://b:2"]
        assert all(row["outcome"] == "refused" for row in result["results"])
        assert all(row["detail"] == "ConnectionRefusedError" for row in result["results"])

    @pytest.mark.asyncio
    async def test_it_stops_at_the_first_address_that_works(self):
        """Rejouer « toutes » les adresses veut dire « rends-moi un lien », pas
        « ouvre-en quatre »."""
        node = _node()
        target = _peer_id(10)
        node._routing.add(target, ["fake://a:1", "fake://b:2", "fake://c:3"])
        tried = []

        async def _first_wins(node_id, uri, timeout):
            tried.append(uri)
            node._note_dial(node_id.raw.hex(), uri, "connected")
            return object()
        node._dial_uri = _first_wins
        result = await node.console_retry_addresses(target.raw.hex())
        assert len(tried) == 1
        assert result["connected"] is True

    @pytest.mark.asyncio
    async def test_one_named_address_dials_only_that_one(self):
        node = _node()
        target = _peer_id(11)
        node._routing.add(target, ["fake://a:1", "fake://b:2"])
        tried = []

        async def _spy(node_id, uri, timeout):
            tried.append(uri)
            return None
        node._dial_uri = _spy
        await node.console_retry_addresses(target.raw.hex(), "fake://b:2")
        assert tried == ["fake://b:2"]


class TestThePeriodicRetry:
    """La boucle. Ce qui est fixe ici, c'est qu'elle ne peut pas inonder."""

    @pytest.mark.asyncio
    async def test_nothing_is_dialled_while_every_medium_says_zero(self):
        node = _node()
        node._routing.add(_peer_id(1), ["fake://a:1"])
        node._dial_uri = _never_called
        assert await node._retry_pass() == 0

    @pytest.mark.asyncio
    async def test_a_pass_is_capped_however_many_nodes_are_waiting(self):
        node = _node()
        for seed in range(2, 40):
            node._routing.add(_peer_id(seed), [f"fake://host{seed}:1"])
        node._retry_interval = lambda uri: 10.0
        dialled = []

        async def _spy(node_id, uri, timeout):
            dialled.append(uri)
            return None
        node._dial_uri = _spy
        assert await node._retry_pass() == _RETRY_MAX_PER_PASS
        assert len(dialled) == _RETRY_MAX_PER_PASS

    @pytest.mark.asyncio
    async def test_an_address_tried_recently_is_left_alone(self):
        node = _node()
        target = _peer_id(3)
        node._routing.add(target, ["fake://a:1"])
        node._retry_interval = lambda uri: 300.0
        node._note_dial(target.raw.hex(), "fake://a:1", "timeout")
        node._dial_uri = _never_called
        assert await node._retry_pass() == 0

    @pytest.mark.asyncio
    async def test_it_is_dialled_again_once_the_interval_has_passed(self):
        node = _node()
        target = _peer_id(4)
        node._routing.add(target, ["fake://a:1"])
        node._retry_interval = lambda uri: 1.0
        node._note_dial(target.raw.hex(), "fake://a:1", "timeout")
        node._dial_log[target.raw.hex()]["fake://a:1"]["at"] = time.monotonic() - 5
        dialled = []

        async def _spy(node_id, uri, timeout):
            dialled.append(uri)
            return None
        node._dial_uri = _spy
        assert await node._retry_pass() == 1
        assert dialled == ["fake://a:1"]

    @pytest.mark.asyncio
    async def test_a_node_already_linked_is_never_dialled(self):
        node = _node()
        target = _peer_id(5)
        node._routing.add(target, ["fake://a:1"])
        node._retry_interval = lambda uri: 1.0
        fake = FakeTransport()
        peer = await node._inject_peer(fake)
        peer.authenticated_id = target
        peer.session = object()
        node._dial_uri = _never_called
        assert await node._retry_pass() == 0

    @pytest.mark.asyncio
    async def test_the_loop_survives_a_dial_that_explodes(self, monkeypatch):
        """Zéro crash : une boucle de récupération qui meurt est une perte
        silencieuse de récupération. On la fait vraiment tourner, plusieurs
        fois, avec un medium qui lève à chaque appel."""
        monkeypatch.setattr("src.node._RETRY_TICK", 0.01)
        node = _node()
        node._routing.add(_peer_id(6), ["fake://a:1"])
        node._retry_interval = lambda uri: 0.0001
        calls = []

        async def _boom(node_id, uri, timeout):
            calls.append(uri)
            raise RuntimeError("the medium exploded")
        node._dial_uri = _boom
        node._running = True
        task = asyncio.create_task(node._address_retry_loop())
        try:
            for _ in range(200):
                await asyncio.sleep(0.01)
                if len(calls) >= 3:
                    break
            assert len(calls) >= 3, calls
            assert not task.done()
        finally:
            node._running = False
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass


async def _never_called(*args, **kwargs):
    raise AssertionError("nothing should have been dialled")


class TestSteeringOnLatency:
    """Déplacer un lien vivant vers une meilleure adresse — seulement si on l'a
    demandé, et seulement si le gain est réel."""

    def test_it_is_off_until_someone_asks(self):
        node = _node()
        assert node.dynamic_address is False
        node.set_dynamic_address(True)
        assert node.dynamic_address is True
        node.set_dynamic_address(False)
        assert node.dynamic_address is False

    @pytest.mark.asyncio
    async def test_a_link_never_measured_is_not_judged(self):
        node = _node()
        target = _peer_id(20)
        node._routing.add(target, ["fake://a:1", "fake://b:2"])
        peer = await node._inject_peer(FakeTransport())
        peer.authenticated_id = target
        peer.session = object()
        peer.remote_addr = "fake://a:1"
        peer.last_rtt = None
        assert node._steer_candidate() == (None, "")

    @pytest.mark.asyncio
    async def test_the_address_in_use_is_never_its_own_candidate(self):
        node = _node()
        target = _peer_id(21)
        node._routing.add(target, ["fake://a:1", "fake://b:2"])
        peer = await node._inject_peer(FakeTransport())
        peer.authenticated_id = target
        peer.session = object()
        peer.remote_addr = "fake://a:1"
        peer.last_rtt = 0.05
        _found, uri = node._steer_candidate()
        assert uri == "fake://b:2"

    @pytest.mark.asyncio
    async def test_a_candidate_just_measured_is_not_measured_again(self):
        node = _node()
        target = _peer_id(22)
        node._routing.add(target, ["fake://a:1", "fake://b:2"])
        peer = await node._inject_peer(FakeTransport())
        peer.authenticated_id = target
        peer.session = object()
        peer.remote_addr = "fake://a:1"
        peer.last_rtt = 0.05
        node._note_steer(target.raw.hex(), "fake://b:2")
        assert node._steer_candidate() == (None, "")

    @pytest.mark.asyncio
    async def test_a_candidate_that_will_not_connect_changes_nothing(self):
        node = _node()
        target = _peer_id(23)
        node._routing.add(target, ["fake://a:1", "fake://b:2"])
        peer = await node._inject_peer(FakeTransport())
        peer.authenticated_id = target
        peer.session = object()
        peer.remote_addr = "fake://a:1"
        peer.last_rtt = 0.05
        node._measure_peer = _measure(50.0)
        node._dial_uri = _no_dial
        assert await node._steer_pass() == "candidate did not connect"
        assert peer in node._peers

    @pytest.mark.asyncio
    async def test_a_marginal_gain_is_not_a_reason_to_move(self):
        """Deux millisecondes de mieux, c'est du bruit — pas une raison de
        payer une poignée de main."""
        node, peer, target = await _steerable(24)
        candidate = await _candidate(node, target)
        node._measure_peer = _measure_by_peer({id(peer): 50.0, id(candidate): 48.5})
        node._dial_uri = _dial_returning(node, candidate)
        assert await node._steer_pass() == "kept the current address"
        assert peer in node._peers and candidate not in node._peers

    @pytest.mark.asyncio
    async def test_a_real_gain_moves_the_link_and_closes_the_old_one(self):
        node, peer, target = await _steerable(25)
        candidate = await _candidate(node, target)
        node._measure_peer = _measure_by_peer({id(peer): 90.0, id(candidate): 12.0})
        node._dial_uri = _dial_returning(node, candidate)
        assert await node._steer_pass() == "moved to fake://b:2"
        assert candidate in node._peers and peer not in node._peers

    @pytest.mark.asyncio
    async def test_two_links_to_one_node_never_outlive_the_measurement(self):
        for winner in (True, False):
            node, peer, target = await _steerable(26 + winner)
            candidate = await _candidate(node, target)
            node._measure_peer = _measure_by_peer(
                {id(peer): 90.0, id(candidate): 5.0 if winner else 95.0})
            node._dial_uri = _dial_returning(node, candidate)
            await node._steer_pass()
            live = [p for p in node._peers if p.authenticated_id == target]
            assert len(live) == 1, winner

    @pytest.mark.asyncio
    async def test_the_table_of_measured_candidates_is_bounded(self):
        node = _node()
        for seed in range(400):
            node._note_steer(_peer_id(seed % 250).raw.hex(), f"fake://a{seed}:1")
        assert len(node._steer_seen) <= 128
        for seen in node._steer_seen.values():
            assert len(seen) <= 8


async def _steerable(seed):
    node = _node()
    target = _peer_id(seed)
    node._routing.add(target, ["fake://a:1", "fake://b:2"])
    peer = await node._inject_peer(FakeTransport())
    peer.authenticated_id = target
    peer.session = object()
    peer.remote_addr = "fake://a:1"
    peer.last_rtt = 0.09
    return node, peer, target


async def _candidate(node, target):
    peer = await node._inject_peer(FakeTransport())
    peer.authenticated_id = target
    peer.session = object()
    peer.remote_addr = "fake://b:2"
    node._peers.remove(peer)          # le dial le remettra
    return peer


def _measure(value):
    async def _run(peer):
        return value
    return _run


def _measure_by_peer(table):
    async def _run(peer):
        return table[id(peer)]
    return _run


def _dial_returning(node, peer):
    """Ce qu'un vrai `_dial_uri` fait : le pair réussi est dans la liste."""
    async def _run(node_id, uri, timeout):
        peer.remote_addr = uri
        if peer not in node._peers:
            node._peers.append(peer)
        return peer
    return _run


async def _no_dial(node_id, uri, timeout):
    return None


class TestPriorityAndBalance:
    """Choisir entre les adresses d'une node : ce que vaut le *medium* (une
    priorité que l'opérateur pose) et ce que mesure l'*adresse*, pesés par un
    seul curseur. Une seule règle, un seul endroit."""

    def test_the_shipped_priorities_are_the_ones_advertised(self):
        assert TCPTransport.setting("priority") == 0
        assert UDPTransport.setting("priority") == 10
        from src.spool_transport import SpoolTransport
        assert SpoolTransport.setting("priority") == -50

    def test_a_priority_is_bounded_both_ways(self):
        field = next(f for f in TCPTransport.OPTIONS if f["name"] == "priority")
        assert (field["min"], field["max"]) == (-254, 254)
        result = TCPTransport.configure({"priority": 900})
        assert "priority" in result["rejected"]
        assert TCPTransport.setting("priority") == 0

    def test_an_unknown_scheme_scores_last_rather_than_crashing(self):
        node = _node()
        assert node._transport_priority("nope://x:1") == 0
        assert node._transport_priority("not a uri") == -254

    def test_the_balance_is_refused_outside_zero_to_a_hundred(self):
        node = _node()
        for bad in (-1, 101, "half", None, 3.7e9):
            with pytest.raises(ValueError):
                node.set_transport_balance(bad)
        assert node.transport_balance == 50

    def test_at_zero_only_latency_counts(self):
        """Le curseur à gauche : la priorité du medium ne doit plus rien
        changer, même entre deux transports très différents."""
        node = _node()
        node.set_transport_balance(0)
        node._transport_priority = lambda uri: 254 if "fast" in uri else -254
        assert node._address_score("fast://a:1", 100.0) < node._address_score("slow://b:1", 5.0)

    def test_at_a_hundred_only_priority_counts(self):
        node = _node()
        node.set_transport_balance(100)
        node._transport_priority = lambda uri: 254 if "good" in uri else -254
        assert node._address_score("good://a:1", 900.0) > node._address_score("bad://b:1", 1.0)

    def test_an_address_never_measured_sits_in_the_middle(self):
        """« Jamais essayée » n'est ni une bonne ni une mauvaise nouvelle."""
        node = _node()
        node.set_transport_balance(0)
        never = node._address_score("fake://a:1", None)
        assert node._address_score("fake://a:1", 1.0) > never
        assert node._address_score("fake://a:1", 500.0) < never

    def test_latency_curves_so_one_absurd_number_flattens_nothing(self):
        """Une échelle linéaire ferait qu'une mesure à 4 s écrase toutes les
        différences réelles entre 5 et 50 ms."""
        node = _node()
        node.set_transport_balance(0)
        near = node._address_score("fake://a:1", 5.0) - node._address_score("fake://a:1", 50.0)
        far = node._address_score("fake://a:1", 4000.0) - node._address_score("fake://a:1", 4050.0)
        assert near > far * 50

    @pytest.mark.asyncio
    async def test_the_dial_order_follows_the_balance(self):
        node = _node()
        target = _peer_id(40)
        addresses = ["slow://a:1", "fast://b:2"]
        node._transport_priority = lambda uri: 200 if uri.startswith("slow") else 0
        node._note_dial(target.raw.hex(), "slow://a:1", "connected", elapsed=0.400)
        node._note_dial(target.raw.hex(), "fast://b:2", "connected", elapsed=0.004)
        node.set_transport_balance(0)
        assert node._preferred(addresses, target.raw.hex())[0] == "fast://b:2"
        node.set_transport_balance(100)
        assert node._preferred(addresses, target.raw.hex())[0] == "slow://a:1"

    def test_global_ipv6_still_breaks_a_tie(self):
        """Le départage historique n'est pas perdu : à score égal, une adresse
        IPv6 globale reste joignable de bout en bout."""
        node = _node()
        ordered = node._preferred(["fake://10.0.0.1:1", "fake://[2a01::1]:1"])
        assert ordered[0] == "fake://[2a01::1]:1"

    def test_the_scheme_order_shown_to_the_operator_is_the_real_one(self):
        """La console affiche l'ordre calculé ici, pas une deuxième
        implémentation de la règle en JavaScript."""
        from src.tcp_transport import TCPServer, TCPTransport as T
        from src.udp_transport import UDPServer, UDPTransport as U
        from src.node import MeshNode
        from src.transport_manager import TransportManager
        manager = TransportManager()
        manager.register("tcp", T, TCPServer)
        manager.register("udp", U, UDPServer)
        node = MeshNode(transport_manager=manager)
        order = [entry["scheme"] for entry in node.transport_preference()]
        assert order == ["udp", "tcp"]          # 10 contre 0
        try:
            T.configure({"priority": 200})
            assert [e["scheme"] for e in node.transport_preference()] == ["tcp", "udp"]
        finally:
            T.SETTINGS = {}

    @pytest.mark.asyncio
    async def test_steering_prefers_a_better_medium_at_equal_latency(self):
        """Le point du système : à latence égale, le medium préféré gagne — et
        c'est la même règle qui a ordonné les dials."""
        node, peer, target = await _steerable(41)
        node.set_transport_balance(100)
        node._transport_priority = lambda uri: 254 if uri.endswith("b:2") else -254
        candidate = await _candidate(node, target)
        node._measure_peer = _measure_by_peer({id(peer): 40.0, id(candidate): 40.0})
        node._dial_uri = _dial_returning(node, candidate)
        assert await node._steer_pass() == "moved to fake://b:2"

    @pytest.mark.asyncio
    async def test_steering_will_not_move_to_a_worse_medium_that_is_barely_faster(self):
        node, peer, target = await _steerable(42)
        node.set_transport_balance(100)
        node._transport_priority = lambda uri: -254 if uri.endswith("b:2") else 254
        candidate = await _candidate(node, target)
        node._measure_peer = _measure_by_peer({id(peer): 40.0, id(candidate): 38.0})
        node._dial_uri = _dial_returning(node, candidate)
        assert await node._steer_pass() == "kept the current address"

    @pytest.mark.asyncio
    async def test_a_manager_that_cannot_answer_never_stops_a_dial(self):
        """Zéro crash : un gestionnaire de transports tiers qui n'implémente pas
        `setting()` doit scorer neutre, pas emporter la composition."""
        class Mute:
            def is_supported(self, scheme):
                return True

            def schemes(self):
                raise RuntimeError("no idea")
        node = _node()
        node._transport_manager = Mute()
        assert node._transport_priority("fake://a:1") == 0
        assert node._preferred(["fake://a:1", "fake://b:2"])
        assert node.transport_preference() == []
