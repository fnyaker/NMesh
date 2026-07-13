"""
Network monitor tests.

The monitor drives when the node re-verifies its own addressing, so these
focus on the trigger logic: immediate first check, re-check on local IP
change and on poke, rate limiting of the expensive network probes (a hostile
peer flapping its connection must not turn us into a STUN/HTTP flooder), and
survival of failing probes and callbacks. All probes are injected — no test
touches the network.
"""
import asyncio
import json

import pytest

from src.net_monitor import NetMonitor
from src.node import MeshNode
from tests.conftest import make_manager


class _Probes:
    """Mutable probe results + call counters."""

    def __init__(self) -> None:
        self.local_ips = ["10.0.0.2"]
        self.public_ip = "203.0.113.7"
        self.stun = ("203.0.113.7", 40001)
        self.public_calls = 0
        self.stun_calls = 0

    def probe_local(self):
        return list(self.local_ips)

    async def probe_public(self):
        self.public_calls += 1
        return self.public_ip

    async def probe_stun(self):
        self.stun_calls += 1
        return self.stun


def _monitor(probes, on_change=None, **kw):
    kw.setdefault("check_interval", 0.02)
    kw.setdefault("full_interval", 60.0)
    kw.setdefault("min_full_gap", 0.0)
    return NetMonitor(probes.probe_local, probes.probe_public,
                      probes.probe_stun, on_change, **kw)


async def _settle(pred, timeout=2.0):
    async with asyncio.timeout(timeout):
        while not pred():
            await asyncio.sleep(0.01)


class TestChecks:
    async def test_first_check_runs_immediately(self):
        probes = _Probes()
        mon = _monitor(probes)
        mon.start()
        try:
            await _settle(lambda: mon.full_checks >= 1)
            st = mon.status()
            assert st["internet"] is True
            assert st["public_ip"] == "203.0.113.7"
            assert st["stun_addr"] == "203.0.113.7:40001"
            assert st["local_ips"] == ["10.0.0.2"]
            json.dumps(st)  # console-serialisable
        finally:
            await mon.stop()

    async def test_local_ip_change_triggers_recheck(self):
        probes = _Probes()
        changes_seen = []
        mon = _monitor(probes, on_change=lambda st, ch: changes_seen.append(ch))
        mon.start()
        try:
            await _settle(lambda: mon.full_checks >= 1)
            before = probes.public_calls
            probes.local_ips = ["192.168.1.5"]
            probes.public_ip = "198.51.100.9"
            await _settle(lambda: probes.public_calls > before)
            await _settle(lambda: mon.public_ip == "198.51.100.9")
            assert any(c.get("local_ips") == (["10.0.0.2"], ["192.168.1.5"])
                       for c in changes_seen)
            await _settle(lambda: any(
                c.get("public_ip") == ("203.0.113.7", "198.51.100.9")
                for c in changes_seen))
        finally:
            await mon.stop()

    async def test_poke_triggers_full_check(self):
        probes = _Probes()
        mon = _monitor(probes)
        mon.start()
        try:
            await _settle(lambda: mon.full_checks >= 1)
            before = probes.public_calls
            mon.poke("peer-lost")
            await _settle(lambda: probes.public_calls > before)
            assert any(r == "peer-lost" for _, r in mon.reasons)
        finally:
            await mon.stop()

    async def test_poke_is_rate_limited(self):
        probes = _Probes()
        mon = _monitor(probes, min_full_gap=3600.0)
        mon.start()
        try:
            await _settle(lambda: mon.full_checks >= 1)
            for _ in range(20):
                mon.poke("flap")
            await asyncio.sleep(0.2)  # several cheap check cycles
            assert mon.full_checks == 1  # network probes ran only once
            assert mon.checks > 1        # but cheap checks kept running
        finally:
            await mon.stop()

    async def test_reasons_are_bounded(self):
        probes = _Probes()
        mon = _monitor(probes)
        for i in range(1000):
            mon.poke(f"r{i}")
        assert len(mon.reasons) <= 8


class TestRobustness:
    async def test_failing_probes_never_kill_the_loop(self):
        probes = _Probes()

        async def boom():
            raise OSError("no network")

        mon = NetMonitor(probes.probe_local, boom, boom,
                         check_interval=0.02, min_full_gap=0.0)
        mon.start()
        try:
            await _settle(lambda: mon.full_checks >= 1)
            assert mon.internet is False
            assert mon.public_ip is None
            # Loop is still alive and checking
            n = mon.checks
            await _settle(lambda: mon.checks > n)
        finally:
            await mon.stop()

    async def test_probe_failure_keeps_last_known_address(self):
        probes = _Probes()
        mon = _monitor(probes)
        mon.start()
        try:
            await _settle(lambda: mon.full_checks >= 1)
            probes.public_ip = None
            probes.stun = None
            mon.poke("recheck")
            await _settle(lambda: mon.full_checks >= 2)
            assert mon.internet is False       # connectivity reported honestly
            assert mon.public_ip == "203.0.113.7"  # stale value kept, aged
        finally:
            await mon.stop()

    async def test_on_change_exception_is_swallowed(self):
        probes = _Probes()

        def bad_callback(st, ch):
            raise RuntimeError("ui bug")

        mon = _monitor(probes, on_change=bad_callback)
        mon.start()
        try:
            await _settle(lambda: mon.full_checks >= 1)
            probes.local_ips = ["172.16.0.9"]
            await _settle(lambda: mon.local_ips == ["172.16.0.9"])
        finally:
            await mon.stop()


class TestNodeIntegration:
    async def test_network_change_updates_advertised_addrs(self):
        node = MeshNode(transport_manager=make_manager())
        node._local_ips = ["10.0.0.2"]
        node._extra_addrs = ["203.0.113.7"]
        node._on_network_change(
            {"local_ips": ["192.168.1.5"]},
            {"local_ips": (["10.0.0.2"], ["192.168.1.5"]),
             "public_ip": ("203.0.113.7", "198.51.100.9")},
        )
        assert node._local_ips == ["192.168.1.5"]
        assert "203.0.113.7" not in node._extra_addrs  # stale public IP dropped
        assert "198.51.100.9" in node._extra_addrs

    async def test_snapshot_has_network_and_transport_details(self):
        node = MeshNode(transport_manager=make_manager())
        snap = await node.console_snapshot()
        assert "network" in snap and snap["network"] is None  # monitor not started
        assert isinstance(snap["transport_details"], list)
        schemes = {t["scheme"] for t in snap["transport_details"]}
        assert "fake" in schemes
        json.dumps(snap)

    async def test_snapshot_reports_hole_punch_state(self):
        from src.node import _PunchState
        from src.node_id import NodeID
        import time as _time

        node = MeshNode(transport_manager=make_manager())

        class _FakeUDPServer:
            _sock = None
        node._udp_server = _FakeUDPServer()
        node._udp_listen_uri = "udp://0.0.0.0:9999"
        target = NodeID(b"\x01" * 20)
        state = _PunchState(target, "198.51.100.9:40001", "203.0.113.7")
        state.deadline = _time.monotonic() + 5.0
        state.probes_sent = 3
        node._punch_pending[target] = state
        node._punch_stats["attempted"] = 1

        snap = await node.console_snapshot()
        udp = next(t for t in snap["transport_details"] if t["scheme"] == "udp")
        hp = udp["hole_punch"]
        assert hp["stats"]["attempted"] == 1
        assert hp["pending"][0]["target"] == target.raw.hex()
        assert hp["pending"][0]["probes_sent"] == 3
        assert 0 < hp["pending"][0]["expires_in"] <= 5.0
        json.dumps(snap)

    async def test_expired_punch_is_pruned_and_counted_failed(self):
        from src.node import _PunchState
        from src.node_id import NodeID
        import time as _time

        node = MeshNode(transport_manager=make_manager())
        target = NodeID(b"\x02" * 20)
        state = _PunchState(target, "198.51.100.9:40001", "203.0.113.7")
        state.deadline = _time.monotonic() - 1.0  # already expired
        node._punch_pending[target] = state

        node._prune_punch_pending()
        assert target not in node._punch_pending
        assert node._punch_stats["failed"] == 1
