"""IP addressing helpers."""
import ipaddress

import pytest

from src import ip_utils
from src.ip_utils import local_networks

from src.ip_utils import (
    split_host_port, is_wildcard, local_ip_addresses, expand_listen_uri,
)


class TestSplitHostPort:
    @pytest.mark.parametrize("s,expected", [
        ("1.2.3.4:9000", ("1.2.3.4", "9000")),
        ("host.example:80", ("host.example", "80")),
        ("[::1]:9000", ("::1", "9000")),
        ("[2001:db8::5]:443", ("2001:db8::5", "443")),
        ("[::]:80", ("::", "80")),
    ])
    def test_valid(self, s, expected):
        assert split_host_port(s) == expected

    @pytest.mark.parametrize("s", ["nohost", "::1", "2001:db8::1", "[::1]", "[::1]80", ""])
    def test_invalid(self, s):
        assert split_host_port(s) is None


class TestWildcard:
    def test_wildcards(self):
        assert is_wildcard("0.0.0.0") and is_wildcard("::") and is_wildcard("")
        assert not is_wildcard("127.0.0.1") and not is_wildcard("1.2.3.4")


class TestLocalIPs:
    def test_returns_list(self):
        ips = local_ip_addresses()
        assert isinstance(ips, list)
        assert all(isinstance(a, str) for a in ips)
        # loopback excluded by default, included on request
        assert all(not a.startswith("127.") for a in ips)
        with_lo = local_ip_addresses(include_loopback=True)
        assert isinstance(with_lo, list)

    def _host(self, monkeypatch, outbound, others):
        """A machine whose default routes leave from ``outbound`` and whose
        hostname resolves to ``others`` — no real socket opened."""
        import socket as socket_module
        routes = iter(outbound)

        class Probe:
            def __init__(self, *_a): self._addr = None
            def connect(self, _probe):
                self._addr = next(routes, None)
                if self._addr is None:
                    raise OSError("no route")
            def getsockname(self): return (self._addr, 0)
            def close(self): pass

        monkeypatch.setattr(socket_module, "socket", Probe)
        monkeypatch.setattr(socket_module, "getaddrinfo",
                            lambda *_a: [(0, 0, 0, "", (ip, 0)) for ip in others])

    def test_the_address_the_default_route_uses_comes_first(self, monkeypatch):
        """Sorted alone, a 192.168 LAN came after every 172.x Docker bridge:
        peers dialled the bridges first, and a list capped at eight lost it."""
        bridges = [f"172.{n}.0.1" for n in range(17, 30)]
        self._host(monkeypatch, ["192.168.1.20"], bridges + ["192.168.1.20"])
        ips = local_ip_addresses()
        assert ips[0] == "192.168.1.20"
        assert ips[1:] == sorted(bridges)

    def test_each_address_once_and_no_scope_id(self, monkeypatch):
        self._host(monkeypatch, ["10.0.0.5", "fd00::5"],
                   ["10.0.0.5", "fe80::1%eth0", "fd00::5", "127.0.0.1"])
        assert local_ip_addresses() == ["10.0.0.5", "fd00::5", "fe80::1"]

    def test_with_no_route_it_is_the_sorted_list(self, monkeypatch):
        self._host(monkeypatch, [], ["10.0.0.9", "10.0.0.2"])
        assert local_ip_addresses() == ["10.0.0.2", "10.0.0.9"]


class TestExpand:
    def test_wildcard_v4_expands(self):
        out = expand_listen_uri("tcp://0.0.0.0:9000", ["1.2.3.4", "10.0.0.1"])
        assert out == ["tcp://1.2.3.4:9000", "tcp://10.0.0.1:9000"]

    def test_extra_appended(self):
        out = expand_listen_uri("tcp://0.0.0.0:9000", ["1.2.3.4"], ["203.0.113.5"])
        assert out == ["tcp://1.2.3.4:9000", "tcp://203.0.113.5:9000"]

    def test_ipv6_bracketed(self):
        out = expand_listen_uri("tcp://[::]:9000", ["fd00::1"])
        assert out == ["tcp://[fd00::1]:9000"]

    def test_link_local_is_not_advertised(self):
        """Meaningless without this machine's zone id: a dialler can only fail."""
        out = expand_listen_uri("tcp://[::]:9000",
                                ["fe80::1", "fe80::2%eth0", "169.254.3.4", "fd00::1"])
        assert out == ["tcp://[fd00::1]:9000"]

    def test_a_concrete_link_local_listen_uri_is_the_operators_word(self):
        assert expand_listen_uri("tcp://[fe80::1]:9000", ["1.2.3.4"]) \
            == ["tcp://[fe80::1]:9000"]

    def test_concrete_unchanged(self):
        assert expand_listen_uri("tcp://192.168.1.5:9000", ["1.2.3.4"]) \
            == ["tcp://192.168.1.5:9000"]

    def test_invalid_uri(self):
        assert expand_listen_uri("not-a-uri", ["1.2.3.4"]) == []

    def test_dedup(self):
        out = expand_listen_uri("tcp://0.0.0.0:9000", ["1.2.3.4", "1.2.3.4"])
        assert out == ["tcp://1.2.3.4:9000"]


# ---------------------------------------------------------------------------
# Attached-network enumeration
# ---------------------------------------------------------------------------

class TestLocalNetworks:
    """A LAN sweep needs the real prefix. Guessing /24 around an address misses
    a /22 or /16 entirely, so these check that the real mask comes through and
    that nothing dangerous does."""

    def test_returns_private_ipv4_networks(self):
        for entry in local_networks():
            net = ipaddress.ip_network(entry["cidr"])
            assert net.version == 4
            assert net.is_private
            assert not net.is_loopback and not net.is_link_local
            assert net.prefixlen <= 30

    def test_never_raises(self):
        assert isinstance(local_networks(), list)

    def test_proc_route_decoding(self, tmp_path, monkeypatch):
        """Fields are little-endian hex; a default route and a via-gateway route
        are not attached networks and must not be reported."""
        route = tmp_path / "route"
        route.write_text(
            "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\n"
            "eth0\t00000000\t0102A8C0\t0003\t0\t0\t0\t00000000\t0\n"   # default
            "eth0\t0000A8C0\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\n"   # /16
            "eth1\t000A0A0A\t0102A8C0\t0003\t0\t0\t0\t00FFFFFF\t0\n"   # via gw
            "wg0\t0000010A\t00000000\t0001\t0\t0\t0\t00F0FFFF\t0\n")   # /20
        monkeypatch.setattr(ip_utils, "_PROC_ROUTE", str(route))
        monkeypatch.setattr(ip_utils, "_iface_address", lambda name: None)
        found = {e["cidr"] for e in ip_utils._networks_from_proc_route()}
        assert "192.168.0.0/255.255.0.0" in found
        assert "10.1.0.0/255.255.240.0" in found
        assert not any(c.endswith("/0.0.0.0") for c in found)   # default route
        assert not any(c.startswith("10.10.10") for c in found)  # via a gateway

    def test_clean_drops_what_must_not_be_swept(self):
        raw = [
            {"cidr": "127.0.0.0/8"},        # loopback
            {"cidr": "169.254.0.0/16"},     # link-local
            {"cidr": "8.8.8.0/24"},         # public: scanning strangers
            {"cidr": "10.0.0.5/32"},        # point-to-point, no hosts
            {"cidr": "10.0.0.4/31"},
            {"cidr": "nonsense"},
            {"cidr": "192.168.1.0/24"},     # the only keeper
            {"cidr": "192.168.1.7/24"},     # same network, deduplicated
        ]
        cleaned = ip_utils._clean_networks(raw)
        assert [e["cidr"] for e in cleaned] == ["192.168.1.0/24"]

    def test_clean_is_bounded(self):
        raw = [{"cidr": f"10.{i}.0.0/24"} for i in range(200)]
        assert len(ip_utils._clean_networks(raw)) <= ip_utils._MAX_NETWORKS

    def test_ifconfig_parsing_handles_hex_masks(self):
        text = ("en0: flags=8863<UP> mtu 1500\n"
                "\tinet 192.168.4.21 netmask 0xfffffc00 broadcast 192.168.7.255\n"
                "lo0: flags=8049<UP> mtu 16384\n"
                "\tinet 127.0.0.1 netmask 0xff000000\n")
        parsed = ip_utils._parse_ifconfig(text)
        assert {"cidr": "192.168.4.21/255.255.252.0", "ip": "192.168.4.21",
                "interface": "en0"} in parsed

    def test_ip_addr_parsing(self):
        text = ("1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever\n"
                "2: eth0    inet 10.2.0.9/22 brd 10.2.3.255 scope global eth0\n")
        parsed = ip_utils._parse_ip_addr(text)
        assert {"cidr": "10.2.0.9/22", "ip": "10.2.0.9",
                "interface": "eth0"} in parsed

    def test_guess_is_the_last_resort_only(self):
        """The guess must still be a guess: no interface name attached, so a
        caller can tell it apart from a real reading."""
        for entry in ip_utils._networks_from_guess():
            assert entry["interface"] is None
            assert entry["cidr"].endswith("/24")
