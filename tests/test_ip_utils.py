"""IP addressing helpers."""
import pytest

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


class TestExpand:
    def test_wildcard_v4_expands(self):
        out = expand_listen_uri("tcp://0.0.0.0:9000", ["1.2.3.4", "10.0.0.1"])
        assert out == ["tcp://1.2.3.4:9000", "tcp://10.0.0.1:9000"]

    def test_extra_appended(self):
        out = expand_listen_uri("tcp://0.0.0.0:9000", ["1.2.3.4"], ["203.0.113.5"])
        assert out == ["tcp://1.2.3.4:9000", "tcp://203.0.113.5:9000"]

    def test_ipv6_bracketed(self):
        out = expand_listen_uri("tcp://[::]:9000", ["fe80::1"])
        assert out == ["tcp://[fe80::1]:9000"]

    def test_concrete_unchanged(self):
        assert expand_listen_uri("tcp://192.168.1.5:9000", ["1.2.3.4"]) \
            == ["tcp://192.168.1.5:9000"]

    def test_invalid_uri(self):
        assert expand_listen_uri("not-a-uri", ["1.2.3.4"]) == []

    def test_dedup(self):
        out = expand_listen_uri("tcp://0.0.0.0:9000", ["1.2.3.4", "1.2.3.4"])
        assert out == ["tcp://1.2.3.4:9000"]
