"""
IP addressing helpers — stdlib only.

Used to make the IP transport self-describing: enumerate the host's own
addresses, parse ``host:port`` (IPv6-safe), and expand a wildcard listen URI
(``tcp://0.0.0.0:9000``) into the concrete, connectable URIs a node should
advertise (one per local address, plus any externally-discovered address).
"""
from __future__ import annotations

import ipaddress
import socket

from .uri import _validate_uri

_WILDCARD = {"0.0.0.0", "::", ""}


def split_host_port(opaque: str) -> tuple[str, str] | None:
    """Split ``host:port`` handling ``[ipv6]:port``. Returns (host, port) or None."""
    if opaque.startswith("["):
        end = opaque.find("]")
        if end == -1 or not opaque[end + 1:].startswith(":"):
            return None
        return opaque[1:end], opaque[end + 2:]
    if opaque.count(":") == 1:
        host, port = opaque.rsplit(":", 1)
        return host, port
    return None  # bare IPv6 without brackets, or malformed


def _fmt_host(ip: str) -> str:
    return f"[{ip}]" if ":" in ip else ip


def is_wildcard(host: str) -> bool:
    return host in _WILDCARD


def local_ip_addresses(include_loopback: bool = False) -> list[str]:
    """Best-effort list of the host's own IP addresses (v4 and v6)."""
    addrs: set[str] = set()
    for family, probe in ((socket.AF_INET, ("8.8.8.8", 80)),
                          (socket.AF_INET6, ("2001:4860:4860::8888", 80))):
        try:
            s = socket.socket(family, socket.SOCK_DGRAM)
            try:
                s.connect(probe)          # no packets sent; picks the outbound addr
                addrs.add(s.getsockname()[0])
            finally:
                s.close()
        except OSError:
            pass
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            addrs.add(info[4][0])
    except OSError:
        pass

    def keep(a: str) -> bool:
        a = a.split("%", 1)[0]  # drop scope id
        if include_loopback:
            return True
        return not (a.startswith("127.") or a == "::1")

    return sorted({a.split("%", 1)[0] for a in addrs if keep(a)})


def expand_listen_uri(uri: str, local_ips: list[str], extra: list[str] = ()) -> list[str]:
    """Expand a listen URI into advertisable URIs.

    A wildcard host becomes one URI per local address (plus ``extra``, e.g. a
    discovered public address). A concrete host is returned unchanged."""
    parsed = _validate_uri(uri)
    if parsed is None:
        return []
    scheme, opaque = parsed
    hp = split_host_port(opaque)
    if hp is None:
        return [uri]
    host, port = hp
    if not is_wildcard(host):
        return [uri]
    out: list[str] = []
    seen: set[str] = set()
    for ip in list(local_ips) + list(extra):
        u = f"{scheme}://{_fmt_host(ip)}:{port}"
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out


def _is_global_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def ip_reachability(scheme: str, uri: str, local_ips: list[str],
                    public_addrs: list[str], confirmed: bool) -> list[dict]:
    """Reachability descriptors for an IP-based listener (tcp/udp).

    Globally-routable addresses (a real public IP, or a discovered reflexive
    one) map to scope ``world``; RFC1918/link-local addresses map to scope
    ``lan`` anchored by our public IP — so *our* ``192.168.0.0/24`` is a
    different audience from the neighbour's identical range behind another
    public IP. ``confirmed`` reflects positive evidence of reachability
    (an accepted inbound authenticated connection on this transport)."""
    parsed = _validate_uri(uri)
    if parsed is None:
        return []
    hp = split_host_port(parsed[1])
    if hp is None:
        return []
    port = hp[1]
    anchor = next((a for a in public_addrs if _is_global_ip(a)), "")
    out: list[dict] = []
    seen: set[tuple[str, str]] = set()

    def add(ip: str, scope: str, anc: str) -> None:
        key = (ip, scope)
        if key in seen:
            return
        seen.add(key)
        out.append({
            "transport": scheme,
            "scope": scope,
            "anchor": anc,
            "address": f"{scheme}://{_fmt_host(ip)}:{port}",
            "confirmed": confirmed,
        })

    for ip in public_addrs:
        if _is_global_ip(ip):
            add(ip, "world", "")
    for ip in local_ips:
        if _is_global_ip(ip):
            add(ip, "world", "")
        else:
            add(ip, "lan", anchor)
    return out
