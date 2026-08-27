"""
IP addressing helpers — stdlib only.

Used to make the IP transport self-describing: enumerate the host's own
addresses, parse ``host:port`` (IPv6-safe), and expand a wildcard listen URI
(``tcp://0.0.0.0:9000``) into the concrete, connectable URIs a node should
advertise (one per local address, plus any externally-discovered address).
"""
from __future__ import annotations

import asyncio
import ipaddress
import socket
import threading

from .uri import _validate_uri

_WILDCARD = {"0.0.0.0", "::", ""}


async def bounded_getaddrinfo(host: str, port: int, *,
                              family=socket.AF_UNSPEC,
                              type=socket.SOCK_STREAM,
                              timeout: float = 5.0):
    """DNS resolution that can never wedge interpreter shutdown.

    ``loop.getaddrinfo`` runs on asyncio's default executor, which is *joined*
    at shutdown — a lookup that hangs on a restricted network would block it
    forever (see ``Docs/Architecture/gotchas.md`` §2). Resolve in a daemon
    thread we abandon on timeout instead."""
    loop = asyncio.get_running_loop()
    fut: asyncio.Future = loop.create_future()

    def _worker() -> None:
        try:
            result = socket.getaddrinfo(host, port, family=family, type=type)
        except Exception as exc:
            result = exc
        if not loop.is_closed():
            loop.call_soon_threadsafe(lambda: fut.done() or fut.set_result(result))

    threading.Thread(target=_worker, name="nmesh-dns", daemon=True).start()
    res = await asyncio.wait_for(fut, timeout)
    if isinstance(res, BaseException):
        raise res
    return res


async def wait_closed_bounded(obj, timeout: float = 1.0) -> None:
    """``wait_closed()`` that cannot wedge the caller.

    Python 3.12 changed ``asyncio.Server.wait_closed()`` to block until every
    accepted connection has finished too, not just until the listening socket
    is shut. Awaiting it while a client is still parked in its handler never
    returns — the shutdown deadlocks, and on 3.11 the same code returned at
    once, so the trap is invisible until the interpreter moves. ``close()`` has
    already shut the listening socket, which is what the caller is really
    waiting for, so wait briefly and move on.

    Whoever owns the connections should drop them *before* calling this; the
    bound is what stops one handler that ignores its close from wedging the
    rest."""
    try:
        await asyncio.wait_for(obj.wait_closed(), timeout=timeout)
    except (asyncio.TimeoutError, Exception):
        pass


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


# Interface / network enumeration
# ---------------------------------------------------------------------------
#
# ``local_ip_addresses`` answers "what are my addresses"; it says nothing about
# the *networks* they sit on. A LAN sweep needs the real prefix — guessing /24
# around an address misses a /22 or /16 entirely, and only sees the interfaces
# the outbound-route probe happens to reveal.
#
# There is no stdlib call for this, so we try sources in order of reliability
# and fall back until something answers. Every source is wrapped: a machine we
# cannot introspect yields fewer networks, never an exception.

_MAX_NETWORKS = 32
_PROC_ROUTE = "/proc/net/route"
_SIOCGIFADDR = 0x8915          # Linux
_SIOCGIFNETMASK = 0x891B


def local_networks() -> list[dict]:
    """Every directly-attached IPv4 network this host sits on.

    Returns ``[{"cidr", "ip", "interface"}, …]`` — ``ip`` is our own address on
    that network when known. Private networks only: sweeping a public prefix we
    happen to be inside would be scanning strangers, not a LAN. Loopback,
    link-local and point-to-point (/31, /32) networks are skipped — none of them
    is a LAN worth discovering."""
    for source in (_networks_from_proc_route, _networks_from_ioctl,
                   _networks_from_command, _networks_from_guess):
        try:
            found = source()
        except Exception:
            found = []
        if found:
            return _clean_networks(found)
    return []


def _clean_networks(raw: list[dict]) -> list[dict]:
    out: list[dict] = []
    seen: set[str] = set()
    for entry in raw:
        try:
            net = ipaddress.ip_network(entry["cidr"], strict=False)
        except (KeyError, ValueError):
            continue
        if net.version != 4 or net.prefixlen >= 31:
            continue
        if not net.is_private or net.is_loopback or net.is_link_local:
            continue
        text = str(net)
        if text in seen:
            continue
        seen.add(text)
        out.append({"cidr": text, "ip": entry.get("ip"),
                    "interface": entry.get("interface")})
        if len(out) >= _MAX_NETWORKS:
            break
    return out


def _networks_from_proc_route() -> list[dict]:
    """Linux: connected routes straight from the kernel's table.

    The most reliable source — a route with no gateway *is* an attached network,
    with its exact mask. Fields are little-endian hex."""
    out = []
    with open(_PROC_ROUTE, encoding="ascii", errors="replace") as handle:
        next(handle, None)                       # header
        for line in handle:
            fields = line.split()
            if len(fields) < 8:
                continue
            iface, dest, gateway, _flags = fields[0], fields[1], fields[2], fields[3]
            mask = fields[7]
            if gateway != "0" * 8:
                continue                          # via a router: not attached
            try:
                network = _le_hex_ip(dest)
                netmask = _le_hex_ip(mask)
            except ValueError:
                continue
            if netmask == "0.0.0.0":
                continue                          # default route
            out.append({"cidr": f"{network}/{netmask}", "interface": iface,
                        "ip": _iface_address(iface)})
    return out


def _le_hex_ip(value: str) -> str:
    """Decode a little-endian hex address as printed by /proc/net/route."""
    raw = int(value, 16)
    return str(ipaddress.IPv4Address(raw.to_bytes(4, "little")))


def _iface_address(name: str) -> str | None:
    try:
        import fcntl
        import struct
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            packed = fcntl.ioctl(sock.fileno(), _SIOCGIFADDR,
                                 struct.pack("256s", name.encode()[:15]))
        return socket.inet_ntoa(packed[20:24])
    except Exception:
        return None


def _networks_from_ioctl() -> list[dict]:
    """Ask each interface for its address and netmask (Linux ioctl numbers)."""
    import fcntl
    import struct
    out = []
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        for _index, name in socket.if_nameindex():
            request = struct.pack("256s", name.encode()[:15])
            try:
                addr = socket.inet_ntoa(
                    fcntl.ioctl(sock.fileno(), _SIOCGIFADDR, request)[20:24])
                mask = socket.inet_ntoa(
                    fcntl.ioctl(sock.fileno(), _SIOCGIFNETMASK, request)[20:24])
            except OSError:
                continue                          # down, or no IPv4 on it
            out.append({"cidr": f"{addr}/{mask}", "ip": addr, "interface": name})
    return out


def _networks_from_command() -> list[dict]:
    """Portable fallback: read what ``ip`` or ``ifconfig`` prints (macOS, BSD).

    Bounded and short-lived; a missing or slow binary just yields nothing."""
    import subprocess
    for argv, parse in ((["ip", "-o", "-4", "addr", "show"], _parse_ip_addr),
                        (["ifconfig", "-a"], _parse_ifconfig)):
        try:
            result = subprocess.run(argv, capture_output=True, text=True,
                                    timeout=5)
        except (OSError, subprocess.SubprocessError):
            continue
        if result.returncode == 0 and result.stdout:
            found = parse(result.stdout[:262144])
            if found:
                return found
    return []


def _parse_ip_addr(text: str) -> list[dict]:
    out = []
    for line in text.splitlines()[:256]:
        fields = line.split()
        if "inet" not in fields:
            continue
        try:
            cidr = fields[fields.index("inet") + 1]
        except IndexError:
            continue
        iface = fields[1].rstrip(":") if len(fields) > 1 else None
        out.append({"cidr": cidr, "ip": cidr.split("/")[0], "interface": iface})
    return out


def _parse_ifconfig(text: str) -> list[dict]:
    """BSD/macOS ``ifconfig``: ``inet 10.0.0.5 netmask 0xffffff00``."""
    out = []
    iface = None
    for line in text.splitlines()[:512]:
        if line and not line[0].isspace():
            iface = line.split(":", 1)[0].split()[0]
        fields = line.split()
        if "inet" not in fields or "netmask" not in fields:
            continue
        try:
            addr = fields[fields.index("inet") + 1]
            mask = fields[fields.index("netmask") + 1]
        except IndexError:
            continue
        if mask.startswith("0x"):
            try:
                mask = str(ipaddress.IPv4Address(int(mask, 16)))
            except ValueError:
                continue
        out.append({"cidr": f"{addr}/{mask}", "ip": addr, "interface": iface})
    return out


def _networks_from_guess() -> list[dict]:
    """Last resort: assume a /24 around each address we know of. Better than
    reporting nothing, and clearly marked as a guess by having no interface."""
    return [{"cidr": f"{address}/24", "ip": address, "interface": None}
            for address in local_ip_addresses()]


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
