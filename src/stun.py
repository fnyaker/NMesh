"""
Minimal STUN client — RFC 5389 Binding Request over UDP.

Used as a fallback when no mesh peer is available to observe our public
address (the mesh-native OBSERVED_ADDR mechanism is preferred). Sends a
single Binding Request to a public STUN server and parses the
XOR-MAPPED-ADDRESS (or MAPPED-ADDRESS) attribute to learn our public
reflexive address.

stdlib only — raw UDP socket, no external library.
"""
from __future__ import annotations

import asyncio
import os
import socket
import struct

# RFC 5389 constants
_STUN_MAGIC_COOKIE = 0x2112A442
_STUN_BINDING_REQUEST = 0x0001
_STUN_BINDING_RESPONSE = 0x0101
_STUN_ATTR_XOR_MAPPED_ADDR = 0x0020
_STUN_ATTR_MAPPED_ADDR = 0x0001

# Default public STUN servers (tried in order)
DEFAULT_STUN_SERVERS: list[tuple[str, int]] = [
    ("stun.l.google.com", 19302),
    ("stun1.l.google.com", 19302),
    ("stun2.l.google.com", 19302),
]

_STUN_TIMEOUT = 3.0  # seconds per attempt


def _build_binding_request() -> bytes:
    """Build a STUN Binding Request with a random transaction ID."""
    txn_id = os.urandom(12)
    # Type(2) | Length(2) | Magic(4) | TransactionID(12) = 20 bytes header
    msg_type = struct.pack("!HH", _STUN_BINDING_REQUEST, 0)
    magic = struct.pack("!I", _STUN_MAGIC_COOKIE)
    return msg_type + magic + txn_id


def _parse_xor_mapped_address(attr_value: bytes, txn_id: bytes) -> tuple[str, int] | None:
    """Parse XOR-MAPPED-ADDRESS attribute (RFC 5389 §15.2)."""
    if len(attr_value) < 8:
        return None
    family = attr_value[1]
    xor_port = struct.unpack("!H", attr_value[2:4])[0]
    port = xor_port ^ (_STUN_MAGIC_COOKIE >> 16)

    if family == 0x01:  # IPv4
        xor_ip = struct.unpack("!I", attr_value[4:8])[0]
        ip_int = xor_ip ^ _STUN_MAGIC_COOKIE
        ip = socket.inet_ntop(socket.AF_INET, struct.pack("!I", ip_int))
        return ip, port
    elif family == 0x02:  # IPv6
        if len(attr_value) < 20:
            return None
        xor_ip_bytes = attr_value[4:20]
        magic_bytes = struct.pack("!I", _STUN_MAGIC_COOKIE) + txn_id
        ip_bytes = bytes(a ^ b for a, b in zip(xor_ip_bytes, magic_bytes))
        ip = socket.inet_ntop(socket.AF_INET6, ip_bytes)
        return ip, port
    return None


def _parse_mapped_address(attr_value: bytes) -> tuple[str, int] | None:
    """Parse legacy MAPPED-ADDRESS attribute (RFC 3489)."""
    if len(attr_value) < 8:
        return None
    family = attr_value[1]
    port = struct.unpack("!H", attr_value[2:4])[0]
    if family == 0x01:  # IPv4
        ip = socket.inet_ntop(socket.AF_INET, attr_value[4:8])
        return ip, port
    elif family == 0x02:  # IPv6
        if len(attr_value) < 20:
            return None
        ip = socket.inet_ntop(socket.AF_INET6, attr_value[4:20])
        return ip, port
    return None


def _parse_binding_response(data: bytes, txn_id: bytes) -> tuple[str, int] | None:
    """Parse a STUN Binding Response and extract the mapped address."""
    if len(data) < 20:
        return None
    msg_type, msg_len = struct.unpack("!HH", data[0:4])
    if msg_type != _STUN_BINDING_RESPONSE:
        return None
    magic = struct.unpack("!I", data[4:8])[0]
    if magic != _STUN_MAGIC_COOKIE:
        return None
    resp_txn_id = data[8:20]
    if resp_txn_id != txn_id:
        return None

    # Parse attributes
    offset = 20
    end = 20 + msg_len
    while offset + 4 <= end and offset + 4 <= len(data):
        attr_type, attr_len = struct.unpack("!HH", data[offset:offset + 4])
        offset += 4
        if offset + attr_len > len(data):
            break
        attr_value = data[offset:offset + attr_len]
        offset += attr_len
        # Pad to 4-byte boundary
        pad = (4 - (attr_len % 4)) % 4
        offset += pad

        if attr_type == _STUN_ATTR_XOR_MAPPED_ADDR:
            result = _parse_xor_mapped_address(attr_value, txn_id)
            if result is not None:
                return result
        elif attr_type == _STUN_ATTR_MAPPED_ADDR:
            result = _parse_mapped_address(attr_value)
            if result is not None:
                return result
    return None


async def query_stun_server(host: str, port: int = 19302,
                            timeout: float = _STUN_TIMEOUT) -> tuple[str, int] | None:
    """
    Send a STUN Binding Request to a single server and return (ip, port)
    of our public reflexive address, or None on failure.
    """
    loop = asyncio.get_running_loop()
    try:
        addrinfo = await loop.getaddrinfo(host, port, family=socket.AF_INET,
                                          type=socket.SOCK_DGRAM)
    except (socket.gaierror, OSError):
        return None
    if not addrinfo:
        return None
    target = addrinfo[0][4]

    request = _build_binding_request()
    txn_id = request[8:20]  # 12-byte transaction ID

    try:
        transport, protocol = await loop.create_datagram_endpoint(
            lambda: _StunProtocol(),
            remote_addr=target,
        )
    except OSError:
        return None

    try:
        transport.sendto(request)
        try:
            data = await asyncio.wait_for(protocol.received, timeout=timeout)
        except (asyncio.TimeoutError, asyncio.CancelledError):
            return None
        return _parse_binding_response(data, txn_id)
    finally:
        try:
            transport.close()
        except Exception:
            pass


async def discover_public_addr(
    servers: list[tuple[str, int]] | None = None,
    timeout: float = _STUN_TIMEOUT,
) -> tuple[str, int] | None:
    """
    Try STUN servers in order until one returns our public address.
    Returns (ip, port) or None if all fail.
    """
    server_list = servers or DEFAULT_STUN_SERVERS
    for host, port in server_list:
        result = await query_stun_server(host, port, timeout)
        if result is not None:
            return result
    return None


class _StunProtocol(asyncio.DatagramProtocol):
    """Minimal datagram protocol that captures the first response."""

    def __init__(self) -> None:
        self.received: asyncio.Future[bytes] = asyncio.get_running_loop().create_future()

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        if not self.received.done():
            self.received.set_result(data)

    def error_received(self, exc: Exception) -> None:
        if not self.received.done():
            self.received.set_exception(exc)
