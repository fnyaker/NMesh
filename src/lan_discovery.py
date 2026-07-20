"""
LAN relay discovery — find a mesh member on the same medium to relay through.

The relayed invitation (see node.py) needs at least one reachable relay. When
none is configured but a mesh member happens to sit on the same broadcast
domain (a LAN), a joiner can find it opportunistically: it broadcasts a small
beacon, and any member that hears it answers with the address(es) it can be
reached at. Those get added to the joiner's relay candidates, which then use
the ordinary (reliable, direct-link) relay path — no fragile datagram bridge.

stdlib only — a raw UDP socket on a fixed discovery port. Everything is
bounded and rate-limited: the beacon carries no secret, an answer only ever
costs the answerer one small reply (rate-limited per source), and a joiner
keeps a bounded set of answers. A hostile answer just wastes one connect
attempt downstream, which is itself bounded.
"""
from __future__ import annotations

import asyncio
import json
import os
import socket

DISCOVERY_PORT = 45888
_REQ = b"NDSCv1"            # beacon: "any relay on this LAN?"
_ANS = b"NDSAv1"           # answer: our reachable relay address(es)
_MAX_ADDRS = 8             # addresses per answer
_MAX_ADDR_LEN = 256
_MAX_ANSWER_LEN = 2048     # cap the answer body before parsing
_RATE_MAX = 30             # answers we emit per source per window
_RATE_WINDOW = 10.0
_MAX_RATE_TRACKED = 256


def _encode_answer(node_id: bytes, addrs: list[str]) -> bytes:
    body = json.dumps(addrs[:_MAX_ADDRS], separators=(",", ":")).encode("utf-8")
    return _ANS + node_id + body


def _decode_answer(data: bytes) -> tuple[bytes, list[str]] | None:
    """Parse an NDSA answer (hostile input). Returns (node_id, addrs) or None."""
    if not data.startswith(_ANS):
        return None
    body = data[len(_ANS):]
    if len(body) < 20 or len(body) > 20 + _MAX_ANSWER_LEN:
        return None
    node_id = body[:20]
    try:
        addrs = json.loads(body[20:])
    except Exception:
        return None
    if not isinstance(addrs, list):
        return None
    out = [a for a in addrs
           if isinstance(a, str) and 0 < len(a) <= _MAX_ADDR_LEN][:_MAX_ADDRS]
    return node_id, out


class _AnswererProtocol(asyncio.DatagramProtocol):
    def __init__(self, disc: "LanDiscovery") -> None:
        self._disc = disc

    def connection_made(self, transport) -> None:
        self._disc._ans_transport = transport

    def datagram_received(self, data: bytes, addr) -> None:
        self._disc._on_request(data, addr)

    def error_received(self, exc) -> None:
        pass  # never crash on socket errors


class _CollectorProtocol(asyncio.DatagramProtocol):
    def __init__(self, on_answer) -> None:
        self._on_answer = on_answer

    def datagram_received(self, data: bytes, addr) -> None:
        self._on_answer(data, addr)

    def error_received(self, exc) -> None:
        pass


class LanDiscovery:
    """Answers discovery beacons (so we are findable as a relay) and can run a
    discovery round (so we can find relays). Either role is independent."""

    def __init__(self, node_id: bytes, relays_cb) -> None:
        self._node_id = node_id
        self._relays_cb = relays_cb           # () -> list[str] of our relay URIs
        self._ans_transport = None
        self._rate: dict[str, tuple[int, float]] = {}

    # -- answerer role ------------------------------------------------------

    async def start(self, host: str = "") -> None:
        """Bind the discovery port and answer beacons. REUSEADDR/REUSEPORT so
        several local nodes (and tests) can share the port."""
        loop = asyncio.get_running_loop()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except (AttributeError, OSError):
            pass
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        except OSError:
            pass
        sock.bind((host, DISCOVERY_PORT))
        await loop.create_datagram_endpoint(
            lambda: _AnswererProtocol(self), sock=sock)

    def _allow(self, src_ip: str) -> bool:
        now = asyncio.get_event_loop().time()
        for k in [k for k, (_, ws) in self._rate.items()
                  if now - ws > _RATE_WINDOW]:
            del self._rate[k]
        while len(self._rate) > _MAX_RATE_TRACKED:
            self._rate.pop(next(iter(self._rate)))
        cnt, ws = self._rate.get(src_ip, (0, now))
        if now - ws > _RATE_WINDOW:
            cnt, ws = 0, now
        if cnt >= _RATE_MAX:
            self._rate[src_ip] = (cnt, ws)
            return False
        self._rate[src_ip] = (cnt + 1, ws)
        return True

    def _on_request(self, data: bytes, addr) -> None:
        if not data.startswith(_REQ):
            return
        if not self._allow(addr[0]):
            return
        try:
            relays = self._relays_cb()
        except Exception:
            relays = []
        if not relays:
            return  # we have nothing to offer — stay silent
        try:
            self._ans_transport.sendto(_encode_answer(self._node_id, relays), addr)
        except Exception:
            pass

    async def stop(self) -> None:
        if self._ans_transport is not None:
            try:
                self._ans_transport.close()
            except Exception:
                pass
            self._ans_transport = None

    # -- discoverer role ----------------------------------------------------

    async def discover(self, timeout: float = 1.5,
                       targets: tuple[str, ...] = ("255.255.255.255",)
                       ) -> list[str]:
        """Broadcast a beacon to each target and collect relay addresses from
        the answers for *timeout* seconds. Returns a bounded, de-duplicated
        list of candidate relay URIs (never our own)."""
        loop = asyncio.get_running_loop()
        found: list[str] = []
        seen: set[str] = set()

        def _on_answer(data: bytes, addr) -> None:
            parsed = _decode_answer(data)
            if parsed is None:
                return
            node_id, addrs = parsed
            if node_id == self._node_id:
                return  # our own answer
            for a in addrs:
                if a not in seen and len(found) < _MAX_ADDRS * 4:
                    seen.add(a)
                    found.append(a)

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        except OSError:
            pass
        sock.bind(("", 0))
        transport, _ = await loop.create_datagram_endpoint(
            lambda: _CollectorProtocol(_on_answer), sock=sock)
        try:
            beacon = _REQ + self._node_id
            for host in targets:
                try:
                    transport.sendto(beacon, (host, DISCOVERY_PORT))
                except OSError:
                    continue
            await asyncio.sleep(timeout)
        finally:
            try:
                transport.close()
            except Exception:
                pass
        return found
