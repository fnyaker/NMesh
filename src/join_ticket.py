"""
Join tickets: one short string that carries where to connect and how to prove it.

The full join is two pieces the operator has to move by hand — an address and an
invite code — plus a console to paste them into. A ticket is the same thing
compacted into one string short enough to read aloud, type on a phone, or put in
a QR code.

    NM1: tcp://203.0.113.7:9000 + a single-use code   →   34 characters

**A ticket is the secret.** Anyone who can read it can join the network until it
expires or is redeemed — it is exactly as sensitive as the invite code inside
it, which is why it is single-use, short-lived by default, and why the console
says so next to every one it prints. Photographing a QR code off a screen is not
an attack anyone needs to be clever about.

Layout, ``version_and_flags | [direct] | [relay ‖ node id] | seed | expiry | check``::

    byte 0      version (high nibble) and flags (low nibble)
                  bit 0  a direct endpoint follows
                  bit 1  …and it is IPv6
                  bit 2  a relay endpoint follows, with the inviter's node id
                  bit 3  …and it is IPv6
    [4/16 + 2]  the inviter's own address and port          (bit 0)
    [4/16 + 2]  a relay's address and port                  (bit 2)
    [20]        the inviter's node id                       (bit 2)
    +8          the invite code's seed (the code is derived from it)
    +4          expiry, unix minutes — a **hint** for the reader
    +2          checksum, to catch a typo before dialling anything

21 bytes for a direct IPv4 ticket, 47 for one carrying both routes — 76
characters of base32, still short enough to read aloud and well inside a small
QR code.

**Both routes in one string, so there is no second exchange.** An invitation
used to be either a ticket (direct only, and useless if the inviter has no
public address) or a block of base64 pasted between two consoles. Carrying a
relay beside the direct endpoint makes one artifact work in both cases: the
joiner dials the inviter if it can, and otherwise reaches it *through* the relay
named here — with the same single-use code either way.

Version 1 tickets still decode. They are the direct-only case with the flags
spelled differently, and refusing to read one would strand invitations already
in somebody's hands.

Two deliberate choices worth stating. Base32 rather than base64: it is longer as
a string, but it is *case-insensitive* (so it can be dictated and retyped) and
it encodes in a QR code's alphanumeric mode at 5 bits per 5.5, where base64
would need byte mode at 6 bits per 8 — the QR ends up smaller. And the expiry is
a hint, not a rule: the node that issued the code is the only authority on
whether it is still valid, and the reader only uses this to say "that one is
stale" without dialling.
"""
from __future__ import annotations

import base64
import hashlib
import ipaddress
import struct
import time

VERSION = 2
LEGACY_VERSION = 1      # the direct-only ticket, still readable
FAMILY_V4 = 4
FAMILY_V6 = 6

FLAG_DIRECT = 1
FLAG_DIRECT_V6 = 2
FLAG_RELAY = 4
FLAG_RELAY_V6 = 8

SEED_BYTES = 8          # 64 bits, behind a single-use code and a lockout
NODE_BYTES = 20         # a NodeID — sha256(DSA public key)[:20]
CHECK_BYTES = 2
_LENGTHS = {FAMILY_V4: 4, FAMILY_V6: 16}

# A ticket is a fixed-size record; anything wildly longer is not one. The bound
# exists so decoding a hostile string costs nothing.
MAX_TEXT = 128

# Bounds on what an operator may ask for. Longer than the invite manager's own
# ceiling would be a lie: it would expire there first.
MIN_TTL = 30.0
MAX_TTL = 6 * 3600.0
DEFAULT_TTL = 600.0


class TicketError(Exception):
    """A ticket that cannot be used, phrased for whoever pasted it."""


def _b32(raw: bytes) -> str:
    return base64.b32encode(raw).decode("ascii").rstrip("=")


def _unb32(text: str) -> bytes:
    padding = "=" * (-len(text) % 8)
    return base64.b32decode(text + padding, casefold=True)


def code_from_seed(seed: bytes) -> str:
    """The invite code a seed stands for.

    Both sides derive it the same way, so the ticket carries 8 bytes instead of
    the code's characters. The code is still an ordinary invite code: single
    use, rate-limited, and never sent over the wire (the handshake proves
    knowledge of it through an HMAC challenge)."""
    return _b32(seed)


def _endpoint(host, port) -> tuple[bytes, bool]:
    """One address and port, packed. Raises ``TicketError`` on anything else."""
    try:
        address = ipaddress.ip_address(host)
    except (ValueError, TypeError):
        # Deliberate: a ticket carries an address, never a name. A name would
        # need a resolver on the scanning side and could point anywhere later.
        raise TicketError("a ticket needs a numeric IP address") from None
    try:
        number = int(port)
    except (TypeError, ValueError):
        raise TicketError("port out of range") from None
    if not 1 <= number <= 65535:
        raise TicketError("port out of range")
    return address.packed + struct.pack("!H", number), address.version == 6


def encode(host, port, seed: bytes, expires_at: float, *,
           relay=None, node_id: bytes = b"") -> str:
    """Build the ticket string. Raises ``TicketError`` on anything unusable.

    ``host``/``port`` are the inviter's own endpoint and may be omitted when it
    has none; ``relay`` is ``(host, port)`` for a node the joiner can reach it
    *through*, and needs ``node_id`` with it — a relayed invitation is routed to
    an identity, so the identity has to be in the string."""
    if len(seed) != SEED_BYTES:
        raise TicketError("wrong seed length")
    flags = 0
    parts: list[bytes] = []
    if host:
        packed, is_v6 = _endpoint(host, port)
        flags |= FLAG_DIRECT | (FLAG_DIRECT_V6 if is_v6 else 0)
        parts.append(packed)
    if relay:
        if len(node_id) != NODE_BYTES:
            raise TicketError("a relayed ticket needs the inviter's node id")
        packed, is_v6 = _endpoint(relay[0], relay[1])
        flags |= FLAG_RELAY | (FLAG_RELAY_V6 if is_v6 else 0)
        parts.append(packed)
        parts.append(node_id)
    if not flags:
        raise TicketError("a ticket needs somewhere to connect")

    body = (bytes([(VERSION << 4) | flags]) + b"".join(parts) + seed
            + struct.pack("!I", max(0, int(expires_at // 60))))
    return _b32(body + _checksum(body))


def decode(text: str) -> dict:
    """Parse a ticket. Raises ``TicketError`` — never anything else.

    Everything here is attacker-supplied, so every step is checked before it is
    used and no failure is allowed to be an exception nobody expected."""
    if not isinstance(text, str):
        raise TicketError("not a ticket")
    cleaned = "".join(text.split()).replace("-", "").upper()
    if not cleaned:
        raise TicketError("empty ticket")
    if len(cleaned) > MAX_TEXT:
        raise TicketError("too long to be a ticket")
    try:
        raw = _unb32(cleaned)
    except Exception:
        raise TicketError("this does not look like a ticket") from None
    if len(raw) < 1 + 4 + 2 + SEED_BYTES + 4 + CHECK_BYTES:
        raise TicketError("this ticket is truncated")

    body, check = raw[:-CHECK_BYTES], raw[-CHECK_BYTES:]
    if check != _checksum(body):
        # Not integrity against an attacker — they would simply recompute it.
        # This catches a mistyped or half-scanned ticket before we dial.
        raise TicketError("this ticket is mistyped or damaged")

    version, low = body[0] >> 4, body[0] & 0x0F
    if version == LEGACY_VERSION:
        return _decode_v1(body, low)
    if version != VERSION:
        raise TicketError(f"ticket version {version} is not supported")
    return _decode_v2(body, low)


def _decode_v1(body: bytes, family: int) -> dict:
    """The direct-only ticket. Read, never written — see the module docstring."""
    size = _LENGTHS.get(family)
    if size is None:
        raise TicketError("unknown address family")
    if len(body) != 1 + size + 2 + SEED_BYTES + 4:
        raise TicketError("this ticket is the wrong length")
    reader = _Reader(body, 1)
    host, port = reader.endpoint(size)
    seed = reader.take(SEED_BYTES)
    minutes = struct.unpack("!I", reader.take(4))[0]
    return _ticket(host, port, "", 0, b"", seed, minutes)


def _decode_v2(body: bytes, flags: int) -> dict:
    if not flags & (FLAG_DIRECT | FLAG_RELAY):
        raise TicketError("this ticket points nowhere")
    expected = 1 + SEED_BYTES + 4
    if flags & FLAG_DIRECT:
        expected += (16 if flags & FLAG_DIRECT_V6 else 4) + 2
    if flags & FLAG_RELAY:
        expected += (16 if flags & FLAG_RELAY_V6 else 4) + 2 + NODE_BYTES
    if len(body) != expected:
        raise TicketError("this ticket is the wrong length")

    reader = _Reader(body, 1)
    host, port = ("", 0)
    relay_host, relay_port, node = ("", 0, b"")
    if flags & FLAG_DIRECT:
        host, port = reader.endpoint(16 if flags & FLAG_DIRECT_V6 else 4)
    if flags & FLAG_RELAY:
        relay_host, relay_port = reader.endpoint(16 if flags & FLAG_RELAY_V6 else 4)
        node = reader.take(NODE_BYTES)
    seed = reader.take(SEED_BYTES)
    minutes = struct.unpack("!I", reader.take(4))[0]
    return _ticket(host, port, relay_host, relay_port, node, seed, minutes)


class _Reader:
    """A cursor over a ticket's body that cannot run off the end silently."""

    __slots__ = ("body", "at")

    def __init__(self, body: bytes, at: int) -> None:
        self.body, self.at = body, at

    def take(self, count: int) -> bytes:
        piece = self.body[self.at:self.at + count]
        if len(piece) != count:
            raise TicketError("this ticket is truncated")
        self.at += count
        return piece

    def endpoint(self, size: int) -> tuple[str, int]:
        address = ipaddress.ip_address(self.take(size))
        port = struct.unpack("!H", self.take(2))[0]
        if not 1 <= port <= 65535:
            raise TicketError("port out of range")
        return str(address), port


def _uri(host: str, port: int) -> str:
    if not host:
        return ""
    shown = f"[{host}]" if ":" in host else host
    return f"tcp://{shown}:{port}"


def _ticket(host, port, relay_host, relay_port, node, seed, minutes) -> dict:
    return {
        "uri": _uri(host, port),
        "host": host,
        "port": port,
        # Where to reach the inviter *through* somebody, when it has no address
        # of its own — or when the one it has does not answer.
        "relay_uri": _uri(relay_host, relay_port),
        "relay_host": relay_host,
        "relay_port": relay_port,
        "node": node.hex() if node else "",
        "code": code_from_seed(seed),
        # Advisory only — the issuing node decides whether the code still works.
        "expires_at": minutes * 60,
        "expired": minutes * 60 < time.time(),
    }


def _checksum(body: bytes) -> bytes:
    return hashlib.sha256(b"nmesh-join-ticket-v1" + body).digest()[:CHECK_BYTES]


def clamp_ttl(seconds) -> float:
    """The lifetime an operator asked for, brought inside what we will issue."""
    try:
        value = float(seconds)
    except (TypeError, ValueError):
        return DEFAULT_TTL
    return max(MIN_TTL, min(value, MAX_TTL))
