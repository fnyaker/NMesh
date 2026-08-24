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

Layout, ``version_and_type | address | port | seed | expiry | check``::

    byte 0      version (high nibble) and address family (low nibble)
    1..4/16     the address, 4 bytes for IPv4 or 16 for IPv6
    +2          port, big endian
    +8          the invite code's seed (the code is derived from it)
    +4          expiry, unix minutes — a **hint** for the reader
    +2          checksum, to catch a typo before dialling anything

21 bytes for IPv4, 33 for IPv6, rendered in unpadded base32.

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

VERSION = 1
FAMILY_V4 = 4
FAMILY_V6 = 6

SEED_BYTES = 8          # 64 bits, behind a single-use code and a lockout
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


def encode(host: str, port: int, seed: bytes, expires_at: float) -> str:
    """Build the ticket string. Raises ``TicketError`` on anything unusable."""
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        # Deliberate: a ticket carries an address, never a name. A name would
        # need a resolver on the scanning side and could point anywhere later.
        raise TicketError("a ticket needs a numeric IP address") from None
    if not 1 <= int(port) <= 65535:
        raise TicketError("port out of range")
    if len(seed) != SEED_BYTES:
        raise TicketError("wrong seed length")

    family = FAMILY_V4 if address.version == 4 else FAMILY_V6
    body = (bytes([(VERSION << 4) | family])
            + address.packed
            + struct.pack("!H", int(port))
            + seed
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

    version, family = body[0] >> 4, body[0] & 0x0F
    if version != VERSION:
        raise TicketError(f"ticket version {version} is not supported")
    size = _LENGTHS.get(family)
    if size is None:
        raise TicketError("unknown address family")
    if len(body) != 1 + size + 2 + SEED_BYTES + 4:
        raise TicketError("this ticket is the wrong length")

    offset = 1
    address = ipaddress.ip_address(body[offset:offset + size])
    offset += size
    port = struct.unpack_from("!H", body, offset)[0]
    offset += 2
    seed = body[offset:offset + SEED_BYTES]
    offset += SEED_BYTES
    minutes = struct.unpack_from("!I", body, offset)[0]

    if not 1 <= port <= 65535:
        raise TicketError("port out of range")
    host = f"[{address}]" if address.version == 6 else str(address)
    return {
        "uri": f"tcp://{host}:{port}",
        "host": str(address),
        "port": port,
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
