"""
"Stop relaying that node's traffic to me."

A node that has decided to stop enduring another can drop what that node sends
it — but when the traffic arrives through relays, dropping it at the end of the
path still costs every relay on the way, and the end of the path last. This is
the request that moves the drop to where the traffic enters: the destination
signs it, the relay that delivers the traffic stops forwarding it, and passes
the same signed request to whoever was feeding it, back along the path.

What it may and may not do
--------------------------
It speaks **only for the destination's own inbox**. The record names the
requester, and the requester is the key that signed it: a relay honours "stop
relaying X to *me*", never "stop relaying X to somebody else". Nobody can use
it to cut a node off from anybody but themselves — the reason a relay never
acts on what it has heard about X, only on what X's destination asked.

It expires. A destination that still wants it renews it; one that changed its
mind lets it run out. The lifetime is bounded so a request cannot pin a rule
in a relay for ever.

Hostile input
-------------
`parse` never raises and never returns a half-checked record: anything
oversized, truncated, expired, badly bounded or badly signed is ``None``. It is
a gate, and a gate that can throw is a gate that can kill a receive loop.
"""
from __future__ import annotations

import struct
import time

from .node_id import NodeID

_DOMAIN = b"nmesh-stop-relay-v1"
VERSION = 1

# version(B) ‖ issued_at(Q) ‖ expires_at(Q) ‖ blocked(20) ‖ pub_len(H) ‖ sig_len(H)
_HDR = struct.Struct("!BQQ20sHH")
_MAX_PUBKEY = 4096
_MAX_SIG = 5000
MAX_RECORD = _HDR.size + _MAX_PUBKEY + _MAX_SIG

MAX_TTL = 3600          # seconds a request may ask to be honoured for
_CLOCK_SKEW = 300       # how far in the future an issue time may claim to be


def _signed(issued_at: int, expires_at: int, blocked: bytes,
            requester: bytes) -> bytes:
    return (_DOMAIN + bytes([VERSION]) + struct.pack("!QQ", issued_at, expires_at)
            + blocked + requester)


def build(blocked: NodeID, requester_pub: bytes, sign, *, ttl: int,
          now: int | None = None) -> bytes:
    """Sign a request that relays stop forwarding ``blocked``'s traffic to the
    key's owner, for ``ttl`` seconds (at most `MAX_TTL`)."""
    now = int(time.time()) if now is None else now
    ttl = max(1, min(int(ttl), MAX_TTL))
    requester = NodeID.from_public_key(requester_pub)
    if requester == blocked:
        raise ValueError("a node does not block itself")
    signature = sign(_signed(now, now + ttl, blocked.raw, requester.raw))
    return (_HDR.pack(VERSION, now, now + ttl, blocked.raw, len(requester_pub),
                      len(signature)) + requester_pub + signature)


def parse(data, verify, now: int | None = None) -> dict | None:
    """``{requester, blocked, issued_at, expires_at}`` for a record that holds
    now, or ``None``."""
    try:
        if not isinstance(data, (bytes, bytearray)) or len(data) > MAX_RECORD:
            return None
        if len(data) < _HDR.size:
            return None
        version, issued, expires, blocked, pub_len, sig_len = _HDR.unpack_from(data, 0)
        if version != VERSION or pub_len > _MAX_PUBKEY or sig_len > _MAX_SIG:
            return None
        if _HDR.size + pub_len + sig_len != len(data):
            return None
        now = int(time.time()) if now is None else now
        if expires <= now or expires <= issued or expires - issued > MAX_TTL:
            return None
        if issued > now + _CLOCK_SKEW:
            return None
        pub = bytes(data[_HDR.size:_HDR.size + pub_len])
        signature = bytes(data[_HDR.size + pub_len:])
        requester = NodeID.from_public_key(pub)
        if requester.raw == blocked:
            return None
        if not verify(_signed(issued, expires, blocked, requester.raw), signature, pub):
            return None
        return {"requester": requester, "blocked": NodeID(bytes(blocked)),
                "issued_at": issued, "expires_at": expires}
    except Exception:
        return None
