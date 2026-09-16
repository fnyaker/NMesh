"""
Asking a medium a question, and the answer you get when it misbehaves.

A transport is **somebody else's code**. Anyone may implement `BaseTransport` +
`BaseServer` and register it by URL scheme — that is the whole third principle —
so the core runs alongside implementations it has never seen, some of them
written badly and some of them written by an adversary who wants this node to
stop. The threat model says the moment data leaves the node it enters hostile
territory; a medium is the *door*, and a door is not more trustworthy than what
comes through it.

The core already wrapped most of these calls in `try`. That is half the job, and
the missing half is the one that actually bit: **it guarded the call and trusted
the answer.** `BaseTransport.remote_ip` is annotated `str | None`, so the code
did `remote.encode(...)` on whatever came back; `idle_timeout` is annotated
`float | None`, so the code did `timeout <= 0`. An annotation is a note between
people who agree. A transport that answers `5`, or `"soon"`, or a ten-megabyte
string, is not disagreeing — it is simply not bound by a comment.

So every question the core asks a medium is asked here, once, and comes back as
the type it was asked for or as the safe default. Two consequences worth stating:

* **Nothing raises.** A caller can use the answer without a guard of its own,
  which is what stops the next reader adding a seventh unguarded call site.
* **Every answer is bounded.** A medium that returns a megabyte where an address
  belongs must not be able to put it in a snapshot, a log, or a counter key —
  "bounds everywhere" applies to what comes *back* from a plug-in exactly as it
  applies to what arrives on a socket.

Failures are written down (`src/faults.py`) rather than swallowed: a transport
that throws on every call is a broken transport, and nobody ever finds out about
one that fails politely.
"""
from __future__ import annotations

import math

from .. import faults
from ..packet import Packet

# What a medium may say about one link. An address is an address; anything
# longer is a payload wearing one's name.
MAX_ADDRESS = 255
# Counters one transport may contribute, and how big each may be. A medium
# writes these into a console page and a link view, so they are bounded for the
# same reason every other display value is.
MAX_STATS = 16
MAX_STAT_KEY = 32
MAX_STAT_TEXT = 128
# Descriptors one server may contribute to "how is this node reachable". A
# listener answering a thousand is answering about somebody else's node.
MAX_DESCRIPTORS = 32
MAX_DESCRIPTOR_KEYS = 24


def _ask(thing, name: str, default, *args):
    """Ask one thing one question. Never raises; a failure is written down.

    **The lookup happens inside the guard**, and that is not a detail. Written
    as ``_ask("endpoints", transport.endpoints, …)`` the attribute is read
    *before* the call is made, so a medium that does not implement an optional
    method — every partial implementation, every duck-typed one — raises an
    `AttributeError` that no `try` here ever sees. This module was written that
    way first and the test suite caught it immediately, which is the whole
    argument for one reader: the mistake is possible once rather than at every
    call site."""
    try:
        method = getattr(thing, name, None)
        return default if method is None else method(*args)
    except Exception as exc:                    # noqa: BLE001 — that is the job
        faults.note(f"medium {name}", exc)
        return default


def _address(raw):
    """One address-shaped answer, or ``None``."""
    if not isinstance(raw, str):
        return None
    text = raw.strip()
    return text[:MAX_ADDRESS] if text else None


def remote_ip(transport) -> str | None:
    """Where this link's far end appears to be, as far as the medium knows.

    ``None`` is a real answer and the safe one: a spool on a USB stick has no
    remote address, and a transport that will not say has not proved anything.
    Every caller already treats ``None`` as "do not know", which is why this can
    turn a wrong type into one."""
    return _address(_ask(transport, "remote_ip", None))


def endpoints(transport) -> dict:
    """``{"local": …, "remote": …}`` — always those two keys, always a string
    or ``None`` under each."""
    raw = _ask(transport, "endpoints", None)
    if not isinstance(raw, dict):
        return {"local": None, "remote": None}
    return {"local": _address(raw.get("local")),
            "remote": _address(raw.get("remote"))}


def idle_timeout(transport) -> float | None:
    """Seconds this medium reaps an idle link after, or ``None`` for never.

    A number, positive and finite, or nothing. The keepalive loop divides by
    this figure to decide how often to probe, and a loop that raises is a node
    that stops noticing dead links — which is a great deal worse than a medium
    that declined to answer."""
    raw = _ask(transport, "idle_timeout", None)
    if isinstance(raw, bool) or not isinstance(raw, (int, float)):
        return None
    value = float(raw)
    if not math.isfinite(value) or value <= 0:
        return None
    return value


def stats(transport) -> dict:
    """Whatever counters this medium keeps, bounded and flattened to scalars."""
    raw = _ask(transport, "stats", None)
    if not isinstance(raw, dict):
        return {}
    out: dict = {}
    for key, value in list(raw.items())[:MAX_STATS]:
        if isinstance(value, str):
            value = value[:MAX_STAT_TEXT]
        elif isinstance(value, bool) or value is None:
            pass
        elif isinstance(value, (int, float)):
            if not math.isfinite(float(value)):
                continue
        else:
            continue            # not a number, not a word: not a counter
        out[str(key)[:MAX_STAT_KEY]] = value
    return out


def reachability(server, uri: str, ctx: dict) -> list:
    """How one listener says this node can be reached, as usable descriptors.

    A descriptor is read by the console, by a join ticket and by the addressing
    logic, all of which index into it. A server that answers a list of integers
    used to reach every one of those readers."""
    raw = _ask(server, "reachability", None, uri, ctx)
    if not isinstance(raw, (list, tuple)):
        return []
    out = []
    for entry in list(raw)[:MAX_DESCRIPTORS]:
        if isinstance(entry, dict) and len(entry) <= MAX_DESCRIPTOR_KEYS:
            out.append(entry)
    return out


def received(raw):
    """What ``receive()`` handed back, if it is a packet at all.

    The receive loop counts its length, traces it and hands it to a handler.
    All three assume a :class:`~src.packet.Packet`, and the one place that
    assumption comes from is a medium — so a transport answering ``None``, or a
    string, took the link down with an exception raised *outside* the loop's
    guard and left an unretrieved task behind it. ``None`` here is the same
    answer as a frame that would not decode, which the loop already knows how
    to charge to the peer."""
    return raw if isinstance(raw, Packet) else None
