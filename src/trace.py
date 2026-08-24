"""
Protocol trace: a bounded recording of what a node actually sends and receives.

Why it exists: "two idle nodes are exchanging 280 kbit/s" is not a question the
throughput counters can answer. They say how much, never *what*. This says what:
one line per packet, and a summary by message type that usually makes the answer
obvious before anyone reads a single line.

What it records, and nothing else: time, direction, message type, size on the
wire, TTL, the peer it crossed, and the source/destination ids in the header.
**No payload, ever** — not the ciphertext, not the plaintext, not a key. The
header is already visible to every relay on the path; the payload is the part
this project exists to protect, and a debugging tool is not a reason to write it
somewhere.

It is still not harmless. A trace is a routing-metadata record: who this node
talks to, when, and how much. It is off by default, lives in memory, is bounded,
stops on its own, and is only ever written to disk when an operator asks.
"""
from __future__ import annotations

import json
import os
import time
from collections import OrderedDict, deque

# A trace is read by a human, or summarised. Both stop being useful long before
# these bounds — they are here so a node under load cannot be made to spend
# memory on diagnostics.
MAX_EVENTS = 20000
DEFAULT_EVENTS = 5000
MAX_SECONDS = 3600.0
DEFAULT_SECONDS = 120.0
_ID_CHARS = 16          # how much of a node id a line carries


class Trace:
    """A ring of protocol events plus per-type totals. Off until started.

    ``record`` sits on the hot path of every packet in and out, so it does the
    least possible work: one bounds check, one tuple, one dict update. When the
    trace is off it is a single attribute test and a return."""

    def __init__(self) -> None:
        self.enabled = False
        self._events: deque = deque(maxlen=DEFAULT_EVENTS)
        self._totals: OrderedDict = OrderedDict()
        self._started_at: float = 0.0
        self._ended_at: float = 0.0
        self._stops_at: float = 0.0
        self._dropped = 0
        self._name_of = {}

    # -- lifecycle ---------------------------------------------------------

    def start(self, *, seconds: float = DEFAULT_SECONDS,
              events: int = DEFAULT_EVENTS, names=None) -> dict:
        """Begin recording. Always bounded in both time and size.

        A trace that runs until someone remembers to stop it is a leak with a
        friendly name, so there is no way to ask for an unbounded one."""
        seconds = max(1.0, min(float(seconds or DEFAULT_SECONDS), MAX_SECONDS))
        events = max(100, min(int(events or DEFAULT_EVENTS), MAX_EVENTS))
        self._events = deque(maxlen=events)
        self._totals = OrderedDict()
        self._dropped = 0
        self._name_of = dict(names or {})
        self._started_at = time.time()
        self._ended_at = 0.0
        self._stops_at = time.monotonic() + seconds
        self.enabled = True
        return self.status()

    def stop(self) -> dict:
        """Stop recording. What was captured stays available to read."""
        if self.enabled and not self._ended_at:
            self._ended_at = time.time()
        self.enabled = False
        return self.status()

    def clear(self) -> None:
        self._events.clear()
        self._totals.clear()
        self._dropped = 0

    def _expired(self) -> bool:
        return self.enabled and time.monotonic() >= self._stops_at

    # -- recording ---------------------------------------------------------

    def record(self, direction: str, packet, nbytes: int, peer_id=None) -> None:
        """One packet crossed the wire. Never raises: a trace must not be able
        to take down the link it is watching."""
        if not self.enabled:
            return
        try:
            if self._expired():
                self.stop()
                return
            kind = packet.type
            key = (direction, kind)
            entry = self._totals.get(key)
            if entry is None:
                if len(self._totals) >= 512:      # bounded even under garbage
                    self._dropped += 1
                    return
                entry = [0, 0]
                self._totals[key] = entry
            entry[0] += 1
            entry[1] += nbytes
            if len(self._events) == self._events.maxlen:
                self._dropped += 1
            self._events.append((
                time.time(), direction, kind, nbytes, packet.ttl,
                _short(peer_id), _short(packet.src_id), _short(packet.dst_id)))
        except Exception:
            # Including a packet with fields we did not expect. Losing a trace
            # line is nothing; losing the receive loop is a security bug.
            self._dropped += 1

    # -- reading -----------------------------------------------------------

    def name(self, kind: int) -> str:
        return self._name_of.get(kind, f"0x{kind:02x}")

    def status(self) -> dict:
        running = self.enabled and not self._expired()
        if self.enabled and not running:
            self.stop()
        return {
            "running": running,
            "events": len(self._events),
            "capacity": self._events.maxlen,
            "dropped": self._dropped,
            "started_at": self._started_at or None,
            "seconds_left": (max(0.0, self._stops_at - time.monotonic())
                             if running else 0.0),
        }

    def summary(self) -> dict:
        """Totals by message type — the part that usually answers the question.

        Sorted by bytes, because "what is filling this link" is almost always a
        question about volume rather than about how many packets there were."""
        window = self._window()
        rows = []
        for (direction, kind), (count, nbytes) in self._totals.items():
            rows.append({
                "direction": direction,
                "type": self.name(kind),
                "packets": count,
                "bytes": nbytes,
                "bytes_per_second": round(nbytes / window, 1) if window else 0.0,
            })
        rows.sort(key=lambda row: row["bytes"], reverse=True)
        total_in = sum(r["bytes"] for r in rows if r["direction"] == "in")
        total_out = sum(r["bytes"] for r in rows if r["direction"] == "out")
        return {
            "window_seconds": round(window, 1),
            "rows": rows,
            "bytes_in": total_in,
            "bytes_out": total_out,
            "bits_per_second": round((total_in + total_out) * 8 / window, 0)
                               if window else 0.0,
        }

    def _window(self) -> float:
        """Seconds the recording actually covered, never zero.

        The wall time from start to stop, **not** the span between the first and
        last event: a 30-second trace holding a half-second burst is describing
        half a second of traffic in thirty, and dividing by the burst would
        report a rate the link never sustained."""
        if not self._started_at:
            return 1.0
        end = self._ended_at or time.time()
        return max(1e-6, end - self._started_at)

    def events(self, limit: int = 500, offset: int = 0) -> list:
        """The most recent events, newest first, as plain dicts."""
        limit = max(1, min(int(limit), 2000))
        offset = max(0, int(offset))
        ordered = list(self._events)[::-1]
        return [{
            "at": round(at, 4),
            "direction": direction,
            "type": self.name(kind),
            "bytes": nbytes,
            "ttl": ttl,
            "peer": peer,
            "src": src,
            "dst": dst,
        } for (at, direction, kind, nbytes, ttl, peer, src, dst)
            in ordered[offset:offset + limit]]

    def export(self) -> dict:
        """Everything held, as one JSON-serialisable document."""
        return {
            "format": "nmesh-trace-1",
            "note": "Routing metadata only — no payload is ever recorded.",
            "status": self.status(),
            "summary": self.summary(),
            "events": self.events(limit=2000),
        }

    def write(self, path: str) -> str:
        """Save the trace to a file, readable only by the node's own account.

        A trace names who this node talks to and when. It goes to disk only
        because an operator asked, and never wider than 0600."""
        text = json.dumps(self.export(), indent=1)
        tmp = path + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(text)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
        return path


def _short(raw) -> str:
    """A node id as a readable prefix. Never the whole thing: a trace is read,
    not used to address anyone."""
    if not raw:
        return ""
    try:
        if isinstance(raw, (bytes, bytearray)):
            return bytes(raw).hex()[:_ID_CHARS]
        return str(getattr(raw, "raw", raw).hex()[:_ID_CHARS])
    except Exception:
        return ""
