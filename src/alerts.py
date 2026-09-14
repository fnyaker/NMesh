"""
Problems worth a person's attention, and nothing else.

A log says everything; an alert says *this one matters*. They are not the same
thing and one is not a filter over the other: a log is off until an operator
turns it on, and a node that has just refused three hundred handshakes should be
able to say so on a console that nobody had the foresight to start recording.

So this is small, always on, and deliberately poorer than a log:

**One entry per problem, not per occurrence.** Entries are keyed, and a repeat
bumps a count and a timestamp rather than adding a row. Three hundred refused
handshakes are one line reading "three hundred", which is the sentence an
operator can act on — and it is also what keeps a flood from turning a console
into a scrolling wall an attacker chose the contents of.

**Bounded, and the *worst* survives.** `MAX_ALERTS` entries; when full, the
oldest of the least severe goes first. A book that evicted by age alone would
let a chatty warning push out the one error on the page.

**Never a reason to act on its own.** An alert is a sentence for a human, so
nothing here cuts a peer off, changes a setting or writes to disk. What acts on
a peer is the reputation book, which is fed by what *we saw*
(`src/reputation.py`); this is the notice board beside it.

Who raises one: the node itself for the handful of conditions it can be certain
about, and an app through the connector — an app knows what "too many failed
uploads" means for itself, exactly as it knows what abuse means for itself
(`report_abuse`). An app's notice is attributed to it by the node, never by the
app, so one cannot post as another or as the core.
"""
from __future__ import annotations

import threading
import time

# Entries held at once. Small on purpose: this is a notice board, and one nobody
# can read to the bottom of is one nobody reads.
MAX_ALERTS = 64

# One entry, bounded on every axis a caller supplies.
MAX_SUMMARY = 160
MAX_DETAIL = 400
MAX_SOURCE = 64
MAX_KEY = 96

WARN, ERROR = "warn", "error"
LEVELS = (WARN, ERROR)
_RANK = {WARN: 0, ERROR: 1}


def clean_level(raw) -> str:
    text = str(raw or "").strip().lower()
    return text if text in _RANK else WARN


class AlertBook:
    """What is wrong here, as a human would want it said. Always on.

    Touched from the node's loop, from the console's threads and from whatever
    thread an app's connector runs on, so everything takes the lock. Nothing in
    here blocks: the whole book is a bounded dict."""

    def __init__(self, *, clock=time.time) -> None:
        self._clock = clock
        self._lock = threading.Lock()
        self._alerts: dict[str, dict] = {}
        self._seq = 0

    def raise_alert(self, key: str, summary: str, *, level: str = WARN,
                    source: str = "node", node: str = "",
                    detail: str = "") -> dict | None:
        """Say that something is wrong. **Never raises.**

        Called from receive loops and from handlers, like `LogBook.record` and
        for the same reason: a diagnostic that can break what it is diagnosing
        is worse than none."""
        try:
            name = str(key or summary or "")[:MAX_KEY]
            if not name:
                return None
            now = self._clock()
            with self._lock:
                entry = self._alerts.get(name)
                if entry is None:
                    self._seq += 1
                    entry = self._alerts[name] = {
                        "key": name, "seq": self._seq, "first": now,
                        "count": 0, "acknowledged": False,
                    }
                entry.update({
                    "level": clean_level(level),
                    "source": str(source or "node")[:MAX_SOURCE],
                    "node": str(node or "")[:40],
                    "summary": str(summary or "")[:MAX_SUMMARY],
                    "detail": str(detail or "")[:MAX_DETAIL],
                    "at": now,
                })
                entry["count"] += 1
                # A problem that has come back is news again, whatever somebody
                # decided about it last time.
                entry["acknowledged"] = False
                self._evict()
                return dict(entry)
        except Exception:               # noqa: BLE001 — never the reason
            return None

    def _evict(self) -> None:
        """Under the lock. The least severe, oldest entry goes first — never
        simply the oldest, or one chatty warning empties the board of errors."""
        while len(self._alerts) > MAX_ALERTS:
            victim = min(self._alerts.values(),
                         key=lambda entry: (_RANK.get(entry["level"], 0),
                                            not entry["acknowledged"],
                                            entry["at"]))
            self._alerts.pop(victim["key"], None)

    def acknowledge(self, key: str) -> bool:
        """A person has seen this. It stays on the board — an operator who wants
        to know whether a thing is still happening is asking about its count,
        not about whether anybody dismissed it — but it stops being unread."""
        with self._lock:
            entry = self._alerts.get(str(key or "")[:MAX_KEY])
            if entry is None:
                return False
            entry["acknowledged"] = True
            return True

    def drop(self, key: str = "") -> int:
        """Forget one alert, or all of them. What raised it will raise it
        again if it is still true, which is the point of forgetting being
        allowed at all."""
        with self._lock:
            if not key:
                count = len(self._alerts)
                self._alerts.clear()
                return count
            return 1 if self._alerts.pop(str(key)[:MAX_KEY], None) else 0

    def alerts(self, *, unacknowledged: bool = False) -> list[dict]:
        """Worst first, then newest. The order a person reads them in."""
        with self._lock:
            rows = [dict(entry) for entry in self._alerts.values()
                    if not unacknowledged or not entry["acknowledged"]]
        rows.sort(key=lambda entry: (-_RANK.get(entry["level"], 0),
                                     -(entry["at"] or 0)))
        return rows

    def status(self) -> dict:
        rows = self.alerts()
        return {
            "alerts": rows,
            "count": len(rows),
            "unread": sum(1 for row in rows if not row["acknowledged"]),
            "worst": rows[0]["level"] if rows else "",
            "max": MAX_ALERTS,
        }
