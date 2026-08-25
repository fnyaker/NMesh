"""
Lightweight node metrics — throughput counters and process load.

Everything here is stdlib-only and O(1) on the hot path: sending or receiving a
packet bumps a couple of integer counters, nothing more. The web console reads
cumulative counters and computes rates client-side, so the node keeps no rolling
windows in memory.
"""
import os
import time
from collections import deque


class Counters:
    """Cumulative packet / byte counters. Plain ints, cheap to bump."""

    __slots__ = ("pkts_in", "pkts_out", "bytes_in", "bytes_out")

    def __init__(self) -> None:
        self.pkts_in = 0
        self.pkts_out = 0
        self.bytes_in = 0
        self.bytes_out = 0

    def on_in(self, nbytes: int) -> None:
        self.pkts_in += 1
        self.bytes_in += nbytes

    def on_out(self, nbytes: int) -> None:
        self.pkts_out += 1
        self.bytes_out += nbytes

    def as_dict(self) -> dict:
        return {
            "pkts_in": self.pkts_in,
            "pkts_out": self.pkts_out,
            "bytes_in": self.bytes_in,
            "bytes_out": self.bytes_out,
        }


class LinkQuality:
    """What a link *feels* like: latency, its spread, and what got lost.

    One RTT number says almost nothing — a link at a steady 40 ms and one
    flapping between 5 and 400 ms average the same. So the last few samples are
    kept (bounded, tiny) and reduced to the four figures an operator actually
    reads: last, best, worst, and jitter. Loss is counted separately, because a
    probe that never comes back has no round trip to average.

    Every method is O(1) and called at most once per liveness probe, never on
    the packet path."""

    __slots__ = ("_samples", "pings", "pongs", "last")

    HISTORY = 32

    def __init__(self) -> None:
        self._samples: deque = deque(maxlen=self.HISTORY)
        self.pings = 0
        self.pongs = 0
        self.last: float | None = None

    def on_ping(self) -> None:
        self.pings += 1

    def on_pong(self, rtt: float) -> None:
        self.pongs += 1
        self.last = rtt
        self._samples.append(rtt)

    @property
    def samples(self) -> list:
        return list(self._samples)

    def jitter(self) -> float | None:
        """Mean absolute difference between consecutive samples (RFC 3550's
        idea, without its smoothing): how *unsteady* the link is."""
        if len(self._samples) < 2:
            return None
        pairs = zip(self._samples, list(self._samples)[1:])
        gaps = [abs(after - before) for before, after in pairs]
        return sum(gaps) / len(gaps)

    def loss(self) -> float | None:
        """Share of probes that never came back, 0..1. ``None`` until a probe
        has had time to fail — one ping in flight is not 100% loss."""
        if self.pings < 2:
            return None
        return max(0.0, min(1.0, (self.pings - self.pongs) / self.pings))

    def as_dict(self) -> dict:
        def ms(value):
            return None if value is None else round(value * 1000, 1)
        samples = self._samples
        return {
            "rtt_ms": ms(self.last),
            "best_ms": ms(min(samples)) if samples else None,
            "worst_ms": ms(max(samples)) if samples else None,
            "avg_ms": ms(sum(samples) / len(samples)) if samples else None,
            "jitter_ms": ms(self.jitter()),
            "loss": None if self.loss() is None else round(self.loss(), 3),
            "probes": self.pings,
            "samples_ms": [ms(value) for value in samples],
        }


class NodeMetrics:
    """Node-wide counters plus a process-load probe."""

    def __init__(self) -> None:
        self.started_at = time.time()
        self.total = Counters()
        self._page_size = 0
        try:
            self._page_size = os.sysconf("SC_PAGE_SIZE")
        except (ValueError, OSError, AttributeError):
            self._page_size = 4096
        self._last_cpu = self._proc_cpu_seconds()
        self._last_cpu_wall = time.time()

    def uptime(self) -> float:
        return time.time() - self.started_at

    # -- process load, Linux /proc, no external deps ----------------------

    def _proc_cpu_seconds(self) -> float | None:
        try:
            t = os.times()
            return t.user + t.system + t.children_user + t.children_system
        except Exception:
            return None

    def rss_bytes(self) -> int | None:
        """Resident set size from /proc/self/statm (Linux). None elsewhere."""
        try:
            with open("/proc/self/statm") as f:
                fields = f.read().split()
            return int(fields[1]) * self._page_size
        except Exception:
            return None

    def cpu_percent(self) -> float | None:
        """CPU used since the previous call, as a percentage of one core."""
        now_cpu = self._proc_cpu_seconds()
        now_wall = time.time()
        if now_cpu is None or self._last_cpu is None:
            return None
        dw = now_wall - self._last_cpu_wall
        dc = now_cpu - self._last_cpu
        self._last_cpu = now_cpu
        self._last_cpu_wall = now_wall
        if dw <= 0:
            return None
        return max(0.0, min(100.0 * dc / dw, 100.0 * (os.cpu_count() or 1)))

    def load(self) -> dict:
        return {
            "rss_bytes": self.rss_bytes(),
            "cpu_percent": self.cpu_percent(),
            "cpu_count": os.cpu_count(),
        }
