"""
Lightweight node metrics — throughput counters and process load.

Everything here is stdlib-only and O(1) on the hot path: sending or receiving a
packet bumps a couple of integer counters, nothing more. The web console reads
cumulative counters and computes rates client-side, so the node keeps no rolling
windows in memory.
"""
import os
import time


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
