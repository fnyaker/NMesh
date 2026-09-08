"""
Lightweight node metrics — throughput counters and process load.

Everything here is stdlib-only and O(1) on the hot path: sending or receiving a
packet bumps a couple of integer counters, nothing more. The web console reads
cumulative counters and computes rates client-side, so the node keeps no rolling
windows in memory.
"""
import os
import time
from collections import OrderedDict, deque


class Counters:
    """Cumulative packet / byte counters. Plain ints, cheap to bump."""

    __slots__ = ("pkts_in", "pkts_out", "bytes_in", "bytes_out", "dropped",
                 "pkts_relayed", "bytes_relayed")

    def __init__(self) -> None:
        self.pkts_in = 0
        self.pkts_out = 0
        self.bytes_in = 0
        self.bytes_out = 0
        # Of what went out, how much was carried for somebody else. A *subset*
        # of `bytes_out`, never a separate total — the name says whose traffic
        # it is, not which direction. Relaying is the one thing a node spends
        # its bandwidth on with nothing of its own to show for it, and it was
        # indistinguishable from its own traffic in every number on screen.
        self.pkts_relayed = 0
        self.bytes_relayed = 0
        # Payloads a bound refused. A drop is not a failure to hide: it is the
        # only honest thing a full queue can do, and an operator watching this
        # climb is watching a consumer that cannot keep up.
        self.dropped = 0

    def on_in(self, nbytes: int) -> None:
        self.pkts_in += 1
        self.bytes_in += nbytes

    def on_out(self, nbytes: int) -> None:
        self.pkts_out += 1
        self.bytes_out += nbytes

    def on_drop(self) -> None:
        self.dropped += 1

    def on_relay(self, nbytes: int) -> None:
        """One packet forwarded for another node. `on_out` has already counted
        it; this says who it was for."""
        self.pkts_relayed += 1
        self.bytes_relayed += nbytes

    def as_dict(self) -> dict:
        return {
            "pkts_in": self.pkts_in,
            "pkts_out": self.pkts_out,
            "bytes_in": self.bytes_in,
            "bytes_out": self.bytes_out,
            "dropped": self.dropped,
            "pkts_relayed": self.pkts_relayed,
            "bytes_relayed": self.bytes_relayed,
        }


class LinkQuality:
    """What a link *feels* like: latency, its spread, and what got lost.

    One RTT number says almost nothing — a link at a steady 40 ms and one
    flapping between 5 and 400 ms average the same. So the last few samples are
    kept (bounded, tiny) and reduced to the four figures an operator actually
    reads: last, best, worst, and jitter. Loss is counted separately, because a
    probe that never comes back has no round trip to average.

    Loss is counted two ways because they answer different questions. The
    lifetime share (`loss`) is what an operator reads. The run of probes since
    the last answer (`since_pong`) is what decides whether the link is still a
    link: a link that carried traffic for an hour and then died never shows a
    high lifetime share — a thousand good probes outvote the dead ones — so the
    ratio alone can never notice that it stopped answering.

    A third reading sits beside those two, and it exists because neither of
    them can answer "is this link fit to carry half of somebody's traffic right
    now" (see `mlo.py`). The lifetime share is a whole history and moves too
    slowly; the run since the last answer only ever separates *dead* from
    alive. So the last :data:`WINDOW` probes are also kept as **outcomes** —
    each one answered, with its round trip, or lost — and `recent_loss` /
    `recent_ms` read that window. One ring, so a link's probe history has one
    home: a second book kept beside this one is a second number that can
    disagree with it.

    Matching an answer to *its own* probe is what makes the window honest.
    ``on_ping``/``on_pong`` keep only the latest probe, which is right at a
    twenty-second cadence and useless at a hundred milliseconds: with several
    probes in flight, every answer but one arrives unmatched. ``sent`` and
    ``answered`` take a token the peer echoes, so each probe is resolved
    individually — and one that is never resolved is charged as a loss by
    ``expire`` rather than left pending for ever.

    Every method is O(1) and called at most once per liveness probe, never on
    the packet path."""

    __slots__ = ("_samples", "pings", "pongs", "last", "since_pong",
                 "answered_at", "_window", "_pending")

    HISTORY = 32
    #: Probes the *recent* window is judged over. Fifty, because that is the
    #: sample MLO's skew and drop share are defined on — one number, stated
    #: once, so the console and the bundle cannot read two different windows.
    WINDOW = 50
    #: Probes that may be in flight at once on one link. At a 100 ms cadence
    #: and a deadline of a few seconds a healthy link holds a handful; this is
    #: the bound that keeps a link answering nothing from growing the table.
    MAX_PENDING = 64

    def __init__(self) -> None:
        self._samples: deque = deque(maxlen=self.HISTORY)
        self.pings = 0
        self.pongs = 0
        self.last: float | None = None
        self.since_pong = 0
        # When this link last answered anything, monotonic. The run above says
        # how many probes went unanswered; only a clock says how *long* that
        # is, and once a cadence is negotiable those two stopped being the same
        # question (see `node._reap_silent_links`). Starts at the link's birth:
        # a link that has never answered has been silent since it opened, which
        # is exactly what we want to measure.
        self.answered_at = time.monotonic()
        # Outcome per probe: the round trip, or None for one that never came
        # back. Bounded by construction.
        self._window: deque = deque(maxlen=self.WINDOW)
        # token -> when it went out. Insertion order is time order, so expiry
        # stops at the first probe still young enough.
        self._pending: OrderedDict = OrderedDict()

    def on_ping(self) -> None:
        self.pings += 1
        self.since_pong += 1

    def on_pong(self, rtt: float) -> None:
        self.pongs += 1
        self.since_pong = 0
        self.answered_at = time.monotonic()
        self.last = rtt
        self._samples.append(rtt)

    def on_answer(self) -> None:
        """A probe came back too late to be timed.

        Once the next probe has gone out there is no round trip left to
        measure — but the answer is still proof the link carries traffic both
        ways, and the whole point of the run is to tell a slow link from a dead
        one. Counting it as silence would cut the slow one."""
        self.pongs += 1
        self.since_pong = 0
        self.answered_at = time.monotonic()

    # -- probes matched to their own answer -------------------------------

    def sent(self, token, at: float) -> None:
        """One probe went out, under a token the peer will echo back."""
        self.on_ping()
        self._pending[token] = at
        while len(self._pending) > self.MAX_PENDING:
            # Overtaken by that many later probes: whatever happened to it, it
            # is not coming back in time to mean anything.
            self._pending.popitem(last=False)
            self._window.append(None)

    def answered(self, token, at: float) -> float | None:
        """A probe came back. Returns its round trip, or ``None`` when the
        answer matched no probe still in flight.

        An unmatched answer is not a fault and never a loss: it is a probe this
        link already gave up on, or a peer too old to echo the token. It is
        still proof the link carries traffic both ways, so it resets the
        silence run exactly as a matched one does."""
        sent_at = self._pending.pop(token, None) if token is not None else None
        if sent_at is None:
            self.on_answer()
            return None
        rtt = max(0.0, at - sent_at)
        self.on_pong(rtt)
        self._window.append(rtt)
        return rtt

    def expire(self, now: float, after: float) -> int:
        """Charge every probe older than ``after`` as lost. Returns how many.

        Without this a probe nobody answers stays pending for ever and the
        window never learns that the link is losing anything — the loss would
        only ever show up as an *absence* of samples, which reads as a quiet
        link rather than a broken one."""
        lost = 0
        for token, at in list(self._pending.items()):
            if now - at <= after:
                break          # insertion order is time order
            del self._pending[token]
            self._window.append(None)
            lost += 1
        return lost

    def recent_ms(self) -> float | None:
        """Mean round trip over the recent window, in milliseconds.

        ``None`` while the window holds no answered probe — an unmeasured link
        is unmeasured, never zero."""
        answered = [rtt for rtt in self._window if rtt is not None]
        if not answered:
            return None
        return sum(answered) / len(answered) * 1000.0

    def recent_loss(self, minimum: int = 2) -> float | None:
        """Share of the recent window that never came back, 0..1.

        ``None`` below ``minimum`` outcomes: a link with two probes behind it
        has not proved anything either way, and treating that as zero loss is
        how an unproven link gets handed half of somebody's traffic."""
        if len(self._window) < max(1, int(minimum)):
            return None
        lost = sum(1 for rtt in self._window if rtt is None)
        return lost / len(self._window)

    def recent_probes(self) -> int:
        """How many outcomes the recent window actually holds."""
        return len(self._window)

    def in_flight(self) -> int:
        return len(self._pending)

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
            "unanswered": self.since_pong,
            "samples_ms": [ms(value) for value in samples],
            # The window MLO judges on, named for what it is so it can never be
            # read as the lifetime figure above it.
            "recent_ms": (None if self.recent_ms() is None
                          else round(self.recent_ms(), 1)),
            "recent_loss": (None if self.recent_loss() is None
                            else round(self.recent_loss(), 3)),
            "recent_probes": self.recent_probes(),
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
