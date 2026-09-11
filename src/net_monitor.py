"""
Network monitor — keeps the node's view of its own addressing fresh.

The IP transports (tcp://, udp://) advertise addresses that can change under
our feet: DHCP renewal, roaming to another network, VPN up/down, suspend and
resume, carrier NAT rebinding. This monitor re-checks the local address set
cheaply on a short timer, and re-runs the expensive discoveries (public IP
over HTTPS, STUN reflexive address) when a *trigger* suggests they may have
changed:

- the local IP set changed (interface up/down, new network),
- a wall-clock jump versus the monotonic clock (suspend/resume),
- an explicit poke from the node (peer connected/lost, a peer observed us at
  an unknown address, a listener was added) — and an **urgent** one, for the
  caller that does not merely suspect our addressing moved but has evidence of
  it (links to several nodes lost at once): it swaps the ordinary rate limit
  for a shorter floor of its own rather than removing one,
- or a periodic full refresh as a fallback.

All probe functions are injected so the monitor is testable without touching
the network. Everything is bounded: pokes coalesce into a single flag, full
checks are rate-limited (a hostile peer flapping its connection cannot make
us hammer STUN/HTTP services), and a failing probe never kills the loop.
"""
from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable

_CHECK_INTERVAL = 15.0       # cheap local checks (no network traffic)
_FULL_INTERVAL = 300.0       # unconditional full refresh fallback
_MIN_FULL_GAP = 30.0         # rate limit between two full (network) checks
# The same limit for a poke that carries evidence. Shorter, never absent: what
# triggers an urgent poke is still something a peer can cause (see
# `node._note_loss_burst`), so removing the bound would hand a peer flapping
# its link a STUN request and an HTTPS fetch per flap.
_MIN_URGENT_GAP = 10.0
_CLOCK_JUMP = 5.0            # wall-vs-monotonic drift treated as suspend/resume
_MAX_REASONS = 8             # last trigger reasons kept for the console


class NetMonitor:
    """Watches local/public addressing and re-verifies it on triggers."""

    def __init__(self,
                 probe_local_ips: Callable[[], list[str]],
                 probe_public_ip: Callable[[], Awaitable[str | None]],
                 probe_stun: Callable[[], Awaitable[tuple[str, int] | None]],
                 on_change: Callable[[dict, dict], None] | None = None,
                 *,
                 check_interval: float = _CHECK_INTERVAL,
                 full_interval: float = _FULL_INTERVAL,
                 min_full_gap: float = _MIN_FULL_GAP,
                 min_urgent_gap: float = _MIN_URGENT_GAP) -> None:
        self._probe_local_ips = probe_local_ips
        self._probe_public_ip = probe_public_ip
        self._probe_stun = probe_stun
        self._on_change = on_change
        self._check_interval = check_interval
        self._full_interval = full_interval
        self._min_full_gap = min_full_gap
        self._min_urgent_gap = min(min_urgent_gap, min_full_gap)

        self.local_ips: list[str] = []
        self.public_ip: str | None = None
        self.stun_addr: tuple[str, int] | None = None
        self.internet: bool | None = None   # None = not yet checked
        self.last_check: float | None = None       # wall clock, cheap check
        self.last_full_check: float | None = None  # wall clock, network check
        self.checks: int = 0
        self.full_checks: int = 0
        self.reasons: list[tuple[float, str]] = []  # (wall time, reason)

        self._poke = asyncio.Event()
        self._urgent = False
        self._task: asyncio.Task | None = None
        self._closed = False
        self._last_full_mono: float = 0.0
        self._last_mono = time.monotonic()
        self._last_wall = time.time()

    # -- lifecycle ----------------------------------------------------------

    def start(self) -> None:
        if self._task is None:
            self._task = asyncio.create_task(self._loop())

    async def stop(self) -> None:
        self._closed = True
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):
                pass
            self._task = None

    # -- triggers -----------------------------------------------------------

    def poke(self, reason: str, *, urgent: bool = False) -> None:
        """Ask for a re-check soon. Coalesced and rate-limited internally.

        ``urgent`` is for a caller with evidence rather than a suspicion: the
        network probes then run against `_MIN_URGENT_GAP` instead of
        `_MIN_FULL_GAP`. It shortens a bound, it never lifts one — the whole
        reason the ordinary gap exists is that pokes are reachable from what a
        peer does."""
        self._note_reason(reason)
        if urgent:
            self._urgent = True
        self._poke.set()

    def _note_reason(self, reason: str) -> None:
        self.reasons.append((time.time(), reason))
        del self.reasons[:-_MAX_REASONS]

    # -- main loop ----------------------------------------------------------

    async def _loop(self) -> None:
        # First pass runs immediately so the node advertises a public address
        # as soon as possible after start.
        while not self._closed:
            try:
                await self._check()
            except Exception:
                pass  # a broken probe must never kill the monitor
            try:
                await asyncio.wait_for(self._poke.wait(), self._check_interval)
            except asyncio.TimeoutError:
                pass

    async def _check(self) -> None:
        self._poke.clear()
        # Read and consume before anything can await: an urgent poke that lands
        # during this pass must arm the *next* one rather than be swallowed by
        # a check that had already decided what it was doing.
        urgent = self._urgent
        self._urgent = False
        now_mono = time.monotonic()
        self.checks += 1
        self.last_check = time.time()

        reasons: list[str] = []

        # Suspend/resume or clock change: wall time moved differently from
        # the monotonic clock since the previous pass.
        wall_delta = time.time() - self._last_wall
        mono_delta = now_mono - self._last_mono
        if abs(wall_delta - mono_delta) > _CLOCK_JUMP:
            reasons.append("clock-jump")
            self._note_reason("clock-jump")
        self._last_mono = now_mono
        self._last_wall = time.time()

        # Cheap local check — no packets on the wire.
        try:
            ips = list(self._probe_local_ips())
        except Exception:
            ips = self.local_ips
        changes: dict[str, tuple] = {}
        if ips != self.local_ips:
            changes["local_ips"] = (self.local_ips, ips)
            self.local_ips = ips
            reasons.append("local-ips-changed")
            self._note_reason("local-ips-changed")

        if self.reasons and self._poke_pending_since_full():
            reasons.append("poked")
        if urgent:
            reasons.append("urgent")

        due = (self.last_full_check is None
               or now_mono - self._last_full_mono >= self._full_interval)
        gap = self._min_urgent_gap if urgent else self._min_full_gap
        allowed = now_mono - self._last_full_mono >= gap
        if due or (reasons and allowed):
            await self._full_check(changes)

        if changes and self._on_change is not None:
            try:
                self._on_change(self.status(), changes)
            except Exception:
                pass

    def _poke_pending_since_full(self) -> bool:
        if self.last_full_check is None:
            return True
        return any(t > self.last_full_check for t, _ in self.reasons)

    async def _full_check(self, changes: dict) -> None:
        """Network probes: public IP over HTTPS and STUN reflexive address."""
        self._last_full_mono = time.monotonic()
        self.last_full_check = time.time()
        self.full_checks += 1

        public_ip: str | None = None
        stun_addr: tuple[str, int] | None = None
        try:
            public_ip = await self._probe_public_ip()
        except Exception:
            public_ip = None
        try:
            stun_addr = await self._probe_stun()
        except Exception:
            stun_addr = None

        internet = public_ip is not None or stun_addr is not None
        if internet != self.internet:
            changes["internet"] = (self.internet, internet)
            self.internet = internet
        # Only overwrite a known address with a *different* discovered one;
        # a transient probe failure keeps the last known value (stale but
        # flagged by its age in status()).
        if public_ip is not None and public_ip != self.public_ip:
            changes["public_ip"] = (self.public_ip, public_ip)
            self.public_ip = public_ip
        if stun_addr is not None and stun_addr != self.stun_addr:
            changes["stun_addr"] = (self.stun_addr, stun_addr)
            self.stun_addr = stun_addr

    # -- reporting ----------------------------------------------------------

    def status(self) -> dict:
        """JSON-serialisable snapshot for the console."""
        now = time.time()
        return {
            "local_ips": list(self.local_ips),
            "public_ip": self.public_ip,
            "stun_addr": (f"{self.stun_addr[0]}:{self.stun_addr[1]}"
                          if self.stun_addr else None),
            "internet": self.internet,
            "last_check_age": (now - self.last_check
                               if self.last_check is not None else None),
            "last_full_check_age": (now - self.last_full_check
                                    if self.last_full_check is not None else None),
            "checks": self.checks,
            "full_checks": self.full_checks,
            "triggers": [{"age": now - t, "reason": r}
                         for t, r in reversed(self.reasons)],
        }
