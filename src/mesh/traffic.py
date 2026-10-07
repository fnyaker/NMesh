"""
What an app says its traffic to one node needs: delivered fast, or carried in
bulk.

A node cannot tell a call from a file by looking at it — both are encrypted
DATA to the same peer — and the two want opposite things from a link. A call
wants a lost packet back before it is a gap, and no reordering; a file wants
the most bytes a long path will carry, and does not mind waiting a round trip
for a loss. Doing either for everybody costs the other, so neither is done
unless an app asks for it, per target, for a while.

Same shape as `mlo.py` and `behaviour.py`: no links, no sockets, no node. It
holds who declared what, for how long, and answers what one target's traffic
needs right now. The node turns that into link settings (`medium.set_profile`)
and into a sending choice (no striping for realtime traffic).

Bounded three ways, because every entry is something an app can ask for: a
lifetime (`MAX_TTL`, renewed by declaring again), a number of targets per app,
and a number of targets in all. A full table refuses, it never evicts: one app
must not be able to push another's declaration out.
"""
from __future__ import annotations

REALTIME = "realtime"
BULK = "bulk"
PROFILES = (REALTIME, BULK)

DEFAULT_TTL = 60.0
MAX_TTL = 600.0
MAX_PER_APP = 64
MAX_TARGETS = 256


class TrafficProfiles:
    """``target -> {app_id: (profile, expires_at)}``."""

    def __init__(self) -> None:
        self._held: dict[bytes, dict[bytes, tuple[str, float]]] = {}

    def __bool__(self) -> bool:
        return bool(self._held)

    def declare(self, app_id: bytes, target: bytes, profile: str | None,
                ttl: float, now: float) -> bool:
        """Hold ``profile`` for ``app_id``'s traffic to ``target`` for ``ttl``
        seconds (clamped to `MAX_TTL`), or drop it with ``profile=None``.
        False when refused: an unknown profile, or a table already full."""
        if profile is None:
            entries = self._held.get(target)
            if entries is not None:
                entries.pop(app_id, None)
                if not entries:
                    del self._held[target]
            return True
        if profile not in PROFILES:
            return False
        ttl = min(max(float(ttl), 1.0), MAX_TTL) if ttl and ttl > 0 else DEFAULT_TTL
        self.expire(now)
        entries = self._held.get(target)
        if entries is None or app_id not in entries:
            if entries is None and len(self._held) >= MAX_TARGETS:
                return False
            if self._count(app_id) >= MAX_PER_APP:
                return False
        self._held.setdefault(target, {})[app_id] = (profile, now + ttl)
        return True

    def forget_app(self, app_id: bytes) -> None:
        """Everything one app declared, at once — it has gone."""
        for target in list(self._held):
            self.declare(app_id, target, None, 0.0, 0.0)

    def expire(self, now: float) -> bool:
        """Drop what has run out; True if anything did."""
        changed = False
        for target in list(self._held):
            entries = self._held[target]
            for app_id in [a for a, (_p, until) in entries.items() if until <= now]:
                del entries[app_id]
                changed = True
            if not entries:
                del self._held[target]
        return changed

    def of(self, target: bytes) -> frozenset:
        """What traffic to ``target`` needs: a set of `PROFILES`."""
        entries = self._held.get(target)
        if not entries:
            return frozenset()
        return frozenset(profile for profile, _until in entries.values())

    def realtime(self, target: bytes) -> bool:
        """The send path's question, without building a set."""
        entries = self._held.get(target)
        return bool(entries) and any(p == REALTIME for p, _u in entries.values())

    def targets(self) -> list[bytes]:
        return list(self._held)

    def view(self, now: float) -> list[dict]:
        """For an operator: who asked what, and for how much longer."""
        return [{"node": target.hex(), "app": app_id.hex(), "profile": profile,
                 "expires_in": round(max(0.0, until - now), 1)}
                for target, entries in self._held.items()
                for app_id, (profile, until) in entries.items()]

    def _count(self, app_id: bytes) -> int:
        return sum(1 for entries in self._held.values() if app_id in entries)
