import hmac
import hashlib
import os
import secrets
import string
import time as _time_module

_ALPHABET     = string.ascii_letters + string.digits
_CODE_TTL     = 300  # 5 minutes — a human typing a code into another console
_MAX_TTL      = 6 * 3600
_MAX_FAILURES = 3
_LOCKOUT_TTL  = 60


def time() -> float:
    return _time_module.time()


def compute_response(code: str, challenge: bytes) -> bytes:
    return hmac.new(code.encode(), challenge, hashlib.sha256).digest()


class InviteManager:
    """
    Manages a pool of active invitation codes.
    Several codes can be live at once (for star networks).
    """

    def __init__(self) -> None:
        # code -> (creation timestamp, TTL). The TTL is per code: an invitation
        # typed by hand lives 5 minutes, while one left on a machine being
        # provisioned has to survive the dependency install (tens of minutes)
        # before that machine starts and uses it.
        self._codes: dict[str, tuple[float, float]] = {}
        self._failures: int = 0
        self._lockout_ts: float = 0.0

    def generate_code(self, ttl: float | None = None) -> str:
        """Issue a code. ``ttl`` (seconds) is bounded: widening the window is
        an explicit choice by the caller, never unlimited. The code stays single
        use, and the anti-bruteforce lockout applies whatever the TTL."""
        window = _CODE_TTL if ttl is None else max(1.0, min(float(ttl), _MAX_TTL))
        code = ''.join(secrets.choice(_ALPHABET) for _ in range(10))
        self._codes[code] = (time(), window)
        return code

    def generate_seeded_code(self, ttl: float | None = None) -> tuple[str, bytes]:
        """Issue a code derived from 8 random bytes, and return both.

        Exactly the same code as ``generate_code`` as far as the protocol is
        concerned — single use, the same lockout, never sent in the clear. The
        only difference is that a join ticket can carry it as 8 bytes instead of
        its characters, which decides the QR code's size."""
        from .join_ticket import SEED_BYTES, code_from_seed
        window = _CODE_TTL if ttl is None else max(1.0, min(float(ttl), _MAX_TTL))
        seed = secrets.token_bytes(SEED_BYTES)
        code = code_from_seed(seed)
        self._codes[code] = (time(), window)
        return code, seed

    def generate_challenge(self) -> bytes:
        return os.urandom(32)

    def live_codes(self) -> list[str]:
        """Codes that have not expired, purging the rest on the way.

        The pool was only ever pruned inside `verify_response`, so expired
        entries accumulated for the life of the process and anything else that
        looked at `_codes` saw them as live."""
        now = time()
        return [code for code in list(self._codes)
                if not self._expire(code, now)]

    def _expire(self, code: str, now: float) -> bool:
        """True (and forgotten) if ``code`` has run out."""
        entry = self._codes.get(code)
        if entry is None:
            return True
        created, window = entry
        if (now - created) > window:
            del self._codes[code]
            return True
        return False

    def has_code(self) -> bool:
        return bool(self.live_codes())

    def consume(self, challenge: bytes | None = None,
                response: bytes | None = None) -> None:
        """Consume the code matching (challenge, response).
        With no arguments, clears every code (legacy use, or a reset)."""
        if challenge is None or response is None:
            self._codes.clear()
            return
        for code in list(self._codes.keys()):
            if hmac.compare_digest(compute_response(code, challenge), response):
                del self._codes[code]
                return

    def record_failure(self) -> None:
        self._failures += 1
        if self._failures >= _MAX_FAILURES:
            self._lockout_ts = time()

    def is_locked_out(self) -> bool:
        if self._failures < _MAX_FAILURES:
            return False
        return (time() - self._lockout_ts) < _LOCKOUT_TTL

    def verify_response(self, challenge: bytes, response: bytes) -> bool:
        if not self._codes:
            return False
        if self.is_locked_out():
            return False
        now = time()
        for code in list(self._codes):
            if self._expire(code, now):
                continue
            if hmac.compare_digest(compute_response(code, challenge), response):
                return True
        return False
