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
    Gère un pool de codes d'invitation actifs.
    Supporte plusieurs codes simultanés (pour les réseaux étoile).
    """

    def __init__(self) -> None:
        # code -> (timestamp de création, TTL). Le TTL est par code : une
        # invitation tapée à la main vit 5 minutes, alors qu'une invitation
        # déposée sur une machine en cours de provisioning doit survivre à
        # l'installation des dépendances (plusieurs dizaines de minutes) avant
        # que la machine ne démarre et ne s'en serve.
        self._codes: dict[str, tuple[float, float]] = {}
        self._failures: int = 0
        self._lockout_ts: float = 0.0

    def generate_code(self, ttl: float | None = None) -> str:
        """Émet un code. ``ttl`` (secondes) est borné : allonger la fenêtre est
        un choix explicite de l'appelant, jamais illimité. Le code reste à usage
        unique, et le lockout anti-bruteforce s'applique quel que soit le TTL."""
        window = _CODE_TTL if ttl is None else max(1.0, min(float(ttl), _MAX_TTL))
        code = ''.join(secrets.choice(_ALPHABET) for _ in range(10))
        self._codes[code] = (time(), window)
        return code

    def generate_challenge(self) -> bytes:
        return os.urandom(32)

    def has_code(self) -> bool:
        return bool(self._codes)

    def consume(self, challenge: bytes | None = None,
                response: bytes | None = None) -> None:
        """Consomme le code qui correspond à (challenge, response).
        Sans arguments, vide tous les codes (usage legacy ou reset)."""
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
        for code, (ts, window) in list(self._codes.items()):
            if (time() - ts) > window:
                del self._codes[code]
                continue
            if hmac.compare_digest(compute_response(code, challenge), response):
                return True
        return False
