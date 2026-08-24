"""
The console credential: hashing it, storing it, checking it.

Split out of ``webconsole.py`` so the installer's password-reset script can use
exactly the same code without importing the mesh node (and, with it, liboqs).
One implementation of how a console password is stored — a second one that
drifted would be a silent authentication bug.

The password itself is never stored: only a scrypt hash and its salt. The file
is created 0600 from the first byte rather than tightened afterwards, because
"afterwards" is a window in which anyone on the machine can read it.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets

FILENAME = "console.cred"

# scrypt, not a plain hash: the console password is typed by a human and is the
# only thing between the network and a node's management surface.
SCRYPT = dict(n=16384, r=8, p=1, dklen=32)

# Long enough to be worth the scrypt work, short enough that hashing it can
# never become the attack. A generated one sits comfortably between the two.
MIN_LENGTH = 12
MAX_LENGTH = 256
GENERATED_BYTES = 18


class CredentialError(Exception):
    """A password that cannot be used, phrased for whoever typed it."""


def path_for(state_dir: str | None) -> str | None:
    return os.path.join(state_dir, FILENAME) if state_dir else None


def generate() -> str:
    """A password nobody has to invent, and nobody will reuse elsewhere."""
    return secrets.token_urlsafe(GENERATED_BYTES)


def hash_password(password: str, salt: bytes) -> bytes:
    return hashlib.scrypt(password.encode("utf-8"), salt=salt, **SCRYPT)


def check(password: str, salt: bytes, expected: bytes) -> bool:
    """Constant-time — the comparison must not leak how much of it matched."""
    if not isinstance(password, str):
        return False
    if len(password) > MAX_LENGTH:
        # Refused before hashing: scrypt on an unbounded input is the cheapest
        # denial of service there is, and no real password is this long.
        return False
    return hmac.compare_digest(hash_password(password, salt), expected)


def validate(password) -> str:
    """Check a password a human just chose. Raises ``CredentialError``."""
    if not isinstance(password, str):
        raise CredentialError("the password must be text")
    if len(password) < MIN_LENGTH:
        raise CredentialError(f"at least {MIN_LENGTH} characters, please")
    if len(password) > MAX_LENGTH:
        raise CredentialError(f"at most {MAX_LENGTH} characters")
    if password.strip() != password:
        # A leading or trailing space is invisible in a form and impossible to
        # debug later. Refuse it rather than store a password nobody can retype.
        raise CredentialError("no leading or trailing whitespace")
    return password


def read(path: str | None):
    """``(salt, hash)`` for a stored credential, or ``None``."""
    if not path or not os.path.exists(path):
        return None
    try:
        with open(path) as handle:
            tag, salt_hex, hash_hex = handle.read(4096).strip().split("$")
        if tag != "scrypt":
            return None
        return bytes.fromhex(salt_hex), bytes.fromhex(hash_hex)
    except Exception:
        return None          # unreadable or corrupt — the caller regenerates


def write(path: str, password: str) -> tuple[bytes, bytes]:
    """Store ``password``'s hash atomically, readable only by its owner."""
    salt = secrets.token_bytes(16)
    digest = hash_password(password, salt)
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w") as handle:
            handle.write(f"scrypt${salt.hex()}${digest.hex()}")
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)
    return salt, digest
