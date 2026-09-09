"""
A signing key that is not sitting in memory.

The node's identity key has to be loaded: it signs handshakes, certificates and
directory claims continuously, and a mesh node that cannot sign is not a node.
A **publisher** key is the opposite case. It is used a handful of times a year,
it is the key that decides what code every node pinning it will run, and until
now it was the same key — so the most consequential secret in the project was
also the one most exposed, kept unlocked on a machine reachable from the network
it publishes to.

This separates them. A publisher key lives on disk encrypted under a passphrase
and is unlocked only for as long as it takes to sign a release. Nothing in the
running node holds it, and nothing in the running node can be made to.

What the passphrase buys, and what it does not
----------------------------------------------
It buys the case that actually happens: the file is copied. A backup, a stolen
laptop, a misconfigured share, a compromised host read at rest. Against those
the passphrase is the whole defence, which is why the derivation is deliberately
expensive rather than merely correct.

It does not buy anything against an attacker who is present *while you publish*.
At that moment the key is in memory by necessity. Nothing here pretends
otherwise, and an operator who needs that property needs a machine that is not
the node.

Choices, and why
----------------
- **scrypt**, from ``cryptography`` (already a dependency). Memory-hard, so a
  hardware guessing rig gains far less than it would against a hash-only KDF.
  The cost parameters are stored *in the file*: a file written today must still
  open in five years on a build whose defaults have moved, and a KDF whose
  parameters are implied is a KDF that can only ever be tuned once.
- **AES-256-GCM** over the secret key, with the whole header as AAD. The salt,
  the cost parameters and the version are therefore authenticated: an attacker
  who can edit the file cannot weaken the derivation and hand it back, which is
  the attack a header outside the tag invites.
- **The public half is stored in the clear**, and the pair is checked against
  itself on unlock. A publisher needs to be able to say which key it is without
  typing a passphrase, and a mismatched pair would otherwise produce signatures
  nobody can verify with no diagnostic anywhere — the same failure
  ``CryptoIdentity.load`` already refuses.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import struct
import time

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

MAGIC = b"NMPK"
VERSION = 1

# A key is named by the hash of its public half, exactly like a node id and a
# publisher id elsewhere: there is no id to lie about, only a key that does or
# does not produce it.
PUBLISHER_ID_LEN = 20
_HEX_ID = re.compile(r"[0-9a-f]{%d}" % (PUBLISHER_ID_LEN * 2))
_MAX_KEYS = 32             # publisher keys one node may hold
_MAX_LABEL = 64


def publisher_id(public_key: bytes) -> bytes:
    return hashlib.sha256(bytes(public_key)).digest()[:PUBLISHER_ID_LEN]


# scrypt cost. n=2^17, r=8, p=1 is roughly 128 MiB and a fraction of a second —
# chosen so that a laptop notices it once at publish time and a guessing rig
# pays it per attempt. Stored in the file, never assumed (see the module note).
DEFAULT_N = 1 << 17
DEFAULT_R = 8
DEFAULT_P = 1

_SALT_LEN = 16
_NONCE_LEN = 12
_MAX_FILE = 1 << 20        # a key pair is a few kilobytes; this is generous

# magic(4) | version(B) | log2_n(B) | r(H) | p(H) | salt(16) | nonce(12)
# | pub_len(H) | secret_len(H)
_HDR = struct.Struct("!4sBBHH16s12sHH")


class PublisherKeyError(Exception):
    """The key could not be written, read, or unlocked."""


def _derive(passphrase: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    if not isinstance(passphrase, str) or not passphrase:
        raise PublisherKeyError("a passphrase is required")
    try:
        return Scrypt(salt=salt, length=32, n=n, r=r, p=p).derive(
            passphrase.encode("utf-8"))
    except Exception as exc:                     # cost parameters out of range
        raise PublisherKeyError(f"unusable key derivation ({exc})") from None


def save(path: str, public_key: bytes, secret_key: bytes, passphrase: str, *,
         n: int = DEFAULT_N, r: int = DEFAULT_R, p: int = DEFAULT_P) -> None:
    """Write a publisher key, encrypted under ``passphrase``.

    Created 0600 **at open time** — not by a chmod afterwards, which would leave
    a window in which the file could be read. Same rule as the node's identity;
    this one decides what code other people run."""
    if not public_key or not secret_key:
        raise PublisherKeyError("both halves of the key are required")
    if n < 2 or n & (n - 1):
        raise PublisherKeyError("scrypt n must be a power of two")
    salt = os.urandom(_SALT_LEN)
    nonce = os.urandom(_NONCE_LEN)
    header = _HDR.pack(MAGIC, VERSION, n.bit_length() - 1, r, p, salt, nonce,
                       len(public_key), len(secret_key))
    key = _derive(passphrase, salt, n, r, p)
    # The header is the AAD, so the salt and the cost parameters are covered by
    # the tag: an attacker who can edit the file cannot lower the cost and hand
    # it back to be opened cheaply.
    sealed = AESGCM(key).encrypt(nonce, bytes(secret_key), header + public_key)
    blob = header + bytes(public_key) + sealed
    tmp = f"{path}.tmp.{os.getpid()}"
    handle = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(handle, "wb") as stream:
            stream.write(blob)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    os.replace(tmp, path)


def public_of(path: str) -> bytes:
    """The public half, without the passphrase.

    A publisher has to be able to say which key it is — to show an operator, to
    compare against a pin — and needing the secret for that would mean typing
    the passphrase to answer a question that is public by definition."""
    header, public, _sealed = _read(path)
    del header
    return public


def load(path: str, passphrase: str) -> tuple[bytes, bytes]:
    """Unlock and return ``(public_key, secret_key)``.

    A wrong passphrase and a tampered file are the same answer on purpose: GCM
    cannot tell them apart, and pretending to would be inventing a distinction
    the cryptography does not support."""
    header, public, sealed = _read(path)
    _magic, _version, log_n, r, p, salt, nonce, _pub_len, secret_len = \
        _HDR.unpack_from(header, 0)
    key = _derive(passphrase, salt, 1 << log_n, r, p)
    try:
        secret = AESGCM(key).decrypt(nonce, sealed, header + public)
    except Exception:
        raise PublisherKeyError(
            "the passphrase is wrong, or the file has been altered") from None
    if len(secret) != secret_len:
        raise PublisherKeyError("the key file is inconsistent")
    return public, secret


def _read(path: str) -> tuple[bytes, bytes, bytes]:
    """``(header, public_key, sealed_secret)``, treating the file as hostile."""
    try:
        with open(path, "rb") as stream:
            blob = stream.read(_MAX_FILE + 1)
    except FileNotFoundError:
        raise PublisherKeyError(f"{path} does not exist") from None
    except OSError as exc:
        raise PublisherKeyError(f"{path} could not be read ({exc})") from None
    if len(blob) > _MAX_FILE:
        raise PublisherKeyError("the key file is implausibly large")
    if len(blob) < _HDR.size:
        raise PublisherKeyError("the key file is too short")
    magic, version, log_n, r, p, _salt, _nonce, pub_len, secret_len = \
        _HDR.unpack_from(blob, 0)
    if magic != MAGIC:
        raise PublisherKeyError("that is not a publisher key file")
    if version != VERSION:
        raise PublisherKeyError(f"unsupported key file version {version}")
    if not 1 <= log_n <= 22 or not 1 <= r <= 64 or not 1 <= p <= 16:
        raise PublisherKeyError("the key file asks for unusable scrypt costs")
    if not pub_len or not secret_len:
        raise PublisherKeyError("the key file has an empty half")
    end = _HDR.size + pub_len
    if end >= len(blob):
        raise PublisherKeyError("the key file is truncated")
    return blob[:_HDR.size], blob[_HDR.size:end], blob[end:]


# ---------------------------------------------------------------------------
# The keys this node holds
# ---------------------------------------------------------------------------

class KeyStore:
    """A directory of publisher keys, one file per key id.

    Without this a publisher key is a path an operator has to remember and
    retype, which is the ergonomics that made pasting hex keys around normal in
    the first place. A key received from somebody else has no path they chose at
    all, so it needed a home before it could have a name.

    The **files are the truth**: the id of a key is derived from its public half
    (:func:`publisher_id`), so the store is re-read from disk rather than from
    an index that could disagree with it. ``index.json`` beside them carries
    only what the files cannot say — a label, when it arrived, and who handed it
    over — and a corrupt or missing index costs those and nothing else."""

    def __init__(self, directory: str | None = None) -> None:
        self._dir = directory
        if self._dir:
            try:
                os.makedirs(self._dir, mode=0o700, exist_ok=True)
            except OSError:
                self._dir = None          # no store; this node holds no keys

    # -- where things are -------------------------------------------------

    def path_for(self, key_id_hex: str) -> str | None:
        """The file a key id lives in, or None when the id is not one."""
        if not self._dir or not _HEX_ID.fullmatch(key_id_hex or ""):
            return None
        return os.path.join(self._dir, f"{key_id_hex}.key")

    def _index_path(self) -> str | None:
        return os.path.join(self._dir, "index.json") if self._dir else None

    def _index(self) -> dict:
        path = self._index_path()
        if not path:
            return {}
        try:
            with open(path) as handle:
                doc = json.load(handle)
        except (FileNotFoundError, OSError, ValueError):
            return {}
        return doc if isinstance(doc, dict) else {}

    def _write_index(self, index: dict) -> None:
        path = self._index_path()
        if not path:
            return
        tmp = f"{path}.tmp.{os.getpid()}"
        handle = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(handle, "w") as stream:
                json.dump(index, stream)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        os.replace(tmp, path)

    # -- mutation ---------------------------------------------------------

    def put(self, public_key: bytes, secret_key: bytes, passphrase: str, *,
            label: str = "", received_from: str = "", **costs) -> dict:
        """Keep a key, encrypted under ``passphrase``. Returns its row.

        The id is derived from the public half, so a key that arrives twice
        replaces itself rather than accumulating — including under a new
        passphrase, which is how somebody changes one."""
        key_id = publisher_id(public_key).hex()
        path = self.path_for(key_id)
        if path is None:
            raise PublisherKeyError("this node has nowhere to keep a key")
        save(path, public_key, secret_key, passphrase, **costs)
        index = self._index()
        existing = index.get(key_id) or {}
        index[key_id] = {
            "label": str(label or existing.get("label", ""))[:_MAX_LABEL],
            "added": existing.get("added") or int(time.time()),
            "received_from": str(received_from
                                 or existing.get("received_from", ""))[:40],
        }
        while len(index) > _MAX_KEYS:
            index.pop(next(iter(index)))
        self._write_index(index)
        return self.get(key_id) or {}

    def forget(self, key_id_hex: str) -> bool:
        """Delete a key from this machine. It is not recoverable from here —
        which is the point of a store that holds secrets rather than a cache."""
        path = self.path_for(key_id_hex)
        if path is None or not os.path.isfile(path):
            return False
        try:
            os.unlink(path)
        except OSError:
            return False
        index = self._index()
        if index.pop(key_id_hex, None) is not None:
            self._write_index(index)
        return True

    # -- reading ----------------------------------------------------------

    def ids(self) -> list[str]:
        if not self._dir:
            return []
        try:
            names = os.listdir(self._dir)
        except OSError:
            return []
        return sorted(name[:-4] for name in names if name.endswith(".key")
                      and _HEX_ID.fullmatch(name[:-4]))

    def get(self, key_id_hex: str) -> dict | None:
        """One key as a page reads it: id, public half, label, provenance.

        The public half is re-read from the file and the id re-derived from it,
        so a file renamed to somebody else's id answers as what it actually
        is — never as what it is filed under."""
        path = self.path_for(key_id_hex)
        if path is None or not os.path.isfile(path):
            return None
        try:
            public = public_of(path)
        except PublisherKeyError:
            return None
        if publisher_id(public).hex() != key_id_hex:
            return None
        meta = self._index().get(key_id_hex) or {}
        return {
            "id": key_id_hex,
            "key": public.hex(),
            "label": str(meta.get("label", ""))[:_MAX_LABEL],
            "added": int(meta["added"]) if isinstance(meta.get("added"), int)
                     and not isinstance(meta.get("added"), bool) else 0,
            "received_from": str(meta.get("received_from", ""))[:40],
        }

    def list(self) -> list[dict]:
        rows = [row for row in (self.get(key_id) for key_id in self.ids())
                if row is not None]
        rows.sort(key=lambda row: (row["label"].lower(), row["id"]))
        return rows

    def __len__(self) -> int:
        return len(self.ids())
