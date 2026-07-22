"""
Per-app DHT overlay — how an app stores shared entries on the mesh DHT.

The mesh DHT (see :mod:`src.dht`) is strictly content-addressed: a value's key
is its own hash, which is what closes the poisoning vector. This module lets an
app put/get entries on that same store while adding two properties the app needs:

  - **Per-app namespace.** Every value is framed ``app_id ‖ flag ‖ body``. The
    app id is the one the node holds for the authenticated session — the app
    never declares it. Two apps therefore never collide (identical content under
    different apps yields different keys), and a reader only accepts a value
    whose framed app id matches its own: app A can hold app B's key and still
    read nothing of B's.

  - **Public or private.** Public entries are stored in the clear (any instance
    of the *same* app, on any node, reads them — "all nodes"). Private entries
    are encrypted by the node with a key the *app* supplies (AES-256-GCM,
    post-quantum-safe symmetric); only app instances that also hold that key can
    read them. The node does the DHT-level crypto; the app owns the key and its
    distribution across nodes. The app id + flag are the GCM AAD, binding the
    ciphertext to its namespace.

Content addressing is untouched: the framed value is what gets hashed and stored,
so the anti-poisoning guarantee of the underlying store still holds.
"""
from __future__ import annotations

import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .app_channel import APP_ID_LEN
from .dht import MAX_VALUE

FLAG_PUBLIC = 0
FLAG_PRIVATE = 1
_NONCE_LEN = 12
_TAG_LEN = 16
_HEADER = APP_ID_LEN + 1                      # app_id ‖ flag
# Ceiling on the app-supplied content so the framed value fits one DHT value.
MAX_CONTENT = MAX_VALUE - _HEADER - _NONCE_LEN - _TAG_LEN
_VALID_KEY_LENS = (16, 24, 32)


class AppDHTError(Exception):
    pass


def frame(app_id: bytes, content: bytes, enc_key: bytes | None = None) -> bytes:
    """Frame an app entry for the content-addressed DHT.

    ``enc_key is None`` → public (stored in the clear). Otherwise the content is
    encrypted under ``enc_key`` (a 16/24/32-byte AES key). Raises ``AppDHTError``
    on a bad app id, oversized content, or an invalid key length — reject by
    default, never silently truncate."""
    if len(app_id) != APP_ID_LEN:
        raise AppDHTError("bad app id")
    if len(content) > MAX_CONTENT:
        raise AppDHTError("content too large for one DHT value")
    if enc_key is None:
        return app_id + bytes([FLAG_PUBLIC]) + content
    if len(enc_key) not in _VALID_KEY_LENS:
        raise AppDHTError("encryption key must be 16, 24 or 32 bytes")
    header = app_id + bytes([FLAG_PRIVATE])
    nonce = os.urandom(_NONCE_LEN)
    ct = AESGCM(enc_key).encrypt(nonce, content, header)  # header is GCM AAD
    return header + nonce + ct


def read(value: bytes, app_id: bytes, dec_key: bytes | None = None) -> bytes | None:
    """Recover an app entry's content from a framed DHT value.

    Returns the content, or ``None`` if the value is malformed, belongs to a
    different app, or is private and ``dec_key`` is missing/wrong. Never raises
    on hostile input — a bad value simply yields ``None`` (reject by default)."""
    if not isinstance(value, (bytes, bytearray)) or len(value) < _HEADER:
        return None
    if bytes(value[:APP_ID_LEN]) != app_id:
        return None  # not this app's namespace — even if the key was guessed
    flag = value[APP_ID_LEN]
    body = bytes(value[_HEADER:])
    if flag == FLAG_PUBLIC:
        return body
    if flag == FLAG_PRIVATE:
        if dec_key is None or len(dec_key) not in _VALID_KEY_LENS:
            return None
        if len(body) < _NONCE_LEN + _TAG_LEN:
            return None
        nonce, ct = body[:_NONCE_LEN], body[_NONCE_LEN:]
        try:
            return AESGCM(dec_key).decrypt(nonce, ct, bytes(value[:_HEADER]))
        except Exception:
            return None  # wrong key / tampered — reveal nothing
    return None  # unknown flag
