"""
Application channel — how apps share the mesh's end-to-end DATA plane safely.

The E2E DATA payload is a single opaque byte string as far as the node is
concerned (see ``node.send_data`` / ``receive_data``). To let *several* apps run
on one node without reading each other's traffic, every application message is
framed with an **app id** that names its section:

    E2E DATA payload  =  app_id(APP_ID_LEN)  ‖  app_payload

The secure app connector (:mod:`src.data_connector`) is the only place that adds
and strips this frame: each connected app declares its app id and receives *only*
messages whose section matches. Management traffic (PING/PONG, routing, DHT,
handshakes) never travels on the DATA plane at all — it uses distinct packet
types — so it is structurally outside every app section.

Two kinds of app id, both ``APP_ID_LEN`` bytes:

  - **built-in** apps shipped with the node use a reserved, name-derived id
    (``builtin_id``). They need no signature — the code is in-tree.
  - **deployed** apps fetched from the mesh are bound to their author's ML-DSA
    key (``deployed_id``); their packages are signed (see
    :mod:`src.app_package`) so the binding can be verified before install.

The two namespaces are domain-separated, so a deployed app can never claim a
built-in's section.
"""
from __future__ import annotations

import hashlib

APP_ID_LEN = 8

_BUILTIN_DOMAIN = b"nmesh.builtin."
_DEPLOYED_DOMAIN = b"nmesh.deployed."


def builtin_id(name: str) -> bytes:
    """Reserved app id for a built-in (in-tree) app. Deterministic per name."""
    return hashlib.sha256(_BUILTIN_DOMAIN + name.encode("utf-8")).digest()[:APP_ID_LEN]


def deployed_id(author_pub: bytes, name: str) -> bytes:
    """App id for a deployed app, bound to its author's DSA public key + name.
    Stable across versions; unforgeable without the author's key."""
    h = hashlib.sha256()
    h.update(_DEPLOYED_DOMAIN)
    h.update(len(author_pub).to_bytes(4, "big"))
    h.update(author_pub)
    h.update(name.encode("utf-8"))
    return h.digest()[:APP_ID_LEN]


def frame(app_id: bytes, payload: bytes) -> bytes:
    """Prefix a payload with its section's app id. ``app_id`` must be exact."""
    if len(app_id) != APP_ID_LEN:
        raise ValueError("app_id must be APP_ID_LEN bytes")
    return app_id + payload


def unframe(data: bytes) -> tuple[bytes, bytes] | None:
    """Split ``app_id ‖ payload``. Returns None for anything too short to carry
    a section header — the caller drops it (reject by default)."""
    if len(data) < APP_ID_LEN:
        return None
    return data[:APP_ID_LEN], data[APP_ID_LEN:]


# Reserved ids for the apps shipped with the node.
CHAT_APP_ID = builtin_id("chat")
# Default section for a connector client that declares none (ad-hoc / demos).
GENERIC_APP_ID = builtin_id("generic")
