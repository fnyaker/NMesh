"""
Content-addressed application packages.

An app is a set of files bundled into a package that can be published on the DHT
and fetched by other nodes. Everything is content-addressed:

  - each file is split into chunks; a chunk's key is ``sha256(chunk)[:20]``.
  - the manifest lists, per file, its size, full SHA-256, and ordered chunk keys.
  - the package id is ``sha256(manifest)[:20]``.

This is what makes sharing safe over an untrusted network (see CLAUDE.md): you
ask for a key and verify that what comes back hashes to it, so a relay or a
malicious peer cannot substitute tampered content. No trust in the sender is
required — only the hash.
"""
from __future__ import annotations

import hashlib
import json

from .app_channel import APP_ID_LEN, deployed_id

CHUNK_SIZE = 49_152            # 48 KiB — comfortably under the 60 KB payload cap
KEY_LEN = 20
_MAX_FILES = 4096
_MAX_CHUNKS_PER_FILE = 1_000_000
_MAX_TOTAL_BYTES = 512 * 1024 * 1024   # ceiling on a reassembled package


class AppPackageError(Exception):
    pass


def content_key(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()[:KEY_LEN]


def build(name: str, version: str, files: dict[str, bytes]):
    """Return (app_id, manifest_bytes, chunks) where chunks maps key -> bytes.

    The returned pieces are exactly what must be published on the DHT: every
    chunk value, plus the manifest itself (keyed by app_id)."""
    if len(files) > _MAX_FILES:
        raise AppPackageError("too many files")
    chunks: dict[bytes, bytes] = {}
    file_entries = []
    for path, content in files.items():
        chunk_keys = []
        for off in range(0, len(content), CHUNK_SIZE):
            piece = content[off:off + CHUNK_SIZE]
            k = content_key(piece)
            chunks[k] = piece
            chunk_keys.append(k.hex())
        file_entries.append({
            "path": path,
            "size": len(content),
            "sha256": hashlib.sha256(content).hexdigest(),
            "chunks": chunk_keys,
        })
    manifest = {"name": name, "version": version, "files": file_entries}
    manifest_bytes = json.dumps(manifest, sort_keys=True).encode("utf-8")
    return content_key(manifest_bytes), manifest_bytes, chunks


def parse_manifest(data: bytes) -> dict:
    """Parse and structurally validate a manifest. Raises AppPackageError."""
    try:
        doc = json.loads(data.decode("utf-8"))
    except Exception as exc:
        raise AppPackageError(f"manifest not valid JSON: {exc}") from exc
    if not isinstance(doc, dict):
        raise AppPackageError("manifest is not an object")
    if not isinstance(doc.get("name"), str) or not isinstance(doc.get("version"), str):
        raise AppPackageError("manifest missing name/version")
    files = doc.get("files")
    if not isinstance(files, list) or len(files) > _MAX_FILES:
        raise AppPackageError("manifest files invalid")
    for fe in files:
        if not isinstance(fe, dict):
            raise AppPackageError("file entry not an object")
        if not isinstance(fe.get("path"), str):
            raise AppPackageError("file path invalid")
        if not isinstance(fe.get("size"), int) or fe["size"] < 0:
            raise AppPackageError("file size invalid")
        if not isinstance(fe.get("sha256"), str) or len(fe["sha256"]) != 64:
            raise AppPackageError("file sha256 invalid")
        ck = fe.get("chunks")
        if not isinstance(ck, list) or len(ck) > _MAX_CHUNKS_PER_FILE:
            raise AppPackageError("file chunks invalid")
        for h in ck:
            if not isinstance(h, str) or len(h) != KEY_LEN * 2:
                raise AppPackageError("chunk key invalid")
    return doc


def chunk_keys(manifest: dict) -> list[bytes]:
    """All chunk keys referenced by a parsed manifest (deduplicated, ordered)."""
    seen: dict[bytes, None] = {}
    for fe in manifest["files"]:
        for h in fe["chunks"]:
            seen.setdefault(bytes.fromhex(h), None)
    return list(seen.keys())


def _chunk_blob(data: bytes) -> tuple[dict[bytes, bytes], list[str]]:
    chunks: dict[bytes, bytes] = {}
    keys: list[str] = []
    for off in range(0, len(data), CHUNK_SIZE):
        piece = data[off:off + CHUNK_SIZE]
        k = content_key(piece)
        chunks[k] = piece
        keys.append(k.hex())
    return chunks, keys


def pack_root(manifest_bytes: bytes) -> tuple[bytes, dict[bytes, bytes]]:
    """Chunk the manifest itself and return (root_bytes, manifest_chunks).

    The root is a small descriptor listing the manifest's chunk keys, so the
    manifest is no longer bounded by a single DHT value — a package can have
    arbitrarily many files. The app id is ``content_key(root_bytes)``."""
    chunks, keys = _chunk_blob(manifest_bytes)
    root = {
        "v": 1,
        "size": len(manifest_bytes),
        "sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "chunks": keys,
    }
    return json.dumps(root, sort_keys=True).encode("utf-8"), chunks


def parse_root(data: bytes) -> dict:
    try:
        doc = json.loads(data.decode("utf-8"))
    except Exception as exc:
        raise AppPackageError(f"root not valid JSON: {exc}") from exc
    if not isinstance(doc, dict) or doc.get("v") != 1:
        raise AppPackageError("bad root")
    if not isinstance(doc.get("size"), int) or not 0 <= doc["size"] <= _MAX_TOTAL_BYTES:
        raise AppPackageError("bad root size")
    if not isinstance(doc.get("sha256"), str) or len(doc["sha256"]) != 64:
        raise AppPackageError("bad root sha256")
    ck = doc.get("chunks")
    if not isinstance(ck, list) or len(ck) > _MAX_CHUNKS_PER_FILE:
        raise AppPackageError("bad root chunks")
    for h in ck:
        if not isinstance(h, str) or len(h) != KEY_LEN * 2:
            raise AppPackageError("bad root chunk key")
    return doc


def reassemble_bytes(size: int, sha256_hex: str, chunk_key_hexes: list[str],
                     get_chunk) -> bytes:
    """Rebuild a blob from content-addressed chunks, verifying each chunk and
    the whole. Raises AppPackageError on any mismatch or missing piece."""
    parts = []
    total = 0
    for h in chunk_key_hexes:
        key = bytes.fromhex(h)
        chunk = get_chunk(key)
        if chunk is None:
            raise AppPackageError(f"missing chunk {h}")
        if content_key(chunk) != key:
            raise AppPackageError(f"chunk {h} fails its hash")
        total += len(chunk)
        if total > _MAX_TOTAL_BYTES:
            raise AppPackageError("blob exceeds size ceiling")
        parts.append(chunk)
    data = b"".join(parts)
    if len(data) != size or hashlib.sha256(data).hexdigest() != sha256_hex:
        raise AppPackageError("reassembled blob fails its hash")
    return data


# ---------------------------------------------------------------------------
# Signed release descriptor — the defined way to deploy an app.
#
# Content addressing (above) makes the *bytes* verifiable: ask for a key, check
# the hash. It says nothing about *who* published them. A release descriptor
# binds a content root to an author's ML-DSA identity: the author signs it, and
# the runtime app id is derived from the author key + name so it cannot be
# claimed by anyone else. Built-in apps skip this entirely (in-tree, reserved id).
# ---------------------------------------------------------------------------

_RELEASE_DOMAIN = b"nmesh-app-release-v1"
_RELEASE_KEYS = ("v", "name", "version", "root_key", "root_sha256", "author", "app_id")


def _release_signing_input(body: dict) -> bytes:
    return _RELEASE_DOMAIN + json.dumps(
        {k: body[k] for k in _RELEASE_KEYS}, sort_keys=True).encode("utf-8")


def build_release(root_key: bytes, root_sha256: str, name: str, version: str,
                  author_pub: bytes, sign) -> tuple[bytes, bytes]:
    """Build a signed release descriptor binding a content root to its author.

    ``sign(message) -> signature`` signs with the author's ML-DSA identity.
    Returns ``(release_bytes, app_id)``. The descriptor is a small JSON blob,
    itself content-addressable (publish it on the DHT like any other value)."""
    app_id = deployed_id(author_pub, name)
    body = {
        "v": 1,
        "name": name,
        "version": version,
        "root_key": root_key.hex(),
        "root_sha256": root_sha256,
        "author": author_pub.hex(),
        "app_id": app_id.hex(),
    }
    body["sig"] = sign(_release_signing_input(body)).hex()
    return json.dumps(body, sort_keys=True).encode("utf-8"), app_id


def parse_release(data: bytes, verify) -> dict:
    """Parse and cryptographically verify a release descriptor.

    ``verify(message, signature, public_key) -> bool``. Every gate rejects by
    default: bad JSON, missing/oversized fields, an app id not bound to the
    author key, or a failed signature all raise ``AppPackageError``. Returns the
    validated descriptor with ``root_key`` / ``app_id`` / ``author`` as bytes."""
    try:
        doc = json.loads(data.decode("utf-8"))
    except Exception as exc:
        raise AppPackageError(f"release not valid JSON: {exc}") from exc
    if not isinstance(doc, dict) or doc.get("v") != 1:
        raise AppPackageError("bad release")
    for k in ("name", "version", "root_key", "root_sha256", "author", "app_id", "sig"):
        if not isinstance(doc.get(k), str):
            raise AppPackageError(f"release field {k} invalid")
    if len(doc["name"]) > 512 or len(doc["version"]) > 64:
        raise AppPackageError("release name/version too long")
    try:
        root_key = bytes.fromhex(doc["root_key"])
        author = bytes.fromhex(doc["author"])
        app_id = bytes.fromhex(doc["app_id"])
        sig = bytes.fromhex(doc["sig"])
    except ValueError as exc:
        raise AppPackageError("release hex field invalid") from exc
    if len(root_key) != KEY_LEN or len(doc["root_sha256"]) != 64:
        raise AppPackageError("release root reference invalid")
    if len(app_id) != APP_ID_LEN or app_id != deployed_id(author, doc["name"]):
        raise AppPackageError("app id not bound to author")
    if not verify(_release_signing_input(doc), sig, author):
        raise AppPackageError("release signature invalid")
    doc["root_key"] = root_key
    doc["author"] = author
    doc["app_id"] = app_id
    return doc


def reassemble(manifest: dict, get_chunk) -> dict[str, bytes]:
    """Rebuild {path: content} from a manifest, fetching chunks via
    ``get_chunk(key) -> bytes | None``. Every chunk and every file is verified
    against its hash; any mismatch or missing piece raises AppPackageError."""
    out: dict[str, bytes] = {}
    total = 0
    for fe in manifest["files"]:
        parts = []
        for h in fe["chunks"]:
            key = bytes.fromhex(h)
            chunk = get_chunk(key)
            if chunk is None:
                raise AppPackageError(f"missing chunk {h}")
            if content_key(chunk) != key:
                raise AppPackageError(f"chunk {h} fails its hash")
            total += len(chunk)
            if total > _MAX_TOTAL_BYTES:
                raise AppPackageError("package exceeds size ceiling")
            parts.append(chunk)
        data = b"".join(parts)
        if len(data) != fe["size"]:
            raise AppPackageError(f"file {fe['path']} wrong size")
        if hashlib.sha256(data).hexdigest() != fe["sha256"]:
            raise AppPackageError(f"file {fe['path']} fails its hash")
        out[fe["path"]] = data
    return out
