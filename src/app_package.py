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
