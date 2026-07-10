"""
Store-and-forward primitives — a portable bundle container.

Delay/disruption-tolerant networking: the two endpoints of a link are never
online at the same time. The medium is a file physically carried from one node
to another ("clé USB fixée à un pigeon"). A ``Bundle`` packs many packets into
one integrity-checked file — the thing you copy onto the removable medium.

Security model (see CLAUDE.md): the medium is hostile territory. Every packet
inside a bundle is already end-to-end encrypted and authenticated by the mesh,
so the carrier can neither read nor forge them; the node's hardened receive path
already drops any malformed/forged packet. The bundle adds a SHA-256 over the
whole container so truncation or tampering on the medium is *detected and
rejected* rather than fed in as garbage. No confidentiality or authenticity is
claimed for the container itself — that lives at the packet layer.
"""
from __future__ import annotations

import hashlib
import os
import struct

_MAGIC = b"NMSHBNDL"
_VERSION = 1
# magic(8) | version(1) | reserved(3) | count(4)
_HEADER = struct.Struct("!8sB3xI")
_REC_LEN = struct.Struct("!I")
_DIGEST_LEN = 32
_MAX_PACKET = 65_535           # a framed packet never exceeds the TCP frame cap
_MAX_PACKETS = 1_000_000       # hard ceiling on packets per bundle
_MAX_BUNDLE = 256 * 1024 * 1024  # 256 MiB ceiling — bounded, no OOM on garbage


class BundleError(Exception):
    pass


class Bundle:
    """A batch of packets serialised into one integrity-checked blob."""

    @staticmethod
    def pack(packets: list[bytes]) -> bytes:
        if len(packets) > _MAX_PACKETS:
            raise BundleError("too many packets for one bundle")
        parts = [_HEADER.pack(_MAGIC, _VERSION, len(packets))]
        for p in packets:
            if len(p) > _MAX_PACKET:
                raise BundleError("packet too large for bundle")
            parts.append(_REC_LEN.pack(len(p)))
            parts.append(p)
        body = b"".join(parts)
        return body + hashlib.sha256(body).digest()

    @staticmethod
    def unpack(data: bytes) -> list[bytes]:
        """Return the list of framed packet blobs. Raises BundleError on any
        structural problem, truncation, or checksum mismatch."""
        if len(data) > _MAX_BUNDLE:
            raise BundleError("bundle exceeds size ceiling")
        if len(data) < _HEADER.size + _DIGEST_LEN:
            raise BundleError("bundle too short")
        magic, version, count = _HEADER.unpack_from(data, 0)
        if magic != _MAGIC:
            raise BundleError("bad magic")
        if version != _VERSION:
            raise BundleError(f"unsupported version {version}")
        if count > _MAX_PACKETS:
            raise BundleError("declared packet count too large")

        body = data[:-_DIGEST_LEN]
        digest = data[-_DIGEST_LEN:]
        if hashlib.sha256(body).digest() != digest:
            raise BundleError("checksum mismatch — bundle corrupt or tampered")

        packets: list[bytes] = []
        offset = _HEADER.size
        end = len(body)
        for _ in range(count):
            if offset + _REC_LEN.size > end:
                raise BundleError("truncated record length")
            (plen,) = _REC_LEN.unpack_from(body, offset)
            offset += _REC_LEN.size
            if plen > _MAX_PACKET:
                raise BundleError("record length exceeds packet cap")
            if offset + plen > end:
                raise BundleError("truncated record body")
            packets.append(body[offset:offset + plen])
            offset += plen
        if offset != end:
            raise BundleError("trailing garbage after declared records")
        return packets


def write_bundle(path: str, packets: list[bytes]) -> None:
    """Atomically write a bundle file (temp + fsync + rename)."""
    data = Bundle.pack(packets)
    tmp = f"{path}.tmp.{os.getpid()}"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, path)
    # fsync the directory so the rename is durable across power loss.
    try:
        dfd = os.open(os.path.dirname(path) or ".", os.O_DIRECTORY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    except (OSError, AttributeError):
        pass


def read_bundle(path: str) -> list[bytes]:
    with open(path, "rb") as f:
        return Bundle.unpack(f.read())
