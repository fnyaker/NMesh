"""
``veil://`` — TCP with nothing on the wire that is the same twice.

A plain ``tcp://`` link opens with a fixed pattern (the listener speaks first,
and its first packet carries a version byte and a run of ``0xff``), which a
censor can match without breaking anything and a prober can confirm by
connecting. This medium removes both:

* **The dialler speaks first, and what it says is indistinguishable from random
  bytes**: a 16-byte salt, a 16-byte tag proving it holds the key, then
  ChaCha20 over a random amount of padding. Everything after is the same stream
  cipher over the ordinary TCP framing, so lengths are hidden too.
* **A listener answers only a hello that proves the key.** Anything else — a
  scanner, a browser, a replayed hello, a hello from a clock five minutes off —
  gets nothing back: the connection is read and discarded for a random time and
  then closed, which is what a port with nothing behind it looks like to a
  prober that is waiting for a banner.

The key is a shared secret of the circle of nodes that use it, set in the
medium's settings. It is a *network-wide* secret: any node that holds it can
recognise the traffic, so it hides the mesh from a censor that does not, not
from the mesh. It does not replace the node-to-node authentication and
encryption, which still run inside.
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import os
import struct
import time

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .contract import option
from .tcp import TCPServer, TCPTransport, _host_port
from ..ip_utils import wait_closed_bounded

SALT = 16
TAG = 16
# The hello's tag covers the minute it was made in, and a listener accepts this
# many minutes either side: wide enough for a phone's clock, narrow enough that
# a captured hello is dead soon after.
CLOCK_WINDOW = 5
MAX_PADDING = 512
MIN_KEY = 12
# The handshake as a whole, each way.
HELLO_TIMEOUT = 10.0
# What a connection that failed the hello is read for before it is let go, and
# how many of those are held at once. Beyond the bound a new one is closed.
SILENCE_MIN, SILENCE_MAX = 10.0, 40.0
SILENCE_READ_MAX = 64 * 1024
MAX_SILENT = 128
# Valid hellos remembered, so a captured one cannot be played again inside its
# window. Only a hello that proved the key is stored, so it cannot be filled by
# somebody who does not hold it.
MAX_SEEN = 4096


def _stream(key: bytes, salt: bytes, direction: bytes):
    material = HKDF(algorithm=hashes.SHA256(), length=48, salt=salt,
                    info=b"nmesh veil " + direction).derive(key)
    return Cipher(algorithms.ChaCha20(material[:32], material[32:48]), mode=None).encryptor()


def _tag(key: bytes, salt: bytes, minute: int) -> bytes:
    return hmac.new(key, b"hello" + salt + struct.pack("!Q", minute), hashlib.sha256).digest()[:TAG]


def _minute() -> int:
    return int(time.time() // 60)


def _clean_key(value) -> bytes:
    text = str(value or "").strip()
    if len(text) < MIN_KEY:
        raise ConnectionError(f"veil needs a key of at least {MIN_KEY} characters")
    return text.encode("utf-8")


class _SealedReader:
    def __init__(self, reader: asyncio.StreamReader, cipher) -> None:
        self._reader, self._cipher = reader, cipher

    async def readexactly(self, count: int) -> bytes:
        return self._cipher.update(await self._reader.readexactly(count))


class _SealedWriter:
    """The writer a :class:`TCPTransport` expects, with a stream cipher in front
    of it. Everything it does not change is the real writer's."""

    def __init__(self, writer: asyncio.StreamWriter, cipher) -> None:
        self._writer, self._cipher = writer, cipher
        self.transport = writer.transport

    def write(self, data: bytes) -> None:
        self._writer.write(self._cipher.update(bytes(data)))

    def writelines(self, parts) -> None:
        # One update for the whole frame: the cipher is a stream and must see
        # the bytes in the order they go out.
        self._writer.write(self._cipher.update(b"".join(parts)))

    def __getattr__(self, name):
        return getattr(self._writer, name)


def _padding() -> bytes:
    count = int.from_bytes(os.urandom(2), "big") % (MAX_PADDING + 1)
    return struct.pack("!H", count) + os.urandom(count)


async def _dial_hello(reader, writer, key: bytes):
    salt = os.urandom(SALT)
    out, back = _stream(key, salt, b"c2s"), _stream(key, salt, b"s2c")
    writer.write(salt + _tag(key, salt, _minute()) + out.update(_padding()))
    await writer.drain()
    sealed_in = _SealedReader(reader, back)
    count = struct.unpack("!H", await sealed_in.readexactly(2))[0]
    if count > MAX_PADDING:
        raise ConnectionError("the listener did not answer as a veil does")
    await sealed_in.readexactly(count)
    return sealed_in, _SealedWriter(writer, out)


class VeilTransport(TCPTransport):
    SCHEME = "veil"

    OPTIONS = TCPTransport.OPTIONS + (
        option("key", "text", "",
               "The secret every node of this circle shares. Anyone holding it "
               "can recognise the traffic; nobody else can tell it from random "
               f"bytes. At least {MIN_KEY} characters, the same on both ends.",
               placeholder="a long phrase"),
    )
    SETTINGS: dict = {}
    _DEFAULTS = None

    async def connect(self, address: str) -> None:
        key = _clean_key(self.setting("key"))
        await super().connect(address)
        reader, writer = self._reader, self._writer
        try:
            async with asyncio.timeout(HELLO_TIMEOUT):
                self._reader, self._writer = await _dial_hello(reader, writer, key)
        except BaseException:
            writer.close()
            self._reader = self._writer = None
            raise
        self._apply_nodelay()


class VeilServer(TCPServer):
    def __init__(self) -> None:
        super().__init__()
        self._seen: dict[bytes, float] = {}
        self._unproven = 0

    async def listen(self, address: str) -> None:
        host, port = _host_port(address)
        _clean_key(VeilTransport.setting("key"))       # refuse to listen without one

        async def _accept(reader, writer):
            # Held from the first byte until the key is proved or the
            # connection is let go: the wait for a hello costs as much as the
            # silence after a bad one.
            if self._unproven >= MAX_SILENT:
                writer.close()
                return
            self._unproven += 1
            try:
                sealed = await self._hello(reader, writer)
                if sealed is None:
                    await self._stay_silent(reader, writer)
                    return
            finally:
                self._unproven -= 1
            transport = VeilTransport._from_accepted(*sealed)
            if self.on_new_connection is not None:
                await self.on_new_connection(transport)

        self._server = await asyncio.start_server(_accept, host, port, reuse_address=True)

    def _fresh(self, salt: bytes) -> bool:
        now = time.monotonic()
        if len(self._seen) >= MAX_SEEN:
            for old in [s for s, until in self._seen.items() if until < now]:
                del self._seen[old]
            while len(self._seen) >= MAX_SEEN:
                self._seen.pop(next(iter(self._seen)))
        if salt in self._seen:
            return False
        self._seen[salt] = now + 2 * (CLOCK_WINDOW + 1) * 60
        return True

    async def _hello(self, reader, writer):
        try:
            key = _clean_key(VeilTransport.setting("key"))     # read now: it can change
            async with asyncio.timeout(HELLO_TIMEOUT):
                head = await reader.readexactly(SALT + TAG)
                salt, tag = head[:SALT], head[SALT:]
                now = _minute()
                proven = False
                for minute in range(now - CLOCK_WINDOW, now + CLOCK_WINDOW + 1):
                    # No early exit: how long this takes must not say which
                    # minute matched.
                    proven |= hmac.compare_digest(tag, _tag(key, salt, minute))
                if not proven or not self._fresh(salt):
                    return None
                incoming = _SealedReader(reader, _stream(key, salt, b"c2s"))
                count = struct.unpack("!H", await incoming.readexactly(2))[0]
                if count > MAX_PADDING:
                    return None
                await incoming.readexactly(count)
                sealed = _SealedWriter(writer, _stream(key, salt, b"s2c"))
                sealed.write(_padding())
                await writer.drain()
                return incoming, sealed
        except (asyncio.TimeoutError, asyncio.IncompleteReadError, OSError, ConnectionError):
            return None

    async def _stay_silent(self, reader, writer) -> None:
        """What a closed-mouthed port does: read, say nothing, hang up later."""
        try:
            hold = SILENCE_MIN + (SILENCE_MAX - SILENCE_MIN) * (
                int.from_bytes(os.urandom(2), "big") / 65535)
            taken = 0
            try:
                async with asyncio.timeout(hold):
                    while taken < SILENCE_READ_MAX:
                        chunk = await reader.read(4096)
                        if not chunk:
                            break
                        taken += len(chunk)
            except (asyncio.TimeoutError, OSError):
                pass
        finally:
            writer.close()

    def reachability(self, uri: str, ctx: dict) -> list[dict]:
        from ..ip_utils import ip_reachability
        return ip_reachability(
            "veil", uri, ctx.get("local_ips", []), ctx.get("public_addrs", []),
            "veil" in ctx.get("inbound_schemes", ()),
            "veil" in ctx.get("public_schemes", ()))

    async def close(self) -> None:
        if self._server:
            self._server.close()
            await wait_closed_bounded(self._server)
