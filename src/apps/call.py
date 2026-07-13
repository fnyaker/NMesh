"""
Audio calls over the mesh — real audio, real time.

NMesh provides the real-time *transport*: PCM audio is framed and streamed over
the chat app's frame channel, with latency measured on arrival. Actual audio
comes from an ``AudioSource`` and goes to an ``AudioSink``. This module ships a
**WAV file** backend using only the stdlib ``wave`` module, so a call is fully
end-to-end and testable with real audio samples, no hardware and no external
dependency.

To use a live microphone/speaker, implement ``AudioSource`` / ``AudioSink`` with
a device backend (e.g. sounddevice) **in your application** — NMesh stays free of
that dependency (charter: minimal deps).

Wire format: each audio frame is one chat "frame". Frame seq 0 carries a header
(magic, sample rate, channels, sample width, samples per frame); frames 1..N
carry raw PCM. On receipt, frames are ordered by seq and written to the sink.
Everything is bounded; a malformed frame is ignored.
"""
from __future__ import annotations

import asyncio
import struct
import wave
from dataclasses import dataclass

from .chat import Frame

_MAGIC = b"NAUD"
_HDR = struct.Struct("!4sIBBI")   # magic | rate | channels | sampwidth | samples/frame
_MAX_FRAMES = 200_000             # per stream, ~1h at 20ms frames — bounded
_MAX_STREAMS = 32


@dataclass(frozen=True)
class AudioFormat:
    rate: int
    channels: int
    sampwidth: int   # bytes per sample (2 = 16-bit PCM)


# ---------------------------------------------------------------------------
# Backends (interface + stdlib WAV implementation)
# ---------------------------------------------------------------------------

class AudioSource:
    """Yields raw PCM frames. `fmt` and `samples_per_frame` describe them."""
    fmt: AudioFormat
    samples_per_frame: int

    def frames(self):
        raise NotImplementedError

    @property
    def frame_ms(self) -> float:
        return 1000.0 * self.samples_per_frame / self.fmt.rate


class AudioSink:
    def set_format(self, fmt: AudioFormat) -> None:
        raise NotImplementedError

    def write(self, pcm: bytes) -> None:
        raise NotImplementedError

    def close(self) -> None:
        raise NotImplementedError


def read_wav(path: str) -> tuple[AudioFormat, bytes]:
    with wave.open(path, "rb") as w:
        fmt = AudioFormat(w.getframerate(), w.getnchannels(), w.getsampwidth())
        pcm = w.readframes(w.getnframes())
    return fmt, pcm


def write_wav(path: str, fmt: AudioFormat, pcm: bytes) -> None:
    with wave.open(path, "wb") as w:
        w.setnchannels(fmt.channels)
        w.setsampwidth(fmt.sampwidth)
        w.setframerate(fmt.rate)
        w.writeframes(pcm)


class WavSource(AudioSource):
    def __init__(self, path: str, frame_ms: float = 20.0) -> None:
        self.fmt, self._pcm = read_wav(path)
        self.samples_per_frame = max(1, int(self.fmt.rate * frame_ms / 1000))
        self._frame_bytes = self.samples_per_frame * self.fmt.channels * self.fmt.sampwidth

    def frames(self):
        for off in range(0, len(self._pcm), self._frame_bytes):
            yield self._pcm[off:off + self._frame_bytes]


class WavSink(AudioSink):
    def __init__(self, path: str) -> None:
        self._path = path
        self._fmt: AudioFormat | None = None
        self._pcm = bytearray()

    def set_format(self, fmt: AudioFormat) -> None:
        self._fmt = fmt

    def write(self, pcm: bytes) -> None:
        self._pcm += pcm

    def close(self) -> None:
        if self._fmt is not None:
            write_wav(self._path, self._fmt, bytes(self._pcm))


# ---------------------------------------------------------------------------
# Header codec
# ---------------------------------------------------------------------------

def encode_header(fmt: AudioFormat, samples_per_frame: int) -> bytes:
    return _HDR.pack(_MAGIC, fmt.rate, fmt.channels, fmt.sampwidth, samples_per_frame)


def decode_header(data: bytes) -> tuple[AudioFormat, int] | None:
    if len(data) < _HDR.size:
        return None
    magic, rate, channels, sampwidth, spf = _HDR.unpack_from(data, 0)
    if magic != _MAGIC or channels < 1 or sampwidth < 1 or rate < 1:
        return None
    return AudioFormat(rate, channels, sampwidth), spf


# ---------------------------------------------------------------------------
# The call
# ---------------------------------------------------------------------------

class _Incoming:
    __slots__ = ("fmt", "frames")

    def __init__(self) -> None:
        self.fmt: AudioFormat | None = None
        self.frames: dict[int, bytes] = {}


class AudioCall:
    """Places and receives audio calls over a ChatApp's frame stream."""

    def __init__(self, chat_app) -> None:
        self._chat = chat_app
        self._streams: dict[tuple[bytes, int], _Incoming] = {}
        self.latencies: list[float] = []   # per received audio frame, ms

    def attach(self) -> None:
        self._chat.add_listener(self._on_event)

    def detach(self) -> None:
        self._chat.remove_listener(self._on_event)

    # -- sending --

    async def place(self, target, source: AudioSource, stream_id: int = 1,
                    pace: bool = True) -> int:
        """Stream `source` to `target`. Returns the number of audio frames sent."""
        await self._chat.send_frame(
            target, stream_id, 0, encode_header(source.fmt, source.samples_per_frame))
        seq = 1
        interval = source.frame_ms / 1000.0
        for frame in source.frames():
            await self._chat.send_frame(target, stream_id, seq, frame)
            seq += 1
            if pace:
                await asyncio.sleep(interval)
        return seq - 1

    # -- receiving --

    def _on_event(self, ev) -> None:
        if not isinstance(ev, Frame):
            return
        key = (ev.src.raw, ev.stream_id)
        buf = self._streams.get(key)
        if buf is None:
            if len(self._streams) >= _MAX_STREAMS:
                return
            buf = self._streams[key] = _Incoming()
        if ev.seq == 0:
            hdr = decode_header(ev.payload)
            if hdr is not None:
                buf.fmt = hdr[0]
        elif len(buf.frames) < _MAX_FRAMES:
            buf.frames[ev.seq] = ev.payload
            if len(self.latencies) < _MAX_FRAMES:
                self.latencies.append(ev.latency_ms)

    def render(self, src, stream_id: int, sink: AudioSink) -> AudioFormat | None:
        """Write the received audio (ordered by seq) to `sink`. Returns the
        format, or None if nothing usable was received."""
        buf = self._streams.get((src.raw, stream_id))
        if buf is None or buf.fmt is None:
            return None
        sink.set_format(buf.fmt)
        for seq in sorted(buf.frames):
            sink.write(buf.frames[seq])
        sink.close()
        return buf.fmt
