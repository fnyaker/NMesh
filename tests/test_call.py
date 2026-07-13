"""
Audio call tests.

NMesh provides the real-time transport; audio comes from a WAV backend (stdlib
`wave`), so a call is exercised end to end with real PCM samples — no hardware,
no external dependency. Drive one ChatApp's frames into another's dispatcher and
check the received audio reassembles bit-for-bit, plus header codec + fuzzing.
"""
import math
import os
import random
import struct
import tempfile

import pytest

from src.apps.chat import ChatApp, Frame
from src.apps.call import (
    AudioCall, AudioFormat, WavSource, WavSink, read_wav, write_wav,
    encode_header, decode_header,
)
from src.node_id import NodeID

SRC = NodeID(os.urandom(20))
DST = NodeID(os.urandom(20))


class StubClient:
    def __init__(self):
        self.sent = []
    async def send(self, target, payload):
        self.sent.append((target, payload))
    async def recv(self):
        import asyncio
        await asyncio.Event().wait()
    async def close(self):
        pass


def _sine_wav(path, rate=8000, seconds=0.5, freq=440.0):
    n = int(rate * seconds)
    pcm = b"".join(
        struct.pack("<h", int(12000 * math.sin(2 * math.pi * freq * i / rate)))
        for i in range(n)
    )
    write_wav(path, AudioFormat(rate, 1, 2), pcm)


class TestHeaderCodec:
    def test_roundtrip(self):
        fmt = AudioFormat(48000, 2, 2)
        got = decode_header(encode_header(fmt, 960))
        assert got == (fmt, 960)

    def test_garbage_rejected(self):
        assert decode_header(b"") is None
        assert decode_header(b"XXXX" + b"\x00" * 20) is None

    def test_fuzz(self):
        rng = random.Random(0xA0D1)
        for _ in range(3000):
            decode_header(bytes(rng.getrandbits(8) for _ in range(rng.randint(0, 32))))


class TestWavBackend:
    def test_wav_roundtrip(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "a.wav")
            _sine_wav(p)
            fmt, pcm = read_wav(p)
            assert fmt.rate == 8000 and fmt.channels == 1 and fmt.sampwidth == 2
            assert len(pcm) > 0


class TestCall:
    async def test_audio_streams_end_to_end(self):
        with tempfile.TemporaryDirectory() as d:
            src_path = os.path.join(d, "in.wav")
            out_path = os.path.join(d, "out.wav")
            _sine_wav(src_path, seconds=0.3)
            orig_fmt, orig_pcm = read_wav(src_path)

            caller = ChatApp(StubClient())
            callee = ChatApp(StubClient())
            call_rx = AudioCall(callee)
            call_rx.attach()

            source = WavSource(src_path, frame_ms=20.0)
            sent = await AudioCall(caller).place(DST, source, stream_id=1, pace=False)
            assert sent > 0

            # Deliver every emitted frame into the callee, as the mesh would.
            for _target, payload in caller._client.sent:
                # payload = type byte (STREAM=0x04) + frame struct + audio;
                # feed it straight through the chat dispatcher.
                callee._dispatch(SRC, payload)

            sink = WavSink(out_path)
            fmt = call_rx.render(SRC, 1, sink)
            assert fmt == orig_fmt
            _, got_pcm = read_wav(out_path)
            assert got_pcm == orig_pcm    # bit-for-bit audio across the mesh
            call_rx.detach()

    async def test_render_unknown_stream_none(self):
        app = ChatApp(StubClient())
        call = AudioCall(app)
        assert call.render(SRC, 99, WavSink("/dev/null")) is None
