"""
Self-contained audio call demo: two nodes on localhost, a WAV streamed in real
time from one to the other, verified bit-for-bit with a latency report.

    python scripts/call_demo.py

Real audio (WAV, stdlib), no hardware. To place a call from a live microphone,
implement AudioSource/AudioSink with a device backend in your app — NMesh keeps
no audio dependency.
"""
import asyncio
import math
import os
import statistics
import struct
import sys
import tempfile
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from src import MeshNode
from src.transport_manager import TransportManager
from src.tcp_transport import TCPTransport, TCPServer
from src.data_connector import DataConnector, ConnectorClient
from src.app_channel import CHAT_APP_ID
from src.apps.chat import ChatApp
from src.apps.call import AudioCall, AudioFormat, WavSource, WavSink, read_wav, write_wav


def _node():
    mgr = TransportManager()
    mgr.register("tcp", TCPTransport, TCPServer)
    return MeshNode(mgr)


async def _chat(node):
    conn = DataConnector(node, host="127.0.0.1", port=0, token="call")
    await conn.start()
    client = ConnectorClient(conn.host, conn.port, "call", CHAT_APP_ID)
    await client.connect()
    app = ChatApp(client)
    await app.start()
    return conn, app


def _tone(path, rate=8000, seconds=1.0, freq=440.0):
    n = int(rate * seconds)
    pcm = b"".join(struct.pack("<h", int(12000 * math.sin(2 * math.pi * freq * i / rate)))
                   for i in range(n))
    write_wav(path, AudioFormat(rate, 1, 2), pcm)


async def main():
    print("=" * 58)
    print("  NMesh audio call demo")
    print("=" * 58)
    with tempfile.TemporaryDirectory() as d:
        src = os.path.join(d, "in.wav")
        out = os.path.join(d, "out.wav")
        _tone(src, seconds=1.0)
        orig_fmt, orig_pcm = read_wav(src)

        bob = _node(); alice = _node()
        code = bob.generate_invite()
        await bob.start(["tcp://127.0.0.1:19190"])
        await alice.join("tcp://127.0.0.1:19190", code)
        await alice.wait_for_session(timeout=15.0)
        await bob.wait_for_session(timeout=15.0)
        bob_conn, bob_app = await _chat(bob)
        alice_conn, alice_app = await _chat(alice)

        rx = AudioCall(bob_app); rx.attach()

        try:
            source = WavSource(src, frame_ms=20.0)
            print(f"\n  streaming {orig_fmt.rate} Hz mono, {len(orig_pcm)} bytes "
                  f"in {source.samples_per_frame}-sample frames…")
            t0 = time.time()
            sent = await AudioCall(alice_app).place(bob.id, source, stream_id=1, pace=True)
            await asyncio.sleep(0.5)  # let the tail arrive
            span = time.time() - t0
            latencies = rx.latencies

            sink = WavSink(out)
            rx.render(alice.id, 1, sink)   # audio came from alice
            _, got = read_wav(out)
            ok = got == orig_pcm

            print(f"  frames sent  : {sent}")
            print(f"  audio        : {'identical ✓' if ok else 'MISMATCH ✗'} "
                  f"({len(got)}/{len(orig_pcm)} bytes)")
            if latencies:
                lat = sorted(latencies)
                print(f"  latency ms   : avg {statistics.mean(lat):.1f} | "
                      f"p50 {lat[len(lat)//2]:.1f} | max {lat[-1]:.1f}")
            print(f"  real-time    : {span:.1f}s for ~1.0s of audio")
            print("\n" + "=" * 58)
        finally:
            rx.detach()
            await alice_app.stop(); await bob_app.stop()
            await alice_conn.stop(); await bob_conn.stop()
            await alice.stop(); await bob.stop()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
