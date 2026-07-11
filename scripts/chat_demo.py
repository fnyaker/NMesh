"""
Self-contained chat demo: two nodes on localhost exchange a text conversation,
transfer a file, and run a real-time frame stream (the "call" primitive), with a
latency/throughput report. No setup — just:

    python scripts/chat_demo.py
"""
import asyncio
import os
import statistics
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from src import MeshNode
from src.transport_manager import TransportManager
from src.tcp_transport import TCPTransport, TCPServer
from src.data_connector import DataConnector, ConnectorClient
from src.apps.chat import ChatApp, TextMessage, FileReceived, Frame


def _node() -> MeshNode:
    mgr = TransportManager()
    mgr.register("tcp", TCPTransport, TCPServer)
    return MeshNode(mgr)


async def _chat_for(node):
    conn = DataConnector(node, host="127.0.0.1", port=0, token="demo")
    await conn.start()
    client = ConnectorClient(conn.host, conn.port, "demo")
    await client.connect()
    app = ChatApp(client)
    await app.start()
    return conn, app


async def _expect(app, kind, timeout=20.0):
    while True:
        ev = await asyncio.wait_for(app.next_event(), timeout=timeout)
        if isinstance(ev, kind):
            return ev


async def main() -> None:
    print("=" * 60)
    print("  NMesh chat demo — two nodes, one mesh")
    print("=" * 60)

    bob = _node()       # host
    alice = _node()     # guest
    code = bob.generate_invite()
    await bob.start(["tcp://127.0.0.1:19180"])
    await alice.join("tcp://127.0.0.1:19180", code)
    await alice.wait_for_session(timeout=15.0)
    await bob.wait_for_session(timeout=15.0)

    bob_conn, bob_app = await _chat_for(bob)
    alice_conn, alice_app = await _chat_for(alice)

    try:
        # --- text conversation ---
        print("\n[text]")
        await alice_app.send_text(bob.id, "Salut Bob 👋")
        msg = await _expect(bob_app, TextMessage)
        print(f"  Bob received : {msg.text!r} from {msg.src.raw.hex()[:12]}…")
        await bob_app.send_text(alice.id, "Salut Alice, bien reçu !")
        reply = await _expect(alice_app, TextMessage)
        print(f"  Alice received: {reply.text!r}")

        # --- file transfer ---
        print("\n[file]")
        blob = os.urandom(1_000_000)   # 1 MB
        t0 = time.time()
        await alice_app.send_file(bob.id, "picture.bin", blob)
        fr = await _expect(bob_app, FileReceived)
        dt = time.time() - t0
        ok = fr.data == blob
        print(f"  Bob received : {fr.name} ({len(fr.data)} bytes) "
              f"integrity={'OK' if ok else 'FAIL'}")
        print(f"  transfer     : {dt*1000:.0f} ms  ({len(blob)/1024/1024/max(dt,1e-9):.1f} MB/s)")

        # --- real-time stream (a "call") ---
        print("\n[real-time stream — a call]")
        frames, rate_hz, size = 150, 50, 320
        interval = 1.0 / rate_hz
        collected: list[Frame] = []

        async def _collect():
            for _ in range(frames):
                collected.append(await _expect(bob_app, Frame))

        collector = asyncio.create_task(_collect())
        start = time.time()
        for seq in range(frames):
            await alice_app.send_frame(bob.id, stream_id=1, seq=seq, payload=os.urandom(size))
            await asyncio.sleep(interval)
        await asyncio.wait_for(collector, timeout=20.0)
        span = time.time() - start

        lat = sorted(f.latency_ms for f in collected)
        p = lambda q: lat[min(len(lat) - 1, int(len(lat) * q))]
        print(f"  frames       : {len(collected)}/{frames} at ~{rate_hz} fps "
              f"({size} B each)")
        print(f"  effective    : {len(collected)/span:.0f} fps over {span:.1f}s")
        print(f"  latency ms   : avg {statistics.mean(lat):.1f} | "
              f"p50 {p(0.50):.1f} | p95 {p(0.95):.1f} | max {lat[-1]:.1f}")

        print("\n" + "=" * 60)
        print("  Demo complete — text, file, and real-time all over the mesh.")
        print("=" * 60)
    finally:
        await alice_app.stop()
        await bob_app.stop()
        await alice_conn.stop()
        await bob_conn.stop()
        await alice.stop()
        await bob.stop()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
