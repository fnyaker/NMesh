"""
Run a MeshNode with the web console attached.

    python scripts/console_demo.py [--listen 0.0.0.0:9000] [--console-host 127.0.0.1]
                                   [--console-port 8787] [--no-tls] [--data DIR]

On first run the console password is generated and printed once — save it.
The TLS certificate is self-signed; its SHA-256 fingerprint is printed so you
can verify it in your browser. The console binds to loopback by default; pass
--console-host 0.0.0.0 to reach it from another machine (do this knowingly).
"""
import argparse
import asyncio
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from src import MeshNode
from src.transport_manager import TransportManager
from src.tcp_transport import TCPTransport, TCPServer
from src.webconsole import WebConsole


async def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--listen", default="0.0.0.0:9000", help="node TCP listen addr")
    ap.add_argument("--console-host", default="127.0.0.1")
    ap.add_argument("--console-port", type=int, default=8787)
    ap.add_argument("--no-tls", action="store_true")
    ap.add_argument("--data", default=None, help="state dir (persists identity + console creds)")
    args = ap.parse_args()

    if args.data:
        os.makedirs(args.data, exist_ok=True)

    mgr = TransportManager()
    mgr.register("tcp", TCPTransport, TCPServer)
    node = MeshNode(
        mgr,
        identity_path=os.path.join(args.data, "node.key") if args.data else None,
        cert_store_path=os.path.join(args.data, "node.certs") if args.data else None,
    )
    await node.start([f"tcp://{args.listen}"])

    console = WebConsole(node, host=args.console_host, port=args.console_port,
                         state_dir=args.data, use_tls=not args.no_tls)
    console.start(loop=asyncio.get_running_loop())

    print("=" * 60)
    print(f"  NMesh node    : {node.id.raw.hex()[:16]}…  listening tcp://{args.listen}")
    print(f"  Web console   : {console.url}")
    if console.generated_password:
        print(f"  Password      : {console.generated_password}   (shown once — save it)")
    else:
        print("  Password      : (existing — from console.cred)")
    if not args.no_tls:
        print(f"  TLS SHA-256   : {console.cert_fingerprint}")
    if args.console_host not in ("127.0.0.1", "localhost", "::1"):
        print("  WARNING       : console is reachable off-host — protect the network path.")
    print("=" * 60, flush=True)

    try:
        while True:
            await asyncio.sleep(3600)
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
    finally:
        console.stop()
        await node.stop()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
