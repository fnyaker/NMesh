"""
Run a MeshNode with the web console attached.

    python scripts/nmesh_node.py [--listen 0.0.0.0:9000] [--console-host 127.0.0.1]
                                   [--console-port 8787] [--no-tls] [--data DIR]

On first run the console password is generated and printed once — save it.
The TLS certificate is self-signed; its SHA-256 fingerprint is printed so you
can verify it in your browser. The console binds to loopback by default; pass
--console-host 0.0.0.0 to reach it from another machine (do this knowingly).
"""
import argparse
import asyncio
import os
import shlex
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from src import MeshNode
from src.transport_manager import TransportManager
from src.tcp_transport import TCPTransport, TCPServer
from src.spool_transport import SpoolTransport, SpoolServer
from src.udp_transport import UDPTransport, UDPServer
from src.webconsole import WebConsole
from src.data_connector import DataConnector, ConnectorClient
from src.process_launcher import ProcessLauncher
from src.app_channel import CHAT_APP_ID
from src.apps.chat import ChatApp
from src.apps.chat_state import ChatState
from src.apps.chat_web import ChatBridge


async def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--listen", default="0.0.0.0:9000", help="node TCP listen addr")
    ap.add_argument("--udp", default=9001, type=int,
                    help="UDP listen port for hole punching (default 9001)")
    ap.add_argument("--no-udp", action="store_true",
                    help="disable the UDP listener (punching stays controllable from the console)")
    ap.add_argument("--stun", action="store_true",
                    help="use STUN to discover public UDP address (fallback)")
    ap.add_argument("--punch-keepalive", action="store_true",
                    help="keep the UDP NAT mapping open continuously (stay "
                         "reachable / relay behind NAT)")
    ap.add_argument("--lan-discovery", action="store_true",
                    help="answer LAN relay-discovery beacons (be findable as a "
                         "relay by joiners on the same network)")
    ap.add_argument("--spool", default=None, help="also listen on a spool:// directory (store-and-forward)")
    ap.add_argument("--console-host", default="127.0.0.1")
    ap.add_argument("--console-port", type=int, default=8787)
    ap.add_argument("--connector-port", type=int, default=None,
                    help="expose a data connector on this loopback port for apps")
    ap.add_argument("--launch", action="append", default=[], metavar="CMD",
                    help="launch an app wired to the mesh (repeatable); needs --connector-port")
    ap.add_argument("--no-chat", action="store_true",
                    help="disable the built-in chat app (served at /chat on the console)")
    ap.add_argument("--no-tls", action="store_true")
    ap.add_argument("--data", default=None, help="state dir (persists identity + console creds)")
    # Read from the environment so a password never lands in the process args
    # (visible in `ps`); a CLI flag still overrides it when given explicitly.
    ap.add_argument("--console-password",
                    default=os.environ.get("NMESH_CONSOLE_PASSWORD") or None,
                    help="console password (default: $NMESH_CONSOLE_PASSWORD, "
                         "else a strong one is generated and printed once)")
    args = ap.parse_args()

    if args.data:
        os.makedirs(args.data, exist_ok=True)

    mgr = TransportManager()
    mgr.register("tcp", TCPTransport, TCPServer)
    mgr.register("spool", SpoolTransport, SpoolServer)
    mgr.register("udp", UDPTransport, UDPServer)
    node = MeshNode(
        mgr,
        identity_path=os.path.join(args.data, "node.key") if args.data else None,
        cert_store_path=os.path.join(args.data, "node.certs") if args.data else None,
        session_store_path=os.path.join(args.data, "node.sessions") if args.data else None,
        app_storage_path=os.path.join(args.data, "app_store") if args.data else None,
        app_store_dir=os.path.join(args.data, "appstore") if args.data else None,
    )
    listen_uris = [f"tcp://{args.listen}"]
    if args.spool:
        listen_uris.append(f"spool://{args.spool}")
    await node.start(listen_uris)
    # Discover public IP before printing so advertised URIs include it
    pub_ip = await node.discover_public_ip()
    if args.udp is not None and not args.no_udp:
        await node.start_udp(args.udp)
        if args.punch_keepalive:
            node.console_set_punch_keepalive(True)
    if args.lan_discovery:
        await node.start_lan_discovery()
        if args.stun:
            pub = await node.discover_public_udp_addr()
            if pub:
                print(f"  STUN          : public UDP addr {pub[0]}:{pub[1]}")

    # A data connector backs both the built-in chat app and any --launch'd apps.
    # When only chat needs it, bind an ephemeral loopback port; --connector-port
    # exposes a fixed one for external apps.
    connector = None
    launcher = None
    chat_app = None
    chat_bridge = None
    if not args.no_chat or args.connector_port is not None:
        connector = DataConnector(node, host="127.0.0.1", port=args.connector_port or 0)
        await connector.start()
        launcher = ProcessLauncher(connector, node_id=node.id)
        for cmd in args.launch:
            await launcher.launch(shlex.split(cmd))
    elif args.launch:
        print("  NOTE          : --launch ignored (requires --connector-port or chat)")

    if not args.no_chat and connector is not None:
        chat_client = ConnectorClient(connector.host, connector.port,
                                      connector.token, CHAT_APP_ID)
        await chat_client.connect()
        chat_state = ChatState(
            os.path.join(args.data, "chat_state.json") if args.data else None)
        chat_app = ChatApp(chat_client, node_id=node.id, state=chat_state)
        await chat_app.start()
        chat_bridge = ChatBridge(chat_app)

    console = WebConsole(node, host=args.console_host, port=args.console_port,
                         state_dir=args.data, use_tls=not args.no_tls,
                         password=args.console_password, chat_bridge=chat_bridge)
    console.start(loop=asyncio.get_running_loop())

    print("=" * 60)
    print(f"  NMesh node    : {node.id.raw.hex()[:16]}…  listening tcp://{args.listen}")
    if pub_ip:
        print(f"  Public IP     : {pub_ip}   (self-discovered)")
    for uri in node.advertised_uris():
        print(f"  Advertised    : {uri}")
    if args.spool:
        print(f"  Spool link    : spool://{args.spool}   (store-and-forward)")
    if args.udp is not None and not args.no_udp:
        print(f"  UDP listener  : udp://0.0.0.0:{args.udp}   (NAT hole punching)")
    print(f"  Web console   : {console.url}")
    if chat_bridge is not None:
        print(f"  Chat app      : {console.url}chat   (built-in, in-app)")
    if console.generated_password:
        print(f"  Password      : {console.generated_password}   (shown once — save it)")
    elif args.console_password:
        print("  Password      : (the one you set via NMESH_CONSOLE_PASSWORD)")
    else:
        print("  Password      : (existing — from console.cred)")
    if not args.no_tls:
        print(f"  TLS SHA-256   : {console.cert_fingerprint}")
    if connector is not None:
        print(f"  Data connector: 127.0.0.1:{connector.port}   token={connector.token}")
    if launcher is not None and launcher.processes:
        print(f"  Launched apps : {', '.join(p.name for p in launcher.processes)}")
    if args.console_host not in ("127.0.0.1", "localhost", "::1"):
        print("  WARNING       : console is reachable off-host — protect the network path.")
    print("=" * 60, flush=True)

    try:
        while True:
            await asyncio.sleep(3600)
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
    finally:
        console.stop()          # also detaches the chat bridge listener
        if chat_app is not None:
            await chat_app.stop()   # closes the in-process connector client
        if launcher is not None:
            await launcher.stop_all()
        if connector is not None:
            await connector.stop()
        await node.stop()  # also stops UDP listener + cleans up punch state


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
