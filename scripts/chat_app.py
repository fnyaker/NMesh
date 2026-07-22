"""
Interactive chat client — a real app that plugs into a running node.

Launch a node exposing a connector, then run this app wired to it. Usually the
node's process launcher starts it for you (injecting the connector env); to run
it by hand, export the connector coordinates first:

    NMESH_CONNECTOR_HOST=127.0.0.1 NMESH_CONNECTOR_PORT=8790 \
    NMESH_CONNECTOR_TOKEN=<token> python scripts/chat_app.py --peer <node_id_hex>

Commands while running:
    <text>            send a text message to the current peer
    /peer <hex>       set the peer node id
    /file <path>      send a file to the current peer
    /quit             exit
"""
import argparse
import asyncio
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from src.data_connector import ConnectorClient
from src.app_channel import CHAT_APP_ID
from src.node_id import NodeID
from src.apps.chat import ChatApp, TextMessage, FileReceived, Frame
from src.apps.chat_web import ChatWebServer


async def _print_events(app: ChatApp) -> None:
    while True:
        ev = await app.next_event()
        who = ev.src.raw.hex()[:12]
        if isinstance(ev, TextMessage):
            print(f"\n[{who}] {ev.text}\n> ", end="", flush=True)
        elif isinstance(ev, FileReceived):
            path = os.path.join(os.getcwd(), os.path.basename(ev.name) or "received.bin")
            with open(path, "wb") as f:
                f.write(ev.data)
            print(f"\n[{who}] sent file {ev.name} ({len(ev.data)} B) → saved {path}\n> ",
                  end="", flush=True)
        elif isinstance(ev, Frame):
            print(f"\n[{who}] frame #{ev.seq} ({ev.latency_ms:.1f} ms)\n> ",
                  end="", flush=True)


async def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--peer", help="peer node id (hex)")
    ap.add_argument("--web", type=int, default=None, metavar="PORT",
                    help="also surface this chat to a local web UI on PORT")
    args = ap.parse_args()

    client = ConnectorClient.from_env(app_id=CHAT_APP_ID)
    await client.connect()
    app = ChatApp(client)
    await app.start()
    me = await client.whoami()
    print(f"connected as {me.raw.hex()}")
    peer = NodeID(bytes.fromhex(args.peer)) if args.peer else None

    web = None
    if args.web is not None:
        web = ChatWebServer(app, host="127.0.0.1", port=args.web, peer=peer)
        web.start(loop=asyncio.get_running_loop())
        print(f"web UI: {web.url}   token={web.token}")

    printer = asyncio.create_task(_print_events(app))
    try:
        print("> ", end="", flush=True)
        while True:
            line = (await asyncio.to_thread(sys.stdin.readline))
            if not line:
                break
            line = line.rstrip("\n")
            if line == "/quit":
                break
            elif line.startswith("/peer "):
                peer = NodeID(bytes.fromhex(line[6:].strip()))
                print(f"peer set to {peer.raw.hex()[:12]}…")
            elif line.startswith("/file "):
                if peer is None:
                    print("set a peer first (/peer <hex>)")
                else:
                    path = line[6:].strip()
                    with open(path, "rb") as f:
                        data = f.read()
                    await app.send_file(peer, os.path.basename(path), data)
                    print(f"sent {path} ({len(data)} B)")
            elif line and peer is not None:
                await app.send_text(peer, line)
            elif line:
                print("set a peer first (/peer <hex>)")
            print("> ", end="", flush=True)
    finally:
        if web is not None:
            web.stop()
        printer.cancel()
        await app.stop()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
