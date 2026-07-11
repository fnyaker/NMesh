"""
Example mesh application: an echo service.

Launched by a NMesh node's process launcher, it reads the connector coordinates
from the environment, joins the mesh, and reflects every message it receives
back to its sender. It is both a demo and the reference for writing your own app
against ``ConnectorClient``.

Run standalone (with a node exposing a connector) via the injected environment:
    NMESH_CONNECTOR_HOST=127.0.0.1 NMESH_CONNECTOR_PORT=8790 \
    NMESH_CONNECTOR_TOKEN=... python scripts/example_app.py
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from src.data_connector import ConnectorClient


async def main() -> None:
    client = ConnectorClient.from_env()
    await client.connect()
    me = await client.whoami()
    print(f"[example_app] joined the mesh as {me.raw.hex()[:16]}…", flush=True)
    while True:
        src, payload = await client.recv()
        await client.send(src, b"echo:" + payload)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
