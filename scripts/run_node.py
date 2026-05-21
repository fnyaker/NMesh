import asyncio
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from src import MeshNode

DATA_DIR     = "/data"
RESULT_FILE  = "/data/result"


def invite_file(index: int) -> str:
    return f"{DATA_DIR}/invite_code_{index}"


async def run_host() -> None:
    addr = os.environ.get("NODE_ADDR", "0.0.0.0:9000")
    count = int(os.environ.get("NODE_COUNT", "1"))
    node = MeshNode()

    os.makedirs(DATA_DIR, exist_ok=True)

    codes = []
    for i in range(2, count + 2):
        code = node.generate_invite()
        with open(invite_file(i), "w") as f:
            f.write(code)
        codes.append((i, code))
        print(f"[HOST] invite code for node_{i}: {code}", flush=True)

    await node.start(addr)
    print(f"[HOST] listening on {addr}", flush=True)

    received = []
    for _ in range(count):
        data = await asyncio.wait_for(node.receive_data(), timeout=60.0)
        msg = data.decode()
        received.append(msg)
        print(f"[HOST] received ({len(received)}/{count}): {msg}", flush=True)

    with open(RESULT_FILE, "w") as f:
        f.write("\n".join(received))

    print(f"[HOST] all {count} messages received — success", flush=True)
    await node.stop()


async def run_join() -> None:
    node_addr = os.environ.get("NODE_ADDR", "0.0.0.0:9001")
    host_addr = os.environ.get("HOST_ADDR", "node_1:9000")
    node_index = int(os.environ.get("NODE_INDEX", "2"))
    message = os.environ.get("MESSAGE", f"hello from node_{node_index}")

    code_file = invite_file(node_index)
    for _ in range(120):
        if os.path.exists(code_file):
            break
        time.sleep(1)
    else:
        print(f"[node_{node_index}] timeout waiting for invite code", flush=True)
        sys.exit(1)

    with open(code_file) as f:
        code = f.read().strip()
    print(f"[node_{node_index}] using code: {code}", flush=True)

    node = MeshNode()
    await node.join(host_addr, code)
    await node.wait_for_session(timeout=30.0)
    await node.send_data(message.encode())
    print(f"[node_{node_index}] sent: {message}", flush=True)
    await node.stop()


if __name__ == "__main__":
    mode = os.environ.get("MODE", "host")
    if mode == "host":
        asyncio.run(run_host())
    elif mode == "join":
        asyncio.run(run_join())
    else:
        print(f"Unknown MODE: {mode}", flush=True)
        sys.exit(1)
