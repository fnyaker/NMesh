"""
NMesh node runner — Docker routing test.

Topology:
    net_a: n1 n2 n3 n4  →  bridge1 (dual-homed)  ←→  bridge2  ←  n5 n6 n7 n8 :net_b

bridge1 listens on 0.0.0.0:9000 (all interfaces → reachable from BOTH networks).
bridge2 joins bridge1 then hosts net_b cluster.
n1 sends a speed test to n8 (cross-cluster, route: n1→bridge1→bridge2→n8).

Environment variables:
  MODE          bridge1 | bridge2 | member
  NAME          node name in logs
  DATA_DIR      shared volume (default /data)
  HOST_ADDR     cluster host for member/bridge2 (default bridge1:9000)
  LISTEN_ADDR   address to listen on for members (default 0.0.0.0:9100)
  IS_SENDER     1 = speed test sender (default 0)
  SENDER_TARGET name of the target node (default n8)
  SENDER_NAME   name of the expected sender (default n1)
  MSG_COUNT     messages to send (default 300)
  MSG_SIZE      payload bytes (default 512)
"""

import asyncio
import os
import struct
import sys
import time
import statistics

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from src import MeshNode
from src.node_id import NodeID
from src.transport_manager import TransportManager
from src.tcp_transport import TCPTransport, TCPServer

DATA_DIR = os.environ.get("DATA_DIR", "/data")
os.makedirs(DATA_DIR, exist_ok=True)


def _env(key: str, default: str) -> str:
    return os.environ.get(key, default)


def _log(name: str, msg: str) -> None:
    ts = time.strftime("%H:%M:%S")
    print(f"[{ts}] [{name}] {msg}", flush=True)


def _bar(n: int, total: int, width: int = 30) -> str:
    filled = int(width * n / max(total, 1))
    return "█" * filled + "░" * (width - filled)


def make_node(name: str) -> MeshNode:
    mgr = TransportManager()
    mgr.register("tcp", TCPTransport, TCPServer)
    return MeshNode(mgr,
                    identity_path=os.path.join(DATA_DIR, f"{name}.key"),
                    cert_store_path=os.path.join(DATA_DIR, f"{name}.certs"))


def write_id(name: str, node: MeshNode) -> None:
    with open(os.path.join(DATA_DIR, f"{name}.id"), "w") as f:
        f.write(node.id.raw.hex())


async def wait_for_id_file(name: str, timeout: float = 120.0) -> NodeID:
    path = os.path.join(DATA_DIR, f"{name}.id")
    deadline = asyncio.get_event_loop().time() + timeout
    while asyncio.get_event_loop().time() < deadline:
        if os.path.exists(path):
            try:
                with open(path) as f:
                    return NodeID(bytes.fromhex(f.read().strip()))
            except Exception:
                pass
        await asyncio.sleep(0.5)
    raise TimeoutError(f"timeout waiting for {name}.id")


async def wait_for_invite(name: str, timeout: float = 120.0) -> str:
    path = os.path.join(DATA_DIR, f"invite_{name}")
    deadline = asyncio.get_event_loop().time() + timeout
    while asyncio.get_event_loop().time() < deadline:
        if os.path.exists(path):
            with open(path) as f:
                return f.read().strip()
        await asyncio.sleep(0.5)
    raise TimeoutError(f"timeout waiting for invite_{name}")


async def all_ids_ready(names: list[str], timeout: float = 180.0) -> dict[str, NodeID]:
    deadline = asyncio.get_event_loop().time() + timeout
    missing = set(names)
    ids: dict[str, NodeID] = {}
    while asyncio.get_event_loop().time() < deadline:
        for n in list(missing):
            path = os.path.join(DATA_DIR, f"{n}.id")
            if os.path.exists(path):
                try:
                    with open(path) as f:
                        ids[n] = NodeID(bytes.fromhex(f.read().strip()))
                    missing.discard(n)
                except Exception:
                    pass
        if not missing:
            return ids
        await asyncio.sleep(1)
    raise TimeoutError(f"timeout waiting for IDs: {missing}")


async def wait_for_n_sessions(node: MeshNode, expected: int, timeout: float) -> None:
    deadline = asyncio.get_event_loop().time() + timeout
    n = 0
    while asyncio.get_event_loop().time() < deadline:
        n = sum(1 for p in node._peers
                if p.session is not None and p.authenticated_id is not None)
        if n >= expected:
            return
        await asyncio.sleep(0.2)
    raise TimeoutError(f"only {n}/{expected} sessions established")


async def periodic_bootstrap(node: MeshNode, name: str, interval: float = 30.0) -> None:
    while True:
        await asyncio.sleep(interval)
        await node.bootstrap()
        known = sum(1 for p in node._peers if p.session is not None and p.dsa_pub)
        _log(name, f"Re-bootstrap complete: {known} authenticated peers")


async def join_with_retry(node: MeshNode, host_addr: str, code: str,
                           name: str, retries: int = 10) -> None:
    for attempt in range(retries):
        try:
            await node.join(f"tcp://{host_addr}", code)
            return
        except Exception as e:
            if attempt < retries - 1:
                _log(name, f"connect failed ({e}), retry {attempt+1}/{retries}…")
                await asyncio.sleep(2)
            else:
                raise


# ─── speed test ───────────────────────────────────────────────────────────────

_MSG_MAGIC  = b"NMSH"
_MSG_HEADER = struct.Struct("!4sIQ")   # magic | seq | ts_ns


def encode_msg(seq: int, size: int) -> bytes:
    h = _MSG_HEADER.pack(_MSG_MAGIC, seq, time.time_ns())
    return h + bytes([seq % 256] * max(0, size - _MSG_HEADER.size))


def decode_msg(data: bytes) -> tuple[int, float] | None:
    if len(data) < _MSG_HEADER.size:
        return None
    magic, seq, ts_ns = _MSG_HEADER.unpack_from(data, 0)
    return (seq, ts_ns / 1e9) if magic == _MSG_MAGIC else None


def _stats_block(latencies_ms: list[float]) -> list[str]:
    if not latencies_ms:
        return []
    s = sorted(latencies_ms)
    p = lambda q: s[max(0, int(len(s) * q) - 1)]
    return [
        f"  avg     : {statistics.mean(s):.1f} ms",
        f"  p50     : {p(0.50):.1f} ms",
        f"  p95     : {p(0.95):.1f} ms",
        f"  p99     : {p(0.99):.1f} ms",
        f"  min/max : {s[0]:.1f} ms / {s[-1]:.1f} ms",
    ]


async def wait_e2e(node: MeshNode, target_id: NodeID, timeout: float = 30.0) -> bool:
    deadline = asyncio.get_event_loop().time() + timeout
    while asyncio.get_event_loop().time() < deadline:
        if target_id in node._e2e_sessions:
            return True
        await asyncio.sleep(0.1)
    return False


async def speed_test_sender(node: MeshNode, name: str,
                             target_id: NodeID, target_name: str,
                             count: int, msg_size: int) -> None:
    sep = "━" * 58
    print(f"\n╔{'═' * 56}╗")
    print(f"║  NMesh Speed Test — {name} → {target_name:<35}║")
    print(f"╚{'═' * 56}╝\n")
    _log(name, f"Sending {count} msgs × {msg_size} B → {target_name}")

    # Probe triggers E2E handshake
    await node.send_data(target_id, encode_msg(0, msg_size))
    _log(name, "Waiting for E2E session…")
    if not await wait_e2e(node, target_id, timeout=45.0):
        _log(name, "ERROR: E2E session timeout — aborting")
        return
    _log(name, "E2E session established ✓")

    t0 = time.time()
    for seq in range(1, count + 1):
        await node.send_data(target_id, encode_msg(seq, msg_size))
        if seq % max(1, count // 20) == 0 or seq == count:
            print(f"\r  [{_bar(seq, count)}] {seq}/{count}", end="", flush=True)
    print()
    elapsed = time.time() - t0

    print(f"\n{sep}")
    print(f"  Sender ({name} → {target_name}):")
    print(f"  sent:       {count} messages")
    print(f"  time:       {elapsed:.2f} s")
    print(f"  throughput: {count/elapsed:.1f} msg/s | {count*msg_size/1024/elapsed:.1f} KB/s")
    print(sep)


async def speed_test_receiver(node: MeshNode, name: str, sender_name: str,
                               expected: int, idle_timeout: float = 20.0) -> None:
    _log(name, f"Receiver — expecting ~{expected} messages from {sender_name}")
    latencies: list[float] = []
    received = 0
    first_ts: float | None = None
    last_activity = time.time()

    async def _collect() -> None:
        nonlocal received, first_ts, last_activity
        while True:
            src, data = await node.receive_data()
            r = decode_msg(data)
            if r is None:
                continue
            seq, send_ts = r
            lat_ms = (time.time() - send_ts) * 1000
            latencies.append(lat_ms)
            received += 1
            last_activity = time.time()
            if first_ts is None:
                first_ts = time.time()
                _log(name, f"First msg (seq={seq}, latency={lat_ms:.1f} ms)")
            elif received % max(1, expected // 5) == 0:
                _log(name, f"  received {received}…")

    task = asyncio.create_task(_collect())
    deadline = time.time() + 180
    while received < expected and time.time() < deadline:
        await asyncio.sleep(0.5)
        if received > 0 and time.time() - last_activity > idle_timeout:
            break
    task.cancel()
    try:
        await task
    except (asyncio.CancelledError, Exception):
        pass

    sep = "━" * 58
    pct = 100 * received / max(expected, 1)
    dur = (latencies[-1] - latencies[0]) / 1000 if len(latencies) > 1 else 1e-9
    tput = (received - 1) / max(dur, 1e-9) if len(latencies) > 1 else 0
    print(f"\n{sep}")
    print(f"  Receiver ({name} ← {sender_name}):")
    print(f"  received: {received}/{expected} ({pct:.1f}%)")
    if latencies:
        print(f"  throughput: {tput:.1f} msg/s")
        for line in _stats_block(latencies):
            print(line)
    print(sep + "\n")


# ─── modes ────────────────────────────────────────────────────────────────────

async def run_bridge1() -> None:
    name      = _env("NAME", "bridge1")
    listen    = _env("LISTEN_ADDR", "0.0.0.0:9000")
    advertise = _env("ADVERTISE",   "bridge1:9000")
    count_a   = int(_env("MEMBER_A_COUNT", "4"))

    node = make_node(name)
    await node.start([f"tcp://{listen}"])
    write_id(name, node)
    _log(name, f"Listening on {advertise} (all interfaces — net_a + net_b)")
    _log(name, f"NodeID: {node.id.raw.hex()[:16]}…")

    bridge2_code = node.generate_invite()
    with open(os.path.join(DATA_DIR, "invite_bridge2"), "w") as f:
        f.write(bridge2_code)
    _log(name, "Invite written for bridge2")

    member_names_a = [f"n{i}" for i in range(1, count_a + 1)]
    for mname in member_names_a:
        code = node.generate_invite()
        with open(os.path.join(DATA_DIR, f"invite_{mname}"), "w") as f:
            f.write(code)
    _log(name, f"Invites written for {', '.join(member_names_a)}")

    all_names = ["bridge2"] + member_names_a + [f"n{i}" for i in range(5, 9)]
    _log(name, "Waiting for all nodes…")
    all_ids = await all_ids_ready(all_names)
    _log(name, f"All {len(all_ids)} nodes online ✓")

    # Wait for direct sessions then bootstrap (discover cross-cluster via Kademlia)
    expected_sessions = 1 + count_a   # bridge2 + n1..n4
    _log(name, f"Waiting for {expected_sessions} sessions…")
    await wait_for_n_sessions(node, expected=expected_sessions, timeout=90.0)
    _log(name, f"{expected_sessions} sessions established ✓ — bootstrapping…")
    await node.bootstrap()
    _log(name, "Bootstrap complete")

    asyncio.create_task(periodic_bootstrap(node, name, interval=30.0))
    _log(name, "Bridge1 ready — backbone running")

    known = 0
    while True:
        await asyncio.sleep(3)
        now = sum(1 for v in all_ids.values() if node._routing.contains(v))
        if now != known:
            known = now
            _log(name, f"Routing table: {known}/{len(all_ids)} remote nodes reachable")


async def run_bridge2() -> None:
    name      = _env("NAME", "bridge2")
    host_addr = _env("HOST_ADDR", "bridge1:9000")
    listen    = _env("LISTEN_ADDR", "0.0.0.0:9002")
    advertise = _env("ADVERTISE",   "bridge2:9002")
    count_b   = int(_env("MEMBER_B_COUNT", "4"))

    node = make_node(name)
    write_id(name, node)

    _log(name, "Waiting for invite from bridge1…")
    code = await wait_for_invite("bridge2")
    _log(name, f"Joining bridge1 at tcp://{host_addr}")
    await join_with_retry(node, host_addr, code, name)
    await node.wait_for_session(timeout=60.0)
    _log(name, "Session with bridge1 established ✓")

    await node.start([f"tcp://{listen}"])
    _log(name, f"Listening on {advertise}")

    # Bootstrap: advertise bridge2's address to bridge1, explore network
    await node.bootstrap()
    _log(name, "Bootstrap (bridge1 cluster) complete")

    member_names_b = [f"n{i}" for i in range(5, 5 + count_b)]
    for mname in member_names_b:
        code = node.generate_invite()
        with open(os.path.join(DATA_DIR, f"invite_{mname}"), "w") as f:
            f.write(code)
    _log(name, f"Invites written for {', '.join(member_names_b)}")

    all_names = ["bridge1"] + member_names_b + [f"n{i}" for i in range(1, 5)]
    _log(name, "Waiting for all nodes…")
    all_ids = await all_ids_ready(all_names)
    _log(name, f"All {len(all_ids)} nodes online ✓")

    # Wait for net_b members then bootstrap again to propagate their presence
    expected_sessions = 1 + count_b   # bridge1 + n5..n8
    _log(name, f"Waiting for {expected_sessions} sessions…")
    await wait_for_n_sessions(node, expected=expected_sessions, timeout=90.0)
    _log(name, f"{expected_sessions} sessions established ✓ — re-bootstrapping…")
    await node.bootstrap()
    _log(name, "Bootstrap complete")

    asyncio.create_task(periodic_bootstrap(node, name, interval=30.0))
    _log(name, "Bridge2 ready — backbone running")

    known = 0
    while True:
        await asyncio.sleep(3)
        now = sum(1 for v in all_ids.values() if node._routing.contains(v))
        if now != known:
            known = now
            _log(name, f"Routing table: {known}/{len(all_ids)} remote nodes reachable")


async def run_member() -> None:
    name        = _env("NAME", "node")
    host_addr   = _env("HOST_ADDR", "bridge1:9000")
    listen      = _env("LISTEN_ADDR", "0.0.0.0:9100")
    is_sender   = _env("IS_SENDER", "0") == "1"
    target_name = _env("SENDER_TARGET", "n8")
    sender_name = _env("SENDER_NAME", "n1")
    msg_count   = int(_env("MSG_COUNT", "300"))
    msg_size    = int(_env("MSG_SIZE",  "512"))

    node = make_node(name)

    # Members listen so the bridge can reach them on-demand
    await node.start([f"tcp://{listen}"])
    write_id(name, node)

    _log(name, "Waiting for invite…")
    code = await wait_for_invite(name)
    _log(name, f"Joining tcp://{host_addr}")
    await join_with_retry(node, host_addr, code, name)
    await node.wait_for_session(timeout=60.0)
    _log(name, "Session established ✓")

    # Bootstrap: advertise our address, explore the network via Kademlia
    await node.bootstrap()
    _log(name, "Bootstrap complete")

    if is_sender:
        _log(name, f"Reading {target_name}.id…")
        target_id = await wait_for_id_file(target_name, timeout=120)
        _log(name, f"Target {target_name}: {target_id.raw.hex()[:16]}…")

        # Wait until target is discoverable (bootstrap may need a few rounds)
        _log(name, "Waiting for target in routing table…")
        deadline = asyncio.get_event_loop().time() + 60
        while asyncio.get_event_loop().time() < deadline:
            if node._routing.contains(target_id):
                break
            await node.find_node(target_id)
            await asyncio.sleep(2)
        else:
            _log(name, "WARNING: target not in routing table — proceeding anyway")

        await speed_test_sender(node, name, target_id, target_name, msg_count, msg_size)
        _log(name, "Speed test complete")
        await asyncio.sleep(5)
    else:
        await speed_test_receiver(node, name, sender_name, expected=msg_count + 1)
        _log(name, "Done")
        await asyncio.sleep(2)

    await node.stop()


if __name__ == "__main__":
    mode = _env("MODE", "member")
    if mode == "bridge1":
        asyncio.run(run_bridge1())
    elif mode == "bridge2":
        asyncio.run(run_bridge2())
    elif mode == "member":
        asyncio.run(run_member())
    else:
        print(f"Unknown MODE: {mode}", flush=True)
        sys.exit(1)
