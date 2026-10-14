"""A mesh of real NMesh nodes spread over several processes, driven from one.

One process simulating a few hundred post-quantum nodes is CPU-bound: its event
loop runs hundreds of milliseconds late and every timer in it is wrong. Here each
worker process holds a share of the nodes (real TCP between all of them, on
loopback), so the machine's cores are what limits the size.

    python tests/tools/mesh_sim.py --procs 8 --nodes 120 --pairs 100
        [--wait 12] [--seed 1] [--kill 0.3] [--src <tree to run>]

Parent and workers speak one JSON object per line on the worker's stdin/stdout.
"""
import argparse
import asyncio
import json
import os
import random
import socket
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
_TREE = os.path.dirname(os.path.dirname(_HERE))


# ---------------------------------------------------------------- worker ----

async def worker(src: str) -> None:
    sys.path.insert(0, src)
    out = os.fdopen(os.dup(1), "w", buffering=1)
    sys.stdout = sys.stderr           # the library prints; the protocol must not mix
    from src import MeshNode
    from src.node_id import NodeID
    from src.tcp_transport import TCPServer, TCPTransport
    from src.transport_manager import TransportManager

    nodes, got, lags = [], [], []

    async def monitor():
        while True:
            t = time.monotonic()
            await asyncio.sleep(0.05)
            lags.append(time.monotonic() - t - 0.05)

    async def drain(i):
        while True:
            _, data = await nodes[i].receive_data()
            got[i].add(bytes(data))

    def free_port():
        s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p

    asyncio.get_running_loop().create_task(monitor())
    loop = asyncio.get_running_loop()
    reader = asyncio.StreamReader()
    await loop.connect_read_pipe(lambda: asyncio.StreamReaderProtocol(reader), sys.stdin)

    async def handle(req):
        op = req["op"]
        if op == "start":
            info = []
            for _ in range(req["count"]):
                mgr = TransportManager(); mgr.register("tcp", TCPTransport, TCPServer)
                node = MeshNode(mgr)
                port = free_port()
                await node.start([f"tcp://127.0.0.1:{port}"])
                nodes.append(node); got.append(set())
                loop.create_task(drain(len(nodes) - 1))
                info.append({"id": node.id.raw.hex(), "port": port})
            return info
        node = nodes[req["i"]] if "i" in req else None
        if op == "invite":
            return node.generate_invite()
        if op == "join":
            await node.join(f"tcp://127.0.0.1:{req['port']}", req["code"])
            await node.wait_for_session(timeout=req.get("timeout", 60.0))
            return True
        if op == "direct":
            target = NodeID.from_hex(req["to"])
            return any(p.authenticated_id == target and p.session is not None for p in node._peers)
        if op == "send":
            await node.send_data(NodeID.from_hex(req["to"]), bytes.fromhex(req["payload"]))
            return True
        if op == "attempt":
            return node._e2e_attempt.get(NodeID.from_hex(req["to"]))
        if op == "got":
            return bytes.fromhex(req["payload"]) in got[req["i"]]
        if op == "kill":
            await node.stop()
            return True
        if op == "links":
            return len({p.authenticated_id for p in node._peers if p.session is not None and p.authenticated_id})
        if op == "counters":
            live = [n for n in nodes if n._running]
            return {"out": sum(n._metrics.total.pkts_out for n in live),
                    "relayed": sum(n._metrics.total.pkts_relayed for n in live)}
        if op == "lag":
            s = sorted(lags); lags.clear()
            return {"p99": s[int(len(s) * 0.99)] if s else 0.0, "max": s[-1] if s else 0.0}
        raise ValueError(op)

    while True:
        line = await reader.readline()
        if not line:
            return
        req = json.loads(line)
        try:
            res = {"ok": await handle(req)}
        except Exception as exc:
            res = {"err": f"{type(exc).__name__}: {exc}"}
        out.write(json.dumps(res) + "\n")


# ---------------------------------------------------------------- parent ----

class Worker:
    def __init__(self, proc):
        self.proc = proc
        self.lock = asyncio.Lock()

    async def call(self, **req):
        async with self.lock:
            self.proc.stdin.write((json.dumps(req) + "\n").encode())
            await self.proc.stdin.drain()
            while True:
                line = await self.proc.stdout.readline()
                if not line:
                    raise RuntimeError("worker died")
                try:
                    res = json.loads(line)
                except ValueError:
                    continue
                if "err" in res:
                    raise RuntimeError(res["err"])
                return res["ok"]


async def parent(args) -> None:
    rnd = random.Random(args.seed)
    env = dict(os.environ)
    workers = []
    for _ in range(args.procs):
        proc = await asyncio.create_subprocess_exec(
            sys.executable, os.path.abspath(__file__), "--worker", "--src", args.src,
            stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL, env=env)
        workers.append(Worker(proc))
    per = [args.nodes // args.procs + (1 if i < args.nodes % args.procs else 0) for i in range(args.procs)]
    infos = await asyncio.gather(*[w.call(op="start", count=c) for w, c in zip(workers, per)])
    nodes = []                       # global index -> (worker, local index, id, port)
    for wi, info in enumerate(infos):
        for li, item in enumerate(info):
            nodes.append((workers[wi], li, item["id"], item["port"]))
    order = list(range(len(nodes)))
    rnd.shuffle(order)               # spread early (hub) nodes over the workers
    t0 = time.monotonic()
    failed = 0
    built = []
    for g in order:
        if built:
            for host in rnd.sample(built, min(args.degree, len(built))):
                hw, hl, _, hport = nodes[host]
                jw, jl, _, _ = nodes[g]
                try:
                    code = await hw.call(op="invite", i=hl)
                    await jw.call(op="join", i=jl, port=hport, code=code, timeout=30.0)
                except Exception:
                    failed += 1
        built.append(g)
    print(f"built {len(nodes)} nodes on {args.procs} processes in {time.monotonic() - t0:.0f}s, "
          f"{failed} joins failed", flush=True)
    async def counters():
        rows = await asyncio.gather(*[w.call(op="counters") for w in workers])
        return sum(r["out"] for r in rows), sum(r["relayed"] for r in rows)

    c0 = await counters()
    await asyncio.sleep(args.settle)
    c1 = await counters()
    print(f"idle: {(c1[0] - c0[0]) / args.settle / len(nodes):.1f} packets/s/node sent, "
          f"{(c1[1] - c0[1]) / args.settle / len(nodes):.2f} relayed for others", flush=True)
    await asyncio.gather(*[w.call(op="lag") for w in workers])      # reset
    c2 = await counters()

    alive = list(range(len(nodes)))
    if args.kill:
        dead = rnd.sample(alive, int(len(alive) * args.kill))
        await asyncio.gather(*[nodes[d][0].call(op="kill", i=nodes[d][1]) for d in dead])
        alive = [g for g in alive if g not in set(dead)]
        print(f"killed {len(dead)} nodes, {len(alive)} left; waiting {args.heal}s", flush=True)
        await asyncio.sleep(args.heal)

    results, retried = [], []
    for _ in range(args.pairs):
        for _try in range(1000):
            a, b = rnd.sample(alive, 2)
            if not await nodes[a][0].call(op="direct", i=nodes[a][1], to=nodes[b][2]):
                break
        payload = os.urandom(24).hex()
        t = time.monotonic()
        await nodes[a][0].call(op="send", i=nodes[a][1], to=nodes[b][2], payload=payload)
        first = await nodes[a][0].call(op="attempt", i=nodes[a][1], to=nodes[b][2])
        got = None
        while time.monotonic() - t < args.wait:
            if await nodes[b][0].call(op="got", i=nodes[b][1], payload=payload):
                got = time.monotonic() - t
                break
            await asyncio.sleep(0.05)
        last = await nodes[a][0].call(op="attempt", i=nodes[a][1], to=nodes[b][2])
        retried.append(last is not None and last != first)
        results.append(got)
    lags = await asyncio.gather(*[w.call(op="lag") for w in workers])
    c3 = await counters()
    print(f"during the {args.pairs} first contacts: {c3[0] - c2[0]} packets sent in all, "
          f"{c3[1] - c2[1]} of them relayed", flush=True)
    ok = sorted(r for r in results if r is not None)
    fast = sum(1 for r in ok if r < 1.0)
    print(f"{'killed ' + str(args.kill) if args.kill else 'healthy'}: first contacts {len(ok)}/{args.pairs} within {args.wait:.0f}s, "
          f"<1s: {fast}, median {ok[len(ok) // 2] if ok else float('nan'):.2f}s, "
          f"p90 {ok[int(len(ok) * .9)] if ok else float('nan'):.2f}s, max {ok[-1] if ok else float('nan'):.1f}s | "
          f"needed a retry: {sum(retried)}/{args.pairs} | "
          f"worst loop lag p99 {max(l['p99'] for l in lags) * 1000:.0f}ms, max {max(l['max'] for l in lags) * 1000:.0f}ms",
          flush=True)
    for w in workers:
        w.proc.kill()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--worker", action="store_true")
    ap.add_argument("--src", default=_TREE, help="the tree whose nodes are run")
    ap.add_argument("--procs", type=int, default=8)
    ap.add_argument("--nodes", type=int, default=240)
    ap.add_argument("--degree", type=int, default=2)
    ap.add_argument("--pairs", type=int, default=100)
    ap.add_argument("--wait", type=float, default=10.0)
    ap.add_argument("--settle", type=float, default=20.0)
    ap.add_argument("--heal", type=float, default=15.0)
    ap.add_argument("--kill", type=float, default=0.0)
    ap.add_argument("--seed", type=int, default=1)
    args = ap.parse_args()
    asyncio.run(worker(args.src) if args.worker else parent(args))
