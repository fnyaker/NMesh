"""Throw hostile requests at a running node's console API and report what breaks.

    python tests/tools/api_fuzz.py https://host:8787 <password> [--rounds N]

Against a throwaway node only: it posts to every route the page's own scripts
call, signed in, and the routes that start work (fleet, chat, connect) are
reached with garbage. What it reports, and nothing else:

* a route that answers **without a session** with anything but a refusal;
* a **5xx** or a dropped connection on any hostile input;
* the node **no longer answering** after a batch.

Standard library only.
"""
from __future__ import annotations

import argparse
import http.client
import json
import os
import random
import ssl
import sys
import time
from collections import Counter
from urllib.parse import quote, urlsplit

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

_HUGE = "A" * 300_000
_DEEP = "[" * 400 + "]" * 400
_KEYS = ("node", "id", "name", "path", "text", "to", "cap", "caps", "host", "port", "user",
         "password", "image", "tail", "op", "since", "rid", "group", "members", "settings")


def _values(rnd: random.Random) -> list:
    return [None, True, False, 0, -1, 2**63, -2**63, 1e308, float("1e-320"), "", " ", "\x00",
            "a\x00b", "../../etc/passwd", "%00", "${jndi:ldap://x}", "' OR 1=1 --", "\ud800",
            "‮", "x" * 70_000, [], {}, [[]], {"a": {"b": {"c": None}}}, [None] * 5000,
            "ab" * 200, "0" * 40, "f" * 40, "f" * 64, "tcp://127.0.0.1:1", "-" * 3000,
            {"__proto__": {"x": 1}}, {"constructor": {"prototype": {}}}, list(range(300))]


def _bodies(rnd: random.Random) -> list[bytes]:
    out = [b"", b"null", b"[]", b"{}", b'"x"', b"1", b"{", b"{\"a\":", b"\xff\xfe\x00",
           _DEEP.encode(), ("{\"a\":" * 300 + "1" + "}" * 300).encode(),
           b'{"a":1,"a":2}', json.dumps({"x": _HUGE}).encode(), b"\x00" * 100]
    values = _values(rnd)
    for _ in range(14):
        body = {rnd.choice(_KEYS): rnd.choice(values) for _ in range(rnd.randint(1, 6))}
        try:
            out.append(json.dumps(body).encode())
        except (TypeError, ValueError):
            pass
    return out


class Client:
    def __init__(self, base: str) -> None:
        parts = urlsplit(base)
        self.host, self.port = parts.hostname, parts.port or 443
        self.tls = parts.scheme == "https"
        self.cookie = ""

    def request(self, method: str, path: str, body: bytes | None = None,
                auth: bool = True, headers: dict | None = None,
                timeout: float = 15.0) -> tuple[int, bytes] | tuple[str, str]:
        try:
            if self.tls:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                conn = http.client.HTTPSConnection(self.host, self.port, timeout=timeout, context=ctx)
            else:
                conn = http.client.HTTPConnection(self.host, self.port, timeout=timeout)
            head = dict(headers or {})
            if auth and self.cookie:
                head["Cookie"] = self.cookie
            if body is not None:
                head.setdefault("Content-Type", "application/json")
            conn.request(method, path, body=body, headers=head)
            response = conn.getresponse()
            data = response.read(65536)
            cookie = response.getheader("Set-Cookie")
            if cookie and not self.cookie and path == "/api/login":
                self.cookie = cookie.split(";", 1)[0]
            conn.close()
            return response.status, data
        except Exception as exc:                       # a refused/reset/timeout is a finding
            return "error", f"{type(exc).__name__}: {exc}"[:120]

    def login(self, password: str) -> bool:
        status, _ = self.request("POST", "/api/login", json.dumps({"password": password}).encode(),
                                 auth=False)
        return status == 200 and bool(self.cookie)

    def alive(self) -> bool:
        status, _ = self.request("GET", "/", auth=False, timeout=10.0)
        return status == 200


def routes(path_file: str | None) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    if path_file:
        for line in open(path_file):
            methods, _, path = line.strip().partition(" ")
            for method in methods.split(","):
                if method in ("GET", "POST") and path.startswith("/api/"):
                    found.append((method, path))
        return found
    from tests.zap.console_openapi import document
    for path, ops in document("https://x")["paths"].items():
        for method in ops:
            found.append((method.upper(), path))
    return found


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("base")
    ap.add_argument("password")
    ap.add_argument("--rounds", type=int, default=3)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--routes", help="file with 'METHOD[,METHOD] /path' lines")
    args = ap.parse_args()
    rnd = random.Random(args.seed)
    client = Client(args.base)
    table = routes(args.routes) + [("POST", "/api/control"), ("POST", "/api/trust"),
                                   ("POST", "/api/invite"), ("POST", "/api/logout-not")]
    findings: list[str] = []

    # 1. every route, no session.
    open_routes = Counter()
    for method, path in table:
        status, _ = client.request(method, path, b"{}" if method == "POST" else None, auth=False)
        open_routes[status] += 1
        if status not in (401, 403, 404, 405, 400):
            findings.append(f"NO-SESSION {method} {path} -> {status}")
    print(f"without a session: {dict(open_routes)}")

    if not client.login(args.password):
        print("login failed")
        return 2

    # 2. hostile bodies, signed in.
    seen = Counter()
    for round_no in range(args.rounds):
        for method, path in table:
            if path.endswith("/shell") or path == "/api/logout-not":
                continue
            for body in (_bodies(rnd) if method == "POST" else [None] * 6):
                target = path
                if method == "GET":
                    value = rnd.choice(_values(rnd))
                    target = f"{path}?{rnd.choice(_KEYS)}={quote(json.dumps(value)[:2000])}"
                status, data = client.request(method, target, body)
                seen[status if isinstance(status, int) else "conn-error"] += 1
                refusal = (status == 502 and b'"error"' in data)   # a relay refusal, not a crash
                if refusal:
                    seen["502-refusal"] += 1
                if not refusal and (status == "error" or (isinstance(status, int) and status >= 500)):
                    findings.append(f"{method} {path} -> {status} {str(data)[:90]!r} "
                                    f"body={(body or b'')[:60]!r}")
        if not client.alive():
            findings.append(f"NODE NOT ANSWERING after round {round_no}")
            break
    print(f"hostile requests: {dict(seen)}")
    unique = sorted(set(findings))
    print(f"{len(unique)} distinct findings")
    for line in unique[:60]:
        print("  ", line)
    return 1 if unique else 0


if __name__ == "__main__":
    sys.exit(main())
