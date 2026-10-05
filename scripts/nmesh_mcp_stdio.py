#!/usr/bin/env python3
"""
Carry MCP between a client that speaks stdio and a node's MCP server.

Some MCP clients start a server as a child process and talk to it over its
standard input and output, one JSON-RPC message per line. The node's MCP app
speaks HTTP. This is the pipe between the two: a line in, POSTed to the node,
its answer out — nothing parsed beyond what that takes, nothing kept.

    NMESH_MCP_URL=http://127.0.0.1:8790/mcp \\
    NMESH_MCP_TOKEN=mcp-… \\
    python3 scripts/nmesh_mcp_stdio.py

Both values are shown on the node's console: Apps → Internal API → Show the
client configuration. Standard library only, like the rest of the node.
"""
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request

MAX_LINE = 1024 * 1024        # what the server takes in one request
TIMEOUT = 630.0               # a tool that runs a job may take ten minutes


def _error(ident, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": ident,
            "error": {"code": -32603, "message": message[:300]}}


def forward(url: str, token: str, line: bytes):
    """One message to the server; its answer, ``None`` for a notification."""
    request = urllib.request.Request(url, data=line, method="POST")
    request.add_header("Content-Type", "application/json")
    request.add_header("Accept", "application/json")
    request.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
            body = response.read(MAX_LINE * 8)
    except urllib.error.HTTPError as exc:
        body = exc.read(MAX_LINE)
        try:
            parsed = json.loads(body or b"null")
        except ValueError:
            parsed = None
        if isinstance(parsed, dict) and parsed.get("jsonrpc") == "2.0":
            return parsed
        return _error(_ident(line), f"the node answered {exc.code}: "
                                    f"{(parsed or {}).get('error', '') if isinstance(parsed, dict) else ''}")
    except (urllib.error.URLError, OSError) as exc:
        return _error(_ident(line), f"the node could not be reached: {exc}")
    if not body:
        return None
    try:
        return json.loads(body)
    except ValueError:
        return _error(_ident(line), "the node answered something that is not JSON")


def _ident(line: bytes):
    try:
        message = json.loads(line)
    except ValueError:
        return None
    return message.get("id") if isinstance(message, dict) else None


def main() -> int:
    url = os.environ.get("NMESH_MCP_URL", "http://127.0.0.1:8790/mcp")
    token = os.environ.get("NMESH_MCP_TOKEN", "")
    if not token:
        print("NMESH_MCP_TOKEN is not set — copy it from the node's console "
              "(Apps → Internal API)", file=sys.stderr)
        return 2
    for raw in sys.stdin.buffer:
        line = raw.strip()
        if not line:
            continue
        if len(line) > MAX_LINE:
            answer = _error(None, "message too large")
        else:
            answer = forward(url, token, line)
        if answer is not None:
            sys.stdout.write(json.dumps(answer) + "\n")
            sys.stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
