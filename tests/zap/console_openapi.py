"""
Describe the console's API for a scanner: every route a page actually calls.

ZAP's spider follows links, and the console's API is reached only from
JavaScript (``fetch``), so a spidered scan tests seven static files and none of
the API. This lists the routes the bundles call (``app_web.routes_in``, the
same reading the MCP server uses) as an OpenAPI document ZAP can import:

    python -m tests.zap.console_openapi https://node:8787 > openapi.json

``.github/workflows/audit.yml`` runs the scan weekly against a throwaway node.
"""
from __future__ import annotations

import json
import sys

from src import app_web, webassets

_NODE = "ab" * 20


def document(server: str) -> dict:
    bundle = "".join(getattr(webassets, name, "") for name in dir(webassets)
                     if name.endswith("_JS"))
    paths: dict = {}
    for method, path in app_web.routes_in(bundle, "/api/"):
        operation = {"responses": {"200": {"description": "ok"}}}
        if method == "GET":
            operation["parameters"] = [{"name": "node", "in": "query",
                                        "schema": {"type": "string"}, "example": _NODE}]
        else:
            operation["requestBody"] = {"content": {"application/json": {"schema": {
                "type": "object", "properties": {
                    "node": {"type": "string", "example": _NODE},
                    "path": {"type": "string", "example": "/tmp"},
                    "name": {"type": "string", "example": "x"}}}}}}
        paths.setdefault(path, {})[method.lower()] = operation
    return {"openapi": "3.0.0", "info": {"title": "NMesh console", "version": "1"},
            "servers": [{"url": server}], "paths": paths}


if __name__ == "__main__":
    json.dump(document(sys.argv[1] if len(sys.argv) > 1 else "https://127.0.0.1:8787"),
              sys.stdout, indent=1)
