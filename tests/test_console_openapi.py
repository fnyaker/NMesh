"""The scanner's map of the console (`tests/zap/console_openapi.py`) is not
empty, and names the routes the pages call."""
from tests.zap.console_openapi import document


def test_it_lists_the_api_the_pages_call():
    paths = document("https://node:8787")["paths"]
    assert len(paths) >= 40
    assert "/api/fleet/password" in paths and "post" in paths["/api/fleet/password"]
    assert all(path.startswith("/api/") for path in paths)
