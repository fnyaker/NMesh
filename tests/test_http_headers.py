"""
What a browser is told by every page this node serves: one policy
(`src/http_headers.py`), on the console and on chat's own server, and no
version of the interpreter in the `Server` line.
"""
import asyncio

import pytest

from src.http_headers import SECURITY_HEADERS
from src.node import MeshNode
from src.webconsole import WebConsole
from tests.conftest import make_manager
from tests.test_webconsole import _request


@pytest.fixture
async def console():
    node = MeshNode(transport_manager=make_manager())
    console = WebConsole(node, host="127.0.0.1", port=0, use_tls=False,
                         password="a-console-password")
    console.start(loop=asyncio.get_running_loop())
    try:
        yield console
    finally:
        console.stop()
        await node.stop()


@pytest.mark.parametrize("path", ["/", "/api/state", "/nowhere", "/robots.txt"])
async def test_every_answer_carries_the_policy(console, path):
    _status, headers, _body, _ = await asyncio.to_thread(_request, console, "GET", path)
    for name, value in SECURITY_HEADERS.items():
        assert headers.get(name.lower()) == value, name


async def test_the_server_line_names_no_interpreter(console):
    _status, headers, _body, _ = await asyncio.to_thread(_request, console, "GET", "/")
    assert headers["server"].strip() == "nmesh-console"


def test_chat_s_server_uses_the_same_policy_and_line():
    import inspect

    from src.apps import chat_web
    source = inspect.getsource(chat_web)
    assert "SECURITY_HEADERS.items()" in source
    assert 'sys_version = ""' in source


def test_no_hsts_on_a_self_signed_console():
    """Pinned by fingerprint; HSTS would make a regenerated certificate a
    console nobody can open."""
    assert "Strict-Transport-Security" not in SECURITY_HEADERS


def test_powerful_features_are_refused():
    policy = SECURITY_HEADERS["Permissions-Policy"]
    for feature in ("camera=()", "microphone=()", "geolocation=()", "usb=()"):
        assert feature in policy
