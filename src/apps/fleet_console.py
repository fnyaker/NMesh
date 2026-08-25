"""
Loopback client for this node's *own* console.

The ``manage`` capability lets an operator drive this node's web console from
theirs. The temptation is to answer those calls inside the app — read the state,
apply the config, hand it back. That would be a **second front door**, with its
own idea of what a session is, its own body limits, and its own bugs.

So the app does the opposite: it replays the request against the real console
over the loopback, exactly as a browser on this machine would. Session checks,
body caps, the login lockout, every route and every refusal are the ones already
written and already tested. The app is a pipe, not an authority.

Two properties make the pipe safe to point at ourselves:

* **The certificate is pinned.** The console's TLS certificate is self-signed,
  so there is no chain to validate; instead the connection is compared against
  the fingerprint the console itself computed. A process squatting the port
  cannot answer in its place.
* **Nothing here is a shortcut.** No token is minted, no check is skipped: the
  caller's token travels with the request and the console decides.
"""
from __future__ import annotations

import asyncio
import hashlib
import http.client
import json
import ssl
import threading

# A proxied call is a local HTTP request; it should take milliseconds. The
# ceiling exists so a wedged console cannot pin a mesh handler for ever.
CALL_TIMEOUT = 20.0
READ_MAX = 512 * 1024


class ConsoleError(Exception):
    """The loopback call could not be made — never the console's own answer."""


async def bounded(call, timeout: float = CALL_TIMEOUT):
    """Await a blocking call in a daemon thread that is never joined.

    Not ``to_thread`` / ``run_in_executor``: asyncio joins its default executor
    at shutdown, so one stuck socket would hang the process on the way out
    (``Docs/Architecture/gotchas.md`` §2). On timeout the thread is abandoned.
    """
    loop = asyncio.get_running_loop()
    future: asyncio.Future = loop.create_future()

    def worker() -> None:
        try:
            outcome = call()
        except BaseException as exc:            # noqa: BLE001 — relayed
            outcome = exc
        if not loop.is_closed():
            loop.call_soon_threadsafe(
                lambda: future.done() or future.set_result(outcome))

    threading.Thread(target=worker, name="nmesh-console-proxy",
                     daemon=True).start()
    try:
        outcome = await asyncio.wait_for(future, timeout)
    except asyncio.TimeoutError:
        raise ConsoleError("the console did not answer in time") from None
    if isinstance(outcome, BaseException):
        raise outcome
    return outcome


class LocalConsole:
    """Calls the console of *this* node, over the loopback interface.

    Bound after the fact: the fleet app is built before the console exists, and
    an app that held a half-built console would be worse than one that reports
    the capability unavailable until it is ready."""

    def __init__(self) -> None:
        self._console = None

    def bind(self, console) -> None:
        self._console = console

    @property
    def available(self) -> bool:
        return self._console is not None and bool(getattr(self._console, "port", 0))

    # -- the call ---------------------------------------------------------

    def _connection(self, timeout: float):
        console = self._console
        if console is None:
            raise ConsoleError("no console on this node")
        # A console bound to every interface is still reachable on loopback, and
        # loopback is the one address that cannot be someone else's machine.
        host = console.host
        if host in ("", "0.0.0.0", "::"):
            host = "127.0.0.1"
        if not getattr(console, "_use_tls", False):
            return http.client.HTTPConnection(host, console.port, timeout=timeout)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        # Self-signed by design: there is no chain to check, so the identity is
        # the fingerprint, compared below on the live socket.
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return http.client.HTTPSConnection(host, console.port, timeout=timeout,
                                           context=context)

    def _verify(self, connection) -> None:
        expected = getattr(self._console, "cert_fingerprint", None)
        if not expected:
            return                       # plain HTTP: nothing to pin
        socket = getattr(connection, "sock", None)
        der = socket.getpeercert(binary_form=True) if socket else None
        if not der:
            raise ConsoleError("could not read the console's certificate")
        if hashlib.sha256(der).hexdigest() != expected:
            raise ConsoleError("the console's certificate does not match")

    def call(self, method: str, path: str, body: bytes | None,
             token: str | None, *, timeout: float = CALL_TIMEOUT) -> tuple:
        """``(status, content_type, body)`` — blocking, run it through
        :func:`bounded`."""
        connection = self._connection(timeout)
        try:
            connection.connect()
            if getattr(self._console, "_use_tls", False):
                self._verify(connection)
            headers = {"Accept": "application/json"}
            if token:
                headers["Authorization"] = "Bearer " + token
            if body is not None:
                headers["Content-Type"] = "application/json"
                headers["Content-Length"] = str(len(body))
            connection.request(method, path, body=body, headers=headers)
            response = connection.getresponse()
            payload = response.read(READ_MAX + 1)
            if len(payload) > READ_MAX:
                raise ConsoleError("that answer is too large to relay")
            ctype = response.getheader("Content-Type", "application/json")
            return response.status, ctype, payload
        except ConsoleError:
            raise
        except OSError as exc:
            raise ConsoleError(f"console unreachable: {exc.strerror or exc}") from None
        except Exception as exc:                # noqa: BLE001 — never leak a trace
            raise ConsoleError(f"console call failed: {type(exc).__name__}") from None
        finally:
            try:
                connection.close()
            except Exception:
                pass


def error_body(message: str) -> bytes:
    return json.dumps({"error": message[:200]}).encode("utf-8")
