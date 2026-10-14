"""
The HTTP server the console, the chat page and the MCP app each run.

``ThreadingHTTPServer`` accepts in one thread and serves each connection in its
own, and nothing in it assumes the other end is hostile. Three things follow,
each of which an unauthenticated client can use:

* **The TLS handshake belongs to the connection, not to the accept loop.** A
  listening socket wrapped for TLS handshakes inside ``accept()``, so one client
  that connects and says nothing holds the only accepting thread, and nobody
  else is served until it hangs up. The wrap here is lazy: ``accept()`` returns
  at once and the handshake runs in the connection's own thread.
* **A connection that says nothing is let go.** ``timeout`` is the handler's to
  set (it becomes the socket's); without one a silent client keeps its thread
  for ever.
* **The number of connections is bounded, in total and per address.** A thread
  each is fine for a console one person uses and a way to run a machine out of
  memory for one anybody can reach; past `MAX_CONNECTIONS` a new connection is
  closed before it costs one. The total alone is not enough: one client holding
  open requests it never finishes takes every slot, and the bound that was meant
  to protect the machine becomes the way to stop the console. So one address is
  held to `MAX_PER_ADDRESS` of them.

And a client that hangs up mid-request is not a fault of ours: the default
``handle_error`` writes a traceback of it to stderr, about 1.4 kB per connection,
for as long as anybody cares to reset connections.
"""
from __future__ import annotations

import socket
import ssl
import sys
import threading
from http.server import ThreadingHTTPServer

# How long a connection may stay silent before it is closed: a request line, the
# rest of its headers, or the next request on a connection kept open.
CONNECTION_TIMEOUT = 30.0
# Connections served at once. A console has a handful of people and a page's few
# parallel requests; this is generous for that and a bound for the rest.
MAX_CONNECTIONS = 256
# …of which one address may hold this many. A browser opens a handful, a page's
# event stream and its parallel requests included.
MAX_PER_ADDRESS = 32


class HardenedServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, handler, *, max_connections: int | None = None) -> None:
        self._slots = threading.BoundedSemaphore(max_connections or MAX_CONNECTIONS)
        self._held: dict[str, int] = {}
        self._held_lock = threading.Lock()
        super().__init__(address, handler)

    def wrap_tls(self, context: ssl.SSLContext) -> None:
        """Serve TLS, with each connection's handshake left to its own thread."""
        self.socket = context.wrap_socket(self.socket, server_side=True,
                                          do_handshake_on_connect=False)

    def _take(self, client_address) -> bool:
        who = str(client_address[0]) if client_address else ""
        with self._held_lock:
            if self._held.get(who, 0) >= MAX_PER_ADDRESS:
                return False
            if not self._slots.acquire(blocking=False):
                return False
            self._held[who] = self._held.get(who, 0) + 1
            return True

    def _give_back(self, client_address) -> None:
        who = str(client_address[0]) if client_address else ""
        with self._held_lock:
            left = self._held.get(who, 0) - 1
            if left > 0:
                self._held[who] = left
            else:
                self._held.pop(who, None)
        self._slots.release()

    def process_request(self, request: socket.socket, client_address) -> None:
        if not self._take(client_address):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._give_back(client_address)
            raise

    def process_request_thread(self, request, client_address) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._give_back(client_address)

    def handle_error(self, request, client_address) -> None:
        exc = sys.exc_info()[1]
        if isinstance(exc, (ConnectionError, TimeoutError, ssl.SSLError, EOFError)):
            return                  # the other end left; there is nothing to report
        super().handle_error(request, client_address)
