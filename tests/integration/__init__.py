"""Helpers shared by the integration tests."""
import socket


def free_port(count: int = 1) -> int:
    """Reserve ``count`` consecutive free TCP ports on loopback, return the first.

    Tests used to guess with ``random.randint(20000, 40000)``, which collides
    with a port another xdist worker already bound — and ``MeshNode.start``
    swallows a bind failure, so the node silently never listens and the test
    fails much later with a confusing "connection refused" (see gotchas: ports).
    """
    held: list[socket.socket] = []
    try:
        while True:
            first = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            first.bind(("127.0.0.1", 0))
            held.append(first)
            base = first.getsockname()[1]
            if count == 1:
                return base
            # Consecutive block: if a follow-on port is taken, drop this base
            # and try again from a fresh one.
            taken = 1
            for offset in range(1, count):
                nxt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                try:
                    nxt.bind(("127.0.0.1", base + offset))
                except OSError:
                    nxt.close()
                    break
                held.append(nxt)
                taken += 1
            if taken == count:
                return base
    finally:
        for s in held:
            s.close()
