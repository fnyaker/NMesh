"""The transports: the contract, and the media that honour it.

A transport is the layer that moves bytes between two nodes, and NMesh is
agnostic about what moves them — TCP, UDP, a directory on a USB stick, and
whatever somebody writes next. This package holds the *contract* and the
transports that ship with the node, and nothing else, so that the whole of what
a new medium must satisfy is in one directory a person can read in an evening.

Layout, and why each file is here:

``contract.py``
    ``BaseTransport`` and ``BaseServer`` — the abstract methods a medium
    implements, and the ``OPTIONS``/``configure()`` shape that makes every
    medium configurable from the console for free. **This file is the
    specification.** Its docstrings are the contract; the guide in
    ``Docs/Transports/guide`` restates it for a human, and if the two disagree
    the code is the one that is right.

``medium.py``
    Every question the core asks a medium, asked once, here — and the answer
    checked on the way back. A transport is somebody else's code (see the
    threat model), so an annotation like ``-> str | None`` is a note between
    people who agree, not a guarantee: a medium that returns a megabyte where an
    address belongs must not be able to put it in a snapshot or a counter.

``manager.py``
    The registry: a scheme (``tcp``, ``udp``, ``spool``…) to a
    ``(transport, server)`` pair, plus the listeners a node currently holds.

``tcp.py``, ``udp.py``, ``spool.py``
    The three media the node ships. Each is written to be read: the module
    docstring says what the medium is *for* and what it cannot do, before any
    code.

``bundle.py``
    Store-and-forward primitives — the file container for a medium that is
    physically carried. Not a transport (it does not speak ``BaseTransport``);
    it is the format the spool transport reads and writes.

**What is deliberately not here.** ``RelayedTransport`` lives in
``src/mesh/peers.py``, beside the link it tunnels through. It satisfies
``BaseTransport`` but it is not a medium — it is core routing wearing the
transport interface, a link that is another node carrying frames. Putting it in
this directory would teach the wrong lesson to the one reader this directory is
for: somebody writing a medium by hand would find an example that is not one.

There is no ``__all__`` here, and no imports of the concrete transports: a
module is not loaded until something asks for it by name. That is what lets a
node run without liboqs' dependencies for a medium it never uses, and it is why
``src/transports/__init__.py`` is a map rather than a manifest.
"""
