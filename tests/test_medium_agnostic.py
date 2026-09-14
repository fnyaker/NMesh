"""
The core is medium-agnostic — stated as an invariant rather than as a hope.

`CLAUDE.md` §3 is the specification: anyone implements `BaseTransport` +
`BaseServer` and registers it by URL scheme, and the core is supposed not to
know what any of them are. It used to say the core knows **no** concrete
transport, full stop, and that sentence was false: `src/node.py` names
`UDPTransport` in thirty-three functions and defines `RelayedTransport` itself.
`Docs/Architecture/transports.md` admitted as much in a heading — "NAT hole
punching (in `node.py`)" — so the two documents disagreed, and nothing held
either of them to anything.

These tests hold the *corrected* claim, which is narrower and true:

* every module in `src/` **except** `node.py` and the transport implementations
  is medium-agnostic — it never names a concrete transport at all;
* `node.py`'s exception is bounded to exactly two media, and the bound is what
  is checked. NAT traversal cannot be written without knowing it is speaking
  datagrams; a *third* concrete transport appearing in the core would be
  something else entirely, and this is what makes that visible on the day it is
  written rather than on the day somebody reads the file.

Written from the charter and not from the code, which is the point: if the code
grows a new dependency on a medium, this fails and somebody has to either
justify it in `CLAUDE.md` or take it out.
"""
import ast
import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
SRC = ROOT / "src"

# The modules that *are* a medium, plus the two that describe the abstraction.
# These are allowed to name themselves.
IMPLEMENTATIONS = {"udp_transport.py", "tcp_transport.py", "spool_transport.py",
                   "transport.py", "transport_manager.py", "medium.py"}

# Anything that names one particular way of moving bytes.
CONCRETE = re.compile(
    r"\b(UDPTransport|TCPTransport|SpoolTransport|RelayedTransport|UDPServer"
    r"|TCPServer|SpoolServer)\b|\b(udp|tcp|spool)_transport\b")

# What `CLAUDE.md` §3 declares the core may know, and why.
#
#   udp      — NAT traversal. A hole is punched through a *stateful datagram*
#              NAT by sending from the same socket the listener owns; there is
#              no medium-agnostic spelling of that, and a transport interface
#              general enough to express it would be a UDP interface with
#              another name.
#   relayed  — the node's own transport, defined in `node.py`: a link that is
#              not a socket at all but another node carrying frames for two
#              peers that cannot reach each other. It is core routing wearing
#              the transport interface, not a medium.
CORE_MAY_KNOW = {"UDPTransport", "UDPServer", "udp_transport", "RelayedTransport"}


def _modules():
    for path in sorted(SRC.rglob("*.py")):
        if path.name in IMPLEMENTATIONS:
            continue
        yield path, path.read_text()


def test_only_the_node_knows_a_concrete_medium():
    """Every other module in `src/` is medium-agnostic, and that is the half of
    the principle that actually holds everywhere."""
    offenders = {}
    for path, text in _modules():
        if path.name == "node.py":
            continue
        found = {m.group(0) for m in CONCRETE.finditer(text)}
        if found:
            offenders[str(path.relative_to(ROOT))] = sorted(found)
    assert offenders == {}, (
        "these modules name a concrete transport, which the core may not: "
        f"{offenders}")


def test_the_node_knows_exactly_the_two_media_the_charter_declares():
    """And no third one appears without somebody saying why.

    This is not a style rule. A core that knows a medium cannot be ported to
    one it has never seen, which is the whole third principle — so the list is
    short, written down in `CLAUDE.md`, and checked."""
    text = (SRC / "node.py").read_text()
    named = {m.group(0) for m in CONCRETE.finditer(text)}
    unexpected = named - CORE_MAY_KNOW
    assert unexpected == set(), (
        f"src/node.py names {sorted(unexpected)}. The core may know "
        f"{sorted(CORE_MAY_KNOW)} and nothing else — see CLAUDE.md §3. If this "
        "is genuinely unavoidable, say so there first; if it is not, it belongs "
        "behind BaseTransport.")


def test_the_charter_and_the_transports_document_say_the_same_thing():
    """They did not. The charter said the core knows *no* concrete transport;
    `transports.md` had a section headed "NAT hole punching (in `node.py`)".
    Documentation that contradicts documentation is worse than either."""
    charter = (ROOT / "CLAUDE.md").read_text()
    transports = (ROOT / "Docs" / "Architecture" / "transports.md").read_text()
    # The charter must name the exception rather than deny it.
    assert "NAT traversal" in charter, \
        "CLAUDE.md §3 must name the one exception it allows"
    assert "knows **no** concrete transport" not in charter, \
        "that absolute is false — src/node.py names UDPTransport"
    # And the document that describes the exception must point back at it.
    assert "CLAUDE.md" in transports, \
        "transports.md must cite the charter clause that permits this"


def test_every_declared_medium_is_reached_only_through_the_interface():
    """A transport's *methods* are called through `BaseTransport` or through
    `src/medium.py`, never by reaching into another module's privates.

    The exception above is about naming a class. It is not a licence to use one
    — `medium.py` exists precisely so that the answer a medium gives is checked
    wherever it comes from."""
    text = (SRC / "node.py").read_text()
    tree = ast.parse(text)
    lines = text.splitlines()
    # Private members of the *UDP* pair the punch path reaches into, which is
    # the concrete cost of the exception. Recorded so it cannot quietly grow.
    reaching = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Attribute) or not node.attr.startswith("_"):
            continue
        owner = node.value
        name = getattr(owner, "attr", None) or getattr(owner, "id", None)
        if name in ("_udp_server", "UDPTransport"):
            reaching.add(f"{name}.{node.attr}")
    allowed = {"_udp_server._sock", "_udp_server._transports",
               "UDPTransport._from_server"}
    assert reaching <= allowed, (
        f"src/node.py reaches into {sorted(reaching - allowed)}. Every new one "
        "is a place the punch path stops being portable — add it here only "
        "with a reason in CLAUDE.md §3.")


def test_a_peer_is_made_by_the_node_and_never_half_wired():
    """A `_Peer` needs three things from its node — where to count bytes, where
    to trace packets, who to tell when the link dies — and ten call sites set
    them by hand, three lines each. Five forgot `trace`, so the relay link and
    every relayed peer were invisible to the one diagnostic an operator turns
    on. Nobody chose that; the shape did.

    So there is one constructor call in the whole module, and it is the
    factory's."""
    text = (SRC / "node.py").read_text()
    built = re.findall(r"_Peer\(", text)
    # The class statement, its own type annotations and the factory. Anything
    # more is a second place that has to remember the wiring.
    made_outside = len([m for m in re.finditer(r"^\s+\w+ = _Peer\(", text,
                                               re.MULTILINE)])
    assert made_outside == 1, (
        f"{made_outside} places build a `_Peer`. The node builds its own peers "
        "(`_new_peer`) so a half-wired one cannot exist — see CLAUDE.md, "
        '"Name the thing, then count the thing".')


@pytest.mark.asyncio
async def test_every_peer_the_node_makes_can_be_traced():
    """The property the missing line cost, asserted on the node rather than on
    the number of assignments."""
    from src.node import MeshNode
    from tests.conftest import FakeTransport, make_manager

    node = MeshNode(transport_manager=make_manager())
    try:
        peer = node._new_peer(FakeTransport(), is_client_side=True)
        assert peer.trace is node.trace
        assert peer.total is node._metrics.total
        # `==`, not `is`: a bound method is a fresh object on every
        # attribute access, so identity is never true here.
        assert peer.on_dead == node._reap_peer
    finally:
        await node.stop()


def test_no_page_decides_anything_from_the_name_of_a_medium():
    """The console renders one block per transport scheme, from what the node
    says about each. It had one exception — `if(scheme !== "udp") return;`
    around the hole-punching panel — which is the same breach as the core's,
    one layer up, and it was *redundant*: the snapshot already carries
    `hole_punch` on whichever scheme can punch, so the page was deciding for
    itself something the node had already answered.

    A page that compares a scheme to a literal cannot render a medium nobody
    has written yet, which is the whole third principle seen from the browser.
    """
    from src import webassets

    # A decision about a **transport scheme**, which is what the rule is about.
    # Deliberately not every occurrence of the word: fleet's docker panel reads
    # `proto === "udp"` off a published port (`-p 8080:80/udp`), which is a
    # container's protocol and has nothing to do with how this node moves bytes.
    # A test that cannot tell those apart is a test somebody will switch off.
    bad = re.compile(r'\b(scheme|transport|medium)\w*\s*(===|!==|==|!=)\s*'
                     r'["\'](tcp|udp|spool|ble|lora|usb)["\']'
                     r'|["\'](tcp|udp|spool|ble|lora|usb)["\']\s*(===|!==|==|!=)\s*'
                     r'\b(scheme|transport|medium)\w*')
    offenders = []
    for name in ("APP_JS", "CHAT_JS", "FLEET_JS", "NODE_JS", "PKG_JS", "TERM_JS"):
        for number, line in enumerate(getattr(webassets, name).splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith(("//", "*", "/*")):
                continue            # a comment may name what it is explaining
            if bad.search(stripped):
                offenders.append(f"{name}:{number}  {stripped[:70]}")
    assert offenders == [], (
        "these decide from the name of a medium rather than from what the node "
        f"declared about it: {offenders}")


@pytest.mark.parametrize("module", ["tcp_transport", "udp_transport"])
def test_a_socket_over_ip_bundles_by_default(module):
    """Written from the decision, not from the constant: on TCP and on UDP a
    probe every hundred milliseconds is cheap, so multi-link operation is on
    and an operator turns it *off* for a metered or battery-powered link. The
    document that describes it has to agree — it said "off by default" in a
    heading for as long as that was true, and a heading is where somebody
    looks."""
    import importlib

    mod = importlib.import_module(f"src.{module}")
    cls = getattr(mod, "UDPTransport", None) or getattr(mod, "TCPTransport")
    mlo = next(o for o in cls.options() if o["name"] == "mlo")
    assert mlo["default"] is True, f"{module}: mlo should be on for a socket"

    doc = (ROOT / "Docs" / "Architecture" / "transports.md").read_text()
    assert "`mlo.py`, off by default" not in doc
    assert "**on by default**" in doc


def test_a_store_and_forward_medium_is_never_bundled():
    """The other half of the same decision, and the reason the default is a
    *per-medium* option rather than a node-wide switch: a spool is a directory
    somebody carries on a USB stick. It declares no `mlo` option at all, and
    that absence is the answer rather than a gap."""
    from src.spool_transport import SpoolTransport

    assert not any(o["name"] == "mlo" for o in SpoolTransport.options())
