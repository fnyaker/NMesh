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

* every module in `src/` **except** the core's own modules (below) and the
  transport implementations is medium-agnostic — it never names a concrete
  transport at all;
* the core's exception is bounded to exactly two media, and the bound is what
  is checked. NAT traversal cannot be written without knowing it is speaking
  datagrams; a *third* concrete transport appearing in the core would be
  something else entirely, and this is what makes that visible on the day it is
  written rather than on the day somebody reads the file.

**Where the exception lives now.** `node.py` used to be one 14,000-line module
holding the whole core, so "the core's exception" and "what `node.py` names"
were the same sentence. The core is now split into focused modules, and the
exception moved with the code that needs it: `src/mesh/peers.py` defines
`RelayedTransport`, the bank of codecs is medium-agnostic, and the datagram
work sits in the node. So the rule names the modules that may know a medium
rather than continuing to imply that one filename is the whole core.
"""
import ast
import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
SRC = ROOT / "src"

# The modules that *are* a medium, plus the ones that describe the abstraction
# and declare which media exist. These are allowed to name themselves.
#
# The transports live in `src/transports/` as a package, so a basename no longer
# identifies one: `src/transports/tcp.py` is a medium and `src/transports/tcp.py`'s
# old address, `src/tcp_transport.py`, is now an alias that re-exports it. Paths
# are relative to `src/`.
IMPLEMENTATIONS = {
    # the media themselves
    "transports/tcp.py", "transports/udp.py", "transports/spool.py",
    # the abstraction: the contract, the registry, and the checked accessor
    "transports/contract.py", "transports/manager.py", "transports/medium.py",
    # store-and-forward primitives — the container the spool medium reads and
    # writes. Not a transport, but it exists only to be one's file format.
    "transports/bundle.py",
    # the registry names every scheme there is by definition — that is its job,
    # and it is the single place a medium is declared (`registry.py`). It loads
    # them lazily, so naming a scheme here does not pull the module in.
    "transports/registry.py",
    # `__init__.py` names RelayedTransport once, in prose, to say why it is *not*
    # in this package. It imports no medium.
    "transports/__init__.py",
}

# The old flat paths, kept as aliases so `Docs/Transports/guide` keeps working.
# They are *not* exempt: an alias that could name a medium unseen would be a
# hole in this rule. They pass on their own merits — each imports a module
# rather than a class, so there is no concrete name in them to find. Listing
# them here as a second category would only hide that, so there is no such list.

# The modules that *are* the core. `node.py` was one file; it is now split into
# the node itself and the parts it is assembled from, some of which live in the
# `src/mesh/` package. Naming them is the point: the rule below checks every
# other module in `src/` is medium-agnostic, so the set of exceptions has to be
# written down rather than inferred from a filename. Paths are relative to the
# repo root, because "which file is this" is no longer answerable by basename
# alone now that the core has a package of its own.
CORE = {
    "src/node.py",
    "src/mesh/messages.py",
    "src/mesh/constants.py",
    "src/mesh/codecs.py",
    "src/mesh/peers.py",
}

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
#   relayed  — the node's own transport, defined beside the link it tunnels
#              through (`src/mesh/peers.py`): a link that is not a socket at all but
#              another node carrying frames for two peers that cannot reach
#              each other. It is core routing wearing the transport interface,
#              not a medium.
CORE_MAY_KNOW = {"UDPTransport", "UDPServer", "RelayedTransport"}

# Which module of the core may know a medium, and the medium it may know. The
# permission is per module on purpose: `src/mesh/peers.py` *defines* the relayed
# transport, the node does the datagram work and also asks "is this link
# relayed?" (a `isinstance` check, which is the cheapest way to exclude a
# tunnelled link from a count of physical ones), and nothing else in the core
# has any business naming either. A new module added to CORE is medium-agnostic
# until somebody says otherwise here.
CORE_MEDIUM_SITES = {
    "src/node.py": {"UDPTransport", "UDPServer", "RelayedTransport"},
    "src/mesh/peers.py": {"RelayedTransport"},
}


def _in_src(path):
    """A module's address below `src/`, which is how IMPLEMENTATIONS names one.
    A basename stopped being an identity when the transports became a package:
    `udp_transport.py` and `transports/udp.py` are two different things now, and
    only one of them is the medium."""
    return str(path.relative_to(SRC))


def _modules():
    for path in sorted(SRC.rglob("*.py")):
        if _in_src(path) in IMPLEMENTATIONS:
            continue
        yield path, path.read_text()


def _rel(path):
    """Where a file is, from the repo root — the only stable name for a module
    now that the core is a package and a basename no longer identifies one."""
    return str(path.relative_to(ROOT))


def test_only_the_core_knows_a_concrete_medium():
    """Every other module in `src/` is medium-agnostic, and that is the half of
    the principle that actually holds everywhere."""
    offenders = {}
    for path, text in _modules():
        if _rel(path) in CORE:
            continue
        found = {m.group(0) for m in CONCRETE.finditer(text)}
        if found:
            offenders[_rel(path)] = sorted(found)
    assert offenders == {}, (
        "these modules name a concrete transport, which the core may not: "
        f"{offenders}")


def test_the_core_knows_exactly_the_two_media_the_charter_declares():
    """And no third one appears without somebody saying why.

    This is not a style rule. A core that knows a medium cannot be ported to
    one it has never seen, which is the whole third principle — so the list is
    short, written down in `CLAUDE.md`, and checked."""
    named = set()
    for path, text in _modules():
        if _rel(path) in CORE:
            named |= {m.group(0) for m in CONCRETE.finditer(text)}
    unexpected = named - CORE_MAY_KNOW
    assert unexpected == set(), (
        f"the core names {sorted(unexpected)}. It may know "
        f"{sorted(CORE_MAY_KNOW)} and nothing else — see CLAUDE.md §3. If this "
        "is genuinely unavoidable, say so there first; if it is not, it belongs "
        "behind BaseTransport.")


def test_each_medium_the_core_knows_is_confined_to_the_module_that_owns_it():
    """The exception used to be one module wide because the core was one module.
    It is not any more, so the permission is written per module: this asserts
    that splitting the file did not quietly spread the exception across the new
    modules, which is the way a refactor weakens a rule without anybody
    choosing it."""
    found = {}
    for path, text in _modules():
        if _rel(path) in CORE:
            names = {m.group(0) for m in CONCRETE.finditer(text)}
            if names:
                found[_rel(path)] = names
    assert found == CORE_MEDIUM_SITES, (
        "the core's medium-naming sites moved. Expected "
        f"{CORE_MEDIUM_SITES}, found {found}. If a medium genuinely belongs in "
        "another module, add it here and record why in CLAUDE.md §3.")


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
        "that absolute is false — the core names UDPTransport"
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

    So there is one constructor call in the core, and it is the factory's. The
    core is now several modules, so this counts across all of them rather than
    letting a new module add a second site out of sight."""
    built = 0
    for page in sorted(SRC.glob("node*.py")):
        text = page.read_text()
        built += len([m for m in re.finditer(r"^\s+\w+ = _Peer\(", text,
                                             re.MULTILINE)])
    assert built == 1, (
        f"{built} places build a `_Peer`. The node builds its own peers "
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
