"""
The charter's own claims, held to.

`CLAUDE.md` is this project's specification, and several of the things it states
absolutely had nothing checking them at all — true today by somebody's
discipline, and free to stop being true tomorrow without a single test turning
red. A rule nothing reads is a wish.

These are written **from the charter's sentences**, not from what the code
happens to do. Each one quotes the clause it holds, so the day one fails the
argument is about the rule rather than about the assertion.

What is checked here: the supply chain, the language, the speed principle's
floor, and the two security absolutes that had exceptions nobody had written
down. What is checked elsewhere: transport-agnosticism
(`test_medium_agnostic.py`), no emoji in an interface (`test_webassets.py`), the
version in two files (`test_updater.py`), and the plane's reach
(`test_control_plane.py`).
"""
import ast
import pathlib
import re
import sys
import time
import unicodedata

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
SRC = ROOT / "src"


# ---------------------------------------------------------------------------
# "Minimal external dependencies. By default: the Python stdlib."
# ---------------------------------------------------------------------------

# The charter's list, verbatim: the runtime may import these and nothing else.
DECLARED = {"oqs", "cryptography"}
TESTING = {"pytest", "pytest_asyncio", "xdist", "_pytest"}


def test_the_runtime_imports_nothing_the_charter_did_not_admit():
    """"Every dependency is an attack surface (see the poisoned NPM/PyPI
    packages)." A list in prose that nothing enforces is how the third one
    arrives — not by decision, but in a commit that needed a helper."""
    extra = {}
    for path in sorted(SRC.rglob("*.py")):
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, ast.Import):
                names = [a.name.split(".")[0] for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0:
                names = [(node.module or "").split(".")[0]]
            else:
                continue
            for name in names:
                if (not name or name in sys.stdlib_module_names
                        or name in DECLARED or name in TESTING):
                    continue
                extra.setdefault(name, []).append(
                    str(path.relative_to(ROOT)))
    assert extra == {}, (
        f"the runtime imports {sorted(extra)}, which CLAUDE.md does not admit. "
        "Adding one is an explicit justification in the PR plus a line in that "
        "list — in that order.")


def test_the_charter_and_the_requirements_file_agree():
    """Two places name the dependencies. Two places are two chances to drift."""
    charter = (ROOT / "CLAUDE.md").read_text()
    required = {line.split("==")[0].split(">")[0].strip().lower()
                for line in (ROOT / "requirements.txt").read_text().splitlines()
                if line.strip() and not line.startswith("#")}
    runtime = {name for name in required if not name.startswith("pytest")}
    assert runtime == {"liboqs-python", "cryptography"}, runtime
    for name in runtime:
        assert f"`{name}`" in charter, f"{name} is installed and undeclared"


# ---------------------------------------------------------------------------
# "The project — code, comments, documentation, commit messages — is written
#  in English."
# ---------------------------------------------------------------------------

# What the project *demonstrates* is not what it is written in. Three places
# hold non-Latin text on purpose and every one of them is right to:
# `test_pseudo.py` proves a pseudonym may be a name in any script,
# `term_emulator_test.js` proves the terminal measures a wide glyph as two
# columns, and `behaviour-rules.md` spells out a homoglyph attack with a real
# Cyrillic letter. So quoted text and backticked spans are *data*, and the
# rule is about the prose around them — which is where a stray character
# actually slips through, because nobody reads it as content.
_QUOTED = re.compile(
    "'''.*?'''" r'|""".*?"""' r"|'[^'\n]*'" r'|"[^"\n]*"'
    r'|`[^`\n]*`' r'|```.*?```', re.DOTALL)


def _foreign_letters(text: str) -> set:
    """Letters from a script English does not use, in the prose.

    Deliberately not "non-ASCII": this project writes in real typography — em
    dashes, arrows, box drawing, the occasional accented loan word — and a test
    that banned those would be a test somebody switches off. What it catches is
    a *script* nobody meant to type, which is exactly how a stray character
    survives a review."""
    out = set()
    for ch in _QUOTED.sub(" ", text):
        if not ch.isalpha() or ord(ch) < 0x250:
            continue          # Latin, including every accented form
        name = unicodedata.name(ch, "")
        if name.split()[0] in ("LATIN", "GREEK", "COPTIC"):
            continue          # µ, Ω, π appear in units and in maths
        out.add(ch)
    return out


@pytest.mark.parametrize("where", ["src", "tests", "scripts", "Docs"])
def test_everything_is_written_in_english(where):
    offenders = {}
    root = ROOT / where
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix in (".pyc", ".png", ".svg"):
            continue
        try:
            found = _foreign_letters(path.read_text())
        except (UnicodeDecodeError, OSError):
            continue
        if found:
            offenders[str(path.relative_to(ROOT))] = sorted(found)
    assert offenders == {}, f"not English: {offenders}"


# ---------------------------------------------------------------------------
# "Hot paths with no superfluous allocation, no needless copy, no redundant
#  crypto."
# ---------------------------------------------------------------------------

def test_framing_a_packet_stays_fast_enough_to_be_beside_the_point():
    """A floor, not a benchmark.

    The charter quotes ~4 MB/s of end-to-end throughput to beat, which is a
    figure about a network and cannot be asserted on a build machine. What
    *can* is the part that is pure CPU and sits under every packet in and out:
    build, pack, unpack. It measures in the hundreds of MB/s, so a floor two
    orders of magnitude below that fails only for a real regression — an
    accidental copy per packet, a quadratic scan, a re-derived header — and
    never because a runner was busy.

    A test that would fail on a slow afternoon is a test somebody deletes."""
    from src.node_id import NodeID
    from src.packet import Packet

    src, dst = NodeID.generate().raw, NodeID.generate().raw
    payload = b"x" * 1200
    rounds = 5000
    started = time.perf_counter()
    for _ in range(rounds):
        Packet.unpack(Packet.create(0x00, src, dst, payload).pack())
    seconds = max(1e-9, time.perf_counter() - started)
    rate = rounds * len(payload) / seconds / 1e6
    assert rate > 20, (
        f"packet framing runs at {rate:.1f} MB/s. It measures in the hundreds; "
        "something on the hottest path in this project just became expensive.")


# ---------------------------------------------------------------------------
# "Secrets compared in constant time (`hmac.compare_digest`)."
# ---------------------------------------------------------------------------

class TestASessionTokenIsASecret:
    """It is compared on every single request, and it was compared by a dict
    lookup — which compares strings. The charter states the rule without an
    exception, so this is the exception nobody had written down."""

    def test_the_table_is_not_keyed_by_the_token(self):
        from src.webconsole import WebConsole

        source = (SRC / "webconsole.py").read_text()
        assert "_handle(token)" in source
        assert "hmac.compare_digest" in source
        # The handle is a digest, so what indexes the table cannot be inverted
        # into a session by anybody who can time a lookup.
        assert WebConsole._handle("abc") != "abc"
        assert len(WebConsole._handle("abc")) == 64

    async def test_a_wrong_token_of_the_right_shape_is_refused(self):
        node, console = await _console()
        try:
            issued = console._issue_token()
            assert console._valid_token(issued) is True
            # Same length, same alphabet, one character different: the case a
            # comparison that stops early tells an attacker about.
            near = issued[:-1] + ("A" if issued[-1] != "A" else "B")
            assert console._valid_token(near) is False
            assert console._valid_token("") is False
            assert console._valid_token(None) is False
        finally:
            console.stop()
            await node.stop()

    async def test_revoking_still_revokes(self):
        """The property the rewrite could quietly have broken."""
        node, console = await _console()
        try:
            kept, other = console._issue_token(), console._issue_token()
            assert console._revoke_all_tokens_except(kept) == 1
            assert console._valid_token(kept) is True
            assert console._valid_token(other) is False
            console._revoke_token(kept)
            assert console._valid_token(kept) is False
        finally:
            console.stop()
            await node.stop()


# ---------------------------------------------------------------------------
# "Counted per identity, not per link: a peer that reconnects to shed an
#  exhausted count is the whole point of counting."
# ---------------------------------------------------------------------------

class TestNoiseIsChargedToWhoeverSentIt:
    """Every violation in this product was charged to the identity *except*
    frames that would not decode, which were counted on the link and nowhere
    else — so an authenticated peer could send noise up to the cut, reconnect,
    and start again, for ever, with its standing never moving."""

    async def test_a_frame_that_will_not_decode_moves_the_senders_standing(self):
        """Through the receive loop, because that is the path that was wrong.

        Asserting on `_charge_identity` alone would prove the function exists.
        What the charter asks is that noise arriving on a real link reach the
        identity's book, so the noise arrives on a real link."""
        import asyncio

        from src.node import MeshNode
        from src.node_id import NodeID
        from src.packet import PacketError
        from tests.conftest import FakeTransport, make_manager

        class _Garbage(FakeTransport):
            """A link that is up and says nothing decodable — which is what a
            peer sending noise looks like from in here."""

            async def receive(self):
                raise PacketError("bad frame")

        node = MeshNode(transport_manager=make_manager())
        try:
            peer = await node._inject_peer(_Garbage())
            peer.authenticated_id = NodeID.generate()
            before = node._reputation.score(peer.authenticated_id)
            deadline = asyncio.get_event_loop().time() + 2.0
            while (peer._malformed < 3
                   and asyncio.get_event_loop().time() < deadline):
                await asyncio.sleep(0.01)
            assert peer._malformed >= 3, "the link was not charged either"
            after = node._reputation.score(peer.authenticated_id)
            # The *score*, not the standing: crossing to "suspect" is a
            # threshold this test has no business restating. What the charter
            # asks is that the identity be charged at all, which is this.
            assert after > before, (
                "noise on a live link left the sender's score untouched — so a "
                "peer sheds its whole allowance by reconnecting")
        finally:
            await node.stop()

    async def test_an_unauthenticated_peer_is_charged_on_the_link_only(self):
        """There is nothing else to charge: a peer with no identity has not
        given us one to remember."""
        from src.node import MeshNode
        from tests.conftest import FakeTransport, make_manager

        node = MeshNode(transport_manager=make_manager())
        try:
            peer = node._new_peer(FakeTransport(), is_client_side=True)
            peer._charge_identity()          # must not raise, must do nothing
            assert peer.note_abuse() is False
        finally:
            await node.stop()


async def _console():
    from src.node import MeshNode
    from src.webconsole import WebConsole
    from tests.conftest import make_manager
    import asyncio

    node = MeshNode(transport_manager=make_manager())
    console = WebConsole(node, host="127.0.0.1", port=0, use_tls=False,
                         password="correct-horse-battery-staple")
    console.start(loop=asyncio.get_running_loop())
    return node, console
