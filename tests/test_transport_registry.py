"""The built-ins must actually arrive on the manager.

`src/transports/registry.py` is the single declaration point for the transports
that ship with the node: `register_all(manager)` is what a script, the console
and the update path all go through to get `tcp://`, `udp://` and `spool://`.

It imports each transport module lazily and **skips** one that will not import,
recording a fault instead of raising. That is deliberate — a medium whose
optional dependency is missing must not stop the node running the others — but
it has a sharp edge: a wrong module path is indistinguishable from "this medium
is unavailable here". The node comes up having registered nothing, the console
offers no transport, and nothing fails loudly.

That is exactly what happened. `import_module(f"{__name__}.{module}")` inside
`transports/registry.py` asks for `transports.registry.tcp`: the module's own
name is one level too deep to reach a *sibling*. Every built-in was skipped, and
a node updated from the branch came up with `tcp://` gone. The unit suite was
green throughout, because no test called `register_all` at all — the function
that every entry point uses was the one function nothing exercised.

These tests hold the declaration point itself, and assert on the **recorded
fault** rather than only on the symptom, so a failure names the missing medium
and its import error instead of just "a scheme is absent".
"""
import pytest

from src.transport_manager import TransportManager
from src.transports.registry import BUILT_IN, register_all


@pytest.fixture
def recorded_faults():
    """Capture `faults.note` calls for the duration of one test.

    The sink is process-global on purpose (`src/faults.py`: "stderr is one
    too"), so it is unhooked afterwards — a test that left it set would keep
    collecting the faults of every node started later in the same worker."""
    from src import faults

    seen: list[tuple[str, BaseException]] = []

    def sink(where, exc):
        seen.append((where, exc))

    faults.watch(sink)
    try:
        yield seen
    finally:
        faults.unwatch(sink)


class TestRegisterAll:
    def test_every_built_in_is_registered(self):
        """The whole point: what is declared is what arrives."""
        registered = set(register_all(TransportManager())._registry)
        expected = {scheme for scheme, _, _, _ in BUILT_IN}
        assert registered == expected

    def test_tcp_and_udp_are_among_them(self):
        """Named explicitly, and not only as set equality against `BUILT_IN`.

        A refactor that quietly truncated `BUILT_IN` — or that split the node's
        transports from a shorter list — would still satisfy an equality check
        against the truncated list. `tcp://` and `udp://` are what a node
        listens on, so they are held by name."""
        registered = register_all(TransportManager())._registry
        assert "tcp" in registered
        assert "udp" in registered
        assert "spool" in registered

    def test_each_entry_names_a_real_class(self):
        """`register_all` refuses an entry whose class is missing, and that
        refusal is a skip too. The declaration is checked directly against the
        modules, so a renamed class is caught as itself rather than as a
        missing scheme."""
        import importlib

        from src.transports import registry

        # `registry.__package__` is the sibling package (a standard attribute);
        # the bug was reaching for `__name__` instead, which is one deeper.
        package = registry.__package__
        for scheme, module_name, transport_name, server_name in BUILT_IN:
            module = importlib.import_module(f"{package}.{module_name}")
            assert hasattr(module, transport_name), (
                f"{scheme} declares transport class {transport_name}, "
                f"which {module.__name__} does not define")
            assert hasattr(module, server_name), (
                f"{scheme} declares server class {server_name}, "
                f"which {module.__name__} does not define")

    def test_nothing_is_lost_to_a_recorded_fault(self, recorded_faults):
        """The skip path must not be taken for the stock transports.

        Asserted on the fault, not the absence of a scheme, so the failure says
        *why* the medium went missing — the import error is already attached to
        the recorded fault."""
        register_all(TransportManager())
        lost = {
            where.rsplit(".", 1)[-1]: exc
            for where, exc in recorded_faults
            if where.startswith("transports.register.")
        }
        assert lost == {}, (
            "a built-in transport failed to import and was silently skipped; "
            f"register_all then brings the node up without it: {lost}")


def _blow_up_on(monkeypatch, module_name: str, exc: BaseException) -> None:
    """Make importing ``transports.<module_name>`` raise ``exc``, and nothing
    else. The failure has to happen inside the entry being tested, so only that
    one name is intercepted."""
    import importlib

    real = importlib.import_module

    def fake(name, *args, **kwargs):
        if name.endswith(f".{module_name}"):
            raise exc
        return real(name, *args, **kwargs)

    monkeypatch.setattr(importlib, "import_module", fake)


class TestOneEntryCannotCostTheOthers:
    """A declaration list is only worth having if one bad line is one bad line.

    Both cases below were real, and both lose an *arbitrary suffix* of the
    transport list rather than the one medium that misbehaved — which is why a
    node came up with a medium an operator could plainly see disappear, and no
    entry in the file that explained it.
    """

    def test_an_unexpected_import_error_does_not_abort_the_loop(self, monkeypatch):
        """Not everything that fails to load is an ``ImportError``.

        A native dependency that refuses to initialise raises ``RuntimeError``;
        a half-written file raises ``SyntaxError``. Catching only
        ``ImportError``/``AttributeError`` let those propagate — so the entries
        *after* the broken one were never registered at all.
        """
        _blow_up_on(monkeypatch, "udp", RuntimeError("liboqs init failed"))
        manager = register_all(TransportManager())

        # `spool` is declared after `udp`, so it is the entry that proves the
        # loop kept going rather than stopping where the failure was.
        assert manager.is_supported("tcp")
        assert manager.is_supported("spool")
        assert not manager.is_supported("udp")

    def test_a_refused_registration_does_not_abort_the_loop(self, monkeypatch):
        """``manager.register`` raises ``TransportError``, and it used to be
        called *outside* the guard.

        A scheme that some plug-in had already claimed therefore took every
        built-in declared after it down with it, although nothing was wrong
        with any of them.
        """
        from src.transports.manager import TransportError

        def refuse(scheme, transport_cls, server_cls):
            raise TransportError(f"scheme already registered: {scheme!r}")

        manager = TransportManager()
        monkeypatch.setattr(manager, "register", refuse)
        register_all(manager)

        # Nothing registered, but the call returned rather than raising: the
        # point is that the failure is contained per entry.
        assert manager.schemes() == []

    def test_a_contained_failure_is_recorded_not_swallowed(self, monkeypatch,
                                                          recorded_faults):
        """Containing a failure and *hiding* it are different things.

        The node must keep running the media it can, and the one it could not
        must be named in the faults — otherwise the console quietly offers one
        transport fewer and no machine can say why.
        """
        _blow_up_on(monkeypatch, "spool", OSError("no such directory"))
        register_all(TransportManager())

        recorded = {
            where.rsplit(".", 1)[-1]: exc
            for where, exc in recorded_faults
            if where.startswith("transports.register.")
        }
        assert set(recorded) == {"spool"}
        assert isinstance(recorded["spool"], OSError)
