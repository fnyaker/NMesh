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
