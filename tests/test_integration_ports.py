"""
No two integration tests may listen on the same port.

The integration suite runs under `pytest-xdist` (`-n auto`, see the pyproject
addopts), so two tests in the same file are routinely alive at the same moment
on different workers. Two of them binding one port is a race: whichever loses
does not fail on what it was testing — it fails fifteen seconds later on
`wait_for_session`, which reads as "the mesh is flaky" rather than as "somebody
reused a number".

It is a bug that hides, too. Locally the pair may never overlap, so the suite is
green for weeks; on a busier runner it overlaps and the failure lands on a
change that had nothing to do with it. This is the second time it happened —
three tests in `test_chat.py` and three in `test_pseudo_dir.py` had been
sharing 19170-19172 for a while, and a new pair of tests collided with the two
above them in their own file.

So the rule is checked rather than remembered, and it is checked in the **fast**
suite: a guard that only runs when you already ran the thing it guards is a
guard you find out about from CI.
"""
from __future__ import annotations

import ast
import collections
import pathlib
import re

INTEGRATION = pathlib.Path(__file__).resolve().parent / "integration"
# The loopback addresses these tests bind and dial. Only this form is claimed:
# a port built at runtime is somebody's own business, and this file has no way
# to reason about it.
_ADDRESS = re.compile(r"127\.0\.0\.1:(\d{4,5})")


def _owners() -> dict[str, set[str]]:
    """``port -> {file::test}`` for every literal loopback address."""
    found: dict[str, set[str]] = collections.defaultdict(set)
    for path in sorted(INTEGRATION.glob("*.py")):
        text = path.read_text()
        functions = sorted(
            (node.lineno, node.end_lineno, node.name)
            for node in ast.walk(ast.parse(text))
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)))
        for number, line in enumerate(text.splitlines(), 1):
            for port in _ADDRESS.findall(line):
                # A helper shared by a whole module (`_pair`, a fixture) is
                # attributed to itself, and several tests calling it is not a
                # collision — they pass the port in.
                owner = next((name for start, end, name in functions
                              if start <= number <= end), "<module>")
                found[port].add(f"{path.name}::{owner}")
    return found


def test_the_suite_has_some_ports_to_check():
    """A guard that silently checks nothing is worse than none: if the address
    form ever changes, this is what says so."""
    assert len(_owners()) > 20


def test_no_port_is_claimed_by_two_tests():
    shared = {port: sorted(owners) for port, owners in _owners().items()
              if len(owners) > 1}
    assert not shared, (
        "these ports are bound by more than one integration test, which under "
        "xdist is a race that surfaces as a session timeout somewhere else:\n"
        + "\n".join(f"  {port}: {', '.join(who)}"
                    for port, who in sorted(shared.items())))
