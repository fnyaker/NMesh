"""
Every TLS context the tree builds refuses anything older than TLS 1.2.

Python's default context already sets that floor today, but an OpenSSL policy
or an older interpreter can lower it, and a context built from
``PROTOCOL_TLS_*`` starts from whatever the library allows. The floor is
written down at each construction so it does not depend on either.
"""
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parent.parent
_BUILT = re.compile(r"^(\s*)(\w+) = ssl\.(?:create_default_context|SSLContext)\(", re.M)
# How far below a construction the floor may be set: the few lines that
# configure the context before it is used.
_WITHIN = 8


def _sources() -> list[pathlib.Path]:
    return sorted([*(ROOT / "src").rglob("*.py"), *(ROOT / "scripts").glob("*.py")])


def _constructions():
    for path in _sources():
        lines = path.read_text().splitlines()
        for number, line in enumerate(lines):
            match = _BUILT.match(line)
            if match:
                yield path, number, match.group(2), lines[number + 1:number + 1 + _WITHIN]


def test_the_tree_builds_tls_contexts():
    assert len(list(_constructions())) >= 5


def test_every_context_sets_a_tls_1_2_floor():
    missing = []
    for path, number, name, following in _constructions():
        floor = f"{name}.minimum_version = ssl.TLSVersion.TLSv1_2"
        if not any(floor in line for line in following):
            missing.append(f"{path.relative_to(ROOT)}:{number + 1}")
    assert not missing, f"no TLS 1.2 floor set after: {missing}"
