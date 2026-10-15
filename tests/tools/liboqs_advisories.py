"""
Is the liboqs a node compiles named by a published advisory?

liboqs is C, built from source (`scripts/liboqs.lock`): no package index lists
it, so neither Dependabot, nor pip-audit, nor an image scanner ever sees it.
Its advisories are published on its own repository, and this reads them:

    python -m tests.tools.liboqs_advisories

An advisory whose affected range holds the locked version fails, unless
`scripts/liboqs.accepted` names it with the reason it cannot reach a node. An
accepted id the locked version is no longer affected by is reported, so the
list shrinks when the lock moves. A range this cannot read counts as affected.

`.github/workflows/audit.yml` runs it on every change and every week.
"""
from __future__ import annotations

import json
import os
import pathlib
import re
import sys
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
LOCK = ROOT / "scripts" / "liboqs.lock"
ACCEPTED = ROOT / "scripts" / "liboqs.accepted"
API = ("https://api.github.com/repos/open-quantum-safe/liboqs/security-advisories"
       "?state=published&per_page=100&page={page}")
_MAX_PAGES = 10
_BOUND = re.compile(r"^(<=|>=|<|>|=)?\s*v?(\d+(?:\.\d+)*)$")


def version(text: str) -> tuple:
    return tuple(int(part) for part in text.split("."))


def _compare(left: tuple, right: tuple) -> int:
    width = max(len(left), len(right))
    left += (0,) * (width - len(left))
    right += (0,) * (width - len(right))
    return (left > right) - (left < right)


def in_range(locked: str, spec) -> bool:
    """GitHub's ``vulnerable_version_range``: comma-separated bounds, every one
    of which must hold (``">= 0.11.0, <= 0.16.0"``). Anything else is read as
    affected: a range nobody can parse is not a range anybody is outside of."""
    if not isinstance(spec, str) or not spec.strip():
        return True
    have = version(locked)
    for bound in spec.split(","):
        match = _BOUND.match(bound.strip())
        if match is None:
            return True
        operator, number = match.group(1) or "=", version(match.group(2))
        order = _compare(have, number)
        holds = {"<": order < 0, "<=": order <= 0, ">": order > 0,
                 ">=": order >= 0, "=": order == 0}[operator]
        if not holds:
            return False
    return True


def affects(advisory: dict, locked: str) -> bool:
    if advisory.get("withdrawn_at"):
        return False
    vulnerabilities = advisory.get("vulnerabilities")
    if not isinstance(vulnerabilities, list) or not vulnerabilities:
        return True
    return any(not isinstance(entry, dict)
               or in_range(locked, entry.get("vulnerable_version_range"))
               for entry in vulnerabilities)


def locked_version(path: pathlib.Path = LOCK) -> str:
    match = re.search(r"^LIBOQS_VERSION=(\d+(?:\.\d+)*)$", path.read_text(), re.M)
    if match is None:
        raise ValueError(f"no LIBOQS_VERSION in {path}")
    return match.group(1)


def accepted(path: pathlib.Path = ACCEPTED) -> dict:
    """``GHSA-xxxx-xxxx-xxxx  why it cannot reach a node``, one per line. An
    entry without its reason is refused: an exception nobody can read back is
    one nobody will ever remove."""
    entries = {}
    for number, line in enumerate(path.read_text().splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        ghsa, _, reason = line.partition(" ")
        if not re.fullmatch(r"GHSA(-[23456789cfghjmpqrvwx]{4}){3}", ghsa) or not reason.strip():
            raise ValueError(f"{path.name}:{number}: expected 'GHSA-… reason'")
        entries[ghsa] = reason.strip()
    return entries


def fetch(token: str | None = None) -> list:
    advisories: list = []
    for page in range(1, _MAX_PAGES + 1):
        request = urllib.request.Request(API.format(page=page), headers={
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28"})
        if token:
            request.add_header("Authorization", f"Bearer {token}")
        with urllib.request.urlopen(request, timeout=30) as response:
            batch = json.load(response)
        if not isinstance(batch, list):
            raise ValueError("the advisory list is not a list")
        advisories.extend(batch)
        if len(batch) < 100:
            return advisories
    raise ValueError(f"more than {_MAX_PAGES} pages of advisories")


def verdict(advisories: list, locked: str, exceptions: dict) -> tuple:
    """(open, excused, stale): the advisories that fail the check, those an
    exception covers, and the exceptions nothing needs any more."""
    hits = [a for a in advisories if isinstance(a, dict) and affects(a, locked)]
    names = {a.get("ghsa_id") for a in hits}
    still_open = [a for a in hits if a.get("ghsa_id") not in exceptions]
    excused = [a for a in hits if a.get("ghsa_id") in exceptions]
    stale = sorted(ghsa for ghsa in exceptions if ghsa not in names)
    return still_open, excused, stale


def _line(advisory: dict) -> str:
    return (f"{advisory.get('ghsa_id')} ({advisory.get('severity')}) "
            f"{advisory.get('summary', '')[:100]}")


def main() -> int:
    locked = locked_version()
    exceptions = accepted()
    still_open, excused, stale = verdict(
        fetch(os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")),
        locked, exceptions)
    print(f"liboqs {locked}")
    for advisory in excused:
        print(f"accepted: {_line(advisory)}\n          {exceptions[advisory['ghsa_id']]}")
    for ghsa in stale:
        print(f"warning: {ghsa} is accepted in {ACCEPTED.name} but no longer "
              f"affects {locked}: remove it")
    for advisory in still_open:
        print(f"failed: {_line(advisory)}")
    if still_open:
        print(f"{len(still_open)} advisory(ies) name liboqs {locked}: move the lock, "
              f"or say in {ACCEPTED.name} why a node cannot reach the code")
        return 1
    print("ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
