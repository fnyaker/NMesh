"""
Every action a workflow runs is pinned to a commit, and no workflow inherits
the token's default permissions.

A tag is a pointer its owner can move: an action referenced as `@v4` runs
whatever the tag names on the day of the run, with the job's token in reach —
the release job's token can publish an image every node pulls. A full commit
SHA cannot be moved; Dependabot (`.github/dependabot.yml`) moves the pin
instead, as a pull request somebody reads.
"""
import pathlib
import re

import pytest

WORKFLOWS = pathlib.Path(__file__).resolve().parent.parent / ".github" / "workflows"
_USES = re.compile(r"^\s*-?\s*uses:\s*(\S+)", re.M)
_PINNED = re.compile(r"^[\w.-]+/[\w./-]+@[0-9a-f]{40}$")


def _workflows() -> list[pathlib.Path]:
    return sorted(WORKFLOWS.glob("*.y*ml"))


def test_there_are_workflows_to_check():
    assert _workflows()


@pytest.mark.parametrize("path", _workflows(), ids=lambda p: p.name)
def test_every_action_is_pinned_to_a_commit(path):
    text = path.read_text()
    refs = _USES.findall(text)
    assert refs, f"{path.name} runs no action: is the pattern still right?"
    loose = [ref for ref in refs if not _PINNED.match(ref)]
    assert not loose, f"{path.name}: pin to a full commit SHA: {loose}"


@pytest.mark.parametrize("path", _workflows(), ids=lambda p: p.name)
def test_a_workflow_starts_with_no_permission(path):
    assert re.search(r"^permissions:\s*\{\}\s*$", path.read_text(), re.M), \
        f"{path.name}: set `permissions: {{}}` and grant each job its own"


def test_a_tag_reference_is_refused():
    assert not _PINNED.match("actions/checkout@v4")
    assert not _PINNED.match("actions/checkout@11d5960")
    assert _PINNED.match("actions/checkout@" + "a" * 40)
