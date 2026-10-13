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


_OPTIONS_WITH_VALUE = {"-v", "--volume", "-w", "--workdir", "-e", "--env",
                       "--name", "--entrypoint", "-u", "--user", "--network"}


def _images_run(text: str) -> list[str]:
    """The image each ``docker run`` names, continuation lines joined."""
    joined = re.sub(r"\\\n\s*", " ", text)
    images = []
    for command in re.findall(r"docker run ([^\n]+)", joined):
        tokens = command.split()
        index = 0
        while index < len(tokens) and tokens[index].startswith("-"):
            index += 2 if tokens[index] in _OPTIONS_WITH_VALUE else 1
        if index < len(tokens):
            images.append(tokens[index])
    return images


@pytest.mark.parametrize("path", _workflows(), ids=lambda p: p.name)
def test_a_third_party_image_is_pinned_by_digest(path):
    """An image built in the job is named through a step output (``$…`` or
    ``'${{ … }}'``); anything else comes from a registry, where a tag moves."""
    for image in _images_run(path.read_text()):
        if image.lstrip("'\"").startswith("$"):
            continue
        assert re.search(r"@sha256:[0-9a-f]{64}$", image), \
            f"{path.name}: pin {image} by digest"


def test_the_image_parser_finds_what_it_must():
    text = ("docker run --rm -v /a:/b \\\n  aquasec/trivy:0.75.0 image x\n"
            "docker run --rm -v \"$PWD:/app\" -w /app \"$BASE\" pytest\n")
    assert _images_run(text) == ["aquasec/trivy:0.75.0", '"$BASE"']


def test_a_tag_reference_is_refused():
    assert not _PINNED.match("actions/checkout@v4")
    assert not _PINNED.match("actions/checkout@11d5960")
    assert _PINNED.match("actions/checkout@" + "a" * 40)


@pytest.mark.parametrize("name", ["base-image.yml", "ci.yml"])
def test_what_publishes_latest_does_it_one_run_at_a_time(name):
    """Two merges a minute apart once let the older build overwrite the newer
    `:latest` (BUGSVULNS 100)."""
    text = (WORKFLOWS / name).read_text()
    assert re.search(r"concurrency:\s*\n\s+group: ", text), name
    assert "cancel-in-progress: false" in text

