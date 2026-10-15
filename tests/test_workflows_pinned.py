"""
Every action a workflow runs is pinned to a commit, and no workflow inherits
the token's default permissions.

A tag is a pointer its owner can move: an action referenced as `@v4` runs
whatever the tag names on the day of the run, with the job's token in reach —
the release job's token can publish an image every node pulls. A full commit
SHA cannot be moved; Dependabot (`.github/dependabot.yml`) moves the pin
instead, as a pull request somebody reads. A workflow of this repository is
named with the self-repository form (`$/…`), which is resolved from the commit
the run is for; `./…` is read from whatever the job's workspace holds by then.

And what the publishing jobs do with their token is held here too: no tool
gets the Docker socket, a scan comes before the registry login, an image of
this repository is used only once its provenance is checked.
"""
import pathlib
import re

import pytest

WORKFLOWS = pathlib.Path(__file__).resolve().parent.parent / ".github" / "workflows"
_USES = re.compile(r"^\s*-?\s*uses:\s*(\S+)", re.M)
_PINNED = re.compile(r"^(?:[\w.-]+/[\w./-]+@[0-9a-f]{40}|\$/[\w./-]+)$")


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


def test_a_workspace_relative_reference_is_refused():
    assert not _PINNED.match("./.github/workflows/tests.yml")
    assert _PINNED.match("$/.github/workflows/tests.yml")


@pytest.mark.parametrize("name", ["base-image.yml", "ci.yml"])
def test_what_publishes_latest_does_it_one_run_at_a_time(name):
    """Two merges a minute apart once let the older build overwrite the newer
    `:latest` (BUGSVULNS 100)."""
    text = (WORKFLOWS / name).read_text()
    assert re.search(r"concurrency:\s*\n\s+group: ", text), name
    assert "cancel-in-progress: false" in text



def _jobs(text: str) -> dict:
    """Each job's text, by name: the two-space keys under ``jobs:``."""
    body = text.split("\njobs:\n", 1)[1]
    parts = re.split(r"^  ([\w-]+):\n", body, flags=re.M)
    return dict(zip(parts[1::2], parts[2::2]))


def test_the_job_splitter_finds_every_job():
    assert set(_jobs((WORKFLOWS / "ci.yml").read_text())) == {"test", "docker"}


@pytest.mark.parametrize("path", _workflows(), ids=lambda p: p.name)
def test_no_tool_is_handed_the_docker_socket(path):
    """The socket is root on the runner, and the runner of a publishing job
    holds the registry login: a scanner image pinned on the wrong day could
    push. Trivy reads a saved image (`--input`) or the registry instead."""
    assert "docker.sock" not in path.read_text(), path.name


@pytest.mark.parametrize("path", _workflows(), ids=lambda p: p.name)
def test_a_scan_runs_before_the_registry_login(path):
    for name, job in _jobs(path.read_text()).items():
        if "trivy" in job and "docker/login-action" in job and "--input" in job:
            assert job.index("trivy") < job.index("docker/login-action"), \
                f"{path.name}/{name}: scan first, log in after"


@pytest.mark.parametrize("path", _workflows(), ids=lambda p: p.name)
def test_an_image_of_this_repository_is_pulled_only_once_proven(path):
    """A pull goes through `.github/scripts/pull-verified.sh` (or
    `provide-base.sh`, which calls it), which checks the attestation and hands
    back the digest it checked."""
    assert "docker pull" not in path.read_text(), path.name


def test_the_scripts_check_the_signer_and_the_branch():
    text = (WORKFLOWS.parent / "scripts" / "pull-verified.sh").read_text()
    assert "gh attestation verify" in text
    assert "--signer-workflow" in text and "--source-ref refs/heads/main" in text


def test_the_base_image_is_published_from_main_only_and_attested():
    text = (WORKFLOWS / "base-image.yml").read_text()
    assert "if: github.ref == 'refs/heads/main'" in text
    assert "actions/attest-build-provenance@" in text


def test_a_release_publishes_only_what_the_suite_passed():
    jobs = _jobs((WORKFLOWS / "release.yml").read_text())
    assert "$/.github/workflows/tests.yml" in jobs["test"]
    for name, job in jobs.items():
        if name != "test":
            assert re.search(r"^    needs: test$", job, re.M), name


def test_a_release_scans_its_image_and_leaves_latest_to_ci():
    text = (WORKFLOWS / "release.yml").read_text()
    assert "--exit-code 1" in text and "--scanners vuln,secret" in text
    tagged = re.findall(r"(?:-t|docker push) (\S+)", text)
    assert tagged and not [tag for tag in tagged if "latest" in tag], tagged


@pytest.mark.parametrize("name", ["ci.yml", "release.yml"])
def test_a_published_image_carries_its_sbom(name):
    text = (WORKFLOWS / name).read_text()
    assert "actions/attest-build-provenance@" in text
    assert "actions/attest-sbom@" in text and "--format cyclonedx" in text


def test_every_dependabot_update_waits_a_week():
    text = (WORKFLOWS.parent / "dependabot.yml").read_text()
    ecosystems = re.findall(r"package-ecosystem: (\S+)", text)
    waits = [int(days) for days in re.findall(r"default-days: (\d+)", text)]
    assert ecosystems and len(waits) == len(ecosystems)
    assert min(waits) >= 7


@pytest.mark.parametrize("path", _workflows(), ids=lambda p: p.name)
def test_a_failing_command_cannot_hide_inside_an_echo(path):
    """``echo "X=$(check)" >> "$GITHUB_ENV"`` exits with echo's status, so a
    failed provenance check would pass on with ``X`` empty. Assign first —
    ``x="$(check)"`` fails the step under ``bash -e`` — then echo."""
    hiding = re.findall(r'^.*echo "[^"\n]*\$\([^\n]*>> "\$GITHUB_\w+".*$', path.read_text(), re.M)
    assert not hiding, f"{path.name}: {hiding}"
