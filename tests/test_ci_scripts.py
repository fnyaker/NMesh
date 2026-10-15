"""
The scripts the workflows use to take an image of this repository
(`.github/scripts`): the published one only when its attestation checks out,
by the digest that was checked, and a local build otherwise. Driven offline,
with a `docker` and a `gh` that answer as each test needs.
"""
import pathlib
import shutil
import stat
import subprocess

import pytest

SCRIPTS = pathlib.Path(__file__).resolve().parent.parent / ".github" / "scripts"
DIGEST = "sha256:" + "ab" * 32
BASE = "ghcr.io/owner/repo-base:latest"


@pytest.fixture
def sandbox(tmp_path):
    tools = tmp_path / "bin"
    tools.mkdir()
    for name in ("bash", "dirname", "cat"):
        (tools / name).symlink_to(shutil.which(name))
    scripts = tmp_path / ".github" / "scripts"
    scripts.mkdir(parents=True)
    for script in SCRIPTS.glob("*.sh"):
        shutil.copy(script, scripts / script.name)
    return tmp_path


def _tool(sandbox, name, body):
    path = sandbox / "bin" / name
    path.write_text("#!/bin/sh\n" + body)
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


def _docker(sandbox, pull_ok=True, digest=f"ghcr.io/owner/repo-base@{DIGEST}"):
    log = sandbox / "docker.log"
    _tool(sandbox, "docker",
          f'echo "$@" >> "{log}"\n'
          'case "$1" in\n'
          f'  pull) exit {0 if pull_ok else 1};;\n'
          f'  inspect) echo "{digest}";;\n'
          "esac\nexit 0\n")
    return log


def _gh(sandbox, verified=True):
    log = sandbox / "gh.log"
    _tool(sandbox, "gh", f'echo "$@" >> "{log}"\nexit {0 if verified else 1}\n')
    return log


def _run(sandbox, script, *args):
    return subprocess.run(
        [shutil.which("bash"), str(sandbox / ".github" / "scripts" / script), *args],
        capture_output=True, text=True, timeout=30, cwd=sandbox,
        env={"PATH": str(sandbox / "bin"), "GITHUB_REPOSITORY": "owner/Repo",
             "GH_TOKEN": "t"})


class TestPullVerified:
    def test_a_proven_image_comes_back_by_digest(self, sandbox):
        _docker(sandbox)
        gh = _gh(sandbox)
        result = _run(sandbox, "pull-verified.sh", BASE, "base-image.yml")
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == f"ghcr.io/owner/repo-base@{DIGEST}"
        asked = gh.read_text()
        assert f"oci://ghcr.io/owner/repo-base@{DIGEST}" in asked
        assert "--signer-workflow owner/Repo/.github/workflows/base-image.yml" in asked
        assert "--source-ref refs/heads/main" in asked

    def test_an_unproven_image_is_refused(self, sandbox):
        _docker(sandbox)
        _gh(sandbox, verified=False)
        result = _run(sandbox, "pull-verified.sh", BASE, "base-image.yml")
        assert result.returncode != 0
        assert not result.stdout.strip()

    def test_an_image_without_a_registry_digest_is_refused(self, sandbox):
        _docker(sandbox, digest="")
        gh = _gh(sandbox)
        result = _run(sandbox, "pull-verified.sh", BASE, "base-image.yml")
        assert result.returncode != 0
        assert not gh.exists()


class TestProvideBase:
    def test_the_published_base_when_proven(self, sandbox):
        docker = _docker(sandbox)
        _gh(sandbox)
        result = _run(sandbox, "provide-base.sh", BASE)
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == f"ghcr.io/owner/repo-base@{DIGEST}"
        assert "build" not in docker.read_text()

    @pytest.mark.parametrize("pull_ok, verified", [(True, False), (False, True)])
    def test_built_here_when_unproven_or_unreachable(self, sandbox, pull_ok, verified):
        docker = _docker(sandbox, pull_ok=pull_ok)
        _gh(sandbox, verified=verified)
        result = _run(sandbox, "provide-base.sh", BASE)
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == BASE
        built = [line for line in docker.read_text().splitlines() if line.startswith("build")]
        assert len(built) == 1
        assert f"-t {BASE}" in built[0]
        assert built[0].split()[2].endswith("docker/Dockerfile.base")

    def test_a_failed_build_fails(self, sandbox):
        _tool(sandbox, "docker", 'case "$1" in pull) exit 1;; build) exit 3;; esac\nexit 0\n')
        _gh(sandbox)
        result = _run(sandbox, "provide-base.sh", BASE)
        assert result.returncode != 0
        assert not result.stdout.strip()
