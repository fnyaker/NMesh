"""
The liboqs a node compiles is the one `scripts/liboqs.lock` names, proven so.

Three things have to agree — the lock, `requirements.txt`'s pin of the wrapper
and the hash-locked set the base image installs — and the build has to refuse a
source that is not the locked one, whichever way it was fetched. The refusals
are checked offline, with a `git` and a `curl` that hand back the wrong thing.
"""
import os
import pathlib
import re
import shutil
import stat
import subprocess

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
LOCK = ROOT / "scripts" / "liboqs.lock"
SCRIPT = ROOT / "scripts" / "build_liboqs.sh"


def _lock() -> dict:
    values = {}
    for line in LOCK.read_text().splitlines():
        if line and not line.startswith("#"):
            key, _, value = line.partition("=")
            values[key] = value
    return values


class TestTheLockAgrees:
    def test_it_is_well_formed(self):
        lock = _lock()
        assert re.fullmatch(r"\d+\.\d+\.\d+", lock["LIBOQS_VERSION"])
        assert re.fullmatch(r"[0-9a-f]{40}", lock["LIBOQS_COMMIT"])
        assert re.fullmatch(r"[0-9a-f]{64}", lock["LIBOQS_TARBALL_SHA256"])

    def test_the_wrapper_is_the_release_s_own(self):
        lock = _lock()
        assert lock["LIBOQS_PYTHON_VERSION"].startswith(lock["LIBOQS_VERSION"])

    def test_requirements_pin_the_locked_wrapper(self):
        pins = (ROOT / "requirements.txt").read_text().splitlines()
        assert f"liboqs-python=={_lock()['LIBOQS_PYTHON_VERSION']}" in pins

    def test_the_image_installs_the_same_wrapper(self):
        text = (ROOT / "docker" / "requirements.lock").read_text()
        assert f"liboqs-python=={_lock()['LIBOQS_PYTHON_VERSION']} " in text

    def test_every_locked_package_carries_a_hash(self):
        text = (ROOT / "docker" / "requirements.lock").read_text()
        entries = re.split(r"\n(?=\S)", text.strip())
        packages = [entry for entry in entries if "==" in entry]
        assert packages
        for entry in packages:
            assert "--hash=sha256:" in entry, entry.splitlines()[0]

    def test_every_requirement_is_in_the_lock(self):
        lock = (ROOT / "docker" / "requirements.lock").read_text().lower()
        for line in (ROOT / "requirements.txt").read_text().splitlines():
            name = re.split(r"[=<>~! ]", line.strip(), maxsplit=1)[0].lower()
            if name:
                assert re.search(rf"^{re.escape(name)}==", lock, re.M), name

    def test_no_other_script_fetches_liboqs(self):
        """One place decides which source is compiled. A second fetch is a
        second chance to build something nobody checked."""
        for path in (ROOT / "start.sh", ROOT / "install.sh",
                     ROOT / "docker" / "Dockerfile.base"):
            assert "open-quantum-safe/liboqs" not in path.read_text(), path.name


@pytest.fixture
def sandbox(tmp_path):
    """The script and its lock, with a PATH holding only what each test puts
    there plus the tools the script needs to fail with."""
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    shutil.copy(SCRIPT, scripts / "build_liboqs.sh")
    shutil.copy(LOCK, scripts / "liboqs.lock")
    tools = tmp_path / "bin"
    tools.mkdir()
    for name in ("bash", "sed", "head", "cut", "mktemp", "rm", "mkdir",
                 "dirname", "sha256sum", "tar", "env", "cat"):
        found = shutil.which(name)
        if found:
            (tools / name).symlink_to(found)
    return tmp_path


def _tool(sandbox, name, body):
    path = sandbox / "bin" / name
    path.write_text("#!/bin/sh\n" + body)
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


def _run(sandbox):
    return subprocess.run(
        [shutil.which("bash"), str(sandbox / "scripts" / "build_liboqs.sh"),
         str(sandbox / "prefix"), "1"],
        capture_output=True, text=True, timeout=60,
        env={"PATH": str(sandbox / "bin"), "TMPDIR": str(sandbox)})


class TestTheBuildRefuses:
    def test_a_tag_that_points_elsewhere(self, sandbox):
        _tool(sandbox, "git", 'case "$1" in\n'
              '  clone) for last; do :; done; mkdir -p "$last";;\n'
              '  -C) echo ' + "f" * 40 + ';;\n'
              "esac\n")
        _tool(sandbox, "cmake", "echo cmake must not run >&2; exit 99\n")
        result = _run(sandbox)
        assert result.returncode != 0
        assert "refusing to build it" in result.stderr
        assert "cmake must not run" not in result.stderr

    def test_an_archive_that_does_not_hash_to_the_lock(self, sandbox):
        _tool(sandbox, "curl", 'while [ $# -gt 0 ]; do\n'
              '  [ "$1" = -o ] && { echo junk > "$2"; shift; }\n'
              "  shift\ndone\n")
        _tool(sandbox, "cmake", "echo cmake must not run >&2; exit 99\n")
        result = _run(sandbox)
        assert result.returncode != 0
        assert "refusing to build it" in result.stderr
        assert "cmake must not run" not in result.stderr

    def test_it_asks_for_one_source_and_no_other(self, sandbox):
        """A failed fetch ends the build: no older tag, no `main`."""
        asked = sandbox / "asked"
        _tool(sandbox, "curl", f'echo "$@" >> "{asked}"; exit 22\n')
        result = _run(sandbox)
        assert result.returncode != 0
        lines = asked.read_text().splitlines()
        assert len(lines) == 1
        assert f"/refs/tags/{_lock()['LIBOQS_VERSION']}.tar.gz" in lines[0]

    def test_a_lock_with_a_short_commit(self, sandbox):
        lock = sandbox / "scripts" / "liboqs.lock"
        lock.write_text(re.sub(r"LIBOQS_COMMIT=\w+", "LIBOQS_COMMIT=5a1a854",
                               lock.read_text()))
        result = _run(sandbox)
        assert result.returncode != 0
        assert "not a full commit id" in result.stderr


@pytest.mark.skipif(os.environ.get("NMESH_NETWORK_TESTS") != "1",
                    reason="fetches liboqs from GitHub; NMESH_NETWORK_TESTS=1")
def test_the_locked_archive_is_the_one_github_serves(tmp_path):
    import hashlib
    import urllib.request
    url = ("https://github.com/open-quantum-safe/liboqs/archive/refs/tags/"
           f"{_lock()['LIBOQS_VERSION']}.tar.gz")
    with urllib.request.urlopen(url, timeout=60) as response:
        body = response.read(64 * 1024 * 1024)
    assert hashlib.sha256(body).hexdigest() == _lock()["LIBOQS_TARBALL_SHA256"]


class TestTheBuildStamps:
    def _proven_git(self, sandbox):
        _tool(sandbox, "git", 'case "$1" in\n'
              '  clone) for last; do :; done; mkdir -p "$last";;\n'
              f'  -C) echo {_lock()["LIBOQS_COMMIT"]};;\n'
              "esac\n")

    def test_a_proven_build_leaves_the_lock_it_was_proven_against(self, sandbox):
        self._proven_git(sandbox)
        _tool(sandbox, "cmake", "exit 0\n")
        _tool(sandbox, "grep", f'exec {shutil.which("grep")} "$@"\n')
        (sandbox / "prefix").mkdir()
        result = _run(sandbox)
        assert result.returncode == 0, result.stderr
        stamp = (sandbox / "prefix" / "nmesh-liboqs.lock").read_text()
        assert f"LIBOQS_COMMIT={_lock()['LIBOQS_COMMIT']}" in stamp
        assert f"LIBOQS_TARBALL_SHA256={_lock()['LIBOQS_TARBALL_SHA256']}" in stamp

    def test_a_refused_build_leaves_none(self, sandbox):
        _tool(sandbox, "git", 'case "$1" in\n'
              '  clone) for last; do :; done; mkdir -p "$last";;\n'
              '  -C) echo ' + "f" * 40 + ';;\n'
              "esac\n")
        _tool(sandbox, "cmake", "exit 0\n")
        (sandbox / "prefix").mkdir()
        assert _run(sandbox).returncode != 0
        assert not (sandbox / "prefix" / "nmesh-liboqs.lock").exists()


class TestWhatIsCompiled:
    """Only the two schemes a node uses are built. liboqs 0.16.0 carries two
    advisories in its LMS code (BUGSVULNS 113); a scheme that is not compiled
    is one no advisory can reach."""

    def _configure_args(self, sandbox) -> list:
        args = sandbox / "cmake-args"
        _tool(sandbox, "git", 'case "$1" in\n'
              '  clone) for last; do :; done; mkdir -p "$last";;\n'
              f'  -C) echo {_lock()["LIBOQS_COMMIT"]};;\n'
              "esac\n")
        _tool(sandbox, "cmake", f'[ "$1" = -S ] && printf "%s\\n" "$@" > "{args}"\nexit 0\n')
        _tool(sandbox, "grep", f'exec {shutil.which("grep")} "$@"\n')
        (sandbox / "prefix").mkdir()
        result = _run(sandbox)
        assert result.returncode == 0, result.stderr
        return args.read_text().splitlines()

    def test_only_the_schemes_the_node_uses(self, sandbox):
        crypto = (ROOT / "src" / "crypto.py").read_text()
        kem = re.search(r'^KEM_ALG = "([^"]+)"', crypto, re.M).group(1)
        dsa = re.search(r'^DSA_ALG = "([^"]+)"', crypto, re.M).group(1)
        wanted = {"KEM_" + kem.lower().replace("-", "_"),
                  "SIG_" + dsa.lower().replace("-", "_")}
        minimal = [arg for arg in self._configure_args(sandbox)
                   if arg.startswith("-DOQS_MINIMAL_BUILD=")]
        assert len(minimal) == 1
        assert set(minimal[0].split("=", 1)[1].split(";")) == wanted

    def test_no_stateful_scheme_and_no_hazardous_signing(self, sandbox):
        args = self._configure_args(sandbox)
        for option in ("OQS_ENABLE_SIG_STFL_LMS", "OQS_ENABLE_SIG_STFL_XMSS",
                       "OQS_HAZARDOUS_EXPERIMENTAL_ENABLE_SIG_STFL_KEY_SIG_GEN"):
            assert f"-D{option}=OFF" in args, option
        assert not [arg for arg in args if arg.endswith("=ON") and "STFL" in arg]
