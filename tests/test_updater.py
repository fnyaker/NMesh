"""
Updating from GitHub — comparing versions and applying one.

This is a supply-chain surface: downloaded code replaces the running code. The
tests are therefore mostly about what must **refuse** — an unreadable version
that is never "newer", an archive trying to escape its destination, a tree that
does not look like NMesh, a failure mid-replacement that must leave the node on
its previous version.

No test touches the network: the downloads are simulated.
"""
import io
import json
import os
import sys
import tarfile
import tomllib
from pathlib import Path

import pytest

from src import updater
from src.version import __version__, is_newer, parse

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(autouse=True)
def _follow_releases(monkeypatch):
    """Every test here means "a node that follows the published releases".

    Said out loud rather than assumed: the branch this node follows now comes
    from its configuration file, and a machine that happens to have one next to
    the checkout would otherwise send these tests somewhere else entirely."""
    monkeypatch.setenv(updater.UPDATE_BRANCH_ENV, "")


class TestVersionComparison:
    def test_matches_pyproject(self):
        """Two sources of truth drifting apart means a wrong version shown to
        the operator."""
        with open(ROOT / "pyproject.toml", "rb") as handle:
            assert tomllib.load(handle)["project"]["version"] == __version__

    def test_newer_is_newer(self):
        assert is_newer("v9.0.0", "0.1.0") is True
        assert is_newer("v0.2.0", "0.1.0") is True
        assert is_newer("v0.1.1", "0.1.0") is True

    def test_same_or_older_is_not(self):
        assert is_newer("v0.1.0", "0.1.0") is False
        assert is_newer("v0.0.9", "0.1.0") is False
        assert is_newer("v0.1.0", "0.2.0") is False

    def test_the_patch_number_is_not_capped_at_nine(self):
        """The project counts the patch number up freely (CLAUDE.md), so it is
        compared as a number, never as a character: 0.1.100 is newer than
        0.1.99, and a minor bump still beats any patch count."""
        assert is_newer("v0.1.10", "0.1.9") is True
        assert is_newer("v0.1.100", "0.1.99") is True
        assert is_newer("v0.1.99", "0.1.100") is False
        assert is_newer("v0.2.0", "0.1.100") is True

    def test_prerelease_sorts_before_its_release(self):
        assert is_newer("v0.2.0-rc1", "0.2.0") is False
        assert is_newer("v0.2.0", "0.2.0-rc1") is True

    def test_unparseable_is_never_newer(self):
        """A tag we cannot read must never trigger an update towards something
        we cannot identify."""
        for junk in ("nightly", "latest", "", None, 42, "v", "release-2024"):
            assert is_newer(junk, "0.1.0") is False

    def test_parse_shapes(self):
        assert parse("v1.2.3") == (1, 2, 3, "")
        assert parse("1.2") == (1, 2, 0, "")
        assert parse("v2") == (2, 0, 0, "")
        assert parse("v1.2.3-rc1") == (1, 2, 3, "-rc1")
        assert parse("garbage") is None


class TestCheckParsing:
    def _release(self, monkeypatch, document):
        monkeypatch.setattr(updater, "_latest_release", lambda: document)

    def test_reports_an_available_release(self, monkeypatch):
        self._release(monkeypatch, {"tag_name": "v99.0.0",
                                    "html_url": "https://example/r",
                                    "body": "notes", "published_at": "2026-01-01"})
        result = updater.check_sync()
        assert result["available"] is True
        assert result["latest"] == "v99.0.0"
        assert result["current"] == __version__

    def test_reports_up_to_date(self, monkeypatch):
        self._release(monkeypatch, {"tag_name": f"v{__version__}"})
        assert updater.check_sync()["available"] is False

    def test_missing_tag_is_an_error(self, monkeypatch):
        self._release(monkeypatch, {"html_url": "https://example/r"})
        with pytest.raises(updater.UpdateError):
            updater.check_sync()

    def test_release_notes_are_bounded(self, monkeypatch):
        self._release(monkeypatch, {"tag_name": "v99.0.0", "body": "x" * 100_000})
        assert len(updater.check_sync()["notes"]) <= updater.MAX_NOTES

    def test_hostile_fields_do_not_leak_through(self, monkeypatch):
        self._release(monkeypatch, {"tag_name": "v99.0.0", "body": 12345,
                                    "html_url": "u" * 5000,
                                    "published_at": ["not", "a", "string"]})
        result = updater.check_sync()
        assert result["notes"] == ""
        assert len(result["url"]) <= 512
        assert isinstance(result["published_at"], str)


class TestFollowingABranch:
    """Checking `src/version.py` at a branch instead of the published releases."""

    def _source(self, monkeypatch, text: str):
        monkeypatch.setattr(updater, "_fetch",
                            lambda url, **kw: text.encode())

    def test_the_branch_says_what_the_latest_version_is(self, monkeypatch):
        self._source(monkeypatch, '__version__ = "99.0.0"\n')
        result = updater.check_sync(branch="main")
        assert result["source"] == "branch"
        assert result["branch"] == "main"
        assert result["latest"] == "99.0.0"
        assert result["available"] is True

    def test_the_same_version_is_not_an_update(self, monkeypatch):
        self._source(monkeypatch, f'__version__ = "{__version__}"\n')
        assert updater.check_sync(branch="main")["available"] is False

    def test_a_file_declaring_nothing_is_an_error(self, monkeypatch):
        self._source(monkeypatch, "# nothing here\n")
        with pytest.raises(updater.UpdateError, match="no version"):
            updater.check_sync(branch="main")

    def test_an_unreadable_version_is_never_newer(self, monkeypatch):
        for text in ('__version__ = "tomorrow"\n',
                     '__version__ = "9.9.9 <script>"\n'):
            self._source(monkeypatch, text)
            with pytest.raises(updater.UpdateError, match="cannot be read"):
                updater.check_sync(branch="main")

    def test_a_branch_name_that_would_leave_the_repository_is_refused(
            self, monkeypatch):
        """An unusable name falls back to the releases rather than being
        escaped into a URL that asks somewhere nobody chose."""
        monkeypatch.setattr(updater, "_latest_release",
                            lambda: {"tag_name": "v99.0.0"})
        for bad in ("../../elsewhere", "/etc", "a branch", "x" * 200):
            assert updater.check_sync(branch=bad)["source"] == "release"

    def test_the_environment_names_the_branch(self, monkeypatch):
        monkeypatch.setenv(updater.UPDATE_BRANCH_ENV, "main")
        self._source(monkeypatch, '__version__ = "99.0.0"\n')
        assert updater.check_sync()["branch"] == "main"

    def test_the_configuration_file_names_the_branch(self, tmp_path,
                                                     monkeypatch):
        monkeypatch.delenv(updater.UPDATE_BRANCH_ENV, raising=False)
        path = tmp_path / "nmesh.conf"
        path.write_text("update_branch = testing\n")
        assert updater.update_branch(str(path)) == "testing"

    def test_no_branch_means_the_releases(self, tmp_path, monkeypatch):
        monkeypatch.delenv(updater.UPDATE_BRANCH_ENV, raising=False)
        path = tmp_path / "nmesh.conf"
        path.write_text("update_branch =\n")
        assert updater.update_branch(str(path)) == ""

    def test_a_branch_the_file_would_refuse_is_not_followed(self, tmp_path,
                                                            monkeypatch):
        monkeypatch.delenv(updater.UPDATE_BRANCH_ENV, raising=False)
        path = tmp_path / "nmesh.conf"
        path.write_text("update_branch = ../elsewhere\n")
        assert updater.update_branch(str(path)) == ""


def _make_release_tarball(entries: dict, top: str = "NMesh-1.0") -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for name, content in entries.items():
            info = tarfile.TarInfo(f"{top}/{name}")
            data = content.encode()
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


class TestApply:
    def _install(self, tmp_path):
        root = tmp_path / "install"
        (root / "src").mkdir(parents=True)
        (root / "src" / "node.py").write_text("old node\n")
        (root / "start.sh").write_text("#!/bin/sh\necho old\n")
        (root / "data").mkdir()
        (root / "data" / "node.key").write_text("IDENTITY")
        (root / ".venv").mkdir()
        (root / ".venv" / "marker").write_text("venv")
        return root

    def _apply(self, monkeypatch, root, archive):
        monkeypatch.setattr(updater, "_download", lambda tag: archive)
        monkeypatch.setattr(updater, "updatable", lambda: (True, ""))
        return updater.apply_sync("v9.9.9", root=str(root))

    def test_replaces_the_tree(self, tmp_path, monkeypatch):
        root = self._install(tmp_path)
        archive = _make_release_tarball({"src/node.py": "new node\n",
                                         "start.sh": "#!/bin/sh\necho new\n"})
        result = self._apply(monkeypatch, root, archive)
        assert result["applied"] == "v9.9.9"
        assert (root / "src" / "node.py").read_text() == "new node\n"
        assert (root / "start.sh").read_text() == "#!/bin/sh\necho new\n"

    def test_never_touches_state_or_the_virtualenv(self, tmp_path, monkeypatch):
        """The node's identity is what makes it *this* node on the mesh. An
        update must never touch it."""
        root = self._install(tmp_path)
        archive = _make_release_tarball({"src/node.py": "new\n", "start.sh": "x\n"})
        self._apply(monkeypatch, root, archive)
        assert (root / "data" / "node.key").read_text() == "IDENTITY"
        assert (root / ".venv" / "marker").read_text() == "venv"

    def test_the_previous_tree_is_kept(self, tmp_path, monkeypatch):
        root = self._install(tmp_path)
        archive = _make_release_tarball({"src/node.py": "new\n", "start.sh": "x\n"})
        result = self._apply(monkeypatch, root, archive)
        backup = Path(result["backup"])
        assert (backup / "src" / "node.py").read_text() == "old node\n"

    def test_scripts_stay_executable(self, tmp_path, monkeypatch):
        root = self._install(tmp_path)
        archive = _make_release_tarball({"src/node.py": "new\n",
                                         "start.sh": "x\n", "install.sh": "y\n"})
        self._apply(monkeypatch, root, archive)
        for script in ("start.sh", "install.sh"):
            assert os.access(root / script, os.X_OK)

    def test_a_tree_that_is_not_nmesh_is_refused(self, tmp_path, monkeypatch):
        root = self._install(tmp_path)
        archive = _make_release_tarball({"README.md": "hello\n"})
        with pytest.raises(updater.UpdateError):
            self._apply(monkeypatch, root, archive)
        # …and nothing moved.
        assert (root / "src" / "node.py").read_text() == "old node\n"

    def test_a_junk_archive_is_refused(self, tmp_path, monkeypatch):
        root = self._install(tmp_path)
        with pytest.raises(updater.UpdateError):
            self._apply(monkeypatch, root, b"not a tarball at all")
        assert (root / "src" / "node.py").read_text() == "old node\n"

    def test_an_archive_without_one_top_level_dir_is_refused(self, tmp_path,
                                                             monkeypatch):
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            for top in ("a", "b"):
                info = tarfile.TarInfo(f"{top}/src/x.py")
                info.size = 1
                archive.addfile(info, io.BytesIO(b"x"))
        root = self._install(tmp_path)
        with pytest.raises(updater.UpdateError):
            self._apply(monkeypatch, root, buffer.getvalue())

    def test_path_traversal_is_refused(self, tmp_path, monkeypatch):
        """An archive aiming outside its destination is rejected, not silently
        sanitised."""
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            info = tarfile.TarInfo("NMesh/../../escaped.txt")
            info.size = 3
            archive.addfile(info, io.BytesIO(b"pwn"))
        root = self._install(tmp_path)
        with pytest.raises(updater.UpdateError):
            self._apply(monkeypatch, root, buffer.getvalue())
        assert not (tmp_path.parent / "escaped.txt").exists()

    def test_a_failed_swap_restores_the_previous_tree(self, tmp_path, monkeypatch):
        """The one outcome to rule out absolutely: a half-replaced tree."""
        root = self._install(tmp_path)
        archive = _make_release_tarball({"src/node.py": "new\n", "start.sh": "x\n"})
        real_copy = updater.shutil.copytree
        calls = {"n": 0}

        def flaky(*args, **kwargs):
            calls["n"] += 1
            if calls["n"] == 1:
                raise OSError("disk full")
            return real_copy(*args, **kwargs)

        monkeypatch.setattr(updater.shutil, "copytree", flaky)
        with pytest.raises(updater.UpdateError):
            self._apply(monkeypatch, root, archive)
        assert (root / "src" / "node.py").read_text() == "old node\n"
        assert (root / "start.sh").read_text() == "#!/bin/sh\necho old\n"

    def test_the_staging_directory_is_cleaned_up(self, tmp_path, monkeypatch):
        root = self._install(tmp_path)
        archive = _make_release_tarball({"src/node.py": "new\n", "start.sh": "x\n"})
        self._apply(monkeypatch, root, archive)
        assert not (root / ".nmesh-update").exists()

    def test_refuses_when_not_updatable(self, tmp_path, monkeypatch):
        root = self._install(tmp_path)
        monkeypatch.setattr(updater, "_download", lambda tag: b"")
        monkeypatch.setattr(updater, "updatable", lambda: (False, "read-only"))
        with pytest.raises(updater.UpdateError, match="read-only"):
            updater.apply_sync("v9.9.9", root=str(root))


class TestApplyingVerifiedFiles:
    """The mesh path: the caller has already checked every byte against a
    signed root, so nothing is downloaded here. What is still ours to check is
    where those bytes land."""

    def _install(self, tmp_path):
        root = tmp_path / "install"
        (root / "src").mkdir(parents=True)
        (root / "src" / "node.py").write_text("old node\n")
        (root / "start.sh").write_text("#!/bin/sh\necho old\n")
        (root / "data").mkdir()
        (root / "data" / "node.key").write_text("IDENTITY")
        (root / ".venv").mkdir()
        (root / ".venv" / "marker").write_text("venv")
        return root

    def _apply(self, monkeypatch, root, files, version="9.9.9"):
        monkeypatch.setattr(updater, "updatable", lambda: (True, ""))
        return updater.apply_files_sync(files, version, root=str(root))

    def test_files_replace_the_tree(self, tmp_path, monkeypatch):
        root = self._install(tmp_path)
        result = self._apply(monkeypatch, root, {
            "src/node.py": b"new node\n",
            "src/deep/thing.py": b"nested\n",
            "start.sh": b"#!/bin/sh\necho new\n",
        })
        assert result["applied"] == "9.9.9"
        assert (root / "src" / "node.py").read_text() == "new node\n"
        assert (root / "src" / "deep" / "thing.py").read_text() == "nested\n"
        assert (root / "start.sh").read_text() == "#!/bin/sh\necho new\n"

    def test_the_scripts_stay_executable(self, tmp_path, monkeypatch):
        root = self._install(tmp_path)
        self._apply(monkeypatch, root, {"src/node.py": b"x\n",
                                        "start.sh": b"#!/bin/sh\n"})
        assert os.stat(root / "start.sh").st_mode & 0o111

    def test_state_and_the_virtualenv_are_untouched(self, tmp_path, monkeypatch):
        root = self._install(tmp_path)
        self._apply(monkeypatch, root, {"src/node.py": b"x\n",
                                        "start.sh": b"#!/bin/sh\n"})
        assert (root / "data" / "node.key").read_text() == "IDENTITY"
        assert (root / ".venv" / "marker").read_text() == "venv"

    @pytest.mark.parametrize("path", [
        "/etc/passwd", "../escaped.py", "src/../../escaped.py",
        "src/\x00node.py", "", ".", "..",
    ])
    def test_a_path_that_reaches_outside_refuses_the_whole_release(
            self, tmp_path, monkeypatch, path):
        """Refused, not sanitised: a package reaching outside its own tree is
        not a release with one bad path in it."""
        root = self._install(tmp_path)
        with pytest.raises(updater.UpdateError):
            self._apply(monkeypatch, root, {"src/version.py": b"x\n",
                                            "start.sh": b"#!/bin/sh\n",
                                            path: b"pwn\n"})
        assert (root / "src" / "node.py").read_text() == "old node\n"
        assert not (tmp_path.parent / "escaped.py").exists()

    def test_something_that_is_not_a_node_is_refused(self, tmp_path, monkeypatch):
        root = self._install(tmp_path)
        with pytest.raises(updater.UpdateError):
            self._apply(monkeypatch, root, {"README.md": b"hello\n"})
        assert (root / "src" / "node.py").read_text() == "old node\n"

    def test_an_empty_release_is_refused(self, tmp_path, monkeypatch):
        root = self._install(tmp_path)
        with pytest.raises(updater.UpdateError):
            self._apply(monkeypatch, root, {})

    def test_a_refusal_to_update_still_applies(self, tmp_path, monkeypatch):
        root = self._install(tmp_path)
        monkeypatch.setattr(updater, "updatable", lambda: (False, "read-only"))
        with pytest.raises(updater.UpdateError, match="read-only"):
            updater.apply_files_sync({"src/x.py": b"x"}, "9.9.9", root=str(root))

    def test_a_failed_swap_restores_the_previous_tree(self, tmp_path, monkeypatch):
        root = self._install(tmp_path)
        real_copy = updater.shutil.copytree
        calls = {"n": 0}

        def flaky(*args, **kwargs):
            calls["n"] += 1
            if calls["n"] == 1:
                return real_copy(*args, **kwargs)
            raise OSError("disk full")

        monkeypatch.setattr(updater.shutil, "copytree", flaky)
        with pytest.raises(updater.UpdateError):
            self._apply(monkeypatch, root, {"src/node.py": b"new\n",
                                            "start.sh": b"#!/bin/sh\n",
                                            "scripts/x.py": b"y\n"})
        assert (root / "src" / "node.py").read_text() == "old node\n"

    def test_no_staging_directory_is_left_behind(self, tmp_path, monkeypatch):
        root = self._install(tmp_path)
        self._apply(monkeypatch, root, {"src/node.py": b"x\n",
                                        "start.sh": b"#!/bin/sh\n"})
        assert not (root / ".nmesh-update").exists()

    def test_safe_relative_is_the_one_gate(self):
        assert updater.safe_relative("src/node.py") == os.path.join("src", "node.py")
        for bad in ("/abs", "../up", "a/../../b", "a/\x00b", "", None, 42, "."):
            assert updater.safe_relative(bad) is None


class TestInstallingFromABranch:
    """A branch moves under its own name, so the tree that arrives is checked
    against the version the operator confirmed."""

    def _install(self, tmp_path):
        root = tmp_path / "install"
        (root / "src").mkdir(parents=True)
        (root / "src" / "version.py").write_text('__version__ = "1.0.0"\n')
        (root / "start.sh").write_text("#!/bin/sh\necho old\n")
        return root

    def _tarball(self, version: str) -> bytes:
        return _make_release_tarball({
            "src/version.py": f'__version__ = "{version}"\n',
            "start.sh": "#!/bin/sh\necho new\n"})

    def test_it_downloads_the_branch_not_a_tag(self, tmp_path, monkeypatch):
        asked = []

        def codeload(ref, what):
            asked.append(ref)
            return self._tarball("99.0.0")

        monkeypatch.setattr(updater, "_codeload", codeload)
        monkeypatch.setattr(updater, "updatable", lambda: (True, ""))
        root = self._install(tmp_path)
        result = updater.apply_sync("99.0.0", root=str(root), branch="main")
        assert asked == ["refs/heads/main"]
        assert result["applied"] == "99.0.0"
        assert (root / "src" / "version.py").read_text().strip().endswith('"99.0.0"')

    def test_a_branch_that_moved_since_the_check_is_refused(self, tmp_path,
                                                            monkeypatch):
        monkeypatch.setattr(updater, "_codeload",
                            lambda ref, what: self._tarball("99.0.1"))
        monkeypatch.setattr(updater, "updatable", lambda: (True, ""))
        root = self._install(tmp_path)
        with pytest.raises(updater.UpdateError, match="now carries 99.0.1"):
            updater.apply_sync("99.0.0", root=str(root), branch="main")
        # Refused before anything was replaced.
        assert (root / "src" / "version.py").read_text() == '__version__ = "1.0.0"\n'
        assert not (root / ".nmesh-update").exists()

    def test_a_tree_declaring_no_version_is_refused(self, tmp_path, monkeypatch):
        archive = _make_release_tarball({"src/node.py": "code\n",
                                         "start.sh": "#!/bin/sh\n"})
        monkeypatch.setattr(updater, "_codeload", lambda ref, what: archive)
        monkeypatch.setattr(updater, "updatable", lambda: (True, ""))
        root = self._install(tmp_path)
        with pytest.raises(updater.UpdateError, match="no version"):
            updater.apply_sync("99.0.0", root=str(root), branch="main")


class TestGuards:
    def test_repo_is_pinned_by_default(self, monkeypatch):
        monkeypatch.delenv("NMESH_UPDATE_REPO", raising=False)
        assert updater.repo() == updater.DEFAULT_REPO

    def test_repo_can_be_pointed_at_a_fork(self, monkeypatch):
        monkeypatch.setenv("NMESH_UPDATE_REPO", "someone/fork")
        assert updater.repo() == "someone/fork"

    def test_service_managed_only_when_told(self, monkeypatch):
        monkeypatch.delenv("NMESH_SERVICE_MANAGED", raising=False)
        assert updater.service_managed() is False
        monkeypatch.setenv("NMESH_SERVICE_MANAGED", "1")
        assert updater.service_managed() is True

    def test_a_supervisor_is_preferred_over_re_execing(self, monkeypatch):
        monkeypatch.setenv("NMESH_SERVICE_MANAGED", "1")
        mode, _launch, reason = updater.restart_plan()
        assert mode == updater.RESTART_SERVICE and reason == ""

    def test_it_re_execs_itself_with_no_supervisor(self, monkeypatch, tmp_path):
        """The Termux case: no init a package can reach, so the node replaces
        its own process image rather than sitting on an installed update."""
        monkeypatch.delenv("NMESH_SERVICE_MANAGED", raising=False)
        script = tmp_path / "nmesh_node.py"
        script.write_text("")
        monkeypatch.setattr(updater, "_LAUNCH",
                            (sys.executable, [str(script), "--fleet"],
                             str(tmp_path)))
        mode, launch, reason = updater.restart_plan()
        assert mode == updater.RESTART_REEXEC and reason == ""
        assert launch == (sys.executable, [str(script), "--fleet"], str(tmp_path))
        assert updater.restart_possible() == (True, "")

    def test_it_refuses_when_the_launch_is_gone(self, monkeypatch, tmp_path):
        monkeypatch.delenv("NMESH_SERVICE_MANAGED", raising=False)
        monkeypatch.setattr(updater, "_LAUNCH",
                            (sys.executable, [str(tmp_path / "vanished.py")],
                             str(tmp_path)))
        ok, reason = updater.restart_possible()
        assert ok is False and "vanished.py" in reason

    def test_it_refuses_with_no_interpreter(self, monkeypatch, tmp_path):
        monkeypatch.delenv("NMESH_SERVICE_MANAGED", raising=False)
        monkeypatch.setattr(updater, "_LAUNCH",
                            (str(tmp_path / "gone"), ["x.py"], str(tmp_path)))
        ok, reason = updater.restart_possible()
        assert ok is False and "interpreter" in reason

    def test_install_root_holds_src(self):
        assert os.path.isdir(os.path.join(updater.install_root(), "src"))

    async def test_bounded_call_gives_up(self):
        """A call that never returns must not block the node."""
        import threading
        with pytest.raises(updater.UpdateError, match="timed out"):
            await updater._bounded(lambda: threading.Event().wait(30), 0.2)

    async def test_bounded_call_relays_errors(self):
        def boom():
            raise updater.UpdateError("nope")

        with pytest.raises(updater.UpdateError, match="nope"):
            await updater._bounded(boom, 5)


class TestArchiveSafety:
    """The refusal must not depend on the interpreter's `tarfile` filter: the
    members are checked before any extraction."""

    def _extract(self, tmp_path, build):
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            build(archive)
        with pytest.raises(updater.UpdateError):
            updater._extract(buffer.getvalue(), str(tmp_path / "stage"))

    def test_absolute_path(self, tmp_path):
        def build(archive):
            info = tarfile.TarInfo("/etc/passwd")
            info.size = 1
            archive.addfile(info, io.BytesIO(b"x"))
        self._extract(tmp_path, build)

    def test_parent_traversal(self, tmp_path):
        def build(archive):
            info = tarfile.TarInfo("NMesh/../../escape")
            info.size = 1
            archive.addfile(info, io.BytesIO(b"x"))
        self._extract(tmp_path, build)

    def test_symlink_out_of_the_tree(self, tmp_path):
        def build(archive):
            info = tarfile.TarInfo("NMesh/evil")
            info.type = tarfile.SYMTYPE
            info.linkname = "/etc/shadow"
            archive.addfile(info)
        self._extract(tmp_path, build)

    def test_special_file(self, tmp_path):
        def build(archive):
            info = tarfile.TarInfo("NMesh/dev")
            info.type = tarfile.CHRTYPE
            archive.addfile(info)
        self._extract(tmp_path, build)

    def test_a_normal_release_extracts(self, tmp_path):
        archive = _make_release_tarball({"src/node.py": "x\n", "start.sh": "y\n"})
        source = updater._extract(archive, str(tmp_path / "stage"))
        assert os.path.isfile(os.path.join(source, "start.sh"))
