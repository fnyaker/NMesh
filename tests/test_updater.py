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
import tarfile
import tomllib
from pathlib import Path

import pytest

from src import updater
from src.version import __version__, is_newer, parse

ROOT = Path(__file__).resolve().parent.parent


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
