"""
A tree on trial, and the way back to the one that worked.

An update that installs cleanly and then dies on start is the worst outcome an
unattended machine can have: the service manager starts it, it dies, for ever,
and the machine is off the mesh until somebody walks up to it. These tests hold
the guard to what it promises — a tree that never stays up is put back after
its chances, a tree that does is left alone, and the guard itself is never the
reason a node did not start.
"""
import json
import os
import subprocess
import sys

import pytest

from src import boot_guard as guard
from src import updater

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _tree(root, label):
    """A stand-in for an installed tree: what a rollback has to put back."""
    (root / "src").mkdir(parents=True, exist_ok=True)
    (root / "src" / "node.py").write_text(f"{label} node\n")
    (root / "start.sh").write_text(f"#!/bin/sh\necho {label}\n")
    (root / "data").mkdir(exist_ok=True)
    (root / "data" / "node.key").write_text("IDENTITY")


def _updated(tmp_path, monkeypatch):
    """A node that has just swapped in a new tree through the real updater."""
    root = tmp_path / "install"
    _tree(root, "old")
    monkeypatch.setattr(updater, "updatable", lambda: (True, ""))
    monkeypatch.setattr(updater, "preflight", lambda _root: "")
    with open(os.path.join(ROOT, "src", "boot_guard.py"), "rb") as handle:
        own_guard = handle.read()
    updater.apply_files_sync({"src/node.py": b"new node\n",
                              "src/boot_guard.py": own_guard,
                              "start.sh": b"#!/bin/sh\necho new\n",
                              "scripts/nmesh_node.py": b"# launcher\n"},
                             "9.9.9", root=str(root))
    return root


class TestATreeOnTrial:
    def test_a_node_that_was_not_updated_is_not_on_trial(self, tmp_path):
        _tree(tmp_path, "old")
        assert guard.begin(str(tmp_path)) == guard.NOT_ON_TRIAL

    def test_every_start_is_counted(self, tmp_path, monkeypatch):
        root = _updated(tmp_path, monkeypatch)
        for boots in range(1, guard.MAX_TRIAL_BOOTS + 1):
            assert guard.begin(str(root)) == guard.ON_TRIAL
            assert guard.trial(str(root))["boots"] == boots
        assert (root / "src" / "node.py").read_text() == "new node\n"

    def test_a_tree_that_never_stays_up_is_put_back(self, tmp_path, monkeypatch):
        root = _updated(tmp_path, monkeypatch)
        for _ in range(guard.MAX_TRIAL_BOOTS):
            guard.begin(str(root))
        assert guard.begin(str(root)) == guard.ROLLED_BACK
        assert (root / "src" / "node.py").read_text() == "old node\n"
        assert (root / "start.sh").read_text() == "#!/bin/sh\necho old\n"
        # What the release added and the old tree never had is gone with it…
        assert not (root / "scripts").exists()
        # …kept aside for whoever wants to know why it failed…
        assert (root / guard.FAILED_DIR / "src" / "node.py").read_text() == "new node\n"
        # …and the node's state was never part of any of it.
        assert (root / "data" / "node.key").read_text() == "IDENTITY"
        assert guard.trial(str(root)) is None
        assert guard.begin(str(root)) == guard.NOT_ON_TRIAL

    def test_the_rollback_is_said_once(self, tmp_path, monkeypatch):
        root = _updated(tmp_path, monkeypatch)
        for _ in range(guard.MAX_TRIAL_BOOTS + 1):
            guard.begin(str(root))
        note = guard.take_note(str(root))
        assert note["restored"] is True and note["version"] == "9.9.9"
        assert note["previous"] and "started" in note["reason"]
        assert guard.take_note(str(root)) is None

    def test_a_tree_that_stays_up_is_the_tree(self, tmp_path, monkeypatch):
        root = _updated(tmp_path, monkeypatch)
        guard.begin(str(root))
        assert guard.confirm(str(root)) is True
        for _ in range(guard.MAX_TRIAL_BOOTS + 2):
            assert guard.begin(str(root)) == guard.NOT_ON_TRIAL
        assert (root / "src" / "node.py").read_text() == "new node\n"
        assert guard.confirm(str(root)) is False

    def test_a_rollback_cut_short_is_finished_by_the_next_start(self, tmp_path,
                                                                monkeypatch):
        """Power cut half-way: `src` is already back, `start.sh` is not. The
        trial file is still there, so the next start finishes the job."""
        root = _updated(tmp_path, monkeypatch)
        for _ in range(guard.MAX_TRIAL_BOOTS):
            guard.begin(str(root))
        backup = root / guard.BACKUP_DIR
        os.makedirs(root / guard.FAILED_DIR)
        os.replace(root / "src", root / guard.FAILED_DIR / "src")
        os.replace(backup / "src", root / "src")
        assert guard.begin(str(root)) == guard.ROLLED_BACK
        assert (root / "src" / "node.py").read_text() == "old node\n"
        assert (root / "start.sh").read_text() == "#!/bin/sh\necho old\n"

    def test_with_nothing_to_go_back_to_it_stops_counting(self, tmp_path):
        _tree(tmp_path, "new")
        guard.start_trial(str(tmp_path), "9.9.9", "0.0.1")
        for _ in range(guard.MAX_TRIAL_BOOTS):
            guard.begin(str(tmp_path))
        assert guard.begin(str(tmp_path)) == guard.NOT_ON_TRIAL
        assert guard.trial(str(tmp_path)) is None
        note = guard.take_note(str(tmp_path))
        assert note["restored"] is False and "no previous tree" in note["detail"]

    @pytest.mark.parametrize("content", [b"", b"not json", b"[1,2]",
                                         b'{"boots": "many"}', b"\xff" * 64,
                                         b"{" * 20000,
                                         b'{"boots": 9, "added": ["data", "/etc"]}'])
    def test_a_trial_file_it_cannot_read_never_stops_a_start(self, tmp_path,
                                                            content):
        _tree(tmp_path, "new")
        (tmp_path / guard.TRIAL_FILE).write_bytes(content)
        assert guard.begin(str(tmp_path)) in (guard.NOT_ON_TRIAL, guard.ON_TRIAL)
        assert (tmp_path / "src" / "node.py").read_text() == "new node\n"
        # Whatever the file says it added, the node's state is not a release.
        assert (tmp_path / "data" / "node.key").read_text() == "IDENTITY"


class TestTheLaunchers:
    def test_start_sh_is_told_to_start_again_after_a_rollback(self, tmp_path,
                                                             monkeypatch):
        root = _updated(tmp_path, monkeypatch)
        script = os.path.join(ROOT, "src", "boot_guard.py")

        def run():
            return subprocess.run([sys.executable, script, "begin", str(root)],
                                  capture_output=True, text=True, timeout=60)

        for _ in range(guard.MAX_TRIAL_BOOTS):
            assert run().returncode == 0
        result = run()
        assert result.returncode == guard.EXIT_ROLLED_BACK
        assert "previous" in result.stdout
        assert run().returncode == 0

    def test_a_guard_given_nonsense_lets_the_node_start(self, tmp_path):
        script = os.path.join(ROOT, "src", "boot_guard.py")
        for argv in ([], ["begin"], ["what", str(tmp_path)]):
            result = subprocess.run([sys.executable, script, *argv],
                                    capture_output=True, timeout=60)
            assert result.returncode == 0

    def test_it_loads_on_its_own(self):
        """It runs exactly when the rest of the tree cannot be trusted to
        import, so it must import nothing of the project."""
        source = open(os.path.join(ROOT, "src", "boot_guard.py")).read()
        assert "from ." not in source and "import src" not in source

    def test_start_sh_counts_before_it_touches_anything(self):
        source = open(os.path.join(ROOT, "start.sh")).read()
        main = source.split('if [ -n "${NMESH_START_LIB:-}" ]; then return 0; fi')[1]
        guarded = main.index("boot_guard.py begin")
        assert guarded < main.index("step 5: Python dependencies")
        assert guarded < main.index('verify_import "src (NMesh core)"')
        assert "NMESH_BOOT_COUNTED=1" in main[guarded:]

    def test_the_launcher_counts_a_start_start_sh_did_not(self, tmp_path,
                                                          monkeypatch):
        """A re-exec after an update runs the launcher without start.sh, and
        must be counted; a start start.sh already counted must not be twice."""
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "nmesh_node_for_guard", os.path.join(ROOT, "scripts", "nmesh_node.py"))
        launcher = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(launcher)
        root = _updated(tmp_path, monkeypatch)
        monkeypatch.setattr(launcher, "ROOT", str(root))
        monkeypatch.setenv("NMESH_BOOT_COUNTED", "1")
        launcher._count_this_start()
        assert guard.trial(str(root))["boots"] == 0
        assert "NMESH_BOOT_COUNTED" not in os.environ
        launcher._count_this_start()
        assert guard.trial(str(root))["boots"] == 1
