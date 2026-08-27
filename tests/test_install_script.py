"""The ./install.sh installer has to lay NMesh down cleanly on any machine.

It reimplements nothing from `start.sh`: it installs a copy of the tree and
points a service at it. The traps covered here are the ones that break a real
installation — `systemctl` present with no systemd behind it (the case for most
container images), no root, no sudo, and the node's state that has to survive an
update.

We source install.sh in library mode (NMESH_INSTALL_LIB=1): nothing is
installed, nothing is launched.
"""
import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
INSTALL = ROOT / "install.sh"
BASH = shutil.which("bash")

pytestmark = pytest.mark.skipif(BASH is None,
                                reason="bash is needed to test the installer")


def run_snippet(tmp_path, snippet, *, fake_bins=(), env=None, isolate=False):
    """Source install.sh in library mode, then run `snippet`."""
    stub_dir = tmp_path / "stubbin"
    stub_dir.mkdir(exist_ok=True)
    base_path = "/usr/bin:/bin:/usr/sbin:/sbin"
    if isolate:
        for tool in ("dirname", "id", "cat", "mkdir", "rm", "tar", "env", "uname"):
            real = shutil.which(tool)
            if real and not (stub_dir / tool).exists():
                (stub_dir / tool).symlink_to(real)
        base_path = ""
    for name, body in fake_bins:
        path = stub_dir / name
        if path.is_symlink():
            path.unlink()
        path.write_text(body)
        path.chmod(0o755)
    environment = {
        "PATH": f"{stub_dir}:{base_path}" if base_path else str(stub_dir),
        "HOME": str(tmp_path / "home"),
        "NMESH_INSTALL_LIB": "1",
    }
    environment.update(env or {})
    (tmp_path / "home").mkdir(exist_ok=True)
    return subprocess.run(
        [BASH, "-c", f'. "{INSTALL}"\n{snippet}'],
        capture_output=True, text=True, env=environment, timeout=60)


class TestInitDetection:
    def test_systemctl_without_systemd_is_not_systemd(self, tmp_path):
        """The container trap: `systemctl` is there, systemd is not. Every
        command would end in "Failed to connect to bus"."""
        result = run_snippet(
            tmp_path, "detect_init",
            fake_bins=[("systemctl", "#!/bin/sh\nexit 1\n")],
            isolate=True)
        assert result.stdout.strip() == "none"

    def test_launchd_is_detected(self, tmp_path):
        result = run_snippet(tmp_path, "detect_init",
                             fake_bins=[("launchctl", "#!/bin/sh\nexit 0\n")],
                             isolate=True)
        assert result.stdout.strip() == "launchd"

    def test_nothing_at_all_is_none(self, tmp_path):
        assert run_snippet(tmp_path, "detect_init",
                           isolate=True).stdout.strip() == "none"


class TestPrivileges:
    def test_no_sudo_no_doas_is_refused_not_guessed(self, tmp_path):
        result = run_snippet(
            tmp_path, 'detect_sudo; echo "[$SUDO]"',
            fake_bins=[("id", "#!/bin/sh\necho 1000\n")], isolate=True)
        assert result.stdout.strip() == "[none]"

    def test_doas_is_accepted(self, tmp_path):
        result = run_snippet(
            tmp_path, 'detect_sudo; echo "[$SUDO]"',
            fake_bins=[("id", "#!/bin/sh\necho 1000\n"),
                       ("doas", "#!/bin/sh\nexit 0\n")], isolate=True)
        assert result.stdout.strip() == "[doas]"

    def test_root_needs_no_prefix(self, tmp_path):
        result = run_snippet(
            tmp_path, 'detect_sudo; echo "[$SUDO]"',
            fake_bins=[("id", "#!/bin/sh\necho 0\n")], isolate=True)
        assert result.stdout.strip() == "[]"


class TestPaths:
    def test_root_installs_under_opt(self, tmp_path):
        result = run_snippet(tmp_path, "default_prefix",
                             fake_bins=[("id", "#!/bin/sh\necho 0\n")],
                             isolate=True)
        assert result.stdout.strip() == "/opt/nmesh"

    def test_a_user_install_needs_no_root(self, tmp_path):
        result = run_snippet(tmp_path, "default_prefix",
                             fake_bins=[("id", "#!/bin/sh\necho 1000\n")],
                             isolate=True)
        prefix = result.stdout.strip()
        assert prefix.endswith("/nmesh")
        assert not prefix.startswith("/opt")

    def test_root_state_lives_in_var_lib(self, tmp_path):
        result = run_snippet(tmp_path, "default_data /opt/nmesh",
                             fake_bins=[("id", "#!/bin/sh\necho 0\n")],
                             isolate=True)
        assert result.stdout.strip() == "/var/lib/nmesh"


class TestServiceUnits:
    def test_systemd_unit_runs_start_sh(self, tmp_path):
        """The service points at start.sh, never at python: a node that starts
        re-checks its dependencies and repairs itself."""
        out = run_snippet(
            tmp_path,
            'systemd_unit /opt/nmesh /var/lib/nmesh nm "--fleet" multi-user.target'
        ).stdout
        assert "ExecStart=/opt/nmesh/start.sh --fleet" in out
        assert "Environment=NMESH_DATA=/var/lib/nmesh" in out
        assert "User=nm" in out
        assert "Restart=always" in out
        assert "NoNewPrivileges=yes" in out
        # The updater restarts the node only when it knows something will bring
        # it back.
        assert "Environment=NMESH_SERVICE_MANAGED=1" in out
        # liboqs is built *inside* the prefix: a system account has no home
        # where the node could find its crypto library again.
        assert "Environment=HOME=/opt/nmesh" in out
        assert "Environment=OQS_INSTALL_PATH=/opt/nmesh/_oqs" in out
        assert "ProtectSystem=full" in out

    def test_systemd_unit_omits_user_when_empty(self, tmp_path):
        out = run_snippet(
            tmp_path,
            'systemd_unit /opt/nmesh /var/lib/nmesh "" "" default.target').stdout
        assert "User=" not in out
        assert "WantedBy=default.target" in out

    def test_openrc_service_runs_start_sh(self, tmp_path):
        out = run_snippet(
            tmp_path,
            'openrc_service /opt/nmesh /var/lib/nmesh nm "--fleet" nmesh').stdout
        assert 'command="/opt/nmesh/start.sh"' in out
        assert 'command_args="--fleet"' in out
        assert 'NMESH_DATA="/var/lib/nmesh"' in out
        assert "NMESH_SERVICE_MANAGED=1" in out
        assert 'OQS_INSTALL_PATH="/opt/nmesh/_oqs"' in out

    def test_launchd_plist_is_well_formed(self, tmp_path):
        out = run_snippet(
            tmp_path,
            'launchd_plist /opt/nmesh /var/lib/nmesh org.nmesh.x "--fleet"').stdout
        import xml.etree.ElementTree as ET
        ET.fromstring(out)          # raises if the plist is malformed
        assert "/opt/nmesh/start.sh" in out
        assert "<string>--fleet</string>" in out
        assert "NMESH_SERVICE_MANAGED" in out
        assert "OQS_INSTALL_PATH" in out


class TestServiceAccount:
    """The node runs under an account of its own: its identity, its session
    store and the console password's hash must be readable only by it."""

    def test_an_existing_account_is_not_recreated(self, tmp_path):
        result = run_snippet(
            tmp_path, 'SUDO=; create_service_user nmesh /opt/nmesh && echo REUSED',
            fake_bins=[("id", "#!/bin/sh\nexit 0\n"),
                       ("useradd", "#!/bin/sh\necho CREATED >&2\nexit 0\n")],
            isolate=True)
        assert "REUSED" in result.stdout
        assert "CREATED" not in result.stderr

    def test_creation_falls_through_to_the_next_tool(self, tmp_path):
        """Every distro spells "system account" differently and refuses the
        others' options: we try, we do not guess."""
        result = run_snippet(
            tmp_path, 'SUDO=; create_service_user nmesh /opt/nmesh && echo CREATED',
            fake_bins=[("id", "#!/bin/sh\nexit 1\n"),
                       ("useradd", "#!/bin/sh\nexit 1\n"),
                       ("adduser", "#!/bin/sh\nexit 0\n")],
            isolate=True)
        assert "CREATED" in result.stdout

    def test_no_tool_at_all_is_reported_not_assumed(self, tmp_path):
        result = run_snippet(
            tmp_path, 'SUDO=; create_service_user nmesh /opt/nmesh || echo NO_ACCOUNT',
            fake_bins=[("id", "#!/bin/sh\nexit 1\n")], isolate=True)
        assert "NO_ACCOUNT" in result.stdout

    def test_owner_spec_without_a_group_is_the_bare_name(self, tmp_path):
        """`chown nmesh:nmesh` fails outright when the distro put the account in
        `nogroup` — and would leave the tree unreadable for the node."""
        result = run_snippet(tmp_path, "owner_spec nmesh",
                             fake_bins=[("id", "#!/bin/sh\nexit 1\n")],
                             isolate=True)
        assert result.stdout.strip() == "nmesh"

    def test_owner_spec_uses_the_group_when_there_is_one(self, tmp_path):
        result = run_snippet(tmp_path, "owner_spec nmesh",
                             fake_bins=[("id", "#!/bin/sh\necho nmesh\n")],
                             isolate=True)
        assert result.stdout.strip() == "nmesh:nmesh"


class TestDirectories:
    def test_a_writable_parent_is_never_escalated(self, tmp_path):
        """The real bug: `sudo mkdir -p ~/.local/share/nmesh/data` gave the
        directory to root, and the node died on its very first write
        ("Permission denied: …/data/node.key.tmp")."""
        marker = tmp_path / "sudo-was-called"
        target = tmp_path / "home" / "share" / "nmesh" / "data"
        result = run_snippet(
            tmp_path,
            f'SUDO=sudo; is_root() {{ return 1; }}; ensure_dir "{target}" ""',
            fake_bins=[("sudo", f"#!/bin/sh\ntouch {marker}\nexec \"$@\"\n")])
        assert result.returncode == 0, result.stderr
        assert target.is_dir()
        assert not marker.exists()

    def test_an_unreachable_parent_does_escalate(self, tmp_path):
        marker = tmp_path / "sudo-was-called"
        result = run_snippet(
            tmp_path,
            f'SUDO=sudo; is_root() {{ return 1; }}; ensure_dir /proc/nmesh-nope "" || true',
            fake_bins=[("sudo", f"#!/bin/sh\ntouch {marker}\nexit 1\n")])
        assert marker.exists()


class TestTreeCopy:
    def test_copies_the_runtime_tree_only(self, tmp_path):
        src = tmp_path / "src_tree"
        (src / "src").mkdir(parents=True)
        (src / "src" / "node.py").write_text("code")
        (src / "src" / "__pycache__").mkdir()
        (src / "src" / "__pycache__" / "x.pyc").write_text("junk")
        (src / "start.sh").write_text("#!/bin/sh\n")
        (src / ".git").mkdir()
        (src / ".git" / "HEAD").write_text("ref")
        (src / ".venv").mkdir()
        (src / ".venv" / "marker").write_text("venv")
        (src / "data").mkdir()
        (src / "data" / "node.key").write_text("IDENTITY")
        dst = tmp_path / "dst"
        result = run_snippet(tmp_path, f'copy_tree "{src}" "{dst}"')
        assert result.returncode == 0, result.stderr

        assert (dst / "src" / "node.py").read_text() == "code"
        assert (dst / "start.sh").exists()
        # Neither the history, nor the venv, nor the node's state is to be copied.
        assert not (dst / ".git").exists()
        assert not (dst / ".venv").exists()
        assert not (dst / "data").exists()
        assert not (dst / "src" / "__pycache__").exists()

    def test_an_empty_source_is_refused(self, tmp_path):
        empty = tmp_path / "empty"
        empty.mkdir()
        result = run_snippet(tmp_path,
                             f'copy_tree "{empty}" "{tmp_path}/out" || echo REFUSED')
        assert "REFUSED" in result.stdout


class TestOrdering:
    """The config file is written 0600 by whoever runs the installer. Written
    *after* the lock-down, it stayed root:root and the node's account could not
    read it at all — the node fell back on its defaults and every setting in the
    file was silently ignored."""

    def test_the_config_is_written_before_the_lock_down(self):
        text = INSTALL.read_text()
        config_write = text.index('CONFIG_FILE="$PREFIX/')
        lock = text.index('lock_down "$PREFIX"')
        assert config_write < lock

    def test_the_lock_down_covers_the_install_directory(self):
        """It is that `chown -R` that catches the config file."""
        text = INSTALL.read_text()
        assert 'chown -R "$OWNER"' in text


class TestPasswordReset:
    def test_the_flag_is_documented(self):
        import subprocess as sp
        result = sp.run([BASH, str(INSTALL), "--help"], capture_output=True,
                        text=True, timeout=30, cwd=str(ROOT))
        assert "--reset-password" in result.stdout

    def test_it_delegates_the_hashing_to_the_node(self):
        """The credential's format must exist in one place only: a second
        implementation in shell that diverged would be a silent authentication
        bug."""
        text = INSTALL.read_text()
        assert "nmesh_password.py" in text
        assert "scrypt" not in text


class TestHelp:
    def test_help_mentions_the_essentials(self):
        result = subprocess.run([BASH, str(INSTALL), "--help"],
                                capture_output=True, text=True, timeout=30,
                                cwd=str(ROOT))
        assert result.returncode == 0
        for expected in ("--uninstall", "--prefix", "--purge", "start.sh"):
            assert expected in result.stdout

    def test_the_script_parses(self):
        assert subprocess.run([BASH, "-n", str(INSTALL)], timeout=30).returncode == 0

    def test_the_script_is_executable(self):
        assert os.access(INSTALL, os.X_OK)
