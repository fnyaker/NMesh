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
        config_write = text.index('CONFIG_FILE="$INSTALL_DIR/')
        lock = text.index('lock_down "$INSTALL_DIR"')
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


class TestPrefixIsNotOurs:
    """Termux exports PREFIX — its own /data/data/com.termux/files/usr — and
    assigning to an inherited exported variable keeps it exported. The installer
    called its install directory PREFIX, so every child, start.sh included, was
    handed the install directory as Termux's prefix: start.sh's Android probe
    ($PREFIX/bin/pkg) found nothing and set a phone up as a Debian box, down to
    apt package names and a hunt for sudo."""

    def _code(self):
        return "\n".join(line for line in INSTALL.read_text().splitlines()
                         if not line.strip().startswith("#"))

    def test_the_installer_never_assigns_to_prefix(self):
        import re
        assert not re.search(r'(?<![A-Z_])PREFIX=', self._code())

    def test_the_installer_never_takes_its_install_dir_from_prefix(self):
        import re
        assert not re.search(r'INSTALL_DIR=.*\$\{?PREFIX\b', self._code())

    def test_prefix_is_only_ever_read_as_termux_own(self):
        """It is read again now — to find Termux's pkg, its service directory
        and its sh — and that is exactly the value the rename protects."""
        import re
        termux_paths = ("bin/pkg", "bin/sh", "var/service", "var/log/sv")
        for line in self._code().splitlines():
            if re.search(r'\$\{?PREFIX\b', line):
                assert any(path in line for path in termux_paths), line

    def test_the_install_directory_has_a_name_of_its_own(self):
        code = self._code()
        assert 'INSTALL_DIR="${NMESH_PREFIX:-}"' in code
        assert '--prefix)     INSTALL_DIR=' in code

    def test_termux_keeps_its_prefix_when_the_installer_runs_start_sh(self, tmp_path):
        """The environment start.sh is handed must still describe the machine."""
        result = run_snippet(
            tmp_path,
            'INSTALL_DIR=/somewhere/else; echo "PREFIX=[${PREFIX:-}]"',
            env={"PREFIX": "/data/data/com.termux/files/usr"},
        )
        assert "PREFIX=[/data/data/com.termux/files/usr]" in result.stdout


class TestAndroidService:
    """A phone had "No supported init system found — nothing will start
    automatically", and the manual command it offered was `sudo -u <yourself>`,
    which on Termux prints sudo's help screen. Android has no init a package can
    reach, but termux-services runs runit inside the app."""

    def _termux(self, tmp_path):
        """A PREFIX that looks like Termux's, with the tools it ships."""
        prefix = tmp_path / "usr"
        (prefix / "bin").mkdir(parents=True, exist_ok=True)
        for name in ("pkg", "sv", "sv-enable"):
            tool = prefix / "bin" / name
            tool.write_text("#!/bin/sh\nexit 0\n")
            tool.chmod(0o755)
        return prefix

    def test_termux_with_services_has_a_service_manager(self, tmp_path):
        prefix = self._termux(tmp_path)
        result = run_snippet(
            tmp_path, 'detect_init',
            env={"PREFIX": str(prefix), "PATH": f"{prefix}/bin:/usr/bin:/bin"})
        assert result.stdout.strip() == "runit"

    def test_a_phone_without_termux_services_is_offered_them(self, tmp_path):
        """Reporting "nothing will start automatically" while the fix is one
        package away is not a report, it is a shrug."""
        prefix = self._termux(tmp_path)
        (prefix / "bin" / "sv-enable").unlink()
        result = run_snippet(
            tmp_path, 'ensure_termux_services && echo INSTALLED || echo GAVE_UP',
            env={"PREFIX": str(prefix), "PATH": f"{prefix}/bin:/usr/bin:/bin"})
        assert "termux-services" in result.stdout + result.stderr

    def test_the_run_script_starts_the_node_in_the_foreground(self, tmp_path):
        """runsv owns the restarting: a run script that daemonises is a service
        that runit thinks died."""
        result = run_snippet(
            tmp_path, 'runit_service /opt/nmesh /var/lib/nmesh "--fleet"',
            env={"PREFIX": "/data/data/com.termux/files/usr"})
        script = result.stdout
        assert script.startswith("#!/data/data/com.termux/files/usr/bin/sh")
        assert "exec ./start.sh --fleet" in script
        assert 'cd "/opt/nmesh"' in script
        assert 'NMESH_DATA="/var/lib/nmesh"' in script
        # `exec 2>&1` is the redirect runit wants; a backgrounded command is
        # what it must never see.
        assert not [line for line in script.splitlines() if line.rstrip().endswith("&")]

    def test_the_service_says_where_its_log_is(self, tmp_path):
        result = run_snippet(tmp_path, 'service_hint runit nmesh',
                             env={"PREFIX": "/data/data/com.termux/files/usr"})
        assert "sv status nmesh" in result.stdout
        assert "/var/log/sv/nmesh/current" in result.stdout

    def test_uninstalling_does_not_install_a_package(self, tmp_path):
        """Removing NMesh from a phone is not the moment to put something new
        on it."""
        text = INSTALL.read_text()
        guard = text[text.index('INIT="$(detect_init)"'):]
        guard = guard[:guard.index("ensure_termux_services")]
        assert '"$UNINSTALL" != true' in guard
        assert '"$RESET_PASSWORD" != true' in guard


class TestOwnership:
    """A user install names itself as the owner, and the string comparison never
    noticed: owner_spec makes "name:group", `id -u`/`id -g` make numbers. So
    every user install chowned its files to itself — a no-op on Linux, a pair of
    warnings on Android, where nothing may chown anything and nothing needs to."""

    def test_my_own_account_is_recognised(self, tmp_path):
        result = run_snippet(
            tmp_path,
            'owner_is_me "$(id -un):$(id -gn)" && echo ME || echo SOMEONE_ELSE')
        assert result.stdout.strip() == "ME"

    def test_my_own_account_without_a_group_is_recognised(self, tmp_path):
        result = run_snippet(tmp_path,
                             'owner_is_me "$(id -un)" && echo ME || echo SOMEONE_ELSE')
        assert result.stdout.strip() == "ME"

    def test_somebody_else_is_not_me(self, tmp_path):
        result = run_snippet(
            tmp_path, 'owner_is_me "nmesh:nmesh" && echo ME || echo SOMEONE_ELSE')
        assert result.stdout.strip() == "SOMEONE_ELSE"

    def test_nothing_is_not_me(self, tmp_path):
        result = run_snippet(tmp_path,
                             'owner_is_me "" && echo ME || echo SOMEONE_ELSE')
        assert result.stdout.strip() == "SOMEONE_ELSE"

    def test_the_manual_hint_never_sudoes_to_yourself(self):
        """`sudo -u you` asks for a password to become who you already are, and
        on Termux it just prints sudo's help."""
        text = INSTALL.read_text()
        hint = text[text.index("No supported init system found"):]
        hint = hint[:hint.index("esac")]
        assert 'owner_is_me "$RUN_USER"' in hint
        assert "cd $INSTALL_DIR && NMESH_DATA=$DATA ./start.sh" in hint
