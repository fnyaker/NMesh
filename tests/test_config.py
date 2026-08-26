"""The node's configuration file.

It is read at startup and written from the console: it is therefore both an
input to the process and an editing surface. The two requirements meet —
nothing it contains may stop a node from starting, and nothing the console sends
may write a value the node would then refuse.
"""
import os
import stat
import subprocess
import sys

import pytest

from src import config

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


class TestParsing:
    def test_a_plain_file_round_trips(self, tmp_path):
        path = str(tmp_path / "nmesh.conf")
        values = config.defaults()
        values["fleet"] = True
        values["console_port"] = 9999
        values["listen"] = "0.0.0.0:9100"
        config.save(path, values)
        loaded, problems = config.load(path)
        assert problems == []
        assert loaded["fleet"] is True
        assert loaded["console_port"] == 9999
        assert loaded["listen"] == "0.0.0.0:9100"

    def test_a_missing_file_is_not_a_problem(self, tmp_path):
        loaded, problems = config.load(str(tmp_path / "absent.conf"))
        assert loaded == {} and problems == []

    def test_comments_and_blank_lines_are_ignored(self):
        values, problems = config.parse("# a comment\n\n  \nfleet = true\n")
        assert values == {"fleet": True} and problems == []

    def test_only_the_keys_present_are_returned(self):
        """The launcher has to tell "unset" from "set to the value that happens
        to be the default": that is what makes precedence work."""
        values, _ = config.parse("fleet = true\n")
        assert list(values) == ["fleet"]

    def test_dashes_and_underscores_are_the_same_key(self):
        values, problems = config.parse("console-port = 9000\n")
        assert values["console_port"] == 9000 and problems == []

    def test_booleans_accept_the_usual_spellings(self):
        for text in ("true", "yes", "on", "1"):
            assert config.parse(f"fleet = {text}")[0]["fleet"] is True
        for text in ("false", "no", "off", "0"):
            assert config.parse(f"fleet = {text}")[0]["fleet"] is False

    def test_launch_is_a_repeatable_key(self):
        values, _ = config.parse("launch = /bin/a\nlaunch = /bin/b\n")
        assert values["launch"] == ["/bin/a", "/bin/b"]

    def test_a_tcp_prefix_on_listen_is_accepted(self):
        assert config.parse("listen = tcp://0.0.0.0:9000")[0]["listen"] == "0.0.0.0:9000"


class TestHostileFiles:
    """An unreadable file is reported and set aside: a node that does not start
    is a worse outcome than a node on its defaults."""

    def test_a_garbage_line_does_not_lose_the_rest(self):
        values, problems = config.parse("this is not a setting\nfleet = true\n")
        assert values["fleet"] is True
        assert len(problems) == 1

    def test_an_unknown_key_is_reported_not_fatal(self):
        values, problems = config.parse("backdoor = yes\nfleet = true\n")
        assert values == {"fleet": True}
        assert any("unknown" in p for p in problems)

    def test_a_bad_value_leaves_the_setting_unset(self):
        values, problems = config.parse("console_port = 99999\n")
        assert "console_port" not in values
        assert problems and "1 and 65535" in problems[0]

    def test_a_huge_file_is_refused_whole(self):
        values, problems = config.parse("fleet = true\n" + "x" * (config.MAX_BYTES + 1))
        assert values == {}
        assert problems and "larger than" in problems[0]

    def test_too_many_lines_stop_at_the_bound(self):
        values, problems = config.parse("\n".join(["fleet = true"] * (config.MAX_LINES + 50)))
        assert any("lines" in p for p in problems)

    def test_a_giant_value_is_dropped_not_stored(self):
        values, problems = config.parse("listen = " + "a" * (config.MAX_VALUE + 1))
        assert "listen" not in values and problems

    def test_too_many_launch_entries_are_bounded(self):
        text = "\n".join([f"launch = /bin/x{i}" for i in range(config.MAX_LIST + 10)])
        values, problems = config.parse(text)
        assert len(values["launch"]) == config.MAX_LIST
        assert problems

    def test_random_bytes_never_raise(self):
        import random
        random.seed(1234)
        for _ in range(200):
            blob = bytes(random.randrange(256) for _ in range(120))
            values, problems = config.parse(blob.decode("utf-8", "replace"))
            assert isinstance(values, dict) and isinstance(problems, list)

    def test_a_null_byte_in_a_path_is_refused(self):
        values, problems = config.parse("spool = /tmp/a\0b\n")
        assert "spool" not in values and problems

    def test_a_hostile_host_value_is_refused(self):
        for bad in ("a b", "a;rm -rf /", "$(id)", "`id`", "a|b", "a/../b"):
            values, problems = config.parse(f"console_host = {bad}\n")
            assert "console_host" not in values, bad

    def test_a_value_cannot_smuggle_a_second_line(self):
        """A value carrying a newline would reopen as two lines at the next
        load — a setting written through the back door."""
        with pytest.raises(config.ConfigError):
            config.validate("console_host", "example.com\nfleet = true")
        with pytest.raises(config.ConfigError):
            config.validate("listen", "0.0.0.0:9000\nfleet = true")


class TestConsoleEdits:
    def test_a_valid_edit_is_applied(self):
        merged, rejected = config.apply_edits(config.defaults(),
                                              {"console_port": "9100"})
        assert merged["console_port"] == 9100 and rejected == []

    def test_a_bad_field_never_takes_the_others_down(self):
        merged, rejected = config.apply_edits(
            config.defaults(), {"console_port": "banana", "fleet": True})
        assert rejected and "console_port" in rejected[0]
        # The refused value stays as it was; the other is not lost.
        assert merged["console_port"] == config.defaults()["console_port"]
        assert merged["fleet"] is True

    def test_launch_is_not_writable_from_the_console(self):
        """Choosing what the node runs is not a setting: it belongs to whoever
        holds the file, not to a web form."""
        merged, rejected = config.apply_edits(config.defaults(),
                                              {"launch": "/bin/sh -c evil"})
        assert rejected and "launch" in rejected[0]
        assert merged["launch"] == []

    def test_the_state_directory_is_not_writable_either(self):
        merged, rejected = config.apply_edits(config.defaults(), {"data": "/tmp/x"})
        assert rejected and merged["data"] is None

    def test_an_unknown_setting_is_refused(self):
        merged, rejected = config.apply_edits(config.defaults(), {"backdoor": "1"})
        assert rejected and "backdoor" not in merged

    def test_a_non_dict_payload_is_refused(self):
        merged, rejected = config.apply_edits(config.defaults(), ["fleet"])
        assert rejected and merged == config.defaults()

    def test_booleans_arrive_as_json_booleans(self):
        merged, rejected = config.apply_edits(config.defaults(), {"fleet": True})
        assert merged["fleet"] is True and rejected == []


class TestOnDisk:
    def test_the_file_is_owner_only(self, tmp_path):
        """It holds no secret today — all the more reason for it not to become
        the place where the first one appears unnoticed."""
        path = str(tmp_path / "nmesh.conf")
        config.save(path, config.defaults())
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o600

    def test_a_permissive_file_is_tightened_on_rewrite(self, tmp_path):
        path = str(tmp_path / "nmesh.conf")
        config.save(path, config.defaults())
        os.chmod(path, 0o644)
        config.save(path, config.defaults())
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o600

    def test_no_temporary_file_is_left_behind(self, tmp_path):
        path = str(tmp_path / "nmesh.conf")
        config.save(path, config.defaults())
        assert not os.path.exists(path + ".tmp")

    def test_the_password_is_never_a_setting(self):
        """A password in the clear, in a file meant to be edited and read, is
        not a configuration option."""
        assert not any("password" in name for name in config.SETTINGS)
        for line in config.render(config.defaults()).splitlines():
            stripped = line.strip()
            assert stripped.startswith("#") or "password" not in stripped.lower()

    def test_every_setting_is_documented_in_the_rendered_file(self):
        text = config.render(config.defaults())
        for name, (_parser, _default, _writable, help_text) in config.SETTINGS.items():
            assert help_text in text, name


class TestUnreadableFile:
    """A file that is present but unreadable is not the same thing as an absent
    one: the second is normal, the first is a broken installation that would run
    the node on settings nobody chose."""

    def test_it_is_reported_not_silently_empty(self, tmp_path, monkeypatch):
        path = tmp_path / "nmesh.conf"
        path.write_text("fleet = true\n")

        def refuse(*args, **kwargs):
            raise PermissionError(13, "Permission denied")

        monkeypatch.setattr("builtins.open", refuse)
        values, problems = config.load(str(path))
        assert values == {}
        assert problems and "Permission denied" in problems[0]

    def test_an_absent_file_stays_silent(self, tmp_path):
        values, problems = config.load(str(tmp_path / "nope.conf"))
        assert values == {} and problems == []


class TestLauncherPrecedence:
    """`scripts/nmesh_node.py` applies command line > file > default, and says
    which were overridden — a silently ignored file is exactly the failure we
    want to make visible."""

    def settle(self, path, argv):
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "nmesh_node_module", os.path.join(ROOT, "scripts", "nmesh_node.py"))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        import argparse

        class Args:
            pass

        args = Args()
        for name in config.SETTINGS:
            setattr(args, name, None)
        args.launch = []
        args.config = str(path)
        for name, value in argv.items():
            setattr(args, name, value)
        return module._settle(args), args

    def test_the_file_is_applied_when_no_flag_is_given(self, tmp_path):
        path = tmp_path / "nmesh.conf"
        path.write_text("fleet = true\nconsole_host = 0.0.0.0\n")
        (_path, problems, overridden, _transports), args = self.settle(path, {})
        assert problems == [] and overridden == []
        assert args.fleet is True and args.console_host == "0.0.0.0"

    def test_a_flag_wins_and_says_so(self, tmp_path):
        path = tmp_path / "nmesh.conf"
        path.write_text("console_port = 9000\n")
        (_path, _problems, overridden, _transports), args = self.settle(
            path, {"console_port": 9443})
        assert args.console_port == 9443
        assert overridden == ["console_port"]

    def test_defaults_fill_what_neither_says(self, tmp_path):
        path = tmp_path / "nmesh.conf"
        path.write_text("fleet = true\n")
        (_path, _problems, _overridden, _transports), args = self.settle(path, {})
        assert args.console_port == 8787 and args.listen == "0.0.0.0:9000"


class TestInstallerMerge:
    """`install.sh` passe ses options au fichier via scripts/nmesh_config.py."""

    def run(self, path, *args):
        return subprocess.run(
            [sys.executable, os.path.join(ROOT, "scripts", "nmesh_config.py"),
             str(path), *args],
            capture_output=True, text=True, timeout=60, cwd=ROOT)

    def test_a_boolean_flag_lands_in_the_file(self, tmp_path):
        path = tmp_path / "nmesh.conf"
        result = self.run(path, "--fleet")
        assert result.returncode == 0, result.stderr
        assert config.load(str(path))[0]["fleet"] is True

    def test_a_valued_flag_lands_in_the_file(self, tmp_path):
        path = tmp_path / "nmesh.conf"
        self.run(path, "--console-host", "0.0.0.0", "--console-port", "9443")
        values = config.load(str(path))[0]
        assert values["console_host"] == "0.0.0.0"
        assert values["console_port"] == 9443

    def test_existing_settings_survive_a_second_run(self, tmp_path):
        path = tmp_path / "nmesh.conf"
        self.run(path, "--fleet")
        self.run(path, "--console-port", "9443")
        values = config.load(str(path))[0]
        assert values["fleet"] is True and values["console_port"] == 9443

    def test_an_unknown_option_is_handed_back_not_dropped(self, tmp_path):
        path = tmp_path / "nmesh.conf"
        result = self.run(path, "--fleet", "--not-a-setting", "x")
        assert result.stdout.split() == ["--not-a-setting", "x"]
        assert config.load(str(path))[0]["fleet"] is True

    def test_an_invalid_value_is_reported_and_not_written(self, tmp_path):
        path = tmp_path / "nmesh.conf"
        result = self.run(path, "--console-port", "70000")
        assert "70000" in result.stderr
        assert config.load(str(path))[0].get("console_port") == 8787


class TestPasswordScript:
    """`install.sh --reset-password` passe par scripts/nmesh_password.py."""

    SCRIPT = os.path.join(ROOT, "scripts", "nmesh_password.py")

    def run(self, *args, stdin=None):
        return subprocess.run([sys.executable, self.SCRIPT, *args],
                              input=stdin, capture_output=True, text=True,
                              timeout=60, cwd=ROOT)

    def test_it_generates_and_prints_a_password(self, tmp_path):
        result = self.run(str(tmp_path))
        assert result.returncode == 0, result.stderr
        password = result.stdout.strip()
        from src import console_auth
        salt, digest = console_auth.read(str(tmp_path / "console.cred"))
        assert console_auth.check(password, salt, digest)

    def test_stdout_carries_the_password_and_nothing_else(self):
        """install.sh captures stdout: a banner slipping in there would become
        the password."""
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            result = self.run(d)
            assert len(result.stdout.strip().splitlines()) == 1

    def test_a_chosen_password_comes_from_stdin_not_the_arguments(self, tmp_path):
        """A password in an argument is readable by everyone in `ps`."""
        result = self.run(str(tmp_path), "--stdin", stdin="a-chosen-password\n")
        assert result.returncode == 0, result.stderr
        from src import console_auth
        salt, digest = console_auth.read(str(tmp_path / "console.cred"))
        assert console_auth.check("a-chosen-password", salt, digest)

    def test_a_weak_password_is_refused_and_nothing_is_written(self, tmp_path):
        result = self.run(str(tmp_path), "--stdin", stdin="short\n")
        assert result.returncode == 1
        assert not (tmp_path / "console.cred").exists()

    def test_a_missing_state_directory_is_reported(self, tmp_path):
        result = self.run(str(tmp_path / "nowhere"))
        assert result.returncode == 1 and "no such state directory" in result.stderr

    def test_the_written_file_is_owner_only(self, tmp_path):
        self.run(str(tmp_path))
        mode = stat.S_IMODE(os.stat(tmp_path / "console.cred").st_mode)
        assert mode == 0o600
