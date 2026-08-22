"""Le fichier de configuration du nœud.

Il est lu au démarrage et écrit depuis la console : c'est donc à la fois une
entrée du processus et une surface d'édition. Les deux exigences se rejoignent —
rien de ce qu'il contient ne doit pouvoir empêcher un nœud de démarrer, et rien
de ce que la console envoie ne doit pouvoir écrire une valeur que le nœud
refuserait ensuite.
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
        """Le lanceur doit distinguer « non réglé » de « réglé à la valeur qui
        se trouve être le défaut » : c'est ce qui fait marcher la précédence."""
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
    """Un fichier illisible se signale et s'ignore : un nœud qui ne démarre pas
    est un pire résultat qu'un nœud sur ses valeurs par défaut."""

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
        """Une valeur qui emporte un saut de ligne se rouvrirait en deux lignes
        au prochain chargement — un réglage écrit par la porte de derrière."""
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
        # La valeur refusée reste celle d'avant ; l'autre n'est pas perdue.
        assert merged["console_port"] == config.defaults()["console_port"]
        assert merged["fleet"] is True

    def test_launch_is_not_writable_from_the_console(self):
        """Choisir ce que le nœud exécute n'est pas un réglage : ça appartient à
        qui détient le fichier, pas à un formulaire web."""
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
        """Il ne contient pas de secret aujourd'hui — raison de plus pour qu'il
        ne devienne pas l'endroit où le premier apparaîtrait sans qu'on le voie."""
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
        """Un mot de passe en clair dans un fichier fait pour être édité et lu
        n'est pas une option de configuration."""
        assert not any("password" in name for name in config.SETTINGS)
        for line in config.render(config.defaults()).splitlines():
            stripped = line.strip()
            assert stripped.startswith("#") or "password" not in stripped.lower()

    def test_every_setting_is_documented_in_the_rendered_file(self):
        text = config.render(config.defaults())
        for name, (_parser, _default, _writable, help_text) in config.SETTINGS.items():
            assert help_text in text, name


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
