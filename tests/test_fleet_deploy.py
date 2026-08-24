"""Le déploiement distant doit être aussi solide que `install.sh` en local.

C'est la même installation : le bootstrap ne pose rien lui-même, il livre l'arbre
et appelle son `install.sh`. Un second installeur, plus faible, est exactement la
façon dont un déploiement distant finit moins solide qu'un local.
"""
import subprocess
import tempfile
import os

import pytest

from src.apps import fleet_provision as fp
from src.apps import fleet_ssh
from src.apps.fleet_ssh import SshCredentials, SshError

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def sh_check(text: str) -> int:
    with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False) as handle:
        handle.write(text)
        path = handle.name
    try:
        return subprocess.run(["sh", "-n", path], capture_output=True,
                              timeout=30).returncode
    finally:
        os.unlink(path)


class TestPayload:
    def test_install_sh_travels_with_the_tree(self):
        """Le bootstrap délègue tout à install.sh : un payload sans lui
        n'installe rien."""
        assert "install.sh" in fp.PAYLOAD_INCLUDE
        payload = fp.build_payload(ROOT)
        import gzip, io, tarfile
        with tarfile.open(fileobj=io.BytesIO(gzip.decompress(payload))) as archive:
            names = archive.getnames()
        assert "install.sh" in names
        assert "start.sh" in names

    def test_a_tree_without_install_sh_is_refused(self, tmp_path):
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "node.py").write_text("code")
        (tmp_path / "start.sh").write_text("#!/bin/sh\n")
        with pytest.raises(fp.ProvisionError):
            fp.build_payload(str(tmp_path))

    def test_state_and_secrets_never_travel(self):
        payload = fp.build_payload(ROOT)
        import gzip, io, tarfile
        with tarfile.open(fileobj=io.BytesIO(gzip.decompress(payload))) as archive:
            names = archive.getnames()
        for name in names:
            parts = set(name.split("/"))
            assert not (parts & {"data", ".venv", ".git", "tests"}), name


class TestTheTwoPhases:
    """Le secret d'élévation n'entre jamais dans un script : la phase qui a
    besoin de root demande un terminal distant, et le pty local y répond."""

    def test_both_phases_are_valid_posix_shell(self):
        stage = fp.staging_name()
        assert sh_check(fp.build_bootstrap(b"payload", {"a": 1}, stage=stage)) == 0
        assert sh_check(fp.build_install_phase(stage=stage)) == 0

    def test_the_delivery_phase_needs_no_privilege(self):
        """Elle est pipée sur stdin : elle ne doit jamais vouloir de terminal,
        donc jamais escalader ni lancer l'installation."""
        script = fp.build_bootstrap(b"payload", {}, stage=fp.staging_name())
        code = [line for line in script.splitlines()
                if line.strip() and not line.strip().startswith("#")]
        for forbidden in ("sudo ", "su - ", "./install.sh"):
            offenders = [line for line in code if forbidden in line]
            assert not offenders, (forbidden, offenders)

    def test_no_password_is_ever_written_into_a_script(self):
        stage = fp.staging_name()
        creds = SshCredentials("bob", password="LOGINSECRET",
                               sudo_password="SUDOSECRET")
        scripts = (fp.build_bootstrap(b"x", {}, stage=stage)
                   + fp.build_install_phase(stage=stage,
                                            can_sudo=creds.can_sudo,
                                            sudo_user=creds.sudo_user))
        assert "LOGINSECRET" not in scripts
        assert "SUDOSECRET" not in scripts

    def test_the_install_phase_calls_install_sh_and_nothing_of_its_own(self):
        script = fp.build_install_phase(stage=fp.staging_name())
        assert "./install.sh" in script
        # Aucune unité écrite à la main : c'est le travail d'install.sh.
        for reimplemented in ("[Unit]", "openrc-run", "launchctl load",
                              "systemctl daemon-reload"):
            assert reimplemented not in script, reimplemented

    def test_a_system_install_names_the_expected_places(self):
        script = fp.build_install_phase(stage=fp.staging_name(), mode="system")
        assert "/opt/nmesh" in script and "/var/lib/nmesh" in script

    def test_a_user_install_runs_as_the_login_account(self):
        script = fp.build_install_phase(stage=fp.staging_name(), mode="user")
        assert "$HOME/.nmesh" in script
        assert "--run-as '$(id -un)'" in script

    def test_an_unknown_mode_is_refused(self):
        with pytest.raises(fp.ProvisionError):
            fp.build_install_phase(stage=fp.staging_name(), mode="root-ish")

    def test_escalation_is_stated_never_probed(self):
        """Sonder pour savoir si on peut sudo, c'est des échecs sudo dans le
        journal d'authentification de la cible."""
        script = fp.build_install_phase(stage=fp.staging_name(), can_sudo=False)
        assert "CAN_SUDO=0" in script
        assert "a system install needs root" in script

    def test_the_staging_directory_is_unguessable(self):
        names = {fp.staging_name() for _ in range(20)}
        assert len(names) == 20
        assert all(name.startswith(".nmesh-deploy-") for name in names)


class TestCredentials:
    def test_the_login_password_is_the_default_sudo_password(self):
        creds = SshCredentials("bob", password="p")
        assert creds.elevate_secret == "p"

    def test_another_account_uses_its_own_password(self):
        creds = SshCredentials("bob", password="p", sudo_user="admin",
                               sudo_password="s")
        assert creds.elevate_secret == "s"

    def test_no_elevation_is_reported_not_assumed(self):
        assert SshCredentials("bob", password="p", can_sudo=False).has_elevation \
            is False
        assert SshCredentials("bob", password="p").has_elevation is True
        assert SshCredentials("bob", password="p", can_sudo=False,
                              sudo_user="admin").has_elevation is True

    def test_the_sudo_password_is_dropped_with_the_rest(self):
        creds = SshCredentials("bob", password="p", sudo_password="s")
        creds.wipe()
        assert creds.elevate_secret is None

    def test_the_repr_never_shows_either_secret(self):
        creds = SshCredentials("bob", password="LOGINSECRET",
                               sudo_password="SUDOSECRET")
        assert "LOGINSECRET" not in repr(creds)
        assert "SUDOSECRET" not in repr(creds)

    def test_a_bad_sudo_username_is_refused(self):
        for bad in ("", "a b", "x" * 65):
            with pytest.raises(SshError):
                SshCredentials("bob", password="p", sudo_user=bad)


class TestPromptOrdering:
    """Quel secret veut un prompt se décide au *moment*, pas au libellé :
    `sudo` demande « password for » et `su` un « password: » nu, tous deux
    indiscernables de celui d'OpenSSH."""

    def fresh(self, may_elevate=1):
        return {"password": 0, "passphrase": 0, "elevate": 0,
                "may_elevate": may_elevate}

    def test_the_first_prompt_is_the_login(self):
        creds = SshCredentials("bob", password="LOGIN", sudo_password="SUDO")
        answered = self.fresh()
        assert fleet_ssh._prompt_answer(b"bob@host's password:", creds,
                                        answered) == b"LOGIN\n"

    def test_the_next_one_is_the_escalation(self):
        creds = SshCredentials("bob", password="LOGIN", sudo_password="SUDO")
        answered = self.fresh()
        fleet_ssh._prompt_answer(b"bob@host's password:", creds, answered)
        assert fleet_ssh._prompt_answer(b"password: ", creds,
                                        answered) == b"SUDO\n"

    def test_a_re_prompt_outside_an_escalating_run_is_ignored(self):
        """Sans terminal distant il n'y a pas de sudo en face : un second prompt
        est OpenSSH qui redemande, et le rejouer brûle une tentative."""
        creds = SshCredentials("bob", password="LOGIN")
        answered = self.fresh(may_elevate=0)
        assert fleet_ssh._prompt_answer(b"bob@host's password:", creds,
                                        answered) == b"LOGIN\n"
        assert fleet_ssh._prompt_answer(b"bob@host's password:", creds,
                                        answered) is None

    def test_a_third_prompt_is_left_unanswered(self):
        """Un re-prompt veut dire que le secret était faux ; le rejouer ne fait
        que brûler des tentatives contre un verrouillage."""
        creds = SshCredentials("bob", password="LOGIN", sudo_password="SUDO")
        answered = self.fresh()
        fleet_ssh._prompt_answer(b"bob@host's password:", creds, answered)
        fleet_ssh._prompt_answer(b"password: ", creds, answered)
        assert fleet_ssh._prompt_answer(b"password: ", creds, answered) is None

    def test_with_key_auth_a_sudo_prompt_is_an_escalation(self):
        creds = SshCredentials("bob", key_path="/k", sudo_password="SUDO")
        assert fleet_ssh._prompt_answer(b"[sudo] password for bob:", creds,
                                        self.fresh()) == b"SUDO\n"

    def test_a_passphrase_prompt_is_neither(self):
        creds = SshCredentials("bob", key_path="/k", key_passphrase="PASS",
                               sudo_password="SUDO")
        assert fleet_ssh._prompt_answer(b"enter passphrase for key", creds,
                                        self.fresh()) == b"PASS\n"


class TestTtyContract:
    async def test_piping_data_into_a_tty_command_is_refused(self):
        """Avec un terminal distant, stdin *est* le terminal : des données
        pipées et un prompt liraient le même canal."""
        creds = SshCredentials("bob", password="p")
        with pytest.raises(SshError):
            await fleet_ssh.run("host", creds, ["/bin/sh"],
                                stdin_data=b"data", request_tty=True)


class TestRefusals:
    """Un install système sans moyen d'atteindre root doit être refusé *avant*
    d'ouvrir une session SSH, pas après que l'opérateur ait tout tapé."""

    async def test_the_app_refuses_a_system_install_with_no_route_to_root(self):
        from tests.test_fleet import Peer
        app = Peer(repo_root=ROOT).app
        with pytest.raises(fp.ProvisionError) as exc:
            await app.provision_local(
                [{"ip": "10.0.0.5"}], username="bob", password="pw",
                can_sudo=False, mode="system")
        assert "root" in str(exc.value)

    async def test_a_user_install_needs_no_route_to_root(self):
        """Il n'a pas besoin de root : il doit passer la porte, quoi qu'il
        arrive ensuite côté machine."""
        from tests.test_fleet import Peer
        app = Peer(repo_root=ROOT).app
        try:
            await app.provision_local(
                [{"ip": "10.0.0.5"}], username="bob", password="pw",
                can_sudo=False, mode="user")
        except fp.ProvisionError as exc:
            assert "root" not in str(exc), exc
        except Exception:
            pass          # l'échec SSH qui suit n'est pas ce qu'on teste ici
