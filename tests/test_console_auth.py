"""Le credential de la console : hachage, stockage, vérification.

Une seule implémentation, partagée par la console et par le script de reset de
l'installeur — un format qui divergerait entre deux écrivains serait un bug
d'authentification silencieux.
"""
import os
import stat

import pytest

from src import console_auth


class TestHashing:
    def test_the_password_itself_is_never_stored(self, tmp_path):
        path = str(tmp_path / "console.cred")
        console_auth.write(path, "a-perfectly-fine-password")
        with open(path) as handle:
            stored = handle.read()
        assert "a-perfectly-fine-password" not in stored
        assert stored.startswith("scrypt$")

    def test_the_same_password_hashes_differently_each_time(self, tmp_path):
        """Un sel par credential : deux nœuds avec le même mot de passe ne
        doivent pas se reconnaître dans un fichier volé."""
        first = str(tmp_path / "a.cred")
        second = str(tmp_path / "b.cred")
        console_auth.write(first, "identical-password-here")
        console_auth.write(second, "identical-password-here")
        assert open(first).read() != open(second).read()

    def test_a_round_trip_checks_out(self, tmp_path):
        path = str(tmp_path / "console.cred")
        salt, digest = console_auth.write(path, "the-right-password")
        assert console_auth.check("the-right-password", salt, digest)
        assert not console_auth.check("the-wrong-password", salt, digest)

    def test_a_stored_credential_reads_back(self, tmp_path):
        path = str(tmp_path / "console.cred")
        console_auth.write(path, "the-right-password")
        salt, digest = console_auth.read(path)
        assert console_auth.check("the-right-password", salt, digest)

    def test_an_absurdly_long_password_is_refused_before_hashing(self):
        """scrypt sur une entrée non bornée est le déni de service le moins
        cher qui soit."""
        salt, digest = b"\x00" * 16, b"\x00" * 32
        assert console_auth.check("x" * (console_auth.MAX_LENGTH + 1),
                                  salt, digest) is False

    def test_a_non_string_never_raises(self):
        salt, digest = b"\x00" * 16, b"\x00" * 32
        assert console_auth.check(None, salt, digest) is False
        assert console_auth.check(1234, salt, digest) is False


class TestCorruptFiles:
    def test_a_missing_file_is_not_a_credential(self, tmp_path):
        assert console_auth.read(str(tmp_path / "absent.cred")) is None

    def test_garbage_is_not_a_credential(self, tmp_path):
        path = tmp_path / "console.cred"
        path.write_text("this is not a credential")
        assert console_auth.read(str(path)) is None

    def test_an_unknown_algorithm_is_refused(self, tmp_path):
        """Un jour où on changera de KDF, un vieux fichier ne doit pas être lu
        comme s'il était du nouveau."""
        path = tmp_path / "console.cred"
        path.write_text("md5$aabb$ccdd")
        assert console_auth.read(str(path)) is None

    def test_non_hex_fields_are_refused(self, tmp_path):
        path = tmp_path / "console.cred"
        path.write_text("scrypt$zzzz$yyyy")
        assert console_auth.read(str(path)) is None

    def test_an_enormous_file_does_not_hang_the_read(self, tmp_path):
        path = tmp_path / "console.cred"
        path.write_text("scrypt$" + "a" * (2 * 1024 * 1024))
        assert console_auth.read(str(path)) is None


class TestValidation:
    def test_a_short_password_is_refused(self):
        with pytest.raises(console_auth.CredentialError):
            console_auth.validate("short")

    def test_an_endless_password_is_refused(self):
        with pytest.raises(console_auth.CredentialError):
            console_auth.validate("x" * (console_auth.MAX_LENGTH + 1))

    def test_surrounding_whitespace_is_refused(self):
        """Invisible dans un formulaire, impossible à retaper plus tard."""
        with pytest.raises(console_auth.CredentialError):
            console_auth.validate("  a-fine-password-here  ")

    def test_a_non_string_is_refused(self):
        with pytest.raises(console_auth.CredentialError):
            console_auth.validate(None)

    def test_a_reasonable_password_passes(self):
        assert console_auth.validate("a-reasonable-password") == \
            "a-reasonable-password"

    def test_a_generated_password_passes_its_own_rules(self):
        for _ in range(20):
            console_auth.validate(console_auth.generate())


class TestOnDisk:
    def test_the_file_is_owner_only(self, tmp_path):
        path = str(tmp_path / "console.cred")
        console_auth.write(path, "a-perfectly-fine-password")
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o600

    def test_the_umask_cannot_loosen_it(self, tmp_path):
        """Créé en 0600 dès le premier octet, pas resserré après coup : « après
        coup » est une fenêtre où n'importe qui sur la machine peut le lire."""
        path = str(tmp_path / "console.cred")
        previous = os.umask(0)
        try:
            console_auth.write(path, "a-perfectly-fine-password")
        finally:
            os.umask(previous)
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o600

    def test_no_temporary_file_is_left_behind(self, tmp_path):
        path = str(tmp_path / "console.cred")
        console_auth.write(path, "a-perfectly-fine-password")
        assert not os.path.exists(path + ".tmp")
