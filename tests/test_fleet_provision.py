"""
SSH reach & provisioning tests.

Two properties carry the weight here:

  - **the credential never leaks** — not into ``argv`` (visible in ``ps`` to
    every local user), not into the environment, not into a file, not into a
    repr or a log line, and not into the payload we push;
  - **the bootstrap is not a shell-injection surface** — every interpolated
    value is quoted, the payload is integrity-checked before a file is written,
    and a pre-authorisation document is validated before it can grant anything.

No test here opens a network connection or spawns ``ssh``: the scan is driven
against closed local ports, and the bootstrap is inspected as text.
"""
import asyncio
import base64
import io
import json
import os
import tarfile

import pytest

from src.apps import fleet_provision, fleet_ssh
from src.apps.fleet_ssh import SshCredentials, SshError

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# ---------------------------------------------------------------------------
# Credentials
# ---------------------------------------------------------------------------

class TestCredentials:
    def test_secret_never_appears_in_a_repr(self):
        """An accidental print or a traceback rendering locals must not spill."""
        creds = SshCredentials("root", password="hunter2",
                               key_passphrase="opensesame")
        for text in (repr(creds), str(creds), f"{creds}"):
            assert "hunter2" not in text
            assert "opensesame" not in text
            assert "root" in text          # the username is not the secret

    def test_wipe_drops_the_secret(self):
        creds = SshCredentials("root", password="hunter2")
        assert creds.has_password is True
        creds.wipe()
        assert creds.has_password is False
        assert creds._password is None

    def test_username_is_validated(self):
        for bad in ("", "a b", "x" * 65, "with\ttab", "line\nbreak"):
            with pytest.raises(SshError):
                SshCredentials(bad, password="p")

    def test_no_slots_leak(self):
        """__slots__ means no __dict__ to accidentally serialise."""
        creds = SshCredentials("root", password="p")
        assert not hasattr(creds, "__dict__")


class TestSshOptions:
    def _options(self, creds, known=None):
        return fleet_ssh._base_options(known, creds, 22)

    def test_password_never_reaches_argv(self):
        creds = SshCredentials("root", password="hunter2")
        assert "hunter2" not in " ".join(self._options(creds))

    def test_passphrase_never_reaches_argv(self):
        creds = SshCredentials("root", key_path="/k", key_passphrase="secret")
        assert "secret" not in " ".join(self._options(creds))

    def test_pinned_host_keys_are_strict(self):
        creds = SshCredentials("root", password="p")
        joined = " ".join(self._options(creds, "/tmp/kh"))
        assert "StrictHostKeyChecking=yes" in joined
        assert "UserKnownHostsFile=/tmp/kh" in joined
        assert "accept-new" not in joined

    def test_agent_and_default_identities_are_off(self):
        """What authenticates must be what the operator chose, not whatever the
        agent happens to hold."""
        joined = " ".join(self._options(SshCredentials("root", key_path="/k")))
        assert "IdentityAgent=none" in joined
        assert "IdentitiesOnly=yes" in joined

    def test_key_only_run_is_batch_mode(self):
        """With no password to type, a prompt we cannot answer must not hang."""
        joined = " ".join(self._options(SshCredentials("root", key_path="/k")))
        assert "BatchMode=yes" in joined

    def test_password_run_is_not_batch_mode(self):
        joined = " ".join(self._options(SshCredentials("root", password="p")))
        assert "BatchMode=yes" not in joined


class TestPromptAnswering:
    def _answer(self, tail, creds, answered=None):
        return fleet_ssh._prompt_answer(tail, creds,
                                        answered or {"password": 0, "passphrase": 0})

    def test_password_prompt_is_answered_once(self):
        creds = SshCredentials("root", password="pw")
        answered = {"password": 0, "passphrase": 0}
        assert self._answer(b"root@host's password:", creds, answered) == b"pw\n"
        # A re-prompt means the secret was wrong; replaying it just burns
        # attempts against a lockout.
        assert self._answer(b"root@host's password:", creds, answered) is None

    def test_passphrase_prompt_is_answered_once(self):
        creds = SshCredentials("root", key_path="/k", key_passphrase="pp")
        answered = {"password": 0, "passphrase": 0}
        assert self._answer(b"enter passphrase for key '/k':", creds,
                            answered) == b"pp\n"
        assert self._answer(b"enter passphrase for key '/k':", creds,
                            answered) is None

    def test_nothing_typed_without_a_secret(self):
        creds = SshCredentials("root", key_path="/k")
        assert self._answer(b"root@host's password:", creds) is None

    def test_ordinary_output_answers_nothing(self):
        creds = SshCredentials("root", password="pw")
        for line in (b"welcome to the machine", b"last login: today",
                     b"", b"\x00\xff garbage"):
            assert self._answer(line, creds) is None


class TestKnownHosts:
    def test_file_is_private_and_removed(self):
        lines = ["10.0.0.1 ssh-ed25519 AAAAC3Nz"]
        with fleet_ssh.KnownHosts(lines) as known:
            assert known.path is not None
            assert oct(os.stat(known.path).st_mode)[-3:] == "600"
            assert "ssh-ed25519" in open(known.path).read()
            path = known.path
        assert not os.path.exists(path)

    def test_no_lines_means_no_file(self):
        with fleet_ssh.KnownHosts([]) as known:
            assert known.path is None

    def test_non_strings_are_dropped(self):
        with fleet_ssh.KnownHosts([None, 5, "10.0.0.1 ssh-rsa AAA"]) as known:
            assert open(known.path).read().strip() == "10.0.0.1 ssh-rsa AAA"


# ---------------------------------------------------------------------------
# LAN discovery
# ---------------------------------------------------------------------------

class TestScan:
    def test_subnets_are_private_only(self):
        for net in fleet_ssh.local_subnets():
            import ipaddress
            assert ipaddress.ip_network(net).is_private

    def test_oversized_subnet_is_refused(self):
        """A /8 sweep is not a LAN discovery, it is a flood."""
        assert fleet_ssh.subnet_hosts(["10.0.0.0/8"]) == []

    def test_hosts_are_bounded(self):
        hosts = fleet_ssh.subnet_hosts(["192.168.0.0/22"], limit=50)
        assert len(hosts) == 50

    def test_bad_subnets_are_skipped(self):
        assert fleet_ssh.subnet_hosts(["nonsense", "", "999.1.1.1/24"]) == []

    async def test_probe_of_a_closed_port_is_none(self):
        # Port 1 on loopback: nothing listens, and nothing raises.
        assert await fleet_ssh.probe_host("127.0.0.1", 1, timeout=0.5) is None

    async def test_probe_of_a_non_ssh_service_is_none(self):
        """A listener that is not SSH must not be reported as one."""
        async def handle(reader, writer):
            writer.write(b"HTTP/1.1 400 Bad Request\r\n")
            await writer.drain()
            writer.close()

        server = await asyncio.start_server(handle, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        try:
            assert await fleet_ssh.probe_host("127.0.0.1", port,
                                              timeout=2.0) is None
        finally:
            server.close()

    async def test_probe_reads_an_ssh_banner(self):
        async def handle(reader, writer):
            writer.write(b"SSH-2.0-OpenSSH_9.6\r\n")
            await writer.drain()
            writer.close()

        server = await asyncio.start_server(handle, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        try:
            found = await fleet_ssh.probe_host("127.0.0.1", port, timeout=2.0)
        finally:
            server.close()
        assert found["banner"] == "SSH-2.0-OpenSSH_9.6"
        assert found["port"] == port

    async def test_banner_is_capped(self):
        async def handle(reader, writer):
            writer.write(b"SSH-2.0-" + b"A" * 100_000)
            await writer.drain()
            writer.close()

        server = await asyncio.start_server(handle, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        try:
            found = await fleet_ssh.probe_host("127.0.0.1", port, timeout=2.0)
        finally:
            server.close()
        assert len(found["banner"]) <= fleet_ssh.MAX_BANNER


class TestKeyDiscovery:
    def test_only_private_keys_are_listed(self, tmp_path):
        (tmp_path / "id_ed25519").write_text(
            "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n")
        (tmp_path / "id_ed25519.pub").write_text("ssh-ed25519 AAAA me@host\n")
        (tmp_path / "known_hosts").write_text("10.0.0.1 ssh-rsa AAA\n")
        (tmp_path / "config").write_text("Host *\n")
        found = fleet_ssh.discover_private_keys(str(tmp_path))
        assert [k["name"] for k in found] == ["id_ed25519"]
        assert found[0]["comment"] == "me@host"

    def test_key_material_is_not_returned(self, tmp_path):
        secret = "-----BEGIN OPENSSH PRIVATE KEY-----\nSUPERSECRETMATERIAL\n"
        (tmp_path / "id_rsa").write_text(secret)
        found = fleet_ssh.discover_private_keys(str(tmp_path))
        assert "SUPERSECRETMATERIAL" not in json.dumps(found)

    def test_encrypted_key_is_flagged(self, tmp_path):
        (tmp_path / "id_rsa").write_text(
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "Proc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00\n\nabc\n")
        assert fleet_ssh.discover_private_keys(str(tmp_path))[0]["encrypted"]

    def test_missing_directory_is_empty(self):
        assert fleet_ssh.discover_private_keys("/nonexistent/.ssh") == []

    def test_oversized_file_is_skipped(self, tmp_path):
        (tmp_path / "id_big").write_text("PRIVATE KEY" + "x" * 200_000)
        assert fleet_ssh.discover_private_keys(str(tmp_path)) == []


# ---------------------------------------------------------------------------
# Payload & pre-authorisation
# ---------------------------------------------------------------------------

class TestPayload:
    def test_payload_carries_the_tree(self):
        payload = fleet_provision.build_payload(ROOT)
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as archive:
            names = archive.getnames()
        assert "start.sh" in names
        assert any(n.startswith("src/") for n in names)
        assert any(n.endswith("scripts/nmesh_node.py") for n in names)

    def test_payload_excludes_state_and_tests(self):
        payload = fleet_provision.build_payload(ROOT)
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as archive:
            names = archive.getnames()
        for name in names:
            parts = set(name.split("/"))
            assert not (parts & fleet_provision.PAYLOAD_EXCLUDE_DIRS)
            assert not name.endswith(".pyc")

    def test_payload_is_reproducible(self):
        """Same tree, same bytes: the operator can state what they deployed."""
        assert (fleet_provision.build_payload(ROOT)
                == fleet_provision.build_payload(ROOT))

    def test_empty_tree_is_refused(self, tmp_path):
        with pytest.raises(fleet_provision.ProvisionError):
            fleet_provision.build_payload(str(tmp_path))


class TestPreauth:
    def _document(self, **kwargs):
        pub = os.urandom(64)
        import hashlib
        node_id = hashlib.sha256(pub).digest()[:20]
        defaults = dict(capabilities=["status"], join_uris=[], join_code="c")
        defaults.update(kwargs)
        return fleet_provision.make_preauth(node_id, pub, **defaults)

    def test_roundtrip(self):
        document, token = self._document(capabilities=["status", "update"])
        parsed = fleet_provision.parse_preauth(document)
        assert parsed["token"] == token
        assert parsed["capabilities"] == ["status", "update"]

    def test_token_digest_is_domain_separated(self):
        token = os.urandom(32)
        import hashlib
        assert (fleet_provision.token_digest(token)
                != hashlib.sha256(token).hexdigest())

    def test_operator_id_must_derive_from_the_key(self):
        """A tampered file that swaps in another key is rejected outright."""
        document, _token = self._document()
        document["operator_pub"] = os.urandom(64).hex()
        assert fleet_provision.parse_preauth(document) is None

    def test_junk_is_rejected(self):
        for junk in (None, [], "text", 42, {}, {"v": 2}, {"v": 1},
                     {"v": 1, "operator_id": "zz"}):
            assert fleet_provision.parse_preauth(junk) is None

    def test_short_token_is_rejected(self):
        document, _token = self._document()
        document["token"] = "aa" * 4
        assert fleet_provision.parse_preauth(document) is None

    def test_unknown_fields_are_bounded(self):
        document, _token = self._document()
        document["label"] = "x" * 10_000
        document["join_uris"] = ["u" * 1000] * 100
        parsed = fleet_provision.parse_preauth(document)
        assert len(parsed["label"]) <= 128
        assert len(parsed["join_uris"]) <= 8

    def test_read_from_file(self, tmp_path):
        document, token = self._document()
        path = tmp_path / "preauth.json"
        path.write_text(json.dumps(document))
        assert fleet_provision.read_preauth(str(path))["token"] == token

    def test_read_missing_file(self):
        assert fleet_provision.read_preauth("/nonexistent/preauth.json") is None

    def test_read_oversized_file(self, tmp_path):
        path = tmp_path / "preauth.json"
        path.write_text("x" * 200_000)
        assert fleet_provision.read_preauth(str(path)) is None


class TestBootstrap:
    def _script(self, **kwargs):
        document, _token = fleet_provision.make_preauth(
            b"\x01" * 20, b"\x02" * 32, capabilities=["status"],
            join_uris=[], join_code=None)
        return fleet_provision.build_bootstrap(b"payload-bytes", document,
                                               **kwargs)

    def test_script_verifies_before_writing(self):
        script = self._script()
        assert "sha256" in script.lower()
        assert "payload integrity check failed" in script
        # The check must come before the unpack, not after.
        assert script.index("integrity check failed") < script.index("tar -xzf")

    def test_script_fails_fast(self):
        assert self._script().startswith("#!/bin/sh\nset -eu")

    def test_preauth_is_written_private(self):
        script = self._script()
        assert "umask 077" in script
        assert "chmod 600" in script

    def test_interpolated_values_are_quoted(self):
        """A directory name with a quote in it must not end the string."""
        script = self._script(install_dir="/opt/nm'esh", service_name="a'b")
        assert "'/opt/nm'\\''esh'" in script
        assert "'a'\\''b'" in script

    def test_no_secret_in_the_script(self):
        """The bootstrap carries a pre-authorisation, never a login."""
        assert "hunter2" not in self._script()

    def test_payload_is_embedded_and_recoverable(self):
        script = fleet_provision.build_bootstrap(
            b"the-real-payload",
            fleet_provision.make_preauth(b"\x01" * 20, b"\x02" * 32,
                                         capabilities=["status"], join_uris=[],
                                         join_code=None)[0])
        body = script.split("<<'NMESH_PAYLOAD_EOF'\n", 1)[1]
        body = body.split("\nNMESH_PAYLOAD_EOF", 1)[0]
        assert base64.b64decode(body.replace("\n", "")) == b"the-real-payload"

    def test_setup_only_installs_no_service(self):
        script = self._script(setup_only=True)
        assert "SETUP_ONLY=1" in script


class TestProvisionRun:
    async def test_a_failing_host_is_a_result_not_an_exception(self, monkeypatch):
        """One unreachable machine must not abort a batch."""
        async def boom(*args, **kwargs):
            raise SshError("authentication failed")

        monkeypatch.setattr(fleet_ssh, "run", boom)
        document, _token = fleet_provision.make_preauth(
            b"\x01" * 20, b"\x02" * 32, capabilities=["status"], join_uris=[],
            join_code=None)
        result = await fleet_provision.provision_host(
            "10.0.0.1", SshCredentials("root", password="p"),
            payload=b"x", preauth=document)
        assert result["ok"] is False
        assert result["error"] == "authentication failed"

    async def test_steps_are_reported(self, monkeypatch):
        async def fake_run(host, creds, command, **kwargs):
            on_output = kwargs.get("on_output")
            on_output("::step::unpacked\n::step::done\n")
            return 0, ""

        monkeypatch.setattr(fleet_ssh, "run", fake_run)
        document, _token = fleet_provision.make_preauth(
            b"\x01" * 20, b"\x02" * 32, capabilities=["status"], join_uris=[],
            join_code=None)
        seen = []
        result = await fleet_provision.provision_host(
            "10.0.0.1", SshCredentials("root", password="p"),
            payload=b"x", preauth=document,
            on_progress=lambda h, s: seen.append(s))
        assert result["ok"] is True
        assert seen == ["unpacked", "done"]

    async def test_missing_done_marker_is_a_failure(self, monkeypatch):
        """Exit status 0 without reaching the end is still not a success."""
        async def fake_run(host, creds, command, **kwargs):
            kwargs.get("on_output")("::step::unpacked\n")
            return 0, ""

        monkeypatch.setattr(fleet_ssh, "run", fake_run)
        document, _token = fleet_provision.make_preauth(
            b"\x01" * 20, b"\x02" * 32, capabilities=["status"], join_uris=[],
            join_code=None)
        result = await fleet_provision.provision_host(
            "10.0.0.1", SshCredentials("root", password="p"),
            payload=b"x", preauth=document)
        assert result["ok"] is False
