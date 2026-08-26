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
import ipaddress
import json
import time
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
        return fleet_ssh._prompt_answer(
            tail, creds,
            answered or {"password": 0, "passphrase": 0, "elevate": 0,
                         "may_elevate": 0})

    def test_password_prompt_is_answered_once(self):
        creds = SshCredentials("root", password="pw")
        answered = {"password": 0, "passphrase": 0, "elevate": 0,
                    "may_elevate": 0}
        assert self._answer(b"root@host's password:", creds, answered) == b"pw\n"
        # A re-prompt means the secret was wrong; replaying it just burns
        # attempts against a lockout.
        assert self._answer(b"root@host's password:", creds, answered) is None

    def test_passphrase_prompt_is_answered_once(self):
        creds = SshCredentials("root", key_path="/k", key_passphrase="pp")
        answered = {"password": 0, "passphrase": 0, "elevate": 0,
                    "may_elevate": 0}
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

class TestNetworkDetection:
    """The sweep covers every network the node is attached to, at the prefix
    actually in use — not a /24 guessed around one address."""

    def _detect(self, monkeypatch, networks):
        monkeypatch.setattr(fleet_ssh, "local_networks", lambda: networks)
        return fleet_ssh.detected_networks()

    def test_every_attached_network_is_reported(self, monkeypatch):
        found = self._detect(monkeypatch, [
            {"cidr": "192.168.1.0/24", "ip": "192.168.1.10", "interface": "eth0"},
            {"cidr": "10.42.0.0/22", "ip": "10.42.1.5", "interface": "wlan0"},
            {"cidr": "172.20.0.0/24", "ip": "172.20.0.1", "interface": "docker0"},
        ])
        assert [e["scan"] for e in found] == ["192.168.1.0/24", "10.42.0.0/22",
                                              "172.20.0.0/24"]
        assert [e["interface"] for e in found] == ["eth0", "wlan0", "docker0"]
        assert all(e["narrowed"] is False for e in found)

    def test_real_prefix_is_honoured_not_assumed(self, monkeypatch):
        """A /22 must be swept as a /22 — the whole point of the change."""
        found = self._detect(monkeypatch, [
            {"cidr": "10.42.0.0/22", "ip": "10.42.1.5", "interface": "wlan0"}])
        assert found[0]["scan"] == "10.42.0.0/22"
        assert found[0]["hosts"] == 1022

    def test_oversized_network_is_narrowed_around_our_address(self, monkeypatch):
        found = self._detect(monkeypatch, [
            {"cidr": "10.0.0.0/16", "ip": "10.0.37.9", "interface": "eth0"}])
        assert found[0]["narrowed"] is True
        assert found[0]["cidr"] == "10.0.0.0/16"          # what was detected
        scan = ipaddress.ip_network(found[0]["scan"])     # what is swept
        assert scan.num_addresses <= fleet_ssh.MAX_NET_ADDRESSES
        assert ipaddress.ip_address("10.0.37.9") in scan  # centred on us

    def test_oversized_network_without_our_address_is_skipped(self, monkeypatch):
        """Nothing to centre the slice on: skip openly rather than sweep an
        arbitrary corner of someone's /8."""
        assert self._detect(monkeypatch, [
            {"cidr": "10.0.0.0/8", "ip": None, "interface": "eth0"}]) == []

    def test_detection_is_bounded(self, monkeypatch):
        found = self._detect(monkeypatch, [
            {"cidr": f"10.{i}.0.0/24", "ip": f"10.{i}.0.2", "interface": "e"}
            for i in range(100)])
        assert len(found) <= fleet_ssh.MAX_SUBNETS

    def test_local_subnets_are_what_gets_swept(self, monkeypatch):
        monkeypatch.setattr(fleet_ssh, "local_networks", lambda: [
            {"cidr": "10.0.0.0/16", "ip": "10.0.37.9", "interface": "eth0"},
            {"cidr": "192.168.5.0/24", "ip": "192.168.5.2", "interface": "eth1"}])
        subnets = fleet_ssh.local_subnets()
        assert "192.168.5.0/24" in subnets
        assert "10.0.0.0/16" not in subnets     # narrowed, not swept whole
        hosts = fleet_ssh.subnet_hosts(subnets, limit=fleet_ssh.MAX_HOSTS)
        assert len(hosts) <= fleet_ssh.MAX_HOSTS

    def test_narrow_picks_the_largest_scannable_slice(self):
        net = ipaddress.ip_network("10.0.0.0/8")
        slice_ = fleet_ssh._narrow(net, "10.1.2.3")
        assert slice_.num_addresses <= fleet_ssh.MAX_NET_ADDRESSES
        assert slice_.num_addresses * 2 > fleet_ssh.MAX_NET_ADDRESSES
        assert ipaddress.ip_address("10.1.2.3") in slice_


class TestPreciseTargets:
    """"Scan my LAN" and "look at exactly this machine" go through the same
    field. What is not understood comes back named, never silently dropped."""

    async def test_single_ip(self):
        targets, rejected = await fleet_ssh.parse_targets(["10.0.0.5"])
        assert targets == [("10.0.0.5", 22)]
        assert rejected == []

    async def test_single_ip_with_port(self):
        targets, _ = await fleet_ssh.parse_targets(["10.0.0.5:2222"])
        assert targets == [("10.0.0.5", 2222)]

    async def test_hostname_is_resolved_here(self):
        """Resolved up front, not left to open_connection: that one would
        resolve on the default executor, joined at shutdown (gotchas §2)."""
        targets, rejected = await fleet_ssh.parse_targets(["localhost"])
        assert rejected == []
        assert targets and targets[0][1] == 22
        assert targets[0][0] in ("127.0.0.1", "::1")

    async def test_hostname_with_port(self):
        targets, _ = await fleet_ssh.parse_targets(["localhost:2022"])
        assert targets and targets[0][1] == 2022

    async def test_unresolvable_name_is_reported_not_dropped(self):
        targets, rejected = await fleet_ssh.parse_targets(
            ["nx-" + "z" * 20 + ".invalid"])
        assert targets == []
        assert len(rejected) == 1

    async def test_subnet_and_machine_mix(self):
        targets, rejected = await fleet_ssh.parse_targets(
            ["192.168.9.0/30", "10.1.2.3:22"])
        assert ("10.1.2.3", 22) in targets
        assert ("192.168.9.1", 22) in targets
        assert rejected == []

    async def test_explicit_public_host_is_allowed(self):
        """Naming a machine is not scanning: a precise host typed by hand is
        allowed wherever it is."""
        targets, rejected = await fleet_ssh.parse_targets(["93.184.216.34"])
        assert targets == [("93.184.216.34", 22)]
        assert rejected == []

    async def test_public_subnet_is_still_refused(self):
        """A public prefix is still a sweep of strangers."""
        targets, rejected = await fleet_ssh.parse_targets(["93.184.216.0/24"])
        assert targets == []
        assert rejected == ["93.184.216.0/24"]

    async def test_bad_ports_are_rejected(self):
        for bad in ("10.0.0.5:0", "10.0.0.5:70000", "10.0.0.5:ssh",
                    "10.0.0.5:-1"):
            targets, rejected = await fleet_ssh.parse_targets([bad])
            assert targets == [] and rejected == [bad]

    async def test_ipv6_literal_target(self):
        """A /64 is not scannable, but naming a machine over v6 is legitimate."""
        targets, rejected = await fleet_ssh.parse_targets(["[::1]:2222"])
        assert targets == [("::1", 2222)]
        assert rejected == []

    async def test_duplicates_collapse(self):
        targets, _ = await fleet_ssh.parse_targets(
            ["10.0.0.5", "10.0.0.5:22", "10.0.0.5"])
        assert targets == [("10.0.0.5", 22)]

    async def test_junk_never_raises(self):
        entries = ["", "   ", "///", ":::", "..", "10.0.0.999", None, 5,
                   "a" * 300, "1.2.3.4:", ":22"]
        targets, rejected = await fleet_ssh.parse_targets(entries)
        assert isinstance(targets, list) and isinstance(rejected, list)

    async def test_total_is_bounded(self):
        targets, _ = await fleet_ssh.parse_targets(
            ["10.0.0.0/24", "10.0.1.0/24"], limit=40)
        assert len(targets) <= 40

    async def test_scan_reaches_a_named_machine(self):
        """End to end: a precise target really reaches a real listener."""
        async def handle(reader, writer):
            writer.write(b"SSH-2.0-OpenSSH_9.6\r\n")
            await writer.drain()
            writer.close()

        server = await asyncio.start_server(handle, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        try:
            found, rejected = await fleet_ssh.scan([f"127.0.0.1:{port}"],
                                                   timeout=2.0)
        finally:
            server.close()
        assert rejected == []
        assert [(h["ip"], h["port"]) for h in found] == [("127.0.0.1", port)]

    async def test_scan_reports_what_it_could_not_parse(self):
        found, rejected = await fleet_ssh.scan(["10.0.0.5:notaport"],
                                                timeout=0.2)
        assert found == []
        assert rejected == ["10.0.0.5:notaport"]


class TestScan:
    def test_subnets_are_private_only(self):
        for net in fleet_ssh.local_subnets():
            assert ipaddress.ip_network(net).is_private

    def test_oversized_subnet_is_refused(self):
        """A /8 handed in explicitly is not a LAN discovery, it is a flood."""
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
        """Same tree, same bytes: the operator can state what they deployed.

        gzip stamps the current time into its header, so this used to hold only
        when both builds landed in the same second — and the bootstrap embeds
        the payload's hash."""
        first = fleet_provision.build_payload(ROOT)
        time.sleep(1.1)
        assert fleet_provision.build_payload(ROOT) == first

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
        stage = kwargs.pop("stage", "stagedir")
        if kwargs:
            # Phase two carries the installation options; phase one only ever
            # delivers. Return them joined so a test can assert about either.
            return (fleet_provision.build_bootstrap(b"payload-bytes", document,
                                                    stage=stage)
                    + fleet_provision.build_install_phase(stage=stage, **kwargs))
        return fleet_provision.build_bootstrap(b"payload-bytes", document,
                                               stage=stage)

    def test_script_verifies_before_writing(self):
        script = self._script()
        assert "sha256" in script.lower()
        assert "payload integrity check failed" in script
        # The check must come before the unpack, not after.
        assert script.index("integrity check failed") < script.index("tar -xzf")

    def test_script_fails_fast(self):
        """Both phases stop at the first error rather than leave a node half
        installed."""
        assert self._script().startswith("#!/bin/sh")
        assert "\nset -eu\n" in self._script()
        assert fleet_provision.build_install_phase(
            stage="stagedir").startswith("set -eu")

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
                                         join_code=None)[0],
            stage="stagedir")
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
        # Deux invocations : la livraison, puis l'installation sous terminal.
        async def fake_run(host, creds, command, **kwargs):
            on_output = kwargs.get("on_output")
            if kwargs.get("request_tty"):
                on_output("::step::done\n")
            else:
                on_output("::step::unpacked\n::step::staged\n")
            return 0, ""

        monkeypatch.setattr(fleet_ssh, "run", fake_run)
        document, _token = fleet_provision.make_preauth(
            b"\x01" * 20, b"\x02" * 32, capabilities=["status"], join_uris=[],
            join_code=None)
        seen = []
        result = await fleet_provision.provision_host(
            "10.0.0.1", SshCredentials("root", password="p"),
            payload=b"x", preauth=document,
            known_hosts_lines=["10.0.0.1 ssh-ed25519 AAAA"],
            on_progress=lambda h, s: seen.append(s))
        assert result["ok"] is True
        assert seen == ["unpacked", "staged", "done"]

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


class TestHostKeyPinning:
    """Pinning is the difference between informed trust-on-first-use and a
    shrug. When there is nothing to pin, that has to be visible."""

    async def test_unpinned_run_announces_itself(self, monkeypatch):
        async def fake_run(host, creds, command, **kwargs):
            kwargs.get("on_output")("::step::done\n")
            return 0, ""

        monkeypatch.setattr(fleet_ssh, "run", fake_run)
        document, _token = fleet_provision.make_preauth(
            b"\x01" * 20, b"\x02" * 32, capabilities=["status"], join_uris=[],
            join_code=None)
        result = await fleet_provision.provision_host(
            "10.0.0.1", SshCredentials("root", password="p"),
            payload=b"x", preauth=document, known_hosts_lines=[])
        assert result["pinned"] is False
        assert any("no host key to pin" in step for step in result["steps"])

    async def test_pinned_run_says_nothing_extra(self, monkeypatch):
        async def fake_run(host, creds, command, **kwargs):
            kwargs.get("on_output")("::step::done\n")
            return 0, ""

        monkeypatch.setattr(fleet_ssh, "run", fake_run)
        document, _token = fleet_provision.make_preauth(
            b"\x01" * 20, b"\x02" * 32, capabilities=["status"], join_uris=[],
            join_code=None)
        result = await fleet_provision.provision_host(
            "10.0.0.1", SshCredentials("root", password="p"),
            payload=b"x", preauth=document,
            known_hosts_lines=["10.0.0.1 ssh-ed25519 AAAA"])
        assert result["pinned"] is True
        assert not any("no host key" in step for step in result["steps"])


class TestMaterialisedKey:
    """`ssh -i` wants a path, so an imported key has to touch a filesystem. The
    window is *one command*: a 0700 directory, a 0600 file, deleted on the way
    out."""

    KEY = "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----"

    def test_material_becomes_a_private_file(self):
        creds = SshCredentials("root", key_data=self.KEY)
        with fleet_ssh.MaterialisedKey(creds) as key:
            assert key.path is not None
            assert oct(os.stat(key.path).st_mode)[-3:] == "600"
            assert oct(os.stat(os.path.dirname(key.path)).st_mode)[-3:] == "700"
            content = open(key.path).read()
            path = key.path
        assert content.startswith("-----BEGIN OPENSSH PRIVATE KEY-----")
        assert content.endswith("\n")      # OpenSSH refuses a key without one
        assert not os.path.exists(path)    # gone with the command

    def test_a_key_with_a_path_is_passed_through(self):
        creds = SshCredentials("root", key_path="/home/me/.ssh/id")
        with fleet_ssh.MaterialisedKey(creds) as key:
            assert key.path == "/home/me/.ssh/id"

    def test_no_key_writes_nothing(self):
        creds = SshCredentials("root", password="p")
        with fleet_ssh.MaterialisedKey(creds) as key:
            assert key.path is None

    def test_material_reaches_the_ssh_command_line_as_a_path(self):
        creds = SshCredentials("root", key_data=self.KEY)
        with fleet_ssh.MaterialisedKey(creds) as key:
            options = fleet_ssh._base_options(None, creds, 22, key.path)
            assert "-i" in options
            assert options[options.index("-i") + 1] == key.path
            assert "IdentitiesOnly=yes" in options
        # …and never the material itself.
        assert self.KEY not in " ".join(options)

    def test_wipe_drops_the_material(self):
        creds = SshCredentials("root", key_data=self.KEY)
        assert creds.has_key is True
        creds.wipe()
        assert creds.has_key is False

    def test_repr_hides_the_material(self):
        creds = SshCredentials("root", key_data=self.KEY)
        assert "PRIVATE KEY" not in repr(creds)
        assert "<set>" in repr(creds)
