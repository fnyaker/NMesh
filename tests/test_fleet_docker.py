"""
Docker's Engine API and Portainer's: the validation in front of them, and the
wire under them. What is built on them — stacks, updates — is
`test_fleet_stacks.py`'s.

Two things are worth proving here and they are not the same thing.

**What reaches a socket or an argv.** Everything an operator sends is hostile
input, and the answer to a name that is not a name is to refuse it, not to
escape it — so these tests check the refusals, and check that a container is
*built* from a validated shape rather than forwarded (a dictionary passed
through would carry every field the daemon knows about and this module does
not, `Privileged` among them).

**That the client actually speaks HTTP.** The Engine API frames its answers
two different ways and Docker's own errors arrive inside a 200 for at least one
route. A real daemon is not available in a test, so these drive the client
against a socket that answers like one.
"""
import asyncio
import json
import os
import socket
import tempfile

import pytest

from src.apps import fleet_docker as docker
from src.apps import fleet_portainer as portainer


# ---------------------------------------------------------------------------
# What may reach a socket
# ---------------------------------------------------------------------------

class TestNamesAndBounds:
    def test_a_name_that_is_not_a_name_is_refused(self):
        for bad in ("", "../etc", "a b", "-leading", "x" * 200, None, 7,
                    "semi;colon", "back\\slash", "new\nline"):
            assert docker.clean_id(bad) == ""
        for good in ("nginx", "my-stack_1", "a.b", "0" * 64):
            assert docker.clean_id(good) == good

    def test_an_image_reference_keeps_its_punctuation_and_nothing_else(self):
        assert docker.clean_image("ghcr.io/owner/img:1.2") == "ghcr.io/owner/img:1.2"
        assert docker.clean_image("img@sha256:" + "a" * 64).startswith("img@")
        for bad in ("img; rm -rf /", "img$(id)", "-img", "img|tee", "", "x" * 300):
            assert docker.clean_image(bad) == ""

    def test_a_compose_file_is_bounded_and_never_binary(self):
        assert docker.clean_compose("services: {}") == "services: {}"
        assert docker.clean_compose("x" * (docker.MAX_COMPOSE + 1)) == ""
        assert docker.clean_compose("a\0b") == ""
        assert docker.clean_compose("   ") == ""

    def test_a_container_is_built_not_forwarded(self):
        """The daemon takes a hundred fields. A body passed through would be
        every one of them, chosen by whoever sent it."""
        body = docker.container_spec({
            "image": "nginx:alpine", "name": "web",
            "Privileged": True, "HostConfig": {"Privileged": True},
            "ports": [{"host": 8080, "container": 80}],
            "env": {"TZ": "Europe/Paris"},
        })
        assert "Privileged" not in body
        assert "Privileged" not in body["HostConfig"]
        assert body["Image"] == "nginx:alpine"
        assert body["Env"] == ["TZ=Europe/Paris"]
        assert body["ExposedPorts"] == {"80/tcp": {}}
        assert body["HostConfig"]["PortBindings"]["80/tcp"] == [{"HostPort": "8080"}]

    def test_a_bind_mount_is_two_absolute_paths_or_a_volume_name(self):
        body = docker.container_spec({"image": "img", "volumes": [
            {"host": "/srv/data", "container": "/data"},
            {"host": "/srv/ro", "container": "/ro", "ro": True},
            {"host": "named-volume", "container": "/vol"},
            {"host": "/a:/b", "container": "/c"},          # a colon would re-split
            {"host": "relative", "container": "/d"},        # a volume name, as docker reads it
            {"host": "/e", "container": "no-slash"},
            {"host": "/f", "container": "/g:/h"},           # a colon on the far side too
        ]})
        assert body["HostConfig"]["Binds"] == [
            "/srv/data:/data", "/srv/ro:/ro:ro", "named-volume:/vol", "relative:/d"]

    def test_an_unusable_restart_policy_falls_back_rather_than_travelling(self):
        body = docker.container_spec({"image": "img", "restart": "; reboot"})
        assert body["HostConfig"]["RestartPolicy"] == {"Name": "unless-stopped"}

    def test_a_command_is_split_never_handed_to_a_shell(self):
        body = docker.container_spec({"image": "img", "command": "sleep 30"})
        assert body["Cmd"] == ["sleep", "30"]
        with pytest.raises(docker.DockerError):
            docker.container_spec({"image": "img", "command": 'a "unbalanced'})

    def test_an_image_is_required(self):
        with pytest.raises(docker.DockerError):
            docker.container_spec({"name": "web"})
        with pytest.raises(docker.DockerError):
            docker.container_spec("not a container")

    def test_environment_names_are_names(self):
        body = docker.container_spec({"image": "img", "env": {
            "GOOD": "1", "bad name": "2", "WITH\nNEWLINE": "3",
            "INJECT": "a\nSECOND=b",
        }})
        assert body["Env"] == ["GOOD=1"]


class TestLogStream:
    def test_the_multiplexed_header_is_taken_off_rather_than_printed(self):
        """A container with no tty has its output framed: eight bytes per frame,
        and printing them raw puts control bytes on somebody's screen."""
        frame = lambda stream, text: (bytes([stream, 0, 0, 0])
                                      + len(text).to_bytes(4, "big") + text)
        raw = frame(1, b"out\n") + frame(2, b"err\n")
        assert docker.demultiplex(raw) == "out\nerr\n"

    def test_an_unframed_stream_is_read_as_text(self):
        assert docker.demultiplex(b"plain output\n") == "plain output\n"
        assert docker.demultiplex(b"") == ""


# ---------------------------------------------------------------------------
# The wire
# ---------------------------------------------------------------------------

class _Daemon:
    """A socket that answers like a docker daemon, and only like one."""

    def __init__(self, answers):
        self.answers = list(answers)
        self.requests = []
        self.server = None
        self.path = None

    async def start(self):
        directory = tempfile.mkdtemp()
        self.path = os.path.join(directory, "docker.sock")
        self.server = await asyncio.start_unix_server(self._serve, self.path)
        os.environ["DOCKER_HOST"] = "unix://" + self.path
        return self.path

    async def stop(self):
        os.environ.pop("DOCKER_HOST", None)
        self.server.close()
        await self.server.wait_closed()

    async def _serve(self, reader, writer):
        line = await reader.readline()
        headers = {}
        while True:
            header = await reader.readline()
            if header in (b"\r\n", b"\n", b""):
                break
            name, _, value = header.decode().partition(":")
            headers[name.strip().lower()] = value.strip()
        length = int(headers.get("content-length") or 0)
        body = await reader.readexactly(length) if length else b""
        self.requests.append((line.decode().strip(), body))
        writer.write(self.answers.pop(0) if self.answers else b"HTTP/1.1 500 x\r\n\r\n")
        await writer.drain()
        writer.close()


def _answer(payload: bytes, *, chunked=False, status=200):
    if chunked:
        body = b""
        for index in range(0, len(payload), 7):
            piece = payload[index:index + 7]
            body += b"%x\r\n" % len(piece) + piece + b"\r\n"
        body += b"0\r\n\r\n"
        head = (f"HTTP/1.1 {status} x\r\nTransfer-Encoding: chunked\r\n"
                "Content-Type: application/json\r\n\r\n").encode()
        return head + body
    head = (f"HTTP/1.1 {status} x\r\nContent-Length: {len(payload)}\r\n"
            "Content-Type: application/json\r\n\r\n").encode()
    return head + payload


class TestEngineClient:
    async def test_a_content_length_answer_is_read(self):
        daemon = _Daemon([_answer(b'{"Version":"25.0.1"}')])
        await daemon.start()
        try:
            assert await docker.call("GET", "/version") == {"Version": "25.0.1"}
            assert daemon.requests[0][0].startswith("GET /v")
        finally:
            await daemon.stop()

    async def test_a_chunked_answer_is_read(self):
        """Both framings, because the daemon uses both and a client that knows
        one reads half the API as an empty body."""
        daemon = _Daemon([_answer(b'[{"Id":"abc","Names":["/web"]}]', chunked=True)])
        await daemon.start()
        try:
            rows = await docker.containers(True)
            assert rows[0]["id"] == "abc" and rows[0]["name"] == "web"
        finally:
            await daemon.stop()

    async def test_the_daemons_own_message_is_what_the_operator_is_told(self):
        daemon = _Daemon([_answer(b'{"message":"No such container: nope"}', status=404)])
        await daemon.start()
        try:
            with pytest.raises(docker.DockerError) as failure:
                await docker.act("nope", "start")
            assert "No such container" in str(failure.value)
        finally:
            await daemon.stop()

    async def test_something_that_is_not_a_daemon_raises_nothing_else(self):
        daemon = _Daemon([b"this is not HTTP at all\r\n\r\n"])
        await daemon.start()
        try:
            with pytest.raises(docker.DockerError):
                await docker.call("GET", "/version")
        finally:
            await daemon.stop()

    async def test_a_missing_socket_is_a_dockererror_not_an_oserror(self):
        os.environ["DOCKER_HOST"] = "unix:///nonexistent/docker.sock"
        try:
            assert docker.available() is False
            with pytest.raises(docker.DockerError):
                await docker.call("GET", "/version")
        finally:
            os.environ.pop("DOCKER_HOST", None)

    async def test_an_action_that_is_not_one_never_reaches_the_socket(self):
        daemon = _Daemon([])
        await daemon.start()
        try:
            with pytest.raises(docker.DockerError):
                await docker.act("abc", "exec")
            assert daemon.requests == []
        finally:
            await daemon.stop()

    async def test_a_failed_pull_inside_a_200_is_still_a_failure(self):
        """Docker reports a pull it could not do inside the body of a 200. A
        client that reads only the status says "pulled" and nothing happened."""
        stream = (b'{"status":"Pulling"}\n'
                  b'{"error":"manifest unknown"}\n')
        daemon = _Daemon([_answer(stream)])
        await daemon.start()
        try:
            with pytest.raises(docker.DockerError) as failure:
                await docker.pull("ghcr.io/owner/img:nope")
            assert "manifest unknown" in str(failure.value)
        finally:
            await daemon.stop()

    async def test_an_oversized_answer_is_refused_rather_than_read(self):
        head = (b"HTTP/1.1 200 x\r\nContent-Length: "
                + str(docker.MAX_RESPONSE + 1).encode() + b"\r\n\r\n")
        daemon = _Daemon([head])
        await daemon.start()
        try:
            with pytest.raises(docker.DockerError):
                await docker.call("GET", "/version")
        finally:
            await daemon.stop()


# ---------------------------------------------------------------------------
# Portainer
# ---------------------------------------------------------------------------

class TestEngineClientBeyondTheBasics:
    async def test_an_engine_that_dropped_our_version_is_asked_again_in_its_own(self):
        """An engine raises its minimum API version over the years. Asking
        `/version` before every call would cost a round trip each time for an
        answer that changes once in a machine's life; the refusal names it."""
        refusal = json.dumps({"message": "client version 1.41 is too old. "
                              "Minimum supported API version is 1.44, please "
                              "upgrade your client to a newer version"}).encode()
        daemon = _Daemon([_answer(refusal, status=400), _answer(b'{"Version":"30.0"}'),
                          _answer(b'{"Version":"30.0"}')])
        await daemon.start()
        saved = dict(docker._api)
        try:
            assert (await docker.call("GET", "/version"))["Version"] == "30.0"
            await docker.call("GET", "/version")
            assert [line.split()[1] for line, _ in daemon.requests] == [
                "/v1.41/version", "/v1.44/version", "/v1.44/version"]
        finally:
            docker._api.update(saved)
            await daemon.stop()

    async def test_a_400_that_is_not_about_the_version_is_not_retried(self):
        daemon = _Daemon([_answer(b'{"message":"bad parameter"}', status=400)])
        await daemon.start()
        try:
            with pytest.raises(docker.DockerError) as failure:
                await docker.call("GET", "/version")
            assert "bad parameter" in str(failure.value)
            assert len(daemon.requests) == 1
        finally:
            await daemon.stop()

    def test_a_reference_splits_where_docker_splits_it(self):
        """A registry's port is a colon too: `127.0.0.1:5000/app` has no tag."""
        assert docker.split_reference("127.0.0.1:5000/app") == ("127.0.0.1:5000/app", "", "")
        assert docker.split_reference("127.0.0.1:5000/app:2") == ("127.0.0.1:5000/app", "2", "")
        assert docker.split_reference("nginx") == ("nginx", "", "")
        assert docker.split_reference("img:1@sha256:ab") == ("img", "1", "sha256:ab")
        assert docker.registry_of("nginx") == "docker.io"
        assert docker.registry_of("owner/app") == "docker.io"
        assert docker.registry_of("ghcr.io/owner/app") == "ghcr.io"
        assert docker.registry_of("localhost/app") == "localhost"

    async def test_a_pull_by_digest_asks_for_the_digest(self):
        digest = "sha256:" + "a" * 64
        daemon = _Daemon([_answer(b'{"status":"done"}'), _answer(b'{"status":"done"}')])
        await daemon.start()
        try:
            assert (await docker.pull("img@" + digest))["image"] == "img@" + digest
            assert (await docker.pull("127.0.0.1:5000/app"))["image"] == "127.0.0.1:5000/app:latest"
            first, second = (line for line, _ in daemon.requests)
            assert "fromImage=img%40sha256%3A" in first and "tag=" not in first
            assert "fromImage=127.0.0.1%3A5000%2Fapp&tag=latest" in second
        finally:
            await daemon.stop()

    def test_a_private_registry_is_reached_with_this_accounts_own_login(self, tmp_path,
                                                                         monkeypatch):
        import base64
        token = base64.b64encode(b"deploy:hunter2").decode()
        (tmp_path / "config.json").write_text(json.dumps(
            {"auths": {"ghcr.io": {"auth": token}}}))
        monkeypatch.setenv("DOCKER_CONFIG", str(tmp_path))
        header = docker._auth_header("ghcr.io/owner/app:1")
        assert header and header[0].startswith("X-Registry-Auth: ")
        blob = json.loads(base64.urlsafe_b64decode(header[0].split(": ", 1)[1]))
        assert blob == {"username": "deploy", "password": "hunter2", "serveraddress": "ghcr.io"}
        # Another registry is not handed this one's password.
        assert docker._auth_header("docker.io/library/nginx") == ()
        assert docker._auth_header("quay.io/x/y") == ()

    def test_a_login_file_that_is_not_one_costs_nothing(self, tmp_path, monkeypatch):
        monkeypatch.setenv("DOCKER_CONFIG", str(tmp_path))
        for content in ("", "not json", "[]", '{"auths": 3}',
                        '{"auths": {"ghcr.io": {"auth": "%%%"}}}'):
            (tmp_path / "config.json").write_text(content)
            assert docker._auth_header("ghcr.io/a/b") == ()

    async def test_an_archive_gives_its_files_and_nothing_else(self):
        """Read through the daemon because a volume's files are root's. A link
        is never followed, a name that climbs is never a key, and nothing is
        written anywhere."""
        import io
        import tarfile
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w") as archive:
            def add(name, data=b"", kind=tarfile.REGTYPE, link=""):
                info = tarfile.TarInfo(name)
                info.type, info.linkname, info.size = kind, link, len(data)
                archive.addfile(info, io.BytesIO(data) if data else None)
            add("1", kind=tarfile.DIRTYPE)
            add("1/docker-compose.yml", b"services: {}\n")
            add("1/stack.env", b"A=1\n")
            add("1/link", kind=tarfile.SYMTYPE, link="/etc/shadow")
            add("1/../../escape", b"x")
        daemon = _Daemon([_answer(buffer.getvalue())])
        await daemon.start()
        try:
            held = await docker.read_archive("portainer", "/data/compose/1")
            assert held == {"docker-compose.yml": b"services: {}\n", "stack.env": b"A=1\n"}
            assert "path=/data/compose/1" in daemon.requests[0][0]
        finally:
            await daemon.stop()

    async def test_an_archive_path_that_is_not_one_never_reaches_the_socket(self):
        daemon = _Daemon([])
        await daemon.start()
        try:
            for container, path in (("portainer", "relative"), ("portainer", "/a/../etc"),
                                    ("bad name", "/data"), ("portainer", "/a\0b")):
                with pytest.raises(docker.DockerError):
                    await docker.read_archive(container, path)
            assert daemon.requests == []
        finally:
            await daemon.stop()

    async def test_an_archive_that_is_not_one_is_a_dockererror(self):
        daemon = _Daemon([_answer(b"definitely not a tar file" * 40)])
        await daemon.start()
        try:
            with pytest.raises(docker.DockerError):
                await docker.read_archive("portainer", "/data")
        finally:
            await daemon.stop()

    async def test_the_registry_digest_is_read_and_checked(self):
        good = "sha256:" + "b" * 64
        daemon = _Daemon([_answer(json.dumps({"Descriptor": {"digest": good}}).encode()),
                          _answer(b'{"Descriptor": {"digest": "md5:xyz"}}'),
                          _answer(b'[]')])
        await daemon.start()
        try:
            assert await docker.remote_digest("nginx:1") == good
            for _ in range(2):
                with pytest.raises(docker.DockerError):
                    await docker.remote_digest("nginx:1")
            assert daemon.requests[0][0].split()[1].endswith("/distribution/nginx:1/json")
        finally:
            await daemon.stop()


class TestPortainerConfiguration:
    def test_an_address_is_a_scheme_and_a_host_and_nothing_more(self):
        assert portainer.clean_url("https://portainer.lan:9443") == "https://portainer.lan:9443"
        assert portainer.clean_url("https://10.0.0.5:9443/") == "https://10.0.0.5:9443"
        for bad in ("", "portainer.lan", "ftp://x", "https://x/api/stacks",
                    "https://x?a=b", "https://" + "x" * 300, None,
                    "https://a b"):
            assert portainer.clean_url(bad) == ""

    def test_a_token_travels_in_the_clear_only_to_this_machine(self):
        """Plain HTTP carries the token as written. On loopback there is no
        wire to read it from; anywhere else there is."""
        for good in ("http://127.0.0.1:9000", "http://localhost:9000",
                     "http://[::1]:9000", "http://127.0.0.2:9000"):
            assert portainer.clean_url(good) == good
        for bad in ("http://192.0.2.4:9000", "http://portainer.lan:9000",
                    "http://[2001:db8::1]:9000", "http://localhost.example:9000"):
            assert portainer.clean_url(bad) == ""

    def test_a_token_that_could_be_a_second_header_is_refused(self):
        assert portainer.clean_token("ptr_abc") == "ptr_abc"
        for bad in ("", "a\r\nX-Admin: 1", "a\nb", "tab\there", "é",
                    "x" * (portainer.MAX_TOKEN + 1), None):
            assert portainer.clean_token(bad) == ""

    def test_a_fingerprint_is_a_sha256_or_nothing(self):
        digest = "ab" * 32
        assert portainer.clean_fingerprint(digest.upper()) == digest
        assert portainer.clean_fingerprint(":".join(digest[i:i + 2]
                                                    for i in range(0, 64, 2))) == digest
        for bad in ("", "abc", "zz" * 32, None):
            assert portainer.clean_fingerprint(bad) == ""

    def test_an_unusable_configuration_never_becomes_a_client(self):
        for url, token in (("", "t"), ("https://x:9443", ""), ("nonsense", "t")):
            with pytest.raises(portainer.PortainerError):
                portainer.Portainer(url, token)


class _PortainerServer:
    """Answers like Portainer over plain HTTP, and records what it was asked."""

    def __init__(self, answers):
        self.answers = list(answers)
        self.requests = []
        self.server = None
        self.port = 0

    async def start(self):
        self.server = await asyncio.start_server(self._serve, "127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]

    async def stop(self):
        self.server.close()
        await self.server.wait_closed()

    async def _serve(self, reader, writer):
        line = await reader.readline()
        headers = {}
        while True:
            header = await reader.readline()
            if header in (b"\r\n", b"\n", b""):
                break
            name, _, value = header.decode().partition(":")
            headers[name.strip().lower()] = value.strip()
        length = int(headers.get("content-length") or 0)
        body = await reader.readexactly(length) if length else b""
        self.requests.append((line.decode().strip(), headers, body))
        writer.write(self.answers.pop(0) if self.answers else _answer(b"{}", status=500))
        await writer.drain()
        writer.close()


class TestPortainerCalls:
    async def _client(self, answers):
        server = _PortainerServer(answers)
        await server.start()
        return server, portainer.Portainer(f"http://127.0.0.1:{server.port}", "ptr_tok")

    async def test_the_token_travels_as_a_header_and_the_stacks_come_back(self):
        payload = json.dumps([
            {"Id": 3, "Name": "site", "EndpointId": 1, "Status": 1, "Type": 2,
             "GitConfig": {"URL": "https://git/x", "ReferenceName": "main"}},
            {"Id": 4, "Name": "idle", "EndpointId": 1, "Status": 2, "Type": 2},
        ]).encode()
        server, client = await self._client([_answer(payload)])
        try:
            stacks = await client.stacks()
            assert [stack["name"] for stack in stacks] == ["site", "idle"]
            assert stacks[0]["active"] is True and stacks[1]["active"] is False
            assert stacks[0]["git"] is True and stacks[1]["git"] is False
            assert server.requests[0][1]["x-api-key"] == "ptr_tok"
        finally:
            await server.stop()

    async def test_a_git_stack_is_redeployed_through_git(self):
        """The two shapes are not interchangeable: handing a git stack a file
        redeploys the version it already had."""
        stack = {"id": 3, "endpoint": 1, "name": "site", "git": True,
                 "git_ref": "main"}
        detail = {"Id": 3, "Env": [], "GitConfig": {"URL": "https://git/x",
                                                    "ReferenceName": "main"}}
        server, client = await self._client([_answer(json.dumps(detail).encode()),
                                             _answer(b'{"Name":"site"}')])
        try:
            await client.redeploy(stack)
            line, _headers, body = server.requests[1]
            assert line.startswith("PUT /api/stacks/3/git/redeploy?endpointId=1")
            sent = json.loads(body)
            assert sent["PullImage"] is True and sent["RepositoryReferenceName"] == "main"
            assert sent["RepositoryAuthentication"] is False
        finally:
            await server.stop()

    async def test_a_file_stack_is_redeployed_with_its_file(self):
        server, client = await self._client([
            _answer(b'{"Id":3,"Env":[]}'),
            _answer(json.dumps({"StackFileContent": "services: {}"}).encode()),
            _answer(b'{"Name":"site"}'),
        ])
        try:
            await client.redeploy({"id": 3, "endpoint": 1, "name": "site",
                                   "git": False})
            assert server.requests[0][0].startswith("GET /api/stacks/3 ")
            assert server.requests[1][0].startswith("GET /api/stacks/3/file")
            line, _headers, body = server.requests[2]
            assert line.startswith("PUT /api/stacks/3?endpointId=1")
            assert json.loads(body)["StackFileContent"] == "services: {}"
            assert json.loads(body)["PullImage"] is True
        finally:
            await server.stop()

    async def test_a_redeploy_hands_the_stacks_environment_back(self):
        """Portainer replaces a stack's environment with what a redeploy
        carries. An empty list there is every variable of the stack erased, and
        the containers recreated without them."""
        env = [{"name": "DB_PASSWORD", "value": "s3cret"}, {"name": "TZ", "value": "UTC"}]
        server, client = await self._client([
            _answer(json.dumps({"Id": 3, "Env": env}).encode()),
            _answer(json.dumps({"StackFileContent": "services: {}"}).encode()),
            _answer(b'{"Name":"site"}'),
        ])
        try:
            done = await client.redeploy({"id": 3, "endpoint": 1, "name": "site"})
            assert json.loads(server.requests[2][2])["Env"] == env
            # Handed back to Portainer, and to nobody else.
            assert "s3cret" not in json.dumps(done)
        finally:
            await server.stop()

    async def test_a_git_stack_keeps_the_credentials_portainer_stored(self):
        """Saying "no authentication" on a redeploy makes Portainer forget the
        repository's credentials, and the next pull of a private repository
        fails. Asking for them with an empty password makes it use its own."""
        detail = {"Id": 3, "Env": [], "GitConfig": {
            "URL": "https://git/x", "ReferenceName": "refs/heads/main",
            "Authentication": {"Username": "deploy", "Password": ""}}}
        server, client = await self._client([_answer(json.dumps(detail).encode()),
                                             _answer(b'{"Name":"site"}')])
        try:
            await client.redeploy({"id": 3, "endpoint": 1, "name": "site", "git": True})
            sent = json.loads(server.requests[1][2])
            assert sent["RepositoryAuthentication"] is True
            assert sent["RepositoryUsername"] == "deploy"
            assert sent["RepositoryPassword"] == ""
            assert sent["RepositoryReferenceName"] == "refs/heads/main"
        finally:
            await server.stop()

    async def test_a_probe_reports_the_version_and_sends_no_token(self):
        server = _PortainerServer([_answer(b'{"Version":"2.45.2","InstanceID":"x"}')])
        await server.start()
        try:
            seen = await portainer.probe(f"http://127.0.0.1:{server.port}")
            assert seen["version"] == "2.45.2" and seen["fingerprint"] == ""
            line, headers, _body = server.requests[0]
            assert line.startswith("GET /api/system/status")
            assert "x-api-key" not in headers
        finally:
            await server.stop()

    async def test_a_probe_of_something_else_says_so(self):
        server = _PortainerServer([_answer(b'<html>hello</html>')])
        await server.start()
        try:
            with pytest.raises(portainer.PortainerError) as failure:
                await portainer.probe(f"http://127.0.0.1:{server.port}")
            assert "not as Portainer" in str(failure.value)
        finally:
            await server.stop()

    async def test_a_refused_token_says_so(self):
        server, client = await self._client([_answer(b'{"message":"no"}', status=401)])
        try:
            with pytest.raises(portainer.PortainerError) as failure:
                await client.stacks()
            assert "token" in str(failure.value)
        finally:
            await server.stop()

    async def test_an_id_that_is_not_one_never_reaches_the_wire(self):
        server, client = await self._client([])
        try:
            for bad in (0, -1, "3", None, 10 ** 12):
                with pytest.raises(portainer.PortainerError):
                    await client.act(bad, 1, "start")
            with pytest.raises(portainer.PortainerError):
                await client.act(3, 1, "delete")
            assert server.requests == []
        finally:
            await server.stop()

    async def test_a_stack_name_portainer_would_refuse_is_refused_here(self):
        server, client = await self._client([])
        try:
            for bad in ("UPPER", "with space", "-lead", "", "x" * 80):
                with pytest.raises(portainer.PortainerError):
                    await client.deploy(bad, "services: {}", 1)
            assert server.requests == []
        finally:
            await server.stop()

    async def test_an_unreachable_portainer_is_a_message_not_a_traceback(self):
        client = portainer.Portainer("http://127.0.0.1:1", "ptr_tok")
        with pytest.raises(portainer.PortainerError) as failure:
            await client.stacks()
        assert "Portainer" in str(failure.value)


def test_a_log_reply_is_cut_to_fit_the_frame_that_carries_it():
    """A reply too long to trim is not a truncated answer — it is a reply nobody
    receives at all, because the far side cannot parse half a JSON document.

    And no fixed ceiling on the text would do: under JSON escaping one `ESC`
    becomes six characters, so a screen of colour codes is six times its own
    length on the wire."""
    import json
    from src.apps.fleet import MAX_BODY, _dump_json
    log = "\x1b[31m" * 20_000              # all escape bytes: the worst case
    blob = _dump_json({"rid": "aa" * 8, "op": "logs", "text": log},
                      "items", "text")
    assert len(blob) <= MAX_BODY
    answer = json.loads(blob)
    # Cut from the front: a log is read from its end.
    assert answer["text"] and log.endswith(answer["text"])


class TestMatchingAStackToPortainersRecord:
    def test_by_the_id_its_directory_gave(self):
        listed = [{"id": 3, "name": "site"}, {"id": 9, "name": "site"}]
        assert portainer.match({"name": "site", "portainer_id": 9}, listed)["id"] == 9
        assert portainer.match({"name": "site", "portainer_id": 4}, listed) is None

    def test_by_name_only_when_the_name_is_unambiguous(self):
        """Two environments may each hold a stack called `site`; updating the
        other machine's would be updating the wrong machine."""
        listed = [{"id": 3, "name": "site"}, {"id": 9, "name": "site"},
                  {"id": 5, "name": "blog"}]
        assert portainer.match({"name": "blog", "portainer_id": 0}, listed)["id"] == 5
        assert portainer.match({"name": "site", "portainer_id": 0}, listed) is None

    def test_the_local_environment_is_the_one_on_this_socket(self):
        endpoints = [{"id": 2, "url": "tcp://192.0.2.9:9001"},
                     {"id": 7, "url": "unix:///var/run/docker.sock"}]
        assert portainer.local_endpoint(endpoints) == 7
        assert portainer.local_endpoint(endpoints[:1]) == 2
        assert portainer.local_endpoint([]) == 0


class TestReachingTheSocket:
    async def test_a_socket_this_account_may_not_open_says_which(self, tmp_path):
        """"No docker here" and "docker is here and this account cannot reach
        it" are one missing group membership apart, and only one of them is
        something an operator can fix in a minute."""
        import socket as socketlib
        path = str(tmp_path / "docker.sock")
        server = socketlib.socket(socketlib.AF_UNIX, socketlib.SOCK_STREAM)
        server.bind(path)
        server.listen(1)
        os.chmod(path, 0o000)
        os.environ["DOCKER_HOST"] = "unix://" + path
        try:
            if os.geteuid() == 0:
                pytest.skip("root can open any socket, which is the point of it")
            with pytest.raises(docker.DockerError) as failure:
                await docker.call("GET", "/version")
            assert "docker group" in str(failure.value)
        finally:
            os.environ.pop("DOCKER_HOST", None)
            server.close()

    async def test_no_socket_at_all_says_that_instead(self, tmp_path):
        os.environ["DOCKER_HOST"] = "unix://" + str(tmp_path / "nothing.sock")
        try:
            with pytest.raises(docker.DockerError) as failure:
                await docker.call("GET", "/version")
            assert "no docker daemon" in str(failure.value)
        finally:
            os.environ.pop("DOCKER_HOST", None)


# ---------------------------------------------------------------------------
# Usage, volumes, networks, image removal
# ---------------------------------------------------------------------------

class TestWhatTheDaemonReportsAboutUse:
    def test_a_share_is_the_container_cpu_over_the_machines(self):
        raw = {"cpu_stats": {"cpu_usage": {"total_usage": 300}, "system_cpu_usage": 2000,
                             "online_cpus": 4},
               "precpu_stats": {"cpu_usage": {"total_usage": 100}, "system_cpu_usage": 1000},
               "memory_stats": {"usage": 5000, "limit": 9000, "stats": {"inactive_file": 1000}}}
        assert docker.sample(raw) == {"cpu": 80.0, "memory": 4000, "limit": 9000}

    @pytest.mark.parametrize("raw", [None, [], "x", {}, {"cpu_stats": []},
                                     {"cpu_stats": {"cpu_usage": {"total_usage": "a"}}},
                                     {"memory_stats": {"usage": True, "stats": []}},
                                     {"cpu_stats": {"cpu_usage": {"total_usage": 9}, "system_cpu_usage": 1,
                                                    "online_cpus": 10**9}}])
    def test_whatever_the_daemon_sends_there_is_a_bounded_answer(self, raw):
        out = docker.sample(raw)
        assert set(out) == {"cpu", "memory", "limit"}
        assert all(isinstance(value, (int, float)) and value >= 0 for value in out.values())

    async def test_a_container_that_cannot_be_read_costs_only_itself(self):
        row = b'[{"Id":"a1","State":"running"},{"Id":"b2","State":"running"},{"Id":"c3","State":"exited"}]'
        daemon = _Daemon([_answer(row), _answer(b'{"message":"gone"}', status=404),
                          _answer(b'{"memory_stats":{"usage":7}}')])
        await daemon.start()
        try:
            found = await docker.stats()
        finally:
            await daemon.stop()
        assert len(found) == 1 and set(found) <= {"a1", "b2"}

    async def test_volumes_and_networks_are_read_whatever_their_shape(self):
        daemon = _Daemon([_answer(b'{"Volumes":[{"Name":"data","Driver":"local"},7,null]}'),
                          _answer(b'[{"Id":"n1","Name":"bridge","Driver":"bridge",'
                                  b'"IPAM":{"Config":[{"Subnet":"192.0.2.0/24"}]},"Containers":{"x":{}}},'
                                  b'{"Name":1,"IPAM":7,"Containers":[]}, 3]')])
        await daemon.start()
        try:
            volumes, networks = await docker.volumes(), await docker.networks()
        finally:
            await daemon.stop()
        assert [v["name"] for v in volumes] == ["data"]
        assert networks[0]["subnet"] == "192.0.2.0/24" and networks[0]["attached"] == 1
        assert networks[1]["subnet"] == "" and networks[1]["attached"] == 0

    @pytest.mark.parametrize("image", [None, 5, "", "a/../../containers/x", "a b", "a?force=1",
                                       "-x", "a\nb", "x" * 300])
    async def test_an_image_that_is_not_one_never_reaches_the_socket(self, image):
        daemon = _Daemon([_answer(b"[]")])
        await daemon.start()
        try:
            with pytest.raises(docker.DockerError):
                await docker.remove_image(image)
            assert daemon.requests == []
        finally:
            await daemon.stop()

    async def test_an_image_is_removed_by_the_name_it_was_given(self):
        daemon = _Daemon([_answer(b"[]")])
        await daemon.start()
        try:
            assert await docker.remove_image("ghcr.io/o/i:1") == {"image": "ghcr.io/o/i:1"}
            assert daemon.requests[0][0].startswith("DELETE /v1.41/images/ghcr.io/o/i:1 ")
        finally:
            await daemon.stop()


class TestAPortainerDeploymentInTheBackground:
    async def _client(self, answers):
        server = _PortainerServer(answers)
        await server.start()
        return server, portainer.Portainer(f"http://127.0.0.1:{server.port}", "ptr_tok")

    async def test_an_update_is_done_when_portainer_says_so(self, monkeypatch):
        """Recent Portainer answers a redeploy with the stack still deploying
        and recreates its containers afterwards."""
        monkeypatch.setattr(portainer, "SETTLE_POLL", 0.01)
        server, client = await self._client([
            _answer(b'{"Id":3,"Env":[]}'),
            _answer(json.dumps({"StackFileContent": "services: {}"}).encode()),
            _answer(b'{"Name":"site","Status":3}'),
            _answer(b'{"Status":3}'),
            _answer(b'{"Status":1,"DeploymentStatus":[{"Status":3},{"Status":1}]}'),
        ])
        try:
            await client.redeploy({"id": 3, "endpoint": 1, "name": "site"})
            assert len(server.requests) == 5
        finally:
            await server.stop()

    async def test_a_deployment_that_failed_is_a_failure(self, monkeypatch):
        monkeypatch.setattr(portainer, "SETTLE_POLL", 0.01)
        failed = {"Status": 2, "DeploymentStatus": [
            {"Status": 3}, {"Status": 4, "Message": "pull access denied"}]}
        server, client = await self._client([
            _answer(b'{"Id":3,"Env":[]}'),
            _answer(json.dumps({"StackFileContent": "services: {}"}).encode()),
            _answer(b'{"Name":"site","Status":3}'),
            _answer(json.dumps(failed).encode()),
        ])
        try:
            with pytest.raises(portainer.PortainerError) as failure:
                await client.redeploy({"id": 3, "endpoint": 1, "name": "site"})
            assert "pull access denied" in str(failure.value)
        finally:
            await server.stop()
