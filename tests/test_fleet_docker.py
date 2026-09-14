"""
Docker and Portainer: the validation in front of them, and the wire under them.

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


class TestStacksFromLabels:
    def test_containers_group_into_the_projects_that_created_them(self):
        rows = [
            {"id": "a", "name": "web", "project": "site", "service": "web",
             "state": "running", "image": "nginx", "portainer": ""},
            {"id": "b", "name": "db", "project": "site", "service": "db",
             "state": "exited", "image": "pg", "portainer": ""},
            {"id": "c", "name": "loose", "project": "", "service": "",
             "state": "running", "image": "busybox", "portainer": ""},
            {"id": "d", "name": "pt", "project": "other", "service": "app",
             "state": "running", "image": "img", "portainer": "other"},
        ]
        stacks = docker.group_stacks(rows)
        assert [stack["name"] for stack in stacks] == ["other", "site"]
        site = stacks[1]
        assert site["total"] == 2 and site["running"] == 1
        assert {entry["service"] for entry in site["services"]} == {"web", "db"}
        # A container in no project is in no stack — not in one called "".
        assert all(stack["name"] for stack in stacks)
        assert stacks[0]["portainer"] == "other"

    def test_a_compose_file_label_that_is_not_a_path_is_dropped(self):
        assert docker.compose_files("/srv/a.yml,/srv/b.yml") == ["/srv/a.yml", "/srv/b.yml"]
        assert docker.compose_files("a.yml") == []
        assert docker.compose_files("/srv/a.yml,relative.yml") == ["/srv/a.yml"]
        assert docker.compose_files("") == []
        assert docker.compose_files("/a\nb.yml") == []


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

class TestPortainerConfiguration:
    def test_an_address_is_a_scheme_and_a_host_and_nothing_more(self):
        assert portainer.clean_url("https://portainer.lan:9443") == "https://portainer.lan:9443"
        assert portainer.clean_url("http://10.0.0.5:9000/") == "http://10.0.0.5:9000"
        for bad in ("", "portainer.lan", "ftp://x", "https://x/api/stacks",
                    "https://x?a=b", "https://" + "x" * 300, None,
                    "https://a b"):
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
        server, client = await self._client([_answer(b'{"Name":"site"}')])
        try:
            await client.redeploy(stack)
            line, _headers, body = server.requests[0]
            assert line.startswith("PUT /api/stacks/3/git/redeploy?endpointId=1")
            assert json.loads(body)["PullImage"] is True
        finally:
            await server.stop()

    async def test_a_file_stack_is_redeployed_with_its_file(self):
        server, client = await self._client([
            _answer(json.dumps({"StackFileContent": "services: {}"}).encode()),
            _answer(b'{"Name":"site"}'),
        ])
        try:
            await client.redeploy({"id": 3, "endpoint": 1, "name": "site",
                                   "git": False})
            assert server.requests[0][0].startswith("GET /api/stacks/3/file")
            line, _headers, body = server.requests[1]
            assert line.startswith("PUT /api/stacks/3?endpointId=1")
            assert json.loads(body)["StackFileContent"] == "services: {}"
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


class TestWhereAComposeFileLands:
    """A file that decides what runs on a machine belongs with that node's own
    state — backed up and wiped with it, never in `/tmp` and never at a path
    somebody sent."""

    def test_it_is_under_the_nodes_data_directory(self):
        assert docker.stack_dir("/var/lib/nmesh") == "/var/lib/nmesh/stacks"

    def test_and_falls_back_to_the_accounts_own_directory(self):
        assert docker.stack_dir().endswith("/.nmesh/stacks")

    async def test_a_name_that_could_climb_out_never_reaches_a_path(self, tmp_path):
        for bad in ("../../etc/cron.d", "/etc/nmesh", "a/b", "", "."):
            with pytest.raises(docker.DockerError):
                await docker.deploy_stack(bad, "services: {}", root=str(tmp_path))
        assert list(tmp_path.iterdir()) == []

    async def test_an_empty_or_oversized_compose_file_is_refused(self, tmp_path):
        for bad in ("", "   ", "x" * (docker.MAX_COMPOSE + 1), "a\0b"):
            with pytest.raises(docker.DockerError):
                await docker.deploy_stack("ok", bad, root=str(tmp_path))
        assert list(tmp_path.iterdir()) == []


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
