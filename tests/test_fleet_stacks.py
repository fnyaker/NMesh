"""
Stacks: finding them on a machine, telling who owns each one, and bringing it
up to date without undoing whoever did.

Three things are worth proving and they are different things.

**Discovery reads the machine, not a database.** Compose labels what it
creates; Portainer labels nothing of its own and is known by the directory it
deploys from. A stack is found, or missed, from those labels alone.

**An update keeps what the container was given.** Recreating through the
Engine is the fallback for anything without a readable file or a connected
Portainer, and the one thing it must not do is lose a setting, a volume or a
network alias on the way — or leave a service down when the new image will not
start.

**What reaches an argv or a socket is checked.** Names from the operator,
paths from labels: each is refused, never escaped.

No real daemon here: the Engine calls are replaced by a fake that records them,
the way `test_fleet_docker.py` drives the client itself against a fake socket.
"""
import os

import pytest

from src.apps import fleet_docker as docker
from src.apps import fleet_stacks as stacks


def _entry(ident, project="", service="", *, state="running", image="img:1",
           workdir="", files="", oneoff=False, extra=None, image_id=""):
    labels = {}
    if project:
        labels[stacks.LABEL_PROJECT] = project
        labels[stacks.LABEL_SERVICE] = service
        labels[stacks.LABEL_WORKDIR] = workdir
        labels[stacks.LABEL_CONFIG] = files
        if oneoff:
            labels[stacks.LABEL_ONEOFF] = "True"
    labels.update(extra or {})
    return {"Id": ident, "Names": ["/" + (service or ident)], "Image": image,
            "ImageID": image_id or "sha256:" + ident, "State": state,
            "Status": "Up", "Labels": labels}


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------

class TestFindingStacks:
    def test_containers_group_into_the_projects_that_created_them(self):
        found = stacks.discover([
            _entry("a", "site", "web", workdir="/srv/site", files="/srv/site/compose.yml"),
            _entry("b", "site", "db", state="exited"),
            _entry("c"),                                     # in no project
            _entry("d", "other", "app"),
        ])
        assert [stack["name"] for stack in found] == ["other", "site"]
        site = found[1]
        assert site["total"] == 2 and site["running"] == 1
        assert [row["service"] for row in site["services"]] == ["db", "web"]
        assert site["workdir"] == "/srv/site"
        assert site["files"] == ["/srv/site/compose.yml"]

    def test_a_one_off_container_is_not_a_service(self):
        """`compose run` leaves containers labelled with the project; they are
        not part of what the stack runs, and recreating one would run its
        command again."""
        found = stacks.discover([_entry("a", "site", "web"),
                                 _entry("b", "site", "web", oneoff=True)])
        assert found[0]["total"] == 1

    def test_a_project_name_that_is_not_a_name_is_no_stack(self):
        assert stacks.discover([_entry("a", "../etc", "x"), _entry("b", "a b", "y")]) == []

    def test_portainer_is_known_by_the_directory_it_deploys_from(self):
        """Portainer writes no label of its own on a stack's containers —
        measured on Portainer 2.45 — so the name of a label is not how it is
        recognised. Its directory is: a path inside its own container."""
        found = stacks.discover([
            _entry("a", "blog", "web", workdir="/data/compose/12",
                   files="/data/compose/12/docker-compose.yml"),
            _entry("b", "plain", "web", workdir="/srv/plain",
                   files="/srv/plain/docker-compose.yml"),
            _entry("c", "nested", "web", workdir="/opt/data/compose/3",
                   files="/opt/data/compose/3/docker-compose.yml"),
        ])
        by_name = {stack["name"]: stack for stack in found}
        assert by_name["blog"]["owner"] == "portainer"
        assert by_name["blog"]["portainer_id"] == 12
        assert by_name["blog"]["files_ok"] is False      # Portainer's, not ours to read
        assert by_name["plain"]["owner"] == "compose"
        assert by_name["nested"]["owner"] == "compose"

    def test_a_file_counts_as_usable_only_when_this_node_can_read_it(self, tmp_path):
        readable = tmp_path / "compose.yml"
        readable.write_text("services: {}\n")
        found = stacks.discover([
            _entry("a", "here", "web", workdir=str(tmp_path), files=str(readable)),
            _entry("b", "gone", "web", workdir="/nonexistent",
                   files="/nonexistent/compose.yml"),
            _entry("c", "none", "web"),
        ])
        by_name = {stack["name"]: stack for stack in found}
        assert by_name["here"]["files_ok"] is True
        assert by_name["gone"]["files_ok"] is False
        assert by_name["none"]["files_ok"] is False

    def test_a_stack_this_node_deployed_says_so(self, tmp_path):
        ours = os.path.join(stacks.stack_dir(str(tmp_path)), "app")
        found = stacks.discover([_entry("a", "app", "web", workdir=ours)], root=str(tmp_path))
        assert found[0]["nmesh"] is True
        beside = stacks.stack_dir(str(tmp_path)) + "-other/app"
        found = stacks.discover([_entry("a", "app", "web", workdir=beside)],
                                root=str(tmp_path))
        assert found[0]["nmesh"] is False

    def test_the_count_of_stacks_and_services_is_bounded(self):
        entries = [_entry(f"c{i}", f"p{i}", "s") for i in range(stacks.MAX_STACKS + 20)]
        entries += [_entry(f"d{i}", "p0", f"s{i}") for i in range(stacks.MAX_SERVICES + 5)]
        found = stacks.discover(entries)
        assert len(found) == stacks.MAX_STACKS
        p0 = next(stack for stack in found if stack["name"] == "p0")
        assert len(p0["services"]) == stacks.MAX_SERVICES
        assert p0["total"] == stacks.MAX_SERVICES + 6

    def test_whatever_the_daemon_sends_there_is_a_list(self):
        hostile = [{}, {"Labels": None}, {"Labels": {stacks.LABEL_PROJECT: 7}},
                   {"Labels": {stacks.LABEL_PROJECT: "ok"}, "Names": "nope",
                    "State": ["x"]}, {"Labels": []}]
        found = stacks.discover(hostile)
        assert [stack["name"] for stack in found] == ["ok"]

    def test_a_compose_file_label_that_is_not_a_path_is_dropped(self):
        assert stacks.compose_files("/srv/a.yml,/srv/b.yml") == ["/srv/a.yml", "/srv/b.yml"]
        assert stacks.compose_files("a.yml") == []
        assert stacks.compose_files("/srv/a.yml,relative.yml") == ["/srv/a.yml"]
        assert stacks.compose_files("/srv/../etc/a.yml") == []
        assert stacks.compose_files("") == []
        assert stacks.compose_files(None) == []
        assert stacks.compose_files("/a\nb.yml") == []
        many = ",".join(f"/f{i}.yml" for i in range(20))
        assert len(stacks.compose_files(many)) == stacks.MAX_FILES


class TestFindingPortainer:
    def _server(self, **override):
        entry = {"Id": "p" * 64, "Names": ["/portainer"], "State": "running",
                 "Image": "portainer/portainer-ce:2.45.2",
                 "Labels": {"io.portainer.server": "true"},
                 "Ports": [{"IP": "0.0.0.0", "PrivatePort": 9000, "PublicPort": 9000},
                           {"IP": "0.0.0.0", "PrivatePort": 9443, "PublicPort": 9443}]}
        entry.update(override)
        return entry

    def test_by_its_label_and_where_it_answers(self):
        found = stacks.find_portainer([_entry("a"), self._server()])
        assert found["server"]["name"] == "portainer"
        assert found["server"]["edition"] == "Community"
        assert found["server"]["tag"] == "2.45.2"
        # HTTPS before HTTP, and a wildcard bind reached on loopback.
        assert found["server"]["url"] == "https://127.0.0.1:9443"

    def test_by_its_image_when_the_label_is_missing(self):
        server = self._server(Labels={}, Image="registry.example/portainer/portainer-ee:2.19")
        found = stacks.find_portainer([server])
        assert found["server"]["edition"] == "Business"

    def test_an_address_it_is_bound_to_is_the_one_suggested(self):
        server = self._server(Ports=[{"IP": "127.0.0.1", "PrivatePort": 9000,
                                      "PublicPort": 19000}])
        assert stacks.find_portainer([server])["server"]["url"] == "http://127.0.0.1:19000"
        server = self._server(Ports=[{"IP": "::1", "PrivatePort": 9443, "PublicPort": 9443}])
        assert stacks.find_portainer([server])["server"]["url"] == "https://[::1]:9443"

    def test_one_that_publishes_nothing_is_given_no_guessed_address(self):
        found = stacks.find_portainer([self._server(Ports=[])])
        assert found["server"]["url"] == ""

    def test_an_agent_is_not_a_server(self):
        found = stacks.find_portainer([_entry("a", image="portainer/agent:2.45.2")])
        assert found == {"server": None, "agent": True}

    def test_nothing_is_found_where_there_is_nothing(self):
        assert stacks.find_portainer([_entry("a"), _entry("b", image="myportainer/x")]) == \
            {"server": None, "agent": False}


class TestHowAStackIsUpdated:
    def test_through_portainer_when_it_owns_it_and_is_connected(self):
        stack = {"owner": "portainer", "files": ["/data/compose/1/docker-compose.yml"]}
        assert stacks.update_method(stack, portainer_api=True,
                                    compose_argv=["docker", "compose"])["method"] == "portainer"

    def test_never_through_compose_when_portainer_owns_it(self):
        """A copy of Portainer's directory resolves a relative bind and an
        `env_file` against the wrong place: the containers would come back
        configured differently. Without the API, the Engine."""
        stack = {"owner": "portainer", "files": ["/data/compose/1/docker-compose.yml"],
                 "files_ok": True}
        assert stacks.update_method(stack, portainer_api=False,
                                    compose_argv=["docker", "compose"])["method"] == "engine"

    def test_through_compose_with_a_readable_file(self):
        stack = {"owner": "compose", "files": ["/srv/a.yml"], "files_ok": True}
        assert stacks.update_method(stack, portainer_api=False,
                                    compose_argv=["docker", "compose"])["method"] == "compose"

    @pytest.mark.parametrize("stack,argv", [
        ({"owner": "compose", "files": [], "files_ok": False}, ["docker", "compose"]),
        ({"owner": "compose", "files": ["/srv/a.yml"], "files_ok": False}, ["docker", "compose"]),
        ({"owner": "compose", "files": ["/srv/a.yml"], "files_ok": True}, None),
    ])
    def test_through_the_engine_when_compose_cannot(self, stack, argv):
        chosen = stacks.update_method(stack, portainer_api=False, compose_argv=argv)
        assert chosen["method"] == "engine" and chosen["why"]


# ---------------------------------------------------------------------------
# Recreating through the Engine
# ---------------------------------------------------------------------------

OLD_ID = "1" * 64


def _raw(**override):
    raw = {
        "Id": OLD_ID, "Name": "/demo-web-1", "Image": "sha256:old",
        "State": {"Running": True},
        "Config": {
            "Image": "registry.example/app:latest", "Hostname": OLD_ID[:12],
            "Env": ["GREETING=hello", "PATH=/usr/bin", "APP_VERSION=1"],
            "Cmd": ["serve"], "Entrypoint": ["/entry"], "WorkingDir": "/app",
            "Labels": {"com.docker.compose.project": "demo",
                       "com.docker.compose.image": "sha256:old",
                       "org.opencontainers.image.version": "1",
                       "mine": "kept"},
            "ExposedPorts": {"80/tcp": {}, "9000/tcp": {}},
            "Volumes": {"/var/lib/app": {}},
        },
        "HostConfig": {"Binds": ["/data/compose/1/data:/data:rw"],
                       "NetworkMode": "demo_default",
                       "RestartPolicy": {"Name": "always"}},
        "Mounts": [
            {"Type": "bind", "Source": "/data/compose/1/data", "Destination": "/data", "RW": True},
            {"Type": "volume", "Name": "a" * 64, "Destination": "/var/lib/app", "RW": True},
        ],
        "NetworkSettings": {"Networks": {
            "demo_default": {"Aliases": ["demo-web-1", "web", OLD_ID[:12]],
                             "IPAddress": "172.18.0.2", "NetworkID": "n1",
                             "IPAMConfig": {"IPv4Address": "172.18.0.50"}},
            "backend": {"Aliases": ["web"], "IPAddress": "172.19.0.4"},
        }},
    }
    raw.update(override)
    return raw


IMAGE = {"Config": {"Env": ["PATH=/usr/bin", "APP_VERSION=1"], "Cmd": ["serve"],
                    "Entrypoint": ["/entry"], "WorkingDir": "/app",
                    "Labels": {"org.opencontainers.image.version": "1"},
                    "ExposedPorts": {"80/tcp": {}}, "Volumes": {"/var/lib/app": {}}}}


class TestTheReplacementsConfiguration:
    def test_what_the_old_image_supplied_is_left_to_the_new_one(self):
        """An image's own environment, command and labels are baked into the
        container's configuration. Kept, the replacement would run the new
        image with the old one's defaults — a version variable that lies, a
        command that no longer exists."""
        body, _later = stacks.recreate_body(_raw(), IMAGE, "sha256:new")
        assert body["Env"] == ["GREETING=hello"]
        assert "Cmd" not in body and "Entrypoint" not in body and "WorkingDir" not in body
        assert "org.opencontainers.image.version" not in body["Labels"]
        assert body["ExposedPorts"] == {"9000/tcp": {}}
        assert "Volumes" not in body

    def test_what_the_container_was_given_is_kept(self):
        body, _later = stacks.recreate_body(_raw(), IMAGE, "sha256:new")
        assert body["Image"] == "registry.example/app:latest"
        assert body["Labels"]["mine"] == "kept"
        assert body["Labels"]["com.docker.compose.project"] == "demo"
        assert body["HostConfig"]["RestartPolicy"] == {"Name": "always"}
        assert "/data/compose/1/data:/data:rw" in body["HostConfig"]["Binds"]

    def test_compose_is_told_which_image_it_now_runs(self):
        """Left at the old id, compose reads the container as diverged from
        its image and recreates it again on its next `up`."""
        body, _later = stacks.recreate_body(_raw(), IMAGE, "sha256:new")
        assert body["Labels"]["com.docker.compose.image"] == "sha256:new"

    def test_a_given_command_survives_with_a_given_entrypoint(self):
        """`--entrypoint` clears the image's command: a command equal to the
        image's next to a custom entrypoint was given, not inherited."""
        raw = _raw()
        raw["Config"]["Entrypoint"] = ["/custom"]
        body, _later = stacks.recreate_body(raw, IMAGE, "sha256:new")
        assert body["Entrypoint"] == ["/custom"] and body["Cmd"] == ["serve"]

    def test_an_anonymous_volume_is_carried_over_by_name(self):
        """Without it the replacement starts with a fresh, empty volume where
        the old one kept its data."""
        body, _later = stacks.recreate_body(_raw(), IMAGE, "sha256:new")
        assert f"{'a' * 64}:/var/lib/app" in body["HostConfig"]["Binds"]

    def test_an_anonymous_volume_compose_declared_gets_its_source_back(self):
        raw = _raw()
        raw["HostConfig"]["Mounts"] = [{"Type": "volume", "Target": "/var/lib/app"}]
        body, _later = stacks.recreate_body(raw, IMAGE, "sha256:new")
        assert body["HostConfig"]["Mounts"] == [
            {"Type": "volume", "Target": "/var/lib/app", "Source": "a" * 64}]
        assert not any(bind.endswith(":/var/lib/app") for bind in body["HostConfig"]["Binds"])

    def test_the_old_id_is_not_carried_as_a_name(self):
        body, _later = stacks.recreate_body(_raw(), IMAGE, "sha256:new")
        assert "Hostname" not in body
        endpoint = body["NetworkingConfig"]["EndpointsConfig"]["demo_default"]
        assert endpoint["Aliases"] == ["demo-web-1", "web"]
        assert endpoint["IPAMConfig"] == {"IPv4Address": "172.18.0.50"}
        assert "IPAddress" not in endpoint and "NetworkID" not in endpoint

    def test_a_hostname_somebody_chose_is_kept(self):
        raw = _raw()
        raw["Config"]["Hostname"] = "web.internal"
        body, _later = stacks.recreate_body(raw, IMAGE, "sha256:new")
        assert body["Hostname"] == "web.internal"

    def test_the_other_networks_are_joined_after_creation(self):
        """Before API 1.44 the Engine attaches one network at create time."""
        body, later = stacks.recreate_body(_raw(), IMAGE, "sha256:new")
        assert list(body["NetworkingConfig"]["EndpointsConfig"]) == ["demo_default"]
        assert later == [("backend", {"Aliases": ["web"]})]

    def test_host_networking_takes_no_endpoint(self):
        raw = _raw()
        raw["HostConfig"]["NetworkMode"] = "host"
        raw["NetworkSettings"] = {"Networks": {"host": {}}}
        body, later = stacks.recreate_body(raw, IMAGE, "sha256:new")
        assert "NetworkingConfig" not in body and later == []

    def test_whatever_the_daemon_sent_there_is_a_body(self):
        for hostile in ({}, {"Config": None, "HostConfig": [], "Mounts": "x",
                             "NetworkSettings": {"Networks": None}},
                        {"Config": {"Env": [1, None, "A=1"], "Labels": []}}):
            body, later = stacks.recreate_body(hostile, {"Config": "nope"}, "sha256:new")
            assert isinstance(body, dict) and isinstance(later, list)


class _Engine:
    """The Engine calls `fleet_stacks` makes, answered from a script and
    recorded. Patched over the client's functions, not over a socket: what is
    under test here is the order and the content of the acts."""

    def __init__(self, raw, *, fresh_id="sha256:new", starts=True, local=None):
        self.raw = raw
        self.fresh_id = fresh_id
        self.starts = starts
        self.calls = []
        self.pulled = []
        self.local = local if local is not None else {}

    def install(self, monkeypatch):
        monkeypatch.setattr(docker, "container_raw", self.container_raw)
        monkeypatch.setattr(docker, "image_raw", self.image_raw)
        monkeypatch.setattr(docker, "pull", self.pull)
        monkeypatch.setattr(docker, "call", self.call)
        monkeypatch.setattr(docker, "raw_containers", self.raw_containers)
        monkeypatch.setattr(stacks, "SETTLE", 0.0)
        return self

    async def container_raw(self, ident):
        if ident == "new-id":
            return {"State": {"Running": self.starts, "ExitCode": 0 if self.starts else 1}}
        if "Id" in self.raw:
            return self.raw
        return self.raw[ident]

    async def image_raw(self, reference):
        if reference in self.local:
            return self.local[reference]
        if reference.startswith("sha256:"):
            return IMAGE
        return {"Id": self.fresh_id}

    async def pull(self, reference):
        self.pulled.append(reference)
        return {"image": reference}

    async def raw_containers(self, _all=True):
        return []

    async def call(self, method, path, body=None, **_options):
        self.calls.append((method, path.split("?")[0], path, body))
        if path.startswith("/containers/create"):
            return {"Id": "new-id"}
        return None


class TestRecreating:
    async def test_a_newer_image_replaces_the_container(self, monkeypatch):
        engine = _Engine(_raw()).install(monkeypatch)
        done = await stacks.recreate(OLD_ID)
        assert done["result"] == "updated" and done["container"] == "new-id"
        assert engine.pulled == ["registry.example/app:latest"]
        acts = [(method, short) for method, short, _path, _body in engine.calls]
        assert acts == [
            ("POST", f"/containers/{OLD_ID}/stop"),
            ("POST", f"/containers/{OLD_ID}/rename"),
            ("POST", "/containers/create"),
            ("POST", "/networks/backend/connect"),
            ("POST", "/containers/new-id/start"),
            ("DELETE", f"/containers/{OLD_ID}"),
        ]
        create = engine.calls[2]
        assert "name=demo-web-1" in create[2]
        # Volumes outlive the old container: it is removed without them.
        assert "v=1" not in engine.calls[-1][2]

    async def test_nothing_is_touched_when_the_image_did_not_move(self, monkeypatch):
        engine = _Engine(_raw(), fresh_id="sha256:old").install(monkeypatch)
        done = await stacks.recreate(OLD_ID)
        assert done["result"] == "current" and engine.calls == []

    @pytest.mark.parametrize("reference", ["app@sha256:" + "c" * 64, "sha256:" + "d" * 64])
    async def test_an_image_named_by_digest_is_left_alone(self, monkeypatch, reference):
        raw = _raw()
        raw["Config"]["Image"] = reference
        engine = _Engine(raw).install(monkeypatch)
        assert (await stacks.recreate(OLD_ID))["result"] == "pinned"
        assert engine.calls == [] and engine.pulled == []

    async def test_a_replacement_that_does_not_stay_up_puts_the_old_one_back(self,
                                                                              monkeypatch):
        """A bad image costs a few seconds of downtime, not the service."""
        engine = _Engine(_raw(), starts=False).install(monkeypatch)
        with pytest.raises(docker.DockerError) as failure:
            await stacks.recreate(OLD_ID)
        assert "put back" in str(failure.value)
        tail = [(method, short) for method, short, _path, _body in engine.calls][-3:]
        assert tail == [("DELETE", "/containers/new-id"),
                        ("POST", f"/containers/{OLD_ID}/rename"),
                        ("POST", f"/containers/{OLD_ID}/start")]
        assert "name=demo-web-1" in engine.calls[-2][2]
        assert not any(method == "DELETE" and short == f"/containers/{OLD_ID}"
                       for method, short, _path, _body in engine.calls)

    async def test_a_container_that_was_stopped_is_not_started(self, monkeypatch):
        engine = _Engine(_raw(State={"Running": False})).install(monkeypatch)
        assert (await stacks.recreate(OLD_ID))["result"] == "updated"
        assert not any(short.endswith("/start") for _m, short, _p, _b in engine.calls)

    async def test_a_container_another_one_shares_a_network_with_is_refused(self,
                                                                             monkeypatch):
        """`network_mode: container:web` names the old container; recreating
        it alone would leave its partner on a network that no longer exists."""
        engine = _Engine(_raw()).install(monkeypatch)
        partner = {"Id": "2" * 64, "HostConfig": {"NetworkMode": f"container:{OLD_ID}"}}
        with pytest.raises(docker.DockerError) as failure:
            await stacks.recreate(OLD_ID, entries=[partner])
        assert "network" in str(failure.value)
        assert not any(short.endswith("/stop") for _m, short, _p, _b in engine.calls)

    async def test_a_name_the_daemon_should_not_have_given_never_reaches_a_path(self,
                                                                               monkeypatch):
        engine = _Engine(_raw(Name="/bad name&x=1")).install(monkeypatch)
        with pytest.raises(docker.DockerError):
            await stacks.recreate(OLD_ID)
        assert engine.calls == []


class TestUpdatingAStackThroughTheEngine:
    def _stack(self):
        return {"name": "demo", "services": [
            {"service": "web", "container": "w", "name": "demo-web-1"},
            {"service": "db", "container": "d", "name": "demo-db-1"},
            {"service": "worker", "container": "k", "name": "demo-worker-1"}]}

    async def test_each_image_is_pulled_once_and_a_failure_costs_only_its_service(
            self, monkeypatch):
        web, db, worker = _raw(), _raw(), _raw()
        web["Name"], db["Name"], worker["Name"] = "/demo-web-1", "/demo-db-1", "/demo-worker-1"
        db["Config"] = dict(db["Config"], Image="postgres:16")
        worker["Config"] = dict(worker["Config"], Image="registry.example/broken:1")
        engine = _Engine({"w": web, "d": db, "k": worker}).install(monkeypatch)

        async def pull(reference):
            if "broken" in reference:
                raise docker.DockerError("manifest unknown")
            engine.pulled.append(reference)
            return {"image": reference}
        monkeypatch.setattr(docker, "pull", pull)
        done = await stacks.engine_update(self._stack())
        results = {step["service"]: step["result"] for step in done["steps"]}
        assert results == {"web": "updated", "db": "updated", "worker": "failed"}
        assert sorted(engine.pulled) == ["postgres:16", "registry.example/app:latest"]
        assert done["updated"] == 2 and done["failed"] == 1

    def test_dependencies_come_first(self):
        services = [{"service": "web"}, {"service": "db"}, {"service": "cache"}]
        entries = [
            _entry("a", "demo", "web", extra={stacks.LABEL_DEPENDS: "db:service_started:false,cache:service_healthy:true"}),
            _entry("b", "demo", "db"),
            _entry("c", "demo", "cache", extra={stacks.LABEL_DEPENDS: "db:service_started:false"}),
        ]
        ordered = [row["service"] for row in stacks._order(services, entries)]
        assert ordered.index("db") < ordered.index("cache") < ordered.index("web")

    def test_a_dependency_cycle_still_ends(self):
        services = [{"service": "a"}, {"service": "b"}]
        entries = [_entry("1", "p", "a", extra={stacks.LABEL_DEPENDS: "b:x:y"}),
                   _entry("2", "p", "b", extra={stacks.LABEL_DEPENDS: "a:x:y"})]
        assert sorted(row["service"] for row in stacks._order(services, entries)) == ["a", "b"]


# ---------------------------------------------------------------------------
# Is there anything newer?
# ---------------------------------------------------------------------------

class TestCheckingForUpdates:
    async def test_each_state_is_told_apart(self, monkeypatch):
        digest_a, digest_b = "sha256:" + "a" * 64, "sha256:" + "b" * 64
        local = {
            "fresh:1": {"Id": "sha256:f", "RepoDigests": [f"fresh@{digest_a}"]},
            "stale:1": {"Id": "sha256:s", "RepoDigests": [f"stale@{digest_a}"]},
            "built:1": {"Id": "sha256:l", "RepoDigests": []},
            "moved:1": {"Id": "sha256:m2", "RepoDigests": [f"moved@{digest_a}"]},
        }

        async def image_raw(reference):
            return local.get(reference)

        async def remote_digest(reference):
            if reference == "private:1":
                raise docker.DockerError("unauthorized")
            return digest_b if reference == "stale:1" else digest_a

        monkeypatch.setattr(docker, "image_raw", image_raw)
        monkeypatch.setattr(docker, "remote_digest", remote_digest)
        entries = [
            {"Id": "c1", "Image": "fresh:1", "ImageID": "sha256:f"},
            {"Id": "c2", "Image": "stale:1", "ImageID": "sha256:s"},
            {"Id": "c3", "Image": "built:1", "ImageID": "sha256:l"},
            {"Id": "c4", "Image": "moved:1", "ImageID": "sha256:m1"},
            {"Id": "c5", "Image": "app@" + digest_a, "ImageID": "sha256:p"},
            {"Id": "c6", "Image": "private:1", "ImageID": "sha256:x"},
        ]
        done = await stacks.check(entries)
        assert done["containers"] == {"c1": "current", "c2": "outdated", "c3": "local",
                                      "c4": "pulled", "c5": "pinned", "c6": "unknown"}
        assert "unauthorized" in done["images"]["private:1"]["why"]

    async def test_a_container_whose_name_moved_is_checked_under_its_name(self, monkeypatch):
        """The daemon lists a container by image id once its tag points at
        another image — which is exactly the container that is behind."""
        async def container_raw(ident):
            return {"Config": {"Image": "moved:1"}}

        async def image_raw(reference):
            return {"Id": "sha256:new", "RepoDigests": ["moved@sha256:" + "a" * 64]}

        async def remote_digest(reference):
            return "sha256:" + "a" * 64

        monkeypatch.setattr(docker, "container_raw", container_raw)
        monkeypatch.setattr(docker, "image_raw", image_raw)
        monkeypatch.setattr(docker, "remote_digest", remote_digest)
        done = await stacks.check([{"Id": "c1", "Image": "sha256:old", "ImageID": "sha256:old"}])
        assert done["containers"] == {"c1": "pulled"}

    async def test_registries_are_asked_a_bounded_number_of_times(self, monkeypatch):
        asked = []

        async def image_raw(reference):
            return {"Id": "sha256:x", "RepoDigests": [reference + "@sha256:" + "a" * 64]}

        async def remote_digest(reference):
            asked.append(reference)
            return "sha256:" + "a" * 64

        monkeypatch.setattr(docker, "image_raw", image_raw)
        monkeypatch.setattr(docker, "remote_digest", remote_digest)
        entries = [{"Id": f"c{i}", "Image": f"img{i}:1", "ImageID": "sha256:x"}
                   for i in range(stacks.MAX_CHECKS + 30)]
        entries += [{"Id": "dup", "Image": "img0:1", "ImageID": "sha256:x"}]
        await stacks.check(entries)
        assert len(asked) == stacks.MAX_CHECKS == len(set(asked))


# ---------------------------------------------------------------------------
# Through compose
# ---------------------------------------------------------------------------

class _Runner:
    def __init__(self, answers=None):
        self.argvs = []
        self.answers = list(answers or [])

    async def __call__(self, argv, *, cwd=None, timeout=None, on_output=None):
        self.argvs.append(list(argv))
        return self.answers.pop(0) if self.answers else (0, "ok")


class TestCompose:
    async def test_the_plugin_is_asked_before_the_old_binary(self, monkeypatch):
        runner = _Runner([(1, "unknown command"), (0, "1.29.2")])
        monkeypatch.setattr(stacks, "run", runner)
        monkeypatch.setitem(stacks._compose, "at", None)
        assert await stacks.compose() == (["docker-compose"], "1.29.2")
        assert runner.argvs == [["docker", "compose", "version", "--short"],
                                ["docker-compose", "version", "--short"]]
        # Believed for a while: asked once, not on every page refresh.
        assert await stacks.compose() == (["docker-compose"], "1.29.2")
        assert len(runner.argvs) == 2

    async def test_a_docker_cli_without_the_plugin_is_no_compose(self, monkeypatch):
        """A `docker` binary on the PATH said nothing about compose: the CLI is
        very often installed without the plugin."""
        async def missing(argv, **_options):
            if argv[0] == "docker-compose":
                raise docker.DockerError("could not run docker-compose")
            return 1, "docker: 'compose' is not a docker command."
        monkeypatch.setattr(stacks, "run", missing)
        monkeypatch.setitem(stacks._compose, "at", None)
        assert await stacks.compose() == (None, "")

    async def test_an_update_pulls_then_brings_it_up_with_its_own_files(self, monkeypatch,
                                                                       tmp_path):
        runner = _Runner()
        monkeypatch.setattr(stacks, "run", runner)
        monkeypatch.setitem(stacks._compose, "at", None)
        runner.answers = [(0, "2.29.1")]
        stack = {"name": "site", "files": ["/srv/site/a.yml", "/srv/site/b.yml"],
                 "workdir": str(tmp_path), "files_ok": True}
        done = await stacks.compose_update(stack)
        assert done["through"] == "compose"
        prefix = ["docker", "compose", "--project-name", "site",
                  "--project-directory", str(tmp_path),
                  "-f", "/srv/site/a.yml", "-f", "/srv/site/b.yml"]
        assert runner.argvs[1:] == [prefix + ["pull", "--ignore-buildable"],
                                    prefix + ["up", "-d"]]
        # A service dropped from the file is somebody's data, not a side effect.
        assert not any("--remove-orphans" in argv for argv in runner.argvs)

    async def test_a_failed_pull_stops_before_anything_is_recreated(self, monkeypatch):
        runner = _Runner([(0, "2.29.1"), (1, "pull access denied")])
        monkeypatch.setattr(stacks, "run", runner)
        monkeypatch.setitem(stacks._compose, "at", None)
        stack = {"name": "site", "files": ["/srv/a.yml"], "workdir": "", "files_ok": True}
        with pytest.raises(docker.DockerError) as failure:
            await stacks.compose_update(stack)
        assert "pull access denied" in str(failure.value)
        assert not any("up" in argv for argv in runner.argvs[1:])

    async def test_an_unreadable_file_is_never_handed_to_compose(self, monkeypatch):
        runner = _Runner([(0, "2.29.1")])
        monkeypatch.setattr(stacks, "run", runner)
        monkeypatch.setitem(stacks._compose, "at", None)
        with pytest.raises(docker.DockerError):
            await stacks.compose_update({"name": "x", "files": ["/a.yml"], "files_ok": False})
        assert len(runner.argvs) == 1

    def test_versions_compare_as_numbers(self):
        assert stacks._at_least("2.15.0", 2, 15) and stacks._at_least("v5.6.0", 2, 15)
        assert not stacks._at_least("2.9.1", 2, 15) and not stacks._at_least("", 2, 15)


class TestRunningAProcess:
    async def test_output_is_bounded_and_the_exit_code_kept(self):
        code, text = await stacks.run(["sh", "-c", "yes x | head -c 200000; exit 3"])
        assert code == 3 and len(text) <= stacks.MAX_OUTPUT

    async def test_a_command_that_outlives_its_bound_is_stopped(self):
        with pytest.raises(docker.DockerError):
            await stacks.run(["sleep", "5"], timeout=0.2)

    async def test_a_missing_binary_is_a_dockererror(self):
        with pytest.raises(docker.DockerError):
            await stacks.run(["/nonexistent/compose"])


# ---------------------------------------------------------------------------
# Start, stop, the file, a new stack
# ---------------------------------------------------------------------------

class TestActingWithoutTheFile:
    async def test_dependencies_start_first_and_stop_last(self, monkeypatch):
        acted = []

        async def raw_containers(_all=True):
            return [_entry("w", "demo", "web", extra={stacks.LABEL_DEPENDS: "db:x:y"}),
                    _entry("d", "demo", "db")]

        async def act(container, action):
            acted.append((container, action))
            return {}

        monkeypatch.setattr(docker, "raw_containers", raw_containers)
        monkeypatch.setattr(docker, "act", act)
        stack = {"name": "demo", "services": [{"service": "web", "container": "w"},
                                              {"service": "db", "container": "d"}]}
        await stacks.engine_act(stack, "start")
        await stacks.engine_act(stack, "stop")
        assert acted == [("d", "start"), ("w", "start"), ("w", "stop"), ("d", "stop")]

    async def test_down_needs_the_file(self):
        with pytest.raises(docker.DockerError):
            await stacks.engine_act({"name": "demo", "services": []}, "down")


class TestReadingAStacksFile:
    async def test_portainers_compose_file_and_never_its_environment(self, monkeypatch):
        """Portainer keeps the stack's variables beside its file, in
        `stack.env`. Those are the stack's secrets; names may travel, values
        never do."""
        async def read_archive(container, path):
            assert (container, path) == ("p" * 64, "/data/compose/12")
            return {"docker-compose.yml": b"services: {}\n", "stack.env": b"PASSWORD=x\n"}
        monkeypatch.setattr(docker, "read_archive", read_archive)
        stack = {"owner": "portainer", "portainer_id": 12,
                 "files": ["/data/compose/12/docker-compose.yml"]}
        done = await stacks.read_file(stack, server="p" * 64)
        assert done == {"path": "/data/compose/12/docker-compose.yml",
                        "text": "services: {}\n", "source": "portainer"}

    async def test_a_portainer_stack_is_never_read_from_the_hosts_path(self):
        with pytest.raises(docker.DockerError):
            await stacks.read_file({"owner": "portainer", "portainer_id": 12,
                                    "files": ["/data/compose/12/docker-compose.yml"]})

    async def test_a_file_on_disk_is_read_bounded(self, tmp_path):
        path = tmp_path / "docker-compose.yml"
        path.write_text("x" * (docker.MAX_COMPOSE + 500))
        done = await stacks.read_file({"owner": "compose", "files": [str(path)]})
        assert done["source"] == "disk"
        assert len(done["text"]) < docker.MAX_COMPOSE + 100
        assert done["text"].endswith("the file is longer")

    async def test_a_label_naming_something_else_is_not_read(self, tmp_path):
        """The label is written by whoever created the container. A label
        pointing at a file that is not compose's is not an invitation."""
        secret = tmp_path / "shadow"
        secret.write_text("root:x")
        for files in ([str(secret)], [str(tmp_path / "gone.yml")], []):
            with pytest.raises(docker.DockerError):
                await stacks.read_file({"owner": "compose", "files": files})


class TestDeployingAStack:
    """A file that decides what runs on a machine belongs with that node's own
    state — backed up and wiped with it, never in `/tmp` and never at a path
    somebody sent."""

    def test_it_is_under_the_nodes_data_directory(self):
        assert stacks.stack_dir("/var/lib/nmesh") == "/var/lib/nmesh/stacks"

    def test_and_falls_back_to_the_accounts_own_directory(self):
        assert stacks.stack_dir().endswith("/.nmesh/stacks")

    async def test_a_name_that_could_climb_out_never_reaches_a_path(self, tmp_path):
        for bad in ("../../etc/cron.d", "/etc/nmesh", "a/b", "", ".", "UPPER"):
            with pytest.raises(docker.DockerError):
                await stacks.deploy(bad, "services: {}", root=str(tmp_path))
        assert list(tmp_path.iterdir()) == []

    async def test_an_empty_or_oversized_compose_file_is_refused(self, tmp_path):
        for bad in ("", "   ", "x" * (docker.MAX_COMPOSE + 1), "a\0b", None):
            with pytest.raises(docker.DockerError):
                await stacks.deploy("ok", bad, root=str(tmp_path))
        assert list(tmp_path.iterdir()) == []

    async def test_the_file_is_written_privately_and_brought_up(self, monkeypatch, tmp_path):
        runner = _Runner([(0, "2.29.1"), (0, "started")])
        monkeypatch.setattr(stacks, "run", runner)
        monkeypatch.setitem(stacks._compose, "at", None)
        done = await stacks.deploy("site", "services: {}\n", root=str(tmp_path))
        path = os.path.join(stacks.stack_dir(str(tmp_path)), "site", "docker-compose.yml")
        assert open(path).read() == "services: {}\n"
        assert os.stat(path).st_mode & 0o077 == 0
        assert done["stack"] == "site"
        assert runner.argvs[1][-2:] == ["up", "-d"]
        assert ["-f", path] == runner.argvs[1][runner.argvs[1].index("-f"):][:2]


def test_nothing_here_runs_through_a_shell():
    """Every process is an argv: a stack name in a command string would be a
    command of its own."""
    import inspect
    source = inspect.getsource(stacks)
    assert "create_subprocess_shell" not in source
    assert "shell=True" not in source
    assert "os.system" not in source



class TestNamingImages:
    async def test_an_image_id_is_replaced_by_the_name_it_was_created_from(self, monkeypatch):
        async def container_raw(ident):
            if ident == "gone":
                raise docker.DockerError("no such container")
            return {"Config": {"Image": "registry.example/app:latest"}}
        monkeypatch.setattr(docker, "container_raw", container_raw)
        rows = [{"container": "a", "image": "sha256:" + "1" * 64},
                {"container": "b", "image": "alpine:3.20"},
                {"container": "gone", "image": "sha256:" + "2" * 64}]
        await stacks.name_images(rows)
        assert [row["image"] for row in rows] == [
            "registry.example/app:latest", "alpine:3.20", "sha256:" + "2" * 64]
