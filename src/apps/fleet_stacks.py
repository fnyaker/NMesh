"""
Stacks — what a machine runs as compose projects, who deployed each one, and
how to bring it up to date without undoing whoever did.

A stack is recovered from the running machine, never from a database of ours:
compose labels every container it creates with its project, its service, the
files it read and the directory it read them from. Portainer deploys through
compose too, and leaves **no label of its own** — what gives one of its stacks
away is the directory, `/data/compose/<id>`, which is a path inside Portainer's
own container. So there are two owners, told apart by that path:

* **compose** — a project whose files are on this machine. It is brought up to
  date the way it was deployed: `compose pull`, then `compose up -d`, with the
  same files from the same directory.
* **portainer** — its file and its environment live in Portainer's database and
  volume. Through Portainer's API when an operator connected one, which is the
  only way Portainer's own record stays true; and when nobody did, through the
  Engine, below. Re-running compose from a copy of Portainer's directory is
  *not* that act: a relative bind and an `env_file` resolve against a different
  directory, and the containers come back configured differently
  (`gotchas.md`, "Docker: who owns a stack").

The third way works for anything, owner or none: **recreate through the
Engine**. Pull each image the stack's containers were created from, and for
each container whose image moved, create its replacement from its own
configuration — less what the old image supplied, so the new image's defaults
apply — and put the old one back if the new one does not stay up. It needs no
file and no credential, which is why it is the fallback rather than a guess.

Everything from an operator is a name checked against a charset; everything
from the daemon is read field by field. Nothing here builds a shell command:
every process is an argv.
"""
from __future__ import annotations

import asyncio
import os
import re
import time

from . import fleet_docker as docker
from .fleet_docker import DockerError

# -- labels ------------------------------------------------------------------
LABEL_PROJECT = "com.docker.compose.project"
LABEL_SERVICE = "com.docker.compose.service"
LABEL_CONFIG = "com.docker.compose.project.config_files"
LABEL_WORKDIR = "com.docker.compose.project.working_dir"
LABEL_ONEOFF = "com.docker.compose.oneoff"
LABEL_IMAGE = "com.docker.compose.image"
LABEL_DEPENDS = "com.docker.compose.depends_on"
LABEL_PORTAINER_SERVER = "io.portainer.server"

# -- bounds ------------------------------------------------------------------
MAX_STACKS = 100
MAX_SERVICES = 64                 # containers listed under one stack
MAX_FILES = 8                     # compose files one project was deployed from
MAX_CHECKS = 40                   # image references asked of registries at once
CHECK_CONCURRENCY = 6
COMPOSE_TIMEOUT = 1800.0          # `compose pull` and `up` pull and build
PROBE_TIMEOUT = 10.0
COMPOSE_PROBE_TTL = 600.0         # how long "is compose here" is believed
SETTLE = 5.0                      # seconds a recreated container must stay up
MAX_OUTPUT = docker.MAX_LOG_BYTES

_PATH_RE = re.compile(r"\A/[^\0\n\r]{0,511}\Z")
_PORTAINER_DIR = re.compile(r"\A/data/compose/(\d{1,9})(?:/|\Z)")
_PORTAINER_IMAGE = re.compile(r"(?:\A|/)portainer/portainer(?:-ce|-ee)?(?::|@|\Z)")
_AGENT_IMAGE = re.compile(r"(?:\A|/)portainer/agent(?::|@|\Z)")
_VERSION_RE = re.compile(r"(\d{1,3})\.(\d{1,3})")
_HEX64 = re.compile(r"\A[0-9a-f]{64}\Z")


def _short(value, limit: int = 200) -> str:
    return value[:limit] if isinstance(value, str) else ""


def _labels(entry) -> dict:
    labels = entry.get("Labels") if isinstance(entry, dict) else None
    return labels if isinstance(labels, dict) else {}


def _dict(value) -> dict:
    return value if isinstance(value, dict) else {}


def _list(value) -> list:
    return value if isinstance(value, list) else []


# ---------------------------------------------------------------------------
# docker compose, if this machine has it
# ---------------------------------------------------------------------------
#
# Two spellings exist on machines still in service: the v2 plugin
# (`docker compose`) and the old standalone binary (`docker-compose`). Which one
# answers is asked, not assumed from a `docker` binary being on the PATH — the
# CLI is very often installed without the plugin.

_compose: dict = {"argv": None, "version": "", "at": None}


async def compose() -> tuple[list[str] | None, str]:
    """The argv prefix that runs compose here, and its version — or None."""
    now = time.monotonic()
    if _compose["at"] is not None and now - _compose["at"] < COMPOSE_PROBE_TTL:
        return _compose["argv"], _compose["version"]
    found, version = None, ""
    for argv in (["docker", "compose"], ["docker-compose"]):
        try:
            code, text = await run(argv + ["version", "--short"], timeout=PROBE_TIMEOUT)
        except DockerError:
            continue
        if code == 0 and _VERSION_RE.search(text):
            found, version = argv, text.strip().splitlines()[-1][:32]
            break
    _compose.update(argv=found, version=version, at=now)
    return found, version


def _at_least(version: str, major: int, minor: int) -> bool:
    match = _VERSION_RE.search(version or "")
    return bool(match) and (int(match.group(1)), int(match.group(2))) >= (major, minor)


async def run(argv: list[str], *, cwd: str | None = None,
              timeout: float = COMPOSE_TIMEOUT, on_output=None) -> tuple[int, str]:
    """Run a command, bounded, never through a shell.

    `on_output` is handed each line as it arrives: a compose pull is minutes of
    silence otherwise, and silence is indistinguishable from a hang."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv, cwd=cwd or None,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
            stdin=asyncio.subprocess.DEVNULL)
    except (OSError, ValueError) as exc:
        raise DockerError(f"could not run {argv[0]} ({type(exc).__name__})") from None
    collected: list[str] = []
    size = 0

    async def drain() -> None:
        nonlocal size
        while True:
            line = await proc.stdout.readline()
            if not line:
                return
            text = line.decode("utf-8", "replace").rstrip("\r\n")
            if size < MAX_OUTPUT:
                collected.append(text)
                size += len(text) + 1
            if on_output is not None:
                try:
                    on_output(text)
                except Exception:
                    pass

    try:
        await asyncio.wait_for(asyncio.gather(drain(), proc.wait()), timeout)
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except OSError:
            pass
        raise DockerError("that took too long and was stopped") from None
    return proc.returncode or 0, "\n".join(collected)[-MAX_OUTPUT:]


# ---------------------------------------------------------------------------
# Portainer, as the Engine sees it
# ---------------------------------------------------------------------------

def _address(port: dict) -> str:
    """Where a published port is reached from this machine itself."""
    ip = port.get("IP") if isinstance(port.get("IP"), str) else ""
    if ip in ("", "0.0.0.0", "::"):
        ip = "127.0.0.1"
    if ":" in ip:
        ip = f"[{ip}]"
    return f"{ip}:{port.get('PublicPort')}"


def find_portainer(entries: list[dict]) -> dict:
    """A Portainer server or agent among this machine's containers.

    Known by the label Portainer's image carries, and by the image's name for a
    build old enough not to carry it. Finding one costs no credential; what it
    is told is only what the Engine already says about it."""
    server, agent = None, False
    for entry in entries:
        image = _short(entry.get("Image"), 256)
        labels = _labels(entry)
        if labels.get(LABEL_PORTAINER_SERVER) == "true" or _PORTAINER_IMAGE.search(image):
            if server is None or entry.get("State") == "running":
                server = entry
        elif _AGENT_IMAGE.search(image):
            agent = True
    found: dict = {"server": None, "agent": agent}
    if server is None:
        return found
    names = _list(server.get("Names"))
    https = http = ""
    for port in _list(server.get("Ports"))[:docker.MAX_PORTS]:
        if not isinstance(port, dict) or not isinstance(port.get("PublicPort"), int):
            continue
        if port.get("PrivatePort") == 9443 and not https:
            https = "https://" + _address(port)
        elif port.get("PrivatePort") == 9000 and not http:
            http = "http://" + _address(port)
    image = _short(server.get("Image"), 256)
    _repository, tag, _digest = docker.split_reference(image)
    found["server"] = {
        "id": _short(server.get("Id"), 64),
        "name": _short(names[0], 128).lstrip("/") if names and isinstance(names[0], str) else "",
        "image": image,
        "tag": tag[:64],
        "edition": "Business" if "-ee" in image else "Community",
        "state": _short(server.get("State"), 32),
        # Nothing to suggest when it publishes nothing: the operator knows
        # where they reach it, and a guessed address is a wrong one.
        "url": https or http,
    }
    return found


def portainer_stack_id(workdir: str, files: list[str]) -> int:
    """The id Portainer gave a stack, read off the directory it deployed from;
    0 when the directory is not one of Portainer's."""
    for path in [workdir] + list(files):
        match = _PORTAINER_DIR.match(path or "")
        if match:
            return int(match.group(1))
    return 0


# ---------------------------------------------------------------------------
# Stacks from labels
# ---------------------------------------------------------------------------

def compose_files(value) -> list[str]:
    """The compose files a project was deployed from, as compose wrote them.

    The label is a comma-separated list of absolute paths. Anything that is not
    one is dropped rather than passed to an argv — the label is written by
    whoever created the container, and this may run as root."""
    out = []
    for path in (value if isinstance(value, str) else "").split(","):
        path = path.strip()
        if _PATH_RE.match(path) and ".." not in path.split("/") and len(out) < MAX_FILES:
            out.append(path)
    return out


def _readable(path: str) -> bool:
    try:
        return os.path.isfile(path) and os.access(path, os.R_OK)
    except (OSError, ValueError):
        return False


def discover(entries: list[dict], *, root: str = "") -> list[dict]:
    """The daemon's container list → the compose projects it describes.

    One entry per project, with what decides how it can be updated: who owns
    it, which files it came from, and whether those files are readable here."""
    projects: dict = {}
    for entry in entries:
        labels = _labels(entry)
        name = docker.clean_id(labels.get(LABEL_PROJECT))
        if not name or labels.get(LABEL_ONEOFF) == "True":
            continue                  # `compose run` leaves one-offs; not services
        stack = projects.get(name)
        if stack is None:
            if len(projects) >= MAX_STACKS:
                continue
            stack = projects[name] = {
                "name": name, "workdir": "", "files": [], "services": [],
                "running": 0, "total": 0}
        if not stack["workdir"]:
            workdir = _short(labels.get(LABEL_WORKDIR), 512)
            stack["workdir"] = workdir if _PATH_RE.match(workdir) else ""
        if not stack["files"]:
            stack["files"] = compose_files(labels.get(LABEL_CONFIG))
        state = _short(entry.get("State"), 32)
        stack["total"] += 1
        if state == "running":
            stack["running"] += 1
        if len(stack["services"]) < MAX_SERVICES:
            names = _list(entry.get("Names"))
            stack["services"].append({
                "service": _short(labels.get(LABEL_SERVICE), 64),
                "container": _short(entry.get("Id"), 64),
                "name": _short(names[0], 128).lstrip("/")
                if names and isinstance(names[0], str) else "",
                "state": state,
                "status": _short(entry.get("Status"), 96),
                "image": _short(entry.get("Image"), 256),
                "image_id": _short(entry.get("ImageID"), 80),
            })
    ours = stack_dir(root)
    out = []
    for stack in sorted(projects.values(), key=lambda entry: entry["name"]):
        stack["services"].sort(key=lambda row: (row["service"], row["name"]))
        number = portainer_stack_id(stack["workdir"], stack["files"])
        stack["owner"] = "portainer" if number else "compose"
        stack["portainer_id"] = number
        stack["files_ok"] = (not number and bool(stack["files"])
                             and all(_readable(path) for path in stack["files"]))
        stack["nmesh"] = bool(stack["workdir"]) and (
            stack["workdir"] + "/").startswith(ours + "/")
        out.append(stack)
    return out


async def name_images(rows: list[dict], key: str = "container") -> None:
    """Put back the name a container was created from where the daemon lists
    an image id instead — which it does once that name points at a newer
    image, so it is exactly the container an operator is looking for."""
    for row in rows:
        if not str(row.get("image", "")).startswith("sha256:"):
            continue
        try:
            raw = await docker.container_raw(row.get(key, ""))
        except DockerError:
            continue
        named = _short(_dict(raw.get("Config")).get("Image"), 256)
        if named:
            row["image"] = named


def update_method(stack: dict, *, portainer_api: bool, compose_argv) -> dict:
    """How *Update* will bring this stack up to date, and why that way.

    Said before anything is done: an operator choosing Update is choosing
    between acts that differ in what they keep, and has to be able to see which
    one this is."""
    if stack.get("owner") == "portainer":
        if portainer_api:
            return {"method": "portainer",
                    "why": "through Portainer's API: it pulls and redeploys "
                           "with the file and environment it holds"}
        return {"method": "engine",
                "why": "Portainer is not connected here, so each image is "
                       "pulled and its container recreated with the settings "
                       "it runs with"}
    if not stack.get("files"):
        return {"method": "engine",
                "why": "no compose file is recorded for it, so each image is "
                       "pulled and its container recreated"}
    if not stack.get("files_ok"):
        return {"method": "engine",
                "why": "its compose file is not readable by this node, so each "
                       "image is pulled and its container recreated"}
    if compose_argv is None:
        return {"method": "engine",
                "why": "docker compose is not installed here, so each image is "
                       "pulled and its container recreated"}
    return {"method": "compose",
            "why": "compose pull, then compose up -d, with the file it was "
                   "deployed from"}


# ---------------------------------------------------------------------------
# Is there anything newer?
# ---------------------------------------------------------------------------

async def check(entries: list[dict]) -> dict:
    """For each container, whether its image has something newer.

    ``current``, ``outdated`` (the registry serves another image under that
    name), ``pulled`` (a newer one is already here and the container still
    runs the old), ``pinned`` (named by digest), ``local`` (never came from a
    registry) or ``unknown`` (the registry would not say). Asked through the
    daemon's distribution route, which reads a manifest and downloads nothing.
    """
    by_ref: dict[str, list[dict]] = {}
    for entry in entries:
        reference = _short(entry.get("Image"), 256)
        if reference.startswith("sha256:"):
            # The name it was created from now points at another image.
            try:
                raw = await docker.container_raw(_short(entry.get("Id"), 64))
                reference = _short(_dict(raw.get("Config")).get("Image"), 256)
            except DockerError:
                continue
        if docker.clean_image(reference):
            by_ref.setdefault(reference, []).append(entry)
    references = sorted(by_ref)[:MAX_CHECKS]
    gate = asyncio.Semaphore(CHECK_CONCURRENCY)
    images: dict = {}

    async def one(reference: str) -> None:
        async with gate:
            images[reference] = await _check_one(reference)

    await asyncio.gather(*(one(reference) for reference in references))
    containers: dict = {}
    for reference in references:
        verdict = images[reference]
        for entry in by_ref[reference]:
            state = verdict["state"]
            if state in ("current", "outdated") and verdict.get("local_id") and \
                    entry.get("ImageID") != verdict["local_id"]:
                state = "pulled"
            containers[_short(entry.get("Id"), 64)] = state
    return {"containers": containers,
            "images": {ref: {"state": images[ref]["state"],
                             "why": images[ref].get("why", "")}
                       for ref in references}}


async def _check_one(reference: str) -> dict:
    _repository, _tag, digest = docker.split_reference(reference)
    if digest:
        return {"state": "pinned"}
    try:
        local = await docker.image_raw(reference)
    except DockerError as exc:
        return {"state": "unknown", "why": str(exc)[:160]}
    local_id = _short(_dict(local).get("Id"), 80)
    held = [value.partition("@")[2] for value in _list(_dict(local).get("RepoDigests"))
            if isinstance(value, str)]
    if local is not None and not held:
        return {"state": "local", "local_id": local_id}
    try:
        remote = await docker.remote_digest(reference)
    except DockerError as exc:
        return {"state": "unknown", "why": str(exc)[:160], "local_id": local_id}
    return {"state": "current" if remote in held else "outdated", "local_id": local_id}


# ---------------------------------------------------------------------------
# Recreate through the Engine
# ---------------------------------------------------------------------------

def _same(left, right) -> bool:
    return (left or None) == (right or None)


def recreate_body(raw: dict, image: dict, new_image_id: str) -> tuple[dict, list]:
    """A container's own configuration, ready to create its replacement.

    What the old *image* supplied is taken back out — its environment, its
    command, its labels, its ports and volumes — so the new image's apply, as
    they would to a container created fresh; what the container was *given* is
    kept. Its anonymous volumes are carried over by name, or the replacement
    would start with empty ones.

    Returns the body and the networks to join after creation: an Engine older
    than API 1.44 attaches one network at create time."""
    config = dict(_dict(raw.get("Config")))
    held = _dict(_dict(image).get("Config"))
    ident = _short(raw.get("Id"), 64)
    if _same(config.get("Entrypoint"), held.get("Entrypoint")):
        config.pop("Entrypoint", None)
        if _same(config.get("Cmd"), held.get("Cmd")):
            config.pop("Cmd", None)
    for key in ("WorkingDir", "User", "Healthcheck", "StopSignal"):
        if _same(config.get(key), held.get(key)):
            config.pop(key, None)
    image_env = set(value for value in _list(held.get("Env")) if isinstance(value, str))
    config["Env"] = [value for value in _list(config.get("Env"))
                     if isinstance(value, str) and value not in image_env]
    image_labels = _dict(held.get("Labels"))
    labels = {key: value for key, value in _dict(config.get("Labels")).items()
              if image_labels.get(key) != value}
    if LABEL_IMAGE in labels:
        labels[LABEL_IMAGE] = new_image_id
    config["Labels"] = labels
    for key in ("ExposedPorts", "Volumes"):
        own = {name: value for name, value in _dict(config.get(key)).items()
               if name not in _dict(held.get(key))}
        if own:
            config[key] = own
        else:
            config.pop(key, None)
    if config.get("Hostname") and ident.startswith(str(config["Hostname"])):
        config.pop("Hostname", None)      # the daemon's default: the old id
    host = dict(_dict(raw.get("HostConfig")))
    anonymous = {}
    for mount in _list(raw.get("Mounts")):
        mount = _dict(mount)
        name = _short(mount.get("Name"), 64)
        target = _short(mount.get("Destination"), 512)
        if mount.get("Type") == "volume" and _HEX64.match(name) and target:
            anonymous[target] = (name, bool(mount.get("RW", True)))
    binds = [value for value in _list(host.get("Binds")) if isinstance(value, str)]
    taken = {value.split(":")[1] for value in binds if value.count(":") >= 1}
    mounts = []
    for mount in _list(host.get("Mounts")):
        mount = dict(_dict(mount))
        target = _short(mount.get("Target"), 512)
        taken.add(target)
        # compose declares an anonymous volume with no source; left that way,
        # the replacement would be given a new, empty one.
        if mount.get("Type") == "volume" and not mount.get("Source") \
                and target in anonymous:
            mount["Source"] = anonymous[target][0]
        mounts.append(mount)
    if mounts:
        host["Mounts"] = mounts
    for target, (name, writable) in anonymous.items():
        if target not in taken:
            binds.append(f"{name}:{target}" + ("" if writable else ":ro"))
    if binds:
        host["Binds"] = binds
    mode = _short(host.get("NetworkMode"), 256)
    attached = _dict(_dict(raw.get("NetworkSettings")).get("Networks"))
    endpoints = {}
    for network, settings in list(attached.items())[:16]:
        settings = _dict(settings)
        endpoint = {"Aliases": [alias for alias in _list(settings.get("Aliases"))
                                if isinstance(alias, str) and not ident.startswith(alias)]}
        for key in ("IPAMConfig", "Links", "DriverOpts"):
            if settings.get(key):
                endpoint[key] = settings[key]
        endpoints[network] = endpoint
    body = dict(config)
    later = []
    if mode in ("host", "none") or mode.startswith("container:"):
        pass                              # no network of its own to join
    elif mode in endpoints:
        body["NetworkingConfig"] = {"EndpointsConfig": {mode: endpoints[mode]}}
        later = [(network, endpoint) for network, endpoint in endpoints.items()
                 if network != mode]
    elif mode in ("", "default", "bridge") and endpoints:
        first = next(iter(endpoints))
        body["NetworkingConfig"] = {"EndpointsConfig": {first: endpoints[first]}}
        later = [(network, endpoint) for network, endpoint in endpoints.items()
                 if network != first]
    body["HostConfig"] = host
    return body, later


async def recreate(container: str, *, pull: bool = True, entries=None,
                   say=None) -> dict:
    """Bring one container onto the newest image of the name it was created
    from. ``updated``, ``current`` (nothing newer), or ``pinned``.

    A replacement that does not stay up puts the old container back, so a bad
    image costs a few seconds of downtime rather than the service."""
    say = say or (lambda _line: None)
    raw = await docker.container_raw(container)
    ident = _short(raw.get("Id"), 64)
    name = _short(raw.get("Name"), 128).lstrip("/")
    reference = _short(_dict(raw.get("Config")).get("Image"), 256)
    result = {"container": ident, "name": name, "image": reference}
    if not docker.clean_id(name) or not docker.clean_id(ident):
        raise DockerError("the daemon named that container in no usable way")
    if not docker.clean_image(reference) or reference.startswith("sha256:") \
            or docker.split_reference(reference)[2]:
        return dict(result, result="pinned")
    if pull:
        say(f"pulling {reference}")
        await docker.pull(reference)
    fresh = await docker.image_raw(reference)
    if fresh is None:
        raise DockerError(f"{reference} is not on this machine after the pull")
    new_id = _short(fresh.get("Id"), 80)
    if new_id == raw.get("Image"):
        return dict(result, result="current")
    if entries is None:
        entries = await docker.raw_containers(True)
    for entry in entries:
        mode = _short(_dict(entry.get("HostConfig")).get("NetworkMode"), 256)
        if mode in (f"container:{ident}", f"container:{name}"):
            raise DockerError(
                f"{name} carries another container's network; update their "
                "stack with compose, which recreates them together")
    old_image = await docker.image_raw(_short(raw.get("Image"), 80)) or {}
    body, later = recreate_body(raw, old_image, new_id)
    state = _dict(raw.get("State"))
    was_running = bool(state.get("Running") or state.get("Restarting"))
    spare = docker.clean_id(f"{name[:100]}-nmesh-old-{ident[:8]}")
    say(f"recreating {name}")
    await docker.call("POST", f"/containers/{ident}/stop?t=10", timeout=120.0)
    await docker.call("POST", f"/containers/{ident}/rename?name={spare}")
    fresh_id = ""
    try:
        answer = await docker.call("POST", f"/containers/create?name={name}",
                                   body=body, timeout=90.0)
        fresh_id = _short(_dict(answer).get("Id"), 64)
        if not fresh_id:
            raise DockerError("docker created it and did not say what it was called")
        for network, endpoint in later:
            if not docker.clean_id(network):
                continue
            await docker.call("POST", f"/networks/{docker.clean_id(network)}/connect",
                              body={"Container": fresh_id, "EndpointConfig": endpoint})
        if was_running:
            await docker.call("POST", f"/containers/{fresh_id}/start", timeout=90.0)
            await asyncio.sleep(SETTLE)
            check_state = _dict((await docker.container_raw(fresh_id)).get("State"))
            if not check_state.get("Running"):
                raise DockerError(
                    f"the new {name} stopped with code {check_state.get('ExitCode')}")
    except DockerError as exc:
        say(f"putting the old {name} back")
        if fresh_id:
            try:
                await docker.call("DELETE", f"/containers/{fresh_id}?force=1")
            except DockerError:
                pass
        await docker.call("POST", f"/containers/{ident}/rename?name={name}")
        if was_running:
            await docker.call("POST", f"/containers/{ident}/start", timeout=90.0)
        raise DockerError(f"{exc}; the old container was put back") from None
    await docker.call("DELETE", f"/containers/{ident}?force=1", timeout=60.0)
    return dict(result, result="updated", container=fresh_id)


def _order(services: list[dict], entries: list[dict]) -> list[dict]:
    """Dependencies first, by the `depends_on` compose records on each one."""
    needs: dict[str, set] = {}
    for entry in entries:
        labels = _labels(entry)
        service = _short(labels.get(LABEL_SERVICE), 64)
        wanted = _short(labels.get(LABEL_DEPENDS), 1024)
        needs[service] = {part.split(":")[0] for part in wanted.split(",") if part}
    ordered, seen = [], set()

    def visit(service: str, depth: int) -> None:
        if service in seen or depth > MAX_SERVICES:
            return
        seen.add(service)
        for other in sorted(needs.get(service, ())):
            visit(other, depth + 1)
        ordered.extend(row for row in services if row["service"] == service)

    for row in services:
        visit(row["service"], 0)
    return ordered + [row for row in services if row not in ordered]


async def engine_update(stack: dict, *, say=None) -> dict:
    """Pull every image a stack's containers came from, once each, then
    recreate the containers whose image moved."""
    say = say or (lambda _line: None)
    entries = await docker.raw_containers(True)
    ours = [entry for entry in entries
            if _labels(entry).get(LABEL_PROJECT) == stack["name"]]
    services = _order(list(stack.get("services") or []), ours)
    pulled: dict = {}
    steps = []
    for row in services:
        label = row["service"] or row["name"]
        try:
            raw = await docker.container_raw(row["container"])
            reference = _short(_dict(raw.get("Config")).get("Image"), 256)
            if docker.clean_image(reference) and not docker.split_reference(reference)[2] \
                    and not reference.startswith("sha256:"):
                if reference not in pulled:
                    say(f"pulling {reference}")
                    try:
                        await docker.pull(reference)
                        pulled[reference] = ""
                    except DockerError as exc:
                        pulled[reference] = str(exc)
                if pulled[reference]:
                    raise DockerError(f"pulling {reference} failed: {pulled[reference]}")
            done = await recreate(row["container"], pull=False, entries=entries, say=say)
        except DockerError as exc:
            # One service that cannot be updated costs only itself: the rest
            # of the stack still gets its new images.
            steps.append({"service": label, "result": "failed", "why": str(exc)[:200]})
            say(f"{label}: failed — {exc}")
            continue
        steps.append({"service": label, "result": done["result"]})
        say(f"{label}: {done['result']}")
    return {"stack": stack["name"], "through": "engine", "steps": steps,
            "updated": sum(1 for step in steps if step["result"] == "updated"),
            "failed": sum(1 for step in steps if step["result"] == "failed")}


# ---------------------------------------------------------------------------
# Through compose
# ---------------------------------------------------------------------------

def _compose_argv(prefix: list[str], stack: dict, *rest: str) -> list[str]:
    argv = list(prefix) + ["--project-name", stack["name"]]
    workdir = stack.get("workdir") or ""
    if _PATH_RE.match(workdir) and os.path.isdir(workdir):
        argv += ["--project-directory", workdir]
    for path in stack.get("files") or []:
        argv += ["-f", path]
    return argv + list(rest)


async def compose_update(stack: dict, *, say=None) -> dict:
    """`compose pull`, then `compose up -d`: the project as its file says,
    with the images the registry serves now.

    No `--remove-orphans`: a service dropped from the file is somebody's
    decision to make about their data, not a side effect of an update."""
    argv, version = await compose()
    if argv is None:
        raise DockerError("this machine has no docker compose")
    if not stack.get("files_ok"):
        raise DockerError("that stack's compose file is not readable here")
    pull = ["pull"] + (["--ignore-buildable"] if _at_least(version, 2, 15) else [])
    code, text = await run(_compose_argv(argv, stack, *pull), on_output=say)
    if code != 0:
        raise DockerError(f"pulling that stack failed: {text[-300:]}")
    code, more = await run(_compose_argv(argv, stack, "up", "-d"), on_output=say)
    if code != 0:
        raise DockerError(f"bringing that stack up failed: {more[-300:]}")
    return {"stack": stack["name"], "through": "compose",
            "output": (text + "\n" + more)[-4000:]}


async def compose_act(stack: dict, action: str, *, say=None) -> dict:
    argv, _version = await compose()
    if argv is None or not stack.get("files_ok"):
        raise DockerError("that needs the stack's compose file and docker compose")
    code, text = await run(_compose_argv(argv, stack, action), on_output=say)
    if code != 0:
        raise DockerError(f"that stack refused to {action}: {text[-300:]}")
    return {"stack": stack["name"], "action": action, "through": "compose",
            "output": text[-4000:]}


async def engine_act(stack: dict, action: str) -> dict:
    """start / stop / restart, container by container — what is possible
    without the file. Dependencies start first and stop last."""
    if action not in ("start", "stop", "restart"):
        raise DockerError("that needs the stack's compose file")
    entries = await docker.raw_containers(True)
    ours = [entry for entry in entries
            if _labels(entry).get(LABEL_PROJECT) == stack["name"]]
    rows = _order(list(stack.get("services") or []), ours)
    if action == "stop":
        rows.reverse()
    if not rows:
        raise DockerError("no container on this machine belongs to that stack")
    for row in rows:
        await docker.act(row["container"], action)
    return {"stack": stack["name"], "action": action, "through": "engine",
            "containers": len(rows)}


# ---------------------------------------------------------------------------
# A stack's file
# ---------------------------------------------------------------------------

async def read_file(stack: dict, *, server: str = "") -> dict:
    """The compose file a stack was deployed from, for reading.

    Only the compose file: Portainer keeps the stack's environment beside it
    (`stack.env`), and a container's environment is where its secrets are —
    names travel, values do not."""
    files = stack.get("files") or []
    if stack.get("owner") == "portainer":
        number = stack.get("portainer_id") or 0
        if not server or not number:
            raise DockerError("Portainer keeps that file; connect it, or run it here")
        held = await docker.read_archive(server, f"/data/compose/{int(number)}")
        wanted = os.path.basename(files[0]) if files else "docker-compose.yml"
        for name in (wanted, "docker-compose.yml", "docker-compose.yaml",
                     "compose.yml", "compose.yaml"):
            if name in held and name.endswith((".yml", ".yaml")):
                return {"path": f"/data/compose/{int(number)}/{name}",
                        "text": _text(held[name]), "source": "portainer"}
        raise DockerError("Portainer's directory for that stack holds no compose file")
    if not files:
        raise DockerError("no compose file is recorded for that stack")
    path = files[0]
    if not path.endswith((".yml", ".yaml")) or not _readable(path):
        raise DockerError("that compose file is not readable by this node")
    with open(path, "rb") as handle:
        return {"path": path, "text": _text(handle.read(docker.MAX_COMPOSE + 1)),
                "source": "disk"}


def _text(raw: bytes) -> str:
    text = raw.decode("utf-8", "replace")
    if len(text) > docker.MAX_COMPOSE:
        text = text[:docker.MAX_COMPOSE] + "\n# … cut here: the file is longer"
    return text


# ---------------------------------------------------------------------------
# Deploying a new one
# ---------------------------------------------------------------------------

def stack_dir(root: str = "") -> str:
    """Where compose files this node deployed are kept.

    Under the node's own data directory when it has one — the same place its
    identity and its session store live, so a compose file that decides what
    runs on this machine is backed up and wiped with the rest of its state.
    Never `/tmp`, and never a path from the wire."""
    base = root or os.path.expanduser("~/.nmesh")
    return os.path.join(base, "stacks")


async def deploy(project: str, content: str, *, root: str = "", say=None) -> dict:
    """Deploy a stack from a compose file an operator wrote.

    The file is written under a directory of this node's own, named for the
    project, so a later update finds it where compose recorded it — and so
    nothing this deploys can be made to overwrite a path chosen by whoever sent
    the file: the only thing from the wire that reaches the path is a name that
    passed :func:`fleet_docker.clean_id`."""
    name = docker.clean_id(project)
    if not name or name != name.lower():
        raise DockerError("a stack name is lowercase letters, digits, - and _")
    body = docker.clean_compose(content)
    if not body:
        raise DockerError("that compose file is empty or too large")
    argv, _version = await compose()
    if argv is None:
        raise DockerError("this machine has no docker compose")
    directory = os.path.join(stack_dir(root), name)
    os.makedirs(directory, mode=0o700, exist_ok=True)
    path = os.path.join(directory, "docker-compose.yml")
    tmp = path + ".new"
    with open(tmp, "w", encoding="utf-8") as handle:
        os.chmod(tmp, 0o600)
        handle.write(body)
    os.replace(tmp, path)
    stack = {"name": name, "files": [path], "workdir": directory, "files_ok": True}
    code, text = await run(_compose_argv(argv, stack, "up", "-d"), on_output=say)
    if code != 0:
        raise DockerError(f"bringing that stack up failed: {text[-300:]}")
    return {"stack": name, "through": "compose", "output": text[-4000:]}
