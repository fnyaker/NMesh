"""
Docker, and the stacks on top of it — what a managed machine runs in containers.

Three ways in, and they are deliberately not interchangeable:

* **The Engine API**, over the machine's own socket. Everything that reads or
  moves a container goes through it: listing, inspecting, logs, start/stop,
  pulling an image, creating one. No CLI needed, no shell, no quoting surface.
* **`docker compose`**, when the binary is there. A *stack* is a compose
  project, and the only honest way to bring one up to date is to re-run the
  compose file it was deployed from — pulling images under a project and
  restarting it is not the same act and quietly does less.
* **Portainer's API**, when this machine is running one. Portainer deploys
  through compose and labels what it deploys, so its stacks already show up in
  the list above; what its API adds is the stack *file* (git or string) and the
  redeploy that fetches it again. A stack Portainer owns is updated through
  Portainer, or the next thing Portainer does will undo it.

**The socket is root.** A process that can talk to `/var/run/docker.sock` can
start a privileged container bind-mounting `/`, which is the machine. That is
why this is a capability of its own, why its description says so in those words,
and why nothing here is reachable without it. The gate is the fleet app's; this
module holds no authorisation of its own and must never be handed input that has
not been through one.

Everything arriving from an operator is hostile input: names, ids, image
references, compose files, Portainer URLs. Each one is validated against a
charset and a bound *before* it reaches a socket or an argv, and a value that
does not validate is refused rather than escaped — there is no escaping here to
get wrong.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import time

# -- bounds -----------------------------------------------------------------
# Every one of these bounds something an operator, or the daemon, can grow.
DEFAULT_SOCKET = "/var/run/docker.sock"
API_VERSION = "v1.41"             # old enough for every engine still supported
CALL_TIMEOUT = 30.0               # one Engine API call
PULL_TIMEOUT = 900.0              # an image pull is minutes, not seconds
COMPOSE_TIMEOUT = 1800.0          # `compose up` builds and pulls
MAX_RESPONSE = 4 * 1024 * 1024    # bytes read from one API answer
MAX_LINE = 64 * 1024              # one header or chunk-size line
MAX_CONTAINERS = 250
MAX_IMAGES = 250
MAX_STACKS = 100
MAX_LOG_TAIL = 2000               # lines
# What a reply may carry back. Sized to fit one frame *after* JSON escaping:
# `_dump_json` drops whole list entries to make a reply fit, and a string is not
# a list — a log too long to trim is a reply nobody receives at all.
MAX_LOG_BYTES = 32_000
MAX_COMPOSE = 40_000              # a compose file, so one reply frame still fits
MAX_ENV = 64                      # variables on a container we create
MAX_PORTS = 32
MAX_MOUNTS = 32

# Labels compose writes on everything it creates. They are the whole reason a
# "stack" can be recovered from a running machine without a database.
LABEL_PROJECT = "com.docker.compose.project"
LABEL_SERVICE = "com.docker.compose.service"
LABEL_CONFIG = "com.docker.compose.project.config_files"
LABEL_WORKDIR = "com.docker.compose.project.working_dir"
# Portainer's own, on the stacks it owns.
LABEL_PORTAINER = "io.portainer.stack.name"

_ID_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_IMAGE_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_.:/@-]{0,255}\Z")
_ENV_NAME_RE = re.compile(r"\A[A-Za-z_][A-Za-z0-9_]{0,63}\Z")
_PATH_RE = re.compile(r"\A/[^\0\n\r]{0,511}\Z")
_RESTART = ("no", "on-failure", "always", "unless-stopped")


class DockerError(Exception):
    """Something a caller can be told. Never carries a traceback outward."""


# ---------------------------------------------------------------------------
# Validation — everything below this line may have come from another machine
# ---------------------------------------------------------------------------

def clean_id(value) -> str:
    """A container, image, network or volume name/id, or "" if it is not one."""
    if not isinstance(value, str):
        return ""
    value = value.strip()
    return value if _ID_RE.match(value) else ""


def clean_image(value) -> str:
    if not isinstance(value, str):
        return ""
    value = value.strip()
    return value if _IMAGE_RE.match(value) else ""


def clean_compose(value) -> str:
    """A compose file. Bounded, and never anything but text.

    Not parsed here: compose is the thing that understands compose, and a
    half-implemented YAML reader deciding what is safe would be a worse gate
    than the capability in front of it."""
    if not isinstance(value, str) or not value.strip():
        return ""
    if len(value) > MAX_COMPOSE:
        return ""
    if "\0" in value:
        return ""
    return value


def _clean_env(raw) -> list[str]:
    out: list[str] = []
    if not isinstance(raw, dict):
        return out
    for name, value in list(raw.items())[:MAX_ENV]:
        if not isinstance(name, str) or not _ENV_NAME_RE.match(name):
            continue
        text = value if isinstance(value, str) else ""
        if len(text) > 1024 or "\0" in text or "\n" in text:
            continue
        out.append(f"{name}={text}")
    return out


def _clean_ports(raw) -> tuple[dict, dict]:
    """`[{host, container, proto}]` → the two shapes the Engine API wants."""
    exposed: dict = {}
    bindings: dict = {}
    if not isinstance(raw, list):
        return exposed, bindings
    for entry in raw[:MAX_PORTS]:
        if not isinstance(entry, dict):
            continue
        try:
            container = int(entry.get("container"))
            host = int(entry.get("host"))
        except (TypeError, ValueError):
            continue
        if not (1 <= container <= 65535 and 0 <= host <= 65535):
            continue
        proto = entry.get("proto") if entry.get("proto") in ("tcp", "udp") else "tcp"
        key = f"{container}/{proto}"
        exposed[key] = {}
        address = entry.get("address")
        bind = {"HostPort": str(host)}
        if isinstance(address, str) and _is_plain_host(address):
            bind["HostIp"] = address
        bindings[key] = [bind]
    return exposed, bindings


def _is_plain_host(value: str) -> bool:
    return bool(value) and len(value) <= 45 and all(
        ch.isalnum() or ch in ".:-" for ch in value)


def _clean_mounts(raw) -> list[str]:
    """`[{host, container, ro}]` → the `Binds` list.

    A bind mount is how a container reaches the host filesystem, so both sides
    are absolute paths with no newline and nothing else — the string goes to the
    daemon as one field and a colon in the wrong place would change what is
    mounted where."""
    out: list[str] = []
    if not isinstance(raw, list):
        return out
    for entry in raw[:MAX_MOUNTS]:
        if not isinstance(entry, dict):
            continue
        source = entry.get("host")
        target = entry.get("container")
        if not isinstance(target, str) or not _PATH_RE.match(target) or ":" in target:
            continue
        if isinstance(source, str) and _PATH_RE.match(source) and ":" not in source:
            pass
        elif clean_id(source):
            source = clean_id(source)          # a named volume, not a path
        else:
            continue
        out.append(f"{source}:{target}" + (":ro" if entry.get("ro") is True else ""))
    return out


def container_spec(raw) -> dict:
    """A container an operator asked for, turned into an Engine API body.

    Built field by field from a validated shape, never passed through: handing
    the daemon a dictionary somebody else wrote would be handing them every
    field this does not know about, `Privileged` among them."""
    if not isinstance(raw, dict):
        raise DockerError("that is not a container")
    image = clean_image(raw.get("image"))
    if not image:
        raise DockerError("that image name is not usable")
    exposed, bindings = _clean_ports(raw.get("ports"))
    host_config = {
        "PortBindings": bindings,
        "Binds": _clean_mounts(raw.get("volumes")),
        "RestartPolicy": {"Name": raw.get("restart")
                          if raw.get("restart") in _RESTART else "unless-stopped"},
    }
    network = clean_id(raw.get("network"))
    if network:
        host_config["NetworkMode"] = network
    body = {
        "Image": image,
        "Env": _clean_env(raw.get("env")),
        "ExposedPorts": exposed,
        "HostConfig": host_config,
        "Labels": {"org.nmesh.deployed": "1"},
    }
    command = raw.get("command")
    if isinstance(command, str) and command.strip():
        if len(command) > 4096 or "\0" in command:
            raise DockerError("that command is not usable")
        # Split here rather than handing the daemon a shell: there is no shell
        # in a container by contract, and `sh -c` would be one we introduced.
        import shlex
        try:
            body["Cmd"] = shlex.split(command)[:64]
        except ValueError:
            raise DockerError("that command is not usable") from None
    return body


# ---------------------------------------------------------------------------
# The Engine API
# ---------------------------------------------------------------------------

def endpoint() -> tuple[str, str]:
    """Where the daemon is: ``("unix", path)`` or ``("tcp", "host:port")``.

    Honours ``DOCKER_HOST`` because that is where a machine already says this,
    and falls back to the socket every distribution ships."""
    raw = os.environ.get("DOCKER_HOST") or ""
    if raw.startswith("unix://"):
        return "unix", raw[7:] or DEFAULT_SOCKET
    if raw.startswith("tcp://") or raw.startswith("http://"):
        rest = raw.split("://", 1)[1].strip("/")
        return ("tcp", rest) if rest else ("unix", DEFAULT_SOCKET)
    return "unix", DEFAULT_SOCKET


def available() -> bool:
    kind, where = endpoint()
    if kind == "unix":
        return os.path.exists(where)
    return bool(where)


def compose_available() -> bool:
    return shutil.which("docker") is not None


async def _open() -> tuple:
    kind, where = endpoint()
    try:
        if kind == "unix":
            return await asyncio.open_unix_connection(where)
        host, _, port = where.partition(":")
        return await asyncio.open_connection(host, int(port or 2375))
    except PermissionError:
        # The socket is there and this account may not speak to it. That is one
        # missing group membership, and saying which is the difference between
        # an operator fixing it in a minute and an operator concluding the
        # machine has no docker.
        raise DockerError(
            "docker is running here, but this node's account cannot reach its "
            "socket — re-run install.sh --docker on that machine, or add its "
            "account to the docker group") from None
    except (OSError, ValueError) as exc:
        raise DockerError(f"no docker daemon here ({type(exc).__name__})") from None


async def _read_line(reader) -> bytes:
    line = await reader.readline()
    if len(line) > MAX_LINE:
        raise DockerError("the daemon answered something oversized")
    return line


async def _read_body(reader, headers: dict) -> bytes:
    """The body, however the daemon chose to frame it. Bounded either way."""
    out = bytearray()
    if headers.get("transfer-encoding", "").lower() == "chunked":
        while True:
            line = (await _read_line(reader)).strip()
            if not line:
                continue
            try:
                size = int(line.split(b";")[0], 16)
            except ValueError:
                raise DockerError("the daemon framed its answer badly") from None
            if size == 0:
                await _read_line(reader)                # the trailing blank line
                break
            if len(out) + size > MAX_RESPONSE:
                raise DockerError("that answer is too large to read")
            out += await reader.readexactly(size)
            await reader.readexactly(2)                 # CRLF after each chunk
        return bytes(out)
    length = headers.get("content-length")
    if length is not None:
        try:
            size = int(length)
        except ValueError:
            raise DockerError("the daemon framed its answer badly") from None
        if size > MAX_RESPONSE:
            raise DockerError("that answer is too large to read")
        return await reader.readexactly(size) if size else b""
    # No framing at all: read to EOF, still bounded.
    while len(out) < MAX_RESPONSE:
        chunk = await reader.read(65536)
        if not chunk:
            break
        out += chunk
    return bytes(out)


async def read_response(reader, timeout: float) -> tuple[int, dict, bytes]:
    """Status, headers and body off a stream. Shared with the Portainer client.

    Written rather than taken from `http.client`: that one is blocking, and a
    blocking read in the default executor is the hang recorded in
    ``Docs/Architecture/gotchas.md`` §2 — asyncio *joins* those threads at
    shutdown, so one stuck socket wedges the whole node on exit."""
    status_line = await asyncio.wait_for(_read_line(reader), timeout)
    parts = status_line.split()
    if len(parts) < 2 or not parts[0].startswith(b"HTTP/"):
        raise DockerError("that is not an HTTP answer")
    try:
        status = int(parts[1])
    except ValueError:
        raise DockerError("that answer had no status") from None
    headers: dict = {}
    while True:
        line = await asyncio.wait_for(_read_line(reader), timeout)
        if line in (b"\r\n", b"\n", b""):
            break
        name, _, value = line.decode("utf-8", "replace").partition(":")
        headers[name.strip().lower()] = value.strip()
    body = await asyncio.wait_for(_read_body(reader, headers), timeout)
    return status, headers, body


def build_request(method: str, target: str, host: str, payload: bytes,
                  extra: tuple = ()) -> bytes:
    """One HTTP/1.1 request, with the connection closed after it.

    `Connection: close` on purpose: a pooled connection to a daemon is a
    lifetime to manage and a socket to leak, for a saving nobody here needs."""
    lines = [f"{method} {target} HTTP/1.1", f"Host: {host}",
             "Connection: close", "Accept: application/json"]
    lines.extend(extra)
    if payload:
        lines.append("Content-Type: application/json")
    lines.append(f"Content-Length: {len(payload)}")
    return ("\r\n".join(lines) + "\r\n\r\n").encode("utf-8") + payload


async def call(method: str, path: str, body=None, *,
               timeout: float = CALL_TIMEOUT, raw: bool = False):
    """One Engine API call. Returns parsed JSON, or bytes when ``raw``.

    Raises :class:`DockerError` and nothing else: a caller of this is answering
    an operator over the mesh, and an unexpected exception there is a handler
    that stops handling."""
    payload = b"" if body is None else json.dumps(body).encode("utf-8")
    head = build_request(method, f"/{API_VERSION}{path}", "docker", payload)

    reader, writer = await _open()
    try:
        writer.write(head)
        await writer.drain()
        status, _headers, data = await read_response(reader, timeout)
    except DockerError:
        raise
    except asyncio.TimeoutError:
        raise DockerError("the docker daemon did not answer in time") from None
    except (OSError, asyncio.IncompleteReadError) as exc:
        raise DockerError(f"the docker daemon hung up ({type(exc).__name__})") from None
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except (OSError, asyncio.TimeoutError):
            pass

    if status >= 400:
        raise DockerError(_message(data, status))
    if raw:
        return data
    if not data:
        return None
    try:
        return json.loads(data)
    except ValueError:
        raise DockerError("the daemon answered something unreadable") from None


def _message(data: bytes, status: int) -> str:
    try:
        parsed = json.loads(data)
        if isinstance(parsed, dict) and isinstance(parsed.get("message"), str):
            return parsed["message"][:200]
    except ValueError:
        pass
    return f"docker refused that ({status})"


# ---------------------------------------------------------------------------
# What a console is shown
# ---------------------------------------------------------------------------
#
# Every shape below is *built*, never forwarded. A daemon's own JSON is deep,
# large, and full of fields nobody on the far side asked for — and one of those
# reply frames has a ceiling to fit inside.

def _short(value, limit: int = 200) -> str:
    return str(value)[:limit] if isinstance(value, (str, int, float)) else ""


def _labels(raw) -> dict:
    return raw if isinstance(raw, dict) else {}


def _container_row(entry: dict) -> dict:
    labels = _labels(entry.get("Labels"))
    names = entry.get("Names") if isinstance(entry.get("Names"), list) else []
    name = _short(names[0].lstrip("/")) if names and isinstance(names[0], str) else ""
    ports = []
    for port in (entry.get("Ports") or [])[:MAX_PORTS]:
        if not isinstance(port, dict):
            continue
        public, private = port.get("PublicPort"), port.get("PrivatePort")
        if public:
            ports.append(f"{public}→{private}/{_short(port.get('Type'), 8)}")
        elif private:
            ports.append(f"{private}/{_short(port.get('Type'), 8)}")
    return {
        "id": _short(entry.get("Id"), 64),
        "name": name,
        "image": _short(entry.get("Image"), 256),
        "state": _short(entry.get("State"), 32),
        "status": _short(entry.get("Status"), 96),
        "created": entry.get("Created") if isinstance(entry.get("Created"), int) else 0,
        "ports": ports[:8],
        "project": _short(labels.get(LABEL_PROJECT), 64),
        "service": _short(labels.get(LABEL_SERVICE), 64),
        "portainer": _short(labels.get(LABEL_PORTAINER), 64),
    }


async def containers(all_of_them: bool = True) -> list[dict]:
    raw = await call("GET", "/containers/json?all=" + ("1" if all_of_them else "0"))
    if not isinstance(raw, list):
        return []
    return [_container_row(entry) for entry in raw[:MAX_CONTAINERS]
            if isinstance(entry, dict)]


async def images() -> list[dict]:
    raw = await call("GET", "/images/json")
    out = []
    for entry in (raw if isinstance(raw, list) else [])[:MAX_IMAGES]:
        if not isinstance(entry, dict):
            continue
        tags = [tag for tag in (entry.get("RepoTags") or [])
                if isinstance(tag, str)][:8]
        out.append({
            "id": _short(entry.get("Id"), 80),
            "tags": tags,
            "size": entry.get("Size") if isinstance(entry.get("Size"), int) else 0,
            "created": entry.get("Created") if isinstance(entry.get("Created"), int) else 0,
        })
    return out


async def overview() -> dict:
    """What this machine's docker *is*, in the few numbers worth a card."""
    version = await call("GET", "/version")
    info = await call("GET", "/info")
    version = version if isinstance(version, dict) else {}
    info = info if isinstance(info, dict) else {}
    return {
        "version": _short(version.get("Version"), 32),
        "api": _short(version.get("ApiVersion"), 16),
        "os": _short(info.get("OperatingSystem"), 96),
        "containers": info.get("Containers") if isinstance(info.get("Containers"), int) else 0,
        "running": info.get("ContainersRunning") if isinstance(info.get("ContainersRunning"), int) else 0,
        "images": info.get("Images") if isinstance(info.get("Images"), int) else 0,
        "compose": compose_available(),
    }


async def inspect(container: str) -> dict:
    ident = clean_id(container)
    if not ident:
        raise DockerError("that is not a container")
    raw = await call("GET", f"/containers/{ident}/json")
    raw = raw if isinstance(raw, dict) else {}
    config = raw.get("Config") if isinstance(raw.get("Config"), dict) else {}
    state = raw.get("State") if isinstance(raw.get("State"), dict) else {}
    host = raw.get("HostConfig") if isinstance(raw.get("HostConfig"), dict) else {}
    labels = _labels(config.get("Labels"))
    restart = host.get("RestartPolicy") if isinstance(host.get("RestartPolicy"), dict) else {}
    return {
        "id": _short(raw.get("Id"), 64),
        "name": _short(raw.get("Name"), 128).lstrip("/"),
        "image": _short(config.get("Image"), 256),
        "state": _short(state.get("Status"), 32),
        "started": _short(state.get("StartedAt"), 40),
        "exit_code": state.get("ExitCode") if isinstance(state.get("ExitCode"), int) else 0,
        "restart": _short(restart.get("Name"), 32),
        "project": _short(labels.get(LABEL_PROJECT), 64),
        "service": _short(labels.get(LABEL_SERVICE), 64),
        # The environment of a container routinely holds its secrets, so only
        # the names travel. Somebody who needs a value has a shell.
        "env_names": sorted({
            entry.split("=", 1)[0][:64] for entry in (config.get("Env") or [])
            if isinstance(entry, str) and "=" in entry})[:64],
        "mounts": [f"{_short(m.get('Source'), 256)}:{_short(m.get('Destination'), 256)}"
                   for m in (raw.get("Mounts") or [])[:MAX_MOUNTS]
                   if isinstance(m, dict)],
    }


# The log stream is multiplexed when the container has no tty: an 8-byte header
# per frame, and printing it raw puts control bytes on a screen.
def demultiplex(raw: bytes) -> str:
    if not raw:
        return ""
    if raw[0] not in (0, 1, 2) or len(raw) < 8:
        return raw.decode("utf-8", "replace")
    out, offset = [], 0
    while offset + 8 <= len(raw):
        size = int.from_bytes(raw[offset + 4:offset + 8], "big")
        offset += 8
        if size < 0 or size > len(raw):
            break
        out.append(raw[offset:offset + size])
        offset += size
    return b"".join(out).decode("utf-8", "replace")


async def logs(container: str, tail: int = 200) -> str:
    ident = clean_id(container)
    if not ident:
        raise DockerError("that is not a container")
    try:
        lines = max(1, min(int(tail), MAX_LOG_TAIL))
    except (TypeError, ValueError):
        lines = 200
    raw = await call(
        "GET",
        f"/containers/{ident}/logs?stdout=1&stderr=1&timestamps=0&tail={lines}",
        raw=True)
    text = demultiplex(raw if isinstance(raw, bytes) else b"")
    return text[-MAX_LOG_BYTES:]


_ACTIONS = {
    "start": ("POST", "/containers/%s/start"),
    "stop": ("POST", "/containers/%s/stop?t=10"),
    "restart": ("POST", "/containers/%s/restart?t=10"),
    "kill": ("POST", "/containers/%s/kill"),
    "pause": ("POST", "/containers/%s/pause"),
    "unpause": ("POST", "/containers/%s/unpause"),
    "remove": ("DELETE", "/containers/%s?force=1"),
}


async def act(container: str, action: str) -> dict:
    ident = clean_id(container)
    if not ident:
        raise DockerError("that is not a container")
    route = _ACTIONS.get(action)
    if route is None:
        raise DockerError("that is not something to do to a container")
    method, path = route
    await call(method, path % ident, timeout=90.0)
    return {"container": ident, "action": action}


async def pull(image: str) -> dict:
    """Fetch an image. Minutes long, and the answer is a stream of progress."""
    reference = clean_image(image)
    if not reference:
        raise DockerError("that image name is not usable")
    name, _, tag = reference.rpartition(":")
    if not name or "/" in tag:
        name, tag = reference, "latest"
    from urllib.parse import quote
    raw = await call(
        "POST",
        f"/images/create?fromImage={quote(name, safe='')}&tag={quote(tag, safe='')}",
        body=None, timeout=PULL_TIMEOUT, raw=True)
    text = (raw or b"").decode("utf-8", "replace")
    # Docker reports a failed pull inside a 200 body, one JSON object per line.
    for line in reversed(text.strip().splitlines()[-20:]):
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        if isinstance(entry, dict) and entry.get("error"):
            raise DockerError(_short(entry["error"], 200))
    return {"image": f"{name}:{tag}"}


async def create(spec: dict) -> dict:
    """Create a container from a validated spec and start it."""
    body = container_spec(spec)
    name = clean_id(spec.get("name")) if isinstance(spec, dict) else ""
    # A missing image is the common failure and it is worth one round trip to
    # fix rather than a refusal an operator has to decode.
    route = "/containers/create" + (f"?name={name}" if name else "")
    try:
        answer = await call("POST", route, body=body, timeout=90.0)
    except DockerError as exc:
        if "No such image" not in str(exc):
            raise
        await pull(body["Image"])
        answer = await call("POST", route, body=body, timeout=90.0)
    ident = _short(answer.get("Id"), 64) if isinstance(answer, dict) else ""
    if not ident:
        raise DockerError("docker created it and did not say what it was called")
    await call("POST", f"/containers/{ident}/start", timeout=90.0)
    return {"container": ident, "name": name, "image": body["Image"]}


# ---------------------------------------------------------------------------
# Stacks
# ---------------------------------------------------------------------------
#
# A stack is a compose project, and a compose project is recoverable from a
# running machine because compose labels everything it creates. No database, no
# second source of truth — what is running *is* the list. Portainer deploys
# through compose too, so its stacks appear here with no special case; what
# tells them apart is the label it adds, and that decides who is allowed to
# update them.

def group_stacks(rows: list[dict]) -> list[dict]:
    """Containers → the projects they belong to."""
    projects: dict = {}
    for row in rows:
        name = row.get("project") or ""
        if not name:
            continue
        stack = projects.setdefault(name, {
            "name": name, "services": [], "running": 0, "total": 0,
            "portainer": row.get("portainer") or "",
        })
        if len(stack["services"]) < 64:
            stack["services"].append({
                "service": row.get("service") or row.get("name"),
                "container": row["id"], "state": row.get("state"),
                "image": row.get("image"),
            })
        stack["total"] += 1
        if row.get("state") == "running":
            stack["running"] += 1
        if row.get("portainer"):
            stack["portainer"] = row["portainer"]
    ordered = sorted(projects.values(), key=lambda entry: entry["name"])
    return ordered[:MAX_STACKS]


async def stacks() -> list[dict]:
    rows = await containers(True)
    found = group_stacks(rows)
    # Where the compose file lives, so an update can re-run it. Read from the
    # labels of one container per project rather than guessed.
    config: dict = {}
    raw = await call("GET", "/containers/json?all=1")
    for entry in (raw if isinstance(raw, list) else [])[:MAX_CONTAINERS]:
        labels = _labels(entry.get("Labels")) if isinstance(entry, dict) else {}
        project = _short(labels.get(LABEL_PROJECT), 64)
        if project and project not in config:
            config[project] = {
                "files": _short(labels.get(LABEL_CONFIG), 1024),
                "workdir": _short(labels.get(LABEL_WORKDIR), 512),
            }
    for stack in found:
        stack.update(config.get(stack["name"], {"files": "", "workdir": ""}))
    return found


def compose_files(files: str) -> list[str]:
    """The compose files a project was deployed from, as compose wrote them.

    The label is a comma-separated list of absolute paths. Anything that is not
    one is dropped rather than passed to an argv — the label is written by the
    daemon, but a daemon is a machine and this runs as root."""
    out = []
    for path in (files or "").split(","):
        path = path.strip()
        if _PATH_RE.match(path) and len(out) < 8:
            out.append(path)
    return out


async def _run(argv: list[str], *, cwd: str | None = None,
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
        raise DockerError(f"could not run docker ({type(exc).__name__})") from None
    collected: list[str] = []
    size = 0

    async def drain() -> None:
        nonlocal size
        while True:
            line = await proc.stdout.readline()
            if not line:
                return
            text = line.decode("utf-8", "replace").rstrip("\n")
            if size < MAX_LOG_BYTES:
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
    return proc.returncode or 0, "\n".join(collected)[-MAX_LOG_BYTES:]


def _compose_argv(project: str, files: list[str], *rest: str) -> list[str]:
    argv = ["docker", "compose", "--project-name", project]
    for path in files:
        argv += ["-f", path]
    return argv + list(rest)


async def stack_up(project: str, files: list[str], workdir: str = "",
                   *, pull_first: bool = True, on_output=None) -> dict:
    """Bring a compose project up to date: pull, then re-run its compose file.

    Pulling under a project and restarting it is *not* this act and quietly does
    less — a container keeps running the image it was created from until it is
    recreated. So `up -d` is the operation, and it is the compose file that
    decides what "up to date" means."""
    name = clean_id(project)
    if not name:
        raise DockerError("that is not a stack")
    if not compose_available():
        raise DockerError("this machine has no docker compose")
    if not files:
        raise DockerError("that stack has no compose file on this machine")
    cwd = workdir if _PATH_RE.match(workdir or "") and os.path.isdir(workdir or "") else None
    if pull_first:
        code, text = await _run(_compose_argv(name, files, "pull"),
                                cwd=cwd, on_output=on_output)
        if code != 0:
            raise DockerError(f"pulling that stack failed: {text[-200:]}")
    code, text = await _run(_compose_argv(name, files, "up", "-d", "--remove-orphans"),
                            cwd=cwd, on_output=on_output)
    if code != 0:
        raise DockerError(f"bringing that stack up failed: {text[-200:]}")
    return {"stack": name, "output": text[-4000:]}


async def stack_act(project: str, files: list[str], action: str,
                    workdir: str = "", *, on_output=None) -> dict:
    """start / stop / restart / down, through compose when it is there.

    Without compose the same three are still possible container by container —
    it is `down` and `up` that need the file, because they create and destroy.
    """
    name = clean_id(project)
    if not name:
        raise DockerError("that is not a stack")
    if action not in ("start", "stop", "restart", "down"):
        raise DockerError("that is not something to do to a stack")
    if compose_available() and files:
        cwd = workdir if _PATH_RE.match(workdir or "") and os.path.isdir(workdir or "") else None
        code, text = await _run(_compose_argv(name, files, action),
                                cwd=cwd, timeout=COMPOSE_TIMEOUT, on_output=on_output)
        if code != 0:
            raise DockerError(f"that stack refused to {action}: {text[-200:]}")
        return {"stack": name, "action": action, "output": text[-4000:]}
    if action == "down":
        raise DockerError("taking a stack down needs its compose file")
    rows = [row for row in await containers(True) if row.get("project") == name]
    if not rows:
        raise DockerError("no container on this machine belongs to that stack")
    for row in rows:
        await act(row["id"], action)
    return {"stack": name, "action": action, "containers": len(rows)}


async def deploy_stack(project: str, content: str, *, root: str = "",
                       on_output=None) -> dict:
    """Deploy a stack from a compose file an operator wrote.

    The file is written under a directory of this node's own, named for the
    project, so a redeploy later finds it exactly where compose recorded it —
    and so nothing this deploys can be made to overwrite a path chosen by
    whoever sent the file: the only thing from the wire that reaches the path is
    a name that passed :func:`clean_id`."""
    name = clean_id(project)
    if not name:
        raise DockerError("that is not a stack name")
    body = clean_compose(content)
    if not body:
        raise DockerError("that compose file is empty or too large")
    if not compose_available():
        raise DockerError("this machine has no docker compose")
    directory = os.path.join(stack_dir(root), name)
    os.makedirs(directory, mode=0o700, exist_ok=True)
    path = os.path.join(directory, "docker-compose.yml")
    tmp = path + ".new"
    with open(tmp, "w", encoding="utf-8") as handle:
        os.chmod(tmp, 0o600)
        handle.write(body)
    os.replace(tmp, path)
    return await stack_up(name, [path], directory, on_output=on_output)


def stack_dir(root: str = "") -> str:
    """Where compose files this node deployed are kept.

    Under the node's own data directory when it has one — the same place its
    identity and its session store live, so a compose file that decides what
    runs on this machine is backed up and wiped with the rest of its state.
    Never `/tmp`, and never a path from the wire."""
    base = root or os.path.expanduser("~/.nmesh")
    return os.path.join(base, "stacks")
