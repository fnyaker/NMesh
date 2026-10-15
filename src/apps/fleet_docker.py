"""
Docker's Engine API, spoken over the machine's own socket.

Everything that reads or moves a container goes through here: listing,
inspecting, logs, start/stop, pulling an image, creating a container, reading a
file out of one. No CLI, no shell, no quoting surface. The stacks built on top
of these containers — compose projects, Portainer's among them — are
`fleet_stacks`'s; this module knows containers and images, and nothing about
who deployed them.

**The socket is root.** A process that can talk to `/var/run/docker.sock` can
start a privileged container bind-mounting `/`, which is the machine. That is
why this is a capability of its own, why its description says so in those words,
and why nothing here is reachable without it. The gate is the fleet app's; this
module holds no authorisation of its own and must never be handed input that has
not been through one.

Everything arriving from an operator is hostile input: names, ids, image
references, compose files. Each one is validated against a charset and a bound
*before* it reaches a socket, and a value that does not validate is refused
rather than escaped — there is no escaping here to get wrong. What the daemon
answers is hostile input too, for the same reason a peer's is: every shape
handed on is built field by field and bounded.
"""
from __future__ import annotations

import asyncio
import base64
import io
import json
import os
import re
import tarfile
from urllib.parse import quote

# -- bounds -----------------------------------------------------------------
# Every one of these bounds something an operator, or the daemon, can grow.
DEFAULT_SOCKET = "/var/run/docker.sock"
API_VERSION = "1.41"              # old enough for every engine still supported
CALL_TIMEOUT = 30.0               # one Engine API call
PULL_TIMEOUT = 900.0              # an image pull is minutes, not seconds
COMPOSE_TIMEOUT = 1800.0          # `compose up` builds and pulls
MAX_RESPONSE = 4 * 1024 * 1024    # bytes read from one API answer
MAX_LINE = 64 * 1024              # one header or chunk-size line
MAX_CONTAINERS = 250
MAX_IMAGES = 250
MAX_VOLUMES = 250
MAX_NETWORKS = 100
MAX_STATS = 40                    # containers sampled at once; each sample takes ~1 s
MAX_LOG_TAIL = 2000               # lines
# What a reply may carry back. Sized to fit one frame *after* JSON escaping:
# `_dump_json` drops whole list entries to make a reply fit, and a string is not
# a list — a log too long to trim is a reply nobody receives at all.
MAX_LOG_BYTES = 32_000
MAX_COMPOSE = 40_000              # a compose file, so one reply frame still fits
MAX_ARCHIVE = 2 * 1024 * 1024     # a directory read out of a container
MAX_ARCHIVE_MEMBERS = 64
MAX_ENV = 64                      # variables on a container we create
MAX_PORTS = 32
MAX_MOUNTS = 32

# Labels compose writes on everything it creates. Read here only to say which
# project a container belongs to; what a project *is* is `fleet_stacks`'s.
LABEL_PROJECT = "com.docker.compose.project"
LABEL_SERVICE = "com.docker.compose.service"

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


# The API version spoken, raised once if the daemon says ours is too old. An
# engine drops old versions over time; asking `/version` first would be a round
# trip on every call for an answer that changes once a machine's lifetime.
_api = {"version": API_VERSION}
_TOO_OLD = re.compile(r"[Mm]inimum supported API version is (\d{1,2}\.\d{1,3})")


async def call(method: str, path: str, body=None, *,
               timeout: float = CALL_TIMEOUT, raw: bool = False,
               headers: tuple = ()):
    """One Engine API call. Returns parsed JSON, or bytes when ``raw``.

    Raises :class:`DockerError` and nothing else: a caller of this is answering
    an operator over the mesh, and an unexpected exception there is a handler
    that stops handling."""
    payload = b"" if body is None else json.dumps(body).encode("utf-8")
    for _attempt in range(2):
        status, data = await _exchange(method, path, payload, timeout, headers)
        if status == 400:
            wanted = _TOO_OLD.search(data[:400].decode("utf-8", "replace"))
            if wanted and wanted.group(1) != _api["version"]:
                _api["version"] = wanted.group(1)
                continue
        break
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


async def _exchange(method: str, path: str, payload: bytes, timeout: float,
                    headers: tuple) -> tuple[int, bytes]:
    head = build_request(method, f"/v{_api['version']}{path}", "docker", payload,
                         extra=headers)
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
    return status, data


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
        "image_id": _short(entry.get("ImageID"), 80),
        "project": _short(labels.get(LABEL_PROJECT), 64),
        "service": _short(labels.get(LABEL_SERVICE), 64),
    }


async def raw_containers(all_of_them: bool = True) -> list[dict]:
    """The daemon's own list, bounded, for a caller that reads the labels."""
    raw = await call("GET", "/containers/json?all=" + ("1" if all_of_them else "0"))
    return [entry for entry in (raw if isinstance(raw, list) else [])[:MAX_CONTAINERS]
            if isinstance(entry, dict)]


async def containers(all_of_them: bool = True) -> list[dict]:
    return [_container_row(entry) for entry in await raw_containers(all_of_them)]


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


def _number(value) -> float:
    return float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else 0.0


def sample(raw) -> dict:
    """CPU share and memory of one container from an Engine stats document.

    The daemon reports counters, not rates: the share is the container's CPU
    time over the machine's between the two readings the document carries."""
    raw = raw if isinstance(raw, dict) else {}
    cpu = raw.get("cpu_stats") if isinstance(raw.get("cpu_stats"), dict) else {}
    before = raw.get("precpu_stats") if isinstance(raw.get("precpu_stats"), dict) else {}

    def total(block: dict) -> float:
        usage = block.get("cpu_usage") if isinstance(block.get("cpu_usage"), dict) else {}
        return _number(usage.get("total_usage"))

    used = total(cpu) - total(before)
    system = _number(cpu.get("system_cpu_usage")) - _number(before.get("system_cpu_usage"))
    cores = int(_number(cpu.get("online_cpus"))) or 1
    percent = used / system * cores * 100.0 if used > 0 and system > 0 else 0.0
    memory = raw.get("memory_stats") if isinstance(raw.get("memory_stats"), dict) else {}
    detail = memory.get("stats") if isinstance(memory.get("stats"), dict) else {}
    # What the kernel can take back is not what the container holds on to.
    held = _number(memory.get("usage")) - _number(detail.get("inactive_file", detail.get("cache")))
    return {"cpu": round(min(max(percent, 0.0), 100.0 * cores), 1),
            "memory": int(max(held, 0.0)), "limit": int(_number(memory.get("limit")))}


async def stats() -> dict:
    """A sample for each running container, taken side by side."""
    rows = [row for row in await containers(False) if row["state"] == "running"]
    rows = rows[:MAX_STATS]

    async def one(row: dict):
        try:
            raw = await call("GET", f"/containers/{clean_id(row['id'])}/stats?stream=false",
                             timeout=10.0)
        except DockerError:
            return row["id"], None
        return row["id"], sample(raw)

    found = await asyncio.gather(*(one(row) for row in rows))
    return {ident: value for ident, value in found if value is not None}


async def volumes() -> list[dict]:
    raw = await call("GET", "/volumes")
    listed = raw.get("Volumes") if isinstance(raw, dict) else None
    return [{"name": _short(entry.get("Name"), 128), "driver": _short(entry.get("Driver"), 32),
             "mount": _short(entry.get("Mountpoint"), 256),
             "created": _short(entry.get("CreatedAt"), 40)}
            for entry in (listed if isinstance(listed, list) else [])[:MAX_VOLUMES]
            if isinstance(entry, dict)]


async def networks() -> list[dict]:
    raw = await call("GET", "/networks")
    out = []
    for entry in (raw if isinstance(raw, list) else [])[:MAX_NETWORKS]:
        if not isinstance(entry, dict):
            continue
        config = (entry.get("IPAM") or {}).get("Config") if isinstance(entry.get("IPAM"), dict) else None
        subnet = next((_short(c.get("Subnet"), 64) for c in (config if isinstance(config, list) else [])
                       if isinstance(c, dict) and c.get("Subnet")), "")
        containers_in = entry.get("Containers")
        out.append({"id": _short(entry.get("Id"), 64), "name": _short(entry.get("Name"), 128),
                    "driver": _short(entry.get("Driver"), 32), "scope": _short(entry.get("Scope"), 16),
                    "subnet": subnet,
                    "attached": len(containers_in) if isinstance(containers_in, dict) else 0})
    return out


async def remove_image(image: str) -> dict:
    ident = clean_image(image)
    if not ident or ".." in ident:          # it becomes part of a request path
        raise DockerError("that is not an image")
    await call("DELETE", f"/images/{ident}", timeout=60.0)
    return {"image": ident}


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


def split_reference(reference: str) -> tuple[str, str, str]:
    """``registry/owner/name:tag@digest`` → (repository, tag, digest).

    The tag is the last colon *after* the last slash: a registry's port is a
    colon too, and ``127.0.0.1:5000/app`` has no tag at all."""
    reference, _, digest = reference.partition("@")
    slash = reference.rfind("/")
    colon = reference.rfind(":")
    if colon > slash:
        return reference[:colon], reference[colon + 1:], digest
    return reference, "", digest


def registry_of(reference: str) -> str:
    """The registry a reference names, as `docker login` keys it."""
    first, sep, _rest = reference.partition("/")
    if sep and ("." in first or ":" in first or first == "localhost"):
        return first
    return "docker.io"


def _auth_header(reference: str) -> tuple:
    """`X-Registry-Auth` for a private registry, from this account's own
    `docker login`.

    Read from the node's account and nowhere else, never sent anywhere but the
    local daemon, and never part of an answer. A credential helper keeps its
    secrets out of the file, so a registry logged into through one is pulled
    anonymously here — and says so in the daemon's refusal."""
    folder = os.environ.get("DOCKER_CONFIG") or os.path.expanduser("~/.docker")
    try:
        with open(os.path.join(folder, "config.json"), "rb") as handle:
            config = json.loads(handle.read(64 * 1024))
    except (OSError, ValueError):
        return ()
    auths = config.get("auths") if isinstance(config, dict) else None
    if not isinstance(auths, dict):
        return ()
    registry = registry_of(reference)
    keys = ("https://index.docker.io/v1/", "docker.io", "index.docker.io") \
        if registry == "docker.io" else (registry, "https://" + registry)
    for key in keys:
        entry = auths.get(key)
        token = entry.get("auth") if isinstance(entry, dict) else None
        if not isinstance(token, str):
            continue
        try:
            user, _, secret = base64.b64decode(token, validate=True).decode().partition(":")
        except (ValueError, UnicodeDecodeError):
            return ()
        blob = json.dumps({"username": user, "password": secret,
                           "serveraddress": key}).encode()
        return ("X-Registry-Auth: " + base64.urlsafe_b64encode(blob).decode(),)
    return ()


async def pull(image: str) -> dict:
    """Fetch an image. Minutes long, and the answer is a stream of progress."""
    reference = clean_image(image)
    if not reference or ".." in reference:
        raise DockerError("that image name is not usable")
    repository, tag, digest = split_reference(reference)
    if digest:
        query = f"fromImage={quote(repository + '@' + digest, safe='')}"
        named = f"{repository}@{digest}"
    else:
        tag = tag or "latest"
        query = f"fromImage={quote(repository, safe='')}&tag={quote(tag, safe='')}"
        named = f"{repository}:{tag}"
    raw = await call("POST", f"/images/create?{query}", body=None,
                     timeout=PULL_TIMEOUT, raw=True, headers=_auth_header(reference))
    text = (raw or b"").decode("utf-8", "replace")
    # Docker reports a failed pull inside a 200 body, one JSON object per line.
    for line in reversed(text.strip().splitlines()[-20:]):
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        if isinstance(entry, dict) and entry.get("error"):
            raise DockerError(_short(entry["error"], 200))
    return {"image": named}


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
# Reads that stay on this machine
# ---------------------------------------------------------------------------
#
# What `fleet_stacks` needs to recreate a container or find a stack's file. The
# raw documents below are the daemon's own and never leave this node whole —
# a container's configuration routinely carries its secrets.

async def container_raw(container: str) -> dict:
    ident = clean_id(container)
    if not ident:
        raise DockerError("that is not a container")
    raw = await call("GET", f"/containers/{ident}/json")
    if not isinstance(raw, dict):
        raise DockerError("the daemon described that container in no usable way")
    return raw


async def image_raw(reference: str) -> dict | None:
    """An image's own document, or None when this machine does not hold it."""
    ident = clean_image(reference)
    if not ident or ".." in ident:
        raise DockerError("that is not an image")
    try:
        raw = await call("GET", f"/images/{ident}/json")
    except DockerError as exc:
        if "No such image" in str(exc) or "not found" in str(exc).lower():
            return None
        raise
    return raw if isinstance(raw, dict) else None


async def remote_digest(reference: str) -> str:
    """What the registry serves under that reference right now, asked through
    the daemon — which holds the network path and the registry's trust, and
    reads only the manifest: nothing is downloaded."""
    ident = clean_image(reference)
    if not ident or ".." in ident:
        raise DockerError("that is not an image")
    raw = await call("GET", f"/distribution/{ident}/json", timeout=20.0,
                     headers=_auth_header(ident))
    descriptor = raw.get("Descriptor") if isinstance(raw, dict) else None
    digest = descriptor.get("digest") if isinstance(descriptor, dict) else None
    if not isinstance(digest, str) or not re.match(r"\Asha256:[0-9a-f]{64}\Z", digest):
        raise DockerError("the registry answered no digest")
    return digest


async def read_archive(container: str, path: str) -> dict[str, bytes]:
    """The regular files under a path inside a container, by name relative to
    the directory read.

    Through the daemon's archive route, because the files a container keeps in
    its volumes are root's on the host and this node's account is not. Bounded
    in bytes and in members; a link, a device or a name that climbs is skipped,
    never followed — nothing here is written to disk."""
    ident = clean_id(container)
    if not ident or not isinstance(path, str) or not path.startswith("/") \
            or ".." in path or len(path) > 512 or "\0" in path:
        raise DockerError("that is not something to read")
    raw = await call("GET", f"/containers/{ident}/archive?path={quote(path, safe='/')}",
                     raw=True)
    if len(raw) > MAX_ARCHIVE:
        raise DockerError("that directory is too large to read")
    out: dict[str, bytes] = {}
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
            for index, member in enumerate(archive):
                if index >= MAX_ARCHIVE_MEMBERS:
                    break
                if not member.isreg() or member.size > MAX_ARCHIVE:
                    continue
                parts = member.name.split("/")
                if member.name.startswith("/") or ".." in parts:
                    continue
                handle = archive.extractfile(member)
                if handle is not None:
                    out["/".join(parts[1:])] = handle.read(MAX_ARCHIVE)
    except (tarfile.TarError, EOFError, OSError):
        raise DockerError("the daemon sent an archive that does not read") from None
    return out
