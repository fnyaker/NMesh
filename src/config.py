"""
The node's configuration file: everything the launcher takes as an option.

Why a file at all: a node installed as a service is started by a unit nobody
wants to edit, and its options are then invisible and unchangeable from the
console. The file is the single place those options live; the launcher reads it,
the console edits it.

Precedence is **command line > file > default**. An explicit flag always wins,
so an existing unit that passes arguments keeps behaving exactly as before.

The file is parsed defensively, like anything else that reaches this process
from outside it: bounded in size and in line count, unknown keys reported and
ignored rather than fatal, every value validated against its own rules, and a
malformed line never able to stop a node from starting. A configuration file
that cannot be understood is reported and skipped — a node that will not boot is
a worse outcome than one running on its defaults.

The console password is deliberately **not** a setting here: it would put a
credential in cleartext in a file whose whole purpose is to be edited and read.
It stays in the environment or is generated (see ``scripts/nmesh_node.py``).
"""
from __future__ import annotations

import os
import re

FILENAME = "nmesh.conf"

# A configuration file is a handful of short lines. These bounds exist so a
# corrupted or hostile file costs a bounded amount of memory and time.
MAX_BYTES = 64 * 1024
MAX_LINES = 500
MAX_VALUE = 1024
MAX_LIST = 32

# `\Z`, not `$`: `$` also matches just before a trailing newline, which would
# let a value carry one into the file and split into a second line on re-read.
_HOST_RE = re.compile(r"\A[A-Za-z0-9._:\[\]-]{1,255}\Z")
_SCHEME_KEY = re.compile(r"\A[a-z0-9_]{1,32}\Z")
_ADDR_RE = re.compile(r"\A[A-Za-z0-9._:\[\]-]{1,255}:\d{1,5}\Z")


class ConfigError(Exception):
    """A value that cannot be used, phrased for whoever typed it."""


def _as_bool(raw: str) -> bool:
    lowered = raw.strip().lower()
    if lowered in ("1", "true", "yes", "on"):
        return True
    if lowered in ("0", "false", "no", "off"):
        return False
    raise ConfigError("expected true or false")


def _as_port(raw: str) -> int:
    try:
        port = int(raw.strip())
    except ValueError:
        raise ConfigError("expected a port number") from None
    if not 1 <= port <= 65535:
        raise ConfigError("port must be between 1 and 65535")
    return port


def _as_optional_port(raw: str):
    if not raw.strip():
        return None
    return _as_port(raw)


def _as_listen(raw: str) -> str:
    # "tcp://host:port" is how every other address in the project is written, so
    # it gets typed here too; the launcher accepts both and so do we.
    value = raw.strip()
    if value.startswith("tcp://"):
        value = value[len("tcp://"):]
    if not _ADDR_RE.match(value):
        raise ConfigError("expected host:port")
    if not 1 <= int(value.rsplit(":", 1)[1]) <= 65535:
        raise ConfigError("port must be between 1 and 65535")
    return value


def _as_host(raw: str) -> str:
    value = raw.strip()
    if not _HOST_RE.match(value):
        raise ConfigError("not a valid host name or address")
    return value


def _as_path(raw: str):
    value = raw.strip()
    if not value:
        return None
    if "\0" in value or len(value) > MAX_VALUE:
        raise ConfigError("not a usable path")
    return value


# name -> (parser, default, whether the console may write it, one-line help)
#
# `launch` runs a command. It is readable from the console but never writable
# there: turning an authenticated web form into a way to choose what the node
# executes is a bigger step than editing settings, and it belongs to whoever has
# the file. The console shows it so nobody is surprised by what is running.
SETTINGS = {
    "listen":          (_as_listen, "0.0.0.0:9000", True,
                        "TCP address the node listens on (host:port)"),
    "udp":             (_as_port, 9001, True,
                        "UDP port used for NAT hole punching"),
    "no_udp":          (_as_bool, False, True,
                        "Disable the UDP listener entirely"),
    # On by default because that is what every node started by start.sh has
    # always done (it used to prepend `--stun` itself). Keeping the behaviour
    # and making it visible beats a file that quietly disagrees with reality.
    "stun":            (_as_bool, True, True,
                        "Discover the public UDP address through STUN"),
    "punch_keepalive": (_as_bool, False, True,
                        "Keep the NAT mapping open so the node stays reachable"),
    "lan_discovery":   (_as_bool, False, True,
                        "Answer LAN relay-discovery beacons"),
    "spool":           (_as_path, None, True,
                        "Directory used as a store-and-forward link"),
    "console_host":    (_as_host, "127.0.0.1", True,
                        "Address the web console binds to"),
    "console_port":    (_as_port, 8787, True, "Web console port"),
    "connector_port":  (_as_optional_port, None, True,
                        "Loopback port exposing the data connector to apps"),
    "no_chat":         (_as_bool, False, True, "Disable the built-in chat app"),
    "fleet":           (_as_bool, False, True,
                        "Enable the fleet app (remote management, can open a shell)"),
    "no_tls":          (_as_bool, False, True,
                        "Serve the console over plain HTTP (loopback only)"),
    "data":            (_as_path, None, False,
                        "State directory — set by the installer, not from here"),
    "launch":          (None, [], False,
                        "Commands launched and wired to the mesh (file only)"),
}

# Keys the launcher takes on the command line, spelled as CLI flags.
CLI_NAMES = {name: "--" + name.replace("_", "-") for name in SETTINGS}


def defaults() -> dict:
    """The configuration of a node with no file and no flags."""
    return {name: (list(spec[1]) if isinstance(spec[1], list) else spec[1])
            for name, spec in SETTINGS.items()}


def path_for(install_root: str, override=None) -> str:
    """Where the file lives: next to the installed tree unless told otherwise."""
    if override:
        return override
    env = os.environ.get("NMESH_CONFIG")
    if env:
        return env
    return os.path.join(install_root, FILENAME)


def parse(text: str) -> tuple[dict, list]:
    """``(values, problems)`` — never raises on bad input.

    Only the keys actually present are returned, so a caller can tell "not set"
    from "set to the default" and apply its own precedence."""
    values: dict = {}
    problems: list = []
    if len(text) > MAX_BYTES:
        return {}, [f"configuration file larger than {MAX_BYTES} bytes — ignored"]
    for number, line in enumerate(text.splitlines(), start=1):
        if number > MAX_LINES:
            problems.append(f"more than {MAX_LINES} lines — the rest is ignored")
            break
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "=" not in stripped:
            problems.append(f"line {number}: no '=' — ignored")
            continue
        key, _, raw = stripped.partition("=")
        key = key.strip().lower().replace("-", "_")
        raw = raw.strip()
        if len(raw) > MAX_VALUE:
            problems.append(f"line {number}: value too long — ignored")
            continue
        if "." in key:
            # `<scheme>.<option>`: a transport setting. Carried through as text
            # and validated by the transport itself — this file has no business
            # knowing what a medium takes, and a new transport must not require
            # a change here.
            scheme, _, field = key.partition(".")
            if not _SCHEME_KEY.match(scheme) or not _SCHEME_KEY.match(field):
                problems.append(f"line {number}: unusable transport key "
                                f"'{key[:40]}' — ignored")
                continue
            table = values.setdefault("transports", {})
            if len(table) >= MAX_LIST and scheme not in table:
                problems.append(f"line {number}: too many transports — ignored")
                continue
            fields = table.setdefault(scheme, {})
            if len(fields) >= MAX_LIST and field not in fields:
                problems.append(f"line {number}: too many settings for "
                                f"'{scheme}' — ignored")
                continue
            fields[field] = raw
            continue
        if key not in SETTINGS:
            problems.append(f"line {number}: unknown setting '{key[:40]}' — ignored")
            continue
        if key == "launch":
            entries = values.setdefault("launch", [])
            if len(entries) >= MAX_LIST:
                problems.append(f"line {number}: more than {MAX_LIST} launch "
                                "commands — ignored")
                continue
            if raw:
                entries.append(raw)
            continue
        parser = SETTINGS[key][0]
        try:
            values[key] = parser(raw)
        except ConfigError as exc:
            problems.append(f"line {number}: {key} — {exc}")
        except Exception:
            problems.append(f"line {number}: {key} — unusable value")
    return values, problems


def load(path: str) -> tuple[dict, list]:
    """Read the file at ``path``. A missing file is not a problem."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            text = handle.read(MAX_BYTES + 1)
    except FileNotFoundError:
        return {}, []
    except OSError as exc:
        return {}, [f"could not read {path}: {exc.strerror or 'error'}"]
    return parse(text)


_HEADER = """\
# NMesh — node configuration.
#
# Written by install.sh and by the web console (Settings → Configuration).
# Command-line flags still win over anything set here, and changes take effect
# when the node restarts.
#
# The console password is NOT here on purpose: it would be a credential sitting
# in cleartext in an editable file. Use $NMESH_CONSOLE_PASSWORD, or let the node
# generate one and print it once.
"""


def render(values: dict) -> str:
    """The file as it should be written: every setting, with its explanation.

    Regenerated wholesale rather than patched line by line — a file this small
    is clearer when it always looks the same, and a half-edited file is the kind
    of thing nobody notices until a node comes back up wrong."""
    out = [_HEADER]
    for name, (_, default, _writable, help_text) in SETTINGS.items():
        value = values.get(name, default)
        out.append(f"\n# {help_text}")
        if name == "launch":
            entries = value if isinstance(value, list) else []
            if not entries:
                out.append("# launch = /path/to/app --flag")
            for entry in entries[:MAX_LIST]:
                out.append(f"launch = {entry}")
            continue
        if value is None:
            out.append(f"# {name} =")
        elif isinstance(value, bool):
            out.append(f"{name} = {'true' if value else 'false'}")
        else:
            out.append(f"{name} = {value}")
    transports = values.get("transports") or {}
    if transports:
        out.append("\n# Transport settings. Each medium declares its own; the "
                   "console\n# (Network → Reachability) renders and validates them.")
        for scheme in sorted(transports):
            fields = transports[scheme] or {}
            for name in sorted(fields):
                out.append(f"{scheme}.{name} = {fields[name]}")
    return "\n".join(out) + "\n"


def save(path: str, values: dict) -> None:
    """Write the file atomically, readable only by the node's own account.

    Same discipline as the identity key: created 0600 from the start rather than
    tightened afterwards. It holds no secret today, and that is exactly why it
    must not become the file where one first appears unnoticed."""
    text = render(values)
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def validate(name: str, raw):
    """Check one setting the way the file's parser would. Raises ConfigError.

    The console hands us strings and JSON scalars alike, so booleans and numbers
    are normalised to text first — one validation path, not two."""
    if name not in SETTINGS:
        raise ConfigError("unknown setting")
    parser, _default, writable, _help = SETTINGS[name]
    if not writable:
        raise ConfigError("this setting is not editable from the console")
    if isinstance(raw, bool):
        raw = "true" if raw else "false"
    elif raw is None:
        raw = ""
    elif not isinstance(raw, str):
        raw = str(raw)
    if len(raw) > MAX_VALUE:
        raise ConfigError("value too long")
    return parser(raw)


def apply_edits(current: dict, edits) -> tuple[dict, list]:
    """``(new values, rejected)`` — validate an edit set from the console.

    Anything rejected leaves the current value untouched: a single bad field
    must not take the rest of the form down with it, and must never write a
    value the node would then refuse to start on."""
    if not isinstance(edits, dict):
        return dict(current), ["the request carried no settings"]
    merged = dict(current)
    rejected: list = []
    for name, raw in list(edits.items())[:len(SETTINGS)]:
        if not isinstance(name, str):
            rejected.append("a setting name that is not text")
            continue
        key = name.strip().lower().replace("-", "_")
        try:
            merged[key] = validate(key, raw)
        except ConfigError as exc:
            rejected.append(f"{key[:40]}: {exc}")
    return merged, rejected


_KINDS = {_as_bool: "bool", _as_port: "int", _as_optional_port: "int"}


def _kind_of(name: str) -> str:
    """How the console should render the field — from the parser, not from the
    default's Python type (``False`` and ``0`` are both falsy ints there)."""
    parser = SETTINGS[name][0]
    if parser is None:
        return "list"
    return _KINDS.get(parser, "text")


def public(values: dict) -> list:
    """The settings as the console shows them: value, editability, help."""
    shown = []
    for name, (_parser, default, writable, help_text) in SETTINGS.items():
        value = values.get(name, default)
        shown.append({
            "name": name,
            "value": value,
            "kind": _kind_of(name),
            "editable": writable,
            "help": help_text,
            "flag": CLI_NAMES[name],
        })
    return shown
