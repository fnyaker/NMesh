#!/usr/bin/env python3
"""
nmeshctl — drive an NMesh node from a terminal.

Made for an operator who reached the machine over SSH: it talks to the node's
own console on this machine, and through it to every node that granted it
``manage``, exactly as the web console does — same session, same operations,
same refusals. Nothing here is a second implementation of anything: the
commands are read from the node's control-plane catalogue, so an operation the
node gains tomorrow is a command tomorrow.

    nmeshctl login --for 8h               # sign in; stays across node restarts
    nmeshctl node state                   # any operation: <module> <op> [--param value]
    nmeshctl config save --settings '{"pseudo": "box"}'
    nmeshctl ops [module]                 # what this node (or --node) can do
    nmeshctl --node <id|name> node state  # the same, on a node this one manages
    nmeshctl fleet requests               # who is asking to manage this node
    nmeshctl fleet approve <id> --caps status,manage
    nmeshctl fleet grant <id> manage apps # what an operator may do here
    nmeshctl logout

The session token is kept in ``~/.config/nmesh/ctl.json`` (0600). The console's
certificate is pinned there at login — read from the node's state directory
when this account can, otherwise shown once for you to confirm, as SSH does.

Standard library only, and no import of the node's own code: a management tool
that needed liboqs to start would be one that does not start on the day it is
needed most.
"""
from __future__ import annotations

import argparse
import getpass
import hashlib
import http.client
import json
import os
import re
import socket
import ssl
import sys
import time
from urllib.parse import quote, urlsplit

DEFAULT_URL = "https://127.0.0.1:8787"
DEFAULT_FOR = "8h"
STATE_DIRS = ("/var/lib/nmesh",)
CERT_NAME = "console_cert.pem"
READ_MAX = 4 * 1024 * 1024
LIST_TIMEOUT = 30.0
JOB_POLL = 1.0
JOB_PATIENCE = 900.0
_NODE_RE = re.compile(r"\A[0-9a-f]{40}\Z")
_DURATION_RE = re.compile(r"\A(\d+)\s*([smhd]?)\Z")
_YES_NO = ("1", "true", "yes", "on", "0", "false", "no", "off")

EXIT_OK, EXIT_FAILED, EXIT_USAGE, EXIT_SIGNED_OUT = 0, 1, 2, 3


class CtlError(Exception):
    """Something to say to the operator, and the code to leave with."""

    def __init__(self, message: str, code: int = EXIT_FAILED) -> None:
        super().__init__(message)
        self.code = code


# ---------------------------------------------------------------------------
# Where things are kept
# ---------------------------------------------------------------------------

def config_path() -> str:
    explicit = os.environ.get("NMESH_CTL_CONFIG")
    if explicit:
        return explicit
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(
        os.path.expanduser("~"), ".config")
    return os.path.join(base, "nmesh", "ctl.json")


def load_config() -> dict:
    path = config_path()
    try:
        with open(path) as handle:
            data = json.load(handle)
    except FileNotFoundError:
        return {}
    except (OSError, ValueError):
        raise CtlError(f"{path} cannot be read — remove it and sign in again")
    return data if isinstance(data, dict) else {}


def save_config(data: dict) -> None:
    """Written 0600 from its first byte: it holds a session token."""
    path = config_path()
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as handle:
        json.dump(data, handle, indent=2)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def parse_duration(text) -> int:
    """``8h``, ``30m``, ``1d``, ``3600`` → seconds. The node caps it anyway."""
    match = _DURATION_RE.match(str(text).strip().lower())
    if not match:
        raise CtlError(f"not a duration: {text!r} (try 8h, 30m, 1d)", EXIT_USAGE)
    value, unit = int(match.group(1)), match.group(2) or "s"
    return value * {"s": 1, "m": 60, "h": 3600, "d": 86400}[unit]


def fingerprint_of_pem(pem: str) -> str:
    return hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem)).hexdigest()


def local_fingerprint() -> str | None:
    """The console's fingerprint read from the node's state directory, when
    this account can read it — which is the case that needs no question."""
    dirs = [os.environ["NMESH_DATA"]] if os.environ.get("NMESH_DATA") else []
    for directory in dirs + list(STATE_DIRS):
        path = os.path.join(directory, CERT_NAME)
        try:
            with open(path) as handle:
                return fingerprint_of_pem(handle.read(65536))
        except (OSError, ValueError):
            continue
    return None


# ---------------------------------------------------------------------------
# Talking to the console
# ---------------------------------------------------------------------------

class Console:
    """One console, reached over HTTPS with its certificate pinned.

    ``node`` and ``then`` are the console's own context headers: the node it
    should relay to, and the one beyond that (``full`` only)."""

    def __init__(self, url: str, *, token: str | None = None,
                 fingerprint: str | None = None, node: str | None = None,
                 then: str | None = None) -> None:
        parts = urlsplit(url)
        if parts.scheme not in ("https", "http") or not parts.hostname:
            raise CtlError(f"not a console address: {url!r}", EXIT_USAGE)
        if parts.scheme == "http" and parts.hostname not in ("127.0.0.1", "::1",
                                                             "localhost"):
            # The console serves plain HTTP on loopback only; anywhere else
            # this would be a password on the wire.
            raise CtlError("plain http is for a console on this machine only",
                           EXIT_USAGE)
        self.url = url
        self.tls = parts.scheme == "https"
        self.host = parts.hostname
        self.port = parts.port or (443 if self.tls else 80)
        self.token = token
        self.fingerprint = fingerprint
        self.node = node
        self.then = then

    def _connection(self, timeout: float):
        if not self.tls:
            return http.client.HTTPConnection(self.host, self.port,
                                              timeout=timeout)
        # Self-signed by design: trust comes from the pinned fingerprint
        # below, checked before a single byte of the request is sent.
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        return http.client.HTTPSConnection(self.host, self.port,
                                           timeout=timeout, context=context)

    def peer_fingerprint(self, timeout: float = 10.0) -> str:
        connection = self._connection(timeout)
        try:
            connection.connect()
            der = connection.sock.getpeercert(binary_form=True)
            return hashlib.sha256(der).hexdigest()
        except OSError as exc:
            raise CtlError(f"console unreachable at {self.url}: {exc}") from None
        finally:
            connection.close()

    def request(self, method: str, path: str, body=None, *,
                timeout: float = LIST_TIMEOUT, here: bool = False):
        """``(status, document)``. ``here`` keeps the call on this console
        whatever node is being driven — its own sessions, its own login."""
        connection = self._connection(timeout)
        try:
            connection.connect()
            if self.tls:
                der = connection.sock.getpeercert(binary_form=True)
                seen = hashlib.sha256(der).hexdigest()
                if not self.fingerprint or seen != self.fingerprint:
                    raise CtlError(
                        "the console's certificate is not the one pinned at "
                        "login — if it was regenerated on purpose, sign in "
                        "again; otherwise something is answering in its place")
            headers = {"Accept": "application/json"}
            if self.token:
                headers["Authorization"] = "Bearer " + self.token
            if self.node and not here:
                headers["X-NMesh-Node"] = self.node
                if self.then:
                    headers["X-NMesh-Then"] = self.then
            data = None
            if body is not None:
                data = json.dumps(body).encode("utf-8")
                headers["Content-Type"] = "application/json"
            connection.request(method, path, body=data, headers=headers)
            response = connection.getresponse()
            payload = response.read(READ_MAX + 1)
            if len(payload) > READ_MAX:
                raise CtlError("the console's answer is too large")
            try:
                document = json.loads(payload) if payload else {}
            except ValueError:
                document = {"error": payload[:200].decode("utf-8", "replace")}
            return response.status, document if isinstance(document, dict) else {
                "result": document}
        except (OSError, socket.timeout, http.client.HTTPException) as exc:
            raise CtlError(f"console unreachable at {self.url}: {exc}") from None
        finally:
            connection.close()

    # -- the control plane ------------------------------------------------

    def frame(self, op: str, params=None, *, timeout: float = LIST_TIMEOUT) -> dict:
        """One control frame; the reply document (``ok``, ``result``…)."""
        status, reply = self.request(
            "POST", "/api/control",
            {"v": 1, "id": "ctl", "op": op, "params": params or {}},
            timeout=timeout)
        if status == 401 and not self.node:
            raise CtlError("signed out — run: nmeshctl login", EXIT_SIGNED_OUT)
        if "ok" not in reply:
            reply = {"ok": False, "code": "failed",
                     "error": reply.get("error") or f"HTTP {status}"}
        return reply


def signed_in() -> Console:
    config = load_config()
    if not config.get("token"):
        raise CtlError("not signed in — run: nmeshctl login", EXIT_SIGNED_OUT)
    expires = config.get("expires_at")
    if isinstance(expires, (int, float)) and expires <= time.time():
        raise CtlError("the session has ended — run: nmeshctl login",
                       EXIT_SIGNED_OUT)
    return Console(config.get("url") or DEFAULT_URL, token=config["token"],
                   fingerprint=config.get("fingerprint"))


# ---------------------------------------------------------------------------
# Saying it
# ---------------------------------------------------------------------------

def emit(value, as_json: bool) -> None:
    if as_json:
        print(json.dumps(value, indent=2, sort_keys=True, default=str))
        return
    if isinstance(value, (dict, list)):
        print(json.dumps(value, indent=2, sort_keys=True, default=str))
    elif value is not None:
        print(value)


def table(rows, columns) -> None:
    """Aligned words, no ornament (the charter's rule for terminal output)."""
    if not rows:
        print("(none)")
        return
    cells = [[str(row.get(key, "") if row.get(key) is not None else "")
              for key, _ in columns] for row in rows]
    widths = [max(len(title), *(len(line[index]) for line in cells))
              for index, (_, title) in enumerate(columns)]
    print("  ".join(title.ljust(width)
                    for (_, title), width in zip(columns, widths)).rstrip())
    for line in cells:
        print("  ".join(cell.ljust(width) for cell, width in zip(line, widths)).rstrip())


def refused(reply: dict) -> CtlError:
    code = reply.get("code") or "failed"
    message = reply.get("error") or code
    detail = reply.get("detail")
    if isinstance(detail, dict) and detail.get("rejected"):
        message += "\n  " + "\n  ".join(str(item) for item in detail["rejected"])
    exit_code = EXIT_SIGNED_OUT if code == "unauthorized" else EXIT_FAILED
    return CtlError(f"{code}: {message}", exit_code)


# ---------------------------------------------------------------------------
# Which node
# ---------------------------------------------------------------------------

def targets(console: Console) -> list:
    status, answer = console.request("GET", "/api/remote/targets", here=True)
    if status == 401:
        raise CtlError("signed out — run: nmeshctl login", EXIT_SIGNED_OUT)
    if not answer.get("available", True) and not answer.get("targets"):
        raise CtlError("the fleet app is not running on this node")
    return [row for row in answer.get("targets") or [] if isinstance(row, dict)]


def resolve_node(console: Console, wanted: str) -> dict:
    """A node this one manages, by id, id prefix, label or name."""
    wanted = (wanted or "").strip()
    rows = targets(console)
    low = wanted.lower()
    exact = [row for row in rows if row.get("id") == low]
    if exact:
        return exact[0]
    matches = [row for row in rows
               if (len(low) >= 4 and str(row.get("id", "")).startswith(low))
               or low in (str(row.get("label") or "").lower(),
                          str(row.get("pseudo") or "").lower())]
    if len(matches) == 1:
        return matches[0]
    if not matches:
        if _NODE_RE.match(low):
            raise CtlError(f"{low} has not granted this node manage")
        raise CtlError(f"no node this one manages is called {wanted!r}")
    names = ", ".join(row.get("label") or row.get("pseudo") or row["id"][:12]
                      for row in matches)
    raise CtlError(f"{wanted!r} names several nodes: {names}", EXIT_USAGE)


def connect(console: Console, target: dict, password: str | None = None) -> None:
    """Open this console's session on ``target``, as the web console does: no
    password where the node granted ``passwordless``, the node's own console
    password otherwise — typed here, sent once, kept nowhere."""
    if target.get("connected") and password is None:
        return
    if password is None and not target.get("passwordless"):
        name = target.get("label") or target.get("pseudo") or target["id"][:12]
        password = getpass.getpass(f"Console password of {name}: ")
    status, answer = console.request("POST", "/api/remote/connect",
                                     {"node": target["id"], "password": password},
                                     here=True)
    if status != 200 or not answer.get("ok"):
        raise CtlError(answer.get("error") or "that node refused the session")


# ---------------------------------------------------------------------------
# Operations
# ---------------------------------------------------------------------------

def catalogue(console: Console) -> list:
    reply = console.frame("control.catalogue")
    if not reply.get("ok"):
        raise refused(reply)
    return [module for module in (reply.get("result") or {}).get("modules") or []
            if isinstance(module, dict)]


def find_operation(modules: list, module: str, op: str) -> dict | None:
    for entry in modules:
        if entry.get("module") == module:
            for row in entry.get("operations") or []:
                if row.get("name") == op:
                    return row
    return None


def coerce(text: str, kind: str):
    """A value typed on a command line, as the operation declared it. JSON is
    accepted wherever a structure is expected; the node checks it again."""
    if kind == "flag":
        lowered = text.lower()
        if lowered in ("1", "true", "yes", "on"):
            return True
        if lowered in ("0", "false", "no", "off"):
            return False
        raise CtlError(f"not a yes/no value: {text!r}", EXIT_USAGE)
    if kind == "count":
        try:
            return int(text)
        except ValueError:
            raise CtlError(f"not a number: {text!r}", EXIT_USAGE) from None
    if kind in ("document", "payload", "tokens"):
        try:
            return json.loads(text)
        except ValueError:
            if kind == "tokens":
                return [part for part in text.split(",") if part]
            raise CtlError(f"not JSON: {text!r}", EXIT_USAGE) from None
    return text


def bind_arguments(row: dict, words: list) -> dict:
    """``--name value``, ``--name=value``, ``name=value`` and a bare ``--flag``
    — against what the operation declared, so a typo is caught here."""
    declared = {param["name"]: param for param in row.get("params") or []
                if isinstance(param, dict) and "name" in param}
    params: dict = {}
    index = 0
    while index < len(words):
        word = words[index]
        if word.startswith("--"):
            name, _, value = word[2:].partition("=")
            name = name.replace("-", "_")
            spec = declared.get(name)
            if spec is None:
                raise CtlError(f"{row.get('name')} takes no --{name} "
                               f"(it takes: {', '.join(declared) or 'nothing'})",
                               EXIT_USAGE)
            if not value and "=" not in word:
                # A bare flag is "yes" unless the next word *is* a yes or no:
                # `--events node=…` must not read `node=…` as the answer.
                if spec.get("kind") == "flag" and (
                        index + 1 >= len(words)
                        or words[index + 1].lower() not in _YES_NO):
                    params[name] = True
                    index += 1
                    continue
                index += 1
                if index >= len(words):
                    raise CtlError(f"--{name} needs a value", EXIT_USAGE)
                value = words[index]
            params[name] = coerce(value, spec.get("kind", "text"))
        elif "=" in word:
            name, _, value = word.partition("=")
            spec = declared.get(name)
            if spec is None:
                raise CtlError(f"{row.get('name')} takes no {name}", EXIT_USAGE)
            params[name] = coerce(value, spec.get("kind", "text"))
        else:
            raise CtlError(f"unexpected {word!r} — arguments are --name value",
                           EXIT_USAGE)
        index += 1
    return params


def run_operation(console: Console, op: str, params: dict, row: dict | None,
                  *, quiet: bool = False) -> dict:
    """Call ``op``; when the node says it must run as a job, start it and wait.

    A console at a distance is told to use a job for anything longer than one
    relayed call (`control-plane.md`), and here the waiting is ours to do."""
    timeout = float((row or {}).get("timeout") or 15.0) + 15.0
    reply = console.frame(op, params, timeout=timeout)
    detail = reply.get("detail") if isinstance(reply.get("detail"), dict) else {}
    if not reply.get("ok") and detail.get("background"):
        started = console.frame("jobs.start", {"op": op, "params": params})
        if not started.get("ok"):
            raise refused(started)
        job = (started.get("result") or {}).get("job")
        if not quiet:
            print(f"started {op} as job {job}", file=sys.stderr)
        deadline = time.monotonic() + JOB_PATIENCE
        while time.monotonic() < deadline:
            time.sleep(JOB_POLL)
            polled = console.frame("jobs.poll", {"job": job})
            if not polled.get("ok"):
                raise refused(polled)
            state = polled.get("result") or {}
            if state.get("state") == "running":
                continue
            if state.get("state") == "failed":
                raise refused({"code": state.get("code"), "error": state.get("error"),
                               "detail": state.get("detail")})
            return state.get("result") or {}
        raise CtlError(f"job {job} is still running — check it with: "
                       f"nmeshctl jobs poll --job {job}")
    if not reply.get("ok"):
        raise refused(reply)
    return reply.get("result")


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_login(args) -> int:
    url = args.url or load_config().get("url") or os.environ.get(
        "NMESH_CONSOLE_URL") or DEFAULT_URL
    probe = Console(url)
    fingerprint = None
    if probe.tls:
        seen = probe.peer_fingerprint()
        expected = (args.fingerprint or "").lower().replace(":", "") or None
        known = load_config().get("fingerprint") if load_config().get("url") == url else None
        local = local_fingerprint()
        if expected:
            if seen != expected:
                raise CtlError("the console's certificate does not match "
                               "--fingerprint")
        elif seen in (known, local):
            pass
        elif args.yes:
            print(f"warning: pinning an unverified certificate {seen}",
                  file=sys.stderr)
        else:
            print(f"The console at {url} presents a certificate this account "
                  f"cannot check against the node's own:\n  sha256 {seen}",
                  file=sys.stderr)
            answer = input("Pin it and continue? [y/N] ").strip().lower()
            if answer not in ("y", "yes"):
                raise CtlError("not signed in")
        fingerprint = seen
    if args.password_stdin:
        password = sys.stdin.readline().rstrip("\n")
    else:
        password = os.environ.get("NMESH_PASSWORD") or getpass.getpass(
            "Console password: ")
    console = Console(url, fingerprint=fingerprint)
    seconds = parse_duration(args.for_)
    status, answer = console.request(
        "POST", "/api/login",
        {"password": password, "for": seconds,
         "label": args.label or f"nmeshctl@{socket.gethostname()}"[:64]},
        here=True)
    if status == 429:
        raise CtlError("too many attempts — wait a minute")
    if status != 200 or not answer.get("token"):
        raise CtlError(answer.get("error") or "the console refused the password")
    save_config({"url": url, "token": answer["token"],
                 "expires_at": answer.get("expires_at"),
                 "fingerprint": fingerprint})
    until = answer.get("expires_at")
    when = time.strftime("%Y-%m-%d %H:%M", time.localtime(until)) if until else "?"
    print(f"ok  signed in to {url} until {when}")
    return EXIT_OK


def cmd_logout(args) -> int:
    config = load_config()
    if config.get("token"):
        try:
            Console(config.get("url") or DEFAULT_URL, token=config["token"],
                    fingerprint=config.get("fingerprint")).request(
                "POST", "/api/logout", {}, here=True)
        except CtlError as exc:
            print(f"warning: {exc} — the token is forgotten here anyway",
                  file=sys.stderr)
    config.pop("token", None)
    config.pop("expires_at", None)
    save_config(config)
    print("ok  signed out")
    return EXIT_OK


def cmd_status(args) -> int:
    console = signed_in()
    status, answer = console.request("GET", "/api/session", here=True)
    if status == 401:
        raise CtlError("signed out — run: nmeshctl login", EXIT_SIGNED_OUT)
    if args.json:
        emit(answer, True)
        return EXIT_OK
    until = answer.get("expires_at")
    print(f"console   {console.url}")
    print(f"node      {answer.get('node', '?')}")
    print("session   " + (time.strftime("until %Y-%m-%d %H:%M",
                                        time.localtime(until))
                          if until else "a browser-style session (ends with the node)"))
    return EXIT_OK


def cmd_ops(args, console: Console) -> int:
    modules = catalogue(console)
    if args.module:
        modules = [entry for entry in modules if entry.get("module") == args.module]
        if not modules:
            raise CtlError(f"no module {args.module!r} here", EXIT_USAGE)
    if args.json:
        emit(modules, True)
        return EXIT_OK
    rows = []
    for entry in modules:
        for row in entry.get("operations") or []:
            params = " ".join(
                ("--" + p["name"] + ("" if p.get("required", True) else "?"))
                for p in row.get("params") or [] if isinstance(p, dict))
            rows.append({"op": f"{entry['module']} {row.get('name')}",
                         "args": params, "what": row.get("summary", "")})
    table(rows, (("op", "OPERATION"), ("args", "ARGUMENTS"), ("what", "WHAT")))
    return EXIT_OK


def cmd_operation(args, console: Console) -> int:
    words = list(args.words)
    if len(words) < 2:
        raise CtlError("usage: nmeshctl <module> <operation> [--name value…]",
                       EXIT_USAGE)
    module, op, rest = words[0], words[1].replace("-", "_"), words[2:]
    modules = catalogue(console)
    row = find_operation(modules, module, op)
    if row is None:
        known = sorted({entry["module"] for entry in modules})
        if module not in known:
            raise CtlError(f"no module {module!r} here (try: nmeshctl ops)",
                           EXIT_USAGE)
        raise CtlError(f"{module} has no operation {op!r} that this console can "
                       f"reach (try: nmeshctl ops {module})", EXIT_USAGE)
    params = bind_arguments(row, rest)
    emit(run_operation(console, f"{module}.{op}", params, row), args.json)
    return EXIT_OK


def cmd_call(args, console: Console) -> int:
    """The raw door: an operation by its full name, arguments as JSON."""
    try:
        params = json.loads(args.params) if args.params else {}
    except ValueError:
        raise CtlError("--params must be a JSON object", EXIT_USAGE) from None
    if not isinstance(params, dict):
        raise CtlError("--params must be a JSON object", EXIT_USAGE)
    emit(run_operation(console, args.op, params, None), args.json)
    return EXIT_OK


def cmd_remote(args) -> int:
    console = signed_in()
    if args.action == "list":
        rows = targets(console)
        if args.json:
            emit(rows, True)
            return EXIT_OK
        table([{**row, "connected": "yes" if row.get("connected") else "",
                "caps": ",".join(row.get("caps") or []),
                "name": row.get("label") or row.get("pseudo") or ""}
               for row in rows],
              (("id", "NODE"), ("name", "NAME"), ("connected", "SESSION"),
               ("caps", "GRANTED")))
        return EXIT_OK
    if not args.target:
        raise CtlError(f"usage: nmeshctl remote {args.action} <node>", EXIT_USAGE)
    target = resolve_node(console, args.target)
    if args.action == "connect":
        connect(console, target, None if target.get("passwordless") else
                getpass.getpass("Console password: "))
        print(f"ok  session open on {target['id']}")
    else:
        console.request("POST", "/api/remote/disconnect", {"node": target["id"]},
                        here=True)
        print(f"ok  session on {target['id']} handed back")
    return EXIT_OK


# -- fleet: who may do what ---------------------------------------------------

def _fleet_state(console: Console) -> dict:
    status, state = console.request("GET", "/api/fleet/state")
    if status == 401:
        raise CtlError("signed out — run: nmeshctl login", EXIT_SIGNED_OUT)
    if status == 404:
        raise CtlError("the fleet app is not running on that node — enable it "
                       "with: nmeshctl apps set --app fleet --action enable")
    if status != 200:
        raise CtlError(state.get("error") or f"the fleet app answered HTTP {status}")
    return state


def _fleet_post(console: Console, action: str, body: dict) -> dict:
    status, answer = console.request("POST", "/api/fleet/" + action, body)
    if status == 401:
        raise CtlError("signed out — run: nmeshctl login", EXIT_SIGNED_OUT)
    if status != 200 or answer.get("ok") is False:
        raise CtlError(answer.get("error") or f"refused (HTTP {status})")
    return answer


def _caps(words) -> list:
    caps = []
    for word in words or []:
        if isinstance(word, str):
            caps.extend(part.strip() for part in word.split(",") if part.strip())
    return caps


def _node_arg(state: dict, wanted: str, section: str) -> str:
    wanted = (wanted or "").strip().lower()
    rows = [row for row in state.get(section) or [] if isinstance(row, dict)]
    exact = [row["id"] for row in rows if row.get("id") == wanted]
    if exact:
        return exact[0]
    found = [row["id"] for row in rows
             if (len(wanted) >= 4 and str(row.get("id", "")).startswith(wanted))
             or wanted in (str(row.get("label") or "").lower(),
                           str(row.get("pseudo") or "").lower())]
    if len(found) == 1:
        return found[0]
    if _NODE_RE.match(wanted):
        return wanted
    if not found:
        raise CtlError(f"no node called {wanted!r} in {section.replace('_', ' ')}")
    raise CtlError(f"{wanted!r} names several nodes", EXIT_USAGE)


def _check_caps(state: dict, caps: list) -> None:
    known = {row.get("name") for row in state.get("capabilities") or []}
    unknown = [cap for cap in caps if cap not in known]
    if unknown:
        raise CtlError(f"unknown capability {', '.join(unknown)} "
                       f"(known: {', '.join(sorted(known))})", EXIT_USAGE)


def cmd_fleet(args, console: Console) -> int:
    state = _fleet_state(console)
    action = args.action
    if action == "caps":
        rows = state.get("capabilities") or []
        if args.json:
            emit(rows, True)
        else:
            table(rows, (("name", "CAPABILITY"), ("description", "WHAT IT ALLOWS")))
        return EXIT_OK
    if action == "requests":
        rows = state.get("pending_in") or []
        if args.json:
            emit(rows, True)
            return EXIT_OK
        table([{**row, "caps": ",".join(row.get("caps") or []),
                "have": ",".join(row.get("have") or []),
                "when": time.strftime("%Y-%m-%d %H:%M",
                                      time.localtime(row.get("at") or 0))}
               for row in rows],
              (("id", "NODE"), ("label", "LABEL"), ("caps", "ASKS FOR"),
               ("have", "HOLDS ALREADY"), ("when", "ASKED")))
        return EXIT_OK
    if action in ("operators", "managed"):
        rows = state.get(action) or []
        if args.json:
            emit(rows, True)
            return EXIT_OK
        table([{**row, "caps": ",".join(row.get("caps") or []),
                "name": row.get("label") or row.get("pseudo") or ""}
               for row in rows],
              (("id", "NODE"), ("name", "NAME"), ("caps", "CAPABILITIES")))
        return EXIT_OK
    if not args.target:
        raise CtlError(f"usage: nmeshctl fleet {action} <node> …", EXIT_USAGE)
    caps = _caps(args.caps)
    if caps:
        _check_caps(state, caps)
    if action == "approve":
        node = _node_arg(state, args.target, "pending_in")
        pending = next((row for row in state.get("pending_in") or []
                        if row.get("id") == node), None)
        if pending is None:
            raise CtlError(f"{node} has not asked to manage this node")
        # Narrowing only: approving can never grant more than was asked.
        asked = pending.get("caps") or []
        wider = [cap for cap in caps if cap not in asked]
        if wider:
            raise CtlError(f"{node} did not ask for {', '.join(wider)} — an "
                           f"approval can only narrow (asked: {', '.join(asked)})",
                           EXIT_USAGE)
        _fleet_post(console, "approve", {"node": node, "caps": caps or asked})
        print(f"ok  {node} may now: {', '.join(caps or asked)}")
    elif action == "deny":
        node = _node_arg(state, args.target, "pending_in")
        _fleet_post(console, "deny", {"node": node, "reason": args.reason or ""})
        print(f"ok  request from {node} refused")
    elif action == "grant":
        # What an operator may do to *this* node: the set given, absolute.
        node = _node_arg(state, args.target, "operators")
        held = next((row.get("caps") or [] for row in state.get("operators") or []
                     if row.get("id") == node), None)
        if held is None:
            raise CtlError(f"{node} is not an operator of this node — it has to "
                           f"ask first (fleet requests)")
        if args.add:
            caps = list(dict.fromkeys(list(held) + caps))
        elif args.remove:
            caps = [cap for cap in held if cap not in caps]
        if not caps:
            raise CtlError("no capability left — to cut it off, use: "
                           "nmeshctl fleet revoke", EXIT_USAGE)
        _fleet_post(console, "caps-set", {"node": node, "caps": caps})
        print(f"ok  {node} may now: {', '.join(caps)}")
    elif action == "revoke":
        node = _node_arg(state, args.target, "operators")
        _fleet_post(console, "revoke", {"node": node})
        print(f"ok  {node} no longer controls this node")
    elif action == "request":
        # Asking another node for rights: a first request, or more of them.
        if not caps:
            raise CtlError("which capabilities? e.g. --caps status,manage",
                           EXIT_USAGE)
        node = _node_arg(state, args.target, "managed")
        managed = any(row.get("id") == node for row in state.get("managed") or [])
        if managed:
            _fleet_post(console, "caps-request", {"node": node, "caps": caps})
        else:
            _fleet_post(console, "enrol", {"node": node, "caps": caps,
                                           "label": args.label or ""})
        print(f"ok  asked {node} for: {', '.join(caps)} — a human there decides")
    elif action == "drop":
        node = _node_arg(state, args.target, "managed")
        _fleet_post(console, "caps-drop", {"node": node, "caps": caps})
        print(f"ok  handed back {', '.join(caps)} on {node}")
    else:
        raise CtlError(f"no fleet action {action!r}", EXIT_USAGE)
    return EXIT_OK


# ---------------------------------------------------------------------------
# The command line
# ---------------------------------------------------------------------------

FLEET_ACTIONS = ("requests", "approve", "deny", "operators", "grant", "revoke",
                 "managed", "request", "drop", "caps")
COMMANDS = ("login", "logout", "status", "ops", "call", "remote", "fleet")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nmeshctl", description="Drive an NMesh node from a terminal.",
        epilog="Any other command is an operation: nmeshctl <module> <op> "
               "[--name value…]. List them with: nmeshctl ops")
    parser.add_argument("--node", help="a node this one manages (id, prefix, "
                                       "label or name) — the command runs there")
    parser.add_argument("--then", help="a node *that* one manages, reached "
                                       "through it (needs its full grant)")
    parser.add_argument("--json", action="store_true",
                        help="answer as JSON, for a script")
    sub = parser.add_subparsers(dest="command")

    login = sub.add_parser("login", help="sign in to this machine's console")
    login.add_argument("--url", help=f"the console (default {DEFAULT_URL})")
    login.add_argument("--for", dest="for_", default=DEFAULT_FOR,
                       help="how long to stay signed in, across restarts "
                            "(e.g. 30m, 8h, 1d; at most 24h)")
    login.add_argument("--label", help="what this session is called on the node")
    login.add_argument("--fingerprint", help="the console certificate's sha256, "
                                             "when it cannot be read here")
    login.add_argument("--yes", action="store_true",
                       help="pin the certificate without asking")
    login.add_argument("--password-stdin", action="store_true",
                       help="read the password from standard input")

    sub.add_parser("logout", help="end the session")
    sub.add_parser("status", help="who and where this session is")

    ops = sub.add_parser("ops", help="the operations this console can reach")
    ops.add_argument("module", nargs="?")

    call = sub.add_parser("call", help="an operation by full name, JSON arguments")
    call.add_argument("op", help="e.g. node.state")
    call.add_argument("--params", help="a JSON object")

    remote = sub.add_parser("remote", help="sessions on the nodes this one manages")
    remote.add_argument("action", choices=("list", "connect", "disconnect"))
    remote.add_argument("target", nargs="?")

    fleet = sub.add_parser("fleet", help="who may manage what")
    fleet.add_argument("action", choices=FLEET_ACTIONS)
    fleet.add_argument("target", nargs="?", help="a node id, prefix, label or name")
    fleet.add_argument("caps", nargs="*", help="capabilities (or --caps a,b)")
    fleet.add_argument("--caps", dest="caps_opt", help="capabilities, comma separated")
    fleet.add_argument("--add", action="store_true",
                       help="grant: add these to what it holds")
    fleet.add_argument("--remove", action="store_true",
                       help="grant: take these away from what it holds")
    fleet.add_argument("--reason", help="deny: what to tell it")
    fleet.add_argument("--label", help="request: what to call that node here")
    return parser


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()
    # `--json` is accepted anywhere: no operation takes an argument of that
    # name, and a script appends it where it likes. `--node` and `--then` only
    # before the command — after it, `--node` is the argument half the
    # operations take (`node ping --node <id>`).
    as_json = "--json" in argv
    argv = [word for word in argv if word != "--json"]
    head, index = [], 0
    while index < len(argv) and argv[index].startswith("--"):
        head.append(argv[index])
        if argv[index] in ("--node", "--then") and index + 1 < len(argv):
            index += 1
            head.append(argv[index])
        index += 1
    rest = argv[index:]
    try:
        if rest and rest[0] not in COMMANDS and not rest[0].startswith("-"):
            args = parser.parse_args(head)
            args.words = rest
            args.command = "operation"
        else:
            args = parser.parse_args(argv)
            if args.command == "fleet":
                args.caps = list(args.caps or []) + _caps([args.caps_opt])
        args.json = args.json or as_json
        if args.command is None:
            parser.print_help()
            return EXIT_USAGE
        if args.command == "login":
            return cmd_login(args)
        if args.command == "logout":
            return cmd_logout(args)
        if args.command == "status":
            return cmd_status(args)
        if args.command == "remote":
            return cmd_remote(args)
        console = signed_in()
        if args.then and not args.node:
            raise CtlError("--then needs --node: the node to reach it through",
                           EXIT_USAGE)
        if args.node:
            target = resolve_node(console, args.node)
            connect(console, target)
            console.node = target["id"]
            if args.then:
                then = args.then.strip().lower()
                if not _NODE_RE.match(then):
                    raise CtlError("--then takes a full node id", EXIT_USAGE)
                if "full" not in (target.get("caps") or []):
                    raise CtlError("reaching on through that node needs its "
                                   "full grant")
                console.then = then
        handlers = {"ops": cmd_ops, "call": cmd_call, "fleet": cmd_fleet,
                    "operation": cmd_operation}
        return handlers[args.command](args, console)
    except CtlError as exc:
        print(f"failed: {exc}", file=sys.stderr)
        return exc.code
    except KeyboardInterrupt:
        print("", file=sys.stderr)
        return EXIT_FAILED


if __name__ == "__main__":
    sys.exit(main())
