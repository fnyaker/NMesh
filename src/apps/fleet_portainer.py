"""
Portainer — the manager a machine may already have in front of its docker.

Portainer deploys through compose and labels nothing of its own: its stacks are
found from the Engine alone (`fleet_stacks`), by the directory they were
deployed from. What its API adds is what the Engine cannot give: the stack's
**file and environment**, held in Portainer's database, and the **redeploy**
that pulls the images and brings the stack up from them while keeping
Portainer's record true. A stack Portainer owns is updated through here when an
operator connected one.

What this holds, and why it is not much
---------------------------------------
One endpoint and one access token per node, kept in the fleet app's encrypted
drawer, **write-only** from the outside: an operator can set it and can see that
it is set, and nothing ever reads it back over the mesh. A token that could be
read back would make the `docker` capability a way of stealing the credential
rather than of using it. The stack's environment is read from Portainer only to
be handed straight back on a redeploy; it never travels.

TLS is verified. A Portainer on a private network very often has a self-signed
certificate, so there is a second way to accept one: **pin its fingerprint**,
read once by :func:`probe` and confirmed by the operator. That is an anchor an
operator chose, which is the only kind of trust this project has — where "just
don't check" is not a setting. Plain HTTP is accepted only to this machine's
own loopback, where there is no wire to read the token from.

Everything from the far side is hostile input, exactly as with the daemon: the
answers are large, deep, and written by something this node does not control, so
the shapes handed on are built field by field and bounded.
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import ipaddress
import json
import re
import ssl

from .fleet_docker import DockerError, build_request, read_response

CALL_TIMEOUT = 30.0
REDEPLOY_TIMEOUT = 900.0         # a redeploy pulls images
MAX_STACKS = 100
MAX_ENDPOINTS = 50
MAX_FILE = 40_000                # a stack file, so one reply frame still fits
MAX_URL = 256
MAX_TOKEN = 512
MAX_ENV = 256                    # variables a stack's environment may carry
SETTLE_POLL = 2.0                # how often a background deployment is asked about
_ACTIVE, _DEPLOYING = 1, 3       # Portainer's own stack statuses

_HOST_RE = re.compile(r"\A[A-Za-z0-9._:\[\]-]{1,200}\Z")
_FINGERPRINT_RE = re.compile(r"\A[0-9a-f]{64}\Z")


class PortainerError(DockerError):
    """Phrased for whoever configured it. Never carries a traceback outward."""


def clean_url(value) -> str:
    """``https://host:9443`` and nothing else — no path, no query, no name we
    would have to resolve later and could be pointed anywhere."""
    if not isinstance(value, str):
        return ""
    text = value.strip().rstrip("/")
    if not text or len(text) > MAX_URL:
        return ""
    scheme, _, rest = text.partition("://")
    if scheme not in ("http", "https") or not rest:
        return ""
    if "/" in rest or not _HOST_RE.match(rest):
        return ""
    if scheme == "http" and not _loopback(rest):
        return ""                # a token in the clear, over a wire
    return f"{scheme}://{rest}"


def _split(url: str) -> tuple[str, str, int, bool]:
    """A clean URL → (authority, host, port, is https)."""
    scheme, _, rest = url.partition("://")
    host, _, port = rest.rpartition(":")
    if not host or not port.isdigit() or host.endswith(":"):
        host, port = rest, "443" if scheme == "https" else "80"
    return rest, host.strip("[]"), int(port), scheme == "https"


def _loopback(authority: str) -> bool:
    host = authority
    if host.startswith("["):
        host = host[1:].partition("]")[0]
    elif host.count(":") == 1:
        host = host.partition(":")[0]
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def clean_token(value) -> str:
    if not isinstance(value, str):
        return ""
    text = value.strip()
    if not text or len(text) > MAX_TOKEN:
        return ""
    # It rides an HTTP header, so a control character in it would be a second
    # header. Refused rather than stripped.
    return text if all(32 <= ord(ch) < 127 for ch in text) else ""


def clean_fingerprint(value) -> str:
    if not isinstance(value, str):
        return ""
    text = value.strip().lower().replace(":", "")
    return text if _FINGERPRINT_RE.match(text) else ""


class Portainer:
    """One configured Portainer, and the calls this app makes to it."""

    def __init__(self, url: str, token: str, *, fingerprint: str = "") -> None:
        self.url = clean_url(url)
        self.token = clean_token(token)
        self.fingerprint = clean_fingerprint(fingerprint)
        if not self.url or not self.token:
            raise PortainerError("that Portainer address or token is not usable")

    # -- the wire ---------------------------------------------------------

    def _target(self) -> tuple[str, str, int, bool]:
        return _split(self.url)

    def _context(self) -> ssl.SSLContext | None:
        authority, _host, _port, secure = self._target()
        if not secure:
            return None
        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        if self.fingerprint:
            # A pin replaces the chain, it does not weaken it: the certificate
            # is checked against a value an operator wrote down, which is more
            # than a public CA would tell us about a machine on a private
            # network.
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        return context

    async def call(self, method: str, path: str, body=None, *,
                   timeout: float = CALL_TIMEOUT):
        authority, host, port, secure = self._target()
        payload = b"" if body is None else json.dumps(body).encode("utf-8")
        head = build_request(method, path, authority, payload,
                             extra=(f"X-API-Key: {self.token}",))
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=self._context()), timeout)
        except (OSError, ssl.SSLError, asyncio.TimeoutError) as exc:
            raise PortainerError(
                f"could not reach Portainer ({type(exc).__name__})") from None
        try:
            if secure and self.fingerprint:
                self._check_pin(writer)
            writer.write(head)
            await writer.drain()
            status, _headers, data = await read_response(reader, timeout)
        except PortainerError:
            raise
        except DockerError as exc:
            raise PortainerError(str(exc)) from None
        except (OSError, ssl.SSLError, asyncio.TimeoutError,
                asyncio.IncompleteReadError) as exc:
            raise PortainerError(
                f"Portainer hung up ({type(exc).__name__})") from None
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (OSError, ssl.SSLError, asyncio.TimeoutError):
                pass
        if status == 401 or status == 403:
            raise PortainerError("Portainer refused that token")
        if status >= 400:
            raise PortainerError(_message(data, status))
        if not data:
            return None
        try:
            return json.loads(data)
        except ValueError:
            raise PortainerError("Portainer answered something unreadable") from None

    def _check_pin(self, writer) -> None:
        sock = writer.get_extra_info("ssl_object")
        raw = sock.getpeercert(True) if sock is not None else None
        if not raw:
            raise PortainerError("that connection produced no certificate to pin")
        seen = hashlib.sha256(raw).hexdigest()
        # Constant time: the comparison is against a secret-shaped value an
        # operator pinned, and there is no reason to leak where it diverges.
        if not hmac.compare_digest(seen, self.fingerprint):
            raise PortainerError(
                "that Portainer presented a different certificate "
                f"({seen[:16]}… rather than {self.fingerprint[:16]}…)")

    # -- what a console asks for ------------------------------------------

    async def endpoints(self) -> list[dict]:
        raw = await self.call("GET", "/api/endpoints")
        out = []
        for entry in (raw if isinstance(raw, list) else [])[:MAX_ENDPOINTS]:
            if not isinstance(entry, dict):
                continue
            out.append({
                "id": _int(entry.get("Id")),
                "name": _text(entry.get("Name"), 96),
                "type": _int(entry.get("Type")),
                "url": _text(entry.get("URL"), 200),
            })
        return out

    async def stacks(self) -> list[dict]:
        raw = await self.call("GET", "/api/stacks")
        out = []
        for entry in (raw if isinstance(raw, list) else [])[:MAX_STACKS]:
            if not isinstance(entry, dict):
                continue
            git = entry.get("GitConfig") if isinstance(entry.get("GitConfig"), dict) else {}
            out.append({
                "id": _int(entry.get("Id")),
                "name": _text(entry.get("Name"), 96),
                "endpoint": _int(entry.get("EndpointId")),
                # 1 active, 2 inactive — Portainer's own numbering.
                "active": _int(entry.get("Status")) == 1,
                "swarm": _int(entry.get("Type")) == 1,
                "git": bool(git.get("URL")),
                "git_url": _text(git.get("URL"), 200),
                "git_ref": _text(git.get("ReferenceName"), 96),
            })
        return out

    async def file(self, stack_id: int) -> str:
        raw = await self.call("GET", f"/api/stacks/{_id(stack_id)}/file")
        content = raw.get("StackFileContent") if isinstance(raw, dict) else ""
        return _text(content, MAX_FILE)

    async def _detail(self, stack_id: int) -> dict:
        """What a redeploy has to hand back unchanged: the stack's environment
        and how its repository is reached. Read here, sent straight back, never
        part of an answer."""
        raw = await self.call("GET", f"/api/stacks/{_id(stack_id)}")
        raw = raw if isinstance(raw, dict) else {}
        env = []
        for entry in (raw.get("Env") if isinstance(raw.get("Env"), list) else [])[:MAX_ENV]:
            if isinstance(entry, dict) and isinstance(entry.get("name"), str) \
                    and isinstance(entry.get("value"), str):
                env.append({"name": entry["name"][:256], "value": entry["value"][:8192]})
        git = raw.get("GitConfig") if isinstance(raw.get("GitConfig"), dict) else {}
        auth = git.get("Authentication") if isinstance(git.get("Authentication"), dict) else None
        return {"env": env, "git": bool(git.get("URL")),
                "git_ref": _text(git.get("ReferenceName"), 256),
                "git_auth": auth is not None,
                "git_user": _text((auth or {}).get("Username"), 256)}

    async def _settled(self, stack_id: int, answer) -> None:
        """Wait out a deployment Portainer runs in the background.

        Recent versions answer a redeploy at once, with the stack still
        *deploying* (status 3), and recreate its containers afterwards. An
        update reported done at that moment is a page drawn in the middle of
        the recreation, and a failure nobody hears about."""
        status = _int(answer.get("Status")) if isinstance(answer, dict) else 0
        waited = 0.0
        while status == _DEPLOYING and waited < REDEPLOY_TIMEOUT:
            await asyncio.sleep(SETTLE_POLL)
            waited += SETTLE_POLL
            raw = await self.call("GET", f"/api/stacks/{_id(stack_id)}")
            raw = raw if isinstance(raw, dict) else {}
            status = _int(raw.get("Status"))
            history = raw.get("DeploymentStatus")
            last = history[-1] if isinstance(history, list) and history else {}
            message = _text(last.get("Message"), 200) if isinstance(last, dict) else ""
            if message and _int(last.get("Status")) not in (_ACTIVE, _DEPLOYING):
                raise PortainerError(f"Portainer could not deploy it: {message}")
        if status == _DEPLOYING:
            raise PortainerError("Portainer is still deploying it; look again later")

    async def act(self, stack_id: int, endpoint_id: int, action: str) -> dict:
        if action not in ("start", "stop"):
            raise PortainerError("that is not something to do to a stack")
        await self.call(
            "POST",
            f"/api/stacks/{_id(stack_id)}/{action}?endpointId={_id(endpoint_id)}",
            body={}, timeout=REDEPLOY_TIMEOUT)
        return {"stack": _id(stack_id), "action": action}

    async def redeploy(self, stack: dict) -> dict:
        """Bring one Portainer stack up to date, the way Portainer's own *Pull
        and redeploy* would.

        Two shapes, because Portainer has two: a stack it pulls from git is
        redeployed by fetching the reference again, and one whose file it holds
        is redeployed by handing that file back. Either way with the stack's
        own environment: Portainer *replaces* the environment with what a
        redeploy carries, so an empty list would wipe it. And a git stack whose
        credentials Portainer stored is asked to use them — saying "no
        authentication" makes it forget them."""
        stack_id, endpoint_id = _id(stack.get("id")), _id(stack.get("endpoint"))
        held = await self._detail(stack_id)
        if held["git"]:
            body = {"RepositoryReferenceName": held["git_ref"] or _text(stack.get("git_ref"), 96),
                    "RepositoryAuthentication": held["git_auth"],
                    "Env": held["env"], "PullImage": True, "Prune": False}
            if held["git_auth"]:
                body["RepositoryUsername"] = held["git_user"]
                body["RepositoryPassword"] = ""
            answer = await self.call(
                "PUT", f"/api/stacks/{stack_id}/git/redeploy?endpointId={endpoint_id}",
                body=body, timeout=REDEPLOY_TIMEOUT)
        else:
            content = await self.file(stack_id)
            if not content:
                raise PortainerError("Portainer holds no file for that stack")
            answer = await self.call(
                "PUT", f"/api/stacks/{stack_id}?endpointId={endpoint_id}",
                body={"StackFileContent": content, "Env": held["env"],
                      "Prune": False, "PullImage": True},
                timeout=REDEPLOY_TIMEOUT)
        await self._settled(stack_id, answer)
        return {"stack": _text(stack.get("name"), 96) or str(stack_id),
                "portainer_id": stack_id, "through": "portainer",
                "name": _text((answer or {}).get("Name") if isinstance(answer, dict)
                              else stack.get("name"), 96)}

    async def deploy(self, name: str, content: str, endpoint_id: int) -> dict:
        """A new standalone (compose) stack, from a file an operator wrote."""
        if not isinstance(name, str) or not re.match(r"\A[a-z0-9][a-z0-9_.-]{0,62}\Z", name):
            raise PortainerError("a Portainer stack name is lowercase, and short")
        body = _text(content, MAX_FILE)
        if not body.strip():
            raise PortainerError("that compose file is empty")
        answer = await self.call(
            "POST",
            f"/api/stacks/create/standalone/string?endpointId={_id(endpoint_id)}",
            body={"name": name, "stackFileContent": body, "env": []},
            timeout=REDEPLOY_TIMEOUT)
        return {"stack": _int((answer or {}).get("Id") if isinstance(answer, dict) else 0),
                "name": name}


async def probe(url: str) -> dict:
    """What answers at an address, before anything is trusted to it: the
    version Portainer reports without a token, and the fingerprint of the
    certificate it presents — for the operator to compare and pin.

    No credential is sent, so an impostor here learns nothing; and nothing it
    says is acted on until an operator pins what it showed."""
    address = clean_url(url)
    if not address:
        raise PortainerError("that is not a Portainer address")
    authority, host, port, secure = _split(address)
    context = None
    if secure:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=context), CALL_TIMEOUT)
    except (OSError, ssl.SSLError, asyncio.TimeoutError) as exc:
        raise PortainerError(f"nothing answered there ({type(exc).__name__})") from None
    fingerprint, version = "", ""
    try:
        if secure:
            sock = writer.get_extra_info("ssl_object")
            raw = sock.getpeercert(True) if sock is not None else None
            fingerprint = hashlib.sha256(raw).hexdigest() if raw else ""
        writer.write(build_request("GET", "/api/system/status", authority, b""))
        await writer.drain()
        status, _headers, data = await read_response(reader, CALL_TIMEOUT)
        if status == 200:
            parsed = json.loads(data)
            if isinstance(parsed, dict):
                version = _text(parsed.get("Version"), 32)
    except (OSError, ssl.SSLError, asyncio.TimeoutError, asyncio.IncompleteReadError,
            ValueError, DockerError):
        pass
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except (OSError, ssl.SSLError, asyncio.TimeoutError):
            pass
    if not version:
        raise PortainerError("that address answers, but not as Portainer")
    return {"url": address, "version": version, "fingerprint": fingerprint}


def local_endpoint(endpoints: list[dict]) -> int:
    """The environment that is this machine's own docker socket, else the first."""
    for entry in endpoints:
        if str(entry.get("url", "")).startswith("unix://"):
            return entry.get("id") or 0
    return endpoints[0].get("id", 0) if endpoints else 0


def match(stack: dict, listed: list[dict]) -> dict | None:
    """The Portainer record for a stack found on this machine.

    By id when the directory gave one — names are Portainer's to reuse across
    environments — and by name otherwise."""
    number = stack.get("portainer_id") or 0
    if number:
        for entry in listed:
            if entry.get("id") == number:
                return entry
        return None
    named = [entry for entry in listed if entry.get("name") == stack.get("name")]
    return named[0] if len(named) == 1 else None


def _int(value) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def _id(value) -> int:
    number = _int(value)
    if not 1 <= number <= 10_000_000:
        raise PortainerError("that is not a Portainer id")
    return number


def _text(value, limit: int) -> str:
    return value[:limit] if isinstance(value, str) else ""


def _message(data: bytes, status: int) -> str:
    try:
        parsed = json.loads(data)
        if isinstance(parsed, dict):
            for key in ("message", "details", "err"):
                if isinstance(parsed.get(key), str):
                    return parsed[key][:200]
    except ValueError:
        pass
    return f"Portainer refused that ({status})"
