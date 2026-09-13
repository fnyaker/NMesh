"""
Portainer — the manager a machine may already have in front of its docker.

Portainer deploys through compose and labels what it deploys, so its stacks are
already in the list this app builds from the running containers. What its API
adds is the two things the labels cannot give: the stack **file** (held by
Portainer, or in a git repository it pulls from) and the **redeploy** that
fetches it again. So a stack Portainer owns is updated *through* Portainer —
running `compose up` behind its back leaves its record stale, and the next thing
it does undoes the update.

What this holds, and why it is not much
---------------------------------------
One endpoint and one access token per node, kept in the fleet app's encrypted
drawer, **write-only** from the outside: an operator can set it and can see that
it is set, and nothing ever reads it back over the mesh. A token that could be
read back would make the `docker` capability a way of stealing the credential
rather than of using it.

TLS is verified. A Portainer on a private network very often has a self-signed
certificate, so there is a second way to accept one: **pin its fingerprint**.
That is an anchor an operator chose, which is the only kind of trust this
project has — where "just don't check" is not a setting, because a pinned
certificate is strictly more information than an unchecked one and costs the
same click.

Everything from the far side is hostile input, exactly as with the daemon: the
answers are large, deep, and written by something this node does not control, so
the shapes handed on are built field by field and bounded.
"""
from __future__ import annotations

import asyncio
import hashlib
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
    return f"{scheme}://{rest}"


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
        scheme, _, rest = self.url.partition("://")
        host, _, port = rest.rpartition(":")
        if not host or not port.isdigit():
            host, port = rest, "443" if scheme == "https" else "80"
        return rest, host.strip("[]"), int(port), scheme == "https"

    def _context(self) -> ssl.SSLContext | None:
        authority, _host, _port, secure = self._target()
        if not secure:
            return None
        context = ssl.create_default_context()
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
        import hmac
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

    async def act(self, stack_id: int, endpoint_id: int, action: str) -> dict:
        if action not in ("start", "stop"):
            raise PortainerError("that is not something to do to a stack")
        await self.call(
            "POST",
            f"/api/stacks/{_id(stack_id)}/{action}?endpointId={_id(endpoint_id)}",
            body={}, timeout=REDEPLOY_TIMEOUT)
        return {"stack": _id(stack_id), "action": action}

    async def redeploy(self, stack: dict) -> dict:
        """Bring one Portainer stack up to date, the way Portainer would.

        Two shapes, because Portainer has two: a stack it pulls from git is
        redeployed by fetching the reference again, and one whose file it holds
        is redeployed by handing that file back with `PullImage`. Guessing
        wrong is a stack that redeploys the version it already had."""
        stack_id, endpoint_id = _id(stack.get("id")), _id(stack.get("endpoint"))
        if stack.get("git"):
            answer = await self.call(
                "PUT", f"/api/stacks/{stack_id}/git/redeploy?endpointId={endpoint_id}",
                body={"RepositoryReferenceName": _text(stack.get("git_ref"), 96),
                      "RepositoryAuthentication": False, "PullImage": True,
                      "Prune": False},
                timeout=REDEPLOY_TIMEOUT)
        else:
            content = await self.file(stack_id)
            if not content:
                raise PortainerError("Portainer holds no file for that stack")
            answer = await self.call(
                "PUT", f"/api/stacks/{stack_id}?endpointId={endpoint_id}",
                body={"StackFileContent": content, "Env": [],
                      "Prune": False, "PullImage": True},
                timeout=REDEPLOY_TIMEOUT)
        return {"stack": stack_id,
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
