"""
Provisioning — turn a bare SSH-reachable machine into a managed mesh node.

One SSH session does the whole job. We build a **self-extracting bootstrap**: a
small ``/bin/sh`` script carrying a gzipped tar of the NMesh tree, which we pipe
into ``sh -s`` on the target. One authentication, one connection, nothing left
behind on the operator's disk.

What the bootstrap does, in order, announcing each step so the operator watches
it happen:

  1. unpack NMesh into an install directory (``/opt/nmesh`` as root, else
     ``~/.nmesh``) after checking the payload's SHA-256 — the archive is verified
     before a single file is written;
  2. run ``start.sh`` in setup-only mode, which already knows how to install
     dependencies on every supported distribution;
  3. drop a **pre-authorisation** file (0600) naming the operator, so the new
     node knows who provisioned it and trusts that identity on first start;
  4. install a boot service for the detected init system (systemd, OpenRC,
     runit or launchd) and start it.

The trust hand-off
------------------
The point of provisioning is that the new node ends up trusting the operator who
created it — without a human clicking "accept" on a machine that has no screen.
The pre-authorisation file carries the operator's **node id and public key**
(delivered over the authenticated SSH channel, which is the root of trust here)
plus a **single-use token**. On first start the new node enrols the operator with
the granted capabilities, proves possession of the token so the operator can bind
this brand-new mesh identity to the provisioning run it just performed, and then
deletes the file. The token is not a long-term secret: it exists to answer "is
the node that just appeared the one I provisioned?", once.

Nothing here ever holds the SSH credential: it belongs to
:mod:`src.apps.fleet_ssh`, lives in a pty for the length of the run, and is
wiped by the caller.
"""
from __future__ import annotations

import base64
import gzip
import hashlib
import io
import json
import os
import secrets
import tarfile
import time
from collections import deque

from . import fleet_ssh
from .fleet_ssh import SshCredentials, SshError

# The tree we ship. Everything a node needs to run, and nothing else — no state
# directory, no keys, no venv, no git history.
# `install.sh` is not optional here: the bootstrap hands the whole install over
# to it rather than reimplementing one, so a payload without it installs nothing.
PAYLOAD_INCLUDE = ("src", "scripts", "start.sh", "install.sh",
                   "requirements.txt", "pyproject.toml")
PAYLOAD_EXCLUDE_DIRS = {"__pycache__", ".git", ".venv", "data", "tests"}
MAX_PAYLOAD = 16 * 1024 * 1024        # refuse to push an implausible tree
# What a failed run keeps of the target's own output. Enough to see the error a
# package manager or a compiler printed, bounded because it comes from a machine
# we do not control.
_TAIL_LINES = 60
_TAIL_LINE_CHARS = 500
TOKEN_LEN = 32
PROVISION_TIMEOUT = 1800.0            # dependency builds are slow on small boxes

PREAUTH_FILENAME = "fleet_preauth.json"


class ProvisionError(Exception):
    pass


# ---------------------------------------------------------------------------
# Payload
# ---------------------------------------------------------------------------

def build_payload(root: str) -> bytes:
    """Gzipped tar of the NMesh tree at ``root``. Deterministic enough to hash
    and compare, bounded in size."""
    buffer = io.BytesIO()
    added = []
    # gzip stamps the current time into its header, so the same tree would hash
    # differently from one second to the next — and the bootstrap embeds that
    # hash. Pin mtime=0 so "same tree, same bytes" actually holds and an
    # operator can state exactly what they deployed.
    with gzip.GzipFile(fileobj=buffer, mode="wb", mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode="w") as archive:
            for entry in PAYLOAD_INCLUDE:
                path = os.path.join(root, entry)
                if not os.path.exists(path):
                    continue
                archive.add(path, arcname=entry, filter=_payload_filter)
                added.append(entry)
    # An empty tree still gzips to a valid (tiny) archive, which would push a
    # working bootstrap that installs nothing. Require the parts a node needs.
    if not {"src", "start.sh", "install.sh"} <= set(added):
        raise ProvisionError(f"no NMesh tree at {root}")
    data = buffer.getvalue()
    if len(data) > MAX_PAYLOAD:
        raise ProvisionError("payload too large")
    return data


def _payload_filter(info: tarfile.TarInfo):
    parts = set(info.name.split("/"))
    if parts & PAYLOAD_EXCLUDE_DIRS or info.name.endswith((".pyc", ".pyo")):
        return None
    # Normalise ownership/time so the same tree yields the same payload.
    info.uid = info.gid = 0
    info.uname = info.gname = "root"
    info.mtime = 0
    return info


def make_preauth(operator_id: bytes, operator_pub: bytes, *,
                 capabilities: list[str], join_uris: list[str],
                 join_code: str | None, label: str = "") -> tuple[dict, bytes]:
    """Build the pre-authorisation document and its single-use token.

    Returns ``(document, token)``. The **operator keeps** ``sha256(token)``; the
    token itself only ever exists in the payload and on the new node, where it is
    consumed once and deleted."""
    token = secrets.token_bytes(TOKEN_LEN)
    document = {
        "v": 1,
        "operator_id": operator_id.hex(),
        "operator_pub": operator_pub.hex(),
        "capabilities": sorted({str(c)[:32] for c in capabilities})[:16],
        "join_uris": [str(u)[:256] for u in join_uris][:8],
        "join_code": (join_code or "")[:64],
        "label": str(label)[:128],
        "token": token.hex(),
        "issued_at": int(time.time()),
    }
    return document, token


def token_digest(token: bytes) -> str:
    return hashlib.sha256(b"nmesh-fleet-preauth-v1" + token).hexdigest()


def read_preauth(path: str) -> dict | None:
    """Load a pre-authorisation file on the *new* node. Hostile-input safe: any
    problem yields None and the node simply starts unmanaged."""
    try:
        if os.path.getsize(path) > 64 * 1024:
            return None
        with open(path, encoding="utf-8") as handle:
            document = json.load(handle)
    except (OSError, ValueError):
        return None
    return parse_preauth(document)


def parse_preauth(document) -> dict | None:
    """Validate a pre-authorisation document. Returns the decoded fields, or
    None if anything about it is off — the node then simply starts unmanaged
    rather than trusting a half-understood grant."""
    if not isinstance(document, dict) or document.get("v") != 1:
        return None
    try:
        operator_id = bytes.fromhex(str(document.get("operator_id", "")))
        operator_pub = bytes.fromhex(str(document.get("operator_pub", "")))
        token = bytes.fromhex(str(document.get("token", "")))
    except ValueError:
        return None
    if len(operator_id) != 20 or not operator_pub or len(token) != TOKEN_LEN:
        return None
    # The operator's id must derive from the key shipped with it, exactly as
    # everywhere else in the tree — a mismatch means a tampered file.
    if hashlib.sha256(operator_pub).digest()[:20] != operator_id:
        return None
    capabilities = document.get("capabilities")
    join_uris = document.get("join_uris")
    return {
        "operator_id": operator_id,
        "operator_pub": operator_pub,
        "token": token,
        "capabilities": [c for c in capabilities if isinstance(c, str)][:16]
                        if isinstance(capabilities, list) else [],
        "join_uris": [u for u in join_uris if isinstance(u, str)][:8]
                     if isinstance(join_uris, list) else [],
        "join_code": str(document.get("join_code") or "")[:64],
        "label": str(document.get("label") or "")[:128],
    }


# ---------------------------------------------------------------------------
# The bootstrap script
# ---------------------------------------------------------------------------

def _sh_quote(value: str) -> str:
    """POSIX single-quote escaping. Every interpolated value goes through this;
    none of them come from the network, and this keeps it that way even if one
    day one does."""
    return "'" + str(value).replace("'", "'\\''") + "'"


def build_bootstrap(payload: bytes, preauth: dict, *, stage: str) -> str:
    """Phase one: the self-extracting delivery script, piped in on stdin.

    Plain POSIX shell — the target may have no bash. Every step prints a
    ``::step::`` marker the caller turns into progress, and any failure exits
    non-zero at once (``set -eu``) rather than leaving a half-installed node."""
    encoded = base64.b64encode(payload).decode("ascii")
    digest = hashlib.sha256(payload).hexdigest()
    preauth_encoded = base64.b64encode(
        json.dumps(preauth, separators=(",", ":")).encode("utf-8")).decode("ascii")
    return _BOOTSTRAP.format(
        payload_b64=_wrap(encoded),
        preauth_b64=preauth_encoded,
        sha256=digest,
        stage=_sh_quote(stage),
        preauth_name=_sh_quote(PREAUTH_FILENAME),
    )


def build_install_phase(*, stage: str, install_dir: str | None = None,
                        data_dir: str | None = None,
                        service_name: str = "nmesh",
                        setup_only: bool = False,
                        mode: str = "system",
                        sudo_user: str | None = None,
                        can_sudo: bool = True) -> str:
    """Phase two: escalate and install, run under a remote terminal.

    ``mode`` is ``"system"`` (a dedicated service account under ``/opt``, what a
    machine meant to host a node should get) or ``"user"`` (the login account's
    own home, where root is not available or not wanted). This script installs
    nothing itself: it calls the delivered tree's ``install.sh``, so a remote
    deploy and a local one are the same install."""
    if mode not in ("system", "user"):
        raise ProvisionError("install mode must be 'system' or 'user'")
    return _INSTALL_PHASE.format(
        stage=_sh_quote(stage),
        install_dir=_sh_quote(install_dir or ""),
        data_dir=_sh_quote(data_dir or ""),
        service=_sh_quote(service_name),
        preauth_name=_sh_quote(PREAUTH_FILENAME),
        setup_only="1" if setup_only else "0",
        mode=_sh_quote(mode),
        sudo_user=_sh_quote(sudo_user or ""),
        can_sudo="1" if can_sudo else "0",
    )


def staging_name() -> str:
    """A fresh, unguessable staging directory *name*, under the login home.

    A name rather than a path because the scripts prefix it with ``$HOME``
    themselves — quoting it here would stop the shell expanding that.
    Unguessable so a hostile local user on the target cannot pre-create it and
    have us unpack into somewhere they control."""
    return f".nmesh-deploy-{secrets.token_hex(8)}"


def _wrap(text: str, width: int = 76) -> str:
    return "\n".join(text[i:i + width] for i in range(0, len(text), width))


_BOOTSTRAP = r"""#!/bin/sh
# Phase one: deliver and verify. Runs as the login user, needs no privilege, and
# leaves everything in one staging directory the second phase consumes. It is
# piped in on stdin, so nothing here may ever want a terminal.
set -eu

say() {{ echo "::step::$1"; }}
die() {{ echo "::error::$1" >&2; exit 1; }}

STAGE="$HOME"/{stage}
PREAUTH_NAME={preauth_name}
WANT_SHA={sha256}

for tool in base64 tar gzip sha256sum; do
    command -v "$tool" >/dev/null 2>&1 || {{
        [ "$tool" = "sha256sum" ] && command -v shasum >/dev/null 2>&1 && continue
        die "missing required tool: $tool"
    }}
done

rm -rf "$STAGE"
mkdir -p "$STAGE" || die "cannot create $STAGE"
chmod 700 "$STAGE"

say "receiving payload"
base64 -d > "$STAGE/payload.tgz" <<'NMESH_PAYLOAD_EOF'
{payload_b64}
NMESH_PAYLOAD_EOF

if command -v sha256sum >/dev/null 2>&1; then
    GOT=$(sha256sum "$STAGE/payload.tgz" | cut -d' ' -f1)
else
    GOT=$(shasum -a 256 "$STAGE/payload.tgz" | cut -d' ' -f1)
fi
[ "$GOT" = "$WANT_SHA" ] || {{ rm -rf "$STAGE"; die "payload integrity check failed"; }}
say "payload verified"

mkdir -p "$STAGE/tree"
tar -xzf "$STAGE/payload.tgz" -C "$STAGE/tree" || die "unpack failed"
rm -f "$STAGE/payload.tgz"
chmod +x "$STAGE/tree/start.sh" "$STAGE/tree/install.sh" 2>/dev/null || true
[ -x "$STAGE/tree/install.sh" ] \
    || die "payload has no install.sh — the node that sent this is too old"
say "unpacked"

OLD_UMASK=$(umask); umask 077
base64 -d > "$STAGE/$PREAUTH_NAME" <<'NMESH_PREAUTH_EOF'
{preauth_b64}
NMESH_PREAUTH_EOF
umask "$OLD_UMASK"
chmod 600 "$STAGE/$PREAUTH_NAME"
say "pre-authorisation written"
say "staged"
"""


# Phase two runs under a *remote* terminal so `sudo` and `su` can ask for their
# password there — the same local pty that answers OpenSSH answers them. That is
# the whole reason this is two invocations instead of one: embedding the
# escalation password in the script would put a secret somewhere it has never
# been, and this project's rule is that it lives in a terminal or nowhere.
_INSTALL_PHASE = r"""set -eu
say() {{ echo "::step::$1"; }}
die() {{ echo "::error::$1" >&2; exit 1; }}

STAGE="$HOME"/{stage}
# INSTALL_DIR, never PREFIX: Termux exports PREFIX (its own prefix), assigning
# to it keeps it exported, and install.sh and start.sh below would then be told
# an Android target is a Debian box.
INSTALL_DIR={install_dir}
DATA={data_dir}
SERVICE={service}
PREAUTH_NAME={preauth_name}
SETUP_ONLY={setup_only}
MODE={mode}
SUDO_USER_NAME={sudo_user}
CAN_SUDO={can_sudo}

[ -d "$STAGE/tree" ] || die "staging directory is gone"
cleanup() {{ rm -rf "$STAGE"; }}
trap cleanup EXIT INT TERM

# ---- how do we reach root? --------------------------------------------------
# Escalation is never guessed: the operator said whether this login can sudo and
# named another account if it cannot. Probing would mean failed sudo attempts in
# the target's own auth log.
ELEVATE=""
if [ "$MODE" = "system" ] && [ "$(id -u)" != "0" ]; then
    if [ -n "$SUDO_USER_NAME" ]; then
        command -v su >/dev/null 2>&1 || die "no su on this machine"
        ELEVATE="su_other"
    elif [ "$CAN_SUDO" = "1" ]; then
        command -v sudo >/dev/null 2>&1 || die "no sudo on this machine"
        if sudo -n true >/dev/null 2>&1; then ELEVATE="sudo_n"; else ELEVATE="sudo_pw"; fi
    else
        die "a system install needs root: tick 'can sudo', name a sudo account, or install under the login user"
    fi
fi

elevated() {{
    case "$ELEVATE" in
        "")        sh -c "$1";;
        sudo_n)    sudo -n sh -c "$1";;
        sudo_pw)   sudo sh -c "$1";;
        su_other)  su - "$SUDO_USER_NAME" -c "$1";;
    esac
}}

# ---- where does it go? ------------------------------------------------------
if [ -z "$INSTALL_DIR" ]; then
    if [ "$MODE" = "system" ]; then INSTALL_DIR=/opt/nmesh; else INSTALL_DIR="$HOME/.nmesh"; fi
fi
if [ -z "$DATA" ]; then
    if [ "$MODE" = "system" ]; then DATA=/var/lib/nmesh; else DATA="$INSTALL_DIR/data"; fi
fi
say "install dir $INSTALL_DIR (state in $DATA)"

# The pre-authorisation goes in before install.sh runs, so its lock-down hands
# it to the node's own account with the rest of the state directory.
elevated "mkdir -p '$DATA' && chmod 700 '$DATA' && cp '$STAGE/$PREAUTH_NAME' '$DATA/$PREAUTH_NAME' && chmod 600 '$DATA/$PREAUTH_NAME'" \
    || die "cannot write the pre-authorisation into $DATA"

# ---- hand over to install.sh ------------------------------------------------
# Dependencies, the dedicated service account, file modes, the boot service, the
# liboqs cache: all install.sh's job. Nothing here reimplements any of it — a
# second, weaker installer is exactly how a remote deploy ends up less solid
# than a local one.
ARGS="--prefix '$INSTALL_DIR' --data '$DATA' --service '$SERVICE'"
[ "$MODE" = "user" ] && ARGS="$ARGS --run-as '$(id -un)'"
[ "$SETUP_ONLY" = "1" ] && ARGS="$ARGS --no-start"

say "running install.sh (dependencies can take a while)"
# Streamed, not swallowed: "dependency setup failed" with nothing behind it is a
# dead end for whoever has to fix it.
elevated "cd '$STAGE/tree' && ./install.sh $ARGS 2>&1" || die "install.sh failed — see the output above"

say "done"
"""


# ---------------------------------------------------------------------------
# Driving one machine through it
# ---------------------------------------------------------------------------

async def provision_host(host: str, creds: SshCredentials, *,
                         payload: bytes, preauth: dict, port: int = 22,
                         known_hosts_lines: list[str] | None = None,
                         install_dir: str | None = None,
                         data_dir: str | None = None,
                         setup_only: bool = False,
                         mode: str = "system",
                         run_as: str | None = None,
                         timeout: float = PROVISION_TIMEOUT,
                         on_progress=None) -> dict:
    """Install NMesh on one machine and report what happened.

    Returns ``{"host", "ok", "steps", "status", "error"}``. Never raises for a
    remote failure — a machine that refuses to be provisioned is a result, not
    an exception, so a batch run keeps going."""
    stage = staging_name()
    delivery = build_bootstrap(payload, preauth, stage=stage)
    install = build_install_phase(
        stage=stage, install_dir=install_dir, data_dir=data_dir,
        setup_only=setup_only, mode=mode,
        sudo_user=creds.sudo_user, can_sudo=creds.can_sudo)
    steps: list[str] = []
    # The last lines the remote actually printed. Markers alone say *that*
    # something failed; this says what — "dependency setup failed" with no
    # output behind it leaves whoever has to fix it with nowhere to start.
    tail: deque = deque(maxlen=_TAIL_LINES)

    def on_output(text: str) -> None:
        for line in text.splitlines():
            marker = line.strip()
            if marker.startswith("::step::") or marker.startswith("::error::"):
                steps.append(marker[8:] if marker.startswith("::step::")
                             else "error: " + marker[9:])
                if on_progress is not None:
                    try:
                        on_progress(host, steps[-1])
                    except Exception:
                        pass
            elif marker:
                tail.append(marker[:_TAIL_LINE_CHARS])

    result = {"host": host, "ok": False, "steps": steps, "status": None,
              "error": None, "pinned": bool(known_hosts_lines), "output": []}
    if not known_hosts_lines:
        # No confirmed host key to pin, so this run falls back to accept-on-first
        # use. That is a real weakening (a machine in the middle would be
        # accepted once), so it is announced rather than done quietly.
        on_output("::step::warning: no host key to pin — trusting on first use\n")
    # Two invocations, deliberately. The payload is piped into the first, which
    # needs no privilege and must not want a terminal; the second asks for one so
    # `sudo`/`su` can prompt there and the local pty can answer — the escalation
    # secret never enters a script, which is the same rule the SSH password
    # follows.
    try:
        status, _output = await fleet_ssh.run(
            host, creds, ["/bin/sh", "-s"], port=port,
            known_hosts_lines=known_hosts_lines,
            stdin_data=delivery.encode("utf-8"), timeout=timeout,
            on_output=on_output)
        if status != 0 or not any(s == "staged" for s in steps):
            result["status"] = status
            result["output"] = list(tail)
            failed = next((s for s in steps if s.startswith("error: ")), None)
            result["error"] = failed or f"delivery exited with status {status}"
            return result
        status, _output = await fleet_ssh.run(
            host, creds, ["/bin/sh", "-c", install], port=port,
            known_hosts_lines=known_hosts_lines,
            request_tty=True, timeout=timeout, on_output=on_output)
    except SshError as exc:
        result["error"] = str(exc)
        return result
    except Exception as exc:                      # never let one host kill a batch
        result["error"] = f"{type(exc).__name__}: {exc}"[:256]
        return result
    result["status"] = status
    result["ok"] = status == 0 and any(s == "done" for s in steps)
    if not result["ok"]:
        # Only on failure: a successful run's output is noise, and it is the
        # target machine's output — bounded before it is kept, like anything
        # else that arrives from outside this process.
        result["output"] = list(tail)
        if result["error"] is None:
            failed = next((s for s in steps if s.startswith("error: ")), None)
            result["error"] = failed or f"bootstrap exited with status {status}"
    return result
