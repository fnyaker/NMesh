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

from . import fleet_ssh
from .fleet_ssh import SshCredentials, SshError

# The tree we ship. Everything a node needs to run, and nothing else — no state
# directory, no keys, no venv, no git history.
PAYLOAD_INCLUDE = ("src", "scripts", "start.sh", "requirements.txt",
                   "pyproject.toml")
PAYLOAD_EXCLUDE_DIRS = {"__pycache__", ".git", ".venv", "data", "tests"}
MAX_PAYLOAD = 16 * 1024 * 1024        # refuse to push an implausible tree
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
    if not {"src", "start.sh"} <= set(added):
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


def build_bootstrap(payload: bytes, preauth: dict, *,
                    install_dir: str | None = None,
                    service_name: str = "nmesh",
                    setup_only: bool = False) -> str:
    """Render the self-extracting ``/bin/sh`` script.

    Plain POSIX shell — the target may have no bash. Every step prints a
    ``::step::`` marker the caller turns into progress, and any failure exits
    non-zero at once (``set -eu``) rather than leaving a half-installed node."""
    encoded = base64.b64encode(payload).decode("ascii")
    digest = hashlib.sha256(payload).hexdigest()
    preauth_encoded = base64.b64encode(
        json.dumps(preauth, separators=(",", ":")).encode("utf-8")).decode("ascii")
    default_dir = install_dir or ""
    return _BOOTSTRAP.format(
        payload_b64=_wrap(encoded),
        preauth_b64=preauth_encoded,
        sha256=digest,
        install_dir=_sh_quote(default_dir),
        service=_sh_quote(service_name),
        preauth_name=_sh_quote(PREAUTH_FILENAME),
        setup_only="1" if setup_only else "0",
    )


def _wrap(text: str, width: int = 76) -> str:
    return "\n".join(text[i:i + width] for i in range(0, len(text), width))


_BOOTSTRAP = r"""#!/bin/sh
set -eu

say() {{ echo "::step::$1"; }}
die() {{ echo "::error::$1" >&2; exit 1; }}

INSTALL_DIR={install_dir}
SERVICE={service}
PREAUTH_NAME={preauth_name}
SETUP_ONLY={setup_only}
WANT_SHA={sha256}

# ---- 1. where do we install? ------------------------------------------------
if [ -z "$INSTALL_DIR" ]; then
    if [ "$(id -u)" = "0" ]; then INSTALL_DIR=/opt/nmesh; else INSTALL_DIR="$HOME/.nmesh"; fi
fi
say "install dir $INSTALL_DIR"

SUDO=""
if [ "$(id -u)" != "0" ]; then
    if command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1; then SUDO="sudo -n";
    elif command -v doas >/dev/null 2>&1; then SUDO="doas"; fi
fi

for tool in base64 tar gzip sha256sum; do
    command -v "$tool" >/dev/null 2>&1 || {{
        [ "$tool" = "sha256sum" ] && command -v shasum >/dev/null 2>&1 && continue
        die "missing required tool: $tool"
    }}
done

# ---- 2. unpack, after verifying the payload --------------------------------
WORK=$(mktemp -d) || die "cannot create temp dir"
chmod 700 "$WORK"
cleanup() {{ rm -rf "$WORK"; }}
trap cleanup EXIT INT TERM

say "receiving payload"
base64 -d > "$WORK/payload.tgz" <<'NMESH_PAYLOAD_EOF'
{payload_b64}
NMESH_PAYLOAD_EOF

if command -v sha256sum >/dev/null 2>&1; then
    GOT=$(sha256sum "$WORK/payload.tgz" | cut -d' ' -f1)
else
    GOT=$(shasum -a 256 "$WORK/payload.tgz" | cut -d' ' -f1)
fi
[ "$GOT" = "$WANT_SHA" ] || die "payload integrity check failed"
say "payload verified"

mkdir -p "$INSTALL_DIR" 2>/dev/null || $SUDO mkdir -p "$INSTALL_DIR"
if [ ! -w "$INSTALL_DIR" ]; then
    $SUDO chown "$(id -u):$(id -g)" "$INSTALL_DIR" || die "install dir not writable"
fi
tar -xzf "$WORK/payload.tgz" -C "$INSTALL_DIR" || die "unpack failed"
chmod +x "$INSTALL_DIR/start.sh" 2>/dev/null || true
say "unpacked"

# ---- 3. pre-authorisation (0600, consumed and deleted on first start) ------
mkdir -p "$INSTALL_DIR/data"
chmod 700 "$INSTALL_DIR/data"
OLD_UMASK=$(umask); umask 077
base64 -d > "$INSTALL_DIR/data/$PREAUTH_NAME" <<'NMESH_PREAUTH_EOF'
{preauth_b64}
NMESH_PREAUTH_EOF
umask "$OLD_UMASK"
chmod 600 "$INSTALL_DIR/data/$PREAUTH_NAME"
say "pre-authorisation written"

# ---- 4. dependencies -------------------------------------------------------
say "installing dependencies (this can take a while)"
cd "$INSTALL_DIR"
NMESH_SETUP_ONLY=1 ./start.sh || die "dependency setup failed"
say "dependencies ready"

[ "$SETUP_ONLY" = "1" ] && {{ say "setup-only: not installing a service"; exit 0; }}

# ---- 5. start at boot ------------------------------------------------------
PYTHON="$INSTALL_DIR/.venv/bin/python"
[ -x "$PYTHON" ] || PYTHON=$(command -v python3) || die "no python"

if command -v systemctl >/dev/null 2>&1 && [ -n "$SUDO$( [ "$(id -u)" = 0 ] && echo root )" ]; then
    say "installing systemd unit"
    UNIT=/etc/systemd/system/$SERVICE.service
    {{
        echo "[Unit]"
        echo "Description=NMesh node"
        echo "After=network-online.target"
        echo "Wants=network-online.target"
        echo ""
        echo "[Service]"
        echo "Type=simple"
        echo "User=$(id -un)"
        echo "WorkingDirectory=$INSTALL_DIR"
        echo "ExecStart=$PYTHON $INSTALL_DIR/scripts/nmesh_node.py --data $INSTALL_DIR/data"
        echo "Restart=always"
        echo "RestartSec=5"
        echo "NoNewPrivileges=yes"
        echo "PrivateTmp=yes"
        echo ""
        echo "[Install]"
        echo "WantedBy=multi-user.target"
    }} > "$WORK/unit"
    $SUDO cp "$WORK/unit" "$UNIT"
    $SUDO systemctl daemon-reload
    $SUDO systemctl enable "$SERVICE" >/dev/null 2>&1 || true
    $SUDO systemctl restart "$SERVICE"
    say "systemd service $SERVICE started"
elif command -v rc-update >/dev/null 2>&1; then
    say "installing OpenRC service"
    {{
        echo "#!/sbin/openrc-run"
        echo "command=$PYTHON"
        echo "command_args=\"$INSTALL_DIR/scripts/nmesh_node.py --data $INSTALL_DIR/data\""
        echo "command_background=true"
        echo "pidfile=/run/$SERVICE.pid"
        echo "name=$SERVICE"
    }} > "$WORK/rc"
    $SUDO cp "$WORK/rc" "/etc/init.d/$SERVICE"
    $SUDO chmod +x "/etc/init.d/$SERVICE"
    $SUDO rc-update add "$SERVICE" default >/dev/null 2>&1 || true
    $SUDO rc-service "$SERVICE" restart || $SUDO rc-service "$SERVICE" start
    say "openrc service $SERVICE started"
elif command -v launchctl >/dev/null 2>&1; then
    say "installing launchd agent"
    PLIST="$HOME/Library/LaunchAgents/org.nmesh.$SERVICE.plist"
    mkdir -p "$HOME/Library/LaunchAgents"
    {{
        echo '<?xml version="1.0" encoding="UTF-8"?>'
        echo '<plist version="1.0"><dict>'
        echo "<key>Label</key><string>org.nmesh.$SERVICE</string>"
        echo "<key>ProgramArguments</key><array>"
        echo "<string>$PYTHON</string>"
        echo "<string>$INSTALL_DIR/scripts/nmesh_node.py</string>"
        echo "<string>--data</string><string>$INSTALL_DIR/data</string>"
        echo "</array>"
        echo "<key>RunAtLoad</key><true/><key>KeepAlive</key><true/>"
        echo '</dict></plist>'
    }} > "$PLIST"
    launchctl unload "$PLIST" >/dev/null 2>&1 || true
    launchctl load "$PLIST"
    say "launchd agent started"
else
    say "no known init system — starting in the background (no boot persistence)"
    nohup "$PYTHON" "$INSTALL_DIR/scripts/nmesh_node.py" --data "$INSTALL_DIR/data" \
        >"$INSTALL_DIR/data/node.log" 2>&1 &
fi

say "done"
"""


# ---------------------------------------------------------------------------
# Driving one machine through it
# ---------------------------------------------------------------------------

async def provision_host(host: str, creds: SshCredentials, *,
                         payload: bytes, preauth: dict, port: int = 22,
                         known_hosts_lines: list[str] | None = None,
                         install_dir: str | None = None,
                         setup_only: bool = False,
                         timeout: float = PROVISION_TIMEOUT,
                         on_progress=None) -> dict:
    """Install NMesh on one machine and report what happened.

    Returns ``{"host", "ok", "steps", "status", "error"}``. Never raises for a
    remote failure — a machine that refuses to be provisioned is a result, not
    an exception, so a batch run keeps going."""
    script = build_bootstrap(payload, preauth, install_dir=install_dir,
                             setup_only=setup_only)
    steps: list[str] = []

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

    result = {"host": host, "ok": False, "steps": steps, "status": None,
              "error": None, "pinned": bool(known_hosts_lines)}
    if not known_hosts_lines:
        # No confirmed host key to pin, so this run falls back to accept-on-first
        # use. That is a real weakening (a machine in the middle would be
        # accepted once), so it is announced rather than done quietly.
        on_output("::step::warning: no host key to pin — trusting on first use\n")
    try:
        status, _output = await fleet_ssh.run(
            host, creds, ["/bin/sh", "-s"], port=port,
            known_hosts_lines=known_hosts_lines,
            stdin_data=script.encode("utf-8"), timeout=timeout,
            on_output=on_output)
    except SshError as exc:
        result["error"] = str(exc)
        return result
    except Exception as exc:                      # never let one host kill a batch
        result["error"] = f"{type(exc).__name__}: {exc}"[:256]
        return result
    result["status"] = status
    result["ok"] = status == 0 and any(s == "done" for s in steps)
    if not result["ok"] and result["error"] is None:
        failed = next((s for s in steps if s.startswith("error: ")), None)
        result["error"] = failed or f"bootstrap exited with status {status}"
    return result
