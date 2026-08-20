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

class SshCredentials:
    """One machine's login material, for one provisioning run.

    Deliberately not a dataclass and deliberately without ``__repr__``/
    ``__str__`` beyond a redacted form: an accidental ``print(creds)`` or an
    exception rendering its locals must not spill the secret. ``wipe()`` drops
    the references as soon as the run is over (CPython strings are immutable, so
    this releases rather than scrubs — the honest bound is "not kept", not
    "erased from RAM")."""

    __slots__ = ("username", "_password", "key_path", "_key_passphrase")

    def __init__(self, username: str, *, password: str | None = None,
                 key_path: str | None = None,
                 key_passphrase: str | None = None) -> None:
        if not username or len(username) > 64 or any(c.isspace() for c in username):
            raise SshError("invalid username")
        self.username = username
        self._password = password or None
        self.key_path = key_path or None
        self._key_passphrase = key_passphrase or None

    @property
    def has_password(self) -> bool:
        return self._password is not None

    @property
    def has_key(self) -> bool:
        return self.key_path is not None

    def wipe(self) -> None:
        self._password = None
        self._key_passphrase = None

    def __repr__(self) -> str:
        return (f"SshCredentials(username={self.username!r}, "
                f"password={'<set>' if self._password else None}, "
                f"key_path={self.key_path!r})")

    __str__ = __repr__


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
                  port: int) -> list[str]:
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
    if creds.has_key:
        options += ["-i", creds.key_path, "-o", "IdentitiesOnly=yes"]
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
              on_output=None) -> tuple[int, str]:
    """Run ``command`` (an argv list, never a shell string) on ``host``.

    Returns ``(exit_status, output)``. The password — if any — is written into
    the pty when OpenSSH asks for it and never appears anywhere else. Output is
    capped at :data:`MAX_OUTPUT`; ``on_output(chunk)`` streams it live.

    ``stdin_data`` is piped to the remote command through a separate pipe, so a
    provisioning payload never has to share the channel that carries the
    secret."""
    if not ssh_available():
        raise SshError("no ssh client on this host")
    if not command:
        raise SshError("empty command")
    with KnownHosts(known_hosts_lines or []) as known:
        argv = (["ssh"] + _base_options(known.path, creds, port)
                + [f"{creds.username}@{host}", "--"] + list(command))
        return await _spawn_with_pty(argv, creds, stdin_data, timeout, on_output)


async def _spawn_with_pty(argv: list[str], creds: SshCredentials,
                          stdin_data: bytes, timeout: float,
                          on_output) -> tuple[int, str]:
    """Spawn ssh with a controlling pty for prompts and a pipe for payload data.

    The pty is what makes the "secret never on disk, never in argv" property
    work: OpenSSH reads its prompts from the terminal, so the password crosses a
    kernel tty buffer into the child and nothing else ever holds it."""
    import pty

    parent_fd, child_fd = pty.openpty()
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
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
    prompts_answered = {"password": 0, "passphrase": 0}
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

    out_task = asyncio.create_task(pump_stdout())
    in_task = asyncio.create_task(feed_stdin())
    try:
        async with asyncio.timeout(timeout):
            status = await proc.wait()
    except asyncio.TimeoutError:
        _kill(proc)
        status = -1
        collected += b"\n[nmesh] timed out\n"
    finally:
        stop_tty()
        for task in (out_task, in_task):
            task.cancel()
        await asyncio.gather(out_task, in_task, return_exceptions=True)
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
    if any(marker in tail for marker in _PASSWORD_PROMPTS):
        if creds._password and answered["password"] == 0:
            answered["password"] += 1
            return creds._password.encode("utf-8") + b"\n"
        return None
    return None


def _kill(proc) -> None:
    try:
        proc.kill()
    except (ProcessLookupError, OSError):
        pass
