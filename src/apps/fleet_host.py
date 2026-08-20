"""
Host facts & maintenance plans — what this machine *is*, and how to update it.

The fleet app manages heterogeneous machines: an operator asking "update this
node" cannot know whether the target speaks apt, dnf, pacman, apk or brew. So
each managed node describes itself, once, and derives its own maintenance plan.
Detection happens when the fleet app first starts (the app's "install" moment)
and is cached in the app drawer; ``refresh()`` re-runs it on demand.

stdlib only, and deliberately read-only: everything here either reads
``/etc/os-release``, ``/proc``, ``os.statvfs`` or looks a binary up on ``PATH``.
Nothing in this module executes a package manager — it only *names* the command
the fleet app would run, so the decision to run it stays with the caller (and
with the capability check in front of it).

Robustness: every probe is wrapped. A machine with no ``/proc``, an unreadable
mount, a truncated ``os-release`` or an exotic init system yields a partial
snapshot with ``None`` fields, never an exception. A node that cannot describe
itself must still stay manageable.
"""
from __future__ import annotations

import os
import platform
import shutil
import socket
import time
from dataclasses import asdict, dataclass, field

# Package managers we know how to drive, most specific first. Each entry maps to
# the argv (never a shell string — no quoting surface) for refresh and upgrade.
_PACKAGE_MANAGERS = [
    ("apt", "apt-get", {
        "refresh": ["apt-get", "update", "-qq"],
        "upgrade": ["apt-get", "-y", "-o", "Dpkg::Options::=--force-confold",
                    "dist-upgrade"],
    }),
    ("dnf", "dnf", {
        "refresh": ["dnf", "-q", "makecache"],
        "upgrade": ["dnf", "-y", "upgrade"],
    }),
    ("yum", "yum", {
        "refresh": ["yum", "-q", "makecache"],
        "upgrade": ["yum", "-y", "update"],
    }),
    ("pacman", "pacman", {
        "refresh": ["pacman", "-Sy", "--noconfirm"],
        "upgrade": ["pacman", "-Su", "--noconfirm"],
    }),
    ("zypper", "zypper", {
        "refresh": ["zypper", "--non-interactive", "refresh"],
        "upgrade": ["zypper", "--non-interactive", "update"],
    }),
    ("apk", "apk", {
        "refresh": ["apk", "update"],
        "upgrade": ["apk", "upgrade"],
    }),
    ("xbps", "xbps-install", {
        "refresh": ["xbps-install", "-S"],
        "upgrade": ["xbps-install", "-yu"],
    }),
    ("brew", "brew", {
        "refresh": ["brew", "update"],
        "upgrade": ["brew", "upgrade"],
    }),
    ("pkg", "pkg", {          # FreeBSD
        "refresh": ["pkg", "update"],
        "upgrade": ["pkg", "upgrade", "-y"],
    }),
]

# Init systems, in the order we probe for them.
_INIT_SYSTEMS = [
    ("systemd", "systemctl"),
    ("openrc", "rc-service"),
    ("runit", "sv"),
    ("launchd", "launchctl"),
    ("s6", "s6-svc"),
]

_MAX_DISKS = 16            # mountpoints reported (bounded output)
_MAX_FIELD = 256           # any single string field we echo back


def _clip(value: str | None) -> str | None:
    """Bound a string read from the host. os-release is a file an attacker with
    local write access controls; we never echo an unbounded field onto the mesh."""
    if not isinstance(value, str):
        return None
    value = value.strip().strip('"').strip("'")
    return value[:_MAX_FIELD] or None


def read_os_release(path: str = "/etc/os-release") -> dict:
    """Parse ``os-release`` into a bounded dict. Empty on any problem."""
    out: dict[str, str] = {}
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            for line in handle:
                if len(out) >= 64:
                    break
                key, sep, value = line.partition("=")
                cleaned = _clip(value) if sep else None
                if cleaned is not None:
                    out[key.strip()[:_MAX_FIELD]] = cleaned
    except (OSError, UnicodeError):
        return {}
    return out


def detect_package_manager() -> tuple[str | None, dict]:
    """Return ``(name, plan)`` for the first package manager on PATH."""
    for name, binary, plan in _PACKAGE_MANAGERS:
        if shutil.which(binary):
            return name, dict(plan)
    return None, {}


def detect_init_system() -> str | None:
    for name, binary in _INIT_SYSTEMS:
        if shutil.which(binary):
            return name
    return None


def _privilege_escalation() -> str | None:
    """How this node would gain root for a package operation. ``None`` means it
    already is root; ``"none"`` means it has no way to escalate (so an update
    request is refused up front rather than half-run)."""
    try:
        if os.geteuid() == 0:
            return None
    except AttributeError:
        return None  # non-POSIX: no notion of euid here
    for candidate in ("sudo", "doas"):
        if shutil.which(candidate):
            return candidate
    return "none"


@dataclass
class HostFacts:
    """A machine's self-description. Cached at app install, refreshable."""

    hostname: str | None = None
    system: str | None = None            # Linux / Darwin / FreeBSD …
    kernel: str | None = None
    arch: str | None = None
    distro_id: str | None = None         # os-release ID (debian, fedora…)
    distro_name: str | None = None       # os-release PRETTY_NAME
    distro_version: str | None = None
    package_manager: str | None = None
    init_system: str | None = None
    escalation: str | None = None        # None = already root, "sudo"/"doas"/"none"
    python: str | None = None
    detected_at: float = 0.0
    plan: dict = field(default_factory=dict)   # package-manager argv, see above

    def as_dict(self) -> dict:
        return asdict(self)

    @property
    def can_update(self) -> bool:
        """True when this node has both a package manager and a way to be root."""
        return bool(self.package_manager) and self.escalation != "none"


def detect() -> HostFacts:
    """Probe the machine. Never raises: an unknown field stays ``None``."""
    facts = HostFacts(detected_at=time.time())
    try:
        facts.hostname = _clip(socket.gethostname())
    except OSError:
        pass
    try:
        facts.system = _clip(platform.system())
        facts.kernel = _clip(platform.release())
        facts.arch = _clip(platform.machine())
        facts.python = _clip(platform.python_version())
    except Exception:
        pass
    release = read_os_release()
    facts.distro_id = release.get("ID")
    facts.distro_name = release.get("PRETTY_NAME") or release.get("NAME")
    facts.distro_version = release.get("VERSION_ID") or release.get("VERSION")
    if facts.distro_name is None and facts.system == "Darwin":
        try:
            facts.distro_name = _clip(f"macOS {platform.mac_ver()[0]}")
        except Exception:
            pass
    facts.package_manager, facts.plan = detect_package_manager()
    facts.init_system = detect_init_system()
    facts.escalation = _privilege_escalation()
    return facts


def update_argv(facts: HostFacts) -> list[list[str]] | None:
    """The exact commands an update would run on this host, in order.

    Returns ``None`` when the host cannot be updated (no known package manager,
    or no path to root) — the caller refuses the request instead of starting
    something it cannot finish. Each command is an **argv list**, never a shell
    string: there is no quoting or injection surface anywhere in this path."""
    if not facts.can_update:
        return None
    steps = [facts.plan.get("refresh"), facts.plan.get("upgrade")]
    commands = [list(step) for step in steps if step]
    if not commands:
        return None
    if facts.escalation in ("sudo", "doas"):
        prefix = [facts.escalation, "-n"] if facts.escalation == "sudo" else [facts.escalation]
        commands = [prefix + command for command in commands]
    return commands


# ---------------------------------------------------------------------------
# Live status (disk / cpu / memory / uptime)
# ---------------------------------------------------------------------------

def _uptime_seconds() -> float | None:
    try:
        with open("/proc/uptime") as handle:
            return float(handle.read().split()[0])
    except (OSError, ValueError, IndexError):
        pass
    try:                                    # BSD / macOS
        import subprocess
        out = subprocess.run(["sysctl", "-n", "kern.boottime"], capture_output=True,
                             text=True, timeout=2).stdout
        marker = out.split("sec = ")[1].split(",")[0]
        return max(0.0, time.time() - float(marker))
    except Exception:
        return None


def _memory() -> dict:
    """Total / available / used bytes. Linux ``/proc/meminfo``, else sysconf."""
    info: dict[str, int | None] = {"total": None, "available": None, "used": None}
    try:
        values = {}
        with open("/proc/meminfo") as handle:
            for line in handle:
                key, _, rest = line.partition(":")
                parts = rest.split()
                if parts:
                    values[key] = int(parts[0]) * 1024     # kB → bytes
        info["total"] = values.get("MemTotal")
        info["available"] = values.get("MemAvailable")
    except (OSError, ValueError):
        try:
            info["total"] = (os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES"))
        except (ValueError, OSError, AttributeError):
            pass
    if info["total"] is not None and info["available"] is not None:
        info["used"] = max(0, info["total"] - info["available"])
    return info


def _mountpoints() -> list[str]:
    """Real, local filesystems worth reporting — bounded, pseudo-fs skipped."""
    skip_types = {"proc", "sysfs", "devtmpfs", "devpts", "tmpfs", "cgroup",
                  "cgroup2", "overlay", "squashfs", "securityfs", "debugfs",
                  "tracefs", "mqueue", "hugetlbfs", "fusectl", "configfs",
                  "pstore", "bpf", "autofs", "binfmt_misc", "nsfs", "ramfs"}
    points: list[str] = []
    try:
        with open("/proc/mounts") as handle:
            for line in handle:
                fields = line.split()
                if len(fields) < 3 or fields[2] in skip_types:
                    continue
                point = fields[1]
                if point not in points:
                    points.append(point)
                if len(points) >= _MAX_DISKS:
                    break
    except OSError:
        pass
    return points or ["/"]


def _disks() -> list[dict]:
    out = []
    for point in _mountpoints():
        try:
            stat = os.statvfs(point)
        except OSError:
            continue          # unreadable / disappeared mount — skip, never fail
        total = stat.f_blocks * stat.f_frsize
        free = stat.f_bavail * stat.f_frsize
        if total <= 0:
            continue
        out.append({
            "mount": point[:_MAX_FIELD],
            "total": total,
            "free": free,
            "used": max(0, total - stat.f_bfree * stat.f_frsize),
        })
    return out[:_MAX_DISKS]


def _load_average() -> list[float] | None:
    try:
        return [round(value, 2) for value in os.getloadavg()]
    except (OSError, AttributeError):
        return None


def collect_status(facts: HostFacts | None = None) -> dict:
    """A full status snapshot: identity, uptime, load, memory, disks.

    Every field is optional — a probe that fails contributes ``None`` and the
    snapshot still goes out. A managed node that cannot measure its disks is
    still a managed node."""
    snapshot = {
        "at": time.time(),
        "hostname": None,
        "uptime": _uptime_seconds(),
        "boot_time": None,
        "cpu_count": os.cpu_count(),
        "load": _load_average(),
        "memory": _memory(),
        "disks": _disks(),
    }
    try:
        snapshot["hostname"] = _clip(socket.gethostname())
    except OSError:
        pass
    if snapshot["uptime"] is not None:
        snapshot["boot_time"] = time.time() - snapshot["uptime"]
    if facts is not None:
        snapshot["host"] = {
            "system": facts.system,
            "distro": facts.distro_name,
            "kernel": facts.kernel,
            "arch": facts.arch,
            "package_manager": facts.package_manager,
            "init_system": facts.init_system,
            "can_update": facts.can_update,
        }
    return snapshot
