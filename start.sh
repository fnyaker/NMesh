#!/usr/bin/env bash
#
# NMesh — launcher script (fully autonomous)
#
# Detects the OS, installs system build tools, creates a venv, installs Python
# dependencies, verifies everything, then launches the node with the web console.
#
#   ./start.sh                                  # node + console, UDP + STUN auto
#   ./start.sh --no-udp                         # disable UDP hole punching
#   ./start.sh --connector-port 8790            # also expose the data connector
#   ./start.sh --spool /mnt/usb/mesh            # add a store-and-forward link
#   ./start.sh --console-host 0.0.0.0           # reach the console from the LAN
#
# Any extra arguments are passed straight to scripts/nmesh_node.py.
#
# Environment switches:
#   NMESH_SETUP_ONLY=1   install and verify everything, then stop (no node)
#   NMESH_VENV=path      virtualenv location (default .venv)
#   NMESH_DATA=path      node state directory (default ./data)
#   OQS_INSTALL_PATH     where liboqs is installed (default ~/_oqs)
#
# Everything above the "MAIN" banner is definitions only: the test-suite sources
# this file with NMESH_START_LIB=1 to exercise them without installing anything.
set -euo pipefail
cd "$(dirname "$0")"

# ── colours ──────────────────────────────────────────────────────────────────
if [ -t 1 ]; then
    G='\033[1;32m'; R='\033[1;31m'; Y='\033[1;33m'; B='\033[1;34m'; N='\033[0m'
else
    G=''; R=''; Y=''; B=''; N=''
fi

ok()   { echo -e "${G}[✓]${N} $*"; }
fail() { echo -e "${R}[✗]${N} $*"; exit 1; }
info() { echo -e "${B}[i]${N} $*"; }
warn() { echo -e "${Y}[!]${N} $*"; }

# ── where "home" is when there is no session ─────────────────────────────────
# A node started by a service manager inherits almost nothing: no HOME, often no
# USER. Under `set -u` a bare $HOME then aborts the script outright — which is
# exactly how a systemd-started node died on "HOME: unbound variable", restart
# after restart. Resolve a directory we can actually write to instead: the
# environment if it is usable, the account's own passwd entry otherwise, and
# failing that the install directory, which belongs to the node by construction
# (step 0 above cd'd into it).
node_home() {
    if [ -n "${HOME:-}" ] && [ -d "${HOME:-}" ] && [ -w "${HOME:-}" ]; then
        echo "$HOME"; return
    fi
    local entry=""
    if command -v getent >/dev/null 2>&1; then
        entry="$(getent passwd "$(id -u)" 2>/dev/null | cut -d: -f6)" || entry=""
    fi
    if [ -n "$entry" ] && [ -d "$entry" ] && [ -w "$entry" ]; then
        echo "$entry"; return
    fi
    pwd
}

# ── package manager abstraction ──────────────────────────────────────────────
# Distros disagree on everything that matters here: whether pip and venv ship
# with the interpreter (Debian, Alpine and Arch split them out), whether pip may
# touch the system at all (PEP 668 marks Debian ≥12, Ubuntu ≥23.04, Fedora ≥38,
# Arch, openSUSE and Homebrew as "externally managed"), and how packages are
# named. Everything distro-specific lives in this section; the rest of the
# script only asks for capabilities.

# os-release is authoritative about the distro; the binary scan is only a
# fallback, since a stray apt-get or a container with several tools installed
# would otherwise decide for us.
family_from_id() {
    case "$1" in
        ubuntu|debian|linuxmint|pop|elementary|zorin|raspbian|kali|devuan|neon|debian-*) echo apt;;
        fedora|rhel|centos|rocky|almalinux|ol|amzn|nobara|scientific) echo dnf;;
        arch|manjaro|endeavouros|garuda|arcolinux|artix|cachyos) echo pacman;;
        opensuse|opensuse-leap|opensuse-tumbleweed|sles|sled|suse) echo zypper;;
        alpine|postmarketos) echo apk;;
        void) echo xbps;;
        *) echo "";;
    esac
}

detect_os() {
    OS_ID=""; OS_LIKE=""
    local release="${OS_RELEASE_FILE:-/etc/os-release}"
    if [ -r "$release" ]; then
        # shellcheck disable=SC1091
        . "$release"
        OS_ID="${ID:-}"; OS_LIKE="${ID_LIKE:-}"
    fi
    OS_KERNEL="$(uname -s)"

    # NixOS and Gentoo build their environment declaratively — running a
    # package manager behind the user's back is wrong there.
    case "$OS_ID" in
        nixos)  PKG=nix;    return;;
        gentoo) PKG=gentoo; return;;
    esac

    # Termux (Android) has no sudo and its own prefix.
    if [ -n "${PREFIX:-}" ] && [ -x "${PREFIX}/bin/pkg" ]; then PKG=termux; return; fi

    if [ "$OS_KERNEL" = "Darwin" ]; then PKG=brew; return; fi
    if [ "$OS_KERNEL" = "FreeBSD" ]; then PKG=freebsd; return; fi

    local family=""
    family="$(family_from_id "$OS_ID")"
    if [ -z "$family" ]; then
        local like
        for like in $OS_LIKE; do
            family="$(family_from_id "$like")"
            [ -n "$family" ] && break
        done
    fi
    # RHEL 7 / CentOS 7 predate dnf.
    if [ "$family" = dnf ] && ! command -v dnf &>/dev/null && command -v yum &>/dev/null; then
        family=yum
    fi
    if [ -n "$family" ]; then PKG="$family"; return; fi

    # Unnamed or exotic distro: trust whatever tool is actually installed.
    local candidate
    for candidate in apt-get dnf zypper pacman apk xbps-install yum; do
        if command -v "$candidate" &>/dev/null; then
            case "$candidate" in
                apt-get)      PKG=apt;;
                dnf)          PKG=dnf;;
                yum)          PKG=yum;;
                zypper)       PKG=zypper;;
                pacman)       PKG=pacman;;
                apk)          PKG=apk;;
                xbps-install) PKG=xbps;;
            esac
            return
        fi
    done
    PKG=unknown
}

# sudo is absent from most containers (which run as root anyway) and from
# Termux. Resolve once: empty prefix as root, an explicit refusal otherwise.
detect_sudo() {
    SUDO=""
    SUDO_NEEDS_PASSWORD=false
    if [ "$(id -u)" -eq 0 ]; then return; fi
    if [ "$PKG" = brew ] || [ "$PKG" = termux ]; then return; fi
    if command -v sudo &>/dev/null; then
        SUDO="sudo"
        # A password prompt is fine on a terminal; without one it would hang.
        if ! sudo -n true 2>/dev/null && [ ! -t 0 ]; then
            SUDO_NEEDS_PASSWORD=true
        fi
        return
    fi
    SUDO="none"
}

# Package names, per family. Empty means "not a separate package here".
#   python   the interpreter itself
#   pipvenv  what makes `python -m venv` produce a venv *with pip*
#   build    what liboqs needs to compile
#   optional nice to have (faster/cleaner build), never fatal
#   native   only needed when pip finds no wheel and compiles from source
pkg_names() {
    local role="$1"
    case "$PKG:$role" in
        apt:python)     echo "python3";;
        apt:pipvenv)    echo "python3-venv python3-pip";;
        apt:build)      echo "cmake gcc g++ make git ca-certificates";;
        apt:optional)   echo "ninja-build python3-dev pkg-config";;
        apt:native)     echo "libssl-dev libffi-dev cargo rustc";;

        dnf:python|yum:python)     echo "python3";;
        dnf:pipvenv|yum:pipvenv)   echo "python3-pip";;
        dnf:build|yum:build)       echo "cmake gcc gcc-c++ make git ca-certificates";;
        dnf:optional|yum:optional) echo "ninja-build python3-devel";;
        dnf:native|yum:native)     echo "openssl-devel libffi-devel cargo rust";;

        pacman:python)   echo "python";;
        pacman:pipvenv)  echo "python-pip";;
        pacman:build)    echo "cmake gcc make git ca-certificates";;
        pacman:optional) echo "ninja pkgconf";;
        pacman:native)   echo "openssl libffi rust";;

        zypper:python)   echo "python3";;
        zypper:pipvenv)  echo "python3-pip";;
        zypper:build)    echo "cmake gcc gcc-c++ make git ca-certificates";;
        zypper:optional) echo "ninja python3-devel pkg-config";;
        zypper:native)   echo "libopenssl-devel libffi-devel cargo rust";;

        apk:python)   echo "python3";;
        apk:pipvenv)  echo "py3-pip";;
        apk:build)    echo "cmake gcc g++ make git ca-certificates musl-dev";;
        apk:optional) echo "ninja python3-dev linux-headers pkgconf";;
        apk:native)   echo "openssl-dev libffi-dev cargo rust";;

        xbps:python)   echo "python3";;
        xbps:pipvenv)  echo "python3-pip";;
        xbps:build)    echo "cmake gcc make git ca-certificates";;
        xbps:optional) echo "ninja python3-devel pkg-config";;
        xbps:native)   echo "openssl-devel libffi-devel cargo rust";;

        brew:python)   echo "python";;
        brew:pipvenv)  echo "";;
        brew:build)    echo "cmake git";;
        brew:optional) echo "ninja";;
        brew:native)   echo "openssl@3 rust";;

        freebsd:python)   echo "python3";;
        freebsd:pipvenv)  echo "py311-pip";;
        freebsd:build)    echo "cmake git gcc gmake";;
        freebsd:optional) echo "ninja";;
        freebsd:native)   echo "openssl libffi rust";;

        termux:python)   echo "python";;
        termux:pipvenv)  echo "python-pip";;
        termux:build)    echo "cmake clang make git";;
        termux:optional) echo "ninja binutils";;
        termux:native)   echo "openssl libffi rust";;

        *) echo "";;
    esac
}

PKG_REFRESHED=false
pkg_refresh() {
    [ "$PKG_REFRESHED" = true ] && return 0
    PKG_REFRESHED=true
    case "$PKG" in
        apt)    $SUDO env DEBIAN_FRONTEND=noninteractive apt-get update -qq || warn "apt-get update failed — continuing with the cached index";;
        apk)    $SUDO apk update -q || warn "apk update failed — continuing";;
        # Arch has no partial upgrades: refreshing the index and then pulling a
        # single package out of it can drag in libraries the installed system
        # does not match. A full -Syu is the only supported way to install.
        pacman) $SUDO pacman -Syu --noconfirm --needed || warn "pacman -Syu failed — continuing";;
        xbps)   $SUDO xbps-install -Sy || warn "xbps sync failed — continuing";;
        brew)   brew update &>/dev/null || true;;
        termux) pkg update -y &>/dev/null || true;;
    esac
    return 0
}

# Install packages. Returns non-zero when the package manager refused, so the
# caller can fall back instead of dying.
pkg_install() {
    [ $# -gt 0 ] || return 0
    if [ "$SUDO" = "none" ]; then
        warn "Not root and sudo is missing — cannot install: $*"
        return 1
    fi
    if [ "${SUDO_NEEDS_PASSWORD:-false}" = true ]; then
        warn "sudo needs a password but there is no terminal to ask on."
        warn "Run once by hand:  sudo <package manager> install $*"
        return 1
    fi
    pkg_refresh
    case "$PKG" in
        apt)     $SUDO env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@";;
        dnf)     $SUDO dnf install -y "$@";;
        yum)     $SUDO yum install -y "$@";;
        pacman)  $SUDO pacman -S --noconfirm --needed "$@";;
        zypper)  $SUDO zypper --non-interactive install -y "$@";;
        apk)     $SUDO apk add --no-cache "$@";;
        xbps)    $SUDO xbps-install -y "$@";;
        brew)    brew install "$@";;
        freebsd) $SUDO pkg install -y "$@";;
        termux)  pkg install -y "$@";;
        *)       return 1;;
    esac
}

# Install a role, tolerating names this particular release does not ship
# (ninja-build vs ninja, python3-dev vs python3-devel…): try the whole set,
# then package by package so one unknown name never sinks the rest.
pkg_install_role() {
    local names; names="$(pkg_names "$1")"
    [ -n "$names" ] || return 0
    # shellcheck disable=SC2086
    if pkg_install $names; then return 0; fi
    local one rc=1
    for one in $names; do
        pkg_install "$one" >/dev/null 2>&1 && rc=0
    done
    return $rc
}

manual_hint() {
    warn "Install by hand, then re-run ./start.sh:"
    case "$PKG" in
        nix)    warn "  nix-shell -p python3 python3Packages.virtualenv cmake gcc gnumake git ninja";;
        gentoo) warn "  emerge -n dev-lang/python dev-build/cmake dev-vcs/git dev-build/ninja";;
        *)      warn "  cmake, a C/C++ compiler, make, git, and Python ≥3.10 with venv + pip";;
    esac
}

# ── python / venv / build helpers ────────────────────────────────────────────

# Newest first: a machine with several interpreters (deadsnakes, RHEL modules,
# Homebrew) should not be pinned to the oldest one that merely qualifies.
find_python() {
    PYTHON=""; PYTHON_VER=""
    local candidate ver major minor
    for candidate in python3 python3.14 python3.13 python3.12 python3.11 python3.10; do
        command -v "$candidate" &>/dev/null || continue
        ver=$("$candidate" -c 'import sys;print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>/dev/null || echo "0.0")
        major="${ver%%.*}"; minor="${ver##*.}"
        case "$major$minor" in *[!0-9]*|"") continue;; esac
        if [ "$major" -gt 3 ] || { [ "$major" -eq 3 ] && [ "$minor" -ge 10 ]; }; then
            PYTHON="$candidate"; PYTHON_VER="$ver"
            return 0
        fi
    done
    return 1
}

# Debian/Ubuntu ship python3 without ensurepip (`python3 -m venv` dies with
# "ensurepip is not available"), Alpine keeps pip in py3-pip, Arch in
# python-pip. A venv without pip is useless to us, so the probe checks both.
venv_capable() {
    local probe rc=0
    probe="$(mktemp -d)"
    "$PYTHON" -m venv "$probe/v" >/dev/null 2>&1 \
        && "$probe/v/bin/python" -m pip --version >/dev/null 2>&1 || rc=1
    rm -rf "$probe"
    return $rc
}

# A venv pinned to an interpreter a distro upgrade removed, or one created
# before pip was installable, is worse than no venv: everything in it fails.
venv_broken() {
    [ -x "$VENV/bin/python" ] || return 0
    "$VENV/bin/python" -c 'import sys' >/dev/null 2>&1 || return 0
    "$VENV/bin/python" -m pip --version >/dev/null 2>&1 || return 0
    return 1
}

have_build_tools() {
    local tool
    for tool in cmake make git; do command -v "$tool" &>/dev/null || return 1; done
    command -v cc &>/dev/null || command -v gcc &>/dev/null || command -v clang &>/dev/null || return 1
    # liboqs needs a modern CMake; the 2.8 shipped by old enterprise distros
    # configures and then fails deep into the build.
    local cver major minor
    cver="$(cmake --version 2>/dev/null | head -1 | awk '{print $3}')"
    major="$(echo "$cver" | cut -d. -f1)"; minor="$(echo "$cver" | cut -d. -f2)"
    case "${major}${minor}" in *[!0-9]*|"") return 1;; esac
    [ "$major" -gt 3 ] && return 0
    [ "$major" -eq 3 ] && [ "$minor" -ge 18 ]
}

cpu_count() { nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 1; }

available_mem_mb() {
    if [ -r /proc/meminfo ]; then
        awk '/MemAvailable:/{print int($2/1024); exit}' /proc/meminfo
    elif command -v sysctl &>/dev/null; then
        sysctl -n hw.memsize 2>/dev/null | awk '{print int($1/1024/1024)}'
    fi
}

# ── post-quantum crypto helpers ──────────────────────────────────────────────
# liboqs-python (the wrapper) only looks for the shared library in
# $OQS_INSTALL_PATH (default ~/_oqs) and in the system linker paths. liboqs must
# therefore be installed into that prefix: any other location "works" only in
# the current shell via LD_LIBRARY_PATH and forces a full recompile on every
# run. And if the wrapper can't find the library on import, it silently clones
# and builds its own copy with unbounded parallelism (OOM on small machines) —
# so the checks below never `import oqs` unless the library is already on disk.
#
# No Linux distro ships a trustworthy prebuilt liboqs: Ubuntu/Debian never had
# one (removed from Debian unstable in April 2025) and Fedora's liboqs-devel is
# stuck on 0.10.0, too old to guarantee the ML-KEM-768 / ML-DSA-65 parameter
# sets this project requires. Source build stays the only correct path there.
# Homebrew's formula is official and current enough to trust, so macOS gets a
# fast path that skips the compile — verified against the required algorithms
# before use.

# The shared library exists where the wrapper will look. No `import oqs`
# here — checking must never trigger the wrapper's surprise auto-build.
pq_lib_on_disk() {
    python - >/dev/null 2>&1 <<'PYEOF'
import ctypes.util, os, sys
from pathlib import Path
prefix = Path(os.environ.get("OQS_INSTALL_PATH", str(Path.home() / "_oqs")))
hits = [p for d in ("lib", "lib64") for p in (prefix / d).glob("liboqs.*")]
sys.exit(0 if (hits or ctypes.util.find_library("oqs")) else 1)
PYEOF
}

# Full functional check: wrapper + library + the exact algorithms we need.
pq_ready() {
    pq_lib_on_disk || return 1
    python - >/dev/null 2>&1 <<'PYEOF'
import oqs
oqs.KeyEncapsulation("ML-KEM-768")
oqs.Signature("ML-DSA-65")
PYEOF
}

# ── reusing a liboqs that is already on this machine ─────────────────────────
# Compiling liboqs takes minutes, and it is the same library whatever prefix it
# ends up in. Installing to a *new* prefix (a user install moving to /opt, a
# second node, a changed --prefix) would otherwise pay that cost again for a
# build that is already sitting on disk.
#
# The test is functional, never a version string: the wrapper actually loads the
# candidate and both required algorithms answer. A library that fails that is
# not reused, it is rebuilt.
liboqs_usable_at() (
    [ -n "$1" ] && [ -d "$1" ] || return 1
    export OQS_INSTALL_PATH="$1"
    pq_ready
)

# Where a built liboqs is kept so the *next* install does not rebuild it. Keyed
# by the wrapper version: a wrapper bump must recompile, since the two have to
# stay in lockstep around the crypto.
liboqs_cache_dir() {
    local base="${NMESH_LIBOQS_CACHE:-}"
    if [ -z "$base" ]; then
        if [ "$(id -u)" = 0 ]; then
            base=/var/cache/nmesh
        else
            base="${XDG_CACHE_HOME:-$(node_home)/.cache}/nmesh"
        fi
    fi
    echo "$base/liboqs-$1"
}

# Keep a copy of what was just built. Best effort by design: a read-only or
# full /var/cache costs the next install a rebuild, it must never fail this one.
cache_liboqs() {
    local cache part
    cache="$(liboqs_cache_dir "${1:-}")"
    [ "$cache" != "$OQS_PREFIX" ] || return 0
    mkdir -p "$cache" 2>/dev/null || return 0
    for part in lib lib64 include; do
        [ -d "$OQS_PREFIX/$part" ] || continue
        rm -rf "$cache/$part" 2>/dev/null || true
        cp -a "$OQS_PREFIX/$part" "$cache/" 2>/dev/null || return 0
    done
    # The library is not a secret and the next install may run as someone else.
    chmod -R a+rX "$cache" 2>/dev/null || true
    return 0
}

# Prefixes worth looking at: only directories that *are* liboqs install trees.
# A system-wide library needs no copy at all — `pq_lib_on_disk` already finds it
# through the linker path, so we never get here for one.
liboqs_candidates() {
    local item
    liboqs_cache_dir "${1:-}"
    # OQS_REUSE_FROM is a colon-separated list, the way PATH is: install.sh
    # fills it with the places a previous install may have left a build.
    if [ -n "${OQS_REUSE_FROM:-}" ]; then
        local IFS=:
        for item in $OQS_REUSE_FROM; do
            [ -n "$item" ] && [ "$item" != "$OQS_PREFIX" ] && echo "$item"
        done
    fi
    for item in "$(node_home)/_oqs" "/opt/nmesh/_oqs"; do
        [ "$item" != "$OQS_PREFIX" ] && echo "$item"
    done
    return 0
}

adopt_liboqs() {
    local candidate
    while read -r candidate; do
        [ -n "$candidate" ] || continue
        liboqs_usable_at "$candidate" || continue
        mkdir -p "$OQS_PREFIX"
        # lib on most systems, lib64 on Fedora/openSUSE — copy whichever exist,
        # headers included: the wrapper only needs the shared object, but a
        # complete prefix is what a later rebuild-check expects to find.
        local part copied=false
        for part in lib lib64 include; do
            [ -d "$candidate/$part" ] || continue
            cp -a "$candidate/$part" "$OQS_PREFIX/" 2>/dev/null && copied=true
        done
        [ "$copied" = true ] || continue
        # Copying is not proof: re-check *at the destination* before believing
        # it — named explicitly rather than through the ambient
        # OQS_INSTALL_PATH, so this holds wherever it is called from.
        if liboqs_usable_at "$OQS_PREFIX"; then
            ADOPTED_FROM="$candidate"
            return 0
        fi
    done < <(liboqs_candidates "${1:-}")
    return 1
}

# Fetch the liboqs sources for $OQS_PY_VER into $SRC: the tag matching the
# wrapper version, else its x.y.0, else main. Minimal images often have no git,
# so a tarball of the same ref from the same origin is an accepted fallback.
fetch_liboqs() {
    local ref url
    for ref in "$OQS_PY_VER" "${OQS_PY_VER%.*}.0" main; do
        if command -v git &>/dev/null && git clone --quiet --depth 1 --branch "$ref" \
            https://github.com/open-quantum-safe/liboqs.git "$SRC" 2>/dev/null; then
            [ "$ref" = main ] && warn "No liboqs tag matches liboqs-python $OQS_PY_VER — building main"
            return 0
        fi
        rm -rf "$SRC"
        if command -v curl &>/dev/null && command -v tar &>/dev/null; then
            url="https://github.com/open-quantum-safe/liboqs/archive/refs/tags/${ref}.tar.gz"
            [ "$ref" = main ] && url="https://github.com/open-quantum-safe/liboqs/archive/refs/heads/main.tar.gz"
            if curl -fsSL "$url" -o "$BUILD_DIR/liboqs.tar.gz" 2>/dev/null; then
                mkdir -p "$SRC"
                if tar -xzf "$BUILD_DIR/liboqs.tar.gz" -C "$SRC" --strip-components=1 2>/dev/null; then
                    rm -f "$BUILD_DIR/liboqs.tar.gz"
                    [ "$ref" = main ] && warn "No liboqs tag matches liboqs-python $OQS_PY_VER — building main"
                    return 0
                fi
            fi
            rm -rf "$SRC" "$BUILD_DIR/liboqs.tar.gz"
        fi
    done
    return 1
}

# ─────────────────────────────── MAIN ────────────────────────────────────────
# The test-suite sources everything above without running any of what follows.
if [ -n "${NMESH_START_LIB:-}" ]; then return 0; fi

detect_os
detect_sudo
case "$PKG" in
    unknown)    warn "Unknown package manager — system dependencies will not be installed automatically.";;
    nix|gentoo) info "OS: ${OS_ID} — declarative packaging, nothing will be installed automatically.";;
    *)          info "OS: ${OS_ID:-$OS_KERNEL} (${PKG})";;
esac

# ── step 1: Python ───────────────────────────────────────────────────────────
info "Checking Python…"
if ! find_python; then
    info "No Python ≥ 3.10 found — installing it…"
    pkg_install_role python || true
    hash -r
    find_python || { manual_hint; fail "Python ≥ 3.10 not found. Install it: https://www.python.org/downloads/"; }
fi
ok "Python $PYTHON_VER ($PYTHON)"

# ── step 2: venv + pip must actually work ────────────────────────────────────
# Since PEP 668 the system pip refuses to install anything anyway, so a working
# venv is the only path — never a fallback to installing into the system.
VENV_TOOL="venv"
if ! venv_capable; then
    info "Python cannot create a virtualenv (no ensurepip/pip) — installing the missing packages…"
    pkg_install_role pipvenv || true
    # Debian keeps venv in a per-minor package when several interpreters are
    # installed; the python3-venv metapackage then points at the wrong one.
    if [ "$PKG" = apt ] && ! venv_capable; then
        pkg_install "python${PYTHON_VER}-venv" >/dev/null 2>&1 \
            || pkg_install "python3-full" >/dev/null 2>&1 || true
    fi
    hash -r
    if ! venv_capable; then
        # Last resort: virtualenv bundles its own pip, so it works even when
        # ensurepip was stripped out of the interpreter.
        info "Still no usable venv — trying virtualenv…"
        case "$PKG" in
            apt|dnf|yum|zypper|xbps) pkg_install "python3-virtualenv" >/dev/null 2>&1 || true;;
            pacman)                  pkg_install "python-virtualenv" >/dev/null 2>&1 || true;;
            apk)                     pkg_install "py3-virtualenv" >/dev/null 2>&1 || true;;
        esac
        hash -r
        if "$PYTHON" -m virtualenv --version >/dev/null 2>&1; then
            VENV_TOOL="virtualenv"
        elif command -v virtualenv &>/dev/null; then
            VENV_TOOL="virtualenv-bin"
        else
            manual_hint
            fail "Cannot create a virtualenv: $PYTHON has no working venv/pip and virtualenv is unavailable."
        fi
    fi
fi
ok "Virtualenv support available ($VENV_TOOL)"

# ── step 3: system build tools ───────────────────────────────────────────────
info "Checking build tools (liboqs needs cmake + a C compiler)…"
if have_build_tools; then
    ok "Build tools already installed"
else
    info "Installing missing build tools…"
    pkg_install_role build || warn "Some build packages could not be installed"
    pkg_install_role optional >/dev/null 2>&1 || true
    hash -r
    have_build_tools && ok "System dependencies installed" \
        || warn "Build tools still incomplete — will try pip-provided cmake/ninja below"
fi

# ── step 4: virtualenv ───────────────────────────────────────────────────────
VENV="${NMESH_VENV:-.venv}"
if [ -d "$VENV" ] && venv_broken; then
    warn "Existing virtualenv in $VENV is unusable — recreating it"
    rm -rf "$VENV"
fi
if [ ! -d "$VENV" ]; then
    info "Creating virtualenv in $VENV…"
    case "$VENV_TOOL" in
        venv)           "$PYTHON" -m venv "$VENV";;
        virtualenv)     "$PYTHON" -m virtualenv "$VENV";;
        virtualenv-bin) virtualenv -p "$PYTHON" "$VENV";;
    esac || fail "Failed to create virtualenv"
    venv_broken && fail "Virtualenv created without a working pip — remove $VENV and re-run"
fi
# shellcheck disable=SC1091
. "$VENV/bin/activate"
ok "Virtualenv active ($VENV)"

# Unknown distro, or one whose cmake is too old: pip ships official cmake and
# ninja wheels, and the venv is ours to install into.
if ! have_build_tools; then
    info "Getting cmake/ninja from pip (no usable system build tooling)…"
    python -m pip install --quiet cmake ninja >/dev/null 2>&1 || true
    hash -r
    have_build_tools || { manual_hint; fail "No usable cmake + C compiler — liboqs cannot be built."; }
    ok "cmake provided by pip"
fi

# ── step 5: Python dependencies ──────────────────────────────────────────────
OQS_PREFIX="${OQS_INSTALL_PATH:-$(node_home)/_oqs}"
# Exported, not just computed: the wrapper reads this variable at import time,
# and so do the probes below. Without it they fall back to their own idea of
# "home", which is not necessarily the one this script just used — the library
# would be built in one place and looked for in another.
export OQS_INSTALL_PATH="$OQS_PREFIX"

if pq_ready && python -c "import cryptography, pytest, pytest_asyncio" >/dev/null 2>&1; then
    ok "Dependencies already installed (fast start)"
else
    info "Installing Python dependencies…"
    python -m pip install --quiet --upgrade pip \
        || warn "pip could not be upgraded — continuing with the bundled one"
    # A venv on Python ≥3.12 has no setuptools, which some sdists still assume.
    python -m pip install --quiet --upgrade setuptools wheel >/dev/null 2>&1 || true

    if ! python -m pip install --quiet -r requirements.txt; then
        # No wheel for this platform (musl, 32-bit ARM, RISC-V…) means pip falls
        # back to compiling cryptography, which needs Rust and the OpenSSL/FFI
        # headers. Install those once, then retry.
        warn "pip install failed — installing native build dependencies and retrying…"
        pkg_install_role native || true
        hash -r
        python -m pip install -r requirements.txt || fail "pip install failed (see output above)"
    fi

    if ! pq_ready && [[ "$(uname -s)" == "Darwin" ]] && command -v brew &>/dev/null; then
        info "macOS — trying prebuilt liboqs via Homebrew (skips the long compile)…"
        brew list liboqs &>/dev/null || brew install liboqs || true
    fi

    # The wrapper version decides which liboqs release we need — both for
    # reusing one and for building it, so it is resolved before either.
    if ! pq_ready; then
        OQS_PY_VER=$(python -c "import importlib.metadata as m; print(m.version('liboqs-python'))") \
            || fail "liboqs-python is not installed"
        if adopt_liboqs "$OQS_PY_VER"; then
            ok "Reused the liboqs already built in $ADOPTED_FROM (no recompile)"
        fi
    fi

    if ! pq_ready; then
        # Build the liboqs release matching the installed wrapper so the two
        # stay in lockstep — a mismatched wrapper/library pair around the
        # crypto is not acceptable, even when it happens to load.
        info "Building liboqs $OQS_PY_VER from source (one-time — a few minutes)…"

        BUILD_DIR="${LIBOQS_BUILD_DIR:-$(node_home)/_oqs_build}"
        rm -rf "$BUILD_DIR"
        mkdir -p "$BUILD_DIR"
        SRC="$BUILD_DIR/liboqs"

        fetch_liboqs || fail "Failed to fetch the liboqs sources (need git or curl + network access)"

        CMAKE_GEN=""
        command -v ninja &>/dev/null && CMAKE_GEN="-GNinja"

        # Same feature flags as the wrapper's own auto-build (the stateful
        # signature symbols must exist or the wrapper fails to load), minus
        # OpenSSL so no dev headers are needed. OQS_BUILD_ONLY_LIB skips
        # tests and docs. The install prefix is the wrapper's search path —
        # user-writable, never needs sudo.
        cmake -S "$SRC" -B "$BUILD_DIR/build" $CMAKE_GEN \
            -DCMAKE_BUILD_TYPE=Release \
            -DBUILD_SHARED_LIBS=ON \
            -DOQS_BUILD_ONLY_LIB=ON \
            -DOQS_USE_OPENSSL=OFF \
            -DOQS_ENABLE_SIG_STFL_LMS=ON \
            -DOQS_ENABLE_SIG_STFL_XMSS=ON \
            -DOQS_HAZARDOUS_EXPERIMENTAL_ENABLE_SIG_STFL_KEY_SIG_GEN=ON \
            -DCMAKE_INSTALL_PREFIX="$OQS_PREFIX" \
            || fail "liboqs cmake configure failed (see output above)"

        # One job per core OOM-kills the build on machines with many cores but
        # little RAM (~1.5 GB per compile unit) — cap jobs by available RAM.
        BUILD_JOBS="$(cpu_count)"
        MEM_MB="$(available_mem_mb || true)"
        if [ -n "${MEM_MB:-}" ] && [ "$MEM_MB" -gt 0 ]; then
            MEM_JOBS=$(( MEM_MB / 1500 ))
            [ "$MEM_JOBS" -ge 1 ] || MEM_JOBS=1
            if [ "$MEM_JOBS" -lt "$BUILD_JOBS" ]; then BUILD_JOBS="$MEM_JOBS"; fi
        fi
        info "Building liboqs with $BUILD_JOBS parallel job(s) (capped by available RAM)…"

        cmake --build "$BUILD_DIR/build" --parallel "$BUILD_JOBS" \
            || fail "liboqs build failed"
        cmake --install "$BUILD_DIR/build" \
            || fail "liboqs install failed"
        # The install lives in $OQS_PREFIX — the build tree is dead weight.
        rm -rf "$BUILD_DIR"
        # Keep a copy so the next install — another prefix, another node on this
        # machine — reuses it instead of spending these minutes again.
        cache_liboqs "$OQS_PY_VER"
    fi

    pq_ready || fail "post-quantum crypto still unusable after install — try: rm -rf $OQS_PREFIX $VENV && ./start.sh"
    ok "Python dependencies installed"
fi

# ── step 6: verify imports ───────────────────────────────────────────────────
info "Verifying imports…"
pq_ready && ok "liboqs-python (ML-KEM-768, ML-DSA-65)" \
    || fail "liboqs-python check failed — try: rm -rf $OQS_PREFIX $VENV && ./start.sh"
python -c "import cryptography" >/dev/null 2>&1 && ok "cryptography (AES-GCM/HKDF)" \
    || fail "cryptography import failed"
python -c "import src" >/dev/null 2>&1 && ok "src (NMesh core)" \
    || fail "src import failed — check project structure"

# Setup-only mode: everything above is the install path, nothing below it is.
# CI and "did my machine get set up?" checks stop here instead of starting a node.
if [ -n "${NMESH_SETUP_ONLY:-}" ]; then
    ok "Setup complete (NMESH_SETUP_ONLY set — not launching the node)"
    exit 0
fi

# ── step 7: launch ───────────────────────────────────────────────────────────
DATA="${NMESH_DATA:-./data}"
mkdir -p "$DATA"

# Default flags: enable UDP hole punching + STUN unless --no-udp is passed
EXTRA_ARGS=("$@")
HAS_UDP=false
for arg in "$@"; do
    case "$arg" in --udp|--no-udp) HAS_UDP=true;; esac
done

DEFAULT_UDP_PORT="${NMESH_UDP_PORT:-9001}"

if [ "$HAS_UDP" = false ]; then
    EXTRA_ARGS=(--udp "$DEFAULT_UDP_PORT" --stun "${EXTRA_ARGS[@]}")
fi

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  NMesh starting — state in $DATA"
echo "═══════════════════════════════════════════════════════════════"
echo ""

exec python -u scripts/nmesh_node.py --data "$DATA" "${EXTRA_ARGS[@]}"
