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
# Any extra arguments are passed straight to scripts/console_demo.py.
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

# ── step 1: Python ───────────────────────────────────────────────────────────
info "Checking Python…"
PYTHON=""
for candidate in python3 python3.12 python3.11 python3.10; do
    if command -v "$candidate" &>/dev/null; then
        ver=$("$candidate" -c 'import sys;print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>/dev/null || echo "0.0")
        major=$(echo "$ver" | cut -d. -f1)
        minor=$(echo "$ver" | cut -d. -f2)
        if [ "$major" -gt 3 ] || { [ "$major" -eq 3 ] && [ "$minor" -ge 10 ]; }; then
            PYTHON="$candidate"
            ok "Python $ver ($candidate)"
            break
        fi
    fi
done
[ -n "$PYTHON" ] || fail "Python ≥ 3.10 not found. Install it: https://www.python.org/downloads/"

# ── step 2: OS detection + system dependencies ───────────────────────────────
info "Detecting OS and checking build tools (liboqs needs cmake + gcc)…"

# Check if build tools are already present — skip install if so
need_system_deps() {
    for tool in cmake gcc g++ make git; do
        command -v "$tool" &>/dev/null || return 0
    done
    # Check for python3-dev / headers
    if [ -f /etc/debian_version ]; then
        dpkg -s python3-dev &>/dev/null || return 0
    fi
    return 1
}

install_apt() {
    sudo apt-get update -qq
    sudo apt-get install -y -qq cmake gcc g++ make git ninja-build \
        python3-dev python3-venv
}
install_dnf() {
    sudo dnf install -y cmake gcc gcc-c++ make git ninja-build \
        python3-devel python3-virtualenv
}
install_pacman() {
    sudo pacman -Sy --noconfirm cmake gcc make git ninja python python-virtualenv
}
install_zypper() {
    sudo zypper install -y cmake gcc gcc-c++ make git ninja \
        python3-devel python3-virtualenv
}
install_brew() {
    brew install cmake git ninja || true
    brew install python@3.12 || true
}
install_apk() {
    sudo apk add --no-cache cmake gcc g++ make git ninja-build \
        python3-dev py3-virtualenv
}

if ! need_system_deps; then
    ok "Build tools already installed"
else
    info "Installing missing build tools…"
    if [ -f /etc/debian_version ]; then
        info "OS: Debian/Ubuntu (apt)"
        install_apt
    elif [ -f /etc/fedora-release ] || [ -f /etc/redhat-release ]; then
        info "OS: Fedora/RHEL (dnf)"
        install_dnf
    elif command -v pacman &>/dev/null; then
        info "OS: Arch Linux (pacman)"
        install_pacman
    elif command -v zypper &>/dev/null; then
        info "OS: openSUSE (zypper)"
        install_zypper
    elif command -v apk &>/dev/null; then
        info "OS: Alpine (apk)"
        install_apk
    elif command -v brew &>/dev/null; then
        info "OS: macOS (Homebrew)"
        install_brew
    else
        warn "Unknown OS — cannot auto-install system dependencies."
        warn "Please install manually: cmake, gcc, g++, make, git, ninja-build, python3-dev"
        warn "Then re-run ./start.sh"
        exit 1
    fi
    ok "System dependencies installed"
fi

# ── step 3: virtualenv ───────────────────────────────────────────────────────
VENV="${NMESH_VENV:-.venv}"
if [ ! -d "$VENV" ]; then
    info "Creating virtualenv in $VENV…"
    "$PYTHON" -m venv "$VENV" || fail "Failed to create virtualenv"
fi
# shellcheck disable=SC1091
. "$VENV/bin/activate"
ok "Virtualenv active ($VENV)"

# ── step 4: Python dependencies ──────────────────────────────────────────────
info "Installing Python dependencies (first run compiles liboqs — may take a few minutes)…"

# Install cryptography + pytest first (these never fail)
pip install --quiet --upgrade pip
pip install --quiet cryptography pytest pytest-asyncio

# liboqs-python bundles liboqs source and tries to compile it on import.
# The auto-build can fail silently on some systems (missing ninja, cmake
# config errors). We force a clean build here with verbose output so the
# user sees what's happening and we can catch errors early.
if ! python -c "import oqs" 2>/dev/null; then
    info "Building liboqs from source (post-quantum crypto)…"
    # OQS_LIBOQS_SRC_DIR forces liboqs-python to use a fresh clone+build
    # instead of its bundled one, which sometimes has stale cmake cache.
    LIBOQS_BUILD_DIR="${LIBOQS_BUILD_DIR:-$HOME/_oqs_build}"
    rm -rf "$LIBOQS_BUILD_DIR"
    mkdir -p "$LIBOQS_BUILD_DIR"

    # Clone liboqs and build it explicitly
    if [ ! -d "$LIBOQS_BUILD_DIR/liboqs" ]; then
        git clone --depth 1 --branch main \
            https://github.com/open-quantum-safe/liboqs.git \
            "$LIBOQS_BUILD_DIR/liboqs" 2>&1 | tail -3
    fi

    # Build liboqs with cmake + ninja (faster + more reliable than make)
    BUILD_TOOL="make"
    if command -v ninja &>/dev/null; then
        BUILD_TOOL="ninja"
    fi

    cmake -S "$LIBOQS_BUILD_DIR/liboqs" -B "$LIBOQS_BUILD_DIR/build" \
        -GNinja -DCMAKE_BUILD_TYPE=Release \
        -DOQS_USE_OPENSSL=OFF 2>&1 | tail -5 \
        || cmake -S "$LIBOQS_BUILD_DIR/liboqs" -B "$LIBOQS_BUILD_DIR/build" \
        -DCMAKE_BUILD_TYPE=Release -DOQS_USE_OPENSSL=OFF 2>&1 | tail -5

    cmake --build "$LIBOQS_BUILD_DIR/build" --parallel 2>&1 | tail -5
    cmake --install "$LIBOQS_BUILD_DIR/build" 2>&1 | tail -3

    # Now install liboqs-python pointing to our built library
    export OQS_LIBOQS_SRC_DIR="$LIBOQS_BUILD_DIR/liboqs"
    pip install --quiet --force-reinstall liboqs-python 2>&1 | tail -5

    # Verify the shared library is loadable
    if ! python -c "import oqs" 2>/dev/null; then
        # Fallback: try to find the .so manually and set LD_LIBRARY_PATH
        LIBOQS_SO=$(find "$LIBOQS_BUILD_DIR" -name "liboqs.so*" -o -name "liboqs.dylib" 2>/dev/null | head -1)
        if [ -n "$LIBOQS_SO" ]; then
            LIBOQS_LIBDIR=$(dirname "$LIBOQS_SO")
            export LD_LIBRARY_PATH="$LIBOQS_LIBDIR:${LD_LIBRARY_PATH:-}"
            info "Set LD_LIBRARY_PATH=$LIBOQS_LIBDIR"
            if ! python -c "import oqs" 2>/dev/null; then
                fail "liboqs built but Python can't load it. Try: export LD_LIBRARY_PATH=$LIBOQS_LIBDIR"
            fi
        else
            fail "liboqs build failed. Check cmake output above. Ensure gcc, g++, cmake, ninja-build are installed."
        fi
    fi
fi
ok "Python dependencies installed"

# ── step 5: verify imports ───────────────────────────────────────────────────
info "Verifying imports…"
python -c "import oqs; print('ok')" 2>/dev/null && ok "liboqs-python (post-quantum crypto)" \
    || fail "liboqs-python import failed — try: rm -rf $HOME/_oqs_build .venv && ./start.sh"
python -c "import cryptography" 2>/dev/null && ok "cryptography (AES-GCM/HKDF)" \
    || fail "cryptography import failed"
python -c "import src" 2>/dev/null && ok "src (NMesh core)" \
    || fail "src import failed — check project structure"

# ── step 6: launch ───────────────────────────────────────────────────────────
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

exec python -u scripts/console_demo.py --data "$DATA" "${EXTRA_ARGS[@]}"
