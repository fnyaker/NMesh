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
    # ninja-build is optional but preferred — don't fail if missing
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
# Post-quantum crypto = liboqs-python (the wrapper) + liboqs (the C library).
#
# liboqs-python only looks for the shared library in $OQS_INSTALL_PATH
# (default ~/_oqs) and in the system linker paths. liboqs must therefore be
# installed into that prefix: any other location "works" only in the current
# shell via LD_LIBRARY_PATH and forces a full recompile on every run. And if
# the wrapper can't find the library on import, it silently clones and builds
# its own copy with unbounded parallelism (OOM on small machines) — so the
# checks below never `import oqs` unless the library is already on disk.
#
# No Linux distro ships a trustworthy prebuilt liboqs: Ubuntu/Debian never
# had one (removed from Debian unstable in April 2025) and Fedora's
# liboqs-devel is stuck on 0.10.0, too old to guarantee the ML-KEM-768 /
# ML-DSA-65 parameter sets this project requires. Source build stays the
# only correct path there. Homebrew's formula is official and current enough
# to trust, so macOS gets a fast path that skips the compile — verified
# against the required algorithms before use.
OQS_PREFIX="${OQS_INSTALL_PATH:-$HOME/_oqs}"

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

if pq_ready && python -c "import cryptography, pytest, pytest_asyncio" >/dev/null 2>&1; then
    ok "Dependencies already installed (fast start)"
else
    info "Installing Python dependencies…"
    pip install --quiet --upgrade pip || fail "pip upgrade failed"
    pip install --quiet -r requirements.txt || fail "pip install failed"

    if ! pq_ready && [[ "$(uname -s)" == "Darwin" ]] && command -v brew &>/dev/null; then
        info "macOS — trying prebuilt liboqs via Homebrew (skips the long compile)…"
        brew list liboqs &>/dev/null || brew install liboqs || true
    fi

    if ! pq_ready; then
        # Build the liboqs release matching the installed wrapper so the two
        # stay in lockstep — a mismatched wrapper/library pair around the
        # crypto is not acceptable, even when it happens to load.
        OQS_PY_VER=$(python -c "import importlib.metadata as m; print(m.version('liboqs-python'))") \
            || fail "liboqs-python is not installed"
        info "Building liboqs $OQS_PY_VER from source (one-time — a few minutes)…"

        BUILD_DIR="${LIBOQS_BUILD_DIR:-$HOME/_oqs_build}"
        rm -rf "$BUILD_DIR"
        mkdir -p "$BUILD_DIR"
        SRC="$BUILD_DIR/liboqs"

        # Tag matching the wrapper version, else its x.y.0, else main.
        for ref in "$OQS_PY_VER" "${OQS_PY_VER%.*}.0" main; do
            if git clone --quiet --depth 1 --branch "$ref" \
                https://github.com/open-quantum-safe/liboqs.git "$SRC" 2>/dev/null; then
                [ "$ref" = main ] && warn "No liboqs tag matches liboqs-python $OQS_PY_VER — building main"
                break
            fi
            rm -rf "$SRC"
        done
        [ -d "$SRC" ] || fail "Failed to clone liboqs repository"

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

        # One job per core OOM-kills the build on machines with many cores
        # but little RAM (~1.5 GB per compile unit) — cap jobs by available RAM.
        cpu_count() { nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 1; }
        available_mem_mb() {
            if [ -r /proc/meminfo ]; then
                awk '/MemAvailable:/{print int($2/1024); exit}' /proc/meminfo
            elif command -v sysctl &>/dev/null; then
                sysctl -n hw.memsize 2>/dev/null | awk '{print int($1/1024/1024)}'
            fi
        }
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
    fi

    pq_ready || fail "post-quantum crypto still unusable after install — try: rm -rf $OQS_PREFIX $VENV && ./start.sh"
    ok "Python dependencies installed"
fi

# ── step 5: verify imports ───────────────────────────────────────────────────
info "Verifying imports…"
pq_ready && ok "liboqs-python (ML-KEM-768, ML-DSA-65)" \
    || fail "liboqs-python check failed — try: rm -rf $OQS_PREFIX $VENV && ./start.sh"
python -c "import cryptography" >/dev/null 2>&1 && ok "cryptography (AES-GCM/HKDF)" \
    || fail "cryptography import failed"
python -c "import src" >/dev/null 2>&1 && ok "src (NMesh core)" \
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
