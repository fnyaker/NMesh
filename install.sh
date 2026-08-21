#!/usr/bin/env bash
#
# NMesh — installer.
#
# Puts NMesh somewhere durable, makes it start with the machine, and launches
# it. The *recommended* way to run NMesh is still `start.sh`: this script does
# not reimplement any of its work, it installs a copy of the tree and points a
# service at `start.sh` inside it. Dependencies, distro quirks, liboqs — all of
# that stays in one place, and a node that boots re-verifies its own install.
#
#   ./install.sh                        # install, enable at boot, start
#   ./install.sh --fleet                # …and enable the fleet app
#   ./install.sh --prefix /srv/nmesh    # choose where it lives
#   ./install.sh --no-start             # install and enable, don't start now
#   ./install.sh --uninstall            # remove the service and the files
#   ./install.sh --uninstall --purge    # …and the node's identity + state
#
# Any other argument is passed to the node, exactly like `start.sh`.
#
# Where things go, unless overridden:
#
#   as root          /opt/nmesh          state in /var/lib/nmesh
#   as a user        ~/.local/share/nmesh  state in ~/.local/share/nmesh/data
#
# Re-running it upgrades in place: the tree is replaced, **state is never
# touched**, and the service is restarted.
#
# Environment switches:
#   NMESH_PREFIX=path    install directory
#   NMESH_DATA=path      node state directory
#   NMESH_SERVICE=name   service name (default nmesh)
#   NMESH_USER=name      user the service runs as (default: the invoking user)
#
# Everything above the "MAIN" banner is definitions only: the test-suite sources
# this file with NMESH_INSTALL_LIB=1 to exercise them without installing.
set -euo pipefail

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

# ── privileges ───────────────────────────────────────────────────────────────
# Same reasoning as start.sh: containers run as root and have no sudo, Termux
# has neither. Resolve once, and never block on a password prompt we cannot
# answer.
detect_sudo() {
    SUDO=""
    if [ "$(id -u)" -eq 0 ]; then return; fi
    if command -v sudo >/dev/null 2>&1; then
        SUDO="sudo"
        if ! sudo -n true 2>/dev/null && [ ! -t 0 ]; then SUDO="none"; fi
        return
    fi
    if command -v doas >/dev/null 2>&1; then SUDO="doas"; return; fi
    SUDO="none"
}

is_root() { [ "$(id -u)" -eq 0 ]; }

# ── where things live ────────────────────────────────────────────────────────
# A user install must not need root, so it goes under the XDG data directory. A
# root install goes to /opt with state in /var/lib, where an administrator
# expects to find it.
default_prefix() {
    if is_root; then
        echo "/opt/nmesh"
    else
        echo "${XDG_DATA_HOME:-$HOME/.local/share}/nmesh"
    fi
}

default_data() {
    if is_root; then
        echo "/var/lib/nmesh"
    else
        echo "$1/data"
    fi
}

# ── init system ──────────────────────────────────────────────────────────────
# Probed in the order that decides how the service is written. "systemd-user"
# is what a non-root install gets: a unit under ~/.config/systemd/user, which
# needs lingering enabled to start without a login session.
detect_init() {
    # `systemctl` on PATH proves nothing: plenty of container images ship it
    # with no systemd behind it, and every call then fails with "Failed to
    # connect to bus". /run/systemd/system is the documented test for a booted
    # systemd, so use that.
    if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
        if is_root || [ "${NMESH_FORCE_SYSTEM:-}" = 1 ]; then
            echo "systemd-system"
        elif systemctl --user show-environment >/dev/null 2>&1; then
            echo "systemd-user"
        else
            echo "none"
        fi
        return
    fi
    if command -v rc-update >/dev/null 2>&1 && is_root; then echo "openrc"; return; fi
    if command -v launchctl >/dev/null 2>&1; then echo "launchd"; return; fi
    echo "none"
}

# ── copying the tree ─────────────────────────────────────────────────────────
# What a running node needs, and nothing else: no .git, no virtualenv, no state
# directory, no test suite. `tar` is used rather than `cp -r` so modes and
# symlinks survive and the exclusion list is honoured on every platform.
TREE_INCLUDE=(src scripts start.sh install.sh requirements.txt pyproject.toml
              README.md CLAUDE.md Docs docker)
TREE_EXCLUDE=(--exclude=__pycache__ --exclude=.git --exclude=.venv
              --exclude=data --exclude='*.pyc')

copy_tree() {
    local src="$1" dst="$2" entry present=()
    for entry in "${TREE_INCLUDE[@]}"; do
        [ -e "$src/$entry" ] && present+=("$entry")
    done
    [ "${#present[@]}" -gt 0 ] || return 1
    mkdir -p "$dst"
    ( cd "$src" && tar -cf - "${TREE_EXCLUDE[@]}" "${present[@]}" ) \
        | ( cd "$dst" && tar -xf - )
}

# ── service definitions ──────────────────────────────────────────────────────
# Every unit points at start.sh, not at python directly. That is deliberate: a
# node that boots then re-verifies its own dependencies heals itself after a
# partial upgrade or a distro package change, and there is exactly one place
# that knows how to install anything.
systemd_unit() {
    local prefix="$1" data="$2" user="$3" args="$4"
    cat <<EOF
[Unit]
Description=NMesh node
Documentation=https://github.com/fnyaker/NMesh
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
${user:+User=$user}
WorkingDirectory=$prefix
Environment=NMESH_DATA=$data
# Tells the updater it may restart the node through the service manager rather
# than leaving the operator with a stopped node after an update.
Environment=NMESH_SERVICE_MANAGED=1
ExecStart=$prefix/start.sh $args
Restart=always
RestartSec=5
# The node needs no new privileges and no private state outside its data dir.
NoNewPrivileges=yes
PrivateTmp=yes

[Install]
WantedBy=$5
EOF
}

openrc_service() {
    local prefix="$1" data="$2" user="$3" args="$4" name="$5"
    cat <<EOF
#!/sbin/openrc-run
name="$name"
description="NMesh node"
command="$prefix/start.sh"
command_args="$args"
command_background=true
command_user="${user:-root}"
directory="$prefix"
export NMESH_DATA="$data"
export NMESH_SERVICE_MANAGED=1
pidfile="/run/\$RC_SVCNAME.pid"
output_log="/var/log/\$RC_SVCNAME.log"
error_log="/var/log/\$RC_SVCNAME.log"

depend() {
    need net
}
EOF
}

launchd_plist() {
    local prefix="$1" data="$2" label="$3" args="$4"
    {
        echo '<?xml version="1.0" encoding="UTF-8"?>'
        echo '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">'
        echo '<plist version="1.0"><dict>'
        echo "  <key>Label</key><string>$label</string>"
        echo '  <key>ProgramArguments</key><array>'
        echo "    <string>$prefix/start.sh</string>"
        local arg
        for arg in $args; do echo "    <string>$arg</string>"; done
        echo '  </array>'
        echo '  <key>EnvironmentVariables</key><dict>'
        echo "    <key>NMESH_DATA</key><string>$data</string>"
        echo "    <key>NMESH_SERVICE_MANAGED</key><string>1</string>"
        echo '  </dict>'
        echo "  <key>WorkingDirectory</key><string>$prefix</string>"
        echo '  <key>RunAtLoad</key><true/>'
        echo '  <key>KeepAlive</key><true/>'
        echo '</dict></plist>'
    }
}

# ── printing ─────────────────────────────────────────────────────────────────
service_hint() {
    case "$1" in
        systemd-system) echo "sudo systemctl status $2 · sudo journalctl -u $2 -f";;
        systemd-user)   echo "systemctl --user status $2 · journalctl --user -u $2 -f";;
        openrc)         echo "rc-service $2 status · tail -f /var/log/$2.log";;
        launchd)        echo "launchctl list | grep $2";;
        *)              echo "(no service installed)";;
    esac
}

# The test-suite sources everything above and stops here.
if [ -n "${NMESH_INSTALL_LIB:-}" ]; then return 0 2>/dev/null || exit 0; fi

# ─────────────────────────────── MAIN ────────────────────────────────────────

SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVICE="${NMESH_SERVICE:-nmesh}"
PREFIX="${NMESH_PREFIX:-}"
DATA="${NMESH_DATA:-}"
RUN_USER="${NMESH_USER:-}"
DO_START=true
UNINSTALL=false
PURGE=false
NODE_ARGS=()

while [ $# -gt 0 ]; do
    case "$1" in
        --prefix)     PREFIX="${2:-}"; shift 2;;
        --data)       DATA="${2:-}"; shift 2;;
        --service)    SERVICE="${2:-}"; shift 2;;
        --run-as)     RUN_USER="${2:-}"; shift 2;;
        --no-start)   DO_START=false; shift;;
        --uninstall)  UNINSTALL=true; shift;;
        --purge)      PURGE=true; shift;;
        -h|--help)    sed -n '2,32p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0;;
        *)            NODE_ARGS+=("$1"); shift;;
    esac
done

detect_sudo
INIT="$(detect_init)"
[ -n "$PREFIX" ] || PREFIX="$(default_prefix)"
[ -n "$DATA" ]   || DATA="$(default_data "$PREFIX")"
[ -n "$RUN_USER" ] || { is_root || RUN_USER="$(id -un)"; }

UNIT_PATH=""
case "$INIT" in
    systemd-system) UNIT_PATH="/etc/systemd/system/$SERVICE.service";;
    systemd-user)   UNIT_PATH="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user/$SERVICE.service";;
    openrc)         UNIT_PATH="/etc/init.d/$SERVICE";;
    launchd)        UNIT_PATH="$HOME/Library/LaunchAgents/org.nmesh.$SERVICE.plist";;
esac

# `run_priv` is a no-op as root and refuses loudly when there is no way up.
run_priv() {
    if [ -z "$SUDO" ]; then "$@"; return; fi
    if [ "$SUDO" = none ]; then
        fail "This step needs root and neither sudo nor doas is available: $*"
    fi
    $SUDO "$@"
}

# ── uninstall ────────────────────────────────────────────────────────────────
if [ "$UNINSTALL" = true ]; then
    info "Removing the NMesh service and files"
    case "$INIT" in
        systemd-system)
            run_priv systemctl disable --now "$SERVICE" >/dev/null 2>&1 || true
            run_priv rm -f "$UNIT_PATH"
            run_priv systemctl daemon-reload || true;;
        systemd-user)
            systemctl --user disable --now "$SERVICE" >/dev/null 2>&1 || true
            rm -f "$UNIT_PATH"
            systemctl --user daemon-reload || true;;
        openrc)
            run_priv rc-service "$SERVICE" stop >/dev/null 2>&1 || true
            run_priv rc-update del "$SERVICE" default >/dev/null 2>&1 || true
            run_priv rm -f "$UNIT_PATH";;
        launchd)
            launchctl unload "$UNIT_PATH" >/dev/null 2>&1 || true
            rm -f "$UNIT_PATH";;
        *) warn "No service to remove (none was installed)";;
    esac
    ok "Service removed"

    if [ -d "$PREFIX" ]; then
        run_priv rm -rf "$PREFIX"
        ok "Removed $PREFIX"
    fi
    if [ "$PURGE" = true ]; then
        # The identity is what makes this node *this* node on the mesh: deleting
        # it is irreversible, and every peer that trusted it now trusts nothing.
        if [ -d "$DATA" ]; then
            run_priv rm -rf "$DATA"
            warn "Purged $DATA — this node's identity is gone for good"
        fi
    elif [ -d "$DATA" ]; then
        info "State kept in $DATA (use --purge to delete the node's identity too)"
    fi
    exit 0
fi

# ── install ──────────────────────────────────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  NMesh installer"
echo "═══════════════════════════════════════════════════════════════"
echo ""

[ -f "$SOURCE_DIR/start.sh" ] || fail "start.sh not found next to install.sh — run this from an NMesh checkout"

SOURCE_REAL="$(cd "$SOURCE_DIR" && pwd -P)"
DEST_REAL="$(cd "$PREFIX" 2>/dev/null && pwd -P || echo "$PREFIX")"
UPGRADE=false
[ -d "$PREFIX/src" ] && UPGRADE=true

if [ "$SOURCE_REAL" = "$DEST_REAL" ]; then
    # Running the installer from inside the install directory is how an upgrade
    # in place looks. Copying a tree onto itself would be a no-op at best.
    info "Already installed here — configuring the service only"
else
    if [ "$UPGRADE" = true ]; then
        info "Upgrading the existing install in $PREFIX (state is left alone)"
    else
        info "Installing to $PREFIX"
    fi
    run_priv mkdir -p "$PREFIX"
    # A user install must own its directory; a root install stays root-owned.
    if ! is_root && [ ! -w "$PREFIX" ]; then
        run_priv chown "$(id -u):$(id -g)" "$PREFIX"
    fi
    copy_tree "$SOURCE_REAL" "$PREFIX" || fail "Could not copy the NMesh tree"
    chmod +x "$PREFIX/start.sh" "$PREFIX/install.sh" 2>/dev/null || true
    ok "Files installed in $PREFIX"
fi

run_priv mkdir -p "$DATA"
if [ -n "$RUN_USER" ] && is_root; then
    run_priv chown -R "$RUN_USER" "$DATA" || true
fi
# State is a secret store (identity key, session store, console password hash).
chmod 700 "$DATA" 2>/dev/null || true
ok "State directory $DATA"

# ── dependencies: delegated to start.sh, never duplicated ────────────────────
info "Installing dependencies (this is start.sh doing its usual work)…"
if ! ( cd "$PREFIX" && NMESH_SETUP_ONLY=1 ./start.sh ); then
    fail "Dependency setup failed — fix the errors above and re-run ./install.sh"
fi
ok "Dependencies ready"

# ── service ──────────────────────────────────────────────────────────────────
ARGS="${NODE_ARGS[*]:-}"
case "$INIT" in
    systemd-system)
        info "Installing systemd unit $UNIT_PATH"
        TMP_UNIT="$(mktemp)"
        systemd_unit "$PREFIX" "$DATA" "$RUN_USER" "$ARGS" multi-user.target > "$TMP_UNIT"
        # The files are already in place: a service manager that refuses is a
        # degraded install, not a failed one. Say so and keep going.
        if run_priv cp "$TMP_UNIT" "$UNIT_PATH" \
           && run_priv systemctl daemon-reload; then
            run_priv systemctl enable "$SERVICE" >/dev/null 2>&1 \
                || warn "Could not enable $SERVICE at boot"
            ok "Service $SERVICE will start at boot"
        else
            warn "systemd refused the unit — NMesh is installed but will not autostart"
            INIT=none
        fi
        rm -f "$TMP_UNIT";;
    systemd-user)
        info "Installing user systemd unit $UNIT_PATH"
        mkdir -p "$(dirname "$UNIT_PATH")"
        systemd_unit "$PREFIX" "$DATA" "" "$ARGS" default.target > "$UNIT_PATH"
        systemctl --user daemon-reload || warn "systemctl --user daemon-reload failed"
        systemctl --user enable "$SERVICE" >/dev/null 2>&1 || warn "Could not enable $SERVICE at boot"
        # Without lingering a user service only runs while you are logged in —
        # which is not "starts with the machine".
        if command -v loginctl >/dev/null 2>&1; then
            if [ "$(loginctl show-user "$(id -un)" -p Linger --value 2>/dev/null || echo no)" != "yes" ]; then
                if [ "$SUDO" != none ]; then
                    run_priv loginctl enable-linger "$(id -un)" >/dev/null 2>&1 \
                        && ok "Lingering enabled — the node starts without a login session" \
                        || warn "Could not enable lingering: the node will only run while you are logged in (sudo loginctl enable-linger $(id -un))"
                else
                    warn "No lingering: the node runs only while you are logged in (sudo loginctl enable-linger $(id -un))"
                fi
            fi
        fi
        ok "Service $SERVICE will start at boot";;
    openrc)
        info "Installing OpenRC service $UNIT_PATH"
        TMP_RC="$(mktemp)"
        openrc_service "$PREFIX" "$DATA" "$RUN_USER" "$ARGS" "$SERVICE" > "$TMP_RC"
        if run_priv cp "$TMP_RC" "$UNIT_PATH" && run_priv chmod +x "$UNIT_PATH"; then
            run_priv rc-update add "$SERVICE" default >/dev/null 2>&1 \
                || warn "Could not enable $SERVICE at boot"
            ok "Service $SERVICE will start at boot"
        else
            warn "OpenRC refused the service — NMesh is installed but will not autostart"
            INIT=none
        fi
        rm -f "$TMP_RC";;
    launchd)
        info "Installing launchd agent $UNIT_PATH"
        mkdir -p "$(dirname "$UNIT_PATH")"
        launchd_plist "$PREFIX" "$DATA" "org.nmesh.$SERVICE" "$ARGS" > "$UNIT_PATH"
        ok "Agent org.nmesh.$SERVICE will start at login";;
    *)
        warn "No supported init system found — nothing will start automatically."
        warn "Run it yourself with:  cd $PREFIX && NMESH_DATA=$DATA ./start.sh $ARGS";;
esac

# ── start ────────────────────────────────────────────────────────────────────
if [ "$DO_START" = true ]; then
    info "Starting NMesh…"
    STARTED=true
    case "$INIT" in
        systemd-system) run_priv systemctl restart "$SERVICE" || STARTED=false;;
        systemd-user)   systemctl --user restart "$SERVICE" || STARTED=false;;
        openrc)         run_priv rc-service "$SERVICE" restart \
                            || run_priv rc-service "$SERVICE" start || STARTED=false;;
        launchd)        launchctl unload "$UNIT_PATH" >/dev/null 2>&1 || true
                        launchctl load "$UNIT_PATH" || STARTED=false;;
        *)              STARTED=false
                        warn "Not starting: no service manager";;
    esac
    if [ "$STARTED" = true ] && [ "$INIT" != none ]; then
        ok "NMesh is running"
    elif [ "$INIT" != none ]; then
        warn "The service did not start — see: $(service_hint "$INIT" "$SERVICE")"
    fi
else
    info "Not starting now (--no-start)"
fi

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  Installed in : $PREFIX"
echo "  State in     : $DATA"
echo "  Service      : $SERVICE ($INIT)"
echo "  Follow it    : $(service_hint "$INIT" "$SERVICE")"
echo ""
echo "  The console prints its URL and a generated password on first"
echo "  start — read them from the service log above."
echo ""
echo "  Upgrade later : re-run ./install.sh from a newer checkout,"
echo "                  or use the console's Settings → Updates page."
echo "  Remove        : ./install.sh --uninstall"
echo "═══════════════════════════════════════════════════════════════"
echo ""
