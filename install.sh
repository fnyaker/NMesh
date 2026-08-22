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
# As root the node gets its own locked-down system account (`nmesh`, no login,
# no password): it owns the install and the state, both mode 700, so nothing on
# the machine but that account and root can read the node's identity keys.
# `--run-as root` opts out; `--run-as somebody` uses an existing account.
#
# Re-running it upgrades in place: the tree is replaced, **state is never
# touched**, and the service is restarted.
#
# Environment switches:
#   NMESH_PREFIX=path    install directory
#   NMESH_DATA=path      node state directory
#   NMESH_SERVICE=name   service name (default nmesh)
#   NMESH_USER=name      account the service runs as (root install: nmesh)
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

# ── directories ──────────────────────────────────────────────────────────────
# Escalating to create a directory hands it to root. `sudo mkdir -p
# ~/.local/share/nmesh/data` did exactly that on a user install: the node runs
# as the user and died on its very first write with
# "Permission denied: .../data/node.key.tmp". So: create it ourselves whenever
# we can, escalate only when the parent really is out of reach, and always make
# sure whoever will run the node ends up owning it. Re-running the installer
# therefore also repairs a directory a previous run got wrong.
ensure_dir() {
    local path="$1" owner="${2:-}"
    if [ ! -d "$path" ]; then
        mkdir -p "$path" 2>/dev/null || run_priv mkdir -p "$path" || return 1
    fi
    [ -n "$owner" ] || return 0
    if is_root; then
        run_priv chown -R "$owner" "$path" 2>/dev/null || true
    elif [ ! -w "$path" ]; then
        run_priv chown -R "$owner" "$path" 2>/dev/null \
            || warn "Could not give $path to $owner — the node will not be able to write there"
    fi
}

# `run_priv` is a no-op as root and refuses loudly when there is no way up.
run_priv() {
    if [ -z "$SUDO" ]; then "$@"; return; fi
    if [ "$SUDO" = none ]; then
        fail "This step needs root and neither sudo nor doas is available: $*"
    fi
    $SUDO "$@"
}

# ── the node's own account ───────────────────────────────────────────────────
# A node's data directory holds its identity key, its session store and the
# console password hash. Running it under the account of whoever happened to
# install it means every process that user runs can read all of that. So a root
# install gives the node an account of its own: no login shell, no password,
# nothing else on the machine belongs to it — and its files are mode 700.
#
# Nothing here is fatal: an account that cannot be created falls back to the
# invoking user, which is exactly what the previous behaviour was.
nologin_path() {
    local candidate
    for candidate in /usr/sbin/nologin /sbin/nologin /usr/bin/nologin; do
        [ -x "$candidate" ] && { echo "$candidate"; return; }
    done
    echo /bin/false
}

user_exists() {
    id -u "$1" >/dev/null 2>&1
}

# Every distro spells "create a system account" differently and most of them
# reject the others' flags, so this tries them in turn rather than guessing from
# the distro name — the account either exists at the end or it does not.
create_service_user() {
    local name="$1" home="$2" shell
    user_exists "$name" && return 0
    shell="$(nologin_path)"
    if command -v useradd >/dev/null 2>&1; then
        run_priv useradd --system --no-create-home --home-dir "$home" \
                 --shell "$shell" "$name" 2>/dev/null && return 0
        run_priv useradd -r -M -d "$home" -s "$shell" "$name" 2>/dev/null && return 0
    fi
    if command -v adduser >/dev/null 2>&1; then
        run_priv adduser --system --group --no-create-home --home "$home" \
                 --shell "$shell" "$name" 2>/dev/null && return 0
        # busybox / Alpine: the group has to be made first.
        run_priv addgroup -S "$name" 2>/dev/null || true
        run_priv adduser -S -D -H -h "$home" -s "$shell" -G "$name" "$name" \
                 2>/dev/null && return 0
    fi
    if command -v pw >/dev/null 2>&1; then          # FreeBSD
        run_priv pw useradd "$name" -d "$home" -s "$shell" -w no 2>/dev/null \
            && return 0
    fi
    return 1
}

delete_service_user() {
    local name="$1"
    user_exists "$name" || return 0
    command -v userdel  >/dev/null 2>&1 && run_priv userdel  "$name" 2>/dev/null && return 0
    command -v deluser  >/dev/null 2>&1 && run_priv deluser  "$name" 2>/dev/null && return 0
    command -v pw       >/dev/null 2>&1 && run_priv pw userdel "$name" 2>/dev/null && return 0
    return 1
}

# `chown user:group` when the account has a group of its own, `chown user`
# otherwise — a `chown x:x` against a system that put the account in `nogroup`
# fails outright and would leave the tree unreadable to the node.
owner_spec() {
    local name="$1" group
    group="$(id -gn "$name" 2>/dev/null || true)"
    if [ -n "$group" ]; then echo "$name:$group"; else echo "$name"; fi
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
# The whole install is self-contained under $prefix — including liboqs, which
# start.sh looks for under \$HOME. A system account has no usable home, so
# pointing HOME at the install directory is what keeps the node able to find
# its crypto library and to repair itself on boot.
Environment=HOME=$prefix
Environment=OQS_INSTALL_PATH=$prefix/_oqs
# Tells the updater it may restart the node through the service manager rather
# than leaving the operator with a stopped node after an update.
Environment=NMESH_SERVICE_MANAGED=1
ExecStart=$prefix/start.sh $args
Restart=always
RestartSec=5
# The node needs no new privileges and no private state outside its data dir.
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectSystem=full

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
export HOME="$prefix"
export OQS_INSTALL_PATH="$prefix/_oqs"
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
        echo "    <key>HOME</key><string>$prefix</string>"
        echo "    <key>OQS_INSTALL_PATH</key><string>$prefix/_oqs</string>"
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
        -h|--help)    sed -n '2,37p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0;;
        *)            NODE_ARGS+=("$1"); shift;;
    esac
done

detect_sudo
INIT="$(detect_init)"
[ -n "$PREFIX" ] || PREFIX="$(default_prefix)"
[ -n "$DATA" ]   || DATA="$(default_data "$PREFIX")"
# As root the node gets a dedicated account (created further down); otherwise it
# can only run as whoever is installing it. `--run-as root` is the way out.
SERVICE_ACCOUNT="${NMESH_ACCOUNT:-nmesh}"
if [ -z "$RUN_USER" ]; then
    if is_root; then RUN_USER="$SERVICE_ACCOUNT"; else RUN_USER="$(id -un)"; fi
fi
[ "$RUN_USER" = root ] && RUN_USER=""

UNIT_PATH=""
case "$INIT" in
    systemd-system) UNIT_PATH="/etc/systemd/system/$SERVICE.service";;
    systemd-user)   UNIT_PATH="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user/$SERVICE.service";;
    openrc)         UNIT_PATH="/etc/init.d/$SERVICE";;
    launchd)        UNIT_PATH="$HOME/Library/LaunchAgents/org.nmesh.$SERVICE.plist";;
esac

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
    # The account only ever existed to own files that are now gone. Without
    # --purge it is left in place: it still owns the state we just kept.
    if [ "$PURGE" = true ] && is_root && [ "$RUN_USER" = "$SERVICE_ACCOUNT" ] \
       && user_exists "$SERVICE_ACCOUNT"; then
        delete_service_user "$SERVICE_ACCOUNT" \
            && ok "Removed the $SERVICE_ACCOUNT account" \
            || warn "Could not remove the $SERVICE_ACCOUNT account"
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
    # A user install must own its directory; a root install stays root-owned.
    ensure_dir "$PREFIX" "$(is_root || echo "$(id -u):$(id -g)")" \
        || fail "Could not create $PREFIX"
    copy_tree "$SOURCE_REAL" "$PREFIX" || fail "Could not copy the NMesh tree"
    chmod +x "$PREFIX/start.sh" "$PREFIX/install.sh" 2>/dev/null || true
    ok "Files installed in $PREFIX"
fi

# ── the account the node runs under ──────────────────────────────────────────
if is_root && [ "$RUN_USER" = "$SERVICE_ACCOUNT" ] && ! user_exists "$RUN_USER"; then
    if create_service_user "$RUN_USER" "$PREFIX"; then
        ok "Created the $RUN_USER system account (no login, no password)"
    else
        warn "Could not create a $RUN_USER account — the node will run as root"
        RUN_USER=""
    fi
fi
if [ -n "$RUN_USER" ] && ! user_exists "$RUN_USER"; then
    fail "No such user: $RUN_USER"
fi

if [ -n "$RUN_USER" ]; then
    OWNER="$(owner_spec "$RUN_USER")"
elif is_root; then
    OWNER="root"
else
    OWNER="$(id -u):$(id -g)"
fi

ensure_dir "$DATA" "$OWNER" || fail "Could not create $DATA"
ok "State directory $DATA"

# ── dependencies: delegated to start.sh, never duplicated ────────────────────
# HOME is pinned to the install directory so liboqs is built *inside* it: the
# node must find the same library at boot as the one built here, and a system
# account has no home of its own to find it in.
info "Installing dependencies (this is start.sh doing its usual work)…"
if ! ( cd "$PREFIX" && HOME="$PREFIX" OQS_INSTALL_PATH="$PREFIX/_oqs" \
       NMESH_SETUP_ONLY=1 ./start.sh ); then
    fail "Dependency setup failed — fix the errors above and re-run ./install.sh"
fi
ok "Dependencies ready"
# start.sh builds liboqs under $HOME, which we just pinned to the install
# directory: the built library stays, its build tree has no reason to.
rm -rf "$PREFIX/_oqs_build" 2>/dev/null || true

# ── lock it down ─────────────────────────────────────────────────────────────
# Only now: the venv and liboqs were just built as the invoking user, and they
# live inside the install directory. Both trees go to the node's account, mode
# 700 — nothing else on the machine can read its identity key, and the node can
# still repair and update itself.
lock_down() {
    local path="$1"
    [ -d "$path" ] || return 0
    if [ "$OWNER" != "$(id -u):$(id -g)" ]; then
        run_priv chown -R "$OWNER" "$path" 2>/dev/null \
            || warn "Could not give $path to $OWNER"
    fi
    chmod 700 "$path" 2>/dev/null || run_priv chmod 700 "$path" 2>/dev/null || true
}
lock_down "$PREFIX"
lock_down "$DATA"
if [ -n "$RUN_USER" ]; then
    ok "Install and state belong to $RUN_USER alone (mode 700)"
else
    warn "The node runs as $(id -un): every process of that user can read its identity key"
fi

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
        if [ -n "$RUN_USER" ]; then
            warn "Run it yourself with:  sudo -u $RUN_USER env HOME=$PREFIX OQS_INSTALL_PATH=$PREFIX/_oqs NMESH_DATA=$DATA $PREFIX/start.sh $ARGS"
        else
            warn "Run it yourself with:  cd $PREFIX && NMESH_DATA=$DATA ./start.sh $ARGS"
        fi;;
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
echo "  Runs as      : ${RUN_USER:-root} (files mode 700)"
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
