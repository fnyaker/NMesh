#!/usr/bin/env bash
#
# One-shot launcher for a NMesh node with the web console.
#
#   ./start.sh                                  # node + console on ./data
#   ./start.sh --connector-port 8790            # also expose the data connector
#   ./start.sh --spool /mnt/usb/mesh            # add a store-and-forward link
#   ./start.sh --console-host 0.0.0.0           # reach the console from the LAN
#
# Any extra arguments are passed straight to scripts/console_demo.py, so this is
# also how you attach custom transports/connectors at launch. On first run it
# creates a virtualenv, installs the (few) dependencies, and builds liboqs.
set -euo pipefail
cd "$(dirname "$0")"

PYTHON="${PYTHON:-python3}"
VENV="${NMESH_VENV:-.venv}"

if [ ! -d "$VENV" ]; then
    echo "[start.sh] creating virtualenv in $VENV"
    "$PYTHON" -m venv "$VENV"
fi
# shellcheck disable=SC1091
. "$VENV/bin/activate"

echo "[start.sh] installing dependencies"
pip install --quiet --upgrade pip
pip install --quiet -r requirements.txt

echo "[start.sh] warming up post-quantum crypto (first run compiles liboqs)"
python -c "import oqs" >/dev/null

DATA="${NMESH_DATA:-./data}"
mkdir -p "$DATA"

echo "[start.sh] launching node — state in $DATA"
exec python -u scripts/console_demo.py --data "$DATA" "$@"
