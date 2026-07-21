#!/bin/sh
# Translate NMESH_* environment variables into nmesh_node.py arguments.
#
#   NMESH_LISTEN          mesh TCP listen addr     (default 0.0.0.0:9000)
#   NMESH_CONSOLE_HOST    web console bind host    (default 0.0.0.0)
#   NMESH_CONSOLE_PORT    web console port         (default 8787)
#   NMESH_CONSOLE_PASSWORD  console login password (optional; read straight from
#                           the env by nmesh_node.py — if unset, a strong one
#                           is generated and printed once in the logs)
#   NMESH_CONNECTOR_PORT  data connector port      (optional)
#   NMESH_SPOOL           spool directory          (optional, store-and-forward)
#   NMESH_DATA            state directory          (default /data)
#   NMESH_NO_TLS          set to disable console TLS (not recommended)
set -e

LISTEN="${NMESH_LISTEN:-0.0.0.0:9000}"
CONSOLE_HOST="${NMESH_CONSOLE_HOST:-0.0.0.0}"
CONSOLE_PORT="${NMESH_CONSOLE_PORT:-8787}"
DATA="${NMESH_DATA:-/data}"

set -- --listen "$LISTEN" --console-host "$CONSOLE_HOST" \
       --console-port "$CONSOLE_PORT" --data "$DATA"

[ -n "$NMESH_CONNECTOR_PORT" ] && set -- "$@" --connector-port "$NMESH_CONNECTOR_PORT"
[ -n "$NMESH_SPOOL" ] && set -- "$@" --spool "$NMESH_SPOOL"
[ -n "$NMESH_NO_TLS" ] && set -- "$@" --no-tls

exec python -u scripts/nmesh_node.py "$@"
