#!/usr/bin/env bash
#
# The base image (Python + a compiled liboqs) a job runs or builds on:
#
#     .github/scripts/provide-base.sh <base image:tag>
#
# The published one when base-image.yml on `main` is proven to have built it,
# pinned by digest; otherwise one built here from docker/Dockerfile.base, under
# the given tag. Never a published image that cannot be traced to a build:
# every test, and the image every container node pulls, sit on top of it.
# Prints the reference to use.
set -euo pipefail

[ $# -eq 1 ] || { echo "usage: provide-base.sh <base image:tag>" >&2; exit 2; }
base="$1"
[[ "$base" =~ ^[a-z0-9][a-z0-9._/-]*:[A-Za-z0-9._-]+$ ]] \
    || { echo "provide-base: not an image reference: $base" >&2; exit 2; }
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"

if pinned="$("$here/pull-verified.sh" "$base" base-image.yml)"; then
    echo "using the published base image, verified: $pinned" >&2
    echo "$pinned"
    exit 0
fi
echo "the published base image is unreachable or unproven — building it here" >&2
docker rmi "$base" >/dev/null 2>&1 || true
docker build -f "$root/docker/Dockerfile.base" -t "$base" "$root" >&2
echo "$base"
