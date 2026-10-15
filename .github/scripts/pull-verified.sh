#!/usr/bin/env bash
#
# Pull an image this repository publishes, and prove which workflow built it:
#
#     .github/scripts/pull-verified.sh <image:tag> <workflow file>
#
# Prints the image pinned by digest (`name@sha256:…`) on success, the one
# reference a later step should use: a tag can be moved between this check and
# the next pull, a digest cannot. Fails unless the digest carries a provenance
# attestation signed by that workflow of this repository, run from `main`.
# Needs GH_TOKEN and GITHUB_REPOSITORY.
set -euo pipefail

[ $# -eq 2 ] || { echo "usage: pull-verified.sh <image:tag> <workflow file>" >&2; exit 2; }
image="$1"
workflow="$2"

docker pull --quiet "$image" >&2
pinned="$(docker inspect --format '{{index .RepoDigests 0}}' "$image")"
# The reference goes on to other steps and into `docker run`: nothing but a
# lowercase registry path and a digest, so it cannot carry a second line or an
# option.
[[ "$pinned" =~ ^[a-z0-9][a-z0-9._/-]*@sha256:[0-9a-f]{64}$ ]] \
    || { echo "pull-verified: $image has no registry digest" >&2; exit 1; }
gh attestation verify "oci://$pinned" \
    --repo "$GITHUB_REPOSITORY" \
    --signer-workflow "$GITHUB_REPOSITORY/.github/workflows/$workflow" \
    --source-ref refs/heads/main >&2
echo "$pinned"
