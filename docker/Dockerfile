# NMesh application image — runs a relay node with the web console (and optional
# data connector). Suitable for hosting a node on a server that opens TCP ports
# and acts as a mesh relay / rendezvous point.
#
# Takes the compiled liboqs and the installed packages from the prebuilt base
# image (docker/Dockerfile.base) into a fresh slim image, and adds the NMesh
# code, so it builds in seconds and never recompiles the crypto library. Override
# the base with --build-arg BASE_IMAGE=... (CI builds it locally when the
# published one isn't reachable).
ARG BASE_IMAGE=ghcr.io/fnyaker/nmesh-base:latest
FROM ${BASE_IMAGE} AS deps

# What runs is a fresh slim image, not the base: the base carries the compiler,
# CMake, git and the dev headers liboqs was built with, none of which a node
# needs and all of which an attacker on the box would be glad of. Only the
# built library and the installed packages are carried over.
FROM python:3.14-slim@sha256:a2b82f3c48559aa0a8446d9af49826b6e2b2016f4cd2afabfe6013ec53729170

WORKDIR /app

# The fleet app drives the system OpenSSH client to discover and provision
# machines (see Docs/Apps/fleet). Without it the provision capability reports
# itself unavailable, which is the correct behaviour but a poor default for an
# image whose whole point is managing other machines. The upgrade takes the
# distribution's security fixes published since the slim image was cut.
RUN apt-get update && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends openssh-client \
    && rm -rf /var/lib/apt/lists/*

ENV OQS_INSTALL_PATH=/opt/liboqs
COPY --from=deps /opt/liboqs /opt/liboqs
COPY --from=deps /usr/local/lib/python3.14/site-packages /usr/local/lib/python3.14/site-packages
RUN python -c "import oqs; oqs.KeyEncapsulation('ML-KEM-768'); oqs.Signature('ML-DSA-65')"

COPY src/ ./src/
COPY scripts/ ./scripts/
# The fleet app pushes this tree to machines it provisions, and the bootstrap it
# sends runs `install.sh` there (which in turn runs `start.sh`) — see
# Docs/Apps/fleet. Without these the payload cannot be built at all: "no NMesh
# tree at /app".
COPY start.sh install.sh pyproject.toml requirements.txt ./
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Persistent state: identity, cert store, session store, console credentials.
VOLUME ["/data"]

# 9000 = mesh TCP transport ; 8787 = web console.
EXPOSE 9000 8787

ENTRYPOINT ["/entrypoint.sh"]
