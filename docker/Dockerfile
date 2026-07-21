# NMesh application image — runs a relay node with the web console (and optional
# data connector). Suitable for hosting a node on a server that opens TCP ports
# and acts as a mesh relay / rendezvous point.
#
# Builds FROM the prebuilt base image (docker/Dockerfile.base), which already
# carries Python + a compiled liboqs. This image only layers the NMesh code on
# top, so it builds in seconds and never recompiles the crypto library. Override
# the base with --build-arg BASE_IMAGE=... (CI builds it locally when the
# published one isn't reachable).
ARG BASE_IMAGE=ghcr.io/fnyaker/nmesh-base:latest
FROM ${BASE_IMAGE}

WORKDIR /app

# Dependencies already live in the base image (installed from the same
# requirements.txt). Only the application code is added here.
COPY src/ ./src/
COPY scripts/ ./scripts/
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Persistent state: identity, cert store, session store, console credentials.
VOLUME ["/data"]

# 9000 = mesh TCP transport ; 8787 = web console.
EXPOSE 9000 8787

ENTRYPOINT ["/entrypoint.sh"]
