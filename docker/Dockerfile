# NMesh node image — runs a relay node with the web console (and optional data
# connector). Suitable for hosting a node on a server that opens TCP ports and
# acts as a mesh relay / rendezvous point.
FROM python:3.13-slim

# liboqs-python builds liboqs from source with CMake's default generator
# ("Unix Makefiles"), which needs `make` — so build-essential (gcc + g++ +
# make), not a bare gcc, or CMake aborts with "CMAKE_MAKE_PROGRAM is not set".
RUN apt-get update && apt-get install -y --no-install-recommends \
        cmake build-essential python3-dev git libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
# Install deps and pre-build liboqs so the first run isn't slow.
RUN pip install --no-cache-dir -r requirements.txt && python -c "import oqs"

COPY src/ ./src/
COPY scripts/ ./scripts/
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Persistent state: identity, cert store, session store, console credentials.
VOLUME ["/data"]

# 9000 = mesh TCP transport ; 8787 = web console.
EXPOSE 9000 8787

ENTRYPOINT ["/entrypoint.sh"]
