#!/usr/bin/env bash
#
# Fetch the liboqs release named in scripts/liboqs.lock, prove it is that
# release, and build it into a prefix:
#
#     scripts/build_liboqs.sh <prefix> [jobs]
#
# The source arrives from GitHub, by `git clone` of the tag or, without git, as
# the tag's archive. Either way it is checked before a line of it is compiled:
# the clone's HEAD must be the locked commit, the archive must hash to the
# locked digest. Anything else is refused — never another tag, never `main`.
# This is the post-quantum half of every node's crypto.
#
# Shared by start.sh and docker/Dockerfile.base, so there is one definition of
# which liboqs a node runs and how it is built.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOCK="$HERE/liboqs.lock"

die() { echo "build_liboqs: $*" >&2; exit 1; }

[ $# -ge 1 ] || die "usage: build_liboqs.sh <prefix> [jobs]"
PREFIX="$1"
JOBS="${2:-1}"
case "$JOBS" in ''|*[!0-9]*) die "jobs must be a number" ;; esac

lock_value() {
    local value
    value="$(sed -n "s/^$1=\([0-9A-Za-z.]*\)\$/\1/p" "$LOCK" | head -n 1)"
    [ -n "$value" ] || die "$1 missing from $LOCK"
    printf '%s' "$value"
}

VERSION="$(lock_value LIBOQS_VERSION)"
COMMIT="$(lock_value LIBOQS_COMMIT)"
DIGEST="$(lock_value LIBOQS_TARBALL_SHA256)"
[ ${#COMMIT} -eq 40 ] || die "LIBOQS_COMMIT is not a full commit id"
[ ${#DIGEST} -eq 64 ] || die "LIBOQS_TARBALL_SHA256 is not a SHA-256"

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | cut -d' ' -f1
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | cut -d' ' -f1
    else
        python3 -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$1"
    fi
}

# The build tree is a few hundred MB: on a small machine /tmp is often RAM, so a
# caller can name a directory on disk instead (start.sh does).
if [ -n "${LIBOQS_BUILD_DIR:-}" ]; then
    WORK="$LIBOQS_BUILD_DIR"
    rm -rf "$WORK"
    mkdir -p "$WORK"
else
    WORK="$(mktemp -d "${TMPDIR:-/tmp}/liboqs-build.XXXXXXXX")"
fi
trap 'rm -rf "$WORK"' EXIT
SRC="$WORK/liboqs"

fetched=false
if command -v git >/dev/null 2>&1 \
   && git clone --quiet --depth 1 --branch "$VERSION" \
        https://github.com/open-quantum-safe/liboqs.git "$SRC" 2>/dev/null; then
    head="$(git -C "$SRC" rev-parse HEAD)"
    [ "$head" = "$COMMIT" ] \
        || die "tag $VERSION is commit $head, the lock says $COMMIT — refusing to build it"
    fetched=true
else
    rm -rf "$SRC"
fi

if [ "$fetched" != true ]; then
    command -v curl >/dev/null 2>&1 && command -v tar >/dev/null 2>&1 \
        || die "need git, or curl and tar, to fetch liboqs"
    curl -fsSL "https://github.com/open-quantum-safe/liboqs/archive/refs/tags/$VERSION.tar.gz" \
        -o "$WORK/liboqs.tar.gz" || die "could not download liboqs $VERSION"
    seen="$(sha256_of "$WORK/liboqs.tar.gz")"
    [ "$seen" = "$DIGEST" ] \
        || die "liboqs $VERSION archive hashes to $seen, the lock says $DIGEST — refusing to build it"
    mkdir -p "$SRC"
    tar -xzf "$WORK/liboqs.tar.gz" -C "$SRC" --strip-components=1 \
        || die "the liboqs archive does not unpack"
fi

GENERATOR=()
command -v ninja >/dev/null 2>&1 && GENERATOR=(-GNinja)

# The wrapper's own feature set (the stateful signature symbols must exist or
# it fails to load), minus OpenSSL so no dev headers are needed.
cmake -S "$SRC" -B "$WORK/build" "${GENERATOR[@]}" \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_SHARED_LIBS=ON \
    -DOQS_BUILD_ONLY_LIB=ON \
    -DOQS_USE_OPENSSL=OFF \
    -DOQS_ENABLE_SIG_STFL_LMS=ON \
    -DOQS_ENABLE_SIG_STFL_XMSS=ON \
    -DOQS_HAZARDOUS_EXPERIMENTAL_ENABLE_SIG_STFL_KEY_SIG_GEN=ON \
    -DCMAKE_INSTALL_PREFIX="$PREFIX" \
    || die "cmake configure failed"
cmake --build "$WORK/build" --parallel "$JOBS" || die "build failed"
cmake --install "$WORK/build" || die "install failed"
# What this build was proven to be, beside it. start.sh reuses a library only
# when this matches the lock it is running with; nothing else writes it.
grep -E '^LIBOQS_(VERSION|COMMIT|TARBALL_SHA256)=' "$LOCK" > "$PREFIX/nmesh-liboqs.lock"
echo "build_liboqs: liboqs $VERSION ($COMMIT) installed in $PREFIX"
