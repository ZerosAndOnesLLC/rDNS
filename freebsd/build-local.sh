#!/bin/sh
# rDNS Local Build — run this on a FreeBSD 15 machine to produce the release tarball.
# Usage: ./build-local.sh [version]
#   version defaults to the value in Cargo.toml

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

die() {
    echo "ERROR: $1" >&2
    exit 1
}

# --- Must be FreeBSD ---
if [ "$(uname -s)" != "FreeBSD" ]; then
    die "This script must be run on FreeBSD"
fi

# --- Must be root (pkg install, /usr/obj write) ---
if [ "$(id -u)" -ne 0 ]; then
    die "Must be run as root (try: sudo sh $0)"
fi

# --- Install dependencies ---
echo "=== [1/5] Installing dependencies ==="
pkg install -y curl git xz

# `sudo` clears PATH, so even if rust is already installed under root's home
# we won't see `cargo` on PATH unless we source cargo's env first.
if [ -f "$HOME/.cargo/env" ]; then
    . "$HOME/.cargo/env"
fi

if ! command -v cargo >/dev/null 2>&1; then
    echo "Installing Rust via rustup..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
        | sh -s -- -y --default-toolchain stable --profile minimal
    . "$HOME/.cargo/env"
fi

echo "--- Using cargo: $(command -v cargo) ---"
cargo --version

# --- Extract version + target ---
cd "$PROJECT_ROOT"
VERSION="${1:-$(grep '^version' Cargo.toml | head -1 | sed 's/.*"\(.*\)"/\1/')}"
ARCH="$(uname -m)"
OS_MAJOR="$(freebsd-version | awk -F. '{print $1}')"
TARGET="freebsd-${OS_MAJOR}-${ARCH}"
STAGE_NAME="rdns-${VERSION}-${TARGET}"

echo ""
echo "  Building rDNS v${VERSION} for ${TARGET}"
echo ""

# --- Build Rust binaries ---
echo "=== [2/5] Building Rust binaries (release) ==="
echo "--- rDNS commit: $(git -C "$PROJECT_ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown) ---"
cargo build --release --locked

# --- Stage release artifacts ---
echo "=== [3/5] Staging release artifacts ==="
OUTPUTDIR="/usr/obj/rdns-release"
mkdir -p "$OUTPUTDIR"

STAGE_DIR="${OUTPUTDIR}/${STAGE_NAME}"
rm -rf "$STAGE_DIR" \
       "${OUTPUTDIR}/${STAGE_NAME}.tar.xz" \
       "${OUTPUTDIR}/${STAGE_NAME}.tar.xz.sha256"
mkdir -p "$STAGE_DIR"

cp "$PROJECT_ROOT/target/release/rdns"         "$STAGE_DIR/"
cp "$PROJECT_ROOT/target/release/rdns-control" "$STAGE_DIR/"
cp "$PROJECT_ROOT/rdns.toml.example"           "$STAGE_DIR/"
cp "$PROJECT_ROOT/dist/rdns.rc"                "$STAGE_DIR/"
cp "$PROJECT_ROOT/LICENSE"                     "$STAGE_DIR/"
cp "$PROJECT_ROOT/README.md"                   "$STAGE_DIR/"

# --- Compress tarball ---
echo "=== [4/5] Compressing tarball (xz -9 -T0) ==="
( cd "$OUTPUTDIR" && XZ_OPT='-9 -T0' tar -cJf "${STAGE_NAME}.tar.xz" "${STAGE_NAME}" )
( cd "$OUTPUTDIR" && sha256 -r "${STAGE_NAME}.tar.xz" > "${STAGE_NAME}.tar.xz.sha256" )
rm -rf "$STAGE_DIR"

# --- Done ---
echo "=== [5/5] Done ==="
echo ""
ls -lh "${OUTPUTDIR}/${STAGE_NAME}.tar.xz"
echo ""
echo "Tarball: ${OUTPUTDIR}/${STAGE_NAME}.tar.xz"
echo "SHA256:  $(cat "${OUTPUTDIR}/${STAGE_NAME}.tar.xz.sha256")"
echo ""
echo "Next: run freebsd/release.sh to publish this tarball to a GitHub release."
