#!/bin/sh
# Stage and compress a release tarball for Linux/macOS builds.
# FreeBSD tarballs are produced by freebsd/build-local.sh with the same layout.
#
# Usage: ci/package.sh <version> <label> <bin-dir> <out-dir> [extra-file...]
#   version   e.g. 1.19.0
#   label     e.g. linux-x86_64, macos-aarch64
#   bin-dir   directory holding the built rdns and rdns-control binaries
#   out-dir   where <name>.tar.xz and <name>.tar.xz.sha256 are written
#   extra     platform-specific files to include (e.g. dist/rdns.service)

set -eu

[ $# -ge 4 ] || { echo "usage: $0 <version> <label> <bin-dir> <out-dir> [extra-file...]" >&2; exit 1; }

VERSION="$1"
LABEL="$2"
BIN_DIR="$3"
OUT_DIR="$4"
shift 4

NAME="rdns-${VERSION}-${LABEL}"
mkdir -p "$OUT_DIR"
OUT_DIR="$(cd "$OUT_DIR" && pwd)"
STAGE="$(mktemp -d)/${NAME}"
mkdir -p "$STAGE"

cp "${BIN_DIR}/rdns" "${BIN_DIR}/rdns-control" "$STAGE/"
cp rdns.toml.example LICENSE README.md "$STAGE/"
for f in "$@"; do
    cp "$f" "$STAGE/"
done

( cd "$(dirname "$STAGE")" && XZ_OPT='-9 -T0' tar -cJf "${OUT_DIR}/${NAME}.tar.xz" "$NAME" )
( cd "$OUT_DIR" && shasum -a 256 "${NAME}.tar.xz" > "${NAME}.tar.xz.sha256" )
rm -rf "$(dirname "$STAGE")"

ls -lh "${OUT_DIR}/${NAME}.tar.xz"
cat "${OUT_DIR}/${NAME}.tar.xz.sha256"
