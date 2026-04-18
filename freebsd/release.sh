#!/bin/sh
# rDNS Release — tag and upload the tarball produced by build-local.sh.
# Usage: ./release.sh [version]
#   version defaults to the value in Cargo.toml
#   Requires: gh (GitHub CLI) authenticated
#
# Run from the FreeBSD build machine after build-local.sh has produced the tarball.

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

die() { echo "ERROR: $1" >&2; exit 1; }

command -v gh >/dev/null 2>&1 || die "GitHub CLI (gh) not found. Install: pkg install gh"

# --- Extract version + target ---
VERSION="${1:-$(grep '^version' "$PROJECT_ROOT/Cargo.toml" | head -1 | sed 's/.*"\(.*\)"/\1/')}"
TAG="v${VERSION}"
ARCH="$(uname -m)"
OS_MAJOR="$(freebsd-version | awk -F. '{print $1}')"
TARGET="freebsd-${OS_MAJOR}-${ARCH}"
STAGE_NAME="rdns-${VERSION}-${TARGET}"
OUTPUTDIR="/usr/obj/rdns-release"

TARBALL="${OUTPUTDIR}/${STAGE_NAME}.tar.xz"
TARBALL_SHA="${TARBALL}.sha256"

echo "============================================"
echo "  rDNS Release"
echo "  Version: ${VERSION}"
echo "  Tag:     ${TAG}"
echo "  Target:  ${TARGET}"
echo "============================================"
echo ""

[ -f "$TARBALL" ]     || die "Tarball not found: $TARBALL (run freebsd/build-local.sh first)"
[ -f "$TARBALL_SHA" ] || die "Checksum not found: $TARBALL_SHA"

echo "Artifacts:"
ls -lh "$TARBALL" "$TARBALL_SHA"
echo ""

# --- Create git tag if it doesn't exist ---
cd "$PROJECT_ROOT"
if git rev-parse "$TAG" >/dev/null 2>&1; then
    echo "Tag ${TAG} already exists"
else
    echo "Creating tag ${TAG}..."
    git tag -a "$TAG" -m "rDNS ${VERSION}"
    git push origin "$TAG"
fi

# --- Build release body ---
SHA_LINE="$(cat "$TARBALL_SHA")"
SIZE="$(du -h "$TARBALL" | awk '{print $1}')"
BODY="## rDNS v${VERSION}

High-performance, security-focused DNS server — build for ${TARGET}.

### Downloads

| File | Size | Description |
|------|------|-------------|
| \`${STAGE_NAME}.tar.xz\` | ${SIZE} | rdns + rdns-control binaries, example config, rc.d script, LICENSE, README |

### Verify Downloads

\`\`\`
${SHA_LINE}
\`\`\`"

# --- Create or update GitHub release ---
echo ""
echo "Creating GitHub release ${TAG}..."
if gh release view "$TAG" >/dev/null 2>&1; then
    echo "Release ${TAG} exists, uploading assets..."
    gh release upload "$TAG" "$TARBALL" "$TARBALL_SHA" --clobber
    gh release edit "$TAG" --draft=false --title "rDNS v${VERSION}" --notes "$BODY" 2>/dev/null || true
else
    gh release create "$TAG" \
        "$TARBALL" "$TARBALL_SHA" \
        --title "rDNS v${VERSION}" \
        --notes "$BODY"
fi

# --- Cleanup old releases (keep most recent N) ---
MAX_RELEASES=20
echo ""
echo "Checking for old releases to clean up (keeping ${MAX_RELEASES})..."
RELEASE_COUNT=$(gh release list --limit 1000 --json tagName -q 'length')
if [ "$RELEASE_COUNT" -gt "$MAX_RELEASES" ]; then
    DELETE_COUNT=$((RELEASE_COUNT - MAX_RELEASES))
    echo "Found ${RELEASE_COUNT} releases, deleting oldest ${DELETE_COUNT}..."
    gh release list --limit 1000 --json tagName -q '.[].tagName' \
        | tail -n "$DELETE_COUNT" \
        | while read -r OLD_TAG; do
              echo "  Deleting release ${OLD_TAG}..."
              gh release delete "$OLD_TAG" --yes --cleanup-tag 2>/dev/null || true
          done
    echo "Cleanup complete. ${MAX_RELEASES} releases retained."
else
    echo "Only ${RELEASE_COUNT} releases, no cleanup needed."
fi

# --- Cleanup old build artifacts ---
echo "Cleaning old tarballs from ${OUTPUTDIR} (keeping v${VERSION})..."
find "$OUTPUTDIR" -maxdepth 1 -type f -name 'rdns-*' -not -name "*${VERSION}*" -delete 2>/dev/null || true

echo ""
echo "============================================"
echo "  Release complete!"
echo "============================================"
echo ""
gh release view "$TAG" --json url -q '.url'
