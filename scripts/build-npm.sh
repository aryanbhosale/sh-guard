#!/bin/bash
set -e

# Build npm platform packages from release artifacts.
# Usage: ./scripts/build-npm.sh <version>

VERSION="${1:-0.1.0}"
PLATFORMS=("darwin-arm64" "darwin-x64" "linux-arm64" "linux-x64" "win32-x64")
TARGETS=("aarch64-apple-darwin" "x86_64-apple-darwin" "aarch64-unknown-linux-gnu" "x86_64-unknown-linux-gnu" "x86_64-pc-windows-msvc")

for i in "${!PLATFORMS[@]}"; do
    PLATFORM="${PLATFORMS[$i]}"
    TARGET="${TARGETS[$i]}"
    PKG_DIR="npm/sh-guard-cli-${PLATFORM}"
    BIN_DIR="${PKG_DIR}/bin"

    echo "Building ${PLATFORM} from ${TARGET}..."

    mkdir -p "${BIN_DIR}"

    # Copy binary from release build
    if [[ "$PLATFORM" == win32-* ]]; then
        cp "target/${TARGET}/release/sh-guard.exe" "${BIN_DIR}/"
    else
        cp "target/${TARGET}/release/sh-guard" "${BIN_DIR}/"
        chmod +x "${BIN_DIR}/sh-guard"
    fi

    # Update version in package.json
    cd "${PKG_DIR}"
    npm version "${VERSION}" --no-git-tag-version --allow-same-version 2>/dev/null || true
    cd -
done

# Update wrapper version
cd npm/sh-guard
npm version "${VERSION}" --no-git-tag-version --allow-same-version 2>/dev/null || true
cd -

echo "Done. Run 'npm publish' in each npm/* directory to publish."
