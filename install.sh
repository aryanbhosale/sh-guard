#!/bin/sh
set -e

REPO="aryanbhosale/sh-guard"
BINARY="sh-guard"

# Detect OS and architecture
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case "$ARCH" in
    x86_64) ARCH="x86_64" ;;
    aarch64|arm64) ARCH="aarch64" ;;
    *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

case "$OS" in
    linux) TARGET="${ARCH}-unknown-linux-gnu" ;;
    darwin) TARGET="${ARCH}-apple-darwin" ;;
    *) echo "Unsupported OS: $OS"; exit 1 ;;
esac

# Get latest release
VERSION=$(curl -s "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | cut -d'"' -f4)
if [ -z "$VERSION" ]; then
    echo "Could not determine latest version. Install via: cargo install sh-guard-cli"
    exit 1
fi

URL="https://github.com/${REPO}/releases/download/${VERSION}/sh-guard-${TARGET}.tar.gz"
echo "Downloading sh-guard ${VERSION} for ${TARGET}..."

TMPDIR=$(mktemp -d)
curl -sL "$URL" -o "${TMPDIR}/sh-guard.tar.gz"
tar xzf "${TMPDIR}/sh-guard.tar.gz" -C "${TMPDIR}"

# Install to /usr/local/bin or ~/.local/bin
if [ -w /usr/local/bin ]; then
    INSTALL_DIR="/usr/local/bin"
else
    INSTALL_DIR="${HOME}/.local/bin"
    mkdir -p "$INSTALL_DIR"
fi

cp "${TMPDIR}/sh-guard" "${INSTALL_DIR}/"
cp "${TMPDIR}/sh-guard-mcp" "${INSTALL_DIR}/" 2>/dev/null || true
chmod +x "${INSTALL_DIR}/sh-guard"
chmod +x "${INSTALL_DIR}/sh-guard-mcp" 2>/dev/null || true
rm -rf "$TMPDIR"

echo "sh-guard ${VERSION} installed to ${INSTALL_DIR}/sh-guard"
echo ""
echo "To auto-configure all your AI coding agents:"
echo "  sh-guard --setup"
