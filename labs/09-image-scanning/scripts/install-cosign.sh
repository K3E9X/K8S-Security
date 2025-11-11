#!/bin/bash
#
# install-cosign.sh - Install Cosign for image signing
#

set -euo pipefail

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "Installing Cosign..."

if command -v cosign &> /dev/null; then
    echo -e "${YELLOW}Cosign is already installed: $(cosign version)${NC}"
    exit 0
fi

# Detect OS and Architecture
OS="$(uname -s)"
ARCH="$(uname -m)"

case "${OS}" in
    Linux*)     PLATFORM="linux";;
    Darwin*)    PLATFORM="darwin";;
    *)          echo "Unsupported OS: ${OS}"; exit 1;;
esac

case "${ARCH}" in
    x86_64)     ARCH="amd64";;
    arm64)      ARCH="arm64";;
    aarch64)    ARCH="arm64";;
    *)          echo "Unsupported architecture: ${ARCH}"; exit 1;;
esac

# Download and install Cosign
COSIGN_VERSION="v2.2.0"
BINARY_URL="https://github.com/sigstore/cosign/releases/download/${COSIGN_VERSION}/cosign-${PLATFORM}-${ARCH}"

echo "Downloading Cosign ${COSIGN_VERSION} for ${PLATFORM}-${ARCH}..."
curl -L -o cosign "${BINARY_URL}"
chmod +x cosign
sudo mv cosign /usr/local/bin/

# Verify installation
if command -v cosign &> /dev/null; then
    echo -e "${GREEN}✓ Cosign installed successfully!${NC}"
    cosign version
else
    echo "Failed to install Cosign"
    exit 1
fi
