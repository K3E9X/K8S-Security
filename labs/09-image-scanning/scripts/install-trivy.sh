#!/bin/bash
#
# install-trivy.sh - Install Trivy vulnerability scanner
#

set -euo pipefail

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "Installing Trivy..."

if command -v trivy &> /dev/null; then
    echo -e "${YELLOW}Trivy is already installed: $(trivy --version)${NC}"
    exit 0
fi

# Detect OS
OS="$(uname -s)"
case "${OS}" in
    Linux*)     PLATFORM=Linux;;
    Darwin*)    PLATFORM=macOS;;
    *)          echo "Unsupported OS: ${OS}"; exit 1;;
esac

# Install Trivy
if [ "$PLATFORM" = "Linux" ]; then
    # Install for Linux
    wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
    echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee -a /etc/apt/sources.list.d/trivy.list
    sudo apt-get update
    sudo apt-get install -y trivy
elif [ "$PLATFORM" = "macOS" ]; then
    # Install for macOS
    brew install trivy
fi

# Verify installation
if command -v trivy &> /dev/null; then
    echo -e "${GREEN}✓ Trivy installed successfully!${NC}"
    trivy --version
else
    echo "Failed to install Trivy"
    exit 1
fi
