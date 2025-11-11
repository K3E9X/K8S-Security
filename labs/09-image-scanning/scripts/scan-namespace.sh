#!/bin/bash
#
# scan-namespace.sh - Scan all images in a namespace
#

set -euo pipefail

NAMESPACE="${1:-default}"

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo ""
echo -e "${BLUE}Scanning images in namespace: ${NAMESPACE}${NC}"
echo ""

# Get all unique images in the namespace
IMAGES=$(kubectl get pods -n "$NAMESPACE" -o jsonpath='{.items[*].spec.containers[*].image}' | tr ' ' '\n' | sort -u)

if [ -z "$IMAGES" ]; then
    echo -e "${YELLOW}No images found in namespace ${NAMESPACE}${NC}"
    exit 0
fi

echo "Found images:"
echo "$IMAGES"
echo ""

# Scan each image
for IMAGE in $IMAGES; do
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${GREEN}Scanning: ${IMAGE}${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

    if ! trivy image --severity HIGH,CRITICAL --ignore-unfixed "$IMAGE"; then
        echo -e "${YELLOW}Warning: Scan failed for ${IMAGE}${NC}"
    fi

    echo ""
done

echo -e "${GREEN}✓ Namespace scan complete${NC}"
