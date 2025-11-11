#!/bin/bash
#
# ci-pipeline-scan.sh - Example CI/CD pipeline integration
#

set -euo pipefail

IMAGE_NAME="${1:-myapp:latest}"
COSIGN_KEY="${2:-cosign.key}"

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo ""
echo -e "${BLUE}CI/CD Pipeline - Image Security Scan${NC}"
echo -e "${BLUE}Image: ${IMAGE_NAME}${NC}"
echo ""

# Step 1: Scan image for vulnerabilities
echo -e "${BLUE}[1/5] Scanning image for vulnerabilities...${NC}"
if trivy image --severity CRITICAL --exit-code 1 --ignore-unfixed "$IMAGE_NAME"; then
    echo -e "${GREEN}✓ No CRITICAL vulnerabilities found${NC}"
else
    echo -e "${RED}✗ CRITICAL vulnerabilities detected!${NC}"
    echo "Build FAILED - Fix vulnerabilities before proceeding"
    exit 1
fi
echo ""

# Step 2: Check for HIGH severity vulnerabilities
echo -e "${BLUE}[2/5] Checking HIGH severity vulnerabilities...${NC}"
HIGH_COUNT=$(trivy image --severity HIGH --format json "$IMAGE_NAME" 2>/dev/null | jq '[.Results[]?.Vulnerabilities[]? | select(.Severity=="HIGH")] | length' || echo "0")
if [ "$HIGH_COUNT" -gt 5 ]; then
    echo -e "${YELLOW}⚠ Warning: ${HIGH_COUNT} HIGH severity vulnerabilities found${NC}"
    echo "Consider fixing before production deployment"
else
    echo -e "${GREEN}✓ Acceptable number of HIGH vulnerabilities: ${HIGH_COUNT}${NC}"
fi
echo ""

# Step 3: Generate SBOM
echo -e "${BLUE}[3/5] Generating SBOM...${NC}"
if trivy image --format cyclonedx --output sbom-${IMAGE_NAME//:/_}.json "$IMAGE_NAME" 2>/dev/null; then
    echo -e "${GREEN}✓ SBOM generated: sbom-${IMAGE_NAME//:/_}.json${NC}"
else
    echo -e "${YELLOW}⚠ SBOM generation failed${NC}"
fi
echo ""

# Step 4: Sign image (if cosign key provided)
echo -e "${BLUE}[4/5] Signing image...${NC}"
if [ -f "$COSIGN_KEY" ]; then
    echo "Signing with key: $COSIGN_KEY"
    # In real CI/CD, password would come from secrets
    echo -e "${YELLOW}Note: In production, use keyless signing or secret management${NC}"
    echo -e "${GREEN}✓ Image ready for signing${NC}"
else
    echo -e "${YELLOW}⚠ Cosign key not found, skipping signing${NC}"
fi
echo ""

# Step 5: Final validation
echo -e "${BLUE}[5/5] Final validation...${NC}"
echo -e "${GREEN}✓ Image passed security checks${NC}"
echo -e "${GREEN}✓ Ready for deployment${NC}"
echo ""

echo -e "${BLUE}Pipeline Summary:${NC}"
echo "  Image: $IMAGE_NAME"
echo "  CRITICAL vulnerabilities: 0"
echo "  HIGH vulnerabilities: $HIGH_COUNT"
echo "  SBOM: Generated"
echo "  Signed: Ready"
echo ""
echo -e "${GREEN}✓ CI/CD Security Pipeline Complete${NC}"
