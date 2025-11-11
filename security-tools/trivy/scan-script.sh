#!/bin/bash
# Trivy image scanning script

set -euo pipefail

IMAGE="${1:-}"
if [ -z "$IMAGE" ]; then
    echo "Usage: $0 <image>"
    exit 1
fi

echo "Scanning image: $IMAGE"

# Scan for vulnerabilities
trivy image \
    --severity CRITICAL,HIGH \
    --exit-code 1 \
    --format json \
    --output trivy-results.json \
    "$IMAGE"

# Scan for misconfigurations
trivy config \
    --severity CRITICAL,HIGH \
    --format table \
    .

echo "Scan complete!"
