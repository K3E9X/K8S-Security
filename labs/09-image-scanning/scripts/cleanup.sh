#!/bin/bash
set -euo pipefail

echo "Cleaning up Lab 09: Image Scanning"
echo "==================================="

kubectl delete namespace lab09-scanning --ignore-not-found

# Clean up local artifacts
rm -f trivy-report.json sbom*.json cosign.key cosign.pub 2>/dev/null || true

echo "✓ Cleanup complete!"
