#!/bin/bash
set -euo pipefail

NAMESPACE="lab03-netpol"
echo "Cleaning up Lab 03: Network Policies"
echo "====================================="
kubectl delete namespace "$NAMESPACE" --ignore-not-found
echo "✓ Cleanup complete!"
