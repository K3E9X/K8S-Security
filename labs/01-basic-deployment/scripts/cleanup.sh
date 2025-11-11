#!/bin/bash
#
# cleanup.sh - Clean up Lab 01 resources
#

set -euo pipefail

NAMESPACE="lab01-basic-deployment"

echo "Cleaning up Lab 01: Basic Deployment"
echo "====================================="
echo ""

# Check if namespace exists
if kubectl get namespace "${NAMESPACE}" &> /dev/null; then
    echo "Deleting namespace: ${NAMESPACE}"
    kubectl delete namespace "${NAMESPACE}" --wait=true
    echo "✓ Namespace deleted"
else
    echo "Namespace ${NAMESPACE} does not exist"
fi

echo ""
echo "Cleanup complete!"
