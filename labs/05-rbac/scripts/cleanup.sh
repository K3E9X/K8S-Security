#!/bin/bash
set -euo pipefail

echo "Cleaning up Lab 05: RBAC"
echo "========================"

kubectl delete namespace lab05-rbac dev prod --ignore-not-found
kubectl delete clusterrole lab05-pod-reader lab05-namespace-viewer --ignore-not-found
kubectl delete clusterrolebinding lab05-cluster-viewer-binding --ignore-not-found

echo "✓ Cleanup complete!"
