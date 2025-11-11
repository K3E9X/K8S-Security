#!/bin/bash
set -euo pipefail

echo "Cleaning up Lab 06: Pod Security"
echo "================================="

kubectl delete namespace lab06-privileged lab06-baseline lab06-restricted lab06-audit --ignore-not-found

echo "✓ Cleanup complete!"
