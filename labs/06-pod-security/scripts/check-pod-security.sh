#!/bin/bash
#
# check-pod-security.sh - Check pod security compliance
#

set -euo pipefail

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Pod Security Compliance Check${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

NAMESPACES=("lab06-privileged" "lab06-baseline" "lab06-restricted")

for NS in "${NAMESPACES[@]}"; do
    if ! kubectl get namespace "$NS" &>/dev/null; then
        echo -e "${YELLOW}Namespace $NS does not exist, skipping${NC}"
        continue
    fi

    echo -e "${BLUE}Checking namespace: $NS${NC}"

    # Show Pod Security labels
    echo "Pod Security Standards:"
    kubectl get namespace "$NS" -o jsonpath='{.metadata.labels}' | grep -o 'pod-security[^,}]*' | sed 's/:/: /'
    echo ""

    # Get pods
    PODS=$(kubectl get pods -n "$NS" -o name 2>/dev/null || echo "")

    if [ -z "$PODS" ]; then
        echo -e "${YELLOW}  No pods in namespace${NC}"
    else
        for POD in $PODS; do
            POD_NAME=$(echo $POD | cut -d'/' -f2)
            echo "  Pod: $POD_NAME"

            # Check if running as root
            if kubectl get pod "$POD_NAME" -n "$NS" -o jsonpath='{.spec.containers[*].securityContext.runAsUser}' | grep -q "^0$\|^$"; then
                echo -e "    ${RED}✗ May be running as root${NC}"
            else
                echo -e "    ${GREEN}✓ Running as non-root user${NC}"
            fi

            # Check privilege escalation
            if kubectl get pod "$POD_NAME" -n "$NS" -o jsonpath='{.spec.containers[*].securityContext.allowPrivilegeEscalation}' | grep -q "false"; then
                echo -e "    ${GREEN}✓ Privilege escalation prevented${NC}"
            else
                echo -e "    ${YELLOW}⚠ Privilege escalation not explicitly prevented${NC}"
            fi

            # Check capabilities
            if kubectl get pod "$POD_NAME" -n "$NS" -o yaml | grep -q "drop:"; then
                echo -e "    ${GREEN}✓ Capabilities dropped${NC}"
            else
                echo -e "    ${YELLOW}⚠ No capabilities dropped${NC}"
            fi

            # Check read-only root filesystem
            if kubectl get pod "$POD_NAME" -n "$NS" -o jsonpath='{.spec.containers[*].securityContext.readOnlyRootFilesystem}' | grep -q "true"; then
                echo -e "    ${GREEN}✓ Read-only root filesystem${NC}"
            else
                echo -e "    ${YELLOW}⚠ Root filesystem not read-only${NC}"
            fi
        done
    fi
    echo ""
done

echo -e "${BLUE}========================================${NC}"
echo -e "${GREEN}Check Complete${NC}"
echo -e "${BLUE}========================================${NC}"
