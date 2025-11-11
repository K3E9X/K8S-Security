#!/bin/bash
#
# security-check.sh - Check security posture of deployments in lab01
#

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

NAMESPACE="lab01-basic-deployment"
DEPLOYMENT="web-app"

echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Security Check for Deployment: ${DEPLOYMENT}${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Check if deployment exists
if ! kubectl get deployment "${DEPLOYMENT}" -n "${NAMESPACE}" &> /dev/null; then
    echo -e "${RED}✗ Deployment ${DEPLOYMENT} not found in namespace ${NAMESPACE}${NC}"
    exit 1
fi

ISSUES=0
PASSED=0

# Get deployment YAML
DEPLOY_YAML=$(kubectl get deployment "${DEPLOYMENT}" -n "${NAMESPACE}" -o yaml)

echo -e "${BLUE}Checking Security Context...${NC}"

# Check if running as non-root
if echo "$DEPLOY_YAML" | grep -q "runAsNonRoot: true"; then
    echo -e "${GREEN}✓ Container configured to run as non-root${NC}"
    ((PASSED++))
else
    echo -e "${RED}✗ Container may be running as root (security risk)${NC}"
    echo "  Recommendation: Set securityContext.runAsNonRoot: true"
    ((ISSUES++))
fi

# Check for read-only root filesystem
if echo "$DEPLOY_YAML" | grep -q "readOnlyRootFilesystem: true"; then
    echo -e "${GREEN}✓ Read-only root filesystem enabled${NC}"
    ((PASSED++))
else
    echo -e "${YELLOW}⚠ Read-only root filesystem not enabled${NC}"
    echo "  Recommendation: Set securityContext.readOnlyRootFilesystem: true"
    ((ISSUES++))
fi

# Check for privilege escalation prevention
if echo "$DEPLOY_YAML" | grep -q "allowPrivilegeEscalation: false"; then
    echo -e "${GREEN}✓ Privilege escalation prevented${NC}"
    ((PASSED++))
else
    echo -e "${RED}✗ Privilege escalation not prevented${NC}"
    echo "  Recommendation: Set securityContext.allowPrivilegeEscalation: false"
    ((ISSUES++))
fi

# Check for dropped capabilities
if echo "$DEPLOY_YAML" | grep -A2 "capabilities:" | grep -q "drop:"; then
    echo -e "${GREEN}✓ Capabilities are being dropped${NC}"
    ((PASSED++))
else
    echo -e "${YELLOW}⚠ No capabilities being dropped${NC}"
    echo "  Recommendation: Drop all capabilities and add only required ones"
    ((ISSUES++))
fi

echo ""
echo -e "${BLUE}Checking Resource Limits...${NC}"

# Check for resource limits
if echo "$DEPLOY_YAML" | grep -q "limits:"; then
    echo -e "${GREEN}✓ Resource limits defined${NC}"
    ((PASSED++))
else
    echo -e "${RED}✗ No resource limits defined (can lead to resource exhaustion)${NC}"
    echo "  Recommendation: Define resources.limits.cpu and resources.limits.memory"
    ((ISSUES++))
fi

# Check for resource requests
if echo "$DEPLOY_YAML" | grep -q "requests:"; then
    echo -e "${GREEN}✓ Resource requests defined${NC}"
    ((PASSED++))
else
    echo -e "${YELLOW}⚠ No resource requests defined${NC}"
    echo "  Recommendation: Define resources.requests.cpu and resources.requests.memory"
    ((ISSUES++))
fi

echo ""
echo -e "${BLUE}Checking Health Probes...${NC}"

# Check for liveness probe
if echo "$DEPLOY_YAML" | grep -q "livenessProbe:"; then
    echo -e "${GREEN}✓ Liveness probe configured${NC}"
    ((PASSED++))
else
    echo -e "${YELLOW}⚠ No liveness probe configured${NC}"
    echo "  Recommendation: Add livenessProbe for automatic restart of unhealthy containers"
    ((ISSUES++))
fi

# Check for readiness probe
if echo "$DEPLOY_YAML" | grep -q "readinessProbe:"; then
    echo -e "${GREEN}✓ Readiness probe configured${NC}"
    ((PASSED++))
else
    echo -e "${YELLOW}⚠ No readiness probe configured${NC}"
    echo "  Recommendation: Add readinessProbe to ensure traffic only goes to ready pods"
    ((ISSUES++))
fi

echo ""
echo -e "${BLUE}Checking Pod Security...${NC}"

# Check for privileged containers
if echo "$DEPLOY_YAML" | grep -q "privileged: true"; then
    echo -e "${RED}✗ Privileged containers detected (major security risk)${NC}"
    echo "  Recommendation: Remove privileged: true"
    ((ISSUES++))
else
    echo -e "${GREEN}✓ No privileged containers${NC}"
    ((PASSED++))
fi

# Check for host network
if echo "$DEPLOY_YAML" | grep -q "hostNetwork: true"; then
    echo -e "${RED}✗ Host network enabled (security risk)${NC}"
    echo "  Recommendation: Remove hostNetwork: true unless absolutely necessary"
    ((ISSUES++))
else
    echo -e "${GREEN}✓ Host network not enabled${NC}"
    ((PASSED++))
fi

# Check for host PID
if echo "$DEPLOY_YAML" | grep -q "hostPID: true"; then
    echo -e "${RED}✗ Host PID enabled (security risk)${NC}"
    echo "  Recommendation: Remove hostPID: true"
    ((ISSUES++))
else
    echo -e "${GREEN}✓ Host PID not enabled${NC}"
    ((PASSED++))
fi

# Check for host IPC
if echo "$DEPLOY_YAML" | grep -q "hostIPC: true"; then
    echo -e "${RED}✗ Host IPC enabled (security risk)${NC}"
    echo "  Recommendation: Remove hostIPC: true"
    ((ISSUES++))
else
    echo -e "${GREEN}✓ Host IPC not enabled${NC}"
    ((PASSED++))
fi

echo ""
echo -e "${BLUE}Checking Runtime Security...${NC}"

# Check for seccomp profile
if echo "$DEPLOY_YAML" | grep -q "seccompProfile:"; then
    echo -e "${GREEN}✓ Seccomp profile configured${NC}"
    ((PASSED++))
else
    echo -e "${YELLOW}⚠ No seccomp profile configured${NC}"
    echo "  Recommendation: Set securityContext.seccompProfile.type: RuntimeDefault"
    ((ISSUES++))
fi

# Check actual pod security
echo ""
echo -e "${BLUE}Checking Running Pods...${NC}"

PODS=$(kubectl get pods -n "${NAMESPACE}" -l app=web-app -o name)

for POD in $PODS; do
    POD_NAME=$(echo $POD | cut -d'/' -f2)
    echo ""
    echo "Pod: ${POD_NAME}"

    # Check if pod is actually running as non-root
    if kubectl exec -n "${NAMESPACE}" "${POD_NAME}" -- id 2>/dev/null | grep -q "uid=0"; then
        echo -e "${RED}  ✗ Pod is running as root (UID 0)${NC}"
        ((ISSUES++))
    else
        echo -e "${GREEN}  ✓ Pod is running as non-root user${NC}"
        ((PASSED++))
    fi
done

# Summary
echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Security Check Summary${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""
echo -e "Checks passed: ${GREEN}${PASSED}${NC}"
echo -e "Issues found:  ${RED}${ISSUES}${NC}"
echo ""

if [ $ISSUES -eq 0 ]; then
    echo -e "${GREEN}✓ Deployment follows security best practices!${NC}"
    exit 0
elif [ $ISSUES -le 5 ]; then
    echo -e "${YELLOW}⚠ Deployment has some security issues that should be addressed${NC}"
    exit 0
else
    echo -e "${RED}✗ Deployment has significant security issues${NC}"
    echo ""
    echo "Apply the hardened deployment to fix these issues:"
    echo "  kubectl apply -f manifests/web-app-deployment-secure.yaml"
    exit 1
fi
