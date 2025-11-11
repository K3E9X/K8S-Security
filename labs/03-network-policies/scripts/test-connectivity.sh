#!/bin/bash
#
# test-connectivity.sh - Test network connectivity and policy enforcement
#

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

NAMESPACE="lab03-netpol"
TESTS_PASSED=0
TESTS_FAILED=0

echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Network Policy Connectivity Tests${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Helper function
test_connection() {
    local source=$1
    local target=$2
    local port=$3
    local should_work=$4
    local description=$5

    echo -n "Testing: $description ... "

    if kubectl exec -n "$NAMESPACE" "deploy/$source" -- timeout 3 nc -zv "$target" "$port" &> /dev/null; then
        if [ "$should_work" = "true" ]; then
            echo -e "${GREEN}✓ PASS${NC} (connection successful as expected)"
            ((TESTS_PASSED++))
        else
            echo -e "${RED}✗ FAIL${NC} (connection should be blocked)"
            ((TESTS_FAILED++))
        fi
    else
        if [ "$should_work" = "false" ]; then
            echo -e "${GREEN}✓ PASS${NC} (connection blocked as expected)"
            ((TESTS_PASSED++))
        else
            echo -e "${RED}✗ FAIL${NC} (connection should work)"
            ((TESTS_FAILED++))
        fi
    fi
}

# Check if pods are running
echo -e "${BLUE}Checking pod status...${NC}"
if ! kubectl get pods -n "$NAMESPACE" | grep -q "Running"; then
    echo -e "${RED}Error: Pods are not running in namespace $NAMESPACE${NC}"
    exit 1
fi
echo -e "${GREEN}✓ All pods are running${NC}"
echo ""

# Test DNS
echo -e "${BLUE}Testing DNS resolution...${NC}"
if kubectl exec -n "$NAMESPACE" deploy/frontend -- nslookup backend &> /dev/null; then
    echo -e "${GREEN}✓ DNS resolution works${NC}"
    ((TESTS_PASSED++))
else
    echo -e "${RED}✗ DNS resolution failed${NC}"
    ((TESTS_FAILED++))
fi
echo ""

# Test allowed connections
echo -e "${BLUE}Testing allowed connections...${NC}"
test_connection "frontend" "backend" "8080" "true" "Frontend → Backend"
test_connection "backend" "database" "5432" "true" "Backend → Database"
echo ""

# Test blocked connections
echo -e "${BLUE}Testing blocked connections...${NC}"
test_connection "frontend" "database" "5432" "false" "Frontend → Database (should be blocked)"
echo ""

# Test HTTP endpoint
echo -e "${BLUE}Testing application functionality...${NC}"
if kubectl exec -n "$NAMESPACE" deploy/frontend -- timeout 5 curl -s http://backend:8080/api/health &> /dev/null; then
    echo -e "${GREEN}✓ Frontend can reach backend API${NC}"
    ((TESTS_PASSED++))
else
    echo -e "${RED}✗ Frontend cannot reach backend API${NC}"
    ((TESTS_FAILED++))
fi
echo ""

# List network policies
echo -e "${BLUE}Active Network Policies:${NC}"
kubectl get networkpolicies -n "$NAMESPACE"
echo ""

# Summary
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Test Summary${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""
echo -e "Tests passed: ${GREEN}$TESTS_PASSED${NC}"
echo -e "Tests failed: ${RED}$TESTS_FAILED${NC}"
echo ""

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}✓ All network policy tests passed!${NC}"
    exit 0
else
    echo -e "${RED}✗ Some tests failed. Review network policies.${NC}"
    exit 1
fi
