#!/bin/bash
#
# rbac-audit.sh - Audit RBAC permissions
#

set -euo pipefail

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}RBAC Audit Report${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

echo -e "${BLUE}ServiceAccounts:${NC}"
echo "Dev namespace:"
kubectl get sa -n dev
echo ""
echo "Prod namespace:"
kubectl get sa -n prod
echo ""
echo "Lab05 namespace:"
kubectl get sa -n lab05-rbac
echo ""

echo -e "${BLUE}Roles:${NC}"
kubectl get roles -A | grep -E "NAMESPACE|dev|prod|lab05"
echo ""

echo -e "${BLUE}RoleBindings:${NC}"
kubectl get rolebindings -A | grep -E "NAMESPACE|dev|prod|lab05"
echo ""

echo -e "${BLUE}ClusterRoles (lab05):${NC}"
kubectl get clusterroles | grep lab05
echo ""

echo -e "${BLUE}ClusterRoleBindings (lab05):${NC}"
kubectl get clusterrolebindings | grep lab05
echo ""

echo -e "${BLUE}Permission Tests:${NC}"
echo ""

test_permission() {
    local sa=$1
    local ns=$2
    local verb=$3
    local resource=$4
    local target_ns=$5

    echo -n "  ${sa} can ${verb} ${resource} in ${target_ns}: "
    if kubectl auth can-i "$verb" "$resource" --as="system:serviceaccount:${ns}:${sa}" -n "$target_ns" &>/dev/null; then
        echo -e "${GREEN}YES${NC}"
    else
        echo -e "${YELLOW}NO${NC}"
    fi
}

echo "Developer SA (dev namespace):"
test_permission "developer" "dev" "create" "deployments" "dev"
test_permission "developer" "dev" "delete" "pods" "dev"
test_permission "developer" "dev" "create" "namespaces" "dev"
echo ""

echo "Viewer SA (dev namespace):"
test_permission "viewer" "dev" "get" "pods" "dev"
test_permission "viewer" "dev" "list" "deployments" "dev"
test_permission "viewer" "dev" "delete" "pods" "dev"
echo ""

echo "CI/CD Deployer SA (prod namespace):"
test_permission "cicd-deployer" "prod" "create" "deployments" "prod"
test_permission "cicd-deployer" "prod" "update" "services" "prod"
test_permission "cicd-deployer" "prod" "delete" "namespaces" "prod"
echo ""

echo -e "${BLUE}========================================${NC}"
echo -e "${GREEN}Audit Complete${NC}"
echo -e "${BLUE}========================================${NC}"
