#!/bin/bash
#
# verify-environment.sh - Verify the K8s security lab environment is properly set up
#

set -euo pipefail

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Counters
CHECKS_PASSED=0
CHECKS_FAILED=0
CHECKS_WARNING=0

# Helper functions
print_header() {
    echo ""
    echo -e "${BLUE}================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}================================${NC}"
    echo ""
}

check_pass() {
    echo -e "${GREEN}✓${NC} $1"
    ((CHECKS_PASSED++))
}

check_fail() {
    echo -e "${RED}✗${NC} $1"
    ((CHECKS_FAILED++))
}

check_warn() {
    echo -e "${YELLOW}⚠${NC} $1"
    ((CHECKS_WARNING++))
}

# Verification functions
check_docker() {
    print_header "Checking Docker"

    if command -v docker &> /dev/null; then
        check_pass "Docker is installed: $(docker --version)"

        if docker info &> /dev/null; then
            check_pass "Docker daemon is running"

            # Check Docker resources
            local mem=$(docker info --format '{{.MemTotal}}' 2>/dev/null || echo "0")
            local mem_gb=$((mem / 1024 / 1024 / 1024))
            if [ "$mem_gb" -ge 4 ]; then
                check_pass "Docker has sufficient memory: ${mem_gb}GB"
            else
                check_warn "Docker memory might be low: ${mem_gb}GB (recommend 4GB+)"
            fi
        else
            check_fail "Docker daemon is not running"
        fi
    else
        check_fail "Docker is not installed"
    fi
}

check_kubectl() {
    print_header "Checking kubectl"

    if command -v kubectl &> /dev/null; then
        check_pass "kubectl is installed: $(kubectl version --client --short 2>/dev/null || kubectl version --client 2>&1 | head -1)"

        if kubectl cluster-info &> /dev/null; then
            check_pass "kubectl can connect to cluster"

            # Check cluster version
            local k8s_version=$(kubectl version --short 2>/dev/null | grep "Server Version" || kubectl version 2>&1 | grep "Server Version")
            check_pass "Cluster version: ${k8s_version}"
        else
            check_fail "kubectl cannot connect to cluster"
        fi
    else
        check_fail "kubectl is not installed"
    fi
}

check_cluster_tools() {
    print_header "Checking Cluster Tools"

    local tool_found=false

    if command -v kind &> /dev/null; then
        check_pass "kind is installed: $(kind version)"
        tool_found=true

        # Check for kind clusters
        local clusters=$(kind get clusters 2>/dev/null | wc -l)
        if [ "$clusters" -gt 0 ]; then
            check_pass "Found $clusters kind cluster(s)"
            kind get clusters | while read cluster; do
                echo "  - $cluster"
            done
        else
            check_warn "No kind clusters found"
        fi
    fi

    if command -v k3d &> /dev/null; then
        check_pass "k3d is installed: $(k3d version | head -1)"
        tool_found=true

        # Check for k3d clusters
        local clusters=$(k3d cluster list 2>/dev/null | grep -v "NAME" | wc -l)
        if [ "$clusters" -gt 0 ]; then
            check_pass "Found $clusters k3d cluster(s)"
        fi
    fi

    if command -v minikube &> /dev/null; then
        check_pass "minikube is installed: $(minikube version --short)"
        tool_found=true

        # Check for minikube profiles
        local profiles=$(minikube profile list 2>/dev/null | grep -v "Profile" | wc -l || echo "0")
        if [ "$profiles" -gt 0 ]; then
            check_pass "Found $profiles minikube profile(s)"
        fi
    fi

    if [ "$tool_found" = false ]; then
        check_fail "No cluster tool found (need kind, k3d, or minikube)"
    fi
}

check_cluster_health() {
    print_header "Checking Cluster Health"

    if ! kubectl cluster-info &> /dev/null; then
        check_fail "Cannot connect to cluster - skipping health checks"
        return
    fi

    # Check nodes
    local nodes=$(kubectl get nodes --no-headers 2>/dev/null | wc -l)
    if [ "$nodes" -gt 0 ]; then
        check_pass "Cluster has $nodes node(s)"

        # Check if all nodes are ready
        local ready_nodes=$(kubectl get nodes --no-headers 2>/dev/null | grep -c " Ready " || echo "0")
        if [ "$ready_nodes" -eq "$nodes" ]; then
            check_pass "All nodes are Ready"
        else
            check_fail "Only $ready_nodes of $nodes nodes are Ready"
        fi
    else
        check_fail "No nodes found in cluster"
    fi

    # Check system pods
    local system_pods=$(kubectl get pods -n kube-system --no-headers 2>/dev/null | wc -l)
    if [ "$system_pods" -gt 0 ]; then
        check_pass "Found $system_pods system pod(s) in kube-system"

        local running_pods=$(kubectl get pods -n kube-system --no-headers 2>/dev/null | grep -c "Running" || echo "0")
        check_pass "$running_pods system pod(s) are Running"
    else
        check_warn "No system pods found in kube-system namespace"
    fi

    # Check core components
    if kubectl get pods -n kube-system -l component=kube-apiserver &> /dev/null || \
       kubectl get pods -n kube-system -l k8s-app=kube-apiserver &> /dev/null; then
        check_pass "API server pod is present"
    fi

    if kubectl get pods -n kube-system -l k8s-app=kube-dns &> /dev/null || \
       kubectl get pods -n kube-system -l k8s-app=coredns &> /dev/null; then
        check_pass "DNS service is present"
    fi
}

check_permissions() {
    print_header "Checking Permissions"

    if ! kubectl cluster-info &> /dev/null; then
        check_fail "Cannot connect to cluster - skipping permission checks"
        return
    fi

    # Check if we can create namespaces
    if kubectl auth can-i create namespaces &> /dev/null; then
        check_pass "Can create namespaces"
    else
        check_fail "Cannot create namespaces"
    fi

    # Check if we can create pods
    if kubectl auth can-i create pods --all-namespaces &> /dev/null; then
        check_pass "Can create pods"
    else
        check_warn "Limited pod creation permissions"
    fi

    # Check if we can create network policies
    if kubectl auth can-i create networkpolicies &> /dev/null; then
        check_pass "Can create network policies"
    else
        check_warn "Cannot create network policies"
    fi

    # Check cluster-admin or similar
    if kubectl auth can-i '*' '*' &> /dev/null; then
        check_pass "Have cluster-admin or equivalent permissions"
    else
        check_warn "Do not have full cluster-admin permissions (may be okay)"
    fi
}

check_optional_tools() {
    print_header "Checking Optional Tools"

    if command -v helm &> /dev/null; then
        check_pass "helm is installed: $(helm version --short)"
    else
        check_warn "helm is not installed (optional but recommended)"
    fi

    if command -v k9s &> /dev/null; then
        check_pass "k9s is installed: $(k9s version --short 2>&1 | head -1)"
    else
        check_warn "k9s is not installed (optional but helpful)"
    fi

    if command -v git &> /dev/null; then
        check_pass "git is installed: $(git --version)"
    else
        check_warn "git is not installed (needed for cloning repos)"
    fi
}

check_network() {
    print_header "Checking Network Configuration"

    if ! kubectl cluster-info &> /dev/null; then
        check_fail "Cannot connect to cluster - skipping network checks"
        return
    fi

    # Check if we can resolve DNS
    if kubectl run test-dns --image=busybox:1.28 --rm -it --restart=Never -- nslookup kubernetes.default &> /dev/null; then
        check_pass "Cluster DNS is working"
    else
        # Try a different approach
        if kubectl get svc kubernetes &> /dev/null; then
            check_pass "Can access Kubernetes service"
        else
            check_warn "DNS check inconclusive"
        fi
    fi

    # Check CNI
    if kubectl get pods -n kube-system -l k8s-app=kube-proxy &> /dev/null; then
        check_pass "kube-proxy is deployed"
    fi
}

check_metrics() {
    print_header "Checking Metrics"

    if ! kubectl cluster-info &> /dev/null; then
        check_fail "Cannot connect to cluster - skipping metrics checks"
        return
    fi

    # Check if metrics-server is installed
    if kubectl get deployment metrics-server -n kube-system &> /dev/null; then
        check_pass "metrics-server is installed"

        # Check if metrics are available
        sleep 2
        if kubectl top nodes &> /dev/null; then
            check_pass "Node metrics are available"
        else
            check_warn "Node metrics not yet available (may need time to initialize)"
        fi
    else
        check_warn "metrics-server is not installed (optional but useful)"
    fi
}

display_summary() {
    print_header "Verification Summary"

    echo "Checks passed:  ${CHECKS_PASSED}"
    echo "Checks failed:  ${CHECKS_FAILED}"
    echo "Warnings:       ${CHECKS_WARNING}"
    echo ""

    if [ "$CHECKS_FAILED" -eq 0 ]; then
        echo -e "${GREEN}✓ Environment is ready for K8s security labs!${NC}"
        return 0
    else
        echo -e "${RED}✗ Environment has issues that need to be addressed${NC}"
        echo ""
        echo "Please fix the failed checks before proceeding with the labs."
        echo "See the troubleshooting guide for help: labs/00-environment-setup/troubleshooting.md"
        return 1
    fi
}

# Main execution
main() {
    echo ""
    echo -e "${BLUE}╔════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║  K8s Security Lab Environment Verification ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════╝${NC}"

    check_docker
    check_kubectl
    check_cluster_tools
    check_cluster_health
    check_permissions
    check_network
    check_metrics
    check_optional_tools

    display_summary
}

# Run main function
main "$@"
