#!/bin/bash
#
# cleanup-all.sh - Cleanup all Kubernetes lab clusters and resources
# Usage: ./cleanup-all.sh [--force]
#

set -euo pipefail

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
FORCE_MODE=false
CLUSTER_PATTERN="k8s-security-lab"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --force|-f)
            FORCE_MODE=true
            shift
            ;;
        *)
            CLUSTER_PATTERN="$1"
            shift
            ;;
    esac
done

# Helper functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_step() {
    echo -e "${BLUE}[STEP]${NC} $1"
}

confirm_cleanup() {
    if [ "$FORCE_MODE" = true ]; then
        return 0
    fi

    echo ""
    log_warn "This will delete ALL resources related to K8s security labs!"
    echo "This includes:"
    echo "  - kind clusters matching pattern: ${CLUSTER_PATTERN}"
    echo "  - k3d clusters matching pattern: ${CLUSTER_PATTERN}"
    echo "  - minikube profiles matching pattern: ${CLUSTER_PATTERN}"
    echo "  - Associated Docker containers and networks"
    echo "  - Local registry containers"
    echo ""
    read -p "Are you sure you want to continue? (yes/NO): " -r
    echo
    if [[ ! $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
        log_info "Cleanup cancelled"
        exit 0
    fi
}

cleanup_kind_clusters() {
    log_step "Checking for kind clusters..."

    if ! command -v kind &> /dev/null; then
        log_info "kind is not installed, skipping"
        return 0
    fi

    local clusters=$(kind get clusters 2>/dev/null | grep "${CLUSTER_PATTERN}" || true)

    if [ -z "$clusters" ]; then
        log_info "No kind clusters found matching pattern: ${CLUSTER_PATTERN}"
        return 0
    fi

    log_info "Found kind clusters:"
    echo "$clusters"
    echo ""

    while IFS= read -r cluster; do
        if [ -n "$cluster" ]; then
            log_info "Deleting kind cluster: ${cluster}"
            kind delete cluster --name "${cluster}"
        fi
    done <<< "$clusters"

    # Clean up any leftover kind config files
    rm -f /tmp/kind-config-*.yaml 2>/dev/null || true

    log_info "kind cleanup complete"
}

cleanup_k3d_clusters() {
    log_step "Checking for k3d clusters..."

    if ! command -v k3d &> /dev/null; then
        log_info "k3d is not installed, skipping"
        return 0
    fi

    local clusters=$(k3d cluster list 2>/dev/null | grep "${CLUSTER_PATTERN}" | awk '{print $1}' || true)

    if [ -z "$clusters" ]; then
        log_info "No k3d clusters found matching pattern: ${CLUSTER_PATTERN}"
        return 0
    fi

    log_info "Found k3d clusters:"
    echo "$clusters"
    echo ""

    while IFS= read -r cluster; do
        if [ -n "$cluster" ]; then
            log_info "Deleting k3d cluster: ${cluster}"
            k3d cluster delete "${cluster}"

            # Also delete associated registry if exists
            local registry="${cluster}-registry"
            if docker ps -a --format '{{.Names}}' | grep -q "k3d-${registry}"; then
                log_info "Deleting k3d registry: ${registry}"
                k3d registry delete "${registry}" 2>/dev/null || true
            fi
        fi
    done <<< "$clusters"

    # Clean up audit logs
    rm -rf /tmp/k3d-audit 2>/dev/null || true

    log_info "k3d cleanup complete"
}

cleanup_minikube_profiles() {
    log_step "Checking for minikube profiles..."

    if ! command -v minikube &> /dev/null; then
        log_info "minikube is not installed, skipping"
        return 0
    fi

    local profiles=$(minikube profile list 2>/dev/null | grep "${CLUSTER_PATTERN}" | awk '{print $2}' || true)

    if [ -z "$profiles" ]; then
        log_info "No minikube profiles found matching pattern: ${CLUSTER_PATTERN}"
        return 0
    fi

    log_info "Found minikube profiles:"
    echo "$profiles"
    echo ""

    while IFS= read -r profile; do
        if [ -n "$profile" ]; then
            log_info "Deleting minikube profile: ${profile}"
            minikube delete --profile "${profile}"
        fi
    done <<< "$profiles"

    log_info "minikube cleanup complete"
}

cleanup_docker_resources() {
    log_step "Cleaning up Docker resources..."

    if ! command -v docker &> /dev/null; then
        log_info "Docker is not installed, skipping"
        return 0
    fi

    # Remove stopped containers related to k8s labs
    log_info "Removing stopped containers..."
    docker container prune -f --filter "label=io.x-k8s.kind.cluster" 2>/dev/null || true

    # Remove dangling images
    log_info "Removing dangling images..."
    docker image prune -f 2>/dev/null || true

    # Remove unused networks
    log_info "Removing unused networks..."
    docker network prune -f 2>/dev/null || true

    # Remove unused volumes (be careful with this)
    if [ "$FORCE_MODE" = true ]; then
        log_warn "Force mode: Removing unused volumes..."
        docker volume prune -f 2>/dev/null || true
    fi

    log_info "Docker cleanup complete"
}

cleanup_kubectl_contexts() {
    log_step "Cleaning up kubectl contexts..."

    if ! command -v kubectl &> /dev/null; then
        log_info "kubectl is not installed, skipping"
        return 0
    fi

    # List contexts that match the pattern
    local contexts=$(kubectl config get-contexts -o name 2>/dev/null | grep "${CLUSTER_PATTERN}" || true)

    if [ -z "$contexts" ]; then
        log_info "No kubectl contexts found matching pattern: ${CLUSTER_PATTERN}"
        return 0
    fi

    log_info "Found kubectl contexts:"
    echo "$contexts"
    echo ""

    while IFS= read -r context; do
        if [ -n "$context" ]; then
            log_info "Deleting kubectl context: ${context}"
            kubectl config delete-context "${context}" 2>/dev/null || true
        fi
    done <<< "$contexts"

    log_info "kubectl context cleanup complete"
}

cleanup_temp_files() {
    log_step "Cleaning up temporary files..."

    # Remove any temporary kubeconfig files
    rm -f /tmp/kubeconfig-*.yaml 2>/dev/null || true

    # Remove any temporary manifest files from labs
    find /tmp -name "*.k8s.yaml" -type f -mtime +1 -delete 2>/dev/null || true

    log_info "Temporary files cleanup complete"
}

display_summary() {
    echo ""
    log_info "Cleanup Summary:"
    echo "===================="

    # Check what's left
    local remaining_kind=$(kind get clusters 2>/dev/null | wc -l || echo "0")
    local remaining_k3d=$(k3d cluster list 2>/dev/null | grep -v "NAME" | wc -l || echo "0")
    local remaining_minikube=$(minikube profile list 2>/dev/null | grep -v "Profile" | wc -l || echo "0")

    echo "Remaining clusters:"
    echo "  kind: ${remaining_kind}"
    echo "  k3d: ${remaining_k3d}"
    echo "  minikube: ${remaining_minikube}"
    echo ""

    if [ "$remaining_kind" -eq 0 ] && [ "$remaining_k3d" -eq 0 ] && [ "$remaining_minikube" -eq 0 ]; then
        log_info "All matching clusters have been cleaned up!"
    else
        log_warn "Some clusters remain. Use 'kind get clusters', 'k3d cluster list', or 'minikube profile list' to check."
    fi
}

# Main execution
main() {
    echo ""
    log_info "K8s Security Lab Cleanup Tool"
    log_info "=============================="
    echo "Pattern: ${CLUSTER_PATTERN}"
    echo "Force mode: ${FORCE_MODE}"
    echo ""

    confirm_cleanup

    log_info "Starting cleanup process..."
    echo ""

    cleanup_kind_clusters
    echo ""

    cleanup_k3d_clusters
    echo ""

    cleanup_minikube_profiles
    echo ""

    cleanup_kubectl_contexts
    echo ""

    cleanup_docker_resources
    echo ""

    cleanup_temp_files
    echo ""

    display_summary

    log_info "Cleanup complete!"
    echo ""
    log_info "To verify, you can run:"
    echo "  kind get clusters"
    echo "  k3d cluster list"
    echo "  minikube profile list"
    echo "  docker ps -a"
}

# Run main function
main "$@"
