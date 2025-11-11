#!/bin/bash
#
# setup-k3d.sh - Create a k3d cluster for K8s security labs
# Usage: ./setup-k3d.sh [cluster-name]
#

set -euo pipefail

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
CLUSTER_NAME="${1:-k8s-security-lab}"
K3S_VERSION="v1.28.2-k3s1"
AGENTS=2  # Number of worker nodes

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

check_prerequisites() {
    log_info "Checking prerequisites..."

    # Check if Docker is installed and running
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed. Please install Docker first."
        exit 1
    fi

    if ! docker info &> /dev/null; then
        log_error "Docker daemon is not running. Please start Docker first."
        exit 1
    fi

    # Check if k3d is installed
    if ! command -v k3d &> /dev/null; then
        log_warn "k3d is not installed. Installing k3d..."
        curl -s https://raw.githubusercontent.com/k3d-io/k3d/main/install.sh | bash
        log_info "k3d installed successfully"
    else
        log_info "k3d is already installed: $(k3d version)"
    fi

    # Check if kubectl is installed
    if ! command -v kubectl &> /dev/null; then
        log_warn "kubectl is not installed. Please install kubectl."
        exit 1
    fi

    log_info "All prerequisites met"
}

create_cluster() {
    log_info "Creating k3d cluster: ${CLUSTER_NAME}"

    # Check if cluster already exists
    if k3d cluster list | grep -q "${CLUSTER_NAME}"; then
        log_warn "Cluster ${CLUSTER_NAME} already exists!"
        read -p "Do you want to delete and recreate it? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            log_info "Deleting existing cluster..."
            k3d cluster delete "${CLUSTER_NAME}"
        else
            log_info "Keeping existing cluster. Exiting."
            exit 0
        fi
    fi

    # Create the cluster with custom configuration
    log_info "Creating cluster with ${AGENTS} worker nodes..."

    k3d cluster create "${CLUSTER_NAME}" \
        --image "rancher/k3s:${K3S_VERSION}" \
        --agents ${AGENTS} \
        --servers 1 \
        --port "80:80@loadbalancer" \
        --port "443:443@loadbalancer" \
        --api-port 6443 \
        --k3s-arg "--disable=traefik@server:0" \
        --k3s-arg "--kube-apiserver-arg=enable-admission-plugins=NodeRestriction,PodSecurityPolicy@server:0" \
        --k3s-arg "--kube-apiserver-arg=audit-log-path=/var/log/kubernetes/audit.log@server:0" \
        --k3s-arg "--kube-apiserver-arg=audit-log-maxage=30@server:0" \
        --k3s-arg "--kube-apiserver-arg=audit-log-maxbackup=10@server:0" \
        --k3s-arg "--kube-apiserver-arg=audit-log-maxsize=100@server:0" \
        --volume /tmp/k3d-audit:/var/log/kubernetes@server:0 \
        --wait

    if [ $? -eq 0 ]; then
        log_info "Cluster created successfully!"
    else
        log_error "Failed to create cluster"
        exit 1
    fi
}

wait_for_cluster() {
    log_info "Waiting for cluster to be ready..."

    # Wait for nodes to be ready
    kubectl wait --for=condition=Ready nodes --all --timeout=300s

    # Wait for core system pods
    sleep 10
    kubectl wait --for=condition=Ready pods --all -n kube-system --timeout=300s

    log_info "Cluster is ready!"
}

display_cluster_info() {
    log_info "Cluster Information:"
    echo "===================="
    echo "Cluster Name: ${CLUSTER_NAME}"
    echo "K3s Version: ${K3S_VERSION}"
    echo ""

    log_info "Nodes:"
    kubectl get nodes -o wide
    echo ""

    log_info "System Pods:"
    kubectl get pods -n kube-system
    echo ""

    log_info "Cluster Context:"
    kubectl config current-context
    echo ""

    log_info "Cluster endpoints:"
    k3d cluster list "${CLUSTER_NAME}"
    echo ""

    log_info "To use this cluster:"
    echo "  kubectl cluster-info"
    echo ""

    log_info "To delete this cluster:"
    echo "  k3d cluster delete ${CLUSTER_NAME}"
}

configure_local_registry() {
    log_info "Setting up local container registry..."

    # Check if registry already exists
    if docker ps -a --format '{{.Names}}' | grep -q "k3d-${CLUSTER_NAME}-registry"; then
        log_info "Registry already exists for this cluster"
    else
        # Create registry
        k3d registry create "${CLUSTER_NAME}-registry" --port 5000
        log_info "Local registry created at localhost:5000"
    fi
}

install_metrics_server() {
    log_info "Metrics-server is already included in k3s"
    sleep 5
    kubectl top nodes 2>/dev/null || log_warn "Metrics may take a moment to be available"
}

# Main execution
main() {
    log_info "Starting k3d cluster setup for K8s Security Lab"
    log_info "Cluster name: ${CLUSTER_NAME}"
    echo ""

    check_prerequisites
    create_cluster
    wait_for_cluster
    configure_local_registry
    install_metrics_server
    display_cluster_info

    log_info "Setup complete! Happy learning!"
    echo ""
    log_info "Quick tips for k3d:"
    echo "  - k3d is lightweight and fast"
    echo "  - Local registry available at localhost:5000"
    echo "  - To push images: docker tag myimage localhost:5000/myimage && docker push localhost:5000/myimage"
}

# Run main function
main "$@"
