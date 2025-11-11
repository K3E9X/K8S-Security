#!/bin/bash
#
# setup-minikube.sh - Create a minikube cluster for K8s security labs
# Usage: ./setup-minikube.sh [cluster-name]
#

set -euo pipefail

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
PROFILE_NAME="${1:-k8s-security-lab}"
K8S_VERSION="v1.28.3"
DRIVER="docker"  # Can be: docker, virtualbox, kvm2, vmware, etc.
NODES=3  # Total nodes including control plane
CPUS=2
MEMORY="4096"  # MB
DISK_SIZE="20g"

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

    # Check if Docker is installed and running (for docker driver)
    if [ "${DRIVER}" == "docker" ]; then
        if ! command -v docker &> /dev/null; then
            log_error "Docker is not installed. Please install Docker first."
            exit 1
        fi

        if ! docker info &> /dev/null; then
            log_error "Docker daemon is not running. Please start Docker first."
            exit 1
        fi
    fi

    # Check if minikube is installed
    if ! command -v minikube &> /dev/null; then
        log_warn "minikube is not installed. Installing minikube..."
        curl -LO https://storage.googleapis.com/minikube/releases/latest/minikube-linux-amd64
        sudo install minikube-linux-amd64 /usr/local/bin/minikube
        rm minikube-linux-amd64
        log_info "minikube installed successfully"
    else
        log_info "minikube is already installed: $(minikube version --short)"
    fi

    # Check if kubectl is installed
    if ! command -v kubectl &> /dev/null; then
        log_warn "kubectl is not installed. Please install kubectl."
        exit 1
    fi

    log_info "All prerequisites met"
}

create_cluster() {
    log_info "Creating minikube cluster: ${PROFILE_NAME}"

    # Check if profile already exists
    if minikube profile list 2>/dev/null | grep -q "${PROFILE_NAME}"; then
        log_warn "Profile ${PROFILE_NAME} already exists!"
        read -p "Do you want to delete and recreate it? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            log_info "Deleting existing profile..."
            minikube delete --profile "${PROFILE_NAME}"
        else
            log_info "Keeping existing profile. Exiting."
            exit 0
        fi
    fi

    # Create the cluster
    log_info "Starting minikube with ${NODES} nodes..."
    log_info "This may take several minutes..."

    minikube start \
        --profile "${PROFILE_NAME}" \
        --kubernetes-version "${K8S_VERSION}" \
        --driver "${DRIVER}" \
        --nodes "${NODES}" \
        --cpus "${CPUS}" \
        --memory "${MEMORY}" \
        --disk-size "${DISK_SIZE}" \
        --container-runtime containerd \
        --extra-config=apiserver.enable-admission-plugins=NodeRestriction,PodSecurity \
        --extra-config=apiserver.audit-log-path=/var/log/kubernetes/audit.log \
        --extra-config=apiserver.audit-log-maxage=30 \
        --extra-config=apiserver.audit-log-maxbackup=10 \
        --extra-config=apiserver.audit-log-maxsize=100 \
        --addons=metrics-server \
        --addons=dashboard \
        --wait=all

    if [ $? -eq 0 ]; then
        log_info "Cluster created successfully!"
    else
        log_error "Failed to create cluster"
        exit 1
    fi
}

configure_cluster() {
    log_info "Configuring cluster..."

    # Set the profile as default
    minikube profile "${PROFILE_NAME}"

    # Enable additional addons
    log_info "Enabling useful addons..."
    minikube addons enable metrics-server -p "${PROFILE_NAME}"
    minikube addons enable registry -p "${PROFILE_NAME}" || log_warn "Registry addon not available"

    log_info "Configuration complete"
}

wait_for_cluster() {
    log_info "Waiting for cluster to be ready..."

    # Wait for nodes to be ready
    kubectl wait --for=condition=Ready nodes --all --timeout=300s

    # Wait for system pods
    kubectl wait --for=condition=Ready pods --all -n kube-system --timeout=300s

    log_info "Cluster is ready!"
}

display_cluster_info() {
    log_info "Cluster Information:"
    echo "===================="
    echo "Profile Name: ${PROFILE_NAME}"
    echo "Kubernetes Version: ${K8S_VERSION}"
    echo "Driver: ${DRIVER}"
    echo "Nodes: ${NODES}"
    echo "CPUs per node: ${CPUS}"
    echo "Memory per node: ${MEMORY}MB"
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

    log_info "Cluster Status:"
    minikube status -p "${PROFILE_NAME}"
    echo ""

    log_info "Enabled Addons:"
    minikube addons list -p "${PROFILE_NAME}" | grep enabled
    echo ""

    log_info "Useful commands:"
    echo "  minikube dashboard -p ${PROFILE_NAME}  # Open Kubernetes dashboard"
    echo "  minikube ssh -p ${PROFILE_NAME}        # SSH into a node"
    echo "  minikube service list -p ${PROFILE_NAME}  # List services"
    echo "  minikube tunnel -p ${PROFILE_NAME}     # Create route to services"
    echo ""

    log_info "To delete this cluster:"
    echo "  minikube delete --profile ${PROFILE_NAME}"
}

setup_ingress() {
    log_info "Setting up ingress controller..."

    minikube addons enable ingress -p "${PROFILE_NAME}"

    log_info "Ingress controller enabled (nginx)"
}

# Main execution
main() {
    log_info "Starting minikube cluster setup for K8s Security Lab"
    log_info "Profile name: ${PROFILE_NAME}"
    echo ""

    check_prerequisites
    create_cluster
    configure_cluster
    wait_for_cluster
    setup_ingress
    display_cluster_info

    log_info "Setup complete! Happy learning!"
    echo ""
    log_info "Quick tips for minikube:"
    echo "  - Use 'minikube tunnel' in a separate terminal for LoadBalancer services"
    echo "  - Access dashboard with 'minikube dashboard -p ${PROFILE_NAME}'"
    echo "  - SSH into nodes with 'minikube ssh -p ${PROFILE_NAME}'"
}

# Run main function
main "$@"
