#!/bin/bash
#
# setup-kind.sh - Create a multi-node kind cluster with custom configuration
# Usage: ./setup-kind.sh [cluster-name]
#

set -euo pipefail

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
CLUSTER_NAME="${1:-k8s-security-lab}"
KIND_VERSION="v0.20.0"
K8S_VERSION="v1.28.0"

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

    # Check if kind is installed
    if ! command -v kind &> /dev/null; then
        log_warn "kind is not installed. Installing kind ${KIND_VERSION}..."
        curl -Lo ./kind "https://kind.sigs.k8s.io/dl/${KIND_VERSION}/kind-linux-amd64"
        chmod +x ./kind
        sudo mv ./kind /usr/local/bin/kind
        log_info "kind installed successfully"
    else
        log_info "kind is already installed: $(kind version)"
    fi

    # Check if kubectl is installed
    if ! command -v kubectl &> /dev/null; then
        log_warn "kubectl is not installed. Please install kubectl."
        exit 1
    fi

    log_info "All prerequisites met"
}

create_kind_config() {
    log_info "Creating kind cluster configuration..."

    cat <<EOF > /tmp/kind-config-${CLUSTER_NAME}.yaml
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
name: ${CLUSTER_NAME}
nodes:
  # Control plane node
  - role: control-plane
    image: kindest/node:${K8S_VERSION}@sha256:b7e1cf6b2b729f604133c667a6be8aab6f4dde5bb042c1891ae248d9154f665b
    kubeadmConfigPatches:
      - |
        kind: InitConfiguration
        nodeRegistration:
          kubeletExtraArgs:
            node-labels: "ingress-ready=true"
    extraPortMappings:
      # HTTP
      - containerPort: 80
        hostPort: 80
        protocol: TCP
      # HTTPS
      - containerPort: 443
        hostPort: 443
        protocol: TCP
      # Metrics server
      - containerPort: 10250
        hostPort: 10250
        protocol: TCP
  # Worker nodes
  - role: worker
    image: kindest/node:${K8S_VERSION}@sha256:b7e1cf6b2b729f604133c667a6be8aab6f4dde5bb042c1891ae248d9154f665b
  - role: worker
    image: kindest/node:${K8S_VERSION}@sha256:b7e1cf6b2b729f604133c667a6be8aab6f4dde5bb042c1891ae248d9154f665b
networking:
  # Default CNI will be kindnet
  disableDefaultCNI: false
  # Pod subnet
  podSubnet: "10.244.0.0/16"
  # Service subnet
  serviceSubnet: "10.96.0.0/12"
# Enable feature gates for security features
featureGates:
  # Pod Security Admission
  PodSecurity: true
# Runtime configuration
kubeadmConfigPatches:
  - |
    kind: ClusterConfiguration
    apiServer:
      extraArgs:
        # Enable audit logging
        audit-log-path: /var/log/kubernetes/audit.log
        audit-log-maxage: "30"
        audit-log-maxbackup: "10"
        audit-log-maxsize: "100"
        # Enable admission plugins
        enable-admission-plugins: NodeRestriction,PodSecurity
    controllerManager:
      extraArgs:
        # Enable pod security
        feature-gates: "PodSecurity=true"
EOF

    log_info "Configuration file created at /tmp/kind-config-${CLUSTER_NAME}.yaml"
}

create_cluster() {
    log_info "Creating kind cluster: ${CLUSTER_NAME}"

    # Check if cluster already exists
    if kind get clusters 2>/dev/null | grep -q "^${CLUSTER_NAME}$"; then
        log_warn "Cluster ${CLUSTER_NAME} already exists!"
        read -p "Do you want to delete and recreate it? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            log_info "Deleting existing cluster..."
            kind delete cluster --name "${CLUSTER_NAME}"
        else
            log_info "Keeping existing cluster. Exiting."
            exit 0
        fi
    fi

    # Create the cluster
    if kind create cluster --config /tmp/kind-config-${CLUSTER_NAME}.yaml; then
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

    # Wait for core pods to be ready
    kubectl wait --for=condition=Ready pods --all -n kube-system --timeout=300s

    log_info "Cluster is ready!"
}

display_cluster_info() {
    log_info "Cluster Information:"
    echo "===================="
    echo "Cluster Name: ${CLUSTER_NAME}"
    echo "Kubernetes Version: ${K8S_VERSION}"
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

    log_info "To use this cluster:"
    echo "  kubectl cluster-info --context kind-${CLUSTER_NAME}"
    echo ""

    log_info "To delete this cluster:"
    echo "  kind delete cluster --name ${CLUSTER_NAME}"
}

install_metrics_server() {
    log_info "Installing metrics-server..."

    kubectl apply -f https://github.com/kubernetes-sigs/metrics-server/releases/latest/download/components.yaml

    # Patch metrics-server for kind
    kubectl patch -n kube-system deployment metrics-server --type=json \
        -p '[{"op":"add","path":"/spec/template/spec/containers/0/args/-","value":"--kubelet-insecure-tls"}]'

    log_info "Metrics-server installed (may take a moment to be ready)"
}

# Main execution
main() {
    log_info "Starting kind cluster setup for K8s Security Lab"
    log_info "Cluster name: ${CLUSTER_NAME}"
    echo ""

    check_prerequisites
    create_kind_config
    create_cluster
    wait_for_cluster
    install_metrics_server
    display_cluster_info

    log_info "Setup complete! Happy learning!"
}

# Run main function
main "$@"
