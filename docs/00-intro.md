# Module 00: Introduction and Prerequisites

## Overview

Welcome to the Kubernetes Architecture and Security Training program. This comprehensive course is designed to take you from Kubernetes fundamentals through advanced security hardening, with hands-on labs and real-world scenarios based on production experience.

This module establishes the foundation for your learning journey, covering prerequisites, learning objectives, and environment setup.

**Estimated Time**: 1 hour

## Learning Objectives

By completing this module, you will:

- Understand the course structure and learning path
- Verify you have the necessary prerequisites
- Set up your local lab environment
- Familiarize yourself with key Kubernetes terminology
- Understand the security-first approach used throughout this training

## Target Audience

This training is designed for:

- **Platform Engineers** building and operating Kubernetes platforms
- **DevOps/SRE Teams** deploying and securing applications
- **Security Engineers** implementing security controls
- **Architects** designing multi-cluster environments
- **Developers** seeking deep platform understanding

## Prerequisites

### Required Knowledge

**Linux Basics** (confidence level: intermediate)
- Command line navigation and file operations
- Understanding of processes, users, and permissions
- Basic shell scripting concepts
- Text editing (vim, nano, or your preferred editor)

**Container Fundamentals** (confidence level: beginner to intermediate)
- What containers are and how they differ from VMs
- Docker basics: building and running containers
- Understanding container images and registries
- Basic Dockerfile syntax

**YAML Syntax** (confidence level: beginner)
- Key-value pairs and nesting
- Lists and arrays
- Data types (strings, numbers, booleans)
- Indentation significance

**Networking Concepts** (confidence level: beginner)
- IP addressing and subnetting
- DNS and name resolution
- TCP/IP and common ports
- Basic routing concepts

### Recommended Knowledge

- Infrastructure as Code concepts (Terraform, Ansible)
- TLS/PKI basics (certificates, public/private keys)
- Experience with cloud providers (Azure, AWS, or GCP)
- Git version control
- CI/CD fundamentals

### Software Requirements

Install the following tools on your local machine:

**Essential Tools:**

1. **kubectl** - Kubernetes command-line tool
   ```bash
   # macOS (via Homebrew)
   brew install kubectl
   
   # Linux
   curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
   sudo install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl
   
   # Verify
   kubectl version --client
   ```

2. **kind** (Kubernetes in Docker) - Recommended for labs
   ```bash
   # macOS
   brew install kind
   
   # Linux
   curl -Lo ./kind https://kind.sigs.k8s.io/dl/v0.20.0/kind-linux-amd64
   chmod +x ./kind
   sudo mv ./kind /usr/local/bin/kind
   
   # Verify
   kind version
   ```

3. **Docker** or **Podman** - Container runtime
   ```bash
   # macOS
   brew install --cask docker
   
   # Ubuntu/Debian
   sudo apt-get update
   sudo apt-get install docker.io
   sudo usermod -aG docker $USER  # Logout and login
   
   # Verify
   docker version
   ```

4. **Helm** - Kubernetes package manager
   ```bash
   # macOS
   brew install helm
   
   # Linux
   curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
   
   # Verify
   helm version
   ```

**Alternative Cluster Tools** (optional):

- **k3d**: Lightweight k3s in Docker
- **minikube**: Local Kubernetes with multiple runtime options

**Recommended Tools:**

- **jq**: JSON processor for kubectl output
- **yq**: YAML processor
- **kubectx/kubens**: Context and namespace switcher
- **k9s**: Terminal UI for Kubernetes

### Hardware Requirements

**Minimum:**
- CPU: 2 cores
- RAM: 8 GB
- Disk: 20 GB free

**Recommended:**
- CPU: 4 cores
- RAM: 16 GB
- Disk: 50 GB free

## Course Structure

### Part I: Foundation (Modules 01-04)

Build core Kubernetes knowledge:
- Basic resources and concepts
- Control plane architecture
- Networking fundamentals
- Storage systems

### Part II: Security (Modules 05-10)

Master Kubernetes security:
- Authentication and authorization
- Pod security standards
- Policy enforcement
- Supply chain security
- Network security

### Part III: Advanced (Modules 11-15)

Production readiness:
- Runtime security
- Incident response
- Compliance and benchmarks
- Multi-cluster patterns
- Real-world case studies

## Learning Path Options

**Intensive Track** (2 weeks, full-time)
- 8 hours per day
- Complete all modules sequentially
- All labs and assessments

**Standard Track** (6 weeks, part-time)
- 3-4 hours per day
- Balanced pace with review time
- Recommended for working professionals

**Self-Paced Track** (12 weeks)
- 1-2 hours per day
- Flexible schedule
- Suitable for independent learners

## Key Concepts and Glossary

Before diving in, familiarize yourself with these core terms:

**Cluster Architecture:**

- **Cluster**: A set of machines (nodes) running containerized applications
- **Control Plane**: Components that manage the cluster state
- **Node**: A worker machine in Kubernetes (VM or physical machine)
- **Pod**: The smallest deployable unit containing one or more containers

**Core Resources:**

- **Deployment**: Manages a replicated set of Pods
- **Service**: Exposes Pods to network traffic
- **Namespace**: Virtual cluster for resource isolation
- **ConfigMap**: Configuration data as key-value pairs
- **Secret**: Sensitive data (credentials, tokens)

**Networking:**

- **CNI**: Container Network Interface plugin
- **Ingress**: HTTP/HTTPS routing to Services
- **NetworkPolicy**: Rules for Pod network traffic
- **Service Mesh**: Infrastructure layer for service-to-service communication

**Security:**

- **RBAC**: Role-Based Access Control
- **PSA**: Pod Security Admission
- **Admission Controller**: Plugins that govern API requests
- **SecComp**: Secure Computing Mode (syscall filtering)
- **AppArmor**: Linux security module

**Complete glossary**: See [Kubernetes Glossary](https://kubernetes.io/docs/reference/glossary/)

## Security-First Approach

This training emphasizes security at every layer:

1. **Secure by Default**: Learn secure configurations from the start
2. **Defense in Depth**: Multiple layers of security controls
3. **Least Privilege**: Minimum necessary permissions
4. **Assume Breach**: Design for containment and detection
5. **Security as Code**: Automated, repeatable security controls

**Core Security Principles:**

- Never run containers as root (unless absolutely necessary)
- Always use RBAC with least privilege
- Implement NetworkPolicies for traffic control
- Scan images for vulnerabilities before deployment
- Enable audit logging
- Use Pod Security Standards
- Encrypt data in transit and at rest

## Lab Environment Setup

### Option 1: kind (Recommended)

```bash
# Create cluster with custom config
cat <<EOF | kind create cluster --name training --config=-
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
- role: worker
- role: worker
EOF

# Verify cluster
kubectl cluster-info --context kind-training
kubectl get nodes

# Expected output:
# NAME                     STATUS   ROLES           AGE   VERSION
# training-control-plane   Ready    control-plane   1m    v1.28.0
# training-worker          Ready    <none>          1m    v1.28.0
# training-worker2         Ready    <none>          1m    v1.28.0
```

### Option 2: k3d

```bash
# Create cluster
k3d cluster create training --servers 1 --agents 2

# Verify
kubectl get nodes
```

### Option 3: minikube

```bash
# Create cluster
minikube start --nodes 3 --cpus 2 --memory 4096

# Verify
kubectl get nodes
```

### Verify Installation

Run this verification script:

```bash
#!/bin/bash
# verify-setup.sh

echo "=== Kubernetes Cluster Verification ==="

# Check kubectl
if ! command -v kubectl &> /dev/null; then
    echo "❌ kubectl not found"
    exit 1
fi
echo "✅ kubectl found: $(kubectl version --client --short 2>/dev/null)"

# Check cluster connection
if ! kubectl cluster-info &> /dev/null; then
    echo "❌ Cannot connect to cluster"
    exit 1
fi
echo "✅ Connected to cluster"

# Check nodes
NODE_COUNT=$(kubectl get nodes --no-headers 2>/dev/null | wc -l)
if [ "$NODE_COUNT" -lt 1 ]; then
    echo "❌ No nodes found"
    exit 1
fi
echo "✅ Found $NODE_COUNT node(s)"

# Check node status
NOT_READY=$(kubectl get nodes --no-headers 2>/dev/null | grep -v " Ready" | wc -l)
if [ "$NOT_READY" -gt 0 ]; then
    echo "⚠️  Warning: $NOT_READY node(s) not ready"
else
    echo "✅ All nodes ready"
fi

# Check essential pods
echo ""
echo "=== Essential System Pods ==="
kubectl get pods -n kube-system

echo ""
echo "🎉 Setup verification complete!"
```

### Accessing Cluster

```bash
# View current context
kubectl config current-context

# List all contexts
kubectl config get-contexts

# Switch context (if multiple clusters)
kubectl config use-context kind-training

# View cluster info
kubectl cluster-info

# Check API server
kubectl get --raw /healthz
```

## Learning Resources

### Official Documentation

- [Kubernetes Docs](https://kubernetes.io/docs/) - Primary reference [^1]
- [Kubernetes API Reference](https://kubernetes.io/docs/reference/kubernetes-api/)
- [kubectl Cheat Sheet](https://kubernetes.io/docs/reference/kubectl/cheatsheet/)

### Security Resources

- [CNCF Security TAG](https://github.com/cncf/tag-security) - Community security guidance [^2]
- [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes) - Security standards [^3]
- [NSA/CISA Kubernetes Hardening Guide](https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF) [^4]

### Community

- **Kubernetes Slack**: [slack.k8s.io](https://slack.k8s.io)
- **Discuss Forum**: [discuss.kubernetes.io](https://discuss.kubernetes.io)
- **Stack Overflow**: `kubernetes` tag

## Assessment Readiness

Before proceeding to Module 01, ensure you can:

- [ ] Successfully create a local Kubernetes cluster
- [ ] Run `kubectl get nodes` and see Ready nodes
- [ ] Understand basic YAML structure
- [ ] Navigate the command line confidently
- [ ] Access and search Kubernetes documentation

## Troubleshooting Common Setup Issues

### Docker Not Running

```bash
# Check Docker status
docker ps

# Start Docker (systemd Linux)
sudo systemctl start docker

# macOS - start Docker Desktop application
```

### kind Cluster Creation Fails

```bash
# Check Docker resources (need at least 4GB RAM)
docker info | grep Memory

# Delete existing cluster and retry
kind delete cluster --name training
kind create cluster --name training
```

### kubectl Cannot Connect

```bash
# Check kubeconfig
kubectl config view

# Verify context
kubectl config current-context

# Test connection
kubectl cluster-info
```

## Next Steps

Once your environment is ready:

1. Complete the [Basic Kubernetes concepts lab](../labs/00-setup/)
2. Review the [Course Roadmap](../SUMMARY.md)
3. Proceed to [Module 01: Kubernetes Basics](01-k8s-basics.md)

## References

[^1]: [Kubernetes Official Documentation](https://kubernetes.io/docs/), accessed November 2025
[^2]: [CNCF TAG Security](https://github.com/cncf/tag-security), accessed November 2025
[^3]: [CIS Kubernetes Benchmark v1.8](https://www.cisecurity.org/benchmark/kubernetes), accessed November 2025
[^4]: [NSA/CISA Kubernetes Hardening Guidance v1.2](https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF), August 2022

---

**Ready to begin?** Proceed to [Module 01: Kubernetes Basics](01-k8s-basics.md)
