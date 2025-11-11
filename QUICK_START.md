# Quick Start Guide

## 🚀 Getting Started

### 1. Clone and Setup

```bash
cd /home/user/K8S-Security

# Verify everything is ready
git status
make help
```

### 2. Build Documentation

```bash
# Install dependencies
pip install -r requirements.txt

# Build documentation site
make docs-build

# Serve locally
make docs-serve
# Open http://localhost:8000
```

### 3. Create Kubernetes Cluster

```bash
# Option 1: kind (recommended)
make kind-up

# Option 2: k3d
make k3d-up

# Option 3: minikube
./labs/scripts/setup-minikube.sh

# Verify cluster
kubectl cluster-info
kubectl get nodes
```

### 4. Run Your First Lab

```bash
# Lab 00: Environment Setup
cd labs/00-environment-setup
./scripts/verify-environment.sh

# Lab 01: Basic Deployment
cd ../01-basic-deployment
kubectl apply -f manifests/web-app-deployment.yaml
kubectl get pods
```

### 5. Deploy Sample Application

```bash
make deploy-sample
kubectl get pods -n demo
kubectl get svc -n demo
```

### 6. Run Security Scans

```bash
# CIS Kubernetes Benchmark
make run-kube-bench

# Image vulnerability scanning
make run-trivy
```

## 📖 Learning Path

**Week 1-2: Foundation**
- Module 00: Introduction
- Module 01: Kubernetes Basics
- Module 02: Control Plane
- Module 03: Networking
- Module 04: Storage

**Week 3-4: Security**
- Module 05: Auth & AuthZ
- Module 06: Pod Security
- Module 07: Admission Control
- Module 08: Observability
- Module 09: Supply Chain
- Module 10: Network Security

**Week 5-6: Advanced**
- Module 11: Runtime Security
- Module 12: Incident Response
- Module 13: CIS Compliance
- Module 14: Multi-cluster
- Module 15: Case Studies

## 🔧 Useful Commands

```bash
# Documentation
make docs-serve          # Serve locally
make docs-build          # Build static site
mkdocs gh-deploy        # Deploy to GitHub Pages

# Cluster Management
make kind-up            # Create kind cluster
make kind-down          # Delete kind cluster
kubectl get nodes       # Check cluster nodes

# Testing
make lint               # Lint markdown and YAML
make validate           # Validate K8s manifests
make test-labs          # Run lab smoke tests

# Cleanup
make cleanup            # Remove deployments
make kind-down          # Delete cluster
```

## 📚 Key Resources

- **Modules**: `/docs/` - All 16 training modules
- **Labs**: `/labs/` - Hands-on exercises
- **Examples**: `/examples/` - Production manifests
- **Security Tools**: `/security-tools/` - Tool configs
- **Assessments**: `/assessments/` - Quizzes & challenges

## 🐛 Troubleshooting

### Documentation won't build
```bash
pip install -r requirements.txt
mkdocs build
```

### Cluster creation fails
```bash
# Check Docker is running
docker ps

# Try different cluster tool
./labs/scripts/setup-k3d.sh
```

### kubectl not found
```bash
# Install kubectl
brew install kubectl  # macOS
# or follow: https://kubernetes.io/docs/tasks/tools/
```

## ✅ Verification Checklist

- [ ] Git status clean
- [ ] Documentation builds successfully
- [ ] Cluster created and accessible
- [ ] Sample deployment works
- [ ] All Makefile commands work

## 🆘 Getting Help

- Check `CONTRIBUTING.md` for guidelines
- Review `WORKFLOW.md` for maintenance
- See `REFERENCES.md` for sources
- Open GitHub issue for bugs

---

**Ready to learn Kubernetes security?** Start with Module 00! 🚀
