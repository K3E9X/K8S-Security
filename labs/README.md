# Kubernetes Security Hands-On Labs

Welcome to the Kubernetes Security hands-on labs! These labs provide practical, real-world experience with Kubernetes security concepts and best practices.

## Getting Started

### Prerequisites

Before starting the labs, ensure you have:
- A working Kubernetes cluster (kind, k3d, or minikube)
- kubectl installed and configured
- Docker installed
- Basic knowledge of Kubernetes concepts
- 4GB+ RAM available
- 20GB+ disk space

### Setup

1. **Clone the repository** (if not already done):
```bash
git clone <repository-url>
cd K8S-Security/labs
```

2. **Set up your cluster** using one of the provided scripts:
```bash
cd scripts
./setup-kind.sh          # Recommended
# OR
./setup-k3d.sh
# OR
./setup-minikube.sh
```

3. **Verify your environment**:
```bash
cd ../00-environment-setup/scripts
./verify-environment.sh
```

## Lab Overview

### Lab 00: Environment Setup
**Time:** 30-45 minutes
**Difficulty:** Beginner

Set up and verify your Kubernetes security lab environment.

**Topics covered:**
- Cluster creation
- Tool installation
- Environment verification

**Start here:** [labs/00-environment-setup/README.md](./00-environment-setup/README.md)

---

### Lab 01: Basic Deployment and Service Exposure
**Time:** 45-60 minutes
**Difficulty:** Beginner

Deploy applications and expose them securely with proper security contexts.

**Topics covered:**
- Deployments and Services
- Security contexts
- Resource limits
- Health probes
- Non-root users

**Start here:** [labs/01-basic-deployment/README.md](./01-basic-deployment/README.md)

---

### Lab 03: Network Policies
**Time:** 60-75 minutes
**Difficulty:** Intermediate

Implement network segmentation and zero-trust networking with NetworkPolicies.

**Topics covered:**
- NetworkPolicy fundamentals
- Ingress and egress rules
- Default deny policies
- DNS access
- Three-tier application security

**Start here:** [labs/03-network-policies/README.md](./03-network-policies/README.md)

---

### Lab 05: Role-Based Access Control (RBAC)
**Time:** 60-75 minutes
**Difficulty:** Intermediate

Implement authentication and authorization with RBAC.

**Topics covered:**
- ServiceAccounts
- Roles and ClusterRoles
- RoleBindings and ClusterRoleBindings
- Least privilege access
- Permission testing

**Start here:** [labs/05-rbac/README.md](./05-rbac/README.md)

---

### Lab 06: Pod Security Standards
**Time:** 60-75 minutes
**Difficulty:** Intermediate

Enforce pod-level security with Pod Security Standards.

**Topics covered:**
- Pod Security Standards (Privileged, Baseline, Restricted)
- Security contexts
- Capabilities
- Read-only root filesystems
- Seccomp and AppArmor profiles

**Start here:** [labs/06-pod-security/README.md](./06-pod-security/README.md)

---

### Lab 09: Image Scanning and Signing
**Time:** 60-75 minutes
**Difficulty:** Advanced

Secure your supply chain with image scanning and signing.

**Topics covered:**
- Vulnerability scanning with Trivy
- Image signing with Cosign
- Signature verification
- SBOM generation
- CI/CD integration

**Start here:** [labs/09-image-scanning/README.md](./09-image-scanning/README.md)

---

## Lab Structure

Each lab includes:

```
lab-XX-name/
├── README.md              # Lab instructions
├── manifests/             # Kubernetes YAML files
│   ├── *.yaml
├── scripts/               # Helper scripts
│   ├── *.sh
├── expected-output.txt    # Expected results
└── troubleshooting.md     # Common issues and solutions
```

## Recommended Lab Sequence

For the best learning experience, complete the labs in this order:

1. **Lab 00** - Environment Setup (Required first)
2. **Lab 01** - Basic Deployment
3. **Lab 03** - Network Policies
4. **Lab 05** - RBAC
5. **Lab 06** - Pod Security
6. **Lab 09** - Image Scanning

Each lab builds upon concepts from previous labs.

## Useful Scripts

### Cluster Management

```bash
# Setup scripts (in labs/scripts/)
./setup-kind.sh [cluster-name]
./setup-k3d.sh [cluster-name]
./setup-minikube.sh [cluster-name]

# Cleanup everything
./cleanup-all.sh
```

### Per-Lab Scripts

Each lab includes:
- `scripts/cleanup.sh` - Clean up lab resources
- Security check scripts specific to the lab
- Helper scripts for testing and verification

## Tips for Success

1. **Read carefully**: Each lab has detailed instructions
2. **Check expected output**: Compare your results with `expected-output.txt`
3. **Use troubleshooting guides**: Refer to `troubleshooting.md` when stuck
4. **Verify each step**: Don't skip verification steps
5. **Clean up**: Use cleanup scripts between labs to free resources

## Common Commands

```bash
# Check cluster status
kubectl cluster-info
kubectl get nodes

# View resources
kubectl get all -n <namespace>

# Check logs
kubectl logs <pod-name> -n <namespace>

# Describe resources for debugging
kubectl describe pod <pod-name> -n <namespace>

# Test permissions
kubectl auth can-i <verb> <resource> --as=<user>

# Port forwarding for testing
kubectl port-forward <pod-name> <local-port>:<pod-port>
```

## Getting Help

### Within Labs
- Check `expected-output.txt` for reference
- Review `troubleshooting.md` for common issues
- Use `--help` with kubectl commands
- Check pod events: `kubectl get events -n <namespace>`

### External Resources
- [Kubernetes Documentation](https://kubernetes.io/docs/)
- [Kubernetes Security Best Practices](https://kubernetes.io/docs/concepts/security/)
- [kubectl Cheat Sheet](https://kubernetes.io/docs/reference/kubectl/cheatsheet/)

### Community
- Kubernetes Slack: https://kubernetes.slack.com
- Stack Overflow: Tag `kubernetes`

## Resource Management

### Check Resource Usage
```bash
kubectl top nodes
kubectl top pods -A
```

### Free Up Resources
```bash
# Delete completed pods
kubectl delete pods --field-selector status.phase=Succeeded --all-namespaces

# Clean up a specific lab
cd labs/<lab-name>/scripts
./cleanup.sh
```

### Full Cleanup
```bash
# Remove all lab resources
cd labs/scripts
./cleanup-all.sh
```

## Solutions

Reference solutions for each lab are available in the `solutions/` directory. Try to complete each lab independently before consulting solutions.

## Cluster Alternatives

### kind (Recommended)
**Pros:** Fast, widely used, good documentation
**Cons:** Limited LoadBalancer support

### k3d
**Pros:** Lightweight, fast, includes registry
**Cons:** Different from standard K8s in some ways

### minikube
**Pros:** Feature-rich, good for learning, includes dashboard
**Cons:** Slower to start, more resource-intensive

Choose based on your preferences and system capabilities.

## Lab Completion Checklist

Track your progress:

- [ ] Lab 00: Environment Setup
- [ ] Lab 01: Basic Deployment
- [ ] Lab 03: Network Policies
- [ ] Lab 05: RBAC
- [ ] Lab 06: Pod Security
- [ ] Lab 09: Image Scanning

## Additional Practice

After completing the labs, try:

1. **Combine concepts**: Apply multiple security controls together
2. **Real applications**: Deploy actual applications with security hardening
3. **Custom scenarios**: Create your own security challenges
4. **Automation**: Script the deployment and security checks
5. **Certification prep**: Use labs to prepare for CKS exam

## Contributing

Found an issue or have suggestions? Please contribute!

1. Report issues in the repository
2. Submit pull requests for improvements
3. Share your experiences and tips

## License

See the main repository LICENSE file.

---

**Happy Learning!** 🚀🔒

For questions or support, refer to the main repository documentation or reach out to the community.
