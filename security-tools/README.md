# Security Tools

This directory contains configurations and examples for Kubernetes security tools.

## Tools Included

- **kube-bench** - CIS Kubernetes Benchmark assessment
- **falco** - Runtime security and threat detection
- **opa-gatekeeper** - Policy enforcement with OPA
- **kyverno** - Kubernetes native policy management
- **trivy** - Vulnerability and misconfiguration scanning

Each subdirectory contains:
- Installation instructions
- Configuration files
- Usage examples
- Integration with CI/CD

## Quick Start

```bash
# Deploy kube-bench
kubectl apply -f kube-bench/job.yaml

# Deploy Falco
kubectl apply -f falco/daemonset.yaml

# Deploy Gatekeeper
kubectl apply -f opa-gatekeeper/install.yaml

# Deploy Kyverno
kubectl apply -f kyverno/install.yaml
```
