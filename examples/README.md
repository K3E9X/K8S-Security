# Kubernetes Examples

This directory contains production-ready examples for various Kubernetes resources and patterns.

## Directory Structure

```
examples/
├── manifests/          # YAML manifests for various resources
│   ├── deployments/    # Deployment examples
│   ├── services/       # Service configurations
│   ├── security/       # Security-focused configs
│   └── networking/     # Network policies and ingress
├── helm-charts/        # Helm chart examples
│   ├── secure-app/     # Secure application chart
│   └── monitoring/     # Monitoring stack chart
└── ci-cd/              # CI/CD pipeline examples
    ├── github-actions/ # GitHub Actions workflows
    └── gitlab-ci/      # GitLab CI examples
```

## Usage

All examples follow Kubernetes security best practices:
- Non-root containers
- Read-only root filesystems where possible
- Network policies for traffic control
- Resource limits and requests
- Pod Security Standards compliance

Refer to individual subdirectories for specific examples and usage instructions.
