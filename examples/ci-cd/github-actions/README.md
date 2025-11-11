# GitHub Actions Secure CI/CD Pipeline

This workflow demonstrates a secure container build and deployment pipeline.

## Features

- Code and filesystem vulnerability scanning with Trivy
- Container image building and pushing to registry
- Image signing with Cosign (keyless)
- Container image scanning
- Automated deployment to Kubernetes
- SARIF upload to GitHub Security

## Usage

1. Add secrets to your repository:
   - `KUBE_CONFIG`: Base64-encoded kubeconfig file

2. Place Kubernetes manifests in `k8s/manifests/`

3. Push to main branch to trigger deployment

## Security Controls

- SARIF results uploaded to GitHub Security tab
- Critical/High vulnerabilities fail the build
- Images are cryptographically signed
- Deployment only on main branch
- Minimal permissions (GITHUB_TOKEN)
