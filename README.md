# Kubernetes Architecture and Security Training

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Documentation](https://img.shields.io/badge/docs-mkdocs-blue.svg)](https://kubernetes.io/docs/)
[![Kubernetes](https://img.shields.io/badge/kubernetes-1.28+-326CE5.svg)](https://kubernetes.io/)

**A comprehensive, hands-on training program for Kubernetes architecture, operations, and security best practices.**

## 🎯 Overview

This repository provides end-to-end training for engineers and architects who want to master Kubernetes from fundamentals through advanced security hardening. Built by practitioners with real-world experience operating large-scale on-premises and cloud Kubernetes platforms, this material emphasizes practical skills, security-first thinking, and production-ready patterns.

### What You'll Learn

- **Architecture**: Deep understanding of Kubernetes control plane, networking, storage, and operational patterns
- **Security**: Authentication, authorization, pod security, admission control, runtime security, and supply chain security
- **Operations**: High availability, disaster recovery, monitoring, logging, and incident response
- **Best Practices**: Production hardening, CIS benchmarks, compliance, and common anti-patterns to avoid

## 👥 Target Audience

- **Platform Engineers** building and operating Kubernetes infrastructure
- **DevOps/SRE Teams** deploying and securing applications on Kubernetes
- **Security Engineers** implementing Kubernetes security controls and threat detection
- **Architects** designing multi-cluster, hybrid, and high-availability Kubernetes platforms
- **Developers** needing deep understanding of the platform their apps run on

### Prerequisites

**Required:**
- Basic Linux command line proficiency
- Understanding of containers (Docker basics)
- Familiarity with YAML syntax
- Basic networking concepts (IP, DNS, routing)

**Recommended:**
- Experience deploying containerized applications
- Understanding of infrastructure as code concepts
- Basic knowledge of TLS/PKI

## 📚 Repository Structure

```
.
├── README.md                    # This file
├── SUMMARY.md                   # Course roadmap and table of contents
├── docs/                        # Full course content (16 modules)
│   ├── 00-intro.md
│   ├── 01-k8s-basics.md
│   ├── 02-control-plane.md
│   └── ...
├── labs/                        # Hands-on labs with step-by-step instructions
│   ├── scripts/                 # Automation scripts (kind, k3d setup)
│   └── solutions/               # Lab solutions
├── examples/                    # YAML manifests, Helm charts, CI/CD examples
│   ├── manifests/
│   ├── helm-charts/
│   └── ci-cd/
├── diagrams/                    # Architecture diagrams (mermaid + draw.io)
│   ├── *.mermaid
│   ├── *.drawio
│   └── *.png
├── security-tools/              # Security tool configurations and examples
│   ├── kube-bench/
│   ├── falco/
│   ├── opa-gatekeeper/
│   └── trivy/
├── assessments/                 # Quizzes and practical challenges
│   ├── solutions/
│   └── scoring-guide.md
├── terraform/                   # Optional cloud infrastructure (Azure)
├── .github/                     # Issue templates, PR template, CI workflows
├── mkdocs.yml                   # Documentation site configuration
├── Makefile                     # Common automation tasks
├── REFERENCES.md                # Citations and sources
├── CONTRIBUTING.md              # Contribution guidelines
├── WORKFLOW.md                  # Content update and maintenance guide
└── LICENSE                      # MIT License
```

## 🗺️ Learning Path

### Foundation Track (Weeks 1-2)
**Estimated Time: 20-25 hours**

1. **Module 00**: Introduction & Prerequisites (1 hour)
2. **Module 01**: Kubernetes Basics (4 hours)
3. **Module 02**: Control Plane & Cluster Components (5 hours)
4. **Module 03**: Networking (5 hours)
5. **Module 04**: Storage (3 hours)

### Security Track (Weeks 3-4)
**Estimated Time: 25-30 hours**

6. **Module 05**: Authentication & Authorization (5 hours)
7. **Module 06**: Pod Security (4 hours)
8. **Module 07**: Admission & Policy (4 hours)
9. **Module 08**: Observability & Logging (5 hours)
10. **Module 09**: Supply Chain & Image Security (5 hours)
11. **Module 10**: Network Security (4 hours)

### Advanced Track (Weeks 5-6)
**Estimated Time: 20-25 hours**

12. **Module 11**: Runtime Security (5 hours)
13. **Module 12**: Incident Response (4 hours)
14. **Module 13**: CIS & Compliance (5 hours)
15. **Module 14**: Multi-cluster & Federation (3 hours)
16. **Module 15**: Case Studies (4 hours)

**Total Estimated Time: 65-80 hours** (includes labs, reading, and practice)

## 🚀 Quick Start

### Setup Local Environment

```bash
# Clone this repository
git clone https://github.com/yourusername/k8s-architecture-and-security-training.git
cd k8s-architecture-and-security-training

# Install prerequisites (macOS example)
brew install kubectl kind helm

# Create a local Kubernetes cluster
make kind-up

# Verify cluster is running
kubectl cluster-info
kubectl get nodes
```

### Alternative: Use k3d or minikube

```bash
# Using k3d
./labs/scripts/setup-k3d.sh

# Using minikube
./labs/scripts/setup-minikube.sh
```

### Run Your First Lab

```bash
# Deploy sample application
make deploy-sample

# Access the application
kubectl get pods -n demo
kubectl get svc -n demo
```

## 📖 How to Use This Repository

### Self-Paced Learning

1. **Read** the module content in `docs/` sequentially
2. **Review** architecture diagrams in each module
3. **Complete** hands-on labs in `labs/`
4. **Practice** with examples in `examples/`
5. **Test** your knowledge with assessments
6. **Reference** the checklists and best practices

### Instructor-Led Workshops

This repository is designed for instructor-led training:
- Each module has **teaching notes** and **timing estimates**
- Labs include **troubleshooting guides** for common issues
- Assessments provide **scoring rubrics** for evaluation
- Slide decks can be generated from markdown using tools like Marp

### Continuous Learning

- Use as a **reference guide** for production cluster operations
- Refer to **security checklists** before production deployments
- Apply **hardening guides** to existing clusters
- Use **audit tooling examples** for security assessments

## 🔧 Available Commands

```bash
make help              # Show all available commands

# Cluster Management
make kind-up           # Create kind cluster
make kind-down         # Delete kind cluster
make k3d-up            # Create k3d cluster
make k3d-down          # Delete k3d cluster

# Application Deployment
make deploy-sample     # Deploy sample application
make deploy-security   # Deploy security tools
make cleanup           # Remove all deployments

# Security Tools
make run-kube-bench    # Run CIS benchmark scan
make run-trivy         # Scan images for vulnerabilities
make run-falco         # Start Falco runtime security

# Documentation
make docs-serve        # Serve documentation locally
make docs-build        # Build static documentation site

# Testing
make lint              # Lint YAML and markdown
make validate          # Validate Kubernetes manifests
make test-labs         # Run lab smoke tests
```

## 🌐 Documentation Site

This repository includes a complete documentation website built with [MkDocs Material](https://squidfunk.github.io/mkdocs-material/).

### Serve Locally

```bash
# Install mkdocs
pip install mkdocs-material

# Serve documentation
mkdocs serve

# Open browser to http://localhost:8000
```

### Deploy to GitHub Pages

```bash
# Build and deploy
mkdocs gh-deploy

# Documentation will be available at:
# https://yourusername.github.io/k8s-architecture-and-security-training/
```

## 🔒 Security Tooling

This repository includes working examples and configurations for:

- **[kube-bench](https://github.com/aquasecurity/kube-bench)**: CIS Kubernetes Benchmark assessment
- **[kube-hunter](https://github.com/aquasecurity/kube-hunter)**: Kubernetes penetration testing
- **[Falco](https://falco.org/)**: Runtime security and threat detection
- **[OPA/Gatekeeper](https://open-policy-agent.github.io/gatekeeper/)**: Policy enforcement
- **[Kyverno](https://kyverno.io/)**: Kubernetes native policy management
- **[Trivy](https://aquasecurity.github.io/trivy/)**: Container image vulnerability scanning
- **[cosign](https://docs.sigstore.dev/cosign/)**: Container image signing and verification

See `security-tools/` directory for configuration examples and usage instructions.

## 🎓 Assessments & Challenges

Test your knowledge with:
- **Multiple-choice quizzes** covering key concepts
- **Practical challenges** requiring hands-on problem solving
- **Security audit exercises** using real-world scenarios
- **Troubleshooting scenarios** with scoring rubrics

All assessments include solutions and detailed explanations in `assessments/solutions/`.

## ☁️ Cloud Resources (Optional)

For advanced labs requiring cloud resources:
- **Terraform modules** for Azure Kubernetes Service (AKS) in `terraform/`
- Clearly marked as **OPTIONAL** - all core content works with local clusters
- Includes cost estimates and cleanup instructions

## 🤝 Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for:
- How to add new modules or labs
- Diagram creation guidelines
- PR review checklist
- Code of conduct

## 📝 License

This project is licensed under the MIT License - see [LICENSE](LICENSE) file for details.

## 🔗 Additional Resources

- [Official Kubernetes Documentation](https://kubernetes.io/docs/)
- [Kubernetes Security Best Practices](https://kubernetes.io/docs/concepts/security/)
- [CNCF Security TAG](https://github.com/cncf/tag-security)
- [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes)
- [NIST SP 800-190: Container Security](https://csrc.nist.gov/publications/detail/sp/800-190/final)

## 📚 Citations

All content is based on authoritative sources and current best practices. See [REFERENCES.md](REFERENCES.md) for complete citations with dates accessed.

## 💬 Support & Feedback

- **Issues**: Report bugs or request features via [GitHub Issues](.github/ISSUE_TEMPLATE/)
- **Discussions**: Ask questions in GitHub Discussions
- **Security Issues**: Report confidentially via [SECURITY.md](SECURITY.md)

## 🗓️ Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history and updates.

---

**Built with ❤️ by Kubernetes practitioners for the community**

*Last updated: November 2025*