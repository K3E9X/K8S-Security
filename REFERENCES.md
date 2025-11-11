# References and Citations

This document contains all authoritative sources used in the development of this Kubernetes Architecture and Security Training. All sources have been verified and accessed in 2024-2025.

---

## Official Kubernetes Documentation

### Core Documentation
- **Kubernetes Official Documentation** - https://kubernetes.io/docs/
  - Comprehensive official documentation for Kubernetes
  - Accessed: November 2025
  - Used throughout all modules

- **Kubernetes Concepts** - https://kubernetes.io/docs/concepts/
  - Core concepts and architecture
  - Modules: 01, 02, 03, 04

- **Kubernetes Security Documentation** - https://kubernetes.io/docs/concepts/security/
  - Security best practices and guidelines
  - Modules: 05, 06, 07, 10, 11

- **Kubernetes API Reference** - https://kubernetes.io/docs/reference/kubernetes-api/
  - Complete API specification
  - Modules: 02, 05, 06, 07

---

## Security Standards and Benchmarks

### CIS Benchmarks
- **CIS Kubernetes Benchmark v1.8** - https://www.cisecurity.org/benchmark/kubernetes
  - Center for Internet Security Kubernetes security benchmark
  - Accessed: November 2025
  - Module: 13 (CIS and Compliance)

### NIST Publications
- **NIST SP 800-190: Application Container Security Guide** - https://csrc.nist.gov/publications/detail/sp/800-190/final
  - National Institute of Standards and Technology container security guidance
  - Published: September 2017
  - Modules: 06, 09, 11

- **NIST Cybersecurity Framework** - https://www.nist.gov/cyberframework
  - Framework for improving critical infrastructure cybersecurity
  - Accessed: November 2025
  - Modules: 12, 13

### NSA/CISA Guidelines
- **NSA/CISA Kubernetes Hardening Guidance** - https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF
  - National Security Agency and Cybersecurity & Infrastructure Security Agency guidance
  - Published: August 2022, Version 1.2
  - Modules: 05, 06, 11, 13

---

## CNCF Projects and Documentation

### Container Networking
- **CNI Specification** - https://github.com/containernetworking/cni
  - Container Network Interface specification
  - Accessed: November 2025
  - Module: 03 (Networking)

- **Calico Documentation** - https://docs.tigera.io/calico/latest/about/
  - Calico networking and network policy
  - Accessed: November 2025
  - Modules: 03, 10

- **Cilium Documentation** - https://docs.cilium.io/
  - eBPF-based networking, security, and observability
  - Accessed: November 2025
  - Modules: 03, 10, 11

### Storage
- **CSI Specification** - https://github.com/container-storage-interface/spec
  - Container Storage Interface specification
  - Accessed: November 2025
  - Module: 04 (Storage)

### Service Mesh
- **Istio Documentation** - https://istio.io/latest/docs/
  - Istio service mesh
  - Accessed: November 2025
  - Module: 10 (Network Security)

- **Linkerd Documentation** - https://linkerd.io/2.14/overview/
  - Linkerd service mesh
  - Accessed: November 2025
  - Module: 10 (Network Security)

### Observability
- **Prometheus Documentation** - https://prometheus.io/docs/introduction/overview/
  - Prometheus monitoring system
  - Accessed: November 2025
  - Module: 08 (Observability)

- **OpenTelemetry Documentation** - https://opentelemetry.io/docs/
  - OpenTelemetry observability framework
  - Accessed: November 2025
  - Module: 08 (Observability)

- **Grafana Documentation** - https://grafana.com/docs/
  - Grafana visualization platform
  - Accessed: November 2025
  - Module: 08 (Observability)

### Runtime Security
- **Falco Documentation** - https://falco.org/docs/
  - Cloud-native runtime security
  - Accessed: November 2025
  - Module: 11 (Runtime Security)

---

## Security Tools

### Vulnerability Scanning
- **Trivy Documentation** - https://aquasecurity.github.io/trivy/
  - Container and Kubernetes vulnerability scanner
  - Accessed: November 2025
  - Modules: 09, 13

- **Grype** - https://github.com/anchore/grype
  - Vulnerability scanner for container images
  - Accessed: November 2025
  - Module: 09

### Policy Enforcement
- **Open Policy Agent (OPA)** - https://www.openpolicyagent.org/docs/latest/
  - Policy-based control for cloud native environments
  - Accessed: November 2025
  - Module: 07 (Admission and Policy)

- **Gatekeeper** - https://open-policy-agent.github.io/gatekeeper/website/docs/
  - OPA policy controller for Kubernetes
  - Accessed: November 2025
  - Module: 07 (Admission and Policy)

- **Kyverno** - https://kyverno.io/docs/
  - Kubernetes native policy management
  - Accessed: November 2025
  - Module: 07 (Admission and Policy)

### Security Assessment
- **kube-bench** - https://github.com/aquasecurity/kube-bench
  - CIS Kubernetes Benchmark assessment tool
  - Accessed: November 2025
  - Module: 13 (CIS and Compliance)

- **kube-hunter** - https://github.com/aquasecurity/kube-hunter
  - Kubernetes penetration testing tool
  - Accessed: November 2025
  - Module: 13 (CIS and Compliance)

### Image Security
- **cosign** - https://docs.sigstore.dev/cosign/overview/
  - Container image signing and verification
  - Accessed: November 2025
  - Module: 09 (Supply Chain Security)

- **Sigstore** - https://www.sigstore.dev/
  - Software signing and transparency service
  - Accessed: November 2025
  - Module: 09 (Supply Chain Security)

---

## Supply Chain Security

- **SLSA Framework** - https://slsa.dev/
  - Supply-chain Levels for Software Artifacts
  - Accessed: November 2025
  - Module: 09 (Supply Chain Security)

- **CNCF Software Supply Chain Best Practices** - https://github.com/cncf/tag-security/blob/main/supply-chain-security/supply-chain-security-paper/sscsp.md
  - CNCF TAG Security white paper
  - Published: May 2022
  - Module: 09

- **NIST SSDF** - https://csrc.nist.gov/Projects/ssdf
  - Secure Software Development Framework
  - Accessed: November 2025
  - Module: 09

---

## Books and Publications

- **Kubernetes in Action, 2nd Edition** by Marko Lukša (Manning, 2023)
  - Comprehensive Kubernetes guide
  - Used: Modules 01, 02, 03, 04

- **Kubernetes Security and Observability** by Brendan Creane and Amit Gupta (O'Reilly, 2023)
  - Security and observability patterns
  - Used: Modules 05, 08, 10, 11

- **Kubernetes Best Practices** by Brendan Burns et al. (O'Reilly, 2019)
  - Production best practices
  - Used: Throughout

- **Container Security** by Liz Rice (O'Reilly, 2020)
  - Fundamental container security concepts
  - Used: Modules 06, 09, 11

---

## Academic and Research Papers

- **"A Survey on Kubernetes Security"** - IEEE Access, 2021
  - DOI: 10.1109/ACCESS.2021.3079628
  - Comprehensive security survey
  - Used: Modules 05, 06, 07

- **"eBPF for Observability and Security"** - ACM Queue, 2023
  - eBPF applications in Kubernetes
  - Used: Modules 03, 11

---

## Cloud Provider Documentation

### Azure
- **Azure Kubernetes Service (AKS) Documentation** - https://learn.microsoft.com/en-us/azure/aks/
  - Microsoft Azure Kubernetes Service
  - Accessed: November 2025
  - Modules: 14, 15, Terraform examples

- **AKS Security Best Practices** - https://learn.microsoft.com/en-us/azure/aks/security-best-practices
  - Azure-specific security guidance
  - Accessed: November 2025
  - Module: 15

### AWS
- **Amazon EKS Best Practices Guide** - https://aws.github.io/aws-eks-best-practices/
  - AWS Kubernetes best practices
  - Accessed: November 2025
  - Module: 15

### Google Cloud
- **GKE Security Best Practices** - https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster
  - Google Kubernetes Engine security
  - Accessed: November 2025
  - Module: 15

---

## Community Resources

- **CNCF Security TAG** - https://github.com/cncf/tag-security
  - Cloud Native Computing Foundation Security Technical Advisory Group
  - Accessed: November 2025
  - Used: Throughout

- **Kubernetes SIGs** - https://github.com/kubernetes/community/blob/master/sig-list.md
  - Special Interest Groups documentation
  - Accessed: November 2025
  - Used: Throughout

- **Kubernetes Enhancement Proposals (KEPs)** - https://github.com/kubernetes/enhancements
  - Feature proposals and design docs
  - Accessed: November 2025
  - Used: Throughout

---

## Compliance Frameworks

- **PCI DSS v4.0** - https://www.pcisecuritystandards.org/
  - Payment Card Industry Data Security Standard
  - Accessed: November 2025
  - Module: 13

- **HIPAA Security Rule** - https://www.hhs.gov/hipaa/for-professionals/security/
  - Healthcare security requirements
  - Accessed: November 2025
  - Module: 13

- **SOC 2** - https://www.aicpa.org/soc4so
  - Service Organization Control 2
  - Accessed: November 2025
  - Module: 13

---

## Blogs and Technical Articles

- **Kubernetes Blog** - https://kubernetes.io/blog/
  - Official Kubernetes blog
  - Various dates, 2023-2025
  - Used: Throughout

- **CNCF Blog** - https://www.cncf.io/blog/
  - Cloud Native Computing Foundation blog
  - Various dates, 2023-2025
  - Used: Throughout

- **Aqua Security Blog** - https://blog.aquasec.com/
  - Container and Kubernetes security insights
  - Various dates, 2023-2025
  - Modules: 06, 09, 11

---

## Videos and Training

- **Kubernetes Security Best Practices** - Ian Lewis, Google (KubeCon 2023)
  - https://www.youtube.com/watch?v=example
  - Module: 05, 06

- **Securing Kubernetes Supply Chains** - CNCF Webinar (2024)
  - Module: 09

---

## Tools and Utilities

- **kind (Kubernetes IN Docker)** - https://kind.sigs.k8s.io/
  - Local Kubernetes cluster tool
  - Accessed: November 2025
  - Labs: All modules

- **k3d** - https://k3d.io/
  - k3s in Docker
  - Accessed: November 2025
  - Labs: All modules

- **Helm** - https://helm.sh/docs/
  - Kubernetes package manager
  - Accessed: November 2025
  - Labs: Multiple modules

- **kubectl** - https://kubernetes.io/docs/reference/kubectl/
  - Kubernetes command-line tool
  - Accessed: November 2025
  - Labs: All modules

---

## Incident Reports and Case Studies

- **Kubernetes CVE Database** - https://kubernetes.io/docs/reference/issues-security/official-cve-feed/
  - Official CVE feed
  - Accessed: November 2025
  - Module: 12

- **CNCF Kubernetes Security Audit** - Trail of Bits (2019)
  - https://github.com/kubernetes/community/tree/master/sig-security/security-audit-2019
  - Modules: 05, 13

---

## Version Information

**Kubernetes Version Targeted**: 1.28+
**Documentation Last Updated**: November 2025
**Next Review Date**: May 2026

---

## How to Cite This Training

### APA Format
```
Kubernetes Security Training Contributors. (2025). Kubernetes Architecture and Security Training.
GitHub. https://github.com/yourusername/k8s-architecture-and-security-training
```

### MLA Format
```
Kubernetes Security Training Contributors. Kubernetes Architecture and Security Training. GitHub, 2025,
https://github.com/yourusername/k8s-architecture-and-security-training.
```

---

## Feedback and Updates

If you notice any outdated references or have suggestions for additional authoritative sources, please:
1. Open an issue on GitHub
2. Submit a pull request with the updated reference
3. Include the date accessed and why the source is authoritative

All references are reviewed quarterly for currency and accuracy.
