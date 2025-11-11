# Course Roadmap

**Kubernetes Architecture and Security Training**

Complete learning path from fundamentals to advanced security hardening.

---

## 📋 Table of Contents

### Part I: Foundation (Weeks 1-2)

#### [Module 00: Introduction](docs/00-intro.md)
*Estimated time: 1 hour*

- Course overview and learning objectives
- Target audience and prerequisites
- Lab environment setup
- Glossary of key terms
- Learning outcomes and certification paths

#### [Module 01: Kubernetes Basics](docs/01-k8s-basics.md)
*Estimated time: 4 hours*

- Kubernetes architecture overview
- Pods: the fundamental unit
- Services and service discovery
- Deployments and ReplicaSets
- Labels, selectors, and annotations
- Namespaces and resource organization
- **Lab**: Deploy first application
- **Lab**: Service discovery patterns

#### [Module 02: Control Plane and Cluster Components](docs/02-control-plane.md)
*Estimated time: 5 hours*

- kube-apiserver: the API gateway
- etcd: distributed key-value store
- kube-controller-manager: reconciliation loops
- kube-scheduler: pod placement decisions
- kubelet: node agent
- kube-proxy: network proxy
- Container runtime (containerd, CRI-O)
- High availability patterns
- **Lab**: etcd backup and restore
- **Lab**: Inspect control plane components
- **Lab**: Configure HA control plane (optional)

#### [Module 03: Networking](docs/03-networking.md)
*Estimated time: 5 hours*

- Container Network Interface (CNI) overview
- CNI plugins: Calico, Cilium, Flannel comparison
- Pod-to-pod communication
- Service types: ClusterIP, NodePort, LoadBalancer
- Ingress controllers and ingress resources
- DNS and service discovery
- NetworkPolicies for traffic control
- eBPF and advanced networking
- Common networking pitfalls
- **Lab**: Deploy CNI plugin
- **Lab**: Configure NetworkPolicies
- **Lab**: Ingress configuration

#### [Module 04: Storage](docs/04-storage.md)
*Estimated time: 3 hours*

- Volumes and volume types
- PersistentVolumes (PV) and PersistentVolumeClaims (PVC)
- StorageClasses and dynamic provisioning
- Container Storage Interface (CSI)
- Volume snapshots and cloning
- StatefulSets for stateful applications
- **Lab**: Configure persistent storage
- **Lab**: StatefulSet deployment
- **Lab**: Volume snapshots

---

### Part II: Security (Weeks 3-4)

#### [Module 05: Authentication and Authorization](docs/05-authn-authz.md)
*Estimated time: 5 hours*

- kubeconfig and cluster authentication
- Client certificates and certificate authorities
- Service accounts and token authentication
- OIDC integration for user authentication
- Role-Based Access Control (RBAC)
- ABAC (deprecated, historical context)
- Admission controllers in auth flow
- Best practices and least privilege
- Common RBAC mistakes
- **Lab**: Configure RBAC roles
- **Lab**: OIDC integration (optional)
- **Lab**: Service account token projection

#### [Module 06: Pod Security](docs/06-pod-security.md)
*Estimated time: 4 hours*

- Pod Security Standards (baseline, restricted, privileged)
- Pod Security Admission (PSA)
- Security contexts and capabilities
- seccomp profiles
- AppArmor and SELinux
- Read-only root filesystems
- Running as non-root
- Image pull policies
- **Lab**: Apply Pod Security Standards
- **Lab**: Configure seccomp and AppArmor
- **Lab**: Secure pod configurations

#### [Module 07: Admission Control and Policy](docs/07-admission-policy.md)
*Estimated time: 4 hours*

- Admission controller overview
- ValidatingWebhookConfiguration
- MutatingWebhookConfiguration
- Open Policy Agent (OPA) and Gatekeeper
- Kyverno policy engine
- Policy as code patterns
- Common policies and use cases
- **Lab**: Deploy Gatekeeper
- **Lab**: Create OPA policies
- **Lab**: Kyverno policy examples

#### [Module 08: Observability and Logging](docs/08-observability.md)
*Estimated time: 5 hours*

- Observability pillars: metrics, logs, traces
- Prometheus for metrics collection
- Grafana for visualization
- OpenTelemetry integration
- Fluentd/Fluent Bit for log aggregation
- Kubernetes audit logs
- Alerting rules and incident detection
- Dashboard best practices
- **Lab**: Deploy Prometheus stack
- **Lab**: Configure audit logging
- **Lab**: Create custom dashboards

#### [Module 09: Supply Chain and Image Security](docs/09-supply-chain.md)
*Estimated time: 5 hours*

- Software supply chain threats
- Image scanning with Trivy
- Image signing with cosign
- SLSA framework overview
- Admission webhooks for image validation
- Private container registries
- CI/CD security patterns
- **Lab**: Image scanning pipeline
- **Lab**: Sign and verify images
- **Lab**: Secure GitHub Actions workflow

#### [Module 10: Network Security](docs/10-network-security.md)
*Estimated time: 4 hours*

- Network segmentation strategies
- Zero trust networking
- Service mesh security (Istio, Linkerd)
- Mutual TLS (mTLS)
- Egress controls
- DNS security
- **Lab**: Implement network segmentation
- **Lab**: Service mesh deployment (optional)
- **Lab**: Egress policy enforcement

---

### Part III: Advanced Topics (Weeks 5-6)

#### [Module 11: Runtime Security](docs/11-runtime-security.md)
*Estimated time: 5 hours*

- Runtime threat detection
- Falco rules and alerts
- Host hardening
- Kernel security parameters
- API server hardening
- etcd security
- kubelet security
- **Lab**: Deploy Falco
- **Lab**: Custom Falco rules
- **Lab**: API server hardening

#### [Module 12: Incident Response](docs/12-incident-response.md)
*Estimated time: 4 hours*

- Incident response lifecycle
- Kubernetes forensics
- Audit log analysis
- Container breakout scenarios
- Containment strategies
- Evidence collection
- Post-incident review
- **Lab**: Forensics exercise
- **Lab**: Analyze security incident
- **Lab**: Containment playbook

#### [Module 13: CIS Benchmark and Compliance](docs/13-cis-compliance.md)
*Estimated time: 5 hours*

- CIS Kubernetes Benchmark overview
- kube-bench assessment
- Control plane security
- Worker node security
- Policies and procedures
- Automated remediation
- Compliance reporting
- **Lab**: Run kube-bench
- **Lab**: Remediate findings
- **Lab**: Continuous compliance monitoring

#### [Module 14: Multi-cluster and Federation](docs/14-multi-cluster.md)
*Estimated time: 3 hours*

- Multi-cluster architectures
- Cluster API overview
- Federation patterns
- Cross-cluster networking
- Identity federation
- Disaster recovery strategies
- **Lab**: Multi-cluster setup
- **Lab**: Cross-cluster service discovery

#### [Module 15: Case Studies and Real-World Scenarios](docs/15-case-studies.md)
*Estimated time: 4 hours*

- Case study: Secure on-premises cluster
- Case study: Hybrid Azure/on-prem deployment
- Threat modeling exercise
- Security architecture review
- Cost vs security tradeoffs
- Migration strategies
- **Lab**: Complete security audit
- **Lab**: Threat model workshop

---

## 🎯 Learning Objectives by Track

### Foundation Track
By the end of the foundation track, you will be able to:
- Deploy and manage Kubernetes workloads
- Understand control plane architecture and components
- Configure networking and storage
- Troubleshoot common cluster issues

### Security Track
By the end of the security track, you will be able to:
- Implement authentication and authorization controls
- Apply pod security standards
- Configure admission policies
- Set up observability and audit logging
- Secure the software supply chain

### Advanced Track
By the end of the advanced track, you will be able to:
- Deploy runtime security monitoring
- Respond to security incidents
- Assess compliance with CIS benchmarks
- Design and operate multi-cluster environments
- Conduct security architecture reviews

---

## 📊 Assessment Points

- **Module 01**: Basic Kubernetes concepts quiz
- **Module 02**: Control plane components assessment
- **Module 05**: RBAC practical challenge
- **Module 06**: Pod security configuration challenge
- **Module 09**: Supply chain security exercise
- **Module 13**: CIS benchmark assessment
- **Module 15**: Final capstone project

---

## 🔄 Suggested Learning Paths

### Path 1: Platform Engineer
Focus: Modules 01, 02, 03, 04, 08, 11, 13, 14

### Path 2: Security Engineer
Focus: Modules 05, 06, 07, 09, 10, 11, 12, 13

### Path 3: Full Stack
Complete all modules sequentially

---

## ⏱️ Time Commitments

- **Intensive**: 2 weeks full-time (8 hours/day)
- **Standard**: 6 weeks part-time (3-4 hours/day)
- **Self-paced**: 12 weeks casual (1-2 hours/day)

---

**Total course content**: 65-80 hours including labs and assessments
