# Lab Solutions

This directory contains reference solutions and answer keys for the hands-on labs.

## Important Note

**Try to complete each lab independently before consulting these solutions.**

The solutions are provided as:
1. Reference implementations
2. Troubleshooting aids
3. Learning resources

## Solution Structure

Each lab solution includes:
- Completed manifests
- Working scripts
- Explanation of key concepts
- Common pitfalls and how to avoid them

## Using Solutions

### When to Use Solutions

✅ **Appropriate use cases:**
- Stuck after genuine troubleshooting attempts
- Verifying your approach is correct
- Learning alternative implementations
- Understanding why something works

❌ **Avoid using solutions for:**
- Skipping the learning process
- Copy-pasting without understanding
- Avoiding troubleshooting
- First attempt at labs

### How to Use Solutions

1. **Try first**: Attempt the lab on your own
2. **Troubleshoot**: Use the lab's troubleshooting guide
3. **Compare**: Check your solution against the reference
4. **Understand**: Don't just copy - understand why it works
5. **Practice**: Try variations and experiments

## Solutions Available

### Lab 00: Environment Setup
**Location:** Covered in main setup scripts
**Key Points:**
- Cluster creation patterns
- Verification approaches
- Common setup issues

### Lab 01: Basic Deployment
**Key Concepts:**
- Deployment strategies
- Security context patterns
- Resource management
- Service exposure methods

**Reference Files:**
- Complete secure deployment manifests
- Security check scripts
- Progressive hardening examples

### Lab 03: Network Policies
**Key Concepts:**
- Default deny patterns
- Label selector strategies
- DNS policy requirements
- Egress/ingress rule design

**Reference Files:**
- Complete policy sets
- Testing methodologies
- Multi-tier application policies

### Lab 05: RBAC
**Key Concepts:**
- Principle of least privilege
- ServiceAccount design
- Role vs ClusterRole decisions
- Permission testing strategies

**Reference Files:**
- Complete RBAC configurations
- Permission audit scripts
- Real-world persona examples

### Lab 06: Pod Security
**Key Concepts:**
- Security standard progression
- Non-root user configuration
- Capability management
- Volume requirements for read-only root

**Reference Files:**
- Compliant pod specifications
- Migration strategies
- Security validation scripts

### Lab 09: Image Scanning
**Key Concepts:**
- Scanning workflow integration
- Vulnerability assessment
- Image signing practices
- CI/CD pipeline integration

**Reference Files:**
- Complete scanning pipelines
- Signing workflows
- Automation examples

## Additional Resources

### Common Patterns

#### Secure Deployment Template
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: secure-app
spec:
  replicas: 2
  selector:
    matchLabels:
      app: secure-app
  template:
    metadata:
      labels:
        app: secure-app
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 1000
        seccompProfile:
          type: RuntimeDefault
      containers:
      - name: app
        image: myapp:latest
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          runAsNonRoot: true
          runAsUser: 1000
          capabilities:
            drop:
              - ALL
        resources:
          requests:
            memory: "64Mi"
            cpu: "100m"
          limits:
            memory: "128Mi"
            cpu: "200m"
```

#### Network Policy Template
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: app-policy
spec:
  podSelector:
    matchLabels:
      app: myapp
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: allowed-source
    ports:
    - protocol: TCP
      port: 8080
  egress:
  - to:
    - podSelector:
        matchLabels:
          app: allowed-dest
    ports:
    - protocol: TCP
      port: 5432
```

### Best Practices Checklist

Use this checklist when reviewing solutions:

**Security Context:**
- [ ] runAsNonRoot: true
- [ ] readOnlyRootFilesystem: true
- [ ] allowPrivilegeEscalation: false
- [ ] Capabilities dropped
- [ ] Seccomp profile set

**Resources:**
- [ ] Requests defined
- [ ] Limits defined
- [ ] Appropriate values

**Networking:**
- [ ] NetworkPolicies applied
- [ ] Default deny in place
- [ ] DNS access allowed

**RBAC:**
- [ ] Least privilege
- [ ] Specific permissions
- [ ] ServiceAccount per app

**Images:**
- [ ] Scanned for vulnerabilities
- [ ] Signed images
- [ ] Minimal base image

## Learning Path

1. **Compare implementations**: Look at different approaches
2. **Understand trade-offs**: Why certain choices were made
3. **Experiment**: Try variations
4. **Document learnings**: Keep notes on what you learned

## Common Mistakes

### 1. Over-Permissive RBAC
❌ **Wrong:**
```yaml
rules:
- apiGroups: ["*"]
  resources: ["*"]
  verbs: ["*"]
```

✅ **Correct:**
```yaml
rules:
- apiGroups: ["apps"]
  resources: ["deployments"]
  verbs: ["get", "list", "create", "update"]
```

### 2. Missing Security Context
❌ **Wrong:**
```yaml
spec:
  containers:
  - name: app
    image: myapp
```

✅ **Correct:**
```yaml
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
  containers:
  - name: app
    image: myapp
    securityContext:
      allowPrivilegeEscalation: false
      capabilities:
        drop: ["ALL"]
```

### 3. No Network Policies
❌ **Wrong:** Deploying without NetworkPolicies

✅ **Correct:** Always apply default deny + specific allow policies

### 4. Not Using Manifests
❌ **Wrong:** Only using imperative kubectl commands

✅ **Correct:** Use declarative YAML manifests for repeatability

## Getting the Most from Solutions

1. **Read the explanations**: Understand the "why"
2. **Test variations**: What happens if you change something?
3. **Break things**: Learn by seeing what fails
4. **Fix without looking**: Try to fix issues before checking solutions
5. **Share learnings**: Discuss with others

## Additional Practice

After reviewing solutions, try:

1. **Implement from scratch**: Without looking at solutions
2. **Add requirements**: Extend the labs with new requirements
3. **Optimize**: Make solutions more efficient or secure
4. **Automate**: Create scripts to deploy full solutions
5. **Document**: Write your own explanations

## Contributing Solutions

Have a better approach? Found an issue? Contribute!

1. Test thoroughly
2. Document clearly
3. Include explanations
4. Submit pull request

---

Remember: **The goal is learning, not just completion.** Take your time to understand each solution thoroughly.
