# Lab 06: Pod Security Standards

## Objectives

By the end of this lab, you will:
- Understand Kubernetes Pod Security Standards (Privileged, Baseline, Restricted)
- Implement Pod Security Admission controller
- Apply security contexts to pods and containers
- Test pod security enforcement
- Migrate from PodSecurityPolicy to Pod Security Standards
- Implement security best practices at the pod level

## Prerequisites

- Completed Lab 00: Environment Setup
- Running Kubernetes cluster (v1.23+)
- kubectl configured
- Understanding of Pod concepts

## Estimated Time

60-75 minutes

## Pod Security Standards Overview

**Three levels:**
1. **Privileged**: Unrestricted (no restrictions)
2. **Baseline**: Minimally restrictive (prevents known privilege escalations)
3. **Restricted**: Heavily restricted (hardened, best practice)

**Enforcement Modes:**
- **enforce**: Reject non-compliant pods
- **audit**: Log violations but allow pods
- **warn**: Show warnings to users but allow pods

## Lab Scenario

You need to implement pod security standards across different namespaces:
- **Development**: Baseline standard with warnings
- **Production**: Restricted standard with enforcement
- **System**: Privileged for system workloads

## Step-by-Step Instructions

### Step 1: Create Namespaces with Pod Security Labels

```bash
# Create namespaces with Pod Security Standards labels
kubectl apply -f manifests/namespaces.yaml

# Verify namespace labels
kubectl get namespaces lab06-privileged -o yaml | grep -A 5 "labels:"
kubectl get namespaces lab06-baseline -o yaml | grep -A 5 "labels:"
kubectl get namespaces lab06-restricted -o yaml | grep -A 5 "labels:"
```

### Step 2: Test Privileged Namespace

Try deploying various pod configurations to privileged namespace.

```bash
# Deploy privileged pod (should work)
kubectl apply -f manifests/pod-privileged.yaml

# Verify pod is running
kubectl get pod -n lab06-privileged

# Check pod is actually privileged
kubectl exec -n lab06-privileged privileged-pod -- id
kubectl exec -n lab06-privileged privileged-pod -- cat /proc/1/status | grep CapEff
```

### Step 3: Test Baseline Namespace

Baseline prevents most privilege escalations.

```bash
# Try to deploy privileged pod (should be rejected)
kubectl apply -f manifests/pod-privileged.yaml -n lab06-baseline
# Should fail with: Error from server (Forbidden): pods "privileged-pod" is forbidden

# Deploy baseline-compliant pod (should work)
kubectl apply -f manifests/pod-baseline.yaml

# Verify pod is running
kubectl get pod -n lab06-baseline
```

### Step 4: Test Restricted Namespace

Restricted enforces security best practices.

```bash
# Try baseline pod in restricted namespace (should be rejected)
kubectl apply -f manifests/pod-baseline.yaml -n lab06-restricted
# Should fail: violates restricted policy

# Deploy restricted-compliant pod (should work)
kubectl apply -f manifests/pod-restricted.yaml

# Verify pod is running
kubectl get pod -n lab06-restricted

# Verify security settings
kubectl describe pod -n lab06-restricted restricted-pod | grep -A 20 "Security Context"
```

### Step 5: Understanding Security Contexts

Security contexts define privilege and access control settings.

```bash
# Apply examples of different security contexts
kubectl apply -f manifests/security-context-examples.yaml

# Compare pods
kubectl get pods -n lab06-baseline -o yaml | grep -A 20 "securityContext"
```

### Step 6: Test Root vs Non-Root User

```bash
# Try to deploy pod running as root in restricted namespace
kubectl apply -f manifests/pod-as-root.yaml -n lab06-restricted
# Should fail

# Deploy pod as non-root user
kubectl apply -f manifests/pod-nonroot.yaml -n lab06-restricted

# Verify user
kubectl exec -n lab06-restricted nonroot-pod -- id
# Should show uid=1000 or similar, not uid=0
```

### Step 7: Test Capabilities

Linux capabilities provide fine-grained privilege control.

```bash
# Deploy pod with dropped capabilities
kubectl apply -f manifests/pod-drop-capabilities.yaml

# Verify capabilities
kubectl exec -n lab06-restricted pod-drop-caps -- grep Cap /proc/1/status
```

### Step 8: Test Read-Only Root Filesystem

```bash
# Deploy pod with read-only root filesystem
kubectl apply -f manifests/pod-readonly-rootfs.yaml

# Try to write to filesystem (should fail)
kubectl exec -n lab06-restricted readonly-pod -- sh -c 'touch /test.txt' || echo "Write blocked (expected)"

# Verify writable volumes work
kubectl exec -n lab06-restricted readonly-pod -- sh -c 'touch /tmp/test.txt && ls /tmp/test.txt'
```

### Step 9: Run Security Compliance Check

```bash
# Run the security compliance script
./scripts/check-pod-security.sh
```

This script checks:
- Pod Security Standard enforcement
- Running pods compliance
- Security context settings
- Capability usage
- Privilege escalation settings

### Step 10: Audit Mode Testing

```bash
# Create audit namespace
kubectl create namespace lab06-audit
kubectl label namespace lab06-audit \
  pod-security.kubernetes.io/enforce=privileged \
  pod-security.kubernetes.io/audit=restricted \
  pod-security.kubernetes.io/warn=restricted

# Deploy non-compliant pod (will succeed but generate audit log)
kubectl apply -f manifests/pod-baseline.yaml -n lab06-audit

# Check audit logs (if configured)
# kubectl logs -n kube-system <api-server-pod> | grep audit
```

### Step 11: Migrate Deployment to Restricted

Take an existing deployment and make it restricted-compliant.

```bash
# Deploy non-compliant deployment
kubectl apply -f manifests/deployment-insecure.yaml

# Check violations
kubectl get pods -n lab06-restricted

# Apply secured deployment
kubectl apply -f manifests/deployment-secure.yaml

# Verify compliance
kubectl get deployment -n lab06-restricted secure-app -o yaml | grep -A 30 securityContext
```

### Step 12: Test AppArmor and Seccomp Profiles

```bash
# Deploy pod with seccomp profile
kubectl apply -f manifests/pod-seccomp.yaml

# Verify seccomp profile
kubectl describe pod -n lab06-restricted seccomp-pod | grep -i seccomp

# Deploy pod with AppArmor (if available)
kubectl apply -f manifests/pod-apparmor.yaml
```

### Step 13: Implement Least Privilege Checklist

Use this checklist for every pod:

```bash
./scripts/least-privilege-check.sh <namespace> <pod-name>
```

Checks:
- [ ] Runs as non-root user
- [ ] Read-only root filesystem
- [ ] Dropped all capabilities
- [ ] No privilege escalation
- [ ] Resource limits defined
- [ ] Seccomp profile applied
- [ ] No host namespaces used

### Step 14: Compare Security Standards

```bash
# Generate comparison report
./scripts/compare-standards.sh
```

Shows differences between Privileged, Baseline, and Restricted standards.

### Step 15: Production Readiness Review

```bash
# Run production readiness check
./scripts/production-readiness.sh lab06-restricted
```

## Verification Checklist

- [ ] Privileged namespace allows all pod configurations
- [ ] Baseline namespace blocks privileged pods
- [ ] Restricted namespace enforces strict security
- [ ] Pods in restricted namespace run as non-root
- [ ] Read-only root filesystem works with writable volumes
- [ ] Capabilities are dropped in restricted pods
- [ ] Audit mode generates logs for violations
- [ ] Security contexts are properly configured
- [ ] Deployments are compliant with standards

## Pod Security Best Practices

1. **Default to Restricted**: Use restricted standard by default
2. **Non-Root User**: Always run as non-root (runAsNonRoot: true)
3. **Drop Capabilities**: Drop ALL, add only what's needed
4. **Read-Only Root FS**: Use readOnlyRootFilesystem: true
5. **No Privilege Escalation**: Set allowPrivilegeEscalation: false
6. **Seccomp Profile**: Use RuntimeDefault or custom profile
7. **Resource Limits**: Always define CPU and memory limits
8. **No Host Namespaces**: Avoid hostNetwork, hostPID, hostIPC

## Pod Security Standard Requirements

### Baseline Standard
- No privileged containers
- No hostPath volumes
- No host namespaces (network, PID, IPC)
- No hostPorts
- Limited capabilities
- No privilege escalation

### Restricted Standard
All Baseline requirements, plus:
- Must run as non-root user
- Must drop ALL capabilities
- Seccomp profile required
- Limited volume types
- No privilege escalation
- Read-only root filesystem recommended

## Common Issues and Solutions

See [troubleshooting.md](./troubleshooting.md) for detailed solutions.

## Cleanup

```bash
# Delete namespaces
kubectl delete namespace lab06-privileged lab06-baseline lab06-restricted lab06-audit

# Or use cleanup script
./scripts/cleanup.sh
```

## Key Takeaways

1. **Pod Security Standards** provide built-in security policies
2. **Three levels** offer flexibility for different use cases
3. **Enforcement modes** allow gradual migration
4. **Security contexts** are critical for pod security
5. **Restricted standard** represents best practices
6. **Audit mode** helps identify violations before enforcing
7. **PSS replaces PSP** (PodSecurityPolicy) in modern Kubernetes

## Additional Challenges

1. **Custom Security Profiles**: Create custom AppArmor/Seccomp profiles
2. **OPA/Gatekeeper**: Implement custom policies with OPA
3. **Admission Webhooks**: Build custom admission controller
4. **Security Scanning**: Integrate with image scanning tools
5. **Policy Enforcement**: Implement CI/CD policy checks

## Next Steps

Proceed to **Lab 09: Image Scanning and Signing** to learn about supply chain security.

## Additional Resources

- [Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [Pod Security Admission](https://kubernetes.io/docs/concepts/security/pod-security-admission/)
- [Security Context](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [Seccomp](https://kubernetes.io/docs/tutorials/security/seccomp/)
- [AppArmor](https://kubernetes.io/docs/tutorials/security/apparmor/)
