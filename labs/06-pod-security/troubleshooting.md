# Lab 06: Pod Security Troubleshooting

## Pod Rejected by Admission Controller

**Symptoms:**
```
Error from server (Forbidden): pods "my-pod" is forbidden: violates PodSecurity "restricted:latest"
```

**Solutions:**
1. Check namespace Pod Security labels:
```bash
kubectl get namespace <namespace> -o yaml | grep pod-security
```

2. Review pod security context:
```bash
kubectl describe pod <pod-name> -n <namespace>
```

3. Apply restricted-compliant configuration:
- Set runAsNonRoot: true
- Drop all capabilities
- Set allowPrivilegeEscalation: false
- Use seccomp profile

## Permission Denied in Read-Only Root Filesystem

**Symptoms:**
```
mkdir: can't create directory '/app/temp': Read-only file system
```

**Solutions:**
Mount emptyDir volumes for writable paths:
```yaml
volumeMounts:
- name: tmp
  mountPath: /tmp
volumes:
- name: tmp
  emptyDir: {}
```

## Container Running as Root

**Symptoms:**
Pod rejected with "must not run as root"

**Solutions:**
Set security context:
```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
```

## Image Doesn't Support Non-Root

**Symptoms:**
Application fails when running as non-root user

**Solutions:**
1. Use unprivileged image variants (e.g., nginx-unprivileged)
2. Modify image to support non-root
3. Request exception (not recommended)

For full troubleshooting, see documentation.
