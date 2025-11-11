# Lab 05: RBAC Troubleshooting

## Permission Denied Errors

**Symptoms:**
```
Error from server (Forbidden): pods is forbidden: User "system:serviceaccount:dev:viewer" cannot create resource "pods"
```

**Solutions:**
1. Check RoleBinding exists and is correct:
```bash
kubectl get rolebinding -n dev
kubectl describe rolebinding viewer-binding -n dev
```

2. Verify Role has required permissions:
```bash
kubectl describe role viewer-role -n dev
```

3. Test specific permission:
```bash
kubectl auth can-i create pods --as=system:serviceaccount:dev:viewer -n dev
```

## ServiceAccount Not Found

**Symptoms:**
```
Error from server (NotFound): serviceaccounts "developer" not found
```

**Solutions:**
```bash
# Verify SA exists
kubectl get sa developer -n dev

# Create if missing
kubectl apply -f manifests/serviceaccounts.yaml
```

## ClusterRole vs Role Confusion

**Issue:** Using ClusterRole for namespace-scoped permissions

**Solution:**
- Use Role for namespace-specific permissions
- Use ClusterRole only for cluster-wide resources

For full troubleshooting guide, see documentation.
