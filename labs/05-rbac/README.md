# Lab 05: Role-Based Access Control (RBAC)

## Objectives

By the end of this lab, you will:
- Understand Kubernetes RBAC concepts (Roles, RoleBindings, ClusterRoles, ClusterRoleBindings)
- Create ServiceAccounts for applications and users
- Implement least-privilege access control
- Test and verify RBAC permissions
- Debug permission issues
- Implement namespace-specific and cluster-wide access controls

## Prerequisites

- Completed Lab 00: Environment Setup
- Running Kubernetes cluster
- kubectl configured with admin access
- Understanding of Kubernetes API resources

## Estimated Time

60-75 minutes

## RBAC Concepts

**Key Components:**
- **ServiceAccount**: Identity for pods and processes
- **Role**: Namespace-scoped permissions
- **ClusterRole**: Cluster-wide permissions
- **RoleBinding**: Grants Role to users/groups/ServiceAccounts in a namespace
- **ClusterRoleBinding**: Grants ClusterRole cluster-wide

**Permission Model:**
- Deny by default
- Explicitly grant permissions
- Additive (no deny rules)

## Lab Scenario

You need to set up RBAC for multiple personas:
1. **Developer**: Can manage deployments in dev namespace
2. **Viewer**: Read-only access to specific namespaces
3. **CI/CD Pipeline**: Can deploy applications
4. **Cluster Admin**: Full cluster access (already exists)

## Step-by-Step Instructions

### Step 1: Create Namespaces

```bash
# Create namespaces for this lab
kubectl create namespace lab05-rbac
kubectl create namespace dev
kubectl create namespace prod

# Set default namespace
kubectl config set-context --current --namespace=lab05-rbac
```

### Step 2: Create ServiceAccounts

```bash
# Apply ServiceAccount manifests
kubectl apply -f manifests/serviceaccounts.yaml

# Verify ServiceAccounts
kubectl get serviceaccounts -n lab05-rbac
kubectl get serviceaccounts -n dev
kubectl get serviceaccounts -n prod
```

### Step 3: Create Roles for Namespace Access

Create roles with specific permissions.

```bash
# Apply Role manifests
kubectl apply -f manifests/roles.yaml

# View created roles
kubectl get roles -n dev
kubectl get roles -n prod

# Describe a role to see permissions
kubectl describe role developer-role -n dev
```

### Step 4: Create RoleBindings

Bind roles to ServiceAccounts.

```bash
# Apply RoleBinding manifests
kubectl apply -f manifests/rolebindings.yaml

# Verify RoleBindings
kubectl get rolebindings -n dev
kubectl get rolebindings -n prod

# Describe a RoleBinding
kubectl describe rolebinding developer-binding -n dev
```

### Step 5: Test Developer Permissions

Test that developer can perform allowed actions.

```bash
# Test as developer ServiceAccount
kubectl auth can-i create deployments --as=system:serviceaccount:dev:developer -n dev
# Should return: yes

kubectl auth can-i delete deployments --as=system:serviceaccount:dev:developer -n dev
# Should return: yes

kubectl auth can-i delete namespaces --as=system:serviceaccount:dev:developer
# Should return: no

# Create a deployment as developer
kubectl apply -f manifests/test-deployment.yaml -n dev --as=system:serviceaccount:dev:developer
```

### Step 6: Test Viewer Permissions

Test read-only access.

```bash
# Test as viewer ServiceAccount
kubectl auth can-i get pods --as=system:serviceaccount:dev:viewer -n dev
# Should return: yes

kubectl auth can-i list deployments --as=system:serviceaccount:dev:viewer -n dev
# Should return: yes

kubectl auth can-i delete pods --as=system:serviceaccount:dev:viewer -n dev
# Should return: no

kubectl auth can-i create deployments --as=system:serviceaccount:dev:viewer -n dev
# Should return: no
```

### Step 7: Create ClusterRoles for Cluster-Wide Access

```bash
# Apply ClusterRole manifests
kubectl apply -f manifests/clusterroles.yaml

# View ClusterRoles
kubectl get clusterroles | grep lab05

# Describe ClusterRole
kubectl describe clusterrole pod-reader
```

### Step 8: Create ClusterRoleBindings

```bash
# Apply ClusterRoleBinding manifests
kubectl apply -f manifests/clusterrolebindings.yaml

# Verify ClusterRoleBindings
kubectl get clusterrolebindings | grep lab05

# Test cluster-wide viewer access
kubectl auth can-i get pods --all-namespaces --as=system:serviceaccount:lab05-rbac:cluster-viewer
# Should return: yes
```

### Step 9: Create CI/CD ServiceAccount with Deployment Permissions

```bash
# Apply CI/CD ServiceAccount and permissions
kubectl apply -f manifests/cicd-rbac.yaml

# Test CI/CD permissions
kubectl auth can-i create deployments --as=system:serviceaccount:prod:cicd-deployer -n prod
# Should return: yes

kubectl auth can-i create secrets --as=system:serviceaccount:prod:cicd-deployer -n prod
# Should return: yes
```

### Step 10: Use ServiceAccount in Pods

Deploy a pod that uses a ServiceAccount.

```bash
# Apply pod with ServiceAccount
kubectl apply -f manifests/pod-with-sa.yaml

# Verify pod is using ServiceAccount
kubectl get pod rbac-test-pod -o yaml | grep serviceAccount

# Execute commands in pod using its ServiceAccount
kubectl exec -it rbac-test-pod -- sh
# Inside pod:
cat /var/run/secrets/kubernetes.io/serviceaccount/token
ls -la /var/run/secrets/kubernetes.io/serviceaccount/
exit
```

### Step 11: Test Permissions from Within Pod

```bash
# Test API access from within pod
kubectl exec -it rbac-test-pod -- sh

# Inside the pod:
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
NAMESPACE=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)

# Try to list pods (should work if SA has permissions)
curl -k -H "Authorization: Bearer $TOKEN" \
  https://kubernetes.default.svc/api/v1/namespaces/$NAMESPACE/pods

exit
```

### Step 12: Run Permission Audit

```bash
# Run the RBAC audit script
./scripts/rbac-audit.sh
```

This script will:
- List all ServiceAccounts
- Show their RoleBindings and ClusterRoleBindings
- Test key permissions
- Identify overly permissive accounts

### Step 13: Generate kubeconfig for ServiceAccount

Create a kubeconfig file for a ServiceAccount (useful for CI/CD).

```bash
# Generate kubeconfig for CI/CD ServiceAccount
./scripts/generate-kubeconfig.sh cicd-deployer prod

# Test the generated kubeconfig
kubectl --kubeconfig=cicd-deployer-kubeconfig.yaml get pods -n prod
```

### Step 14: Implement Least Privilege

Review and tighten permissions.

```bash
# Check what permissions a ServiceAccount actually needs
kubectl auth can-i --list --as=system:serviceaccount:dev:developer -n dev

# Apply restricted role
kubectl apply -f manifests/developer-role-restricted.yaml
```

### Step 15: Troubleshoot RBAC Issues

```bash
# Debug permission denied errors
kubectl auth can-i create pods --as=system:serviceaccount:dev:viewer -n dev -v=10

# View all permissions for a ServiceAccount
kubectl describe clusterrolebinding | grep -A 5 "system:serviceaccount:dev:developer"
```

## Verification Checklist

- [ ] ServiceAccounts created in appropriate namespaces
- [ ] Roles created with correct permissions
- [ ] RoleBindings correctly associate roles with ServiceAccounts
- [ ] Developer can create/delete deployments in dev namespace
- [ ] Viewer can only read resources, cannot modify
- [ ] CI/CD ServiceAccount can deploy to prod namespace
- [ ] Cluster-wide viewer can read pods in all namespaces
- [ ] ServiceAccounts cannot perform unauthorized actions
- [ ] Pods can use ServiceAccounts to access Kubernetes API

## RBAC Best Practices

1. **Principle of Least Privilege**: Grant minimum necessary permissions
2. **Avoid cluster-admin**: Don't use cluster-admin except when necessary
3. **Namespace Isolation**: Use Roles instead of ClusterRoles when possible
4. **ServiceAccount per Application**: Don't share ServiceAccounts
5. **Regular Audits**: Periodically review and cleanup permissions
6. **Use Groups**: Bind roles to groups rather than individual users
7. **Avoid Wildcards**: Be specific about resources and verbs
8. **Document Permissions**: Maintain documentation of who has what access

## Common RBAC Patterns

### Pattern 1: Read-Only Access
```yaml
rules:
- apiGroups: [""]
  resources: ["pods", "services"]
  verbs: ["get", "list", "watch"]
```

### Pattern 2: Deployment Manager
```yaml
rules:
- apiGroups: ["apps"]
  resources: ["deployments"]
  verbs: ["*"]
```

### Pattern 3: Secret Reader
```yaml
rules:
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get"]
  resourceNames: ["specific-secret"]  # Optional: limit to specific secrets
```

## Common Issues and Solutions

See [troubleshooting.md](./troubleshooting.md) for detailed solutions.

## Cleanup

```bash
# Delete namespaces
kubectl delete namespace lab05-rbac dev prod

# Or use cleanup script
./scripts/cleanup.sh
```

## Key Takeaways

1. **RBAC is deny-by-default**: Must explicitly grant permissions
2. **ServiceAccounts** provide identity for pods and processes
3. **Roles** are namespace-scoped, **ClusterRoles** are cluster-wide
4. **Bindings** connect identities to roles
5. **Least privilege** is critical for security
6. **Regular audits** help maintain security posture
7. **`kubectl auth can-i`** is your friend for testing permissions

## Additional Challenges

1. **Aggregate ClusterRoles**: Create roles that aggregate other roles
2. **User Authentication**: Set up user certificates and test RBAC
3. **RBAC for Custom Resources**: Create RBAC for CRDs
4. **Admission Controllers**: Combine RBAC with admission policies
5. **Audit Logging**: Enable audit logging for RBAC events

## Next Steps

Proceed to **Lab 06: Pod Security Standards** to learn about pod-level security controls.

## Additional Resources

- [RBAC Documentation](https://kubernetes.io/docs/reference/access-authn-authz/rbac/)
- [Configure RBAC for ServiceAccounts](https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/)
- [RBAC Tool](https://github.com/alcideio/rbac-tool)
- [rbac.dev](https://rbac.dev/) - RBAC visualizer
