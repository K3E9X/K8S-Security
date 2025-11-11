# Lab 03: Network Policies for Network Segmentation

## Objectives

By the end of this lab, you will:
- Understand Kubernetes network policies and their importance
- Implement network segmentation using NetworkPolicies
- Create ingress and egress rules to control pod-to-pod communication
- Implement a zero-trust network model
- Troubleshoot network connectivity issues

## Prerequisites

- Completed Lab 00 and Lab 01
- Running Kubernetes cluster with CNI that supports NetworkPolicies
- kubectl configured
- Understanding of network basics (IP, ports, protocols)

## Estimated Time

60-75 minutes

## Lab Scenario

You are deploying a three-tier application (frontend, backend, database) and need to implement network segmentation to:
- Allow only frontend to communicate with backend
- Allow only backend to communicate with database
- Deny all other traffic by default (zero-trust)
- Allow DNS resolution for all pods

## Network Policy Concepts

**Key Principles:**
- By default, all pods can communicate with all other pods
- NetworkPolicies are additive (multiple policies combine)
- Empty selector `{}` matches all pods
- NetworkPolicies are namespaced
- Require CNI support (Calico, Cilium, Weave, etc.)

## Step-by-Step Instructions

### Step 1: Create Namespace and Verify CNI Support

```bash
# Create namespace
kubectl create namespace lab03-netpol

# Set as default
kubectl config set-context --current --namespace=lab03-netpol

# Check if NetworkPolicy API is available
kubectl api-resources | grep networkpolicies
```

### Step 2: Deploy Three-Tier Application

Deploy frontend, backend, and database components.

```bash
# Deploy all application components
kubectl apply -f manifests/database.yaml
kubectl apply -f manifests/backend.yaml
kubectl apply -f manifests/frontend.yaml

# Wait for pods to be ready
kubectl wait --for=condition=ready pod --all --timeout=120s

# Verify all pods are running
kubectl get pods -o wide
```

### Step 3: Test Connectivity Without Network Policies

Test that all pods can communicate (default behavior).

```bash
# Get pod IPs
kubectl get pods -o wide

# Test frontend → backend (should work)
kubectl exec -it deploy/frontend -- curl -s http://backend:8080/api/health

# Test frontend → database (should work, but shouldn't!)
kubectl exec -it deploy/frontend -- nc -zv database 5432

# Test backend → database (should work)
kubectl exec -it deploy/backend -- nc -zv database 5432
```

**Result:** All connections work because there are no network restrictions.

### Step 4: Implement Default Deny Policy

Start with a zero-trust approach: deny all traffic by default.

```bash
# Apply default deny policy
kubectl apply -f manifests/default-deny-all.yaml

# Verify the policy
kubectl get networkpolicies
kubectl describe networkpolicy default-deny-all
```

### Step 5: Test Connectivity After Default Deny

```bash
# Test frontend → backend (should fail)
kubectl exec -it deploy/frontend -- timeout 5 curl -s http://backend:8080/api/health || echo "Connection denied (expected)"

# Test DNS (should fail)
kubectl exec -it deploy/frontend -- timeout 5 nslookup backend || echo "DNS failed (needs fix)"
```

**Result:** All connections fail (including DNS).

### Step 6: Allow DNS for All Pods

DNS is required for service discovery.

```bash
# Apply DNS policy
kubectl apply -f manifests/allow-dns.yaml

# Test DNS now works
kubectl exec -it deploy/frontend -- nslookup backend
```

### Step 7: Allow Frontend → Backend Traffic

```bash
# Apply backend network policy (allows ingress from frontend)
kubectl apply -f manifests/backend-netpol.yaml

# Test frontend → backend (should work now)
kubectl exec -it deploy/frontend -- curl -s http://backend:8080/api/health

# Test frontend → database (should still fail)
kubectl exec -it deploy/frontend -- timeout 5 nc -zv database 5432 || echo "Blocked (expected)"
```

### Step 8: Allow Backend → Database Traffic

```bash
# Apply database network policy (allows ingress from backend only)
kubectl apply -f manifests/database-netpol.yaml

# Test backend → database (should work)
kubectl exec -it deploy/backend -- nc -zv database 5432

# Test frontend → database (should still fail)
kubectl exec -it deploy/frontend -- timeout 5 nc -zv database 5432 || echo "Blocked (expected)"
```

### Step 9: Implement Egress Rules

Control outbound traffic from pods.

```bash
# Apply egress policy for frontend
kubectl apply -f manifests/frontend-netpol-egress.yaml

# Test frontend can reach backend
kubectl exec -it deploy/frontend -- curl -s http://backend:8080/api/health

# Test frontend cannot reach external internet (if configured)
kubectl exec -it deploy/frontend -- timeout 5 curl -s https://google.com || echo "External blocked"
```

### Step 10: Verify Network Segmentation

Run the comprehensive verification script:

```bash
./scripts/test-connectivity.sh
```

This script tests all connectivity paths and verifies:
- ✓ Frontend can reach backend
- ✓ Backend can reach database
- ✗ Frontend cannot reach database directly
- ✓ DNS works for all pods
- ✓ Network policies are correctly applied

### Step 11: Visualize Network Policies

```bash
# List all network policies
kubectl get networkpolicies

# Describe each policy
kubectl describe networkpolicy backend-allow-frontend
kubectl describe networkpolicy database-allow-backend
kubectl describe networkpolicy default-deny-all

# View policy YAML
kubectl get networkpolicy backend-allow-frontend -o yaml
```

### Step 12: Test Policy Enforcement

Create a test pod that shouldn't have access:

```bash
# Create unauthorized pod
kubectl run unauthorized-pod --image=nicolaka/netshoot --rm -it -- bash

# Inside the pod, try to access database (should fail)
nc -zv database 5432

# Try to access backend (should fail)
curl http://backend:8080/api/health

exit
```

### Step 13: Allow Specific External Access

Allow backend to access external API (example: 8.8.8.8 for DNS).

```bash
# Apply egress policy for backend with external access
kubectl apply -f manifests/backend-netpol-egress-external.yaml

# Test external connectivity
kubectl exec -it deploy/backend -- curl -s https://api.example.com
```

### Step 14: Monitoring and Logging

```bash
# View network policy events
kubectl get events -n lab03-netpol

# Check for policy-related errors
kubectl logs -l app=backend --tail=50

# If using Calico, view policy rules
# calicoctl get networkpolicies --output yaml
```

## Verification Checklist

- [ ] Three-tier application deployed (frontend, backend, database)
- [ ] Default deny-all policy applied
- [ ] DNS resolution works for all pods
- [ ] Frontend can communicate with backend
- [ ] Backend can communicate with database
- [ ] Frontend CANNOT communicate with database directly
- [ ] Unauthorized pods cannot access any services
- [ ] All NetworkPolicies show as active
- [ ] Application functionality works end-to-end

## Network Policy Best Practices

1. **Default Deny**: Start with deny-all, then explicitly allow
2. **Principle of Least Privilege**: Allow only necessary connections
3. **Label Selectors**: Use meaningful labels for policy targeting
4. **DNS Access**: Always allow DNS (port 53) for service discovery
5. **Monitoring**: Monitor and log denied connections
6. **Documentation**: Document the intended traffic flows
7. **Testing**: Test policies before applying to production

## Common Issues and Solutions

See [troubleshooting.md](./troubleshooting.md) for detailed solutions.

## Cleanup

```bash
# Delete namespace
kubectl delete namespace lab03-netpol

# Or use cleanup script
./scripts/cleanup.sh
```

## Key Takeaways

1. **NetworkPolicies** provide microsegmentation within clusters
2. **Zero-trust model**: Deny by default, allow explicitly
3. **Label selectors** are key to policy targeting
4. **CNI support** is required for NetworkPolicies
5. **DNS must be allowed** for service discovery
6. **Policies are additive**: Multiple policies combine
7. **Namespace isolation** can be enforced with policies

## Additional Challenges

1. **Monitoring**: Set up policy violation alerts
2. **Namespace Isolation**: Prevent cross-namespace communication
3. **External Traffic**: Implement egress filtering for external APIs
4. **CIDR Blocks**: Use IP CIDR blocks for external services
5. **Policy Testing**: Create automated tests for policy enforcement

## Next Steps

Proceed to **Lab 05: RBAC (Role-Based Access Control)** to learn about authentication and authorization.

## Additional Resources

- [Network Policies Documentation](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [Network Policy Recipes](https://github.com/ahmetb/kubernetes-network-policy-recipes)
- [Calico Network Policy](https://docs.projectcalico.org/security/kubernetes-network-policy)
- [Cilium Network Policy](https://docs.cilium.io/en/stable/policy/)
