# Lab 03: Network Policies Troubleshooting

## CNI Not Supporting Network Policies

**Symptoms:**
NetworkPolicies are created but have no effect.

**Solutions:**
1. Check CNI support: kind (kindnet - partial), k3d (no support), minikube (depends on CNI)
2. Install Calico for full support:
```bash
kubectl apply -f https://docs.projectcalico.org/manifests/calico.yaml
```

## DNS Not Working

**Symptoms:**
Cannot resolve service names after applying policies.

**Solutions:**
Ensure DNS egress is allowed:
```bash
kubectl apply -f manifests/allow-dns.yaml
```

## Connection Timeout

**Symptoms:**
Connections hang or timeout instead of being refused.

**Solutions:**
This is expected behavior - NetworkPolicies drop packets silently.
Use shorter timeouts:
```bash
kubectl exec deploy/frontend -- timeout 3 nc -zv database 5432
```

## All Connections Blocked

**Symptoms:**
No connectivity after applying policies.

**Solutions:**
1. Check if default-deny-all was applied
2. Apply specific allow policies
3. Verify label selectors match pods:
```bash
kubectl get pods --show-labels -n lab03-netpol
```

For more issues, see the full troubleshooting guide.
