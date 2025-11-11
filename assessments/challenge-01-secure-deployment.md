# Challenge 01: Secure Application Deployment

**Difficulty**: Intermediate  
**Time**: 60 minutes  
**Topics**: Pod security, RBAC, NetworkPolicies

## Scenario

You are tasked with deploying a web application to a production Kubernetes cluster. The application has three tiers:

1. Frontend (NGINX)
2. Backend API (Node.js)
3. Database (PostgreSQL)

The security team has provided requirements that must be met.

## Requirements

### 1. Pod Security
- [ ] All containers must run as non-root
- [ ] Read-only root filesystems where possible
- [ ] Drop all capabilities
- [ ] Apply seccomp RuntimeDefault profile
- [ ] Resource limits configured

### 2. Network Security
- [ ] Default deny all traffic
- [ ] Frontend can receive ingress from internet (port 80/443)
- [ ] Frontend can connect to backend (port 8080)
- [ ] Backend can connect to database (port 5432)
- [ ] All pods can do DNS lookups
- [ ] No other traffic allowed

### 3. Access Control
- [ ] Create service account for each tier
- [ ] Apply least privilege RBAC
- [ ] Disable automounting of default SA token

### 4. Application Configuration
- [ ] Database credentials stored in Secret
- [ ] Configuration in ConfigMap
- [ ] Health checks configured
- [ ] Pod anti-affinity for high availability

## Deliverables

Submit the following YAML manifests:

1. `namespaces.yaml` - Production namespace
2. `network-policies.yaml` - All NetworkPolicies
3. `frontend/` - Frontend deployment and service
4. `backend/` - Backend deployment and service  
5. `database/` - Database statefulset and service
6. `rbac.yaml` - Service accounts and RBAC
7. `secrets.yaml` - Secrets (example values only)
8. `configmaps.yaml` - Configuration data

## Evaluation Criteria (100 points)

**Security (50 points)**
- Pod security contexts configured correctly (15 pts)
- Network policies implement zero-trust (15 pts)
- RBAC follows least privilege (10 pts)
- Secrets not exposed in plain text (10 pts)

**Functionality (30 points)**
- All components deploy successfully (10 pts)
- Services can communicate as designed (10 pts)
- Health checks work (10 pts)

**Best Practices (20 points)**
- Resource limits set (5 pts)
- High availability configured (5 pts)
- Documentation and comments (5 pts)
- Follows Kubernetes naming conventions (5 pts)

## Testing

```bash
# Deploy your solution
kubectl apply -f challenge-01/

# Verify pods are running
kubectl get pods -n production

# Test network policies
kubectl run test-pod --rm -it --image=nicolaka/netshoot -- /bin/bash
# Try connecting to services

# Check RBAC
kubectl auth can-i list pods --as=system:serviceaccount:production:frontend-sa
```

## Hints

- Start with network policies first
- Use labels consistently
- Test each component before integrating
- Review Module 06 (Pod Security) and Module 05 (RBAC)

Solution available in `solutions/challenge-01/`
