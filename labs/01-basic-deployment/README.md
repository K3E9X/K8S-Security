# Lab 01: Basic Deployment and Service Exposure

## Objectives

By the end of this lab, you will:
- Deploy a containerized application to Kubernetes
- Understand Pod, Deployment, and Service resources
- Expose applications using different Service types
- Perform basic security checks on deployments
- Understand the security implications of service exposure

## Prerequisites

- Completed Lab 00: Environment Setup
- Running Kubernetes cluster
- kubectl configured and connected to your cluster
- Basic understanding of containers and Kubernetes concepts

## Estimated Time

45-60 minutes

## Lab Scenario

You are tasked with deploying a simple web application to your Kubernetes cluster. You need to ensure the application is:
- Highly available (multiple replicas)
- Accessible from outside the cluster
- Following basic security practices

## Step-by-Step Instructions

### Step 1: Create a Namespace

Namespaces provide logical isolation for resources.

```bash
# Create a namespace for this lab
kubectl create namespace lab01-basic-deployment

# Set this namespace as default for subsequent commands
kubectl config set-context --current --namespace=lab01-basic-deployment

# Verify namespace creation
kubectl get namespaces
```

### Step 2: Deploy a Simple Application

We'll deploy an nginx web server as our sample application.

```bash
# Create a deployment using kubectl
kubectl create deployment web-app \
  --image=nginx:1.25-alpine \
  --replicas=3 \
  --port=80

# Watch the deployment rollout
kubectl rollout status deployment/web-app

# View the deployment
kubectl get deployments
kubectl describe deployment web-app
```

**Review the deployment details:**
- Number of replicas
- Container image
- Labels and selectors
- Deployment strategy

### Step 3: Understanding Pods

Deployments create Pods to run your application.

```bash
# List all pods
kubectl get pods

# Get detailed information about pods
kubectl get pods -o wide

# Describe a specific pod (replace POD_NAME)
kubectl describe pod <POD_NAME>

# View pod logs
kubectl logs <POD_NAME>

# Execute a command in a pod
kubectl exec -it <POD_NAME> -- /bin/sh
# Inside the pod:
whoami
hostname
ps aux
exit
```

### Step 4: Apply Declarative Configuration

Instead of imperative commands, use YAML manifests for better reproducibility.

```bash
# Apply the improved deployment manifest
kubectl apply -f manifests/web-app-deployment.yaml

# View the changes
kubectl get deployment web-app -o yaml
```

### Step 5: Create a ClusterIP Service

ClusterIP is the default service type, providing internal cluster access only.

```bash
# Create a ClusterIP service
kubectl apply -f manifests/web-app-service-clusterip.yaml

# View the service
kubectl get service web-app-clusterip
kubectl describe service web-app-clusterip

# Get the service endpoints
kubectl get endpoints web-app-clusterip
```

### Step 6: Test Internal Access

```bash
# Create a temporary pod to test internal access
kubectl run test-pod --image=busybox:1.36 -it --rm --restart=Never -- sh

# Inside the test pod:
wget -qO- http://web-app-clusterip
wget -qO- http://web-app-clusterip.lab01-basic-deployment.svc.cluster.local
exit
```

### Step 7: Expose with NodePort Service

NodePort exposes the service on each node's IP at a static port.

```bash
# Create a NodePort service
kubectl apply -f manifests/web-app-service-nodeport.yaml

# View the NodePort service
kubectl get service web-app-nodeport
```

**For kind clusters:**
```bash
# Get the node port
NODE_PORT=$(kubectl get service web-app-nodeport -o jsonpath='{.spec.ports[0].nodePort}')
echo "NodePort: $NODE_PORT"

# Access via localhost (kind exposes ports)
curl http://localhost:$NODE_PORT
```

**For minikube:**
```bash
minikube service web-app-nodeport -n lab01-basic-deployment
```

### Step 8: Expose with LoadBalancer Service (Cloud/MetalLB)

LoadBalancer service type provisions a load balancer (cloud or MetalLB).

```bash
# Create a LoadBalancer service
kubectl apply -f manifests/web-app-service-loadbalancer.yaml

# View the LoadBalancer service
kubectl get service web-app-loadbalancer

# For kind/k3d, you may need MetalLB or port-forwarding
# For minikube, use minikube tunnel in another terminal
```

**For minikube:**
```bash
# In a separate terminal, run:
minikube tunnel

# Then access the EXTERNAL-IP shown in:
kubectl get service web-app-loadbalancer
```

### Step 9: Security Analysis - Current State

Let's analyze the security posture of our deployment.

```bash
# Run the security check script
./scripts/security-check.sh
```

This will check for:
- Container running as root
- No resource limits
- No security context
- Privileged containers
- Host network usage

### Step 10: Apply Security Hardening

Now apply security best practices.

```bash
# Apply the hardened deployment
kubectl apply -f manifests/web-app-deployment-secure.yaml

# Watch the rolling update
kubectl rollout status deployment/web-app

# Verify the security improvements
kubectl get deployment web-app -o yaml | grep -A 10 securityContext
```

### Step 11: Verify Security Improvements

```bash
# Check that pods are running as non-root
kubectl exec <POD_NAME> -- id

# Verify resource limits
kubectl describe pod <POD_NAME> | grep -A 5 "Limits:"

# Run security check again
./scripts/security-check.sh
```

### Step 12: Test Application Functionality

Ensure the hardened deployment still works correctly.

```bash
# Test internal access
kubectl run test-pod --image=busybox:1.36 -it --rm --restart=Never -- \
  wget -qO- http://web-app-clusterip

# Test NodePort access
curl http://localhost:$NODE_PORT
```

### Step 13: Scale the Deployment

```bash
# Scale up
kubectl scale deployment web-app --replicas=5

# Watch the scaling
kubectl get pods -w
# Press Ctrl+C to stop watching

# Scale down
kubectl scale deployment web-app --replicas=3
```

### Step 14: Update the Application

Perform a rolling update.

```bash
# Update the image version
kubectl set image deployment/web-app nginx=nginx:1.26-alpine

# Watch the rollout
kubectl rollout status deployment/web-app

# Check rollout history
kubectl rollout history deployment/web-app

# If needed, rollback
# kubectl rollout undo deployment/web-app
```

### Step 15: Explore Service Discovery

```bash
# View service DNS records
kubectl run dns-test --image=busybox:1.36 -it --rm --restart=Never -- \
  nslookup web-app-clusterip

# View environment variables for service discovery
kubectl exec <POD_NAME> -- env | grep WEB_APP
```

## Verification Checklist

- [ ] Namespace `lab01-basic-deployment` exists
- [ ] Deployment `web-app` has 3 replicas running
- [ ] All pods are in Running state and Ready
- [ ] ClusterIP service is accessible from within cluster
- [ ] NodePort service is accessible from host machine
- [ ] Security context is applied (non-root user)
- [ ] Resource limits are defined
- [ ] Application responds correctly to HTTP requests
- [ ] Rolling updates work without downtime

## Security Best Practices Demonstrated

1. **Non-root user**: Containers run as non-root user (UID 101)
2. **Read-only root filesystem**: Prevents runtime modifications
3. **Resource limits**: CPU and memory limits prevent resource exhaustion
4. **Drop capabilities**: Removed unnecessary Linux capabilities
5. **No privilege escalation**: Prevent container from gaining additional privileges
6. **Service isolation**: Using namespaces for logical separation

## Common Issues and Solutions

See [troubleshooting.md](./troubleshooting.md) for detailed solutions.

## Cleanup

To clean up this lab:

```bash
# Delete all resources in the namespace
kubectl delete namespace lab01-basic-deployment

# Or use the cleanup script
./scripts/cleanup.sh
```

## Key Takeaways

1. **Deployments** provide declarative updates and rollback capabilities
2. **Services** enable stable networking and service discovery
3. **Service types** (ClusterIP, NodePort, LoadBalancer) serve different use cases
4. **Security contexts** are essential for container security
5. **Resource limits** prevent resource exhaustion attacks
6. **Namespaces** provide logical isolation and access control boundaries

## Additional Challenges

If you finish early, try these challenges:

1. **Add Health Checks**: Implement liveness and readiness probes
2. **ConfigMap**: Externalize nginx configuration using ConfigMap
3. **Ingress**: Set up an Ingress resource for HTTP routing
4. **Multiple Services**: Deploy a frontend and backend application
5. **Network Policy**: Restrict traffic between pods (preview for Lab 03)

## Next Steps

Proceed to **Lab 03: Network Policies** to learn how to control network traffic between pods.

## Additional Resources

- [Kubernetes Deployments](https://kubernetes.io/docs/concepts/workloads/controllers/deployment/)
- [Kubernetes Services](https://kubernetes.io/docs/concepts/services-networking/service/)
- [Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [Resource Management](https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/)
