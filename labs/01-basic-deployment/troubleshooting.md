# Lab 01: Troubleshooting Guide

## Common Issues and Solutions

### Deployment Issues

#### Pods not starting

**Symptoms:**
```
NAME                       READY   STATUS             RESTARTS   AGE
web-app-xxx-yyy           0/1     CrashLoopBackOff   5          3m
```

**Solutions:**

1. Check pod logs:
```bash
kubectl logs <POD_NAME> -n lab01-basic-deployment
```

2. Check pod events:
```bash
kubectl describe pod <POD_NAME> -n lab01-basic-deployment
```

3. Common causes:
   - Image pull errors
   - Application crashes
   - Missing dependencies
   - Configuration errors

#### ImagePullBackOff errors

**Symptoms:**
```
Events:
  Failed to pull image "nginx:1.25-alpine": rpc error: code = Unknown desc = Error response from daemon: Get https://registry-1.docker.io/v2/: net/http: request canceled
```

**Solutions:**

1. Verify image name and tag:
```bash
docker pull nginx:1.25-alpine
```

2. Check network connectivity:
```bash
curl -I https://registry.hub.docker.com
```

3. If using private registry, ensure imagePullSecrets are configured

#### Pods stuck in Pending

**Symptoms:**
```
NAME                       READY   STATUS    RESTARTS   AGE
web-app-xxx-yyy           0/1     Pending   0          5m
```

**Solutions:**

1. Check pod events:
```bash
kubectl describe pod <POD_NAME> -n lab01-basic-deployment
```

2. Common causes:
   - Insufficient cluster resources
   - Node selector not matching any nodes
   - Resource limits too high

3. Check node resources:
```bash
kubectl top nodes
kubectl describe nodes
```

4. Check resource requests:
```bash
kubectl get deployment web-app -n lab01-basic-deployment -o yaml | grep -A 5 resources
```

### Service Issues

#### Service not accessible

**Symptoms:**
- Cannot connect to service
- Connection timeout
- Connection refused

**Solutions:**

1. Verify service exists:
```bash
kubectl get service -n lab01-basic-deployment
```

2. Check service endpoints:
```bash
kubectl get endpoints web-app-clusterip -n lab01-basic-deployment
```

If endpoints list is empty, check:
- Pod labels match service selector
- Pods are running and ready

3. Verify service selector:
```bash
kubectl describe service web-app-clusterip -n lab01-basic-deployment
kubectl get pods -n lab01-basic-deployment --show-labels
```

4. Test from within cluster:
```bash
kubectl run test-pod --image=busybox:1.36 -it --rm --restart=Never -n lab01-basic-deployment -- \
  wget -qO- http://web-app-clusterip
```

#### NodePort not accessible

**Symptoms:**
- Cannot access service via NodePort from host

**Solutions:**

1. Get the NodePort:
```bash
kubectl get service web-app-nodeport -n lab01-basic-deployment
```

2. For kind:
```bash
# Check if port mapping is configured in kind config
docker ps | grep kind

# Access via localhost
curl http://localhost:<NODE_PORT>
```

3. For minikube:
```bash
# Get minikube IP
minikube ip

# Access service
curl http://$(minikube ip):<NODE_PORT>

# Or use minikube service command
minikube service web-app-nodeport -n lab01-basic-deployment
```

4. Check firewall rules:
```bash
# Linux
sudo iptables -L -n | grep <NODE_PORT>

# macOS/Windows - check Docker Desktop settings
```

#### LoadBalancer stuck in Pending

**Symptoms:**
```
NAME                    TYPE           CLUSTER-IP      EXTERNAL-IP   PORT(S)
web-app-loadbalancer    LoadBalancer   10.96.xxx.xxx   <pending>     80:xxxxx/TCP
```

**Solutions:**

1. **For kind**: LoadBalancer requires MetalLB or similar
```bash
# Install MetalLB (optional)
kubectl apply -f https://raw.githubusercontent.com/metallb/metallb/v0.13.12/config/manifests/metallb-native.yaml
```

2. **For k3d**: LoadBalancer works by default

3. **For minikube**: Use minikube tunnel
```bash
# In a separate terminal
minikube tunnel
```

4. **For cloud providers**: Check provider-specific configuration

5. **Workaround**: Use port-forward
```bash
kubectl port-forward service/web-app-loadbalancer 8080:80 -n lab01-basic-deployment
```

### Security Context Issues

#### Permission denied errors with secure deployment

**Symptoms:**
```
nginx: [emerg] mkdir() "/var/cache/nginx/client_temp" failed (13: Permission denied)
```

**Solutions:**

This happens when using readOnlyRootFilesystem without providing writable volumes.

1. Verify volumes are mounted:
```bash
kubectl describe pod <POD_NAME> -n lab01-basic-deployment | grep -A 10 "Mounts:"
```

2. The secure deployment manifest includes necessary volumes:
   - /var/cache/nginx → emptyDir
   - /var/run → emptyDir
   - /tmp → emptyDir

3. If still failing, check pod logs:
```bash
kubectl logs <POD_NAME> -n lab01-basic-deployment
```

#### Container runs as root despite securityContext

**Symptoms:**
```bash
$ kubectl exec <POD_NAME> -- id
uid=0(root) gid=0(root)
```

**Solutions:**

1. Verify securityContext is applied:
```bash
kubectl get pod <POD_NAME> -n lab01-basic-deployment -o yaml | grep -A 10 securityContext
```

2. Check both pod-level and container-level securityContext

3. Some images override the user in Dockerfile:
```dockerfile
# Image might have:
USER root
```

4. Use numeric UID instead of username:
```yaml
securityContext:
  runAsUser: 101  # numeric UID
  runAsNonRoot: true
```

#### OOMKilled errors

**Symptoms:**
```
NAME                       READY   STATUS      RESTARTS   AGE
web-app-xxx-yyy           0/1     OOMKilled   3          2m
```

**Solutions:**

1. Check resource limits:
```bash
kubectl describe pod <POD_NAME> -n lab01-basic-deployment | grep -A 5 "Limits:"
```

2. Increase memory limits:
```yaml
resources:
  limits:
    memory: "256Mi"  # Increase from 128Mi
```

3. Check actual memory usage:
```bash
kubectl top pod <POD_NAME> -n lab01-basic-deployment
```

### Health Probe Issues

#### Pods restarting due to liveness probe

**Symptoms:**
```
NAME                       READY   STATUS    RESTARTS   AGE
web-app-xxx-yyy           1/1     Running   10         5m
```

**Solutions:**

1. Check probe configuration:
```bash
kubectl describe pod <POD_NAME> -n lab01-basic-deployment | grep -A 5 "Liveness:"
```

2. Common issues:
   - initialDelaySeconds too short
   - Application slow to start
   - Probe endpoint incorrect

3. Adjust timing:
```yaml
livenessProbe:
  initialDelaySeconds: 30  # Increase
  periodSeconds: 10
  timeoutSeconds: 5
  failureThreshold: 3
```

4. Test probe endpoint manually:
```bash
kubectl exec <POD_NAME> -n lab01-basic-deployment -- wget -qO- http://localhost:80/
```

#### Service not receiving traffic despite ready pods

**Symptoms:**
- Pods show as Ready
- Service endpoints are populated
- But traffic doesn't reach pods

**Solutions:**

1. Check readiness probe:
```bash
kubectl describe pod <POD_NAME> -n lab01-basic-deployment | grep -A 5 "Readiness:"
```

2. Verify endpoint readiness:
```bash
kubectl get endpoints web-app-clusterip -n lab01-basic-deployment -o yaml
```

3. Check service port mapping:
```bash
kubectl describe service web-app-clusterip -n lab01-basic-deployment
```

### Namespace Issues

#### Resources not found

**Symptoms:**
```
Error from server (NotFound): deployments.apps "web-app" not found
```

**Solutions:**

1. Check current namespace:
```bash
kubectl config view --minify | grep namespace
```

2. Specify namespace explicitly:
```bash
kubectl get deployment web-app -n lab01-basic-deployment
```

3. Set default namespace:
```bash
kubectl config set-context --current --namespace=lab01-basic-deployment
```

4. Verify namespace exists:
```bash
kubectl get namespaces | grep lab01
```

### Scaling Issues

#### New pods not starting when scaling up

**Symptoms:**
```bash
$ kubectl scale deployment web-app --replicas=10
# Only 3 pods running instead of 10
```

**Solutions:**

1. Check cluster capacity:
```bash
kubectl top nodes
kubectl describe nodes
```

2. Check for resource constraints:
```bash
kubectl describe deployment web-app -n lab01-basic-deployment
```

3. Look for pod events:
```bash
kubectl get events -n lab01-basic-deployment --sort-by='.lastTimestamp'
```

### Rolling Update Issues

#### Update stuck or failing

**Symptoms:**
```bash
$ kubectl rollout status deployment/web-app
Waiting for deployment "web-app" rollout to finish: 1 old replicas are pending termination...
```

**Solutions:**

1. Check rollout history:
```bash
kubectl rollout history deployment/web-app -n lab01-basic-deployment
```

2. Check pod events:
```bash
kubectl get events -n lab01-basic-deployment
```

3. Check new pods:
```bash
kubectl get pods -n lab01-basic-deployment
kubectl logs <NEW_POD_NAME> -n lab01-basic-deployment
```

4. Rollback if needed:
```bash
kubectl rollout undo deployment/web-app -n lab01-basic-deployment
```

5. Pause and resume rollout:
```bash
kubectl rollout pause deployment/web-app -n lab01-basic-deployment
# Debug the issue
kubectl rollout resume deployment/web-app -n lab01-basic-deployment
```

## Verification Commands

Use these commands to verify your setup:

```bash
# Check all resources
kubectl get all -n lab01-basic-deployment

# Check deployment status
kubectl rollout status deployment/web-app -n lab01-basic-deployment

# Check pod health
kubectl get pods -n lab01-basic-deployment -o wide

# Check service endpoints
kubectl get endpoints -n lab01-basic-deployment

# View logs from all pods
kubectl logs -l app=web-app -n lab01-basic-deployment --all-containers=true

# Check events
kubectl get events -n lab01-basic-deployment --sort-by='.lastTimestamp'

# Test connectivity
kubectl run test-pod --image=busybox:1.36 -it --rm --restart=Never -n lab01-basic-deployment -- \
  wget -qO- http://web-app-clusterip
```

## Getting Help

If issues persist:

1. Run the security check script to identify problems:
```bash
./scripts/security-check.sh
```

2. Collect diagnostic information:
```bash
kubectl get all -n lab01-basic-deployment -o yaml > lab01-resources.yaml
kubectl get events -n lab01-basic-deployment > lab01-events.txt
```

3. Consult Kubernetes documentation:
   - [Debugging Pods](https://kubernetes.io/docs/tasks/debug/debug-application/)
   - [Debugging Services](https://kubernetes.io/docs/tasks/debug/debug-application/debug-service/)
