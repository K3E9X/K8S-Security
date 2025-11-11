# Lab 00: Troubleshooting Guide

This guide provides solutions to common issues you might encounter during environment setup.

## Docker Issues

### Docker is not running

**Symptoms:**
```
Cannot connect to the Docker daemon. Is the docker daemon running?
```

**Solutions:**

**Linux:**
```bash
sudo systemctl start docker
sudo systemctl enable docker
```

**macOS/Windows:**
- Open Docker Desktop application
- Ensure Docker Desktop is running in the system tray

### Docker permission denied

**Symptoms:**
```
Got permission denied while trying to connect to the Docker daemon socket
```

**Solutions:**

**Linux:**
```bash
# Add your user to docker group
sudo usermod -aG docker $USER

# Log out and log back in, then verify
docker ps
```

### Insufficient Docker resources

**Symptoms:**
- Cluster creation fails or is very slow
- Pods stuck in Pending state
- Out of memory errors

**Solutions:**

**Docker Desktop:**
1. Open Docker Desktop settings
2. Go to Resources
3. Increase:
   - CPUs: Minimum 2, recommended 4
   - Memory: Minimum 4GB, recommended 8GB
   - Disk: Minimum 20GB
4. Click "Apply & Restart"

## kubectl Issues

### kubectl not found

**Symptoms:**
```
kubectl: command not found
```

**Solutions:**

Check if kubectl is in your PATH:
```bash
echo $PATH
which kubectl
```

Install kubectl if missing:
```bash
# Linux
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
chmod +x kubectl
sudo mv kubectl /usr/local/bin/

# macOS
brew install kubectl
```

### kubectl cannot connect to cluster

**Symptoms:**
```
The connection to the server localhost:8080 was refused
```

**Solutions:**

1. Verify cluster is running:
```bash
kind get clusters
# or
k3d cluster list
# or
minikube status
```

2. Ensure kubeconfig is set correctly:
```bash
# For kind
kind export kubeconfig --name k8s-security-lab

# For k3d
k3d kubeconfig merge k8s-security-lab --kubeconfig-switch-context

# For minikube
minikube update-context --profile k8s-security-lab
```

3. Check kubeconfig:
```bash
kubectl config view
kubectl config get-contexts
kubectl config use-context [context-name]
```

### kubectl version mismatch

**Symptoms:**
```
Warning: version difference between client and server is too large
```

**Solutions:**

This is usually just a warning and won't prevent labs from working. However, if you experience issues:

```bash
# Check versions
kubectl version --short

# Update kubectl to match cluster version
# Follow installation instructions for your OS
```

## Cluster Creation Issues

### kind cluster creation fails

**Symptoms:**
```
ERROR: failed to create cluster: failed to generate kubeadm config content
```

**Solutions:**

1. Delete any existing cluster:
```bash
kind delete cluster --name k8s-security-lab
```

2. Clean up Docker resources:
```bash
docker system prune -f
```

3. Try creating cluster again:
```bash
cd labs/scripts
./setup-kind.sh
```

4. If still failing, check Docker logs:
```bash
docker logs [container-name]
```

### kind cluster nodes not ready

**Symptoms:**
```
WARN  Cluster was created, but nodes are NotReady
```

**Solutions:**

1. Wait a few minutes and check again:
```bash
kubectl get nodes
kubectl get pods -n kube-system
```

2. Check node conditions:
```bash
kubectl describe node [node-name]
```

3. Check CNI plugin:
```bash
kubectl get pods -n kube-system -l k8s-app=kindnet
kubectl logs -n kube-system -l k8s-app=kindnet
```

### k3d cluster creation fails

**Symptoms:**
```
ERRO[0000] Failed to create cluster
```

**Solutions:**

1. Check Docker network:
```bash
docker network ls
docker network prune -f
```

2. Delete and recreate:
```bash
k3d cluster delete k8s-security-lab
cd labs/scripts
./setup-k3d.sh
```

3. Try with different ports if 80/443 are in use:
```bash
k3d cluster create k8s-security-lab --port "8080:80@loadbalancer"
```

### minikube start fails

**Symptoms:**
```
Exiting due to PROVIDER_DOCKER_NOT_RUNNING
```

**Solutions:**

1. Ensure Docker is running
2. Try with explicit driver:
```bash
minikube start --driver=docker --profile k8s-security-lab
```

3. If using VM driver, ensure virtualization is enabled in BIOS

4. Delete and recreate:
```bash
minikube delete --profile k8s-security-lab
cd labs/scripts
./setup-minikube.sh
```

## Network Issues

### Cannot pull container images

**Symptoms:**
```
ImagePullBackOff
ErrImagePull
```

**Solutions:**

1. Check internet connectivity:
```bash
curl -I https://registry.hub.docker.com
```

2. Check if images can be pulled directly:
```bash
docker pull nginx:latest
```

3. If behind a corporate proxy, configure Docker proxy:
```bash
# Create or edit /etc/docker/daemon.json
{
  "proxies": {
    "http-proxy": "http://proxy.example.com:8080",
    "https-proxy": "https://proxy.example.com:8080",
    "no-proxy": "localhost,127.0.0.1"
  }
}

# Restart Docker
sudo systemctl restart docker
```

4. For minikube, set proxy:
```bash
minikube start --docker-env HTTP_PROXY=http://proxy.example.com:8080
```

### DNS resolution not working

**Symptoms:**
```
nslookup: can't resolve 'kubernetes.default'
```

**Solutions:**

1. Check CoreDNS pods:
```bash
kubectl get pods -n kube-system -l k8s-app=kube-dns
kubectl logs -n kube-system -l k8s-app=kube-dns
```

2. Restart CoreDNS:
```bash
kubectl rollout restart deployment coredns -n kube-system
```

3. Check DNS service:
```bash
kubectl get svc -n kube-system kube-dns
```

### Port conflicts

**Symptoms:**
```
Bind for 0.0.0.0:80 failed: port is already allocated
```

**Solutions:**

1. Find what's using the port:
```bash
sudo lsof -i :80
sudo netstat -tulpn | grep :80
```

2. Stop the conflicting service or use different ports:
```bash
# For kind
kind create cluster --config [config-with-different-ports]

# For k3d
k3d cluster create --port "8080:80@loadbalancer"
```

## Resource Issues

### Pods stuck in Pending

**Symptoms:**
```
NAME                    READY   STATUS    RESTARTS   AGE
my-pod-xxx-yyy         0/1     Pending   0          5m
```

**Solutions:**

1. Check pod events:
```bash
kubectl describe pod [pod-name]
```

2. Check node resources:
```bash
kubectl top nodes
kubectl describe nodes
```

3. If insufficient resources, scale down or increase Docker resources

### Out of disk space

**Symptoms:**
```
no space left on device
```

**Solutions:**

1. Clean up Docker:
```bash
docker system prune -a -f
docker volume prune -f
```

2. Clean up kind images:
```bash
kind get clusters | xargs -n1 kind delete cluster --name
```

3. Increase Docker disk size in Docker Desktop settings

## Permission Issues

### Cannot create resources

**Symptoms:**
```
Error from server (Forbidden): pods is forbidden
```

**Solutions:**

1. Check current context and user:
```bash
kubectl config current-context
kubectl config view
```

2. For kind, ensure you're using the correct context:
```bash
kubectl config use-context kind-k8s-security-lab
```

3. Verify permissions:
```bash
kubectl auth can-i create pods
kubectl auth can-i '*' '*'
```

## Metrics Issues

### metrics-server not working

**Symptoms:**
```
error: Metrics API not available
```

**Solutions:**

1. Check metrics-server deployment:
```bash
kubectl get deployment metrics-server -n kube-system
kubectl get pods -n kube-system -l k8s-app=metrics-server
```

2. Check logs:
```bash
kubectl logs -n kube-system -l k8s-app=metrics-server
```

3. For kind, patch metrics-server:
```bash
kubectl patch -n kube-system deployment metrics-server --type=json \
  -p '[{"op":"add","path":"/spec/template/spec/containers/0/args/-","value":"--kubelet-insecure-tls"}]'
```

4. Wait a few minutes for metrics to be collected:
```bash
# Metrics need time to be collected
sleep 60
kubectl top nodes
```

## Platform-Specific Issues

### macOS: Docker Desktop not starting

**Solutions:**
1. Check System Preferences > Security & Privacy for blocked applications
2. Reset Docker Desktop: Preferences > Reset > Reset to factory defaults
3. Ensure enough disk space available

### Windows WSL2: Docker Desktop integration

**Solutions:**
1. Enable WSL2 backend in Docker Desktop settings
2. Ensure WSL2 is properly installed:
```powershell
wsl --list --verbose
wsl --set-default-version 2
```

3. In Docker Desktop, enable integration with your WSL2 distro

### Linux: Firewall blocking connections

**Solutions:**
```bash
# For firewalld
sudo firewall-cmd --zone=docker --add-masquerade --permanent
sudo firewall-cmd --reload

# For ufw
sudo ufw allow from 172.17.0.0/16
```

## Getting More Help

If you continue to experience issues:

1. **Check tool versions:**
```bash
docker --version
kubectl version
kind version  # or k3d/minikube
```

2. **Gather cluster information:**
```bash
kubectl cluster-info dump > cluster-dump.txt
kubectl get events --all-namespaces > events.txt
```

3. **Check logs:**
```bash
# For kind
docker logs [kind-container-name]

# For k3d
k3d cluster list
docker ps -a

# For minikube
minikube logs
```

4. **Consult documentation:**
- [kind troubleshooting](https://kind.sigs.k8s.io/docs/user/known-issues/)
- [k3d troubleshooting](https://k3d.io/v5.4.6/faq/faq/)
- [minikube troubleshooting](https://minikube.sigs.k8s.io/docs/drivers/docker/)

5. **Community resources:**
- Kubernetes Slack: https://kubernetes.slack.com
- Stack Overflow: Tag `kubernetes`
- GitHub Issues for specific tools

## Clean Slate Approach

If all else fails, start fresh:

```bash
# Clean up everything
cd labs/scripts
./cleanup-all.sh --force

# Remove Docker resources
docker system prune -a --volumes -f

# Restart Docker
sudo systemctl restart docker  # Linux
# Or restart Docker Desktop on macOS/Windows

# Create cluster again
./setup-kind.sh
```

Remember to back up any important data before doing a complete cleanup!
