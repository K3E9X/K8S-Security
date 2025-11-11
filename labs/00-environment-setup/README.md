# Lab 00: Environment Setup

## Objectives

By the end of this lab, you will:
- Install and verify all required tools for Kubernetes security labs
- Create a local Kubernetes cluster for hands-on exercises
- Verify cluster connectivity and basic operations
- Understand the lab environment and available resources

## Prerequisites

- A Linux, macOS, or Windows (with WSL2) system
- At least 4GB of available RAM
- Docker installed and running
- Internet connectivity for downloading tools and container images
- Basic familiarity with command-line operations

## Estimated Time

30-45 minutes

## Tools Required

The following tools will be needed throughout the labs:

1. **kubectl** - Kubernetes command-line tool
2. **Docker** - Container runtime
3. **kind** OR **k3d** OR **minikube** - Local Kubernetes cluster
4. **helm** (optional) - Kubernetes package manager
5. **git** - Version control

## Step-by-Step Instructions

### Step 1: Verify Docker Installation

First, ensure Docker is installed and running:

```bash
docker --version
docker ps
```

**Expected output:**
```
Docker version 24.x.x, build xxxxx
CONTAINER ID   IMAGE     COMMAND   CREATED   STATUS    PORTS     NAMES
```

If Docker is not installed:
- **Linux**: Follow instructions at https://docs.docker.com/engine/install/
- **macOS**: Install Docker Desktop from https://www.docker.com/products/docker-desktop
- **Windows**: Install Docker Desktop with WSL2 backend

### Step 2: Install kubectl

kubectl is the primary tool for interacting with Kubernetes clusters.

**Linux:**
```bash
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
chmod +x kubectl
sudo mv kubectl /usr/local/bin/
```

**macOS:**
```bash
brew install kubectl
```

**Verify installation:**
```bash
kubectl version --client
```

### Step 3: Choose and Install a Cluster Tool

You need ONE of the following tools. We recommend **kind** for this course.

#### Option A: Install kind (Recommended)

```bash
# For Linux
curl -Lo ./kind https://kind.sigs.k8s.io/dl/v0.20.0/kind-linux-amd64
chmod +x ./kind
sudo mv ./kind /usr/local/bin/kind

# For macOS
brew install kind

# Verify
kind version
```

#### Option B: Install k3d

```bash
# Linux or macOS
curl -s https://raw.githubusercontent.com/k3d-io/k3d/main/install.sh | bash

# Verify
k3d version
```

#### Option C: Install minikube

```bash
# Linux
curl -LO https://storage.googleapis.com/minikube/releases/latest/minikube-linux-amd64
sudo install minikube-linux-amd64 /usr/local/bin/minikube

# macOS
brew install minikube

# Verify
minikube version
```

### Step 4: Create Your Kubernetes Cluster

Use the provided setup scripts to create your cluster:

**For kind:**
```bash
cd labs/scripts
./setup-kind.sh
```

**For k3d:**
```bash
cd labs/scripts
./setup-k3d.sh
```

**For minikube:**
```bash
cd labs/scripts
./setup-minikube.sh
```

The script will:
- Check prerequisites
- Create a multi-node cluster
- Configure security features
- Install metrics-server
- Display cluster information

**This process may take 5-10 minutes depending on your internet connection.**

### Step 5: Verify Cluster Access

Once the cluster is created, verify you can access it:

```bash
# Check cluster info
kubectl cluster-info

# List nodes
kubectl get nodes

# Check system pods
kubectl get pods -n kube-system

# Verify you can create resources
kubectl create namespace test
kubectl delete namespace test
```

### Step 6: Install Additional Tools (Optional but Recommended)

#### Install helm

```bash
# Linux or macOS
curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash

# Verify
helm version
```

#### Install k9s (Interactive Cluster Manager)

```bash
# Linux
curl -sS https://webinstall.dev/k9s | bash

# macOS
brew install k9s

# Launch k9s
k9s
```

### Step 7: Run the Environment Verification Script

```bash
cd labs/00-environment-setup/scripts
./verify-environment.sh
```

This script will check:
- Tool installations
- Cluster connectivity
- Required permissions
- Available resources

### Step 8: Explore Your Cluster

Get familiar with your cluster:

```bash
# View cluster information
kubectl cluster-info dump > cluster-info.txt

# Check available API resources
kubectl api-resources

# View cluster nodes with details
kubectl get nodes -o wide

# Check cluster resource usage
kubectl top nodes

# View all namespaces
kubectl get namespaces
```

### Step 9: Create a Test Deployment

Let's verify everything works by creating a simple deployment:

```bash
# Create a test namespace
kubectl create namespace lab-test

# Create a simple nginx deployment
kubectl create deployment nginx --image=nginx:latest -n lab-test

# Wait for the pod to be ready
kubectl wait --for=condition=ready pod -l app=nginx -n lab-test --timeout=60s

# Check the deployment
kubectl get pods -n lab-test

# Clean up
kubectl delete namespace lab-test
```

## Verification Checklist

Use this checklist to ensure your environment is ready:

- [ ] Docker is installed and running
- [ ] kubectl is installed and in PATH
- [ ] Cluster tool (kind/k3d/minikube) is installed
- [ ] Kubernetes cluster is created and running
- [ ] kubectl can connect to the cluster
- [ ] All cluster nodes are in "Ready" state
- [ ] System pods in kube-system namespace are running
- [ ] You can create and delete resources
- [ ] Metrics-server is available (optional but recommended)
- [ ] helm is installed (optional)

## Common Issues and Solutions

See [troubleshooting.md](./troubleshooting.md) for detailed solutions to common problems.

## Expected Output

After completing this lab, you should see:

1. **Cluster nodes ready:**
```
NAME                              STATUS   ROLES           AGE   VERSION
k8s-security-lab-control-plane    Ready    control-plane   5m    v1.28.0
k8s-security-lab-worker           Ready    <none>          4m    v1.28.0
k8s-security-lab-worker2          Ready    <none>          4m    v1.28.0
```

2. **System pods running:**
```
NAME                                         READY   STATUS    RESTARTS   AGE
coredns-5d78c9869d-xxxxx                    1/1     Running   0          5m
etcd-k8s-security-lab-control-plane         1/1     Running   0          5m
kube-apiserver-k8s-security-lab...          1/1     Running   0          5m
kube-controller-manager-k8s-security...     1/1     Running   0          5m
kube-proxy-xxxxx                            1/1     Running   0          5m
kube-scheduler-k8s-security-lab...          1/1     Running   0          5m
```

3. **Successful test deployment creation and deletion**

## Next Steps

Once your environment is set up and verified:

1. Familiarize yourself with kubectl commands
2. Explore the Kubernetes dashboard (if using minikube: `minikube dashboard`)
3. Review the cluster architecture
4. Proceed to **Lab 01: Basic Deployment**

## Additional Resources

- [Kubernetes Official Documentation](https://kubernetes.io/docs/)
- [kubectl Cheat Sheet](https://kubernetes.io/docs/reference/kubectl/cheatsheet/)
- [kind Documentation](https://kind.sigs.k8s.io/)
- [k3d Documentation](https://k3d.io/)
- [minikube Documentation](https://minikube.sigs.k8s.io/)

## Lab Cleanup

To save resources when not working on labs:

```bash
# Stop the cluster (keeps it for later)
kind export kubeconfig --name k8s-security-lab  # Just to save config
docker stop $(docker ps -q --filter "name=k8s-security-lab")  # For kind

# Or completely delete the cluster
cd labs/scripts
./cleanup-all.sh
```

## Notes

- The cluster setup scripts create clusters optimized for security labs
- Audit logging is enabled by default
- Pod Security admission is configured
- Network policies are supported
- Keep your cluster running between labs to save time
- Resources used: ~2-4 GB RAM, ~10-20 GB disk space

---

**Congratulations!** Your environment is now ready for the Kubernetes security labs.
