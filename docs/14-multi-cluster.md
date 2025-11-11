# Module 14: Multi-cluster and Federation

## Overview

**Estimated Time:** 8-9 hours

**Module Type:** Advanced Architecture and Operations

**Prerequisites:**
- Module 03 - Networking Fundamentals
- Module 05 - Authentication and Authorization
- Module 10 - Network Security
- Understanding of distributed systems and high availability
- Familiarity with service mesh concepts and disaster recovery

Multi-cluster Kubernetes architectures enable scalability, geographic distribution, disaster recovery, and compliance requirements. This module covers multi-cluster architecture patterns, Cluster API for cluster lifecycle management, federation strategies using kubefed and service mesh, cross-cluster networking with Submariner and Cilium Cluster Mesh, identity federation, disaster recovery strategies, and multi-region deployment patterns. Based on CNCF best practices and production deployments from enterprises running Kubernetes at scale.

---

## Learning Objectives

By the end of this module, you will be able to:

1. Design multi-cluster architectures for various use cases
2. Deploy and manage clusters using Cluster API
3. Implement federation strategies with kubefed and service mesh
4. Configure cross-cluster networking with Submariner and Cilium
5. Synchronize RBAC and identity across clusters
6. Implement disaster recovery and business continuity
7. Deploy multi-region applications with traffic management
8. Design for high availability across clusters
9. Manage secrets and configuration across clusters
10. Monitor and observe multi-cluster environments

---

## 1. Multi-cluster Architecture Patterns

### 1.1 Common Multi-cluster Patterns

```mermaid
graph TB
    subgraph "Pattern 1: Geographic Distribution"
        A1[US-East Cluster] --> LB1[Global Load Balancer]
        A2[US-West Cluster] --> LB1
        A3[EU Cluster] --> LB1
        A4[APAC Cluster] --> LB1
        LB1 --> U1[Users]
    end

    subgraph "Pattern 2: Environment Isolation"
        B1[Dev Cluster]
        B2[Staging Cluster]
        B3[Production Cluster]
        B1 --> B2
        B2 --> B3
    end

    subgraph "Pattern 3: Workload Segmentation"
        C1[Compute Cluster] --> C3[Data Cluster]
        C2[ML/AI Cluster] --> C3
        C3 --> C4[Storage Backend]
    end

    subgraph "Pattern 4: Disaster Recovery"
        D1[Primary Cluster] -.->|Replicate| D2[DR Cluster]
        D1 --> D3[Active Traffic]
        D2 -.->|Failover| D3
    end

    style A1 fill:#4ecdc4
    style A2 fill:#4ecdc4
    style A3 fill:#4ecdc4
    style A4 fill:#4ecdc4
    style D1 fill:#ff6b6b
    style D2 fill:#ffe66d
```

### 1.2 Decision Matrix: When to Use Multi-cluster

| Use Case | Single Cluster | Multi-cluster | Rationale |
|----------|---------------|---------------|-----------|
| Small team, single app | ✅ Recommended | ❌ Overkill | Simplicity wins |
| Geographic distribution | ❌ High latency | ✅ Required | Low latency for users |
| Compliance (data residency) | ❌ May violate | ✅ Required | Data must stay in region |
| Blast radius reduction | ⚠️ Namespaces help | ✅ Better isolation | Full isolation between clusters |
| Resource limits (1000+ nodes) | ❌ Scale limits | ✅ Required | Exceeds single cluster limits |
| Disaster recovery | ⚠️ Multi-AZ only | ✅ Recommended | Survive region failure |
| Org boundaries (multi-tenant) | ⚠️ Complex RBAC | ✅ Better isolation | Clean separation of concerns |
| Heterogeneous workloads | ⚠️ Node pools | ✅ Cleaner | Different configs per cluster |

### 1.3 Reference Architecture: Multi-region Production

**Architecture Overview:**

```yaml
# Multi-region production architecture
architecture:
  regions:
    - name: us-east-1
      clusters:
        - name: prod-use1-01
          purpose: production workloads
          size: 100 nodes
          k8s_version: 1.29
        - name: prod-use1-02
          purpose: production workloads (HA pair)
          size: 100 nodes
          k8s_version: 1.29

    - name: us-west-2
      clusters:
        - name: prod-usw2-01
          purpose: production workloads
          size: 80 nodes
          k8s_version: 1.29

    - name: eu-central-1
      clusters:
        - name: prod-euc1-01
          purpose: production workloads + GDPR
          size: 60 nodes
          k8s_version: 1.29

  management:
    cluster: mgmt-use1-01
    purpose: Fleet management, GitOps, monitoring
    size: 20 nodes
    tools:
      - Cluster API
      - ArgoCD
      - Prometheus Federation
      - Thanos

  networking:
    mesh: Cilium Cluster Mesh
    cross_cluster: Submariner
    ingress: Global Load Balancer (AWS Global Accelerator)
    egress: Centralized per region

  data:
    replication: Active-Active
    backup: Multi-region S3
    database: CockroachDB (geo-distributed)

  identity:
    federation: Dex with OIDC
    rbac_sync: kubefed RBAC controller
```

---

## 2. Cluster API Overview

### 2.1 Cluster API Architecture

```mermaid
graph TB
    A[Management Cluster] --> B[Cluster API Controller]
    B --> C[Infrastructure Provider]
    B --> D[Bootstrap Provider]
    B --> E[Control Plane Provider]

    C --> F[AWS/Azure/GCP/VMware]
    D --> G[kubeadm/k3s/Talos]
    E --> H[Control Plane Machines]

    H --> I[Worker Nodes]

    J[GitOps Repo] --> K[ArgoCD/Flux]
    K --> A
    K --> L[Cluster Manifests]
    L --> B

    style A fill:#4169e1
    style B fill:#ff6b6b
    style J fill:#90ee90
```

### 2.2 Installing Cluster API

**Bootstrap Management Cluster:**

```bash
#!/bin/bash
# install-cluster-api.sh

set -e

echo "=== Installing Cluster API ==="

# Install clusterctl
curl -L https://github.com/kubernetes-sigs/cluster-api/releases/download/v1.6.1/clusterctl-linux-amd64 \
  -o clusterctl
chmod +x clusterctl
sudo mv clusterctl /usr/local/bin/

# Set provider credentials (AWS example)
export AWS_REGION=us-east-1
export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
export AWS_B64ENCODED_CREDENTIALS=$(clusterawsadm bootstrap credentials encode-as-profile)

# Initialize management cluster
clusterctl init \
  --infrastructure aws \
  --bootstrap kubeadm \
  --control-plane kubeadm

# Verify installation
kubectl get pods -n capi-system
kubectl get pods -n capi-kubeadm-bootstrap-system
kubectl get pods -n capi-kubeadm-control-plane-system
kubectl get pods -n capa-system

echo "=== Cluster API installed successfully ==="
```

### 2.3 Creating Workload Clusters

**Cluster Manifest:**

```yaml
# workload-cluster.yaml
apiVersion: cluster.x-k8s.io/v1beta1
kind: Cluster
metadata:
  name: prod-use1-01
  namespace: default
spec:
  clusterNetwork:
    pods:
      cidrBlocks:
        - 10.244.0.0/16
    services:
      cidrBlocks:
        - 10.96.0.0/12
  infrastructureRef:
    apiVersion: infrastructure.cluster.x-k8s.io/v1beta2
    kind: AWSCluster
    name: prod-use1-01
  controlPlaneRef:
    apiVersion: controlplane.cluster.x-k8s.io/v1beta1
    kind: KubeadmControlPlane
    name: prod-use1-01-control-plane
---
apiVersion: infrastructure.cluster.x-k8s.io/v1beta2
kind: AWSCluster
metadata:
  name: prod-use1-01
  namespace: default
spec:
  region: us-east-1
  sshKeyName: k8s-admin
  network:
    vpc:
      availabilityZoneUsageLimit: 3
      availabilityZoneSelection: Ordered
    subnets:
      - availabilityZone: us-east-1a
        cidrBlock: 10.0.0.0/24
        isPublic: true
      - availabilityZone: us-east-1b
        cidrBlock: 10.0.1.0/24
        isPublic: true
      - availabilityZone: us-east-1c
        cidrBlock: 10.0.2.0/24
        isPublic: true
      - availabilityZone: us-east-1a
        cidrBlock: 10.0.10.0/24
        isPublic: false
      - availabilityZone: us-east-1b
        cidrBlock: 10.0.11.0/24
        isPublic: false
      - availabilityZone: us-east-1c
        cidrBlock: 10.0.12.0/24
        isPublic: false
  bastion:
    enabled: true
---
apiVersion: controlplane.cluster.x-k8s.io/v1beta1
kind: KubeadmControlPlane
metadata:
  name: prod-use1-01-control-plane
  namespace: default
spec:
  version: v1.29.0
  replicas: 3
  machineTemplate:
    infrastructureRef:
      apiVersion: infrastructure.cluster.x-k8s.io/v1beta2
      kind: AWSMachineTemplate
      name: prod-use1-01-control-plane
  kubeadmConfigSpec:
    initConfiguration:
      nodeRegistration:
        kubeletExtraArgs:
          cloud-provider: aws
    clusterConfiguration:
      apiServer:
        extraArgs:
          cloud-provider: aws
          audit-log-path: /var/log/kubernetes/audit.log
          audit-log-maxage: "30"
          audit-log-maxbackup: "10"
          audit-log-maxsize: "100"
      controllerManager:
        extraArgs:
          cloud-provider: aws
    joinConfiguration:
      nodeRegistration:
        kubeletExtraArgs:
          cloud-provider: aws
---
apiVersion: infrastructure.cluster.x-k8s.io/v1beta2
kind: AWSMachineTemplate
metadata:
  name: prod-use1-01-control-plane
  namespace: default
spec:
  template:
    spec:
      instanceType: t3.large
      iamInstanceProfile: control-plane.cluster-api-provider-aws.sigs.k8s.io
      sshKeyName: k8s-admin
      ami:
        id: ami-0c55b159cbfafe1f0
---
apiVersion: cluster.x-k8s.io/v1beta1
kind: MachineDeployment
metadata:
  name: prod-use1-01-workers
  namespace: default
spec:
  clusterName: prod-use1-01
  replicas: 10
  selector:
    matchLabels: {}
  template:
    spec:
      clusterName: prod-use1-01
      version: v1.29.0
      bootstrap:
        configRef:
          apiVersion: bootstrap.cluster.x-k8s.io/v1beta1
          kind: KubeadmConfigTemplate
          name: prod-use1-01-workers
      infrastructureRef:
        apiVersion: infrastructure.cluster.x-k8s.io/v1beta2
        kind: AWSMachineTemplate
        name: prod-use1-01-workers
---
apiVersion: infrastructure.cluster.x-k8s.io/v1beta2
kind: AWSMachineTemplate
metadata:
  name: prod-use1-01-workers
  namespace: default
spec:
  template:
    spec:
      instanceType: t3.xlarge
      iamInstanceProfile: nodes.cluster-api-provider-aws.sigs.k8s.io
      sshKeyName: k8s-admin
      ami:
        id: ami-0c55b159cbfafe1f0
---
apiVersion: bootstrap.cluster.x-k8s.io/v1beta1
kind: KubeadmConfigTemplate
metadata:
  name: prod-use1-01-workers
  namespace: default
spec:
  template:
    spec:
      joinConfiguration:
        nodeRegistration:
          kubeletExtraArgs:
            cloud-provider: aws
```

**Deploy and Manage:**

```bash
# Create workload cluster
kubectl apply -f workload-cluster.yaml

# Watch cluster creation
watch kubectl get clusters,machines,kubeadmcontrolplanes

# Get kubeconfig for new cluster
clusterctl get kubeconfig prod-use1-01 > prod-use1-01.kubeconfig

# Verify cluster
kubectl --kubeconfig=prod-use1-01.kubeconfig get nodes

# Scale workers
kubectl patch machinedeployment prod-use1-01-workers \
  --type merge \
  --patch '{"spec":{"replicas":20}}'

# Upgrade cluster
kubectl patch kubeadmcontrolplane prod-use1-01-control-plane \
  --type merge \
  --patch '{"spec":{"version":"v1.29.1"}}'
```

### 2.4 Cluster Lifecycle Management

**Automated Cluster Upgrades:**

```yaml
# cluster-upgrade-policy.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: cluster-upgrade-policy
  namespace: default
data:
  policy.yaml: |
    clusters:
      - name: prod-*
        upgrade:
          schedule: "0 2 * * SUN"  # Sunday 2 AM
          strategy: RollingUpdate
          max_unavailable: 1
          pre_checks:
            - kube-bench
            - pod-security-check
          post_checks:
            - smoke-tests
            - integration-tests

      - name: dev-*
        upgrade:
          auto: true
          track: stable

      - name: staging-*
        upgrade:
          approval: manual
          track: latest
```

---

## 3. Federation Strategies

### 3.1 kubefed Installation and Configuration

**Install kubefed:**

```bash
#!/bin/bash
# install-kubefed.sh

# Install kubefedctl
VERSION=0.10.0
curl -LO "https://github.com/kubernetes-sigs/kubefed/releases/download/v${VERSION}/kubefedctl-${VERSION}-linux-amd64.tgz"
tar -xzf "kubefedctl-${VERSION}-linux-amd64.tgz"
sudo mv kubefedctl /usr/local/bin/

# Install kubefed in host cluster
helm repo add kubefed-charts https://raw.githubusercontent.com/kubernetes-sigs/kubefed/master/charts
helm install kubefed kubefed-charts/kubefed \
  --namespace kube-federation-system \
  --create-namespace

# Join member clusters
kubefedctl join prod-use1 \
  --cluster-context prod-use1-01 \
  --host-cluster-context mgmt-cluster \
  --v=2

kubefedctl join prod-usw2 \
  --cluster-context prod-usw2-01 \
  --host-cluster-context mgmt-cluster \
  --v=2

# Verify federation
kubectl get kubefedclusters -n kube-federation-system
```

### 3.2 Federated Resources

**Federated Deployment:**

```yaml
# federated-app.yaml
apiVersion: types.kubefed.io/v1beta1
kind: FederatedDeployment
metadata:
  name: nginx-app
  namespace: default
spec:
  template:
    metadata:
      labels:
        app: nginx
    spec:
      replicas: 3
      selector:
        matchLabels:
          app: nginx
      template:
        metadata:
          labels:
            app: nginx
        spec:
          containers:
          - name: nginx
            image: nginx:1.25
            ports:
            - containerPort: 80
  placement:
    clusters:
      - name: prod-use1
      - name: prod-usw2
      - name: prod-euc1
  overrides:
    - clusterName: prod-use1
      clusterOverrides:
        - path: "/spec/replicas"
          value: 5
    - clusterName: prod-euc1
      clusterOverrides:
        - path: "/spec/template/spec/containers/0/env"
          value:
            - name: REGION
              value: eu-central-1
---
apiVersion: types.kubefed.io/v1beta1
kind: FederatedService
metadata:
  name: nginx-service
  namespace: default
spec:
  template:
    spec:
      type: LoadBalancer
      selector:
        app: nginx
      ports:
      - protocol: TCP
        port: 80
        targetPort: 80
  placement:
    clusters:
      - name: prod-use1
      - name: prod-usw2
      - name: prod-euc1
```

### 3.3 Service Mesh Federation (Istio Multi-cluster)

**Istio Multi-primary Installation:**

```bash
#!/bin/bash
# setup-istio-multicluster.sh

# Install istioctl
curl -L https://istio.io/downloadIstio | ISTIO_VERSION=1.20.1 sh -
cd istio-1.20.1
export PATH=$PWD/bin:$PATH

# Configure cluster 1 as primary
kubectl config use-context prod-use1-01

cat <<EOF | istioctl install -y -f -
apiVersion: install.istio.io/v1alpha1
kind: IstioOperator
spec:
  values:
    global:
      meshID: mesh1
      multiCluster:
        clusterName: cluster1
      network: network1
EOF

# Install east-west gateway
kubectl apply -f samples/multicluster/expose-services.yaml

# Get gateway address
export DISCOVERY_ADDRESS=$(kubectl get svc istio-eastwestgateway \
  -n istio-system -o jsonpath='{.status.loadBalancer.ingress[0].ip}')

# Configure cluster 2 as primary
kubectl config use-context prod-usw2-01

cat <<EOF | istioctl install -y -f -
apiVersion: install.istio.io/v1alpha1
kind: IstioOperator
spec:
  values:
    global:
      meshID: mesh1
      multiCluster:
        clusterName: cluster2
      network: network2
EOF

# Enable endpoint discovery between clusters
istioctl create-remote-secret \
  --context=prod-use1-01 \
  --name=cluster1 | \
  kubectl apply -f - --context=prod-usw2-01

istioctl create-remote-secret \
  --context=prod-usw2-01 \
  --name=cluster2 | \
  kubectl apply -f - --context=prod-use1-01

# Verify multi-cluster mesh
kubectl get services -n istio-system
```

**Cross-cluster Service Discovery:**

```yaml
# multi-cluster-service.yaml
apiVersion: v1
kind: Service
metadata:
  name: api-service
  namespace: production
spec:
  type: ClusterIP
  selector:
    app: api
  ports:
  - port: 8080
    targetPort: 8080
---
apiVersion: networking.istio.io/v1beta1
kind: ServiceEntry
metadata:
  name: api-service-remote
  namespace: production
spec:
  hosts:
  - api-service.production.global
  location: MESH_INTERNAL
  ports:
  - number: 8080
    name: http
    protocol: HTTP
  resolution: DNS
  endpoints:
  - address: api-service.production.svc.cluster.local
    locality: us-east-1
  - address: api-service.production.cluster2.global
    locality: us-west-2
---
apiVersion: networking.istio.io/v1beta1
kind: DestinationRule
metadata:
  name: api-service-failover
  namespace: production
spec:
  host: api-service.production.global
  trafficPolicy:
    loadBalancer:
      localityLbSetting:
        enabled: true
        distribute:
        - from: us-east-1
          to:
            "us-east-1": 80
            "us-west-2": 20
        failover:
        - from: us-east-1
          to: us-west-2
```

---

## 4. Cross-cluster Networking

### 4.1 Submariner for Cross-cluster Connectivity

**Install Submariner:**

```bash
#!/bin/bash
# install-submariner.sh

# Download subctl
curl -Ls https://get.submariner.io | bash
export PATH=$PATH:~/.local/bin

# Deploy broker
kubectl config use-context mgmt-cluster
subctl deploy-broker --kubeconfig mgmt-cluster.kubeconfig

# Join cluster 1
kubectl config use-context prod-use1-01
subctl join broker-info.subm --kubeconfig prod-use1-01.kubeconfig \
  --clusterid cluster1 \
  --natt=false \
  --cable-driver vxlan

# Join cluster 2
kubectl config use-context prod-usw2-01
subctl join broker-info.subm --kubeconfig prod-usw2-01.kubeconfig \
  --clusterid cluster2 \
  --natt=false \
  --cable-driver vxlan

# Verify connectivity
subctl show all
subctl verify --only connectivity
```

**Export Services Across Clusters:**

```yaml
# service-export.yaml
apiVersion: v1
kind: Service
metadata:
  name: database
  namespace: data-tier
spec:
  type: ClusterIP
  selector:
    app: postgres
  ports:
  - port: 5432
    targetPort: 5432
---
apiVersion: multicluster.x-k8s.io/v1alpha1
kind: ServiceExport
metadata:
  name: database
  namespace: data-tier
```

**Import Services:**

```yaml
# Service automatically imported, access via:
# database.data-tier.svc.clusterset.local
apiVersion: v1
kind: Pod
metadata:
  name: app
  namespace: applications
spec:
  containers:
  - name: app
    image: myapp:v1.0.0
    env:
    - name: DATABASE_URL
      value: postgresql://user:pass@database.data-tier.svc.clusterset.local:5432/mydb
```

### 4.2 Cilium Cluster Mesh

**Setup Cilium Cluster Mesh:**

```bash
#!/bin/bash
# setup-cilium-clustermesh.sh

# Install Cilium in cluster 1
kubectl config use-context prod-use1-01
cilium install \
  --cluster-name cluster1 \
  --cluster-id 1 \
  --ipam kubernetes \
  --set hubble.relay.enabled=true

# Install Cilium in cluster 2
kubectl config use-context prod-usw2-01
cilium install \
  --cluster-name cluster2 \
  --cluster-id 2 \
  --ipam kubernetes \
  --set hubble.relay.enabled=true

# Enable Cluster Mesh
kubectl config use-context prod-use1-01
cilium clustermesh enable --service-type LoadBalancer

kubectl config use-context prod-usw2-01
cilium clustermesh enable --service-type LoadBalancer

# Connect clusters
kubectl config use-context prod-use1-01
cilium clustermesh connect \
  --context prod-use1-01 \
  --destination-context prod-usw2-01

# Verify connectivity
cilium clustermesh status

# Test with Hubble
hubble observe --pod default/app --follow
```

**Global Service:**

```yaml
# global-service.yaml
apiVersion: v1
kind: Service
metadata:
  name: global-api
  namespace: production
  annotations:
    io.cilium/global-service: "true"
    io.cilium/service-affinity: "local"
spec:
  type: ClusterIP
  selector:
    app: api
  ports:
  - port: 8080
    targetPort: 8080
```

---

## 5. Identity Federation and RBAC Synchronization

### 5.1 Federated Authentication with Dex

**Dex Configuration:**

```yaml
# dex-config.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: dex
  namespace: auth
data:
  config.yaml: |
    issuer: https://dex.example.com

    storage:
      type: kubernetes
      config:
        inCluster: true

    web:
      http: 0.0.0.0:5556

    connectors:
    - type: ldap
      id: ldap
      name: LDAP
      config:
        host: ldap.example.com:636
        insecureSkipVerify: false
        bindDN: cn=admin,dc=example,dc=com
        bindPW: password
        userSearch:
          baseDN: ou=users,dc=example,dc=com
          filter: "(objectClass=person)"
          username: uid
          idAttr: uid
          emailAttr: mail
          nameAttr: cn
        groupSearch:
          baseDN: ou=groups,dc=example,dc=com
          filter: "(objectClass=groupOfNames)"
          userAttr: DN
          groupAttr: member
          nameAttr: cn

    oauth2:
      skipApprovalScreen: true

    staticClients:
    - id: kubernetes
      redirectURIs:
      - 'https://prod-use1-01.example.com/callback'
      - 'https://prod-usw2-01.example.com/callback'
      - 'https://prod-euc1-01.example.com/callback'
      name: 'Kubernetes Clusters'
      secret: kubernetes-client-secret
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: dex
  namespace: auth
spec:
  replicas: 3
  selector:
    matchLabels:
      app: dex
  template:
    metadata:
      labels:
        app: dex
    spec:
      containers:
      - name: dex
        image: ghcr.io/dexidp/dex:v2.37.0
        command: ["/usr/local/bin/dex", "serve", "/etc/dex/config.yaml"]
        ports:
        - name: http
          containerPort: 5556
        volumeMounts:
        - name: config
          mountPath: /etc/dex
      volumes:
      - name: config
        configMap:
          name: dex
```

**API Server OIDC Configuration:**

```yaml
# Apply to all cluster API servers
apiVersion: v1
kind: Pod
metadata:
  name: kube-apiserver
  namespace: kube-system
spec:
  containers:
  - name: kube-apiserver
    command:
    - kube-apiserver
    - --oidc-issuer-url=https://dex.example.com
    - --oidc-client-id=kubernetes
    - --oidc-username-claim=email
    - --oidc-groups-claim=groups
    - --oidc-ca-file=/etc/kubernetes/pki/oidc-ca.crt
```

### 5.2 RBAC Synchronization

**Federated ClusterRole:**

```yaml
# federated-rbac.yaml
apiVersion: types.kubefed.io/v1beta1
kind: FederatedClusterRole
metadata:
  name: developer
spec:
  template:
    rules:
    - apiGroups: ["", "apps", "batch"]
      resources: ["*"]
      verbs: ["get", "list", "watch"]
    - apiGroups: [""]
      resources: ["pods/log", "pods/portforward"]
      verbs: ["get", "list", "create"]
  placement:
    clusters:
    - name: prod-use1
    - name: prod-usw2
    - name: prod-euc1
---
apiVersion: types.kubefed.io/v1beta1
kind: FederatedClusterRoleBinding
metadata:
  name: developers
spec:
  template:
    roleRef:
      apiGroup: rbac.authorization.k8s.io
      kind: ClusterRole
      name: developer
    subjects:
    - kind: Group
      name: developers
      apiGroup: rbac.authorization.k8s.io
  placement:
    clusters:
    - name: prod-use1
    - name: prod-usw2
    - name: prod-euc1
```

---

## 6. Disaster Recovery Strategies

### 6.1 DR Architecture

```mermaid
graph TB
    subgraph "Primary Region: us-east-1"
        P1[Prod Cluster 1] --> P2[RDS Primary]
        P1 --> P3[S3 Primary]
        P1 --> P4[etcd Primary]
    end

    subgraph "DR Region: us-west-2"
        D1[DR Cluster] --> D2[RDS Replica]
        D1 --> D3[S3 Replica]
        D1 --> D4[etcd Backup]
    end

    P2 -.->|Async Replication| D2
    P3 -.->|Cross-region Replication| D3
    P4 -.->|Velero Backup| D4

    U[Users] --> R[Route 53]
    R -->|Active| P1
    R -.->|Failover| D1

    M[Monitoring] --> P1
    M --> D1
    M --> F{Health Check}
    F -->|Failure| T[Trigger Failover]
    T --> R

    style P1 fill:#90ee90
    style D1 fill:#ffe66d
    style F fill:#ff6b6b
```

### 6.2 Backup and Restore with Velero

**Install Velero:**

```bash
#!/bin/bash
# install-velero.sh

# Download Velero
wget https://github.com/vmware-tanzu/velero/releases/download/v1.12.1/velero-v1.12.1-linux-amd64.tar.gz
tar -xvf velero-v1.12.1-linux-amd64.tar.gz
sudo mv velero-v1.12.1-linux-amd64/velero /usr/local/bin/

# Install Velero with AWS plugin
velero install \
  --provider aws \
  --plugins velero/velero-plugin-for-aws:v1.8.0 \
  --bucket velero-backups-prod \
  --secret-file ./credentials-velero \
  --backup-location-config region=us-east-1 \
  --snapshot-location-config region=us-east-1 \
  --use-volume-snapshots=true \
  --use-node-agent

# Configure backup storage location for DR region
velero backup-location create dr-backup \
  --provider aws \
  --bucket velero-backups-dr \
  --config region=us-west-2
```

**Backup Schedules:**

```yaml
# velero-schedules.yaml
apiVersion: velero.io/v1
kind: Schedule
metadata:
  name: daily-backup
  namespace: velero
spec:
  schedule: "0 2 * * *"
  template:
    includedNamespaces:
    - production
    - staging
    excludedResources:
    - events
    - events.events.k8s.io
    ttl: 720h0m0s  # 30 days
    storageLocation: dr-backup
    volumeSnapshotLocations:
    - dr-backup
---
apiVersion: velero.io/v1
kind: Schedule
metadata:
  name: hourly-backup-critical
  namespace: velero
spec:
  schedule: "0 * * * *"
  template:
    includedNamespaces:
    - production
    labelSelector:
      matchLabels:
        backup: critical
    ttl: 168h0m0s  # 7 days
    storageLocation: dr-backup
```

**Disaster Recovery Restore:**

```bash
#!/bin/bash
# disaster-recovery-restore.sh

set -e

echo "=== DISASTER RECOVERY RESTORE ==="

# Switch to DR cluster
kubectl config use-context dr-cluster-usw2

# List available backups
velero backup get

# Restore latest backup
LATEST_BACKUP=$(velero backup get -o json | jq -r '.items | sort_by(.status.startTimestamp) | last | .metadata.name')

echo "Restoring backup: ${LATEST_BACKUP}"

# Perform restore
velero restore create dr-restore-$(date +%Y%m%d-%H%M%S) \
  --from-backup ${LATEST_BACKUP} \
  --restore-volumes=true \
  --wait

# Verify restore
kubectl get all -n production
kubectl get pv,pvc -n production

# Update DNS to point to DR cluster
echo "Updating Route 53..."
aws route53 change-resource-record-sets \
  --hosted-zone-id Z1234567890ABC \
  --change-batch file://failover-dns-change.json

echo "=== DR Restore Complete ==="
echo "Monitor application health and verify functionality"
```

### 6.3 RTO and RPO Optimization

**Recovery Time Objective (RTO) Strategies:**

1. **Hot Standby (RTO: < 5 minutes)**
   - Active-Active across regions
   - Real-time replication
   - DNS failover only
   - Highest cost

2. **Warm Standby (RTO: < 30 minutes)**
   - DR cluster running with minimal workload
   - Scheduled backups (every 15 minutes)
   - Scale up on failover
   - Medium cost

3. **Cold Standby (RTO: < 4 hours)**
   - No DR cluster running
   - Create cluster from backups
   - Restore from latest backup
   - Lowest cost

**Recovery Point Objective (RPO) Configuration:**

```yaml
# Low RPO strategy (< 5 minutes)
apiVersion: velero.io/v1
kind: Schedule
metadata:
  name: continuous-backup
  namespace: velero
spec:
  schedule: "*/5 * * * *"  # Every 5 minutes
  template:
    includedNamespaces:
    - production
    labelSelector:
      matchLabels:
        tier: critical
    ttl: 24h0m0s
```

---

## 7. Multi-region Deployment Patterns

### 7.1 Global Traffic Management

**External DNS with Route 53:**

```yaml
# external-dns.yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: external-dns
  namespace: kube-system
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: external-dns
rules:
- apiGroups: [""]
  resources: ["services", "endpoints", "pods"]
  verbs: ["get", "watch", "list"]
- apiGroups: ["extensions", "networking.k8s.io"]
  resources: ["ingresses"]
  verbs: ["get", "watch", "list"]
- apiGroups: [""]
  resources: ["nodes"]
  verbs: ["list"]
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: external-dns
  namespace: kube-system
spec:
  selector:
    matchLabels:
      app: external-dns
  template:
    metadata:
      labels:
        app: external-dns
    spec:
      serviceAccountName: external-dns
      containers:
      - name: external-dns
        image: registry.k8s.io/external-dns/external-dns:v0.14.0
        args:
        - --source=service
        - --source=ingress
        - --domain-filter=example.com
        - --provider=aws
        - --policy=sync
        - --aws-zone-type=public
        - --registry=txt
        - --txt-owner-id=prod-use1-01
        - --annotation-filter=external-dns.alpha.kubernetes.io/hostname
---
# Multi-region service with geolocation routing
apiVersion: v1
kind: Service
metadata:
  name: api
  namespace: production
  annotations:
    external-dns.alpha.kubernetes.io/hostname: api.example.com
    external-dns.alpha.kubernetes.io/aws-geolocation-continent-code: NA
    external-dns.alpha.kubernetes.io/set-identifier: us-east-1
spec:
  type: LoadBalancer
  selector:
    app: api
  ports:
  - port: 443
    targetPort: 8080
```

### 7.2 Multi-region Application Deployment

**GitOps with ArgoCD:**

```yaml
# argocd-multicluster-app.yaml
apiVersion: argoproj.io/v1alpha1
kind: ApplicationSet
metadata:
  name: global-app
  namespace: argocd
spec:
  generators:
  - list:
      elements:
      - cluster: prod-use1
        region: us-east-1
        replicas: "10"
      - cluster: prod-usw2
        region: us-west-2
        replicas: "8"
      - cluster: prod-euc1
        region: eu-central-1
        replicas: "6"
  template:
    metadata:
      name: 'global-app-{{cluster}}'
    spec:
      project: production
      source:
        repoURL: https://github.com/example/app
        targetRevision: main
        path: k8s/overlays/{{region}}
        helm:
          parameters:
          - name: replicaCount
            value: '{{replicas}}'
          - name: region
            value: '{{region}}'
      destination:
        server: '{{cluster}}'
        namespace: production
      syncPolicy:
        automated:
          prune: true
          selfHeal: true
        syncOptions:
        - CreateNamespace=true
```

---

## Summary

This module covered:

1. **Multi-cluster Patterns** - Geographic distribution, DR, workload segmentation
2. **Cluster API** - Automated cluster lifecycle management
3. **Federation** - kubefed and service mesh multi-cluster strategies
4. **Cross-cluster Networking** - Submariner and Cilium Cluster Mesh
5. **Identity Federation** - Centralized authentication and RBAC sync
6. **Disaster Recovery** - Backup, restore, RTO/RPO optimization
7. **Multi-region Deployments** - Traffic management and GitOps

## Hands-On Labs

1. Deploy multi-cluster environment with Cluster API
2. Implement service mesh federation with Istio
3. Configure cross-cluster networking with Submariner
4. Set up federated identity with Dex
5. Perform DR simulation and restore
6. Deploy multi-region application with ArgoCD
7. Implement global traffic management

## Additional Resources

- [Cluster API Documentation](https://cluster-api.sigs.k8s.io/)
- [KubeFed User Guide](https://github.com/kubernetes-sigs/kubefed)
- [Istio Multi-cluster Setup](https://istio.io/latest/docs/setup/install/multicluster/)
- [Submariner Architecture](https://submariner.io/getting-started/architecture/)
- [Cilium Cluster Mesh](https://docs.cilium.io/en/stable/network/clustermesh/)
- [Velero Documentation](https://velero.io/docs/)

---

**Next Module:** [Module 15 - Case Studies and Real-World Scenarios](15-case-studies.md)
