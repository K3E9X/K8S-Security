# Module 05: Authentication and Authorization

## Overview

**Estimated Time:** 5-6 hours

**Module Type:** Security Deep Dive

**Prerequisites:**
- Module 01 - Kubernetes Basics
- Module 02 - Control Plane and Cluster Components
- Understanding of authentication concepts (certificates, tokens, OAuth/OIDC)

Security is paramount in Kubernetes. This module covers authentication (authn) and authorization (authz) mechanisms that control who can access the cluster and what they can do. You'll learn about kubeconfig files, service accounts, Role-Based Access Control (RBAC), and integration with external identity providers using OIDC. Understanding these concepts is essential for securing production Kubernetes clusters.

---

## Learning Objectives

By the end of this module, you will be able to:

1. Understand Kubernetes authentication mechanisms and strategies
2. Configure and use kubeconfig files and contexts
3. Implement Role-Based Access Control (RBAC) with Roles and RoleBindings
4. Create and manage Service Accounts for Pod authentication
5. Integrate external identity providers using OIDC
6. Apply principle of least privilege in RBAC policies
7. Troubleshoot authentication and authorization issues
8. Implement security best practices for cluster access control

---

## 1. Authentication Overview

### 1.1 What is Authentication?

Authentication is the process of verifying the identity of a user or service account accessing the Kubernetes API. Once authenticated, the request proceeds to authorization.

**Authentication Flow:**
1. Client sends request to API server with credentials
2. API server authenticates using configured authentication strategies
3. If successful, user identity is established
4. Request proceeds to authorization
5. If authorization succeeds, request is admitted and executed

### 1.2 User Types

**Normal Users:**
- Humans accessing the cluster
- Managed outside Kubernetes
- Typically authenticated via certificates or external identity providers
- No User API object in Kubernetes

**Service Accounts:**
- Processes running in Pods
- Managed by Kubernetes API
- Automatically mounted into Pods
- Represented as ServiceAccount objects

### 1.3 Authentication Strategies

Kubernetes supports multiple authentication strategies:

1. **X.509 Client Certificates**
   - Most common for cluster administrators
   - Certificates signed by cluster CA
   - User identified by certificate Common Name (CN)
   - Group membership from Organization (O) fields

2. **Static Token Files**
   - Pre-shared tokens in a file
   - Not recommended for production
   - No expiration or rotation

3. **Bootstrap Tokens**
   - Used for node bootstrapping
   - Time-limited
   - Stored as Secrets

4. **Service Account Tokens**
   - JWT tokens for service accounts
   - Automatically mounted in Pods
   - Can be created manually

5. **OpenID Connect (OIDC)**
   - Integration with external identity providers
   - Recommended for user authentication
   - Supports SSO and MFA

6. **Webhook Token Authentication**
   - External authentication service
   - Custom authentication logic
   - Bearer token verification

7. **Authenticating Proxy**
   - Proxy handles authentication
   - Passes user identity via headers
   - Used with corporate SSO systems

---

## 2. kubeconfig and Contexts

### 2.1 kubeconfig Structure

kubeconfig files contain cluster connection information and credentials.

**Structure:**
```yaml
apiVersion: v1
kind: Config
current-context: dev-cluster
clusters:
- name: dev-cluster
  cluster:
    certificate-authority-data: <base64-ca-cert>
    server: https://dev.example.com:6443
- name: prod-cluster
  cluster:
    certificate-authority-data: <base64-ca-cert>
    server: https://prod.example.com:6443
contexts:
- name: dev-context
  context:
    cluster: dev-cluster
    user: dev-admin
    namespace: development
- name: prod-context
  context:
    cluster: prod-cluster
    user: prod-admin
    namespace: production
users:
- name: dev-admin
  user:
    client-certificate-data: <base64-client-cert>
    client-key-data: <base64-client-key>
- name: prod-admin
  user:
    client-certificate-data: <base64-client-cert>
    client-key-data: <base64-client-key>
```

### 2.2 Creating kubeconfig

**Manual Creation:**

```bash
# Set cluster
kubectl config set-cluster dev-cluster \
  --server=https://dev.example.com:6443 \
  --certificate-authority=/path/to/ca.crt \
  --embed-certs=true

# Set credentials
kubectl config set-credentials dev-admin \
  --client-certificate=/path/to/client.crt \
  --client-key=/path/to/client.key \
  --embed-certs=true

# Set context
kubectl config set-context dev-context \
  --cluster=dev-cluster \
  --user=dev-admin \
  --namespace=development

# Use context
kubectl config use-context dev-context
```

### 2.3 Context Management

```bash
# View current context
kubectl config current-context

# List all contexts
kubectl config get-contexts

# Switch context
kubectl config use-context prod-context

# View kubeconfig
kubectl config view

# View kubeconfig with secrets
kubectl config view --raw

# Set default namespace for context
kubectl config set-context --current --namespace=production
```

### 2.4 Multiple kubeconfig Files

```bash
# Use multiple kubeconfig files
export KUBECONFIG=~/.kube/config:~/.kube/dev-config:~/.kube/prod-config

# Merge kubeconfig files
KUBECONFIG=~/.kube/config:~/.kube/dev-config kubectl config view --flatten > ~/.kube/merged-config
```

### 2.5 User Authentication with Certificates

**Generate User Certificate:**

```bash
# Generate private key
openssl genrsa -out developer.key 2048

# Create certificate signing request
openssl req -new -key developer.key -out developer.csr -subj "/CN=developer/O=engineering"

# Create CertificateSigningRequest
cat <<EOF | kubectl apply -f -
apiVersion: certificates.k8s.io/v1
kind: CertificateSigningRequest
metadata:
  name: developer-csr
spec:
  request: $(cat developer.csr | base64 | tr -d '\n')
  signerName: kubernetes.io/kube-apiserver-client
  expirationSeconds: 31536000  # 1 year
  usages:
  - client auth
EOF

# Approve CSR
kubectl certificate approve developer-csr

# Get certificate
kubectl get csr developer-csr -o jsonpath='{.status.certificate}' | base64 -d > developer.crt

# Create kubeconfig for user
kubectl config set-credentials developer \
  --client-certificate=developer.crt \
  --client-key=developer.key \
  --embed-certs=true
```

---

## 3. Role-Based Access Control (RBAC)

### 3.1 RBAC Overview

RBAC regulates access to Kubernetes resources based on roles assigned to users or service accounts.

**RBAC Components:**
- **Role:** Permissions within a namespace
- **ClusterRole:** Permissions cluster-wide
- **RoleBinding:** Binds Role to users/groups/service accounts in a namespace
- **ClusterRoleBinding:** Binds ClusterRole cluster-wide

### 3.2 Roles

**Namespace-Scoped Role:**

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: pod-reader
  namespace: development
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list", "watch"]
- apiGroups: [""]
  resources: ["pods/log"]
  verbs: ["get"]
```

**Common API Groups:**
- `""` (core) - Pods, Services, ConfigMaps, Secrets, etc.
- `apps` - Deployments, StatefulSets, DaemonSets, ReplicaSets
- `batch` - Jobs, CronJobs
- `rbac.authorization.k8s.io` - Roles, RoleBindings
- `networking.k8s.io` - Ingresses, NetworkPolicies

**Common Verbs:**
- `get`, `list`, `watch` - Read operations
- `create` - Create resources
- `update`, `patch` - Modify resources
- `delete`, `deletecollection` - Delete resources
- `*` - All verbs (use sparingly!)

**Advanced Role Example:**

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: developer-role
  namespace: production
rules:
# Allow full access to deployments
- apiGroups: ["apps"]
  resources: ["deployments"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
# Allow read access to pods
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list", "watch"]
# Allow pod logs access
- apiGroups: [""]
  resources: ["pods/log"]
  verbs: ["get", "list"]
# Allow exec into pods (debugging)
- apiGroups: [""]
  resources: ["pods/exec"]
  verbs: ["create"]
# Allow access to services
- apiGroups: [""]
  resources: ["services"]
  verbs: ["get", "list", "watch", "create", "update", "patch"]
# Allow ConfigMap read
- apiGroups: [""]
  resources: ["configmaps"]
  verbs: ["get", "list", "watch"]
# Deny Secret access (no rule = deny)
```

### 3.3 ClusterRoles

**Cluster-Wide Role:**

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: cluster-reader
rules:
- apiGroups: [""]
  resources: ["nodes", "persistentvolumes"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["storage.k8s.io"]
  resources: ["storageclasses"]
  verbs: ["get", "list", "watch"]
```

**ClusterRole for Namespace Resources:**

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: pod-reader-all-namespaces
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list", "watch"]
```

### 3.4 RoleBindings

**Bind Role to User:**

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: developer-binding
  namespace: production
subjects:
- kind: User
  name: developer
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: Role
  name: developer-role
  apiGroup: rbac.authorization.k8s.io
```

**Bind Role to Group:**

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: engineering-binding
  namespace: development
subjects:
- kind: Group
  name: engineering
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: Role
  name: developer-role
  apiGroup: rbac.authorization.k8s.io
```

**Bind Role to Service Account:**

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: app-binding
  namespace: production
subjects:
- kind: ServiceAccount
  name: app-sa
  namespace: production
roleRef:
  kind: Role
  name: app-role
  apiGroup: rbac.authorization.k8s.io
```

### 3.5 ClusterRoleBindings

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: cluster-admin-binding
subjects:
- kind: User
  name: admin
  apiGroup: rbac.authorization.k8s.io
- kind: Group
  name: cluster-admins
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: cluster-admin
  apiGroup: rbac.authorization.k8s.io
```

### 3.6 Built-in ClusterRoles

Kubernetes provides several built-in ClusterRoles:

**cluster-admin:**
- Superuser access
- Full permissions across cluster
- Use sparingly!

**admin:**
- Full access within a namespace
- Can create Roles and RoleBindings
- Cannot modify ResourceQuotas or namespace itself

**edit:**
- Read/write access to most resources in namespace
- Cannot view or modify Roles or RoleBindings
- Good for developers

**view:**
- Read-only access to most resources
- Cannot view Secrets or Roles/RoleBindings
- Good for monitoring

**Example Usage:**

```yaml
# Give user edit permissions in namespace
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: developer-edit
  namespace: development
subjects:
- kind: User
  name: developer
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: edit
  apiGroup: rbac.authorization.k8s.io
```

### 3.7 Aggregated ClusterRoles

```yaml
# Define aggregation rule
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: monitoring
aggregationRule:
  clusterRoleSelectors:
  - matchLabels:
      rbac.example.com/aggregate-to-monitoring: "true"
rules: []  # Rules automatically filled
---
# ClusterRole that aggregates
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: monitoring-pods
  labels:
    rbac.example.com/aggregate-to-monitoring: "true"
rules:
- apiGroups: [""]
  resources: ["pods", "pods/log"]
  verbs: ["get", "list", "watch"]
```

### 3.8 Resource-Specific Permissions

**Limit access to specific resource instances:**

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: configmap-reader
  namespace: production
rules:
- apiGroups: [""]
  resources: ["configmaps"]
  resourceNames: ["app-config", "database-config"]  # Only these
  verbs: ["get", "list"]
```

**Subresources:**

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: pod-debugger
  namespace: production
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list"]
- apiGroups: [""]
  resources: ["pods/exec", "pods/log", "pods/portforward"]
  verbs: ["create", "get"]
```

---

## 4. Service Accounts

### 4.1 What are Service Accounts?

Service Accounts provide an identity for processes running in Pods. They are used for Pod-to-API server authentication.

**Automatic Creation:**
- Every namespace has a `default` service account
- Automatically mounted in Pods at `/var/run/secrets/kubernetes.io/serviceaccount/`

### 4.2 Creating Service Accounts

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: app-sa
  namespace: production
  labels:
    app: myapp
automountServiceAccountToken: true
```

**Create with kubectl:**

```bash
kubectl create serviceaccount app-sa -n production
```

### 4.3 Using Service Accounts in Pods

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: app-pod
  namespace: production
spec:
  serviceAccountName: app-sa
  automountServiceAccountToken: true
  containers:
  - name: app
    image: myapp:1.0
```

**Disable auto-mounting:**

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: app-pod
spec:
  serviceAccountName: app-sa
  automountServiceAccountToken: false  # Don't mount SA token
  containers:
  - name: app
    image: myapp:1.0
```

### 4.4 Service Account Tokens

**Token Location in Pod:**
```bash
# Inside Pod
cat /var/run/secrets/kubernetes.io/serviceaccount/token
cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
cat /var/run/secrets/kubernetes.io/serviceaccount/namespace
```

**Create Token Manually (1.24+):**

```bash
kubectl create token app-sa -n production --duration=8h
```

**Legacy Token Secret (pre-1.24):**

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: app-sa-token
  namespace: production
  annotations:
    kubernetes.io/service-account.name: app-sa
type: kubernetes.io/service-account-token
```

### 4.5 Service Account with RBAC

**Complete Example:**

```yaml
# Service Account
apiVersion: v1
kind: ServiceAccount
metadata:
  name: pod-reader-sa
  namespace: production
---
# Role
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: pod-reader-role
  namespace: production
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list", "watch"]
---
# RoleBinding
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: pod-reader-binding
  namespace: production
subjects:
- kind: ServiceAccount
  name: pod-reader-sa
  namespace: production
roleRef:
  kind: Role
  name: pod-reader-role
  apiGroup: rbac.authorization.k8s.io
---
# Pod using Service Account
apiVersion: v1
kind: Pod
metadata:
  name: pod-reader-pod
  namespace: production
spec:
  serviceAccountName: pod-reader-sa
  containers:
  - name: kubectl
    image: bitnami/kubectl:latest
    command: ['sh', '-c', 'while true; do kubectl get pods; sleep 30; done']
```

---

## 5. OIDC Integration

### 5.1 What is OIDC?

OpenID Connect (OIDC) is an identity layer on top of OAuth 2.0. It allows Kubernetes to integrate with external identity providers like:

- Azure Active Directory
- Google Identity
- Okta
- Keycloak
- Auth0
- Dex

### 5.2 API Server OIDC Configuration

**API Server Flags:**

```yaml
# kube-apiserver configuration
spec:
  containers:
  - name: kube-apiserver
    command:
    - kube-apiserver
    - --oidc-issuer-url=https://accounts.google.com
    - --oidc-client-id=kubernetes
    - --oidc-username-claim=email
    - --oidc-groups-claim=groups
    - --oidc-ca-file=/etc/kubernetes/pki/oidc-ca.crt
    - --oidc-username-prefix=oidc:
    - --oidc-groups-prefix=oidc:
```

**Flag Descriptions:**
- `--oidc-issuer-url`: OIDC provider URL
- `--oidc-client-id`: Client ID for the cluster
- `--oidc-username-claim`: JWT claim for username
- `--oidc-groups-claim`: JWT claim for groups
- `--oidc-ca-file`: CA certificate for OIDC provider
- `--oidc-username-prefix`: Prefix for usernames
- `--oidc-groups-prefix`: Prefix for groups

### 5.3 kubeconfig with OIDC

**Using oidc-login kubectl plugin:**

```bash
# Install oidc-login
kubectl krew install oidc-login
```

```yaml
apiVersion: v1
kind: Config
users:
- name: oidc-user
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1beta1
      command: kubectl
      args:
      - oidc-login
      - get-token
      - --oidc-issuer-url=https://accounts.google.com
      - --oidc-client-id=kubernetes
      - --oidc-client-secret=secret
```

### 5.4 OIDC with RBAC

```yaml
# ClusterRoleBinding for OIDC group
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: engineering-admin
subjects:
- kind: Group
  name: oidc:engineering@example.com
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: admin
  apiGroup: rbac.authorization.k8s.io
```

### 5.5 Dex as OIDC Provider

**Dex Deployment:**

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: dex
  namespace: auth
spec:
  replicas: 1
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
        ports:
        - containerPort: 5556
        volumeMounts:
        - name: config
          mountPath: /etc/dex
      volumes:
      - name: config
        configMap:
          name: dex-config
```

**Dex ConfigMap:**

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: dex-config
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
        bindDN: cn=admin,dc=example,dc=com
        bindPW: password
        userSearch:
          baseDN: ou=users,dc=example,dc=com
          filter: "(objectClass=person)"
          username: uid
          idAttr: uid
          emailAttr: mail
        groupSearch:
          baseDN: ou=groups,dc=example,dc=com
          filter: "(objectClass=groupOfNames)"
          userAttr: DN
          groupAttr: member
          nameAttr: cn
    staticClients:
    - id: kubernetes
      redirectURIs:
      - http://localhost:8000
      - http://localhost:18000
      name: 'Kubernetes'
      secret: kubernetes-secret
```

---

## 6. Authentication and Authorization Flow Diagram

```mermaid
sequenceDiagram
    participant User
    participant kubectl
    participant APIServer as API Server
    participant Authn as Authentication
    participant Authz as Authorization
    participant AdmCtrl as Admission Control
    participant etcd

    User->>kubectl: kubectl get pods
    kubectl->>kubectl: Load kubeconfig<br/>Get credentials
    kubectl->>APIServer: HTTPS Request<br/>TLS + Bearer Token/Cert

    APIServer->>Authn: Authenticate Request

    alt X.509 Certificate
        Authn->>Authn: Verify cert signature<br/>Extract CN (user)<br/>Extract O (groups)
    else OIDC Token
        Authn->>Authn: Validate JWT<br/>Extract claims<br/>Get user & groups
    else Service Account
        Authn->>Authn: Verify SA token<br/>Get SA identity
    end

    Authn-->>APIServer: Identity: user=alice<br/>groups=[developers]

    APIServer->>Authz: Authorize Request<br/>user, resource, verb

    Authz->>Authz: Check RBAC rules<br/>Role, RoleBinding<br/>ClusterRole, ClusterRoleBinding

    alt Authorized
        Authz-->>APIServer: Allow
    else Not Authorized
        Authz-->>APIServer: Deny (403 Forbidden)
        APIServer-->>kubectl: Error: Forbidden
        kubectl-->>User: Error message
    end

    APIServer->>AdmCtrl: Mutating Webhooks
    AdmCtrl->>AdmCtrl: Modify request if needed
    AdmCtrl-->>APIServer: Modified request

    APIServer->>AdmCtrl: Validating Webhooks
    AdmCtrl->>AdmCtrl: Validate request

    alt Valid
        AdmCtrl-->>APIServer: Allow
    else Invalid
        AdmCtrl-->>APIServer: Deny (400 Bad Request)
        APIServer-->>kubectl: Error: Invalid
        kubectl-->>User: Error message
    end

    APIServer->>etcd: Store/Retrieve resource
    etcd-->>APIServer: Resource data

    APIServer-->>kubectl: Success Response<br/>Resource data
    kubectl-->>User: Display result

    style Authn fill:#FF6B6B,stroke:#fff,color:#fff
    style Authz fill:#4ECDC4,stroke:#fff,color:#fff
    style AdmCtrl fill:#95E1D3,stroke:#fff,color:#000
    style APIServer fill:#326CE5,stroke:#fff,color:#fff
```

---

## 7. Best Practices

### 7.1 Authentication Best Practices

1. **Use OIDC for user authentication**
   - Centralized identity management
   - MFA support
   - Audit trail
   - Token expiration

2. **Avoid static credentials**
   - No static token files
   - No long-lived tokens
   - Rotate certificates regularly

3. **Use short-lived tokens**
   - Service account token TTL
   - Regular rotation
   - Automatic expiration

4. **Enable audit logging**
   - Track authentication attempts
   - Monitor failed logins
   - Compliance requirements

### 7.2 RBAC Best Practices

1. **Principle of least privilege**
   - Grant minimum permissions needed
   - Start restrictive, add as needed
   - Regular permission reviews

2. **Use Roles over ClusterRoles when possible**
   - Namespace isolation
   - Limit blast radius
   - Easier to manage

3. **Avoid wildcards**
```yaml
# DON'T
rules:
- apiGroups: ["*"]
  resources: ["*"]
  verbs: ["*"]

# DO
rules:
- apiGroups: [""]
  resources: ["pods", "services"]
  verbs: ["get", "list", "watch"]
```

4. **Use groups instead of individual users**
   - Easier management
   - Consistent permissions
   - Better for OIDC integration

5. **Separate service accounts per application**
   - Isolation between apps
   - Granular permissions
   - Better audit trail

6. **Regular RBAC audits**
   - Review permissions quarterly
   - Remove unused bindings
   - Check for privilege escalation

### 7.3 Service Account Best Practices

1. **Don't use default service account**
```yaml
# Create dedicated SA
apiVersion: v1
kind: ServiceAccount
metadata:
  name: myapp-sa
---
spec:
  serviceAccountName: myapp-sa
```

2. **Disable auto-mounting when not needed**
```yaml
spec:
  automountServiceAccountToken: false
```

3. **Use bound service account tokens (1.24+)**
   - Time-limited
   - Audience-bound
   - More secure

4. **Minimize service account permissions**
   - Only what app needs
   - No cluster-admin
   - Namespace-scoped when possible

---

## 8. Anti-Patterns and Common Mistakes

### 8.1 Authentication Anti-Patterns

❌ **Using admin credentials for everything**
- Security risk
- No accountability
- Violates least privilege

❌ **Sharing kubeconfig files**
- No individual accountability
- Cannot revoke individual access
- Compliance violations

❌ **Long-lived static tokens**
```yaml
# INSECURE
--token-auth-file=/etc/kubernetes/tokens.csv
```

### 8.2 RBAC Anti-Patterns

❌ **Overly permissive roles**
```yaml
# TOO PERMISSIVE
rules:
- apiGroups: ["*"]
  resources: ["*"]
  verbs: ["*"]
```

❌ **Granting cluster-admin unnecessarily**
```yaml
# DANGEROUS - Only for actual admins
roleRef:
  kind: ClusterRole
  name: cluster-admin
```

❌ **Ignoring namespace boundaries**
```yaml
# Creates security risk
kind: ClusterRoleBinding  # Should be RoleBinding
```

❌ **Not using resource names**
```yaml
# Allows access to ALL secrets
resources: ["secrets"]
verbs: ["get"]

# Better - specific secrets
resources: ["secrets"]
resourceNames: ["app-secret"]
verbs: ["get"]
```

### 8.3 Service Account Anti-Patterns

❌ **Using default service account**
```yaml
# DON'T rely on default
spec:
  # serviceAccountName: default (implicit)
```

❌ **Granting unnecessary permissions to Pods**
```yaml
# Pod doesn't need API access but SA has permissions
spec:
  serviceAccountName: powerful-sa  # Unnecessary
  automountServiceAccountToken: true
```

❌ **Not rotating service account tokens**
- Long-lived tokens
- Security risk if compromised
- Use short-lived tokens

---

## 9. RBAC Examples and Common Patterns

### 9.1 Developer Role

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: developer
  namespace: development
rules:
# Full access to deployments, services
- apiGroups: ["apps"]
  resources: ["deployments", "replicasets"]
  verbs: ["*"]
- apiGroups: [""]
  resources: ["services", "configmaps"]
  verbs: ["*"]
# Read-only for pods
- apiGroups: [""]
  resources: ["pods", "pods/log"]
  verbs: ["get", "list", "watch"]
# Exec into pods for debugging
- apiGroups: [""]
  resources: ["pods/exec"]
  verbs: ["create"]
# No access to secrets
```

### 9.2 CI/CD Role

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: cicd-deployer
  namespace: production
rules:
# Deploy applications
- apiGroups: ["apps"]
  resources: ["deployments"]
  verbs: ["get", "list", "create", "update", "patch"]
# Manage services
- apiGroups: [""]
  resources: ["services"]
  verbs: ["get", "list", "create", "update", "patch"]
# Read-only for pods (verification)
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list", "watch"]
# Manage ConfigMaps
- apiGroups: [""]
  resources: ["configmaps"]
  verbs: ["get", "list", "create", "update", "patch"]
# No delete permissions
```

### 9.3 Read-Only Cluster Viewer

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: cluster-viewer
rules:
- apiGroups: [""]
  resources: ["nodes", "namespaces", "persistentvolumes"]
  verbs: ["get", "list", "watch"]
- apiGroups: [""]
  resources: ["pods", "services", "configmaps"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["apps"]
  resources: ["deployments", "statefulsets", "daemonsets"]
  verbs: ["get", "list", "watch"]
# No secrets access
# No write permissions
```

### 9.4 Monitoring Role

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: monitoring
rules:
# Metrics
- apiGroups: [""]
  resources: ["nodes/metrics", "pods/metrics"]
  verbs: ["get", "list"]
# Node and pod info
- apiGroups: [""]
  resources: ["nodes", "pods"]
  verbs: ["get", "list", "watch"]
# Resource metrics
- apiGroups: ["metrics.k8s.io"]
  resources: ["nodes", "pods"]
  verbs: ["get", "list"]
```

### 9.5 Namespace Admin

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: team-admin
  namespace: team-namespace
subjects:
- kind: Group
  name: team-leads
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: admin  # Built-in admin role
  apiGroup: rbac.authorization.k8s.io
```

---

## 10. Troubleshooting

### 10.1 Check User Permissions

```bash
# Can I create pods?
kubectl auth can-i create pods

# Can I delete deployments in namespace?
kubectl auth can-i delete deployments -n production

# Can specific user do action?
kubectl auth can-i list secrets --as=developer -n production

# Check all permissions for user
kubectl auth can-i --list --as=developer -n production
```

### 10.2 Verify RBAC Configuration

```bash
# List all roles in namespace
kubectl get roles -n production

# Describe role
kubectl describe role developer -n production

# List role bindings
kubectl get rolebindings -n production

# Describe role binding
kubectl describe rolebinding developer-binding -n production

# List cluster roles
kubectl get clusterroles

# List cluster role bindings
kubectl get clusterrolebindings
```

### 10.3 Debug Authentication Issues

```bash
# View kubeconfig
kubectl config view

# Check current user
kubectl config current-context

# Verify API server connectivity
kubectl cluster-info

# Check certificate expiration
kubeadm certs check-expiration

# View audit logs (on control plane)
cat /var/log/kubernetes/audit.log | jq '.user.username'
```

---

## 11. Hands-on Lab References

This module includes the following hands-on labs in the `/labs/05-authn-authz/` directory:

1. **Lab 5.1: User Authentication with Certificates**
   - Generate user certificates
   - Create kubeconfig
   - Test authentication
   - File: `/labs/05-authn-authz/lab-5.1-user-authn.md`

2. **Lab 5.2: RBAC Basics**
   - Create Roles and RoleBindings
   - Test permissions
   - Use built-in roles
   - File: `/labs/05-authn-authz/lab-5.2-rbac-basics.md`

3. **Lab 5.3: Service Accounts**
   - Create service accounts
   - Bind roles to service accounts
   - Use in Pods
   - File: `/labs/05-authn-authz/lab-5.3-service-accounts.md`

4. **Lab 5.4: OIDC Integration**
   - Configure OIDC provider
   - Set up API server
   - Test OIDC authentication
   - File: `/labs/05-authn-authz/lab-5.4-oidc.md`

5. **Lab 5.5: RBAC Troubleshooting**
   - Debug permission issues
   - Audit RBAC configuration
   - Fix common problems
   - File: `/labs/05-authn-authz/lab-5.5-troubleshooting.md`

---

## 12. Security Checklist

### Authentication
- [ ] Use OIDC for user authentication in production
- [ ] Disable anonymous authentication (--anonymous-auth=false)
- [ ] Enable audit logging for authentication events
- [ ] Rotate certificates before expiration
- [ ] Use short-lived tokens (not static tokens)
- [ ] Implement MFA via OIDC provider
- [ ] Disable insecure authentication methods
- [ ] Use TLS for all API server connections

### Authorization (RBAC)
- [ ] Enable RBAC (--authorization-mode=Node,RBAC)
- [ ] Follow principle of least privilege
- [ ] Use Roles over ClusterRoles when possible
- [ ] Avoid wildcard permissions (*) in production
- [ ] Regular RBAC audit (quarterly minimum)
- [ ] Document all custom roles
- [ ] Use groups instead of individual users
- [ ] Implement namespace isolation with RBAC
- [ ] Restrict access to cluster-admin role
- [ ] Monitor for privilege escalation attempts

### Service Accounts
- [ ] Create dedicated service accounts per application
- [ ] Don't use default service account
- [ ] Disable automountServiceAccountToken when not needed
- [ ] Use bound service account tokens (1.24+)
- [ ] Minimize service account permissions
- [ ] Regular service account audit
- [ ] Implement service account token rotation
- [ ] Use namespace-scoped permissions

### Secrets Management
- [ ] Restrict access to secrets via RBAC
- [ ] Use external secret management (Vault, etc.)
- [ ] Enable encryption at rest for secrets
- [ ] Audit secret access
- [ ] Rotate secrets regularly
- [ ] Don't log secrets
- [ ] Use immutable secrets when appropriate

### Compliance and Audit
- [ ] Enable comprehensive audit logging
- [ ] Retain audit logs per compliance requirements
- [ ] Monitor authentication failures
- [ ] Track privilege escalation attempts
- [ ] Regular access reviews
- [ ] Document all custom RBAC policies
- [ ] Implement alerting for suspicious activities

---

## 13. References

1. **Kubernetes Official Documentation**
   - Authentication: https://kubernetes.io/docs/reference/access-authn-authz/authentication/
   - Authorization: https://kubernetes.io/docs/reference/access-authn-authz/authorization/
   - RBAC: https://kubernetes.io/docs/reference/access-authn-authz/rbac/
   - Service Accounts: https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/
   - Admission Controllers: https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/

2. **Security Best Practices**
   - CIS Kubernetes Benchmark: https://www.cisecurity.org/benchmark/kubernetes
   - NSA/CISA Kubernetes Hardening Guide: https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF
   - OWASP Kubernetes Security Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Kubernetes_Security_Cheat_Sheet.html

3. **OIDC and Identity**
   - OpenID Connect Core: https://openid.net/specs/openid-connect-core-1_0.html
   - Dex Documentation: https://dexidp.io/docs/
   - Keycloak Documentation: https://www.keycloak.org/documentation

4. **Tools**
   - kubectl-who-can: https://github.com/aquasecurity/kubectl-who-can
   - rbac-lookup: https://github.com/FairwindsOps/rbac-lookup
   - rakkess: https://github.com/corneliusweig/rakkess
   - audit2rbac: https://github.com/liggitt/audit2rbac

5. **CNCF Resources**
   - CNCF Security TAG: https://github.com/cncf/tag-security
   - Kubernetes SIG Auth: https://github.com/kubernetes/community/tree/master/sig-auth

6. **Books and Guides**
   - "Kubernetes Security" by Liz Rice and Michael Hausenblas (O'Reilly)
   - "Kubernetes Best Practices" by Brendan Burns et al. (O'Reilly)
   - "Managing Kubernetes" by Brendan Burns and Craig Tracey (O'Reilly)

---

## Summary

In this module, you learned about Kubernetes authentication and authorization:

**Authentication:**
- Multiple authentication strategies (certificates, OIDC, service accounts)
- kubeconfig files and context management
- User certificate generation and management
- OIDC integration for enterprise identity providers

**Authorization (RBAC):**
- Roles and ClusterRoles define permissions
- RoleBindings and ClusterRoleBindings assign permissions
- Built-in roles (cluster-admin, admin, edit, view)
- Principle of least privilege

**Service Accounts:**
- Identity for Pods and processes
- Bound to namespaces
- Used with RBAC for Pod authorization
- Token management and rotation

**Best Practices:**
- Use OIDC for user authentication
- Implement least privilege with RBAC
- Create dedicated service accounts per application
- Regular audits and access reviews
- Comprehensive audit logging

**Security:**
- Disable anonymous authentication
- Avoid wildcard permissions
- Regular certificate rotation
- Monitor for privilege escalation
- Implement namespace isolation

Understanding authentication and authorization is critical for securing Kubernetes clusters. These mechanisms form the foundation of cluster security and must be properly configured and maintained.

---

**Training Modules Complete!**

This concludes the Kubernetes training modules. You now have comprehensive knowledge of:
- Module 01: Kubernetes Basics
- Module 02: Control Plane and Cluster Components
- Module 03: Networking
- Module 04: Storage
- Module 05: Authentication and Authorization

Continue to the hands-on labs to reinforce your learning and gain practical experience!
