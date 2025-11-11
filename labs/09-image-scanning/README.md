# Lab 09: Container Image Scanning and Signing

## Objectives

By the end of this lab, you will:
- Scan container images for vulnerabilities using Trivy
- Understand CVE severity levels and remediation
- Implement image signing with Cosign
- Verify image signatures before deployment
- Integrate security scanning into CI/CD pipelines
- Implement image admission policies

## Prerequisites

- Completed Lab 00: Environment Setup
- Running Kubernetes cluster
- kubectl configured
- Docker installed
- Basic understanding of container images

## Estimated Time

60-75 minutes

## Supply Chain Security Concepts

**Key Components:**
- **Image Scanning**: Identify vulnerabilities in container images
- **Image Signing**: Cryptographically sign images
- **Signature Verification**: Verify images before deployment
- **SBOM**: Software Bill of Materials for transparency
- **Admission Control**: Enforce policies at deployment time

## Lab Scenario

You need to implement supply chain security for your containerized applications:
1. Scan images for vulnerabilities
2. Sign trusted images
3. Verify signatures during deployment
4. Block unsigned or vulnerable images

## Step-by-Step Instructions

### Step 1: Install Trivy

Trivy is a comprehensive vulnerability scanner for containers.

```bash
# Install Trivy
./scripts/install-trivy.sh

# Verify installation
trivy --version
```

### Step 2: Scan Container Images

Scan images for vulnerabilities.

```bash
# Scan a public image
trivy image nginx:latest

# Scan with specific severity
trivy image --severity HIGH,CRITICAL nginx:latest

# Generate JSON report
trivy image --format json --output trivy-report.json nginx:latest

# Scan with table format
trivy image --format table nginx:1.25-alpine
```

### Step 3: Understand CVE Results

Review the scan output:
- **CVE ID**: Common Vulnerabilities and Exposures identifier
- **Severity**: CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN
- **Package**: Affected software package
- **Fixed Version**: Version that resolves the vulnerability

```bash
# View only fixable vulnerabilities
trivy image --severity CRITICAL --ignore-unfixed nginx:latest

# Scan and count vulnerabilities
./scripts/count-vulnerabilities.sh nginx:latest
```

### Step 4: Scan Local and Private Images

```bash
# Build a test image
docker build -t myapp:v1 -f manifests/Dockerfile.sample .

# Scan local image
trivy image myapp:v1

# Scan image from private registry (if configured)
trivy image --username <user> --password <pass> myregistry.com/myapp:v1
```

### Step 5: Install Cosign for Image Signing

Cosign is a tool for signing and verifying container images.

```bash
# Install Cosign
./scripts/install-cosign.sh

# Verify installation
cosign version
```

### Step 6: Generate Signing Keys

```bash
# Generate key pair
cosign generate-key-pair

# This creates:
# - cosign.key (private key - keep secret!)
# - cosign.pub (public key - share this)

# Set password when prompted
# Store keys securely!

# View public key
cat cosign.pub
```

### Step 7: Sign Container Images

```bash
# Tag an image for our registry
docker tag nginx:alpine localhost:5000/nginx:signed

# Push to local registry (if running k3d)
docker push localhost:5000/nginx:signed

# Sign the image
cosign sign --key cosign.key localhost:5000/nginx:signed

# Enter private key password when prompted
```

### Step 8: Verify Image Signatures

```bash
# Verify signed image
cosign verify --key cosign.pub localhost:5000/nginx:signed

# The output should show signature verification details

# Try to verify unsigned image (should fail)
cosign verify --key cosign.pub nginx:alpine || echo "Verification failed (expected)"
```

### Step 9: Create Namespace and Apply Policies

```bash
# Create namespace for this lab
kubectl create namespace lab09-scanning

# Set default namespace
kubectl config set-context --current --namespace=lab09-scanning
```

### Step 10: Deploy Pre-Scanned Images

Deploy containers using scanned and approved images.

```bash
# Apply deployment with scanned image
kubectl apply -f manifests/deployment-scanned.yaml

# Check deployment
kubectl get deployment
kubectl get pods
```

### Step 11: Scan Images in Kubernetes

Use Trivy to scan running containers.

```bash
# Scan all images in a namespace
./scripts/scan-namespace.sh lab09-scanning

# Generate cluster-wide vulnerability report
./scripts/cluster-scan-report.sh
```

### Step 12: Implement Admission Control with Policy

Create a simple admission policy to block vulnerable images.

```bash
# Apply admission policy configuration
kubectl apply -f manifests/image-policy.yaml

# Try to deploy image with HIGH vulnerabilities (should be blocked)
# This requires an admission controller like OPA or Kyverno
```

### Step 13: Create CI/CD Integration Script

```bash
# Example CI/CD pipeline script
./scripts/ci-pipeline-scan.sh

# This script:
# 1. Builds image
# 2. Scans for vulnerabilities
# 3. Fails if CRITICAL vulnerabilities found
# 4. Signs image if scan passes
# 5. Pushes to registry
```

### Step 14: Generate SBOM

Software Bill of Materials provides transparency.

```bash
# Generate SBOM with Trivy
trivy image --format cyclonedx --output sbom.json nginx:alpine

# View SBOM
cat sbom.json | jq '.components[] | {name: .name, version: .version}'

# Generate SBOM with Syft (alternative tool)
# syft nginx:alpine -o json > sbom-syft.json
```

### Step 15: Vulnerability Remediation

```bash
# Run the remediation guide script
./scripts/vulnerability-remediation.sh nginx:latest

# This provides:
# - List of vulnerabilities
# - Recommended fixes
# - Alternative base images
# - Patch availability
```

### Step 16: Implement Scanning Policy

Create organizational scanning policies.

```bash
# Apply scanning policy
kubectl apply -f manifests/scanning-policy.yaml

# Test policy enforcement
./scripts/test-scan-policy.sh
```

### Step 17: Continuous Scanning

Set up periodic scanning of deployed images.

```bash
# Apply CronJob for continuous scanning
kubectl apply -f manifests/continuous-scan-cronjob.yaml

# View scan results
kubectl logs -l app=image-scanner
```

## Verification Checklist

- [ ] Trivy installed and working
- [ ] Can scan container images
- [ ] Understand CVE severity levels
- [ ] Cosign installed and working
- [ ] Can generate signing keys
- [ ] Can sign container images
- [ ] Can verify image signatures
- [ ] Scanned images deployed to cluster
- [ ] Namespace scanning works
- [ ] CI/CD integration script functions
- [ ] SBOM generation works
- [ ] Remediation guidance available

## Image Security Best Practices

1. **Scan All Images**: Scan before deployment and continuously
2. **Use Minimal Base Images**: Reduce attack surface (alpine, distroless)
3. **Update Regularly**: Keep base images and packages updated
4. **Sign Images**: Cryptographically sign trusted images
5. **Verify Signatures**: Always verify before deployment
6. **SBOM**: Generate and maintain SBOMs
7. **Admission Control**: Block vulnerable/unsigned images
8. **Private Registry**: Use private registry for internal images
9. **No Secrets in Images**: Never embed secrets in images
10. **Least Privilege**: Run as non-root, drop capabilities

## Trivy Scanning Options

```bash
# Basic scan
trivy image <image>

# Scan with severity filter
trivy image --severity CRITICAL,HIGH <image>

# Ignore unfixed vulnerabilities
trivy image --ignore-unfixed <image>

# Scan specific file
trivy filesystem /path/to/dir

# Scan Git repository
trivy repo https://github.com/org/repo

# Generate HTML report
trivy image --format template --template "@contrib/html.tpl" -o report.html <image>

# Scan with custom policy
trivy image --policy policy.rego <image>
```

## Cosign Usage Patterns

```bash
# Generate keys
cosign generate-key-pair

# Sign image
cosign sign --key cosign.key <image>

# Verify image
cosign verify --key cosign.pub <image>

# Sign with keyless mode (using OIDC)
cosign sign <image>

# Attach SBOM to image
cosign attach sbom --sbom sbom.json <image>

# Verify and download SBOM
cosign verify-attestation --key cosign.pub <image>
```

## Common Issues and Solutions

See [troubleshooting.md](./troubleshooting.md) for detailed solutions.

## Cleanup

```bash
# Delete namespace
kubectl delete namespace lab09-scanning

# Remove test images
docker rmi myapp:v1 localhost:5000/nginx:signed

# Or use cleanup script
./scripts/cleanup.sh
```

## Key Takeaways

1. **Image scanning** is critical for supply chain security
2. **Trivy** provides comprehensive vulnerability scanning
3. **Cosign** enables cryptographic image signing
4. **Signature verification** prevents tampering
5. **SBOM** provides transparency
6. **Admission control** enforces policies
7. **Continuous scanning** catches new vulnerabilities
8. **CI/CD integration** shifts security left

## Additional Challenges

1. **OPA/Gatekeeper**: Implement admission policies with OPA
2. **Kyverno**: Use Kyverno for image verification policies
3. **Notary**: Explore Docker Content Trust with Notary
4. **Sigstore**: Implement keyless signing with Sigstore
5. **Falco**: Add runtime security monitoring
6. **Harbor**: Deploy Harbor for secure registry with scanning

## Next Steps

Continue exploring:
- Runtime security with Falco
- Admission controllers (OPA, Kyverno)
- Secret management
- Compliance scanning
- Multi-cluster security

## Additional Resources

- [Trivy Documentation](https://aquasecurity.github.io/trivy/)
- [Cosign Documentation](https://docs.sigstore.dev/cosign/overview/)
- [Sigstore Project](https://www.sigstore.dev/)
- [SLSA Framework](https://slsa.dev/)
- [Supply Chain Security Best Practices](https://kubernetes.io/docs/concepts/security/supply-chain-security/)
- [SBOM and Software Transparency](https://www.cisa.gov/sbom)
