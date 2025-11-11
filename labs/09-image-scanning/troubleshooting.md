# Lab 09: Image Scanning Troubleshooting

## Trivy Installation Issues

**Symptoms:**
Cannot install Trivy or command not found.

**Solutions:**
```bash
# For Linux (Debian/Ubuntu)
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee -a /etc/apt/sources.list.d/trivy.list
sudo apt-get update && sudo apt-get install -y trivy

# For macOS
brew install trivy

# Verify
trivy --version
```

## Trivy Database Update Errors

**Symptoms:**
```
Error: failed to download vulnerability DB
```

**Solutions:**
```bash
# Clear cache and retry
rm -rf ~/.cache/trivy
trivy image --download-db-only

# Use offline mode if needed
trivy image --skip-db-update <image>
```

## Cosign Key Generation Issues

**Symptoms:**
Cosign fails to generate keys.

**Solutions:**
```bash
# Ensure cosign is properly installed
cosign version

# Generate keys with explicit password
COSIGN_PASSWORD=mypassword cosign generate-key-pair

# Or use keyless mode
cosign sign <image>  # Uses OIDC
```

## Image Signing Permission Denied

**Symptoms:**
```
Error: signing <image>: PUT request failed: UNAUTHORIZED
```

**Solutions:**
```bash
# Login to registry first
docker login <registry>

# Or for local registry
docker login localhost:5000

# Then sign
cosign sign --key cosign.key <image>
```

## Cannot Verify Signature

**Symptoms:**
```
Error: no matching signatures
```

**Solutions:**
1. Ensure image was actually signed
2. Use correct public key
3. Check image reference matches exactly
```bash
cosign verify --key cosign.pub <exact-image-reference>
```

For full troubleshooting guide, see documentation.
