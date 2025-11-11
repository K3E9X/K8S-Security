# Terraform Examples (Optional)

⚠️ **WARNING**: These are OPTIONAL examples for advanced labs requiring cloud resources.

- All core training content works with local clusters (kind, k3d, minikube)
- Cloud resources incur costs
- Always destroy resources after use

## Azure Examples

The `azure/` directory contains:
- AKS cluster with security best practices
- Network policies and private cluster configuration
- Azure AD integration
- Key Vault integration for secrets

## Usage

```bash
cd terraform/azure

# Initialize
terraform init

# Review plan (shows cost estimate)
terraform plan

# Create resources (COSTS MONEY)
terraform apply

# When done, destroy resources
terraform destroy
```

## Cost Estimates

**Basic AKS cluster**: ~$150-200/month
**Production AKS**: ~$500-1000/month

Always use cost calculators and set budget alerts.
