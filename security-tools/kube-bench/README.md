# kube-bench

CIS Kubernetes Benchmark assessment tool.

## Usage

```bash
# Create namespace
kubectl create namespace security-tools

# Create ServiceAccount with required permissions
kubectl apply -f rbac.yaml

# Run assessment
kubectl apply -f job.yaml

# View results
kubectl logs -n security-tools job/kube-bench
```

## Continuous Monitoring

Deploy as CronJob to run assessments regularly:

```bash
kubectl apply -f cronjob.yaml
```

Results are saved and can be forwarded to monitoring systems.
