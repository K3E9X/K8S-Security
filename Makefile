.PHONY: help kind-up kind-down k3d-up k3d-down deploy-sample cleanup run-kube-bench run-trivy docs-serve docs-build lint validate test-labs

# Default target
.DEFAULT_GOAL := help

# Variables
CLUSTER_NAME := training-cluster
KIND_CONFIG := labs/scripts/kind-config.yaml

## help: Show this help message
help:
	@echo "Kubernetes Architecture and Security Training - Make Commands"
	@echo ""
	@echo "Cluster Management:"
	@echo "  make kind-up           Create kind cluster"
	@echo "  make kind-down         Delete kind cluster"
	@echo "  make k3d-up            Create k3d cluster"
	@echo "  make k3d-down          Delete k3d cluster"
	@echo ""
	@echo "Application Deployment:"
	@echo "  make deploy-sample     Deploy sample application"
	@echo "  make cleanup           Remove all deployments"
	@echo ""
	@echo "Security Tools:"
	@echo "  make run-kube-bench    Run CIS benchmark scan"
	@echo "  make run-trivy         Scan images for vulnerabilities"
	@echo ""
	@echo "Documentation:"
	@echo "  make docs-serve        Serve documentation locally"
	@echo "  make docs-build        Build static documentation site"
	@echo ""
	@echo "Testing:"
	@echo "  make lint              Lint YAML and markdown"
	@echo "  make validate          Validate Kubernetes manifests"
	@echo "  make test-labs         Run lab smoke tests"

## kind-up: Create kind cluster
kind-up:
	@echo "Creating kind cluster..."
	@./labs/scripts/setup-kind.sh

## kind-down: Delete kind cluster
kind-down:
	@echo "Deleting kind cluster..."
	@kind delete cluster --name $(CLUSTER_NAME) || true

## k3d-up: Create k3d cluster
k3d-up:
	@echo "Creating k3d cluster..."
	@./labs/scripts/setup-k3d.sh

## k3d-down: Delete k3d cluster
k3d-down:
	@echo "Deleting k3d cluster..."
	@k3d cluster delete $(CLUSTER_NAME) || true

## deploy-sample: Deploy sample application
deploy-sample:
	@echo "Deploying sample application..."
	@kubectl create namespace demo --dry-run=client -o yaml | kubectl apply -f -
	@kubectl apply -f examples/manifests/deployments/secure-nginx.yaml -n demo
	@echo "Sample app deployed! Check with: kubectl get pods -n demo"

## cleanup: Remove all deployments
cleanup:
	@echo "Cleaning up deployments..."
	@kubectl delete namespace demo --ignore-not-found=true
	@echo "Cleanup complete!"

## run-kube-bench: Run CIS benchmark scan
run-kube-bench:
	@echo "Running kube-bench CIS scan..."
	@kubectl create namespace security-tools --dry-run=client -o yaml | kubectl apply -f -
	@kubectl apply -f security-tools/kube-bench/job.yaml
	@echo "Waiting for job to complete..."
	@kubectl wait --for=condition=complete job/kube-bench -n security-tools --timeout=120s || true
	@kubectl logs -n security-tools job/kube-bench

## run-trivy: Scan images for vulnerabilities
run-trivy:
	@echo "Scanning images with Trivy..."
	@./security-tools/trivy/scan-script.sh nginx:1.25-alpine

## docs-serve: Serve documentation locally
docs-serve:
	@echo "Serving documentation on http://localhost:8000"
	@mkdocs serve

## docs-build: Build static documentation site
docs-build:
	@echo "Building documentation..."
	@mkdocs build
	@echo "Documentation built in site/"

## lint: Lint YAML and markdown files
lint:
	@echo "Linting markdown files..."
	@markdownlint '**/*.md' --ignore node_modules --ignore .github || true
	@echo "Linting YAML files..."
	@yamllint . || true

## validate: Validate Kubernetes manifests
validate:
	@echo "Validating Kubernetes YAML manifests..."
	@find examples labs -name "*.yaml" -o -name "*.yml" | while read file; do \
		echo "Validating $$file"; \
		kubectl apply --dry-run=client -f "$$file" 2>&1 || true; \
	done

## test-labs: Run lab smoke tests
test-labs:
	@echo "Running lab smoke tests..."
	@./labs/scripts/setup-kind.sh
	@kubectl create namespace smoke-test
	@kubectl run test-pod --image=nginx:1.25 -n smoke-test
	@kubectl wait --for=condition=Ready pod/test-pod -n smoke-test --timeout=60s
	@kubectl delete namespace smoke-test
	@echo "Lab tests passed!"
