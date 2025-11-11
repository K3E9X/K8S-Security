# Azure AKS Cluster with Security Best Practices
# WARNING: This creates resources that incur costs

terraform {
  required_version = ">= 1.5"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
  }
}

provider "azurerm" {
  features {}
}

# Variables
variable "resource_group_name" {
  description = "Resource group name"
  default     = "k8s-training-rg"
}

variable "location" {
  description = "Azure region"
  default     = "eastus"
}

variable "cluster_name" {
  description = "AKS cluster name"
  default     = "k8s-training-cluster"
}

# Resource Group
resource "azurerm_resource_group" "main" {
  name     = var.resource_group_name
  location = var.location

  tags = {
    Environment = "Training"
    ManagedBy   = "Terraform"
  }
}

# Virtual Network
resource "azurerm_virtual_network" "main" {
  name                = "${var.cluster_name}-vnet"
  address_space       = ["10.0.0.0/16"]
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
}

# Subnet for AKS
resource "azurerm_subnet" "aks" {
  name                 = "aks-subnet"
  resource_group_name  = azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = ["10.0.1.0/24"]
}

# AKS Cluster with Security Features
resource "azurerm_kubernetes_cluster" "main" {
  name                = var.cluster_name
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  dns_prefix          = var.cluster_name
  
  # Private cluster (recommended for production)
  # private_cluster_enabled = true
  
  # Enable RBAC
  role_based_access_control_enabled = true

  # Default node pool with security
  default_node_pool {
    name                = "default"
    node_count          = 2
    vm_size             = "Standard_D2s_v3"
    vnet_subnet_id      = azurerm_subnet.aks.id
    enable_auto_scaling = true
    min_count           = 2
    max_count           = 5
    
    # Security hardening
    upgrade_settings {
      max_surge = "33%"
    }
  }

  # Managed identity
  identity {
    type = "SystemAssigned"
  }

  # Network profile with network policy
  network_profile {
    network_plugin     = "azure"
    network_policy     = "calico"
    load_balancer_sku  = "standard"
    outbound_type      = "loadBalancer"
  }

  # Enable Azure AD integration
  # azure_active_directory_role_based_access_control {
  #   managed                = true
  #   admin_group_object_ids = []
  # }

  tags = {
    Environment = "Training"
    ManagedBy   = "Terraform"
  }
}

# Outputs
output "kube_config" {
  value     = azurerm_kubernetes_cluster.main.kube_config_raw
  sensitive = true
}

output "cluster_name" {
  value = azurerm_kubernetes_cluster.main.name
}

output "resource_group_name" {
  value = azurerm_resource_group.main.name
}
