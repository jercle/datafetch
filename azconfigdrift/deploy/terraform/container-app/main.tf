# az-config-drift on Azure Container Apps: in an existing environment, or
# in a new one with its Log Analytics workspace (leave
# container_app_environment_id unset).
#
# Every replica runs the same schedule; a tenant is read by one replica at
# a time (see deploy/kubernetes/base/deployment.yaml for how). The collector
# listens on no port, so the app has no ingress and a fixed number of
# replicas: there is nothing to scale on.
#
# The app signs in to App Configuration with a user-assigned identity, so
# no secret is needed for that. The MongoDB address comes from Key Vault.

terraform {
  required_providers {
    azurerm = { source = "hashicorp/azurerm", version = ">= 4.0" }
  }
}

variable "name" {
  type    = string
  default = "az-config-drift"
}
variable "resource_group_name" { type = string }
variable "location" { type = string }
variable "container_app_environment_id" {
  type        = string
  default     = null
  description = "An existing Container Apps environment. Null: one is created, with a Log Analytics workspace."
}
variable "infrastructure_subnet_id" {
  type        = string
  default     = null
  description = "For a new environment: the subnet to put it in, when MongoDB is only reachable privately."
}
variable "cpu" {
  type    = number
  default = 0.5
}
variable "memory" {
  type        = string
  default     = "1Gi"
  description = "Use 2Gi with the PowerShell image (Dockerfile.pwsh)."
}
variable "image" {
  type        = string
  description = "The datafetch image, for example myregistry.azurecr.io/datafetch:1.4.0"
}
variable "registry_server" {
  type        = string
  description = "The Azure Container Registry the image is pulled from, e.g. myregistry.azurecr.io."
}
variable "registry_id" {
  type        = string
  description = "Resource ID of that registry, to let the app's identity pull from it."
}
variable "app_configuration_id" {
  type        = string
  description = "Resource ID of the App Configuration store holding datafetching.azConfigDrift.*"
}
variable "app_configuration_endpoint" { type = string }
variable "app_configuration_label" {
  type    = string
  default = ""
}
variable "mongo_uri_secret_id" {
  type        = string
  description = "Key Vault secret ID (versionless) of the MongoDB connection string."
}
variable "key_vault_id" { type = string }
variable "replicas" {
  type    = number
  default = 2
}
variable "tags" {
  type    = map(string)
  default = {}
}

resource "azurerm_log_analytics_workspace" "this" {
  count               = var.container_app_environment_id == null ? 1 : 0
  name                = "log-${var.name}"
  resource_group_name = var.resource_group_name
  location            = var.location
  sku                 = "PerGB2018"
  retention_in_days   = 30
  tags                = var.tags
}

resource "azurerm_container_app_environment" "this" {
  count                      = var.container_app_environment_id == null ? 1 : 0
  name                       = "cae-${var.name}"
  resource_group_name        = var.resource_group_name
  location                   = var.location
  log_analytics_workspace_id = azurerm_log_analytics_workspace.this[0].id
  infrastructure_subnet_id   = var.infrastructure_subnet_id
  tags                       = var.tags
}

locals {
  environment_id = coalesce(var.container_app_environment_id, try(azurerm_container_app_environment.this[0].id, null))
}

resource "azurerm_user_assigned_identity" "this" {
  name                = "id-${var.name}"
  resource_group_name = var.resource_group_name
  location            = var.location
  tags                = var.tags
}

resource "azurerm_role_assignment" "app_configuration" {
  scope                = var.app_configuration_id
  role_definition_name = "App Configuration Data Reader"
  principal_id         = azurerm_user_assigned_identity.this.principal_id
}

# Also for the Key Vault references among the settings (client secrets).
resource "azurerm_role_assignment" "key_vault" {
  scope                = var.key_vault_id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = azurerm_user_assigned_identity.this.principal_id
}

resource "azurerm_role_assignment" "registry" {
  scope                = var.registry_id
  role_definition_name = "AcrPull"
  principal_id         = azurerm_user_assigned_identity.this.principal_id
}

resource "azurerm_container_app" "this" {
  name                         = var.name
  resource_group_name          = var.resource_group_name
  container_app_environment_id = local.environment_id
  revision_mode                = "Single"
  tags                         = var.tags

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.this.id]
  }

  registry {
    server   = var.registry_server
    identity = azurerm_user_assigned_identity.this.id
  }

  secret {
    name                = "mongo-uri"
    key_vault_secret_id = var.mongo_uri_secret_id
    identity            = azurerm_user_assigned_identity.this.id
  }

  template {
    min_replicas = var.replicas
    max_replicas = var.replicas

    container {
      name   = "collector"
      image  = var.image
      args   = ["az-config-drift", "-loop"]
      cpu    = var.cpu
      memory = var.memory

      env {
        name  = "AZURE_APPCONFIG_ENDPOINT"
        value = var.app_configuration_endpoint
      }
      env {
        name  = "AZURE_APPCONFIG_MANAGED_IDENTITY"
        value = azurerm_user_assigned_identity.this.client_id
      }
      env {
        name  = "AZURE_APPCONFIG_LABEL"
        value = var.app_configuration_label
      }
      env {
        name        = "AZCONFIGDRIFT_MONGO_URI"
        secret_name = "mongo-uri"
      }
    }
  }

  # The first revision needs to pull the image and read the secret.
  depends_on = [azurerm_role_assignment.key_vault, azurerm_role_assignment.registry, azurerm_role_assignment.app_configuration]
}

output "principal_id" {
  value       = azurerm_user_assigned_identity.this.principal_id
  description = "The app's identity. It reads App Configuration and Key Vault; the tenants are read with the credentials in the settings."
}

output "container_app_environment_id" {
  value = local.environment_id
}
