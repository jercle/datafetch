# The Azure side of running az-config-drift on an existing AKS cluster:
#
# - an identity the Secrets Store CSI driver uses, through workload
#   identity, to read the collector's two secrets from Key Vault;
# - those two secrets (optional: leave the values empty to manage them
#   elsewhere);
# - pull access to the registry for the cluster's kubelet.
#
# What runs in the cluster is in deploy/kubernetes (kustomize), applied by
# Argo CD (deploy/argocd) or by hand. The outputs are the values the
# production overlay has placeholders for.
#
# The cluster needs: the OIDC issuer and workload identity enabled, and the
# add-on azure-keyvault-secrets-provider.
#
# Not applied by the author: plan it against your provider versions.

terraform {
  required_version = ">= 1.6"
  required_providers {
    azurerm = { source = "hashicorp/azurerm", version = ">= 4.0" }
  }
}

variable "resource_group_name" {
  type        = string
  description = "Where the identity is created."
}
variable "location" { type = string }
variable "aks_oidc_issuer_url" {
  type        = string
  description = "azurerm_kubernetes_cluster.<name>.oidc_issuer_url"
}
variable "aks_kubelet_object_id" {
  type        = string
  default     = null
  description = "azurerm_kubernetes_cluster.<name>.kubelet_identity[0].object_id. Set together with registry_id to let the cluster pull the image."
}
variable "registry_id" {
  type    = string
  default = null
}
variable "key_vault_id" { type = string }
variable "namespace" {
  type    = string
  default = "az-config-drift"
}
variable "service_account" {
  type    = string
  default = "az-config-drift"
}
variable "appconfig_client_secret" {
  type        = string
  default     = ""
  sensitive   = true
  description = "Client secret of the service principal that reads App Configuration. Empty: the Key Vault secret is not managed here."
}
variable "mongo_uri" {
  type        = string
  default     = ""
  sensitive   = true
  description = "MongoDB connection string. Empty: the Key Vault secret is not managed here."
}
variable "tags" {
  type    = map(string)
  default = {}
}

data "azurerm_client_config" "current" {}

resource "azurerm_user_assigned_identity" "secrets" {
  name                = "id-az-config-drift-secrets"
  resource_group_name = var.resource_group_name
  location            = var.location
  tags                = var.tags
}

# Only pods running as this service account in this namespace can use it.
resource "azurerm_federated_identity_credential" "secrets" {
  name                = "az-config-drift"
  resource_group_name = var.resource_group_name
  parent_id           = azurerm_user_assigned_identity.secrets.id
  audience            = ["api://AzureADTokenExchange"]
  issuer              = var.aks_oidc_issuer_url
  subject             = "system:serviceaccount:${var.namespace}:${var.service_account}"
}

resource "azurerm_role_assignment" "key_vault" {
  scope                = var.key_vault_id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = azurerm_user_assigned_identity.secrets.principal_id
}

resource "azurerm_role_assignment" "registry" {
  count                = var.registry_id != null && var.aks_kubelet_object_id != null ? 1 : 0
  scope                = var.registry_id
  role_definition_name = "AcrPull"
  principal_id         = var.aks_kubelet_object_id
}

# The names the production overlay's SecretProviderClass asks for.
resource "azurerm_key_vault_secret" "appconfig_client_secret" {
  count        = var.appconfig_client_secret != "" ? 1 : 0
  name         = "az-config-drift-appconfig-client-secret"
  value        = var.appconfig_client_secret
  key_vault_id = var.key_vault_id
}

resource "azurerm_key_vault_secret" "mongo_uri" {
  count        = var.mongo_uri != "" ? 1 : 0
  name         = "az-config-drift-mongo-uri"
  value        = var.mongo_uri
  key_vault_id = var.key_vault_id
}

output "secrets_identity_client_id" {
  value       = azurerm_user_assigned_identity.secrets.client_id
  description = "For the ServiceAccount annotation and the SecretProviderClass clientID in deploy/kubernetes/overlays/production."
}
output "tenant_id" {
  value       = data.azurerm_client_config.current.tenant_id
  description = "For the SecretProviderClass tenantId."
}
