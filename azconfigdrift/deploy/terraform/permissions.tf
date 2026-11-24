# What the collector's service principal needs in one tenant: Reader on a
# management group (the root one, to see everything) and the Microsoft Graph
# application permissions its Microsoft 365 modules read with. Apply once
# per tenant. Not applied or planned by the author: check it against your
# provider versions. Granting Graph application permissions needs a Global
# Administrator or Privileged Role Administrator.
#
# A permission you leave out only makes its sources show as "No permission"
# in the dashboard; switch those sources off there, or add the permission.

terraform {
  required_providers {
    azurerm = { source = "hashicorp/azurerm" }
    azuread = { source = "hashicorp/azuread" }
  }
}

variable "management_group_id" {
  description = "Management group to assign Reader at, e.g. /providers/Microsoft.Management/managementGroups/<tenant id> for the root."
  type        = string
}

variable "collector_object_id" {
  description = "Object ID of the collector's service principal (the enterprise application, not the app registration)."
  type        = string
}

variable "azure" {
  description = "Grant what the Azure modules need."
  type        = bool
  default     = true
}

variable "graph_permissions" {
  description = "Microsoft Graph application permissions to grant. The default is everything the built-in modules read; remove what you switch off."
  type        = set(string)
  default = [
    # m365-identity
    "Organization.Read.All",
    "Domain.Read.All",
    "Policy.Read.All",
    "Directory.Read.All",
    "AdministrativeUnit.Read.All",
    "OnPremDirectorySynchronization.Read.All",
    "IdentityProvider.Read.All",
    # m365-roles
    "RoleManagement.Read.Directory",
    "RoleEligibilitySchedule.Read.Directory",
    "RoleManagementPolicy.Read.Directory",
    # m365-applications
    "Application.Read.All",
    # m365-groups (off by default)
    "Group.Read.All",
    # m365-governance
    "AccessReview.Read.All",
    "EntitlementManagement.Read.All",
    "LifecycleWorkflows.Read.All",
    # m365-intune
    "DeviceManagementConfiguration.Read.All",
    "DeviceManagementServiceConfig.Read.All",
    "DeviceManagementApps.Read.All",
    "DeviceManagementRBAC.Read.All",
    "DeviceManagementManagedDevices.Read.All",
    # m365-collaboration
    "SharePointTenantSettings.Read.All",
    "TeamworkAppSettings.Read.All",
    "AppCatalog.Read.All",
    "OrgSettings-Microsoft365Install.Read.All",
    "ReportSettings.Read.All",
    "PeopleSettings.Read.All",
    "OrgSettings-AppsAndServices.Read.All",
    "OrgSettings-Forms.Read.All",
    "OrgSettings-Todo.Read.All",
    "OrgSettings-DynamicsVoice.Read.All",
    # m365-information-protection
    "InformationProtectionPolicy.Read.All",
    "RecordsManagement.Read.All",
  ]
}

variable "delegated_permissions" {
  description = "Microsoft Graph delegated permissions to consent to for the whole tenant, for the sources read as the service account. The default is what the built-in modules read that way; add the permission of any source you switch to the service account in the dashboard."
  type        = set(string)
  default = [
    # m365-governance: terms of use has no application permission
    "Agreement.Read.All",
  ]
}

variable "app_configuration_id" {
  description = "Resource ID of the Azure App Configuration store that holds the collector's settings (under azureDriftChecker), when the collector reads it with this same service principal. Leave empty when it signs in to the store as something else, or is handed its settings by cloudini."
  type        = string
  default     = ""
}

variable "exchange_online" {
  description = "Also grant what the Exchange Online module needs: the Exchange.ManageAsApp permission and the Global Reader directory role. The module is off by default."
  type        = bool
  default     = false
}

# Every Azure module: Resource Graph and the Resource Manager lists.
resource "azurerm_role_assignment" "reader" {
  count                = var.azure ? 1 : 0
  scope                = var.management_group_id
  role_definition_name = "Reader"
  principal_id         = var.collector_object_id
}

# Reads the settings the dashboard writes. The dashboard's own identity
# needs App Configuration Data Owner on the store to write them; that is
# not assigned here. Settings stored as Key Vault references also need
# Key Vault Secrets User on the vault, for both.
resource "azurerm_role_assignment" "app_configuration" {
  count                = var.app_configuration_id == "" ? 0 : 1
  scope                = var.app_configuration_id
  role_definition_name = "App Configuration Data Reader"
  principal_id         = var.collector_object_id
}

data "azuread_application_published_app_ids" "well_known" {}

data "azuread_service_principal" "graph" {
  client_id = data.azuread_application_published_app_ids.well_known.result["MicrosoftGraph"]
}

resource "azuread_app_role_assignment" "graph" {
  for_each            = var.graph_permissions
  app_role_id         = data.azuread_service_principal.graph.app_role_ids[each.value]
  principal_object_id = var.collector_object_id
  resource_object_id  = data.azuread_service_principal.graph.object_id
}

# Admin consent for the delegated permissions. They only work for a user
# who also holds a directory role that may read the data (Global Reader
# covers everything here): assign that to the service account yourself.
resource "azuread_service_principal_delegated_permission_grant" "graph" {
  count                                = length(var.delegated_permissions) > 0 ? 1 : 0
  service_principal_object_id          = var.collector_object_id
  resource_service_principal_object_id = data.azuread_service_principal.graph.object_id
  claim_values                         = var.delegated_permissions
}

data "azuread_service_principal" "exchange" {
  count     = var.exchange_online ? 1 : 0
  client_id = data.azuread_application_published_app_ids.well_known.result["Office365ExchangeOnline"]
}

resource "azuread_app_role_assignment" "exchange" {
  count               = var.exchange_online ? 1 : 0
  app_role_id         = data.azuread_service_principal.exchange[0].app_role_ids["Exchange.ManageAsApp"]
  principal_object_id = var.collector_object_id
  resource_object_id  = data.azuread_service_principal.exchange[0].object_id
}

# Exchange Online decides what an application may run by its directory
# role. Global Reader can run the Get- cmdlets the module uses.
resource "azuread_directory_role" "global_reader" {
  count        = var.exchange_online ? 1 : 0
  display_name = "Global Reader"
}

resource "azuread_directory_role_assignment" "exchange" {
  count               = var.exchange_online ? 1 : 0
  role_id             = azuread_directory_role.global_reader[0].template_id
  principal_object_id = var.collector_object_id
}
