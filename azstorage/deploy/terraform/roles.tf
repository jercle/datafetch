# The two roles the collector's service principal needs, assigned at a
# management group so that new subscriptions are covered. Apply once per
# tenant. Not applied or planned by the author: check it against your
# provider version.

variable "management_group_id" {
  description = "Management group to assign at, e.g. /providers/Microsoft.Management/managementGroups/contoso."
  type        = string
}

variable "collector_object_id" {
  description = "Object ID of the collector's service principal (the enterprise application, not the app registration)."
  type        = string
}

variable "measure_containers" {
  description = "Also grant Storage Blob Data Reader, which the collector needs to add up container sizes. It lets the principal read every blob."
  type        = bool
  default     = true
}

# Lists subscriptions, storage accounts, containers and disks, and reads the
# capacity metrics.
resource "azurerm_role_assignment" "reader" {
  scope                = var.management_group_id
  role_definition_name = "Reader"
  principal_id         = var.collector_object_id
}

# Lists blobs, to measure containers. Leave it out (measure_containers =
# false, and collect.containerSizes = false in the collector's config) if the
# principal should not be able to read blob contents.
resource "azurerm_role_assignment" "blob_reader" {
  count                = var.measure_containers ? 1 : 0
  scope                = var.management_group_id
  role_definition_name = "Storage Blob Data Reader"
  principal_id         = var.collector_object_id
}
