# terraform -chdir=deploy/terraform/container-app apply -var-file=example.tfvars
resource_group_name        = "rg-az-config-drift"
location                   = "australiaeast"
image                      = "myregistry.azurecr.io/datafetch:1.0.0"
registry_server            = "myregistry.azurecr.io"
registry_id                = "/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.ContainerRegistry/registries/myregistry"
app_configuration_id       = "/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.AppConfiguration/configurationStores/mystore"
app_configuration_endpoint = "https://mystore.azconfig.io"
key_vault_id               = "/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.KeyVault/vaults/my-key-vault"
mongo_uri_secret_id        = "https://my-key-vault.vault.azure.net/secrets/az-config-drift-mongo-uri"
replicas                   = 2
# container_app_environment_id = "/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.App/managedEnvironments/<name>"
