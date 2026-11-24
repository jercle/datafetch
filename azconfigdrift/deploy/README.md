# Deploying az-config-drift

What is deployed is the **collector**: the datafetch image, started as
`datafetch az-config-drift -loop`, that needs MongoDB and (optionally) Azure App Configuration. Any number of
replicas can run; each tenant is read by one at a time. The dashboard is
not deployed from here: its modules are part of cld-dash, which reads the
same MongoDB.

None of this was applied or built by the author. Plan and review it
against your own provider and cluster versions before relying on it.

| Where | Use | Secrets come from |
|---|---|---|
| One machine | `compose/` | a local `.env` file |
| Azure Container Apps | `terraform/container-app/` | Key Vault, through the app's managed identity |
| Kubernetes (AKS) | `kubernetes/` + `terraform/aks/` + `argocd/` | Key Vault, through the CSI driver and workload identity |
| A VM with systemd | `az-config-drift.service` | an environment file |

`terraform/permissions.tf` is separate from all of these: it grants the
collector's service principal what it reads **in each tenant**.

## The image

The image is datafetch's, built in the repository root. Its entry point
is `datafetch`, so every manifest here passes `az-config-drift -loop` as
arguments.

```
docker build -t myregistry.azurecr.io/datafetch:1.0.0 --build-arg VERSION=1.0.0 .
docker push myregistry.azurecr.io/datafetch:1.0.0
```

`Dockerfile.pwsh`, also in the repository root, builds the larger image with PowerShell, for the
Microsoft Teams module only. It needs a writable home and `/tmp`: on
Kubernetes turn `readOnlyRootFilesystem` off for it or mount `emptyDir`
volumes there, and in compose remove `read_only: true`.

## Locally, with Docker Compose

```
cd azconfigdrift/deploy/compose
cp .env.example .env                    # MongoDB password, tenant secrets
cp config.example.json config.json      # your tenants
docker compose up -d --build
docker compose logs -f collector
```

MongoDB listens on `127.0.0.1:27017` for cld-dash. Settings come from
`config.json`; see the comment in `docker-compose.yml` to add App
Configuration. `docker compose down` keeps the data, `down -v` deletes it.

## Azure Container Apps

`terraform/container-app/` is a module: a user-assigned identity with
access to App Configuration, Key Vault and the registry, and the app with
a fixed number of replicas and no ingress. Give it an existing environment
or let it create one.

```
terraform -chdir=azconfigdrift/deploy/terraform/container-app init
terraform -chdir=azconfigdrift/deploy/terraform/container-app apply -var-file=example.tfvars
```

Before the first apply, put the MongoDB connection string in Key Vault
under the secret that `mongo_uri_secret_id` names. To roll out a new
version, change `image` and apply.

## Kubernetes

Three parts:

1. **Azure side**, once: `terraform/aks/` creates the identity the CSI
   driver reads Key Vault with, optionally the two Key Vault secrets, and
   pull access to the registry. The cluster needs the OIDC issuer, workload
   identity and the `azure-keyvault-secrets-provider` add-on.
2. **Manifests**: `kubernetes/base` (namespace with restricted pod
   security, service account, Deployment with three replicas, disruption
   budget, network policy) and `kubernetes/overlays/production`, which pins
   the image and takes the secrets from Key Vault. Fill in the lines marked
   `<-` in the overlay with your registry, App Configuration store, Key
   Vault and the two Terraform outputs.
3. **Delivery**: `kubectl apply -k azconfigdrift/deploy/kubernetes/overlays/production`,
   or Argo CD with `argocd/application.yaml`.

On Argo CD: it is worth using if the cluster already runs it, or you want
the cluster to follow Git and undo changes made by hand. For this one
Deployment alone it is not needed. On AKS the Flux extension
(`azurerm_kubernetes_flux_configuration`) does the same from Terraform
without installing anything yourself; point it at the same overlay path.

Without Key Vault, use the base with a Secret made from
`kubernetes/secret.example.yaml`.

On AKS the collector signs in to App Configuration with a client secret:
its reader supports managed identity only through the instance metadata
and Container Apps endpoints, not Kubernetes workload identity.
