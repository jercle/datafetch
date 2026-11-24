package catalog

import "github.com/jercle/datafetch/azconfigdrift/internal/model"

// Azure settings come from Azure Resource Graph, which returns the full
// properties of every resource in a tenant with one paged query, plus a few
// Resource Manager lists for what Resource Graph does not hold. All of it
// needs the Reader role (at the root management group to see everything).

func resources(types ...string) Source {
	return Source{ID: "resources", Name: "Resources", Kind: KindARG, Table: "resources", Types: types, Permission: "Reader"}
}

func azureModules() []Module {
	const reader = "Reader"
	sub := "/subscriptions/{subscriptionId}/providers/"
	return []Module{
		{
			ID: "azure-governance", Platform: model.PlatformAzure, Name: "Governance", DefaultEnabled: true,
			Description: "Management groups, subscriptions, resource groups, Azure Policy and resource locks.",
			Sources: []Source{
				{ID: "containers", Name: "Management groups, subscriptions and resource groups", Kind: KindARG, Table: "resourcecontainers", Permission: reader},
				{ID: "policy-assignments", Name: "Policy assignments", Kind: KindARG, Table: "policyresources", Types: []string{"microsoft.authorization/policyassignments"}, Permission: reader},
				{ID: "policy-definitions", Name: "Custom policy definitions", Kind: KindARG, Table: "policyresources", Types: []string{"microsoft.authorization/policydefinitions"}, Where: "properties.policyType =~ 'Custom'", Permission: reader},
				{ID: "policy-set-definitions", Name: "Custom policy initiatives", Kind: KindARG, Table: "policyresources", Types: []string{"microsoft.authorization/policysetdefinitions"}, Where: "properties.policyType =~ 'Custom'", Permission: reader},
				{ID: "policy-exemptions", Name: "Policy exemptions", Kind: KindARG, Table: "policyresources", Types: []string{"microsoft.authorization/policyexemptions"}, Permission: reader},
				{ID: "locks", Name: "Resource locks", Kind: KindARM, Path: sub + "Microsoft.Authorization/locks?api-version=2020-05-01", Permission: reader},
				resources("microsoft.resources/", "microsoft.managedservices/", "microsoft.blueprint/", "microsoft.costmanagement/", "microsoft.consumption/"),
			},
		},
		{
			ID: "azure-access", Platform: model.PlatformAzure, Name: "Access control", DefaultEnabled: true,
			Description: "Role assignments at every scope, custom role definitions and managed identities.",
			Sources: []Source{
				{ID: "role-assignments", Name: "Role assignments", Kind: KindARG, Table: "authorizationresources", Types: []string{"microsoft.authorization/roleassignments"}, Permission: reader,
					Refs:  []Ref{{Path: "properties.principalId", Kind: RefPrincipal}, {Path: "properties.roleDefinitionId", Kind: RefAzureRole}, {Path: "properties.createdBy", Kind: RefPrincipal}, {Path: "properties.updatedBy", Kind: RefPrincipal}, {Path: "properties.scope", Kind: RefAzureScope}},
					Title: []string{"properties.principalId", "properties.roleDefinitionId", "properties.scope"}},
				{ID: "role-definitions", Name: "Custom role definitions", Kind: KindARG, Table: "authorizationresources", Types: []string{"microsoft.authorization/roledefinitions"}, Where: "properties.type =~ 'CustomRole'", Permission: reader},
				{ID: "classic-administrators", Name: "Classic administrators", Kind: KindARG, Table: "authorizationresources", Types: []string{"microsoft.authorization/classicadministrators"}, Permission: reader},
				resources("microsoft.managedidentity/"),
			},
		},
		{
			ID: "azure-network", Platform: model.PlatformAzure, Name: "Networking", DefaultEnabled: true,
			Description: "Virtual networks, security groups, route tables, firewalls, gateways, load balancers, public IPs, private endpoints, DNS, Front Door and CDN.",
			Sources:     []Source{resources("microsoft.network/", "microsoft.cdn/", "microsoft.classicnetwork/")},
		},
		{
			ID: "azure-compute", Platform: model.PlatformAzure, Name: "Compute and containers", DefaultEnabled: true,
			Description: "Virtual machines, scale sets, disks, images, AKS, container apps, registries, Virtual Desktop and Arc machines.",
			Sources: []Source{resources("microsoft.compute/", "microsoft.containerservice/", "microsoft.containerinstance/", "microsoft.containerregistry/",
				"microsoft.app/", "microsoft.desktopvirtualization/", "microsoft.batch/", "microsoft.hybridcompute/", "microsoft.devtestlab/",
				"microsoft.servicefabric/", "microsoft.avs/", "microsoft.classiccompute/")},
		},
		{
			ID: "azure-data", Platform: model.PlatformAzure, Name: "Storage and data", DefaultEnabled: true,
			Description: "Storage accounts, SQL, Cosmos DB, PostgreSQL, MySQL, Redis, Data Factory, Synapse, Databricks, backup and recovery vaults.",
			Sources: []Source{resources("microsoft.storage/", "microsoft.sql/", "microsoft.documentdb/", "microsoft.dbforpostgresql/", "microsoft.dbformysql/",
				"microsoft.dbformariadb/", "microsoft.cache/", "microsoft.datafactory/", "microsoft.synapse/", "microsoft.databricks/", "microsoft.kusto/",
				"microsoft.netapp/", "microsoft.datalakestore/", "microsoft.datalakeanalytics/", "microsoft.sqlvirtualmachine/", "microsoft.recoveryservices/",
				"microsoft.dataprotection/", "microsoft.purview/", "microsoft.storagesync/", "microsoft.classicstorage/")},
		},
		{
			ID: "azure-security", Platform: model.PlatformAzure, Name: "Security", DefaultEnabled: true,
			Description: "Key vaults, Defender for Cloud plans and settings, security contacts and Sentinel resources.",
			Sources: []Source{
				resources("microsoft.keyvault/", "microsoft.security/", "microsoft.securityinsights/", "microsoft.attestation/"),
				{ID: "defender-plans", Name: "Defender for Cloud plans", Kind: KindARM, Path: sub + "Microsoft.Security/pricings?api-version=2024-01-01", Permission: reader,
					Ignore: []string{"properties.freeTrialRemainingTime", "properties.enablementTime", "properties.extensions.*.operationStatus"}},
				{ID: "defender-settings", Name: "Defender for Cloud settings", Kind: KindARM, Path: sub + "Microsoft.Security/settings?api-version=2022-05-01", Permission: reader},
				{ID: "security-contacts", Name: "Security contacts", Kind: KindARM, Path: sub + "Microsoft.Security/securityContacts?api-version=2020-01-01-preview", Permission: reader},
				{ID: "auto-provisioning", Name: "Defender auto-provisioning", Kind: KindARM, Path: sub + "Microsoft.Security/autoProvisioningSettings?api-version=2017-08-01-preview", Permission: reader},
			},
		},
		{
			ID: "azure-monitoring", Platform: model.PlatformAzure, Name: "Monitoring and management", DefaultEnabled: true,
			Description: "Log Analytics workspaces, alert rules, action groups, data collection rules, Automation accounts and subscription diagnostic settings.",
			Sources: []Source{
				resources("microsoft.insights/", "microsoft.operationalinsights/", "microsoft.operationsmanagement/", "microsoft.alertsmanagement/",
					"microsoft.monitor/", "microsoft.automation/", "microsoft.dashboard/", "microsoft.portal/", "microsoft.maintenance/"),
				{ID: "subscription-diagnostics", Name: "Subscription diagnostic settings", Kind: KindARM, Path: sub + "Microsoft.Insights/diagnosticSettings?api-version=2021-05-01-preview", Permission: reader},
			},
		},
		{
			ID: "azure-apps", Platform: model.PlatformAzure, Name: "Apps and integration", DefaultEnabled: true,
			Description: "App Service, Functions, API Management, Logic Apps, Service Bus, Event Hubs, Event Grid, App Configuration, AI and IoT services.",
			Sources: []Source{resources("microsoft.web/", "microsoft.apimanagement/", "microsoft.logic/", "microsoft.servicebus/", "microsoft.eventhub/",
				"microsoft.eventgrid/", "microsoft.relay/", "microsoft.signalrservice/", "microsoft.appconfiguration/", "microsoft.cognitiveservices/",
				"microsoft.machinelearningservices/", "microsoft.search/", "microsoft.botservice/", "microsoft.communication/", "microsoft.notificationhubs/",
				"microsoft.devices/", "microsoft.streamanalytics/", "microsoft.certificateregistration/", "microsoft.domainregistration/")},
		},
		{
			ID: "azure-other", Platform: model.PlatformAzure, Name: "Other Azure resources", DefaultEnabled: true,
			Description: "Every resource type that no other Azure module reads, so nothing is left out.",
			Sources:     []Source{{ID: "resources", Name: "Resources", Kind: KindARG, Table: "resources", Other: true, Permission: reader}},
		},
	}
}
