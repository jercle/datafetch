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
				// What has been spent so far is not a setting.
				{ID: "budgets", Name: "Budgets and cost alerts", Kind: KindARM, Path: sub + "Microsoft.Consumption/budgets?api-version=2023-05-01", Permission: reader,
					Ignore: []string{"etag", "properties.currentSpend", "properties.forecastSpend"}},
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
				{ID: "role-definitions", Name: "Custom role definitions", Kind: KindARG, Table: "authorizationresources", Types: []string{"microsoft.authorization/roledefinitions"}, Where: "properties.type =~ 'CustomRole'", Permission: reader, NameFrom: "properties.roleName"},
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
			Sources: []Source{func() Source {
				s := resources("microsoft.compute/", "microsoft.containerservice/", "microsoft.containerinstance/", "microsoft.containerregistry/",
					"microsoft.app/", "microsoft.desktopvirtualization/", "microsoft.batch/", "microsoft.hybridcompute/", "microsoft.devtestlab/",
					"microsoft.servicefabric/", "microsoft.avs/", "microsoft.classiccompute/")
				// Extensions are part of the machine they are installed on.
				s.Nest = []Nest{
					{Type: "microsoft.compute/virtualmachines/extensions", Field: "extensions"},
					{Type: "microsoft.compute/virtualmachinescalesets/extensions", Field: "extensions"},
					{Type: "microsoft.hybridcompute/machines/extensions", Field: "extensions"},
				}
				return s
			}()},
		},
		{
			ID: "azure-data", Platform: model.PlatformAzure, Name: "Storage and data", DefaultEnabled: true,
			Description: "Storage accounts, SQL, Cosmos DB, PostgreSQL, MySQL, Redis, Data Factory, Synapse, Databricks, backup and recovery vaults.",
			Sources: []Source{resources("microsoft.storage/", "microsoft.sql/", "microsoft.documentdb/", "microsoft.dbforpostgresql/", "microsoft.dbformysql/",
				"microsoft.dbformariadb/", "microsoft.cache/", "microsoft.datafactory/", "microsoft.synapse/", "microsoft.databricks/", "microsoft.kusto/",
				"microsoft.netapp/", "microsoft.datalakestore/", "microsoft.datalakeanalytics/", "microsoft.sqlvirtualmachine/", "microsoft.recoveryservices/",
				"microsoft.dataprotection/", "microsoft.purview/", "microsoft.storagesync/", "microsoft.classicstorage/"),
				// Settings of a storage account's blob and file services, and of
				// a SQL server, that are resources of their own and not in
				// Resource Graph.
				each("storage-blob-settings", "Storage blob service settings", "{resource}/blobServices/default?api-version=2023-05-01", true, "microsoft.storage/storageaccounts"),
				each("storage-file-settings", "Storage file service settings", "{resource}/fileServices/default?api-version=2023-05-01", true, "microsoft.storage/storageaccounts"),
				each("sql-auditing", "SQL server auditing", "{resource}/auditingSettings/default?api-version=2021-11-01", true, "microsoft.sql/servers"),
				each("sql-firewall-rules", "SQL server firewall rules", "{resource}/firewallRules?api-version=2021-11-01", false, "microsoft.sql/servers"),
			},
		},
		{
			ID: "azure-sentinel", Platform: model.PlatformAzure, Name: "Microsoft Sentinel", DefaultEnabled: true,
			Description: "Per Sentinel workspace: analytics and automation rules, data connectors, watchlists, installed solutions, hunting queries and settings.",
			Sources:     sentinel(),
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
				// Where each resource sends its logs. Not in Resource Graph:
				// asked of every resource of the types that matter most.
				{ID: "resource-diagnostics", Name: "Resource diagnostic settings", Kind: KindARM, Permission: reader,
					Path: "{resource}/providers/Microsoft.Insights/diagnosticSettings?api-version=2021-05-01-preview", Each: DiagnosticTypes},
			},
		},
		{
			ID: "azure-apps", Platform: model.PlatformAzure, Name: "Apps and integration", DefaultEnabled: true,
			Description: "App Service, Functions, API Management, Logic Apps, Service Bus, Event Hubs, Event Grid, App Configuration, AI and IoT services.",
			Sources: []Source{resources("microsoft.web/", "microsoft.apimanagement/", "microsoft.logic/", "microsoft.servicebus/", "microsoft.eventhub/",
				"microsoft.eventgrid/", "microsoft.relay/", "microsoft.signalrservice/", "microsoft.appconfiguration/", "microsoft.cognitiveservices/",
				"microsoft.machinelearningservices/", "microsoft.search/", "microsoft.botservice/", "microsoft.communication/", "microsoft.notificationhubs/",
				"microsoft.devices/", "microsoft.streamanalytics/", "microsoft.certificateregistration/", "microsoft.domainregistration/"),
				// What Resource Graph leaves out of an app: its full site
				// configuration and its sign-in settings (without secrets).
				each("app-site-config", "App Service site configuration", "{resource}/config/web?api-version=2023-12-01", true, "microsoft.web/sites"),
				each("app-auth-settings", "App Service authentication settings", "{resource}/config/authsettingsV2?api-version=2023-12-01", true, "microsoft.web/sites"),
			},
		},
		{
			ID: "azure-other", Platform: model.PlatformAzure, Name: "Other Azure resources", DefaultEnabled: true,
			Description: "Every resource type that no other Azure module reads, so nothing is left out.",
			Sources:     []Source{{ID: "resources", Name: "Resources", Kind: KindARG, Table: "resources", Other: true, Permission: reader}},
		},
	}
}

// sentinel is what Microsoft Sentinel keeps per workspace. None of it is
// in Resource Graph: each list is read from Resource Manager, once for
// every workspace Sentinel is enabled on.
func sentinel() []Source {
	const (
		reader = "Reader (or Microsoft Sentinel Reader)"
		// The current generally available version, and the newest preview
		// for what has no stable version yet.
		stable  = "2025-09-01"
		preview = "2025-07-01-preview"
		si      = "{workspace}/providers/Microsoft.SecurityInsights/"
	)
	// When and by which request something was last written is not
	// configuration; who wrote it is kept, and named.
	volatile := []string{"etag", "systemData", "properties.lastModifiedUtc", "properties.lastModifiedTimeUtc", "properties.createdTimeUtc", "properties.lastUpdatedTimeUtc"}
	who := []Ref{{Path: "properties.createdBy.objectId", Kind: RefPrincipal}, {Path: "properties.lastModifiedBy.objectId", Kind: RefPrincipal},
		{Path: "properties.updatedBy.objectId", Kind: RefPrincipal}}
	src := func(id, name, path, version string) Source {
		return Source{ID: id, Name: name, Kind: KindARM, Path: path + "?api-version=" + version, Permission: reader, Ignore: volatile, NameFrom: "properties.displayName"}
	}
	rules := src("alert-rules", "Analytics rules", si+"alertRules", stable)
	automation := src("automation-rules", "Automation rules", si+"automationRules", stable)
	automation.Refs = who
	watchlists := src("watchlists", "Watchlists", si+"watchlists", stable)
	watchlists.Refs = who
	// The definition of a watchlist, not what is in it.
	watchlists.Ignore = append(append([]string{}, volatile...), "properties.updated", "properties.provisioningState", "properties.uploadStatus", "properties.numberOfLinesToSkip")
	connectors := src("data-connectors", "Data connectors", si+"dataConnectors", stable)
	solutions := src("content-packages", "Installed solutions", si+"contentPackages", stable)
	anomalies := src("anomaly-settings", "Anomaly detection settings", si+"securityMLAnalyticsSettings", stable)
	onboarding := src("onboarding", "Onboarding state", si+"onboardingStates", stable)
	repositories := src("source-controls", "Repository connections", si+"sourcecontrols", stable)
	// Preview only: entity analytics, UEBA, anomalies, data access by Microsoft engineers.
	settings := src("settings", "Workspace settings", si+"settings", preview)
	// Hunting queries, parsers and functions are saved searches of the workspace itself.
	searches := src("saved-searches", "Hunting queries and functions", "{workspace}/savedSearches", "2020-08-01")
	searches.Ignore = append(append([]string{}, volatile...), "properties.version")
	// How long each table is kept and on which plan. The columns of a table
	// are Microsoft's to change, and are left out.
	tables := src("table-retention", "Table retention and plans", "{workspace}/tables", "2023-09-01")
	tables.NameFrom = ""
	tables.Ignore = append(append([]string{}, volatile...), "properties.schema", "properties.provisioningState", "properties.lastPlanModifiedDate",
		"properties.resultStatistics", "properties.restoredLogs", "properties.searchResults")
	return []Source{rules, automation, connectors, watchlists, solutions, anomalies, settings, onboarding, repositories, searches, tables}
}

// each is a Resource Manager source read once for every resource of the
// given types.
func each(id, name, path string, single bool, types ...string) Source {
	return Source{ID: id, Name: name, Kind: KindARM, Path: path, Single: single, Each: types, Permission: "Reader", Ignore: []string{"etag", "systemData"}}
}

// DiagnosticTypes are the resource types whose diagnostic settings are
// read: the ones a security baseline usually asks to have logging on.
var DiagnosticTypes = []string{
	"microsoft.keyvault/vaults", "microsoft.storage/storageaccounts", "microsoft.sql/servers/databases", "microsoft.network/networksecuritygroups",
	"microsoft.network/azurefirewalls", "microsoft.network/applicationgateways", "microsoft.network/frontdoors", "microsoft.cdn/profiles",
	"microsoft.network/publicipaddresses", "microsoft.network/virtualnetworkgateways", "microsoft.network/bastionhosts",
	"microsoft.web/sites", "microsoft.containerservice/managedclusters", "microsoft.containerregistry/registries",
	"microsoft.operationalinsights/workspaces", "microsoft.automation/automationaccounts", "microsoft.recoveryservices/vaults",
	"microsoft.eventhub/namespaces", "microsoft.servicebus/namespaces", "microsoft.logic/workflows", "microsoft.apimanagement/service",
	"microsoft.documentdb/databaseaccounts", "microsoft.dbforpostgresql/flexibleservers", "microsoft.dbformysql/flexibleservers",
	"microsoft.cognitiveservices/accounts", "microsoft.datafactory/factories",
}
