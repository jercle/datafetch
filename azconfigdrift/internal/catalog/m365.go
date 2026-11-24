package catalog

import "github.com/jercle/datafetch/azconfigdrift/internal/model"

// Microsoft 365 settings come from Microsoft Graph, with application
// permissions unless a source is marked delegated (or switched to the
// service account in the dashboard). Each source names the permission it needs; a source the
// service principal may not read is recorded as "denied" and the rest of
// the module is still read.
//
// Exchange Online has no settings in Microsoft Graph. Its module runs the
// Get- cmdlets through the REST endpoint behind the Exchange Online
// PowerShell module, and is off until switched on in the dashboard.

func list(id, name, path, permission string) Source {
	return Source{ID: id, Name: name, Kind: KindGraph, Path: path, Type: id, Permission: permission}
}

func single(id, name, path, permission string) Source {
	s := list(id, name, path, permission)
	s.Single = true
	return s
}

func (s Source) beta() Source { s.Beta = true; return s }

// delegated marks a source whose endpoint has no application permission.
func (s Source) delegated() Source { s.Delegated = true; return s }

func (s Source) ignore(paths ...string) Source { s.Ignore = append(s.Ignore, paths...); return s }

func (s Source) key(field string) Source { s.KeyField = field; return s }

func (s Source) with(children ...Child) Source { s.Children = children; return s }

func (s Source) attach(a ...Attach) Source { s.Attach = a; return s }

func (s Source) keep(field, value string, not bool) Source {
	s.Keep = &Keep{Field: field, Value: value, Not: not}
	return s
}

// refs names the identifiers at these paths; title names the object after them.
func (s Source) refs(r ...Ref) Source { s.Refs = append(s.Refs, r...); return s }

func (s Source) title(paths ...string) Source { s.Title = paths; return s }

func (s Source) typed(t string) Source { s.Type = t; return s }

// roles stores the principal's directory and Azure roles inside it.
func (s Source) roles(mode string) Source {
	s.Roles = mode
	s.Refs = append(s.Refs, RoleRefs...)
	return s
}

// teams is a cmdlet of the MicrosoftTeams PowerShell module.
func teams(id, name, cmd string) Source {
	return Source{ID: id, Name: name, Kind: KindPwsh, Script: "teams", Cmdlet: cmd, Type: id, KeyField: "Identity",
		Permission: "the Teams Administrator (or Global Reader) role for the application, and pwsh with the MicrosoftTeams module where the collector runs"}
}

func cmdlet(id, name, cmd string) Source {
	return Source{
		ID: id, Name: name, Kind: KindEXO, Cmdlet: cmd, Type: id, KeyField: "Guid",
		Permission: "Exchange.ManageAsApp and the Global Reader role",
		// Bookkeeping every Exchange object carries.
		Ignore: []string{"isValid", "exchangeVersion", "distinguishedName", "organizationId", "id", "exchangeObjectId", "organizationalUnitRoot"},
	}
}

func m365Modules() []Module {
	const (
		policy   = "Policy.Read.All"
		dir      = "Directory.Read.All"
		roles    = "RoleManagement.Read.Directory"
		pim      = "RoleManagementPolicy.Read.Directory"
		entitle  = "EntitlementManagement.Read.All"
		intune   = "DeviceManagementConfiguration.Read.All"
		apps     = "DeviceManagementApps.Read.All"
		service  = "DeviceManagementServiceConfig.Read.All"
		intuneRB = "DeviceManagementRBAC.Read.All"
		pimScope = "?$filter=scopeId eq '/' and scopeType eq 'DirectoryRole'"
	)
	assignments := Child{Field: "assignments", Suffix: "assignments"}
	principal, entraRole := Ref{Path: "principalId", Kind: RefPrincipal}, Ref{Path: "roleDefinitionId", Kind: RefEntraRole}
	// The delegated permissions granted to an application are stored with
	// the application they were granted to, not as objects of their own.
	grants := Attach{Field: "oauth2PermissionGrants", Path: "/oauth2PermissionGrants?$top=999", By: "clientId", Drop: []string{"id", "clientId"}, Permission: dir}
	grantRefs := []Ref{{Path: "oauth2PermissionGrants.*.resourceId", Kind: RefPrincipal}, {Path: "oauth2PermissionGrants.*.principalId", Kind: RefPrincipal}}
	return []Module{
		{
			ID: "m365-identity", Platform: model.PlatformM365, Name: "Entra ID tenant settings", DefaultEnabled: true,
			Description: "Organisation and domains, authorisation and authentication method policies, security defaults, cross-tenant access, consent, token and app policies, directory settings.",
			Sources: []Source{
				list("organization", "Organisation", "/organization", "Organization.Read.All").ignore("directorySizeQuota", "assignedPlans", "provisionedPlans"),
				single("branding", "Company branding", "/organization/{tenantId}/branding", "Organization.Read.All").ignore("cdnList"),
				list("domains", "Domains", "/domains", "Domain.Read.All"),
				list("subscribed-skus", "Licences", "/subscribedSkus", "Organization.Read.All").ignore("consumedUnits"),
				single("authorization-policy", "Authorisation policy", "/policies/authorizationPolicy", policy),
				single("security-defaults", "Security defaults", "/policies/identitySecurityDefaultsEnforcementPolicy", policy),
				single("authentication-methods-policy", "Authentication methods policy", "/policies/authenticationMethodsPolicy", policy),
				single("authentication-flows-policy", "Authentication flows policy", "/policies/authenticationFlowsPolicy", policy),
				single("admin-consent-request-policy", "Admin consent request policy", "/policies/adminConsentRequestPolicy", policy),
				list("permission-grant-policies", "Permission grant policies", "/policies/permissionGrantPolicies", policy),
				single("cross-tenant-access-policy", "Cross-tenant access policy", "/policies/crossTenantAccessPolicy", policy),
				single("cross-tenant-access-default", "Cross-tenant access defaults", "/policies/crossTenantAccessPolicy/default", policy),
				list("cross-tenant-access-partners", "Cross-tenant access partners", "/policies/crossTenantAccessPolicy/partners", policy).key("tenantId"),
				single("external-identities-policy", "External identities policy", "/policies/externalIdentitiesPolicy", policy).beta(),
				single("device-registration-policy", "Device registration policy", "/policies/deviceRegistrationPolicy", policy).beta(),
				single("default-app-management-policy", "Default app management policy", "/policies/defaultAppManagementPolicy", policy),
				list("app-management-policies", "App management policies", "/policies/appManagementPolicies", policy),
				list("token-lifetime-policies", "Token lifetime policies", "/policies/tokenLifetimePolicies", policy),
				list("token-issuance-policies", "Token issuance policies", "/policies/tokenIssuancePolicies", policy),
				list("home-realm-discovery-policies", "Home realm discovery policies", "/policies/homeRealmDiscoveryPolicies", policy),
				list("claims-mapping-policies", "Claims mapping policies", "/policies/claimsMappingPolicies", policy),
				list("activity-timeout-policies", "Activity-based timeout policies", "/policies/activityBasedTimeoutPolicies", policy),
				list("feature-rollout-policies", "Feature rollout policies", "/policies/featureRolloutPolicies", policy),
				list("mdm-policies", "MDM enrolment scope", "/policies/mobileDeviceManagementPolicies", policy),
				list("mam-policies", "MAM enrolment scope", "/policies/mobileAppManagementPolicies", policy),
				list("directory-settings", "Directory settings", "/groupSettings", dir),
				list("administrative-units", "Administrative units", "/directory/administrativeUnits", "AdministrativeUnit.Read.All"),
				list("on-premises-sync", "Directory synchronisation", "/directory/onPremisesSynchronization", "OnPremDirectorySynchronization.Read.All"),
				list("identity-providers", "Identity providers", "/identity/identityProviders", "IdentityProvider.Read.All"),
			},
		},
		{
			ID: "m365-conditional-access", Platform: model.PlatformM365, Name: "Conditional Access", DefaultEnabled: true,
			Description: "Conditional Access policies, named locations, authentication contexts and authentication strengths.",
			Sources: []Source{
				list("policies", "Policies", "/identity/conditionalAccess/policies", policy),
				list("named-locations", "Named locations", "/identity/conditionalAccess/namedLocations", policy),
				list("authentication-contexts", "Authentication contexts", "/identity/conditionalAccess/authenticationContextClassReferences", policy),
				list("authentication-strengths", "Authentication strengths", "/policies/authenticationStrengthPolicies", policy),
			},
		},
		{
			ID: "m365-roles", Platform: model.PlatformM365, Name: "Directory roles and PIM", DefaultEnabled: true,
			Description: "Role definitions, active and eligible role assignments, and the Privileged Identity Management settings of each role.",
			Sources: []Source{
				list("role-definitions", "Role definitions", "/roleManagement/directory/roleDefinitions", roles),
				list("role-assignments", "Role assignments", "/roleManagement/directory/roleAssignments", roles).refs(principal, entraRole).title("principalId", "roleDefinitionId"),
				// One object per user, group or application that holds a
				// role, with every directory and Azure role it holds.
				func() Source {
					s := list("principal-roles", "Roles by principal", "/roleManagement/directory/roleAssignments", roles).refs(Ref{Path: "id", Kind: RefPrincipal}).title("id").roles(RolesPrincipal)
					s.Principals = true
					return s
				}(),
				list("role-eligibility", "Eligible assignments", "/roleManagement/directory/roleEligibilitySchedules", "RoleEligibilitySchedule.Read.Directory").ignore("status").
					refs(principal, entraRole).title("principalId", "roleDefinitionId"),
				list("pim-policies", "PIM role settings", "/policies/roleManagementPolicies"+pimScope+"&$expand=rules", pim),
				list("pim-policy-assignments", "PIM role setting assignments", "/policies/roleManagementPolicyAssignments"+pimScope, pim).refs(entraRole).title("roleDefinitionId"),
			},
		},
		{
			ID: "m365-applications", Platform: model.PlatformM365, Name: "Applications", DefaultEnabled: true,
			Description: "App registrations, enterprise applications with the delegated permissions granted to them, and managed identities.",
			Sources: []Source{
				list("applications", "App registrations", "/applications?$top=999", "Application.Read.All").roles(RolesApplication),
				list("service-principals", "Enterprise applications", "/servicePrincipals?$top=999", "Application.Read.All").
					keep("servicePrincipalType", "ManagedIdentity", true).attach(grants).refs(grantRefs...).roles(RolesPrincipal),
				// Managed identities are service principals too; they are
				// listed as a type of their own.
				list("managed-identities", "Managed identities", "/servicePrincipals?$top=999", "Application.Read.All").
					keep("servicePrincipalType", "ManagedIdentity", false).attach(grants).refs(grantRefs...).typed("managed-identities").roles(RolesPrincipal),
			},
		},
		{
			ID: "m365-groups", Platform: model.PlatformM365, Name: "Groups", DefaultEnabled: false,
			Description: "The settings of every group (not its members) and the group expiry policy. Off by default: large tenants have very many groups.",
			Sources: []Source{
				list("groups", "Groups", "/groups?$top=999", "Group.Read.All").ignore("renewedDateTime"),
				list("lifecycle-policies", "Expiry policies", "/groupLifecyclePolicies", dir),
			},
		},
		{
			ID: "m365-governance", Platform: model.PlatformM365, Name: "Identity governance", DefaultEnabled: true,
			Description: "Access reviews, entitlement management, terms of use and lifecycle workflows.",
			Sources: []Source{
				list("access-reviews", "Access review definitions", "/identityGovernance/accessReviews/definitions", "AccessReview.Read.All").ignore("status"),
				list("access-packages", "Access packages", "/identityGovernance/entitlementManagement/accessPackages", entitle),
				list("access-package-policies", "Access package assignment policies", "/identityGovernance/entitlementManagement/assignmentPolicies", entitle),
				list("catalogs", "Catalogues", "/identityGovernance/entitlementManagement/catalogs", entitle),
				list("connected-organizations", "Connected organisations", "/identityGovernance/entitlementManagement/connectedOrganizations", entitle),
				single("entitlement-settings", "Entitlement management settings", "/identityGovernance/entitlementManagement/settings", entitle),
				list("terms-of-use", "Terms of use", "/identityGovernance/termsOfUse/agreements", "Agreement.Read.All").delegated(),
				list("lifecycle-workflows", "Lifecycle workflows", "/identityGovernance/lifecycleWorkflows/workflows", "LifecycleWorkflows.Read.All").ignore("nextScheduleRunDateTime"),
			},
		},
		{
			ID: "m365-intune", Platform: model.PlatformM365, Name: "Intune", DefaultEnabled: true,
			Description: "Compliance and configuration policies, settings catalogue, administrative templates, endpoint security, enrolment, Autopilot, update rings, scripts, app protection and app configuration.",
			Sources: []Source{
				single("device-management", "Tenant settings", "/deviceManagement", intune).ignore("subscriptionState", "deviceProtectionOverview", "windowsMalwareOverview", "managedDeviceOverview"),
				list("compliance-policies", "Compliance policies", "/deviceManagement/deviceCompliancePolicies?$expand=assignments", intune),
				list("device-configurations", "Configuration profiles", "/deviceManagement/deviceConfigurations?$expand=assignments", intune),
				list("settings-catalog", "Settings catalogue policies", "/deviceManagement/configurationPolicies", intune).beta().
					with(Child{Field: "settings", Suffix: "settings"}, assignments).ignore("settingCount"),
				list("administrative-templates", "Administrative templates", "/deviceManagement/groupPolicyConfigurations", intune).beta().
					with(Child{Field: "definitionValues", Suffix: "definitionValues?$expand=definition($select=id,displayName,categoryPath,classType)"}, assignments),
				list("endpoint-security", "Endpoint security policies", "/deviceManagement/intents", intune).beta().
					with(Child{Field: "settings", Suffix: "settings"}, assignments),
				list("enrollment-configurations", "Enrolment restrictions and status page", "/deviceManagement/deviceEnrollmentConfigurations?$expand=assignments", service),
				list("autopilot-profiles", "Autopilot deployment profiles", "/deviceManagement/windowsAutopilotDeploymentProfiles?$expand=assignments", service).beta(),
				list("assignment-filters", "Assignment filters", "/deviceManagement/assignmentFilters", intune).beta(),
				list("feature-update-profiles", "Windows feature update profiles", "/deviceManagement/windowsFeatureUpdateProfiles", intune).beta().ignore("deployableContentDisplayName", "endOfSupportDate"),
				list("quality-update-profiles", "Windows quality update profiles", "/deviceManagement/windowsQualityUpdateProfiles", intune).beta(),
				list("driver-update-profiles", "Windows driver update profiles", "/deviceManagement/windowsDriverUpdateProfiles", intune).beta().ignore("newUpdates", "inventorySyncStatus", "deviceReporting"),
				list("scripts", "PowerShell scripts", "/deviceManagement/deviceManagementScripts", intune).beta(),
				list("shell-scripts", "macOS shell scripts", "/deviceManagement/deviceShellScripts", intune).beta(),
				list("remediations", "Remediation scripts", "/deviceManagement/deviceHealthScripts", intune).beta().ignore("highestAvailableVersion"),
				list("device-categories", "Device categories", "/deviceManagement/deviceCategories", "DeviceManagementManagedDevices.Read.All"),
				list("terms-and-conditions", "Terms and conditions", "/deviceManagement/termsAndConditions", service),
				list("notification-templates", "Notification templates", "/deviceManagement/notificationMessageTemplates", service),
				single("apple-push-certificate", "Apple push certificate", "/deviceManagement/applePushNotificationCertificate", service).ignore("certificate"),
				list("role-definitions", "Intune role definitions", "/deviceManagement/roleDefinitions", intuneRB),
				list("role-assignments", "Intune role assignments", "/deviceManagement/roleAssignments", intuneRB),
				list("app-protection-policies", "App protection policies", "/deviceAppManagement/managedAppPolicies", apps).ignore("deployedAppCount", "isAssigned"),
				list("app-configurations", "App configuration policies (devices)", "/deviceAppManagement/mobileAppConfigurations?$expand=assignments", apps),
				list("targeted-app-configurations", "App configuration policies (apps)", "/deviceAppManagement/targetedManagedAppConfigurations", apps).ignore("deployedAppCount"),
				list("assigned-apps", "Assigned apps", "/deviceAppManagement/mobileApps?$filter=isAssigned eq true&$expand=assignments", apps).beta().
					ignore("uploadState", "dependentAppCount", "supersedingAppCount", "supersededAppCount", "usedLicenseCount", "largeIcon"),
			},
		},
		{
			ID: "m365-collaboration", Platform: model.PlatformM365, Name: "SharePoint, Teams and Microsoft 365 apps", DefaultEnabled: true,
			Description: "SharePoint and OneDrive tenant settings, Teams app settings and organisation apps, Microsoft 365 apps installation options, and the org-wide settings Graph exposes. Teams policies are not in Microsoft Graph.",
			Sources: []Source{
				single("sharepoint-settings", "SharePoint and OneDrive settings", "/admin/sharepoint/settings", "SharePointTenantSettings.Read.All"),
				single("teams-app-settings", "Teams app settings", "/teamwork/teamsAppSettings", "TeamworkAppSettings.Read.All"),
				list("teams-org-apps", "Teams organisation apps", "/appCatalogs/teamsApps?$filter=distributionMethod eq 'organization'&$expand=appDefinitions", "AppCatalog.Read.All"),
				single("m365-apps-installation", "Microsoft 365 apps installation options", "/admin/microsoft365Apps/installationOptions", "OrgSettings-Microsoft365Install.Read.All"),
				single("report-settings", "Report settings", "/admin/reportSettings", "ReportSettings.Read.All"),
				list("profile-card-properties", "Profile card properties", "/admin/people/profileCardProperties", "PeopleSettings.Read.All").key("directoryPropertyName"),
				single("pronouns", "Pronouns", "/admin/people/pronouns", "PeopleSettings.Read.All"),
				single("item-insights", "Item insights", "/admin/people/itemInsights", "PeopleSettings.Read.All"),
				single("apps-and-services", "User-owned apps and services", "/admin/appsAndServices", "OrgSettings-AppsAndServices.Read.All").beta(),
				single("forms", "Forms settings", "/admin/forms", "OrgSettings-Forms.Read.All").beta(),
				single("todo", "To Do settings", "/admin/todo", "OrgSettings-Todo.Read.All").beta(),
				single("dynamics-voice", "Dynamics customer voice settings", "/admin/dynamics", "OrgSettings-DynamicsVoice.Read.All").beta(),
			},
		},
		{
			ID: "m365-information-protection", Platform: model.PlatformM365, Name: "Information protection", DefaultEnabled: true,
			Description: "Sensitivity labels and their policy settings, and retention labels. Data loss prevention and retention policies are not in Microsoft Graph.",
			Sources: []Source{
				list("sensitivity-labels", "Sensitivity labels", "/security/informationProtection/sensitivityLabels", "InformationProtectionPolicy.Read.All").beta(),
				single("label-policy-settings", "Label policy settings", "/security/informationProtection/labelPolicySettings", "InformationProtectionPolicy.Read.All").beta(),
				list("retention-labels", "Retention labels", "/security/labels/retentionLabels", "RecordsManagement.Read.All"),
			},
		},
		{
			ID: "m365-sharepoint", Platform: model.PlatformM365, Name: "SharePoint Online tenant", DefaultEnabled: true,
			Description: "Every tenant setting of SharePoint and OneDrive, as Get-SPOTenant shows them.",
			Sources: []Source{
				// SharePoint refuses tokens an application got with a client
				// secret, so this is read as the service account by default.
				{ID: "tenant", Name: "Tenant settings", Kind: KindSPO, Path: "/_api/SPO.Tenant", Type: "sharepoint-tenant", Single: true, Delegated: true,
					Permission: "the service account, with the SharePoint Administrator role",
					// What is used, as opposed to what is allowed.
					Ignore: []string{"StorageQuotaAllocated", "ResourceQuotaAllocated", "odata.metadata", "odata.type", "odata.id", "odata.editLink"}},
			},
		},
		{
			ID: "m365-power-platform", Platform: model.PlatformM365, Name: "Power Platform", DefaultEnabled: true,
			Description: "Power Platform tenant settings, data loss prevention policies and environments.",
			Sources: func() []Source {
				const p = "the application registered as a Power Platform management application"
				return []Source{
					{ID: "tenant-settings", Name: "Tenant settings", Kind: KindPP, Method: "POST", Single: true, Type: "tenant-settings", Permission: p,
						Path: "/providers/Microsoft.BusinessAppPlatform/listTenantSettings?api-version=2021-04-01"},
					{ID: "dlp-policies", Name: "Data loss prevention policies", Kind: KindPP, Type: "dlp-policies", Permission: p, KeyField: "name",
						Path: "/providers/PowerPlatform.Governance/v2/policies", Ignore: []string{"etag", "lastModifiedTime"}},
					{ID: "environments", Name: "Environments", Kind: KindPP, Type: "environments", Permission: p, KeyField: "name", NameFrom: "properties.displayName",
						Path:   "/providers/Microsoft.BusinessAppPlatform/scopes/admin/environments?api-version=2021-04-01",
						Ignore: []string{"properties.lastModifiedTime", "properties.lastActivity", "properties.capacity", "properties.states.runtime", "properties.clientUris"}},
				}
			}(),
		},
		{
			ID: "m365-teams", Platform: model.PlatformM365, Name: "Microsoft Teams policies", DefaultEnabled: false,
			Description: "Meeting, messaging, calling and app policies, external and guest access. Read with the MicrosoftTeams PowerShell module, which must be installed where the collector runs.",
			Sources: []Source{
				teams("meeting-policies", "Meeting policies", "Get-CsTeamsMeetingPolicy"),
				teams("messaging-policies", "Messaging policies", "Get-CsTeamsMessagingPolicy"),
				teams("calling-policies", "Calling policies", "Get-CsTeamsCallingPolicy"),
				teams("app-permission-policies", "App permission policies", "Get-CsTeamsAppPermissionPolicy"),
				teams("app-setup-policies", "App setup policies", "Get-CsTeamsAppSetupPolicy"),
				teams("channels-policies", "Teams and channels policies", "Get-CsTeamsChannelsPolicy"),
				teams("live-event-policies", "Live event policies", "Get-CsTeamsMeetingBroadcastPolicy"),
				teams("events-policies", "Events policies", "Get-CsTeamsEventsPolicy"),
				teams("update-policies", "Update policies", "Get-CsTeamsUpdateManagementPolicy"),
				teams("external-access-policies", "External access policies", "Get-CsExternalAccessPolicy"),
				teams("federation", "External access (federation) settings", "Get-CsTenantFederationConfiguration"),
				teams("client-configuration", "Teams client configuration", "Get-CsTeamsClientConfiguration"),
				teams("meeting-configuration", "Meeting configuration", "Get-CsTeamsMeetingConfiguration"),
				teams("guest-meeting", "Guest meeting settings", "Get-CsTeamsGuestMeetingConfiguration"),
				teams("guest-messaging", "Guest messaging settings", "Get-CsTeamsGuestMessagingConfiguration"),
				teams("guest-calling", "Guest calling settings", "Get-CsTeamsGuestCallingConfiguration"),
			},
		},
		{
			ID: "m365-defender", Platform: model.PlatformM365, Name: "Defender XDR", DefaultEnabled: true,
			Description: "Custom detection rules, Defender for Identity sensors and Defender for Endpoint indicators.",
			Sources: []Source{
				// Only in beta. When a rule last ran and what it found is not configuration.
				list("detection-rules", "Custom detection rules", "/security/rules/detectionRules", "CustomDetection.Read.All").beta().
					ignore("lastRunDetails", "lastModifiedDateTime"),
				// How a sensor is doing changes by the hour; how it is set up does not.
				list("identity-sensors", "Defender for Identity sensors", "/security/identities/sensors", "SecurityIdentitiesSensors.Read.All").
					ignore("healthStatus", "openHealthIssuesCount", "version", "serviceStatus", "createdDateTime"),
				{ID: "indicators", Name: "Defender for Endpoint indicators", Kind: KindMDE, Path: "/api/indicators", Type: "indicators",
					Permission: "Ti.Read.All on WindowsDefenderATP", Ignore: []string{"@odata.type"}},
			},
		},
		{
			ID: "m365-exchange", Platform: model.PlatformM365, Name: "Exchange Online", DefaultEnabled: false,
			Description: "Organisation and transport configuration, mail flow rules, connectors, accepted and remote domains, anti-spam, anti-malware, anti-phishing, Safe Links and Safe Attachments, DKIM, sharing and mobile device policies. Off by default: it uses the endpoint behind Exchange Online PowerShell, which Microsoft does not document for direct use.",
			Sources: []Source{
				cmdlet("organization-config", "Organisation configuration", "Get-OrganizationConfig"),
				cmdlet("transport-config", "Transport configuration", "Get-TransportConfig"),
				cmdlet("accepted-domains", "Accepted domains", "Get-AcceptedDomain"),
				cmdlet("remote-domains", "Remote domains", "Get-RemoteDomain"),
				cmdlet("transport-rules", "Mail flow rules", "Get-TransportRule"),
				cmdlet("inbound-connectors", "Inbound connectors", "Get-InboundConnector"),
				cmdlet("outbound-connectors", "Outbound connectors", "Get-OutboundConnector"),
				cmdlet("anti-spam-policies", "Anti-spam inbound policies", "Get-HostedContentFilterPolicy"),
				cmdlet("anti-spam-rules", "Anti-spam inbound rules", "Get-HostedContentFilterRule"),
				cmdlet("outbound-spam-policies", "Anti-spam outbound policies", "Get-HostedOutboundSpamFilterPolicy"),
				cmdlet("connection-filter-policies", "Connection filter policies", "Get-HostedConnectionFilterPolicy"),
				cmdlet("anti-malware-policies", "Anti-malware policies", "Get-MalwareFilterPolicy"),
				cmdlet("anti-malware-rules", "Anti-malware rules", "Get-MalwareFilterRule"),
				cmdlet("anti-phish-policies", "Anti-phishing policies", "Get-AntiPhishPolicy"),
				cmdlet("anti-phish-rules", "Anti-phishing rules", "Get-AntiPhishRule"),
				cmdlet("safe-attachment-policies", "Safe Attachments policies", "Get-SafeAttachmentPolicy"),
				cmdlet("safe-links-policies", "Safe Links policies", "Get-SafeLinksPolicy"),
				cmdlet("safe-attachment-rules", "Safe Attachments rules", "Get-SafeAttachmentRule"),
				cmdlet("safe-links-rules", "Safe Links rules", "Get-SafeLinksRule"),
				cmdlet("outbound-spam-rules", "Anti-spam outbound rules", "Get-HostedOutboundSpamFilterRule"),
				cmdlet("quarantine-policies", "Quarantine policies", "Get-QuarantinePolicy"),
				cmdlet("preset-eop-rules", "Preset security policies (EOP)", "Get-EOPProtectionPolicyRule"),
				cmdlet("preset-defender-rules", "Preset security policies (Defender for Office 365)", "Get-ATPProtectionPolicyRule"),
				cmdlet("built-in-protection", "Built-in protection rule", "Get-ATPBuiltInProtectionRule"),
				cmdlet("defender-for-office", "Defender for Office 365 settings", "Get-AtpPolicyForO365"),
				cmdlet("dkim", "DKIM signing", "Get-DkimSigningConfig").ignore("lastChecked", "rotateOnDate", "selectorBeforeRotateOnDate", "selectorAfterRotateOnDate"),
				cmdlet("sharing-policies", "Sharing policies", "Get-SharingPolicy"),
				cmdlet("organization-relationships", "Organisation relationships", "Get-OrganizationRelationship"),
				cmdlet("owa-policies", "Outlook on the web policies", "Get-OwaMailboxPolicy"),
				cmdlet("mobile-device-policies", "Mobile device mailbox policies", "Get-MobileDeviceMailboxPolicy"),
				cmdlet("authentication-policies", "Authentication policies", "Get-AuthenticationPolicy"),
				cmdlet("role-assignment-policies", "Role assignment policies", "Get-RoleAssignmentPolicy"),
				cmdlet("mailbox-plans", "Mailbox plans", "Get-MailboxPlan"),
				cmdlet("cas-mailbox-plans", "Client access mailbox plans", "Get-CASMailboxPlan"),
				cmdlet("audit-config", "Admin audit log configuration", "Get-AdminAuditLogConfig"),
				cmdlet("irm-config", "IRM configuration", "Get-IRMConfiguration"),
				cmdlet("external-in-outlook", "External sender tagging", "Get-ExternalInOutlook"),
			},
		},
	}
}
