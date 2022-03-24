package storage

import (
	"core-building-block/core/model"
)

//Application
func applicationFromStorage(item *application) model.Application {
	if item == nil {
		return model.Application{}
	}

	types := applicationTypesFromStorage(item.Types)
	return model.Application{ID: item.ID, Name: item.Name, MultiTenant: item.MultiTenant,
		SharedIdentities: item.SharedIdentities, Admin: item.Admin, System: item.System,
		Types: types, DateCreated: item.DateCreated, DateUpdated: item.DateUpdated}
}

func applicationsFromStorage(itemsList []application) []model.Application {
	if len(itemsList) == 0 {
		return make([]model.Application, 0)
	}

	var items []model.Application
	for _, app := range itemsList {
		items = append(items, applicationFromStorage(&app))
	}
	return items
}

//ApplicationType
func applicationTypeFromStorage(item *applicationType) model.ApplicationType {
	if item == nil {
		return model.ApplicationType{}
	}

	appType := model.ApplicationType{ID: item.ID, Identifier: item.Identifier, Name: item.Name}
	versions := versionsFromStorage(item.Versions, appType)
	appType.Versions = versions

	return appType
}

func applicationTypesFromStorage(itemsList []applicationType) []model.ApplicationType {
	if len(itemsList) == 0 {
		return make([]model.ApplicationType, 0)
	}

	var items []model.ApplicationType
	for _, appType := range itemsList {
		items = append(items, applicationTypeFromStorage(&appType))
	}
	return items
}

//AppOrgRole
func appOrgRoleFromStorage(item *appOrgRole, appOrg model.ApplicationOrganization) model.AppOrgRole {
	if item == nil {
		return model.AppOrgRole{}
	}

	return model.AppOrgRole{ID: item.ID, Name: item.Name, Description: item.Description,
		System: item.System, Permissions: item.Permissions, AppOrg: appOrg,
		DateCreated: item.DateCreated, DateUpdated: item.DateUpdated}
}

func appOrgRolesFromStorage(items []appOrgRole, appOrg model.ApplicationOrganization) []model.AppOrgRole {
	if len(items) == 0 {
		return make([]model.AppOrgRole, 0)
	}

	res := make([]model.AppOrgRole, len(items))
	for i, org := range items {
		res[i] = appOrgRoleFromStorage(&org, appOrg)
	}
	return res
}

func appOrgRoleToStorage(item model.AppOrgRole) appOrgRole {
	return appOrgRole{ID: item.ID, Name: item.Name, Description: item.Description,
		System: item.System, AppOrgID: item.AppOrg.ID, Permissions: item.Permissions,
		DateCreated: item.DateCreated, DateUpdated: item.DateUpdated}
}

func appOrgRolesToStorage(items []model.AppOrgRole) []appOrgRole {
	if len(items) == 0 {
		return make([]appOrgRole, 0)
	}

	res := make([]appOrgRole, len(items))
	for i, role := range items {
		res[i] = appOrgRoleToStorage(role)
	}
	return res
}

// AppConfig Version
func versionFromStorage(item *version, appType model.ApplicationType) model.Version {
	if item == nil {
		return model.Version{}
	}

	return model.Version{ID: item.ID, VersionNumbers: item.VersionNumbers, ApplicationType: appType, DateCreated: item.DateCreated, DateUpdated: item.DateUpdated}
}

func versionsFromStorage(itemList []version, appType model.ApplicationType) []model.Version {
	if len(itemList) == 0 {
		return make([]model.Version, 0)
	}

	var items []model.Version
	for _, version := range itemList {
		items = append(items, versionFromStorage(&version, appType))
	}

	return items
}

func versionToStorage(item model.Version) version {
	return version{ID: item.ID, VersionNumbers: item.VersionNumbers, AppTypeID: item.ApplicationType.ID, DateCreated: item.DateCreated, DateUpdated: item.DateUpdated}
}

func versionsToStorage(itemList []model.Version) []version {
	if len(itemList) == 0 {
		return make([]version, 0)
	}

	var items []version
	for _, version := range itemList {
		items = append(items, versionToStorage(version))
	}

	return items
}

// AppConfig
func appConfigFromStorage(item *applicationConfig, appOrg *model.ApplicationOrganization, appType model.ApplicationType) model.ApplicationConfig {
	if item == nil {
		return model.ApplicationConfig{}
	}
	return model.ApplicationConfig{ID: item.ID, AppOrg: appOrg, ApplicationType: appType, Data: item.Data, Version: versionFromStorage(&item.Version, appType), DateCreated: item.DateCreated, DateUpdated: item.DateUpdated}
}

func appConfigsFromStorage(itemList []applicationConfig, appOrg *model.ApplicationOrganization, appType model.ApplicationType) []model.ApplicationConfig {
	if len(itemList) == 0 {
		return make([]model.ApplicationConfig, 0)
	}

	res := make([]model.ApplicationConfig, len(itemList))
	for i, appConfig := range itemList {
		res[i] = appConfigFromStorage(&appConfig, appOrg, appType)
	}

	return res
}

func appConfigToStorage(item model.ApplicationConfig) applicationConfig {
	appConfig := applicationConfig{ID: item.ID, AppTypeID: item.ApplicationType.ID, Version: versionToStorage(item.Version), Data: item.Data, DateCreated: item.DateCreated, DateUpdated: item.DateUpdated}
	if item.AppOrg != nil {
		appConfig.AppOrgID = &item.AppOrg.ID
	}

	return appConfig
}

//AppOrgGroup
func appOrgGroupFromStorage(item *appOrgGroup, appOrg model.ApplicationOrganization) model.AppOrgGroup {
	if item == nil {
		return model.AppOrgGroup{}
	}

	roles := appOrgRolesFromStorage(item.Roles, appOrg)
	return model.AppOrgGroup{ID: item.ID, Name: item.Name, System: item.System, Permissions: item.Permissions, Roles: roles,
		AppOrg: appOrg, DateCreated: item.DateCreated, DateUpdated: item.DateUpdated}
}

func appOrgGroupsFromStorage(items []appOrgGroup, appOrg model.ApplicationOrganization) []model.AppOrgGroup {
	if len(items) == 0 {
		return make([]model.AppOrgGroup, 0)
	}

	res := make([]model.AppOrgGroup, len(items))
	for i, orgGroup := range items {
		res[i] = appOrgGroupFromStorage(&orgGroup, appOrg)
	}
	return res
}

func appOrgGroupToStorage(item model.AppOrgGroup) appOrgGroup {
	roles := appOrgRolesToStorage(item.Roles)
	return appOrgGroup{ID: item.ID, Name: item.Name, System: item.System, AppOrgID: item.AppOrg.ID,
		Permissions: item.Permissions, Roles: roles, DateCreated: item.DateCreated, DateUpdated: item.DateUpdated}
}

func appOrgGroupsToStorage(items []model.AppOrgGroup) []appOrgGroup {
	if len(items) == 0 {
		return make([]appOrgGroup, 0)
	}

	res := make([]appOrgGroup, len(items))
	for i, group := range items {
		res[i] = appOrgGroupToStorage(group)
	}
	return res
}

//Organization
func organizationFromStorage(item *organization) model.Organization {
	if item == nil {
		return model.Organization{}
	}

	return model.Organization{ID: item.ID, Name: item.Name, Type: item.Type,
		Config: item.Config, DateCreated: item.DateCreated, DateUpdated: item.DateUpdated}
}

func organizationsFromStorage(itemsList []organization) []model.Organization {
	if len(itemsList) == 0 {
		return make([]model.Organization, 0)
	}

	var items []model.Organization
	for _, org := range itemsList {
		items = append(items, organizationFromStorage(&org))
	}
	return items
}

func organizationToStorage(item *model.Organization) *organization {
	if item == nil {
		return nil
	}

	return &organization{ID: item.ID, Name: item.Name, Type: item.Type, Config: item.Config,
		DateCreated: item.DateCreated, DateUpdated: item.DateUpdated}
}

//ApplicationOrganization
func applicationOrganizationToStorage(item model.ApplicationOrganization) applicationOrganization {
	return applicationOrganization{ID: item.ID, AppID: item.Application.ID, OrgID: item.Organization.ID,
		ServicesIDs: item.ServicesIDs, IdentityProvidersSettings: item.IdentityProvidersSettings,
		SupportedAuthTypes: item.SupportedAuthTypes, DateCreated: item.DateCreated, DateUpdated: item.DateUpdated}
}

func applicationOrganizationFromStorage(item applicationOrganization, application model.Application, organization model.Organization) model.ApplicationOrganization {
	return model.ApplicationOrganization{ID: item.ID, Application: application, Organization: organization,
		ServicesIDs: item.ServicesIDs, IdentityProvidersSettings: item.IdentityProvidersSettings,
		SupportedAuthTypes: item.SupportedAuthTypes, LoginsSessionsSetting: item.LoginsSessionsSetting,
		DateCreated: item.DateCreated, DateUpdated: item.DateUpdated}
}

func applicationTypeToStorage(item model.ApplicationType) applicationType {
	return applicationType{ID: item.ID, Identifier: item.Identifier, Name: item.Name, Versions: versionsToStorage(item.Versions)}
}

func applicationTypesToStorage(items []model.ApplicationType) []applicationType {
	if len(items) == 0 {
		return make([]applicationType, 0)
	}

	res := make([]applicationType, len(items))
	for i, appllicationType := range items {
		res[i] = applicationTypeToStorage(appllicationType)
	}
	return res
}

func applicationToStorage(item *model.Application) *application {
	applicationTypes := applicationTypesToStorage(item.Types)

	return &application{ID: item.ID, Name: item.Name, MultiTenant: item.MultiTenant,
		SharedIdentities: item.SharedIdentities, Admin: item.Admin, System: item.System,
		Types: applicationTypes, DateCreated: item.DateCreated, DateUpdated: item.DateUpdated}
}
