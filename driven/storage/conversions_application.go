package storage

import (
	"core-building-block/core/model"

	"github.com/rokwire/core-auth-library-go/authservice"
)

//Application
func applicationFromStorage(item *application) model.Application {
	if item == nil {
		return model.Application{}
	}

	types := applicationTypesFromStorage(item.Types)
	return model.Application{ID: item.ID, Name: item.Name, MultiTenant: item.MultiTenant, RequiresOwnUsers: item.RequiresOwnUsers, Admin: item.Admin,
		MaxLoginSessionDuration: item.MaxLoginSessionDuration, Types: types, DateCreated: item.DateCreated, DateUpdated: item.DateUpdated}
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

	return model.ApplicationType{ID: item.ID, Identifier: item.Identifier, Name: item.Name, Versions: item.Versions}
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
func applicationOrganizationFromStorage(item applicationOrganization, application model.Application, organization model.Organization) model.ApplicationOrganization {
	return model.ApplicationOrganization{ID: item.ID, Application: application, Organization: organization,
		ServicesIDs: item.ServicesIDs, IdentityProvidersSettings: item.IdentityProvidersSettings,
		SupportedAuthTypes: item.SupportedAuthTypes, DateCreated: item.DateCreated, DateUpdated: item.DateUpdated}
}

func applicationTypeToStorage(item model.ApplicationType) applicationType {
	return applicationType{ID: item.ID, Identifier: item.Identifier, Name: item.Name, Versions: item.Versions}
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

	return &application{ID: item.ID, Name: item.Name, MultiTenant: item.MultiTenant, RequiresOwnUsers: item.RequiresOwnUsers, Admin: item.Admin,
		MaxLoginSessionDuration: item.MaxLoginSessionDuration, Types: applicationTypes, DateCreated: item.DateCreated, DateUpdated: item.DateUpdated}
}

//ServiceID
func serviceIDFromStorage(item *model.ApplicationOrganization) *model.ApplicationOrganization {

	return &model.ApplicationOrganization{ServicesIDs: item.ServicesIDs}
}

func serviceRegToStorage(item *model.ServiceReg) *model.ServiceReg {
	if item == nil {
		return nil
	}
	return &model.ServiceReg{Registration: authservice.ServiceReg{ServiceID: item.Registration.ServiceID, Host: item.Registration.Host}}
}

func serviceRegListToStorage(items []model.ServiceReg) []model.ServiceReg {
	out := make([]model.ServiceReg, len(items))
	for i, item := range items {
		servRegItems := serviceRegToStorage(&item)
		if servRegItems != nil {
			out[i] = *servRegItems
		} else {
			out[i] = model.ServiceReg{}
		}
	}
	return out
}
