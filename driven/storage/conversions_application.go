package storage

import "core-building-block/core/model"

//ApplicationPermission
func applicationPermissionFromStorage(item *applicationPermission, application model.Application) model.ApplicationPermission {
	if item == nil {
		return model.ApplicationPermission{}
	}

	return model.ApplicationPermission{ID: item.ID, Name: item.Name, Application: application,
		DateCreated: item.DateCreated, DateUpdated: item.DateUpdated}
}

func applicationPermissionsFromStorage(items []applicationPermission, application model.Application) []model.ApplicationPermission {
	if len(items) == 0 {
		return make([]model.ApplicationPermission, 0)
	}

	res := make([]model.ApplicationPermission, len(items))
	for i, org := range items {
		res[i] = applicationPermissionFromStorage(&org, application)
	}
	return res
}

func applicationPermissionToStorage(item model.ApplicationPermission) applicationPermission {
	return applicationPermission{ID: item.ID, Name: item.Name, AppID: item.Application.ID, DateCreated: item.DateCreated, DateUpdated: item.DateUpdated}
}

func applicationPermissionsToStorage(items []model.ApplicationPermission) []applicationPermission {
	if len(items) == 0 {
		return make([]applicationPermission, 0)
	}

	res := make([]applicationPermission, len(items))
	for i, permission := range items {
		res[i] = applicationPermissionToStorage(permission)
	}
	return res
}

//ApplicationRole
func applicationRoleFromStorage(item *applicationRole, application model.Application) model.ApplicationRole {
	if item == nil {
		return model.ApplicationRole{}
	}

	permissions := applicationPermissionsFromStorage(item.Permissions, application)
	return model.ApplicationRole{ID: item.ID, Name: item.Name, Description: item.Description,
		Permissions: permissions, Application: application,
		DateCreated: item.DateCreated, DateUpdated: item.DateUpdated}
}

func applicationRolesFromStorage(items []applicationRole, application model.Application) []model.ApplicationRole {
	if len(items) == 0 {
		return make([]model.ApplicationRole, 0)
	}

	res := make([]model.ApplicationRole, len(items))
	for i, org := range items {
		res[i] = applicationRoleFromStorage(&org, application)
	}
	return res
}

func applicationRoleToStorage(item model.ApplicationRole) applicationRole {
	permissions := applicationPermissionsToStorage(item.Permissions)
	return applicationRole{ID: item.ID, Name: item.Name, Description: item.Description,
		AppID: item.Application.ID, Permissions: permissions,
		DateCreated: item.DateCreated, DateUpdated: item.DateUpdated}
}

func applicationRolesToStorage(items []model.ApplicationRole) []applicationRole {
	if len(items) == 0 {
		return make([]applicationRole, 0)
	}

	res := make([]applicationRole, len(items))
	for i, role := range items {
		res[i] = applicationRoleToStorage(role)
	}
	return res
}

//ApplicationGroup
func applicationGroupFromStorage(item *applicationGroup, application model.Application) model.ApplicationGroup {
	if item == nil {
		return model.ApplicationGroup{}
	}

	permissions := applicationPermissionsFromStorage(item.Permissions, application)
	roles := applicationRolesFromStorage(item.Roles, application)
	return model.ApplicationGroup{ID: item.ID, Name: item.Name, Permissions: permissions, Roles: roles,
		Application: application, DateCreated: item.DateCreated, DateUpdated: item.DateUpdated}
}

func applicationGroupsFromStorage(items []applicationGroup, application model.Application) []model.ApplicationGroup {
	if len(items) == 0 {
		return make([]model.ApplicationGroup, 0)
	}

	res := make([]model.ApplicationGroup, len(items))
	for i, orgGroup := range items {
		res[i] = applicationGroupFromStorage(&orgGroup, application)
	}
	return res
}

func applicationGroupToStorage(item model.ApplicationGroup) applicationGroup {
	permissions := applicationPermissionsToStorage(item.Permissions)
	roles := applicationRolesToStorage(item.Roles)
	return applicationGroup{ID: item.ID, Name: item.Name, AppID: item.Application.ID,
		Permissions: permissions, Roles: roles, DateCreated: item.DateCreated, DateUpdated: item.DateUpdated}
}

func applicationGroupsToStorage(items []model.ApplicationGroup) []applicationGroup {
	if len(items) == 0 {
		return make([]applicationGroup, 0)
	}

	res := make([]applicationGroup, len(items))
	for i, group := range items {
		res[i] = applicationGroupToStorage(group)
	}
	return res
}

//Organization
func organizationFromStorage(item *organization, applications []model.Application) model.Organization {
	if item == nil {
		return model.Organization{}
	}

	//TODO
	return model.Organization{ID: item.ID, Name: item.Name, Type: item.Type,
		Config: item.Config /* Applications: applications,*/, DateCreated: item.DateCreated, DateUpdated: item.DateUpdated}
}

func organizationsFromStorage(itemsList []organization, applications []model.Application) []model.Organization {
	if len(itemsList) == 0 {
		return make([]model.Organization, 0)
	}

	var items []model.Organization
	for _, org := range itemsList {
		//prepare the organization applications
		var orgApplications []model.Application
		if len(org.Applications) > 0 {
			for _, appID := range org.Applications {
				for _, app := range applications {
					if appID == app.ID {
						orgApplications = append(orgApplications, app)
					}
				}
			}
		}

		items = append(items, organizationFromStorage(&org, orgApplications))
	}
	return items
}

func organizationToStorage(item *model.Organization) *organization {
	if item == nil {
		return nil
	}

	//TODO
	/*
		//prepare applications
		applicationsIDs := make([]string, len(item.Applications))
		for i, application := range item.Applications {
			applicationsIDs[i] = application.ID
		} */

	return &organization{ID: item.ID, Name: item.Name, Type: item.Type, Config: item.Config,
		Applications: nil, DateCreated: item.DateCreated, DateUpdated: item.DateUpdated}
}
