package storage

import (
	"core-building-block/core/model"
)

//Organization
func organizationFromStorage(item *organization, applications []model.Application) model.Organization {
	if item == nil {
		return model.Organization{}
	}

	return model.Organization{ID: item.ID, Name: item.Name, Type: item.Type, RequiresOwnLogin: item.RequiresOwnLogin,
		LoginTypes: item.LoginTypes, Config: item.Config, Applications: applications,
		DateCreated: item.DateCreated, DateUpdated: item.DateUpdated}
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

	//prepare applications
	applicationsIDs := make([]string, len(item.Applications))
	for i, application := range item.Applications {
		applicationsIDs[i] = application.ID
	}

	return &organization{ID: item.ID, Name: item.Name, Type: item.Type, RequiresOwnLogin: item.RequiresOwnLogin,
		LoginTypes: item.LoginTypes, Config: item.Config, Applications: applicationsIDs, DateCreated: item.DateCreated, DateUpdated: item.DateUpdated}
}

//OrganizationPermission
func organizationPermissionFromStorage(item *organizationPermission, organization model.Organization) model.OrganizationPermission {
	if item == nil {
		return model.OrganizationPermission{}
	}

	return model.OrganizationPermission{ID: item.ID, Name: item.Name, Organization: organization,
		DateCreated: item.DateCreated, DateUpdated: item.DateUpdated}
}

func organizationPermissionsFromStorage(items []organizationPermission, organization model.Organization) []model.OrganizationPermission {
	if len(items) == 0 {
		return make([]model.OrganizationPermission, 0)
	}

	res := make([]model.OrganizationPermission, len(items))
	for i, org := range items {
		res[i] = organizationPermissionFromStorage(&org, organization)
	}
	return res
}

func organizationPermissionToStorage(item model.OrganizationPermission) organizationPermission {
	return organizationPermission{ID: item.ID, Name: item.Name, OrgID: item.Organization.ID, DateCreated: item.DateCreated, DateUpdated: item.DateUpdated}
}

func organizationPermissionsToStorage(items []model.OrganizationPermission) []organizationPermission {
	if len(items) == 0 {
		return make([]organizationPermission, 0)
	}

	res := make([]organizationPermission, len(items))
	for i, permission := range items {
		res[i] = organizationPermissionToStorage(permission)
	}
	return res
}

//OrganizationRole
func organizationRoleFromStorage(item *organizationRole, organization model.Organization) model.OrganizationRole {
	if item == nil {
		return model.OrganizationRole{}
	}

	permissions := organizationPermissionsFromStorage(item.Permissions, organization)
	return model.OrganizationRole{ID: item.ID, Name: item.Name, Description: item.Description,
		Permissions: permissions, Organization: organization,
		DateCreated: item.DateCreated, DateUpdated: item.DateUpdated}
}

func organizationRolesFromStorage(items []organizationRole, organization model.Organization) []model.OrganizationRole {
	if len(items) == 0 {
		return make([]model.OrganizationRole, 0)
	}

	res := make([]model.OrganizationRole, len(items))
	for i, org := range items {
		res[i] = organizationRoleFromStorage(&org, organization)
	}
	return res
}

func organizationRoleToStorage(item model.OrganizationRole) organizationRole {
	permissions := organizationPermissionsToStorage(item.Permissions)
	return organizationRole{ID: item.ID, Name: item.Name, Description: item.Description,
		OrgID: item.Organization.ID, Permissions: permissions,
		DateCreated: item.DateCreated, DateUpdated: item.DateUpdated}
}

func organizationRolesToStorage(items []model.OrganizationRole) []organizationRole {
	if len(items) == 0 {
		return make([]organizationRole, 0)
	}

	res := make([]organizationRole, len(items))
	for i, role := range items {
		res[i] = organizationRoleToStorage(role)
	}
	return res
}

//OrganizationGroup
func organizationGroupFromStorage(item *organizationGroup, organization model.Organization) model.OrganizationGroup {
	if item == nil {
		return model.OrganizationGroup{}
	}

	permissions := organizationPermissionsFromStorage(item.Permissions, organization)
	roles := organizationRolesFromStorage(item.Roles, organization)
	return model.OrganizationGroup{ID: item.ID, Name: item.Name, Permissions: permissions, Roles: roles,
		Organization: organization, DateCreated: item.DateCreated, DateUpdated: item.DateUpdated}
}

func organizationGroupsFromStorage(items []organizationGroup, organization model.Organization) []model.OrganizationGroup {
	if len(items) == 0 {
		return make([]model.OrganizationGroup, 0)
	}

	res := make([]model.OrganizationGroup, len(items))
	for i, orgGroup := range items {
		res[i] = organizationGroupFromStorage(&orgGroup, organization)
	}
	return res
}

func organizationGroupToStorage(item model.OrganizationGroup) organizationGroup {
	permissions := organizationPermissionsToStorage(item.Permissions)
	roles := organizationRolesToStorage(item.Roles)
	return organizationGroup{ID: item.ID, Name: item.Name, OrgID: item.Organization.ID,
		Permissions: permissions, Roles: roles, DateCreated: item.DateCreated, DateUpdated: item.DateUpdated}
}

func organizationGroupsToStorage(items []model.OrganizationGroup) []organizationGroup {
	if len(items) == 0 {
		return make([]organizationGroup, 0)
	}

	res := make([]organizationGroup, len(items))
	for i, group := range items {
		res[i] = organizationGroupToStorage(group)
	}
	return res
}

//Application
func applicationFromStorage(item *application) model.Application {
	if item == nil {
		return model.Application{}
	}
	return model.Application{ID: item.ID, Name: item.Name, Versions: item.Versions,
		DateCreated: item.DateCreated, DateUpdated: item.DateUpdated}
}

func applicationsFromStorage(items []application) []model.Application {
	if len(items) == 0 {
		return make([]model.Application, 0)
	}

	res := make([]model.Application, len(items))
	for i, app := range items {
		res[i] = applicationFromStorage(&app)
	}
	return res
}

//OrganizationMembership
/*
func organizationMembershipFromUserStorage(item *userMembership, sa *Adapter) *model.OrganizationMembership {
	if item == nil {
		return nil
	}

	membership := model.OrganizationMembership{ID: item.ID, OrgUserData: item.OrgUserData,
		DateCreated: item.DateCreated, DateUpdated: item.DateUpdated}

	org, err := sa.getCachedOrganization(item.OrgID)
	if err != nil {
		sa.db.logger.Warnf("failed to find cached organization for org_id %s\n", item.OrgID)
	} else {
		membership.Organization = *org
		membership.Permissions = organizationPermissionsFromStorage(item.Permissions, *org)
		membership.Roles = organizationRolesFromStorage(item.Roles, *org)
		membership.Groups = organizationGroupsFromStorage(item.Groups, *org)
	}

	return &membership
}

func organizationMembershipToUserStorage(item *model.OrganizationMembership) *userMembership {
	if item == nil {
		return nil
	}

	permissions := organizationPermissionsToStorage(item.Permissions)
	roles := organizationRolesToStorage(item.Roles)
	groups := organizationGroupsToStorage(item.Groups)
	return &userMembership{ID: item.ID, OrgID: item.Organization.ID, OrgUserData: item.OrgUserData,
		Permissions: permissions, Roles: roles, Groups: groups, DateCreated: item.DateCreated, DateUpdated: item.DateUpdated}
}

func organizationMembershipListFromUserStorage(items []userMembership, sa *Adapter) []model.OrganizationMembership {
	if items == nil {
		return nil
	}
	out := make([]model.OrganizationMembership, len(items))
	for i, item := range items {
		defItem := organizationMembershipFromUserStorage(&item, sa)
		if defItem != nil {
			out[i] = *defItem
		} else {
			out[i] = model.OrganizationMembership{}
		}
	}
	return out
}

func organizationMembershipListToUserStorage(items []model.OrganizationMembership) []userMembership {
	if items == nil {
		return nil
	}
	out := make([]userMembership, len(items))
	for i, item := range items {
		defItem := organizationMembershipToUserStorage(&item)
		if defItem != nil {
			out[i] = *defItem
		} else {
			out[i] = userMembership{}
		}
	}
	return out
}
*/
