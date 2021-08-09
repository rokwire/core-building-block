package storage

import (
	"core-building-block/core/model"
	"fmt"
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
		LoginTypes: item.LoginTypes, Config: item.Config, Applications: nil, DateCreated: item.DateCreated, DateUpdated: item.DateUpdated}
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

//OrganizationRole
func organizationRoleFromStorage(item *organizationRole, organization model.Organization) model.OrganizationRole {
	if item == nil {
		return model.OrganizationRole{}
	}

	permissions := make([]model.OrganizationPermission, len(item.Permissions))
	for i, permission := range item.Permissions {
		permissions[i] = organizationPermissionFromStorage(&permission, organization)
	}

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

//OrganizationGroup
func organizationGroupFromStorage(item *organizationGroup, organization model.Organization) model.OrganizationGroup {
	if item == nil {
		return model.OrganizationGroup{}
	}

	permissions := make([]model.OrganizationPermission, len(item.Permissions))
	for i, permission := range item.Permissions {
		permissions[i] = organizationPermissionFromStorage(&permission, organization)
	}

	roles := make([]model.OrganizationRole, len(item.Roles))
	for i, role := range item.Roles {
		roles[i] = organizationRoleFromStorage(&role, organization)
	}

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

//OrganizationMembership
func organizationMembershipFromUserStorage(item *userMembership, sa *Adapter) *model.OrganizationMembership {
	if item == nil {
		return nil
	}

	membership := model.OrganizationMembership{ID: item.ID, OrgUserData: item.OrgUserData,
		Permissions: item.Permissions, Roles: item.Roles, Groups: item.Groups,
		DateCreated: item.DateCreated, DateUpdated: item.DateUpdated}

	org, err := sa.getCachedOrganization(item.OrgID)
	if err != nil {
		fmt.Printf("failed to find cached organization for org_id %s\n", item.OrgID)
	} else {
		membership.Organization = *org
	}

	return &membership
}

func organizationMembershipToUserStorage(item *model.OrganizationMembership) *userMembership {
	if item == nil {
		return nil
	}

	return &userMembership{ID: item.ID, OrgID: item.Organization.ID, OrgUserData: item.OrgUserData,
		Permissions: item.Permissions, Roles: item.Roles, Groups: item.Groups,
		DateCreated: item.DateCreated, DateUpdated: item.DateUpdated}
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
