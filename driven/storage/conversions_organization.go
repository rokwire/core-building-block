package storage

import (
	"core-building-block/core/model"
)

//Organization
func organizationFromStorage(item *organization, applications []model.Application) model.Organization {
	if item == nil {
		return model.Organization{}
	}

	return model.Organization{ID: item.ID, Name: item.Name, Type: item.Type,
		Config: item.Config, Applications: applications, DateCreated: item.DateCreated, DateUpdated: item.DateUpdated}
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

	return &organization{ID: item.ID, Name: item.Name, Type: item.Type, Config: item.Config,
		Applications: applicationsIDs, DateCreated: item.DateCreated, DateUpdated: item.DateUpdated}
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
