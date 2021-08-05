package storage

import (
	"core-building-block/core/model"
	"fmt"
)

//User
func userFromStorage(item *user, sa *Adapter) model.User {
	if item == nil {
		return model.User{}
	}

	return model.User{ID: item.ID, Account: item.Account, Profile: item.Profile,
		Permissions: item.Permissions, Roles: item.Roles, Groups: item.Groups,
		OrganizationsMemberships: organizationMembershipListFromUserStorage(item.OrganizationsMemberships, sa), Devices: item.Devices,
		DateCreated: item.DateCreated, DateUpdated: item.DateUpdated}
}

func userToStorage(item *model.User) *user {
	if item == nil {
		return nil
	}

	return &user{ID: item.ID, Account: item.Account, Profile: item.Profile, Permissions: item.Permissions, Roles: item.Roles, Groups: item.Groups, OrganizationsMemberships: organizationMembershipListToUserStorage(item.OrganizationsMemberships), Devices: item.Devices}
}

//OrganizationMembership
func organizationMembershipFromUserStorage(item *userMembership, sa *Adapter) *model.OrganizationMembership {
	if item == nil {
		return nil
	}

	membership := model.OrganizationMembership{ID: item.ID, OrgUserData: item.OrgUserData,
		Permissions: item.Permissions, Roles: item.Roles, Groups: item.Groups,
		DateCreated: item.DateCreated, DateUpdated: item.DateUpdated}

	org, err := sa.getOrganization(item.OrgID)
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
