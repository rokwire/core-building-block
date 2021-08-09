package storage

import (
	"core-building-block/core/model"
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

//Device

func deviceToStorage(item *model.Device) *device {
	if item == nil {
		return nil
	}

	users := make([]string, len(item.Users))
	for i, user := range item.Users {
		users[i] = user.ID
	}

	return &device{ID: item.ID, Type: item.Type, OS: item.OS, MacAddress: item.MacAddress,
		Users: users, DateCreated: item.DateCreated, DateUpdated: item.DateUpdated}
}
