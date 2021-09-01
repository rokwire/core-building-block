package storage

import (
	"core-building-block/core/model"
)

//User
func userFromStorage(item *user, sa *Adapter) model.User {
	if item == nil {
		return model.User{}
	}

	id := item.ID
	applicationsAccounts := item.ApplicationsAccounts
	profile := item.Profile
	organizationsMemberships := userMembershipsFromStorage(*item, sa)
	devices := userDevicesFromStorage(*item)
	dateCreated := item.DateCreated
	dateUpdated := item.DateUpdated

	return model.User{ID: id, ApplicationsAccounts: applicationsAccounts, Profile: profile,
		OrganizationsMemberships: organizationsMemberships, Devices: devices,
		DateCreated: dateCreated, DateUpdated: dateUpdated}

}

func userToStorage(item *model.User) *user {
	if item == nil {
		return nil
	}

	id := item.ID
	applicationsAccounts := item.ApplicationsAccounts
	profile := item.Profile
	organizationsMemberships := userMembershipsToStorage(item)
	devices := userDevicesToStorage(item)
	dateCreated := item.DateCreated
	dateUpdated := item.DateUpdated

	return &user{ID: id, ApplicationsAccounts: applicationsAccounts, Profile: profile,
		OrganizationsMemberships: organizationsMemberships, Devices: devices,
		DateCreated: dateCreated, DateUpdated: dateUpdated}
}

func userMembershipsFromStorage(item user, sa *Adapter) []model.OrganizationMembership {
	memberships := make([]model.OrganizationMembership, len(item.OrganizationsMemberships))

	for i, membership := range item.OrganizationsMemberships {
		organization, err := sa.getCachedOrganization(membership.OrgID)
		if err != nil {
			sa.logger.Errorf("error getting organization - %s", err)
		} else {
			memberships[i] = userMembershipFromStorage(membership, *organization)
		}
	}
	return memberships
}

func userMembershipFromStorage(item userMembership, organization model.Organization) model.OrganizationMembership {
	id := item.ID
	dateCreated := item.DateCreated
	dateUpdated := item.DateUpdated

	return model.OrganizationMembership{ID: id, Organization: organization, DateCreated: dateCreated, DateUpdated: dateUpdated}
}

func userMembershipsToStorage(item *model.User) []userMembership {
	memberships := make([]userMembership, len(item.OrganizationsMemberships))

	for i, membership := range item.OrganizationsMemberships {
		memberships[i] = userMembershipToStorage(membership)
	}
	return memberships
}

func userMembershipToStorage(item model.OrganizationMembership) userMembership {
	id := item.ID
	orgID := item.Organization.ID
	dateCreated := item.DateCreated
	dateUpdated := item.DateUpdated

	return userMembership{ID: id, OrgID: orgID, DateCreated: dateCreated, DateUpdated: dateUpdated}
}

func userDevicesFromStorage(item user) []model.Device {
	devices := make([]model.Device, len(item.Devices))

	for i, device := range item.Devices {
		devices[i] = userDeviceFromStorage(device)
	}
	return devices
}

func userDeviceFromStorage(item userDevice) model.Device {
	return model.Device{ID: item.ID, Type: item.Type, OS: item.OS, MacAddress: item.MacAddress,
		DateCreated: item.DateCreated, DateUpdated: item.DateUpdated}
}

func userDevicesToStorage(item *model.User) []userDevice {
	devices := make([]userDevice, len(item.Devices))

	for i, device := range item.Devices {
		devices[i] = userDeviceToStorage(device)
	}
	return devices
}

func userDeviceToStorage(item model.Device) userDevice {
	return userDevice{ID: item.ID, Type: item.Type, OS: item.OS, MacAddress: item.MacAddress,
		DateCreated: item.DateCreated, DateUpdated: item.DateUpdated}
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
