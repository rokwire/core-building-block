package storage

import (
	"core-building-block/core/model"
)

//Account
func accountFromStorage(item account, sa *Adapter, application model.Application, organziation model.Organization) model.Account {
	id := item.ID
	permissions := applicationPermissionsFromStorage(item.Permissions, application)
	roles := applicationRolesFromStorage(item.Roles, application)
	groups := applicationGroupsFromStorage(item.Groups, application)
	authTypes := accountAuthTypesFromStorage(item.AuthTypes)
	profile := profileFromStorage(item.Profile)
	devices := accountDevicesFromStorage(item)
	dateCreated := item.DateCreated
	dateUpdated := item.DateUpdated
	return model.Account{ID: id, Application: application, Organization: organziation,
		Permissions: permissions, Roles: roles, Groups: groups, AuthTypes: authTypes, Profile: profile,
		Devices: devices, DateCreated: dateCreated, DateUpdated: dateUpdated}
}

func accountToStorage(item *model.Account) *account {
	/*	if item == nil {
			return nil
		}

		id := item.ID
		applicationsAccounts := item.ApplicationsAccounts
		profile := item.Profile
		devices := userDevicesToStorage(item)
		dateCreated := item.DateCreated
		dateUpdated := item.DateUpdated

		return &user{ID: id, ApplicationsAccounts: applicationsAccounts, Profile: profile,
			Devices: devices, DateCreated: dateCreated, DateUpdated: dateUpdated} */
	return nil
}

func accountDevicesFromStorage(item account) []model.Device {
	devices := make([]model.Device, len(item.Devices))

	for i, device := range item.Devices {
		devices[i] = accountDeviceFromStorage(device)
	}
	return devices
}

func accountDeviceFromStorage(item userDevice) model.Device {
	return model.Device{ID: item.ID, Type: item.Type, OS: item.OS, MacAddress: item.MacAddress,
		DateCreated: item.DateCreated, DateUpdated: item.DateUpdated}
}

func accountDevicesToStorage(item *model.Account) []userDevice {
	devices := make([]userDevice, len(item.Devices))

	for i, device := range item.Devices {
		devices[i] = accountDeviceToStorage(device)
	}
	return devices
}

func accountDeviceToStorage(item model.Device) userDevice {
	return userDevice{ID: item.ID, Type: item.Type, OS: item.OS, MacAddress: item.MacAddress,
		DateCreated: item.DateCreated, DateUpdated: item.DateUpdated}
}

//AccountAuthType
func accountAuthTypeFromStorage(item accountAuthType) model.AccountAuthType {
	id := item.ID
	authType := model.AuthType{ID: item.AuthTypeID}
	identifier := item.Identifier
	params := item.Params
	active := item.Active
	active2FA := item.Active2FA
	return model.AccountAuthType{ID: id, AuthType: authType, Identifier: identifier, Params: params,
		Active: active, Active2FA: active2FA, DateCreated: item.DateCreated, DateUpdated: item.DateUpdated}
}

func accountAuthTypesFromStorage(items []accountAuthType) []model.AccountAuthType {
	if len(items) == 0 {
		return make([]model.AccountAuthType, 0)
	}

	res := make([]model.AccountAuthType, len(items))
	for i, aat := range items {
		res[i] = accountAuthTypeFromStorage(aat)
	}
	return res
}

//Profile
func profileFromStorage(item profile) model.Profile {
	return model.Profile{ID: item.ID, PhotoURL: item.PhotoURL, FirstName: item.FirstName, LastName: item.LastName,
		DateCreated: item.DateCreated, DateUpdated: item.DateUpdated}
}

//Device
func deviceToStorage(item *model.Device) *device {
	if item == nil {
		return nil
	}

	accounts := make([]string, len(item.Accounts))
	for i, account := range item.Accounts {
		accounts[i] = account.ID
	}

	return &device{ID: item.ID, Type: item.Type, OS: item.OS, MacAddress: item.MacAddress,
		Accounts: accounts, DateCreated: item.DateCreated, DateUpdated: item.DateUpdated}
}
