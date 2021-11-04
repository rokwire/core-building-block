package storage

import (
	"core-building-block/core/model"
)

//Account
func accountFromStorage(item account, sa *Adapter, appOrg model.ApplicationOrganization) model.Account {
	id := item.ID
	permissions := item.Permissions
	roles := appOrgRolesFromStorage(item.Roles, appOrg)
	groups := appOrgGroupsFromStorage(item.Groups, appOrg)
	authTypes := accountAuthTypesFromStorage(item.AuthTypes)
	profile := profileFromStorage(item.Profile)
	devices := accountDevicesFromStorage(item)
	dateCreated := item.DateCreated
	dateUpdated := item.DateUpdated
	return model.Account{ID: id, AppOrg: appOrg, Permissions: permissions,
		Roles: roles, Groups: groups, AuthTypes: authTypes, Preferences: item.Preferences, Profile: profile,
		Devices: devices, DateCreated: dateCreated, DateUpdated: dateUpdated}
}

func accountToStorage(item *model.Account) *account {
	id := item.ID
	appOrgID := item.AppOrg.ID
	permissions := item.Permissions
	roles := appOrgRolesToStorage(item.Roles)
	groups := appOrgGroupsToStorage(item.Groups)
	authTypes := accountAuthTypesToStorage(item.AuthTypes)
	profile := profileToStorage(item.Profile)
	devices := accountDevicesToStorage(item)
	dateCreated := item.DateCreated
	dateUpdated := item.DateUpdated

	return &account{ID: id, AppOrgID: appOrgID, Permissions: permissions, Roles: roles, Groups: groups, AuthTypes: authTypes,
		Preferences: item.Preferences, Profile: profile, Devices: devices, DateCreated: dateCreated, DateUpdated: dateUpdated}
}

/*func getAccountFromStorage(item []account) []model.Account {
	if item == nil {
		return nil
	}
	/*profile := profileToStorage(item.Profile)
	//permissions
	permissions := applicationPermissionsToStorage(item.Permissions)
	//roles
	roles := applicationRolesToStorage(item.Roles)
	//groups
	groups := applicationGroupsToStorage(item.Groups)
	//account auth types
	authTypes := accountAuthTypesToStorage(item.AuthTypes)
	appID := item.Application.ID
	orgID := item.Organization.ID

	return &model.Account{Permissions: item.Permissions, Roles: item.Roles, Groups: item.Groups, AuthTypes: item.AuthTypes,
		Preferences: item.Preferences, Profile: item.Profile}
}*/

/*func getAccountsListToStorage(item []model.Account) []model.Account {
	if len(item) == 0 {
		return make([]model.Account, 0)
	}

	var items []model.Account
	for _, accounts := range item {
		items = append(items, accountFromStorage(accounts))
	}
	return items
}*/

func accountDevicesFromStorage(item account) []model.Device {
	devices := make([]model.Device, len(item.Devices))

	for i, device := range item.Devices {
		devices[i] = accountDeviceFromStorage(device)
	}
	return devices
}

func accountDeviceFromStorage(item userDevice) model.Device {
	return model.Device{ID: item.ID, Type: item.Type, OS: item.OS,
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
	return userDevice{ID: item.ID, Type: item.Type, OS: item.OS,
		DateCreated: item.DateCreated, DateUpdated: item.DateUpdated}
}

//AccountAuthType
func accountAuthTypeFromStorage(item accountAuthType) model.AccountAuthType {
	id := item.ID
	authType := model.AuthType{ID: item.AuthTypeID, Code: item.AuthTypeCode}
	identifier := item.Identifier
	params := item.Params
	var credential *model.Credential
	if item.CredentialID != nil {
		credential = &model.Credential{ID: *item.CredentialID}
	}
	active := item.Active
	active2FA := item.Active2FA
	return model.AccountAuthType{ID: id, AuthType: authType, Identifier: identifier, Params: params, Credential: credential,
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

func accountAuthTypeToStorage(item model.AccountAuthType) accountAuthType {
	var credentialID *string
	if item.Credential != nil {
		credentialID = &item.Credential.ID
	}
	return accountAuthType{ID: item.ID, AuthTypeID: item.AuthType.ID, AuthTypeCode: item.AuthType.Code, Identifier: item.Identifier,
		Params: item.Params, CredentialID: credentialID, Active: item.Active, Active2FA: item.Active2FA, DateCreated: item.DateCreated, DateUpdated: item.DateUpdated}
}

func accountAuthTypesToStorage(items []model.AccountAuthType) []accountAuthType {
	if len(items) == 0 {
		return make([]accountAuthType, 0)
	}

	res := make([]accountAuthType, len(items))
	for i, aat := range items {
		res[i] = accountAuthTypeToStorage(aat)
	}
	return res
}

//Profile
func profileFromStorage(item profile) model.Profile {
	return model.Profile{ID: item.ID, PhotoURL: item.PhotoURL, FirstName: item.FirstName, LastName: item.LastName,
		Email: item.Email, Phone: item.Phone, BirthYear: item.BirthYear, Address: item.Address, ZipCode: item.ZipCode,
		State: item.State, Country: item.Country, DateCreated: item.DateCreated, DateUpdated: item.DateUpdated}
}

func profileToStorage(item model.Profile) profile {
	return profile{ID: item.ID, PhotoURL: item.PhotoURL, FirstName: item.FirstName, LastName: item.LastName,
		Email: item.Email, Phone: item.Phone, BirthYear: item.BirthYear, Address: item.Address, ZipCode: item.ZipCode,
		State: item.State, Country: item.Country, DateCreated: item.DateCreated, DateUpdated: item.DateUpdated}
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

	return &device{ID: item.ID, Type: item.Type, OS: item.OS,
		Accounts: accounts, DateCreated: item.DateCreated, DateUpdated: item.DateUpdated}
}

//Credential
func credentialFromStorage(item credential) model.Credential {
	accountAuthTypes := make([]model.AccountAuthType, len(item.AccountsAuthTypes))
	for i, id := range item.AccountsAuthTypes {
		accountAuthTypes[i] = model.AccountAuthType{ID: id}
	}
	authType := model.AuthType{ID: item.AuthTypeID}
	return model.Credential{ID: item.ID, AuthType: authType, AccountsAuthTypes: accountAuthTypes, Verified: item.Verified,
		Value: item.Value, DateCreated: item.DateCreated, DateUpdated: item.DateUpdated}
}

func credentialToStorage(item *model.Credential) *credential {
	if item == nil {
		return nil
	}

	accountAuthTypes := make([]string, len(item.AccountsAuthTypes))
	for i, aat := range item.AccountsAuthTypes {
		accountAuthTypes[i] = aat.ID
	}
	return &credential{ID: item.ID, AuthTypeID: item.AuthType.ID, AccountsAuthTypes: accountAuthTypes, Verified: item.Verified,
		Value: item.Value, DateCreated: item.DateCreated, DateUpdated: item.DateUpdated}
}
