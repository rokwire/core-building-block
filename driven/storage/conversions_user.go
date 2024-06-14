// Copyright 2022 Board of Trustees of the University of Illinois.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package storage

import (
	"core-building-block/core/model"
)

// OrgAppMembership
func orgAppMembershipFromStorage(item orgAppMembership, appOrg model.ApplicationOrganization) model.OrgAppMembership {
	roles := accountRolesFromStorage(item.Roles, appOrg)
	groups := accountGroupsFromStorage(item.Groups, appOrg)

	return model.OrgAppMembership{ID: item.ID, AppOrg: appOrg, Permissions: item.Permissions,
		Roles: roles, Groups: groups, Preferences: item.Preferences,
		MostRecentClientVersion: item.MostRecentClientVersion}
}

func orgAppsMembershipsFromStorage(items []orgAppMembership, appsOrgs []model.ApplicationOrganization) []model.OrgAppMembership {
	if len(items) == 0 {
		return make([]model.OrgAppMembership, 0)
	}

	res := make([]model.OrgAppMembership, len(items))
	for i, item := range items {
		//find the application organization
		var appOrg *model.ApplicationOrganization
		for _, cAppOrg := range appsOrgs {
			if cAppOrg.ID == item.AppOrgID {
				current := cAppOrg
				appOrg = &current
				break
			}
		}

		if appOrg != nil {
			res[i] = orgAppMembershipFromStorage(item, *appOrg)
		}
	}
	return res
}

func orgAppMembershipToStorage(item model.OrgAppMembership) orgAppMembership {
	id := item.ID
	appOrgID := item.AppOrg.ID
	permissions := item.Permissions
	roles := accountRolesToStorage(item.Roles)
	groups := accountGroupsToStorage(item.Groups)
	preferences := item.Preferences
	mostRecentClientVersion := item.MostRecentClientVersion

	return orgAppMembership{ID: id, AppOrgID: appOrgID, Permissions: permissions, Roles: roles, Groups: groups,
		Preferences: preferences, MostRecentClientVersion: mostRecentClientVersion}
}

func orgAppsMembershipsToStorage(items []model.OrgAppMembership) []orgAppMembership {
	res := make([]orgAppMembership, len(items))
	for i, c := range items {
		res[i] = orgAppMembershipToStorage(c)
	}
	return res
}

// DeletedOrgAppMembership
func deletedMembershipsFromStorage(items []deletedOrgAppMembership, appsOrgs []model.ApplicationOrganization) []model.DeletedOrgAppMembership {
	if len(items) == 0 {
		return make([]model.DeletedOrgAppMembership, 0)
	}

	res := make([]model.DeletedOrgAppMembership, len(items))
	for i, item := range items {
		//find the application organization
		appOrg := model.ApplicationOrganization{ID: item.AppOrgID}
		for i := range appsOrgs {
			cAppOrg := appsOrgs[i]
			if cAppOrg.ID == item.AppOrgID {
				appOrg = cAppOrg
				break
			}
		}

		res[i] = model.DeletedOrgAppMembership{ID: item.ID, AccountID: item.AccountID,
			ExternalIDs: item.ExternalIDs, AppOrg: appOrg, Context: item.Context, DateCreated: item.DateCreated}
	}
	return res
}

func deletedMembershipToStorage(item model.DeletedOrgAppMembership) deletedOrgAppMembership {
	return deletedOrgAppMembership{ID: item.ID, AccountID: item.AccountID, ExternalIDs: item.ExternalIDs,
		AppOrgID: item.AppOrg.ID, Context: item.Context, DateCreated: item.DateCreated}
}

// Account
func accountFromStorage(item tenantAccount, currentAppOrg *string, membershipsAppsOrgs []model.ApplicationOrganization) model.Account {
	id := item.ID
	orgID := item.OrgID
	orgAppsMemberships := orgAppsMembershipsFromStorage(item.OrgAppsMemberships, membershipsAppsOrgs)

	/// Set the Current App Org Membership
	var currentM model.OrgAppMembership
	if currentAppOrg != nil {
		for _, oaMembership := range orgAppsMemberships {
			if oaMembership.AppOrg.ID == *currentAppOrg {
				currentM = oaMembership
				break
			}
		}
	} else {
		currentM = model.OrgAppMembership{}
	}
	cAppOrg := currentM.AppOrg
	cPermissions := currentM.Permissions
	cRoles := currentM.Roles
	cGroups := currentM.Groups
	cPreferences := currentM.Preferences
	cMostRecentClientVersion := currentM.MostRecentClientVersion
	/// End Current App Org Membership

	scopes := item.Scopes
	authTypes := accountAuthTypesFromStorage(item.AuthTypes)
	mfaTypes := mfaTypesFromStorage(item.MFATypes)
	username := item.Username
	externalIDs := item.ExternalIDs
	systemConfigs := item.SystemConfigs
	profile := profileFromStorage(item.Profile)
	privacy := item.Privacy
	devices := accountDevicesFromStorage(item.Devices)
	anonymous := item.Anonymous

	//not used?
	verified := false
	if item.Verified != nil && *item.Verified {
		verified = true
	}

	dateCreated := item.DateCreated
	dateUpdated := item.DateUpdated
	lastLoginDate := item.LastLoginDate
	lastAccessTokenDate := item.LastAccessTokenDate
	return model.Account{ID: id, OrgID: orgID, OrgAppsMemberships: orgAppsMemberships,

		AppOrg:                  cAppOrg,                  //current membership
		Permissions:             cPermissions,             //current membership
		Roles:                   cRoles,                   //current membership
		Groups:                  cGroups,                  //current membership
		Preferences:             cPreferences,             //current membership
		MostRecentClientVersion: cMostRecentClientVersion, //current membership

		Scopes: scopes, AuthTypes: authTypes, MFATypes: mfaTypes, Username: username,
		ExternalIDs: externalIDs, SystemConfigs: systemConfigs, Profile: profile,
		Privacy: privacy, Devices: devices, Anonymous: anonymous, Verified: verified,
		DateCreated: dateCreated, DateUpdated: dateUpdated, LastLoginDate: lastLoginDate,
		LastAccessTokenDate: lastAccessTokenDate}
}

func accountsFromStorage(items []tenantAccount, currentAppOrg *string, membershipsAppsOrgs []model.ApplicationOrganization) []model.Account {
	if len(items) == 0 {
		return make([]model.Account, 0)
	}

	res := make([]model.Account, len(items))
	for i, item := range items {
		res[i] = accountFromStorage(item, currentAppOrg, membershipsAppsOrgs)
	}
	return res
}

func accountToStorage(item *model.Account) *tenantAccount {
	id := item.ID
	orgID := item.OrgID
	orgAppsMemberships := orgAppsMembershipsToStorage(item.OrgAppsMemberships)
	scopes := item.Scopes
	authTypes := accountAuthTypesToStorage(item.AuthTypes)
	mfaTypes := mfaTypesToStorage(item.MFATypes)
	username := item.Username
	externalIDs := item.ExternalIDs
	systemConfigs := item.SystemConfigs
	profile := profileToStorage(item.Profile)
	devices := accountDevicesToStorage(item)
	anonymous := item.Anonymous
	privacy := item.Privacy

	var verified *bool //not used?
	if item.Verified {
		verified = &item.Verified
	}

	dateCreated := item.DateCreated
	dateUpdated := item.DateUpdated
	lastLoginDate := item.LastLoginDate
	lastAccessTokenDate := item.LastAccessTokenDate

	return &tenantAccount{ID: id, OrgID: orgID, OrgAppsMemberships: orgAppsMemberships,
		Scopes: scopes, AuthTypes: authTypes, MFATypes: mfaTypes, Username: username,
		ExternalIDs: externalIDs, SystemConfigs: systemConfigs, Profile: profile, Devices: devices,
		Anonymous: anonymous, Privacy: privacy, Verified: verified, DateCreated: dateCreated,
		DateUpdated: dateUpdated, LastLoginDate: lastLoginDate, LastAccessTokenDate: lastAccessTokenDate}
}

func accountToStorageDeprecated(item *model.Account) *account {
	id := item.ID
	appOrgID := item.AppOrg.ID
	permissions := item.Permissions
	roles := accountRolesToStorage(item.Roles)
	groups := accountGroupsToStorage(item.Groups)
	authTypes := accountAuthTypesToStorage(item.AuthTypes)
	mfaTypes := mfaTypesToStorage(item.MFATypes)
	profile := profileToStorage(item.Profile)
	devices := accountDevicesToStorage(item)
	dateCreated := item.DateCreated
	dateUpdated := item.DateUpdated
	lastLoginDate := item.LastLoginDate
	lastAccessTokenDate := item.LastAccessTokenDate
	mostRecentClientVersion := item.MostRecentClientVersion

	return &account{ID: id, AppOrgID: appOrgID, Anonymous: item.Anonymous, Permissions: permissions, Roles: roles, Groups: groups, Scopes: item.Scopes, AuthTypes: authTypes, MFATypes: mfaTypes,
		Privacy: item.Privacy, Verified: item.Verified, Username: item.Username, ExternalIDs: item.ExternalIDs, Preferences: item.Preferences, Profile: profile, SystemConfigs: item.SystemConfigs, Devices: devices,
		DateCreated: dateCreated, DateUpdated: dateUpdated, LastLoginDate: lastLoginDate, LastAccessTokenDate: lastAccessTokenDate, MostRecentClientVersion: mostRecentClientVersion}
}

func accountDevicesFromStorage(accDevices []userDevice) []model.Device {
	devices := make([]model.Device, len(accDevices))

	for i, device := range accDevices {
		devices[i] = accountDeviceFromStorage(device)
	}
	return devices
}

func accountDeviceFromStorage(item userDevice) model.Device {
	return model.Device{ID: item.ID, DeviceID: item.DeviceID, Type: item.Type, OS: item.OS,
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
	return userDevice{ID: item.ID, DeviceID: item.DeviceID, Type: item.Type, OS: item.OS,
		DateCreated: item.DateCreated, DateUpdated: item.DateUpdated}
}

// AccountAuthType
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
	return model.AccountAuthType{ID: id, AuthType: authType, Identifier: identifier, Params: params, Credential: credential,
		Active: active, Unverified: item.Unverified, Linked: item.Linked, DateCreated: item.DateCreated, DateUpdated: item.DateUpdated}
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
		Params: item.Params, CredentialID: credentialID, Active: item.Active, Unverified: item.Unverified, Linked: item.Linked, DateCreated: item.DateCreated, DateUpdated: item.DateUpdated}
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

// AccountRole
func accountRoleFromStorage(item *accountRole, appOrg model.ApplicationOrganization) model.AccountRole {
	if item == nil {
		return model.AccountRole{}
	}

	appOrgRole := appOrgRoleFromStorage(&item.Role, appOrg)
	return model.AccountRole{Role: appOrgRole, Active: item.Active, AdminSet: item.AdminSet}
}

func accountRolesFromStorage(items []accountRole, application model.ApplicationOrganization) []model.AccountRole {
	if len(items) == 0 {
		return make([]model.AccountRole, 0)
	}

	res := make([]model.AccountRole, len(items))
	for i, item := range items {
		res[i] = accountRoleFromStorage(&item, application)
	}
	return res
}

func accountRoleToStorage(item model.AccountRole) accountRole {
	appRole := appOrgRoleToStorage(item.Role)
	return accountRole{Role: appRole, Active: item.Active, AdminSet: item.AdminSet}
}

func accountRolesToStorage(items []model.AccountRole) []accountRole {
	if len(items) == 0 {
		return make([]accountRole, 0)
	}

	res := make([]accountRole, len(items))
	for i, item := range items {
		res[i] = accountRoleToStorage(item)
	}
	return res
}

// ApplicationGroup
func accountGroupFromStorage(item *accountGroup, appOrg model.ApplicationOrganization) model.AccountGroup {
	if item == nil {
		return model.AccountGroup{}
	}

	appOrgGroup := appOrgGroupFromStorage(&item.Group, appOrg)
	return model.AccountGroup{Group: appOrgGroup, Active: item.Active, AdminSet: item.AdminSet}
}

func accountGroupsFromStorage(items []accountGroup, appOrg model.ApplicationOrganization) []model.AccountGroup {
	if len(items) == 0 {
		return make([]model.AccountGroup, 0)
	}

	res := make([]model.AccountGroup, len(items))
	for i, item := range items {
		res[i] = accountGroupFromStorage(&item, appOrg)
	}
	return res
}

func accountGroupToStorage(item model.AccountGroup) accountGroup {
	appGroup := appOrgGroupToStorage(item.Group)
	return accountGroup{Group: appGroup, Active: item.Active, AdminSet: item.AdminSet}
}

func accountGroupsToStorage(items []model.AccountGroup) []accountGroup {
	if len(items) == 0 {
		return make([]accountGroup, 0)
	}

	res := make([]accountGroup, len(items))
	for i, item := range items {
		res[i] = accountGroupToStorage(item)
	}
	return res
}

// Profile
func profileFromStorage(item profile) model.Profile {
	return model.Profile{ID: item.ID, PhotoURL: item.PhotoURL, FirstName: item.FirstName, LastName: item.LastName,
		Email: item.Email, Phone: item.Phone, BirthYear: item.BirthYear, Address: item.Address, ZipCode: item.ZipCode,
		State: item.State, Country: item.Country, DateCreated: item.DateCreated, DateUpdated: item.DateUpdated,
		UnstructuredProperties: item.UnstructuredProperties}
}

func profileToStorage(item model.Profile) profile {
	return profile{ID: item.ID, PhotoURL: item.PhotoURL, FirstName: item.FirstName, LastName: item.LastName,
		Email: item.Email, Phone: item.Phone, BirthYear: item.BirthYear, Address: item.Address, ZipCode: item.ZipCode,
		State: item.State, Country: item.Country, DateCreated: item.DateCreated, DateUpdated: item.DateUpdated,
		UnstructuredProperties: item.UnstructuredProperties}
}

// Device
func deviceToStorage(item *model.Device) *device {
	if item == nil {
		return nil
	}

	return &device{ID: item.ID, DeviceID: item.DeviceID, Type: item.Type, OS: item.OS,
		Account: item.Account.ID, DateCreated: item.DateCreated, DateUpdated: item.DateUpdated}
}

func deviceFromStorage(item device) model.Device {
	return model.Device{ID: item.ID, DeviceID: item.DeviceID, Type: item.Type, OS: item.OS, DateUpdated: item.DateUpdated}
}

// Credential
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

// MFA
func mfaTypesFromStorage(items []mfaType) []model.MFAType {
	res := make([]model.MFAType, len(items))
	for i, mfa := range items {
		res[i] = mfaTypeFromStorage(mfa)
	}
	return res
}

func mfaTypeFromStorage(item mfaType) model.MFAType {
	return model.MFAType{ID: item.ID, Type: item.Type, Verified: item.Verified, Params: item.Params, DateCreated: item.DateCreated,
		DateUpdated: item.DateUpdated}
}

func mfaTypesToStorage(items []model.MFAType) []mfaType {
	res := make([]mfaType, len(items))
	for i, mfa := range items {
		res[i] = mfaTypeToStorage(&mfa)
	}
	return res
}

func mfaTypeToStorage(item *model.MFAType) mfaType {
	//don't store totp qr code
	params := make(map[string]interface{})
	for k, v := range item.Params {
		if k != "qr_code" {
			params[k] = v
		}
	}

	return mfaType{ID: item.ID, Type: item.Type, Verified: item.Verified, Params: params, DateCreated: item.DateCreated,
		DateUpdated: item.DateUpdated}
}
