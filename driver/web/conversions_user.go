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

package web

import (
	"core-building-block/core/model"
	Def "core-building-block/driver/web/docs/gen"
	"core-building-block/utils"
)

// Account
func accountToDef(item model.Account) *Def.Account {
	//profile
	profile := profileToDef(&item.Profile)
	//privacy
	privacy := privacyToDef(&item.Privacy)
	//preferences
	preferences := &item.Preferences
	//secrets
	secrets := &item.Secrets
	//systemConfigs
	systemConfigs := &item.SystemConfigs
	//permissions
	permissions := applicationPermissionsToDef(item.Permissions)
	//roles
	roles := accountRolesToDef(item.GetActiveRoles())
	//groups
	groups := accountGroupsToDef(item.GetActiveGroups())
	//account auth types
	authTypes := accountAuthTypesToDefLegacy(&item)
	//account identifiers
	identifiers := accountIdentifiersToDef(item.Identifiers)
	//account usage information
	lastLoginDate := utils.FormatTime(item.LastLoginDate)
	lastAccessTokenDate := utils.FormatTime(item.LastAccessTokenDate)

	scopes := item.Scopes
	if scopes == nil {
		scopes = []string{}
	}

	//app
	var as []model.Application
	if item.OrgAppsMemberships != nil {
		for _, a := range item.OrgAppsMemberships {
			as = append(as, a.AppOrg.Application)
		}
	}
	apps := partialAppsToDef(as)

	// maintain backwards compatibility
	var username *string
	if usernameIdentifier := item.GetAccountIdentifier("username", ""); usernameIdentifier != nil {
		username = &usernameIdentifier.Identifier
	}
	if emailIdentifier := item.GetAccountIdentifier("email", ""); emailIdentifier != nil {
		profile.Email = &emailIdentifier.Identifier
	}
	if phoneIdentifier := item.GetAccountIdentifier("phone", ""); phoneIdentifier != nil {
		profile.Phone = &phoneIdentifier.Identifier
	}

	return &Def.Account{Id: &item.ID, Apps: &apps, Anonymous: &item.Anonymous, System: &item.AppOrg.Organization.System, Permissions: &permissions, Roles: &roles, Groups: &groups,
		Privacy: privacy, Verified: &item.Verified, Scopes: &scopes, Identifiers: &identifiers, AuthTypes: &authTypes, Profile: profile, Preferences: preferences, Secrets: secrets,
		SystemConfigs: systemConfigs, LastLoginDate: &lastLoginDate, LastAccessTokenDate: &lastAccessTokenDate, MostRecentClientVersion: item.MostRecentClientVersion, Username: username}
}

func accountsToDef(items []model.Account) []Def.Account {
	result := make([]Def.Account, len(items))
	for i, item := range items {
		result[i] = *accountToDef(item)
	}
	return result
}

func partialAccountToDef(item model.Account, params map[string]interface{}) *Def.PartialAccount {
	//permissions
	permissions := applicationPermissionsToDef(item.Permissions)
	//roles
	roles := accountRolesToDef(item.GetActiveRoles())
	//groups
	groups := accountGroupsToDef(item.GetActiveGroups())

	scopes := item.Scopes
	if scopes == nil {
		scopes = []string{}
	}

	//systemConfigs
	systemConfigs := &item.SystemConfigs
	//account identifiers
	identifiers := accountIdentifiersToDef(item.Identifiers)
	//account auth types
	authTypes := accountAuthTypesToDefLegacy(&item)
	for i := 0; i < len(authTypes); i++ {
		authTypes[i].Params = nil
	}
	//dates
	var dateUpdated *string
	dateCreated := utils.FormatTime(&item.DateCreated)
	if item.DateUpdated != nil {
		formatted := utils.FormatTime(item.DateUpdated)
		dateUpdated = &formatted
	}

	//params
	var paramsData *map[string]interface{}
	if params != nil {
		paramsData = &params
	}

	privacy := privacyToDef(&item.Privacy)

	//app
	var as []model.Application
	if item.OrgAppsMemberships != nil {
		for _, a := range item.OrgAppsMemberships {
			as = append(as, a.AppOrg.Application)
		}
	}
	apps := partialAppsToDef(as)

	// maintain backwards compatibility
	var username *string
	if usernameIdentifier := item.GetAccountIdentifier("username", ""); usernameIdentifier != nil {
		username = &usernameIdentifier.Identifier
	}

	return &Def.PartialAccount{Id: &item.ID, Apps: &apps, Anonymous: item.Anonymous, AppId: item.AppOrg.Application.ID, OrgId: item.AppOrg.Organization.ID, FirstName: item.Profile.FirstName,
		LastName: item.Profile.LastName, System: &item.AppOrg.Organization.System, Permissions: permissions, Roles: roles, Groups: groups,
		Privacy: privacy, Verified: &item.Verified, Scopes: &scopes, SystemConfigs: systemConfigs, Identifiers: identifiers, AuthTypes: authTypes,
		DateCreated: &dateCreated, DateUpdated: dateUpdated, Params: paramsData, Username: username}
}

func partialAccountsToDef(items []model.Account, paramsList []map[string]interface{}) []Def.PartialAccount {
	result := make([]Def.PartialAccount, len(items))
	for i, item := range items {
		var params map[string]interface{}
		if len(paramsList) > i {
			params = paramsList[i]
		}
		result[i] = *partialAccountToDef(item, params)
	}
	return result
}

// AccountAuthType
func accountAuthTypeToDef(item model.AccountAuthType) Def.AccountAuthType {
	params := item.Params

	code := item.SupportedAuthType.AuthType.Code
	return Def.AccountAuthType{Id: item.ID, AuthTypeCode: code, Active: &item.Active, Params: &params, Code: &code}
}

func accountAuthTypesToDef(items []model.AccountAuthType) []Def.AccountAuthType {
	result := make([]Def.AccountAuthType, len(items))
	for i, item := range items {
		result[i] = accountAuthTypeToDef(item)
	}
	return result
}

func accountAuthTypesToDefLegacy(account *model.Account) []Def.AccountAuthType {
	if account == nil {
		return nil
	}

	aats := make([]Def.AccountAuthType, 0)
	for _, aat := range account.AuthTypes {
		resAat := accountAuthTypeToDef(aat)
		addedLegacy := false
		for _, id := range account.Identifiers {
			// create the account auth type and set the identifier if the account has an identifier code matching an alias
			code := id.Code
			identifier := id.Identifier
			legacyAat := resAat
			if id.AccountAuthTypeID != nil && *id.AccountAuthTypeID == aat.ID && id.Primary != nil && *id.Primary {
				// only use the primary identifierfor old account auth types
				legacyAat.Identifier = &identifier

				aats = append(aats, legacyAat)
				addedLegacy = true
			} else if id.AccountAuthTypeID == nil && utils.Contains(aat.SupportedAuthType.AuthType.Aliases, id.Code) {
				if code == "phone" {
					code = "twilio_" + code
				}
				legacyAat.Code = &code
				legacyAat.Identifier = &identifier

				aats = append(aats, legacyAat)
				addedLegacy = true
			}
		}

		if !addedLegacy {
			aats = append(aats, resAat)
		}
	}

	return aats
}

// AccountIdentifier
func accountIdentifierToDef(item model.AccountIdentifier) Def.AccountIdentifier {
	return Def.AccountIdentifier{Id: item.ID, Code: item.Code, Identifier: item.Identifier, Linked: item.Linked, Verified: item.Verified,
		Sensitive: item.Sensitive, AccountAuthTypeId: item.AccountAuthTypeID}
}

func accountIdentifiersToDef(items []model.AccountIdentifier) []Def.AccountIdentifier {
	result := make([]Def.AccountIdentifier, len(items))
	for i, item := range items {
		result[i] = accountIdentifierToDef(item)
	}
	return result
}

// AccountRole
func accountRoleToDef(item model.AccountRole) Def.AppOrgRole {
	permissions := applicationPermissionsToDef(item.Role.Permissions)

	scopes := item.Role.Scopes
	if scopes == nil {
		scopes = []string{}
	}

	//dates
	var dateUpdated *string
	dateCreated := utils.FormatTime(&item.Role.DateCreated)
	if item.Role.DateUpdated != nil {
		formatted := utils.FormatTime(item.Role.DateUpdated)
		dateUpdated = &formatted
	}

	return Def.AppOrgRole{Id: &item.Role.ID, Name: item.Role.Name, Description: &item.Role.Description, System: &item.Role.System, DateCreated: &dateCreated, DateUpdated: dateUpdated, Permissions: &permissions, Scopes: &scopes}
}

func accountRolesToDef(items []model.AccountRole) []Def.AppOrgRole {
	result := make([]Def.AppOrgRole, len(items))
	for i, item := range items {
		result[i] = accountRoleToDef(item)
	}
	return result
}

// AccountGroup
func accountGroupToDef(item model.AccountGroup) Def.AppOrgGroup {
	permissions := applicationPermissionsToDef(item.Group.Permissions)
	roles := appOrgRolesToDef(item.Group.Roles)

	//dates
	var dateUpdated *string
	dateCreated := utils.FormatTime(&item.Group.DateCreated)
	if item.Group.DateUpdated != nil {
		formatted := utils.FormatTime(item.Group.DateUpdated)
		dateUpdated = &formatted
	}

	return Def.AppOrgGroup{Id: &item.Group.ID, Name: item.Group.Name, Description: &item.Group.Description, System: &item.Group.System, DateCreated: &dateCreated, DateUpdated: dateUpdated, Permissions: &permissions, Roles: &roles}
}

func accountGroupsToDef(items []model.AccountGroup) []Def.AppOrgGroup {
	result := make([]Def.AppOrgGroup, len(items))
	for i, item := range items {
		result[i] = accountGroupToDef(item)
	}
	return result
}

// Profile
func profileFromDef(item *Def.Profile) model.Profile {
	if item == nil {
		return model.Profile{}
	}

	var photoURL string
	if item.PhotoUrl != nil {
		photoURL = *item.PhotoUrl
	}
	var firstName string
	if item.FirstName != nil {
		firstName = *item.FirstName
	}
	var lastName string
	if item.LastName != nil {
		lastName = *item.LastName
	}
	var birthYear int
	if item.BirthYear != nil {
		birthYear = *item.BirthYear
	}
	var address string
	if item.Address != nil {
		address = *item.Address
	}
	var zipCode string
	if item.ZipCode != nil {
		zipCode = *item.ZipCode
	}
	var state string
	if item.State != nil {
		state = *item.State
	}
	var country string
	if item.Country != nil {
		country = *item.Country
	}

	var unstructuredProperties map[string]interface{}
	if item.UnstructuredProperties != nil {
		unstructuredProperties = *item.UnstructuredProperties
	}

	return model.Profile{PhotoURL: photoURL, FirstName: firstName, LastName: lastName,
		BirthYear: int16(birthYear), Address: address, ZipCode: zipCode,
		State: state, Country: country, UnstructuredProperties: unstructuredProperties}
}

func profileToDef(item *model.Profile) *Def.Profile {
	if item == nil {
		return nil
	}

	itemVal := *item
	birthYear := int(itemVal.BirthYear)
	return &Def.Profile{Id: &itemVal.ID, PhotoUrl: &itemVal.PhotoURL, FirstName: &itemVal.FirstName, LastName: &itemVal.LastName,
		BirthYear: &birthYear, Address: &itemVal.Address, ZipCode: &itemVal.ZipCode, State: &itemVal.State,
		Country: &itemVal.Country, UnstructuredProperties: &itemVal.UnstructuredProperties}
}

func profileFromDefNullable(item *Def.ProfileNullable) model.Profile {
	if item == nil {
		return model.Profile{}
	}

	var photoURL string
	if item.PhotoUrl != nil {
		photoURL = *item.PhotoUrl
	}
	var firstName string
	if item.FirstName != nil {
		firstName = *item.FirstName
	}
	var lastName string
	if item.LastName != nil {
		lastName = *item.LastName
	}
	var birthYear int
	if item.BirthYear != nil {
		birthYear = *item.BirthYear
	}
	var address string
	if item.Address != nil {
		address = *item.Address
	}
	var zipCode string
	if item.ZipCode != nil {
		zipCode = *item.ZipCode
	}
	var state string
	if item.State != nil {
		state = *item.State
	}
	var country string
	if item.Country != nil {
		country = *item.Country
	}

	var unstructuredProperties map[string]interface{}
	if item.UnstructuredProperties != nil {
		unstructuredProperties = *item.UnstructuredProperties
	}

	return model.Profile{PhotoURL: photoURL, FirstName: firstName, LastName: lastName,
		BirthYear: int16(birthYear), Address: address, ZipCode: zipCode,
		State: state, Country: country, UnstructuredProperties: unstructuredProperties}
}

func privacyToDef(item *model.Privacy) *Def.Privacy {
	if item == nil {
		return nil
	}

	return &Def.Privacy{
		Public: &item.Public,
	}
}

func privacyFromDef(item *Def.Privacy) model.Privacy {
	if item == nil {
		return model.Privacy{}
	}

	var public bool
	if item.Public != nil {
		public = *item.Public
	}

	return model.Privacy{Public: public}
}

func privacyFromDefNullable(item *Def.PrivacyNullable) model.Privacy {
	if item == nil {
		return model.Privacy{}
	}

	var public bool
	if item.Public != nil {
		public = *item.Public
	}

	return model.Privacy{Public: public}
}

// MFA
func mfaDataListToDef(items []model.MFAType) []Def.SharedResMfa {
	out := make([]Def.SharedResMfa, len(items))
	for i, item := range items {
		defItem := mfaDataToDef(&item)
		if defItem != nil {
			out[i] = *defItem
		} else {
			out[i] = Def.SharedResMfa{}
		}
	}
	return out
}

func mfaDataToDef(item *model.MFAType) *Def.SharedResMfa {
	if item == nil {
		return nil
	}

	mfaType := item.Type
	verified := item.Verified
	params := item.Params
	delete(params, "expires")
	//TODO: mask identifier

	//email and phone
	delete(params, "code")
	//totp
	delete(params, "secret")
	//recovery
	delete(params, "codes")

	return &Def.SharedResMfa{Type: &mfaType, Verified: &verified, Params: &params}
}

// Device
func deviceFromDef(item *Def.Device) *model.Device {
	if item == nil {
		return nil
	}

	return &model.Device{DeviceID: item.DeviceId, Type: string(item.Type), OS: defString(item.Os)}
}

func deviceToDef(item *model.Device) *Def.Device {
	if item == nil {
		return nil
	}

	return &Def.Device{Id: &item.ID, DeviceId: item.DeviceID, Type: Def.DeviceType(item.Type), Os: &item.OS}
}

func deviceListToDef(items []model.Device) []Def.Device {
	out := make([]Def.Device, len(items))
	for i, item := range items {
		defItem := deviceToDef(&item)
		if defItem != nil {
			out[i] = *defItem
		} else {
			out[i] = Def.Device{}
		}
	}
	return out
}
