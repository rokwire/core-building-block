package web

import (
	"core-building-block/core/model"
	Def "core-building-block/driver/web/docs/gen"
)

//Account
func accountToDef(item model.Account) *Def.ResSharedAccount {
	//profile
	profile := profileToDef(&item.Profile)
	//preferences
	preferences := &item.Preferences
	//permissions
	permissions := applicationPermissionsToDef(item.Permissions)
	//roles
	roles := accountRolesToDef(item.GetActiveRoles())
	//groups
	groups := accountGroupsToDef(item.GetActiveGroups())
	//account auth types
	authTypes := accountAuthTypesToDef(item.AuthTypes)
	return &Def.ResSharedAccount{Id: item.ID, Permissions: &permissions, Roles: &roles, Groups: &groups,
		AuthTypes: &authTypes, Profile: profile, Preferences: preferences}
}

//Accounts
func getAccountsToDef(item *model.Account) *Def.ResSharedLoginAccount {
	if item == nil {
		return nil
	}
	profile := profileToDef(&item.Profile)
	//permissions
	permissions := applicationPermissionsToDef(item.Permissions)
	//roles
	roles := appOrgRolesToDef(item.Roles)
	//groups
	groups := appOrgGroupsToDef(item.Groups)
	//account auth types
	authTypes := accountAuthTypesToDef(item.AuthTypes)
	return &Def.ResSharedLoginAccount{Id: item.ID, Permissions: &permissions, Roles: &roles, Groups: &groups, AuthTypes: &authTypes, Profile: profile}

}

func getAccountsListToDef(item []model.Account) []Def.ResSharedLoginAccount {
	out := make([]Def.ResSharedLoginAccount, len(item))
	for i, item := range item {
		defItem := getAccountsToDef(&item)
		if defItem != nil {
			out[i] = *defItem
		} else {
			out[i] = Def.ResSharedLoginAccount{}
		}
	}
	return out
}

//AccountAuthType
func accountAuthTypeToDef(item model.AccountAuthType) Def.AccountAuthTypeFields {
	params := &Def.AccountAuthTypeFields_Params{}
	params.AdditionalProperties = item.Params
	return Def.AccountAuthTypeFields{Id: &item.ID, Code: &item.AuthType.Code, Identifier: &item.Identifier, Active: &item.Active, Active2fa: &item.Active2FA, Params: params}
}

func accountAuthTypesToDef(items []model.AccountAuthType) []Def.AccountAuthTypeFields {
	result := make([]Def.AccountAuthTypeFields, len(items))
	for i, item := range items {
		result[i] = accountAuthTypeToDef(item)
	}
	return result
}

//AccountRole
func accountRoleToDef(item model.AccountRole) Def.AppOrgRoleFields {
	return Def.AppOrgRoleFields{Id: item.Role.ID, Name: item.Role.Name}
}

func accountRolesToDef(items []model.AccountRole) []Def.AppOrgRoleFields {
	result := make([]Def.AppOrgRoleFields, len(items))
	for i, item := range items {
		result[i] = accountRoleToDef(item)
	}
	return result
}

//AccountGroup
func accountGroupToDef(item model.AccountGroup) Def.AppOrgGroupFields {
	return Def.AppOrgGroupFields{Id: item.Group.ID, Name: item.Group.Name}
}

func accountGroupsToDef(items []model.AccountGroup) []Def.AppOrgGroupFields {
	result := make([]Def.AppOrgGroupFields, len(items))
	for i, item := range items {
		result[i] = accountGroupToDef(item)
	}
	return result
}

//Profile
func profileFromDef(item *Def.ReqSharedProfile) model.Profile {
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
	var email string
	if item.Email != nil {
		email = *item.Email
	}
	var phone string
	if item.Phone != nil {
		phone = *item.Phone
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
	return model.Profile{PhotoURL: photoURL, FirstName: firstName, LastName: lastName,
		Email: email, Phone: phone, BirthYear: int16(birthYear), Address: address, ZipCode: zipCode,
		State: state, Country: country}
}

func profileToDef(item *model.Profile) *Def.ProfileFields {
	birthYear := int(item.BirthYear)
	return &Def.ProfileFields{Id: &item.ID, PhotoUrl: &item.PhotoURL, FirstName: &item.FirstName, LastName: &item.LastName,
		Email: &item.Email, Phone: &item.Phone, BirthYear: &birthYear, Address: &item.Address, ZipCode: &item.ZipCode,
		State: &item.State, Country: &item.Country}
}

func profileFromDefNullable(item *Def.ReqSharedProfileNullable) model.Profile {
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
	var email string
	if item.Email != nil {
		email = *item.Email
	}
	var phone string
	if item.Phone != nil {
		phone = *item.Phone
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
	return model.Profile{PhotoURL: photoURL, FirstName: firstName, LastName: lastName,
		Email: email, Phone: phone, BirthYear: int16(birthYear), Address: address, ZipCode: zipCode,
		State: state, Country: country}
}

//Device
func deviceFromDef(item *Def.DeviceFields) *model.Device {
	if item == nil {
		return nil
	}
	return &model.Device{ID: item.Id, Type: string(item.Type), OS: defString(item.Os)}
}

func deviceToDef(item *model.Device) *Def.DeviceFields {
	if item == nil {
		return nil
	}

	return &Def.DeviceFields{Id: item.ID, Type: Def.DeviceFieldsType(item.Type), Os: &item.OS}
}

func deviceListToDef(items []model.Device) []Def.DeviceFields {
	out := make([]Def.DeviceFields, len(items))
	for i, item := range items {
		defItem := deviceToDef(&item)
		if defItem != nil {
			out[i] = *defItem
		} else {
			out[i] = Def.DeviceFields{}
		}
	}
	return out
}
