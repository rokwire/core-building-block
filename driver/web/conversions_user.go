package web

import (
	"core-building-block/core/model"
	Def "core-building-block/driver/web/docs/gen"
)

//User
func userFromDef(item *Def.Account) model.Account {
	/*	if item == nil {
			return model.Account{}
		}

		// account := userAccountFromDef(item.Account)
		// profile := userProfileFromDef(item.Profile)
		//TODO: add permissions
		return model.Account{ID: *item.Id} */
	return model.Account{}

}

func userToDef(item *model.Account) *Def.Account {
	/*if item == nil {
		return nil
	}

	//TODO
	//account := userAccountToDef(&item.Account)
	profile := userProfileToDef(&item.Profile)
	devices := deviceListToDef(item.Devices)
	//TODO: handle permissions
	return &Def.User{Id: item.ID /*Account: account,*/ /*, Profile: profile, Devices: &devices} */
	return nil
}

//AccountAuthType
func accountAuthTypeToDef(item model.AccountAuthType) Def.AccountAuthTypeFields {
	params := &Def.AccountAuthTypeFields_Params{}
	params.AdditionalProperties = item.Params
	return Def.AccountAuthTypeFields{Id: &item.ID, Identifier: &item.Identifier, Active: &item.Active, Active2fa: &item.Active2FA, Params: params}
}

func accountAuthTypesToDef(items []model.AccountAuthType) []Def.AccountAuthTypeFields {
	result := make([]Def.AccountAuthTypeFields, len(items))
	for i, item := range items {
		result[i] = accountAuthTypeToDef(item)
	}
	return result
}

//Profile
func profileFromDef(item *Def.ProfileFields) *model.Profile {
	if item == nil {
		return &model.Profile{}
	}

	return &model.Profile{ID: *item.Id, PhotoURL: *item.PhotoUrl, FirstName: *item.FirstName, LastName: *item.LastName,
		Email: *item.Email, Phone: *item.Phone, BirthYear: int16(*item.BirthYear), Address: *item.Address, ZipCode: *item.ZipCode,
		State: *item.State, Country: *item.Country}
}

func profileToDef(item *model.Profile) *Def.ProfileFields {
	birthYear := int(item.BirthYear)
	return &Def.ProfileFields{Id: &item.ID, PhotoUrl: &item.PhotoURL, FirstName: &item.FirstName, LastName: &item.LastName,
		Email: &item.Email, Phone: &item.Phone, BirthYear: &birthYear, Address: &item.Address, ZipCode: &item.ZipCode,
		State: &item.State, Country: &item.Country}
}

//Device
func deviceFromDef(item *Def.DeviceFields) *model.Device {
	if item == nil {
		return nil
	}
	return &model.Device{ID: item.Id, Type: string(item.Type), OS: defString(item.Os), MacAddress: defString(item.MacAddress)}
}

func deviceToDef(item *model.Device) *Def.DeviceFields {
	if item == nil {
		return nil
	}

	return &Def.DeviceFields{Id: item.ID, Type: Def.DeviceFieldsType(item.Type), Os: &item.OS, MacAddress: &item.MacAddress}
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
