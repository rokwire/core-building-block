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
	return &model.Profile{ID: *item.Id, FirstName: defString(item.FirstName), LastName: defString(item.LastName), PhotoURL: defString(item.PhotoUrl)}
}

func profileToDef(item *model.Profile) *Def.ProfileFields {
	return &Def.ProfileFields{Id: &item.ID, FirstName: &item.FirstName, LastName: &item.LastName, PhotoUrl: &item.PhotoURL}
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
