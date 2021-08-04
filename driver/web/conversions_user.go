package web

import (
	"core-building-block/core/model"
	Def "core-building-block/driver/web/docs/gen"
)

//User
func userFromDef(item *Def.User) model.User {
	if item == nil {
		return model.User{}
	}

	// account := userAccountFromDef(item.Account)
	// profile := userProfileFromDef(item.Profile)
	//TODO: add permissions
	return model.User{ID: item.Id}

}

func userToDef(item *model.User) *Def.User {
	if item == nil {
		return nil
	}

	account := userAccountToDef(&item.Account)
	profile := userProfileToDef(&item.Profile)
	groups := globalGroupListToDef(item.Groups)
	roles := globalRoleListToDef(item.Roles)
	memberships := organizationMembershipListToDef(item.OrganizationsMemberships)
	devices := deviceListToDef(item.Devices)
	//TODO: handle permissions
	return &Def.User{Id: item.ID, Account: account, Profile: profile, Groups: &groups, Roles: &roles, OrgMemberships: &memberships, Devices: &devices}
}

//UserAccount
func userAccountFromDef(item *Def.UserAccount) *model.UserAccount {
	if item == nil {
		return nil
	}
	return &model.UserAccount{ID: item.Id, Email: defString(item.Email), Phone: defString(item.Phone), Username: defString(item.Username), LoginTypes: []string{}}
}

func userAccountToDef(item *model.UserAccount) *Def.UserAccount {
	if item == nil {
		return nil
	}
	return &Def.UserAccount{Id: item.ID, Email: &item.Email, Phone: &item.Phone, Username: &item.Username}
}

//UserProfile
func userProfileFromDef(item *Def.UserProfile) *model.UserProfile {
	if item == nil {
		return nil
	}
	return &model.UserProfile{ID: item.Id, FirstName: defString(item.FirstName), LastName: defString(item.LastName),
		PhotoURL: defString(item.PhotoUrl), Address: defString(item.Address), Country: defString(item.Country),
		DateOfBirth: defString(item.DateOfBirth), HomeCounty: defString(item.HomeCounty), MiddleName: defString(item.MiddleName),
		State: defString(item.State), WorkCounty: defString(item.WorkCounty), ZipCode: defString(item.ZipCode)}
}

func userProfileToDef(item *model.UserProfile) *Def.UserProfile {
	if item == nil {
		return nil
	}
	return &Def.UserProfile{Id: item.ID, FirstName: &item.FirstName, LastName: &item.LastName, PhotoUrl: &item.PhotoURL,
		Address: &item.Address, Country: &item.Country, DateOfBirth: &item.DateOfBirth, HomeCounty: &item.HomeCounty,
		MiddleName: &item.MiddleName, State: &item.State, WorkCounty: &item.WorkCounty, ZipCode: &item.ZipCode}
}

//OrganizationMembership
func organizationMembershipFromDef(item *Def.OrganizationMembership) *model.OrganizationMembership {
	if item == nil {
		return nil
	}
	user := model.User{ID: defString(item.UserId)}
	org := model.Organization{ID: defString(item.OrgId)}
	//TODO: handle permissions, roles, and groups
	return &model.OrganizationMembership{ID: item.Id, User: user, Organization: org, OrgUserData: defMap(item.OrgUserData)}
}

func organizationMembershipToDef(item *model.OrganizationMembership) *Def.OrganizationMembership {
	if item == nil {
		return nil
	}
	roles := organizationRoleListToDef(item.Roles)
	groups := organizationGroupListToDef(item.Groups)
	//TODO: handle permissions
	return &Def.OrganizationMembership{Id: item.ID, UserId: &item.User.ID, OrgId: &item.Organization.ID, OrgUserData: &item.OrgUserData, Roles: &roles, Groups: &groups}
}

func organizationMembershipListToDef(items []model.OrganizationMembership) []Def.OrganizationMembership {
	if items == nil {
		return nil
	}
	out := make([]Def.OrganizationMembership, len(items))
	for i, item := range items {
		defItem := organizationMembershipToDef(&item)
		if defItem != nil {
			out[i] = *defItem
		} else {
			out[i] = Def.OrganizationMembership{}
		}
	}
	return out
}

//Device
func deviceFromDef(item *Def.Device) *model.Device {
	if item == nil {
		return nil
	}
	return &model.Device{ID: item.Id, Type: string(item.Type), OS: defString(item.Os), MacAddress: defString(item.MacAddress)}
}

func deviceToDef(item *model.Device) *Def.Device {
	if item == nil {
		return nil
	}
	return &Def.Device{Id: item.ID, Type: Def.DeviceType(item.Type), Os: &item.OS, MacAddress: &item.MacAddress}
}

func deviceListToDef(items []model.Device) []Def.Device {
	if items == nil {
		return nil
	}
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
