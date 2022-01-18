package web

import (
	"core-building-block/core/model"
	Def "core-building-block/driver/web/docs/gen"
)

//Application
func applicationToDef(item model.Application) Def.ApplicationFields {

	return Def.ApplicationFields{Id: item.ID, Name: item.Name, MultiTenant: &item.MultiTenant,
		RequiresOwnUsers: &item.RequiresOwnUsers}
}

//ApplicationType
func appTypeToDef(item *model.ApplicationType) *Def.ApplicationTypeFields {
	return &Def.ApplicationTypeFields{Identifier: item.Identifier, Name: &item.Name, Versions: &item.Versions}
}

//AuthType
func authTypeToDef(item *model.AuthType) *Def.AuthTypeFields {
	return &Def.AuthTypeFields{Code: &item.Code, Description: &item.Description, IgnoreMfa: &item.IgnoreMFA, IsExternal: &item.IsExternal,
		Params: &Def.AuthTypeFields_Params{AdditionalProperties: map[string]interface{}{}}}
}

//ApplicationOrganization
func appOrgToDef(item *model.ApplicationOrganization) *Def.ApplicationOrganization {

	return &Def.ApplicationOrganization{Organization: &Def.Organization{Config: &Def.OrganizationConfig{Fields: &Def.OrganizationConfigFields{Domains: &item.Organization.Config.Domains}}},
		Application: &Def.Application{Fields: &Def.ApplicationFields{MultiTenant: &item.Application.MultiTenant,
			Name: item.Application.Name, RequiresOwnUsers: &item.Application.RequiresOwnUsers}}}
}

func applicationsToDef(item []model.Application) []Def.ApplicationFields {
	result := make([]Def.ApplicationFields, len(item))
	for i, item := range item {
		result[i] = applicationToDef(item)
	}
	return result
}

//ApplicationPermission
func applicationPermissionToDef(item model.Permission) Def.PermissionFields {
	return Def.PermissionFields{Id: item.ID, Name: item.Name, ServiceId: &item.ServiceID, Assigners: &item.Assigners}
}

func applicationPermissionsToDef(items []model.Permission) []Def.PermissionFields {
	result := make([]Def.PermissionFields, len(items))
	for i, item := range items {
		result[i] = applicationPermissionToDef(item)
	}
	return result
}

//AppOrgRole
func appOrgRoleToDef(item model.AppOrgRole) Def.AppOrgRoleFields {
	return Def.AppOrgRoleFields{Id: item.ID, Name: item.Name, System: &item.System}
}

func appOrgRolesToDef(items []model.AppOrgRole) []Def.AppOrgRoleFields {
	result := make([]Def.AppOrgRoleFields, len(items))
	for i, item := range items {
		result[i] = appOrgRoleToDef(item)
	}
	return result
}

//AppOrgGroup
func appOrgGroupToDef(item model.AppOrgGroup) Def.AppOrgGroupFields {
	return Def.AppOrgGroupFields{Id: item.ID, Name: item.Name, System: &item.System}
}

func appOrgGroupsToDef(items []model.AppOrgGroup) []Def.AppOrgGroupFields {
	result := make([]Def.AppOrgGroupFields, len(items))
	for i, item := range items {
		result[i] = appOrgGroupToDef(item)
	}
	return result
}

//Organization
func organizationToDef(item *model.Organization) *Def.OrganizationFields {
	if item == nil {
		return nil
	}

	return &Def.OrganizationFields{Id: item.ID, Name: item.Name, Type: Def.OrganizationFieldsType(item.Type)}
}

func organizationsToDef(items []model.Organization) []Def.OrganizationFields {
	result := make([]Def.OrganizationFields, len(items))
	for i, item := range items {
		result[i] = *organizationToDef(&item)
	}
	return result
}

func loginSessionFieldsToDef(item model.LoginSession) *Def.LoginSessionFields {
	return &Def.LoginSessionFields{AccessToken: &item.AccessToken, Anonymous: &item.Anonymous, Id: &item.ID, IdAddress: &item.IPAddress,
		Identifier: &item.Identifier}
}

//LoginSession
func loginSessionToDef(item model.LoginSession) *Def.LoginSession {
	//accountAuthType
	accuntAuthType := accountAuthTypeToDef(*item.AccountAuthType)
	//appOrg
	appOrg := appOrgToDef(&item.AppOrg)
	//appType
	appType := appTypeToDef(&item.AppType)
	//authType
	authType := authTypeToDef(&item.AccountAuthType.AuthType)
	//device
	device := deviceToDef(item.Device)

	return &Def.LoginSession{AccountAuthType: &Def.AccountAuthType{Fields: &accuntAuthType}, AppOrg: appOrg, AppType: &Def.ApplicationType{Fields: appType},
		AuthType: &Def.AuthType{Fields: authType}, Device: &Def.Device{Fields: device}, Fields: &Def.LoginSessionFields{AccessToken: &item.AccessToken, Anonymous: &item.Anonymous,
			Id: &item.ID, IdAddress: &item.IPAddress, Identifier: &item.Identifier, Params: &Def.LoginSessionFields_Params{AdditionalProperties: accuntAuthType.Params.AdditionalProperties}}}
}

func loginSessionsToDef(items []model.LoginSession) []Def.LoginSession {
	result := make([]Def.LoginSession, len(items))
	for i, item := range items {
		result[i] = *loginSessionToDef(item)
	}
	return result
}
