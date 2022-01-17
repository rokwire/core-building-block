package web

import (
	"core-building-block/core/model"
	Def "core-building-block/driver/web/docs/gen"
)

//Application
func applicationToDef(item *model.Application) *Def.Application {
	if item == nil {
		return nil
	}

	fields := Def.ApplicationFields{Id: item.ID, Name: item.Name, MultiTenant: &item.MultiTenant,
		RequiresOwnUsers: &item.RequiresOwnUsers}
	types := applicationTypeListToDef(item.Types)

	return &Def.Application{Fields: &fields, Types: &types}
}

func applicationTypeListToDef(items []model.ApplicationType) []Def.ApplicationType {
	result := make([]Def.ApplicationType, len(items))
	for i, item := range items {
		result[i] = *applicationTypeToDef(&item)
	}
	return result
}

func applicationTypeToDef(item *model.ApplicationType) *Def.ApplicationType {
	if item == nil {
		return nil
	}

	var name *string
	if len(item.Name) > 0 {
		name = &item.Name
	}
	var versions *[]string
	if len(item.Versions) > 0 {
		versions = &item.Versions
	}

	return &Def.ApplicationType{Fields: &Def.ApplicationTypeFields{Id: item.ID, Identifier: item.Identifier, Name: name, Versions: versions}}
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
func organizationToDef(item *model.Organization) *Def.Organization {
	if item == nil {
		return nil
	}

	fields := Def.OrganizationFields{Id: item.ID, Name: item.Name, Type: Def.OrganizationFieldsType(item.Type)}

	return &Def.Organization{Config: organizationConfigToDef(&item.Config), Fields: &fields}
}

func organizationsToDef(items []model.Organization) []Def.Organization {
	result := make([]Def.Organization, len(items))
	for i, item := range items {
		result[i] = *organizationToDef(&item)
	}
	return result
}

func organizationConfigToDef(item *model.OrganizationConfig) *Def.OrganizationConfig {
	if item == nil {
		return nil
	}

	var id *string
	if len(item.ID) > 0 {
		id = &item.ID
	}
	var domains *[]string
	if len(item.Domains) > 0 {
		domains = &item.Domains
	}

	return &Def.OrganizationConfig{Fields: &Def.OrganizationConfigFields{Id: id, Domains: domains}}
}
