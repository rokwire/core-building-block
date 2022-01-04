package web

import (
	"core-building-block/core/model"
	Def "core-building-block/driver/web/docs/gen"
)

//Application
func applicationToDef(item *model.Application) *Def.ApplicationFields {
	if item == nil {
		return nil
	}

	return &Def.ApplicationFields{Id: item.ID, Name: item.Name, MultiTenant: &item.MultiTenant,
		RequiresOwnUsers: &item.RequiresOwnUsers, MaxLoginSessionDuration: item.MaxLoginSessionDuration}
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
	return Def.AppOrgRoleFields{Id: item.ID, Name: item.Name}
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
	return Def.AppOrgGroupFields{Id: item.ID, Name: item.Name}
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
