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

	return &Def.ApplicationFields{Id: item.ID, Name: item.Name, MultiTenant: &item.MultiTenant, RequiresOwnUsers: &item.RequiresOwnUsers}
}

//ApplicationPermission
func applicationPermissionToDef(item model.Permission) Def.ApplicationPermissionFields {
	return Def.ApplicationPermissionFields{Id: item.ID, Name: item.Name}
}

func applicationPermissionsToDef(items []model.Permission) []Def.ApplicationPermissionFields {
	result := make([]Def.ApplicationPermissionFields, len(items))
	for i, item := range items {
		result[i] = applicationPermissionToDef(item)
	}
	return result
}

//AppOrgRole
func appOrgRoleToDef(item model.AppOrgRole) Def.ApplicationRoleFields {
	return Def.ApplicationRoleFields{Id: item.ID, Name: item.Name}
}

func appOrgRolesToDef(items []model.AppOrgRole) []Def.ApplicationRoleFields {
	result := make([]Def.ApplicationRoleFields, len(items))
	for i, item := range items {
		result[i] = appOrgRoleToDef(item)
	}
	return result
}

//AppOrgGroup
func appOrgGroupToDef(item model.AppOrgGroup) Def.ApplicationGroupFields {
	return Def.ApplicationGroupFields{Id: item.ID, Name: item.Name}
}

func appOrgGroupsToDef(items []model.AppOrgGroup) []Def.ApplicationGroupFields {
	result := make([]Def.ApplicationGroupFields, len(items))
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
