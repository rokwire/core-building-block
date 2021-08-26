package web

import (
	"core-building-block/core/model"
	Def "core-building-block/driver/web/docs/gen"
)

//TODO revert this when need it
/*

//ApplicationGroup
func applicationGroupFromDef(item *Def.ApplicationGroup) *model.ApplicationGroup {
	if item == nil {
		return nil
	}
	org := model.Organization{ID: item.OrgId}
	//TODO: handle permissions, roles, and memberships
	return &model.OrganizationGroup{ID: item.Id, Name: item.Name, Organization: org}
}

func applicationGroupToDef(item *model.ApplicationGroup) *Def.ApplicationGroup {
	if item == nil {
		return nil
	}
	roles := organizationRoleListToDef(item.Roles)
	//TODO: handle permissions and memberships
	return &Def.OrganizationGroup{Id: item.ID, Name: item.Name, Roles: &roles, OrgId: item.Organization.ID}
}

func applicationGroupListToDef(items []model.ApplicationGroup) []Def.ApplicationGroup {
	out := make([]Def.OrganizationGroup, len(items))
	for i, item := range items {
		defItem := organizationGroupToDef(&item)
		if defItem != nil {
			out[i] = *defItem
		} else {
			out[i] = Def.OrganizationGroup{}
		}
	}
	return out
}

//OrganizationRole
func applicationRoleFromDef(item *Def.ApplicationRole) *model.ApplicationRole {
	if item == nil {
		return nil
	}
	org := model.Organization{ID: item.OrgId}
	//TODO: handle permissions
	return &model.OrganizationRole{ID: item.Id, Name: item.Name, Organization: org}
}

func applicationRoleToDef(item *model.ApplicationRole) *Def.ApplicationRole {
	if item == nil {
		return nil
	}
	//TODO: handle permissions
	return &Def.OrganizationRole{Id: item.ID, Name: item.Name, OrgId: item.Organization.ID}
}

func applicationRoleListToDef(items []model.ApplicationRole) []Def.ApplicationRole {
	out := make([]Def.OrganizationRole, len(items))
	for i, item := range items {
		defItem := organizationRoleToDef(&item)
		if defItem != nil {
			out[i] = *defItem
		} else {
			out[i] = Def.OrganizationRole{}
		}
	}
	return out
}
*/

//Application
func applicationToDef(item *model.Application) *Def.Application {
	if item == nil {
		return nil
	}
	//TODO
	return &Def.Application{Id: item.ID, Name: item.Name, Versions: nil}
}
