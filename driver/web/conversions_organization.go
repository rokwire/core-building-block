package web

import (
	"core-building-block/core/model"
	Def "core-building-block/driver/web/docs/gen"
)

//Organization
func organizationToDef(item *model.Organization) *Def.Organization {
	if item == nil {
		return nil
	}

	orgConfig := Def.OrganizationConfig{Id: &item.Config.ID, Domains: &item.Config.Domains}
	return &Def.Organization{Id: item.ID, Name: item.Name, LoginTypes: &item.LoginTypes,
		RequiresOwnLogin: &item.RequiresOwnLogin, Config: &orgConfig, Type: Def.OrganizationType(item.Type)}
}

//OrganizationGroup
func organizationGroupFromDef(item *Def.OrganizationGroup) *model.OrganizationGroup {
	if item == nil {
		return nil
	}
	org := model.Organization{ID: item.OrgId}
	//TODO: handle permissions, roles, and memberships
	return &model.OrganizationGroup{ID: item.Id, Name: item.Name, Organization: org}
}

func organizationGroupToDef(item *model.OrganizationGroup) *Def.OrganizationGroup {
	if item == nil {
		return nil
	}
	roles := organizationRoleListToDef(item.Roles)
	//TODO: handle permissions and memberships
	return &Def.OrganizationGroup{Id: item.ID, Name: item.Name, Roles: &roles, OrgId: item.Organization.ID}
}

func organizationGroupListToDef(items []model.OrganizationGroup) []Def.OrganizationGroup {
	if items == nil {
		return nil
	}
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
func organizationRoleFromDef(item *Def.OrganizationRole) *model.OrganizationRole {
	if item == nil {
		return nil
	}
	org := model.Organization{ID: item.OrgId}
	//TODO: handle permissions
	return &model.OrganizationRole{ID: item.Id, Name: item.Name, Organization: org}
}

func organizationRoleToDef(item *model.OrganizationRole) *Def.OrganizationRole {
	if item == nil {
		return nil
	}
	//TODO: handle permissions
	return &Def.OrganizationRole{Id: item.ID, Name: item.Name, OrgId: item.Organization.ID}
}

func organizationRoleListToDef(items []model.OrganizationRole) []Def.OrganizationRole {
	if items == nil {
		return nil
	}
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
