package web

import (
	"core-building-block/core/model"
	Def "core-building-block/driver/web/docs/gen"
)

//GlobalGroup
func globalGroupFromDef(item *Def.GlobalGroup) *model.GlobalGroup {
	if item == nil {
		return nil
	}
	//TODO: handle permissions and roles
	return &model.GlobalGroup{ID: item.Id, Name: item.Name}
}

func globalGroupToDef(item *model.GlobalGroup) *Def.GlobalGroup {
	if item == nil {
		return nil
	}
	roles := globalRoleListToDef(item.Roles)
	//TODO: handle permissions and users
	return &Def.GlobalGroup{Id: item.ID, Name: item.Name, Roles: &roles}
}

func globalGroupListToDef(items []model.GlobalGroup) []Def.GlobalGroup {
	if items == nil {
		return nil
	}
	out := make([]Def.GlobalGroup, len(items))
	for i, item := range items {
		defItem := globalGroupToDef(&item)
		if defItem != nil {
			out[i] = *defItem
		} else {
			out[i] = Def.GlobalGroup{}
		}
	}
	return out
}

//GlobalRole
func globalRoleFromDef(item *Def.GlobalRole) *model.GlobalRole {
	if item == nil {
		return nil
	}
	//TODO: handle permissions
	return &model.GlobalRole{ID: item.Id, Name: item.Name}
}

func globalRoleToDef(item *model.GlobalRole) *Def.GlobalRole {
	if item == nil {
		return nil
	}
	//TODO: handle permissions
	return &Def.GlobalRole{Id: item.ID, Name: item.Name}
}

func globalRoleListToDef(items []model.GlobalRole) []Def.GlobalRole {
	if items == nil {
		return nil
	}
	out := make([]Def.GlobalRole, len(items))
	for i, item := range items {
		defItem := globalRoleToDef(&item)
		if defItem != nil {
			out[i] = *defItem
		} else {
			out[i] = Def.GlobalRole{}
		}
	}
	return out
}

//GlobalPermissions
func globalPermissionsFromDef(item *Def.GlobalPermissions) *model.GlobalPermission {
	if item == nil {
		return nil
	}
	return &model.GlobalPermission{ID: item.Id, Name: *item.Name}
}

func globalPermissionsToDef(item *model.GlobalPermission) *Def.GlobalPermissions {
	if item == nil {
		return nil
	}
	return &Def.GlobalPermissions{Id: item.ID, Name: &item.Name}
}

func globalPermissionsListToDef(items []model.GlobalPermission) []Def.GlobalPermissions {
	if items == nil {
		return nil
	}
	out := make([]Def.GlobalPermissions, len(items))
	for i, item := range items {
		defItem := globalPermissionsToDef(&item)
		if defItem != nil {
			out[i] = *defItem
		} else {
			out[i] = Def.GlobalPermissions{}
		}
	}
	return out
}
