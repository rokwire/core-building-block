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
