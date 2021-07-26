package web

import (
	"core-building-block/core/model"
	Def "core-building-block/driver/web/docs/gen"

	"github.com/rokmetro/auth-library/authservice"
)

func pubKeyFromDef(item *Def.PubKey) *authservice.PubKey {
	if item == nil {
		return nil
	}
	return &authservice.PubKey{KeyPem: item.KeyPem, Alg: item.Alg}
}

func pubKeyToDef(item *authservice.PubKey) *Def.PubKey {
	if item == nil {
		return nil
	}
	return &Def.PubKey{KeyPem: item.KeyPem, Alg: item.Alg}
}

func serviceRegFromDef(item *Def.ServiceReg) *authservice.ServiceReg {
	if item == nil {
		return nil
	}
	pubKey := pubKeyFromDef(item.PubKey)
	return &authservice.ServiceReg{ServiceID: item.ServiceId, Host: item.Host, PubKey: pubKey}
}

func serviceRegToDef(item *authservice.ServiceReg) *Def.ServiceReg {
	if item == nil {
		return nil
	}
	pubKey := pubKeyToDef(item.PubKey)
	return &Def.ServiceReg{ServiceId: item.ServiceID, Host: item.Host, PubKey: pubKey}
}

func serviceRegListToDef(items []authservice.ServiceReg) []Def.ServiceReg {
	if items == nil {
		return nil
	}
	out := make([]Def.ServiceReg, len(items))
	for i, item := range items {
		reg := serviceRegToDef(&item)
		if reg != nil {
			out[i] = *reg
		} else {
			out[i] = Def.ServiceReg{}
		}
	}
	return out
}

func organizationToDef(item *model.Organization) *Def.Organization {
	if item == nil {
		return nil
	}

	orgConfig := Def.OrganizationConfig{Id: &item.Config.ID, Domains: &item.Config.Domains}
	return &Def.Organization{Id: item.ID, Name: item.Name, LoginTypes: &item.LoginTypes,
		RequiresOwnLogin: &item.RequiresOwnLogin, Config: &orgConfig, Type: Def.OrganizationType(item.Type)}
}
