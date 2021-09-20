package web

import (
	"core-building-block/core/model"
	Def "core-building-block/driver/web/docs/gen"

	"github.com/rokmetro/auth-library/authorization"
	"github.com/rokmetro/auth-library/authservice"
	"github.com/rokmetro/logging-library/errors"
	"github.com/rokmetro/logging-library/logutils"
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

func serviceRegFromDef(item *Def.ServiceReg) (*model.ServiceReg, error) {
	if item == nil {
		return nil, nil
	}
	pubKey := pubKeyFromDef(item.PubKey)
	scopes, err := serviceScopeListFromDef(item.Scopes)
	if err != nil {
		return nil, err
	}
	return &model.ServiceReg{Registration: authservice.ServiceReg{ServiceID: item.ServiceId, Host: item.Host, PubKey: pubKey}, Name: item.Name,
		Description: item.Description, InfoURL: defString(item.InfoUrl), LogoURL: defString(item.LogoUrl), Scopes: scopes, FirstParty: item.FirstParty}, nil
}

func serviceRegToDef(item *model.ServiceReg) *Def.ServiceReg {
	if item == nil {
		return nil
	}
	pubKey := pubKeyToDef(item.Registration.PubKey)
	scopes := serviceScopeListToDef(item.Scopes)
	return &Def.ServiceReg{ServiceId: item.Registration.ServiceID, Host: item.Registration.Host, PubKey: pubKey, Name: item.Name, Description: item.Description,
		InfoUrl: &item.InfoURL, LogoUrl: &item.LogoURL, Scopes: &scopes, FirstParty: item.FirstParty}
}

func serviceRegListToDef(items []model.ServiceReg) []Def.ServiceReg {
	out := make([]Def.ServiceReg, len(items))
	for i, item := range items {
		defItem := serviceRegToDef(&item)
		if defItem != nil {
			out[i] = *defItem
		} else {
			out[i] = Def.ServiceReg{}
		}
	}
	return out
}

func authServiceRegToDef(item *authservice.ServiceReg) *Def.AuthServiceReg {
	if item == nil {
		return nil
	}
	pubKey := pubKeyToDef(item.PubKey)
	return &Def.AuthServiceReg{ServiceId: item.ServiceID, Host: item.Host, PubKey: pubKey}
}

func authServiceRegListToDef(items []model.ServiceReg) []Def.AuthServiceReg {
	out := make([]Def.AuthServiceReg, len(items))
	for i, item := range items {
		defItem := authServiceRegToDef(&item.Registration)
		if defItem != nil {
			out[i] = *defItem
		} else {
			out[i] = Def.AuthServiceReg{}
		}
	}
	return out
}

func serviceScopeFromDef(item *Def.ServiceScope) (*model.ServiceScope, error) {
	if item == nil {
		return nil, nil
	}

	scope, err := authorization.ScopeFromString(item.Scope)
	if err != nil {
		return nil, err
	}

	return &model.ServiceScope{Scope: scope, Required: item.Required, Explanation: defString(item.Explanation)}, nil
}

func serviceScopeToDef(item *model.ServiceScope) *Def.ServiceScope {
	if item == nil {
		return nil
	}
	return &Def.ServiceScope{Scope: item.Scope.String(), Required: item.Required, Explanation: &item.Explanation}
}

func serviceScopeListFromDef(items *[]Def.ServiceScope) ([]model.ServiceScope, error) {
	if items == nil || *items == nil {
		return nil, nil
	}
	out := make([]model.ServiceScope, len(*items))
	for i, item := range *items {
		defItem, err := serviceScopeFromDef(&item)
		if err != nil {
			return nil, errors.WrapErrorAction(logutils.ActionParse, model.TypeServiceScope, nil, err)
		}
		if defItem != nil {
			out[i] = *defItem
		} else {
			out[i] = model.ServiceScope{}
		}
	}
	return out, nil
}

func serviceScopeListToDef(items []model.ServiceScope) []Def.ServiceScope {
	out := make([]Def.ServiceScope, len(items))
	for i, item := range items {
		defItem := serviceScopeToDef(&item)
		if defItem != nil {
			out[i] = *defItem
		} else {
			out[i] = Def.ServiceScope{}
		}
	}
	return out
}

func scopeListFromDef(items *[]string) ([]authorization.Scope, error) {
	if items == nil || *items == nil {
		return nil, nil
	}
	out := make([]authorization.Scope, len(*items))
	for i, item := range *items {
		defItem, err := authorization.ScopeFromString(item)
		if err != nil {
			return nil, errors.WrapErrorAction(logutils.ActionParse, model.TypeScope, nil, err)
		}
		if defItem != nil {
			out[i] = *defItem
		} else {
			out[i] = authorization.Scope{}
		}
	}
	return out, nil
}

func scopeListToDef(items []authorization.Scope) []string {
	if items == nil {
		return nil
	}
	out := make([]string, len(items))
	for i, item := range items {
		defItem := item.String()
		out[i] = defItem
	}
	return out
}

func jsonWebKeyToDef(item *model.JSONWebKey) *Def.JWK {
	if item == nil {
		return nil
	}
	return &Def.JWK{Alg: Def.JWKAlg(item.Alg), Kid: item.Kid, Kty: Def.JWKKty(item.Kty), Use: Def.JWKUse(item.Use), N: item.N, E: item.E}
}

func jsonWebKeySetDef(items *model.JSONWebKeySet) *Def.JWKS {
	if items == nil || items.Keys == nil {
		return nil
	}
	out := make([]Def.JWK, len(items.Keys))
	for i, item := range items.Keys {
		defItem := jsonWebKeyToDef(&item)
		if defItem != nil {
			out[i] = *defItem
		} else {
			out[i] = Def.JWK{}
		}
	}
	return &Def.JWKS{Keys: out}
}
