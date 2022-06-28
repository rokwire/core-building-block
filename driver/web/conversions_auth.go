// Copyright 2022 Board of Trustees of the University of Illinois.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package web

import (
	"core-building-block/core/model"
	Def "core-building-block/driver/web/docs/gen"
	"core-building-block/utils"

	"github.com/rokwire/core-auth-library-go/authorization"
	"github.com/rokwire/core-auth-library-go/authservice"
	"github.com/rokwire/logging-library-go/errors"
	"github.com/rokwire/logging-library-go/logutils"
)

//LoginSession
func loginSessionToDef(item model.LoginSession) Def.SharedResLoginSession {
	var accountAuthTypeID *string
	var accountAuthTypeIdentifier *string
	if item.AccountAuthType != nil {
		accountAuthTypeID = &item.AccountAuthType.ID
		accountAuthTypeIdentifier = &item.AccountAuthType.Identifier
	}

	appTypeID := item.AppType.ID
	appTypeIdentifier := item.AppType.Identifier
	authTypeCode := item.AuthType.Code
	deviceID := item.Device.ID
	refreshTokensCount := len(item.RefreshTokens)
	stateExpires := utils.FormatTime(item.StateExpires)
	dateRefreshed := utils.FormatTime(item.DateRefreshed)
	dateUpdated := utils.FormatTime(item.DateUpdated)
	dateCreated := utils.FormatTime(&item.DateCreated)
	return Def.SharedResLoginSession{Id: &item.ID, Anonymous: &item.Anonymous, AccountAuthTypeId: accountAuthTypeID,
		AccountAuthTypeIdentifier: accountAuthTypeIdentifier, AppTypeId: &appTypeID, AppTypeIdentifier: &appTypeIdentifier,
		AuthTypeCode: &authTypeCode, Identifier: &item.Identifier, IpAddress: &item.IPAddress, DeviceId: &deviceID,
		RefreshTokensCount: &refreshTokensCount, State: &item.State, MfaAttempts: &item.MfaAttempts, StateExpires: &stateExpires,
		DateRefreshed: &dateRefreshed, DateUpdated: &dateUpdated, DateCreated: &dateCreated,
	}
}

func loginSessionsToDef(items []model.LoginSession) []Def.SharedResLoginSession {
	result := make([]Def.SharedResLoginSession, len(items))
	for i, item := range items {
		result[i] = loginSessionToDef(item)
	}
	return result
}

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

func apiKeyFromDef(item Def.APIKey) model.APIKey {
	id := ""
	if item.Id != nil {
		id = *item.Id
	}
	return model.APIKey{ID: id, AppID: item.AppId, Key: item.Key}
}

func apiKeyToDef(item *model.APIKey) *Def.APIKey {
	if item == nil {
		return nil
	}
	return &Def.APIKey{Id: &item.ID, AppId: item.AppID, Key: item.Key}
}

func apiKeyListToDef(items []model.APIKey) []Def.APIKey {
	out := make([]Def.APIKey, len(items))
	for i, item := range items {
		defItem := apiKeyToDef(&item)
		if defItem != nil {
			out[i] = *defItem
		} else {
			out[i] = Def.APIKey{}
		}
	}
	return out
}

func serviceAccountListToDef(items []model.ServiceAccount) []Def.ServiceAccount {
	out := make([]Def.ServiceAccount, len(items))
	for i, item := range items {
		defItem := serviceAccountToDef(&item)
		if defItem != nil {
			out[i] = *defItem
		} else {
			out[i] = Def.ServiceAccount{}
		}
	}
	return out
}

func serviceAccountToDef(item *model.ServiceAccount) *Def.ServiceAccount {
	if item == nil {
		return nil
	}

	accountID := item.AccountID
	name := item.Name
	var appID *string
	if item.Application != nil {
		appID = &item.Application.ID
	}
	var orgID *string
	if item.Organization != nil {
		orgID = &item.Organization.ID
	}
	permissions := make([]string, len(item.Permissions))
	for i, p := range item.Permissions {
		permissions[i] = p.Name
	}
	firstParty := item.FirstParty
	creds := serviceAccountCredentialListToDef(item.Credentials)

	return &Def.ServiceAccount{AccountId: accountID, Name: name, AppId: appID, OrgId: orgID, Permissions: permissions,
		FirstParty: firstParty, Creds: &creds}
}

func serviceAccountCredentialFromDef(item *Def.ServiceAccountCredential) *model.ServiceAccountCredential {
	if item == nil {
		return nil
	}

	var id string
	if item.Id != nil {
		id = *item.Id
	}

	var params map[string]interface{}
	if item.Params != nil {
		params = *item.Params
	}

	return &model.ServiceAccountCredential{ID: id, Name: item.Name, Type: string(item.Type), Params: params}
}

func serviceAccountCredentialListFromDef(items []Def.ServiceAccountCredential) []model.ServiceAccountCredential {
	out := make([]model.ServiceAccountCredential, len(items))
	for i, item := range items {
		defItem := serviceAccountCredentialFromDef(&item)
		if defItem != nil {
			out[i] = *defItem
		} else {
			out[i] = model.ServiceAccountCredential{}
		}
	}
	return out
}

func serviceAccountCredentialToDef(item *model.ServiceAccountCredential) *Def.ServiceAccountCredential {
	if item == nil {
		return nil
	}

	id := item.ID
	params := item.Params
	dateCreated := item.DateCreated.Format("2006-01-02T15:04:05.000Z")

	return &Def.ServiceAccountCredential{Id: &id, Name: item.Name, Type: Def.ServiceAccountCredentialType(item.Type),
		Params: &params, DateCreated: &dateCreated}
}

func serviceAccountCredentialListToDef(items []model.ServiceAccountCredential) []Def.ServiceAccountCredential {
	out := make([]Def.ServiceAccountCredential, len(items))
	for i, item := range items {
		defItem := serviceAccountCredentialToDef(&item)
		if defItem != nil {
			out[i] = *defItem
		} else {
			out[i] = Def.ServiceAccountCredential{}
		}
	}
	return out
}

func appOrgPairToDef(item model.AppOrgPair) Def.AppOrgPair {
	return Def.AppOrgPair{AppId: item.AppID, OrgId: item.OrgID}
}

func appOrgPairListToDef(items []model.AppOrgPair) []Def.AppOrgPair {
	out := make([]Def.AppOrgPair, len(items))
	for i, item := range items {
		out[i] = appOrgPairToDef(item)
	}
	return out
}

func serviceRegFromDef(item *Def.ServiceReg) (*model.ServiceReg, error) {
	if item == nil {
		return nil, nil
	}

	var serviceAccountID string
	if item.ServiceAccountId != nil {
		serviceAccountID = *item.ServiceAccountId
	}
	pubKey := pubKeyFromDef(item.PubKey)
	scopes, err := serviceScopeListFromDef(item.Scopes)
	if err != nil {
		return nil, err
	}
	return &model.ServiceReg{Registration: authservice.ServiceReg{ServiceID: item.ServiceId, ServiceAccountID: serviceAccountID, Host: item.Host, PubKey: pubKey},
		Name: item.Name, Description: item.Description, InfoURL: defString(item.InfoUrl), LogoURL: defString(item.LogoUrl), Scopes: scopes, FirstParty: item.FirstParty, VersionURL: item.VersionUrl}, nil
}

func serviceRegToDef(item *model.ServiceReg) *Def.ServiceReg {
	if item == nil {
		return nil
	}

	var serviceAccountID *string
	if item.Registration.ServiceAccountID != "" {
		serviceAccountID = &item.Registration.ServiceAccountID
	}
	pubKey := pubKeyToDef(item.Registration.PubKey)
	scopes := serviceScopeListToDef(item.Scopes)
	return &Def.ServiceReg{ServiceId: item.Registration.ServiceID, ServiceAccountId: serviceAccountID, Host: item.Registration.Host,
		PubKey: pubKey, Name: item.Name, Description: item.Description, InfoUrl: &item.InfoURL, LogoUrl: &item.LogoURL,
		Scopes: &scopes, FirstParty: item.FirstParty, VersionUrl: item.VersionURL}
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

	var serviceAccountID *string
	if item.ServiceAccountID != "" {
		serviceAccountID = &item.ServiceAccountID
	}
	pubKey := pubKeyToDef(item.PubKey)
	return &Def.AuthServiceReg{ServiceId: item.ServiceID, ServiceAccountId: serviceAccountID, Host: item.Host, PubKey: pubKey}
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

//AuthType
func authTypeToDef(item *model.AuthType) *Def.AuthTypeFields {
	if item == nil {
		return nil
	}

	return &Def.AuthTypeFields{Id: &item.ID, Code: &item.Code, Description: &item.Description,
		IsExternal: &item.IsExternal, IsAnonymous: &item.IsAnonymous, UseCredentials: &item.UseCredentials,
		IgnoreMfa: &item.IgnoreMFA, Params: &Def.AuthTypeFields_Params{AdditionalProperties: item.Params}}
}

func authTypesToDef(items []model.AuthType) []Def.AuthTypeFields {
	result := make([]Def.AuthTypeFields, len(items))
	for i, item := range items {
		result[i] = *authTypeToDef(&item)
	}
	return result
}
