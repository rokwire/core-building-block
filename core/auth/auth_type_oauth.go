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

package auth

import (
	"core-building-block/core/model"
	"core-building-block/driven/oauthprovider"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/rokwire/logging-library-go/errors"
	"github.com/rokwire/logging-library-go/logs"
	"github.com/rokwire/logging-library-go/logutils"
	"gopkg.in/go-playground/validator.v9"
)

const (
	typeAuthConfig    logutils.MessageDataType = "auth config"
	typeRefreshParams logutils.MessageDataType = "refresh params"
	methodPost        string                   = "POST"
)

// OAuth implementation of authType
type oauthAuthImpl struct {
	auth     *Auth
	authType string
}

type oauthRefreshParams struct {
	RefreshToken string `json:"refresh_token" bson:"refresh_token" validate:"required"`
}

func (a *oauthAuthImpl) externalLogin(authType model.AuthType, appType model.ApplicationType, appOrg model.ApplicationOrganization, creds string, params string, l *logs.Log) (*model.ExternalSystemUser, map[string]interface{}, error) {
	config, err := a.getOAuthConfig(authType, appType)
	if err != nil {
		return nil, nil, errors.WrapErrorAction(logutils.ActionGet, typeAuthConfig, logutils.StringArgs(a.authType), err)
	}

	code, err := config.GetAuthorizationCode(creds, params)
	if err != nil {
		return nil, nil, errors.WrapErrorAction(logutils.ActionGet, "authorization code", logutils.StringArgs(a.authType), err)
	}

	return a.loadTokensAndInfo(config, authType, appOrg, code, params, false, l)
}

func (a *oauthAuthImpl) refresh(params map[string]interface{}, authType model.AuthType, appType model.ApplicationType, appOrg model.ApplicationOrganization, l *logs.Log) (*model.ExternalSystemUser, map[string]interface{}, error) {
	config, err := a.getOAuthConfig(authType, appType)
	if err != nil {
		return nil, nil, errors.WrapErrorAction(logutils.ActionGet, typeAuthConfig, logutils.StringArgs(a.authType), err)
	}

	refreshParams, err := a.refreshParamsFromMap(params)
	if err != nil {
		return nil, nil, errors.WrapErrorAction(logutils.ActionParse, typeAuthRefreshParams, logutils.StringArgs(a.authType), err)
	}

	paramsString, err := json.Marshal(params)
	if err != nil {
		return nil, nil, errors.WrapErrorAction(logutils.ActionMarshal, typeAuthRefreshParams, nil, err)
	}

	return a.loadTokensAndInfo(config, authType, appOrg, refreshParams.RefreshToken, string(paramsString), true, l)
}

func (a *oauthAuthImpl) getLoginURL(authType model.AuthType, appType model.ApplicationType, l *logs.Log) (string, map[string]interface{}, error) {
	config, err := a.getOAuthConfig(authType, appType)
	if err != nil {
		return "", nil, errors.WrapErrorAction(logutils.ActionGet, typeAuthConfig, logutils.StringArgs(a.authType), err)
	}

	return config.BuildLoginURLResponse()
}

// --- Helper functions ---

func (a *oauthAuthImpl) loadTokensAndInfo(config oauthprovider.OAuthConfig, authType model.AuthType, appOrg model.ApplicationOrganization, creds string, params string,
	refresh bool, l *logs.Log) (*model.ExternalSystemUser, map[string]interface{}, error) {
	newToken, responseParams, err := a.auth.oauthProvider.LoadToken(config, creds, params, refresh)
	if err != nil {
		return nil, nil, errors.WrapErrorAction(logutils.ActionGet, logutils.TypeToken, nil, err)
	}
	if refresh && strings.TrimSpace(newToken.GetAuthorizationHeader()) == "" {
		l.Warnf("%s refresh tokens not enabled for app_id=%s, org_id=%s", a.authType, appOrg.Organization.ID, appOrg.Application.ID)
		return nil, nil, nil
	}

	sub, err := config.CheckIDToken(newToken)
	if err != nil {
		return nil, nil, errors.WrapErrorAction(logutils.ActionValidate, logutils.TypeToken, nil, err)
	}

	userInfo, err := a.auth.oauthProvider.LoadUserInfo(config, newToken)
	if err != nil {
		return nil, nil, errors.WrapErrorAction(logutils.ActionGet, "user info", nil, err)
	}

	var userClaims map[string]interface{}
	err = json.Unmarshal(userInfo, &userClaims)
	if err != nil {
		return nil, nil, errors.WrapErrorAction(logutils.ActionUnmarshal, "user info", nil, err)
	}

	userClaimsSub, _ := userClaims["sub"].(string)
	if !config.CheckSubject(sub, userClaimsSub) {
		return nil, nil, errors.ErrorData(logutils.StatusInvalid, "subject claim", &logutils.FieldArgs{"id_token": sub, "user_claims": userClaimsSub})
	}

	externalUser, err := a.getExternalUser(userClaims, authType, appOrg, l)
	if err != nil {
		return nil, nil, errors.WrapErrorAction(logutils.ActionGet, model.TypeExternalSystemUser, nil, err)
	}

	return externalUser, responseParams, nil
}

func (a *oauthAuthImpl) getExternalUser(claims map[string]interface{}, authType model.AuthType, appOrg model.ApplicationOrganization, l *logs.Log) (*model.ExternalSystemUser, error) {
	identityProviderID, _ := authType.Params["identity_provider"].(string)
	identityProviderSetting := appOrg.FindIdentityProviderSetting(identityProviderID)
	if identityProviderSetting == nil {
		return nil, errors.ErrorData(logutils.StatusMissing, model.TypeIdentityProviderConfig, &logutils.FieldArgs{"app_org": appOrg.ID, "identity_provider_id": identityProviderID})
	}

	//identifier
	identifier, _ := claims[identityProviderSetting.UserIdentifierField].(string)
	//first name
	firstName, _ := claims[identityProviderSetting.FirstNameField].(string)
	//middle name
	middleName, _ := claims[identityProviderSetting.MiddleNameField].(string)
	//last name
	lastName, _ := claims[identityProviderSetting.LastNameField].(string)
	//name
	name, _ := claims[identityProviderSetting.NameField].(string)
	names := strings.Split(name, " ")
	if firstName == "" {
		firstName = names[0]
	}
	if lastName == "" {
		lastName = names[len(names)-1]
	}
	//email
	email, _ := claims[identityProviderSetting.EmailField].(string)
	//roles
	rolesList, _ := claims[identityProviderSetting.RolesField].([]interface{})
	roles := make([]string, len(rolesList))
	for i, item := range rolesList {
		role, _ := item.(string)
		roles[i] = role
	}
	//groups
	groupsList, _ := claims[identityProviderSetting.GroupsField].([]interface{})
	groups := make([]string, len(groupsList))
	for i, item := range groupsList {
		group, _ := item.(string)
		groups[i] = group
	}
	//system specific
	systemSpecific := map[string]interface{}{}
	userSpecificFields := identityProviderSetting.UserSpecificFields
	if len(userSpecificFields) > 0 {
		for _, field := range userSpecificFields {
			fieldValue, _ := claims[field].(string)
			systemSpecific[field] = fieldValue
		}
	}
	//external ids
	externalIDs := make(map[string]string)
	for k, v := range identityProviderSetting.ExternalIDFields {
		externalID, ok := claims[v].(string)
		if !ok {
			l.ErrorWithDetails("failed to parse external id", logutils.Fields{k: claims[v]})
			continue
		}
		externalIDs[k] = externalID
	}

	return &model.ExternalSystemUser{Identifier: identifier, ExternalIDs: externalIDs, FirstName: firstName,
		MiddleName: middleName, LastName: lastName, Email: email, Roles: roles, Groups: groups, SystemSpecific: systemSpecific}, nil
}

func (a *oauthAuthImpl) getOAuthConfig(authType model.AuthType, appType model.ApplicationType) (oauthprovider.OAuthConfig, error) {
	errFields := &logutils.FieldArgs{"auth_type_id": authType.ID, "app_type_id": appType}

	identityProviderID, ok := authType.Params["identity_provider"].(string)
	if !ok {
		return nil, errors.ErrorData(logutils.StatusInvalid, "identity provider", errFields)
	}
	authConfig, err := a.auth.getCachedIdentityProviderConfig(identityProviderID, appType.ID)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeIdentityProviderConfig, errFields, err)
	}

	configBytes, err := json.Marshal(authConfig.Config)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionMarshal, model.TypeIdentityProviderConfig, errFields, err)
	}

	var config oauthprovider.OAuthConfig
	switch a.authType {
	case AuthTypeOidc:
		{
			var oidcConfig oidcAuthConfig
			config = &oidcConfig
		}
	case AuthTypeOAuth2:
		{
			var oauth2Config oauth2AuthConfig
			config = &oauth2Config
		}
	default:
		return nil, errors.ErrorData(logutils.StatusInvalid, model.TypeAuthType, logutils.StringArgs(a.authType))
	}
	err = json.Unmarshal(configBytes, &config)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionUnmarshal, model.TypeIdentityProviderConfig, errFields, err)
	}
	validate := validator.New()
	err = validate.Struct(config)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionValidate, model.TypeIdentityProviderConfig, errFields, err)
	}

	return config, nil
}

func (a *oauthAuthImpl) refreshParamsFromMap(val map[string]interface{}) (*oauthRefreshParams, error) {
	oauthToken, ok := val[fmt.Sprintf("%s_token", a.authType)].(map[string]interface{})
	if !ok {
		return nil, errors.ErrorData(logutils.StatusMissing, logutils.MessageDataType(fmt.Sprintf("%s token", a.authType)), nil)
	}

	refreshToken, ok := oauthToken["refresh_token"].(string)
	if !ok {
		return nil, errors.ErrorData(logutils.StatusMissing, "refresh token", nil)
	}

	return &oauthRefreshParams{RefreshToken: refreshToken}, nil
}
