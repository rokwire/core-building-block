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
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/rokwire/logging-library-go/errors"
	"github.com/rokwire/logging-library-go/logs"
	"github.com/rokwire/logging-library-go/logutils"
	"gopkg.in/go-playground/validator.v9"
)

type oauthConfig interface {
	getAuthorizeURL() string
	getTokenURL() string
	getUserInfoURL() string

	getAuthorizationCode(auth *Auth, creds string, params string) (string, error)
	buildNewTokenRequest(auth *Auth, creds string, params string, refresh bool) (*http.Request, error)
	checkIDToken(token oauthToken) (string, error)
	checkSubject(tokenSubject string, userSubject string) bool
	buildLoginURLResponse(auth *Auth) (string, map[string]interface{}, error)
}

type oauthToken interface {
	getAuthorizationHeader() string
	getResponse() map[string]interface{}
	getIDToken() string
}

type oauthRefreshParams struct {
	RefreshToken string `json:"refresh_token" bson:"refresh_token" validate:"required"`
}

func (a *Auth) getOAuthConfig(authType model.AuthType, appType model.ApplicationType) (oauthConfig, error) {
	errFields := &logutils.FieldArgs{"auth_type_id": authType.ID, "app_type_id": appType}

	identityProviderID, ok := authType.Params["identity_provider"].(string)
	if !ok {
		return nil, errors.ErrorData(logutils.StatusInvalid, "identity provider", errFields)
	}
	appTypeID := appType.ID
	authConfig, err := a.getCachedIdentityProviderConfig(identityProviderID, appTypeID)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeIdentityProviderConfig, errFields, err)
	}

	configBytes, err := json.Marshal(authConfig.Config)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionMarshal, model.TypeIdentityProviderConfig, errFields, err)
	}

	var config oauthConfig
	if strings.HasSuffix("_"+authType.Code, "_oidc") {
		var oidcConfig oidcAuthConfig
		config = &oidcConfig
	} else if strings.HasSuffix("_"+authType.Code, "_oauth2") {
		var oauth2Config oauth2AuthConfig
		config = &oauth2Config
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

func (a *Auth) getExternalUser(claims map[string]interface{}, authType model.AuthType, appOrg model.ApplicationOrganization, l *logs.Log) (*model.ExternalSystemUser, error) {
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

func refreshParamsFromMap(val map[string]interface{}, oauthType string) (*oauthRefreshParams, error) {
	oauth2Token, ok := val[fmt.Sprintf("%s_token", oauthType)].(map[string]interface{})
	if !ok {
		return nil, errors.ErrorData(logutils.StatusMissing, logutils.MessageDataType(fmt.Sprintf("%s token", oauthType)), nil)
	}

	refreshToken, ok := oauth2Token["refresh_token"].(string)
	if !ok {
		return nil, errors.ErrorData(logutils.StatusMissing, "refresh token", nil)
	}

	return &oauthRefreshParams{RefreshToken: refreshToken}, nil
}
