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
	"core-building-block/utils"
	"encoding/json"
	"net/url"
	"strconv"

	"github.com/rokwire/logging-library-go/errors"
	"github.com/rokwire/logging-library-go/logs"
	"github.com/rokwire/logging-library-go/logutils"
	"gopkg.in/go-playground/validator.v9"
)

const (
	//AuthTypeOAuth2 oauth2 auth type
	AuthTypeOAuth2 string = "oauth2"

	typeOAuth2AuthConfig    logutils.MessageDataType = "oauth2 auth config"
	typeOAuth2LoginParams   logutils.MessageDataType = "oauth2 login params"
	typeOAuth2RefreshParams logutils.MessageDataType = "oauth2 refresh params"
	typeOAuth2Token         logutils.MessageDataType = "oauth2 token"
)

// OAuth2 implementation of authType
type oauth2AuthImpl struct {
	auth     *Auth
	authType string
}

type oauth2AuthConfig struct {
	Host         string `json:"host" validate:"required"`
	AuthorizeURL string `json:"authorize_url"`
	TokenURL     string `json:"token_url"`
	UserInfoURL  string `json:"userinfo_url"`
	Scopes       string `json:"scopes"`
	AllowSignUp  bool   `json:"allow_signup"`
	UseState     bool   `json:"use_state"`
	ClientID     string `json:"client_id" validate:"required"`
	ClientSecret string `json:"client_secret" validate:"required"`
}

type oauth2Token struct {
	AccessToken string `json:"access_token" validate:"required"`
	Scope       string `json:"scope" validate:"required"`
	TokenType   string `json:"token_type" validate:"required"`
}

type oauth2RefreshParams struct {
	RefreshToken string `json:"refresh_token" bson:"refresh_token" validate:"required"`
}

func (a *oauth2AuthImpl) externalLogin(authType model.AuthType, appType model.ApplicationType, appOrg model.ApplicationOrganization, creds string, params string, l *logs.Log) (*model.ExternalSystemUser, map[string]interface{}, error) {
	return nil, nil, errors.New(logutils.Unimplemented)
}

func (a *oauth2AuthImpl) refresh(params map[string]interface{}, authType model.AuthType, appType model.ApplicationType, appOrg model.ApplicationOrganization, l *logs.Log) (*model.ExternalSystemUser, map[string]interface{}, error) {
	return nil, nil, errors.New(logutils.Unimplemented)
}

func (a *oauth2AuthImpl) getLoginURL(authType model.AuthType, appType model.ApplicationType, redirectURI string, l *logs.Log) (string, map[string]interface{}, error) {
	oauth2Config, err := a.getOAuth2AuthConfig(authType, appType)
	if err != nil {
		return "", nil, errors.WrapErrorAction(logutils.ActionGet, typeOAuth2AuthConfig, nil, err)
	}

	//TODO: necessary?
	responseParams := map[string]interface{}{
		"redirect_uri": redirectURI,
	}

	bodyData := map[string]string{
		"client_id":    oauth2Config.ClientID,
		"redirect_uri": redirectURI,
		"scope":        oauth2Config.Scopes,
		"login":        "", //TODO: propt user with specific account to use (optional)
		"allow_aignup": strconv.FormatBool(oauth2Config.AllowSignUp),
	}

	//TODO: will need to store state variable to make use of this
	if oauth2Config.UseState {
		state, err := generateState()
		if err != nil {
			return "", nil, errors.WrapErrorAction("generating", "random state", nil, err)
		}
		bodyData["state"] = state
	}

	authURL := oauth2Config.Host + "/login/oauth/authorize"
	if len(oauth2Config.AuthorizeURL) > 0 {
		authURL = oauth2Config.AuthorizeURL
	}

	query := url.Values{}
	for k, v := range bodyData {
		query.Set(k, v)
	}
	return authURL + "?" + query.Encode(), responseParams, nil
}

func (a *oauth2AuthImpl) getOAuth2AuthConfig(authType model.AuthType, appType model.ApplicationType) (*oauth2AuthConfig, error) {
	errFields := &logutils.FieldArgs{"auth_type_id": authType.ID, "app_type_id": appType}

	identityProviderID, ok := authType.Params["identity_provider"].(string)
	if !ok {
		return nil, errors.ErrorData(logutils.StatusInvalid, "identity provider", errFields)
	}
	appTypeID := appType.ID
	authConfig, err := a.auth.getCachedIdentityProviderConfig(identityProviderID, appTypeID)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeIdentityProviderConfig, errFields, err)
	}

	configBytes, err := json.Marshal(authConfig.Config)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionMarshal, model.TypeIdentityProviderConfig, errFields, err)
	}

	var oauth2Config oauth2AuthConfig
	err = json.Unmarshal(configBytes, &oauth2Config)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionUnmarshal, model.TypeIdentityProviderConfig, errFields, err)
	}

	validate := validator.New()
	err = validate.Struct(oauth2Config)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionValidate, model.TypeIdentityProviderConfig, errFields, err)
	}

	return &oauth2Config, nil
}

// --- Helper functions ---

// generateState generates and returns a randomized state string
func generateState() (string, error) {
	state, err := utils.GenerateRandomString(50)
	if err != nil {
		return "", errors.WrapErrorAction("generating", "state string", nil, err)
	}

	return state, nil
}

// initOAuth2Auth initializes and registers a new OAuth2 auth instance
func initOAuth2Auth(auth *Auth) (*oauth2AuthImpl, error) {
	oauth2 := &oauth2AuthImpl{auth: auth, authType: AuthTypeOAuth2}

	err := auth.registerExternalAuthType(oauth2.authType, oauth2)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionRegister, typeAuthType, nil, err)
	}

	return oauth2, nil
}
