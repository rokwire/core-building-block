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

	"github.com/rokwire/logging-library-go/errors"
	"github.com/rokwire/logging-library-go/logs"
	"github.com/rokwire/logging-library-go/logutils"
)

const (
	//AuthTypeOAuth2 oauth2 auth type
	AuthTypeOAuth2 string = "oauth2"

	typeOAuth2AuthConfig logutils.MessageDataType = "oauth2 auth config"
	typeOAuth2Token      logutils.MessageDataType = "oauth2 token"
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
	ClientID     string `json:"client_id" validate:"required"`
	ClientSecret string `json:"client_secret"`
}

type oauth2Token struct {
	AccessToken string `json:"access_token" validate:"required"`
	Scope       string `json:"scope" validate:"required"`
	TokenType   string `json:"token_type" validate:"required"`
}

func (a *oauth2AuthImpl) externalLogin(authType model.AuthType, appType model.ApplicationType, appOrg model.ApplicationOrganization, creds string, params string, l *logs.Log) (*model.ExternalSystemUser, map[string]interface{}, error) {
	return nil, nil, errors.New(logutils.Unimplemented)
}

// refresh must be implemented for OIDC auth
func (a *oauth2AuthImpl) refresh(params map[string]interface{}, authType model.AuthType, appType model.ApplicationType, appOrg model.ApplicationOrganization, l *logs.Log) (*model.ExternalSystemUser, map[string]interface{}, error) {
	return nil, nil, errors.New(logutils.Unimplemented)
}

func (a *oauth2AuthImpl) getLoginURL(authType model.AuthType, appType model.ApplicationType, redirectURI string, l *logs.Log) (string, map[string]interface{}, error) {
	return "", nil, errors.New(logutils.Unimplemented)
}

func (a *oauth2AuthImpl) checkToken(idToken string, authType model.AuthType, appType model.ApplicationType, oidcConfig *oidcAuthConfig, l *logs.Log) (string, error) {
	return "", errors.New(logutils.Unimplemented)
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
