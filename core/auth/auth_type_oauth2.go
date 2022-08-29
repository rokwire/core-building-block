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
	"core-building-block/driven/oauthprovider"
	"core-building-block/utils"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/rokwire/logging-library-go/errors"
	"github.com/rokwire/logging-library-go/logutils"
	"gopkg.in/go-playground/validator.v9"
)

const (
	//AuthTypeOAuth2 oauth2 auth type
	AuthTypeOAuth2 string = "oauth2"

	typeOAuth2LoginParams logutils.MessageDataType = "oauth2 login params"
)

type oauth2AuthConfig struct {
	Host         string `json:"host" validate:"required"`
	RedirectURI  string `json:"redirect_uri" validate:"required"`
	AuthorizeURL string `json:"authorize_url"`
	TokenURL     string `json:"token_url"`
	UserInfoURL  string `json:"userinfo_url"`
	Scopes       string `json:"scopes"`
	AllowSignUp  bool   `json:"allow_signup"`
	UseState     bool   `json:"use_state"`
	UseRefresh   bool   `json:"use_refresh"`
	ClientID     string `json:"client_id" validate:"required"`
	ClientSecret string `json:"client_secret" validate:"required"`
}

func (o *oauth2AuthConfig) EmptyToken() oauthprovider.OAuthToken {
	var token oauth2Token
	return &token
}

func (o *oauth2AuthConfig) GetAuthorizeURL() string {
	url := o.Host + "/login/oauth/authorize"
	if len(o.AuthorizeURL) > 0 {
		url = o.AuthorizeURL
	}

	return url
}

func (o *oauth2AuthConfig) GetTokenURL() string {
	tokenURL := o.Host + "/login/oauth/access_token"
	if len(o.TokenURL) > 0 {
		tokenURL = o.TokenURL
	}

	url := ""
	if strings.Contains(tokenURL, "{client_id}") {
		url = strings.ReplaceAll(tokenURL, "{client_id}", o.ClientID)
		url = strings.ReplaceAll(url, "{client_secret}", o.ClientSecret)
	} else {
		url = tokenURL
	}

	return url
}

func (o *oauth2AuthConfig) GetUserInfoURL() string {
	url := o.Host + "/login/oauth/user"
	if len(o.UserInfoURL) > 0 {
		url = o.UserInfoURL
	}

	return url
}

func (o *oauth2AuthConfig) GetAuthorizationCode(creds string, params string) (string, error) {
	var loginParams oauth2LoginParams
	if o.UseState {
		err := json.Unmarshal([]byte(params), &loginParams)
		if err != nil {
			return "", errors.WrapErrorAction(logutils.ActionUnmarshal, typeOAuth2LoginParams, nil, err)
		}
		validate := validator.New()
		err = validate.Struct(loginParams)
		if err != nil {
			return "", errors.WrapErrorAction(logutils.ActionValidate, typeOAuth2LoginParams, nil, err)
		}
	}

	parsedCreds, err := utils.QueryValuesFromURL(creds)
	if err != nil {
		return "", errors.WrapErrorAction(logutils.ActionParse, "oauth2 creds", nil, err)
	}
	//state in creds must match state generated for login url (if used)
	if o.UseState && loginParams.State != parsedCreds.Get("state") {
		return "", errors.ErrorData(logutils.StatusInvalid, "oauth2 login", &logutils.FieldArgs{"state": parsedCreds.Get("state")})
	}

	return parsedCreds.Get("code"), nil
}

func (o *oauth2AuthConfig) BuildNewTokenRequest(creds string, params string, refresh bool) (*http.Request, error) {
	if refresh && !o.UseRefresh {
		return nil, nil
	}

	body := map[string]string{
		"client_id":    o.ClientID,
		"redirect_uri": o.RedirectURI,
	}
	if o.ClientSecret != "" {
		body["client_secret"] = o.ClientSecret
	}
	if refresh {
		body["refresh_token"] = creds
		body["grant_type"] = "refresh_token"
	} else {
		body["code"] = creds
	}

	encoded := utils.EncodeQueryValues(body)
	headers := map[string]string{
		"Accept":         "application/json",
		"Content-Type":   "application/x-www-form-urlencoded",
		"Content-Length": strconv.Itoa(len(body)),
	}

	req, err := http.NewRequest(http.MethodPost, o.GetTokenURL(), strings.NewReader(encoded))
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionCreate, logutils.TypeRequest, nil, err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	return req, nil
}

func (o *oauth2AuthConfig) CheckIDToken(token oauthprovider.OAuthToken) (string, error) {
	return "", nil
}

func (o *oauth2AuthConfig) CheckSubject(tokenSubject string, userSubject string) bool {
	return true
}

func (o *oauth2AuthConfig) BuildLoginURLResponse() (string, map[string]interface{}, error) {
	query := map[string]string{
		"client_id":    o.ClientID,
		"redirect_uri": o.RedirectURI,
		"scope":        o.Scopes,
		"allow_signup": strconv.FormatBool(o.AllowSignUp),
	}

	responseParams := make(map[string]interface{})
	if o.UseState {
		state, err := o.generateState()
		if err != nil {
			return "", nil, errors.WrapErrorAction("generating", "random state", nil, err)
		}
		query["state"] = state
		responseParams["state"] = state
	}

	return o.GetAuthorizeURL() + "?" + utils.EncodeQueryValues(query), responseParams, nil
}

// --- Helper functions ---

// generateState generates and returns a randomized state string
func (o *oauth2AuthConfig) generateState() (string, error) {
	state, err := utils.GenerateRandomString(50)
	if err != nil {
		return "", errors.WrapErrorAction("generating", "state string", nil, err)
	}

	return state, nil
}

type oauth2Token struct {
	AccessToken  string `json:"access_token" validate:"required"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type" validate:"required"`
	Scope        string `json:"scope" validate:"required"`
}

func (t *oauth2Token) GetAuthorizationHeader() string {
	return fmt.Sprintf("%s %s", t.TokenType, t.AccessToken)
}

func (t *oauth2Token) GetResponse() map[string]interface{} {
	tokenParams := map[string]interface{}{
		"access_token":  t.AccessToken,
		"refresh_token": t.RefreshToken,
		"token_type":    t.TokenType,
		"scope":         t.Scope,
	}

	params := map[string]interface{}{"oauth2_token": tokenParams}
	return params
}

func (t *oauth2Token) GetIDToken() string {
	return ""
}

type oauth2LoginParams struct {
	State string `json:"state"`
}

// initOAuth2Auth initializes and registers a new OAuth auth instance for OAuth2
func initOAuth2Auth(auth *Auth) (*oauthAuthImpl, error) {
	oauth2 := &oauthAuthImpl{auth: auth, authType: AuthTypeOAuth2}

	err := auth.registerExternalAuthType(AuthTypeOAuth2, oauth2)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionRegister, typeAuthType, logutils.StringArgs(AuthTypeOAuth2), err)
	}

	return oauth2, nil
}
