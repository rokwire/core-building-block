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
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

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

func (o *oauth2AuthConfig) getAuthorizeURL() string {
	url := o.Host + "/login/oauth/authorize"
	if len(o.AuthorizeURL) > 0 {
		url = o.AuthorizeURL
	}

	return url
}

func (o *oauth2AuthConfig) getTokenURL() string {
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

func (o *oauth2AuthConfig) getUserInfoURL() string {
	url := o.Host + "/login/oauth/user"
	if len(o.UserInfoURL) > 0 {
		url = o.UserInfoURL
	}

	return url
}

func (o *oauth2AuthConfig) getAuthorizationCode(auth *Auth, creds string, params string) (string, error) {
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

	parsedCreds, err := auth.queryValuesFromURL(creds)
	if err != nil {
		return "", errors.WrapErrorAction(logutils.ActionParse, "oauth2 creds", nil, err)
	}
	//state in creds must match state generated for login url (if used)
	if o.UseState && loginParams.State != parsedCreds.Get("state") {
		return "", errors.ErrorData(logutils.StatusInvalid, "oauth2 login", &logutils.FieldArgs{"state": parsedCreds.Get("state")})
	}

	return parsedCreds.Get("code"), nil
}

func (o *oauth2AuthConfig) buildNewTokenRequest(auth *Auth, token string, refresh bool) (*http.Request, error) {
	body := map[string]string{
		"client_id":    o.ClientID,
		"redirect_uri": o.RedirectURI,
	}
	if o.ClientSecret != "" {
		body["client_secret"] = o.ClientSecret
	}
	if refresh {
		body["refresh_token"] = token
		body["grant_type"] = "refresh_token"
	} else {
		body["code"] = token
	}

	encoded := auth.encodeQueryValues(body)
	headers := map[string]string{
		"Accept":         "application/json",
		"Content-Type":   "application/x-www-form-urlencoded",
		"Content-Length": strconv.Itoa(len(body)),
	}

	req, err := http.NewRequest(http.MethodPost, o.getTokenURL(), strings.NewReader(encoded))
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionCreate, logutils.TypeRequest, nil, err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	return req, nil
}

func (o *oauth2AuthConfig) checkIDToken(token oauthToken) (string, error) {
	return "", nil
}

func (o *oauth2AuthConfig) checkSubject(tokenSubject string, userSubject string) bool {
	return true
}

func (o *oauth2AuthConfig) buildLoginURLResponse(auth *Auth) (string, map[string]interface{}, error) {
	query := map[string]string{
		"client_id":    o.ClientID,
		"redirect_uri": o.RedirectURI,
		"scope":        o.Scopes,
		"allow_signup": strconv.FormatBool(o.AllowSignUp),
	}

	responseParams := make(map[string]interface{})
	if o.UseState {
		state, err := generateState()
		if err != nil {
			return "", nil, errors.WrapErrorAction("generating", "random state", nil, err)
		}
		query["state"] = state
		responseParams["state"] = state
	}

	return o.getAuthorizeURL() + "?" + auth.encodeQueryValues(query), responseParams, nil
}

type oauth2LoginParams struct {
	State string `json:"state"`
}

type oauth2Token struct {
	AccessToken string `json:"access_token" validate:"required"`
	Scope       string `json:"scope" validate:"required"`
	TokenType   string `json:"token_type" validate:"required"`
}

func (t *oauth2Token) getAuthorizationHeader() string {
	return fmt.Sprintf("%s %s", t.TokenType, t.AccessToken)
}

func (t *oauth2Token) getResponse() map[string]interface{} {
	tokenParams := map[string]interface{}{}
	tokenParams["access_token"] = t.AccessToken
	tokenParams["token_type"] = t.TokenType

	params := map[string]interface{}{}
	params["oauth2_token"] = tokenParams
	return params
}

type oauth2RefreshParams struct {
	RefreshToken string `json:"refresh_token" bson:"refresh_token" validate:"required"`
}

func (a *oauth2AuthImpl) externalLogin(authType model.AuthType, appType model.ApplicationType, appOrg model.ApplicationOrganization, creds string, params string, l *logs.Log) (*model.ExternalSystemUser, map[string]interface{}, error) {
	oauth2Config, err := a.getOAuth2AuthConfig(authType, appType)
	if err != nil {
		return nil, nil, errors.WrapErrorAction(logutils.ActionGet, typeOAuth2AuthConfig, nil, err)
	}

	code, err := oauth2Config.getAuthorizationCode(a.auth, creds, params)
	if err != nil {
		return nil, nil, errors.WrapErrorAction(logutils.ActionGet, "authorization code", nil, err)
	}

	externalUser, parameters, err := a.loadOAuth2TokensAndInfo(oauth2Config, authType, appType, appOrg, code, false, l)
	if err != nil {
		return nil, nil, err
	}

	return externalUser, parameters, nil
}

func (a *oauth2AuthImpl) refresh(params map[string]interface{}, authType model.AuthType, appType model.ApplicationType, appOrg model.ApplicationOrganization, l *logs.Log) (*model.ExternalSystemUser, map[string]interface{}, error) {
	oauth2Config, err := a.getOAuth2AuthConfig(authType, appType)
	if err != nil {
		return nil, nil, errors.WrapErrorAction(logutils.ActionGet, typeOAuth2AuthConfig, nil, err)
	}
	if !oauth2Config.UseRefresh {
		return nil, nil, errors.Newf("oauth2 refresh tokens not enabled for org_id=%s, app_id=%s", appOrg.Organization.ID, appOrg.Application.ID)
	}

	refreshParams, err := refreshParamsFromMap(params, AuthTypeOAuth2)
	if err != nil {
		return nil, nil, errors.WrapErrorAction(logutils.ActionParse, typeAuthRefreshParams, nil, err)
	}

	return a.loadOAuth2TokensAndInfo(oauth2Config, authType, appType, appOrg, refreshParams.RefreshToken, true, l)
}

func (a *oauth2AuthImpl) getLoginURL(authType model.AuthType, appType model.ApplicationType, l *logs.Log) (string, map[string]interface{}, error) {
	oauth2Config, err := a.getOAuth2AuthConfig(authType, appType)
	if err != nil {
		return "", nil, errors.WrapErrorAction(logutils.ActionGet, typeOAuth2AuthConfig, nil, err)
	}

	return oauth2Config.buildLoginURLResponse(a.auth)
}

func (a *oauth2AuthImpl) loadOAuth2TokensAndInfo(oauth2Config *oauth2AuthConfig, authType model.AuthType, appType model.ApplicationType,
	appOrg model.ApplicationOrganization, token string, refresh bool, l *logs.Log) (*model.ExternalSystemUser, map[string]interface{}, error) {
	newToken, err := a.loadOAuth2TokenWithParams(oauth2Config, token, refresh)
	if err != nil {
		return nil, nil, errors.WrapErrorAction(logutils.ActionGet, typeOAuth2Token, nil, err)
	}

	sub, err := oauth2Config.checkIDToken(newToken)
	if err != nil {
		return nil, nil, errors.WrapErrorAction(logutils.ActionValidate, typeOidcToken, nil, err)
	}

	userInfo, err := a.loadOAuth2UserInfo(oauth2Config, newToken)
	if err != nil {
		return nil, nil, errors.WrapErrorAction(logutils.ActionGet, "user info", nil, err)
	}

	var userClaims map[string]interface{}
	err = json.Unmarshal(userInfo, &userClaims)
	if err != nil {
		return nil, nil, errors.WrapErrorAction(logutils.ActionUnmarshal, "user info", nil, err)
	}

	userClaimsSub, _ := userClaims["sub"].(string)
	if !oauth2Config.checkSubject(sub, userClaimsSub) {
		return nil, nil, errors.Newf("mismatching user info sub %s and id token sub %s", userClaimsSub, sub)
	}

	identityProviderID, _ := authType.Params["identity_provider"].(string)
	identityProviderSetting := appOrg.FindIdentityProviderSetting(identityProviderID)
	if identityProviderSetting == nil {
		return nil, nil, errors.ErrorData(logutils.StatusMissing, model.TypeIdentityProviderConfig, &logutils.FieldArgs{"app_org": appOrg.ID, "identity_provider_id": identityProviderID})
	}

	//identifier
	identifier, _ := userClaims[identityProviderSetting.UserIdentifierField].(string)
	//name
	name, _ := userClaims[identityProviderSetting.NameField].(string)
	names := strings.Split(name, " ")
	//email
	email, _ := userClaims[identityProviderSetting.EmailField].(string)
	//system specific
	systemSpecific := map[string]interface{}{}
	userSpecificFields := identityProviderSetting.UserSpecificFields
	if len(userSpecificFields) > 0 {
		for _, field := range userSpecificFields {
			fieldValue, _ := userClaims[field].(string)
			systemSpecific[field] = fieldValue
		}
	}
	//external ids
	externalIDs := make(map[string]string)
	for k, v := range identityProviderSetting.ExternalIDFields {
		externalID, ok := userClaims[v].(string)
		if !ok {
			l.ErrorWithDetails("failed to parse external id", logutils.Fields{k: userClaims[v]})
			continue
		}
		externalIDs[k] = externalID
	}

	externalUser := model.ExternalSystemUser{Identifier: identifier, ExternalIDs: externalIDs, FirstName: names[0],
		LastName: names[len(names)-1], Email: email, SystemSpecific: systemSpecific}

	return &externalUser, newToken.getResponse(), nil
}

func (a *oauth2AuthImpl) loadOAuth2TokenWithParams(oauth2Config *oauth2AuthConfig, token string, refresh bool) (*oauth2Token, error) {
	req, err := oauth2Config.buildNewTokenRequest(a.auth, token, refresh)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionCreate, "oauth2 token request", nil, err)
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionSend, logutils.TypeRequest, nil, err)
	}

	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionRead, logutils.TypeRequestBody, nil, err)
	}
	if resp.StatusCode != 200 {
		return nil, errors.ErrorData(logutils.StatusInvalid, logutils.TypeResponse, &logutils.FieldArgs{"status_code": resp.StatusCode, "error": string(body)})
	}

	var authToken oauth2Token
	err = json.Unmarshal(body, &authToken)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionUnmarshal, logutils.TypeToken, nil, err)
	}
	validate := validator.New()
	err = validate.Struct(authToken)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionValidate, logutils.TypeToken, nil, err)
	}

	return &authToken, nil
}

func (a *oauth2AuthImpl) loadOAuth2UserInfo(oauth2Config *oauth2AuthConfig, token *oauth2Token) ([]byte, error) {
	client := &http.Client{}
	req, err := http.NewRequest(http.MethodGet, oauth2Config.getUserInfoURL(), nil)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionCreate, logutils.TypeRequest, nil, err)
	}
	req.Header.Set("Authorization", token.getAuthorizationHeader())

	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionSend, logutils.TypeRequest, nil, err)
	}

	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionRead, logutils.TypeResponse, nil, err)
	}
	if resp.StatusCode != 200 {
		return nil, errors.ErrorData(logutils.StatusInvalid, logutils.TypeResponse, &logutils.FieldArgs{"status_code": resp.StatusCode, "error": string(body)})
	}
	if len(body) == 0 {
		return nil, errors.ErrorData(logutils.StatusMissing, logutils.TypeResponseBody, nil)
	}

	return body, nil
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
