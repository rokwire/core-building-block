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
	"net/url"
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

type oauth2LoginParams struct {
	State string `json:"state"`
}

type oauth2Token struct {
	AccessToken string `json:"access_token" validate:"required"`
	Scope       string `json:"scope" validate:"required"`
	TokenType   string `json:"token_type" validate:"required"`
}

type oauth2RefreshParams struct {
	RefreshToken string `json:"refresh_token" bson:"refresh_token" validate:"required"`
}

func oauth2RefreshParamsFromMap(val map[string]interface{}) (*oauth2RefreshParams, error) {
	oauth2Token, ok := val["oauth2_token"].(map[string]interface{})
	if !ok {
		return nil, errors.ErrorData(logutils.StatusMissing, "oauth2 token", nil)
	}

	refreshToken, ok := oauth2Token["refresh_token"].(string)
	if !ok {
		return nil, errors.ErrorData(logutils.StatusMissing, "refresh token", nil)
	}

	return &oauth2RefreshParams{RefreshToken: refreshToken}, nil
}

func (a *oauth2AuthImpl) externalLogin(authType model.AuthType, appType model.ApplicationType, appOrg model.ApplicationOrganization, creds string, params string, l *logs.Log) (*model.ExternalSystemUser, map[string]interface{}, error) {
	oauth2Config, err := a.getOAuth2AuthConfig(authType, appType)
	if err != nil {
		return nil, nil, errors.WrapErrorAction(logutils.ActionGet, typeOAuth2AuthConfig, nil, err)
	}

	var loginParams oauth2LoginParams
	if oauth2Config.UseState {
		err := json.Unmarshal([]byte(params), &loginParams)
		if err != nil {
			return nil, nil, errors.WrapErrorAction(logutils.ActionUnmarshal, typeOAuth2LoginParams, nil, err)
		}
		validate := validator.New()
		err = validate.Struct(loginParams)
		if err != nil {
			return nil, nil, errors.WrapErrorAction(logutils.ActionValidate, typeOAuth2LoginParams, nil, err)
		}
	}

	parsedCreds, err := a.auth.queryValuesFromURL(creds)
	if err != nil {
		return nil, nil, errors.WrapErrorAction(logutils.ActionParse, "oauth2 creds", nil, err)
	}

	//state in creds must match state generated for login url (if used)
	if oauth2Config.UseState && loginParams.State != parsedCreds.Get("state") {
		return nil, nil, errors.ErrorData(logutils.StatusInvalid, "oauth2 login", &logutils.FieldArgs{"state": parsedCreds.Get("state")})
	}

	externalUser, parameters, err := a.newToken(parsedCreds.Get("code"), authType, appType, appOrg, oauth2Config, l)
	if err != nil {
		return nil, nil, err
	}

	return externalUser, parameters, nil
}

func (a *oauth2AuthImpl) refresh(params map[string]interface{}, authType model.AuthType, appType model.ApplicationType, appOrg model.ApplicationOrganization, l *logs.Log) (*model.ExternalSystemUser, map[string]interface{}, error) {
	refreshParams, err := oauth2RefreshParamsFromMap(params)
	if err != nil {
		return nil, nil, errors.WrapErrorAction(logutils.ActionParse, typeAuthRefreshParams, nil, err)
	}

	oauth2Config, err := a.getOAuth2AuthConfig(authType, appType)
	if err != nil {
		return nil, nil, errors.WrapErrorAction(logutils.ActionGet, typeOAuth2AuthConfig, nil, err)
	}

	return a.refreshToken(authType, appType, appOrg, refreshParams, oauth2Config, l)
}

func (a *oauth2AuthImpl) getLoginURL(authType model.AuthType, appType model.ApplicationType, redirectURI string, l *logs.Log) (string, map[string]interface{}, error) {
	oauth2Config, err := a.getOAuth2AuthConfig(authType, appType)
	if err != nil {
		return "", nil, errors.WrapErrorAction(logutils.ActionGet, typeOAuth2AuthConfig, nil, err)
	}

	responseParams := map[string]interface{}{
		"redirect_uri": redirectURI,
	}

	bodyData := map[string]string{
		"client_id":    oauth2Config.ClientID,
		"redirect_uri": redirectURI,
		"scope":        oauth2Config.Scopes,
		"allow_signup": strconv.FormatBool(oauth2Config.AllowSignUp),
	}

	if oauth2Config.UseState {
		state, err := generateState()
		if err != nil {
			return "", nil, errors.WrapErrorAction("generating", "random state", nil, err)
		}
		bodyData["state"] = state
		responseParams["state"] = state
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

func (a *oauth2AuthImpl) newToken(code string, authType model.AuthType, appType model.ApplicationType, appOrg model.ApplicationOrganization, oauth2Config *oauth2AuthConfig, l *logs.Log) (*model.ExternalSystemUser, map[string]interface{}, error) {
	bodyData := map[string]string{
		"client_id": oauth2Config.ClientID,
		"code":      code,
	}

	return a.loadOAuth2TokensAndInfo(bodyData, oauth2Config, authType, appType, appOrg, l)
}

func (a *oauth2AuthImpl) refreshToken(authType model.AuthType, appType model.ApplicationType, appOrg model.ApplicationOrganization,
	params *oauth2RefreshParams, oauth2Config *oauth2AuthConfig, l *logs.Log) (*model.ExternalSystemUser, map[string]interface{}, error) {
	if !oauth2Config.UseRefresh {
		return nil, nil, errors.Newf("oauth2 refresh tokens not enabled for org_id=%s, app_id=%s",
			appOrg.Organization.ID, appOrg.Application.ID)
	}

	bodyData := map[string]string{
		"refresh_token": params.RefreshToken,
		"grant_type":    "refresh_token",
		"client_id":     oauth2Config.ClientID,
	}

	return a.loadOAuth2TokensAndInfo(bodyData, oauth2Config, authType, appType, appOrg, l)
}

func (a *oauth2AuthImpl) loadOAuth2TokensAndInfo(bodyData map[string]string, oauth2Config *oauth2AuthConfig, authType model.AuthType, appType model.ApplicationType,
	appOrg model.ApplicationOrganization, l *logs.Log) (*model.ExternalSystemUser, map[string]interface{}, error) {
	token, err := a.loadOAuth2TokenWithParams(bodyData, oauth2Config)
	if err != nil {
		return nil, nil, errors.WrapErrorAction(logutils.ActionGet, typeOAuth2Token, nil, err)
	}

	userInfoURL := oauth2Config.Host + "/login/oauth/user"
	if len(oauth2Config.UserInfoURL) > 0 {
		userInfoURL = oauth2Config.UserInfoURL
	}
	userInfo, err := a.loadOAuth2UserInfo(token, userInfoURL)
	if err != nil {
		return nil, nil, errors.WrapErrorAction(logutils.ActionGet, "user info", nil, err)
	}

	var userClaims map[string]interface{}
	err = json.Unmarshal(userInfo, &userClaims)
	if err != nil {
		return nil, nil, errors.WrapErrorAction(logutils.ActionUnmarshal, "user info", nil, err)
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
			a.auth.logger.ErrorWithFields("failed to parse external id", logutils.Fields{k: userClaims[v]})
			continue
		}
		externalIDs[k] = externalID
	}

	externalUser := model.ExternalSystemUser{Identifier: identifier, ExternalIDs: externalIDs, FirstName: names[0],
		LastName: names[len(names)-1], Email: email, SystemSpecific: systemSpecific}

	oauth2Params := map[string]interface{}{}
	oauth2Params["access_token"] = token.AccessToken
	oauth2Params["token_type"] = token.TokenType

	params := map[string]interface{}{}
	params["oauth2_token"] = oauth2Params
	return &externalUser, params, nil
}

func (a *oauth2AuthImpl) loadOAuth2TokenWithParams(params map[string]string, oauth2Config *oauth2AuthConfig) (*oauth2Token, error) {
	tokenURI := ""
	oauth2TokenURL := oauth2Config.Host + "/login/oauth/access_token"
	if len(oauth2Config.TokenURL) > 0 {
		oauth2TokenURL = oauth2Config.TokenURL
	}
	if strings.Contains(oauth2TokenURL, "{client_id}") {
		tokenURI = strings.ReplaceAll(oauth2TokenURL, "{client_id}", oauth2Config.ClientID)
		tokenURI = strings.ReplaceAll(tokenURI, "{client_secret}", oauth2Config.ClientSecret)
	} else if len(oauth2Config.ClientSecret) > 0 {
		tokenURI = oauth2TokenURL
		params["client_secret"] = oauth2Config.ClientSecret
	} else {
		tokenURI = oauth2TokenURL
	}

	data := url.Values{}
	for k, v := range params {
		data.Set(k, v)
	}
	headers := map[string]string{
		"Accept":         "application/json",
		"Content-Type":   "application/x-www-form-urlencoded",
		"Content-Length": strconv.Itoa(len(data.Encode())),
	}

	client := &http.Client{}
	req, err := http.NewRequest(http.MethodPost, tokenURI, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionCreate, logutils.TypeRequest, nil, err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
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

func (a *oauth2AuthImpl) loadOAuth2UserInfo(token *oauth2Token, url string) ([]byte, error) {
	if len(token.AccessToken) == 0 {
		return nil, errors.ErrorData(logutils.StatusMissing, "access token", nil)
	}
	if len(token.TokenType) == 0 {
		return nil, errors.ErrorData(logutils.StatusMissing, "token type", nil)
	}
	if len(url) == 0 {
		return nil, errors.ErrorData(logutils.StatusMissing, "user info url", nil)
	}

	client := &http.Client{}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionCreate, logutils.TypeRequest, nil, err)
	}
	req.Header.Set("Authorization", fmt.Sprintf("%s %s", token.TokenType, token.AccessToken))

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
