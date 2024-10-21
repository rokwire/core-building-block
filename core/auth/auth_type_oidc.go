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
	"context"
	"core-building-block/core/model"
	"core-building-block/utils"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"gopkg.in/go-playground/validator.v9"

	"github.com/coreos/go-oidc"
	"github.com/rokwire/core-auth-library-go/v3/authutils"
	"github.com/rokwire/logging-library-go/v2/errors"
	"github.com/rokwire/logging-library-go/v2/logs"
	"github.com/rokwire/logging-library-go/v2/logutils"
)

const (
	//AuthTypeOidc oidc auth type
	AuthTypeOidc string = "oidc"

	typeOidcAuthConfig    logutils.MessageDataType = "oidc auth config"
	typeOidcCheckParams   logutils.MessageDataType = "oidc check params"
	typeOidcLoginParams   logutils.MessageDataType = "oidc login params"
	typeOidcRefreshParams logutils.MessageDataType = "oidc refresh params"
	typeOidcToken         logutils.MessageDataType = "oidc token"
)

// OIDC implementation of authType
type oidcAuthImpl struct {
	auth     *Auth
	authType string
}

type oidcAuthConfig struct {
	Host               string            `json:"host" validate:"required"`
	AuthorizeURL       string            `json:"authorize_url"`
	TokenURL           string            `json:"token_url"`
	UserInfoURL        string            `json:"userinfo_url"`
	Scopes             string            `json:"scopes"`
	UseRefresh         bool              `json:"use_refresh"`
	UsePKCE            bool              `json:"use_pkce"`
	ClientID           string            `json:"client_id" validate:"required"`
	ClientSecret       string            `json:"client_secret"`
	AuthorizeClaims    string            `json:"authorize_claims"`
	Claims             map[string]string `json:"claims" validate:"required"`
	RequiredPopulation string            `json:"required_population"`
	Populations        map[string]string `json:"populations"`
}

type oidcLoginParams struct {
	CodeVerifier string `json:"pkce_verifier"`
	RedirectURI  string `json:"redirect_uri" validate:"required"`
}

type oidcToken struct {
	IDToken      string `json:"id_token" validate:"required"`
	AccessToken  string `json:"access_token" validate:"required"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type" validate:"required"`
	ExpiresIn    int    `json:"expires_in"`
}

type oidcRefreshParams struct {
	RefreshToken string `json:"refresh_token" bson:"refresh_token" validate:"required"`
	RedirectURI  string `json:"redirect_uri" bson:"redirect_uri" validate:"required"`
}

func oidcRefreshParamsFromMap(val map[string]interface{}) (*oidcRefreshParams, error) {
	oidcToken, ok := val["oidc_token"].(map[string]interface{})
	if !ok {
		return nil, errors.ErrorData(logutils.StatusMissing, "oidc token", nil)
	}

	refreshToken, ok := oidcToken["refresh_token"].(string)
	if !ok {
		return nil, errors.ErrorData(logutils.StatusMissing, "refresh token", nil)
	}
	redirectURI, ok := val["redirect_uri"].(string)
	if !ok {
		return nil, errors.ErrorData(logutils.StatusMissing, "redirect uri", nil)
	}

	return &oidcRefreshParams{RefreshToken: refreshToken, RedirectURI: redirectURI}, nil
}

func (a *oidcAuthImpl) externalLogin(authType model.AuthType, appType model.ApplicationType, appOrg model.ApplicationOrganization, creds string, params string, l *logs.Log) (*model.ExternalSystemUser, map[string]interface{}, string, error) {
	var loginParams oidcLoginParams
	err := json.Unmarshal([]byte(params), &loginParams)
	if err != nil {
		return nil, nil, "", errors.WrapErrorAction(logutils.ActionUnmarshal, typeOidcLoginParams, nil, err)
	}
	validate := validator.New()
	err = validate.Struct(loginParams)
	if err != nil {
		return nil, nil, "", errors.WrapErrorAction(logutils.ActionValidate, typeOidcLoginParams, nil, err)
	}

	oidcConfig, err := a.getOidcAuthConfig(authType, appType)
	if err != nil {
		return nil, nil, "", errors.WrapErrorAction(logutils.ActionGet, typeOidcAuthConfig, nil, err)
	}

	parsedCreds, err := url.Parse(strings.ReplaceAll(creds, `"`, ""))
	if err != nil {
		return nil, nil, "", errors.WrapErrorAction(logutils.ActionParse, "oidc login creds", nil, err)
	}

	externalUser, parameters, accessToken, err := a.newToken(parsedCreds.Query().Get("code"), authType, appType, appOrg, &loginParams, oidcConfig, l)
	if err != nil {
		return nil, nil, "", err
	}

	return externalUser, parameters, accessToken, nil
}

// refresh must be implemented for OIDC auth
func (a *oidcAuthImpl) refresh(params map[string]interface{}, authType model.AuthType, appType model.ApplicationType, appOrg model.ApplicationOrganization, l *logs.Log) (*model.ExternalSystemUser, map[string]interface{}, string, error) {
	refreshParams, err := oidcRefreshParamsFromMap(params)
	if err != nil {
		return nil, nil, "", errors.WrapErrorAction(logutils.ActionParse, typeAuthRefreshParams, nil, err)
	}

	oidcConfig, err := a.getOidcAuthConfig(authType, appType)
	if err != nil {
		return nil, nil, "", errors.WrapErrorAction(logutils.ActionGet, typeOidcAuthConfig, nil, err)
	}

	return a.refreshToken(authType, appType, appOrg, refreshParams, oidcConfig, l)
}

func (a *oidcAuthImpl) getLoginURL(authType model.AuthType, appType model.ApplicationType, redirectURI string, l *logs.Log) (string, map[string]interface{}, error) {
	oidcConfig, err := a.getOidcAuthConfig(authType, appType)
	if err != nil {
		return "", nil, errors.WrapErrorAction(logutils.ActionGet, typeOidcAuthConfig, nil, err)
	}

	responseParams := map[string]interface{}{
		"redirect_uri": redirectURI,
	}

	scopes := oidcConfig.Scopes
	if len(scopes) == 0 {
		scopes = "openid profile email offline_access"
	}

	bodyData := map[string]string{
		"scope":         scopes,
		"response_type": "code",
		"redirect_uri":  redirectURI,
		"client_id":     oidcConfig.ClientID,
	}

	if len(oidcConfig.AuthorizeClaims) > 0 {
		bodyData["claims"] = oidcConfig.AuthorizeClaims
	}

	if oidcConfig.UsePKCE {
		codeChallenge, codeVerifier, err := generatePkceChallenge()
		if err != nil {
			return "", nil, errors.WrapErrorAction(logutils.ActionGenerate, "pkce challenge", nil, err)
		}
		bodyData["code_challenge_method"] = "S256"
		bodyData["code_challenge"] = codeChallenge

		responseParams["pkce_verifier"] = codeVerifier
	}

	authURL := oidcConfig.Host + "/idp/profile/oidc/authorize"
	if len(oidcConfig.AuthorizeURL) > 0 {
		authURL = oidcConfig.AuthorizeURL
	}

	query := url.Values{}
	for k, v := range bodyData {
		query.Set(k, v)
	}
	return authURL + "?" + query.Encode(), responseParams, nil
}

func (a *oidcAuthImpl) checkToken(idToken string, authType model.AuthType, appType model.ApplicationType, oidcConfig *oidcAuthConfig, l *logs.Log) (string, error) {
	var err error
	if oidcConfig == nil {
		oidcConfig, err = a.getOidcAuthConfig(authType, appType)
		if err != nil {
			return "", errors.WrapErrorAction(logutils.ActionGet, typeOidcAuthConfig, nil, err)
		}
	}

	oidcProvider := oidcConfig.Host
	oidcClientID := oidcConfig.ClientID

	// Validate the token
	provider, err := oidc.NewProvider(context.Background(), oidcProvider)
	if err != nil {
		return "", errors.WrapErrorAction(logutils.ActionInitialize, "oidc provider", nil, err)
	}
	tokenVerifier := provider.Verifier(&oidc.Config{ClientID: oidcClientID})
	verifiedToken, err := tokenVerifier.Verify(context.Background(), idToken)
	if err != nil {
		return "", errors.WrapErrorAction(logutils.ActionValidate, logutils.TypeToken, nil, err)
	}

	var rawClaims map[string]interface{}
	if err := verifiedToken.Claims(&rawClaims); err != nil {
		return "", errors.WrapErrorAction(logutils.ActionUnmarshal, logutils.TypeClaim, nil, err)
	}

	sub, ok := rawClaims["sub"].(string)
	if !ok {
		return "", errors.ErrorData(logutils.StatusInvalid, logutils.TypeClaim, &logutils.FieldArgs{"sub": rawClaims["sub"]})
	}

	return sub, nil
}

func (a *oidcAuthImpl) newToken(code string, authType model.AuthType, appType model.ApplicationType, appOrg model.ApplicationOrganization, params *oidcLoginParams, oidcConfig *oidcAuthConfig, l *logs.Log) (*model.ExternalSystemUser, map[string]interface{}, string, error) {
	bodyData := map[string]string{
		"code":         code,
		"grant_type":   "authorization_code",
		"redirect_uri": params.RedirectURI,
		"client_id":    oidcConfig.ClientID,
	}
	if len(params.CodeVerifier) > 0 {
		bodyData["code_verifier"] = params.CodeVerifier
	}

	return a.loadOidcTokensAndInfo(bodyData, oidcConfig, authType, appType, appOrg, params.RedirectURI, l)
}

func (a *oidcAuthImpl) refreshToken(authType model.AuthType, appType model.ApplicationType, appOrg model.ApplicationOrganization,
	params *oidcRefreshParams, oidcConfig *oidcAuthConfig, l *logs.Log) (*model.ExternalSystemUser, map[string]interface{}, string, error) {
	if !oidcConfig.UseRefresh {
		return nil, nil, "", errors.ErrorData(logutils.StatusDisabled, "refresh tokens", &logutils.FieldArgs{"app_id": appOrg.Application.ID, "org_id": appOrg.Organization.ID})
	}

	bodyData := map[string]string{
		"refresh_token": params.RefreshToken,
		"grant_type":    "refresh_token",
		"redirect_uri":  params.RedirectURI,
		"client_id":     oidcConfig.ClientID,
	}

	return a.loadOidcTokensAndInfo(bodyData, oidcConfig, authType, appType, appOrg, params.RedirectURI, l)
}

func (a *oidcAuthImpl) loadOidcTokensAndInfo(bodyData map[string]string, oidcConfig *oidcAuthConfig, authType model.AuthType, appType model.ApplicationType,
	appOrg model.ApplicationOrganization, redirectURI string, l *logs.Log) (*model.ExternalSystemUser, map[string]interface{}, string, error) {
	token, err := a.loadOidcTokenWithParams(bodyData, oidcConfig)
	if err != nil {
		return nil, nil, "", errors.WrapErrorAction(logutils.ActionGet, typeOidcToken, nil, err)
	}

	sub, err := a.checkToken(token.IDToken, authType, appType, oidcConfig, l)
	if err != nil {
		return nil, nil, "", errors.WrapErrorAction(logutils.ActionValidate, typeOidcToken, nil, err)
	}

	userInfoURL := oidcConfig.Host + "/idp/profile/oidc/userinfo"
	if len(oidcConfig.UserInfoURL) > 0 {
		userInfoURL = oidcConfig.UserInfoURL
	}
	userInfo, err := a.loadOidcUserInfo(token, userInfoURL)
	if err != nil {
		return nil, nil, "", errors.WrapErrorAction(logutils.ActionGet, "user info", nil, err)
	}

	var userClaims map[string]interface{}
	err = json.Unmarshal(userInfo, &userClaims)
	if err != nil {
		return nil, nil, "", errors.WrapErrorAction(logutils.ActionUnmarshal, "user info", nil, err)
	}

	userClaimsSub, _ := userClaims["sub"].(string)
	if userClaimsSub != sub {
		return nil, nil, "", errors.ErrorData("mismatched", "sub fields", &logutils.FieldArgs{"user info": userClaimsSub, "id token": sub})
	}

	identityProviderID, _ := authType.Params["identity_provider"].(string)
	identityProviderSetting := appOrg.FindIdentityProviderSetting(identityProviderID)

	if identityProviderSetting == nil {
		return nil, nil, "", errors.ErrorData(logutils.StatusMissing, model.TypeIdentityProviderConfig, &logutils.FieldArgs{"app_org": appOrg.ID, "identity_provider_id": identityProviderID})
	}

	//identifier
	identifier, _ := userClaims[identityProviderSetting.UserIdentifierField].(string)
	//first name
	firstName, _ := userClaims[identityProviderSetting.FirstNameField].(string)
	//middle name
	middleName, _ := userClaims[identityProviderSetting.MiddleNameField].(string)
	//last name
	lastName, _ := userClaims[identityProviderSetting.LastNameField].(string)
	//email
	email, _ := userClaims[identityProviderSetting.EmailField].(string)
	//ferpa
	ferpa := false //dy default
	ferpaFieldVal, exists := userClaims[identityProviderSetting.FerpaField]
	if exists { //we are not sure if it is bool or string, so handle both
		if ferpaVal, ok := ferpaFieldVal.(bool); ok {
			ferpa = ferpaVal
		} else if ferpaStr, ok := ferpaFieldVal.(string); ok {
			if ferpaStr == "true" {
				ferpa = true
			} else if ferpaStr == "false" {
				ferpa = false
			}
		}
	}

	//roles
	rolesList, _ := userClaims[identityProviderSetting.RolesField].([]interface{})
	roles := make([]string, len(rolesList))
	for i, item := range rolesList {
		role, _ := item.(string)
		roles[i] = role
	}
	//groups
	groupsList, _ := userClaims[identityProviderSetting.GroupsField].([]interface{})
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

	externalUser := model.ExternalSystemUser{Identifier: identifier, ExternalIDs: externalIDs, FirstName: firstName,
		MiddleName: middleName, LastName: lastName, Email: email, Roles: roles, Groups: groups, SystemSpecific: systemSpecific, Ferpa: ferpa}

	oidcParams := map[string]interface{}{}
	oidcParams["id_token"] = token.IDToken
	oidcParams["access_token"] = token.AccessToken
	oidcParams["refresh_token"] = token.RefreshToken
	oidcParams["token_type"] = token.TokenType

	params := map[string]interface{}{}
	params["oidc_token"] = oidcParams
	params["redirect_uri"] = redirectURI
	return &externalUser, params, token.AccessToken, nil
}

func (a *oidcAuthImpl) loadOidcTokenWithParams(params map[string]string, oidcConfig *oidcAuthConfig) (*oidcToken, error) {
	tokenURI := ""
	oidcTokenURL := oidcConfig.Host + "/idp/profile/oidc/token"
	if len(oidcConfig.TokenURL) > 0 {
		oidcTokenURL = oidcConfig.TokenURL
	}
	if strings.Contains(oidcTokenURL, "{shibboleth_client_id}") {
		tokenURI = strings.ReplaceAll(oidcTokenURL, "{shibboleth_client_id}", oidcConfig.ClientID)
		tokenURI = strings.ReplaceAll(tokenURI, "{shibboleth_client_secret}", oidcConfig.ClientSecret)
	} else if len(oidcConfig.ClientSecret) > 0 {
		tokenURI = oidcTokenURL
		params["client_secret"] = oidcConfig.ClientSecret
	} else {
		tokenURI = oidcTokenURL
	}

	data := url.Values{}
	for k, v := range params {
		data.Set(k, v)
	}
	headers := map[string]string{
		"Content-Type":   "application/x-www-form-urlencoded",
		"Content-Length": strconv.Itoa(len(data.Encode())),
	}

	req, err := http.NewRequest(http.MethodPost, tokenURI, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionCreate, logutils.TypeRequest, nil, err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionSend, logutils.TypeRequest, nil, err)
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionRead, logutils.TypeRequestBody, nil, err)
	}
	if resp.StatusCode != 200 {
		return nil, errors.ErrorData(logutils.StatusInvalid, logutils.TypeResponse, &logutils.FieldArgs{"status_code": resp.StatusCode, "error": string(body)})
	}

	var authToken oidcToken
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

func (a *oidcAuthImpl) loadOidcUserInfo(token *oidcToken, url string) ([]byte, error) {
	if len(token.AccessToken) == 0 {
		return nil, errors.ErrorData(logutils.StatusMissing, "access token", nil)
	}
	if len(token.TokenType) == 0 {
		return nil, errors.ErrorData(logutils.StatusMissing, "token type", nil)
	}
	if len(url) == 0 {
		return nil, errors.ErrorData(logutils.StatusMissing, "user info url", nil)
	}

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionCreate, logutils.TypeRequest, nil, err)
	}
	req.Header.Set("Authorization", fmt.Sprintf("%s %s", token.TokenType, token.AccessToken))

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionSend, logutils.TypeRequest, nil, err)
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
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

func (a *oidcAuthImpl) getOidcAuthConfig(authType model.AuthType, appType model.ApplicationType) (*oidcAuthConfig, error) {
	errFields := &logutils.FieldArgs{"auth_type_id": authType.ID, "app_type_id": appType.ID}

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

	var oidcConfig oidcAuthConfig
	err = json.Unmarshal(configBytes, &oidcConfig)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionUnmarshal, model.TypeIdentityProviderConfig, errFields, err)
	}

	validate := validator.New()
	err = validate.Struct(oidcConfig)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionValidate, model.TypeIdentityProviderConfig, errFields, err)
	}

	return &oidcConfig, nil
}

// --- Helper functions ---

// generatePkceChallenge generates and returns a PKCE code challenge and verifier
func generatePkceChallenge() (string, string, error) {
	codeVerifier, err := utils.GenerateRandomString(50)
	if err != nil {
		return "", "", errors.WrapErrorAction(logutils.ActionGenerate, "code verifier", nil, err)
	}

	codeChallengeBytes, err := authutils.HashSha256([]byte(codeVerifier))
	if err != nil {
		return "", "", errors.WrapErrorAction(logutils.ActionCompute, "code verifier hash", nil, err)
	}
	codeChallenge := base64.URLEncoding.EncodeToString(codeChallengeBytes)

	return codeChallenge, codeVerifier, nil
}

// initOidcAuth initializes and registers a new OIDC auth instance
func initOidcAuth(auth *Auth) (*oidcAuthImpl, error) {
	oidc := &oidcAuthImpl{auth: auth, authType: AuthTypeOidc}

	err := auth.registerExternalAuthType(oidc.authType, oidc)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionRegister, typeExternalAuthType, nil, err)
	}

	return oidc, nil
}
