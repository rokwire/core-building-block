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
	"core-building-block/driven/oauthprovider"
	"core-building-block/utils"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/coreos/go-oidc"
	"github.com/rokwire/core-auth-library-go/v2/authutils"
	"github.com/rokwire/logging-library-go/errors"
	"github.com/rokwire/logging-library-go/logutils"
	"gopkg.in/go-playground/validator.v9"
)

const (
	//AuthTypeOidc oidc auth type
	AuthTypeOidc string = "oidc"

	typeOidcLoginParams logutils.MessageDataType = "oidc login params"
)

type oidcAuthConfig struct {
	Host               string            `json:"host" validate:"required"`
	RedirectURI        string            `json:"redirect_uri"`
	AuthorizeURL       string            `json:"authorize_url"`
	TokenURL           string            `json:"token_url"`
	UserInfoURL        string            `json:"userinfo_url"`
	Scopes             string            `json:"scopes"`
	UseRefresh         bool              `json:"use_refresh"`
	UsePKCE            bool              `json:"use_pkce"`
	UseState           bool              `json:"use_state"`
	ClientID           string            `json:"client_id" validate:"required"`
	ClientSecret       string            `json:"client_secret"`
	AuthorizeClaims    string            `json:"authorize_claims"`
	Claims             map[string]string `json:"claims" validate:"required"`
	RequiredPopulation string            `json:"required_population"`
	Populations        map[string]string `json:"populations"`
}

func (o *oidcAuthConfig) GetAuthorizeURL() string {
	url := o.Host + "/idp/profile/oidc/authorize"
	if len(o.AuthorizeURL) > 0 {
		url = o.AuthorizeURL
	}

	return url
}

func (o *oidcAuthConfig) GetTokenURL() string {
	tokenURL := o.Host + "/idp/profile/oidc/token"
	if len(o.TokenURL) > 0 {
		tokenURL = o.TokenURL
	}

	url := ""
	if strings.Contains(tokenURL, "{shibboleth_client_id}") {
		url = strings.ReplaceAll(tokenURL, "{shibboleth_client_id}", o.ClientID)
		url = strings.ReplaceAll(url, "{shibboleth_client_secret}", o.ClientSecret)
	} else {
		url = tokenURL
	}

	return url
}

func (o *oidcAuthConfig) GetUserInfoURL() string {
	url := o.Host + "/idp/profile/oidc/userinfo"
	if len(o.UserInfoURL) > 0 {
		url = o.UserInfoURL
	}

	return url
}

func (o *oidcAuthConfig) BuildNewTokenRequest(creds string, params string, refresh bool) (*oauthprovider.OAuthRequest, map[string]interface{}, error) {
	if refresh && !o.UseRefresh {
		return nil, nil, nil
	}

	var loginParams oidcLoginParams
	err := json.Unmarshal([]byte(params), &loginParams)
	if err != nil {
		return nil, nil, errors.WrapErrorAction(logutils.ActionUnmarshal, typeOidcLoginParams, nil, err)
	}

	redirectURI := o.RedirectURI
	if redirectURI == "" {
		redirectURI = loginParams.RedirectURI
	}

	body := map[string]string{
		"client_id":    o.ClientID,
		"redirect_uri": redirectURI,
	}
	if o.ClientSecret != "" {
		body["client_secret"] = o.ClientSecret
	}
	if refresh {
		body["refresh_token"] = creds
		body["grant_type"] = "refresh_token"
	} else {
		parsedCreds, err := utils.QueryValuesFromURL(creds)
		if err != nil {
			return nil, nil, errors.WrapErrorAction(logutils.ActionParse, "oidc creds", nil, err)
		}
		//state in creds must match state generated for login url (if used)
		if o.UseState && loginParams.State != parsedCreds.Get("state") {
			return nil, nil, errors.ErrorData(logutils.StatusInvalid, "oidc login", &logutils.FieldArgs{"state": parsedCreds.Get("state")})
		}

		body["code"] = parsedCreds.Get("code")
		body["grant_type"] = "authorization_code"

		if len(loginParams.CodeVerifier) > 0 {
			body["code_verifier"] = loginParams.CodeVerifier
		}
	}

	encoded := utils.EncodeQueryValues(body)
	headers := map[string]string{
		"Content-Type":   "application/x-www-form-urlencoded",
		"Content-Length": strconv.Itoa(len(body)),
	}

	responseParams := map[string]interface{}{}
	if o.RedirectURI == "" {
		responseParams["redirect_uri"] = redirectURI
	}

	return &oauthprovider.OAuthRequest{Method: methodPost, URL: o.GetTokenURL(), Body: encoded, Headers: headers}, responseParams, nil
}

func (o *oidcAuthConfig) ParseTokenResponse(response []byte, params map[string]interface{}) (oauthprovider.OAuthToken, map[string]interface{}, error) {
	var token oidcToken
	err := json.Unmarshal(response, &token)
	if err != nil {
		return nil, nil, errors.WrapErrorAction(logutils.ActionUnmarshal, logutils.TypeToken, nil, err)
	}
	validate := validator.New()
	err = validate.Struct(token)
	if err != nil {
		return nil, nil, errors.WrapErrorAction(logutils.ActionValidate, logutils.TypeToken, nil, err)
	}

	params["oidc_token"] = token.GetResponseParams()
	return &token, params, nil
}

func (o *oidcAuthConfig) CheckIDToken(token oauthprovider.OAuthToken) (string, error) {
	provider, err := oidc.NewProvider(context.Background(), o.Host)
	if err != nil {
		return "", errors.WrapErrorAction(logutils.ActionInitialize, "oidc provider", nil, err)
	}
	tokenVerifier := provider.Verifier(&oidc.Config{ClientID: o.ClientID})
	verifiedToken, err := tokenVerifier.Verify(context.Background(), token.GetIDToken())
	if err != nil {
		return "", errors.WrapErrorAction(logutils.ActionValidate, "id token", nil, err)
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

func (o *oidcAuthConfig) CheckSubject(tokenSubject string, userSubject string) bool {
	return tokenSubject == userSubject
}

func (o *oidcAuthConfig) BuildLoginURLResponse(redirectURI string) (string, map[string]interface{}, error) {
	scopes := o.Scopes
	if len(scopes) == 0 {
		scopes = "openid profile email offline_access"
	}

	if o.RedirectURI != "" {
		redirectURI = o.RedirectURI
	}

	query := map[string]string{
		"scope":         scopes,
		"response_type": "code",
		"redirect_uri":  redirectURI,
		"client_id":     o.ClientID,
	}

	if len(o.AuthorizeClaims) > 0 {
		query["claims"] = o.AuthorizeClaims
	}

	responseParams := make(map[string]interface{})
	responseParams["redirect_uri"] = redirectURI
	if o.UsePKCE {
		codeChallenge, codeVerifier, err := o.generatePkceChallenge()
		if err != nil {
			return "", nil, errors.WrapErrorAction("generating", "pkce challenge", nil, err)
		}
		query["code_challenge_method"] = "S256"
		query["code_challenge"] = codeChallenge
		responseParams["pkce_verifier"] = codeVerifier
	}
	if o.UseState {
		state, err := utils.GenerateRandomString(50)
		if err != nil {
			return "", nil, errors.WrapErrorAction("generating", "random state", nil, err)
		}
		query["state"] = state
		responseParams["state"] = state
	}

	return o.GetAuthorizeURL() + "?" + utils.EncodeQueryValues(query), responseParams, nil
}

// --- Helper functions ---

// generatePkceChallenge generates and returns a PKCE code challenge and verifier
func (o *oidcAuthConfig) generatePkceChallenge() (string, string, error) {
	codeVerifier, err := utils.GenerateRandomString(50)
	if err != nil {
		return "", "", errors.WrapErrorAction("generating", "code verifier", nil, err)
	}

	codeChallengeBytes, err := authutils.HashSha256([]byte(codeVerifier))
	if err != nil {
		return "", "", errors.WrapErrorAction("hashing", "code verifier", nil, err)
	}
	codeChallenge := base64.URLEncoding.EncodeToString(codeChallengeBytes)

	return codeChallenge, codeVerifier, nil
}

type oidcToken struct {
	IDToken      string `json:"id_token" validate:"required"`
	AccessToken  string `json:"access_token" validate:"required"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type" validate:"required"`
	ExpiresIn    int    `json:"expires_in"`
}

func (t *oidcToken) GetAuthorizationHeader() string {
	return fmt.Sprintf("%s %s", t.TokenType, t.AccessToken)
}

func (t *oidcToken) GetResponseParams() map[string]interface{} {
	return map[string]interface{}{
		"id_token":      t.IDToken,
		"access_token":  t.AccessToken,
		"refresh_token": t.RefreshToken,
		"token_type":    t.TokenType,
	}
}

func (t *oidcToken) GetIDToken() string {
	return t.IDToken
}

type oidcLoginParams struct {
	CodeVerifier string `json:"pkce_verifier"`
	State        string `json:"state"`
	RedirectURI  string `json:"redirect_uri"`
}

// initOidcAuth initializes and registers a new OAuth auth instance for OIDC
func initOidcAuth(auth *Auth) (*oauthAuthImpl, error) {
	oidc := &oauthAuthImpl{auth: auth, authType: AuthTypeOidc}

	err := auth.registerExternalAuthType(AuthTypeOidc, oidc)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionRegister, typeAuthType, logutils.StringArgs(AuthTypeOidc), err)
	}

	return oidc, nil
}
