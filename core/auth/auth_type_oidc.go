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
	"core-building-block/utils"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"gopkg.in/go-playground/validator.v9"

	"github.com/coreos/go-oidc"
	"github.com/rokwire/core-auth-library-go/v2/authutils"
	"github.com/rokwire/logging-library-go/errors"
	"github.com/rokwire/logging-library-go/logutils"
)

const (
	//AuthTypeOidc oidc auth type
	AuthTypeOidc string = "oidc"

	typeOidcLoginParams logutils.MessageDataType = "oidc login params"
)

type oidcAuthConfig struct {
	Host               string            `json:"host" validate:"required"`
	RedirectURI        string            `json:"redirect_uri" validate:"required"`
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

func (o *oidcAuthConfig) getAuthorizeURL() string {
	url := o.Host + "/idp/profile/oidc/authorize"
	if len(o.AuthorizeURL) > 0 {
		url = o.AuthorizeURL
	}

	return url
}

func (o *oidcAuthConfig) getTokenURL() string {
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

func (o *oidcAuthConfig) getUserInfoURL() string {
	url := o.Host + "/idp/profile/oidc/userinfo"
	if len(o.UserInfoURL) > 0 {
		url = o.UserInfoURL
	}

	return url
}

func (o *oidcAuthConfig) getAuthorizationCode(auth *Auth, creds string, params string) (string, error) {
	parsedCreds, err := auth.queryValuesFromURL(creds)
	if err != nil {
		return "", errors.WrapErrorAction(logutils.ActionParse, "oidc creds", nil, err)
	}

	return parsedCreds.Get("code"), nil
}

func (o *oidcAuthConfig) buildNewTokenRequest(auth *Auth, creds string, params string, refresh bool) (*http.Request, error) {
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
		body["grant_type"] = "authorization_code"

		var loginParams oidcLoginParams
		err := json.Unmarshal([]byte(params), &loginParams)
		if err != nil {
			return nil, errors.WrapErrorAction(logutils.ActionUnmarshal, typeOidcLoginParams, nil, err)
		}
		validate := validator.New()
		err = validate.Struct(loginParams)
		if err != nil {
			return nil, errors.WrapErrorAction(logutils.ActionValidate, typeOidcLoginParams, nil, err)
		}
		if len(loginParams.CodeVerifier) > 0 {
			body["code_verifier"] = loginParams.CodeVerifier
		}
	}

	encoded := auth.encodeQueryValues(body)
	headers := map[string]string{
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

func (o *oidcAuthConfig) checkIDToken(token oauthToken) (string, error) {
	provider, err := oidc.NewProvider(context.Background(), o.Host)
	if err != nil {
		return "", errors.WrapErrorAction(logutils.ActionInitialize, "oidc provider", nil, err)
	}
	tokenVerifier := provider.Verifier(&oidc.Config{ClientID: o.ClientID})
	verifiedToken, err := tokenVerifier.Verify(context.Background(), token.getIDToken())
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

func (o *oidcAuthConfig) checkSubject(tokenSubject string, userSubject string) bool {
	return tokenSubject == userSubject
}

func (o *oidcAuthConfig) buildLoginURLResponse(auth *Auth) (string, map[string]interface{}, error) {
	scopes := o.Scopes
	if len(scopes) == 0 {
		scopes = "openid profile email offline_access"
	}

	query := map[string]string{
		"scope":         scopes,
		"response_type": "code",
		"redirect_uri":  o.RedirectURI,
		"client_id":     o.ClientID,
	}

	if len(o.AuthorizeClaims) > 0 {
		query["claims"] = o.AuthorizeClaims
	}

	responseParams := make(map[string]interface{})
	if o.UsePKCE {
		codeChallenge, codeVerifier, err := o.generatePkceChallenge()
		if err != nil {
			return "", nil, errors.WrapErrorAction("generating", "pkce challenge", nil, err)
		}
		query["code_challenge_method"] = "S256"
		query["code_challenge"] = codeChallenge
		responseParams["pkce_verifier"] = codeVerifier
	}

	return o.getAuthorizeURL() + "?" + auth.encodeQueryValues(query), responseParams, nil
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

func (t *oidcToken) getAuthorizationHeader() string {
	return fmt.Sprintf("%s %s", t.TokenType, t.AccessToken)
}

func (t *oidcToken) getResponse() map[string]interface{} {
	tokenParams := map[string]interface{}{}
	tokenParams["id_token"] = t.IDToken
	tokenParams["access_token"] = t.AccessToken
	tokenParams["refresh_token"] = t.RefreshToken
	tokenParams["token_type"] = t.TokenType

	params := map[string]interface{}{}
	params["oidc_token"] = tokenParams
	return params
}

func (t *oidcToken) getIDToken() string {
	return t.IDToken
}

type oidcLoginParams struct {
	CodeVerifier string `json:"pkce_verifier"`
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
