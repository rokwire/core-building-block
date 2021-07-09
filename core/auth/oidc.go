package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/coreos/go-oidc"
)

type oidcToken struct {
	IDToken      string `json:"id_token"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
}

// OIDC implementation of authType
type oidcAuthImpl struct {
	auth *Auth
}

type oidcCheckParams struct {
	OrgID string `json:"org_id"`
	AppID string `json:"app_id"`
}

type oidcLoginParams struct {
	OrgID        string `json:"org_id"`
	AppID        string `json:"app_id"`
	Code         string `json:"code"`
	CodeVerifier string `json:"pkce_verifier"`
	RedirectURI  string `json:"redirect_uri"`
}

type oidcRefreshParams struct {
	OrgID       string `json:"org_id"`
	AppID       string `json:"app_id"`
	RedirectURI string `json:"redirect_uri"`
}

func (a *oidcAuthImpl) check(creds string, params string) (*UserAuth, error) {
	paramsMap := make(map[string]interface{})
	err := json.Unmarshal([]byte(params), &paramsMap)
	if err != nil {
		return nil, err
	}
	credType, ok := paramsMap["cred_type"].(string)
	if !ok {
		return nil, errors.New("cred_type parameter missing or invalid")
	}

	switch credType {
	case "id_token":
		var checkParams oidcCheckParams
		err := json.Unmarshal([]byte(params), &checkParams)
		if err != nil {
			return nil, err
		}
		return a.checkToken(creds, &checkParams, nil)
	case "code":
		var loginParams oidcLoginParams
		err := json.Unmarshal([]byte(params), &loginParams)
		if err != nil {
			return nil, err
		}
		return a.newToken(creds, &loginParams)
	case "refresh_token":
		var refreshParams oidcRefreshParams
		err := json.Unmarshal([]byte(params), &refreshParams)
		if err != nil {
			return nil, err
		}
		return a.refreshToken(creds, &refreshParams)
	default:
		return nil, errors.New("unimplemented cred_type")
	}
}

func (a *oidcAuthImpl) checkToken(idToken string, params *oidcCheckParams, authInfo *AuthInfo) (*UserAuth, error) {
	if authInfo == nil {
		authInfo = a.auth.getAuthInfo(params.OrgID, params.AppID)
	}

	oidcProvider := authInfo.OIDCHost
	oidcClientID := authInfo.OIDCClientID

	// Validate the token
	provider, err := oidc.NewProvider(context.Background(), oidcProvider)
	if err != nil {
		return nil, err
	}
	tokenVerifier := provider.Verifier(&oidc.Config{ClientID: oidcClientID})
	verifiedToken, err := tokenVerifier.Verify(context.Background(), idToken)
	if err != nil {
		return nil, err
	}

	var rawClaims map[string]interface{}
	if err := verifiedToken.Claims(&rawClaims); err != nil {
		log.Printf("error getting raw claims from token - %s\n", err)
	} else {
		log.Printf("Raw Token Claims: %v", rawClaims)
	}

	userAuth := UserAuth{}
	userAuth.ID = rawClaims["id"].(string)
	userAuth.Name = rawClaims["name"].(string)
	userAuth.Email = rawClaims["email"].(string)
	userAuth.Phone = rawClaims["phone"].(string)
	userAuth.Issuer = rawClaims["iss"].(string)
	userAuth.Exp = rawClaims["exp"].(float64)
	return &userAuth, nil
}

func (a *oidcAuthImpl) newToken(code string, params *oidcLoginParams) (*UserAuth, error) {
	authInfo := a.auth.getAuthInfo(params.OrgID, params.AppID)

	if len(authInfo.OIDCTokenURL) == 0 {
		return nil, errors.New("auth info missing OIDC token URL")
	}
	if len(authInfo.OIDCUserURL) == 0 {
		return nil, errors.New("auth info missing OIDC user URL")
	}
	if len(authInfo.OIDCClientID) == 0 {
		return nil, errors.New("auth info missing OIDC client ID")
	}

	bodyData := map[string]string{
		"code":         code,
		"grant_type":   "authorization_code",
		"redirect_uri": params.RedirectURI,
		"client_id":    authInfo.OIDCClientID,
	}
	if len(params.CodeVerifier) > 0 {
		bodyData["code_verifier"] = params.CodeVerifier
	}

	return a.loadOidcTokensAndInfo(bodyData, authInfo)
}

func (a *oidcAuthImpl) refreshToken(refreshToken string, params *oidcRefreshParams) (*UserAuth, error) {
	authInfo := a.auth.getAuthInfo(params.OrgID, params.AppID)

	if len(authInfo.OIDCTokenURL) == 0 {
		return nil, errors.New("auth info missing OIDC token URL")
	}
	if len(authInfo.OIDCUserURL) == 0 {
		return nil, errors.New("auth info missing OIDC user URL")
	}
	if len(authInfo.OIDCClientID) == 0 {
		return nil, errors.New("auth info missing OIDC client ID")
	}
	if !authInfo.OIDCUseRefresh {
		return nil, errors.New("should not use refresh token")
	}

	bodyData := map[string]string{
		"refresh_token": refreshToken,
		"grant_type":    "refresh_token",
		"redirect_uri":  params.RedirectURI,
		"client_id":     authInfo.OIDCClientID,
	}

	return a.loadOidcTokensAndInfo(bodyData, authInfo)
}

func (a *oidcAuthImpl) loadOidcTokensAndInfo(bodyData map[string]string, authInfo *AuthInfo) (*UserAuth, error) {
	oidcToken, err := a.loadOidcTokenWithParams(bodyData, authInfo)
	if err != nil {
		return nil, err
	}
	if oidcToken == nil {
		return nil, errors.New("get auth token failed")
	}

	userAuth, err := a.checkToken(oidcToken.IDToken, nil, authInfo)
	userAuth.RefreshToken = oidcToken.RefreshToken

	userInfo, err := a.loadOidcUserInfo(oidcToken, authInfo.OIDCUserURL)
	if userInfo == nil {
		return nil, errors.New("get auth user failed")
	}
	var userMap map[string]interface{}
	err = json.Unmarshal(userInfo, &userMap)
	if err != nil {
		return nil, err
	}

	var userPhoto []byte
	if photoURL, ok := userMap["picture"].(string); ok {
		userPhoto, err = a.loadOidcUserInfo(oidcToken, photoURL)
		if err != nil {
			log.Println("Error fetching user photo:", err.Error())
		}
	}
	userAuth.Picture = userPhoto

	return userAuth, nil
}

func (a *oidcAuthImpl) loadOidcTokenWithParams(params map[string]string, authInfo *AuthInfo) (*oidcToken, error) {
	tokenUri := ""
	if strings.Contains(authInfo.OIDCTokenURL, "{shibboleth_client_id}") {
		tokenUri = strings.ReplaceAll(authInfo.OIDCTokenURL, "{shibboleth_client_id}", authInfo.OIDCClientID)
		tokenUri = strings.ReplaceAll(tokenUri, "{shibboleth_client_secret}", authInfo.OIDCClientSecret)
	} else if len(authInfo.OIDCClientSecret) > 0 {
		tokenUri = authInfo.OIDCTokenURL
		params["client_secret"] = authInfo.OIDCClientSecret
	} else {
		tokenUri = authInfo.OIDCTokenURL
	}

	uri := url.URL{}
	for k, v := range params {
		if len(uri.RawQuery) < 1 {
			uri.RawQuery += fmt.Sprintf("%s=%s", k, v)
		} else {
			uri.RawQuery += fmt.Sprintf("&%s=%s", k, v)
		}
	}
	headers := map[string]string{
		"Content-Type":   "application/x-www-form-urlencoded",
		"Content-Length": strconv.Itoa(len(uri.Query().Encode())),
	}
	jsonData, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}

	client := &http.Client{}
	req, err := http.NewRequest("POST", tokenUri, bytes.NewReader(jsonData))
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, errors.New("error with response code != 200")
	}

	var authToken oidcToken
	err = json.Unmarshal(body, &authToken)
	if err != nil {
		return nil, err
	}

	return &authToken, nil
}

func (a *oidcAuthImpl) loadOidcUserInfo(token *oidcToken, url string) ([]byte, error) {
	if len(token.AccessToken) == 0 {
		return nil, errors.New("missing access token")
	}
	if len(token.TokenType) == 0 {
		return nil, errors.New("missing token type")
	}
	if len(url) == 0 {
		return nil, errors.New("missing oidc user info url")
	}

	client := &http.Client{}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", fmt.Sprintf("%s %s", token.TokenType, token.AccessToken))

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, errors.New("error with response code != 200")
	}

	return body, nil
}

//initOidcAuth initializes and registers a new OIDC auth instance
func initOidcAuth(auth *Auth) (*oidcAuthImpl, error) {
	oidc := &oidcAuthImpl{auth: auth}

	err := auth.registerAuthType("oidc", oidc)
	if err != nil {
		return nil, err
	}

	return oidc, nil
}
