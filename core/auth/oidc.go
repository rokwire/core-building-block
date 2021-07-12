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

// OIDC implementation of authType
type oidcAuthImpl struct {
	auth *Auth
}

type oidcAuthConfig struct {
	Issuer             string            `json:"issuer" bson:"issuer"`
	Host               string            `json:"host" bson:"host"`
	Scopes             string            `json:"scopes" bson:"scopes"`
	UseRefresh         bool              `json:"use_refresh" bson:"use_refresh"`
	UsePKCE            bool              `json:"use_pkce" bson:"use_pkce"`
	ClientID           string            `json:"client_id" bson:"client_id"`
	ClientSecret       string            `json:"client_secret" bson:"client_secret"`
	Claims             map[string]string `json:"claims" bson:"claims"`
	RequiredPopulation string            `json:"required_population" bson:"required_population"`
	Populations        map[string]string `json:"populations" bson:"populations"`
}

type oidcMobileParams struct {
	OrgID         string `json:"org_id" validate:"required"`
	AppID         string `json:"app_id" validate:"required"`
	CodeChallenge string `json:"pkce_challenge"`
	RedirectURI   string `json:"redirect_uri" validate:"required"`
}

type oidcCheckParams struct {
	OrgID string `json:"org_id" validate:"required"`
	AppID string `json:"app_id" validate:"required"`
}

type oidcLoginParams struct {
	OrgID        string `json:"org_id" validate:"required"`
	AppID        string `json:"app_id" validate:"required"`
	CodeVerifier string `json:"pkce_verifier"`
	RedirectURI  string `json:"redirect_uri" validate:"required"`
}

type oidcRefreshParams struct {
	OrgID       string `json:"org_id" validate:"required"`
	AppID       string `json:"app_id" validate:"required"`
	RedirectURI string `json:"redirect_uri" validate:"required"`
}

type oidcToken struct {
	IDToken      string `json:"id_token"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
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
		return nil, fmt.Errorf("unimplemented cred_type %s", credType)
	}
}

func (a *oidcAuthImpl) mobileLoginURL(params string) (string, error) {
	var mobileParams oidcMobileParams
	err := json.Unmarshal([]byte(params), &mobileParams)
	if err != nil {
		return "", err
	}

	authConfig := a.auth.getAuthConfig(mobileParams.OrgID, mobileParams.AppID, "oidc")
	oidcConfig, ok := authConfig.Config.(oidcAuthConfig)
	if !ok {
		return "", fmt.Errorf("auth config for orgID %s, appID %s cannot be used for oidc", mobileParams.OrgID, mobileParams.AppID)
	}

	if len(oidcConfig.Host) == 0 {
		return "", errors.New("oidc auth config missing host")
	}
	if len(oidcConfig.ClientID) == 0 {
		return "", errors.New("oidc auth config missing client ID")
	}

	scopes := oidcConfig.Scopes
	if len(scopes) == 0 {
		scopes = "openid profile email offline_access"
	}

	bodyData := map[string]string{
		"scope":         scopes,
		"response_type": "code",
		"redirect_uri":  mobileParams.RedirectURI,
		"client_id":     oidcConfig.ClientID,
	}

	if len(oidcConfig.Claims) > 0 {
		claims, err := json.Marshal(oidcConfig.Claims)
		if err == nil {
			bodyData["claims"] = string(claims)
		}
	}

	if oidcConfig.UsePKCE {
		bodyData["code_challenge_method"] = "S256"
		bodyData["code_challenge"] = mobileParams.CodeChallenge
	}

	url, err := url.Parse(oidcConfig.Host + "/idp/profile/oidc/authorize")
	if err != nil {
		return "", fmt.Errorf("oidc auth url for orgID %s, appID %s could not be parsed", mobileParams.OrgID, mobileParams.AppID)
	}
	for k, v := range bodyData {
		if len(url.RawQuery) < 1 {
			url.RawQuery += fmt.Sprintf("%s=%s", k, v)
		} else {
			url.RawQuery += fmt.Sprintf("&%s=%s", k, v)
		}
	}

	return url.String(), nil
}

func (a *oidcAuthImpl) checkToken(idToken string, params *oidcCheckParams, oidcConfig *oidcAuthConfig) (string, error) {
	if oidcConfig == nil {
		authConfig := a.auth.getAuthConfig(params.OrgID, params.AppID, "oidc")
		newOidcConfig, ok := authConfig.Config.(oidcAuthConfig)
		if !ok {
			return "", fmt.Errorf("auth config for orgID %s, appID %s cannot be used for oidc", params.OrgID, params.AppID)
		}
		oidcConfig = &newOidcConfig
	}

	oidcProvider := oidcConfig.Host
	oidcClientID := oidcConfig.ClientID

	// Validate the token
	provider, err := oidc.NewProvider(context.Background(), oidcProvider)
	if err != nil {
		return "", err
	}
	tokenVerifier := provider.Verifier(&oidc.Config{ClientID: oidcClientID})
	verifiedToken, err := tokenVerifier.Verify(context.Background(), idToken)
	if err != nil {
		return "", err
	}

	var rawClaims map[string]interface{}
	if err := verifiedToken.Claims(&rawClaims); err != nil {
		return "", fmt.Errorf("error getting raw claims from token: %s", err.Error())
	}
	// log.Printf("Raw Token Claims: %v\n", rawClaims)

	sub, ok := rawClaims["sub"].(string)
	if !ok {
		return "", fmt.Errorf("id token sub claim %v has invalid type", rawClaims["sub"])
	}

	return sub, nil
}

func (a *oidcAuthImpl) newToken(code string, params *oidcLoginParams) (*UserAuth, error) {
	authConfig := a.auth.getAuthConfig(params.OrgID, params.AppID, "oidc")
	oidcConfig, ok := authConfig.Config.(oidcAuthConfig)
	if !ok {
		return nil, fmt.Errorf("auth config for orgID %s, appID %s cannot be used for oidc", params.OrgID, params.AppID)
	}

	if len(oidcConfig.Host) == 0 {
		return nil, errors.New("oidc auth config missing host")
	}
	if len(oidcConfig.ClientID) == 0 {
		return nil, errors.New("oidc auth config missing client ID")
	}

	bodyData := map[string]string{
		"code":         code,
		"grant_type":   "authorization_code",
		"redirect_uri": params.RedirectURI,
		"client_id":    oidcConfig.ClientID,
	}
	if len(params.CodeVerifier) > 0 {
		bodyData["code_verifier"] = params.CodeVerifier
	}

	return a.loadOidcTokensAndInfo(bodyData, &oidcConfig)
}

func (a *oidcAuthImpl) refreshToken(refreshToken string, params *oidcRefreshParams) (*UserAuth, error) {
	authConfig := a.auth.getAuthConfig(params.OrgID, params.AppID, "oidc")
	oidcConfig, ok := authConfig.Config.(oidcAuthConfig)
	if !ok {
		return nil, fmt.Errorf("auth config for orgID %s, appID %s cannot be used for oidc", params.OrgID, params.AppID)
	}

	if len(oidcConfig.Host) == 0 {
		return nil, errors.New("oidc auth config missing host")
	}
	if len(oidcConfig.ClientID) == 0 {
		return nil, errors.New("oidc auth config missing client ID")
	}
	if !oidcConfig.UseRefresh {
		return nil, errors.New("should not use refresh token")
	}

	bodyData := map[string]string{
		"refresh_token": refreshToken,
		"grant_type":    "refresh_token",
		"redirect_uri":  params.RedirectURI,
		"client_id":     oidcConfig.ClientID,
	}

	return a.loadOidcTokensAndInfo(bodyData, &oidcConfig)
}

func (a *oidcAuthImpl) loadOidcTokensAndInfo(bodyData map[string]string, oidcConfig *oidcAuthConfig) (*UserAuth, error) {
	oidcToken, err := a.loadOidcTokenWithParams(bodyData, oidcConfig)
	if err != nil {
		return nil, err
	}
	if oidcToken == nil {
		return nil, errors.New("get auth token failed")
	}

	userAuth := UserAuth{}
	sub, err := a.checkToken(oidcToken.IDToken, nil, oidcConfig)
	if err != nil {
		return nil, err
	}
	userAuth.RefreshToken = oidcToken.RefreshToken

	userInfo, err := a.loadOidcUserInfo(oidcToken, oidcConfig.Host+"/idp/profile/oidc/userinfo")
	if err != nil {
		return nil, fmt.Errorf("get auth user failed: %s", err)
	}
	if userInfo == nil {
		return nil, errors.New("get auth user failed")
	}
	var userClaims map[string]interface{}
	err = json.Unmarshal(userInfo, &userClaims)
	if err != nil {
		return nil, err
	}

	userAuth.Sub = userClaims["sub"].(string)
	if userAuth.Sub != sub {
		return nil, fmt.Errorf("mismatching user info sub %s and id token sub %s", userAuth.Sub, sub)
	}
	userAuth.UserID = readFromClaims("user_id", &oidcConfig.Claims, &userClaims).(string)
	userAuth.Name = readFromClaims("name", &oidcConfig.Claims, &userClaims).(string)
	userAuth.Email = readFromClaims("email", &oidcConfig.Claims, &userClaims).(string)
	userAuth.Phone = readFromClaims("phone", &oidcConfig.Claims, &userClaims).(string)
	userAuth.Exp = readFromClaims("exp", &oidcConfig.Claims, &userClaims).(float64)

	var userPhoto []byte
	if photoURL, ok := readFromClaims("picture", &oidcConfig.Claims, &userClaims).(string); ok {
		userPhoto, err = a.loadOidcUserInfo(oidcToken, photoURL)
		if err != nil {
			log.Println("Error fetching user photo:", err.Error())
		}
	}
	userAuth.Picture = userPhoto

	return &userAuth, nil
}

func (a *oidcAuthImpl) loadOidcTokenWithParams(params map[string]string, oidcConfig *oidcAuthConfig) (*oidcToken, error) {
	tokenUri := ""
	oidcTokenURL := oidcConfig.Host + "/idp/profile/oidc/token"
	if strings.Contains(oidcTokenURL, "{shibboleth_client_id}") {
		tokenUri = strings.ReplaceAll(oidcTokenURL, "{shibboleth_client_id}", oidcConfig.ClientID)
		tokenUri = strings.ReplaceAll(tokenUri, "{shibboleth_client_secret}", oidcConfig.ClientSecret)
	} else if len(oidcConfig.ClientSecret) > 0 {
		tokenUri = oidcTokenURL
		params["client_secret"] = oidcConfig.ClientSecret
	} else {
		tokenUri = oidcTokenURL
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

// --- Helper functions ---
func readFromClaims(key string, claimsMap *map[string]string, rawClaims *map[string]interface{}) interface{} {
	if claimsMap == nil {
		return nil
	}
	if rawClaims == nil {
		return nil
	}

	claimsKey := (*claimsMap)[key]
	if len(claimsKey) > 0 {
		return (*rawClaims)[claimsKey]
	}
	return nil
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
