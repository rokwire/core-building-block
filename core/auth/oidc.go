package auth

import (
	"bytes"
	"context"
	"core-building-block/core/model"
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
	"gopkg.in/go-playground/validator.v9"
)

// OIDC implementation of authType
type oidcAuthImpl struct {
	auth *Auth
}

type oidcAuthConfig struct {
	Issuer             string            `json:"issuer"`
	Host               string            `json:"host" validate:"required"`
	Scopes             string            `json:"scopes" validate:"required"`
	UseRefresh         bool              `json:"use_refresh" validate:"required"`
	UsePKCE            bool              `json:"use_pkce" validate:"required"`
	ClientID           string            `json:"client_id" validate:"required"`
	ClientSecret       string            `json:"client_secret"`
	Claims             map[string]string `json:"claims" validate:"required"`
	RequiredPopulation string            `json:"required_population"`
	Populations        map[string]string `json:"populations"`
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
	IDToken      string `json:"id_token" validate:"required"`
	AccessToken  string `json:"access_token" validate:"required"`
	RefreshToken string `json:"refresh_token" validate:"required"`
	TokenType    string `json:"token_type" validate:"required"`
	ExpiresIn    int    `json:"expires_in"`
}

func (a *oidcAuthImpl) check(creds string, params string) (*model.UserAuth, error) {
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
		validate := validator.New()
		err = validate.Struct(loginParams)
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
		validate := validator.New()
		err = validate.Struct(refreshParams)
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
	validate := validator.New()
	err = validate.Struct(mobileParams)
	if err != nil {
		return "", err
	}

	oidcConfig, err := a.getOidcAuthConfig(mobileParams.OrgID, mobileParams.AppID)
	if err != nil {
		return "", fmt.Errorf("auth config for orgID %s, appID %s cannot be used for oidc: %s", mobileParams.OrgID, mobileParams.AppID, err.Error())
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
	var err error
	if oidcConfig == nil {
		oidcConfig, err = a.getOidcAuthConfig(params.OrgID, params.AppID)
		if err != nil {
			return "", fmt.Errorf("auth config for orgID %s, appID %s cannot be used for oidc: %s", params.OrgID, params.AppID, err.Error())
		}
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

func (a *oidcAuthImpl) newToken(code string, params *oidcLoginParams) (*model.UserAuth, error) {
	oidcConfig, err := a.getOidcAuthConfig(params.OrgID, params.AppID)
	if err != nil {
		return nil, fmt.Errorf("auth config for orgID %s, appID %s cannot be used for oidc: %s", params.OrgID, params.AppID, err.Error())
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

	return a.loadOidcTokensAndInfo(bodyData, oidcConfig)
}

func (a *oidcAuthImpl) refreshToken(refreshToken string, params *oidcRefreshParams) (*model.UserAuth, error) {
	oidcConfig, err := a.getOidcAuthConfig(params.OrgID, params.AppID)
	if err != nil {
		return nil, fmt.Errorf("auth config for orgID %s, appID %s cannot be used for oidc: %s", params.OrgID, params.AppID, err.Error())
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

	return a.loadOidcTokensAndInfo(bodyData, oidcConfig)
}

func (a *oidcAuthImpl) loadOidcTokensAndInfo(bodyData map[string]string, oidcConfig *oidcAuthConfig) (*model.UserAuth, error) {
	oidcToken, err := a.loadOidcTokenWithParams(bodyData, oidcConfig)
	if err != nil {
		return nil, err
	}
	if oidcToken == nil {
		return nil, errors.New("get auth token failed")
	}

	userAuth := model.UserAuth{}
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
	var ok bool
	userID := readFromClaims("user_id", &oidcConfig.Claims, &userClaims)
	if userAuth.UserID, ok = userID.(string); !ok {
		log.Printf("Failed to cast user_id %v to string\n", userID)
	}
	name := readFromClaims("name", &oidcConfig.Claims, &userClaims)
	if userAuth.Name, ok = name.(string); !ok {
		log.Printf("Failed to cast name %v to string\n", name)
	}
	email := readFromClaims("email", &oidcConfig.Claims, &userClaims)
	if userAuth.Email, ok = email.(string); !ok {
		log.Printf("Failed to cast email %v to string\n", email)
	}
	phone := readFromClaims("phone", &oidcConfig.Claims, &userClaims)
	if userAuth.Phone, ok = phone.(string); !ok {
		log.Printf("Failed to cast phone %v to string\n", phone)
	}
	exp := readFromClaims("exp", &oidcConfig.Claims, &userClaims)
	if userAuth.Exp, ok = exp.(float64); !ok {
		log.Printf("Failed to cast exp %v to string\n", exp)
	}

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
	validate := validator.New()
	err = validate.Struct(authToken)
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

func (a *oidcAuthImpl) getOidcAuthConfig(orgID string, appID string) (*oidcAuthConfig, error) {
	authConfig, err := a.auth.getAuthConfig(orgID, appID, "oidc")
	if err != nil {
		return nil, err
	}

	configBytes, err := json.Marshal(authConfig.Config)
	if err != nil {
		return nil, err
	}
	var oidcConfig oidcAuthConfig
	err = json.Unmarshal(configBytes, &oidcConfig)
	if err != nil {
		return nil, err
	}
	validate := validator.New()
	err = validate.Struct(oidcConfig)
	if err != nil {
		return nil, err
	}

	return &oidcConfig, nil
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
