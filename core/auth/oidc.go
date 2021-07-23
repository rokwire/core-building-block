package auth

import (
	"bytes"
	"context"
	"core-building-block/core/model"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/coreos/go-oidc"
	"gopkg.in/go-playground/validator.v9"

	log "github.com/rokmetro/logging-library/loglib"
)

const (
	typeOidcAuthConfig    log.LogData = "oidc auth config"
	typeOidcMobileParams  log.LogData = "oidc mobile params"
	typeOidcCheckParams   log.LogData = "oidc check params"
	typeOidcLoginParams   log.LogData = "oidc login params"
	typeOidcRefreshParams log.LogData = "oidc refresh params"
	typeOidcToken         log.LogData = "oidc token"
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

func (a *oidcAuthImpl) check(creds string, params string, l *log.Log) (*model.UserAuth, error) {
	paramsMap := make(map[string]interface{})
	err := json.Unmarshal([]byte(params), &paramsMap)
	if err != nil {
		return nil, log.WrapActionError(log.ActionUnmarshal, "params", nil, err)
	}
	credType, ok := paramsMap["cred_type"].(string)
	if !ok {
		return nil, log.DataError(log.StatusInvalid, "param", &log.FieldArgs{"cred_type": paramsMap["cred_type"]})
	}

	switch credType {
	case "code":
		var loginParams oidcLoginParams
		err := json.Unmarshal([]byte(params), &loginParams)
		if err != nil {
			return nil, log.WrapActionError(log.ActionUnmarshal, typeOidcLoginParams, nil, err)
		}
		validate := validator.New()
		err = validate.Struct(loginParams)
		if err != nil {
			return nil, log.WrapActionError(log.ActionValidate, typeOidcLoginParams, nil, err)
		}
		return a.newToken(creds, &loginParams, l)
	case "refresh_token":
		var refreshParams oidcRefreshParams
		err := json.Unmarshal([]byte(params), &refreshParams)
		if err != nil {
			return nil, log.WrapActionError(log.ActionUnmarshal, typeOidcRefreshParams, nil, err)
		}
		validate := validator.New()
		err = validate.Struct(refreshParams)
		if err != nil {
			return nil, log.WrapActionError(log.ActionValidate, typeOidcRefreshParams, nil, err)
		}
		return a.refreshToken(creds, &refreshParams, l)
	default:
		return nil, log.DataError(log.StatusInvalid, "cred type", log.StringArgs(credType))
	}
}

func (a *oidcAuthImpl) verify(id string, verification string, l *log.Log) error {
	return nil
}

func (a *oidcAuthImpl) mobileLoginURL(params string, l *log.Log) (string, error) {
	var mobileParams oidcMobileParams
	err := json.Unmarshal([]byte(params), &mobileParams)
	if err != nil {
		return "", log.WrapActionError(log.ActionUnmarshal, typeOidcMobileParams, nil, err)
	}
	validate := validator.New()
	err = validate.Struct(mobileParams)
	if err != nil {
		return "", log.WrapActionError(log.ActionValidate, typeOidcMobileParams, nil, err)
	}

	oidcConfig, err := a.getOidcAuthConfig(mobileParams.OrgID, mobileParams.AppID)
	if err != nil {
		return "", log.WrapActionError(log.ActionGet, typeOidcAuthConfig, nil, err)
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
		return "", log.WrapActionError(log.ActionParse, "auth url", &log.FieldArgs{"org_id": mobileParams.OrgID, "app_id": mobileParams.AppID}, err)
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

func (a *oidcAuthImpl) checkToken(idToken string, params *oidcCheckParams, oidcConfig *oidcAuthConfig, l *log.Log) (string, error) {
	var err error
	if oidcConfig == nil {
		oidcConfig, err = a.getOidcAuthConfig(params.OrgID, params.AppID)
		if err != nil {
			return "", log.WrapActionError(log.ActionGet, typeOidcAuthConfig, nil, err)
		}
	}

	oidcProvider := oidcConfig.Host
	oidcClientID := oidcConfig.ClientID

	// Validate the token
	provider, err := oidc.NewProvider(context.Background(), oidcProvider)
	if err != nil {
		return "", log.WrapActionError(log.ActionInitialize, "oidc provider", nil, err)
	}
	tokenVerifier := provider.Verifier(&oidc.Config{ClientID: oidcClientID})
	verifiedToken, err := tokenVerifier.Verify(context.Background(), idToken)
	if err != nil {
		return "", log.WrapActionError(log.ActionValidate, log.TypeToken, nil, err)
	}

	var rawClaims map[string]interface{}
	if err := verifiedToken.Claims(&rawClaims); err != nil {
		return "", log.WrapActionError(log.ActionUnmarshal, log.TypeClaim, nil, err)
	}

	sub, ok := rawClaims["sub"].(string)
	if !ok {
		return "", log.DataError(log.StatusInvalid, log.TypeClaim, &log.FieldArgs{"sub": rawClaims["sub"]})
	}

	return sub, nil
}

func (a *oidcAuthImpl) newToken(code string, params *oidcLoginParams, l *log.Log) (*model.UserAuth, error) {
	oidcConfig, err := a.getOidcAuthConfig(params.OrgID, params.AppID)
	if err != nil {
		return nil, log.WrapActionError(log.ActionGet, typeOidcAuthConfig, nil, err)
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

	return a.loadOidcTokensAndInfo(bodyData, oidcConfig, l)
}

func (a *oidcAuthImpl) refreshToken(refreshToken string, params *oidcRefreshParams, l *log.Log) (*model.UserAuth, error) {
	oidcConfig, err := a.getOidcAuthConfig(params.OrgID, params.AppID)
	if err != nil {
		return nil, log.WrapActionError(log.ActionGet, typeOidcAuthConfig, nil, err)
	}
	if !oidcConfig.UseRefresh {
		return nil, log.NewErrorf("refresh tokens not enabled for org_id=%s, app_id=%s", params.OrgID, params.AppID)
	}

	bodyData := map[string]string{
		"refresh_token": refreshToken,
		"grant_type":    "refresh_token",
		"redirect_uri":  params.RedirectURI,
		"client_id":     oidcConfig.ClientID,
	}

	return a.loadOidcTokensAndInfo(bodyData, oidcConfig, l)
}

func (a *oidcAuthImpl) loadOidcTokensAndInfo(bodyData map[string]string, oidcConfig *oidcAuthConfig, l *log.Log) (*model.UserAuth, error) {
	oidcToken, err := a.loadOidcTokenWithParams(bodyData, oidcConfig)
	if err != nil {
		return nil, log.WrapActionError(log.ActionGet, typeOidcToken, nil, err)
	}

	userAuth := model.UserAuth{}
	sub, err := a.checkToken(oidcToken.IDToken, nil, oidcConfig, l)
	if err != nil {
		return nil, log.WrapActionError(log.ActionValidate, typeOidcToken, nil, err)
	}
	userAuth.RefreshToken = oidcToken.RefreshToken

	userInfo, err := a.loadOidcUserInfo(oidcToken, oidcConfig.Host+"/idp/profile/oidc/userinfo")
	if err != nil {
		return nil, log.WrapActionError(log.ActionGet, "user info", nil, err)
	}

	var userClaims map[string]interface{}
	err = json.Unmarshal(userInfo, &userClaims)
	if err != nil {
		return nil, log.WrapActionError(log.ActionUnmarshal, "user info", nil, err)
	}

	userAuth.Sub = userClaims["sub"].(string)
	if userAuth.Sub != sub {
		return nil, log.NewErrorf("mismatching user info sub %s and id token sub %s", userAuth.Sub, sub)
	}
	var ok bool
	userID := readFromClaims("user_id", &oidcConfig.Claims, &userClaims)
	if userAuth.UserID, ok = userID.(string); !ok {
		l.LogAction(log.Warn, log.StatusError, log.ActionCast, log.TypeString, &log.FieldArgs{"user_id": userID})
	}
	name := readFromClaims("name", &oidcConfig.Claims, &userClaims)
	if userAuth.Name, ok = name.(string); !ok {
		l.LogAction(log.Warn, log.StatusError, log.ActionCast, log.TypeString, &log.FieldArgs{"name": name})
	}
	email := readFromClaims("email", &oidcConfig.Claims, &userClaims)
	if userAuth.Email, ok = email.(string); !ok {
		l.LogAction(log.Warn, log.StatusError, log.ActionCast, log.TypeString, &log.FieldArgs{"email": email})
	}
	phone := readFromClaims("phone", &oidcConfig.Claims, &userClaims)
	if userAuth.Phone, ok = phone.(string); !ok {
		l.LogAction(log.Warn, log.StatusError, log.ActionCast, log.TypeString, &log.FieldArgs{"phone": phone})
	}
	exp := readFromClaims("exp", &oidcConfig.Claims, &userClaims)
	if userAuth.Exp, ok = exp.(float64); !ok {
		l.LogAction(log.Warn, log.StatusError, log.ActionCast, "float64", &log.FieldArgs{"exp": exp})
	}

	var userPhoto []byte
	if photoURL, ok := readFromClaims("picture", &oidcConfig.Claims, &userClaims).(string); ok {
		userPhoto, err = a.loadOidcUserInfo(oidcToken, photoURL)
		if err != nil {
			l.WarnAction(log.ActionGet, "photo", err)
		}
	}
	userAuth.Picture = userPhoto

	return &userAuth, nil
}

func (a *oidcAuthImpl) loadOidcTokenWithParams(params map[string]string, oidcConfig *oidcAuthConfig) (*oidcToken, error) {
	tokenURI := ""
	oidcTokenURL := oidcConfig.Host + "/idp/profile/oidc/token"
	if strings.Contains(oidcTokenURL, "{shibboleth_client_id}") {
		tokenURI = strings.ReplaceAll(oidcTokenURL, "{shibboleth_client_id}", oidcConfig.ClientID)
		tokenURI = strings.ReplaceAll(tokenURI, "{shibboleth_client_secret}", oidcConfig.ClientSecret)
	} else if len(oidcConfig.ClientSecret) > 0 {
		tokenURI = oidcTokenURL
		params["client_secret"] = oidcConfig.ClientSecret
	} else {
		tokenURI = oidcTokenURL
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
		return nil, log.WrapActionError(log.ActionMarshal, "params", nil, err)
	}

	client := &http.Client{}
	req, err := http.NewRequest("POST", tokenURI, bytes.NewReader(jsonData))
	if err != nil {
		return nil, log.WrapActionError(log.ActionCreate, log.TypeRequest, nil, err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, log.WrapActionError(log.ActionSend, log.TypeRequest, nil, err)
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, log.WrapActionError(log.ActionRead, log.TypeRequestBody, nil, err)
	}
	if resp.StatusCode != 200 {
		return nil, log.DataError(log.StatusInvalid, log.TypeResponse, &log.FieldArgs{"status_code": resp.StatusCode, "error": string(body)})
	}

	var authToken oidcToken
	err = json.Unmarshal(body, &authToken)
	if err != nil {
		return nil, log.WrapActionError(log.ActionUnmarshal, log.TypeToken, nil, err)
	}
	validate := validator.New()
	err = validate.Struct(authToken)
	if err != nil {
		return nil, log.WrapActionError(log.ActionValidate, log.TypeToken, nil, err)
	}

	return &authToken, nil
}

func (a *oidcAuthImpl) loadOidcUserInfo(token *oidcToken, url string) ([]byte, error) {
	if len(token.AccessToken) == 0 {
		return nil, log.DataError(log.StatusMissing, "access token", nil)
	}
	if len(token.TokenType) == 0 {
		return nil, log.DataError(log.StatusMissing, "token type", nil)
	}
	if len(url) == 0 {
		return nil, log.DataError(log.StatusMissing, "user info url", nil)
	}

	client := &http.Client{}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, log.WrapActionError(log.ActionCreate, log.TypeRequest, nil, err)
	}
	req.Header.Set("Authorization", fmt.Sprintf("%s %s", token.TokenType, token.AccessToken))

	resp, err := client.Do(req)
	if err != nil {
		return nil, log.WrapActionError(log.ActionSend, log.TypeRequest, nil, err)
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, log.WrapActionError(log.ActionRead, log.TypeResponse, nil, err)
	}
	if resp.StatusCode != 200 {
		return nil, log.DataError(log.StatusInvalid, log.TypeResponse, &log.FieldArgs{"status_code": resp.StatusCode, "error": string(body)})
	}
	if len(body) == 0 {
		return nil, log.DataError(log.StatusMissing, log.TypeResponseBody, nil)
	}

	return body, nil
}

func (a *oidcAuthImpl) getOidcAuthConfig(orgID string, appID string) (*oidcAuthConfig, error) {
	errFields := &log.FieldArgs{"org_id": orgID, "app_id": appID, "auth_type": "oidc"}

	authConfig, err := a.auth.getAuthConfig(orgID, appID, "oidc")
	if err != nil {
		return nil, log.WrapActionError(log.ActionFind, model.TypeAuthConfig, errFields, err)
	}

	var oidcConfig oidcAuthConfig
	err = json.Unmarshal(authConfig.Config, &oidcConfig)
	if err != nil {
		return nil, log.WrapActionError(log.ActionUnmarshal, model.TypeAuthConfig, errFields, err)
	}

	validate := validator.New()
	err = validate.Struct(oidcConfig)
	if err != nil {
		return nil, log.WrapActionError(log.ActionValidate, model.TypeAuthConfig, errFields, err)
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
		return nil, log.WrapActionError(log.ActionRegister, typeAuthType, nil, err)
	}

	return oidc, nil
}
