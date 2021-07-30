package auth

import (
	"bytes"
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

	"github.com/coreos/go-oidc"
	"gopkg.in/go-playground/validator.v9"

	"github.com/rokmetro/auth-library/authutils"
	log "github.com/rokmetro/logging-library/loglib"
)

const (
	authTypeOidc string = "oidc"

	typeOidcAuthConfig    log.LogData = "oidc auth config"
	typeOidcCheckParams   log.LogData = "oidc check params"
	typeOidcLoginParams   log.LogData = "oidc login params"
	typeOidcRefreshParams log.LogData = "oidc refresh params"
	typeOidcToken         log.LogData = "oidc token"
)

// OIDC implementation of authType
type oidcAuthImpl struct {
	auth     *Auth
	authType string
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

type oidcLoginParams struct {
	CodeVerifier string `json:"pkce_verifier"`
	RedirectURI  string `json:"redirect_uri" validate:"required"`
}

type oidcRefreshParams struct {
	RedirectURI string `json:"redirect_uri" validate:"required"`
}

type oidcToken struct {
	IDToken      string `json:"id_token" validate:"required"`
	AccessToken  string `json:"access_token" validate:"required"`
	RefreshToken string `json:"refresh_token" validate:"required"`
	TokenType    string `json:"token_type" validate:"required"`
	ExpiresIn    int    `json:"expires_in"`
}

func (a *oidcAuthImpl) check(creds string, orgID string, appID string, params string, l *log.Log) (*model.UserAuth, error) {
	paramsMap := make(map[string]interface{})
	err := json.Unmarshal([]byte(params), &paramsMap)
	if err != nil {
		return nil, log.WrapErrorAction(log.ActionUnmarshal, "params", nil, err)
	}
	credType, ok := paramsMap["cred_type"].(string)
	if !ok {
		return nil, log.ErrorData(log.StatusInvalid, "param", &log.FieldArgs{"cred_type": paramsMap["cred_type"]})
	}

	switch credType {
	case "code":
		var loginParams oidcLoginParams
		err := json.Unmarshal([]byte(params), &loginParams)
		if err != nil {
			return nil, log.WrapErrorAction(log.ActionUnmarshal, typeOidcLoginParams, nil, err)
		}
		validate := validator.New()
		err = validate.Struct(loginParams)
		if err != nil {
			return nil, log.WrapErrorAction(log.ActionValidate, typeOidcLoginParams, nil, err)
		}
		return a.newToken(creds, orgID, appID, &loginParams, l)
	case "refresh_token":
		var refreshParams oidcRefreshParams
		err := json.Unmarshal([]byte(params), &refreshParams)
		if err != nil {
			return nil, log.WrapErrorAction(log.ActionUnmarshal, typeOidcRefreshParams, nil, err)
		}
		validate := validator.New()
		err = validate.Struct(refreshParams)
		if err != nil {
			return nil, log.WrapErrorAction(log.ActionValidate, typeOidcRefreshParams, nil, err)
		}
		return a.refreshToken(creds, orgID, appID, &refreshParams, l)
	default:
		return nil, log.ErrorData(log.StatusInvalid, "cred type", log.StringArgs(credType))
	}
}

//refresh must be implemented for OIDC auth
func (a *oidcAuthImpl) refresh(refreshToken string, orgID string, appID string, l *log.Log) (*model.UserAuth, error) {
	//TODO: Implement
	return nil, log.NewError(log.Unimplemented)
}

func (a *oidcAuthImpl) getLoginUrl(orgID string, appID string, redirectUri string, l *log.Log) (string, map[string]interface{}, error) {
	oidcConfig, err := a.getOidcAuthConfig(orgID, appID)
	if err != nil {
		return "", nil, log.WrapErrorAction(log.ActionGet, typeOidcAuthConfig, nil, err)
	}

	responseParams := map[string]interface{}{
		"redirect_uri": redirectUri,
	}

	scopes := oidcConfig.Scopes
	if len(scopes) == 0 {
		scopes = "openid profile email offline_access"
	}

	bodyData := map[string]string{
		"scope":         scopes,
		"response_type": "code",
		"redirect_uri":  redirectUri,
		"client_id":     oidcConfig.ClientID,
	}

	if len(oidcConfig.Claims) > 0 {
		claims, err := json.Marshal(oidcConfig.Claims)
		if err == nil {
			bodyData["claims"] = string(claims)
		}
	}

	if oidcConfig.UsePKCE {
		codeChallenge, codeVerifier, err := generatePkceChallenge()
		if err != nil {
			return "", nil, log.WrapErrorAction("generating", "pkce challenge", nil, err)
		}
		bodyData["code_challenge_method"] = "S256"
		bodyData["code_challenge"] = codeChallenge

		responseParams["pkce_verifier"] = codeVerifier
	}

	url, err := url.Parse(oidcConfig.Host + "/idp/profile/oidc/authorize")
	if err != nil {
		return "", nil, log.WrapErrorAction(log.ActionParse, "auth url", &log.FieldArgs{"org_id": orgID, "app_id": appID}, err)
	}
	for k, v := range bodyData {
		if len(url.RawQuery) < 1 {
			url.RawQuery += fmt.Sprintf("%s=%s", k, v)
		} else {
			url.RawQuery += fmt.Sprintf("&%s=%s", k, v)
		}
	}

	return url.String(), responseParams, nil
}

func (a *oidcAuthImpl) checkToken(idToken string, orgID string, appID string, oidcConfig *oidcAuthConfig, l *log.Log) (string, error) {
	var err error
	if oidcConfig == nil {
		oidcConfig, err = a.getOidcAuthConfig(orgID, appID)
		if err != nil {
			return "", log.WrapErrorAction(log.ActionGet, typeOidcAuthConfig, nil, err)
		}
	}

	oidcProvider := oidcConfig.Host
	oidcClientID := oidcConfig.ClientID

	// Validate the token
	provider, err := oidc.NewProvider(context.Background(), oidcProvider)
	if err != nil {
		return "", log.WrapErrorAction(log.ActionInitialize, "oidc provider", nil, err)
	}
	tokenVerifier := provider.Verifier(&oidc.Config{ClientID: oidcClientID})
	verifiedToken, err := tokenVerifier.Verify(context.Background(), idToken)
	if err != nil {
		return "", log.WrapErrorAction(log.ActionValidate, log.TypeToken, nil, err)
	}

	var rawClaims map[string]interface{}
	if err := verifiedToken.Claims(&rawClaims); err != nil {
		return "", log.WrapErrorAction(log.ActionUnmarshal, log.TypeClaim, nil, err)
	}

	sub, ok := rawClaims["sub"].(string)
	if !ok {
		return "", log.ErrorData(log.StatusInvalid, log.TypeClaim, &log.FieldArgs{"sub": rawClaims["sub"]})
	}

	return sub, nil
}

func (a *oidcAuthImpl) newToken(code string, orgID string, appID string, params *oidcLoginParams, l *log.Log) (*model.UserAuth, error) {
	oidcConfig, err := a.getOidcAuthConfig(orgID, appID)
	if err != nil {
		return nil, log.WrapErrorAction(log.ActionGet, typeOidcAuthConfig, nil, err)
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

	return a.loadOidcTokensAndInfo(bodyData, oidcConfig, orgID, appID, l)
}

func (a *oidcAuthImpl) refreshToken(refreshToken string, orgID string, appID string, params *oidcRefreshParams, l *log.Log) (*model.UserAuth, error) {
	oidcConfig, err := a.getOidcAuthConfig(orgID, appID)
	if err != nil {
		return nil, log.WrapErrorAction(log.ActionGet, typeOidcAuthConfig, nil, err)
	}
	if !oidcConfig.UseRefresh {
		return nil, log.NewErrorf("refresh tokens not enabled for org_id=%s, app_id=%s", orgID, appID)
	}

	bodyData := map[string]string{
		"refresh_token": refreshToken,
		"grant_type":    "refresh_token",
		"redirect_uri":  params.RedirectURI,
		"client_id":     oidcConfig.ClientID,
	}

	return a.loadOidcTokensAndInfo(bodyData, oidcConfig, orgID, appID, l)
}

func (a *oidcAuthImpl) loadOidcTokensAndInfo(bodyData map[string]string, oidcConfig *oidcAuthConfig, orgID string, appID string, l *log.Log) (*model.UserAuth, error) {
	oidcToken, err := a.loadOidcTokenWithParams(bodyData, oidcConfig)
	if err != nil {
		return nil, log.WrapErrorAction(log.ActionGet, typeOidcToken, nil, err)
	}

	userAuth := model.UserAuth{}
	sub, err := a.checkToken(oidcToken.IDToken, orgID, appID, oidcConfig, l)
	if err != nil {
		return nil, log.WrapErrorAction(log.ActionValidate, typeOidcToken, nil, err)
	}
	userAuth.RefreshToken = oidcToken.RefreshToken

	userInfo, err := a.loadOidcUserInfo(oidcToken, oidcConfig.Host+"/idp/profile/oidc/userinfo")
	if err != nil {
		return nil, log.WrapErrorAction(log.ActionGet, "user info", nil, err)
	}

	var userClaims map[string]interface{}
	err = json.Unmarshal(userInfo, &userClaims)
	if err != nil {
		return nil, log.WrapErrorAction(log.ActionUnmarshal, "user info", nil, err)
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
	if expFloat, ok := exp.(float64); !ok {
		l.LogAction(log.Warn, log.StatusError, log.ActionCast, "float64", &log.FieldArgs{"exp": exp})
	} else {
		expInt := int64(expFloat)
		userAuth.Exp = &expInt
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
		return nil, log.WrapErrorAction(log.ActionMarshal, "params", nil, err)
	}

	client := &http.Client{}
	req, err := http.NewRequest("POST", tokenURI, bytes.NewReader(jsonData))
	if err != nil {
		return nil, log.WrapErrorAction(log.ActionCreate, log.TypeRequest, nil, err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, log.WrapErrorAction(log.ActionSend, log.TypeRequest, nil, err)
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, log.WrapErrorAction(log.ActionRead, log.TypeRequestBody, nil, err)
	}
	if resp.StatusCode != 200 {
		return nil, log.ErrorData(log.StatusInvalid, log.TypeResponse, &log.FieldArgs{"status_code": resp.StatusCode, "error": string(body)})
	}

	var authToken oidcToken
	err = json.Unmarshal(body, &authToken)
	if err != nil {
		return nil, log.WrapErrorAction(log.ActionUnmarshal, log.TypeToken, nil, err)
	}
	validate := validator.New()
	err = validate.Struct(authToken)
	if err != nil {
		return nil, log.WrapErrorAction(log.ActionValidate, log.TypeToken, nil, err)
	}

	return &authToken, nil
}

func (a *oidcAuthImpl) loadOidcUserInfo(token *oidcToken, url string) ([]byte, error) {
	if len(token.AccessToken) == 0 {
		return nil, log.ErrorData(log.StatusMissing, "access token", nil)
	}
	if len(token.TokenType) == 0 {
		return nil, log.ErrorData(log.StatusMissing, "token type", nil)
	}
	if len(url) == 0 {
		return nil, log.ErrorData(log.StatusMissing, "user info url", nil)
	}

	client := &http.Client{}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, log.WrapErrorAction(log.ActionCreate, log.TypeRequest, nil, err)
	}
	req.Header.Set("Authorization", fmt.Sprintf("%s %s", token.TokenType, token.AccessToken))

	resp, err := client.Do(req)
	if err != nil {
		return nil, log.WrapErrorAction(log.ActionSend, log.TypeRequest, nil, err)
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, log.WrapErrorAction(log.ActionRead, log.TypeResponse, nil, err)
	}
	if resp.StatusCode != 200 {
		return nil, log.ErrorData(log.StatusInvalid, log.TypeResponse, &log.FieldArgs{"status_code": resp.StatusCode, "error": string(body)})
	}
	if len(body) == 0 {
		return nil, log.ErrorData(log.StatusMissing, log.TypeResponseBody, nil)
	}

	return body, nil
}

func (a *oidcAuthImpl) getOidcAuthConfig(orgID string, appID string) (*oidcAuthConfig, error) {
	errFields := &log.FieldArgs{"org_id": orgID, "app_id": appID, "auth_type": a.authType}

	authConfig, err := a.auth.getAuthConfig(orgID, appID, a.authType)
	if err != nil {
		return nil, log.WrapErrorAction(log.ActionFind, model.TypeAuthConfig, errFields, err)
	}

	var oidcConfig oidcAuthConfig
	err = json.Unmarshal(authConfig.Config, &oidcConfig)
	if err != nil {
		return nil, log.WrapErrorAction(log.ActionUnmarshal, model.TypeAuthConfig, errFields, err)
	}

	validate := validator.New()
	err = validate.Struct(oidcConfig)
	if err != nil {
		return nil, log.WrapErrorAction(log.ActionValidate, model.TypeAuthConfig, errFields, err)
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

//generatePkceChallenge generates and returns a PKCE code challenge and verifier
func generatePkceChallenge() (string, string, error) {
	codeVerifier, err := utils.GenerateRandomString(50)
	if err != nil {
		return "", "", log.WrapErrorAction("generating", "code verifier", nil, err)
	}

	codeChallengeBytes, err := authutils.HashSha256([]byte(codeVerifier))
	if err != nil {
		return "", "", log.WrapErrorAction("hashing", "code verifier", nil, err)
	}
	codeChallenge := base64.URLEncoding.EncodeToString(codeChallengeBytes)

	return codeChallenge, codeVerifier, nil
}

//initOidcAuth initializes and registers a new OIDC auth instance
func initOidcAuth(auth *Auth) (*oidcAuthImpl, error) {
	oidc := &oidcAuthImpl{auth: auth, authType: authTypeOidc}

	err := auth.registerAuthType(oidc.authType, oidc)
	if err != nil {
		return nil, log.WrapErrorAction(log.ActionRegister, typeAuthType, nil, err)
	}

	return oidc, nil
}
