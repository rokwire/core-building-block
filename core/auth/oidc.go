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
	"github.com/rokwire/core-auth-library-go/authutils"
	"github.com/rokwire/logging-library-go/errors"
	"github.com/rokwire/logging-library-go/logs"
	"github.com/rokwire/logging-library-go/logutils"
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

type oidcCreds struct {
	Sub         string `bson:"sub"`
	IDPHost     string `bson:"idp_host"`
	IDPClientID string `bson:"idp_client_id"`
}

func (o *oidcCreds) toMap() map[string]interface{} {
	if o == nil {
		return map[string]interface{}{}
	}

	return map[string]interface{}{
		"sub":           o.Sub,
		"idp_host":      o.IDPHost,
		"idp_client_id": o.IDPClientID,
	}
}

func oidcCredsFromMap(val map[string]interface{}) (*oidcCreds, error) {
	sub, ok := val["sub"].(string)
	if !ok {
		return nil, errors.ErrorData(logutils.StatusMissing, "sub", nil)
	}

	idpHost, ok := val["idp_host"].(string)
	if !ok {
		return nil, errors.ErrorData(logutils.StatusMissing, "idp host", nil)
	}

	idpClientID, ok := val["idp_client_id"].(string)
	if !ok {
		return nil, errors.ErrorData(logutils.StatusMissing, "idp client id", nil)
	}

	return &oidcCreds{Sub: sub, IDPHost: idpHost, IDPClientID: idpClientID}, nil
}

type oidcRefreshParams struct {
	RefreshToken string `json:"refresh_token" bson:"refresh_token" validate:"required"`
	RedirectURI  string `json:"redirect_uri" bson:"redirect_uri" validate:"required"`
}

func (o *oidcRefreshParams) toMap() map[string]interface{} {
	if o == nil {
		return map[string]interface{}{}
	}

	return map[string]interface{}{
		"refresh_token": o.RefreshToken,
		"redirect_uri":  o.RedirectURI,
	}
}

func oidcRefreshParamsFromMap(val map[string]interface{}) (*oidcRefreshParams, error) {
	oidcToken, ok := val["oidc_token"].(map[string]interface{})
	if !ok {
		return nil, errors.ErrorData(logutils.StatusMissing, "refresh token", nil)
	}

	refreshToken := oidcToken["refresh_token"].(string)
	redirectURI := oidcToken["redirect_uri"].(string)

	return &oidcRefreshParams{RefreshToken: refreshToken, RedirectURI: redirectURI}, nil
}

func (a *oidcAuthImpl) externalLogin(authType model.AuthType, appType model.ApplicationType, appOrg model.ApplicationOrganization, creds string, params string, l *logs.Log) (*model.ExternalSystemUser, map[string]interface{}, error) {
	var loginParams oidcLoginParams
	err := json.Unmarshal([]byte(params), &loginParams)
	if err != nil {
		return nil, nil, errors.WrapErrorAction(logutils.ActionUnmarshal, typeOidcLoginParams, nil, err)
	}
	validate := validator.New()
	err = validate.Struct(loginParams)
	if err != nil {
		return nil, nil, errors.WrapErrorAction(logutils.ActionValidate, typeOidcLoginParams, nil, err)
	}

	oidcConfig, err := a.getOidcAuthConfig(authType, appType)
	if err != nil {
		return nil, nil, errors.WrapErrorAction(logutils.ActionGet, typeOidcAuthConfig, nil, err)
	}

	parsedCreds, err := url.Parse(strings.ReplaceAll(creds, `"`, ""))
	if err != nil {
		return nil, nil, errors.WrapErrorAction(logutils.ActionParse, "oidc login creds", nil, err)
	}

	externalUser, parameters, err := a.newToken(parsedCreds.Query().Get("code"), authType, appType, appOrg, &loginParams, oidcConfig, l)
	if err != nil {
		return nil, nil, err
	}

	return externalUser, parameters, nil
}

func (a *oidcAuthImpl) verify(id string, verification string, l *logs.Log) error {
	return errors.New(logutils.Unimplemented)
}

//refresh must be implemented for OIDC auth
func (a *oidcAuthImpl) refresh(params map[string]interface{}, authType model.AuthType, appType model.ApplicationType, appOrg model.ApplicationOrganization, l *logs.Log) (map[string]interface{}, error) {
	refreshParams, err := oidcRefreshParamsFromMap(params)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionParse, typeAuthRefreshParams, nil, err)
	}

	oidcConfig, err := a.getOidcAuthConfig(authType, appType)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionGet, typeOidcAuthConfig, nil, err)
	}

	result, err := a.refreshToken(authType, appType, appOrg, refreshParams, oidcConfig, l)
	if err != nil {
		return nil, err
	}

	return result, nil
}

func (a *oidcAuthImpl) getLoginURL(authType model.AuthType, appType model.ApplicationType, appOrg model.ApplicationOrganization, redirectURI string, l *logs.Log) (string, map[string]interface{}, error) {
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
			return "", nil, errors.WrapErrorAction("generating", "pkce challenge", nil, err)
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

func (a *oidcAuthImpl) newToken(code string, authType model.AuthType, appType model.ApplicationType, appOrg model.ApplicationOrganization, params *oidcLoginParams, oidcConfig *oidcAuthConfig, l *logs.Log) (*model.ExternalSystemUser, map[string]interface{}, error) {
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
	params *oidcRefreshParams, oidcConfig *oidcAuthConfig, l *logs.Log) (map[string]interface{}, error) {
	if !oidcConfig.UseRefresh {
		return nil, errors.Newf("refresh tokens not enabled for org_id=%s, app_id=%s",
			appOrg.Organization.ID, appOrg.Application.ID)
	}

	bodyData := map[string]string{
		"refresh_token": params.RefreshToken,
		"grant_type":    "refresh_token",
		"redirect_uri":  params.RedirectURI,
		"client_id":     oidcConfig.ClientID,
	}

	_, result, err := a.loadOidcTokensAndInfo(bodyData, oidcConfig, authType, appType, appOrg, params.RedirectURI, l)
	return result, err
}

func (a *oidcAuthImpl) loadOidcTokensAndInfo(bodyData map[string]string, oidcConfig *oidcAuthConfig, authType model.AuthType, appType model.ApplicationType,
	appOrg model.ApplicationOrganization, redirectURI string, l *logs.Log) (*model.ExternalSystemUser, map[string]interface{}, error) {
	token, err := a.loadOidcTokenWithParams(bodyData, oidcConfig)
	if err != nil {
		return nil, nil, errors.WrapErrorAction(logutils.ActionGet, typeOidcToken, nil, err)
	}

	sub, err := a.checkToken(token.IDToken, authType, appType, oidcConfig, l)
	if err != nil {
		return nil, nil, errors.WrapErrorAction(logutils.ActionValidate, typeOidcToken, nil, err)
	}

	userInfoURL := oidcConfig.Host + "/idp/profile/oidc/userinfo"
	if len(oidcConfig.UserInfoURL) > 0 {
		userInfoURL = oidcConfig.UserInfoURL
	}
	userInfo, err := a.loadOidcUserInfo(token, userInfoURL)
	if err != nil {
		return nil, nil, errors.WrapErrorAction(logutils.ActionGet, "user info", nil, err)
	}

	var userClaims map[string]interface{}
	err = json.Unmarshal(userInfo, &userClaims)
	if err != nil {
		return nil, nil, errors.WrapErrorAction(logutils.ActionUnmarshal, "user info", nil, err)
	}

	userClaimsSub, _ := userClaims["sub"].(string)
	if userClaimsSub != sub {
		return nil, nil, errors.Newf("mismatching user info sub %s and id token sub %s", userClaimsSub, sub)
	}

	identityProviderID, _ := authType.Params["identity_provider"].(string)
	identityProviderSetting := appOrg.FindIdentityProviderSetting(identityProviderID)

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

	externalUser := model.ExternalSystemUser{Identifier: identifier, FirstName: firstName, MiddleName: middleName, LastName: lastName,
		Email: email, Groups: groups, SystemSpecific: systemSpecific}

	oidcParams := map[string]interface{}{}
	oidcParams["id_token"] = token.IDToken
	oidcParams["access_token"] = token.AccessToken
	oidcParams["refresh_token"] = token.RefreshToken
	oidcParams["token_type"] = token.TokenType
	oidcParams["redirect_uri"] = redirectURI

	params := map[string]interface{}{}
	params["oidc_token"] = oidcParams
	return &externalUser, params, nil
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

func (a *oidcAuthImpl) validateUser(userAuth *model.UserAuth, credentials map[string]interface{}) (bool, error) {
	creds, err := oidcCredsFromMap(credentials)
	if err != nil {
		return false, err
	}

	if userAuth.Sub != creds.Sub {
		return false, errors.ErrorData(logutils.StatusInvalid, model.TypeUserAuth, logutils.StringArgs(userAuth.UserID))
	}
	return true, nil
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
		return "", "", errors.WrapErrorAction("generating", "code verifier", nil, err)
	}

	codeChallengeBytes, err := authutils.HashSha256([]byte(codeVerifier))
	if err != nil {
		return "", "", errors.WrapErrorAction("hashing", "code verifier", nil, err)
	}
	codeChallenge := base64.URLEncoding.EncodeToString(codeChallengeBytes)

	return codeChallenge, codeVerifier, nil
}

//initOidcAuth initializes and registers a new OIDC auth instance
func initOidcAuth(auth *Auth) (*oidcAuthImpl, error) {
	oidc := &oidcAuthImpl{auth: auth, authType: AuthTypeOidc}

	err := auth.registerExternalAuthType(oidc.authType, oidc)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionRegister, typeAuthType, nil, err)
	}

	return oidc, nil
}
