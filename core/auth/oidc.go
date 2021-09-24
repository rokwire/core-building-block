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
	"github.com/rokmetro/auth-library/authutils"
	"github.com/rokmetro/logging-library/errors"
	"github.com/rokmetro/logging-library/logs"
	"github.com/rokmetro/logging-library/logutils"
)

const (
	authTypeOidc string = "oidc"

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

type oidcResponseParams struct {
	OIDCToken oidcTokenResponseParams `json:"oidc_token"`
}

type oidcTokenResponseParams struct {
	IDToken     string `json:"id_token"`
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
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
	refreshToken, ok := val["refresh_token"].(string)
	if !ok {
		return nil, errors.ErrorData(logutils.StatusMissing, "refresh token", nil)
	}

	redirectURI, ok := val["redirect_uri"].(string)
	if !ok {
		return nil, errors.ErrorData(logutils.StatusMissing, "redirect uri", nil)
	}

	return &oidcRefreshParams{RefreshToken: refreshToken, RedirectURI: redirectURI}, nil
}

func (a *oidcAuthImpl) externalLogin(authType model.AuthType, appType model.ApplicationType, appOrg model.ApplicationOrganization, creds string, params string, l *logs.Log) (*model.ExternalSystemUser, interface{}, error) {
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
func (a *oidcAuthImpl) userExist(externalUserIdentifier string, authType model.AuthType, appType model.ApplicationType, appOrg model.ApplicationOrganization, l *logs.Log) (*model.Account, error) {
	appID := appOrg.Application.ID
	orgID := appOrg.Organization.ID
	authTypeID := authType.ID
	identifier := externalUserIdentifier

	//FindAccount(appID string, orgID string, authTypeID string, accountAuthTypeIdentifier string) (*model.Account, error)
	account, err := a.auth.storage.FindAccount(appID, orgID, authTypeID, identifier)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeAccount, nil, err) //TODO add args..
	}
	return account, nil
}

//refresh must be implemented for OIDC auth
func (a *oidcAuthImpl) refresh(params map[string]interface{}, orgID string, appID string, l *logs.Log) (*model.UserAuth, error) {
	return nil, nil
	/*refreshParams, err := oidcRefreshParamsFromMap(params)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionParse, typeAuthRefreshParams, nil, err)
	}

	oidcConfig, err := a.getOidcAuthConfig(orgID, appID)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionGet, typeOidcAuthConfig, nil, err)
	}

	userAuth, err := a.refreshToken(orgID, appID, refreshParams, oidcConfig, l)
	if err != nil {
		return nil, err
	}

	return userAuth, nil */
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

func (a *oidcAuthImpl) newToken(code string, authType model.AuthType, appType model.ApplicationType, appOrg model.ApplicationOrganization, params *oidcLoginParams, oidcConfig *oidcAuthConfig, l *logs.Log) (*model.ExternalSystemUser, interface{}, error) {
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

func (a *oidcAuthImpl) refreshToken(orgID string, appID string, params *oidcRefreshParams, oidcConfig *oidcAuthConfig, l *logs.Log) (*model.UserAuth, error) {
	/*	if !oidcConfig.UseRefresh {
			return nil, errors.Newf("refresh tokens not enabled for org_id=%s, app_id=%s", orgID, appID)
		}

		bodyData := map[string]string{
			"refresh_token": params.RefreshToken,
			"grant_type":    "refresh_token",
			"redirect_uri":  params.RedirectURI,
			"client_id":     oidcConfig.ClientID,
		}

		return a.loadOidcTokensAndInfo(bodyData, oidcConfig, orgID, appID, params.RedirectURI, l) */
	return nil, nil
}

func (a *oidcAuthImpl) loadOidcTokensAndInfo(bodyData map[string]string, oidcConfig *oidcAuthConfig, authType model.AuthType, appType model.ApplicationType,
	appOrg model.ApplicationOrganization, redirectURI string, l *logs.Log) (*model.ExternalSystemUser, interface{}, error) {
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

	tokenResponseParams := oidcTokenResponseParams{IDToken: token.IDToken, AccessToken: token.AccessToken, TokenType: token.TokenType}

	return &externalUser, tokenResponseParams, nil
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
	oidc := &oidcAuthImpl{auth: auth, authType: authTypeOidc}

	err := auth.registerExternalAuthType(oidc.authType, oidc)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionRegister, typeAuthType, nil, err)
	}

	return oidc, nil
}
