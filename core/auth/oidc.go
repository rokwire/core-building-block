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

//dynamic claimsMap

var uidClaimTag string = ""
var nameClaimTag string = ""
var firstNameClaimTag string = ""
var lastNameClaimTag string = ""
var emailClaimTag string = ""
var phoneClaimTag string = ""
var groupsClaimTag string = ""
var populationsClaimTag string = ""

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
	Web    bool   `json:"web"`
	Domain string `json:"domain"`
}

type oidcLoginParams struct {
	Web          bool   `json:"web"`
	Domain       string `json:"domain"`
	Code         string `json:"code"`
	CodeVerifier string `json:"pkce_verifier"`
	RedirectURI  string `json:"redirect_uri"` // endpoint on core BB?
}

type oidcRefreshParams struct {
	Web         string `json:"web"`
	Domain      string `json:"domain"`
	RedirectURI string `json:"redirect_uri"` // endpoint on core BB?
}

func (a *oidcAuthImpl) login(creds string, params string) (map[string]interface{}, error) {
	// use credType argument to function instead?
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
		return a.checkToken(creds, checkParams)
	case "code":
		var loginParams oidcLoginParams
		err := json.Unmarshal([]byte(params), &loginParams)
		if err != nil {
			return nil, err
		}
		return a.newToken(creds, loginParams)
	case "refresh_token":
		var refreshParams oidcRefreshParams
		err := json.Unmarshal([]byte(params), &refreshParams)
		if err != nil {
			return nil, err
		}
		return a.refreshToken(creds, refreshParams)
	default:
		return nil, errors.New("unimplemented cred_type")
	}
}

func (a *oidcAuthImpl) checkToken(idToken string, params oidcCheckParams) (map[string]interface{}, error) {
	authInfo := a.auth.getAuthInfo(params.Domain)

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

	// var claims Claims
	// uidClaimTag = authInfo.Claims["uid"]
	// nameClaimTag = authInfo.Claims["name"]
	// firstNameClaimTag = authInfo.Claims["firstname"]
	// lastNameClaimTag = authInfo.Claims["lastname"]
	// emailClaimTag = authInfo.Claims["email"]
	// phoneClaimTag = authInfo.Claims["phone"]
	// groupsClaimTag = authInfo.Claims["groups"]
	// populationsClaimTag = authInfo.Claims["populations"]
	// log.Printf("AuthInfo Claims: %v", authInfo.Claims)

	// if err := idToken.Claims(&claims); err != nil {
	// 	log.Printf("error getting claims from token - %s\n", err)
	// 	return nil, err
	// }

	// populationsString := ""
	// inRequiredPopulation := (authInfo.RequiredPopulation == "")
	// if populations, ok := claims.Populations.([]interface{}) ok {
	// 	for _, populationInterface := range populations {
	// 		if population, ok := populationInterface.(string) ok {
	// 			if authInfo.RequiredPopulation == population {
	// 				inRequiredPopulation = true
	// 			}

	// 			if authInfo.Populations != nil {
	// 				if populationString, ok := authInfo.Populations[population] ok {
	// 					if populationsString != "" {
	// 						populationsString += ","
	// 					}
	// 					populationsString += populationString
	// 				}
	// 			}
	// 		}
	// 	}
	// }

	// if !inRequiredPopulation {
	// 	log.Printf("missing required population: %s - %v\n", authInfo.RequiredPopulation, claims.Populations)
	// 	return nil
	// }

	// claims.Populations = populationsString

	// var groups string
	// groupsMap := make(map[string]string)

	// for key, value := range authInfo.Groups {
	// 	groupsMap[value] = key
	// }
	// groupsSplit := strings.Split(*claims.Groups, ",")

	// for _, s := range groupsSplit {
	// 	if groups != "" {
	// 		groups += ", "
	// 	}
	// 	groups += groupsMap[s]
	// }
	// claims.Groups = &groups

	// uidClaimTag = "uid"
	// nameClaimTag = "name"
	// emailClaimTag = "email"
	// phoneClaimTag = "phone"
	// groupsClaimTag = "groups"
	// populationsClaimTag = "populations"

	return rawClaims, nil
}

func (a *oidcAuthImpl) newToken(code string, params oidcLoginParams) (map[string]interface{}, error) {
	authInfo := a.auth.getAuthInfo(params.Domain)

	bodyData := map[string]string{
		"code":         code,
		"grant_type":   "authorization_code",
		"redirect_uri": params.RedirectURI,
		"client_id":    authInfo.OIDCClientID,
	}
	if len(params.CodeVerifier) > 0 {
		bodyData["code_verifier"] = params.CodeVerifier
	}

	// 1. Request Tokens
	oidcToken, err := a.loadOidcTokenWithParams(bodyData, authInfo)
	if err != nil {
		return nil, err
	}
	if oidcToken == nil {
		return nil, errors.New("get auth token failed")
	}

	var claims Claims
	checkParams := oidcCheckParams{Web: params.Web, Domain: params.Domain}
	oidcClaims, err := a.checkToken(oidcToken.IDToken, checkParams)
	claims.ID = oidcClaims["id"].(string)
	claims.Name = oidcClaims["name"].(string)
	claims.Email = oidcClaims["email"].(string)
	claims.Phone = oidcClaims["phone"].(string)
	claims.Groups = oidcClaims["groups"]
	claims.Issuer = oidcClaims["iss"].(string)
	claims.Exp = oidcClaims["exp"].(float64)

	// 2. Request rokwire access token
	accessToken, err := a.auth.generateAccessToken(&claims)
	if err != nil {
		return nil, err
	}

	csrfToken := ""
	var cookie http.Cookie
	if params.Web {
		cookie = http.Cookie{
			Name:   "rokmetro-access",
			Value:  accessToken,
			Domain: "services.rokmetro.com",
			// Expires:  expirationTime,
			SameSite: http.SameSiteNoneMode,
			Secure:   true,
			HttpOnly: true,
		}
		accessToken = ""

		csrfToken, err = a.auth.generateCSRFToken(&claims)
		if err != nil {
			return nil, err
		}
	}

	// 3. Request auth user
	userInfo, err := a.loadOidcUserInfo(oidcToken, authInfo.OIDCUserURL)
	if userInfo == nil {
		return nil, errors.New("get auth user failed")
	}
	var userMap map[string]interface{}
	err = json.Unmarshal(userInfo, &userMap)
	if err != nil {
		return nil, err
	}

	// 4. UserData from core?

	// 5. Request user picture
	var userPhoto []byte
	if photoURL, ok := userMap["picture"].(string); ok {
		userPhoto, err = a.loadOidcUserInfo(oidcToken, photoURL)
		if err != nil {
			log.Println("Error fetching user photo:", err.Error())
		}
	}

	loginResponse := map[string]interface{}{
		"rokwire_access_token": accessToken,
		"csrf_token":           csrfToken,
		"refresh_token":        oidcToken.RefreshToken,
		"user_info":            userInfo,
		"user_photo":           userPhoto,
		"cookie":               cookie,
	}

	return loginResponse, nil
}

func (a *oidcAuthImpl) refreshToken(refreshToken string, params oidcRefreshParams) (map[string]interface{}, error) {
	authInfo := a.auth.getAuthInfo(params.Domain)

	if len(authInfo.OIDCTokenURL) == 0 {
		return nil, errors.New("auth info missing OIDC token URL")
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
	oidcToken, err := a.loadOidcTokenWithParams(bodyData, authInfo)
	if err != nil {
		return nil, err
	}

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

	loginResponse := map[string]interface{}{
		"refresh_token": oidcToken.RefreshToken,
		"user_info":     userInfo,
		"user_photo":    userPhoto,
	}

	return loginResponse, nil
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

	var uri url.URL
	for k, v := range params {
		uri.Query().Set(k, v)
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
