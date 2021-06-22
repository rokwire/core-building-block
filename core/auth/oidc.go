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
	"sync"

	"github.com/coreos/go-oidc"
	"golang.org/x/sync/syncmap"
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

	authInfo     *syncmap.Map //cache authInfo / client id -> authInfo
	authInfoLock *sync.RWMutex
}

type oidcCheckParams struct {
	// ClientID string `json:"client_id"`
	Web     bool   `json:"web"`
	Domain  string `json:"domain"`
	IDToken string `json:"id_token"`
}

type oidcLoginParams struct {
	// ClientID     string `json:"client_id"`
	Web          bool   `json:"web"`
	Domain       string `json:"domain"`
	Code         string `json:"code"`
	CodeVerifier string `json:"pkce_verifier"`
	RedirectURI  string `json:"redirect_uri"` // should this be used for requests from mobile client?
}

func (a *oidcAuthImpl) login(creds string, params string) (map[string]interface{}, error) {
	paramsMap := make(map[string]interface{})
	err := json.Unmarshal([]byte(params), &paramsMap)
	if err != nil {
		return nil, err
	}
	credType, ok := paramsMap["cred_type"].(string)
	if !ok {
		return nil, errors.New("cred_type parameter missing or invalid")
	}
	// check for web vs. mobile?
	switch credType {
	case "id_token":
		return a.checkToken(creds, params)
	case "code":
		return a.newToken(creds, params)
	case "refresh_token":
		return a.refreshToken(creds, params)
	default:
		return nil, errors.New("unimplemented cred_type")
	}
}

func (a *oidcAuthImpl) checkToken(idToken string, params string) (map[string]interface{}, error) {
	var checkParams oidcCheckParams
	err := json.Unmarshal([]byte(params), &checkParams)
	if err != nil {
		return nil, err
	}

	authInfo, err := a.auth.storage.FindDomainAuthInfo(checkParams.Domain)
	if err != nil {
		return nil, err
	}

	oidcProvider := authInfo.OIDCHost
	oidcAdminClientID := authInfo.OIDCClientID

	// Validate the token
	provider, err := oidc.NewProvider(context.Background(), oidcProvider)
	if err != nil {
		return nil, err
	}
	tokenVerifier := provider.Verifier(&oidc.Config{ClientID: oidcAdminClientID})
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

func (a *oidcAuthImpl) newToken(code string, params string) (map[string]interface{}, error) {
	var loginParams oidcLoginParams
	err := json.Unmarshal([]byte(params), &loginParams)
	if err != nil {
		return nil, err
	}

	authInfo, err := a.auth.storage.FindDomainAuthInfo(loginParams.Domain)
	if err != nil {
		return nil, err
	}

	// 1. Request Tokens
	oidcToken, err := a.loadOidcTokenWithCode(code, &loginParams, authInfo)
	if oidcToken == nil {
		return nil, errors.New("get auth token failed")
	}

	// 2. Request rokwire access token
	accessToken, err := a.auth.generateAccessToken()
	if err != nil {
		return nil, err
	}

	csrfToken := ""
	if loginParams.Web {
		csrfToken, err = a.auth.generateCSRFToken()
		if err != nil {
			return nil, err
		}
	}

	// 3. Request auth user
	userInfo, err := a.loadOidcUser(oidcToken, authInfo.OIDCUserURL)
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
		userPhoto, err = a.getUserPhoto(oidcToken, photoURL)
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
	}

	return loginResponse, nil
}

func (a *oidcAuthImpl) refreshToken(creds string, params string) (map[string]interface{}, error) {
	return nil, errors.New("unimplemented")
}

func (a *oidcAuthImpl) loadOidcTokenWithCode(code string, params *oidcLoginParams, authInfo *AuthInfo) (*oidcToken, error) {
	if authInfo == nil {
		return nil, errors.New("authInfo must not be nil")
	}
	tokenUri := ""
	bodyData := map[string]string{
		"code":         code,
		"grant_type":   "authorization_code",
		"redirect_uri": params.RedirectURI,
		"client_id":    authInfo.OIDCClientID,
	}

	if strings.Contains(authInfo.OIDCTokenURL, "{shibboleth_client_id}") {
		tokenUri = strings.ReplaceAll(authInfo.OIDCTokenURL, "{shibboleth_client_id}", authInfo.OIDCClientID)
		tokenUri = strings.ReplaceAll(tokenUri, "{shibboleth_client_secret}", authInfo.OIDCClientSecret)
	} else if len(authInfo.OIDCClientSecret) > 0 {
		tokenUri = authInfo.OIDCTokenURL
		bodyData["client_secret"] = authInfo.OIDCClientSecret
	} else {
		tokenUri = authInfo.OIDCTokenURL
	}

	if len(params.CodeVerifier) > 0 {
		bodyData["code_verifier"] = params.CodeVerifier
	}

	var uri url.URL
	for k, v := range bodyData {
		uri.Query().Set(k, v)
	}
	headers := map[string]string{
		"Content-Type":   "application/x-www-form-urlencoded",
		"Content-Length": strconv.Itoa(len(uri.Query().Encode())),
	}
	jsonData, err := json.Marshal(bodyData)
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

func (a *oidcAuthImpl) loadOidcUser(token *oidcToken, userURL string) ([]byte, error) {
	if len(token.AccessToken) == 0 {
		return nil, errors.New("missing access token")
	}
	if len(token.TokenType) == 0 {
		return nil, errors.New("missing token type")
	}
	if len(userURL) == 0 {
		return nil, errors.New("missing oidc user url")
	}

	client := &http.Client{}
	req, err := http.NewRequest("GET", userURL, nil)
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

func (a *oidcAuthImpl) getUserPhoto(token *oidcToken, photoURL string) ([]byte, error) {
	client := &http.Client{}
	req, err := http.NewRequest("GET", photoURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", fmt.Sprintf("%s %s", token.TokenType, token.AccessToken))

	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	return body, nil
}

// func (a *oidcAuthImpl) loadAuthInfoDocs() error {
// 	//1 load
// 	authInfoDocs, err := a.auth.storage.LoadAuthInfoDocs()
// 	if err != nil {
// 		return err
// 	}

// 	//2 set
// 	a.setAuthInfo(authInfoDocs)

// 	return nil
// }

// func (a *oidcAuthImpl) getAuthInfo(domain string) *AuthInfo {
// 	a.authInfoLock.RLock()
// 	defer a.authInfoLock.RUnlock()

// 	var authInfo AuthInfo //to return

// 	item, _ := a.authInfo.Load(domain)
// 	if item != nil {
// 		authInfo = item.(AuthInfo)
// 	} else {
// 		log.Println("getAPIKey() -> nil for domain", domain)
// 	}

// 	return &authInfo
// }

// func (a *oidcAuthImpl) setAuthInfo(authInfo map[string]AuthInfo) {
// 	a.authInfoLock.Lock()
// 	defer a.authInfoLock.Unlock()

// 	//first clear the old data
// 	a.authInfo = &syncmap.Map{}

// 	for key, value := range authInfo {
// 		a.authInfo.Store(key, value)
// 	}
// }

//initOidcAuth initializes and registers a new OIDC auth instance
func initOidcAuth(auth *Auth) (*oidcAuthImpl, error) {
	authInfo := &syncmap.Map{}
	authInfoLock := &sync.RWMutex{}
	oidc := &oidcAuthImpl{auth: auth, authInfo: authInfo, authInfoLock: authInfoLock}

	err := auth.registerAuthType("oidc", oidc)
	if err != nil {
		return nil, err
	}

	// err = oidc.loadAuthInfoDocs()
	// if err != nil {
	// 	return nil, err
	// }

	return oidc, nil
}
