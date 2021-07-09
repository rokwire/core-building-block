package auth

import (
	"core-building-block/core/model"
	"fmt"
	"log"
	"sync"

	"golang.org/x/sync/syncmap"
)

type UserAuth struct {
	ID           string
	Name         string
	Email        string
	Phone        string
	Picture      []byte
	Groups       interface{}
	Issuer       string
	Exp          float64
	RefreshToken string
}

type AuthInfo struct {
	OrgID              string            `json:"org_id" bson:"org_id"`
	AppID              string            `json:"app_id" bson:"app_id"`
	Issuer             string            `json:"issuer" bson:"issuer"`
	OIDCKeyURL         string            `json:"oidc_key_url" bson:"oidc_key_url"`
	OIDCHost           string            `json:"oidc_host" bson:"oidc_host"`
	OIDCTokenURL       string            `json:"oidc_token_url" bson:"oidc_token_url"`
	OIDCAuthURL        string            `json:"oidc_auth_url" bson:"oidc_auth_url"`
	OIDCUserURL        string            `json:"oidc_user_url" bson:"oidc_user_url"`
	OIDCScopes         string            `json:"oidc_scopes" bson:"oidc_scopes"`
	OIDCUseRefresh     bool              `json:"oidc_use_refresh" bson:"oidc_use_refresh"`
	OIDCUsePKCE        bool              `json:"oidc_use_pkce" bson:"oidc_use_pkce"`
	OIDCClientID       string            `json:"oidc_client_id" bson:"oidc_client_id"`
	OIDCClientSecret   string            `json:"oidc_client_secret" bson:"oidc_client_secret"`
	Type               string            `json:"type" bson:"type"`
	Claims             map[string]string `json:"claims" bson:"claims"`
	RequiredPopulation string            `json:"required_population" bson:"required_population"`
	Populations        map[string]string `json:"populations" bson:"populations"`
}

//Interface for authentication mechanisms
type authType interface {
	//Check validity of provided credentials
	check(creds string, params string) (*UserAuth, error)
}

type Auth struct {
	storage Storage

	authTypes    map[string]authType
	authInfo     *syncmap.Map //cache authInfo / domain -> authInfo
	authInfoLock *sync.RWMutex
}

//NewAuth creates a new auth instance
func NewAuth(storage Storage) *Auth {
	authInfo := &syncmap.Map{}
	authInfoLock := &sync.RWMutex{}
	auth := &Auth{storage: storage, authInfo: authInfo, authInfoLock: authInfoLock}

	//Initialize auth types
	initEmailAuth(auth)
	initPhoneAuth(auth)
	initOidcAuth(auth)
	initSamlAuth(auth)
	initFirebaseAuth(auth)

	err := auth.LoadAuthInfoDocs()
	if err != nil {
		log.Println("NewAuth() -> failed to cache auth info documents")
	}

	return auth
}

func (a *Auth) registerAuthType(name string, auth authType) error {
	if _, ok := a.authTypes[name]; ok {
		return fmt.Errorf("the requested auth type name has already been registered: %s", name)
	}

	a.authTypes[name] = auth

	return nil
}

func (a Auth) getAuthType(name string) (authType, error) {
	if auth, ok := a.authTypes[name]; ok {
		return auth, nil
	}

	return nil, fmt.Errorf("invalid auth type: %s", name)
}

func (a Auth) Login(authName string, creds string, params string) (*model.User, error) {
	auth, err := a.getAuthType(authName)
	if err != nil {
		return nil, err
	}

	claims, err := auth.check(creds, params)
	if err != nil {
		return nil, err
	}
	log.Println(claims)

	//TODO: Implement account management and return user using claims

	return nil, nil
}

//createAccount creates a new user account
func (a Auth) createAccount(claims *UserAuth) {
	//TODO: Implement
}

//updateAccount updates a user's account information
func (a Auth) updateAccount(claims *UserAuth) {
	//TODO: Implement
}

//deleteAccount deletes a user account
func (a Auth) deleteAccount(claims *UserAuth) {
	//TODO: Implement
}

func (a Auth) LoadAuthInfoDocs() error {
	authInfoDocs, err := a.storage.LoadAuthInfoDocs()
	if err != nil {
		return err
	}

	a.setAuthInfo(authInfoDocs)

	return nil
}

func (a Auth) getAuthInfo(orgID string, appID string) *AuthInfo {
	a.authInfoLock.RLock()
	defer a.authInfoLock.RUnlock()

	var authInfo *AuthInfo //to return

	item, _ := a.authInfo.Load(fmt.Sprintf("%s_%s", orgID, appID))
	if item != nil {
		authInfoFromCache, ok := item.(AuthInfo)
		if !ok {
			log.Println("getAuthInfo(): failed to cast cache item to AuthInfo")
			return nil
		}
		authInfo = &authInfoFromCache
	} else {
		var err error
		authInfo, err = a.storage.FindDomainAuthInfo(orgID, appID)
		if err != nil {
			return nil
		}
	}

	return authInfo
}

func (a Auth) setAuthInfo(authInfo map[string]AuthInfo) {
	a.authInfoLock.Lock()
	defer a.authInfoLock.Unlock()

	a.authInfo = &syncmap.Map{}

	for key, value := range authInfo {
		a.authInfo.Store(key, value)
	}
}

type Storage interface {
	FindDomainAuthInfo(orgID string, appID string) (*AuthInfo, error)
	LoadAuthInfoDocs() (map[string]AuthInfo, error)
}
