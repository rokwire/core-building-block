package auth

import (
	"core-building-block/core/model"
	"errors"
	"fmt"
	"log"
	"sync"

	"golang.org/x/sync/syncmap"
	"gopkg.in/go-playground/validator.v9"
)

type UserAuth struct {
	UserID       string
	Sub          string
	Name         string
	Email        string
	Phone        string
	Picture      []byte
	Exp          float64
	RefreshToken string
}

type AuthConfig struct {
	OrgID  string      `json:"org_id" bson:"org_id" validate:"required"`
	AppID  string      `json:"app_id" bson:"app_id" validate:"required"`
	Type   string      `json:"type" bson:"type" validate:"required"`
	Config interface{} `json:"config" bson:"config" validate:"required"`
}

//Interface for authentication mechanisms
type authType interface {
	//Check validity of provided credentials
	check(creds string, params string) (*UserAuth, error)
}

//Auth interface TODO
type Auth struct {
	storage Storage

	authTypes       map[string]authType
	authConfigs     *syncmap.Map //cache authConfigs / orgID_appID -> authConfig
	authConfigsLock *sync.RWMutex
}

//NewAuth creates a new auth instance
func NewAuth(storage Storage) *Auth {
	authConfigs := &syncmap.Map{}
	authConfigsLock := &sync.RWMutex{}
	auth := &Auth{storage: storage, authConfigs: authConfigs, authConfigsLock: authConfigsLock}

	//Initialize auth types
	initEmailAuth(auth)
	initPhoneAuth(auth)
	initOidcAuth(auth)
	initSamlAuth(auth)
	initFirebaseAuth(auth)

	err := auth.LoadAuthConfigs()
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

func (a Auth) LoadAuthConfigs() error {
	authConfigDocs, err := a.storage.LoadAuthConfigs()
	if err != nil {
		return err
	}

	a.setAuthConfigs(authConfigDocs)

	return nil
}

func (a Auth) getAuthConfig(orgID string, appID string, authType string) (*AuthConfig, error) {
	a.authConfigsLock.RLock()
	defer a.authConfigsLock.RUnlock()

	var authConfig *AuthConfig //to return

	item, _ := a.authConfigs.Load(fmt.Sprintf("%s_%s_%s", orgID, appID, authType))
	if item != nil {
		authConfigFromCache, ok := item.(AuthConfig)
		if !ok {
			return nil, errors.New("failed to cast cache item to AuthConfig")
		}
		authConfig = &authConfigFromCache
		return authConfig, nil
	}
	return nil, errors.New("auth config does not exist")
}

func (a Auth) setAuthConfigs(authConfigs *[]AuthConfig) {
	a.authConfigs = &syncmap.Map{}
	validate := validator.New()
	var err error

	a.authConfigsLock.Lock()
	defer a.authConfigsLock.Unlock()
	for _, authConfig := range *authConfigs {
		err = validate.Struct(authConfig)
		if err == nil {
			a.authConfigs.Store(fmt.Sprintf("%s_%s_%s", authConfig.OrgID, authConfig.AppID, authConfig.Type), authConfig)
		}
	}
}

type Storage interface {
	FindAuthConfig(orgID string, appID string, authType string) (*AuthConfig, error)
	LoadAuthConfigs() (*[]AuthConfig, error)
}
