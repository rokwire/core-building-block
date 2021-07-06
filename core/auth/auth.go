package auth

import (
	"core-building-block/core/model"
	"fmt"
	"log"
)

//Claims represents the claims entity
type Claims struct {
	ID     string
	Name   string
	Email  string
	Phone  string
	Groups interface{}
	Issuer string
	Exp    float64
}

//Interface for authentication mechanisms
type authType interface {
	//Check validity of provided credentials
	check(creds string) (*Claims, error)
}

//Auth represents the auth functionality unit
type Auth struct {
	storage Storage

	authTypes map[string]authType
}

//NewAuth creates a new auth instance
func NewAuth(storage Storage) *Auth {
	authTypes := map[string]authType{}
	auth := &Auth{storage: storage, authTypes: authTypes}

	//Initialize auth types
	initEmailAuth(auth)
	initPhoneAuth(auth)
	initOidcAuth(auth)
	initSamlAuth(auth)
	initFirebaseAuth(auth)

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

//Login logs a user in using the specified credentials and authentication method
func (a Auth) Login(authName string, creds string) (*model.User, error) {
	auth, err := a.getAuthType(authName)
	if err != nil {
		return nil, err
	}

	claims, err := auth.check(creds)
	if err != nil {
		return nil, err
	}
	log.Println(claims)

	//TODO: Implement account management and return user using claims

	return nil, nil
}

//createAccount creates a new user account
func (a Auth) createAccount(claims *Claims) {
	//TODO: Implement
}

//updateAccount updates a user's account information
func (a Auth) updateAccount(claims *Claims) {
	//TODO: Implement
}

//deleteAccount deletes a user account
func (a Auth) deleteAccount(claims *Claims) {
	//TODO: Implement
}

//Storage interface for auth package
type Storage interface {
	ReadTODO() error
}
