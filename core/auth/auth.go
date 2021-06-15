package auth

import "fmt"

type Claims struct {
	ID     string
	Name   string
	Email  string
	Phone  string
	Groups interface{}
	Issuer string
	Exp    float64
}

// Interface for authentication mechanisms
type authType interface {
	// Check validity of provided credentials
	check(creds string) (*Claims, error)
}

type Auth struct {
	storage Storage

	emailAuth    *emailAuthImpl
	phoneAuth    *phoneAuthImpl
	oidcAuth     *oidcAuthImpl
	samlAuthImpl *samlAuthImpl
	firebaseAuth *firebaseAuthImpl
}

//NewAuth creates a new auth instance
func NewAuth(storage Storage) *Auth {
	emailAuth := newEmailAuth()
	phoneAuth := newPhoneAuth()
	oidcAuth := newOidcAuth()
	samlAuth := newSamlAuth()
	firebaseAuth := newFirebaseAuth()
	return &Auth{storage: storage, emailAuth: emailAuth, phoneAuth: phoneAuth, oidcAuth: oidcAuth, samlAuthImpl: samlAuth, firebaseAuth: firebaseAuth}
}

func (a Auth) check(creds string, authType string) (*Claims, error) {
	switch authType {
	case "email":
		return a.emailAuth.check(creds)
	case "phone":
		return a.phoneAuth.check(creds)
	case "oidc":
		return a.oidcAuth.check(creds)
	case "saml":
		return a.samlAuthImpl.check(creds)
	case "firebase":
		return a.firebaseAuth.check(creds)
	default:
		return nil, fmt.Errorf("invalid authentication type: %s", authType)
	}
}

func (a Auth) createAccount(claims *Claims) {
	//TODO: Implement
}

func (a Auth) updateAccount(claims *Claims) {
	//TODO: Implement
}

func (a Auth) deleteAccount(claims *Claims) {
	//TODO: Implement
}

type Storage interface {
	ReadTODO() error
}
