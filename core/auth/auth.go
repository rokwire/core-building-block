package auth

import (
	"core-building-block/core/model"
	"crypto/rsa"
	"fmt"
	"log"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/rokmetro/auth-library/authservice"
	"github.com/rokmetro/auth-library/authutils"
	"github.com/rokmetro/auth-library/tokenauth"
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

	authPrivKey *rsa.PrivateKey

	authService *authservice.AuthService
	TokenAuth   *tokenauth.TokenAuth

	issuer      string //Issuer for tokens (should match service host)
	minTokenExp int64  //Minimum access token expiration time in minutes
	maxTokenExp int64  //Maximum access token expiration time in minutes
}

//NewAuth creates a new auth instance
//Token Exp Suggestions: Min = 5, Max = 60
func NewAuth(serviceID string, host string, authPrivKey *rsa.PrivateKey, storage Storage, minTokenExp int64, maxTokenExp int64) (*Auth, error) {
	//TODO: Create local ServiceRegLoader implementation
	serviceLoader := NewLocalServiceRegLoader(storage)

	authService, err := authservice.NewAuthService(serviceID, host, serviceLoader)
	if err != nil {
		return nil, fmt.Errorf("error initializing auth service: %v", err)
	}

	tokenAuth, err := tokenauth.NewTokenAuth(true, authService)
	if err != nil {
		return nil, fmt.Errorf("error initializing token auth: %v", err)
	}

	authTypes := map[string]authType{}
	auth := &Auth{storage: storage, authTypes: authTypes, authPrivKey: authPrivKey, authService: authService, TokenAuth: tokenAuth,
		minTokenExp: minTokenExp, maxTokenExp: maxTokenExp}

	//Initialize auth types
	initEmailAuth(auth)
	initPhoneAuth(auth)
	initOidcAuth(auth)
	initSamlAuth(auth)
	initFirebaseAuth(auth)

	return auth, nil
}

func (a *Auth) registerAuthType(name string, auth authType) error {
	if _, ok := a.authTypes[name]; ok {
		return fmt.Errorf("the requested auth type name has already been registered: %s", name)
	}

	a.authTypes[name] = auth

	return nil
}

func (a *Auth) getAuthType(name string) (authType, error) {
	if auth, ok := a.authTypes[name]; ok {
		return auth, nil
	}

	return nil, fmt.Errorf("invalid auth type: %s", name)
}

//Login logs a user in using the specified credentials and authentication method
//	Input:
//		authName (string): Name of the authentication method for provided creds (eg. "email")
//		creds (string): Credentials/JSON encoded credential structure defined for the specific auth type
//	Returns:
//		Access token (string): Signed ROKWIRE access token to be used to authorize future requests
//		User (User): User object for authenticated user
func (a *Auth) Login(authName string, creds string) (string, *model.User, error) {
	auth, err := a.getAuthType(authName)
	if err != nil {
		return "", nil, err
	}

	claims, err := auth.check(creds)
	if err != nil {
		return "", nil, err
	}
	log.Println(claims)

	//TODO: Implement account management and return token and user using claims

	return "", nil, nil
}

func (a *Auth) GetScopedAccessToken(claims tokenauth.Claims, serviceID string, scope string) (string, error) {
	scopedClaims := a.getStandardClaims(claims.Subject, serviceID, claims.OrgID, nil)
	return a.buildAccessToken(scopedClaims, "", scope)
}

func (a *Auth) buildAccessToken(claims tokenauth.Claims, permissions string, scope string) (string, error) {
	claims.Purpose = "access"
	claims.Permissions = permissions
	claims.Scope = scope
	return a.generateToken(&claims)
}

func (a *Auth) buildCsrfToken(claims tokenauth.Claims) (string, error) {
	claims.Purpose = "csrf"
	return a.generateToken(&claims)
}

func (a *Auth) getStandardClaims(sub string, aud string, orgID string, exp *int64) tokenauth.Claims {
	return tokenauth.Claims{
		StandardClaims: jwt.StandardClaims{
			Audience:  aud,
			Subject:   sub,
			ExpiresAt: a.getExp(exp),
			IssuedAt:  time.Now().Unix(),
			Issuer:    a.issuer,
		}, OrgID: orgID,
	}
}

func (a *Auth) generateToken(claims *tokenauth.Claims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	kid, err := authutils.GetKeyFingerprint(&a.authPrivKey.PublicKey)
	if err != nil {
		return "", fmt.Errorf("error computing auth key fingerprint: %v", err)
	}
	token.Header["kid"] = kid
	return token.SignedString(a.authPrivKey)
}

func (a *Auth) getExp(exp *int64) int64 {
	if exp == nil {
		defaultTime := time.Now().Add(30 * time.Minute) //TODO: Set up org configs for default token exp
		return defaultTime.Unix()
	} else {
		expTime := time.Unix(*exp, 0)
		minTime := time.Now().Add(time.Duration(a.minTokenExp) * time.Minute)
		maxTime := time.Now().Add(time.Duration(a.maxTokenExp) * time.Minute)

		if expTime.Before(minTime) {
			return minTime.Unix()
		} else if expTime.After(maxTime) {
			return maxTime.Unix()
		}

		return *exp
	}
}

//createAccount creates a new user account
func (a *Auth) createAccount(claims *tokenauth.Claims) {
	//TODO: Implement
}

//updateAccount updates a user's account information
func (a *Auth) updateAccount(claims *tokenauth.Claims) {
	//TODO: Implement
}

//deleteAccount deletes a user account
func (a *Auth) deleteAccount(claims *tokenauth.Claims) {
	//TODO: Implement
}

//LocalServiceRegLoaderImpl provides a local implementation for ServiceRegLoader
type LocalServiceRegLoaderImpl struct {
	storage Storage
	*authservice.ServiceRegSubscriptions
}

func (l *LocalServiceRegLoaderImpl) LoadServices() ([]authservice.ServiceReg, error) {
	return l.storage.LoadServiceRegs(l.GetSubscribedServices())
}

//NewLocalServiceRegLoader creates and configures a new LocalServiceRegLoaderImpl instance
func NewLocalServiceRegLoader(storage Storage) *LocalServiceRegLoaderImpl {
	subscriptions := authservice.NewServiceRegSubscriptions([]string{"all"})
	return &LocalServiceRegLoaderImpl{storage: storage, ServiceRegSubscriptions: subscriptions}
}

//Storage interface for auth package
type Storage interface {
	ReadTODO() error
	LoadServiceRegs(serviceIDs []string) ([]authservice.ServiceReg, error) //TODO: Implement in sotrage adapater
}
