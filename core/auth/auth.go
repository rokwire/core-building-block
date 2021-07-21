package auth

import (
	"core-building-block/core/model"
	"core-building-block/driven/storage"
	"crypto/rsa"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/rokmetro/auth-library/authservice"
	"github.com/rokmetro/auth-library/authutils"
	"github.com/rokmetro/auth-library/tokenauth"
	"golang.org/x/sync/syncmap"
	"gopkg.in/go-playground/validator.v9"
)

//Interface for authentication mechanisms
type authType interface {
	//Check validity of provided credentials
	check(creds string, params string) (*model.UserAuth, error)
}

//Auth represents the auth functionality unit
type Auth struct {
	storage Storage

	authTypes map[string]authType

	authPrivKey *rsa.PrivateKey

	AuthService *authservice.AuthService

	serviceID   string
	host        string //Service host
	minTokenExp int64  //Minimum access token expiration time in minutes
	maxTokenExp int64  //Maximum access token expiration time in minutes

	authConfigs     *syncmap.Map //cache authConfigs / orgID_appID -> authConfig
	authConfigsLock *sync.RWMutex
}

//NewAuth creates a new auth instance
func NewAuth(serviceID string, host string, authPrivKey *rsa.PrivateKey, storage Storage, minTokenExp *int64, maxTokenExp *int64) (*Auth, error) {
	if minTokenExp == nil {
		var minTokenExpVal int64 = 5
		minTokenExp = &minTokenExpVal
	}

	if maxTokenExp == nil {
		var maxTokenExpVal int64 = 60
		maxTokenExp = &maxTokenExpVal
	}

	authTypes := map[string]authType{}

	authConfigs := &syncmap.Map{}
	authConfigsLock := &sync.RWMutex{}
	auth := &Auth{storage: storage, authTypes: authTypes, authPrivKey: authPrivKey, AuthService: nil,
		serviceID: serviceID, host: host, minTokenExp: *minTokenExp, maxTokenExp: *maxTokenExp,
		authConfigs: authConfigs, authConfigsLock: authConfigsLock}

	err := auth.storeReg()
	if err != nil {
		return nil, fmt.Errorf("error storing reg: %v", err)
	}

	serviceLoader := NewLocalServiceRegLoader(storage)

	authService, err := authservice.NewAuthService(serviceID, host, serviceLoader)
	if err != nil {
		return nil, fmt.Errorf("error initializing auth service: %v", err)
	}

	auth.AuthService = authService

	//Initialize auth types
	initEmailAuth(auth)
	initPhoneAuth(auth)
	initOidcAuth(auth)
	initSamlAuth(auth)
	initFirebaseAuth(auth)

	initAPIKeyAuth(auth)
	initSignatureAuth(auth)

	err = auth.LoadAuthConfigs()
	if err != nil {
		log.Println("NewAuth() -> failed to cache auth info documents")
	}

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
func (a *Auth) Login(authName string, creds string, params string) (string, *model.User, error) {
	auth, err := a.getAuthType(authName)
	if err != nil {
		return "", nil, err
	}

	claims, err := auth.check(creds, params)
	if err != nil {
		return "", nil, err
	}
	log.Println(claims)

	//TODO: Implement account management and return token and user using claims

	return "", nil, nil
}

//GetScopedAccessToken TODO
func (a *Auth) GetScopedAccessToken(claims tokenauth.Claims, serviceID string, scope string) (string, error) {
	scopedClaims := a.getStandardClaims(claims.Subject, serviceID, claims.OrgID, claims.AppID, nil)
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

func (a *Auth) getStandardClaims(sub string, aud string, orgID string, appID string, exp *int64) tokenauth.Claims {
	return tokenauth.Claims{
		StandardClaims: jwt.StandardClaims{
			Audience:  aud,
			Subject:   sub,
			ExpiresAt: a.getExp(exp),
			IssuedAt:  time.Now().Unix(),
			Issuer:    a.host,
		}, OrgID: orgID, AppID: appID,
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
	}
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

//findAccount retrieves a user's account information
func (a *Auth) findAccount(claims *tokenauth.Claims, userAuth *UserAuth) (*model.User, error) {
	return a.storage.FindUser(userAuth.UserID)
}

//createAccount creates a new user account
func (a *Auth) createAccount(claims *tokenauth.Claims, userAuth *UserAuth) (*model.User, error) {
	names := strings.Split(userAuth.Name, " ")
	newUser := model.User{}

	newAccount := model.UserAccount{Email: userAuth.Email, Phone: userAuth.Phone, Username: userAuth.UserID}
	newUser.Account = newAccount
	newProfile := model.UserProfile{FirstName: names[0], LastName: names[len(names)-1]}
	newUser.Profile = newProfile

	newOrgMembership := model.OrganizationMembership{}
	organization, err := a.storage.FindOrganization(claims.OrgID)
	if err != nil {
		return nil, err
	}
	newOrgMembership.Organization = *organization

	newOrgMembership.Permissions = strings.Split(claims.Permissions, ",")

	device := model.Device{}
	newUser.Devices = []model.Device{device}

	newUser.OrganizationsMemberships = []model.OrganizationMembership{newOrgMembership}
	newUser.OrganizationsMemberships[0].User = newUser

	return a.storage.InsertUser(&newUser)
}

//updateAccount updates a user's account information
func (a *Auth) updateAccount(claims *tokenauth.Claims, userAuth *UserAuth) (*model.User, error) {
	updatedUser := model.User{}
	return a.storage.UpdateUser(&updatedUser)
}

//deleteAccount deletes a user account
func (a *Auth) deleteAccount(claims *tokenauth.Claims, userAuth *UserAuth) error {
	return a.storage.DeleteUser(claims.Id)
}

//storeReg stores the service registration record
func (a *Auth) storeReg() error {
	pem, err := authutils.GetPubKeyPem(&a.authPrivKey.PublicKey)
	if err != nil {
		return fmt.Errorf("error encoding auth pub key for storage: %v", err)
	}

	key := authservice.PubKey{KeyPem: pem, Alg: "RS256"}

	// Setup "auth" registration for token validation
	authReg := authservice.ServiceReg{ServiceID: "auth", Host: a.host, PubKey: &key}
	err = a.storage.SaveServiceReg(&authReg)
	if err != nil {
		return fmt.Errorf("error saving auth service reg: %v", err)
	}

	// Setup core registration for signature validation
	coreReg := authservice.ServiceReg{ServiceID: a.serviceID, Host: a.host, PubKey: &key}
	err = a.storage.SaveServiceReg(&coreReg)
	if err != nil {
		return fmt.Errorf("error saving core service reg: %v", err)
	}

	return nil
}

//LoadAuthConfigs loads the auth configs
func (a *Auth) LoadAuthConfigs() error {
	authConfigDocs, err := a.storage.LoadAuthConfigs()
	if err != nil {
		return err
	}

	a.setAuthConfigs(authConfigDocs)

	return nil
}

func (a *Auth) getAuthConfig(orgID string, appID string, authType string) (*model.AuthConfig, error) {
	a.authConfigsLock.RLock()
	defer a.authConfigsLock.RUnlock()

	var authConfig *model.AuthConfig //to return

	item, _ := a.authConfigs.Load(fmt.Sprintf("%s_%s_%s", orgID, appID, authType))
	if item != nil {
		authConfigFromCache, ok := item.(model.AuthConfig)
		if !ok {
			return nil, errors.New("failed to cast cache item to AuthConfig")
		}
		authConfig = &authConfigFromCache
		return authConfig, nil
	}
	return nil, errors.New("auth config does not exist")
}

func (a *Auth) setAuthConfigs(authConfigs *[]model.AuthConfig) {
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

//LocalServiceRegLoaderImpl provides a local implementation for ServiceRegLoader
type LocalServiceRegLoaderImpl struct {
	storage Storage
	*authservice.ServiceRegSubscriptions
}

//LoadServices implements ServiceRegLoader interface
func (l *LocalServiceRegLoaderImpl) LoadServices() ([]authservice.ServiceReg, error) {
	return l.storage.GetServiceRegs(l.GetSubscribedServices())
}

//NewLocalServiceRegLoader creates and configures a new LocalServiceRegLoaderImpl instance
func NewLocalServiceRegLoader(storage Storage) *LocalServiceRegLoaderImpl {
	subscriptions := authservice.NewServiceRegSubscriptions([]string{"all"})
	return &LocalServiceRegLoaderImpl{storage: storage, ServiceRegSubscriptions: subscriptions}
}

//Storage interface to communicate with the storage
type Storage interface {
	FindUser(id string) (*model.User, error)
	InsertUser(user *model.User) (*model.User, error)
	UpdateUser(user *model.User) (*model.User, error)
	DeleteUser(id string) error

	FindOrganization(id string) (*model.Organization, error)

	GetServiceRegs(serviceIDs []string) ([]authservice.ServiceReg, error)
	SaveServiceReg(reg *authservice.ServiceReg) error

	FindAuthConfig(orgID string, appID string, authType string) (*model.AuthConfig, error)
	LoadAuthConfigs() (*[]model.AuthConfig, error)
}

//StorageListener represents storage listener implementation for the auth package
type StorageListener struct {
	Auth *Auth
	storage.DefaultListenerImpl
}

//OnAuthConfigUpdated notifies that an auth config has been updated
func (al *StorageListener) OnAuthConfigUpdated() {
	al.Auth.LoadAuthConfigs()
}
