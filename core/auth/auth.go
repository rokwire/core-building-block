package auth

import (
	"core-building-block/core/model"
	"crypto/rsa"
	"fmt"
	"sync"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/rokmetro/auth-library/authservice"
	"github.com/rokmetro/auth-library/authutils"
	"github.com/rokmetro/auth-library/tokenauth"
	"golang.org/x/sync/syncmap"
	"gopkg.in/go-playground/validator.v9"

	log "github.com/rokmetro/logging-library/loglib"
)

const (
	typeAuthType   log.LogData = "auth type"
	TypeUserAuth   log.LogData = "user auth"
	TypeAuthConfig log.LogData = "user auth"
	TypeAuth       log.LogData = "auth"
	TypeServiceReg log.LogData = "service reg"
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
	OrgID string `json:"org_id" bson:"org_id" validate:"required"`
	AppID string `json:"app_id" bson:"app_id" validate:"required"`
	Type  string `json:"type" bson:"type" validate:"required"`

	//Config is a JSON encoded auth type specific structure
	Config []byte `json:"config" bson:"config" validate:"required"`
}

//Interface for authentication mechanisms
type authType interface {
	//Check validity of provided credentials
	check(creds string, params string, l *log.Log) (*UserAuth, error)
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
func NewAuth(serviceID string, host string, authPrivKey *rsa.PrivateKey, storage Storage, minTokenExp *int64, maxTokenExp *int64, logger *log.Logger) (*Auth, error) {
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
		return nil, log.WrapActionError(log.SaveAction, "reg", nil, err)
	}

	serviceLoader := NewLocalServiceRegLoader(storage)

	authService, err := authservice.NewAuthService(serviceID, host, serviceLoader)
	if err != nil {
		return nil, log.WrapActionError(log.InitializeAction, "auth service", nil, err)
	}

	auth.AuthService = authService

	//Initialize auth types
	initEmailAuth(auth)
	initPhoneAuth(auth)
	initOidcAuth(auth)
	initSamlAuth(auth)
	initFirebaseAuth(auth)

	initApiKeyAuth(auth)
	initSignatureAuth(auth)

	err = auth.LoadAuthConfigs()
	if err != nil {
		logger.Warn("NewAuth() failed to cache auth info documents")
	}

	return auth, nil
}

func (a *Auth) registerAuthType(name string, auth authType) error {
	if _, ok := a.authTypes[name]; ok {
		return log.NewErrorf("the requested auth type name has already been registered: %s", name)
	}

	a.authTypes[name] = auth

	return nil
}

func (a *Auth) getAuthType(name string) (authType, error) {
	if auth, ok := a.authTypes[name]; ok {
		return auth, nil
	}

	return nil, log.DataError(log.InvalidStatus, typeAuthType, log.StringArgs(name))
}

//Login logs a user in using the specified credentials and authentication method
//	Input:
//		authType (string): Name of the authentication method for provided creds (eg. "email")
//		creds (string): Credentials/JSON encoded credential structure defined for the specified auth type
//		params (string): JSON encoded params defined by specified auth type
//		l (*loglib.Log): Log object pointer for request
//	Returns:
//		Access token (string): Signed ROKWIRE access token to be used to authorize future requests
//		User (User): User object for authenticated user
func (a *Auth) Login(authType string, creds string, params string, l *log.Log) (string, *model.User, error) {
	auth, err := a.getAuthType(authType)
	if err != nil {
		return "", nil, log.WrapActionError(log.LoadCacheAction, typeAuthType, nil, err)
	}

	_, err = auth.check(creds, params, l)
	if err != nil {
		return "", nil, log.WrapActionError(log.ValidateAction, "creds", nil, err)
	}

	//TODO: Implement account management and return token and user using claims

	return "", nil, nil
}

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
		return "", log.WrapActionError(log.ComputeAction, "fingerprint", log.StringArgs("auth key"), err)
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

//storeReg stores the service registration record
func (a *Auth) storeReg() error {
	pem, err := authutils.GetPubKeyPem(&a.authPrivKey.PublicKey)
	if err != nil {
		return log.WrapActionError(log.EncodeAction, "auth pub key", nil, err)
	}

	key := authservice.PubKey{KeyPem: pem, Alg: "RS256"}

	// Setup "auth" registration for token validation
	authReg := authservice.ServiceReg{ServiceID: "auth", Host: a.host, PubKey: &key}
	err = a.storage.SaveServiceReg(&authReg)
	if err != nil {
		return log.WrapActionError(log.SaveAction, TypeServiceReg, log.StringArgs("auth"), err)
	}

	// Setup core registration for signature validation
	coreReg := authservice.ServiceReg{ServiceID: a.serviceID, Host: a.host, PubKey: &key}
	err = a.storage.SaveServiceReg(&coreReg)
	if err != nil {
		return log.WrapActionError(log.SaveAction, TypeServiceReg, log.StringArgs("core"), err)
	}

	return nil
}

func (a Auth) LoadAuthConfigs() error {
	authConfigDocs, err := a.storage.LoadAuthConfigs()
	if err != nil {
		return log.WrapActionError(log.FindAction, TypeAuthConfig, nil, err)
	}

	a.setAuthConfigs(authConfigDocs)

	return nil
}

func (a Auth) getAuthConfig(orgID string, appID string, authType string) (*AuthConfig, error) {
	a.authConfigsLock.RLock()
	defer a.authConfigsLock.RUnlock()

	var authConfig *AuthConfig //to return

	errArgs := &log.FieldArgs{"org_id": orgID, "app_id": appID, "auth_type": authType}

	item, _ := a.authConfigs.Load(fmt.Sprintf("%s_%s_%s", orgID, appID, authType))
	if item != nil {
		authConfigFromCache, ok := item.(AuthConfig)
		if !ok {
			return nil, log.ActionError(log.CastAction, TypeAuthConfig, errArgs)
		}
		authConfig = &authConfigFromCache
		return authConfig, nil
	}
	return nil, log.DataError(log.MissingStatus, TypeAuthConfig, errArgs)
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

type Storage interface {
	GetServiceRegs(serviceIDs []string) ([]authservice.ServiceReg, error)
	SaveServiceReg(reg *authservice.ServiceReg) error

	FindAuthConfig(orgID string, appID string, authType string) (*AuthConfig, error)
	LoadAuthConfigs() (*[]AuthConfig, error)
}
