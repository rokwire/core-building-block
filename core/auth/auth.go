package auth

import (
	"core-building-block/core/model"
	"core-building-block/driven/storage"
	"crypto/rsa"
	"fmt"
	"reflect"
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
	authServiceID string = "auth"
	authKeyAlg    string = "RS256"

	typeAuthType log.LogData = "auth type"
	typeAuth     log.LogData = "auth"
)

//Interface for authentication mechanisms
type authType interface {
	//check checks the validity of provided credentials
	check(creds string, orgID string, appID string, params string, l *log.Log) (*model.UserAuth, error)
	//refresh refreshes the access token using provided refresh token
	refresh(refreshToken string, orgID string, appID string, l *log.Log) (*model.UserAuth, error)
	//getLoginUrl retrieves and pre-formats a login url and params for the SSO provider
	getLoginUrl(orgID string, appID string, redirectUri string, l *log.Log) (string, map[string]interface{}, error)
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

//TODO: Once the profile has been transferred and the new user ID scheme has been adopted across all services
//		this should be replaced by tokenauth.Claims directly
//tokenClaims is a temporary claims model to provide backwards compatibility
type tokenClaims struct {
	tokenauth.Claims
	UID   string `json:"uid,omitempty"`
	Email string `json:"email,omitempty"`
	Phone string `json:"phone,omitempty"`
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
		return nil, log.WrapActionError(log.ActionSave, "reg", nil, err)
	}

	serviceLoader := NewLocalServiceRegLoader(storage)

	authService, err := authservice.NewAuthService(serviceID, host, serviceLoader)
	if err != nil {
		return nil, log.WrapActionError(log.ActionInitialize, "auth service", nil, err)
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
		logger.Warn("NewAuth() failed to cache auth configs")
	}

	return auth, nil
}

//Login logs a user in using the specified credentials and authentication method
//	Input:
//		authType (string): Name of the authentication method for provided creds (eg. "email")
//		creds (string): Credentials/JSON encoded credential structure defined for the specified auth type
//		orgID (string): ID of the organization that the user is logging in to
//		appID (string): ID of the app/client that the user is logging in from
//		params (string): JSON encoded params defined by specified auth type
//		l (*loglib.Log): Log object pointer for request
//	Returns:
//		Access token (string): Signed ROKWIRE access token to be used to authorize future requests
//		User (User): User object for authenticated user
//		Refresh Token (string): Refresh token that can be sent to refresh the access token once it expires
func (a *Auth) Login(authType string, creds string, orgID string, appID string, params string, l *log.Log) (string, string, *model.User, error) {
	var user *model.User
	var err error
	auth, err := a.getAuthType(authType)
	if err != nil {
		return "", "", nil, log.WrapActionError(log.ActionLoadCache, typeAuthType, nil, err)
	}

	userAuth, err := auth.check(creds, orgID, appID, params, l)
	if err != nil {
		return "", "", nil, log.WrapActionError(log.ActionValidate, "creds", nil, err)
	}

	if len(userAuth.AccountID) > 0 {
		user, err = a.findAccount(userAuth)
		if err != nil {
			return "", "", nil, err
		}
		user, update, newMembership := a.needsUserUpdate(userAuth, user)
		if update {
			var newMembershipOrgData *map[string]interface{}
			if newMembership {
				newMembershipOrgData = &userAuth.OrgData
			}
			_, err = a.updateAccount(user, newMembershipOrgData)
			if err != nil {
				return "", "", nil, err
			}
		}
	} else {
		if userAuth.NewCreds != nil {
			authCred := model.AuthCred{
				OrgID:  orgID,
				AppID:  appID,
				Type:   authType,
				UserID: userAuth.UserID,
				Creds:  userAuth.NewCreds,
			}
			user, err = a.createAccount(userAuth, &authCred)
			if err != nil {
				return "", "", nil, err
			}
		} else {
			return "", "", nil, log.WrapActionError(log.ActionValidate, model.TypeAuthCred, nil, err)
		}
	}

	claims := a.getStandardClaims("", userAuth.UserID, userAuth.Email, userAuth.Phone, "rokwire", orgID, appID, userAuth.Exp)
	token, err := a.buildAccessToken(claims, "", "all")
	if err != nil {
		return "", "", nil, log.WrapActionError("build", log.TypeToken, nil, err)
	}

	//TODO: Implement account management

	return token, userAuth.RefreshToken, user, nil
}

//Refresh refreshes an access token using a refresh token
//	Input:
//		refreshToken (string): Refresh token
//		l (*loglib.Log): Log object pointer for request
//	Returns:
//		Access token (string): Signed ROKWIRE access token to be used to authorize future requests
//		Refresh Token (string): Refresh token that can be sent to refresh the access token once it expires
func (a *Auth) Refresh(refreshToken string, l *log.Log) (string, string, error) {
	return "", "", log.NewError(log.Unimplemented)
}

//GetLoginUrl returns a pre-formatted login url for SSO providers
//	Input:
//		authType (string): Name of the authentication method for provided creds (eg. "email")
//		orgID (string): ID of the organization that the user is logging in to
//		appID (string): ID of the app/client that the user is logging in from
//		redirectUri (string): Registered redirect URI where client will receive response
//		l (*loglib.Log): Log object pointer for request
//	Returns:
//		Login URL (string): SSO provider login URL to be launched in a browser
//		Params (map[string]interface{}): Params to be sent in subsequent request (if necessary)
func (a *Auth) GetLoginUrl(authType string, orgID string, appID string, redirectUri string, l *log.Log) (string, map[string]interface{}, error) {
	auth, err := a.getAuthType(authType)
	if err != nil {
		return "", nil, log.WrapActionError(log.ActionLoadCache, typeAuthType, nil, err)
	}

	loginUrl, params, err := auth.getLoginUrl(orgID, appID, redirectUri, l)
	if err != nil {
		return "", nil, log.WrapActionError(log.ActionGet, "login url", nil, err)
	}

	return loginUrl, params, nil
}

//GetScopedAccessToken TODO
func (a *Auth) GetScopedAccessToken(claims tokenClaims, serviceID string, scope string) (string, error) {
	scopedClaims := a.getStandardClaims(claims.Subject, claims.UID, "", "", serviceID, claims.OrgID, claims.AppID, nil)
	return a.buildAccessToken(scopedClaims, "", scope)
}

//GetServiceRegistrations retrieves all service registrations
func (a *Auth) GetServiceRegistrations(serviceIDs []string) ([]authservice.ServiceReg, error) {
	return a.storage.FindServiceRegs(serviceIDs)
}

//RegisterService creates a new service registration
func (a *Auth) RegisterService(reg *authservice.ServiceReg) error {
	return a.storage.InsertServiceReg(reg)
}

//UpdateServiceRegistration updates an existing service registration
func (a *Auth) UpdateServiceRegistration(reg *authservice.ServiceReg) error {
	if reg.ServiceID == authServiceID || reg.ServiceID == a.serviceID {
		return log.NewErrorf("modifying service registration not allowed for service id %v", reg.ServiceID)
	}
	return a.storage.UpdateServiceReg(reg)
}

//DeregisterService deletes an existing service registration
func (a *Auth) DeregisterService(serviceID string) error {
	if serviceID == authServiceID || serviceID == a.serviceID {
		return log.NewErrorf("deregistering service not allowed for service id %v", serviceID)
	}
	return a.storage.DeleteServiceReg(serviceID)
}

//findAccount retrieves a user's account information
func (a *Auth) findAccount(userAuth *model.UserAuth) (*model.User, error) {
	return a.storage.FindUserByAccountID(userAuth.AccountID)
}

//createAccount creates a new user account
func (a *Auth) createAccount(userAuth *model.UserAuth, authCred *model.AuthCred) (*model.User, error) {
	return a.storage.InsertUser(userAuth, authCred)
}

//updateAccount updates a user's account information
func (a *Auth) updateAccount(user *model.User, newOrgData *map[string]interface{}) (*model.User, error) {
	return a.storage.UpdateUser(user, newOrgData)
}

//deleteAccount deletes a user account
func (a *Auth) deleteAccount(id string) error {
	return a.storage.DeleteUser(id)
}

//needsUserUpdate determines if user should be updated by userAuth (assumes userAuth is most up-to-date)
func (a *Auth) needsUserUpdate(userAuth *model.UserAuth, user *model.User) (*model.User, bool, bool) {
	update := false

	// account
	if userAuth.Email != user.Account.Email {
		user.Account.Email = userAuth.Email
		update = true
	}
	if userAuth.Phone != user.Account.Phone {
		user.Account.Phone = userAuth.Phone
		update = true
	}

	// profile
	if user.Profile.FirstName != userAuth.FirstName {
		user.Profile.FirstName = userAuth.FirstName
		update = true
	}
	if user.Profile.LastName != userAuth.LastName {
		user.Profile.LastName = userAuth.LastName
		update = true
	}

	// org data
	foundOrg := false
	for _, m := range user.OrganizationsMemberships {
		if m.Organization.ID == userAuth.OrgData["orgID"] {
			foundOrg = true
			if !reflect.DeepEqual(userAuth.OrgData, m.OrgUserData) {
				m.OrgUserData = userAuth.OrgData
				update = true
			}
		}
	}

	return user, update, !foundOrg
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

	return nil, log.DataError(log.StatusInvalid, typeAuthType, log.StringArgs(name))
}

func (a *Auth) buildAccessToken(claims tokenClaims, permissions string, scope string) (string, error) {
	claims.Purpose = "access"
	claims.Permissions = permissions
	claims.Scope = scope
	return a.generateToken(&claims)
}

func (a *Auth) buildCsrfToken(claims tokenClaims) (string, error) {
	claims.Purpose = "csrf"
	return a.generateToken(&claims)
}

func (a *Auth) getStandardClaims(sub string, uid string, email string, phone string, aud string, orgID string, appID string, exp *int64) tokenClaims {
	return tokenClaims{
		Claims: tokenauth.Claims{
			StandardClaims: jwt.StandardClaims{
				Audience:  aud,
				Subject:   sub,
				ExpiresAt: a.getExp(exp),
				IssuedAt:  time.Now().Unix(),
				Issuer:    a.host,
			}, OrgID: orgID, AppID: appID,
		}, UID: uid, Email: email, Phone: phone,
	}
}

func (a *Auth) generateToken(claims *tokenClaims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	kid, err := authutils.GetKeyFingerprint(&a.authPrivKey.PublicKey)
	if err != nil {
		return "", log.WrapActionError(log.ActionCompute, "fingerprint", log.StringArgs("auth key"), err)
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

//storeReg stores the service registration record
func (a *Auth) storeReg() error {
	pem, err := authutils.GetPubKeyPem(&a.authPrivKey.PublicKey)
	if err != nil {
		return log.WrapActionError(log.ActionEncode, "auth pub key", nil, err)
	}

	key := authservice.PubKey{KeyPem: pem, Alg: authKeyAlg}

	// Setup "auth" registration for token validation
	authReg := authservice.ServiceReg{ServiceID: authServiceID, Host: a.host, PubKey: &key}
	err = a.storage.SaveServiceReg(&authReg)
	if err != nil {
		return log.WrapActionError(log.ActionSave, model.TypeServiceReg, log.StringArgs(authServiceID), err)
	}

	// Setup core registration for signature validation
	coreReg := authservice.ServiceReg{ServiceID: a.serviceID, Host: a.host, PubKey: &key}
	err = a.storage.SaveServiceReg(&coreReg)
	if err != nil {
		return log.WrapActionError(log.ActionSave, model.TypeServiceReg, log.StringArgs(a.serviceID), err)
	}

	return nil
}

//LoadAuthConfigs loads the auth configs
func (a *Auth) LoadAuthConfigs() error {
	authConfigDocs, err := a.storage.LoadAuthConfigs()
	if err != nil {
		return log.WrapActionError(log.ActionFind, model.TypeAuthConfig, nil, err)
	}

	a.setAuthConfigs(authConfigDocs)

	return nil
}

func (a *Auth) getAuthConfig(orgID string, appID string, authType string) (*model.AuthConfig, error) {
	a.authConfigsLock.RLock()
	defer a.authConfigsLock.RUnlock()

	var authConfig *model.AuthConfig //to return

	errArgs := &log.FieldArgs{"org_id": orgID, "app_id": appID, "auth_type": authType}

	item, _ := a.authConfigs.Load(fmt.Sprintf("%s_%s_%s", orgID, appID, authType))
	if item != nil {
		authConfigFromCache, ok := item.(model.AuthConfig)
		if !ok {
			return nil, log.ActionError(log.ActionCast, model.TypeAuthConfig, errArgs)
		}
		authConfig = &authConfigFromCache
		return authConfig, nil
	}
	return nil, log.DataError(log.StatusMissing, model.TypeAuthConfig, errArgs)
}

func (a *Auth) setAuthConfigs(authConfigs *[]model.AuthConfig) {
	a.authConfigs = &syncmap.Map{}
	validate := validator.New()

	a.authConfigsLock.Lock()
	defer a.authConfigsLock.Unlock()
	for _, authConfig := range *authConfigs {
		err := validate.Struct(authConfig)
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
	return l.storage.FindServiceRegs(l.GetSubscribedServices())
}

//NewLocalServiceRegLoader creates and configures a new LocalServiceRegLoaderImpl instance
func NewLocalServiceRegLoader(storage Storage) *LocalServiceRegLoaderImpl {
	subscriptions := authservice.NewServiceRegSubscriptions([]string{"all"})
	return &LocalServiceRegLoaderImpl{storage: storage, ServiceRegSubscriptions: subscriptions}
}

//Storage interface to communicate with the storage
type Storage interface {
	FindUserByAccountID(accountID string) (*model.User, error)
	InsertUser(userAuth *model.UserAuth, authCred *model.AuthCred) (*model.User, error)
	UpdateUser(user *model.User, newOrgData *map[string]interface{}) (*model.User, error)
	DeleteUser(id string) error

	FindCredentials(orgID string, appID string, authType string, userID string) (*model.AuthCred, error)

	FindOrganization(id string) (*model.Organization, error)

	//ServiceRegs
	FindServiceRegs(serviceIDs []string) ([]authservice.ServiceReg, error)
	FindServiceReg(serviceID string) (*authservice.ServiceReg, error)
	InsertServiceReg(reg *authservice.ServiceReg) error
	UpdateServiceReg(reg *authservice.ServiceReg) error
	SaveServiceReg(reg *authservice.ServiceReg) error
	DeleteServiceReg(serviceID string) error

	//AuthConfigs
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

//OnServiceRegsUpdated notifies that a service registration has been updated
func (al *StorageListener) OnServiceRegsUpdated() {
	al.Auth.AuthService.LoadServices()
}
