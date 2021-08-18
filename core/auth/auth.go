package auth

import (
	"core-building-block/core/model"
	"core-building-block/driven/storage"
	"core-building-block/utils"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"reflect"
	"sync"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	"github.com/rokmetro/auth-library/authservice"
	"github.com/rokmetro/auth-library/authutils"
	"github.com/rokmetro/auth-library/tokenauth"
	"golang.org/x/sync/syncmap"
	"gopkg.in/go-playground/validator.v9"

	"github.com/rokmetro/logging-library/errors"
	"github.com/rokmetro/logging-library/logs"
	"github.com/rokmetro/logging-library/logutils"
)

const (
	authServiceID  string = "auth"
	authKeyAlg     string = "RS256"
	rokwireKeyword string = "ROKWIRE"

	typeAuthType          logutils.MessageDataType = "auth type"
	typeAuth              logutils.MessageDataType = "auth"
	typeAuthRefreshParams logutils.MessageDataType = "auth refresh params"

	refreshTokenLength int   = 256
	refreshTokenExpiry int   = 7 * 24 * 60
	accessTokenExpiry  int64 = 30
)

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

//TokenClaims is a temporary claims model to provide backwards compatibility
//TODO: Once the profile has been transferred and the new user ID scheme has been adopted across all services
//		this should be replaced by tokenauth.Claims directly
type TokenClaims struct {
	tokenauth.Claims
	UID   string `json:"uid,omitempty"`
	Email string `json:"email,omitempty"`
	Phone string `json:"phone,omitempty"`
}

//NewAuth creates a new auth instance
func NewAuth(serviceID string, host string, authPrivKey *rsa.PrivateKey, storage Storage, minTokenExp *int64, maxTokenExp *int64, logger *logs.Logger) (*Auth, error) {
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
		return nil, errors.WrapErrorAction(logutils.ActionSave, "reg", nil, err)
	}

	serviceLoader := NewLocalServiceRegLoader(storage)

	authService, err := authservice.NewAuthService(serviceID, host, serviceLoader)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionInitialize, "auth service", nil, err)
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

	err = auth.loadAuthConfigs()
	if err != nil {
		logger.Warnf("NewAuth() failed to cache auth configs: %v", err)
	}

	return auth, nil
}

//findAccount retrieves a user's account information
func (a *Auth) findAccount(userAuth *model.UserAuth) (*model.User, error) {
	return a.storage.FindUserByAccountID(userAuth.AccountID)
}

//createAccount creates a new user account
func (a *Auth) createAccount(userAuth *model.UserAuth) (*model.User, error) {
	if userAuth == nil {
		return nil, errors.ErrorData(logutils.StatusMissing, model.TypeUserAuth, nil)
	}

	newUser, err := a.setupUser(userAuth)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionCreate, model.TypeUser, nil, err)
	}
	return a.storage.InsertUser(newUser, userAuth.Creds)
}

//updateAccount updates a user's account information
func (a *Auth) updateAccount(user *model.User, orgID string, newOrgData *map[string]interface{}) (*model.User, error) {
	return a.storage.UpdateUser(user, orgID, newOrgData)
}

//deleteAccount deletes a user account
func (a *Auth) deleteAccount(id string) error {
	return a.storage.DeleteUser(id)
}

func (a *Auth) setupUser(userAuth *model.UserAuth) (*model.User, error) {
	if userAuth == nil {
		return nil, errors.ErrorData(logutils.StatusInvalid, logutils.TypeArg, logutils.StringArgs(model.TypeUserAuth))
	}

	now := time.Now().UTC()
	newID, err := uuid.NewUUID()
	if err != nil {
		return nil, errors.WrapErrorAction("generate", "uuid", logutils.StringArgs("user_id"), err)
	}
	newUser := model.User{ID: newID.String(), DateCreated: now}

	accountID, err := uuid.NewUUID()
	if err != nil {
		return nil, errors.WrapErrorAction("generate", "uuid", logutils.StringArgs("account_id"), err)
	}
	newUser.Account = model.UserAccount{ID: accountID.String(), Email: userAuth.Email, Phone: userAuth.Phone, Username: userAuth.UserID, DateCreated: now}

	profileID, err := uuid.NewUUID()
	if err != nil {
		return nil, errors.WrapErrorAction("generate", "uuid", logutils.StringArgs("profile_id"), err)
	}
	newUser.Profile = model.UserProfile{ID: profileID.String(), FirstName: userAuth.FirstName, LastName: userAuth.LastName, DateCreated: now}

	if userAuth.OrgID != "" {
		membershipID, err := uuid.NewUUID()
		if err != nil {
			return nil, errors.WrapErrorAction("generate", "uuid", logutils.StringArgs("membership_id"), err)
		}

		organization, err := a.storage.FindOrganization(userAuth.OrgID)
		if err != nil {
			return nil, err
		}
		newOrgMembership := model.OrganizationMembership{ID: membershipID.String(), Organization: *organization, OrgUserData: userAuth.OrgData, DateCreated: now}

		// TODO:
		// maybe set groups based on organization populations

		newUser.OrganizationsMemberships = []model.OrganizationMembership{newOrgMembership}
	}

	//TODO: populate new device with device information (search for existing device first)
	deviceID, err := uuid.NewUUID()
	if err != nil {
		return nil, errors.WrapErrorAction("generate", "uuid", logutils.StringArgs("device_id"), err)
	}
	newDevice := model.Device{ID: deviceID.String(), Type: "other", Users: []model.User{newUser}, DateCreated: now}
	newUser.Devices = []model.Device{newDevice}

	return &newUser, nil
}

//needsUserUpdate determines if user should be updated by userAuth (assumes userAuth is most up-to-date)
func (a *Auth) needsUserUpdate(userAuth *model.UserAuth, user *model.User) (*model.User, bool, bool) {
	update := false

	// account
	if len(user.Account.Email) == 0 && len(userAuth.Email) > 0 {
		user.Account.Email = userAuth.Email
		update = true
	}
	if len(user.Account.Phone) == 0 && len(userAuth.Phone) > 0 {
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
		if m.Organization.ID == userAuth.OrgID {
			foundOrg = true

			orgDataBytes, err := json.Marshal(m.OrgUserData)
			if err != nil {
				break
			}
			var orgData map[string]interface{}
			json.Unmarshal(orgDataBytes, &orgData)

			if !reflect.DeepEqual(userAuth.OrgData, orgData) {
				m.OrgUserData = userAuth.OrgData
				update = true
			}
			break
		}
	}

	return user, update, !foundOrg
}

func (a *Auth) registerAuthType(name string, auth authType) error {
	if _, ok := a.authTypes[name]; ok {
		return errors.Newf("the requested auth type name has already been registered: %s", name)
	}

	a.authTypes[name] = auth

	return nil
}

func (a *Auth) getAuthType(name string) (authType, error) {
	if auth, ok := a.authTypes[name]; ok {
		return auth, nil
	}

	return nil, errors.ErrorData(logutils.StatusInvalid, typeAuthType, logutils.StringArgs(name))
}

func (a *Auth) buildAccessToken(claims TokenClaims, permissions string, scope string) (string, error) {
	claims.Purpose = "access"
	claims.Permissions = permissions
	claims.Scope = scope
	return a.generateToken(&claims)
}

func (a *Auth) buildCsrfToken(claims TokenClaims) (string, error) {
	claims.Purpose = "csrf"
	return a.generateToken(&claims)
}

func (a *Auth) buildRefreshToken() (string, *time.Time, error) {
	newToken, err := utils.GenerateRandomString(refreshTokenLength)
	if err != nil {
		return "", nil, errors.WrapErrorAction(logutils.ActionCompute, logutils.TypeToken, nil, err)
	}

	expireTime := time.Now().UTC().Add(time.Minute * time.Duration(refreshTokenExpiry))
	return newToken, &expireTime, nil
}

func (a *Auth) getStandardClaims(sub string, uid string, email string, phone string, aud string, orgID string, appID string, exp *int64) TokenClaims {
	return TokenClaims{
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

func (a *Auth) generateToken(claims *TokenClaims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	kid, err := authutils.GetKeyFingerprint(&a.authPrivKey.PublicKey)
	if err != nil {
		return "", errors.WrapErrorAction(logutils.ActionCompute, "fingerprint", logutils.StringArgs("auth key"), err)
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
		return errors.WrapErrorAction(logutils.ActionEncode, model.TypePubKey, logutils.StringArgs("auth"), err)
	}

	key := authservice.PubKey{KeyPem: pem, Alg: authKeyAlg}

	// Setup "auth" registration for token validation
	authReg := model.ServiceReg{Registration: authservice.ServiceReg{ServiceID: authServiceID, Host: a.host, PubKey: &key},
		Name: "ROKWIRE Auth Service", Description: "The Auth Service is a subsystem of the Core Building Block that manages authentication and authorization.", FirstParty: true}
	err = a.storage.SaveServiceReg(&authReg)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionSave, model.TypeServiceReg, logutils.StringArgs(authServiceID), err)
	}

	// Setup core registration for signature validation
	coreReg := model.ServiceReg{Registration: authservice.ServiceReg{ServiceID: a.serviceID, Host: a.host, PubKey: &key},
		Name: "ROKWIRE Core Building Block", Description: "The Core Building Block manages user, auth, and organization data for the ROKWIRE platform.", FirstParty: true}
	err = a.storage.SaveServiceReg(&coreReg)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionSave, model.TypeServiceReg, logutils.StringArgs(a.serviceID), err)
	}

	return nil
}

//loadAuthConfigs loads the auth configs
func (a *Auth) loadAuthConfigs() error {
	authConfigDocs, err := a.storage.LoadAuthConfigs()
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionFind, model.TypeAuthConfig, nil, err)
	}

	a.setAuthConfigs(authConfigDocs)

	return nil
}

func (a *Auth) getAuthConfig(orgID string, appID string, authType string) (*model.AuthConfig, error) {
	a.authConfigsLock.RLock()
	defer a.authConfigsLock.RUnlock()

	var authConfig *model.AuthConfig //to return

	errArgs := &logutils.FieldArgs{"org_id": orgID, "app_id": appID, "auth_type": authType}

	item, _ := a.authConfigs.Load(fmt.Sprintf("%s_%s_%s", orgID, appID, authType))
	if item != nil {
		authConfigFromCache, ok := item.(model.AuthConfig)
		if !ok {
			return nil, errors.ErrorAction(logutils.ActionCast, model.TypeAuthConfig, errArgs)
		}
		authConfig = &authConfigFromCache
		return authConfig, nil
	}
	return nil, errors.ErrorData(logutils.StatusMissing, model.TypeAuthConfig, errArgs)
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
	regs, err := l.storage.FindServiceRegs(l.GetSubscribedServices())
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeServiceReg, nil, err)
	}

	authRegs := make([]authservice.ServiceReg, len(regs))
	serviceErrors := map[string]error{}
	for i, serviceReg := range regs {
		reg := serviceReg.Registration
		err = reg.PubKey.LoadKeyFromPem()
		if err != nil {
			serviceErrors[reg.ServiceID] = err
		}
		authRegs[i] = reg
	}

	err = nil
	if len(serviceErrors) > 0 {
		err = fmt.Errorf("error loading services: %v", serviceErrors)
	}

	return authRegs, err
}

//NewLocalServiceRegLoader creates and configures a new LocalServiceRegLoaderImpl instance
func NewLocalServiceRegLoader(storage Storage) *LocalServiceRegLoaderImpl {
	subscriptions := authservice.NewServiceRegSubscriptions([]string{"all"})
	return &LocalServiceRegLoaderImpl{storage: storage, ServiceRegSubscriptions: subscriptions}
}

//StorageListener represents storage listener implementation for the auth package
type StorageListener struct {
	auth *Auth
	storage.DefaultListenerImpl
}

//OnAuthConfigUpdated notifies that an auth config has been updated
func (al *StorageListener) OnAuthConfigUpdated() {
	al.auth.loadAuthConfigs()
}

//OnServiceRegsUpdated notifies that a service registration has been updated
func (al *StorageListener) OnServiceRegsUpdated() {
	al.auth.AuthService.LoadServices()
}
