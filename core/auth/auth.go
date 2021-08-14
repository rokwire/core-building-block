package auth

import (
	"core-building-block/core/model"
	"core-building-block/driven/storage"
	"core-building-block/utils"
	"crypto/rsa"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	"github.com/rokmetro/auth-library/authorization"
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

//Interface for authentication mechanisms
type authType interface {
	//check checks the validity of provided credentials
	check(creds string, orgID string, appID string, params string, l *logs.Log) (*model.UserAuth, error)
	//refresh refreshes the access token using provided refresh token
	refresh(params map[string]interface{}, orgID string, appID string, l *logs.Log) (*model.UserAuth, error)
	//getLoginUrl retrieves and pre-formats a login url and params for the SSO provider
	getLoginURL(orgID string, appID string, redirectURI string, l *logs.Log) (string, map[string]interface{}, error)
	//isGlobal returns whether an authType is orgID, appID independent
	isGlobal() bool
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

	err = auth.LoadAuthConfigs()
	if err != nil {
		logger.Warnf("NewAuth() failed to cache auth configs: %v", err)
	}

	return auth, nil
}

//GetHost returns the host/issuer of the auth service
func (a *Auth) GetHost() string {
	return a.host
}

//Login logs a user in using the specified credentials and authentication method
//	Input:
//		authType (string): Name of the authentication method for provided creds (eg. "email")
//		creds (string): Credentials/JSON encoded credential structure defined for the specified auth type
//		orgID (string): ID of the organization that the user is logging in to
//		appID (string): ID of the app/client that the user is logging in from
//		params (string): JSON encoded params defined by specified auth type
//		l (*logs.Log): Log object pointer for request
//	Returns:
//		Access token (string): Signed ROKWIRE access token to be used to authorize future requests
//		Refresh Token (string): Refresh token that can be sent to refresh the access token once it expires
//		User (User): User object for authenticated user
//		Params (interface{}): authType-specific set of parameters passed back to client
func (a *Auth) Login(authType string, creds string, orgID string, appID string, params string, l *logs.Log) (string, string, *model.User, interface{}, error) {
	var user *model.User
	var err error
	auth, err := a.getAuthType(authType)
	if err != nil {
		return "", "", nil, nil, errors.WrapErrorAction(logutils.ActionLoadCache, typeAuthType, nil, err)
	}

	userAuth, err := auth.check(creds, orgID, appID, params, l)
	if err != nil {
		return "", "", nil, nil, errors.WrapErrorAction(logutils.ActionValidate, "creds", nil, err)
	}

	if userAuth == nil || userAuth.Creds == nil {
		return "", "", nil, nil, errors.WrapErrorData(logutils.StatusInvalid, "user auth creds", nil, err)
	}

	//RefreshParams == nil indicates that a refresh token should not be generated
	refreshToken := ""
	hadRefresh := (userAuth.Creds.Refresh != nil)
	if userAuth.RefreshParams != nil {
		var expireTime *time.Time
		refreshToken, expireTime, err = a.buildRefreshToken()
		if err != nil {
			return "", "", nil, nil, err
		}

		refreshParams := model.AuthRefresh{CurrentToken: refreshToken, Expires: expireTime, Params: userAuth.RefreshParams}

		userAuth.Creds.Refresh = &refreshParams
	} else {
		userAuth.Creds.Refresh = nil
	}

	if len(userAuth.AccountID) > 0 {
		user, err = a.findAccount(userAuth)
		if err != nil {
			return "", "", nil, nil, err
		}
		user, update, newMembership := a.needsUserUpdate(userAuth, user)
		if update {
			var newMembershipOrgData *map[string]interface{}
			if newMembership {
				newMembershipOrgData = &userAuth.OrgData
			}
			_, err = a.updateAccount(user, newMembershipOrgData)
			if err != nil {
				return "", "", nil, nil, err
			}
		}

		if userAuth.Creds.Refresh != nil || hadRefresh {
			if auth.isGlobal() {
				err = a.storage.UpdateCredentials("", "", authType, userAuth.UserID, userAuth.Creds.Refresh)
			} else {
				err = a.storage.UpdateCredentials(orgID, appID, authType, userAuth.UserID, userAuth.Creds.Refresh)
			}
			if err != nil {
				return "", "", nil, nil, errors.WrapErrorAction(logutils.ActionUpdate, model.TypeAuthCred, nil, err)
			}
		}
	} else {
		user, err = a.createAccount(userAuth)
		if err != nil {
			return "", "", nil, nil, err
		}
	}

	claims := a.getStandardClaims(user.ID, userAuth.UserID, userAuth.Email, userAuth.Phone, "rokwire", orgID, appID, userAuth.Exp)
	token, err := a.buildAccessToken(claims, "", authorization.ScopeGlobal)
	if err != nil {
		return "", "", nil, nil, errors.WrapErrorAction("build", logutils.TypeToken, nil, err)
	}

	return token, refreshToken, user, userAuth.ResponseParams, nil
}

//Refresh refreshes an access token using a refresh token
//	Input:
//		refreshToken (string): Refresh token
//		l (*logs.Log): Log object pointer for request
//	Returns:
//		Access token (string): Signed ROKWIRE access token to be used to authorize future requests
//		Refresh token (string): Refresh token that can be sent to refresh the access token once it expires
//		Params (interface{}): authType-specific set of parameters passed back to client
func (a *Auth) Refresh(refreshToken string, l *logs.Log) (string, string, interface{}, error) {
	credentials, err := a.storage.FindCredentialsByRefreshToken(refreshToken)
	if err != nil {
		return "", "", nil, errors.WrapErrorAction("refreshing", logutils.TypeToken, nil, err)
	}
	if credentials == nil || credentials.Refresh == nil {
		return "", "", nil, errors.ErrorData(logutils.StatusMissing, model.TypeAuthRefresh, nil)
	}

	validate := validator.New()
	err = validate.Struct(credentials.Refresh)
	if err != nil {
		return "", "", nil, errors.WrapErrorAction(logutils.ActionValidate, typeAuthRefreshParams, nil, err)
	}

	if !credentials.Refresh.Expires.After(time.Now().UTC()) {
		return "", "", nil, errors.ErrorAction(logutils.ActionValidate, "refresh expiration", nil)
	}

	if refreshToken == credentials.Refresh.PreviousToken {
		err = a.storage.UpdateCredentials(credentials.OrgID, credentials.AppID, credentials.Type, credentials.UserID, nil)
		if err != nil {
			return "", "", nil, errors.WrapErrorAction(logutils.ActionValidate, "refresh reuse", nil, err)
		}
		return "", "", nil, errors.ErrorAction(logutils.ActionValidate, "refresh reuse", nil)
	}
	if refreshToken != credentials.Refresh.CurrentToken {
		return "", "", nil, errors.ErrorAction(logutils.ActionValidate, model.TypeRefreshToken, nil)
	}

	auth, err := a.getAuthType(credentials.Type)
	if err != nil {
		return "", "", nil, errors.WrapErrorAction(logutils.ActionLoadCache, typeAuthType, nil, err)
	}

	userAuth, err := auth.refresh(credentials.Refresh.Params, credentials.OrgID, credentials.AppID, l)
	if err != nil {
		return "", "", nil, errors.WrapErrorAction("refresh", logutils.TypeToken, nil, err)
	}

	if userAuth == nil || userAuth.Creds == nil {
		return "", "", nil, errors.WrapErrorData(logutils.StatusInvalid, "user auth creds", nil, err)
	}

	user, err := a.storage.FindUserByAccountID(credentials.AccountID)
	if err != nil {
		return "", "", nil, err
	}

	claims := a.getStandardClaims(user.ID, userAuth.UserID, user.Account.Email, user.Account.Phone, "rokwire", credentials.OrgID, credentials.AppID, userAuth.Exp)
	token, err := a.buildAccessToken(claims, "", authorization.ScopeGlobal)
	if err != nil {
		return "", "", nil, errors.WrapErrorAction(logutils.ActionCreate, logutils.TypeToken, nil, err)
	}

	newRefreshToken := ""
	if userAuth.Creds.Refresh != nil {
		var expireTime *time.Time
		newRefreshToken, expireTime, err = a.buildRefreshToken()
		if err != nil {
			return "", "", nil, errors.WrapErrorAction(logutils.ActionCreate, model.TypeRefreshToken, nil, err)
		}

		refresh := model.AuthRefresh{CurrentToken: newRefreshToken, PreviousToken: refreshToken, Expires: expireTime, Params: userAuth.RefreshParams}

		err = a.storage.UpdateCredentials(credentials.OrgID, credentials.AppID, credentials.Type, credentials.UserID, &refresh)
		if err != nil {
			return "", "", nil, err
		}
	}

	return token, newRefreshToken, userAuth.ResponseParams, nil
}

//GetLoginURL returns a pre-formatted login url for SSO providers
//	Input:
//		authType (string): Name of the authentication method for provided creds (eg. "email")
//		orgID (string): ID of the organization that the user is logging in to
//		appID (string): ID of the app/client that the user is logging in from
//		redirectURI (string): Registered redirect URI where client will receive response
//		l (*loglib.Log): Log object pointer for request
//	Returns:
//		Login URL (string): SSO provider login URL to be launched in a browser
//		Params (map[string]interface{}): Params to be sent in subsequent request (if necessary)
func (a *Auth) GetLoginURL(authType string, orgID string, appID string, redirectURI string, l *logs.Log) (string, map[string]interface{}, error) {
	auth, err := a.getAuthType(authType)
	if err != nil {
		return "", nil, errors.WrapErrorAction(logutils.ActionLoadCache, typeAuthType, nil, err)
	}

	loginURL, params, err := auth.getLoginURL(orgID, appID, redirectURI, l)
	if err != nil {
		return "", nil, errors.WrapErrorAction(logutils.ActionGet, "login url", nil, err)
	}

	return loginURL, params, nil
}

//AuthorizeService returns a scoped token for the specified service and the service registration record if authorized or
//	the service registration record if not. Passing "approvedScopes" will update the service authorization for this user and
//	return a scoped access token which reflects this change.
//	Input:
//		claims (tokenClaims): Claims from un-scoped user access token
//		serviceID (string): ID of the service to be authorized
//		approvedScopes ([]string): list of scope strings to be approved
//		l (*logs.Log): Log object pointer for request
//	Returns:
//		Access token (string): Signed scoped access token to be used to authorize requests to the specified service
//		Approved Scopes ([]authorization.Scope): The approved scopes included in the provided token
//		Service reg (*model.ServiceReg): The service registration record for the requested service
func (a *Auth) AuthorizeService(claims TokenClaims, serviceID string, approvedScopes []authorization.Scope, l *logs.Log) (string, []authorization.Scope, *model.ServiceReg, error) {
	var authorization model.ServiceAuthorization
	if approvedScopes != nil {
		//If approved scopes are being updated, save update and return token with updated scopes
		authorization = model.ServiceAuthorization{UserID: claims.Subject, ServiceID: serviceID, Scopes: approvedScopes}
		err := a.storage.SaveServiceAuthorization(&authorization)
		if err != nil {
			return "", nil, nil, errors.WrapErrorAction(logutils.ActionSave, model.TypeServiceAuthorization, nil, err)
		}
	} else {
		serviceAuth, err := a.storage.FindServiceAuthorization(claims.Subject, serviceID)
		if err != nil {
			return "", nil, nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeServiceAuthorization, nil, err)
		}

		if serviceAuth != nil {
			//If service authorization exists, generate token with saved scopes
			authorization = *serviceAuth
		} else {
			//If no service authorization exists, return the service registration record
			reg, err := a.storage.FindServiceReg(serviceID)
			if err != nil {
				return "", nil, nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeServiceReg, nil, err)
			}
			return "", nil, reg, nil
		}
	}

	token, err := a.GetScopedAccessToken(claims, serviceID, authorization.Scopes)
	if err != nil {
		return "", nil, nil, errors.WrapErrorAction("build", logutils.TypeToken, nil, err)
	}

	return token, authorization.Scopes, nil, nil
}

//GetScopedAccessToken returns a scoped access token with the requested scopes
func (a *Auth) GetScopedAccessToken(claims TokenClaims, serviceID string, scopes []authorization.Scope) (string, error) {
	scopeStrings := []string{}
	services := []string{serviceID}
	for _, scope := range scopes {
		scopeStrings = append(scopeStrings, scope.String())
		if !authutils.ContainsString(services, scope.ServiceID) {
			services = append(services, scope.ServiceID)
		}
	}

	aud := strings.Join(services, ",")
	scope := strings.Join(scopeStrings, " ")

	scopedClaims := a.getStandardClaims(claims.Subject, "", "", "", aud, claims.OrgID, claims.AppID, nil)
	return a.buildAccessToken(scopedClaims, "", scope)
}

//GetServiceRegistrations retrieves all service registrations
func (a *Auth) GetServiceRegistrations(serviceIDs []string) ([]model.ServiceReg, error) {
	return a.storage.FindServiceRegs(serviceIDs)
}

//RegisterService creates a new service registration
func (a *Auth) RegisterService(reg *model.ServiceReg) error {
	if reg != nil && !reg.FirstParty && strings.Contains(strings.ToUpper(reg.Name), rokwireKeyword) {
		return errors.Newf("the name of a third-party service may not contain \"%s\"", rokwireKeyword)
	}
	return a.storage.InsertServiceReg(reg)
}

//UpdateServiceRegistration updates an existing service registration
func (a *Auth) UpdateServiceRegistration(reg *model.ServiceReg) error {
	if reg != nil {
		if reg.Registration.ServiceID == authServiceID || reg.Registration.ServiceID == a.serviceID {
			return errors.Newf("modifying service registration not allowed for service id %v", reg.Registration.ServiceID)
		}
		if !reg.FirstParty && strings.Contains(strings.ToUpper(reg.Name), rokwireKeyword) {
			return errors.Newf("the name of a third-party service may not contain \"%s\"", rokwireKeyword)
		}
	}
	return a.storage.UpdateServiceReg(reg)
}

//DeregisterService deletes an existing service registration
func (a *Auth) DeregisterService(serviceID string) error {
	if serviceID == authServiceID || serviceID == a.serviceID {
		return errors.Newf("deregistering service not allowed for service id %v", serviceID)
	}
	return a.storage.DeleteServiceReg(serviceID)
}

//GetAuthKeySet generates a JSON Web Key Set for auth service registration
func (a *Auth) GetAuthKeySet() (*model.JSONWebKeySet, error) {
	authReg, err := a.AuthService.GetServiceReg("auth")
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionLoadCache, model.TypeServiceReg, logutils.StringArgs("auth"), err)
	}

	if authReg == nil || authReg.PubKey == nil || authReg.PubKey.Key == nil {
		return nil, errors.ErrorData(logutils.StatusMissing, model.TypePubKey, nil)
	}

	jwk, err := model.JSONWebKeyFromPubKey(authReg.PubKey)
	if err != nil || jwk == nil {
		return nil, errors.WrapErrorAction(logutils.ActionCreate, model.TypeJSONWebKey, nil, err)
	}

	return &model.JSONWebKeySet{Keys: []model.JSONWebKey{*jwk}}, nil
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
func (a *Auth) updateAccount(user *model.User, newOrgData *map[string]interface{}) (*model.User, error) {
	return a.storage.UpdateUser(user, newOrgData)
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
	if len(user.Account.Email) == 0 {
		user.Account.Email = userAuth.Email
		update = true
	}
	if len(user.Account.Phone) == 0 {
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
		if m.Organization.ID == userAuth.OrgData["org_id"] {
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

//LoadAuthConfigs loads the auth configs
func (a *Auth) LoadAuthConfigs() error {
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

//Storage interface to communicate with the storage
type Storage interface {
	//Users
	FindUserByAccountID(accountID string) (*model.User, error)
	InsertUser(user *model.User, authCred *model.AuthCreds) (*model.User, error)
	UpdateUser(user *model.User, newOrgData *map[string]interface{}) (*model.User, error)
	DeleteUser(id string) error

	//Organizations
	FindOrganization(id string) (*model.Organization, error)

	//Credentials
	FindCredentialsByRefreshToken(token string) (*model.AuthCreds, error)
	FindCredentials(orgID string, appID string, authType string, userID string) (*model.AuthCreds, error)
	UpdateCredentials(orgID string, appID string, authType string, userID string, refresh *model.AuthRefresh) error

	//ServiceRegs
	FindServiceRegs(serviceIDs []string) ([]model.ServiceReg, error)
	FindServiceReg(serviceID string) (*model.ServiceReg, error)
	InsertServiceReg(reg *model.ServiceReg) error
	UpdateServiceReg(reg *model.ServiceReg) error
	SaveServiceReg(reg *model.ServiceReg) error
	DeleteServiceReg(serviceID string) error

	//AuthConfigs
	FindAuthConfig(orgID string, appID string, authType string) (*model.AuthConfig, error)
	LoadAuthConfigs() (*[]model.AuthConfig, error)

	//ServiceAuthorizations
	FindServiceAuthorization(userID string, orgID string) (*model.ServiceAuthorization, error)
	SaveServiceAuthorization(authorization *model.ServiceAuthorization) error
	DeleteServiceAuthorization(userID string, orgID string) error
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
