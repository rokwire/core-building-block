package auth

import (
	"core-building-block/core/model"
	"core-building-block/driven/profilebb"
	"core-building-block/driven/storage"
	"core-building-block/utils"
	"crypto/rsa"
	"encoding/json"
	"fmt"
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
	"gopkg.in/gomail.v2"

	"github.com/rokmetro/logging-library/errors"
	"github.com/rokmetro/logging-library/logs"
	"github.com/rokmetro/logging-library/logutils"
)

const (
	authServiceID  string = "auth"
	authKeyAlg     string = "RS256"
	rokwireKeyword string = "ROKWIRE"

	typeMail              logutils.MessageDataType = "mail"
	typeAuthType          logutils.MessageDataType = "auth type"
	typeExternalAuthType  logutils.MessageDataType = "external auth type"
	typeAnonymousAuthType logutils.MessageDataType = "anonymous auth type"
	typeAuth              logutils.MessageDataType = "auth"
	typeAuthRefreshParams logutils.MessageDataType = "auth refresh params"

	refreshTokenLength       int = 256
	refreshTokenExpiry       int = 7 * 24 * 60
	refreshTokenDeletePeriod int = 2
	refreshTokenLimit        int = 3
)

//Auth represents the auth functionality unit
type Auth struct {
	storage Storage
	emailer Emailer

	logger *logs.Logger

	authTypes          map[string]authType
	externalAuthTypes  map[string]externalAuthType
	anonymousAuthTypes map[string]anonymousAuthType

	authPrivKey *rsa.PrivateKey

	AuthService *authservice.AuthService

	serviceID   string
	host        string //Service host
	minTokenExp int64  //Minimum access token expiration time in minutes
	maxTokenExp int64  //Maximum access token expiration time in minutes

	profileBB ProfileBuildingBlock

	emailFrom       string
	emailDialer     *gomail.Dialer
	cachedAuthTypes *syncmap.Map //cache auth types
	authTypesLock   *sync.RWMutex

	cachedIdentityProviders *syncmap.Map //cache identityProviders
	identityProvidersLock   *sync.RWMutex

	cachedApplicationsOrganizations *syncmap.Map //cache applications organizations
	applicationsOrganizationsLock   *sync.RWMutex

	apiKeys     *syncmap.Map //cache api keys / api_key (string) -> APIKey
	apiKeysLock *sync.RWMutex

	//delete refresh tokens timer
	deleteRefreshTimer *time.Timer
	timerDone          chan bool
}

//NewAuth creates a new auth instance
func NewAuth(serviceID string, host string, authPrivKey *rsa.PrivateKey, storage Storage, emailer Emailer, minTokenExp *int64, maxTokenExp *int64, twilioAccountSID string,
	twilioToken string, twilioServiceSID string, profileBB *profilebb.Adapter, smtpHost string, smtpPortNum int, smtpUser string, smtpPassword string, smtpFrom string, logger *logs.Logger) (*Auth, error) {
	if minTokenExp == nil {
		var minTokenExpVal int64 = 5
		minTokenExp = &minTokenExpVal
	}

	if maxTokenExp == nil {
		var maxTokenExpVal int64 = 60
		maxTokenExp = &maxTokenExpVal
	}
	//maybe set up from config collection for diff types of auth
	emailDialer := gomail.NewDialer(smtpHost, smtpPortNum, smtpUser, smtpPassword)

	authTypes := map[string]authType{}
	externalAuthTypes := map[string]externalAuthType{}
	anonymousAuthTypes := map[string]anonymousAuthType{}

	cachedAuthTypes := &syncmap.Map{}
	authTypesLock := &sync.RWMutex{}

	cachedIdentityProviders := &syncmap.Map{}
	identityProvidersLock := &sync.RWMutex{}

	cachedApplicationsOrganizations := &syncmap.Map{}
	applicationsOrganizationsLock := &sync.RWMutex{}

	apiKeys := &syncmap.Map{}
	apiKeysLock := &sync.RWMutex{}

	timerDone := make(chan bool)

	auth := &Auth{storage: storage, emailer: emailer, logger: logger, authTypes: authTypes, externalAuthTypes: externalAuthTypes, anonymousAuthTypes: anonymousAuthTypes,
		authPrivKey: authPrivKey, AuthService: nil, serviceID: serviceID, host: host, minTokenExp: *minTokenExp,
		maxTokenExp: *maxTokenExp, profileBB: profileBB, cachedIdentityProviders: cachedIdentityProviders, identityProvidersLock: identityProvidersLock,
		cachedAuthTypes: cachedAuthTypes, authTypesLock: authTypesLock,
		cachedApplicationsOrganizations: cachedApplicationsOrganizations, applicationsOrganizationsLock: applicationsOrganizationsLock,
		timerDone: timerDone, emailDialer: emailDialer, emailFrom: smtpFrom, apiKeys: apiKeys, apiKeysLock: apiKeysLock}

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
	initUsernameAuth(auth)
	initEmailAuth(auth)
	initPhoneAuth(auth, twilioAccountSID, twilioToken, twilioServiceSID)
	initFirebaseAuth(auth)
	initAPIKeyAuth(auth)
	initSignatureAuth(auth)

	initOidcAuth(auth)
	initSamlAuth(auth)

	err = auth.cacheAuthTypes()
	if err != nil {
		logger.Warnf("NewAuth() failed to cache auth types: %v", err)
	}

	err = auth.cacheIdentityProviders()
	if err != nil {
		logger.Warnf("NewAuth() failed to cache identity providers: %v", err)
	}

	err = auth.cacheApplicationsOrganizations()
	if err != nil {
		logger.Warnf("NewAuth() failed to cache applications organizations: %v", err)
	}

	err = auth.cacheAPIKeys()
	if err != nil {
		logger.Warnf("NewAuth() failed to cache api keys: %v", err)
	}

	return auth, nil

}

func (a *Auth) applyExternalAuthType(authType model.AuthType, appType model.ApplicationType, appOrg model.ApplicationOrganization,
	creds string, params string, regProfile model.Profile, regPreferences map[string]interface{}, l *logs.Log) (*model.Account, *model.AccountAuthType, interface{}, error) {
	var account *model.Account
	var accountAuthType *model.AccountAuthType
	var profile *model.Profile
	var preferences map[string]interface{}
	var extParams interface{}

	//external auth type
	authImpl, err := a.getExternalAuthTypeImpl(authType)
	if err != nil {
		return nil, nil, nil, errors.WrapErrorAction(logutils.ActionLoadCache, typeExternalAuthType, nil, err)
	}

	//1. get the user from the external system
	var externalUser *model.ExternalSystemUser
	externalUser, extParams, err = authImpl.externalLogin(authType, appType, appOrg, creds, params, l)
	if err != nil {
		return nil, nil, nil, errors.WrapErrorAction("logging in", "external user", nil, err)
	}

	//2. check if the user exists
	account, err = authImpl.userExist(externalUser.Identifier, authType, appType, appOrg, l)
	if err != nil {
		return nil, nil, nil, errors.WrapErrorData(logutils.StatusMissing, "external user", nil, err)
	}
	if account != nil {
		//user exists, just check if need to update it

		//get the current external user
		accountAuthType, err = a.findAccountAuthType(account, &authType, externalUser.Identifier)
		if err != nil {
			return nil, nil, nil, err
		}
		currentDataMap := accountAuthType.Params["user"]
		currentDataJSON, err := utils.ConvertToJSON(currentDataMap)
		if err != nil {
			return nil, nil, nil, errors.WrapErrorAction(logutils.ActionMarshal, "external user", nil, err)
		}
		var currentData *model.ExternalSystemUser
		err = json.Unmarshal(currentDataJSON, &currentData)
		if err != nil {
			return nil, nil, nil, errors.ErrorAction(logutils.ActionUnmarshal, "external user", nil)
		}

		newData := *externalUser

		//check if external system user needs to be updated
		if !currentData.Equals(newData) {
			//there is changes so we need to update it
			accountAuthType.Params["user"] = newData
			err = a.storage.UpdateAccountAuthType(*accountAuthType)
			if err != nil {
				return nil, nil, nil, errors.WrapErrorAction(logutils.ActionUpdate, model.TypeUserAuth, nil, err)
			}
		}
	} else {
		//user does not exist, we need to register it

		//TODO: use shared profile
		useSharedProfile := false

		identifier := externalUser.Identifier
		accountAuthTypeParams := map[string]interface{}{}
		accountAuthTypeParams["user"] = externalUser

		accountAuthType, _, profile, preferences, err = a.prepareRegistrationData(authType, identifier, accountAuthTypeParams, nil, nil, regProfile, regPreferences, l)

		if err != nil {
			return nil, nil, nil, errors.WrapErrorAction("error preparing registration data", model.TypeUserAuth, nil, err)
		}

		account, err = a.registerUser(appOrg, *accountAuthType, nil, useSharedProfile, *profile, preferences, l)
		if err != nil {
			return nil, nil, nil, errors.WrapErrorAction(logutils.ActionRegister, model.TypeAccount, nil, err)
		}
	}

	return account, accountAuthType, extParams, nil
}

func (a *Auth) applyAnonymousAuthType(authType model.AuthType, appType model.ApplicationType, appOrg model.ApplicationOrganization, creds string, params string, l *logs.Log) (string, interface{}, error) { //auth type
	authImpl, err := a.getAnonymousAuthTypeImpl(authType)
	if err != nil {
		return "", nil, errors.WrapErrorAction(logutils.ActionLoadCache, typeAnonymousAuthType, nil, err)
	}

	//Check the credentials
	anonymousID, anonymousParams, err := authImpl.checkCredentials(authType, appType, appOrg, creds, l)
	if err != nil {
		return "", nil, errors.WrapErrorAction(logutils.ActionValidate, model.TypeCreds, nil, err)
	}

	return anonymousID, anonymousParams, nil
}

func (a *Auth) applyAuthType(authType model.AuthType, appType model.ApplicationType, appOrg model.ApplicationOrganization,
	creds string, params string, regProfile model.Profile, regPreferences map[string]interface{}, l *logs.Log) (string, *model.Account, *model.AccountAuthType, error) {
	var message string
	var account *model.Account
	var accountAuthType *model.AccountAuthType
	var credential *model.Credential
	var profile *model.Profile
	var preferences map[string]interface{}

	//auth type
	authImpl, err := a.getAuthTypeImpl(authType)
	if err != nil {
		return "", nil, nil, errors.WrapErrorAction(logutils.ActionLoadCache, typeAuthType, nil, err)
	}

	//check if the user exists check
	account, accountAuthType, err = authImpl.userExist(authType, appType, appOrg, creds, l)
	if err != nil {
		return "", nil, nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeAccount, nil, err)
	}

	accountExists := (account != nil && accountAuthType != nil)

	//check if it is sign in or sign up
	isSignUp, err := a.isSignUp(accountExists, params, l)
	if err != nil {
		return "", nil, nil, errors.WrapErrorAction("error checking is sign up", "", nil, err)
	}
	if isSignUp {
		if accountExists {
			return "", nil, nil, errors.New("account already exists")
		}

		//TODO: use shared profile
		useSharedProfile := false

		credentialID, _ := uuid.NewUUID()
		credID := credentialID.String()

		//apply sign up
		message, identifier, credentialValue, err := authImpl.signUp(authType, appType, appOrg, creds, params, credentialID.String(), l)
		if err != nil {
			return "", nil, nil, errors.Wrap("error signing up", err)
		}

		accountAuthType, credential, profile, preferences, err = a.prepareRegistrationData(authType, *identifier, nil, &credID, credentialValue, regProfile, regPreferences, l)
		if err != nil {
			return "", nil, nil, errors.WrapErrorAction("error preparing registration data", model.TypeUserAuth, nil, err)
		}

		account, err = a.registerUser(appOrg, *accountAuthType, credential, useSharedProfile, *profile, preferences, l)
		if err != nil {
			return "", nil, nil, errors.WrapErrorAction(logutils.ActionRegister, model.TypeAccount, nil, err)
		}

		return message, account, accountAuthType, nil
	}

	//apply sign in
	if !accountExists {
		return "", nil, nil, errors.ErrorData(logutils.StatusMissing, model.TypeAccount, nil)
	}

	//2. it seems the user exist, now check the credentials
	message, validCredentials, err := authImpl.checkCredentials(*accountAuthType, creds, l)
	if err != nil {
		return "", nil, nil, errors.WrapErrorAction(logutils.ActionValidate, model.TypeCredential, nil, err)
	}
	if !*validCredentials {
		return "", nil, nil, errors.ErrorData(logutils.StatusInvalid, model.TypeCredential, nil)
	}

	return message, account, accountAuthType, nil
}

//isSignUp checks if the operation is sign in or sign up
// 	first check if the client has set sign_up field
//	if sign_up field has not been sent then check if the user exists
func (a *Auth) isSignUp(accountExists bool, params string, l *logs.Log) (bool, error) {
	//check if sign_up field has been passed
	useSignUpFieldCheck := strings.Contains(params, "sign_up")

	if useSignUpFieldCheck {
		type signUpParams struct {
			SignUp bool `json:"sign_up"`
		}
		var sParams signUpParams
		err := json.Unmarshal([]byte(params), &sParams)
		if err != nil {
			return false, errors.WrapErrorAction(logutils.ActionUnmarshal, "sign up params", nil, err)
		}

		return sParams.SignUp, nil
	}

	if accountExists {
		//the user exists, so return false
		return false, nil
	}

	//the user does not exists, so it has to register
	return true, nil
}

func (a *Auth) findAccountAuthType(account *model.Account, authType *model.AuthType, identifier string) (*model.AccountAuthType, error) {
	if account == nil {
		return nil, errors.ErrorData(logutils.StatusMissing, model.TypeAccount, nil)
	}

	if authType == nil {
		return nil, errors.ErrorData(logutils.StatusMissing, typeAuthType, nil)
	}

	accountAuthType := account.GetAccountAuthType(authType.ID, identifier)
	if accountAuthType == nil {
		return nil, errors.New("for some reasons the user auth type is nil")
	}

	accountAuthType.AuthType = *authType

	if accountAuthType.Credential != nil {
		//populate credentials in accountAuthType
		credential, err := a.storage.FindCredential(accountAuthType.Credential.ID)
		if err != nil {
			return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeCredential, nil, err)
		}
		accountAuthType.Credential = credential
	}

	return accountAuthType, nil
}

func (a *Auth) applyLogin(account model.Account, accountAuthType model.AccountAuthType, appType model.ApplicationType, params interface{}, l *logs.Log) (*string, *string, error) {
	//TODO add login session which keeps the tokens, the auth type params(illinois tokens), eventually the device etc
	//TODO think if to return the whole login session object..

	//access token
	orgID := account.Organization.ID
	appID := account.Application.ID
	claims := a.getStandardClaims(account.ID, accountAuthType.Identifier, account.Profile.Email, account.Profile.Phone, "rokwire", orgID, appID, accountAuthType.AuthType.Code, nil, false)
	permissions := account.GetPermissionNames()
	accessToken, err := a.buildAccessToken(claims, strings.Join(permissions, ","), authorization.ScopeGlobal)
	if err != nil {
		return nil, nil, errors.WrapErrorAction(logutils.ActionCreate, logutils.TypeToken, nil, err)
	}

	//refresh token
	refreshToken, _, err := a.buildRefreshToken()
	if err != nil {
		return nil, nil, errors.WrapErrorAction(logutils.ActionCreate, logutils.TypeToken, nil, err)
	}

	return &accessToken, &refreshToken, nil
}

func (a *Auth) applyAnonymousLogin(authType *model.AuthType, anonymousID string, orgID string, appType model.ApplicationType, params interface{}, l *logs.Log) (*string, error) {
	//access token
	appTypeIdentifier := appType.Identifier
	claims := a.getStandardClaims(anonymousID, "", "", "", "rokwire", orgID, appTypeIdentifier, authType.Code, nil, true)
	accessToken, err := a.buildAccessToken(claims, "", authorization.ScopeGlobal)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionCreate, logutils.TypeToken, nil, err)
	}

	return &accessToken, nil
}

func (a *Auth) prepareRegistrationData(authType model.AuthType, identifier string, accountAuthTypeParams map[string]interface{},
	credentialID *string, credentialValue map[string]interface{},
	profile model.Profile, preferences map[string]interface{}, l *logs.Log) (*model.AccountAuthType, *model.Credential, *model.Profile, map[string]interface{}, error) {
	now := time.Now()

	//account auth type
	accountAuthTypeID, _ := uuid.NewUUID()
	active := true
	active2FA := false
	accountAuthType := &model.AccountAuthType{ID: accountAuthTypeID.String(), AuthType: authType,
		Identifier: identifier, Params: accountAuthTypeParams, Credential: nil, Active: active, Active2FA: active2FA, DateCreated: now}

	//credential
	var credential *model.Credential
	if credentialID != nil && credentialValue != nil {
		//there is a credential
		credential = &model.Credential{ID: *credentialID, AccountsAuthTypes: []model.AccountAuthType{*accountAuthType}, Value: credentialValue, Verified: false,
			AuthType: authType, DateCreated: now, DateUpdated: &now}

		accountAuthType.Credential = credential
	}

	///profile and preferences
	//get profile BB data
	gotProfile, gotPreferences, err := a.getProfileBBData(authType, identifier, l)
	if err != nil {
		args := &logutils.FieldArgs{"auth_type": authType.Code, "identifier": identifier}
		return nil, nil, nil, nil, errors.WrapErrorAction(logutils.ActionGet, "error getting profile BB data", args, err)
	}
	readyProfile := profile
	//if there is profile bb data
	if gotProfile != nil {
		readyProfile = a.prepareProfile(profile, *gotProfile, l)
	}
	readyPreferences := preferences
	//if there is preferences bb data
	if gotPreferences != nil {
		readyPreferences = a.preparePreferences(preferences, gotPreferences, l)
	}

	//generate profile ID
	profileID, _ := uuid.NewUUID()
	readyProfile.ID = profileID.String()
	//date created
	readyProfile.DateCreated = time.Now()
	///

	return accountAuthType, credential, &readyProfile, readyPreferences, nil
}

func (a *Auth) prepareProfile(clientData model.Profile, profileBBData model.Profile, l *logs.Log) model.Profile {
	//TODO - merge from both sources
	return profileBBData
}

func (a *Auth) preparePreferences(clientData map[string]interface{}, profileBBData map[string]interface{}, l *logs.Log) map[string]interface{} {
	//TODO - merge from both sources
	return profileBBData
}

func (a *Auth) getProfileBBData(authType model.AuthType, identifier string, l *logs.Log) (*model.Profile, map[string]interface{}, error) {
	var profile *model.Profile
	var preferences map[string]interface{}
	var err error

	profileSearch := make(map[string]string)
	if authType.Code == "twilio_phone" {
		profileSearch["phone"] = identifier
	}
	if authType.Code == "illinois_oidc" {
		profileSearch["uin"] = identifier
	}
	if profileSearch != nil {
		profile, preferences, err = a.profileBB.GetProfileBBData(profileSearch, l)
		if err != nil {
			return nil, nil, err
		}
	}
	return profile, preferences, nil
}

//registerUser registers account for an organization in an application
//	Input:
//		appOrg (ApplicationOrganization): The application organization which the user is registering in
//		accountAuthType (AccountAuthType): In which way the user will be logging in the application
//		credential (*Credential): Information for the user
//		useSharedProfile (bool): It says if the system to look if the user has account in another application in the system and to use its profile instead of creating a new profile
//		preferences (map[string]interface{}): Preferences of the user
//		profile (Profile): Information for the user
//		l (*logs.Log): Log object pointer for request
//	Returns:
//		Registered account (Account): Registered Account object
func (a *Auth) registerUser(appOrg model.ApplicationOrganization, accountAuthType model.AccountAuthType, credential *model.Credential,
	useSharedProfile bool, profile model.Profile, preferences map[string]interface{}, l *logs.Log) (*model.Account, error) {

	//TODO - analyse what should go in one transaction

	//TODO - ignore useSharedProfile for now
	accountID, _ := uuid.NewUUID()
	application := appOrg.Application
	organization := appOrg.Organization
	authTypes := []model.AccountAuthType{accountAuthType}

	account := model.Account{ID: accountID.String(), Application: application, Organization: organization,
		Permissions: nil, Roles: nil, Groups: nil, AuthTypes: authTypes, Preferences: preferences, Profile: profile, DateCreated: time.Now()} // Anonymous: accountAuthType.AuthType.IsAnonymous

	insertedAccount, err := a.storage.InsertAccount(account)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionInsert, model.TypeAccount, nil, err)
	}

	if credential != nil {
		//TODO - in one transaction
		if err = a.storage.InsertCredential(credential, nil); err != nil {
			return nil, errors.WrapErrorAction(logutils.ActionInsert, model.TypeCredential, nil, err)
		}
	}

	return insertedAccount, nil
}

func (a *Auth) registerAuthType(name string, auth authType) error {
	if _, ok := a.authTypes[name]; ok {
		return errors.Newf("the requested auth type name has already been registered: %s", name)
	}

	a.authTypes[name] = auth

	return nil
}

func (a *Auth) registerExternalAuthType(name string, auth externalAuthType) error {
	if _, ok := a.externalAuthTypes[name]; ok {
		return errors.Newf("the requested external auth type name has already been registered: %s", name)
	}

	a.externalAuthTypes[name] = auth

	return nil
}

func (a *Auth) registerAnonymousAuthType(name string, auth anonymousAuthType) error {
	if _, ok := a.anonymousAuthTypes[name]; ok {
		return errors.Newf("the requested anonymous auth type name has already been registered: %s", name)
	}

	a.anonymousAuthTypes[name] = auth

	return nil
}

func (a *Auth) validateAuthType(authenticationType string, appTypeIdentifier string, orgID string) (*model.AuthType, *model.ApplicationType, *model.ApplicationOrganization, error) {
	//get the auth type
	authType, err := a.getCachedAuthType(authenticationType)
	if err != nil {
		return nil, nil, nil, errors.WrapErrorAction(logutils.ActionValidate, typeAuthType, logutils.StringArgs(authenticationType), err)
	}

	//get the app type
	applicationType, err := a.storage.FindApplicationTypeByIdentifier(appTypeIdentifier)
	if err != nil {
		return nil, nil, nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeApplicationType, logutils.StringArgs(appTypeIdentifier), err)

	}
	if applicationType == nil {
		return nil, nil, nil, errors.ErrorData(logutils.StatusMissing, model.TypeApplicationType, logutils.StringArgs(appTypeIdentifier))
	}

	//get the app org
	applicationID := applicationType.Application.ID
	appOrg, err := a.getCachedApplicationOrganization(applicationID, orgID)
	if err != nil {
		return nil, nil, nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeApplicationOrganization, logutils.StringArgs(orgID), err)
	}

	//check if the auth type is supported for this application and organization
	if !appOrg.IsAuthTypeSupported(*applicationType, *authType) {
		return nil, nil, nil, errors.ErrorAction(logutils.ActionValidate, "not supported auth type for application and organization", nil)
	}

	return authType, applicationType, appOrg, nil
}

func (a *Auth) getAuthTypeImpl(authType model.AuthType) (authType, error) {
	if auth, ok := a.authTypes[authType.Code]; ok {
		return auth, nil
	}

	return nil, errors.ErrorData(logutils.StatusInvalid, typeAuthType, logutils.StringArgs(authType.Code))
}

func (a *Auth) getExternalAuthTypeImpl(authType model.AuthType) (externalAuthType, error) {
	key := authType.Code

	//illinois_oidc, other_oidc
	if strings.HasSuffix(authType.Code, "_oidc") {
		key = "oidc"
	}

	if auth, ok := a.externalAuthTypes[key]; ok {
		return auth, nil
	}

	return nil, errors.ErrorData(logutils.StatusInvalid, typeExternalAuthType, logutils.StringArgs(key))
}

func (a *Auth) getAnonymousAuthTypeImpl(authType model.AuthType) (anonymousAuthType, error) {
	if auth, ok := a.anonymousAuthTypes[authType.Code]; ok {
		return auth, nil
	}

	return nil, errors.ErrorData(logutils.StatusInvalid, typeAnonymousAuthType, logutils.StringArgs(authType.Code))
}

func (a *Auth) buildAccessToken(claims tokenauth.Claims, permissions string, scope string) (string, error) {
	claims.Purpose = "access"
	if !claims.Anonymous {
		claims.Permissions = permissions
	}
	claims.Scope = scope
	return a.generateToken(&claims)
}

func (a *Auth) buildCsrfToken(claims tokenauth.Claims) (string, error) {
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

func (a *Auth) getStandardClaims(sub string, uid string, email string, phone string, aud string, orgID string, appID string, authType string, exp *int64, anonymous bool) tokenauth.Claims {
	return tokenauth.Claims{
		StandardClaims: jwt.StandardClaims{
			Audience:  aud,
			Subject:   sub,
			ExpiresAt: a.getExp(exp),
			IssuedAt:  time.Now().Unix(),
			Issuer:    a.host,
		}, OrgID: orgID, AppID: appID, AuthType: authType, UID: uid, Email: email, Phone: phone, Anonymous: anonymous,
	}
}

func (a *Auth) generateToken(claims *tokenauth.Claims) (string, error) {
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

//cacheAuthTypes caches the auth types
func (a *Auth) cacheAuthTypes() error {
	a.logger.Info("cacheAuthTypes..")

	authTypes, err := a.storage.LoadAuthTypes()
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionFind, model.TypeAuthType, nil, err)
	}

	a.setCachedAuthTypes(authTypes)

	return nil
}

func (a *Auth) setCachedAuthTypes(authProviders []model.AuthType) {
	a.authTypesLock.Lock()
	defer a.authTypesLock.Unlock()

	a.cachedAuthTypes = &syncmap.Map{}
	validate := validator.New()

	for _, authType := range authProviders {
		err := validate.Struct(authType)
		if err == nil {
			//we will get it by id and code as well
			a.cachedAuthTypes.Store(authType.ID, authType)
			a.cachedAuthTypes.Store(authType.Code, authType)
		} else {
			a.logger.Errorf("failed to validate and cache auth type with code %s: %s", authType.Code, err.Error())
		}
	}
}

func (a *Auth) getCachedAuthType(key string) (*model.AuthType, error) {
	a.authTypesLock.RLock()
	defer a.authTypesLock.RUnlock()

	errArgs := &logutils.FieldArgs{"code or id": key}

	item, _ := a.cachedAuthTypes.Load(key)
	if item != nil {
		authType, ok := item.(model.AuthType)
		if !ok {
			return nil, errors.ErrorAction(logutils.ActionCast, model.TypeAuthType, errArgs)
		}
		return &authType, nil
	}
	return nil, errors.ErrorData(logutils.StatusMissing, model.TypeOrganization, errArgs)
}

//cacheIdentityProviders caches the identity providers
func (a *Auth) cacheIdentityProviders() error {
	a.logger.Info("cacheIdentityProviders..")

	identityProviders, err := a.storage.LoadIdentityProviders()
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionFind, model.TypeIdentityProvider, nil, err)
	}

	a.setCachedIdentityProviders(identityProviders)

	return nil
}

func (a *Auth) setCachedIdentityProviders(identityProviders []model.IdentityProvider) {
	a.identityProvidersLock.Lock()
	defer a.identityProvidersLock.Unlock()

	a.cachedIdentityProviders = &syncmap.Map{}
	validate := validator.New()

	for _, idPr := range identityProviders {
		err := validate.Struct(idPr)
		if err == nil {
			a.cachedIdentityProviders.Store(idPr.ID, idPr)
		} else {
			a.logger.Errorf("failed to validate and cache identity provider with id %s: %s", idPr.ID, err.Error())
		}
	}
}

func (a *Auth) getCachedIdentityProviderConfig(id string, appTypeID string) (*model.IdentityProviderConfig, error) {
	a.identityProvidersLock.RLock()
	defer a.identityProvidersLock.RUnlock()

	errArgs := &logutils.FieldArgs{"id": id, "app_type_id": appTypeID}

	item, _ := a.cachedIdentityProviders.Load(id)
	if item != nil {
		identityProvider, ok := item.(model.IdentityProvider)
		if !ok {
			return nil, errors.ErrorAction(logutils.ActionCast, model.TypeIdentityProvider, errArgs)
		}
		//find the identity provider config
		for _, idPrConfig := range identityProvider.Configs {
			if idPrConfig.AppTypeID == appTypeID {
				return &idPrConfig, nil
			}
		}
		return nil, errors.ErrorData(logutils.StatusMissing, model.TypeIdentityProviderConfig, errArgs)
	}
	return nil, errors.ErrorData(logutils.StatusMissing, model.TypeOrganization, errArgs)
}

func (a *Auth) cacheAPIKeys() error {
	apiKeys, err := a.storage.LoadAPIKeys()
	if err != nil {
		return errors.WrapErrorAction("loading", model.TypeAPIKey, nil, err)
	}
	a.setCachedAPIKeys(apiKeys)
	return nil
}

func (a *Auth) setCachedAPIKeys(apiKeys []model.APIKey) {
	a.apiKeysLock.Lock()
	defer a.apiKeysLock.Unlock()

	a.apiKeys = &syncmap.Map{}
	for _, apiKey := range apiKeys {
		a.apiKeys.Store(apiKey.Key, apiKey)
	}
}

func (a *Auth) getCachedAPIKey(key string) (*model.APIKey, error) {
	a.apiKeysLock.RLock()
	defer a.apiKeysLock.RUnlock()

	item, _ := a.apiKeys.Load(key)
	if item != nil {
		if key, ok := item.(model.APIKey); ok {
			return &key, nil
		}
		return nil, errors.ErrorData(logutils.StatusInvalid, model.TypeAPIKey, nil)
	}
	return nil, errors.ErrorAction(logutils.ActionLoadCache, model.TypeAPIKey, nil)
}

//cacheApplicationsOrganizations caches the applications organizations
func (a *Auth) cacheApplicationsOrganizations() error {
	a.logger.Info("cacheApplicationsOrganizations..")

	applicationsOrganizations, err := a.storage.LoadApplicationsOrganizations()
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionFind, model.TypeApplicationOrganization, nil, err)
	}

	a.setCachedApplicationsOrganizations(applicationsOrganizations)

	return nil
}

func (a *Auth) setCachedApplicationsOrganizations(applicationsOrganization []model.ApplicationOrganization) {
	a.applicationsOrganizationsLock.Lock()
	defer a.applicationsOrganizationsLock.Unlock()

	a.cachedApplicationsOrganizations = &syncmap.Map{}
	validate := validator.New()

	for _, appOrg := range applicationsOrganization {
		err := validate.Struct(appOrg)
		if err == nil {
			key := fmt.Sprintf("%s_%s", appOrg.Application.ID, appOrg.Organization.ID)
			a.cachedApplicationsOrganizations.Store(key, appOrg)
		} else {
			a.logger.Errorf("failed to validate and cache applications organizations with ids %s-%s: %s",
				appOrg.Application.ID, appOrg.Organization.ID, err.Error())
		}
	}
}

func (a *Auth) getCachedApplicationOrganization(appID string, orgID string) (*model.ApplicationOrganization, error) {
	a.applicationsOrganizationsLock.RLock()
	defer a.applicationsOrganizationsLock.RUnlock()

	key := fmt.Sprintf("%s_%s", appID, orgID)
	errArgs := &logutils.FieldArgs{"key": key}

	item, _ := a.cachedApplicationsOrganizations.Load(key)
	if item != nil {
		appOrg, ok := item.(model.ApplicationOrganization)
		if !ok {
			return nil, errors.ErrorAction(logutils.ActionCast, model.TypeApplicationOrganization, errArgs)
		}
		return &appOrg, nil
	}
	return nil, errors.ErrorData(logutils.StatusMissing, model.TypeApplicationOrganization, errArgs)
}

func (a *Auth) checkRefreshTokenLimit(orgID string, appID string, credsID string) error {
	tokens, err := a.storage.LoadRefreshTokens(orgID, appID, credsID)
	if err != nil {
		return errors.WrapErrorAction("limit checking", model.TypeAuthRefresh, nil, err)
	}
	if len(tokens) >= refreshTokenLimit {
		err = a.storage.DeleteRefreshToken(tokens[0].CurrentToken)
		if err != nil {
			return errors.WrapErrorAction("limit checking", model.TypeAuthRefresh, nil, err)
		}
	}
	return nil
}

func (a *Auth) setupDeleteRefreshTimer() {
	//cancel if active
	if a.deleteRefreshTimer != nil {
		a.timerDone <- true
		a.deleteRefreshTimer.Stop()
	}

	a.deleteExpiredRefreshTokens()
}

func (a *Auth) deleteExpiredRefreshTokens() {
	now := time.Now().UTC()
	err := a.storage.DeleteExpiredRefreshTokens(&now)
	if err != nil {
		a.logger.Error(err.Error())
	}

	duration := time.Hour * time.Duration(refreshTokenDeletePeriod)
	a.deleteRefreshTimer = time.NewTimer(duration)
	select {
	case <-a.deleteRefreshTimer.C:
		// timer expired
		a.deleteRefreshTimer = nil

		a.deleteExpiredRefreshTokens()
	case <-a.timerDone:
		// timer aborted
		a.deleteRefreshTimer = nil
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
	for i, serviceReg := range regs {
		reg := serviceReg.Registration
		reg.PubKey.LoadKeyFromPem()
		authRegs[i] = reg
	}

	return authRegs, nil
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

//OnAuthTypesUpdated notifies that auth types have been has been updated
func (al *StorageListener) OnAuthTypesUpdated() {
	al.auth.cacheAuthTypes()
}

//OnIdentityProvidersUpdated notifies that identity providers have been updated
func (al *StorageListener) OnIdentityProvidersUpdated() {
	al.auth.cacheIdentityProviders()
}

//OnAPIKeysUpdated notifies api keys have been updated
func (al *StorageListener) OnAPIKeysUpdated() {
	al.auth.cacheAPIKeys()
}

//OnApplicationsOrganizationsUpdated notifies that applications organizations have been updated
func (al *StorageListener) OnApplicationsOrganizationsUpdated() {
	al.auth.cacheApplicationsOrganizations()
}

//OnServiceRegsUpdated notifies that a service registration has been updated
func (al *StorageListener) OnServiceRegsUpdated() {
	al.auth.AuthService.LoadServices()
}
