// Copyright 2022 Board of Trustees of the University of Illinois.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package auth

import (
	"core-building-block/core/model"
	"core-building-block/driven/phoneverifier"
	"core-building-block/driven/storage"
	"core-building-block/utils"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	"github.com/rokwire/core-auth-library-go/v3/authorization"
	"github.com/rokwire/core-auth-library-go/v3/authservice"
	"github.com/rokwire/core-auth-library-go/v3/authutils"
	"github.com/rokwire/core-auth-library-go/v3/keys"
	"github.com/rokwire/core-auth-library-go/v3/sigauth"
	"github.com/rokwire/core-auth-library-go/v3/tokenauth"
	"golang.org/x/sync/syncmap"
	"gopkg.in/go-playground/validator.v9"

	"github.com/rokwire/logging-library-go/v2/errors"
	"github.com/rokwire/logging-library-go/v2/logs"
	"github.com/rokwire/logging-library-go/v2/logutils"
)

const (
	//ServiceAuthTypeCore core auth type
	ServiceAuthTypeCore string = "core"

	authServiceID  string = "auth"
	rokwireKeyword string = "ROKWIRE"

	rokwireTokenAud string = "rokwire"

	allServices string = "all"

	// AdminScopePrefix is the prefix on scope resources used to indicate that the scope is intended for administration
	AdminScopePrefix string = "admin_"
	// UpdateScopesPermission is the permission that allows an admin to update account/role scopes
	UpdateScopesPermission string = "update_auth_scopes"

	defaultIllinoisOIDCIdentifier string = "uin"
	illinoisOIDCCode              string = "illinois_oidc"

	serviceAESKey string = "service_aes_key"

	typeMail              logutils.MessageDataType = "mail"
	typeIdentifierType    logutils.MessageDataType = "identifier type"
	typeExternalAuthType  logutils.MessageDataType = "external auth type"
	typeAnonymousAuthType logutils.MessageDataType = "anonymous auth type"
	typeServiceAuthType   logutils.MessageDataType = "service auth type"
	typeAuth              logutils.MessageDataType = "auth"
	typeAuthRefreshParams logutils.MessageDataType = "auth refresh params"

	typeVerificationCode string = "verification code"

	operationSignIn    string = "sign-in"
	operationAppSignUp string = "app-sign-up"
	operationOrgSignUp string = "org-sign-up"

	refreshTokenLength int = 256

	sessionDeletePeriod int = 24 // hours
	maxSessionsDelete   int = 250

	sessionIDRateLimit  int = 5
	sessionIDRatePeriod int = 5 // minutes

	loginStateLength   int = 128
	loginStateDuration int = 5 // minutes

	maxMfaAttempts    int = 5
	mfaCodeExpiration int = 5 // minutes
	mfaCodeMax        int = 1000000
)

// Auth represents the auth functionality unit
type Auth struct {
	storage       Storage
	emailer       Emailer
	phoneVerifier PhoneVerifier

	logger *logs.Logger

	identifierTypes    map[string]identifierType
	authTypes          map[string]authType
	externalAuthTypes  map[string]externalAuthType
	anonymousAuthTypes map[string]anonymousAuthType
	serviceAuthTypes   map[string]serviceAuthType
	mfaTypes           map[string]mfaType

	currentAuthPrivKey *keys.PrivKey
	oldAuthPrivKey     *keys.PrivKey
	serviceAESKey      []byte

	ServiceRegManager *authservice.ServiceRegManager
	SignatureAuth     *sigauth.SignatureAuth

	serviceID string
	host      string //Service host

	defaultAccessTokenExpirationPolicy model.AccessTokenExpirationPolicy

	profileBB  ProfileBuildingBlock
	identityBB IdentityBuildingBlock

	cachedIdentityProviders *syncmap.Map //cache identityProviders
	identityProvidersLock   *sync.RWMutex

	apiKeys     *syncmap.Map //cache api keys / api_key (string) -> APIKey
	apiKeysLock *sync.RWMutex

	//delete sessions timer
	deleteSessionsTimer     *time.Timer
	deleteSessionsTimerDone chan bool

	version string
}

// NewAuth creates a new auth instance
func NewAuth(serviceID string, host string, currentAuthPrivKey *keys.PrivKey, oldAuthPrivKey *keys.PrivKey, authService *authservice.AuthService, storage Storage, emailer Emailer,
	phoneVerifier PhoneVerifier, profileBB ProfileBuildingBlock, defaultTokenExp *int, minTokenExp *int, maxTokenExp *int, supportLegacySigs bool, version string, logger *logs.Logger) (*Auth, error) {
	defaultTokenExpVal := 30
	if defaultTokenExp != nil {
		defaultTokenExpVal = *defaultTokenExp
	}

	minTokenExpVal := 5
	if minTokenExp != nil {
		minTokenExpVal = *minTokenExp
	}

	maxTokenExpVal := 60
	if maxTokenExp != nil {
		maxTokenExpVal = *maxTokenExp
	}

	defaultAccessTokenExpirationPolicy := model.AccessTokenExpirationPolicy{
		DefaultExp: defaultTokenExpVal,
		MinExp:     minTokenExpVal,
		MaxExp:     maxTokenExpVal,
	}

	identifierTypes := map[string]identifierType{}
	authTypes := map[string]authType{}
	externalAuthTypes := map[string]externalAuthType{}
	anonymousAuthTypes := map[string]anonymousAuthType{}
	serviceAuthTypes := map[string]serviceAuthType{}
	mfaTypes := map[string]mfaType{}

	cachedIdentityProviders := &syncmap.Map{}
	identityProvidersLock := &sync.RWMutex{}

	apiKeys := &syncmap.Map{}
	apiKeysLock := &sync.RWMutex{}

	deleteSessionsTimerDone := make(chan bool)

	auth := &Auth{storage: storage, emailer: emailer, phoneVerifier: phoneVerifier, logger: logger, identifierTypes: identifierTypes, authTypes: authTypes,
		externalAuthTypes: externalAuthTypes, anonymousAuthTypes: anonymousAuthTypes, serviceAuthTypes: serviceAuthTypes, mfaTypes: mfaTypes,
		currentAuthPrivKey: currentAuthPrivKey, oldAuthPrivKey: oldAuthPrivKey, ServiceRegManager: nil, serviceID: serviceID, host: host,
		defaultAccessTokenExpirationPolicy: defaultAccessTokenExpirationPolicy, profileBB: profileBB, cachedIdentityProviders: cachedIdentityProviders,
		identityProvidersLock: identityProvidersLock, apiKeys: apiKeys, apiKeysLock: apiKeysLock, deleteSessionsTimerDone: deleteSessionsTimerDone, version: version}

	err := auth.verifyServiceAESKey()
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionVerify, "service AES key", nil, err)
	}

	err = auth.storeCoreRegs()
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionSave, model.TypeServiceReg, nil, err)
	}
	auth.storeCoreServiceAccount()

	serviceRegLoader := NewLocalServiceRegLoader(storage)

	// Instantiate a ServiceRegManager to manage the service registration data loaded by serviceRegLoader
	serviceRegManager, err := authservice.NewServiceRegManager(authService, serviceRegLoader, true)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionInitialize, "service reg manager", nil, err)
	}

	auth.ServiceRegManager = serviceRegManager

	signatureAuth, err := sigauth.NewSignatureAuth(currentAuthPrivKey, serviceRegManager, true, supportLegacySigs)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionInitialize, "signature auth", nil, err)
	}

	auth.SignatureAuth = signatureAuth

	// identifier types
	initUsernameIdentifier(auth)
	initEmailIdentifier(auth)
	initPhoneIdentifier(auth)
	initExternalIdentifier(auth)

	// auth types
	initAnonymousAuth(auth)
	initPasswordAuth(auth)
	initCodeAuth(auth)
	initWebAuthnAuth(auth)
	// initFirebaseAuth(auth)
	// initSignatureAuth(auth)

	// external auth types
	initOidcAuth(auth)
	initSamlAuth(auth)

	// service auth types
	initStaticTokenServiceAuth(auth)
	initSignatureServiceAuth(auth)

	// mfa types
	initTotpMfa(auth)
	initEmailMfa(auth)
	initPhoneMfa(auth)
	initRecoveryMfa(auth)

	err = auth.cacheIdentityProviders()
	if err != nil {
		logger.Warnf("NewAuth() failed to cache identity providers: %v", err)
	}

	err = auth.cacheAPIKeys()
	if err != nil {
		logger.Warnf("NewAuth() failed to cache api keys: %v", err)
	}

	return auth, nil

}

// SetIdentityBB sets the identity BB adapter
func (a *Auth) SetIdentityBB(identityBB IdentityBuildingBlock) {
	a.identityBB = identityBB
}

func (a *Auth) applyExternalAuthType(supportedAuthType model.SupportedAuthType, appType model.ApplicationType, appOrg model.ApplicationOrganization, creds string, params string, clientVersion *string,
	regProfile model.Profile, privacy model.Privacy, regPreferences map[string]interface{}, admin bool, l *logs.Log) (map[string]interface{}, *model.Account, []model.MFAType, error) {
	var newAccount *model.Account
	var mfaTypes []model.MFAType

	//external auth type
	authImpl, err := a.getExternalAuthTypeImpl(supportedAuthType.AuthType)
	if err != nil {
		return nil, nil, nil, errors.WrapErrorAction(logutils.ActionLoadCache, typeExternalAuthType, nil, err)
	}

	//1. get the user from the external system
	//var externalUser *model.ExternalSystemUser
	externalUser, extParams, externalCreds, err := authImpl.externalLogin(supportedAuthType.AuthType, appType, appOrg, creds, params, l)
	if err != nil {
		return nil, nil, nil, errors.WrapErrorAction("logging in", "external user", nil, err)
	}

	//2. find the account for the org and the user identity
	// get the correct code for the external identifier from the external IDs map
	code := ""
	for k, v := range externalUser.ExternalIDs {
		if v == externalUser.Identifier {
			code = k
		}
	}
	if code == "" && externalUser.Email == externalUser.Identifier {
		code = IdentifierTypeEmail
	}

	account, err := a.storage.FindAccount(nil, code, externalUser.Identifier, &appOrg.Organization.ID, nil) // do not provide an appOrgID because we want to know if there is an account in the organization with the same identifier
	if err != nil {
		return nil, nil, nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeAccount, nil, err)
	}
	a.setLogContext(account, l)

	//3. check if it is operationSignIn or operationOrgSignUp or operationAppSignUp
	operation, err := a.determineOperation(account, appOrg.ID)
	if err != nil {
		return nil, nil, nil, errors.WrapErrorAction(logutils.ActionVerify, "determine operation external", nil, err)
	}
	//4. apply operation
	switch operation {
	case operationSignIn:
		canSignIn := a.canSignIn(account, code, externalUser.Identifier, appOrg.ID)
		if !canSignIn {
			return nil, nil, nil, errors.ErrorData(logutils.StatusInvalid, model.TypeAccount, &logutils.FieldArgs{"app_org_id": appOrg.ID, "code": code, "identifier": externalUser.Identifier})
		}

		//account exists
		newAccount, err = a.applySignInExternal(account, supportedAuthType, appOrg, *externalUser, externalCreds, l)
		if err != nil {
			return nil, nil, nil, errors.WrapErrorAction(logutils.ActionApply, "external sign in", nil, err)
		}
		mfaTypes = account.GetVerifiedMFATypes()

		//TODO: make sure we do not return any refresh tokens in extParams
		return extParams, newAccount, mfaTypes, nil
	case operationAppSignUp:
		if admin {
			return nil, nil, nil, errors.ErrorData(logutils.StatusInvalid, "sign up", &logutils.FieldArgs{"code": code, "identifier": externalUser.Identifier,
				"app_org_id": appOrg.ID, "admin": true}).SetStatus(utils.ErrorStatusNotAllowed)
		}

		//We have prepared this operation as it is based on the tenants accounts but for now we disable it
		//as we do not use it(yet) and better not to introduce additional complexity.
		//Also this would trigger client updates as well for supporting this
		return nil, nil, nil, errors.ErrorData(logutils.StatusDisabled, "app sign up", nil)
	case operationOrgSignUp:
		if admin {
			return nil, nil, nil, errors.ErrorData(logutils.StatusInvalid, "sign up", &logutils.FieldArgs{"code": code, "identifier": externalUser.Identifier,
				"app_org_id": appOrg.ID, "admin": true}).SetStatus(utils.ErrorStatusNotAllowed)
		}

		//user does not exist, we need to register it
		newAccount, err = a.applyOrgSignUpExternal(nil, supportedAuthType, appOrg, *externalUser, externalCreds, regProfile, privacy, regPreferences, clientVersion, l)
		if err != nil {
			return nil, nil, nil, errors.WrapErrorAction(logutils.ActionApply, "org external sign up", nil, err)
		}

		//TODO: make sure we do not return any refresh tokens in extParams
		return extParams, newAccount, mfaTypes, nil
	}

	return nil, nil, nil, errors.ErrorData(logutils.StatusInvalid, typeExternalAuthType+" operation", nil)
}

func (a *Auth) applySignInExternal(account *model.Account, supportedAuthType model.SupportedAuthType, appOrg model.ApplicationOrganization,
	externalUser model.ExternalSystemUser, externalCreds string, l *logs.Log) (*model.Account, error) {
	var accountAuthTypes []model.AccountAuthType
	var err error

	//find account auth type (there should only be one account auth type with matching auth type code)
	accountAuthTypes, err = a.findAccountAuthTypesAndCredentials(account, supportedAuthType)
	if err != nil {
		return nil, err
	}
	if len(accountAuthTypes) != 1 {
		return nil, errors.ErrorData(logutils.StatusInvalid, model.TypeAccountAuthType,
			&logutils.FieldArgs{"count": len(accountAuthTypes), "auth_type_id": supportedAuthType.AuthType.ID, "identifier": externalUser.Identifier})
	}

	//check if need to update the account data
	newAccount, err := a.updateExternalUserIfNeeded(accountAuthTypes[0], externalUser, supportedAuthType.AuthType, appOrg, externalCreds, l)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionUpdate, model.TypeExternalSystemUser, nil, err)
	}

	if newAccount != nil {
		newAccount.SortAccountAuthTypes(accountAuthTypes[0].ID, "")
		newAccount.SortAccountIdentifiers(externalUser.Identifier)
	}

	return newAccount, nil
}

func (a *Auth) applyOrgSignUpExternal(context storage.TransactionContext, supportedAuthType model.SupportedAuthType, appOrg model.ApplicationOrganization, externalUser model.ExternalSystemUser,
	externalCreds string, regProfile model.Profile, privacy model.Privacy, regPreferences map[string]interface{}, clientVersion *string, l *logs.Log) (*model.Account, error) {
	//1. prepare external admin user data
	identifiers, aatParams, profile, preferences, err := a.prepareExternalUserData(supportedAuthType.AuthType, externalUser, regProfile, regPreferences, l)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionPrepare, "external admin user data", nil, err)
	}

	identityProviderID, ok := supportedAuthType.AuthType.Params["identity_provider"].(string)
	if !ok {
		return nil, errors.ErrorData(logutils.StatusMissing, "identity provider id", nil)
	}
	identityProviderSetting := appOrg.FindIdentityProviderSetting(identityProviderID)
	if identityProviderSetting == nil {
		return nil, errors.ErrorData(logutils.StatusMissing, model.TypeIdentityProviderSetting, nil)
	}

	var identityBBProfile *model.Profile
	if identityProviderSetting.IdentityBBBaseURL != "" {
		identityBBProfile, err = a.identityBB.GetUserProfile(identityProviderSetting.IdentityBBBaseURL, externalUser, externalCreds, l)
		if err != nil {
			l.WarnError(logutils.MessageAction(logutils.StatusError, "syncing", "identity bb data", nil), err)
		}
	}

	//2. apply profile data from the external user if not provided
	newProfile, err := a.applyProfileDataFromExternalUser(*profile, externalUser, nil, identityBBProfile, false)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionApply, "profile data from external user", nil, err)
	}
	if newProfile != nil {
		profile = newProfile
	}

	//3. roles and groups mapping
	externalRoles, externalGroups, err := a.getExternalUserAuthorization(externalUser, identityProviderSetting)
	if err != nil {
		l.WarnError(logutils.MessageActionError(logutils.ActionGet, "external authorization", nil), err)
	}

	//4. register the account
	//External and anonymous auth is automatically verified, otherwise verified if credential has been verified previously
	account, err := a.registerUser(context, identifiers, supportedAuthType.AuthType, true, aatParams, appOrg, nil,
		*profile, privacy, preferences, nil, externalRoles, externalGroups, nil, nil, clientVersion, l)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionRegister, model.TypeAccount, nil, err)
	}

	return account, nil
}

func (a *Auth) applySignUpAdminExternal(context storage.TransactionContext, supportedAuthType model.SupportedAuthType, appOrg model.ApplicationOrganization, externalUser model.ExternalSystemUser, regProfile model.Profile,
	privacy model.Privacy, permissions []string, roleIDs []string, groupIDs []string, scopes []string, creatorPermissions []string, clientVersion *string, l *logs.Log) (*model.Account, error) {
	//1. prepare external admin user data
	identifiers, aatParams, profile, _, err := a.prepareExternalUserData(supportedAuthType.AuthType, externalUser, regProfile, nil, l)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionPrepare, "external admin user data", nil, err)
	}

	//2. register the account
	//External and anonymous auth is automatically verified, otherwise verified if credential has been verified previously
	account, err := a.registerUser(context, identifiers, supportedAuthType.AuthType, false, aatParams, appOrg, nil, *profile, privacy, nil,
		permissions, roleIDs, groupIDs, scopes, creatorPermissions, clientVersion, l)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionRegister, "admin account", nil, err)
	}

	return account, nil
}

func (a *Auth) prepareExternalUserData(authType model.AuthType, externalUser model.ExternalSystemUser, regProfile model.Profile,
	regPreferences map[string]interface{}, l *logs.Log) ([]model.AccountIdentifier, map[string]interface{}, *model.Profile, map[string]interface{}, error) {

	//1. prepare profile and preferences
	profile, preferences, err := a.prepareRegistrationData(authType, externalUser.Identifier, regProfile, regPreferences, l)
	if err != nil {
		return nil, nil, nil, nil, errors.WrapErrorAction(logutils.ActionPrepare, "user registration data", nil, err)
	}

	//2. prepare the registration data
	params := map[string]interface{}{"user": externalUser}

	//3. create the account identifiers
	now := time.Now().UTC()
	accountID := uuid.NewString()
	accountIdentifiers := make([]model.AccountIdentifier, 0)
	for k, v := range externalUser.ExternalIDs {
		primary := (v == externalUser.Identifier)
		accountIdentifiers = append(accountIdentifiers, model.AccountIdentifier{ID: uuid.NewString(), Code: k, Identifier: v, Verified: true,
			Sensitive: utils.Contains(externalUser.SensitiveExternalIDs, k), Primary: &primary, Account: model.Account{ID: accountID}, DateCreated: now})
	}
	if externalUser.Email != "" {
		primary := (externalUser.Email == externalUser.Identifier)
		accountIdentifiers = append(accountIdentifiers, model.AccountIdentifier{ID: uuid.NewString(), Code: IdentifierTypeEmail, Identifier: externalUser.Email,
			Verified: externalUser.IsEmailVerified, Sensitive: true, Primary: &primary, Account: model.Account{ID: accountID}, DateCreated: now})
	}
	// AccountAuthTypeID field will be set later

	return accountIdentifiers, params, profile, preferences, nil
}

func (a *Auth) applyProfileDataFromExternalUser(profile model.Profile, newExternalUser model.ExternalSystemUser,
	currentExternalUser *model.ExternalSystemUser, identityBBProfile *model.Profile, alwaysSync bool) (*model.Profile, error) {
	newProfile := profile
	if identityBBProfile != nil {
		newProfile = newProfile.Merge(*identityBBProfile)
		alwaysSync = true // External auth system data should always override identity bb data
	}

	//first name
	if len(newExternalUser.FirstName) > 0 && (alwaysSync || len(profile.FirstName) == 0 || (currentExternalUser != nil && currentExternalUser.FirstName != newExternalUser.FirstName)) {
		newProfile.FirstName = newExternalUser.FirstName
	}
	//last name
	if len(newExternalUser.LastName) > 0 && (alwaysSync || len(profile.LastName) == 0 || (currentExternalUser != nil && currentExternalUser.LastName != newExternalUser.LastName)) {
		newProfile.LastName = newExternalUser.LastName
	}

	changed := !utils.DeepEqual(profile, newProfile)
	if changed {
		now := time.Now().UTC()
		newProfile.DateUpdated = &now
		return &newProfile, nil
	}

	return nil, nil
}

func (a *Auth) updateExternalUserIfNeeded(accountAuthType model.AccountAuthType, externalUser model.ExternalSystemUser,
	authType model.AuthType, appOrg model.ApplicationOrganization, externalCreds string, l *logs.Log) (*model.Account, error) {
	l.Info("updateExternalUserIfNeeded")

	//get the current external user
	currentData, err := utils.JSONConvert[model.ExternalSystemUser, interface{}](accountAuthType.Params["user"])
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionParse, model.TypeExternalSystemUser, nil, err)
	}

	identityProviderID, ok := authType.Params["identity_provider"].(string)
	if !ok {
		return nil, errors.ErrorData(logutils.StatusMissing, "identity provider id", nil)
	}
	identityProviderSetting := appOrg.FindIdentityProviderSetting(identityProviderID)
	if identityProviderSetting == nil {
		return nil, errors.ErrorData(logutils.StatusMissing, model.TypeIdentityProviderSetting, nil)
	}

	var identityBBProfile *model.Profile
	if identityProviderSetting.IdentityBBBaseURL != "" {
		identityBBProfile, err = a.identityBB.GetUserProfile(identityProviderSetting.IdentityBBBaseURL, externalUser, externalCreds, l)
		if err != nil {
			l.WarnError(logutils.MessageAction(logutils.StatusError, "syncing", "identity bb data", nil), err)
		}
	}

	//check if external system user needs to be updated
	var newAccount *model.Account
	//there is changes so we need to update it
	//TODO: Can we do this all in a single storage operation?
	updatedActiveStatus := !accountAuthType.Active
	updatedExternalUser := !currentData.Equals(externalUser)
	accountAuthType.Params["user"] = externalUser
	now := time.Now().UTC()
	accountAuthType.DateUpdated = &now

	//TODO: make sure external identifiers get updated in storage and in account memory
	transaction := func(context storage.TransactionContext) error {
		//1. first find the account record
		currentAppOrgID := appOrg.ID
		account, err := a.storage.FindAccountByAuthTypeID(context, accountAuthType.ID, &currentAppOrgID)
		if err != nil {
			return errors.WrapErrorAction(logutils.ActionFind, model.TypeAccount, nil, err)
		}
		if account == nil {
			return errors.ErrorData(logutils.StatusMissing, model.TypeAccount, &logutils.FieldArgs{"account_auth_type_id": accountAuthType.ID})
		}

		//2. update the account auth type in the account record
		newAccountAuthTypes := make([]model.AccountAuthType, len(account.AuthTypes))
		for j, aAuthType := range account.AuthTypes {
			if aAuthType.ID == accountAuthType.ID {
				accountAuthType.Active = true
				newAccountAuthTypes[j] = accountAuthType
			} else {
				newAccountAuthTypes[j] = aAuthType
			}
		}
		account.AuthTypes = newAccountAuthTypes

		// 3. update external ids
		updatedIdentifiers := a.updateExternalIdentifiers(account, accountAuthType.ID, &externalUser, false)

		// 4. update profile
		profileUpdated := false
		newProfile, err := a.applyProfileDataFromExternalUser(account.Profile, externalUser, currentData, identityBBProfile,
			identityProviderSetting.AlwaysSyncProfile)
		if err != nil {
			return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeProfile, nil, err)
		}
		if newProfile != nil {
			account.Profile = *newProfile
			profileUpdated = true
		}

		// 5. update roles and groups mapping
		roles, groups, err := a.getExternalUserAuthorization(externalUser, identityProviderSetting)
		if err != nil {
			return errors.WrapErrorAction(logutils.ActionGet, "external authorization", nil, err)
		}
		rolesUpdated, err := a.updateExternalAccountRoles(account, roles, currentAppOrgID)
		if err != nil {
			return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeAccountRoles, nil, err)
		}
		groupsUpdated, err := a.updateExternalAccountGroups(account, groups, currentAppOrgID)
		if err != nil {
			return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeAccountGroups, nil, err)
		}

		// 6. update account if needed
		if updatedActiveStatus || updatedExternalUser || updatedIdentifiers || profileUpdated || rolesUpdated || groupsUpdated {
			err = a.storage.SaveAccount(context, account)
			if err != nil {
				return errors.WrapErrorAction(logutils.ActionSave, model.TypeAccount, nil, err)
			}
		}

		newAccount = account
		return nil
	}

	err = a.storage.PerformTransaction(transaction)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionUpdate, model.TypeUserAuth, nil, err)
	}
	return newAccount, nil
}

func (a *Auth) applyAnonymousAuthType(authType model.AuthType, creds string) (string, *model.Account, map[string]interface{}, error) { //auth type
	authImpl, err := a.getAnonymousAuthTypeImpl(authType)
	if err != nil {
		return "", nil, nil, errors.WrapErrorAction(logutils.ActionLoadCache, typeAnonymousAuthType, nil, err)
	}

	//Check the credentials
	anonymousID, anonymousParams, err := authImpl.checkCredentials(creds)
	if err != nil {
		return "", nil, nil, errors.WrapErrorAction(logutils.ActionValidate, model.TypeCreds, nil, err)
	}

	account, err := a.storage.FindAccountByID(nil, nil, nil, anonymousID)
	if err != nil {
		return "", nil, nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeAccount, &logutils.FieldArgs{"id": anonymousID}, err)
	}
	if account != nil && !account.Anonymous {
		return "", nil, nil, errors.ErrorData(logutils.StatusInvalid, "anonymous account", &logutils.FieldArgs{"id": anonymousID})
	}

	return anonymousID, account, anonymousParams, nil
}

func (a *Auth) applyAuthType(supportedAuthType model.SupportedAuthType, appOrg model.ApplicationOrganization, appType *model.ApplicationType,
	creds string, params string, clientVersion *string, regProfile model.Profile, privacy model.Privacy, regPreferences map[string]interface{},
	accountIdentifierID *string, admin bool, l *logs.Log) (map[string]interface{}, *model.Account, []model.MFAType, error) {

	//identifier type
	identifierImpl := a.getIdentifierTypeImpl(creds, nil, nil)
	authImpl, err := a.getAuthTypeImpl(supportedAuthType)
	if err != nil {
		return nil, nil, nil, errors.WrapErrorAction(logutils.ActionLoadCache, model.TypeAuthType, nil, err)
	}

	var account *model.Account
	appOrgID := &appOrg.ID
	if identifierImpl == nil {
		// if given an account identifier ID, find the account and attempt sign in (operationSignIn)
		if accountIdentifierID != nil {
			account, err = a.storage.FindAccountByIdentifierID(nil, *accountIdentifierID, appOrgID)
			if err != nil {
				return nil, nil, nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeAccount, &logutils.FieldArgs{"identifier.id": *accountIdentifierID}, err)
			}
			if account == nil {
				return nil, nil, nil, errors.ErrorData(logutils.StatusMissing, model.TypeAccount, &logutils.FieldArgs{"identifier.id": *accountIdentifierID})
			}

			// attempt sign-in after finding the account
			retParams, verifiedMFATypes, err := a.applySignIn(nil, authImpl, supportedAuthType, appOrg, account, creds, params, accountIdentifierID)
			return retParams, account, verifiedMFATypes, err
		}

		// attempt identifier-less login (only sign in is allowed because sign up is impossible without a user identifier)
		message, credID, err := a.checkCredentials(nil, authImpl, nil, nil, creds, params, appOrg)
		if err != nil {
			return nil, nil, nil, errors.WrapErrorAction(logutils.ActionVerify, model.TypeCredential, nil, err)
		}

		if message != nil {
			return map[string]interface{}{"message": *message}, nil, nil, nil
		}

		account, err := a.storage.FindAccountByCredentialID(nil, credID, appOrgID)
		if err != nil {
			return nil, nil, nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeAccount, &logutils.FieldArgs{"credential_id": credID}, err)
		}

		if authImpl.requireIdentifierVerificationForSignIn() && len(account.GetVerifiedAccountIdentifiers()) == 0 {
			return nil, nil, nil, errors.ErrorData(logutils.StatusInvalid, model.TypeAccount, &logutils.FieldArgs{"verified": false})
		}

		accountAuthTypes, err := a.findAccountAuthTypesAndCredentials(account, supportedAuthType)
		if err != nil {
			return nil, nil, nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeAccountAuthType, nil, err)
		}

		_, verifiedMFATypes, err := a.completeSignIn(nil, account, accountAuthTypes, credID)
		return nil, account, verifiedMFATypes, err
	}

	code := identifierImpl.getCode()
	identifier := identifierImpl.getIdentifier()
	//find the account for the org and the user identity
	account, err = a.storage.FindAccount(nil, code, identifier, &appOrg.Organization.ID, nil) // do not provide an appOrgID because we want to know if there is an account in the organization with the same identifier
	if err != nil {
		return nil, nil, nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeAccount, &logutils.FieldArgs{"app_org_id": appOrg.ID, "code": code, "identifier": identifier}, err)
	}
	a.setLogContext(account, l)

	//check if it is operationSignIn or operationOrgSignUp or operationAppSignUp
	operation, err := a.determineOperationWithClientParams(account, appOrg.ID, params)
	if err != nil {
		return nil, nil, nil, errors.WrapErrorAction(logutils.ActionVerify, "determine operation internal", nil, err)
	}
	switch operation {
	case operationSignIn:
		canSignIn := a.canSignIn(account, code, identifier, appOrg.ID)
		if !canSignIn {
			return nil, nil, nil, errors.ErrorData(logutils.StatusInvalid, model.TypeAccount, &logutils.FieldArgs{"app_org_id": appOrg.ID, "code": code, "identifier": identifier})
		}

		///apply sign in
		retParams, verifiedMFATypes, err := a.applySignIn(identifierImpl, authImpl, supportedAuthType, appOrg, account, creds, params, nil)
		if err != nil {
			return nil, nil, nil, err
		}
		return retParams, account, verifiedMFATypes, err
	case operationAppSignUp:
		if admin {
			return nil, nil, nil, errors.ErrorData(logutils.StatusInvalid, "sign up", &logutils.FieldArgs{"identifier": identifier,
				"auth_type": supportedAuthType.AuthType.Code, "app_org_id": appOrg.ID, "admin": true}).SetStatus(utils.ErrorStatusNotAllowed)
		}

		//We have prepared this operation as it is based on the tenants accounts but for now we disable it
		//as we do not use it(yet) and better not to introduce additional complexity.
		//Also this would trigger client updates as well for supporting this
		return nil, nil, nil, errors.ErrorData(logutils.StatusDisabled, "app sign up", nil)
	case operationOrgSignUp:
		if admin {
			return nil, nil, nil, errors.ErrorData(logutils.StatusInvalid, "sign up", &logutils.FieldArgs{"identifier": identifier,
				"auth_type": supportedAuthType.AuthType.Code, "app_org_id": appOrg.ID, "admin": true}).SetStatus(utils.ErrorStatusNotAllowed)
		}

		retParams, account, err := a.applyOrgSignUp(identifierImpl, account, supportedAuthType, appOrg, appType, creds, params, clientVersion, regProfile, privacy, regPreferences, l)
		if err != nil {
			return nil, nil, nil, err
		}
		return retParams, account, nil, nil
	}

	return nil, nil, nil, errors.ErrorData(logutils.StatusInvalid, "internal auth type operation", nil)
}

func (a *Auth) applySignIn(identifierImpl identifierType, authImpl authType, supportedAuthType model.SupportedAuthType, appOrg model.ApplicationOrganization,
	account *model.Account, creds string, params string, accountIdentifierID *string) (map[string]interface{}, []model.MFAType, error) {
	if account == nil {
		return nil, nil, errors.ErrorData(logutils.StatusMissing, model.TypeAccount, nil).SetStatus(utils.ErrorStatusNotFound)
	}

	//find account identifier
	var accountIdentifier *model.AccountIdentifier
	identifier := ""
	if accountIdentifierID != nil {
		accountIdentifier = account.GetAccountIdentifierByID(*accountIdentifierID)
	} else if identifierImpl != nil {
		identifier = identifierImpl.getIdentifier()
		accountIdentifier = account.GetAccountIdentifier(identifierImpl.getCode(), identifier)
	}
	if accountIdentifier == nil {
		return nil, nil, errors.ErrorData(logutils.StatusMissing, model.TypeAccountIdentifier, &logutils.FieldArgs{"identifier": identifier})
	}
	if !accountIdentifier.Verified && accountIdentifier.Linked {
		return nil, nil, errors.ErrorData(logutils.StatusInvalid, model.TypeAccountIdentifier, &logutils.FieldArgs{"verified": false, "linked": true})
	}

	if identifierImpl == nil {
		identifierImpl = a.getIdentifierTypeImpl("", &accountIdentifier.Code, &accountIdentifier.Identifier)
		if identifierImpl == nil {
			return nil, nil, errors.ErrorData(logutils.StatusInvalid, typeIdentifierType, &logutils.FieldArgs{"code": accountIdentifier.Code, "identifier": accountIdentifier.Identifier})
		}
	}
	if identifierImpl.requireVerificationForSignIn() || authImpl.requireIdentifierVerificationForSignIn() {
		err := identifierImpl.checkVerified(accountIdentifier, appOrg.Application.Name)
		if err != nil {
			return nil, nil, errors.WrapErrorData(logutils.StatusInvalid, model.TypeAccountIdentifier, &logutils.FieldArgs{"verified": false}, err)
		}
	}

	//find account auth type
	accountAuthTypes, err := a.findAccountAuthTypesAndCredentials(account, supportedAuthType)
	if err != nil {
		return nil, nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeAccountAuthType, nil, err)
	}

	updateIdentifier := !accountIdentifier.Verified
	message, credID, err := a.checkCredentials(identifierImpl, authImpl, &account.ID, accountAuthTypes, creds, params, appOrg)
	if err != nil {
		return nil, nil, errors.WrapErrorAction(logutils.ActionVerify, model.TypeCredential, nil, err)
	}

	account.SortAccountIdentifiers(identifierImpl.getIdentifier())
	if updateIdentifier && message == nil {
		accountIdentifier.Verified = true
		err := a.storage.UpdateAccountIdentifier(nil, *accountIdentifier)
		if err != nil {
			return nil, nil, errors.WrapErrorAction(logutils.ActionUpdate, model.TypeAccountIdentifier, nil, err)
		}
	}

	return a.completeSignIn(message, account, accountAuthTypes, credID)
}

func (a *Auth) completeSignIn(message *string, account *model.Account, accountAuthTypes []model.AccountAuthType, credID string) (map[string]interface{}, []model.MFAType, error) {
	//sort by the account auth type used to perform the login
	for _, aat := range accountAuthTypes {
		if credID == "" || (aat.Credential != nil && aat.Credential.ID == credID) {
			account.SortAccountAuthTypes(aat.ID, "")

			// if the account auth type is not already active, mark it as active
			if !aat.Active {
				aat.Active = true
				err := a.storage.UpdateAccountAuthType(nil, aat)
				if err != nil {
					return nil, nil, errors.WrapErrorAction(logutils.ActionUpdate, model.TypeAccountAuthType, nil, err)
				}
			}

			break
		}
	}

	var retParams map[string]interface{}
	if message != nil {
		retParams = map[string]interface{}{"message": *message}
	}
	return retParams, account.GetVerifiedMFATypes(), nil
}

func (a *Auth) checkCredentials(identifierImpl identifierType, authImpl authType, accountID *string, aats []model.AccountAuthType, creds string,
	params string, appOrg model.ApplicationOrganization) (*string, string, error) {
	//check the credentials
	msg, credID, err := authImpl.checkCredentials(identifierImpl, accountID, aats, creds, params, appOrg)
	if err != nil {
		return nil, "", errors.WrapErrorAction(logutils.ActionValidate, model.TypeCredential, nil, err)
	}

	var message *string
	if msg != "" {
		message = &msg
	}
	return message, credID, nil
}

func (a *Auth) applyOrgSignUp(identifierImpl identifierType, account *model.Account, supportedAuthType model.SupportedAuthType, appOrg model.ApplicationOrganization,
	appType *model.ApplicationType, creds string, params string, clientVersion *string, regProfile model.Profile, privacy model.Privacy,
	regPreferences map[string]interface{}, l *logs.Log) (map[string]interface{}, *model.Account, error) {
	if account != nil {
		err := a.handleAccountIdentifierConflict(*account, identifierImpl, true)
		if err != nil {
			return nil, nil, err
		}
	}

	if identifierImpl.getCode() == IdentifierTypeUsername {
		username := identifierImpl.getIdentifier()
		accounts, err := a.storage.FindAccountsByUsername(nil, &appOrg, username)
		if err != nil {
			return nil, nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeAccount, nil, err)
		}
		if len(accounts) > 0 {
			return nil, nil, errors.ErrorData(logutils.StatusInvalid, model.TypeAccountUsername, logutils.StringArgs(username+" taken")).SetStatus(utils.ErrorStatusUsernameTaken)
		}
	}

	retParams, account, err := a.signUpNewAccount(nil, identifierImpl, supportedAuthType, appOrg, appType, creds, params, clientVersion, regProfile, privacy, regPreferences, nil, nil, nil, nil, nil, l)
	if err != nil {
		return nil, nil, err
	}

	return retParams, account, nil
}

func (a *Auth) applyCreateAnonymousAccount(context storage.TransactionContext, appOrg model.ApplicationOrganization, anonymousID string,
	preferences map[string]interface{}, systemConfigs map[string]interface{}) (*model.Account, error) {

	id := anonymousID
	orgID := appOrg.Organization.ID

	orgAppMembership := model.OrgAppMembership{ID: uuid.NewString(), AppOrg: appOrg, Preferences: preferences}
	orgAppsMemberships := []model.OrgAppMembership{orgAppMembership}

	aSystemConfigs := systemConfigs
	anonymous := true
	dateCreated := time.Now()

	account := model.Account{ID: id, OrgID: orgID, OrgAppsMemberships: orgAppsMemberships, SystemConfigs: aSystemConfigs, Anonymous: anonymous, DateCreated: dateCreated}

	return a.storage.InsertAccount(context, account)
}

func (a *Auth) signUpNewAccount(context storage.TransactionContext, identifierImpl identifierType, supportedAuthType model.SupportedAuthType, appOrg model.ApplicationOrganization,
	appType *model.ApplicationType, creds string, params string, clientVersion *string, regProfile model.Profile, privacy model.Privacy, regPreferences map[string]interface{},
	permissions []string, roles []string, groups []string, scopes []string, creatorPermissions []string, l *logs.Log) (map[string]interface{}, *model.Account, error) {
	var retParams map[string]interface{}
	var accountIdentifier *model.AccountIdentifier
	var credential *model.Credential

	profile, preferences, err := a.prepareRegistrationData(supportedAuthType.AuthType, identifierImpl.getIdentifier(), regProfile, regPreferences, l)
	if err != nil {
		return nil, nil, errors.WrapErrorAction(logutils.ActionPrepare, "user registration data", nil, err)
	}

	//apply sign up
	authImpl, err := a.getAuthTypeImpl(supportedAuthType)
	if err != nil {
		return nil, nil, errors.WrapErrorAction(logutils.ActionLoadCache, model.TypeAuthType, nil, err)
	}
	if creatorPermissions == nil {
		var message string
		message, accountIdentifier, credential, err = authImpl.signUp(identifierImpl, nil, appOrg, creds, params)
		if err != nil {
			return nil, nil, errors.WrapErrorAction("signing up", "user", nil, err)
		}

		if message != "" {
			retParams = map[string]interface{}{"message": message}
		}
	} else {
		retParams, accountIdentifier, credential, err = authImpl.signUpAdmin(identifierImpl, appOrg, creds)
		if err != nil {
			return nil, nil, errors.WrapErrorAction("signing up", "admin user", nil, err)
		}
	}
	if accountIdentifier == nil {
		return nil, nil, errors.ErrorData(logutils.StatusMissing, model.TypeAccountIdentifier, nil)
	}

	if credential != nil {
		credential.AuthType.ID = supportedAuthType.AuthType.ID
	}

	var accountAuthTypeParams map[string]interface{}
	if supportedAuthType.AuthType.Code == AuthTypeWebAuthn && appType != nil {
		accountAuthTypeParams = map[string]interface{}{"app_type_identifier": appType.Identifier}
	}
	account, err := a.registerUser(context, []model.AccountIdentifier{*accountIdentifier}, supportedAuthType.AuthType, retParams == nil, accountAuthTypeParams,
		appOrg, credential, *profile, privacy, preferences, permissions, roles, groups, scopes, creatorPermissions, clientVersion, l)
	if err != nil {
		return nil, nil, errors.WrapErrorAction(logutils.ActionRegister, model.TypeAccount, nil, err)
	}

	return retParams, account, nil
}

// validateAPIKey checks if the given API key is valid for the given app ID
func (a *Auth) validateAPIKey(apiKey string, appID string) error {
	validAPIKey, err := a.getCachedAPIKey(apiKey)
	if err != nil || validAPIKey == nil || validAPIKey.AppID != appID {
		return errors.ErrorData(logutils.StatusInvalid, model.TypeAPIKey, &logutils.FieldArgs{"app_id": appID})
	}

	return nil
}

func (a *Auth) canSignIn(account *model.Account, code string, identifier string, desireAppOrgID string) bool {
	if account != nil {
		hasAppMembership := account.HasAppMembership(desireAppOrgID)
		if !hasAppMembership {
			return false
		}

		ai := account.GetAccountIdentifier(code, identifier)
		return ai == nil || !ai.Linked || ai.Verified
	}

	return false
}

// determineOperationWithClientParams determine the operation
//
//	first check if the client has set sign_up field - first priority
//	if sign_up field has not been sent then check if the user exists
func (a *Auth) determineOperationWithClientParams(account *model.Account, desiredAppOrgID string, clientParams string) (string, error) {
	//check if sign_up field has been passed - first priority
	useSignUpFieldCheck := strings.Contains(clientParams, "sign_up")

	if useSignUpFieldCheck {
		type signUpParams struct {
			SignUp bool `json:"sign_up"`
		}
		var sParams signUpParams
		err := json.Unmarshal([]byte(clientParams), &sParams)
		if err != nil {
			return "", errors.WrapErrorAction(logutils.ActionUnmarshal, "sign up params", nil, err)
		}

		if !sParams.SignUp {
			return operationSignIn, nil //the client wants to apply sign-in operation
		}

		//the client wants to apply sign up operation but we must analize which one is the correct
		determinedOperation, err := a.determineOperation(account, desiredAppOrgID)
		if err != nil {
			return "", errors.WrapErrorAction(logutils.ActionApply, "determine operation - internal - client priority", nil, err)
		}
		if determinedOperation == operationOrgSignUp || determinedOperation == operationAppSignUp {
			return determinedOperation, nil
		}
		return "", errors.New("cannot apply sign up operation")
	}

	//if the client has not specified then decide based on that if the user exists
	return a.determineOperation(account, desiredAppOrgID)
}

// determine operation
//
//	operationSignIn or operationOrgSignUp or operationAppSignUp
func (a *Auth) determineOperation(account *model.Account, desiredAppOrgID string) (string, error) {
	if account == nil {
		return operationOrgSignUp, nil //first registration for this user identity and organization
	}

	hasAppMembership := account.HasAppMembership(desiredAppOrgID)
	if !hasAppMembership {
		return operationAppSignUp, nil //the user identity has registration in the orgnization but does not have for the application
	}

	//the user identity has both org registration and app membership
	return operationSignIn, nil
}

func (a *Auth) getAccount(code string, identifier string, apiKey string, appTypeIdentifier string, orgID string) (*model.Account, *model.ApplicationOrganization, error) {
	//validate if the provided app type is supported by the provided application and organization
	_, appOrg, err := a.validateAppOrg(&appTypeIdentifier, nil, orgID)
	if err != nil {
		return nil, nil, errors.WrapErrorAction(logutils.ActionValidate, model.TypeAuthType, nil, err)
	}

	//do not allow for admins
	if appOrg.Application.Admin {
		return nil, nil, errors.ErrorData(logutils.StatusInvalid, model.TypeApplication, logutils.StringArgs("not allowed for admins"))
	}

	//TODO: Ideally we would not make many database calls before validating the API key. Currently needed to get app ID
	err = a.validateAPIKey(apiKey, appOrg.Application.ID)
	if err != nil {
		return nil, nil, errors.WrapErrorData(logutils.StatusInvalid, model.TypeAPIKey, nil, err)
	}

	//check if the account exists check
	account, err := a.storage.FindAccount(nil, code, identifier, &orgID, &appOrg.ID)
	if err != nil {
		return nil, nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeAccount, &logutils.FieldArgs{"app_org_id": appOrg.ID, "code": code, "identifier": identifier}, err)
	}

	return account, appOrg, nil
}

func (a *Auth) findAccountAuthTypesAndCredentials(account *model.Account, supportedAuthType model.SupportedAuthType) ([]model.AccountAuthType, error) {
	if account == nil {
		return nil, errors.ErrorData(logutils.StatusMissing, model.TypeAccount, nil)
	}

	accountAuthTypes := account.GetAccountAuthTypes(supportedAuthType.AuthType.Code)
	for i, aat := range accountAuthTypes {
		accountAuthTypes[i].SupportedAuthType = supportedAuthType

		if aat.Credential != nil {
			//populate credentials in accountAuthType
			credential, err := a.storage.FindCredential(nil, aat.Credential.ID)
			if err != nil || credential == nil {
				return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeCredential, nil, err)
			}
			credential.AuthType = supportedAuthType.AuthType
			accountAuthTypes[i].Credential = credential
		}
	}

	return accountAuthTypes, nil
}

func (a *Auth) findAccountAuthTypeByID(account *model.Account, accountAuthTypeID string) (*model.AccountAuthType, error) {
	if account == nil {
		return nil, errors.ErrorData(logutils.StatusMissing, model.TypeAccount, nil)
	}

	if accountAuthTypeID == "" {
		return nil, errors.ErrorData(logutils.StatusMissing, logutils.TypeString, nil)
	}

	accountAuthType := account.GetAccountAuthTypeByID(accountAuthTypeID)
	if accountAuthType == nil {
		return nil, errors.ErrorData(logutils.StatusMissing, model.TypeAccountAuthType, nil)
	}

	authType, err := a.storage.FindAuthType(accountAuthType.SupportedAuthType.AuthType.ID)
	if err != nil || authType == nil {
		return nil, errors.WrapErrorAction(logutils.ActionLoadCache, model.TypeAuthType, logutils.StringArgs(accountAuthType.SupportedAuthType.AuthType.ID), err)
	}

	//TODO: Handle retrieving supported auth type/params?
	accountAuthType.SupportedAuthType = model.SupportedAuthType{AuthType: *authType}

	if accountAuthType.Credential != nil {
		//populate credentials in accountAuthType
		credential, err := a.storage.FindCredential(nil, accountAuthType.Credential.ID)
		if err != nil {
			return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeCredential, nil, err)
		}
		credential.AuthType = *authType
		accountAuthType.Credential = credential
	}
	return accountAuthType, nil
}

func (a *Auth) updateAccountIdentifier(context storage.TransactionContext, account *model.Account, accountIdentifier *model.AccountIdentifier) error {
	if account == nil {
		return errors.ErrorData(logutils.StatusMissing, model.TypeAccount, nil)
	}
	if accountIdentifier == nil {
		return errors.ErrorData(logutils.StatusMissing, model.TypeAccountIdentifier, nil)
	}

	newAccountIdentifiers := make([]model.AccountIdentifier, len(account.Identifiers))
	for j, aIdentifier := range account.Identifiers {
		if aIdentifier.ID == accountIdentifier.ID {
			newAccountIdentifiers[j] = *accountIdentifier
		} else {
			newAccountIdentifiers[j] = aIdentifier
		}
	}
	account.Identifiers = newAccountIdentifiers

	// update account
	err := a.storage.SaveAccount(context, account)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionSave, model.TypeAccount, nil, err)
	}

	return nil
}

func (a *Auth) clearExpiredSessions(identifier string, l *logs.Log) error {
	l.Info("clearExpiredSessions")

	//load the sessions for the identifier
	loginsSessions, err := a.storage.FindLoginSessions(nil, identifier)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionFind, model.TypeLoginSession, logutils.StringArgs("clear expired"), err)
	}

	//determine the expired sessions
	expiredSessions := []model.LoginSession{}
	for _, session := range loginsSessions {
		if session.IsExpired() {
			expiredSessions = append(expiredSessions, session)
		}
	}

	//log sessions and expired sessions count
	l.Info(fmt.Sprintf("there are %d sessions", len(loginsSessions)))
	l.Info(fmt.Sprintf("there are %d expired sessions", len(expiredSessions)))

	//clear the expird sessions if there are such ones
	if len(expiredSessions) > 0 {
		l.Info("there is expired sessions for deleting")

		err = a.deleteLoginSessions(nil, expiredSessions, l)
		if err != nil {
			return errors.WrapErrorAction(logutils.ActionDelete, model.TypeLoginSession, nil, err)
		}
	} else {
		l.Info("there is no expired sessions for deleting")
	}

	return nil
}

func (a *Auth) applyLogin(anonymous bool, sub string, authType model.AuthType, appOrg model.ApplicationOrganization, account *model.Account,
	appType model.ApplicationType, ipAddress string, deviceType string, deviceOS *string, deviceID *string, clientVersion *string, params map[string]interface{},
	state string, l *logs.Log) (*model.LoginSession, error) {

	var err error
	var loginSession *model.LoginSession
	transaction := func(context storage.TransactionContext) error {
		///1. assign device to session and account
		var device *model.Device
		if !anonymous {
			//1. check if the device exists
			device, err = a.storage.FindDevice(context, deviceID, sub)
			if err != nil {
				return errors.WrapErrorAction(logutils.ActionFind, model.TypeDevice, nil, err)
			}
			if device != nil {
				//2.1 device exists, so do nothing
			} else {
				//2.2 device does not exist, we need to assign it to the account

				device, err = a.createDevice(sub, deviceType, deviceOS, deviceID)
				if err != nil {
					return errors.WrapErrorAction(logutils.ActionCreate, model.TypeDevice, nil, err)
				}
				_, err := a.storage.InsertDevice(context, *device)
				if err != nil {
					return errors.WrapErrorAction(logutils.ActionInsert, model.TypeDevice, nil, err)
				}
			}
		}
		///

		///create login session entity
		loginSession, err = a.createLoginSession(anonymous, sub, authType, appOrg, account, appType, ipAddress, params, state, device)
		if err != nil {
			return errors.WrapErrorAction(logutils.ActionCreate, model.TypeLoginSession, nil, err)
		}

		//1. store login session
		err = a.storage.InsertLoginSession(context, *loginSession)
		if err != nil {
			return errors.WrapErrorAction(logutils.ActionInsert, model.TypeLoginSession, nil, err)
		}

		//2. check session limit against number of active sessions
		sessionLimit := appOrg.LoginsSessionsSetting.MaxConcurrentSessions
		if sessionLimit > 0 {
			loginSessions, err := a.storage.FindLoginSessions(context, loginSession.Identifier)
			if err != nil {
				return errors.WrapErrorAction(logutils.ActionFind, model.TypeLoginSession, nil, err)
			}
			if len(loginSessions) < 1 {
				l.ErrorWithDetails("failed to find login session after inserting", logutils.Fields{"identifier": loginSession.Identifier})
			}

			if len(loginSessions) > sessionLimit {
				// delete first session in list (sorted by date created)
				err = a.deleteLoginSession(context, loginSessions[0], l)
				if err != nil {
					return errors.WrapErrorAction(logutils.ActionDelete, model.TypeLoginSession, nil, err)
				}
			}
		}
		// update account usage information
		// TODO: Handle anonymous accounts if needed in the future
		if !anonymous {
			err = a.storage.UpdateAccountUsageInfo(context, sub, true, true, clientVersion)
			if err != nil {
				return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeAccountUsageInfo, nil, err)
			}
		}
		return nil
	}

	err = a.storage.PerformTransaction(transaction)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionUpdate, model.TypeUserAuth, nil, err)
	}

	return loginSession, nil
}

func (a *Auth) createDevice(accountID string, deviceType string, deviceOS *string, deviceID *string) (*model.Device, error) {
	//id
	idUUID, _ := uuid.NewUUID()
	id := idUUID.String()

	//account
	account := model.Account{ID: accountID}

	return &model.Device{ID: id, DeviceID: deviceID, Account: account,
		Type: deviceType, OS: *deviceOS, DateCreated: time.Now()}, nil
}

func (a *Auth) createLoginSession(anonymous bool, sub string, authType model.AuthType, appOrg model.ApplicationOrganization, account *model.Account,
	appType model.ApplicationType, ipAddress string, params map[string]interface{}, state string, device *model.Device) (*model.LoginSession, error) {

	//id
	id := uuid.NewString()

	//access token
	orgID := appOrg.Organization.ID
	appID := appOrg.Application.ID
	name := ""
	email := ""
	phone := ""
	username := ""
	permissions := []string{}
	scopes := []string{authorization.ScopeGlobal}
	externalIDs := make(map[string]string)
	if !anonymous {
		if account == nil {
			return nil, errors.ErrorData(logutils.StatusMissing, model.TypeAccount, nil)
		}
		if emailIdentifier := account.GetAccountIdentifier(IdentifierTypeEmail, ""); emailIdentifier != nil {
			email = emailIdentifier.Identifier
		}
		if phoneIdentifier := account.GetAccountIdentifier(IdentifierTypePhone, ""); phoneIdentifier != nil {
			phone = phoneIdentifier.Identifier
		}
		if usernameIdentifier := account.GetAccountIdentifier(IdentifierTypeUsername, ""); usernameIdentifier != nil {
			username = usernameIdentifier.Identifier
		}
		name = account.Profile.GetFullName()
		permissions = account.GetPermissionNames()
		scopes = append(scopes, account.GetScopes()...)
		for _, external := range account.GetExternalAccountIdentifiers() {
			externalIDs[external.Code] = external.Identifier
		}
	}
	claims := a.getStandardClaims(sub, name, email, phone, username, rokwireTokenAud, orgID, appID, authType.Code, externalIDs, nil, anonymous, true, appOrg.Application.Admin, appOrg.Organization.System, false, true, id, &appOrg.LoginsSessionsSetting.AccessTokenExpirationPolicy)
	accessToken, err := a.buildAccessToken(claims, strings.Join(permissions, ","), strings.Join(scopes, " "))
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionCreate, logutils.TypeToken, nil, err)
	}

	//refresh token
	refreshToken := utils.GenerateRandomString(refreshTokenLength)

	now := time.Now().UTC()
	var stateExpires *time.Time
	if state != "" {
		stateExpireTime := now.Add(time.Minute * time.Duration(loginStateDuration))
		stateExpires = &stateExpireTime
	}

	loginSession := model.LoginSession{ID: id, AppOrg: appOrg, AuthType: authType, AppType: appType, Anonymous: anonymous, Identifier: sub,
		Account: account, Device: device, IPAddress: ipAddress, AccessToken: accessToken, RefreshTokens: []string{refreshToken}, Params: params,
		State: state, StateExpires: stateExpires, DateCreated: now}

	return &loginSession, nil
}

func (a *Auth) deleteLoginSession(context storage.TransactionContext, loginSession model.LoginSession, l *logs.Log) error {
	//always log what session has been deleted
	l.Info("deleting loging session - " + loginSession.LogInfo())

	err := a.storage.DeleteLoginSession(context, loginSession.ID)
	if err != nil {
		l.WarnError(logutils.MessageActionError(logutils.ActionDelete, model.TypeLoginSession, nil), err)
		return err
	}
	return nil
}

func (a *Auth) deleteLoginSessions(context storage.TransactionContext, loginSessions []model.LoginSession, l *logs.Log) error {
	//always log what session has been deleted, also prepare the IDs
	ids := make([]string, len(loginSessions))
	l.Info("expired sessions to be deleted:")
	for i, session := range loginSessions {
		l.Info("deleting loging session - " + session.LogInfo())

		ids[i] = session.ID
	}

	//delete the sessions from the storage
	err := a.storage.DeleteLoginSessionsByIDs(context, ids)
	if err != nil {
		l.WarnError(logutils.MessageActionError(logutils.ActionDelete, model.TypeLoginSession, nil), err)
		return err
	}
	return nil
}

func (a *Auth) prepareRegistrationData(authType model.AuthType, identifier string, profile model.Profile, preferences map[string]interface{}, l *logs.Log) (*model.Profile, map[string]interface{}, error) {
	//no need to merge from profile BB for new apps

	///profile and preferences
	//get profile BB data
	gotProfile, gotPreferences, err := a.getProfileBBData(authType, identifier, l)
	if err != nil {
		args := &logutils.FieldArgs{"auth_type": authType.Code, "identifier": identifier}
		return nil, nil, errors.WrapErrorAction(logutils.ActionGet, "profile BB data", args, err)
	}

	readyProfile := profile
	//if there is profile bb data
	if gotProfile != nil {
		readyProfile = a.mergeProfiles(profile, gotProfile, false)
	}
	readyPreferences := preferences
	//if there is preferences bb data
	if gotPreferences != nil {
		readyPreferences = a.mergePreferences(preferences, gotPreferences)
	}

	//generate profile ID
	profileID, _ := uuid.NewUUID()
	readyProfile.ID = profileID.String()
	//date created
	if readyProfile.DateCreated.IsZero() {
		readyProfile.DateCreated = time.Now()
	}

	if readyPreferences != nil {
		if readyPreferences["date_created"] == nil {
			readyPreferences["date_created"] = time.Now()
		} else {
			preferencesCreated, ok := readyPreferences["date_created"].(time.Time)
			if !ok || preferencesCreated.IsZero() {
				readyPreferences["date_created"] = time.Now()
			}
		}
	}
	///

	return &readyProfile, readyPreferences, nil
}

func (a *Auth) prepareAccountAuthType(authType model.AuthType, accountAuthTypeActive bool, accountAuthTypeParams map[string]interface{}, credential *model.Credential) (*model.AccountAuthType, error) {
	now := time.Now()

	//account auth type
	accountAuthTypeID := uuid.NewString()
	accountAuthType := &model.AccountAuthType{ID: accountAuthTypeID, SupportedAuthType: model.SupportedAuthType{AuthType: authType},
		Params: accountAuthTypeParams, Credential: credential, Active: accountAuthTypeActive, DateCreated: now}

	//credential
	if credential != nil {
		//there is a credential
		credential.AccountsAuthTypes = append(credential.AccountsAuthTypes, *accountAuthType)
	}

	return accountAuthType, nil
}

func (a *Auth) mergeProfiles(dst model.Profile, src *model.Profile, shared bool) model.Profile {
	if src == nil {
		return dst
	}

	dst.PhotoURL = utils.SetStringIfEmpty(dst.PhotoURL, src.PhotoURL)
	dst.FirstName = utils.SetStringIfEmpty(dst.FirstName, src.FirstName)
	dst.LastName = utils.SetStringIfEmpty(dst.LastName, src.LastName)
	dst.Address = utils.SetStringIfEmpty(dst.Address, src.Address)
	dst.ZipCode = utils.SetStringIfEmpty(dst.ZipCode, src.ZipCode)
	dst.State = utils.SetStringIfEmpty(dst.State, src.State)
	dst.Country = utils.SetStringIfEmpty(dst.Country, src.Country)

	if dst.BirthYear == 0 {
		dst.BirthYear = src.BirthYear
	}
	if shared {
		dst.ID = src.ID
	}

	return dst
}

func (a *Auth) mergePreferences(clientData map[string]interface{}, profileBBData map[string]interface{}) map[string]interface{} {
	mergedData := profileBBData
	for k, v := range clientData {
		if profileBBData[k] == nil {
			mergedData[k] = v
		}
	}

	return mergedData
}

func (a *Auth) getProfileBBData(authType model.AuthType, identifier string, l *logs.Log) (*model.Profile, map[string]interface{}, error) {
	var profile *model.Profile
	var preferences map[string]interface{}
	var err error

	var profileSearch map[string]string
	if authType.Code == "twilio_phone" {
		profileSearch = map[string]string{"phone": identifier}
	} else if authType.Code == "illinois_oidc" {
		profileSearch = map[string]string{"uin": identifier}
	}

	if profileSearch != nil {
		profile, preferences, err = a.profileBB.GetProfileBBData(profileSearch, l)
		if err != nil {
			return nil, nil, err
		}
	}
	return profile, preferences, nil
}

// sign up an account to a specific application in the organization
//
//	Input:
//		account (Account): The account
//		appOrg (ApplicationOrganization): The application organization where this account will be attached
//		permissionNames ([]string): set of permissions to assign
//		roleIDs ([]string): set of roles to assign
//		groupIDs ([]string): set of groups to assign
//		clientVersion (*string): client version
//		creatorPermissions ([]string): creator permissions
//	Returns:
//		Updated account (Account): The updated account object
func (a *Auth) appSignUp(context storage.TransactionContext, account model.Account, appOrg model.ApplicationOrganization,
	permissionNames []string, roleIDs []string, groupIDs []string, clientVersion *string, creatorPermissions []string) (*model.Account, error) {

	//check permissions, roles and groups
	permissions, err := a.CheckPermissions(context, []model.ApplicationOrganization{appOrg}, permissionNames, creatorPermissions, false)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionValidate, model.TypePermission, nil, err)
	}

	roles, err := a.CheckRoles(context, &appOrg, roleIDs, creatorPermissions, false)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionValidate, model.TypeAppOrgRole, nil, err)
	}

	groups, err := a.CheckGroups(context, &appOrg, groupIDs, creatorPermissions, false)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionGet, model.TypeAppOrgGroup, nil, err)
	}

	//create new app membership
	rolesItems := model.AccountRolesFromAppOrgRoles(roles, true, true)
	groupsItems := model.AccountGroupsFromAppOrgGroups(groups, true, true)
	newAppMembership := model.OrgAppMembership{ID: uuid.NewString(), AppOrg: appOrg,
		Permissions: permissions, Roles: rolesItems, Groups: groupsItems, MostRecentClientVersion: clientVersion}

	//add it to the account
	account.OrgAppsMemberships = append(account.OrgAppsMemberships, newAppMembership)

	//save the account
	err = a.storage.SaveAccount(context, &account)
	if err != nil {
		return nil, err
	}

	//set current membership
	account.SetCurrentMembership(newAppMembership)

	return &account, nil
}

// registerUser registers account for an organization in an application
//
//	Input:
//		authType (AuthType): The authentication type
//		userIdentifier (string): The user identifier
//		accountAuthTypeParams (map[string]interface{}): Account auth type params
//		appOrg (ApplicationOrganization): The application organization which the user is registering in
//		credential (*Credential): Information for the user
//		preferences (map[string]interface{}): Preferences of the user
//		profile (Profile): Information for the user
//		permissionNames ([]string): set of permissions to assign to the user
//		roleIDs ([]string): set of roles to assign to the user
//		groupIDs ([]string): set of groups to assign to the user
//		adminSet (bool): whether an admin is trying to set permissions, roles, or groups for the user
//		creatorPermissions ([]string): an admin user's permissions to validate
//		l (*logs.Log): Log object pointer for request
//	Returns:
//		Registered account (Account): Registered Account object
func (a *Auth) registerUser(context storage.TransactionContext, accountIdentifiers []model.AccountIdentifier, authType model.AuthType, accountAuthTypeActive bool, accountAuthTypeParams map[string]interface{},
	appOrg model.ApplicationOrganization, credential *model.Credential, profile model.Profile, privacy model.Privacy, preferences map[string]interface{},
	permissionNames []string, roleIDs []string, groupIDs []string, scopes []string, creatorPermissions []string, clientVersion *string, l *logs.Log) (*model.Account, error) {
	if len(accountIdentifiers) == 0 {
		return nil, errors.ErrorData(logutils.StatusMissing, model.TypeAccountIdentifier, nil)
	}

	account, err := a.constructAccount(context, accountIdentifiers, authType, accountAuthTypeActive, accountAuthTypeParams, appOrg, credential,
		profile, privacy, preferences, permissionNames, roleIDs, groupIDs, scopes, creatorPermissions, clientVersion, l)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionCreate, model.TypeAccount, nil, err)
	}

	err = a.storeNewAccountInfo(context, *account, credential)
	if err != nil {
		return nil, errors.WrapErrorAction("storing", "new account information", nil, err)
	}

	return account, nil
}

func (a *Auth) constructAccount(context storage.TransactionContext, accountIdentifiers []model.AccountIdentifier, authType model.AuthType, accountAuthTypeActive bool, accountAuthTypeParams map[string]interface{},
	appOrg model.ApplicationOrganization, credential *model.Credential, profile model.Profile, privacy model.Privacy, preferences map[string]interface{},
	permissionNames []string, roleIDs []string, groupIDs []string, scopes []string, assignerPermissions []string, clientVersion *string, l *logs.Log) (*model.Account, error) {
	//create account auth type
	accountAuthType, err := a.prepareAccountAuthType(authType, accountAuthTypeActive, accountAuthTypeParams, credential)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionCreate, model.TypeAccountAuthType, nil, err)
	}
	if accountAuthType.Params["user"] != nil {
		// external auth type, so set account auth type IDs for identifiers
		for i := range accountIdentifiers {
			accountIdentifiers[i].AccountAuthTypeID = &accountAuthType.ID
		}
	}

	//create account object
	accountID := accountIdentifiers[0].Account.ID
	authTypes := []model.AccountAuthType{*accountAuthType}

	//assumes admin creator permissions are always non-nil
	adminSet := assignerPermissions != nil
	var permissions []model.Permission
	var roles []model.AppOrgRole
	var groups []model.AppOrgGroup
	if adminSet {
		permissions, err = a.CheckPermissions(context, []model.ApplicationOrganization{appOrg}, permissionNames, assignerPermissions, false)
		if err != nil {
			return nil, errors.WrapErrorAction(logutils.ActionValidate, model.TypePermission, nil, err)
		}

		roles, err = a.CheckRoles(context, &appOrg, roleIDs, assignerPermissions, false)
		if err != nil {
			return nil, errors.WrapErrorAction(logutils.ActionValidate, model.TypeAppOrgRole, nil, err)
		}

		groups, err = a.CheckGroups(context, &appOrg, groupIDs, assignerPermissions, false)
		if err != nil {
			return nil, errors.WrapErrorAction(logutils.ActionGet, model.TypeAppOrgGroup, nil, err)
		}
	} else {
		permissions, err = a.storage.FindPermissionsByName(context, permissionNames)
		if err != nil {
			l.WarnError(logutils.MessageAction(logutils.StatusError, logutils.ActionFind, model.TypePermission, nil), err)
		}

		roles, err = a.storage.FindAppOrgRolesByIDs(context, roleIDs, appOrg.ID)
		if err != nil {
			l.WarnError(logutils.MessageAction(logutils.StatusError, logutils.ActionFind, model.TypeAppOrgRole, nil), err)
		}

		groups, err = a.storage.FindAppOrgGroupsByIDs(context, groupIDs, appOrg.ID)
		if err != nil {
			l.WarnError(logutils.MessageAction(logutils.StatusError, logutils.ActionFind, model.TypeAppOrgGroup, nil), err)
		}
	}

	if scopes != nil && (!adminSet || utils.Contains(assignerPermissions, UpdateScopesPermission)) {
		newScopes := []string{}
		for _, scope := range scopes {
			parsedScope, err := authorization.ScopeFromString(scope)
			if err != nil {
				if adminSet {
					return nil, errors.WrapErrorAction(logutils.ActionValidate, model.TypeScope, nil, err)
				}
				l.WarnError(logutils.MessageAction(logutils.StatusError, logutils.ActionValidate, model.TypeScope, nil), err)
				continue
			}
			if !strings.HasPrefix(parsedScope.Resource, model.AdminScopePrefix) {
				parsedScope.Resource = model.AdminScopePrefix + parsedScope.Resource
				scope = parsedScope.String()
			}
			newScopes = append(newScopes, scope)
		}
		scopes = newScopes
	} else {
		scopes = nil
	}

	orgID := appOrg.Organization.ID

	orgAppMembership := model.OrgAppMembership{ID: uuid.NewString(), AppOrg: appOrg,
		Permissions: permissions, Roles: model.AccountRolesFromAppOrgRoles(roles, true, adminSet),
		Groups: model.AccountGroupsFromAppOrgGroups(groups, true, adminSet), Preferences: preferences,
		MostRecentClientVersion: clientVersion}
	orgAppsMemberships := []model.OrgAppMembership{orgAppMembership}

	account := model.Account{ID: accountID, OrgID: orgID, OrgAppsMemberships: orgAppsMemberships,
		AppOrg:                  orgAppMembership.AppOrg,                  //current
		Permissions:             orgAppMembership.Permissions,             //current
		Roles:                   orgAppMembership.Roles,                   //current
		Groups:                  orgAppMembership.Groups,                  //current
		Preferences:             orgAppMembership.Preferences,             //current
		MostRecentClientVersion: orgAppMembership.MostRecentClientVersion, //current
		Scopes:                  scopes, AuthTypes: authTypes, Identifiers: accountIdentifiers,
		Profile: profile, Privacy: privacy, DateCreated: time.Now()}

	return &account, nil
}

func (a *Auth) storeNewAccountInfo(context storage.TransactionContext, account model.Account, credential *model.Credential) error {
	//insert account object - it includes the account auth type
	_, err := a.storage.InsertAccount(context, account)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionInsert, model.TypeAccount, nil, err)
	}

	//create credential
	if credential != nil {
		err = a.storage.InsertCredential(context, credential)
		if err != nil {
			return errors.WrapErrorAction(logutils.ActionInsert, model.TypeCredential, nil, err)
		}
	}

	return nil
}

func (a *Auth) linkAccountAuthType(account *model.Account, supportedAuthType model.SupportedAuthType, appOrg model.ApplicationOrganization, appType *model.ApplicationType,
	creds string, params string) (*string, *model.AccountAuthType, error) {
	var message *string
	var aat *model.AccountAuthType
	var err error

	var accountIdentifier *model.AccountIdentifier
	tryIdentifierLink := false
	identifierImpl := a.getIdentifierTypeImpl(creds, nil, nil)
	if identifierImpl != nil {
		accountIdentifier = account.GetAccountIdentifier(identifierImpl.getCode(), identifierImpl.getIdentifier())

		// only try if an identifier was provided and the account does not already have it (conflicts will be handled if attempted)
		tryIdentifierLink = (accountIdentifier == nil)
	}

	authImpl, err := a.getAuthTypeImpl(supportedAuthType)
	if err != nil {
		return nil, nil, errors.WrapErrorAction(logutils.ActionLoadCache, model.TypeAuthType, nil, err)
	}

	aats, err := a.findAccountAuthTypesAndCredentials(account, supportedAuthType)
	if err != nil {
		return nil, nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeAccountAuthType, &logutils.FieldArgs{"auth_type_code": supportedAuthType.AuthType.Code}, err)
	}

	inactiveAats := make([]model.AccountAuthType, 0)
	for _, aat := range aats {
		if !aat.Active {
			inactiveAats = append(inactiveAats, aat)
		}
	}

	transaction := func(context storage.TransactionContext) error {
		if len(inactiveAats) > 0 {
			// there are inactive account auth types (have not been used to sign in yet), so try to verify one of them using creds
			var accountAuthType *model.AccountAuthType // do not return this account auth type, so use a new variable
			message, accountAuthType, err = a.verifyAuthTypeActive(identifierImpl, accountIdentifier, authImpl, aats, account.ID, creds, params, appOrg)
			if err != nil {
				return err
			}
			if accountAuthType != nil {
				for i, accAuthType := range account.AuthTypes {
					if accAuthType.ID == accountAuthType.ID {
						account.AuthTypes[i] = *accountAuthType
						break
					}
				}
			}

			updateIdentifier := accountIdentifier != nil && !accountIdentifier.Verified
			if updateIdentifier && message == nil {
				accountIdentifier.Verified = true
				err := a.storage.UpdateAccountIdentifier(context, *accountIdentifier)
				if err != nil {
					return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeAccountIdentifier, nil, err)
				}
			}

			return nil
		}

		if !authImpl.allowMultiple() && len(aats) > 0 {
			// only one account auth type of this type is allowed, so try linking only the identifier
			if tryIdentifierLink {
				message, err = a.linkAccountIdentifier(context, account, identifierImpl)
				if err != nil {
					return errors.WrapErrorAction("linking", model.TypeAccountIdentifier, nil, err)
				}

				return nil
			}

			return errors.ErrorData(logutils.StatusInvalid, model.TypeAuthType, &logutils.FieldArgs{"allow_multiple": false, "code": supportedAuthType.AuthType.Code})
		}

		//apply sign up
		signUpMessage, _, credential, err := authImpl.signUp(identifierImpl, &account.ID, appOrg, creds, params)
		if err != nil {
			return errors.WrapErrorAction("signing up", "user", nil, err)
		}
		if signUpMessage != "" {
			message = &signUpMessage
		}

		if credential != nil {
			credential.AuthType.ID = supportedAuthType.AuthType.ID
		}

		var accountAuthTypeParams map[string]interface{}
		if supportedAuthType.AuthType.Code == AuthTypeWebAuthn && appType != nil {
			accountAuthTypeParams = map[string]interface{}{"app_type_identifier": appType.Identifier}
		}
		aat, err = a.prepareAccountAuthType(supportedAuthType.AuthType, false, accountAuthTypeParams, credential)
		if err != nil {
			return errors.WrapErrorAction(logutils.ActionCreate, model.TypeAccountAuthType, nil, err)
		}
		aat.Account = *account

		err = a.registerAccountAuthType(context, *aat, credential, nil, false)
		if err != nil {
			return errors.WrapErrorAction(logutils.ActionRegister, model.TypeAccountAuthType, nil, err)
		}

		if tryIdentifierLink {
			message, err = a.linkAccountIdentifier(context, account, identifierImpl)
			if err != nil {
				return errors.WrapErrorAction("linking", model.TypeAccountIdentifier, nil, err)
			}
		}

		return nil
	}

	err = a.storage.PerformTransaction(transaction)
	if err != nil {
		return nil, nil, err
	}

	return message, aat, nil
}

func (a *Auth) verifyAuthTypeActive(identifierImpl identifierType, accountIdentifier *model.AccountIdentifier, authImpl authType, accountAuthTypes []model.AccountAuthType, accountID string,
	creds string, params string, appOrg model.ApplicationOrganization) (*string, *model.AccountAuthType, error) {
	if accountIdentifier != nil && identifierImpl.requireVerificationForSignIn() {
		err := identifierImpl.checkVerified(accountIdentifier, appOrg.Application.Name)
		if err != nil {
			return nil, nil, errors.WrapErrorData(logutils.StatusInvalid, model.TypeAccountIdentifier, &logutils.FieldArgs{"verified": false}, err)
		}
	}

	message, credID, err := a.checkCredentials(identifierImpl, authImpl, &accountID, accountAuthTypes, creds, params, appOrg)
	if err != nil {
		return nil, nil, errors.WrapErrorAction(logutils.ActionVerify, model.TypeCredential, nil, err)
	}

	for _, aat := range accountAuthTypes {
		if credID == "" || (aat.Credential != nil && aat.Credential.ID == credID) {
			aat.Active = true
			err = a.storage.UpdateAccountAuthType(nil, aat)
			if err != nil {
				return nil, nil, errors.WrapErrorAction(logutils.ActionUpdate, model.TypeAccountAuthType, nil, err)
			}

			return message, &aat, nil
		}
	}
	return nil, nil, errors.ErrorData(logutils.StatusMissing, model.TypeAccountAuthType, &logutils.FieldArgs{"credential_id": credID})
}

func (a *Auth) linkAccountAuthTypeExternal(account *model.Account, supportedAuthType model.SupportedAuthType, appType model.ApplicationType, appOrg model.ApplicationOrganization,
	creds string, params string, l *logs.Log) (*model.AccountAuthType, error) {
	authImpl, err := a.getExternalAuthTypeImpl(supportedAuthType.AuthType)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionLoadCache, model.TypeAuthType, nil, err)
	}

	externalUser, _, _, err := authImpl.externalLogin(supportedAuthType.AuthType, appType, appOrg, creds, params, l)
	if err != nil {
		return nil, errors.WrapErrorAction("logging in", "external user", nil, err)
	}

	// get the correct code for the external identifier from the external IDs map
	code := ""
	for k, v := range externalUser.ExternalIDs {
		if v == externalUser.Identifier {
			code = k
		}
	}
	if code == "" && externalUser.Email == externalUser.Identifier {
		code = IdentifierTypeEmail
	}

	var accountAuthType *model.AccountAuthType
	transaction := func(context storage.TransactionContext) error {
		newCredsAccount, err := a.storage.FindAccount(context, code, externalUser.Identifier, &appOrg.Organization.ID, &appOrg.ID)
		if err != nil {
			return errors.WrapErrorAction(logutils.ActionFind, model.TypeAccount, nil, err)
		}
		//cannot link creds if an account already exists for new creds
		if newCredsAccount != nil {
			return errors.ErrorData("existing", model.TypeAccount, nil).SetStatus(utils.ErrorStatusAlreadyExists)
		}

		accountAuthTypeParams := map[string]interface{}{"user": externalUser}
		accountAuthType, err = a.prepareAccountAuthType(supportedAuthType.AuthType, true, accountAuthTypeParams, nil)
		if err != nil {
			return errors.WrapErrorAction(logutils.ActionCreate, model.TypeAccountAuthType, nil, err)
		}

		updatedIdentifiers := a.updateExternalIdentifiers(account, accountAuthType.ID, externalUser, true)

		accountAuthType.Account = *account
		err = a.registerAccountAuthType(context, *accountAuthType, nil, account.Identifiers, updatedIdentifiers)
		if err != nil {
			return errors.WrapErrorAction(logutils.ActionRegister, model.TypeAccountAuthType, nil, err)
		}

		return nil
	}

	err = a.storage.PerformTransaction(transaction)
	if err != nil {
		return nil, err
	}

	return accountAuthType, nil
}

func (a *Auth) registerAccountAuthType(context storage.TransactionContext, accountAuthType model.AccountAuthType, credential *model.Credential, accountIdentifiers []model.AccountIdentifier, updatedIdentifiers bool) error {
	var err error
	if credential != nil {
		//TODO - in one transaction
		if err = a.storage.InsertCredential(context, credential); err != nil {
			return errors.WrapErrorAction(logutils.ActionInsert, model.TypeCredential, nil, err)
		}
	}

	err = a.storage.InsertAccountAuthType(context, accountAuthType)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionInsert, model.TypeAccountAuthType, nil, err)
	}

	if updatedIdentifiers {
		err = a.storage.UpdateAccountIdentifiers(context, accountAuthType.Account.ID, accountIdentifiers)
		if err != nil {
			return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeAccountIdentifier, nil, err)
		}
	}

	return nil
}

func (a *Auth) unlinkAccountAuthType(accountID string, accountAuthTypeID *string, authenticationType *string, identifier *string, admin bool) (*model.Account, error) {
	account, err := a.storage.FindAccountByID(nil, nil, nil, accountID)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeAccount, nil, err)
	}
	if account == nil {
		return nil, errors.ErrorData(logutils.StatusMissing, model.TypeAccount, &logutils.FieldArgs{"id": accountID})
	}
	if len(account.AuthTypes) < 2 {
		return nil, errors.ErrorData(logutils.StatusInvalid, model.TypeAccount, &logutils.FieldArgs{"auth_types": len(account.AuthTypes)})
	}

	for i, aat := range account.AuthTypes {
		// unlink auth type with matching code and identifier
		aatIDMatch := accountAuthTypeID != nil && aat.ID == *accountAuthTypeID
		aatCodeMatch := authenticationType != nil && utils.Contains(aat.SupportedAuthType.AuthType.Aliases, *authenticationType)
		if aatIDMatch || aatCodeMatch {
			transaction := func(context storage.TransactionContext) error {
				if aatCodeMatch && identifier != nil && (!aat.SupportedAuthType.AuthType.IsExternal || admin) {
					err = a.unlinkAccountIdentifier(context, account, nil, identifier, admin)
					if err != nil {
						return errors.WrapErrorAction("unlinking", model.TypeAccountIdentifier, &logutils.FieldArgs{"account_id": account.ID, "identifier": *identifier}, err)
					}
				}

				aat.Account = *account
				err = a.removeAccountAuthType(context, aat)
				if err != nil {
					return errors.WrapErrorAction("unlinking", model.TypeAccountAuthType, nil, err)
				}

				return nil
			}

			err = a.storage.PerformTransaction(transaction)
			if err != nil {
				return nil, err
			}

			account.AuthTypes = append(account.AuthTypes[:i], account.AuthTypes[i+1:]...)
			break
		}
	}

	return account, nil
}

func (a *Auth) linkAccountIdentifier(context storage.TransactionContext, account *model.Account, identifierImpl identifierType) (*string, error) {
	identifier := identifierImpl.getIdentifier()

	existingIdentifierAccount, err := a.storage.FindAccount(context, identifierImpl.getCode(), identifier, nil, &account.AppOrg.ID)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeAccount, nil, err)
	}
	if existingIdentifierAccount != nil {
		err = a.handleAccountIdentifierConflict(*existingIdentifierAccount, identifierImpl, false)
		if err != nil {
			return nil, err
		}
	}

	message, accountIdentifier, err := identifierImpl.buildIdentifier(&account.ID, account.AppOrg.Application.Name)
	if err != nil {
		return nil, errors.WrapErrorAction("building", model.TypeAccountIdentifier, &logutils.FieldArgs{"account_id": account.ID, "identifier": identifier}, err)
	}
	accountIdentifier.Linked = true

	account.Identifiers = append(account.Identifiers, *accountIdentifier)
	err = a.storage.InsertAccountIdentifier(context, *accountIdentifier)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionCreate, model.TypeAccountIdentifier, &logutils.FieldArgs{"account_id": account.ID, "identifier": identifier}, err)
	}

	return &message, nil
}

func (a *Auth) unlinkAccountIdentifier(context storage.TransactionContext, account *model.Account, accountIdentifierID *string, identifier *string, admin bool) error {
	if len(account.Identifiers) < 2 {
		return errors.ErrorData(logutils.StatusInvalid, model.TypeAccount, &logutils.FieldArgs{"identifiers": len(account.Identifiers)})
	}

	verifiedIdentifiers := account.GetVerifiedAccountIdentifiers()
	if len(verifiedIdentifiers) == 1 {
		idMatch := accountIdentifierID != nil && verifiedIdentifiers[0].ID == *accountIdentifierID
		identifierMatch := identifier != nil && verifiedIdentifiers[0].Identifier == *identifier
		if idMatch || identifierMatch {
			return errors.ErrorData(logutils.StatusInvalid, model.TypeAccount, &logutils.FieldArgs{"verified_identifiers": 1})
		}
	}

	for i, id := range account.Identifiers {
		// unlink identifier with matching identifier value (do not directly unlink identifiers with associated auth type unless admin)
		if id.AccountAuthTypeID == nil || admin {
			if (identifier != nil && *identifier == id.Identifier) || (accountIdentifierID != nil && *accountIdentifierID == id.ID) {
				id.Account = *account
				err := a.storage.DeleteAccountIdentifier(context, id)
				if err != nil {
					return errors.WrapErrorAction(logutils.ActionDelete, model.TypeAccountIdentifier, nil, err)
				}

				account.Identifiers = append(account.Identifiers[:i], account.Identifiers[i+1:]...)
				break
			}
		}
	}

	return nil
}

func (a *Auth) handleAccountIdentifierConflict(account model.Account, identifierImpl identifierType, newAccount bool) error {
	accountIdentifier := account.GetAccountIdentifier(identifierImpl.getCode(), identifierImpl.getIdentifier())
	if accountIdentifier == nil || accountIdentifier.Verified {
		//cannot link creds if a verified account already exists for new creds
		return errors.ErrorData("existing", model.TypeAccount, nil).SetStatus(utils.ErrorStatusAlreadyExists)
	}

	//if this is the only auth type (this will only be possible for accounts created through sign up that were never verified/used)
	if len(account.Identifiers) == 1 {
		//if signing up, do not replace previous unverified account created through sign up
		if newAccount {
			return errors.ErrorData("existing", model.TypeAccount, nil).SetStatus(utils.ErrorStatusAlreadyExists)
		}
		//if linked to a different unverified account, remove whole account
		accountApps := account.GetApps()
		accountAppsIDs := make([]string, len(accountApps))
		for i, c := range accountApps {
			accountAppsIDs[i] = c.ID
		}
		err := a.deleteAccount(nil, account, accountAppsIDs) //from all apps
		if err != nil {
			return errors.WrapErrorAction(logutils.ActionDelete, model.TypeAccount, nil, err)
		}
	} else {
		//Otherwise unlink auth type from account
		err := a.storage.DeleteAccountIdentifier(nil, *accountIdentifier)
		if err != nil {
			return errors.WrapErrorAction(logutils.ActionDelete, model.TypeAccountAuthType, nil, err)
		}
	}

	return nil
}

func (a *Auth) removeAccountAuthType(context storage.TransactionContext, aat model.AccountAuthType) error {
	//1. delete account auth type in account
	err := a.storage.DeleteAccountAuthType(context, aat)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionDelete, model.TypeAccountAuthType, nil, err)
	}

	//2. delete credential if it exists
	if aat.Credential != nil {
		err = a.removeAccountAuthTypeCredential(context, aat)
		if err != nil {
			return errors.WrapErrorAction(logutils.ActionDelete, model.TypeCredential, nil, err)
		}
	}

	//3. delete identifiers with matching account auth type ID
	if aat.Params["user"] != nil {
		err = a.storage.DeleteExternalAccountIdentifiers(context, aat)
		if err != nil {
			return errors.WrapErrorAction(logutils.ActionDelete, model.TypeAccountIdentifier, &logutils.FieldArgs{"external": true, "account_auth_type_id": aat.ID}, err)
		}
	}

	return nil
}

func (a *Auth) removeAccountAuthTypeCredential(context storage.TransactionContext, aat model.AccountAuthType) error {
	credential, err := a.storage.FindCredential(context, aat.Credential.ID)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionFind, model.TypeCredential, nil, err)
	}

	if len(credential.AccountsAuthTypes) > 1 {
		now := time.Now().UTC()
		for i, credAat := range credential.AccountsAuthTypes {
			if credAat.ID == aat.ID {
				credential.AccountsAuthTypes = append(credential.AccountsAuthTypes[:i], credential.AccountsAuthTypes[i+1:]...)
				credential.DateUpdated = &now
				err = a.storage.UpdateCredential(context, credential)
				if err != nil {
					return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeCredential, nil, err)
				}
				break
			}
		}
	} else {
		err = a.storage.DeleteCredential(context, credential.ID)
		if err != nil {
			return errors.WrapErrorAction(logutils.ActionDelete, model.TypeCredential, nil, err)
		}
	}

	return nil
}

func (a *Auth) deleteAccount(context storage.TransactionContext, account model.Account, fromAppsIDs []string) error {
	if len(fromAppsIDs) == 0 {
		return errors.Newf("no apps specified")
	}

	//check that every passed app is available for the account
	for _, c := range fromAppsIDs {
		hasApp := account.HasApp(c)
		if !hasApp {
			return errors.Newf("%s does not have %s app", account.ID, c)
		}
	}

	//we are sure that all passed apps are available for the account
	//now we have to decide if we have to remove the while account or just to unattach it from specific apps
	allAccountApps := account.GetApps()
	if len(allAccountApps) == len(fromAppsIDs) {
		//means remove all apps => remove the whole account
		return a.deleteFullAccount(context, account)
	}
	//means remove specific apps only, so unattach only them
	return a.deleteAppsFromAccount(context, account, fromAppsIDs)
}

func (a *Auth) deleteAppsFromAccount(context storage.TransactionContext, account model.Account, fromAppsIDs []string) error {
	// compare the applicationIDs and find the matching IDs for the org_app_memberships
	var membershipsIDs []string
	for _, a := range account.OrgAppsMemberships {
		for _, b := range fromAppsIDs {
			if a.AppOrg.Application.ID == b {
				membershipsIDs = append(membershipsIDs, a.ID)
			}
		}
	}

	err := a.storage.DeleteOrgAppsMemberships(context, account.ID, membershipsIDs)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionDelete, model.TypeAccount, nil, err)
	}

	return nil
}

func (a *Auth) deleteFullAccount(context storage.TransactionContext, account model.Account) error {
	//1. delete the account record
	err := a.storage.DeleteAccount(context, account.ID)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionDelete, model.TypeAccount, nil, err)
	}

	//2. remove account auth types from or delete credentials
	for _, aat := range account.AuthTypes {
		if aat.Credential != nil {
			err = a.removeAccountAuthTypeCredential(context, aat)
			if err != nil {
				return errors.WrapErrorAction(logutils.ActionDelete, model.TypeCredential, nil, err)
			}
		}
	}

	//3. delete login sessions
	err = a.storage.DeleteLoginSessionsByIdentifier(context, account.ID)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionDelete, model.TypeLoginSession, nil, err)
	}

	//4. delete devices records
	for _, device := range account.Devices {
		err = a.storage.DeleteDevice(context, device.ID)
		if err != nil {
			return errors.WrapErrorAction(logutils.ActionDelete, model.TypeDevice, nil, err)
		}
	}

	return nil
}

func (a *Auth) constructServiceAccount(accountID string, name string, appID string, orgID string, permissions []string, scopes []authorization.Scope, firstParty bool, assignerPermissions []string) (*model.ServiceAccount, error) {
	permissionList, err := a.storage.FindPermissionsByName(nil, permissions)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypePermission, nil, err)
	}
	for _, permission := range permissionList {
		err = permission.CheckAssigners(assignerPermissions)
		if err != nil {
			return nil, errors.WrapErrorAction(logutils.ActionValidate, "assigner permissions", &logutils.FieldArgs{"name": permission.Name}, err)
		}
	}

	var application *model.Application
	if appID != authutils.AllApps {
		application, err = a.storage.FindApplication(nil, appID)
		if err != nil || application == nil {
			return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeApplication, nil, err)
		}
	}
	var organization *model.Organization
	if orgID != authutils.AllOrgs {
		organization, err = a.storage.FindOrganization(orgID)
		if err != nil || organization == nil {
			return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeOrganization, nil, err)
		}
	}

	return &model.ServiceAccount{AccountID: accountID, Name: name, Application: application, Organization: organization,
		Permissions: permissionList, Scopes: scopes, FirstParty: firstParty}, nil
}

func (a *Auth) checkServiceAccountCreds(r *sigauth.Request, accountID *string, firstParty bool, single bool, l *logs.Log) ([]model.ServiceAccount, string, error) {
	var requestData model.ServiceAccountTokenRequest
	err := json.Unmarshal(r.Body, &requestData)
	if err != nil {
		return nil, "", errors.WrapErrorAction(logutils.ActionUnmarshal, logutils.MessageDataType("service account access token request"), nil, err)
	}

	serviceAuthType, err := a.getServiceAuthTypeImpl(requestData.AuthType)
	if err != nil {
		l.Info("error getting service auth type on get service access token")
		return nil, "", errors.WrapErrorAction(logutils.ActionGet, typeServiceAuthType, nil, err)
	}

	params := map[string]interface{}{"first_party": firstParty}
	if accountID == nil {
		params["account_id"] = requestData.AccountID
		l.AddContext("account_id", requestData.AccountID)
	} else {
		params["account_id"] = *accountID
		l.AddContext("account_id", *accountID)
	}
	if single {
		params["app_id"] = requestData.AppID
		params["org_id"] = requestData.OrgID
	}

	accounts, err := serviceAuthType.checkCredentials(r, requestData.Creds, params)
	if err != nil {
		return nil, "", errors.WrapErrorAction(logutils.ActionValidate, model.TypeServiceAccountCredential, nil, err)
	}

	return accounts, requestData.AuthType, nil
}

func (a *Auth) buildAccessTokenForServiceAccount(account model.ServiceAccount, authType string) (string, *model.AppOrgPair, error) {
	permissions := account.GetPermissionNames()
	appID := authutils.AllApps
	if account.Application != nil {
		appID = account.Application.ID
	}
	orgID := authutils.AllOrgs
	if account.Organization != nil {
		orgID = account.Organization.ID
	}

	aud := ""
	services, scope := a.tokenDataForScopes(account.Scopes)
	if account.FirstParty {
		aud = rokwireTokenAud
	} else if len(services) > 0 {
		aud = strings.Join(services, ",")
	}

	claims := a.getStandardClaims(account.AccountID, account.Name, "", "", "", aud, orgID, appID, authType, nil, nil, false, true, false, false, true, account.FirstParty, "", &a.defaultAccessTokenExpirationPolicy)
	accessToken, err := a.buildAccessToken(claims, strings.Join(permissions, ","), scope)
	if err != nil {
		return "", nil, errors.WrapErrorAction(logutils.ActionCreate, logutils.TypeToken, nil, err)
	}
	return accessToken, &model.AppOrgPair{AppID: appID, OrgID: orgID}, nil
}

func (a *Auth) registerIdentifierType(name string, identifier identifierType) error {
	if _, ok := a.identifierTypes[name]; ok {
		return errors.ErrorData(logutils.StatusFound, typeIdentifierType, &logutils.FieldArgs{"name": name})
	}

	a.identifierTypes[name] = identifier

	return nil
}

func (a *Auth) registerAuthType(name string, auth authType) error {
	if _, ok := a.authTypes[name]; ok {
		return errors.ErrorData(logutils.StatusFound, model.TypeAuthType, &logutils.FieldArgs{"name": name})
	}

	a.authTypes[name] = auth

	return nil
}

func (a *Auth) registerExternalAuthType(name string, auth externalAuthType) error {
	if _, ok := a.externalAuthTypes[name]; ok {
		return errors.ErrorData(logutils.StatusFound, typeExternalAuthType, &logutils.FieldArgs{"name": name})
	}

	a.externalAuthTypes[name] = auth

	return nil
}

func (a *Auth) registerAnonymousAuthType(name string, auth anonymousAuthType) error {
	if _, ok := a.anonymousAuthTypes[name]; ok {
		return errors.ErrorData(logutils.StatusFound, typeAnonymousAuthType, &logutils.FieldArgs{"name": name})
	}

	a.anonymousAuthTypes[name] = auth

	return nil
}

func (a *Auth) registerServiceAuthType(name string, auth serviceAuthType) error {
	if _, ok := a.serviceAuthTypes[name]; ok {
		return errors.ErrorData(logutils.StatusFound, typeServiceAuthType, &logutils.FieldArgs{"name": name})
	}

	a.serviceAuthTypes[name] = auth

	return nil
}

func (a *Auth) registerMfaType(name string, mfa mfaType) error {
	if _, ok := a.mfaTypes[name]; ok {
		return errors.ErrorData(logutils.StatusFound, model.TypeMFAType, &logutils.FieldArgs{"name": name})
	}

	a.mfaTypes[name] = mfa

	return nil
}

func (a *Auth) validateAuthType(authenticationType string, appTypeIdentifier *string, appID *string, orgID string) (*model.SupportedAuthType, *model.ApplicationType, *model.ApplicationOrganization, error) {
	//get the auth type
	authType, err := a.storage.FindAuthType(authenticationType)
	if err != nil || authType == nil {
		return nil, nil, nil, errors.WrapErrorAction(logutils.ActionValidate, model.TypeAuthType, logutils.StringArgs(authenticationType), err)
	}

	//get the app type and app org
	applicationType, appOrg, err := a.validateAppOrg(appTypeIdentifier, appID, orgID)
	if err != nil {
		return nil, nil, nil, errors.WrapErrorAction(logutils.ActionValidate, model.TypeApplicationOrganization, nil, err)
	}

	//check if the auth type is supported for this application and organization
	if applicationType != nil {
		supportedAuthType := appOrg.FindSupportedAuthType(*applicationType, *authType)
		if supportedAuthType == nil {
			return nil, nil, nil, errors.ErrorAction(logutils.ActionValidate, "not supported auth type for application and organization", &logutils.FieldArgs{"app_type_id": applicationType.ID, "auth_type_id": authType.ID})
		}
		return supportedAuthType, applicationType, appOrg, nil
	}

	for _, appType := range appOrg.Application.Types {
		supportedAuthType := appOrg.FindSupportedAuthType(appType, *authType)
		if supportedAuthType != nil {
			appTypeValue := appType
			return supportedAuthType, &appTypeValue, appOrg, nil
		}
	}
	return nil, nil, nil, errors.ErrorData(logutils.StatusInvalid, model.TypeAuthType, &logutils.FieldArgs{"app_org_id": appOrg.ID, "auth_type": authenticationType})
}

func (a *Auth) validateAppOrg(appTypeIdentifier *string, appID *string, orgID string) (*model.ApplicationType, *model.ApplicationOrganization, error) {
	var applicationID string
	var applicationType *model.ApplicationType
	var err error
	if appID != nil {
		applicationID = *appID
	} else if appTypeIdentifier != nil {
		applicationType, err = a.storage.FindApplicationType(*appTypeIdentifier)
		if err != nil {
			return nil, nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeApplicationType, logutils.StringArgs(*appTypeIdentifier), err)

		}
		if applicationType == nil {
			return nil, nil, errors.ErrorData(logutils.StatusMissing, model.TypeApplicationType, logutils.StringArgs(*appTypeIdentifier))
		}
		applicationID = applicationType.Application.ID
	}

	//get the app org
	appOrg, err := a.storage.FindApplicationOrganization(applicationID, orgID)
	if err != nil {
		return nil, nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeApplicationOrganization, &logutils.FieldArgs{"app_id": applicationID, "org_id": orgID}, err)
	}
	if appOrg == nil {
		return nil, nil, errors.ErrorData(logutils.StatusMissing, model.TypeApplicationOrganization, &logutils.FieldArgs{"app_id": applicationID, "org_id": orgID})
	}

	return applicationType, appOrg, nil
}

func (a *Auth) getIdentifierTypeImpl(identifierJSON string, identifierCode *string, userIdentifier *string) identifierType {
	if identifierCode != nil && userIdentifier != nil {
		code := *identifierCode
		if code == illinoisOIDCCode {
			// backwards compatibility: if an OIDC auth type is used, illinois_oidc was provided, so use uin as the identifier code
			code = defaultIllinoisOIDCIdentifier
		} else if code == string(phoneverifier.TypeTwilio) {
			code = IdentifierTypePhone
		}

		identifierMap := map[string]string{code: *userIdentifier}
		identifierBytes, err := json.Marshal(identifierMap)
		if err != nil {
			a.logger.Errorf("error marshalling json for identifierType: %v", err)
			return nil
		}
		identifierJSON = string(identifierBytes)
	}

	if identifierJSON != "" {
		for code, identifierImpl := range a.identifierTypes {
			if code == IdentifierTypeExternal {
				continue
			}
			if strings.Contains(identifierJSON, code) {
				specificIdentifierImpl, err := identifierImpl.withIdentifier(identifierJSON)
				if err == nil && specificIdentifierImpl.getIdentifier() != "" {
					return specificIdentifierImpl
				}
			}
		}

		// default to the external identifier type
		specificExternalImpl, err := a.identifierTypes[IdentifierTypeExternal].withIdentifier(identifierJSON)
		if err == nil && specificExternalImpl.getIdentifier() != "" {
			return specificExternalImpl
		}
	}

	return nil
}

func (a *Auth) getAuthTypeImpl(supportedAuthType model.SupportedAuthType) (authType, error) {
	if auth, ok := a.authTypes[supportedAuthType.AuthType.Code]; ok {
		return auth.withParams(supportedAuthType.Params)
	}

	return nil, errors.ErrorData(logutils.StatusInvalid, model.TypeAuthType, logutils.StringArgs(supportedAuthType.AuthType.Code))
}

func (a *Auth) getExternalAuthTypeImpl(authType model.AuthType) (externalAuthType, error) {
	key := authType.Code

	//illinois_oidc, other_oidc
	if strings.HasSuffix(authType.Code, "_"+AuthTypeOidc) {
		key = AuthTypeOidc
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

func (a *Auth) getServiceAuthTypeImpl(serviceAuthType string) (serviceAuthType, error) {
	if auth, ok := a.serviceAuthTypes[serviceAuthType]; ok {
		return auth, nil
	}

	return nil, errors.ErrorData(logutils.StatusInvalid, typeServiceAuthType, logutils.StringArgs(serviceAuthType))
}

func (a *Auth) getMfaTypeImpl(mfaType string) (mfaType, error) {
	if mfa, ok := a.mfaTypes[mfaType]; ok {
		return mfa, nil
	}

	return nil, errors.ErrorData(logutils.StatusInvalid, model.TypeMFAType, logutils.StringArgs(mfaType))
}

func (a *Auth) buildAccessToken(claims tokenauth.Claims, permissions string, scope string) (string, error) {
	claims.Purpose = "access"
	if !claims.Anonymous {
		claims.Permissions = permissions
	}
	claims.Scope = scope
	return tokenauth.GenerateSignedToken(&claims, a.currentAuthPrivKey)
}

func (a *Auth) buildCsrfToken(claims tokenauth.Claims) (string, error) {
	claims.Purpose = "csrf"
	return tokenauth.GenerateSignedToken(&claims, a.currentAuthPrivKey)
}

// getScopedAccessToken returns a scoped access token with the requested scopes
func (a *Auth) getScopedAccessToken(claims tokenauth.Claims, serviceID string, scopes []authorization.Scope) (string, error) {
	aud, scope := a.tokenDataForScopes(scopes)
	if !authutils.ContainsString(aud, serviceID) {
		aud = append(aud, serviceID)
	}

	scopedClaims := a.getStandardClaims(claims.Subject, "", "", "", "", strings.Join(aud, ","), claims.OrgID, claims.AppID, claims.AuthType, claims.ExternalIDs, &claims.ExpiresAt, claims.Anonymous, claims.Authenticated, false, false, claims.Service, false, claims.SessionID, nil)
	return a.buildAccessToken(scopedClaims, "", scope)
}

func (a *Auth) tokenDataForScopes(scopes []authorization.Scope) ([]string, string) {
	scopeStrings := make([]string, len(scopes))
	services := []string{}
	for i, scope := range scopes {
		scopeStrings[i] = scope.String()
		if !authutils.ContainsString(services, scope.ServiceID) {
			services = append(services, scope.ServiceID)
		}
	}

	return services, strings.Join(scopeStrings, " ")
}

func (a *Auth) getStandardClaims(sub string, name string, email string, phone string, username string, aud string, orgID string, appID string, authType string, externalIDs map[string]string,
	exp *int64, anonymous bool, authenticated bool, admin bool, system bool, service bool, firstParty bool, sessionID string, accessTokenExpPolicy *model.AccessTokenExpirationPolicy) tokenauth.Claims {
	return tokenauth.Claims{
		StandardClaims: jwt.StandardClaims{
			Audience:  aud,
			Subject:   sub,
			ExpiresAt: a.getExp(exp, accessTokenExpPolicy),
			IssuedAt:  time.Now().Unix(),
			Issuer:    a.host,
		}, OrgID: orgID, AppID: appID, AuthType: authType, Name: name, Email: email, Phone: phone, Username: username,
		ExternalIDs: externalIDs, Anonymous: anonymous, Authenticated: authenticated, Admin: admin, System: system,
		Service: service, FirstParty: firstParty, SessionID: sessionID,
	}
}

func (a *Auth) getExp(exp *int64, accessTokenExpPolicy *model.AccessTokenExpirationPolicy) int64 {
	policy := a.applyDefaultAccessTokenPolicy(accessTokenExpPolicy)
	defaultExp := a.defaultAccessTokenExpirationPolicy.DefaultExp
	if policy != nil {
		defaultExp = policy.DefaultExp
	}
	if exp == nil {
		defaultTime := time.Now().Add(time.Duration(defaultExp) * time.Minute)
		return defaultTime.Unix()
	}

	if policy != nil {
		expTime := time.Unix(*exp, 0)
		minTime := time.Now().Add(time.Duration(policy.MinExp) * time.Minute)
		maxTime := time.Now().Add(time.Duration(policy.MaxExp) * time.Minute)

		if expTime.Before(minTime) {
			return minTime.Unix()
		} else if expTime.After(maxTime) {
			return maxTime.Unix()
		}
	}

	return *exp
}

func (a *Auth) applyDefaultAccessTokenPolicy(policy *model.AccessTokenExpirationPolicy) *model.AccessTokenExpirationPolicy {
	if policy == nil {
		return nil
	}
	mergedPolicy := *policy
	if mergedPolicy.DefaultExp == 0 {
		mergedPolicy.DefaultExp = a.defaultAccessTokenExpirationPolicy.DefaultExp
	}
	if mergedPolicy.MinExp == 0 {
		mergedPolicy.MinExp = a.defaultAccessTokenExpirationPolicy.MinExp
	}
	if mergedPolicy.MaxExp == 0 {
		mergedPolicy.MaxExp = a.defaultAccessTokenExpirationPolicy.MaxExp
	}
	return &mergedPolicy
}

func (a *Auth) getExternalUserAuthorization(externalUser model.ExternalSystemUser, identityProviderSetting *model.IdentityProviderSetting) ([]string, []string, error) {
	if identityProviderSetting == nil {
		return nil, nil, errors.ErrorData(logutils.StatusMissing, model.TypeIdentityProviderSetting, nil)
	}

	//roles
	roles := []string{}
	for _, item := range externalUser.Roles {
		roleID := identityProviderSetting.Roles[item]
		if len(roleID) > 0 {
			roles = append(roles, roleID)
		}
	}

	//groups
	groups := []string{}
	for _, item := range externalUser.Groups {
		groupID := identityProviderSetting.Groups[item]
		if len(groupID) > 0 {
			groups = append(groups, groupID)
		}
	}

	return roles, groups, nil
}

func (a *Auth) updateExternalAccountRoles(account *model.Account, newExternalRoleIDs []string, currentAppOrgID string) (bool, error) {
	if account == nil {
		return false, errors.ErrorData(logutils.StatusInvalid, model.TypeAccount, logutils.StringArgs("nil"))
	}

	updated := false
	newRoles := []model.AccountRole{}
	//Remove any roles which were not set by an admin and are not in new list
	for _, role := range account.Roles {
		if role.AdminSet || authutils.ContainsString(newExternalRoleIDs, role.Role.ID) {
			newRoles = append(newRoles, role)
		} else {
			updated = true
		}
	}

	//Add any new roles that account does not currently have
	addedRoleIDs := []string{}
	for _, roleID := range newExternalRoleIDs {
		if account.GetRole(roleID) == nil {
			addedRoleIDs = append(addedRoleIDs, roleID)
			updated = true
		}
	}

	addedRoles, err := a.storage.FindAppOrgRolesByIDs(nil, addedRoleIDs, account.AppOrg.ID)
	if err != nil {
		return false, errors.WrapErrorAction(logutils.ActionFind, model.TypeAccountRoles, nil, err)
	}
	newRoles = append(newRoles, model.AccountRolesFromAppOrgRoles(addedRoles, true, false)...)

	//set the new roles
	account.Roles = newRoles
	index := -1
	for i, c := range account.OrgAppsMemberships {
		if c.AppOrg.ID == currentAppOrgID {
			index = i
			break
		}
	}
	if index != -1 {
		account.OrgAppsMemberships[index].Roles = newRoles
	}

	return updated, nil
}

func (a *Auth) updateExternalAccountGroups(account *model.Account, newExternalGroupIDs []string, currentAppOrgID string) (bool, error) {
	if account == nil {
		return false, errors.ErrorData(logutils.StatusInvalid, model.TypeAccount, logutils.StringArgs("nil"))
	}

	updated := false
	newGroups := []model.AccountGroup{}
	//Remove any groups which were not set by an admin and are not in new list
	for _, group := range account.Groups {
		if group.AdminSet || authutils.ContainsString(newExternalGroupIDs, group.Group.ID) {
			newGroups = append(newGroups, group)
		} else {
			updated = true
		}
	}

	addedGroupIDs := []string{}
	for _, groupID := range newExternalGroupIDs {
		if account.GetGroup(groupID) == nil {
			addedGroupIDs = append(addedGroupIDs, groupID)
			updated = true
		}
	}

	addedGroups, err := a.storage.FindAppOrgGroupsByIDs(nil, addedGroupIDs, account.AppOrg.ID)
	if err != nil {
		return false, errors.WrapErrorAction(logutils.ActionFind, model.TypeAccountGroups, nil, err)
	}
	newGroups = append(newGroups, model.AccountGroupsFromAppOrgGroups(addedGroups, true, false)...)

	account.Groups = newGroups
	index := -1
	for i, c := range account.OrgAppsMemberships {
		if c.AppOrg.ID == currentAppOrgID {
			index = i
			break
		}
	}
	if index != -1 {
		account.OrgAppsMemberships[index].Groups = newGroups
	}

	return updated, nil
}

func (a *Auth) updateExternalIdentifiers(account *model.Account, accountAuthTypeID string, externalUser *model.ExternalSystemUser, linked bool) bool {
	updated := false
	now := time.Now().UTC()
	for k, v := range externalUser.ExternalIDs {
		accountIdentifier := account.GetAccountIdentifier(k, "")
		if accountIdentifier == nil {
			primary := (v == externalUser.Identifier)
			newIdentifier := model.AccountIdentifier{ID: uuid.NewString(), Code: k, Identifier: v, Verified: true, Linked: linked, AccountAuthTypeID: &accountAuthTypeID,
				Sensitive: utils.Contains(externalUser.SensitiveExternalIDs, k), Primary: &primary, Account: model.Account{ID: account.ID}, DateCreated: now}
			account.Identifiers = append(account.Identifiers, newIdentifier)
			updated = true
		} else if accountIdentifier.Identifier != v {
			now := time.Now().UTC()
			primary := (v == externalUser.Identifier)
			accountIdentifier.Identifier = v
			accountIdentifier.Primary = &primary
			accountIdentifier.DateUpdated = &now
			updated = true
		}
	}

	if externalUser.Email != "" {
		hasExternalEmail := false
		for i, identifier := range account.Identifiers {
			if identifier.Code == IdentifierTypeEmail {
				aatMatch := identifier.AccountAuthTypeID != nil && *identifier.AccountAuthTypeID == accountAuthTypeID // have an external email
				identifierMatch := identifier.AccountAuthTypeID == nil && identifier.Identifier == externalUser.Email // have an internal email matching external email field
				hasExternalEmail = aatMatch || identifierMatch
				if (aatMatch && identifier.Identifier != externalUser.Email) || identifierMatch {
					// update if have mismatching external email or internal email matching external email field
					primary := (externalUser.Email == externalUser.Identifier)
					account.Identifiers[i].Identifier = externalUser.Email
					account.Identifiers[i].Primary = &primary
					// if the external email is not already verified, set verified to the default setting
					if !account.Identifiers[i].Verified {
						account.Identifiers[i].Verified = externalUser.IsEmailVerified
					}

					updated = true
				}
				if hasExternalEmail {
					break
				}
			}
		}
		if !hasExternalEmail {
			primary := (externalUser.Email == externalUser.Identifier)
			account.Identifiers = append(account.Identifiers, model.AccountIdentifier{ID: uuid.NewString(), Code: IdentifierTypeEmail, Identifier: externalUser.Email,
				Verified: externalUser.IsEmailVerified, Linked: linked, Sensitive: true, AccountAuthTypeID: &accountAuthTypeID, Primary: &primary,
				Account: model.Account{ID: account.ID}, DateCreated: now})
			updated = true
		}
	}

	return updated
}

func (a *Auth) setLogContext(account *model.Account, l *logs.Log) {
	accountID := "nil"
	if account != nil {
		accountID = account.ID
	}
	l.SetContext("account_id", accountID)
}

func (a *Auth) verifyServiceAESKey() error {
	key, err := a.storage.FindKey(serviceAESKey)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionFind, model.TypeKey, nil, err)
	}
	if key == nil {
		// if key does not exist, generate one and store it encrypted with the current service public key
		keyBytes, err := utils.GenerateAESKey()
		if err != nil {
			return errors.WrapErrorAction(logutils.ActionGenerate, "service AES key", nil, err)
		}

		// encrypt the new service AES key with the current service public key
		encryptedKeyBytes, err := a.currentAuthPrivKey.PubKey.Encrypt(keyBytes, nil)
		if err != nil {
			return errors.WrapErrorAction(logutils.ActionEncrypt, "service AES key", nil, err)
		}
		newKey := model.Key{Name: serviceAESKey, Key: base64.StdEncoding.EncodeToString(encryptedKeyBytes), DateCreated: time.Now().UTC()}

		err = a.storage.InsertKey(newKey)
		if err != nil {
			return errors.WrapErrorAction(logutils.ActionInsert, model.TypeKey, nil, err)
		}

		a.serviceAESKey = keyBytes
	} else {
		// if key does exist, check if it should be rotated
		decodedKey, err := base64.StdEncoding.DecodeString(key.Key)
		if err != nil {
			return errors.WrapErrorAction(logutils.ActionDecode, "service AES key", nil, err)
		}

		// attempt to decode and decrypt the stored service AES key with the current private key
		decryptedKey, err := a.currentAuthPrivKey.Decrypt(decodedKey, nil)
		if err != nil {
			a.logger.Infof("failed to decrypt service AES key using current private key: %v", err)
			a.logger.Info("attempting service private key rotation.....")

			if a.oldAuthPrivKey == nil {
				return errors.ErrorData(logutils.StatusMissing, "previous service private key", nil)
			}

			// attempt to decode and decrypt the stored service AES key with the old private key
			decryptedKey, err = a.oldAuthPrivKey.Decrypt(decodedKey, nil)
			if err != nil {
				return errors.WrapErrorAction(logutils.ActionDecrypt, "service AES key", nil, err)
			}

			// re-encrypt the service AES key with the current private key and store it
			encryptedKeyBytes, err := a.currentAuthPrivKey.PubKey.Encrypt([]byte(decryptedKey), nil)
			if err != nil {
				return errors.WrapErrorAction(logutils.ActionEncrypt, "service AES key", nil, err)
			}
			updatedKey := model.Key{Name: serviceAESKey, Key: base64.StdEncoding.EncodeToString(encryptedKeyBytes)}

			err = a.storage.UpdateKey(updatedKey)
			if err != nil {
				return errors.WrapErrorAction(logutils.ActionInsert, model.TypeKey, nil, err)
			}
		}

		a.serviceAESKey = []byte(decryptedKey)
	}

	return nil
}

// storeCoreRegs stores the service registration records for the Core BB
func (a *Auth) storeCoreRegs() error {
	err := a.storage.MigrateServiceRegs()
	if err != nil {
		return errors.WrapErrorAction("migrating", model.TypeServiceReg, nil, err)
	}

	// Setup "auth" registration for token validation
	authReg := model.ServiceRegistration{Registration: authservice.ServiceReg{ServiceID: authServiceID, Host: a.host, PubKey: a.currentAuthPrivKey.PubKey}, CoreHost: a.host,
		Name: "ROKWIRE Auth Service", Description: "The Auth Service is a subsystem of the Core Building Block that manages authentication and authorization.", FirstParty: true}
	err = a.storage.SaveServiceReg(&authReg, true)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionSave, model.TypeServiceReg, logutils.StringArgs(authServiceID), err)
	}

	// Setup core registration for signature validation
	coreReg := model.ServiceRegistration{Registration: authservice.ServiceReg{ServiceID: a.serviceID, ServiceAccountID: a.serviceID, Host: a.host, PubKey: a.currentAuthPrivKey.PubKey}, CoreHost: a.host,
		Name: "ROKWIRE Core Building Block", Description: "The Core Building Block manages user, auth, and organization data for the ROKWIRE platform.", FirstParty: true}
	err = a.storage.SaveServiceReg(&coreReg, true)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionSave, model.TypeServiceReg, logutils.StringArgs(a.serviceID), err)
	}

	return nil
}

// storeCoreServiceAccount stores the service account record for the Core BB
func (a *Auth) storeCoreServiceAccount() {
	coreAccount := model.ServiceAccount{AccountID: a.serviceID, Name: "ROKWIRE Core Building Block", FirstParty: true, DateCreated: time.Now().UTC()}
	// Setup core service account if missing
	a.storage.InsertServiceAccount(&coreAccount)
}

// cacheIdentityProviders caches the identity providers
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
		return errors.WrapErrorAction(logutils.ActionLoad, model.TypeAPIKey, nil, err)
	}
	a.setCachedAPIKeys(apiKeys)
	return nil
}

func (a *Auth) setCachedAPIKeys(apiKeys []model.APIKey) {
	a.apiKeysLock.Lock()
	defer a.apiKeysLock.Unlock()

	a.apiKeys = &syncmap.Map{}
	for _, apiKey := range apiKeys {
		a.apiKeys.Store(apiKey.ID, apiKey)
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

func (a *Auth) getCachedAPIKeys() ([]model.APIKey, error) {
	a.apiKeysLock.RLock()
	defer a.apiKeysLock.RUnlock()

	var err error
	apiKeyList := make([]model.APIKey, 0)
	idsFound := make([]string, 0)
	a.apiKeys.Range(func(key, item interface{}) bool {
		errArgs := &logutils.FieldArgs{"key": key}
		if item == nil {
			err = errors.ErrorData(logutils.StatusInvalid, model.TypeAPIKey, errArgs)
			return false
		}

		apiKey, ok := item.(model.APIKey)
		if !ok {
			err = errors.ErrorAction(logutils.ActionCast, model.TypeAPIKey, errArgs)
			return false
		}

		if !utils.Contains(idsFound, apiKey.ID) {
			apiKeyList = append(apiKeyList, apiKey)
			idsFound = append(idsFound, apiKey.ID)
		}

		return true
	})

	return apiKeyList, err
}

func (a *Auth) deleteSessions() {
	// to delete:
	// - not completed MFA
	// - expired sessions

	//1. not completed MFA
	a.deleteNotCompletedMFASessions()

	//2. expired sessions
	a.deleteExpiredSessions()
}

func (a *Auth) deleteNotCompletedMFASessions() {
	a.logger.Info("deleteNotCompletedMFASessions")

	err := a.storage.DeleteMFAExpiredSessions()
	if err != nil {
		a.logger.Error(err.Error())
	}
}

func (a *Auth) deleteExpiredSessions() {
	a.logger.Info("deleteExpiredSessions")

	appsOrgs, err := a.storage.FindApplicationsOrganizations()
	if err != nil {
		a.logger.Error(err.Error())
	}

	if len(appsOrgs) == 0 {
		a.logger.Error("for some reasons apps orgs are missing")
		return
	}

	for _, appOrg := range appsOrgs {
		a.logger.Infof("delete expired sessions for %s app org", appOrg.ID)

		//find the app/org sessions
		sessions, err := a.storage.FindSessionsLazy(appOrg.Application.ID, appOrg.Organization.ID)
		if err != nil {
			a.logger.Errorf("error on finding unused sessions - %s", err)
		}

		//continue if no sessions
		if len(sessions) == 0 {
			a.logger.Infof("no sessions for %s app org", appOrg.ID)
			continue
		}

		//determine which sessions are expired
		forDelete := []model.LoginSession{}
		for _, session := range sessions {
			if session.IsExpired() {
				forDelete = append(forDelete, session)
			}
		}

		//count if no expired sessions
		if len(forDelete) == 0 {
			a.logger.Infof("no expired sessions for %s app org", appOrg.ID)
			continue
		}

		//we have expired sessions, so we need to delete them
		expiredCount := len(forDelete)
		a.logger.Infof("we have %d expired sessions, so we need to delete them", expiredCount)

		//we delete max 250 items
		if expiredCount > maxSessionsDelete {
			a.logger.Infof("%d expired sessions > %d, so remove only %d",
				expiredCount, maxSessionsDelete, maxSessionsDelete)
			forDelete = forDelete[0 : maxSessionsDelete-1]
		} else {
			a.logger.Infof("%d expired sessions <= %d, so do nothing", expiredCount, maxSessionsDelete)
		}

		//log the data that will be deleted and prepare the IDs
		ids := make([]string, len(forDelete))
		a.logger.Info("expired sessions to be deleted:")
		for i, session := range forDelete {
			a.logger.Info("deleting loging session - " + session.LogInfo())

			ids[i] = session.ID
		}

		//delete the sessions from the storage
		err = a.storage.DeleteLoginSessionsByIDs(nil, ids)
		if err != nil {
			a.logger.Errorf("error on deleting logins sessions - %s", err)
		}
	}
}

// LocalServiceRegLoaderImpl provides a local implementation for AuthDataLoader
type LocalServiceRegLoaderImpl struct {
	storage Storage
	*authservice.ServiceRegSubscriptions
}

// LoadServices implements ServiceRegLoader interface
func (l *LocalServiceRegLoaderImpl) LoadServices() ([]authservice.ServiceReg, error) {
	regs := l.storage.FindServiceRegs(l.GetSubscribedServices())
	authRegs := make([]authservice.ServiceReg, len(regs))
	for i, serviceReg := range regs {
		reg := serviceReg.Registration
		reg.PubKey.Decode()
		authRegs[i] = reg
	}

	return authRegs, nil
}

// NewLocalServiceRegLoader creates and configures a new LocalServiceRegLoaderImpl instance
func NewLocalServiceRegLoader(storage Storage) *LocalServiceRegLoaderImpl {
	subscriptions := authservice.NewServiceRegSubscriptions([]string{allServices})
	return &LocalServiceRegLoaderImpl{storage: storage, ServiceRegSubscriptions: subscriptions}
}

// LocalServiceAccountLoaderImpl provides a local implementation for authservice.ServiceAccountLoader
type LocalServiceAccountLoaderImpl struct {
	auth Auth
}

// LoadAccessToken gets an access token for appID, orgID if the implementing service is granted access
func (l *LocalServiceAccountLoaderImpl) LoadAccessToken(appID string, orgID string) (*authservice.AccessToken, error) {
	account, err := l.auth.storage.FindServiceAccount(nil, l.auth.serviceID, authutils.AllApps, authutils.AllOrgs)
	if err != nil || account == nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeServiceAccount, logutils.StringArgs(l.auth.serviceID), err)
	}
	token, _, err := l.auth.buildAccessTokenForServiceAccount(*account, ServiceAuthTypeCore)
	return &authservice.AccessToken{Token: token, TokenType: model.TokenTypeBearer}, err
}

// LoadAccessTokens gets an access token for each app org pair the implementing service is granted access
func (l *LocalServiceAccountLoaderImpl) LoadAccessTokens() (map[authservice.AppOrgPair]authservice.AccessToken, error) {
	token, err := l.LoadAccessToken(authutils.AllApps, authutils.AllOrgs)
	if err != nil || token == nil {
		return nil, errors.WrapErrorAction(logutils.ActionGet, logutils.TypeToken, nil, err)
	}
	tokens := map[authservice.AppOrgPair]authservice.AccessToken{{AppID: authutils.AllApps, OrgID: authutils.AllOrgs}: *token}
	return tokens, nil
}

// NewLocalServiceAccountLoader creates and configures a new LocalServiceAccountLoaderImpl instance
func NewLocalServiceAccountLoader(auth Auth) *LocalServiceAccountLoaderImpl {
	return &LocalServiceAccountLoaderImpl{auth: auth}
}

// StorageListener represents storage listener implementation for the auth package
type StorageListener struct {
	auth *Auth
	storage.DefaultListenerImpl
}

// OnIdentityProvidersUpdated notifies that identity providers have been updated
func (al *StorageListener) OnIdentityProvidersUpdated() {
	al.auth.cacheIdentityProviders()
}

// OnAPIKeysUpdated notifies api keys have been updated
func (al *StorageListener) OnAPIKeysUpdated() {
	al.auth.cacheAPIKeys()
}

// OnServiceRegistrationsUpdated notifies that a service registration has been updated
func (al *StorageListener) OnServiceRegistrationsUpdated() {
	al.auth.ServiceRegManager.LoadServices()
}
