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
	"core-building-block/driven/storage"
	"core-building-block/utils"
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
	authKeyAlg     string = "RS256"
	rokwireKeyword string = "ROKWIRE"

	rokwireTokenAud string = "rokwire"

	allServices string = "all"

	// AdminScopePrefix is the prefix on scope resources used to indicate that the scope is intended for administration
	AdminScopePrefix string = "admin_"
	// UpdateScopesPermission is the permission that allows an admin to update account/role scopes
	UpdateScopesPermission string = "update_auth_scopes"

	typeMail              logutils.MessageDataType = "mail"
	typeExternalAuthType  logutils.MessageDataType = "external auth type"
	typeAnonymousAuthType logutils.MessageDataType = "anonymous auth type"
	typeServiceAuthType   logutils.MessageDataType = "service auth type"
	typeAuth              logutils.MessageDataType = "auth"
	typeAuthRefreshParams logutils.MessageDataType = "auth refresh params"

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
	storage Storage
	emailer Emailer

	logger *logs.Logger

	authTypes          map[string]authType
	externalAuthTypes  map[string]externalAuthType
	anonymousAuthTypes map[string]anonymousAuthType
	serviceAuthTypes   map[string]serviceAuthType
	mfaTypes           map[string]mfaType

	authPrivKey *keys.PrivKey

	ServiceRegManager *authservice.ServiceRegManager
	SignatureAuth     *sigauth.SignatureAuth

	serviceID   string
	host        string //Service host
	minTokenExp int64  //Minimum access token expiration time in minutes
	maxTokenExp int64  //Maximum access token expiration time in minutes

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
func NewAuth(serviceID string, host string, authPrivKey *keys.PrivKey, authService *authservice.AuthService, storage Storage, emailer Emailer, minTokenExp *int64,
	maxTokenExp *int64, supportLegacySigs bool, twilioAccountSID string, twilioToken string, twilioServiceSID string, profileBB ProfileBuildingBlock,
	smtpHost string, smtpPortNum int, smtpUser string, smtpPassword string, smtpFrom string, logger *logs.Logger, version string) (*Auth, error) {
	if minTokenExp == nil {
		var minTokenExpVal int64 = 5
		minTokenExp = &minTokenExpVal
	}

	if maxTokenExp == nil {
		var maxTokenExpVal int64 = 60
		maxTokenExp = &maxTokenExpVal
	}

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

	auth := &Auth{storage: storage, emailer: emailer, logger: logger, authTypes: authTypes, externalAuthTypes: externalAuthTypes, anonymousAuthTypes: anonymousAuthTypes,
		serviceAuthTypes: serviceAuthTypes, mfaTypes: mfaTypes, authPrivKey: authPrivKey, ServiceRegManager: nil, serviceID: serviceID, host: host, minTokenExp: *minTokenExp,
		maxTokenExp: *maxTokenExp, profileBB: profileBB, cachedIdentityProviders: cachedIdentityProviders, identityProvidersLock: identityProvidersLock,
		apiKeys: apiKeys, apiKeysLock: apiKeysLock, deleteSessionsTimerDone: deleteSessionsTimerDone, version: version}

	err := auth.storeCoreRegs()
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

	signatureAuth, err := sigauth.NewSignatureAuth(authPrivKey, serviceRegManager, true, supportLegacySigs)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionInitialize, "signature auth", nil, err)
	}

	auth.SignatureAuth = signatureAuth

	// auth types
	initUsernameAuth(auth)
	initEmailAuth(auth)
	initPhoneAuth(auth, twilioAccountSID, twilioToken, twilioServiceSID)
	initFirebaseAuth(auth)
	initAnonymousAuth(auth)
	initSignatureAuth(auth)

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

func (a *Auth) applyExternalAuthType(authType model.AuthType, appType model.ApplicationType, appOrg model.ApplicationOrganization, creds string, params string, clientVersion *string,
	regProfile model.Profile, privacy model.Privacy, regPreferences map[string]interface{}, username string, admin bool, l *logs.Log) (*model.AccountAuthType, map[string]interface{}, []model.MFAType, map[string]string, error) {
	var accountAuthType *model.AccountAuthType
	var mfaTypes []model.MFAType
	var externalIDs map[string]string

	//external auth type
	authImpl, err := a.getExternalAuthTypeImpl(authType)
	if err != nil {
		return nil, nil, nil, nil, errors.WrapErrorAction(logutils.ActionLoadCache, typeExternalAuthType, nil, err)
	}

	//1. get the user from the external system
	//var externalUser *model.ExternalSystemUser
	externalUser, extParams, externalCreds, err := authImpl.externalLogin(authType, appType, appOrg, creds, params, l)
	if err != nil {
		return nil, nil, nil, nil, errors.WrapErrorAction("logging in", "external user", nil, err)
	}

	//2. find the account for the org and the user identity
	account, err := a.storage.FindAccountByOrgAndIdentifier(nil, appOrg.Organization.ID, authType.ID, externalUser.Identifier, appOrg.ID)
	if err != nil {
		return nil, nil, nil, nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeAccount, nil, err) //TODO add args..
	}
	a.setLogContext(account, l)

	//3. check if it is "sign-in" or "org-sign-up" or "app-sign-up"
	operation, err := a.determineOperationExternal(account, appOrg.ID, l)
	if err != nil {
		return nil, nil, nil, nil, errors.WrapErrorAction(logutils.ActionVerify, "determine operation external", nil, err)
	}
	//4. apply operation
	switch operation {
	case "sign-in":
		canSignIn := a.canSignInV2(account, authType.ID, externalUser.Identifier, appOrg.ID)
		if !canSignIn {
			return nil, nil, nil, nil, errors.Newf("cannot sign in %s %s", authType.ID, externalUser.Identifier)
		}

		//account exists
		accountAuthType, err = a.applySignInExternal(account, authType, appOrg, *externalUser, externalCreds, l)
		if err != nil {
			return nil, nil, nil, nil, errors.WrapErrorAction(logutils.ActionApply, "external sign in", nil, err)
		}
		mfaTypes = account.GetVerifiedMFATypes()
		externalIDs = account.ExternalIDs

		//TODO: make sure we do not return any refresh tokens in extParams
		return accountAuthType, extParams, mfaTypes, externalIDs, nil
	case "app-sign-up":
		if admin {
			return nil, nil, nil, nil, errors.ErrorData(logutils.StatusInvalid, "sign up", &logutils.FieldArgs{"identifier": externalUser.Identifier,
				"auth_type": authType.Code, "app_org_id": appOrg.ID, "admin": true}).SetStatus(utils.ErrorStatusNotAllowed)
		}

		//We have prepared this operation as it is based on the tenants accounts but for now we disable it
		//as we do not use it(yet) and better not to introduce additional complexity.
		//Also this would trigger client updates as well for supporting this
		return nil, nil, nil, nil, errors.New("app-sign-up operation is not supported")
	case "org-sign-up":
		if admin {
			return nil, nil, nil, nil, errors.ErrorData(logutils.StatusInvalid, "sign up", &logutils.FieldArgs{"identifier": externalUser.Identifier,
				"auth_type": authType.Code, "app_org_id": appOrg.ID, "admin": true}).SetStatus(utils.ErrorStatusNotAllowed)
		}

		//user does not exist, we need to register it
		accountAuthType, err = a.applyOrgSignUpExternal(nil, authType, appOrg, *externalUser, externalCreds, regProfile, privacy, regPreferences, username, clientVersion, l)
		if err != nil {
			return nil, nil, nil, nil, errors.WrapErrorAction(logutils.ActionApply, "external sign up", nil, err)
		}
		externalIDs = externalUser.ExternalIDs

		//TODO: make sure we do not return any refresh tokens in extParams
		return accountAuthType, extParams, mfaTypes, externalIDs, nil
	}

	return nil, nil, nil, nil, errors.Newf("not supported operation - internal auth type")
}

func (a *Auth) applySignInExternal(account *model.Account, authType model.AuthType, appOrg model.ApplicationOrganization,
	externalUser model.ExternalSystemUser, externalCreds string, l *logs.Log) (*model.AccountAuthType, error) {
	var accountAuthType *model.AccountAuthType
	var err error

	//find account auth type
	accountAuthType, err = a.findAccountAuthType(account, &authType, externalUser.Identifier)
	if err != nil {
		return nil, err
	}

	//check if need to update the account data
	newAccount, err := a.updateExternalUserIfNeeded(*accountAuthType, externalUser, authType, appOrg, externalCreds, l)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionUpdate, model.TypeExternalSystemUser, nil, err)
	}

	if newAccount != nil {
		accountAuthType.Account = *newAccount
	}

	if accountAuthType.Unverified {
		accountAuthType.SetUnverified(false)
		err := a.storage.UpdateAccountAuthType(*accountAuthType)
		if err != nil {
			return nil, errors.WrapErrorAction(logutils.ActionUpdate, model.TypeAccountAuthType, nil, err)
		}
	}

	return accountAuthType, nil
}

func (a *Auth) applyOrgSignUpExternal(context storage.TransactionContext, authType model.AuthType, appOrg model.ApplicationOrganization, externalUser model.ExternalSystemUser,
	externalCreds string, regProfile model.Profile, privacy model.Privacy, regPreferences map[string]interface{}, username string, clientVersion *string, l *logs.Log) (*model.AccountAuthType, error) {
	var accountAuthType *model.AccountAuthType

	//1. prepare external admin user data
	identifier, aatParams, profile, preferences, err := a.prepareExternalUserData(authType, appOrg, externalUser, regProfile, nil, l)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionPrepare, "external admin user data", nil, err)
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

	//2. apply profile data from the external user if not provided
	newProfile, err := a.applyProfileDataFromExternalUser(*profile, externalUser, nil, identityBBProfile, false, l)
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

	//4. check username
	if username != "" {
		err = a.checkUsername(nil, &appOrg, username)
		if err != nil {
			return nil, err
		}
	}

	//5. register the account
	accountAuthType, err = a.registerUser(context, authType, identifier, aatParams, appOrg, nil,
		externalUser.ExternalIDs, *profile, privacy, preferences, username, nil, externalRoles, externalGroups, nil, nil, clientVersion, l)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionRegister, model.TypeAccount, nil, err)
	}

	return accountAuthType, nil
}

func (a *Auth) applySignUpAdminExternal(context storage.TransactionContext, authType model.AuthType, appOrg model.ApplicationOrganization, externalUser model.ExternalSystemUser, regProfile model.Profile,
	privacy model.Privacy, username string, permissions []string, roleIDs []string, groupIDs []string, scopes []string, creatorPermissions []string, clientVersion *string, l *logs.Log) (*model.AccountAuthType, error) {
	var accountAuthType *model.AccountAuthType

	//1. prepare external admin user data
	identifier, aatParams, profile, _, err := a.prepareExternalUserData(authType, appOrg, externalUser, regProfile, nil, l)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionPrepare, "external admin user data", nil, err)
	}

	//2. check username
	if username != "" {
		err = a.checkUsername(nil, &appOrg, username)
		if err != nil {
			return nil, err
		}
	}

	//3. register the account
	accountAuthType, err = a.registerUser(context, authType, identifier, aatParams, appOrg, nil, nil, *profile, privacy, nil,
		username, permissions, roleIDs, groupIDs, scopes, creatorPermissions, clientVersion, l)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionRegister, "admin account", nil, err)
	}

	return accountAuthType, nil
}

func (a *Auth) prepareExternalUserData(authType model.AuthType, appOrg model.ApplicationOrganization, externalUser model.ExternalSystemUser, regProfile model.Profile,
	regPreferences map[string]interface{}, l *logs.Log) (string, map[string]interface{}, *model.Profile, map[string]interface{}, error) {
	var profile model.Profile
	var preferences map[string]interface{}

	/*	//1. check if needs to use shared profile
		useSharedProfile, sharedProfile, _, err := a.applySharedProfile(appOrg.Application, authType.ID, externalUser.Identifier, l)
		if err != nil {
			return "", nil, false, nil, nil, errors.WrapErrorAction(logutils.ActionApply, "shared profile", nil, err)
		}

		if useSharedProfile {
			l.Infof("%s uses a shared profile", externalUser.Identifier)

			//merge client profile and shared profile
			profile = a.mergeProfiles(regProfile, sharedProfile, true)
			preferences = regPreferences
		} else { */
	l.Infof("%s does not use a shared profile", externalUser.Identifier)

	profile = regProfile
	preferences = regPreferences

	//prepare profile and preferences
	preparedProfile, preparedPreferences, err := a.prepareRegistrationData(authType, externalUser.Identifier, profile, preferences, l)
	if err != nil {
		return "", nil, nil, nil, errors.WrapErrorAction(logutils.ActionPrepare, "user registration data", nil, err)
	}
	profile = *preparedProfile
	preferences = preparedPreferences
	//	}

	//2. prepare the registration data
	params := map[string]interface{}{}
	params["user"] = externalUser

	return externalUser.Identifier, params, &profile, preferences, nil
}

func (a *Auth) applyProfileDataFromExternalUser(profile model.Profile, newExternalUser model.ExternalSystemUser,
	currentExternalUser *model.ExternalSystemUser, identityBBProfile *model.Profile, alwaysSync bool, l *logs.Log) (*model.Profile, error) {
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
	//email
	if len(newExternalUser.Email) > 0 && (alwaysSync || len(profile.Email) == 0 || (currentExternalUser != nil && currentExternalUser.Email != newExternalUser.Email)) {
		newProfile.Email = newExternalUser.Email
	}

	changed := !utils.DeepEqual(profile, newProfile)
	if changed {
		now := time.Now()
		newProfile.DateUpdated = &now
		return &newProfile, nil
	}

	return nil, nil
}

func (a *Auth) updateExternalUserIfNeeded(accountAuthType model.AccountAuthType, externalUser model.ExternalSystemUser,
	authType model.AuthType, appOrg model.ApplicationOrganization, externalCreds string, l *logs.Log) (*model.Account, error) {
	l.Info("updateExternalUserIfNeeded")

	//get the current external user
	currentDataMap := accountAuthType.Params["user"]
	currentDataJSON, err := utils.ConvertToJSON(currentDataMap)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionMarshal, model.TypeExternalSystemUser, nil, err)
	}
	var currentData *model.ExternalSystemUser
	err = json.Unmarshal(currentDataJSON, &currentData)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionUnmarshal, model.TypeExternalSystemUser, nil, err)
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
	updatedExternalUser := !currentData.Equals(externalUser)
	accountAuthType.Params["user"] = externalUser
	now := time.Now()
	accountAuthType.DateUpdated = &now

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
				newAccountAuthTypes[j] = accountAuthType
			} else {
				newAccountAuthTypes[j] = aAuthType
			}
		}
		account.AuthTypes = newAccountAuthTypes

		// 3. update external ids
		for k, v := range externalUser.ExternalIDs {
			if account.ExternalIDs == nil {
				account.ExternalIDs = make(map[string]string)
			}
			if account.ExternalIDs[k] != v {
				updatedExternalUser = true
				account.ExternalIDs[k] = v
			}
		}

		// 4. update profile
		profileUpdated := false
		newProfile, err := a.applyProfileDataFromExternalUser(account.Profile, externalUser, currentData, identityBBProfile,
			identityProviderSetting.AlwaysSyncProfile, l)
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
		if updatedExternalUser || profileUpdated || rolesUpdated || groupsUpdated {
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

	account, err := a.storage.FindAccountByID(nil, anonymousID)
	if err != nil {
		return "", nil, nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeAccount, &logutils.FieldArgs{"id": anonymousID}, err)
	}
	if account != nil && !account.Anonymous {
		return "", nil, nil, errors.ErrorData(logutils.StatusInvalid, "anonymous account", &logutils.FieldArgs{"id": anonymousID})
	}

	return anonymousID, account, anonymousParams, nil
}

func (a *Auth) applyAuthType(authType model.AuthType, appOrg model.ApplicationOrganization, creds string, params string, clientVersion *string, regProfile model.Profile,
	privacy model.Privacy, regPreferences map[string]interface{}, username string, admin bool, l *logs.Log) (string, *model.AccountAuthType, []model.MFAType, map[string]string, error) {

	//auth type
	authImpl, err := a.getAuthTypeImpl(authType)
	if err != nil {
		return "", nil, nil, nil, errors.WrapErrorAction(logutils.ActionLoadCache, model.TypeAuthType, nil, err)
	}

	//check if the user exists check
	userIdentifier, err := authImpl.getUserIdentifier(creds)
	if err != nil {
		return "", nil, nil, nil, errors.WrapErrorAction(logutils.ActionGet, "user identifier", nil, err)
	}

	if userIdentifier != "" {
		if authType.Code == AuthTypeTwilioPhone && regProfile.Phone == "" {
			regProfile.Phone = userIdentifier
		} else if authType.Code == AuthTypeEmail && regProfile.Email == "" {
			regProfile.Email = userIdentifier
		} else if authType.Code == authTypeUsername {
			username = userIdentifier
		}
	}

	//find the account for the org and the user identity
	account, err := a.storage.FindAccountByOrgAndIdentifier(nil, appOrg.Organization.ID, authType.ID, userIdentifier, appOrg.ID)
	if err != nil {
		return "", nil, nil, nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeAccount, nil, err) //TODO add args..
	}
	a.setLogContext(account, l)

	//check if it is "sign-in" or "org-sign-up" or "app-sign-up"
	operation, err := a.determineOperationInternal(account, appOrg.ID, params, l)
	if err != nil {
		return "", nil, nil, nil, errors.WrapErrorAction(logutils.ActionVerify, "determine operation internal", nil, err)
	}
	switch operation {
	case "sign-in":
		canSignIn := a.canSignInV2(account, authType.ID, userIdentifier, appOrg.ID)
		if !canSignIn {
			return "", nil, nil, nil, errors.Newf("cannot sign in %s %s", authType.ID, userIdentifier)
		}

		///apply sign in
		message, accountAuthType, mfaTypes, externalIDs, err := a.applySignIn(authImpl, authType, account, userIdentifier, creds, l)
		if err != nil {
			return "", nil, nil, nil, err
		}
		return message, accountAuthType, mfaTypes, externalIDs, nil
	case "app-sign-up":
		if admin {
			return "", nil, nil, nil, errors.ErrorData(logutils.StatusInvalid, "sign up", &logutils.FieldArgs{"identifier": userIdentifier,
				"auth_type": authType.Code, "app_org_id": appOrg.ID, "admin": true}).SetStatus(utils.ErrorStatusNotAllowed)
		}

		//We have prepared this operation as it is based on the tenants accounts but for now we disable it
		//as we do not use it(yet) and better not to introduce additional complexity.
		//Also this would trigger client updates as well for supporting this
		return "", nil, nil, nil, errors.New("app-sign-up operation is not supported")
	case "org-sign-up":
		if admin {
			return "", nil, nil, nil, errors.ErrorData(logutils.StatusInvalid, "sign up", &logutils.FieldArgs{"identifier": userIdentifier,
				"auth_type": authType.Code, "app_org_id": appOrg.ID, "admin": true}).SetStatus(utils.ErrorStatusNotAllowed)
		}

		message, accountAuthType, err := a.applyOrgSignUp(authImpl, account, authType, appOrg, userIdentifier, creds, params, clientVersion,
			regProfile, privacy, regPreferences, username, l)
		if err != nil {
			return "", nil, nil, nil, err
		}
		return message, accountAuthType, nil, nil, nil
	}

	return "", nil, nil, nil, errors.Newf("not supported operation - internal auth type")
}

func (a *Auth) applySignIn(authImpl authType, authType model.AuthType, account *model.Account, userIdentifier string,
	creds string, l *logs.Log) (string, *model.AccountAuthType, []model.MFAType, map[string]string, error) {
	if account == nil {
		return "", nil, nil, nil, errors.ErrorData(logutils.StatusMissing, model.TypeAccount, nil).SetStatus(utils.ErrorStatusNotFound)
	}

	//find account auth type
	accountAuthType, err := a.findAccountAuthType(account, &authType, userIdentifier)
	if accountAuthType == nil {
		return "", nil, nil, nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeAccountAuthType, nil, err)
	}

	if accountAuthType.Unverified && accountAuthType.Linked {
		return "", nil, nil, nil, errors.ErrorData(logutils.StatusInvalid, model.TypeAccountAuthType, &logutils.FieldArgs{"verified": false, "linked": true})
	}

	var message string
	message, err = a.checkCredentials(authImpl, authType, accountAuthType, creds, l)
	if err != nil {
		return "", nil, nil, nil, errors.WrapErrorAction(logutils.ActionVerify, model.TypeCredential, nil, err)
	}

	return message, accountAuthType, account.GetVerifiedMFATypes(), account.ExternalIDs, nil
}

func (a *Auth) checkCredentialVerified(authImpl authType, accountAuthType *model.AccountAuthType, l *logs.Log) error {
	verified, expired, err := authImpl.isCredentialVerified(accountAuthType.Credential, l)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionVerify, "credential verified", nil, err)
	}

	if !*verified {
		//it is unverified
		if expired == nil || !*expired {
			//not expired, just notify the client that it is "unverified"
			return errors.ErrorData("unverified", "credential", nil).SetStatus(utils.ErrorStatusUnverified)
		}
		//expired, first restart the verification and then notify the client that it is unverified and verification is restarted

		//restart credential verification
		err = authImpl.restartCredentialVerification(accountAuthType.Credential, accountAuthType.Account.AppOrg.Application.Name, l)
		if err != nil {
			return errors.WrapErrorAction("restarting", "credential verification", nil, err)
		}

		//notify the client
		return errors.ErrorData("expired", "credential verification", nil).SetStatus(utils.ErrorStatusVerificationExpired)
	}

	return nil
}

func (a *Auth) checkCredentials(authImpl authType, authType model.AuthType, accountAuthType *model.AccountAuthType, creds string, l *logs.Log) (string, error) {
	//check is verified
	if authType.UseCredentials {
		err := a.checkCredentialVerified(authImpl, accountAuthType, l)
		if err != nil {
			return "", err
		}
	}

	//check the credentials
	message, err := authImpl.checkCredentials(*accountAuthType, creds, l)
	if err != nil {
		return message, errors.WrapErrorAction(logutils.ActionValidate, model.TypeCredential, nil, err)
	}

	//if sign in was completed successfully, set auth type to verified
	if message == "" && accountAuthType.Unverified {
		accountAuthType.SetUnverified(false)
		err := a.storage.UpdateAccountAuthType(*accountAuthType)
		if err != nil {
			return "", errors.WrapErrorAction(logutils.ActionUpdate, model.TypeAccountAuthType, nil, err)
		}
	}

	return message, nil
}

func (a *Auth) applyOrgSignUp(authImpl authType, account *model.Account, authType model.AuthType, appOrg model.ApplicationOrganization, userIdentifier string, creds string,
	params string, clientVersion *string, regProfile model.Profile, privacy model.Privacy, regPreferences map[string]interface{}, username string, l *logs.Log) (string, *model.AccountAuthType, error) {
	if account != nil {
		err := a.handleAccountAuthTypeConflict(*account, authType.ID, userIdentifier, true)
		if err != nil {
			return "", nil, err
		}
	}

	if username != "" {
		err := a.checkUsername(nil, &appOrg, username)
		if err != nil {
			return "", nil, err
		}
	}

	retParams, accountAuthType, err := a.signUpNewAccount(nil, authImpl, authType, appOrg, userIdentifier, creds, params, clientVersion, regProfile, privacy, regPreferences, username, nil, nil, nil, nil, nil, l)
	if err != nil {
		return "", nil, err
	}

	message, _ := retParams["message"].(string)
	return message, accountAuthType, nil
}

func (a *Auth) applySignUpAdmin(context storage.TransactionContext, authImpl authType, account *model.Account, authType model.AuthType, appOrg model.ApplicationOrganization, identifier string, password string,
	regProfile model.Profile, privacy model.Privacy, username string, permissions []string, roles []string, groups []string, scopes []string, creatorPermissions []string, clientVersion *string, l *logs.Log) (map[string]interface{}, *model.AccountAuthType, error) {

	if username != "" {
		err := a.checkUsername(nil, &appOrg, username)
		if err != nil {
			return nil, nil, err
		}
	}

	return a.signUpNewAccount(context, authImpl, authType, appOrg, identifier, password, "", clientVersion, regProfile, privacy, nil, username, permissions, roles, groups, scopes, creatorPermissions, l)
}

func (a *Auth) applyCreateAnonymousAccount(context storage.TransactionContext, appOrg model.ApplicationOrganization, anonymousID string,
	preferences map[string]interface{}, systemConfigs map[string]interface{}, l *logs.Log) (*model.Account, error) {

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

func (a *Auth) signUpNewAccount(context storage.TransactionContext, authImpl authType, authType model.AuthType, appOrg model.ApplicationOrganization, userIdentifier string,
	creds string, params string, clientVersion *string, regProfile model.Profile, privacy model.Privacy, regPreferences map[string]interface{}, username string, permissions []string,
	roles []string, groups []string, scopes []string, creatorPermissions []string, l *logs.Log) (map[string]interface{}, *model.AccountAuthType, error) {
	var retParams map[string]interface{}
	var credential *model.Credential
	var profile model.Profile
	var preferences map[string]interface{}

	/*
		//check if needs to use shared profile
		useSharedProfile, sharedProfile, sharedCredential, err := a.applySharedProfile(appOrg.Application, authType.ID, userIdentifier, l)
		if err != nil {
			return nil, nil, errors.WrapErrorAction(logutils.ActionApply, "shared profile", nil, err)
		}

			if useSharedProfile {
			l.Infof("%s uses a shared profile", userIdentifier)

			//allow sign up only if the shared credential is verified
			if credential != nil && !credential.Verified {
				l.Infof("trying to sign up in %s with unverified shared credentials", appOrg.Organization.Name)
				return nil, nil, errors.ErrorData("unverified", model.TypeCredential, nil).SetStatus(utils.ErrorStatusSharedCredentialUnverified)
			}

			//merge client profile and shared profile
			profile = a.mergeProfiles(regProfile, sharedProfile, true)
			preferences = regPreferences

			credential = sharedCredential
			retParams = map[string]interface{}{"message": "successfuly registered"}
		} else { */
	l.Infof("%s does not use a shared profile", userIdentifier)

	profile = regProfile
	preferences = regPreferences

	preparedProfile, preparedPreferences, err := a.prepareRegistrationData(authType, userIdentifier, profile, preferences, l)
	if err != nil {
		return nil, nil, errors.WrapErrorAction(logutils.ActionPrepare, "user registration data", nil, err)
	}
	profile = *preparedProfile
	preferences = preparedPreferences

	credID := uuid.NewString()

	//apply sign up
	var credentialValue map[string]interface{}
	if creatorPermissions == nil {
		var message string
		message, credentialValue, err = authImpl.signUp(authType, appOrg, creds, params, credID, l)
		if err != nil {
			return nil, nil, errors.WrapErrorAction("signing up", "user", nil, err)
		}

		retParams = map[string]interface{}{"message": message}
	} else {
		retParams, credentialValue, err = authImpl.signUpAdmin(authType, appOrg, userIdentifier, creds, credID)
		if err != nil {
			return nil, nil, errors.WrapErrorAction("signing up", "admin user", nil, err)
		}
	}

	//credential
	if credentialValue != nil {
		now := time.Now()
		credential = &model.Credential{ID: credID, AccountsAuthTypes: nil, Value: credentialValue, Verified: false,
			AuthType: authType, DateCreated: now, DateUpdated: &now}
	}
	//	}

	accountAuthType, err := a.registerUser(context, authType, userIdentifier, nil, appOrg, credential,
		nil, profile, privacy, preferences, username, permissions, roles, groups, scopes, creatorPermissions, clientVersion, l)
	if err != nil {
		return nil, nil, errors.WrapErrorAction(logutils.ActionRegister, model.TypeAccount, nil, err)
	}

	return retParams, accountAuthType, nil
}

// validateAPIKey checks if the given API key is valid for the given app ID
func (a *Auth) validateAPIKey(apiKey string, appID string) error {
	validAPIKey, err := a.getCachedAPIKey(apiKey)
	if err != nil || validAPIKey == nil || validAPIKey.AppID != appID {
		return errors.ErrorData(logutils.StatusInvalid, model.TypeAPIKey, &logutils.FieldArgs{"app_id": appID})
	}

	return nil
}

// deprecated
func (a *Auth) canSignIn(account *model.Account, authTypeID string, userIdentifier string) bool {
	if account != nil {
		aat := account.GetAccountAuthType(authTypeID, userIdentifier)
		return aat == nil || !aat.Linked || !aat.Unverified
	}

	return false
}

func (a *Auth) canSignInV2(account *model.Account, authTypeID string, userIdentifier string, desireAppOrgID string) bool {
	if account != nil {
		hasAppMembership := account.HasAppMembership(desireAppOrgID)
		if !hasAppMembership {
			return false
		}

		aat := account.GetAccountAuthType(authTypeID, userIdentifier)
		return aat == nil || !aat.Linked || !aat.Unverified
	}

	return false
}

// determineOperationInternal determine the operation
//
//	first check if the client has set sign_up field - first priority
//	if sign_up field has not been sent then check if the user exists
func (a *Auth) determineOperationInternal(account *model.Account, desiredAppOrgID string, clientParams string, l *logs.Log) (string, error) {
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
			return "sign-in", nil //the client wants to apply sign-in operation
		} else {
			//the client wants to apply sign up operation but we must analize which one is the correct
			determinedOperation, err := a.determineOperation(account, desiredAppOrgID, l)
			if err != nil {
				return "", errors.WrapErrorAction(logutils.ActionApply, "determine operation - internal - client priority", nil, err)
			}
			if determinedOperation == "org-sign-up" || determinedOperation == "app-sign-up" {
				return determinedOperation, nil
			} else {
				return "", errors.New("cannot apply sign up operation")
			}
		}
	}

	//if the client has not specified then decide based on that if the user exists
	return a.determineOperation(account, desiredAppOrgID, l)
}

func (a *Auth) determineOperationExternal(account *model.Account, desiredAppOrgID string, l *logs.Log) (string, error) {
	return a.determineOperation(account, desiredAppOrgID, l)
}

// determine operation
//
//	"sign-in" or "org-sign-up" or "app-sign-up"
func (a *Auth) determineOperation(account *model.Account, desiredAppOrgID string, l *logs.Log) (string, error) {
	if account == nil {
		return "org-sign-up", nil //first registration for this user identity and organization
	}

	hasAppMembership := account.HasAppMembership(desiredAppOrgID)
	if !hasAppMembership {
		return "app-sign-up", nil //the user identity has registration in the orgnization but does not have for the application
	}

	//the user identity has both org registration and app membership
	return "sign-in", nil
}

func (a *Auth) getAccount(authenticationType string, userIdentifier string, apiKey string, appTypeIdentifier string, orgID string) (*model.Account, string, *model.ApplicationOrganization, error) {
	//validate if the provided auth type is supported by the provided application and organization
	authType, _, appOrg, err := a.validateAuthType(authenticationType, appTypeIdentifier, orgID)
	if err != nil {
		return nil, "", nil, errors.WrapErrorAction(logutils.ActionValidate, model.TypeAuthType, nil, err)
	}

	//do not allow for admins
	if appOrg.Application.Admin {
		return nil, "", nil, errors.ErrorData(logutils.StatusInvalid, model.TypeApplication, logutils.StringArgs("not allowed for admins"))
	}

	//TODO: Ideally we would not make many database calls before validating the API key. Currently needed to get app ID
	err = a.validateAPIKey(apiKey, appOrg.Application.ID)
	if err != nil {
		return nil, "", nil, errors.WrapErrorData(logutils.StatusInvalid, model.TypeAPIKey, nil, err)
	}

	//check if the account exists check
	account, err := a.storage.FindAccount(nil, appOrg.ID, authType.ID, userIdentifier)
	if err != nil {
		return nil, "", nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeAccount, nil, err)
	}

	return account, authType.ID, appOrg, nil
}

func (a *Auth) findAccountAuthType(account *model.Account, authType *model.AuthType, identifier string) (*model.AccountAuthType, error) {
	if account == nil {
		return nil, errors.ErrorData(logutils.StatusMissing, model.TypeAccount, nil)
	}

	if authType == nil {
		return nil, errors.ErrorData(logutils.StatusMissing, model.TypeAuthType, nil)
	}

	accountAuthType := account.GetAccountAuthType(authType.ID, identifier)
	if accountAuthType == nil {
		return nil, errors.ErrorData(logutils.StatusMissing, model.TypeAccountAuthType, nil)
	}

	accountAuthType.AuthType = *authType

	if accountAuthType.Credential != nil {
		//populate credentials in accountAuthType
		credential, err := a.storage.FindCredential(nil, accountAuthType.Credential.ID)
		if err != nil || credential == nil {
			return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeCredential, nil, err)
		}
		credential.AuthType = *authType
		accountAuthType.Credential = credential
	}

	return accountAuthType, nil
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

	authType, err := a.storage.FindAuthType(accountAuthType.AuthType.ID)
	if err != nil || authType == nil {
		return nil, errors.WrapErrorAction(logutils.ActionLoadCache, model.TypeAuthType, logutils.StringArgs(accountAuthType.AuthType.ID), err)
	}

	accountAuthType.AuthType = *authType

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

func (a *Auth) applyLogin(anonymous bool, sub string, authType model.AuthType, appOrg model.ApplicationOrganization,
	accountAuthType *model.AccountAuthType, appType model.ApplicationType, externalIDs map[string]string, ipAddress string, deviceType string,
	deviceOS *string, deviceID *string, clientVersion *string, params map[string]interface{}, state string, l *logs.Log) (*model.LoginSession, error) {

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

				device, err = a.createDevice(sub, deviceType, deviceOS, deviceID, l)
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
		loginSession, err = a.createLoginSession(anonymous, sub, authType, appOrg, accountAuthType, appType, externalIDs, ipAddress, params, state, device, l)
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

func (a *Auth) createDevice(accountID string, deviceType string, deviceOS *string, deviceID *string, l *logs.Log) (*model.Device, error) {
	//id
	idUUID, _ := uuid.NewUUID()
	id := idUUID.String()

	//account
	account := model.Account{ID: accountID}

	return &model.Device{ID: id, DeviceID: deviceID, Account: account,
		Type: deviceType, OS: *deviceOS, DateCreated: time.Now()}, nil
}

func (a *Auth) createLoginSession(anonymous bool, sub string, authType model.AuthType,
	appOrg model.ApplicationOrganization, accountAuthType *model.AccountAuthType, appType model.ApplicationType,
	externalIDs map[string]string, ipAddress string, params map[string]interface{}, state string, device *model.Device, l *logs.Log) (*model.LoginSession, error) {

	//id
	idUUID, _ := uuid.NewUUID()
	id := idUUID.String()

	//account auth type
	if !anonymous {
		//sort account auth types by the one used for login
		accountAuthType.Account.SortAccountAuthTypes(accountAuthType.Identifier)
	}

	//access token
	orgID := appOrg.Organization.ID
	appID := appOrg.Application.ID
	uid := ""
	name := ""
	email := ""
	phone := ""
	permissions := []string{}
	scopes := []string{authorization.ScopeGlobal}
	if !anonymous {
		uid = accountAuthType.Identifier
		name = accountAuthType.Account.Profile.GetFullName()
		email = accountAuthType.Account.Profile.Email
		phone = accountAuthType.Account.Profile.Phone
		permissions = accountAuthType.Account.GetPermissionNames()
		scopes = append(scopes, accountAuthType.Account.GetScopes()...)
	}
	claims := a.getStandardClaims(sub, uid, name, email, phone, rokwireTokenAud, orgID, appID, authType.Code, externalIDs, nil, anonymous, true, appOrg.Application.Admin, appOrg.Organization.System, false, true, idUUID.String())
	accessToken, err := a.buildAccessToken(claims, strings.Join(permissions, ","), strings.Join(scopes, " "))
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionCreate, logutils.TypeToken, nil, err)
	}

	//refresh token
	refreshToken, err := a.buildRefreshToken()
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionCreate, logutils.TypeToken, nil, err)
	}

	now := time.Now().UTC()
	var stateExpires *time.Time
	if state != "" {
		stateExpireTime := now.Add(time.Minute * time.Duration(loginStateDuration))
		stateExpires = &stateExpireTime
	}

	loginSession := model.LoginSession{ID: id, AppOrg: appOrg, AuthType: authType,
		AppType: appType, Anonymous: anonymous, Identifier: sub, ExternalIDs: externalIDs, AccountAuthType: accountAuthType,
		Device: device, IPAddress: ipAddress, AccessToken: accessToken, RefreshTokens: []string{refreshToken}, Params: params,
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

func (a *Auth) prepareRegistrationData(authType model.AuthType, identifier string,
	profile model.Profile, preferences map[string]interface{}, l *logs.Log) (*model.Profile, map[string]interface{}, error) {
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

func (a *Auth) prepareAccountAuthType(authType model.AuthType, identifier string, accountAuthTypeParams map[string]interface{},
	credential *model.Credential, unverified bool, linked bool) (*model.AccountAuthType, *model.Credential, error) {
	now := time.Now()

	//account auth type
	accountAuthTypeID, _ := uuid.NewUUID()
	active := true
	accountAuthType := &model.AccountAuthType{ID: accountAuthTypeID.String(), AuthType: authType,
		Identifier: identifier, Params: accountAuthTypeParams, Credential: credential, Unverified: unverified, Linked: linked, Active: active, DateCreated: now}

	//credential
	if credential != nil {
		//there is a credential
		credential.AccountsAuthTypes = append(credential.AccountsAuthTypes, *accountAuthType)
	}

	return accountAuthType, credential, nil
}

func (a *Auth) mergeProfiles(dst model.Profile, src *model.Profile, shared bool) model.Profile {
	if src == nil {
		return dst
	}

	dst.PhotoURL = utils.SetStringIfEmpty(dst.PhotoURL, src.PhotoURL)
	dst.FirstName = utils.SetStringIfEmpty(dst.FirstName, src.FirstName)
	dst.LastName = utils.SetStringIfEmpty(dst.LastName, src.LastName)
	dst.Email = utils.SetStringIfEmpty(dst.Email, src.Email)
	dst.Phone = utils.SetStringIfEmpty(dst.Phone, src.Phone)
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
//		Registered account (AccountAuthType): Registered Account object
func (a *Auth) registerUser(context storage.TransactionContext, authType model.AuthType, userIdentifier string, accountAuthTypeParams map[string]interface{},
	appOrg model.ApplicationOrganization, credential *model.Credential, externalIDs map[string]string, profile model.Profile, privacy model.Privacy, preferences map[string]interface{},
	username string, permissionNames []string, roleIDs []string, groupIDs []string, scopes []string, creatorPermissions []string, clientVersion *string, l *logs.Log) (*model.AccountAuthType, error) {

	//External and anonymous auth is automatically verified, otherwise verified if credential has been verified previously
	unverified := true
	if creatorPermissions == nil {
		if authType.IsExternal || authType.IsAnonymous {
			unverified = false
		} else if credential != nil {
			unverified = !credential.Verified
		}
	}

	accountAuthType, err := a.constructAccount(context, authType, userIdentifier, accountAuthTypeParams, appOrg, credential,
		unverified, externalIDs, profile, privacy, preferences, username, permissionNames, roleIDs, groupIDs, scopes, creatorPermissions, clientVersion, l)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionCreate, model.TypeAccount, nil, err)
	}

	err = a.storeNewAccountInfo(context, accountAuthType.Account, credential, profile)
	if err != nil {
		return nil, errors.WrapErrorAction("storing", "new account information", nil, err)
	}

	return accountAuthType, nil
}

func (a *Auth) constructAccount(context storage.TransactionContext, authType model.AuthType, userIdentifier string, accountAuthTypeParams map[string]interface{},
	appOrg model.ApplicationOrganization, credential *model.Credential, unverified bool, externalIDs map[string]string, profile model.Profile, privacy model.Privacy, preferences map[string]interface{},
	username string, permissionNames []string, roleIDs []string, groupIDs []string, scopes []string, assignerPermissions []string, clientVersion *string, l *logs.Log) (*model.AccountAuthType, error) {
	//create account auth type
	accountAuthType, _, err := a.prepareAccountAuthType(authType, userIdentifier, accountAuthTypeParams, credential, unverified, false)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionCreate, model.TypeAccountAuthType, nil, err)
	}

	//create account object
	accountID, _ := uuid.NewUUID()
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

	account := model.Account{ID: accountID.String(), OrgID: orgID, OrgAppsMemberships: orgAppsMemberships,
		AppOrg:                  orgAppMembership.AppOrg,                  //current
		Permissions:             orgAppMembership.Permissions,             //current
		Roles:                   orgAppMembership.Roles,                   //current
		Groups:                  orgAppMembership.Groups,                  //current
		Preferences:             orgAppMembership.Preferences,             //current
		MostRecentClientVersion: orgAppMembership.MostRecentClientVersion, //current
		Scopes:                  scopes, AuthTypes: authTypes,
		ExternalIDs: externalIDs, Profile: profile, Privacy: privacy, Username: username, DateCreated: time.Now()}

	accountAuthType.Account = account
	return accountAuthType, nil
}

func (a *Auth) storeNewAccountInfo(context storage.TransactionContext, account model.Account, credential *model.Credential, profile model.Profile) error {
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

func (a *Auth) checkUsername(context storage.TransactionContext, appOrg *model.ApplicationOrganization, username string) error {
	accounts, err := a.storage.FindAccountsByUsername(context, appOrg, username)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionFind, model.TypeAccount, nil, err)
	}
	if len(accounts) > 0 {
		return errors.ErrorData(logutils.StatusInvalid, model.TypeAccountUsername, logutils.StringArgs(username+" taken")).SetStatus(utils.ErrorStatusUsernameTaken)
	}

	return nil
}

func (a *Auth) linkAccountAuthType(account model.Account, authType model.AuthType, appOrg model.ApplicationOrganization,
	creds string, params string, l *logs.Log) (string, *model.AccountAuthType, error) {
	authImpl, err := a.getAuthTypeImpl(authType)
	if err != nil {
		return "", nil, errors.WrapErrorAction(logutils.ActionLoadCache, model.TypeAuthType, nil, err)
	}

	userIdentifier, err := authImpl.getUserIdentifier(creds)
	if err != nil {
		return "", nil, errors.WrapErrorAction(logutils.ActionGet, "user identifier", nil, err)
	}

	//2. check if the user exists
	newCredsAccount, err := a.storage.FindAccount(nil, appOrg.ID, authType.ID, userIdentifier)
	if err != nil {
		return "", nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeAccount, nil, err)
	}
	if newCredsAccount != nil {
		//if account is current account, attempt sign-in. Otherwise, handle conflict
		if newCredsAccount.ID == account.ID {
			message, aat, err := a.applyLinkVerify(authImpl, authType, &account, userIdentifier, creds, l)
			if err != nil {
				return "", nil, err
			}
			if message != "" {
				return "", nil, errors.ErrorData("incomplete", "verification", nil).SetStatus(utils.ErrorStatusUnverified)
			}
			if aat != nil {
				for i, accAuthType := range account.AuthTypes {
					if accAuthType.ID == aat.ID {
						account.AuthTypes[i] = *aat
						break
					}
				}
			}
			return "", nil, nil
		}

		err = a.handleAccountAuthTypeConflict(*newCredsAccount, authType.ID, userIdentifier, false)
		if err != nil {
			return "", nil, err
		}
	}

	credID := uuid.NewString()

	//apply sign up
	message, credentialValue, err := authImpl.signUp(authType, appOrg, creds, params, credID, l)
	if err != nil {
		return "", nil, errors.WrapErrorAction("signing up", "user", nil, err)
	}

	//credential
	var credential *model.Credential
	if credentialValue != nil {
		now := time.Now()
		credential = &model.Credential{ID: credID, AccountsAuthTypes: nil, Value: credentialValue, Verified: false,
			AuthType: authType, DateCreated: now, DateUpdated: &now}
	}

	accountAuthType, credential, err := a.prepareAccountAuthType(authType, userIdentifier, nil, credential, true, true)
	if err != nil {
		return "", nil, errors.WrapErrorAction(logutils.ActionCreate, model.TypeAccountAuthType, nil, err)
	}
	accountAuthType.Account = account

	err = a.registerAccountAuthType(*accountAuthType, credential, nil, l)
	if err != nil {
		return "", nil, errors.WrapErrorAction(logutils.ActionRegister, model.TypeAccountAuthType, nil, err)
	}

	return message, accountAuthType, nil
}

func (a *Auth) applyLinkVerify(authImpl authType, authType model.AuthType, account *model.Account,
	userIdentifier string, creds string, l *logs.Log) (string, *model.AccountAuthType, error) {
	//find account auth type
	accountAuthType, err := a.findAccountAuthType(account, &authType, userIdentifier)
	if accountAuthType == nil {
		return "", nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeAccountAuthType, nil, err)
	}

	if !accountAuthType.Linked {
		return "", nil, errors.ErrorData(logutils.StatusInvalid, model.TypeAccountAuthType, &logutils.FieldArgs{"linked": false})
	}

	if !accountAuthType.Unverified {
		return "", nil, errors.ErrorData(logutils.StatusInvalid, model.TypeAccountAuthType, &logutils.FieldArgs{"verified": true})
	}

	var message string
	message, err = a.checkCredentials(authImpl, authType, accountAuthType, creds, l)
	if err != nil {
		return "", nil, errors.WrapErrorAction(logutils.ActionVerify, model.TypeCredential, nil, err)
	}

	return message, accountAuthType, nil
}

func (a *Auth) linkAccountAuthTypeExternal(account model.Account, authType model.AuthType, appType model.ApplicationType, appOrg model.ApplicationOrganization,
	creds string, params string, l *logs.Log) (*model.AccountAuthType, error) {
	authImpl, err := a.getExternalAuthTypeImpl(authType)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionLoadCache, model.TypeAuthType, nil, err)
	}

	externalUser, _, _, err := authImpl.externalLogin(authType, appType, appOrg, creds, params, l)
	if err != nil {
		return nil, errors.WrapErrorAction("logging in", "external user", nil, err)
	}

	//2. check if the user exists
	newCredsAccount, err := a.storage.FindAccount(nil, appOrg.ID, authType.ID, externalUser.Identifier)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeAccount, nil, err)
	}
	//cannot link creds if an account already exists for new creds
	if newCredsAccount != nil {
		return nil, errors.ErrorData("existing", model.TypeAccount, nil).SetStatus(utils.ErrorStatusAlreadyExists)
	}

	accountAuthTypeParams := map[string]interface{}{}
	accountAuthTypeParams["user"] = externalUser

	accountAuthType, credential, err := a.prepareAccountAuthType(authType, externalUser.Identifier, accountAuthTypeParams, nil, false, true)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionCreate, model.TypeAccountAuthType, nil, err)
	}
	accountAuthType.Account = account

	for k, v := range externalUser.ExternalIDs {
		if account.ExternalIDs == nil {
			account.ExternalIDs = make(map[string]string)
		}
		if account.ExternalIDs[k] == "" {
			account.ExternalIDs[k] = v
		}
	}

	err = a.registerAccountAuthType(*accountAuthType, credential, account.ExternalIDs, l)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionRegister, model.TypeAccountAuthType, nil, err)
	}

	return accountAuthType, nil
}

func (a *Auth) registerAccountAuthType(accountAuthType model.AccountAuthType, credential *model.Credential, externalIDs map[string]string, l *logs.Log) error {
	var err error
	if credential != nil {
		//TODO - in one transaction
		if err = a.storage.InsertCredential(nil, credential); err != nil {
			return errors.WrapErrorAction(logutils.ActionInsert, model.TypeCredential, nil, err)
		}
	}

	err = a.storage.InsertAccountAuthType(accountAuthType)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionInsert, model.TypeAccount, nil, err)
	}

	if externalIDs != nil {
		err = a.storage.UpdateAccountExternalIDs(accountAuthType.Account.ID, externalIDs)
		if err != nil {
			return errors.WrapErrorAction(logutils.ActionUpdate, "account external IDs", nil, err)
		}

		err = a.storage.UpdateLoginSessionExternalIDs(accountAuthType.Account.ID, externalIDs)
		if err != nil {
			return errors.WrapErrorAction(logutils.ActionUpdate, "login session external IDs", nil, err)
		}
	}

	return nil
}

func (a *Auth) unlinkAccountAuthType(accountID string, authenticationType string, appTypeIdentifier string, identifier string, l *logs.Log) (*model.Account, error) {
	account, err := a.storage.FindAccountByID(nil, accountID)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeAccount, nil, err)
	}
	if account == nil {
		return nil, errors.ErrorData(logutils.StatusMissing, model.TypeAccount, &logutils.FieldArgs{"id": accountID})
	}

	for i, aat := range account.AuthTypes {
		// unlink auth type with matching code and identifier
		if aat.AuthType.Code == authenticationType && aat.Identifier == identifier {
			aat.Account = *account
			err := a.removeAccountAuthType(aat)
			if err != nil {
				return nil, errors.WrapErrorAction("unlinking", model.TypeAccountAuthType, nil, err)
			}

			account.AuthTypes = append(account.AuthTypes[:i], account.AuthTypes[i+1:]...)
			break
		}
	}

	return account, nil
}

func (a *Auth) handleAccountAuthTypeConflict(account model.Account, authTypeID string, userIdentifier string, newAccount bool) error {
	aat := account.GetAccountAuthType(authTypeID, userIdentifier)
	if aat == nil || !aat.Unverified {
		//cannot link creds if a verified account already exists for new creds
		return errors.ErrorData("existing", model.TypeAccount, nil).SetStatus(utils.ErrorStatusAlreadyExists)
	}

	//if this is the only auth type (this will only be possible for accounts created through sign up that were never verified/used)
	if len(account.AuthTypes) == 1 {
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
		err := a.removeAccountAuthType(*aat)
		if err != nil {
			return errors.WrapErrorAction(logutils.ActionDelete, model.TypeAccountAuthType, nil, err)
		}
	}

	return nil
}

func (a *Auth) removeAccountAuthType(aat model.AccountAuthType) error {
	transaction := func(context storage.TransactionContext) error {
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

		//3. delete login sessions using unlinked account auth type (if unverified no sessions should exist)
		if !aat.Unverified {
			err = a.storage.DeleteLoginSessionsByAccountAuthTypeID(context, aat.ID)
			if err != nil {
				return errors.WrapErrorAction(logutils.ActionDelete, model.TypeLoginSession, nil, err)
			}
		}

		return nil
	}

	return a.storage.PerformTransaction(transaction)
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

	//validate and determine if we should remove the whole account or just ot unattach it from specific apps
	//allAccountApps := account.GetApps()

	//	log.Println(allAccountApps)

	return a.deleteFullAccount(context, account)
}

func (a *Auth) deleteAccountFromApps(context storage.TransactionContext, account model.Account, fromAppsIDs []string) error {
	//TODO
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

	claims := a.getStandardClaims(account.AccountID, "", account.Name, "", "", aud, orgID, appID, authType, nil, nil, false, true, false, false, true, account.FirstParty, "")
	accessToken, err := a.buildAccessToken(claims, strings.Join(permissions, ","), scope)
	if err != nil {
		return "", nil, errors.WrapErrorAction(logutils.ActionCreate, logutils.TypeToken, nil, err)
	}
	return accessToken, &model.AppOrgPair{AppID: appID, OrgID: orgID}, nil
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

func (a *Auth) validateAuthType(authenticationType string, appTypeIdentifier string, orgID string) (*model.AuthType, *model.ApplicationType, *model.ApplicationOrganization, error) {
	//get the auth type
	authType, err := a.storage.FindAuthType(authenticationType)
	if err != nil || authType == nil {
		return nil, nil, nil, errors.WrapErrorAction(logutils.ActionValidate, model.TypeAuthType, logutils.StringArgs(authenticationType), err)
	}

	//get the app type
	applicationType, err := a.storage.FindApplicationType(appTypeIdentifier)
	if err != nil {
		return nil, nil, nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeApplicationType, logutils.StringArgs(appTypeIdentifier), err)
	}
	if applicationType == nil {
		return nil, nil, nil, errors.ErrorData(logutils.StatusMissing, model.TypeApplicationType, logutils.StringArgs(appTypeIdentifier))
	}

	//get the app org
	applicationID := applicationType.Application.ID
	appOrg, err := a.storage.FindApplicationOrganization(applicationID, orgID)
	if err != nil {
		return nil, nil, nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeApplicationOrganization, &logutils.FieldArgs{"app_id": applicationID, "org_id": orgID}, err)
	}
	if appOrg == nil {
		return nil, nil, nil, errors.ErrorData(logutils.StatusMissing, model.TypeApplicationOrganization, &logutils.FieldArgs{"app_id": applicationID, "org_id": orgID})
	}

	//check if the auth type is supported for this application and organization
	if !appOrg.IsAuthTypeSupported(*applicationType, *authType) {
		return nil, nil, nil, errors.ErrorAction(logutils.ActionValidate, "not supported auth type for application and organization", &logutils.FieldArgs{"app_type_id": applicationType.ID, "auth_type_id": authType.ID})
	}

	return authType, applicationType, appOrg, nil
}

func (a *Auth) validateAuthTypeForAppOrg(authenticationType string, appID string, orgID string) (*model.AuthType, *model.ApplicationOrganization, error) {
	authType, err := a.storage.FindAuthType(authenticationType)
	if err != nil || authType == nil {
		return nil, nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeAuthType, logutils.StringArgs(authenticationType), err)
	}

	appOrg, err := a.storage.FindApplicationOrganization(appID, orgID)
	if err != nil {
		return nil, nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeApplicationOrganization, &logutils.FieldArgs{"app_id": appID, "org_id": orgID}, err)
	}
	if appOrg == nil {
		return nil, nil, errors.ErrorData(logutils.StatusMissing, model.TypeApplicationOrganization, &logutils.FieldArgs{"app_id": appID, "org_id": orgID})
	}

	for _, appType := range appOrg.Application.Types {
		if appOrg.IsAuthTypeSupported(appType, *authType) {
			return authType, appOrg, nil
		}
	}

	return nil, nil, errors.ErrorData(logutils.StatusInvalid, model.TypeAuthType, &logutils.FieldArgs{"app_org_id": appOrg.ID, "auth_type": authenticationType})
}

func (a *Auth) getAuthTypeImpl(authType model.AuthType) (authType, error) {
	if auth, ok := a.authTypes[authType.Code]; ok {
		return auth, nil
	}

	return nil, errors.ErrorData(logutils.StatusInvalid, model.TypeAuthType, logutils.StringArgs(authType.Code))
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
	return tokenauth.GenerateSignedToken(&claims, a.authPrivKey)
}

func (a *Auth) buildCsrfToken(claims tokenauth.Claims) (string, error) {
	claims.Purpose = "csrf"
	return tokenauth.GenerateSignedToken(&claims, a.authPrivKey)
}

func (a *Auth) buildRefreshToken() (string, error) {
	newToken, err := utils.GenerateRandomString(refreshTokenLength)
	if err != nil {
		return "", errors.WrapErrorAction(logutils.ActionCompute, logutils.TypeToken, nil, err)
	}

	return newToken, nil
}

// getScopedAccessToken returns a scoped access token with the requested scopes
func (a *Auth) getScopedAccessToken(claims tokenauth.Claims, serviceID string, scopes []authorization.Scope) (string, error) {
	aud, scope := a.tokenDataForScopes(scopes)
	if !authutils.ContainsString(aud, serviceID) {
		aud = append(aud, serviceID)
	}

	scopedClaims := a.getStandardClaims(claims.Subject, "", "", "", "", strings.Join(aud, ","), claims.OrgID, claims.AppID, claims.AuthType, claims.ExternalIDs, &claims.ExpiresAt, claims.Anonymous, claims.Authenticated, false, false, claims.Service, false, claims.SessionID)
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

func (a *Auth) getStandardClaims(sub string, uid string, name string, email string, phone string, aud string, orgID string, appID string,
	authType string, externalIDs map[string]string, exp *int64, anonymous bool, authenticated bool, admin bool, system bool, service bool, firstParty bool, sessionID string) tokenauth.Claims {
	return tokenauth.Claims{
		StandardClaims: jwt.StandardClaims{
			Audience:  aud,
			Subject:   sub,
			ExpiresAt: a.getExp(exp),
			IssuedAt:  time.Now().Unix(),
			Issuer:    a.host,
		}, OrgID: orgID, AppID: appID, AuthType: authType, UID: uid, Name: name, Email: email, Phone: phone,
		ExternalIDs: externalIDs, Anonymous: anonymous, Authenticated: authenticated, Admin: admin, System: system,
		Service: service, FirstParty: firstParty, SessionID: sessionID,
	}
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

func (a *Auth) setLogContext(account *model.Account, l *logs.Log) {
	accountID := "nil"
	if account != nil {
		accountID = account.ID
	}
	l.SetContext("account_id", accountID)
}

// storeCoreRegs stores the service registration records for the Core BB
func (a *Auth) storeCoreRegs() error {
	err := a.storage.MigrateServiceRegs()
	if err != nil {
		return errors.WrapErrorAction("migrating", model.TypeServiceReg, nil, err)
	}

	// Setup "auth" registration for token validation
	authReg := model.ServiceRegistration{Registration: authservice.ServiceReg{ServiceID: authServiceID, Host: a.host, PubKey: a.authPrivKey.PubKey}, CoreHost: a.host,
		Name: "ROKWIRE Auth Service", Description: "The Auth Service is a subsystem of the Core Building Block that manages authentication and authorization.", FirstParty: true}
	err = a.storage.SaveServiceReg(&authReg, true)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionSave, model.TypeServiceReg, logutils.StringArgs(authServiceID), err)
	}

	// Setup core registration for signature validation
	coreReg := model.ServiceRegistration{Registration: authservice.ServiceReg{ServiceID: a.serviceID, ServiceAccountID: a.serviceID, Host: a.host, PubKey: a.authPrivKey.PubKey}, CoreHost: a.host,
		Name: "ROKWIRE Core Building Block", Description: "The Core Building Block manages user, auth, and organization data for the ROKWIRE platform.", FirstParty: true}
	err = a.storage.SaveServiceReg(&coreReg, true)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionSave, model.TypeServiceReg, logutils.StringArgs(a.serviceID), err)
	}

	return nil
}

// storeCoreServiceAccount stores the service account record for the Core BB
func (a *Auth) storeCoreServiceAccount() {
	coreAccount := model.ServiceAccount{AccountID: a.serviceID, Name: "ROKWIRE Core Building Block", FirstParty: true, DateCreated: time.Now()}
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
