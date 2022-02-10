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
	"github.com/rokwire/core-auth-library-go/authorization"
	"github.com/rokwire/core-auth-library-go/authservice"
	"github.com/rokwire/core-auth-library-go/authutils"
	"github.com/rokwire/core-auth-library-go/tokenauth"
	"golang.org/x/sync/syncmap"
	"gopkg.in/go-playground/validator.v9"
	"gopkg.in/gomail.v2"

	"github.com/rokwire/logging-library-go/errors"
	"github.com/rokwire/logging-library-go/logs"
	"github.com/rokwire/logging-library-go/logutils"
)

const (
	authServiceID  string = "auth"
	authKeyAlg     string = "RS256"
	rokwireKeyword string = "ROKWIRE"

	rokwireTokenAud string = "rokwire"

	typeMail              logutils.MessageDataType = "mail"
	typeAuthType          logutils.MessageDataType = "auth type"
	typeExternalAuthType  logutils.MessageDataType = "external auth type"
	typeAnonymousAuthType logutils.MessageDataType = "anonymous auth type"
	typeMfaType           logutils.MessageDataType = "mfa type"
	typeAuth              logutils.MessageDataType = "auth"
	typeAuthRefreshParams logutils.MessageDataType = "auth refresh params"

	refreshTokenLength int = 256

	sessionDeletePeriod int = 24
	maxSessionsDelete   int = 250

	loginStateLength   int = 128
	loginStateDuration int = 5

	maxMfaAttempts    int = 5
	mfaCodeExpiration int = 5
	mfaCodeMax        int = 1000000
)

//Auth represents the auth functionality unit
type Auth struct {
	storage Storage
	emailer Emailer

	logger *logs.Logger

	authTypes          map[string]authType
	externalAuthTypes  map[string]externalAuthType
	anonymousAuthTypes map[string]anonymousAuthType
	mfaTypes           map[string]mfaType

	authPrivKey *rsa.PrivateKey

	AuthService *authservice.AuthService

	serviceID   string
	host        string //Service host
	minTokenExp int64  //Minimum access token expiration time in minutes
	maxTokenExp int64  //Maximum access token expiration time in minutes

	profileBB ProfileBuildingBlock

	emailFrom   string
	emailDialer *gomail.Dialer

	cachedIdentityProviders *syncmap.Map //cache identityProviders
	identityProvidersLock   *sync.RWMutex

	apiKeys     *syncmap.Map //cache api keys / api_key (string) -> APIKey
	apiKeysLock *sync.RWMutex

	//delete refresh tokens timer
	deleteSessionsTimer *time.Timer
	timerDone           chan bool
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
	mfaTypes := map[string]mfaType{}

	cachedIdentityProviders := &syncmap.Map{}
	identityProvidersLock := &sync.RWMutex{}

	apiKeys := &syncmap.Map{}
	apiKeysLock := &sync.RWMutex{}

	timerDone := make(chan bool)

	auth := &Auth{storage: storage, emailer: emailer, logger: logger, authTypes: authTypes, externalAuthTypes: externalAuthTypes, anonymousAuthTypes: anonymousAuthTypes,
		mfaTypes: mfaTypes, authPrivKey: authPrivKey, AuthService: nil, serviceID: serviceID, host: host, minTokenExp: *minTokenExp,
		maxTokenExp: *maxTokenExp, profileBB: profileBB, cachedIdentityProviders: cachedIdentityProviders, identityProvidersLock: identityProvidersLock,
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
	initAnonymousAuth(auth)
	initSignatureAuth(auth)

	initOidcAuth(auth)
	initSamlAuth(auth)

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

func (a *Auth) applyExternalAuthType(authType model.AuthType, appType model.ApplicationType, appOrg model.ApplicationOrganization,
	creds string, params string, regProfile model.Profile, regPreferences map[string]interface{}, l *logs.Log) (*model.AccountAuthType, map[string]interface{}, []model.MFAType, error) {
	var accountAuthType *model.AccountAuthType
	var mfaTypes []model.MFAType

	//external auth type
	authImpl, err := a.getExternalAuthTypeImpl(authType)
	if err != nil {
		return nil, nil, nil, errors.WrapErrorAction(logutils.ActionLoadCache, typeExternalAuthType, nil, err)
	}

	//1. get the user from the external system
	//var externalUser *model.ExternalSystemUser
	externalUser, extParams, err := authImpl.externalLogin(authType, appType, appOrg, creds, params, l)
	if err != nil {
		return nil, nil, nil, errors.WrapErrorAction("logging in", "external user", nil, err)
	}

	//2. check if the user exists
	account, err := a.storage.FindAccount(appOrg.ID, authType.ID, externalUser.Identifier)
	if err != nil {
		return nil, nil, nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeAccount, nil, err)
	}
	if account != nil {
		//account exists
		accountAuthType, mfaTypes, err = a.applySignInExternal(*account, authType, appOrg, *externalUser, l)
		if err != nil {
			return nil, nil, nil, errors.Wrap("error on apply sign in external", err)
		}
	} else {
		//user does not exist, we need to register it
		accountAuthType, err = a.applySignUpExternal(authType, appOrg, *externalUser, regProfile, regPreferences, l)
		if err != nil {
			return nil, nil, nil, errors.Wrap("error on apply sign up external", err)
		}
	}

	//TODO: make sure we do not return any refresh tokens in extParams
	return accountAuthType, extParams, mfaTypes, nil
}

func (a *Auth) applySignInExternal(account model.Account, authType model.AuthType, appOrg model.ApplicationOrganization,
	externalUser model.ExternalSystemUser, l *logs.Log) (*model.AccountAuthType, []model.MFAType, error) {
	var accountAuthType *model.AccountAuthType
	var mfaTypes []model.MFAType

	var err error

	//find account auth type
	accountAuthType, err = a.findAccountAuthType(&account, &authType, externalUser.Identifier)
	if err != nil {
		return nil, nil, err
	}

	//check if need to update the account data
	err = a.updateDataIfNeeded(*accountAuthType, externalUser, authType, appOrg, l)
	if err != nil {
		return nil, nil, errors.WrapErrorAction("update account if needed", "", nil, err)
	}

	mfaTypes = account.GetVerifiedMFATypes()

	return accountAuthType, mfaTypes, nil
}

func (a *Auth) applySignUpExternal(authType model.AuthType, appOrg model.ApplicationOrganization, externalUser model.ExternalSystemUser,
	regProfile model.Profile, regPreferences map[string]interface{}, l *logs.Log) (*model.AccountAuthType, error) {
	var accountAuthType *model.AccountAuthType

	var profile model.Profile
	var preferences map[string]interface{}

	//1. check if needs to use shared profile
	useSharedProfile, sharedProfile, _, err := a.applySharedProfile(appOrg.Application, authType.ID, externalUser.Identifier, l)
	if err != nil {
		return nil, errors.Wrap("error applying shared profile", err)
	}

	if useSharedProfile {
		l.Infof("%s uses a shared profile", externalUser.Identifier)

		//merge client profile and shared profile
		profile = a.mergeClientAndSharedProfile(regProfile, *sharedProfile)
		preferences = regPreferences
	} else {
		l.Infof("%s does not use a shared profile", externalUser.Identifier)

		profile = regProfile
		preferences = regPreferences
	}

	//2. prepare the registration data
	identifier := externalUser.Identifier
	accountAuthTypeParams := map[string]interface{}{}
	accountAuthTypeParams["user"] = externalUser

	//prepare profile and preferences
	preparedProfile, preparedPreferences, err := a.prepareRegistrationData(authType, identifier, profile, preferences, l)
	if err != nil {
		return nil, errors.WrapErrorAction("error preparing registration data", model.TypeUserAuth, nil, err)
	}

	//3. apply profile data from the external user if not provided
	_, err = a.applyProfileDataFromExternalUser(preparedProfile, externalUser, l)
	if err != nil {
		return nil, errors.WrapErrorAction("error applying profile data from external user on registration", model.TypeProfile, nil, err)
	}

	//4. roles and groups mapping
	roles, groups, err := a.getExternalUserAuthorization(externalUser, appOrg, authType)
	if err != nil {
		l.WarnAction(logutils.ActionGet, "external authorization", err)
	}

	//5. register the account
	accountAuthType, err = a.registerUser(authType, identifier, appOrg, nil, useSharedProfile, *preparedProfile, preparedPreferences, roles, groups, l)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionRegister, model.TypeAccount, nil, err)
	}

	return accountAuthType, nil
}

func (a *Auth) applyProfileDataFromExternalUser(profile *model.Profile, externalUser model.ExternalSystemUser, l *logs.Log) (*bool, error) {
	l.Info("applyProfileDataFromExternalUser")

	if profile == nil {
		l.Error("for some reasons the profile is nil")
		return nil, errors.New("for some reasons the profile is nil")
	}

	changed := false
	//first name
	if len(profile.FirstName) == 0 && len(externalUser.FirstName) > 0 {
		profile.FirstName = externalUser.FirstName
		changed = true
	}
	//last name
	if len(profile.LastName) == 0 && len(externalUser.LastName) > 0 {
		profile.LastName = externalUser.LastName
		changed = true
	}
	//email
	if len(profile.Email) == 0 && len(externalUser.Email) > 0 {
		profile.Email = externalUser.Email
		changed = true
	}
	return &changed, nil
}

func (a *Auth) updateDataIfNeeded(accountAuthType model.AccountAuthType, externalUser model.ExternalSystemUser,
	authType model.AuthType, appOrg model.ApplicationOrganization, l *logs.Log) error {
	l.Info("updateDataIfNeeded")

	//1. check if need to update the external user data
	err := a.updateExternalUserIfNeeded(accountAuthType, externalUser, authType, appOrg, l)
	if err != nil {
		return errors.WrapErrorAction("error on updating external user if needed", "", nil, err)
	}

	//2. check if need to update the profile data
	err = a.updateProfileIfNeeded(accountAuthType.Account, externalUser, l)
	if err != nil {
		return errors.WrapErrorAction("error on updating profile if needed", "", nil, err)
	}
	return nil
}

func (a *Auth) updateExternalUserIfNeeded(accountAuthType model.AccountAuthType, externalUser model.ExternalSystemUser,
	authType model.AuthType, appOrg model.ApplicationOrganization, l *logs.Log) error {
	l.Info("updateExternalUserIfNeeded")

	//get the current external user
	currentDataMap := accountAuthType.Params["user"]
	currentDataJSON, err := utils.ConvertToJSON(currentDataMap)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionMarshal, "external user", nil, err)
	}
	var currentData *model.ExternalSystemUser
	err = json.Unmarshal(currentDataJSON, &currentData)
	if err != nil {
		return errors.ErrorAction(logutils.ActionUnmarshal, "external user", nil)
	}

	newData := externalUser

	//check if external system user needs to be updated
	if !currentData.Equals(newData) {
		//there is changes so we need to update it
		//TODO: Can we do this all in a single storage operation?
		accountAuthType.Params["user"] = newData
		now := time.Now()
		accountAuthType.DateUpdated = &now

		transaction := func(context storage.TransactionContext) error {
			//1. first find the account record
			account, err := a.storage.FindAccountByAuthTypeID(context, accountAuthType.ID)
			if err != nil {
				return errors.WrapErrorAction(logutils.ActionFind, model.TypeAccount, nil, err)
			}
			if account == nil {
				return errors.ErrorAction(logutils.ActionFind, "for some reason account is nil for account auth type", &logutils.FieldArgs{"account auth type id": accountAuthType.ID})
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

			//3. update roles and groups mapping
			roles, groups, err := a.getExternalUserAuthorization(externalUser, appOrg, authType)
			if err != nil {
				return errors.WrapErrorAction(logutils.ActionGet, "external authorization", nil, err)
			}
			_, err = a.updateExternalAccountRoles(account, roles)
			if err != nil {
				return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeAccountRoles, nil, err)
			}

			_, err = a.updateExternalAccountGroups(account, groups)
			if err != nil {
				return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeAccountGroups, nil, err)
			}

			//4. update the account record
			err = a.storage.SaveAccount(context, account)
			if err != nil {
				return errors.WrapErrorAction(logutils.ActionSave, model.TypeAccount, nil, err)
			}

			return nil
		}

		err = a.storage.PerformTransaction(transaction)
		if err != nil {
			return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeUserAuth, nil, err)
		}
		return nil
	}
	return nil
}

func (a *Auth) updateProfileIfNeeded(account model.Account, externalUser model.ExternalSystemUser, l *logs.Log) error {
	l.Info("updateProfileIfNeeded")

	profile := account.Profile
	changed, err := a.applyProfileDataFromExternalUser(&profile, externalUser, l)
	if err != nil {
		return errors.WrapErrorAction("error applying profile data from external user", model.TypeProfile, nil, err)
	}

	if *changed {
		l.Info("the profile will be updated")
		err := a.storage.UpdateProfile(account.ID, &profile)
		if err != nil {
			return errors.WrapErrorData("error updating profile from external user data", model.TypeProfile, nil, err)
		}
	}
	return nil
}

func (a *Auth) applyAnonymousAuthType(authType model.AuthType, appType model.ApplicationType, appOrg model.ApplicationOrganization, creds string, params string, l *logs.Log) (string, map[string]interface{}, error) { //auth type
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
	creds string, params string, regProfile model.Profile, regPreferences map[string]interface{}, l *logs.Log) (string, *model.AccountAuthType, []model.MFAType, error) {

	//auth type
	authImpl, err := a.getAuthTypeImpl(authType)
	if err != nil {
		return "", nil, nil, errors.WrapErrorAction(logutils.ActionLoadCache, typeAuthType, nil, err)
	}

	//check if the user exists check
	userIdentifier, err := authImpl.getUserIdentifier(creds)
	if err != nil {
		return "", nil, nil, errors.WrapErrorAction(logutils.ActionGet, "user identifier", nil, err)
	}
	account, err := a.storage.FindAccount(appOrg.ID, authType.ID, userIdentifier)
	if err != nil {
		return "", nil, nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeAccount, nil, err) //TODO add args..
	}

	accountExists := (account != nil)

	//check if it is sign in or sign up
	isSignUp, err := a.isSignUp(accountExists, params, l)
	if err != nil {
		return "", nil, nil, errors.WrapErrorAction("error checking is sign up", "", nil, err)
	}
	if isSignUp {
		message, accountAuthType, err := a.applySignUp(authImpl, accountExists, authType, appType, appOrg, userIdentifier,
			creds, params, regProfile, regPreferences, l)
		if err != nil {
			return "", nil, nil, err
		}
		return message, accountAuthType, nil, nil
	}
	///apply sign in
	return a.applySignIn(authImpl, authType, accountExists, *account, userIdentifier, creds, l)
}

func (a *Auth) applySignIn(authImpl authType, authType model.AuthType, accountExists bool, account model.Account,
	userIdentifier string, creds string, l *logs.Log) (string, *model.AccountAuthType, []model.MFAType, error) {
	if !accountExists {
		return "", nil, nil, errors.ErrorData(logutils.StatusMissing, model.TypeAccount, nil).SetStatus(utils.ErrorStatusNotFound)
	}

	mfaTypes := account.GetVerifiedMFATypes()

	//find account auth type
	accountAuthType, err := a.findAccountAuthType(&account, &authType, userIdentifier)
	if accountAuthType == nil {
		return "", nil, nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeAccountAuthType, nil, err)
	}

	//check the credentials
	message, err := authImpl.checkCredentials(*accountAuthType, creds, l)
	if err != nil {
		return "", nil, nil, errors.WrapErrorAction(logutils.ActionValidate, model.TypeCredential, nil, err)
	}

	//check is verified
	if authType.UseCredentials {
		verified, expired, err := authImpl.isCredentialVerified(accountAuthType.Credential, l)
		if err != nil {
			return "", nil, nil, errors.Wrap("error checking is credential verified", err)
		}
		if !*verified {
			//it is unverified

			//check if verification is expired
			if !*expired {
				//not expired, just notify the client that it is "unverified"
				return "", nil, nil, errors.ErrorData("", "unverified credential", nil).SetStatus(utils.ErrorStatusUnverified)
			}
			//expired, first restart the verification and then notify the client that it is unverified and verification is restarted

			//restart credential verification
			err = authImpl.restartCredentialVerification(accountAuthType.Credential, l)
			if err != nil {
				return "", nil, nil, errors.Wrap("error restarting creation verification", err)
			}

			//notify the client
			return "", nil, nil, errors.ErrorData("", "credential verification expired", nil).SetStatus(utils.ErrorStatusVerificationExpired)
		}
	}

	return message, accountAuthType, mfaTypes, nil
}

func (a *Auth) applySignUp(authImpl authType, accountExists bool, authType model.AuthType, appType model.ApplicationType,
	appOrg model.ApplicationOrganization, userIdentifier string, creds string, params string,
	regProfile model.Profile, regPreferences map[string]interface{}, l *logs.Log) (string, *model.AccountAuthType, error) {
	if accountExists {
		return "", nil, errors.New("account already exists").SetStatus(utils.ErrorStatusAlreadyExists)
	}

	var message string
	var credential *model.Credential
	var profile model.Profile
	var preferences map[string]interface{}

	//check if needs to use shared profile
	useSharedProfile, sharedProfile, sharedCredential, err := a.applySharedProfile(appOrg.Application, authType.ID, userIdentifier, l)
	if err != nil {
		return "", nil, errors.Wrap("error applying shared profile", err)
	}

	if useSharedProfile {
		l.Infof("%s uses a shared profile", userIdentifier)

		//allow sign up only if the shared credential is verified
		if !sharedCredential.Verified {
			l.Infof("trying to sign up in %s with unverified shared credentials", appOrg.Organization.Name)
			return "", nil, errors.New("unverified credentials").SetStatus(utils.ErrorStatusSharedCredentialUnverified)
		}

		//merge client profile and shared profile
		profile = a.mergeClientAndSharedProfile(regProfile, *sharedProfile)
		preferences = regPreferences

		credential = sharedCredential

		message = "sucessfully registered"
	} else {
		l.Infof("%s does not use a shared profile", userIdentifier)

		profile = regProfile
		preferences = regPreferences

		credentialID, _ := uuid.NewUUID()
		credID := credentialID.String()

		///apply sign up
		var credentialValue map[string]interface{}
		message, credentialValue, err = authImpl.signUp(authType, appType, appOrg, creds, params, credentialID.String(), l)
		if err != nil {
			return "", nil, errors.Wrap("error signing up", err)
		}

		//credential
		if credentialValue != nil {
			now := time.Now()
			credential = &model.Credential{ID: credID, AccountsAuthTypes: nil, Value: credentialValue, Verified: false,
				AuthType: authType, DateCreated: now, DateUpdated: &now}
		}
	}

	preparedProfile, preparedPreferences, err := a.prepareRegistrationData(authType, userIdentifier, profile, preferences, l)
	if err != nil {
		return "", nil, errors.WrapErrorAction("error preparing registration data", model.TypeUserAuth, nil, err)
	}

	accountAuthType, err := a.registerUser(authType, userIdentifier, appOrg, credential, useSharedProfile, *preparedProfile, preparedPreferences, nil, nil, l)
	if err != nil {
		return "", nil, errors.WrapErrorAction(logutils.ActionRegister, model.TypeAccount, nil, err)
	}

	return message, accountAuthType, nil
}

func (a *Auth) mergeClientAndSharedProfile(clientData model.Profile, sharedProfile model.Profile) model.Profile {
	clientData.ID = sharedProfile.ID

	clientData.PhotoURL = utils.SetStringIfEmpty(clientData.PhotoURL, sharedProfile.PhotoURL)
	clientData.FirstName = utils.SetStringIfEmpty(clientData.FirstName, sharedProfile.FirstName)
	clientData.LastName = utils.SetStringIfEmpty(clientData.LastName, sharedProfile.LastName)
	clientData.Email = utils.SetStringIfEmpty(clientData.Email, sharedProfile.Email)
	clientData.Phone = utils.SetStringIfEmpty(clientData.Phone, sharedProfile.Phone)
	clientData.Address = utils.SetStringIfEmpty(clientData.Address, sharedProfile.Address)
	clientData.ZipCode = utils.SetStringIfEmpty(clientData.ZipCode, sharedProfile.ZipCode)
	clientData.State = utils.SetStringIfEmpty(clientData.State, sharedProfile.State)
	clientData.Country = utils.SetStringIfEmpty(clientData.Country, sharedProfile.Country)

	if clientData.BirthYear == 0 {
		clientData.BirthYear = sharedProfile.BirthYear
	}

	return clientData
}

func (a *Auth) applySharedProfile(app model.Application, authTypeID string, userIdentifier string, l *logs.Log) (bool, *model.Profile, *model.Credential, error) {
	//do not share profiles by default
	useSharedProfile := false

	var sharedProfile *model.Profile
	var sharedCredential *model.Credential

	var err error

	//the application uses shared profiles
	if app.SharedIdentities {
		l.Infof("%s uses shared identities", app.Name)

		hasSharedProfile := false
		hasSharedProfile, sharedProfile, sharedCredential, err = a.hasSharedProfile(app, authTypeID, userIdentifier, l)
		if err != nil {
			return false, nil, nil, errors.Wrap("error checking shared profile", err)
		}
		if hasSharedProfile {
			l.Infof("%s already has a profile, so use it", userIdentifier)
			useSharedProfile = true
		} else {
			l.Infof("%s does not have a profile", userIdentifier)
		}
	} else {
		l.Infof("%s does not use shared identities", app.Name)
	}

	return useSharedProfile, sharedProfile, sharedCredential, nil
}

func (a *Auth) hasSharedProfile(app model.Application, authTypeID string, userIdentifier string, l *logs.Log) (bool, *model.Profile, *model.Credential, error) {
	l.Info("hasSharedProfile")

	//find if already there is a profile for the application
	profiles, err := a.storage.FindProfiles(app.ID, authTypeID, userIdentifier)
	if err != nil {
		return false, nil, nil, errors.Wrap("error finding profiles", err)
	}
	if len(profiles) == 0 {
		l.Info("there is no profile yet")
		return false, nil, nil, nil
	}

	//find profile
	var profile *model.Profile
	var credential *model.Credential
	var credentialID *string
	for _, current := range profiles {
		for _, account := range current.Accounts {
			for _, accAuthType := range account.AuthTypes {
				if accAuthType.Identifier == userIdentifier {
					//get the profile
					profile = &current

					if accAuthType.Credential != nil {
						credentialID = &accAuthType.Credential.ID //we have only the id loaded in the credential object
					}
					break
				}
			}
		}
	}

	//find the credential
	if credentialID != nil {
		credential, err = a.storage.FindCredential(nil, *credentialID)
		if err != nil {
			return false, nil, nil, errors.Wrap("error finding a credential", err)
		}
	}
	return true, profile, credential, nil
}

//validateAPIKey checks if the given API key is valid for the given app ID
func (a *Auth) validateAPIKey(apiKey string, appID string) error {
	validAPIKey, err := a.getCachedAPIKey(apiKey)
	if err != nil || validAPIKey == nil || validAPIKey.AppID != appID {
		return errors.Newf("incorrect key for app_id=%v", appID)
	}

	return nil
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
		credential, err := a.storage.FindCredential(nil, accountAuthType.Credential.ID)
		if err != nil {
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
		return nil, errors.New("for some reasons the user auth type is nil")
	}

	authType, err := a.storage.FindAuthType(accountAuthType.AuthType.ID)
	if err != nil {
		return nil, errors.New("Failed to find authType by ID in accountAuthType")

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
		return errors.Wrap("error finding logins sessions for clearing them", err)
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
			return errors.Wrap("error on deleting logins sessions", err)
		}
	} else {
		l.Info("there is no expired sessions for deleting")
	}

	return nil
}

func (a *Auth) applyLogin(anonymous bool, sub string, authType model.AuthType, appOrg model.ApplicationOrganization,
	accountAuthType *model.AccountAuthType, appType model.ApplicationType, ipAddress string, deviceType string,
	deviceOS *string, deviceID string, params map[string]interface{}, state string, l *logs.Log) (*model.LoginSession, error) {

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
					return errors.WrapErrorAction("error creating device", model.TypeDevice, nil, err)
				}
				_, err := a.storage.InsertDevice(context, *device)
				if err != nil {
					return errors.WrapErrorAction(logutils.ActionInsert, model.TypeDevice, nil, err)
				}
			}
		}
		///

		///create login session entity
		loginSession, err = a.createLoginSession(anonymous, sub, authType, appOrg, accountAuthType, appType, ipAddress, params, state, device, l)
		if err != nil {
			return errors.WrapErrorAction("error creating a session", "", nil, err)
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
		///

		return nil
	}

	err = a.storage.PerformTransaction(transaction)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionUpdate, model.TypeUserAuth, nil, err)
	}

	return loginSession, nil
}

func (a *Auth) createDevice(accountID string, deviceType string, deviceOS *string, deviceID string, l *logs.Log) (*model.Device, error) {
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
	ipAddress string, params map[string]interface{}, state string, device *model.Device, l *logs.Log) (*model.LoginSession, error) {

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
	if !anonymous {
		uid = accountAuthType.Identifier
		name = accountAuthType.Account.Profile.GetFullName()
		email = accountAuthType.Account.Profile.Email
		phone = accountAuthType.Account.Profile.Phone
		permissions = accountAuthType.Account.GetPermissionNames()
	}
	claims := a.getStandardClaims(sub, uid, name, email, phone, rokwireTokenAud, orgID, appID, authType.Code, nil, anonymous, true, appOrg.Application.Admin)
	accessToken, err := a.buildAccessToken(claims, strings.Join(permissions, ","), authorization.ScopeGlobal)
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
		AppType: appType, Anonymous: anonymous, Identifier: sub, AccountAuthType: accountAuthType,
		Device: device, IPAddress: ipAddress, AccessToken: accessToken, RefreshTokens: []string{refreshToken}, Params: params,
		State: state, StateExpires: stateExpires, DateCreated: now}

	return &loginSession, nil
}

func (a *Auth) deleteLoginSession(context storage.TransactionContext, loginSession model.LoginSession, l *logs.Log) error {
	//always log what session has been deleted
	l.Info("deleting loging session - " + loginSession.LogInfo())

	err := a.storage.DeleteLoginSession(context, loginSession.ID)
	if err != nil {
		l.WarnAction(logutils.ActionDelete, model.TypeLoginSession, err)
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
		l.WarnAction(logutils.ActionDelete, model.TypeLoginSession, err)
		return err
	}
	return nil
}

func (a *Auth) prepareRegistrationData(authType model.AuthType, identifier string,
	profile model.Profile, preferences map[string]interface{}, l *logs.Log) (*model.Profile, map[string]interface{}, error) {

	///profile and preferences
	//get profile BB data
	gotProfile, gotPreferences, err := a.getProfileBBData(authType, identifier, l)
	if err != nil {
		args := &logutils.FieldArgs{"auth_type": authType.Code, "identifier": identifier}
		return nil, nil, errors.WrapErrorAction(logutils.ActionGet, "error getting profile BB data", args, err)
	}

	readyProfile := profile
	//if there is profile bb data
	if gotProfile != nil {
		readyProfile = a.prepareProfile(profile, *gotProfile)
	}
	readyPreferences := preferences
	//if there is preferences bb data
	if gotPreferences != nil {
		readyPreferences = a.preparePreferences(preferences, gotPreferences)
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
	credential *model.Credential) (*model.AccountAuthType, *model.Credential, error) {
	now := time.Now()

	//account auth type
	accountAuthTypeID, _ := uuid.NewUUID()
	active := true
	accountAuthType := &model.AccountAuthType{ID: accountAuthTypeID.String(), AuthType: authType,
		Identifier: identifier, Params: accountAuthTypeParams, Credential: credential, Active: active, DateCreated: now}

	//credential
	if credential != nil {
		//there is a credential
		credential.AccountsAuthTypes = append(credential.AccountsAuthTypes, *accountAuthType)
	}

	return accountAuthType, credential, nil
}

func (a *Auth) prepareProfile(clientData model.Profile, profileBBData model.Profile) model.Profile {
	clientData.PhotoURL = utils.SetStringIfEmpty(clientData.PhotoURL, profileBBData.PhotoURL)
	clientData.FirstName = utils.SetStringIfEmpty(clientData.FirstName, profileBBData.FirstName)
	clientData.LastName = utils.SetStringIfEmpty(clientData.LastName, profileBBData.LastName)
	clientData.Email = utils.SetStringIfEmpty(clientData.Email, profileBBData.Email)
	clientData.Phone = utils.SetStringIfEmpty(clientData.Phone, profileBBData.Phone)
	clientData.Address = utils.SetStringIfEmpty(clientData.Address, profileBBData.Address)
	clientData.ZipCode = utils.SetStringIfEmpty(clientData.ZipCode, profileBBData.ZipCode)
	clientData.State = utils.SetStringIfEmpty(clientData.State, profileBBData.State)
	clientData.Country = utils.SetStringIfEmpty(clientData.Country, profileBBData.Country)

	if clientData.BirthYear == 0 {
		clientData.BirthYear = profileBBData.BirthYear
	}

	return clientData
}

func (a *Auth) preparePreferences(clientData map[string]interface{}, profileBBData map[string]interface{}) map[string]interface{} {
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

//registerUser registers account for an organization in an application
//	Input:
//		authType (AuthType): The authentication type
//		userIdentifier (string): The user identifier
//		appOrg (ApplicationOrganization): The application organization which the user is registering in
//		credential (*Credential): Information for the user
//		useSharedProfile (bool): It says if the system to look if the user has account in another application in the system and to use its profile instead of creating a new profile
//		preferences (map[string]interface{}): Preferences of the user
//		profile (Profile): Information for the user
//		l (*logs.Log): Log object pointer for request
//	Returns:
//		Registered account (AccountAuthType): Registered Account object
func (a *Auth) registerUser(authType model.AuthType, userIdentifier string, appOrg model.ApplicationOrganization,
	credential *model.Credential, useSharedProfile bool,
	profile model.Profile, preferences map[string]interface{}, roleIDs []string, groupIDs []string, l *logs.Log) (*model.AccountAuthType, error) {

	//TODO - analyse what should go in one transaction

	//create account auth type
	accountAuthType, credential, err := a.prepareAccountAuthType(authType, userIdentifier, nil, credential)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionCreate, model.TypeAccountAuthType, nil, err)
	}

	//create account object
	accountID, _ := uuid.NewUUID()
	authTypes := []model.AccountAuthType{*accountAuthType}

	roles, err := a.storage.FindAppOrgRoles(roleIDs, appOrg.ID)
	if err != nil {
		l.WarnError(logutils.MessageAction(logutils.StatusError, logutils.ActionFind, model.TypeAppOrgRole, nil), err)
	}
	groups, err := a.storage.FindAppOrgGroups(groupIDs, appOrg.ID)
	if err != nil {
		l.WarnError(logutils.MessageAction(logutils.StatusError, logutils.ActionFind, model.TypeAppOrgGroup, nil), err)
	}

	account := model.Account{ID: accountID.String(), AppOrg: appOrg,
		Permissions: nil, Roles: model.AccountRolesFromAppOrgRoles(roles, true, false), Groups: model.AccountGroupsFromAppOrgGroups(groups, true, false),
		AuthTypes: authTypes, Preferences: preferences, Profile: profile, DateCreated: time.Now()} // Anonymous: accountAuthType.AuthType.IsAnonymous

	//insert account object - it includes the account auth type
	insertedAccount, err := a.storage.InsertAccount(account)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionInsert, model.TypeAccount, nil, err)
	}

	//insert or update credential
	if credential != nil {
		//TODO - in one transaction
		if useSharedProfile {
			//update credential
			err = a.storage.UpdateCredential(nil, credential)
			if err != nil {
				return nil, errors.Wrapf("error updating a credential", err)
			}
		} else {
			//create credential
			err = a.storage.InsertCredential(credential)
			if err != nil {
				return nil, errors.Wrapf("error inserting a credential", err)
			}
		}
	}

	accountAuthType.Account = *insertedAccount

	return accountAuthType, nil
}

func (a *Auth) linkAccountAuthType(account model.Account, authType model.AuthType, appType model.ApplicationType, appOrg model.ApplicationOrganization,
	creds string, params string, l *logs.Log) (string, *model.AccountAuthType, error) {
	authImpl, err := a.getAuthTypeImpl(authType)
	if err != nil {
		return "", nil, errors.WrapErrorAction(logutils.ActionLoadCache, typeAuthType, nil, err)
	}

	userIdentifier, err := authImpl.getUserIdentifier(creds)
	if err != nil {
		return "", nil, errors.WrapErrorAction(logutils.ActionGet, "user identifier", nil, err)
	}

	//2. check if the user exists
	newCredsAccount, err := a.storage.FindAccount(appOrg.ID, authType.ID, userIdentifier)
	if err != nil {
		return "", nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeAccount, nil, err)
	}
	//cannot link creds if an account already exists for new creds
	if newCredsAccount != nil {
		return "", nil, errors.New("an account already exists for the provided credentials")
	}

	credentialID, _ := uuid.NewUUID()
	credID := credentialID.String()

	//apply sign up
	message, credentialValue, err := authImpl.signUp(authType, appType, appOrg, creds, params, credentialID.String(), l)
	if err != nil {
		return "", nil, errors.Wrap("error signing up", err)
	}

	//credential
	var credential *model.Credential
	if credentialValue != nil {
		now := time.Now()
		credential = &model.Credential{ID: credID, AccountsAuthTypes: nil, Value: credentialValue, Verified: false,
			AuthType: authType, DateCreated: now, DateUpdated: &now}
	}

	accountAuthType, credential, err := a.prepareAccountAuthType(authType, userIdentifier, nil, credential)
	if err != nil {
		return "", nil, errors.WrapErrorAction(logutils.ActionCreate, model.TypeAccountAuthType, nil, err)
	}
	accountAuthType.Account = account

	err = a.registerAccountAuthType(*accountAuthType, credential, l)
	if err != nil {
		return "", nil, errors.WrapErrorAction(logutils.ActionRegister, model.TypeAccountAuthType, nil, err)
	}

	return message, accountAuthType, nil
}

func (a *Auth) linkAccountAuthTypeExternal(account model.Account, authType model.AuthType, appType model.ApplicationType, appOrg model.ApplicationOrganization,
	creds string, params string, l *logs.Log) (*model.AccountAuthType, error) {
	authImpl, err := a.getExternalAuthTypeImpl(authType)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionLoadCache, typeAuthType, nil, err)
	}

	externalUser, _, err := authImpl.externalLogin(authType, appType, appOrg, creds, params, l)
	if err != nil {
		return nil, errors.WrapErrorAction("logging in", "external user", nil, err)
	}

	//2. check if the user exists
	newCredsAccount, err := a.storage.FindAccount(appOrg.ID, authType.ID, externalUser.Identifier)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeAccount, nil, err)
	}
	//cannot link creds if an account already exists for new creds
	if newCredsAccount != nil {
		return nil, errors.New("an account already exists for the provided credentials")
	}

	accountAuthTypeParams := map[string]interface{}{}
	accountAuthTypeParams["user"] = externalUser

	accountAuthType, credential, err := a.prepareAccountAuthType(authType, externalUser.Identifier, accountAuthTypeParams, nil)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionCreate, model.TypeAccountAuthType, nil, err)
	}
	accountAuthType.Account = account

	err = a.registerAccountAuthType(*accountAuthType, credential, l)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionRegister, model.TypeAccountAuthType, nil, err)
	}

	return accountAuthType, nil
}

func (a *Auth) registerAccountAuthType(accountAuthType model.AccountAuthType, credential *model.Credential, l *logs.Log) error {
	var err error
	if credential != nil {
		//TODO - in one transaction
		if err = a.storage.InsertCredential(credential); err != nil {
			return errors.WrapErrorAction(logutils.ActionInsert, model.TypeCredential, nil, err)
		}
	}

	err = a.storage.InsertAccountAuthType(accountAuthType)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionInsert, model.TypeAccount, nil, err)
	}

	return nil
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

func (a *Auth) registerMfaType(name string, mfa mfaType) error {
	if _, ok := a.mfaTypes[name]; ok {
		return errors.Newf("the requested mfa type name has already been registered: %s", name)
	}

	a.mfaTypes[name] = mfa

	return nil
}

func (a *Auth) validateAuthType(authenticationType string, appTypeIdentifier string, orgID string) (*model.AuthType, *model.ApplicationType, *model.ApplicationOrganization, error) {
	//get the auth type
	authType, err := a.storage.FindAuthType(authenticationType)
	if err != nil {
		return nil, nil, nil, errors.WrapErrorAction(logutils.ActionValidate, typeAuthType, logutils.StringArgs(authenticationType), err)
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

func (a *Auth) getMfaTypeImpl(mfaType string) (mfaType, error) {
	if mfa, ok := a.mfaTypes[mfaType]; ok {
		return mfa, nil
	}

	return nil, errors.ErrorData(logutils.StatusInvalid, typeMfaType, logutils.StringArgs(mfaType))
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

func (a *Auth) buildRefreshToken() (string, error) {
	newToken, err := utils.GenerateRandomString(refreshTokenLength)
	if err != nil {
		return "", errors.WrapErrorAction(logutils.ActionCompute, logutils.TypeToken, nil, err)
	}

	return newToken, nil
}

//getScopedAccessToken returns a scoped access token with the requested scopes
func (a *Auth) getScopedAccessToken(claims tokenauth.Claims, serviceID string, scopes []authorization.Scope) (string, error) {
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

	scopedClaims := a.getStandardClaims(claims.Subject, "", "", "", "", aud, claims.OrgID, claims.AppID, claims.AuthType, &claims.ExpiresAt, claims.Anonymous, claims.Authenticated, false)
	return a.buildAccessToken(scopedClaims, "", scope)
}

func (a *Auth) getStandardClaims(sub string, uid string, name string, email string, phone string, aud string, orgID string, appID string,
	authType string, exp *int64, anonymous bool, authenticated bool, admin bool) tokenauth.Claims {
	return tokenauth.Claims{
		StandardClaims: jwt.StandardClaims{
			Audience:  aud,
			Subject:   sub,
			ExpiresAt: a.getExp(exp),
			IssuedAt:  time.Now().Unix(),
			Issuer:    a.host,
		}, OrgID: orgID, AppID: appID, AuthType: authType, UID: uid, Name: name, Email: email, Phone: phone,
		Anonymous: anonymous, Authenticated: authenticated, Admin: admin,
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

func (a *Auth) getExternalUserAuthorization(externalUser model.ExternalSystemUser, appOrg model.ApplicationOrganization, authType model.AuthType) ([]string, []string, error) {
	identityProviderID, ok := authType.Params["identity_provider"].(string)
	if !ok {
		return nil, nil, errors.ErrorData(logutils.StatusMissing, "identitiy provider id", nil)
	}
	identityProviderSetting := appOrg.FindIdentityProviderSetting(identityProviderID)
	if identityProviderSetting == nil {
		return nil, nil, errors.ErrorData(logutils.StatusMissing, model.TypeIdentityProvider, nil)
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

func (a *Auth) updateExternalAccountRoles(account *model.Account, newExternalRoleIDs []string) (bool, error) {
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

	addedRoles, err := a.storage.FindAppOrgRoles(addedRoleIDs, account.AppOrg.ID)
	if err != nil {
		return false, errors.WrapErrorAction(logutils.ActionFind, model.TypeAccountRoles, nil, err)
	}
	newRoles = append(newRoles, model.AccountRolesFromAppOrgRoles(addedRoles, true, false)...)

	account.Roles = newRoles
	return updated, nil
}

func (a *Auth) updateExternalAccountGroups(account *model.Account, newExternalGroupIDs []string) (bool, error) {
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

	addedGroups, err := a.storage.FindAppOrgGroups(addedGroupIDs, account.AppOrg.ID)
	if err != nil {
		return false, errors.WrapErrorAction(logutils.ActionFind, model.TypeAccountGroups, nil, err)
	}
	newGroups = append(newGroups, model.AccountGroupsFromAppOrgGroups(addedGroups, true, false)...)

	account.Groups = newGroups
	return updated, nil
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

func (a *Auth) setupDeleteSessionsTimer() {
	a.logger.Info("setupDeleteSessionsTimer")

	//cancel if active
	if a.deleteSessionsTimer != nil {
		a.timerDone <- true
		a.deleteSessionsTimer.Stop()
	}

	a.deleteSessions()
}

func (a *Auth) deleteSessions() {
	a.logger.Info("deleteSessions")

	// to delete:
	// - not completed MFA
	// - expired sessions

	//1. not completed MFA
	a.deleteNotCompletedMFASessions()

	//2. expired sessions
	a.deleteExpiredSessions()

	duration := time.Hour * time.Duration(sessionDeletePeriod)
	a.deleteSessionsTimer = time.NewTimer(duration)
	select {
	case <-a.deleteSessionsTimer.C:
		// timer expired
		a.deleteSessionsTimer = nil

		a.deleteSessions()
	case <-a.timerDone:
		// timer aborted
		a.deleteSessionsTimer = nil
	}
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

	appsOrgs, err := a.storage.LoadApplicationsOrganizations()
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

//OnIdentityProvidersUpdated notifies that identity providers have been updated
func (al *StorageListener) OnIdentityProvidersUpdated() {
	al.auth.cacheIdentityProviders()
}

//OnAPIKeysUpdated notifies api keys have been updated
func (al *StorageListener) OnAPIKeysUpdated() {
	al.auth.cacheAPIKeys()
}

//OnServiceRegsUpdated notifies that a service registration has been updated
func (al *StorageListener) OnServiceRegsUpdated() {
	al.auth.AuthService.LoadServices()
}
