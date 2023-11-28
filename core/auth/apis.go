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
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/rokwire/core-auth-library-go/v3/authorization"
	"github.com/rokwire/core-auth-library-go/v3/authutils"
	"github.com/rokwire/core-auth-library-go/v3/sigauth"
	"github.com/rokwire/core-auth-library-go/v3/tokenauth"
	"github.com/rokwire/logging-library-go/v2/errors"
	"github.com/rokwire/logging-library-go/v2/logutils"

	"github.com/rokwire/logging-library-go/v2/logs"
)

// Start starts the auth service
func (a *Auth) Start() {
	storageListener := StorageListener{auth: a}
	a.storage.RegisterStorageListener(&storageListener)

	go utils.StartTimer(a.deleteSessionsTimer, a.deleteSessionsTimerDone, time.Hour*time.Duration(sessionDeletePeriod), a.deleteSessions, "delete sessions", a.logger)
}

// GetHost returns the host/issuer of the auth service
func (a *Auth) GetHost() string {
	return a.host
}

// Login logs a user into a specific application using the specified credentials and authentication method.
// The authentication method must be one of the supported for the application.
//
//	Input:
//		ipAddress (string): Client's IP address
//		deviceType (string): "mobile" or "web" or "desktop" etc
//		deviceOS (*string): Device OS
//		deviceID (*string): Device ID
//		authenticationType (string): Name of the authentication method for provided creds (eg. "email", "username", "illinois_oidc")
//		creds (string): Credentials/JSON encoded credential structure defined for the specified auth type
//		apiKey (string): API key to validate the specified app
//		appTypeIdentifier (string): identifier of the app type/client that the user is logging in from
//		orgID (string): ID of the organization that the user is logging in
//		params (string): JSON encoded params defined by specified auth type
//		profile (Profile): Account profile
//		preferences (map): Account preferences
//		admin (bool): Is this an admin login?
//		l (*logs.Log): Log object pointer for request
//	Returns:
//		Message (*string): message
//		Login session (*LoginSession): Signed ROKWIRE access token to be used to authorize future requests
//			Access token (string): Signed ROKWIRE access token to be used to authorize future requests
//			Refresh Token (string): Refresh token that can be sent to refresh the access token once it expires
//			AccountAuthType (AccountAuthType): AccountAuthType object for authenticated user
//			Params (interface{}): authType-specific set of parameters passed back to client
//			State (string): login state used if account is enrolled in MFA
//		MFA types ([]model.MFAType): list of MFA types account is enrolled in
func (a *Auth) Login(ipAddress string, deviceType string, deviceOS *string, deviceID *string, authenticationType string, creds string, apiKey string,
	appTypeIdentifier string, orgID string, params string, clientVersion *string, profile model.Profile, privacy model.Privacy, preferences map[string]interface{},
	username string, admin bool, l *logs.Log) (*string, *model.LoginSession, []model.MFAType, error) {
	//TODO - analyse what should go in one transaction

	//validate if the provided auth type is supported by the provided application and organization
	authType, appType, appOrg, err := a.validateAuthType(authenticationType, appTypeIdentifier, orgID)
	if err != nil || authType == nil {
		return nil, nil, nil, errors.WrapErrorAction(logutils.ActionValidate, model.TypeAuthType, nil, err)
	}

	if appOrg.Application.Admin != admin {
		if admin {
			return nil, nil, nil, errors.ErrorData(logutils.StatusInvalid, model.TypeApplication, logutils.StringArgs("use services login endpoint"))
		}
		return nil, nil, nil, errors.ErrorData(logutils.StatusInvalid, model.TypeApplication, logutils.StringArgs("use admin login endpoint"))
	}

	//TODO: Ideally we would not make many database calls before validating the API key. Currently needed to get app ID
	err = a.validateAPIKey(apiKey, appType.Application.ID)
	if err != nil {
		return nil, nil, nil, errors.WrapErrorData(logutils.StatusInvalid, model.TypeAPIKey, nil, err)
	}

	username = strings.TrimSpace(strings.ToLower(username))

	anonymous := false
	sub := ""

	var message string
	var accountAuthType *model.AccountAuthType
	var responseParams map[string]interface{}
	var externalIDs map[string]string
	var mfaTypes []model.MFAType
	var state string

	//get the auth type implementation for the auth type
	if authType.IsAnonymous && !admin {
		anonymous = true

		anonymousID := ""
		var account *model.Account
		anonymousID, account, responseParams, err = a.applyAnonymousAuthType(*authType, creds)
		if err != nil {
			return nil, nil, nil, errors.WrapErrorAction(logutils.ActionApply, typeAnonymousAuthType, logutils.StringArgs("user"), err)
		}
		sub = anonymousID

		if account != nil {
			accountAuthType = &model.AccountAuthType{Account: *account}
		}
	} else if authType.IsExternal {
		accountAuthType, responseParams, mfaTypes, externalIDs, err = a.applyExternalAuthType(*authType, *appType, *appOrg, creds, params, clientVersion, profile, privacy, preferences, username, admin, l)
		if err != nil {
			return nil, nil, nil, errors.WrapErrorAction(logutils.ActionApply, typeExternalAuthType, logutils.StringArgs("user"), err)
		}

		sub = accountAuthType.Account.ID
	} else {
		message, accountAuthType, mfaTypes, externalIDs, err = a.applyAuthType(*authType, *appOrg, creds, params, clientVersion, profile, privacy, preferences, username, admin, l)
		if err != nil {
			return nil, nil, nil, errors.WrapErrorAction(logutils.ActionApply, model.TypeAuthType, logutils.StringArgs("user"), err)
		}
		//message
		if len(message) > 0 {
			return &message, nil, nil, nil
		}

		sub = accountAuthType.Account.ID

		//the credentials are valid
	}

	//check if account is enrolled in MFA
	if !authType.IgnoreMFA && len(mfaTypes) > 0 {
		state, err = utils.GenerateRandomString(loginStateLength)
		if err != nil {
			return nil, nil, nil, errors.WrapErrorAction(logutils.ActionGenerate, "login state", nil, err)
		}
	}

	//clear the expired sessions for the identifier - user or anonymous
	err = a.clearExpiredSessions(sub, l)
	if err != nil {
		return nil, nil, nil, errors.WrapErrorAction(logutils.ActionDelete, "expired login sessions", &logutils.FieldArgs{"identifier": sub}, err)
	}

	//now we are ready to apply login for the user or anonymous
	loginSession, err := a.applyLogin(anonymous, sub, *authType, *appOrg, accountAuthType, *appType, externalIDs, ipAddress, deviceType, deviceOS, deviceID, clientVersion, responseParams, state, l)
	if err != nil {
		return nil, nil, nil, errors.WrapErrorAction(logutils.ActionApply, "login", logutils.StringArgs("user"), err)
	}

	if loginSession.State == "" {
		return nil, loginSession, nil, nil
	}

	return nil, &model.LoginSession{ID: loginSession.ID, Identifier: loginSession.Identifier, Params: responseParams, State: loginSession.State}, mfaTypes, nil
}

// Logout logs out an account from app/org
//
//	Input:
//		allSessions (bool): If to remove the current session only or all sessions for the app/org for the account
func (a *Auth) Logout(appID string, orgID string, currentAccountID string, sessionID string, allSessions bool, l *logs.Log) error {
	if allSessions {
		err := a.storage.DeleteLoginSessionsByIdentifier(nil, currentAccountID)
		if err != nil {
			return errors.WrapErrorAction(logutils.ActionDelete, model.TypeLoginSession, &logutils.FieldArgs{"identifier": currentAccountID}, err)
		}
	} else {
		err := a.storage.DeleteLoginSession(nil, sessionID)
		if err != nil {
			return errors.WrapErrorAction(logutils.ActionDelete, model.TypeLoginSession, &logutils.FieldArgs{"session_id": sessionID}, err)
		}
	}
	return nil
}

// AccountExists checks if a user is already registered
// The authentication method must be one of the supported for the application.
//
//	Input:
//		authenticationType (string): Name of the authentication method for provided creds (eg. "email", "username", "illinois_oidc")
//		userIdentifier (string): User identifier for the specified auth type
//		apiKey (string): API key to validate the specified app
//		appTypeIdentifier (string): identifier of the app type/client that the user is logging in from
//		orgID (string): ID of the organization that the user is logging in
//	Returns:
//		accountExisted (bool): valid when error is nil
func (a *Auth) AccountExists(authenticationType string, userIdentifier string, apiKey string, appTypeIdentifier string, orgID string) (bool, error) {
	account, _, _, err := a.getAccount(authenticationType, userIdentifier, apiKey, appTypeIdentifier, orgID)
	if err != nil {
		return false, errors.WrapErrorAction(logutils.ActionGet, model.TypeAccount, nil, err)
	}

	return account != nil, nil
}

// CanSignIn checks if a user can sign in
// The authentication method must be one of the supported for the application.
//
//	Input:
//		authenticationType (string): Name of the authentication method for provided creds (eg. "email", "username", "illinois_oidc")
//		userIdentifier (string): User identifier for the specified auth type
//		apiKey (string): API key to validate the specified app
//		appTypeIdentifier (string): identifier of the app type/client being used
//		orgID (string): ID of the organization being used
//	Returns:
//		canSignIn (bool): valid when error is nil
func (a *Auth) CanSignIn(authenticationType string, userIdentifier string, apiKey string, appTypeIdentifier string, orgID string) (bool, error) {
	account, authTypeID, appOrg, err := a.getAccount(authenticationType, userIdentifier, apiKey, appTypeIdentifier, orgID)
	if err != nil {
		return false, errors.WrapErrorAction(logutils.ActionGet, model.TypeAccount, nil, err)
	}

	return a.canSignInV2(account, authTypeID, userIdentifier, appOrg.ID), nil
}

// CanLink checks if a user can link a new auth type
// The authentication method must be one of the supported for the application.
//
//	Input:
//		authenticationType (string): Name of the authentication method for provided creds (eg. "email", "username", "illinois_oidc")
//		userIdentifier (string): User identifier for the specified auth type
//		apiKey (string): API key to validate the specified app
//		appTypeIdentifier (string): identifier of the app type/client being used
//		orgID (string): ID of the organization being used
//	Returns:
//		canLink (bool): valid when error is nil
func (a *Auth) CanLink(authenticationType string, userIdentifier string, apiKey string, appTypeIdentifier string, orgID string) (bool, error) {
	account, authTypeID, _, err := a.getAccount(authenticationType, userIdentifier, apiKey, appTypeIdentifier, orgID)
	if err != nil {
		return false, errors.WrapErrorAction(logutils.ActionGet, model.TypeAccount, nil, err)
	}

	if account != nil {
		aat := account.GetAccountAuthType(authTypeID, userIdentifier)
		return (aat != nil && aat.Unverified), nil
	}

	return true, nil
}

// Refresh refreshes an access token using a refresh token
//
//	Input:
//		refreshToken (string): Refresh token
//		apiKey (string): API key to validate the specified app
//		l (*logs.Log): Log object pointer for request
//	Returns:
//		Login session (*LoginSession): Signed ROKWIRE access token to be used to authorize future requests
//			Access token (string): Signed ROKWIRE access token to be used to authorize future requests
//			Refresh Token (string): Refresh token that can be sent to refresh the access token once it expires
//			Params (interface{}): authType-specific set of parameters passed back to client
func (a *Auth) Refresh(refreshToken string, apiKey string, clientVersion *string, l *logs.Log) (*model.LoginSession, error) {
	var loginSession *model.LoginSession

	//find the login session for the refresh token
	loginSession, err := a.storage.FindLoginSession(refreshToken)
	if err != nil {
		l.Infof("error finding session by refresh token - %s", refreshToken)
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeLoginSession, logutils.StringArgs("refresh token"), err)
	}
	if loginSession == nil {
		l.Infof("there is no a session for refresh token - %s", refreshToken)
		return nil, nil
	}
	l.SetContext("account_id", loginSession.Identifier)

	//check if the session is expired
	if loginSession.IsExpired() {
		l.Infof("the session is expired, so delete it and return null - %s", refreshToken)

		//remove the session
		err = a.deleteLoginSession(nil, *loginSession, l)
		if err != nil {
			return nil, errors.WrapErrorAction(logutils.ActionDelete, "expired login session", nil, err)
		}

		//return nul
		return nil, nil
	}

	//check if a previous refresh token is being used
	//the session must contain the token since the session was returned by Mongo, so the token is old if not equal to the last token in the list
	currentToken := loginSession.CurrentRefreshToken()
	if currentToken == "" {
		return nil, errors.ErrorData(logutils.StatusMissing, "refresh tokens", nil)
	}
	if refreshToken != currentToken {
		l.Infof("previous refresh token being used, so delete login session and return null - %s", refreshToken)

		//remove the session
		err = a.deleteLoginSession(nil, *loginSession, l)
		if err != nil {
			return nil, errors.WrapErrorAction(logutils.ActionDelete, model.TypeLoginSession, logutils.StringArgs("previous refresh token"), err)
		}

		return nil, nil
	}

	//TODO: Ideally we would not make many database calls before validating the API key. Currently needed to get app ID
	err = a.validateAPIKey(apiKey, loginSession.AppOrg.Application.ID)
	if err != nil {
		return nil, errors.WrapErrorData(logutils.StatusInvalid, model.TypeAPIKey, nil, err)
	}

	///now:
	// - generate new access token
	sub := loginSession.Identifier
	orgID := loginSession.AppOrg.Organization.ID
	appID := loginSession.AppOrg.Application.ID
	authType := loginSession.AuthType.Code

	anonymous := loginSession.Anonymous
	uid := ""
	name := ""
	email := ""
	phone := ""
	permissions := []string{}

	// - generate new params and update the account if needed(if external auth type)
	if loginSession.AuthType.IsExternal {
		extAuthType, err := a.getExternalAuthTypeImpl(loginSession.AuthType)
		if err != nil {
			l.Infof("error getting external auth type on refresh - %s", refreshToken)
			return nil, errors.WrapErrorAction(logutils.ActionGet, "external auth type", nil, err)
		}

		externalUser, refreshedData, externalCreds, err := extAuthType.refresh(loginSession.Params, loginSession.AuthType, loginSession.AppType, loginSession.AppOrg, l)
		if err != nil {
			l.Infof("error refreshing external auth type on refresh - %s", refreshToken)
			return nil, errors.WrapErrorAction(logutils.ActionRefresh, "external auth type", nil, err)
		}

		//check if need to update the account data
		newAccount, err := a.updateExternalUserIfNeeded(*loginSession.AccountAuthType, *externalUser, loginSession.AuthType, loginSession.AppOrg, externalCreds, l)
		if err != nil {
			return nil, errors.WrapErrorAction(logutils.ActionUpdate, model.TypeExternalSystemUser, logutils.StringArgs("refresh"), err)
		}

		loginSession.Params = refreshedData //assign the refreshed data
		if newAccount != nil {
			loginSession.ExternalIDs = newAccount.ExternalIDs
		}
	}

	scopes := []string{authorization.ScopeGlobal}
	if !anonymous {
		accountAuthType := loginSession.AccountAuthType
		if accountAuthType == nil {
			l.Infof("for some reasons account auth type is null for not anonymous login - %s", loginSession.ID)
			return nil, errors.ErrorAction("for some reasons account auth type is null for not anonymous login", "", nil)
		}
		uid = accountAuthType.Identifier
		name = accountAuthType.Account.Profile.GetFullName()
		email = accountAuthType.Account.Profile.Email
		phone = accountAuthType.Account.Profile.Phone
		permissions = accountAuthType.Account.GetPermissionNames()
		scopes = append(scopes, accountAuthType.Account.GetScopes()...)
	}
	claims := a.getStandardClaims(sub, uid, name, email, phone, rokwireTokenAud, orgID, appID, authType, loginSession.ExternalIDs, nil, anonymous, false, loginSession.AppOrg.Application.Admin, loginSession.AppOrg.Organization.System, false, true, loginSession.ID)
	accessToken, err := a.buildAccessToken(claims, strings.Join(permissions, ","), strings.Join(scopes, " "))
	if err != nil {
		l.Infof("error generating acccess token on refresh - %s", refreshToken)
		return nil, errors.WrapErrorAction(logutils.ActionCreate, logutils.TypeToken, nil, err)
	}
	loginSession.AccessToken = accessToken //set the generated token
	// - generate new refresh token
	refreshToken, err = a.buildRefreshToken()
	if err != nil {
		l.Infof("error generating refresh token on refresh - %s", refreshToken)
		return nil, errors.WrapErrorAction(logutils.ActionCreate, logutils.TypeToken, nil, err)
	}
	if loginSession.RefreshTokens == nil {
		loginSession.RefreshTokens = make([]string, 0)
	}
	loginSession.RefreshTokens = append(loginSession.RefreshTokens, refreshToken) //set the generated token

	now := time.Now()
	loginSession.DateUpdated = &now
	loginSession.DateRefreshed = &now

	//store the updated session
	err = a.storage.UpdateLoginSession(nil, *loginSession)
	if err != nil {
		l.Infof("error updating login session on refresh - %s", refreshToken)
		return nil, errors.WrapErrorAction(logutils.ActionUpdate, model.TypeLoginSession, nil, err)
	}

	// update account usage information
	// TODO: Handle anonymous accounts if needed in the future
	if !anonymous {
		err = a.storage.UpdateAccountUsageInfo(nil, loginSession.Identifier, false, true, clientVersion)
		if err != nil {
			return nil, errors.WrapErrorAction(logutils.ActionUpdate, model.TypeAccountUsageInfo, nil, err)
		}
	}

	//return the updated session
	return loginSession, nil
}

// GetLoginURL returns a pre-formatted login url for SSO providers
//
//	Input:
//		authenticationType (string): Name of the authentication method for provided creds (eg. "email", "username", "illinois_oidc")
//		appTypeIdentifier (string): Identifier of the app type/client that the user is logging in from
//		orgID (string): ID of the organization that the user is logging in
//		redirectURI (string): Registered redirect URI where client will receive response
//		apiKey (string): API key to validate the specified app
//		l (*loglib.Log): Log object pointer for request
//	Returns:
//		Login URL (string): SSO provider login URL to be launched in a browser
//		Params (map[string]interface{}): Params to be sent in subsequent request (if necessary)
func (a *Auth) GetLoginURL(authenticationType string, appTypeIdentifier string, orgID string, redirectURI string, apiKey string, l *logs.Log) (string, map[string]interface{}, error) {
	//validate if the provided auth type is supported by the provided application and organization
	authType, appType, _, err := a.validateAuthType(authenticationType, appTypeIdentifier, orgID)
	if err != nil {
		return "", nil, errors.WrapErrorAction(logutils.ActionValidate, model.TypeAuthType, nil, err)
	}

	//TODO: Ideally we would not make many database calls before validating the API key. Currently needed to get app ID
	err = a.validateAPIKey(apiKey, appType.Application.ID)
	if err != nil {
		return "", nil, errors.WrapErrorData(logutils.StatusInvalid, model.TypeAPIKey, nil, err)
	}

	//get the auth type implementation for the auth type
	authImpl, err := a.getExternalAuthTypeImpl(*authType)
	if err != nil {
		return "", nil, errors.WrapErrorAction(logutils.ActionLoadCache, model.TypeAuthType, nil, err)
	}

	//get login URL
	loginURL, params, err := authImpl.getLoginURL(*authType, *appType, redirectURI, l)
	if err != nil {
		return "", nil, errors.WrapErrorAction(logutils.ActionGet, "login url", nil, err)
	}

	return loginURL, params, nil
}

// LoginMFA verifies a code sent by a user as a final login step for enrolled accounts.
// The MFA type must be one of the supported for the application.
//
//	Input:
//		apiKey (string): API key to validate the specified app
//		accountID (string): ID of account user is trying to access
//		sessionID (string): ID of login session generated during login
//		identifier (string): Email, phone, or TOTP device name
//		mfaType (string): Type of MFA code sent
//		mfaCode (string): Code that must be verified
//		state (string): Variable used to verify user has already passed credentials check
//		l (*logs.Log): Log object pointer for request
//	Returns:
//		Message (*string): message
//		Login session (*LoginSession): Signed ROKWIRE access token to be used to authorize future requests
//			Access token (string): Signed ROKWIRE access token to be used to authorize future requests
//			Refresh Token (string): Refresh token that can be sent to refresh the access token once it expires
//			AccountAuthType (AccountAuthType): AccountAuthType object for authenticated user
func (a *Auth) LoginMFA(apiKey string, accountID string, sessionID string, identifier string, mfaType string, mfaCode string, state string, l *logs.Log) (*string, *model.LoginSession, error) {
	var message string
	var loginSession *model.LoginSession
	var err error
	transaction := func(context storage.TransactionContext) error {
		//1. find mfa type in account
		loginSession, err = a.storage.FindAndUpdateLoginSession(context, sessionID)
		if err != nil {
			return errors.WrapErrorAction(logutils.ActionFind, model.TypeLoginSession, &logutils.FieldArgs{"session_id": sessionID}, err)
		}

		if loginSession.MfaAttempts >= maxMfaAttempts {
			a.deleteLoginSession(context, *loginSession, l)
			message = fmt.Sprintf("max mfa attempts reached: %d", maxMfaAttempts)
			return errors.ErrorData(logutils.StatusInvalid, model.TypeLoginSession, logutils.StringArgs(message))
		}

		//2. check api key
		err = a.validateAPIKey(apiKey, loginSession.AppOrg.Application.ID)
		if err != nil {
			return errors.WrapErrorData(logutils.StatusInvalid, model.TypeAPIKey, logutils.StringArgs(apiKey), err)
		}

		//3. find mfa type in account
		errFields := &logutils.FieldArgs{"account_id": accountID, "type": mfaType}
		mfa, err := a.storage.FindMFAType(context, accountID, identifier, mfaType)
		if err != nil {
			return errors.WrapErrorAction(logutils.ActionFind, model.TypeMFAType, errFields, err)
		}
		if mfa == nil {
			message = "account not enrolled"
			return errors.ErrorData(logutils.StatusMissing, model.TypeMFAType, errFields)
		}
		if !mfa.Verified {
			message = "mfa type not verified"
			return errors.ErrorData(logutils.StatusMissing, model.TypeMFAType, errFields)
		}
		if mfa.Params == nil {
			return errors.ErrorData(logutils.StatusMissing, "mfa params", errFields)
		}

		//4. check state variable
		if state != loginSession.State {
			message = "invalid login state"
			return errors.ErrorData(logutils.StatusInvalid, "login state", errFields)
		}
		if loginSession.StateExpires != nil && time.Now().UTC().After(*loginSession.StateExpires) {
			a.deleteLoginSession(context, *loginSession, l)
			message = "expired state"
			return errors.ErrorData(logutils.StatusInvalid, "expired state", nil)
		}

		//5. verify code
		mfaImpl, err := a.getMfaTypeImpl(mfaType)
		if err != nil {
			return errors.WrapErrorAction(logutils.ActionLoadCache, model.TypeMFAType, nil, err)
		}
		verifyMsg, err := mfaImpl.verify(context, mfa, accountID, mfaCode)
		if err != nil {
			if verifyMsg != nil {
				message = *verifyMsg
			}
			return errors.WrapErrorAction(logutils.ActionVerify, "mfa code", errFields, err)
		}

		loginSession.State = ""
		loginSession.StateExpires = nil
		loginSession.MfaAttempts = 0
		err = a.storage.UpdateLoginSession(context, *loginSession)
		if err != nil {
			return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeLoginSession, nil, err)
		}

		return nil
	}

	err = a.storage.PerformTransaction(transaction)
	if err != nil {
		if message != "" {
			return &message, nil, errors.WrapErrorAction(logutils.ActionVerify, model.TypeMFAType, nil, err)
		}
		return nil, nil, errors.WrapErrorAction(logutils.ActionVerify, model.TypeMFAType, nil, err)
	}

	return nil, loginSession, nil
}

// CreateAdminAccount creates an account for a new admin user
func (a *Auth) CreateAdminAccount(authenticationType string, appID string, orgID string, identifier string, profile model.Profile, privacy model.Privacy, username string,
	permissions []string, roleIDs []string, groupIDs []string, scopes []string, creatorPermissions []string, clientVersion *string, l *logs.Log) (*model.Account, map[string]interface{}, error) {
	//TODO: add admin authentication policies that specify which auth types may be used for each app org
	if authenticationType != AuthTypeOidc && authenticationType != AuthTypeEmail && !strings.HasSuffix(authenticationType, "_oidc") {
		return nil, nil, errors.ErrorData(logutils.StatusInvalid, "auth type", nil)
	}

	// check if the provided auth type is supported by the provided application and organization
	authType, appOrg, err := a.validateAuthTypeForAppOrg(authenticationType, appID, orgID)
	if err != nil {
		return nil, nil, errors.WrapErrorAction(logutils.ActionValidate, model.TypeAuthType, nil, err)
	}

	// create account
	var accountAuthType *model.AccountAuthType
	var newAccount *model.Account
	var params map[string]interface{}
	transaction := func(context storage.TransactionContext) error {
		//1. check if the user exists
		account, err := a.storage.FindAccount(context, appOrg.ID, authType.ID, identifier)
		if err != nil {
			return errors.WrapErrorAction(logutils.ActionFind, model.TypeAccount, nil, err)
		}
		if account != nil {
			return errors.ErrorData(logutils.StatusFound, model.TypeAccount, &logutils.FieldArgs{"app_org_id": appOrg.ID, "auth_type": authType.Code, "identifier": identifier})
		}

		//2. account does not exist, so apply sign up
		profile.DateCreated = time.Now().UTC()
		if authType.IsExternal {
			externalUser := model.ExternalSystemUser{Identifier: identifier}
			accountAuthType, err = a.applySignUpAdminExternal(context, *authType, *appOrg, externalUser, profile, privacy, username, permissions, roleIDs, groupIDs, scopes, creatorPermissions, clientVersion, l)
			if err != nil {
				return errors.WrapErrorAction(logutils.ActionRegister, "admin user", &logutils.FieldArgs{"auth_type": authType.Code, "identifier": identifier}, err)
			}
		} else {
			authImpl, err := a.getAuthTypeImpl(*authType)
			if err != nil {
				return errors.WrapErrorAction(logutils.ActionLoadCache, typeExternalAuthType, nil, err)
			}

			profile.Email = identifier
			params, accountAuthType, err = a.applySignUpAdmin(context, authImpl, account, *authType, *appOrg, identifier, "", profile, privacy, username, permissions, roleIDs, groupIDs, scopes, creatorPermissions, clientVersion, l)
			if err != nil {
				return errors.WrapErrorAction(logutils.ActionRegister, "admin user", &logutils.FieldArgs{"auth_type": authType.Code, "identifier": identifier}, err)
			}
		}

		newAccount = &accountAuthType.Account
		return nil
	}

	err = a.storage.PerformTransaction(transaction)
	if err != nil {
		return nil, nil, errors.WrapErrorAction(logutils.ActionCreate, "admin account", nil, err)
	}

	return newAccount, params, nil
}

// UpdateAdminAccount updates an existing user's account with new permissions, roles, and groups
func (a *Auth) UpdateAdminAccount(authenticationType string, appID string, orgID string, identifier string, permissions []string, roleIDs []string,
	groupIDs []string, scopes []string, updaterPermissions []string, l *logs.Log) (*model.Account, map[string]interface{}, error) {
	//TODO: when elevating existing accounts to application level admin, need to enforce any authentication policies set up for the app org
	// when demoting from application level admin to standard user, may want to inform user of applicable authentication policy changes

	if authenticationType != AuthTypeOidc && authenticationType != AuthTypeEmail && !strings.HasSuffix(authenticationType, "_oidc") {
		return nil, nil, errors.ErrorData(logutils.StatusInvalid, "auth type", nil)
	}

	// check if the provided auth type is supported by the provided application and organization
	authType, appOrg, err := a.validateAuthTypeForAppOrg(authenticationType, appID, orgID)
	if err != nil {
		return nil, nil, errors.WrapErrorAction(logutils.ActionValidate, model.TypeAuthType, nil, err)
	}

	var updatedAccount *model.Account
	var params map[string]interface{}
	transaction := func(context storage.TransactionContext) error {
		//1. check if the user exists
		account, err := a.storage.FindAccount(context, appOrg.ID, authType.ID, identifier)
		if err != nil {
			return errors.WrapErrorAction(logutils.ActionFind, model.TypeAccount, nil, err)
		}
		if account == nil {
			return errors.ErrorData(logutils.StatusMissing, model.TypeAccount, &logutils.FieldArgs{"app_org_id": appOrg.ID, "auth_type": authType.Code, "identifier": identifier})
		}

		//2. check if the user's auth type is verified
		accountAuthType := account.GetAccountAuthType(authType.ID, identifier)
		if accountAuthType == nil || accountAuthType.Unverified {
			return errors.ErrorData("Unverified", model.TypeAccountAuthType, &logutils.FieldArgs{"app_org_id": appOrg.ID, "auth_type": authType.Code, "identifier": identifier}).SetStatus(utils.ErrorStatusUnverified)
		}

		//3. update account permissions
		updatedAccount = account
		updated := false
		revoked := false

		added, removed, unchanged := utils.StringListDiff(permissions, account.GetAssignedPermissionNames())
		if len(added) > 0 || len(removed) > 0 {
			newPermissions := []model.Permission{}
			if len(added) > 0 {
				addedPermissions, err := a.CheckPermissions(context, []model.ApplicationOrganization{*appOrg}, added, updaterPermissions, false)
				if err != nil {
					return errors.WrapErrorAction(logutils.ActionGrant, model.TypePermission, nil, err)
				}
				newPermissions = append(newPermissions, addedPermissions...)
			}

			if len(removed) > 0 {
				_, err := a.CheckPermissions(context, []model.ApplicationOrganization{*appOrg}, removed, updaterPermissions, true)
				if err != nil {
					return errors.WrapErrorAction(logutils.ActionRevoke, model.TypePermission, nil, err)
				}
				revoked = true
			}

			if len(unchanged) > 0 {
				unchangedPermissions, err := a.storage.FindPermissionsByName(context, unchanged)
				if err != nil {
					return errors.WrapErrorAction(logutils.ActionFind, model.TypePermission, nil, err)
				}
				newPermissions = append(newPermissions, unchangedPermissions...)
			}

			err = a.storage.UpdateAccountPermissions(context, account.ID, appOrg.ID, newPermissions)
			if err != nil {
				return errors.WrapErrorAction(logutils.ActionUpdate, "admin account permissions", nil, err)
			}

			updatedAccount.Permissions = newPermissions
			updated = true
		}

		//4. update account roles
		added, removed, unchanged = utils.StringListDiff(roleIDs, account.GetAssignedRoleIDs())
		if len(added) > 0 || len(removed) > 0 {
			newRoles := []model.AppOrgRole{}
			if len(added) > 0 {
				addedRoles, err := a.CheckRoles(context, appOrg, added, updaterPermissions, false)
				if err != nil {
					return errors.WrapErrorAction(logutils.ActionGrant, model.TypeAccountRoles, nil, err)
				}
				newRoles = append(newRoles, addedRoles...)
			}

			if len(removed) > 0 {
				_, err := a.CheckRoles(context, appOrg, removed, updaterPermissions, true)
				if err != nil {
					return errors.WrapErrorAction(logutils.ActionRevoke, model.TypeAccountRoles, nil, err)
				}
				revoked = true
			}

			if len(unchanged) > 0 {
				unchangedRoles, err := a.storage.FindAppOrgRolesByIDs(context, unchanged, appOrg.ID)
				if err != nil {
					return errors.WrapErrorAction(logutils.ActionFind, model.TypeAccountRoles, nil, err)
				}
				newRoles = append(newRoles, unchangedRoles...)
			}

			newAccountRoles := model.AccountRolesFromAppOrgRoles(newRoles, true, true)
			err = a.storage.UpdateAccountRoles(context, account.ID, appOrg.ID, newAccountRoles)
			if err != nil {
				return errors.WrapErrorAction(logutils.ActionUpdate, "admin account roles", nil, err)
			}

			updatedAccount.Roles = newAccountRoles
			updated = true
		}

		//5. update account groups
		added, removed, unchanged = utils.StringListDiff(groupIDs, account.GetAssignedGroupIDs())
		if len(added) > 0 || len(removed) > 0 {
			newGroups := []model.AppOrgGroup{}
			if len(added) > 0 {
				addedGroups, err := a.CheckGroups(context, appOrg, added, updaterPermissions, false)
				if err != nil {
					return errors.WrapErrorAction(logutils.ActionGrant, model.TypeAccountGroups, nil, err)
				}
				newGroups = append(newGroups, addedGroups...)
			}

			if len(removed) > 0 {
				_, err := a.CheckGroups(context, appOrg, removed, updaterPermissions, true)
				if err != nil {
					return errors.WrapErrorAction(logutils.ActionRevoke, model.TypeAccountGroups, nil, err)
				}
				revoked = true
			}

			if len(unchanged) > 0 {
				unchangedGroups, err := a.storage.FindAppOrgGroupsByIDs(context, unchanged, appOrg.ID)
				if err != nil {
					return errors.WrapErrorAction(logutils.ActionFind, model.TypeAccountGroups, nil, err)
				}
				newGroups = append(newGroups, unchangedGroups...)
			}

			newAccountGroups := model.AccountGroupsFromAppOrgGroups(newGroups, true, true)
			err = a.storage.UpdateAccountGroups(context, account.ID, appOrg.ID, newAccountGroups)
			if err != nil {
				return errors.WrapErrorAction(logutils.ActionUpdate, "admin account groups", nil, err)
			}

			updatedAccount.Groups = newAccountGroups
			updated = true
		}

		//6. update account scopes
		if scopes != nil && utils.Contains(updaterPermissions, model.UpdateScopesPermission) && !utils.DeepEqual(account.Scopes, scopes) {
			for i, scope := range scopes {
				parsedScope, err := authorization.ScopeFromString(scope)
				if err != nil {
					return errors.WrapErrorAction(logutils.ActionValidate, model.TypeScope, nil, err)
				}
				if !strings.HasPrefix(parsedScope.Resource, model.AdminScopePrefix) {
					parsedScope.Resource = model.AdminScopePrefix + parsedScope.Resource
					scopes[i] = parsedScope.String()
				}
			}
			err = a.storage.UpdateAccountScopes(context, account.ID, scopes)
			if err != nil {
				return errors.WrapErrorAction(logutils.ActionUpdate, "admin account scopes", nil, err)
			}

			updatedAccount.Scopes = scopes
			updated = true
		}

		//7. delete active login sessions if anything was revoked
		if revoked {
			err = a.storage.DeleteLoginSessionsByIdentifier(context, account.ID)
			if err != nil {
				return errors.WrapErrorAction(logutils.ActionDelete, model.TypeLoginSession, nil, err)
			}
		}

		if updated {
			now := time.Now().UTC()
			updatedAccount.DateUpdated = &now
		}

		return nil
	}

	err = a.storage.PerformTransaction(transaction)
	if err != nil {
		return nil, nil, errors.WrapErrorAction(logutils.ActionUpdate, "admin account", nil, err)
	}

	return updatedAccount, params, nil
}

// CreateAnonymousAccount creates a new anonymous account
func (a *Auth) CreateAnonymousAccount(context storage.TransactionContext, appID string, orgID string, anonymousID string, preferences map[string]interface{},
	systemConfigs map[string]interface{}, skipExistsCheck bool, l *logs.Log) (*model.Account, error) {
	// check if the provided auth type is supported by the provided application and organization
	authType, appOrg, err := a.validateAuthTypeForAppOrg(AuthTypeAnonymous, appID, orgID)
	if err != nil || appOrg == nil {
		return nil, errors.WrapErrorAction(logutils.ActionValidate, model.TypeAuthType, nil, err)
	}

	// create account
	var newAccount *model.Account
	transaction := func(context storage.TransactionContext) error {
		//1. check if the user exists
		if context == nil || !skipExistsCheck {
			account, err := a.storage.FindAccountByIDV2(context, orgID, appID, anonymousID)
			if err != nil {
				return errors.WrapErrorAction(logutils.ActionFind, model.TypeAccount, nil, err)
			}
			if account != nil {
				return errors.ErrorData(logutils.StatusFound, model.TypeAccount, &logutils.FieldArgs{"app_org_id": appOrg.ID, "auth_type": authType.Code, "account_id": anonymousID})
			}
		}

		newAccount, err = a.applyCreateAnonymousAccount(context, *appOrg, anonymousID, preferences, systemConfigs, l)
		if err != nil {
			return errors.WrapErrorAction(logutils.ActionCreate, "anonymous account", &logutils.FieldArgs{"account_id": anonymousID}, err)
		}

		return nil
	}

	if context == nil {
		err = a.storage.PerformTransaction(transaction)
		if err != nil {
			return nil, errors.WrapErrorAction(logutils.ActionCreate, "anonymous account", nil, err)
		}
	} else {
		transaction(context)
	}

	return newAccount, nil
}

// VerifyCredential verifies credential (checks the verification code in the credentials collection)
func (a *Auth) VerifyCredential(id string, verification string, l *logs.Log) error {
	credential, err := a.storage.FindCredential(nil, id)
	if err != nil || credential == nil {
		return errors.WrapErrorAction(logutils.ActionFind, model.TypeCredential, nil, err)
	}

	if credential.Verified {
		return errors.ErrorAction(logutils.ActionVerify, model.TypeCredential, logutils.StringArgs("already verified"))
	}

	//get the auth type
	authType, err := a.storage.FindAuthType(credential.AuthType.ID)
	if err != nil || authType == nil {
		return errors.WrapErrorAction(logutils.ActionLoadCache, model.TypeAuthType, logutils.StringArgs(credential.AuthType.ID), err)
	}
	if !authType.UseCredentials {
		return errors.ErrorData(logutils.StatusInvalid, model.TypeAuthType, logutils.StringArgs("credential verification"))
	}

	authImpl, err := a.getAuthTypeImpl(*authType)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionLoadCache, model.TypeAuthType, nil, err)
	}

	authTypeCreds, err := authImpl.verifyCredential(credential, verification, l)
	if err != nil || authTypeCreds == nil {
		return errors.WrapErrorAction(logutils.ActionValidate, "verification code", nil, err)
	}

	credential.Verified = true
	credential.Value = authTypeCreds
	if err = a.storage.UpdateCredential(nil, credential); err != nil {
		return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeCredential, nil, err)
	}

	return nil
}

// UpdateCredential updates the credential object with the new value
//
//	Input:
//		accountID: id of the associated account to reset
//		accountAuthTypeID (string): id of the AccountAuthType
//		params: specific params for the different auth types
//	Returns:
//		error: if any
//
// TODO: Clear login sessions using old creds
// Handle refresh tokens when applicable
func (a *Auth) UpdateCredential(accountID string, accountAuthTypeID string, params string, l *logs.Log) error {
	//Get the user credential from account auth type in accounts collection
	account, err := a.storage.FindAccountByID(nil, accountID)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionFind, model.TypeAccount, nil, err)
	}
	accountAuthType, err := a.findAccountAuthTypeByID(account, accountAuthTypeID)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionFind, model.TypeAuthType, nil, err)
	}
	if accountAuthType.Credential == nil {
		return errors.ErrorData(logutils.StatusMissing, model.TypeCredential, logutils.StringArgs("reset password"))
	}

	credential := accountAuthType.Credential
	//Determine the auth type for resetPassword
	authType := accountAuthType.AuthType
	if !authType.UseCredentials {
		return errors.ErrorData(logutils.StatusInvalid, model.TypeAuthType, logutils.StringArgs("reset password"))
	}

	authImpl, err := a.getAuthTypeImpl(authType)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionLoadCache, model.TypeAuthType, nil, err)
	}

	authTypeCreds, err := authImpl.resetCredential(credential, nil, params, l)
	if err != nil || authTypeCreds == nil {
		return errors.WrapErrorAction(logutils.ActionValidate, "reset password", nil, err)
	}

	//Update the credential with new password
	credential.Value = authTypeCreds
	if err = a.storage.UpdateCredential(nil, credential); err != nil {
		return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeCredential, nil, err)
	}

	return nil
}

// ResetForgotCredential resets forgot credential
//
//	Input:
//		credsID: id of the credential object
//		resetCode: code from the reset link
//		params: specific params for the different auth types
//	Returns:
//		error: if any
//
// TODO: Clear login sessions using old creds
// Handle refresh tokens when applicable
func (a *Auth) ResetForgotCredential(credsID string, resetCode string, params string, l *logs.Log) error {
	credential, err := a.storage.FindCredential(nil, credsID)
	if err != nil || credential == nil {
		return errors.WrapErrorAction(logutils.ActionFind, model.TypeCredential, nil, err)
	}

	//Determine the auth type for resetPassword
	authType, err := a.storage.FindAuthType(credential.AuthType.ID)
	if err != nil || authType == nil {
		return errors.WrapErrorAction(logutils.ActionLoadCache, model.TypeAuthType, logutils.StringArgs(credential.AuthType.ID), err)
	}
	if !authType.UseCredentials {
		return errors.ErrorData(logutils.StatusInvalid, model.TypeAuthType, logutils.StringArgs("reset forgot credential"))
	}

	authImpl, err := a.getAuthTypeImpl(*authType)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionLoadCache, model.TypeAuthType, nil, err)
	}

	authTypeCreds, err := authImpl.resetCredential(credential, &resetCode, params, l)
	if err != nil || authTypeCreds == nil {
		return errors.WrapErrorAction(logutils.ActionValidate, model.TypeCredential, nil, err)
	}
	//Update the credential with new password
	credential.Value = authTypeCreds
	if err = a.storage.UpdateCredential(nil, credential); err != nil {
		return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeCredential, nil, err)
	}

	return nil
}

// ForgotCredential initiate forgot credential process (generates a reset link and sends to the given identifier for email auth type)
//
//	Input:
//		authenticationType (string): Name of the authentication method for provided creds (eg. "email", "username", "illinois_oidc")
//		identifier: identifier of the account auth type
//		appTypeIdentifier (string): Identifier of the app type/client that the user is logging in from
//		orgID (string): ID of the organization that the user is logging in
//		apiKey (string): API key to validate the specified app
//	Returns:
//		error: if any
func (a *Auth) ForgotCredential(authenticationType string, appTypeIdentifier string, orgID string, apiKey string, identifier string, l *logs.Log) error {
	//validate if the provided auth type is supported by the provided application and organization
	authType, _, appOrg, err := a.validateAuthType(authenticationType, appTypeIdentifier, orgID)
	if err != nil || authType == nil || appOrg == nil {
		return errors.WrapErrorAction(logutils.ActionValidate, model.TypeAuthType, nil, err)
	}

	//do not allow for admins
	if appOrg.Application.Admin {
		return errors.ErrorData(logutils.StatusDisabled, "admin credential reset", logutils.StringArgs("contact a system admin to reset credentials"))
	}

	//check for api key
	//TODO: Ideally we would not make many database calls before validating the API key. Currently needed to get app ID
	err = a.validateAPIKey(apiKey, appOrg.Application.ID)
	if err != nil {
		return errors.WrapErrorData(logutils.StatusInvalid, model.TypeAPIKey, nil, err)
	}

	//check if the auth types uses credentials
	if !authType.UseCredentials {
		return errors.ErrorData(logutils.StatusInvalid, model.TypeAuthType, logutils.StringArgs("credential reset"))
	}

	authImpl, err := a.getAuthTypeImpl(*authType)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionLoadCache, model.TypeAuthType, nil, err)
	}
	authTypeID := authType.ID

	//Find the credential for setting reset code and expiry and sending credID in reset link
	account, err := a.storage.FindAccount(nil, appOrg.ID, authTypeID, identifier)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionFind, model.TypeAccount, nil, err)
	}

	accountAuthType, err := a.findAccountAuthType(account, authType, identifier)
	if accountAuthType == nil {
		return errors.WrapErrorAction(logutils.ActionFind, model.TypeAccountAuthType, nil, err)
	}
	credential := accountAuthType.Credential
	if credential == nil {
		return errors.ErrorData(logutils.StatusMissing, model.TypeCredential, logutils.StringArgs("credential reset"))
	}
	a.setLogContext(account, l)

	//do not allow to reset credential for unverified credentials
	err = a.checkCredentialVerified(authImpl, accountAuthType, l)
	if err != nil {
		return err
	}

	authTypeCreds, err := authImpl.forgotCredential(credential, identifier, appOrg.Application.Name, l)
	if err != nil || authTypeCreds == nil {
		return errors.WrapErrorAction(logutils.ActionValidate, "forgot password", nil, err)
	}

	//Update the credential with reset code and expiry
	credential.Value = authTypeCreds
	if err = a.storage.UpdateCredential(nil, credential); err != nil {
		return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeCredential, nil, err)
	}
	return nil
}

// SendVerifyCredential sends the verification code to the identifier
func (a *Auth) SendVerifyCredential(authenticationType string, appTypeIdentifier string, orgID string, apiKey string, identifier string, l *logs.Log) error {
	//validate if the provided auth type is supported by the provided application and organization
	authType, _, appOrg, err := a.validateAuthType(authenticationType, appTypeIdentifier, orgID)
	if err != nil || authType == nil || appOrg == nil {
		return errors.WrapErrorAction(logutils.ActionValidate, model.TypeAuthType, nil, err)
	}
	//validate api key before making db calls
	err = a.validateAPIKey(apiKey, appOrg.Application.ID)
	if err != nil {
		return errors.WrapErrorData(logutils.StatusInvalid, model.TypeAPIKey, nil, err)
	}

	if !authType.UseCredentials {
		return errors.ErrorData(logutils.StatusInvalid, model.TypeAuthType, logutils.StringArgs("credential verification code"))
	}

	authImpl, err := a.getAuthTypeImpl(*authType)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionLoadCache, model.TypeAuthType, nil, err)
	}
	account, err := a.storage.FindAccount(nil, appOrg.ID, authType.ID, identifier)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionFind, model.TypeAccount, nil, err)
	}
	accountAuthType, err := a.findAccountAuthType(account, authType, identifier)
	if accountAuthType == nil {
		return errors.WrapErrorAction(logutils.ActionFind, model.TypeAccountAuthType, nil, err)
	}
	a.setLogContext(account, l)
	credential := accountAuthType.Credential
	if credential == nil {
		return errors.ErrorData(logutils.StatusMissing, model.TypeCredential, logutils.StringArgs("credential verification code"))
	}

	if credential.Verified {
		return errors.ErrorData(logutils.StatusInvalid, "credential verification status", &logutils.FieldArgs{"verified": true})
	}

	err = authImpl.sendVerifyCredential(credential, appOrg.Application.Name, l)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionSend, "verification code", nil, err)
	}

	return nil
}

// VerifyMFA verifies a code sent by a user as a final MFA enrollment step.
// The MFA type must be one of the supported for the application.
//
//	Input:
//		accountID (string): ID of account for which user is trying to verify MFA
//		identifier (string): Email, phone, or TOTP device name
//		mfaType (string): Type of MFA code sent
//		mfaCode (string): Code that must be verified
//	Returns:
//		Message (*string): message
//		Recovery codes ([]string): List of account recovery codes returned if enrolling in MFA for first time
func (a *Auth) VerifyMFA(accountID string, identifier string, mfaType string, mfaCode string) (*string, []string, error) {
	var recoveryMfa *model.MFAType
	var message *string
	transaction := func(context storage.TransactionContext) error {
		errFields := &logutils.FieldArgs{"account_id": accountID, "type": mfaType}
		//1. find mfa type in account
		mfa, err := a.storage.FindMFAType(context, accountID, identifier, mfaType)
		if err != nil {
			return errors.WrapErrorAction(logutils.ActionFind, model.TypeMFAType, errFields, err)
		}
		if mfa == nil {
			return errors.ErrorData(logutils.StatusMissing, model.TypeMFAType, errFields)
		}

		if mfa.Verified {
			return errors.ErrorData(logutils.StatusInvalid, model.TypeMFAType, &logutils.FieldArgs{"verified": true})
		}
		if mfa.Params == nil {
			return errors.ErrorData(logutils.StatusMissing, "mfa params", errFields)
		}

		//2. get mfa type implementation
		mfaImpl, err := a.getMfaTypeImpl(mfaType)
		if err != nil {
			return errors.WrapErrorAction(logutils.ActionLoadCache, model.TypeMFAType, nil, err)
		}
		message, err = mfaImpl.verify(context, mfa, accountID, mfaCode)
		if err != nil {
			return errors.WrapErrorAction(logutils.ActionValidate, model.TypeMFAType, errFields, err)
		}

		//3. update existing MFA type
		mfa.Verified = true
		err = a.storage.UpdateMFAType(context, mfa, accountID)
		if err != nil {
			return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeMFAType, &logutils.FieldArgs{"account_id": accountID, "id": mfa.ID}, err)
		}

		//4. find account
		account, err := a.storage.FindAccountByID(context, accountID)
		if err != nil {
			return errors.WrapErrorAction(logutils.ActionFind, model.TypeAccount, &logutils.FieldArgs{"id": accountID}, err)
		}

		//5. only mfa type just been verified, so enroll in recovery mfa automatically
		if len(account.MFATypes) == 1 {
			mfaImpl, err := a.getMfaTypeImpl(MfaTypeRecovery)
			if err != nil {
				return errors.WrapErrorAction(logutils.ActionLoadCache, model.TypeMFAType, nil, err)
			}
			recoveryMfa, err = mfaImpl.enroll(MfaTypeRecovery)
			if err != nil {
				return errors.WrapErrorAction(logutils.ActionValidate, model.TypeMFAType, &logutils.FieldArgs{"account_id": accountID, "type": MfaTypeRecovery}, err)
			}

			// insert recovery mfa type
			err = a.storage.InsertMFAType(context, recoveryMfa, accountID)
			if err != nil {
				return errors.WrapErrorAction(logutils.ActionInsert, model.TypeMFAType, &logutils.FieldArgs{"account_id": accountID, "type": MfaTypeRecovery}, err)
			}
		}

		return nil
	}

	err := a.storage.PerformTransaction(transaction)
	if err != nil {
		return message, nil, errors.WrapErrorAction(logutils.ActionVerify, model.TypeMFAType, nil, err)
	}

	if recoveryMfa != nil && recoveryMfa.Params != nil {
		recoveryCodes, ok := recoveryMfa.Params["codes"].([]string)
		if !ok {
			return nil, nil, errors.ErrorAction(logutils.ActionCast, "recovery codes", nil)
		}

		return nil, recoveryCodes, nil
	}

	return nil, nil, nil
}

// GetMFATypes gets all MFA types set up for an account
//
//	Input:
//		accountID (string): Account ID to find MFA types
//	Returns:
//		MFA Types ([]model.MFAType): MFA information for all enrolled types
func (a *Auth) GetMFATypes(accountID string) ([]model.MFAType, error) {
	mfa, err := a.storage.FindMFATypes(accountID)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeMFAType, nil, err)
	}

	return mfa, nil
}

// AddMFAType adds a form of MFA to an account
//
//	Input:
//		accountID (string): Account ID to add MFA
//		identifier (string): Email, phone, or TOTP device name
//		mfaType (string): Type of MFA to be added
//	Returns:
//		MFA Type (*model.MFAType): MFA information for the specified type
func (a *Auth) AddMFAType(accountID string, identifier string, mfaType string) (*model.MFAType, error) {
	mfaImpl, err := a.getMfaTypeImpl(mfaType)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionLoadCache, model.TypeMFAType, nil, err)
	}

	newMfa, err := mfaImpl.enroll(identifier)
	if err != nil {
		return nil, errors.WrapErrorAction("enrolling", model.TypeMFAType, nil, err)
	}

	err = a.storage.InsertMFAType(nil, newMfa, accountID)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionInsert, model.TypeMFAType, &logutils.FieldArgs{"account_id": accountID, "type": mfaType}, err)
	}

	return newMfa, nil
}

// RemoveMFAType removes a form of MFA from an account
//
//	Input:
//		accountID (string): Account ID to remove MFA
//		identifier (string): Email, phone, or TOTP device name
//		mfaType (string): Type of MFA to remove
func (a *Auth) RemoveMFAType(accountID string, identifier string, mfaType string) error {
	transaction := func(context storage.TransactionContext) error {
		//1. remove mfa type from account
		err := a.storage.DeleteMFAType(context, accountID, identifier, mfaType)
		if err != nil {
			return errors.WrapErrorAction(logutils.ActionDelete, model.TypeMFAType, &logutils.FieldArgs{"account_id": accountID, "identifier": identifier, "type": mfaType}, err)
		}

		//2. find account
		account, err := a.storage.FindAccountByID(context, accountID)
		if err != nil {
			return errors.WrapErrorAction(logutils.ActionFind, model.TypeAccount, nil, err)
		}
		if account == nil {
			return errors.ErrorData(logutils.StatusMissing, model.TypeAccount, &logutils.FieldArgs{"id": accountID})
		}

		//3. check if account only has recovery MFA remaining
		if len(account.MFATypes) == 1 && account.MFATypes[0].Type == MfaTypeRecovery {
			err = a.storage.DeleteMFAType(context, accountID, MfaTypeRecovery, MfaTypeRecovery)
			if err != nil {
				return errors.WrapErrorAction(logutils.ActionDelete, model.TypeMFAType, &logutils.FieldArgs{"account_id": accountID, "identifier": MfaTypeRecovery, "type": MfaTypeRecovery}, err)
			}
		}

		return nil
	}

	err := a.storage.PerformTransaction(transaction)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionDelete, model.TypeMFAType, nil, err)
	}

	return nil
}

// GetServiceAccountParams returns a list of app, org pairs a service account has access to
func (a *Auth) GetServiceAccountParams(accountID string, firstParty bool, r *sigauth.Request, l *logs.Log) ([]model.AppOrgPair, error) {
	accounts, _, err := a.checkServiceAccountCreds(r, &accountID, firstParty, false, l)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionValidate, model.TypeServiceAccountCredential, nil, err)
	}

	appOrgPairs := make([]model.AppOrgPair, len(accounts))
	for i, account := range accounts {
		appID := authutils.AllApps
		if account.Application != nil {
			appID = account.Application.ID
		}
		orgID := authutils.AllOrgs
		if account.Organization != nil {
			orgID = account.Organization.ID
		}
		appOrgPairs[i] = model.AppOrgPair{AppID: appID, OrgID: orgID}
	}

	return appOrgPairs, nil
}

// GetServiceAccessToken returns an access token for a non-human client
func (a *Auth) GetServiceAccessToken(firstParty bool, r *sigauth.Request, l *logs.Log) (string, error) {
	accounts, authType, err := a.checkServiceAccountCreds(r, nil, firstParty, true, l)
	if err != nil {
		return "", errors.WrapErrorAction(logutils.ActionValidate, model.TypeServiceAccountCredential, nil, err)
	}

	accessToken, _, err := a.buildAccessTokenForServiceAccount(accounts[0], authType)
	if err != nil {
		return "", err
	}

	return accessToken, nil
}

// GetAllServiceAccessTokens returns an access token for each app, org pair a service account has access to
func (a *Auth) GetAllServiceAccessTokens(firstParty bool, r *sigauth.Request, l *logs.Log) (map[model.AppOrgPair]string, error) {
	accounts, authType, err := a.checkServiceAccountCreds(r, nil, firstParty, false, l)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionValidate, model.TypeServiceAccountCredential, nil, err)
	}

	accessTokens := make(map[model.AppOrgPair]string, len(accounts))
	for _, account := range accounts {
		accessToken, appOrgPair, err := a.buildAccessTokenForServiceAccount(account, authType)
		if err != nil {
			return nil, err
		}

		accessTokens[*appOrgPair] = accessToken
	}

	return accessTokens, nil
}

// GetServiceAccounts gets all service accounts matching a search
func (a *Auth) GetServiceAccounts(params map[string]interface{}) ([]model.ServiceAccount, error) {
	serviceAccounts, err := a.storage.FindServiceAccounts(params)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeServiceAccount, nil, err)
	}

	return serviceAccounts, nil
}

// RegisterServiceAccount registers a service account
func (a *Auth) RegisterServiceAccount(accountID *string, fromAppID *string, fromOrgID *string, name *string, appID string, orgID string, permissions *[]string,
	scopes []authorization.Scope, firstParty *bool, creds []model.ServiceAccountCredential, assignerPermissions []string, l *logs.Log) (*model.ServiceAccount, error) {
	var newAccount *model.ServiceAccount
	var err error
	var newName string
	var permissionList []string
	var displayParamsList []map[string]interface{}

	if name != nil {
		newName = *name
	}
	if permissions != nil {
		permissionList = *permissions
	}

	if accountID != nil && fromAppID != nil && fromOrgID != nil {
		var fromAccount *model.ServiceAccount
		fromAccount, err = a.storage.FindServiceAccount(nil, *accountID, *fromAppID, *fromOrgID)
		if err != nil {
			return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeServiceAccount, nil, err)
		}

		if newName == "" {
			newName = fromAccount.Name
		}
		if permissionList == nil {
			permissionList = fromAccount.GetPermissionNames()
		}
		if scopes == nil {
			scopes = fromAccount.Scopes
		}

		newAccount, err = a.constructServiceAccount(fromAccount.AccountID, newName, appID, orgID, permissionList, scopes, fromAccount.FirstParty, assignerPermissions)
		if err != nil {
			return nil, errors.WrapErrorAction(logutils.ActionCreate, model.TypeServiceAccount, nil, err)
		}
		newAccount.Credentials = fromAccount.Credentials
	} else {
		if firstParty == nil {
			return nil, errors.ErrorData(logutils.StatusMissing, logutils.TypeArg, logutils.StringArgs("first party"))
		}

		newAccount, err = a.constructServiceAccount(uuid.NewString(), newName, appID, orgID, permissionList, scopes, *firstParty, assignerPermissions)
		if err != nil {
			return nil, errors.WrapErrorAction(logutils.ActionCreate, model.TypeServiceAccount, nil, err)
		}

		newAccount.Credentials = make([]model.ServiceAccountCredential, 0)
		displayParamsList = make([]map[string]interface{}, 0)
		for _, cred := range creds {
			serviceAuthType, err := a.getServiceAuthTypeImpl(cred.Type)
			if err != nil {
				l.Infof("error getting service auth type on register service account: %s", err.Error())
				continue
			}

			displayParams, err := serviceAuthType.addCredentials(&cred)
			if err != nil {
				l.Warnf("error adding %s credential on register service account: %s", cred.Type, err.Error())
				continue
			}

			newAccount.Credentials = append(newAccount.Credentials, cred)
			displayParamsList = append(displayParamsList, displayParams)
		}
	}

	newAccount.DateCreated = time.Now().UTC()
	err = a.storage.InsertServiceAccount(newAccount)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionInsert, model.TypeServiceAccount, nil, err)
	}

	for i, params := range displayParamsList {
		newAccount.Credentials[i].Params = params
	}

	return newAccount, nil
}

// DeregisterServiceAccount deregisters a service account
func (a *Auth) DeregisterServiceAccount(accountID string) error {
	// delete all service account instances matching accountID
	err := a.storage.DeleteServiceAccounts(accountID)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionDelete, model.TypeServiceAccount, nil, err)
	}

	return nil
}

// GetServiceAccountInstance gets a service account instance
func (a *Auth) GetServiceAccountInstance(accountID string, appID string, orgID string) (*model.ServiceAccount, error) {
	serviceAccount, err := a.storage.FindServiceAccount(nil, accountID, appID, orgID)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeServiceAccount, nil, err)
	}

	return serviceAccount, nil
}

// UpdateServiceAccountInstance updates a service account instance
func (a *Auth) UpdateServiceAccountInstance(id string, appID string, orgID string, name *string, permissions *[]string, scopes []authorization.Scope, assignerPermissions []string) (*model.ServiceAccount, error) {
	var updatedAccount *model.ServiceAccount
	transaction := func(context storage.TransactionContext) error {
		//1. find service account
		serviceAccount, err := a.storage.FindServiceAccount(context, id, appID, orgID)
		if err != nil {
			return errors.WrapErrorAction(logutils.ActionFind, model.TypeServiceAccount, nil, err)
		}
		updatedAccount = serviceAccount

		//2. find app orgs
		var appIDParam *string
		if appID != authutils.AllApps {
			appIDParam = &appID
		}
		var orgIDParam *string
		if orgID != authutils.AllOrgs {
			orgIDParam = &orgID
		}
		appOrgs, err := a.storage.FindApplicationOrganizations(appIDParam, orgIDParam)
		if err != nil {
			return errors.WrapErrorAction(logutils.ActionFind, model.TypeApplicationOrganization, nil, err)
		}
		if len(appOrgs) == 0 {
			return errors.ErrorData(logutils.StatusMissing, model.TypeApplicationOrganization, &logutils.FieldArgs{"app_id": appID, "org_id": orgID})
		}

		//3. check for updates, update as needed
		updated := false
		if name != nil && serviceAccount.Name != *name {
			serviceAccount.Name = *name
			updated = true
		}
		if permissions != nil {
			updatedPermissions := make([]model.Permission, 0)
			added, removed, unchanged := utils.StringListDiff(*permissions, serviceAccount.GetPermissionNames())
			if len(added) > 0 {
				permissionList, err := a.CheckPermissions(context, appOrgs, *permissions, assignerPermissions, false)
				if err != nil {
					return errors.WrapErrorAction(logutils.ActionValidate, model.TypePermission, nil, err)
				}

				updatedPermissions = append(updatedPermissions, permissionList...)
				updated = true
			}
			if len(removed) > 0 {
				_, err := a.CheckPermissions(context, appOrgs, *permissions, assignerPermissions, true)
				if err != nil {
					return errors.WrapErrorAction(logutils.ActionRevoke, model.TypePermission, nil, err)
				}

				updated = true
			}
			if len(unchanged) > 0 {
				permissionList, err := a.storage.FindPermissionsByName(context, unchanged)
				if err != nil {
					return errors.WrapErrorAction(logutils.ActionFind, model.TypePermission, nil, err)
				}

				updatedPermissions = append(updatedPermissions, permissionList...)
			}

			serviceAccount.Permissions = updatedPermissions
		}
		if !utils.DeepEqual(serviceAccount.Scopes, scopes) {
			serviceAccount.Scopes = scopes
			updated = true
		}

		//4. update service account in database
		if updated {
			updatedAccount, err = a.storage.UpdateServiceAccount(context, serviceAccount)
			if err != nil {
				return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeServiceAccount, nil, err)
			}
		}

		return nil
	}

	err := a.storage.PerformTransaction(transaction)
	if err != nil {
		return nil, err
	}

	return updatedAccount, nil
}

// DeregisterServiceAccountInstance deregisters a service account instance
func (a *Auth) DeregisterServiceAccountInstance(id string, appID string, orgID string) error {
	err := a.storage.DeleteServiceAccount(id, appID, orgID)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionDelete, model.TypeServiceAccount, nil, err)
	}

	return nil
}

// AddServiceAccountCredential adds a credential to a service account
func (a *Auth) AddServiceAccountCredential(accountID string, creds *model.ServiceAccountCredential, l *logs.Log) (*model.ServiceAccountCredential, error) {
	if creds == nil {
		return nil, errors.ErrorData(logutils.StatusMissing, model.TypeServiceAccountCredential, nil)
	}

	serviceAuthType, err := a.getServiceAuthTypeImpl(creds.Type)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionGet, typeServiceAuthType, nil, err)
	}

	displayParams, err := serviceAuthType.addCredentials(creds)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionInsert, model.TypeServiceAccountCredential, nil, err)
	}

	err = a.storage.InsertServiceAccountCredential(accountID, creds)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionInsert, model.TypeServiceAccountCredential, nil, err)
	}

	creds.Params = displayParams
	return creds, nil
}

// RemoveServiceAccountCredential removes a credential from a service account
func (a *Auth) RemoveServiceAccountCredential(accountID string, credID string) error {
	err := a.storage.DeleteServiceAccountCredential(accountID, credID)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionDelete, model.TypeServiceAccountCredential, nil, err)
	}

	return nil
}

// AuthorizeService returns a scoped token for the specified service and the service registration record if authorized or
//
//	the service registration record if not. Passing "approvedScopes" will update the service authorization for this user and
//	return a scoped access token which reflects this change.
//	Input:
//		claims (tokenauth.Claims): Claims from un-scoped user access token
//		serviceID (string): ID of the service to be authorized
//		approvedScopes ([]string): list of scope strings to be approved
//		l (*logs.Log): Log object pointer for request
//	Returns:
//		Access token (string): Signed scoped access token to be used to authorize requests to the specified service
//		Approved Scopes ([]authorization.Scope): The approved scopes included in the provided token
//		Service reg (*model.ServiceReg): The service registration record for the requested service
func (a *Auth) AuthorizeService(claims tokenauth.Claims, serviceID string, approvedScopes []authorization.Scope, l *logs.Log) (string, []authorization.Scope, *model.ServiceRegistration, error) {
	var serviceAuth model.ServiceAuthorization
	if approvedScopes != nil {
		//Prevent user from setting admin scopes
		var newScopes []authorization.Scope
		for _, scope := range approvedScopes {
			if !strings.HasPrefix(scope.Resource, model.AdminScopePrefix) {
				newScopes = append(newScopes, scope)
			}
		}

		//If approved scopes are being updated, save update and return token with updated scopes
		serviceAuth = model.ServiceAuthorization{UserID: claims.Subject, ServiceID: serviceID, Scopes: newScopes}
		err := a.storage.SaveServiceAuthorization(&serviceAuth)
		if err != nil {
			return "", nil, nil, errors.WrapErrorAction(logutils.ActionSave, model.TypeServiceAuthorization, nil, err)
		}
	} else {
		curServiceAuth, err := a.storage.FindServiceAuthorization(claims.Subject, serviceID)
		if err != nil {
			return "", nil, nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeServiceAuthorization, nil, err)
		}

		if curServiceAuth != nil {
			//If service authorization exists, generate token with saved scopes
			serviceAuth = *curServiceAuth
		} else {
			//If no service authorization exists, return the service registration record
			reg, err := a.storage.FindServiceReg(serviceID)
			if err != nil {
				return "", nil, nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeServiceReg, nil, err)
			}
			return "", nil, reg, nil
		}
	}

	token, err := a.getScopedAccessToken(claims, serviceID, serviceAuth.Scopes)
	if err != nil {
		return "", nil, nil, errors.WrapErrorAction("building", logutils.TypeToken, nil, err)
	}

	return token, serviceAuth.Scopes, nil, nil
}

// GetAdminToken returns an admin token for the specified application and organization
func (a *Auth) GetAdminToken(claims tokenauth.Claims, appID string, orgID string, l *logs.Log) (string, error) {
	//verify that the provided appID is valid for the organization
	appOrg, err := a.storage.FindApplicationOrganization(appID, orgID)
	if err != nil {
		return "", errors.WrapErrorAction(logutils.ActionFind, model.TypeApplicationOrganization, &logutils.FieldArgs{"org_id": orgID, "app_id": appID}, err)
	}
	if appOrg == nil {
		return "", errors.ErrorData(logutils.StatusMissing, model.TypeApplicationOrganization, &logutils.FieldArgs{"org_id": orgID, "app_id": appID})
	}

	adminClaims := a.getStandardClaims(claims.Subject, claims.UID, claims.Name, claims.Email, claims.Phone, claims.Audience, orgID, appID, claims.AuthType,
		claims.ExternalIDs, &claims.ExpiresAt, false, false, true, claims.System, claims.Service, claims.FirstParty, claims.SessionID)
	return a.buildAccessToken(adminClaims, claims.Permissions, claims.Scope)
}

// LinkAccountAuthType links new credentials to an existing account.
// The authentication method must be one of the supported for the application.
//
//	Input:
//		orgID (string): Org id
//		appID (string): App id
//		accountID (string): ID of the account to link the creds to
//		authenticationType (string): Name of the authentication method for provided creds (eg. "email", "username", "illinois_oidc")
//		appTypeIdentifier (string): identifier of the app type/client that the user is logging in from
//		creds (string): Credentials/JSON encoded credential structure defined for the specified auth type
//		params (string): JSON encoded params defined by specified auth type
//		l (*logs.Log): Log object pointer for request
//	Returns:
//		message (*string): response message
//		account (*model.Account): account data after the operation
func (a *Auth) LinkAccountAuthType(orgID string, appID string, accountID string, authenticationType string, appTypeIdentifier string, creds string, params string, l *logs.Log) (*string, *model.Account, error) {
	message := ""
	var newAccountAuthType *model.AccountAuthType

	account, err := a.storage.FindAccountByIDV2(nil, orgID, appID, accountID)
	if err != nil {
		return nil, nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeAccount, nil, err)
	}
	if account == nil {
		return nil, nil, errors.ErrorData(logutils.StatusMissing, model.TypeAccount, &logutils.FieldArgs{"id": accountID})
	}

	//validate if the provided auth type is supported by the provided application and organization
	authType, appType, appOrg, err := a.validateAuthType(authenticationType, appTypeIdentifier, account.AppOrg.Organization.ID)
	if err != nil || authType == nil || appType == nil || appOrg == nil {
		return nil, nil, errors.WrapErrorAction(logutils.ActionValidate, model.TypeAuthType, nil, err)
	}

	if authType.IsAnonymous {
		return nil, nil, errors.ErrorData(logutils.StatusInvalid, model.TypeAuthType, &logutils.FieldArgs{"anonymous": true})
	} else if authType.IsExternal {
		newAccountAuthType, err = a.linkAccountAuthTypeExternal(*account, *authType, *appType, *appOrg, creds, params, l)
		if err != nil {
			return nil, nil, errors.WrapErrorAction("linking", model.TypeCredential, nil, err)
		}
	} else {
		message, newAccountAuthType, err = a.linkAccountAuthType(*account, *authType, *appOrg, creds, params, l)
		if err != nil {
			return nil, nil, errors.WrapErrorAction("linking", model.TypeCredential, nil, err)
		}
	}

	if newAccountAuthType != nil {
		account.AuthTypes = append(account.AuthTypes, *newAccountAuthType)
	}

	return &message, account, nil
}

// UnlinkAccountAuthType unlinks credentials from an existing account.
// The authentication method must be one of the supported for the application.
//
//	Input:
//		accountID (string): ID of the account to unlink creds from
//		authenticationType (string): Name of the authentication method of account auth type to unlink
//		appTypeIdentifier (string): Identifier of the app type/client that the user is logging in from
//		identifier (string): Identifier of account auth type to unlink
//		l (*logs.Log): Log object pointer for request
//	Returns:
//		account (*model.Account): account data after the operation
func (a *Auth) UnlinkAccountAuthType(accountID string, authenticationType string, appTypeIdentifier string, identifier string, l *logs.Log) (*model.Account, error) {
	return a.unlinkAccountAuthType(accountID, authenticationType, appTypeIdentifier, identifier, l)
}

// DeleteAccount deletes an account for the given id
func (a *Auth) DeleteAccount(id string, apps []string) error {
	transaction := func(context storage.TransactionContext) error {
		//1. first find the account record
		account, err := a.storage.FindAccountByID(context, id)
		if err != nil {
			return errors.WrapErrorAction(logutils.ActionFind, model.TypeAccount, nil, err)
		}
		if account == nil {
			return errors.ErrorData(logutils.StatusMissing, model.TypeAccount, nil)
		}

		err = a.deleteAccount(context, *account, apps)
		if err != nil {
			return errors.WrapErrorAction(logutils.ActionDelete, model.TypeAccount, nil, err)
		}

		return nil
	}

	return a.storage.PerformTransaction(transaction)
}

// InitializeSystemAccount initializes the first system account
func (a *Auth) InitializeSystemAccount(context storage.TransactionContext, authType model.AuthType, appOrg model.ApplicationOrganization,
	allSystemPermission string, email string, password string, clientVersion string, l *logs.Log) (string, error) {
	//auth type
	authImpl, err := a.getAuthTypeImpl(authType)
	if err != nil {
		return "", errors.WrapErrorAction(logutils.ActionLoadCache, model.TypeAuthType, nil, err)
	}

	now := time.Now()
	profile := model.Profile{ID: uuid.NewString(), Email: email, DateCreated: now}
	privacy := model.Privacy{Public: false}
	permissions := []string{allSystemPermission}

	_, accountAuthType, err := a.applySignUpAdmin(context, authImpl, nil, authType, appOrg, email, password, profile, privacy, "", permissions, nil, nil, nil, permissions, &clientVersion, l)
	if err != nil {
		return "", errors.WrapErrorAction(logutils.ActionRegister, "initial system user", &logutils.FieldArgs{"email": email}, err)
	}

	return accountAuthType.Account.ID, nil
}

/*
// GrantAccountPermissions grants new permissions to an account after validating the assigner has required permissions
func (a *Auth) GrantAccountPermissions(context storage.TransactionContext, account *model.Account, permissionNames []string, assignerPermissions []string) error {
	//check if there is data
	if account == nil {
		return errors.ErrorData(logutils.StatusMissing, model.TypeAccount, nil)
	}

	//verify that the account do not have any of the permissions which are supposed to be granted
	newPermissions := make([]string, 0)
	for _, current := range permissionNames {
		if account.GetPermissionNamed(current) == nil {
			newPermissions = append(newPermissions, current)
		}
	}
	//no error if no zero new permissions are being granted
	if len(newPermissions) == 0 {
		return nil
	}

	//check permissions
	permissions, err := a.CheckPermissions(context, []model.ApplicationOrganization{account.AppOrg}, newPermissions, assignerPermissions, false)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionValidate, model.TypePermission, nil, err)
	}

	//update account if authorized
	err = a.storage.InsertAccountPermissions(context, account.ID, permissions)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionInsert, model.TypeAccountPermissions, &logutils.FieldArgs{"account_id": account.ID}, err)
	}

	account.Permissions = append(account.Permissions, permissions...)
	return nil
} */

// CheckPermissions loads permissions by names from storage and checks that they are assignable and valid for the given appOrgs or revocable
func (a *Auth) CheckPermissions(context storage.TransactionContext, appOrgs []model.ApplicationOrganization, permissionNames []string, assignerPermissions []string, revoke bool) ([]model.Permission, error) {
	if len(appOrgs) == 0 {
		return nil, errors.ErrorData(logutils.StatusMissing, model.TypeApplicationOrganization, nil)
	}

	serviceIDs := make([]string, 0)
	for _, appOrg := range appOrgs {
		serviceIDs = append(serviceIDs, appOrg.ServicesIDs...)
	}

	//find permissions
	permissions, err := a.storage.FindPermissionsByName(context, permissionNames)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypePermission, nil, err)
	}
	//Allow revocation of missing permissions
	if len(permissions) != len(permissionNames) && !revoke {
		badNames := make([]string, 0)
		for _, pName := range permissionNames {
			bad := true
			for _, p := range permissions {
				if p.Name == pName {
					bad = false
					break
				}
			}
			if bad {
				badNames = append(badNames, pName)
			}
		}
		return nil, errors.ErrorData(logutils.StatusInvalid, model.TypePermission, &logutils.FieldArgs{"names": badNames})
	}

	//check if authorized
	for _, permission := range permissions {
		if !utils.Contains(serviceIDs, permission.ServiceID) {
			//Allow revocation of permissions for invalid services
			if revoke {
				continue
			}
			return nil, errors.ErrorData(logutils.StatusInvalid, model.TypePermission, &logutils.FieldArgs{"name": permission.Name, "service_id": permission.ServiceID})
		}
		err = permission.CheckAssigners(assignerPermissions)
		if err != nil {
			return nil, errors.WrapErrorAction(logutils.ActionValidate, "assigner permissions", &logutils.FieldArgs{"name": permission.Name}, err)
		}
	}

	return permissions, nil
}

// GrantAccountRoles grants new roles to an account after validating the assigner has required permissions
func (a *Auth) GrantAccountRoles(context storage.TransactionContext, account *model.Account, roleIDs []string, assignerPermissions []string) error {
	//check if there is data
	if account == nil {
		return errors.ErrorData(logutils.StatusMissing, model.TypeAccount, nil)
	}

	//verify that the account do not have any of the roles which are supposed to be granted
	newRoles := make([]string, 0)
	for _, current := range roleIDs {
		if account.GetRole(current) == nil {
			newRoles = append(newRoles, current)
		}
	}
	//no error if no zero new roles are being granted
	if len(newRoles) == 0 {
		return nil
	}

	//check roles
	roles, err := a.CheckRoles(context, &account.AppOrg, newRoles, assignerPermissions, false)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionValidate, model.TypeAppOrgRole, nil, err)
	}

	//update account if authorized
	accountRoles := model.AccountRolesFromAppOrgRoles(roles, true, true)
	err = a.storage.InsertAccountRoles(context, account.ID, account.AppOrg.ID, accountRoles)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionInsert, model.TypeAccountRoles, &logutils.FieldArgs{"account_id": account.ID}, err)
	}

	account.Roles = append(account.Roles, accountRoles...)
	return nil
}

// CheckRoles loads appOrg roles by IDs from storage and checks that they are assignable or revocable
func (a *Auth) CheckRoles(context storage.TransactionContext, appOrg *model.ApplicationOrganization, roleIDs []string, assignerPermissions []string, revoke bool) ([]model.AppOrgRole, error) {
	if appOrg == nil {
		return nil, errors.ErrorData(logutils.StatusInvalid, model.TypeApplicationOrganization, nil)
	}

	//find roles
	roles, err := a.storage.FindAppOrgRolesByIDs(context, roleIDs, appOrg.ID)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeAppOrgRole, nil, err)
	}
	if len(roles) != len(roleIDs) && !revoke {
		badIDs := make([]string, 0)
		for _, rID := range roleIDs {
			bad := true
			for _, r := range roles {
				if r.ID == rID {
					bad = false
					break
				}
			}
			if bad {
				badIDs = append(badIDs, rID)
			}
		}
		return nil, errors.ErrorData(logutils.StatusInvalid, model.TypeAppOrgRole, &logutils.FieldArgs{"ids": badIDs})
	}

	//check if authorized
	for _, cRole := range roles {
		err = cRole.CheckAssigners(assignerPermissions)
		if err != nil {
			return nil, errors.WrapErrorAction(logutils.ActionValidate, "assigner permissions", &logutils.FieldArgs{"id": cRole.ID}, err)
		}
	}

	return roles, nil
}

// GrantAccountGroups grants new groups to an account after validating the assigner has required permissions
func (a *Auth) GrantAccountGroups(context storage.TransactionContext, account *model.Account, groupIDs []string, assignerPermissions []string) error {
	//check if there is data
	if account == nil {
		return errors.ErrorData(logutils.StatusMissing, model.TypeAccount, nil)
	}

	//ensure that the account does not have the groups before adding
	newGroups := make([]string, 0)
	for _, current := range groupIDs {
		if account.GetGroup(current) == nil {
			newGroups = append(newGroups, current)
		}
	}
	//no error if no zero new groups are being granted
	if len(newGroups) == 0 {
		return nil
	}

	//check groups
	groups, err := a.CheckGroups(context, &account.AppOrg, newGroups, assignerPermissions, false)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionValidate, model.TypeAppOrgGroup, nil, err)
	}

	//update account if authorized
	accountGroups := model.AccountGroupsFromAppOrgGroups(groups, true, true)
	err = a.storage.InsertAccountGroups(context, account.ID, account.AppOrg.ID, accountGroups)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionInsert, model.TypeAccountGroups, &logutils.FieldArgs{"account_id": account.ID}, err)
	}

	account.Groups = append(account.Groups, accountGroups...)
	return nil
}

// CheckGroups loads appOrg groups by IDs from storage and checks that they are assignable or revocable
func (a *Auth) CheckGroups(context storage.TransactionContext, appOrg *model.ApplicationOrganization, groupIDs []string, assignerPermissions []string, revoke bool) ([]model.AppOrgGroup, error) {
	if appOrg == nil {
		return nil, errors.ErrorData(logutils.StatusInvalid, model.TypeApplicationOrganization, nil)
	}

	//find groups
	groups, err := a.storage.FindAppOrgGroupsByIDs(context, groupIDs, appOrg.ID)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeAppOrgGroup, nil, err)
	}
	if len(groups) != len(groupIDs) && !revoke {
		badIDs := make([]string, 0)
		for _, gID := range groupIDs {
			bad := true
			for _, g := range groups {
				if g.ID == gID {
					bad = false
					break
				}
			}
			if bad {
				badIDs = append(badIDs, gID)
			}
		}
		return nil, errors.ErrorData(logutils.StatusInvalid, model.TypeAppOrgGroup, &logutils.FieldArgs{"ids": badIDs})
	}

	//check assigners
	for _, group := range groups {
		err = group.CheckAssigners(assignerPermissions)
		if err != nil {
			return nil, errors.WrapErrorAction(logutils.ActionValidate, "assigner permissions", &logutils.FieldArgs{"id": group.ID}, err)
		}
	}

	return groups, nil
}

// GetServiceRegistrations retrieves all service registrations
func (a *Auth) GetServiceRegistrations(serviceIDs []string) []model.ServiceRegistration {
	return a.storage.FindServiceRegs(serviceIDs)
}

// RegisterService creates a new service registration
func (a *Auth) RegisterService(reg *model.ServiceRegistration) error {
	if reg != nil && !reg.FirstParty && strings.Contains(strings.ToUpper(reg.Name), rokwireKeyword) {
		return errors.ErrorData(logutils.StatusInvalid, "third-party service name", logutils.StringArgs(fmt.Sprintf("may not contain \"%s\"", rokwireKeyword)))
	}
	return a.storage.InsertServiceReg(reg)
}

// UpdateServiceRegistration updates an existing service registration
func (a *Auth) UpdateServiceRegistration(reg *model.ServiceRegistration) error {
	if reg != nil {
		if reg.Registration.ServiceID == authServiceID || reg.Registration.ServiceID == a.serviceID {
			return errors.ErrorAction(logutils.ActionUpdate, model.TypeServiceReg, logutils.StringArgs(reg.Registration.ServiceID)).SetStatus(utils.ErrorStatusNotAllowed)
		}
		if !reg.FirstParty && strings.Contains(strings.ToUpper(reg.Name), rokwireKeyword) {
			return errors.ErrorData(logutils.StatusInvalid, "third-party service name", logutils.StringArgs(fmt.Sprintf("may not contain \"%s\"", rokwireKeyword)))
		}
	}
	return a.storage.UpdateServiceReg(reg)
}

// DeregisterService deletes an existing service registration
func (a *Auth) DeregisterService(serviceID string) error {
	if serviceID == authServiceID || serviceID == a.serviceID {
		return errors.ErrorAction(logutils.ActionDeregister, model.TypeServiceReg, logutils.StringArgs(serviceID))
	}
	return a.storage.DeleteServiceReg(serviceID)
}

// GetAuthKeySet generates a JSON Web Key Set for auth service registration
func (a *Auth) GetAuthKeySet() (jwk.Set, error) {
	authReg, err := a.ServiceRegManager.GetServiceReg("auth")
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionLoadCache, model.TypeServiceReg, logutils.StringArgs("auth"), err)
	}

	if authReg == nil || authReg.PubKey == nil || authReg.PubKey.Key == nil {
		return nil, errors.ErrorData(logutils.StatusMissing, model.TypePubKey, nil)
	}

	webKey, err := jwk.New(authReg.PubKey.Key)
	if err != nil || webKey == nil {
		return nil, errors.WrapErrorAction(logutils.ActionCreate, model.TypeJSONWebKey, nil, err)
	}
	err = webKey.Set(jwk.KeyUsageKey, "sig")
	if err != nil {
		return nil, errors.WrapErrorAction("setting", model.TypeJSONWebKey+" "+jwk.KeyUsageKey, logutils.StringArgs("sig"), err)
	}
	err = webKey.Set(jwk.KeyIDKey, authReg.PubKey.KeyID)
	if err != nil {
		return nil, errors.WrapErrorAction("setting", model.TypeJSONWebKey+" "+jwk.KeyIDKey, logutils.StringArgs(authReg.PubKey.KeyID), err)
	}
	err = webKey.Set(jwk.AlgorithmKey, authReg.PubKey.Alg)
	if err != nil {
		return nil, errors.WrapErrorAction("setting", model.TypeJSONWebKey+" "+jwk.AlgorithmKey, logutils.StringArgs(authReg.PubKey.Alg), err)
	}

	keySet := jwk.NewSet()
	keySet.Add(webKey)
	return keySet, nil
}

// GetApplicationAPIKeys finds and returns the API keys for the provided app
func (a *Auth) GetApplicationAPIKeys(appID string) ([]model.APIKey, error) {
	cachedAPIKeys, err := a.getCachedAPIKeys()
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionLoadCache, model.TypeAPIKey, nil, err)
	}

	applicationAPIKeys := make([]model.APIKey, 0)
	for _, apiKey := range cachedAPIKeys {
		if apiKey.AppID == appID {
			applicationAPIKeys = append(applicationAPIKeys, apiKey)
		}
	}

	return applicationAPIKeys, nil
}

// GetAPIKey finds and returns an API key
func (a *Auth) GetAPIKey(ID string) (*model.APIKey, error) {
	return a.getCachedAPIKey(ID)
}

// CreateAPIKey creates a new API key
func (a *Auth) CreateAPIKey(apiKey model.APIKey) (*model.APIKey, error) {
	id, _ := uuid.NewUUID()
	apiKey.ID = id.String()
	return a.storage.InsertAPIKey(nil, apiKey)
}

// UpdateAPIKey updates an existing API key
func (a *Auth) UpdateAPIKey(apiKey model.APIKey) error {
	if len(apiKey.ID) == 0 {
		return errors.ErrorData(logutils.StatusMissing, "api key id", nil)
	}
	return a.storage.UpdateAPIKey(apiKey)
}

// DeleteAPIKey deletes an API key
func (a *Auth) DeleteAPIKey(ID string) error {
	//1. find api key to delete
	apiKey, err := a.getCachedAPIKey(ID)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionFind, model.TypeAPIKey, &logutils.FieldArgs{"id": ID}, err)
	}

	//2. find all api keys with same app id
	apiKeys, err := a.GetApplicationAPIKeys(apiKey.AppID)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionFind, model.TypeAPIKey, nil, err)
	}

	//3. delete api key if there is another api key for app id
	if len(apiKeys) > 1 {
		err = a.storage.DeleteAPIKey(ID)
		if err != nil {
			return errors.WrapErrorAction(logutils.ActionDelete, model.TypeAPIKey, nil, err)
		}
	}

	return nil
}

// ValidateAPIKey validates the given API key for the given app ID
func (a *Auth) ValidateAPIKey(appID string, apiKey string) error {
	return a.validateAPIKey(apiKey, appID)
}
