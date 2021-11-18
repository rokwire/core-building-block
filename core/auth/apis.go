package auth

import (
	"core-building-block/core/model"
	"core-building-block/driven/storage"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/rokwire/core-auth-library-go/authorization"
	"github.com/rokwire/core-auth-library-go/authutils"
	"github.com/rokwire/core-auth-library-go/tokenauth"
	"github.com/rokwire/logging-library-go/errors"
	"github.com/rokwire/logging-library-go/logutils"

	"github.com/rokwire/logging-library-go/logs"
)

//Start starts the auth service
func (a *Auth) Start() {
	storageListener := StorageListener{auth: a}
	a.storage.RegisterStorageListener(&storageListener)

	go a.setupDeleteSessionsTimer()
}

//GetHost returns the host/issuer of the auth service
func (a *Auth) GetHost() string {
	return a.host
}

//Login logs a user in a specific application using the specified credentials and authentication method.
//The authentication method must be one of the supported for the application.
//	Input:
//		ipAddress (string): Client's IP address
//		deviceType (string): "mobile" or "web" or "desktop" etc
//		deviceOS (*string): Device OS
//		deviceID (string): Device ID
//		authenticationType (string): Name of the authentication method for provided creds (eg. "email", "username", "illinois_oidc")
//		creds (string): Credentials/JSON encoded credential structure defined for the specified auth type
//		apiKey (string): API key to validate the specified app
//		appTypeIdentifier (string): identifier of the app type/client that the user is logging in from
//		orgID (string): ID of the organization that the user is logging in
//		params (string): JSON encoded params defined by specified auth type
//		profile (Profile): Account profile
//		preferences (map): Account preferences
//		l (*logs.Log): Log object pointer for request
//	Returns:
//		Message (*string): message
//		Login session (*LoginSession): Signed ROKWIRE access token to be used to authorize future requests
//			Access token (string): Signed ROKWIRE access token to be used to authorize future requests
//			Refresh Token (string): Refresh token that can be sent to refresh the access token once it expires
//			AccountAuthType (AccountAuthType): AccountAuthType object for authenticated user
//			Params (interface{}): authType-specific set of parameters passed back to client
func (a *Auth) Login(ipAddress string, deviceType string, deviceOS *string, deviceID string,
	authenticationType string, creds string, apiKey string, appTypeIdentifier string, orgID string, params string,
	profile model.Profile, preferences map[string]interface{}, l *logs.Log) (*string, *model.LoginSession, error) {
	//TODO - analyse what should go in one transaction

	//validate if the provided auth type is supported by the provided application and organization
	authType, appType, appOrg, err := a.validateAuthType(authenticationType, appTypeIdentifier, orgID)
	if err != nil {
		return nil, nil, errors.WrapErrorAction(logutils.ActionValidate, typeAuthType, nil, err)
	}

	//TODO: Ideally we would not make many database calls before validating the API key. Currently needed to get app ID
	err = a.validateAPIKey(apiKey, appType.Application.ID)
	if err != nil {
		return nil, nil, errors.WrapErrorData(logutils.StatusInvalid, model.TypeAPIKey, nil, err)
	}

	var message string

	anonymous := false
	sub := ""

	var accountAuthType *model.AccountAuthType
	var responseParams map[string]interface{}

	//get the auth type implementation for the auth type
	if authType.IsAnonymous {
		anonymous = true

		anonymousID := ""
		anonymousID, responseParams, err = a.applyAnonymousAuthType(*authType, *appType, *appOrg, creds, params, l)
		if err != nil {
			return nil, nil, errors.WrapErrorAction("apply anonymous auth type", "user", nil, err)
		}
		sub = anonymousID

	} else if authType.IsExternal {
		accountAuthType, responseParams, err = a.applyExternalAuthType(*authType, *appType, *appOrg, creds, params, profile, preferences, l)
		if err != nil {
			return nil, nil, errors.WrapErrorAction("apply external auth type", "user", nil, err)

		}

		sub = accountAuthType.Account.ID

		//TODO groups mapping
	} else {
		message, accountAuthType, err = a.applyAuthType(*authType, *appType, *appOrg, creds, params, profile, preferences, l)
		if err != nil {
			return nil, nil, errors.WrapErrorAction("apply auth type", "user", nil, err)
		}
		//message
		if len(message) > 0 {
			return &message, nil, nil
		}

		sub = accountAuthType.Account.ID

		//the credentials are valid
	}

	//now we are ready to apply login for the user or anonymous
	loginSession, err := a.applyLogin(anonymous, sub, *authType, *appOrg, accountAuthType, *appType, ipAddress, deviceType, deviceOS, deviceID, responseParams, l)
	if err != nil {
		return nil, nil, errors.WrapErrorAction("error apply login auth type", "user", nil, err)
	}

	return nil, loginSession, nil
}

//AccountExists checks if a user is already registered
//The authentication method must be one of the supported for the application.
//	Input:
//		authenticationType (string): Name of the authentication method for provided creds (eg. "email", "username", "illinois_oidc")
//		userIdentifier (string): User identifier for the specified auth type
//		apiKey (string): API key to validate the specified app
//		appTypeIdentifier (string): identifier of the app type/client that the user is logging in from
//		orgID (string): ID of the organization that the user is logging in
//		l (*logs.Log): Log object pointer for request
//	Returns:
//		accountExisted (bool): valid when error is nil
func (a *Auth) AccountExists(authenticationType string, userIdentifier string, apiKey string, appTypeIdentifier string, orgID string, l *logs.Log) (bool, error) {
	//validate if the provided auth type is supported by the provided application and organization
	authType, appType, appOrg, err := a.validateAuthType(authenticationType, appTypeIdentifier, orgID)
	if err != nil {
		return false, errors.WrapErrorAction(logutils.ActionValidate, typeAuthType, nil, err)
	}

	//TODO: Ideally we would not make many database calls before validating the API key. Currently needed to get app ID
	err = a.validateAPIKey(apiKey, appType.Application.ID)
	if err != nil {
		return false, errors.WrapErrorData(logutils.StatusInvalid, model.TypeAPIKey, nil, err)
	}

	//check if the account exists check
	account, err := a.storage.FindAccount(appOrg.ID, authType.ID, userIdentifier)
	if err != nil {
		return false, errors.WrapErrorAction(logutils.ActionFind, model.TypeAccount, nil, err)
	}

	return account != nil, nil
}

//Refresh refreshes an access token using a refresh token
//	Input:
//		refreshToken (string): Refresh token
//		apiKey (string): API key to validate the specified app
//		l (*logs.Log): Log object pointer for request
//	Returns:
//		Login session (*LoginSession): Signed ROKWIRE access token to be used to authorize future requests
//			Access token (string): Signed ROKWIRE access token to be used to authorize future requests
//			Refresh Token (string): Refresh token that can be sent to refresh the access token once it expires
//			Params (interface{}): authType-specific set of parameters passed back to client
func (a *Auth) Refresh(refreshToken string, apiKey string, l *logs.Log) (*model.LoginSession, error) {
	var loginSession *model.LoginSession

	//find the login session for the refresh token
	loginSession, err := a.storage.FindLoginSession(refreshToken)
	if err != nil {
		l.Infof("error finding session by refresh token - %s", refreshToken)
		return nil, errors.WrapErrorAction("error finding session by refresh token", "", nil, err)
	}
	if loginSession == nil {
		l.Infof("there is no a session for refresh token - %s", refreshToken)
		return nil, nil
	}

	//check if the session is expired
	if loginSession.IsExpired() {
		l.Infof("the session is expired, so delete it and return null - %s", refreshToken)

		//remove the session
		err = a.storage.DeleteLoginSession(nil, loginSession.ID)
		if err != nil {
			return nil, errors.WrapErrorAction("error deleting expired session", "", nil, err)
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
		err = a.storage.DeleteLoginSession(nil, loginSession.ID)
		if err != nil {
			return nil, errors.WrapErrorAction("error deleting expired session", "", nil, err)
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
			return nil, errors.WrapErrorAction("error getting external auth type on refresh", "", nil, err)
		}

		externalUser, refreshedData, err := extAuthType.refresh(loginSession.Params, loginSession.AuthType, loginSession.AppType, loginSession.AppOrg, l)
		if err != nil {
			l.Infof("error refreshing external auth type on refresh - %s", refreshToken)
			return nil, errors.WrapErrorAction("error refreshing external auth type on refresh", "", nil, err)
		}

		//check if need to update the account
		authType, err := a.storage.FindAuthType(loginSession.AuthType.ID)
		if err != nil {
			l.Infof("error getting auth type - %s", refreshToken)
			return nil, errors.WrapErrorAction("error getting auth type", "", nil, err)
		}
		err = a.updateAccountIfNeeded(*loginSession.AccountAuthType, *externalUser, *authType, loginSession.AppOrg)
		if err != nil {
			return nil, errors.WrapErrorAction("update account if needed on refresh", "", nil, err)
		}

		loginSession.Params = refreshedData //assing the refreshed data
	}

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
	}
	claims := a.getStandardClaims(sub, uid, name, email, phone, "rokwire", orgID, appID, authType, nil, anonymous, false, false)
	accessToken, err := a.buildAccessToken(claims, strings.Join(permissions, ","), authorization.ScopeGlobal)
	if err != nil {
		l.Infof("error generating acccess token on refresh - %s", refreshToken)
		return nil, errors.WrapErrorAction(logutils.ActionCreate, logutils.TypeToken, nil, err)
	}
	loginSession.AccessToken = accessToken //set the generated token
	// - generate new refresh token
	refreshToken, expires, err := a.buildRefreshToken()
	if err != nil {
		l.Infof("error generating refresh token on refresh - %s", refreshToken)
		return nil, errors.WrapErrorAction(logutils.ActionCreate, logutils.TypeToken, nil, err)
	}
	if loginSession.RefreshTokens == nil {
		loginSession.RefreshTokens = make([]string, 0)
	}
	loginSession.RefreshTokens = append(loginSession.RefreshTokens, refreshToken) //set the generated token
	// - update the expired field
	loginSession.Expires = *expires

	//store the updated session
	now := time.Now()
	loginSession.DateUpdated = &now
	err = a.storage.UpdateLoginSession(*loginSession)
	if err != nil {
		l.Infof("error updating login session on refresh - %s", refreshToken)
		return nil, errors.WrapErrorAction("error updating login session on refresh", "", nil, err)
	}

	//return the updated session
	return loginSession, nil
}

//GetLoginURL returns a pre-formatted login url for SSO providers
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
	authType, appType, appOrg, err := a.validateAuthType(authenticationType, appTypeIdentifier, orgID)
	if err != nil {
		return "", nil, errors.WrapErrorAction(logutils.ActionValidate, typeAuthType, nil, err)
	}

	//TODO: Ideally we would not make many database calls before validating the API key. Currently needed to get app ID
	err = a.validateAPIKey(apiKey, appType.Application.ID)
	if err != nil {
		return "", nil, errors.WrapErrorData(logutils.StatusInvalid, model.TypeAPIKey, nil, err)
	}

	//get the auth type implementation for the auth type
	authImpl, err := a.getExternalAuthTypeImpl(*authType)
	if err != nil {
		return "", nil, errors.WrapErrorAction(logutils.ActionLoadCache, typeAuthType, nil, err)
	}

	//get login URL
	loginURL, params, err := authImpl.getLoginURL(*authType, *appType, *appOrg, redirectURI, l)
	if err != nil {
		return "", nil, errors.WrapErrorAction(logutils.ActionGet, "login url", nil, err)
	}

	return loginURL, params, nil
}

//VerifyCredential verifies credential (checks the verification code in the credentials collection)
func (a *Auth) VerifyCredential(id string, verification string, l *logs.Log) error {
	credential, err := a.storage.FindCredential(id)
	if err != nil || credential == nil {
		return errors.WrapErrorAction(logutils.ActionFind, model.TypeCredential, nil, err)
	}

	if credential.Verified {
		return errors.New("credential has already been verified")
	}

	//get the auth type
	authType, err := a.storage.FindAuthType(credential.AuthType.ID)
	if err != nil || authType == nil {
		return errors.WrapErrorAction(logutils.ActionLoadCache, typeAuthType, logutils.StringArgs(credential.AuthType.ID), err)
	}
	if !authType.UseCredentials {
		return errors.WrapErrorAction("invalid auth type for credential verification", model.TypeAuthType, nil, err)
	}

	authImpl, err := a.getAuthTypeImpl(*authType)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionLoadCache, typeAuthType, nil, err)
	}

	authTypeCreds, err := authImpl.verifyCredential(credential, verification, l)
	if err != nil || authTypeCreds == nil {
		return errors.WrapErrorAction(logutils.ActionValidate, "verification code", nil, err)
	}

	credential.Verified = true
	credential.Value = authTypeCreds
	if err = a.storage.UpdateCredential(credential); err != nil {
		return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeCredential, nil, err)
	}

	return nil
}

//UpdateCredential updates the credential object with the new value
//	Input:
//		accountID: id of the associated account to reset
//		accountAuthTypeID (string): id of the AccountAuthType
//		params: specific params for the different auth types
//	Returns:
//		error: if any
//TODO: Clear login sessions using old creds
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
		return errors.New("Invalid account auth type for reset password")
	}

	credential := accountAuthType.Credential
	//Determine the auth type for resetPassword
	authType := accountAuthType.AuthType
	if !authType.UseCredentials {
		return errors.WrapErrorAction("invalid auth type for reset password client", model.TypeAuthType, nil, err)
	}

	authImpl, err := a.getAuthTypeImpl(authType)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionLoadCache, typeAuthType, nil, err)
	}

	authTypeCreds, err := authImpl.resetCredential(credential, nil, params, l)
	if err != nil || authTypeCreds == nil {
		return errors.WrapErrorAction(logutils.ActionValidate, "reset password", nil, err)
	}
	//Update the credential with new password
	credential.Value = authTypeCreds
	if err = a.storage.UpdateCredential(credential); err != nil {
		return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeCredential, nil, err)
	}

	return nil
}

//ResetForgotCredential resets forgot credential
//	Input:
//		credsID: id of the credential object
//		resetCode: code from the reset link
//		params: specific params for the different auth types
//	Returns:
//		error: if any
//TODO: Clear login sessions using old creds
// Handle refresh tokens when applicable
func (a *Auth) ResetForgotCredential(credsID string, resetCode string, params string, l *logs.Log) error {
	credential, err := a.storage.FindCredential(credsID)
	if err != nil || credential == nil {
		return errors.WrapErrorAction(logutils.ActionFind, model.TypeCredential, nil, err)
	}

	//Determine the auth type for resetPassword
	authType, err := a.storage.FindAuthType(credential.AuthType.ID)
	if err != nil || authType == nil {
		return errors.WrapErrorAction(logutils.ActionLoadCache, typeAuthType, logutils.StringArgs(credential.AuthType.ID), err)
	}
	if !authType.UseCredentials {
		return errors.WrapErrorAction("invalid auth type for reset password link", model.TypeAuthType, nil, err)
	}

	authImpl, err := a.getAuthTypeImpl(*authType)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionLoadCache, typeAuthType, nil, err)
	}

	authTypeCreds, err := authImpl.resetCredential(credential, &resetCode, params, l)
	if err != nil || authTypeCreds == nil {
		return errors.WrapErrorAction(logutils.ActionValidate, "reset password", nil, err)
	}
	//Update the credential with new password
	credential.Value = authTypeCreds
	if err = a.storage.UpdateCredential(credential); err != nil {
		return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeCredential, nil, err)
	}

	return nil
}

//ForgotCredential initiate forgot credential process (generates a reset link and sends to the given identifier for email auth type)
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
	authType, appType, appOrg, err := a.validateAuthType(authenticationType, appTypeIdentifier, orgID)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionValidate, typeAuthType, nil, err)
	}

	//check for api key
	//TODO: Ideally we would not make many database calls before validating the API key. Currently needed to get app ID
	err = a.validateAPIKey(apiKey, appType.Application.ID)
	if err != nil {
		return errors.WrapErrorData(logutils.StatusInvalid, model.TypeAPIKey, nil, err)
	}

	//check if the auth types uses credentials
	if !authType.UseCredentials {
		return errors.WrapErrorAction("invalid auth type for forgot credential", model.TypeAuthType, nil, err)
	}

	authImpl, err := a.getAuthTypeImpl(*authType)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionLoadCache, typeAuthType, nil, err)
	}
	authTypeID := authType.ID

	//Find the credential for setting reset code and expiry and sending credID in reset link
	account, err := a.storage.FindAccount(appOrg.ID, authTypeID, identifier)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionFind, model.TypeAccount, nil, err)
	}

	accountAuthType, err := a.findAccountAuthType(account, authType, identifier)
	if accountAuthType == nil {
		return errors.WrapErrorAction(logutils.ActionFind, model.TypeAccountAuthType, nil, err)
	}
	credential := accountAuthType.Credential
	if credential == nil {
		return errors.New("Invalid account auth type for reset link")
	}
	//do not allow to reset credential for unverified credentials
	if !credential.Verified {
		return errors.New("The credential is not verified")
	}

	authTypeCreds, err := authImpl.forgotCredential(credential, identifier, l)
	if err != nil || authTypeCreds == nil {
		return errors.WrapErrorAction(logutils.ActionValidate, "forgot password", nil, err)
	}
	//Update the credential with reset code and expiry
	credential.Value = authTypeCreds
	if err = a.storage.UpdateCredential(credential); err != nil {
		return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeCredential, nil, err)
	}
	return nil
}

//GetServiceAccessToken returns an access token for a non-human client
func (a *Auth) GetServiceAccessToken(authType string, creds string, l *logs.Log) (*string, string, error) {
	serviceAuthType, err := a.getServiceAuthTypeImpl(authType)
	if err != nil {
		l.Info("error getting service auth type on get service access token")
		return nil, "", errors.WrapErrorAction("error getting service auth type on get service access token", "", nil, err)
	}

	message, account, err := serviceAuthType.checkCredentials(creds, l)
	if err != nil {
		return message, "", errors.WrapErrorAction(logutils.ActionValidate, "service account creds", nil, err)
	}

	permissions := account.GetPermissionNames()
	var appID string
	if account.Application != nil {
		appID = account.Application.ID
	}
	var orgID string
	if account.Organization != nil {
		orgID = account.Organization.ID
	}
	claims := a.getStandardClaims(account.ID, "", "", "", "", "rokwire", orgID, appID, authType, nil, false, true, true)
	accessToken, err := a.buildAccessToken(claims, strings.Join(permissions, ","), authorization.ScopeGlobal)
	if err != nil {
		return nil, "", errors.WrapErrorAction(logutils.ActionCreate, logutils.TypeToken, nil, err)
	}
	return nil, accessToken, errors.New(logutils.Unimplemented)
}

//GetServiceAccounts gets all service accounts
func (a *Auth) GetServiceAccounts() ([]model.ServiceAccount, error) {
	serviceAccounts, err := a.storage.FindServiceAccounts()
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeServiceAccount, nil, err)
	}

	return serviceAccounts, nil
}

//RegisterServiceAccount registers a service account
func (a *Auth) RegisterServiceAccount(name string, orgID *string, appID *string, permissions []string, roles []string) error {
	id, _ := uuid.NewUUID()
	permissionList, err := a.storage.FindPermissionsByName(permissions)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionFind, model.TypePermission, nil, err)
	}

	//TODO: get application, organization, and roles
	newAccount := model.ServiceAccount{ID: id.String(), Name: name, Permissions: permissionList}
	err = a.storage.InsertServiceAccount(&newAccount)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionInsert, model.TypeServiceAccount, nil, err)
	}

	return errors.New(logutils.Unimplemented)
}

//UpdateServiceAccount updates a service account
func (a *Auth) UpdateServiceAccount(id *string, name string, orgID *string, appID *string, permissions []string, roles []string) (*string, error) {
	return nil, errors.New(logutils.Unimplemented)
}

//DeregisterServiceAccount deregisters a service account
func (a *Auth) DeregisterServiceAccount(id string) error {
	err := a.storage.DeleteServiceAccount(id)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionDelete, model.TypeServiceAccount, nil, err)
	}

	return nil
}

//AddServiceToken adds a token to a service account
func (a *Auth) AddServiceToken(accountID string, name string, l *logs.Log) (string, error) {
	var token string

	transaction := func(context storage.TransactionContext) error {
		//1. find service account
		account, err := a.storage.FindServiceAccountByID(context, accountID)
		if err != nil {
			return errors.WrapErrorAction(logutils.ActionFind, model.TypeServiceAccount, nil, err)
		}

		//2. build new token
		token, _, err = a.buildRefreshToken()
		if err != nil {
			l.Info("error generating service account token")
			return errors.WrapErrorAction(logutils.ActionCreate, logutils.TypeToken, nil, err)
		}

		//3. update service account
		newToken := model.StaticToken{Name: name, Token: token}
		account.Tokens = append(account.Tokens, newToken)
		err = a.storage.UpdateServiceAccount(context, account)
		if err != nil {
			return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeServiceAccount, nil, err)
		}

		return nil
	}

	err := a.storage.PerformTransaction(transaction)
	if err != nil {
		return "", errors.WrapErrorAction(logutils.ActionUpdate, model.TypeUserAuth, nil, err)
	}
	return token, nil
}

//RemoveServiceToken removes a token from a service account
func (a *Auth) RemoveServiceToken(accountID string, name string) error {
	transaction := func(context storage.TransactionContext) error {
		//1. find service account
		account, err := a.storage.FindServiceAccountByID(context, accountID)
		if err != nil {
			return errors.WrapErrorAction(logutils.ActionFind, model.TypeServiceAccount, nil, err)
		}

		//2. remove token from token list
		updated := false
		for i, t := range account.Tokens {
			if t.Name == name {
				account.Tokens = append(account.Tokens[:i], account.Tokens[i+1:]...)
				updated = true
				break
			}
		}

		//3. update account
		if updated {
			err = a.storage.UpdateServiceAccount(context, account)
			if err != nil {
				return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeServiceAccount, nil, err)
			}
		}

		return nil
	}

	err := a.storage.PerformTransaction(transaction)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeUserAuth, nil, err)
	}
	return nil
}

//AuthorizeService returns a scoped token for the specified service and the service registration record if authorized or
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
func (a *Auth) AuthorizeService(claims tokenauth.Claims, serviceID string, approvedScopes []authorization.Scope, l *logs.Log) (string, []authorization.Scope, *model.ServiceReg, error) {
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
func (a *Auth) GetScopedAccessToken(claims tokenauth.Claims, serviceID string, scopes []authorization.Scope) (string, error) {
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

	scopedClaims := a.getStandardClaims(claims.Subject, "", "", "", "", aud, claims.OrgID, claims.AppID, claims.AuthType, nil, claims.Anonymous, claims.Authenticated, claims.Service)
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

//GetApplicationAPIKeys finds and returns the API keys for the provided app
func (a *Auth) GetApplicationAPIKeys(appID string) ([]model.APIKey, error) {
	return a.storage.FindApplicationAPIKeys(appID)
}

//GetAPIKey finds and returns an API key
func (a *Auth) GetAPIKey(ID string) (*model.APIKey, error) {
	return a.storage.FindAPIKey(ID)
}

//CreateAPIKey creates a new API key
func (a *Auth) CreateAPIKey(apiKey model.APIKey) (*model.APIKey, error) {
	id, _ := uuid.NewUUID()
	apiKey.ID = id.String()
	return a.storage.InsertAPIKey(apiKey)
}

//UpdateAPIKey updates an existing API key
func (a *Auth) UpdateAPIKey(apiKey model.APIKey) error {
	if len(apiKey.ID) == 0 {
		return errors.Newf("id cannot be empty")
	}
	return a.storage.UpdateAPIKey(apiKey)
}

//DeleteAPIKey deletes an API key
func (a *Auth) DeleteAPIKey(ID string) error {
	return a.storage.DeleteAPIKey(ID)
}
