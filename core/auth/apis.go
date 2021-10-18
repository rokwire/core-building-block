package auth

import (
	"core-building-block/core/model"
	"strings"

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

	go a.setupDeleteRefreshTimer()
}

//GetHost returns the host/issuer of the auth service
func (a *Auth) GetHost() string {
	return a.host
}

//Login logs a user in a specific application using the specified credentials and authentication method.
//The authentication method must be one of the supported for the application.
//	Input:
//		IP (string): Client's IP address
//		deviceType (string): "mobile" or "web" or "desktop" etc
//		deviceOS (*string): Device OS
//		deviceID (string): Device ID
//		authenticationType (string): Name of the authentication method for provided creds (eg. "email", "username", "illinois_oidc")
//		creds (string): Credentials/JSON encoded credential structure defined for the specified auth type
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
func (a *Auth) Login(IP string, deviceType string, deviceOS *string, deviceID string,
	authenticationType string, creds string, appTypeIdentifier string, orgID string, params string,
	profile model.Profile, preferences map[string]interface{}, l *logs.Log) (*string, *model.LoginSession, error) {
	//TODO - analyse what should go in one transaction

	//validate if the provided auth type is supported by the provided application and organization
	authType, appType, appOrg, err := a.validateAuthType(authenticationType, appTypeIdentifier, orgID)
	if err != nil {
		return nil, nil, errors.WrapErrorAction(logutils.ActionValidate, typeAuthType, nil, err)
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
	loginSession, err := a.applyLogin(anonymous, sub, *authType, *appOrg, accountAuthType, *appType, IP, deviceType, deviceOS, deviceID, responseParams, l)
	if err != nil {
		return nil, nil, errors.WrapErrorAction("error apply login auth type", "user", nil, err)
	}

	return nil, loginSession, nil
}

//Refresh refreshes an access token using a refresh token
//	Input:
//		refreshToken (string): Refresh token
//		l (*logs.Log): Log object pointer for request
//	Returns:
//		Login session (*LoginSession): Signed ROKWIRE access token to be used to authorize future requests
//			Access token (string): Signed ROKWIRE access token to be used to authorize future requests
//			Refresh Token (string): Refresh token that can be sent to refresh the access token once it expires
//			Params (interface{}): authType-specific set of parameters passed back to client
func (a *Auth) Refresh(refreshToken string, l *logs.Log) (*model.LoginSession, error) {
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
		err = a.storage.DeleteLoginSession(loginSession.ID)
		if err != nil {
			return nil, errors.WrapErrorAction("error deleting expired session", "", nil, err)
		}

		//return nul
		return nil, nil
	}

	///now:
	// - generate new access token
	sub := loginSession.Identifier
	orgID := loginSession.AppOrg.Organization.ID
	appID := loginSession.AppOrg.Application.ID
	authType := loginSession.AuthType.Code

	anonymous := loginSession.Anonymous
	uid := ""
	email := ""
	phone := ""
	permissions := []string{}
	if !anonymous {
		accountAuthType := loginSession.AccountAuthType
		if accountAuthType == nil {
			l.Infof("for some reasons account auth type is null for not anonymous login - %s", loginSession.ID)
			return nil, errors.ErrorAction("for some reasons account auth type is null for not anonymous login", "", nil)
		}
		uid = accountAuthType.Identifier
		email = accountAuthType.Account.Profile.Email
		phone = accountAuthType.Account.Profile.Phone
		permissions = accountAuthType.Account.GetPermissionNames()
	}
	claims := a.getStandardClaims(sub, uid, email, phone, "rokwire", orgID, appID, authType, nil, anonymous)
	accessToken, err := a.buildAccessToken(claims, strings.Join(permissions, ","), authorization.ScopeGlobal)
	if err != nil {
		l.Infof("error gnerating acccess token on refresh - %s", refreshToken)
		return nil, errors.WrapErrorAction(logutils.ActionCreate, logutils.TypeToken, nil, err)
	}
	loginSession.AccessToken = accessToken //set the generated token
	// - generate new refresh token
	// - update the expired field
	// - generate new params(if external auth type)
	//TODO

	return loginSession, nil
	/*
		refresh, err := a.storage.FindRefreshToken(refreshToken)
		if err != nil {
			return "", "", nil, errors.WrapErrorAction("refreshing", logutils.TypeToken, nil, err)
		}

		credentials, err := a.storage.FindCredentialsByID(refresh.CredsID)
		if err != nil {
			return "", "", nil, errors.WrapErrorAction("refreshing", logutils.TypeToken, nil, err)
		}
		if credentials == nil {
			return "", "", nil, errors.ErrorData(logutils.StatusMissing, model.TypeAuthCred, nil)
		}

		validate := validator.New()
		err = validate.Struct(refresh)
		if err != nil {
			return "", "", nil, errors.WrapErrorAction(logutils.ActionValidate, typeAuthRefreshParams, nil, err)
		}

		if !refresh.Expires.After(time.Now().UTC()) {
			err = a.storage.DeleteRefreshToken(refresh.CurrentToken)
			if err != nil {
				return "", "", nil, errors.WrapErrorAction(logutils.ActionValidate, "refresh expiration", nil, err)
			}
			return "", "", nil, errors.ErrorAction(logutils.ActionValidate, "refresh expiration", nil)
		}

		if refreshToken == refresh.PreviousToken {
			err = a.storage.DeleteRefreshToken(refresh.CurrentToken)
			if err != nil {
				return "", "", nil, errors.WrapErrorAction(logutils.ActionValidate, "refresh reuse", nil, err)
			}
			return "", "", nil, errors.ErrorAction(logutils.ActionValidate, "refresh reuse", nil)
		}
		if refreshToken != refresh.CurrentToken {
			return "", "", nil, errors.ErrorAction(logutils.ActionValidate, model.TypeRefreshToken, nil)
		}

		auth, err := a.getAuthType(credentials.AuthType)
		if err != nil {
			return "", "", nil, errors.WrapErrorAction(logutils.ActionLoadCache, typeAuthType, nil, err)
		}

		userAuth, err := auth.refresh(refresh.Params, refresh.OrgID, refresh.AppID, l)
		if err != nil {
			return "", "", nil, errors.WrapErrorAction("refreshing", logutils.TypeToken, nil, err)
		}

		if userAuth == nil {
			return "", "", nil, errors.WrapErrorData(logutils.StatusInvalid, model.TypeUserAuth, nil, err)
		}

		user, err := a.storage.FindUserByAccountID(credentials.AccountID)
		if err != nil {
			return "", "", nil, err
		}

		user, update, _ := a.needsUserUpdate(userAuth, user)
		if update {
			_, err = a.updateAccount(user, "", nil)
			if err != nil {
				return "", "", nil, err
			}
		}

		claims := a.getStandardClaims(user.ID, userAuth.UserID, user.Account.Email, user.Account.Phone, "rokwire", refresh.OrgID, refresh.AppID, userAuth.Exp)
		token, err := a.buildAccessToken(claims, "", authorization.ScopeGlobal)
		if err != nil {
			return "", "", nil, errors.WrapErrorAction(logutils.ActionCreate, logutils.TypeToken, nil, err)
		}

		newRefreshToken := ""
		if userAuth.RefreshParams != nil {
			var expireTime *time.Time
			newRefreshToken, expireTime, err = a.buildRefreshToken()
			if err != nil {
				return "", "", nil, errors.WrapErrorAction(logutils.ActionCreate, model.TypeRefreshToken, nil, err)
			}

			now := time.Now().UTC()
			updatedRefresh := model.AuthRefresh{CurrentToken: newRefreshToken, PreviousToken: refreshToken, Expires: expireTime,
				Params: userAuth.RefreshParams, DateUpdated: &now}

			err = a.storage.UpdateRefreshToken(refreshToken, &updatedRefresh)
			if err != nil {
				return "", "", nil, err
			}
		}

		return token, newRefreshToken, userAuth.ResponseParams, nil
	*/
}

//GetLoginURL returns a pre-formatted login url for SSO providers
//	Input:
//		authenticationType (string): Name of the authentication method for provided creds (eg. "email", "username", "illinois_oidc")
//		appTypeIdentifier (string): Identifier of the app type/client that the user is logging in from
//		orgID (string): ID of the organization that the user is logging in
//		redirectURI (string): Registered redirect URI where client will receive response
//		l (*loglib.Log): Log object pointer for request
//	Returns:
//		Login URL (string): SSO provider login URL to be launched in a browser
//		Params (map[string]interface{}): Params to be sent in subsequent request (if necessary)
func (a *Auth) GetLoginURL(authenticationType string, appTypeIdentifier string, orgID string, redirectURI string, l *logs.Log) (string, map[string]interface{}, error) {
	//validate if the provided auth type is supported by the provided application and organization
	authType, appType, appOrg, err := a.validateAuthType(authenticationType, appTypeIdentifier, orgID)
	if err != nil {
		return "", nil, errors.WrapErrorAction(logutils.ActionValidate, typeAuthType, nil, err)
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

//Verify checks the verification code generated on signup
func (a *Auth) Verify(id string, verification string, l *logs.Log) error {
	credential, err := a.storage.FindCredential(id)
	if err != nil || credential == nil {
		return errors.WrapErrorAction(logutils.ActionFind, model.TypeCredential, nil, err)
	}

	if credential.Verified {
		return errors.New("credential has already been verified")
	}

	//get the auth type
	authType, err := a.getCachedAuthType(credential.AuthType.ID)
	if err != nil || authType == nil {
		return errors.WrapErrorAction(logutils.ActionLoadCache, typeAuthType, logutils.StringArgs(credential.AuthType.ID), err)
	}
	if authType.IsExternal {
		return errors.WrapErrorAction("invalid auth type for verify", model.TypeAuthType, nil, err)
	}

	authImpl, err := a.getAuthTypeImpl(*authType)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionLoadCache, typeAuthType, nil, err)
	}

	authTypeCreds, err := authImpl.verify(credential, verification, l)
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

	scopedClaims := a.getStandardClaims(claims.Subject, "", "", "", aud, claims.OrgID, claims.AppID, claims.AuthType, nil, claims.Anonymous)
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

//GetAPIKey finds and returns the API key for the provided org and app
func (a *Auth) GetAPIKey(orgID string, appID string) (*model.APIKey, error) {
	return a.storage.FindAPIKey(orgID, appID)
}

//CreateAPIKey creates a new API key for the provided org and app
func (a *Auth) CreateAPIKey(apiKey *model.APIKey) error {
	return a.storage.InsertAPIKey(apiKey)
}

//UpdateAPIKey updates an existing API key
func (a *Auth) UpdateAPIKey(apiKey *model.APIKey) error {
	return a.storage.UpdateAPIKey(apiKey)
}

//DeleteAPIKey deletes an existing API key
func (a *Auth) DeleteAPIKey(orgID string, appID string) error {
	return a.storage.DeleteAPIKey(orgID, appID)
}
