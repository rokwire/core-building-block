package auth

import (
	"core-building-block/core/model"
	"core-building-block/utils"
	"encoding/json"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/rokmetro/auth-library/authorization"
	"github.com/rokmetro/auth-library/authutils"
	"github.com/rokmetro/logging-library/errors"
	"github.com/rokmetro/logging-library/logutils"

	"github.com/rokmetro/logging-library/logs"
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
//		authType (string): Name of the authentication method for provided creds (eg. "email", "username", "illinois_oidc")
//		creds (string): Credentials/JSON encoded credential structure defined for the specified auth type
//		appID (string): ID of the app/client that the user is logging in from
//		params (string): JSON encoded params defined by specified auth type
//		l (*logs.Log): Log object pointer for request
//	Returns:
//		Access token (string): Signed ROKWIRE access token to be used to authorize future requests
//		Refresh Token (string): Refresh token that can be sent to refresh the access token once it expires
//		User (User): User object for authenticated user
//		Params (interface{}): authType-specific set of parameters passed back to client
func (a *Auth) Login(authType string, creds string, appID string, params string, l *logs.Log) (string, string, *model.User, interface{}, error) {
	//validate if the provided auth type is supported by the provided application
	authTypeEntity, appTypeEntity, err := a.validateAuthType(authType, appID)
	if err != nil {
		return "", "", nil, nil, errors.WrapErrorAction(logutils.ActionValidate, typeAuthType, nil, err)
	}

	accessToken := ""
	refreshToken := ""
	var user *model.User
	var responseParams interface{}

	//get the auth type implementation for the auth type
	if authTypeEntity.IsExternal {
		//external auth type
		authImpl, err := a.getExternalAuthTypeImpl(*authTypeEntity)
		if err != nil {
			return "", "", nil, nil, errors.WrapErrorAction(logutils.ActionLoadCache, typeExternalAuthType, nil, err)
		}

		//1. get the user from the external system
		externalUser, err := authImpl.externalLogin(creds, *authTypeEntity, *appTypeEntity, params, l)
		if err != nil {
			return "", "", nil, nil, errors.WrapErrorAction("error getting external user", "external user", nil, err)
		}

		//2. check if the user exists
		user, err = authImpl.userExist(externalUser.Identifier, *authTypeEntity, *appTypeEntity, l)
		if err != nil {
			return "", "", nil, nil, errors.WrapErrorAction("error checking if external user exists", "external user", nil, err)
		}
		if user != nil {
			//user exists, just check if need to update it

			//get the current external user
			userAuthType := user.FindUserAuthType(appTypeEntity.Application.ID, authTypeEntity.ID)
			if userAuthType == nil {
				return "", "", nil, nil, errors.ErrorAction("for some reasons the user auth type is nil", "", nil)
			}
			currentDataMap := userAuthType.Params["user"]
			currentDataJson, err := utils.ConvertToJSON(currentDataMap)
			if err != nil {
				return "", "", nil, nil, errors.WrapErrorAction("error converting map to json", "", nil, err)
			}
			var currentData *model.ExternalSystemUser
			err = json.Unmarshal(currentDataJson, &currentData)
			if err != nil {
				return "", "", nil, nil, errors.ErrorAction("error converting json to type", "", nil)
			}

			newData := *externalUser

			//check if external system user needs to be updated
			if !currentData.Equals(newData) {
				//there is changes so we need to update it
				userAuthType.Params["user"] = newData
				err = a.storage.UpdateUserAuthType(*userAuthType)
				if err != nil {
					return "", "", nil, nil, errors.WrapErrorAction(logutils.ActionUpdate, model.TypeUserAuth, nil, err)
				}
			}

		} else {
			//user does not exist, we need to register it

			//app
			app := appTypeEntity.Application

			//user auth type
			userAuthTypeID, _ := uuid.NewUUID()
			params := map[string]interface{}{}
			params["identifier"] = externalUser.Identifier
			params["user"] = externalUser
			userAuthType := model.UserAuthType{ID: userAuthTypeID.String(), AuthTypeID: authTypeEntity.ID, Active: true, Params: params}

			//credential
			var credential *string //null as the user authenticates outside the system

			//profile
			profileID, _ := uuid.NewUUID()
			profile := model.UserProfile{ID: profileID.String(), DateCreated: time.Now()}

			//useSharedUser
			useSharedUser := false // for now this is disable

			user, err = a.registerUser(app, userAuthType, credential, profile, useSharedUser, l)
			if err != nil {
				return "", "", nil, nil, errors.WrapErrorAction("error register user", model.TypeUser, nil, err)
			}
		}

		//TODO groups mapping

	} else {
		//auth type
		authImpl, err := a.getAuthTypeImpl(*authTypeEntity)
		if err != nil {
			return "", "", nil, nil, errors.WrapErrorAction(logutils.ActionLoadCache, typeAuthType, nil, err)
		}

		//1. check if the user exists
		user, err = authImpl.userExist(*authTypeEntity, *appTypeEntity, creds, l)
		if err != nil {
			return "", "", nil, nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeUser, nil, err)
		}
		if user == nil {
			return "", "", nil, nil, errors.WrapErrorAction("exist", model.TypeUser, nil, err)
		}

		//2. it seems the user exist, now check the credentials
		userAuthType := user.FindUserAuthType(appTypeEntity.Application.ID, authTypeEntity.ID)
		if userAuthType == nil {
			return "", "", nil, nil, errors.ErrorAction("for some reasons the user auth type is nil", "", nil)
		}
		validCredentials, err := authImpl.checkCredentials(*userAuthType, creds, l)
		if err != nil {
			return "", "", nil, nil, errors.WrapErrorAction("error checking credentials", "", nil, err)
		}
		if !*validCredentials {
			return "", "", nil, nil, errors.WrapErrorAction("invalid credentials", "", nil, err)
		}

		//the credentials are valid
	}

	///prepare the response
	//access token
	claims := a.getStandardClaims(user.ID, "TODO", "TODO", "TODO", "rokwire", "TODO", appID, nil)
	accessToken, err = a.buildAccessToken(claims, "", authorization.ScopeGlobal)
	if err != nil {
		return "", "", nil, nil, errors.WrapErrorAction(logutils.ActionCreate, logutils.TypeToken, nil, err)
	}

	//refresh token
	refreshToken = "TODO"

	return accessToken, refreshToken, user, responseParams, nil

	//check credentials
	/*	userAuth, err := authImpl.check(creds, *authTypeEntity, *appTypeEntity, params, l)
		if err != nil {
			return "", "", nil, nil, errors.WrapErrorAction(logutils.ActionValidate, "login creds", nil, err)
		}

	log.Println(userAuth)*/

	return "", "", nil, nil, nil
	/*var user *model.User
	var err error
	auth, err := a.getAuthType(authType)
	if err != nil {
		return "", "", nil, nil, errors.WrapErrorAction(logutils.ActionLoadCache, typeAuthType, nil, err)
	}

	userAuth, err := auth.check(creds, orgID, appID, params, l)
	if err != nil {
		return "", "", nil, nil, errors.WrapErrorAction(logutils.ActionValidate, "login creds", nil, err)
	}

	if userAuth == nil || userAuth.Creds == nil {
		return "", "", nil, nil, errors.WrapErrorData(logutils.StatusInvalid, "user auth creds", nil, err)
	}

	//RefreshParams == nil indicates that a refresh token should not be generated
	refreshToken := ""
	var refreshParams *model.AuthRefresh
	if userAuth.RefreshParams != nil {
		var expireTime *time.Time
		refreshToken, expireTime, err = a.buildRefreshToken()
		if err != nil {
			return "", "", nil, nil, err
		}

		refreshParams = &model.AuthRefresh{CurrentToken: refreshToken, Expires: expireTime, AppID: appID, OrgID: orgID,
			CredsID: userAuth.Creds.ID, Params: userAuth.RefreshParams, DateCreated: time.Now().UTC()}
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
			_, err = a.updateAccount(user, orgID, newMembershipOrgData)
			if err != nil {
				return "", "", nil, nil, err
			}
		}

		if refreshParams != nil {
			err = a.checkRefreshTokenLimit(orgID, appID, userAuth.Creds.ID)
			if err != nil {
				a.logger.Error(err.Error())
			} else {
				err = a.storage.InsertRefreshToken(refreshParams)
				if err != nil {
					return "", "", nil, nil, err
				}
			}
		}
	} else if userAuth.OrgID == orgID {
		user, err = a.createAccount(userAuth)
		if err != nil {
			return "", "", nil, nil, err
		}

		if refreshParams != nil {
			err = a.storage.InsertRefreshToken(refreshParams)
			if err != nil {
				return "", "", nil, nil, err
			}
		}
	} else {
		return "", "", nil, nil, errors.ErrorData(logutils.StatusInvalid, "org_id", logutils.StringArgs(orgID))
	}

	claims := a.getStandardClaims(user.ID, userAuth.UserID, userAuth.Email, userAuth.Phone, "rokwire", orgID, appID, userAuth.Exp)
	token, err := a.buildAccessToken(claims, "", authorization.ScopeGlobal)
	if err != nil {
		return "", "", nil, nil, errors.WrapErrorAction(logutils.ActionCreate, logutils.TypeToken, nil, err)
	}

	return token, refreshToken, user, userAuth.ResponseParams, nil

	*/
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
	//TODO
	return "", "", nil, nil
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
//		authType (string): Name of the authentication method for provided creds (eg. "email", "username", "illinois_oidc")
//		appID (string): ID of the app/client that the user is logging in from
//		redirectURI (string): Registered redirect URI where client will receive response
//		l (*loglib.Log): Log object pointer for request
//	Returns:
//		Login URL (string): SSO provider login URL to be launched in a browser
//		Params (map[string]interface{}): Params to be sent in subsequent request (if necessary)
func (a *Auth) GetLoginURL(authType string, appID string, redirectURI string, l *logs.Log) (string, map[string]interface{}, error) {
	//validate if the provided auth type is supported by the provided application
	authTypeEntity, appTypeEntity, err := a.validateAuthType(authType, appID)
	if err != nil {
		return "", nil, errors.WrapErrorAction(logutils.ActionValidate, typeAuthType, nil, err)
	}

	//get the auth type implementation for the auth type
	authImpl, err := a.getExternalAuthTypeImpl(*authTypeEntity)
	if err != nil {
		return "", nil, errors.WrapErrorAction(logutils.ActionLoadCache, typeAuthType, nil, err)
	}

	//get login URL
	loginURL, params, err := authImpl.getLoginURL(*authTypeEntity, *appTypeEntity, redirectURI, l)
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
