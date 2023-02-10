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

package web

import (
	"core-building-block/core"
	"core-building-block/core/model"
	Def "core-building-block/driver/web/docs/gen"
	"core-building-block/utils"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"

	"github.com/gorilla/mux"
	"github.com/rokwire/core-auth-library-go/v2/tokenauth"
	"github.com/rokwire/logging-library-go/v2/errors"
	"github.com/rokwire/logging-library-go/v2/logs"
	"github.com/rokwire/logging-library-go/v2/logutils"
)

const (
	actionAdd    logutils.MessageActionType = "adding"
	actionRemove logutils.MessageActionType = "removing"
)

// AdminApisHandler handles the admin rest APIs implementation
type AdminApisHandler struct {
	coreAPIs *core.APIs
}

// getTest TODO get test
func (h AdminApisHandler) getTest(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HTTPResponse {
	res := h.coreAPIs.Administration.AdmGetTest()

	return l.HTTPResponseSuccessMessage(res)
}

// getTestModel gives a test model instance
func (h AdminApisHandler) getTestModel(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HTTPResponse {
	res := h.coreAPIs.Administration.AdmGetTestModel()

	return l.HTTPResponseSuccessMessage(res)
}

func (h AdminApisHandler) login(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HTTPResponse {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionRead, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	//get ip
	ip := utils.GetIP(l, r)
	if err != nil {
		return l.HTTPResponseError("Error getting IP", err, http.StatusInternalServerError, true)
	}

	clientVersion := r.Header.Get("CLIENT_VERSION")

	var requestData Def.SharedReqLogin
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionUnmarshal, logutils.MessageDataType("auth login request"), nil, err, http.StatusBadRequest, true)
	}

	//creds
	requestCreds, err := interfaceToJSON(requestData.Creds)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionMarshal, model.TypeCreds, nil, err, http.StatusBadRequest, true)
	}

	//params
	requestParams, err := interfaceToJSON(requestData.Params)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionMarshal, "params", nil, err, http.StatusBadRequest, true)
	}

	//preferences
	var requestPreferences map[string]interface{}
	if requestData.Preferences != nil {
		requestPreferences = *requestData.Preferences
	}

	//profile ////
	requestProfile := profileFromDefNullable(requestData.Profile)

	username := ""
	if requestData.Username != nil {
		username = *requestData.Username
	}

	//device
	requestDevice := requestData.Device

	message, loginSession, mfaTypes, err := h.coreAPIs.Auth.Login(ip, string(requestDevice.Type), requestDevice.Os, *requestDevice.DeviceId, string(requestData.AuthType),
		requestCreds, requestData.ApiKey, requestData.AppTypeIdentifier, requestData.OrgId, requestParams, &clientVersion, requestProfile, requestPreferences, username, true, l)
	if err != nil {
		loggingErr, ok := err.(*errors.Error)
		if ok && loggingErr.Status() != "" {
			return l.HTTPResponseError("Error logging in", err, http.StatusUnauthorized, true)
		}
		return l.HTTPResponseError("Error logging in", err, http.StatusInternalServerError, true)
	}

	///prepare response

	//message
	if message != nil {
		responseData := &Def.SharedResLogin{Message: message}
		respData, err := json.Marshal(responseData)
		if err != nil {
			return l.HTTPResponseErrorAction(logutils.ActionMarshal, logutils.MessageDataType("auth login response"), nil, err, http.StatusInternalServerError, false)
		}
		return l.HTTPResponseSuccessJSON(respData)
	}

	if loginSession.State != "" {
		//params
		var paramsRes interface{}
		if loginSession.Params != nil {
			paramsRes = loginSession.Params
		}

		mfaResp := mfaDataListToDef(mfaTypes)
		responseData := &Def.SharedResLoginMfa{AccountId: loginSession.Identifier, Enrolled: mfaResp, Params: &paramsRes,
			SessionId: loginSession.ID, State: loginSession.State}
		respData, err := json.Marshal(responseData)
		if err != nil {
			return l.HTTPResponseErrorAction(logutils.ActionMarshal, logutils.MessageDataType("auth login response"), nil, err, http.StatusInternalServerError, false)
		}
		return l.HTTPResponseSuccessJSON(respData)
	}

	return authBuildLoginResponse(l, loginSession)
}

func (h AdminApisHandler) loginMFA(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HTTPResponse {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionRead, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	var mfaData Def.SharedReqLoginMfa
	err = json.Unmarshal(data, &mfaData)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionUnmarshal, logutils.MessageDataType("login mfa request"), nil, err, http.StatusBadRequest, true)
	}

	l.AddContext("account_id", mfaData.AccountId)
	message, loginSession, err := h.coreAPIs.Auth.LoginMFA(mfaData.ApiKey, mfaData.AccountId, mfaData.SessionId, mfaData.Identifier, string(mfaData.Type), mfaData.Code, mfaData.State, l)
	if message != nil {
		return l.HTTPResponseError(*message, err, http.StatusUnauthorized, false)
	}
	if err != nil {
		return l.HTTPResponseError("Error logging in", err, http.StatusInternalServerError, true)
	}

	return authBuildLoginResponse(l, loginSession)
}

func (h AdminApisHandler) loginURL(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HTTPResponse {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionRead, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	var requestData Def.SharedReqLoginUrl
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionUnmarshal, "auth login url request", nil, err, http.StatusBadRequest, true)
	}

	loginURL, params, err := h.coreAPIs.Auth.GetLoginURL(string(requestData.AuthType), requestData.AppTypeIdentifier, requestData.OrgId, requestData.RedirectUri, requestData.ApiKey, l)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionGet, "login url", nil, err, http.StatusInternalServerError, true)
	}

	responseData := &Def.SharedResLoginUrl{LoginUrl: loginURL, Params: &params}
	respData, err := json.Marshal(responseData)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionMarshal, "auth login url response", nil, err, http.StatusInternalServerError, false)
	}

	return l.HTTPResponseSuccessJSON(respData)
}

func (h AdminApisHandler) refresh(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HTTPResponse {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionRead, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	clientVersion := r.Header.Get("CLIENT_VERSION")

	var requestData Def.SharedReqRefresh
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionUnmarshal, logutils.MessageDataType("auth refresh request"), nil, err, http.StatusBadRequest, true)
	}

	loginSession, err := h.coreAPIs.Auth.Refresh(requestData.RefreshToken, requestData.ApiKey, &clientVersion, l)
	if err != nil {
		return l.HTTPResponseError("Error refreshing token", err, http.StatusInternalServerError, true)
	}
	if loginSession == nil {
		//if login session is null then unauthorized
		l.Infof("trying to refresh - %s", requestData.RefreshToken)
		return l.HTTPResponseError(http.StatusText(http.StatusUnauthorized), nil, http.StatusUnauthorized, true)
	}

	accessToken := loginSession.AccessToken
	refreshToken := loginSession.CurrentRefreshToken()
	var paramsRes interface{}
	if loginSession.Params != nil {
		paramsRes = loginSession.Params
	}

	tokenType := Def.SharedResRokwireTokenTokenTypeBearer
	rokwireToken := Def.SharedResRokwireToken{AccessToken: &accessToken, RefreshToken: &refreshToken, TokenType: &tokenType}
	responseData := &Def.SharedResRefresh{Token: &rokwireToken, Params: &paramsRes}
	respData, err := json.Marshal(responseData)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionMarshal, logutils.MessageDataType("auth refresh response"), nil, err, http.StatusInternalServerError, false)
	}

	return l.HTTPResponseSuccessJSON(respData)
}

func (h AdminApisHandler) getServiceRegistrations(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HTTPResponse {
	serviceIDsParam := r.URL.Query().Get("ids")
	if serviceIDsParam == "" {
		return l.HTTPResponseErrorData(logutils.StatusMissing, logutils.TypeQueryParam, logutils.StringArgs("ids"), nil, http.StatusBadRequest, false)
	}
	serviceIDs := strings.Split(serviceIDsParam, ",")

	serviceRegs := h.coreAPIs.Auth.GetServiceRegistrations(serviceIDs)
	serviceRegResp := serviceRegListToDef(serviceRegs)

	data, err := json.Marshal(serviceRegResp)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionMarshal, model.TypeServiceReg, nil, err, http.StatusInternalServerError, false)
	}

	return l.HTTPResponseSuccessJSON(data)
}

func (h AdminApisHandler) getAppConfigs(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HTTPResponse {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionRead, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	var requestData Def.SharedReqAppConfigs
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionUnmarshal, logutils.MessageDataType("application config request"), nil, err, http.StatusBadRequest, true)
	}

	version := model.VersionNumbersFromString(requestData.Version)
	if version == nil {
		return l.HTTPResponseErrorData(logutils.StatusInvalid, model.TypeVersionNumbers, nil, nil, http.StatusBadRequest, false)
	}

	appConfig, err := h.coreAPIs.Administration.AdmGetAppConfig(requestData.AppTypeIdentifier, nil, *version, &requestData.ApiKey)
	if err != nil || appConfig == nil {
		return l.HTTPResponseErrorAction(logutils.ActionGet, model.TypeApplicationConfig, nil, err, http.StatusInternalServerError, true)
	}

	appConfigResp := appConfigToDef(*appConfig)

	response, err := json.Marshal(appConfigResp)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionMarshal, model.TypeApplicationConfig, nil, err, http.StatusInternalServerError, false)
	}

	return l.HTTPResponseSuccessJSON(response)
}

func (h AdminApisHandler) getAppConfigsForOrganization(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HTTPResponse {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionRead, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	var requestData Def.SharedReqAppConfigsOrg
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionUnmarshal, logutils.MessageDataType("application org config request"), nil, err, http.StatusBadRequest, true)
	}

	version := model.VersionNumbersFromString(requestData.Version)
	if version == nil {
		return l.HTTPResponseErrorData(logutils.StatusInvalid, model.TypeVersionNumbers, nil, nil, http.StatusBadRequest, false)
	}

	appConfig, err := h.coreAPIs.Administration.AdmGetAppConfig(requestData.AppTypeIdentifier, &claims.OrgID, *version, nil)
	if err != nil || appConfig == nil {
		return l.HTTPResponseErrorAction(logutils.ActionGet, model.TypeApplicationConfig, nil, err, http.StatusInternalServerError, true)
	}

	appConfigResp := appConfigToDef(*appConfig)

	response, err := json.Marshal(appConfigResp)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionMarshal, model.TypeApplicationConfig, nil, err, http.StatusInternalServerError, false)
	}

	return l.HTTPResponseSuccessJSON(response)
}

func (h AdminApisHandler) getApplications(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HTTPResponse {
	applications, err := h.coreAPIs.Administration.AdmGetApplications(claims.OrgID)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionGet, model.TypeApplication, nil, err, http.StatusInternalServerError, true)
	}

	response := applicationsToDef(applications)

	data, err := json.Marshal(response)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionMarshal, model.TypeApplication, nil, err, http.StatusInternalServerError, false)
	}
	return l.HTTPResponseSuccessJSON(data)
}

func (h AdminApisHandler) getApplicationGroups(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HTTPResponse {

	get, err := h.coreAPIs.Administration.AdmGetAppOrgGroups(claims.AppID, claims.OrgID)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionGet, model.TypeApplicationOrganization, nil, err, http.StatusInternalServerError, true)
	}

	response := appOrgGroupsToDef(get)

	data, err := json.Marshal(response)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionMarshal, model.TypeAppOrgGroup, nil, err, http.StatusInternalServerError, false)
	}
	return l.HTTPResponseSuccessJSON(data)
}

func (h AdminApisHandler) getApplicationPermissions(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HTTPResponse {
	permissions, err := h.coreAPIs.Administration.AdmGetApplicationPermissions(claims.AppID, claims.OrgID, l)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionGet, model.TypeApplicationOrganization, nil, err, http.StatusInternalServerError, true)
	}

	response := applicationPermissionsToDef(permissions)

	data, err := json.Marshal(response)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionMarshal, model.TypePermission, nil, err, http.StatusInternalServerError, false)
	}
	return l.HTTPResponseSuccessJSON(data)
}

func (h AdminApisHandler) getApplicationRoles(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HTTPResponse {
	appOrgRoles, err := h.coreAPIs.Administration.AdmGetAppOrgRoles(claims.AppID, claims.OrgID)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionGet, model.TypeApplicationOrganization, nil, err, http.StatusInternalServerError, true)
	}

	response := appOrgRolesToDef(appOrgRoles)

	data, err := json.Marshal(response)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionMarshal, model.TypeAppOrgRole, nil, err, http.StatusInternalServerError, false)
	}

	return l.HTTPResponseSuccessJSON(data)
}

func (h AdminApisHandler) getApplicationAccounts(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HTTPResponse {
	var err error

	//limit and offset
	limit := 20
	limitArg := r.URL.Query().Get("limit")
	if limitArg != "" {
		limit, err = strconv.Atoi(limitArg)
		if err != nil {
			return l.HTTPResponseErrorAction(logutils.ActionParse, logutils.TypeArg, logutils.StringArgs("limit"), err, http.StatusBadRequest, false)
		}
	}
	offset := 0
	offsetArg := r.URL.Query().Get("offset")
	if offsetArg != "" {
		offset, err = strconv.Atoi(offsetArg)
		if err != nil {
			return l.HTTPResponseErrorAction(logutils.ActionParse, logutils.TypeArg, logutils.StringArgs("offset"), err, http.StatusBadRequest, false)
		}
	}

	//account ID
	var accountID *string
	accountIDParam := r.URL.Query().Get("account-id")
	if len(accountIDParam) > 0 {
		accountID = &accountIDParam
	}
	//first name
	var firstName *string
	firstNameParam := r.URL.Query().Get("firstname")
	if len(firstNameParam) > 0 {
		firstName = &firstNameParam
	}
	//last name
	var lastName *string
	lastNameParam := r.URL.Query().Get("lastname")
	if len(lastNameParam) > 0 {
		lastName = &lastNameParam
	}
	//auth type
	var authType *string
	authTypeParam := r.URL.Query().Get("auth-type")
	if len(authTypeParam) > 0 {
		authType = &authTypeParam
	}
	//auth type identifier
	var authTypeIdentifier *string
	authTypeIdentifierParam := r.URL.Query().Get("auth-type-identifier")
	if len(authTypeIdentifierParam) > 0 {
		authTypeIdentifier = &authTypeIdentifierParam
	}

	//admin
	var hasPermissions *bool
	hasPermissionsArg := r.URL.Query().Get("has-permissions")
	if hasPermissionsArg != "" {
		hasPermissionsVal, err := strconv.ParseBool(hasPermissionsArg)
		if err != nil {
			return l.HTTPResponseErrorAction(logutils.ActionParse, logutils.TypeArg, logutils.StringArgs("has-permissions"), err, http.StatusBadRequest, false)
		}
		hasPermissions = &hasPermissionsVal
	}
	//anonymous
	var anonymous *bool
	anonymousArg := r.URL.Query().Get("anonymous")
	if anonymousArg != "" {
		anonymousVal, err := strconv.ParseBool(anonymousArg)
		if err != nil {
			return l.HTTPResponseErrorAction(logutils.ActionParse, logutils.TypeArg, logutils.StringArgs("anonymous"), err, http.StatusBadRequest, false)
		}
		anonymous = &anonymousVal
	}
	//permissions
	var permissions []string
	permissionsArg := r.URL.Query().Get("permissions")
	if permissionsArg != "" {
		permissions = strings.Split(permissionsArg, ",")
	}
	//roleIDs
	var roleIDs []string
	rolesArg := r.URL.Query().Get("role-ids")
	if rolesArg != "" {
		roleIDs = strings.Split(rolesArg, ",")
	}
	//groupIDs
	var groupIDs []string
	groupsArg := r.URL.Query().Get("group-ids")
	if groupsArg != "" {
		groupIDs = strings.Split(groupsArg, ",")
	}

	accounts, err := h.coreAPIs.Administration.AdmGetAccounts(limit, offset, claims.AppID, claims.OrgID, accountID, firstName, lastName, authType, authTypeIdentifier, anonymous, hasPermissions, permissions, roleIDs, groupIDs)
	if err != nil {
		return l.HTTPResponseErrorAction("error finding accounts", model.TypeAccount, nil, err, http.StatusInternalServerError, true)
	}

	response := partialAccountsToDef(accounts)

	data, err := json.Marshal(response)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionMarshal, model.TypeAccount, nil, err, http.StatusInternalServerError, false)
	}
	return l.HTTPResponseSuccessJSON(data)
}

func (h AdminApisHandler) getApplicationLoginSessions(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HTTPResponse {
	identifierFromQuery := r.URL.Query().Get("identifier")
	var identifier *string
	if len(identifierFromQuery) > 0 {
		identifier = &identifierFromQuery
	}

	accountAuthTypeIdentifierFromQuery := r.URL.Query().Get("account-auth-type-identifier")
	var accountAuthTypeIdentifier *string
	if len(accountAuthTypeIdentifierFromQuery) > 0 {
		accountAuthTypeIdentifier = &accountAuthTypeIdentifierFromQuery
	}

	appTypeIDFromQuery := r.URL.Query().Get("app-type-id")
	var appTypeID *string
	if len(appTypeIDFromQuery) > 0 {
		appTypeID = &appTypeIDFromQuery
	}

	appTypeIdentifierFromQuery := r.URL.Query().Get("app-type-identifier")
	var appTypeIdentifier *string
	if len(appTypeIdentifierFromQuery) > 0 {
		appTypeIdentifier = &appTypeIdentifierFromQuery
	}

	anonymousFromQuery := r.URL.Query().Get("anonymous")
	var anonymous *bool
	if len(anonymousFromQuery) > 0 {
		result, _ := strconv.ParseBool(anonymousFromQuery)
		anonymous = &result
	}

	deviceIDFromQuery := r.URL.Query().Get("device-id")
	var deviceID *string
	if len(deviceIDFromQuery) > 0 {
		deviceID = &deviceIDFromQuery
	}

	ipAddressFromQuery := r.URL.Query().Get("ip-address")
	var ipAddress *string
	if len(ipAddressFromQuery) > 0 {
		ipAddress = &ipAddressFromQuery
	}

	getLoginSessions, err := h.coreAPIs.Administration.AdmGetApplicationLoginSessions(claims.AppID, claims.OrgID, identifier, accountAuthTypeIdentifier, appTypeID,
		appTypeIdentifier, anonymous, deviceID, ipAddress)
	if err != nil {
		return l.HTTPResponseErrorAction("error finding login sessions", model.TypeLoginSession, nil, err, http.StatusInternalServerError, true)
	}

	loginSessions := loginSessionsToDef(getLoginSessions)

	data, err := json.Marshal(loginSessions)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionMarshal, model.TypeLoginSession, nil, err, http.StatusInternalServerError, false)
	}
	return l.HTTPResponseSuccessJSON(data)
}

func (h AdminApisHandler) getAccount(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HTTPResponse {
	account, err := h.coreAPIs.Administration.AdmGetAccount(claims.Subject)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionGet, model.TypeAccount, nil, err, http.StatusInternalServerError, true)
	}

	var accountData *Def.Account
	if account != nil {
		account.SortAccountAuthTypes(claims.UID)
		accountData = accountToDef(*account)
	}

	data, err := json.Marshal(accountData)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionMarshal, model.TypeAccount, nil, err, http.StatusInternalServerError, false)
	}

	return l.HTTPResponseSuccessJSON(data)
}

func (h AdminApisHandler) createAdminAccount(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HTTPResponse {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionRead, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	clientVersion := r.Header.Get("CLIENT_VERSION")

	var requestData Def.SharedReqCreateAccount
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionUnmarshal, logutils.MessageDataType("create account request"), nil, err, http.StatusBadRequest, true)
	}

	var permissions []string
	if requestData.Permissions != nil {
		permissions = *requestData.Permissions
	}
	var roleIDs []string
	if requestData.RoleIds != nil {
		roleIDs = *requestData.RoleIds
	}
	var groupIDs []string
	if requestData.GroupIds != nil {
		groupIDs = *requestData.GroupIds
	}
	profile := profileFromDefNullable(requestData.Profile)

	username := ""
	if requestData.Username != nil {
		username = *requestData.Username
	}

	creatorPermissions := strings.Split(claims.Permissions, ",")
	account, params, err := h.coreAPIs.Auth.CreateAdminAccount(string(requestData.AuthType), claims.AppID, claims.OrgID,
		requestData.Identifier, profile, username, permissions, roleIDs, groupIDs, creatorPermissions, &clientVersion, l)
	if err != nil || account == nil {
		return l.HTTPResponseErrorAction(logutils.ActionCreate, model.TypeAccount, nil, err, http.StatusInternalServerError, true)
	}

	respData := partialAccountToDef(*account, params)

	data, err = json.Marshal(respData)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionMarshal, model.TypeAccount, nil, err, http.StatusInternalServerError, false)
	}

	return l.HTTPResponseSuccessJSON(data)
}

func (h AdminApisHandler) updateAdminAccount(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HTTPResponse {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionRead, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	var requestData Def.SharedReqUpdateAccount
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionUnmarshal, logutils.MessageDataType("update account request"), nil, err, http.StatusBadRequest, true)
	}

	var permissions []string
	if requestData.Permissions != nil {
		permissions = *requestData.Permissions
	}
	var roleIDs []string
	if requestData.RoleIds != nil {
		roleIDs = *requestData.RoleIds
	}
	var groupIDs []string
	if requestData.GroupIds != nil {
		groupIDs = *requestData.GroupIds
	}
	updaterPermissions := strings.Split(claims.Permissions, ",")
	account, params, err := h.coreAPIs.Auth.UpdateAdminAccount(string(requestData.AuthType), claims.AppID, claims.OrgID, requestData.Identifier,
		permissions, roleIDs, groupIDs, updaterPermissions, l)
	if err != nil || account == nil {
		return l.HTTPResponseErrorAction(logutils.ActionUpdate, model.TypeAccount, nil, err, http.StatusInternalServerError, true)
	}

	respData := partialAccountToDef(*account, params)

	data, err = json.Marshal(respData)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionMarshal, model.TypeAccount, nil, err, http.StatusInternalServerError, false)
	}

	return l.HTTPResponseSuccessJSON(data)
}

func (h AdminApisHandler) getMFATypes(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HTTPResponse {
	mfaDataList, err := h.coreAPIs.Auth.GetMFATypes(claims.Subject)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionGet, model.TypeMFAType, nil, err, http.StatusInternalServerError, true)
	}

	mfaResp := mfaDataListToDef(mfaDataList)

	data, err := json.Marshal(mfaResp)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionMarshal, model.TypeMFAType, nil, err, http.StatusInternalServerError, false)
	}

	return l.HTTPResponseSuccessJSON(data)
}

func (h AdminApisHandler) addMFAType(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HTTPResponse {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionRead, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	var mfaData Def.SharedReqMfa
	err = json.Unmarshal(data, &mfaData)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionUnmarshal, logutils.MessageDataType("add mfa request"), nil, err, http.StatusBadRequest, true)
	}

	mfa, err := h.coreAPIs.Auth.AddMFAType(claims.Subject, mfaData.Identifier, string(mfaData.Type))
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionInsert, model.TypeMFAType, nil, err, http.StatusInternalServerError, true)
	}

	mfaResp := mfaDataToDef(mfa)

	respData, err := json.Marshal(mfaResp)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionMarshal, model.TypeMFAType, nil, err, http.StatusInternalServerError, false)
	}

	return l.HTTPResponseSuccessJSON(respData)
}

func (h AdminApisHandler) removeMFAType(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HTTPResponse {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionRead, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	var mfaData Def.SharedReqMfa
	err = json.Unmarshal(data, &mfaData)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionUnmarshal, logutils.MessageDataType("remove mfa request"), nil, err, http.StatusBadRequest, true)
	}

	err = h.coreAPIs.Auth.RemoveMFAType(claims.Subject, mfaData.Identifier, string(mfaData.Type))
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionDelete, model.TypeMFAType, nil, err, http.StatusInternalServerError, true)
	}

	return l.HTTPResponseSuccess()
}

func (h AdminApisHandler) verifyMFA(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HTTPResponse {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionRead, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	var mfaData Def.SharedReqMfa
	err = json.Unmarshal(data, &mfaData)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionUnmarshal, logutils.MessageDataType("verify mfa request"), nil, err, http.StatusBadRequest, true)
	}

	if mfaData.Code == nil || *mfaData.Code == "" {
		return l.HTTPResponseErrorData(logutils.StatusMissing, "mfa code", nil, nil, http.StatusBadRequest, true)
	}

	message, recoveryCodes, err := h.coreAPIs.Auth.VerifyMFA(claims.Subject, mfaData.Identifier, string(mfaData.Type), *mfaData.Code)
	if message != nil {
		return l.HTTPResponseError(*message, nil, http.StatusBadRequest, true)
	}
	if err != nil {
		return l.HTTPResponseError("Error verifying MFA", err, http.StatusInternalServerError, true)
	}

	if recoveryCodes == nil {
		recoveryCodes = []string{}
	}

	response, err := json.Marshal(recoveryCodes)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionMarshal, "mfa recovery codes", nil, err, http.StatusInternalServerError, false)
	}

	return l.HTTPResponseSuccessJSON(response)
}

func (h AdminApisHandler) updateAccountUsername(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HTTPResponse {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionRead, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	var username Def.Username
	err = json.Unmarshal(data, &username)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionUnmarshal, model.TypeAccountUsername, nil, err, http.StatusBadRequest, true)
	}

	err = h.coreAPIs.Administration.AdmUpdateAccountUsername(claims.Subject, claims.AppID, claims.OrgID, username.Username)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionUpdate, model.TypeAccountUsername, nil, err, http.StatusInternalServerError, true)
	}

	return l.HTTPResponseSuccess()
}

func (h AdminApisHandler) getAppToken(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HTTPResponse {
	appID := r.URL.Query().Get("app_id")
	if appID == "" {
		return l.HTTPResponseErrorData(logutils.StatusMissing, logutils.TypeQueryParam, logutils.StringArgs("app_id"), nil, http.StatusBadRequest, false)
	}

	token, err := h.coreAPIs.Auth.GetAdminToken(*claims, appID, claims.OrgID, l)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionGet, "app token", nil, err, http.StatusInternalServerError, true)
	}

	response := Def.AdminToken{Token: token}
	responseJSON, err := json.Marshal(response)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionMarshal, "app token", nil, err, http.StatusInternalServerError, false)
	}

	return l.HTTPResponseSuccessJSON(responseJSON)
}

// createApplicationGroup creates an application group
func (h AdminApisHandler) createApplicationGroup(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HTTPResponse {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionRead, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}
	var requestData Def.AdminReqApplicationGroup
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionUnmarshal, model.TypeAppOrgGroup, nil, err, http.StatusBadRequest, true)
	}

	//system flag
	system := false
	if requestData.System != nil {
		system = *requestData.System
	}

	//permissions names
	var permissionNames []string
	if requestData.Permissions != nil {
		permissionNames = *requestData.Permissions
	}

	//roles ids
	var rolesIDs []string
	if requestData.Roles != nil {
		rolesIDs = *requestData.Roles
	}

	//account ids
	var accountIDs []string
	if requestData.AccountIds != nil {
		accountIDs = *requestData.AccountIds
	}

	if len(permissionNames) == 0 && len(rolesIDs) == 0 {
		return l.HTTPResponseErrorData(logutils.StatusMissing, "permissions and application organization roles", nil, nil, http.StatusBadRequest, false)
	}

	assignerPermissions := strings.Split(claims.Permissions, ",")
	group, err := h.coreAPIs.Administration.AdmCreateAppOrgGroup(requestData.Name, requestData.Description, system, permissionNames, rolesIDs, accountIDs, claims.AppID, claims.OrgID, assignerPermissions, claims.System, l)
	if err != nil || group == nil {
		return l.HTTPResponseErrorAction(logutils.ActionCreate, model.TypeAppOrgGroup, nil, err, http.StatusInternalServerError, true)
	}

	respGroup := appOrgGroupToDef(*group)
	response, err := json.Marshal(respGroup)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionMarshal, model.TypeAppOrgGroup, nil, err, http.StatusInternalServerError, false)
	}
	return l.HTTPResponseSuccessJSON(response)
}

// updateApplicationGroup updates an application group
func (h AdminApisHandler) updateApplicationGroup(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HTTPResponse {
	params := mux.Vars(r)
	groupID := params["id"]
	if len(groupID) <= 0 {
		return l.HTTPResponseErrorData(logutils.StatusMissing, logutils.TypeQueryParam, logutils.StringArgs("id"), nil, http.StatusBadRequest, false)
	}

	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionRead, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}
	var requestData Def.AdminReqApplicationGroup
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionUnmarshal, model.TypeAppOrgGroup, nil, err, http.StatusBadRequest, true)
	}

	//system flag
	system := false
	if requestData.System != nil {
		system = *requestData.System
	}

	//permissions names
	var permissionNames []string
	if requestData.Permissions != nil {
		permissionNames = *requestData.Permissions
	}

	//roles ids
	var rolesIDs []string
	if requestData.Roles != nil {
		rolesIDs = *requestData.Roles
	}

	//account ids
	var accountIDs []string
	if requestData.AccountIds != nil {
		accountIDs = *requestData.AccountIds
	}

	if len(permissionNames) == 0 && len(rolesIDs) == 0 {
		return l.HTTPResponseErrorData(logutils.StatusMissing, "permissions and application organization roles", nil, nil, http.StatusBadRequest, false)
	}

	assignerPermissions := strings.Split(claims.Permissions, ",")
	group, err := h.coreAPIs.Administration.AdmUpdateAppOrgGroup(groupID, requestData.Name, requestData.Description, system, permissionNames, rolesIDs, accountIDs, claims.AppID, claims.OrgID, assignerPermissions, claims.System, l)
	if err != nil || group == nil {
		return l.HTTPResponseErrorAction(logutils.ActionUpdate, model.TypeAppOrgGroup, nil, err, http.StatusInternalServerError, true)
	}

	respGroup := appOrgGroupToDef(*group)
	response, err := json.Marshal(respGroup)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionMarshal, model.TypeAppOrgGroup, nil, err, http.StatusInternalServerError, false)
	}
	return l.HTTPResponseSuccessJSON(response)
}

func (h AdminApisHandler) deleteApplicationGroup(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HTTPResponse {
	params := mux.Vars(r)
	groupsID := params["id"]
	if len(groupsID) <= 0 {
		return l.HTTPResponseErrorData(logutils.StatusMissing, logutils.TypeQueryParam, logutils.StringArgs("id"), nil, http.StatusBadRequest, false)
	}

	assignerPermissions := strings.Split(claims.Permissions, ",")
	err := h.coreAPIs.Administration.AdmDeleteAppOrgGroup(groupsID, claims.AppID, claims.OrgID, assignerPermissions, claims.System, l)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionDelete, model.TypeAppOrgGroup, nil, err, http.StatusInternalServerError, true)
	}
	return l.HTTPResponseSuccess()
}

// addAccountsToGroup adds a group the given account
func (h AdminApisHandler) addAccountsToGroup(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HTTPResponse {
	params := mux.Vars(r)
	groupID := params["id"]
	if len(groupID) <= 0 {
		return l.HTTPResponseErrorData(logutils.StatusMissing, logutils.TypeQueryParam, logutils.StringArgs("id"), nil, http.StatusBadRequest, false)
	}

	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionRead, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	var requestData Def.AdminReqAddAccountsToGroup
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionUnmarshal, model.TypeAccount, nil, err, http.StatusBadRequest, true)
	}

	assignerPermissions := strings.Split(claims.Permissions, ",")
	err = h.coreAPIs.Administration.AdmAddAccountsToGroup(claims.AppID, claims.OrgID, groupID, requestData.AccountIds, assignerPermissions, l)
	if err != nil {
		return l.HTTPResponseErrorAction(actionAdd, model.TypeAccount, nil, err, http.StatusInternalServerError, true)
	}

	return l.HTTPResponseSuccess()
}

// removeAccountsFromGroup removes accounts from a given group
func (h AdminApisHandler) removeAccountsFromGroup(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HTTPResponse {
	params := mux.Vars(r)
	groupID := params["id"]
	if len(groupID) <= 0 {
		return l.HTTPResponseErrorData(logutils.StatusMissing, logutils.TypeQueryParam, logutils.StringArgs("id"), nil, http.StatusBadRequest, false)
	}

	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionRead, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	var requestData Def.AdminReqRemoveAccountFromGroup
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionUnmarshal, model.TypeAppOrgGroup, nil, err, http.StatusBadRequest, true)
	}

	assignerPermissions := strings.Split(claims.Permissions, ",")
	err = h.coreAPIs.Administration.AdmRemoveAccountsFromGroup(claims.AppID, claims.OrgID, groupID, requestData.AccountIds, assignerPermissions, l)
	if err != nil {
		return l.HTTPResponseErrorAction(actionRemove, model.TypeAccount, nil, err, http.StatusInternalServerError, true)
	}

	return l.HTTPResponseSuccess()
}

// createApplicationRole creates an application role
func (h AdminApisHandler) createApplicationRole(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HTTPResponse {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionRead, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	var requestData Def.AdminReqApplicationRole
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionUnmarshal, model.TypeAppOrgRole, nil, err, http.StatusBadRequest, true)
	}

	system := false
	if requestData.System != nil {
		system = *requestData.System
	}
	assignerPermissions := strings.Split(claims.Permissions, ",")
	role, err := h.coreAPIs.Administration.AdmCreateAppOrgRole(requestData.Name, requestData.Description, system, requestData.Permissions, claims.AppID, claims.OrgID, assignerPermissions, claims.System, l)
	if err != nil || role == nil {
		return l.HTTPResponseErrorAction(logutils.ActionGet, model.TypeAppOrgRole, nil, err, http.StatusInternalServerError, true)
	}

	respRole := appOrgRoleToDef(*role)
	response, err := json.Marshal(respRole)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionMarshal, model.TypeAppOrgRole, nil, err, http.StatusInternalServerError, false)
	}

	return l.HTTPResponseSuccessJSON(response)
}

func (h AdminApisHandler) updateApplicationRole(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HTTPResponse {
	params := mux.Vars(r)
	rolesID := params["id"]
	if len(rolesID) <= 0 {
		return l.HTTPResponseErrorData(logutils.StatusMissing, logutils.TypeQueryParam, logutils.StringArgs("id"), nil, http.StatusBadRequest, false)
	}

	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionRead, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	var requestData Def.AdminReqApplicationRole
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionUnmarshal, model.TypeAppOrgRole, nil, err, http.StatusBadRequest, true)
	}

	system := false
	if requestData.System != nil {
		system = *requestData.System
	}
	assignerPermissions := strings.Split(claims.Permissions, ",")
	role, err := h.coreAPIs.Administration.AdmUpdateAppOrgRole(rolesID, requestData.Name, requestData.Description, system, requestData.Permissions, claims.AppID, claims.OrgID, assignerPermissions, claims.System, l)
	if err != nil || role == nil {
		return l.HTTPResponseErrorAction(logutils.ActionUpdate, model.TypeAppOrgRole, nil, err, http.StatusInternalServerError, true)
	}

	respRole := appOrgRoleToDef(*role)
	response, err := json.Marshal(respRole)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionMarshal, model.TypeAppOrgRole, nil, err, http.StatusInternalServerError, false)
	}

	return l.HTTPResponseSuccessJSON(response)
}

func (h AdminApisHandler) deleteApplicationRole(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HTTPResponse {
	params := mux.Vars(r)
	rolesID := params["id"]
	if len(rolesID) <= 0 {
		return l.HTTPResponseErrorData(logutils.StatusMissing, logutils.TypeQueryParam, logutils.StringArgs("id"), nil, http.StatusBadRequest, false)
	}

	assignerPermissions := strings.Split(claims.Permissions, ",")
	err := h.coreAPIs.Administration.AdmDeleteAppOrgRole(rolesID, claims.AppID, claims.OrgID, assignerPermissions, claims.System, l)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionDelete, model.TypeAppOrgRole, nil, err, http.StatusInternalServerError, true)
	}
	return l.HTTPResponseSuccess()
}

func (h AdminApisHandler) deleteApplicationLoginSession(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HTTPResponse {
	params := mux.Vars(r)
	identifier := params["account_id"]
	if len(identifier) <= 0 {
		return l.HTTPResponseErrorData(logutils.StatusMissing, logutils.TypeQueryParam, logutils.StringArgs("account_id"), nil, http.StatusBadRequest, false)
	}

	params2 := mux.Vars(r)
	sessionID := params2["session_id"]
	if len(sessionID) <= 0 {
		return l.HTTPResponseErrorData(logutils.StatusMissing, logutils.TypeQueryParam, logutils.StringArgs("session_id"), nil, http.StatusBadRequest, false)
	}

	err := h.coreAPIs.Administration.AdmDeleteApplicationLoginSession(claims.AppID, claims.OrgID, claims.Subject, identifier, sessionID, l)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionDelete, model.TypeLoginSession, nil, err, http.StatusInternalServerError, true)
	}
	return l.HTTPResponseSuccess()
}

func (h AdminApisHandler) getApplicationAccountDevices(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HTTPResponse {
	params := mux.Vars(r)
	accountID := params["id"]
	if len(accountID) <= 0 {
		return l.HTTPResponseErrorData(logutils.StatusMissing, logutils.TypeQueryParam, logutils.StringArgs("id"), nil, http.StatusBadRequest, false)
	}

	if len(accountID) <= 0 {
		return l.HTTPResponseErrorData(logutils.StatusMissing, logutils.TypeQueryParam, logutils.StringArgs("id"), nil, http.StatusBadRequest, false)
	}
	devices, err := h.coreAPIs.Administration.AdmGetApplicationAccountDevices(claims.AppID, claims.OrgID, accountID, l)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionGet, model.TypeDevice, nil, err, http.StatusInternalServerError, true)
	}

	devicesRes := deviceListToDef(devices)
	data, err := json.Marshal(devicesRes)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionMarshal, model.TypeApplication, nil, err, http.StatusInternalServerError, false)
	}
	return l.HTTPResponseSuccessJSON(data)
}

// grantAccountPermissions grants an account the given permissions
func (h AdminApisHandler) grantAccountPermissions(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HTTPResponse {
	params := mux.Vars(r)
	accountID := params["id"]
	if len(accountID) <= 0 {
		return l.HTTPResponseErrorData(logutils.StatusMissing, logutils.TypeQueryParam, logutils.StringArgs("id"), nil, http.StatusBadRequest, false)
	}

	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionRead, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	var requestData Def.AdminReqGrantPermissions
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionUnmarshal, model.TypePermission, nil, err, http.StatusBadRequest, true)
	}

	assignerPermissions := strings.Split(claims.Permissions, ",")
	err = h.coreAPIs.Administration.AdmGrantAccountPermissions(claims.AppID, claims.OrgID, accountID, requestData.Permissions, assignerPermissions, l)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionGrant, model.TypePermission, nil, err, http.StatusInternalServerError, true)
	}

	return l.HTTPResponseSuccess()
}

// revokeAccountPermissions removes permissions from an account
func (h AdminApisHandler) revokeAccountPermissions(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HTTPResponse {
	params := mux.Vars(r)
	accountID := params["id"]
	if len(accountID) <= 0 {
		return l.HTTPResponseErrorData(logutils.StatusMissing, logutils.TypeQueryParam, logutils.StringArgs("id"), nil, http.StatusBadRequest, false)
	}

	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionRead, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}
	var requestData Def.AdminReqRevokePermissions
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionUnmarshal, model.TypePermission, nil, err, http.StatusBadRequest, true)
	}

	assignerPermissions := strings.Split(claims.Permissions, ",")
	err = h.coreAPIs.Administration.AdmRevokeAccountPermissions(claims.AppID, claims.OrgID, accountID, requestData.Permissions, assignerPermissions, l)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionRevoke, model.TypePermission, nil, err, http.StatusInternalServerError, true)
	}

	return l.HTTPResponseSuccess()
}

// grantAccountRoles grants an account the given roles
func (h AdminApisHandler) grantAccountRoles(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HTTPResponse {
	params := mux.Vars(r)
	accountID := params["id"]
	if len(accountID) <= 0 {
		return l.HTTPResponseErrorData(logutils.StatusMissing, logutils.TypeQueryParam, logutils.StringArgs("id"), nil, http.StatusBadRequest, false)
	}

	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionRead, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	var requestData Def.AdminReqGrantRolesToAccount
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionUnmarshal, model.TypeAppOrgRole, nil, err, http.StatusBadRequest, true)
	}

	assignerPermissions := strings.Split(claims.Permissions, ",")
	err = h.coreAPIs.Administration.AdmGrantAccountRoles(claims.AppID, claims.OrgID, accountID, requestData.RoleIds, assignerPermissions, l)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionGrant, model.TypeAppOrgRole, nil, err, http.StatusInternalServerError, true)
	}

	return l.HTTPResponseSuccess()
}

// revokeAccountRoles removes role from a given account
func (h AdminApisHandler) revokeAccountRoles(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HTTPResponse {
	params := mux.Vars(r)
	accountID := params["id"]
	if len(accountID) <= 0 {
		return l.HTTPResponseErrorData(logutils.StatusMissing, logutils.TypeQueryParam, logutils.StringArgs("id"), nil, http.StatusBadRequest, false)
	}

	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionRead, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	var requestData Def.AdminReqRevokeRolesFromAccount
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionUnmarshal, model.TypeAppOrgRole, nil, err, http.StatusBadRequest, true)
	}

	assignerPermissions := strings.Split(claims.Permissions, ",")
	err = h.coreAPIs.Administration.AdmRevokeAccountRoles(claims.AppID, claims.OrgID, accountID, requestData.RoleIds, assignerPermissions, l)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionRevoke, model.TypeAppOrgRole, nil, err, http.StatusInternalServerError, true)
	}

	return l.HTTPResponseSuccess()
}

// getAccountSystemConfigs returns the system configs for a specific account
func (h AdminApisHandler) getAccountSystemConfigs(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HTTPResponse {
	params := mux.Vars(r)
	accountID := params["id"]
	if len(accountID) <= 0 {
		return l.HTTPResponseErrorData(logutils.StatusMissing, logutils.TypeQueryParam, logutils.StringArgs("id"), nil, http.StatusBadRequest, false)
	}

	configs, err := h.coreAPIs.Administration.AdmGetAccountSystemConfigs(claims.AppID, claims.OrgID, accountID, l)
	if err != nil {
		loggingErr, ok := err.(*errors.Error)
		if ok && loggingErr.Status() == utils.ErrorStatusNotAllowed {
			return l.HTTPResponseError(http.StatusText(http.StatusForbidden), nil, http.StatusForbidden, false)
		}
		return l.HTTPResponseErrorAction(logutils.ActionGet, model.TypeAccountSystemConfigs, nil, err, http.StatusInternalServerError, true)
	}

	response := configs

	data, err := json.Marshal(response)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionMarshal, model.TypeAccountSystemConfigs, nil, err, http.StatusInternalServerError, false)
	}

	return l.HTTPResponseSuccessJSON(data)
}

// updateAccountSystemConfigs updates the system config for a specific account
func (h AdminApisHandler) updateAccountSystemConfigs(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HTTPResponse {
	params := mux.Vars(r)
	accountID := params["id"]
	if len(accountID) <= 0 {
		return l.HTTPResponseErrorData(logutils.StatusMissing, logutils.TypeQueryParam, logutils.StringArgs("id"), nil, http.StatusBadRequest, false)
	}

	var createAnonymous bool
	createAnonymousArg := r.URL.Query().Get("create-anonymous")
	if createAnonymousArg != "" {
		createAnonymous, _ = strconv.ParseBool(createAnonymousArg)
	}

	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionRead, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	var configs map[string]interface{}
	err = json.Unmarshal(data, &configs)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionUnmarshal, "system configs update request", nil, err, http.StatusBadRequest, true)
	}

	created, err := h.coreAPIs.Administration.AdmUpdateAccountSystemConfigs(claims.AppID, claims.OrgID, accountID, configs, createAnonymous, l)
	if err != nil {
		loggingErr, ok := err.(*errors.Error)
		if ok && loggingErr.Status() == utils.ErrorStatusNotAllowed {
			return l.HTTPResponseError(http.StatusText(http.StatusForbidden), nil, http.StatusForbidden, false)
		}
		return l.HTTPResponseErrorAction(logutils.ActionUpdate, model.TypeAccountSystemConfigs, nil, err, http.StatusInternalServerError, true)
	}

	if created {
		return l.HTTPResponseSuccessMessage("Created new anonymous account with ID " + accountID)
	}

	return l.HTTPResponseSuccess()
}

// grantPermissionsToRole grants a role the given permission
func (h AdminApisHandler) grantPermissionsToRole(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HTTPResponse {
	params := mux.Vars(r)
	roleID := params["id"]
	if len(roleID) <= 0 {
		return l.HTTPResponseErrorData(logutils.StatusMissing, logutils.TypeQueryParam, logutils.StringArgs("id"), nil, http.StatusBadRequest, false)
	}

	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionRead, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	var requestData Def.AdminReqGrantPermissionsToRole
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionUnmarshal, model.TypeAppOrgRole, nil, err, http.StatusBadRequest, true)
	}

	assignerPermissions := strings.Split(claims.Permissions, ",")
	err = h.coreAPIs.Administration.AdmGrantPermissionsToRole(claims.AppID, claims.OrgID, roleID, requestData.Permissions, assignerPermissions, claims.System, l)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionGrant, model.TypePermission, nil, err, http.StatusInternalServerError, true)
	}

	return l.HTTPResponseSuccess()
}

// NewAdminApisHandler creates new admin rest Handler instance
func NewAdminApisHandler(coreAPIs *core.APIs) AdminApisHandler {
	return AdminApisHandler{coreAPIs: coreAPIs}
}
