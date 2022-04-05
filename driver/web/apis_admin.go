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
	"github.com/rokwire/core-auth-library-go/tokenauth"
	"github.com/rokwire/logging-library-go/errors"
	"github.com/rokwire/logging-library-go/logs"
	"github.com/rokwire/logging-library-go/logutils"
)

const (
	actionGrant logutils.MessageActionType = "granting"
)

//AdminApisHandler handles the admin rest APIs implementation
type AdminApisHandler struct {
	coreAPIs *core.APIs
}

//getTest TODO get test
func (h AdminApisHandler) getTest(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	res := h.coreAPIs.Administration.AdmGetTest()

	return l.HttpResponseSuccessMessage(res)
}

//getTestModel gives a test model instance
func (h AdminApisHandler) getTestModel(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	res := h.coreAPIs.Administration.AdmGetTestModel()

	return l.HttpResponseSuccessMessage(res)
}

func (h AdminApisHandler) adminLogin(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionRead, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	//get ip
	ip := utils.GetIP(l, r)
	if err != nil {
		return l.HttpResponseError("Error getting IP", err, http.StatusInternalServerError, true)
	}

	var requestData Def.SharedReqLogin
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionUnmarshal, logutils.MessageDataType("auth login request"), nil, err, http.StatusBadRequest, true)
	}

	//creds
	requestCreds, err := interfaceToJSON(requestData.Creds)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionMarshal, model.TypeCreds, nil, err, http.StatusBadRequest, true)
	}

	//params
	requestParams, err := interfaceToJSON(requestData.Params)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionMarshal, "params", nil, err, http.StatusBadRequest, true)
	}

	//preferences
	var requestPreferences map[string]interface{}
	if requestData.Preferences != nil {
		requestPreferences = *requestData.Preferences
	}

	//profile ////
	requestProfile := profileFromDefNullable(requestData.Profile)

	//device
	requestDevice := requestData.Device

	message, loginSession, mfaTypes, err := h.coreAPIs.Auth.Login(ip, string(requestDevice.Type), requestDevice.Os, *requestDevice.DeviceId,
		string(requestData.AuthType), requestCreds, requestData.ApiKey, requestData.AppTypeIdentifier, requestData.OrgId, requestParams, requestProfile, requestPreferences, true, l)
	if err != nil {
		loggingErr, ok := err.(*errors.Error)
		if ok && loggingErr.Status() != "" {
			return l.HttpResponseError("Error logging in", err, http.StatusUnauthorized, true)
		}
		return l.HttpResponseError("Error logging in", err, http.StatusInternalServerError, true)
	}

	///prepare response

	//message
	if message != nil {
		responseData := &Def.SharedResLogin{Message: message}
		respData, err := json.Marshal(responseData)
		if err != nil {
			return l.HttpResponseErrorAction(logutils.ActionMarshal, logutils.MessageDataType("auth login response"), nil, err, http.StatusInternalServerError, false)
		}
		return l.HttpResponseSuccessJSON(respData)
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
			return l.HttpResponseErrorAction(logutils.ActionMarshal, logutils.MessageDataType("auth login response"), nil, err, http.StatusInternalServerError, false)
		}
		return l.HttpResponseSuccessJSON(respData)
	}

	return authBuildLoginResponse(l, loginSession)
}

func (h AdminApisHandler) adminLoginMFA(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionRead, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	var mfaData Def.SharedReqLoginMfa
	err = json.Unmarshal(data, &mfaData)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionUnmarshal, logutils.MessageDataType("login mfa request"), nil, err, http.StatusBadRequest, true)
	}

	message, loginSession, err := h.coreAPIs.Auth.LoginMFA(mfaData.ApiKey, mfaData.AccountId, mfaData.SessionId, mfaData.Identifier, string(mfaData.Type), mfaData.Code, mfaData.State, l)
	if message != nil {
		return l.HttpResponseError(*message, err, http.StatusUnauthorized, false)
	}
	if err != nil {
		return l.HttpResponseError("Error logging in", err, http.StatusInternalServerError, true)
	}

	return authBuildLoginResponse(l, loginSession)
}

func (h AdminApisHandler) adminLoginURL(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionRead, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	var requestData Def.SharedReqLoginUrl
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionUnmarshal, "auth login url request", nil, err, http.StatusBadRequest, true)
	}

	loginURL, params, err := h.coreAPIs.Auth.GetLoginURL(string(requestData.AuthType), requestData.AppTypeIdentifier, requestData.OrgId, requestData.RedirectUri, requestData.ApiKey, l)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionGet, "login url", nil, err, http.StatusInternalServerError, true)
	}

	responseData := &Def.SharedResLoginUrl{LoginUrl: loginURL, Params: &params}
	respData, err := json.Marshal(responseData)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionMarshal, "auth login url response", nil, err, http.StatusInternalServerError, false)
	}

	return l.HttpResponseSuccessJSON(respData)
}

func (h AdminApisHandler) adminRefresh(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionRead, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	var requestData Def.SharedReqRefresh
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionUnmarshal, logutils.MessageDataType("auth refresh request"), nil, err, http.StatusBadRequest, true)
	}

	loginSession, err := h.coreAPIs.Auth.Refresh(requestData.RefreshToken, requestData.ApiKey, l)
	if err != nil {
		return l.HttpResponseError("Error refreshing token", err, http.StatusInternalServerError, true)
	}
	if loginSession == nil {
		//if login session is null then unauthorized
		l.Infof("trying to refresh - %s", requestData.RefreshToken)
		return l.HttpResponseError(http.StatusText(http.StatusUnauthorized), nil, http.StatusUnauthorized, true)
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
		return l.HttpResponseErrorAction(logutils.ActionMarshal, logutils.MessageDataType("auth refresh response"), nil, err, http.StatusInternalServerError, false)
	}

	return l.HttpResponseSuccessJSON(respData)
}

func (h AdminApisHandler) adminGetApplications(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	applications, err := h.coreAPIs.Administration.AdmGetApplications(claims.OrgID)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionGet, model.TypeApplication, nil, err, http.StatusInternalServerError, true)
	}

	response := applicationsToDef(applications)

	data, err := json.Marshal(response)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionMarshal, model.TypeApplication, nil, err, http.StatusInternalServerError, false)
	}
	return l.HttpResponseSuccessJSON(data)
}

func (h AdminApisHandler) adminGetApplicationGroups(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {

	get, err := h.coreAPIs.Administration.AdmGetAppOrgGroups(claims.AppID, claims.OrgID)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionGet, model.TypeApplicationOrganization, nil, err, http.StatusInternalServerError, true)
	}

	response := appOrgGroupsToDef(get)

	data, err := json.Marshal(response)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionMarshal, model.TypeAppOrgGroup, nil, err, http.StatusInternalServerError, false)
	}
	return l.HttpResponseSuccessJSON(data)
}

func (h AdminApisHandler) getApplicationPermissions(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	permissions, err := h.coreAPIs.Administration.AdmGetApplicationPermissions(claims.AppID, claims.OrgID, l)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionGet, model.TypeApplicationOrganization, nil, err, http.StatusInternalServerError, true)
	}

	response := applicationPermissionsToDef(permissions)

	data, err := json.Marshal(response)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionMarshal, model.TypePermission, nil, err, http.StatusInternalServerError, false)
	}
	return l.HttpResponseSuccessJSON(data)
}

func (h AdminApisHandler) adminGetApplicationOrgRoles(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	appOrgRoles, err := h.coreAPIs.Administration.AdmGetAppOrgRoles(claims.AppID, claims.OrgID)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionGet, model.TypeApplicationOrganization, nil, err, http.StatusInternalServerError, true)
	}

	response := appOrgRolesToDef(appOrgRoles)

	data, err := json.Marshal(response)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionMarshal, model.TypeAppOrgRole, nil, err, http.StatusInternalServerError, false)
	}

	return l.HttpResponseSuccessJSON(data)
}

func (h AdminApisHandler) getApplicationAccounts(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	//account ID
	var accountID *string
	accountIDParam := r.URL.Query().Get("account-id")
	if len(accountIDParam) > 0 {
		accountID = &accountIDParam
	}

	//auth type identifier
	var authTypeIdentifier *string
	authTypeIdentifierParam := r.URL.Query().Get("auth-type-identifier")
	if len(authTypeIdentifierParam) > 0 {
		authTypeIdentifier = &authTypeIdentifierParam
	}

	accounts, err := h.coreAPIs.Administration.AdmGetAccounts(claims.AppID, claims.OrgID, accountID, authTypeIdentifier)
	if err != nil {
		return l.HttpResponseErrorAction("error finding accounts", model.TypeAccount, nil, err, http.StatusInternalServerError, true)
	}
	response := аccountsToDef(accounts)

	data, err := json.Marshal(response)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionMarshal, model.TypeAccount, nil, err, http.StatusInternalServerError, false)
	}
	return l.HttpResponseSuccessJSON(data)
}

func (h AdminApisHandler) getApplicationLoginSessions(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
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
		return l.HttpResponseErrorAction("error finding login sessions", model.TypeLoginSession, nil, err, http.StatusInternalServerError, true)
	}

	loginSessions := loginSessionsToDef(getLoginSessions)

	data, err := json.Marshal(loginSessions)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionMarshal, model.TypeLoginSession, nil, err, http.StatusInternalServerError, false)
	}
	return l.HttpResponseSuccessJSON(data)
}

func (h AdminApisHandler) getAccount(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	account, err := h.coreAPIs.Administration.AdmGetAccount(claims.Subject)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionGet, model.TypeAccount, nil, err, http.StatusInternalServerError, true)
	}

	var accountData *Def.SharedResAccount
	if account != nil {
		account.SortAccountAuthTypes(claims.UID)
		accountData = accountToDef(*account)
	}

	data, err := json.Marshal(accountData)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionMarshal, model.TypeAccount, nil, err, http.StatusInternalServerError, false)
	}

	return l.HttpResponseSuccessJSON(data)
}

func (h AdminApisHandler) getMFATypes(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	mfaDataList, err := h.coreAPIs.Auth.GetMFATypes(claims.Subject)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionGet, model.TypeMFAType, nil, err, http.StatusInternalServerError, true)
	}

	mfaResp := mfaDataListToDef(mfaDataList)

	data, err := json.Marshal(mfaResp)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionMarshal, model.TypeMFAType, nil, err, http.StatusInternalServerError, false)
	}

	return l.HttpResponseSuccessJSON(data)
}

func (h AdminApisHandler) addMFAType(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionRead, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	var mfaData Def.SharedReqMfa
	err = json.Unmarshal(data, &mfaData)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionUnmarshal, logutils.MessageDataType("add mfa request"), nil, err, http.StatusBadRequest, true)
	}

	mfa, err := h.coreAPIs.Auth.AddMFAType(claims.Subject, mfaData.Identifier, string(mfaData.Type))
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionInsert, model.TypeMFAType, nil, err, http.StatusInternalServerError, true)
	}

	mfaResp := mfaDataToDef(mfa)

	respData, err := json.Marshal(mfaResp)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionMarshal, model.TypeMFAType, nil, err, http.StatusInternalServerError, false)
	}

	return l.HttpResponseSuccessJSON(respData)
}

func (h AdminApisHandler) removeMFAType(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionRead, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	var mfaData Def.SharedReqMfa
	err = json.Unmarshal(data, &mfaData)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionUnmarshal, logutils.MessageDataType("remove mfa request"), nil, err, http.StatusBadRequest, true)
	}

	err = h.coreAPIs.Auth.RemoveMFAType(claims.Subject, mfaData.Identifier, string(mfaData.Type))
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionDelete, model.TypeMFAType, nil, err, http.StatusInternalServerError, true)
	}

	return l.HttpResponseSuccess()
}

func (h AdminApisHandler) adminVerifyMFA(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionRead, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	var mfaData Def.SharedReqMfa
	err = json.Unmarshal(data, &mfaData)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionUnmarshal, logutils.MessageDataType("verify mfa request"), nil, err, http.StatusBadRequest, true)
	}

	if mfaData.Code == nil || *mfaData.Code == "" {
		return l.HttpResponseErrorData(logutils.StatusMissing, "mfa code", nil, nil, http.StatusBadRequest, true)
	}

	message, recoveryCodes, err := h.coreAPIs.Auth.VerifyMFA(claims.Subject, mfaData.Identifier, string(mfaData.Type), *mfaData.Code)
	if message != nil {
		return l.HttpResponseError(*message, nil, http.StatusBadRequest, true)
	}
	if err != nil {
		return l.HttpResponseError("Error verifying MFA", err, http.StatusInternalServerError, true)
	}

	if recoveryCodes == nil {
		recoveryCodes = []string{}
	}

	response, err := json.Marshal(recoveryCodes)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionMarshal, "mfa recovery codes", nil, err, http.StatusInternalServerError, false)
	}

	return l.HttpResponseSuccessJSON(response)
}

func (h AdminApisHandler) getAppToken(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	appID := r.URL.Query().Get("app_id")
	if appID == "" {
		return l.HttpResponseErrorData(logutils.StatusMissing, logutils.TypeQueryParam, logutils.StringArgs("app_id"), nil, http.StatusBadRequest, false)
	}

	token, err := h.coreAPIs.Auth.GetAdminToken(*claims, appID, l)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionGet, "app token", nil, err, http.StatusInternalServerError, true)
	}

	response := Def.AdminResAppToken{Token: token}
	responseJSON, err := json.Marshal(response)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionMarshal, "app token", nil, err, http.StatusInternalServerError, false)
	}

	return l.HttpResponseSuccessJSON(responseJSON)
}

//adminCreateApplicationGroup creates an application group
func (h AdminApisHandler) adminCreateApplicationGroup(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionRead, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}
	var requestData Def.AdminReqCreateApplicationGroup
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionUnmarshal, model.TypeAppOrgGroup, nil, err, http.StatusBadRequest, true)
	}

	//permissions ids
	var permissionsIDs []string
	if requestData.Permissions != nil {
		permissionsIDs = *requestData.Permissions
	}

	//roles ids
	var rolesIDs []string
	if requestData.Roles != nil {
		rolesIDs = *requestData.Roles
	}

	assignerPermissions := strings.Split(claims.Permissions, ",")
	_, err = h.coreAPIs.Administration.AdmCreateAppOrgGroup(requestData.Name, permissionsIDs, rolesIDs, claims.AppID, claims.OrgID, assignerPermissions, l)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionGet, model.TypeAppOrgGroup, nil, err, http.StatusInternalServerError, true)
	}
	return l.HttpResponseSuccess()
}

func (h AdminApisHandler) adminDeleteApplicationGroup(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	params := mux.Vars(r)
	groupsID := params["id"]
	if len(groupsID) <= 0 {
		return l.HttpResponseErrorData(logutils.StatusMissing, logutils.TypeQueryParam, logutils.StringArgs("id"), nil, http.StatusBadRequest, false)
	}

	assignerPermissions := strings.Split(claims.Permissions, ",")
	err := h.coreAPIs.Administration.AdmDeleteAppOrgGroup(groupsID, claims.AppID, claims.OrgID, assignerPermissions, l)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionDelete, model.TypeAppOrgGroup, nil, err, http.StatusInternalServerError, true)
	}
	return l.HttpResponseSuccess()
}

//addAccountsToGroup adds a group the given account
func (h AdminApisHandler) addAccountsToGroup(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionRead, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	var requestData Def.AdminReqAddAccountsToGroup
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionUnmarshal, model.TypeAccount, nil, err, http.StatusBadRequest, true)
	}

	assignerPermissions := strings.Split(claims.Permissions, ",")
	err = h.coreAPIs.Administration.AdmAddAccountsToGroup(claims.AppID, claims.OrgID, requestData.GroupId, requestData.AccountIds, assignerPermissions, l)
	if err != nil {
		return l.HttpResponseErrorAction(actionGrant, model.TypeAccount, nil, err, http.StatusInternalServerError, true)
	}

	return l.HttpResponseSuccess()
}

//removeAccountsFromGroup removes accounts from a given group
func (h AdminApisHandler) removeAccountsFromGroup(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionRead, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	var requestData Def.AdminReqRemoveAccountFromGroup
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionUnmarshal, model.TypeAppOrgGroup, nil, err, http.StatusBadRequest, true)
	}

	assignerPermissions := strings.Split(claims.Permissions, ",")
	err = h.coreAPIs.Administration.AdmRemoveAccountsFromGroup(claims.AppID, claims.OrgID, requestData.GroupId, requestData.AccountIds, assignerPermissions, l)
	if err != nil {
		return l.HttpResponseErrorAction(actionGrant, model.TypeAppOrgRole, nil, err, http.StatusInternalServerError, true)
	}

	return l.HttpResponseSuccess()
}

//adminCreateApplicationRole creates an application role
func (h AdminApisHandler) adminCreateApplicationRole(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionRead, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	var requestData Def.AdminReqCreateApplicationRole
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionUnmarshal, model.TypeAppOrgRole, nil, err, http.StatusBadRequest, true)
	}

	assignerPermissions := strings.Split(claims.Permissions, ",")
	_, err = h.coreAPIs.Administration.AdmCreateAppOrgRole(requestData.Name, requestData.Description, requestData.Permissions, claims.AppID, claims.OrgID, assignerPermissions, l)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionGet, model.TypeAppOrgRole, nil, err, http.StatusInternalServerError, true)
	}

	return l.HttpResponseSuccess()
}

func (h AdminApisHandler) adminDeleteApplicationRole(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	params := mux.Vars(r)
	rolesID := params["id"]
	if len(rolesID) <= 0 {
		return l.HttpResponseErrorData(logutils.StatusMissing, logutils.TypeQueryParam, logutils.StringArgs("id"), nil, http.StatusBadRequest, false)
	}

	assignerPermissions := strings.Split(claims.Permissions, ",")
	err := h.coreAPIs.Administration.AdmDeleteAppOrgRole(rolesID, claims.AppID, claims.OrgID, assignerPermissions, l)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionDelete, model.TypeAppOrgRole, nil, err, http.StatusInternalServerError, true)
	}
	return l.HttpResponseSuccess()
}

func (h AdminApisHandler) deleteApplicationLoginSession(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	params := mux.Vars(r)
	identifier := params["account_id"]
	if len(identifier) <= 0 {
		return l.HttpResponseErrorData(logutils.StatusMissing, logutils.TypeQueryParam, logutils.StringArgs("account_id"), nil, http.StatusBadRequest, false)
	}

	params2 := mux.Vars(r)
	sessionID := params2["session_id"]
	if len(sessionID) <= 0 {
		return l.HttpResponseErrorData(logutils.StatusMissing, logutils.TypeQueryParam, logutils.StringArgs("session_id"), nil, http.StatusBadRequest, false)
	}

	err := h.coreAPIs.Administration.AdmDeleteApplicationLoginSession(claims.AppID, claims.OrgID, claims.Subject, identifier, sessionID, l)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionDelete, model.TypeLoginSession, nil, err, http.StatusInternalServerError, true)
	}
	return l.HttpResponseSuccess()
}

func (h AdminApisHandler) getApplicationAccountDevices(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	params := mux.Vars(r)
	accountID := params["id"]
	if len(accountID) <= 0 {
		return l.HttpResponseErrorData(logutils.StatusMissing, logutils.TypeQueryParam, logutils.StringArgs("id"), nil, http.StatusBadRequest, false)
	}

	if len(accountID) <= 0 {
		return l.HttpResponseErrorData(logutils.StatusMissing, logutils.TypeQueryParam, logutils.StringArgs("id"), nil, http.StatusBadRequest, false)
	}
	devices, err := h.coreAPIs.Administration.AdmGetApplicationAccountDevices(claims.AppID, claims.OrgID, accountID, l)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionGet, model.TypeDevice, nil, err, http.StatusInternalServerError, true)
	}

	devicesRes := deviceListToDef(devices)
	data, err := json.Marshal(devicesRes)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionMarshal, model.TypeApplication, nil, err, http.StatusInternalServerError, false)
	}
	return l.HttpResponseSuccessJSON(data)
}

//grantAccountsPermissions grants an account the given permissions
func (h AdminApisHandler) grantAccountPermissions(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionRead, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	var requestData Def.AdminReqGrantPermissions
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionUnmarshal, model.TypePermission, nil, err, http.StatusBadRequest, true)
	}

	assignerPermissions := strings.Split(claims.Permissions, ",")
	err = h.coreAPIs.Administration.AdmGrantAccountPermissions(claims.AppID, claims.OrgID, requestData.AccountId, requestData.Permissions, assignerPermissions, l)
	if err != nil {
		return l.HttpResponseErrorAction(actionGrant, model.TypePermission, nil, err, http.StatusInternalServerError, true)
	}

	return l.HttpResponseSuccess()
}

//revokeAccountPermissions removes permissions from an account
func (h AdminApisHandler) revokeAccountPermissions(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionRead, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}
	var requestData Def.AdminReqRevokePermissions
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionUnmarshal, model.TypePermission, nil, err, http.StatusBadRequest, true)
	}

	assignerPermissions := strings.Split(claims.Permissions, ",")
	err = h.coreAPIs.Administration.AdmRevokeAccountPermissions(claims.AppID, claims.OrgID, requestData.AccountId, requestData.Permissions, assignerPermissions, l)
	if err != nil {
		return l.HttpResponseErrorAction(actionGrant, model.TypePermission, nil, err, http.StatusInternalServerError, true)
	}

	return l.HttpResponseSuccess()
}

//grantAccountRoles grants an account the given roles
func (h AdminApisHandler) grantAccountRoles(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {

	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionRead, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	var requestData Def.AdminReqGrantRolesToAccount
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionUnmarshal, model.TypeAppOrgRole, nil, err, http.StatusBadRequest, true)
	}

	assignerPermissions := strings.Split(claims.Permissions, ",")
	err = h.coreAPIs.Administration.AdmGrantAccountRoles(claims.AppID, claims.OrgID, requestData.AccountId, requestData.RoleIds, assignerPermissions, l)
	if err != nil {
		return l.HttpResponseErrorAction(actionGrant, model.TypeAppOrgRole, nil, err, http.StatusInternalServerError, true)
	}

	return l.HttpResponseSuccess()
}

//revokeAccountRoles removes role from a given account
func (h AdminApisHandler) revokeAccountRoles(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionRead, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	var requestData Def.AdminReqRevokeRolesFromAccount
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionUnmarshal, model.TypeAppOrgRole, nil, err, http.StatusBadRequest, true)
	}

	assignerPermissions := strings.Split(claims.Permissions, ",")
	err = h.coreAPIs.Administration.AdmRevokeAccountRoles(claims.AppID, claims.OrgID, requestData.AccountId, requestData.RoleIds, assignerPermissions, l)
	if err != nil {
		return l.HttpResponseErrorAction(actionGrant, model.TypeAppOrgRole, nil, err, http.StatusInternalServerError, true)
	}

	return l.HttpResponseSuccess()
}

//adminGrantPermissionsToRole grants a role the given permission
func (h AdminApisHandler) adminGrantPermissionsToRole(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionRead, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	var requestData Def.AdminReqGrantPermissionsToRole
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionUnmarshal, model.TypeAppOrgRole, nil, err, http.StatusBadRequest, true)
	}

	assignerPermissions := strings.Split(claims.Permissions, ",")
	err = h.coreAPIs.Administration.AdmGrantPermissionsToRole(claims.AppID, claims.OrgID, requestData.RoleId, requestData.Permissions, assignerPermissions, l)
	if err != nil {
		return l.HttpResponseErrorAction(actionGrant, model.TypeAppOrgRole, nil, err, http.StatusInternalServerError, true)
	}

	return l.HttpResponseSuccess()
}

//NewAdminApisHandler creates new admin rest Handler instance
func NewAdminApisHandler(coreAPIs *core.APIs) AdminApisHandler {
	return AdminApisHandler{coreAPIs: coreAPIs}
}
