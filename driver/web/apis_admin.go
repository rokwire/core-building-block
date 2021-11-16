package web

import (
	"core-building-block/core"
	"core-building-block/core/model"
	Def "core-building-block/driver/web/docs/gen"
	"core-building-block/utils"
	"encoding/json"
	"io/ioutil"
	"net/http"

	"github.com/rokwire/core-auth-library-go/tokenauth"
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

	var requestData Def.ReqSharedLogin
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

	message, loginSession, err := h.coreAPIs.Auth.Login(ip, string(requestDevice.Type), requestDevice.Os, *requestDevice.DeviceId,
		string(requestData.AuthType), requestCreds, requestData.ApiKey, requestData.AppTypeIdentifier, requestData.OrgId, requestParams, requestProfile, requestPreferences, l)
	if err != nil {
		return l.HttpResponseError("Error logging in", err, http.StatusInternalServerError, true)
	}

	///prepare response

	//message
	if message != nil {
		responseData := &Def.ResSharedLogin{Message: message}
		respData, err := json.Marshal(responseData)
		if err != nil {
			return l.HttpResponseErrorAction(logutils.ActionMarshal, logutils.MessageDataType("auth login response"), nil, err, http.StatusInternalServerError, false)
		}
		return l.HttpResponseSuccessJSON(respData)
	}

	//token
	accessToken := loginSession.AccessToken
	refreshToken := loginSession.CurrentRefreshToken()

	tokenType := Def.ResSharedRokwireTokenTokenTypeBearer
	rokwireToken := Def.ResSharedRokwireToken{AccessToken: &accessToken, RefreshToken: &refreshToken, TokenType: &tokenType}

	//account
	var accountData *Def.ResSharedAccount
	if !loginSession.Anonymous {
		account := loginSession.AccountAuthType.Account

		//profile
		profile := profileToDef(&account.Profile)
		//preferences
		preferences := &account.Preferences
		//permissions
		permissions := applicationPermissionsToDef(account.Permissions)
		//roles
		roles := accountRolesToDef(account.GetActiveRoles())
		//groups
		groups := accountGroupsToDef(account.GetActiveGroups())
		//account auth types
		authTypes := accountAuthTypesToDef(account.AuthTypes)
		accountData = &Def.ResSharedAccount{Id: account.ID, Permissions: &permissions, Roles: &roles, Groups: &groups, AuthTypes: &authTypes, Profile: profile, Preferences: preferences}
	}

	//params
	var paramsRes interface{}
	if loginSession.Params != nil {
		paramsRes = loginSession.Params
	}

	responseData := &Def.ResSharedLogin{Token: &rokwireToken, Account: accountData, Params: &paramsRes}
	respData, err := json.Marshal(responseData)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionMarshal, logutils.MessageDataType("auth login response"), nil, err, http.StatusInternalServerError, false)
	}

	return l.HttpResponseSuccessJSON(respData)
}

func (h AdminApisHandler) adminLoginURL(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionRead, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	var requestData Def.ReqSharedLoginUrl
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionUnmarshal, "auth login url request", nil, err, http.StatusBadRequest, true)
	}

	loginURL, params, err := h.coreAPIs.Auth.GetLoginURL(string(requestData.AuthType), requestData.AppTypeIdentifier, requestData.OrgId, requestData.RedirectUri, requestData.ApiKey, l)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionGet, "login url", nil, err, http.StatusInternalServerError, true)
	}

	responseData := &Def.ResSharedLoginUrl{LoginUrl: loginURL, Params: &params}
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

	var requestData Def.ReqSharedRefresh
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

	tokenType := Def.ResSharedRokwireTokenTokenTypeBearer
	rokwireToken := Def.ResSharedRokwireToken{AccessToken: &accessToken, RefreshToken: &refreshToken, TokenType: &tokenType}
	responseData := &Def.ResSharedRefresh{Token: &rokwireToken, Params: &paramsRes}
	respData, err := json.Marshal(responseData)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionMarshal, logutils.MessageDataType("auth refresh response"), nil, err, http.StatusInternalServerError, false)
	}

	return l.HttpResponseSuccessJSON(respData)
}

func (h AdminApisHandler) adminGetApplicationOrgRoles(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	getAppOrgRoles, err := h.coreAPIs.Administration.AdmGetApplicationOrgRoles()
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionGet, model.TypeAppOrgRole, nil, err, http.StatusInternalServerError, true)
	}
	var response []Def.AppOrgRoleFields
	for _, appOrgRole := range getAppOrgRoles {
		r := appOrgRoleToDef(appOrgRole)
		response = append(response, r)
	}

	data, err := json.Marshal(response)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionMarshal, model.TypeAppOrgRole, nil, err, http.StatusInternalServerError, false)
	}
	return l.HttpResponseSuccessJSON(data)
}

//adminCreateApplicationOrgRoles creates an application_organization_role
func (h AdminApisHandler) adminCreateApplicationOrgRoles(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionRead, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	var requestData Def.ReqApplicationRolesRequest
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionUnmarshal, model.TypeAppOrgRole, nil, err, http.StatusBadRequest, true)
	}

	_, err = h.coreAPIs.Administration.AdmCreateAppOrgRole(requestData.Name, requestData.AppId, requestData.Description, requestData.Permissions)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionGet, model.TypeAppOrgRole, nil, err, http.StatusInternalServerError, true)
	}

	return l.HttpResponseSuccess()
}

func (h AdminApisHandler) adminGetApplicationOrgGroups(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	getAppOrgGroups, err := h.coreAPIs.Administration.AdmGetApplicationOrgGroups()
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionGet, model.TypeAppOrgGroup, nil, err, http.StatusInternalServerError, true)
	}
	var response []Def.AppOrgGroupFields
	for _, appOrgGroup := range getAppOrgGroups {
		r := appOrgGroupToDef(appOrgGroup)
		response = append(response, r)
	}

	data, err := json.Marshal(response)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionMarshal, model.TypeAppOrgGroup, nil, err, http.StatusInternalServerError, false)
	}
	return l.HttpResponseSuccessJSON(data)
}

//adminCreateApplicationOrgGroups creates an application_organization_role
func (h AdminApisHandler) adminCreateApplicationOrgGroups(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionRead, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	var requestData Def.ReqCreateAppOrgGroupsRequest
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionUnmarshal, model.TypeAppOrgGroup, nil, err, http.StatusBadRequest, true)
	}

	_, err = h.coreAPIs.Administration.AdmCreateAppOrgGroup(requestData.Name, requestData.Id, *requestData.Permissions, *requestData.Roles)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionGet, model.TypeAppOrgGroup, nil, err, http.StatusInternalServerError, true)
	}

	return l.HttpResponseSuccess()
}

func (h AdminApisHandler) adminDeleteApplicationOrgGroups(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	id := r.URL.Query().Get("id")
	if id == "" {
		return l.HttpResponseErrorData(logutils.StatusMissing, logutils.TypeQueryParam, logutils.StringArgs("id"), nil, http.StatusBadRequest, false)
	}

	err := h.coreAPIs.Administration.AdmDeleteAppOrgGroup(id)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionDelete, model.TypeAppOrgGroup, nil, err, http.StatusInternalServerError, true)
	}

	return l.HttpResponseSuccess()
}

//NewAdminApisHandler creates new admin rest Handler instance
func NewAdminApisHandler(coreAPIs *core.APIs) AdminApisHandler {
	return AdminApisHandler{coreAPIs: coreAPIs}
}
