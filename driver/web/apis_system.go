package web

import (
	"core-building-block/core"
	"core-building-block/core/model"
	Def "core-building-block/driver/web/docs/gen"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
	"github.com/rokwire/core-auth-library-go/tokenauth"
	"github.com/rokwire/logging-library-go/logs"
	"github.com/rokwire/logging-library-go/logutils"
)

//SystemApisHandler handles system APIs implementation
type SystemApisHandler struct {
	coreAPIs *core.APIs
}

//createGlobalConfig creates a global config
func (h SystemApisHandler) createGlobalConfig(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionRead, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	var requestData Def.GlobalConfig
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionUnmarshal, model.TypeGlobalConfig, nil, err, http.StatusBadRequest, true)
	}

	_, err = h.coreAPIs.System.SysCreateGlobalConfig(requestData.Setting)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionCreate, model.TypeGlobalConfig, nil, err, http.StatusInternalServerError, true)
	}

	return l.HttpResponseSuccess()
}

//getGlobalConfig gets config
func (h SystemApisHandler) getGlobalConfig(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	config, err := h.coreAPIs.System.SysGetGlobalConfig()
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionGet, model.TypeGlobalConfig, nil, err, http.StatusInternalServerError, true)
	}

	var responseData *Def.GlobalConfig
	if config != nil {
		responseData = &Def.GlobalConfig{Setting: config.Setting}
	}
	data, err := json.Marshal(responseData)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionMarshal, model.TypeGlobalConfig, nil, err, http.StatusInternalServerError, false)
	}

	return l.HttpResponseSuccessJSON(data)
}

//updateGlobalConfig updates global config
func (h SystemApisHandler) updateGlobalConfig(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionRead, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	var updateConfig Def.GlobalConfig
	err = json.Unmarshal(data, &updateConfig)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionUnmarshal, model.TypeGlobalConfig, nil, err, http.StatusBadRequest, true)
	}

	setting := updateConfig.Setting

	err = h.coreAPIs.System.SysUpdateGlobalConfig(setting)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionUpdate, model.TypeGlobalConfig, nil, err, http.StatusInternalServerError, true)
	}

	return l.HttpResponseSuccess()
}

//createOrganization creates organization
func (h SystemApisHandler) createOrganization(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {

	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionRead, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	var requestData Def.SystemReqCreateOrganization
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionUnmarshal, model.TypeOrganization, nil, err, http.StatusBadRequest, true)
	}

	name := requestData.Name
	types := requestData.Type
	domains := requestData.Config.Domains

	_, err = h.coreAPIs.System.SysCreateOrganization(name, string(types), *domains)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionCreate, model.TypeOrganization, nil, err, http.StatusInternalServerError, true)
	}

	return l.HttpResponseSuccess()
}

//updateOrganization updates organization
func (h SystemApisHandler) updateOrganization(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	params := mux.Vars(r)
	ID := params["id"]
	if len(ID) <= 0 {
		return l.HttpResponseErrorData(logutils.StatusMissing, logutils.TypeQueryParam, logutils.StringArgs("id"), nil, http.StatusBadRequest, false)
	}

	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HttpResponseErrorData(logutils.StatusInvalid, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}
	var requestData Def.SystemReqUpdateOrganization
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionUnmarshal, model.TypeOrganization, nil, err, http.StatusBadRequest, true)
	}

	name := requestData.Name
	requestType := requestData.Type
	organizationDomains := requestData.Config.Domains

	err = h.coreAPIs.System.SysUpdateOrganization(ID, name, string(requestType), *organizationDomains)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionUpdate, model.TypeOrganization, nil, err, http.StatusInternalServerError, true)
	}

	return l.HttpResponseSuccess()
}

//getOrganization gets organization
func (h SystemApisHandler) getOrganization(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	params := mux.Vars(r)
	ID := params["id"]
	if len(ID) <= 0 {
		return l.HttpResponseErrorData(logutils.StatusMissing, logutils.TypeQueryParam, logutils.StringArgs("id"), nil, http.StatusBadRequest, false)
	}
	org, err := h.coreAPIs.System.SysGetOrganization(ID)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionGet, model.TypeOrganization, nil, err, http.StatusInternalServerError, true)
	}
	if org == nil {
		return l.HttpResponseErrorData(logutils.StatusMissing, model.TypeOrganization, &logutils.FieldArgs{"id": ID}, nil, http.StatusNotFound, false)
	}

	responseData := organizationToDef(org)
	data, err := json.Marshal(responseData)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionMarshal, model.TypeOrganization, nil, err, http.StatusInternalServerError, false)
	}
	return l.HttpResponseSuccessJSON(data)
}

//getOrganizations gets organizations
func (h SystemApisHandler) getOrganizations(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	organizations, err := h.coreAPIs.System.SysGetOrganizations()
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionGet, model.TypeOrganization, nil, err, http.StatusInternalServerError, true)
	}

	response := organizationsToDef(organizations)

	data, err := json.Marshal(response)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionMarshal, model.TypeOrganization, nil, err, http.StatusInternalServerError, false)
	}
	return l.HttpResponseSuccessJSON(data)
}

func (h SystemApisHandler) getServiceRegistrations(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	serviceIDsParam := r.URL.Query().Get("ids")
	if serviceIDsParam == "" {
		return l.HttpResponseErrorData(logutils.StatusMissing, logutils.TypeQueryParam, logutils.StringArgs("ids"), nil, http.StatusBadRequest, false)
	}
	serviceIDs := strings.Split(serviceIDsParam, ",")

	serviceRegs, err := h.coreAPIs.Auth.GetServiceRegistrations(serviceIDs)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionGet, model.TypeServiceReg, nil, err, http.StatusInternalServerError, true)
	}

	serviceRegResp := serviceRegListToDef(serviceRegs)

	data, err := json.Marshal(serviceRegResp)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionMarshal, model.TypeServiceReg, nil, err, http.StatusInternalServerError, false)
	}

	return l.HttpResponseSuccessJSON(data)
}

func (h SystemApisHandler) registerService(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionRead, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	var requestData Def.ServiceReg
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionUnmarshal, model.TypeServiceReg, nil, err, http.StatusBadRequest, true)
	}

	serviceReg, err := serviceRegFromDef(&requestData)
	if err != nil {
		return l.HttpResponseErrorData(logutils.StatusInvalid, model.TypeServiceReg, nil, err, http.StatusBadRequest, true)
	}

	err = h.coreAPIs.Auth.RegisterService(serviceReg)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionCreate, model.TypeServiceReg, nil, err, http.StatusInternalServerError, true)
	}

	return l.HttpResponseSuccess()
}

func (h SystemApisHandler) updateServiceRegistration(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HttpResponseErrorData(logutils.StatusInvalid, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	var requestData Def.ServiceReg
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionUnmarshal, model.TypeServiceReg, nil, err, http.StatusBadRequest, true)
	}

	serviceReg, err := serviceRegFromDef(&requestData)
	if err != nil {
		return l.HttpResponseErrorData(logutils.StatusInvalid, model.TypeServiceReg, nil, err, http.StatusBadRequest, true)
	}

	err = h.coreAPIs.Auth.UpdateServiceRegistration(serviceReg)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionUpdate, model.TypeServiceReg, nil, err, http.StatusInternalServerError, true)
	}

	return l.HttpResponseSuccess()
}

func (h SystemApisHandler) deregisterService(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	serviceID := r.URL.Query().Get("id")
	if serviceID == "" {
		return l.HttpResponseErrorData(logutils.StatusMissing, logutils.TypeQueryParam, logutils.StringArgs("id"), nil, http.StatusBadRequest, false)
	}

	err := h.coreAPIs.Auth.DeregisterService(serviceID)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionDelete, model.TypeServiceReg, nil, err, http.StatusInternalServerError, true)
	}

	return l.HttpResponseSuccess()
}

func (h SystemApisHandler) getApplicationAPIKeys(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	appID := r.URL.Query().Get("app_id")
	if appID == "" {
		return l.HttpResponseErrorData(logutils.StatusMissing, logutils.TypeQueryParam, logutils.StringArgs("app_id"), nil, http.StatusBadRequest, false)
	}

	apiKeys, err := h.coreAPIs.Auth.GetApplicationAPIKeys(appID)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionGet, model.TypeAPIKey, nil, err, http.StatusInternalServerError, true)
	}

	responseData := apiKeyListToDef(apiKeys)
	data, err := json.Marshal(responseData)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionMarshal, model.TypeAPIKey, nil, err, http.StatusInternalServerError, false)
	}
	return l.HttpResponseSuccessJSON(data)
}

func (h SystemApisHandler) getAPIKey(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	id := r.URL.Query().Get("id")
	if id == "" {
		return l.HttpResponseErrorData(logutils.StatusMissing, logutils.TypeQueryParam, logutils.StringArgs("id"), nil, http.StatusBadRequest, false)
	}

	apiKey, err := h.coreAPIs.Auth.GetAPIKey(id)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionGet, model.TypeAPIKey, nil, err, http.StatusInternalServerError, true)
	}
	if apiKey == nil {
		return l.HttpResponseErrorData(logutils.StatusMissing, model.TypeAPIKey, &logutils.FieldArgs{"id": id}, nil, http.StatusNotFound, false)
	}

	responseData := apiKeyToDef(apiKey)
	data, err := json.Marshal(responseData)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionMarshal, model.TypeAPIKey, nil, err, http.StatusInternalServerError, false)
	}
	return l.HttpResponseSuccessJSON(data)
}

func (h SystemApisHandler) createAPIKey(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionRead, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	var requestData Def.APIKey
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionUnmarshal, model.TypeAPIKey, nil, err, http.StatusBadRequest, true)
	}

	apiKey := apiKeyFromDef(requestData)
	_, err = h.coreAPIs.Auth.CreateAPIKey(apiKey)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionCreate, model.TypeAPIKey, nil, err, http.StatusInternalServerError, true)
	}

	return l.HttpResponseSuccess()
}

func (h SystemApisHandler) updateAPIKey(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HttpResponseErrorData(logutils.StatusInvalid, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	var requestData Def.APIKey
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionUnmarshal, model.TypeAPIKey, nil, err, http.StatusBadRequest, true)
	}

	apiKey := apiKeyFromDef(requestData)
	err = h.coreAPIs.Auth.UpdateAPIKey(apiKey)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionUpdate, model.TypeAPIKey, nil, err, http.StatusInternalServerError, true)
	}

	return l.HttpResponseSuccess()
}

func (h SystemApisHandler) deleteAPIKey(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	id := r.URL.Query().Get("id")
	if id == "" {
		return l.HttpResponseErrorData(logutils.StatusMissing, logutils.TypeQueryParam, logutils.StringArgs("id"), nil, http.StatusBadRequest, false)
	}

	err := h.coreAPIs.Auth.DeleteAPIKey(id)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionDelete, model.TypeAPIKey, nil, err, http.StatusInternalServerError, true)
	}

	return l.HttpResponseSuccess()
}

func (h SystemApisHandler) getApplication(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	params := mux.Vars(r)
	ID := params["id"]
	if len(ID) <= 0 {
		return l.HttpResponseErrorData(logutils.StatusMissing, logutils.TypeQueryParam, logutils.StringArgs("id"), nil, http.StatusBadRequest, false)
	}
	app, err := h.coreAPIs.System.SysGetApplication(ID)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionGet, model.TypeApplication, nil, err, http.StatusInternalServerError, true)
	}
	if app == nil {
		return l.HttpResponseErrorData(logutils.StatusMissing, model.TypeApplication, &logutils.FieldArgs{"id": ID}, nil, http.StatusNotFound, false)
	}

	responseData := applicationToDef(*app)
	data, err := json.Marshal(responseData)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionMarshal, model.TypeApplication, nil, err, http.StatusInternalServerError, false)
	}
	return l.HttpResponseSuccessJSON(data)
}

//createApplication creates an application
func (h SystemApisHandler) createApplication(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionRead, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	var requestData Def.SystemReqCreateApplication
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionUnmarshal, model.TypeApplication, nil, err, http.StatusBadRequest, true)
	}

	name := requestData.Name
	multiTenant := requestData.MultiTenant
	requiresOwnUsers := requestData.RequiresOwnUsers
	maxLoginSessionDuration := requestData.MaxLoginSessionDuration

	var appType Def.ApplicationTypeFields
	applicationType := []string{}
	applicationType = append(applicationType, appType.Identifier, *appType.Name)
	_, err = h.coreAPIs.System.SysCreateApplication(name, multiTenant, requiresOwnUsers, maxLoginSessionDuration, appType.Identifier, *appType.Name, *appType.Versions)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionCreate, model.TypeApplication, nil, err, http.StatusInternalServerError, true)
	}

	return l.HttpResponseSuccess()
}

func (h SystemApisHandler) getApplications(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {

	applications, err := h.coreAPIs.System.SysGetApplications()
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionGet, model.TypeApplication, nil, err, http.StatusInternalServerError, true)
	}
	var response []Def.ApplicationFields
	for _, application := range applications {
		r := applicationToDef(application)
		response = append(response, r)
	}

	data, err := json.Marshal(response)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionMarshal, model.TypeApplication, nil, err, http.StatusInternalServerError, false)
	}
	return l.HttpResponseSuccessJSON(data)
}

//createPermission creates an permission
func (h SystemApisHandler) createPermission(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionRead, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	var requestData Def.SystemReqPermissions
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionUnmarshal, model.TypePermission, nil, err, http.StatusBadRequest, true)
	}

	_, err = h.coreAPIs.System.SysCreatePermission(requestData.Name, *requestData.ServiceId, requestData.Assigners)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionCreate, model.TypePermission, nil, err, http.StatusInternalServerError, true)
	}

	return l.HttpResponseSuccess()
}

//updatePermission updates an permission
func (h SystemApisHandler) updatePermission(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionRead, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	var requestData Def.SystemReqPermissions
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionUnmarshal, model.TypePermission, nil, err, http.StatusBadRequest, true)
	}

	_, err = h.coreAPIs.System.SysUpdatePermission(requestData.Name, requestData.ServiceId, requestData.Assigners)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionUpdate, model.TypePermission, nil, err, http.StatusInternalServerError, true)
	}

	return l.HttpResponseSuccess()
}

//createApplicationRole creates an application role
func (h SystemApisHandler) createApplicationRole(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionRead, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	var requestData Def.SystemReqApplicationRoles
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionUnmarshal, model.TypeAppOrgRole, nil, err, http.StatusBadRequest, true)
	}

	_, err = h.coreAPIs.System.SysCreateAppOrgRole(requestData.Name, requestData.AppId, requestData.Description, requestData.Permissions)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionGet, model.TypeAppOrgRole, nil, err, http.StatusInternalServerError, true)
	}

	return l.HttpResponseSuccess()
}

//grantAccountPermissions grants an account the given permissions
func (h SystemApisHandler) grantAccountPermissions(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionRead, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	var requestData Def.SystemReqAccountPermissions
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionUnmarshal, model.TypePermission, nil, err, http.StatusBadRequest, true)
	}

	assignerPermissions := strings.Split(claims.Permissions, ",")
	err = h.coreAPIs.System.SysGrantAccountPermissions(requestData.AccountId, requestData.Permissions, assignerPermissions)
	if err != nil {
		return l.HttpResponseErrorAction(actionGrant, model.TypePermission, nil, err, http.StatusInternalServerError, true)
	}

	return l.HttpResponseSuccess()
}

//grantAccountRoles grants an account the given roles
func (h SystemApisHandler) grantAccountRoles(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionRead, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	var requestData Def.SystemReqAccountRoles
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionUnmarshal, model.TypeAppOrgRole, nil, err, http.StatusBadRequest, true)
	}

	err = h.coreAPIs.System.SysGrantAccountRoles(requestData.AccountId, requestData.AppId, requestData.RoleIds)
	if err != nil {
		return l.HttpResponseErrorAction(actionGrant, model.TypeAppOrgRole, nil, err, http.StatusInternalServerError, true)
	}

	return l.HttpResponseSuccess()
}

//getMFATypes gets the mfa types an account is enrolled in
func (h SystemApisHandler) getMFATypes(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
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

//addMFAType enrolls an account in a mfa type
func (h SystemApisHandler) addMFAType(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
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

//removeMFAType removes a mfa type from an account
func (h SystemApisHandler) removeMFAType(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
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

//NewSystemApisHandler creates new system Handler instance
func NewSystemApisHandler(coreAPIs *core.APIs) SystemApisHandler {
	return SystemApisHandler{coreAPIs: coreAPIs}
}
